//! F-01 (audit HIGH): the base-fee floor is consensus-enforced, twice.
//!
//! Admission (mempool) and packing (proposer filter) always refused
//! below-floor transactions, but a Byzantine proposer could bypass both by
//! constructing a block directly: `validate_proposal` had no fee condition
//! and the apply path re-checked everything EXCEPT the floor, so every
//! honest validator accepted and executed underpriced transactions — and
//! failed ones paid nothing (the D2 free-failure loop). These tests pin the
//! two closing checks:
//!
//! * VALIDATE (`ValidatorRuntime::validate_proposal`): refuses any block
//!   carrying a transaction below the effective floor
//!   (`Mempool::effective_floor_for_tx` = base + D2 penalty + PQ surcharge),
//!   fail-closed with a reason naming the transaction.
//! * APPLY (`InMemoryStateEngine` block path): charges at least the floor
//!   (`commit_native` floors the fee; the fast path floors identically), and
//!   attributable execution failures still pay the floor while consuming
//!   their nonce (no more free failures).
//!
//! NONCE NOTE (documented behaviour): the failure fee and the nonce advance
//! are ATOMIC — either both happen (floor debited, nonce consumed) or
//! neither does. A failed transaction whose failure is attributable (valid
//! signature, right chain, sender exists, `tx.nonce == sender.nonce` at
//! execution, sender covers the floor) pays the floor AND advances the
//! sender nonce — exactly like a success, minus the value movement. The
//! consumed nonce is the replay protection and the spam rate-limit: without
//! the advance the same failing transaction could be re-packed forever for
//! one floor payment, and the block's own per-sender sequence would cascade
//! into further failures. A failure that takes no money (bad signature,
//! wrong chain-id, stale/future nonce, missing sender, or a sender that
//! cannot cover the floor) changes NO state at all — balance AND nonce
//! untouched, on the block path just like on the single-transaction path
//! (the historical atomicity pin holds for the zero-payment case).

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;

use stellereum::consensus::ValidatorSet;
use stellereum::runtime::ValidatorRuntime;
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::{OpCode, GAS_BASIC_TRANSFER};

/// Governed consensus floor for the apply tests: above the 280k default
/// transfer cost, so the floor (not the operation price) is what binds.
const FLOOR: u64 = 500_000;
/// PQ activation surcharge, pinned here so the tests name the same number
/// the floor formula adds (mirrors `PQ_ACTIVATION_SURCHARGE_GAS`).
const PQ_SURCHARGE: u64 = 45_000;
const TS: u64 = 1_760_000_000;
const BAL: u64 = 10_000_000;

fn user_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

fn id_of(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

/// Engine with the governed consensus floor set (the apply path reads the
/// GOVERNED base — the env half of admission is node-local config and must
/// not move consensus; see `consensus_floor_parts`).
async fn engine_with_floor(floor: u64) -> Arc<InMemoryStateEngine> {
    let e = Arc::new(InMemoryStateEngine::new());
    e.governance_write().await.applied.min_gas_limit = Some(floor);
    e
}

/// A payload that cannot run on `gas`: a plain transfer costs
/// `GAS_BASIC_TRANSFER`, so executing it with a tiny limit ends out of gas
/// AFTER admission (admission only reserves `amount + gas`, which is
/// covered) — the canonical attributable execution failure.
fn oom_payload() -> Vec<OpCode> {
    vec![OpCode::Transfer {
        recipient: [0xCC; 32],
        amount: 1,
    }]
}

fn mk_block(txs: Vec<Transaction>, proposer: &SigningKey) -> Block {
    let order_merkle_root = stellereum::mev::compute_order_merkle_root(&txs);
    let mut blk = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 1,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: txs,
        cross_shard_out: vec![],
        timestamp: TS,
        proposer: id_of(proposer),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
    };
    blk.sign_block(proposer);
    blk
}

// ===========================================================================
// APPLY: charge at least the floor
// ===========================================================================

/// A below-floor transaction still executes (the floor is a price, not a
/// ban) but is charged the floor, never its declaration.
#[tokio::test]
async fn apply_charges_floor_for_underpriced_tx() {
    let engine = engine_with_floor(FLOOR).await;
    let alice = user_key();
    let from = id_of(&alice);
    engine.update_account(AccountState::new(from, BAL)).await;

    // Declares 100, floor is 500k: applies, pays the floor.
    let tx = Transaction::sign(&alice, [0xB0; 32], 1_000, 100, 0, 1, 1);
    let (applied, failed, fees_collected, status, fees) =
        engine.apply_block_parallel_fees(&[tx], TS).await;

    assert_eq!((applied, failed), (1, 0));
    assert_eq!(status, vec![true]);
    assert_eq!(
        fees,
        vec![FLOOR],
        "must charge the floor, not the declaration"
    );
    assert_eq!(fees_collected, FLOOR);
    let sender = engine.get_account(&from).await.unwrap();
    assert_eq!(sender.balance, BAL - 1_000 - FLOOR);
    assert_eq!(sender.nonce, 1);
}

/// An attributable execution failure (out-of-gas payload, head nonce, funded
/// sender) still pays the floor AND consumes its nonce — the D2
/// free-failure loop is closed.
#[tokio::test]
async fn failed_tx_pays_floor_and_advances_nonce() {
    let engine = engine_with_floor(FLOOR).await;
    let alice = user_key();
    let from = id_of(&alice);
    engine.update_account(AccountState::new(from, BAL)).await;

    // Gas 100 cannot run a 280k transfer: admitted (0 + 100 is covered),
    // fails at execution, pays the floor.
    let tx = Transaction::sign_with_payload(&alice, [0xB0; 32], 0, 100, 0, 1, 1, oom_payload());
    let (applied, failed, fees_collected, status, fees) =
        engine.apply_block_parallel_fees(&[tx], TS).await;

    assert_eq!((applied, failed), (0, 1));
    assert_eq!(status, vec![false]);
    assert_eq!(fees, vec![FLOOR], "a failed tx must still pay the floor");
    assert_eq!(fees_collected, FLOOR);
    let sender = engine.get_account(&from).await.unwrap();
    assert_eq!(
        sender.balance,
        BAL - FLOOR,
        "only the floor leaves the account"
    );
    assert_eq!(sender.nonce, 1, "a paid failure consumes its nonce");

    // The follow-up at the advanced nonce applies: failures no longer
    // cascade, and the consumed nonce cannot be replayed.
    let next = Transaction::sign(&alice, [0xB0; 32], 0, FLOOR, 1, 1, 1);
    let (applied2, failed2, _, status2, _) = engine.apply_block_parallel_fees(&[next], TS).await;
    assert_eq!((applied2, failed2), (1, 0));
    assert_eq!(status2, vec![true]);
}

/// A sender that cannot cover the floor at execution fails atomically:
/// no debit AND no nonce advance (no pay, no state change). A transaction
/// whose fee the sender cannot cover was never going to run, and charging
/// their remaining dust for it would be a griefing surface, not a safety
/// property. The transaction is replayable but worthless, while each failure
/// still escalates the sender's D2 mirror (see below), so retrying only
/// raises the price of the sender's future transactions.
#[tokio::test]
async fn broke_sender_failure_changes_nothing() {
    let engine = engine_with_floor(FLOOR).await;
    let alice = user_key();
    let from = id_of(&alice);
    engine
        .update_account(AccountState::new(from, 1_200_000))
        .await;

    // tx1: declared 500k, moves 600k via payload. Admitted (500k reserved),
    // applies (1.1M affordable), leaves 100k.
    let drain = Transaction::sign_with_payload(
        &alice,
        [0xB0; 32],
        0,
        FLOOR,
        0,
        1,
        1,
        vec![OpCode::Transfer {
            recipient: [0xB0; 32],
            amount: 600_000,
        }],
    );
    // tx2: admitted against the simulated remainder, out of gas at
    // execution, with only 100k left against the 500k floor.
    let broke = Transaction::sign_with_payload(&alice, [0xB0; 32], 0, 100, 1, 1, 1, oom_payload());
    let (applied, failed, fees_collected, status, fees) =
        engine.apply_block_parallel_fees(&[drain, broke], TS).await;

    assert_eq!((applied, failed), (1, 1));
    assert_eq!(status, vec![true, false]);
    assert_eq!(fees, vec![FLOOR, 0], "cannot cover the floor: pays nothing");
    assert_eq!(fees_collected, FLOOR);
    let sender = engine.get_account(&from).await.unwrap();
    assert_eq!(sender.balance, 100_000, "dust is not drained");
    assert_eq!(sender.nonce, 1, "no pay, no advance: nonce untouched");
}

/// A transaction that cannot even reserve the floor at admission never
/// executes and moves nothing (the documented residual: admission-invalid
/// transactions fail free — only a Byzantine proposer can pack them, at its
/// own block-space cost).
#[tokio::test]
async fn unfunded_for_floor_fails_free_at_admission() {
    let engine = engine_with_floor(FLOOR).await;
    let alice = user_key();
    let from = id_of(&alice);
    // Covers amount (0) + gas (100) but not the 500k floor.
    engine.update_account(AccountState::new(from, 100)).await;

    let tx = Transaction::sign_with_payload(&alice, [0xB0; 32], 0, 100, 0, 1, 1, oom_payload());
    let (applied, failed, fees_collected, status, fees) =
        engine.apply_block_parallel_fees(&[tx], TS).await;

    assert_eq!((applied, failed), (0, 1));
    assert_eq!(status, vec![false]);
    assert_eq!(fees, vec![0]);
    assert_eq!(fees_collected, 0);
    let sender = engine.get_account(&from).await.unwrap();
    assert_eq!(sender.balance, 100);
    assert_eq!(sender.nonce, 0, "never admitted: nonce untouched");
}

/// Non-attributable failures move nothing: a replay (stale nonce) must not
/// double-charge, and a gap (future nonce) must not burn the sequence.
///
/// Note the D2 mirror still records the SENDER of any failed block
/// transaction (status-based, exactly like mempool `note_apply_feedback`),
/// so the gap below escalates this sender's next floor by one step — the
/// honest apply therefore declares (and pays) above it.
#[tokio::test]
async fn replay_and_gap_failures_pay_nothing() {
    let engine = engine_with_floor(0).await;
    let alice = user_key();
    let from = id_of(&alice);
    engine.update_account(AccountState::new(from, BAL)).await;

    // Gap first: nonce 5 while the head is 0 — never admitted, never charged.
    let gap = Transaction::sign(&alice, [0xB0; 32], 0, FLOOR, 5, 1, 1);
    let (a1, f1, _, s1, fees1) = engine.apply_block_parallel_fees(&[gap], TS).await;
    assert_eq!((a1, f1), (0, 1));
    assert_eq!(s1, vec![false]);
    assert_eq!(fees1, vec![0]);

    // Consume nonce 0 honestly (declaring above the one-step penalty the gap
    // just recorded), then replay it: the replay fails free (it already paid
    // when it first applied — charging again is double-charge).
    let first = Transaction::sign(&alice, [0xB0; 32], 0, FLOOR, 0, 1, 1);
    assert_eq!(engine.apply_block_parallel_fees(&[first], TS).await.0, 1);
    let replay = Transaction::sign(&alice, [0xB0; 32], 0, FLOOR, 0, 1, 1);
    let (a3, f3, _, s3, fees3) = engine.apply_block_parallel_fees(&[replay], TS).await;
    assert_eq!((a3, f3), (0, 1));
    assert_eq!(s3, vec![false]);
    assert_eq!(fees3, vec![0]);

    let sender = engine.get_account(&from).await.unwrap();
    assert_eq!(sender.nonce, 1, "only the honest apply advanced the nonce");
    assert_eq!(
        sender.balance,
        BAL - FLOOR,
        "only the honest apply was charged"
    );
}

/// Mixed block through the shared transition core: a valid tx, an
/// underpriced success and an attributable failure. Every coin that leaves
/// a sender arrives somewhere (proposer or recipient): supply conserved.
#[tokio::test]
async fn fee_accounting_balances_with_floor_and_failure_fees() {
    let engine = engine_with_floor(FLOOR).await;
    let alice = user_key();
    let from = id_of(&alice);
    let proposer = user_key();
    let proposer_id = id_of(&proposer);
    engine.update_account(AccountState::new(from, BAL)).await;

    let valid = Transaction::sign(&alice, [0xB0; 32], 1_000, 600_000, 0, 1, 1);
    let cheap_ok = Transaction::sign(&alice, [0xB0; 32], 500, 100, 1, 1, 1);
    let fails = Transaction::sign_with_payload(&alice, [0xB0; 32], 0, 100, 2, 1, 1, oom_payload());
    let total_before = BAL; // proposer starts at 0
    let out = engine
        .apply_block_transition(&mk_block(vec![valid, cheap_ok, fails], &proposer), 0)
        .await;

    assert_eq!(out.status, vec![true, true, false]);
    assert_eq!(out.tx_fees, vec![600_000, FLOOR, FLOOR]);
    assert_eq!(out.fees_collected, 600_000 + FLOOR + FLOOR);

    let sender = engine.get_account(&from).await.unwrap();
    assert_eq!(
        sender.balance,
        BAL - (1_000 + 600_000) - (500 + FLOOR) - FLOOR
    );
    assert_eq!(
        sender.nonce, 3,
        "success, paid floor AND paid failure all advance"
    );
    let bob = engine.get_account(&[0xB0; 32]).await.unwrap();
    assert_eq!(bob.balance, 1_000 + 500);
    let proposer_acct = engine.get_account(&proposer_id).await.unwrap();
    assert_eq!(proposer_acct.balance, 600_000 + FLOOR + FLOOR);
    assert_eq!(
        sender.balance + bob.balance + proposer_acct.balance,
        total_before,
        "supply conserved: every debit arrived somewhere"
    );
}

/// The consensus D2 mirror escalates the floor after failures (same step as
/// admission) and clears on success — derived purely from applied blocks.
#[tokio::test]
async fn consensus_penalty_mirror_escalates_and_clears() {
    let engine = engine_with_floor(0).await; // floor = penalty only
    let alice = user_key();
    let from = id_of(&alice);
    engine.update_account(AccountState::new(from, BAL)).await;

    // Fail once at floor 0: pays 0 and - no pay, no state change - leaves
    // the nonce alone, but the mirror records the failure.
    let fail = Transaction::sign_with_payload(&alice, [0xB0; 32], 0, 0, 0, 1, 1, oom_payload());
    let (_, _, _, s1, fees1) = engine.apply_block_parallel_fees(&[fail], TS).await;
    assert_eq!(s1, vec![false]);
    assert_eq!(fees1, vec![0]);
    assert_eq!(
        engine.get_account(&from).await.unwrap().nonce,
        0,
        "unpaid failure burns no nonce"
    );
    // Next transaction is charged the one-step penalty as its floor.
    let punished = Transaction::sign(&alice, [0xB0; 32], 0, 100_000, 0, 1, 1);
    let (_, _, _, s2, fees2) = engine.apply_block_parallel_fees(&[punished], TS).await;
    assert_eq!(s2, vec![true]);
    assert_eq!(
        fees2,
        vec![GAS_BASIC_TRANSFER],
        "one failure escalates the floor by one bond step"
    );

    // Success clears the mirror: the floor is 0 again.
    let cleared = Transaction::sign(&alice, [0xB0; 32], 0, 0, 1, 1, 1);
    let (_, _, _, s3, fees3) = engine.apply_block_parallel_fees(&[cleared], TS).await;
    assert_eq!(s3, vec![true]);
    assert_eq!(fees3, vec![0], "one success clears the penalty");
}

/// PQ activation floor includes the 45k surcharge at apply, under the same
/// predicate admission uses.
#[tokio::test]
async fn pq_activation_floor_includes_surcharge_at_apply() {
    use stellereum::post_quantum::{
        derive_pq_address, PqScheme, PqSignatureEnvelope, DEFAULT_SALT,
    };
    use stellereum::sharding::Transaction as Tx;

    let engine = engine_with_floor(FLOOR).await;
    let seed = 0xA0u8;
    let pk = Tx::sample_falcon512_pubkey(seed);
    let from = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);
    engine.update_account(AccountState::new(from, BAL)).await;

    // Declares exactly the base floor: the surcharge is charged on top.
    let mut tx = Tx {
        from,
        to: [0xB0; 32],
        amount: 0,
        gas_limit: FLOOR,
        nonce: 0,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload: Vec::new(),

        priority_fee_per_gas: 0,
    };
    let msg = tx.signing_message();
    let sig = Tx::create_falcon512_test_signature(&pk, &msg, seed);
    tx.signature = PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk, sig).encode();
    assert!(tx.is_pq_activation());

    let (applied, failed, _, status, fees) = engine.apply_block_parallel_fees(&[tx], TS).await;
    assert_eq!((applied, failed), (1, 0));
    assert_eq!(status, vec![true]);
    assert_eq!(
        fees,
        vec![FLOOR + PQ_SURCHARGE],
        "activation pays base floor + surcharge"
    );
    let sender = engine.get_account(&from).await.unwrap();
    assert_eq!(sender.balance, BAL - FLOOR - PQ_SURCHARGE);
}

// ===========================================================================
// VALIDATE: refuse underpriced blocks, loudly
// ===========================================================================

fn single_validator() -> (SigningKey, ValidatorSet, Arc<InMemoryStateEngine>) {
    let key = SigningKey::generate(&mut OsRng);
    let me = id_of(&key);
    let engine = Arc::new(InMemoryStateEngine::new());
    let vset = ValidatorSet::from_list(vec![(me, 1)]);
    (key, vset, engine)
}

/// A honestly-proposed block at/above the floor validates.
#[tokio::test]
async fn validate_accepts_block_at_or_above_floor() {
    let (key, vset, engine) = single_validator();
    let me = id_of(&key);
    engine
        .update_account(AccountState::new(me, 10_000_000))
        .await;
    let mut rt = ValidatorRuntime::new(key.clone(), vset, engine.clone(), 1);
    rt.mempool.write().await.base_fee = FLOOR;

    // Funded above amount + floor, declared above the floor: packed + valid.
    let alice = user_key();
    let from = id_of(&alice);
    engine.update_account(AccountState::new(from, BAL)).await;
    let tx = Transaction::sign(&alice, [0xB0; 32], 1_000, FLOOR, 0, 1, 1);
    rt.mempool
        .write()
        .await
        .add_checked(tx, BAL)
        .expect("above-floor funded tx admitted");

    let block = rt.propose(TS).await.expect("propose must succeed");
    assert!(!block.transactions.is_empty());
    let root = engine.get_state_root().await;
    assert_eq!(block.state_root, root);
    rt.validate_proposal(&block, root)
        .expect("a block at the floor must validate");
}

/// A block carrying a valid-signature but underpriced transaction is refused,
/// naming the transaction hash.
#[tokio::test]
async fn validate_refuses_underpriced_block_naming_tx() {
    let (key, vset, engine) = single_validator();
    let me = id_of(&key);
    engine
        .update_account(AccountState::new(me, 10_000_000))
        .await;
    let mut rt = ValidatorRuntime::new(key.clone(), vset, engine.clone(), 1);
    rt.mempool.write().await.base_fee = FLOOR;

    let alice = user_key();
    let from = id_of(&alice);
    engine.update_account(AccountState::new(from, BAL)).await;
    // Genuine above-floor block first (fixes height/root/prev/proposer).
    let good = Transaction::sign(&alice, [0xB0; 32], 1_000, FLOOR, 0, 1, 1);
    rt.mempool
        .write()
        .await
        .add_checked(good, BAL)
        .expect("admitted");
    let genuine = rt.propose(TS).await.expect("propose must succeed");
    let root = engine.get_state_root().await;
    rt.validate_proposal(&genuine, root)
        .expect("genuine block validates");

    // Byzantine swap: same envelope, one underpriced (but correctly signed
    // and funded) transaction, re-signed by the real proposer.
    let cheap = Transaction::sign(&alice, [0xB0; 32], 1_000, 100, 0, 1, 1);
    let cheap_hash = hex::encode(cheap.compute_tx_hash());
    let mut bad = genuine.clone();
    bad.transactions = vec![cheap];
    // The proposer re-commits to the order it packed: the order root is part
    // of the signed hash, so a Byzantine proposer updates it too (that is
    // exactly what keeps the ORDER commitment meaningful).
    bad.order_merkle_root = stellereum::mev::compute_order_merkle_root(&bad.transactions);
    bad.sign_block(&key);
    let err = rt
        .validate_proposal(&bad, root)
        .expect_err("underpriced block must be refused");
    assert!(
        err.contains("fee floor"),
        "refusal must name the rule: {err}"
    );
    assert!(
        err.contains(&cheap_hash),
        "refusal must name the transaction: {err}"
    );
}

/// The surcharge is part of the validate floor: an activation transaction
/// covering the base but not the 45k surcharge is refused.
#[tokio::test]
async fn validate_refuses_activation_missing_surcharge() {
    use stellereum::post_quantum::{
        derive_pq_address, PqScheme, PqSignatureEnvelope, DEFAULT_SALT,
    };
    use stellereum::sharding::Transaction as Tx;

    let (key, vset, engine) = single_validator();
    let me = id_of(&key);
    engine
        .update_account(AccountState::new(me, 10_000_000))
        .await;
    let mut rt = ValidatorRuntime::new(key.clone(), vset, engine.clone(), 1);
    rt.mempool.write().await.base_fee = FLOOR;

    // Genuine block for a correct envelope.
    let alice = user_key();
    engine
        .update_account(AccountState::new(id_of(&alice), BAL))
        .await;
    let good = Transaction::sign(&alice, [0xB0; 32], 1_000, FLOOR, 0, 1, 1);
    rt.mempool
        .write()
        .await
        .add_checked(good, BAL)
        .expect("admitted");
    let genuine = rt.propose(TS).await.expect("propose must succeed");
    let root = engine.get_state_root().await;

    // Activation declaring base but not base + surcharge.
    let seed = 0xA1u8;
    let pk = Tx::sample_falcon512_pubkey(seed);
    let from = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);
    let mut act = Tx {
        from,
        to: [0xB0; 32],
        amount: 0,
        gas_limit: FLOOR,
        nonce: 0,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload: Vec::new(),

        priority_fee_per_gas: 0,
    };
    let msg = act.signing_message();
    let sig = Tx::create_falcon512_test_signature(&pk, &msg, seed);
    act.signature = PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk, sig).encode();
    assert!(act.is_pq_activation());

    let mut bad = genuine.clone();
    bad.transactions = vec![act];
    bad.order_merkle_root = stellereum::mev::compute_order_merkle_root(&bad.transactions);
    bad.sign_block(&key);
    let err = rt
        .validate_proposal(&bad, root)
        .expect_err("activation missing the surcharge must be refused");
    assert!(err.contains("fee floor"), "must name the rule: {err}");
    assert!(err.contains("45000"), "must show the surcharge leg: {err}");
}

/// The D2 penalty is part of the validate floor: after a recorded failure
/// the sender must over-post, exactly like admission.
#[tokio::test]
async fn validate_enforces_failure_penalty_like_admission() {
    let (key, vset, engine) = single_validator();
    let me = id_of(&key);
    engine
        .update_account(AccountState::new(me, 10_000_000))
        .await;
    let mut rt = ValidatorRuntime::new(key.clone(), vset, engine.clone(), 1);

    let alice = user_key();
    let from = id_of(&alice);
    engine.update_account(AccountState::new(from, BAL)).await;
    // Admit the envelope block tx BEFORE the penalty lands (`add` enforces
    // the current floor, so it must precede the failure feedback).
    let ok_tx = Transaction::sign(&alice, [0xB0; 32], 1, FLOOR, 0, 1, 1);
    rt.mempool
        .write()
        .await
        .add(ok_tx)
        .expect("at-floor tx admitted before any penalty");
    {
        let mut mp = rt.mempool.write().await;
        mp.base_fee = FLOOR;
        // One recorded failure: penalty is one bond step (280k).
        mp.note_apply_feedback(&[from], &[]);
        assert_eq!(mp.effective_floor(&from), FLOOR + GAS_BASIC_TRANSFER);
    }
    // Direct admission would refuse this (penalty not covered)...
    let penalised = Transaction::sign(&alice, [0xB0; 32], 1, FLOOR, 1, 1, 1);
    assert_eq!(
        rt.mempool.write().await.add_checked(penalised.clone(), BAL),
        Err(stellereum::mempool::MempoolError::FeeTooLow)
    );

    // ...and so must validation of a block carrying it.
    let genuine = rt.propose(TS).await.expect("propose must succeed");
    let root = engine.get_state_root().await;
    let mut bad = genuine.clone();
    bad.transactions = vec![penalised];
    bad.order_merkle_root = stellereum::mev::compute_order_merkle_root(&bad.transactions);
    bad.sign_block(&key);
    let err = rt
        .validate_proposal(&bad, root)
        .expect_err("penalty-underpriced block must be refused");
    assert!(err.contains("fee floor"), "must name the rule: {err}");
    assert!(err.contains("penalty"), "must show the penalty leg: {err}");

    // Covering base + penalty validates.
    let rich = Transaction::sign(&alice, [0xB0; 32], 1, FLOOR + GAS_BASIC_TRANSFER, 1, 1, 1);
    let mut good = genuine.clone();
    good.transactions = vec![rich];
    good.order_merkle_root = stellereum::mev::compute_order_merkle_root(&good.transactions);
    good.sign_block(&key);
    rt.validate_proposal(&good, root)
        .expect("base + penalty must validate");
}
