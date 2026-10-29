//! Bridge challenge truth gate (audit B2): resolve-time re-verification.
//!
//! The old revoke rule paid the challenger `bond + 10%` on ANY past-deadline
//! resolve with no evidence in the payload, so a false challenger who
//! suppressed the recipient's confirm evidence for the 1h window turned an
//! honest deposit into a profitable theft. The fix gates the payout on a
//! TRUTH CHECK through the same adapter verification the deposit path uses:
//!
//! * FALSE challenge — resolve carries evidence that VERIFIES: confirm,
//!   challenger bond SLASHED to the recipient, no 10% reward (no profit).
//! * TRUE challenge — resolve carries evidence that FAILS, past the
//!   deadline: revoke pays bond + 10% as before.
//! * UNAVAILABLE evidence — resolve carries NOTHING, past the deadline:
//!   DEFER (deadline pushed out, bounded, no coin moves), then REFUSE LOUDLY
//!   with no payout. Never pays on missing evidence.
//!
//! Every test runs through `apply_block_transition`, the same entry point
//! consensus uses — no direct `plan()` calls.

use ed25519_dalek::{Signer, SigningKey};
use stellereum::bridge::{
    bridge_adapters::DepositEvidence, challenge_bond_for, BridgeIntent, SupportedChain,
    TeleportBridgeEngine, CHALLENGE_MAX_AGE_SECS, DISPUTE_WINDOW_SECS, MAX_RESOLVE_DEFERRALS,
    RESOLVE_DEFER_SECS,
};
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::staking::{MIN_VALIDATOR_BOND, STELL_MIN_BOND_BUFFER};
use stellereum::state_engine::InMemoryStateEngine;
use stellereum::svm::{OpCode, GAS_BASIC_TRANSFER, GAS_BRIDGE_INTENT};

/// Fixed, realistic block timestamp. Never 0: 0 is exactly the bug I12 pins.
const TS: u64 = 1_760_000_000;
/// Nano-STELL per STELL, for readable amounts.
const STELL: u64 = 1_000_000_000;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

async fn balance(e: &InMemoryStateEngine, addr: &[u8; 32]) -> u64 {
    e.get_account(addr).await.map(|a| a.balance).unwrap_or(0)
}

/// Fund and bond `n` validators, so the COMMITTED relayer set has `n` members.
async fn setup(n: usize) -> (InMemoryStateEngine, Vec<SigningKey>) {
    let e = InMemoryStateEngine::new();
    let mut keys = Vec::with_capacity(n);
    for i in 0..n {
        let k = key(0xA0 + i as u8);
        let pk = k.verifying_key().to_bytes();
        e.credit_native(&pk, 10 * MIN_VALIDATOR_BOND)
            .await
            .expect("fund the validator");
        e.staking_write()
            .await
            .bond(pk, MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER, 0)
            .expect("bond it into the committed ledger");
        keys.push(k);
    }
    (e, keys)
}

async fn fund(e: &InMemoryStateEngine, addr: &[u8; 32], amount: u64) {
    e.credit_native(addr, amount).await.expect("fund");
}

fn deposit(source_tx_hash: [u8; 32], recipient: [u8; 32], amount: u64) -> BridgeIntent {
    BridgeIntent::Deposit {
        chain: SupportedChain::Ton,
        source_tx_hash,
        recipient,
        amount,
    }
}

fn attest(dep: &BridgeIntent, signers: &[SigningKey]) -> BridgeIntent {
    let event = dep.deposit_event(Vec::new()).expect("deposit event");
    let msg = TeleportBridgeEngine::deposit_signing_message(&event);
    let signatures = signers
        .iter()
        .map(|k| (k.verifying_key().to_bytes(), k.sign(&msg).to_vec()))
        .collect();
    let source_tx_hash = match dep {
        BridgeIntent::Deposit { source_tx_hash, .. } => *source_tx_hash,
        other => panic!("attest() only pairs with a Deposit: {other:?}"),
    };
    BridgeIntent::Attest {
        source_tx_hash,
        signatures,
    }
}

/// A quorum-attested evidence bundle for (`hash`, `recipient`, `amount`) —
/// the same signatures the deposit quorum used, replayed as evidence.
fn quorum_proof(
    hash: [u8; 32],
    recipient: [u8; 32],
    amount: u64,
    signers: &[SigningKey],
) -> BridgeIntent {
    let dep = deposit(hash, recipient, amount);
    let att = attest(&dep, signers);
    let signatures = match att {
        BridgeIntent::Attest { signatures, .. } => signatures,
        _ => unreachable!(),
    };
    BridgeIntent::DepositProof {
        source_tx_hash: hash,
        evidence: Box::new(DepositEvidence::QuorumAttested { signatures }),
    }
}

/// Shape-valid but cryptographically FAILING evidence: an outsider key with
/// junk bytes. Passes the VM shape check (non-empty), fails adapter
/// verification — the TRUE-challenge (fraud) signal the revoke payout needs.
fn failing_proof(hash: [u8; 32]) -> BridgeIntent {
    BridgeIntent::DepositProof {
        source_tx_hash: hash,
        evidence: Box::new(DepositEvidence::QuorumAttested {
            signatures: vec![([0xEEu8; 32], vec![0u8; 64])],
        }),
    }
}

fn bridge_tx(payer: &SigningKey, nonce: u64, ops: Vec<OpCode>) -> Transaction {
    let gas = GAS_BRIDGE_INTENT * ops.len() as u64 + 1_000;
    Transaction::sign_with_payload(
        payer,
        payer.verifying_key().to_bytes(),
        0,
        gas,
        nonce,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        ops,
    )
}

fn bridge_block(height: u64, timestamp: u64, txs: Vec<Transaction>, proposer: [u8; 32]) -> Block {
    let order_merkle_root = stellereum::mev::compute_order_merkle_root(&txs);
    Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: txs,
        cross_shard_out: vec![],
        timestamp,
        proposer,
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
    }
}

fn ops_list(intents: Vec<BridgeIntent>) -> Vec<OpCode> {
    intents
        .into_iter()
        .map(|i| OpCode::SysCallBridge(Box::new(i)))
        .collect()
}

/// Settle a quorum deposit and return nothing (precondition helper).
async fn settle_deposit(
    e: &InMemoryStateEngine,
    vals: &[SigningKey],
    payer_pk: [u8; 32],
    hash: [u8; 32],
    recipient: [u8; 32],
    amount: u64,
) {
    // The wrapping-tx payer (key 0x03) needs gas money of its own.
    fund(e, &key(0x03).verifying_key().to_bytes(), 1_000_000).await;
    let dep = deposit(hash, recipient, amount);
    let att = attest(&dep, &vals[..2]);
    let tx = bridge_tx(&key(0x03), 0, ops_list(vec![att, dep]));
    let out = e
        .apply_block_transition(&bridge_block(1, TS, vec![tx], payer_pk), 0)
        .await;
    assert_eq!(out.status, vec![true], "setup deposit must apply");
    assert_eq!(balance(e, &recipient).await, amount);
}

// ===========================================================================
// 1. FALSE challenge: evidence verifies fine => bond SLASHED, no profit —
//    even when the resolve lands past the deadline (suppression fails).
// ===========================================================================

#[tokio::test]
async fn false_challenge_is_slashed_even_past_deadline_no_profit() {
    let (e, vals) = setup(3).await;
    let payer_pk = key(0x03).verifying_key().to_bytes();
    let challenger = key(0xC0);
    let challenger_pk = challenger.verifying_key().to_bytes();
    // The audit's whale: 50k STELL deposit, 500 STELL bond, 5k STELL would-be
    // profit under the old empty-resolve rule.
    let amount = 50_000 * STELL;
    let bond = challenge_bond_for(amount);
    assert_eq!(bond, 500 * STELL);
    fund(&e, &challenger_pk, 10_000 * STELL).await;
    let recipient = [0xADu8; 32];
    let hash = [0x73u8; 32];
    settle_deposit(&e, &vals, payer_pk, hash, recipient, amount).await;

    // False challenge freezes the honest deposit.
    let tx_c = bridge_tx(
        &challenger,
        0,
        ops_list(vec![BridgeIntent::Challenge {
            source_tx_hash: hash,
        }]),
    );
    let out = e
        .apply_block_transition(&bridge_block(2, TS + 10, vec![tx_c], challenger_pk), 0)
        .await;
    assert_eq!(out.status, vec![true]);
    assert_eq!(balance(&e, &recipient).await, 0, "clawed back while open");

    // Suppression window passes with no confirm — then the evidence lands
    // LATE, past the deadline. Truth still beats timing: confirm + slash.
    let tx_r = bridge_tx(
        &challenger,
        1,
        ops_list(vec![
            quorum_proof(hash, recipient, amount, &vals),
            BridgeIntent::Resolve { dispute_id: 0 },
        ]),
    );
    let out = e
        .apply_block_transition(
            &bridge_block(3, TS + 10 + DISPUTE_WINDOW_SECS, vec![tx_r], challenger_pk),
            0,
        )
        .await;
    assert_eq!(out.status, vec![true], "late valid evidence still confirms");
    assert_eq!(
        balance(&e, &recipient).await,
        amount + bond,
        "clawback returns plus the slashed bond as freeze compensation"
    );
    assert_eq!(
        balance(&e, &challenger_pk).await,
        10_000 * STELL - bond,
        "false challenger nets -bond (the 5k reward never pays): unprofitable"
    );
    {
        let br = e.bridge_read().await;
        let d = br.disputes.get(&0).unwrap();
        assert!(d.resolved && d.confirmed);
    }
}

// ===========================================================================
// 2. TRUE challenge: evidence present but FAILING, past the deadline =>
//    revoke pays bond + 10% as before.
// ===========================================================================

#[tokio::test]
async fn failing_evidence_past_deadline_never_pays_reward() {
    let (e, vals) = setup(3).await;
    let payer_pk = key(0x03).verifying_key().to_bytes();
    let challenger = key(0xC0);
    let challenger_pk = challenger.verifying_key().to_bytes();
    fund(&e, &challenger_pk, 10 * STELL).await;
    let recipient = [0xADu8; 32];
    let amount = 100 * STELL;
    let bond = challenge_bond_for(amount);
    let hash = [0x73u8; 32];
    settle_deposit(&e, &vals, payer_pk, hash, recipient, amount).await;

    let tx_c = bridge_tx(
        &challenger,
        0,
        ops_list(vec![BridgeIntent::Challenge {
            source_tx_hash: hash,
        }]),
    );
    let out = e
        .apply_block_transition(&bridge_block(2, TS + 10, vec![tx_c], challenger_pk), 0)
        .await;
    assert_eq!(out.status, vec![true]);

    // SEC-01 FIX: Submitting failing evidence past the deadline does NOT trigger
    // fraud payout. It simply defers (Path 3) without paying a single coin to the challenger.
    let tx_r = bridge_tx(
        &challenger,
        1,
        ops_list(vec![
            failing_proof(hash),
            BridgeIntent::Resolve { dispute_id: 0 },
        ]),
    );
    let out = e
        .apply_block_transition(
            &bridge_block(3, TS + 10 + DISPUTE_WINDOW_SECS, vec![tx_r], challenger_pk),
            0,
        )
        .await;
    assert_eq!(
        out.status,
        vec![true],
        "resolve with unverified evidence defers"
    );
    // Challenger is STILL down the bond and nets ZERO reward!
    assert_eq!(
        balance(&e, &challenger_pk).await,
        10 * STELL - bond,
        "challenger still down the bond: ZERO profit from fabricated failing evidence"
    );
    assert_eq!(
        balance(&e, &recipient).await,
        0,
        "credit still parked while open"
    );
    {
        let br = e.bridge_read().await;
        let d = br.disputes.get(&0).unwrap();
        assert!(!d.resolved, "dispute deferred, NOT resolved as fraud");
        let escrow = balance(&e, &stellereum::bridge::BRIDGE_ESCROW).await;
        assert_eq!(
            escrow,
            amount + bond,
            "escrow still holds both deposit and bond"
        );
    }
}

// ===========================================================================
// 3. UNAVAILABLE evidence: past-deadline empty resolves DEFER (bounded),
//    then REFUSE with no payout — and honest recovery still works after.
// ===========================================================================

#[tokio::test]
async fn suppressed_evidence_resolve_defers_then_refuses_without_payout() {
    let (e, vals) = setup(3).await;
    let payer_pk = key(0x03).verifying_key().to_bytes();
    let challenger = key(0xC0);
    let challenger_pk = challenger.verifying_key().to_bytes();
    fund(&e, &challenger_pk, 10 * STELL).await;
    let recipient = [0xADu8; 32];
    let amount = 100 * STELL;
    let bond = challenge_bond_for(amount);
    let hash = [0x73u8; 32];
    settle_deposit(&e, &vals, payer_pk, hash, recipient, amount).await;

    // Challenge filed near the end of the challenge-age window, so the
    // deferral cap binds after exactly MAX_RESOLVE_DEFERRALS extensions:
    // D0 = CH_T + WINDOW, cap = TS + MAX_AGE + WINDOW*(1+K).
    let challenge_at = TS + CHALLENGE_MAX_AGE_SECS - 100;
    let tx_c = bridge_tx(
        &challenger,
        0,
        ops_list(vec![BridgeIntent::Challenge {
            source_tx_hash: hash,
        }]),
    );
    let out = e
        .apply_block_transition(&bridge_block(2, challenge_at, vec![tx_c], challenger_pk), 0)
        .await;
    assert_eq!(out.status, vec![true]);
    let d0 = challenge_at + DISPUTE_WINDOW_SECS;
    assert_eq!(e.bridge_read().await.disputes.get(&0).unwrap().deadline, d0);

    // Empty resolves past the deadline: each DEFERS (applies, no payout).
    let mut nonce = 1u64;
    let mut height = 3u64;
    let mut now = d0;
    let mut defers = 0u32;
    for _ in 0..10 {
        let tx_r = bridge_tx(
            &challenger,
            nonce,
            ops_list(vec![BridgeIntent::Resolve { dispute_id: 0 }]),
        );
        let out = e
            .apply_block_transition(&bridge_block(height, now, vec![tx_r], challenger_pk), 0)
            .await;
        if out.status != vec![true] {
            break;
        }
        defers += 1;
        nonce += 1;
        height += 1;
        let d = e.bridge_read().await.disputes.get(&0).cloned().unwrap();
        assert!(!d.resolved, "a defer never settles the dispute");
        assert_eq!(
            d.deadline,
            now + RESOLVE_DEFER_SECS,
            "each defer pushes the deadline one window out"
        );
        // No coin moves on a defer: challenger still down the bond,
        // recipient still clawed back, escrow still holds both.
        assert_eq!(balance(&e, &challenger_pk).await, 10 * STELL - bond);
        assert_eq!(balance(&e, &recipient).await, 0);
        assert_eq!(
            balance(&e, &stellereum::bridge::BRIDGE_ESCROW).await,
            amount + bond
        );
        now = d.deadline;
    }
    assert_eq!(
        defers, MAX_RESOLVE_DEFERRALS,
        "deferral is bounded: exactly K extensions, then the resolve refuses"
    );
    // Terminal: one more empty resolve past the bound REFUSES (no payout).
    // F-01 note: a refused resolve is an attributable failure, and the loop's
    // first refusal already recorded one D2 penalty step for the challenger,
    // so this refusal PAYS that floor step (nonce advances). Payer and
    // proposer coincide here, so the fee self-rebates: no bridge coin moves,
    // only the nonce does. A state-root-equality check would be stale.
    //
    // The retry must carry the challenger's CURRENT nonce: the loop's own
    // refusal already consumed one (a refused transaction still advances the
    // nonce), so the stale `nonce` would be refused at ADMISSION - free, and
    // it would not exercise the paid-refusal path at all.
    let challenger_before = e.get_account(&challenger_pk).await.unwrap();
    let tx_last = bridge_tx(
        &challenger,
        challenger_before.nonce,
        ops_list(vec![BridgeIntent::Resolve { dispute_id: 0 }]),
    );
    let out = e
        .apply_block_transition(&bridge_block(height, now, vec![tx_last], challenger_pk), 0)
        .await;
    assert_eq!(
        out.status,
        vec![false],
        "evidence unavailable + bound exhausted: fail closed, no payout"
    );
    assert_eq!(
        out.tx_fees,
        vec![GAS_BASIC_TRANSFER],
        "paid refusal: exactly one D2 penalty step (fail-closed, never free, never a payout)"
    );
    let challenger_after = e.get_account(&challenger_pk).await.unwrap();
    assert_eq!(
        challenger_after.nonce,
        challenger_before.nonce + 1,
        "paid refusal consumes its nonce"
    );
    assert_eq!(
        challenger_after.balance, challenger_before.balance,
        "payer == proposer: the refusal fee self-rebates, no bridge coin moves"
    );
    assert_eq!(balance(&e, &challenger_pk).await, 10 * STELL - bond);
    assert_eq!(balance(&e, &recipient).await, 0);
    assert_eq!(
        balance(&e, &stellereum::bridge::BRIDGE_ESCROW).await,
        amount + bond,
        "escrow still holds both legs: refusal settles nothing"
    );
    assert!(
        !e.bridge_read().await.disputes.get(&0).unwrap().resolved,
        "refusal never settles the dispute"
    );

    // Honest recovery is never bricked: valid evidence confirms even after
    // the deferral bound is exhausted — and the suppressor is slashed.
    let resolver = key(0xD0);
    let resolver_pk = resolver.verifying_key().to_bytes();
    fund(&e, &resolver_pk, 10 * STELL).await;
    let tx_rec = bridge_tx(
        &resolver,
        0,
        ops_list(vec![
            quorum_proof(hash, recipient, amount, &vals),
            BridgeIntent::Resolve { dispute_id: 0 },
        ]),
    );
    let out = e
        .apply_block_transition(
            &bridge_block(height + 1, now + 1, vec![tx_rec], resolver_pk),
            0,
        )
        .await;
    assert_eq!(out.status, vec![true], "late truth still confirms");
    assert_eq!(
        balance(&e, &recipient).await,
        amount + bond,
        "clawback returns plus the slashed bond"
    );
    assert!(e.bridge_read().await.disputes.get(&0).unwrap().confirmed);
}

// ===========================================================================
// 4. Failing evidence BEFORE the deadline revokes nothing (window open).
// ===========================================================================

#[tokio::test]
async fn failing_evidence_before_deadline_revokes_nothing() {
    let (e, vals) = setup(3).await;
    let payer_pk = key(0x03).verifying_key().to_bytes();
    let challenger = key(0xC0);
    let challenger_pk = challenger.verifying_key().to_bytes();
    fund(&e, &challenger_pk, 10 * STELL).await;
    let recipient = [0xADu8; 32];
    let amount = 100 * STELL;
    let bond = challenge_bond_for(amount);
    let hash = [0x73u8; 32];
    settle_deposit(&e, &vals, payer_pk, hash, recipient, amount).await;

    let tx_c = bridge_tx(
        &challenger,
        0,
        ops_list(vec![BridgeIntent::Challenge {
            source_tx_hash: hash,
        }]),
    );
    let out = e
        .apply_block_transition(&bridge_block(2, TS + 10, vec![tx_c], challenger_pk), 0)
        .await;
    assert_eq!(out.status, vec![true]);

    // Garbage evidence while the window is still open: refused, dispute open.
    let settled = e.get_state_root().await;
    let tx_r = bridge_tx(
        &challenger,
        1,
        ops_list(vec![
            failing_proof(hash),
            BridgeIntent::Resolve { dispute_id: 0 },
        ]),
    );
    let out = e
        .apply_block_transition(&bridge_block(3, TS + 20, vec![tx_r], challenger_pk), 0)
        .await;
    assert_eq!(
        out.status,
        vec![false],
        "failing evidence alone revokes only at/after the deadline"
    );
    // The refusal moves NO BRIDGE COIN: the deposit stays clawed back in
    // escrow, the challenger's bond stays locked and the dispute stays open.
    // (The STATE ROOT does move: a refused transaction is an attributable
    // failure, so it pays the D2 floor step and consumes its nonce - that is
    // the engine's fail-closed rule, not a bridge effect. Payer == proposer
    // here, so the fee self-rebates and no balance changes.)
    assert_eq!(balance(&e, &recipient).await, 0, "the credit stays parked");
    assert_eq!(
        balance(&e, &challenger_pk).await,
        10 * STELL - bond,
        "the bond stays locked: a refused resolve pays the challenger nothing"
    );
    assert_eq!(
        balance(&e, &stellereum::bridge::BRIDGE_ESCROW).await,
        amount + bond,
        "the escrow still holds the deposit and the bond"
    );
    assert!(!e.bridge_read().await.disputes.get(&0).unwrap().resolved);
    assert_ne!(
        e.get_state_root().await,
        settled,
        "the refusal itself is charged (nonce + D2 step), but it moves no bridge coin"
    );
}

// ===========================================================================
// 5. Honest relay unaffected: plain quorum + evidence-path deposits credit
//    with no dispute anywhere in the picture.
// ===========================================================================

#[tokio::test]
async fn honest_relay_unaffected_by_the_truth_gate() {
    let (e, vals) = setup(3).await;
    let payer_pk = key(0x03).verifying_key().to_bytes();
    fund(&e, &payer_pk, 1_000_000).await;

    // Quorum path, no challenge: credits exactly as before.
    let recipient_q = [0xC1u8; 32];
    let amount_q = 77 * STELL;
    let hash_q = [0x81u8; 32];
    let dep_q = deposit(hash_q, recipient_q, amount_q);
    let att_q = attest(&dep_q, &vals[..2]);
    let tx = bridge_tx(&key(0x03), 0, ops_list(vec![att_q, dep_q]));
    let out = e
        .apply_block_transition(&bridge_block(1, TS, vec![tx], payer_pk), 0)
        .await;
    assert_eq!(
        out.status,
        vec![true],
        "honest quorum deposit still credits"
    );
    assert_eq!(balance(&e, &recipient_q).await, amount_q);

    // Evidence path, no challenge: credits exactly as before.
    let recipient_e = [0xC2u8; 32];
    let amount_e = 55 * STELL;
    let hash_e = [0x82u8; 32];
    let tx = bridge_tx(
        &key(0x03),
        1,
        ops_list(vec![
            quorum_proof(hash_e, recipient_e, amount_e, &vals),
            deposit(hash_e, recipient_e, amount_e),
        ]),
    );
    let out = e
        .apply_block_transition(&bridge_block(2, TS + 1, vec![tx], payer_pk), 0)
        .await;
    assert_eq!(
        out.status,
        vec![true],
        "honest evidence deposit still credits"
    );
    assert_eq!(balance(&e, &recipient_e).await, amount_e);

    assert!(
        e.bridge_read().await.disputes.is_empty(),
        "no dispute exists without a challenge"
    );
}
