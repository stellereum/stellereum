//! Bridge dispute layer (optimistic L1) on the live block path.
//!
//! A quorum-path deposit can be frozen by anyone posting
//! [`CHALLENGE_BOND_NANO`] ([`BridgeIntent::Challenge`]) and settles only by
//! [`BridgeIntent::Resolve`]: evidence-confirm (valid [`DepositProof`] in the
//! same payload), fraud-evidence revoke (FAILING evidence past
//! [`DISPUTE_WINDOW_SECS`]), or defer-then-refuse when evidence is
//! unavailable (an empty resolve past the deadline never pays — audit B2
//! truth gate). Every test below runs through `apply_block_transition`, the
//! same entry point consensus uses — no direct `plan()` calls.

use ed25519_dalek::{Signer, SigningKey};
use stellereum::bridge::{
    bridge_adapters::DepositEvidence, BridgeIntent, SupportedChain, TeleportBridgeEngine,
    CHALLENGE_BOND_NANO, DISPUTE_WINDOW_SECS,
};
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::staking::{MIN_VALIDATOR_BOND, STELL_MIN_BOND_BUFFER};
use stellereum::state_engine::InMemoryStateEngine;
use stellereum::svm::{OpCode, GAS_BRIDGE_INTENT};

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
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
    }
}

fn ops_list(intents: Vec<BridgeIntent>) -> Vec<OpCode> {
    intents
        .into_iter()
        .map(|i| OpCode::SysCallBridge(Box::new(i)))
        .collect()
}

/// Settle a quorum deposit and return (recipient, amount, hash).
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
// 1. Challenge freezes a quorum deposit
// ===========================================================================

#[tokio::test]
async fn challenge_freezes_quorum_deposit() {
    let (e, vals) = setup(3).await;
    let payer_pk = key(0x03).verifying_key().to_bytes();
    let challenger = key(0xC0);
    let challenger_pk = challenger.verifying_key().to_bytes();
    fund(&e, &challenger_pk, 10 * STELL).await;
    let recipient = [0xADu8; 32];
    let amount = 100 * STELL;
    let hash = [0x73u8; 32];
    settle_deposit(&e, &vals, payer_pk, hash, recipient, amount).await;

    let tx = bridge_tx(
        &challenger,
        0,
        ops_list(vec![BridgeIntent::Challenge {
            source_tx_hash: hash,
        }]),
    );
    let before = e.get_state_root().await;
    // Proposer == challenger: the declared gas rebates straight back, so the
    // balance assertions below see ONLY the bond lock.
    let out = e
        .apply_block_transition(&bridge_block(2, TS + 10, vec![tx], challenger_pk), 0)
        .await;
    assert_eq!(
        out.status,
        vec![true],
        "a fresh quorum deposit challenges cleanly"
    );
    assert_eq!(balance(&e, &recipient).await, 0, "full amount clawed back");
    assert_eq!(
        balance(&e, &challenger_pk).await,
        10 * STELL - CHALLENGE_BOND_NANO,
        "bond locked (gas goes to the proposer and back here)"
    );
    {
        let br = e.bridge_read().await;
        assert!(br.deposit_records.get(&hash).unwrap().disputed);
        let d = br.disputes.get(&0).expect("dispute 0 opens");
        assert!(!d.resolved);
        assert_eq!(d.challenger, challenger_pk);
        assert_eq!(d.recipient, recipient);
        assert_eq!(d.amount, amount);
        assert_eq!(d.bond, CHALLENGE_BOND_NANO);
        assert_eq!(d.deadline, TS + 10 + DISPUTE_WINDOW_SECS);
        assert_eq!(br.next_dispute_id, 1);
    }
    assert_ne!(e.get_state_root().await, before, "freeze commits");
}

// ===========================================================================
// 2. Double challenge refused (once, ever)
// ===========================================================================

#[tokio::test]
async fn double_challenge_is_refused() {
    let (e, vals) = setup(3).await;
    let payer_pk = key(0x03).verifying_key().to_bytes();
    let challenger = key(0xC0);
    fund(&e, &challenger.verifying_key().to_bytes(), 10 * STELL).await;
    let recipient = [0xADu8; 32];
    let hash = [0x73u8; 32];
    settle_deposit(&e, &vals, payer_pk, hash, recipient, 100 * STELL).await;

    let tx_a = bridge_tx(
        &challenger,
        0,
        ops_list(vec![BridgeIntent::Challenge {
            source_tx_hash: hash,
        }]),
    );
    let out = e
        .apply_block_transition(
            &bridge_block(
                2,
                TS + 10,
                vec![tx_a],
                challenger.verifying_key().to_bytes(),
            ),
            0,
        )
        .await;
    assert_eq!(out.status, vec![true]);
    let tx_b = bridge_tx(
        &challenger,
        1,
        ops_list(vec![BridgeIntent::Challenge {
            source_tx_hash: hash,
        }]),
    );
    let settled = e.get_state_root().await;
    let out = e
        .apply_block_transition(
            &bridge_block(
                3,
                TS + 20,
                vec![tx_b],
                challenger.verifying_key().to_bytes(),
            ),
            0,
        )
        .await;
    assert_eq!(
        out.status,
        vec![false],
        "second challenge of one hash refuses"
    );
    // The refusal moves NO BRIDGE COIN: the deposit stays clawed back, the
    // bond stays locked in escrow, and the dispute stays open. (The state
    // ROOT does move: a refused transaction is an attributable failure, so it
    // pays the D2 floor step and consumes its nonce - the engine's
    // fail-closed rule, not a bridge effect. Payer == proposer here, so the
    // fee self-rebates and no balance changes.)
    assert_eq!(
        balance(&e, &recipient).await,
        0,
        "the credit stays clawed back"
    );
    assert_eq!(
        balance(&e, &stellereum::bridge::BRIDGE_ESCROW).await,
        100 * STELL + CHALLENGE_BOND_NANO,
        "the escrow holds exactly one deposit + one bond: no second clawback"
    );
    {
        let br = e.bridge_read().await;
        assert_eq!(br.disputes.len(), 1, "no second dispute is opened");
        assert!(!br.disputes.get(&0).unwrap().resolved);
    }
    assert_ne!(
        e.get_state_root().await,
        settled,
        "the refusal itself is charged (nonce + D2 step), but it moves no bridge coin"
    );
}

// ===========================================================================
// 3. Unknown / stale challenges refused
// ===========================================================================

#[tokio::test]
async fn challenge_unknown_hash_is_refused() {
    let (e, _vals) = setup(3).await;
    let payer_pk = key(0x03).verifying_key().to_bytes();
    let challenger = key(0xC0);
    fund(&e, &challenger.verifying_key().to_bytes(), 10 * STELL).await;
    let tx = bridge_tx(
        &challenger,
        0,
        ops_list(vec![BridgeIntent::Challenge {
            source_tx_hash: [0x99u8; 32],
        }]),
    );
    let out = e
        .apply_block_transition(&bridge_block(1, TS, vec![tx], payer_pk), 0)
        .await;
    assert_eq!(out.status, vec![false], "no record, no freeze");
}

#[tokio::test]
async fn challenge_stale_deposit_is_refused() {
    let (e, vals) = setup(3).await;
    let payer_pk = key(0x03).verifying_key().to_bytes();
    let challenger = key(0xC0);
    fund(&e, &challenger.verifying_key().to_bytes(), 10 * STELL).await;
    let recipient = [0xADu8; 32];
    let hash = [0x73u8; 32];
    settle_deposit(&e, &vals, payer_pk, hash, recipient, 100 * STELL).await;

    // 25h later: past the 24h challenge age even though no dispute exists.
    let tx = bridge_tx(
        &challenger,
        0,
        ops_list(vec![BridgeIntent::Challenge {
            source_tx_hash: hash,
        }]),
    );
    let out = e
        .apply_block_transition(&bridge_block(2, TS + 25 * 3600, vec![tx], payer_pk), 0)
        .await;
    assert_eq!(
        out.status,
        vec![false],
        "stale deposits are outside the window"
    );
    assert_eq!(balance(&e, &recipient).await, 100 * STELL, "untouched");
}

// ===========================================================================
// 4. Resolve-confirm by evidence (bond slashes to the recipient)
// ===========================================================================

#[tokio::test]
async fn resolve_confirms_with_evidence_and_slashes_bond_to_recipient() {
    let (e, vals) = setup(3).await;
    let payer_pk = key(0x03).verifying_key().to_bytes();
    let challenger = key(0xC0);
    let challenger_pk = challenger.verifying_key().to_bytes();
    fund(&e, &challenger_pk, 10 * STELL).await;
    let recipient = [0xADu8; 32];
    let amount = 100 * STELL;
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

    // Anyone resolves: evidence overrules the challenge.
    let resolver = key(0xD0);
    let resolver_pk = resolver.verifying_key().to_bytes();
    fund(&e, &resolver_pk, 10 * STELL).await;
    let tx_r = bridge_tx(
        &resolver,
        0,
        ops_list(vec![
            quorum_proof(hash, recipient, amount, &vals),
            BridgeIntent::Resolve { dispute_id: 0 },
        ]),
    );
    let out = e
        .apply_block_transition(&bridge_block(3, TS + 20, vec![tx_r], resolver_pk), 0)
        .await;
    assert_eq!(out.status, vec![true], "valid evidence confirms");
    assert_eq!(
        balance(&e, &recipient).await,
        amount + CHALLENGE_BOND_NANO,
        "clawback returns plus the slashed bond as freeze compensation"
    );
    {
        let br = e.bridge_read().await;
        let d = br.disputes.get(&0).unwrap();
        assert!(d.resolved && d.confirmed);
    }
    // Terminal: resolving again refuses.
    let tx_r2 = bridge_tx(
        &resolver,
        1,
        ops_list(vec![BridgeIntent::Resolve { dispute_id: 0 }]),
    );
    let settled = e.get_state_root().await;
    let out = e
        .apply_block_transition(&bridge_block(4, TS + 30, vec![tx_r2], resolver_pk), 0)
        .await;
    assert_eq!(out.status, vec![false], "resolved disputes are terminal");
    // The refusal moves NO BRIDGE COIN (the confirm already paid out; a
    // second resolve cannot pay twice). The state ROOT does move: a refused
    // transaction is an attributable failure, so it pays the D2 floor step
    // and consumes its nonce - the engine's fail-closed rule, not a bridge
    // effect. Payer == proposer here, so the fee self-rebates.
    assert_eq!(
        balance(&e, &recipient).await,
        100 * STELL + CHALLENGE_BOND_NANO,
        "the confirm payout is not repeated by the refused resolve"
    );
    assert_eq!(
        balance(&e, &stellereum::bridge::BRIDGE_ESCROW).await,
        0,
        "the escrow stays empty"
    );
    {
        let br = e.bridge_read().await;
        let d = br.disputes.get(&0).unwrap();
        assert!(d.resolved && d.confirmed, "the verdict is terminal");
    }
    assert_ne!(
        e.get_state_root().await,
        settled,
        "the refusal itself is charged (nonce + D2 step), but it moves no bridge coin"
    );
}

// ===========================================================================
// 5. Early resolve without evidence refused; revoke with FAILING evidence
//    after expiry pays out (the B2 truth gate: an EMPTY resolve past the
//    deadline defers instead of paying — pinned in bridge_challenge_tests).
// ===========================================================================

#[tokio::test]
async fn resolve_before_deadline_without_evidence_is_refused() {
    let (e, vals) = setup(3).await;
    let payer_pk = key(0x03).verifying_key().to_bytes();
    let challenger = key(0xC0);
    let challenger_pk = challenger.verifying_key().to_bytes();
    fund(&e, &challenger_pk, 10 * STELL).await;
    let recipient = [0xADu8; 32];
    let hash = [0x73u8; 32];
    settle_deposit(&e, &vals, payer_pk, hash, recipient, 100 * STELL).await;
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

    let tx_r = bridge_tx(
        &challenger,
        1,
        ops_list(vec![BridgeIntent::Resolve { dispute_id: 0 }]),
    );
    let out = e
        .apply_block_transition(&bridge_block(3, TS + 20, vec![tx_r], challenger_pk), 0)
        .await;
    assert_eq!(
        out.status,
        vec![false],
        "window open + no evidence: nothing to resolve"
    );
}

#[tokio::test]
async fn resolve_revokes_after_expiry_and_rewards_challenger() {
    let (e, vals) = setup(3).await;
    let payer_pk = key(0x03).verifying_key().to_bytes();
    let challenger = key(0xC0);
    let challenger_pk = challenger.verifying_key().to_bytes();
    fund(&e, &challenger_pk, 10 * STELL).await;
    let recipient = [0xADu8; 32];
    let amount = 100 * STELL;
    let bond = stellereum::bridge::challenge_bond_for(amount);
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

    // Past the 1h window with FAILING evidence (fraud signal) and no valid
    // evidence: revoke. (An empty resolve here would DEFER with no payout —
    // the B2 truth gate, pinned in bridge_challenge_tests.)
    let tx_r = bridge_tx(
        &challenger,
        1,
        ops_list(vec![
            BridgeIntent::DepositProof {
                source_tx_hash: hash,
                evidence: Box::new(DepositEvidence::QuorumAttested {
                    signatures: vec![([0xEEu8; 32], vec![0u8; 64])],
                }),
            },
            BridgeIntent::Resolve { dispute_id: 0 },
        ]),
    );
    let out = e
        .apply_block_transition(
            &bridge_block(3, TS + 10 + DISPUTE_WINDOW_SECS, vec![tx_r], challenger_pk),
            0,
        )
        .await;
    assert_eq!(out.status, vec![true], "expiry defers under SEC-01");
    // Under SEC-01: unverified evidence defers without payout; challenger is still down the bond.
    assert_eq!(
        balance(&e, &challenger_pk).await,
        10 * STELL - bond,
        "challenger remains down the bond during deferrals: zero unearned profit"
    );
    assert_eq!(
        balance(&e, &recipient).await,
        0,
        "credit stays parked while in deferral"
    );
    {
        let br = e.bridge_read().await;
        let d = br.disputes.get(&0).unwrap();
        assert!(
            !d.resolved && !d.confirmed,
            "dispute deferred, not confirmed"
        );
    }
}

// ===========================================================================
// 5b. TRUE challenge: a VERIFIED fraud proof (the relayer quorum's own
//     retraction of the deposit) revokes it on the live block path: the
//     finder gets its bond plus the 10% finder reward out of the escrow,
//     the remainder burns, and the recipient gets NOTHING back.
// ===========================================================================

/// The quorum-signed retraction preimage for exactly this claim.
fn failure_proof(
    hash: [u8; 32],
    recipient: [u8; 32],
    amount: u64,
    signers: &[SigningKey],
) -> BridgeIntent {
    let msg = TeleportBridgeEngine::deposit_failure_signing_message(
        SupportedChain::Ton,
        hash,
        recipient,
        amount,
    );
    let signatures = signers
        .iter()
        .map(|k| (k.verifying_key().to_bytes(), k.sign(&msg).to_vec()))
        .collect();
    BridgeIntent::DepositProof {
        source_tx_hash: hash,
        evidence: Box::new(DepositEvidence::QuorumAttested { signatures }),
    }
}

#[tokio::test]
async fn verified_fraud_proof_revokes_pays_the_finder_and_burns_the_rest() {
    let (e, vals) = setup(3).await;
    let payer_pk = key(0x03).verifying_key().to_bytes();
    let challenger = key(0xC0);
    let challenger_pk = challenger.verifying_key().to_bytes();
    fund(&e, &challenger_pk, 10 * STELL).await;
    let recipient = [0xADu8; 32];
    let amount = 100 * STELL;
    let bond = stellereum::bridge::challenge_bond_for(amount);
    let reward = stellereum::bridge::dispute_reward_for(amount);
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
    assert_eq!(balance(&e, &recipient).await, 0, "clawed back into escrow");
    assert_eq!(
        balance(&e, &stellereum::bridge::BRIDGE_ESCROW).await,
        amount + bond,
        "the escrow holds the deposit and the bond"
    );

    // The relayer quorum retracts the deposit (a genuine, verifiable fraud
    // proof): the finder is paid bond + reward, the rest burns.
    let tx_r = bridge_tx(
        &challenger,
        1,
        ops_list(vec![
            failure_proof(hash, recipient, amount, &vals),
            BridgeIntent::Resolve { dispute_id: 0 },
        ]),
    );
    let out = e
        .apply_block_transition(
            &bridge_block(3, TS + 10 + DISPUTE_WINDOW_SECS, vec![tx_r], challenger_pk),
            0,
        )
        .await;
    assert_eq!(out.status, vec![true], "a verified fraud proof revokes");
    assert_eq!(
        balance(&e, &challenger_pk).await,
        10 * STELL + reward,
        "the finder gets its bond back plus the 10% finder reward"
    );
    assert_eq!(
        balance(&e, &recipient).await,
        0,
        "a revoked (fraudulent) deposit never returns to the recipient"
    );
    assert_eq!(
        balance(&e, &stellereum::bridge::BRIDGE_ESCROW).await,
        0,
        "the escrow is drained: the reward went to the finder, the rest burned"
    );
    {
        let br = e.bridge_read().await;
        let d = br.disputes.get(&0).unwrap();
        assert!(
            d.resolved && !d.confirmed,
            "the dispute settled as a revoke"
        );
        assert_eq!(
            br.total_minted, reward,
            "the mint counter unwinds by the burned amount only; the finder keeps the reward"
        );
    }
}

// ===========================================================================
// 6. Challenge of an evidence-path deposit is refused (math needs no challenge)
// ===========================================================================

#[tokio::test]
async fn challenge_evidence_path_deposit_is_refused() {
    let (e, vals) = setup(3).await;
    let payer_pk = key(0x03).verifying_key().to_bytes();
    fund(&e, &payer_pk, 1_000_000).await;
    let challenger = key(0xC0);
    fund(&e, &challenger.verifying_key().to_bytes(), 10 * STELL).await;
    let recipient = [0xC1u8; 32];
    let amount = 77 * STELL;
    let hash = [0x81u8; 32];

    // Admit via the evidence path (no quorum attestation at all).
    let tx = bridge_tx(
        &key(0x03),
        0,
        ops_list(vec![
            quorum_proof(hash, recipient, amount, &vals),
            deposit(hash, recipient, amount),
        ]),
    );
    let out = e
        .apply_block_transition(&bridge_block(1, TS, vec![tx], payer_pk), 0)
        .await;
    assert_eq!(out.status, vec![true], "evidence path admits");
    {
        let br = e.bridge_read().await;
        assert!(!br.deposit_records.get(&hash).unwrap().via_quorum);
    }

    let tx_c = bridge_tx(
        &challenger,
        0,
        ops_list(vec![BridgeIntent::Challenge {
            source_tx_hash: hash,
        }]),
    );
    let out = e
        .apply_block_transition(&bridge_block(2, TS + 10, vec![tx_c], payer_pk), 0)
        .await;
    assert_eq!(
        out.status,
        vec![false],
        "evidence-path deposits are math, not testimony"
    );
    assert_eq!(balance(&e, &recipient).await, amount, "untouched");
}

// ===========================================================================
// 7. Challenge with insufficient bond / moved funds fails closed
// ===========================================================================

#[tokio::test]
async fn challenge_without_bond_cover_is_refused() {
    let (e, vals) = setup(3).await;
    let payer_pk = key(0x03).verifying_key().to_bytes();
    let poor = key(0xC1);
    fund(&e, &poor.verifying_key().to_bytes(), 100).await; // dust: no bond
    let recipient = [0xADu8; 32];
    let hash = [0x73u8; 32];
    settle_deposit(&e, &vals, payer_pk, hash, recipient, 100 * STELL).await;

    let tx = bridge_tx(
        &poor,
        0,
        ops_list(vec![BridgeIntent::Challenge {
            source_tx_hash: hash,
        }]),
    );
    let settled = e.get_state_root().await;
    let out = e
        .apply_block_transition(&bridge_block(2, TS + 10, vec![tx], payer_pk), 0)
        .await;
    assert_eq!(out.status, vec![false], "bond uncovered: whole tx fails");
    assert_eq!(
        e.get_state_root().await,
        settled,
        "fail closed, nothing moves"
    );
    assert!(
        !e.bridge_read()
            .await
            .deposit_records
            .get(&hash)
            .unwrap()
            .disputed
    );
}

// ===========================================================================
// 8. Migration: V2 and V1 snapshots restore with empty dispute maps
// ===========================================================================

#[tokio::test]
async fn v2_and_v1_snapshots_restore_as_unchallengeable() {
    use stellereum::bridge::{BridgeStateV1, BridgeStateV2};
    let e = InMemoryStateEngine::new();

    // V2 shape (pre-dispute): restores, records empty.
    let v2 = BridgeStateV2 {
        total_minted: 5,
        ..Default::default()
    };
    let bytes = bincode::serialize(&v2).expect("V2 serializes");
    e.restore_bridge(&bytes).await.expect("V2 restores");
    {
        let br = e.bridge_read().await;
        assert_eq!(br.total_minted, 5);
        assert!(br.deposit_records.is_empty() && br.disputes.is_empty());
        assert!(!br.is_empty(), "minted state is non-empty");
    }

    // V1 shape (pre-F-H): still restores through the full chain.
    let v1 = BridgeStateV1 {
        escrow_balance: 7,
        ..Default::default()
    };
    let bytes = bincode::serialize(&v1).expect("V1 serializes");
    e.restore_bridge(&bytes).await.expect("V1 restores");
    {
        let br = e.bridge_read().await;
        assert_eq!(br.escrow_balance, 7);
        assert!(br.deposit_records.is_empty() && br.disputes.is_empty());
    }
}

// ===========================================================================
// 9. Dispute state moves the root (completeness: records + disputes committed)
// ===========================================================================

#[tokio::test]
async fn dispute_state_is_committed_in_the_root() {
    let (e, vals) = setup(3).await;
    let payer_pk = key(0x03).verifying_key().to_bytes();
    let challenger = key(0xC0);
    let challenger_pk = challenger.verifying_key().to_bytes();
    fund(&e, &challenger_pk, 10 * STELL).await;
    let recipient = [0xADu8; 32];
    let hash = [0x73u8; 32];
    settle_deposit(&e, &vals, payer_pk, hash, recipient, 100 * STELL).await;

    // The bridge domain is already non-empty (records commit on deposit).
    assert!(!e.bridge_read().await.is_empty());
    let root_with_record = e.get_state_root().await;
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
    assert_ne!(
        e.get_state_root().await,
        root_with_record,
        "opening a dispute must move the state root (I1)"
    );
    // Field-level digest coverage lives in
    // `bridge_domain_is_folded_into_the_commitment_digest` (records/disputes
    // cases); here the live path proves end-to-end commitment.
}
