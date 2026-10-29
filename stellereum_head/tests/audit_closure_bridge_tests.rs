//! Audit closure: bridge findings B1 (zk-gate reachability), B2 (challenge
//! truth-gate payout matrix), B3 (refund race atomicity).
//!
//! NEW file — never edits shared tests. Runs `BridgeState::plan` directly
//! (pure policy gate, no balances needed: settlement Pass-1 escrow checks live
//! in `state_engine`, already covered by `bridge_*` suites).

use ed25519_dalek::{Signer, SigningKey};
use stellereum::bridge::{
    bridge_adapters::DepositEvidence, challenge_bond_for, dispute_reward_for, BridgeIntent,
    BridgeState, SupportedChain, TeleportBridgeEngine, CHALLENGE_MAX_AGE_SECS,
    DISPUTE_WINDOW_SECS, LIVE_DEPOSIT_ASSET, MAX_RESOLVE_DEFERRALS, REFUND_GRACE_SECS,
    RESOLVE_DEFER_SECS,
};
use stellereum::zkml::{QuantizedLayer, QuantizedLinearModel, ZkMlProof};

const TS: u64 = 1_760_000_000;
const STELL: u64 = 1_000_000_000;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn validators() -> (Vec<SigningKey>, Vec<[u8; 32]>) {
    let ks = vec![key(0xA0), key(0xA1), key(0xA2)];
    let pubs = ks.iter().map(|k| k.verifying_key().to_bytes()).collect();
    (ks, pubs)
}

fn deposit(hash: [u8; 32], recipient: [u8; 32], amount: u64) -> BridgeIntent {
    BridgeIntent::Deposit {
        chain: SupportedChain::Ton,
        source_tx_hash: hash,
        recipient,
        amount,
    }
}

fn attest_for(dep: &BridgeIntent, signers: &[SigningKey]) -> BridgeIntent {
    let event = dep.deposit_event(Vec::new()).expect("deposit event");
    let msg = TeleportBridgeEngine::deposit_signing_message(&event);
    let signatures = signers
        .iter()
        .map(|k| (k.verifying_key().to_bytes(), k.sign(&msg).to_vec()))
        .collect();
    let source_tx_hash = match dep {
        BridgeIntent::Deposit { source_tx_hash, .. } => *source_tx_hash,
        other => panic!("attest only pairs with a Deposit: {other:?}"),
    };
    BridgeIntent::Attest {
        source_tx_hash,
        signatures,
    }
}

fn quorum_proof(hash: [u8; 32], recipient: [u8; 32], amount: u64, signers: &[SigningKey]) -> BridgeIntent {
    let dep = deposit(hash, recipient, amount);
    let att = attest_for(&dep, signers);
    let signatures = match att {
        BridgeIntent::Attest { signatures, .. } => signatures,
        _ => unreachable!(),
    };
    BridgeIntent::DepositProof {
        source_tx_hash: hash,
        evidence: Box::new(DepositEvidence::QuorumAttested { signatures }),
    }
}

/// Shape-valid but cryptographically failing evidence (outsider key, junk
/// bytes): passes shape, fails adapter verification — the TRUE-challenge
/// (fraud) signal a revoke payout requires.
fn failing_proof(hash: [u8; 32]) -> BridgeIntent {
    BridgeIntent::DepositProof {
        source_tx_hash: hash,
        evidence: Box::new(DepositEvidence::QuorumAttested {
            signatures: vec![([0xEEu8; 32], vec![0u8; 64])],
        }),
    }
}

fn model() -> QuantizedLinearModel {
    QuantizedLinearModel::new(vec![QuantizedLayer::new(2, 2, vec![2, -1, 1, 3], vec![1, -2])])
}

// ===========================================================================
// B1: live route enumeration + vacuous gate on the consensus path
// ===========================================================================

#[test]
fn b1_live_route_universe_is_exactly_the_four_stell_routes() {
    let routes = stellereum::bridge::teleport_live_route_ids();
    assert_eq!(routes.len(), 4, "one route per SupportedChain variant");
    assert_eq!(routes, ["0:STELL", "1:STELL", "2:STELL", "3:STELL"]);
    for r in &routes {
        assert!(r.ends_with(LIVE_DEPOSIT_ASSET));
    }
}

#[test]
fn b1_live_plan_admits_deposit_with_no_proof_and_no_registry() {
    // The consensus path never consults a model: plan() rebuilds the engine
    // with an empty registry, and the Deposit variant cannot carry a proof.
    let (_ks, pubs) = validators();
    let state = BridgeState::default();
    let payer = [0x03u8; 32];
    let hash = [0x71u8; 32];
    let recipient = [0xADu8; 32];
    let dep = deposit(hash, recipient, 100 * STELL);
    let att = attest_for(&dep, &[key(0xA0), key(0xA1)]);
    let plan = state
        .plan(&[att, dep], &pubs, payer, TS)
        .expect("live quorum deposit plans");
    assert_eq!(plan.effects.len(), 1);
    // Contrast: the SAME route with a proof but an empty (live-like)
    // registry fails closed on the offline engine.
    let m = model();
    let (_out, proof) = ZkMlProof::prove_inference(&m, &[3, 4]);
    let mut engine = TeleportBridgeEngine::new(pubs.clone());
    let draft = stellereum::bridge::TeleportDepositEvent {
        source_chain: SupportedChain::Ton,
        source_tx_hash: [0x72u8; 32],
        recipient,
        asset: LIVE_DEPOSIT_ASSET.to_string(),
        amount: 100 * STELL,
        validator_signatures: vec![],
        zk_proof: None,
    };
    let msg = TeleportBridgeEngine::deposit_signing_message(&draft);
    let sigs = [&key(0xA0), &key(0xA1)]
        .iter()
        .map(|k| (k.verifying_key().to_bytes(), k.sign(&msg).to_vec()))
        .collect();
    let ev = stellereum::bridge::TeleportDepositEvent {
        validator_signatures: sigs,
        zk_proof: Some(proof),
        ..draft
    };
    let err = engine
        .process_deposit(&ev)
        .expect_err("empty registry must reject proof-carrying deposits");
    assert!(err.contains("no registered model"), "got: {err}");
    assert!(engine.teleport_zk_model_for(&ev).is_none());
}

#[test]
fn b1_deposit_event_never_carries_a_proof() {
    // Pins the transport absence: every Deposit intent maps to zk_proof None.
    for chain in [
        SupportedChain::Ton,
        SupportedChain::Arbitrum,
        SupportedChain::Ethereum,
        SupportedChain::Solana,
    ] {
        let dep = BridgeIntent::Deposit {
            chain,
            source_tx_hash: [0x11u8; 32],
            recipient: [0x22u8; 32],
            amount: 7,
        };
        let ev = dep.deposit_event(vec![]).expect("deposit event");
        assert!(ev.zk_proof.is_none(), "live deposit event carries no proof");
        assert_eq!(ev.asset, LIVE_DEPOSIT_ASSET);
    }
}

// ===========================================================================
// B2: payout-matrix pins at plan level
// ===========================================================================

fn settled_quorum_state(
    state: &BridgeState,
    pubs: &[[u8; 32]],
    payer: [u8; 32],
    hash: [u8; 32],
    recipient: [u8; 32],
    amount: u64,
    signers: &[SigningKey],
    now: u64,
) -> BridgeState {
    let dep = deposit(hash, recipient, amount);
    let att = attest_for(&dep, signers);
    state
        .plan(&[att, dep], pubs, payer, now)
        .expect("setup deposit plans")
        .state
}

#[test]
fn b2_bond_and_reward_math_is_pinned_including_dust() {
    // Whale (audit example): 50k STELL -> 500 bond, 5k reward.
    assert_eq!(challenge_bond_for(50_000 * STELL), 500 * STELL);
    assert_eq!(dispute_reward_for(50_000 * STELL), 5_000 * STELL);
    // 1% rule at 100 STELL.
    assert_eq!(challenge_bond_for(100 * STELL), STELL);
    assert_eq!(dispute_reward_for(100 * STELL), 10 * STELL);
    // Dust asymmetry (documented residual): the 1 STELL floor EXCEEDS 1% of
    // a dust deposit, pricing honest challengers out of dust fraud.
    assert_eq!(challenge_bond_for(STELL / 2), STELL);
    assert!(challenge_bond_for(STELL / 2) > (STELL / 2) / 100);
    // Reward never exceeds the disputed amount and never vanishes to zero.
    assert_eq!(dispute_reward_for(0), 0);
    assert_eq!(dispute_reward_for(5), 1);
    assert_eq!(dispute_reward_for(3 * STELL), 3 * STELL / 10);
}

#[test]
fn b2_false_challenge_confirm_slashes_bond_no_reward() {
    let (ks, pubs) = validators();
    let payer = [0x03u8; 32];
    let challenger = [0xC0u8; 32];
    let recipient = [0xADu8; 32];
    let amount = 100 * STELL;
    let bond = challenge_bond_for(amount);
    let hash = [0x73u8; 32];

    let s1 = settled_quorum_state(
        &BridgeState::default(),
        &pubs,
        payer,
        hash,
        recipient,
        amount,
        &ks[..2],
        TS,
    );
    let s2 = s1
        .plan(
            &[BridgeIntent::Challenge {
                source_tx_hash: hash,
            }],
            &pubs,
            challenger,
            TS + 10,
        )
        .expect("challenge plans")
        .state;
    // Resolve with VALID evidence (even past the deadline): confirm.
    let plan = s2
        .plan(
            &[
                quorum_proof(hash, recipient, amount, &ks),
                BridgeIntent::Resolve { dispute_id: 0 },
            ],
            &pubs,
            challenger,
            TS + 10 + DISPUTE_WINDOW_SECS,
        )
        .expect("confirm resolves");
    let d = plan.state.disputes.get(&0).expect("dispute 0");
    assert!(d.resolved && d.confirmed, "FALSE challenge confirms");
    let unparks: u64 = plan
        .effects
        .iter()
        .filter_map(|e| match e {
            stellereum::bridge::BridgeEffect::Unpark { recipient: r, amount: a }
                if *r == recipient =>
            {
                Some(*a)
            }
            _ => None,
        })
        .sum();
    assert_eq!(
        unparks,
        amount + bond,
        "clawback returns plus the slashed bond; no 10% reward moves"
    );
    assert!(!plan.effects.iter().any(|e| matches!(
        e,
        stellereum::bridge::BridgeEffect::Burn { .. }
    )));
}

#[test]
fn b2_true_challenge_revoke_pays_bond_plus_reward_and_burns_rest() {
    let (ks, pubs) = validators();
    let payer = [0x03u8; 32];
    let challenger = [0xC0u8; 32];
    let recipient = [0xADu8; 32];
    let amount = 100 * STELL;
    let bond = challenge_bond_for(amount);
    let reward = dispute_reward_for(amount);
    let hash = [0x73u8; 32];

    let s1 = settled_quorum_state(
        &BridgeState::default(),
        &pubs,
        payer,
        hash,
        recipient,
        amount,
        &ks[..2],
        TS,
    );
    let s2 = s1
        .plan(
            &[BridgeIntent::Challenge {
                source_tx_hash: hash,
            }],
            &pubs,
            challenger,
            TS + 10,
        )
        .expect("challenge plans")
        .state;
    let plan = s2
        .plan(
            &[
                failing_proof(hash),
                BridgeIntent::Resolve { dispute_id: 0 },
            ],
            &pubs,
            challenger,
            TS + 10 + DISPUTE_WINDOW_SECS,
        )
        .expect("revoke resolves");
    let d = plan.state.disputes.get(&0).expect("dispute 0");
    assert!(d.resolved && !d.confirmed, "TRUE challenge revokes");
    let to_challenger: u64 = plan
        .effects
        .iter()
        .filter_map(|e| match e {
            stellereum::bridge::BridgeEffect::Unpark { recipient: r, amount: a }
                if *r == challenger =>
            {
                Some(*a)
            }
            _ => None,
        })
        .sum();
    assert_eq!(to_challenger, bond + reward, "bond back plus 10% reward");
    let burned: u64 = plan
        .effects
        .iter()
        .filter_map(|e| match e {
            stellereum::bridge::BridgeEffect::Burn { amount: a } => Some(*a),
            _ => None,
        })
        .sum();
    assert_eq!(burned, amount - reward, "remainder burns");
    assert_eq!(plan.state.total_minted, 0, "revoked mint unwinds");
}

#[test]
fn b2_suppressed_evidence_defers_exactly_k_times_then_refuses() {
    let (ks, pubs) = validators();
    let payer = [0x03u8; 32];
    let challenger = [0xC0u8; 32];
    let recipient = [0xADu8; 32];
    let amount = 100 * STELL;
    let bond = challenge_bond_for(amount);
    let hash = [0x73u8; 32];

    let s1 = settled_quorum_state(
        &BridgeState::default(),
        &pubs,
        payer,
        hash,
        recipient,
        amount,
        &ks[..2],
        TS,
    );
    // Challenge at the last second of the challenge-age window so the
    // deferral cap binds after exactly MAX_RESOLVE_DEFERRALS extensions.
    let challenge_at = TS + CHALLENGE_MAX_AGE_SECS - 100;
    let s2 = s1
        .plan(
            &[BridgeIntent::Challenge {
                source_tx_hash: hash,
            }],
            &pubs,
            challenger,
            challenge_at,
        )
        .expect("challenge plans")
        .state;
    let d0 = challenge_at + DISPUTE_WINDOW_SECS;
    assert_eq!(s2.disputes.get(&0).unwrap().deadline, d0);

    let mut state = s2;
    let mut now = d0;
    for i in 0..MAX_RESOLVE_DEFERRALS {
        let plan = state
            .plan(
                &[BridgeIntent::Resolve { dispute_id: 0 }],
                &pubs,
                challenger,
                now,
            )
            .expect("empty resolve past deadline DEFERS (applies, no payout)");
        assert!(plan.effects.is_empty(), "a defer moves no coin");
        let d = plan.state.disputes.get(&0).unwrap();
        assert!(!d.resolved, "a defer never settles");
        assert_eq!(d.deadline, now + RESOLVE_DEFER_SECS, "defer {i}: one window out");
        let next = d.deadline;
        state = plan.state;
        now = next;
    }
    // Bound exhausted: LOUD refuse, no payout.
    let err = state
        .plan(
            &[BridgeIntent::Resolve { dispute_id: 0 }],
            &pubs,
            challenger,
            now,
        )
        .expect_err("past the bound the resolve must REFUSE");
    assert!(err.contains("deferral bound exhausted"), "got: {err}");
    // Escrow accounting untouched throughout: bond still locked, no reward.
    let _ = bond;
    assert!(!state.disputes.get(&0).unwrap().resolved);
}

#[test]
fn b2_failing_evidence_before_deadline_revokes_nothing() {
    let (ks, pubs) = validators();
    let payer = [0x03u8; 32];
    let challenger = [0xC0u8; 32];
    let recipient = [0xADu8; 32];
    let hash = [0x73u8; 32];
    let s1 = settled_quorum_state(
        &BridgeState::default(),
        &pubs,
        payer,
        hash,
        recipient,
        100 * STELL,
        &ks[..2],
        TS,
    );
    let s2 = s1
        .plan(
            &[BridgeIntent::Challenge {
                source_tx_hash: hash,
            }],
            &pubs,
            challenger,
            TS + 10,
        )
        .expect("challenge plans")
        .state;
    let err = s2
        .plan(
            &[
                failing_proof(hash),
                BridgeIntent::Resolve { dispute_id: 0 },
            ],
            &pubs,
            challenger,
            TS + 20,
        )
        .expect_err("window open: failing evidence revokes nothing");
    assert!(err.contains("window still open"), "got: {err}");
}

// ===========================================================================
// B3: refund race atomicity, both directions
// ===========================================================================

#[test]
fn b3_release_then_refund_is_refused_executed_wins() {
    let (_ks, pubs) = validators();
    let payer = [0x05u8; 32];
    let amount = STELL;
    let s0 = BridgeState::default();
    // Small withdrawal parks with unlock_at == now.
    let s1 = s0
        .plan(
            &[BridgeIntent::Withdraw {
                chain: SupportedChain::Arbitrum,
                target_address: "0xdeadbeef".to_string(),
                amount,
            }],
            &pubs,
            payer,
            TS,
        )
        .expect("withdraw parks")
        .state;
    assert!(!s1.pending_withdrawals.get(&0).unwrap().executed);
    // Release at maturity: executed flips.
    let s2 = s1
        .plan(&[BridgeIntent::Release { req_id: 0 }], &pubs, payer, TS)
        .expect("matured release applies")
        .state;
    assert!(s2.pending_withdrawals.get(&0).unwrap().executed);
    // Refund after execution: refused, even past grace.
    let err = s2
        .plan(
            &[BridgeIntent::Refund { req_id: 0 }],
            &pubs,
            payer,
            TS + REFUND_GRACE_SECS + 1,
        )
        .expect_err("refund-after-release must fail (executed flag)");
    assert!(err.contains("already executed"), "got: {err}");
}

#[test]
fn b3_refund_then_release_is_refused_deletion_wins() {
    let (_ks, pubs) = validators();
    let payer = [0x05u8; 32];
    let amount = STELL;
    let s0 = BridgeState::default();
    let s1 = s0
        .plan(
            &[BridgeIntent::Withdraw {
                chain: SupportedChain::Arbitrum,
                target_address: "0xdeadbeef".to_string(),
                amount,
            }],
            &pubs,
            payer,
            TS,
        )
        .expect("withdraw parks")
        .state;
    // Refund past grace: request deleted.
    let s2 = s1
        .plan(
            &[BridgeIntent::Refund { req_id: 0 }],
            &pubs,
            payer,
            TS + REFUND_GRACE_SECS + 1,
        )
        .expect("past-grace refund applies")
        .state;
    assert!(s2.pending_withdrawals.get(&0).is_none());
    // Release of the refunded id: unknown.
    let err = s2
        .plan(&[BridgeIntent::Release { req_id: 0 }], &pubs, payer, TS + REFUND_GRACE_SECS + 2)
        .expect_err("release-after-refund must fail (deleted)");
    assert!(err.contains("not found"), "got: {err}");
    // Double refund: unknown too.
    let err = s2
        .plan(
            &[BridgeIntent::Refund { req_id: 0 }],
            &pubs,
            payer,
            TS + REFUND_GRACE_SECS + 3,
        )
        .expect_err("second refund finds nothing");
    assert!(err.contains("not found"), "got: {err}");
}

#[test]
fn b3_refund_guards_sender_and_grace() {
    let (_ks, pubs) = validators();
    let payer = [0x05u8; 32];
    let stranger = [0x06u8; 32];
    let s1 = BridgeState::default()
        .plan(
            &[BridgeIntent::Withdraw {
                chain: SupportedChain::Ton,
                target_address: "EQD-test".to_string(),
                amount: STELL,
            }],
            &pubs,
            payer,
            TS,
        )
        .expect("withdraw parks")
        .state;
    // Too early.
    let err = s1
        .plan(&[BridgeIntent::Refund { req_id: 0 }], &pubs, payer, TS + 60)
        .expect_err("grace not passed");
    assert!(err.contains("Refund locked"), "got: {err}");
    // Wrong sender, past grace.
    let err = s1
        .plan(
            &[BridgeIntent::Refund { req_id: 0 }],
            &pubs,
            stranger,
            TS + REFUND_GRACE_SECS + 1,
        )
        .expect_err("stranger cannot refund");
    assert!(err.contains("original sender"), "got: {err}");
}
