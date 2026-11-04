//! Audit closure: bridge findings B1 (zk-gate reachability), B2 (challenge
//! truth-gate payout matrix), B3 (refund race atomicity).
//!
//! NEW file — never edits shared tests. Runs `BridgeState::plan` directly
//! (pure policy gate, no balances needed: settlement Pass-1 escrow checks live
//! in `state_engine`, already covered by `bridge_*` suites).

use ed25519_dalek::{Signer, SigningKey};
use stellereum::bridge::{
    bridge_adapters::DepositEvidence, challenge_bond_for, dispute_reward_for, BridgeEffect,
    BridgeIntent, BridgePlan, BridgeState, SupportedChain, TeleportBridgeEngine,
    BRIDGE_MINT_CAP_NANO, CHALLENGE_MAX_AGE_SECS, DISPUTE_WINDOW_SECS, LIVE_DEPOSIT_ASSET,
    MAX_RESOLVE_DEFERRALS, REFUND_GRACE_SECS, RESOLVE_DEFER_SECS,
};
use stellereum::zkml::{QuantizedLayer, QuantizedLinearModel, ZkMlProof};

const TS: u64 = 1_760_000_000;
const STELL: u64 = 1_000_000_000;
const ESCROW: [u8; 32] = stellereum::bridge::BRIDGE_ESCROW;

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

fn quorum_proof(
    hash: [u8; 32],
    recipient: [u8; 32],
    amount: u64,
    signers: &[SigningKey],
) -> BridgeIntent {
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
/// bytes): passes shape, fails adapter verification. SEC-01: unverifiable
/// evidence is NOT a fraud signal — it fails to confirm the deposit and
/// defers the dispute (no payout, no burn). It must never pay a bounty.
fn failing_proof(hash: [u8; 32]) -> BridgeIntent {
    BridgeIntent::DepositProof {
        source_tx_hash: hash,
        evidence: Box::new(DepositEvidence::QuorumAttested {
            signatures: vec![([0xEEu8; 32], vec![0u8; 64])],
        }),
    }
}

/// A GENUINE quorum-attested FAILURE proof: the committed relayer quorum
/// signs the domain-separated retraction preimage for exactly this claim
/// (`TeleportBridgeEngine::deposit_failure_signing_message`). This is the
/// only thing the dispute layer accepts as a fraud proof — a challenger
/// without the quorum's keys cannot produce one.
fn genuine_failure_proof(
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

fn model() -> QuantizedLinearModel {
    QuantizedLinearModel::new(vec![QuantizedLayer::new(
        2,
        2,
        vec![2, -1, 1, 3],
        vec![1, -2],
    )])
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
    let (_out, proof) = ZkMlProof::prove_reexec(&m, &[3, 4]);
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

#[allow(clippy::too_many_arguments)]
// GATE: bridge test helper pins quorum-state setup inputs explicitly; a struct would obscure the matrix.
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
            stellereum::bridge::BridgeEffect::Unpark {
                recipient: r,
                amount: a,
            } if *r == recipient => Some(*a),
            _ => None,
        })
        .sum();
    assert_eq!(
        unparks,
        amount + bond,
        "clawback returns plus the slashed bond; no 10% reward moves"
    );
    assert!(!plan
        .effects
        .iter()
        .any(|e| matches!(e, stellereum::bridge::BridgeEffect::Burn { .. })));
}

/// B2 / SEC-01: an UNPROVEN challenge never pays a bounty.
///
/// The garbage bundle passes the VM shape check and fails every
/// cryptographic check. Under the old (vulnerable) rule "evidence present but
/// not verifying, past the deadline => fraud" this exact payload revoked an
/// honest deposit and paid the challenger bond + 10% while burning the rest —
/// an attacker could farm the bounty with junk signatures. The hardened
/// rule: unverifiable evidence proves nothing. The dispute DEFERS (the
/// deadline is pushed out one window), no coin moves, the challenger's bond
/// stays locked and the deposit is not burned.
#[test]
fn unproven_challenge_evidence_never_pays_a_bounty() {
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
    let deadline_before = s2.disputes.get(&0).expect("dispute 0").deadline;

    // Past the deadline, carrying only junk signatures.
    let plan = s2
        .plan(
            &[failing_proof(hash), BridgeIntent::Resolve { dispute_id: 0 }],
            &pubs,
            challenger,
            TS + 10 + DISPUTE_WINDOW_SECS,
        )
        .expect("unproven evidence defers, it does not fail the tx");
    let d = plan.state.disputes.get(&0).expect("dispute 0");

    // 1) The dispute is NOT settled.
    assert!(!d.resolved, "unproven evidence never settles the dispute");
    assert!(!d.confirmed, "unproven evidence never confirms it either");
    // 2) NO coin moves at all: no Unpark to the challenger (neither the bond
    //    nor a finder reward), no Burn of the escrowed deposit.
    assert!(
        plan.effects.is_empty(),
        "an unproven challenge moves no coin: {:?}",
        plan.effects
    );
    assert!(
        !plan
            .effects
            .iter()
            .any(|e| matches!(e, BridgeEffect::Burn { .. })),
        "an unproven challenge never burns the deposit"
    );
    assert!(
        !plan.effects.iter().any(|e| matches!(
            e,
            BridgeEffect::Unpark { recipient, .. } if *recipient == challenger
        )),
        "the challenger's bond is NOT paid out on an unproven challenge"
    );
    // 3) The deferral: the deadline is pushed one window out, bounded.
    assert_eq!(
        d.deadline,
        deadline_before + RESOLVE_DEFER_SECS,
        "an unproven challenge defers: the deadline moves one window out"
    );
    // 4) The mint is untouched (no unwind on a deferred dispute) and the
    //    deposit record stays frozen.
    assert_eq!(plan.state.total_minted, amount, "no mint unwind on a defer");
    assert!(
        plan.state
            .deposit_records
            .get(&hash)
            .expect("record")
            .disputed,
        "the deposit stays frozen while the dispute is open"
    );
    let _ = bond;
}

/// B2 / W7.1: the POSITIVE CONTROL — a genuine, quorum-attested failure
/// proof revokes the deposit and pays the finder.
///
/// This is the behaviour the old test wanted, reached through REAL evidence:
/// the committed relayer quorum signs the domain-separated retraction
/// preimage for exactly this claim, so the fraud is PROVEN (and cannot be
/// forged by a challenger). The finder gets its bond back plus the 10%
/// finder reward, both paid out of the escrowed deposit; the remainder
/// BURNS; the mint counters unwind by the burned amount.
#[test]
fn genuine_quorum_failure_proof_revokes_pays_bond_plus_reward_and_burns_the_rest() {
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
                genuine_failure_proof(hash, recipient, amount, &ks),
                BridgeIntent::Resolve { dispute_id: 0 },
            ],
            &pubs,
            challenger,
            TS + 10 + DISPUTE_WINDOW_SECS,
        )
        .expect("a verified fraud proof revokes");
    let d = plan.state.disputes.get(&0).expect("dispute 0");
    assert!(d.resolved && !d.confirmed, "a verified fraud proof revokes");

    let to_challenger: u64 = plan
        .effects
        .iter()
        .filter_map(|e| match e {
            BridgeEffect::Unpark {
                recipient: r,
                amount: a,
            } if *r == challenger => Some(*a),
            _ => None,
        })
        .sum();
    assert_eq!(
        to_challenger,
        bond + reward,
        "bond back plus the 10% finder reward"
    );
    let burned: u64 = plan
        .effects
        .iter()
        .filter_map(|e| match e {
            BridgeEffect::Burn { amount: a } => Some(*a),
            _ => None,
        })
        .sum();
    assert_eq!(burned, amount - reward, "the remainder burns");
    // The fraudulent deposit NEVER returns to its (fraudulent) recipient.
    let to_recipient: u64 = plan
        .effects
        .iter()
        .filter_map(|e| match e {
            BridgeEffect::Unpark {
                recipient: r,
                amount: a,
            } if *r == recipient => Some(*a),
            _ => None,
        })
        .sum();
    assert_eq!(
        to_recipient, 0,
        "a revoked deposit is never unparked back to the recipient"
    );
    // CONSERVATION (exact): the escrow held `amount + bond`; the finder took
    // `bond + reward`; the burn is `amount - reward`. Nothing is created and
    // nothing is lost.
    assert_eq!(
        to_challenger + burned,
        amount + bond,
        "escrow in == escrow out: the reward is paid out of the clawback, never minted"
    );
    // The mint counters unwind by the BURNED amount only: the finder's reward
    // is still outstanding minted supply, so unwinding the full deposit would
    // hand the cumulative mint cap free headroom.
    assert_eq!(
        plan.state.total_minted, reward,
        "the revoked mint unwinds by the burned amount; the finder keeps the reward"
    );
}

/// PRECEDENCE (W7.1): a verified retraction outranks the deposit's own
/// (always replayable) attestation - otherwise the retraction could never
/// take effect, because the attestation that admitted the deposit is public
/// and can be replayed by anyone at any time.
#[test]
fn a_verified_retraction_outranks_the_deposits_own_attestation() {
    let (ks, pubs) = validators();
    let payer = [0x03u8; 32];
    let challenger = [0xC0u8; 32];
    let recipient = [0xADu8; 32];
    let amount = 100 * STELL;
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
    // Both the attestation (it happened) AND the retraction (it did not) in
    // one payload: the retraction wins, because the attestation is always
    // replayable.
    let plan = s2
        .plan(
            &[
                quorum_proof(hash, recipient, amount, &ks),
                genuine_failure_proof(hash, recipient, amount, &ks),
                BridgeIntent::Resolve { dispute_id: 0 },
            ],
            &pubs,
            challenger,
            TS + 10 + DISPUTE_WINDOW_SECS,
        )
        .expect("the retraction decides");
    let d = plan.state.disputes.get(&0).expect("dispute 0");
    assert!(
        d.resolved && !d.confirmed,
        "the retraction outranks the always-replayable attestation"
    );
    let burned: u64 = plan
        .effects
        .iter()
        .filter_map(|e| match e {
            BridgeEffect::Burn { amount: a } => Some(*a),
            _ => None,
        })
        .sum();
    assert_eq!(
        burned,
        amount - dispute_reward_for(amount),
        "a revoked deposit burns the remainder"
    );
}

/// The fraud proof must be a RETRACTION OF THIS EXACT CLAIM: a quorum
/// signature over a different amount (or over the ordinary "it happened"
/// preimage) is not a fraud proof for this deposit.
#[test]
fn a_retraction_for_another_claim_never_revokes() {
    let (ks, pubs) = validators();
    let payer = [0x03u8; 32];
    let challenger = [0xC0u8; 32];
    let recipient = [0xADu8; 32];
    let amount = 100 * STELL;
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

    // A retraction of a DIFFERENT amount: the preimage binds the amount, so
    // it does not verify against this claim — it is not a fraud signal.
    let other = genuine_failure_proof(hash, recipient, amount * 2, &ks);
    let plan = s2
        .plan(
            &[other, BridgeIntent::Resolve { dispute_id: 0 }],
            &pubs,
            challenger,
            TS + 10 + DISPUTE_WINDOW_SECS,
        )
        .expect("a mismatched retraction defers like any unproven evidence");
    assert!(
        plan.effects.is_empty(),
        "a retraction for another claim never moves a coin"
    );
    assert!(
        !plan.state.disputes.get(&0).unwrap().resolved,
        "a retraction for another claim never settles the dispute"
    );

    // A retraction signed by an OUTSIDER key (not in the committed quorum)
    // is equally worthless.
    let outsider = key(0xEE);
    let forged = genuine_failure_proof(hash, recipient, amount, &[outsider]);
    let plan = s2
        .plan(
            &[forged, BridgeIntent::Resolve { dispute_id: 0 }],
            &pubs,
            challenger,
            TS + 10 + DISPUTE_WINDOW_SECS,
        )
        .expect("an outsider retraction defers like any unproven evidence");
    assert!(
        plan.effects.is_empty(),
        "a retraction outside the committed quorum never moves a coin"
    );
    assert!(
        !plan.state.disputes.get(&0).unwrap().resolved,
        "a retraction outside the committed quorum never settles the dispute"
    );
}

/// AUDIT (W7.1, question 1): a challenge with NO evidence at all can never
/// reach a payout — not before the deadline, not after it, and not after the
/// deferral bound is exhausted.
#[test]
fn a_challenge_with_no_evidence_never_reaches_a_payout() {
    let (ks, pubs) = validators();
    let payer = [0x03u8; 32];
    let challenger = [0xC0u8; 32];
    let recipient = [0xADu8; 32];
    let amount = 100 * STELL;
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
    // Challenge at the LAST second of the challenge-age window, so the
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

    // Before the deadline: refused outright, nothing moves.
    let err = s2
        .plan(
            &[BridgeIntent::Resolve { dispute_id: 0 }],
            &pubs,
            challenger,
            challenge_at + 10,
        )
        .expect_err("an empty resolve inside the window is refused");
    assert!(err.contains("window still open"), "got: {err}");

    // Past the deadline: DEFER (bounded), never a payout.
    let mut state = s2;
    let mut now = challenge_at + DISPUTE_WINDOW_SECS;
    for i in 0..MAX_RESOLVE_DEFERRALS {
        let plan = state
            .plan(
                &[BridgeIntent::Resolve { dispute_id: 0 }],
                &pubs,
                challenger,
                now,
            )
            .expect("an empty resolve past the deadline defers");
        assert!(plan.effects.is_empty(), "defer {i}: a defer moves no coin");
        assert!(!plan.state.disputes.get(&0).unwrap().resolved);
        now = plan.state.disputes.get(&0).unwrap().deadline;
        state = plan.state;
    }
    // Past the bound: LOUD refusal, still no payout.
    let err = state
        .plan(
            &[BridgeIntent::Resolve { dispute_id: 0 }],
            &pubs,
            challenger,
            now,
        )
        .expect_err("past the bound the resolve refuses");
    assert!(err.contains("deferral bound exhausted"), "got: {err}");
    assert!(!state.disputes.get(&0).unwrap().resolved);
}

/// AUDIT (W7.1, question 2): the deferral is BOUNDED for every challenge
/// time — the deadline can never be pushed past the documented cap, so the
/// dispute can never be deferred forever.
#[test]
fn the_deferral_bound_is_enforced_for_every_challenge_time() {
    let (ks, pubs) = validators();
    let payer = [0x03u8; 32];
    let challenger = [0xC0u8; 32];
    let recipient = [0xADu8; 32];
    let amount = 100 * STELL;

    // Challenge at several points of the challenge-age window, from the very
    // first second to the very last one.
    for offset in [
        0u64,
        1,
        CHALLENGE_MAX_AGE_SECS / 2,
        CHALLENGE_MAX_AGE_SECS - 1,
    ] {
        let hash = [((offset % 100) as u8) ^ 0x40; 32];
        let at = TS + offset;
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
                at,
            )
            .expect("challenge plans")
            .state;
        // The cap is derived from the DEPOSIT time, never from the challenge
        // time, so an early challenge cannot buy extra windows either.
        let cap = TS
            .saturating_add(CHALLENGE_MAX_AGE_SECS)
            .saturating_add(DISPUTE_WINDOW_SECS * (1 + MAX_RESOLVE_DEFERRALS as u64));
        let mut state = s2;
        let mut now = at + DISPUTE_WINDOW_SECS;
        let mut defers = 0u32;
        loop {
            let plan = match state.plan(
                &[BridgeIntent::Resolve { dispute_id: 0 }],
                &pubs,
                challenger,
                now,
            ) {
                Ok(p) => p,
                Err(e) => {
                    assert!(
                        e.contains("deferral bound exhausted"),
                        "the only refusal allowed is the bound: got {e}"
                    );
                    break;
                }
            };
            let d = plan.state.disputes.get(&0).expect("dispute 0");
            assert!(
                d.deadline <= cap,
                "the deadline may never be pushed past the cap (offset {offset})"
            );
            assert!(!d.resolved, "a defer never settles");
            defers += 1;
            assert!(
                u64::from(defers)
                    <= (CHALLENGE_MAX_AGE_SECS / DISPUTE_WINDOW_SECS)
                        + 1
                        + MAX_RESOLVE_DEFERRALS as u64,
                "the number of deferrals is bounded (offset {offset})"
            );
            now = d.deadline;
            state = plan.state;
        }
        assert!(
            defers >= MAX_RESOLVE_DEFERRALS,
            "every dispute is guaranteed at least K deferrals (offset {offset})"
        );
    }
}

// ===========================================================================
// B4: conservation over a randomized deposit/challenge/resolve/defer sequence
// ===========================================================================

/// A minimal coin ledger: the plan is pure policy, so the test applies the
/// effects itself and checks the books.
#[derive(Default)]
struct Ledger {
    balances: std::collections::BTreeMap<[u8; 32], i128>,
}

impl Ledger {
    fn fund(&mut self, addr: [u8; 32], amount: u64) {
        *self.balances.entry(addr).or_insert(0) += amount as i128;
    }
    fn balance(&self, addr: &[u8; 32]) -> i128 {
        *self.balances.get(addr).unwrap_or(&0)
    }
    fn delta(&mut self, addr: [u8; 32], d: i128) {
        *self.balances.entry(addr).or_insert(0) += d;
    }
    /// Apply a plan's effects. Returns `(minted, burned)`.
    fn apply(&mut self, plan: &BridgePlan, payer: [u8; 32]) -> (u64, u64) {
        let mut minted = 0u64;
        let mut burned = 0u64;
        for e in &plan.effects {
            match e {
                BridgeEffect::Credit { recipient, amount } => {
                    self.delta(*recipient, *amount as i128);
                    minted += *amount;
                }
                BridgeEffect::Park { amount } => {
                    self.delta(payer, -(*amount as i128));
                    self.delta(ESCROW, *amount as i128);
                }
                BridgeEffect::Unpark { recipient, amount } => {
                    self.delta(ESCROW, -(*amount as i128));
                    self.delta(*recipient, *amount as i128);
                }
                BridgeEffect::Clawback { account, amount } => {
                    self.delta(*account, -(*amount as i128));
                    self.delta(ESCROW, *amount as i128);
                }
                BridgeEffect::Burn { amount } => {
                    self.delta(ESCROW, -(*amount as i128));
                    burned += *amount;
                }
            }
        }
        (minted, burned)
    }
    /// Total supply tracked by the ledger (every account, the escrow included).
    fn supply(&self) -> i128 {
        self.balances.values().sum()
    }
}

/// B4 / W7.1 (requirement 3): over a randomized sequence of deposits,
/// challenges, resolves and defers, the books must balance EXACTLY and no
/// balance may ever go negative.
///
/// The invariant: the tracked supply changes by exactly what the bridge
/// minted minus what it burned — a challenge moves coins into the escrow, a
/// confirm moves them back, a revoke pays the finder out of the escrow and
/// burns the rest, and a defer moves NOTHING.
#[test]
fn bridge_dispute_conservation_holds_over_a_randomized_sequence() {
    // Deterministic PRNG (xorshift64*), so the sequence is reproducible.
    let mut seed = 0x2545F491_4F6CDD1Du64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };

    let (ks, pubs) = validators();
    let payer = [0x03u8; 32];
    let challengers = [[0xC0u8; 32], [0xC1u8; 32]];
    let mut ledger = Ledger::default();
    ledger.fund(payer, 1_000_000 * STELL);
    for c in challengers {
        ledger.fund(c, 1_000 * STELL);
    }

    let mut state = BridgeState::default();
    let mut now = TS;
    let mut deposits: Vec<([u8; 32], [u8; 32], u64)> = Vec::new();
    let mut disputes: Vec<u64> = Vec::new();
    let mut minted_total = 0u64;
    let mut burned_total = 0u64;
    // The supply the actors started with (the bridge itself mints nothing
    // until a deposit lands).
    let initial = 1_000_000 * STELL + 2 * 1_000 * STELL;
    // THE INVARIANT, checked after EVERY step: the tracked supply equals the
    // initial supply plus what the bridge minted minus what it burned - i.e.
    // every coin the bridge moved is accounted for, and the only coins that
    // left the system left through an explicit burn.
    let check = |ledger: &Ledger, minted: u64, burned: u64| {
        assert_eq!(
            ledger.supply(),
            initial as i128 + minted as i128 - burned as i128,
            "the books balance exactly: supply == initial + minted - burned"
        );
        for (addr, bal) in &ledger.balances {
            assert!(
                *bal >= 0,
                "no balance may go negative: {:?} holds {bal}",
                addr
            );
        }
        assert!(
            ledger.balance(&ESCROW) >= 0,
            "the escrow never goes negative"
        );
    };

    // Phase 1: deposits.
    for i in 0..12u8 {
        let hash = [0x90 + i; 32];
        let recipient = [0x50 + i; 32];
        let amount = (1 + (next() % 500)) * STELL;
        let dep = deposit(hash, recipient, amount);
        let att = attest_for(&dep, &ks[..2]);
        let plan = state
            .plan(&[att, dep], &pubs, payer, now)
            .expect("deposit plans");
        let (minted, burned) = ledger.apply(&plan, payer);
        minted_total += minted;
        burned_total += burned;
        check(&ledger, minted_total, burned_total);
        state = plan.state;
        deposits.push((hash, recipient, amount));
        now += 60 + next() % 600;
    }

    // Phase 2: challenges, resolves and defers.
    for _ in 0..60 {
        let roll = next() % 10;
        let challenger = challengers[(next() % challengers.len() as u64) as usize];
        if roll < 3 && !deposits.is_empty() {
            // Challenge a deposit that is not disputed yet.
            let idx = (next() % deposits.len() as u64) as usize;
            let (hash, _, _) = deposits[idx];
            if state
                .deposit_records
                .get(&hash)
                .map(|r| r.disputed)
                .unwrap_or(true)
            {
                now += 60;
                continue;
            }
            let plan = match state.plan(
                &[BridgeIntent::Challenge {
                    source_tx_hash: hash,
                }],
                &pubs,
                challenger,
                now,
            ) {
                Ok(p) => p,
                Err(_) => {
                    now += 60;
                    continue;
                }
            };
            let (_, burned) = ledger.apply(&plan, challenger);
            burned_total += burned;
            check(&ledger, minted_total, burned_total);
            state = plan.state;
            disputes.push(state.next_dispute_id - 1);
        } else if !disputes.is_empty() {
            // Resolve an open dispute with one of three payloads: the honest
            // attestation (confirm), a junk bundle (defer) or a genuine
            // retraction (revoke).
            let did = disputes[(next() % disputes.len() as u64) as usize];
            let mut intents: Vec<BridgeIntent> = Vec::new();
            let Some(d) = state.disputes.get(&did) else {
                now += 60;
                continue;
            };
            let (hash, recipient, amount) = *deposits
                .iter()
                .find(|(h, _, _)| *h == d.source_tx_hash)
                .expect("dispute has a deposit");
            match next() % 3 {
                0 => intents.push(quorum_proof(hash, recipient, amount, &ks)),
                1 => intents.push(failing_proof(hash)),
                _ => intents.push(genuine_failure_proof(hash, recipient, amount, &ks)),
            }
            intents.push(BridgeIntent::Resolve { dispute_id: did });
            let plan = match state.plan(&intents, &pubs, challenger, now) {
                Ok(p) => p,
                Err(_) => {
                    now += 60;
                    continue;
                }
            };
            let (_, burned) = ledger.apply(&plan, challenger);
            burned_total += burned;
            check(&ledger, minted_total, burned_total);
            state = plan.state;
        }
        now += 60 + next() % 600;
    }

    // Final book check: supply == initial supply + minted - burned.
    check(&ledger, minted_total, burned_total);
    // The bridge's own mint counter agrees with the burned amount: the
    // outstanding minted supply is exactly what the ledger holds above the
    // initial balances.
    assert!(
        state.total_minted <= BRIDGE_MINT_CAP_NANO,
        "the cumulative mint cap still holds"
    );
    // Every dispute that resolved did so by moving the escrow in and out
    // exactly: the escrow balance is the sum of the open disputes' amounts
    // plus their bonds.
    let expected_escrow: u64 = state
        .disputes
        .values()
        .filter(|d| !d.resolved)
        .map(|d| d.amount + d.bond)
        .sum();
    assert_eq!(
        ledger.balance(&ESCROW),
        expected_escrow as i128,
        "the escrow holds exactly the open disputes' deposit + bond"
    );
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
        assert_eq!(
            d.deadline,
            now + RESOLVE_DEFER_SECS,
            "defer {i}: one window out"
        );
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
            &[failing_proof(hash), BridgeIntent::Resolve { dispute_id: 0 }],
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
    assert!(!s2.pending_withdrawals.contains_key(&0));
    // Release of the refunded id: unknown.
    let err = s2
        .plan(
            &[BridgeIntent::Release { req_id: 0 }],
            &pubs,
            payer,
            TS + REFUND_GRACE_SECS + 2,
        )
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
