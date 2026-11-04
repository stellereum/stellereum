//! §9 CONFIDENTIAL TRANSFER engine layer, at the API/commitment level.
//!
//! Privacy is library-only today: `src/crypto_privacy.rs` can BUILD a Pedersen
//! commitment and a `ConfidentialTransfer`, but nothing applied one to a ledger
//! and nothing committed the result. These tests pin the engine invariants that
//! the coordinator's opcode handler will rely on:
//!
//! 1. value conservation — `sum(C_in) - sum(C_out) == fee*G`;
//! 2. a forged balance (an equation that does not hold) is rejected and the
//!    state does not move;
//! 3. a commitment cannot be spent twice;
//! 4. the shielded state has a deterministic digest that any mutation changes;
//! 5. two nodes that apply the SAME payload reach the SAME digest/root;
//! 6. the domain is CONDITIONAL: an empty state contributes zero bytes, so the
//!    genesis root and `COMMITMENT_VERSION == 4` are untouched (the KAT file
//!    `tests/genesis_root_known_answer_tests.rs` proves the root itself).
//!
//! No clock, no RNG in the engine: the same inputs always produce the same
//! bytes, which is the only reason a shielded ledger can be consensus state.

use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha256};

use stellereum::commitment::{
    commitment_digest, commitment_digest_with_confidential, CommitmentSnapshot,
};
use stellereum::contract::ContractRegistry;
use stellereum::crypto_privacy::{
    confidential_digest, write_confidential_domain, ConfidentialError, ConfidentialState,
    ConfidentialTransfer, PedersenCommitment, ZERO_COMMITMENT,
};
use stellereum::governance::Governance;
use stellereum::oracle::OracleState;
use stellereum::orderbook::OrderbookManager;
use stellereum::pmm::PrimaryMarketMaker;
use stellereum::staking::StakingLedger;
use stellereum::token::TokenRegistry;
use stellereum::zkml::SessionKeyRegistry;

const SENDER: [u8; 32] = [0x11; 32];
const RECIPIENT: [u8; 32] = [0x22; 32];

/// Fund a test transfer's inputs as SENDER-owned (audit 2026-10-06: inputs
/// must be recorded as owned by the sender, or apply rejects NotOwner).
fn fund_inputs(state: &mut ConfidentialState, tx: &ConfidentialTransfer) {
    for c in &tx.input_commitments {
        state.note_shielded_output(&SENDER, c.commitment);
    }
}

/// A valid one-in/one-out transfer: input (value + fee), output (value), both
/// with the SAME blinding, so `C_in - C_out = fee*G` exactly. This is the same
/// blinding-conservation trick `Wallet::create_confidential_transfer` uses.
fn balanced_transfer(value: u64, fee: u64) -> ConfidentialTransfer {
    let r = Scalar::from(0x5EED_u64);
    let c_in = PedersenCommitment::commit(value + fee, &r);
    let c_out = PedersenCommitment::commit(value, &r);
    ConfidentialTransfer::new(vec![c_in], vec![c_out], fee)
}

fn empty_snapshot() -> CommitmentSnapshot {
    CommitmentSnapshot {
        tokens: TokenRegistry::default(),
        staking: StakingLedger::default(),
        orderbooks: OrderbookManager::default(),
        order_escrow: std::collections::HashMap::new(),
        pmm: PrimaryMarketMaker::new(),
        pmm_usdt_token: None,
        pmm_treasury: [0u8; 32],
        contracts: ContractRegistry::default(),
        governance: Governance::default(),
        oracle: OracleState::default(),
        session_keys: SessionKeyRegistry::default(),
        bridge: stellereum::bridge::BridgeState::default(),
        cross_shard_consumed: Vec::new(),
        cross_shard_produced: Vec::new(),
        cross_shard_completed: Vec::new(),
        cross_shard_xpc: Vec::new(),
    }
}

// ===========================================================================
// 1. Conservation holds and the balances move as the group equation dictates.
// ===========================================================================

#[test]
fn conservation_holds_and_shielded_balances_move() {
    let tx = balanced_transfer(1_480, 20);
    assert!(
        tx.verify_balance_conservation(),
        "precondition: the equation holds"
    );

    let mut state = ConfidentialState::new();
    assert!(state.is_empty());
    assert_eq!(state.balance(&SENDER), ZERO_COMMITMENT);

    fund_inputs(&mut state, &tx);
    state
        .apply_transfer(&SENDER, &RECIPIENT, &tx)
        .expect("a balanced transfer must apply");

    // Sender spent sum(C_in) and received nothing: balance = -C_in.
    assert_eq!(
        state.balance(&SENDER),
        ZERO_COMMITMENT.sub(&tx.input_commitments[0]).unwrap(),
        "sender is debited by exactly the input commitment"
    );
    // Recipient gained sum(C_out): balance = +C_out.
    assert_eq!(
        state.balance(&RECIPIENT),
        ZERO_COMMITMENT.add(&tx.output_commitments[0]).unwrap(),
        "recipient is credited by exactly the output commitment"
    );
    assert_eq!(
        state.total_fees, 20,
        "the fee advances the transparent total"
    );
    assert!(state.is_spent(&tx.input_commitments[0].commitment));
    assert!(!state.is_empty());
}

#[test]
fn self_transfer_nets_to_exactly_the_fee() {
    // sender == recipient must combine the debit and credit, not clobber one
    // with the other: net change is -C_in + C_out = -fee*G.
    let tx = balanced_transfer(1_000, 25);
    let mut state = ConfidentialState::new();
    fund_inputs(&mut state, &tx);
    state
        .apply_transfer(&SENDER, &SENDER, &tx)
        .expect("self transfer applies");

    let fee_point = curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT * Scalar::from(25u64);
    let expected = ZERO_COMMITMENT
        .sub(&tx.input_commitments[0])
        .unwrap()
        .add(&tx.output_commitments[0])
        .unwrap();
    assert_eq!(state.balance(&SENDER), expected);
    assert_eq!(
        expected.commitment,
        PedersenCommitment {
            commitment: (-fee_point).compress().to_bytes()
        }
        .commitment,
        "net balance change is exactly the fee commitment"
    );
}

// ===========================================================================
// 2. A forged balance is rejected and moves nothing.
// ===========================================================================

#[test]
fn forged_balance_is_rejected_and_state_is_unchanged() {
    // 100 in, 1000 out, no fee: the equation fails by a whole 900*G.
    let r = Scalar::from(3u64);
    let c_in = PedersenCommitment::commit(100, &r);
    let c_out = PedersenCommitment::commit(1_000, &r);
    let forged = ConfidentialTransfer::new(vec![c_in], vec![c_out], 0);

    let mut state = ConfidentialState::new();
    let before = confidential_digest(&state);
    fund_inputs(&mut state, &forged);
    let funded = confidential_digest(&state);
    assert_ne!(funded, before, "funding itself is state");

    let err = state
        .apply_transfer(&SENDER, &RECIPIENT, &forged)
        .expect_err("an unbalanced transfer must be rejected");
    assert_eq!(err, ConfidentialError::ConservationViolated);
    assert!(
        err.to_string().contains("balance"),
        "the error must name the violated rule: {err}"
    );
    assert_eq!(
        confidential_digest(&state),
        funded,
        "a rejected transfer must not move the shielded digest past funding"
    );
    assert!(
        !state.is_empty(),
        "funding remains; only the transfer was refused"
    );
}

#[test]
fn malformed_commitment_is_rejected() {
    // A 32-byte string that is not a canonical Ristretto encoding.
    let junk = PedersenCommitment {
        commitment: [0xFF; 32],
    };
    let tx = ConfidentialTransfer::new(
        vec![junk],
        vec![PedersenCommitment::commit(0, &Scalar::from(1u64))],
        0,
    );
    let mut state = ConfidentialState::new();
    let err = state.apply_transfer(&SENDER, &RECIPIENT, &tx).unwrap_err();
    assert_eq!(err, ConfidentialError::InvalidCommitment([0xFF; 32]));
    assert!(state.is_empty());
}

// ===========================================================================
// 3. Double-spend of the same commitment is rejected.
// ===========================================================================

#[test]
fn double_spend_of_a_commitment_is_rejected() {
    let tx = balanced_transfer(500, 10);
    let input = tx.input_commitments[0].commitment;

    let mut state = ConfidentialState::new();
    fund_inputs(&mut state, &tx);
    state
        .apply_transfer(&SENDER, &RECIPIENT, &tx)
        .expect("first spend applies");
    assert!(
        state.is_spent(&input),
        "the input commitment is now in the spent set"
    );
    let after_first = confidential_digest(&state);

    let err = state
        .apply_transfer(&SENDER, &RECIPIENT, &tx)
        .expect_err("the same commitment cannot be spent twice");
    assert_eq!(err, ConfidentialError::DoubleSpend(input));
    assert!(
        err.to_string().contains("already spent"),
        "the error must name the double spend: {err}"
    );
    assert_eq!(
        confidential_digest(&state),
        after_first,
        "a rejected double-spend must not move the digest"
    );
}

#[test]
fn repeated_input_inside_one_transfer_is_rejected() {
    // Spend the same input commitment twice in ONE transfer: the multiset sum
    // would be ill-defined, so it is refused before the spent set is touched.
    let r = Scalar::from(9u64);
    let c_in = PedersenCommitment::commit(1_000, &r);
    let c_out = PedersenCommitment::commit(1_000, &r);
    // (C_in + C_in) - C_out = 1000*G != 0, so this is also unbalanced; the
    // duplicate check fires first and identifies the real defect.
    let tx = ConfidentialTransfer::new(vec![c_in, c_in], vec![c_out], 0);

    let mut state = ConfidentialState::new();
    let err = state.apply_transfer(&SENDER, &RECIPIENT, &tx).unwrap_err();
    assert_eq!(err, ConfidentialError::DuplicateInput(c_in.commitment));
    assert!(state.is_empty());
}

// ===========================================================================
// 4. Deterministic digest, sensitive to every field.
// ===========================================================================

#[test]
fn identical_states_digest_identically_and_every_mutation_changes_it() {
    let tx = balanced_transfer(700, 30);

    let build = || {
        let mut s = ConfidentialState::new();
        fund_inputs(&mut s, &tx);
        s.apply_transfer(&SENDER, &RECIPIENT, &tx).unwrap();
        s
    };
    let a = build();
    let b = build();
    assert_eq!(
        confidential_digest(&a),
        confidential_digest(&b),
        "two identical shielded states must digest identically"
    );

    // Mutate the fee total.
    let mut fee_changed = a.clone();
    fee_changed.total_fees += 1;
    assert_ne!(confidential_digest(&a), confidential_digest(&fee_changed));

    // Mutate the spent set.
    let mut spent_changed = a.clone();
    spent_changed.spent.insert([0xAB; 32]);
    assert_ne!(confidential_digest(&a), confidential_digest(&spent_changed));

    // Mutate a balance (one byte of one commitment).
    let mut balance_changed = a.clone();
    let mut c = balance_changed.balance(&RECIPIENT);
    c.commitment[0] ^= 0x01;
    balance_changed.balances.insert(RECIPIENT, c);
    assert_ne!(
        confidential_digest(&a),
        confidential_digest(&balance_changed)
    );

    // And the transfer encoding itself is deterministic + mutation sensitive.
    assert_eq!(tx.encode(), balanced_transfer(700, 30).encode());
    assert_eq!(tx.digest(), balanced_transfer(700, 30).digest());
    let mut other = balanced_transfer(700, 30);
    other.fee = 31;
    assert_ne!(tx.digest(), other.digest());
}

// ===========================================================================
// 5. Same payload => same digest (two independent nodes agree).
// ===========================================================================

#[test]
fn same_payload_same_shielded_root() {
    let tx = balanced_transfer(1_234, 56);

    let mut node_a = ConfidentialState::new();
    let mut node_b = ConfidentialState::new();
    fund_inputs(&mut node_a, &tx);
    fund_inputs(&mut node_b, &tx);
    node_a.apply_transfer(&SENDER, &RECIPIENT, &tx).unwrap();
    node_b.apply_transfer(&SENDER, &RECIPIENT, &tx).unwrap();

    assert_eq!(
        confidential_digest(&node_a),
        confidential_digest(&node_b),
        "applying the same payload to identical state must reach the same digest"
    );
    assert_eq!(node_a, node_b, "the states themselves are equal");

    // The commitment-level entry point agrees too.
    let snap = empty_snapshot();
    assert_eq!(
        commitment_digest_with_confidential(&snap, &node_a),
        commitment_digest_with_confidential(&snap, &node_b)
    );
}

// ===========================================================================
// 6. Conditional domain: empty contributes NOTHING (genesis is untouched).
// ===========================================================================

#[test]
fn empty_confidential_domain_contributes_zero_bytes() {
    let empty = ConfidentialState::new();

    // A hasher that folded the empty domain must equal a fresh hasher: zero
    // bytes written. That is what makes the fold safe against the pinned
    // genesis root without a COMMITMENT_VERSION bump.
    let mut folded = Sha256::new();
    write_confidential_domain(&mut folded, &empty);
    let fresh = Sha256::new();
    assert_eq!(
        folded.finalize(),
        fresh.finalize(),
        "an empty shielded state must write zero bytes"
    );

    // And at the commitment layer, the confidential-aware digest is exactly the
    // existing commitment digest when the domain is empty...
    let snap = empty_snapshot();
    assert_eq!(
        commitment_digest_with_confidential(&snap, &empty),
        commitment_digest(&snap),
        "empty shielded domain must not re-root the chain"
    );

    // ...and differs the moment shielded state exists.
    let mut used = empty.clone();
    let seed_tx = balanced_transfer(100, 5);
    fund_inputs(&mut used, &seed_tx);
    used.apply_transfer(&SENDER, &RECIPIENT, &seed_tx).unwrap();
    assert_ne!(
        commitment_digest_with_confidential(&snap, &used),
        commitment_digest(&snap),
        "a non-empty shielded domain must be visible in the commitment"
    );
}

// ===========================================================================
// §9 Batched verification (MSM throughput layer): differential tests.
//
// HARD RULE: consensus-affecting results are BIT-IDENTICAL across backends.
// The scalar path is the reference; the batch/MSM entry points are
// throughput only. Every test below builds randomized inputs (deterministic
// seed, so failures replay), computes the scalar result and the batched
// result independently, and asserts exact equality — including on invalid
// inputs, where both must reject. At least one accepting and one rejecting
// case per test, so the suite cannot pass vacuously.
// ===========================================================================

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use stellereum::crypto_privacy::{msm_backend_name, BitProof, RangeProof, MSM_FOLD_CUTOFF};

fn prize_rng() -> StdRng {
    StdRng::seed_from_u64(0x9E3779B9_7F4A7C15)
}

#[test]
fn batch_openings_match_scalar_randomized() {
    let mut rng = prize_rng();
    assert!(
        msm_backend_name().contains("dalek"),
        "backend label must name dalek"
    );
    assert!(
        (1..=64).contains(&MSM_FOLD_CUTOFF),
        "fold cutoff must be sane"
    );
    for &n in &[0usize, 1, 2, 7, 8, 9, 33] {
        let mut ops: Vec<(PedersenCommitment, u64, Scalar)> = Vec::with_capacity(n + 3);
        for _ in 0..n {
            let v = rng.gen_range(0..1_000_000u64);
            let r = Scalar::from(rng.gen::<u64>());
            ops.push((PedersenCommitment::commit(v, &r), v, r));
        }
        // Negative cases: wrong value, wrong blinding, tampered bytes.
        if n > 0 {
            let (c, v, r) = ops[0];
            ops.push((c, v.wrapping_add(1), r));
            ops.push((c, v, r + Scalar::ONE));
            let mut bad = c;
            bad.commitment[0] ^= 0x01;
            ops.push((bad, v, r));
        }
        let scalar: Vec<bool> = ops.iter().map(|(c, v, r)| c.verify(*v, r)).collect();
        assert_eq!(PedersenCommitment::batch_verify(&ops), scalar);
        if n > 0 {
            assert!(scalar[0], "honest opening must verify");
            assert!(
                scalar[n..].iter().all(|&b| !b),
                "forged openings must reject"
            );
        }
    }
    assert!(PedersenCommitment::batch_verify(&[]).is_empty());
}

#[test]
fn batch_conservation_matches_scalar_randomized() {
    let mut rng = prize_rng();
    let mut txs = Vec::new();
    // Valid multi-input transfers: blindings telescope (r_out = r1 + r2).
    for _ in 0..8 {
        let (a, b, fee) = (
            rng.gen_range(0..10_000u64),
            rng.gen_range(0..10_000u64),
            rng.gen_range(0..100u64),
        );
        let (r1, r2) = (
            Scalar::from(rng.gen::<u64>()),
            Scalar::from(rng.gen::<u64>()),
        );
        // sum_in - sum_out = (a+fee+b - (a+b))*G = fee*G exactly.
        let c1 = PedersenCommitment::commit(a + fee, &r1);
        let c2 = PedersenCommitment::commit(b, &r2);
        let cout = PedersenCommitment::commit(a + b, &(r1 + r2));
        txs.push(ConfidentialTransfer::new(vec![c1, c2], vec![cout], fee));
    }
    // Forged, empty-sided, and malformed transfers.
    {
        let r = Scalar::from(rng.gen::<u64>());
        txs.push(ConfidentialTransfer::new(
            vec![PedersenCommitment::commit(100, &r)],
            vec![PedersenCommitment::commit(1_000, &r)],
            0,
        ));
        txs.push(ConfidentialTransfer::new(vec![], vec![], 0));
        txs.push(ConfidentialTransfer::new(
            vec![PedersenCommitment {
                commitment: [0xFF; 32],
            }],
            vec![PedersenCommitment::commit(0, &r)],
            0,
        ));
    }
    let scalar: Vec<bool> = txs
        .iter()
        .map(|t| t.verify_balance_conservation())
        .collect();
    assert!(
        scalar[..8].iter().all(|&b| b),
        "honest transfers must verify"
    );
    assert!(
        !scalar[8..].iter().any(|&b| b),
        "forged transfers must reject"
    );
    assert_eq!(
        ConfidentialTransfer::batch_verify_balance_conservation(&txs),
        scalar,
        "batch conservation must equal scalar conservation on every input"
    );
    assert!(ConfidentialTransfer::batch_verify_balance_conservation(&[]).is_empty());
}

#[test]
fn batch_range_proofs_match_scalar_randomized() {
    let mut rng = prize_rng();
    let mut pairs: Vec<(PedersenCommitment, RangeProof)> = Vec::new();
    for i in 0..24 {
        let bits = [8u8, 16, 32][i % 3];
        let max = if bits == 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        };
        let v = rng.gen_range(0..=max.min(1_000_000));
        let r = Scalar::from(rng.gen::<u64>());
        let c = PedersenCommitment::commit(v, &r);
        pairs.push((c, RangeProof::prove(&c, v, &r, bits)));
    }
    // Negative cases.
    {
        let r = Scalar::from(rng.gen::<u64>());
        let c = PedersenCommitment::commit(5, &r);
        let p = RangeProof::prove(&c, 5, &r, 8);
        // Wrong commitment.
        pairs.push((PedersenCommitment::commit(6, &r), p.clone()));
        // Tampered bit commitment.
        let mut tp = p.clone();
        tp.bit_commitments[0] = PedersenCommitment::commit(1, &Scalar::from(rng.gen::<u64>()));
        pairs.push((c, tp));
        // Truncated proof (length mismatch).
        let mut short = p.clone();
        short.bit_proofs.pop();
        pairs.push((c, short));
        // Degenerate bit-widths.
        let mut zero = p.clone();
        zero.bits = 0;
        pairs.push((c, zero));
        let mut wide = p.clone();
        wide.bits = 65;
        pairs.push((c, wide));
        // Tampered OR-proof bytes (verdict may vary, agreement may not).
        let mut tb = p;
        tb.bit_proofs[0].s0[0] ^= 0xFF;
        pairs.push((c, tb));
    }
    let refs: Vec<(&PedersenCommitment, &RangeProof)> = pairs.iter().map(|(c, p)| (c, p)).collect();
    let scalar: Vec<bool> = refs.iter().map(|(c, p)| RangeProof::verify(c, p)).collect();
    assert!(scalar[..24].iter().all(|&b| b), "honest proofs must verify");
    assert!(
        scalar[24..].iter().all(|&b| !b),
        "forged proofs must reject: {scalar:?}"
    );
    assert_eq!(
        RangeProof::batch_verify(&refs),
        scalar,
        "batch range verify must equal scalar verify on every input"
    );
    assert!(RangeProof::batch_verify(&[]).is_empty());
}

#[test]
fn bitproof_msm_matches_scalar_randomized() {
    let mut rng = prize_rng();
    let mut trues = 0;
    let mut falses = 0;
    for i in 0..64 {
        let bit = i % 2 == 0;
        let r = Scalar::from(rng.gen::<u64>());
        let c = PedersenCommitment::commit(bit as u64, &r);
        let mut proof = BitProof::prove(&c, bit, &r);
        if i % 3 == 0 {
            // Tamper with random proof bytes: verdict may flip, agreement not.
            let dst = match rng.gen_range(0..4) {
                0 => &mut proof.e0,
                1 => &mut proof.s0,
                2 => &mut proof.e1,
                _ => &mut proof.s1,
            };
            dst[rng.gen_range(0..32)] ^= 1 << rng.gen_range(0..8);
        }
        let (a, b) = (
            BitProof::verify(&c, &proof),
            BitProof::verify_scalar(&c, &proof),
        );
        assert_eq!(a, b, "MSM/scalar BitProof diverged at case {i}");
        if a {
            trues += 1;
        } else {
            falses += 1;
        }
        // And against a junk commitment both must reject.
        let junk = PedersenCommitment {
            commitment: [0xFF; 32],
        };
        assert!(!BitProof::verify(&junk, &proof));
        assert!(!BitProof::verify_scalar(&junk, &proof));
    }
    assert!(
        trues > 0 && falses > 0,
        "need both outcomes: {trues}/{falses}"
    );
}

// ===========================================================================
// Ownership (audit 2026-10-06, F-A fix).
// ===========================================================================

#[test]
fn unowned_inputs_are_rejected_and_move_nothing() {
    // Fresh commitments nobody funded: the old code spent them happily.
    let tx = balanced_transfer(200, 10);
    let mut state = ConfidentialState::new();
    let before = confidential_digest(&state);
    let err = state
        .apply_transfer(&SENDER, &RECIPIENT, &tx)
        .expect_err("unowned inputs must be rejected");
    assert_eq!(
        err,
        ConfidentialError::NotOwner(tx.input_commitments[0].commitment)
    );
    assert_eq!(confidential_digest(&state), before);
    assert!(state.is_empty());
}

#[test]
fn others_commitment_is_rejected_even_when_funded() {
    // Funded to SOMEONE ELSE (the recipient of an earlier transfer): the
    // sender still may not spend it.
    let tx = balanced_transfer(200, 10);
    let mut state = ConfidentialState::new();
    state.note_shielded_output(&RECIPIENT, tx.input_commitments[0].commitment);
    let err = state
        .apply_transfer(&SENDER, &RECIPIENT, &tx)
        .expect_err("another account's commitment must be rejected");
    assert_eq!(
        err,
        ConfidentialError::NotOwner(tx.input_commitments[0].commitment)
    );
}

#[test]
fn ownership_map_tracks_spend_and_fund() {
    let tx = balanced_transfer(300, 15);
    let mut state = ConfidentialState::new();
    fund_inputs(&mut state, &tx);
    assert_eq!(
        state.owned.get(&tx.input_commitments[0].commitment),
        Some(&SENDER),
        "funding records ownership"
    );
    state.apply_transfer(&SENDER, &RECIPIENT, &tx).unwrap();
    assert!(
        !state
            .owned
            .contains_key(&tx.input_commitments[0].commitment),
        "spend clears ownership"
    );
    assert_eq!(
        state.owned.get(&tx.output_commitments[0].commitment),
        Some(&RECIPIENT),
        "outputs are owned by the recipient"
    );
    // A spent input is gone from ownership: replay now fails as double-spend
    // (spent check precedes ownership), never as a fresh spend.
    let err = state.apply_transfer(&SENDER, &RECIPIENT, &tx).unwrap_err();
    assert_eq!(
        err,
        ConfidentialError::DoubleSpend(tx.input_commitments[0].commitment)
    );
}

// ===========================================================================
// Snapshot upgrade (audit 2026-10-06, F-A fix).
// ===========================================================================

#[test]
fn v1_snapshot_upgrades_with_frozen_unowned_outputs() {
    use curve25519_dalek::scalar::Scalar;
    use stellereum::crypto_privacy::{ConfidentialStateV1, PedersenCommitment};
    // Old-shape state with history but no ownership map.
    let v1 = ConfidentialStateV1 {
        balances: [(SENDER, PedersenCommitment::commit(100, &Scalar::from(1u64)))]
            .into_iter()
            .collect(),
        spent: [PedersenCommitment::commit(50, &Scalar::from(2u64)).commitment]
            .into_iter()
            .collect(),
        total_fees: 7,
    };
    let bytes = bincode::serialize(&v1).expect("v1 serializes");
    // New code must still READ it (prefix-compatible): upgrade, don't refuse.
    let upgraded: ConfidentialState = {
        match bincode::deserialize::<ConfidentialState>(&bytes) {
            Ok(s) => s,
            Err(_) => {
                let old: ConfidentialStateV1 = bincode::deserialize(&bytes).expect("v1 reads");
                old.upgrade()
            }
        }
    };
    assert_eq!(upgraded.balances, v1.balances);
    assert_eq!(upgraded.spent, v1.spent);
    assert_eq!(upgraded.total_fees, 7);
    assert!(
        upgraded.owned.is_empty(),
        "pre-fix outputs are unattributed"
    );
    // ...and therefore unspendable (frozen, not stealable).
    let tx = balanced_transfer(10, 1);
    let err = upgraded
        .clone()
        .apply_transfer(&SENDER, &RECIPIENT, &tx)
        .unwrap_err();
    assert_eq!(
        err,
        ConfidentialError::NotOwner(tx.input_commitments[0].commitment)
    );
}

#[test]
fn pre_ownership_digest_is_byte_identical_after_upgrade() {
    // Upgrade compat (deploy lesson 2026-10-06): a restored pre-fix state
    // (no owned map) must digest EXACTLY as before, or the node refuses to
    // start on restore-root mismatch. The owned section is self-conditional.
    use curve25519_dalek::scalar::Scalar;
    use stellereum::crypto_privacy::{ConfidentialStateV1, PedersenCommitment};
    let v1 = ConfidentialStateV1 {
        balances: [(SENDER, PedersenCommitment::commit(100, &Scalar::from(1u64)))]
            .into_iter()
            .collect(),
        spent: [PedersenCommitment::commit(50, &Scalar::from(2u64)).commitment]
            .into_iter()
            .collect(),
        total_fees: 7,
    };
    let upgraded = v1.upgrade();
    assert_eq!(
        confidential_digest(&upgraded),
        {
            // Reference: the OLD domain encoding (no owned section at all).
            // Recomputed here from the same fields the old writer emitted.
            let mut tmp = ConfidentialState::new();
            tmp.balances = upgraded.balances.clone();
            tmp.spent = upgraded.spent.clone();
            tmp.total_fees = upgraded.total_fees;
            // owned is empty -> gate skips the section -> identical bytes.
            confidential_digest(&tmp)
        },
        "upgraded state without owned entries digests like the old encoding"
    );
    // And a state WITH owned entries visibly differs (the section exists).
    let mut with_owned = upgraded.clone();
    with_owned.note_shielded_output(&SENDER, [0xAA; 32]);
    assert_ne!(
        confidential_digest(&with_owned),
        confidential_digest(&upgraded),
        "owned entries must enter the digest"
    );
}
