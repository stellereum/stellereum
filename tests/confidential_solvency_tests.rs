//! Shielded-pool solvency regression tests (gap F-A).
//!
//! The pool was equation-only: `ConfidentialState::apply_transfer` checks
//! `sum(C_in) - sum(C_out) == fee*G` plus the spent set, so a commitment to a
//! negative/wrapped value sailed through and minted money out of nothing —
//! before any unshield/entry-exit feature may ship, every confidential input
//! AND output must prove non-negativity in [0, 2^64), fail-closed.
//!
//! These tests pin the fail-closed entry points in `src/crypto_privacy.rs`
//! (`ConfidentialTransfer::verify_ranges`,
//! `ConfidentialState::verify_transfer_with_ranges`,
//! `ConfidentialState::apply_transfer_with_ranges`):
//!
//! 1. a crafted negative-value INPUT (balance equation intact) is rejected;
//! 2. a crafted negative-value OUTPUT (balance equation intact) is rejected;
//! 3. a missing proof set is rejected loudly (no equation-only fallback);
//! 4. an honest transfer with full proofs is accepted exactly once;
//! 5. a replayed (double-spent) input is rejected via the spent set.
//!
//! Rejections are atomic: on error the state is byte-for-byte what it was
//! before (no partial acceptance — spent set, ownership map and fee total
//! all unchanged).

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

use stellereum::crypto_privacy::{
    ConfidentialError, ConfidentialState, ConfidentialTransfer, PedersenCommitment, RangeProof,
};

const SENDER: [u8; 32] = [0x11; 32];
const RECIPIENT: [u8; 32] = [0x22; 32];

fn blinding(seed: u64) -> Scalar {
    Scalar::from(seed)
}

/// Fund test inputs as SENDER-owned shielded coins.
fn fund_inputs(state: &mut ConfidentialState, tx: &ConfidentialTransfer) {
    for c in &tx.input_commitments {
        state.note_shielded_output(&SENDER, c.commitment);
    }
}

/// Point subtraction on commitments: `a - b` as a commitment encoding
/// `v_a - v_b` — exact group arithmetic, so the balance equation still holds
/// while the result encodes a NEGATIVE value no range proof can cover.
fn sub_commitment(a: &PedersenCommitment, b: &PedersenCommitment) -> PedersenCommitment {
    let pa = CompressedRistretto(a.commitment)
        .decompress()
        .expect("valid point");
    let pb = CompressedRistretto(b.commitment)
        .decompress()
        .expect("valid point");
    PedersenCommitment {
        commitment: (pa - pb).compress().to_bytes(),
    }
}

fn assert_pristine(state: &ConfidentialState) {
    assert!(
        state.spent.is_empty(),
        "rejection must not touch the spent set"
    );
    assert_eq!(state.total_fees, 0, "rejection must not advance fees");
}

// ===========================================================================
// 1. Negative-value crafted INPUT: equation holds, proofs must catch it.
// ===========================================================================

#[test]
fn negative_value_crafted_input_rejected() {
    // Inputs: an honest 1500 coin plus a crafted -500 coin, summing to 1000.
    // Output: an honest 1000 coin. fee = 0, so sum_in == sum_out exactly.
    let r_out = blinding(0xC10C);
    let r_big = blinding(0xB16);
    let c_out = PedersenCommitment::commit(1_000, &r_out);
    let c_big = PedersenCommitment::commit(1_500, &r_big);
    let c_neg = sub_commitment(&c_out, &c_big); // encodes -500

    let tx = ConfidentialTransfer::new(vec![c_big, c_neg], vec![c_out], 0);
    // The F-A hole, documented: the bare group equation HOLDS for this
    // money-printing transfer (1500 + (-500) == 1000).
    assert!(
        tx.verify_balance_conservation(),
        "premise: the crafted transfer satisfies the balance equation"
    );

    let mut state = ConfidentialState::new();
    fund_inputs(&mut state, &tx);

    // Honest proof for the honest input; a borrowed decoy proof for the
    // negative coin (no valid bit-decomposition of -500 exists, so whatever
    // the attacker attaches must fail reconstruction/binding).
    let r_decoy = blinding(0xDEC00);
    let c_decoy = PedersenCommitment::commit(500, &r_decoy);
    let p_big = RangeProof::prove_auto(&c_big, 1_500, &r_big);
    let p_decoy = RangeProof::prove_auto(&c_decoy, 500, &r_decoy);
    let p_out = RangeProof::prove_auto(&c_out, 1_000, &r_out);
    let input_ranges = vec![p_big, p_decoy];
    let output_ranges = vec![p_out];

    // Read-only gate rejects first, touching nothing.
    assert_eq!(
        state.verify_transfer_with_ranges(&SENDER, &tx, &input_ranges, &output_ranges),
        Err(ConfidentialError::InvalidRangeProof(c_neg.commitment))
    );
    // Mutating gate rejects with the same loud error...
    assert_eq!(
        state.apply_transfer_with_ranges(&SENDER, &RECIPIENT, &tx, &input_ranges, &output_ranges),
        Err(ConfidentialError::InvalidRangeProof(c_neg.commitment))
    );
    // ...and accepts nothing partially.
    assert_pristine(&state);
    assert!(state.is_owned(&c_big.commitment));
    assert!(state.is_owned(&c_neg.commitment));
    assert!(!state.is_owned(&c_out.commitment));

    // Control: the legacy equation-only path ACCEPTS this mint-from-nothing
    // on a clone — that is exactly the gap the fail-closed entry point
    // closes. (Never use bare apply_transfer as a solvency gate.)
    let mut legacy = state.clone();
    assert!(
        legacy.apply_transfer(&SENDER, &RECIPIENT, &tx).is_ok(),
        "control: equation-only check passes the negative-input forgery"
    );
}

// ===========================================================================
// 2. Negative-value crafted OUTPUT: per-output non-negativity enforced.
// ===========================================================================

#[test]
fn negative_value_crafted_output_rejected() {
    // Input: honest 1000. Outputs: honest 1500 plus crafted -500.
    // fee = 0: sum_out == sum_in exactly.
    let r_in = blinding(0x1A9E7);
    let r_big = blinding(0x0B16);
    let c_in = PedersenCommitment::commit(1_000, &r_in);
    let c_big = PedersenCommitment::commit(1_500, &r_big);
    let c_neg = sub_commitment(&c_in, &c_big); // encodes -500

    let tx = ConfidentialTransfer::new(vec![c_in], vec![c_big, c_neg], 0);
    assert!(
        tx.verify_balance_conservation(),
        "premise: the crafted transfer satisfies the balance equation"
    );

    let mut state = ConfidentialState::new();
    fund_inputs(&mut state, &tx);

    let r_decoy = blinding(0xDEC01);
    let c_decoy = PedersenCommitment::commit(42, &r_decoy);
    let p_in = RangeProof::prove_auto(&c_in, 1_000, &r_in);
    let p_big = RangeProof::prove_auto(&c_big, 1_500, &r_big);
    let p_decoy = RangeProof::prove_auto(&c_decoy, 42, &r_decoy);

    let input_ranges = vec![p_in];
    let output_ranges = vec![p_big, p_decoy];
    assert_eq!(
        state.verify_transfer_with_ranges(&SENDER, &tx, &input_ranges, &output_ranges),
        Err(ConfidentialError::InvalidRangeProof(c_neg.commitment))
    );
    assert_eq!(
        state.apply_transfer_with_ranges(&SENDER, &RECIPIENT, &tx, &input_ranges, &output_ranges),
        Err(ConfidentialError::InvalidRangeProof(c_neg.commitment))
    );
    assert_pristine(&state);
    assert!(!state.is_owned(&c_big.commitment));
    assert!(!state.is_owned(&c_neg.commitment));
}

// ===========================================================================
// 3. Missing proofs: fail-closed, never fail-open.
// ===========================================================================

#[test]
fn missing_proof_rejected() {
    // Honest one-in/one-out transfer: input (value + fee), output (value),
    // same blinding, so C_in - C_out == fee*G exactly.
    let r = blinding(0x5EED);
    let value = 1_480u64;
    let fee = 20u64;
    let c_in = PedersenCommitment::commit(value + fee, &r);
    let c_out = PedersenCommitment::commit(value, &r);
    let tx = ConfidentialTransfer::new(vec![c_in], vec![c_out], fee);
    assert!(tx.verify_balance_conservation());

    let p_in = RangeProof::prove_auto(&c_in, value + fee, &r);
    let p_out = RangeProof::prove_auto(&c_out, value, &r);

    // No proofs at all.
    {
        let mut state = ConfidentialState::new();
        fund_inputs(&mut state, &tx);
        assert_eq!(
            state.verify_transfer_with_ranges(&SENDER, &tx, &[], std::slice::from_ref(&p_out)),
            Err(ConfidentialError::MissingRangeProof)
        );
        assert_eq!(
            state.apply_transfer_with_ranges(
                &SENDER,
                &RECIPIENT,
                &tx,
                &[],
                std::slice::from_ref(&p_out)
            ),
            Err(ConfidentialError::MissingRangeProof)
        );
        assert_pristine(&state);
    }
    // Output proof set dropped (count mismatch on the other side).
    {
        let mut state = ConfidentialState::new();
        fund_inputs(&mut state, &tx);
        assert_eq!(
            state.apply_transfer_with_ranges(
                &SENDER,
                &RECIPIENT,
                &tx,
                std::slice::from_ref(&p_in),
                &[]
            ),
            Err(ConfidentialError::MissingRangeProof)
        );
        assert_pristine(&state);
    }
    // Truncated proof (a bit-proof removed): lengths still match at the
    // bundle level, so this is an INVALID proof, not a missing one — and it
    // still fails closed without ever touching the curve.
    {
        let mut state = ConfidentialState::new();
        fund_inputs(&mut state, &tx);
        let mut bad_out = p_out.clone();
        bad_out.bit_proofs.pop();
        assert_eq!(
            state.apply_transfer_with_ranges(
                &SENDER,
                &RECIPIENT,
                &tx,
                std::slice::from_ref(&p_in),
                &[bad_out]
            ),
            Err(ConfidentialError::InvalidRangeProof(c_out.commitment))
        );
        assert_pristine(&state);
    }
    // Tampered proof (bit-commitment swapped): reconstruction breaks, so the
    // gate rejects deterministically — still fail-closed.
    {
        let mut state = ConfidentialState::new();
        fund_inputs(&mut state, &tx);
        let mut bad_in = p_in.clone();
        bad_in.bit_commitments[0] =
            PedersenCommitment::commit(1, &PedersenCommitment::random_blinding());
        assert!(!RangeProof::verify(&c_in, &bad_in));
        assert_eq!(
            state.apply_transfer_with_ranges(
                &SENDER,
                &RECIPIENT,
                &tx,
                &[bad_in],
                std::slice::from_ref(&p_out)
            ),
            Err(ConfidentialError::InvalidRangeProof(c_in.commitment))
        );
        assert_pristine(&state);
    }
}

// ===========================================================================
// 4. Valid transfer accepted exactly once (full proofs, all gates green).
// ===========================================================================

#[test]
fn valid_transfer_accepted() {
    let r = blinding(0xBEEF);
    let value = 1_480u64;
    let fee = 20u64;
    let c_in = PedersenCommitment::commit(value + fee, &r);
    let c_out = PedersenCommitment::commit(value, &r);
    let tx = ConfidentialTransfer::new(vec![c_in], vec![c_out], fee);

    let p_in = RangeProof::prove_auto(&c_in, value + fee, &r);
    let p_out = RangeProof::prove_auto(&c_out, value, &r);
    let input_ranges = vec![p_in];
    let output_ranges = vec![p_out];

    let mut state = ConfidentialState::new();
    fund_inputs(&mut state, &tx);

    // Read-only gate passes without mutating...
    assert_eq!(
        state.verify_transfer_with_ranges(&SENDER, &tx, &input_ranges, &output_ranges),
        Ok(())
    );
    assert_pristine(&state);

    // ...then the mutating gate commits exactly once.
    assert_eq!(
        state.apply_transfer_with_ranges(&SENDER, &RECIPIENT, &tx, &input_ranges, &output_ranges),
        Ok(())
    );
    assert!(state.is_spent(&c_in.commitment));
    assert!(!state.is_owned(&c_in.commitment));
    assert!(state.is_owned(&c_out.commitment));
    assert_eq!(state.total_fees, fee);
}

// ===========================================================================
// 5. Double-spend via the spent set: replay rejected, fees not doubled.
// ===========================================================================

#[test]
fn double_spend_via_spent_set_rejected() {
    let r = blinding(0xD0E5);
    let value = 900u64;
    let fee = 5u64;
    let c_in = PedersenCommitment::commit(value + fee, &r);
    let c_out = PedersenCommitment::commit(value, &r);
    let tx = ConfidentialTransfer::new(vec![c_in], vec![c_out], fee);

    let input_ranges = vec![RangeProof::prove_auto(&c_in, value + fee, &r)];
    let output_ranges = vec![RangeProof::prove_auto(&c_out, value, &r)];

    let mut state = ConfidentialState::new();
    fund_inputs(&mut state, &tx);

    assert_eq!(
        state.apply_transfer_with_ranges(&SENDER, &RECIPIENT, &tx, &input_ranges, &output_ranges),
        Ok(())
    );
    assert_eq!(state.total_fees, fee);

    // Replay of the byte-identical bundle: proofs still verify, conservation
    // still holds — the SPENT SET is what rejects it, atomically.
    assert_eq!(
        state.verify_transfer_with_ranges(&SENDER, &tx, &input_ranges, &output_ranges),
        Err(ConfidentialError::DoubleSpend(c_in.commitment))
    );
    assert_eq!(
        state.apply_transfer_with_ranges(&SENDER, &RECIPIENT, &tx, &input_ranges, &output_ranges),
        Err(ConfidentialError::DoubleSpend(c_in.commitment))
    );
    // No partial effects from the rejected replay: fees not doubled, the
    // output still owned once by the recipient.
    assert_eq!(state.total_fees, fee);
    assert_eq!(state.spent.len(), 1);
    assert!(state.is_owned(&c_out.commitment));
}
