//! Block-level parallel pre-verification of shielded proofs.
//!
//! `InMemoryStateEngine::apply_block_parallel_fees` collects the
//! `SysCallConfidentialTransfer2` bundles of admitted transactions and verifies
//! them across cores BEFORE the sequential execute loop; the SVM handler then
//! skips only the range-proof re-verification on a cache hit (every state
//! check — ownership, spent set, conservation, fees — still runs, and a miss
//! runs the full check as before).
//!
//! These tests pin:
//!
//! 1. PRE-PASS == SEQUENTIAL: `batch_verify_balanced_with_ranges` returns
//!    bit-identical verdicts to a sequential `verify_balanced_with_ranges` loop
//!    on a mixed valid/invalid bundle set, deterministically across runs;
//! 2. BLOCK == SINGLE-TX: a mixed valid/invalid block applied through
//!    `apply_block_parallel_fees` (pre-pass + cache on) reaches the same
//!    per-tx verdicts, shielded digest and state root as applying the same
//!    transactions one by one through `apply_transaction` (which never touches
//!    the cache);
//! 3. the preverify digest is stable for identical bundles and moves on any
//!    mutation (so a cache hit can only ever stand for the same bytes).

use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;

use stellereum::crypto_privacy::{
    confidential_digest, confidential_transfer2_preverify_digest, ConfidentialTransfer,
    PedersenCommitment, RangeProof,
};
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::{confidential_transfer2_gas, OpCode, GAS_CONFIDENTIAL_SHIELD};

const BLOCK_TS: u64 = 1_760_000_000;
const RECIPIENT: [u8; 32] = [0x22; 32];

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn sender_of(seed: u8) -> [u8; 32] {
    key(seed).verifying_key().to_bytes()
}

fn blinding(seed: u8) -> Scalar {
    Scalar::from(0x5EED_u64 + seed as u64)
}

/// A valid one-in/one-out transfer with caller-chosen blinding: input
/// (value + fee), output (value), so `C_in - C_out == fee*G` exactly.
fn balanced_transfer(value: u64, fee: u64, r: Scalar) -> ConfidentialTransfer {
    let c_in = PedersenCommitment::commit(value + fee, &r);
    let c_out = PedersenCommitment::commit(value, &r);
    ConfidentialTransfer::new(vec![c_in], vec![c_out], fee)
}

fn prove(
    transfer: &ConfidentialTransfer,
    in_value: u64,
    out_value: u64,
    r: Scalar,
) -> (Vec<RangeProof>, Vec<RangeProof>) {
    let ins = transfer
        .input_commitments
        .iter()
        .map(|c| RangeProof::prove_auto(c, in_value, &r))
        .collect();
    let outs = transfer
        .output_commitments
        .iter()
        .map(|c| RangeProof::prove_auto(c, out_value, &r))
        .collect();
    (ins, outs)
}

/// Exact gas a shield-entry + transfer2 payload consumes, so the declared
/// `gas_limit` equals what the single-tx path charges and the two paths can
/// be compared all the way down to the state root.
fn shield_transfer_gas(input_ranges: &[RangeProof], output_ranges: &[RangeProof]) -> u64 {
    GAS_CONFIDENTIAL_SHIELD + confidential_transfer2_gas(input_ranges, output_ranges)
}

#[allow(clippy::too_many_arguments)]
// GATE: test helper builds shielded transfers with explicit range params; keeps vectors readable at call sites.
fn shield_transfer_tx(
    sk: &SigningKey,
    transfer: ConfidentialTransfer,
    in_value: u64,
    _out_value: u64,
    r: Scalar,
    input_ranges: Vec<RangeProof>,
    output_ranges: Vec<RangeProof>,
    nonce: u64,
) -> Transaction {
    let shield_in = transfer.input_commitments[0];
    let gas = shield_transfer_gas(&input_ranges, &output_ranges);
    Transaction::sign_with_payload(
        sk,
        [0xEE; 32],
        0,
        gas,
        nonce,
        1,
        1,
        vec![
            OpCode::SysCallConfidentialShield {
                commitment: shield_in.commitment,
                amount: in_value,
                blinding: r.to_bytes(),
            },
            OpCode::SysCallConfidentialTransfer2 {
                recipient: RECIPIENT,
                transfer: Box::new(transfer),
                input_ranges,
                output_ranges,
            },
        ],
    )
}

fn valid_shield_transfer_tx(seed: u8, value: u64, fee: u64, nonce: u64) -> Transaction {
    let r = blinding(seed);
    let t = balanced_transfer(value, fee, r);
    let (ir, or_) = prove(&t, value + fee, value, r);
    shield_transfer_tx(&key(seed), t, value + fee, value, r, ir, or_, nonce)
}

/// Bundle set: (transfer, input_ranges, output_ranges, expected_verdict).
/// 5 valid + 4 invalid, so the batch (threshold 4) takes the parallel path.
fn mixed_bundles() -> Vec<(ConfidentialTransfer, Vec<RangeProof>, Vec<RangeProof>, bool)> {
    let mut out = Vec::new();
    // Valid bundles (distinct blindings => distinct commitments).
    for (i, seed) in [0xA1u8, 0xA2, 0xA3, 0xA4, 0xA5].iter().enumerate() {
        let r = blinding(*seed);
        let value = 1_000 + i as u64 * 100;
        let fee = 10 + i as u64;
        let t = balanced_transfer(value, fee, r);
        let (ir, or_) = prove(&t, value + fee, value, r);
        out.push((t, ir, or_, true));
    }
    // Invalid: tampered proof byte (deterministic corruption).
    {
        let r = blinding(0xB1);
        let t = balanced_transfer(2_000, 15, r);
        let (mut ir, or_) = prove(&t, 2_015, 2_000, r);
        ir[0].bit_proofs[0].s0[0] ^= 0xFF;
        out.push((t, ir, or_, false));
    }
    // Invalid: unbalanced equation with individually valid proofs.
    {
        let r = Scalar::from(3u64);
        let t = ConfidentialTransfer::new(
            vec![PedersenCommitment::commit(100, &r)],
            vec![PedersenCommitment::commit(1_000, &r)],
            0,
        );
        let (ir, or_) = prove(&t, 100, 1_000, r);
        out.push((t, ir, or_, false));
    }
    // Invalid: count mismatch (output proof dropped).
    {
        let r = blinding(0xB3);
        let t = balanced_transfer(3_000, 25, r);
        let (ir, _) = prove(&t, 3_025, 3_000, r);
        out.push((t, ir, Vec::new(), false));
    }
    // Invalid: truncated proof (a bit-proof removed => length mismatch, so
    // verification fails closed without ever touching the curve).
    {
        let r = blinding(0xB4);
        let t = balanced_transfer(4_000, 30, r);
        let (ir, mut or_) = prove(&t, 4_030, 4_000, r);
        or_[0].bit_proofs.pop();
        out.push((t, ir, or_, false));
    }
    out
}

// ===========================================================================
// 1. Pre-pass verdicts == sequential verdicts on a mixed valid/invalid set.
// ===========================================================================

#[test]
fn prepass_batch_verdicts_match_sequential_on_mixed_bundles() {
    let bundles = mixed_bundles();
    assert!(bundles.len() >= 4, "the batch must take the parallel path");
    let refs: Vec<(&ConfidentialTransfer, &[RangeProof], &[RangeProof])> = bundles
        .iter()
        .map(|(t, i, o, _)| (t, i.as_slice(), o.as_slice()))
        .collect();

    // Sequential reference: one scalar check per bundle, in order.
    let sequential: Vec<bool> = refs
        .iter()
        .map(|(t, i, o)| t.verify_balanced_with_ranges(i, o))
        .collect();
    let expected: Vec<bool> = bundles.iter().map(|(_, _, _, v)| *v).collect();
    assert_eq!(
        sequential, expected,
        "the test premise itself: 5 valid + 4 invalid bundles"
    );

    // The pre-pass primitive (rayon above the threshold, order-preserving).
    let batched = ConfidentialTransfer::batch_verify_balanced_with_ranges(&refs);
    assert_eq!(
        batched, sequential,
        "PRE-PASS DIVERGENCE: parallel verdicts must equal the sequential ones"
    );

    // Determinism across runs (pool scheduling must not move verdicts).
    let again = ConfidentialTransfer::batch_verify_balanced_with_ranges(&refs);
    assert_eq!(batched, again, "the pre-pass must be deterministic");
}

// ===========================================================================
// 2. The preverify digest keys exactly the verified bytes.
// ===========================================================================

#[test]
fn preverify_digest_is_stable_and_moves_on_any_mutation() {
    let bundles = mixed_bundles();
    let (t, ir, or_, _) = &bundles[0];
    let d0 = confidential_transfer2_preverify_digest(t, ir, or_);
    assert_eq!(
        d0,
        confidential_transfer2_preverify_digest(t, ir, or_),
        "identical bundles must digest identically"
    );

    // A flipped proof byte, a reordered input set and a changed fee all move
    // the digest, so a cache hit can never stand for different bytes.
    let mut tampered_ir = ir.clone();
    tampered_ir[0].bit_proofs[0].s0[0] ^= 0x01;
    assert_ne!(
        d0,
        confidential_transfer2_preverify_digest(t, &tampered_ir, or_),
        "a mutated proof must miss the cache"
    );
    let mut tampered_t = t.clone();
    tampered_t.fee += 1;
    assert_ne!(
        d0,
        confidential_transfer2_preverify_digest(&tampered_t, ir, or_),
        "a mutated fee must miss the cache"
    );
    assert_ne!(
        d0,
        confidential_transfer2_preverify_digest(t, ir, &[]),
        "a dropped proof set must miss the cache"
    );
}

// ===========================================================================
// 3. Mixed block: block path (pre-pass on) == sequential single-tx path.
// ===========================================================================

/// Build one mixed block: 4 valid shielded transfers (seeds 0x11-0x14), one
/// tampered-proof transfer (0x15), one unbalanced transfer (0x16), one
/// count-mismatch transfer (0x17), and a double-spend pair from 0x18 (the
/// replay carries byte-identical bundles, exercising digest dedupe).
/// Every tx carries its EXACT consumed gas, so verdicts, shielded state and
/// roots are all comparable across the two paths.
fn mixed_block_txs() -> Vec<Transaction> {
    let mut txs = Vec::new();
    for (i, seed) in [0x11u8, 0x12, 0x13, 0x14].iter().enumerate() {
        let value = 1_480 + i as u64 * 111;
        let fee = 20 + i as u64;
        txs.push(valid_shield_transfer_tx(*seed, value, fee, 0));
    }
    // Tampered proof.
    {
        let r = blinding(0x15);
        let t = balanced_transfer(2_000, 15, r);
        let (mut ir, or_) = prove(&t, 2_015, 2_000, r);
        ir[0].bit_proofs[0].s0[0] ^= 0xFF;
        txs.push(shield_transfer_tx(
            &key(0x15),
            t,
            2_015,
            2_000,
            r,
            ir,
            or_,
            0,
        ));
    }
    // Unbalanced (forged equation, valid individual proofs).
    {
        let r = Scalar::from(3u64);
        let t = ConfidentialTransfer::new(
            vec![PedersenCommitment::commit(100, &r)],
            vec![PedersenCommitment::commit(1_000, &r)],
            0,
        );
        let (ir, or_) = prove(&t, 100, 1_000, r);
        txs.push(shield_transfer_tx(&key(0x16), t, 100, 1_000, r, ir, or_, 0));
    }
    // Count mismatch.
    {
        let r = blinding(0x17);
        let t = balanced_transfer(3_000, 25, r);
        let (ir, _) = prove(&t, 3_025, 3_000, r);
        txs.push(shield_transfer_tx(
            &key(0x17),
            t,
            3_025,
            3_000,
            r,
            ir,
            Vec::new(),
            0,
        ));
    }
    // Double-spend pair: full shield+transfer, then a transfer-only replay of
    // the SAME bundle (same digest) one nonce later.
    {
        let r = blinding(0x18);
        let t = balanced_transfer(900, 5, r);
        let (ir, or_) = prove(&t, 905, 900, r);
        txs.push(shield_transfer_tx(
            &key(0x18),
            t.clone(),
            905,
            900,
            r,
            ir.clone(),
            or_.clone(),
            0,
        ));
        let gas = confidential_transfer2_gas(&ir, &or_);
        txs.push(Transaction::sign_with_payload(
            &key(0x18),
            [0xEE; 32],
            0,
            gas,
            1,
            1,
            1,
            vec![OpCode::SysCallConfidentialTransfer2 {
                recipient: RECIPIENT,
                transfer: Box::new(t),
                input_ranges: ir,
                output_ranges: or_,
            }],
        ));
    }
    txs
}

#[tokio::test]
async fn mixed_block_block_path_matches_sequential_single_tx_path() {
    let txs = mixed_block_txs();
    // 9 proof bundles (>= 4): the pre-pass takes the parallel path while the
    // single-tx path verifies everything sequentially.
    let n_proof_txs = txs
        .iter()
        .filter(|tx| {
            tx.payload
                .iter()
                .any(|op| matches!(op, OpCode::SysCallConfidentialTransfer2 { .. }))
        })
        .count();
    assert!(
        n_proof_txs >= 4,
        "the block must cross the parallel threshold"
    );

    let seeds = [0x11u8, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18];
    async fn funded() -> InMemoryStateEngine {
        let e = InMemoryStateEngine::new();
        for s in [0x11u8, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18] {
            e.update_account(AccountState::new(sender_of(s), 1_000_000))
                .await;
        }
        e
    }

    // Block path: admission + parallel pre-pass + sequential execute.
    let live = funded().await;
    let (applied, failed, _, status, _) = live.apply_block_parallel_fees(&txs, BLOCK_TS).await;
    assert_eq!(
        status,
        vec![true, true, true, true, false, false, false, true, false],
        "unexpected block-path verdicts: applied={applied} failed={failed}"
    );
    assert_eq!((applied, failed), (5, 4));

    // Sequential path: the same transactions one by one, never touching the
    // cache. Starts from byte-identical funding, same order, same timestamps.
    let seq = funded().await;
    let mut expected_status = Vec::with_capacity(txs.len());
    for tx in &txs {
        expected_status.push(seq.apply_transaction(tx, BLOCK_TS).await.is_ok());
    }
    assert_eq!(
        status, expected_status,
        "BLOCK VS SINGLE-TX DIVERGENCE: the pre-pass changed a verdict"
    );

    let live_shielded = confidential_digest(&live.confidential_read().await.clone());
    let seq_shielded = confidential_digest(&seq.confidential_read().await.clone());
    assert_eq!(
        live_shielded, seq_shielded,
        "both paths must reach the same shielded digest"
    );
    assert_eq!(
        live.get_state_root().await,
        seq.get_state_root().await,
        "both paths must commit identical state"
    );
    // Sanity on what the five valid transfers did: fees 20+21+22+23+5.
    assert_eq!(
        live.confidential_read().await.total_fees,
        20 + 21 + 22 + 23 + 5
    );
    assert_eq!(
        live.confidential_read().await.spent.len(),
        5,
        "exactly the five valid inputs join the spent set"
    );
    let _ = seeds;
}

// ===========================================================================
// 4. Throughput probe (prints only): sequential vs batched verification.
// ===========================================================================

#[test]
fn probe_parallel_proof_speedup() {
    // 16 valid 32-bit bundles: enough work to see cores matter, cheap enough
    // to prove in-test. Asserts correctness; the speedup itself is printed
    // for the operator (timing, not a verdict).
    let mut owned = Vec::new();
    for i in 0u8..16 {
        let r = Scalar::from(0xF00D_u64 + i as u64);
        let value = 5_000 + i as u64 * 37;
        let fee = 7 + (i as u64 % 5);
        let t = balanced_transfer(value, fee, r);
        let (ir, or_) = prove(&t, value + fee, value, r);
        owned.push((t, ir, or_));
    }
    let refs: Vec<(&ConfidentialTransfer, &[RangeProof], &[RangeProof])> = owned
        .iter()
        .map(|(t, i, o)| (t, i.as_slice(), o.as_slice()))
        .collect();

    let t0 = std::time::Instant::now();
    let sequential: Vec<bool> = refs
        .iter()
        .map(|(t, i, o)| t.verify_balanced_with_ranges(i, o))
        .collect();
    let dt_seq = t0.elapsed();
    let t1 = std::time::Instant::now();
    let batched = ConfidentialTransfer::batch_verify_balanced_with_ranges(&refs);
    let dt_batch = t1.elapsed();
    assert_eq!(batched, sequential);
    assert!(batched.iter().all(|&b| b));
    eprintln!(
        "proof-verify probe: sequential={:?} batched(parallel)={:?} speedup={:.2}x bundles={}",
        dt_seq,
        dt_batch,
        dt_seq.as_secs_f64() / dt_batch.as_secs_f64().max(1e-9),
        refs.len(),
    );
}
