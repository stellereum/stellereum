//! HashPool integration KATs — UNWIRED (test-local wiring, lead wires later).
//!
//! UNWIRED: `stellereum/src/hashpool.rs` has NO `mod` line in `lib.rs`
//! (default-off sandbox; lead adds `#[cfg(test)] mod hashpool;` when ready —
//! the `mev_pq_plan.rs` precedent). Until then this file includes the module
//! by path, so NO existing file is touched:
//! `#[path = "../src/hashpool.rs"] mod hashpool;`
//! Real Falcon-512 sign/verify comes from the already-vendored tree
//! (`stellereum::post_quantum`); ML-KEM-768 from the vendored `ml-kem`
//! crate. No new dependencies.
//!
//! Groups (one section each below):
//!  A. stealth round-trip (3 recipients) + wrong-recipient exclusion
//!  B. commit/nullify determinism
//!  C. double-spend refused (same Nf twice + serial substitution)
//!  D. tampered-opening refused
//!  E. batch happy (4x25 exact conservation) + unbalanced + one-bad-sig +
//!     non-uniform-amounts refused
//!  F. domain separation (commit vs nullifier vs stealth vs sig-msg)
//!  G. SHAKE-256 NIST-vector pin (vendored sponge check)

#[path = "../src/hashpool.rs"]
mod hashpool;

use hashpool::{
    HashPool, HpError, OutputNote, SpendOpening, coinjoin_apply, coinjoin_build,
    coinjoin_sig_msg, coinjoin_verify, hp_shake256, note_commit, note_nullifier,
    stealth_decap, stealth_encap, stealth_scan, HP_CT_LEN, HP_EK_LEN,
};
use ml_kem::{
    MlKem768,
    kem::{FromSeed, KeyExport},
};
use stellereum::post_quantum::{FalconKeypair, PqScheme, verify_pq_signature};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn kem_seed(byte: u8) -> [u8; 64] {
    [byte; 64]
}

fn ek_bytes(seed_byte: u8) -> Vec<u8> {
    let seed: ml_kem::Seed = kem_seed(seed_byte).into();
    let (_, ek) = MlKem768::from_seed(&seed);
    ek.to_bytes().as_slice().to_vec()
}

fn falcon(seed_byte: u8) -> FalconKeypair {
    FalconKeypair::generate_from_seed_bytes(&[seed_byte; 32])
}

fn falcon_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    verify_pq_signature(PqScheme::Falcon512, pk, msg, sig)
}

const CHAIN: u64 = 7;
const DENOM: u64 = 25;

/// Fund a pool with `n` denomination-`DENOM` notes; returns the pool, the
/// spend openings (with public stealths) and one Falcon owner key per note.
fn funded_pool(n: usize) -> (HashPool, Vec<SpendOpening>, Vec<FalconKeypair>) {
    let mut pool = HashPool::new(CHAIN);
    assert_eq!(pool.chain_id(), CHAIN);
    assert!(pool.is_empty());
    let mut openings = Vec::with_capacity(n);
    let mut keys = Vec::with_capacity(n);
    for i in 0..n {
        let ek = ek_bytes(0x10 + i as u8);
        let randomness = [(0xA0 + i as u8); 32];
        let (_, stealth) = stealth_encap(&ek, i as u64, &randomness).expect("encap");
        let blinding = [(0xB0 + i as u8); 32];
        let serial = [(0xC0 + i as u8); 32];
        let c = note_commit(CHAIN, DENOM, &blinding, &stealth);
        let nf = note_nullifier(&serial);
        pool.deposit(c, stealth, nf).expect("deposit");
        openings.push(SpendOpening { serial, value: DENOM, blinding, stealth });
        keys.push(falcon(0xD0 + i as u8));
    }
    (pool, openings, keys)
}

/// Sign the canonical message for (`openings`, `outputs`, `fee`) with `keys`.
fn sign_canonical(
    openings: &[SpendOpening],
    outputs: &[OutputNote],
    fee: u64,
    keys: &[FalconKeypair],
) -> Vec<(SpendOpening, Vec<u8>, Vec<u8>)> {
    let mut in_cs: Vec<[u8; 32]> = openings
        .iter()
        .map(|o| note_commit(CHAIN, o.value, &o.blinding, &o.stealth))
        .collect();
    in_cs.sort();
    let mut in_nfs: Vec<[u8; 32]> = openings.iter().map(|o| note_nullifier(&o.serial)).collect();
    in_nfs.sort();
    let mut out_pairs: Vec<([u8; 32], [u8; 32])> = outputs
        .iter()
        .map(|o| (note_commit(CHAIN, o.value, &o.blinding, &o.stealth), note_nullifier(&o.serial)))
        .collect();
    out_pairs.sort_by(|a, b| a.0.cmp(&b.0));
    let out_cs: Vec<[u8; 32]> = out_pairs.iter().map(|(c, _)| *c).collect();
    let out_nfs: Vec<[u8; 32]> = out_pairs.iter().map(|(_, n)| *n).collect();
    let msg = coinjoin_sig_msg(CHAIN, &in_cs, &in_nfs, &out_cs, &out_nfs, fee);
    openings
        .iter()
        .zip(keys.iter())
        .map(|(o, k)| (o.clone(), k.public_key.clone(), k.sign(&msg)))
        .collect()
}

fn fresh_outputs(n: usize) -> Vec<OutputNote> {
    (0..n)
        .map(|i| OutputNote {
            value: DENOM,
            blinding: [(0xE0 + i as u8); 32],
            stealth: [(0xF0 + i as u8); 32],
            serial: [(0x08 + i as u8); 32],
        })
        .collect()
}

// ---------------------------------------------------------------------------
// A. Stealth round-trip (3 recipients) + wrong-recipient exclusion
// ---------------------------------------------------------------------------

#[test]
fn stealth_roundtrip_three_recipients() {
    let eks = [ek_bytes(0x11), ek_bytes(0x22), ek_bytes(0x33)];
    assert!(eks.iter().all(|ek| ek.len() == HP_EK_LEN));
    let randomness = [0x5Au8; 32];
    let index = 9u64;
    // Sender encaps to recipient 1.
    let (ct, addr) = stealth_encap(&eks[1], index, &randomness).expect("encap");
    assert_eq!(ct.len(), HP_CT_LEN);
    // Recipient 1 decaps to the same stealth address.
    let back = stealth_decap(&kem_seed(0x22), &ct, index).expect("decap");
    assert_eq!(back, addr);
    // Determinism: same inputs, same outputs.
    let (ct2, addr2) = stealth_encap(&eks[1], index, &randomness).expect("encap");
    assert_eq!((ct.clone(), addr), (ct2.clone(), addr2));
    // Scan finds recipient 1; a different index does not match.
    let seeds = [kem_seed(0x11), kem_seed(0x22), kem_seed(0x33)];
    assert_eq!(stealth_scan(&seeds, &ct2, index, &addr), Some(1));
    assert_eq!(stealth_scan(&seeds, &ct2, index + 1, &addr), None);
}

#[test]
fn stealth_wrong_recipients_excluded() {
    let eks = [ek_bytes(0x11), ek_bytes(0x22), ek_bytes(0x33)];
    let randomness = [0x5Au8; 32];
    let index = 9u64;
    let (ct, addr) = stealth_encap(&eks[1], index, &randomness).expect("encap");
    // Non-recipients derive DIFFERENT addresses (excluded).
    for seed in [kem_seed(0x11), kem_seed(0x33)] {
        let other = stealth_decap(&seed, &ct, index).expect("decap");
        assert_ne!(other, addr);
    }
    // Scan without the true recipient finds nothing.
    let wrong = [kem_seed(0x11), kem_seed(0x33)];
    assert_eq!(stealth_scan(&wrong, &ct, index, &addr), None);
    // Tampered ct: decap is infallible (implicit rejection) but yields a
    // non-matching address — the scan excludes it.
    let mut bad = ct.clone();
    bad[0] ^= 0x01;
    let bad_addr = stealth_decap(&kem_seed(0x22), &bad, index).expect("decap infallible");
    assert_ne!(bad_addr, addr);
    let seeds = [kem_seed(0x11), kem_seed(0x22), kem_seed(0x33)];
    assert_eq!(stealth_scan(&seeds, &bad, index, &addr), None);
    // Malformed inputs are refused outright.
    assert_eq!(stealth_encap(&[0u8; 100], index, &randomness), Err(HpError::BadEncapsulationKey));
    assert_eq!(stealth_decap(&kem_seed(0x22), &[0u8; 10], index), Err(HpError::BadCiphertext));
}

// ---------------------------------------------------------------------------
// B. Commit / nullify determinism
// ---------------------------------------------------------------------------

#[test]
fn commit_nullify_deterministic_and_sensitive() {
    let blinding = [0x77u8; 32];
    let stealth = [0x88u8; 32];
    let serial = [0x99u8; 32];
    let c1 = note_commit(CHAIN, DENOM, &blinding, &stealth);
    let c2 = note_commit(CHAIN, DENOM, &blinding, &stealth);
    assert_eq!(c1, c2);
    let n1 = note_nullifier(&serial);
    assert_eq!(n1, note_nullifier(&serial));
    // Every field is load-bearing.
    assert_ne!(c1, note_commit(CHAIN + 1, DENOM, &blinding, &stealth));
    assert_ne!(c1, note_commit(CHAIN, DENOM + 1, &blinding, &stealth));
    let mut bad_blind = blinding;
    bad_blind[0] ^= 0x01;
    assert_ne!(c1, note_commit(CHAIN, DENOM, &bad_blind, &stealth));
    let mut bad_stealth = stealth;
    bad_stealth[31] ^= 0x01;
    assert_ne!(c1, note_commit(CHAIN, DENOM, &blinding, &bad_stealth));
    let mut bad_serial = serial;
    bad_serial[0] ^= 0x01;
    assert_ne!(n1, note_nullifier(&bad_serial));
    // Non-trivial (not all zeros).
    assert!(c1.iter().any(|&b| b != 0));
    assert!(n1.iter().any(|&b| b != 0));
}

// ---------------------------------------------------------------------------
// C. Double-spend refused
// ---------------------------------------------------------------------------

#[test]
fn double_spend_refused_same_nullifier_twice() {
    let mut pool = HashPool::new(CHAIN);
    let blinding = [0x01u8; 32];
    let stealth = [0x02u8; 32];
    let serial = [0x03u8; 32];
    let c = note_commit(CHAIN, DENOM, &blinding, &stealth);
    let nf = note_nullifier(&serial);
    pool.deposit(c, stealth, nf).expect("deposit");
    assert_eq!(pool.spend(&c, &serial, DENOM, &blinding), Ok(nf));
    assert!(pool.is_spent(&nf));
    // Same nullifier twice: refused.
    assert_eq!(
        pool.spend(&c, &serial, DENOM, &blinding),
        Err(HpError::AlreadySpent)
    );
    // Serial substitution on the same note: refused (serial is bound at
    // deposit — a different serial yields a different, unbound nullifier).
    let other_serial = [0x04u8; 32];
    assert_eq!(
        pool.spend(&c, &other_serial, DENOM, &blinding),
        Err(HpError::SerialMismatch)
    );
}

// ---------------------------------------------------------------------------
// D. Tampered opening refused
// ---------------------------------------------------------------------------

#[test]
fn tampered_opening_refused() {
    let mut pool = HashPool::new(CHAIN);
    let blinding = [0x01u8; 32];
    let stealth = [0x02u8; 32];
    let serial = [0x03u8; 32];
    let c = note_commit(CHAIN, DENOM, &blinding, &stealth);
    pool.deposit(c, stealth, note_nullifier(&serial)).expect("deposit");
    // Duplicate registration refused.
    assert_eq!(
        pool.deposit(c, stealth, note_nullifier(&serial)),
        Err(HpError::DuplicateDeposit)
    );
    // Wrong value / wrong blinding: recomputation misses.
    assert_eq!(
        pool.spend(&c, &serial, DENOM + 1, &blinding),
        Err(HpError::CommitmentMismatch)
    );
    let mut bad_blind = blinding;
    bad_blind[0] ^= 0x01;
    assert_eq!(
        pool.spend(&c, &serial, DENOM, &bad_blind),
        Err(HpError::CommitmentMismatch)
    );
    // Unknown commitment: refused.
    let unknown = [0xABu8; 32];
    assert_eq!(
        pool.spend(&unknown, &serial, DENOM, &blinding),
        Err(HpError::UnknownCommitment)
    );
    // Chain mismatch is structural: a pool for another chain never contains C.
    let other_pool = HashPool::new(CHAIN + 1);
    assert!(!other_pool.contains(&c));
}

// ---------------------------------------------------------------------------
// E. CoinJoin batch: happy + refusal cases
// ---------------------------------------------------------------------------

#[test]
fn batch_happy_4x25_exact_conservation() {
    let (mut pool, openings, keys) = funded_pool(4);
    let outputs = fresh_outputs(4);
    let fee = 0u64;
    let spends = sign_canonical(&openings, &outputs, fee, &keys);
    let batch = coinjoin_build(CHAIN, spends, outputs.clone(), fee).expect("build");
    // Deterministic order: inputs AND outputs sorted by commitment.
    let in_cs: Vec<[u8; 32]> = batch.inputs.iter().map(|i| i.commitment).collect();
    let mut sorted = in_cs.clone();
    sorted.sort();
    assert_eq!(in_cs, sorted);
    // Conservation: 4x25 in == 4x25 out + 0 fee.
    let sum_in: u64 = batch.inputs.iter().map(|i| i.opening.value).sum();
    let sum_out: u64 = batch.outputs.iter().map(|o| o.value).sum();
    assert_eq!((sum_in, sum_out, batch.fee), (100, 100, 0));
    coinjoin_verify(&pool, &batch, &falcon_verify).expect("verify");
    coinjoin_apply(&mut pool, &batch).expect("apply");
    assert_eq!(pool.spent_len(), 4);
    assert_eq!(pool.len(), 8);
    for o in &outputs {
        let c = note_commit(CHAIN, o.value, &o.blinding, &o.stealth);
        assert!(pool.contains(&c));
        assert!(!pool.is_spent(&note_nullifier(&o.serial)));
    }
    // Inputs are now spent: note-level re-spend is refused too.
    let first = &batch.inputs[0];
    assert_eq!(
        pool.spend(&first.commitment, &first.opening.serial, DENOM, &first.opening.blinding),
        Err(HpError::AlreadySpent)
    );
    // Non-canonical input order is refused.
    let mut shuffled = batch.clone();
    shuffled.inputs.swap(0, 1);
    assert_eq!(
        coinjoin_verify(&pool, &shuffled, &falcon_verify),
        Err(HpError::OrderNotCanonical)
    );
}

#[test]
fn batch_unbalanced_refused() {
    let (_, openings, keys) = funded_pool(4);
    // Uniform but short: 4x25 in vs 3x25 out, fee 0.
    let short = fresh_outputs(3);
    let spends = sign_canonical(&openings, &short, 0, &keys);
    assert_eq!(
        coinjoin_build(CHAIN, spends, short, 0),
        Err(HpError::Unbalanced { sum_in: 100, sum_out: 75, fee: 0 })
    );
    // Fee made explicit: 4x25 in vs 4x25 out with fee 1 does not conserve.
    let outputs = fresh_outputs(4);
    let spends = sign_canonical(&openings, &outputs, 1, &keys);
    assert_eq!(
        coinjoin_build(CHAIN, spends, outputs, 1),
        Err(HpError::Unbalanced { sum_in: 100, sum_out: 100, fee: 1 })
    );
}

#[test]
fn batch_one_bad_sig_refused() {
    let (pool, openings, keys) = funded_pool(4);
    let outputs = fresh_outputs(4);
    let mut spends = sign_canonical(&openings, &outputs, 0, &keys);
    // Sanity: untampered batch verifies.
    let batch = coinjoin_build(CHAIN, spends.clone(), outputs.clone(), 0).expect("build");
    coinjoin_verify(&pool, &batch, &falcon_verify).expect("verify");
    // Flip one byte of one signature: refused.
    spends[2].2[10] ^= 0x01;
    let bad = coinjoin_build(CHAIN, spends, outputs, 0).expect("build");
    assert_eq!(coinjoin_verify(&pool, &bad, &falcon_verify), Err(HpError::BadSignature));
}

#[test]
fn batch_non_uniform_amounts_refused() {
    let (_, openings, keys) = funded_pool(4);
    // Non-uniform outputs.
    let mut mixed = fresh_outputs(4);
    mixed[3].value = 24;
    let spends = sign_canonical(&openings, &mixed, 0, &keys);
    assert_eq!(
        coinjoin_build(CHAIN, spends, mixed, 0),
        Err(HpError::NonUniformAmount)
    );
    // Non-uniform inputs (no pool interaction: build fails structurally first).
    let mut bad_ins = openings.clone();
    bad_ins[0].value = 30;
    let spends: Vec<(SpendOpening, Vec<u8>, Vec<u8>)> = bad_ins
        .into_iter()
        .zip(keys.iter())
        .map(|(o, k)| (o, k.public_key.clone(), Vec::new()))
        .collect();
    assert_eq!(
        coinjoin_build(CHAIN, spends, fresh_outputs(4), 0),
        Err(HpError::NonUniformAmount)
    );
}

// ---------------------------------------------------------------------------
// F. Domain separation
// ---------------------------------------------------------------------------

#[test]
fn domain_separation_commit_vs_nullifier() {
    // Same 32-byte material through different domains never collides.
    for byte in [0x00u8, 0x42u8, 0xFFu8] {
        let x = [byte; 32];
        let c = note_commit(CHAIN, DENOM, &x, &x);
        let nf = note_nullifier(&x);
        let mut pre = Vec::new();
        pre.extend_from_slice(b"STELL_HP_STEALTH_V1");
        pre.extend_from_slice(&x);
        pre.extend_from_slice(&0u64.to_be_bytes());
        let mut st = [0u8; 32];
        hp_shake256(&pre, &mut st);
        assert_ne!(c, nf);
        assert_ne!(c, st);
        assert_ne!(nf, st);
        // A real commitment output is never a valid nullifier input in the
        // spend path: spending with serial := commitment bytes binds
        // Nf(null(C)) which no deposit bound (deposits bind Nf(real serial)).
        let mut pool = HashPool::new(CHAIN);
        let blinding = [0x01u8; 32];
        let stealth = [0x02u8; 32];
        let serial = [0x03u8; 32];
        let cc = note_commit(CHAIN, DENOM, &blinding, &stealth);
        pool.deposit(cc, stealth, note_nullifier(&serial)).expect("deposit");
        assert_ne!(note_nullifier(&cc), note_nullifier(&serial));
        assert_eq!(
            pool.spend(&cc, &cc, DENOM, &blinding),
            Err(HpError::SerialMismatch)
        );
    }
    // The batch sig-message domain is distinct from note domains.
    let msg = coinjoin_sig_msg(CHAIN, &[[0x11u8; 32]], &[[0x22u8; 32]], &[[0x33u8; 32]], &[[0x44u8; 32]], 0);
    assert_ne!(msg, note_commit(CHAIN, DENOM, &[0x11u8; 32], &[0x33u8; 32]));
    assert_ne!(msg, note_nullifier(&[0x11u8; 32]));
}

// ---------------------------------------------------------------------------
// G. SHAKE-256 NIST-vector pin (vendored sponge check)
// ---------------------------------------------------------------------------

#[test]
fn shake256_matches_nist_vectors() {
    // SHAKE256("") 32 bytes (NIST ShortMsgKAT).
    let mut out = [0u8; 32];
    hp_shake256(b"", &mut out);
    assert_eq!(
        hex::encode(out),
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
    );
    // SHAKE256("abc") 32 bytes (NIST ShortMsgKAT).
    hp_shake256(b"abc", &mut out);
    assert_eq!(
        hex::encode(out),
        "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
    );
    // 64-byte squeeze crosses the 136-byte rate boundary logic.
    let mut out64 = [0u8; 64];
    hp_shake256(b"", &mut out64);
    assert_eq!(
        hex::encode(out64),
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f\
         d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
            .replace(['\n', ' '], "")
    );
}
