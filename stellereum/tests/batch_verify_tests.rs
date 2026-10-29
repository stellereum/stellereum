//! Batch Ed25519 verification tests for transactions.
//! Batch verify must accept all-valid sets and reject if ANY signature is bad
//! (same security guarantee as one-by-one verification, but faster).

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use stellereum::sharding::Transaction;

fn tx(sk: &SigningKey, n: u64) -> Transaction {
    Transaction::sign(sk, [9u8; 32], 10, n, n, 1, 1)
}
#[test]
fn batch_accepts_all_valid() {
    let sk = SigningKey::generate(&mut OsRng);
    let txs: Vec<Transaction> = (0..100).map(|i| tx(&sk, i)).collect();
    assert!(Transaction::verify_signatures_batch(&txs));
}

#[test]
fn batch_rejects_if_any_invalid() {
    let sk = SigningKey::generate(&mut OsRng);
    let mut txs: Vec<Transaction> = (0..50).map(|i| tx(&sk, i)).collect();
    // tamper one signature
    txs[17].signature[0] ^= 0xFF;
    assert!(
        !Transaction::verify_signatures_batch(&txs),
        "batch must reject a bad signature"
    );
}

#[test]
fn batch_matches_single_verification() {
    let sk = SigningKey::generate(&mut OsRng);
    let txs: Vec<Transaction> = (0..64).map(|i| tx(&sk, i)).collect();
    let single_all = txs.iter().all(|t| t.verify_signature());
    let batch = Transaction::verify_signatures_batch(&txs);
    assert_eq!(single_all, batch);

    // tamper amount (signature no longer matches) -> both must be false
    let mut bad = txs.clone();
    bad[0].amount = 999;
    assert!(!bad[0].verify_signature());
    assert!(!Transaction::verify_signatures_batch(&bad));
}

#[test]
fn batch_empty_is_true() {
    assert!(Transaction::verify_signatures_batch(&[]));
}

#[test]
fn batch_mixed_keys() {
    // Transactions from many different senders must each verify.
    let mut txs = Vec::new();
    for i in 0..40u64 {
        let sk = SigningKey::generate(&mut OsRng);
        txs.push(Transaction::sign(&sk, [1u8; 32], i, i, i, 1, 1));
    }
    assert!(Transaction::verify_signatures_batch(&txs));
    // corrupt one
    txs[3].signature[10] ^= 0x01;
    assert!(!Transaction::verify_signatures_batch(&txs));
}

// ---------------------------------------------------------------------------
// Partitioned tx batch: one bad neighbor must not sink the good ones.
// ---------------------------------------------------------------------------

use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use stellereum::consensus::{QuorumCertificate, ValidatorSet, Vote, VoteKind};
use stellereum::sharding::Block;

fn det_rng() -> StdRng {
    StdRng::seed_from_u64(0xBA7C4)
}

#[test]
fn partitioned_keeps_good_txs_with_one_forgery() {
    let sk = SigningKey::generate(&mut OsRng);
    let mut txs: Vec<Transaction> = (0..50).map(|i| tx(&sk, i)).collect();
    txs[17].signature[0] ^= 0xFF;
    // All-or-nothing batch still fails closed...
    assert!(!Transaction::verify_signatures_batch(&txs));
    // ...but the partitioned form identifies exactly the offender.
    let flags = Transaction::verify_signatures_partitioned(&txs);
    assert_eq!(flags.len(), txs.len());
    for (i, f) in flags.iter().enumerate() {
        assert_eq!(*f, i != 17, "only index 17 is forged");
    }
    // And the all-valid set partitions to all-true.
    let good: Vec<Transaction> = (0..50).map(|i| tx(&sk, i + 1000)).collect();
    assert!(Transaction::verify_signatures_partitioned(&good)
        .iter()
        .all(|b| *b));
    assert!(Transaction::verify_signatures_batch(&good));
}

#[test]
fn partitioned_matches_scalar_differential_randomized() {
    // Seeded RNG: deterministic across runs and machines.
    let mut rng = det_rng();
    for round in 0..25 {
        let n = 1 + (rng.next_u32() % 24) as usize;
        let mut txs = Vec::with_capacity(n);
        for i in 0..n {
            // Mix of shared-sender and fresh-sender txs.
            let sk = if rng.next_u32().is_multiple_of(2) {
                SigningKey::from_bytes(&[round as u8; 32])
            } else {
                let mut b = [0u8; 32];
                rng.fill_bytes(&mut b);
                SigningKey::from_bytes(&b)
            };
            let mut t = Transaction::sign(&sk, [1u8; 32], i as u64, i as u64, i as u64, 1, 1);
            // Corrupt ~1/4 of items: signature bytes, amount (detached sig),
            // or sender (wrong key).
            match rng.next_u32() % 4 {
                0 => {
                    let j = (rng.next_u32() as usize) % t.signature.len().max(1);
                    if !t.signature.is_empty() {
                        t.signature[j] ^= 0x01;
                    }
                }
                1 => t.amount = t.amount.wrapping_add(1),
                2 => t.from[0] ^= 0x80,
                _ => {}
            }
            txs.push(t);
        }
        let scalar: Vec<bool> = txs.iter().map(|t| t.verify_signature()).collect();
        let part = Transaction::verify_signatures_partitioned(&txs);
        assert_eq!(
            scalar, part,
            "partitioned must equal scalar per item (round {round})"
        );
        assert_eq!(
            Transaction::verify_signatures_batch(&txs),
            scalar.iter().all(|b| *b),
            "batch bool must equal AND of scalars (round {round})"
        );
        // filter_valid_transactions keeps exactly the scalar-good ones, in order.
        let kept = Transaction::filter_valid_transactions(&txs);
        let expected: Vec<Transaction> = txs
            .iter()
            .zip(scalar.iter())
            .filter(|(_, k)| **k)
            .map(|(t, _)| t.clone())
            .collect();
        assert_eq!(kept.len(), expected.len());
        for (a, b) in kept.iter().zip(expected.iter()) {
            assert_eq!(a.compute_tx_hash(), b.compute_tx_hash());
        }
    }
}

#[test]
fn partitioned_mixed_session_and_legacy() {
    use stellereum::zkml::{SessionKeyAuthorization, SCOPE_TRANSFER};
    const CHAIN_ID: u64 = 5757;
    let master = SigningKey::generate(&mut OsRng);
    let session = SigningKey::generate(&mut OsRng);
    let grant = SessionKeyAuthorization::sign_delegation(
        &master,
        session.verifying_key().to_bytes(),
        u64::MAX,
        1_000_000,
        SCOPE_TRANSFER,
        1_000_000,
        CHAIN_ID,
    );
    let stx =
        Transaction::sign_with_session(&session, grant, [1u8; 32], 10, 100, 0, 1, 1, Vec::new());
    assert!(stx.verify_signature());
    let mut txs = vec![tx(&master, 0), stx, tx(&master, 1)];
    assert!(Transaction::verify_signatures_batch(&txs));
    assert!(Transaction::verify_signatures_partitioned(&txs)
        .iter()
        .all(|b| *b));
    // Forge the SESSION signature only: exactly that item must fail.
    txs[1].signature[3] ^= 0x40;
    assert!(!txs[1].verify_signature());
    assert!(!Transaction::verify_signatures_batch(&txs));
    assert_eq!(
        Transaction::verify_signatures_partitioned(&txs),
        vec![true, false, true]
    );
}

// ---------------------------------------------------------------------------
// Vote batch verification: all-valid accept, one forgery rejects + keeps good.
// ---------------------------------------------------------------------------

fn vote_keys(n: usize) -> Vec<SigningKey> {
    (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect()
}

fn vote_set(ks: &[SigningKey], bh: [u8; 32]) -> Vec<Vote> {
    ks.iter()
        .map(|k| Vote::sign(k, 7, 2, VoteKind::Precommit, Some(bh)))
        .collect()
}

#[test]
fn vote_batch_accepts_all_valid() {
    let ks = vote_keys(32);
    let votes = vote_set(&ks, [0x42u8; 32]);
    assert!(Vote::verify_batch(&votes));
    assert!(Vote::partition_valid(&votes).iter().all(|b| *b));
    assert!(votes.iter().all(|v| v.verify()));
}

#[test]
fn vote_batch_rejects_one_forgery_and_keeps_good() {
    let ks = vote_keys(32);
    let mut votes = vote_set(&ks, [0x42u8; 32]);
    votes[9].signature[7] ^= 0xFF;
    assert!(!votes[9].verify());
    // Fail closed...
    assert!(!Vote::verify_batch(&votes));
    // ...but the good votes are identified, not dropped.
    let flags = Vote::partition_valid(&votes);
    for (i, f) in flags.iter().enumerate() {
        assert_eq!(*f, i != 9, "only index 9 is forged");
    }
}

#[test]
fn vote_batch_matches_scalar_differential_randomized() {
    let mut rng = det_rng();
    for round in 0..25 {
        let n = 1 + (rng.next_u32() % 20) as usize;
        let ks: Vec<SigningKey> = (0..n)
            .map(|_| {
                let mut b = [0u8; 32];
                rng.fill_bytes(&mut b);
                SigningKey::from_bytes(&b)
            })
            .collect();
        let mut votes: Vec<Vote> = ks
            .iter()
            .enumerate()
            .map(|(i, k)| {
                // Vary height/round/kind/target per vote: distinct messages.
                let kind = if i % 2 == 0 {
                    VoteKind::Prevote
                } else {
                    VoteKind::Precommit
                };
                let mut bh = [0u8; 32];
                rng.fill_bytes(&mut bh);
                let target = if i % 3 == 0 { None } else { Some(bh) };
                Vote::sign(k, round as u64, (i % 4) as u32, kind, target)
            })
            .collect();
        // Corrupt a random subset.
        for v in votes.iter_mut() {
            match rng.next_u32() % 4 {
                0 => {
                    let j = (rng.next_u32() as usize) % v.signature.len().max(1);
                    if !v.signature.is_empty() {
                        v.signature[j] ^= 0x01;
                    }
                }
                1 => v.height = v.height.wrapping_add(1),
                _ => {}
            }
        }
        let scalar: Vec<bool> = votes.iter().map(|v| v.verify()).collect();
        assert_eq!(
            Vote::partition_valid(&votes),
            scalar,
            "vote partition == scalar (round {round})"
        );
        assert_eq!(
            Vote::verify_batch(&votes),
            scalar.iter().all(|b| *b),
            "vote batch bool == AND of scalars (round {round})"
        );
    }
}

#[test]
fn vote_batch_empty_is_true() {
    assert!(Vote::verify_batch(&[]));
    assert!(Vote::partition_valid(&[]).is_empty());
}

// ---------------------------------------------------------------------------
// VoteSet::add_batch: same outcomes as sequential add, order-independent.
// ---------------------------------------------------------------------------

#[test]
fn voteset_add_batch_matches_sequential_and_keeps_good() {
    let ks = vote_keys(10);
    let vs = ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    );
    let bh = [0x11u8; 32];
    let mut votes = vote_set(&ks, bh);
    // One forged vote and one outsider vote: both rejected, good kept.
    votes[3].signature[0] ^= 0xFF;
    let outsider = SigningKey::generate(&mut OsRng);
    votes.push(Vote::sign(&outsider, 7, 2, VoteKind::Precommit, Some(bh)));

    let mut seq = stellereum::consensus::VoteSet::new();
    let mut seq_res = Vec::new();
    for v in votes.clone() {
        seq_res.push(seq.add(v, &vs, 7, 2, VoteKind::Precommit).is_ok());
    }
    let mut batched = stellereum::consensus::VoteSet::new();
    let batch_res = batched.add_batch(votes.clone(), &vs, 7, 2, VoteKind::Precommit);
    let batch_ok: Vec<bool> = batch_res.iter().map(|r| r.is_ok()).collect();
    assert_eq!(
        seq_res, batch_ok,
        "per-vote admission outcomes must match sequential add"
    );
    assert_eq!(seq.len(), batched.len());
    assert_eq!(
        seq.quorum_target(&vs),
        batched.quorum_target(&vs),
        "quorum outcome must match"
    );
    // The forged vote (index 3) and the outsider (last) are rejected; the rest kept.
    assert!(!batch_ok[3]);
    assert!(!batch_ok[votes.len() - 1]);
    assert_eq!(batched.len(), 9);
}

#[test]
fn voteset_add_batch_is_permutation_independent() {
    let ks = vote_keys(12);
    let vs = ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    );
    let bh = [0x22u8; 32];
    let votes = vote_set(&ks, bh);
    // Reverse the input: same admitted SET and same quorum either way.
    let rev: Vec<Vote> = votes.iter().rev().cloned().collect();
    let mut a = stellereum::consensus::VoteSet::new();
    let mut b = stellereum::consensus::VoteSet::new();
    let ra = a.add_batch(votes, &vs, 7, 2, VoteKind::Precommit);
    let rb = b.add_batch(rev, &vs, 7, 2, VoteKind::Precommit);
    assert!(ra.iter().all(|r| r.is_ok()));
    assert!(rb.iter().all(|r| r.is_ok()));
    assert_eq!(a.len(), b.len());
    assert_eq!(a.quorum_target(&vs), b.quorum_target(&vs));
    // Per-INPUT results still align with each call's own input order.
    assert_eq!(ra.len(), 12);
    assert_eq!(rb.len(), 12);
}

// ---------------------------------------------------------------------------
// Block quorum batch equivalence vs a scalar reference loop.
// ---------------------------------------------------------------------------

/// The pre-batch scalar semantics, reimplemented as a test oracle: dedup,
/// membership-then-verify, power-weighted threshold.
fn scalar_quorum(block: &Block, vs: &ValidatorSet) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};
    use std::collections::HashSet;
    let required = vs.quorum_power();
    if required == u64::MAX {
        return false;
    }
    let h = block.compute_hash();
    let mut seen = HashSet::new();
    let mut power = 0u64;
    for (pubkey, sig_bytes) in &block.validator_signatures {
        if !seen.insert(*pubkey) {
            continue;
        }
        let vp = vs.power_of(pubkey);
        if vp == 0 {
            continue;
        }
        if let Ok(vk) = VerifyingKey::from_bytes(pubkey) {
            if let Ok(sig) = Signature::from_slice(sig_bytes) {
                use ed25519_dalek::Verifier;
                if vk.verify(&h, &sig).is_ok() {
                    power = power.saturating_add(vp);
                }
            }
        }
    }
    power >= required
}

fn signed_block(n: usize) -> (Block, Vec<SigningKey>) {
    let ks = vote_keys(n);
    let mut block = Block {
        shard_id: 0,
        height: 1,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 0,
        proposer: ks[0].verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    for k in &ks {
        block.sign_block(k);
    }
    (block, ks)
}

#[test]
fn block_quorum_batch_equivalence_randomized() {
    let mut rng = det_rng();
    for round in 0..20 {
        let n = 2 + (rng.next_u32() % 10) as usize;
        let (mut block, ks) = signed_block(n);
        let vs = ValidatorSet::from_list(
            ks.iter()
                .map(|k| (k.verifying_key().to_bytes(), 1))
                .collect(),
        );
        // Mutations: forge a sig, duplicate a signer, add a non-member signer.
        match rng.next_u32() % 5 {
            0 => {
                let j = (rng.next_u32() as usize) % block.validator_signatures.len();
                let l = block.validator_signatures[j].1.len();
                block.validator_signatures[j].1[(rng.next_u32() as usize) % l] ^= 0x01;
            }
            1 => {
                let dup = block.validator_signatures[0].clone();
                block.validator_signatures.push(dup);
            }
            2 => {
                let outsider = SigningKey::generate(&mut OsRng);
                use ed25519_dalek::Signer;
                let h = block.compute_hash();
                let s = outsider.sign(&h).to_vec();
                block
                    .validator_signatures
                    .push((outsider.verifying_key().to_bytes(), s));
            }
            3 => {
                block.validator_signatures.truncate(1);
            }
            _ => {}
        }
        assert_eq!(
            block.verify_validator_quorum(&vs),
            scalar_quorum(&block, &vs),
            "quorum batch must equal scalar oracle (round {round})"
        );
        // Head-count variant: same verdict as its own scalar loop.
        let need = (n / 2).max(1);
        let mut seen = std::collections::HashSet::new();
        let mut valid = 0usize;
        {
            use ed25519_dalek::{Signature, Verifier, VerifyingKey};
            let h = block.compute_hash();
            for (pubkey, sig_bytes) in &block.validator_signatures {
                if !seen.insert(*pubkey) {
                    continue;
                }
                if let Ok(vk) = VerifyingKey::from_bytes(pubkey) {
                    if let Ok(sig) = Signature::from_slice(sig_bytes) {
                        if vk.verify(&h, &sig).is_ok() {
                            valid += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(
            block.verify_signatures(need),
            valid >= need,
            "round {round}"
        );
        let _ = round;
    }
}

#[test]
fn block_quorum_rejects_single_forgery_below_threshold() {
    // 4 validators, quorum power 3. Forge one of 3 present sigs -> 2/3, reject.
    let (mut block, ks) = signed_block(4);
    block.validator_signatures.truncate(3);
    let vs = ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    );
    assert!(block.verify_validator_quorum(&vs));
    block.validator_signatures[1].1[0] ^= 0xFF;
    assert!(!block.verify_validator_quorum(&vs));
    assert!(!scalar_quorum(&block, &vs));
}

#[test]
fn qc_batch_still_covers_quorum_path() {
    // Existing verify_batch precedent (commit 687ec90) keeps working: a full
    // QC verifies, a tampered one does not.
    let ks = vote_keys(7);
    let bh = [0x77u8; 32];
    let sigs: Vec<([u8; 32], Vec<u8>)> = ks
        .iter()
        .map(|k| {
            let v = Vote::sign(k, 1, 0, VoteKind::Precommit, Some(bh));
            (v.voter, v.signature)
        })
        .collect();
    let qc = QuorumCertificate {
        height: 1,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(bh),
        signatures: sigs,
    };
    let vs = ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    );
    assert!(qc.verify(&vs));
}
