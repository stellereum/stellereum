//! QC batch verification: benchmarks + batched==serial differentials.
//!
//! Scope: `QuorumCertificate::verify` / `signers_set` (QC-VERIFY path only).
//! The Ed25519 threshold path in `verify_unified` is batch-then-per-sig; the
//! classical branch of `signers_set` must attribute EXACTLY the members a
//! serial per-signature loop would name. These tests pin that equality and
//! report wall-clock ms for fixed fixtures at k=7/64/100 (run with
//! `-- --nocapture`).

use ed25519_dalek::SigningKey;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::collections::HashSet;
use std::time::Instant;
use stellereum::consensus::{
    ed25519_sig_bytes, QuorumCertificate, ValidatorId, ValidatorSet, Vote, VoteKind,
    MAX_COMMIT_CERT_SIGNERS,
};

const BH: [u8; 32] = [0x77u8; 32];
const HH: u64 = 1;
const RR: u32 = 0;

fn det_keys(k: usize, seed: u64) -> Vec<SigningKey> {
    let mut rng = StdRng::seed_from_u64(seed);
    (0..k)
        .map(|_| {
            let mut b = [0u8; 32];
            rng.fill_bytes(&mut b);
            SigningKey::from_bytes(&b)
        })
        .collect()
}

fn val_set(ks: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    )
}

fn build_qc(ks: &[SigningKey]) -> (QuorumCertificate, ValidatorSet) {
    let sigs: Vec<(ValidatorId, Vec<u8>)> = ks
        .iter()
        .map(|k| {
            let v = Vote::sign(k, HH, RR, VoteKind::Precommit, Some(BH));
            (v.voter, v.signature)
        })
        .collect();
    let qc = QuorumCertificate {
        height: HH,
        round: RR,
        kind: VoteKind::Precommit,
        block_hash: Some(BH),
        signatures: sigs,
    };
    let vs = val_set(ks);
    (qc, vs)
}

/// Pre-batch serial oracle for pure-Ed25519 QCs (no marker envelopes):
/// dedup, membership-then-verify per signature, power-weighted threshold.
fn serial_qc_verify(qc: &QuorumCertificate, vs: &ValidatorSet) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};
    // Anti-DoS cap first (mirrors verify_unified): over-cap rejects before crypto.
    if qc.signatures.len() > MAX_COMMIT_CERT_SIGNERS {
        return false;
    }
    let msg = stellereum::consensus::vote_sign_bytes(qc.height, qc.round, qc.kind, &qc.block_hash);
    let mut seen = HashSet::new();
    let mut power = 0u64;
    for (voter, sig_bytes) in &qc.signatures {
        if !seen.insert(*voter) {
            continue;
        }
        let vp = vs.power_of(voter);
        if vp == 0 {
            continue;
        }
        let Ok(vk) = VerifyingKey::from_bytes(voter) else {
            continue;
        };
        let Ok(sig) = Signature::from_slice(ed25519_sig_bytes(sig_bytes)) else {
            continue;
        };
        if vk.verify_strict(&msg, &sig).is_ok() {
            power = power.saturating_add(vp);
        }
    }
    power >= vs.quorum_power()
}

/// Pre-batch serial oracle for `signers_set` classical branch (no markers).
fn serial_qc_signers(qc: &QuorumCertificate, vs: &ValidatorSet) -> HashSet<ValidatorId> {
    use ed25519_dalek::{Signature, VerifyingKey};
    let msg = stellereum::consensus::vote_sign_bytes(qc.height, qc.round, qc.kind, &qc.block_hash);
    let mut out = HashSet::new();
    for (voter, payload) in &qc.signatures {
        if vs.power_of(voter) == 0 {
            continue;
        }
        let Ok(vk) = VerifyingKey::from_bytes(voter) else {
            continue;
        };
        let Ok(sig) = Signature::from_slice(ed25519_sig_bytes(payload)) else {
            continue;
        };
        if vk.verify_strict(&msg, &sig).is_ok() {
            out.insert(*voter);
        }
    }
    out
}

#[test]
fn qc_verify_benchmark_fixed_fixtures() {
    // Fixed fixtures: seeded keys, fixed (height, round, kind, target).
    // REPORT ONLY (no timing asserts): paste output for before/after.
    for (k, iters) in [(7usize, 200usize), (64, 50), (100, 30)] {
        let ks = det_keys(k, 0x9C1);
        let (qc, vs) = build_qc(&ks);
        assert!(qc.verify(&vs), "k={k} fixture QC must verify");
        let t = Instant::now();
        for _ in 0..iters {
            assert!(qc.verify(&vs));
        }
        let ms = t.elapsed().as_secs_f64() * 1000.0;
        println!("qc_verify k={k} iters={iters} total_ms={ms:.2} mean_ms={:.4}", ms / iters as f64);
        let t = Instant::now();
        for _ in 0..iters {
            let _ = qc.signers_set(&vs);
        }
        let ms = t.elapsed().as_secs_f64() * 1000.0;
        println!(
            "qc_signers_set k={k} iters={iters} total_ms={ms:.2} mean_ms={:.4}",
            ms / iters as f64
        );
    }
}

#[test]
fn qc_verify_differential_randomized() {
    // Fixed seeds: deterministic across runs and machines.
    let mut rng = StdRng::seed_from_u64(0x9CB47);
    for round in 0..40 {
        let n = 1 + (rng.next_u32() % 16) as usize;
        let ks = (0..n)
            .map(|_| {
                let mut b = [0u8; 32];
                rng.fill_bytes(&mut b);
                SigningKey::from_bytes(&b)
            })
            .collect::<Vec<_>>();
        let (mut qc, vs) = build_qc(&ks);
        // Mutations: corrupt one sig, duplicate a signer, add an outsider,
        // garbage bytes, or truncate below quorum.
        match rng.next_u32() % 6 {
            0 => {
                let j = (rng.next_u32() as usize) % qc.signatures.len();
                let l = qc.signatures[j].1.len();
                qc.signatures[j].1[(rng.next_u32() as usize) % l] ^= 0x01;
            }
            1 => {
                let dup = qc.signatures[0].clone();
                qc.signatures.push(dup);
            }
            2 => {
                let outsider = SigningKey::from_bytes(&{
                    let mut b = [0u8; 32];
                    rng.fill_bytes(&mut b);
                    b
                });
                let v = Vote::sign(&outsider, HH, RR, VoteKind::Precommit, Some(BH));
                qc.signatures.push((v.voter, v.signature));
            }
            3 => {
                let j = (rng.next_u32() as usize) % qc.signatures.len();
                qc.signatures[j].1 = vec![0u8; 3];
            }
            4 => {
                qc.signatures.truncate(1);
            }
            _ => {}
        }
        assert_eq!(
            qc.verify(&vs),
            serial_qc_verify(&qc, &vs),
            "batched verify == serial verdict (round {round})"
        );
        assert_eq!(
            qc.signers_set(&vs),
            serial_qc_signers(&qc, &vs),
            "batched signers == serial attribution (round {round})"
        );
    }
}

#[test]
fn qc_verify_edges_empty_overcap_one_corrupt() {
    // Empty QC: no candidates -> false on both paths.
    let ks = det_keys(4, 0xE1);
    let vs = val_set(&ks);
    let empty = QuorumCertificate {
        height: HH,
        round: RR,
        kind: VoteKind::Precommit,
        block_hash: Some(BH),
        signatures: vec![],
    };
    assert!(!empty.verify(&vs));
    assert_eq!(empty.verify(&vs), serial_qc_verify(&empty, &vs));
    assert!(empty.signers_set(&vs).is_empty());

    // Over-cap: attacker-supplied list rejected before any crypto.
    let big_ks = det_keys(8, 0xE2);
    let (mut over, big_vs) = build_qc(&big_ks);
    while over.signatures.len() <= MAX_COMMIT_CERT_SIGNERS {
        let dup = over.signatures[0].clone();
        over.signatures.push(dup);
    }
    assert!(over.signatures.len() > MAX_COMMIT_CERT_SIGNERS);
    assert!(!over.verify(&big_vs));
    assert_eq!(over.verify(&big_vs), serial_qc_verify(&over, &big_vs));

    // 1-corrupt with quorum still reachable: verdict stays true and the
    // offender is unattributed, exactly like the serial oracle.
    let ks4 = det_keys(4, 0xE3);
    let (mut qc, vs4) = build_qc(&ks4);
    qc.signatures[1].1[0] ^= 0xFF;
    assert!(qc.verify(&vs4), "3/4 good still reaches quorum 3");
    assert_eq!(qc.verify(&vs4), serial_qc_verify(&qc, &vs4));
    let signers = qc.signers_set(&vs4);
    assert_eq!(signers, serial_qc_signers(&qc, &vs4));
    assert_eq!(signers.len(), 3);
}

#[test]
fn qc_verify_mixed_scheme_falcon_envelope_pins() {
    use stellereum::consensus::{
        clear_validator_pq_keys_for_tests, register_validator_pq_key, VoteSet,
    };
    use stellereum::post_quantum::{FalconKeypair, PqScheme};
    clear_validator_pq_keys_for_tests();
    // Mixed-scheme QC: Falcon-envelope votes assemble a classical Ed25519
    // list (bare halves) plus a µQC marker. The classical halves still
    // batch; Falcon halves stay per-sig (no Falcon batch API exists).
    let sks = det_keys(4, 0xF4);
    let fks: Vec<FalconKeypair> = (0..4).map(|i| FalconKeypair::generate_from_seed(0xB0 + i)).collect();
    let vs = {
        let mut s = ValidatorSet::new();
        for (sk, fk) in sks.iter().zip(fks.iter()) {
            let id = sk.verifying_key().to_bytes();
            s.add(id, 1);
            register_validator_pq_key(id, PqScheme::Falcon512, fk.public_key().to_vec());
        }
        s
    };
    let target = Some([0x5Eu8; 32]);
    let mut set = VoteSet::new();
    for (sk, fk) in sks.iter().zip(fks.iter()) {
        set.add(
            Vote::sign_with_falcon(sk, fk, 9, 1, VoteKind::Precommit, target),
            &vs,
            9,
            1,
            VoteKind::Precommit,
        )
        .unwrap();
    }
    let parent = [0x6Bu8; 32];
    let qc = set.certificate(target, &vs, &parent).expect("4/4 must form");
    assert!(qc.verify(&vs), "all-valid mixed-scheme QC must verify");
    assert_eq!(qc.signers_set(&vs).len(), 4);
    // Corrupt one classical entry byte: µQC path still holds quorum and the
    // classical fallback counts exactly the good ones — verdict unchanged.
    let mut bad = qc.clone();
    // Find a non-marker classical entry and flip one byte.
    let idx = bad
        .signatures
        .iter()
        .position(|(v, s)| *v != [0xFDu8; 32] && *v != [0xFEu8; 32] && *v != [0xFFu8; 32] && s.len() == 64)
        .expect("classical entries present");
    bad.signatures[idx].1[0] ^= 0x01;
    assert!(bad.verify(&vs), "µQC still proves quorum after 1 classical forgery");
    // Attribution is the UNION of paths: the corrupted voter drops out of
    // the classical set but stays named via the still-verifying µQC marker.
    let bad_signers = bad.signers_set(&vs);
    assert_eq!(bad_signers.len(), 4);
    assert!(bad_signers.contains(&bad.signatures[idx].0));
    clear_validator_pq_keys_for_tests();
}
