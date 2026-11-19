//! QC batch verification: benchmarks + batched==serial differentials.
//!
//! Scope: `QuorumCertificate::verify` / `signers_set` (QC-VERIFY path only).
//! Under FULL-PQ, `verify_unified` verifies Falcon-512 µQC (`PQ_UQC_MARKER_ID`)
//! and CEC Epoch (`PQ_QC_MARKER_ID`) envelopes via `verify_staged_pq_signatures`
//! (serial `<= 8`, chunked-parallel rayon `> 8`). These tests pin equality
//! against a plain serial per-signature oracle and report wall-clock ms for
//! fixed fixtures at k=7/64/100 (run with `-- --nocapture`).

use ed25519_dalek::SigningKey;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::collections::HashSet;
use std::sync::Mutex;
use std::time::Instant;
use stellereum::consensus::{
    clear_validator_pq_keys_for_tests, decode_pq_epoch_envelope, decode_pq_micro_envelope,
    derive_sortition_committee, encode_pq_micro_envelope, get_validator_pq_key,
    micro_committee_size, mixed_quorum_pair_safe, pq_micro_required_power,
    register_validator_pq_key, vote_sign_bytes, PqMicroCertificate, QuorumCertificate, ValidatorId,
    ValidatorSet, Vote, VoteKind, VoteSet, MAX_COMMIT_CERT_SIGNERS, PQ_QC_MARKER_ID,
    PQ_UQC_MARKER_ID,
};
use stellereum::post_quantum::{verify_pq_signature, FalconKeypair, PqScheme};

const BH: [u8; 32] = [0x77u8; 32];
const PARENT: [u8; 32] = [0x6Bu8; 32];
const HH: u64 = 1;
const RR: u32 = 0;

/// Global PQ validator key registry is process-wide; serialize tests in this
/// file so clearing keys in one test never races with another.
static PQ_KEY_LOCK: Mutex<()> = Mutex::new(());

fn det_keys(k: usize, seed: u64) -> Vec<(SigningKey, FalconKeypair)> {
    let mut rng = StdRng::seed_from_u64(seed);
    (0..k)
        .map(|_| {
            let mut ed_bytes = [0u8; 32];
            rng.fill_bytes(&mut ed_bytes);
            let mut fq_bytes = [0u8; 32];
            rng.fill_bytes(&mut fq_bytes);
            (
                SigningKey::from_bytes(&ed_bytes),
                FalconKeypair::generate_from_seed_bytes(&fq_bytes),
            )
        })
        .collect()
}

fn val_set(ks: &[(SigningKey, FalconKeypair)]) -> ValidatorSet {
    let mut vs = ValidatorSet::new();
    for (sk, fk) in ks {
        let id = sk.verifying_key().to_bytes();
        vs.add(id, 1);
        register_validator_pq_key(id, PqScheme::Falcon512, fk.public_key.clone());
    }
    vs
}

fn build_qc(ks: &[(SigningKey, FalconKeypair)]) -> (QuorumCertificate, ValidatorSet) {
    let vs = val_set(ks);
    let mut set = VoteSet::new();
    for (sk, fk) in ks {
        set.add(
            Vote::sign_with_falcon(sk, fk, HH, RR, VoteKind::Precommit, Some(BH)),
            &vs,
            HH,
            RR,
            VoteKind::Precommit,
        )
        .expect("valid Falcon vote must be accepted");
    }
    let qc = set
        .certificate(Some(BH), &vs, &PARENT)
        .expect("full set must form QC");
    (qc, vs)
}

/// Serial per-signature oracle for `PqMicroCertificate` attribution.
fn serial_micro_cert_valid_signers(
    qc: &QuorumCertificate,
    cert: &PqMicroCertificate,
    vs: &ValidatorSet,
    msg: &[u8],
) -> Option<Vec<ValidatorId>> {
    if cert.height != qc.height || cert.round != qc.round || !cert.scheme.is_post_quantum() {
        return None;
    }
    let expected_committee_size = micro_committee_size(vs.len());
    if cert.committee_size != expected_committee_size
        || cert.committee_size == 0
        || cert.committee_size as usize > MAX_COMMIT_CERT_SIGNERS
    {
        return None;
    }
    let expected_bitmask_len = (cert.committee_size as usize).div_ceil(8);
    if cert.signers_bitmask.len() != expected_bitmask_len {
        return None;
    }
    for i in (cert.committee_size as usize)..(cert.signers_bitmask.len() * 8) {
        if (cert.signers_bitmask[i / 8] & (1 << (i % 8))) != 0 {
            return None;
        }
    }
    let committee = derive_sortition_committee(
        vs,
        cert.height,
        cert.round,
        cert.committee_size,
        &cert.sortition_parent,
    );
    let expected_len = (cert.committee_size as usize).min(vs.len());
    if committee.len() != expected_len || committee.is_empty() {
        return None;
    }
    for i in committee.len()..(cert.committee_size as usize) {
        if cert.is_signer(i) {
            return None;
        }
    }
    let signed_count = cert.signed_count();
    let is_compact = cert.signatures.len() == signed_count;
    let is_full = cert.signatures.len() == cert.committee_size as usize;
    if !is_compact && !is_full {
        return None;
    }
    let mut sig_idx = 0;
    let mut valid = Vec::new();
    for (i, val_id) in committee.iter().enumerate() {
        if cert.is_signer(i) {
            let sig = if is_compact {
                let s = &cert.signatures[sig_idx];
                sig_idx += 1;
                s
            } else {
                &cert.signatures[i]
            };
            let (scheme, pubkey) = get_validator_pq_key(val_id)?;
            if scheme != cert.scheme {
                return None;
            }
            if !verify_pq_signature(scheme, &pubkey, msg, sig) {
                return None;
            }
            valid.push(*val_id);
        }
    }
    Some(valid)
}

/// Serial per-signature oracle for `PQ_QC_MARKER_ID` epoch certificates.
fn serial_epoch_cert_valid_signers(
    qc: &QuorumCertificate,
    cert: &PqMicroCertificate,
    vs: &ValidatorSet,
    msg: &[u8],
) -> Option<Vec<ValidatorId>> {
    if cert.height != qc.height || cert.round != qc.round || !cert.scheme.is_post_quantum() {
        return None;
    }
    if vs.is_empty() {
        return None;
    }
    let mut ids: Vec<ValidatorId> = vs.validators.keys().copied().collect();
    ids.sort_unstable();
    let signed_count = cert.signed_count();
    let is_compact = cert.signatures.len() == signed_count;
    let is_full =
        cert.signatures.len() == ids.len() || cert.signatures.len() == cert.committee_size as usize;
    if !is_compact && !is_full {
        return None;
    }
    let mut sig_idx = 0;
    let mut valid = Vec::new();
    for (i, val_id) in ids.iter().enumerate() {
        if cert.is_signer(i) {
            let sig = if is_compact {
                let s = &cert.signatures[sig_idx];
                sig_idx += 1;
                s
            } else {
                &cert.signatures[i]
            };
            let (scheme, pubkey) = get_validator_pq_key(val_id)?;
            if scheme != cert.scheme {
                return None;
            }
            if !verify_pq_signature(scheme, &pubkey, msg, sig) {
                return None;
            }
            valid.push(*val_id);
        }
    }
    Some(valid)
}

/// Serial oracle for FULL-PQ `QuorumCertificate::verify`:
/// anti-DoS cap, then serial per-signature verification of µQC / epoch envelopes.
fn serial_qc_verify(qc: &QuorumCertificate, vs: &ValidatorSet) -> bool {
    if qc.signatures.len() > MAX_COMMIT_CERT_SIGNERS {
        return false;
    }
    let msg = vote_sign_bytes(qc.height, qc.round, qc.kind, &qc.block_hash);
    for (voter, payload) in &qc.signatures {
        if *voter == PQ_UQC_MARKER_ID {
            if let Some(cert) = decode_pq_micro_envelope(payload) {
                if let Some(valid) = serial_micro_cert_valid_signers(qc, &cert, vs, &msg) {
                    let committee = derive_sortition_committee(
                        vs,
                        cert.height,
                        cert.round,
                        cert.committee_size,
                        &cert.sortition_parent,
                    );
                    let committee_total: u64 = committee.iter().map(|id| vs.power_of(id)).sum();
                    if committee_total == 0 {
                        continue;
                    }
                    let quorum_power = pq_micro_required_power(committee_total, vs.total_power());
                    if !mixed_quorum_pair_safe(quorum_power, vs.quorum_power(), vs.total_power()) {
                        continue;
                    }
                    let valid_power: u64 = valid.iter().map(|id| vs.power_of(id)).sum();
                    if valid_power >= quorum_power {
                        return true;
                    }
                }
            }
        } else if *voter == PQ_QC_MARKER_ID {
            if let Some(cert) =
                decode_pq_epoch_envelope(payload).or_else(|| decode_pq_micro_envelope(payload))
            {
                if let Some(valid) = serial_epoch_cert_valid_signers(qc, &cert, vs, &msg) {
                    let power: u64 = valid.iter().map(|id| vs.power_of(id)).sum();
                    if power >= vs.quorum_power() {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Serial oracle for FULL-PQ `QuorumCertificate::signers_set`.
fn serial_qc_signers(qc: &QuorumCertificate, vs: &ValidatorSet) -> HashSet<ValidatorId> {
    let msg = vote_sign_bytes(qc.height, qc.round, qc.kind, &qc.block_hash);
    let mut out = HashSet::new();
    for (voter, payload) in &qc.signatures {
        if *voter == PQ_UQC_MARKER_ID {
            if let Some(cert) = decode_pq_micro_envelope(payload) {
                if let Some(ids) = serial_micro_cert_valid_signers(qc, &cert, vs, &msg) {
                    out.extend(ids);
                }
            }
        } else if *voter == PQ_QC_MARKER_ID {
            if let Some(cert) =
                decode_pq_epoch_envelope(payload).or_else(|| decode_pq_micro_envelope(payload))
            {
                if let Some(ids) = serial_epoch_cert_valid_signers(qc, &cert, vs, &msg) {
                    out.extend(ids);
                }
            }
        }
    }
    out
}

#[test]
fn qc_verify_benchmark_fixed_fixtures() {
    let _guard = PQ_KEY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_validator_pq_keys_for_tests();
    // Fixed fixtures: seeded Falcon keys, fixed (height, round, kind, target).
    // REPORT ONLY (no timing asserts): paste output for before/after.
    for (k, iters) in [(7usize, 200usize), (64, 50), (100, 30)] {
        let ks = det_keys(k, 0x9C1 + k as u64);
        let (qc, vs) = build_qc(&ks);
        assert!(qc.verify(&vs), "k={k} fixture QC must verify");
        let t = Instant::now();
        for _ in 0..iters {
            assert!(qc.verify(&vs));
        }
        let ms = t.elapsed().as_secs_f64() * 1000.0;
        println!(
            "qc_verify k={k} iters={iters} total_ms={ms:.2} mean_ms={:.4}",
            ms / iters as f64
        );
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
    clear_validator_pq_keys_for_tests();
}

#[test]
fn qc_verify_differential_randomized() {
    let _guard = PQ_KEY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_validator_pq_keys_for_tests();
    // Fixed seeds: deterministic across runs and machines.
    let mut rng = StdRng::seed_from_u64(0x9CB47);
    for round in 0..40 {
        let n = 1 + (rng.next_u32() % 16) as usize;
        let ks = det_keys(n, 0x1000 + round as u64);
        let (mut qc, vs) = build_qc(&ks);
        // Mutations: corrupt one Falcon sig in µQC, duplicate marker, swap in
        // outsider sig, garbage marker bytes, or truncate µQC below quorum.
        match rng.next_u32() % 6 {
            0 => {
                let idx = qc
                    .signatures
                    .iter()
                    .position(|(v, _)| *v == PQ_UQC_MARKER_ID)
                    .expect("µQC marker present");
                let mut cert = decode_pq_micro_envelope(&qc.signatures[idx].1).unwrap();
                let j = (rng.next_u32() as usize) % cert.signatures.len();
                let l = cert.signatures[j].len();
                cert.signatures[j][(rng.next_u32() as usize) % l] ^= 0x01;
                qc.signatures[idx].1 = encode_pq_micro_envelope(&cert);
            }
            1 => {
                let idx = qc
                    .signatures
                    .iter()
                    .position(|(v, _)| *v == PQ_UQC_MARKER_ID)
                    .expect("µQC marker present");
                let dup = qc.signatures[idx].clone();
                qc.signatures.push(dup);
            }
            2 => {
                let mut b = [0u8; 32];
                rng.fill_bytes(&mut b);
                let outsider_fk = FalconKeypair::generate_from_seed_bytes(&b);
                let msg = vote_sign_bytes(HH, RR, VoteKind::Precommit, &Some(BH));
                let idx = qc
                    .signatures
                    .iter()
                    .position(|(v, _)| *v == PQ_UQC_MARKER_ID)
                    .expect("µQC marker present");
                let mut cert = decode_pq_micro_envelope(&qc.signatures[idx].1).unwrap();
                let j = (rng.next_u32() as usize) % cert.signatures.len();
                cert.signatures[j] = outsider_fk.sign(&msg);
                qc.signatures[idx].1 = encode_pq_micro_envelope(&cert);
            }
            3 => {
                let idx = qc
                    .signatures
                    .iter()
                    .position(|(v, _)| *v == PQ_UQC_MARKER_ID)
                    .expect("µQC marker present");
                qc.signatures[idx].1 = vec![0u8; 3];
            }
            4 => {
                let idx = qc
                    .signatures
                    .iter()
                    .position(|(v, _)| *v == PQ_UQC_MARKER_ID)
                    .expect("µQC marker present");
                let mut cert = decode_pq_micro_envelope(&qc.signatures[idx].1).unwrap();
                if n >= 2 {
                    // Keep only signer 0 (below quorum for any n >= 2).
                    cert.signers_bitmask.fill(0);
                    cert.signers_bitmask[0] = 0x01;
                    cert.signatures.truncate(1);
                } else {
                    cert.signers_bitmask.fill(0);
                    cert.signatures.clear();
                }
                qc.signatures[idx].1 = encode_pq_micro_envelope(&cert);
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
    clear_validator_pq_keys_for_tests();
}

#[test]
fn qc_verify_edges_empty_overcap_one_corrupt() {
    let _guard = PQ_KEY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_validator_pq_keys_for_tests();
    // Empty QC: no candidates -> false on both paths.
    let ks = det_keys(4, 0xE1);
    let vs = val_set(&ks);
    let empty = QuorumCertificate {
        shard_id: 0,
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

    // 3/4 valid signers with 1 omitted reaches quorum 3 and attributes 3.
    let ks4 = det_keys(4, 0xE3);
    let vs4 = val_set(&ks4);
    let mut set3 = VoteSet::new();
    for (sk, fk) in ks4.iter().take(3) {
        set3.add(
            Vote::sign_with_falcon(sk, fk, HH, RR, VoteKind::Precommit, Some(BH)),
            &vs4,
            HH,
            RR,
            VoteKind::Precommit,
        )
        .unwrap();
    }
    let qc3 = set3.certificate(Some(BH), &vs4, &PARENT).unwrap();
    assert!(qc3.verify(&vs4), "3/4 good reaches quorum 3");
    assert_eq!(qc3.verify(&vs4), serial_qc_verify(&qc3, &vs4));
    let signers3 = qc3.signers_set(&vs4);
    assert_eq!(signers3, serial_qc_signers(&qc3, &vs4));
    assert_eq!(signers3.len(), 3);

    // 1-corrupt inside µQC: fail-closed under FULL-PQ (verify == false, no signers).
    let (mut bad_qc, _) = build_qc(&ks4);
    let idx = bad_qc
        .signatures
        .iter()
        .position(|(v, _)| *v == PQ_UQC_MARKER_ID)
        .expect("µQC marker present");
    let mut cert = decode_pq_micro_envelope(&bad_qc.signatures[idx].1).unwrap();
    cert.signatures[1][0] ^= 0xFF;
    bad_qc.signatures[idx].1 = encode_pq_micro_envelope(&cert);
    assert!(!bad_qc.verify(&vs4), "corrupted µQC entry must fail closed");
    assert_eq!(bad_qc.verify(&vs4), serial_qc_verify(&bad_qc, &vs4));
    assert_eq!(bad_qc.signers_set(&vs4), serial_qc_signers(&bad_qc, &vs4));
    assert!(bad_qc.signers_set(&vs4).is_empty());

    clear_validator_pq_keys_for_tests();
}

#[test]
fn qc_verify_mixed_scheme_falcon_envelope_pins() {
    let _guard = PQ_KEY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    use stellereum::consensus::VoteSet;
    clear_validator_pq_keys_for_tests();
    // Mixed-scheme QC: Falcon-envelope votes assemble a classical Ed25519
    // list (bare halves) plus a µQC marker. Under FULL-PQ only the µQC marker
    // counts; classical entries are inert.
    let sks: Vec<SigningKey> = (0..4).map(|i| det_keys(4, 0xF4)[i].0.clone()).collect();
    let fks: Vec<FalconKeypair> = (0..4)
        .map(|i| FalconKeypair::generate_from_seed(0xB0 + i))
        .collect();
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
    let qc = set
        .certificate(target, &vs, &parent)
        .expect("4/4 must form");
    assert!(qc.verify(&vs), "all-valid mixed-scheme QC must verify");
    assert_eq!(qc.signers_set(&vs).len(), 4);
    // Corrupt one classical entry byte: µQC path still holds quorum and the
    // classical entries are inert — verdict unchanged.
    let mut bad = qc.clone();
    let idx = bad
        .signatures
        .iter()
        .position(|(v, s)| {
            *v != [0xFDu8; 32] && *v != [0xFEu8; 32] && *v != [0xFFu8; 32] && s.len() == 64
        })
        .expect("classical entries present");
    bad.signatures[idx].1[0] ^= 0x01;
    assert!(
        bad.verify(&vs),
        "µQC still proves quorum after 1 classical forgery"
    );
    let bad_signers = bad.signers_set(&vs);
    assert_eq!(bad_signers.len(), 4);
    assert!(bad_signers.contains(&bad.signatures[idx].0));
    clear_validator_pq_keys_for_tests();
}
