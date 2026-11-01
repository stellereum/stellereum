//! Power-weighted µQC quorum — regression for the N=3 fragile-unanimous audit.
//!
//! Вещдок: при N=3 поголовный порог `floor(2*3/3)+1 = 3/3` требовал единогласия —
//! падение любого валидатора останавливало сеть, хотя по весам A+B=4000 ≥ 3334
//! кворум был. Проверяет новый подсчёт в `src/consensus.rs`:
//! сумма весов подписантов комитета ≥ `floor(2*W/3)+1` от веса комитета.
//!
//! Кейсы (все на скошенном сете 2000/2000/1000, W=5000, quorum=3334):
//! * 2 подписанта-тяжеловеса (4000) — ПРОХОДИТ (старый код требовал 3/3);
//! * 1 подписант (2000) — НЕ проходит;
//! * старые 3/3 — проходят новым кодом (обратная совместимость);
//! * пустой комитет / нулевой вес — отказ (fail-closed);
//! * CEC-путь (полный сет, power-учёт) — не сломан;
//! * `VoteSet::certificate` компилирует µQC уже с 2 тяжёлых голосов.

use stellereum::consensus::{
    derive_sortition_committee, encode_pq_epoch_envelope, encode_pq_micro_envelope,
    pq_micro_quorum_power, pq_micro_quorum_threshold, register_validator_pq_key, vote_sign_bytes,
    PqMicroCertificate, QuorumCertificate, ValidatorSet, Vote, VoteKind, PQ_QC_MARKER_ID,
    PQ_UQC_MARKER_ID,
};
use stellereum::post_quantum::{derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT};

// --- fixtures ----------------------------------------------------------------

const HEAVY: u64 = 2000;
const LIGHT: u64 = 1000;
const TOTAL_W: u64 = 5000;
const QUORUM_W: u64 = 3334; // floor(2*5000/3)+1

struct Fixture {
    vs: ValidatorSet,
    /// (validator id, falcon keypair); ids are PQ-derived addresses.
    keys: Vec<([u8; 32], FalconKeypair)>,
    heavy: [[u8; 32]; 2],
    committee: Vec<[u8; 32]>,
    height: u64,
    round: u32,
    kind: VoteKind,
    block_hash: Option<[u8; 32]>,
    msg: Vec<u8>,
}

fn setup_pq_set(seeds: [u8; 3], height: u64, round: u32) -> Fixture {
    let mut vs = ValidatorSet::new();
    let mut keys = Vec::new();
    let powers = [HEAVY, HEAVY, LIGHT];
    for (i, seed) in seeds.iter().enumerate() {
        let fk = FalconKeypair::generate_from_seed(*seed);
        let pk = fk.public_key().to_vec();
        let id = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);
        vs.add(id, powers[i]);
        register_validator_pq_key(id, PqScheme::Falcon512, pk);
        keys.push((id, fk));
    }
    // N=3, committee_size=3 → sortition возвращает весь сет (детерминировано).
    // The parent block hash seeds the draw; it must be the SAME one on the
    // build and the verify side, so it is pinned in the fixture.
    let parent = [0x5Au8; 32];
    let committee = derive_sortition_committee(&vs, height, round, 3, &parent);
    assert_eq!(committee.len(), 3, "N=3 committee must be the whole set");
    let kind = VoteKind::Precommit;
    let block_hash = Some([0xABu8; 32]);
    let msg = vote_sign_bytes(height, round, kind, &block_hash);
    // Тяжеловесы — два id с весом 2000.
    let mut heavy_ids: Vec<[u8; 32]> = keys[..2].iter().map(|(id, _)| *id).collect();
    heavy_ids.sort_unstable();
    Fixture {
        vs,
        keys,
        heavy: [heavy_ids[0], heavy_ids[1]],
        committee,
        height,
        round,
        kind,
        block_hash,
        msg,
    }
}

fn fk_of<'a>(f: &'a Fixture, id: &[u8; 32]) -> &'a FalconKeypair {
    f.keys
        .iter()
        .find(|(k, _)| k == id)
        .map(|(_, fk)| fk)
        .unwrap()
}

/// Собрать компактный µQC по подмножеству комитета `signer_ids` (сигнатуры — в
/// порядке индексов комитета, битмаска — по тем же индексам).
fn build_uqc(f: &Fixture, signer_ids: &[[u8; 32]]) -> PqMicroCertificate {
    let committee_size = 3u32;
    let mut bitmask = vec![0u8; 1];
    let mut signatures = Vec::new();
    for (i, member) in f.committee.iter().enumerate() {
        if signer_ids.contains(member) {
            bitmask[i / 8] |= 1 << (i % 8);
            signatures.push(fk_of(f, member).sign(&f.msg));
        }
    }
    PqMicroCertificate {
        scheme: PqScheme::Falcon512,
        height: f.height,
        round: f.round,
        committee_size,
        signers_bitmask: bitmask,
        signatures,
        sortition_parent: [0x5Au8; 32],
        // Predates the phase-3 VRF seal (mechanical fallout of the new
        // trailing field): legacy draw.
        vrf_beacon: None,
    }
}

fn wrap_uqc(f: &Fixture, uqc: &PqMicroCertificate) -> QuorumCertificate {
    QuorumCertificate {
        height: f.height,
        round: f.round,
        kind: f.kind,
        block_hash: f.block_hash,
        signatures: vec![(PQ_UQC_MARKER_ID, encode_pq_micro_envelope(uqc))],
    }
}

// --- threshold math ------------------------------------------------------------

#[test]
fn micro_quorum_power_math_is_classical_two_thirds_plus_one() {
    assert_eq!(pq_micro_quorum_power(TOTAL_W), QUORUM_W);
    assert_eq!(
        pq_micro_quorum_power(0),
        u64::MAX,
        "нулевой вес — fail-closed"
    );
    // Легаси-кривая на головах не тронута (запинена bridge-тестом).
    assert_eq!(pq_micro_quorum_threshold(3), 3);
    assert_eq!(pq_micro_quorum_threshold(16), 11);
    assert_eq!(pq_micro_quorum_threshold(0), usize::MAX);
}

// --- verify path ----------------------------------------------------------------

#[test]
fn two_heavy_weights_of_three_pass_power_quorum() {
    // Вещдок: A+B=4000 ≥ 3334 живёт без третьего; поголовный код требовал 3/3.
    let f = setup_pq_set([0xA1, 0xA2, 0xA3], 7, 0);
    let uqc = build_uqc(&f, &f.heavy.clone());
    assert_eq!(uqc.signed_count(), 2, "по головам — лишь 2/3");
    assert!(
        !uqc.has_quorum(),
        "легаси-счётчик по-прежнему видит недобор 2 < 3 (инспекция, не гейт)"
    );
    assert_eq!(uqc.signed_power(&f.committee, &f.vs), 4000);
    assert!(uqc.has_power_quorum(&f.committee, &f.vs));
    let qc = wrap_uqc(&f, &uqc);
    assert!(
        qc.verify(&f.vs),
        "2/2 веса (4000 ≥ 3334) обязаны верифицироваться"
    );
    assert!(qc.verify_unified(&f.vs));
}

#[test]
fn single_signer_weight_does_not_reach_quorum() {
    let f = setup_pq_set([0xB1, 0xB2, 0xB3], 8, 0);
    let one = [f.heavy[0]];
    let uqc = build_uqc(&f, &one);
    assert_eq!(uqc.signed_power(&f.committee, &f.vs), HEAVY);
    assert!(!uqc.has_power_quorum(&f.committee, &f.vs));
    let qc = wrap_uqc(&f, &uqc);
    assert!(!qc.verify(&f.vs), "1/3 (2000 < 3334) обязан отклоняться");
    assert!(!qc.verify_unified(&f.vs));
}

#[test]
fn legacy_three_of_three_still_verifies() {
    // Обратная совместимость: старые 3/3 несут полный вес комитета.
    let f = setup_pq_set([0xC1, 0xC2, 0xC3], 9, 0);
    let all: Vec<[u8; 32]> = f.committee.clone();
    let uqc = build_uqc(&f, &all);
    assert_eq!(uqc.signed_count(), 3);
    assert!(uqc.has_quorum(), "3/3 проходит и легаси-счёт");
    assert_eq!(uqc.signed_power(&f.committee, &f.vs), TOTAL_W);
    let qc = wrap_uqc(&f, &uqc);
    assert!(
        qc.verify(&f.vs),
        "старые 3/3 серты обязаны проходить новым кодом"
    );
    assert!(qc.verify_unified(&f.vs));
}

#[test]
fn empty_committee_and_zero_weight_fail_closed() {
    let f = setup_pq_set([0xD1, 0xD2, 0xD3], 10, 0);
    // Пустой комитет.
    let empty = PqMicroCertificate {
        scheme: PqScheme::Falcon512,
        height: f.height,
        round: f.round,
        committee_size: 0,
        signers_bitmask: vec![],
        signatures: vec![],
        sortition_parent: [0x5Au8; 32],
        // Predates the phase-3 VRF seal (mechanical fallout of the new
        // trailing field): legacy draw.
        vrf_beacon: None,
    };
    let qc = QuorumCertificate {
        height: f.height,
        round: f.round,
        kind: f.kind,
        block_hash: f.block_hash,
        signatures: vec![(PQ_UQC_MARKER_ID, encode_pq_micro_envelope(&empty))],
    };
    assert!(!qc.verify(&ValidatorSet::new()));
    assert!(!qc.verify(&f.vs));
    assert!(!empty.has_power_quorum(&[], &f.vs));

    // Нулевой вес: пустой validator set, комитет вывести не из чего.
    let vs_empty = ValidatorSet::new();
    assert_eq!(vs_empty.quorum_power(), u64::MAX);
    let committee = derive_sortition_committee(&vs_empty, f.height, f.round, 3, &[0x5Au8; 32]);
    assert!(committee.is_empty());
    let bogus = PqMicroCertificate {
        scheme: PqScheme::Falcon512,
        height: f.height,
        round: f.round,
        committee_size: 3,
        signers_bitmask: vec![0b0000_0011],
        signatures: vec![vec![0u8; 8], vec![0u8; 8]],
        sortition_parent: [0x5Au8; 32],
        // Predates the phase-3 VRF seal (mechanical fallout of the new
        // trailing field): legacy draw.
        vrf_beacon: None,
    };
    let qc2 = QuorumCertificate {
        height: f.height,
        round: f.round,
        kind: f.kind,
        block_hash: f.block_hash,
        signatures: vec![(PQ_UQC_MARKER_ID, encode_pq_micro_envelope(&bogus))],
    };
    assert!(!qc2.verify(&vs_empty), "нулевой вес — отказ");
}

// --- CEC path ---------------------------------------------------------------------

#[test]
fn cec_power_path_still_verifies() {
    // CEC уже считал по весам — проверяем, что путь не сломан: A+B=4000 ≥ 3334.
    let f = setup_pq_set([0xE1, 0xE2, 0xE3], 11, 0);
    let mut ids: Vec<[u8; 32]> = f.vs.validators.keys().copied().collect();
    ids.sort_unstable();
    assert_eq!(ids, f.committee, "при N=3 комитет совпадает с полным сетом");
    let mut bitmask = vec![0u8; 1];
    let mut signatures = Vec::new();
    for (i, id) in ids.iter().enumerate() {
        if f.heavy.contains(id) {
            bitmask[i / 8] |= 1 << (i % 8);
            signatures.push(fk_of(&f, id).sign(&f.msg));
        }
    }
    let cec = PqMicroCertificate {
        scheme: PqScheme::Falcon512,
        height: f.height,
        round: f.round,
        committee_size: ids.len() as u32,
        signers_bitmask: bitmask,
        signatures,
        sortition_parent: [0x5Au8; 32],
        // Predates the phase-3 VRF seal (mechanical fallout of the new
        // trailing field): legacy draw.
        vrf_beacon: None,
    };
    let qc = QuorumCertificate {
        height: f.height,
        round: f.round,
        kind: f.kind,
        block_hash: f.block_hash,
        signatures: vec![(PQ_QC_MARKER_ID, encode_pq_epoch_envelope(&cec))],
    };
    assert!(qc.verify(&f.vs), "CEC с кворумом по весу обязан проходить");
    assert!(qc.verify_unified(&f.vs));
}

// --- end-to-end: VoteSet compilation -----------------------------------------------

#[test]
fn voteset_compiles_uqc_from_two_heavy_falcon_votes() {
    // Сквозной путь: два Ed25519-голоса тяжеловесов дают и классический кворум
    // (4000 ≥ 3334), и µQC по весу — старый счётчик 2 < 3 его бы не скомпилировал.
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let height = 12u64;
    let round = 0u32;
    let kind = VoteKind::Precommit;
    let block_hash = Some([0xCDu8; 32]);

    let mut vs = ValidatorSet::new();
    let mut sks = Vec::new();
    let mut fks = Vec::new();
    let powers = [HEAVY, HEAVY, LIGHT];
    for (i, p) in powers.iter().enumerate() {
        let sk = SigningKey::generate(&mut OsRng);
        let id = sk.verifying_key().to_bytes();
        let fk = FalconKeypair::generate_from_seed(0xF0 + i as u8);
        vs.add(id, *p);
        register_validator_pq_key(id, PqScheme::Falcon512, fk.public_key().to_vec());
        sks.push(sk);
        fks.push(fk);
    }
    assert_eq!(vs.quorum_power(), QUORUM_W);

    let mut set = stellereum::consensus::VoteSet::new();
    for i in 0..2 {
        let v = Vote::sign_with_falcon(&sks[i], &fks[i], height, round, kind, block_hash);
        set.add(v, &vs, height, round, kind)
            .expect("heavy vote admits");
    }
    let parent = [0x5Au8; 32];
    let qc = set
        .certificate(block_hash, &vs, &parent)
        .expect("classical quorum 4000 ≥ 3334 must form");
    assert!(qc.verify(&vs));
    let uqc = qc
        .pq_micro_certificate()
        .expect("µQC обязан скомпилироваться уже с 2 тяжёлых голосов (по весу), а не ждать 3/3");
    assert_eq!(
        uqc.signed_power(
            &derive_sortition_committee(&vs, height, round, uqc.committee_size, &parent),
            &vs
        ),
        4000
    );
    assert!(qc.verify_unified(&vs));
}
