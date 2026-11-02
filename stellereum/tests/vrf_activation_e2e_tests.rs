//! VRF activation end-to-end: provisioning → registry → assembly↔verify,
//! default-off identity, seedless fallback, forged-seal refusal.
//!
//! Gate: secret provisioning (`derive_vrf_secret_seed` installed via
//! `with_vrf_secret_seed`), the `STELL_VRF_KEYS` registry loader
//! (`parse_vrf_keys_config` / `vrf_registry_from_env`), and the threaded live
//! verify/attribution path (`verify_unified` / `signers_set` consulting the
//! env activation + the startup-loaded registry). Default-off (env unset,
//! empty registry) is byte-identical to the legacy path.
//!
//! No crypto changes here: `vrf_prove` / `vrf_verify` math is untouched; this
//! suite only wires provisioning, loading and threading. No BLS changes.
//!
//! Process-global state (env vars, PQ-key registry, live VRF registry) is
//! shared by every test in this binary, so ALL tests serialize on `SERIAL`
//! and restore env on drop.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use stellereum::consensus::{
    clear_live_vrf_registry_for_tests, clear_validator_pq_keys_for_tests, derive_sortition_committee,
    derive_sortition_committee_gated, encode_pq_micro_envelope, register_validator_pq_key,
    set_live_vrf_registry, sortition_seed, sortition_seed_gated, vote_sign_bytes,
    PqMicroCertificate, ValidatorSet, Vote, VoteKind, VoteSet, VrfBeaconSeal,
};
use stellereum::post_quantum::FalconKeypair;
use stellereum::runtime::ValidatorRuntime;
use stellereum::state_engine::InMemoryStateEngine;
use stellereum::vrf::{
    derive_vrf_secret_seed, parse_vrf_keys_config, verify_vrf_seed_for_validator,
    vrf_activation_from_env, vrf_election_seed, vrf_prove, vrf_registry_from_env, VrfActivation,
    VrfRegistry, VrfSecret, VRF_ACTIVATION_HEIGHT_ENV, VRF_KEYS_ENV,
};

const ACTIVATION_H: u64 = 1_000_000;
const ROUND: u32 = 0;
const KIND: VoteKind = VoteKind::Precommit;

static SERIAL: Mutex<()> = Mutex::new(());

struct EnvRestore {
    saved: Vec<(&'static str, Option<String>)>,
}

impl EnvRestore {
    fn save(keys: &[&'static str]) -> Self {
        let saved = keys.iter().map(|k| (*k, std::env::var(k).ok())).collect();
        Self { saved }
    }
}

impl Drop for EnvRestore {
    fn drop(&mut self) {
        for (k, v) in &self.saved {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
    }
}

fn ed_seed(tag: u8, i: usize) -> [u8; 32] {
    let mut s = [tag; 32];
    s[0] = i as u8;
    s[31] ^= i as u8;
    s
}

/// Deterministic N-validator network where every VRF key is DERIVED from the
/// validator's ed seed (the provisioning rule) and the registry is built by
/// the LOADER from a `STELL_VRF_KEYS`-shaped string (not by hand-insertion).
struct Net {
    vs: ValidatorSet,
    ids: Vec<[u8; 32]>,
    ed: Vec<SigningKey>,
    falcon: Vec<FalconKeypair>,
    vrf_seeds: Vec<[u8; 32]>,
    reg: VrfRegistry,
    parent: [u8; 32],
    block_hash: Option<[u8; 32]>,
    keys_env: String,
}

fn setup_net(n: usize, tag: u8, power: u64) -> Net {
    clear_validator_pq_keys_for_tests();
    clear_live_vrf_registry_for_tests();
    let mut vs = ValidatorSet::new();
    let mut ids = Vec::new();
    let mut ed = Vec::new();
    let mut falcon = Vec::new();
    let mut vrf_seeds = Vec::new();
    let mut entries = Vec::new();
    for i in 0..n {
        let seed = ed_seed(tag, i);
        let sk = SigningKey::from_bytes(&seed);
        let id = sk.verifying_key().to_bytes();
        let fk = FalconKeypair::generate_from_seed_bytes(&ed_seed(tag.wrapping_add(0x50), i));
        vs.add(id, power);
        register_validator_pq_key(
            id,
            stellereum::post_quantum::PqScheme::Falcon512,
            fk.public_key().to_vec(),
        );
        // Provisioning rule: the VRF seed is derived from the ed seed.
        let vrf_seed = derive_vrf_secret_seed(&seed);
        let vrf_pk = VrfSecret::from_seed(&vrf_seed).public_key().to_bytes();
        entries.push(format!("{}:{}", hex::encode(id), hex::encode(vrf_pk)));
        ids.push(id);
        ed.push(sk);
        falcon.push(fk);
        vrf_seeds.push(vrf_seed);
    }
    let keys_env = entries.join(",");
    let reg = parse_vrf_keys_config(&keys_env);
    assert_eq!(reg.len(), n, "loader must admit every honest entry");
    Net {
        vs,
        ids,
        ed,
        falcon,
        vrf_seeds,
        reg,
        parent: [0x5Au8; 32],
        block_hash: Some([0xABu8; 32]),
        keys_env,
    }
}

fn vote_set_for(net: &Net, height: u64, round: u32) -> VoteSet {
    let mut set = VoteSet::new();
    for i in 0..net.ids.len() {
        let v = Vote::sign_with_falcon(&net.ed[i], &net.falcon[i], height, round, KIND, net.block_hash);
        set.add(v, &net.vs, height, round, KIND)
            .expect("honest vote admits");
    }
    set
}

fn msg_for(height: u64, round: u32, block_hash: &Option<[u8; 32]>) -> Vec<u8> {
    vote_sign_bytes(height, round, KIND, block_hash)
}

// --- (a) seed derivation: determinism, restarts, distinct keypair ----------

#[test]
fn seed_derivation_deterministic_distinct_and_stable_across_restarts() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let _restore = EnvRestore::save(&[VRF_ACTIVATION_HEIGHT_ENV, VRF_KEYS_ENV]);

    let ed = ed_seed(0x42, 3);
    // Same ed seed ⇒ same VRF seed, twice (and the VRF pubkey follows).
    let first = derive_vrf_secret_seed(&ed);
    let second = derive_vrf_secret_seed(&ed);
    assert_eq!(first, second, "derivation must be deterministic");
    let pk1 = VrfSecret::from_seed(&first).public_key().to_bytes();
    let pk2 = VrfSecret::from_seed(&second).public_key().to_bytes();
    assert_eq!(pk1, pk2);

    // "Across restarts": re-derive from the same raw seed bytes a third time
    // (a fresh process reading the same key file lands here).
    let restart_seed = ed_seed(0x42, 3);
    assert_eq!(derive_vrf_secret_seed(&restart_seed), first);
    assert_eq!(
        VrfSecret::from_seed(&derive_vrf_secret_seed(&restart_seed))
            .public_key()
            .to_bytes(),
        pk1
    );

    // Distinct keypair from ed: the VRF pubkey is not the ed pubkey, and a
    // different ed seed derives a different VRF key.
    let ed_pk = SigningKey::from_bytes(&ed).verifying_key().to_bytes();
    assert_ne!(pk1, ed_pk, "VRF key must differ from the ed key");
    let other = derive_vrf_secret_seed(&ed_seed(0x42, 4));
    assert_ne!(first, other, "different ed seed ⇒ different VRF seed");
    assert_ne!(
        VrfSecret::from_seed(&other).public_key().to_bytes(),
        pk1
    );
}

// --- (b) registry loader: valid / garbage / empty --------------------------

#[test]
fn registry_loader_accepts_valid_rejects_garbage() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let _restore = EnvRestore::save(&[VRF_ACTIVATION_HEIGHT_ENV, VRF_KEYS_ENV]);

    // Two honest entries round-trip through the loader byte-exactly.
    let id0 = ed_seed(0x11, 0);
    let vrf0 = VrfSecret::from_seed(&derive_vrf_secret_seed(&id0))
        .public_key()
        .to_bytes();
    let id1 = ed_seed(0x11, 1);
    let vrf1 = VrfSecret::from_seed(&derive_vrf_secret_seed(&id1))
        .public_key()
        .to_bytes();
    let raw = format!("{}:{},{}:{}", hex::encode(id0), hex::encode(vrf0), hex::encode(id1), hex::encode(vrf1));
    let reg = parse_vrf_keys_config(&raw);
    assert_eq!(reg.len(), 2);
    assert_eq!(reg.get(&id0), Some(vrf0));
    assert_eq!(reg.get(&id1), Some(vrf1));

    // Whitespace and uppercase hex are tolerated (operator-edited files).
    let raw_ws = format!(
        "  {} : {} , {}:{}  ",
        hex::encode(id0).to_uppercase(),
        hex::encode(vrf0).to_uppercase(),
        hex::encode(id1),
        hex::encode(vrf1)
    );
    let reg_ws = parse_vrf_keys_config(&raw_ws);
    assert_eq!(reg_ws.len(), 2);
    assert_eq!(reg_ws.get(&id0), Some(vrf0));

    // Garbage entries fail closed: skipped, never stored, never a panic.
    // (`vrf_bad` is the identity point — refused; `vrf_ff` does not
    // decompress — refused.)
    let vrf_bad = [0u8; 32];
    let vrf_ff = [0xFFu8; 32];
    let garbage = format!(
        "nothex:{},{}:zz,short:00,three:parts:here,,{}:{},{}:{},{}:{}",
        hex::encode(vrf0),
        hex::encode(id0),
        hex::encode(id0),
        hex::encode(vrf_bad),
        hex::encode(id0),
        hex::encode(vrf_ff),
        hex::encode([0x09u8; 32]),
        hex::encode(vrf0),
    );
    let reg_g = parse_vrf_keys_config(&garbage);
    assert_eq!(
        reg_g.len(),
        1,
        "only the trailing honest entry survives the garbage"
    );
    assert_eq!(reg_g.get(&[0x09u8; 32]), Some(vrf0));
    assert!(reg_g.get(&id0).is_none());

    // Empty / whitespace-only input ⇒ empty registry (legacy fallback).
    assert!(parse_vrf_keys_config("").is_empty());
    assert!(parse_vrf_keys_config("   ").is_empty());
    assert!(parse_vrf_keys_config(",,,").is_empty());
}

#[test]
fn registry_loader_env_unset_empty_and_valid() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let _restore = EnvRestore::save(&[VRF_ACTIVATION_HEIGHT_ENV, VRF_KEYS_ENV]);

    // Unset ⇒ empty registry (default-off).
    std::env::remove_var(VRF_KEYS_ENV);
    assert!(vrf_registry_from_env().is_empty());

    // Empty ⇒ empty registry.
    std::env::set_var(VRF_KEYS_ENV, "   ");
    assert!(vrf_registry_from_env().is_empty());

    // Valid env ⇒ loaded registry (the startup path).
    let id = ed_seed(0x22, 7);
    let vrf_pk = VrfSecret::from_seed(&derive_vrf_secret_seed(&id))
        .public_key()
        .to_bytes();
    std::env::set_var(VRF_KEYS_ENV, format!("{}:{}", hex::encode(id), hex::encode(vrf_pk)));
    let reg = vrf_registry_from_env();
    assert_eq!(reg.len(), 1);
    assert_eq!(reg.get(&id), Some(vrf_pk));

    // Garbage env ⇒ empty registry, no panic (fail-closed at startup).
    std::env::set_var(VRF_KEYS_ENV, "garbage-no-colon");
    assert!(vrf_registry_from_env().is_empty());
}

// --- (c) assembly↔verify agreement with provisioned seed + loaded registry --

#[test]
fn assembly_verify_agreement_with_provisioned_seed_and_loaded_registry() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let _restore = EnvRestore::save(&[VRF_ACTIVATION_HEIGHT_ENV, VRF_KEYS_ENV]);

    let net = setup_net(4, 0x33, 10);
    let active = VrfActivation::FromHeight(ACTIVATION_H);
    assert!(active.is_active_at(ACTIVATION_H));

    // The LOADER-built registry (from the STELL_VRF_KEYS-shaped string) holds
    // the provisioned keys — this is the registry the verifier will use.
    assert_eq!(net.reg.len(), 4);
    for (i, id) in net.ids.iter().enumerate() {
        let expected = VrfSecret::from_seed(&net.vrf_seeds[i]).public_key().to_bytes();
        assert_eq!(net.reg.get(id), Some(expected));
    }
    // ...and the env loader parses the same string identically.
    std::env::set_var(VRF_KEYS_ENV, &net.keys_env);
    let env_reg = vrf_registry_from_env();
    assert_eq!(env_reg.len(), 4);
    assert_eq!(env_reg.get(&net.ids[0]), net.reg.get(&net.ids[0]));

    // Proposer: the provisioned seed is installed on the runtime exactly as
    // startup does (`with_vrf_secret_seed(derive_vrf_secret_seed(ed))`), and
    // the seal is minted where the secret lives.
    let state = Arc::new(InMemoryStateEngine::new());
    let proposer = ValidatorRuntime::new(
        SigningKey::from_bytes(&ed_seed(0x33, 0)),
        net.vs.clone(),
        state,
        1,
    )
    .with_vrf_activation(active)
    .with_vrf_secret_seed(net.vrf_seeds[0]);
    let seal = proposer
        .vrf_beacon_seal_for(ACTIVATION_H, ROUND, &net.parent)
        .expect("provisioned proposer must mint a seal");
    assert_eq!(seal.validator_id, net.ids[0]);
    let seed_input = sortition_seed(&net.parent, ACTIVATION_H, ROUND);
    assert_eq!(
        verify_vrf_seed_for_validator(&net.reg, &net.ids[0], &seed_input, &seal.proof),
        Some(seal.proof.output),
        "minted seal must verify under the loaded registry"
    );

    // Assembly embeds the seal; the verified output switches the seed.
    let set = vote_set_for(&net, ACTIVATION_H, ROUND);
    let qc = set
        .certificate_with_parent_vrf(
            net.block_hash,
            &net.vs,
            Some(&net.parent),
            &active,
            Some(&net.reg),
            Some(seal.clone()),
        )
        .expect("quorum present: certificate must form");
    let cert = qc.pq_micro_certificate().expect("µQC must be attached");
    assert_eq!(cert.vrf_beacon, Some(seal.clone()));
    assert_eq!(
        sortition_seed_gated(&net.parent, ACTIVATION_H, ROUND, &active, Some(&seal.proof.output)),
        vrf_election_seed(&seal.proof.output, ACTIVATION_H, ROUND)
    );

    // Explicit verify: verifier checks the seal and lands on the same
    // committee the proposer used.
    let msg = msg_for(ACTIVATION_H, ROUND, &net.block_hash);
    assert!(
        qc.verify_micro_cert_with_vrf(&cert, &net.vs, &msg, None, &active, Some(&net.reg)),
        "sealed certificate must verify against the loaded registry"
    );
    let expected = derive_sortition_committee_gated(
        &net.vs,
        ACTIVATION_H,
        ROUND,
        4,
        &net.parent,
        &active,
        Some(&seal.proof.output),
    );
    assert_eq!(
        qc.micro_cert_valid_signers_with_vrf(&cert, &net.vs, &msg, None, &active, Some(&net.reg)),
        Some(expected.clone()),
        "verifier must land on the proposer's committee"
    );

    // Live verify/attribution (the threaded path: env activation + the
    // startup-loaded global registry) agrees with the explicit path.
    std::env::set_var(VRF_ACTIVATION_HEIGHT_ENV, ACTIVATION_H.to_string());
    assert_eq!(vrf_activation_from_env(), active);
    set_live_vrf_registry(net.reg.clone());
    assert!(
        qc.verify_unified(&net.vs),
        "live verify must accept the sealed certificate at the armed height"
    );
    let live_signers: HashSet<[u8; 32]> = qc.signers_set(&net.vs).into_iter().collect();
    let expected_set: HashSet<[u8; 32]> = expected.into_iter().collect();
    assert_eq!(live_signers, expected_set, "live attribution must match");
}

// --- (d) default-off identity: byte-identical certs -------------------------

#[test]
fn default_off_identity_byte_identical_certs() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let _restore = EnvRestore::save(&[VRF_ACTIVATION_HEIGHT_ENV, VRF_KEYS_ENV]);

    // Env unset + no live registry: the shipped default-off configuration.
    std::env::remove_var(VRF_ACTIVATION_HEIGHT_ENV);
    std::env::remove_var(VRF_KEYS_ENV);
    clear_live_vrf_registry_for_tests();
    assert_eq!(vrf_activation_from_env(), VrfActivation::Disabled);
    assert!(vrf_registry_from_env().is_empty());

    let net = setup_net(4, 0x44, 10);
    let h = 9u64;
    let set = vote_set_for(&net, h, ROUND);
    let legacy_qc = set
        .certificate(net.block_hash, &net.vs, &net.parent)
        .expect("legacy certificate must form");
    let threaded_qc = set
        .certificate_with_parent_vrf(
            net.block_hash,
            &net.vs,
            Some(&net.parent),
            &VrfActivation::Disabled,
            None,
            None,
        )
        .expect("threaded certificate must form");
    assert_eq!(threaded_qc, legacy_qc, "default-off must be struct-identical");

    // Byte-compare the canonical envelopes (not just the structs).
    let legacy_cert = legacy_qc.pq_micro_certificate().expect("µQC attached");
    let threaded_cert = threaded_qc.pq_micro_certificate().expect("µQC attached");
    assert_eq!(legacy_cert.vrf_beacon, None);
    assert_eq!(
        encode_pq_micro_envelope(&threaded_cert),
        encode_pq_micro_envelope(&legacy_cert),
        "default-off canonical bytes must be legacy bytes"
    );

    // The threaded LIVE path (env unset, registry cleared) verifies legacy
    // and attributes the legacy committee — exactly like today.
    let msg = msg_for(h, ROUND, &net.block_hash);
    assert!(legacy_qc.verify_unified(&net.vs));
    let legacy_committee = derive_sortition_committee(&net.vs, h, ROUND, 4, &net.parent);
    let live_signers: HashSet<[u8; 32]> = legacy_qc.signers_set(&net.vs).into_iter().collect();
    assert_eq!(
        live_signers,
        legacy_committee.into_iter().collect::<HashSet<[u8; 32]>>()
    );
    // A valid seal for this height is IGNORED while the gate is Disabled
    // (the height gate, not proof presence, decides).
    let seed_input = sortition_seed(&net.parent, h, ROUND);
    let proof = vrf_prove(&VrfSecret::from_seed(&net.vrf_seeds[0]), &seed_input);
    let sealed = PqMicroCertificate::new(
        legacy_cert.scheme,
        legacy_cert.height,
        legacy_cert.round,
        legacy_cert.committee_size,
        legacy_cert.signers_bitmask.clone(),
        legacy_cert.signatures.clone(),
        legacy_cert.sortition_parent,
    )
    .with_vrf_beacon(VrfBeaconSeal::new(net.ids[0], proof));
    assert!(
        legacy_qc.verify_micro_cert_with_vrf(
            &sealed,
            &net.vs,
            &msg,
            None,
            &VrfActivation::Disabled,
            Some(&net.reg)
        ),
        "Disabled gate must ignore even a valid seal"
    );
}

// --- (e) seedless (remote-signer) runtime falls back, never seals -----------

#[test]
fn seedless_runtime_falls_back_to_legacy() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let _restore = EnvRestore::save(&[VRF_ACTIVATION_HEIGHT_ENV, VRF_KEYS_ENV]);

    let net = setup_net(4, 0x55, 10);
    let active = VrfActivation::FromHeight(ACTIVATION_H);

    // No seed installed (the remote-signer shape: no local VRF material) ⇒ no
    // seal even at an armed height — legacy fallback, never a bypass.
    let state = Arc::new(InMemoryStateEngine::new());
    let seedless = ValidatorRuntime::new(
        SigningKey::from_bytes(&ed_seed(0x55, 0)),
        net.vs.clone(),
        state,
        1,
    )
    .with_vrf_activation(active);
    assert_eq!(
        seedless.vrf_beacon_seal_for(ACTIVATION_H, ROUND, &net.parent),
        None,
        "seedless runtime must mint nothing"
    );

    // Assembly without a seal carries no seal; legacy verifies (explicit and
    // live paths agree).
    std::env::remove_var(VRF_ACTIVATION_HEIGHT_ENV);
    clear_live_vrf_registry_for_tests();
    let set = vote_set_for(&net, ACTIVATION_H, ROUND);
    let qc = set
        .certificate_with_parent_vrf(
            net.block_hash,
            &net.vs,
            Some(&net.parent),
            &active,
            Some(&net.reg),
            None,
        )
        .expect("must form");
    let cert = qc.pq_micro_certificate().expect("attached");
    assert_eq!(cert.vrf_beacon, None, "None seal embeds nothing");
    let msg = msg_for(ACTIVATION_H, ROUND, &net.block_hash);
    assert!(
        qc.verify_micro_cert_with_vrf(&cert, &net.vs, &msg, None, &active, Some(&net.reg)),
        "sealless assembly verifies under legacy"
    );
    assert!(qc.verify_unified(&net.vs), "live path verifies legacy too");
    let legacy_committee = derive_sortition_committee(&net.vs, ACTIVATION_H, ROUND, 4, &net.parent);
    assert_eq!(
        qc.micro_cert_valid_signers_with_vrf(&cert, &net.vs, &msg, None, &active, Some(&net.reg)),
        Some(legacy_committee.clone())
    );
}

// --- forged seal from a known key still REFUSES (no regression) --------------

#[test]
fn forged_seal_from_known_key_still_refuses() {
    let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let _restore = EnvRestore::save(&[VRF_ACTIVATION_HEIGHT_ENV, VRF_KEYS_ENV]);

    let net = setup_net(4, 0x66, 10);
    let active = VrfActivation::FromHeight(ACTIVATION_H);
    let h = ACTIVATION_H;
    let msg = msg_for(h, ROUND, &net.block_hash);

    let seed_input = sortition_seed(&net.parent, h, ROUND);
    let mut bad_proof = vrf_prove(&VrfSecret::from_seed(&net.vrf_seeds[0]), &seed_input);
    bad_proof.proof[7] ^= 0x01;
    let forged_seal = VrfBeaconSeal::new(net.ids[0], bad_proof);

    // Assembly never embeds an unverified seal (falls back to legacy bytes).
    let set = vote_set_for(&net, h, ROUND);
    let qc = set
        .certificate_with_parent_vrf(
            net.block_hash,
            &net.vs,
            Some(&net.parent),
            &active,
            Some(&net.reg),
            Some(forged_seal.clone()),
        )
        .expect("must form");
    assert_eq!(
        qc.pq_micro_certificate().expect("attached").vrf_beacon,
        None,
        "assembly must not embed a forged seal"
    );

    // A cert that (hypothetically) carries the forged seal REFUSES.
    let legacy_cert = qc.pq_micro_certificate().expect("attached");
    let forged_cert = PqMicroCertificate::new(
        legacy_cert.scheme,
        legacy_cert.height,
        legacy_cert.round,
        legacy_cert.committee_size,
        legacy_cert.signers_bitmask.clone(),
        legacy_cert.signatures.clone(),
        legacy_cert.sortition_parent,
    )
    .with_vrf_beacon(forged_seal);
    assert!(
        !qc.verify_micro_cert_with_vrf(
            &forged_cert,
            &net.vs,
            &msg,
            None,
            &active,
            Some(&net.reg)
        ),
        "forged proof bytes must refuse the whole certificate"
    );
    assert_eq!(
        qc.micro_cert_valid_signers_with_vrf(
            &forged_cert,
            &net.vs,
            &msg,
            None,
            &active,
            Some(&net.reg)
        ),
        None,
        "forged proof attributes nobody"
    );
}
