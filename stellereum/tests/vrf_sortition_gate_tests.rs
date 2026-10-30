//! VRF sortition height gate — phase-1 wiring regression.
//!
//! Gate: `stellereum::vrf::VrfActivation` (default `Disabled` — live
//! consensus bytes unchanged until `STELL_VRF_ACTIVATION_HEIGHT` configures a
//! `FromHeight(h)` boundary; XPC-activation-height pattern).
//!
//! * Pre-activation output is byte-identical to today (pinned fixed vectors).
//! * Post-activation the seed is the registry-verified VRF output.
//! * Unverified proofs refuse (no verified output is ever minted).
//! * Determinism: repeated runs agree (no wall clock / local randomness).
//!
//! No quorum, timeout, or vote changes: this file touches election seeds only.

use stellereum::consensus::{
    derive_sortition_committee, derive_sortition_committee_gated, sortition_seed,
    sortition_seed_gated, ValidatorSet,
};
use stellereum::post_quantum::FalconKeypair;
use stellereum::vrf::{
    verify_vrf_seed_for_validator, vrf_binding_preimage, vrf_election_seed, vrf_prove, VrfActivation,
    VrfBinding, VrfRegistry, VrfSecret,
};

// --- pinned fixed vectors (captured from the pre-gate code path) ----------------
// Fixture: 4 validators ids [01;32..04;32], power 10 each, committee size 2,
// parent [0x5A;32], height 9, round 2.
const PIN_SEED_PARENT_9_2: &str =
    "5e0914d250fd5ad600f4944a7df56bf6094b52ccac2e9999cc85de4d1ced82fb";
const PIN_COMM_PRE_0: &str =
    "0202020202020202020202020202020202020202020202020202020202020202";
const PIN_COMM_PRE_1: &str =
    "0404040404040404040404040404040404040404040404040404040404040404";
// VRF output of secret [0x42;32] over the seed above; election seed and
// committee at the activation boundary (height 1_000_000, round 2).
const PIN_VRF_OUTPUT: &str =
    "0359c092aa6f3b3a232c1d8c2d67e13113891dc21e8b242dcc1e76aece72c00a";
const PIN_ELECTION_SEED_H1M: &str =
    "bdd392b1f3a62762e511617e2d75d5ac55e16a00fcd68a056181f021526531c4";
const PIN_COMM_POST_0: &str =
    "0202020202020202020202020202020202020202020202020202020202020202";
const PIN_COMM_POST_1: &str =
    "0303030303030303030303030303030303030303030303030303030303030303";

const ACTIVATION_H: u64 = 1_000_000;

fn h32(s: &str) -> [u8; 32] {
    let v = hex::decode(s).expect("pin must be hex");
    v.as_slice().try_into().expect("pin must be 32 bytes")
}

fn fixture_set() -> (ValidatorSet, Vec<[u8; 32]>) {
    let ids: Vec<[u8; 32]> = (1u8..=4).map(|i| [i; 32]).collect();
    let vs = ValidatorSet::from_list(ids.iter().map(|id| (*id, 10)).collect());
    (vs, ids)
}

/// Every validator gets a Falcon-bound, registered VRF key (deterministic —
/// no OS randomness, no wall clock).
fn registered_registry(ids: &[[u8; 32]]) -> (VrfRegistry, Vec<VrfSecret>) {
    let mut reg = VrfRegistry::new();
    let mut secrets = Vec::new();
    for (i, id) in ids.iter().enumerate() {
        let falcon_seed = [(i as u8).wrapping_add(0x70); 32];
        let falcon = FalconKeypair::generate_from_seed_bytes(&falcon_seed);
        let sk = VrfSecret::from_seed(&[(i as u8).wrapping_add(0x42); 32]);
        let vrf_pk = sk.public_key().to_bytes();
        let sig = falcon.sign(&vrf_binding_preimage(id, &vrf_pk));
        reg.register(
            &VrfBinding {
                validator_id: *id,
                vrf_pk,
                falcon_sig: sig,
            },
            falcon.public_key(),
        )
        .expect("honest binding registers");
        secrets.push(sk);
    }
    (reg, secrets)
}

#[test]
fn pre_activation_output_byte_identical_to_today() {
    // The gate defaults OFF.
    assert_eq!(VrfActivation::default(), VrfActivation::Disabled);
    assert_eq!(VrfActivation::Disabled.boundary(), None);

    let (vs, _) = fixture_set();
    let parent = [0x5Au8; 32];

    // Fixed vectors pinned from the pre-gate path.
    assert_eq!(sortition_seed(&parent, 9, 2), h32(PIN_SEED_PARENT_9_2));
    assert_eq!(
        derive_sortition_committee(&vs, 9, 2, 2, &parent),
        vec![h32(PIN_COMM_PRE_0), h32(PIN_COMM_PRE_1)]
    );

    // Gated-with-Disabled agrees with legacy over a sweep of inputs.
    let parents = [[0x5Au8; 32], [0x6Bu8; 32], [0x00u8; 32], [0xFFu8; 32]];
    for p in &parents {
        for h in [0u64, 1, 9, ACTIVATION_H - 1, ACTIVATION_H, ACTIVATION_H + 1] {
            for r in [0u32, 1, 2] {
                for k in [0u32, 1, 2, 3, 4, 100] {
                    assert_eq!(
                        derive_sortition_committee_gated(
                            &vs,
                            h,
                            r,
                            k,
                            p,
                            &VrfActivation::Disabled,
                            None
                        ),
                        derive_sortition_committee(&vs, h, r, k, p),
                        "Disabled gate must be byte-identical (h={h} r={r} k={k})"
                    );
                    assert_eq!(
                        sortition_seed_gated(p, h, r, &VrfActivation::Disabled, None),
                        sortition_seed(p, h, r)
                    );
                }
            }
        }
    }

    // Configured-but-pre-activation heights stay on the parent path — even
    // when a valid VRF output is offered (the height gate, not proof
    // presence, decides).
    let active = VrfActivation::FromHeight(ACTIVATION_H);
    let (_, ids) = fixture_set();
    let (reg, secrets) = registered_registry(&ids);
    for h in [0u64, 9, ACTIVATION_H - 1] {
        let seed_input = sortition_seed(&parent, h, 2);
        let proof = vrf_prove(&secrets[0], &seed_input);
        let verified =
            verify_vrf_seed_for_validator(&reg, &ids[0], &seed_input, &proof).expect("mints");
        assert_eq!(
            sortition_seed_gated(&parent, h, 2, &active, Some(&verified)),
            sortition_seed(&parent, h, 2),
            "pre-activation ignores even a valid VRF output (h={h})"
        );
        assert_eq!(
            derive_sortition_committee_gated(&vs, h, 2, 2, &parent, &active, Some(&verified)),
            derive_sortition_committee(&vs, h, 2, 2, &parent)
        );
        // And with no output at all.
        assert_eq!(
            sortition_seed_gated(&parent, h, 2, &active, None),
            sortition_seed(&parent, h, 2)
        );
    }
}

#[test]
fn post_activation_uses_vrf_seed() {
    let (vs, ids) = fixture_set();
    let (reg, secrets) = registered_registry(&ids);
    let parent = [0x5Au8; 32];
    let active = VrfActivation::FromHeight(ACTIVATION_H);
    assert!(active.is_active_at(ACTIVATION_H));

    // The VRF signs the height/round seed input (same bytes on every node).
    let seed_input = sortition_seed(&parent, ACTIVATION_H, 2);
    let proof = vrf_prove(&secrets[0], &seed_input);
    assert_eq!(proof.output, h32(PIN_VRF_OUTPUT));
    let verified =
        verify_vrf_seed_for_validator(&reg, &ids[0], &seed_input, &proof).expect("mints");

    // The gated seed IS the VRF election seed (pinned), NOT the parent seed.
    let gated = sortition_seed_gated(&parent, ACTIVATION_H, 2, &active, Some(&verified));
    assert_eq!(gated, h32(PIN_ELECTION_SEED_H1M));
    assert_eq!(gated, vrf_election_seed(&verified, ACTIVATION_H, 2));
    assert_ne!(
        gated,
        sortition_seed(&parent, ACTIVATION_H, 2),
        "post-activation must leave the parent-hash seed"
    );

    // The committee follows the VRF seed (pinned, and different from the
    // pre-activation committee for this fixture).
    let committee = derive_sortition_committee_gated(
        &vs,
        ACTIVATION_H,
        2,
        2,
        &parent,
        &active,
        Some(&verified),
    );
    assert_eq!(committee, vec![h32(PIN_COMM_POST_0), h32(PIN_COMM_POST_1)]);
    assert_ne!(
        committee,
        derive_sortition_committee(&vs, ACTIVATION_H, 2, 2, &parent),
        "post-activation committee must not equal the parent-hash draw here"
    );

    // Height binding: neighbouring heights draw distinct seeds.
    let next = sortition_seed_gated(&parent, ACTIVATION_H + 1, 2, &active, Some(&verified));
    assert_ne!(gated, next);
}

#[test]
fn unverified_vrf_proof_refuses() {
    let (_, ids) = fixture_set();
    let (reg, secrets) = registered_registry(&ids);
    let parent = [0x5Au8; 32];
    let active = VrfActivation::FromHeight(ACTIVATION_H);
    let seed_input = sortition_seed(&parent, ACTIVATION_H, 2);
    let proof = vrf_prove(&secrets[0], &seed_input);

    // Unknown validator (never registered) mints nothing.
    assert_eq!(
        verify_vrf_seed_for_validator(&reg, &[0x22u8; 32], &seed_input, &proof),
        None,
        "unregistered id refuses"
    );
    // Tampered proof bytes refuse.
    let mut bad = proof.clone();
    bad.proof[7] ^= 0x01;
    assert_eq!(
        verify_vrf_seed_for_validator(&reg, &ids[0], &seed_input, &bad),
        None,
        "forged proof refuses"
    );
    // Swapped output refuses (output bound to proof bytes).
    let mut bad_out = proof.clone();
    bad_out.output[3] ^= 0x40;
    assert_eq!(
        verify_vrf_seed_for_validator(&reg, &ids[0], &seed_input, &bad_out),
        None,
        "substituted output refuses"
    );
    // Proof for another seed input refuses.
    assert_eq!(
        verify_vrf_seed_for_validator(&reg, &ids[0], &[0x99u8; 32], &proof),
        None,
        "wrong seed input refuses"
    );
    // Proof by a foreign secret under a registered id refuses.
    let foreign = vrf_prove(&VrfSecret::from_seed(&[0xEEu8; 32]), &seed_input);
    assert_eq!(
        verify_vrf_seed_for_validator(&reg, &ids[0], &seed_input, &foreign),
        None,
        "foreign secret refuses under an honest id"
    );

    // Without a minted output, an ACTIVE height falls back to the parent
    // seed — attacker bytes never enter the election (liveness preserved,
    // forgery worthless). Only `Some` minted above may feed the VRF path.
    assert_eq!(
        sortition_seed_gated(&parent, ACTIVATION_H, 2, &active, None),
        sortition_seed(&parent, ACTIVATION_H, 2)
    );
}

#[test]
fn determinism_across_repeated_runs() {
    let (vs, ids) = fixture_set();
    let (reg, secrets) = registered_registry(&ids);
    let parent = [0x5Au8; 32];
    let active = VrfActivation::FromHeight(ACTIVATION_H);

    for _ in 0..25 {
        // Proving is pure: identical bytes every run.
        let a = vrf_prove(&secrets[1], &sortition_seed(&parent, ACTIVATION_H, 0));
        let b = vrf_prove(&secrets[1], &sortition_seed(&parent, ACTIVATION_H, 0));
        assert_eq!(a, b);

        // Registry-bound verification mints the same output every run.
        let seed_input = sortition_seed(&parent, ACTIVATION_H, 0);
        let proof = vrf_prove(&secrets[1], &seed_input);
        let first = verify_vrf_seed_for_validator(&reg, &ids[1], &seed_input, &proof);
        let second = verify_vrf_seed_for_validator(&reg, &ids[1], &seed_input, &proof);
        assert_eq!(first, second);
        let verified = first.expect("mints");

        // Both election paths are pure functions of their inputs.
        assert_eq!(
            derive_sortition_committee_gated(
                &vs,
                ACTIVATION_H,
                0,
                2,
                &parent,
                &active,
                Some(&verified)
            ),
            derive_sortition_committee_gated(
                &vs,
                ACTIVATION_H,
                0,
                2,
                &parent,
                &active,
                Some(&verified)
            )
        );
        assert_eq!(
            derive_sortition_committee(&vs, 9, 2, 2, &parent),
            vec![h32(PIN_COMM_PRE_0), h32(PIN_COMM_PRE_1)]
        );
    }
}
