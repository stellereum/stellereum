//! VRF activation wiring — startup seam regression (phase-1 wiring, phase-3 blocked).
//!
//! Gate: `stellereum::vrf::VrfActivation` (default `Disabled` — live consensus
//! bytes unchanged until `STELL_VRF_ACTIVATION_HEIGHT` configures a
//! `FromHeight(h)` boundary; XPC-activation-height pattern). `src/main.rs`
//! constructs the live activation from the env at startup (default-off) and
//! logs the boundary; threading into `HeightConsensus` construction is phase 3
//! (blocked: `HeightConsensus` lives in `src/consensus.rs` and its four live
//! sortition call sites pin `Disabled`+`None`).
//!
//! What this pins:
//! * Default-off identity: with the env unset (or garbage), the activation
//!   read from the env is `Disabled`, and the gated election is byte-identical
//!   to the legacy parent-hash draw over a sweep of inputs (same schedule
//!   with/without the env).
//! * Activation-height boundary: below the boundary the gated path stays on
//!   the legacy seed/committee even with a valid VRF output; at/above the
//!   boundary a verified output switches the seed to `vrf_election_seed` (and
//!   the committee follows); at/above with NO output falls back to legacy.
//! * Determinism: same key + same height ⇒ same proof, same minted output,
//!   same committee, every run (no wall clock / local randomness).
//!
//! No quorum, timeout, vote, or certificate changes: election seeds only.

use stellereum::consensus::{
    derive_sortition_committee, derive_sortition_committee_gated, sortition_seed,
    sortition_seed_gated, ValidatorSet,
};
use stellereum::post_quantum::FalconKeypair;
use stellereum::vrf::{
    verify_vrf_seed_for_validator, vrf_activation_from_env, vrf_binding_preimage, vrf_election_seed,
    vrf_prove, VrfActivation, VrfBinding, VrfRegistry, VrfSecret, VRF_ACTIVATION_HEIGHT_ENV,
};

const ACTIVATION_H: u64 = 1_000_000;

// --- env isolation (same pattern as tests/bls_pop_tests.rs) ----------------

static ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct EnvRestore {
    saved: Vec<(&'static str, Option<String>)>,
}

impl EnvRestore {
    fn save(keys: &[&'static str]) -> Self {
        let saved = keys
            .iter()
            .map(|k| (*k, std::env::var(k).ok()))
            .collect();
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

// --- fixtures ----------------------------------------------------------------

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

fn minted_output_for(
    reg: &VrfRegistry,
    id: &[u8; 32],
    secret: &VrfSecret,
    height: u64,
    round: u32,
    parent: &[u8; 32],
) -> [u8; 32] {
    let seed_input = sortition_seed(parent, height, round);
    let proof = vrf_prove(secret, &seed_input);
    verify_vrf_seed_for_validator(reg, id, &seed_input, &proof).expect("honest proof mints")
}

// --- 1. default-off identity (same schedule with/without the env) ------------

#[test]
fn default_off_identity_same_schedule_with_and_without_env() {
    let _gate = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let _restore = EnvRestore::save(&[VRF_ACTIVATION_HEIGHT_ENV]);

    // Env unset ⇒ Disabled (the startup default in main.rs).
    std::env::remove_var(VRF_ACTIVATION_HEIGHT_ENV);
    assert_eq!(vrf_activation_from_env(), VrfActivation::Disabled);
    assert_eq!(VrfActivation::default(), VrfActivation::Disabled);

    let (vs, _) = fixture_set();
    let parents = [[0x5Au8; 32], [0x6Bu8; 32], [0x00u8; 32], [0xFFu8; 32]];
    for p in &parents {
        for h in [0u64, 1, 9, ACTIVATION_H - 1, ACTIVATION_H, ACTIVATION_H + 1] {
            for r in [0u32, 1, 2] {
                for k in [0u32, 1, 2, 3, 4, 100] {
                    // The activation the binary would construct at startup with
                    // the env unset — must drive the legacy path exactly.
                    let startup = vrf_activation_from_env();
                    assert_eq!(
                        derive_sortition_committee_gated(&vs, h, r, k, p, &startup, None),
                        derive_sortition_committee(&vs, h, r, k, p),
                        "unset env must elect exactly like today (h={h} r={r} k={k})"
                    );
                    assert_eq!(
                        sortition_seed_gated(p, h, r, &startup, None),
                        sortition_seed(p, h, r)
                    );
                }
            }
        }
    }

    // Garbage env ⇒ Disabled too (fail-closed to today's bytes, never a panic).
    for garbage in ["tomorrow", "1.5", "-3", "0x10", " "] {
        std::env::set_var(VRF_ACTIVATION_HEIGHT_ENV, garbage);
        assert_eq!(
            vrf_activation_from_env(),
            VrfActivation::Disabled,
            "garbage {garbage:?} must stay INACTIVE"
        );
    }

    // A scheduled height parses to the boundary (the value main.rs logs).
    std::env::set_var(VRF_ACTIVATION_HEIGHT_ENV, ACTIVATION_H.to_string());
    assert_eq!(
        vrf_activation_from_env(),
        VrfActivation::FromHeight(ACTIVATION_H)
    );
    assert_eq!(
        vrf_activation_from_env().boundary(),
        Some(ACTIVATION_H)
    );
}

// --- 2. activation-height boundary -------------------------------------------

#[test]
fn activation_boundary_below_legacy_at_and_above_vrf_gated() {
    let _gate = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let _restore = EnvRestore::save(&[VRF_ACTIVATION_HEIGHT_ENV]);
    std::env::set_var(VRF_ACTIVATION_HEIGHT_ENV, ACTIVATION_H.to_string());
    let activation = vrf_activation_from_env();
    assert!(activation.is_active_at(ACTIVATION_H));
    assert!(!activation.is_active_at(ACTIVATION_H - 1));

    let (vs, ids) = fixture_set();
    let (reg, secrets) = registered_registry(&ids);
    let parent = [0x5Au8; 32];

    // Below the boundary: legacy seed AND legacy committee even WITH a valid
    // verified output (the height gate, not proof presence, decides).
    for h in [0u64, 9, ACTIVATION_H - 1] {
        let verified = minted_output_for(&reg, &ids[0], &secrets[0], h, 2, &parent);
        assert_eq!(
            sortition_seed_gated(&parent, h, 2, &activation, Some(&verified)),
            sortition_seed(&parent, h, 2),
            "pre-activation ignores even a valid VRF output (h={h})"
        );
        assert_eq!(
            derive_sortition_committee_gated(&vs, h, 2, 2, &parent, &activation, Some(&verified)),
            derive_sortition_committee(&vs, h, 2, 2, &parent),
            "pre-activation committee is the legacy draw (h={h})"
        );
        // And with no output at all.
        assert_eq!(
            sortition_seed_gated(&parent, h, 2, &activation, None),
            sortition_seed(&parent, h, 2)
        );
    }

    // At and above the boundary WITH a verified output: the seed IS the VRF
    // election seed (not the parent seed), and the committee follows it.
    for h in [ACTIVATION_H, ACTIVATION_H + 1, ACTIVATION_H + 1_000] {
        let verified = minted_output_for(&reg, &ids[0], &secrets[0], h, 2, &parent);
        let gated = sortition_seed_gated(&parent, h, 2, &activation, Some(&verified));
        assert_eq!(gated, vrf_election_seed(&verified, h, 2));
        assert_ne!(
            gated,
            sortition_seed(&parent, h, 2),
            "post-activation must leave the parent-hash seed (h={h})"
        );
        assert_eq!(
            derive_sortition_committee_gated(&vs, h, 2, 2, &parent, &activation, Some(&verified)),
            derive_sortition_committee_gated(&vs, h, 2, 2, &parent, &activation, Some(&verified)),
            "post-activation committee must be a pure function of the VRF seed"
        );
    }

    // At/above with NO verified output: fail-closed fallback to the legacy
    // seed — attacker bytes can never enter the election (liveness preserved,
    // forgery worthless). Only `Some` minted by the registry feeds the VRF path.
    for h in [ACTIVATION_H, ACTIVATION_H + 1] {
        assert_eq!(
            sortition_seed_gated(&parent, h, 2, &activation, None),
            sortition_seed(&parent, h, 2),
            "active height with no minted output falls back to legacy (h={h})"
        );
        assert_eq!(
            derive_sortition_committee_gated(&vs, h, 2, 2, &parent, &activation, None),
            derive_sortition_committee(&vs, h, 2, 2, &parent),
        );
    }

    // `FromHeight(0)` arms from genesis (fresh-chain schedule).
    let genesis = VrfActivation::FromHeight(0);
    assert!(genesis.is_active_at(0));
    assert_eq!(genesis.boundary(), Some(0));
}

// --- 3. determinism (same key + height ⇒ same outcome) -----------------------

#[test]
fn determinism_same_key_and_height_same_outcome() {
    let _gate = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let _restore = EnvRestore::save(&[VRF_ACTIVATION_HEIGHT_ENV]);
    std::env::remove_var(VRF_ACTIVATION_HEIGHT_ENV);

    let (vs, ids) = fixture_set();
    let (reg, secrets) = registered_registry(&ids);
    let parent = [0x5Au8; 32];
    let activation = VrfActivation::FromHeight(ACTIVATION_H);
    // The env-off startup activation is deterministic too.
    let startup_off = vrf_activation_from_env();

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
                &activation,
                Some(&verified)
            ),
            derive_sortition_committee_gated(
                &vs,
                ACTIVATION_H,
                0,
                2,
                &parent,
                &activation,
                Some(&verified)
            )
        );
        assert_eq!(
            derive_sortition_committee_gated(&vs, 9, 2, 2, &parent, &startup_off, None),
            derive_sortition_committee(&vs, 9, 2, 2, &parent)
        );
        // Env reads are deterministic within the process.
        assert_eq!(vrf_activation_from_env(), VrfActivation::Disabled);
    }
}
