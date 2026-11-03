//! Canonical-draw pin: the parent-hash draw is THE sortition mechanism.
//!
//! Lead decision: `STELL_VRF_ACTIVATION_HEIGHT` arming is retired (setting it
//! warns loudly and is ignored — `vrf_activation_from_env` always returns
//! `Disabled`), the ECVRF prove/verify bodies are removed (classical, off),
//! and election math is untouched.
//!
//! What this pins (read-only against the draw — no caller rewiring):
//! * Retired flag: any configured `STELL_VRF_ACTIVATION_HEIGHT` value (a valid
//!   height, garbage, whitespace) reads `Disabled` with no panic; the
//!   boundary is `None` and no height is active.
//! * Canonical draw: on the PQ-enforced path (`set_pure_pq_override(Some(true))`)
//!   with the VRF registry present-but-off (populated, Falcon-bound) and
//!   dummy output bytes offered to the gate, the gated draw is
//!   byte-identical to the legacy parent-hash draw — no output is ever
//!   consulted (nothing can mint one: prove/verify are removed). Fixed
//!   vectors pin the canonical bytes.
//!
//! No quorum, lock, timeout, vote, or certificate changes: seeds/committees only.

use stellereum::consensus::{
    derive_sortition_committee, derive_sortition_committee_gated, sortition_seed,
    sortition_seed_gated, ValidatorSet,
};
use stellereum::post_quantum::{set_pure_pq_override, FalconKeypair};
use stellereum::vrf::{
    vrf_activation_from_env, vrf_binding_preimage, VrfActivation, VrfBinding, VrfRegistry, VrfSecret,
    VRF_ACTIVATION_HEIGHT_ENV, VRF_IS_POST_QUANTUM,
};

// Canonical fixed vectors (same bytes as the pre-gate path pins):
// 4 validators ids [01;32..04;32], power 10 each, committee size 2,
// parent [0x5A;32], height 9, round 2.
const PIN_SEED_PARENT_9_2: &str =
    "5e0914d250fd5ad600f4944a7df56bf6094b52ccac2e9999cc85de4d1ced82fb";
const PIN_COMM_PRE_0: &str =
    "0202020202020202020202020202020202020202020202020202020202020202";
const PIN_COMM_PRE_1: &str =
    "0404040404040404040404040404040404040404040404040404040404040404";

static ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
        set_pure_pq_override(None);
    }
}

fn h32(s: &str) -> [u8; 32] {
    hex::decode(s)
        .expect("pin must be hex")
        .as_slice()
        .try_into()
        .expect("pin must be 32 bytes")
}

fn fixture_set() -> (ValidatorSet, Vec<[u8; 32]>) {
    let ids: Vec<[u8; 32]> = (1u8..=4).map(|i| [i; 32]).collect();
    let vs = ValidatorSet::from_list(ids.iter().map(|id| (*id, 10)).collect());
    (vs, ids)
}

/// VRF registry present: every validator holds a Falcon-bound registered key —
///
/// yet the gate stays OFF (no activation), and nothing can mint outputs
/// (prove/verify removed), so only inert dummy bytes are ever offered.
fn present_but_off_registry(ids: &[[u8; 32]]) -> VrfRegistry {
    let mut reg = VrfRegistry::new();
    for (i, id) in ids.iter().enumerate() {
        let falcon_seed = [(i as u8).wrapping_add(0x70); 32];
        let falcon = FalconKeypair::generate_from_seed_bytes(&falcon_seed);
        let vrf_sk = VrfSecret::from_seed(&[(i as u8).wrapping_add(0x42); 32]);
        let vrf_pk = vrf_sk.public_key().to_bytes();
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
    }
    reg
}

#[test]
fn retired_activation_flag_is_ignored_with_loud_warn() {
    let _gate = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let _restore = EnvRestore::save(&[VRF_ACTIVATION_HEIGHT_ENV]);

    // Unset / empty: silent Disabled (the shipped default).
    std::env::remove_var(VRF_ACTIVATION_HEIGHT_ENV);
    assert_eq!(vrf_activation_from_env(), VrfActivation::Disabled);
    std::env::set_var(VRF_ACTIVATION_HEIGHT_ENV, "   ");
    assert_eq!(vrf_activation_from_env(), VrfActivation::Disabled);

    // Set (valid height, zero, garbage): RETIRED — loud WARN on stderr, still
    // Disabled, no boundary, no active height, never a panic.
    for configured in ["1000000", "0", "500", "tomorrow", "1.5", "-3", "0x10"] {
        std::env::set_var(VRF_ACTIVATION_HEIGHT_ENV, configured);
        let activation = vrf_activation_from_env();
        assert_eq!(
            activation,
            VrfActivation::Disabled,
            "configured {configured:?} must stay INACTIVE (retired)"
        );
        assert_eq!(activation.boundary(), None);
        for h in [0u64, 1, 9, 999_999, 1_000_000, 1_000_001, u64::MAX] {
            assert!(
                !activation.is_active_at(h),
                "retired flag must arm no height (h={h})"
            );
        }
    }
    assert_eq!(VrfActivation::default(), VrfActivation::Disabled);

    // The retired shape still compiles for old configs: FromHeight constructs
    // and reports its boundary (nothing live arms it from the environment).
    assert_eq!(
        VrfActivation::FromHeight(1_000_000).boundary(),
        Some(1_000_000)
    );
}

#[test]
fn canonical_draw_consumed_on_pq_path_vrf_output_never_read() {
    let _gate = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let _restore = EnvRestore::save(&[VRF_ACTIVATION_HEIGHT_ENV]);

    // PQ enforcement ON, VRF module present-but-off: the startup activation the
    // binary constructs (env set, as a stale deployment would) is Disabled.
    set_pure_pq_override(Some(true));
    assert!(stellereum::post_quantum::is_pure_pq_enforced());
    assert!(
        !std::hint::black_box(VRF_IS_POST_QUANTUM),
        "ECVRF stays marked classical: no PQ-path consumption"
    );
    std::env::set_var(VRF_ACTIVATION_HEIGHT_ENV, "1000000");
    let startup = vrf_activation_from_env();
    assert_eq!(startup, VrfActivation::Disabled);

    let (vs, ids) = fixture_set();
    let reg = present_but_off_registry(&ids);
    assert_eq!(reg.len(), 4);

    // Canonical bytes pinned: the parent-hash seed and committee for the
    // fixture are exactly the pre-gate vectors.
    let parent = [0x5Au8; 32];
    assert_eq!(sortition_seed(&parent, 9, 2), h32(PIN_SEED_PARENT_9_2));
    assert_eq!(
        derive_sortition_committee(&vs, 9, 2, 2, &parent),
        vec![h32(PIN_COMM_PRE_0), h32(PIN_COMM_PRE_1)]
    );

    // Sweep: every gated draw with inert dummy output bytes offered equals
    // the parent-hash draw — no output is ever read while the gate is
    // Disabled (nothing live can mint a verified output: prove/verify are
    // removed, so the bytes below stand in for "whatever a caller offers").
    let parents = [[0x5Au8; 32], [0x6Bu8; 32], [0x00u8; 32], [0xFFu8; 32]];
    for p in &parents {
        for h in [0u64, 1, 9, 999_999, 1_000_000, 1_000_001] {
            for r in [0u32, 1, 2] {
                let verified = [0xABu8; 32];
                assert_eq!(
                    sortition_seed_gated(p, h, r, &startup, Some(&verified)),
                    sortition_seed(p, h, r),
                    "Disabled gate must not read the offered output (h={h} r={r})"
                );
                for k in [0u32, 1, 2, 3, 4, 100] {
                    assert_eq!(
                        derive_sortition_committee_gated(&vs, h, r, k, p, &startup, Some(&verified)),
                        derive_sortition_committee(&vs, h, r, k, p),
                        "PQ-enforced run elects the parent-hash committee (h={h} r={r} k={k})"
                    );
                }
            }
        }
    }

    // A new parent still re-draws the seed: parent hash is the only entropy.
    assert_ne!(
        sortition_seed(&parent, 9, 2),
        sortition_seed(&[0x6Bu8; 32], 9, 2)
    );
}
