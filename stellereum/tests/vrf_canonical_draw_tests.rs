//! Canonical-draw pin: the parent-hash draw is THE sortition mechanism.
//!
//! Election math is untouched; sortition takes only the parent hash,
//! height, round, and stake. Fixed vectors pin the canonical bytes.
//!
//! No quorum, lock, timeout, vote, or certificate changes: seeds/committees only.

use stellereum::consensus::{derive_sortition_committee, sortition_seed, ValidatorSet};
use stellereum::post_quantum::set_pure_pq_override;

// Canonical fixed vectors:
// 4 validators ids [01;32..04;32], power 10 each, committee size 2,
// parent [0x5A;32], height 9, round 2.
const PIN_SEED_PARENT_9_2: &str =
    "5e0914d250fd5ad600f4944a7df56bf6094b52ccac2e9999cc85de4d1ced82fb";
const PIN_COMM_PRE_0: &str =
    "0202020202020202020202020202020202020202020202020202020202020202";
const PIN_COMM_PRE_1: &str =
    "0404040404040404040404040404040404040404040404040404040404040404";

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

#[test]
fn canonical_draw_pins_vectors() {
    set_pure_pq_override(Some(true));
    assert!(stellereum::post_quantum::is_pure_pq_enforced());
    let (vs, _ids) = fixture_set();
    let parent = [0x5Au8; 32];
    assert_eq!(sortition_seed(&parent, 9, 2), h32(PIN_SEED_PARENT_9_2));
    assert_eq!(
        derive_sortition_committee(&vs, 9, 2, 2, &parent),
        vec![h32(PIN_COMM_PRE_0), h32(PIN_COMM_PRE_1)]
    );
    set_pure_pq_override(None);
}

#[test]
fn canonical_draw_consumed_on_pq_path() {
    set_pure_pq_override(Some(true));
    assert!(stellereum::post_quantum::is_pure_pq_enforced());
    let (vs, _ids) = fixture_set();
    let parent = [0x5Au8; 32];
    assert_eq!(sortition_seed(&parent, 9, 2), h32(PIN_SEED_PARENT_9_2));
    assert_eq!(
        derive_sortition_committee(&vs, 9, 2, 2, &parent),
        vec![h32(PIN_COMM_PRE_0), h32(PIN_COMM_PRE_1)]
    );

    // Sweep: the canonical draw is deterministic across parents/heights/rounds.
    let parents = [[0x5Au8; 32], [0x6Bu8; 32], [0x00u8; 32], [0xFFu8; 32]];
    for p in &parents {
        for h in [0u64, 1, 9, 999_999, 1_000_000, 1_000_001] {
            for r in [0u32, 1, 2] {
                for k in [0u32, 1, 2, 3, 4, 100] {
                    assert_eq!(
                        derive_sortition_committee(&vs, h, r, k, p),
                        derive_sortition_committee(&vs, h, r, k, p),
                        "canonical draw must be deterministic (h={h} r={r} k={k})"
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
    set_pure_pq_override(None);
}
