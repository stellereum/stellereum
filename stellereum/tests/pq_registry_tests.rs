//! On-chain PQ key registry tests: registration, delayed rotation, refusals,
//! history bound, staking-hook mirroring. Deterministic: fixed seeds and
//! explicit heights only — no wall-clock, no env, no filesystem, no shared
//! global state (safe under parallel test execution).

use ed25519_dalek::{Signer, SigningKey};
use stellereum::consensus::ValidatorId;
use stellereum::post_quantum::{
    FalconKeypair, PqScheme, ED25519_PUBKEY_LEN, FALCON512_PUBKEY_LEN, HYBRID_PUBKEY_LEN,
};
use stellereum::pq_registry::{
    verify_rotation_announcement, PqRegistry, PqRegistryError, PQ_KEY_HISTORY_LIMIT,
    PQ_MAX_KEY_BYTES, PQ_ROTATION_DELAY_HEIGHTS,
};
use stellereum::staking::{
    StakingLedger, COMMISSION_EFFECT_DELAY_HEIGHTS, MIN_VALIDATOR_BOND, STELL_MIN_BOND_BUFFER,
};

fn vid(n: u8) -> ValidatorId {
    [n; 32]
}

fn falcon_key(fill: u8) -> Vec<u8> {
    vec![fill; FALCON512_PUBKEY_LEN]
}

fn bonded_ledger(ids: &[ValidatorId]) -> StakingLedger {
    let mut l = StakingLedger::new();
    for id in ids {
        l.bond(*id, MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER, 0)
            .expect("test bond must succeed");
    }
    l
}

fn registered_pair(id: ValidatorId, key: &[u8], at: u64) -> (StakingLedger, PqRegistry) {
    let mut ledger = bonded_ledger(&[id]);
    let mut reg = PqRegistry::new();
    ledger
        .pq_register_key(&mut reg, id, PqScheme::Falcon512, key.to_vec(), at, at)
        .expect("test registration must succeed");
    (ledger, reg)
}

// ---- constants: rotation delay philosophy + bounds are pinned ----

#[test]
fn rotation_delay_matches_commission_exit_window_philosophy() {
    // The rotation delay is deliberately the SAME window as the commission
    // delegator-exit delay: observers get one full window to sync the
    // announcement before any key (or rate) changes authority.
    assert_eq!(PQ_ROTATION_DELAY_HEIGHTS, 7_200);
    assert_eq!(
        PQ_ROTATION_DELAY_HEIGHTS, COMMISSION_EFFECT_DELAY_HEIGHTS,
        "rotation and commission delays must move together (same exit-window philosophy)"
    );
    assert_eq!(PQ_KEY_HISTORY_LIMIT, 2);
    assert_eq!(PQ_MAX_KEY_BYTES, HYBRID_PUBKEY_LEN);
    assert_eq!(PQ_MAX_KEY_BYTES, 929);
}

// ---- registration happy path ----

#[test]
fn register_happy_path_tracks_key_and_mirrors_committed_map() {
    let id = vid(1);
    let key = falcon_key(0xA5);
    let (ledger, reg) = registered_pair(id, &key, 10);

    let rec = reg.record_of(&id).expect("record must exist");
    assert_eq!(rec.scheme, PqScheme::Falcon512);
    assert_eq!(rec.pubkey, key);
    assert_eq!(rec.activated_at, 10);
    assert!(rec.pending.is_none());
    assert!(rec.history.is_empty());

    // Height-gated read serves the key inside its window.
    assert_eq!(
        reg.get_active_key(&id, 10),
        Some((PqScheme::Falcon512, key.clone()))
    );
    assert_eq!(
        reg.get_active_key(&id, 999_999),
        Some((PqScheme::Falcon512, key.clone()))
    );
    // Before activation: fail-closed.
    assert_eq!(reg.get_active_key(&id, 9), None);
    // Unknown validator: fail-closed.
    assert_eq!(reg.get_active_key(&vid(2), 10), None);

    // Staking hook mirrors into the committed map existing readers use.
    assert_eq!(
        ledger.get_pq_key(&id),
        Some((PqScheme::Falcon512, key.clone()))
    );
    assert_eq!(
        ledger.pq_active_key(&reg, &id, 10),
        Some((PqScheme::Falcon512, key))
    );
    assert_eq!(ledger.pq_active_key(&reg, &vid(2), 10), None);
}

#[test]
fn register_accepts_real_falcon_key_bytes() {
    // Proves the registry size gates align with real key material (not just
    // synthetic fill vectors): deterministic seed, no randomness.
    let kp = FalconKeypair::generate_from_seed_bytes(&[0x77u8; 32]);
    assert_eq!(kp.public_key().len(), FALCON512_PUBKEY_LEN);
    let id = vid(3);
    let (_ledger, reg) = registered_pair(id, kp.public_key(), 0);
    assert_eq!(
        reg.current_key_of(&id),
        Some((PqScheme::Falcon512, kp.public_key().to_vec()))
    );
}

// ---- rotation: announce -> effective -> old-invalid ----

#[test]
fn rotation_announce_effective_then_old_invalid() {
    let id = vid(1);
    let old = falcon_key(0xA5);
    let new = falcon_key(0x5A);
    let (mut ledger, mut reg) = registered_pair(id, &old, 10);
    let stake_before = ledger.total_stake(&id);

    ledger
        .pq_announce_rotation(&mut reg, id, PqScheme::Falcon512, new.clone(), 100)
        .expect("announce must succeed");
    let pending = reg.pending_of(&id).expect("rotation must be pending");
    assert_eq!(pending.announced_height, 100);
    assert_eq!(pending.effective_height, 100 + PQ_ROTATION_DELAY_HEIGHTS); // 7300
    assert_eq!(pending.pubkey, new);

    // Old key stays authoritative until the effective height — including in
    // the committed mirror existing readers use.
    assert_eq!(
        reg.get_active_key(&id, 7_299),
        Some((PqScheme::Falcon512, old.clone()))
    );
    assert_eq!(
        ledger.get_pq_key(&id),
        Some((PqScheme::Falcon512, old.clone()))
    );
    // At the effective height the pending key resolves even BEFORE apply runs
    // (readers never depend on apply timing).
    assert_eq!(
        reg.get_active_key(&id, 7_300),
        Some((PqScheme::Falcon512, new.clone()))
    );

    // Late apply still stamps the ANNOUNCED effective height (deterministic
    // windows regardless of when apply lands).
    ledger
        .pq_apply_rotation(&mut reg, id, 8_000)
        .expect("late apply must succeed");
    let rec = reg.record_of(&id).expect("record must exist");
    assert_eq!(rec.activated_at, 7_300);
    assert!(rec.pending.is_none());
    assert_eq!(rec.history.len(), 1);
    assert_eq!(rec.history[0].pubkey, old);
    assert_eq!(rec.history[0].activated_at, 10);
    assert_eq!(rec.history[0].superseded_at, 7_300);

    // New key authoritative at/after effective; old serves only its window.
    assert_eq!(
        reg.get_active_key(&id, 7_300),
        Some((PqScheme::Falcon512, new.clone()))
    );
    assert_eq!(
        reg.get_active_key(&id, 50_000),
        Some((PqScheme::Falcon512, new.clone()))
    );
    assert_eq!(
        reg.get_active_key(&id, 5_000),
        Some((PqScheme::Falcon512, old.clone()))
    );
    // Committed mirror follows apply.
    assert_eq!(ledger.get_pq_key(&id), Some((PqScheme::Falcon512, new)));
    // Rotation moves no stake.
    assert_eq!(ledger.total_stake(&id), stake_before);
}

#[test]
fn sweep_applies_only_due_rotations_in_id_order() {
    let (a, b) = (vid(1), vid(2));
    let mut ledger = bonded_ledger(&[a, b]);
    let mut reg = PqRegistry::new();
    for (id, fill) in [(a, 0xA5), (b, 0xB6)] {
        ledger
            .pq_register_key(&mut reg, id, PqScheme::Falcon512, falcon_key(fill), 0, 0)
            .unwrap();
    }
    ledger
        .pq_announce_rotation(&mut reg, a, PqScheme::Falcon512, falcon_key(0x01), 0)
        .unwrap(); // effective 7200
    ledger
        .pq_announce_rotation(&mut reg, b, PqScheme::Falcon512, falcon_key(0x02), 100)
        .unwrap(); // effective 7300

    let applied = ledger.pq_apply_due_rotations(&mut reg, 7_250);
    assert_eq!(applied, vec![a]);
    assert_eq!(
        ledger.get_pq_key(&a),
        Some((PqScheme::Falcon512, falcon_key(0x01)))
    );
    assert!(reg.pending_of(&b).is_some(), "b not due yet");

    let applied = ledger.pq_apply_due_rotations(&mut reg, 7_300);
    assert_eq!(applied, vec![b]);
    assert!(reg.pending_of(&b).is_none());
}

// ---- refusals (fail-closed) ----

#[test]
fn refusals_unknown_double_pending_past_oversize_disabled_not_due() {
    let id = vid(1);
    let unknown = vid(9);
    let mut ledger = bonded_ledger(&[id]);
    let mut reg = PqRegistry::new();

    // Unknown validator (no bond) refused on every path, registry + hooks.
    assert_eq!(
        reg.register(unknown, PqScheme::Falcon512, falcon_key(1), 0, 0, false),
        Err(PqRegistryError::UnknownValidator)
    );
    assert_eq!(
        reg.announce_rotation(unknown, PqScheme::Falcon512, falcon_key(1), 0, false),
        Err(PqRegistryError::UnknownValidator)
    );
    assert_eq!(
        reg.apply_rotation(unknown, 0, false),
        Err(PqRegistryError::UnknownValidator)
    );
    assert_eq!(
        ledger.pq_register_key(&mut reg, unknown, PqScheme::Falcon512, falcon_key(1), 0, 0),
        Err(PqRegistryError::UnknownValidator)
    );
    assert_eq!(
        ledger.pq_announce_rotation(&mut reg, unknown, PqScheme::Falcon512, falcon_key(1), 0),
        Err(PqRegistryError::UnknownValidator)
    );
    assert_eq!(
        ledger.pq_apply_rotation(&mut reg, unknown, 0),
        Err(PqRegistryError::UnknownValidator)
    );
    assert_eq!(ledger.pq_active_key(&reg, &unknown, 0), None);

    // Activation in the past refused (history is append-only).
    assert_eq!(
        ledger.pq_register_key(&mut reg, id, PqScheme::Falcon512, falcon_key(1), 50, 100),
        Err(PqRegistryError::ActivationInPast)
    );

    // Oversized keys refused: over the hard cap AND wrong-size-for-scheme.
    assert_eq!(
        ledger.pq_register_key(
            &mut reg,
            id,
            PqScheme::Falcon512,
            vec![0u8; PQ_MAX_KEY_BYTES + 1],
            0,
            0
        ),
        Err(PqRegistryError::OversizedKey)
    );
    assert_eq!(
        ledger.pq_register_key(&mut reg, id, PqScheme::Falcon512, vec![0u8; 100], 0, 0),
        Err(PqRegistryError::OversizedKey)
    );

    // Disabled scheme (ML-DSA-44) refused even at its canonical size.
    assert_eq!(
        ledger.pq_register_key(&mut reg, id, PqScheme::MlDsa44, vec![0u8; 1312], 0, 0),
        Err(PqRegistryError::DisabledScheme)
    );
    // ... and Hybrid must be exactly 929 bytes.
    assert_eq!(
        ledger.pq_register_key(
            &mut reg,
            id,
            PqScheme::Hybrid,
            vec![0u8; FALCON512_PUBKEY_LEN],
            0,
            0
        ),
        Err(PqRegistryError::OversizedKey)
    );
    assert!(ledger
        .pq_register_key(
            &mut reg,
            id,
            PqScheme::Hybrid,
            vec![0u8; HYBRID_PUBKEY_LEN],
            0,
            0
        )
        .is_ok());

    // Double-pending refused.
    let id2 = vid(2);
    let mut ledger2 = bonded_ledger(&[id2]);
    let mut reg2 = PqRegistry::new();
    ledger2
        .pq_register_key(&mut reg2, id2, PqScheme::Falcon512, falcon_key(1), 0, 0)
        .unwrap();
    // Re-register refused: rotate, do not re-register.
    assert_eq!(
        ledger2.pq_register_key(&mut reg2, id2, PqScheme::Falcon512, falcon_key(2), 0, 0),
        Err(PqRegistryError::AlreadyRegistered)
    );
    ledger2
        .pq_announce_rotation(&mut reg2, id2, PqScheme::Falcon512, falcon_key(2), 0)
        .unwrap();
    assert_eq!(
        ledger2.pq_announce_rotation(&mut reg2, id2, PqScheme::Falcon512, falcon_key(3), 10),
        Err(PqRegistryError::RotationAlreadyPending)
    );

    // Apply before effective refused; apply with nothing pending refused.
    assert_eq!(
        ledger2.pq_apply_rotation(&mut reg2, id2, PQ_ROTATION_DELAY_HEIGHTS - 1),
        Err(PqRegistryError::RotationNotDue)
    );
    let id3 = vid(3);
    let mut ledger3 = bonded_ledger(&[id3]);
    let mut reg3 = PqRegistry::new();
    ledger3
        .pq_register_key(&mut reg3, id3, PqScheme::Falcon512, falcon_key(1), 0, 0)
        .unwrap();
    assert_eq!(
        ledger3.pq_apply_rotation(&mut reg3, id3, 1_000_000),
        Err(PqRegistryError::NoPendingRotation)
    );

    // Backdated announcement (now before the current key's activation) refused.
    let id4 = vid(4);
    let mut ledger4 = bonded_ledger(&[id4]);
    let mut reg4 = PqRegistry::new();
    ledger4
        .pq_register_key(&mut reg4, id4, PqScheme::Falcon512, falcon_key(1), 500, 500)
        .unwrap();
    assert_eq!(
        ledger4.pq_announce_rotation(&mut reg4, id4, PqScheme::Falcon512, falcon_key(2), 100),
        Err(PqRegistryError::ActivationInPast)
    );
}

#[test]
fn announcing_current_key_cancels_pending_rotation() {
    let id = vid(1);
    let cur = falcon_key(0xA5);
    let (mut ledger, mut reg) = registered_pair(id, &cur, 0);
    ledger
        .pq_announce_rotation(&mut reg, id, PqScheme::Falcon512, falcon_key(0x5A), 0)
        .unwrap();
    assert!(reg.pending_of(&id).is_some());
    // Re-asserting the current key drops the flight that never took effect.
    assert!(ledger
        .pq_announce_rotation(&mut reg, id, PqScheme::Falcon512, cur.clone(), 50)
        .is_ok());
    assert!(reg.pending_of(&id).is_none());
    assert_eq!(
        reg.get_active_key(&id, 7_200),
        Some((PqScheme::Falcon512, cur))
    );
}

// ---- bounded history ----

#[test]
fn history_is_bounded_oldest_evicted_first() {
    let id = vid(1);
    let (mut ledger, mut reg) = registered_pair(id, &falcon_key(0xA0), 0);
    // Three rotations: A -> B -> C -> D.
    for (i, fill) in [0xB0u8, 0xC0, 0xD0].iter().enumerate() {
        let at = (i as u64) * PQ_ROTATION_DELAY_HEIGHTS;
        ledger
            .pq_announce_rotation(&mut reg, id, PqScheme::Falcon512, falcon_key(*fill), at)
            .unwrap();
        ledger
            .pq_apply_rotation(&mut reg, id, at + PQ_ROTATION_DELAY_HEIGHTS)
            .unwrap();
    }
    let history = reg.history_of(&id).expect("history must exist");
    assert_eq!(history.len(), PQ_KEY_HISTORY_LIMIT);
    // Oldest (A, fill 0xA0) evicted; B and C retained oldest-first.
    assert_eq!(history[0].pubkey, falcon_key(0xB0));
    assert_eq!(history[0].activated_at, PQ_ROTATION_DELAY_HEIGHTS);
    assert_eq!(history[0].superseded_at, 2 * PQ_ROTATION_DELAY_HEIGHTS);
    assert_eq!(history[1].pubkey, falcon_key(0xC0));
    // Evicted windows no longer resolve (bounded: fail-closed past the bound).
    assert_eq!(reg.get_active_key(&id, 100), None);
    // Retained windows still verify late evidence.
    assert_eq!(
        reg.get_active_key(&id, PQ_ROTATION_DELAY_HEIGHTS + 10),
        Some((PqScheme::Falcon512, falcon_key(0xB0)))
    );
    assert_eq!(
        reg.get_active_key(&id, 2 * PQ_ROTATION_DELAY_HEIGHTS + 10),
        Some((PqScheme::Falcon512, falcon_key(0xC0)))
    );
    // Current (D) authoritative now.
    assert_eq!(
        reg.get_active_key(&id, 3 * PQ_ROTATION_DELAY_HEIGHTS),
        Some((PqScheme::Falcon512, falcon_key(0xD0)))
    );
}

// ---- legacy adoption + consensus-key rotation pairing ----

#[test]
fn announce_adopts_legacy_committed_key_without_changing_authority() {
    let id = vid(1);
    let legacy = falcon_key(0x77);
    let mut ledger = bonded_ledger(&[id]);
    // Pre-rotation immediate path (genesis/tests): no registry record.
    ledger
        .register_pq_key(id, PqScheme::Falcon512, legacy.clone())
        .unwrap();
    let mut reg = PqRegistry::new();
    assert!(reg.record_of(&id).is_none());

    let new = falcon_key(0x99);
    ledger
        .pq_announce_rotation(&mut reg, id, PqScheme::Falcon512, new.clone(), 1_000)
        .expect("announce must adopt the legacy key and stage the rotation");
    let rec = reg.record_of(&id).expect("adopted record must exist");
    assert_eq!(rec.activated_at, 0, "pre-tracking provenance");
    assert_eq!(rec.pubkey, legacy);
    // Authority untouched until effective: legacy serves everywhere below it.
    assert_eq!(
        reg.get_active_key(&id, 5),
        Some((PqScheme::Falcon512, legacy.clone()))
    );
    assert_eq!(
        reg.get_active_key(&id, 1_000 + PQ_ROTATION_DELAY_HEIGHTS - 1),
        Some((PqScheme::Falcon512, legacy))
    );
    assert_eq!(
        reg.get_active_key(&id, 1_000 + PQ_ROTATION_DELAY_HEIGHTS),
        Some((PqScheme::Falcon512, new))
    );
}

#[test]
fn announce_adopts_ed25519_fallback_for_keyless_validator() {
    let id = vid(1);
    let mut ledger = bonded_ledger(&[id]);
    let mut reg = PqRegistry::new();
    ledger
        .pq_announce_rotation(&mut reg, id, PqScheme::Falcon512, falcon_key(2), 0)
        .unwrap();
    let rec = reg.record_of(&id).expect("adopted record must exist");
    assert_eq!(rec.scheme, PqScheme::Ed25519);
    assert_eq!(rec.pubkey, id.to_vec());
    assert_eq!(rec.pubkey.len(), ED25519_PUBKEY_LEN);
}

#[test]
fn pq_record_travels_with_consensus_key_rotation() {
    // Documented pairing: `StakingLedger::rotate_key` moves the stake record
    // (signature frozen); the caller moves the PQ record alongside it.
    let (old, new) = (vid(1), vid(2));
    let key_a = falcon_key(0xA5);
    let key_b = falcon_key(0x5A);
    let (mut ledger, mut reg) = registered_pair(old, &key_a, 0);
    ledger
        .pq_announce_rotation(&mut reg, old, PqScheme::Falcon512, key_b.clone(), 0)
        .unwrap();

    ledger
        .rotate_key(old, new)
        .expect("consensus rotation must succeed");
    reg.migrate_validator(old, new)
        .expect("pq record must migrate");

    assert!(reg.record_of(&old).is_none());
    let rec = reg
        .record_of(&new)
        .expect("record must travel with the stake");
    assert_eq!(rec.pubkey, key_a);
    assert_eq!(rec.pending.as_ref().map(|p| p.pubkey.clone()), Some(key_b));
    // Reads follow membership: new id serves, dead id refuses.
    assert_eq!(
        ledger.pq_active_key(&reg, &new, 0),
        Some((PqScheme::Falcon512, key_a))
    );
    assert_eq!(ledger.pq_active_key(&reg, &old, 0), None);

    // Migration never merges: target with its own record refuses, source kept.
    let other = vid(3);
    let mut ledger2 = bonded_ledger(&[other, new]);
    let mut reg2 = PqRegistry::new();
    ledger2
        .pq_register_key(&mut reg2, other, PqScheme::Falcon512, falcon_key(9), 0, 0)
        .unwrap();
    ledger2
        .pq_register_key(&mut reg2, new, PqScheme::Falcon512, falcon_key(8), 0, 0)
        .unwrap();
    assert_eq!(
        reg2.migrate_validator(other, new),
        Err(PqRegistryError::AlreadyRegistered)
    );
    assert!(
        reg2.record_of(&other).is_some(),
        "failed migration loses nothing"
    );
    assert_eq!(
        reg2.migrate_validator(other, other),
        Err(PqRegistryError::AlreadyRegistered)
    );
}

// ---- validator-signed announcement helper ----

#[test]
fn rotation_announcement_signature_verifies_under_consensus_key() {
    use stellereum::pq_registry::pq_rotation_announcement_preimage;

    let sk = SigningKey::from_bytes(&[0x42u8; 32]);
    let id: [u8; 32] = sk.verifying_key().to_bytes();
    let key = falcon_key(0xA5);
    let eff = 7_300u64;
    let preimage = pq_rotation_announcement_preimage(&id, PqScheme::Falcon512, &key, eff);
    let sig = sk.sign(&preimage).to_bytes();

    assert!(verify_rotation_announcement(
        &id,
        PqScheme::Falcon512,
        &key,
        eff,
        &sig
    ));
    // Wrong consensus key refuses.
    let other = SigningKey::from_bytes(&[0x43u8; 32])
        .verifying_key()
        .to_bytes();
    assert!(!verify_rotation_announcement(
        &other,
        PqScheme::Falcon512,
        &key,
        eff,
        &sig
    ));
    // Tampered height refuses.
    assert!(!verify_rotation_announcement(
        &id,
        PqScheme::Falcon512,
        &key,
        eff + 1,
        &sig
    ));
    // Tampered key refuses.
    assert!(!verify_rotation_announcement(
        &id,
        PqScheme::Falcon512,
        &falcon_key(0x00),
        eff,
        &sig
    ));
    // Wrong-length signature refuses (never panics).
    assert!(!verify_rotation_announcement(
        &id,
        PqScheme::Falcon512,
        &key,
        eff,
        &[0u8; 10]
    ));
}

// ---- RPC visibility contract (rotation story) ----
// `stell_getPqKey` / `stell_getPqRegistryStatus` (rpc.rs) are thin read-only
// projections of THESE read APIs: `record_of` fields (scheme / pubkey /
// activated_at / pending) + `get_active_key` at the requested height for the
// served key + `len` for the status count. Pinned here at the registry level
// so a registry change that would alter an RPC answer fails here first.
// Local registries only (no shared global state — safe under parallel test
// execution).

#[test]
fn rpc_projection_inputs_scheme_key_window_and_pending() {
    let id = vid(0xE1);
    let old = falcon_key(0xA5);
    let new = falcon_key(0x5A);
    let (mut ledger, mut reg) = registered_pair(id, &old, 10);
    ledger
        .pq_announce_rotation(&mut reg, id, PqScheme::Falcon512, new.clone(), 100)
        .expect("announce must succeed");
    let eff = 100 + PQ_ROTATION_DELAY_HEIGHTS;

    // What `stell_getPqKey` projects around the served key.
    let rec = reg.record_of(&id).expect("record must exist");
    assert_eq!(rec.scheme.name(), "Falcon-512");
    assert_eq!(rec.scheme.id(), 2);
    assert_eq!(rec.pubkey, old);
    assert_eq!(rec.activated_at, 10);
    let pending = rec.pending.as_ref().expect("rotation must be pending");
    assert_eq!(pending.scheme, PqScheme::Falcon512);
    assert_eq!(pending.pubkey, new);
    assert_eq!(pending.announced_height, 100);
    assert_eq!(pending.effective_height, eff);

    // The served key itself is the height-indexed read, pre/post effective.
    assert_eq!(
        reg.get_active_key(&id, eff - 1),
        Some((PqScheme::Falcon512, old.clone()))
    );
    assert_eq!(
        reg.get_active_key(&id, eff),
        Some((PqScheme::Falcon512, new.clone()))
    );

    // Unknown validator serves nothing (the RPC errors, never fabricates).
    assert_eq!(reg.get_active_key(&vid(0xE2), eff), None);
    assert!(reg.record_of(&vid(0xE2)).is_none());
}

#[test]
fn rpc_status_count_inputs_len_semantics() {
    // What `stell_getPqRegistryStatus` reports as `count`.
    let mut reg = PqRegistry::new();
    assert!(reg.is_empty());
    assert_eq!(reg.len(), 0);
    let mut ledger = bonded_ledger(&[vid(1), vid(2)]);
    ledger
        .pq_register_key(&mut reg, vid(1), PqScheme::Falcon512, falcon_key(1), 0, 0)
        .expect("register must succeed");
    assert_eq!(reg.len(), 1);
    assert!(!reg.is_empty());
    ledger
        .pq_register_key(&mut reg, vid(2), PqScheme::Falcon512, falcon_key(2), 0, 0)
        .expect("register must succeed");
    assert_eq!(reg.len(), 2);
}
