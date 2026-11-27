//! W16 — live bridge deposits must resolve quorum keys AT the settlement
//! height, not at `attestation_height = 0`.
//!
//! Pre-fix, the `BridgeIntent::Deposit` arm of `BridgeState::plan_at_height`
//! called `TeleportBridgeEngine::process_deposit`, which verified through the
//! pre-V2 wrapper `verify_quorum_signatures` at height 0 with the legacy
//! consensus lookup. Consequences at/after the bridge V2 activation height:
//!
//! * a validator that ROTATED its committed PQ key was still checked against
//!   the key active at height 0, so a compromised rotated-out key could forge
//!   deposits;
//! * a legitimate attestation signed with the NEW key was rejected.
//!
//! These regressions drive the real settlement path (`plan_at_height`) with a
//! committed `PqRegistry` built in-process (no process-local key map for the
//! V2 assertions), plus the legacy `process_deposit` wrapper it must preserve.

use std::sync::Mutex;

use stellereum::bridge::{
    set_bridge_v2_activation_override, BridgeEffect, BridgeIntent, BridgePlan, BridgeState,
    PqKeyLookup, PreV2ConsensusLookup, SupportedChain, TeleportBridgeEngine,
};
use stellereum::consensus::{clear_validator_pq_keys_for_tests, sync_committed_pq_registry};
use stellereum::post_quantum::{FalconKeypair, PqScheme};
use stellereum::pq_registry::{PqRegistry, PQ_ROTATION_DELAY_HEIGHTS};

const NOW: u64 = 1_760_000_000;
const CHAIN_ID: u64 = 7;
const STELL: u64 = 1_000_000_000;
const PAYER: [u8; 32] = [0x03u8; 32];
const RECIPIENT: [u8; 32] = [0xADu8; 32];

/// Process-wide PQ registry + verified-vote cache are shared across tests in
/// this binary; serialize the tests that touch them and restore clean state.
static GLOBAL_LOCK: Mutex<()> = Mutex::new(());

struct BridgeGate;

impl BridgeGate {
    fn at(height: u64) -> Self {
        set_bridge_v2_activation_override(Some(height));
        Self
    }
}

impl Drop for BridgeGate {
    fn drop(&mut self) {
        set_bridge_v2_activation_override(None);
    }
}

/// Installs the fixture registry as the process-wide legacy/committed lookup
/// (what `PreV2ConsensusLookup` reads), and clears it on drop.
struct GlobalPqState;

impl GlobalPqState {
    fn install(registry: &PqRegistry) -> Self {
        sync_committed_pq_registry(registry, true);
        Self
    }
}

impl Drop for GlobalPqState {
    fn drop(&mut self) {
        sync_committed_pq_registry(&PqRegistry::new(), true);
        clear_validator_pq_keys_for_tests();
    }
}

/// Two deterministic validators with keys A and B committed at height 0.
struct Fixture {
    ids: Vec<[u8; 32]>,
    keys: Vec<FalconKeypair>,
    registry: PqRegistry,
}

impl Fixture {
    fn new() -> Self {
        let ids = vec![[0x11u8; 32], [0x22u8; 32]];
        let keys = vec![
            FalconKeypair::generate_from_seed_bytes(&[0xA1u8; 32]),
            FalconKeypair::generate_from_seed_bytes(&[0xB2u8; 32]),
        ];
        let mut registry = PqRegistry::new();
        for (id, key) in ids.iter().zip(keys.iter()) {
            registry
                .register(*id, PqScheme::Falcon512, key.public_key.clone(), 0, 0, true)
                .expect("fixture key registration");
        }
        Self {
            ids,
            keys,
            registry,
        }
    }

    fn dep(&self, hash_byte: u8, amount: u64) -> BridgeIntent {
        BridgeIntent::Deposit {
            chain: SupportedChain::Ton,
            source_tx_hash: [hash_byte; 32],
            recipient: RECIPIENT,
            amount: amount.saturating_mul(STELL),
        }
    }
}

fn sign_deposit(dep: &BridgeIntent, signers: &[([u8; 32], &FalconKeypair)]) -> BridgeIntent {
    let event = dep.deposit_event(Vec::new()).expect("deposit event");
    let msg = TeleportBridgeEngine::deposit_signing_message(&event);
    let signatures = signers
        .iter()
        .map(|(id, key)| (*id, key.sign(&msg)))
        .collect();
    let source_tx_hash = match dep {
        BridgeIntent::Deposit { source_tx_hash, .. } => *source_tx_hash,
        other => panic!("attest only pairs with a Deposit: {other:?}"),
    };
    BridgeIntent::Attest {
        source_tx_hash,
        signatures,
    }
}

fn plan_at(
    intents: &[BridgeIntent],
    ids: &[[u8; 32]],
    height: u64,
    lookup: &dyn PqKeyLookup,
) -> Result<BridgePlan, String> {
    BridgeState::default().plan_at_height(intents, ids, PAYER, NOW, height, CHAIN_ID, lookup)
}

/// Control: an honest two-of-two attestation signed by the CURRENT committed
/// keys is accepted at a V2-active height.
#[test]
fn honest_deposit_verifies_with_keys_active_at_height() {
    let _lock = GLOBAL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _gate = BridgeGate::at(0);
    let fx = Fixture::new();
    let _global = GlobalPqState::install(&fx.registry);

    let height = 50_000u64;
    assert!(
        stellereum::bridge::bridge_v2_active_at(height),
        "precondition: the height must be V2-active"
    );

    let dep = fx.dep(0x01, 10);
    let att = sign_deposit(&dep, &[(fx.ids[0], &fx.keys[0]), (fx.ids[1], &fx.keys[1])]);
    let plan = plan_at(&[att, dep], &fx.ids, height, &fx.registry)
        .expect("both current keys must reach quorum at `height`");

    assert_eq!(
        plan.effects,
        vec![BridgeEffect::Credit {
            recipient: RECIPIENT,
            amount: 10 * STELL,
        }]
    );
}

/// THE DEFECT: after validator 1 rotates its committed PQ key, an attestation
/// signed by the ROTATED-OUT key must be rejected at the effective height,
/// while the NEW key must be accepted. Pre-fix both verdicts are inverted
/// (height-0 verification accepts the old key and rejects the new one).
#[test]
fn rotated_out_key_cannot_forge_deposit_and_new_key_is_accepted_at_height() {
    let _lock = GLOBAL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _gate = BridgeGate::at(0);
    let mut fx = Fixture::new();

    let announce_height = 1_000u64;
    let effective = announce_height.saturating_add(PQ_ROTATION_DELAY_HEIGHTS);
    let new_key = FalconKeypair::generate_from_seed_bytes(&[0xC3u8; 32]);

    fx.registry
        .announce_rotation(
            fx.ids[0],
            PqScheme::Falcon512,
            new_key.public_key.clone(),
            announce_height,
            true,
        )
        .expect("rotation announcement");
    assert_eq!(
        fx.registry
            .pending_of(&fx.ids[0])
            .map(|p| p.effective_height),
        Some(effective),
        "precondition: the rotation is due at `effective`"
    );
    fx.registry
        .apply_rotation(fx.ids[0], effective, true)
        .expect("rotation applies at its effective height");
    assert_eq!(
        fx.registry.get_active_key(&fx.ids[0], effective),
        Some((PqScheme::Falcon512, new_key.public_key.clone())),
        "precondition: the committed key at `effective` is the NEW key"
    );

    // Pre-fix, `process_deposit` verified at height 0 through this same
    // process-wide registry, where the OLD key is still authoritative.
    let _global = GlobalPqState::install(&fx.registry);

    // OLD key at the rotation height: must NOT count (compromised key gone).
    let old_dep = fx.dep(0x11, 10);
    let old_att = sign_deposit(
        &old_dep,
        &[(fx.ids[0], &fx.keys[0]), (fx.ids[1], &fx.keys[1])],
    );
    let old_err = plan_at(&[old_att, old_dep], &fx.ids, effective, &fx.registry)
        .expect_err("a rotated-out key must not authorize a deposit at `effective`");
    assert!(
        old_err.contains("quorum not reached"),
        "refusal must be sub-quorum, got: {old_err}"
    );

    // NEW key at the rotation height: must verify.
    let new_dep = fx.dep(0x12, 10);
    let new_att = sign_deposit(&new_dep, &[(fx.ids[0], &new_key), (fx.ids[1], &fx.keys[1])]);
    let plan = plan_at(&[new_att, new_dep], &fx.ids, effective, &fx.registry)
        .expect("the new committed key must authorize a deposit at `effective`");
    assert_eq!(
        plan.effects,
        vec![BridgeEffect::Credit {
            recipient: RECIPIENT,
            amount: 10 * STELL,
        }]
    );
}

/// Thin-wrapper parity: `process_deposit(ev)` and
/// `process_deposit_at_height(ev, 0, &PreV2ConsensusLookup)` must agree on
/// verdicts and state transitions for valid, sub-quorum and duplicate inputs.
#[test]
fn process_deposit_is_the_height_zero_legacy_wrapper() {
    let _lock = GLOBAL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _gate = BridgeGate::at(0);
    let fx = Fixture::new();
    let _global = GlobalPqState::install(&fx.registry);

    let dep = fx.dep(0x21, 10);
    let valid_att = sign_deposit(&dep, &[(fx.ids[0], &fx.keys[0]), (fx.ids[1], &fx.keys[1])]);
    let valid_event = match valid_att {
        BridgeIntent::Attest { signatures, .. } => dep.deposit_event(signatures),
        other => panic!("expected Attest, got {other:?}"),
    }
    .expect("valid deposit event");

    let mut wrapper_engine = TeleportBridgeEngine::new(fx.ids.clone());
    let mut generic_engine = TeleportBridgeEngine::new(fx.ids.clone());
    let wrapper_first = wrapper_engine.process_deposit(&valid_event);
    let generic_first =
        generic_engine.process_deposit_at_height(&valid_event, 0, &PreV2ConsensusLookup);
    assert_eq!(
        wrapper_first, generic_first,
        "the legacy wrapper must be exactly the height-0 PreV2 entry point"
    );
    assert_eq!(wrapper_first, Ok(10 * STELL));

    // Replay: both engines reject the duplicate identically.
    let wrapper_second = wrapper_engine.process_deposit(&valid_event);
    let generic_second =
        generic_engine.process_deposit_at_height(&valid_event, 0, &PreV2ConsensusLookup);
    assert_eq!(wrapper_second, generic_second);
    assert!(wrapper_second.is_err(), "duplicate source tx must fail");

    // Sub-quorum: one signature on each fresh engine, same refusal.
    let one_att = sign_deposit(&dep, &[(fx.ids[0], &fx.keys[0])]);
    let one_event = match one_att {
        BridgeIntent::Attest { signatures, .. } => dep.deposit_event(signatures),
        other => panic!("expected Attest, got {other:?}"),
    }
    .expect("sub-quorum deposit event");
    let mut wrapper_engine = TeleportBridgeEngine::new(fx.ids.clone());
    let mut generic_engine = TeleportBridgeEngine::new(fx.ids.clone());
    assert_eq!(
        wrapper_engine.process_deposit(&one_event),
        generic_engine.process_deposit_at_height(&one_event, 0, &PreV2ConsensusLookup)
    );
}

/// Below `bridge_v2_active_at` the deposit arm still uses the legacy
/// `PreV2ConsensusLookup`, so a pre-v7 replay verdict is unchanged even if a
/// caller passes a committed height-indexed registry.
#[test]
fn pre_v7_replay_keeps_legacy_verdicts_below_bridge_activation() {
    let _lock = GLOBAL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _gate = BridgeGate::at(u64::MAX);
    let fx = Fixture::new();
    let _global = GlobalPqState::install(&fx.registry);

    let height = 42u64;
    assert!(
        !stellereum::bridge::bridge_v2_active_at(height),
        "precondition: the bridge V2 gate is off at this height"
    );

    let dep = fx.dep(0x31, 10);
    let att = sign_deposit(&dep, &[(fx.ids[0], &fx.keys[0]), (fx.ids[1], &fx.keys[1])]);
    let legacy = plan_at(&[att.clone(), dep.clone()], &fx.ids, height, &fx.registry)
        .expect("pre-v7 replay accepts the legacy attestation");

    // The legacy `plan()` wrapper pins height 0 + PreV2; same verdict/effect.
    let pinned = BridgeState::default()
        .plan(&[att.clone(), dep.clone()], &fx.ids, PAYER, NOW)
        .expect("legacy plan wrapper accepts the same attestation");
    assert_eq!(legacy.effects, pinned.effects);

    // A V2-active height would select the caller's lookup; below activation it
    // must be ignored, so an EMPTY committed registry cannot change the verdict.
    let empty_registry = PqRegistry::new();
    let verdict = plan_at(&[att, dep], &fx.ids, height, &empty_registry)
        .expect("below activation the committed candidate lookup is ignored");
    assert_eq!(verdict.effects, legacy.effects);
}

/// The legacy `process_deposit` keeps its historical height-0 behaviour even
/// after a rotation: the OLD key still verifies there, the NEW key does not.
/// This is the compatibility guarantee the live path must not disturb.
#[test]
fn legacy_process_deposit_keeps_height_zero_behaviour_after_rotation() {
    let _lock = GLOBAL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _gate = BridgeGate::at(0);
    let mut fx = Fixture::new();

    let announce_height = 1_000u64;
    let effective = announce_height.saturating_add(PQ_ROTATION_DELAY_HEIGHTS);
    let new_key = FalconKeypair::generate_from_seed_bytes(&[0xD4u8; 32]);
    fx.registry
        .announce_rotation(
            fx.ids[0],
            PqScheme::Falcon512,
            new_key.public_key.clone(),
            announce_height,
            true,
        )
        .expect("rotation announcement");
    fx.registry
        .apply_rotation(fx.ids[0], effective, true)
        .expect("rotation applies");
    let _global = GlobalPqState::install(&fx.registry);

    let old_dep = fx.dep(0x41, 10);
    let old_att = sign_deposit(
        &old_dep,
        &[(fx.ids[0], &fx.keys[0]), (fx.ids[1], &fx.keys[1])],
    );
    let old_event = match old_att {
        BridgeIntent::Attest { signatures, .. } => old_dep.deposit_event(signatures),
        other => panic!("expected Attest, got {other:?}"),
    }
    .expect("old-key deposit event");

    let new_dep = fx.dep(0x42, 10);
    let new_att = sign_deposit(&new_dep, &[(fx.ids[0], &new_key), (fx.ids[1], &fx.keys[1])]);
    let new_event = match new_att {
        BridgeIntent::Attest { signatures, .. } => new_dep.deposit_event(signatures),
        other => panic!("expected Attest, got {other:?}"),
    }
    .expect("new-key deposit event");

    // Historical height-0 verdicts: old key authoritative, new key not.
    let mut engine = TeleportBridgeEngine::new(fx.ids.clone());
    assert_eq!(
        engine.process_deposit(&old_event),
        Ok(10 * STELL),
        "legacy process_deposit must keep verifying at height 0"
    );
    let mut engine = TeleportBridgeEngine::new(fx.ids.clone());
    assert!(
        engine.process_deposit(&new_event).is_err(),
        "legacy process_deposit must keep refusing the not-yet-active key at height 0"
    );

    // And the thin wrapper agrees byte-for-byte with the explicit height-0 call.
    let mut wrapper_engine = TeleportBridgeEngine::new(fx.ids.clone());
    let mut generic_engine = TeleportBridgeEngine::new(fx.ids.clone());
    assert_eq!(
        wrapper_engine.process_deposit(&old_event),
        generic_engine.process_deposit_at_height(&old_event, 0, &PreV2ConsensusLookup),
    );
}
