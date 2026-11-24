//! Wave 4 engine-hardening regressions.
//!
//! Pins the five audit fixes whose behaviour is reachable from the public API:
//!  * S1-FALCON-CACHE-THRASH  — junk tx pubkeys may never wipe the whole
//!    Falcon pubkey cache, and pinned consensus keys survive a key flood.
//!  * S1-STATEROOT-CONCURRENT-STALE — concurrent root reads converge on the
//!    digest of the CURRENT committed state (a stale fold is never published).
//!  * S2-WASMI-UNBOUNDED-TABLE-OOM — the height-gated WASM table-elements cap
//!    is inert by default (byte-identical legacy acceptance) and enforces at
//!    the activation height.
//!  * S1-SAFETY-LEGACY-VALUEID-FALLBACK — a legacy `vote_watermark` prevote
//!    whose block body is missing fail-closes (quarantine) instead of
//!    fabricating `value_id == block_hash`.
//!  * the `wasm-table-elements-cap` row exists in the gate manifest, INERT and
//!    without a proving test.
//!
//! The walk-path fixes (S1-WALK-SAFETY-QUARANTINE / S1-WALK-SCHEDULE-RESET)
//! need the private `walk_chain_once_with_lanes` harness and live in
//! `src/node/sync.rs`'s `recovery_walk_tests` module.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use stellereum::contract::{ContractRegistry, MAX_CONTRACT_TABLE_ELEMENTS};
use stellereum::post_quantum::{
    pin_falcon_pubkey, verify_pq_signature, FalconKeypair, PqScheme, FALCON512_SIG_LEN,
};
use stellereum::safety::{
    derive_safety_chain_id, AuthorityMode, SafetyAuthority, SafetyBootContext,
};
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};
use stellereum::state_engine::InMemoryStateEngine;
use stellereum::storage::{SafetyRecordIdentity, Storage, VoteWatermark, VoteWatermarkEntry};

// ---------------------------------------------------------------------------
// S1-FALCON-CACHE-THRASH
// ---------------------------------------------------------------------------

#[test]
fn falcon_consensus_pubkey_survives_a_junk_pubkey_flood() {
    // A consensus validator key is explicitly pinned (the hook consensus key
    // registration should use).
    let consensus = FalconKeypair::generate_from_seed(0x42);
    assert!(
        pin_falcon_pubkey(consensus.pubkey()),
        "a canonical Falcon public key must pin"
    );
    assert!(!pin_falcon_pubkey(&[0u8; 8]), "malformed keys never pin");

    // Junk transaction pubkeys still reach the cache (the decode runs before
    // the signature check), which is exactly what used to wipe it wholesale.
    for seed in 0..64u8 {
        let junk = FalconKeypair::generate_from_seed(seed);
        let mut sig = vec![0u8; FALCON512_SIG_LEN];
        sig[0] = 0x29; // valid framing, garbage body -> decode, then refuse
        assert!(
            !verify_pq_signature(PqScheme::Falcon512, junk.pubkey(), b"junk", &sig),
            "a garbage signature must be refused"
        );
    }

    // The pinned consensus key still verifies and the cache stayed bounded
    // (LRU tier + pinned tier), never cleared.
    let msg = b"consensus vote";
    let sig = consensus.sign(msg);
    assert!(
        verify_pq_signature(PqScheme::Falcon512, consensus.pubkey(), msg, &sig),
        "the pinned consensus key must still verify after the flood"
    );
    let len = stellereum::post_quantum::falcon_pubkey_cache_len();
    assert!(len >= 1, "the cache was cleared wholesale");
    assert!(
        len <= 4096 + 1024,
        "the Falcon pubkey cache must stay bounded, got {len}"
    );
}

// ---------------------------------------------------------------------------
// S1-STATEROOT-CONCURRENT-STALE
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_root_reads_converge_on_the_current_commitment() {
    let engine = Arc::new(InMemoryStateEngine::new());

    // Readers race writers, one round at a time. Every round mutates a
    // committed domain (EVM bindings) while a root read is in flight.
    let mut readers = Vec::new();
    for i in 0..32u8 {
        let reader_engine = Arc::clone(&engine);
        readers.push(tokio::spawn(
            async move { reader_engine.get_state_root().await },
        ));
        engine
            .evm_bindings_write()
            .await
            .bind([i; 20], [i.wrapping_add(1); 32])
            .expect("distinct bindings must not conflict");
    }
    for reader in readers {
        reader.await.expect("root read task");
    }

    // Reference engine that applied the same mutations sequentially.
    let reference = InMemoryStateEngine::new();
    for i in 0..32u8 {
        reference
            .evm_bindings_write()
            .await
            .bind([i; 20], [i.wrapping_add(1); 32])
            .expect("distinct bindings must not conflict");
    }
    let expected = reference.get_state_root().await;

    assert_eq!(
        engine.get_state_root().await,
        expected,
        "the trie must hold the digest of the CURRENT committed state; a stale \
         concurrent fold must never win the write race"
    );
}

// ---------------------------------------------------------------------------
// S2-WASMI-UNBOUNDED-TABLE-OOM
// ---------------------------------------------------------------------------

#[test]
fn wasm_table_elements_cap_is_inert_below_activation_and_enforced_above() {
    use stellereum::chain_spec;

    assert_eq!(MAX_CONTRACT_TABLE_ELEMENTS, 16_384);
    assert_eq!(chain_spec::WASM_TABLE_ELEMENTS_CAP_HEIGHT, u64::MAX);

    // Inert means disabled at EVERY reachable height (u64::MAX included).
    for height in [0u64, 1, 1_000, 253_000, 10_000_000, u64::MAX - 1, u64::MAX] {
        assert!(
            !chain_spec::wasm_table_elements_cap_active_at(height),
            "the compiled default gate must never fire (height {height})"
        );
    }

    let at_cap = wat::parse_str(r#"(module (table 16384 funcref))"#).unwrap();
    let over_cap = wat::parse_str(r#"(module (table 16385 funcref))"#).unwrap();
    let over_cap_max = wat::parse_str(r#"(module (table 0 16385 funcref))"#).unwrap();

    // (a) Legacy / Ruleset v7 acceptance is BYTE-IDENTICAL: the default entry
    // points and the gated wrappers below activation accept the oversized
    // table exactly as before.
    assert!(ContractRegistry::validate_code(&over_cap).is_ok());
    assert!(ContractRegistry::validate_code_with_table_cap(&over_cap, false).is_ok());
    assert!(ContractRegistry::validate_code_at(&over_cap, 1).is_ok());
    assert!(ContractRegistry::validate_code_at(&over_cap_max, 1).is_ok());

    // (b) Section-4 (`Table`) validation and the wasmi StoreLimits budget do
    // enforce the cap when it is on.
    assert_eq!(
        ContractRegistry::validate_code_with_table_cap(&over_cap, true),
        Err(stellereum::contract::ContractError::InvalidWasm)
    );
    assert_eq!(
        ContractRegistry::validate_code_with_table_cap(&over_cap_max, true),
        Err(stellereum::contract::ContractError::InvalidWasm)
    );
    assert!(ContractRegistry::validate_code_with_table_cap(&at_cap, true).is_ok());
    assert!(
        ContractRegistry::validate_code_hardened_with_table_cap(&over_cap, 1_000_000, true)
            .is_err()
    );

    // (c) Height gating: below the gate the walk path is unchanged; at/above it
    // the same code refuses. The test override keeps the frozen constant
    // untouched.
    let gate = 100u64;
    chain_spec::set_wasm_table_elements_cap_override(Some(gate));
    assert!(!chain_spec::wasm_table_elements_cap_active_at(gate - 1));
    assert!(chain_spec::wasm_table_elements_cap_active_at(gate));
    assert!(ContractRegistry::validate_code_at(&over_cap, gate - 1).is_ok());
    assert_eq!(
        ContractRegistry::validate_code_at(&over_cap, gate),
        Err(stellereum::contract::ContractError::InvalidWasm)
    );
    assert!(ContractRegistry::validate_code_at(&at_cap, gate).is_ok());
    chain_spec::set_wasm_table_elements_cap_override(None);
    assert!(ContractRegistry::validate_code_at(&over_cap, u64::MAX).is_ok());
}

#[test]
fn wasm_table_elements_cap_gate_row_is_inert() {
    let gates = stellereum::feature_gates::table();
    let gate = gates
        .iter()
        .find(|g| g.id == "wasm-table-elements-cap")
        .expect("wasm-table-elements-cap must be in the gate manifest");
    assert_eq!(gate.symbol, "WASM_TABLE_ELEMENTS_CAP_HEIGHT");
    assert_eq!(gate.value, u64::MAX);
    assert_eq!(gate.status(), "INERT");
    assert!(
        gate.test.is_none(),
        "an inert gate must not claim a proving test"
    );
}

// ---------------------------------------------------------------------------
// S1-SAFETY-LEGACY-VALUEID-FALLBACK
// ---------------------------------------------------------------------------

static NEXT_DIR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

struct TestDir(std::path::PathBuf);

impl TestDir {
    fn new(tag: &str) -> Self {
        let id = NEXT_DIR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("stell-w4-engine-{tag}-{}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn legacy_block(height: u64, tag: u8) -> Block {
    Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash: [0u8; 32],
        state_root: [tag; 32],
        timestamp: 1_700_000_000 + height,
        // A later-round proposal: `value_id` is the round-free identity, so it
        // is DISTINCT from `compute_hash()` here — which is exactly why
        // fabricating `value_id == block_hash` is unsafe.
        round: 1,
        ..Default::default()
    }
}

fn identity_for(validator: [u8; 32], genesis_root: [u8; 32]) -> SafetyRecordIdentity {
    SafetyRecordIdentity {
        validator,
        chain: derive_safety_chain_id(stellereum::consensus::consensus_chain_id(), &genesis_root),
        shard: MASTERCHAIN_SHARD,
    }
}

fn init_clean_genesis_storage(dir: &TestDir, genesis_root: [u8; 32]) -> Arc<Storage> {
    let storage = Arc::new(Storage::open(&dir.0).expect("open storage"));
    storage
        .set_meta("genesis_state_root", &genesis_root)
        .expect("set genesis_state_root");
    storage
}

fn clean_genesis_boot_ctx() -> SafetyBootContext {
    SafetyBootContext {
        is_validator: true,
        is_observer_env: false,
        new_chain_explicit: true,
        restored_finalized: None,
        restored_state_height: Some(0),
        restored_finalized_qc_verified: false,
        legacy_checkpoint: None,
        legacy_watermark: None,
    }
}

/// A legacy `vote_watermark` prevote at the safety record's own height with a
/// target block that is NOT in storage must fail closed (quarantine) instead
/// of fabricating `value_id == block_hash`; with the body present the value_id
/// is resolved from the real block.
#[test]
fn legacy_watermark_prevote_missing_body_quarantines_instead_of_fabricating_value_id() {
    let key = SigningKey::from_bytes(&[0x71; 32]);
    let validator = key.verifying_key().to_bytes();
    let genesis_root = [0x5Au8; 32];
    let identity = identity_for(validator, genesis_root);

    // The record's payload starts at height 1 / finalized 0 (clean genesis).
    let missing_target = [0xABu8; 32];

    // (a) Body missing -> quarantine (fail closed).
    {
        let dir = TestDir::new("legacy-missing");
        let storage = init_clean_genesis_storage(&dir, genesis_root);
        let auth = SafetyAuthority::open_from_storage(
            storage.clone(),
            identity.clone(),
            clean_genesis_boot_ctx(),
        );
        assert_eq!(
            auth.mode(),
            AuthorityMode::Active,
            "clean genesis initializes"
        );

        let mut wm = VoteWatermark::default();
        wm.note(VoteWatermarkEntry {
            height: 1,
            round: 3,
            kind: 0,
            target: Some(missing_target),
            shard_id: MASTERCHAIN_SHARD,
        });
        let ctx = SafetyBootContext {
            new_chain_explicit: false,
            legacy_watermark: Some(wm),
            ..clean_genesis_boot_ctx()
        };
        let auth = SafetyAuthority::open_from_storage(storage, identity.clone(), ctx);
        match auth.mode() {
            AuthorityMode::Quarantined(reason) => assert!(
                reason.contains("missing from storage"),
                "unexpected quarantine reason: {reason}"
            ),
            other => panic!("a missing prevote body must quarantine, got {other:?}"),
        }
        assert!(!auth.can_sign());
    }

    // (b) Body present -> the REAL value_id is resolved, never `block_hash`.
    {
        let dir = TestDir::new("legacy-present");
        let storage = init_clean_genesis_storage(&dir, genesis_root);
        let auth = SafetyAuthority::open_from_storage(
            storage.clone(),
            identity.clone(),
            clean_genesis_boot_ctx(),
        );
        assert_eq!(auth.mode(), AuthorityMode::Active);

        let block = legacy_block(1, 0x77);
        let block_hash = block.compute_hash();
        assert_ne!(
            block.value_id(),
            block_hash,
            "fixture must exercise a distinct value_id"
        );
        storage
            .put_block(&block)
            .expect("persist prevote target body");

        let mut wm = VoteWatermark::default();
        wm.note(VoteWatermarkEntry {
            height: 1,
            round: 3,
            kind: 0,
            target: Some(block_hash),
            shard_id: MASTERCHAIN_SHARD,
        });
        let ctx = SafetyBootContext {
            new_chain_explicit: false,
            legacy_watermark: Some(wm),
            ..clean_genesis_boot_ctx()
        };
        let auth = SafetyAuthority::open_from_storage(storage, identity, ctx);
        assert_eq!(auth.mode(), AuthorityMode::Active);
        let payload = auth.current_state().expect("active payload");
        assert_eq!(payload.highest_prevote_round, Some(3));
        let last = payload
            .last_non_nil_prevote
            .expect("non-nil legacy prevote recorded");
        assert_eq!(last.block_hash, block_hash);
        assert_eq!(
            last.value_id,
            block.value_id(),
            "the resolved value_id must come from the block body, not be fabricated"
        );
    }
}
