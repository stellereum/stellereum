//! Workchain boot-guard tests (fail-closed text + hatch only).
//!
//! Pins [`stellereum::sharding::check_workchain_boot_guard`]: the default
//! single-shard `{0}` registry boots unchanged, any other registry
//! (`STELL_SHARDS != {0}`) refuses with an error naming the freeze doc
//! (`docs/PUBLIC_TESTNET_CODE_GAPS.md §1`) unless the local soak/test hatch
//! `STELL_EXPERIMENTAL_SHARDS=1` is set.

use stellereum::sharding::{
    check_workchain_boot_guard, check_workchain_boot_guard_with_hatch, ShardRegistry,
    EXPERIMENTAL_SHARDS_ENV, SHARD_REGISTRY_ENV, WORKCHAIN_FREEZE_DOC,
};
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn lock_env() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn save_env() -> (Option<String>, Option<String>) {
    (
        std::env::var(SHARD_REGISTRY_ENV).ok(),
        std::env::var(EXPERIMENTAL_SHARDS_ENV).ok(),
    )
}

fn restore_env(saved: (Option<String>, Option<String>)) {
    match saved.0 {
        Some(v) => std::env::set_var(SHARD_REGISTRY_ENV, v),
        None => std::env::remove_var(SHARD_REGISTRY_ENV),
    }
    match saved.1 {
        Some(v) => std::env::set_var(EXPERIMENTAL_SHARDS_ENV, v),
        None => std::env::remove_var(EXPERIMENTAL_SHARDS_ENV),
    }
}

#[test]
fn default_single_registry_boots_unchanged() {
    let _g = lock_env();
    let saved = save_env();
    std::env::remove_var(SHARD_REGISTRY_ENV);
    std::env::remove_var(EXPERIMENTAL_SHARDS_ENV);
    let registry = ShardRegistry::from_env_or(0);
    assert_eq!(registry, ShardRegistry::single());
    assert!(check_workchain_boot_guard(&registry).is_ok());
    restore_env(saved);
}

#[test]
fn multishard_without_hatch_refuses_naming_freeze() {
    let _g = lock_env();
    let saved = save_env();
    std::env::set_var(SHARD_REGISTRY_ENV, "0,1");
    std::env::remove_var(EXPERIMENTAL_SHARDS_ENV);
    let registry = ShardRegistry::from_env_or(0);
    assert!(registry.is_sharded());
    let err = check_workchain_boot_guard(&registry).expect_err("must refuse multishard boot");
    assert!(
        err.contains(WORKCHAIN_FREEZE_DOC),
        "error must name the freeze doc: {err}"
    );
    assert!(err.contains("STELL_SHARDS"), "error must name STELL_SHARDS: {err}");
    assert!(
        err.contains(EXPERIMENTAL_SHARDS_ENV),
        "error must document the hatch: {err}"
    );
    restore_env(saved);
}

#[test]
fn multishard_with_hatch_boots() {
    let _g = lock_env();
    let saved = save_env();
    std::env::set_var(SHARD_REGISTRY_ENV, "0,1");
    std::env::set_var(EXPERIMENTAL_SHARDS_ENV, "1");
    let registry = ShardRegistry::from_env_or(0);
    assert!(registry.is_sharded());
    assert!(check_workchain_boot_guard(&registry).is_ok());
    restore_env(saved);
}

#[test]
fn noncanonical_single_shard_without_hatch_refuses() {
    // `STELL_SHARDS != {0}` is the refusal condition: even a lone workchain
    // `{1}` is not the canonical registry.
    let registry = ShardRegistry::from_ids([1]);
    let err = check_workchain_boot_guard_with_hatch(&registry, false)
        .expect_err("must refuse non-canonical single shard");
    assert!(err.contains(WORKCHAIN_FREEZE_DOC), "must name freeze doc: {err}");
    assert!(check_workchain_boot_guard_with_hatch(&registry, true).is_ok());
}

#[test]
fn hatch_flag_is_exact_match_only() {
    let multi = ShardRegistry::from_ids([0, 1]);
    // Pure core: only hatch=true passes.
    assert!(check_workchain_boot_guard_with_hatch(&multi, false).is_err());
    assert!(check_workchain_boot_guard_with_hatch(&multi, true).is_ok());
    // Env wrapper: anything but exactly "1" is disabled.
    let _g = lock_env();
    let saved = save_env();
    std::env::remove_var(SHARD_REGISTRY_ENV);
    for bad in ["0", "true", "", " 1 ", "2"] {
        std::env::set_var(EXPERIMENTAL_SHARDS_ENV, bad);
        assert!(
            check_workchain_boot_guard(&multi).is_err(),
            "hatch value {bad:?} must not unlock multishard"
        );
    }
    std::env::set_var(EXPERIMENTAL_SHARDS_ENV, "1");
    assert!(check_workchain_boot_guard(&multi).is_ok());
    restore_env(saved);
}
