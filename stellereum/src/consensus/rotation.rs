use std::collections::HashMap;

use super::types::{clear_verified_vote_cache, Height, ValidatorId};

/// Global registry for validator post-quantum public keys.
#[allow(clippy::type_complexity)]
// GATE: registry type is fixed by consensus key shape; alias would churn all call sites without benefit.
static PQ_VALIDATOR_KEYS: std::sync::RwLock<
    Option<HashMap<ValidatorId, (crate::post_quantum::PqScheme, Vec<u8>)>>,
> = std::sync::RwLock::new(None);

/// Register a validator's post-quantum public key and scheme.
pub fn register_validator_pq_key(
    id: ValidatorId,
    scheme: crate::post_quantum::PqScheme,
    pubkey: Vec<u8>,
) {
    // Disabled schemes register nothing (ML-DSA-44's verifier is forgeable).
    if scheme.is_disabled() {
        return;
    }
    let mut lock = PQ_VALIDATOR_KEYS.write().unwrap_or_else(|e| e.into_inner());
    let map = lock.get_or_insert_with(HashMap::new);
    map.insert(id, (scheme, pubkey.clone()));
    drop(lock);
    // Mirror into the height-indexed committed registry as a pre-tracking
    // legacy key (`activated_at = 0`): the widest truthful window, so votes
    // at every height keep verifying exactly as before until a rotation is
    // announced for this validator. `AlreadyRegistered` means rotation state
    // already exists — keep it (never clobber history from a head-key sync).
    {
        let mut reg = PQ_COMMITTED_REGISTRY
            .write()
            .unwrap_or_else(|e| e.into_inner());
        let _ = reg.adopt_legacy_key(id, scheme, pubkey, true);
    }
    // KEY-ROTATION INVALIDATION (in-zone trigger): a (re-)registration
    // changes what `Vote::verify` computes for this voter, so every cached
    // verdict — keyed on the old key bytes — is dropped. Miss = full verify.
    clear_verified_vote_cache();
}

/// Height-indexed committed PQ registry (rotation-aware verify source).
///
/// Tracks the SAME lifecycle as [`crate::pq_registry::PqRegistry`]
/// (announce-now / effective-at-`+delay`, bounded superseded history) and
/// reuses its read — [`crate::pq_registry::PqRegistry::get_active_key`] —
/// instead of duplicating the window math. `register_validator_pq_key`
/// mirrors every head key here via `adopt_legacy_key` (`activated_at = 0`);
/// rotations are announced against this registry, so readers resolve the
/// key authoritative AT the vote/block height, not the current head key.
static PQ_COMMITTED_REGISTRY: std::sync::LazyLock<
    std::sync::RwLock<crate::pq_registry::PqRegistry>,
> = std::sync::LazyLock::new(|| std::sync::RwLock::new(crate::pq_registry::PqRegistry::new()));

/// Resolve the authoritative PQ key for `validator` AT `height`.
///
/// Committed-registry read FIRST ([`crate::pq_registry::PqRegistry::get_active_key`]
/// semantics, reused not duplicated): when the validator has a tracked record,
/// that record is authoritative fail-closed (`None` = no key at this height —
/// unknown validator, pre-activation, or pruned history). Validators never
/// tracked fall back to the legacy head map only when
/// [`crate::pq_registry::pq_lifecycle_active_at`]`(height)` is `false`;
/// post-W3 activation reads strictly from `PQ_COMMITTED_REGISTRY` (fail-closed).
/// Fail-closed in every doubt branch: `None` refuses verification.
pub fn pq_key_at_height(
    validator: &ValidatorId,
    height: Height,
) -> Option<(crate::post_quantum::PqScheme, Vec<u8>)> {
    let reg = PQ_COMMITTED_REGISTRY
        .read()
        .unwrap_or_else(|e| e.into_inner());
    if reg.record_of(validator).is_some() {
        return reg.get_active_key(validator, height);
    }
    drop(reg);
    if crate::pq_registry::pq_lifecycle_active_at(height) {
        return None;
    }
    get_validator_pq_key(validator)
}

/// Resolve the authoritative PQ key for `validator` AT `height` strictly from
/// `PQ_COMMITTED_REGISTRY` without falling back to the legacy head map
/// (`PQ_VALIDATOR_KEYS`). Used when [`crate::pq_registry::pq_lifecycle_active_at`]
/// is active so process-local key overrides can never leak into verification.
pub fn pq_key_at_height_strict(
    validator: &ValidatorId,
    height: Height,
) -> Option<(crate::post_quantum::PqScheme, Vec<u8>)> {
    let reg = PQ_COMMITTED_REGISTRY
        .read()
        .unwrap_or_else(|e| e.into_inner());
    reg.get_active_key(validator, height)
}

/// Synchronize `PQ_COMMITTED_REGISTRY` from the committed on-chain
/// [`crate::pq_registry::PqRegistry`] after block finalization or state restore.
///
/// When `clear_legacy_map` is `true` (post-W3 when
/// [`crate::pq_registry::pq_lifecycle_active_at`] is active), clears legacy
/// `PQ_VALIDATOR_KEYS` so all readers (`pq_key_at_height`) rely solely on the
/// height-indexed `PQ_COMMITTED_REGISTRY` with no process-local leakage.
///
/// Calls `clear_verified_vote_cache()` ONLY when `PQ_COMMITTED_REGISTRY` or
/// `PQ_VALIDATOR_KEYS` actually changed, avoiding cache flushes on empty ticks.
pub fn sync_committed_pq_registry(reg: &crate::pq_registry::PqRegistry, clear_legacy_map: bool) {
    let registry_changed = {
        let mut committed = PQ_COMMITTED_REGISTRY
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if committed.records() != reg.records() {
            *committed = reg.clone();
            true
        } else {
            false
        }
    };

    let legacy_cleared = if clear_legacy_map {
        let mut legacy = PQ_VALIDATOR_KEYS.write().unwrap_or_else(|e| e.into_inner());
        match legacy.as_mut() {
            Some(map) if !map.is_empty() => {
                map.clear();
                true
            }
            Some(_) | None => false,
        }
    } else {
        false
    };

    if registry_changed || legacy_cleared {
        clear_verified_vote_cache();
    }
}

/// Announce a PQ key rotation for tests: the replacement takes effect at
/// `now_height + PQ_ROTATION_DELAY_HEIGHTS`; the current key stays
/// authoritative until then (reads via [`pq_key_at_height`] resolve the
/// pending key only for heights `>= effective_height`).
///
/// Test-only driver for the committed registry above (production rotations
/// arrive through the staking hooks, out of this file's scope). Fail-closed
/// exactly like [`crate::pq_registry::PqRegistry::announce_rotation`];
/// clears the verified-vote cache so pre-announcement verdicts (keyed on the
/// old key bytes) can never serve post-rotation heights.
#[cfg(any(test, debug_assertions))]
pub fn pq_announce_rotation_for_tests(
    validator: ValidatorId,
    scheme: crate::post_quantum::PqScheme,
    pubkey: Vec<u8>,
    now_height: Height,
) -> Result<u64, crate::pq_registry::PqRegistryError> {
    let effective = {
        let mut reg = PQ_COMMITTED_REGISTRY
            .write()
            .unwrap_or_else(|e| e.into_inner());
        reg.announce_rotation(validator, scheme, pubkey, now_height, true)?;
        reg.pending_of(&validator)
            .map(|p| p.effective_height)
            .unwrap_or(now_height.saturating_add(crate::pq_registry::PQ_ROTATION_DELAY_HEIGHTS))
    };
    clear_verified_vote_cache();
    Ok(effective)
}

/// Retrieve a registered validator's post-quantum scheme and public key.
pub fn get_validator_pq_key(id: &ValidatorId) -> Option<(crate::post_quantum::PqScheme, Vec<u8>)> {
    let lock = PQ_VALIDATOR_KEYS.read().unwrap_or_else(|e| e.into_inner());
    lock.as_ref()?.get(id).cloned()
}

/// Clear registered validator post-quantum keys (for test hygiene).
#[cfg(any(test, debug_assertions))]
pub fn clear_validator_pq_keys_for_tests() {
    let mut lock = PQ_VALIDATOR_KEYS.write().unwrap_or_else(|e| e.into_inner());
    if let Some(map) = lock.as_mut() {
        map.clear();
    }
    // The vote verdicts below are keyed on the registered PQ key bytes: a
    // key-registry wipe without a cache wipe would serve stale verdicts.
    clear_verified_vote_cache();
}
