//! MEV committee KEM registry: validator id -> ML-KEM-768 encapsulation key.
//!
//! # Status: registry + rotation math ONLY — no consensus change
//!
//! The RANK-1 MEV transport leg ([`crate::mev_epoch::contribution_pq`])
//! encapsulates each share package to the recipient's ML-KEM-768 key, but it
//! takes those keys as a caller-supplied map (`recipient_index -> ek`): there
//! was no on-chain source for them, so every call site hand-rolled key
//! sourcing. This module is that source: a deterministic
//! [`MevKemRegistry`] mapping validator id -> current ML-KEM-768
//! encapsulation key (+ activation height + bounded superseded history) with
//! an announce-now / effective-at-`+delay` rotation lifecycle.
//!
//! # Lifecycle
//!
//! * `register` — first-time KEM key registration, effective at an explicit
//!   activation height (no backdating: activation in the past is refused).
//! * `announce_rotation` — stage a replacement key. It takes effect
//!   [`MEV_KEM_ROTATION_DELAY_HEIGHTS`] heights later; the CURRENT key stays
//!   authoritative until then (reads via
//!   [`MevKemRegistry::get_active_ek`] resolve the pending key only for
//!   heights `>= effective_height`).
//! * `apply_rotation` / `apply_due_rotations` — bookkeeping that retires the
//!   old key into the bounded history ([`MEV_KEM_HISTORY_LIMIT`] entries) and
//!   promotes the pending key. Reads do NOT depend on apply having run: a
//!   node that has not applied yet resolves the same key for a given height
//!   as one that has.
//!
//! # Chosen shape: pure registry, caller-held — the `pq_registry` precedent
//!
//! This mirrors [`crate::pq_registry::PqRegistry`] exactly: `BTreeMap`
//! iteration order (never `HashMap`), every transition a deterministic
//! function of its inputs (validator-set membership arrives as an explicit
//! `validator_known` bool, no wall clock, no env, no global state), and the
//! same announce/apply/cancel state machine. Differences are deliberate and
//! minimal:
//!
//! * ONE key kind only (ML-KEM-768, [`MEV_KEM_EK_LEN`] bytes): no
//!   scheme tag, no disabled-scheme gate — there is nothing else to track.
//! * NO legacy adoption: a KEM key never predates tracking (the classical
//!   X25519 leg is REMOVED and has no KEM key to adopt), so every member
//!   registers explicitly and an unknown id is fail-closed, never a fallback.
//!
//! # MEV read path (lead wiring — `mev_epoch.rs` only)
//!
//! [`crate::mev_epoch::EpochDkg::contribution_pq_from_registry`] resolves
//! every recipient ek from this registry (unknown recipient → `Err`,
//! fail-closed, never a classical package) and
//! [`crate::mev_epoch::EpochDkg::ingest_pq_from_registry`] refuses a seed
//! whose derived ek is not the registered active key at that height (so a
//! rotated key is enforced post-delay). Threshold math, Feldman VSS and
//! sealing are untouched — the registry only decides WHICH bytes are keys.
//!
//! # Rotation delay philosophy (same const family as `pq_registry`)
//!
//! [`MEV_KEM_ROTATION_DELAY_HEIGHTS`] is pinned EQUAL to
//! [`crate::pq_registry::PQ_ROTATION_DELAY_HEIGHTS`] (7,200 heights ≈ 6 h at
//! 3 s blocks): a rotation must be observable on-chain well BEFORE the new
//! key becomes the encapsulation key, in-flight packages keep opening under
//! the old key until the effective height, and a compromised KEM key cannot
//! be swapped to an attacker key instantly. Deterministic const, never env.
//!
//! FREEZE (protocol freeze 2026-11-03, same freeze as the PQ registry delay):
//! 7,200 heights. Change requires spec update + audit note (AGENTS.md §7).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::consensus::ValidatorId;

// ============================================================================
// Constants (consts in code — never env)
// ============================================================================

/// Rotation delay in heights: an announced MEV KEM key takes effect this many
/// heights after the announcement.
///
/// WHY (same exit-window philosophy as
/// [`crate::pq_registry::PQ_ROTATION_DELAY_HEIGHTS`], pinned equal in
/// tests): rotation must be observable on-chain well BEFORE the new key
/// becomes the encapsulation key. Contributors keep encapsulating to the old
/// key until the effective height, and a compromised key cannot be swapped to
/// an attacker key instantly. Deterministic const, never env: rotation
/// admission is consensus (every node applying the same blocks must agree on
/// when a key activates).
///
/// RULESET v2: 30,000 heights x 240 ms = **7,200 s (2 h)**. Full table:
/// `docs/RULESET_V2.md`.
///
/// FREEZE (protocol freeze 2026-11-03): deterministic const, never env.
/// Change requires spec update + audit note (AGENTS.md §7).
pub const MEV_KEM_ROTATION_DELAY_HEIGHTS: u64 = 30_000;

/// How many superseded KEM keys are retained per validator (bounded history).
///
/// WHY 2 (same bound as [`crate::pq_registry::PQ_KEY_HISTORY_LIMIT`]):
/// delayed packages may arrive after a rotation, so recipients need the
/// recently-superseded keys — but unbounded history is unbounded state growth
/// (each entry is [`MEV_KEM_EK_LEN`] bytes). Two covers a rotation plus its
/// predecessor; anything older is outside any realistic evidence window and
/// is refused fail-closed.
pub const MEV_KEM_HISTORY_LIMIT: usize = 2;

/// ML-KEM-768 encapsulation key length (FIPS 203).
///
/// Equals [`crate::mev_epoch::PQ_KEM_EK_LEN`] (1,184 bytes), the exact size
/// every KEM admission path enforces. Pinned equal in tests; the registry
/// stores NO seeds (decapsulation keys stay node-local — the registry only
/// ever sees public encapsulation bytes).
pub const MEV_KEM_EK_LEN: usize = 1184;

// ============================================================================
// Errors (fail-closed refusals)
// ============================================================================

/// Fail-closed refusal for a MEV KEM registry write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MevKemRegistryError {
    /// Validator is not in the validator set, or has no registered KEM key.
    UnknownValidator,
    /// `register` for an id that already has a tracked key (rotate instead).
    AlreadyRegistered,
    /// `announce_rotation` while a rotation is already pending (one flight
    /// at a time — announce the CURRENT key to cancel, then re-announce).
    RotationAlreadyPending,
    /// Backdated activation: `register` with `activation_height < now`, or
    /// `announce_rotation` with `now` before the current key's activation
    /// (history must never be rewritten).
    ActivationInPast,
    /// Future activation in a peer announcement: `activation_height > now_height`
    /// would leave `get_active_ek(..., now_height)` returning `None`.
    ActivationInFuture,
    /// Key bytes are not exactly [`MEV_KEM_EK_LEN`] (a removed classical
    /// X25519 key or any other shape is refused here — never silently
    /// encapsulated to).
    MalformedKey,
    /// `apply_rotation` with nothing pending.
    NoPendingRotation,
    /// `apply_rotation` before the announced effective height.
    RotationNotDue,
    /// Pending rotation or superseded history violates height invariants.
    InvalidHeightInvariant,
    /// ML-KEM-768 encapsulation key is already registered or pending for another validator.
    DuplicateKey,
    /// Height arithmetic overflowed `u64::MAX`.
    ArithmeticOverflow,
}

impl std::fmt::Display for MevKemRegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            MevKemRegistryError::UnknownValidator => {
                "unknown validator (not in validator set or no registered KEM key): refusing"
            }
            MevKemRegistryError::AlreadyRegistered => {
                "validator already has a registered KEM key: rotate, do not re-register"
            }
            MevKemRegistryError::RotationAlreadyPending => {
                "a KEM rotation is already pending: one flight at a time (announce the current key to cancel)"
            }
            MevKemRegistryError::ActivationInPast => {
                "activation height is in the past: KEM key history is append-only, backdating refused"
            }
            MevKemRegistryError::ActivationInFuture => {
                "peer KEM key activation height is in the future relative to current height: refusing"
            }
            MevKemRegistryError::MalformedKey => {
                "KEM key bytes must be exactly 1184 bytes (ML-KEM-768 encapsulation key): refusing"
            }
            MevKemRegistryError::NoPendingRotation => "no KEM rotation is pending: nothing to apply",
            MevKemRegistryError::RotationNotDue => {
                "KEM rotation is not yet effective: apply at or after the announced effective height"
            }
            MevKemRegistryError::InvalidHeightInvariant => {
                "KEM key record violates pending/history height invariants: refusing"
            }
            MevKemRegistryError::DuplicateKey => {
                "ML-KEM-768 encapsulation key is already bound to another validator: refusing"
            }
            MevKemRegistryError::ArithmeticOverflow => {
                "MEV KEM registry height arithmetic overflow"
            }
        };
        write!(f, "{s}")
    }
}

impl std::error::Error for MevKemRegistryError {}

// ============================================================================
// Records
// ============================================================================

/// An announced-but-not-yet-effective KEM key rotation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingMevKemRotation {
    /// Replacement encapsulation key bytes (exactly [`MEV_KEM_EK_LEN`]).
    pub ek: Vec<u8>,
    /// Height at which the rotation was announced.
    pub announced_height: u64,
    /// First height at which the replacement key is authoritative
    /// (`announced_height + `[`MEV_KEM_ROTATION_DELAY_HEIGHTS`]).
    pub effective_height: u64,
}

/// A superseded KEM key retained for late packages. Valid exactly for
/// `activated_at <= height < superseded_at`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupersededMevKemKey {
    /// Superseded encapsulation key bytes.
    pub ek: Vec<u8>,
    /// Height at which this key became authoritative.
    pub activated_at: u64,
    /// First height at which it stopped being authoritative.
    pub superseded_at: u64,
}

/// The tracked KEM key state for one validator: current key + activation
/// height + pending rotation + bounded superseded history.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MevKemKeyRecord {
    /// Current encapsulation key bytes (authoritative until a pending
    /// rotation's effective height).
    pub ek: Vec<u8>,
    /// Height at which the current key became authoritative.
    pub activated_at: u64,
    /// Announced rotation, if one is in flight.
    pub pending: Option<PendingMevKemRotation>,
    /// Superseded keys, oldest-first, capped at [`MEV_KEM_HISTORY_LIMIT`].
    pub history: Vec<SupersededMevKemKey>,
}

// ============================================================================
// Registry
// ============================================================================

/// Deterministic MEV committee KEM registry: validator id -> [`MevKemKeyRecord`].
///
/// `BTreeMap` (never `HashMap`) so iteration — e.g. the
/// [`MevKemRegistry::apply_due_rotations`] sweep — is identical on every
/// node. Pure state machine: validator-set membership arrives as an explicit
/// `validator_known` bool, keeping every transition a deterministic function
/// of its inputs (no wall clock, no env, no global state).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MevKemRegistry {
    keys: BTreeMap<ValidatorId, MevKemKeyRecord>,
}

impl MevKemRegistry {
    /// Empty registry (no tracked keys — the default-off posture).
    pub fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
        }
    }

    /// Number of validators with a tracked KEM key.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// True when no validator has a tracked KEM key.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The full tracked record for `validator`, if any.
    pub fn record_of(&self, validator: &ValidatorId) -> Option<&MevKemKeyRecord> {
        self.keys.get(validator)
    }

    /// The current encapsulation key for `validator`, if tracked.
    pub fn current_ek_of(&self, validator: &ValidatorId) -> Option<Vec<u8>> {
        self.keys.get(validator).map(|r| r.ek.clone())
    }

    /// The pending rotation for `validator`, if one is in flight.
    pub fn pending_of(&self, validator: &ValidatorId) -> Option<&PendingMevKemRotation> {
        self.keys.get(validator).and_then(|r| r.pending.as_ref())
    }

    /// The superseded-key history for `validator` (oldest-first), if tracked.
    pub fn history_of(&self, validator: &ValidatorId) -> Option<&[SupersededMevKemKey]> {
        self.keys.get(validator).map(|r| r.history.as_slice())
    }

    /// Returns `true` if `ek` is currently active or pending on any validator
    /// other than `exclude_validator`.
    fn ek_used_by_other(&self, exclude_validator: &ValidatorId, ek: &[u8]) -> bool {
        self.keys.iter().any(|(id, rec)| {
            if id == exclude_validator {
                return false;
            }
            if rec.ek.as_slice() == ek {
                return true;
            }
            rec.pending.as_ref().is_some_and(|p| p.ek.as_slice() == ek)
        })
    }

    /// Register a validator's FIRST KEM key.
    ///
    /// Effective at `activation_height` (may be `now` or the future — never
    /// the past). Fail-closed: unknown validator, existing record
    /// ([`MevKemRegistryError::AlreadyRegistered`] — rotate, do not
    /// re-register), duplicate key on another validator
    /// ([`MevKemRegistryError::DuplicateKey`]), wrong-size key, or
    /// `activation_height < now_height`.
    pub fn register(
        &mut self,
        validator: ValidatorId,
        ek: Vec<u8>,
        activation_height: u64,
        now_height: u64,
        validator_known: bool,
    ) -> Result<(), MevKemRegistryError> {
        if !validator_known {
            return Err(MevKemRegistryError::UnknownValidator);
        }
        if self.keys.contains_key(&validator) {
            return Err(MevKemRegistryError::AlreadyRegistered);
        }
        validate_ek_bytes(&ek)?;
        if self.ek_used_by_other(&validator, &ek) {
            return Err(MevKemRegistryError::DuplicateKey);
        }
        if activation_height < now_height {
            return Err(MevKemRegistryError::ActivationInPast);
        }
        self.keys.insert(
            validator,
            MevKemKeyRecord {
                ek,
                activated_at: activation_height,
                pending: None,
                history: Vec::new(),
            },
        );
        Ok(())
    }

    /// Announce a KEM key rotation: the replacement takes effect at
    /// `now_height + `[`MEV_KEM_ROTATION_DELAY_HEIGHTS`]. The current key
    /// stays authoritative until then.
    ///
    /// Fail-closed: unknown validator (or no tracked key — `register`
    /// first), wrong-size key, backdated announcement (`now_height` before
    /// the current key's activation), duplicate key bound to another
    /// validator, height overflow, or a rotation already in flight
    /// ([`MevKemRegistryError::RotationAlreadyPending`]).
    ///
    /// Cancelling: announcing a key IDENTICAL to the current one clears a
    /// pending rotation (no-op success, mirrors the commission
    /// announce-current-cancels rule) and succeeds with nothing pending.
    pub fn announce_rotation(
        &mut self,
        validator: ValidatorId,
        ek: Vec<u8>,
        now_height: u64,
        validator_known: bool,
    ) -> Result<(), MevKemRegistryError> {
        if !validator_known {
            return Err(MevKemRegistryError::UnknownValidator);
        }
        validate_ek_bytes(&ek)?;
        let is_cancel = {
            let rec = self
                .keys
                .get(&validator)
                .ok_or(MevKemRegistryError::UnknownValidator)?;
            if now_height < rec.activated_at {
                return Err(MevKemRegistryError::ActivationInPast);
            }
            if rec.ek == ek {
                true
            } else if rec.pending.is_some() {
                return Err(MevKemRegistryError::RotationAlreadyPending);
            } else {
                false
            }
        };
        if is_cancel {
            // Cancel-by-reannounce: the operator re-asserts the current key,
            // dropping a pending rotation that never took effect.
            if let Some(rec) = self.keys.get_mut(&validator) {
                rec.pending = None;
            }
            return Ok(());
        }
        if self.ek_used_by_other(&validator, &ek) {
            return Err(MevKemRegistryError::DuplicateKey);
        }
        let effective_height = now_height
            .checked_add(MEV_KEM_ROTATION_DELAY_HEIGHTS)
            .ok_or(MevKemRegistryError::ArithmeticOverflow)?;
        let rec = self
            .keys
            .get_mut(&validator)
            .ok_or(MevKemRegistryError::UnknownValidator)?;
        rec.pending = Some(PendingMevKemRotation {
            ek,
            announced_height: now_height,
            effective_height,
        });
        Ok(())
    }

    /// Promote a due pending rotation: the old current key retires into the
    /// bounded history, the pending key becomes current with
    /// `activated_at = effective_height` (NOT `now_height`, so nodes that
    /// apply late still derive identical windows).
    ///
    /// Fail-closed: unknown validator / untracked key, nothing pending, or
    /// `now_height` before the announced effective height.
    pub fn apply_rotation(
        &mut self,
        validator: ValidatorId,
        now_height: u64,
        validator_known: bool,
    ) -> Result<(), MevKemRegistryError> {
        if !validator_known {
            return Err(MevKemRegistryError::UnknownValidator);
        }
        let rec = self
            .keys
            .get_mut(&validator)
            .ok_or(MevKemRegistryError::UnknownValidator)?;
        let pending = rec
            .pending
            .clone()
            .ok_or(MevKemRegistryError::NoPendingRotation)?;
        if now_height < pending.effective_height {
            return Err(MevKemRegistryError::RotationNotDue);
        }
        let old = SupersededMevKemKey {
            ek: std::mem::take(&mut rec.ek),
            activated_at: rec.activated_at,
            superseded_at: pending.effective_height,
        };
        rec.ek = pending.ek;
        rec.activated_at = pending.effective_height;
        rec.pending = None;
        rec.history.push(old);
        truncate_history(&mut rec.history);
        Ok(())
    }

    /// Promote EVERY rotation due at `now_height`, in validator-id order
    /// (deterministic across nodes). Returns the ids whose rotation was
    /// applied. Never fails: entries that are not due are left untouched.
    pub fn apply_due_rotations(&mut self, now_height: u64) -> Vec<ValidatorId> {
        let due: Vec<ValidatorId> = self
            .keys
            .iter()
            .filter_map(|(id, rec)| match &rec.pending {
                Some(p) if now_height >= p.effective_height => Some(*id),
                _ => None,
            })
            .collect();
        for id in &due {
            // Due-ness was just established from the same state; the only
            // refusal possible would be a logic bug, and a sweep must never
            // panic — a skipped entry stays pending for the next height.
            let _ = self.apply_rotation(*id, now_height, true);
        }
        due
    }

    /// Resolve the authoritative KEM key for `validator` AT `height`.
    ///
    /// * pending rotation with `height >= effective_height` → pending key
    ///   (rotation has activated at this height, even if `apply` has not run
    ///   yet — readers never depend on apply timing);
    /// * else current key, if `height >= activated_at`;
    /// * else the superseded key whose `[activated_at, superseded_at)`
    ///   window contains `height` (late packages under a retired key);
    /// * else `None` (unknown validator or height outside every validity
    ///   window — fail-closed, never a classical fallback).
    pub fn get_active_ek(&self, validator: &ValidatorId, height: u64) -> Option<Vec<u8>> {
        let rec = self.keys.get(validator)?;
        if let Some(p) = &rec.pending {
            if height >= p.effective_height {
                return Some(p.ek.clone());
            }
        }
        if height >= rec.activated_at {
            return Some(rec.ek.clone());
        }
        rec.history
            .iter()
            .find(|e| e.activated_at <= height && height < e.superseded_at)
            .map(|e| e.ek.clone())
    }

    /// Deterministically upsert a peer's ML-KEM-768 encapsulation key, or
    /// confirm an identical re-announcement (idempotent).
    ///
    /// Fail-closed:
    /// * `validator_known == false` -> [`MevKemRegistryError::UnknownValidator`].
    /// * Invalid / non-1184-byte key -> [`MevKemRegistryError::MalformedKey`].
    /// * `activation_height > now_height` ->
    ///   [`MevKemRegistryError::ActivationInFuture`] (a peer cannot insert an
    ///   inactive future key that would cause `get_active_ek(..., now_height)`
    ///   to return `None`).
    /// * Validator already holds a DIFFERENT current key ->
    ///   [`MevKemRegistryError::AlreadyRegistered`] (never overwrites silently
    ///   without an explicit rotation).
    ///
    /// Returns `Ok(true)` if a new key record was inserted, `Ok(false)` if the
    /// validator already holds the exact same current key.
    pub fn upsert_registered_ek(
        &mut self,
        validator: ValidatorId,
        ek: Vec<u8>,
        activation_height: u64,
        now_height: u64,
        validator_known: bool,
    ) -> Result<bool, MevKemRegistryError> {
        if !validator_known {
            return Err(MevKemRegistryError::UnknownValidator);
        }
        validate_ek_bytes(&ek)?;
        if activation_height > now_height {
            return Err(MevKemRegistryError::ActivationInFuture);
        }
        if let Some(existing) = self.keys.get(&validator) {
            if existing.ek == ek {
                return Ok(false);
            }
            return Err(MevKemRegistryError::AlreadyRegistered);
        }
        if self.ek_used_by_other(&validator, &ek) {
            return Err(MevKemRegistryError::DuplicateKey);
        }
        self.keys.insert(
            validator,
            MevKemKeyRecord {
                ek,
                activated_at: activation_height,
                pending: None,
                history: Vec::new(),
            },
        );
        Ok(true)
    }

    /// Deterministically merge entries from `other` into `self` in `ValidatorId`
    /// order.
    ///
    /// Atomic and fail-closed: validates every key and height invariant in
    /// `other` (current, pending, and history) and verifies there are no
    /// conflicting current/pending keys before mutating `self`. Identical
    /// entries are idempotent; conflicting current keys return
    /// [`MevKemRegistryError::AlreadyRegistered`] without modifying `self`.
    /// Returns the number of newly inserted/updated records.
    pub fn merge_from(&mut self, other: &MevKemRegistry) -> Result<usize, MevKemRegistryError> {
        for (id, rec) in &other.keys {
            validate_record_invariants(rec)?;
            if let Some(existing) = self.keys.get(id) {
                if existing.ek != rec.ek {
                    return Err(MevKemRegistryError::AlreadyRegistered);
                }
                if existing.pending.is_some()
                    && rec.pending.is_some()
                    && existing.pending != rec.pending
                {
                    return Err(MevKemRegistryError::RotationAlreadyPending);
                }
            }
        }
        let mut merged = 0usize;
        for (id, rec) in &other.keys {
            match self.keys.get_mut(id) {
                Some(existing) => {
                    if existing.pending.is_none() && rec.pending.is_some() {
                        existing.pending = rec.pending.clone();
                        merged += 1;
                    }
                }
                None => {
                    let mut cloned = rec.clone();
                    truncate_history(&mut cloned.history);
                    self.keys.insert(*id, cloned);
                    merged += 1;
                }
            }
        }
        Ok(merged)
    }

    /// Deterministically merge all valid, non-conflicting entries from `other`
    /// into `self` in `ValidatorId` (`BTreeMap`) order.
    ///
    /// Unlike [`Self::merge_from`] (which aborts atomically on the first
    /// conflict), this skips individual invalid or conflicting validator
    /// entries with a warning rather than discarding all other peers' valid
    /// keys. Returns the number of newly inserted or updated records.
    pub fn merge_non_conflicting(&mut self, other: &MevKemRegistry) -> usize {
        let mut merged = 0usize;
        for (id, rec) in &other.keys {
            if let Err(e) = validate_record_invariants(rec) {
                tracing::warn!(
                    "[mev-kem] skipping invalid peer KEM record for {}: {e}",
                    hex::encode(&id[..6])
                );
                continue;
            }
            match self.keys.get_mut(id) {
                Some(existing) => {
                    if existing.ek != rec.ek {
                        tracing::warn!(
                            "[mev-kem] skipping conflicting peer KEM key for {} (existing key preserved)",
                            hex::encode(&id[..6])
                        );
                        continue;
                    }
                    if existing.pending.is_some()
                        && rec.pending.is_some()
                        && existing.pending != rec.pending
                    {
                        tracing::warn!(
                            "[mev-kem] skipping conflicting pending KEM rotation for {}",
                            hex::encode(&id[..6])
                        );
                        continue;
                    }
                    if existing.pending.is_none() && rec.pending.is_some() {
                        existing.pending = rec.pending.clone();
                        merged += 1;
                    }
                }
                None => {
                    let mut cloned = rec.clone();
                    truncate_history(&mut cloned.history);
                    self.keys.insert(*id, cloned);
                    merged += 1;
                }
            }
        }
        merged
    }

    /// Move a validator's whole KEM record to a new consensus id (call
    /// alongside a consensus-key rotation: rotation state must travel with
    /// the record — the same precedent as
    /// [`crate::pq_registry::PqRegistry::migrate_validator`] — otherwise a
    /// rekeyed validator strands its pending rotation and history under a
    /// dead id).
    ///
    /// No-op `Ok` when `old` has no tracked record. Refuses
    /// ([`MevKemRegistryError::AlreadyRegistered`], record restored
    /// untouched) when `new` already has one, so a migration can never merge
    /// or clobber.
    pub fn migrate_validator(
        &mut self,
        old: ValidatorId,
        new: ValidatorId,
    ) -> Result<(), MevKemRegistryError> {
        if old == new {
            return Err(MevKemRegistryError::AlreadyRegistered);
        }
        let rec = match self.keys.remove(&old) {
            None => return Ok(()),
            Some(r) => r,
        };
        if self.keys.contains_key(&new) {
            self.keys.insert(old, rec);
            return Err(MevKemRegistryError::AlreadyRegistered);
        }
        self.keys.insert(new, rec);
        Ok(())
    }
}

/// Enforce the bounded history: keep the newest [`MEV_KEM_HISTORY_LIMIT`]
/// entries (oldest-first order, evict from the front).
fn truncate_history(history: &mut Vec<SupersededMevKemKey>) {
    if history.len() > MEV_KEM_HISTORY_LIMIT {
        let excess = history.len() - MEV_KEM_HISTORY_LIMIT;
        history.drain(..excess);
    }
}

/// Validate key bytes and height invariants on a [`MevKemKeyRecord`] before
/// merging it from another registry.
fn validate_record_invariants(rec: &MevKemKeyRecord) -> Result<(), MevKemRegistryError> {
    validate_ek_bytes(&rec.ek)?;
    if let Some(p) = &rec.pending {
        validate_ek_bytes(&p.ek)?;
        let Some(min_effective) = p
            .announced_height
            .checked_add(MEV_KEM_ROTATION_DELAY_HEIGHTS)
        else {
            return Err(MevKemRegistryError::InvalidHeightInvariant);
        };
        if p.announced_height < rec.activated_at || p.effective_height < min_effective {
            return Err(MevKemRegistryError::InvalidHeightInvariant);
        }
    }
    for h in &rec.history {
        validate_ek_bytes(&h.ek)?;
        if h.activated_at >= h.superseded_at {
            return Err(MevKemRegistryError::InvalidHeightInvariant);
        }
    }
    Ok(())
}

/// Fail-closed KEM admission: the bytes must be EXACTLY the ML-KEM-768
/// encapsulation size ([`MEV_KEM_EK_LEN`]) and a valid FIPS-203 ML-KEM-768
/// encapsulation key (`ml_kem::EncapsulationKey768::new`) — a removed classical
/// X25519 key or non-canonical/malformed encoding is refused here, never
/// silently accepted or encapsulated to.
pub fn validate_ek_bytes(ek: &[u8]) -> Result<(), MevKemRegistryError> {
    if ek.len() != MEV_KEM_EK_LEN {
        return Err(MevKemRegistryError::MalformedKey);
    }
    let key = ml_kem::kem::Key::<ml_kem::EncapsulationKey768>::try_from(ek)
        .map_err(|_| MevKemRegistryError::MalformedKey)?;
    ml_kem::EncapsulationKey768::new(&key).map_err(|_| MevKemRegistryError::MalformedKey)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ek(tag: u8) -> Vec<u8> {
        crate::mev_epoch::pq_kem_ek_from_seed(&[tag; 64])
    }

    #[test]
    fn merge_validates_pending_and_history_height_invariants() {
        let id0 = [0x11; 32];
        let id1 = [0x22; 32];
        let ek0 = test_ek(0x01);
        let ek1 = test_ek(0x02);

        // 1. Pending rotation with insufficient delay is refused by merge_from
        // and skipped by merge_non_conflicting.
        let mut bad_delay = MevKemRegistry::new();
        bad_delay.keys.insert(
            id0,
            MevKemKeyRecord {
                ek: ek0.clone(),
                activated_at: 10,
                pending: Some(PendingMevKemRotation {
                    ek: ek1.clone(),
                    announced_height: 10,
                    effective_height: 10 + MEV_KEM_ROTATION_DELAY_HEIGHTS - 1,
                }),
                history: Vec::new(),
            },
        );
        let mut reg = MevKemRegistry::new();
        assert_eq!(
            reg.merge_from(&bad_delay),
            Err(MevKemRegistryError::InvalidHeightInvariant)
        );
        assert_eq!(reg.merge_non_conflicting(&bad_delay), 0);
        assert!(reg.is_empty());

        // 2. Pending rotation with announced_height < activated_at is refused.
        let mut bad_announced = MevKemRegistry::new();
        bad_announced.keys.insert(
            id0,
            MevKemKeyRecord {
                ek: ek0.clone(),
                activated_at: 20,
                pending: Some(PendingMevKemRotation {
                    ek: ek1.clone(),
                    announced_height: 19,
                    effective_height: 19 + MEV_KEM_ROTATION_DELAY_HEIGHTS,
                }),
                history: Vec::new(),
            },
        );
        assert_eq!(
            reg.merge_from(&bad_announced),
            Err(MevKemRegistryError::InvalidHeightInvariant)
        );

        // 3. History entry with activated_at >= superseded_at is refused,
        // while valid sibling entry (id1) is still absorbed by merge_non_conflicting.
        let mut bad_history = MevKemRegistry::new();
        bad_history.keys.insert(
            id0,
            MevKemKeyRecord {
                ek: ek0.clone(),
                activated_at: 20,
                pending: None,
                history: vec![SupersededMevKemKey {
                    ek: ek1.clone(),
                    activated_at: 15,
                    superseded_at: 15,
                }],
            },
        );
        bad_history.keys.insert(
            id1,
            MevKemKeyRecord {
                ek: ek1.clone(),
                activated_at: 0,
                pending: None,
                history: Vec::new(),
            },
        );
        assert_eq!(
            reg.merge_from(&bad_history),
            Err(MevKemRegistryError::InvalidHeightInvariant)
        );
        assert!(reg.is_empty());
        assert_eq!(reg.merge_non_conflicting(&bad_history), 1);
        assert!(reg.record_of(&id0).is_none());
        assert_eq!(reg.get_active_ek(&id1, 0), Some(ek1));
    }

    #[test]
    fn announce_rotation_near_u64_max_returns_err() {
        let id = [0x33; 32];
        let ek0 = test_ek(0x11);
        let ek1 = test_ek(0x12);
        let mut reg = MevKemRegistry::new();
        let start = u64::MAX - 10;
        reg.register(id, ek0, start, start, true)
            .expect("register near u64::MAX");
        let err = reg
            .announce_rotation(id, ek1, u64::MAX - 5, true)
            .expect_err("rotation near u64::MAX must fail on overflow");
        assert_eq!(err, MevKemRegistryError::ArithmeticOverflow);
        assert!(reg.pending_of(&id).is_none());
    }

    #[test]
    fn duplicate_ek_across_validators_is_refused() {
        let id0 = [0x41; 32];
        let id1 = [0x42; 32];
        let ek0 = test_ek(0x21);
        let ek1 = test_ek(0x22);
        let mut reg = MevKemRegistry::new();
        reg.register(id0, ek0.clone(), 0, 0, true)
            .expect("initial registration succeeds");

        assert_eq!(
            reg.register(id1, ek0.clone(), 0, 0, true),
            Err(MevKemRegistryError::DuplicateKey)
        );
        assert_eq!(
            reg.upsert_registered_ek(id1, ek0.clone(), 0, 0, true),
            Err(MevKemRegistryError::DuplicateKey)
        );
        reg.register(id1, ek1, 0, 0, true)
            .expect("distinct key succeeds");
        assert_eq!(
            reg.announce_rotation(id1, ek0, 10, true),
            Err(MevKemRegistryError::DuplicateKey)
        );
    }
}
