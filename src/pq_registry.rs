//! On-chain post-quantum (PQ) key registry with delayed rotation.
//!
//! # Status: registry + rotation math ONLY — no consensus change
//!
//! Validator PQ keys (Falcon-512 today) are distributed out of band via
//! `STELL_PEER_PQ_KEYS` env config: there is no on-chain registry and no
//! rotation story (a compromised PQ key can never be replaced without a
//! coordinated redeploy). This module is the on-chain replacement: a
//! deterministic [`PqRegistry`] mapping validator id -> current PQ public key
//! (+ key-type tag + activation height + bounded superseded history) with an
//! announce-now / effective-at-`+delay` rotation lifecycle.
//!
//! # Lifecycle
//!
//! * `register` — first-time key registration, effective at an explicit
//!   activation height (no backdating: activation in the past is refused).
//! * `announce_rotation` — stage a replacement key. It takes effect
//!   [`PQ_ROTATION_DELAY_HEIGHTS`] heights later; the CURRENT key stays
//!   authoritative until then (reads via [`PqRegistry::get_active_key`]
//!   resolve the pending key only for heights `>= effective_height`).
//! * `apply_rotation` / `apply_due_rotations` — bookkeeping that retires the
//!   old key into the bounded history ([`PQ_KEY_HISTORY_LIMIT`] entries) and
//!   promotes the pending key. Reads do NOT depend on apply having run: a
//!   node that has not applied yet resolves the same key for a given height
//!   as one that has.
//!
//! # Chosen shape: staking-hook calls, NOT a new transaction type
//!
//! Registration could have been a validator-signed key-announcement
//! transaction (new `OpCode`, new mempool admission, new block-application
//! branch). That is the most invasive option: it touches the SVM wire enums
//! and every admission path. The hooks in [`crate::staking::StakingLedger`]
//! (`pq_register_key`, `pq_announce_rotation`, `pq_apply_rotation`,
//! `pq_apply_due_rotations`, `pq_active_key`) are the least invasive fit:
//! the rotation state machine lives here (pure, deterministic, BTreeMap
//! iteration order), membership checks + committed-key mirroring live there,
//! and a future opcode only needs to (1) verify the announcement signature
//! with [`verify_rotation_announcement`] and (2) call the hook — exactly how
//! `rotate_key` leaves caller-auth to its opcode handler today.
//!
//! # Consensus read path (lead wiring — NOT done here)
//!
//! Verification paths must resolve the key **at the vote's height**, not the
//! current head key:
//!
//! ```ignore
//! // consensus.rs (e.g. `pq_path_verify` / `epoch_cert_valid_signers`):
//! // replace `get_validator_pq_key(&id)` with:
//! match ledger.pq_active_key(&registry, &id, vote_height) {
//!     Some((scheme, pk)) => crate::post_quantum::verify_pq_signature(scheme, &pk, &msg, &sig),
//!     None => false, // fail-closed: unknown validator or no key at that height
//! }
//! ```
//!
//! `get_active_key` serves the pending key for `height >= effective_height`
//! even before `apply` runs, the current key inside its validity window, and
//! superseded keys inside their `[activated_at, superseded_at)` windows (so
//! late-arriving equivocation evidence still verifies against the key that
//! signed it). Anything else — unknown validator, height before the first
//! activation — is `None`.
//!
//! # Persistence (lead wiring)
//!
//! [`PqRegistry`] is `Serialize`/`Deserialize` and empty by default, but it is
//! deliberately NOT embedded in [`crate::staking::StakingLedger`] yet:
//! appending a field would break the exhaustive `StakingLedger { ... }`
//! constructors in `storage.rs` (out of this scope) and would need a
//! conditional commitment domain (empty writes nothing, genesis root
//! untouched — the `validator_pq_keys` precedent in `commitment.rs`) plus a
//! `DomainSnapshotV*` fallback. Until that lands, the hooks mirror every
//! CURRENT key into the already-committed `validator_pq_keys` map, so the
//! existing digest/slash readers keep working unchanged.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::consensus::ValidatorId;
use crate::post_quantum::{PqScheme, HYBRID_PUBKEY_LEN};

// ============================================================================
// Constants (consts in code — never env)
// ============================================================================

/// Rotation delay in heights: an announced PQ key takes effect this many
/// heights after the announcement (7,200 heights ≈ 6 h at 3 s blocks).
///
/// WHY (same exit-window philosophy as
/// [`crate::staking::COMMISSION_EFFECT_DELAY_HEIGHTS`], pinned equal in
/// tests): rotation must be observable on-chain well BEFORE the new key
/// becomes the verification key. Verifiers and light clients sync the
/// announcement, old votes in flight keep verifying under the old key until
/// the effective height, and a compromised key cannot be swapped to an
/// attacker key instantly. Deterministic const, never env: rotation admission
/// is consensus (every node applying the same blocks must agree on when a
/// key activates).
///
/// FREEZE (protocol freeze 2026-11-03): 7,200 heights ≈ 6 h at 3 s blocks
/// (spec docs/specs/02_CRYPTO_AND_PQ_PHASE2.md §6, == CN-VRF EPOCH_LEN).
/// Change requires spec update + audit note (AGENTS.md §7).
pub const PQ_ROTATION_DELAY_HEIGHTS: u64 = 7_200;

/// How many superseded keys are retained per validator (bounded history).
///
/// WHY 2: equivocation evidence and late votes may arrive after a rotation,
/// so verifiers need the recently-superseded keys — but unbounded history is
/// unbounded state growth (each entry is up to [`PQ_MAX_KEY_BYTES`] bytes).
/// Two covers a rotation plus its predecessor; anything older is outside any
/// realistic evidence window and is refused fail-closed.
pub const PQ_KEY_HISTORY_LIMIT: usize = 2;

/// Hard cap on any tracked PQ public key, in bytes.
///
/// Equals [`crate::post_quantum::HYBRID_PUBKEY_LEN`] (929 = 32-byte Ed25519 +
/// 897-byte Falcon-512), the largest canonical key in
/// [`crate::post_quantum`]. Every admission path additionally requires the
/// EXACT per-scheme size (`scheme.pubkey_size()`), so this cap is the outer
/// bound and the exact check is the inner one.
pub const PQ_MAX_KEY_BYTES: usize = HYBRID_PUBKEY_LEN;

/// Domain tag for the rotation-announcement preimage signed by the
/// validator's consensus (ed25519) key.
pub const PQ_ROTATION_ANNOUNCE_DST: &[u8] = b"STELL_PQ_ROTATE_V1";

// ============================================================================
// Errors (fail-closed refusals)
// ============================================================================

/// Fail-closed refusal for a PQ registry write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PqRegistryError {
    /// Validator is not in the validator set, or has no registered PQ key.
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
    /// Key bytes do not match the scheme's canonical size (outer bound:
    /// [`PQ_MAX_KEY_BYTES`).
    OversizedKey,
    /// Scheme is disabled fail-closed ([`PqScheme::is_disabled`], today
    /// ML-DSA-44: not real FIPS-204 math, never tracked).
    DisabledScheme,
    /// `apply_rotation` with nothing pending.
    NoPendingRotation,
    /// `apply_rotation` before the announced effective height.
    RotationNotDue,
}

impl std::fmt::Display for PqRegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            PqRegistryError::UnknownValidator => {
                "unknown validator (not in validator set or no registered PQ key): refusing"
            }
            PqRegistryError::AlreadyRegistered => {
                "validator already has a registered PQ key: rotate, do not re-register"
            }
            PqRegistryError::RotationAlreadyPending => {
                "a PQ rotation is already pending: one flight at a time (announce the current key to cancel)"
            }
            PqRegistryError::ActivationInPast => {
                "activation height is in the past: PQ key history is append-only, backdating refused"
            }
            PqRegistryError::OversizedKey => {
                "PQ key bytes do not match the scheme's canonical size: refusing"
            }
            PqRegistryError::DisabledScheme => {
                "PQ scheme is disabled fail-closed (ML-DSA-44): submit Falcon-512 or Hybrid"
            }
            PqRegistryError::NoPendingRotation => "no PQ rotation is pending: nothing to apply",
            PqRegistryError::RotationNotDue => {
                "PQ rotation is not yet effective: apply at or after the announced effective height"
            }
        };
        write!(f, "{s}")
    }
}

impl std::error::Error for PqRegistryError {}

// ============================================================================
// Records
// ============================================================================

/// An announced-but-not-yet-effective PQ key rotation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingPqRotation {
    /// Key-type tag of the replacement key.
    pub scheme: PqScheme,
    /// Replacement public key bytes (exact `scheme.pubkey_size()`).
    pub pubkey: Vec<u8>,
    /// Height at which the rotation was announced.
    pub announced_height: u64,
    /// First height at which the replacement key is authoritative
    /// (`announced_height + `[`PQ_ROTATION_DELAY_HEIGHTS`]).
    pub effective_height: u64,
}

/// A superseded PQ key retained for late verification (equivocation
/// evidence, delayed votes). Valid exactly for
/// `activated_at <= height < superseded_at`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupersededPqKey {
    /// Key-type tag of the superseded key.
    pub scheme: PqScheme,
    /// Superseded public key bytes.
    pub pubkey: Vec<u8>,
    /// Height at which this key became authoritative.
    pub activated_at: u64,
    /// First height at which it stopped being authoritative.
    pub superseded_at: u64,
}

/// The tracked PQ key state for one validator: current key + key-type tag +
/// activation height + pending rotation + bounded superseded history.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqKeyRecord {
    /// Key-type tag of the current key.
    pub scheme: PqScheme,
    /// Current public key bytes (authoritative until a pending rotation's
    /// effective height).
    pub pubkey: Vec<u8>,
    /// Height at which the current key became authoritative.
    pub activated_at: u64,
    /// Announced rotation, if one is in flight.
    pub pending: Option<PendingPqRotation>,
    /// Superseded keys, oldest-first, capped at [`PQ_KEY_HISTORY_LIMIT`].
    pub history: Vec<SupersededPqKey>,
}

// ============================================================================
// Registry
// ============================================================================

/// Deterministic on-chain PQ key registry: validator id -> [`PqKeyRecord`].
///
/// `BTreeMap` (never `HashMap`) so iteration — e.g. the
/// [`PqRegistry::apply_due_rotations`] sweep — is identical on every node.
/// Pure state machine: validator-set membership arrives as an explicit
/// `validator_known` bool from the [`crate::staking::StakingLedger`] hooks,
/// keeping every transition a deterministic function of its inputs (no wall
/// clock, no env, no global state).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PqRegistry {
    keys: BTreeMap<ValidatorId, PqKeyRecord>,
}

impl PqRegistry {
    /// Empty registry (no tracked keys — the default-off posture).
    pub fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
        }
    }

    /// Number of validators with a tracked PQ key.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// True when no validator has a tracked PQ key.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The full tracked record for `validator`, if any.
    pub fn record_of(&self, validator: &ValidatorId) -> Option<&PqKeyRecord> {
        self.keys.get(validator)
    }

    /// The current key for `validator`, if tracked.
    pub fn current_key_of(&self, validator: &ValidatorId) -> Option<(PqScheme, Vec<u8>)> {
        self.keys
            .get(validator)
            .map(|r| (r.scheme, r.pubkey.clone()))
    }

    /// The pending rotation for `validator`, if one is in flight.
    pub fn pending_of(&self, validator: &ValidatorId) -> Option<&PendingPqRotation> {
        self.keys.get(validator).and_then(|r| r.pending.as_ref())
    }

    /// The superseded-key history for `validator` (oldest-first), if tracked.
    pub fn history_of(&self, validator: &ValidatorId) -> Option<&[SupersededPqKey]> {
        self.keys.get(validator).map(|r| r.history.as_slice())
    }

    /// Register a validator's FIRST PQ key.
    ///
    /// Effective at `activation_height` (may be `now` or the future — never
    /// the past). Fail-closed: unknown validator, existing record
    /// ([`PqRegistryError::AlreadyRegistered`] — rotate, do not re-register),
    /// disabled scheme, wrong-size key, or `activation_height < now_height`.
    pub fn register(
        &mut self,
        validator: ValidatorId,
        scheme: PqScheme,
        pubkey: Vec<u8>,
        activation_height: u64,
        now_height: u64,
        validator_known: bool,
    ) -> Result<(), PqRegistryError> {
        if !validator_known {
            return Err(PqRegistryError::UnknownValidator);
        }
        if self.keys.contains_key(&validator) {
            return Err(PqRegistryError::AlreadyRegistered);
        }
        validate_key_bytes(scheme, &pubkey)?;
        if activation_height < now_height {
            return Err(PqRegistryError::ActivationInPast);
        }
        self.keys.insert(
            validator,
            PqKeyRecord {
                scheme,
                pubkey,
                activated_at: activation_height,
                pending: None,
                history: Vec::new(),
            },
        );
        Ok(())
    }

    /// Adopt a pre-rotation key (genesis / legacy `register_pq_key` path)
    /// into rotation tracking WITHOUT changing its authority.
    ///
    /// The key was authoritative before rotation tracking existed, so
    /// `activated_at` is 0 (pre-tracking provenance — the widest truthful
    /// window, so old votes keep verifying). Same fail-closed gates as
    /// [`PqRegistry::register`] except the past check, which is vacuous for
    /// pre-tracking keys by construction. Refuses disabled schemes even for
    /// legacy keys: a forgeable scheme must never enter tracking.
    pub fn adopt_legacy_key(
        &mut self,
        validator: ValidatorId,
        scheme: PqScheme,
        pubkey: Vec<u8>,
        validator_known: bool,
    ) -> Result<(), PqRegistryError> {
        if !validator_known {
            return Err(PqRegistryError::UnknownValidator);
        }
        if self.keys.contains_key(&validator) {
            return Err(PqRegistryError::AlreadyRegistered);
        }
        validate_key_bytes(scheme, &pubkey)?;
        self.keys.insert(
            validator,
            PqKeyRecord {
                scheme,
                pubkey,
                activated_at: 0,
                pending: None,
                history: Vec::new(),
            },
        );
        Ok(())
    }

    /// Announce a PQ key rotation: the replacement takes effect at
    /// `now_height + `[`PQ_ROTATION_DELAY_HEIGHTS`]. The current key stays
    /// authoritative until then.
    ///
    /// Fail-closed: unknown validator (or no tracked key — `register` /
    /// [`PqRegistry::adopt_legacy_key`] first), disabled scheme, wrong-size
    /// key, backdated announcement (`now_height` before the current key's
    /// activation), or a rotation already in flight
    /// ([`PqRegistryError::RotationAlreadyPending`]).
    ///
    /// Cancelling: announcing a key IDENTICAL to the current one clears a
    /// pending rotation (no-op success, mirrors the commission
    /// announce-current-cancels rule) and succeeds with nothing pending.
    pub fn announce_rotation(
        &mut self,
        validator: ValidatorId,
        scheme: PqScheme,
        pubkey: Vec<u8>,
        now_height: u64,
        validator_known: bool,
    ) -> Result<(), PqRegistryError> {
        if !validator_known {
            return Err(PqRegistryError::UnknownValidator);
        }
        validate_key_bytes(scheme, &pubkey)?;
        let rec = self
            .keys
            .get_mut(&validator)
            .ok_or(PqRegistryError::UnknownValidator)?;
        if now_height < rec.activated_at {
            return Err(PqRegistryError::ActivationInPast);
        }
        if rec.scheme == scheme && rec.pubkey == pubkey {
            // Cancel-by-reannounce: the operator re-asserts the current key,
            // dropping a pending rotation that never took effect.
            rec.pending = None;
            return Ok(());
        }
        if rec.pending.is_some() {
            return Err(PqRegistryError::RotationAlreadyPending);
        }
        let effective_height = now_height.saturating_add(PQ_ROTATION_DELAY_HEIGHTS);
        rec.pending = Some(PendingPqRotation {
            scheme,
            pubkey,
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
    ) -> Result<(), PqRegistryError> {
        if !validator_known {
            return Err(PqRegistryError::UnknownValidator);
        }
        let rec = self
            .keys
            .get_mut(&validator)
            .ok_or(PqRegistryError::UnknownValidator)?;
        let pending = rec
            .pending
            .clone()
            .ok_or(PqRegistryError::NoPendingRotation)?;
        if now_height < pending.effective_height {
            return Err(PqRegistryError::RotationNotDue);
        }
        let old = SupersededPqKey {
            scheme: rec.scheme,
            pubkey: std::mem::take(&mut rec.pubkey),
            activated_at: rec.activated_at,
            superseded_at: pending.effective_height,
        };
        rec.scheme = pending.scheme;
        rec.pubkey = pending.pubkey;
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

    /// Resolve the authoritative PQ key for `validator` AT `height`.
    ///
    /// * pending rotation with `height >= effective_height` → pending key
    ///   (rotation has activated at this height, even if `apply` has not run
    ///   yet — readers never depend on apply timing);
    /// * else current key, if `height >= activated_at`;
    /// * else the superseded key whose `[activated_at, superseded_at)`
    ///   window contains `height` (late evidence under a retired key);
    /// * else `None` (unknown validator or height outside every validity
    ///   window — fail-closed).
    pub fn get_active_key(
        &self,
        validator: &ValidatorId,
        height: u64,
    ) -> Option<(PqScheme, Vec<u8>)> {
        let rec = self.keys.get(validator)?;
        if let Some(p) = &rec.pending {
            if height >= p.effective_height {
                return Some((p.scheme, p.pubkey.clone()));
            }
        }
        if height >= rec.activated_at {
            return Some((rec.scheme, rec.pubkey.clone()));
        }
        rec.history
            .iter()
            .find(|e| e.activated_at <= height && height < e.superseded_at)
            .map(|e| (e.scheme, e.pubkey.clone()))
    }

    /// Move a validator's whole PQ record to a new consensus id (call alongside
    /// [`crate::staking::StakingLedger::rotate_key`]: rotation state must
    /// travel with the record — same precedent as the jail / commission-schedule
    /// moves — otherwise a rekeyed validator strands its pending rotation and
    /// history under a dead id).
    ///
    /// No-op `Ok` when `old` has no tracked record. Refuses
    /// ([`PqRegistryError::AlreadyRegistered`], record restored untouched)
    /// when `new` already has one, so a migration can never merge or clobber.
    pub fn migrate_validator(
        &mut self,
        old: ValidatorId,
        new: ValidatorId,
    ) -> Result<(), PqRegistryError> {
        if old == new {
            return Err(PqRegistryError::AlreadyRegistered);
        }
        let rec = match self.keys.remove(&old) {
            None => return Ok(()),
            Some(r) => r,
        };
        if self.keys.contains_key(&new) {
            self.keys.insert(old, rec);
            return Err(PqRegistryError::AlreadyRegistered);
        }
        self.keys.insert(new, rec);
        Ok(())
    }
}

/// Enforce the bounded history: keep the newest [`PQ_KEY_HISTORY_LIMIT`]
/// entries (oldest-first order, evict from the front).
fn truncate_history(history: &mut Vec<SupersededPqKey>) {
    if history.len() > PQ_KEY_HISTORY_LIMIT {
        let excess = history.len() - PQ_KEY_HISTORY_LIMIT;
        history.drain(..excess);
    }
}

/// Fail-closed key admission: disabled schemes never enter tracking, and the
/// bytes must be EXACTLY the scheme's canonical size (which is always `<=`
/// [`PQ_MAX_KEY_BYTES`]).
fn validate_key_bytes(scheme: PqScheme, pubkey: &[u8]) -> Result<(), PqRegistryError> {
    if scheme.is_disabled() {
        return Err(PqRegistryError::DisabledScheme);
    }
    if pubkey.len() != scheme.pubkey_size() {
        return Err(PqRegistryError::OversizedKey);
    }
    debug_assert!(
        pubkey.len() <= PQ_MAX_KEY_BYTES,
        "canonical PQ key exceeds hard cap"
    );
    Ok(())
}

// ============================================================================
// Validator-signed announcement (future transaction path)
// ============================================================================

/// Preimage the validator's CONSENSUS (ed25519) key signs to authorize a PQ
/// key announcement: `DST || validator_id(32) || scheme_id(1) || pubkey ||
/// effective_height(8le)`.
///
/// Signed with the consensus key (whose bytes ARE the validator id), NOT the
/// current PQ key: rotation must survive PQ-key compromise, and a validator
/// with no PQ key yet (Ed25519 fallback) can still announce its first one.
/// The opcode handler verifies this signature and then calls the staking
/// hook — the hooks themselves take the validator id as the authenticated
/// caller (the `rotate_key` auth precedent).
pub fn pq_rotation_announcement_preimage(
    validator_id: &[u8; 32],
    scheme: PqScheme,
    pubkey: &[u8],
    effective_height: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(PQ_ROTATION_ANNOUNCE_DST.len() + 32 + 1 + pubkey.len() + 8);
    out.extend_from_slice(PQ_ROTATION_ANNOUNCE_DST);
    out.extend_from_slice(validator_id);
    out.push(scheme.id());
    out.extend_from_slice(pubkey);
    out.extend_from_slice(&effective_height.to_le_bytes());
    out
}

/// Verify a rotation-announcement signature against the validator's consensus
/// (ed25519) key. Thin alias over the standard ed25519 path — provided for
/// the future announcement opcode and pinned by tests here.
pub fn verify_rotation_announcement(
    consensus_id: &[u8; 32],
    scheme: PqScheme,
    pubkey: &[u8],
    effective_height: u64,
    ed_sig: &[u8],
) -> bool {
    crate::post_quantum::verify_pq_signature(
        crate::post_quantum::PqScheme::Ed25519,
        consensus_id,
        &pq_rotation_announcement_preimage(consensus_id, scheme, pubkey, effective_height),
        ed_sig,
    )
}
