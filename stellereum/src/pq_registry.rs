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
use crate::post_quantum::{
    verify_pq_signature, PqScheme, FALCON512_PUBKEY_LEN, FALCON512_SIG_LEN, MLDSA44_PUBKEY_LEN,
};

// ============================================================================
// Activation gate (Ruleset v7 — frozen at u64::MAX until R5)
// ============================================================================

/// Ruleset v7 PQ validator lifecycle activation height (`0` = active from genesis).
///
/// Activates 3-key separation with `withdrawal_address`, Falcon-512 PoP
/// rotation, explicit `cancel_rotation`, `next_seq` replay protection, and
/// 720k-height evidence retention.
pub const PQ_LIFECYCLE_ACTIVATION_HEIGHT: u64 = 0;

#[cfg(any(test, debug_assertions))]
thread_local! {
    static PQ_LIFECYCLE_ACTIVATION_OVERRIDE: std::cell::Cell<Option<u64>> =
        const { std::cell::Cell::new(None) };
}

/// Set (or clear with `None`) the TEST/DEBUG-ONLY `PQ_LIFECYCLE_ACTIVATION_HEIGHT`
/// override for the calling thread. Absent from release builds.
#[cfg(any(test, debug_assertions))]
pub fn set_pq_lifecycle_activation_override(activation: Option<u64>) {
    PQ_LIFECYCLE_ACTIVATION_OVERRIDE.with(|c| c.set(activation));
}

/// Effective `PQ_LIFECYCLE` activation height for the calling thread.
pub fn effective_pq_lifecycle_activation_height() -> u64 {
    #[cfg(any(test, debug_assertions))]
    if let Some(h) = PQ_LIFECYCLE_ACTIVATION_OVERRIDE.with(|c| c.get()) {
        return h;
    }
    PQ_LIFECYCLE_ACTIVATION_HEIGHT
}

/// True iff the Ruleset v7 PQ validator lifecycle is active at `height`.
///
/// Strictly returns `false` for every height (including `u64::MAX`) when the
/// effective gate is `u64::MAX` (`GatedOff`).
pub fn pq_lifecycle_active_at(height: u64) -> bool {
    let gate = effective_pq_lifecycle_activation_height();
    gate != u64::MAX && height >= gate
}

// ============================================================================
// Constants (consts in code — never env)
// ============================================================================

/// Rotation delay in heights: an announced PQ key takes effect this many
/// heights after the announcement.
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
/// RULESET v2: 30,000 heights x 240 ms = **7,200 s (2 h)** (the v1 value of
/// 7,200 heights had shrunk to ~28.8 min at the live tempo). Full table:
/// `docs/RULESET_V2.md`.
///
/// FREEZE (protocol freeze 2026-11-03): deterministic const, never env
/// (spec docs/specs/02_CRYPTO_AND_PQ_PHASE2.md §6, == CN-VRF EPOCH_LEN).
/// Change requires spec update + audit note (AGENTS.md §7).
pub const PQ_ROTATION_DELAY_HEIGHTS: u64 = 30_000;

/// Minimum number of superseded keys always retained per validator.
///
/// Pre-W3 hard cap; under W3 (`PQ_LIFECYCLE_ACTIVATION_HEIGHT`), acts as the
/// lower floor alongside [`PQ_EVIDENCE_RETENTION_HEIGHTS`] and
/// [`PQ_KEY_HISTORY_MAX_COUNT`].
pub const PQ_KEY_HISTORY_LIMIT: usize = 2;

/// Evidence retention window in heights under W3: equals 48h at 240 ms/block
/// (covering the full `UNBONDING_PERIOD_SECS = 172_800` slashing window).
pub const PQ_EVIDENCE_RETENTION_HEIGHTS: u64 = 720_000;

/// Hard DoS cap on retained superseded keys per validator under W3.
pub const PQ_KEY_HISTORY_MAX_COUNT: usize = 32;

/// Hard cap on any tracked PQ public key, in bytes.
///
/// Equals [`crate::post_quantum::MLDSA44_PUBKEY_LEN`] (1312 bytes), the
/// largest canonical key among the schemes in [`crate::post_quantum`].
/// ML-DSA-44 is disabled fail-closed (no verifier), so Falcon-512 (897) is
/// the only key size that can actually be registered today; the cap stays at
/// the enum-wide maximum so a future FIPS-204 verifier needs no cap change.
/// Every admission path additionally requires the EXACT per-scheme size
/// (`scheme.pubkey_size()`), so this cap is the outer bound and the exact
/// check is the inner one.
pub const PQ_MAX_KEY_BYTES: usize = MLDSA44_PUBKEY_LEN;

/// Domain tag for the legacy rotation-announcement preimage (retained only
/// until R3-D/F removes the old stub).
pub const PQ_ROTATION_ANNOUNCE_DST: &[u8] = b"STELL_PQ_ROTATE_V1";

/// Domain tag for the canonical Falcon-512 Proof-of-Possession (PoP) preimage
/// in `SysCallRegisterValidator` and `SysCallRotateVotingKey`.
pub const PQ_KEY_POP_DST: &[u8] = b"STELL_PQ_KEY_POP_V1";

/// Domain tag for deriving an immutable post-W3 `ValidatorId`.
pub const PQ_VAL_ID_DST: &[u8] = b"STELL_VAL_ID_V1";

/// Derive the immutable 32-byte `ValidatorId` for a newly registered post-W3
/// validator:
/// `BLAKE3("STELL_VAL_ID_V1" || chain_id.to_be_bytes() || withdrawal_address || initial_voting_pubkey)`.
pub fn derive_validator_id(
    chain_id: u64,
    withdrawal_address: &[u8; 32],
    initial_voting_pubkey: &[u8],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(PQ_VAL_ID_DST);
    h.update(&chain_id.to_be_bytes());
    h.update(withdrawal_address);
    h.update(initial_voting_pubkey);
    *h.finalize().as_bytes()
}

// ============================================================================
// Errors (fail-closed refusals)
// ============================================================================

/// Fail-closed refusal for a PQ registry write or PoP verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PqRegistryError {
    /// Validator is not in the validator set, or has no registered PQ key.
    UnknownValidator,
    /// `register` for an id that already has a tracked key (rotate instead).
    AlreadyRegistered,
    /// `announce_rotation` while a rotation is already pending (one flight
    /// at a time — cancel first, then re-announce).
    RotationAlreadyPending,
    /// Backdated activation: `register` with `activation_height < now`, or
    /// `announce_rotation` with `now` before the current key's activation
    /// (history must never be rewritten).
    ActivationInPast,
    /// Key bytes do not match the scheme's canonical size (outer bound:
    /// [`PQ_MAX_KEY_BYTES`]).
    OversizedKey,
    /// Scheme is disabled fail-closed ([`PqScheme::is_disabled`], today
    /// ML-DSA-44 or removed classical schemes 0x01/0x04).
    DisabledScheme,
    /// `apply_rotation` or `cancel_rotation` with nothing pending.
    NoPendingRotation,
    /// `apply_rotation` before the announced effective height.
    RotationNotDue,
    /// Announced replacement key is identical to the validator's current key.
    SameKey,
    /// Key is already registered or pending for another validator.
    DuplicateKey,
    /// Supplied `rotation_seq` does not match `PqKeyRecord::next_seq`.
    InvalidRotationSeq { expected: u64, got: u64 },
    /// Height or sequence arithmetic overflowed `u64::MAX`.
    ArithmeticOverflow,
    /// `cancel_rotation` attempted at or after `pending.effective_height`.
    RotationAlreadyEffective,
    /// Falcon-512 public key lacks the canonical `0x09` header byte.
    InvalidPubkeyHeader,
    /// PoP signature has wrong length or failed `verify_pq_signature`.
    InvalidPopSignature,
}

impl std::fmt::Display for PqRegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PqRegistryError::UnknownValidator => write!(
                f,
                "unknown validator (not in validator set or no registered PQ key): refusing"
            ),
            PqRegistryError::AlreadyRegistered => write!(
                f,
                "validator already has a registered PQ key: rotate, do not re-register"
            ),
            PqRegistryError::RotationAlreadyPending => write!(
                f,
                "a PQ rotation is already pending: one flight at a time (cancel pending rotation first)"
            ),
            PqRegistryError::ActivationInPast => write!(
                f,
                "activation height is in the past: PQ key history is append-only, backdating refused"
            ),
            PqRegistryError::OversizedKey => write!(
                f,
                "PQ key bytes do not match the scheme's canonical size: refusing"
            ),
            PqRegistryError::DisabledScheme => write!(
                f,
                "PQ scheme is disabled fail-closed: only Falcon-512 (0x02) is accepted"
            ),
            PqRegistryError::NoPendingRotation => {
                write!(f, "no PQ rotation is pending: nothing to apply or cancel")
            }
            PqRegistryError::RotationNotDue => write!(
                f,
                "PQ rotation is not yet effective: apply at or after the announced effective height"
            ),
            PqRegistryError::SameKey => write!(
                f,
                "replacement PQ key matches the validator's current active key: refusing"
            ),
            PqRegistryError::DuplicateKey => write!(
                f,
                "PQ public key is already registered or pending for another validator: refusing"
            ),
            PqRegistryError::InvalidRotationSeq { expected, got } => write!(
                f,
                "invalid PQ rotation sequence number: expected {expected}, got {got}"
            ),
            PqRegistryError::ArithmeticOverflow => {
                write!(f, "PQ registry height or sequence arithmetic overflow")
            }
            PqRegistryError::RotationAlreadyEffective => write!(
                f,
                "pending PQ rotation is already effective at current height: cannot cancel"
            ),
            PqRegistryError::InvalidPubkeyHeader => write!(
                f,
                "Falcon-512 public key lacks canonical 0x09 header byte: refusing"
            ),
            PqRegistryError::InvalidPopSignature => {
                write!(f, "PQ voting key Proof-of-Possession signature is invalid")
            }
        }
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
/// activation height + pending rotation + bounded superseded history +
/// monotonic replay-protection sequence.
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
    /// Superseded keys, oldest-first, pruned per [`PQ_EVIDENCE_RETENTION_HEIGHTS`]
    /// and capped at [`PQ_KEY_HISTORY_MAX_COUNT`].
    pub history: Vec<SupersededPqKey>,
    /// Next expected rotation/cancel sequence number (`0` is reserved for
    /// initial registration, so active records start at `next_seq = 1`).
    #[serde(default)]
    pub next_seq: u64,
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

    /// Deterministic `BTreeMap` view of all tracked validator records.
    pub fn records(&self) -> &BTreeMap<ValidatorId, PqKeyRecord> {
        &self.keys
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

    /// Returns true if `(scheme, pubkey)` is currently active or pending on
    /// any validator other than `exclude_validator`.
    fn key_used_by_other(
        &self,
        exclude_validator: &ValidatorId,
        scheme: PqScheme,
        pubkey: &[u8],
    ) -> bool {
        self.keys.iter().any(|(id, rec)| {
            if id == exclude_validator {
                return false;
            }
            if rec.scheme == scheme && rec.pubkey.as_slice() == pubkey {
                return true;
            }
            rec.pending
                .as_ref()
                .is_some_and(|p| p.scheme == scheme && p.pubkey.as_slice() == pubkey)
        })
    }

    /// Register a validator's FIRST PQ key with an explicit initial sequence
    /// number (`seq = 0` for canonical registration, advancing `next_seq` to `1`).
    ///
    /// Rejects duplicate keys already registered or pending on another validator
    /// ([`PqRegistryError::DuplicateKey`]).
    #[allow(clippy::too_many_arguments)]
    // GATE: pure state-machine entry taking explicit (validator, scheme, pubkey, two heights, seq, membership).
    pub fn register_with_seq(
        &mut self,
        validator: ValidatorId,
        scheme: PqScheme,
        pubkey: Vec<u8>,
        activation_height: u64,
        now_height: u64,
        seq: u64,
        validator_known: bool,
    ) -> Result<(), PqRegistryError> {
        if !validator_known {
            return Err(PqRegistryError::UnknownValidator);
        }
        if self.keys.contains_key(&validator) {
            return Err(PqRegistryError::AlreadyRegistered);
        }
        validate_key_bytes(scheme, &pubkey)?;
        if self.key_used_by_other(&validator, scheme, &pubkey) {
            return Err(PqRegistryError::DuplicateKey);
        }
        if activation_height < now_height {
            return Err(PqRegistryError::ActivationInPast);
        }
        let next_seq = seq
            .checked_add(1)
            .ok_or(PqRegistryError::ArithmeticOverflow)?;
        self.keys.insert(
            validator,
            PqKeyRecord {
                scheme,
                pubkey,
                activated_at: activation_height,
                pending: None,
                history: Vec::new(),
                next_seq,
            },
        );
        Ok(())
    }

    /// Register a validator's FIRST PQ key (`seq = 0`, `next_seq = 1`).
    ///
    /// Effective at `activation_height` (may be `now` or the future — never
    /// the past). Fail-closed: unknown validator, existing record
    /// ([`PqRegistryError::AlreadyRegistered`] — rotate, do not re-register),
    /// duplicate key on another validator, disabled scheme, wrong-size key,
    /// or `activation_height < now_height`.
    pub fn register(
        &mut self,
        validator: ValidatorId,
        scheme: PqScheme,
        pubkey: Vec<u8>,
        activation_height: u64,
        now_height: u64,
        validator_known: bool,
    ) -> Result<(), PqRegistryError> {
        self.register_with_seq(
            validator,
            scheme,
            pubkey,
            activation_height,
            now_height,
            0,
            validator_known,
        )
    }

    /// Adopt a pre-rotation key (genesis / legacy `register_pq_key` path)
    /// into rotation tracking WITHOUT changing its authority (`activated_at = 0`,
    /// `next_seq = 1`).
    ///
    /// The key was authoritative before rotation tracking existed, so
    /// `activated_at` is 0 (pre-tracking provenance — the widest truthful
    /// window, so old votes keep verifying). Refuses disabled schemes even for
    /// legacy keys: a forgeable scheme must never enter tracking.
    pub fn adopt_legacy_key(
        &mut self,
        validator: ValidatorId,
        scheme: PqScheme,
        pubkey: Vec<u8>,
        validator_known: bool,
    ) -> Result<(), PqRegistryError> {
        self.adopt_legacy_key_at(validator, scheme, pubkey, 0, validator_known)
    }

    /// Adopt a legacy key into rotation tracking at an explicit `at_height`
    /// with `next_seq = 1` (used for deterministic pre-W3 -> W3 migration).
    pub fn adopt_legacy_key_at(
        &mut self,
        validator: ValidatorId,
        scheme: PqScheme,
        pubkey: Vec<u8>,
        at_height: u64,
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
                activated_at: at_height,
                pending: None,
                history: Vec::new(),
                next_seq: 1,
            },
        );
        Ok(())
    }

    /// Announce a PQ key rotation with strict W3 replay/uniqueness checks:
    /// - verifies `rotation_seq == rec.next_seq`
    /// - forbids rotating to the validator's own current key (`SameKey`)
    /// - forbids using a key registered or pending on another validator (`DuplicateKey`)
    /// - uses `now_height.checked_add(PQ_ROTATION_DELAY_HEIGHTS)` (`ArithmeticOverflow`)
    /// - increments `rec.next_seq` via `checked_add(1)`
    pub fn announce_rotation_seq(
        &mut self,
        validator: ValidatorId,
        scheme: PqScheme,
        pubkey: Vec<u8>,
        now_height: u64,
        rotation_seq: u64,
        validator_known: bool,
    ) -> Result<(), PqRegistryError> {
        if !validator_known {
            return Err(PqRegistryError::UnknownValidator);
        }
        validate_key_bytes(scheme, &pubkey)?;
        {
            let rec = self
                .keys
                .get(&validator)
                .ok_or(PqRegistryError::UnknownValidator)?;
            if now_height < rec.activated_at {
                return Err(PqRegistryError::ActivationInPast);
            }
            if rotation_seq != rec.next_seq {
                return Err(PqRegistryError::InvalidRotationSeq {
                    expected: rec.next_seq,
                    got: rotation_seq,
                });
            }
            if rec.scheme == scheme && rec.pubkey == pubkey {
                return Err(PqRegistryError::SameKey);
            }
            if rec.pending.is_some() {
                return Err(PqRegistryError::RotationAlreadyPending);
            }
        }
        if self.key_used_by_other(&validator, scheme, &pubkey) {
            return Err(PqRegistryError::DuplicateKey);
        }
        let effective_height = now_height
            .checked_add(PQ_ROTATION_DELAY_HEIGHTS)
            .ok_or(PqRegistryError::ArithmeticOverflow)?;
        let rec = self
            .keys
            .get_mut(&validator)
            .ok_or(PqRegistryError::UnknownValidator)?;
        let next_seq = rec
            .next_seq
            .checked_add(1)
            .ok_or(PqRegistryError::ArithmeticOverflow)?;
        rec.next_seq = next_seq;
        rec.pending = Some(PendingPqRotation {
            scheme,
            pubkey,
            announced_height: now_height,
            effective_height,
        });
        Ok(())
    }

    /// Announce a PQ key rotation (compatibility wrapper for pre-W3 callers in
    /// `staking.rs` and `consensus/rotation.rs` until R3-B..F).
    ///
    /// When [`pq_lifecycle_active_at`] is `true` at `now_height`, enforces strict
    /// W3 semantics (delegating to [`Self::announce_rotation_seq`]). When
    /// `PQ_LIFECYCLE_ACTIVATION_HEIGHT` is gated off (`u64::MAX`), preserves
    /// pre-W3 compatibility (including cancel-by-reannounce).
    pub fn announce_rotation(
        &mut self,
        validator: ValidatorId,
        scheme: PqScheme,
        pubkey: Vec<u8>,
        now_height: u64,
        validator_known: bool,
    ) -> Result<(), PqRegistryError> {
        if pq_lifecycle_active_at(now_height) {
            if !validator_known {
                return Err(PqRegistryError::UnknownValidator);
            }
            let seq = self
                .keys
                .get(&validator)
                .map(|r| r.next_seq)
                .ok_or(PqRegistryError::UnknownValidator)?;
            return self.announce_rotation_seq(
                validator,
                scheme,
                pubkey,
                now_height,
                seq,
                validator_known,
            );
        }
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
            // Pre-W3 compatibility: cancel-by-reannounce when gated off.
            rec.pending = None;
            return Ok(());
        }
        if rec.pending.is_some() {
            return Err(PqRegistryError::RotationAlreadyPending);
        }
        let effective_height = now_height
            .checked_add(PQ_ROTATION_DELAY_HEIGHTS)
            .ok_or(PqRegistryError::ArithmeticOverflow)?;
        let next_seq = rec
            .next_seq
            .checked_add(1)
            .ok_or(PqRegistryError::ArithmeticOverflow)?;
        rec.next_seq = next_seq;
        rec.pending = Some(PendingPqRotation {
            scheme,
            pubkey,
            announced_height: now_height,
            effective_height,
        });
        Ok(())
    }

    /// Explicitly cancel a pending rotation before it takes effect.
    ///
    /// Fail-closed: only allowed when `rec.pending.is_some()` AND
    /// `now_height < pending.effective_height` (otherwise returns
    /// [`PqRegistryError::RotationAlreadyEffective`]), verifies
    /// `rotation_seq == rec.next_seq`, and increments `rec.next_seq`.
    pub fn cancel_rotation(
        &mut self,
        validator: ValidatorId,
        now_height: u64,
        rotation_seq: u64,
        validator_known: bool,
    ) -> Result<(), PqRegistryError> {
        if !validator_known {
            return Err(PqRegistryError::UnknownValidator);
        }
        let rec = self
            .keys
            .get_mut(&validator)
            .ok_or(PqRegistryError::UnknownValidator)?;
        if rotation_seq != rec.next_seq {
            return Err(PqRegistryError::InvalidRotationSeq {
                expected: rec.next_seq,
                got: rotation_seq,
            });
        }
        let pending = rec
            .pending
            .as_ref()
            .ok_or(PqRegistryError::NoPendingRotation)?;
        if now_height >= pending.effective_height {
            return Err(PqRegistryError::RotationAlreadyEffective);
        }
        let next_seq = rec
            .next_seq
            .checked_add(1)
            .ok_or(PqRegistryError::ArithmeticOverflow)?;
        rec.next_seq = next_seq;
        rec.pending = None;
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
        truncate_history(&mut rec.history, now_height);
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

    /// Canonical W3 alias for [`Self::get_active_key`].
    pub fn pq_key_at_height(
        &self,
        validator: &ValidatorId,
        height: u64,
    ) -> Option<(PqScheme, Vec<u8>)> {
        self.get_active_key(validator, height)
    }

    /// Resolve the authoritative PQ key for `validator` AT `height`, enforcing
    /// that any superseded key is still within [`PQ_EVIDENCE_RETENTION_HEIGHTS`]
    /// relative to `now_height` (`now_height.saturating_sub(superseded_at) <
    /// PQ_EVIDENCE_RETENTION_HEIGHTS`) and rejecting future heights
    /// (`height > now_height`).
    pub fn pq_key_at_height_within_retention(
        &self,
        validator: &ValidatorId,
        height: u64,
        now_height: u64,
    ) -> Option<(PqScheme, Vec<u8>)> {
        if height > now_height {
            return None;
        }
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
            .find(|e| {
                e.activated_at <= height
                    && height < e.superseded_at
                    && now_height.saturating_sub(e.superseded_at) < PQ_EVIDENCE_RETENTION_HEIGHTS
            })
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

/// Enforce the W3 retention + hard-cap history bounds:
/// keep every [`SupersededPqKey`] within [`PQ_EVIDENCE_RETENTION_HEIGHTS`] of
/// `now_height`, always retaining at least [`PQ_KEY_HISTORY_LIMIT`] (2) newest
/// entries, and capping at [`PQ_KEY_HISTORY_MAX_COUNT`] (32).
pub fn truncate_superseded_history(history: &mut Vec<SupersededPqKey>, now_height: u64) {
    while history.len() > PQ_KEY_HISTORY_LIMIT {
        if now_height.saturating_sub(history[0].superseded_at) >= PQ_EVIDENCE_RETENTION_HEIGHTS {
            history.remove(0);
        } else {
            break;
        }
    }
    if history.len() > PQ_KEY_HISTORY_MAX_COUNT {
        let excess = history.len() - PQ_KEY_HISTORY_MAX_COUNT;
        history.drain(..excess);
    }
}

/// Gate-aware history truncation: preserves pre-W3 `PQ_KEY_HISTORY_LIMIT`
/// behavior while `PQ_LIFECYCLE_ACTIVATION_HEIGHT` is gated off, and applies
/// [`truncate_superseded_history`] once active.
fn truncate_history(history: &mut Vec<SupersededPqKey>, now_height: u64) {
    if !pq_lifecycle_active_at(now_height) {
        if history.len() > PQ_KEY_HISTORY_LIMIT {
            let excess = history.len() - PQ_KEY_HISTORY_LIMIT;
            history.drain(..excess);
        }
        return;
    }
    truncate_superseded_history(history, now_height);
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
// Canonical Falcon-512 Proof-of-Possession (PoP)
// ============================================================================

/// Canonical preimage signed by a new Falcon-512 voting key to prove
/// possession in `SysCallRegisterValidator` (`rotation_seq = 0`) and
/// `SysCallRotateVotingKey`:
/// ```text
/// PQ_KEY_POP_DST (19B: b"STELL_PQ_KEY_POP_V1")
/// || chain_id.to_be_bytes()                 (8B)
/// || validator_id                           (32B)
/// || withdrawal_address                     (32B)
/// || rotation_seq.to_be_bytes()             (8B)
/// || scheme.id()                            (1B = 0x02)
/// || (pubkey.len() as u16).to_be_bytes()    (2B = 897)
/// || pubkey                                 (897B)
/// ```
pub fn pq_voting_key_pop_preimage(
    chain_id: u64,
    validator_id: &[u8; 32],
    withdrawal_address: &[u8; 32],
    rotation_seq: u64,
    scheme: PqScheme,
    pubkey: &[u8],
) -> Vec<u8> {
    let pk_len = u16::try_from(pubkey.len()).unwrap_or(u16::MAX);
    let mut out = Vec::with_capacity(PQ_KEY_POP_DST.len() + 8 + 32 + 32 + 8 + 1 + 2 + pubkey.len());
    out.extend_from_slice(PQ_KEY_POP_DST);
    out.extend_from_slice(&chain_id.to_be_bytes());
    out.extend_from_slice(validator_id);
    out.extend_from_slice(withdrawal_address);
    out.extend_from_slice(&rotation_seq.to_be_bytes());
    out.push(scheme.id());
    out.extend_from_slice(&pk_len.to_be_bytes());
    out.extend_from_slice(pubkey);
    out
}

/// Verify a Falcon-512 Proof-of-Possession signature for a new voting key.
///
/// Enforces fail-closed:
/// 1. `scheme_id` decodes to `PqScheme::Falcon512` (`0x02`; refuses `0x01`, `0x03`, `0x04`).
/// 2. `pubkey.len() == FALCON512_PUBKEY_LEN` (`897`) and `pubkey[0] == 0x09`.
/// 3. `pop_signature.len() == FALCON512_SIG_LEN` (`666`).
/// 4. `verify_pq_signature(PqScheme::Falcon512, pubkey, &preimage, pop_signature)` is `true`.
pub fn verify_voting_key_pop(
    chain_id: u64,
    validator_id: &[u8; 32],
    withdrawal_address: &[u8; 32],
    rotation_seq: u64,
    scheme_id: u8,
    pubkey: &[u8],
    pop_signature: &[u8],
) -> Result<(), PqRegistryError> {
    let scheme = PqScheme::from_id(scheme_id).map_err(|_| PqRegistryError::DisabledScheme)?;
    if scheme != PqScheme::Falcon512 || scheme.is_disabled() {
        return Err(PqRegistryError::DisabledScheme);
    }
    if pubkey.len() != FALCON512_PUBKEY_LEN {
        return Err(PqRegistryError::OversizedKey);
    }
    if pubkey[0] != 0x09 {
        return Err(PqRegistryError::InvalidPubkeyHeader);
    }
    if pop_signature.len() != FALCON512_SIG_LEN {
        return Err(PqRegistryError::InvalidPopSignature);
    }
    let preimage = pq_voting_key_pop_preimage(
        chain_id,
        validator_id,
        withdrawal_address,
        rotation_seq,
        scheme,
        pubkey,
    );
    if !verify_pq_signature(PqScheme::Falcon512, pubkey, &preimage, pop_signature) {
        return Err(PqRegistryError::InvalidPopSignature);
    }
    Ok(())
}

// ============================================================================
// Legacy Ed25519 stub (kept only until R3-D/F migrates tests/pq_registry_tests.rs)
// ============================================================================

/// LEGACY STUB (do not use in new code; replaced by [`pq_voting_key_pop_preimage`]):
/// Preimage a validator's consensus identity key would sign to authorize a PQ
/// key announcement: `DST || validator_id(32) || scheme_id(1) || pubkey ||
/// effective_height(8le)`.
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

/// LEGACY STUB (always returns `false`; replaced by [`verify_voting_key_pop`]):
/// retained until R3-D/F updates `tests/pq_registry_tests.rs`.
pub fn verify_rotation_announcement(
    consensus_id: &[u8; 32],
    scheme: PqScheme,
    pubkey: &[u8],
    effective_height: u64,
    ed_sig: &[u8],
) -> bool {
    let _ = (consensus_id, scheme, pubkey, effective_height, ed_sig);
    false
}
