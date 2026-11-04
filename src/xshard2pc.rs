//! §9 CROSS-SHARD TWO-PHASE COMMIT (2PC) for native value transfers.
//!
//! # Why this module exists
//!
//! The M2/M3 cross-shard flow is a **one-way outbox → inbox** pipeline with an
//! ack and a *unilateral* timeout bounce:
//!
//! ```text
//! SOURCE S                          TARGET T
//!   commit Transfer  ──────────────▶  commit Transfer  (credits the recipient)
//!         │                                   │
//!         │                                   └── ack ──▶ S commits the ack
//!         └── timeout (64 heights) ──▶ commit Bounce (refunds the sender)
//! ```
//!
//! Both decisions are made by the SOURCE shard alone, and the target's credit
//! happens *before* the source learns that the credit happened. A malicious
//! (Byzantine) source shard can therefore observe the credit on the target and
//! then bounce the very same transfer: the value is minted on the target AND
//! refunded on the source. That is a cross-shard double spend, and the design
//! is safe only while the source shard is honest.
//!
//! # The 2PC that replaces it
//!
//! ```text
//!   S: PREPARE ────────────▶ T: validates the proof, records PREPARED
//!   S: (escrow)                                    │
//!   S: ◀──────── PREPARE-ACK (T's quorum-signed vote, proven against T's
//!   S:               committed state)              │
//!   S: COMMIT ───────────▶ T: records COMMITTED, credits the recipient
//!
//!   S: ABORT-REQUEST ─────▶ T: NOT prepared → records ABORTED, replies
//!   S: ◀──────── ABORT-ACK  (proven against T's committed state)
//!   S: ABORTED (refund the escrow)
//! ```
//!
//! Three properties make the decision ATOMIC and UNAMBIGUOUS:
//!
//! 1. **The target never credits on a bare transfer.** It credits only on a
//!    COMMIT that is proven against the SOURCE's committed state (the source
//!    really escrowed the value) — and only if the target itself is already
//!    PREPARED for that message id.
//! 2. **The target never aborts a transfer it has prepared.** Once the target
//!    is PREPARED it has voted YES, and a 2PC participant that has voted YES
//!    must eventually COMMIT. So the target can only reach ABORTED from
//!    "never prepared", and the ABORTED state therefore *proves* that the
//!    target never prepared.
//! 3. **The source may only abort with the target's authorisation.** The
//!    source's ABORT is admissible only when it carries the target's ABORT-ACK
//!    — a proof, anchored to a finalized target header, of the target's
//!    ABORTED record. The target's committed state can hold either PREPARED
//!    or ABORTED for a message id, never both, and an honest target that
//!    prepared can never produce the ABORT-ACK. So a source that prepared
//!    successfully **cannot** abort, and the audit's double spend is
//!    unreachable.
//!
//! The state machine is MONOTONE: `Prepared → Committed | Aborted`, decided
//! once, on the shard that owns the record. A node that crashes mid-2PC
//! resumes from the persisted record and reaches the SAME decision.
//!
//! # What is NOT here
//!
//! * The legacy outbox/inbox/ack/bounce flow is untouched and still runs for
//!   transfers produced before the activation height
//!   ([`XpcActivation`]).
//! * The liveness cost is real and deliberate: a transfer whose target shard
//!   is unreachable stays ESCROWED (the value is neither credited nor
//!   refunded) until the target answers. That is the price of not letting the
//!   source decide unilaterally.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::sharding::ShardId;

/// The domain separator for the 2PC state leaves in the state trie.
pub const XPC_STATE_TAG: &[u8; 9] = b"XSHARD2PC";

/// The legacy phase: the message is a pre-2PC record and its kind is derived
/// from the direction and the legacy `bounce` / `bounced` flags.
pub const XPC_LEGACY: u8 = 0;
/// PREPARE: source → target, carries the source's account-leaf proof.
pub const XPC_PREPARE: u8 = 1;
/// PREPARE-ACK: target → source, carries the proof of the target's PREPARED
/// record in the target's committed state.
pub const XPC_PREPARE_ACK: u8 = 2;
/// COMMIT: source → target, carries the proof of the source's PREPARED (or
/// COMMITTED) record in the source's committed state.
pub const XPC_COMMIT: u8 = 3;
/// ABORT-REQUEST: source → target, asks the target to abort a transfer it
/// never prepared.
pub const XPC_ABORT_REQUEST: u8 = 4;
/// ABORT-ACK: target → source, carries the proof of the target's ABORTED
/// record — the source's authorisation to refund the escrow.
pub const XPC_ABORT_ACK: u8 = 5;

/// The number of source-shard heights the source waits for a PREPARE-ACK
/// before it may ask the target to abort.
///
/// The window is deliberately generous: the target needs one block to prepare
/// and one more to publish its ack, so a healthy exchange completes in two
/// heights. The window is a LIVENESS parameter only — it can never make the
/// abort unsafe, because the abort additionally requires the target's
/// ABORT-ACK.
pub const XPC_PREPARE_TIMEOUT_HEIGHTS: u64 = 64;

/// The phase of one 2PC transfer, as recorded by the shard that owns it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum XpcPhase {
    /// The transfer is prepared: the value is escrowed (source) or the
    /// participant has voted YES and waits for the decision (target).
    Prepared,
    /// The transfer is decided COMMITTED. On the target this is the phase in
    /// which the recipient is credited; on the source it means the escrow is
    /// released.
    Committed,
    /// The transfer is decided ABORTED. On the target this means the target
    /// never prepared it (and never credited it); on the source it means the
    /// escrow is refunded.
    Aborted,
}

impl XpcPhase {
    /// The wire code of the phase (the byte stored in the state leaf).
    pub fn code(self) -> u8 {
        match self {
            XpcPhase::Prepared => 1,
            XpcPhase::Committed => 2,
            XpcPhase::Aborted => 3,
        }
    }

    /// Decode a phase code. `None` for an unknown code (fail closed).
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(XpcPhase::Prepared),
            2 => Some(XpcPhase::Committed),
            3 => Some(XpcPhase::Aborted),
            _ => None,
        }
    }
}

/// The committed 2PC state of ONE transfer, as held by the shard that owns
/// the record (the source for a source-owned record, the target for a
/// target-owned record).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct XpcRecord {
    /// The transfer itself. The record keeps the WHOLE transaction because
    /// both sides must be able to rebuild the cross-shard records of the
    /// transfer after a restart: the target has to answer a PREPARE with a
    /// PREPARE-ACK, and the target never produced the transaction.
    pub tx: crate::sharding::Transaction,
    /// The transaction hash — the 2PC identity of the transfer. The
    /// transaction commits to the source and target shard ids, so the hash
    /// binds the whole transfer.
    pub tx_hash: [u8; 32],
    pub source_shard: ShardId,
    pub target_shard: ShardId,
    /// The current phase. MONOTONE: it moves `Prepared → Committed` or
    /// `Prepared → Aborted` exactly once and never back.
    pub phase: XpcPhase,
    /// The height at which this shard recorded the PREPARED phase.
    pub prepared_height: u64,
    /// The height at which this shard recorded the decision (0 while the
    /// transfer is still prepared).
    pub decided_height: u64,
}

impl XpcRecord {
    /// A fresh PREPARED record.
    pub fn prepared(
        tx: crate::sharding::Transaction,
        source_shard: ShardId,
        target_shard: ShardId,
        height: u64,
    ) -> Self {
        let tx_hash = tx.compute_tx_hash();
        Self {
            tx,
            tx_hash,
            source_shard,
            target_shard,
            phase: XpcPhase::Prepared,
            prepared_height: height,
            decided_height: 0,
        }
    }

    /// The sender of the transfer.
    pub fn from(&self) -> [u8; 32] {
        self.tx.from
    }

    /// The recipient of the transfer.
    pub fn to(&self) -> [u8; 32] {
        self.tx.to
    }

    /// The transferred amount.
    pub fn amount(&self) -> u64 {
        self.tx.amount
    }
}

/// The trie key of the 2PC state leaf of one transfer.
///
/// The key is derived from the TRANSACTION HASH, not from the message id: the
/// message id changes with the carrier block (so it differs per phase and per
/// re-emission), while the transaction hash is the stable identity of the
/// transfer across every phase and on every shard.
pub fn xpc_state_key(tx_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(XPC_STATE_TAG);
    h.update(tx_hash);
    h.finalize().into()
}

/// The trie VALUE of the 2PC state leaf: the phase code followed by the
/// transaction hash.
///
/// The value is fully reconstructible by a verifier that holds the message
/// (the phase comes from the message kind, the transaction hash from the
/// carried transaction), which is what makes the leaf provable.
pub fn xpc_state_value(phase: XpcPhase, tx_hash: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(33);
    v.push(phase.code());
    v.extend_from_slice(tx_hash);
    v
}

/// The activation switch: from which height NEW cross-shard transfers use the
/// 2PC instead of the legacy outbox/inbox/ack/bounce flow.
///
/// `Disabled` keeps the legacy flow for every transfer — the mode the
/// already-deployed chain state runs in, and the mode the pre-2PC
/// integration tests exercise. `FromHeight(h)` switches transfers PRODUCED at
/// height `h` or later to the 2PC; transfers produced before `h` keep
/// running the legacy flow to completion, so the two never interleave on one
/// transfer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum XpcActivation {
    /// The 2PC is off (legacy flow only).
    #[default]
    Disabled,
    /// The 2PC is on for transfers produced at height >= the boundary.
    FromHeight(u64),
}

impl XpcActivation {
    /// True when a transfer produced at `height` must use the 2PC.
    pub fn is_active_at(&self, height: u64) -> bool {
        match *self {
            XpcActivation::Disabled => false,
            XpcActivation::FromHeight(h) => height >= h,
        }
    }

    /// The activation boundary height, if the 2PC is on.
    pub fn boundary(&self) -> Option<u64> {
        match *self {
            XpcActivation::Disabled => None,
            XpcActivation::FromHeight(h) => Some(h),
        }
    }
}

/// The verdict of a 2PC state transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XpcTransition {
    /// The record did not exist and was created in the PREPARED phase.
    Created,
    /// The record advanced to the given phase.
    Advanced(XpcPhase),
    /// The record was already in a state that makes the transition a no-op
    /// (a replay of an already-applied record).
    Noop,
    /// The transition is refused: it would break the atomicity invariant
    /// (e.g. committing an ABORTED transfer, or aborting a COMMITTED one).
    Refused(&'static str),
}

impl XpcTransition {
    /// True when the transition changed the committed state.
    pub fn changed(self) -> bool {
        matches!(self, XpcTransition::Created | XpcTransition::Advanced(_))
    }
}

/// The SOURCE-side transition: the source prepared the transfer and escrowed
/// the value.
///
/// Idempotent: a replayed PREPARE for a transfer that is already prepared (or
/// already decided) is a no-op, never a re-escrow.
pub fn source_prepare(existing: Option<&XpcRecord>) -> XpcTransition {
    match existing {
        None => XpcTransition::Created,
        Some(rec) => {
            if rec.phase == XpcPhase::Prepared {
                XpcTransition::Noop
            } else {
                // Already decided: a late PREPARE must not reopen the
                // lifecycle (it would let a second escrow happen).
                XpcTransition::Refused("transfer already decided")
            }
        }
    }
}

/// The SOURCE-side transition: the target's PREPARE-ACK arrived, so the
/// source commits the transfer and releases the escrow.
///
/// A transfer that is already ABORTED is refused: the target voted NO (it
/// never prepared), so it will never credit, and a late ack must not reopen
/// it. A transfer that is already COMMITTED is a no-op (idempotent replay).
pub fn source_on_prepare_ack(existing: Option<&XpcRecord>) -> XpcTransition {
    match existing {
        None => XpcTransition::Refused("prepare-ack without a prepared record"),
        Some(rec) => match rec.phase {
            XpcPhase::Prepared => XpcTransition::Advanced(XpcPhase::Committed),
            XpcPhase::Committed => XpcTransition::Noop,
            XpcPhase::Aborted => XpcTransition::Refused("transfer already aborted"),
        },
    }
}

/// The SOURCE-side transition: the target's ABORT-ACK arrived, so the source
/// aborts the transfer and refunds the escrow.
///
/// A transfer that is already COMMITTED is REFUSED: this is the double-spend
/// attempt. The source has released the escrow and the target has voted YES,
/// so a refund now would mint the value twice. The refusal is the whole point
/// of the 2PC.
pub fn source_on_abort_ack(existing: Option<&XpcRecord>) -> XpcTransition {
    match existing {
        None => XpcTransition::Refused("abort-ack without a prepared record"),
        Some(rec) => match rec.phase {
            XpcPhase::Prepared => XpcTransition::Advanced(XpcPhase::Aborted),
            XpcPhase::Committed => XpcTransition::Refused("transfer already committed"),
            XpcPhase::Aborted => XpcTransition::Noop,
        },
    }
}

/// The TARGET-side transition: the source's PREPARE arrived and validated.
///
/// The target records PREPARED and votes YES. It never moves out of PREPARED
/// except through a decision, so a replayed PREPARE is a no-op and a PREPARE
/// for an already-decided transfer is refused.
pub fn target_prepare(existing: Option<&XpcRecord>) -> XpcTransition {
    match existing {
        None => XpcTransition::Created,
        Some(rec) => {
            if rec.phase == XpcPhase::Prepared {
                XpcTransition::Noop
            } else {
                XpcTransition::Refused("transfer already decided")
            }
        }
    }
}

/// The TARGET-side transition: the source's COMMIT arrived, so the target
/// commits the transfer AND CREDITS the recipient.
///
/// This is the ONLY transition that moves value on the target, and it is
/// reachable only from PREPARED — so the recipient is credited exactly once
/// and never for an aborted transfer.
pub fn target_on_commit(existing: Option<&XpcRecord>) -> XpcTransition {
    match existing {
        None => XpcTransition::Refused("commit without a prepared record"),
        Some(rec) => match rec.phase {
            XpcPhase::Prepared => XpcTransition::Advanced(XpcPhase::Committed),
            XpcPhase::Committed => XpcTransition::Noop,
            XpcPhase::Aborted => XpcTransition::Refused("transfer already aborted"),
        },
    }
}

/// The TARGET-side transition: the source asks the target to abort.
///
/// * The target is PREPARED → REFUSED. The target has voted YES; a 2PC
///   participant that voted YES must commit, and this refusal is exactly what
///   blocks the source's double-spend attempt.
/// * The target has no record → the transfer is ABORTED. The ABORTED record
///   is the target's authorisation for the source's refund, and it PROVES
///   that the target never prepared (and so never credited).
/// * The target is already COMMITTED → refused (the value is credited).
/// * The target is already ABORTED → no-op.
pub fn target_on_abort_request(existing: Option<&XpcRecord>) -> XpcTransition {
    match existing {
        None => XpcTransition::Advanced(XpcPhase::Aborted),
        Some(rec) => match rec.phase {
            XpcPhase::Prepared => XpcTransition::Refused("target already voted to prepare"),
            XpcPhase::Committed => XpcTransition::Refused("transfer already committed"),
            XpcPhase::Aborted => XpcTransition::Noop,
        },
    }
}

/// The source's view of a pending transfer: what it must still do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceAction {
    /// Nothing (the transfer is decided, or this shard is not the source).
    Idle,
    /// Re-publish the PREPARE (the target has not answered yet).
    Reprepare,
    /// Publish the COMMIT (the target voted YES; the source decided).
    Commit,
    /// Ask the target to abort (the prepare window elapsed with no vote).
    AbortRequest,
}

/// The cadence of the PREPARE re-publication, in heights.
///
/// The OPENING PREPARE is published by the block that carries the transfer
/// (it is the record that escrows the value), so it is published exactly
/// once. If that message never reaches the target - the source crashed
/// between the finalization of that block and the publication, or the
/// transport lost it - the transfer would wait for the whole prepare window
/// before the abort path refunds it. The source therefore RE-PUBLISHES the
/// PREPARE while it waits, on this cadence, so the target gets the request
/// again.
///
/// The re-published record proves the source's PREPARED state (the escrow)
/// instead of the sender's account leaf: after the escrow the sender's
/// balance no longer covers the amount, so the opening proof (which says
/// "the sender had the funds") can no longer be produced - and it does not
/// need to be: the PREPARED leaf IS the escrow, written by the source in
/// the very block that debited the sender.
pub const XPC_REPREPARE_INTERVAL: u64 = 8;

/// True when the source must re-publish the PREPARE of this record at
/// `height`.
///
/// A PURE function of the committed record and the height (no clock, no
/// node-local state), so every node of the source shard derives the same
/// answer and the published set is deterministic.
pub fn should_reprepare(record: &XpcRecord, height: u64) -> bool {
    if record.phase != XpcPhase::Prepared {
        return false;
    }
    if height
        >= record
            .prepared_height
            .saturating_add(XPC_PREPARE_TIMEOUT_HEIGHTS)
    {
        return false;
    }
    // The first re-publication is one height after the prepare, then every
    // `XPC_REPREPARE_INTERVAL` heights.
    height.saturating_sub(record.prepared_height) % XPC_REPREPARE_INTERVAL == 1
}

/// What the SOURCE shard must do for one of its 2PC records at `height`.
pub fn source_action(record: &XpcRecord, height: u64) -> SourceAction {
    match record.phase {
        XpcPhase::Prepared => {
            if height
                >= record
                    .prepared_height
                    .saturating_add(XPC_PREPARE_TIMEOUT_HEIGHTS)
            {
                SourceAction::AbortRequest
            } else {
                SourceAction::Reprepare
            }
        }
        XpcPhase::Committed => SourceAction::Commit,
        XpcPhase::Aborted => SourceAction::Idle,
    }
}

/// What the TARGET shard must do for one of its 2PC records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetAction {
    /// Nothing (the transfer is decided).
    Idle,
    /// Publish the PREPARE-ACK (the target voted YES and waits for the
    /// decision).
    PrepareAck,
    /// Publish the ABORT-ACK (the target aborted; the source may refund).
    AbortAck,
}

/// What the TARGET shard must do for one of its 2PC records.
pub fn target_action(record: &XpcRecord) -> TargetAction {
    match record.phase {
        XpcPhase::Prepared => TargetAction::PrepareAck,
        XpcPhase::Committed => TargetAction::Idle,
        XpcPhase::Aborted => TargetAction::AbortAck,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(phase: XpcPhase) -> XpcRecord {
        let signer = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let tx = crate::sharding::Transaction::sign(&signer, [3u8; 32], 100, 280_000, 0, 0, 1);
        let mut r = XpcRecord::prepared(tx, 0, 1, 10);
        r.phase = phase;
        r
    }

    #[test]
    fn the_phase_is_monotone() {
        // Source: prepared -> committed, and never back.
        let r = rec(XpcPhase::Prepared);
        assert_eq!(
            source_on_prepare_ack(Some(&r)),
            XpcTransition::Advanced(XpcPhase::Committed)
        );
        assert_eq!(
            source_on_prepare_ack(Some(&rec(XpcPhase::Committed))),
            XpcTransition::Noop
        );
        // A late abort-ack can never un-commit a committed transfer.
        assert!(matches!(
            source_on_abort_ack(Some(&rec(XpcPhase::Committed))),
            XpcTransition::Refused(_)
        ));
    }

    #[test]
    fn a_prepared_target_refuses_the_abort() {
        assert!(matches!(
            target_on_abort_request(Some(&rec(XpcPhase::Prepared))),
            XpcTransition::Refused(_)
        ));
        // A target that never prepared aborts, and that is its authorisation.
        assert_eq!(
            target_on_abort_request(None),
            XpcTransition::Advanced(XpcPhase::Aborted)
        );
    }

    #[test]
    fn a_committed_target_never_credits_twice() {
        assert_eq!(
            target_on_commit(Some(&rec(XpcPhase::Prepared))),
            XpcTransition::Advanced(XpcPhase::Committed)
        );
        assert_eq!(
            target_on_commit(Some(&rec(XpcPhase::Committed))),
            XpcTransition::Noop
        );
        // An aborted transfer is never credited.
        assert!(matches!(
            target_on_commit(Some(&rec(XpcPhase::Aborted))),
            XpcTransition::Refused(_)
        ));
    }

    #[test]
    fn the_source_action_follows_the_timeout() {
        let r = rec(XpcPhase::Prepared);
        assert_eq!(source_action(&r, 10), SourceAction::Reprepare);
        assert_eq!(
            source_action(&r, 10 + XPC_PREPARE_TIMEOUT_HEIGHTS),
            SourceAction::AbortRequest
        );
    }

    #[test]
    fn the_reprepare_cadence_is_deterministic_and_bounded() {
        let r = rec(XpcPhase::Prepared); // prepared at height 10
                                         // The first re-publication is one height after the prepare...
        assert!(!should_reprepare(&r, 10), "the prepare height itself");
        assert!(should_reprepare(&r, 11));
        // ... then every XPC_REPREPARE_INTERVAL heights.
        assert!(!should_reprepare(&r, 12));
        assert!(!should_reprepare(&r, 18));
        assert!(should_reprepare(&r, 19));
        // It never fires past the prepare window (the abort path takes over).
        let window = 10 + XPC_PREPARE_TIMEOUT_HEIGHTS;
        assert!(!should_reprepare(&r, window));
        assert!(!should_reprepare(&r, window + 100));
        // A decided transfer is never re-prepared.
        let mut committed = rec(XpcPhase::Committed);
        committed.prepared_height = 10;
        assert!(!should_reprepare(&committed, 11));
        let mut aborted = rec(XpcPhase::Aborted);
        aborted.prepared_height = 10;
        assert!(!should_reprepare(&aborted, 11));
    }

    #[test]
    fn the_activation_switch_is_a_height_boundary() {
        assert!(!XpcActivation::Disabled.is_active_at(0));
        assert!(!XpcActivation::Disabled.is_active_at(u64::MAX));
        let a = XpcActivation::FromHeight(100);
        assert!(!a.is_active_at(99));
        assert!(a.is_active_at(100));
        assert!(a.is_active_at(101));
    }

    #[test]
    fn the_state_leaf_is_reconstructible() {
        let tx = [7u8; 32];
        let key = xpc_state_key(&tx);
        let value = xpc_state_value(XpcPhase::Prepared, &tx);
        assert_eq!(value.len(), 33);
        assert_eq!(value[0], XpcPhase::Prepared.code());
        assert_eq!(&value[1..], &tx[..]);
        // The key is namespaced, so it can never collide with an account leaf.
        assert_ne!(key, [0u8; 32]);
    }
}
