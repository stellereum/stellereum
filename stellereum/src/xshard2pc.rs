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
//! * The legacy outbox/inbox/ack/bounce flow is untouched for transfers
//!   produced before the activation height ([`XpcActivation`]). On an
//!   UPGRADED chain such a legacy transfer can NOT deliver value: the target
//!   refuses the one-step legacy credit because the message proves only the
//!   sender's pre-transfer balance, not the source-side escrow (XSHARD-01).
//!   The value is therefore returned to the sender by the deterministic
//!   timeout bounce, not delivered; `XPC_ACTIVATION_HEIGHT = 0` means a fresh
//!   chain never produces such a transfer at all. The switch is NOT an
//!   operator knob: it comes from the compile-time chain spec
//!   ([`XPC_ACTIVATION_HEIGHT`] / [`XpcActivation::from_chain_spec`]).
//! * The liveness cost is real and deliberate: a transfer whose target shard
//!   is unreachable stays ESCROWED (the value is neither credited nor
//!   refunded) until the target answers. That is the price of not letting the
//!   source decide unilaterally.
//!
//! # Bounded re-emission
//!
//! Both sides re-derive their pending records from the committed state at
//! every height, so a stuck transfer would otherwise put one PREPARE / ACK on
//! the wire per block forever. The re-emission is capped three ways, all as
//! PURE functions of the committed record and the height (so every node
//! derives the same set):
//!
//! * [`should_reprepare`] publishes at most
//!   [`XPC_REPREPARE_RETRY_LIMIT`] PREPARE retries per transfer per
//!   [`XPC_PREPARE_TIMEOUT_HEIGHTS`] window;
//! * [`target_action_at`] publishes at most one PREPARE-ACK / ABORT-ACK per
//!   transfer per [`XPC_ACK_REEMIT_INTERVAL`] window (slow cadence after the
//!   early recovery burst), never after the record is COMMITTED, and keeps the
//!   ABORT-ACK recoverable (the source's consumer is idempotent) until the
//!   record retires;
//! * [`bounded_reemit_plan`] truncates the WHOLE per-height re-emission set to
//!   [`XPC_MAX_REEMITS_PER_HEIGHT`], with a deterministic height rotation so a
//!   busy shard cannot starve the tail.

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

/// The chain-spec activation height of the cross-shard 2PC.
///
/// ACTIVE FROM GENESIS (`0`): every cross-shard transfer produced at height
/// `0` or later uses prepare/vote/commit, so a fresh chain never publishes a
/// value transfer through the legacy one-way flow. That flow is still
/// REFUSED at the target's credit gate (XSHARD-01: a one-step message cannot
/// prove the source-side escrow), which is why the atomic path must be the
/// only path new value can take.
///
/// HONEST UPGRADE BEHAVIOUR: on a chain upgraded from a build with the 2PC
/// off, a transfer that was already produced under the legacy flow keeps
/// being handled by that flow, but it does NOT "complete" by delivering
/// value. The target refuses the legacy credit (XSHARD-01), and the
/// deterministic height-timeout bounce refunds the sender on the source. Such
/// a transfer is therefore refund-only, never delivered; only the 2PC
/// (PREPARE → PREPARE-ACK → COMMIT) moves cross-shard value. This constant —
/// and only this constant — is the production source of [`XpcActivation`]
/// (see [`XpcActivation::from_chain_spec`]): the protocol freeze forbids
/// env-driven protocol switches, so an operator variable can never arm the
/// 2PC on a running chain, and every node derives the same boundary from the
/// same compiled value. Flipping it is a protocol change and ships together
/// with this gate in a release.
pub const XPC_ACTIVATION_HEIGHT: u64 = 0;

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

    /// The structural invariant of a committed 2PC record.
    ///
    /// A record whose bytes disagree with themselves can never be trusted as
    /// a proof base (its state-trie leaf would bind a phase to a transaction
    /// it does not describe), so [`XpcRecord`] construction paths fail closed
    /// on `false` instead of "repairing" it:
    ///
    /// * the source and target shards are distinct and equal to the carried
    ///   transaction's own shard ids;
    /// * the stored transaction hash really is the carried transaction's;
    /// * `Prepared` has no decision height, and a decided phase was decided no
    ///   earlier than it was prepared.
    pub fn is_consistent(&self) -> bool {
        self.source_shard != self.target_shard
            && self.source_shard == self.tx.source_shard
            && self.target_shard == self.tx.target_shard
            && self.tx.compute_tx_hash() == self.tx_hash
            && match self.phase {
                XpcPhase::Prepared => self.decided_height == 0,
                XpcPhase::Committed | XpcPhase::Aborted => {
                    // `0` is the "not decided" sentinel: a decided phase must
                    // carry a real height, and it cannot predate the prepare.
                    self.decided_height != 0 && self.decided_height >= self.prepared_height
                }
            }
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
/// height `h` or later to the 2PC; transfers produced before `h` keep the
/// legacy flow, which on an upgraded chain is REFUND-ONLY (the target refuses
/// the one-step legacy credit under XSHARD-01 and the source's timeout bounce
/// returns the value). The two never interleave on one transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XpcActivation {
    /// The 2PC is off (legacy flow only).
    Disabled,
    /// The 2PC is on for transfers produced at height >= the boundary.
    FromHeight(u64),
}

impl Default for XpcActivation {
    /// The default is the CHAIN SPEC value, not a hard-coded `Disabled`: the
    /// production switch has exactly one source ([`Self::from_chain_spec`]).
    fn default() -> Self {
        Self::from_chain_spec()
    }
}

impl XpcActivation {
    /// The PRODUCTION switch: derived from the compile-time chain spec gate
    /// [`XPC_ACTIVATION_HEIGHT`]. The shipped value is `0` (active from
    /// genesis), so a fresh chain arms the 2PC from its first block.
    ///
    /// `u64::MAX` remains the explicit "off" sentinel and maps to
    /// [`Self::Disabled`] — never to `FromHeight(u64::MAX)`, which would
    /// report a boundary at the last representable height and let a node treat
    /// the gate as "armed". This constructor is the ONLY production source of
    /// the switch; test code may build [`Self::FromHeight`] directly to
    /// exercise the boundary.
    pub const fn from_chain_spec() -> Self {
        if XPC_ACTIVATION_HEIGHT == u64::MAX {
            XpcActivation::Disabled
        } else {
            XpcActivation::FromHeight(XPC_ACTIVATION_HEIGHT)
        }
    }

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

/// Hard cap on concurrent active `Prepared` 2PC records per sender on a target
/// shard once [`crate::chain_spec::xshard_bounce_escrow_required_active_at`] is active.
pub const MAX_ACTIVE_PREPARED_PER_SENDER: usize = 4;

/// Deterministic TTL (in heights) after which an unresolved `Prepared` 2PC
/// record retires in [`is_retired`] once
/// [`crate::chain_spec::xshard_bounce_escrow_required_active_at`] is active.
pub const XPC_PREPARE_TTL_HEIGHTS: u64 = 4_096;

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

/// Gate-protected `XPC-PREPARED-UNBOUNDED` admission check for target `Prepared`
/// records:
/// 1. At most ONE active `Prepared` record per `(source_shard, from, source_nonce)`,
///    blocking multi-`tx_hash` same-nonce spam against a single affordability proof;
/// 2. At most [`MAX_ACTIVE_PREPARED_PER_SENDER`] concurrent active `Prepared`
///    records from the same `(source_shard, from)` sender.
pub fn target_prepare_slot_available<'a, I>(
    active_records: I,
    source_shard: ShardId,
    from: &[u8; 32],
    source_nonce: u64,
    tx_hash: &[u8; 32],
) -> bool
where
    I: IntoIterator<Item = &'a XpcRecord>,
{
    let mut sender_active_count = 0usize;
    for rec in active_records {
        if rec.phase != XpcPhase::Prepared || rec.source_shard != source_shard {
            continue;
        }
        if rec.tx.from != *from || rec.tx_hash == *tx_hash {
            continue;
        }
        if rec.tx.nonce == source_nonce {
            return false;
        }
        sender_active_count += 1;
        if sender_active_count >= MAX_ACTIVE_PREPARED_PER_SENDER {
            return false;
        }
    }
    true
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

/// How many times a source may RE-PUBLISH the PREPARE of one transfer inside
/// one [`XPC_PREPARE_TIMEOUT_HEIGHTS`] window.
///
/// The opening PREPARE is published exactly once, by the block that escrows
/// the value. One retry covers the only case the retry exists for (the
/// opening record never reached the target); further retries are amplification
/// and buy nothing, because the target answers a PREPARE with a PREPARE-ACK
/// and the source re-derives that answer from its committed state.
pub const XPC_REPREPARE_RETRY_LIMIT: u64 = 1;

/// The cadence of the PREPARE re-publication, in heights.
///
/// One retry per prepare window: the retry fires one height after the prepare
/// and the next would land after [`XPC_PREPARE_TIMEOUT_HEIGHTS`], where the
/// abort path takes over and no further PREPARE is published.
pub const XPC_REPREPARE_INTERVAL: u64 = XPC_PREPARE_TIMEOUT_HEIGHTS;

/// True when the source must re-publish the PREPARE of this record at
/// `height`.
///
/// A PURE function of the committed record and the height (no clock, no
/// node-local state), so every node of the source shard derives the same
/// answer and the published set is deterministic. The retry is BOUNDED: at
/// most [`XPC_REPREPARE_RETRY_LIMIT`] per transfer per
/// [`XPC_PREPARE_TIMEOUT_HEIGHTS`] window, so a transfer that has to wait out
/// the window puts one extra PREPARE on the wire, not one per block.
pub fn should_reprepare(record: &XpcRecord, height: u64) -> bool {
    if record.phase != XpcPhase::Prepared {
        return false;
    }
    let Some(elapsed) = height.checked_sub(record.prepared_height) else {
        return false;
    };
    if elapsed == 0 {
        return false;
    }
    if elapsed >= XPC_PREPARE_TIMEOUT_HEIGHTS {
        return false;
    }
    // The retry slot inside the current window: the first retry one height
    // after the prepare, then one per XPC_REPREPARE_INTERVAL heights.
    let slot = elapsed % XPC_REPREPARE_INTERVAL;
    slot != 0 && slot <= XPC_REPREPARE_RETRY_LIMIT
}

/// The cadence of ABORT-REQUEST re-publication after the prepare timeout.
///
/// The request is not a value movement; its only purpose is to solicit the
/// target's idempotent ABORT-ACK. Re-sending it every height let N stuck
/// transfers consume the entire per-block control budget forever, starving
/// every new PREPARE and ACK. One request per ACK window is enough: the target
/// re-emits its ACK on the same cadence, so a lost request is recovered by the
/// next window.
pub const XPC_ABORT_REQUEST_INTERVAL: u64 = XPC_PREPARE_TIMEOUT_HEIGHTS;

/// What the SOURCE shard must do for one of its 2PC records at `height`.
///
/// A COMMITTED record is terminal: the source owes at most a BOUNDED burst of
/// COMMIT re-publications so a lost COMMIT can still reach the target. It
/// publishes on [`XPC_COMMIT_REEMIT_INTERVAL`] and stops at
/// [`XPC_TERMINAL_RETENTION_HEIGHTS`]; after that the record is retired by the
/// state engine (see [`is_retired`]), so a historical transfer is never
/// re-published, re-cloned or re-hashed forever. The schedule is a pure
/// function of (record, height), so every node derives the same set.
pub fn source_action(record: &XpcRecord, height: u64) -> SourceAction {
    match record.phase {
        XpcPhase::Prepared => {
            let Some(elapsed) = height.checked_sub(record.prepared_height) else {
                return SourceAction::Idle;
            };
            if elapsed < XPC_PREPARE_TIMEOUT_HEIGHTS {
                SourceAction::Reprepare
            } else {
                let since_timeout = elapsed - XPC_PREPARE_TIMEOUT_HEIGHTS;
                if since_timeout.is_multiple_of(XPC_ABORT_REQUEST_INTERVAL) {
                    SourceAction::AbortRequest
                } else {
                    SourceAction::Idle
                }
            }
        }
        XpcPhase::Committed => {
            let Some(elapsed) = height.checked_sub(record.decided_height) else {
                return SourceAction::Idle;
            };
            if elapsed == 0 || elapsed >= XPC_TERMINAL_RETENTION_HEIGHTS {
                return SourceAction::Idle;
            }
            // Early recovery burst: the decision height +1, then one per
            // interval for the first few windows. After that the slow
            // heartbeat keeps a late COMMIT obtainable without re-publishing
            // every 64 heights for a full retention day. A live target's
            // PREPARE-ACK refreshes `decided_height`, which restarts this
            // schedule, so prompt recovery is never dependent on the slow
            // heartbeat.
            let early_window = XPC_COMMIT_REEMIT_INTERVAL.saturating_mul(4);
            let due = if elapsed <= early_window {
                elapsed == 1 || elapsed.is_multiple_of(XPC_COMMIT_REEMIT_INTERVAL)
            } else if elapsed == XPC_TERMINAL_RETENTION_HEIGHTS.saturating_sub(1) {
                // FINAL COPY: the last slow heartbeat can fall up to a full
                // interval before retirement. Publish once more immediately
                // before the record is pruned so a target that came online in
                // that gap still gets a decision while the record exists.
                true
            } else {
                elapsed.is_multiple_of(XPC_COMMIT_REEMIT_INTERVAL_SLOW)
            };
            if due {
                SourceAction::Commit
            } else {
                SourceAction::Idle
            }
        }
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
///
/// This is the UNBOUNDED view: it says what the record owes the source at
/// all. Emission goes through [`target_action_at`], which adds the per-window
/// bound and the terminal rules.
pub fn target_action(record: &XpcRecord) -> TargetAction {
    match record.phase {
        XpcPhase::Prepared => TargetAction::PrepareAck,
        XpcPhase::Committed => TargetAction::Idle,
        XpcPhase::Aborted => TargetAction::AbortAck,
    }
}

/// The cadence of an ACK re-publication, in heights.
///
/// The ACK is the target's vote: one record is enough to complete a healthy
/// exchange, and a LOST one must be recoverable without a per-block flood.
/// So the target emits it one height after the phase was recorded, then at
/// most once per window of this many heights.
pub const XPC_ACK_REEMIT_INTERVAL: u64 = XPC_PREPARE_TIMEOUT_HEIGHTS;

/// How many heights a TERMINAL (COMMITTED or ABORTED) 2PC record is retained
/// after its decision before the state engine retires it.
///
/// The record becomes terminal when this shard CONSUMED the decisive record
/// (`PREPARE-ACK` / `COMMIT` / `ABORT-ACK`), i.e. it is already in the
/// committed `cross_shard_completed` set. The source still gets a bounded
/// COMMIT re-publication window (see [`source_action`]) so a lost COMMIT is
/// recoverable; after this many heights neither side needs the record again:
///
///  * a replay of a decisive record finds no record and is refused (never
///    credited/refunded twice), and
///  * the target's mailbox prune already drops terminal copies
///    (`completed_cross_shard`), so retiring the record loses no information.
///
/// RETENTION VS RECOVERY (critical): the first value (`256`) was sized for a
/// 3 s cadence and left only ~46 s of recovery at a ~240 ms block rate. A
/// target that restarts or catches up for longer than that could never obtain
/// the source's COMMIT: the source had already released the escrow and the
/// record was retired, so the recipient was permanently uncredited. One day
/// at the live 240 ms tempo (`24*3600*1000 / 240 = 360_000`) gives a real sync
/// / restart window. [`source_action`] additionally restarts this window every
/// time the still-PREPARED target re-sends a PREPARE-ACK (a pull hint), so a
/// target that is alive but has not applied COMMIT keeps the obligation alive
/// indefinitely; only a target silent for the WHOLE window loses it. At the
/// 50 ms minimum tempo this is ~5 h; see the block-interval note below.
///
/// The retirement height is `decided_height + XPC_TERMINAL_RETENTION_HEIGHTS`
/// on every node: a pure function of the committed record and the applied
/// block height, never a local clock. A decision that is older than this when
/// a node restores an old snapshot is retired on that node's next applied
/// block, so all nodes converge to the same bounded record set.
pub const XPC_TERMINAL_RETENTION_HEIGHTS: u64 = 360_000;

/// The cadence of a terminal COMMIT re-publication, in heights.
///
/// A healthy exchange needs one COMMIT; the retries only cover a lost one. One
/// emission one height after the decision, then at most one per window, keeps
/// the source's per-block footprint bounded without making a single lost
/// COMMIT unrecoverable.
pub const XPC_COMMIT_REEMIT_INTERVAL: u64 = XPC_PREPARE_TIMEOUT_HEIGHTS;

/// Slow COMMIT heartbeat after the early recovery burst.
///
/// The first [`XPC_TERMINAL_RETENTION_HEIGHTS`] / 64 heights would otherwise
/// re-publish one COMMIT every 64 heights for a whole day per stuck transfer.
/// A live target re-sends PREPARE-ACK every 64 heights while it is still
/// PREPARED, and that ack REFRESHES the source's decision height (see the
/// engine's `PrepareAck` arm), which immediately restarts the early cadence —
/// so prompt recovery does not depend on the slow heartbeat. A silent target
/// only needs the occasional COMMIT; one per 4 096 heights (~16 min at 240 ms)
/// is enough to make a late copy available without flooding every block.
pub const XPC_COMMIT_REEMIT_INTERVAL_SLOW: u64 = 4_096;

/// Control-record budget reserved for INBOUND re-emissions from the peer
/// shard (its PREPARE-ACK / ABORT-ACK / COMMIT records).
///
/// The per-height cap covers every 2PC control record in a block, both the
/// ones this shard derives from its committed state and the ones pulled from
/// its mailbox. Without a reservation a stream of new outbound transfers could
/// fill the whole budget every block and starve the acks that complete the
/// transfers already in flight.
pub const XPC_INBOUND_CONTROL_RESERVE: usize = 4;

/// How many heights an inbound cross-shard message may stay in the node-local
/// mailbox without being admitted before it is QUARANTINED (pruned) as
/// never-admissible.
///
/// Some rejections are permanent (a bad proof, a record for an unknown or
/// already-completed transfer, an anchor that aged out of the finalized-header
/// window). Before this bound such a message was skipped forever: it was never
/// included, so apply never pruned it, and a peer could grow the mailbox
/// without limit. The expiry height is `first_seen_height + this`; the clock is
/// the locally applied chain height (deterministic per node) and the map is
/// node-local transport bookkeeping, never consensus state.
pub const XPC_MAILBOX_QUARANTINE_HEIGHTS: u64 = 64;

/// Hard cap on the number of distinct inbound message ids tracked at once.
///
/// Expiry alone still allows a same-height burst of unbounded records, so the
/// tracker is also bounded: when it exceeds this, the oldest-tracked entries
/// (lowest first-seen height, then msg id) are pruned from the mailbox first.
/// A valid message pruned this way can be re-published; the bound is what stops
/// a remote peer from forcing unbounded memory use.
pub const XPC_MAILBOX_MAX_TRACKED: usize = 4096;

/// How many OPENING PREPAREs the proposer may add at a height, given that
/// `plan_len` control records are already due from the committed state.
///
/// The total (plan + inbound + opening) never exceeds
/// [`XPC_MAX_REEMITS_PER_HEIGHT`], so the proposer can never build a block its
/// own validator set rejects. Up to [`XPC_INBOUND_CONTROL_RESERVE`] slots are
/// held back for the peer's control records; the rest ride this height and
/// the remaining outbound transfers are carried to later heights in the same
/// deterministic selection order.
pub fn opening_prepare_budget(plan_len: usize) -> usize {
    let remaining = XPC_MAX_REEMITS_PER_HEIGHT.saturating_sub(plan_len);
    remaining.saturating_sub(XPC_INBOUND_CONTROL_RESERVE.min(remaining))
}

/// True when this record is eligible for retirement at `height`.
///
/// PURE function of the committed record, the applied height, and the active
/// chain-spec gate, so every node retires exactly the same records at exactly
/// the same height (and the resulting state root and replay snapshot agree).
/// Pre-activation (`xshard_bounce_escrow_required_active_at(height) == false`),
/// `Prepared` records are never retired here; once active, unresolved
/// `Prepared` records expire at `prepared_height + XPC_PREPARE_TTL_HEIGHTS`.
pub fn is_retired(record: &XpcRecord, height: u64) -> bool {
    is_retired_at(
        record,
        height,
        crate::chain_spec::xshard_bounce_escrow_required_active_at(height),
    )
}

/// Pure form of [`is_retired`] with an explicit `enforce_prepared_ttl` gate.
pub fn is_retired_at(record: &XpcRecord, height: u64, enforce_prepared_ttl: bool) -> bool {
    match record.phase {
        XpcPhase::Prepared => {
            enforce_prepared_ttl
                && height
                    >= record
                        .prepared_height
                        .saturating_add(XPC_PREPARE_TTL_HEIGHTS)
        }
        XpcPhase::Committed | XpcPhase::Aborted => {
            height
                >= record
                    .decided_height
                    .saturating_add(XPC_TERMINAL_RETENTION_HEIGHTS)
        }
    }
}

/// The hard cap on the number of 2PC/control records a shard may re-emit in
/// ONE block, across every transfer it owns.
///
/// Without it, `N` stuck transfers would put `N` records in every block —
/// amplification that grows with the backlog. The cap is part of the
/// deterministic plan ([`bounded_reemit_plan`]), not a node-local policy, so
/// two honest proposers derive the same block content.
pub const XPC_MAX_REEMITS_PER_HEIGHT: usize = 16;

/// The hard cap on the TOTAL number of records in a block's
/// `cross_shard_out`, across BOTH kinds of record the field carries:
///
///  * the legacy one-way transfers (and their acks/bounces), and
///  * every §9 2PC control record (PREPARE / PREPARE-ACK / COMMIT /
///    ABORT-REQUEST / ABORT-ACK).
///
/// [`XPC_MAX_REEMITS_PER_HEIGHT`] bounds only the 2PC re-emission plan; a
/// pre-2PC (legacy) block had no equivalent bound at all, so a Byzantine
/// proposer could pack an unbounded number of outbound transfer records (one
/// per transaction it packs) and an unbounded mailbox pull. Both the proposer
/// and every validator enforce THIS constant, so the proposer never builds a
/// block its own validator set refuses, and the excess is carried to later
/// heights.
///
/// The cap is a pure constant (not a node-local policy): two honest proposers
/// derive the same per-height decision, and a validator re-checks the exact
/// same bound on the wire.
pub const XPC_MAX_CROSS_SHARD_RECORDS_PER_BLOCK: usize = XPC_MAX_REEMITS_PER_HEIGHT;

/// How many OUTBOUND transfer/PREPARE records may ride one block, given that
/// `control_plan_len` 2PC control records are already due from committed
/// state.
///
/// Bounded by the TOTAL cap, with [`XPC_INBOUND_CONTROL_RESERVE`] slots held
/// back for records pulled from the inbound mailbox. Used for the legacy
/// (pre-activation) flow as well as the 2PC opening PREPAREs, so both kinds
/// obey one deterministic budget.
pub fn outbound_record_budget(control_plan_len: usize) -> usize {
    let remaining = XPC_MAX_CROSS_SHARD_RECORDS_PER_BLOCK.saturating_sub(control_plan_len);
    remaining.saturating_sub(XPC_INBOUND_CONTROL_RESERVE.min(remaining))
}

/// True when the target must (re-)publish an ACK for this record at
/// `height`.
///
/// A PURE function of the committed record and the height:
///
/// * `Prepared` — one ACK one height after the prepare, then at most one per
///   [`XPC_ACK_REEMIT_INTERVAL`] window while the source has not decided;
/// * `Committed` — NEVER (the transfer is decided; the target owes nothing);
/// * `Aborted` — one ACK one height after the abort decision, then at most one
///   per [`XPC_ACK_REEMIT_INTERVAL`] window until the record retires. The
///   source's `source_on_abort_ack` is idempotent (`Noop` once Aborted), so a
///   duplicate is harmless — and it is the ONLY way a lost authorisation can
///   be recovered. A one-shot emission made one dropped packet delay the
///   refund by a whole retention window.
pub fn should_reemit_ack(record: &XpcRecord, height: u64) -> bool {
    match record.phase {
        XpcPhase::Prepared => {
            let Some(elapsed) = height.checked_sub(record.prepared_height) else {
                return false;
            };
            elapsed != 0 && elapsed % XPC_ACK_REEMIT_INTERVAL == 1
        }
        XpcPhase::Committed => false,
        XpcPhase::Aborted => {
            let Some(elapsed) = height.checked_sub(record.decided_height) else {
                return false;
            };
            if elapsed == 0 || elapsed >= XPC_TERMINAL_RETENTION_HEIGHTS {
                return false;
            }
            let early_window = XPC_COMMIT_REEMIT_INTERVAL.saturating_mul(4);
            if elapsed <= early_window {
                elapsed == 1 || elapsed.is_multiple_of(XPC_ACK_REEMIT_INTERVAL)
            } else if elapsed == XPC_TERMINAL_RETENTION_HEIGHTS.saturating_sub(1) {
                // Final authorisation copy before the record is pruned; the
                // source's refund is still claimable if it was offline.
                true
            } else {
                elapsed.is_multiple_of(XPC_COMMIT_REEMIT_INTERVAL_SLOW)
            }
        }
    }
}

/// What the TARGET shard must emit for one of its 2PC records at `height`.
///
/// The BOUNDED view of [`target_action`]: an ACK is emitted at most once per
/// [`XPC_ACK_REEMIT_INTERVAL`] window, never after COMMIT, and a bounded
/// number of times after ABORT (the source's consumer is idempotent).
/// Unknown phase bytes fail closed to [`TargetAction::Idle`].
pub fn target_action_at(record: &XpcRecord, height: u64) -> TargetAction {
    if !should_reemit_ack(record, height) {
        return TargetAction::Idle;
    }
    match record.phase {
        XpcPhase::Prepared => TargetAction::PrepareAck,
        XpcPhase::Aborted => TargetAction::AbortAck,
        XpcPhase::Committed => TargetAction::Idle,
    }
}

/// One record a source or target shard should publish at a height.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XpcReemit {
    /// The stable 2PC identity of the transfer.
    pub tx_hash: [u8; 32],
    /// The wire phase ([`XPC_PREPARE`], [`XPC_PREPARE_ACK`],
    /// [`XPC_COMMIT`], [`XPC_ABORT_REQUEST`] or [`XPC_ABORT_ACK`]).
    pub phase: u8,
}

/// The deterministic, BOUNDED re-emission plan of one shard at `height`.
///
/// Applies the same rules the protocol uses — [`source_action`] plus
/// [`should_reprepare`] on the source side, [`target_action_at`] on the
/// target side — to every record the shard owns, sorts the result by
/// transaction hash for determinism, rotates by `height` so a busy shard does
/// not starve the same tail every block, and truncates it to
/// [`XPC_MAX_REEMITS_PER_HEIGHT`].
///
/// The truncation is the amplification cap: a shard with a thousand stuck
/// transfers still publishes at most [`XPC_MAX_REEMITS_PER_HEIGHT`] records
/// per block, and the height rotation guarantees every transfer is served.
pub fn bounded_reemit_plan(records: &[XpcRecord], shard: ShardId, height: u64) -> Vec<XpcReemit> {
    let mut plan: Vec<XpcReemit> = records
        .iter()
        .filter_map(|rec| {
            let phase = if rec.source_shard == shard {
                match source_action(rec, height) {
                    SourceAction::Commit => XPC_COMMIT,
                    SourceAction::AbortRequest => XPC_ABORT_REQUEST,
                    SourceAction::Reprepare => {
                        if !should_reprepare(rec, height) {
                            return None;
                        }
                        XPC_PREPARE
                    }
                    SourceAction::Idle => return None,
                }
            } else if rec.target_shard == shard {
                match target_action_at(rec, height) {
                    TargetAction::PrepareAck => XPC_PREPARE_ACK,
                    TargetAction::AbortAck => XPC_ABORT_ACK,
                    TargetAction::Idle => return None,
                }
            } else {
                return None;
            };
            Some(XpcReemit {
                tx_hash: rec.tx_hash,
                phase,
            })
        })
        .collect();
    plan.sort_by_key(|r| r.tx_hash);
    if plan.len() > XPC_MAX_REEMITS_PER_HEIGHT {
        let offset = (height as usize) % plan.len();
        plan.rotate_left(offset);
        plan.truncate(XPC_MAX_REEMITS_PER_HEIGHT);
    }
    plan
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
        // The request is BOUNDED to one per ACK window: a stuck transfer must
        // not consume a control-record slot every block forever (that starved
        // every new PREPARE/ACK once 16 transfers were stuck).
        assert_eq!(
            source_action(&r, 10 + XPC_PREPARE_TIMEOUT_HEIGHTS + 1),
            SourceAction::Idle
        );
        assert_eq!(
            source_action(
                &r,
                10 + XPC_PREPARE_TIMEOUT_HEIGHTS + XPC_ABORT_REQUEST_INTERVAL
            ),
            SourceAction::AbortRequest
        );
        let requests: Vec<u64> = (10..10 + 4 * XPC_ABORT_REQUEST_INTERVAL)
            .filter(|height| source_action(&r, *height) == SourceAction::AbortRequest)
            .collect();
        assert_eq!(
            requests,
            vec![
                10 + XPC_PREPARE_TIMEOUT_HEIGHTS,
                10 + XPC_PREPARE_TIMEOUT_HEIGHTS + XPC_ABORT_REQUEST_INTERVAL,
                10 + XPC_PREPARE_TIMEOUT_HEIGHTS + 2 * XPC_ABORT_REQUEST_INTERVAL
            ],
            "one abort request per window: {requests:?}"
        );
    }

    #[test]
    fn the_reprepare_cadence_is_deterministic_and_bounded() {
        let r = rec(XpcPhase::Prepared); // prepared at height 10
                                         // Exactly ONE retry inside the whole prepare window: at most
                                         // XPC_REPREPARE_RETRY_LIMIT per XPC_PREPARE_TIMEOUT_HEIGHTS window.
        let retries: Vec<u64> = (10..10 + XPC_PREPARE_TIMEOUT_HEIGHTS)
            .filter(|height| should_reprepare(&r, *height))
            .collect();
        assert_eq!(
            retries,
            vec![11],
            "the PREPARE retry must be bounded to one per window, got {retries:?}"
        );
        assert!(!should_reprepare(&r, 10), "the prepare height itself");
        assert!(!should_reprepare(&r, 9), "before the prepare");
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
    fn the_ack_cadence_is_bounded_and_terminal() {
        let prepared = rec(XpcPhase::Prepared); // prepared at height 10
                                                // The unbounded view still says the record owes a vote; the bounded
                                                // view emits it one height after the prepare, then once per window.
        assert_eq!(target_action(&prepared), TargetAction::PrepareAck);
        assert_eq!(target_action_at(&prepared, 10), TargetAction::Idle);
        assert_eq!(target_action_at(&prepared, 11), TargetAction::PrepareAck);
        assert_eq!(target_action_at(&prepared, 12), TargetAction::Idle);
        let acks: Vec<u64> = (10..10 + 4 * XPC_ACK_REEMIT_INTERVAL)
            .filter(|height| target_action_at(&prepared, *height) == TargetAction::PrepareAck)
            .collect();
        assert_eq!(acks.len(), 4, "at most one ACK per window: {acks:?}");

        // COMMITTED: the transfer is decided, the target never re-emits.
        let mut committed = rec(XpcPhase::Committed);
        committed.decided_height = 20;
        assert!(committed.is_consistent());
        for height in [10, 11, 21, 10_000] {
            assert_eq!(target_action_at(&committed, height), TargetAction::Idle);
        }

        // ABORTED: one authorisation one height after the decision, then at
        // most one per ACK window while the record is retained — a lost
        // ABORT-ACK must be recoverable (the source's consumer is idempotent).
        let mut aborted = rec(XpcPhase::Aborted);
        aborted.decided_height = 20;
        assert!(aborted.is_consistent());
        assert_eq!(target_action_at(&aborted, 20), TargetAction::Idle);
        assert_eq!(target_action_at(&aborted, 21), TargetAction::AbortAck);
        assert_eq!(
            target_action_at(&aborted, 20 + XPC_ACK_REEMIT_INTERVAL),
            TargetAction::AbortAck,
            "a later window re-sends the authorisation"
        );
        for height in [22, 23, 20 + XPC_ACK_REEMIT_INTERVAL - 1] {
            assert_eq!(
                target_action_at(&aborted, height),
                TargetAction::Idle,
                "at most one abort authorisation per window: {height}"
            );
        }
        // Bounded: nothing after the retention window.
        assert_eq!(
            target_action_at(&aborted, 20 + XPC_TERMINAL_RETENTION_HEIGHTS),
            TargetAction::Idle
        );
        let acks: Vec<u64> = (20..20 + 4 * XPC_ACK_REEMIT_INTERVAL)
            .filter(|height| target_action_at(&aborted, *height) == TargetAction::AbortAck)
            .collect();
        assert_eq!(acks.len(), 4, "one AbortAck per window: {acks:?}");
    }

    #[test]
    fn the_reemit_plan_is_capped_and_deterministic() {
        let signer = ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]);
        let total = XPC_MAX_REEMITS_PER_HEIGHT * 3;
        let mut records = Vec::new();
        for nonce in 0..total as u64 {
            let tx = crate::sharding::Transaction::sign(
                &signer,
                [(nonce & 0xff) as u8; 32],
                100,
                280_000,
                nonce,
                0,
                1,
            );
            records.push(XpcRecord::prepared(tx, 0, 1, 10));
        }
        // Every record is due for its single retry at height 11.
        let plan = bounded_reemit_plan(&records, 0, 11);
        assert_eq!(
            plan.len(),
            XPC_MAX_REEMITS_PER_HEIGHT,
            "the per-height cap must bound the whole set"
        );
        assert!(plan.iter().all(|r| r.phase == XPC_PREPARE));
        assert_eq!(plan, bounded_reemit_plan(&records, 0, 11), "deterministic");

        // The height rotation serves a DIFFERENT subset on the next retry
        // window, so the cap cannot starve the tail.
        let next = bounded_reemit_plan(&records, 0, 10 + XPC_PREPARE_TIMEOUT_HEIGHTS);
        assert_eq!(next.len(), XPC_MAX_REEMITS_PER_HEIGHT);
        assert_ne!(plan, next, "the plan rotates with the height");

        // Every transfer is served within ceil(total / cap) windows.
        let windows = total.div_ceil(XPC_MAX_REEMITS_PER_HEIGHT);
        let mut served = std::collections::HashSet::new();
        for window in 0..windows {
            let height =
                10 + XPC_PREPARE_TIMEOUT_HEIGHTS + window as u64 * XPC_ABORT_REQUEST_INTERVAL;
            for reemit in bounded_reemit_plan(&records, 0, height) {
                served.insert(reemit.tx_hash);
            }
        }
        assert_eq!(
            served.len(),
            total,
            "the rotation must serve every transfer"
        );

        // A shard that does not own the records never emits for them.
        assert!(bounded_reemit_plan(&records, 9, 11).is_empty());
    }

    #[test]
    fn the_activation_gate_comes_from_the_chain_spec() {
        // The compiled chain-spec constant is the ONLY production source of
        // the switch. It arms the 2PC from genesis, so no value transfer on a
        // fresh chain can take the legacy one-way flow.
        assert_eq!(XPC_ACTIVATION_HEIGHT, 0);
        assert_eq!(
            XpcActivation::from_chain_spec(),
            XpcActivation::FromHeight(0)
        );
        assert_eq!(XpcActivation::default(), XpcActivation::from_chain_spec());
        assert_eq!(XpcActivation::from_chain_spec().boundary(), Some(0));
        assert!(XpcActivation::from_chain_spec().is_active_at(0));
        assert!(XpcActivation::from_chain_spec().is_active_at(u64::MAX));
        // The explicit off switch still means off at every height; only the
        // chain spec (0 above) arms the protocol.
        assert!(!XpcActivation::Disabled.is_active_at(0));
        assert!(!XpcActivation::Disabled.is_active_at(u64::MAX));
    }

    #[test]
    fn unknown_phase_codes_fail_closed() {
        for code in [0u8, 4, 5, 7, 255] {
            assert_eq!(
                XpcPhase::from_code(code),
                None,
                "phase code {code} must not decode"
            );
        }
        for phase in [XpcPhase::Prepared, XpcPhase::Committed, XpcPhase::Aborted] {
            assert_eq!(XpcPhase::from_code(phase.code()), Some(phase));
        }
    }

    #[test]
    fn duplicate_records_are_refused_not_advanced() {
        // A replayed transition is either a no-op (already applied) or a
        // refusal (would move a decided record); it NEVER advances the phase.
        let prepared = rec(XpcPhase::Prepared);
        assert_eq!(source_prepare(Some(&prepared)), XpcTransition::Noop);
        assert_eq!(target_prepare(Some(&prepared)), XpcTransition::Noop);
        assert_eq!(
            source_on_prepare_ack(Some(&prepared)),
            XpcTransition::Advanced(XpcPhase::Committed)
        );
        assert_eq!(
            target_on_abort_request(None),
            XpcTransition::Advanced(XpcPhase::Aborted),
            "only a target with NO record can abort"
        );
        // The applied records reject the replayed record.
        let mut committed = rec(XpcPhase::Committed);
        committed.decided_height = 11;
        assert_eq!(source_on_prepare_ack(Some(&committed)), XpcTransition::Noop);
        assert_eq!(target_on_commit(Some(&committed)), XpcTransition::Noop);
        let mut aborted = rec(XpcPhase::Aborted);
        aborted.decided_height = 11;
        assert_eq!(target_on_abort_request(Some(&aborted)), XpcTransition::Noop);
    }

    #[test]
    fn inconsistent_records_are_recognised() {
        let good = rec(XpcPhase::Prepared);
        assert!(good.is_consistent());

        let mut decided = rec(XpcPhase::Committed);
        decided.decided_height = 11;
        assert!(decided.is_consistent());

        let mut prepared_with_decision = rec(XpcPhase::Prepared);
        prepared_with_decision.decided_height = 5;
        assert!(!prepared_with_decision.is_consistent());

        let mut decided_before_prepared = rec(XpcPhase::Aborted);
        decided_before_prepared.decided_height = 9;
        assert!(!decided_before_prepared.is_consistent());

        let mut decided_at_zero = rec(XpcPhase::Committed);
        decided_at_zero.decided_height = 0;
        assert!(
            !decided_at_zero.is_consistent(),
            "zero is the 'not decided' sentinel"
        );

        let mut wrong_target = rec(XpcPhase::Prepared);
        wrong_target.target_shard = 7;
        assert!(!wrong_target.is_consistent());

        let mut wrong_hash = rec(XpcPhase::Prepared);
        wrong_hash.tx_hash = [0u8; 32];
        assert!(!wrong_hash.is_consistent());
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

/// Executable refinement pin for P14 §B + P15 §A (R1–R5, 9-state ANCHORED
/// machine, PROOF-ONLY violations).
///
/// Port of the transition enumerations in
/// `stellereum-math/code/xpc_refinement_full.py::concrete_reachable`
/// (NOT a copy of the Python): each successor first checks local
/// admissibility against the REAL [`XpcTransition`] functions above, then
/// applies the peer guard. `anchored = true` is VALIDATE
/// (`xpc_admissible` / `verify_xpc_anchored`: claimed peer phase must equal
/// the actual peer phase); `anchored = false` is APPLY
/// (`apply_xpc_record` / `verify_xpc_proof`: proof against the
/// attacker-controlled `source_state_root`, so the claimed phase is
/// unconstrained). Deterministic: fixed seeds, no randomness, no clock.
#[cfg(test)]
mod model_tests {
    use super::*;
    use std::collections::{BTreeSet, VecDeque};

    /// Model phase: `N` = no record, the rest wrap the real [`XpcPhase`].
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    enum M {
        N,
        P,
        C,
        A,
    }

    impl M {
        fn phase(self) -> Option<XpcPhase> {
            match self {
                M::N => None,
                M::P => Some(XpcPhase::Prepared),
                M::C => Some(XpcPhase::Committed),
                M::A => Some(XpcPhase::Aborted),
            }
        }
    }

    /// Concrete model state: source/target records plus value counters.
    /// `credit` moves only on target COMMIT, `refund` only on source ABORT.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    struct St {
        s: M,
        t: M,
        credit: u8,
        refund: u8,
    }

    fn mk_rec(phase: XpcPhase) -> XpcRecord {
        let signer = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let tx = crate::sharding::Transaction::sign(&signer, [3u8; 32], 100, 280_000, 0, 0, 1);
        let mut r = XpcRecord::prepared(tx, 0, 1, 10);
        r.phase = phase;
        r
    }

    /// The 9 documented abstract states (P15 A.1):
    /// `(N,N) (P,N) (P,P) (P,C) (P,A) (A,N) (A,A) (C,P) (C,C)`.
    fn abstract_states() -> BTreeSet<(M, M)> {
        use M::{A, C, N, P};
        BTreeSet::from([
            (N, N),
            (P, N),
            (P, P),
            (P, C),
            (P, A),
            (A, N),
            (A, A),
            (C, P),
            (C, C),
        ])
    }

    /// Port of `concrete_reachable`: the six transition families. Each arm
    /// asserts the corresponding REAL transition agrees locally; the
    /// `anchored` flag then enforces the peer guard (R1/R4).
    fn successors(cur: St, anchored: bool) -> Vec<St> {
        let mut out = Vec::new();
        // 1. Source PREPARE (local escrow, no peer check in either mode).
        if cur.s == M::N {
            assert_eq!(source_prepare(None), XpcTransition::Created);
            out.push(St {
                s: M::P,
                t: cur.t,
                credit: cur.credit,
                refund: cur.refund,
            });
        }
        // 2. Target PREPARE: local `target_prepare(None) == Created`;
        //    ANCHORED needs source escrow `s in {P, C}`.
        if cur.t == M::N {
            assert_eq!(target_prepare(None), XpcTransition::Created);
            if !anchored || cur.s == M::P || cur.s == M::C {
                out.push(St {
                    s: cur.s,
                    t: M::P,
                    credit: cur.credit,
                    refund: cur.refund,
                });
            }
        }
        // 3. Source on PREPARE-ACK: local Prepared -> Committed;
        //    ANCHORED needs target voted YES `t in {P, C}`.
        if cur.s == M::P && cur.credit == 0 {
            let r = mk_rec(XpcPhase::Prepared);
            assert_eq!(
                source_on_prepare_ack(Some(&r)),
                XpcTransition::Advanced(XpcPhase::Committed)
            );
            if !anchored || cur.t == M::P || cur.t == M::C {
                out.push(St {
                    s: M::C,
                    t: cur.t,
                    credit: cur.credit,
                    refund: cur.refund,
                });
            }
        }
        // 4. Source on ABORT-ACK: local Prepared -> Aborted (+1 refund);
        //    ANCHORED needs target never-prepared `t in {N, A}`.
        if cur.s == M::P && cur.refund == 0 {
            let r = mk_rec(XpcPhase::Prepared);
            assert_eq!(
                source_on_abort_ack(Some(&r)),
                XpcTransition::Advanced(XpcPhase::Aborted)
            );
            if !anchored || cur.t == M::N || cur.t == M::A {
                out.push(St {
                    s: M::A,
                    t: cur.t,
                    credit: cur.credit,
                    refund: cur.refund + 1,
                });
            }
        }
        // 5. Target on COMMIT: local Prepared -> Committed (+1 credit);
        //    ANCHORED needs source escrow `s in {P, C}`.
        if cur.t == M::P && cur.credit == 0 {
            let r = mk_rec(XpcPhase::Prepared);
            assert_eq!(
                target_on_commit(Some(&r)),
                XpcTransition::Advanced(XpcPhase::Committed)
            );
            if !anchored || cur.s == M::P || cur.s == M::C {
                out.push(St {
                    s: cur.s,
                    t: M::C,
                    credit: cur.credit + 1,
                    refund: cur.refund,
                });
            }
        }
        // 6. Target on ABORT-REQUEST: local None -> Aborted (authorisation
        //    for the source refund); ANCHORED needs source escrow
        //    `s in {P, C}` (the request carries the source Prepared leaf).
        if cur.t == M::N {
            assert_eq!(
                target_on_abort_request(None),
                XpcTransition::Advanced(XpcPhase::Aborted)
            );
            if !anchored || cur.s == M::P || cur.s == M::C {
                out.push(St {
                    s: cur.s,
                    t: M::A,
                    credit: cur.credit,
                    refund: cur.refund,
                });
            }
        }
        out
    }

    fn bfs(anchored: bool) -> BTreeSet<St> {
        let mut seen = BTreeSet::new();
        let mut queue = VecDeque::new();
        let start = St {
            s: M::N,
            t: M::N,
            credit: 0,
            refund: 0,
        };
        seen.insert(start);
        queue.push_back(start);
        while let Some(cur) = queue.pop_front() {
            for nx in successors(cur, anchored) {
                if seen.insert(nx) {
                    queue.push_back(nx);
                }
            }
        }
        seen
    }

    /// I1–I4 + I2 counters as plain booleans (P15 A.1).
    fn holds_invariants(st: St) -> bool {
        let i1 = !(st.s == M::A && st.t == M::C);
        let i2 = st.credit <= 1 && st.refund <= 1;
        let i3 = st.t != M::C || st.s == M::P || st.s == M::C;
        let i4 = st.s != M::A || st.t == M::N || st.t == M::A;
        i1 && i2 && i3 && i4
    }

    /// Violation labels mirroring `check()` in
    /// `code/xpc_refinement_full.py`: projection outside the 9 abstract
    /// states, double credit/refund, and the two named counterexamples.
    fn violations_of(st: St, abs: &BTreeSet<(M, M)>) -> Vec<&'static str> {
        let mut v = Vec::new();
        if !abs.contains(&(st.s, st.t)) {
            v.push("projection not in abstract reachable");
        }
        if st.credit > 1 || st.refund > 1 {
            v.push("double credit/refund");
        }
        if st.s == M::A && st.t == M::C && st.credit == 1 && st.refund == 1 {
            v.push("double spend");
        }
        if st.s == M::N && st.t == M::C && st.credit == 1 {
            v.push("mint without source");
        }
        v
    }

    fn count_violations(set: &BTreeSet<St>, abs: &BTreeSet<(M, M)>) -> usize {
        set.iter().map(|st| violations_of(*st, abs).len()).sum()
    }

    #[test]
    fn real_guards_match_model_assumptions() {
        // Local admissibility the model relies on (successors() asserts
        // these on every visit; pinned here as a direct unit check).
        assert_eq!(source_prepare(None), XpcTransition::Created);
        assert_eq!(target_prepare(None), XpcTransition::Created);
        let p = mk_rec(XpcPhase::Prepared);
        assert_eq!(
            source_on_prepare_ack(Some(&p)),
            XpcTransition::Advanced(XpcPhase::Committed)
        );
        assert_eq!(
            source_on_abort_ack(Some(&p)),
            XpcTransition::Advanced(XpcPhase::Aborted)
        );
        assert_eq!(
            target_on_commit(Some(&p)),
            XpcTransition::Advanced(XpcPhase::Committed)
        );
        assert_eq!(
            target_on_abort_request(None),
            XpcTransition::Advanced(XpcPhase::Aborted)
        );
        // Monotone refusals: the double-spend / re-credit edges stay shut.
        let c = mk_rec(XpcPhase::Committed);
        let a = mk_rec(XpcPhase::Aborted);
        assert!(matches!(
            source_on_abort_ack(Some(&c)),
            XpcTransition::Refused(_)
        ));
        assert!(matches!(
            target_on_commit(Some(&a)),
            XpcTransition::Refused(_)
        ));
        assert!(matches!(
            target_on_abort_request(Some(&p)),
            XpcTransition::Refused(_)
        ));
        // Model phases cover the real phase codes 1/2/3.
        assert_eq!(M::P.phase(), Some(XpcPhase::Prepared));
        assert_eq!(M::C.phase(), Some(XpcPhase::Committed));
        assert_eq!(M::A.phase(), Some(XpcPhase::Aborted));
        assert_eq!(M::N.phase(), None);
    }

    #[test]
    fn anchored_bfs_nine_states_zero_violations() {
        let abs = abstract_states();
        let seen = bfs(true);
        assert_eq!(seen.len(), 9, "ANCHORED must reach exactly 9 states");
        let proj: BTreeSet<(M, M)> = seen.iter().map(|st| (st.s, st.t)).collect();
        assert_eq!(
            proj, abs,
            "ANCHORED projections must equal the 9 abstract states"
        );
        for st in &seen {
            assert!(holds_invariants(*st), "I1–I4 violated at {st:?}");
            assert!(st.credit <= 1 && st.refund <= 1, "I2 violated at {st:?}");
            assert!(
                violations_of(*st, &abs).is_empty(),
                "unexpected violation at {st:?}"
            );
        }
        assert_eq!(count_violations(&seen, &abs), 0);
    }

    #[test]
    fn proof_only_bfs_sixteen_states_nine_violations() {
        let abs = abstract_states();
        let seen = bfs(false);
        assert_eq!(seen.len(), 16, "PROOF-ONLY must reach 16 states");
        assert_eq!(
            count_violations(&seen, &abs),
            9,
            "PROOF-ONLY must reproduce the 9 documented violations"
        );
    }

    #[test]
    fn proof_only_mint_without_source_regression() {
        // Counterexample `(N,C)` with `credit=1`: target credited with no
        // source escrow (fake `source_state_root` + proof passes proof-only).
        let abs = abstract_states();
        let proof_only = bfs(false);
        let mint = St {
            s: M::N,
            t: M::C,
            credit: 1,
            refund: 0,
        };
        assert!(
            proof_only.contains(&mint),
            "(N,C) mint must be reachable under PROOF-ONLY"
        );
        assert!(
            violations_of(mint, &abs).contains(&"mint without source"),
            "(N,C) must be flagged as mint without source"
        );
        // Honest gate: unreachable under ANCHORED, so a future fix that
        // re-anchors apply flips THIS assert honestly (it will fail).
        assert!(
            !bfs(true).contains(&mint),
            "(N,C) mint must stay unreachable under ANCHORED"
        );
    }

    #[test]
    fn proof_only_double_spend_regression() {
        // Counterexample `(A,C)` with `credit=1, refund=1`: credited on the
        // target AND refunded on the source.
        let abs = abstract_states();
        let proof_only = bfs(false);
        let ds = St {
            s: M::A,
            t: M::C,
            credit: 1,
            refund: 1,
        };
        assert!(
            proof_only.contains(&ds),
            "(A,C) double spend must be reachable under PROOF-ONLY"
        );
        assert!(
            violations_of(ds, &abs).contains(&"double spend"),
            "(A,C) must be flagged as double spend"
        );
        assert!(
            !holds_invariants(ds),
            "(A,C) must violate I1 (source=A yet target=C)"
        );
        assert!(
            !bfs(true).contains(&ds),
            "(A,C) double spend must stay unreachable under ANCHORED"
        );
    }

    #[test]
    fn ninth_state_p_c_commit_holds_escrow() {
        // The 9th state of P15 (missing from P5's 8): the target credits on
        // the source's `[Prepared, Committed]` leaf while the source still
        // holds the escrow (`s == P`). COMMIT accepts both phases.
        let anchored = bfs(true);
        let pc = St {
            s: M::P,
            t: M::C,
            credit: 1,
            refund: 0,
        };
        assert!(
            anchored.contains(&pc),
            "(P,C) must be reachable under ANCHORED"
        );
        assert!(holds_invariants(pc), "(P,C) must satisfy I1–I4");
        // The credit edge fires from Prepared exactly once; replays are
        // no-ops, never a second credit.
        let p = mk_rec(XpcPhase::Prepared);
        let c = mk_rec(XpcPhase::Committed);
        assert_eq!(
            target_on_commit(Some(&p)),
            XpcTransition::Advanced(XpcPhase::Committed)
        );
        assert_eq!(target_on_commit(Some(&c)), XpcTransition::Noop);
        // Escrow held: the source record behind `(P,C)` is still Prepared,
        // so it can still decide COMMIT (no premature refund).
        let src = mk_rec(XpcPhase::Prepared);
        assert_eq!(
            source_on_prepare_ack(Some(&src)),
            XpcTransition::Advanced(XpcPhase::Committed)
        );
        assert!(matches!(
            source_on_abort_ack(Some(&c)),
            XpcTransition::Refused(_)
        ));
    }
}

#[cfg(test)]
mod retention_tests {
    use super::*;

    fn committed_at(decided: u64) -> XpcRecord {
        let signer = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let tx = crate::sharding::Transaction::sign(&signer, [4u8; 32], 10, 280_000, 0, 0, 1);
        let mut rec = XpcRecord::prepared(tx, 0, 1, decided.saturating_sub(1));
        rec.phase = XpcPhase::Committed;
        rec.decided_height = decided;
        assert!(rec.is_consistent());
        rec
    }

    #[test]
    fn a_committed_source_re_emits_on_a_bounded_cadence_then_stops() {
        let rec = committed_at(10);
        // One emission the height after the decision, then one per interval,
        // never at the decision height itself.
        assert_eq!(source_action(&rec, 10), SourceAction::Idle);
        assert_eq!(source_action(&rec, 11), SourceAction::Commit);
        assert_eq!(source_action(&rec, 12), SourceAction::Idle);
        assert_eq!(
            source_action(&rec, 10 + XPC_COMMIT_REEMIT_INTERVAL),
            SourceAction::Commit
        );
        // After the early burst, a slow heartbeat keeps a late COMMIT
        // obtainable (a live target's PREPARE-ACK refreshes the window; a
        // silent one still gets a copy each slow interval).
        assert_eq!(
            source_action(&rec, 10 + 4 * XPC_COMMIT_REEMIT_INTERVAL + 1),
            SourceAction::Idle
        );
        assert_eq!(
            source_action(&rec, 10 + XPC_COMMIT_REEMIT_INTERVAL_SLOW),
            SourceAction::Commit
        );
        // Bounded: after the retention window the source owes nothing.
        // The height just before retirement is the FINAL copy, so a target
        // that came online late still gets a decision.
        assert_eq!(
            source_action(&rec, 10 + XPC_TERMINAL_RETENTION_HEIGHTS - 1),
            SourceAction::Commit
        );
        assert_eq!(
            source_action(&rec, 10 + XPC_TERMINAL_RETENTION_HEIGHTS - 2),
            SourceAction::Idle
        );
        assert_eq!(
            source_action(&rec, 10 + XPC_TERMINAL_RETENTION_HEIGHTS),
            SourceAction::Idle
        );
        assert_eq!(source_action(&rec, u64::MAX), SourceAction::Idle);
        // The window is sized for a real sync/restart at the live tempo, not
        // the old 256-height (~46 s at 240 ms) one.
        assert!(
            std::hint::black_box(XPC_TERMINAL_RETENTION_HEIGHTS) >= 360_000,
            "retention must cover a day at 240 ms: {XPC_TERMINAL_RETENTION_HEIGHTS}"
        );
    }

    #[test]
    fn only_terminal_records_are_retired_and_only_at_the_fixed_height() {
        let prepared = {
            let signer = ed25519_dalek::SigningKey::from_bytes(&[10u8; 32]);
            let tx = crate::sharding::Transaction::sign(&signer, [5u8; 32], 10, 280_000, 0, 0, 1);
            XpcRecord::prepared(tx, 0, 1, 10)
        };
        assert!(!is_retired(&prepared, u64::MAX));
        assert!(!is_retired_at(
            &prepared,
            10 + XPC_PREPARE_TTL_HEIGHTS,
            false
        ));
        assert!(!is_retired_at(
            &prepared,
            10 + XPC_PREPARE_TTL_HEIGHTS - 1,
            true
        ));
        assert!(is_retired_at(&prepared, 10 + XPC_PREPARE_TTL_HEIGHTS, true));
        let committed = committed_at(20);
        assert!(!is_retired(
            &committed,
            20 + XPC_TERMINAL_RETENTION_HEIGHTS - 1
        ));
        assert!(is_retired(&committed, 20 + XPC_TERMINAL_RETENTION_HEIGHTS));
        assert!(is_retired(&committed, u64::MAX));
    }

    #[test]
    fn target_prepare_slot_available_enforces_nonce_uniqueness_and_sender_cap() {
        let signer = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let from = signer.verifying_key().to_bytes();
        let tx_n0_a = crate::sharding::Transaction::sign(&signer, [1u8; 32], 10, 280_000, 0, 0, 1);
        let tx_n0_b = crate::sharding::Transaction::sign(&signer, [2u8; 32], 10, 280_000, 0, 0, 1);
        let rec_n0_a = XpcRecord::prepared(tx_n0_a.clone(), 0, 1, 10);

        // Same (source_shard, from, nonce) with a distinct tx_hash is refused.
        assert!(!target_prepare_slot_available(
            [&rec_n0_a],
            0,
            &from,
            0,
            &tx_n0_b.compute_tx_hash()
        ));
        // Same tx_hash is allowed (idempotency check is handled by target_prepare).
        assert!(target_prepare_slot_available(
            [&rec_n0_a],
            0,
            &from,
            0,
            &rec_n0_a.tx_hash
        ));

        // Distinct nonces are allowed up to MAX_ACTIVE_PREPARED_PER_SENDER, then blocked.
        let mut active = Vec::new();
        for nonce in 0..MAX_ACTIVE_PREPARED_PER_SENDER as u64 {
            let tx =
                crate::sharding::Transaction::sign(&signer, [3u8; 32], 10, 280_000, nonce, 0, 1);
            active.push(XpcRecord::prepared(tx, 0, 1, 10));
        }
        let tx_extra = crate::sharding::Transaction::sign(
            &signer,
            [3u8; 32],
            10,
            280_000,
            MAX_ACTIVE_PREPARED_PER_SENDER as u64,
            0,
            1,
        );
        assert!(!target_prepare_slot_available(
            active.iter(),
            0,
            &from,
            MAX_ACTIVE_PREPARED_PER_SENDER as u64,
            &tx_extra.compute_tx_hash()
        ));

        // Decided records do not consume active Prepared capacity.
        active[0].phase = XpcPhase::Committed;
        active[0].decided_height = 12;
        assert!(target_prepare_slot_available(
            active.iter(),
            0,
            &from,
            MAX_ACTIVE_PREPARED_PER_SENDER as u64,
            &tx_extra.compute_tx_hash()
        ));
    }

    #[test]
    fn the_opening_budget_plus_the_plan_never_exceeds_the_cap() {
        for plan_len in 0..=XPC_MAX_REEMITS_PER_HEIGHT {
            let opening = opening_prepare_budget(plan_len);
            assert!(
                plan_len + opening <= XPC_MAX_REEMITS_PER_HEIGHT,
                "plan={plan_len} opening={opening}"
            );
            let reserved = XPC_INBOUND_CONTROL_RESERVE.min(XPC_MAX_REEMITS_PER_HEIGHT - plan_len);
            assert_eq!(
                plan_len + opening + reserved,
                XPC_MAX_REEMITS_PER_HEIGHT,
                "the plan, the opening budget and the inbound reserve partition the cap"
            );
        }
        assert_eq!(
            opening_prepare_budget(0),
            XPC_MAX_REEMITS_PER_HEIGHT - XPC_INBOUND_CONTROL_RESERVE
        );
    }

    #[test]
    fn the_total_cap_bounds_the_legacy_and_2pc_outbound_budgets_alike() {
        // One total cap, not one per kind. Both the 2PC opening budget and the
        // legacy outbound budget must leave room for the plan and the inbound
        // reserve; neither may exceed the total the validator enforces.
        assert_eq!(
            XPC_MAX_CROSS_SHARD_RECORDS_PER_BLOCK,
            XPC_MAX_REEMITS_PER_HEIGHT
        );
        for plan_len in 0..=XPC_MAX_CROSS_SHARD_RECORDS_PER_BLOCK {
            let outbound = outbound_record_budget(plan_len);
            let reserved =
                XPC_INBOUND_CONTROL_RESERVE.min(XPC_MAX_CROSS_SHARD_RECORDS_PER_BLOCK - plan_len);
            assert_eq!(
                plan_len + outbound + reserved,
                XPC_MAX_CROSS_SHARD_RECORDS_PER_BLOCK,
                "plan={plan_len} outbound={outbound} reserve={reserved}"
            );
        }
        // The legacy flow has no plan (`plan_len = 0`) and gets the SAME
        // budget the 2PC openings would get with an empty plan.
        assert_eq!(
            outbound_record_budget(0),
            opening_prepare_budget(0),
            "legacy and 2PC openings share one total budget"
        );
    }
}
