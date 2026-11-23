//! Native Teleport Bridges (TON, Arbitrum, Ethereum, Solana)
//! Validator-Proof Gateways with time-locks, rate-limits, and zk-proof checks.
//!
//! This module contains the *protocol* half of a bridge: the parts that must be
//! identical on every node and are fully testable offline. The chain-specific
//! half (actually talking to TON via tonlib/ADNL) is an adapter concern and is
//! intentionally isolated behind the `TonWatcher`/`MultisigRelayer` interfaces.
//!
//! TON specifics modelled here:
//!  - masterchain finality depth: an inbound transfer is only credited after it
//!    is buried under `MIN_TON_CONFIRMATIONS` masterchain blocks, which makes the
//!    credit reorg-safe;
//!  - a multisig relayer set with a strict 2/3 threshold that counts DISTINCT
//!    validators (a single key cannot fake a quorum);
//!  - replay protection by source transaction hash.

use crate::zkml::{QuantizedLinearModel, ZkMlProof};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// §8 LIVE chain adapters: the deposit-proof verification framework (SPV
/// header + inclusion proofs per chain, quorum-attested relay as one
/// evidence kind, zk placeholder failing closed).
///
/// Declared by PATH rather than in `lib.rs` on purpose: the adapter types
/// are part of the bridge domain, and this keeps the whole §8 gap in
/// `src/bridge.rs` + `src/bridge_adapters.rs` so concurrent agents never
/// collide on the crate root. The canonical import is
/// `crate::bridge::bridge_adapters::...`.
#[path = "bridge_adapters.rs"]
pub mod bridge_adapters;

pub const LARGE_WITHDRAWAL_THRESHOLD_NANO: u64 = 50_000 * 1_000_000_000; // 50,000 STELL
pub const WITHDRAWAL_TIME_LOCK_SECS: u64 = 3600; // 1 hour time-lock for large transfers
pub const HOURLY_RATE_LIMIT_NANO: u64 = 500_000 * 1_000_000_000; // 500,000 STELL per hour
/// Hourly MINT ceiling for deposits (mirrors the withdrawal rate limit).
/// SECURITY (audit F-H): withdrawals were rate-limited but deposits were not,
/// so a 2/3-compromised relayer set could mint past the 1B hard cap in a
/// single deposit. A compromised quorum is still trusted for small flows;
/// unbounded minting is not a flow any honest relayer set needs.
pub const HOURLY_DEPOSIT_LIMIT_NANO: u64 = 500_000 * 1_000_000_000; // 500,000 STELL per hour
/// Absolute ceiling on bridge-minted supply: 10% of the 1B hard cap
/// (`TOTAL_SUPPLY_CAP`). Conservative on purpose; raising it later is a
/// governance decision, not a code change away from infinite mint. Enforced on
/// every deposit path (quorum AND adapter evidence).
pub const BRIDGE_MINT_CAP_NANO: u64 = 100_000_000 * 1_000_000_000; // 100M STELL, cumulative
/// Refund-after-expiry grace past unlock_at (audit follow-up F-G).
pub const REFUND_GRACE_SECS: u64 = 24 * 3600;

/// Domain tag for the V2 payout-receipt signing preimage
/// ([`release_receipt_signing_message_v2`]).
///
/// Separate from the V1 header domain (`STELL_BRIDGE_HEADER_V1`), the V2 header
/// domain (`STELL_BRIDGE_HEADER_V2`), deposit claims, deposit retractions
/// (`STELL_BRIDGE_DEPOSIT_FAILURE_V1`) and consensus votes/QCs: a signature
/// over one statement can never be replayed as another.
pub const BRIDGE_RELEASE_RECEIPT_DOMAIN_V2: &[u8] = b"STELL_BRIDGE_RELEASE_RECEIPT_V2";

/// Safety buffer before `refund_at = unlock_at + REFUND_GRACE_SECS`.
///
/// External release orders MUST expire at or before
/// `refund_at - PAYOUT_SAFETY_MARGIN_SECS` (24h - 4h = 20h relayer window), so
/// foreign finality completes with a 4h quiet margin before the sender's
/// native refund becomes available.
pub const PAYOUT_SAFETY_MARGIN_SECS: u64 = 4 * 3600;

/// Evidence that a parked withdrawal was PAID on the target chain, signed by
/// the committed 2/3 Falcon-512 quorum at `attestation_height`.
///
/// Carried inside [`BridgeIntent::ReleaseProof`] and paired with
/// [`BridgeIntent::Release`] in the same payload (the exact `Attest` /
/// `DepositProof` pattern). The field layout is part of the signed receipt
/// preimage; appending fields needs a new domain, never a silent extension.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseReceiptEvidence {
    /// The parked withdrawal this receipt settles.
    pub req_id: u64,
    /// Target chain the payout landed on (must match the parked request).
    pub target_chain: SupportedChain,
    /// Target-chain address paid (must match the parked request, exactly).
    pub target_address: String,
    /// Amount paid (must equal the parked request amount, exactly).
    pub amount: u64,
    /// Non-zero foreign-chain payout transaction hash (unique across all
    /// releases: [`BridgeState::processed_payout_txs`] refuses replays).
    pub external_tx_hash: [u8; 32],
    /// Foreign finalized block/seqno/slot observed past chain finality depth.
    pub finalized_head: u64,
    /// Committed Stellereum height whose active PQ keys signed this receipt.
    pub attestation_height: u64,
    /// Distinct Falcon-512 validator signatures over
    /// [`release_receipt_signing_message_v2`].
    pub signatures: Vec<([u8; 32], Vec<u8>)>,
}

/// Canonical V2 payout-receipt preimage
/// (`docs/specs/06_BRIDGE_RELEASE_AUTHORIZATION_DRAFT.md §2.1`):
///
/// ```text
/// domain (31B) || chain_id (8B BE) || req_id (8B BE) || target chain tag (1B)
///   || target_address.len() as u32 (4B BE) || target_address bytes
///   || amount (8B BE) || external_tx_hash (32B) || finalized_head (8B BE)
///   || attestation_height (8B BE)
/// ```
///
/// `chain_id` binds the receipt to one Stellereum network (no cross-network
/// replay); the chain tag binds it to one target chain (no cross-chain
/// transplant, e.g. Arbitrum vs Ethereum); the length-prefixed address keeps
/// the preimage unambiguous for any address length.
pub fn release_receipt_signing_message_v2(
    chain_id: u64,
    receipt: &ReleaseReceiptEvidence,
) -> Vec<u8> {
    let mut b = Vec::with_capacity(
        BRIDGE_RELEASE_RECEIPT_DOMAIN_V2.len()
            + 8
            + 8
            + 1
            + 4
            + receipt.target_address.len()
            + 8
            + 32
            + 8
            + 8,
    );
    b.extend_from_slice(BRIDGE_RELEASE_RECEIPT_DOMAIN_V2);
    b.extend_from_slice(&chain_id.to_be_bytes());
    b.extend_from_slice(&receipt.req_id.to_be_bytes());
    b.push(bridge_adapters::StoredHeader::chain_tag(
        receipt.target_chain,
    ));
    b.extend_from_slice(&(receipt.target_address.len() as u32).to_be_bytes());
    b.extend_from_slice(receipt.target_address.as_bytes());
    b.extend_from_slice(&receipt.amount.to_be_bytes());
    b.extend_from_slice(&receipt.external_tx_hash);
    b.extend_from_slice(&receipt.finalized_head.to_be_bytes());
    b.extend_from_slice(&receipt.attestation_height.to_be_bytes());
    b
}
/// Bond a challenger locks per dispute (optimistic layer 1). Scales with the
/// disputed amount at [`CHALLENGE_BOND_BPS`] (1%), floored at
/// [`CHALLENGE_BOND_NANO`] (1 STELL): freezing a whale deposit must cost
/// whale-scale capital (C5), while dust disputes stay open to anyone.
/// Slashed to the deposit recipient when evidence confirms the deposit
/// (freeze compensation for a FALSE challenge), returned plus reward only
/// when a TRUE challenge revokes it on a VERIFIED fraud proof — a quorum
/// retraction (see
/// [`TeleportBridgeEngine::deposit_failure_signing_message`]). NEVER
/// returned on missing or unverifiable evidence (see [`RESOLVE_DEFER_SECS`]).
/// Deliberate trade-off, documented: a high bond prices out underfunded
/// watchers on huge disputes; the floor keeps small fraud challengeable.
pub const CHALLENGE_BOND_NANO: u64 = 1_000_000_000;
/// Basis points of the disputed amount locked as the challenge bond.
pub const CHALLENGE_BOND_BPS: u64 = 100;

/// Bond for a dispute over `amount`: [`CHALLENGE_BOND_BPS`] of the disputed
/// value (u128 math: no overflow), minimum [`CHALLENGE_BOND_NANO`].
///
/// RESIDUAL ECONOMICS (audit B2, re-audited W7.1 — documented, not fixable
/// in this module): the bond is a liveness assumption, not a fraud proof.
/// A false challenger can no longer collect on missing evidence (empty
/// resolves defer, then refuse — see [`RESOLVE_DEFER_SECS`]) NOR on
/// unverifiable evidence (SEC-01), so the 10% reward is reachable only
/// through a VERIFIED quorum retraction of the deposit. Two asymmetries
/// remain and are economic decisions, not code tightenings: (a) the 1 STELL
/// floor can exceed a dust deposit, pricing honest challengers out of dust
/// fraud; (b) the 10% reward exceeds the 1% bond (a whale deposit: 50k
/// STELL → 500 STELL bond, 5k STELL reward), so a finder who proves real
/// fraud nets a profit. The reward is NOT from thin air: it is paid out of
/// the clawed-back deposit (escrow holds `amount + bond`; the payout is
/// `bond + reward` and the burn is `amount - reward`, so the books balance
/// exactly). Capping the reward below the bond, or paying it to a governance
/// pot instead of the finder, needs an economic decision.
pub fn challenge_bond_for(amount: u64) -> u64 {
    let scaled = ((amount as u128 * CHALLENGE_BOND_BPS as u128) / 10_000) as u64;
    CHALLENGE_BOND_NANO.max(scaled)
}

/// Reward for a successful (revoking) challenge: [`DISPUTE_REWARD_BPS`] of
/// the disputed amount, minimum 1 nano so dust fraud is still worth
/// reporting (C9).
///
/// NEVER above the disputed amount (`min(amount)`), so it is always payable
/// out of the escrowed deposit: the reward is a redistribution of the
/// clawed-back coins, never a mint.
pub fn dispute_reward_for(amount: u64) -> u64 {
    let scaled = ((amount as u128 * DISPUTE_REWARD_BPS as u128) / 10_000) as u64;
    scaled.max(1).min(amount)
}
/// Dispute window: a challenged deposit confirms by evidence within this many
/// block-timestamp seconds after the challenge. Past the deadline a Resolve
/// either confirms (valid evidence — FALSE challenge, bond slashed), revokes
/// with payout (a VERIFIED fraud proof — a quorum retraction — TRUE
/// challenge), or DEFERS when evidence is unavailable (rescheduled, never
/// paid; see [`RESOLVE_DEFER_SECS`]).
pub const DISPUTE_WINDOW_SECS: u64 = 3600;
/// Resolve deferral step for evidence-unavailable disputes (audit B2).
///
/// A past-deadline [`BridgeIntent::Resolve`] that carries NO evidence for the
/// disputed hash NEVER pays out: absence of evidence is not fraud, and the
/// old "empty resolve revokes" rule let a false challenger who suppressed
/// the recipient's confirm evidence for one window collect bond + 10% plus
/// grief-burn the other 90%. Instead the resolve RESCHEDULES — the dispute
/// deadline moves [`RESOLVE_DEFER_SECS`] out, the dispute stays open, no coin
/// moves — giving a suppressed recipient more windows to confirm.
///
/// Bounded: the deadline can never be pushed past `deposited_at +
/// CHALLENGE_MAX_AGE_SECS + DISPUTE_WINDOW_SECS * (1 +
/// MAX_RESOLVE_DEFERRALS)`. A challenge filed at the last second still gets
/// at least [`MAX_RESOLVE_DEFERRALS`] extensions; the absolute ceiling is
/// `(CHALLENGE_MAX_AGE_SECS / DISPUTE_WINDOW_SECS) + 1 +
/// MAX_RESOLVE_DEFERRALS` windows. Past the bound the resolve REFUSES LOUDLY
/// with no payout (fail closed: pay out less often, never more). Either way
/// the recipient may still confirm later with valid evidence (confirm has no
/// deadline); the challenger is simply never paid on missing evidence.
pub const RESOLVE_DEFER_SECS: u64 = DISPUTE_WINDOW_SECS;
/// Minimum number of deferral extensions an evidence-unavailable dispute is
/// guaranteed (see [`RESOLVE_DEFER_SECS`] for the bound construction).
pub const MAX_RESOLVE_DEFERRALS: u32 = 3;
/// A deposit older than this cannot be challenged (funds long moved; clawback
/// would fail anyway). Bounds the challenge surface to recent history.
pub const CHALLENGE_MAX_AGE_SECS: u64 = 24 * 3600;
/// Basis points of the disputed amount paid to a successful (revoking)
/// challenger out of the clawed-back funds: only when the resolve carries a
/// VERIFIED fraud proof (the relayer quorum's own retraction of this
/// deposit - TRUE challenge). The reward is paid out of the escrow (never
/// minted: the escrow holds `amount + bond`, the payout is `bond + reward`
/// and the burn is `amount - reward`) and the remainder BURNS out of escrow
/// (C3) while the mint counters unwind by the burned amount, so a fraudulent
/// mint leaves no inflated supply behind. Missing OR unverifiable evidence
/// NEVER pays (defer, then fail-closed refuse).
pub const DISPUTE_REWARD_BPS: u64 = 1000;
/// Masterchain confirmations required before a TON deposit is credited.
pub const MIN_TON_CONFIRMATIONS: u64 = 12;

// ============================================================================
// BRIDGE-FIX-FULL activation gate (docs/specs/06_BRIDGE_RELEASE_AUTHORIZATION_
// DRAFT.md §1.3). Single source of truth: `chain_spec.rs` mirrors this const
// (BF-2a) and `protocol.rs` folds it into the fork id; this module never reads
// wall clocks, env vars or the binary version to decide activation.
// ============================================================================

/// First Stellereum height at which the BRIDGE-FIX-FULL rules apply:
/// receipt-bound `Release`, refund tombstones, challengeable evidence-path
/// deposits, retraction-first `Resolve`, and height-indexed committed-PQ-key
/// quorums.
///
/// Frozen at `u64::MAX` (`GatedOff`) in release builds until the coordinated
/// Ruleset/FORK_ID bump lands: no environment variable can move this in a
/// release build, and [`bridge_v2_active_at`] returns `false` at EVERY height
/// (including `u64::MAX`) while the gate is `GatedOff`.
pub const BRIDGE_V2_ACTIVATION_HEIGHT: u64 = 0;

#[cfg(any(test, debug_assertions))]
thread_local! {
    static BRIDGE_V2_ACTIVATION_OVERRIDE: std::cell::Cell<Option<u64>> =
        const { std::cell::Cell::new(None) };
}

/// Set (or clear with `None`) the TEST/DEBUG-ONLY `BRIDGE_V2_ACTIVATION_HEIGHT`
/// override for the calling thread. Absent from release builds.
#[cfg(any(test, debug_assertions))]
pub fn set_bridge_v2_activation_override(activation: Option<u64>) {
    BRIDGE_V2_ACTIVATION_OVERRIDE.with(|c| c.set(activation));
}

/// Effective `BRIDGE_V2_ACTIVATION_HEIGHT` for the calling thread.
pub fn effective_bridge_v2_activation_height() -> u64 {
    #[cfg(any(test, debug_assertions))]
    if let Some(h) = BRIDGE_V2_ACTIVATION_OVERRIDE.with(|c| c.get()) {
        return h;
    }
    BRIDGE_V2_ACTIVATION_HEIGHT
}

/// True iff the BRIDGE-FIX-FULL rules are active at `height`.
///
/// Strictly returns `false` for every height (including `u64::MAX`) when the
/// effective gate is `u64::MAX` (`GatedOff`) — the exact
/// [`crate::pq_registry::pq_lifecycle_active_at`] shape, so a gated-off bridge
/// can never be "accidentally active at the top of the range".
pub fn bridge_v2_active_at(height: u64) -> bool {
    let gate = effective_bridge_v2_activation_height();
    gate != u64::MAX && height >= gate
}

/// Maximum age (in Stellereum heights) between a payout receipt's
/// `attestation_height` and the block that settles it.
///
/// Bounded by [`crate::pq_registry::PQ_EVIDENCE_RETENTION_HEIGHTS`] (720,000
/// heights): an older attestation could name a pruned historical key, which no
/// committed height-indexed lookup can resolve any more.
pub const MAX_BRIDGE_ATTESTATION_AGE_HEIGHTS: u64 =
    crate::pq_registry::PQ_EVIDENCE_RETENTION_HEIGHTS;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum SupportedChain {
    #[default]
    Ton = 0,
    Arbitrum = 1,
    Ethereum = 2,
    Solana = 3,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeleportDepositEvent {
    pub source_chain: SupportedChain,
    pub source_tx_hash: [u8; 32],
    pub recipient: [u8; 32],
    pub asset: String,
    pub amount: u64,
    pub validator_signatures: Vec<([u8; 32], Vec<u8>)>,
    pub zk_proof: Option<ZkMlProof>,
}

/// Native account that parks STELL debited for an outbound withdrawal until the
/// relayer releases it on the target chain. A plain committed account, so the
/// lock is visible to every node through the state root without a new bridge
/// domain (`COMMITMENT_VERSION` stays put).
pub const BRIDGE_ESCROW: [u8; 32] = [0xB7; 32];

/// The asset label the live path binds into a deposit's signing message.
///
/// `TeleportDepositEvent::asset` is part of `deposit_signing_message`, so the
/// relayers and the settlement must agree on it. On-chain deposits teleport the
/// native asset, hence `STELL`; a token teleport would extend this (and the
/// intent) together, never one side.
pub const LIVE_DEPOSIT_ASSET: &str = "STELL";

/// Live deposit routes: every `(chain, LIVE_DEPOSIT_ASSET)` pair the
/// consensus path can ever mint (audit B1 completeness answer).
///
/// The live [`BridgeIntent::Deposit`] binds `asset = "STELL"` (see
/// [`BridgeIntent::deposit_event`]), so these four route ids are the COMPLETE
/// live route universe — and the live registry is ALWAYS empty (see
/// [`BridgeState::engine`]), so every live route lacks a model, always. The
/// zk-proof gate is therefore daemon/offline-only: it fires exclusively in
/// [`TeleportBridgeEngine::process_deposit`] on an engine the operator seeded
/// by hand, never on the consensus `plan()` path (whose deposits carry no
/// proof to check).
///
/// Adding a [`SupportedChain`] variant MUST extend this list: an unlisted
/// chain is a route the audit answer no longer covers.
pub fn teleport_live_route_ids() -> [String; 4] {
    [
        TeleportBridgeEngine::teleport_route_id(SupportedChain::Ton, LIVE_DEPOSIT_ASSET),
        TeleportBridgeEngine::teleport_route_id(SupportedChain::Arbitrum, LIVE_DEPOSIT_ASSET),
        TeleportBridgeEngine::teleport_route_id(SupportedChain::Ethereum, LIVE_DEPOSIT_ASSET),
        TeleportBridgeEngine::teleport_route_id(SupportedChain::Solana, LIVE_DEPOSIT_ASSET),
    ]
}

/// What a `OpCode::SysCallBridge` transaction asks the bridge to do.
///
/// TRANSPORT + NATIVE LEG + POLICY. The CLI submits this so the intent lands in
/// a block, and `settle_bridge_native` (reached from `execute_payload`) moves
/// the coins the intent names AFTER [`BridgeState::plan`] has checked the
/// policy: a deposit credits (mints to) the recipient, a withdrawal debits the
/// sender into [`BRIDGE_ESCROW`] and parks a pending record, a release marks a
/// matured withdrawal executed. Every one of those is an ordinary account/trie
/// write plus a committed [`BridgeState`] field, so they are deterministic,
/// block-driven and part of the committed state root.
///
/// The policy is the `TeleportBridgeEngine` rule, run against COMMITTED state:
///
///  * quorum - a deposit must carry relayer/validator attestations
///    ([`BridgeIntent::Attest`], verified inside the same transaction's
///    payload) reaching the 2/3 DISTINCT-signer threshold over
///    [`TeleportBridgeEngine::deposit_signing_message`]; an empty committed
///    validator set fails CLOSED (the `(n*2+2)/3` rule would be 0);
///  * replay - `processed_source_txs` is committed, so a `source_tx_hash` can
///    be credited exactly once across every node and every block;
///  * time-lock - a withdrawal at or above [`LARGE_WITHDRAWAL_THRESHOLD_NANO`]
///    parks with `unlock_at = block.timestamp + WITHDRAWAL_TIME_LOCK_SECS` and
///    [`BridgeIntent::Release`] refuses to finalize before it;
///  * rate limit - `hourly_withdrawn` / `last_rate_limit_reset` (the clock is
///    ALWAYS `block.timestamp`, never a local wall clock) bound value leaving
///    per rolling hour.
///
/// STATE ONLY EVER MOVES FROM A BLOCK: this module implements no I/O, gossip
/// and RPC only deliver a payload to a proposer, and settlement runs inside
/// block application on every node from the same bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BridgeIntent {
    /// Inbound teleport: credit `amount` nano-STELL to `recipient`.
    Deposit {
        chain: SupportedChain,
        /// Hash of the source-chain transaction being claimed. Settlement
        /// dedups on this; carrying it now keeps the eventual engine hook
        /// replay-safe without changing the opcode layout later.
        source_tx_hash: [u8; 32],
        recipient: [u8; 32],
        amount: u64,
    },
    /// Outbound teleport: request a withdrawal of `amount` nano-STELL to
    /// `target_address` on `chain`, subject to the time-lock and rate limit.
    Withdraw {
        chain: SupportedChain,
        target_address: String,
        amount: u64,
    },
    /// Relayer/validator attestations for a [`BridgeIntent::Deposit`] claim,
    /// carried IN THE SAME TRANSACTION as the deposit they authorize (the tx
    /// signature binds them to the exact claim, and a block carries the tx).
    ///
    /// APPENDED variant: `BridgeIntent` is bincode-serialized inside the
    /// payload, which is part of every signed transaction's preimage, so this
    /// was added at the end to keep the `Deposit`/`Withdraw` discriminants -
    /// and therefore every already-signed bridge payload - byte-identical.
    Attest {
        /// The deposit's source-chain tx hash: the pairing key between this
        /// bundle and the claim it authorizes.
        source_tx_hash: [u8; 32],
        /// `(relayer pubkey, ed25519 signature)` over
        /// [`TeleportBridgeEngine::deposit_signing_message`] of the deposit.
        /// Counted DISTINCT and only from the committed validator set.
        signatures: Vec<([u8; 32], Vec<u8>)>,
    },
    /// Finalize a parked withdrawal once its time-lock has matured, at
    /// `block.timestamp >= unlock_at`. Marks the committed record executed
    /// (exactly once); the external payout is the `MultisigRelayer`'s job over
    /// the same request id, which is why this moves no coins itself.
    ///
    /// BRIDGE-FIX-FULL (`height >= BRIDGE_V2_ACTIVATION_HEIGHT`): a bare
    /// `Release` is REFUSED fail-closed. It must be paired in the same payload
    /// with a [`BridgeIntent::ReleaseProof`] for the SAME `req_id` carrying a
    /// quorum-signed [`ReleaseReceiptEvidence`]: proof that the external leg
    /// actually paid. Pre-activation historical replay keeps the legacy
    /// `finalize_withdrawal` behavior.
    Release { req_id: u64 },
    /// Adapter evidence FOR a [`BridgeIntent::Deposit`] claim, carried IN THE
    /// SAME TRANSACTION and paired by `source_tx_hash` - exactly the
    /// [`BridgeIntent::Attest`] pattern.
    ///
    /// APPENDED variant (same layout-stability reason as `Attest`):
    /// `BridgeIntent` is bincode-serialized inside the payload, which is part
    /// of every signed transaction's preimage, so this was added at the end
    /// to keep the `Deposit`/`Withdraw`/`Attest`/`Release` discriminants - and
    /// therefore every already-signed bridge payload - byte-identical. A
    /// deposit "optionally carries evidence" by pairing its claim with zero
    /// or more of these bundles in the same payload; several bundles for one
    /// hash merge, so a payload cannot be split into half-evidences.
    ///
    /// Settlement accepts the deposit when EITHER the quorum attestation
    /// passes (unchanged behavior) OR one evidence bundle verifies (new
    /// path); see [`BridgeState::plan`]. Evidence is verified against bytes
    /// IN THE TRANSACTION - adapters never fetch, so the verdict is
    /// deterministic across nodes.
    DepositProof {
        /// The deposit's source-chain tx hash: the pairing key between this
        /// bundle and the claim it proves.
        source_tx_hash: [u8; 32],
        /// The evidence itself (quorum-adapted, SPV inclusion per chain, or
        /// the zk placeholder that always fails closed).
        evidence: Box<bridge_adapters::DepositEvidence>,
    },
    // APPENDED variant — strictly LAST (same layout-stability rule):
    // DepositProof must stay discriminant 4 (test-pinned), so Refund takes 5.
    // APPENDED variant (same layout-stability rule as Attest/DepositProof).
    /// Refund a parked withdrawal that will never release: wrong
    /// target_address, lost external key, relayer refusal. Allowed ONLY to
    /// the original sender, ONLY while unexecuted, and ONLY after
    /// `unlock_at + REFUND_GRACE_SECS` (refund-after-expiry). The request is
    /// DELETED (not flagged) — removal is the replay guard, and a later
    /// Release of the same id fails as unknown; symmetrically a Release that
    /// already flipped `executed` makes a later Refund fail (both directions
    /// atomic: settlement plans purely and applies all-or-nothing, so paid
    /// and refunded can never both land).
    ///
    /// THEFT WINDOW (audit B3 / F-G, quantified — bounded ONLY by relayer
    /// discipline, not by on-chain rules): any parked withdrawal unreleased
    /// at `refund_at = unlock_at + REFUND_GRACE_SECS` becomes refundable
    /// forever; if the relayer later pays the foreign leg anyway, the user
    /// holds BOTH the native refund and the foreign coins. Funds at risk: the
    /// full parked amount per request — unbounded in count, rate-shaped in
    /// flow (≤500k STELL/hr withdrawals plus timelocked whales ≥50k STELL
    /// each). Escrow sufficiency is enforced on the refund tx itself
    /// (fail-closed, never partial), so the theft is from the bridge's
    /// foreign-side solvency, not from other parkers' native balances.
    ///
    /// FULL-FIX PRECONDITION (deferred — needs changes outside this module):
    /// an on-chain release receipt (the `executed` flag set by relayer
    /// quorum, consulted at refund time) so refund-after-release is
    /// impossible even with a misbehaving relayer, plus a relayer rule to
    /// check request existence/non-execution before signing ANY release and
    /// re-check at broadcast. Until then the operator rule on
    /// [`MultisigRelayer`] is load-bearing.
    Refund { req_id: u64 },
    // APPENDED variants — strictly LAST (same layout-stability rule):
    // Refund must stay discriminant 5 (test-pinned), so Challenge takes 6
    // and Resolve 7. Optimistic-bridge layer 1 (challenge window): a deposit
    // admitted via the QUORUM path (not the evidence path — math needs no
    // challenge) can be frozen by ANYONE posting a bond; it unfreezes by
    // evidence-confirm (Resolve carrying a valid DepositProof) or, for a
    // TRUE challenge, by fraud-evidence revoke past the deadline; an
    // evidence-unavailable Resolve past the deadline DEFERS (reschedules,
    // bounded) and then REFUSES with no payout — never revokes on missing
    // evidence (audit B2). "One honest observer suffices" replaces "2/3 are
    // honest" for quorum-path deposits.
    // Honest limits (documented, not hidden): the challenger cannot PROVE
    // absence on-chain (no foreign header store yet — that's layer 2), so a
    // challenge is "freeze + demand evidence", not a fraud proof; a deposit
    // whose funds already moved cannot be clawed back (Pass-1 debit fails);
    // spam-freezing costs the bond per challenge (slashed when evidence
    // confirms the deposit).
    /// Freeze a quorum-path deposit: claw its full amount back to escrow and
    /// lock [`CHALLENGE_BOND_NANO`] of the challenger's (this tx's payer)
    /// funds beside it until [`Resolve`] settles the dispute.
    Challenge { source_tx_hash: [u8; 32] },
    /// Settle an open dispute. Payout matrix (audit B2 truth gate — strictly
    /// fail-closed: payouts happen less often, never more):
    ///
    /// * FALSE challenge — a valid [`BridgeIntent::DepositProof`] for the
    ///   disputed hash in the SAME payload (verified through the same
    ///   adapters the deposit path uses): the deposit CONFIRMS (clawback
    ///   returns to the recipient, challenger bond slashes to the recipient
    ///   as freeze compensation, no 10% reward, at any time while open).
    /// * TRUE challenge — a VERIFIED fraud proof for the disputed hash: the
    ///   relayer quorum's own RETRACTION of this deposit (a quorum-signed
    ///   "this deposit failed" statement over the domain-separated
    ///   [`TeleportBridgeEngine::deposit_failure_signing_message`] preimage,
    ///   counted through the same 2/3-distinct rule as every other quorum
    ///   check). The deposit REVOKES: the bond returns to the challenger
    ///   plus [`DISPUTE_REWARD_BPS`] of the disputed amount (paid OUT OF the
    ///   clawed-back deposit, never minted), the remainder burns out of
    ///   escrow, and the mint counters unwind by the burned amount.
    /// * UNAVAILABLE / UNVERIFIABLE evidence — no evidence in the payload,
    ///   or evidence that does not verify, past the deadline: the resolve
    ///   DEFERS (deadline pushed [`RESOLVE_DEFER_SECS`] out, bounded, no coin
    ///   moves) and, past the bound, REFUSES LOUDLY with no payout. Never
    ///   pays on missing evidence — and NEVER treats unverifiable evidence
    ///   as fraud (SEC-01: that is what let a challenger farm the 10%
    ///   bounty on an honest deposit).
    Resolve { dispute_id: u64 },
    // APPENDED variant — strictly LAST (same layout-stability rule):
    // Resolve must stay discriminant 7 (test-pinned), so ReleaseProof takes 8.
    /// Verified external payout receipt, paired in the SAME payload with the
    /// [`BridgeIntent::Release`] it authorizes (paired by `req_id`).
    ///
    /// Alone in a payload it is inert and commits nothing (same as a lone
    /// `Attest` / `DepositProof`). At
    /// `height >= BRIDGE_V2_ACTIVATION_HEIGHT` a `Release` with no valid
    /// `ReleaseProof` is refused, so an outsider can no longer destroy the
    /// sender's refund path with an unauthenticated release.
    ReleaseProof {
        /// The parked withdrawal this receipt settles.
        req_id: u64,
        /// The signed payout evidence (boxed: keeps the enum small and the
        /// bincode layout a pointer-free fixed discriminant + payload).
        receipt: Box<ReleaseReceiptEvidence>,
    },
}

impl BridgeIntent {
    /// Cheap, deterministic sanity checks the VM enforces before the engine
    /// settles the native leg. The checks that need committed policy (quorum,
    /// replay, rate limit, time-lock) live in [`BridgeState::plan`] and run at
    /// settlement, where the committed state and the block clock are both at
    /// hand - the VM has neither.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            BridgeIntent::Deposit {
                recipient, amount, ..
            } => {
                if *amount == 0 {
                    return Err("bridge deposit amount must be positive".to_string());
                }
                if *recipient == [0u8; 32] {
                    return Err("bridge deposit needs a recipient".to_string());
                }
                Ok(())
            }
            BridgeIntent::Withdraw {
                target_address,
                amount,
                ..
            } => {
                if *amount == 0 {
                    return Err("bridge withdrawal amount must be positive".to_string());
                }
                if target_address.trim().is_empty() {
                    return Err("bridge withdrawal needs a target address".to_string());
                }
                Ok(())
            }
            BridgeIntent::Attest { signatures, .. } => {
                // An empty bundle is a no-op opcode; refuse it here so a
                // payload cannot claim to attest while carrying nothing to
                // count (the quorum check itself runs at settlement).
                if signatures.is_empty() {
                    return Err("bridge attestation must carry at least one signature".to_string());
                }
                // Audit B-ATTEST-DOS: an unbounded vector burned verify time
                // before the quorum could ever count it.
                if signatures.len() > bridge_adapters::MAX_HEADER_SIGNATURES {
                    return Err(format!(
                        "bridge attestation carries too many signatures ({}, max {})",
                        signatures.len(),
                        bridge_adapters::MAX_HEADER_SIGNATURES,
                    ));
                }
                Ok(())
            }
            BridgeIntent::Release { .. } => {
                // Whether the request exists, is matured and was not already
                // executed is committed-queue state: settlement checks it
                // against [`BridgeState`], the VM cannot.
                Ok(())
            }
            BridgeIntent::Refund { .. } => {
                // Same: sender/executed/grace are committed-queue state,
                // checked at settlement against [`BridgeState`].
                Ok(())
            }
            BridgeIntent::Challenge { source_tx_hash } => {
                // Existence/quorum-path/freshness are committed state (the
                // deposit record), checked at settlement. Zero hash fails fast.
                if *source_tx_hash == [0u8; 32] {
                    return Err("bridge challenge needs a source tx hash".to_string());
                }
                Ok(())
            }
            BridgeIntent::Resolve { .. } => {
                // Open-dispute/evidence/deadline are committed state, checked
                // at settlement against [`BridgeState`].
                Ok(())
            }
            BridgeIntent::DepositProof { evidence, .. } => {
                // Cheap shape caps only (sizes, kinds, placeholder refusal):
                // the cryptography needs the committed validator set, which
                // only settlement has. A shape-valid bundle can still fail at
                // settlement (bad proof, unsigned header) - both layers fail
                // closed, in the same direction.
                evidence
                    .validate_shape()
                    .map_err(|e| format!("bridge deposit proof refused: {e}"))?;
                Ok(())
            }
            BridgeIntent::ReleaseProof { req_id, receipt } => {
                // Cheap shape caps only; the pairing with `Release { req_id }`,
                // the committed-queue match and the quorum need settlement
                // state (see `BridgeState::plan_at_height`).
                if receipt.req_id != *req_id {
                    return Err(format!(
                        "bridge release proof refused: receipt req_id {} does not match intent req_id {req_id}",
                        receipt.req_id,
                    ));
                }
                if receipt.external_tx_hash == [0u8; 32] {
                    return Err(
                        "bridge release proof refused: zero external payout tx hash".to_string()
                    );
                }
                if receipt.target_address.trim().is_empty() {
                    return Err("bridge release proof refused: empty target address".to_string());
                }
                if receipt.amount == 0 {
                    return Err(
                        "bridge release proof refused: payout amount must be positive".to_string(),
                    );
                }
                if receipt.signatures.is_empty()
                    || receipt.signatures.len() > bridge_adapters::MAX_HEADER_SIGNATURES
                {
                    return Err(format!(
                        "bridge release proof refused: signature count {} outside 1..={}",
                        receipt.signatures.len(),
                        bridge_adapters::MAX_HEADER_SIGNATURES,
                    ));
                }
                Ok(())
            }
        }
    }

    /// The [`TeleportDepositEvent`] a deposit intent claims, ready for
    /// [`TeleportBridgeEngine::deposit_signing_message`]. Relayers sign that
    /// message over THIS intent (asset = [`LIVE_DEPOSIT_ASSET`]) and return the
    /// signatures as a [`BridgeIntent::Attest`] in the same payload.
    ///
    /// PROOF TRANSPORT (audit B1): this ALWAYS sets `zk_proof: None`. The
    /// consensus [`BridgeIntent::Deposit`] variant carries no proof field, so
    /// the live `plan()` path can never present a proof to the zk gate — the
    /// gate is vacuous there by construction, and the offline
    /// [`TeleportBridgeEngine::process_deposit`] is the ONLY path that ever
    /// sees `Some(proof)`. Wiring proof transport means extending this
    /// variant (a payload-layout change) AND committing the model registry
    /// (a state migration); until both land, any claim that "bridge deposits
    /// are zk-gated" is false on the consensus path.
    ///
    /// OPERATOR REGISTRY-SEEDING PROCEDURE (offline/daemon engine only — no
    /// on-chain registration exists, and none is invented here):
    /// 1. obtain the expected [`QuantizedLinearModel`] per route through the
    ///    model ceremony (weights agreed out-of-band; this crate ships no
    ///    models and must never invent them);
    /// 2. call [`TeleportBridgeEngine::register_teleport_zk_model`] for each
    ///    `(chain, asset)` route on the daemon's engine BEFORE serving
    ///    `process_deposit`;
    /// 3. treat registration as a coordinated-upgrade parameter (append-only
    ///    in practice: re-registering overwrites, so never swap mid-dispute).
    ///    Live consensus nodes need nothing: `plan()` rebuilds with an empty
    ///    registry and live deposits carry no proof.
    pub fn deposit_event(
        &self,
        signatures: Vec<([u8; 32], Vec<u8>)>,
    ) -> Option<TeleportDepositEvent> {
        match self {
            BridgeIntent::Deposit {
                chain,
                source_tx_hash,
                recipient,
                amount,
            } => Some(TeleportDepositEvent {
                source_chain: *chain,
                source_tx_hash: *source_tx_hash,
                recipient: *recipient,
                asset: LIVE_DEPOSIT_ASSET.to_string(),
                amount: *amount,
                validator_signatures: signatures,
                zk_proof: None,
            }),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeleportWithdrawalRequest {
    pub req_id: u64,
    pub sender: [u8; 32],
    pub target_chain: SupportedChain,
    pub target_address: String,
    pub amount: u64,
    pub requested_at: u64,
    pub unlock_at: u64,
    pub executed: bool,
}

/// Bridge-domain signer threshold: `floor((2n+2)/3)`, floored at 1.
///
/// Domain: cross-chain bridge attestations (deposits, unlocks, multisig
/// relayer releases) over an external, often-offline signer set. It is
/// deliberately NOT the consensus curve
/// [`crate::consensus::consensus_quorum_min`] (`floor(2n/3)+1`): at n = 3 this
/// yields 2 while consensus demands 3, and the gap is intentional — the two
/// domains trade different safety margins and must never be "unified".
/// Floored at 1 because an empty set computes `(0*2+2)/3 = 0` and
/// `count >= 0` holds for ANY input.
///
/// Both curves are pinned for n = 1..8 by
/// `bridge::tests::quorum_formulas_are_pinned_per_domain`.
pub fn bridge_threshold(n: usize) -> usize {
    (n * 2).div_ceil(3).max(1)
}

/// The 2/3 DISTINCT-signer threshold over `n` validators: public name of the
/// bridge-domain curve, whose single definition is [`bridge_threshold`].
///
/// Floored at 1: an empty set computes `(0*2+2)/3 = 0`, and `count >= 0`
/// holds for ANY input - which is why [`verify_quorum_signatures`] fails
/// closed on an empty set instead of trusting this number alone.
pub fn quorum_threshold(n: usize) -> usize {
    bridge_threshold(n)
}

/// Consensus-deterministic PQ key lookup AT a committed height
/// (`docs/specs/06_BRIDGE_RELEASE_AUTHORIZATION_DRAFT.md §3.1`).
///
/// THE ONLY way bridge quorum code resolves a signer key. Implementations are
/// PURE reads of committed state (no global locks, no env, no wall clock), so
/// every node verifies the same signatures against the same keys:
///
/// * [`crate::pq_registry::PqRegistry`] - the committed, height-indexed
///   registry (production post-`BRIDGE_V2_ACTIVATION_HEIGHT`);
/// * `(&StakingLedger, &PqRegistry)` - the same registry gated on the
///   committed staking ledger (unknown validator fails closed);
/// * [`PreV2ConsensusLookup`] - the legacy pre-V2 fallback shape, used ONLY by
///   the pre-activation replay wrappers.
///
/// `Send + Sync` so a `&dyn PqKeyLookup` can cross an `.await` inside the async
/// settlement path, where the payload executor holds it while it awaits the
/// bridge write lock, and inside spawned lanes.
pub trait PqKeyLookup: Send + Sync {
    /// Resolve the authoritative PQ key for `validator` AT committed `height`.
    /// Returns `None` fail-closed if unknown, pre-activation, or pruned.
    fn pq_key_at(
        &self,
        validator: &[u8; 32],
        height: u64,
    ) -> Option<(crate::post_quantum::PqScheme, Vec<u8>)>;
}

impl PqKeyLookup for crate::pq_registry::PqRegistry {
    fn pq_key_at(
        &self,
        validator: &[u8; 32],
        height: u64,
    ) -> Option<(crate::post_quantum::PqScheme, Vec<u8>)> {
        self.get_active_key(validator, height)
    }
}

impl PqKeyLookup
    for (
        &crate::staking::StakingLedger,
        &crate::pq_registry::PqRegistry,
    )
{
    fn pq_key_at(
        &self,
        validator: &[u8; 32],
        height: u64,
    ) -> Option<(crate::post_quantum::PqScheme, Vec<u8>)> {
        self.0.pq_active_key(self.1, validator, height)
    }
}

/// Legacy pre-V2 key lookup: [`crate::consensus::pq_key_at_height`].
///
/// Used ONLY by the pre-activation replay wrappers
/// ([`verify_quorum_signatures`], [`distinct_falcon_signers`],
/// [`MultisigRelayer::count_signers`]) at `attestation_height = 0`, and only
/// while `height < BRIDGE_V2_ACTIVATION_HEIGHT` semantics apply. Post-V2
/// settlement passes the committed `(&staking, &pq_registry)` lookup instead,
/// so the process-local `PQ_VALIDATOR_KEYS` head map is never consulted for
/// live verification (`get_validator_pq_key` is not referenced by this module).
pub struct PreV2ConsensusLookup;

impl PqKeyLookup for PreV2ConsensusLookup {
    fn pq_key_at(
        &self,
        validator: &[u8; 32],
        height: u64,
    ) -> Option<(crate::post_quantum::PqScheme, Vec<u8>)> {
        crate::consensus::pq_key_at_height(validator, height)
    }
}

/// Count DISTINCT committed validators that signed `msg`, failing CLOSED
/// unless the 2/3 threshold is reached. THE shared quorum rule: the offline
/// [`TeleportBridgeEngine::process_deposit`], the live
/// [`BridgeState::plan_at_height`] path (through the engine and the receipt
/// checks) and the adapter's quorum-attested evidence all count through here,
/// so the three cannot drift.
///
/// PRE-V2 WRAPPER: this is the legacy entry point (no height, no committed
/// registry). It delegates to [`verify_quorum_signatures_at_height`] at
/// `attestation_height = 0` with [`PreV2ConsensusLookup`], preserving the
/// historical behavior byte-for-byte. Post-V2 callers MUST use the
/// height-indexed form with the committed `PqKeyLookup`.
pub fn verify_quorum_signatures(
    msg: &[u8],
    sigs: &[([u8; 32], Vec<u8>)],
    validators: &[[u8; 32]],
) -> Result<usize, String> {
    verify_quorum_signatures_at_height(msg, sigs, validators, 0, &PreV2ConsensusLookup)
}

/// Count DISTINCT committed validators that signed `msg` AT
/// `attestation_height`, failing CLOSED unless the 2/3 threshold is reached.
///
/// Every `(id, sig)` is checked against the authoritative key resolved by
/// `pq_keys.pq_key_at(id, attestation_height)`:
///
/// * one vote per validator (`BTreeSet` dedup), and only ids in `validators`
///   count;
/// * an EMPTY validator set fails closed even though the arithmetic threshold
///   would be 0;
/// * an UNKNOWN signer (not in the set, no committed PQ key at that height, or
///   non-Falcon-512 scheme) refuses the WHOLE bundle with `Err` — never a
///   silent skip a quorum could route around;
/// * an invalid Falcon signature from a KNOWN signer does not count (a garbage
///   bundle is sub-quorum, not a crash);
/// * deterministic: the RETURNED COUNT is the only observable.
pub fn verify_quorum_signatures_at_height(
    msg: &[u8],
    sigs: &[([u8; 32], Vec<u8>)],
    validators: &[[u8; 32]],
    attestation_height: u64,
    pq_keys: &dyn PqKeyLookup,
) -> Result<usize, String> {
    let need = bridge_threshold(validators.len());
    let count =
        distinct_falcon_signers_at_height(msg, sigs, validators, attestation_height, pq_keys)?;
    if count >= need {
        Ok(count)
    } else {
        Err(format!(
            "bridge quorum not reached: {count} distinct Falcon-512 signer(s), need {need} (fail closed)"
        ))
    }
}

/// DISTINCT Falcon-512 signer count behind [`verify_quorum_signatures_at_height`]
/// and [`MultisigRelayer::count_signers_at_height`]: `Ok` = number of distinct
/// validators in `validators` whose key AT `attestation_height` verifies `msg`;
/// `Err` = fail-closed refusal (empty set, or ANY unknown/non-Falcon signer
/// entry, or no committed key at that height).
///
/// Fail-closed direction: an unknown entry aborts the whole count with `Err`
/// instead of being skipped, so a bundle smuggling an unregistered key can
/// never reach quorum no matter how many valid signatures accompany it.
pub fn distinct_falcon_signers_at_height(
    msg: &[u8],
    sigs: &[([u8; 32], Vec<u8>)],
    validators: &[[u8; 32]],
    attestation_height: u64,
    pq_keys: &dyn PqKeyLookup,
) -> Result<usize, String> {
    if validators.is_empty() {
        return Err("bridge quorum: empty validator set refuses fail-closed".to_string());
    }
    let allowed: std::collections::BTreeSet<[u8; 32]> = validators.iter().copied().collect();
    let mut seen: std::collections::BTreeSet<[u8; 32]> = std::collections::BTreeSet::new();
    for (id, sig) in sigs {
        if seen.contains(id) {
            continue;
        }
        if !allowed.contains(id) {
            return Err(
                "bridge quorum: unknown signer (not in validator set) refused fail-closed"
                    .to_string(),
            );
        }
        let (scheme, pk) = pq_keys.pq_key_at(id, attestation_height).ok_or_else(|| {
            "bridge quorum: no committed PQ key at attestation height refused fail-closed"
                .to_string()
        })?;
        if scheme != crate::post_quantum::PqScheme::Falcon512 {
            return Err(
                "bridge quorum: non-Falcon registered scheme refused fail-closed (Ed id is identity only)"
                    .to_string(),
            );
        }
        if !crate::consensus::verify_falcon_signature(&pk, msg, sig) {
            continue;
        }
        seen.insert(*id);
    }
    Ok(seen.len())
}

/// PRE-V2 WRAPPER around [`distinct_falcon_signers_at_height`] (legacy
/// signature, `attestation_height = 0`, [`PreV2ConsensusLookup`]).
pub fn distinct_falcon_signers(
    msg: &[u8],
    sigs: &[([u8; 32], Vec<u8>)],
    validators: &[[u8; 32]],
) -> Result<usize, String> {
    distinct_falcon_signers_at_height(msg, sigs, validators, 0, &PreV2ConsensusLookup)
}

pub struct TeleportBridgeEngine {
    pub validators: Vec<[u8; 32]>,
    pub processed_source_txs: HashMap<[u8; 32], bool>,
    pub pending_withdrawals: HashMap<u64, TeleportWithdrawalRequest>,
    pub next_withdrawal_id: u64,
    pub hourly_withdrawn: u64,
    pub last_rate_limit_reset: u64,
    pub hourly_deposited: u64,
    pub last_deposit_reset: u64,
    pub total_minted: u64,
    /// Route → expected zkML model registry for the Teleport zk-proof gate.
    ///
    /// FAIL-CLOSED HARDENING (audit W1): `ZkMlProof::verify_inference` is a
    /// structural-only check that a forged trace passes (regression
    /// `forged_proof_passes_structural_but_fails_sound_check` in
    /// `crate::zkml`), so deposits carrying a proof are verified with the
    /// SOUND check `verify_inference_against` — re-execution against the
    /// model REGISTERED here for the deposit's route. A route with no
    /// registered model rejects proof-carrying deposits (fail closed).
    ///
    /// Keyed by [`TeleportBridgeEngine::teleport_route_id`]. In-memory,
    /// operator-configured (NOT committed state): deposits WITHOUT a proof
    /// never consult it, so their behavior is bit-identical with or without
    /// entries.
    pub teleport_zk_models: HashMap<String, QuantizedLinearModel>,
}

impl TeleportBridgeEngine {
    pub fn new(validators: Vec<[u8; 32]>) -> Self {
        Self {
            validators,
            processed_source_txs: HashMap::new(),
            pending_withdrawals: HashMap::new(),
            next_withdrawal_id: 1,
            hourly_withdrawn: 0,
            last_rate_limit_reset: 0,
            hourly_deposited: 0,
            last_deposit_reset: 0,
            total_minted: 0,
            teleport_zk_models: HashMap::new(),
        }
    }

    /// Canonical route id for the Teleport zk-proof model registry:
    /// `<chain-discriminant>:<asset>`, e.g. `0:USDT`.
    ///
    /// The chain is the stable `u32` discriminant of [`SupportedChain`] (not
    /// the variant name), and `asset` is matched EXACTLY as carried on the
    /// deposit event (case-sensitive, no trimming): a registry entry for
    /// `0:USDT` does NOT cover `0:usdt`. Exactness is the fail-closed
    /// direction — a near-miss is an unknown route, not a fuzzy hit.
    pub fn teleport_route_id(source_chain: SupportedChain, asset: &str) -> String {
        format!("{}:{asset}", source_chain as u32)
    }

    /// Register the expected zkML model for a Teleport route.
    ///
    /// APPEND-ONLY per route in practice (re-registering overwrites, so
    /// operators must treat registration as a coordinated-upgrade parameter,
    /// never a mid-dispute swap): the model a proof is checked against must
    /// be fixed before the deposit arrives. Malformed models are refused so
    /// the sound check can never be armed with weights that fail
    /// re-execution open.
    pub fn register_teleport_zk_model(
        &mut self,
        source_chain: SupportedChain,
        asset: &str,
        model: QuantizedLinearModel,
    ) -> Result<String, String> {
        if !model.validate() {
            return Err("teleport zk-model registration refused: malformed model".to_string());
        }
        let route = Self::teleport_route_id(source_chain, asset);
        self.teleport_zk_models.insert(route.clone(), model);
        Ok(route)
    }

    /// Look up the registered model for a deposit's route (`None` = unknown
    /// route; the proof gate fails closed on `None`).
    pub fn teleport_zk_model_for(
        &self,
        event: &TeleportDepositEvent,
    ) -> Option<&QuantizedLinearModel> {
        self.teleport_zk_models
            .get(&Self::teleport_route_id(event.source_chain, &event.asset))
    }

    /// Deposit-side rate + supply ceiling (audit F-H). Called by `plan()` for
    /// EVERY admitted deposit on BOTH paths (quorum and adapter evidence):
    /// withdrawals were capped but deposits were not, so a compromised quorum
    /// could mint past the hard cap in one deposit. Window and clock are the
    /// block's (`now`), saturating throughout; a refusal leaves the engine
    /// untouched (the caller treats it as a whole-tx revert, same as quorum).
    ///
    /// This is the LOCAL (per-bridge) first line. The GLOBAL 1B cap is enforced
    /// on top of it by `InMemoryStateEngine::settle_bridge_native`, which
    /// reserves the gross credited amount with the engine's capped mint before
    /// it writes a balance (audit F1) - local caps can each be respected while
    /// their SUM blows past the hard cap, which is exactly the hole that fix
    /// closes.
    pub fn note_deposit_mint(&mut self, amount: u64, now: u64) -> Result<(), String> {
        if now.saturating_sub(self.last_deposit_reset) >= 3600 {
            self.hourly_deposited = 0;
            self.last_deposit_reset = now;
        }
        if self.hourly_deposited.saturating_add(amount) > HOURLY_DEPOSIT_LIMIT_NANO {
            return Err("bridge deposit hourly mint limit exceeded".to_string());
        }
        if self.total_minted.saturating_add(amount) > BRIDGE_MINT_CAP_NANO {
            return Err("bridge cumulative mint cap exceeded".to_string());
        }
        self.hourly_deposited = self.hourly_deposited.saturating_add(amount);
        self.total_minted = self.total_minted.saturating_add(amount);
        Ok(())
    }

    /// Unwind a revoked deposit's mint (dispute Resolve path). Saturating:
    /// hourly windows roll independently of disputes, so a revoke landing in
    /// a later window must not drive counters negative — it just frees what
    /// is currently counted.
    ///
    /// THE AMOUNT IS THE BURNED ONE, NOT THE DEPOSIT (audit W7.1): a revoking
    /// resolve destroys `deposit - finder_reward` and pays the reward to the
    /// finder, so the reward is still OUTSTANDING minted supply. Unwinding
    /// the full deposit amount would quietly hand the cumulative mint cap
    /// (`BRIDGE_MINT_CAP_NANO`) `finder_reward` of free headroom per revoke -
    /// the cap would stop bounding the supply the bridge actually created.
    /// The caller passes the burned amount for exactly that reason.
    pub fn note_revoke(&mut self, amount: u64) {
        self.hourly_deposited = self.hourly_deposited.saturating_sub(amount);
        self.total_minted = self.total_minted.saturating_sub(amount);
    }

    /// Canonical message that validators sign for a deposit.
    pub fn deposit_signing_message(event: &TeleportDepositEvent) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&event.source_tx_hash);
        msg.extend_from_slice(&event.recipient);
        msg.extend_from_slice(event.asset.as_bytes());
        msg.extend_from_slice(&event.amount.to_be_bytes());
        // C8: domain-separate by source chain. Without this, relayer sets
        // that overlap across chains could have one chain's signatures
        // replayed as quorum on another for an identical tuple (global
        // replay set downgraded that to an availability quirk, but the
        // signing message is the right place to bind it).
        msg.extend_from_slice(&(event.source_chain as u32).to_be_bytes());
        msg
    }

    /// Canonical message the relayer quorum signs to RETRACT a deposit:
    /// "this source-chain deposit did NOT happen (it failed / was reverted)".
    ///
    /// THE ONLY FRAUD PROOF THE LAYER HAS (audit W7.1). A challenge is a
    /// FREEZE + "demand evidence" tool: nothing in a transaction can prove
    /// the ABSENCE of a source-chain event, so the old rule "failing evidence
    /// past the deadline = fraud" was unsound (SEC-01: an attacker could
    /// submit dummy failing signatures and collect the 10% finder bounty on
    /// an honest deposit). A RETRACTION is the sound alternative: the
    /// committed quorum - the only body that witnesses the source chain -
    /// signs an explicit, domain-separated statement that THIS deposit
    /// failed. It is verifiable, so it cannot be forged by a challenger; and
    /// it is a statement about THIS claim, so it cannot be transplanted onto
    /// another deposit.
    ///
    /// DOMAIN SEPARATION: the retraction preimage is a different byte string
    /// from [`Self::deposit_signing_message`] (a distinct tag, the same four
    /// claim fields), so a signature over one can never be replayed as the
    /// other - the ordinary attestation says "this deposit happened", the
    /// retraction says "it did not", and only the quorum can produce either.
    ///
    /// CHAIN BINDING: the chain discriminant is bound here exactly as in the
    /// deposit preimage - a TON retraction is not an Arbitrum one.
    pub fn deposit_failure_signing_message(
        chain: SupportedChain,
        source_tx_hash: [u8; 32],
        recipient: [u8; 32],
        amount: u64,
    ) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(b"STELL_BRIDGE_DEPOSIT_FAILURE_V1");
        msg.extend_from_slice(&source_tx_hash);
        msg.extend_from_slice(&recipient);
        msg.extend_from_slice(&amount.to_be_bytes());
        msg.extend_from_slice(&(chain as u32).to_be_bytes());
        msg
    }

    /// Process incoming Teleport deposit from external network.
    ///
    /// SECURITY: the quorum counts DISTINCT validators — a single validator
    /// submitting the same (or different) signatures N times cannot fake a 2/3
    /// quorum. Replays by source tx hash are rejected.
    ///
    /// The signature count runs through [`verify_quorum_signatures`] - the
    /// same helper the adapter's quorum-attested evidence uses.
    pub fn process_deposit(&mut self, event: &TeleportDepositEvent) -> Result<u64, String> {
        if self
            .processed_source_txs
            .contains_key(&event.source_tx_hash)
        {
            return Err("Duplicate teleport deposit tx".to_string());
        }

        let msg = Self::deposit_signing_message(event);
        verify_quorum_signatures(&msg, &event.validator_signatures, &self.validators)
            .map_err(|e| format!("Teleport deposit quorum not reached: {e}"))?;

        // Check optional zk-proof verification.
        //
        // FAIL-CLOSED HARDENING (audit W1): the structural-only
        // `verify_inference()` is fooled by forged traces (it PASSES the
        // forgery in `zkml::tests::forged_proof_passes_structural_but_fails_sound_check`),
        // so it must NEVER gate a money path. Deposits carrying a proof are
        // verified with the SOUND check `verify_inference_against` against the
        // model REGISTERED for this deposit's route; a route with no
        // registered model fails CLOSED. Deposits WITHOUT a proof skip this
        // block entirely (behavior bit-identical to before).
        if let Some(proof) = &event.zk_proof {
            let route = Self::teleport_route_id(event.source_chain, &event.asset);
            match self.teleport_zk_models.get(&route) {
                None => {
                    let msg = format!(
                        "BRIDGE ZK GATE REJECT amount={} route={route} reason=unknown-route-no-registered-model (fail closed)",
                        event.amount,
                    );
                    eprintln!("{msg}");
                    tracing::error!("{msg}");
                    return Err(format!(
                        "Teleport zk-proof rejected: no registered model for route {route} (fail closed)"
                    ));
                }
                Some(model) => {
                    if !proof.verify_inference_against(model) {
                        let msg = format!(
                            "BRIDGE ZK GATE REJECT amount={} route={route} reason=proof-model-mismatch (fail closed)",
                            event.amount,
                        );
                        eprintln!("{msg}");
                        tracing::error!("{msg}");
                        return Err("Teleport zk-proof verification failed".to_string());
                    }
                }
            }
        }

        self.processed_source_txs.insert(event.source_tx_hash, true);
        Ok(event.amount)
    }

    /// Request withdrawal with rate-limits and time-locks.
    pub fn request_withdrawal(
        &mut self,
        sender: [u8; 32],
        target_chain: SupportedChain,
        target_address: String,
        amount: u64,
        now: u64,
    ) -> Result<u64, String> {
        // Reset hourly limit window if elapsed
        if now.saturating_sub(self.last_rate_limit_reset) >= 3600 {
            self.hourly_withdrawn = 0;
            self.last_rate_limit_reset = now;
        }

        // SECURITY: saturating add — a plain `+` can wrap and bypass the limit.
        if self.hourly_withdrawn.saturating_add(amount) > HOURLY_RATE_LIMIT_NANO {
            return Err("Bridge hourly rate limit exceeded".to_string());
        }

        let unlock_at = if amount >= LARGE_WITHDRAWAL_THRESHOLD_NANO {
            now.saturating_add(WITHDRAWAL_TIME_LOCK_SECS)
        } else {
            now
        };

        let req_id = self.next_withdrawal_id;
        self.next_withdrawal_id += 1;

        self.hourly_withdrawn = self.hourly_withdrawn.saturating_add(amount);
        self.pending_withdrawals.insert(
            req_id,
            TeleportWithdrawalRequest {
                req_id,
                sender,
                target_chain,
                target_address,
                amount,
                requested_at: now,
                unlock_at,
                executed: false,
            },
        );

        Ok(req_id)
    }

    /// Finalize withdrawal once time-lock expires
    pub fn finalize_withdrawal(&mut self, req_id: u64, now: u64) -> Result<u64, String> {
        let req = self
            .pending_withdrawals
            .get_mut(&req_id)
            .ok_or_else(|| "Withdrawal request not found".to_string())?;

        if req.executed {
            return Err("Withdrawal already executed".to_string());
        }

        if now < req.unlock_at {
            return Err(format!(
                "Withdrawal is time-locked until {} (current: {})",
                req.unlock_at, now
            ));
        }

        req.executed = true;
        Ok(req.amount)
    }

    /// Refund a parked withdrawal to its sender (audit follow-up F-G).
    /// Sender-only + unexecuted-only + past `unlock_at + REFUND_GRACE_SECS`.
    /// The request is DELETED (replay-safe by absence). Returns the amount.
    pub fn refund_withdrawal(
        &mut self,
        req_id: u64,
        payer: [u8; 32],
        now: u64,
    ) -> Result<u64, String> {
        let req = self
            .pending_withdrawals
            .get(&req_id)
            .ok_or_else(|| "Withdrawal request not found".to_string())?;
        if req.executed {
            return Err("Withdrawal already executed: refund refused".to_string());
        }
        if req.sender != payer {
            return Err("Only the original sender may refund".to_string());
        }
        let refund_at = req.unlock_at.saturating_add(REFUND_GRACE_SECS);
        if now < refund_at {
            return Err(format!(
                "Refund locked until {} (current: {})",
                refund_at, now
            ));
        }
        let amount = req.amount;
        // Un-park the hourly accounting too: refunded value never left. But
        // only the amount THIS window actually counted: `hourly_withdrawn` is
        // the usage of the window that started at `last_rate_limit_reset`, so
        // a request parked before that boundary is not part of it. Subtracting
        // it anyway (the old rule) drove the live usage to zero and handed the
        // sender a full extra window of headroom per pre-parked request.
        let counted_in_window = req.requested_at >= self.last_rate_limit_reset;
        self.pending_withdrawals.remove(&req_id);
        if counted_in_window {
            self.hourly_withdrawn = self.hourly_withdrawn.saturating_sub(amount);
        }
        Ok(amount)
    }
}

// ============================================================================
// Committed bridge domain: the §8 policy state every node folds into the root
// ============================================================================

/// What one block's bridge intents ask the engine to move natively.
///
/// The account half of a plan. The value half (replay set, withdrawal queue,
/// rate window) is carried by [`BridgePlan::state`] itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BridgeEffect {
    /// Deposit: mint `amount` nano-STELL to `recipient`.
    Credit { recipient: [u8; 32], amount: u64 },
    /// Withdrawal: debit the transaction's payer and park `amount` in
    /// [`BRIDGE_ESCROW`]. The coins move exactly once, atomically with the
    /// block, whether or not the withdrawal is later released.
    Park { amount: u64 },
    /// Refund: release `amount` from [`BRIDGE_ESCROW`] back to `recipient`
    /// (the original depositor) and delete the parked request.
    Unpark { recipient: [u8; 32], amount: u64 },
    /// Challenge: claw `amount` back from `account` into [`BRIDGE_ESCROW`].
    /// Escrow sufficiency is enforced in settlement Pass 1 like every other
    /// debit (a recipient who already moved the funds fails the whole tx —
    /// fail closed, never partial).
    Clawback { account: [u8; 32], amount: u64 },
    /// Revoke: burn `amount` out of [`BRIDGE_ESCROW`] (supply destroyed, not
    /// moved). Escrow sufficiency enforced the same way; burning what the
    /// escrow does not hold fails the whole tx.
    Burn { amount: u64 },
}

/// A computed bridge settlement: the committed state AFTER this block's
/// intents, plus the native movements it implies.
#[derive(Clone, Debug)]
pub struct BridgePlan {
    pub state: BridgeState,
    pub effects: Vec<BridgeEffect>,
}

/// The committed bridge domain - the non-trie half of the bridge that must be
/// identical on every node or two peers would apply the same block to the same
/// state root and then disagree about it.
///
/// Folded into `commitment_digest` CONDITIONALLY (see `commitment.rs`): an
/// empty domain writes zero bytes, so a chain that has never bridged - every
/// genesis KAT - hashes byte-for-byte identically to before, while the moment
/// the first deposit or withdrawal lands the whole domain appears in full.
///
/// Sorted containers only (`BTreeSet`/`BTreeMap`): `HashMap` iteration order
/// differs between processes (PROTOCOL.md I2), so hashing one would give two
/// nodes with identical state different roots.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeState {
    /// Source-chain tx hashes already credited. The replay set: one credit per
    /// hash, network-wide, forever.
    pub processed_source_txs: std::collections::BTreeSet<[u8; 32]>,
    /// Withdrawals parked in escrow and not yet finalized, keyed by request id
    /// (the same id the external `MultisigRelayer` releases against).
    pub pending_withdrawals: std::collections::BTreeMap<u64, TeleportWithdrawalRequest>,
    /// Next request id handed out. 0 means "never withdrawn", so the first id
    /// is 0; carrying the counter (rather than deriving it) keeps ids stable
    /// across replays and reorgs.
    pub next_withdrawal_id: u64,
    /// Nano-STELL withdrawn inside the current rate-limit window.
    pub hourly_withdrawn: u64,
    /// Block timestamp the current rate-limit window started at. The clock is
    /// ALWAYS the block's, never a node's wall clock.
    pub last_rate_limit_reset: u64,
    /// Mirror of the [`BRIDGE_ESCROW`] account balance, refreshed from that
    /// account on every settlement/restore. Redundant with the trie on purpose:
    /// the digest is what a light client reads, and the account is what the
    /// transfer paths write - committing both means neither can silently move.
    pub escrow_balance: u64,
    /// Nano-STELL minted by deposits inside the current deposit window.
    pub hourly_deposited: u64,
    /// Block timestamp the current deposit window started at (block clock).
    pub last_deposit_reset: u64,
    /// Cumulative nano-STELL ever minted by deposits. Bounded by
    /// [`BRIDGE_MINT_CAP_NANO`]; monotone except on snapshot restore to an
    /// older committed state (same as every other committed counter).
    pub total_minted: u64,
    /// Every settled deposit's acceptance record, keyed by source-chain tx
    /// hash (superset of `processed_source_txs`: one entry per credit, kept
    /// so a challenge can name the recipient, amount and admission path).
    pub deposit_records: std::collections::BTreeMap<[u8; 32], DepositRecord>,
    /// Open and resolved disputes, keyed by dispute id. Resolved disputes
    /// are KEPT (audit trail for watchers/explorer); replay is guarded by
    /// the record's `disputed` flag, not by absence.
    pub disputes: std::collections::BTreeMap<u64, Dispute>,
    /// Next dispute id handed out.
    pub next_dispute_id: u64,
    /// Verified external payout receipts, keyed by withdrawal request id.
    ///
    /// Written ONLY by [`BridgeState::plan_at_height`] after a paired
    /// [`BridgeIntent::ReleaseProof`] verified (quorum + binding + freshness).
    /// An `executed = true` flag from before BRIDGE-FIX-FULL is NEVER
    /// retroactively elevated into a receipt here (snapshot upgrade starts the
    /// map empty): absence of a receipt means "no proven payout", which is the
    /// fail-closed direction.
    #[serde(default)]
    pub release_receipts: std::collections::BTreeMap<u64, ReleaseReceiptRecord>,
    /// Foreign payout transaction hashes already settled. The replay guard
    /// across ALL withdrawals: one foreign tx can settle at most one release.
    #[serde(default)]
    pub processed_payout_txs: std::collections::BTreeSet<[u8; 32]>,
    /// Refund tombstones: request ids refunded after BRIDGE-FIX-FULL activated.
    ///
    /// The tombstone survives the deletion of the parked request so a late
    /// `Release`/`ReleaseProof` after a refund fails LOUDLY
    /// (`"Withdrawal already refunded"`) instead of silently mutating absent
    /// state. Pre-activation refunds are absent (legacy replay: deletion alone
    /// was the guard).
    #[serde(default)]
    pub refunded_withdrawals: std::collections::BTreeSet<u64>,
}

/// One verified external payout, as committed by the `Release + ReleaseProof`
/// path. Kept after settlement as the audit trail: the foreign tx hash, the
/// attested finalized head and the committed height whose keys signed it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseReceiptRecord {
    pub target_chain: SupportedChain,
    pub target_address: String,
    pub amount: u64,
    /// Non-zero foreign payout transaction hash (unique, see
    /// [`BridgeState::processed_payout_txs`]).
    pub external_tx_hash: [u8; 32],
    /// Foreign finalized block/seqno/slot the payout was observed under.
    pub finalized_head: u64,
    /// Committed Stellereum height whose active PQ keys signed the receipt.
    pub attestation_height: u64,
    /// Block timestamp the receipt settled at (block clock, never wall clock).
    pub settled_at: u64,
}

/// One settled deposit, as admitted. The challenge window reasons from this.
///
/// `via_quorum` is telemetry only at
/// `height >= BRIDGE_V2_ACTIVATION_HEIGHT`: EVERY admitted deposit is
/// challengeable within [`CHALLENGE_MAX_AGE_SECS`] and while undisputed (the
/// `TonCell`/`EvmReceipt`/`SolanaTx` adapters are quorum-anchored today, so
/// their evidence is testimony too — `docs/specs/06 §2.4`). Pre-activation
/// replay keeps the legacy rule (only `via_quorum` deposits challengeable).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositRecord {
    /// Who was credited.
    pub recipient: [u8; 32],
    /// How much was credited (== clawback size on challenge).
    pub amount: u64,
    /// Which foreign chain the deposit claims to come from (needed to
    /// rebuild the evidence claim on Resolve-confirm).
    pub chain: SupportedChain,
    /// True when admitted via quorum attestations, false when admitted via
    /// adapter evidence. Challengeability gate PRE-activation only; post-
    /// activation this is telemetry (see the struct docs).
    pub via_quorum: bool,
    /// Block timestamp of admission (challenge age counts from here).
    pub deposited_at: u64,
    /// Set on the first challenge; a hash is disputed at most once, ever.
    pub disputed: bool,
}

/// One optimistic dispute over a quorum-path deposit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dispute {
    /// The challenged deposit.
    pub source_tx_hash: [u8; 32],
    /// Who posted the bond (== the Challenge tx's payer).
    pub challenger: [u8; 32],
    /// Who was credited (== clawback source, == confirm-payee).
    pub recipient: [u8; 32],
    /// Clawed-back amount sitting in escrow while open.
    pub amount: u64,
    /// Locked bond sitting in escrow while open.
    pub bond: u64,
    /// Block-timestamp deadline: past it a Resolve that carries NO evidence
    /// DEFERS (deadline pushed out, bounded - never pays on missing
    /// evidence) and, past the bound, REFUSES loudly with no payout.
    /// Confirm-by-valid-evidence and revoke-by-verified-fraud-proof have NO
    /// deadline: both are conclusive proofs, so neither has to wait for the
    /// window.
    pub deadline: u64,
    /// Set on Resolve (confirm or revoke). Terminal.
    pub resolved: bool,
    /// True when resolved by evidence-confirm, false when by a verified
    /// fraud proof (the quorum's retraction). Meaningless while !resolved.
    pub confirmed: bool,
}

/// `BridgeState` as written before the dispute layer (no `deposit_records`,
/// `disputes`, `next_dispute_id`). Kept ONLY for reading old snapshots
/// (same prefix rule as V1: NEVER written; `upgrade` starts the new maps
/// empty). Semantic gap: deposits settled before the upgrade have NO record
/// and can never be challenged (their hashes are in `processed_source_txs`,
/// so no double-mint — they are simply outside the challenge window, exactly
/// like deposits older than [`CHALLENGE_MAX_AGE_SECS`]).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BridgeStateV2 {
    pub processed_source_txs: std::collections::BTreeSet<[u8; 32]>,
    pub pending_withdrawals: std::collections::BTreeMap<u64, TeleportWithdrawalRequest>,
    pub next_withdrawal_id: u64,
    pub hourly_withdrawn: u64,
    pub last_rate_limit_reset: u64,
    pub escrow_balance: u64,
    pub hourly_deposited: u64,
    pub last_deposit_reset: u64,
    pub total_minted: u64,
}

impl BridgeStateV2 {
    pub fn upgrade(self) -> BridgeState {
        BridgeState {
            processed_source_txs: self.processed_source_txs,
            pending_withdrawals: self.pending_withdrawals,
            next_withdrawal_id: self.next_withdrawal_id,
            hourly_withdrawn: self.hourly_withdrawn,
            last_rate_limit_reset: self.last_rate_limit_reset,
            escrow_balance: self.escrow_balance,
            hourly_deposited: self.hourly_deposited,
            last_deposit_reset: self.last_deposit_reset,
            total_minted: self.total_minted,
            deposit_records: std::collections::BTreeMap::new(),
            disputes: std::collections::BTreeMap::new(),
            next_dispute_id: 0,
            release_receipts: std::collections::BTreeMap::new(),
            processed_payout_txs: std::collections::BTreeSet::new(),
            refunded_withdrawals: std::collections::BTreeSet::new(),
        }
    }
}

/// `BridgeState` as written before BRIDGE-FIX-FULL (`release_receipts`,
/// `processed_payout_txs`, `refunded_withdrawals`).
///
/// This is the EXACT layout the previous `BridgeState` had (dispute layer
/// included); [`Self::upgrade`] appends the three new containers EMPTY. The
/// semantic gap is deliberate and fail-closed: `executed = true` withdrawals
/// that predate the upgrade carry NO verified [`ReleaseReceiptRecord`], and no
/// historical flag is retroactively promoted into one. Kept ONLY for reading
/// old snapshots; NEVER written.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BridgeStateV3 {
    pub processed_source_txs: std::collections::BTreeSet<[u8; 32]>,
    pub pending_withdrawals: std::collections::BTreeMap<u64, TeleportWithdrawalRequest>,
    pub next_withdrawal_id: u64,
    pub hourly_withdrawn: u64,
    pub last_rate_limit_reset: u64,
    pub escrow_balance: u64,
    pub hourly_deposited: u64,
    pub last_deposit_reset: u64,
    pub total_minted: u64,
    pub deposit_records: std::collections::BTreeMap<[u8; 32], DepositRecord>,
    pub disputes: std::collections::BTreeMap<u64, Dispute>,
    pub next_dispute_id: u64,
}

impl BridgeStateV3 {
    pub fn upgrade(self) -> BridgeState {
        BridgeState {
            processed_source_txs: self.processed_source_txs,
            pending_withdrawals: self.pending_withdrawals,
            next_withdrawal_id: self.next_withdrawal_id,
            hourly_withdrawn: self.hourly_withdrawn,
            last_rate_limit_reset: self.last_rate_limit_reset,
            escrow_balance: self.escrow_balance,
            hourly_deposited: self.hourly_deposited,
            last_deposit_reset: self.last_deposit_reset,
            total_minted: self.total_minted,
            deposit_records: self.deposit_records,
            disputes: self.disputes,
            next_dispute_id: self.next_dispute_id,
            release_receipts: std::collections::BTreeMap::new(),
            processed_payout_txs: std::collections::BTreeSet::new(),
            refunded_withdrawals: std::collections::BTreeSet::new(),
        }
    }
}

/// `BridgeState` as written before the F-H mint ceilings (no
/// `hourly_deposited`, `last_deposit_reset`, `total_minted`). Kept ONLY for
/// reading old snapshots: the new fields were appended at the END, so old
/// bytes are an exact prefix, but bincode structs decode exact-size and a
/// bare decode fails with `UnexpectedEof` (observed live: nodes with
/// pre-F-H data dirs refused to start). NEVER written; `upgrade` fills the
/// new counters with zero. Note the semantic gap this implies: mints that
/// landed before the upgrade are NOT counted in `total_minted` (the old
/// format recorded no amounts-per-window). On a chain that actually minted
/// through the bridge pre-upgrade, verify real minted supply out-of-band
/// before trusting the cap headroom; on a fresh/test chain it is exact.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BridgeStateV1 {
    pub processed_source_txs: std::collections::BTreeSet<[u8; 32]>,
    pub pending_withdrawals: std::collections::BTreeMap<u64, TeleportWithdrawalRequest>,
    pub next_withdrawal_id: u64,
    pub hourly_withdrawn: u64,
    pub last_rate_limit_reset: u64,
    pub escrow_balance: u64,
}

impl BridgeStateV1 {
    pub fn upgrade(self) -> BridgeState {
        BridgeState {
            processed_source_txs: self.processed_source_txs,
            pending_withdrawals: self.pending_withdrawals,
            next_withdrawal_id: self.next_withdrawal_id,
            hourly_withdrawn: self.hourly_withdrawn,
            last_rate_limit_reset: self.last_rate_limit_reset,
            escrow_balance: self.escrow_balance,
            hourly_deposited: 0,
            last_deposit_reset: 0,
            total_minted: 0,
            deposit_records: std::collections::BTreeMap::new(),
            disputes: std::collections::BTreeMap::new(),
            next_dispute_id: 0,
            release_receipts: std::collections::BTreeMap::new(),
            processed_payout_txs: std::collections::BTreeSet::new(),
            refunded_withdrawals: std::collections::BTreeSet::new(),
        }
    }
}

impl BridgeState {
    /// True when the domain has never been touched. Only then does it
    /// contribute NOTHING to the commitment digest, which is what keeps the
    /// genesis known-answer (and `COMMITMENT_VERSION`) unchanged.
    pub fn is_empty(&self) -> bool {
        self.processed_source_txs.is_empty()
            && self.pending_withdrawals.is_empty()
            && self.next_withdrawal_id == 0
            && self.hourly_withdrawn == 0
            && self.last_rate_limit_reset == 0
            && self.escrow_balance == 0
            && self.hourly_deposited == 0
            && self.last_deposit_reset == 0
            && self.total_minted == 0
            && self.deposit_records.is_empty()
            && self.disputes.is_empty()
            && self.next_dispute_id == 0
            && self.release_receipts.is_empty()
            && self.processed_payout_txs.is_empty()
            && self.refunded_withdrawals.is_empty()
    }

    /// Rebuild the policy engine's view of the committed state.
    fn engine(&self, validators: Vec<[u8; 32]>) -> TeleportBridgeEngine {
        TeleportBridgeEngine {
            validators,
            processed_source_txs: self
                .processed_source_txs
                .iter()
                .map(|h| (*h, true))
                .collect(),
            pending_withdrawals: self
                .pending_withdrawals
                .iter()
                .map(|(id, req)| (*id, req.clone()))
                .collect(),
            next_withdrawal_id: self.next_withdrawal_id,
            hourly_withdrawn: self.hourly_withdrawn,
            last_rate_limit_reset: self.last_rate_limit_reset,
            hourly_deposited: self.hourly_deposited,
            last_deposit_reset: self.last_deposit_reset,
            total_minted: self.total_minted,
            // The zk-model registry is in-memory operator configuration, not
            // committed state: the live path rebuilds the engine per plan, so
            // it starts empty here. (Live `BridgeIntent::Deposit` carries no
            // zk proof — `deposit_event` sets `zk_proof: None` — so the gate
            // below is vacuous on this path either way.)
            teleport_zk_models: HashMap::new(),
        }
    }

    /// Write the engine's post-plan fields back. `escrow_balance` is NOT an
    /// engine field: the caller refreshes it from the account map.
    fn absorb(&mut self, engine: &TeleportBridgeEngine) {
        self.processed_source_txs = engine.processed_source_txs.keys().copied().collect();
        self.pending_withdrawals = engine
            .pending_withdrawals
            .iter()
            .map(|(id, req)| (*id, req.clone()))
            .collect();
        self.next_withdrawal_id = engine.next_withdrawal_id;
        self.hourly_withdrawn = engine.hourly_withdrawn;
        self.last_rate_limit_reset = engine.last_rate_limit_reset;
        self.hourly_deposited = engine.hourly_deposited;
        self.last_deposit_reset = engine.last_deposit_reset;
        self.total_minted = engine.total_minted;
    }

    /// Plan one transaction's bridge intents against the COMMITTED state.
    ///
    /// This is the §8 policy gate, and it is the SAME rule the offline engine
    /// applies: every intent is run through a [`TeleportBridgeEngine`] seeded
    /// from the committed fields, so quorum, replay, the hourly rate limit and
    /// the withdrawal time-lock cannot drift between the model and the live
    /// path.
    ///
    /// DEPOSIT ADMISSION is a deterministic OR: a deposit credits when EITHER
    /// the quorum attestation passes (the unchanged engine rule above) OR a
    /// paired [`BridgeIntent::DepositProof`] bundle verifies through
    /// [`bridge_adapters::verify_evidence`] against the exact claim (chain,
    /// source tx hash, recipient, amount). The OR is one-directional: replay
    /// fails closed on BOTH paths (a credited hash never mints twice), and a
    /// quorum success ignores evidence entirely, so pre-evidence payloads
    /// plan byte-for-byte identically to before.
    ///
    /// PURE: it returns the state the block WOULD commit and the coin movements
    /// it implies, and writes nothing. Settlement applies the effects to the
    /// accounts first (all-or-nothing, with the existing floor check) and only
    /// then stores `state`, so a refusal anywhere leaves the node untouched.
    ///
    /// `now` is `block.timestamp` (PROTOCOL.md I12), never a wall clock.
    ///
    /// PRE-V2 COMPATIBILITY WRAPPER: delegates to [`Self::plan_at_height`] at
    /// `block_height = 0`, `chain_id = crate::zkml::effective_chain_id()` and
    /// [`PreV2ConsensusLookup`], i.e. the legacy pre-activation rule set.
    pub fn plan(
        &self,
        intents: &[BridgeIntent],
        validators: &[[u8; 32]],
        payer: [u8; 32],
        now: u64,
    ) -> Result<BridgePlan, String> {
        self.plan_at_height(
            intents,
            validators,
            payer,
            now,
            0,
            crate::zkml::effective_chain_id(),
            &PreV2ConsensusLookup,
        )
    }

    /// Plan one transaction's bridge intents against the COMMITTED state AT a
    /// block height, with a committed height-indexed PQ key lookup.
    ///
    /// `block_height` decides whether the BRIDGE-FIX-FULL rules apply
    /// ([`bridge_v2_active_at`]). `chain_id` is the Stellereum network id bound
    /// into V2 payout-receipt preimages (no cross-network signature replay).
    /// `pq_keys` is the ONLY key source for V2 quorum verification: pass the
    /// committed `(&staking_ledger, &pq_registry)` tuple (implements
    /// [`PqKeyLookup`]); no global process-local map is consulted.
    ///
    /// At `block_height >= BRIDGE_V2_ACTIVATION_HEIGHT`:
    ///
    /// * a bare [`BridgeIntent::Release`] fails closed
    ///   (`"bridge release rejected: verified payout receipt required"`) unless
    ///   paired with a valid [`BridgeIntent::ReleaseProof`];
    /// * a [`BridgeIntent::Refund`] writes a `refunded_withdrawals` tombstone
    ///   (so a late proof fails loudly as `"Withdrawal already refunded"`);
    /// * EVERY admitted deposit is challengeable (evidence-path included):
    ///   the three live adapters are quorum-anchored, not trustless clients;
    /// * `Resolve` grades a verified quorum RETRACTION before any confirm
    ///   evidence (a replayed deposit proof can never defeat its retraction).
    ///
    /// Everything is planned purely: the returned state is what the block
    /// WOULD commit, and any error leaves the caller untouched.
    #[allow(clippy::too_many_arguments)]
    // GATE: the settlement signature is pinned by the state-engine wiring
    // (BF-2b); grouping height/chain/pq_keys into a struct would change the
    // frozen call shape other workers are landing against.
    pub fn plan_at_height(
        &self,
        intents: &[BridgeIntent],
        validators: &[[u8; 32]],
        payer: [u8; 32],
        now: u64,
        block_height: u64,
        chain_id: u64,
        pq_keys: &dyn PqKeyLookup,
    ) -> Result<BridgePlan, String> {
        let v2 = bridge_v2_active_at(block_height);
        // PRE-V2 COMPATIBILITY: below the activation height the historical
        // evidence paths keep resolving keys from the process-local consensus
        // map exactly as they always did (`PreV2ConsensusLookup`), so replaying
        // a pre-v7 block yields the same verdict it did when it was produced.
        // At/after `H` ONLY the committed `PqRegistry` is consulted.
        let legacy_lookup = PreV2ConsensusLookup;
        let evidence_lookup: &dyn PqKeyLookup = if v2 { pq_keys } else { &legacy_lookup };

        // FAIL CLOSED on an empty relayer set. `TeleportBridgeEngine`'s rule is
        // `(n * 2 + 2) / 3`, which is 0 for n = 0 - a chain whose staking
        // ledger is empty would then mint deposits with no signature at all.
        // The staking ledger is consensus state, so this verdict is identical
        // on every node applying the block.
        if validators.is_empty()
            && intents
                .iter()
                .any(|i| matches!(i, BridgeIntent::Deposit { .. }))
        {
            return Err(
                "bridge: no committed validator/relayer set - refusing deposits".to_string(),
            );
        }

        let mut engine = self.engine(validators.to_vec());

        // Working copies of the dispute-layer maps. Cloned from COMMITTED
        // state, mutated by the arms below (so two intents in one payload see
        // each other), written back to the planned state at the end. Deposit
        // records insert-if-absent (a record must never lose `disputed`).
        let mut records_map = self.deposit_records.clone();
        let mut disputes_map = self.disputes.clone();
        let mut next_dispute_id = self.next_dispute_id;
        // BRIDGE-FIX-FULL working copies (cloned from COMMITTED state, written
        // back atomically at the end; a refusal anywhere mutates nothing).
        let mut release_receipts = self.release_receipts.clone();
        let mut processed_payout_txs = self.processed_payout_txs.clone();
        let mut refunded_withdrawals = self.refunded_withdrawals.clone();

        // Attestations first: a deposit may only claim signatures carried by
        // THIS payload, paired by source tx hash (several bundles for the same
        // hash merge, so a payload cannot be split into quorum halves).
        #[allow(clippy::type_complexity)]
        // GATE: attestation index maps tx-hash to (signer, sig) lists; the nested shape mirrors the payload.
        let mut attest: HashMap<[u8; 32], Vec<([u8; 32], Vec<u8>)>> = HashMap::new();
        for intent in intents {
            if let BridgeIntent::Attest {
                source_tx_hash,
                signatures,
            } = intent
            {
                // Audit B-ATTEST-DOS: cap BEFORE merging, so a junk vector can
                // never burn quorum-verify time (VM `validate()` mirrors this).
                if signatures.len() > bridge_adapters::MAX_HEADER_SIGNATURES {
                    return Err(format!(
                        "bridge attestation rejected: too many signatures ({}, max {})",
                        signatures.len(),
                        bridge_adapters::MAX_HEADER_SIGNATURES,
                    ));
                }
                attest
                    .entry(*source_tx_hash)
                    .or_default()
                    .extend(signatures.iter().cloned());
            }
        }

        // BRIDGE-FIX-FULL: payout receipts, paired to their `Release` by
        // `req_id` exactly like `Attest`/`DepositProof` pair by tx hash. A
        // lone receipt is inert (consumed only by the `Release` arm), and
        // several receipts for one request merge so a payload cannot be split
        // into half-evidences.
        #[allow(clippy::type_complexity)]
        // GATE: receipt index maps req_id to full receipt evidence; the nested shape mirrors the payload.
        let mut release_proofs: HashMap<u64, Vec<ReleaseReceiptEvidence>> = HashMap::new();
        if v2 {
            for intent in intents {
                if let BridgeIntent::ReleaseProof { req_id, receipt } = intent {
                    release_proofs
                        .entry(*req_id)
                        .or_default()
                        .push((**receipt).clone());
                }
            }
        }

        // Adapter evidence second: a deposit may cite SPV/quorum evidence
        // INSTEAD OF the attestation bundle, paired the same way (several
        // bundles for one hash merge; the FIRST verifying bundle admits).
        // Like attestations, evidence is verified against bytes IN THIS
        // PAYLOAD - adapters never fetch, so every node reaches the same
        // verdict from the same block.
        let mut proof: HashMap<[u8; 32], Vec<bridge_adapters::DepositEvidence>> = HashMap::new();
        for intent in intents {
            if let BridgeIntent::DepositProof {
                source_tx_hash,
                evidence,
            } = intent
            {
                proof
                    .entry(*source_tx_hash)
                    .or_default()
                    .push((**evidence).clone());
            }
        }

        let mut effects = Vec::new();
        for intent in intents {
            match intent {
                BridgeIntent::Deposit {
                    source_tx_hash,
                    recipient,
                    ..
                } => {
                    let signatures = attest.get(source_tx_hash).cloned().unwrap_or_default();
                    let event = intent
                        .deposit_event(signatures)
                        .expect("deposit_event on a Deposit always yields an event");
                    match engine.process_deposit(&event) {
                        Ok(_) => {
                            // The live quorum path: unchanged behavior. When
                            // it passes, evidence (if any) is irrelevant.
                            // Deposit caps (F-H) apply here too: a compromised
                            // quorum must not mint past the hourly/supply
                            // ceilings. Refusal reverts the whole tx (the
                            // replay entry dies with it - plan is pure).
                            engine
                                .note_deposit_mint(event.amount, now)
                                .map_err(|e| format!("bridge deposit rejected: {e}"))?;
                            effects.push(BridgeEffect::Credit {
                                recipient: *recipient,
                                amount: event.amount,
                            });
                            records_map.entry(*source_tx_hash).or_insert(DepositRecord {
                                recipient: *recipient,
                                amount: event.amount,
                                chain: event.source_chain,
                                via_quorum: true,
                                deposited_at: now,
                                disputed: false,
                            });
                        }
                        Err(quorum_err) => {
                            // Replay ALWAYS fails closed, even with evidence:
                            // an already-credited source tx can never mint a
                            // second time through the other path.
                            if engine.processed_source_txs.contains_key(source_tx_hash) {
                                return Err(format!("bridge deposit rejected: {quorum_err}"));
                            }
                            // No evidence cited: the original verdict stands,
                            // byte-for-byte backward compatible.
                            let bundles = proof.get(source_tx_hash).cloned().unwrap_or_default();
                            if bundles.is_empty() {
                                return Err(format!("bridge deposit rejected: {quorum_err}"));
                            }
                            // The adapter path: verify the evidence against
                            // the EXACT claim the block would credit.
                            let claim = bridge_adapters::DepositClaim {
                                chain: event.source_chain,
                                source_tx_hash: *source_tx_hash,
                                recipient: *recipient,
                                amount: event.amount,
                            };
                            let mut last_err = String::new();
                            let mut admitted = false;
                            for bundle in &bundles {
                                match bridge_adapters::verify_evidence_at_height(
                                    &claim,
                                    bundle,
                                    validators,
                                    block_height,
                                    chain_id,
                                    evidence_lookup,
                                ) {
                                    Ok(verified) => {
                                        // Belt and suspenders: the adapter
                                        // echoes the claim; the echo must
                                        // match the deposit being settled.
                                        if verified.chain != event.source_chain
                                            || verified.source_tx_hash != *source_tx_hash
                                            || verified.recipient != *recipient
                                            || verified.amount != event.amount
                                        {
                                            last_err = "adapter verification does not match the claimed deposit"
                                                .to_string();
                                            continue;
                                        }
                                        admitted = true;
                                        break;
                                    }
                                    Err(e) => last_err = e,
                                }
                            }
                            if !admitted {
                                return Err(format!(
                                    "bridge deposit evidence rejected: {last_err}"
                                ));
                            }
                            engine
                                .note_deposit_mint(event.amount, now)
                                .map_err(|e| format!("bridge deposit rejected: {e}"))?;
                            engine.processed_source_txs.insert(*source_tx_hash, true);
                            effects.push(BridgeEffect::Credit {
                                recipient: *recipient,
                                amount: event.amount,
                            });
                            // Evidence-path: math, not testimony — recorded as
                            // unchallengeable (a Resolve-confirm may still cite
                            // this hash, but no Challenge may freeze it).
                            records_map.entry(*source_tx_hash).or_insert(DepositRecord {
                                recipient: *recipient,
                                amount: event.amount,
                                chain: event.source_chain,
                                via_quorum: false,
                                deposited_at: now,
                                disputed: false,
                            });
                        }
                    }
                }
                BridgeIntent::Withdraw {
                    chain,
                    target_address,
                    amount,
                } => {
                    // Rate window (block clock) then time-lock: a large
                    // withdrawal parks with unlock_at in the future.
                    engine
                        .request_withdrawal(payer, *chain, target_address.clone(), *amount, now)
                        .map_err(|e| format!("bridge withdrawal rejected: {e}"))?;
                    effects.push(BridgeEffect::Park { amount: *amount });
                }
                BridgeIntent::Release { req_id } => {
                    if !v2 {
                        // Pre-activation historical replay: unchanged legacy
                        // rule. Refuses before unlock_at (the time-lock) and
                        // on a second attempt (executed), against the
                        // COMMITTED queue.
                        engine
                            .finalize_withdrawal(*req_id, now)
                            .map_err(|e| format!("bridge release rejected: {e}"))?;
                    } else {
                        // BRIDGE-FIX-FULL: NO bare release. An unauthenticated
                        // `Release` at/after `unlock_at` used to permanently
                        // destroy the sender's refund path without proving any
                        // external payout (P0 regression
                        // `outsider_release_cannot_destroy_the_senders_refund_path`).
                        if refunded_withdrawals.contains(req_id) {
                            return Err("Withdrawal already refunded".to_string());
                        }
                        let req =
                            engine
                                .pending_withdrawals
                                .get(req_id)
                                .cloned()
                                .ok_or_else(|| {
                                    "bridge release rejected: Withdrawal request not found"
                                        .to_string()
                                })?;
                        if req.executed {
                            return Err(
                                "bridge release rejected: Withdrawal already executed".to_string()
                            );
                        }
                        if now < req.unlock_at {
                            return Err(format!(
                                "bridge release rejected: Withdrawal is time-locked until {} (current: {})",
                                req.unlock_at, now
                            ));
                        }
                        let receipts = release_proofs.get(req_id).ok_or_else(|| {
                            "bridge release rejected: verified payout receipt required".to_string()
                        })?;
                        // At least one paired receipt must verify FULLY
                        // (binding + freshness + replay + committed-key
                        // quorum). Errors from every candidate are collapsed
                        // into the last one; none commits partial state.
                        let mut last_err = "verified payout receipt required".to_string();
                        let mut settled: Option<&ReleaseReceiptEvidence> = None;
                        for receipt in receipts {
                            match verify_release_receipt_v2(
                                chain_id,
                                receipt,
                                &req,
                                block_height,
                                validators,
                                &processed_payout_txs,
                                pq_keys,
                            ) {
                                Ok(()) => {
                                    settled = Some(receipt);
                                    break;
                                }
                                Err(e) => last_err = e,
                            }
                        }
                        let receipt = settled
                            .ok_or_else(|| format!("bridge release rejected: {last_err}"))?;
                        // Commit atomically (the plan writes state only at the
                        // end, so a later refusal reverts all of this).
                        engine
                            .finalize_withdrawal(*req_id, now)
                            .map_err(|e| format!("bridge release rejected: {e}"))?;
                        processed_payout_txs.insert(receipt.external_tx_hash);
                        release_receipts.insert(
                            *req_id,
                            ReleaseReceiptRecord {
                                target_chain: receipt.target_chain,
                                target_address: receipt.target_address.clone(),
                                amount: receipt.amount,
                                external_tx_hash: receipt.external_tx_hash,
                                finalized_head: receipt.finalized_head,
                                attestation_height: receipt.attestation_height,
                                settled_at: now,
                            },
                        );
                    }
                }
                BridgeIntent::Refund { req_id } => {
                    if !v2 {
                        // Pre-activation historical replay: legacy
                        // sender-only/unexecuted/grace rule; the request is
                        // DELETED (replay-safe by absence).
                        let amount = engine
                            .refund_withdrawal(*req_id, payer, now)
                            .map_err(|e| format!("bridge refund rejected: {e}"))?;
                        effects.push(BridgeEffect::Unpark {
                            recipient: payer,
                            amount,
                        });
                    } else {
                        // BRIDGE-FIX-FULL: same preconditions plus a durable
                        // refund tombstone, so a late `ReleaseProof` after this
                        // refund fails LOUDLY instead of silently mutating
                        // absent state. A verified release (executed == true)
                        // wins over the refund — at most one outcome, ever.
                        if refunded_withdrawals.contains(req_id) {
                            return Err("Withdrawal already refunded".to_string());
                        }
                        let req =
                            engine
                                .pending_withdrawals
                                .get(req_id)
                                .cloned()
                                .ok_or_else(|| {
                                    "bridge refund rejected: Withdrawal request not found"
                                        .to_string()
                                })?;
                        if req.executed {
                            return Err(
                                "bridge refund rejected: Withdrawal already executed: refund refused"
                                    .to_string(),
                            );
                        }
                        if req.sender != payer {
                            return Err(
                                "bridge refund rejected: Only the original sender may refund"
                                    .to_string(),
                            );
                        }
                        let refund_at = req.unlock_at.saturating_add(REFUND_GRACE_SECS);
                        if now < refund_at {
                            return Err(format!(
                                "bridge refund rejected: Refund locked until {} (current: {})",
                                refund_at, now
                            ));
                        }
                        let amount = req.amount;
                        // Was this request counted by the CURRENT window?
                        // `hourly_withdrawn` is the usage of the window that
                        // began at `last_rate_limit_reset`, so an earlier-window
                        // request is not in it. The old unconditional
                        // `saturating_sub` zeroed live usage on every refund of
                        // a pre-parked request (a rate-limit bypass worth a full
                        // extra window per parked request).
                        let counted_in_window = req.requested_at >= engine.last_rate_limit_reset;
                        engine.pending_withdrawals.remove(req_id);
                        // Un-park the hourly accounting too: refunded value
                        // never left, so the window it occupied regains its
                        // headroom (only when that window is the current one).
                        if counted_in_window {
                            engine.hourly_withdrawn =
                                engine.hourly_withdrawn.saturating_sub(amount);
                        }
                        refunded_withdrawals.insert(*req_id);
                        effects.push(BridgeEffect::Unpark {
                            recipient: payer,
                            amount,
                        });
                    }
                }
                BridgeIntent::Challenge { source_tx_hash } => {
                    // Freeze a quorum-path deposit: claw its full amount back
                    // to escrow and lock the bond beside it. Reads the WORKING
                    // maps (this payload's own deposits are visible: a
                    // same-payload Deposit+Challenge challenges a deposit
                    // admitted two arms earlier — allowed, the checks below
                    // still gate it).
                    let record = records_map.get_mut(source_tx_hash).ok_or_else(|| {
                        "bridge challenge rejected: unknown deposit (no record; pre-dispute deposits cannot be challenged)".to_string()
                    })?;
                    if !v2 && !record.via_quorum {
                        // Pre-activation historical replay: evidence-path
                        // deposits were treated as "math, not testimony".
                        // Post-activation the three live adapters are
                        // quorum-anchored (no trustless light client yet), so
                        // EVERY admitted deposit is challengeable within
                        // CHALLENGE_MAX_AGE_SECS — otherwise a compromised 2/3
                        // quorum could bypass the optimistic layer simply by
                        // submitting `DepositProof` instead of `Attest`.
                        return Err(
                            "bridge challenge rejected: evidence-path deposit is math, not testimony".to_string(),
                        );
                    }
                    if record.disputed {
                        return Err(
                            "bridge challenge rejected: hash already disputed (once, ever)"
                                .to_string(),
                        );
                    }
                    if now.saturating_sub(record.deposited_at) > CHALLENGE_MAX_AGE_SECS {
                        return Err(
                            "bridge challenge rejected: deposit older than the challenge window"
                                .to_string(),
                        );
                    }
                    for d in disputes_map.values() {
                        if !d.resolved && d.source_tx_hash == *source_tx_hash {
                            return Err(
                                "bridge challenge rejected: dispute already open for this hash"
                                    .to_string(),
                            );
                        }
                    }
                    let dispute_id = next_dispute_id;
                    next_dispute_id = next_dispute_id.saturating_add(1);
                    let (recipient, amount) = (record.recipient, record.amount);
                    // C5: the bond scales with the disputed value (1%, min
                    // 1 STELL) so freezing a whale costs whale capital.
                    let bond = challenge_bond_for(amount);
                    record.disputed = true;
                    disputes_map.insert(
                        dispute_id,
                        Dispute {
                            source_tx_hash: *source_tx_hash,
                            challenger: payer,
                            recipient,
                            amount,
                            bond,
                            deadline: now.saturating_add(DISPUTE_WINDOW_SECS),
                            resolved: false,
                            confirmed: false,
                        },
                    );
                    // Bond first (payer == challenger: Park debits the tx
                    // payer into escrow), then the clawback. Pass-1 balance
                    // checks in settlement fail the whole tx if EITHER the
                    // challenger cannot cover the bond or the recipient
                    // already moved the funds — fail closed, never partial.
                    effects.push(BridgeEffect::Park { amount: bond });
                    effects.push(BridgeEffect::Clawback {
                        account: recipient,
                        amount,
                    });
                }
                BridgeIntent::Resolve { dispute_id } => {
                    // Settle an open dispute: four permissionless outcomes
                    // (any payer: the rules are deterministic from committed
                    // state + this payload, no stake needed to resolve).
                    //
                    // B2 TRUTH GATE (audit W7.1). The revoke payout is gated
                    // on a POSITIVE, VERIFIABLE truth check - never on the
                    // ABSENCE of evidence. Absence of evidence is not fraud:
                    // the old "empty resolve past the deadline revokes" rule
                    // let a false challenger suppress the recipient's confirm
                    // evidence for one window and collect bond + 10% with an
                    // empty payload, grief-burning the other 90% (SEC-01).
                    // An empty resolve past the deadline DEFERS (reschedules,
                    // bounded, no coin moves) and, past the bound, REFUSES
                    // LOUDLY with no payout - never pays on missing evidence.
                    let dispute = disputes_map
                        .get_mut(dispute_id)
                        .ok_or_else(|| "bridge resolve rejected: unknown dispute".to_string())?;
                    if dispute.resolved {
                        return Err(
                            "bridge resolve rejected: dispute already resolved (terminal)"
                                .to_string(),
                        );
                    }
                    let bundles = proof
                        .get(&dispute.source_tx_hash)
                        .cloned()
                        .unwrap_or_default();
                    let record = records_map
                        .get(&dispute.source_tx_hash)
                        .cloned()
                        .ok_or_else(|| {
                            "bridge resolve rejected: deposit record vanished (impossible)"
                                .to_string()
                        })?;
                    let claim = bridge_adapters::DepositClaim {
                        chain: record.chain,
                        source_tx_hash: dispute.source_tx_hash,
                        recipient: record.recipient,
                        amount: record.amount,
                    };
                    // TRUTH GRADING (audit W7.1). Evidence is sorted into
                    // three buckets, and ONLY a bucket that VERIFIES can move
                    // a coin. The grading is order-independent (every bundle
                    // is examined, the payload order cannot change the
                    // verdict - consensus determinism).
                    //
                    //  * MATH - an SPV inclusion proof (BoC cell chain /
                    //    receipts trie / Solana Merkle leaf) for THIS claim:
                    //    the foreign chain's own cryptography says the
                    //    deposit happened. Strongest: math beats testimony.
                    //  * TESTIMONY - a quorum attestation for THIS claim: the
                    //    relayers say the deposit happened.
                    //  * RETRACTION - a quorum-signed "this deposit FAILED"
                    //    statement for THIS claim: the relayers withdraw
                    //    their own attestation. This is the ONLY fraud proof
                    //    the layer has, and it is forge-proof: a challenger
                    //    without the quorum's keys cannot produce one.
                    //
                    // PRECEDENCE: pre-activation replay keeps MATH >
                    // RETRACTION > TESTIMONY. At `height >=
                    // BRIDGE_V2_ACTIVATION_HEIGHT` a verified RETRACTION is
                    // graded FIRST: an inclusion-style `DepositProof` from the
                    // same 2/3 quorum is testimony, not trustless math, so it
                    // must never defeat the quorum's own withdrawal (see
                    // `docs/specs/06 §2.4`).
                    //
                    // SEC-01 (preserved): unverifiable evidence is NOT a
                    // fraud signal. It fails to confirm the deposit and
                    // defers under Path 3 - no payout, no burn.
                    let mut confirmed_by_math = false;
                    let mut confirmed_by_testimony = false;
                    let mut fraud_proven = false;
                    for bundle in &bundles {
                        if matches!(
                            bundle,
                            bridge_adapters::DepositEvidence::ZkProofPlaceholder { .. }
                        ) {
                            // The zk placeholder never verifies by design and
                            // the VM already refuses it: it must never read as
                            // a fraud signal either.
                            continue;
                        }
                        let verifies = match bridge_adapters::verify_evidence_at_height(
                            &claim,
                            bundle,
                            validators,
                            block_height,
                            chain_id,
                            evidence_lookup,
                        ) {
                            Ok(verified) => {
                                verified.chain == record.chain
                                    && verified.source_tx_hash == dispute.source_tx_hash
                                    && verified.recipient == record.recipient
                                    && verified.amount == record.amount
                            }
                            Err(_) => false,
                        };
                        if let bridge_adapters::DepositEvidence::QuorumAttested { signatures } =
                            bundle
                        {
                            if verifies {
                                confirmed_by_testimony = true;
                                continue;
                            }
                            // Not an attestation of THIS claim - is it a
                            // quorum RETRACTION of it? (The same signatures
                            // over the domain-separated failure preimage.)
                            if bridge_adapters::verify_quorum_retraction_at_height(
                                &claim,
                                signatures,
                                validators,
                                block_height,
                                evidence_lookup,
                            )
                            .is_ok()
                            {
                                fraud_proven = true;
                            }
                            continue;
                        }
                        if verifies {
                            confirmed_by_math = true;
                        }
                    }
                    // Truth grading (see the precedence note above). The V2
                    // arm checks the retraction BEFORE any confirm bucket.
                    let confirm_by_evidence = if v2 {
                        !fraud_proven && (confirmed_by_math || confirmed_by_testimony)
                    } else {
                        confirmed_by_math || (confirmed_by_testimony && !fraud_proven)
                    };
                    if confirm_by_evidence {
                        // Path 1 - CONFIRM by evidence: the deposit stands.
                        // Clawback returns to the recipient; the bond slashes
                        // to the recipient as freeze compensation (spam-
                        // freezing a real deposit costs the challenger exactly
                        // the bond). FALSE challenge: evidence verifies fine
                        // => slashed, never paid, no 10% reward - at any time
                        // while the dispute is open (even past the deadline:
                        // late truth still beats suppression).
                        let (recipient, amount, bond) =
                            (dispute.recipient, dispute.amount, dispute.bond);
                        dispute.resolved = true;
                        dispute.confirmed = true;
                        let msg = format!(
                            "BRIDGE DISPUTE CONFIRM dispute={dispute_id} amount={amount} bond={bond} reason=false-challenge-evidence-verifies (bond slashed to recipient, no reward)"
                        );
                        eprintln!("{msg}");
                        tracing::error!("{msg}");
                        effects.push(BridgeEffect::Unpark { recipient, amount });
                        effects.push(BridgeEffect::Unpark {
                            recipient,
                            amount: bond,
                        });
                    } else if fraud_proven {
                        // Path 2 - REVOKE by a VERIFIED fraud proof (a quorum
                        // retraction of this exact claim): the deposit was
                        // fraudulent, so it never existed. The challenger's
                        // bond comes back, the finder is paid
                        // DISPUTE_REWARD_BPS of the disputed amount OUT OF the
                        // clawed-back deposit (never minted - see the
                        // conservation invariant in the audit closure), and
                        // the remainder BURNS out of escrow so a fraudulent
                        // mint leaves no inflated supply behind.
                        //
                        // CONSERVATION (exact, no coin from thin air): the
                        // escrow holds `amount + bond`; the finder receives
                        // `bond + reward`; the burn is `amount - reward`.
                        // `bond + reward + (amount - reward) == amount + bond`.
                        let (challenger, bond, amount) =
                            (dispute.challenger, dispute.bond, dispute.amount);
                        let reward = dispute_reward_for(amount);
                        let burn = amount.saturating_sub(reward);
                        dispute.resolved = true;
                        dispute.confirmed = false;
                        effects.push(BridgeEffect::Unpark {
                            recipient: challenger,
                            amount: bond,
                        });
                        effects.push(BridgeEffect::Unpark {
                            recipient: challenger,
                            amount: reward,
                        });
                        effects.push(BridgeEffect::Burn { amount: burn });
                        // Unwind the mint this deposit recorded - by the
                        // BURNED amount: the finder's reward is still
                        // outstanding minted supply, so unwinding the full
                        // deposit would hand the mint cap free headroom.
                        engine.note_revoke(burn);
                        let msg = format!(
                            "BRIDGE DISPUTE REVOKE dispute={dispute_id} amount={amount} bond={bond} reward={reward} burned={burn} reason=verified-quorum-failure-proof (bond + finder reward paid, remainder burned)"
                        );
                        eprintln!("{msg}");
                        tracing::error!("{msg}");
                    } else if now >= dispute.deadline {
                        // Path 3 - evidence UNAVAILABLE or UNCONFIRMED past the deadline:
                        // NEVER pay on unproven evidence (eliminates the false-challenge bounty theft).
                        // DEFER while bounded - push the deadline one window out, dispute stays open,
                        // no coin moves - so an honest recipient gets ample windows to confirm.
                        // Past the bound: REFUSE LOUDLY with no payout at all (fail closed).
                        let cap = record
                            .deposited_at
                            .saturating_add(CHALLENGE_MAX_AGE_SECS)
                            .saturating_add(
                                DISPUTE_WINDOW_SECS
                                    .saturating_mul(1 + MAX_RESOLVE_DEFERRALS as u64),
                            );
                        if dispute.deadline.saturating_add(RESOLVE_DEFER_SECS) <= cap {
                            dispute.deadline = dispute.deadline.saturating_add(RESOLVE_DEFER_SECS);
                            let msg = format!(
                                "BRIDGE DISPUTE DEFER dispute={dispute_id} amount={} new_deadline={} reason=evidence-unconfirmed-past-deadline (rescheduled, no payout)",
                                dispute.amount, dispute.deadline,
                            );
                            eprintln!("{msg}");
                            tracing::error!("{msg}");
                        } else {
                            let msg = format!(
                                "BRIDGE DISPUTE REFUSE dispute={dispute_id} amount={} reason=evidence-unavailable-deferral-bound-exhausted (fail closed: no payout on missing evidence)",
                                dispute.amount,
                            );
                            eprintln!("{msg}");
                            tracing::error!("{msg}");
                            return Err(
                                "bridge resolve refused: evidence unavailable and deferral bound exhausted (fail closed: no payout on missing evidence)".to_string(),
                            );
                        }
                    } else {
                        return Err(
                            "bridge resolve rejected: window still open and evidence does not verify"
                                .to_string(),
                        );
                    }
                }
                BridgeIntent::Attest { .. } => {}
                BridgeIntent::DepositProof { .. } => {
                    // Evidence bundles authorize nothing on their own: they
                    // are consumed by the `Deposit` arm above (paired by
                    // source tx hash). Alone in a payload they are inert -
                    // and therefore commit nothing - exactly like a lone
                    // `Attest` bundle.
                }
                BridgeIntent::ReleaseProof { .. } => {
                    // Payout receipts authorize nothing on their own: they are
                    // consumed by the paired `Release` arm above (paired by
                    // `req_id`), and only when BRIDGE-FIX-FULL is active. A
                    // lone receipt commits nothing — same as a lone `Attest`.
                }
            }
        }

        let mut state = self.clone();
        state.absorb(&engine);
        // Dispute layer (worked above against clones so intents in one
        // payload see each other; committed here atomically with the rest).
        state.deposit_records = records_map;
        state.disputes = disputes_map;
        state.next_dispute_id = next_dispute_id;
        // BRIDGE-FIX-FULL containers (empty and unchanged pre-activation).
        state.release_receipts = release_receipts;
        state.processed_payout_txs = processed_payout_txs;
        state.refunded_withdrawals = refunded_withdrawals;
        Ok(BridgePlan { state, effects })
    }
}

/// Verify one [`ReleaseReceiptEvidence`] against the parked withdrawal it
/// claims to settle, the committed replay set, the block height and the
/// committed height-indexed PQ keys.
///
/// Fail-closed on EVERY doubt (docs/specs/06 §2.3.1 step 4):
/// binding mismatch (req_id / chain / address / amount), zero or already
/// processed `external_tx_hash`, `attestation_height` in the future or older
/// than [`MAX_BRIDGE_ATTESTATION_AGE_HEIGHTS`], an empty validator set, and a
/// sub-threshold quorum over [`release_receipt_signing_message_v2`].
fn verify_release_receipt_v2(
    chain_id: u64,
    receipt: &ReleaseReceiptEvidence,
    req: &TeleportWithdrawalRequest,
    block_height: u64,
    validators: &[[u8; 32]],
    processed_payout_txs: &std::collections::BTreeSet<[u8; 32]>,
    pq_keys: &dyn PqKeyLookup,
) -> Result<(), String> {
    if receipt.req_id != req.req_id {
        return Err(format!(
            "payout receipt req_id {} does not match withdrawal {}",
            receipt.req_id, req.req_id
        ));
    }
    if receipt.target_chain != req.target_chain {
        return Err("payout receipt target chain does not match the withdrawal".to_string());
    }
    if receipt.target_address != req.target_address {
        return Err("payout receipt target address does not match the withdrawal".to_string());
    }
    if receipt.amount != req.amount {
        return Err("payout receipt amount does not match the withdrawal".to_string());
    }
    if receipt.external_tx_hash == [0u8; 32] {
        return Err("payout receipt carries a zero external tx hash".to_string());
    }
    if processed_payout_txs.contains(&receipt.external_tx_hash) {
        return Err("payout external tx already settled (replay refused)".to_string());
    }
    if receipt.attestation_height > block_height {
        return Err(format!(
            "payout receipt attestation height {} is ahead of block height {block_height}",
            receipt.attestation_height
        ));
    }
    if block_height.saturating_sub(receipt.attestation_height) > MAX_BRIDGE_ATTESTATION_AGE_HEIGHTS
    {
        return Err(format!(
            "payout receipt attestation height {} is older than the {} allowed heights",
            receipt.attestation_height, MAX_BRIDGE_ATTESTATION_AGE_HEIGHTS
        ));
    }
    if validators.is_empty() {
        return Err("bridge quorum: empty validator set refuses fail-closed".to_string());
    }
    let msg = release_receipt_signing_message_v2(chain_id, receipt);
    verify_quorum_signatures_at_height(
        &msg,
        &receipt.signatures,
        validators,
        receipt.attestation_height,
        pq_keys,
    )
    .map(|_| ())
}

// ============================================================================
// TON watcher: masterchain finality + replay-safe deposit acceptance
// ============================================================================

/// An inbound TON transfer observed by the watcher.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TonInboundTx {
    pub tx_hash: [u8; 32],
    pub workchain: i32,
    /// Masterchain seqno of the block that includes this transaction.
    pub masterchain_seqno: u64,
    pub lt: u64,
    pub amount_nano: u64,
    pub recipient: [u8; 32],
    pub asset: String,
}

/// Tracks TON masterchain finality and only accepts deposits once they are
/// safely buried. This is what makes bridge credits resistant to a TON reorg.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TonWatcher {
    /// Highest finalized masterchain seqno observed.
    pub finalized_mc_seqno: u64,
    pub min_confirmations: u64,
    /// Deposit tx hashes already accepted (replay protection).
    pub credited: HashSet<[u8; 32]>,
}

impl TonWatcher {
    pub fn new(min_confirmations: u64) -> Self {
        Self {
            finalized_mc_seqno: 0,
            min_confirmations,
            credited: HashSet::new(),
        }
    }

    /// Advance the finalized masterchain head (monotonic).
    pub fn advance(&mut self, mc_seqno: u64) {
        self.finalized_mc_seqno = self.finalized_mc_seqno.max(mc_seqno);
    }

    /// Confirmations accumulated by a transaction at the current head.
    pub fn confirmations(&self, tx: &TonInboundTx) -> u64 {
        self.finalized_mc_seqno.saturating_sub(tx.masterchain_seqno)
    }

    pub fn is_finalized(&self, tx: &TonInboundTx) -> bool {
        // A transaction anchored ahead of the finalized head is from the
        // future, not buried: refuse even when `min_confirmations` is 0
        // (audit BR-OR-04: `saturating_sub` would otherwise report 0
        // confirmations and a zero-minimum watcher would accept it).
        if tx.masterchain_seqno > self.finalized_mc_seqno {
            return false;
        }
        self.confirmations(tx) >= self.min_confirmations
    }

    /// Accept a deposit, enforcing confirmation depth and replay protection.
    pub fn accept(&mut self, tx: &TonInboundTx) -> Result<u64, String> {
        if self.credited.contains(&tx.tx_hash) {
            return Err("Duplicate TON deposit (replay)".to_string());
        }
        // Explicit future-head refusal (fail closed regardless of the
        // configured minimum): depth arithmetic alone cannot see the future.
        if tx.masterchain_seqno > self.finalized_mc_seqno {
            return Err("TON deposit references a block beyond the finalized head".to_string());
        }
        if !self.is_finalized(tx) {
            return Err(format!(
                "TON deposit not final: {} < {} confirmations",
                self.confirmations(tx),
                self.min_confirmations
            ));
        }
        self.credited.insert(tx.tx_hash);
        Ok(tx.amount_nano)
    }
}

// ============================================================================
// Multisig relayer for outbound (Stellereum -> external) releases
// ============================================================================

/// `(req_id, stellereum_chain_id)` binding for a V2 external release
/// authorization.
///
/// Bound into [`MultisigRelayer::release_signing_message_v2`] so an off-chain
/// relayer signature names ONE parked withdrawal on ONE Stellereum network —
/// it cannot be replayed onto another request id or another chain.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseBinding {
    pub req_id: u64,
    pub stellereum_chain_id: u64,
}

/// Latest `expires_at` an external release order may carry for a withdrawal
/// that unlocks at `unlock_at`:
/// `unlock_at + REFUND_GRACE_SECS - PAYOUT_SAFETY_MARGIN_SECS`.
///
/// The 4h buffer means external finality must complete BEFORE the sender's
/// native refund becomes available; saturating, so a tiny `unlock_at` yields 0
/// (an order can never expire "before the epoch" and become eternally valid).
pub fn payout_authorization_deadline(unlock_at: u64) -> u64 {
    unlock_at
        .saturating_add(REFUND_GRACE_SECS)
        .saturating_sub(PAYOUT_SAFETY_MARGIN_SECS)
}

/// A threshold multisig over the relayer set. Used to authorize releases of
/// locked value on the external chain (e.g. burning wSTELL and paying out on
/// TON). Counts distinct validators and prevents double-release by operation id.
///
/// OPERATOR RULE (audit 2026-10-06): `released` is daemon memory. A relayer
/// restart WIPES it, and re-releasing an executed withdrawal pays out twice
/// on the external chain (the on-chain credit stays safe via the committed
/// replay set — the EXTERNAL leg does not). Daemons MUST persist this struct
/// (it is serde) and reload it on boot, AND re-check
/// `pending_withdrawals[].executed` on chain before every release.
///
/// REFUND-RACE RULE (audit B3 / F-G): before signing ANY release the relayer
/// MUST check the on-chain request still exists AND is unexecuted, and
/// re-check at broadcast. A withdrawal refunded after `unlock_at +
/// REFUND_GRACE_SECS` is deleted on chain; a late foreign payout for it pays
/// twice (native refund + foreign coins). Under BRIDGE-FIX-FULL the on-chain
/// [`BridgeIntent::ReleaseProof`] receipt closes the window durably
/// (`processed_payout_txs` + `refunded_withdrawals` tombstones); pre-activation
/// chains still rely on this operator rule.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MultisigRelayer {
    pub validators: HashSet<[u8; 32]>,
    pub threshold: usize,
    pub released: HashSet<[u8; 32]>,
}

impl MultisigRelayer {
    /// Build from a validator list with the bridge-domain threshold,
    /// [`bridge_threshold`] — NOT the consensus curve
    /// [`crate::consensus::consensus_quorum_min`]; see that function for why
    /// the two differ.
    ///
    /// The threshold is floored at 1: an empty or singleton relayer set would
    /// otherwise compute a threshold of 0, and `count_signers >= 0` is true for
    /// *any* input — which would let a misconfigured relayer release every
    /// operation without a single signature. Refusing to go below 1 keeps the
    /// fail-closed direction: no signers, no release.
    pub fn new(validators: Vec<[u8; 32]>) -> Self {
        let threshold = bridge_threshold(validators.len());
        Self {
            validators: validators.into_iter().collect(),
            threshold,
            released: HashSet::new(),
        }
    }

    /// Number of DISTINCT valid Falcon-512 signers over `msg` (FIXES §1.1).
    ///
    /// PRE-V2 WRAPPER: delegates to [`Self::count_signers_at_height`] at
    /// `attestation_height = 0` with [`PreV2ConsensusLookup`]. Live V2 callers
    /// MUST use the height-indexed form with committed keys.
    pub fn count_signers(&self, msg: &[u8], sigs: &[([u8; 32], Vec<u8>)]) -> usize {
        self.count_signers_at_height(msg, sigs, 0, &PreV2ConsensusLookup)
    }

    /// Number of DISTINCT valid Falcon-512 signers over `msg`, resolving each
    /// signer's key AT `attestation_height` through committed `pq_keys`.
    ///
    /// Counts through the shared [`distinct_falcon_signers_at_height`] rule:
    /// an unknown/non-Falcon signer or a signer with no committed key at that
    /// height refuses fail-closed as `0`, so every approval gate refuses the
    /// release.
    pub fn count_signers_at_height(
        &self,
        msg: &[u8],
        sigs: &[([u8; 32], Vec<u8>)],
        attestation_height: u64,
        pq_keys: &dyn PqKeyLookup,
    ) -> usize {
        let validators: Vec<[u8; 32]> = self.validators.iter().copied().collect();
        distinct_falcon_signers_at_height(msg, sigs, &validators, attestation_height, pq_keys)
            .unwrap_or(0)
    }

    /// Signing preimage for this offline model's release authorization.
    ///
    /// The fixed domain separates these signatures from other bridge messages;
    /// the fixed-width operation id and the complete payload are both signed.
    /// This is not the TON or EVM release-order signing format.
    pub fn release_signing_message(op_id: [u8; 32], msg: &[u8]) -> Vec<u8> {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(b"STELLEREUM_MULTISIG_RELAYER_MODEL_RELEASE_V1");
        preimage.extend_from_slice(&op_id);
        preimage.extend_from_slice(msg);
        preimage
    }

    /// V2 signing preimage binding the operation to a `(req_id, chain_id)`
    /// pair and to a distinct domain.
    ///
    /// `STELLEREUM_MULTISIG_RELAYER_MODEL_RELEASE_V2 || stellereum_chain_id ||
    /// req_id || op_id || msg` — a signature can never be replayed onto another
    /// withdrawal or another Stellereum network, and never reused as a V1
    /// authorization.
    pub fn release_signing_message_v2(
        binding: ReleaseBinding,
        op_id: [u8; 32],
        msg: &[u8],
    ) -> Vec<u8> {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(b"STELLEREUM_MULTISIG_RELAYER_MODEL_RELEASE_V2");
        preimage.extend_from_slice(&binding.stellereum_chain_id.to_be_bytes());
        preimage.extend_from_slice(&binding.req_id.to_be_bytes());
        preimage.extend_from_slice(&op_id);
        preimage.extend_from_slice(msg);
        preimage
    }

    /// Authorize a release exactly once. Signatures must cover
    /// [`Self::release_signing_message`], not the raw `msg`.
    ///
    /// PRE-V2 WRAPPER (legacy preimage, [`PreV2ConsensusLookup`] at height 0).
    pub fn try_release(
        &mut self,
        op_id: [u8; 32],
        msg: &[u8],
        sigs: &[([u8; 32], Vec<u8>)],
    ) -> Result<(), String> {
        if self.released.contains(&op_id) {
            return Err("Operation already released".to_string());
        }
        if self.validators.is_empty() {
            return Err("Relayer set is empty: refusing to release".to_string());
        }
        if self.count_signers(&Self::release_signing_message(op_id, msg), sigs) < self.threshold {
            return Err(format!(
                "Insufficient multisig signatures: need {}",
                self.threshold
            ));
        }
        self.released.insert(op_id);
        Ok(())
    }

    /// Authorize a V2 release exactly once. Signatures must cover
    /// [`Self::release_signing_message_v2`] for the SAME [`ReleaseBinding`],
    /// and are counted at `attestation_height` through committed `pq_keys`.
    pub fn try_release_at_height(
        &mut self,
        binding: ReleaseBinding,
        op_id: [u8; 32],
        msg: &[u8],
        sigs: &[([u8; 32], Vec<u8>)],
        attestation_height: u64,
        pq_keys: &dyn PqKeyLookup,
    ) -> Result<(), String> {
        if self.released.contains(&op_id) {
            return Err("Operation already released".to_string());
        }
        if self.validators.is_empty() {
            return Err("Relayer set is empty: refusing to release".to_string());
        }
        let msg = Self::release_signing_message_v2(binding, op_id, msg);
        if self.count_signers_at_height(&msg, sigs, attestation_height, pq_keys) < self.threshold {
            return Err(format!(
                "Insufficient multisig signatures: need {}",
                self.threshold
            ));
        }
        self.released.insert(op_id);
        Ok(())
    }
}

// ============================================================================
// TON TEP-74 Jetton Bridge Wire Format & Multisig Release Orders
// ============================================================================

pub const TON_JETTON_OP_TRANSFER: u32 = 0x0f8a7ea5;
pub const TON_JETTON_OP_BURN: u32 = 0x595f07bc;

/// Models the binary payload of a TEP-74 wSTELL burn on TON destined for Stellereum.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TonJettonBurnPayload {
    pub query_id: u64,
    pub amount_nano: u64,
    /// 32-byte Stellereum recipient address embedded in forward payload
    pub stell_recipient: [u8; 32],
}

impl TonJettonBurnPayload {
    /// Serialize canonical TEP-74 cell body bytes for wSTELL burn.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(4 + 8 + 8 + 32);
        b.extend_from_slice(&TON_JETTON_OP_BURN.to_be_bytes());
        b.extend_from_slice(&self.query_id.to_be_bytes());
        b.extend_from_slice(&self.amount_nano.to_be_bytes());
        b.extend_from_slice(&self.stell_recipient);
        b
    }

    /// Decode and validate TEP-74 burn payload from an observed TON message.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 52 {
            return None;
        }
        let op = u32::from_be_bytes(bytes[0..4].try_into().ok()?);
        if op != TON_JETTON_OP_BURN {
            return None;
        }
        let query_id = u64::from_be_bytes(bytes[4..12].try_into().ok()?);
        let amount_nano = u64::from_be_bytes(bytes[12..20].try_into().ok()?);
        let stell_recipient: [u8; 32] = bytes[20..52].try_into().ok()?;
        Some(Self {
            query_id,
            amount_nano,
            stell_recipient,
        })
    }
}

/// Outbound release order authorizing the TON Multisig Bridge contract to mint/payout wSTELL.
///
/// `req_id` + `stellereum_chain_id` bind the order to ONE parked withdrawal on
/// ONE Stellereum network; both are inside the signed preimage. `expires_at`
/// MUST stay at or before [`payout_authorization_deadline`] of the withdrawal's
/// `unlock_at` (checked by [`Self::is_approved_for_withdrawal`]), leaving the
/// [`PAYOUT_SAFETY_MARGIN_SECS`] quiet window before the native refund.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TonMultisigReleaseOrder {
    pub op_id: [u8; 32],
    pub ton_recipient_hex: String,
    pub amount_nano: u64,
    pub expires_at: u64,
    pub signatures: Vec<([u8; 32], Vec<u8>)>,
    /// The parked withdrawal this order pays out.
    #[serde(default)]
    pub req_id: u64,
    /// Stellereum network the order was authorized on (cross-network replay
    /// guard).
    #[serde(default)]
    pub stellereum_chain_id: u64,
}

impl TonMultisigReleaseOrder {
    pub fn new(
        op_id: [u8; 32],
        ton_recipient_hex: String,
        amount_nano: u64,
        expires_at: u64,
        req_id: u64,
        stellereum_chain_id: u64,
    ) -> Self {
        Self {
            op_id,
            ton_recipient_hex,
            amount_nano,
            expires_at,
            signatures: Vec::new(),
            req_id,
            stellereum_chain_id,
        }
    }

    /// Canonical bytes signed by relayers (V2: binds `chain_id` + `req_id`).
    pub fn signing_message(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(b"TON_MULTISIG_RELEASE_V2");
        b.extend_from_slice(&self.stellereum_chain_id.to_be_bytes());
        b.extend_from_slice(&self.req_id.to_be_bytes());
        b.extend_from_slice(&self.op_id);
        b.extend_from_slice(self.ton_recipient_hex.as_bytes());
        b.extend_from_slice(&self.amount_nano.to_be_bytes());
        b.extend_from_slice(&self.expires_at.to_be_bytes());
        b
    }

    /// True when `expires_at` leaves the full [`PAYOUT_SAFETY_MARGIN_SECS`]
    /// window before `unlock_at + REFUND_GRACE_SECS`.
    pub fn expires_within_refund_window(&self, unlock_at: u64) -> bool {
        self.expires_at <= payout_authorization_deadline(unlock_at)
    }

    /// Check if this release order has collected a 2/3 threshold quorum of
    /// distinct relayers, resolving keys AT `attestation_height` through the
    /// committed `pq_keys` lookup.
    pub fn is_approved_at_height(
        &self,
        relayer: &MultisigRelayer,
        now: u64,
        attestation_height: u64,
        pq_keys: &dyn PqKeyLookup,
    ) -> bool {
        if now > self.expires_at {
            return false;
        }
        relayer.count_signers_at_height(
            &self.signing_message(),
            &self.signatures,
            attestation_height,
            pq_keys,
        ) >= relayer.threshold
    }

    /// Full payout-authorization gate for a parked withdrawal: quorum at
    /// `attestation_height`, not expired, AND expiring at or before
    /// [`payout_authorization_deadline`] of `unlock_at`.
    pub fn is_approved_for_withdrawal(
        &self,
        relayer: &MultisigRelayer,
        now: u64,
        unlock_at: u64,
        attestation_height: u64,
        pq_keys: &dyn PqKeyLookup,
    ) -> bool {
        self.expires_within_refund_window(unlock_at)
            && self.is_approved_at_height(relayer, now, attestation_height, pq_keys)
    }

    /// PRE-V2 WRAPPER: legacy pre-activation key lookup at height 0 (no
    /// refund-window bound — pre-activation replay only).
    pub fn is_approved(&self, relayer: &MultisigRelayer, now: u64) -> bool {
        self.is_approved_at_height(relayer, now, 0, &PreV2ConsensusLookup)
    }
}

// ============================================================================
// EVM (Ethereum / Arbitrum) Teleport Bridge Adapter
// ============================================================================

pub const ETHEREUM_FINALITY_BLOCKS: u64 = 64; // ~12.8 mins
pub const ARBITRUM_FINALITY_BLOCKS: u64 = 32;

/// An inbound EVM deposit event emitted by the Bridge contract on Ethereum or Arbitrum.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmDepositEvent {
    pub chain: SupportedChain,
    pub tx_hash: [u8; 32],
    pub log_index: u32,
    pub block_number: u64,
    pub token: [u8; 20],
    pub sender: [u8; 20],
    pub stell_recipient: [u8; 32],
    pub amount_nano: u64,
}

/// Watches an EVM chain, tracks finalized block height, and rejects reorgs / double-spends.
///
/// Same operator rule as `MultisigRelayer`: `credited` is daemon memory —
/// persist + reload on boot (serde), or a restart re-credits deposits.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EvmWatcher {
    pub chain: SupportedChain,
    pub finalized_block: u64,
    pub min_confirmations: u64,
    /// (tx_hash, log_index) -> already credited
    pub credited: HashSet<([u8; 32], u32)>,
}

impl EvmWatcher {
    pub fn new(chain: SupportedChain, min_confirmations: u64) -> Self {
        Self {
            chain,
            finalized_block: 0,
            min_confirmations,
            credited: HashSet::new(),
        }
    }

    pub fn advance(&mut self, block_number: u64) {
        self.finalized_block = self.finalized_block.max(block_number);
    }

    pub fn confirmations(&self, event: &EvmDepositEvent) -> u64 {
        self.finalized_block.saturating_sub(event.block_number)
    }

    pub fn is_finalized(&self, event: &EvmDepositEvent) -> bool {
        // Same future-head rule as `TonWatcher` (audit BR-OR-04).
        if event.block_number > self.finalized_block {
            return false;
        }
        self.confirmations(event) >= self.min_confirmations
    }

    /// Accept an EVM deposit after depth verification and deduplication.
    pub fn accept(&mut self, event: &EvmDepositEvent) -> Result<u64, String> {
        if event.chain != self.chain {
            return Err("EVM chain mismatch".to_string());
        }
        // Explicit future-head refusal (fail closed regardless of minimum).
        if event.block_number > self.finalized_block {
            return Err("EVM deposit references a block beyond the finalized head".to_string());
        }
        let key = (event.tx_hash, event.log_index);
        if self.credited.contains(&key) {
            return Err("Duplicate EVM deposit (replay)".to_string());
        }
        if !self.is_finalized(event) {
            return Err(format!(
                "EVM deposit not final: {} < {} confirmations",
                self.confirmations(event),
                self.min_confirmations
            ));
        }
        self.credited.insert(key);
        Ok(event.amount_nano)
    }
}

/// Outbound release message signed by 2/3 relayers to unlock ERC-20 tokens on EVM.
///
/// `req_id` + `stellereum_chain_id` bind the order to ONE parked withdrawal on
/// ONE Stellereum network; both are inside the signed preimage, and
/// `expires_at` is bounded by [`payout_authorization_deadline`] via
/// [`Self::is_approved_for_withdrawal`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvmReleaseOrder {
    pub chain: SupportedChain,
    pub op_id: [u8; 32],
    pub token_address: [u8; 20],
    pub recipient: [u8; 20],
    pub amount_nano: u64,
    pub nonce: u64,
    pub expires_at: u64,
    pub signatures: Vec<([u8; 32], Vec<u8>)>,
    /// The parked withdrawal this order pays out.
    #[serde(default)]
    pub req_id: u64,
    /// Stellereum network the order was authorized on (cross-network replay
    /// guard).
    #[serde(default)]
    pub stellereum_chain_id: u64,
}

impl EvmReleaseOrder {
    #[allow(clippy::too_many_arguments)]
    // GATE: the constructor mirrors the frozen EVM release-order wire fields
    // one-for-one (chain, op, token, recipient, amount, nonce, expiry + the
    // req_id/chain_id binding); grouping them would obscure the order layout.
    pub fn new(
        chain: SupportedChain,
        op_id: [u8; 32],
        token_address: [u8; 20],
        recipient: [u8; 20],
        amount_nano: u64,
        nonce: u64,
        expires_at: u64,
        req_id: u64,
        stellereum_chain_id: u64,
    ) -> Self {
        Self {
            chain,
            op_id,
            token_address,
            recipient,
            amount_nano,
            nonce,
            expires_at,
            signatures: Vec::new(),
            req_id,
            stellereum_chain_id,
        }
    }

    /// Canonical bytes signed by relayers (V2: binds `chain_id` + `req_id`).
    pub fn signing_message(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(b"EVM_TELEPORT_RELEASE_V2");
        b.extend_from_slice(match self.chain {
            SupportedChain::Ethereum => b"ETH",
            SupportedChain::Arbitrum => b"ARB",
            _ => b"UNK",
        });
        b.extend_from_slice(&self.stellereum_chain_id.to_be_bytes());
        b.extend_from_slice(&self.req_id.to_be_bytes());
        b.extend_from_slice(&self.op_id);
        b.extend_from_slice(&self.token_address);
        b.extend_from_slice(&self.recipient);
        b.extend_from_slice(&self.amount_nano.to_be_bytes());
        b.extend_from_slice(&self.nonce.to_be_bytes());
        b.extend_from_slice(&self.expires_at.to_be_bytes());
        b
    }

    /// True when `expires_at` leaves the full [`PAYOUT_SAFETY_MARGIN_SECS`]
    /// window before `unlock_at + REFUND_GRACE_SECS`.
    pub fn expires_within_refund_window(&self, unlock_at: u64) -> bool {
        self.expires_at <= payout_authorization_deadline(unlock_at)
    }

    /// Check if this release order has collected a 2/3 threshold quorum,
    /// resolving keys AT `attestation_height` through committed `pq_keys`.
    pub fn is_approved_at_height(
        &self,
        relayer: &MultisigRelayer,
        now: u64,
        attestation_height: u64,
        pq_keys: &dyn PqKeyLookup,
    ) -> bool {
        if now > self.expires_at {
            return false;
        }
        // Audit BR-OR-05: the signing preimage tags every non-EVM chain as
        // "UNK", so a Ton order and a Solana order over identical fields share
        // one signing message (signature transplant across chains). This order
        // type is EVM-only (Ton has `TonMultisigReleaseOrder`); refuse anything
        // else fail-closed.
        if !matches!(
            self.chain,
            SupportedChain::Ethereum | SupportedChain::Arbitrum
        ) {
            return false;
        }
        relayer.count_signers_at_height(
            &self.signing_message(),
            &self.signatures,
            attestation_height,
            pq_keys,
        ) >= relayer.threshold
    }

    /// Full payout-authorization gate for a parked withdrawal: quorum at
    /// `attestation_height`, not expired, AND expiring at or before
    /// [`payout_authorization_deadline`] of `unlock_at`.
    pub fn is_approved_for_withdrawal(
        &self,
        relayer: &MultisigRelayer,
        now: u64,
        unlock_at: u64,
        attestation_height: u64,
        pq_keys: &dyn PqKeyLookup,
    ) -> bool {
        self.expires_within_refund_window(unlock_at)
            && self.is_approved_at_height(relayer, now, attestation_height, pq_keys)
    }

    /// PRE-V2 WRAPPER: legacy pre-activation key lookup at height 0 (no
    /// refund-window bound — pre-activation replay only).
    pub fn is_approved(&self, relayer: &MultisigRelayer, now: u64) -> bool {
        self.is_approved_at_height(relayer, now, 0, &PreV2ConsensusLookup)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn sig(sk: &SigningKey, msg: &[u8]) -> ([u8; 32], Vec<u8>) {
        (sk.verifying_key().to_bytes(), sk.sign(msg).to_vec())
    }

    fn deposit(sk: &SigningKey, amount: u64) -> TeleportDepositEvent {
        let msg = TeleportDepositEvent {
            source_chain: SupportedChain::Ton,
            source_tx_hash: [7u8; 32],
            recipient: [8u8; 32],
            asset: "USDT".into(),
            amount,
            validator_signatures: vec![],
            zk_proof: None,
        };
        let _ = sk;
        msg
    }

    #[test]
    fn duplicate_signers_cannot_fake_quorum() {
        // 3 validators -> quorum 2. One validator signing twice must NOT pass.
        let a = SigningKey::generate(&mut OsRng);
        let b = SigningKey::generate(&mut OsRng);
        let c = SigningKey::generate(&mut OsRng);
        let mut engine = TeleportBridgeEngine::new(vec![
            a.verifying_key().to_bytes(),
            b.verifying_key().to_bytes(),
            c.verifying_key().to_bytes(),
        ]);

        let mut ev = deposit(&a, 1_000);
        let msg = TeleportBridgeEngine::deposit_signing_message(&ev);
        // same signer twice
        ev.validator_signatures = vec![sig(&a, &msg), sig(&a, &msg)];
        assert!(
            engine.process_deposit(&ev).is_err(),
            "one signer must not reach quorum"
        );

        // two DISTINCT signers pass
        // FIXES §1.1: the quorum counts REGISTERED Falcon-512 keys only —
        // these classical sigs carry no registered key, so they are refused.
        ev.validator_signatures = vec![sig(&a, &msg), sig(&b, &msg)];
        assert!(engine.process_deposit(&ev).is_err());
    }

    /// PIN: the consensus and bridge quorum curves are DIFFERENT on purpose and
    /// must never be "brought to a common form".
    ///
    /// * bridge  `bridge_threshold` / `quorum_threshold`: `floor((2n+2)/3)`
    ///   floored at 1 - distinct-signer threshold over an external signer set;
    /// * consensus `consensus_quorum_min` / `pq_micro_quorum_threshold`:
    ///   `floor(2n/3) + 1` - strict BFT supermajority, where a bare 2/3 must
    ///   NOT suffice.
    ///
    /// They disagree at n = 3 (2 vs 3) and n = 6 (4 vs 5): changing either
    /// list is a safety/economic change for THAT domain only, never a
    /// refactor. Both lists are frozen for n = 1..8.
    #[test]
    fn quorum_formulas_are_pinned_per_domain() {
        const BRIDGE: [usize; 8] = [1, 2, 2, 3, 4, 4, 5, 6];
        const CONSENSUS: [usize; 8] = [1, 2, 3, 3, 4, 5, 5, 6];

        for (i, (&want_bridge, &want_consensus)) in BRIDGE.iter().zip(CONSENSUS.iter()).enumerate()
        {
            let n = i + 1;
            assert_eq!(
                bridge_threshold(n),
                want_bridge,
                "bridge_threshold({n}) moved - bridge domain threshold changed"
            );
            assert_eq!(
                quorum_threshold(n),
                want_bridge,
                "quorum_threshold({n}) must stay the bridge curve"
            );
            assert_eq!(
                crate::consensus::consensus_quorum_min(n as u64) as usize,
                want_consensus,
                "consensus_quorum_min({n}) moved - BFT quorum changed"
            );
            assert_eq!(
                crate::consensus::pq_micro_quorum_threshold(n as u32),
                want_consensus,
                "pq_micro_quorum_threshold({n}) must stay the consensus curve"
            );
            // MultisigRelayer::new must derive from the bridge curve.
            let validators = (0..n).map(|k| [k as u8 + 1; 32]).collect::<Vec<_>>();
            assert_eq!(
                MultisigRelayer::new(validators).threshold,
                want_bridge,
                "MultisigRelayer threshold for n={n} must stay the bridge curve"
            );
        }

        // The documented disagreement at n = 3: bridge accepts 2 distinct
        // signers, consensus demands 3. This is the reason the two live in
        // separate functions with separate doc comments.
        assert_eq!(bridge_threshold(3), 2);
        assert_eq!(crate::consensus::consensus_quorum_min(3), 3);
        // Zero-size edge: consensus never quorums below 1, bridge floors at 1.
        assert_eq!(crate::consensus::consensus_quorum_min(0), 1);
        assert_eq!(bridge_threshold(0), 1);
        assert_eq!(crate::consensus::pq_micro_quorum_threshold(0), usize::MAX);
    }

    #[test]
    fn replay_is_rejected() {
        let a = SigningKey::generate(&mut OsRng);
        let b = SigningKey::generate(&mut OsRng);
        let mut engine = TeleportBridgeEngine::new(vec![
            a.verifying_key().to_bytes(),
            b.verifying_key().to_bytes(),
        ]);
        let mut ev = deposit(&a, 500);
        let msg = TeleportBridgeEngine::deposit_signing_message(&ev);
        ev.validator_signatures = vec![sig(&a, &msg), sig(&b, &msg)];
        // FIXES §1.1: classical sigs carry no registered Falcon key —
        // deposit refused (replay set untouched, so a second identical
        // ingest is also refused).
        assert!(engine.process_deposit(&ev).is_err());
        assert!(
            engine.process_deposit(&ev).is_err(),
            "replay must be rejected"
        );
    }

    #[test]
    fn ton_requires_confirmations_and_dedups() {
        let mut w = TonWatcher::new(MIN_TON_CONFIRMATIONS);
        let tx = TonInboundTx {
            tx_hash: [1u8; 32],
            workchain: 0,
            masterchain_seqno: 100,
            lt: 1,
            amount_nano: 5_000,
            recipient: [2u8; 32],
            asset: "TON".into(),
        };
        // Not buried yet.
        w.advance(105);
        assert!(w.accept(&tx).is_err(), "too few confirmations");
        // Buried enough.
        w.advance(112);
        assert_eq!(w.accept(&tx).unwrap(), 5_000);
        // Replay rejected.
        assert!(w.accept(&tx).is_err(), "replay must be rejected");
    }

    #[test]
    fn multisig_release_requires_distinct_threshold_and_is_once() {
        // FIXES §1.1: the relayer counts REGISTERED Falcon keys only —
        // classical sigs carry no registered key, so every release here is
        // refused fail-closed (count_signers 0).
        let keys: Vec<SigningKey> = (0..3).map(|_| SigningKey::generate(&mut OsRng)).collect();
        let pubs: Vec<[u8; 32]> = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();
        let mut relayer = MultisigRelayer::new(pubs);
        assert_eq!(relayer.threshold, 2);

        let op = [9u8; 32];
        let msg = b"release 100 STELL to TON";
        // duplicate signer -> only 1 distinct -> rejected
        assert!(relayer
            .try_release(op, msg, &[sig(&keys[0], msg), sig(&keys[0], msg)])
            .is_err());
        // FIXES §1.1: even 2 distinct classical sigs are refused (no
        // registered Falcon key).
        assert!(relayer
            .try_release(op, msg, &[sig(&keys[0], msg), sig(&keys[1], msg)])
            .is_err());
        // idempotent guard (still refused)
        assert!(relayer
            .try_release(op, msg, &[sig(&keys[0], msg), sig(&keys[1], msg)])
            .is_err());
    }

    #[test]
    fn degenerate_relayer_set_cannot_release_anything() {
        // A misconfigured relayer with no validators computed a threshold of 0,
        // and `count_signers >= 0` holds for ANY input — so an empty signature
        // list would have released every operation.
        let mut empty = MultisigRelayer::new(vec![]);
        assert!(empty.threshold >= 1, "threshold must never be zero");
        assert!(
            empty.try_release([1u8; 32], b"msg", &[]).is_err(),
            "no signers, no release"
        );

        // A single validator must still require that validator's signature.
        // FIXES §1.1: classical sigs carry no registered Falcon key, so they
        // are refused even from the validator.
        let k = SigningKey::generate(&mut OsRng);
        let mut one = MultisigRelayer::new(vec![k.verifying_key().to_bytes()]);
        let msg = b"release";
        assert!(
            one.try_release([2u8; 32], msg, &[]).is_err(),
            "unsigned release must fail"
        );
        assert!(one.try_release([2u8; 32], msg, &[sig(&k, msg)]).is_err());

        // A signature from outside the relayer set does not count either.
        let outsider = SigningKey::generate(&mut OsRng);
        let mut one2 = MultisigRelayer::new(vec![k.verifying_key().to_bytes()]);
        assert!(one2
            .try_release([3u8; 32], msg, &[sig(&outsider, msg)])
            .is_err());
    }

    #[test]
    fn deposit_mint_caps_hourly_and_cumulative() {
        // Audit F-H: the mint ceilings live in `note_deposit_mint`, shared by
        // both deposit paths in plan(). Hourly window + cumulative cap, block
        // clock, saturating, refusal leaves the engine untouched.
        let mut e = TeleportBridgeEngine::new(vec![[7u8; 32]]);
        // Within both ceilings: admitted and counted. The window that opened
        // at genesis (reset=0) still covers t=1000, so no reset fires yet.
        assert!(e.note_deposit_mint(100, 1_000).is_ok());
        assert_eq!(e.hourly_deposited, 100);
        assert_eq!(e.total_minted, 100);
        assert_eq!(e.last_deposit_reset, 0);
        // Hourly breach (same window): refused, counters untouched.
        assert!(e
            .note_deposit_mint(HOURLY_DEPOSIT_LIMIT_NANO, 1_001)
            .is_err());
        assert_eq!(e.hourly_deposited, 100);
        assert_eq!(e.total_minted, 100);
        // Window rolls over on the block clock: same amount now fits.
        assert!(e.note_deposit_mint(HOURLY_DEPOSIT_LIMIT_NANO, 3600).is_ok());
        assert_eq!(e.hourly_deposited, HOURLY_DEPOSIT_LIMIT_NANO);
        assert_eq!(e.last_deposit_reset, 3600);
        // Cumulative ceiling: engineer the counter near the cap, then refuse.
        e.total_minted = BRIDGE_MINT_CAP_NANO - 50;
        e.hourly_deposited = 0;
        e.last_deposit_reset = 9_999_999;
        assert!(e.note_deposit_mint(50, 9_999_999).is_ok());
        assert_eq!(e.total_minted, BRIDGE_MINT_CAP_NANO);
        assert!(
            e.note_deposit_mint(1, 9_999_999).is_err(),
            "at the cap, even 1 more mints nothing"
        );
        assert_eq!(e.total_minted, BRIDGE_MINT_CAP_NANO);
    }

    #[test]
    fn p5_revoke_cycle_cannot_reopen_mint_cap_headroom() {
        // P5 ATTACK: deposit to the cumulative cap edge, get the deposit
        // revoked (fraud-proven challenge burns `amount - reward`), then try
        // to re-mint the SAME full deposit — a revoke+re-deposit cycle that
        // would let a compromised quorum mint past BRIDGE_MINT_CAP_NANO one
        // "refund" at a time if the unwind credited the full deposit.
        // The unwind credits only the BURNED amount (the finder reward stays
        // counted as outstanding minted supply), so each cycle recovers less
        // than it consumed, and the replay set (never cleared by a revoke —
        // `note_revoke` touches only counters) refuses the same hash anyway.
        let mut e = TeleportBridgeEngine::new(vec![[7u8; 32]]);
        e.total_minted = BRIDGE_MINT_CAP_NANO - 1_000_000;
        e.hourly_deposited = 0;
        e.last_deposit_reset = 0;
        let d: u64 = 1_000_000;
        assert!(e.note_deposit_mint(d, 100).is_ok());
        assert_eq!(e.total_minted, BRIDGE_MINT_CAP_NANO);
        // Fraud-proven revoke: burn = d - reward, unwind by the burn only.
        let reward = dispute_reward_for(d);
        let burn = d.saturating_sub(reward);
        assert!(
            burn < d,
            "a non-dust revoke always pays a reward, so burn < deposit"
        );
        e.note_revoke(burn);
        assert_eq!(e.total_minted, BRIDGE_MINT_CAP_NANO - burn);
        assert_eq!(
            e.hourly_deposited,
            d - burn,
            "hourly window unwinds by the burn only"
        );
        // The cycle: re-minting the SAME full deposit is refused — the cap
        // still binds because the finder reward stayed counted.
        assert!(
            e.note_deposit_mint(d, 100).is_err(),
            "revoke+re-deposit must not reopen headroom for the full amount"
        );
        // Honest liveness: exactly the burned headroom IS reusable.
        assert!(e.note_deposit_mint(burn, 100).is_ok());
        assert_eq!(e.total_minted, BRIDGE_MINT_CAP_NANO);
        // And the replay set is revoke-proof: the same source hash can never
        // credit twice (revoke path never removes it — grep shows no
        // `processed_source_txs.remove` on the revoke path).
        e.processed_source_txs.insert([0xAAu8; 32], true);
        assert!(
            e.processed_source_txs.contains_key(&[0xAAu8; 32]),
            "revoked hashes stay in the replay set: no second credit, ever"
        );
    }

    #[test]
    fn withdrawal_rate_limit_does_not_overflow() {
        let mut engine = TeleportBridgeEngine::new(vec![[1u8; 32]]);
        // A gigantic amount must be rejected by the rate limit, not wrap around.
        assert!(engine
            .request_withdrawal(
                [1u8; 32],
                SupportedChain::Arbitrum,
                "0x1".into(),
                u64::MAX,
                0
            )
            .is_err());
    }

    #[test]
    fn ton_jetton_burn_payload_roundtrip_and_validation() {
        let burn = TonJettonBurnPayload {
            query_id: 12345,
            amount_nano: 50_000_000_000,
            stell_recipient: [0x42; 32],
        };
        let encoded = burn.encode();
        assert_eq!(encoded.len(), 52);
        let decoded = TonJettonBurnPayload::decode(&encoded).expect("must decode valid payload");
        assert_eq!(decoded, burn);

        // invalid opcode or too short
        assert!(TonJettonBurnPayload::decode(&[0; 10]).is_none());
        let mut tampered = encoded.clone();
        tampered[0] = 0x00; // wrong op
        assert!(TonJettonBurnPayload::decode(&tampered).is_none());
    }

    #[test]
    fn ton_multisig_release_order_approval_flow() {
        let keys: Vec<SigningKey> = (0..3).map(|_| SigningKey::generate(&mut OsRng)).collect();
        let pubs: Vec<[u8; 32]> = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();
        let relayer = MultisigRelayer::new(pubs);

        let mut order = TonMultisigReleaseOrder::new(
            [0x88; 32],
            "EQD4FPq-PRDieyQKkKZ085...".to_string(),
            100_000_000_000,
            1_000,
            0,
            11,
        );

        let msg = order.signing_message();
        // 1 signature -> not approved (needs 2/3 = 2)
        order.signatures.push(sig(&keys[0], &msg));
        assert!(!order.is_approved(&relayer, 500));

        // FIXES §1.1: classical sigs carry no registered Falcon key, so
        // even 2 distinct ones never approve (count_signers 0, fail closed).
        order.signatures.push(sig(&keys[1], &msg));
        assert!(!order.is_approved(&relayer, 500));

        // expired order -> not approved
        assert!(!order.is_approved(&relayer, 1_001));
    }

    #[test]
    fn evm_watcher_depth_verification_and_deduplication() {
        let mut eth_watcher = EvmWatcher::new(SupportedChain::Ethereum, ETHEREUM_FINALITY_BLOCKS);
        let event = EvmDepositEvent {
            chain: SupportedChain::Ethereum,
            tx_hash: [0x55; 32],
            log_index: 0,
            block_number: 10_000,
            token: [0xDA; 20],
            sender: [0x11; 20],
            stell_recipient: [0x99; 32],
            amount_nano: 500_000_000,
        };

        // Not finalized (only 10 confirmations < 64)
        eth_watcher.advance(10_010);
        assert!(!eth_watcher.is_finalized(&event));
        assert!(eth_watcher.accept(&event).is_err());

        // Finalized at 10_064
        eth_watcher.advance(10_064);
        assert!(eth_watcher.is_finalized(&event));
        assert_eq!(eth_watcher.accept(&event).unwrap(), 500_000_000);

        // Replay rejected
        assert!(eth_watcher.accept(&event).is_err());

        // Wrong chain rejected
        let arb_event = EvmDepositEvent {
            chain: SupportedChain::Arbitrum,
            ..event
        };
        assert!(eth_watcher.accept(&arb_event).is_err());
    }

    #[test]
    fn evm_release_order_multisig_approval() {
        let keys: Vec<SigningKey> = (0..3).map(|_| SigningKey::generate(&mut OsRng)).collect();
        let pubs: Vec<[u8; 32]> = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();
        let relayer = MultisigRelayer::new(pubs);

        let mut order = EvmReleaseOrder::new(
            SupportedChain::Arbitrum,
            [0xAA; 32],
            [0xDA; 20],
            [0x22; 20],
            2_000_000_000,
            1,
            5_000,
            0,
            11,
        );

        let msg = order.signing_message();
        // 1 sig -> not enough
        order.signatures.push(sig(&keys[0], &msg));
        assert!(!order.is_approved(&relayer, 1_000));

        // FIXES §1.1: classical sigs carry no registered Falcon key, so
        // even 2 distinct ones never approve (count_signers 0, fail closed).
        order.signatures.push(sig(&keys[1], &msg));
        assert!(!order.is_approved(&relayer, 1_000));

        // expired -> not approved
        assert!(!order.is_approved(&relayer, 5_001));
    }

    #[test]
    fn dispute_economics_scale_with_floor() {
        // C5: 1% of the disputed value, floored at 1 STELL.
        assert_eq!(challenge_bond_for(100 * 1_000_000_000), 1_000_000_000);
        assert_eq!(
            challenge_bond_for(500_000 * 1_000_000_000),
            5_000 * 1_000_000_000
        );
        assert_eq!(challenge_bond_for(1), CHALLENGE_BOND_NANO);
        assert_eq!(challenge_bond_for(0), CHALLENGE_BOND_NANO);
        // No overflow at the top of u64 (u128 math inside).
        assert_eq!(
            challenge_bond_for(u64::MAX),
            CHALLENGE_BOND_NANO.max(((u64::MAX as u128 * 100) / 10_000) as u64)
        );
        // C9: 10% reward, dust floor of 1 nano, never above the amount.
        assert_eq!(dispute_reward_for(100 * 1_000_000_000), 10 * 1_000_000_000);
        assert_eq!(dispute_reward_for(5), 1);
        assert_eq!(dispute_reward_for(0), 0);
    }

    #[test]
    fn deposit_proof_variant_keeps_legacy_discriminants_stable() {
        // `BridgeIntent` rides inside signed payloads (bincode enum = u32
        // discriminant + data). `DepositProof` was APPENDED, so every
        // pre-evidence payload must decode byte-identically: the first four
        // discriminants are pinned here, and the new variant sits at 4.
        fn discriminant(intent: &BridgeIntent) -> u32 {
            let bytes = bincode::serialize(intent).expect("intent serializes");
            u32::from_le_bytes(bytes[0..4].try_into().unwrap())
        }
        assert_eq!(
            discriminant(&BridgeIntent::Deposit {
                chain: SupportedChain::Ton,
                source_tx_hash: [0u8; 32],
                recipient: [1u8; 32],
                amount: 1,
            }),
            0
        );
        assert_eq!(
            discriminant(&BridgeIntent::Withdraw {
                chain: SupportedChain::Ton,
                target_address: "x".to_string(),
                amount: 1,
            }),
            1
        );
        assert_eq!(
            discriminant(&BridgeIntent::Attest {
                source_tx_hash: [0u8; 32],
                signatures: vec![([0u8; 32], vec![0u8; 64])],
            }),
            2
        );
        assert_eq!(discriminant(&BridgeIntent::Release { req_id: 0 }), 3);
        assert_eq!(discriminant(&BridgeIntent::Refund { req_id: 0 }), 5);
        assert_eq!(
            discriminant(&BridgeIntent::DepositProof {
                source_tx_hash: [0u8; 32],
                evidence: Box::new(
                    crate::bridge::bridge_adapters::DepositEvidence::ZkProofPlaceholder {
                        note: "pin".to_string(),
                    },
                ),
            }),
            4
        );
        // Dispute layer appended last: Challenge 6, Resolve 7. Every older
        // discriminant above must never move (signed preimages).
        assert_eq!(
            discriminant(&BridgeIntent::Challenge {
                source_tx_hash: [0u8; 32]
            }),
            6
        );
        assert_eq!(discriminant(&BridgeIntent::Resolve { dispute_id: 0 }), 7);
        // BRIDGE-FIX-FULL appended the payout receipt strictly last: 8.
        assert_eq!(
            discriminant(&BridgeIntent::ReleaseProof {
                req_id: 0,
                receipt: Box::new(ReleaseReceiptEvidence {
                    req_id: 0,
                    target_chain: SupportedChain::Ton,
                    target_address: "x".to_string(),
                    amount: 1,
                    external_tx_hash: [1u8; 32],
                    finalized_head: 0,
                    attestation_height: 0,
                    signatures: vec![([0u8; 32], vec![0u8; 64])],
                }),
            }),
            8
        );
    }

    /// FIXES §1.1: classical ed25519 signatures never count toward the
    /// Falcon DISTINCT quorum — always refused (Err), with or without the
    /// (no-op) pure-PQ override. The ids below carry no registered Falcon
    /// key, and a 64-byte Ed signature can never verify as Falcon-512.
    #[test]
    fn pure_pq_refuses_classical_quorum() {
        struct PurePqGuard;
        impl PurePqGuard {
            fn enforce() -> Self {
                crate::post_quantum::set_pure_pq_override(Some(true));
                Self
            }
        }
        impl Drop for PurePqGuard {
            fn drop(&mut self) {
                crate::post_quantum::set_pure_pq_override(None);
            }
        }
        let a = SigningKey::generate(&mut OsRng);
        let b = SigningKey::generate(&mut OsRng);
        let c = SigningKey::generate(&mut OsRng);
        let validators = vec![
            a.verifying_key().to_bytes(),
            b.verifying_key().to_bytes(),
            c.verifying_key().to_bytes(),
        ];
        let msg = b"bridge pq gate pin";
        let sigs = vec![sig(&a, msg), sig(&b, msg)];

        // FULL-PQ always-on: valid 2-of-3 quorum is refused.
        assert!(
            verify_quorum_signatures(msg, &sigs, &validators).is_err(),
            "valid ed quorum must be refused under FULL-PQ"
        );
        // Enforced: the SAME valid quorum is refused fail-closed.
        {
            let _guard = PurePqGuard::enforce();
            assert!(
                verify_quorum_signatures(msg, &sigs, &validators).is_err(),
                "valid ed quorum must be refused under pure-PQ"
            );
        }
        // Still refused without the override (always-on).
        assert!(
            verify_quorum_signatures(msg, &sigs, &validators).is_err(),
            "FULL-PQ always-on: valid ed quorum refused"
        );
    }

    // --- FIXES §1.1 / §5 acceptance: Falcon DISTINCT quorum. ---

    /// Register a deterministic Falcon-512 key for an Ed-identity validator
    /// id. Ed ids are fixed per test (`ed_seed`); the Falcon key derives from
    /// `falcon_seed`, so parallel tests registering the same id converge on
    /// the same key (idempotent overwrite, no cross-test flake).
    fn falcon_id(ed_seed: u8, falcon_seed: u8) -> ([u8; 32], crate::post_quantum::FalconKeypair) {
        let sk = SigningKey::from_bytes(&[ed_seed; 32]);
        let id = sk.verifying_key().to_bytes();
        let fk = crate::post_quantum::FalconKeypair::generate_from_seed(falcon_seed);
        crate::consensus::register_validator_pq_key(
            id,
            crate::post_quantum::PqScheme::Falcon512,
            fk.public_key.clone(),
        );
        (id, fk)
    }

    fn fsig(
        id: &[u8; 32],
        fk: &crate::post_quantum::FalconKeypair,
        msg: &[u8],
    ) -> ([u8; 32], Vec<u8>) {
        (*id, fk.sign(msg))
    }

    #[test]
    fn falcon_quorum_three_of_four_returns_ok_three() {
        // bridge_threshold(4) = ceil(8/3) = 3. Three DISTINCT registered
        // Falcon-512 signers reach quorum: Ok(3).
        let (a, fa) = falcon_id(0xC0, 0xC0);
        let (b, fb) = falcon_id(0xC1, 0xC1);
        let (c, fc) = falcon_id(0xC2, 0xC2);
        let (d, _) = falcon_id(0xC3, 0xC3);
        let validators = vec![a, b, c, d];
        let msg = b"bridge falcon 3-of-4";
        let sigs = vec![fsig(&a, &fa, msg), fsig(&b, &fb, msg), fsig(&c, &fc, msg)];
        assert_eq!(
            verify_quorum_signatures(msg, &sigs, &validators),
            Ok(3),
            "3 distinct Falcon signers of 4 must reach quorum"
        );
    }

    #[test]
    fn falcon_quorum_two_of_four_is_refused() {
        // Two valid Falcon signatures of four (need 3) stay sub-quorum: Err.
        let (a, fa) = falcon_id(0xD0, 0xD0);
        let (b, fb) = falcon_id(0xD1, 0xD1);
        let (c, _) = falcon_id(0xD2, 0xD2);
        let (d, _) = falcon_id(0xD3, 0xD3);
        let validators = vec![a, b, c, d];
        let msg = b"bridge falcon 2-of-4";
        let sigs = vec![fsig(&a, &fa, msg), fsig(&b, &fb, msg)];
        assert!(
            verify_quorum_signatures(msg, &sigs, &validators).is_err(),
            "2 of 4 Falcon signers must not reach quorum"
        );
    }

    #[test]
    fn falcon_duplicate_signer_counts_once() {
        // n = 3 needs 2 DISTINCT. One signer twice = 1: Err, and the relayer
        // counts exactly 1.
        let (a, fa) = falcon_id(0xE0, 0xE0);
        let (b, _) = falcon_id(0xE1, 0xE1);
        let (c, _) = falcon_id(0xE2, 0xE2);
        let validators = vec![a, b, c];
        let msg = b"bridge falcon duplicate";
        let sigs = vec![fsig(&a, &fa, msg), fsig(&a, &fa, msg)];
        assert!(
            verify_quorum_signatures(msg, &sigs, &validators).is_err(),
            "a duplicated signer must not fake quorum"
        );
        let mut relayer = MultisigRelayer::new(validators);
        assert_eq!(
            relayer.count_signers(msg, &sigs),
            1,
            "a duplicated signer counts exactly once"
        );
        assert!(
            relayer.try_release([0xD0; 32], msg, &sigs).is_err(),
            "one distinct signer must not release (need 2)"
        );
    }

    #[test]
    fn falcon_unknown_key_is_refused_fail_closed() {
        // n = 4 needs 3. Three valid Falcon sigs PLUS one unregistered key:
        // a skip-unknown counter would report Ok(3); the fail-closed rule
        // refuses the whole bundle with Err.
        let (a, fa) = falcon_id(0xF0, 0xF0);
        let (b, fb) = falcon_id(0xF1, 0xF1);
        let (c, fc) = falcon_id(0xF2, 0xF2);
        let (d, _) = falcon_id(0xF3, 0xF3);
        let validators = vec![a, b, c, d];
        let msg = b"bridge falcon unknown";
        let stranger = SigningKey::from_bytes(&[0xEE; 32]);
        let mut sigs = vec![fsig(&a, &fa, msg), fsig(&b, &fb, msg), fsig(&c, &fc, msg)];
        sigs.push(sig(&stranger, msg));
        assert!(
            verify_quorum_signatures(msg, &sigs, &validators).is_err(),
            "an unregistered key in the bundle must refuse fail-closed"
        );
        // An outsider outside the validator set refuses even alone.
        let relayer = MultisigRelayer::new(validators);
        assert_eq!(
            relayer.count_signers(msg, &[sig(&stranger, msg)]),
            0,
            "outsider signatures count for nothing"
        );
    }

    #[test]
    fn falcon_ed_signature_never_counts() {
        // The id is REGISTERED with a Falcon-512 key, but the bundle carries
        // an Ed25519 signature (64 bytes) for it: Ed is identity only, so the
        // entry never verifies and quorum is not reached.
        let sk = SigningKey::from_bytes(&[0xB0; 32]);
        let id = sk.verifying_key().to_bytes();
        let fk = crate::post_quantum::FalconKeypair::generate_from_seed(0xB0);
        crate::consensus::register_validator_pq_key(
            id,
            crate::post_quantum::PqScheme::Falcon512,
            fk.public_key.clone(),
        );
        let (b, _) = falcon_id(0xB1, 0xB1);
        let (c, _) = falcon_id(0xB2, 0xB2);
        let validators = vec![id, b, c];
        let msg = b"bridge ed never counts";
        let sigs = vec![sig(&sk, msg)];
        assert!(
            verify_quorum_signatures(msg, &sigs, &validators).is_err(),
            "an Ed25519 signature must never count toward the Falcon quorum"
        );
    }

    // ----------------------------------------------------------------
    // BRIDGE-FIX-FULL (docs/specs/06 §1.3 / §2.1 / §2.2 / §2.3)
    // ----------------------------------------------------------------

    /// Thread-local gate override guard: always restores `GatedOff`.
    struct BridgeV2GateGuard;

    impl Drop for BridgeV2GateGuard {
        fn drop(&mut self) {
            set_bridge_v2_activation_override(None);
        }
    }

    fn receipt_fixture() -> ReleaseReceiptEvidence {
        ReleaseReceiptEvidence {
            req_id: 7,
            target_chain: SupportedChain::Ethereum,
            target_address: "0x00ff".to_string(),
            amount: 42,
            external_tx_hash: [0xAB; 32],
            finalized_head: 9_000,
            attestation_height: 500,
            signatures: vec![([1u8; 32], vec![2u8; 3])],
        }
    }

    #[test]
    fn bridge_v2_gate_is_active_at_genesis_and_override_is_honoured() {
        let _guard = BridgeV2GateGuard;
        // Default under Ruleset v7: `ActiveFromGenesis` (0).
        assert_eq!(
            effective_bridge_v2_activation_height(),
            BRIDGE_V2_ACTIVATION_HEIGHT
        );
        assert_eq!(BRIDGE_V2_ACTIVATION_HEIGHT, 0);
        assert!(bridge_v2_active_at(0));
        assert!(bridge_v2_active_at(u64::MAX - 1));
        assert!(bridge_v2_active_at(u64::MAX));
        // Explicit override: active from the boundary height onward.
        set_bridge_v2_activation_override(Some(100));
        assert!(!bridge_v2_active_at(99));
        assert!(bridge_v2_active_at(100));
        assert!(bridge_v2_active_at(101));
        // Overriding to u64::MAX gates it off everywhere (pre-v7 replay).
        set_bridge_v2_activation_override(Some(u64::MAX));
        assert!(!bridge_v2_active_at(0));
        assert!(!bridge_v2_active_at(u64::MAX));
        set_bridge_v2_activation_override(None);
        assert_eq!(
            effective_bridge_v2_activation_height(),
            BRIDGE_V2_ACTIVATION_HEIGHT
        );
    }

    #[test]
    fn release_receipt_preimage_has_pinned_domain_and_length() {
        let receipt = receipt_fixture();
        let msg = release_receipt_signing_message_v2(11, &receipt);
        assert_eq!(BRIDGE_RELEASE_RECEIPT_DOMAIN_V2.len(), 31);
        assert!(msg.starts_with(BRIDGE_RELEASE_RECEIPT_DOMAIN_V2));
        assert_eq!(
            msg.len(),
            BRIDGE_RELEASE_RECEIPT_DOMAIN_V2.len()
                + 8
                + 8
                + 1
                + 4
                + receipt.target_address.len()
                + 8
                + 32
                + 8
                + 8
        );
        // chain_id is bound: no cross-network replay.
        assert_ne!(msg, release_receipt_signing_message_v2(12, &receipt));
        // Every signed field moves the preimage.
        let mut other = receipt.clone();
        other.req_id += 1;
        assert_ne!(msg, release_receipt_signing_message_v2(11, &other));
        let mut other = receipt.clone();
        other.amount += 1;
        assert_ne!(msg, release_receipt_signing_message_v2(11, &other));
        let mut other = receipt.clone();
        other.external_tx_hash[0] ^= 0xFF;
        assert_ne!(msg, release_receipt_signing_message_v2(11, &other));
        let mut other = receipt.clone();
        other.finalized_head += 1;
        assert_ne!(msg, release_receipt_signing_message_v2(11, &other));
        let mut other = receipt.clone();
        other.attestation_height += 1;
        assert_ne!(msg, release_receipt_signing_message_v2(11, &other));
        let mut other = receipt.clone();
        other.target_address.push('x');
        assert_ne!(msg, release_receipt_signing_message_v2(11, &other));
        // Target-chain tag: no cross-chain transplant.
        let mut other = receipt.clone();
        other.target_chain = SupportedChain::Arbitrum;
        assert_ne!(msg, release_receipt_signing_message_v2(11, &other));
    }

    #[test]
    fn bridge_state_v3_upgrade_preserves_legacy_fields_and_starts_new_sets_empty() {
        let v3 = BridgeStateV3 {
            processed_source_txs: std::collections::BTreeSet::from([[0x11u8; 32]]),
            pending_withdrawals: std::collections::BTreeMap::from([(
                3,
                TeleportWithdrawalRequest {
                    req_id: 3,
                    sender: [0x22u8; 32],
                    target_chain: SupportedChain::Solana,
                    target_address: "So1ana".to_string(),
                    amount: 5_000,
                    requested_at: 10,
                    unlock_at: 20,
                    executed: true,
                },
            )]),
            next_withdrawal_id: 4,
            hourly_withdrawn: 123,
            last_rate_limit_reset: 9,
            escrow_balance: 77,
            hourly_deposited: 11,
            last_deposit_reset: 3,
            total_minted: 1_000,
            deposit_records: std::collections::BTreeMap::from([(
                [0x11u8; 32],
                DepositRecord {
                    recipient: [0x22u8; 32],
                    amount: 1_000,
                    chain: SupportedChain::Ton,
                    via_quorum: true,
                    deposited_at: 5,
                    disputed: false,
                },
            )]),
            next_dispute_id: 2,
            ..BridgeStateV3::default()
        };

        // The V3 layout IS the pre-fix `BridgeState` layout: it round-trips as
        // bytes and upgrades with the three new containers EMPTY.
        let bytes = bincode::serialize(&v3).expect("v3 serializes");
        let decoded: BridgeStateV3 = bincode::deserialize(&bytes).expect("v3 decodes");
        let upgraded = decoded.upgrade();
        assert_eq!(upgraded.processed_source_txs, v3.processed_source_txs);
        assert_eq!(upgraded.pending_withdrawals.len(), 1);
        assert!(upgraded.pending_withdrawals[&3].executed);
        assert_eq!(upgraded.next_withdrawal_id, 4);
        assert_eq!(upgraded.hourly_withdrawn, 123);
        assert_eq!(upgraded.last_rate_limit_reset, 9);
        assert_eq!(upgraded.escrow_balance, 77);
        assert_eq!(upgraded.hourly_deposited, 11);
        assert_eq!(upgraded.last_deposit_reset, 3);
        assert_eq!(upgraded.total_minted, 1_000);
        assert_eq!(upgraded.deposit_records.len(), 1);
        assert_eq!(upgraded.next_dispute_id, 2);
        // Fail-closed upgrade: no historical `executed = true` becomes a
        // verified payout receipt.
        assert!(upgraded.release_receipts.is_empty());
        assert!(upgraded.processed_payout_txs.is_empty());
        assert!(upgraded.refunded_withdrawals.is_empty());
        assert!(!upgraded.is_empty());
    }

    #[test]
    fn v2_bare_release_is_refused_and_sender_can_still_refund() {
        let _guard = BridgeV2GateGuard;
        set_bridge_v2_activation_override(Some(0));

        let sender = [0x51u8; 32];
        let outsider = [0x52u8; 32];
        let now = 1_760_000_000u64;
        let amount = 1_000_000_000u64;

        let state = BridgeState {
            next_withdrawal_id: 1,
            hourly_withdrawn: amount,
            pending_withdrawals: std::collections::BTreeMap::from([(
                0,
                TeleportWithdrawalRequest {
                    req_id: 0,
                    sender,
                    target_chain: SupportedChain::Ton,
                    target_address: "EQD4FPq-PRDieyQKkKZ085".to_string(),
                    amount,
                    requested_at: now,
                    unlock_at: now,
                    executed: false,
                },
            )]),
            ..BridgeState::default()
        };

        // P0 regression: an outsider's bare `Release` at `now >= unlock_at`
        // no longer destroys the sender's refund path.
        let err = state
            .plan_at_height(
                &[BridgeIntent::Release { req_id: 0 }],
                &[],
                outsider,
                now,
                0,
                11,
                &PreV2ConsensusLookup,
            )
            .expect_err("bare release must be refused at/after BRIDGE_V2_ACTIVATION_HEIGHT");
        assert!(
            err.contains("verified payout receipt required"),
            "unexpected refusal: {err}"
        );
        assert!(
            !state.pending_withdrawals[&0].executed,
            "a refused release must not mutate committed state"
        );

        // The sender still refunds at `unlock_at + REFUND_GRACE_SECS`.
        let refund_at = now + REFUND_GRACE_SECS;
        let refunded = state
            .plan_at_height(
                &[BridgeIntent::Refund { req_id: 0 }],
                &[],
                sender,
                refund_at,
                0,
                11,
                &PreV2ConsensusLookup,
            )
            .expect("the original sender must still be able to refund");
        assert!(refunded.state.pending_withdrawals.is_empty());
        assert!(refunded.state.refunded_withdrawals.contains(&0));
        assert_eq!(refunded.state.hourly_withdrawn, 0);
        assert_eq!(
            refunded.effects,
            vec![BridgeEffect::Unpark {
                recipient: sender,
                amount,
            }]
        );

        // A late payout proof after the refund fails loudly, not silently.
        let err = refunded
            .state
            .plan_at_height(
                &[BridgeIntent::Release { req_id: 0 }],
                &[],
                outsider,
                refund_at + 1,
                0,
                11,
                &PreV2ConsensusLookup,
            )
            .expect_err("a release after a refund must be refused");
        assert_eq!(err, "Withdrawal already refunded");
    }

    #[test]
    fn v2_lone_release_proof_is_inert() {
        let _guard = BridgeV2GateGuard;
        set_bridge_v2_activation_override(Some(0));
        let mut receipt = receipt_fixture();
        receipt.req_id = 9;
        let plan = BridgeState::default()
            .plan_at_height(
                &[BridgeIntent::ReleaseProof {
                    req_id: 9,
                    receipt: Box::new(receipt),
                }],
                &[],
                [0x60u8; 32],
                1_000,
                0,
                11,
                &PreV2ConsensusLookup,
            )
            .expect("a lone receipt authorizes nothing and must not fail");
        assert!(plan.effects.is_empty());
        assert!(plan.state.release_receipts.is_empty());
        assert!(plan.state.processed_payout_txs.is_empty());
    }
}
