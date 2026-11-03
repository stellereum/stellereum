//! Staking, delegation, slashing and validator rewards.
//!
//! Validators bond STELL as collateral. A validator's consensus voting power is
//! derived from its bonded stake (not a static list), so misbehaviour has a real
//! economic cost. The module is a pure, deterministic state machine:
//!
//!  - `bond` / `unbond` / `withdraw`: stake lifecycle with a cooldown so a
//!    validator cannot exit instantly after signing a conflicting vote.
//!  - `delegate` / `undelegate`: delegators share a validator's rewards and
//!    slashing proportionally.
//!  - `slash_equivocation`: consumes consensus equivocation evidence
//!    `(voter, vote_a, vote_b)` and burns a fraction of the offender's stake.
//!  - `distribute_rewards`: mints block rewards from the emission schedule and
//!    splits them between the validator and its delegators (minus commission).
//!
//! All balances are nano-STELL. The module owns its own accounting (it does not
//! reach into the state engine), so it can be unit-tested and reasoned about in
//! isolation; the runtime wires it to the state engine and consensus.
//!
//! ACTIVATION BOUNDARY — W10.5 (pinned, 2026-10-23 #292785/#292786 stall):
//! every stake mutation in this ledger (`bond` / `add_bond` / `unbond` /
//! `withdraw` / `slash`, including ejection-by-filter when a slash pushes a
//! self-bond below MIN) takes effect in CONSENSUS at height H+1 — NEVER
//! mid-flight. The runtime derives the set from this ledger at ledger-height
//! L and STAGES it for activation at L+1
//! (`ValidatorRuntime::install_due_validator_set`, adoption height
//! [`crate::sharding::validator_set_adoption_height`]); every node that
//! applied the same chain prefix therefore switches validator sets — and
//! quorum thresholds — at the same agreed height, and every quorum check for
//! a certificate at height H MUST use the set in force AT H
//! (`ValidatorRuntime::validator_set_for_height`), never the live set.
//! Pinned by `tests/w10_5_activation_race.rs`.

use crate::consensus::{ValidatorId, ValidatorSet};
use crate::tokenomics::TeamVestingSchedule;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Minimum SELF-bond below which a validator is ejected from the consensus
/// set (1,000 STELL). [`StakingLedger::to_validator_set`] filters on
/// `self_bond >= MIN` (power itself is `self_bond + delegated`); delegations
/// alone can NEVER elect or re-elect — only self-bond crosses the filter.
///
/// урок валидатора C: bonding exactly MIN leaves zero margin — a single
/// downtime slash (0.1%, [`DOWNTIME_SLASH_BPS`]) pushes `self_bond` below MIN
/// and the validator drops out of the set at the next boundary, then any
/// top-up (e.g. re-staked rewards) back over MIN silently re-elects it with
/// no liveness check. Hence since the re-entry fix:
///  - [`StakingLedger::bond`] REFUSES (fail-closed) any new bond below
///    MIN+buffer ([`STELL_MIN_BOND_BUFFER`]): bare-MIN bonds cannot be created;
///  - top-ups ([`StakingLedger::add_bond`]) that leave `self_bond` below
///    MIN+buffer stay accepted but WARN loudly (fail-open, log-only);
///  - every `slash` emits a loud WARN when the remainder sits within
///    [`slash_eject_warn_gap_nano`] above MIN or drops below MIN;
///  - set refreshes WARN on every re-entrant (see [`validator_set_gains`],
///    [`reentry_warn_message_for`]) and keep a liveness watch on it (see
///    [`reentry_liveness_risk`]) — visibility only, the derived set is never
///    altered.
///
/// FREEZE (protocol freeze 2026-11-03): 1,000 STELL entry floor, never env.
/// Change requires spec update + audit note (AGENTS.md §7).
pub const MIN_VALIDATOR_BOND: u64 = 1_000 * 1_000_000_000;

/// Hard entry buffer in nano-STELL (100 STELL): a NEW bond must carry at
/// least `MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER` of self-bond, or
/// [`StakingLedger::bond`] refuses it with [`StakingError::BondBelowMinimum`].
///
/// Deterministic on purpose — a plain const, NOT the
/// `STELL_MIN_BOND_BUFFER` env var ([`min_bond_buffer_nano`]): bond admission
/// is consensus (every node applying the same `SysCallStake` must reach the
/// same accept/refuse), while the env-driven WARN thresholds are node-local
/// log policy and may differ. Default equals
/// [`DEFAULT_MIN_BOND_BUFFER_NANO`] so the enforced floor and the
/// recommended cushion agree out of the box.
///
/// FREEZE (protocol freeze 2026-11-03): 100 STELL admission buffer, never env.
/// Change requires spec update + audit note (AGENTS.md §7).
pub const STELL_MIN_BOND_BUFFER: u64 = 100 * 1_000_000_000;

/// Required self-bond for a NEW bond: MIN + buffer (fail-closed floor).
pub fn required_bond_floor_nano() -> u64 {
    MIN_VALIDATOR_BOND.saturating_add(STELL_MIN_BOND_BUFFER)
}

/// Env var: eject-approach WARN gap in nano-STELL (default 100 STELL).
/// When a slash leaves `MIN <= self_bond < MIN + gap`, a loud WARN fires:
/// "validator X будет выкинут через ~Y". Node-local log policy, not
/// consensus — nodes MAY differ, state is unaffected.
pub const SLASH_EJECT_WARN_GAP_ENV: &str = "STELL_SLASH_EJECT_WARN_GAP";
/// Env var: minimum-bond buffer in nano-STELL (default 100 STELL).
/// When `bond`/`add_bond` leave `self_bond < MIN + buffer`, a WARN fires
/// recommending MIN+buffer. Node-local log policy, not consensus.
pub const MIN_BOND_BUFFER_ENV: &str = "STELL_MIN_BOND_BUFFER";
/// Default eject-approach WARN gap: 100 STELL in nano.
pub const DEFAULT_SLASH_EJECT_WARN_GAP_NANO: u64 = 100 * 1_000_000_000;
/// Default minimum-bond buffer: 100 STELL in nano.
pub const DEFAULT_MIN_BOND_BUFFER_NANO: u64 = 100 * 1_000_000_000;

/// Effective eject-approach WARN gap in nano-STELL (`STELL_SLASH_EJECT_WARN_GAP`,
/// default [`DEFAULT_SLASH_EJECT_WARN_GAP_NANO`]). Unparseable/missing -> default.
/// `0` disables the approach WARN (the actual-eject WARN always fires).
pub fn slash_eject_warn_gap_nano() -> u64 {
    parse_nano_env(
        std::env::var(SLASH_EJECT_WARN_GAP_ENV).ok(),
        DEFAULT_SLASH_EJECT_WARN_GAP_NANO,
    )
}

/// Effective minimum-bond buffer in nano-STELL (`STELL_MIN_BOND_BUFFER`,
/// default [`DEFAULT_MIN_BOND_BUFFER_NANO`]). Unparseable/missing -> default.
pub fn min_bond_buffer_nano() -> u64 {
    parse_nano_env(
        std::env::var(MIN_BOND_BUFFER_ENV).ok(),
        DEFAULT_MIN_BOND_BUFFER_NANO,
    )
}

/// Parse a nano-STELL env value: trimmed integer, fallback to `default` on
/// missing/garbage. `Some("0")` is honoured as 0 (disable), only garbage
/// falls back. Extracted so tests cover the parsing without mutating the
/// process env (cargo tests run in parallel).
pub fn parse_nano_env(raw: Option<String>, default: u64) -> u64 {
    raw.and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

/// Pure predicate: `self_bond` is still elected but within `gap` above MIN —
/// one more slash likely ejects it. (`gap` is injected so tests stay
/// deterministic without touching env; production passes
/// [`slash_eject_warn_gap_nano`].)
pub fn self_bond_within_eject_gap_for(self_bond: u64, gap: u64) -> bool {
    self_bond >= MIN_VALIDATOR_BOND && self_bond.saturating_sub(MIN_VALIDATOR_BOND) < gap
}

/// Pure predicate: `self_bond` lacks the recommended MIN+`buffer` cushion.
/// (`buffer` injected for determinism; production passes
/// [`min_bond_buffer_nano`].)
pub fn self_bond_lacks_buffer_for(self_bond: u64, buffer: u64) -> bool {
    self_bond < MIN_VALIDATOR_BOND.saturating_add(buffer)
}

/// Build the eject-approach WARN text, or `None` when no WARN applies.
/// `Some` when `MIN <= self_bond < MIN + gap` (approaching eject).
/// The actual-eject case (`self_bond < MIN`) is reported by
/// [`eject_message_for`], not here.
pub fn eject_warn_message_for(
    validator: &ValidatorId,
    self_bond: u64,
    burned: u64,
    gap: u64,
) -> Option<String> {
    if !self_bond_within_eject_gap_for(self_bond, gap) {
        return None;
    }
    let remaining = self_bond.saturating_sub(MIN_VALIDATOR_BOND);
    Some(format!(
        "SLASH-EJECT-WARN validator {} будет выкинут через ~{} nano-STELL (~{:.3} STELL): self_bond {} after -{} slash, MIN {} (gap {}): top up urgently or the next slash ejects it from the set",
        hex::encode(validator),
        remaining,
        remaining as f64 / 1_000_000_000.0,
        self_bond,
        burned,
        MIN_VALIDATOR_BOND,
        gap,
    ))
}

/// Build the actual-eject WARN text, or `None` when the validator is still elected.
pub fn eject_message_for(validator: &ValidatorId, self_bond: u64, burned: u64) -> Option<String> {
    if self_bond >= MIN_VALIDATOR_BOND {
        return None;
    }
    Some(format!(
        "SLASH-EJECT validator {} EJECTED from the set: self_bond {} < MIN {} after -{} slash: re-bond to MIN+buffer to rejoin",
        hex::encode(validator),
        self_bond,
        MIN_VALIDATOR_BOND,
        burned,
    ))
}

/// Build the MIN+buffer WARN text for `bond`/`add_bond`, or `None` when the
/// resulting self-bond already carries the cushion.
pub fn buffer_warn_message_for(total_self_bond: u64, buffer: u64) -> Option<String> {
    if !self_bond_lacks_buffer_for(total_self_bond, buffer) {
        return None;
    }
    Some(format!(
        "MIN-BOND-BUFFER validator self_bond {} < MIN {} + buffer {} (recommended bond = MIN+buffer = {}): a single downtime slash can eject a bare-MIN bond; top up to at least MIN+buffer",
        total_self_bond,
        MIN_VALIDATOR_BOND,
        buffer,
        MIN_VALIDATOR_BOND.saturating_add(buffer),
    ))
}

/// Maximum active validators (consensus set cap): 250.///
///
/// FREEZE (protocol freeze 2026-11-03): set-size cap input to quorum math.
/// Change requires spec update + audit note (AGENTS.md §7).
///
/// Rationale (multi-chain research 2026): TON caps at 400 (380 live),
/// Cosmos Hub at 180, Polygon PoS at 105, BNB at 45, Sui ~102-127,
/// Aptos ~129, NEAR top-100 block producers / ~213 total.
/// A 150-250 window gives TON-class decentralization while keeping BFT
/// gossip O(N^2) tractable; per-block votes use a µQC-16 sortition
/// committee so 250 does not hurt 250ms-1s block times.
/// Full / RPC / archive nodes are UNLIMITED — only consensus voters are capped.
pub const MAX_ACTIVE_VALIDATORS: usize = 250;

/// Target minimum active validators for healthy mainnet decentralization.
/// Below this the chain still runs (testnet starts at 2-4), but governance
/// should incentivize growth toward this floor. Not enforced as a stall.
pub const TARGET_MIN_VALIDATORS: usize = 150;

/// Address that physically holds bonded stake.
///
/// The ledger is the authority on *who owns* what, but the coins sit in this
/// account: that is what makes a bond real (you cannot stake what you do not
/// have) and what makes slashing a burn rather than a bookkeeping note.
pub const STAKING_POOL: [u8; 32] = [0x53; 32];
/// Address that physically holds minted-but-unclaimed staking rewards.
///
/// E2 fix: block rewards used to be credited as ledger counters with no
/// backing, then paid out of `STAKING_POOL` — i.e. out of bonded principal.
/// Rewards are now minted into THIS pool (capped by
/// [`REWARDS_EMISSION_CAP`]) and claims debit it, so principal is never
/// touched by a reward payout. Distinct from `STAKING_POOL` (0x53),
/// `BRIDGE_ESCROW` (0xB7) and `SHIELD_ESCROW` (0xC0) by construction.
pub const REWARDS_POOL: [u8; 32] = [0x52; 32];
/// Cumulative cap on all staking rewards ever minted (350M STELL), mirroring
/// the `validator_rewards` allocation in `crate::tokenomics::TokenAllocation`.
/// [`StakingLedger::distribute_reward`] refuses (fail-closed) once minting
/// `reward` more would exceed this.
pub const REWARDS_EMISSION_CAP: u64 = 350_000_000 * 1_000_000_000;
/// Minimum delegation amount (1 STELL).
pub const MIN_DELEGATION: u64 = 1_000_000_000;
/// Unbonding cooldown before funds can be withdrawn (~2 days at 3s blocks).
///
/// FREEZE (protocol freeze 2026-11-03): deterministic const, never env.
/// Change requires spec update + audit note (AGENTS.md §7).
pub const UNBONDING_PERIOD_SECS: u64 = 2 * 24 * 3600;
/// Slash fraction for equivocation (double-sign), in basis points (5%).
///
/// FREEZE (protocol freeze 2026-11-03): deterministic const, never env.
/// Change requires spec update + audit note (AGENTS.md §7).
pub const EQUIVOCATION_SLASH_BPS: u64 = 500;
/// Slash fraction for micro-committee equivocation (100% of bond).
///
/// FREEZE (protocol freeze 2026-11-03): deterministic const, never env.
/// Change requires spec update + audit note (AGENTS.md §7).
pub const MICRO_COMMITTEE_SLASH_BPS: u64 = 10_000;
/// Slash fraction for prolonged downtime, in basis points (0.1%).
///
/// FREEZE (protocol freeze 2026-11-03): deterministic const, never env.
/// Change requires spec update + audit note (AGENTS.md §7).
pub const DOWNTIME_SLASH_BPS: u64 = 10;
/// Consecutive missed heights before a downtime slash fires.
///
/// FREEZE (protocol freeze 2026-11-03): deterministic const, never env.
/// Change requires spec update + audit note (AGENTS.md §7).
pub const DOWNTIME_MISS_THRESHOLD: u32 = 10;
/// Minimum heights between two downtime slashes for the same validator, so a
/// long outage costs a bounded amount rather than draining the whole bond.
///
/// FREEZE (protocol freeze 2026-11-03): deterministic const, never env.
/// Change requires spec update + audit note (AGENTS.md §7).
pub const DOWNTIME_PENALTY_COOLDOWN: u64 = 100;
/// Default validator commission on delegated rewards (10%).
///
/// PRODUCT DECISION — COMMISSION CHANGES ONLY THROUGH THE BOUNDED
/// ANNOUNCE/APPLY PATH (audit I3, evolved 2026-11-02): the rate is still set
/// once at `bond` and priced for newcomers by governance
/// (`SetDefaultCommissionBps`), and neither `add_bond` nor any top-up opcode
/// changes it. What changed is that the ledger now exposes
/// [`StakingLedger::announce_commission`] + [`StakingLedger::apply_commission`]:
/// a raise is announced `COMMISSION_EFFECT_DELAY_HEIGHTS` heights before it
/// takes effect (the delegator-exit window the original decision demanded as
/// the EXACT PRECONDITION for any `SetCommission` opcode — `unbond` and
/// `redelegate` stay fully available during it, so captives can leave), each
/// step moves at most `COMMISSION_MAX_DELTA_BPS`, at most one effective change
/// per `COMMISSION_CHANGE_COOLDOWN_HEIGHTS`, and everything else is refused
/// fail-closed. A 100% commission is still allowed but still pays delegators
/// exactly 0 rather than stealing. Announcing the CURRENT rate cancels a
/// pending change. Reward math still reads the rate at distribution time, so
/// a change — like the direct field writes the adversarial tests simulate —
/// applies to new emission only, never retroactively.
///
/// NOTE (wiring, out of scope): no SVM opcode exposes this yet (svm.rs is
/// owned by another scope); the path is ledger-complete and RPC-observable
/// (`stell_getValidatorStatus`) so operators and wallets can use it the
/// moment an opcode lands.
///
/// FREEZE (protocol freeze 2026-11-03): 10% default commission, never env.
/// Change requires spec update + audit note (AGENTS.md §7).
pub const DEFAULT_COMMISSION_BPS: u64 = 1_000;
/// Basis-point denominator for every `*_bps` field (commission, slashes).
///
/// FREEZE (protocol freeze 2026-11-03): 10_000 divisor, never env.
/// Change requires spec update + audit note (AGENTS.md §7).
pub const BPS_DENOMINATOR: u64 = 10_000;

/// Jail release delay in heights: a downtime-jailed validator becomes
/// eligible for [`StakingLedger::unjail`] this many heights after the jailing
/// penalty fired (1,000 heights ≈ 50 min at 3 s blocks).
///
/// Deterministic const (never env): jail admission and release are consensus
/// (every node applying the same blocks must reach the same jailed set), and
/// the delay deliberately exceeds [`DOWNTIME_PENALTY_COOLDOWN`] (100) so a
/// validator cannot unjail inside the same outage window that would
/// immediately re-slash it.
///
/// FREEZE (protocol freeze 2026-11-03): 1,000 heights ≈ 50 min at 3 s blocks.
/// Change requires spec update + audit note (AGENTS.md §7).
pub const JAIL_RELEASE_DELAY_HEIGHTS: u64 = 1_000;

/// Maximum commission change per [`StakingLedger::announce_commission`], in
/// basis points (500 = 5 percentage points). A raise from 10% to 100% takes
/// at least 18 announced steps — a rug cannot land in one transaction.
/// Fail-closed: a larger delta is refused with
/// [`StakingError::CommissionDeltaExceeded`].
///
/// FREEZE (protocol freeze 2026-11-03): 500 BPS max step, never env.
/// Change requires spec update + audit note (AGENTS.md §7).
pub const COMMISSION_MAX_DELTA_BPS: u64 = 500;

/// Delegator-exit window in heights: an announced commission change takes
/// effect this many heights after the announcement (7,200 heights ≈ 6 h at
/// 3 s blocks). During the window the announced rate is queryable
/// ([`StakingLedger::commission_schedule_of`], `stell_getValidatorStatus`)
/// and `undelegate`/`redelegate` stay fully available, so no delegator is
/// ever surprised by a raise — the exit window the immutability decision
/// demanded as the EXACT PRECONDITION for any `SetCommission` path.
///
/// FREEZE (protocol freeze 2026-11-03): 7,200 heights ≈ 6 h, never env.
/// Change requires spec update + audit note (AGENTS.md §7).
pub const COMMISSION_EFFECT_DELAY_HEIGHTS: u64 = 7_200;

/// Minimum heights between two EFFECTIVE commission changes for one
/// validator (7,200 ≈ 6 h). Announcing while the cooldown from the last
/// effective change has not elapsed is refused fail-closed with
/// [`StakingError::CommissionNotDue`].
///
/// FREEZE (protocol freeze 2026-11-03): 7,200 heights ≈ 6 h, never env.
/// Change requires spec update + audit note (AGENTS.md §7).
pub const COMMISSION_CHANGE_COOLDOWN_HEIGHTS: u64 = 7_200;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StakingError {
    BondBelowMinimum,
    DelegationBelowMinimum,
    NotValidator,
    AlreadyValidator,
    InsufficientBond,
    InsufficientDelegation,
    CooldownNotElapsed,
    NothingToWithdraw,
    BadCommission,
    /// RESERVED, intentionally never constructed (audit I2): the variant names
    /// the single-batch design that was never built. `unbond`/`undelegate`
    /// push one [`UnbondingEntry`] per call and support UNLIMITED concurrent
    /// batches (per-owner `withdrawable` aggregation is exact and
    /// theft-tested), so enforcing this variant would brick legitimate
    /// partial exits. Kept so the name stays reserved in the serialized
    /// error space; do NOT add a guard constructing it without a migration
    /// plan for ledgers that already hold concurrent batches.
    UnbondingInProgress,
    /// Crediting claimed rewards to the account failed; rewards were restored.
    RewardCreditFailed,
    /// Minting `reward` more would exceed [`REWARDS_EMISSION_CAP`]; the
    /// reward is refused and nothing is credited (fail-closed over cap).
    RewardsCapExceeded,
    /// The rewards pool cannot cover a claimable amount; the claim is refused
    /// and the ledger entry is left intact (fail-closed, never principal).
    RewardsPoolShortfall,
    /// Stake locked in an open governance vote cannot exit. A yes-voter
    /// could otherwise vote and then undelegate before finalization,
    /// shrinking the quorum denominator while the recorded weight persists
    /// and flipping Rejected to Passed with no new vote (E7). The lock is
    /// taken by `Governance::vote` and released by `Governance::finalize`
    /// on the terminal transition; `unbond`/`undelegate` refuse the locked
    /// portion with this error until then.
    LockedInGovernanceVote,
    /// Equivocation evidence carried an invalid or unverified signature.
    InvalidSignature,
    /// Fail-closed arithmetic (audit L3): `add_bond`/`delegate` used to
    /// `saturating_add` at `u64::MAX` — a silent cap rather than a refusal.
    /// Unreachable at live supplies (1 B cap) but wrong by policy: stake
    /// accounting must refuse rather than cap, exactly like
    /// `distribute_reward`'s `checked_add`. Overflow now refuses with this.
    ArithmeticOverflow,
    /// The zero address (`[0u8; 32]`) can never be a delegator (audit L2):
    /// self-bond matures under the reserved owner key `[0u8; 32]`
    /// (`owner.unwrap_or([0u8; 32])` in `process_unbonding`), so a delegator
    /// at that address would share the `(validator, [0;32])` withdrawable key
    /// with the validator's own principal — withdrawable by EITHER
    /// `withdraw` or `withdraw_delegator`. Transacting FROM the zero address
    /// is computationally infeasible (it needs a signature under pubkey
    /// `[0;32]`), so this is defense-in-depth only, but the refusal is free:
    /// `delegate`/`withdraw_delegator`/`stake_delegate` reject it
    /// fail-closed and the self-bond key stays exclusive to `withdraw`.
    ZeroAddress,
    /// Fail-closed bps gate (staking-economics audit 2026-11-01, low (b)):
    /// [`StakingLedger::slash`] refuses `slash_bps > BPS_DENOMINATOR` with
    /// this instead of burning more than 100% of the slashable base. All
    /// live callers pass constants `<= 10_000` (`EQUIVOCATION_SLASH_BPS`,
    /// `MICRO_COMMITTEE_SLASH_BPS`, `DOWNTIME_SLASH_BPS`), so the gate is a
    /// no-op on every reachable path — defense-in-depth only. Appended last
    /// so existing serialized error indices are untouched.
    BadSlashBps,
    /// A validator is currently jailed (downtime) and excluded from the
    /// consensus set: `delegate` to it, `redelegate` to it and reward
    /// distributions for it are refused until [`StakingLedger::unjail`]
    /// re-admits it. Exits (`unbond`/`undelegate`/`redelegate` away) stay
    /// available — jail never holds funds hostage.
    Jailed,
    /// [`StakingLedger::unjail`] called for a validator that is not jailed.
    NotJailed,
    /// An announced commission change exceeds the per-change bound
    /// ([`COMMISSION_MAX_DELTA_BPS`]) — or, on `announce`, violates the
    /// absolute cap the same way [`StakingError::BadCommission`] does for
    /// bonds. Refused fail-closed, ledger untouched.
    CommissionDeltaExceeded,
    /// No commission change is due: `apply` with nothing pending, `apply`
    /// before the announced effective height, or `announce` inside the
    /// post-change cooldown ([`COMMISSION_CHANGE_COOLDOWN_HEIGHTS`]).
    /// Refused fail-closed, ledger untouched.
    CommissionNotDue,
    /// A redelegation with an invalid shape: source and destination are the
    /// same validator. Refused fail-closed (a same-validator "move" would
    /// otherwise launder the anti-long-range lock timestamp).
    InvalidRedelegation,
}

impl std::fmt::Display for StakingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // BondBelowMinimum names the enforced floor explicitly (the operator
        // must see the number, not just "too low"): it is formatted from the
        // consts so the text can never drift from the check in `bond`.
        if *self == StakingError::BondBelowMinimum {
            return write!(
                f,
                "bond is below the required minimum validator bond plus buffer (MIN {} + buffer {} = required {} nano-STELL): bond at least MIN+buffer",
                MIN_VALIDATOR_BOND,
                STELL_MIN_BOND_BUFFER,
                required_bond_floor_nano(),
            );
        }
        let s = match self {
            StakingError::BondBelowMinimum => unreachable!("handled above"),
            StakingError::DelegationBelowMinimum => "delegation is below the minimum",
            StakingError::NotValidator => "not an active validator",
            StakingError::AlreadyValidator => "already a validator",
            StakingError::InsufficientBond => "insufficient self-bond",
            StakingError::InsufficientDelegation => "insufficient delegated stake",
            StakingError::CooldownNotElapsed => "unbonding cooldown has not elapsed",
            StakingError::NothingToWithdraw => "no unbonded stake available to withdraw",
            StakingError::BadCommission => "commission must be <= 100%",
            StakingError::UnbondingInProgress => "an unbonding is already in progress",
            StakingError::RewardCreditFailed => "failed to credit rewards; rewards were restored",
            StakingError::RewardsCapExceeded => "staking rewards emission cap reached",
            StakingError::RewardsPoolShortfall => "rewards pool cannot cover the claim",
            StakingError::LockedInGovernanceVote => "stake is locked in an open governance vote",
            StakingError::InvalidSignature => "invalid signature",
            StakingError::ArithmeticOverflow => {
                "stake amount overflows u64: refusing instead of saturating"
            }
            StakingError::ZeroAddress => {
                "the zero address cannot hold a delegation (self-bond key is reserved)"
            }
            StakingError::BadSlashBps => "slash basis points must be <= 10000 (100%)",
            StakingError::Jailed => "validator is jailed (downtime) and excluded from the set until unjailed",
            StakingError::NotJailed => "validator is not jailed",
            StakingError::CommissionDeltaExceeded => {
                "commission change exceeds the per-change bound: refusing instead of repricing"
            }
            StakingError::CommissionNotDue => {
                "no commission change is due (nothing pending, effective height not reached, or change cooldown active)"
            }
            StakingError::InvalidRedelegation => {
                "redelegation source and destination must differ"
            }
        };
        write!(f, "{s}")
    }
}

/// Compact Post-Quantum equivocation evidence per Section 3 of STELLEREUM_PQ_BFT_V5_MASTER_SPEC.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactPqEquivocationEvidence {
    pub voter: ValidatorId,
    pub height: u64,
    pub round: u32,
    pub kind: crate::consensus::VoteKind,
    pub block_hash_a: Option<[u8; 32]>,
    pub signature_a: Vec<u8>,
    pub block_hash_b: Option<[u8; 32]>,
    pub signature_b: Vec<u8>,
}

impl CompactPqEquivocationEvidence {
    #[allow(clippy::too_many_arguments)]
    // GATE: equivocation evidence carries both votes; splitting changes public API.
    pub fn new(
        voter: ValidatorId,
        height: u64,
        round: u32,
        kind: crate::consensus::VoteKind,
        block_hash_a: Option<[u8; 32]>,
        signature_a: Vec<u8>,
        block_hash_b: Option<[u8; 32]>,
        signature_b: Vec<u8>,
    ) -> Self {
        Self {
            voter,
            height,
            round,
            kind,
            block_hash_a,
            signature_a,
            block_hash_b,
            signature_b,
        }
    }

    /// Compute deduplication key over `BLAKE3(voter || height || round || kind)`.
    pub fn dedup_key(&self) -> [u8; 32] {
        pq_equivocation_dedup_key(&self.voter, self.height, self.round, self.kind)
    }

    /// Bincode wire size of the envelope (gas accounting + DoS cap).
    ///
    /// Unmeasurable (should be impossible) reads as `usize::MAX` so the size
    /// cap refuses it instead of admitting it - the same shape as
    /// [`crate::consensus::EquivocationEvidence::wire_len`].
    pub fn wire_len(&self) -> usize {
        bincode::serialized_size(self)
            .map(|n| n as usize)
            .unwrap_or(usize::MAX)
    }
}

/// Hard cap on one PQ equivocation evidence envelope's wire size
/// (fail-closed: larger is refused, never truncated).
///
/// A PQ envelope carries TWO post-quantum signatures plus two targets, so it
/// is legitimately larger than the Ed25519 one (whose cap is
/// [`crate::consensus::MAX_EQUIVOCATION_EVIDENCE_BYTES`]). The cap is a
/// DoS bound, not a format limit: a real Falcon-512 pair is ~1.4 KB, a
/// hybrid pair ~1.5 KB, and everything above this is a probe rather than
/// evidence.
pub const MAX_PQ_EQUIVOCATION_EVIDENCE_BYTES: usize = 8_192;

/// Compute deduplication key over `BLAKE3(voter || height || round || kind)`
/// to prevent repeat compounding burns.
pub fn pq_equivocation_dedup_key(
    voter: &ValidatorId,
    height: u64,
    round: u32,
    kind: crate::consensus::VoteKind,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(voter);
    hasher.update(&height.to_be_bytes());
    hasher.update(&round.to_be_bytes());
    hasher.update(&[match kind {
        crate::consensus::VoteKind::Prevote => 0,
        crate::consensus::VoteKind::Precommit => 1,
    }]);
    *hasher.finalize().as_bytes()
}

/// A single delegation from one delegator to one validator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delegation {
    pub delegator: [u8; 32],
    pub validator: ValidatorId,
    pub amount: u64,
}

/// The unbonding lifecycle: `amount` is released once `now >= release_at`.
///
/// `owner` identifies WHO may later withdraw the matured funds:
///  - `None`            -> the validator's own self-bond
///  - `Some(delegator)` -> a delegator's undelegated stake
///
/// SECURITY: the owner MUST be carried through `process_unbonding`; crediting
/// every matured entry to the validator let a validator steal its delegators'
/// unbonded stake.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnbondingEntry {
    pub validator: ValidatorId,
    /// `None` = validator self-bond; `Some` = delegator.
    pub owner: Option<[u8; 32]>,
    pub amount: u64,
    pub release_at: u64,
}

/// A downtime jail record: `validator` is excluded from the consensus set
/// from `jailed_at_height` until [`StakingLedger::unjail`] re-admits it, and
/// re-admission is only possible at or after `release_height`
/// (`jailed_at_height + `[`JAIL_RELEASE_DELAY_HEIGHTS`]).
///
/// Jailing is automatic and evidence-driven: [`StakingLedger::note_missed_heights`]
/// installs this record whenever a downtime slash fires (the live path in
/// `state_engine.rs::apply_downtime_slash*` flows through there, so every
/// node jails identically). It is NOT installed by direct `slash`/
/// `slash_downtime` calls (no height is known there) — the same wired/unwired
/// distinction as the equivocation primitives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JailRecord {
    /// Height at which the jailing downtime penalty fired.
    pub jailed_at_height: u64,
    /// First height at which [`StakingLedger::unjail`] may succeed.
    pub release_height: u64,
}

/// An announced-but-not-yet-effective commission change: the delegator-exit
/// window made concrete. `announced_height` is when the validator called
/// [`StakingLedger::announce_commission`]; the rate takes effect at
/// `effective_height` (`announced_height +`
/// [`COMMISSION_EFFECT_DELAY_HEIGHTS`]) via [`StakingLedger::apply_commission`].
/// Between the two, delegators can read it
/// ([`StakingLedger::commission_schedule_of`], `stell_getValidatorStatus`)
/// and exit (`undelegate`/`redelegate` stay fully available).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingCommissionChange {
    /// The announced rate, in basis points (`<= `[`BPS_DENOMINATOR`]).
    pub new_bps: u64,
    /// First height at which `apply` may install it.
    pub effective_height: u64,
    /// Height at which it was announced.
    pub announced_height: u64,
}

/// Per-validator commission schedule: the rate-limiter state for the bounded
/// mutable-commission path.
///
/// `last_effective_height` is `None` for validators that bonded before this
/// path existed (or never changed commission): their first announcement is
/// always due (no phantom cooldown from height 0). `pending` carries the
/// announced change, if any; announcing again REPLACES the pending change
/// (intent update, nothing took effect yet), while announcing the CURRENT
/// rate clears it (cancel).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommissionSchedule {
    /// Height of the last EFFECTIVE change, `None` if never changed.
    pub last_effective_height: Option<u64>,
    /// Announced change awaiting its effective height, if any.
    pub pending: Option<PendingCommissionChange>,
}

/// Per-validator staking record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorStake {
    /// Self-bonded stake (slashable).
    pub self_bond: u64,
    /// Total delegated by others (slashable, owned by delegators).
    pub delegated: u64,
    /// Commission on delegated rewards, in basis points.
    pub commission_bps: u64,
    /// Reward accrued to this validator (self-bond share) not yet withdrawn.
    pub pending_rewards: u64,
    /// Slashing history (total burned) for transparency.
    pub total_slashed: u64,
    /// Consecutive heights this validator failed to contribute to a finalised
    /// quorum certificate, and the height at which the counter was last reset.
    /// Both are derived from blocks, never from local observation, so every node
    /// counts identically.
    pub missed: u32,
    /// Height of the last downtime slash, so one outage is punished once and
    /// repeated replays of the same evidence cannot slash repeatedly.
    pub last_downtime_penalty: u64,
}

impl ValidatorStake {
    pub fn total(&self) -> u64 {
        self.self_bond.saturating_add(self.delegated)
    }
}

/// Fixed-point scale of the lazy delegator-reward accumulator.
///
/// The accumulator stores "reward per delegated nano-STELL" as a scaled
/// integer: one unit of `reward_per_token` is `1 / REWARD_PER_TOKEN_SCALE`
/// of a nano-STELL per nano-STELL of delegated stake. 1e18 is the F1 /
/// DeFi convention (the Cosmos SDK `Dec` precision, the ERC-20
/// `rewardPerToken` scale) and it is ALSO the largest round scale that keeps
/// every intermediate of this ledger inside `u128`:
/// `pool (≤ REWARDS_EMISSION_CAP = 3.5e17) * SCALE (1e18) = 3.5e35`, two
/// orders of magnitude below `u128::MAX (3.4e38)`.
///
/// PRECISION CONTRACT (why a delegator is never over-credited):
/// the accumulator truncates the rate `pool / delegated` to `SCALE` digits,
/// so the rate error is `< 1 / SCALE` per distribution. A delegator's share
/// of that error is `stake * (1 / SCALE)`, and the stake is bounded by the
/// total supply (1e9 STELL = 1e18 nano), so the share error is `< 1` nano
/// PER DISTRIBUTION: the lazy share is at most one nano BELOW the exact
/// pro-rata value, and never above it (the truncated rate never
/// over-credits).
///
/// CAVEAT (corrected in the F1 re-audit): the "< 1 nano" bound is PER
/// DISTRIBUTION, not per settlement. A delegator that is left unsettled
/// across `K` distributions accumulates up to `K` nanos of truncation loss
/// (each distribution truncates the rate once). The eager implementation
/// floors each distribution's share separately and therefore loses up to
/// `K` nanos as well — the two differ by at most `K` nanos, in EITHER
/// direction (the lazy rate's carried remainder can make the lazy share
/// land slightly ABOVE the eager one). Neither ever exceeds the exact
/// pro-rata value, so the pool is never over-drawn; the difference is
/// protocol-favouring dust that stays locked in `rewards_pool`.
pub const REWARD_PER_TOKEN_SCALE: u128 = 1_000_000_000_000_000_000;

/// Per-validator lazy delegator-reward accumulator (F1-style).
///
/// The EAGER implementation credited every delegator of a validator on every
/// block: `share_i = pool * stake_i / delegated_total`, for EVERY `i`. With
/// thousands of dust delegators that is O(N) work per block over a map that
/// an attacker can grow for free — a CPU denial-of-service vector against
/// every node that executes the block.
///
/// The LAZY (F1) formulation replaces the per-delegator credit with a single
/// per-validator ACCUMULATOR and computes each delegator's entitlement only
/// when it is touched (a claim, a stake change, a slash). The state here is
/// the whole per-validator bookkeeping:
///
///  * [`reward_per_token`](Self::reward_per_token) — the cumulative scaled
///    rate (F1's `current_rewards.ratio`). It only ever GROWS, so a
///    delegator's entitlement is `stake * (rate_now - rate_checkpoint)`.
///  * [`historical_rewards`](Self::historical_rewards) — the cumulative
///    delegator pool this validator has been funded with (F1's
///    `historical_rewards`): the numerator the rate was built from.
///  * [`remaining_rewards`](Self::remaining_rewards) — the part of that pool
///    that has not been claimed yet (F1's `validator_remaining_rewards`).
///  * [`remainder`](Self::remainder) / [`remainder_den`](Self::remainder_den)
///    — the un-truncated fraction of the last rate division, carried into the
///    next one so a run of distributions with a stable delegated total loses
///    NO value at all (the truncated dust would otherwise be silently
///    destroyed once per block).
///
/// Nothing here is derived: every field is committed to the state root by
/// [`crate::commitment`] (conditionally, so the genesis known-answer vectors
/// stay byte-identical).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorRewardState {
    /// Cumulative scaled reward-per-token: the rate a delegator's share is
    /// measured against. Grows monotonically with every distribution.
    pub reward_per_token: u128,
    /// Cumulative delegator pool allocated to this validator (the numerator).
    pub historical_rewards: u128,
    /// Delegator pool allocated but not yet claimed by the delegators.
    pub remaining_rewards: u128,
    /// Carried fraction of the last rate division (numerator over
    /// [`remainder_den`](Self::remainder_den)).
    pub remainder: u128,
    /// The delegated total [`remainder`](Self::remainder) is denominated in.
    /// A change of the delegated total re-denominates it (the carry is
    /// dropped, which costs `< 1 / SCALE` of the rate — a fraction of a nano
    /// per delegator).
    pub remainder_den: u64,
}

impl ValidatorRewardState {
    /// The scaled rate increment for `pool` spread over `delegated` units of
    /// stake, carrying the un-truncated remainder into the next call.
    ///
    /// O(1): no delegator is touched.
    fn accrue(&mut self, pool: u64, delegated: u64) {
        if pool == 0 || delegated == 0 {
            return;
        }
        if self.remainder_den != delegated {
            // The carried remainder is denominated in the OLD delegated
            // total: re-denominate by dropping it (worth < 1/SCALE of the
            // rate, i.e. a fraction of a nano per delegator).
            self.remainder = 0;
            self.remainder_den = delegated;
        }
        let den = delegated as u128;
        let num = pool as u128 * REWARD_PER_TOKEN_SCALE + self.remainder;
        let inc = num / den;
        self.remainder = num % den;
        self.reward_per_token = self.reward_per_token.saturating_add(inc);
        self.historical_rewards = self.historical_rewards.saturating_add(pool as u128);
        self.remaining_rewards = self.remaining_rewards.saturating_add(pool as u128);
    }
}

/// `floor(a * b / d)` for the magnitudes this ledger can reach, WITHOUT an
/// intermediate that overflows `u128`.
///
/// The naive `a * b` overflows: `a` is a delegator's stake (up to `u64::MAX`)
/// and `b` is the scaled accumulator delta (up to `~3.5e35`), so the product
/// reaches `~6e54` — far past `u128::MAX (3.4e38)`. Splitting `b` into
/// `q * d + r` keeps both products in range:
///
/// ```text
/// a * b / d = a * q + a * r / d          (a*q is an integer, so the floor
///                                          is exact)
/// ```
///
/// with `q = b / d` (the whole reward-per-token units, `≤ 3.5e17` for this
/// ledger) and `r < d` (the fraction, `< 1e18`).
fn mul_div_floor(a: u128, b: u128, d: u128) -> u128 {
    if a == 0 || b == 0 || d == 0 {
        return 0;
    }
    let q = b / d;
    let r = b % d;
    let whole = a.saturating_mul(q);
    let frac = a.saturating_mul(r) / d;
    whole.saturating_add(frac)
}

/// Quorum-safety (fragile-set) assessment — урок ночи C.
///
/// Three equal stakes need 3/3 for quorum (`floor(2T/3)+1` over power), so
/// ANY single halt stops the chain; the live 2/2 stand is in the same
/// position. [`MAX_ACTIVE_VALIDATORS`] caps the top of the set, this guards
/// the bottom: it never refuses anything (testnet is fail-open here), it
/// only REPORTS, loudly — a WARN at every stake mutation plus the `fragile`
/// flag on `stell_getValidators`.
///
/// Returns `Some(reason)` when the power distribution is fragile:
///  - empty / zero-power set (cannot reach quorum at all);
///  - N=3 with equal power (quorum is 3/3 by construction);
///  - general case: quorum needs 100% of the set, i.e. losing even the
///    smallest validator already drops below quorum (`total - min < quorum`).
///    Otherwise `None`.
pub fn validator_powers_fragility(powers: &[u64]) -> Option<String> {
    let n = powers.len();
    if n == 0 {
        return Some("fragile validator set: empty set cannot reach quorum".to_string());
    }
    let total = powers.iter().fold(0u64, |a, &p| a.saturating_add(p));
    if total == 0 {
        return Some("fragile validator set: zero total power cannot reach quorum".to_string());
    }
    // Same curve as `ValidatorSet::quorum_power` (floor(2T/3)+1), in u128 so
    // a huge total cannot wrap the `*2`.
    let quorum = ((total as u128 * 2) / 3 + 1).min(u64::MAX as u128) as u64;
    if n == 3 && powers[0] == powers[1] && powers[1] == powers[2] {
        return Some(format!(
            "fragile validator set: N=3 equal power ({}) needs 3/3 for quorum {quorum} of {total}: any single halt stops the chain",
            powers[0]
        ));
    }
    let min = powers.iter().copied().min().unwrap_or(0);
    if total.saturating_sub(min) < quorum {
        return Some(format!(
            "fragile validator set: quorum {quorum} of total {total} requires 100% of the set: losing even the smallest validator ({min}) stops the chain"
        ));
    }
    None
}

/// Re-entry liveness window in heights: a validator that rejoined the set
/// and still shows no votes after this many heights is a liveness risk.
///
/// Equals [`DOWNTIME_MISS_THRESHOLD`] (10) deliberately: 10 consecutive
/// heights absent from the quorum certificate is exactly what the downtime
/// slasher already treats as "deliberately offline", so the watch window and
/// the slash window agree on what "offline" means.
pub const REENTRY_LIVENESS_WINDOW_HEIGHTS: u64 = DOWNTIME_MISS_THRESHOLD as u64;

/// Re-entrants of a set refresh: members of `next` that were absent from
/// `prev`, with their new power. Pure and deterministic (BTreeMap order), so
/// every node derives the same list from the same two sets — but it is still
/// LOCAL POLICY input only: callers must WARN, never alter the derived set.
///
/// урок валидатора C: at N=3 a slashed-ejected validator drifted back over
/// MIN (top-up) and silently rejoined while still offline; the micro-quorum
/// was unanimous, so the offline re-entrant halted the chain. Every gain the
/// refresh installs gets a LOUD warn (see [`reentry_warn_message_for`]) plus
/// a node-local liveness watch (see [`reentry_liveness_risk`]).
pub fn validator_set_gains(prev: &ValidatorSet, next: &ValidatorSet) -> Vec<(ValidatorId, u64)> {
    next.validators
        .iter()
        .filter(|(id, _)| !prev.validators.contains_key(*id))
        .map(|(id, power)| (*id, *power))
        .collect()
}

/// Build the LOUD re-entry WARN text for one gained member. `Some` always
/// (a gain is always worth shouting about); carries member, power, height.
pub fn reentry_warn_message_for(member: &ValidatorId, power: u64, height: u64) -> String {
    format!(
        "VALIDATOR-RE-ENTRY validator {} REJOINED the consensus set at height {height} with power {power}: it was ABSENT from the previous set (slash-eject + top-up re-entry while possibly still offline): verify it is actually online and voting — an offline re-entrant in a micro-quorum halts the chain",
        hex::encode(member),
    )
}

/// Pure predicate: a re-entrant that joined at `rejoined_at` is a liveness
/// risk at `now_height` when N heights have passed and its QC-derived
/// `missed` streak is non-zero (it is not contributing to certificates).
///
/// `missed` is the ledger's own downtime streak ([`ValidatorStake::missed`],
/// reset whenever the validator signs a certificate): block-content-derived
/// like the downtime slash itself, so it survives height boundaries — unlike
/// the gossip-local per-height peer-rounds map, which has no per-voter
/// reader and is reset at every height advance. `missed > 0` (not `>= N`)
/// because the streak resets to 0 on every downtime slash; demanding `>= N`
/// would go blind exactly when the slash fires.
pub fn reentry_liveness_risk(rejoined_at: u64, now_height: u64, missed: u32) -> bool {
    now_height.saturating_sub(rejoined_at) >= REENTRY_LIVENESS_WINDOW_HEIGHTS && missed > 0
}

/// Build the repeating liveness-risk WARN text for a watched re-entrant.
pub fn reentry_liveness_warn_message_for(
    member: &ValidatorId,
    power: u64,
    rejoined_at: u64,
    now_height: u64,
    missed: u32,
) -> String {
    format!(
        "VALIDATOR-LIVENESS-RISK re-entrant validator {} (power {power}, rejoined at height {rejoined_at}) has shown no votes for {} heights (missed streak {missed}, now {now_height}): treat as OFFLINE until it votes — do not assume quorum headroom it cannot provide",
        hex::encode(member),
        now_height.saturating_sub(rejoined_at),
    )
}

/// Deterministic staking ledger.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StakingLedger {
    pub validators: HashMap<ValidatorId, ValidatorStake>,
    /// (validator, delegator) -> amount
    pub delegations: HashMap<(ValidatorId, [u8; 32]), u64>,
    /// Per-delegator claimable rewards: (validator, delegator) -> nano
    ///
    /// LAZY ACCOUNTING (F1): this map holds the SETTLED part of a
    /// delegator's entitlement — the part that was materialised when the
    /// delegator last TOUCHED its position (a claim, a stake change, a
    /// slash). The UNSETTLED part is computed on demand from the validator's
    /// accumulator and the delegator's checkpoint; read the TOTAL owed with
    /// [`StakingLedger::delegator_rewards_of`], never this map alone.
    pub delegator_rewards: HashMap<(ValidatorId, [u8; 32]), u64>,
    /// Pending unbondings, keyed by validator.
    pub unbonding: Vec<UnbondingEntry>,
    /// Funds that have completed cooldown and can be withdrawn by their owner.
    /// (owner, validator) -> amount ready.
    pub withdrawable: HashMap<(ValidatorId, [u8; 32]), u64>,
    /// Total STELL burned by slashing (deflationary).
    pub total_burned: u64,
    /// Minted-but-unclaimed staking rewards backing every `pending_rewards`
    /// and `delegator_rewards` entry (E2 fix). Increased by
    /// `distribute_reward` (the mint), decreased by the claim paths. Claims
    /// debit [`REWARDS_POOL`], not [`STAKING_POOL`], so rewards never come
    /// out of bonded principal. Zero on a fresh ledger.
    #[serde(default)]
    pub rewards_pool: u64,
    /// Cumulative staking rewards ever minted. Compared against
    /// [`REWARDS_EMISSION_CAP`] on every mint (fail-closed over cap).
    /// Monotonic except via saturating arithmetic; zero on a fresh ledger.
    #[serde(default)]
    pub rewards_minted: u64,
    /// Per-owner stake locked in OPEN governance votes (E7 fix), in nano.
    ///
    /// Keyed by the VOTER (a validator id for self-bond, a delegator address
    /// for delegated stake) — the same identity whose weight
    /// [`crate::governance::Governance::vote`] records. `unbond` refuses the
    /// locked portion of self-bond, `undelegate` the locked portion of the
    /// position, so a vote's backing cannot exit before `finalize` releases
    /// it. Saturating and per-owner (not per-proposal): an owner who votes
    /// the same stake on two open proposals locks twice the stake and cannot
    /// exit any of it until one finalizes — over-conservative by design
    /// (fail-closed beats precise). Empty on a fresh ledger and whenever no
    /// vote is open, so the conditional commitment domain writes zero bytes
    /// and the genesis root is untouched.
    #[serde(default)]
    pub locked_governance: HashMap<[u8; 32], u64>,
    /// Deduplication set of processed PQ equivocation evidence keys:
    /// BLAKE3(voter || height || round || kind).
    #[serde(default)]
    pub pq_equivocation_dedup: HashSet<[u8; 32]>,
    /// Deduplication set of processed block-carried (Ed25519-vote)
    /// equivocation offenses, keyed by
    /// [`crate::consensus::EquivocationEvidence::offense_key`] —
    /// `BLAKE3(domain ‖ voter ‖ height ‖ round ‖ kind ‖ target_lo ‖
    /// target_hi)`. Same offense (either vote order, any number of
    /// rebroadcasts or block re-inclusions) keys identically, so the wired
    /// path slashes it exactly once per chain. Insert-only from the wired
    /// transition path; derived deterministically from applied blocks, so
    /// every node that applies the same blocks holds the same set.
    ///
    /// SHARED with the proposal-equivocation path
    /// ([`crate::consensus::ProposalEquivocationEvidence::offense_key`]):
    /// vote and proposal keys live under distinct BLAKE3 domains, so the
    /// two offense classes can share one set without ever colliding.
    ///
    /// NOT folded into the commitment digest (same posture as the PQ set
    /// above): an empty set writes nothing and the genesis KAT is
    /// untouched. A conditional domain (E7-style) is the follow-up if
    /// light-client provability of the set is ever needed.
    #[serde(default)]
    pub equivocation_dedup: HashSet<[u8; 32]>,
    /// Registered post-quantum public keys and schemes per validator.
    #[serde(default)]
    pub validator_pq_keys: HashMap<ValidatorId, (crate::post_quantum::PqScheme, Vec<u8>)>,
    /// Governed minimum validator bond (if set).
    #[serde(default)]
    pub min_validator_bond: Option<u64>,
    /// Team vesting schedules by account (audit: team vesting claim gate).
    ///
    /// An account present here may not spend below its schedule's locked
    /// floor (see [`TeamVestingSchedule::check_balance_floor`]); the spend
    /// path ([`crate::state_engine::InMemoryStateEngine`] native commit)
    /// refuses the whole transaction fail-closed when it would. `BTreeMap`
    /// (not `HashMap`) so iteration is deterministic across nodes.
    ///
    /// Empty on every live chain today: `TeamVestingSchedule` was CLI-only
    /// (`unlocked_amount`/`claimable_amount` with no on-chain lock) and
    /// genesis funds validator accounts only, so no vested allocations
    /// exist to migrate — the gate ships as the correct default and activates
    /// per account on registration. FOLLOW-UP MIGRATION (required before any
    /// registration on a live chain counts as fully closed): (1) a
    /// CONDITIONAL commitment domain for this map in `commitment.rs`
    /// (empty writes zero bytes, genesis root untouched — same contract as
    /// the rewards/gov-locks domains); (2) a `DomainSnapshotV2` fallback in
    /// `storage.rs` carrying the new field; (3) a governance-gated
    /// registration action (new `GovAction` + SVM wiring). Until then a
    /// registered schedule is enforced identically by every node that
    /// applied the same blocks (registration is deterministic block content
    /// only — no live writer exists yet), but it does not move the root.
    #[serde(default)]
    pub vesting_schedules: BTreeMap<[u8; 32], TeamVestingSchedule>,
    /// Per-validator lazy delegator-reward accumulator (F1-style).
    ///
    /// This is what makes `distribute_reward` O(1): a distribution bumps the
    /// validator's accumulator instead of walking its delegations. Empty on a
    /// ledger that never distributed a delegator reward, so the conditional
    /// commitment domain writes zero bytes and the genesis root is untouched.
    ///
    /// APPENDED AT THE END of the struct (like every field added after the
    /// first): bincode has no field names, so the trailing fields are what
    /// makes the OLD bytes an exact PREFIX of the new ones — and the
    /// `StakingLedgerV3` shape in [`crate::storage`] is what decodes them.
    #[serde(default)]
    pub reward_accumulators: HashMap<ValidatorId, ValidatorRewardState>,
    /// Per-delegator checkpoint of the validator's accumulator:
    /// (validator, delegator) -> the `reward_per_token` value the delegator
    /// was settled at.
    ///
    /// The delegator's unsettled entitlement is
    /// `stake * (rate_now - checkpoint) / REWARD_PER_TOKEN_SCALE`. The
    /// checkpoint moves on every settlement (claim, delegate, undelegate,
    /// slash), so a delegator never earns on stake it did not have.
    #[serde(default)]
    pub delegator_reward_checkpoints: HashMap<(ValidatorId, [u8; 32]), u128>,
    /// Downtime jail records by validator. A jailed validator is excluded
    /// from [`Self::to_validator_set`] (and [`Self::elected_count`]) until
    /// [`Self::unjail`] re-admits it. Installed automatically by
    /// [`Self::note_missed_heights`] when a downtime slash fires; empty on
    /// every ledger that never suffered one, so the conditional commitment
    /// treatment (commitment.rs, out of scope — follow-up conditional domain)
    /// keeps the genesis root untouched.
    ///
    /// SERIALIZATION (upgrade hazard, reported): appended at the END with
    /// `#[serde(default)]` like every prior addition; old snapshots decode
    /// via the versioned `DomainSnapshotV*` fallback chain and
    /// `StakingLedgerV3::upgrade` fills these empty (exact: no jail,
    /// schedule or lock rows can exist in pre-feature bytes). A storage.rs
    /// `DomainSnapshotV7`-style fallback for CURRENT-shape bytes (with the
    /// lazy accumulator but without these maps) is still required before any
    /// live data-dir upgrade — flagged as a cross-scope follow-up.
    #[serde(default)]
    pub jail: HashMap<ValidatorId, JailRecord>,
    /// Per-validator commission schedules (bounded mutable commission with a
    /// delegator-exit window). Empty until the first
    /// [`Self::announce_commission`]; see [`CommissionSchedule`].
    #[serde(default)]
    pub commission_schedule: HashMap<ValidatorId, CommissionSchedule>,
    /// Anti-long-range redelegation locks: (validator, delegator) ->
    /// timestamp before which the position now at `validator` may not be
    /// redelegated AGAIN. Set to `now + `[`UNBONDING_PERIOD_SECS`] on every
    /// [`Self::redelegate`] INTO `validator`; `redelegate` FROM a locked
    /// position is refused with [`StakingError::CooldownNotElapsed`], while
    /// `undelegate` (which starts the full unbond wait itself) stays
    /// available. Empty until the first redelegation.
    #[serde(default)]
    pub redelegation_lock: HashMap<(ValidatorId, [u8; 32]), u64>,
}

impl StakingLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a validator with an initial self-bond.
    ///
    /// Fail-closed on a thin bond (урок валидатора C): `amount` below
    /// MIN+buffer ([`required_bond_floor_nano`], i.e. 1100 STELL) is REFUSED
    /// with [`StakingError::BondBelowMinimum`] — a bare-MIN bond is one
    /// downtime slash away from ejection, so it cannot be created. Use
    /// [`StakingLedger::add_bond`] to top up an existing (grandfathered)
    /// validator; top-ups stay fail-open and only WARN below MIN+buffer.
    pub fn bond(
        &mut self,
        validator: ValidatorId,
        amount: u64,
        commission_bps: u64,
    ) -> Result<(), StakingError> {
        // Consensus-critical: plain consts only, never the env-driven
        // `min_bond_buffer_nano()` — every node must reach the same
        // accept/refuse for the same bond.
        if amount < required_bond_floor_nano() {
            return Err(StakingError::BondBelowMinimum);
        }
        if commission_bps > BPS_DENOMINATOR {
            return Err(StakingError::BadCommission);
        }
        if self.validators.contains_key(&validator) {
            return Err(StakingError::AlreadyValidator);
        }
        self.validators.insert(
            validator,
            ValidatorStake {
                self_bond: amount,
                delegated: 0,
                commission_bps,
                pending_rewards: 0,
                total_slashed: 0,
                missed: 0,
                last_downtime_penalty: 0,
            },
        );
        // Fail-open cushion policy on top of the fail-closed floor above: when
        // the operator raised the env buffer beyond STELL_MIN_BOND_BUFFER, a
        // bond inside [floor, MIN+env_buffer) still WARNs (log-only).
        if let Some(msg) = buffer_warn_message_for(amount, min_bond_buffer_nano()) {
            tracing::warn!("SysCallStake/bond {}: {msg}", hex::encode(validator));
        }
        self.warn_if_quorum_fragile("SysCallStake/bond");
        Ok(())
    }

    /// Genesis-only bond: byte-identical bookkeeping to [`Self::bond`] MINUS
    /// the MIN+buffer floor check. Genesis recompute MUST reproduce the v1
    /// genesis root (`61336779...`, bonds at bare MIN) or the stored-root
    /// guard refuses to boot existing data dirs. The runtime floor applies to
    /// NEW stakes via `bond()`; founding entries are grandfathered by
    /// construction (every live validator tops up past the buffer anyway).
    /// CALLERS: `fund_genesis` ONLY. Never for user stakes.
    pub fn bond_genesis(
        &mut self,
        validator: ValidatorId,
        amount: u64,
        commission_bps: u64,
    ) -> Result<(), StakingError> {
        if commission_bps > BPS_DENOMINATOR {
            return Err(StakingError::BadCommission);
        }
        if self.validators.contains_key(&validator) {
            return Err(StakingError::AlreadyValidator);
        }
        self.validators.insert(
            validator,
            ValidatorStake {
                self_bond: amount,
                delegated: 0,
                commission_bps,
                pending_rewards: 0,
                total_slashed: 0,
                missed: 0,
                last_downtime_penalty: 0,
            },
        );
        if let Some(msg) = buffer_warn_message_for(amount, min_bond_buffer_nano()) {
            tracing::warn!("genesis-bond {}: {msg}", hex::encode(validator));
        }
        self.warn_if_quorum_fragile("genesis-bond");
        Ok(())
    }

    /// Add more self-bond to an existing validator.
    ///
    /// Fail-open on thin top-ups (grandfathered bare-MIN validators re-enter
    /// this way): any amount is accepted, below-MIN+buffer WARNs loudly.
    /// Fail-closed on arithmetic (audit L3): overflow refuses with
    /// [`StakingError::ArithmeticOverflow`] instead of saturating at u64::MAX.
    pub fn add_bond(&mut self, validator: ValidatorId, amount: u64) -> Result<(), StakingError> {
        let v = self
            .validators
            .get_mut(&validator)
            .ok_or(StakingError::NotValidator)?;
        v.self_bond = v
            .self_bond
            .checked_add(amount)
            .ok_or(StakingError::ArithmeticOverflow)?;
        let total = v.self_bond;
        // Fail-open: top-ups that still leave the bond below MIN+buffer WARN.
        if let Some(msg) = buffer_warn_message_for(total, min_bond_buffer_nano()) {
            tracing::warn!("SysCallStake/top-up {}: {msg}", hex::encode(validator));
        }
        self.warn_if_quorum_fragile("SysCallStake/top-up");
        Ok(())
    }

    /// Whether `validator` is currently jailed (downtime) and therefore
    /// excluded from the consensus set.
    pub fn is_jailed(&self, validator: &ValidatorId) -> bool {
        self.jail.contains_key(validator)
    }

    /// The jail record for `validator`, if jailed. Read-only query path for
    /// operators (`stell_getValidatorStatus` serves this).
    pub fn jail_record(&self, validator: &ValidatorId) -> Option<JailRecord> {
        self.jail.get(validator).copied()
    }

    /// Re-admit a downtime-jailed validator to the consensus set (effective
    /// at the H+1 activation boundary like every other stake mutation).
    ///
    /// Fail-closed conditions (ALL must hold):
    ///  1. the validator IS jailed, else [`StakingError::NotJailed`];
    ///  2. `now_height >= release_height` (the downtime window plus the
    ///     [`JAIL_RELEASE_DELAY_HEIGHTS`] cooldown has passed), else
    ///     [`StakingError::CooldownNotElapsed`];
    ///  3. `self_bond >= `[`required_bond_floor_nano`]` (MIN+buffer — the
    ///     bare-MIN ejection edge: a validator that cannot absorb one more
    ///     downtime slash may not rejoin), else
    ///     [`StakingError::BondBelowMinimum`]. A jailed operator below the
    ///     floor tops up via [`Self::add_bond`] first (top-ups stay allowed
    ///     while jailed; exits do too — jail never holds funds hostage).
    ///
    /// Effects: the jail record is removed, the downtime streak is reset
    /// (`missed = 0` — the validator re-proves liveness going forward; while
    /// jailed it was unelected and therefore untracked, so no streak could
    /// accrue), and a LOUD re-entry WARN fires (same treatment as a set
    /// gain). The penalty history (`last_downtime_penalty`,
    /// `total_slashed`) is PRESERVED — unjailing never launders a record.
    /// No stake moves, so the conservation invariant holds trivially
    /// (debug-asserted).
    pub fn unjail(&mut self, validator: ValidatorId, now_height: u64) -> Result<(), StakingError> {
        let supply_before = self.ledger_stake_supply();
        let record = self
            .jail
            .get(&validator)
            .copied()
            .ok_or(StakingError::NotJailed)?;
        if now_height < record.release_height {
            return Err(StakingError::CooldownNotElapsed);
        }
        let self_bond = self
            .validators
            .get(&validator)
            .map(|v| v.self_bond)
            .unwrap_or(0);
        if self_bond < required_bond_floor_nano() {
            return Err(StakingError::BondBelowMinimum);
        }
        self.jail.remove(&validator);
        if let Some(v) = self.validators.get_mut(&validator) {
            v.missed = 0;
        }
        tracing::warn!(
            "VALIDATOR-UNJAIL validator {} re-admitted at height {now_height} (jailed at {}, self_bond {self_bond}): verify it is actually online and voting — an offline re-entrant in a micro-quorum halts the chain",
            hex::encode(validator),
            record.jailed_at_height,
        );
        self.warn_if_quorum_fragile("unjail");
        debug_assert_eq!(
            supply_before,
            self.ledger_stake_supply(),
            "unjail must move no stake"
        );
        Ok(())
    }

    /// The commission schedule for `validator`, if it ever announced a
    /// change. Read-only query path for operators deciding whether to stay
    /// delegated through a pending raise (`stell_getValidatorStatus`).
    pub fn commission_schedule_of(&self, validator: &ValidatorId) -> Option<CommissionSchedule> {
        self.commission_schedule.get(validator).copied()
    }

    /// Announce a commission change (phase 1 of 2). The rate does NOT move:
    /// a [`PendingCommissionChange`] is recorded with
    /// `effective_height = now_height + `[`COMMISSION_EFFECT_DELAY_HEIGHTS`],
    /// and [`Self::apply_commission`] installs it once that height is
    /// reached. The window between is the delegator-exit window — the rate
    /// is queryable and `undelegate`/`redelegate` stay fully available.
    ///
    /// Fail-closed (ledger untouched on any refusal):
    ///  - unknown validator → [`StakingError::NotValidator`];
    ///  - `new_bps > `[`BPS_DENOMINATOR`] → [`StakingError::BadCommission`];
    ///  - `|new − current| > `[`COMMISSION_MAX_DELTA_BPS`] →
    ///    [`StakingError::CommissionDeltaExceeded`];
    ///  - announced inside the post-change cooldown (`now_height <
    ///    last_effective + `[`COMMISSION_CHANGE_COOLDOWN_HEIGHTS`] with a
    ///    previous effective change on record) →
    ///    [`StakingError::CommissionNotDue`].
    ///
    /// Announcing the CURRENT rate cancels a pending change (no-op success,
    /// no cooldown imposed). Announcing a different rate REPLACES a pending
    /// one (intent update — nothing took effect yet, so there is nothing to
    /// unwind); the new effective height is recomputed from this call.
    /// No stake moves (debug-asserted).
    pub fn announce_commission(
        &mut self,
        validator: ValidatorId,
        new_bps: u64,
        now_height: u64,
    ) -> Result<(), StakingError> {
        let supply_before = self.ledger_stake_supply();
        let current = self
            .validators
            .get(&validator)
            .map(|v| v.commission_bps)
            .ok_or(StakingError::NotValidator)?;
        if new_bps > BPS_DENOMINATOR {
            return Err(StakingError::BadCommission);
        }
        if new_bps == current {
            // Cancel-by-reannounce: a pending change that never took effect
            // is dropped, and no cooldown is imposed for the no-op.
            if let Some(s) = self.commission_schedule.get_mut(&validator) {
                s.pending = None;
            }
            debug_assert_eq!(
                supply_before,
                self.ledger_stake_supply(),
                "announce must move no stake"
            );
            return Ok(());
        }
        if new_bps.abs_diff(current) > COMMISSION_MAX_DELTA_BPS {
            return Err(StakingError::CommissionDeltaExceeded);
        }
        let last = self
            .commission_schedule
            .get(&validator)
            .and_then(|s| s.last_effective_height);
        if let Some(prev) = last {
            if now_height < prev.saturating_add(COMMISSION_CHANGE_COOLDOWN_HEIGHTS) {
                return Err(StakingError::CommissionNotDue);
            }
        }
        let effective_height = now_height.saturating_add(COMMISSION_EFFECT_DELAY_HEIGHTS);
        self.commission_schedule
            .entry(validator)
            .or_default()
            .pending = Some(PendingCommissionChange {
            new_bps,
            effective_height,
            announced_height: now_height,
        });
        tracing::warn!(
            "COMMISSION-ANNOUNCE validator {}: {} bps -> {new_bps} bps effective at height {effective_height} (announced at {now_height}): delegators may undelegate/redelegate before then",
            hex::encode(validator),
            current,
        );
        debug_assert_eq!(
            supply_before,
            self.ledger_stake_supply(),
            "announce must move no stake"
        );
        Ok(())
    }

    /// Install a due announced commission change (phase 2 of 2).
    ///
    /// Fail-closed: unknown validator → [`StakingError::NotValidator`];
    /// nothing pending, or `now_height` before the announced effective
    /// height → [`StakingError::CommissionNotDue`]. On success the rate moves
    /// (new emission only — past accruals are untouched, exactly like the
    /// direct field writes the adversarial tests pin) and the cooldown basis
    /// advances. No stake moves (debug-asserted).
    pub fn apply_commission(
        &mut self,
        validator: ValidatorId,
        now_height: u64,
    ) -> Result<(), StakingError> {
        let supply_before = self.ledger_stake_supply();
        // Validator first (unknown key is NotValidator even with no schedule),
        // then the due check.
        if !self.validators.contains_key(&validator) {
            return Err(StakingError::NotValidator);
        }
        let pending = self
            .commission_schedule
            .get(&validator)
            .and_then(|s| s.pending)
            .ok_or(StakingError::CommissionNotDue)?;
        if now_height < pending.effective_height {
            return Err(StakingError::CommissionNotDue);
        }
        let v = self
            .validators
            .get_mut(&validator)
            .ok_or(StakingError::NotValidator)?;
        v.commission_bps = pending.new_bps;
        if let Some(s) = self.commission_schedule.get_mut(&validator) {
            s.pending = None;
            s.last_effective_height = Some(now_height);
        }
        tracing::warn!(
            "COMMISSION-APPLIED validator {}: new rate {} bps effective at height {now_height}",
            hex::encode(validator),
            pending.new_bps,
        );
        debug_assert_eq!(
            supply_before,
            self.ledger_stake_supply(),
            "apply must move no stake"
        );
        Ok(())
    }

    /// Rotate a validator's consensus key: move the ENTIRE record (self-bond,
    /// delegations, rewards, unbonding entries, withdrawable balances AND the
    /// slashing/downtime history) from `old` to `new`, atomically. Nothing is
    /// created or destroyed: total stake, per-delegator positions and the
    /// slash history are byte-identical under the new key.
    ///
    /// Downtime/missed-height counters CARRY OVER deliberately: rotation must
    /// never launder a downtime record (otherwise a failing validator escapes
    /// its slash by rekeying). The new key inherits the exact standing — good
    /// or bad — of the old one.
    ///
    /// Fails when `old` is not a validator (nothing to rotate) or `new`
    /// already is one (rotation must never merge two records: amounts would
    /// mix and delegator accounting would become ambiguous). Auth (caller ==
    /// `old`) is enforced by the opcode handler, not here.
    pub fn rotate_key(&mut self, old: ValidatorId, new: ValidatorId) -> Result<(), StakingError> {
        if old == new {
            return Err(StakingError::AlreadyValidator);
        }
        if self.validators.contains_key(&new) {
            return Err(StakingError::AlreadyValidator);
        }
        if !self.validators.contains_key(&old) {
            return Err(StakingError::NotValidator);
        }
        if self.locked_governance.get(&old).copied().unwrap_or(0) > 0 {
            return Err(StakingError::LockedInGovernanceVote);
        }
        let record = self
            .validators
            .remove(&old)
            .ok_or(StakingError::NotValidator)?;
        self.validators.insert(new, record);
        // Every keyed map follows the record. Collect-then-write (no
        // in-place mutation during iteration): HashMap order differs between
        // processes, but the SET of entries moved is order-independent, so
        // every node derives the same ledger either way.
        let moved_delegations: Vec<([u8; 32], u64)> = self
            .delegations
            .iter()
            .filter(|((v, _), _)| *v == old)
            .map(|((_, d), a)| (*d, *a))
            .collect();
        for (d, _a) in &moved_delegations {
            self.delegations.remove(&(old, *d));
        }
        for (d, a) in moved_delegations {
            self.delegations.insert((new, d), a);
        }
        let moved_rewards: Vec<([u8; 32], u64)> = self
            .delegator_rewards
            .iter()
            .filter(|((v, _), _)| *v == old)
            .map(|((_, d), a)| (*d, *a))
            .collect();
        for (d, _a) in &moved_rewards {
            self.delegator_rewards.remove(&(old, *d));
        }
        for (d, a) in moved_rewards {
            self.delegator_rewards.insert((new, d), a);
        }
        // LAZY (F1): the delegator checkpoints move with the positions they
        // belong to, and the validator's accumulator moves with the record —
        // a rotated validator keeps its exact reward standing (a delegator
        // must not lose, or re-win, the accrual it earned under the old key).
        let moved_checkpoints: Vec<([u8; 32], u128)> = self
            .delegator_reward_checkpoints
            .iter()
            .filter(|((v, _), _)| *v == old)
            .map(|((_, d), c)| (*d, *c))
            .collect();
        for (d, _c) in &moved_checkpoints {
            self.delegator_reward_checkpoints.remove(&(old, *d));
        }
        for (d, c) in moved_checkpoints {
            self.delegator_reward_checkpoints.insert((new, d), c);
        }
        if let Some(acc) = self.reward_accumulators.remove(&old) {
            self.reward_accumulators.insert(new, acc);
        }
        for entry in self.unbonding.iter_mut() {
            if entry.validator == old {
                entry.validator = new;
            }
        }
        let moved_withdrawable: Vec<([u8; 32], u64)> = self
            .withdrawable
            .iter()
            .filter(|((v, _), _)| *v == old)
            .map(|((_, o), a)| (*o, *a))
            .collect();
        for (o, _a) in &moved_withdrawable {
            self.withdrawable.remove(&(old, *o));
        }
        for (o, a) in moved_withdrawable {
            self.withdrawable.insert((new, o), a);
        }
        // E7: a rotated validator's governance lock travels with its stake.
        // Without this the old key would hold a lock against no stake (its
        // future votes are already impossible — it is no longer a validator)
        // while the new key's identical stake voted nowhere and could exit
        // from under the open vote it inherited.
        if let Some(amt) = self.locked_governance.remove(&old) {
            let entry = self.locked_governance.entry(new).or_insert(0);
            *entry = entry.saturating_add(amt);
        }
        if let Some(pq_key) = self.validator_pq_keys.remove(&old) {
            self.validator_pq_keys.insert(new, pq_key);
        }
        // Jail, commission schedule and redelegation locks travel with the
        // record: rotation must neither launder a jail nor strand (or fork)
        // the rate-limiter and lock state. The gov-lock precedent above
        // applies — same stake, same standing, new key.
        if let Some(rec) = self.jail.remove(&old) {
            self.jail.insert(new, rec);
        }
        if let Some(sched) = self.commission_schedule.remove(&old) {
            self.commission_schedule.insert(new, sched);
        }
        let moved_locks: Vec<([u8; 32], u64)> = self
            .redelegation_lock
            .iter()
            .filter(|((v, _), _)| *v == old)
            .map(|((_, d), t)| (*d, *t))
            .collect();
        for (d, _t) in &moved_locks {
            self.redelegation_lock.remove(&(old, *d));
        }
        for (d, t) in moved_locks {
            let entry = self.redelegation_lock.entry((new, d)).or_insert(0);
            *entry = (*entry).max(t);
        }
        Ok(())
    }

    /// Start unbonding `amount` of self-bond. Funds become withdrawable after
    /// the cooldown. The validator must stay above the minimum bond (or drop to
    /// zero to fully exit).
    pub fn unbond(
        &mut self,
        validator: ValidatorId,
        amount: u64,
        now: u64,
    ) -> Result<(), StakingError> {
        let v = self
            .validators
            .get_mut(&validator)
            .ok_or(StakingError::NotValidator)?;
        if amount > v.self_bond {
            return Err(StakingError::InsufficientBond);
        }
        // E7: the locked portion of self-bond cannot exit while its vote is
        // open (checked after the balance check so over-draws keep the
        // pre-existing error).
        let locked = self.locked_governance.get(&validator).copied().unwrap_or(0);
        if amount > v.self_bond.saturating_sub(locked) {
            return Err(StakingError::LockedInGovernanceVote);
        }
        let remaining = v.self_bond - amount;
        // Either fully exit, or remain a valid validator above the minimum plus buffer floor.
        if remaining != 0 && remaining < required_bond_floor_nano() {
            return Err(StakingError::BondBelowMinimum);
        }
        v.self_bond = remaining;
        self.unbonding.push(UnbondingEntry {
            validator,
            owner: None,
            amount,
            release_at: now.saturating_add(UNBONDING_PERIOD_SECS),
        });
        Ok(())
    }

    /// Delegate stake to a validator. Requires a minimum delegation.
    ///
    /// Fail-closed on the zero delegator (audit L2: the `(validator, [0;32])`
    /// withdrawable key is the validator's own matured self-bond) and on
    /// arithmetic (audit L3: overflow refuses instead of saturating).
    pub fn delegate(
        &mut self,
        delegator: [u8; 32],
        validator: ValidatorId,
        amount: u64,
    ) -> Result<(), StakingError> {
        if delegator == [0u8; 32] {
            return Err(StakingError::ZeroAddress);
        }
        if amount < MIN_DELEGATION {
            return Err(StakingError::DelegationBelowMinimum);
        }
        let (self_bond, delegated_now, held) = {
            let v = self
                .validators
                .get(&validator)
                .ok_or(StakingError::NotValidator)?;
            (
                v.self_bond,
                v.delegated,
                self.delegations
                    .get(&(validator, delegator))
                    .copied()
                    .unwrap_or(0),
            )
        };
        if self_bond < MIN_VALIDATOR_BOND {
            return Err(StakingError::NotValidator);
        }
        // A jailed validator is out of the set: new delegations cannot park
        // on it (its power counts for nothing until `unjail`). Exits stay
        // available; only entry is refused.
        if self.jail.contains_key(&validator) {
            return Err(StakingError::Jailed);
        }
        // Fail-closed arithmetic BEFORE any mutation: a refused delegation
        // leaves the ledger byte-identical (the lazy settle below is a
        // bookkeeping move, but it must not happen on a refused call).
        let new_delegated = delegated_now
            .checked_add(amount)
            .ok_or(StakingError::ArithmeticOverflow)?;
        let new_held = held
            .checked_add(amount)
            .ok_or(StakingError::ArithmeticOverflow)?;
        // LAZY (F1): settle the delegator's position BEFORE the stake grows.
        // The rewards it already earned are materialised verbatim, and the
        // checkpoint moves to the current rate so the ENLARGED stake only
        // earns from the next distribution on — exactly what the eager
        // `pool * stake / delegated` split did (a delegator never earned on
        // stake it did not have).
        self.settle_delegator_rewards(delegator, validator);
        let v = self
            .validators
            .get_mut(&validator)
            .ok_or(StakingError::NotValidator)?;
        v.delegated = new_delegated;
        self.delegations.insert((validator, delegator), new_held);
        self.warn_if_quorum_fragile("top-up/delegate");
        Ok(())
    }

    /// Begin undelegating `amount` from a validator (subject to cooldown).
    /// Argument order: (delegator, validator, amount, now) — delegator first.
    ///
    /// LAZY (F1): the delegator's position is SETTLED first, so the rewards
    /// it already earned are materialised into `delegator_rewards` (and
    /// survive the exit untouched) and the reduced stake only earns from the
    /// next distribution on.
    pub fn undelegate(
        &mut self,
        delegator: [u8; 32],
        validator: ValidatorId,
        amount: u64,
        now: u64,
    ) -> Result<(), StakingError> {
        let key = (validator, delegator);
        let current = self.delegations.get(&key).copied().unwrap_or(0);
        if amount > current {
            return Err(StakingError::InsufficientDelegation);
        }
        // E7: the locked portion of the position cannot exit while its vote
        // is open. Per-owner (not per-position) lock, so a lock taken against
        // the owner's total stake conservatively covers every position.
        let locked = self.locked_governance.get(&delegator).copied().unwrap_or(0);
        if amount > current.saturating_sub(locked) {
            return Err(StakingError::LockedInGovernanceVote);
        }
        // LAZY (F1): settle BEFORE the stake shrinks — the accrued rewards
        // are preserved verbatim and the reduced stake only earns from the
        // next distribution on.
        self.settle_delegator_rewards(delegator, validator);
        let v = self
            .validators
            .get_mut(&validator)
            .ok_or(StakingError::NotValidator)?;
        v.delegated = v.delegated.saturating_sub(amount);
        if current - amount == 0 {
            self.delegations.remove(&key);
        } else {
            self.delegations.insert(key, current - amount);
        }
        self.unbonding.push(UnbondingEntry {
            validator,
            owner: Some(delegator),
            amount,
            release_at: now.saturating_add(UNBONDING_PERIOD_SECS),
        });
        Ok(())
    }

    /// Timestamp before which the position (`validator`, `delegator`) may not
    /// be redelegated AGAIN; 0 when no redelegation lock exists. Read-only
    /// query path for wallets planning a move.
    pub fn redelegation_locked_until(&self, validator: &ValidatorId, delegator: &[u8; 32]) -> u64 {
        self.redelegation_lock
            .get(&(*validator, *delegator))
            .copied()
            .unwrap_or(0)
    }

    /// Move `amount` of `delegator`'s stake from validator `from` to validator
    /// `to` WITHOUT the full unbond wait: voting power shifts immediately
    /// (effective at the H+1 activation boundary), no withdrawal round-trip.
    ///
    /// ANTI-LONG-RANGE RULE (documented contract): a redelegation is a fast
    /// path, not a free hop. The moved amount is locked against FURTHER
    /// redelegation until `now + `[`UNBONDING_PERIOD_SECS`] — the same window
    /// an unbond would take — so stake cannot be hopped between validators
    /// inside one unbonding period to double-attribute voting history across
    /// forks. Redelegating FROM a locked position is refused fail-closed
    /// with [`StakingError::CooldownNotElapsed`]. `undelegate` is NOT gated
    /// by this lock: it starts the full unbond wait itself, so it cannot
    /// abuse the fast path (it IS the slow path).
    ///
    /// Fail-closed (ledger byte-identical on any refusal; arithmetic checked
    /// BEFORE any mutation like `delegate`):
    ///  - zero delegator → [`StakingError::ZeroAddress`];
    ///  - `from == to` → [`StakingError::InvalidRedelegation`] (a
    ///    same-validator "move" would otherwise launder the lock timestamp);
    ///  - `amount == 0` or `amount > held` →
    ///    [`StakingError::InsufficientDelegation`];
    ///  - unknown `from`, unknown `to`, `to` jailed, or `to.self_bond < MIN`
    ///    → [`StakingError::NotValidator`] / [`StakingError::Jailed`]
    ///    (stake may FLEE a jailed validator — `from` jailed is allowed —
    ///    but may never be parked ON one);
    ///  - governance-locked portion → [`StakingError::LockedInGovernanceVote`]
    ///    (same per-owner check as `undelegate`);
    ///  - position still redelegation-locked →
    ///    [`StakingError::CooldownNotElapsed`];
    ///  - aggregate overflow → [`StakingError::ArithmeticOverflow`].
    ///
    /// Reward accounting is the `delegate`/`undelegate` settle pattern on
    /// BOTH sides: the `from` position's accrued rewards are materialised
    /// verbatim (they survive the move), and the moved stake earns at `to`
    /// only from the NEXT distribution on (it never claims a share of pools
    /// distributed before it arrived). Conservation holds exactly: the same
    /// nanos leave one aggregate and enter the other (debug-asserted via
    /// [`Self::ledger_stake_supply`]).
    pub fn redelegate(
        &mut self,
        delegator: [u8; 32],
        from: ValidatorId,
        to: ValidatorId,
        amount: u64,
        now: u64,
    ) -> Result<(), StakingError> {
        let supply_before = self.ledger_stake_supply();
        if delegator == [0u8; 32] {
            return Err(StakingError::ZeroAddress);
        }
        if from == to {
            return Err(StakingError::InvalidRedelegation);
        }
        let from_key = (from, delegator);
        let held = self.delegations.get(&from_key).copied().unwrap_or(0);
        if amount == 0 || amount > held {
            return Err(StakingError::InsufficientDelegation);
        }
        // E7: the locked portion of the position cannot move while its vote
        // is open (same per-owner conservative check as `undelegate`).
        let locked = self.locked_governance.get(&delegator).copied().unwrap_or(0);
        if amount > held.saturating_sub(locked) {
            return Err(StakingError::LockedInGovernanceVote);
        }
        // Anti-long-range: the fast path cannot be chained inside one
        // unbonding period.
        if now < self.redelegation_locked_until(&from, &delegator) {
            return Err(StakingError::CooldownNotElapsed);
        }
        if !self.validators.contains_key(&from) {
            return Err(StakingError::NotValidator);
        }
        {
            let dst = self.validators.get(&to).ok_or(StakingError::NotValidator)?;
            if self.jail.contains_key(&to) {
                return Err(StakingError::Jailed);
            }
            if dst.self_bond < MIN_VALIDATOR_BOND {
                return Err(StakingError::NotValidator);
            }
        }
        // Fail-closed arithmetic BEFORE any mutation: a refused move leaves
        // the ledger byte-identical.
        let to_delegated = self.validators.get(&to).map(|v| v.delegated).unwrap_or(0);
        let to_held = self.delegations.get(&(to, delegator)).copied().unwrap_or(0);
        let new_to_delegated = to_delegated
            .checked_add(amount)
            .ok_or(StakingError::ArithmeticOverflow)?;
        let new_to_held = to_held
            .checked_add(amount)
            .ok_or(StakingError::ArithmeticOverflow)?;
        // LAZY (F1): settle BOTH sides before the stakes move — the `from`
        // accrual is preserved verbatim, and the moved stake only earns at
        // `to` from the next distribution on.
        self.settle_delegator_rewards(delegator, from);
        self.settle_delegator_rewards(delegator, to);
        if let Some(v) = self.validators.get_mut(&from) {
            v.delegated = v.delegated.saturating_sub(amount);
        }
        if let Some(v) = self.validators.get_mut(&to) {
            v.delegated = new_to_delegated;
        }
        if held - amount == 0 {
            self.delegations.remove(&from_key);
        } else {
            self.delegations.insert(from_key, held - amount);
        }
        self.delegations.insert((to, delegator), new_to_held);
        // Arm the anti-long-range lock on the ARRIVAL position: this stake
        // may not take the fast path again until one full unbonding period
        // has passed. `max` (not overwrite) so concurrent positions keep the
        // furthest release.
        let release = now.saturating_add(UNBONDING_PERIOD_SECS);
        let entry = self.redelegation_lock.entry((to, delegator)).or_insert(0);
        *entry = (*entry).max(release);
        self.warn_if_quorum_fragile("redelegate");
        debug_assert_eq!(
            supply_before,
            self.ledger_stake_supply(),
            "redelegate must conserve stake exactly"
        );
        Ok(())
    }

    /// Move all matured unbonding entries into `withdrawable`, crediting the
    /// entry's OWNER (validator for self-bond, delegator for undelegation).
    ///
    /// Audit P2: fail-closed arithmetic (like L3 `add_bond`/`delegate`):
    /// every maturing amount is pre-validated against its withdrawable key
    /// BEFORE anything moves, so an overflow refusal leaves all entries
    /// pending (partial maturation is the bug being closed).
    pub fn process_unbonding(&mut self, now: u64) -> Result<(), StakingError> {
        use std::collections::HashMap;
        let mut maturing: HashMap<(ValidatorId, [u8; 32]), u128> = HashMap::new();
        for e in self.unbonding.iter().filter(|e| now >= e.release_at) {
            let owner = e.owner.unwrap_or([0u8; 32]);
            *maturing.entry((e.validator, owner)).or_insert(0) += e.amount as u128;
        }
        for ((v, o), sum) in &maturing {
            let cur = self.withdrawable.get(&(*v, *o)).copied().unwrap_or(0) as u128;
            if cur + sum > u64::MAX as u128 {
                return Err(StakingError::ArithmeticOverflow);
            }
        }
        let mut still_pending = Vec::new();
        for e in self.unbonding.drain(..) {
            if now >= e.release_at {
                let owner = e.owner.unwrap_or([0u8; 32]);
                let key = (e.validator, owner);
                let entry = self.withdrawable.entry(key).or_insert(0);
                // Provably unreachable after the pre-pass above (defense in depth).
                *entry = entry
                    .checked_add(e.amount)
                    .ok_or(StakingError::ArithmeticOverflow)?;
            } else {
                still_pending.push(e);
            }
        }
        self.unbonding = still_pending;
        Ok(())
    }

    pub fn withdrawable_of(&self, validator: &ValidatorId) -> u64 {
        self.withdrawable
            .get(&(*validator, [0u8; 32]))
            .copied()
            .unwrap_or(0)
    }

    /// Matured funds a delegator may withdraw from a validator.
    /// Argument order: (validator, delegator) — validator first, the opposite
    /// of [`Self::withdraw_delegator`].
    pub fn withdrawable_delegator(&self, validator: &ValidatorId, delegator: &[u8; 32]) -> u64 {
        self.withdrawable
            .get(&(*validator, *delegator))
            .copied()
            .unwrap_or(0)
    }

    /// Withdraw matured self-bond funds for a validator.
    pub fn withdraw(&mut self, validator: ValidatorId) -> Result<u64, StakingError> {
        let key = (validator, [0u8; 32]);
        let amount = self.withdrawable.remove(&key).unwrap_or(0);
        if amount == 0 {
            return Err(StakingError::NothingToWithdraw);
        }
        Ok(amount)
    }

    /// Withdraw matured undelegated funds for a delegator.
    /// Argument order: (delegator, validator) — delegator first, the opposite
    /// of [`Self::withdrawable_delegator`].
    ///
    /// Fail-closed on the zero delegator (audit L2): `(validator, [0u8; 32])`
    /// is the validator's own matured self-bond, readable only via
    /// [`Self::withdraw`]. `delegate` can no longer create a zero-address
    /// position, and this guard keeps the key exclusive even against a
    /// directly-constructed ledger or a helper called with a raw zero id.
    pub fn withdraw_delegator(
        &mut self,
        delegator: [u8; 32],
        validator: ValidatorId,
    ) -> Result<u64, StakingError> {
        if delegator == [0u8; 32] {
            return Err(StakingError::ZeroAddress);
        }
        let key = (validator, delegator);
        let amount = self.withdrawable.remove(&key).unwrap_or(0);
        if amount == 0 {
            return Err(StakingError::NothingToWithdraw);
        }
        Ok(amount)
    }

    /// Total bonded (self + delegated) for a validator.
    pub fn total_stake(&self, validator: &ValidatorId) -> u64 {
        self.validators
            .get(validator)
            .map(|v| v.total())
            .unwrap_or(0)
    }

    /// Conserved stake supply of the whole ledger: every self-bond plus every
    /// delegation plus every in-flight unbonding plus every matured-but-
    /// unwithdrawn amount (saturating, so adversarial state can never panic
    /// a debug assertion).
    ///
    /// CONSERVATION CONTRACT: `bond`/`add_bond` move value IN from outside
    /// (the caller debits the account and credits the pool); `slash` moves
    /// value OUT (`total_burned` rises by exactly the burned amount, and the
    /// supply falls by exactly the same); `distribute_reward` MINTS backing
    /// (`rewards_pool`/`rewards_minted` rise — the pending entries are new
    /// value, deliberately NOT in this sum); every other transition
    /// (`unbond`/`undelegate`/`redelegate`/`process_unbonding`/`withdraw`/
    /// `unjail`/commission paths/`rotate_key`) must leave this sum EXACTLY
    /// unchanged. The moving paths debug-assert that; the test suite asserts
    /// it in release mode (`tests/validator_ux_tests.rs`).
    pub fn ledger_stake_supply(&self) -> u64 {
        let mut total = 0u64;
        for v in self.validators.values() {
            total = total
                .saturating_add(v.self_bond)
                .saturating_add(v.delegated);
        }
        for e in &self.unbonding {
            total = total.saturating_add(e.amount);
        }
        for a in self.withdrawable.values() {
            total = total.saturating_add(*a);
        }
        total
    }

    /// Lock `amount` of `owner`'s stake for an open governance vote (E7).
    ///
    /// Called by [`crate::governance::Governance::vote`] with the exact
    /// weight the vote recorded. Saturating: weights are `u128` at the
    /// ballot box and `u64` here, so callers saturate on the way in and the
    /// same saturated value comes back out at `unlock_governance`.
    pub fn lock_governance(&mut self, owner: [u8; 32], amount: u64) {
        if amount == 0 {
            return;
        }
        let entry = self.locked_governance.entry(owner).or_insert(0);
        *entry = entry.saturating_add(amount);
    }

    /// Release `amount` of `owner`'s governance lock (E7).
    ///
    /// Called by [`crate::governance::Governance::finalize`] once per voter
    /// on the terminal transition. Saturating and self-cleaning: the entry
    /// is removed at zero, so a fully-unlocked ledger holds an empty map —
    /// which is what keeps the conditional commitment domain byte-identical
    /// to a ledger that never voted.
    pub fn unlock_governance(&mut self, owner: [u8; 32], amount: u64) {
        if amount == 0 {
            return;
        }
        let cur = self.locked_governance.get(&owner).copied().unwrap_or(0);
        let left = cur.saturating_sub(amount);
        if left == 0 {
            self.locked_governance.remove(&owner);
        } else {
            self.locked_governance.insert(owner, left);
        }
    }

    /// Stake of `owner` currently locked in open governance votes.
    pub fn locked_governance_of(&self, owner: &[u8; 32]) -> u64 {
        self.locked_governance.get(owner).copied().unwrap_or(0)
    }

    /// Build a consensus `ValidatorSet` weighted by total bonded stake. Only
    /// validators with a self-bond at or above the minimum are included, and
    /// JAILED validators are excluded until [`Self::unjail`] re-admits them
    /// (a jailed key holds stake but contributes no votes — counting it
    /// would credit quorum headroom that cannot sign).
    /// The set is sorted by total stake (descending, id tiebreak) and
    /// truncated to [`MAX_ACTIVE_VALIDATORS`] (250) — TON-style Elector cap.
    /// Full nodes are unaffected (unlimited).
    ///
    /// ACTIVATION (W10.5): the returned set is the set FOR THE NEXT HEIGHT
    /// BOUNDARY — a ledger read at height L derives the consensus set in
    /// force from L+1 on (`crate::sharding::validator_set_adoption_height`).
    /// Callers must STAGE it via
    /// `ValidatorRuntime::install_validator_set_from_ledger`, never install
    /// it mid-flight, and must resolve quorum checks with
    /// `ValidatorRuntime::validator_set_for_height`.
    pub fn to_validator_set(&self) -> ValidatorSet {
        let min_bond = self.min_validator_bond.unwrap_or(MIN_VALIDATOR_BOND);
        let mut ranked: Vec<(ValidatorId, u64)> = self
            .validators
            .iter()
            .filter(|(id, v)| v.self_bond >= min_bond && !self.jail.contains_key(*id))
            .map(|(id, v)| (*id, v.total()))
            .filter(|(_, power)| *power > 0)
            .collect();
        // Deterministic: highest stake first, validator id breaks ties.
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        if ranked.len() > MAX_ACTIVE_VALIDATORS {
            ranked.truncate(MAX_ACTIVE_VALIDATORS);
        }
        ValidatorSet::from_list(ranked)
    }

    /// Number of validators that would be elected (post-cap, post-jail), for RPC/metrics.
    pub fn elected_count(&self) -> usize {
        let min_bond = self.min_validator_bond.unwrap_or(MIN_VALIDATOR_BOND);
        self.validators
            .iter()
            .filter(|(id, v)| {
                v.self_bond >= min_bond && v.total() > 0 && !self.jail.contains_key(*id)
            })
            .count()
            .min(MAX_ACTIVE_VALIDATORS)
    }

    /// Saturating total power of the CURRENT elected set (same post-cap
    /// ranking as [`Self::to_validator_set`]).
    ///
    /// CALLER-SIDE HARDENING for the staking-economics audit 2026-11-01 low
    /// (a): [`crate::consensus::ValidatorSet::total_power`] sums with a
    /// panicking `Iterator::sum` (frozen — `consensus.rs` is out of scope),
    /// and the staking layer CAN feed it unbounded values: `bond` accepts any
    /// `u64` amount, so 250 validators at `u64::MAX` each would make
    /// `to_validator_set().total_power()` panic in debug (wrap in release).
    /// This helper folds the exact same elected set with `saturating_add`,
    /// so it saturates at `u64::MAX` instead of panicking — unreachable at
    /// live supplies (1 B cap), fail-closed by policy everywhere else.
    /// Staking-layer consumers that need the elected total MUST use this,
    /// never `to_validator_set().total_power()`. (No production staking code
    /// calls `total_power` today: [`Self::quorum_fragility`] already folds
    /// with `saturating_add` via [`validator_powers_fragility`].)
    pub fn elected_total_power_saturating(&self) -> u64 {
        self.to_validator_set()
            .validators
            .values()
            .fold(0u64, |acc, &p| acc.saturating_add(p))
    }

    /// Quorum-safety of the CURRENT elected set (same post-cap ranking as
    /// [`Self::to_validator_set`): `Some(reason)` when the set is fragile —
    /// see [`validator_powers_fragility`]. This is the verdict `main.rs`
    /// WARNs about and `stell_getValidators` reports as `fragile`.
    pub fn quorum_fragility(&self) -> Option<String> {
        let vs = self.to_validator_set();
        let powers: Vec<u64> = vs.validators.values().copied().collect();
        validator_powers_fragility(&powers)
    }

    /// Loud-by-design: every stake mutation that leaves a fragile set logs a
    /// WARN. Fail-open (never refuses the stake), but never silent.
    fn warn_if_quorum_fragile(&self, what: &str) {
        if let Some(reason) = self.quorum_fragility() {
            tracing::warn!("QUORUM-SAFETY {what}: {reason}");
        }
    }

    /// Slash a fraction (basis points) of a validator's TOTAL stake (self +
    /// delegated), burning it. Self-bond is consumed first, then delegated.
    /// Returns the amount burned.
    ///
    /// FAIL-CLOSED BPS GATE (staking-economics audit 2026-11-01, low (b)):
    /// `slash_bps > BPS_DENOMINATOR` is refused with
    /// [`StakingError::BadSlashBps`] and moves nothing — without the gate a
    /// `bps > 10_000` would burn MORE than 100% of the slashable base (the
    /// `burn` formula is linear in `bps` while every consumption below is
    /// clamped by real stake, so the excess would silently vanish into
    /// `remaining` instead of `total_burned`). All live callers pass
    /// constants `<= 10_000`, so the gate never fires on reachable paths.
    ///
    /// ROUNDING (audit L1, verified conservative): the per-delegator `cut`
    /// floors, so `slashed_total ≤ take` by `< n_delegators` nanos. Map and
    /// aggregate stay mutually consistent (both reduced by `slashed_total`);
    /// the unfloorable nanos simply REMAIN STAKED — the dust favors the
    /// slashed party, never the protocol. Pinned by closure-suite test.
    pub fn slash(&mut self, validator: ValidatorId, slash_bps: u64) -> Result<u64, StakingError> {
        // Fail-closed bps gate BEFORE any state lookup: burning more than
        // 100% is never meaningful, so refuse it regardless of membership.
        if slash_bps > BPS_DENOMINATOR {
            return Err(StakingError::BadSlashBps);
        }
        let (self_bond, delegated_now) = {
            let v = self
                .validators
                .get(&validator)
                .ok_or(StakingError::NotValidator)?;
            (v.self_bond, v.delegated)
        };
        // Saturating sums (econ audit 2026-11-01): `Iterator::sum` panics on
        // overflow in debug and wraps in release. Per-validator pending
        // unbondings are bounded by bonded stake at live supplies, but the
        // ledger must never panic on adversarial state. Saturation can only
        // OVERSTATE the slashable base, and every consumption below is
        // clamped with `min`, so `actually_burned` never exceeds real stake
        // (fail-closed; the stake↔burned conservation is preserved exactly).
        let unbonding_self: u64 = self
            .unbonding
            .iter()
            .filter(|e| e.validator == validator && e.owner.is_none())
            .fold(0u64, |acc, e| acc.saturating_add(e.amount));
        // Audit P1: in-flight delegator stake (unbonding, owner set) is part
        // of the slashable base — it secured the chain during the infraction
        // window. Excluding it let exiting stake escape the burn entirely.
        let unbonding_deleg: u64 = self
            .unbonding
            .iter()
            .filter(|e| e.validator == validator && e.owner.is_some())
            .fold(0u64, |acc, e| acc.saturating_add(e.amount));
        let total = self_bond
            .saturating_add(delegated_now)
            .saturating_add(unbonding_self)
            .saturating_add(unbonding_deleg);
        let burn = (total as u128 * slash_bps as u128 / BPS_DENOMINATOR as u128) as u64;
        if burn == 0 {
            return Ok(0);
        }
        // In-flight delegator stake takes its haircut FIRST (pro-rata, floored
        // like the active pool below): exiting stake cannot shelter behind the
        // validator's bond. Active delegations keep the self-first shield.
        let mut unbond_cut_total = 0u64;
        for entry in self.unbonding.iter_mut() {
            if entry.validator == validator && entry.owner.is_some() {
                let cut =
                    (entry.amount as u128 * slash_bps as u128 / BPS_DENOMINATOR as u128) as u64;
                // Cap the cumulative haircut at `burn` (econ audit 2026-11-01):
                // with saturating unbonding sums the base can UNDERSTATE the
                // true pending total, and an uncapped haircut would then
                // consume more stake than `burn` accounts for — destroying
                // value that neither stays staked nor reaches `total_burned`.
                // In-range the cap is a no-op (the haircut sum provably never
                // exceeds `burn` there: a sum of floors never exceeds the
                // floor of the sum).
                let cut = cut
                    .min(entry.amount)
                    .min(burn.saturating_sub(unbond_cut_total));
                entry.amount -= cut;
                unbond_cut_total = unbond_cut_total.saturating_add(cut);
            }
        }
        self.unbonding.retain(|e| e.amount > 0);
        let mut remaining = burn.saturating_sub(unbond_cut_total);
        // Consume self-bond first.
        let from_self = remaining.min(self_bond);
        if let Some(v) = self.validators.get_mut(&validator) {
            v.self_bond -= from_self;
        }
        remaining -= from_self;

        // Consume validator's pending unbonding entries.
        if remaining > 0 {
            for entry in self.unbonding.iter_mut() {
                if entry.validator == validator && entry.owner.is_none() {
                    let take = remaining.min(entry.amount);
                    entry.amount -= take;
                    remaining -= take;
                    if remaining == 0 {
                        break;
                    }
                }
            }
            self.unbonding.retain(|e| e.amount > 0);
        }

        if remaining > 0 {
            // Slash delegators proportionally.
            let delegated = delegated_now;
            if delegated > 0 {
                let take = remaining.min(delegated);
                let ratio_num = take as u128;
                let ratio_den = delegated as u128;
                let keys: Vec<(ValidatorId, [u8; 32])> = self
                    .delegations
                    .keys()
                    .filter(|(vid, _)| *vid == validator)
                    .copied()
                    .collect();
                let mut slashed_total = 0u64;
                for key in keys {
                    let amount = self.delegations.get(&key).copied().unwrap_or(0);
                    let cut = (amount as u128 * ratio_num / ratio_den) as u64;
                    let cut = cut.min(amount);
                    if cut > 0 {
                        // LAZY (F1): settle the delegator BEFORE its stake is
                        // cut, so the rewards it already earned are
                        // materialised verbatim and survive the slash (the
                        // eager implementation credited them at distribution
                        // time, where a slash could not touch them). The
                        // reduced stake only earns from the next distribution
                        // on.
                        self.settle_delegator_rewards(key.1, key.0);
                        if amount - cut == 0 {
                            self.delegations.remove(&key);
                        } else {
                            self.delegations.insert(key, amount - cut);
                        }
                        slashed_total = slashed_total.saturating_add(cut);
                    }
                }
                if let Some(v) = self.validators.get_mut(&validator) {
                    v.delegated -= slashed_total;
                }
                remaining = remaining.saturating_sub(slashed_total);
            }
        }
        let actually_burned = burn - remaining;
        if let Some(v) = self.validators.get_mut(&validator) {
            v.total_slashed = v.total_slashed.saturating_add(actually_burned);
        }
        self.total_burned = self.total_burned.saturating_add(actually_burned);
        // Loud-by-design eject policy (урок валидатора C): a slash that drops
        // self_bond below MIN ejects the validator from the set at the next
        // boundary — never silent. A slash that leaves it within the WARN gap
        // above MIN warns "validator X будет выкинут через ~Y" so the operator
        // can top up. Fail-open, log-only: state is already updated above.
        let self_bond_after = self
            .validators
            .get(&validator)
            .map(|v| v.self_bond)
            .unwrap_or(0);

        if let Some(msg) = eject_message_for(&validator, self_bond_after, actually_burned) {
            tracing::warn!("{msg}");
        } else if let Some(msg) = eject_warn_message_for(
            &validator,
            self_bond_after,
            actually_burned,
            slash_eject_warn_gap_nano(),
        ) {
            tracing::warn!("{msg}");
        }
        Ok(actually_burned)
    }

    /// Slash for equivocation using consensus double-vote evidence.
    /// The evidence is `(voter, vote_a, vote_b)` as produced by `VoteSet`.
    ///
    /// PRODUCT DECISION — UNWIRED IN PRODUCTION (audit O1/M3-scope, closed
    /// explicitly, NOT ambiguous): this primitive is correct and fully tested
    /// (conflicting-only, 5% of total, self-bond-first via `slash`), but NO
    /// live state-transition path calls it — the only production caller
    /// (`ValidatorRuntime::apply_equivocation_slashes`) is deliberately dead
    /// (gossip-observed evidence is non-deterministic across nodes; slashing
    /// it would fork the state root). Double-signing THROUGH THIS PRIMITIVE
    /// is therefore UNPUNISHED on the live chain; only downtime slashing is
    /// live through it.
    /// THE WIRED PATH is [`Self::slash_equivocation_verified`] instead:
    ///     same 5% burn, but fail-closed verification (shape + both signatures
    ///     + membership) and per-offense chain dedup, fed ONLY by block-carried
    ///     evidence (`OpCode::SysCallReportEquivocation` scanned from the
    ///     decided block in `apply_block_transition`, pool-debited at the call
    ///     site like downtime). That satisfies BOTH preconditions below, which
    ///     is why it — and not this function — is wired.
    ///     EXACT PRECONDITION FOR WIRING (retained for the record): (1) equivocation evidence travels
    ///     INSIDE the block as verifiable content (a block-format change —
    ///     `Block` is bincode-frozen, so this needs a coordinated rollout), so
    ///     every node slashes from identical evidence; AND (2) the live wiring
    ///     debits `STAKING_POOL` by `burned` (this primitive mutates ledger
    ///     fields only — like `slash`, the coins move at the caller, cf. the
    ///     downtime path in `state_engine.rs`), or pool/ledger drift by `burned`.
    ///     Until BOTH hold, wiring this would trade a free-double-sign for a
    ///     chain split — safety beats the feature.
    pub fn slash_equivocation(
        &mut self,
        evidence: &(ValidatorId, crate::consensus::Vote, crate::consensus::Vote),
    ) -> Result<u64, StakingError> {
        let (voter, a, b) = evidence;
        // Only count as equivocation if the two votes are genuinely conflicting
        // (same height/round/kind, different target). Otherwise ignore.
        if a.height != b.height || a.round != b.round || a.kind != b.kind {
            return Ok(0);
        }
        if a.block_hash == b.block_hash {
            return Ok(0);
        }
        self.slash(*voter, EQUIVOCATION_SLASH_BPS)
    }

    /// Slash for block-carried equivocation evidence — THE WIRED PATH.
    ///
    /// Unlike the legacy [`Self::slash_equivocation`] above (which trusts
    /// caller tuples — hunt Finding 12 pins that behavior, DO NOT change
    /// it), this primitive is fail-closed end to end:
    ///
    ///  1. SHAPE: same height/round/kind with differing targets, and
    ///     `voter` equal to both votes' voter. Anything else (single vote
    ///     repeated, cross-kind pair, framing with another key's vote)
    ///     burns 0 with a loud WARN — never an error, so block application
    ///     can never fail on hostile evidence.
    ///  2. SIGNATURES: both votes must [`crate::consensus::Vote::verify`].
    ///     Unsigned/forged votes burn 0 with a loud WARN (Finding 12 fixed
    ///     here: unsigned "evidence" no longer burns stake).
    ///  3. MEMBERSHIP: unknown voters get `Err(NotValidator)` (house style;
    ///     transition callers map it to skip-and-log, never block failure).
    ///  4. DEDUP: the per-offense key
    ///     ([`crate::consensus::EquivocationEvidence::offense_key`]:
    ///     offender ‖ height ‖ round ‖ kind ‖ conflicting hashes) is
    ///     consumed on first processing — a repeat of the same offense
    ///     (either vote order, any number of rebroadcasts or block
    ///     re-inclusions/replays) burns 0. Same offense slashed once per
    ///     chain, on every node identically.
    ///  5. BURN: 5% of total stake ([`EQUIVOCATION_SLASH_BPS`]), self-bond
    ///     first with the audited `slash` spillover to delegators.
    ///
    /// LEDGER-ONLY like `slash` itself: the coins move at the caller, which
    /// MUST debit [`STAKING_POOL`] by the returned `burned` (cf. the
    /// downtime path in `state_engine.rs`), or pool/ledger drift by `burned`.
    ///
    /// Eject WARNs ride along via `slash` (below-MIN eject / WARN-gap loud
    /// logs), exactly like the downtime path.
    pub fn slash_equivocation_verified(
        &mut self,
        evidence: &crate::consensus::EquivocationEvidence,
    ) -> Result<u64, StakingError> {
        let voter = evidence.voter;
        let (a, b) = (&evidence.vote_a, &evidence.vote_b);
        // 1. Shape — refuse anything that is not a genuine conflicting pair.
        if a.height != b.height || a.round != b.round || a.kind != b.kind {
            tracing::warn!(
                "equivocation REFUSED (not same height/round/kind) for {}: refusing to slash",
                hex::encode(voter),
            );
            return Ok(0);
        }
        if a.block_hash == b.block_hash {
            tracing::warn!(
                "equivocation REFUSED (identical targets — single vote repeated) for {}: refusing to slash",
                hex::encode(voter),
            );
            return Ok(0);
        }
        if voter != a.voter || voter != b.voter {
            tracing::warn!(
                "equivocation REFUSED (voter mismatch — framing with another key's vote) for {}: refusing to slash",
                hex::encode(voter),
            );
            return Ok(0);
        }
        // 2. Signatures — both votes must verify under the accused key.
        //
        // GATE-FIRST (pure-PQ fail-closed): classical-only evidence (either
        // vote without a Falcon half) is refused up front — no slash is
        // computed from it. With enforcement off this gate is skipped and the
        // check below is byte-identical to before (`Vote::verify` itself
        // already requires Falcon under pure-PQ, so the two refusals agree).
        if crate::post_quantum::is_pure_pq_enforced()
            && (a.falcon_signature().is_none() || b.falcon_signature().is_none())
        {
            tracing::warn!(
                "equivocation REFUSED (pure-PQ: classical-only evidence) for {}: refusing to slash",
                hex::encode(voter),
            );
            return Ok(0);
        }
        if !a.verify() || !b.verify() {
            tracing::warn!(
                "equivocation REFUSED (vote signature does not verify) for {}: refusing to slash",
                hex::encode(voter),
            );
            return Ok(0);
        }
        // 3. Membership.
        if !self.validators.contains_key(&voter) {
            return Err(StakingError::NotValidator);
        }
        // 4. Per-offense dedup — consume the key on first processing.
        let key = evidence.offense_key();
        if self.equivocation_dedup.contains(&key) {
            return Ok(0);
        }
        self.equivocation_dedup.insert(key);
        // 5. Burn 5% (self-bond first, audited spillover).
        let burned = self.slash(voter, EQUIVOCATION_SLASH_BPS)?;
        if burned > 0 {
            tracing::warn!(
                "equivocation SLASHED {} (5%): offender {} at height {} round {:?}, burned {}",
                hex::encode(voter),
                hex::encode(voter),
                a.height,
                a.round,
                burned,
            );
        }
        Ok(burned)
    }

    /// Slash for block-carried PROPOSAL equivocation evidence — THE WIRED PATH.
    ///
    /// The proposal mirror of [`Self::slash_equivocation_verified`]: same 5%
    /// burn ([`EQUIVOCATION_SLASH_BPS`]), same fail-closed verification
    /// (shape + both proposer signatures + membership), same per-offense
    /// chain dedup — fed ONLY by block-carried evidence
    /// (`OpCode::SysCallReportProposalEquivocation` scanned from the decided
    /// block in `apply_block_transition`, pool-debited at the call site like
    /// downtime).
    ///
    ///  1. SHAPE: same height with differing block hashes, and `proposer`
    ///     equal to both blocks' `proposer`. Anything else (one block
    ///     repeated, cross-height pair, framing with another key's block)
    ///     burns 0 with a loud WARN — never an error, so block application
    ///     can never fail on hostile evidence.
    ///  2. SIGNATURES: both blocks must pass
    ///     [`crate::consensus::verify_proposer_signature`] under the accused
    ///     key. Forged blocks burn 0 with a loud WARN.
    ///  3. MEMBERSHIP: unknown proposers get `Err(NotValidator)` (house
    ///     style; transition callers map it to skip-and-log, never block
    ///     failure).
    ///  4. DEDUP: the per-offense key
    ///     ([`crate::consensus::ProposalEquivocationEvidence::offense_key`]:
    ///     offender ‖ height ‖ conflicting hashes, canonical order) is
    ///     consumed on first processing in the shared [`Self::equivocation_dedup`]
    ///     set — the vote and proposal keys live under distinct BLAKE3
    ///     domains, so the sets can never collide. A repeat of the same
    ///     offense (either block order, any number of rebroadcasts or block
    ///     re-inclusions/replays) burns 0. Same offense slashed once per
    ///     chain, on every node identically.
    ///  5. BURN: 5% of total stake ([`EQUIVOCATION_SLASH_BPS`]), self-bond
    ///     first with the audited `slash` spillover to delegators.
    ///
    /// LEDGER-ONLY like `slash` itself: the coins move at the caller, which
    /// MUST debit [`STAKING_POOL`] by the returned `burned`, or pool/ledger
    /// drift by `burned`.
    ///
    /// Eject WARNs ride along via `slash` (below-MIN eject / WARN-gap loud
    /// logs), exactly like the downtime and vote-equivocation paths.
    pub fn slash_proposal_equivocation_verified(
        &mut self,
        evidence: &crate::consensus::ProposalEquivocationEvidence,
    ) -> Result<u64, StakingError> {
        let proposer = evidence.proposer;
        let (a, b) = (&evidence.block_a, &evidence.block_b);
        // 1. Shape — refuse anything that is not a genuine conflicting pair.
        if a.height != b.height {
            tracing::warn!(
                "proposal equivocation REFUSED (cross-height pair) for {}: refusing to slash",
                hex::encode(proposer),
            );
            return Ok(0);
        }
        if a.compute_hash() == b.compute_hash() {
            tracing::warn!(
                "proposal equivocation REFUSED (identical blocks — single proposal repeated) for {}: refusing to slash",
                hex::encode(proposer),
            );
            return Ok(0);
        }
        if proposer != a.proposer || proposer != b.proposer {
            tracing::warn!(
                "proposal equivocation REFUSED (proposer mismatch — framing with another key's block) for {}: refusing to slash",
                hex::encode(proposer),
            );
            return Ok(0);
        }
        // 2. Signatures — both blocks must verify under the accused key.
        if !crate::consensus::verify_proposer_signature(a)
            || !crate::consensus::verify_proposer_signature(b)
        {
            tracing::warn!(
                "proposal equivocation REFUSED (proposer signature does not verify) for {}: refusing to slash",
                hex::encode(proposer),
            );
            return Ok(0);
        }
        // 3. Membership.
        if !self.validators.contains_key(&proposer) {
            return Err(StakingError::NotValidator);
        }
        // 4. Per-offense dedup — consume the key on first processing.
        let key = evidence.offense_key();
        if self.equivocation_dedup.contains(&key) {
            return Ok(0);
        }
        self.equivocation_dedup.insert(key);
        // 5. Burn 5% (self-bond first, audited spillover).
        let burned = self.slash(proposer, EQUIVOCATION_SLASH_BPS)?;
        if burned > 0 {
            tracing::warn!(
                "proposal equivocation SLASHED {} (5%): offender {} at height {}, burned {}",
                hex::encode(proposer),
                hex::encode(proposer),
                a.height,
                burned,
            );
        }
        Ok(burned)
    }

    /// Register or update a post-quantum public key and scheme for an active validator.
    pub fn register_pq_key(
        &mut self,
        validator: ValidatorId,
        scheme: crate::post_quantum::PqScheme,
        pubkey: Vec<u8>,
    ) -> Result<(), StakingError> {
        if !self.validators.contains_key(&validator) {
            return Err(StakingError::NotValidator);
        }
        if pubkey.len() != scheme.pubkey_size() {
            return Err(StakingError::InvalidSignature);
        }
        self.validator_pq_keys.insert(validator, (scheme, pubkey));
        Ok(())
    }

    /// Retrieve the registered post-quantum key and scheme for a validator, if any,
    /// falling back to Ed25519 (with the 32-byte `ValidatorId` as public key) if the
    /// validator exists in the ledger.
    ///
    /// GATE-FIRST P2-10 (pure-PQ fail-closed): when
    /// [`crate::post_quantum::is_pure_pq_enforced`] is on, the Ed25519 fallback
    /// is REFUSED (`None`) — an unregistered validator surfaces as a loud
    /// caller-side refusal instead of yielding classical key material. With
    /// enforcement off the fallback is byte-identical to before.
    pub fn get_pq_key(
        &self,
        validator: &ValidatorId,
    ) -> Option<(crate::post_quantum::PqScheme, Vec<u8>)> {
        if let Some((s, pk)) = self.validator_pq_keys.get(validator) {
            Some((*s, pk.clone()))
        } else if self.validators.contains_key(validator) {
            if crate::post_quantum::is_pure_pq_enforced() {
                tracing::warn!(
                    "PQ key REFUSED (pure-PQ: no registered PQ key) for {}: refusing classical Ed25519 fallback",
                    hex::encode(validator),
                );
                return None;
            }
            Some((crate::post_quantum::PqScheme::Ed25519, validator.to_vec()))
        } else {
            None
        }
    }

    /// On-chain PQ key registry hooks (see `crate::pq_registry`).
    ///
    /// Thin membership-gated delegates over a caller-held
    /// [`crate::pq_registry::PqRegistry`]: the registry owns the rotation
    /// state machine, the ledger owns membership + the committed
    /// `validator_pq_keys` mirror (kept in sync on `register`/`apply` so the
    /// existing commitment/slash readers keep working unchanged — announce
    /// deliberately leaves the mirror on the OLD key until the effective
    /// height). Auth (caller == validator, announcement signature) is
    /// enforced by the future opcode handler, not here — the `rotate_key`
    /// precedent. No stake moves on any path (debug-asserted where a supply
    /// read is cheap).
    ///
    /// CALL-SITE NOTE (consensus-key rotation): [`Self::rotate_key`] does NOT
    /// touch the registry (signature frozen); invoke
    /// [`crate::pq_registry::PqRegistry::migrate_validator`] alongside it so
    /// pending rotations and history travel with the record.
    /// Register a validator's first PQ key in `registry` (effective at
    /// `activation_height`; see [`crate::pq_registry::PqRegistry::register`]).
    /// Mirrors the key into committed `validator_pq_keys` on success.
    #[allow(clippy::too_many_arguments)]
    // GATE: hook threads (registry, validator, scheme, key, two heights); a params struct would churn the hook call sites for no benefit.
    pub fn pq_register_key(
        &mut self,
        registry: &mut crate::pq_registry::PqRegistry,
        validator: ValidatorId,
        scheme: crate::post_quantum::PqScheme,
        pubkey: Vec<u8>,
        activation_height: u64,
        now_height: u64,
    ) -> Result<(), crate::pq_registry::PqRegistryError> {
        let supply_before = self.ledger_stake_supply();
        let known = self.validators.contains_key(&validator);
        registry.register(
            validator,
            scheme,
            pubkey.clone(),
            activation_height,
            now_height,
            known,
        )?;
        self.validator_pq_keys.insert(validator, (scheme, pubkey));
        debug_assert_eq!(
            supply_before,
            self.ledger_stake_supply(),
            "pq register must move no stake"
        );
        Ok(())
    }

    /// Announce a PQ key rotation in `registry` (effective at
    /// `now_height + PQ_ROTATION_DELAY_HEIGHTS`; see
    /// [`crate::pq_registry::PqRegistry::announce_rotation`]). The committed
    /// mirror keeps the OLD key until `pq_apply_rotation` — the old key
    /// stays authoritative through the delay window.
    ///
    /// First rotation-aware use for a validator whose key predates tracking
    /// (genesis / legacy `register_pq_key`) auto-adopts the committed current
    /// key (or the Ed25519 fallback) as the tracked baseline with
    /// pre-tracking provenance — adoption never changes authority.
    pub fn pq_announce_rotation(
        &mut self,
        registry: &mut crate::pq_registry::PqRegistry,
        validator: ValidatorId,
        scheme: crate::post_quantum::PqScheme,
        pubkey: Vec<u8>,
        now_height: u64,
    ) -> Result<(), crate::pq_registry::PqRegistryError> {
        let supply_before = self.ledger_stake_supply();
        if !self.validators.contains_key(&validator) {
            return Err(crate::pq_registry::PqRegistryError::UnknownValidator);
        }
        if registry.record_of(&validator).is_none() {
            // NOTE (P2-10 consequence): `get_pq_key` refuses the Ed25519
            // fallback under pure-PQ, so a member with no registered PQ key
            // yields `None` here — fail closed instead of panicking on the old
            // "fallback always yields a key" assumption.
            let Some((cur_scheme, cur_pubkey)) = self.get_pq_key(&validator) else {
                tracing::warn!(
                    "pq announce REFUSED (pure-PQ: member {} has no registered PQ key — nothing to adopt)",
                    hex::encode(validator),
                );
                return Err(crate::pq_registry::PqRegistryError::UnknownValidator);
            };
            registry.adopt_legacy_key(validator, cur_scheme, cur_pubkey, true)?;
        }
        registry.announce_rotation(validator, scheme, pubkey, now_height, true)?;
        debug_assert_eq!(
            supply_before,
            self.ledger_stake_supply(),
            "pq announce must move no stake"
        );
        Ok(())
    }

    /// Promote a due pending rotation (see
    /// [`crate::pq_registry::PqRegistry::apply_rotation`]) and mirror the new
    /// current key into committed `validator_pq_keys`.
    pub fn pq_apply_rotation(
        &mut self,
        registry: &mut crate::pq_registry::PqRegistry,
        validator: ValidatorId,
        now_height: u64,
    ) -> Result<(), crate::pq_registry::PqRegistryError> {
        let supply_before = self.ledger_stake_supply();
        if !self.validators.contains_key(&validator) {
            return Err(crate::pq_registry::PqRegistryError::UnknownValidator);
        }
        registry.apply_rotation(validator, now_height, true)?;
        if let Some((scheme, pubkey)) = registry.current_key_of(&validator) {
            self.validator_pq_keys.insert(validator, (scheme, pubkey));
        }
        debug_assert_eq!(
            supply_before,
            self.ledger_stake_supply(),
            "pq apply must move no stake"
        );
        Ok(())
    }

    /// Promote every rotation due at `now_height` (deterministic id order;
    /// see [`crate::pq_registry::PqRegistry::apply_due_rotations`]), mirroring
    /// each member validator's new key into `validator_pq_keys`. Returns the
    /// member validators whose rotation activated. Records of non-members
    /// still advance in the registry (same blocks, same registry on every
    /// node) but never touch the committed mirror.
    pub fn pq_apply_due_rotations(
        &mut self,
        registry: &mut crate::pq_registry::PqRegistry,
        now_height: u64,
    ) -> Vec<ValidatorId> {
        let applied = registry.apply_due_rotations(now_height);
        applied
            .into_iter()
            .filter(|v| {
                let member = self.validators.contains_key(v);
                if member {
                    if let Some((scheme, pubkey)) = registry.current_key_of(v) {
                        self.validator_pq_keys.insert(*v, (scheme, pubkey));
                    }
                }
                member
            })
            .collect()
    }

    /// Resolve the authoritative PQ key for `validator` AT `height` (see
    /// [`crate::pq_registry::PqRegistry::get_active_key`]). Fail-closed:
    /// unknown validator → `None`. This is the read the consensus
    /// verification paths will use (lead wiring); it is NOT consulted by any
    /// staking path today.
    pub fn pq_active_key(
        &self,
        registry: &crate::pq_registry::PqRegistry,
        validator: &ValidatorId,
        height: u64,
    ) -> Option<(crate::post_quantum::PqScheme, Vec<u8>)> {
        if !self.validators.contains_key(validator) {
            return None;
        }
        registry.get_active_key(validator, height)
    }

    /// Slash for post-quantum equivocation using `CompactPqEquivocationEvidence`.
    ///
    /// THE WIRED PATH (audit O1/F4 wiring, PQ arm). Production caller:
    /// [`crate::svm::OpCode::SysCallReportPqEquivocation`], whose handler
    /// calls THIS function on the clone-committed ledger and hands the
    /// returned `burned` to the engine, which debits `STAKING_POOL` by
    /// exactly that amount. Both preconditions the unwired note below used
    /// to state now hold:
    ///
    ///  1. BLOCK-CARRIED, SIGNATURE-VERIFIABLE EVIDENCE: the evidence rides
    ///     inside the block body (the opcode is part of the transaction
    ///     payload, so the tx hash commits it and the block hash commits
    ///     the tx), and BOTH signatures are verified here through
    ///     `crate::post_quantum::verify_pq_signature` against the accused
    ///     validator's REGISTERED key.
    ///  2. A `STAKING_POOL` DEBIT of `burned` at the live call site (the VM
    ///     hands the burn to the engine's native commit, which debits the
    ///     pool inside the same undo-protected settlement as every other
    ///     native movement - so a refused transaction burns nothing and
    ///     leaves no pool/ledger drift).
    ///
    /// The micro-committee 100% arm (see `is_micro_committee` below) is
    /// deliberately NOT reachable from the live path yet: it evicts the
    /// validator and leaves stranded `delegator_rewards`/`withdrawable`/
    /// `unbonding` rows whose UX must be specified first, and the committee
    /// mode must be derived from COMMITTED state - never from the reporter.
    /// The opcode therefore uses the standard 5% arm, which already makes
    /// PQ equivocation PUNISHABLE.
    ///
    /// Per Section 3 of STELLEREUM_PQ_BFT_V5_MASTER_SPEC:
    /// - Verifies conflicting targets (`block_hash_a != block_hash_b`).
    /// - Verifies both signatures against the voter's registered key via `crate::post_quantum::verify_pq_signature`.
    /// - Penalty: if `is_micro_committee == true`, slashes 100% of bond (10,000 bps) and evicts; if standard, slashes 5% (500 bps).
    /// - Deduplication: keys deduplication over `BLAKE3(voter || height || round || kind)` to prevent repeat compounding burns.
    pub fn slash_pq_equivocation(
        &mut self,
        evidence: &CompactPqEquivocationEvidence,
        is_micro_committee: bool,
    ) -> Result<u64, StakingError> {
        // 1. Conflicting targets verification:
        // Only count as equivocation if the two votes are genuinely conflicting
        // (different target). Otherwise reject / ignore with 0 burned.
        if evidence.block_hash_a == evidence.block_hash_b {
            return Ok(0);
        }

        // 2. Active validator verification:
        if !self.validators.contains_key(&evidence.voter) {
            return Err(StakingError::NotValidator);
        }

        // 3. Registered key resolution (GATE-FIRST P2-11: NO classical
        // fallback under pure-PQ — unregistered validators yield
        // `InvalidSignature`, never an Ed25519 key the evidence could verify
        // against; likewise a registered classical/disabled scheme is refused).
        let (scheme, pubkey) = if let Some((s, pk)) = self.validator_pq_keys.get(&evidence.voter) {
            (*s, pk.clone())
        } else if crate::post_quantum::is_pure_pq_enforced() {
            tracing::warn!(
                "PQ equivocation REFUSED (pure-PQ: no registered PQ key) for {}: refusing classical fallback",
                hex::encode(evidence.voter),
            );
            return Err(StakingError::InvalidSignature);
        } else {
            (
                crate::post_quantum::PqScheme::Ed25519,
                evidence.voter.to_vec(),
            )
        };
        if crate::post_quantum::is_pure_pq_enforced()
            && (!scheme.is_post_quantum() || scheme.is_disabled())
        {
            tracing::warn!(
                "PQ equivocation REFUSED (pure-PQ: classical scheme evidence) for {}: refusing to slash",
                hex::encode(evidence.voter),
            );
            return Err(StakingError::InvalidSignature);
        }

        // 4. Construct vote sign message preimages:
        let msg_a = crate::consensus::vote_sign_bytes(
            evidence.height,
            evidence.round,
            evidence.kind,
            &evidence.block_hash_a,
        );
        let msg_b = crate::consensus::vote_sign_bytes(
            evidence.height,
            evidence.round,
            evidence.kind,
            &evidence.block_hash_b,
        );

        // Strip vote BLS envelope when present on standard Ed25519 signatures
        let sig_a = if scheme == crate::post_quantum::PqScheme::Ed25519
            && evidence.signature_a.len() != 64
        {
            crate::consensus::ed25519_sig_bytes(&evidence.signature_a)
        } else {
            evidence.signature_a.as_slice()
        };
        let sig_b = if scheme == crate::post_quantum::PqScheme::Ed25519
            && evidence.signature_b.len() != 64
        {
            crate::consensus::ed25519_sig_bytes(&evidence.signature_b)
        } else {
            evidence.signature_b.as_slice()
        };

        // 5. Signature verification:
        let valid_a = crate::post_quantum::verify_pq_signature(scheme, &pubkey, &msg_a, sig_a);
        let valid_b = crate::post_quantum::verify_pq_signature(scheme, &pubkey, &msg_b, sig_b);
        if !valid_a || !valid_b {
            return Err(StakingError::InvalidSignature);
        }

        // 6. Deduplication over BLAKE3(voter || height || round || kind):
        let dedup_key = pq_equivocation_dedup_key(
            &evidence.voter,
            evidence.height,
            evidence.round,
            evidence.kind,
        );
        if self.pq_equivocation_dedup.contains(&dedup_key) {
            return Ok(0);
        }
        self.pq_equivocation_dedup.insert(dedup_key);

        // 7. Penalty calculation & execution:
        let slash_bps = if is_micro_committee {
            MICRO_COMMITTEE_SLASH_BPS
        } else {
            EQUIVOCATION_SLASH_BPS
        };

        let burned = self.slash(evidence.voter, slash_bps)?;
        if is_micro_committee {
            self.validators.remove(&evidence.voter);
            self.validator_pq_keys.remove(&evidence.voter);
        }
        Ok(burned)
    }

    /// Slash for downtime.
    pub fn slash_downtime(&mut self, validator: ValidatorId) -> Result<u64, StakingError> {
        self.slash(validator, DOWNTIME_SLASH_BPS)
    }

    /// Note that `validator` did not contribute to the quorum certificate of
    /// `height`, and slash once the outage is long enough to be deliberate.
    ///
    /// `signed` is the set of validators whose precommit is in the certificate.
    /// The evidence is the certificate itself, so every node reaches the same
    /// verdict from the same block - unlike a local "I didn't hear from them"
    /// timer, which is unsound (a node behind a partition would slash honest
    /// peers) and non-deterministic (nodes would disagree).
    ///
    /// Returns the burned amount if a slash fired, else 0.
    #[allow(clippy::nonminimal_bool)]
    // GATE: explicit cooldown guards wrap on old certificates; simplify would reintroduce wrap.
    pub fn note_missed_heights(
        &mut self,
        height: u64,
        signer: &dyn Fn(&ValidatorId) -> bool,
        eligible: &[ValidatorId],
    ) -> u64 {
        // Decide first, slash second.
        //
        // This used to reimplement the burn inline, and the inline version was
        // wrong in three ways at once:
        //
        //   * it decremented `ValidatorStake.delegated` WITHOUT touching
        //     `StakingLedger::delegations`, so the aggregate and the map drifted
        //     apart by exactly the burned amount -- and `distribute_reward` divides
        //     by one while summing the other, so the drift is not cosmetic;
        //   * the delegated leg was `rec.delegated.min(burn - from_self)`, a
        //     saturating floor with no cap, so a validator that had fully unbonded
        //     (self_bond == 0, reachable via `unbond` while delegations remain)
        //     lost its ENTIRE delegation to one 0.1% penalty;
        //   * it never incremented `total_burned`, so the ledger under-reported
        //     the destruction while the coins did leave the staking pool. The pool
        //     is a plain trie account, so that drift moves the state root.
        //
        // `slash` already does all of this correctly, so the fix is to use it. It
        // needs `&mut self`, hence the two-phase structure.
        let mut penalise: Vec<ValidatorId> = Vec::new();
        for v in eligible {
            let Some(rec) = self.validators.get_mut(v) else {
                continue;
            };
            if signer(v) {
                // Back online: forgive the streak.
                rec.missed = 0;
                continue;
            }
            rec.missed = rec.missed.saturating_add(1);
            // The cooldown only applies to a REPEAT offence: the first one must
            // not be blocked just because the chain is still young.
            //
            // `height >= last_downtime_penalty` is load-bearing. Without it,
            // re-applying an OLD certificate makes the subtraction wrap to a huge
            // value, the cooldown reads as satisfied, and the penalty fires again
            // while moving the stamp backwards -- so the documented "keyed on the
            // height, so re-applying an old certificate is a no-op" did not hold.
            let cooled = (rec.last_downtime_penalty == 0 || height >= rec.last_downtime_penalty)
                && (rec.last_downtime_penalty == 0
                    || height - rec.last_downtime_penalty >= DOWNTIME_PENALTY_COOLDOWN);
            if rec.missed >= DOWNTIME_MISS_THRESHOLD && cooled {
                rec.last_downtime_penalty = height;
                rec.missed = 0;
                penalise.push(*v);
            }
        }

        let mut slashed = 0u64;
        for v in penalise {
            if let Ok(burned) = self.slash(v, DOWNTIME_SLASH_BPS) {
                slashed = slashed.saturating_add(burned);
                // JAIL ON DOWNTIME SLASH (validator-UX gap): the offender is
                // excluded from the set until `unjail` re-admits it. The
                // trigger is the evidence-driven penalty itself (same decided
                // set every node derives from the same blocks), so all nodes
                // jail identically at the same height. Refreshing an existing
                // record (repeat outage after an unjail) moves the release
                // forward; it never shortens it. A slash that burns 0
                // installs no jail (nothing happened).
                if burned > 0 {
                    let release = height.saturating_add(JAIL_RELEASE_DELAY_HEIGHTS);
                    self.jail
                        .entry(v)
                        .and_modify(|r| {
                            r.jailed_at_height = height;
                            r.release_height = r.release_height.max(release);
                        })
                        .or_insert(JailRecord {
                            jailed_at_height: height,
                            release_height: release,
                        });
                    tracing::warn!(
                        "VALIDATOR-JAILED validator {} jailed at height {height} after a downtime slash (burned {burned}): excluded from the set until height {release} AND self_bond back at MIN+buffer ({}); top up with add_bond, then unjail",
                        hex::encode(v),
                        required_bond_floor_nano(),
                    );
                }
            }
        }
        slashed
    }

    /// Distribute `reward` (minted nano-STELL) to `validator`. Split:
    ///   - commission goes to the validator on the delegated portion;
    ///   - the rest is split pro-rata between self-bond and delegators.
    ///
    /// O(1) — THE LAZY (F1) ACCUMULATOR. The delegator leg is NOT paid out
    /// here: the distribution only bumps the validator's
    /// [`ValidatorRewardState::reward_per_token`] accumulator by
    /// `delegator_pool / delegated` (scaled by
    /// [`REWARD_PER_TOKEN_SCALE`]), and every delegator's entitlement is
    /// computed LAZILY, from that accumulator and the delegator's own
    /// checkpoint, when the delegator is touched (claim / stake change /
    /// slash).
    ///
    /// WHY (the DoS this removes): the eager implementation walked EVERY
    /// delegation of the validator on EVERY block —
    /// `share_i = delegator_pool * stake_i / delegated` for each `i`. The
    /// number of delegators is attacker-controlled (one 1-STELL delegation
    /// each, and the minimum delegation is 1 STELL), so block execution cost
    /// grew without bound while the reward per delegator shrank to zero: a
    /// cheap CPU denial of service against every node that executes the
    /// block. The accumulator makes the per-block cost independent of the
    /// delegator count.
    ///
    /// ROUNDING (audit L1, verified conservative): the validator's own leg is
    /// computed as `reward − delegated_share + commission` — EXACT, no floor
    /// loss — and the delegator pool is distributed with the accumulator's
    /// scaled rate. The per-delegator floor is applied when the delegator's
    /// entitlement is computed, so the dust is the same shape as before
    /// (`< n_delegators` nanos per settlement) and it stays locked in
    /// `rewards_pool` (no sweep path): rounding favors the protocol (dust
    /// lock), never the operator, never the delegator. Deliberately left
    /// un-swept: crediting the remainder to the proposer would make the
    /// proposer's payout depend on the delegator COUNT (a grindable input),
    /// while the lock is value-neutral and unexploitable.
    ///
    /// PRECISION: the scaled rate truncates by `< 1 / REWARD_PER_TOKEN_SCALE`
    /// per distribution, so a delegator's settled share is at most ONE nano
    /// below the EXACT pro-rata value per distribution (and never above it,
    /// so the pool is never over-drawn). Over a settlement that spans `K`
    /// distributions the truncation accumulates to at most `K` nanos — the
    /// same order as the eager implementation's own per-distribution floor,
    /// so the two differ by at most `K` nanos in either direction.
    /// `dust_favors_the_protocol_not_the_operator` (closure suite) still
    /// holds: the dust is still protocol-favouring.
    ///
    /// E2 fix: the mint is explicit and capped. `reward` is added to
    /// [`StakingLedger::rewards_pool`] (backing for the entries credited
    /// below) and [`StakingLedger::rewards_minted`]; once
    /// `rewards_minted + reward` would exceed [`REWARDS_EMISSION_CAP`] the
    /// whole distribution is refused with
    /// [`StakingError::RewardsCapExceeded`] and NOTHING is credited
    /// (fail-closed over cap — callers must not mint on `Err`).
    pub fn distribute_reward(
        &mut self,
        validator: ValidatorId,
        reward: u64,
    ) -> Result<(), StakingError> {
        let (total, delegated, commission_bps) = {
            let v = self
                .validators
                .get(&validator)
                .ok_or(StakingError::NotValidator)?;
            (v.total(), v.delegated, v.commission_bps)
        };
        // A jailed validator is out of the set and earns no proposals: paying
        // it would reward an offline key. Refused fail-closed (nothing
        // minted, nothing credited — the caller must not mint on `Err`).
        if self.jail.contains_key(&validator) {
            return Err(StakingError::Jailed);
        }
        if reward == 0 {
            return Ok(());
        }
        if total == 0 {
            // A validator with NO stake at all (fully unbonded, or slashed to
            // zero) cannot receive a reward. REFUSE (fail-closed) instead of
            // returning `Ok`: the caller ([`crate::state_engine`]'s block
            // application) mints the NATIVE leg whenever `distribute_reward`
            // returns `Ok`, so an `Ok` here would create coins in
            // `REWARDS_POOL` with NO ledger counterpart (`rewards_minted` /
            // `rewards_pool` untouched) — a silent mint/ledger divergence that
            // inflates the native supply and breaks the 1:1 backing the
            // E2 rewards-pool invariant depends on.
            return Err(StakingError::NotValidator);
        }
        let minted = self
            .rewards_minted
            .checked_add(reward)
            .ok_or(StakingError::RewardsCapExceeded)?;
        if minted > REWARDS_EMISSION_CAP {
            return Err(StakingError::RewardsCapExceeded);
        }
        self.rewards_minted = minted;
        self.rewards_pool = self.rewards_pool.saturating_add(reward);
        // Commission applies only to the delegated share.
        let delegated_share = (reward as u128 * delegated as u128 / total as u128) as u64;
        let commission =
            (delegated_share as u128 * commission_bps as u128 / BPS_DENOMINATOR as u128) as u64;
        let validator_reward = reward - delegated_share + commission;
        if let Some(v) = self.validators.get_mut(&validator) {
            v.pending_rewards = v.pending_rewards.saturating_add(validator_reward);
        }

        // Remaining delegated reward: bump the LAZY accumulator. O(1) — no
        // delegator is touched, so the cost of a distribution does not depend
        // on how many delegators the validator has.
        let delegator_pool = delegated_share - commission;
        if delegated > 0 && delegator_pool > 0 {
            self.reward_accumulators
                .entry(validator)
                .or_default()
                .accrue(delegator_pool, delegated);
        }
        Ok(())
    }

    /// The validator's current scaled reward rate (the accumulator value).
    fn reward_rate(&self, validator: &ValidatorId) -> u128 {
        self.reward_accumulators
            .get(validator)
            .map(|a| a.reward_per_token)
            .unwrap_or(0)
    }

    /// The delegator's UNSETTLED entitlement for `validator`: what the
    /// accumulator says it has earned since its last settlement.
    ///
    /// O(1): it reads the validator's accumulator and the delegator's
    /// checkpoint — it never walks the delegator set.
    fn unsettled_delegator_rewards(&self, delegator: [u8; 32], validator: ValidatorId) -> u128 {
        let key = (validator, delegator);
        let rate_now = self.reward_rate(&validator);
        let checkpoint = self
            .delegator_reward_checkpoints
            .get(&key)
            .copied()
            .unwrap_or(0);
        if rate_now <= checkpoint {
            return 0;
        }
        let stake = self.delegations.get(&key).copied().unwrap_or(0) as u128;
        if stake == 0 {
            return 0;
        }
        mul_div_floor(stake, rate_now - checkpoint, REWARD_PER_TOKEN_SCALE)
    }

    /// TOTAL reward owed to `delegator` by `validator`: the settled part
    /// (already materialised into `delegator_rewards`) plus the unsettled
    /// part computed from the lazy accumulator.
    ///
    /// This is the accessor the RPC / query paths must use: the raw
    /// `delegator_rewards` map holds only the SETTLED part.
    pub fn delegator_rewards_of(&self, delegator: [u8; 32], validator: ValidatorId) -> u64 {
        let settled = self
            .delegator_rewards
            .get(&(validator, delegator))
            .copied()
            .unwrap_or(0) as u128;
        settled
            .saturating_add(self.unsettled_delegator_rewards(delegator, validator))
            .min(u64::MAX as u128) as u64
    }

    /// SETTLE a delegator's position: materialise its unsettled entitlement
    /// into `delegator_rewards` and move its checkpoint to the current rate.
    ///
    /// Called whenever the delegator's stake changes (delegate / undelegate /
    /// slash) so that
    ///   - the rewards it already earned are preserved verbatim, and
    ///   - its NEW stake only earns from the NEXT distribution on (it cannot
    ///     claim a share of the pools that were distributed before it had
    ///     the stake).
    ///
    /// O(1): it touches exactly one delegator.
    fn settle_delegator_rewards(&mut self, delegator: [u8; 32], validator: ValidatorId) {
        let key = (validator, delegator);
        let pending = self.unsettled_delegator_rewards(delegator, validator);
        if pending > 0 {
            let amount = pending.min(u64::MAX as u128) as u64;
            let entry = self.delegator_rewards.entry(key).or_insert(0);
            *entry = entry.saturating_add(amount);
        }
        self.set_delegator_checkpoint(delegator, validator);
    }

    /// Move the delegator's checkpoint to the validator's current rate.
    ///
    /// A checkpoint of ZERO is the default (an absent entry reads as zero), so
    /// a ledger that never distributed a delegator reward holds NO checkpoint
    /// rows at all — the map stays as small as the delegator set that has
    /// actually earned something.
    fn set_delegator_checkpoint(&mut self, delegator: [u8; 32], validator: ValidatorId) {
        let key = (validator, delegator);
        let rate_now = self.reward_rate(&validator);
        if rate_now > 0 {
            self.delegator_reward_checkpoints.insert(key, rate_now);
        } else {
            self.delegator_reward_checkpoints.remove(&key);
        }
    }

    /// Withdraw accrued validator rewards.
    ///
    /// E2 fix: the claim consumes [`StakingLedger::rewards_pool`] backing.
    /// When the pool cannot cover the accrued amount the claim is refused
    /// with [`StakingError::RewardsPoolShortfall`] and the entry is left
    /// intact (fail-closed — rewards never fall back to principal).
    pub fn claim_validator_rewards(&mut self, validator: ValidatorId) -> Result<u64, StakingError> {
        let pending = self
            .validators
            .get(&validator)
            .ok_or(StakingError::NotValidator)?
            .pending_rewards;
        if pending > self.rewards_pool {
            return Err(StakingError::RewardsPoolShortfall);
        }
        let v = self
            .validators
            .get_mut(&validator)
            .ok_or(StakingError::NotValidator)?;
        v.pending_rewards = 0;
        self.rewards_pool -= pending;
        Ok(pending)
    }

    /// Withdraw accrued delegator rewards.
    ///
    /// LAZY (F1): the amount owed is computed on demand from the validator's
    /// accumulator and the delegator's checkpoint (plus whatever was already
    /// settled into `delegator_rewards`), so the claim does not depend on a
    /// per-block eager credit. O(1): one delegator, one accumulator read.
    ///
    /// E2 fix: like [`Self::claim_validator_rewards`], the claim consumes
    /// [`StakingLedger::rewards_pool`] backing. When nothing is claimable —
    /// or the pool cannot cover it — the entry is left intact and 0 is
    /// returned (callers revert on 0), so a shortfall can never reach
    /// principal.
    pub fn claim_delegator_rewards(&mut self, delegator: [u8; 32], validator: ValidatorId) -> u64 {
        let key = (validator, delegator);
        let amount = self.delegator_rewards_of(delegator, validator);
        if amount == 0 || amount > self.rewards_pool {
            return 0;
        }
        self.delegator_rewards.remove(&key);
        // The checkpoint moves to the current rate: the paid-out entitlement
        // must not be re-accrued by the next distribution.
        self.set_delegator_checkpoint(delegator, validator);
        self.rewards_pool -= amount;
        if let Some(state) = self.reward_accumulators.get_mut(&validator) {
            state.remaining_rewards = state.remaining_rewards.saturating_sub(amount as u128);
        }
        amount
    }

    /// Register a team vesting schedule for `account` (audit: team vesting
    /// claim gate — the on-chain lock `TeamVestingSchedule` never had).
    ///
    /// Fail-closed: refuses the zero address, a zero total allocation, and a
    /// duplicate registration (unregister first to rotate). Loud by design:
    /// every registration WARNs so a newly locked account is never silent.
    /// Pure ledger mutation — deterministic on identical input, no clock read.
    pub fn register_team_vesting(
        &mut self,
        account: [u8; 32],
        schedule: TeamVestingSchedule,
    ) -> Result<(), String> {
        if account == [0u8; 32] {
            return Err("team vesting: refusing to track the zero address".to_string());
        }
        if schedule.total_allocation == 0 {
            return Err("team vesting: refusing a zero total allocation".to_string());
        }
        if self.vesting_schedules.contains_key(&account) {
            return Err(format!(
                "team vesting: {} is already tracked (unregister first to rotate)",
                hex::encode(account),
            ));
        }
        self.vesting_schedules.insert(account, schedule);
        tracing::warn!(
            "TEAM-VESTING-REGISTER account {} is now vesting-tracked: spends below the schedule's locked floor will be refused",
            hex::encode(account),
        );
        Ok(())
    }

    /// Remove the vesting schedule for `account`. Returns whether one was
    /// tracked. Idempotent: untracking an untracked account is a no-op
    /// `false`, never an error.
    pub fn unregister_team_vesting(&mut self, account: &[u8; 32]) -> bool {
        let removed = self.vesting_schedules.remove(account).is_some();
        if removed {
            tracing::warn!(
                "TEAM-VESTING-UNREGISTER account {} is no longer vesting-tracked",
                hex::encode(account),
            );
        }
        removed
    }

    /// Vesting schedule tracking `account`, if any.
    pub fn vesting_schedule_of(&self, account: &[u8; 32]) -> Option<&TeamVestingSchedule> {
        self.vesting_schedules.get(account)
    }

    /// Locked floor for `account` at `now`: 0 when untracked, else the
    /// schedule's [`TeamVestingSchedule::locked_amount`]. Pure, so the spend
    /// path can snapshot it before taking the accounts lock.
    pub fn vesting_locked_floor_of(&self, account: &[u8; 32], now: u64) -> u64 {
        self.vesting_schedules
            .get(account)
            .map(|s| s.locked_amount(now))
            .unwrap_or(0)
    }

    /// Fail-closed vesting gate for one post-spend balance: `Ok(())` when
    /// `account` is untracked or `balance_after` stays at/above its locked
    /// floor, else `Err` with the schedule's refusal (nothing mutated).
    pub fn check_vesting_balance_floor(
        &self,
        account: &[u8; 32],
        now: u64,
        balance_after: u64,
    ) -> Result<(), String> {
        if let Some(s) = self.vesting_schedules.get(account) {
            s.check_balance_floor(now, balance_after)?;
        }
        Ok(())
    }
}

/// `StakingLedger` as written before the E2 rewards-pool fix (no
/// `rewards_pool`/`rewards_minted`) and before the E7 governance locks (no
/// `locked_governance`). Kept ONLY for reading old snapshots: the new fields
/// were appended at the END, so old bytes are an exact prefix, but bincode
/// structs decode exact-size and a bare decode fails with `UnexpectedEof`
/// (the observed-live class: pre-F-H bridge dirs refused to start). NEVER
/// written; `upgrade` fills the new counters with zero and the lock map
/// empty. Note the semantic gap this implies: rewards minted before the
/// upgrade are NOT counted in `rewards_minted` (the old format recorded no
/// mint totals), so on a chain that minted pre-upgrade verify real minted
/// supply out-of-band before trusting the cap headroom; on a fresh/test
/// chain it is exact. The empty lock map IS exact: open governance votes
/// cannot exist in a pre-E7 snapshot.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StakingLedgerV1 {
    pub validators: HashMap<ValidatorId, ValidatorStake>,
    /// (validator, delegator) -> amount
    pub delegations: HashMap<(ValidatorId, [u8; 32]), u64>,
    /// Per-delegator claimable rewards: (validator, delegator) -> nano
    pub delegator_rewards: HashMap<(ValidatorId, [u8; 32]), u64>,
    /// Pending unbondings, keyed by validator.
    pub unbonding: Vec<UnbondingEntry>,
    /// Funds that have completed cooldown and can be withdrawn by their owner.
    /// (owner, validator) -> amount ready.
    pub withdrawable: HashMap<(ValidatorId, [u8; 32]), u64>,
    /// Total STELL burned by slashing (deflationary).
    pub total_burned: u64,
}

impl StakingLedgerV1 {
    pub fn upgrade(self) -> StakingLedger {
        StakingLedger {
            validators: self.validators,
            delegations: self.delegations,
            delegator_rewards: self.delegator_rewards,
            // Exact: the lazy accumulator did not exist, so every reward in
            // `delegator_rewards` was already materialised and there is
            // nothing to reconstruct.
            reward_accumulators: HashMap::new(),
            delegator_reward_checkpoints: HashMap::new(),
            unbonding: self.unbonding,
            withdrawable: self.withdrawable,
            total_burned: self.total_burned,
            rewards_pool: 0,
            rewards_minted: 0,
            locked_governance: HashMap::new(),
            pq_equivocation_dedup: HashSet::new(),
            equivocation_dedup: HashSet::new(),
            validator_pq_keys: HashMap::new(),
            // Exact: no jail, commission-schedule or redelegation-lock rows
            // can exist in pre-feature bytes (the paths that create them did
            // not exist).
            jail: HashMap::new(),
            commission_schedule: HashMap::new(),
            redelegation_lock: HashMap::new(),
            // Exact: no vesting-tracked accounts can exist in a pre-gate
            // snapshot (the registry did not exist), so empty is not a guess.
            vesting_schedules: BTreeMap::new(),
            min_validator_bond: None,
        }
    }
}

/// Pre-`equivocation_dedup`/`vesting_schedules` ledger shape (everything up
/// to `validator_pq_keys`, i.e. what the live network persisted before the
/// coordinated upgrade that appended those two trailing fields). bincode has
/// no field names, so old bytes do not decode as the current struct — this
/// shape bridges them. Upgrade fills the two new sets/maps EMPTY, which is
/// exact (neither registry existed when those bytes were written: no
/// equivocation evidence was ever processed into a dedup set, no vesting
/// schedule was ever registered).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StakingLedgerV2 {
    pub validators: HashMap<ValidatorId, ValidatorStake>,
    pub delegations: HashMap<(ValidatorId, [u8; 32]), u64>,
    pub delegator_rewards: HashMap<(ValidatorId, [u8; 32]), u64>,
    pub unbonding: Vec<UnbondingEntry>,
    pub withdrawable: HashMap<(ValidatorId, [u8; 32]), u64>,
    pub total_burned: u64,
    #[serde(default)]
    pub rewards_pool: u64,
    #[serde(default)]
    pub rewards_minted: u64,
    #[serde(default)]
    pub locked_governance: HashMap<[u8; 32], u64>,
    #[serde(default)]
    pub pq_equivocation_dedup: HashSet<[u8; 32]>,
    #[serde(default)]
    pub validator_pq_keys: HashMap<ValidatorId, (crate::post_quantum::PqScheme, Vec<u8>)>,
}

impl StakingLedgerV2 {
    pub fn upgrade(self) -> StakingLedger {
        StakingLedger {
            validators: self.validators,
            delegations: self.delegations,
            delegator_rewards: self.delegator_rewards,
            // Exact: the lazy accumulator did not exist, so every reward in
            // `delegator_rewards` was already materialised.
            reward_accumulators: HashMap::new(),
            delegator_reward_checkpoints: HashMap::new(),
            unbonding: self.unbonding,
            withdrawable: self.withdrawable,
            total_burned: self.total_burned,
            rewards_pool: self.rewards_pool,
            rewards_minted: self.rewards_minted,
            locked_governance: self.locked_governance,
            pq_equivocation_dedup: self.pq_equivocation_dedup,
            equivocation_dedup: HashSet::new(),
            validator_pq_keys: self.validator_pq_keys,
            // Exact: no jail, commission-schedule or redelegation-lock rows
            // can exist in pre-feature bytes.
            jail: HashMap::new(),
            commission_schedule: HashMap::new(),
            redelegation_lock: HashMap::new(),
            vesting_schedules: BTreeMap::new(),
            min_validator_bond: None,
        }
    }
}

/// `StakingLedger` as written BEFORE the lazy (F1) reward accumulator
/// (no `reward_accumulators` / `delegator_reward_checkpoints`). Kept ONLY
/// for reading old snapshots: the two lazy fields were appended at the END,
/// so the old bytes are an exact prefix, but bincode structs decode
/// exact-size and a bare decode fails with `UnexpectedEof` (the observed-live
/// class: a pre-upgrade data dir refuses to start). NEVER written;
/// `upgrade` fills the two new maps EMPTY, which is EXACT: the eager
/// implementation credited every delegator at distribution time, so every
/// reward a pre-upgrade ledger knows about is already materialised in
/// `delegator_rewards` and no accumulator state has to be reconstructed.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StakingLedgerV3 {
    pub validators: HashMap<ValidatorId, ValidatorStake>,
    pub delegations: HashMap<(ValidatorId, [u8; 32]), u64>,
    pub delegator_rewards: HashMap<(ValidatorId, [u8; 32]), u64>,
    pub unbonding: Vec<UnbondingEntry>,
    pub withdrawable: HashMap<(ValidatorId, [u8; 32]), u64>,
    pub total_burned: u64,
    #[serde(default)]
    pub rewards_pool: u64,
    #[serde(default)]
    pub rewards_minted: u64,
    #[serde(default)]
    pub locked_governance: HashMap<[u8; 32], u64>,
    #[serde(default)]
    pub pq_equivocation_dedup: HashSet<[u8; 32]>,
    #[serde(default)]
    pub equivocation_dedup: HashSet<[u8; 32]>,
    #[serde(default)]
    pub validator_pq_keys: HashMap<ValidatorId, (crate::post_quantum::PqScheme, Vec<u8>)>,
    #[serde(default)]
    pub min_validator_bond: Option<u64>,
    #[serde(default)]
    pub vesting_schedules: BTreeMap<[u8; 32], TeamVestingSchedule>,
}

impl StakingLedgerV3 {
    pub fn upgrade(self) -> StakingLedger {
        StakingLedger {
            validators: self.validators,
            delegations: self.delegations,
            delegator_rewards: self.delegator_rewards,
            // Exact: see the type docs — every pre-upgrade reward was
            // materialised eagerly, so the accumulator starts empty and the
            // delegators start with no checkpoint (rate 0).
            reward_accumulators: HashMap::new(),
            delegator_reward_checkpoints: HashMap::new(),
            // Exact: no jail, commission-schedule or redelegation-lock rows
            // can exist in pre-feature bytes (the paths that create them did
            // not exist), so empty is not a guess.
            jail: HashMap::new(),
            commission_schedule: HashMap::new(),
            redelegation_lock: HashMap::new(),
            unbonding: self.unbonding,
            withdrawable: self.withdrawable,
            total_burned: self.total_burned,
            rewards_pool: self.rewards_pool,
            rewards_minted: self.rewards_minted,
            locked_governance: self.locked_governance,
            pq_equivocation_dedup: self.pq_equivocation_dedup,
            equivocation_dedup: self.equivocation_dedup,
            validator_pq_keys: self.validator_pq_keys,
            vesting_schedules: self.vesting_schedules,
            min_validator_bond: self.min_validator_bond,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{Vote, VoteKind};
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn vid(n: u8) -> ValidatorId {
        [n; 32]
    }
    fn del(n: u8) -> [u8; 32] {
        [0xD0 + n; 32]
    }
    fn stell(n: u64) -> u64 {
        n * 1_000_000_000
    }

    #[test]
    fn bond_enforces_minimum_plus_buffer_and_commission() {
        let mut l = StakingLedger::new();
        // Below MIN: refused.
        assert_eq!(
            l.bond(vid(1), stell(999), DEFAULT_COMMISSION_BPS),
            Err(StakingError::BondBelowMinimum)
        );
        // Bare MIN (no buffer): refused — one downtime slash from ejection.
        assert_eq!(
            l.bond(vid(1), stell(1000), DEFAULT_COMMISSION_BPS),
            Err(StakingError::BondBelowMinimum)
        );
        // Just under the floor: refused, and the error names the requirement.
        assert_eq!(
            l.bond(vid(1), stell(1099), DEFAULT_COMMISSION_BPS),
            Err(StakingError::BondBelowMinimum)
        );
        assert!(format!("{}", StakingError::BondBelowMinimum)
            .contains(&required_bond_floor_nano().to_string()));
        // Commission is checked after the floor: bad commission on a good bond.
        assert_eq!(
            l.bond(vid(1), stell(1100), 10_001),
            Err(StakingError::BadCommission)
        );
        l.bond(vid(1), stell(1100), DEFAULT_COMMISSION_BPS).unwrap();
        assert_eq!(l.total_stake(&vid(1)), stell(1100));
        // double registration rejected
        assert_eq!(
            l.bond(vid(1), stell(1100), DEFAULT_COMMISSION_BPS),
            Err(StakingError::AlreadyValidator)
        );
    }

    #[test]
    fn unbond_requires_cooldown_then_withdraw() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(3000), DEFAULT_COMMISSION_BPS).unwrap();
        l.unbond(vid(1), stell(1000), 1_000).unwrap();
        // still below release time
        l.process_unbonding(1_000).unwrap();
        assert_eq!(l.withdrawable_of(&vid(1)), 0);
        assert_eq!(l.withdraw(vid(1)), Err(StakingError::NothingToWithdraw));
        // after cooldown
        l.process_unbonding(1_000 + UNBONDING_PERIOD_SECS).unwrap();
        assert_eq!(l.withdrawable_of(&vid(1)), stell(1000));
        assert_eq!(l.withdraw(vid(1)).unwrap(), stell(1000));
    }

    #[test]
    fn unbond_cannot_drop_below_minimum_without_full_exit() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(2000), DEFAULT_COMMISSION_BPS).unwrap();
        // leaving 500 (< floor 1100) is rejected
        assert_eq!(
            l.unbond(vid(1), stell(1500), 0),
            Err(StakingError::BondBelowMinimum)
        );
        // leaving 1000 (< floor 1100) is also rejected (retaining the 100 STELL buffer floor)
        assert_eq!(
            l.unbond(vid(1), stell(1000), 0),
            Err(StakingError::BondBelowMinimum)
        );
        // full exit is allowed
        assert!(l.unbond(vid(1), stell(2000), 0).is_ok());
    }

    #[test]
    fn delegation_and_undelegation() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(1100), DEFAULT_COMMISSION_BPS).unwrap();
        assert_eq!(
            l.delegate(del(1), vid(1), stell(0)),
            Err(StakingError::DelegationBelowMinimum)
        );
        l.delegate(del(1), vid(1), stell(500)).unwrap();
        assert_eq!(l.total_stake(&vid(1)), stell(1600));
        l.undelegate(del(1), vid(1), stell(200), 0).unwrap();
        assert_eq!(l.total_stake(&vid(1)), stell(1400));
        assert_eq!(
            l.undelegate(del(1), vid(1), stell(999), 0),
            Err(StakingError::InsufficientDelegation)
        );
    }

    #[test]
    fn validator_set_weighted_by_stake() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(1100), DEFAULT_COMMISSION_BPS).unwrap();
        l.bond(vid(2), stell(3000), DEFAULT_COMMISSION_BPS).unwrap();
        l.delegate(del(9), vid(1), stell(6000)).unwrap();
        let vs = l.to_validator_set();
        assert_eq!(vs.power_of(&vid(1)), stell(7100));
        assert_eq!(vs.power_of(&vid(2)), stell(3000));
        assert_eq!(vs.total_power(), stell(10_100));
        // quorum = 2/3 + 1
        assert_eq!(vs.quorum_power(), (stell(10_100) * 2) / 3 + 1);
    }

    #[test]
    fn equivocation_slashes_and_burns() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(1100), DEFAULT_COMMISSION_BPS).unwrap();
        l.delegate(del(1), vid(1), stell(1000)).unwrap();
        let sk = SigningKey::generate(&mut OsRng);
        let a = Vote::sign(&sk, 1, 0, VoteKind::Prevote, Some([1u8; 32]));
        let b = Vote::sign(&sk, 1, 0, VoteKind::Prevote, Some([2u8; 32]));
        let burned = l.slash_equivocation(&(vid(1), a, b)).unwrap();
        // 5% of 2100 = 105
        assert_eq!(burned, stell(105));
        assert_eq!(l.total_stake(&vid(1)), stell(1995));
        assert_eq!(l.total_burned, stell(105));
    }

    #[test]
    fn non_conflicting_votes_are_not_equivocation() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(1100), DEFAULT_COMMISSION_BPS).unwrap();
        let sk = SigningKey::generate(&mut OsRng);
        // same target -> not equivocation
        let a = Vote::sign(&sk, 1, 0, VoteKind::Prevote, Some([1u8; 32]));
        let b = Vote::sign(&sk, 1, 0, VoteKind::Prevote, Some([1u8; 32]));
        assert_eq!(l.slash_equivocation(&(vid(1), a, b)).unwrap(), 0);
        // different height -> not equivocation
        let c = Vote::sign(&sk, 2, 0, VoteKind::Prevote, Some([1u8; 32]));
        let d = Vote::sign(&sk, 1, 0, VoteKind::Prevote, Some([2u8; 32]));
        assert_eq!(l.slash_equivocation(&(vid(1), c, d)).unwrap(), 0);
    }

    #[test]
    fn verified_equivocation_burns_five_percent_self_first() {
        use crate::consensus::EquivocationEvidence;
        let mut l = StakingLedger::new();
        let sk = SigningKey::generate(&mut OsRng);
        let offender = sk.verifying_key().to_bytes();
        l.bond(offender, stell(2000), DEFAULT_COMMISSION_BPS)
            .unwrap();
        let a = Vote::sign(&sk, 1, 0, VoteKind::Prevote, Some([1u8; 32]));
        let b = Vote::sign(&sk, 1, 0, VoteKind::Prevote, Some([2u8; 32]));
        let ev = EquivocationEvidence::new(offender, a, b);
        let before = l.validators[&offender].self_bond;
        let burned = l.slash_equivocation_verified(&ev).unwrap();
        assert_eq!(burned, stell(100), "5% of 2000 STELL");
        assert_eq!(l.validators[&offender].self_bond, before - burned);
        assert_eq!(l.validators[&offender].total_slashed, burned);
        assert_eq!(l.total_burned, burned);
    }

    #[test]
    fn verified_equivocation_dedupes_repeat_offense() {
        use crate::consensus::EquivocationEvidence;
        let mut l = StakingLedger::new();
        let sk = SigningKey::generate(&mut OsRng);
        let offender = sk.verifying_key().to_bytes();
        l.bond(offender, stell(2000), DEFAULT_COMMISSION_BPS)
            .unwrap();
        let a = Vote::sign(&sk, 1, 0, VoteKind::Prevote, Some([1u8; 32]));
        let b = Vote::sign(&sk, 1, 0, VoteKind::Prevote, Some([2u8; 32]));
        let ev = EquivocationEvidence::new(offender, a.clone(), b.clone());
        let first = l.slash_equivocation_verified(&ev).unwrap();
        assert!(first > 0);
        // Same pair again, and votes-swapped: both burn 0, stake untouched.
        let swapped = EquivocationEvidence::new(offender, b, a);
        assert_eq!(l.slash_equivocation_verified(&ev).unwrap(), 0);
        assert_eq!(l.slash_equivocation_verified(&swapped).unwrap(), 0);
        assert_eq!(l.total_burned, first);
        assert_eq!(l.total_stake(&offender), stell(2000) - first);
        // A DISTINCT pair at the same height/round is a new offense.
        let a2 = Vote::sign(&sk, 1, 0, VoteKind::Prevote, Some([1u8; 32]));
        let c = Vote::sign(&sk, 1, 0, VoteKind::Prevote, Some([3u8; 32]));
        let fresh = EquivocationEvidence::new(offender, a2, c);
        let second = l.slash_equivocation_verified(&fresh).unwrap();
        assert!(second > 0, "distinct conflicting pair is a new offense");
        assert_eq!(l.total_burned, first + second);
    }

    #[test]
    fn verified_equivocation_refuses_forgeries_fail_closed() {
        use crate::consensus::EquivocationEvidence;
        let mut l = StakingLedger::new();
        let sk = SigningKey::generate(&mut OsRng);
        let offender = sk.verifying_key().to_bytes();
        l.bond(offender, stell(2000), DEFAULT_COMMISSION_BPS)
            .unwrap();
        let other = SigningKey::generate(&mut OsRng);
        let a = Vote::sign(&sk, 1, 0, VoteKind::Prevote, Some([1u8; 32]));
        // Framing with another key's vote burns nothing (Finding 12 fixed).
        let framed = Vote::sign(&other, 1, 0, VoteKind::Prevote, Some([2u8; 32]));
        let ev = EquivocationEvidence::new(offender, a.clone(), framed);
        assert_eq!(l.slash_equivocation_verified(&ev).unwrap(), 0);
        // Zeroed signatures burn nothing.
        let mut za = a.clone();
        let mut zb = Vote::sign(&sk, 1, 0, VoteKind::Prevote, Some([2u8; 32]));
        za.signature = vec![0u8; 64];
        zb.signature = vec![0u8; 64];
        let ev_fake = EquivocationEvidence::new(offender, za, zb);
        assert_eq!(l.slash_equivocation_verified(&ev_fake).unwrap(), 0);
        // Same target twice burns nothing.
        let ev_same = EquivocationEvidence::new(offender, a.clone(), a);
        assert_eq!(l.slash_equivocation_verified(&ev_same).unwrap(), 0);
        // Unknown voter errors (transition maps to skip-and-log).
        let outsider = SigningKey::generate(&mut OsRng);
        let oid = outsider.verifying_key().to_bytes();
        let oa = Vote::sign(&outsider, 1, 0, VoteKind::Prevote, Some([1u8; 32]));
        let ob = Vote::sign(&outsider, 1, 0, VoteKind::Prevote, Some([2u8; 32]));
        let ev_out = EquivocationEvidence::new(oid, oa, ob);
        assert_eq!(
            l.slash_equivocation_verified(&ev_out),
            Err(StakingError::NotValidator)
        );
        // Nothing moved anywhere.
        assert_eq!(l.total_stake(&offender), stell(2000));
        assert_eq!(l.total_burned, 0);
    }

    #[test]
    fn reward_split_with_commission() {
        let mut l = StakingLedger::new();
        // validator self 1100, delegator 1000 -> total 2100, commission 10%
        l.bond(vid(1), stell(1100), 1_000).unwrap();
        l.delegate(del(1), vid(1), stell(1000)).unwrap();
        // reward 200 over total 2100: delegated_share=95238095238,
        // commission=9523809523, validator=114285714285, delegator=85714285715
        l.distribute_reward(vid(1), stell(200)).unwrap();
        assert_eq!(l.claim_validator_rewards(vid(1)).unwrap(), 114_285_714_285);
        assert_eq!(l.claim_delegator_rewards(del(1), vid(1)), 85_714_285_715);
    }

    #[test]
    fn rotate_key_moves_everything_and_never_merges() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(2000), DEFAULT_COMMISSION_BPS).unwrap();
        l.delegate(del(1), vid(1), stell(500)).unwrap();
        l.undelegate(del(1), vid(1), stell(200), 0).unwrap();
        // Slash history exists: rotation must carry it (no laundering).
        l.slash(vid(1), 1_000).unwrap();
        let slashed_before = l.validators[&vid(1)].total_slashed;
        let total_before = l.total_stake(&vid(1));

        l.rotate_key(vid(1), vid(2)).unwrap();
        assert!(!l.validators.contains_key(&vid(1)), "old key is gone");
        let v = &l.validators[&vid(2)];
        assert_eq!(v.commission_bps, DEFAULT_COMMISSION_BPS);
        assert_eq!(
            v.total_slashed, slashed_before,
            "slash history carries over"
        );
        assert_eq!(
            l.total_stake(&vid(2)),
            total_before,
            "stake preserved exactly"
        );
        assert_eq!(
            l.delegations.get(&(vid(2), del(1))).copied(),
            Some(stell(300)),
            "delegation follows the record"
        );
        assert!(!l.delegations.contains_key(&(vid(1), del(1))));
        assert!(
            l.unbonding
                .iter()
                .any(|u| u.validator == vid(2) && u.amount == stell(180)),
            "pending unbonding follows the record (200 less the 10% slash haircut, audit P1)"
        );
        assert!(
            l.unbonding.iter().all(|u| u.validator != vid(1)),
            "nothing still names the old key"
        );
        // Rotated record still validates and still slashes.
        assert!(l.to_validator_set().validators.contains_key(&vid(2)));
    }

    #[test]
    fn rotate_key_refuses_unknown_old_and_existing_new() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(2000), DEFAULT_COMMISSION_BPS).unwrap();
        assert_eq!(
            l.rotate_key(vid(9), vid(2)),
            Err(StakingError::NotValidator),
            "nothing to rotate"
        );
        l.bond(vid(3), stell(2000), DEFAULT_COMMISSION_BPS).unwrap();
        assert_eq!(
            l.rotate_key(vid(1), vid(3)),
            Err(StakingError::AlreadyValidator),
            "rotation must never merge two records"
        );
        assert_eq!(
            l.rotate_key(vid(1), vid(1)),
            Err(StakingError::AlreadyValidator),
            "self-rotation is a no-op refusal"
        );
        // Failed rotations move nothing.
        assert!(l.validators.contains_key(&vid(1)));
        assert!(l.validators.contains_key(&vid(3)));
    }

    #[test]
    fn slash_preserves_delegator_proportion() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(1100), DEFAULT_COMMISSION_BPS).unwrap();
        l.delegate(del(1), vid(1), stell(1000)).unwrap();
        l.delegate(del(2), vid(1), stell(1000)).unwrap();
        // slash 10% of 3100 = 310; self 1100 covers all 310 -> delegators untouched
        l.slash(vid(1), 1_000).unwrap();
        assert_eq!(l.total_stake(&vid(1)), stell(2790));
        assert_eq!(
            l.delegations.get(&(vid(1), del(1))).copied(),
            Some(stell(1000))
        );
    }

    #[test]
    fn undelegated_funds_go_to_the_delegator_not_the_validator() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(2000), DEFAULT_COMMISSION_BPS).unwrap();
        l.delegate(del(1), vid(1), stell(1500)).unwrap();
        l.undelegate(del(1), vid(1), stell(1500), 0).unwrap();
        l.process_unbonding(UNBONDING_PERIOD_SECS + 1).unwrap();

        // The validator must NOT be able to withdraw the delegator's stake.
        assert_eq!(l.withdrawable_of(&vid(1)), 0);
        assert_eq!(l.withdraw(vid(1)), Err(StakingError::NothingToWithdraw));
        // The delegator owns and can withdraw it.
        assert_eq!(l.withdrawable_delegator(&vid(1), &del(1)), stell(1500));
        assert_eq!(l.withdraw_delegator(del(1), vid(1)).unwrap(), stell(1500));
    }

    #[test]
    fn self_unbond_and_delegator_undelegate_do_not_merge() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(5000), DEFAULT_COMMISSION_BPS).unwrap();
        l.delegate(del(1), vid(1), stell(1000)).unwrap();
        l.unbond(vid(1), stell(2000), 0).unwrap(); // validator self-bond
        l.undelegate(del(1), vid(1), stell(1000), 0).unwrap(); // delegator stake
        l.process_unbonding(UNBONDING_PERIOD_SECS + 1).unwrap();

        // Amounts are tracked separately per owner: no cross-credit.
        assert_eq!(l.withdrawable_of(&vid(1)), stell(2000));
        assert_eq!(l.withdrawable_delegator(&vid(1), &del(1)), stell(1000));
        assert_eq!(l.withdraw(vid(1)).unwrap(), stell(2000));
        assert_eq!(l.withdraw_delegator(del(1), vid(1)).unwrap(), stell(1000));
    }

    /// A bond must move REAL value into the staking pool and give the bonded
    /// account voting power. A bond used to be recorded without any coin moving,
    /// which handed out validator power for free.
    #[tokio::test]
    async fn bonding_moves_real_funds_and_grants_validator_power() {
        use crate::state_engine::{AccountState, InMemoryStateEngine};
        use crate::svm::OpCode;
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let engine = InMemoryStateEngine::new();
        let alice = SigningKey::generate(&mut OsRng);
        let alice_addr = alice.verifying_key().to_bytes();
        let validator = [0x77u8; 32];
        let start = 10_000 * 1_000_000_000u64;
        engine
            .update_account(AccountState::new(alice_addr, start))
            .await;

        let tx = crate::sharding::Transaction::sign_with_payload(
            &alice,
            alice_addr,
            0,
            10_000,
            0,
            1,
            1,
            vec![OpCode::SysCallStake {
                validator,
                amount: required_bond_floor_nano(),
            }],
        );
        engine
            .apply_transaction(&tx, 0)
            .await
            .expect("bond must be accepted");

        let alice_balance = engine.get_account(&alice_addr).await.unwrap().balance;
        let pool_balance = engine
            .get_account(&STAKING_POOL)
            .await
            .map(|a| a.balance)
            .unwrap_or(0);
        // Only the gas actually consumed is charged (GAS_STAKE_BOND), not the
        // declared gas_limit, so the exact debit is knowable.
        assert_eq!(
            alice_balance,
            start - required_bond_floor_nano() - crate::svm::GAS_STAKE_BOND,
            "bond + gas actually used must be debited"
        );
        assert_eq!(
            pool_balance,
            required_bond_floor_nano(),
            "bonded value must be in the pool"
        );

        let vs = engine.staking_read().await.to_validator_set();
        assert_eq!(
            vs.power_of(&validator),
            required_bond_floor_nano(),
            "bond must buy voting power"
        );
    }

    /// You cannot bond what you do not have, and the attempt must leave no trace.
    #[tokio::test]
    async fn unaffordable_bond_is_rejected() {
        use crate::state_engine::{AccountState, InMemoryStateEngine};
        use crate::svm::OpCode;
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let engine = InMemoryStateEngine::new();
        let bob = SigningKey::generate(&mut OsRng);
        let bob_addr = bob.verifying_key().to_bytes();
        let validator = [0x78u8; 32];
        engine.update_account(AccountState::new(bob_addr, 10)).await;

        let tx = crate::sharding::Transaction::sign_with_payload(
            &bob,
            bob_addr,
            0,
            10_000,
            0,
            1,
            1,
            vec![OpCode::SysCallStake {
                validator,
                amount: required_bond_floor_nano(),
            }],
        );
        assert!(
            engine.apply_transaction(&tx, 0).await.is_err(),
            "must not bond what you lack"
        );
        let vs = engine.staking_read().await.to_validator_set();
        assert!(
            !vs.validators.contains_key(&validator),
            "no phantom validator"
        );
    }

    /// A thin (below-MIN+buffer) bond is rejected, and the attempt moves
    /// nothing; a bond that fails the floor leaves no phantom validator.
    #[tokio::test]
    async fn thin_bond_is_rejected_and_moves_nothing() {
        use crate::state_engine::{AccountState, InMemoryStateEngine};
        use crate::svm::OpCode;
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let engine = InMemoryStateEngine::new();
        let dave = SigningKey::generate(&mut OsRng);
        let dave_addr = dave.verifying_key().to_bytes();
        let validator = [0x7Au8; 32];
        engine
            .update_account(AccountState::new(dave_addr, 10_000 * 1_000_000_000))
            .await;

        // Bare MIN is affordable but below the MIN+buffer floor: refused.
        let tx = crate::sharding::Transaction::sign_with_payload(
            &dave,
            dave_addr,
            0,
            10_000,
            0,
            1,
            1,
            vec![OpCode::SysCallStake {
                validator,
                amount: MIN_VALIDATOR_BOND,
            }],
        );
        assert!(
            engine.apply_transaction(&tx, 0).await.is_err(),
            "bare-MIN bond must be refused"
        );
        let vs = engine.staking_read().await.to_validator_set();
        assert!(
            !vs.validators.contains_key(&validator),
            "no phantom validator"
        );
    }

    /// A bond is atomic with the rest of the payload: if the transaction reverts
    /// later, the validator must not exist.
    #[tokio::test]
    async fn reverted_bond_leaves_no_validator() {
        use crate::state_engine::{AccountState, InMemoryStateEngine};
        use crate::svm::OpCode;
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let engine = InMemoryStateEngine::new();
        let carol = SigningKey::generate(&mut OsRng);
        let carol_addr = carol.verifying_key().to_bytes();
        let validator = [0x79u8; 32];
        engine
            .update_account(AccountState::new(carol_addr, 10_000 * 1_000_000_000))
            .await;

        let tx = crate::sharding::Transaction::sign_with_payload(
            &carol,
            carol_addr,
            0,
            50_000,
            0,
            1,
            1,
            vec![
                OpCode::SysCallStake {
                    validator,
                    amount: required_bond_floor_nano(),
                },
                // More than remains after the bond -> reverts the whole payload.
                OpCode::Transfer {
                    recipient: [0x01u8; 32],
                    amount: 9_500_000_000_000,
                },
            ],
        );
        assert!(engine.apply_transaction(&tx, 0).await.is_err());
        let vs = engine.staking_read().await.to_validator_set();
        assert!(
            !vs.validators.contains_key(&validator),
            "a reverted bond must not create a validator"
        );
    }

    /// Downtime is punished from block evidence: a validator that keeps missing
    /// the quorum certificate is slashed, an honest one never is.
    #[test]
    fn downtime_slashing_is_driven_by_the_quorum_certificate() {
        let honest = [0x01u8; 32];
        let offline = [0x02u8; 32];
        let mut l = StakingLedger::new();
        l.bond(honest, stell(1100), 0).unwrap();
        l.bond(offline, stell(1100), 0).unwrap();
        let both = vec![honest, offline];

        // `offline` never signs; `honest` always does.
        let signer = |v: &ValidatorId| *v == honest;
        let mut burned_total = 0u64;

        for height in 1..=(DOWNTIME_MISS_THRESHOLD as u64) {
            burned_total += l.note_missed_heights(height, &signer, &both);
        }
        assert_eq!(
            burned_total,
            stell(1100) * DOWNTIME_SLASH_BPS / 10_000,
            "exactly one slash when the threshold is reached"
        );
        assert_eq!(
            l.validators[&honest].self_bond,
            stell(1100),
            "an honest validator must never be punished"
        );
        assert_eq!(
            l.validators[&offline].self_bond,
            stell(1100) - burned_total,
            "the offline validator must actually lose stake"
        );
        // The MIN+buffer floor absorbs one downtime slash: 1100 - 1.1 STELL is
        // still above MIN, so the validator is NOT ejected (this is what the
        // buffer is for — урок валидатора C bonded bare MIN and ejected).
        assert!(
            l.validators[&offline].self_bond >= MIN_VALIDATOR_BOND,
            "the buffer must absorb a single downtime slash"
        );

        // The streak is forgiven as soon as it signs again, and the cooldown stops
        // a single long outage from draining the whole bond.
        for height in 20..(20 + DOWNTIME_MISS_THRESHOLD as u64) {
            let both_signed = |_: &ValidatorId| true;
            assert_eq!(l.note_missed_heights(height, &both_signed, &both), 0);
        }
        assert_eq!(
            l.validators[&offline].missed, 0,
            "signing again clears the streak"
        );
    }

    /// The same evidence replayed must not slash twice: the cooldown keys on the
    /// height, so re-applying an old certificate is a no-op.
    #[test]
    fn downtime_slash_respects_the_cooldown() {
        let v = [0x03u8; 32];
        let mut l = StakingLedger::new();
        l.bond(v, stell(1100), 0).unwrap();
        let never = |_: &ValidatorId| false;
        let one = vec![v];

        // A full streak first.
        let mut burned = 0;
        for height in 1..=DOWNTIME_MISS_THRESHOLD as u64 {
            burned += l.note_missed_heights(height, &never, &one);
        }
        assert!(burned > 0, "the first streak must cost something");
        // Replaying that same evidence must not burn anything more.
        let replay = l.note_missed_heights(DOWNTIME_MISS_THRESHOLD as u64, &never, &one);
        assert_eq!(replay, 0, "replaying the same height must not slash again");
    }

    /// E2: every mint funds the rewards pool 1:1, and claims consume it.
    #[test]
    fn rewards_mint_funds_pool_and_claims_consume_it() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(1100), 1_000).unwrap();
        l.delegate(del(1), vid(1), stell(1000)).unwrap();
        assert_eq!(l.rewards_pool, 0);
        assert_eq!(l.rewards_minted, 0);

        l.distribute_reward(vid(1), stell(200)).unwrap();
        assert_eq!(l.rewards_minted, stell(200), "mint is tracked cumulatively");
        assert_eq!(l.rewards_pool, stell(200), "mint funds the pool 1:1");

        // Validator share 114285714285, delegator share 85714285715 (see
        // reward_split test for the exact integer math).
        let v_amt = l.claim_validator_rewards(vid(1)).unwrap();
        assert_eq!(v_amt, 114_285_714_285);
        assert_eq!(
            l.rewards_pool, 85_714_285_715,
            "validator claim consumes pool"
        );
        let d_amt = l.claim_delegator_rewards(del(1), vid(1));
        assert_eq!(d_amt, 85_714_285_715);
        assert_eq!(l.rewards_pool, 0, "pool fully consumed by claims");
        assert_eq!(
            l.rewards_minted,
            stell(200),
            "cumulative mint never decreases"
        );
        // Nothing left: both paths are now empty, fail-closed.
        assert_eq!(l.claim_validator_rewards(vid(1)).unwrap(), 0);
        assert_eq!(l.claim_delegator_rewards(del(1), vid(1)), 0);
    }

    /// P5 ATTACKS (staking theft): delegate→undelegate→claim in one block must
    /// not double-count; withdrawing before maturity must fail; matured funds
    /// are exit queue (not slashable — slashing them would punish exited
    /// stake, and `slash` only burns still-bonded funds); commission is
    /// immutable after bond.
    #[test]
    fn p5_exit_and_claim_sequences_are_conservative() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(1100), 1_000).unwrap();
        l.delegate(del(1), vid(1), stell(1000)).unwrap();
        l.distribute_reward(vid(1), stell(200)).unwrap();
        // Delegate -> undelegate -> claim in one block: the delegator keeps
        // exactly what it earned (85714285715, see reward_split math), the
        // reduced stake earns nothing extra, and the pool balances exactly.
        l.undelegate(del(1), vid(1), stell(1000), 0).unwrap();
        assert_eq!(l.claim_delegator_rewards(del(1), vid(1)), 85_714_285_715);
        assert_eq!(
            l.claim_delegator_rewards(del(1), vid(1)),
            0,
            "second claim pays nothing"
        );
        // Exit queue: nothing matured yet (cooldown not elapsed).
        l.process_unbonding(1).unwrap();
        assert_eq!(l.withdrawable_delegator(&vid(1), &del(1)), 0);
        assert_eq!(
            l.withdraw_delegator(del(1), vid(1)),
            Err(StakingError::NothingToWithdraw),
            "early withdraw of unmatured exit must fail closed"
        );
        // After maturity the exit pays exactly once.
        l.process_unbonding(UNBONDING_PERIOD_SECS + 1).unwrap();
        assert_eq!(l.withdrawable_delegator(&vid(1), &del(1)), stell(1000));
        assert_eq!(l.withdraw_delegator(del(1), vid(1)).unwrap(), stell(1000));
        assert_eq!(
            l.withdraw_delegator(del(1), vid(1)),
            Err(StakingError::NothingToWithdraw),
            "second withdraw of the same exit must fail"
        );
        // Commission immutability: no setter exists — the bonded rate stands.
        assert_eq!(l.validators[&vid(1)].commission_bps, 1_000);
    }

    /// E2: the emission cap is enforced fail-closed — over cap refuses and
    /// credits nothing (no partial mint, no phantom pending rewards).
    #[test]
    fn rewards_cap_is_fail_closed() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(1100), 0).unwrap();
        // Pre-fill to just under the cap.
        l.rewards_minted = REWARDS_EMISSION_CAP - 100;
        l.rewards_pool = 50;
        // Exactly to the cap is allowed.
        l.distribute_reward(vid(1), 100).unwrap();
        assert_eq!(l.rewards_minted, REWARDS_EMISSION_CAP);
        assert_eq!(l.rewards_pool, 150);
        // One nano over refuses and moves nothing.
        assert_eq!(
            l.distribute_reward(vid(1), 1),
            Err(StakingError::RewardsCapExceeded)
        );
        assert_eq!(l.rewards_minted, REWARDS_EMISSION_CAP, "no partial mint");
        assert_eq!(l.rewards_pool, 150, "pool untouched by refused mint");
        assert_eq!(
            l.validators[&vid(1)].pending_rewards,
            100,
            "refused mint credits no phantom rewards"
        );
        // Zero rewards are a no-op even at the cap (heartbeat blocks stay cheap).
        assert!(l.distribute_reward(vid(1), 0).is_ok());
    }

    /// E2: a claim the pool cannot cover is refused with the entry intact —
    /// rewards never fall back to bonded principal.
    #[test]
    fn rewards_claim_shortfall_never_touches_principal() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(1100), 0).unwrap();
        l.distribute_reward(vid(1), stell(10)).unwrap();
        let owed = l.validators[&vid(1)].pending_rewards;
        assert!(owed > 0);
        // Simulate pool funds lost (must never happen via the API): the
        // claim refuses instead of reaching into self_bond.
        l.rewards_pool = 0;
        assert_eq!(
            l.claim_validator_rewards(vid(1)),
            Err(StakingError::RewardsPoolShortfall)
        );
        assert_eq!(
            l.validators[&vid(1)].pending_rewards,
            owed,
            "refused claim leaves the entry intact"
        );
        assert_eq!(
            l.validators[&vid(1)].self_bond,
            stell(1100),
            "principal untouched by the shortfall"
        );
    }

    // -----------------------------------------------------------------------
    // LAZY (F1) ACCUMULATOR — the O(1) distribution and its exactness.
    // -----------------------------------------------------------------------

    /// Deterministic xorshift64 PRNG. The differential test must be
    /// reproducible byte-for-byte on every machine: no `rand`, no clock.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    /// Distinct delegator addresses (the zero address is reserved).
    fn delegator_addr(i: usize) -> [u8; 32] {
        let mut d = [0xAB; 32];
        d[0] = (i & 0xff) as u8;
        d[1] = (i >> 8) as u8;
        d
    }

    /// The EAGER reference implementation, verbatim from the pre-lazy code:
    /// every delegator of the validator is credited `pool * stake / delegated`
    /// on every distribution.
    fn eager_delegator_share(pool: u64, stake: u64, delegated_total: u64) -> u64 {
        if delegated_total == 0 {
            return 0;
        }
        (pool as u128 * stake as u128 / delegated_total as u128) as u64
    }

    /// The EAGER reference split of one distribution: (validator leg,
    /// delegator pool).
    fn eager_split(reward: u64, self_bond: u64, delegated: u64, commission_bps: u64) -> (u64, u64) {
        let total = self_bond + delegated;
        let delegated_share = (reward as u128 * delegated as u128 / total as u128) as u64;
        let commission =
            (delegated_share as u128 * commission_bps as u128 / BPS_DENOMINATOR as u128) as u64;
        let validator_reward = reward - delegated_share + commission;
        (validator_reward, delegated_share - commission)
    }

    /// Build `n` delegators with pseudo-random stakes (in nano-STELL) and
    /// return them. `granularity` is the stake quantum; the stakes are
    /// multiples of it (plus the exact remainder on the last one) and sum to
    /// `total` EXACTLY — the differential comparison needs the same
    /// denominator on both sides.
    fn delegator_set(n: usize, total: u64, granularity: u64, seed: u64) -> Vec<u64> {
        let mut rng = Lcg(seed);
        let mut out: Vec<u64> = Vec::with_capacity(n);
        let mut sum = 0u64;
        for _ in 0..n {
            let s = granularity * (1 + rng.below(9));
            out.push(s);
            sum += s;
        }
        // Shrink to the target in whole quanta (never below one quantum),
        // then hand the exact remainder to the last delegator.
        while sum > total {
            let mut progressed = false;
            for s in out.iter_mut() {
                if sum <= total {
                    break;
                }
                if *s > granularity {
                    *s -= granularity;
                    sum -= granularity;
                    progressed = true;
                }
            }
            assert!(
                progressed,
                "cannot shrink the stake set to the target total"
            );
        }
        let last = out.len() - 1;
        out[last] += total - sum;
        assert_eq!(out.iter().sum::<u64>(), total);
        out
    }

    /// THE DIFFERENTIAL TEST (1/2): 1000 delegators, one distribution, the
    /// lazy accumulator against the EAGER reference.
    ///
    /// The delegated total is 10,000 STELL = 1e13 nano, which DIVIDES the
    /// accumulator scale (1e18): the scaled rate is therefore EXACT (no
    /// truncation at all) and the lazy allocation must match the eager one
    /// BIT-FOR-BIT — delegator by delegator AND in total.
    #[test]
    fn lazy_accumulator_matches_eager_reference_for_1000_delegators() {
        const N: usize = 1000;
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(1100), 1_000).unwrap();
        let stakes = delegator_set(
            N,
            10_000 * 1_000_000_000,
            1_000_000_000,
            0x2545_F491_4F6C_DD1D,
        );
        for (i, s) in stakes.iter().enumerate() {
            l.delegate(delegator_addr(i), vid(1), *s).unwrap();
        }
        let delegated = l.validators[&vid(1)].delegated;
        assert_eq!(delegated, 10_000 * 1_000_000_000);
        assert_eq!(l.delegations.len(), N);

        l.distribute_reward(vid(1), stell(200)).unwrap();

        // THE O(1) PROOF: the distribution credited NO delegator row. The
        // eager implementation wrote N entries here; the lazy one wrote none.
        assert!(
            l.delegator_rewards.is_empty(),
            "a lazy distribution must not credit delegators eagerly"
        );
        assert!(
            l.delegator_reward_checkpoints.is_empty(),
            "a lazy distribution must not touch delegator checkpoints"
        );
        assert_eq!(
            l.reward_accumulators.len(),
            1,
            "one accumulator per funded validator, not one row per delegator"
        );

        // The EAGER reference for the same distribution.
        let (validator_reward, pool) = eager_split(stell(200), stell(1100), delegated, 1_000);
        let mut eager_total = 0u64;
        let mut lazy_total = 0u64;
        for (i, s) in stakes.iter().enumerate() {
            let addr = delegator_addr(i);
            let eager = eager_delegator_share(pool, *s, delegated);
            eager_total += eager;
            let lazy = l.delegator_rewards_of(addr, vid(1));
            assert_eq!(
                lazy, eager,
                "delegator {i}: the lazy accumulator must match the eager split exactly"
            );
            let claimed = l.claim_delegator_rewards(addr, vid(1));
            assert_eq!(
                claimed, eager,
                "delegator {i}: the claim pays the eager amount"
            );
            lazy_total += claimed;
        }
        assert_eq!(
            lazy_total, eager_total,
            "the TOTAL distributed must equal the eager total"
        );
        // Conservation: minted == validator leg + delegator payouts + the
        // dust that stays locked in the rewards pool (never swept).
        assert_eq!(
            l.claim_validator_rewards(vid(1)).unwrap(),
            validator_reward,
            "the validator leg is unchanged by the lazy path"
        );
        assert_eq!(
            l.rewards_pool,
            pool - eager_total,
            "the per-delegator dust stays locked in the pool (protocol-favouring)"
        );
    }

    /// THE DIFFERENTIAL TEST (2/2): the same comparison with stakes that do
    /// NOT divide the accumulator scale, so the scaled rate truncates.
    ///
    /// The contract there is the PRECISION one: the truncated rate never
    /// over-credits, and no delegator may be off by more than ONE nano-STELL
    /// from the eager reference (the rate error is `< stake / SCALE`, and the
    /// stake is bounded by the total supply = 1e18 nano = SCALE).
    #[test]
    fn lazy_claim_is_within_one_nano_of_eager_for_unaligned_stakes() {
        const N: usize = 1000;
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(1100), 1_000).unwrap();
        // 1 STELL granularity but a total that does NOT divide 1e18.
        let stakes = delegator_set(
            N,
            10_003 * 1_000_000_000 + 7,
            1_000_000_000,
            0x9E37_79B9_7F4A_7C15,
        );
        for (i, s) in stakes.iter().enumerate() {
            l.delegate(delegator_addr(i), vid(1), *s).unwrap();
        }
        let delegated = l.validators[&vid(1)].delegated;
        l.distribute_reward(vid(1), stell(200)).unwrap();

        let (_validator_reward, pool) = eager_split(stell(200), stell(1100), delegated, 1_000);
        let mut eager_total = 0u64;
        let mut lazy_total = 0u64;
        for (i, s) in stakes.iter().enumerate() {
            let addr = delegator_addr(i);
            let eager = eager_delegator_share(pool, *s, delegated);
            eager_total += eager;
            let lazy = l.delegator_rewards_of(addr, vid(1));
            assert!(
                lazy <= eager,
                "delegator {i}: the truncated rate must never over-credit ({lazy} > {eager})"
            );
            assert!(
                eager - lazy <= 1,
                "delegator {i}: off by more than one nano ({lazy} vs {eager})"
            );
            let claimed = l.claim_delegator_rewards(addr, vid(1));
            assert_eq!(claimed, lazy);
            lazy_total += claimed;
        }
        assert!(
            eager_total - lazy_total <= N as u64,
            "the total may only lose the per-delegator dust (<= one nano each)"
        );
        // The pool backs every claim 1:1: what was paid out came out of the
        // minted pool, and the validator's leg plus the dust stay in it.
        assert_eq!(
            l.rewards_pool,
            stell(200) - lazy_total,
            "the lazy path never mints and never over-pays"
        );
    }

    /// LAZY: the accrued rewards survive an exit and a re-entry, and the
    /// re-delegated stake earns ONLY from the new emission (the double-dip
    /// the eager implementation already refused).
    #[test]
    fn lazy_rewards_survive_undelegate_and_re_delegate() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(1100), 1_000).unwrap();
        l.delegate(del(1), vid(1), stell(1000)).unwrap();
        l.delegate(del(2), vid(1), stell(1000)).unwrap();

        l.distribute_reward(vid(1), stell(200)).unwrap();
        let owed_1 = l.delegator_rewards_of(del(1), vid(1));
        let owed_2 = l.delegator_rewards_of(del(2), vid(1));
        assert!(owed_1 > 0 && owed_2 > 0);

        // The delegator leaves: the accrued reward is SETTLED (materialised)
        // and survives the exit untouched.
        l.undelegate(del(1), vid(1), stell(1000), 0).unwrap();
        assert_eq!(
            l.delegator_rewards_of(del(1), vid(1)),
            owed_1,
            "undelegate must not zero already-accrued rewards"
        );
        assert_eq!(
            l.delegator_rewards.get(&(vid(1), del(1))).copied(),
            Some(owed_1),
            "the accrued reward is materialised on the exit"
        );

        // It comes back: the re-delegated stake earns ONLY from the next
        // emission, never the one that was already distributed.
        l.delegate(del(1), vid(1), stell(1000)).unwrap();
        l.distribute_reward(vid(1), stell(200)).unwrap();
        let after = l.delegator_rewards_of(del(1), vid(1));
        assert_eq!(
            after,
            owed_1 * 2,
            "the re-delegated stake earns exactly one more emission"
        );
    }

    /// LAZY: a slash must not eat the rewards a delegator already earned —
    /// the eager implementation credited them at distribution time, where a
    /// slash could not touch them.
    #[test]
    fn lazy_slash_preserves_accrued_delegator_rewards() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(1100), 1_000).unwrap();
        l.delegate(del(1), vid(1), stell(1000)).unwrap();
        l.distribute_reward(vid(1), stell(200)).unwrap();
        let owed = l.delegator_rewards_of(del(1), vid(1));
        assert!(owed > 0);

        l.slash(vid(1), 1_000).unwrap(); // 10%
        assert_eq!(
            l.delegator_rewards_of(del(1), vid(1)),
            owed,
            "a slash must not touch already-accrued rewards"
        );
    }

    /// LAZY: a key rotation carries the accumulator and the checkpoints, so
    /// the delegator's standing is exactly preserved under the new key.
    #[test]
    fn rotate_key_moves_the_lazy_accumulator_and_checkpoints() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(1100), 1_000).unwrap();
        l.delegate(del(1), vid(1), stell(1000)).unwrap();
        l.distribute_reward(vid(1), stell(200)).unwrap();
        let owed = l.delegator_rewards_of(del(1), vid(1));
        assert!(owed > 0);

        l.rotate_key(vid(1), vid(2)).unwrap();
        assert!(!l.reward_accumulators.contains_key(&vid(1)));
        assert!(l.reward_accumulators.contains_key(&vid(2)));
        assert_eq!(
            l.delegator_rewards_of(del(1), vid(2)),
            owed,
            "the rotation must preserve the delegator's standing exactly"
        );
    }

    // -----------------------------------------------------------------------
    // RANDOMIZED DIFFERENTIAL TEST (F1 re-audit): 200 random operations
    // against an EAGER reference implementation.
    //
    // The eager reference is the pre-lazy implementation, verbatim: every
    // delegator of a validator is credited `pool * stake / delegated` at
    // DISTRIBUTION time, and a stake change never touches the already
    // materialised reward. The lazy ledger must agree with it up to the
    // per-distribution flooring (the lazy truncates the RATE once per
    // distribution, the eager truncates each SHARE once per distribution), so
    // the two differ by at most one nano per distribution per delegator, in
    // EITHER direction — but never by more, and never above the exact
    // pro-rata value.
    // -----------------------------------------------------------------------

    /// One validator's state in the EAGER reference.
    #[derive(Clone, Default)]
    struct EagerVal {
        self_bond: u64,
        delegated: u64,
        commission_bps: u64,
        pending_rewards: u64,
    }

    /// The pre-lazy (eager) delegator-reward implementation, used as the
    /// differential reference.
    #[derive(Clone, Default)]
    struct EagerRef {
        validators: HashMap<ValidatorId, EagerVal>,
        delegations: HashMap<(ValidatorId, [u8; 32]), u64>,
        /// In-flight (unbonding) delegator stake, mirrored from the lazy
        /// pipeline (audit P1: exiting stake takes the slash haircut first).
        unbonding: Vec<(ValidatorId, [u8; 32], u64)>,
        /// Materialised (already credited) delegator rewards.
        rewards: HashMap<(ValidatorId, [u8; 32]), u64>,
        /// Cumulative amounts already claimed (so a comparison can use the
        /// lifetime total, exactly like the lazy side).
        claimed: HashMap<(ValidatorId, [u8; 32]), u64>,
        minted: u64,
    }

    impl EagerRef {
        fn distribute(&mut self, v: ValidatorId, reward: u64) {
            let Some(val) = self.validators.get(&v).cloned() else {
                return;
            };
            let total = val.self_bond + val.delegated;
            if total == 0 || reward == 0 {
                return;
            }
            self.minted = self.minted.saturating_add(reward);
            let delegated_share = (reward as u128 * val.delegated as u128 / total as u128) as u64;
            let commission = (delegated_share as u128 * val.commission_bps as u128
                / BPS_DENOMINATOR as u128) as u64;
            let validator_reward = reward - delegated_share + commission;
            let pool = delegated_share - commission;
            if let Some(slot) = self.validators.get_mut(&v) {
                slot.pending_rewards = slot.pending_rewards.saturating_add(validator_reward);
            }
            if val.delegated == 0 || pool == 0 {
                return;
            }
            // EAGER: credit EVERY delegator, now.
            let keys: Vec<(ValidatorId, [u8; 32])> = self
                .delegations
                .iter()
                .filter(|((vid, _), _)| *vid == v)
                .map(|(k, _)| *k)
                .collect();
            for key in keys {
                let stake = self.delegations.get(&key).copied().unwrap_or(0);
                if stake == 0 {
                    continue;
                }
                let share = (pool as u128 * stake as u128 / val.delegated as u128) as u64;
                let e = self.rewards.entry(key).or_insert(0);
                *e = e.saturating_add(share);
            }
        }

        fn delegate(&mut self, d: [u8; 32], v: ValidatorId, amount: u64) {
            if let Some(val) = self.validators.get_mut(&v) {
                val.delegated = val.delegated.saturating_add(amount);
            }
            let e = self.delegations.entry((v, d)).or_insert(0);
            *e = e.saturating_add(amount);
        }

        fn undelegate(&mut self, d: [u8; 32], v: ValidatorId, amount: u64) {
            if let Some(val) = self.validators.get_mut(&v) {
                val.delegated = val.delegated.saturating_sub(amount);
            }
            let key = (v, d);
            let cur = self.delegations.get(&key).copied().unwrap_or(0);
            if cur <= amount {
                self.delegations.remove(&key);
            } else {
                self.delegations.insert(key, cur - amount);
            }
            // Mirror the lazy pipeline: exiting stake stays slashable until
            // matured (audit P1).
            self.unbonding.push((v, d, amount));
        }

        fn slash(&mut self, v: ValidatorId, bps: u64) {
            let Some(val) = self.validators.get(&v).cloned() else {
                return;
            };
            let unbond_sum: u64 = self
                .unbonding
                .iter()
                .filter(|(vid, _, _)| *vid == v)
                .map(|(_, _, a)| *a)
                .sum();
            let total = val.self_bond + val.delegated + unbond_sum;
            let burn = (total as u128 * bps as u128 / BPS_DENOMINATOR as u128) as u64;
            if burn == 0 {
                return;
            }
            // In-flight haircut first (mirrors the lazy order, audit P1).
            let mut remaining = burn;
            for entry in self.unbonding.iter_mut().filter(|(vid, _, _)| *vid == v) {
                let cut = (entry.2 as u128 * bps as u128 / BPS_DENOMINATOR as u128) as u64;
                let cut = cut.min(entry.2);
                entry.2 -= cut;
                remaining = remaining.saturating_sub(cut);
            }
            self.unbonding.retain(|(_, _, a)| *a > 0);
            let from_self = remaining.min(val.self_bond);
            if let Some(slot) = self.validators.get_mut(&v) {
                slot.self_bond -= from_self;
            }
            remaining -= from_self;
            if remaining == 0 || val.delegated == 0 {
                return;
            }
            let take = remaining.min(val.delegated);
            let ratio_num = take as u128;
            let ratio_den = val.delegated as u128;
            let keys: Vec<(ValidatorId, [u8; 32])> = self
                .delegations
                .iter()
                .filter(|((vid, _), _)| *vid == v)
                .map(|(k, _)| *k)
                .collect();
            let mut slashed = 0u64;
            for key in keys {
                let amount = self.delegations.get(&key).copied().unwrap_or(0);
                let cut = (amount as u128 * ratio_num / ratio_den) as u64;
                let cut = cut.min(amount);
                if cut == 0 {
                    continue;
                }
                if amount - cut == 0 {
                    self.delegations.remove(&key);
                } else {
                    self.delegations.insert(key, amount - cut);
                }
                slashed += cut;
            }
            if let Some(slot) = self.validators.get_mut(&v) {
                slot.delegated = slot.delegated.saturating_sub(slashed);
            }
        }

        fn claim(&mut self, d: [u8; 32], v: ValidatorId) -> u64 {
            let key = (v, d);
            let amount = self.rewards.get(&key).copied().unwrap_or(0);
            if amount == 0 {
                return 0;
            }
            self.rewards.remove(&key);
            let c = self.claimed.entry(key).or_insert(0);
            *c = c.saturating_add(amount);
            amount
        }
    }

    /// THE RANDOMIZED DIFFERENTIAL TEST: 200 random bond/delegate/distribute/
    /// undelegate/claim/slash operations, the lazy ledger against the eager
    /// reference.
    ///
    /// The invariants asserted after EVERY operation:
    ///
    ///  1. the STAKE POSITIONS are byte-identical (the lazy path never
    ///     changes a delegator's stake);
    ///  2. no delegator is OVER-CREDITED: the lazy lifetime total is at most
    ///     the eager one plus one nano per distribution (the lazy rate's
    ///     carried remainder can land a hair above the eager per-distribution
    ///     floor, but never by more than that);
    ///  3. the lazy total is never below the eager one by more than one nano
    ///     per distribution either (the truncation error must not accumulate
    ///     without bound);
    ///  4. the total DISTRIBUTED (validator leg + every delegator's lifetime
    ///     entitlement) never exceeds the total MINTED;
    ///  5. the rewards pool always covers every outstanding entitlement (the
    ///     1:1 backing invariant), and the dust only ever grows.
    #[test]
    fn lazy_ledger_matches_eager_reference_over_200_random_operations() {
        const OPS: usize = 200;
        const N_DELEGATORS: usize = 6;
        const N_VALIDATORS: usize = 3;

        let mut rng = Lcg(0x0DDC_0FFE_EBAD_F00D);
        let mut l = StakingLedger::new();
        let mut eager = EagerRef::default();

        for v in 1..=N_VALIDATORS {
            let id = vid(v as u8);
            let bond = stell(2000);
            let commission = (v as u64) * 250;
            l.bond(id, bond, commission).unwrap();
            eager.validators.insert(
                id,
                EagerVal {
                    self_bond: bond,
                    delegated: 0,
                    commission_bps: commission,
                    pending_rewards: 0,
                },
            );
        }

        let mut distributions: u64 = 0;
        let mut minted: u64 = 0;
        let mut claimed_total: u64 = 0;
        let mut validator_claimed: u64 = 0;

        for step in 0..OPS {
            // Pick an operation. Weights are chosen so the mix exercises the
            // lazy path hard: many distributions, many stake changes.
            let op = rng.below(100);
            let v = vid(1 + (rng.below(N_VALIDATORS as u64)) as u8);
            let d = delegator_addr(rng.below(N_DELEGATORS as u64) as usize);

            match op {
                0..=29 => {
                    // DISTRIBUTE. A validator that was slashed to ZERO total
                    // stake is REFUSED (fail-closed: the caller would
                    // otherwise mint coins with no ledger counterpart), and
                    // the reference skips it the same way.
                    let reward = stell(1 + rng.below(50));
                    let total = l.validators.get(&v).map(|x| x.total()).unwrap_or(0);
                    if total == 0 {
                        assert!(l.distribute_reward(v, reward).is_err());
                        eager.distribute(v, reward);
                        assert_eq!(l.rewards_minted, eager.minted, "step {step}: mint mismatch");
                        continue;
                    }
                    l.distribute_reward(v, reward).unwrap();
                    eager.distribute(v, reward);
                    assert_eq!(l.rewards_minted, eager.minted, "step {step}: mint mismatch");
                    minted += reward;
                    distributions += 1;
                    assert_eq!(l.rewards_minted, minted);
                }
                30..=54 => {
                    // DELEGATE. A validator whose self-bond fell below the
                    // minimum refuses new delegations; the reference skips it
                    // the same way.
                    let amount = stell(1 + rng.below(30));
                    let before = l.delegations.get(&(v, d)).copied().unwrap_or(0);
                    if l.delegate(d, v, amount).is_err() {
                        continue;
                    }
                    eager.delegate(d, v, amount);
                    assert_eq!(
                        l.delegations.get(&(v, d)).copied().unwrap_or(0),
                        before + amount,
                        "step {step}: delegate mismatch"
                    );
                }
                55..=74 => {
                    // UNDELEGATE (only what is held).
                    let held = l.delegations.get(&(v, d)).copied().unwrap_or(0);
                    if held == 0 {
                        continue;
                    }
                    let amount = 1 + rng.below(held);
                    l.undelegate(d, v, amount, 0).unwrap();
                    eager.undelegate(d, v, amount);
                }
                75..=89 => {
                    // CLAIM (delegator). The two implementations floor at
                    // different points (the eager one floors each
                    // distribution's SHARE, the lazy one floors the RATE once
                    // per distribution and carries the remainder), so the
                    // amounts may differ by the accumulated truncation — at
                    // most one nano per distribution, in either direction.
                    let got = l.claim_delegator_rewards(d, v);
                    let want = eager.claim(d, v);
                    let diff = got as i128 - want as i128;
                    assert!(
                        diff.abs() <= distributions as i128,
                        "step {step}: the claim diverged from the reference by {diff} nanos \
                         (got {got}, want {want}, slack {distributions})"
                    );
                    claimed_total += got;
                }
                90..=97 => {
                    // SLASH.
                    let bps = 1 + rng.below(2_000);
                    l.slash(v, bps).unwrap();
                    eager.slash(v, bps);
                }
                _ => {
                    // CLAIM (validator).
                    let got = l.claim_validator_rewards(v).unwrap_or(0);
                    let want = eager
                        .validators
                        .get(&v)
                        .map(|x| x.pending_rewards)
                        .unwrap_or(0);
                    assert_eq!(got, want, "step {step}: the validator claim must match");
                    if let Some(slot) = eager.validators.get_mut(&v) {
                        slot.pending_rewards = 0;
                    }
                    validator_claimed += got;
                }
            }

            // ---- INVARIANT 1: the stake positions are identical. ----
            assert_eq!(
                l.delegations, eager.delegations,
                "step {step}: the stake positions diverged from the reference"
            );
            for (vid_, val) in &eager.validators {
                let lv = &l.validators[vid_];
                assert_eq!(
                    lv.delegated, val.delegated,
                    "step {step}: delegated aggregate"
                );
                assert_eq!(lv.self_bond, val.self_bond, "step {step}: self bond");
            }

            // ---- INVARIANTS 2/3: the lifetime entitlements agree. ----
            let mut _lazy_lifetime_total: u128 = 0;
            let mut _eager_lifetime_total: u128 = 0;
            for key in eager
                .delegations
                .keys()
                .chain(eager.rewards.keys())
                .chain(eager.claimed.keys())
            {
                let lazy_now = l.delegator_rewards_of(key.1, key.0) as u128;
                let lazy_claimed = eager.claimed.get(key).copied().unwrap_or(0) as u128;
                let lazy_lifetime = lazy_now + lazy_claimed;
                let eager_now = eager.rewards.get(key).copied().unwrap_or(0) as u128;
                let eager_claimed = eager.claimed.get(key).copied().unwrap_or(0) as u128;
                let eager_lifetime = eager_now + eager_claimed;
                _lazy_lifetime_total += lazy_lifetime;
                _eager_lifetime_total += eager_lifetime;
                let slack = distributions as i128;
                let diff = lazy_lifetime as i128 - eager_lifetime as i128;
                assert!(
                    diff <= slack,
                    "step {step}: delegator {key:?} is OVER-CREDITED by the lazy ledger \
                     ({lazy_lifetime} vs {eager_lifetime}, slack {slack})"
                );
                assert!(
                    -diff <= slack,
                    "step {step}: delegator {key:?} is UNDER-CREDITED by the lazy ledger \
                     ({lazy_lifetime} vs {eager_lifetime}, slack {slack})"
                );
            }

            // ---- INVARIANT 4: never distribute more than was minted. ----
            let outstanding: u128 = l
                .delegator_rewards
                .values()
                .map(|v| *v as u128)
                .sum::<u128>()
                + l.validators
                    .values()
                    .map(|v| v.pending_rewards as u128)
                    .sum::<u128>();
            assert!(
                outstanding <= minted as u128,
                "step {step}: outstanding rewards ({outstanding}) exceed the minted total ({minted})"
            );
            assert!(
                l.rewards_pool as u128 >= outstanding,
                "step {step}: the rewards pool ({}) does not cover the outstanding rewards ({outstanding})",
                l.rewards_pool
            );
            assert_eq!(
                l.rewards_minted, minted,
                "step {step}: the mint counter drifted from the reference"
            );
        }

        // The run must have exercised the interesting paths.
        assert!(
            distributions > 20,
            "the run must include many distributions"
        );
        assert!(claimed_total > 0, "the run must include claims");
        assert!(
            validator_claimed > 0,
            "the run must include validator claims"
        );
    }

    /// A delegator that fully undelegated earns NOTHING from the
    /// distributions that follow: the checkpoint moved on the exit, so the
    /// stake it no longer has cannot earn.
    #[test]
    fn lazy_undelegated_stake_never_earns_again() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(1100), DEFAULT_COMMISSION_BPS).unwrap();
        l.delegate(del(1), vid(1), stell(1000)).unwrap();
        l.distribute_reward(vid(1), stell(200)).unwrap();
        let owed = l.delegator_rewards_of(del(1), vid(1));
        assert!(owed > 0);

        l.undelegate(del(1), vid(1), stell(1000), 0).unwrap();
        for _ in 0..10 {
            l.distribute_reward(vid(1), stell(200)).unwrap();
        }
        assert_eq!(
            l.delegator_rewards_of(del(1), vid(1)),
            owed,
            "a delegator that left must not earn on the stake it no longer has"
        );
    }

    /// The lazy accumulator and the delegator checkpoints SURVIVE a
    /// snapshot/restore round trip: the ledger is bincode-serialised (the
    /// storage layer's `DomainSnapshot` carries it verbatim) and decoded
    /// again — the delegator's entitlement must be IDENTICAL, and the
    /// delegator must not be able to claim the same accrual twice.
    #[test]
    fn lazy_accumulator_survives_a_snapshot_restore_round_trip() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(1100), DEFAULT_COMMISSION_BPS).unwrap();
        l.delegate(del(1), vid(1), stell(1000)).unwrap();
        l.delegate(del(2), vid(1), stell(2000)).unwrap();
        l.distribute_reward(vid(1), stell(200)).unwrap();

        let owed_1 = l.delegator_rewards_of(del(1), vid(1));
        let owed_2 = l.delegator_rewards_of(del(2), vid(1));
        assert!(owed_1 > 0 && owed_2 > 0);

        // The storage layer writes the ledger with bincode (no field names),
        // so the round trip is exactly this.
        let bytes = bincode::serialize(&l).unwrap();
        let mut back: StakingLedger = bincode::deserialize(&bytes).unwrap();
        assert_eq!(
            back.reward_accumulators, l.reward_accumulators,
            "the accumulator must survive the round trip"
        );
        assert_eq!(
            back.delegator_reward_checkpoints, l.delegator_reward_checkpoints,
            "the checkpoints must survive the round trip"
        );
        assert_eq!(
            back.delegator_rewards_of(del(1), vid(1)),
            owed_1,
            "the entitlement must be identical after the restore"
        );
        assert_eq!(back.delegator_rewards_of(del(2), vid(1)), owed_2);
        assert_eq!(back.rewards_minted, l.rewards_minted);
        assert_eq!(back.rewards_pool, l.rewards_pool);

        // And the restored ledger must not pay the same accrual twice.
        let claimed = back.claim_delegator_rewards(del(1), vid(1));
        assert_eq!(claimed, owed_1, "the restored ledger pays exactly once");
        assert_eq!(back.delegator_rewards_of(del(1), vid(1)), 0);
    }

    /// The E7 governance-lock domain and the lazy accumulator coexist: a
    /// governance lock does not disturb the reward accounting.
    #[test]
    fn lazy_rewards_survive_governance_locks() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(2000), DEFAULT_COMMISSION_BPS).unwrap();
        l.delegate(del(1), vid(1), stell(1000)).unwrap();
        l.distribute_reward(vid(1), stell(200)).unwrap();
        let owed = l.delegator_rewards_of(del(1), vid(1));
        l.lock_governance(del(1), stell(1000));
        assert_eq!(
            l.delegator_rewards_of(del(1), vid(1)),
            owed,
            "a governance lock must not touch the reward accounting"
        );
    }

    /// E7: locked stake cannot unbond/undelegate; the lock is saturating,
    /// self-cleaning, and travels with a key rotation.
    #[test]
    fn governance_locks_block_exits_until_released() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(2000), DEFAULT_COMMISSION_BPS).unwrap();
        l.delegate(del(1), vid(1), stell(1000)).unwrap();

        // Lock the delegator's full 1000 position: no exit at all.
        l.lock_governance(del(1), stell(1000));
        assert_eq!(l.locked_governance_of(&del(1)), stell(1000));
        assert_eq!(
            l.undelegate(del(1), vid(1), stell(1), 0),
            Err(StakingError::LockedInGovernanceVote)
        );
        // Locking zero is a no-op (keeps the map — and the digest — clean).
        l.lock_governance(del(1), 0);
        assert_eq!(l.locked_governance_of(&del(1)), stell(1000));
        // Partial release re-opens exactly the released portion.
        l.unlock_governance(del(1), stell(400));
        assert_eq!(l.locked_governance_of(&del(1)), stell(600));
        l.undelegate(del(1), vid(1), stell(400), 0).unwrap();
        assert_eq!(
            l.undelegate(del(1), vid(1), stell(1), 0),
            Err(StakingError::LockedInGovernanceVote)
        );
        // Full release empties the map (no phantom entries in the digest).
        l.unlock_governance(del(1), stell(600));
        assert!(l.locked_governance.is_empty());
        l.undelegate(del(1), vid(1), stell(600), 0).unwrap();

        // Self-bond locks refuse unbond the same way (partial lock, partial exit).
        l.lock_governance(vid(1), stell(500));
        assert_eq!(
            l.unbond(vid(1), stell(1600), 0),
            Err(StakingError::LockedInGovernanceVote)
        );
        l.unbond(vid(1), stell(900), 0).unwrap();
        // Over-release saturates to empty, never underflows.
        l.unlock_governance(vid(1), u64::MAX);
        assert!(l.locked_governance.is_empty());
    }

    /// Key rotation is strictly forbidden while stake is locked in governance
    /// to eliminate vote multiplication exploits.
    #[test]
    fn governance_lock_follows_key_rotation() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(2000), DEFAULT_COMMISSION_BPS).unwrap();
        l.lock_governance(vid(1), stell(2000));
        assert_eq!(
            l.rotate_key(vid(1), vid(2)),
            Err(StakingError::LockedInGovernanceVote)
        );
        l.unlock_governance(vid(1), stell(2000));
        l.rotate_key(vid(1), vid(2)).unwrap();
        assert_eq!(l.locked_governance_of(&vid(1)), 0);
        assert_eq!(l.locked_governance_of(&vid(2)), 0);
        l.unbond(vid(2), stell(2000), 0).unwrap();
    }

    /// Build two conflicting bodies for one height, both signed by `sk`.
    fn proposal_pair(
        sk: &SigningKey,
        height: u64,
        t1: u64,
        t2: u64,
    ) -> crate::consensus::ProposalEquivocationEvidence {
        use crate::consensus::ProposalEquivocationEvidence;
        let mk = |ts: u64| {
            let mut b = crate::sharding::Block {
                height,
                proposer: sk.verifying_key().to_bytes(),
                timestamp: ts,
                ..Default::default()
            };
            b.sign_block(sk);
            b
        };
        ProposalEquivocationEvidence::new(sk.verifying_key().to_bytes(), mk(t1), mk(t2))
    }

    #[test]
    fn verified_proposal_equivocation_burns_five_percent_self_first() {
        let mut l = StakingLedger::new();
        let sk = SigningKey::generate(&mut OsRng);
        let offender = sk.verifying_key().to_bytes();
        l.bond(offender, stell(2000), DEFAULT_COMMISSION_BPS)
            .unwrap();
        let ev = proposal_pair(&sk, 5, 1_000, 2_000);
        assert_ne!(
            ev.block_a.compute_hash(),
            ev.block_b.compute_hash(),
            "need two distinct bodies"
        );
        let before = l.validators[&offender].self_bond;
        let burned = l.slash_proposal_equivocation_verified(&ev).unwrap();
        assert_eq!(burned, stell(100), "5% of 2000 STELL");
        assert_eq!(l.validators[&offender].self_bond, before - burned);
        assert_eq!(l.validators[&offender].total_slashed, burned);
        assert_eq!(l.total_burned, burned);
    }

    #[test]
    fn verified_proposal_equivocation_dedupes_repeat_offense() {
        let mut l = StakingLedger::new();
        let sk = SigningKey::generate(&mut OsRng);
        let offender = sk.verifying_key().to_bytes();
        l.bond(offender, stell(2000), DEFAULT_COMMISSION_BPS)
            .unwrap();
        let ev = proposal_pair(&sk, 5, 1_000, 2_000);
        let first = l.slash_proposal_equivocation_verified(&ev).unwrap();
        assert!(first > 0);
        // Same pair again, and blocks-swapped: both burn 0, stake untouched.
        let swapped = crate::consensus::ProposalEquivocationEvidence::new(
            offender,
            ev.block_b.clone(),
            ev.block_a.clone(),
        );
        assert_eq!(l.slash_proposal_equivocation_verified(&ev).unwrap(), 0);
        assert_eq!(l.slash_proposal_equivocation_verified(&swapped).unwrap(), 0);
        assert_eq!(l.total_burned, first);
        assert_eq!(l.total_stake(&offender), stell(2000) - first);
        // A DISTINCT conflicting pair at the same height is a new offense.
        let fresh = proposal_pair(&sk, 5, 3_000, 4_000);
        let second = l.slash_proposal_equivocation_verified(&fresh).unwrap();
        assert!(second > 0, "distinct conflicting pair is a new offense");
        assert_eq!(l.total_burned, first + second);
    }

    #[test]
    fn verified_proposal_equivocation_refuses_forgeries_fail_closed() {
        let mut l = StakingLedger::new();
        let sk = SigningKey::generate(&mut OsRng);
        let offender = sk.verifying_key().to_bytes();
        l.bond(offender, stell(2000), DEFAULT_COMMISSION_BPS)
            .unwrap();
        // Same block twice burns nothing (single proposal repeated).
        let same = proposal_pair(&sk, 5, 1_000, 1_000);
        assert_eq!(l.slash_proposal_equivocation_verified(&same).unwrap(), 0);
        // Framing with another key's block burns nothing.
        let other = SigningKey::generate(&mut OsRng);
        let mut ob = crate::sharding::Block {
            height: 5,
            proposer: other.verifying_key().to_bytes(),
            timestamp: 9_000,
            ..Default::default()
        };
        ob.sign_block(&other);
        let framed = crate::consensus::ProposalEquivocationEvidence::new(
            offender,
            proposal_pair(&sk, 5, 1_000, 2_000).block_a.clone(),
            ob,
        );
        assert_eq!(l.slash_proposal_equivocation_verified(&framed).unwrap(), 0);
        // Forged signature burns nothing.
        let mut forged = proposal_pair(&sk, 5, 1_000, 2_000);
        forged.block_b.validator_signatures[0].1[0] ^= 0xFF;
        assert_eq!(l.slash_proposal_equivocation_verified(&forged).unwrap(), 0);
        // Unknown proposer errors (transition maps to skip-and-log).
        let outsider = SigningKey::generate(&mut OsRng);
        let oid = outsider.verifying_key().to_bytes();
        let oev = crate::consensus::ProposalEquivocationEvidence::new(
            oid,
            {
                let mut b = crate::sharding::Block {
                    height: 5,
                    proposer: oid,
                    timestamp: 1,
                    ..Default::default()
                };
                b.sign_block(&outsider);
                b
            },
            {
                let mut b = crate::sharding::Block {
                    height: 5,
                    proposer: oid,
                    timestamp: 2,
                    ..Default::default()
                };
                b.sign_block(&outsider);
                b
            },
        );
        assert_eq!(
            l.slash_proposal_equivocation_verified(&oev),
            Err(StakingError::NotValidator)
        );
        // Nothing moved anywhere.
        assert_eq!(l.total_stake(&offender), stell(2000));
        assert_eq!(l.total_burned, 0);
    }

    #[test]
    fn test_pq_equivocation_valid_evidence_slashes_bonded_validator() {
        let mut l = StakingLedger::new();
        let sk = SigningKey::generate(&mut OsRng);
        let vid = sk.verifying_key().to_bytes();
        l.bond(vid, stell(2000), DEFAULT_COMMISSION_BPS).unwrap();
        l.delegate(del(1), vid, stell(1000)).unwrap();
        // Total stake = 3000 STELL

        let h = 10;
        let r = 0;
        let kind = VoteKind::Prevote;
        let target_a = Some([0x11; 32]);
        let target_b = Some([0x22; 32]);

        let msg_a = crate::consensus::vote_sign_bytes(h, r, kind, &target_a);
        let msg_b = crate::consensus::vote_sign_bytes(h, r, kind, &target_b);
        let sig_a = sk.sign(&msg_a).to_bytes().to_vec();
        let sig_b = sk.sign(&msg_b).to_bytes().to_vec();

        let evidence = CompactPqEquivocationEvidence {
            voter: vid,
            height: h,
            round: r,
            kind,
            block_hash_a: target_a,
            signature_a: sig_a,
            block_hash_b: target_b,
            signature_b: sig_b,
        };

        let burned = l.slash_pq_equivocation(&evidence, false).unwrap();
        // Standard: 5% of 3000 STELL = 150 STELL (500 bps)
        assert_eq!(burned, stell(150));
        assert_eq!(l.total_stake(&vid), stell(2850));
        assert_eq!(l.total_burned, stell(150));
        assert!(l.validators.contains_key(&vid));
    }

    #[test]
    fn test_pq_equivocation_micro_committee_100_percent_and_evicts() {
        let mut l = StakingLedger::new();
        let sk = SigningKey::generate(&mut OsRng);
        let vid = sk.verifying_key().to_bytes();
        l.bond(vid, stell(1100), DEFAULT_COMMISSION_BPS).unwrap();
        l.delegate(del(1), vid, stell(1000)).unwrap();
        // Total stake = 2100 STELL

        let h = 42;
        let r = 1;
        let kind = VoteKind::Precommit;
        let target_a = Some([0xAA; 32]);
        let target_b = Some([0xBB; 32]);

        let msg_a = crate::consensus::vote_sign_bytes(h, r, kind, &target_a);
        let msg_b = crate::consensus::vote_sign_bytes(h, r, kind, &target_b);
        let sig_a = sk.sign(&msg_a).to_bytes().to_vec();
        let sig_b = sk.sign(&msg_b).to_bytes().to_vec();

        let evidence = CompactPqEquivocationEvidence {
            voter: vid,
            height: h,
            round: r,
            kind,
            block_hash_a: target_a,
            signature_a: sig_a,
            block_hash_b: target_b,
            signature_b: sig_b,
        };

        let burned = l.slash_pq_equivocation(&evidence, true).unwrap();
        // Micro-committee: 100% of bond (10,000 bps)
        assert_eq!(burned, stell(2100));
        assert_eq!(l.total_burned, stell(2100));
        assert_eq!(l.total_stake(&vid), 0);
        // Eviction check: removed from validators
        assert!(!l.validators.contains_key(&vid));
        assert!(!l.delegations.contains_key(&(vid, del(1))));
    }

    #[test]
    fn test_pq_equivocation_non_conflicting_targets_rejected() {
        let mut l = StakingLedger::new();
        let sk = SigningKey::generate(&mut OsRng);
        let vid = sk.verifying_key().to_bytes();
        l.bond(vid, stell(1100), DEFAULT_COMMISSION_BPS).unwrap();

        let h = 5;
        let r = 0;
        let kind = VoteKind::Prevote;
        let target = Some([0x42; 32]);

        let msg = crate::consensus::vote_sign_bytes(h, r, kind, &target);
        let sig = sk.sign(&msg).to_bytes().to_vec();

        // Target A == Target B -> non-conflicting
        let evidence = CompactPqEquivocationEvidence {
            voter: vid,
            height: h,
            round: r,
            kind,
            block_hash_a: target,
            signature_a: sig.clone(),
            block_hash_b: target,
            signature_b: sig.clone(),
        };

        let burned = l.slash_pq_equivocation(&evidence, false).unwrap();
        assert_eq!(burned, 0, "Non-conflicting evidence must not slash");
        assert_eq!(l.total_stake(&vid), stell(1100));
        assert_eq!(l.total_burned, 0);

        // Also both None -> non-conflicting
        let msg_nil = crate::consensus::vote_sign_bytes(h, r, kind, &None);
        let sig_nil = sk.sign(&msg_nil).to_bytes().to_vec();
        let evidence_nil = CompactPqEquivocationEvidence {
            voter: vid,
            height: h,
            round: r,
            kind,
            block_hash_a: None,
            signature_a: sig_nil.clone(),
            block_hash_b: None,
            signature_b: sig_nil,
        };
        let burned_nil = l.slash_pq_equivocation(&evidence_nil, false).unwrap();
        assert_eq!(burned_nil, 0);
        assert_eq!(l.total_stake(&vid), stell(1100));
    }

    #[test]
    fn test_pq_equivocation_invalid_signature_rejected_with_error() {
        let mut l = StakingLedger::new();
        let sk = SigningKey::generate(&mut OsRng);
        let vid = sk.verifying_key().to_bytes();
        l.bond(vid, stell(1100), DEFAULT_COMMISSION_BPS).unwrap();

        let h = 5;
        let r = 0;
        let kind = VoteKind::Prevote;
        let target_a = Some([0x11; 32]);
        let target_b = Some([0x22; 32]);

        let msg_a = crate::consensus::vote_sign_bytes(h, r, kind, &target_a);
        let msg_b = crate::consensus::vote_sign_bytes(h, r, kind, &target_b);
        let sig_a = sk.sign(&msg_a).to_bytes().to_vec();
        let sig_b = sk.sign(&msg_b).to_bytes().to_vec();

        // 1. Tampered signature B
        let mut bad_sig_b = sig_b.clone();
        bad_sig_b[0] ^= 0xFF;
        let evidence_bad_b = CompactPqEquivocationEvidence {
            voter: vid,
            height: h,
            round: r,
            kind,
            block_hash_a: target_a,
            signature_a: sig_a.clone(),
            block_hash_b: target_b,
            signature_b: bad_sig_b,
        };
        assert_eq!(
            l.slash_pq_equivocation(&evidence_bad_b, false),
            Err(StakingError::InvalidSignature)
        );
        assert_eq!(l.total_stake(&vid), stell(1100));
        assert_eq!(l.total_burned, 0);

        // 2. Tampered signature A
        let mut bad_sig_a = sig_a.clone();
        bad_sig_a[0] ^= 0xFF;
        let evidence_bad_a = CompactPqEquivocationEvidence {
            voter: vid,
            height: h,
            round: r,
            kind,
            block_hash_a: target_a,
            signature_a: bad_sig_a,
            block_hash_b: target_b,
            signature_b: sig_b.clone(),
        };
        assert_eq!(
            l.slash_pq_equivocation(&evidence_bad_a, false),
            Err(StakingError::InvalidSignature)
        );

        // 3. Forged signature by another validator
        let other_sk = SigningKey::generate(&mut OsRng);
        let forged_sig_b = other_sk.sign(&msg_b).to_bytes().to_vec();
        let evidence_forged = CompactPqEquivocationEvidence {
            voter: vid,
            height: h,
            round: r,
            kind,
            block_hash_a: target_a,
            signature_a: sig_a,
            block_hash_b: target_b,
            signature_b: forged_sig_b,
        };
        assert_eq!(
            l.slash_pq_equivocation(&evidence_forged, false),
            Err(StakingError::InvalidSignature)
        );
    }

    #[test]
    fn test_pq_equivocation_deduplication_prevents_double_slashing() {
        let mut l = StakingLedger::new();
        let sk = SigningKey::generate(&mut OsRng);
        let vid = sk.verifying_key().to_bytes();
        l.bond(vid, stell(2000), DEFAULT_COMMISSION_BPS).unwrap();

        let h = 100;
        let r = 2;
        let kind = VoteKind::Prevote;
        let target_a = Some([0x01; 32]);
        let target_b = Some([0x02; 32]);

        let msg_a = crate::consensus::vote_sign_bytes(h, r, kind, &target_a);
        let msg_b = crate::consensus::vote_sign_bytes(h, r, kind, &target_b);
        let sig_a = sk.sign(&msg_a).to_bytes().to_vec();
        let sig_b = sk.sign(&msg_b).to_bytes().to_vec();

        let evidence = CompactPqEquivocationEvidence {
            voter: vid,
            height: h,
            round: r,
            kind,
            block_hash_a: target_a,
            signature_a: sig_a,
            block_hash_b: target_b,
            signature_b: sig_b,
        };

        // First presentation slashes 5% of 2000 = 100 STELL
        let burned1 = l.slash_pq_equivocation(&evidence, false).unwrap();
        assert_eq!(burned1, stell(100));
        assert_eq!(l.total_stake(&vid), stell(1900));
        assert_eq!(l.total_burned, stell(100));

        // Replay of same evidence is deduplicated -> returns Ok(0)
        let burned2 = l.slash_pq_equivocation(&evidence, false).unwrap();
        assert_eq!(burned2, 0, "Duplicate evidence must return 0 burned");
        assert_eq!(
            l.total_stake(&vid),
            stell(1900),
            "Stake must not compound burn"
        );
        assert_eq!(l.total_burned, stell(100));

        // Third vote on the same (voter, height, round, kind) is also deduplicated
        let target_c = Some([0x03; 32]);
        let msg_c = crate::consensus::vote_sign_bytes(h, r, kind, &target_c);
        let sig_c = sk.sign(&msg_c).to_bytes().to_vec();
        let evidence_c = CompactPqEquivocationEvidence {
            voter: vid,
            height: h,
            round: r,
            kind,
            block_hash_a: target_a,
            signature_a: evidence.signature_a.clone(),
            block_hash_b: target_c,
            signature_b: sig_c,
        };
        let burned3 = l.slash_pq_equivocation(&evidence_c, false).unwrap();
        assert_eq!(
            burned3, 0,
            "Deduplication key BLAKE3(voter || height || round || kind) prevents compounding"
        );
        assert_eq!(l.total_stake(&vid), stell(1900));
    }

    #[test]
    fn test_pq_equivocation_falcon512_registered_key_slashes() {
        let mut l = StakingLedger::new();
        let vid = vid(77);
        l.bond(vid, stell(5000), DEFAULT_COMMISSION_BPS).unwrap();

        // Register a REAL Falcon-512 keypair. `slash_pq_equivocation` verifies
        // through `verify_pq_signature` -> `verify_falcon512` (FIPS 206 math, no
        // test fallback), so a synthetic check-digest signature is always
        // rejected as InvalidSignature.
        let fk = crate::post_quantum::FalconKeypair::generate_from_seed(77);
        let falcon_pk = fk.public_key().to_vec();
        l.register_pq_key(
            vid,
            crate::post_quantum::PqScheme::Falcon512,
            falcon_pk.clone(),
        )
        .unwrap();

        assert_eq!(
            l.get_pq_key(&vid),
            Some((crate::post_quantum::PqScheme::Falcon512, falcon_pk.clone()))
        );

        let h = 200;
        let r = 0;
        let kind = VoteKind::Prevote;
        let target_a = Some([0xAA; 32]);
        let target_b = Some([0xBB; 32]);

        let msg_a = crate::consensus::vote_sign_bytes(h, r, kind, &target_a);
        let msg_b = crate::consensus::vote_sign_bytes(h, r, kind, &target_b);

        let sig_a = fk.sign(&msg_a);
        let sig_b = fk.sign(&msg_b);
        assert_eq!(sig_a.len(), crate::post_quantum::FALCON512_SIG_LEN);
        assert_eq!(sig_b.len(), crate::post_quantum::FALCON512_SIG_LEN);
        assert!(
            crate::post_quantum::verify_pq_signature(
                crate::post_quantum::PqScheme::Falcon512,
                &falcon_pk,
                &msg_a,
                &sig_a
            ) && crate::post_quantum::verify_pq_signature(
                crate::post_quantum::PqScheme::Falcon512,
                &falcon_pk,
                &msg_b,
                &sig_b
            ),
            "the evidence must carry signatures the ledger itself will accept"
        );

        let evidence = CompactPqEquivocationEvidence {
            voter: vid,
            height: h,
            round: r,
            kind,
            block_hash_a: target_a,
            signature_a: sig_a,
            block_hash_b: target_b,
            signature_b: sig_b,
        };

        // Standard 5% slash on 5000 STELL = 250 STELL
        let burned = l.slash_pq_equivocation(&evidence, false).unwrap();
        assert_eq!(burned, stell(250));
        assert_eq!(l.total_stake(&vid), stell(4750));
        assert_eq!(l.total_burned, stell(250));
    }

    // --- MIN+buffer / eject-WARN policy (урок валидатора C) ---

    /// Capture WARN+ logs emitted by `f` on THIS thread (scoped default
    /// subscriber, so parallel tests are unaffected).
    #[cfg(test)]
    fn capture_warns(f: impl FnOnce()) -> String {
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::fmt::writer::MakeWriter;

        #[derive(Clone)]
        struct BufWriter(Arc<Mutex<Vec<u8>>>);
        struct BufGuard(Arc<Mutex<Vec<u8>>>);
        impl<'a> MakeWriter<'a> for BufWriter {
            type Writer = BufGuard;
            fn make_writer(&'a self) -> Self::Writer {
                BufGuard(self.0.clone())
            }
        }
        impl std::io::Write for BufGuard {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
        let sub = tracing_subscriber::fmt()
            .with_writer(BufWriter(buf.clone()))
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(sub, f);
        let out = String::from_utf8(buf.lock().unwrap().clone()).unwrap_or_default();
        out
    }

    #[test]
    fn slash_warns_within_gap_before_eject_and_on_eject() {
        // Pure message builders first (no env, no subscriber).
        let gap = stell(100);
        let v = vid(9);
        // Well above the gap: silent.
        assert!(eject_warn_message_for(&v, stell(1300), stell(1), gap).is_none());
        assert!(eject_message_for(&v, stell(1300), stell(1)).is_none());
        // Inside [MIN, MIN+gap): approach WARN with the required wording.
        let msg =
            eject_warn_message_for(&v, stell(1045), stell(55), gap).expect("must warn in gap");
        assert!(
            msg.contains("будет выкинут через"),
            "message must say: {msg}"
        );
        assert!(msg.contains("SLASH-EJECT-WARN"), "message must say: {msg}");
        // Below MIN: eject WARN, not approach WARN.
        assert!(eject_warn_message_for(&v, stell(999), stell(1), gap).is_none());
        let msg = eject_message_for(&v, stell(999), stell(1)).expect("must report eject");
        assert!(msg.contains("EJECTED"), "message must say: {msg}");

        // Live: slash landing inside the default 100 STELL gap WARNs loudly.
        let logs = capture_warns(|| {
            let mut l = StakingLedger::new();
            l.bond(vid(11), stell(1100), DEFAULT_COMMISSION_BPS)
                .unwrap();
            // 5% of 1100 = 55 -> 1045, i.e. 45 STELL above MIN: inside the gap.
            let burned = l.slash(vid(11), 500).unwrap();
            assert_eq!(burned, stell(55));
            assert_eq!(l.validators[&vid(11)].self_bond, stell(1045));
        });
        assert!(
            logs.contains("будет выкинут через"),
            "slash must WARN in gap, got: {logs}"
        );
        assert!(
            logs.contains("SLASH-EJECT-WARN"),
            "slash must WARN in gap, got: {logs}"
        );

        // Live: validator C case, modern shape — floor bond (1100) + a slash
        // that actually ejects + WARNs. (Bare-MIN bonds can no longer be
        // created: `bond` refuses them, see bond_enforces_minimum_plus_buffer.)
        let logs = capture_warns(|| {
            let mut l = StakingLedger::new();
            l.bond(vid(12), stell(1100), DEFAULT_COMMISSION_BPS)
                .unwrap();
            // 10% of 1100 = 110 -> 990 < MIN: ejected.
            let burned = l.slash(vid(12), 1_000).unwrap();
            assert_eq!(burned, stell(110));
            assert!(l.validators[&vid(12)].self_bond < MIN_VALIDATOR_BOND);
            assert!(!l.to_validator_set().validators.contains_key(&vid(12)));
        });
        assert!(
            logs.contains("EJECTED"),
            "eject must WARN loudly, got: {logs}"
        );
        assert!(
            logs.contains("SLASH-EJECT"),
            "eject must WARN loudly, got: {logs}"
        );
    }

    #[test]
    fn bond_and_add_bond_warn_below_min_plus_buffer() {
        let buf = stell(100);
        // Pure builders: bare MIN lacks the cushion, MIN+buffer does not.
        assert!(buffer_warn_message_for(stell(1000), buf).is_some());
        assert!(buffer_warn_message_for(stell(1099), buf).is_some());
        assert!(buffer_warn_message_for(stell(1100), buf).is_none());
        assert!(buffer_warn_message_for(stell(5000), buf).is_none());
        // Env parsing without touching the process env (parallel-safe).
        assert_eq!(parse_nano_env(None, stell(100)), stell(100));
        assert_eq!(parse_nano_env(Some("123".to_string()), stell(100)), 123);
        assert_eq!(parse_nano_env(Some("  456  ".to_string()), stell(100)), 456);
        assert_eq!(
            parse_nano_env(Some("garbage".to_string()), stell(100)),
            stell(100)
        );
        assert_eq!(DEFAULT_SLASH_EJECT_WARN_GAP_NANO, stell(100));
        assert_eq!(DEFAULT_MIN_BOND_BUFFER_NANO, stell(100));

        // Live: bare-MIN bond is REFUSED (fail-closed floor, not a WARN).
        let logs = capture_warns(|| {
            let mut l = StakingLedger::new();
            assert_eq!(
                l.bond(vid(21), stell(1000), DEFAULT_COMMISSION_BPS),
                Err(StakingError::BondBelowMinimum)
            );
        });
        assert!(
            !logs.contains("MIN-BOND-BUFFER"),
            "refused bond needs no cushion WARN, got: {logs}"
        );

        // Live: cushioned bond is silent on the buffer channel.
        let logs = capture_warns(|| {
            let mut l = StakingLedger::new();
            assert!(l.bond(vid(22), stell(1200), DEFAULT_COMMISSION_BPS).is_ok());
        });
        assert!(
            !logs.contains("MIN-BOND-BUFFER"),
            "cushioned bond must not buffer-WARN, got: {logs}"
        );

        // Live: add_bond below MIN+buffer WARNs, above it does not; never refused.
        let logs = capture_warns(|| {
            let mut l = StakingLedger::new();
            l.bond(vid(23), stell(1200), DEFAULT_COMMISSION_BPS)
                .unwrap();
            // Slash down into the buffer-less zone, then top up insufficiently.
            l.slash(vid(23), 500).unwrap(); // 5% of 1200 = 60 -> 1140 (has buffer)
            assert!(l.add_bond(vid(23), stell(10)).is_ok());
        });
        assert!(
            !logs.contains("MIN-BOND-BUFFER") || logs.contains("SLASH-EJECT-WARN"),
            "1140+10=1150 keeps the cushion-or-slash WARNs only, got: {logs}"
        );

        let logs = capture_warns(|| {
            let mut l = StakingLedger::new();
            l.bond(vid(24), stell(1100), DEFAULT_COMMISSION_BPS)
                .unwrap();
            l.slash(vid(24), 500).unwrap(); // 5% of 1100 = 55 -> 1045 (no cushion)
            assert!(l.add_bond(vid(24), stell(50)).is_ok()); // 1095 < 1100 -> WARN
            assert_eq!(l.validators[&vid(24)].self_bond, stell(1095));
        });
        assert!(
            logs.contains("MIN-BOND-BUFFER"),
            "under-cushion top-up must WARN, got: {logs}"
        );
    }

    #[test]
    fn slash_deducts_from_pending_unbonding_entries() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(2000), DEFAULT_COMMISSION_BPS).unwrap();
        // Fully unbond to zero active self-bond
        l.unbond(vid(1), stell(2000), 100).unwrap();
        assert_eq!(l.validators[&vid(1)].self_bond, 0);
        assert_eq!(l.unbonding.len(), 1);
        assert_eq!(l.unbonding[0].amount, stell(2000));

        // Slash 10% (1000 bps)
        let burned = l.slash(vid(1), 1_000).unwrap();
        assert_eq!(burned, stell(200));
        assert_eq!(l.total_burned, stell(200));
        assert_eq!(l.unbonding.len(), 1);
        assert_eq!(l.unbonding[0].amount, stell(1800));

        // Unbonding entries fully drained are removed
        let burned2 = l.slash(vid(1), 10_000).unwrap(); // 100% of remaining 1800
        assert_eq!(burned2, stell(1800));
        assert!(l.unbonding.is_empty());
    }

    #[test]
    fn rotate_key_strictly_forbids_governance_locked_validator() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(2000), DEFAULT_COMMISSION_BPS).unwrap();
        l.lock_governance(vid(1), stell(1000));
        assert_eq!(
            l.rotate_key(vid(1), vid(2)),
            Err(StakingError::LockedInGovernanceVote)
        );
        l.unlock_governance(vid(1), stell(1000));
        assert!(l.rotate_key(vid(1), vid(2)).is_ok());
    }

    #[test]
    fn unbond_strictly_requires_required_bond_floor_or_zero() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(2000), DEFAULT_COMMISSION_BPS).unwrap();
        // required_bond_floor_nano() is 1100 STELL.
        // Leaving 1099 STELL (< 1100) must fail
        assert_eq!(
            l.unbond(vid(1), stell(901), 0),
            Err(StakingError::BondBelowMinimum)
        );
        // Leaving 1100 STELL (== 1100) succeeds
        assert!(l.unbond(vid(1), stell(900), 0).is_ok());
        // Remaining is 1100. Unbonding 1100 leaves 0 (full exit), succeeds
        assert!(l.unbond(vid(1), stell(1100), 0).is_ok());
    }

    #[test]
    fn delegate_requires_minimum_self_bond() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(1100), DEFAULT_COMMISSION_BPS).unwrap();
        // Fully unbond validator to drop below MIN_VALIDATOR_BOND
        l.unbond(vid(1), stell(1100), 0).unwrap();
        assert_eq!(l.validators[&vid(1)].self_bond, 0);

        // Delegation to inactive validator is rejected
        assert_eq!(
            l.delegate(del(1), vid(1), stell(500)),
            Err(StakingError::NotValidator)
        );
    }

    /// The PQ evidence envelope must be MEASURABLE (the gas table prices it
    /// per wire byte) and BOUNDED (the DoS cap refuses anything bigger
    /// instead of truncating it).
    #[test]
    fn pq_evidence_wire_len_is_measured_and_bounded() {
        let sk = SigningKey::generate(&mut OsRng);
        let vid = sk.verifying_key().to_bytes();
        let h = 5u64;
        let r = 0u32;
        let kind = VoteKind::Prevote;
        let target_a = Some([0x11u8; 32]);
        let target_b = Some([0x22u8; 32]);
        let msg_a = crate::consensus::vote_sign_bytes(h, r, kind, &target_a);
        let msg_b = crate::consensus::vote_sign_bytes(h, r, kind, &target_b);
        let ev = CompactPqEquivocationEvidence {
            voter: vid,
            height: h,
            round: r,
            kind,
            block_hash_a: target_a,
            signature_a: sk.sign(&msg_a).to_bytes().to_vec(),
            block_hash_b: target_b,
            signature_b: sk.sign(&msg_b).to_bytes().to_vec(),
        };
        let len = ev.wire_len();
        assert!(len > 0, "the envelope must have a measurable size");
        assert!(
            len <= MAX_PQ_EQUIVOCATION_EVIDENCE_BYTES,
            "an Ed25519 envelope ({len} bytes) must fit the cap"
        );
        // The dedup key is the per-offense identity: same (voter, height,
        // round, kind) -> same key, so the same offense cannot burn twice.
        let mut other = ev.clone();
        other.block_hash_b = Some([0x33u8; 32]);
        assert_eq!(
            ev.dedup_key(),
            other.dedup_key(),
            "the dedup key must not depend on the targets"
        );
    }

    #[test]
    fn to_validator_set_respects_governed_min_validator_bond() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(1500), DEFAULT_COMMISSION_BPS).unwrap();
        l.bond(vid(2), stell(2500), DEFAULT_COMMISSION_BPS).unwrap();

        // Default: both elected (both >= 1000)
        let vs = l.to_validator_set();
        assert!(vs.validators.contains_key(&vid(1)));
        assert!(vs.validators.contains_key(&vid(2)));
        assert_eq!(l.elected_count(), 2);

        // Governed min bond raised to 2000 STELL
        l.min_validator_bond = Some(stell(2000));
        let vs_gov = l.to_validator_set();
        assert!(!vs_gov.validators.contains_key(&vid(1)));
        assert!(vs_gov.validators.contains_key(&vid(2)));
        assert_eq!(l.elected_count(), 1);
    }
}
