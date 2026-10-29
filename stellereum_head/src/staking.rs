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
    parse_nano_env(std::env::var(SLASH_EJECT_WARN_GAP_ENV).ok(), DEFAULT_SLASH_EJECT_WARN_GAP_NANO)
}

/// Effective minimum-bond buffer in nano-STELL (`STELL_MIN_BOND_BUFFER`,
/// default [`DEFAULT_MIN_BOND_BUFFER_NANO`]). Unparseable/missing -> default.
pub fn min_bond_buffer_nano() -> u64 {
    parse_nano_env(std::env::var(MIN_BOND_BUFFER_ENV).ok(), DEFAULT_MIN_BOND_BUFFER_NANO)
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
    self_bond >= MIN_VALIDATOR_BOND
        && self_bond.saturating_sub(MIN_VALIDATOR_BOND) < gap
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
pub fn eject_warn_message_for(validator: &ValidatorId, self_bond: u64, burned: u64, gap: u64) -> Option<String> {
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

/// Maximum active validators (consensus set cap): 250.
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
pub const MIN_DELEGATION: u64 = 1 * 1_000_000_000;
/// Unbonding cooldown before funds can be withdrawn (~2 days at 3s blocks).
pub const UNBONDING_PERIOD_SECS: u64 = 2 * 24 * 3600;
/// Slash fraction for equivocation (double-sign), in basis points (5%).
pub const EQUIVOCATION_SLASH_BPS: u64 = 500;
/// Slash fraction for micro-committee equivocation (100% of bond).
pub const MICRO_COMMITTEE_SLASH_BPS: u64 = 10_000;
/// Slash fraction for prolonged downtime, in basis points (0.1%).
pub const DOWNTIME_SLASH_BPS: u64 = 10;
/// Consecutive missed heights before a downtime slash fires.
pub const DOWNTIME_MISS_THRESHOLD: u32 = 10;
/// Minimum heights between two downtime slashes for the same validator, so a
/// long outage costs a bounded amount rather than draining the whole bond.
pub const DOWNTIME_PENALTY_COOLDOWN: u64 = 100;
/// Default validator commission on delegated rewards (10%).
///
/// PRODUCT DECISION — COMMISSION IS IMMUTABLE AFTER BOND (audit I3, closed
/// explicitly): set once at `bond`, priced for newcomers by governance
/// (`SetDefaultCommissionBps`); neither `add_bond` nor any opcode changes it.
/// A validator can neither raise NOR lower commission, so delegators lock
/// into the genesis rate — transparent at `delegate` time (the rate is
/// ledger state, readable before delegating), and 100% commission is allowed
/// but pays delegators exactly 0 rather than stealing. No theft vector.
/// EXACT PRECONDITION FOR A `SetCommission` OPCODE: ship it WITH a
/// delegator-exit window (announce N heights before the new rate takes
/// effect, during which `unbond`/`undelegate` bypass any new-bonding delay
/// so captives can leave); without the window a raise is a rug. Until then,
/// immutability is the safe default — pinned by closure-suite test.
pub const DEFAULT_COMMISSION_BPS: u64 = 1_000;
const BPS_DENOMINATOR: u64 = 10_000;

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
            StakingError::ArithmeticOverflow => "stake amount overflows u64: refusing instead of saturating",
            StakingError::ZeroAddress => "the zero address cannot hold a delegation (self-bond key is reserved)",
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
}

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
/// Otherwise `None`.
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
    /// NOT folded into the commitment digest (same posture as the PQ set
    /// above): an empty set writes nothing and the genesis KAT is
    /// untouched. A conditional domain (E7-style) is the follow-up if
    /// light-client provability of the set is ever needed.
    #[serde(default)]
    pub equivocation_dedup: HashSet<[u8; 32]>,
    /// Registered post-quantum public keys and schemes per validator.
    #[serde(default)]
    pub validator_pq_keys: HashMap<ValidatorId, (crate::post_quantum::PqScheme, Vec<u8>)>,
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
    pub fn rotate_key(
        &mut self,
        old: ValidatorId,
        new: ValidatorId,
    ) -> Result<(), StakingError> {
        if old == new {
            return Err(StakingError::AlreadyValidator);
        }
        if self.validators.contains_key(&new) {
            return Err(StakingError::AlreadyValidator);
        }
        let record = self.validators.remove(&old).ok_or(StakingError::NotValidator)?;
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
        // Either fully exit, or remain a valid validator above the minimum.
        if remaining != 0 && remaining < MIN_VALIDATOR_BOND {
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
        let v = self
            .validators
            .get_mut(&validator)
            .ok_or(StakingError::NotValidator)?;
        v.delegated = v
            .delegated
            .checked_add(amount)
            .ok_or(StakingError::ArithmeticOverflow)?;
        let entry = self.delegations.entry((validator, delegator)).or_insert(0);
        *entry = (*entry)
            .checked_add(amount)
            .ok_or(StakingError::ArithmeticOverflow)?;
        self.warn_if_quorum_fragile("top-up/delegate");
        Ok(())
    }

    /// Begin undelegating `amount` from a validator (subject to cooldown).
    /// Argument order: (delegator, validator, amount, now) — delegator first.
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

    /// Move all matured unbonding entries into `withdrawable`, crediting the
    /// entry's OWNER (validator for self-bond, delegator for undelegation).
    pub fn process_unbonding(&mut self, now: u64) {
        let mut still_pending = Vec::new();
        for e in self.unbonding.drain(..) {
            if now >= e.release_at {
                let owner = e.owner.unwrap_or([0u8; 32]);
                let key = (e.validator, owner);
                let entry = self.withdrawable.entry(key).or_insert(0);
                *entry = entry.saturating_add(e.amount);
            } else {
                still_pending.push(e);
            }
        }
        self.unbonding = still_pending;
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
        self.validators.get(validator).map(|v| v.total()).unwrap_or(0)
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
    /// validators with a self-bond at or above the minimum are included.
    /// The set is sorted by total stake (descending, id tiebreak) and
    /// truncated to [`MAX_ACTIVE_VALIDATORS`] (250) — TON-style Elector cap.
    /// Full nodes are unaffected (unlimited).
    pub fn to_validator_set(&self) -> ValidatorSet {
        let mut ranked: Vec<(ValidatorId, u64)> = self
            .validators
            .iter()
            .filter(|(_, v)| v.self_bond >= MIN_VALIDATOR_BOND)
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

    /// Number of validators that would be elected (post-cap), for RPC/metrics.
    pub fn elected_count(&self) -> usize {
        self.validators
            .values()
            .filter(|v| v.self_bond >= MIN_VALIDATOR_BOND && v.total() > 0)
            .count()
            .min(MAX_ACTIVE_VALIDATORS)
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
    /// ROUNDING (audit L1, verified conservative): the per-delegator `cut`
    /// floors, so `slashed_total ≤ take` by `< n_delegators` nanos. Map and
    /// aggregate stay mutually consistent (both reduced by `slashed_total`);
    /// the unfloorable nanos simply REMAIN STAKED — the dust favors the
    /// slashed party, never the protocol. Pinned by closure-suite test.
    pub fn slash(&mut self, validator: ValidatorId, slash_bps: u64) -> Result<u64, StakingError> {
        let v = self
            .validators
            .get_mut(&validator)
            .ok_or(StakingError::NotValidator)?;
        let total = v.total();
        let burn = (total as u128 * slash_bps as u128 / BPS_DENOMINATOR as u128) as u64;
        if burn == 0 {
            return Ok(0);
        }
        // Consume self-bond first.
        let from_self = burn.min(v.self_bond);
        v.self_bond -= from_self;
        let mut remaining = burn - from_self;
        if remaining > 0 {
            // Slash delegators proportionally.
            let delegated = v.delegated;
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
                        if amount - cut == 0 {
                            self.delegations.remove(&key);
                        } else {
                            self.delegations.insert(key, amount - cut);
                        }
                        slashed_total += cut;
                    }
                }
                v.delegated -= slashed_total;
                remaining = remaining.saturating_sub(slashed_total);
            }
        }
        let actually_burned = burn - remaining;
        v.total_slashed = v.total_slashed.saturating_add(actually_burned);
        self.total_burned = self.total_burned.saturating_add(actually_burned);
        // Loud-by-design eject policy (урок валидатора C): a slash that drops
        // self_bond below MIN ejects the validator from the set at the next
        // boundary — never silent. A slash that leaves it within the WARN gap
        // above MIN warns "validator X будет выкинут через ~Y" so the operator
        // can top up. Fail-open, log-only: state is already updated above.
        let self_bond_after = v.self_bond;
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
    /// same 5% burn, but fail-closed verification (shape + both signatures
    /// + membership) and per-offense chain dedup, fed ONLY by block-carried
    /// evidence (`OpCode::SysCallReportEquivocation` scanned from the
    /// decided block in `apply_block_transition`, pool-debited at the call
    /// site like downtime). That satisfies BOTH preconditions below, which
    /// is why it — and not this function — is wired.
    /// EXACT PRECONDITION FOR WIRING (retained for the record): (1) equivocation evidence travels
    /// INSIDE the block as verifiable content (a block-format change —
    /// `Block` is bincode-frozen, so this needs a coordinated rollout), so
    /// every node slashes from identical evidence; AND (2) the live wiring
    /// debits `STAKING_POOL` by `burned` (this primitive mutates ledger
    /// fields only — like `slash`, the coins move at the caller, cf. the
    /// downtime path in `state_engine.rs`), or pool/ledger drift by `burned`.
    /// Until BOTH hold, wiring this would trade a free-double-sign for a
    /// chain split — safety beats the feature.
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
    pub fn get_pq_key(&self, validator: &ValidatorId) -> Option<(crate::post_quantum::PqScheme, Vec<u8>)> {
        if let Some((s, pk)) = self.validator_pq_keys.get(validator) {
            Some((*s, pk.clone()))
        } else if self.validators.contains_key(validator) {
            Some((crate::post_quantum::PqScheme::Ed25519, validator.to_vec()))
        } else {
            None
        }
    }

    /// Slash for post-quantum equivocation using `CompactPqEquivocationEvidence`.
    ///
    /// PRODUCT DECISION — UNWIRED IN PRODUCTION (same as `slash_equivocation`
    /// above, closed explicitly): zero production callers. The PQ path has no
    /// "non-PQ tradeoff" cover story — it is simply unwired until in-block
    /// evidence exists. EXACT PRECONDITION FOR WIRING: identical two-part
    /// gate — (1) block-carried, signature-verifiable evidence (both
    /// signatures already verify through `verify_pq_signature` here), AND (2)
    /// a `STAKING_POOL` debit of `burned` at the live call site (plus, for
    /// the micro-committee 100% arm, a decision on the stranded
    /// `delegator_rewards`/`withdrawable`/`unbonding` rows the eviction
    /// leaves behind — still claimable today, but the UX must be specified).
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

        // 3. Registered key resolution:
        let (scheme, pubkey) = if let Some((s, pk)) = self.validator_pq_keys.get(&evidence.voter) {
            (*s, pk.clone())
        } else {
            (crate::post_quantum::PqScheme::Ed25519, evidence.voter.to_vec())
        };

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
        let sig_a = if scheme == crate::post_quantum::PqScheme::Ed25519 && evidence.signature_a.len() != 64 {
            crate::consensus::ed25519_sig_bytes(&evidence.signature_a)
        } else {
            evidence.signature_a.as_slice()
        };
        let sig_b = if scheme == crate::post_quantum::PqScheme::Ed25519 && evidence.signature_b.len() != 64 {
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
            let cooled = (rec.last_downtime_penalty == 0
                || height >= rec.last_downtime_penalty)
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
            }
        }
        slashed
    }

    /// Distribute `reward` (minted nano-STELL) to `validator`. Split:
    ///   - commission goes to the validator on the delegated portion;
    ///   - the rest is split pro-rata between self-bond and delegators.
    ///
    /// ROUNDING (audit L1, verified conservative): both splits floor per
    /// recipient. The validator's own leg is computed as
    /// `reward − delegated_share + commission` — EXACT, no floor loss — so the
    /// only dust is the per-delegator `share` floors (`< n_delegators` nanos
    /// per distribution, single-digit nanos in practice, ~0.3 STELL/yr
    /// chain-wide at 5 blocks/s). The dust is NEVER attributable to anyone
    /// and stays locked in `rewards_pool` (no sweep path): rounding favors
    /// the protocol (dust lock), never the operator, never the delegator.
    /// Deliberately left un-swept: crediting the remainder to the proposer
    /// would make the proposer's payout depend on the delegator COUNT (a
    /// grindable input), while the lock is value-neutral and unexploitable.
    /// Pinned by `dust_favors_the_protocol_not_the_operator` (closure suite).
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
        let v = self
            .validators
            .get_mut(&validator)
            .ok_or(StakingError::NotValidator)?;
        let total = v.total();
        if total == 0 || reward == 0 {
            return Ok(());
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
        let delegated_share = (reward as u128 * v.delegated as u128 / total as u128) as u64;
        let commission = (delegated_share as u128 * v.commission_bps as u128
            / BPS_DENOMINATOR as u128) as u64;
        let validator_reward = reward - delegated_share + commission;
        v.pending_rewards = v.pending_rewards.saturating_add(validator_reward);

        // Remaining delegated reward split across delegators pro-rata.
        let delegator_pool = delegated_share - commission;
        if v.delegated > 0 && delegator_pool > 0 {
            let keys: Vec<(ValidatorId, [u8; 32])> = self
                .delegations
                .keys()
                .filter(|(vid, _)| *vid == validator)
                .copied()
                .collect();
            for key in keys {
                let amount = self.delegations.get(&key).copied().unwrap_or(0);
                let share = (delegator_pool as u128 * amount as u128 / v.delegated as u128) as u64;
                *self.delegator_rewards.entry(key).or_insert(0) =
                    self.delegator_rewards.get(&key).copied().unwrap_or(0).saturating_add(share);
            }
        }
        Ok(())
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
    /// E2 fix: like [`Self::claim_validator_rewards`], the claim consumes
    /// [`StakingLedger::rewards_pool`] backing. When nothing is claimable —
    /// or the pool cannot cover it — the entry is left intact and 0 is
    /// returned (callers revert on 0), so a shortfall can never reach
    /// principal.
    pub fn claim_delegator_rewards(
        &mut self,
        delegator: [u8; 32],
        validator: ValidatorId,
    ) -> u64 {
        let key = (validator, delegator);
        let amount = self.delegator_rewards.get(&key).copied().unwrap_or(0);
        if amount == 0 || amount > self.rewards_pool {
            return 0;
        }
        self.delegator_rewards.remove(&key);
        self.rewards_pool -= amount;
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
            unbonding: self.unbonding,
            withdrawable: self.withdrawable,
            total_burned: self.total_burned,
            rewards_pool: 0,
            rewards_minted: 0,
            locked_governance: HashMap::new(),
            pq_equivocation_dedup: HashSet::new(),
            equivocation_dedup: HashSet::new(),
            validator_pq_keys: HashMap::new(),
            // Exact: no vesting-tracked accounts can exist in a pre-gate
            // snapshot (the registry did not exist), so empty is not a guess.
            vesting_schedules: BTreeMap::new(),
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
            unbonding: self.unbonding,
            withdrawable: self.withdrawable,
            total_burned: self.total_burned,
            rewards_pool: self.rewards_pool,
            rewards_minted: self.rewards_minted,
            locked_governance: self.locked_governance,
            pq_equivocation_dedup: self.pq_equivocation_dedup,
            equivocation_dedup: HashSet::new(),
            validator_pq_keys: self.validator_pq_keys,
            vesting_schedules: BTreeMap::new(),
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
        assert_eq!(l.bond(vid(1), stell(999), DEFAULT_COMMISSION_BPS), Err(StakingError::BondBelowMinimum));
        // Bare MIN (no buffer): refused — one downtime slash from ejection.
        assert_eq!(l.bond(vid(1), stell(1000), DEFAULT_COMMISSION_BPS), Err(StakingError::BondBelowMinimum));
        // Just under the floor: refused, and the error names the requirement.
        assert_eq!(l.bond(vid(1), stell(1099), DEFAULT_COMMISSION_BPS), Err(StakingError::BondBelowMinimum));
        assert!(format!("{}", StakingError::BondBelowMinimum).contains(&required_bond_floor_nano().to_string()));
        // Commission is checked after the floor: bad commission on a good bond.
        assert_eq!(l.bond(vid(1), stell(1100), 10_001), Err(StakingError::BadCommission));
        l.bond(vid(1), stell(1100), DEFAULT_COMMISSION_BPS).unwrap();
        assert_eq!(l.total_stake(&vid(1)), stell(1100));
        // double registration rejected
        assert_eq!(l.bond(vid(1), stell(1100), DEFAULT_COMMISSION_BPS), Err(StakingError::AlreadyValidator));
    }

    #[test]
    fn unbond_requires_cooldown_then_withdraw() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(2000), DEFAULT_COMMISSION_BPS).unwrap();
        l.unbond(vid(1), stell(1000), 1_000).unwrap();
        // still below release time
        l.process_unbonding(1_000);
        assert_eq!(l.withdrawable_of(&vid(1)), 0);
        assert_eq!(l.withdraw(vid(1)), Err(StakingError::NothingToWithdraw));
        // after cooldown
        l.process_unbonding(1_000 + UNBONDING_PERIOD_SECS);
        assert_eq!(l.withdrawable_of(&vid(1)), stell(1000));
        assert_eq!(l.withdraw(vid(1)).unwrap(), stell(1000));
    }

    #[test]
    fn unbond_cannot_drop_below_minimum_without_full_exit() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(2000), DEFAULT_COMMISSION_BPS).unwrap();
        // leaving 500 (< min 1000) is rejected
        assert_eq!(l.unbond(vid(1), stell(1500), 0), Err(StakingError::BondBelowMinimum));
        // full exit is allowed
        assert!(l.unbond(vid(1), stell(2000), 0).is_ok());
    }

    #[test]
    fn delegation_and_undelegation() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(1100), DEFAULT_COMMISSION_BPS).unwrap();
        assert_eq!(l.delegate(del(1), vid(1), stell(0)), Err(StakingError::DelegationBelowMinimum));
        l.delegate(del(1), vid(1), stell(500)).unwrap();
        assert_eq!(l.total_stake(&vid(1)), stell(1600));
        l.undelegate(del(1), vid(1), stell(200), 0).unwrap();
        assert_eq!(l.total_stake(&vid(1)), stell(1400));
        assert_eq!(l.undelegate(del(1), vid(1), stell(999), 0), Err(StakingError::InsufficientDelegation));
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
        l.bond(offender, stell(2000), DEFAULT_COMMISSION_BPS).unwrap();
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
        l.bond(offender, stell(2000), DEFAULT_COMMISSION_BPS).unwrap();
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
        l.bond(offender, stell(2000), DEFAULT_COMMISSION_BPS).unwrap();
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
        assert_eq!(v.total_slashed, slashed_before, "slash history carries over");
        assert_eq!(l.total_stake(&vid(2)), total_before, "stake preserved exactly");
        assert_eq!(
            l.delegations.get(&(vid(2), del(1))).copied(),
            Some(stell(300)),
            "delegation follows the record"
        );
        assert!(l.delegations.get(&(vid(1), del(1))).is_none());
        assert!(
            l.unbonding.iter().any(|u| u.validator == vid(2) && u.amount == stell(200)),
            "pending unbonding follows the record"
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
        assert_eq!(l.delegations.get(&(vid(1), del(1))).copied(), Some(stell(1000)));
    }

    #[test]
    fn undelegated_funds_go_to_the_delegator_not_the_validator() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(2000), DEFAULT_COMMISSION_BPS).unwrap();
        l.delegate(del(1), vid(1), stell(1500)).unwrap();
        l.undelegate(del(1), vid(1), stell(1500), 0).unwrap();
        l.process_unbonding(UNBONDING_PERIOD_SECS + 1);

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
        l.process_unbonding(UNBONDING_PERIOD_SECS + 1);

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
        engine.update_account(AccountState::new(alice_addr, start)).await;

        let tx = crate::sharding::Transaction::sign_with_payload(
            &alice,
            alice_addr,
            0,
            10_000,
            0,
            1,
            1,
            vec![OpCode::SysCallStake { validator, amount: required_bond_floor_nano() }],
        );
        engine.apply_transaction(&tx, 0).await.expect("bond must be accepted");

        let alice_balance = engine.get_account(&alice_addr).await.unwrap().balance;
        let pool_balance = engine.get_account(&STAKING_POOL).await.map(|a| a.balance).unwrap_or(0);
        // Only the gas actually consumed is charged (GAS_STAKE_BOND), not the
        // declared gas_limit, so the exact debit is knowable.
        assert_eq!(
            alice_balance,
            start - required_bond_floor_nano() - crate::svm::GAS_STAKE_BOND,
            "bond + gas actually used must be debited"
        );
        assert_eq!(pool_balance, required_bond_floor_nano(), "bonded value must be in the pool");

        let vs = engine.staking_read().await.to_validator_set();
        assert_eq!(vs.power_of(&validator), required_bond_floor_nano(), "bond must buy voting power");
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
            vec![OpCode::SysCallStake { validator, amount: required_bond_floor_nano() }],
        );
        assert!(engine.apply_transaction(&tx, 0).await.is_err(), "must not bond what you lack");
        let vs = engine.staking_read().await.to_validator_set();
        assert!(!vs.validators.contains_key(&validator), "no phantom validator");
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
        engine.update_account(AccountState::new(dave_addr, 10_000 * 1_000_000_000)).await;

        // Bare MIN is affordable but below the MIN+buffer floor: refused.
        let tx = crate::sharding::Transaction::sign_with_payload(
            &dave,
            dave_addr,
            0,
            10_000,
            0,
            1,
            1,
            vec![OpCode::SysCallStake { validator, amount: MIN_VALIDATOR_BOND }],
        );
        assert!(engine.apply_transaction(&tx, 0).await.is_err(), "bare-MIN bond must be refused");
        let vs = engine.staking_read().await.to_validator_set();
        assert!(!vs.validators.contains_key(&validator), "no phantom validator");
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
        engine.update_account(AccountState::new(carol_addr, 10_000 * 1_000_000_000)).await;

        let tx = crate::sharding::Transaction::sign_with_payload(
            &carol,
            carol_addr,
            0,
            50_000,
            0,
            1,
            1,
            vec![
                OpCode::SysCallStake { validator, amount: required_bond_floor_nano() },
                // More than remains after the bond -> reverts the whole payload.
                OpCode::Transfer { recipient: [0x01u8; 32], amount: 9_500_000_000_000 },
            ],
        );
        assert!(engine.apply_transaction(&tx, 0).await.is_err());
        let vs = engine.staking_read().await.to_validator_set();
        assert!(!vs.validators.contains_key(&validator), "a reverted bond must not create a validator");
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
            l.validators[&honest].self_bond, stell(1100),
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
        assert_eq!(l.validators[&offline].missed, 0, "signing again clears the streak");
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
        assert_eq!(l.rewards_pool, 85_714_285_715, "validator claim consumes pool");
        let d_amt = l.claim_delegator_rewards(del(1), vid(1));
        assert_eq!(d_amt, 85_714_285_715);
        assert_eq!(l.rewards_pool, 0, "pool fully consumed by claims");
        assert_eq!(l.rewards_minted, stell(200), "cumulative mint never decreases");
        // Nothing left: both paths are now empty, fail-closed.
        assert_eq!(l.claim_validator_rewards(vid(1)).unwrap(), 0);
        assert_eq!(l.claim_delegator_rewards(del(1), vid(1)), 0);
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
            l.validators[&vid(1)].pending_rewards, 100,
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
            l.validators[&vid(1)].pending_rewards, owed,
            "refused claim leaves the entry intact"
        );
        assert_eq!(
            l.validators[&vid(1)].self_bond,
            stell(1100),
            "principal untouched by the shortfall"
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
        l.unbond(vid(1), stell(1000), 0).unwrap();
        // Over-release saturates to empty, never underflows.
        l.unlock_governance(vid(1), u64::MAX);
        assert!(l.locked_governance.is_empty());
    }

    /// E7: a rotated validator carries its governance lock to the new key, so
    /// the stake cannot exit from under the open vote it inherited.
    #[test]
    fn governance_lock_follows_key_rotation() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(2000), DEFAULT_COMMISSION_BPS).unwrap();
        l.lock_governance(vid(1), stell(2000));
        l.rotate_key(vid(1), vid(2)).unwrap();
        assert_eq!(l.locked_governance_of(&vid(1)), 0);
        assert_eq!(l.locked_governance_of(&vid(2)), stell(2000));
        assert_eq!(
            l.unbond(vid(2), stell(2000), 0),
            Err(StakingError::LockedInGovernanceVote)
        );
        l.unlock_governance(vid(2), stell(2000));
        l.unbond(vid(2), stell(2000), 0).unwrap();
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
        assert_eq!(l.total_stake(&vid), stell(1900), "Stake must not compound burn");
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
        assert_eq!(burned3, 0, "Deduplication key BLAKE3(voter || height || round || kind) prevents compounding");
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
        l.register_pq_key(vid, crate::post_quantum::PqScheme::Falcon512, falcon_pk.clone()).unwrap();

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
        let msg = eject_warn_message_for(&v, stell(1045), stell(55), gap).expect("must warn in gap");
        assert!(msg.contains("будет выкинут через"), "message must say: {msg}");
        assert!(msg.contains("SLASH-EJECT-WARN"), "message must say: {msg}");
        // Below MIN: eject WARN, not approach WARN.
        assert!(eject_warn_message_for(&v, stell(999), stell(1), gap).is_none());
        let msg = eject_message_for(&v, stell(999), stell(1)).expect("must report eject");
        assert!(msg.contains("EJECTED"), "message must say: {msg}");

        // Live: slash landing inside the default 100 STELL gap WARNs loudly.
        let logs = capture_warns(|| {
            let mut l = StakingLedger::new();
            l.bond(vid(11), stell(1100), DEFAULT_COMMISSION_BPS).unwrap();
            // 5% of 1100 = 55 -> 1045, i.e. 45 STELL above MIN: inside the gap.
            let burned = l.slash(vid(11), 500).unwrap();
            assert_eq!(burned, stell(55));
            assert_eq!(l.validators[&vid(11)].self_bond, stell(1045));
        });
        assert!(logs.contains("будет выкинут через"), "slash must WARN in gap, got: {logs}");
        assert!(logs.contains("SLASH-EJECT-WARN"), "slash must WARN in gap, got: {logs}");

        // Live: validator C case, modern shape — floor bond (1100) + a slash
        // that actually ejects + WARNs. (Bare-MIN bonds can no longer be
        // created: `bond` refuses them, see bond_enforces_minimum_plus_buffer.)
        let logs = capture_warns(|| {
            let mut l = StakingLedger::new();
            l.bond(vid(12), stell(1100), DEFAULT_COMMISSION_BPS).unwrap();
            // 10% of 1100 = 110 -> 990 < MIN: ejected.
            let burned = l.slash(vid(12), 1_000).unwrap();
            assert_eq!(burned, stell(110));
            assert!(l.validators[&vid(12)].self_bond < MIN_VALIDATOR_BOND);
            assert!(!l.to_validator_set().validators.contains_key(&vid(12)));
        });
        assert!(logs.contains("EJECTED"), "eject must WARN loudly, got: {logs}");
        assert!(logs.contains("SLASH-EJECT"), "eject must WARN loudly, got: {logs}");
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
        assert_eq!(parse_nano_env(Some("garbage".to_string()), stell(100)), stell(100));
        assert_eq!(DEFAULT_SLASH_EJECT_WARN_GAP_NANO, stell(100));
        assert_eq!(DEFAULT_MIN_BOND_BUFFER_NANO, stell(100));

        // Live: bare-MIN bond is REFUSED (fail-closed floor, not a WARN).
        let logs = capture_warns(|| {
            let mut l = StakingLedger::new();
            assert_eq!(l.bond(vid(21), stell(1000), DEFAULT_COMMISSION_BPS), Err(StakingError::BondBelowMinimum));
        });
        assert!(!logs.contains("MIN-BOND-BUFFER"), "refused bond needs no cushion WARN, got: {logs}");

        // Live: cushioned bond is silent on the buffer channel.
        let logs = capture_warns(|| {
            let mut l = StakingLedger::new();
            assert!(l.bond(vid(22), stell(1200), DEFAULT_COMMISSION_BPS).is_ok());
        });
        assert!(!logs.contains("MIN-BOND-BUFFER"), "cushioned bond must not buffer-WARN, got: {logs}");

        // Live: add_bond below MIN+buffer WARNs, above it does not; never refused.
        let logs = capture_warns(|| {
            let mut l = StakingLedger::new();
            l.bond(vid(23), stell(1200), DEFAULT_COMMISSION_BPS).unwrap();
            // Slash down into the buffer-less zone, then top up insufficiently.
            l.slash(vid(23), 500).unwrap(); // 5% of 1200 = 60 -> 1140 (has buffer)
            assert!(l.add_bond(vid(23), stell(10)).is_ok());
        });
        assert!(!logs.contains("MIN-BOND-BUFFER") || logs.contains("SLASH-EJECT-WARN"),
            "1140+10=1150 keeps the cushion-or-slash WARNs only, got: {logs}");

        let logs = capture_warns(|| {
            let mut l = StakingLedger::new();
            l.bond(vid(24), stell(1100), DEFAULT_COMMISSION_BPS).unwrap();
            l.slash(vid(24), 500).unwrap(); // 5% of 1100 = 55 -> 1045 (no cushion)
            assert!(l.add_bond(vid(24), stell(50)).is_ok()); // 1095 < 1100 -> WARN
            assert_eq!(l.validators[&vid(24)].self_bond, stell(1095));
        });
        assert!(logs.contains("MIN-BOND-BUFFER"), "under-cushion top-up must WARN, got: {logs}");
    }
}
