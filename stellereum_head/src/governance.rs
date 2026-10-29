//! On-chain Governance: stake-weighted proposals and voting.
//!
//! Token holders vote on network parameters with voting power equal to their
//! bonded stake (validators) plus delegators' bonded stake — the same ledger
//! that secures consensus, so governance power tracks economic skin-in-the-game.
//!
//! Lifecycle:
//!   1. `propose`  — a staker submits a `Proposal` with a concrete `GovAction`.
//!   2. `vote`     — stakers vote Yes/No/Abstain; one vote per voter per proposal,
//!                   weight = current staked balance. Votes are locked to the
//!                   proposal id and cannot be changed (no vote flipping).
//!   3. `finalize` — after `voting_end`, if turnout >= quorum and yes > no, the
//!                   proposal is `Passed`, else `Rejected`.
//!   4. `execute`  — a passed proposal's action is applied exactly once.
//!
//! Safety / determinism:
//!  - All arithmetic is integer (u128 for weight accumulation).
//!  - Voting power is snapshotted at vote time and the ledger is the single
//!    source of truth, so every node computes the same tally.
//!  - A proposal can be executed at most once; execution is idempotent-guarded.

use crate::consensus::ValidatorId;
use crate::staking::StakingLedger;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Quorum: minimum share of total stake that must participate (2/3), in bps.
/// 6,666 bps = 66.66%, so an exact 2/3 turnout passes.
pub const GOVERNANCE_QUORUM_BPS: u64 = 6_666;
/// Quorum floor (E5): `SetGovernanceQuorumBps` values below 1/3 (3333 bps)
/// are rejected at BOTH propose-time validation and execute-time. Without a
/// floor one proposal can ratchet quorum to 0.01% (irreversible capture).
pub const GOVERNANCE_QUORUM_FLOOR_BPS: u64 = 3_333;
/// Passing threshold: yes must exceed no (strict majority of cast votes).
pub const GOVERNANCE_VOTING_PERIOD_SECS: u64 = 3 * 24 * 3600; // 3 days
/// Minimum stake required to submit a proposal (10,000 STELL), in bps-free nano.
pub const PROPOSAL_MIN_STAKE_NANO: u64 = 10_000 * 1_000_000_000;

const BPS: u128 = 10_000;
/// Basis points as u64 for parameter bounds checks.
const BPS_U64: u64 = 10_000;
/// Upper bound for `SetMinValidatorBond`: 1000x the protocol floor (1M STELL).
/// Lets governance tighten Sybil resistance hard without ever pricing out the
/// whole validator set at once (which would halt the chain for lack of quorum).
pub const MAX_VALIDATOR_BOND: u64 = 1_000_000 * 1_000_000_000;
/// Upper bound for `SetBlockReward`: 10M STELL per block. Generous against the
/// 0.317 STELL default, but a passed fat-finger (let alone u64::MAX) must not
/// be able to hyperinflate past the hard cap on the next block.
pub const MAX_BLOCK_REWARD_NANO: u64 = 10_000_000 * 1_000_000_000;
/// Upper bound for `SetMinGasLimit`: 10x the base transfer fee (audit
/// follow-up). Lets governance price out spam hard without ever bricking the
/// faucet/test flows that declare exactly the base fee... which is why the
/// ADMISSION floor stays max(env, governed): raising governed above what the
/// owner set in env only affects admission if the operator also raises env.
/// (Full migration to a purely governed floor is a separate step.)
pub const MAX_MIN_GAS_LIMIT: u64 = 10 * crate::svm::GAS_BASIC_TRANSFER;
/// Maximum proposal title size in bytes (E4).
///
/// Titles are committed state on every node (hashed into the governance
/// digest). Without a cap, one 10k-STELL proposal can bloat the state with
/// megabytes of junk that every node stores and digests forever. 256 bytes
/// is ample for a human-readable title; anything larger is grief, not
/// governance. Enforced at propose time AND at execution (smuggled
/// proposals fail closed and stay `Passed`).
pub const MAX_PROPOSAL_TITLE_BYTES: usize = 256;
/// Maximum `GovAction::Signal` text size in bytes (E4, same rationale as
/// the title cap: the text is committed state). 1024 bytes fits a real
/// statement; larger payloads belong off-chain (e.g. IPFS hash in the text).
pub const MAX_SIGNAL_BYTES: usize = 1_024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovError {
    NotStaker,
    InsufficientStake,
    UnknownProposal,
    VotingClosed,
    /// The voting window has not ended yet (distinct from "closed").
    VotingStillOpen,
    AlreadyVoted,
    NotPassed,
    AlreadyExecuted,
    InvalidAction,
}

impl std::fmt::Display for GovError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            GovError::NotStaker => "caller has no staked balance",
            GovError::InsufficientStake => "insufficient stake to propose",
            GovError::UnknownProposal => "proposal not found",
            GovError::VotingClosed => "voting period is closed",
            GovError::VotingStillOpen => "voting period has not ended yet",
            GovError::AlreadyVoted => "already voted on this proposal",
            GovError::NotPassed => "proposal has not passed",
            GovError::AlreadyExecuted => "proposal already executed",
            // Names every propose/execute bound (E5 quorum floor 3333 bps,
            // E4 title/signal caps, E6 non-zero publisher) so a rejected
            // action explains the rule at both propose-time and execute-time.
            GovError::InvalidAction => {
                "invalid governance action (bounds: governance quorum 3333..10000 bps; title <= 256B; signal <= 1024B; publisher key non-zero)"
            }
        };
        write!(f, "{s}")
    }
}

/// A concrete, executable parameter change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovAction {
    /// Change the minimum validator self-bond (nano-STELL).
    SetMinValidatorBond(u64),
    /// Change the equivocation slash fraction (bps).
    SetEquivocationSlashBps(u64),
    /// Change the default validator commission (bps).
    SetDefaultCommissionBps(u64),
    /// Change the block reward (nano-STELL).
    SetBlockReward(u64),
    /// Change the PMM redemption buffer (bps).
    SetPmmRedemptionBufferBps(u64),
    /// Change the governance quorum (bps).
    SetGovernanceQuorumBps(u64),
    /// A no-op signalling proposal (e.g. community sentiment). Carries the text so a
    /// signal is actually part of the committed state rather than a nameless flag.
    Signal(String),
    // APPENDED, never inserted above: `GovAction` is bincode-serialized inside
    // every committed `Proposal`, and `commitment.rs` maps each variant to an
    // explicit tag in `governance_digest`. Renumbering any existing action would
    // change the tag of proposals already committed to the root.
    /// Authorise an oracle publisher key in the committed oracle registry.
    ///
    /// The publisher set was already committed (`OracleState.publishers`) but
    /// had no on-chain writer: tests injected keys by hand. A `GovAction` is
    /// that writer, so a feed's authority is itself a ratified, committed
    /// decision that every node derives from the same block.
    RegisterOraclePublisher([u8; 32]),
    /// Revoke a previously registered oracle publisher key.
    UnregisterOraclePublisher([u8; 32]),
    /// Clear the latched oracle circuit breaker.
    ///
    /// A peg/deviation violation latches the breaker automatically; only a
    /// passed vote may clear it, so the alarm cannot be silenced off-chain.
    ResetOracleBreaker,
    // APPENDED, never inserted above (same discriminant rule as the oracle
    // actions above).
    /// Raise/lower the admission base-fee floor (nano-STELL). Bounded by
    /// `MAX_MIN_GAS_LIMIT`; the effective floor is max(env, governed).
    SetMinGasLimit(u64),
}

impl GovAction {
    /// Reject obviously invalid parameter values (defense in depth).
    pub fn validate(&self) -> Result<(), GovError> {
        match self {
            GovAction::SetEquivocationSlashBps(b) | GovAction::SetDefaultCommissionBps(b) => {
                if *b > 10_000 {
                    return Err(GovError::InvalidAction);
                }
            }
            GovAction::SetPmmRedemptionBufferBps(b) => {
                if *b > 10_000 {
                    return Err(GovError::InvalidAction);
                }
            }
            GovAction::SetGovernanceQuorumBps(b) => {
                // E5 floor: quorum below 1/3 (3333 bps) would let one proposal
                // irreversibly capture governance (0.01% quorum). Reject
                // below the 3333 bps floor at propose time (mirrored at
                // execute time). Upper bound 10000 bps unchanged.
                if *b < GOVERNANCE_QUORUM_FLOOR_BPS || *b > 10_000 {
                    return Err(GovError::InvalidAction);
                }
            }
            GovAction::SetMinGasLimit(v) => {
                if *v == 0 || *v > MAX_MIN_GAS_LIMIT {
                    return Err(GovError::InvalidAction);
                }
            }
            GovAction::RegisterOraclePublisher(pk) | GovAction::UnregisterOraclePublisher(pk) => {
                // The all-zero key is not a key: reject it up front rather than
                // committing a registry entry that can never produce a feed.
                if *pk == [0u8; 32] {
                    return Err(GovError::InvalidAction);
                }
            }
            GovAction::Signal(text) => {
                // E4: the text is committed state; cap it (mirrored at
                // execute time so a smuggled proposal fails closed).
                if text.len() > MAX_SIGNAL_BYTES {
                    return Err(GovError::InvalidAction);
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Whether this action only has an effect on the committed oracle domain.
    ///
    /// `Governance::execute` cannot reach the oracle (it is a different
    /// subsystem), so an oracle action must be executed through
    /// `execute_with_oracle`. This predicate lets a caller (and the tests) tell
    /// the two apart before execution.
    pub fn is_oracle_action(&self) -> bool {
        matches!(
            self,
            GovAction::RegisterOraclePublisher(_)
                | GovAction::UnregisterOraclePublisher(_)
                | GovAction::ResetOracleBreaker
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteChoice {
    Yes,
    No,
    Abstain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalStatus {
    Open,
    Passed,
    Rejected,
    Executed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal {
    pub id: u64,
    pub proposer: ValidatorId,
    pub title: String,
    pub action: GovAction,
    pub created_at: u64,
    pub voting_end: u64,
    pub yes: u128,
    pub no: u128,
    pub abstain: u128,
    pub voters: HashMap<[u8; 32], VoteChoice>,
    pub status: ProposalStatus,
    /// E7: the quorum base, frozen at propose time.
    ///
    /// `finalize` used to read the LIVE total voting power, so a yes-voter
    /// who undelegated before finalization shrank the denominator while the
    /// recorded weight persisted — flipping Rejected to Passed with no new
    /// vote. The base is now fixed when the proposal opens and every later
    /// finalize measures the same recorded turnout against the same base.
    pub electorate: u128,
    /// E7: per-voter locked weight (voter -> weight recorded at vote time).
    ///
    /// The mirror of the staking-side lock: `vote` inserts here AND calls
    /// `StakingLedger::lock_governance` with the same weight (saturated to
    /// `u64`); `finalize` unlocks every entry on the terminal transition.
    /// Kept (not drained) after finalization as the audit trail of whose
    /// stake backed the tally, and folded into the governance digest.
    pub weights: HashMap<[u8; 32], u128>,
}

impl Proposal {
    /// Total weight cast (yes + no + abstain).
    pub fn turnout(&self) -> u128 {
        self.yes + self.no + self.abstain
    }
}

/// The governance engine. Holds proposals and the parameter it has applied.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Governance {
    pub proposals: HashMap<u64, Proposal>,
    pub next_id: u64,
    pub quorum_bps: u64,
    /// Applied parameter values (last executed action wins).
    pub applied: AppliedParams,
}

/// Snapshot of governance-controlled parameters.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedParams {
    pub min_validator_bond: Option<u64>,
    pub equivocation_slash_bps: Option<u64>,
    pub default_commission_bps: Option<u64>,
    pub block_reward: Option<u64>,
    pub pmm_redemption_buffer_bps: Option<u64>,
    pub min_gas_limit: Option<u64>,
    pub signal: Option<String>,
}

impl Governance {
    pub fn new() -> Self {
        Self {
            proposals: HashMap::new(),
            next_id: 1,
            quorum_bps: GOVERNANCE_QUORUM_BPS,
            applied: AppliedParams::default(),
        }
    }

    /// Submit a proposal. Requires the proposer to hold >= PROPOSAL_MIN_STAKE.
    pub fn propose(
        &mut self,
        ledger: &StakingLedger,
        proposer: ValidatorId,
        title: String,
        action: GovAction,
        now: u64,
    ) -> Result<u64, GovError> {
        action.validate()?;
        // E4: titles are committed (digested) state: cap the bytes up front.
        // (The execute-time backstop in `execute_inner` covers proposals that
        // bypassed this check.)
        if title.len() > MAX_PROPOSAL_TITLE_BYTES {
            return Err(GovError::InvalidAction);
        }
        let stake = ledger.total_stake(&proposer);
        if stake == 0 {
            return Err(GovError::NotStaker);
        }
        if stake < PROPOSAL_MIN_STAKE_NANO {
            return Err(GovError::InsufficientStake);
        }
        let id = self.next_id;
        self.next_id += 1;
        // E7: freeze the quorum base now. Every finalize of this proposal
        // measures turnout against THIS electorate, so later exits entries
        // cannot move the goalposts.
        let electorate = Self::total_voting_power(ledger);
        // Hygiene (audit G1): an empty electorate must never open a vote.
        // Unreachable through this path today (the stake gate above implies a
        // non-zero electorate), but a zero base would make `quorum_needed`
        // truncate to 0 — fail closed here rather than trust every future
        // caller to keep the invariant.
        if electorate == 0 {
            return Err(GovError::InvalidAction);
        }
        self.proposals.insert(
            id,
            Proposal {
                id,
                proposer,
                title,
                action,
                created_at: now,
                voting_end: now + GOVERNANCE_VOTING_PERIOD_SECS,
                yes: 0,
                no: 0,
                abstain: 0,
                voters: HashMap::new(),
                status: ProposalStatus::Open,
                electorate,
                weights: HashMap::new(),
            },
        );
        Ok(id)
    }

    /// Cast a vote weighted by the voter's current staked balance.
    ///
    /// E7: the recorded weight is ALSO locked in the staking ledger
    /// (`StakingLedger::lock_governance`), so the backing stake cannot
    /// unbond/undelegate until `finalize` releases it. Takes the ledger by
    /// `&mut` for exactly that lock; the weight arithmetic itself is
    /// unchanged (self-bond + delegated-out, counted once).
    pub fn vote(
        &mut self,
        ledger: &mut StakingLedger,
        voter: [u8; 32],
        proposal_id: u64,
        choice: VoteChoice,
        now: u64,
    ) -> Result<u128, GovError> {
        let p = self
            .proposals
            .get_mut(&proposal_id)
            .ok_or(GovError::UnknownProposal)?;
        if p.status != ProposalStatus::Open {
            return Err(GovError::VotingClosed);
        }
        if now >= p.voting_end {
            return Err(GovError::VotingClosed);
        }
        if p.voters.contains_key(&voter) {
            return Err(GovError::AlreadyVoted);
        }
        // Voting weight = the stake THIS voter actually owns:
        //   - its own self-bond (if it is a validator), plus
        //   - any stake it has delegated OUT to validators.
        // SECURITY: we must NOT use `total_stake` (which includes delegations
        // made BY OTHERS to this validator) and then also add the delegator
        // loop — that double-counts stake and lets a self-delegating validator
        // (or a delegator of another validator) inflate its vote.
        let self_bond = ledger
            .validators
            .get(&voter)
            .map(|v| v.self_bond as u128)
            .unwrap_or(0);
        let delegated_out: u128 = ledger
            .delegations
            .iter()
            .filter(|((_, d), _)| *d == voter)
            .map(|(_, amount)| *amount as u128)
            .sum();
        let weight = self_bond + delegated_out;
        if weight == 0 {
            return Err(GovError::NotStaker);
        }
        p.voters.insert(voter, choice);
        p.weights.insert(voter, weight);
        match choice {
            VoteChoice::Yes => p.yes = p.yes.saturating_add(weight),
            VoteChoice::No => p.no = p.no.saturating_add(weight),
            VoteChoice::Abstain => p.abstain = p.abstain.saturating_add(weight),
        }
        // E7: lock the backing stake (saturating u128 -> u64; the same
        // saturated value is released at finalize, so the lock always clears
        // exactly). `lock_governance` cannot fail, so the tally above and
        // the lock below cannot disagree.
        ledger.lock_governance(voter, u64::try_from(weight).unwrap_or(u64::MAX));
        Ok(weight)
    }

    /// Finalize a proposal after voting ends. Turnout must meet the quorum
    /// and yes must strictly exceed no.
    ///
    /// E7: the quorum is measured against the FROZEN `electorate` recorded
    /// at propose time — never the live total — and every voter's staking
    /// lock is released on the terminal (Passed/Rejected) transition, so an
    /// exit after finalization always succeeds and an exit before it always
    /// fails. Takes the ledger by `&mut` for exactly that release.
    ///
    /// TINY-ELECTORATE NOTE (audit G1): `quorum_needed = electorate * Q /
    /// 10000` truncates down (an electorate under ~2 units needs 0), but the
    /// pass still requires `yes > no`, so empty/zero-turnout can NEVER pass:
    /// a pass needs at least one unit of yes-weight, i.e. turnout ≥ 1. The
    /// 10k-STELL proposal minimum keeps real electorates far from the
    /// rounding zone, and `propose` refuses an empty electorate outright — no
    /// stronger floor is needed (flooring `quorum_needed` at 1 would be a
    /// no-op given the `yes > no` gate).
    pub fn finalize(
        &mut self,
        ledger: &mut StakingLedger,
        proposal_id: u64,
        now: u64,
    ) -> Result<ProposalStatus, GovError> {
        // Read the gating fields first so the terminal transition below is
        // the single writer (the borrow ends before any unlock call).
        let (voting_end, status) = {
            let p = self
                .proposals
                .get(&proposal_id)
                .ok_or(GovError::UnknownProposal)?;
            (p.voting_end, p.status)
        };
        if status != ProposalStatus::Open {
            return Ok(status);
        }
        if now < voting_end {
            return Err(GovError::VotingStillOpen); // still in the voting window
        }
        let p = self
            .proposals
            .get_mut(&proposal_id)
            .ok_or(GovError::UnknownProposal)?;
        let quorum_needed = p.electorate * self.quorum_bps as u128 / BPS;
        let passed = p.turnout() >= quorum_needed && p.yes > p.no;
        p.status = if passed {
            ProposalStatus::Passed
        } else {
            ProposalStatus::Rejected
        };
        // E7: release every lock exactly once. This is the only transition
        // out of `Open` (re-finalize early-returns above), so no voter can
        // be unlocked twice and no lock can survive its proposal.
        let locked: Vec<([u8; 32], u128)> =
            p.weights.iter().map(|(voter, w)| (*voter, *w)).collect();
        for (voter, weight) in locked {
            ledger.unlock_governance(voter, u64::try_from(weight).unwrap_or(u64::MAX));
        }
        Ok(p.status)
    }

    /// Execute a passed proposal's action exactly once; any account may execute
    /// a passed proposal (no proposer-only gate, so a lost/rotated proposer key
    /// cannot brick execution).
    ///
    /// NOTE (E5): no timelock by deferred design decision — execution is
    /// allowed as soon as the proposal has passed (finalized).
    ///
    /// Oracle actions cannot be reached from here: the oracle is a separate
    /// committed domain. Passing one fails closed with `InvalidAction` and
    /// leaves the proposal `Passed` (not `Executed`), so it can still be applied
    /// correctly through [`Governance::execute_with_oracle`] - silently marking
    /// it executed while changing nothing in the oracle would be a lie told to
    /// every node that trusts the root.
    pub fn execute(
        &mut self,
        executor: [u8; 32],
        proposal_id: u64,
    ) -> Result<&AppliedParams, GovError> {
        self.execute_inner(executor, proposal_id, None)
    }

    /// Execute a passed proposal whose action ALSO moves committed oracle state
    /// (publisher registration/revocation, breaker reset).
    ///
    /// Both domains are written in this single call, so the action is
    /// all-or-nothing: either the proposal is `Executed` and the oracle moved,
    /// or neither. That is what makes it deterministic - every node applying the
    /// same passed proposal against the same starting oracle lands on the same
    /// subsequent state root, and no node can apply the governance half without
    /// the oracle half.
    pub fn execute_with_oracle(
        &mut self,
        executor: [u8; 32],
        proposal_id: u64,
        oracle: &mut crate::oracle::OracleState,
    ) -> Result<&AppliedParams, GovError> {
        self.execute_inner(executor, proposal_id, Some(oracle))
    }

    fn execute_inner(
        &mut self,
        _executor: [u8; 32],
        proposal_id: u64,
        mut oracle: Option<&mut crate::oracle::OracleState>,
    ) -> Result<&AppliedParams, GovError> {
        let p = self
            .proposals
            .get_mut(&proposal_id)
            .ok_or(GovError::UnknownProposal)?;
        // E5: anyone-can-execute — no `p.proposer == executor` (`NotProposer`)
        // gate, so a lost/rotated proposer key cannot brick a passed proposal.
        // NOTE: no timelock by deferred design decision.
        match p.status {
            ProposalStatus::Passed => {}
            ProposalStatus::Executed => return Err(GovError::AlreadyExecuted),
            _ => return Err(GovError::NotPassed),
        }
        // Clone the action so the `Proposal` borrow ends before any domain is
        // written (the oracle is a separate parameter; `self.applied` is a
        // disjoint field of `self`).
        //
        // EXECUTE-TIME BACKSTOPS (mirror the propose-time rules): a proposal
        // that bypassed `propose`/`validate` (deserialized history, direct
        // state write) must fail closed here and stay `Passed`, never commit
        // junk. Each arm below re-checks exactly what propose-time enforces.
        if p.title.len() > MAX_PROPOSAL_TITLE_BYTES {
            return Err(GovError::InvalidAction);
        }
        let action = p.action.clone();
        // PARAMETER BOUNDS (audit F-K): every value below is consensus state
        // once executed, and voters do not validate values when voting - so an
        // unchecked action turns one passed proposal (or one fat-fingered one)
        // into a bricked chain: quorum 0 lets everything pass, quorum >100%
        // deadlocks governance, u64::MAX block reward hyperinflates past the
        // hard cap on the very next block, u64::MAX min-bond ejects every
        // validator, >100% commission/slash steals or burns all stake. Bounds
        // are checked here, at execution, on every node identically; a passed
        // proposal that fails them stays `Passed` and fails closed on every
        // retry (same shape as the oracle-action guard above).
        match action {
            GovAction::SetMinValidatorBond(v) => {
                if v < crate::staking::MIN_VALIDATOR_BOND || v > MAX_VALIDATOR_BOND {
                    return Err(GovError::InvalidAction);
                }
                self.applied.min_validator_bond = Some(v)
            }
            GovAction::SetEquivocationSlashBps(v) => {
                if v > BPS_U64 {
                    return Err(GovError::InvalidAction);
                }
                self.applied.equivocation_slash_bps = Some(v)
            }
            GovAction::SetDefaultCommissionBps(v) => {
                if v > BPS_U64 {
                    return Err(GovError::InvalidAction);
                }
                self.applied.default_commission_bps = Some(v)
            }
            GovAction::SetBlockReward(v) => {
                if v > MAX_BLOCK_REWARD_NANO {
                    return Err(GovError::InvalidAction);
                }
                self.applied.block_reward = Some(v)
            }
            GovAction::SetPmmRedemptionBufferBps(v) => {
                if v > BPS_U64 {
                    return Err(GovError::InvalidAction);
                }
                self.applied.pmm_redemption_buffer_bps = Some(v)
            }
            GovAction::SetMinGasLimit(v) => {
                if v == 0 || v > MAX_MIN_GAS_LIMIT {
                    return Err(GovError::InvalidAction);
                }
                self.applied.min_gas_limit = Some(v)
            }
            GovAction::SetGovernanceQuorumBps(v) => {
                // E5 floor (mirrors propose-time `validate`): below 3333 bps
                // would capture governance; ceiling 10000 bps unchanged.
                if v < GOVERNANCE_QUORUM_FLOOR_BPS || v > BPS_U64 {
                    return Err(GovError::InvalidAction);
                }
                self.quorum_bps = v
            }
            GovAction::Signal(text) => {
                // E4 backstop (mirrors `validate`): smuggled oversize text
                // fails closed instead of bloating committed state.
                if text.len() > MAX_SIGNAL_BYTES {
                    return Err(GovError::InvalidAction);
                }
                self.applied.signal = Some(text)
            }
            GovAction::RegisterOraclePublisher(pk) => {
                // E6 backstop (mirrors `validate`): the all-zero key is not a
                // publisher. Without this, a proposal smuggled past
                // propose-time validation would commit a registry entry that
                // can never produce a feed.
                if pk == [0u8; 32] {
                    return Err(GovError::InvalidAction);
                }
                oracle
                    .as_deref_mut()
                    .ok_or(GovError::InvalidAction)?
                    .register_publisher(pk);
            }
            GovAction::UnregisterOraclePublisher(pk) => {
                oracle
                    .as_deref_mut()
                    .ok_or(GovError::InvalidAction)?
                    .unregister_publisher(pk);
            }
            GovAction::ResetOracleBreaker => {
                oracle.as_deref_mut().ok_or(GovError::InvalidAction)?.reset_breaker();
            }
        }
        // Only reached once every domain (governance AND, for an oracle action,
        // the oracle) has been written, so `Executed` never over-promises.
        self.proposals
            .get_mut(&proposal_id)
            .expect("proposal existence checked above")
            .status = ProposalStatus::Executed;
        Ok(&self.applied)
    }

    pub fn get(&self, id: u64) -> Option<&Proposal> {
        self.proposals.get(&id)
    }

    /// Total voting power across the ledger: every validator's self-bond plus
    /// every delegation (stake delegated out). Each staked nano is counted
    /// exactly once, matching the per-voter weights in `vote`, so the quorum
    /// numerator and denominator share the same base.
    pub fn total_voting_power(ledger: &StakingLedger) -> u128 {
        let self_bonds: u128 = ledger
            .validators
            .values()
            .map(|v| v.self_bond as u128)
            .sum();
        let delegated: u128 = ledger.delegations.values().map(|a| *a as u128).sum();
        self_bonds + delegated
    }

    /// Number of proposals in a given status (for dashboards/tests).
    pub fn count_status(&self, status: ProposalStatus) -> usize {
        self.proposals.values().filter(|p| p.status == status).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::staking::{StakingLedger, DEFAULT_COMMISSION_BPS};

    fn stell(n: u64) -> u64 {
        n * 1_000_000_000
    }

    fn vid(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn del(n: u8) -> [u8; 32] {
        [0xD0 + n; 32]
    }

    /// Build a ledger with `n` validators each bonded `bond` STELL.
    fn ledger_with(n: usize, bond_stell: u64) -> (StakingLedger, Vec<[u8; 32]>) {
        let mut l = StakingLedger::new();
        let ids: Vec<[u8; 32]> = (0..n).map(|i| [i as u8 + 1; 32]).collect();
        for id in &ids {
            l.bond(*id, stell(bond_stell), DEFAULT_COMMISSION_BPS).unwrap();
        }
        (l, ids)
    }

    #[test]
    fn propose_requires_minimum_stake() {
        let mut l = StakingLedger::new();
        let poor = [9u8; 32];
        l.bond(poor, stell(1_000) + crate::staking::STELL_MIN_BOND_BUFFER, DEFAULT_COMMISSION_BPS).unwrap();
        let mut g = Governance::new();
        // 1,100 < 10,000 min -> rejected
        assert_eq!(
            g.propose(&l, poor, "t".into(), GovAction::Signal("t".into()), 0),
            Err(GovError::InsufficientStake)
        );
    }

    #[test]
    fn full_vote_pass_execute_flow() {
        let (mut l, ids) = ledger_with(3, 10_000);
        let mut g = Governance::new();
        let id = g
            .propose(&l, ids[0], "raise reward".into(), GovAction::SetBlockReward(stell(9)), 0)
            .unwrap();
        // 2 of 3 vote yes (>= 2/3 quorum)
        g.vote(&mut l, ids[0], id, VoteChoice::Yes, 1).unwrap();
        g.vote(&mut l, ids[1], id, VoteChoice::Yes, 1).unwrap();
        g.vote(&mut l, ids[2], id, VoteChoice::No, 1).unwrap();
        let status = g.finalize(&mut l, id, GOVERNANCE_VOTING_PERIOD_SECS + 1).unwrap();
        assert_eq!(status, ProposalStatus::Passed);
        let applied = g.execute(ids[0], id).unwrap();
        assert_eq!(applied.block_reward, Some(stell(9)));
        // cannot execute twice
        assert_eq!(g.execute(ids[0], id), Err(GovError::AlreadyExecuted));
    }

    #[test]
    fn low_turnout_fails_quorum() {
        let (mut l, ids) = ledger_with(3, 10_000);
        let mut g = Governance::new();
        let id = g.propose(&l, ids[0], "x".into(), GovAction::Signal("t".into()), 0).unwrap();
        // only 1 of 3 votes (~33% < 2/3 quorum)
        g.vote(&mut l, ids[0], id, VoteChoice::Yes, 1).unwrap();
        let status = g.finalize(&mut l, id, GOVERNANCE_VOTING_PERIOD_SECS + 1).unwrap();
        assert_eq!(status, ProposalStatus::Rejected);
    }

    #[test]
    fn no_majority_is_rejected() {
        let (mut l, ids) = ledger_with(3, 10_000);
        let mut g = Governance::new();
        let id = g.propose(&l, ids[0], "x".into(), GovAction::Signal("t".into()), 0).unwrap();
        // all vote but yes does not exceed no
        g.vote(&mut l, ids[0], id, VoteChoice::No, 1).unwrap();
        g.vote(&mut l, ids[1], id, VoteChoice::No, 1).unwrap();
        g.vote(&mut l, ids[2], id, VoteChoice::Yes, 1).unwrap();
        let status = g.finalize(&mut l, id, GOVERNANCE_VOTING_PERIOD_SECS + 1).unwrap();
        assert_eq!(status, ProposalStatus::Rejected);
    }

    #[test]
    fn cannot_vote_twice_or_after_close() {
        let (mut l, ids) = ledger_with(3, 10_000);
        let mut g = Governance::new();
        let id = g.propose(&l, ids[0], "x".into(), GovAction::Signal("t".into()), 0).unwrap();
        g.vote(&mut l, ids[0], id, VoteChoice::Yes, 1).unwrap();
        assert_eq!(g.vote(&mut l, ids[0], id, VoteChoice::No, 1), Err(GovError::AlreadyVoted));
        assert_eq!(
            g.vote(&mut l, ids[1], id, VoteChoice::Yes, GOVERNANCE_VOTING_PERIOD_SECS + 1),
            Err(GovError::VotingClosed)
        );
    }

    #[test]
    fn vote_weight_tracks_stake() {
        let mut l = StakingLedger::new();
        l.bond([1u8; 32], stell(10_000), DEFAULT_COMMISSION_BPS).unwrap();
        l.bond([2u8; 32], stell(30_000), DEFAULT_COMMISSION_BPS).unwrap();
        let mut g = Governance::new();
        let id = g.propose(&l, [1u8; 32], "x".into(), GovAction::Signal("t".into()), 0).unwrap();
        let w1 = g.vote(&mut l, [1u8; 32], id, VoteChoice::Yes, 1).unwrap();
        let w2 = g.vote(&mut l, [2u8; 32], id, VoteChoice::No, 1).unwrap();
        assert_eq!(w1, stell(10_000) as u128);
        assert_eq!(w2, stell(30_000) as u128);
        let p = g.get(id).unwrap();
        assert_eq!(p.yes, stell(10_000) as u128);
        assert_eq!(p.no, stell(30_000) as u128);
    }

    #[test]
    fn invalid_action_values_rejected() {
        let (l, ids) = ledger_with(1, 10_000);
        let mut g = Governance::new();
        // 150% slash is nonsense
        assert_eq!(
            g.propose(&l, ids[0], "bad".into(), GovAction::SetEquivocationSlashBps(15_000), 0),
            Err(GovError::InvalidAction)
        );
        // zero quorum is nonsense
        assert_eq!(
            g.propose(&l, ids[0], "bad".into(), GovAction::SetGovernanceQuorumBps(0), 0),
            Err(GovError::InvalidAction)
        );
    }

    #[test]
    fn anyone_can_execute_passed_proposal() {
        let (mut l, ids) = ledger_with(3, 10_000);
        let mut g = Governance::new();
        let id = g.propose(&l, ids[0], "x".into(), GovAction::Signal("t".into()), 0).unwrap();
        g.vote(&mut l, ids[0], id, VoteChoice::Yes, 1).unwrap();
        g.vote(&mut l, ids[1], id, VoteChoice::Yes, 1).unwrap();
        g.finalize(&mut l, id, GOVERNANCE_VOTING_PERIOD_SECS + 1).unwrap();
        // E5: no proposer-only gate — a non-proposer executes fine.
        assert!(g.execute(ids[1], id).is_ok());
        assert_eq!(g.get(id).unwrap().status, ProposalStatus::Executed);
    }

    #[test]
    fn quorum_floor_rejected_at_propose_time() {
        let (l, ids) = ledger_with(1, 10_000);
        let mut g = Governance::new();
        // 1 bps (0.01%) must be refused at propose time.
        assert_eq!(
            g.propose(&l, ids[0], "bad".into(), GovAction::SetGovernanceQuorumBps(1), 0),
            Err(GovError::InvalidAction)
        );
        // Just below the 3333 bps floor is also refused.
        assert_eq!(
            g.propose(
                &l,
                ids[0],
                "bad".into(),
                GovAction::SetGovernanceQuorumBps(GOVERNANCE_QUORUM_FLOOR_BPS - 1),
                0
            ),
            Err(GovError::InvalidAction)
        );
        // The floor error message must name the floor.
        let err = g
            .propose(&l, ids[0], "bad".into(), GovAction::SetGovernanceQuorumBps(1), 0)
            .unwrap_err();
        assert!(
            format!("{err}").contains("3333"),
            "quorum-floor error must name the 3333 bps floor, got: {err}"
        );
        // The floor itself is accepted.
        assert!(
            g.propose(
                &l,
                ids[0],
                "ok".into(),
                GovAction::SetGovernanceQuorumBps(GOVERNANCE_QUORUM_FLOOR_BPS),
                0
            )
            .is_ok()
        );
    }

    #[test]
    fn quorum_floor_enforced_at_execute_time() {
        let (_l, ids) = ledger_with(3, 10_000);
        let mut g = Governance::new();
        // Bypass propose-time validation by inserting directly, then prove the
        // execute-time backstop still refuses 1 bps.
        let id = g.next_id;
        g.next_id += 1;
        g.proposals.insert(
            id,
            Proposal {
                id,
                proposer: ids[0],
                title: "sneaky".into(),
                action: GovAction::SetGovernanceQuorumBps(1),
                created_at: 0,
                voting_end: GOVERNANCE_VOTING_PERIOD_SECS,
                yes: 0,
                no: 0,
                abstain: 0,
                voters: HashMap::new(),
                status: ProposalStatus::Passed,
                electorate: 0,
                weights: HashMap::new(),
            },
        );
        let err = g.execute(ids[1], id).unwrap_err();
        assert_eq!(err, GovError::InvalidAction);
        assert!(
            format!("{err}").contains("3333"),
            "execute-time floor error must name the 3333 bps floor, got: {err}"
        );
        assert_eq!(g.get(id).unwrap().status, ProposalStatus::Passed);
    }

    #[test]
    fn non_proposer_can_execute_passed_quorum_change() {
        let (mut l, ids) = ledger_with(3, 10_000);
        let mut g = Governance::new();
        let id = g
            .propose(&l, ids[0], "q".into(), GovAction::SetGovernanceQuorumBps(5_000), 0)
            .unwrap();
        g.vote(&mut l, ids[0], id, VoteChoice::Yes, 1).unwrap();
        g.vote(&mut l, ids[1], id, VoteChoice::Yes, 1).unwrap();
        g.finalize(&mut l, id, GOVERNANCE_VOTING_PERIOD_SECS + 1).unwrap();
        // Non-proposer executes a passed quorum change.
        g.execute(ids[2], id).unwrap();
        assert_eq!(g.quorum_bps, 5_000);
    }

    #[test]
    fn quorum_action_applies() {
        let (mut l, ids) = ledger_with(3, 10_000);
        let mut g = Governance::new();
        let id = g
            .propose(&l, ids[0], "q".into(), GovAction::SetGovernanceQuorumBps(5_000), 0)
            .unwrap();
        g.vote(&mut l, ids[0], id, VoteChoice::Yes, 1).unwrap();
        g.vote(&mut l, ids[1], id, VoteChoice::Yes, 1).unwrap();
        g.finalize(&mut l, id, GOVERNANCE_VOTING_PERIOD_SECS + 1).unwrap();
        g.execute(ids[0], id).unwrap();
        assert_eq!(g.quorum_bps, 5_000);
    }

    #[test]
    fn vote_weight_does_not_double_count_delegated_stake() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(10_000), DEFAULT_COMMISSION_BPS).unwrap();
        l.delegate(del(2), vid(1), stell(5_000)).unwrap();
        let mut g = Governance::new();
        let id = g.propose(&l, vid(1), "x".into(), GovAction::Signal("t".into()), 0).unwrap();
        // The validator owns its 10k self-bond; the 5k delegated by del(2) is
        // del(2)'s stake, NOT the validator's. Vote weight must be exactly 10k.
        let w = g.vote(&mut l, vid(1), id, VoteChoice::Yes, 1).unwrap();
        assert_eq!(w, stell(10_000) as u128, "delegated-in stake must not double count");
    }

    #[test]
    fn self_delegation_does_not_inflate_vote() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(10_000), DEFAULT_COMMISSION_BPS).unwrap();
        l.delegate(vid(1), vid(1), stell(5_000)).unwrap();
        let mut g = Governance::new();
        let id = g.propose(&l, vid(1), "x".into(), GovAction::Signal("t".into()), 0).unwrap();
        // self-bond 10k + own delegation out 5k = 15k (counted once each)
        let w = g.vote(&mut l, vid(1), id, VoteChoice::Yes, 1).unwrap();
        assert_eq!(w, stell(15_000) as u128, "self-delegation must not be counted twice");
    }

    #[test]
    fn delegator_votes_with_own_stake_only_once() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(10_000), DEFAULT_COMMISSION_BPS).unwrap();
        l.bond(vid(2), stell(10_000), DEFAULT_COMMISSION_BPS).unwrap();
        l.delegate(vid(1), vid(2), stell(5_000)).unwrap(); // vid1 delegates 5k to vid2
        let mut g = Governance::new();
        let id = g.propose(&l, vid(1), "x".into(), GovAction::Signal("t".into()), 0).unwrap();
        // vid1's own stake is 10k (self) + 5k (delegated out); it must NOT also
        // gain the 5k as if it were still consensus power on vid1.
        let w = g.vote(&mut l, vid(1), id, VoteChoice::Yes, 1).unwrap();
        assert_eq!(w, stell(15_000) as u128);
    }

    #[test]
    fn finalize_denominator_matches_total_voting_power() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(10_000), DEFAULT_COMMISSION_BPS).unwrap();
        l.delegate(del(1), vid(1), stell(9_000)).unwrap();
        // total voting power = self 10k + delegated 9k = 19k
        assert_eq!(Governance::total_voting_power(&l), stell(19_000) as u128);
        let mut g = Governance::new();
        let id = g.propose(&l, vid(1), "x".into(), GovAction::Signal("t".into()), 0).unwrap();
        g.vote(&mut l, vid(1), id, VoteChoice::Yes, 1).unwrap(); // 10k
        g.vote(&mut l, del(1), id, VoteChoice::Yes, 1).unwrap(); // 9k
        let p = g.get(id).unwrap();
        // turnout (19k) must not exceed the quorum base (19k)
        assert!(p.turnout() <= Governance::total_voting_power(&l));
        let status = g.finalize(&mut l, id, GOVERNANCE_VOTING_PERIOD_SECS + 1).unwrap();
        assert_eq!(status, ProposalStatus::Passed);
    }

    /// E7 (vote-then-exit flips quorum): 29k base needs 19,331, so 19k
    /// yes-votes must stay Rejected even after yes-voter B exits 9k (which
    /// shrinks the live base to 20k / needs 13,332). The exit must be
    /// refused while the vote is open AND the outcome must not flip.
    #[test]
    fn vote_then_exit_cannot_flip_quorum() {
        use crate::staking::StakingError;

        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(10_000), DEFAULT_COMMISSION_BPS).unwrap();
        l.bond(vid(2), stell(10_000), DEFAULT_COMMISSION_BPS).unwrap();
        l.delegate(del(1), vid(1), stell(9_000)).unwrap();
        assert_eq!(Governance::total_voting_power(&l), stell(29_000) as u128);
        let mut g = Governance::new();
        let id = g.propose(&l, vid(1), "x".into(), GovAction::Signal("t".into()), 0).unwrap();
        // The quorum base is frozen at propose time.
        assert_eq!(g.get(id).unwrap().electorate, stell(29_000) as u128);
        g.vote(&mut l, vid(1), id, VoteChoice::Yes, 1).unwrap(); // 10k
        g.vote(&mut l, del(1), id, VoteChoice::Yes, 1).unwrap(); // 9k
        assert_eq!(g.get(id).unwrap().turnout(), stell(19_000) as u128);
        // B's 9k backed an open vote: the exit is refused, ...
        assert_eq!(
            l.undelegate(del(1), vid(1), stell(9_000), 2),
            Err(StakingError::LockedInGovernanceVote)
        );
        // ... and even a completed exit could not move the frozen base:
        // 19k < 19,331 quorum on 29k stays Rejected.
        let status = g.finalize(&mut l, id, GOVERNANCE_VOTING_PERIOD_SECS + 1).unwrap();
        assert_eq!(
            status,
            ProposalStatus::Rejected,
            "E7: 19k < 19,331 quorum on the 29k propose-time base"
        );
        // The terminal transition releases the locks: the exit works now.
        assert_eq!(l.locked_governance_of(&del(1)), 0);
        l.undelegate(del(1), vid(1), stell(9_000), 3).unwrap();
    }
}
