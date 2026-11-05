//! On-chain Governance: stake-weighted proposals and voting.
//!
//! Token holders vote on network parameters with voting power equal to their
//! bonded stake (validators) plus delegators' bonded stake — the same ledger
//! that secures consensus, so governance power tracks economic skin-in-the-game.
//!
//! Lifecycle:
//!   1. `propose`  — a staker submits a `Proposal` with a concrete `GovAction`.
//!   2. `vote`     — stakers vote Yes/No/Abstain; one vote per voter per proposal,
//!      weight = current staked balance. Votes are locked to the
//!      proposal id and cannot be changed (no vote flipping).
//!   3. `finalize` — after `voting_end`, if turnout >= quorum and yes > no, the
//!      proposal is `Passed`, else `Rejected`.
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
use std::collections::BTreeMap;

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
/// Timelock delay in heights between a proposal passing and its execution
/// (KI-23 fix: voted proposals no longer execute immediately).
///
/// A passed proposal schedules execution at `pass_height +
/// GOV_TIMELOCK_HEIGHTS`; execution before maturity REFUSES fail-closed
/// (`GovError::Timelocked`, proposal stays `Passed`). Query via
/// [`Governance::executable_height_of`] / [`Governance::is_mature`]
/// (and `get` status `Passed` = pending).
///
/// Choice: 7,200 heights ≈ 6 h at 3 s blocks — the SAME exit-window
/// philosophy as [`crate::staking::COMMISSION_EFFECT_DELAY_HEIGHTS`]
/// (delegators get a window to exit before a commission raise lands; here
/// the chain gets a window to react before a passed action lands).
/// Deterministic const, never env (consensus: every node applying the same
/// blocks must reach the same maturity; an env knob would fork the chain).
///
/// There is deliberately NO emergency bypass in this module (out of scope;
/// reported as follow-up).
///
/// FREEZE (protocol freeze 2026-11-03 style): 7,200 heights, never env.
/// Change requires spec update + audit note (AGENTS.md §7).
pub const GOV_TIMELOCK_HEIGHTS: u64 = 7_200;

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
/// ADMISSION floor stays max(frozen, governed): raising governed above the
/// frozen floor only affects admission at the governed value.
/// (Protocol freeze 2026-11-03: the frozen half is identical on all nodes.)
///
/// FREEZE (protocol freeze 2026-11-03): 10x the cheapest real transfer.
/// Change requires spec update + audit note (AGENTS.md §7).
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
    /// KI-23 timelock: the proposal passed but its executable height has not
    /// been reached. Fail-closed; the proposal stays `Passed`.
    Timelocked,
    /// Operator-signed governance identity: the ingest path requires a wallet
    /// signature and none was supplied. Fail-closed; the legacy unsigned path
    /// is refused except behind the dev-test escape.
    MissingSignature,
    /// The supplied governance signature does not verify against the claimed
    /// proposer/voter staking key (wrong key, tampered bytes, or wrong chain).
    BadSignature,
    /// The proposal nonce was already consumed by this proposer. Fail-closed;
    /// the caller must mint a fresh nonce and re-sign.
    ReplayedNonce,
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
            GovError::Timelocked =>
                "proposal timelock has not matured (execution refused fail-closed)",
            GovError::MissingSignature =>
                "missing governance signature (operator-signed identity required: pass 'signature' over (chain_id || action || nonce))",
            GovError::BadSignature =>
                "invalid governance signature (not verifiable against the claimed staking key)",
            GovError::ReplayedNonce =>
                "replayed governance nonce (this proposer already consumed this nonce; mint a fresh one)",
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
    /// `MAX_MIN_GAS_LIMIT`; the effective floor is max(frozen, governed).
    SetMinGasLimit(u64),
    /// Schedule a coordinated software upgrade at a specific block height.
    SoftwareUpgrade {
        name: String,
        height: u64,
        sha256: [u8; 32],
    },
    /// Cancel an upcoming scheduled software upgrade.
    CancelUpgrade,
}

impl GovAction {
    /// The canonical action string of this action.
    ///
    /// This is the `type` a caller sends to `stell_submitProposal`, and it is
    /// the ONLY spelling that selects this action: the dispatcher maps the
    /// string to exactly one variant, and an unknown string is REFUSED (it
    /// never falls back to `Signal`).
    ///
    /// The strings are distinct per variant, so `stell_proposal` can render
    /// an action as the same word the proposer used. `ACTION_TYPES` lists them
    /// all, and the test below pins the one-to-one mapping: adding a variant
    /// without giving it a string breaks that test.
    pub fn action_type(&self) -> &'static str {
        match self {
            GovAction::SetMinValidatorBond(_) => "set_min_validator_bond",
            GovAction::SetEquivocationSlashBps(_) => "set_equivocation_slash_bps",
            GovAction::SetDefaultCommissionBps(_) => "set_default_commission_bps",
            GovAction::SetBlockReward(_) => "set_block_reward",
            GovAction::SetPmmRedemptionBufferBps(_) => "set_pmm_redemption_buffer_bps",
            GovAction::SetGovernanceQuorumBps(_) => "set_governance_quorum_bps",
            GovAction::Signal(_) => "signal",
            GovAction::RegisterOraclePublisher(_) => "register_oracle_publisher",
            GovAction::UnregisterOraclePublisher(_) => "unregister_oracle_publisher",
            GovAction::ResetOracleBreaker => "reset_oracle_breaker",
            GovAction::SetMinGasLimit(_) => "set_min_gas_limit",
            GovAction::SoftwareUpgrade { .. } => "software_upgrade",
            GovAction::CancelUpgrade => "cancel_upgrade",
        }
    }

    /// Every canonical action string, in the order the variants are declared.
    ///
    /// The list is the documented vocabulary of `stell_submitProposal`: a
    /// `type` outside it is refused instead of being turned into a `Signal`.
    pub const ACTION_TYPES: &'static [&'static str] = &[
        "set_min_validator_bond",
        "set_equivocation_slash_bps",
        "set_default_commission_bps",
        "set_block_reward",
        "set_pmm_redemption_buffer_bps",
        "set_governance_quorum_bps",
        "signal",
        "register_oracle_publisher",
        "unregister_oracle_publisher",
        "reset_oracle_breaker",
        "set_min_gas_limit",
        "software_upgrade",
        "cancel_upgrade",
    ];

    /// Deprecated aliases of the canonical action strings.
    ///
    /// An alias is accepted for backwards compatibility ONLY: the canonical
    /// string of every action is the one [`GovAction::action_type`] returns.
    pub const ACTION_TYPE_ALIASES: &'static [(&'static str, &'static str)] =
        &[("upgrade", "software_upgrade")];

    /// Is `action_type` one of the canonical action strings (or a documented
    /// alias of one)?
    pub fn is_known_action_type(action_type: &str) -> bool {
        Self::ACTION_TYPES.contains(&action_type)
            || Self::ACTION_TYPE_ALIASES
                .iter()
                .any(|(alias, _)| *alias == action_type)
    }

    /// Reject obviously invalid parameter values (defense in depth).
    pub fn validate(&self) -> Result<(), GovError> {
        match self {
            GovAction::SetMinValidatorBond(v) => {
                if *v < crate::staking::MIN_VALIDATOR_BOND || *v > MAX_VALIDATOR_BOND {
                    return Err(GovError::InvalidAction);
                }
            }
            GovAction::SetBlockReward(v) => {
                if *v > MAX_BLOCK_REWARD_NANO {
                    return Err(GovError::InvalidAction);
                }
            }
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
            GovAction::SoftwareUpgrade {
                name,
                height,
                sha256,
            } => {
                if name.is_empty()
                    || name.len() > 64
                    || *height == 0
                    || *sha256 == [0u8; 32]
                    || !upgrade_name_is_safe(name)
                {
                    return Err(GovError::InvalidAction);
                }
            }
            GovAction::CancelUpgrade => {}
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

// ---------------------------------------------------------------------------
// Action strings: the JSON-RPC vocabulary of `stell_submitProposal`
// ---------------------------------------------------------------------------

/// A parameter of a governance action, as it arrives over JSON-RPC.
fn gov_u64(p: &serde_json::Value, key: &str) -> Result<u64, String> {
    match p.get(key) {
        Some(serde_json::Value::Number(n)) => n
            .as_u64()
            .ok_or_else(|| format!("parameter '{key}' must be an unsigned integer")),
        Some(serde_json::Value::String(s)) => s
            .trim()
            .parse::<u64>()
            .map_err(|_| format!("parameter '{key}' must be an unsigned integer")),
        Some(_) => Err(format!("parameter '{key}' must be an unsigned integer")),
        None => Err(format!("missing parameter '{key}'")),
    }
}

/// A 32-byte key of a governance action, as it arrives over JSON-RPC.
fn gov_key(p: &serde_json::Value, key: &str) -> Result<[u8; 32], String> {
    let s = match p.get(key) {
        Some(serde_json::Value::String(s)) => s.trim().to_string(),
        Some(_) => return Err(format!("parameter '{key}' must be a hex string")),
        None => return Err(format!("missing parameter '{key}'")),
    };
    let clean = s.strip_prefix("0x").unwrap_or(&s);
    let bytes = hex::decode(clean).map_err(|e| format!("parameter '{key}': bad hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("parameter '{key}' must be 32 bytes (64 hex chars)"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Build the action named by `action_type` from the JSON parameters.
///
/// EVERY variant of [`GovAction`] has exactly one canonical action string
/// (see [`GovAction::action_type`]) and every one of them is reachable here.
///
/// FAIL CLOSED (audit W7.2): an unknown action string is an ERROR. It used to
/// fall into a catch-all arm that turned it into a `Signal` — a silent no-op
/// that made a typo (or a caller that expected a parameter change) look like
/// a proposal that was accepted. It is now refused, and the refusal names
/// the known vocabulary.
///
/// The returned action is NOT validated here: [`GovAction::validate`] (and
/// the execute-time backstops) own the bounds, so propose-time and
/// execute-time apply the same rules.
pub fn gov_action_from_params(
    action_type: &str,
    p: &serde_json::Value,
) -> Result<GovAction, String> {
    match action_type {
        "set_min_validator_bond" => Ok(GovAction::SetMinValidatorBond(gov_u64(p, "value")?)),
        "set_equivocation_slash_bps" => {
            Ok(GovAction::SetEquivocationSlashBps(gov_u64(p, "value")?))
        }
        "set_default_commission_bps" => {
            Ok(GovAction::SetDefaultCommissionBps(gov_u64(p, "value")?))
        }
        "set_block_reward" => Ok(GovAction::SetBlockReward(gov_u64(p, "value")?)),
        "set_pmm_redemption_buffer_bps" => {
            Ok(GovAction::SetPmmRedemptionBufferBps(gov_u64(p, "value")?))
        }
        "set_governance_quorum_bps" => Ok(GovAction::SetGovernanceQuorumBps(gov_u64(p, "value")?)),
        "signal" => {
            let text = match p.get("text") {
                Some(serde_json::Value::String(s)) => s.clone(),
                Some(_) => return Err("parameter 'text' must be a string".to_string()),
                None => return Err("missing parameter 'text'".to_string()),
            };
            Ok(GovAction::Signal(text))
        }
        "register_oracle_publisher" => {
            Ok(GovAction::RegisterOraclePublisher(gov_key(p, "publisher")?))
        }
        "unregister_oracle_publisher" => Ok(GovAction::UnregisterOraclePublisher(gov_key(
            p,
            "publisher",
        )?)),
        "reset_oracle_breaker" => Ok(GovAction::ResetOracleBreaker),
        "set_min_gas_limit" => Ok(GovAction::SetMinGasLimit(gov_u64(p, "value")?)),
        "software_upgrade" | "upgrade" => {
            let name = match p.get("name") {
                Some(serde_json::Value::String(s)) => s.clone(),
                Some(_) => return Err("parameter 'name' must be a string".to_string()),
                None => return Err("missing parameter 'name'".to_string()),
            };
            let height = gov_u64(p, "height")?;
            let sha256 = match p.get("sha256") {
                Some(serde_json::Value::String(s)) => {
                    let clean = s.trim().strip_prefix("0x").unwrap_or(s.trim());
                    let bytes = hex::decode(clean)
                        .map_err(|e| format!("parameter 'sha256': bad hex: {e}"))?;
                    if bytes.len() != 32 {
                        return Err(
                            "parameter 'sha256' must be 32 bytes (64 hex chars)".to_string()
                        );
                    }
                    let mut out = [0u8; 32];
                    out.copy_from_slice(&bytes);
                    out
                }
                Some(_) => return Err("parameter 'sha256' must be a hex string".to_string()),
                None => return Err("missing parameter 'sha256'".to_string()),
            };
            Ok(GovAction::SoftwareUpgrade {
                name,
                height,
                sha256,
            })
        }
        "cancel_upgrade" => Ok(GovAction::CancelUpgrade),
        other => Err(format!(
            "unknown governance action type '{other}' (known: {})",
            GovAction::ACTION_TYPES.join(", ")
        )),
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
    /// Audit G1: frozen per-voter weights (voter -> weight at propose time).
    /// Late-bonded stake votes at ZERO: without this, stake bonded mid-vote
    /// counts at full weight against the frozen base (turnout inflation —
    /// flash-bond pushes sub-quorum proposals over the line). `None` =
    /// pre-upgrade proposal (falls back to live weights, exactly the old
    /// behavior) so persisted governance state migrates without a fork.
    pub electorate_weights: Option<BTreeMap<[u8; 32], u128>>,
    /// Audit G2: the proposer's own stake locked while the proposal is open
    /// (skin-in-the-game: proposing then fully exiting is refused by the
    /// staking-side lock). Released at finalize alongside voter weights.
    /// `0` = pre-upgrade proposal (nothing locked, old behavior).
    pub proposer_lock: u64,
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
    /// KI-23 timelock schedule: proposal id -> executable height
    /// (`pass_height + GOV_TIMELOCK_HEIGHTS`).
    ///
    /// Set on the Passed transition by `finalize_at_height` ONLY. No entry
    /// means unscheduled: Open/Rejected, or a pre-timelock Passed migrated
    /// from storage (executes immediately via either path — one-time
    /// migration, not a bypass: all NEW passes schedule `Some`).
    /// Kept (not drained) after execution as the audit trail of when the
    /// proposal became executable. `#[serde(default)]` so persisted state
    /// without this map loads with no maturities (legacy immediate).
    #[serde(default)]
    pub timelocks: HashMap<u64, u64>,
    /// Consumed operator-signature proposal nonces: (proposer, nonce).
    ///
    /// Replay protection for the signed propose path (`propose_signed`):
    /// a signature binds (chain_id || proposer || title || action || nonce),
    /// and the nonce is consumed here on success, so a captured envelope can
    /// never open a second proposal. Votes need no nonce: they are
    /// proposal-scoped (one vote per voter per proposal, see `vote`), so a
    /// replayed vote envelope is idempotent-or-refused, never double-counted.
    /// `#[serde(default)]` so pre-signature storage loads with an empty set
    /// (exact: no signed nonce existed before this path, nothing to replay).
    /// Deliberately NOT in the commitment digest: admission replay state, not
    /// tally state (same precedent as `timelocks`).
    #[serde(default)]
    pub gov_propose_nonces: std::collections::HashSet<([u8; 32], u64)>,
}

/// Coordinated software upgrade plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradePlan {
    pub name: String,
    pub height: u64,
    pub sha256: [u8; 32],
}

/// TRUE when an upgrade plan's `name` is a SAFE single path segment.///
/// The name is used to build the path of the new binary
/// (`data/upgrades/<name>/stellereum`), so a name that carries a path
/// separator (or a `..`) lets a governance proposal point the upgrade at an
/// ARBITRARY path outside the operator's upgrade directory.
///
/// PATH TRAVERSAL (audit W6.7): before this check the only constraints on
/// `name` were "non-empty, at most 64 bytes", so `../../../../tmp/evil`
/// was a legal upgrade name and the exec site built
/// `data/upgrades/../../../../tmp/evil/stellereum` — outside
/// `data/upgrades/` entirely. The hash check still had to pass, but the
/// sandbox the operator believed they had ("the plan names a directory
/// under `data/upgrades/`") did not exist.
///
/// The rule is deliberately strict and SYMPTOMATIC: exactly one path
/// segment, made only of ASCII letters, digits, `-`, `_` and `.`, and NOT
/// `.` or `..`. That is a strict superset of the names an operator uses in
/// practice (`v0.2.0`, `2026-10-20-hotfix`, `release_1`).
pub fn upgrade_name_is_safe(name: &str) -> bool {
    if name.is_empty() || name.len() > 64 {
        return false;
    }
    // A path separator of ANY flavour (unix `/`, windows `\`, and the
    // unicode look-alikes that survive a naive byte check) is refused.
    if name
        .chars()
        .any(|c| c == '/' || c == '\\' || c == '\0' || !c.is_ascii())
    {
        return false;
    }
    if name == "." || name == ".." {
        return false;
    }
    // A leading dot would create a hidden directory; refuse it together with
    // the `.`/`..` cases above.
    if name.starts_with('.') {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

// ===========================================================================
// OPERATOR TOOLING: the software-upgrade exec path
//
// The upgrade plan names a DIRECTORY under `data/upgrades/`; the node looks
// there for the new binary, verifies it against the plan's SHA-256 and
// `execve`s it. Three properties must hold, and each of them was a hole
// before the W6.7 re-audit:
//
//  1. the plan's name may not escape `data/upgrades/` (see
//     [`upgrade_name_is_safe`]);
//  2. the binary that is EXECUTED must be the binary that was HASHED — the
//     old path read+hash'd the file and then exec'd it BY PATH, so the file
//     could be swapped in between (TOCTOU). The staging helper below copies
//     the VERIFIED BYTES into a private directory and hands back that copy;
//  3. the candidate must not be a SYMLINK — a symlink turns the "candidate
//     under the operator's upgrade directory" into "any file on the box"
//     (and the old `set_permissions(0o755)` on the candidate chmod-ed the
//     symlink's TARGET).
// ===========================================================================

/// Maximum size of an upgrade candidate binary (bytes). A blob bigger than
/// this is refused before it is read into memory.
pub const MAX_UPGRADE_BINARY_BYTES: u64 = 512 * 1024 * 1024;

/// The environment variable that ARMS the live migration (`execve` of the new
/// binary) at an upgrade height.
///
/// **OFF unless it is explicitly set to `1`/`true`** (audit W8.3, production
/// blocker A8). An on-chain governance proposal is a quorum decision about the
/// CHAIN's rules; it is not, and must not be, a decision to replace the
/// running binary on the operator's box. Arming the live migration is an
/// operator-local, node-by-node decision, so it takes an operator-local,
/// node-by-node switch — and the default is the safe one.
pub const AUTO_UPGRADE_ENV: &str = "STELL_AUTO_UPGRADE";

/// Whether the live migration is ARMED, given the raw environment value.
///
/// The rules, stated once so the startup log and the exec site cannot drift:
///
/// * `None` (the variable is not set) → **NOT armed**;
/// * `Some("1")` / `Some("true")` (case-insensitive, surrounding whitespace
///   ignored) → armed;
/// * anything else (`"0"`, `"false"`, `"yes"`, `"on"`, garbage) → NOT armed.
///
/// Only the two literal spellings arm it. A typo therefore fails SAFE (the
/// node halts at the upgrade height with exit code 42 and the supervisor
/// restarts it), never open.
pub fn auto_upgrade_armed_from(value: Option<&str>) -> bool {
    match value {
        Some(v) => {
            let v = v.trim();
            v == "1" || v.eq_ignore_ascii_case("true")
        }
        None => false,
    }
}

/// Whether the live migration is armed on THIS node, right now.
///
/// Reads [`AUTO_UPGRADE_ENV`]. **Unset means NOT armed** — the default is the
/// safe one (audit W8.3 / production blocker A8).
pub fn auto_upgrade_armed() -> bool {
    auto_upgrade_armed_from(std::env::var(AUTO_UPGRADE_ENV).ok().as_deref())
}

/// A one-line, operator-facing description of the arming state, for the
/// startup banner. Never leaks anything but the state itself.
pub fn auto_upgrade_state_line() -> String {
    if auto_upgrade_armed() {
        format!(
            "{AUTO_UPGRADE_ENV}=1 — LIVE MIGRATION ARMED: at an approved upgrade height this \
             node will exec the verified new binary IN PLACE"
        )
    } else {
        format!(
            "{AUTO_UPGRADE_ENV} is not set to 1/true — the live migration is DISARMED: at an \
             approved upgrade height this node halts with exit code 42 (Cosmovisor-compatible) \
             and the supervisor restarts it"
        )
    }
}

/// The candidate paths an upgrade plan may name, in the order they are tried.
///
/// EMPTY when the plan's name is not a safe single segment: the plan is then
/// refused outright rather than resolved to an arbitrary path.
pub fn upgrade_candidate_paths(plan: &UpgradePlan) -> Vec<std::path::PathBuf> {
    if !upgrade_name_is_safe(&plan.name) {
        return Vec::new();
    }
    vec![
        std::path::PathBuf::from(format!("data/upgrades/{}/stellereum", plan.name)),
        std::path::PathBuf::from(format!("data/upgrades/{}/bin/stellereum", plan.name)),
        std::path::PathBuf::from("/usr/local/bin/stellereum.new"),
    ]
}

/// Read `candidate`, verify it against `expected_sha256`, and stage the
/// VERIFIED BYTES into a private directory.
///
/// Returns the path of the staged copy — THAT is what must be executed. The
/// staging copy is created with `O_EXCL`-style semantics (a fresh private
/// directory with a random name), written with mode 0700 and fsynced, so
/// nothing can replace it between the hash check and the `execve`.
///
/// REFUSES a symlinked candidate (and a non-regular file): the "candidate"
/// must be a real file inside the operator's upgrade directory, not a pointer
/// to an arbitrary path.
pub fn stage_verified_upgrade_binary(
    candidate: &std::path::Path,
    expected_sha256: &[u8; 32],
) -> Result<std::path::PathBuf, String> {
    use sha2::{Digest, Sha256};
    // 1. The candidate must be a regular file, NOT a symlink. `symlink_metadata`
    //    does NOT follow the link, so a symlink is detected as such.
    let meta = std::fs::symlink_metadata(candidate)
        .map_err(|e| format!("upgrade candidate {}: {e}", candidate.display()))?;
    if meta.file_type().is_symlink() {
        return Err(format!(
            "upgrade candidate {} is a SYMLINK: refusing (the candidate must be a regular file)",
            candidate.display()
        ));
    }
    if !meta.is_file() {
        return Err(format!(
            "upgrade candidate {} is not a regular file",
            candidate.display()
        ));
    }
    // SYMLINKED PARENT (audit W8.3, residual of the W6.7 re-audit): the
    // candidate FILE is checked above, but its PARENT directory was not. A
    // symlinked parent (`data/upgrades/v1.0.0` -> `/etc`) turns "the candidate
    // under the operator's upgrade directory" into "a file somewhere else on
    // the box" — the hash check still protects the CONTENT, but the sandbox
    // the operator believes they have ("the plan names a directory under
    // data/upgrades/") would not exist. The parent must therefore be a REAL
    // directory, not a link to one. Fail-closed: a symlinked parent is
    // refused loudly rather than followed.
    let parent = candidate.parent().filter(|p| !p.as_os_str().is_empty());
    if let Some(parent) = parent {
        let pmeta = std::fs::symlink_metadata(parent).map_err(|e| {
            format!(
                "upgrade candidate {}: parent directory {}: {e}",
                candidate.display(),
                parent.display()
            )
        })?;
        if pmeta.file_type().is_symlink() {
            return Err(format!(
                "upgrade candidate {}: parent directory {} is a SYMLINK: refusing (the candidate must live in a real directory)",
                candidate.display(),
                parent.display()
            ));
        }
        if !pmeta.is_dir() {
            return Err(format!(
                "upgrade candidate {}: parent {} is not a directory",
                candidate.display(),
                parent.display()
            ));
        }
    }
    if meta.len() > MAX_UPGRADE_BINARY_BYTES {
        return Err(format!(
            "upgrade candidate {} is too large ({} bytes > {MAX_UPGRADE_BINARY_BYTES})",
            candidate.display(),
            meta.len()
        ));
    }
    // 2. Read + hash.
    let bytes = std::fs::read(candidate)
        .map_err(|e| format!("read upgrade candidate {}: {e}", candidate.display()))?;
    if bytes.len() as u64 > MAX_UPGRADE_BINARY_BYTES {
        return Err("upgrade candidate too large".to_string());
    }
    let hash = Sha256::digest(&bytes);
    // SEC-04: strict equality, and the all-zero digest is never a match (it is
    // refused at propose/execute time as well — belt and braces).
    if *expected_sha256 == [0u8; 32] || expected_sha256.as_slice() != hash.as_slice() {
        return Err(format!(
            "upgrade candidate {} sha256 mismatch (expected {}, got {})",
            candidate.display(),
            hex::encode(expected_sha256),
            hex::encode(hash)
        ));
    }
    // 3. Stage the VERIFIED BYTES into a private directory. The copy is what
    //    gets executed, so a swap of the candidate after this point cannot
    //    change what runs (the TOCTOU is closed).
    let staging = stage_private_dir()?;
    let staged = staging.join("stellereum.new");
    std::fs::write(&staged, &bytes).map_err(|e| format!("stage upgrade binary: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("stage upgrade binary perms: {e}"))?;
    }
    Ok(staged)
}

/// Create a private (0700) staging directory with a random name.
fn stage_private_dir() -> Result<std::path::PathBuf, String> {
    let base = std::env::temp_dir();
    for _ in 0..8 {
        let mut suffix = [0u8; 8];
        // A random suffix: the directory must not be predictable, or a local
        // attacker could pre-create it (or plant a symlink in it).
        if getrandom(&mut suffix).is_err() {
            continue;
        }
        let dir = base.join(format!(
            "stell-upgrade-{}-{}",
            std::process::id(),
            hex::encode(suffix)
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            // `create_dir` (not create_dir_all) FAILS if the path exists, and
            // the mode is applied at creation time — no window in which the
            // directory is world-readable.
            match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => return Ok(dir),
                Err(_) => continue,
            }
        }
        #[cfg(not(unix))]
        {
            match std::fs::create_dir(&dir) {
                Ok(()) => return Ok(dir),
                Err(_) => continue,
            }
        }
    }
    Err("could not create a private staging directory for the upgrade binary".to_string())
}

/// Fill `buf` with random bytes from the OS.
fn getrandom(buf: &mut [u8]) -> Result<(), String> {
    use rand::RngCore;
    rand::rngs::OsRng
        .try_fill_bytes(buf)
        .map_err(|e| format!("os randomness unavailable: {e}"))
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
    pub upgrade_plan: Option<UpgradePlan>,
}

impl Governance {
    pub fn new() -> Self {
        Self {
            proposals: HashMap::new(),
            next_id: 1,
            quorum_bps: GOVERNANCE_QUORUM_BPS,
            applied: AppliedParams::default(),
            timelocks: HashMap::new(),
            gov_propose_nonces: std::collections::HashSet::new(),
        }
    }

    /// Submit a proposal. Requires the proposer to hold >= PROPOSAL_MIN_STAKE.
    pub fn propose(
        &mut self,
        ledger: &mut StakingLedger,
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
        // Audit G1: freeze per-voter weights too (same instant, same ledger
        // read): late-bonded stake must not vote against this base. The sum
        // below equals `total_voting_power` by construction (same addends,
        // grouped per voter instead of globally).
        let mut electorate_weights: BTreeMap<[u8; 32], u128> = BTreeMap::new();
        for (vid, v) in ledger.validators.iter() {
            *electorate_weights.entry(*vid).or_insert(0) += v.self_bond as u128;
        }
        for ((_, d), amount) in ledger.delegations.iter() {
            *electorate_weights.entry(*d).or_insert(0) += *amount as u128;
        }
        electorate_weights.retain(|_, w| *w > 0);
        let electorate: u128 = electorate_weights.values().sum();
        // Hygiene (audit G1): an empty electorate must never open a vote.
        // Unreachable through this path today (the stake gate above implies a
        // non-zero electorate), but a zero base would make `quorum_needed`
        // truncate to 0 — fail closed here rather than trust every future
        // caller to keep the invariant.
        if electorate == 0 {
            return Err(GovError::InvalidAction);
        }
        // Audit G2: lock the proposer's OWN stake (self-bond + delegations
        // out — the same formula as vote weight) for the proposal's lifetime.
        // Others' delegations TO the proposer are not theirs to lock.
        let proposer_own: u128 = ledger
            .validators
            .get(&proposer)
            .map(|v| v.self_bond as u128)
            .unwrap_or(0)
            + ledger
                .delegations
                .iter()
                .filter(|((_, d), _)| *d == proposer)
                .map(|(_, amount)| *amount as u128)
                .sum::<u128>();
        let proposer_lock = u64::try_from(proposer_own).unwrap_or(u64::MAX);
        ledger.lock_governance(proposer, proposer_lock);
        self.proposals.insert(
            id,
            Proposal {
                id,
                proposer,
                title,
                action,
                created_at: now,
                voting_end: now.saturating_add(GOVERNANCE_VOTING_PERIOD_SECS),
                yes: 0,
                no: 0,
                abstain: 0,
                voters: HashMap::new(),
                status: ProposalStatus::Open,
                electorate,
                electorate_weights: Some(electorate_weights),
                proposer_lock,
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
        // Vote-equivocation philosophy (never slash, deterministic outcome):
        // a replayed vote with the SAME choice is idempotent (returns the
        // recorded weight, touches neither the tally nor the staking lock —
        // a replay can never double-count). A DIFFERENT choice is refused
        // (first choice wins); flipping is not supported.
        if let Some(prev) = p.voters.get(&voter) {
            if *prev == choice {
                return Ok(p.weights.get(&voter).copied().unwrap_or(0));
            }
            return Err(GovError::AlreadyVoted);
        }
        // Voting weight = the stake THIS voter actually owns:
        //   - its own self-bond (if it is a validator), plus
        //   - any stake it has delegated OUT to validators.
        // SECURITY: we must NOT use `total_stake` (which includes delegations
        // made BY OTHERS to this validator) and then also add the delegator
        // loop — that double-counts stake and lets a self-delegating validator
        // (or a delegator of another validator) inflate its vote.
        // Audit G1: weight comes from the PROPOSE-time snapshot when present
        // (late-bonded stake votes at zero — it is simply absent from the
        // map). `None` = pre-upgrade proposal: live weights, old behavior.
        let weight = match &p.electorate_weights {
            Some(snap) => snap.get(&voter).copied().ok_or(GovError::NotStaker)?,
            None => {
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
                self_bond + delegated_out
            }
        };
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

    // =======================================================================
    // OPERATOR-SIGNED GOVERNANCE IDENTITY (ingest-path entry validation).
    //
    // A proposal/vote envelope carries a wallet signature over a
    // chain-bound, length-framed message. Verification binds the envelope to
    // the SAME staking key whose stake is locked/voted:
    //   * the envelope's claimed address must EQUAL the proposer/voter, and
    //   * that address must hold stake in the ledger snapshot the tally
    //     reads (propose gate / vote snapshot, enforced by `propose`/`vote`
    //     themselves — a signature from a stakeless key verifies but still
    //     lands on `NotStaker`, so the check is never theater);
    //   * the wallet preimage itself binds `chain_id`, so a testnet envelope
    //     never verifies on another chain.
    // No new crypto: envelopes are `crate::wallet_signing::WalletSignature`
    // (Ed25519/Falcon-512/Hybrid), verified by `verify_message`.
    // =======================================================================

    /// Domain tag for signed proposal envelopes (framing prefix only; the
    /// chain binding comes from the wallet preimage).
    pub const GOV_PROPOSE_TAG: &[u8] = b"STELL-GOV-PROPOSE-V1";
    /// Domain tag for signed vote envelopes.
    pub const GOV_VOTE_TAG: &[u8] = b"STELL-GOV-VOTE-V1";

    /// Canonical bytes the proposer signs:
    /// `TAG || 0x00 || chain_id BE || proposer || nonce BE || title || action`.
    /// Length-framed (no `a||b` vs `ab` ambiguity); the action is the
    /// canonical JSON of the EXACT `GovAction` the node will apply, so any
    /// tampered parameter invalidates the envelope.
    pub fn gov_propose_message(
        chain_id: u64,
        proposer: &[u8; 32],
        title: &str,
        action: &GovAction,
        nonce: u64,
    ) -> Vec<u8> {
        let action_json = crate::wallet_signing::canonical_json(
            &serde_json::to_value(action).unwrap_or(serde_json::Value::Null),
        );
        let mut out = Vec::with_capacity(
            Self::GOV_PROPOSE_TAG.len()
                + 1
                + 8
                + 32
                + 8
                + 8
                + title.len()
                + 8
                + action_json.len(),
        );
        out.extend_from_slice(Self::GOV_PROPOSE_TAG);
        out.push(0x00);
        out.extend_from_slice(&chain_id.to_be_bytes());
        out.extend_from_slice(proposer);
        out.extend_from_slice(&nonce.to_be_bytes());
        out.extend_from_slice(&(title.len() as u64).to_be_bytes());
        out.extend_from_slice(title.as_bytes());
        out.extend_from_slice(&(action_json.len() as u64).to_be_bytes());
        out.extend_from_slice(action_json.as_bytes());
        out
    }

    /// Canonical bytes the voter signs:
    /// `TAG || 0x00 || chain_id BE || proposal_id BE || choice || voter`.
    /// Proposal-scoped by construction: the envelope names its proposal, so
    /// cross-proposal replay is impossible and same-proposal replay is
    /// idempotent-or-refused via the voters map (no nonce store needed).
    pub fn gov_vote_message(
        chain_id: u64,
        proposal_id: u64,
        choice: VoteChoice,
        voter: &[u8; 32],
    ) -> Vec<u8> {
        let choice_byte = match choice {
            VoteChoice::Yes => 0u8,
            VoteChoice::No => 1u8,
            VoteChoice::Abstain => 2u8,
        };
        let mut out = Vec::with_capacity(Self::GOV_VOTE_TAG.len() + 1 + 8 + 8 + 1 + 32);
        out.extend_from_slice(Self::GOV_VOTE_TAG);
        out.push(0x00);
        out.extend_from_slice(&chain_id.to_be_bytes());
        out.extend_from_slice(&proposal_id.to_be_bytes());
        out.push(choice_byte);
        out.extend_from_slice(voter);
        out
    }

    /// Whether `(proposer, nonce)` was already consumed by a signed proposal.
    pub fn propose_nonce_used(&self, proposer: &[u8; 32], nonce: u64) -> bool {
        self.gov_propose_nonces.contains(&(*proposer, nonce))
    }

    /// Submit a proposal with operator-signed identity. Verifies the envelope
    /// against the claimed proposer staking key, consumes the nonce, then
    /// delegates to [`Governance::propose`] (stake gates and tally paths
    /// unchanged). The nonce is consumed ONLY on success, so a refused
    /// proposal (bad stake, bad action) does not burn the caller's nonce.
    #[allow(clippy::too_many_arguments)]
    // GATE: signed propose needs identity + envelope + ledger context; callers pass them explicitly.
    pub fn propose_signed(
        &mut self,
        ledger: &mut StakingLedger,
        proposer: ValidatorId,
        title: String,
        action: GovAction,
        now: u64,
        chain_id: u64,
        nonce: u64,
        sig: &crate::wallet_signing::WalletSignature,
    ) -> Result<u64, GovError> {
        if sig.claimed_address() != proposer {
            return Err(GovError::BadSignature);
        }
        let message = Self::gov_propose_message(chain_id, &proposer, &title, &action, nonce);
        if !crate::wallet_signing::verify_message(&proposer, chain_id, &message, sig) {
            return Err(GovError::BadSignature);
        }
        if self.propose_nonce_used(&proposer, nonce) {
            return Err(GovError::ReplayedNonce);
        }
        let id = self.propose(ledger, proposer, title, action, now)?;
        self.gov_propose_nonces.insert((proposer, nonce));
        Ok(id)
    }

    /// Cast a vote with operator-signed identity. Verifies the envelope
    /// against the claimed voter staking key, then delegates to
    /// [`Governance::vote`] (weight snapshot, tally, and lock paths
    /// unchanged — including same-choice idempotency).
    #[allow(clippy::too_many_arguments)]
    // GATE: signed vote needs identity + envelope + ledger context; callers pass them explicitly.
    pub fn vote_signed(
        &mut self,
        ledger: &mut StakingLedger,
        voter: [u8; 32],
        proposal_id: u64,
        choice: VoteChoice,
        now: u64,
        chain_id: u64,
        sig: &crate::wallet_signing::WalletSignature,
    ) -> Result<u128, GovError> {
        if sig.claimed_address() != voter {
            return Err(GovError::BadSignature);
        }
        let message = Self::gov_vote_message(chain_id, proposal_id, choice, &voter);
        if !crate::wallet_signing::verify_message(&voter, chain_id, &message, sig) {
            return Err(GovError::BadSignature);
        }
        self.vote(ledger, voter, proposal_id, choice, now)
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
        // Legacy path (pre-timelock): no height supplied, so no maturity is
        // scheduled (`timelocks` stays empty for this proposal and `execute`
        // allows immediate execution). Kept so existing callers/tests pinning
        // vote/tally behavior stay byte-identical; NEW passes must use
        // `finalize_at_height` so execution is timelocked (KI-23).
        // Vote/quorum/tally math below is UNCHANGED.
        self.finalize_inner(ledger, proposal_id, now, None)
    }

    /// Finalize a proposal after voting ends AND schedule its timelock.
    ///
    /// Vote/quorum/tally math is byte-identical to [`Governance::finalize`]
    /// (turnout >= frozen quorum, yes > no, non-zero decisive turnout; locks
    /// released exactly once on the terminal transition). On the
    /// Open -> Passed transition ONLY, records
    /// `timelocks[id] = cur_height.saturating_add(GOV_TIMELOCK_HEIGHTS)`;
    /// Rejected schedules nothing. Re-finalize of a non-Open proposal
    /// early-returns WITHOUT touching an existing schedule (idempotent).
    pub fn finalize_at_height(
        &mut self,
        ledger: &mut StakingLedger,
        proposal_id: u64,
        now: u64,
        cur_height: u64,
    ) -> Result<ProposalStatus, GovError> {
        self.finalize_inner(ledger, proposal_id, now, Some(cur_height))
    }

    fn finalize_inner(
        &mut self,
        ledger: &mut StakingLedger,
        proposal_id: u64,
        now: u64,
        cur_height: Option<u64>,
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
        let passed = p.turnout() >= quorum_needed && p.yes > p.no && (p.yes + p.no) > 0;
        p.status = if passed {
            ProposalStatus::Passed
        } else {
            ProposalStatus::Rejected
        };
        // KI-23: schedule the timelock on the Passed transition only, when a
        // height was supplied. Saturating: near-u64::MAX maturity clamps,
        // never wraps.
        if p.status == ProposalStatus::Passed {
            if let Some(h) = cur_height {
                self.timelocks
                    .insert(proposal_id, h.saturating_add(GOV_TIMELOCK_HEIGHTS));
            }
        }
        // E7: release every lock exactly once. This is the only transition
        // out of `Open` (re-finalize early-returns above), so no voter can
        // be unlocked twice and no lock can survive its proposal.
        // Audit G2: the proposer's own-stake lock releases here too.
        let locked: Vec<([u8; 32], u128)> = p
            .weights
            .iter()
            .map(|(voter, w)| (*voter, *w))
            .chain(std::iter::once((p.proposer, p.proposer_lock as u128)))
            .collect();
        for (voter, weight) in locked {
            ledger.unlock_governance(voter, u64::try_from(weight).unwrap_or(u64::MAX));
        }
        Ok(p.status)
    }

    /// Execute a passed proposal's action exactly once; any account may execute
    /// a passed proposal (no proposer-only gate, so a lost/rotated proposer key
    /// cannot brick execution).
    ///
    /// KI-23 TIMELOCK (replaces the E5 "no timelock by deferred design
    /// decision"): a proposal scheduled via `finalize_at_height` REFUSES
    /// execution before `executable_height_of(id)` (fail-closed
    /// `Timelocked`, stays `Passed`). This legacy `execute` supplies NO
    /// height, so a scheduled proposal ALWAYS refuses here — callers MUST use
    /// `execute_at_height` with the current chain height. An UNSCHEDULED
    /// Passed (legacy `finalize`, or pre-timelock storage with no `timelocks`
    /// entry) executes immediately (one-time migration, not a bypass).
    ///
    /// There is deliberately NO emergency bypass in this module (out of
    /// scope; reported as follow-up).
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
        self.execute_inner(executor, proposal_id, None, None)
    }

    /// Execute a passed proposal at the current chain height, enforcing the
    /// KI-23 timelock: before `executable_height_of(id)` refuses fail-closed
    /// (`Timelocked`, stays `Passed`); at/after maturity applies exactly once.
    /// Anyone may execute (no proposer-only gate).
    pub fn execute_at_height(
        &mut self,
        executor: [u8; 32],
        proposal_id: u64,
        cur_height: u64,
    ) -> Result<&AppliedParams, GovError> {
        self.execute_inner(executor, proposal_id, None, Some(cur_height))
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
    ///
    /// Timelock: same rule as [`Governance::execute`] — a scheduled proposal
    /// refuses without a height (use `execute_with_oracle_at_height`).
    pub fn execute_with_oracle(
        &mut self,
        executor: [u8; 32],
        proposal_id: u64,
        oracle: &mut crate::oracle::OracleState,
    ) -> Result<&AppliedParams, GovError> {
        self.execute_inner(executor, proposal_id, Some(oracle), None)
    }

    /// Oracle-aware execution at the current chain height (timelock-enforcing;
    /// see [`Governance::execute_at_height`]).
    pub fn execute_with_oracle_at_height(
        &mut self,
        executor: [u8; 32],
        proposal_id: u64,
        oracle: &mut crate::oracle::OracleState,
        cur_height: u64,
    ) -> Result<&AppliedParams, GovError> {
        self.execute_inner(executor, proposal_id, Some(oracle), Some(cur_height))
    }

    /// Height at which a passed proposal becomes executable, if scheduled.
    ///
    /// `None` = unscheduled (Open/Rejected, or pre-timelock Passed with no
    /// `timelocks` entry — executes immediately as the one-time migration).
    /// Query surface for the timelock alongside `get(id).status == Passed`
    /// (= pending execution).
    pub fn executable_height_of(&self, proposal_id: u64) -> Option<u64> {
        self.timelocks.get(&proposal_id).copied()
    }

    /// Whether `proposal_id` may execute at `cur_height`.
    ///
    /// Unscheduled Passed (no entry) counts as mature (legacy immediate);
    /// non-Passed never counts as mature. Executed counts as mature only if
    /// its recorded height is reached (history queries stay truthful).
    pub fn is_mature(&self, proposal_id: u64, cur_height: u64) -> bool {
        let status = self.proposals.get(&proposal_id).map(|p| p.status);
        match status {
            Some(ProposalStatus::Passed) | Some(ProposalStatus::Executed) => {}
            _ => return false,
        }
        match self.timelocks.get(&proposal_id) {
            Some(m) => cur_height >= *m,
            None => true,
        }
    }

    fn execute_inner(
        &mut self,
        _executor: [u8; 32],
        proposal_id: u64,
        mut oracle: Option<&mut crate::oracle::OracleState>,
        cur_height: Option<u64>,
    ) -> Result<&AppliedParams, GovError> {
        // KI-23 gate FIRST (before any domain write): a scheduled proposal
        // refuses without/at-before maturity, fail-closed, staying `Passed`.
        // `None` height (legacy `execute`) refuses whenever an entry exists;
        // `None` entry (legacy `finalize` / pre-timelock storage) is the
        // one-time migration and proceeds immediately.
        if let Some(maturity) = self.timelocks.get(&proposal_id).copied() {
            let mature = match cur_height {
                Some(h) => h >= maturity,
                None => false,
            };
            if !mature {
                // Existence + status checked below for the exact error
                // (`UnknownProposal` / `AlreadyExecuted` / `NotPassed` win
                // over `Timelocked` when the proposal is not in `Passed`).
                let status = self.proposals.get(&proposal_id).map(|p| p.status);
                match status {
                    Some(ProposalStatus::Passed) => return Err(GovError::Timelocked),
                    Some(ProposalStatus::Executed) => {
                        return Err(GovError::AlreadyExecuted)
                    }
                    Some(_) => return Err(GovError::NotPassed),
                    None => return Err(GovError::UnknownProposal),
                }
            }
        }
        let p = self
            .proposals
            .get_mut(&proposal_id)
            .ok_or(GovError::UnknownProposal)?;
        // E5: anyone-can-execute — no `p.proposer == executor` (`NotProposer`)
        // gate, so a lost/rotated proposer key cannot brick a passed proposal.
        // KI-23: maturity enforced above; reaching here means mature-or-legacy.
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
                if !(crate::staking::MIN_VALIDATOR_BOND..=MAX_VALIDATOR_BOND).contains(&v) {
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
                if !(GOVERNANCE_QUORUM_FLOOR_BPS..=BPS_U64).contains(&v) {
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
                if pk == [0u8; 32] {
                    return Err(GovError::InvalidAction);
                }
                oracle
                    .as_deref_mut()
                    .ok_or(GovError::InvalidAction)?
                    .unregister_publisher(pk);
            }
            GovAction::ResetOracleBreaker => {
                oracle.ok_or(GovError::InvalidAction)?.reset_breaker();
            }
            GovAction::SoftwareUpgrade {
                name,
                height,
                sha256,
            } => {
                if name.is_empty()
                    || name.len() > 64
                    || height == 0
                    || sha256 == [0u8; 32]
                    || !upgrade_name_is_safe(&name)
                {
                    return Err(GovError::InvalidAction);
                }
                self.applied.upgrade_plan = Some(UpgradePlan {
                    name,
                    height,
                    sha256,
                });
            }
            GovAction::CancelUpgrade => {
                self.applied.upgrade_plan = None;
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
        self.proposals
            .values()
            .filter(|p| p.status == status)
            .count()
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
            l.bond(*id, stell(bond_stell), DEFAULT_COMMISSION_BPS)
                .unwrap();
        }
        (l, ids)
    }

    /// Every variant of `GovAction`, one instance each.
    ///
    /// Adding a variant to the enum without giving it a canonical action
    /// string breaks the two tests below — that is the point: the mapping
    /// between a variant and its action string can never silently go stale.
    fn every_action() -> Vec<GovAction> {
        vec![
            GovAction::SetMinValidatorBond(1),
            GovAction::SetEquivocationSlashBps(1),
            GovAction::SetDefaultCommissionBps(1),
            GovAction::SetBlockReward(1),
            GovAction::SetPmmRedemptionBufferBps(1),
            GovAction::SetGovernanceQuorumBps(3_333),
            GovAction::Signal("hello".to_string()),
            GovAction::RegisterOraclePublisher([1u8; 32]),
            GovAction::UnregisterOraclePublisher([1u8; 32]),
            GovAction::ResetOracleBreaker,
            GovAction::SetMinGasLimit(21_000),
            GovAction::SoftwareUpgrade {
                name: "v0.2.0".to_string(),
                height: 100,
                sha256: [7u8; 32],
            },
            GovAction::CancelUpgrade,
        ]
    }

    /// The action strings are ONE-TO-ONE with the variants (audit W7.2).
    #[test]
    fn every_action_has_a_distinct_canonical_action_string() {
        let actions = every_action();
        assert_eq!(
            actions.len(),
            GovAction::ACTION_TYPES.len(),
            "the number of variants and the number of action strings must match"
        );
        let mut seen: Vec<&str> = Vec::new();
        for a in &actions {
            let t = a.action_type();
            assert!(
                !seen.contains(&t),
                "two actions share the action string '{t}'"
            );
            seen.push(t);
        }
        for t in seen {
            assert!(
                GovAction::ACTION_TYPES.contains(&t),
                "the action string '{t}' is not in ACTION_TYPES"
            );
        }
    }

    /// Every action string round-trips back to the variant it names
    /// (audit W7.2): nothing is unreachable, nothing is ambiguous.
    #[test]
    fn every_action_string_round_trips_to_its_action() {
        for a in every_action() {
            let t = a.action_type();
            let p = match &a {
                GovAction::SetMinValidatorBond(_)
                | GovAction::SetEquivocationSlashBps(_)
                | GovAction::SetDefaultCommissionBps(_)
                | GovAction::SetBlockReward(_)
                | GovAction::SetPmmRedemptionBufferBps(_)
                | GovAction::SetGovernanceQuorumBps(_)
                | GovAction::SetMinGasLimit(_) => {
                    serde_json::json!({ "value": match &a {
                        GovAction::SetMinValidatorBond(v)
                        | GovAction::SetEquivocationSlashBps(v)
                        | GovAction::SetDefaultCommissionBps(v)
                        | GovAction::SetBlockReward(v)
                        | GovAction::SetPmmRedemptionBufferBps(v)
                        | GovAction::SetGovernanceQuorumBps(v)
                        | GovAction::SetMinGasLimit(v) => *v,
                        _ => unreachable!(),
                    } })
                }
                GovAction::Signal(text) => serde_json::json!({ "text": text }),
                GovAction::RegisterOraclePublisher(pk)
                | GovAction::UnregisterOraclePublisher(pk) => {
                    serde_json::json!({ "publisher": hex::encode(pk) })
                }
                GovAction::ResetOracleBreaker | GovAction::CancelUpgrade => serde_json::json!({}),
                GovAction::SoftwareUpgrade {
                    name,
                    height,
                    sha256,
                } => serde_json::json!({
                    "name": name,
                    "height": height,
                    "sha256": hex::encode(sha256),
                }),
            };
            let back = gov_action_from_params(t, &p)
                .unwrap_or_else(|e| panic!("action '{t}' must parse: {e}"));
            assert_eq!(back, a, "action '{t}' must round-trip to its variant");
        }
    }

    /// An UNKNOWN action string is REFUSED, never turned into a `Signal`
    /// (audit W7.2).
    #[test]
    fn unknown_action_type_fails_closed() {
        for bad in [
            "upgrade_the_thing",
            "",
            "SIGNAL",
            "set_min_validator_bond_v2",
            "software upgrade",
        ] {
            let err = gov_action_from_params(bad, &serde_json::json!({ "text": "x" })).unwrap_err();
            assert!(
                err.contains("unknown governance action type"),
                "the refusal must name the problem, got: {err}"
            );
            assert!(
                !GovAction::is_known_action_type(bad),
                "'{bad}' must not be a known action type"
            );
        }
        // The canonical vocabulary IS known.
        for t in GovAction::ACTION_TYPES {
            assert!(GovAction::is_known_action_type(t));
        }
        // The documented alias is known too (and maps to its canonical name).
        assert!(GovAction::is_known_action_type("upgrade"));
    }

    /// The action string of a variant is what the RPC answers report.
    #[test]
    fn action_type_of_signal_is_signal() {
        assert_eq!(GovAction::Signal("x".into()).action_type(), "signal");
        assert_eq!(GovAction::CancelUpgrade.action_type(), "cancel_upgrade");
    }

    #[test]
    fn propose_requires_minimum_stake() {
        let mut l = StakingLedger::new();
        let poor = [9u8; 32];
        l.bond(
            poor,
            stell(1_000) + crate::staking::STELL_MIN_BOND_BUFFER,
            DEFAULT_COMMISSION_BPS,
        )
        .unwrap();
        let mut g = Governance::new();
        // 1,100 < 10,000 min -> rejected
        assert_eq!(
            g.propose(&mut l, poor, "t".into(), GovAction::Signal("t".into()), 0),
            Err(GovError::InsufficientStake)
        );
    }

    #[test]
    fn full_vote_pass_execute_flow() {
        let (mut l, ids) = ledger_with(3, 10_000);
        let mut g = Governance::new();
        let id = g
            .propose(
                &mut l,
                ids[0],
                "raise reward".into(),
                GovAction::SetBlockReward(stell(9)),
                0,
            )
            .unwrap();
        // 2 of 3 vote yes (>= 2/3 quorum)
        g.vote(&mut l, ids[0], id, VoteChoice::Yes, 1).unwrap();
        g.vote(&mut l, ids[1], id, VoteChoice::Yes, 1).unwrap();
        g.vote(&mut l, ids[2], id, VoteChoice::No, 1).unwrap();
        let status = g
            .finalize(&mut l, id, GOVERNANCE_VOTING_PERIOD_SECS + 1)
            .unwrap();
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
        let id = g
            .propose(&mut l, ids[0], "x".into(), GovAction::Signal("t".into()), 0)
            .unwrap();
        // only 1 of 3 votes (~33% < 2/3 quorum)
        g.vote(&mut l, ids[0], id, VoteChoice::Yes, 1).unwrap();
        let status = g
            .finalize(&mut l, id, GOVERNANCE_VOTING_PERIOD_SECS + 1)
            .unwrap();
        assert_eq!(status, ProposalStatus::Rejected);
    }

    #[test]
    fn no_majority_is_rejected() {
        let (mut l, ids) = ledger_with(3, 10_000);
        let mut g = Governance::new();
        let id = g
            .propose(&mut l, ids[0], "x".into(), GovAction::Signal("t".into()), 0)
            .unwrap();
        // all vote but yes does not exceed no
        g.vote(&mut l, ids[0], id, VoteChoice::No, 1).unwrap();
        g.vote(&mut l, ids[1], id, VoteChoice::No, 1).unwrap();
        g.vote(&mut l, ids[2], id, VoteChoice::Yes, 1).unwrap();
        let status = g
            .finalize(&mut l, id, GOVERNANCE_VOTING_PERIOD_SECS + 1)
            .unwrap();
        assert_eq!(status, ProposalStatus::Rejected);
    }

    #[test]
    fn cannot_vote_twice_or_after_close() {
        let (mut l, ids) = ledger_with(3, 10_000);
        let mut g = Governance::new();
        let id = g
            .propose(&mut l, ids[0], "x".into(), GovAction::Signal("t".into()), 0)
            .unwrap();
        g.vote(&mut l, ids[0], id, VoteChoice::Yes, 1).unwrap();
        assert_eq!(
            g.vote(&mut l, ids[0], id, VoteChoice::No, 1),
            Err(GovError::AlreadyVoted)
        );
        assert_eq!(
            g.vote(
                &mut l,
                ids[1],
                id,
                VoteChoice::Yes,
                GOVERNANCE_VOTING_PERIOD_SECS + 1
            ),
            Err(GovError::VotingClosed)
        );
    }

    /// Same-choice vote replay is idempotent: the recorded weight is
    /// returned, the tally does not move, and the staking lock is not
    /// topped up (a replay can never double-count). A different choice is
    /// refused (first choice wins) — the vote-equivocation philosophy: never
    /// slash, deterministic outcome.
    #[test]
    fn vote_same_choice_replay_is_idempotent() {
        let (mut l, ids) = ledger_with(2, 10_000);
        let mut g = Governance::new();
        let id = g
            .propose(&mut l, ids[0], "x".into(), GovAction::Signal("t".into()), 0)
            .unwrap();
        let w1 = g.vote(&mut l, ids[0], id, VoteChoice::Yes, 1).unwrap();
        let yes_before = g.proposals.get(&id).unwrap().yes;
        let lock_before = l.locked_governance_of(&ids[0]);
        // Replay the identical vote: idempotent success, same weight.
        let w2 = g.vote(&mut l, ids[0], id, VoteChoice::Yes, 1).unwrap();
        assert_eq!(w1, w2, "replay must return the recorded weight");
        let p = g.proposals.get(&id).unwrap();
        assert_eq!(p.yes, yes_before, "replay must not move the tally");
        assert_eq!(p.no, 0);
        assert_eq!(
            l.locked_governance_of(&ids[0]),
            lock_before,
            "replay must not top up the staking lock"
        );
        // A different choice on the same proposal is refused (no flipping).
        assert_eq!(
            g.vote(&mut l, ids[0], id, VoteChoice::No, 1),
            Err(GovError::AlreadyVoted)
        );
        assert_eq!(
            g.proposals.get(&id).unwrap().yes,
            yes_before,
            "a refused flip must not move the tally either"
        );
    }

    /// Signed proposals: a valid envelope opens the proposal; wrong key,
    /// tampered bytes, wrong chain, and replayed nonces all fail closed.
    /// A valid signature from a STAKELESS key still lands on `NotStaker` —
    /// the binding is to the key whose stake is locked, never theater.
    #[test]
    fn propose_signed_binds_key_chain_action_and_nonce() {
        use crate::wallet_signing::WalletSigningKey;
        const CHAIN: u64 = 777;
        let key = WalletSigningKey::ed25519([0xA1u8; 32]);
        let addr = key.address();
        let other = WalletSigningKey::ed25519([0xB2u8; 32]);
        let mut l = StakingLedger::new();
        l.bond(addr, stell(10_000), DEFAULT_COMMISSION_BPS).unwrap();
        let mut g = Governance::new();
        let title = "raise reward".to_string();
        let action = GovAction::SetBlockReward(stell(9));
        let nonce = 7u64;
        // Valid envelope: opens the proposal and consumes the nonce.
        let msg = Governance::gov_propose_message(CHAIN, &addr, &title, &action, nonce);
        let sig = key.sign_message(CHAIN, &msg).unwrap();
        assert!(!g.propose_nonce_used(&addr, nonce));
        let id = g
            .propose_signed(&mut l, addr, title.clone(), action.clone(), 0, CHAIN, nonce, &sig)
            .unwrap();
        assert_eq!(id, 1);
        assert!(g.propose_nonce_used(&addr, nonce));
        // Exact replay: same envelope, nonce already consumed.
        assert_eq!(
            g.propose_signed(&mut l, addr, title.clone(), action.clone(), 0, CHAIN, nonce, &sig),
            Err(GovError::ReplayedNonce)
        );
        // Owner double-signs a different title under the same nonce: the
        // signature verifies (they own the key) but the nonce is spent.
        let msg2 = Governance::gov_propose_message(CHAIN, &addr, "other title", &action, nonce);
        let sig2 = key.sign_message(CHAIN, &msg2).unwrap();
        assert_eq!(
            g.propose_signed(
                &mut l,
                addr,
                "other title".into(),
                action.clone(),
                0,
                CHAIN,
                nonce,
                &sig2
            ),
            Err(GovError::ReplayedNonce)
        );
        // Wrong key: another key's envelope presented as this proposer.
        let wrong_msg = Governance::gov_propose_message(CHAIN, &addr, &title, &action, 8);
        let wrong = other.sign_message(CHAIN, &wrong_msg).unwrap();
        assert_eq!(
            g.propose_signed(&mut l, addr, title.clone(), action.clone(), 0, CHAIN, 8, &wrong),
            Err(GovError::BadSignature)
        );
        // Tampered title: sign one title, present for another.
        let tampered_msg = Governance::gov_propose_message(CHAIN, &addr, "tampered", &action, 9);
        let tampered_sig = key.sign_message(CHAIN, &tampered_msg).unwrap();
        assert_eq!(
            g.propose_signed(&mut l, addr, title.clone(), action.clone(), 0, CHAIN, 9, &tampered_sig),
            Err(GovError::BadSignature)
        );
        // Wrong chain: minted elsewhere, refused here.
        let cross_msg = Governance::gov_propose_message(CHAIN + 1, &addr, &title, &action, 10);
        let cross = key.sign_message(CHAIN + 1, &cross_msg).unwrap();
        assert_eq!(
            g.propose_signed(&mut l, addr, title.clone(), action.clone(), 0, CHAIN, 10, &cross),
            Err(GovError::BadSignature)
        );
        // Stakeless key with a PERFECTLY valid signature: NotStaker, not Open.
        let lone = WalletSigningKey::ed25519([0xC3u8; 32]);
        let lone_addr = lone.address();
        let lone_msg = Governance::gov_propose_message(CHAIN, &lone_addr, &title, &action, 1);
        let lone_sig = lone.sign_message(CHAIN, &lone_msg).unwrap();
        assert_eq!(
            g.propose_signed(&mut l, lone_addr, title, action, 0, CHAIN, 1, &lone_sig),
            Err(GovError::NotStaker)
        );
    }

    /// Signed votes: a valid envelope records the weight; tampered choice,
    /// wrong voter, and wrong chain fail closed; same-choice replay is
    /// idempotent; a stakeless signature lands on `NotStaker`.
    #[test]
    fn vote_signed_binds_key_chain_proposal_and_choice() {
        use crate::wallet_signing::WalletSigningKey;
        const CHAIN: u64 = 777;
        let voter_key = WalletSigningKey::ed25519([0xB2u8; 32]);
        let voter = voter_key.address();
        let proposer_key = WalletSigningKey::ed25519([0xA1u8; 32]);
        let proposer = proposer_key.address();
        let mut l = StakingLedger::new();
        l.bond(proposer, stell(10_000), DEFAULT_COMMISSION_BPS)
            .unwrap();
        l.bond(voter, stell(20_000), DEFAULT_COMMISSION_BPS).unwrap();
        let mut g = Governance::new();
        let id = g
            .propose(&mut l, proposer, "x".into(), GovAction::Signal("t".into()), 0)
            .unwrap();
        // Valid envelope records the weight.
        let msg = Governance::gov_vote_message(CHAIN, id, VoteChoice::Yes, &voter);
        let sig = voter_key.sign_message(CHAIN, &msg).unwrap();
        let w = g
            .vote_signed(&mut l, voter, id, VoteChoice::Yes, 1, CHAIN, &sig)
            .unwrap();
        assert_eq!(w, stell(20_000) as u128);
        // Same-choice replay: idempotent, tally unmoved.
        let w2 = g
            .vote_signed(&mut l, voter, id, VoteChoice::Yes, 1, CHAIN, &sig)
            .unwrap();
        assert_eq!(w, w2);
        assert_eq!(g.proposals.get(&id).unwrap().yes, w);
        // Different choice with a FRESH valid signature: refused, first wins.
        let flip_msg = Governance::gov_vote_message(CHAIN, id, VoteChoice::No, &voter);
        let flip = voter_key.sign_message(CHAIN, &flip_msg).unwrap();
        assert_eq!(
            g.vote_signed(&mut l, voter, id, VoteChoice::No, 1, CHAIN, &flip),
            Err(GovError::AlreadyVoted)
        );
        // Tampered choice: Yes-envelope presented as No.
        assert_eq!(
            g.vote_signed(&mut l, voter, id, VoteChoice::No, 1, CHAIN, &sig),
            Err(GovError::BadSignature)
        );
        // Wrong voter: proposer's envelope presented as the voter.
        let impostor_msg = Governance::gov_vote_message(CHAIN, id, VoteChoice::Yes, &voter);
        let impostor = proposer_key.sign_message(CHAIN, &impostor_msg).unwrap();
        assert_eq!(
            g.vote_signed(&mut l, voter, id, VoteChoice::Yes, 1, CHAIN, &impostor),
            Err(GovError::BadSignature)
        );
        // Wrong proposal id: envelope for another proposal.
        let elsewhere_msg = Governance::gov_vote_message(CHAIN, id + 100, VoteChoice::Yes, &voter);
        let elsewhere = voter_key.sign_message(CHAIN, &elsewhere_msg).unwrap();
        assert_eq!(
            g.vote_signed(&mut l, voter, id, VoteChoice::Yes, 1, CHAIN, &elsewhere),
            Err(GovError::BadSignature)
        );
        // Wrong chain.
        let cross_msg = Governance::gov_vote_message(CHAIN + 1, id, VoteChoice::Yes, &voter);
        let cross = voter_key.sign_message(CHAIN + 1, &cross_msg).unwrap();
        assert_eq!(
            g.vote_signed(&mut l, voter, id, VoteChoice::Yes, 1, CHAIN, &cross),
            Err(GovError::BadSignature)
        );
        // Stakeless key, valid signature: NotStaker (binding is not theater).
        let lone = WalletSigningKey::ed25519([0xC3u8; 32]);
        let lone_addr = lone.address();
        let lone_msg = Governance::gov_vote_message(CHAIN, id, VoteChoice::Yes, &lone_addr);
        let lone_sig = lone.sign_message(CHAIN, &lone_msg).unwrap();
        assert_eq!(
            g.vote_signed(&mut l, lone_addr, id, VoteChoice::Yes, 1, CHAIN, &lone_sig),
            Err(GovError::NotStaker)
        );
    }

    #[test]
    fn vote_weight_tracks_stake() {
        let mut l = StakingLedger::new();
        l.bond([1u8; 32], stell(10_000), DEFAULT_COMMISSION_BPS)
            .unwrap();
        l.bond([2u8; 32], stell(30_000), DEFAULT_COMMISSION_BPS)
            .unwrap();
        let mut g = Governance::new();
        let id = g
            .propose(&mut l, [1u8; 32], "x".into(), GovAction::Signal("t".into()), 0)
            .unwrap();
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
        let (mut l, ids) = ledger_with(1, 10_000);
        let mut g = Governance::new();
        // 150% slash is nonsense
        assert_eq!(
            g.propose(
                &mut l,
                ids[0],
                "bad".into(),
                GovAction::SetEquivocationSlashBps(15_000),
                0
            ),
            Err(GovError::InvalidAction)
        );
        // zero quorum is nonsense
        assert_eq!(
            g.propose(
                &mut l,
                ids[0],
                "bad".into(),
                GovAction::SetGovernanceQuorumBps(0),
                0
            ),
            Err(GovError::InvalidAction)
        );
    }

    #[test]
    fn anyone_can_execute_passed_proposal() {
        let (mut l, ids) = ledger_with(3, 10_000);
        let mut g = Governance::new();
        let id = g
            .propose(&mut l, ids[0], "x".into(), GovAction::Signal("t".into()), 0)
            .unwrap();
        g.vote(&mut l, ids[0], id, VoteChoice::Yes, 1).unwrap();
        g.vote(&mut l, ids[1], id, VoteChoice::Yes, 1).unwrap();
        g.finalize(&mut l, id, GOVERNANCE_VOTING_PERIOD_SECS + 1)
            .unwrap();
        // E5: no proposer-only gate — a non-proposer executes fine.
        assert!(g.execute(ids[1], id).is_ok());
        assert_eq!(g.get(id).unwrap().status, ProposalStatus::Executed);
    }

    #[test]
    fn quorum_floor_rejected_at_propose_time() {
        let (mut l, ids) = ledger_with(1, 10_000);
        let mut g = Governance::new();
        // 1 bps (0.01%) must be refused at propose time.
        assert_eq!(
            g.propose(
                &mut l,
                ids[0],
                "bad".into(),
                GovAction::SetGovernanceQuorumBps(1),
                0
            ),
            Err(GovError::InvalidAction)
        );
        // Just below the 3333 bps floor is also refused.
        assert_eq!(
            g.propose(
                &mut l,
                ids[0],
                "bad".into(),
                GovAction::SetGovernanceQuorumBps(GOVERNANCE_QUORUM_FLOOR_BPS - 1),
                0
            ),
            Err(GovError::InvalidAction)
        );
        // The floor error message must name the floor.
        let err = g
            .propose(
                &mut l,
                ids[0],
                "bad".into(),
                GovAction::SetGovernanceQuorumBps(1),
                0,
            )
            .unwrap_err();
        assert!(
            format!("{err}").contains("3333"),
            "quorum-floor error must name the 3333 bps floor, got: {err}"
        );
        // The floor itself is accepted.
        assert!(g
            .propose(
                &mut l,
                ids[0],
                "ok".into(),
                GovAction::SetGovernanceQuorumBps(GOVERNANCE_QUORUM_FLOOR_BPS),
                0
            )
            .is_ok());
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
                electorate_weights: None,
                proposer_lock: 0,
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
            .propose(
                &mut l,
                ids[0],
                "q".into(),
                GovAction::SetGovernanceQuorumBps(5_000),
                0,
            )
            .unwrap();
        g.vote(&mut l, ids[0], id, VoteChoice::Yes, 1).unwrap();
        g.vote(&mut l, ids[1], id, VoteChoice::Yes, 1).unwrap();
        g.finalize(&mut l, id, GOVERNANCE_VOTING_PERIOD_SECS + 1)
            .unwrap();
        // Non-proposer executes a passed quorum change.
        g.execute(ids[2], id).unwrap();
        assert_eq!(g.quorum_bps, 5_000);
    }

    #[test]
    fn quorum_action_applies() {
        let (mut l, ids) = ledger_with(3, 10_000);
        let mut g = Governance::new();
        let id = g
            .propose(
                &mut l,
                ids[0],
                "q".into(),
                GovAction::SetGovernanceQuorumBps(5_000),
                0,
            )
            .unwrap();
        g.vote(&mut l, ids[0], id, VoteChoice::Yes, 1).unwrap();
        g.vote(&mut l, ids[1], id, VoteChoice::Yes, 1).unwrap();
        g.finalize(&mut l, id, GOVERNANCE_VOTING_PERIOD_SECS + 1)
            .unwrap();
        g.execute(ids[0], id).unwrap();
        assert_eq!(g.quorum_bps, 5_000);
    }

    #[test]
    fn vote_weight_does_not_double_count_delegated_stake() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(10_000), DEFAULT_COMMISSION_BPS)
            .unwrap();
        l.delegate(del(2), vid(1), stell(5_000)).unwrap();
        let mut g = Governance::new();
        let id = g
            .propose(&mut l, vid(1), "x".into(), GovAction::Signal("t".into()), 0)
            .unwrap();
        // The validator owns its 10k self-bond; the 5k delegated by del(2) is
        // del(2)'s stake, NOT the validator's. Vote weight must be exactly 10k.
        let w = g.vote(&mut l, vid(1), id, VoteChoice::Yes, 1).unwrap();
        assert_eq!(
            w,
            stell(10_000) as u128,
            "delegated-in stake must not double count"
        );
    }

    #[test]
    fn self_delegation_does_not_inflate_vote() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(10_000), DEFAULT_COMMISSION_BPS)
            .unwrap();
        l.delegate(vid(1), vid(1), stell(5_000)).unwrap();
        let mut g = Governance::new();
        let id = g
            .propose(&mut l, vid(1), "x".into(), GovAction::Signal("t".into()), 0)
            .unwrap();
        // self-bond 10k + own delegation out 5k = 15k (counted once each)
        let w = g.vote(&mut l, vid(1), id, VoteChoice::Yes, 1).unwrap();
        assert_eq!(
            w,
            stell(15_000) as u128,
            "self-delegation must not be counted twice"
        );
    }

    #[test]
    fn delegator_votes_with_own_stake_only_once() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(10_000), DEFAULT_COMMISSION_BPS)
            .unwrap();
        l.bond(vid(2), stell(10_000), DEFAULT_COMMISSION_BPS)
            .unwrap();
        l.delegate(vid(1), vid(2), stell(5_000)).unwrap(); // vid1 delegates 5k to vid2
        let mut g = Governance::new();
        let id = g
            .propose(&mut l, vid(1), "x".into(), GovAction::Signal("t".into()), 0)
            .unwrap();
        // vid1's own stake is 10k (self) + 5k (delegated out); it must NOT also
        // gain the 5k as if it were still consensus power on vid1.
        let w = g.vote(&mut l, vid(1), id, VoteChoice::Yes, 1).unwrap();
        assert_eq!(w, stell(15_000) as u128);
    }

    #[test]
    fn finalize_denominator_matches_total_voting_power() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(10_000), DEFAULT_COMMISSION_BPS)
            .unwrap();
        l.delegate(del(1), vid(1), stell(9_000)).unwrap();
        // total voting power = self 10k + delegated 9k = 19k
        assert_eq!(Governance::total_voting_power(&l), stell(19_000) as u128);
        let mut g = Governance::new();
        let id = g
            .propose(&mut l, vid(1), "x".into(), GovAction::Signal("t".into()), 0)
            .unwrap();
        g.vote(&mut l, vid(1), id, VoteChoice::Yes, 1).unwrap(); // 10k
        g.vote(&mut l, del(1), id, VoteChoice::Yes, 1).unwrap(); // 9k
        let p = g.get(id).unwrap();
        // turnout (19k) must not exceed the quorum base (19k)
        assert!(p.turnout() <= Governance::total_voting_power(&l));
        let status = g
            .finalize(&mut l, id, GOVERNANCE_VOTING_PERIOD_SECS + 1)
            .unwrap();
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
        l.bond(vid(1), stell(10_000), DEFAULT_COMMISSION_BPS)
            .unwrap();
        l.bond(vid(2), stell(10_000), DEFAULT_COMMISSION_BPS)
            .unwrap();
        l.delegate(del(1), vid(1), stell(9_000)).unwrap();
        assert_eq!(Governance::total_voting_power(&l), stell(29_000) as u128);
        let mut g = Governance::new();
        let id = g
            .propose(&mut l, vid(1), "x".into(), GovAction::Signal("t".into()), 0)
            .unwrap();
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
        let status = g
            .finalize(&mut l, id, GOVERNANCE_VOTING_PERIOD_SECS + 1)
            .unwrap();
        assert_eq!(
            status,
            ProposalStatus::Rejected,
            "E7: 19k < 19,331 quorum on the 29k propose-time base"
        );
        // The terminal transition releases the locks: the exit works now.
        assert_eq!(l.locked_governance_of(&del(1)), 0);
        l.undelegate(del(1), vid(1), stell(9_000), 3).unwrap();
    }

    #[test]
    fn validate_bounds_min_validator_bond_and_block_reward() {
        // Below MIN_VALIDATOR_BOND: invalid
        assert_eq!(
            GovAction::SetMinValidatorBond(crate::staking::MIN_VALIDATOR_BOND - 1).validate(),
            Err(GovError::InvalidAction)
        );
        // Above MAX_VALIDATOR_BOND: invalid
        assert_eq!(
            GovAction::SetMinValidatorBond(MAX_VALIDATOR_BOND + 1).validate(),
            Err(GovError::InvalidAction)
        );
        // Valid MIN_VALIDATOR_BOND
        assert!(
            GovAction::SetMinValidatorBond(crate::staking::MIN_VALIDATOR_BOND)
                .validate()
                .is_ok()
        );
        assert!(GovAction::SetMinValidatorBond(MAX_VALIDATOR_BOND)
            .validate()
            .is_ok());

        // Above MAX_BLOCK_REWARD_NANO: invalid
        assert_eq!(
            GovAction::SetBlockReward(MAX_BLOCK_REWARD_NANO + 1).validate(),
            Err(GovError::InvalidAction)
        );
        // Valid BlockReward
        assert!(GovAction::SetBlockReward(MAX_BLOCK_REWARD_NANO)
            .validate()
            .is_ok());
        assert!(GovAction::SetBlockReward(0).validate().is_ok());
    }

    #[test]
    fn finalize_requires_positive_non_abstaining_turnout() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(10_000), DEFAULT_COMMISSION_BPS)
            .unwrap();
        let mut g = Governance::new();
        let id = g
            .propose(
                &mut l,
                vid(1),
                "abstain only".into(),
                GovAction::Signal("s".into()),
                0,
            )
            .unwrap();

        // Only abstain vote: turnout meets quorum (100%), but yes == 0, no == 0
        g.vote(&mut l, vid(1), id, VoteChoice::Abstain, 1).unwrap();
        let status = g
            .finalize(&mut l, id, GOVERNANCE_VOTING_PERIOD_SECS + 1)
            .unwrap();
        assert_eq!(status, ProposalStatus::Rejected);
    }

    #[test]
    fn validate_software_upgrade_rejects_zero_sha256() {
        let action_zero_sha = GovAction::SoftwareUpgrade {
            name: "v1.0.0".into(),
            height: 100,
            sha256: [0u8; 32],
        };
        assert_eq!(action_zero_sha.validate(), Err(GovError::InvalidAction));

        let action_empty_name = GovAction::SoftwareUpgrade {
            name: "".into(),
            height: 100,
            sha256: [1u8; 32],
        };
        assert_eq!(action_empty_name.validate(), Err(GovError::InvalidAction));

        let action_zero_height = GovAction::SoftwareUpgrade {
            name: "v1.0.0".into(),
            height: 0,
            sha256: [1u8; 32],
        };
        assert_eq!(action_zero_height.validate(), Err(GovError::InvalidAction));

        let action_valid = GovAction::SoftwareUpgrade {
            name: "v1.0.0".into(),
            height: 100,
            sha256: [1u8; 32],
        };
        assert!(action_valid.validate().is_ok());
    }

    // -----------------------------------------------------------------------
    // UPGRADE PATH SAFETY (audit W6.7)
    // -----------------------------------------------------------------------

    /// The upgrade plan's NAME is used to build the path of the new binary.
    /// A name carrying a path separator (or a `..`) resolves OUTSIDE the
    /// operator's `data/upgrades/` directory — a path traversal that lets a
    /// governance proposal point the exec at an arbitrary path on the box.
    #[test]
    fn upgrade_name_rejects_path_traversal() {
        for bad in [
            "../evil",
            "../../../../tmp/evil",
            "a/b",
            "a\\b",
            "..",
            ".",
            ".hidden",
            "",
            "name with space",
            "name\0nul",
            "naïve",
        ] {
            assert!(
                !upgrade_name_is_safe(bad),
                "the upgrade name {bad:?} must be refused"
            );
            let action = GovAction::SoftwareUpgrade {
                name: bad.to_string(),
                height: 100,
                sha256: [1u8; 32],
            };
            assert_eq!(
                action.validate(),
                Err(GovError::InvalidAction),
                "the upgrade action {bad:?} must be refused at propose time"
            );
        }
        for good in ["v1.0.0", "v0.2.0-rc1", "release_2026_10_20", "hotfix1"] {
            assert!(
                upgrade_name_is_safe(good),
                "the upgrade name {good:?} must be accepted"
            );
            let action = GovAction::SoftwareUpgrade {
                name: good.to_string(),
                height: 100,
                sha256: [1u8; 32],
            };
            assert!(
                action.validate().is_ok(),
                "{good:?} must be a legal upgrade name"
            );
        }
    }

    /// A traversal name never resolves to a candidate path: the candidate
    /// list is EMPTY, so the exec site has nothing to run.
    #[test]
    fn upgrade_candidates_are_empty_for_an_unsafe_name() {
        let plan = UpgradePlan {
            name: "../../../../tmp/evil".into(),
            height: 100,
            sha256: [1u8; 32],
        };
        assert!(
            upgrade_candidate_paths(&plan).is_empty(),
            "an unsafe name must resolve to NO candidate path"
        );
        let ok = UpgradePlan {
            name: "v1.0.0".into(),
            height: 100,
            sha256: [1u8; 32],
        };
        let paths = upgrade_candidate_paths(&ok);
        assert_eq!(paths.len(), 3);
        assert!(paths[0].to_string_lossy().contains("data/upgrades/v1.0.0/"));
    }

    /// The EXECUTE-time backstop mirrors the propose-time rule: a plan whose
    /// name smuggled a traversal in (a deserialized history, a direct state
    /// write) fails closed and stays `Passed`.
    #[test]
    fn execute_refuses_an_unsafe_upgrade_name() {
        let mut g = Governance::new();
        let l = ledger_with(3, 2_000).0;
        let proposer = [0x11u8; 32];
        let now = 1_000u64;
        // Smuggle the bad name PAST propose (direct state write, exactly the
        // "deserialized history" case the backstop exists for).
        let pid = g.next_id;
        g.next_id += 1;
        let electorate = Governance::total_voting_power(&l);
        g.proposals.insert(
            pid,
            Proposal {
                id: pid,
                proposer,
                title: "t".into(),
                action: GovAction::SoftwareUpgrade {
                    name: "../../../../tmp/evil".into(),
                    height: 100,
                    sha256: [7u8; 32],
                },
                created_at: now,
                voting_end: now.saturating_add(GOVERNANCE_VOTING_PERIOD_SECS),
                yes: 0,
                no: 0,
                abstain: 0,
                voters: HashMap::new(),
                status: ProposalStatus::Passed,
                electorate,
                electorate_weights: None,
                proposer_lock: 0,
                weights: HashMap::new(),
            },
        );
        assert!(
            g.execute([0u8; 32], pid).is_err(),
            "the execute backstop must refuse an unsafe upgrade name"
        );
        assert!(
            g.applied.upgrade_plan.is_none(),
            "a refused upgrade must not install a plan"
        );
        assert_eq!(
            g.get(pid).map(|p| p.status),
            Some(ProposalStatus::Passed),
            "the proposal must stay Passed so it can be retried/failed closed"
        );
    }

    /// The staging helper refuses a SYMLINKED candidate: the "candidate under
    /// the operator's upgrade directory" must not be a pointer to an
    /// arbitrary path.
    #[test]
    fn staging_refuses_a_symlinked_candidate() {
        let dir = std::env::temp_dir().join(format!(
            "stell_upgrade_symlink_test_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let real = dir.join("real.bin");
        std::fs::write(&real, b"not really a binary").unwrap();
        let link = dir.join("link.bin");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, &link).unwrap();
        #[cfg(not(unix))]
        std::fs::write(&link, b"not really a binary").unwrap();

        let expected: [u8; 32];
        {
            use sha2::{Digest, Sha256};
            expected = Sha256::digest(b"not really a binary").into();
        }
        let err = stage_verified_upgrade_binary(&link, &expected)
            .expect_err("a symlinked candidate must be refused");
        assert!(
            err.contains("SYMLINK") || err.contains("not a regular file"),
            "the error must name the symlink: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The staging helper returns a copy of the VERIFIED BYTES: the staged
    /// file is what must be executed, so a swap of the candidate after the
    /// check cannot change what runs.
    #[test]
    fn staging_copies_the_verified_bytes_and_refuses_a_mismatch() {
        let dir = std::env::temp_dir().join(format!(
            "stell_upgrade_stage_test_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cand = dir.join("stellereum");
        let payload = b"#!/bin/sh\necho upgraded\n";
        std::fs::write(&cand, payload).unwrap();

        let expected: [u8; 32];
        {
            use sha2::{Digest, Sha256};
            expected = Sha256::digest(payload).into();
        }
        // A mismatch is refused.
        let err = stage_verified_upgrade_binary(&cand, &[0u8; 32])
            .expect_err("the all-zero digest must be refused");
        assert!(
            err.contains("mismatch"),
            "the error must name the mismatch: {err}"
        );
        let mut wrong = expected;
        wrong[0] ^= 0xff;
        let err = stage_verified_upgrade_binary(&cand, &wrong).expect_err("must refuse");
        assert!(
            err.contains("mismatch"),
            "the error must name the mismatch: {err}"
        );

        // The right digest stages a byte-identical copy.
        let staged = stage_verified_upgrade_binary(&cand, &expected).expect("stage");
        assert_eq!(std::fs::read(&staged).unwrap(), payload);
        assert_ne!(staged, cand, "the staged copy must be a DIFFERENT file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::symlink_metadata(&staged)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700, "the staged binary must be owner-only");
        }
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&staged);
    }

    // -----------------------------------------------------------------------
    // LIVE MIGRATION ARMING (audit W8.3 / production blocker A8)
    // -----------------------------------------------------------------------

    /// The live migration is OFF unless the operator explicitly arms it.
    ///
    /// The old default was "armed unless told otherwise", so an on-chain
    /// governance proposal alone was enough to make the node `execve` a new
    /// binary. This is the production blocker the audit listed as A8, and
    /// the arming is now a node-local, operator-local decision.
    #[test]
    fn live_migration_is_disarmed_unless_explicitly_armed() {
        // Unset: NOT armed. This is the default that matters.
        assert!(
            !auto_upgrade_armed_from(None),
            "an unset {} must leave the live migration DISARMED",
            AUTO_UPGRADE_ENV
        );
        // The two literal arming spellings.
        assert!(auto_upgrade_armed_from(Some("1")));
        assert!(auto_upgrade_armed_from(Some("true")));
        assert!(auto_upgrade_armed_from(Some("TRUE")));
        assert!(auto_upgrade_armed_from(Some("True")));
        assert!(
            auto_upgrade_armed_from(Some(" 1 ")),
            "surrounding space is ignored"
        );
        // Everything else fails SAFE.
        for off in [
            "0", "false", "FALSE", "", " ", "yes", "on", "2", "armed", "tru",
        ] {
            assert!(
                !auto_upgrade_armed_from(Some(off)),
                "{off:?} must NOT arm the live migration"
            );
        }
    }

    /// The operator-facing state line always says WHICH state the node is in
    /// and never leaks anything else.
    #[test]
    fn live_migration_state_line_names_the_switch() {
        let line = auto_upgrade_state_line();
        assert!(
            line.contains(AUTO_UPGRADE_ENV),
            "the line must name the switch: {line}"
        );
        assert!(
            line.contains("DISARMED") || line.contains("ARMED"),
            "the line must state the state: {line}"
        );
    }

    /// A SYMLINKED PARENT directory is refused: the candidate file itself is
    /// checked for being a link, but its parent was not, so a linked parent
    /// turned "the candidate under the operator's upgrade directory" into
    /// "a file somewhere else on the box".
    #[cfg(unix)]
    #[test]
    fn staging_refuses_a_symlinked_parent_directory() {
        let base = std::env::temp_dir().join(format!(
            "stell_upgrade_symparent_test_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let real_dir = base.join("real_dir");
        std::fs::create_dir_all(&real_dir).unwrap();
        let payload = b"#!/bin/sh\necho upgraded\n";
        std::fs::write(real_dir.join("stellereum"), payload).unwrap();

        // The candidate's parent is a SYMLINK to a real directory.
        let link_dir = base.join("link_dir");
        std::os::unix::fs::symlink(&real_dir, &link_dir).unwrap();
        let cand = link_dir.join("stellereum");

        let expected: [u8; 32];
        {
            use sha2::{Digest, Sha256};
            expected = Sha256::digest(payload).into();
        }
        let err = stage_verified_upgrade_binary(&cand, &expected)
            .expect_err("a symlinked parent directory must be refused");
        assert!(
            err.contains("SYMLINK"),
            "the error must name the symlinked parent: {err}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The staging helper still works when the parent is a REAL directory:
    /// the symlinked-parent refusal must not break the ordinary path.
    #[test]
    fn staging_accepts_a_candidate_under_a_real_directory() {
        let dir = std::env::temp_dir().join(format!(
            "stell_upgrade_realparent_test_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let payload = b"#!/bin/sh\necho upgraded\n";
        let cand = dir.join("stellereum");
        std::fs::write(&cand, payload).unwrap();
        let expected: [u8; 32];
        {
            use sha2::{Digest, Sha256};
            expected = Sha256::digest(payload).into();
        }
        let staged = stage_verified_upgrade_binary(&cand, &expected)
            .expect("a candidate under a real directory must stage");
        assert_eq!(std::fs::read(&staged).unwrap(), payload);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&staged);
    }

    // -----------------------------------------------------------------------
    // KI-23 TIMELOCK (voted proposals execute at pass_height + delay)
    // -----------------------------------------------------------------------

    /// Drive a proposal to Passed via the height-aware finalize (100% yes).
    fn pass_at_height(
        l: &mut StakingLedger,
        g: &mut Governance,
        proposer: [u8; 32],
        voters: &[[u8; 32]],
        action: GovAction,
        pass_height: u64,
    ) -> u64 {
        let id = g
            .propose(l, proposer, "t".into(), action, 0)
            .expect("propose");
        for v in voters {
            g.vote(l, *v, id, VoteChoice::Yes, 1).expect("vote");
        }
        let status = g
            .finalize_at_height(l, id, GOVERNANCE_VOTING_PERIOD_SECS + 1, pass_height)
            .expect("finalize");
        assert_eq!(status, ProposalStatus::Passed);
        id
    }

    #[test]
    fn timelock_const_is_7200_heights_no_env() {
        // Pinned: same exit-window philosophy as the commission delay.
        assert_eq!(GOV_TIMELOCK_HEIGHTS, 7_200);
        assert_eq!(
            crate::staking::COMMISSION_EFFECT_DELAY_HEIGHTS,
            7_200,
            "timelock mirrors the commission exit window"
        );
    }

    #[test]
    fn timelock_schedule_sets_maturity() {
        let (mut l, ids) = ledger_with(3, 10_000);
        let mut g = Governance::new();
        let pass_height = 1_000_000u64;
        let id = pass_at_height(
            &mut l,
            &mut g,
            ids[0],
            &ids,
            GovAction::Signal("t".into()),
            pass_height,
        );
        assert_eq!(
            g.executable_height_of(id),
            Some(pass_height.saturating_add(GOV_TIMELOCK_HEIGHTS))
        );
        assert_eq!(g.get(id).unwrap().status, ProposalStatus::Passed);
    }

    #[test]
    fn timelock_early_execution_refused_fail_closed() {
        let (mut l, ids) = ledger_with(3, 10_000);
        let mut g = Governance::new();
        let pass_height = 50_000u64;
        let id = pass_at_height(
            &mut l,
            &mut g,
            ids[0],
            &ids,
            GovAction::SetBlockReward(stell(9)),
            pass_height,
        );
        let maturity = pass_height + GOV_TIMELOCK_HEIGHTS;
        // Legacy path (no height) refuses a scheduled proposal fail-closed.
        assert_eq!(g.execute(ids[0], id), Err(GovError::Timelocked));
        // Height-aware path before maturity refuses too.
        assert_eq!(
            g.execute_at_height(ids[0], id, maturity - 1),
            Err(GovError::Timelocked)
        );
        assert_eq!(g.get(id).unwrap().status, ProposalStatus::Passed);
        assert!(g.applied.block_reward.is_none());
        // Retry is identically refused (no partial state).
        assert_eq!(
            g.execute_at_height(ids[0], id, maturity - 1),
            Err(GovError::Timelocked)
        );
    }

    #[test]
    fn timelock_matured_executes_exactly_once() {
        let (mut l, ids) = ledger_with(3, 10_000);
        let mut g = Governance::new();
        let pass_height = 77_000u64;
        let id = pass_at_height(
            &mut l,
            &mut g,
            ids[0],
            &ids,
            GovAction::SetBlockReward(stell(9)),
            pass_height,
        );
        let maturity = pass_height + GOV_TIMELOCK_HEIGHTS;
        g.execute_at_height(ids[1], id, maturity)
            .expect("matured must execute");
        assert_eq!(g.get(id).unwrap().status, ProposalStatus::Executed);
        assert_eq!(g.applied.block_reward, Some(stell(9)));
        assert_eq!(
            g.execute_at_height(ids[1], id, maturity + 1),
            Err(GovError::AlreadyExecuted)
        );
    }

    #[test]
    fn timelock_exact_boundary_maturity_minus_one_refuses_maturity_executes() {
        let (mut l, ids) = ledger_with(3, 10_000);
        let mut g = Governance::new();
        let pass_height = 123_456u64;
        let id = pass_at_height(
            &mut l,
            &mut g,
            ids[0],
            &ids,
            GovAction::Signal("b".into()),
            pass_height,
        );
        let maturity = pass_height + GOV_TIMELOCK_HEIGHTS;
        assert!(!g.is_mature(id, maturity - 1));
        assert!(g.is_mature(id, maturity));
        assert_eq!(
            g.execute_at_height(ids[0], id, maturity - 1),
            Err(GovError::Timelocked)
        );
        g.execute_at_height(ids[0], id, maturity)
            .expect("maturity executes");
        assert_eq!(g.get(id).unwrap().status, ProposalStatus::Executed);
    }

    #[test]
    fn timelock_query_surfaces_pending_and_executable_height() {
        let (mut l, ids) = ledger_with(3, 10_000);
        let mut g = Governance::new();
        let pass_height = 9_000u64;
        let id = pass_at_height(
            &mut l,
            &mut g,
            ids[0],
            &ids,
            GovAction::Signal("q".into()),
            pass_height,
        );
        // Pending: Passed (not Executed) + scheduled executable height.
        assert_eq!(g.get(id).unwrap().status, ProposalStatus::Passed);
        assert_eq!(
            g.executable_height_of(id),
            Some(pass_height + GOV_TIMELOCK_HEIGHTS)
        );
        assert!(!g.is_mature(id, pass_height));
        assert!(g.is_mature(id, pass_height + GOV_TIMELOCK_HEIGHTS));
        // Unknown proposal: no schedule, never mature.
        assert_eq!(g.executable_height_of(999_999), None);
        assert!(!g.is_mature(999_999, u64::MAX));
    }

    #[test]
    fn timelock_oracle_path_enforces_maturity() {
        let (mut l, ids) = ledger_with(3, 10_000);
        let mut g = Governance::new();
        let pass_height = 5_000u64;
        let id = pass_at_height(
            &mut l,
            &mut g,
            ids[0],
            &ids,
            GovAction::RegisterOraclePublisher([0x31u8; 32]),
            pass_height,
        );
        let maturity = pass_height + GOV_TIMELOCK_HEIGHTS;
        let mut oracle = crate::oracle::OracleState::default();
        // Legacy oracle path (no height) refuses a scheduled proposal.
        assert_eq!(
            g.execute_with_oracle(ids[0], id, &mut oracle),
            Err(GovError::Timelocked)
        );
        assert!(oracle.publishers.is_empty());
        // Height-aware path before maturity refuses too.
        assert_eq!(
            g.execute_with_oracle_at_height(ids[1], id, &mut oracle, maturity - 1),
            Err(GovError::Timelocked)
        );
        assert!(oracle.publishers.is_empty());
        // At maturity applies exactly once (both domains).
        g.execute_with_oracle_at_height(ids[1], id, &mut oracle, maturity)
            .expect("matured oracle action must apply");
        assert!(oracle.publishers.contains(&[0x31u8; 32]));
        assert_eq!(g.get(id).unwrap().status, ProposalStatus::Executed);
    }

    /// C-02/P0: height-aware finalization releases EVERY staking lock
    /// (proposer + all voters) exactly once, schedules the exact 7200-height
    /// maturity, and refuses early execution fail-closed.
    /// // GATE: proves the live-path `finalize_at_height` contract — locks
    /// cannot outlive the vote; extends, never weakens.
    #[test]
    fn finalize_at_height_releases_all_locks_with_exact_maturity() {
        let (mut l, ids) = ledger_with(3, 10_000);
        let mut g = Governance::new();
        let now_due = GOVERNANCE_VOTING_PERIOD_SECS + 1;
        let id = g
            .propose(&mut l, ids[0], "t".into(), GovAction::Signal("t".into()), 0)
            .expect("propose");
        for v in &ids {
            g.vote(&mut l, *v, id, VoteChoice::Yes, 1).expect("vote");
        }
        // Locks are held for the whole voting window (the C-02 grief when
        // finalization never runs: unbond stays impossible).
        for v in &ids {
            assert!(
                l.locked_governance_of(v) > 0,
                "voter lock must be held before finalize"
            );
        }
        let pass_height = 7_000u64;
        let status = g
            .finalize_at_height(&mut l, id, now_due, pass_height)
            .expect("finalize");
        assert_eq!(status, ProposalStatus::Passed);
        assert!(
            l.locked_governance.is_empty(),
            "finalize must release every gov lock exactly once"
        );
        // Exact maturity: pass_height + 7200, boundary-checked both sides.
        let maturity = pass_height + GOV_TIMELOCK_HEIGHTS;
        assert_eq!(maturity, 14_200);
        assert_eq!(g.executable_height_of(id), Some(maturity));
        assert_eq!(
            g.execute_at_height(ids[0], id, maturity - 1),
            Err(GovError::Timelocked)
        );
        assert_eq!(g.get(id).unwrap().status, ProposalStatus::Passed);
        g.execute_at_height(ids[0], id, maturity)
            .expect("maturity executes");
        assert_eq!(g.get(id).unwrap().status, ProposalStatus::Executed);
    }
}
