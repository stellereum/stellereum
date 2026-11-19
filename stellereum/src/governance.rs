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
use std::collections::BTreeMap;
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
///
/// HEIGHT-TEMPO NOTE (LOGIC_BUG_SWEEP §7.1): at the live ~240 ms tempo this
/// is ~28.8 minutes, not the ~6 h the design assumed at 3 s blocks. The
/// timelock still enforces a real delay, so it is not unsafe in the same way
/// as the downtime threshold, but a longer reaction window is desirable. A
/// retune is a consensus change and must ship behind an activation height, so
/// it is deliberately deferred here (see `docs/LOGIC_BUG_SWEEP.md` §7.1).
/// Six hours at the 240 ms target tempo (`90_000 x 240 ms`). Ruleset v2
/// re-scaled this from the 7_200-height value that meant six hours at the old
/// ~3 s block time; the wall-clock intent, not the height count, is the
/// invariant.
pub const GOV_TIMELOCK_HEIGHTS: u64 = 90_000;

/// COMPILED DEFAULT for the DETERMINISTIC upgrade-execution gate.
///
/// The EFFECTIVE value lives in the genesis chain spec
/// ([`crate::chain_spec::GenesisChainSpec::upgrade_exec_activation_height`]);
/// this constant is only the fallback for a chain whose genesis spec does not
/// set one. Leaving it at `u64::MAX` keeps every existing chain and test
/// byte-identical: the sweep is inert at every reachable height.
///
/// Why a separate gate: the sweep is consensus-affecting (it flips a matured,
/// voted `SoftwareUpgrade` to `Executed` and installs `AppliedParams::upgrade_plan`,
/// which is committed in the state root). Every node applying the same block
/// must reach the same verdict, so the value is fixed at genesis — never an
/// env knob (an env knob is a per-node fork window; see
/// `docs/UPGRADE_AND_RECOVERY.md` §1.1/§1.2).
pub const UPGRADE_EXEC_ACTIVATION_HEIGHT: u64 = u64::MAX;

/// TEST-ONLY override of the genesis chain spec's upgrade-execution gate for
/// the CALLING THREAD. Delegates to
/// [`crate::chain_spec::set_upgrade_exec_activation_override`] so tests keep
/// the existing narrow entry point while the chain spec remains the single
/// source of truth. Release builds have no override.
#[cfg(any(test, debug_assertions))]
pub fn set_upgrade_exec_activation_override(activation: Option<u64>) {
    crate::chain_spec::set_upgrade_exec_activation_override(activation);
}

/// The upgrade-execution activation height in force: the genesis chain spec's
/// value (compiled default `u64::MAX` for chains that do not set it). This is
/// a thin, read-only delegate; the chain spec owns the value.
pub fn upgrade_exec_activation_height() -> u64 {
    crate::chain_spec::upgrade_exec_activation_height()
}

/// True once the deterministic upgrade-execution gate is open at `height`.
///
/// `>=` is the activation semantic every other gate uses (the first block at
/// the genesis-spec height runs the sweep; pre-activation blocks are
/// untouched). Every execution path (deterministic sweep, direct RPC,
/// legacy `execute`, oracle variant) funnels through this predicate.
pub fn upgrade_exec_active_at(height: u64) -> bool {
    crate::chain_spec::upgrade_exec_active_at(height)
}

/// Activation height for BLOCK-CARRIED governance: the propose/vote opcode
/// scan (`InMemoryStateEngine::apply_gov_ops`) and the deterministic
/// finalize+execute sweep (`InMemoryStateEngine::apply_governance_transition`).
///
/// CHOICE: `0` — active from genesis. Rationale:
///  * this repository has no deployed mainnet to migrate (the chain is new:
///    the governance executor and the block carrier are both being switched
///    on before launch), so there is no historical block whose verdict would
///    change retroactively;
///  * block-carried governance is the ONLY way a multi-validator network can
///    change a parameter: the direct RPC form is refused on N>1 by design
///    (it would fork), so leaving this inert would leave every real network
///    with static parameters forever;
///  * `0` is a plain compile-time constant, identical on every node, so every
///    node applying the same block reaches the same verdict. It is NEVER an
///    env knob (an env knob is a per-node fork window).
///
/// The gate covers proposals, votes, deterministic finalization and the
/// execution of every `GovAction`. `SoftwareUpgrade` installs a plan only when
/// the separate [`upgrade_exec_active_at`] chain-spec gate is also open: a
/// binary rollout is a heavier, separately ratified decision and must never
/// ride in on a parameter-change activation. `CancelUpgrade` is deliberately
/// ungated — it can only clear a plan, so it must remain available as a safety
/// valve before and after that gate opens.
///
/// Tests can force a closed gate per thread through
/// [`set_gov_ops_activation_override`] (debug builds only, the
/// `QC_SPLIT_ACTIVATION_HEIGHT` pattern). Release builds have no override.
pub const GOV_OPS_ACTIVATION_HEIGHT: u64 = 0;

// TEST-ONLY override of the block-carried governance activation height,
// scoped to the CALLING THREAD (same pattern as
// `UPGRADE_EXEC_ACTIVATION_OVERRIDE` above). The frozen constant stays `0`;
// an override exists so tests can still pin the pre-activation no-op without
// changing process-wide state while other tests run in parallel.
#[cfg(any(test, debug_assertions))]
thread_local! {
    static GOV_OPS_ACTIVATION_OVERRIDE: std::cell::Cell<Option<u64>> =
        const { std::cell::Cell::new(None) };
}

/// Set (or clear with `None`) the TEST-ONLY block-carried governance
/// activation height for the CALLING THREAD. Available in test/debug builds
/// only; release builds always use [`GOV_OPS_ACTIVATION_HEIGHT`].
#[cfg(any(test, debug_assertions))]
pub fn set_gov_ops_activation_override(activation: Option<u64>) {
    GOV_OPS_ACTIVATION_OVERRIDE.with(|c| c.set(activation));
}

/// The block-carried governance activation height in force for the calling
/// thread: the frozen [`GOV_OPS_ACTIVATION_HEIGHT`] unless a test/debug
/// caller installed [`set_gov_ops_activation_override`].
pub fn gov_ops_activation_height() -> u64 {
    #[cfg(any(test, debug_assertions))]
    if let Some(activation) = GOV_OPS_ACTIVATION_OVERRIDE.with(|c| c.get()) {
        return activation;
    }
    GOV_OPS_ACTIVATION_HEIGHT
}

/// True once block-carried governance is active at `height` (`>=` semantic:
/// the first block at the ratified height applies).
pub fn gov_ops_active_at(height: u64) -> bool {
    height >= gov_ops_activation_height()
}

/// The executor identity the deterministic sweep passes to
/// [`Governance::execute_at_height`].
///
/// Execution is deliberately ANYONE-can-execute (there is no proposer-only
/// rule, so a lost/rotated proposer key cannot brick a passed proposal). The
/// value is a fixed constant rather than a caller-chosen address so the
/// result is a pure function of committed state + block height: all zeroes is
/// the canonical "system" identity.
pub const UPGRADE_EXECUTOR: [u8; 32] = [0u8; 32];

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
    /// Governance write refused on a multi-node deployment. A local-only
    /// `propose`/`vote` would diverge this node's state root from peers that
    /// never saw it, so the write is refused fail-closed unless the operator
    /// explicitly arms [`GOV_MULTINODE_WRITES_ENV`] (default OFF). Carries
    /// the loud refusal text (validator set size + escape name) so every
    /// surface (RPC, runtime) reports the same reason. The deterministic
    /// finalize sweep never returns this (it derives from decided blocks,
    /// identically on every node).
    MultiNodeRefused(String),
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
            // Multi-node refusal carries its own text (validator set size +
            // escape env name), so every surface reports the same loud reason.
            GovError::MultiNodeRefused(msg) => msg.as_str(),
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
///
/// `name` is the TARGET VERSION label of the build the plan authorises (the
/// same string that names the staging directory `data/upgrades/<name>/`);
/// `height` is the coordinated halt height; `sha256` is the SHA-256 of the
/// target binary. The schema is frozen on purpose: it is embedded in
/// bincode-serialised `AppliedParams`, so adding a field here would make every
/// existing data directory undecodable (a hard fork). The plan's chain binding
/// is therefore NOT a stored field — it comes from the vote that tallied it
/// (§ [`Governance::execute_due_upgrades_at_height`]).
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

/// Escape hatch env for the single-node governance-write guard (documented,
/// default OFF): `1` or case-insensitive `true` opts in; anything else
/// (including unset) refuses multi-node writes fail-closed.
///
/// Arm it ONLY when you accept that a local-only governance mutation is NOT
/// replicated: every peer that never saw the write derives a different state
/// root, i.e. the chain forks. The supported way to govern a multi-validator
/// network is the BLOCK-CARRIED path: build a transaction carrying
/// `SysCallGovPropose` / `SysCallGovVote`
/// ([`Governance::gov_propose_tx`] / [`Governance::gov_vote_tx`]), submit it
/// through normal admission, and let every node apply the same block. This
/// escape hatch applies ONLY to the legacy direct-ledger-write RPC/runtime
/// forms.
pub const GOV_MULTINODE_WRITES_ENV: &str = "STELL_GOV_ALLOW_MULTINODE_WRITES";

/// Parse the escape-hatch flag: `1` or case-insensitive `true` (surrounding
/// whitespace trimmed) opts in; anything else (including `None`) is OFF.
/// Pure (no env read) so tests pin the truth table without touching the
/// process environment.
pub fn is_gov_multinode_escape(raw: Option<&str>) -> bool {
    match raw {
        Some(s) => {
            let t = s.trim();
            t == "1" || t.eq_ignore_ascii_case("true")
        }
        None => false,
    }
}

/// The escape hatch over the live process environment (default OFF).
pub fn governance_multinode_escape_enabled() -> bool {
    is_gov_multinode_escape(std::env::var(GOV_MULTINODE_WRITES_ENV).ok().as_deref())
}

/// Fail-closed single-node guard for governance WRITES (`propose`/`vote`
/// entry — NOT the deterministic finalize sweep).
///
/// A local-only governance mutation on a multi-node deployment diverges the
/// state root (peers that never saw the write commit a different root), so:
/// * `validator_count <= 1` (solo/dev stand: no peer to diverge from) → `Ok`.
/// * `validator_count > 1` + `allow_multinode_writes` (escape armed) → `Ok`.
/// * `validator_count > 1` without the escape → `Err` with a loud reason
///   (validator set size + escape env name + default-OFF note).
///
/// `validator_count` is the in-force validator set size
/// (`ValidatorSet::len` — the same count the runtime gates on); it is the
/// canonical multi-node signal, not a second peer-count source. The `Err`
/// text is the single source of truth for the refusal: the runtime maps it
/// into [`GovError::MultiNodeRefused`] and the RPC hook reports it verbatim.
pub fn governance_write_allowed(
    validator_count: usize,
    allow_multinode_writes: bool,
) -> Result<(), String> {
    if validator_count <= 1 || allow_multinode_writes {
        return Ok(());
    }
    Err(format!(
        "governance writes REFUSED on a multi-node deployment (in-force validator set size = {validator_count} > 1): \
         a local-only governance mutation would diverge this node's state root from peers that never saw it — \
         run the write against a solo node, or explicitly opt in with {GOV_MULTINODE_WRITES_ENV}=1 \
         (default OFF; multi-node writes are local-only and WILL fork the chain)"
    ))
}

/// [`governance_write_allowed`] over the live process environment: the count
/// comes from the caller (runtime: `self.validators.len()`), the escape from
/// [`governance_multinode_escape_enabled`]. This is the 3-line hook the RPC
/// layer calls before touching governance state.
pub fn governance_write_allowed_from_env(validator_count: usize) -> Result<(), String> {
    governance_write_allowed(validator_count, governance_multinode_escape_enabled())
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
        //
        // S9 (vote weight backed by LIVE stake): the snapshot is only an
        // UPPER BOUND. A voter can `unbond`/`undelegate` its position between
        // propose and vote; no lock exists yet, so the exit succeeds. Without
        // the min() below the vote still counted the departed stake at full
        // weight and `lock_governance` recorded a lock with nothing behind
        // it (the E7 guarantee was false). Cap the recorded weight at what
        // the voter actually holds NOW: `self_bond + delegated-out`, exactly
        // the live formula used when the snapshot is absent. Stake bonded
        // after propose still cannot vote (the snapshot cap stays), and the
        // lock is taken for the same capped amount, so unbond/undelegate can
        // no longer remove a counted vote.
        let live_self_bond: u128 = ledger
            .validators
            .get(&voter)
            .map(|v| v.self_bond as u128)
            .unwrap_or(0);
        let live_delegated_out: u128 = ledger
            .delegations
            .iter()
            .filter(|((_, d), _)| *d == voter)
            .map(|(_, amount)| *amount as u128)
            .sum();
        let live_weight = live_self_bond.saturating_add(live_delegated_out);
        let weight = match &p.electorate_weights {
            Some(snap) => {
                let snap_weight = snap.get(&voter).copied().ok_or(GovError::NotStaker)?;
                snap_weight.min(live_weight)
            }
            None => live_weight,
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
            Self::GOV_PROPOSE_TAG.len() + 1 + 8 + 32 + 8 + 8 + title.len() + 8 + action_json.len(),
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

    /// Read-only half of [`Governance::propose_signed`]: verifies the
    /// operator envelope against the claimed proposer staking key and checks
    /// nonce freshness, WITHOUT consuming the nonce or opening a proposal.
    ///
    /// The block-carried RPC path calls this before admitting a gov tx (same
    /// refusals as the direct path, nothing consumed); the authoritative
    /// nonce consumption stays in [`Governance::propose_signed`] (direct
    /// path) and in the block scan's id-gate (`proposal_id == next_id`,
    /// which makes a replayed block-carried propose refuse at apply).
    pub fn check_propose_envelope(
        &self,
        proposer: ValidatorId,
        title: &str,
        action: &GovAction,
        chain_id: u64,
        nonce: u64,
        sig: &crate::wallet_signing::WalletSignature,
    ) -> Result<(), GovError> {
        if sig.claimed_address() != proposer {
            return Err(GovError::BadSignature);
        }
        let message = Self::gov_propose_message(chain_id, &proposer, title, action, nonce);
        if !crate::wallet_signing::verify_message(&proposer, chain_id, &message, sig) {
            return Err(GovError::BadSignature);
        }
        if self.propose_nonce_used(&proposer, nonce) {
            return Err(GovError::ReplayedNonce);
        }
        Ok(())
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
        self.check_propose_envelope(proposer, &title, &action, chain_id, nonce, sig)?;
        let id = self.propose(ledger, proposer, title, action, now)?;
        self.gov_propose_nonces.insert((proposer, nonce));
        Ok(id)
    }

    /// Read-only half of [`Governance::vote_signed`]: verifies the operator
    /// envelope against the claimed voter staking key, WITHOUT recording a
    /// vote. Same refusals as the direct path (`BadSignature` first, then
    /// the vote's own gates on a live check), nothing locked or tallied.
    pub fn check_vote_envelope(
        &self,
        voter: [u8; 32],
        proposal_id: u64,
        choice: VoteChoice,
        chain_id: u64,
        sig: &crate::wallet_signing::WalletSignature,
    ) -> Result<(), GovError> {
        if sig.claimed_address() != voter {
            return Err(GovError::BadSignature);
        }
        let message = Self::gov_vote_message(chain_id, proposal_id, choice, &voter);
        if !crate::wallet_signing::verify_message(&voter, chain_id, &message, sig) {
            return Err(GovError::BadSignature);
        }
        Ok(())
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
        self.check_vote_envelope(voter, proposal_id, choice, chain_id, sig)?;
        self.vote(ledger, voter, proposal_id, choice, now)
    }

    // -----------------------------------------------------------------------
    // Block-carried governance builders (HDAE-GOV write path).
    //
    // The opcodes below are built by NAME (`OpCode::SysCallGovPropose` /
    // `OpCode::SysCallGovVote` — never raw discriminants): the names + field
    // shapes are the K1 contract (see the `OpCode` docs). Identity on the
    // block path is the TRANSACTION signer (`tx.from` = proposer/voter, whose
    // stake the apply gates on) — no operator envelope rides the opcode, so
    // these builders take no `WalletSignature`: the caller authorizes by
    // PQ-signing the assembled transaction with their own key (the session/PQ
    // signing path: `Transaction::signing_message` + PQ envelope, or
    // `sign_with_session_falcon512`), exactly like every other tx-building
    // flow, and submits it through the normal admission path (mempool ->
    // block). The node never signs as the caller.
    // -----------------------------------------------------------------------

    /// Build the block-carried propose opcode for the proposal the caller
    /// names. `proposal_id` MUST be the `next_id` the chain will hold when
    /// the tx applies (read it from `stell_governanceParams`; the apply
    /// refuses any other id fail-closed, so a stale read wastes gas but
    /// moves nothing). `height_observed` MUST be the block height the tx
    /// applies at (the apply refuses any other height: no cross-height
    /// replay); the earliest includable height is finalized-tip + 1.
    ///
    /// Fail-fast (same rules the apply enforces): an oversize title or an
    /// out-of-bounds action is refused HERE with `InvalidAction`, so a
    /// wallet learns before paying admission + gas. The apply re-validates
    /// authoritatively (a passed check here never excuses a refusal there).
    pub fn gov_propose_opcode(
        proposal_id: u64,
        title: String,
        action: GovAction,
        height_observed: u64,
    ) -> Result<crate::svm::OpCode, GovError> {
        if title.len() > MAX_PROPOSAL_TITLE_BYTES {
            return Err(GovError::InvalidAction);
        }
        action.validate()?;
        Ok(crate::svm::OpCode::SysCallGovPropose {
            proposal_id,
            title,
            action: Box::new(action),
            height_observed,
        })
    }

    /// Build the block-carried vote opcode. `height_observed` pins the exact
    /// block height (same rule as the propose twin). The voting window,
    /// one-vote rule and weight snapshot are enforced at apply (a vote for
    /// an unknown/closed proposal refuses there, moving nothing but gas).
    pub fn gov_vote_opcode(
        proposal_id: u64,
        choice: VoteChoice,
        height_observed: u64,
    ) -> crate::svm::OpCode {
        crate::svm::OpCode::SysCallGovVote {
            proposal_id,
            choice,
            height_observed,
        }
    }

    /// Assemble the UNSIGNED block-carried propose transaction: envelope
    /// (`from` = proposer, caller nonce/gas/shards) + the propose opcode.
    /// `signature` is left empty for the caller to fill by PQ-signing
    /// `tx.signing_message()` with their own key; submit the sealed tx via
    /// `stell_submitProposal` (`tx` form) or `stell_sendRawTransaction`.
    /// `to` is the sender itself (self-directed carrier, same convention as
    /// the `SysCallStake` flow); `amount` is zero (gov ops move no tokens).
    #[allow(clippy::too_many_arguments)]
    // GATE: a signing template names every signed byte explicitly (identity + replay + fee + route + intent); callers pass them, no defaults.
    pub fn gov_propose_tx(
        from: [u8; 32],
        tx_nonce: u64,
        gas_limit: u64,
        source_shard: crate::sharding::ShardId,
        target_shard: crate::sharding::ShardId,
        proposal_id: u64,
        title: String,
        action: GovAction,
        height_observed: u64,
    ) -> Result<crate::sharding::Transaction, GovError> {
        let op = Self::gov_propose_opcode(proposal_id, title, action, height_observed)?;
        Ok(crate::sharding::Transaction {
            from,
            to: from,
            amount: 0,
            gas_limit,
            nonce: tx_nonce,
            source_shard,
            target_shard,
            signature: Vec::new(),
            payload: vec![op],
            priority_fee_per_gas: 0,
        })
    }

    /// Assemble the UNSIGNED block-carried vote transaction (same envelope
    /// convention as [`Governance::gov_propose_tx`]; `from` = voter).
    #[allow(clippy::too_many_arguments)]
    // GATE: same explicit-bytes rule as the propose template.
    pub fn gov_vote_tx(
        from: [u8; 32],
        tx_nonce: u64,
        gas_limit: u64,
        source_shard: crate::sharding::ShardId,
        target_shard: crate::sharding::ShardId,
        proposal_id: u64,
        choice: VoteChoice,
        height_observed: u64,
    ) -> crate::sharding::Transaction {
        let op = Self::gov_vote_opcode(proposal_id, choice, height_observed);
        crate::sharding::Transaction {
            from,
            to: from,
            amount: 0,
            gas_limit,
            nonce: tx_nonce,
            source_shard,
            target_shard,
            signature: Vec::new(),
            payload: vec![op],
            priority_fee_per_gas: 0,
        }
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

    /// Whether at least one upgrade action is DUE at `cur_height`: `Passed`,
    /// mature under the KI-23 timelock, and either `SoftwareUpgrade` or
    /// `CancelUpgrade`.
    ///
    /// Read-only: the apply-path fast check calls this so a block with nothing
    /// due takes no governance write lock and bumps no commitment generation
    /// (which is what keeps the pre-activation path and an ordinary block
    /// byte-identical; the sweep itself re-derives the set under the lock).
    pub fn has_due_upgrade(&self, cur_height: u64) -> bool {
        self.proposals.values().any(|p| {
            p.status == ProposalStatus::Passed
                && matches!(
                    p.action,
                    GovAction::SoftwareUpgrade { .. } | GovAction::CancelUpgrade
                )
                && self.is_mature(p.id, cur_height)
        })
    }

    /// Deterministic upgrade-execution sweep: execute EVERY passed, matured
    /// upgrade action at `cur_height`, in ascending proposal-id order.
    ///
    /// This is the piece that makes a voted upgrade execute without a
    /// node-local RPC call (`stell_executeProposal`) or a wall-clock event:
    /// it is a pure function of committed governance state + the block height,
    /// so every node that applies the same blocks installs the same
    /// `AppliedParams::upgrade_plan` at the same height and commits the same
    /// state root.
    ///
    /// AUTHORITY (no new vote scheme): a candidate must be `Passed` (the only
    /// terminal status `finalize`/`finalize_at_height` assigns after measuring
    /// turnout against the proposal's FROZEN electorate), and the tally is
    /// re-derived here from the committed values — `turnout >=
    /// electorate * quorum_bps / 10_000`, `yes > no`, and a non-zero decisive
    /// turnout. A proposal that fails that re-derivation stays `Passed` and is
    /// refused loudly (fail-closed), so a smuggled/deserialised proposal can
    /// never execute on the strength of a hand-written status.
    ///
    /// MATURITY is the existing KI-23 timelock (`executable_height_of`, i.e.
    /// `pass_height + GOV_TIMELOCK_HEIGHTS`); `plan.height` is the separate
    /// coordinated HALT height and must still be in the FUTURE at execution
    /// time — a plan whose halt height has already passed is a silent dud in
    /// the old event-based path (`docs/UPGRADE_AND_RECOVERY.md` §1.2.3) and is
    /// refused loudly here instead.
    ///
    /// FAIL-CLOSED invalid plan: `name` (the target version), `height` and
    /// `sha256` (the binary hash) must all be present and sane
    /// ([`upgrade_name_is_safe`] re-checked, non-zero height and digest).
    ///
    /// CHAIN ID: `chain_id` is the chain applying the block
    /// ([`crate::consensus::consensus_chain_id`], the id every vote preimage and
    /// block hash binds). A call for any other chain refuses every candidate
    /// loudly and touches nothing — a plan is only executable on the chain
    /// whose governance state tallied its vote.
    ///
    /// COMMITTED-PLAN CONFLICT: if a plan is already committed and a matured
    /// proposal names a DIFFERENT `(name, height, sha256)` at or before that
    /// committed height, the proposal is refused (`hash does not match the
    /// committed one`). A strictly later height is a legitimate follow-up
    /// upgrade and is allowed.
    ///
    /// IDEMPOTENT: execution goes through [`Governance::execute_at_height`],
    /// whose `Passed -> Executed` transition is single-shot; a replay at the
    /// same or a later height finds no due proposal (status `Executed`) and
    /// changes nothing, so re-applying/replaying a block is byte-identical.
    pub fn execute_due_upgrades_at_height(
        &mut self,
        cur_height: u64,
        chain_id: u64,
    ) -> UpgradeExecOutcome {
        let mut out = UpgradeExecOutcome::default();
        let due = self.due_upgrade_ids(cur_height);
        if due.is_empty() {
            return out;
        }
        let this_chain = crate::consensus::consensus_chain_id();
        if chain_id != this_chain {
            let reason = format!(
                "plan is not executable on this chain: supplied chain id {chain_id} != \
                 this consensus chain id {this_chain} (a plan is bound to the chain whose \
                 vote tallied it)"
            );
            for id in due {
                out.checked += 1;
                tracing::error!(
                    "upgrade execution REFUSED at height {cur_height}: proposal {id}: {reason}"
                );
                out.refused.push((id, reason.clone()));
            }
            return out;
        }
        for id in due {
            out.checked += 1;
            match self.execute_one_due_action(id, cur_height, None) {
                Ok(()) => out.executed.push(id),
                Err(reason) => {
                    tracing::error!(
                        "upgrade execution REFUSED at height {cur_height}: proposal {id}: {reason} \
                         (proposal stays Passed; no plan was installed)"
                    );
                    out.refused.push((id, reason));
                }
            }
        }
        out
    }

    /// Ascending ids of the upgrade actions that are `Passed` and mature at
    /// `cur_height` (the sweep's deterministic order).
    fn due_upgrade_ids(&self, cur_height: u64) -> Vec<u64> {
        let mut ids: Vec<u64> = self
            .proposals
            .values()
            .filter(|p| {
                p.status == ProposalStatus::Passed
                    && matches!(
                        p.action,
                        GovAction::SoftwareUpgrade { .. } | GovAction::CancelUpgrade
                    )
                    && self.is_mature(p.id, cur_height)
            })
            .map(|p| p.id)
            .collect();
        ids.sort_unstable();
        ids
    }

    /// Validate and execute ONE due governance action. `Err` is the loud
    /// reason; on `Err` no state has moved (every check precedes the
    /// domain write, and [`Governance::execute_at_height`] /
    /// [`Governance::execute_with_oracle_at_height`] only write after their
    /// own gates pass).
    ///
    /// `oracle` must be supplied for oracle actions (`register`/`unregister`
    /// publisher, breaker reset); non-oracle actions ignore it. The upgrade
    /// arms keep the plan-specific fail-closed checks (safe version label,
    /// non-zero/future halt height, committed-plan conflict).
    fn execute_one_due_action(
        &mut self,
        proposal_id: u64,
        cur_height: u64,
        oracle: Option<&mut crate::oracle::OracleState>,
    ) -> Result<(), String> {
        // Snapshot everything the checks need so the `Proposal` borrow ends
        // before the mutable execution call.
        let (status, electorate, turnout, yes, no, action) = {
            let p = self
                .proposals
                .get(&proposal_id)
                .ok_or_else(|| "proposal not found".to_string())?;
            (
                p.status,
                p.electorate,
                p.turnout(),
                p.yes,
                p.no,
                p.action.clone(),
            )
        };
        if status != ProposalStatus::Passed {
            return Err(format!(
                "proposal is not Passed (status {status:?}): only a passed vote may execute"
            ));
        }
        // AUTHORITY: reuse the existing tallies, exactly the finalize formula
        // (frozen electorate, current governed quorum, yes > no, non-zero
        // decisive turnout). No new vote scheme is introduced.
        let quorum_needed = electorate * self.quorum_bps as u128 / BPS;
        if turnout < quorum_needed || yes <= no || yes + no == 0 {
            return Err(format!(
                "vote did not carry quorum at execution time: turnout {turnout} < needed \
                 {quorum_needed}, yes {yes} vs no {no} (electorate {electorate}, quorum {} bps)",
                self.quorum_bps
            ));
        }
        match &action {
            GovAction::SoftwareUpgrade {
                name,
                height,
                sha256,
            } => {
                // FAIL-CLOSED plan parsing (the backstops mirror propose and
                // execute time, so a plan smuggled into committed state cannot
                // install itself).
                if name.is_empty() || name.len() > 64 || !upgrade_name_is_safe(name) {
                    return Err(format!(
                        "unparseable upgrade plan: target version {name:?} is not a safe \
                         version label (1..=64 bytes, one ASCII path segment)"
                    ));
                }
                if *height == 0 {
                    return Err("unparseable upgrade plan: no coordinated halt height (0)".into());
                }
                if *sha256 == [0u8; 32] {
                    return Err(format!(
                        "unparseable upgrade plan {name:?}: no target binary hash (all-zero sha256)"
                    ));
                }
                if *height <= cur_height {
                    return Err(format!(
                        "mismatched upgrade plan {name:?}: halt height {height} is not in the \
                         future at execution height {cur_height} (stale plan refused instead of \
                         silently never halting)"
                    ));
                }
                if let Some(committed) = &self.applied.upgrade_plan {
                    let same = committed.name == *name
                        && committed.height == *height
                        && committed.sha256 == *sha256;
                    if !same && *height <= committed.height {
                        return Err(format!(
                            "plan hash {} does not match the committed plan for height {} \
                             (committed {} at height {}, version {:?})",
                            hex::encode(sha256),
                            height,
                            hex::encode(committed.sha256),
                            committed.height,
                            committed.name,
                        ));
                    }
                }
            }
            GovAction::CancelUpgrade => {}
            // Every other action (parameter change, signal, oracle action,
            // min-gas floor) is validated by the execute-time backstops in
            // `execute_inner`/`execute_with_oracle_at_height` (bounds, title
            // cap, publisher key, quorum floor), identical on every node.
            _ => {}
        }
        // Single-shot `Passed -> Executed` transition, timelock re-checked
        // against `cur_height`; the action is applied only when every check
        // above passed. Oracle actions need the committed oracle domain so
        // the governance half and the oracle half are all-or-nothing.
        if action.is_oracle_action() {
            let oracle = oracle.ok_or_else(|| {
                format!(
                    "oracle action ({}) requires the committed oracle domain, which was not supplied",
                    action.action_type()
                )
            })?;
            self.execute_with_oracle_at_height(UPGRADE_EXECUTOR, proposal_id, oracle, cur_height)
                .map(|_| ())
                .map_err(|e| format!("execute refused: {e}"))
        } else {
            self.execute_at_height(UPGRADE_EXECUTOR, proposal_id, cur_height)
                .map(|_| ())
                .map_err(|e| format!("execute refused: {e}"))
        }
    }

    /// Whether any governance action needs the committed oracle domain at
    /// `cur_height` (used by the apply path to take the oracle write lock only
    /// when an oracle action is actually due).
    pub fn has_due_oracle_action(&self, cur_height: u64) -> bool {
        self.proposals.values().any(|p| {
            p.status == ProposalStatus::Passed
                && p.action.is_oracle_action()
                && self.is_mature(p.id, cur_height)
        })
    }

    /// Ascending ids of every `Passed`, mature governance action that the
    /// deterministic block-path executor may run at `cur_height`.
    ///
    /// `SoftwareUpgrade` is included only while the separate
    /// [`upgrade_exec_active_at`] gate is open. `CancelUpgrade` is always
    /// included: it is a safety valve that can only clear a plan, and must
    /// work before AND after the gate opens. Every other action is governed
    /// solely by [`GOV_OPS_ACTIVATION_HEIGHT`]. Ordering is ascending id, so
    /// two nodes applying the same block execute the same actions in the same
    /// order (last-write-wins parameter actions therefore converge).
    fn due_governance_ids(&self, cur_height: u64) -> Vec<u64> {
        let upgrades = upgrade_exec_active_at(cur_height);
        let mut ids: Vec<u64> = self
            .proposals
            .values()
            .filter(|p| {
                p.status == ProposalStatus::Passed
                    && self.is_mature(p.id, cur_height)
                    && (upgrades || !matches!(p.action, GovAction::SoftwareUpgrade { .. }))
            })
            .map(|p| p.id)
            .collect();
        ids.sort_unstable();
        ids
    }

    /// Read-only fast path for the apply step: true when this block can move
    /// governance state (an Open proposal whose voting window has closed, or a
    /// Passed action that is mature and runnable).
    ///
    /// When false, [`crate::state_engine::InMemoryStateEngine::apply_governance_transition`]
    /// takes no lock and bumps no commitment generation, so an ordinary block
    /// leaves the state root byte-identical.
    pub fn has_due_governance(&self, now: u64, cur_height: u64) -> bool {
        let upgrades = upgrade_exec_active_at(cur_height);
        self.proposals.values().any(|p| {
            (p.status == ProposalStatus::Open && now >= p.voting_end)
                || (p.status == ProposalStatus::Passed
                    && self.is_mature(p.id, cur_height)
                    && (upgrades || !matches!(p.action, GovAction::SoftwareUpgrade { .. })))
        })
    }

    /// Deterministically finalize every `Open` proposal whose voting window
    /// closed at or before `now` (the block timestamp), in ascending id
    /// order. Returns the finalized ids.
    ///
    /// Uses [`Governance::finalize_at_height`] so a pass records
    /// `cur_height + GOV_TIMELOCK_HEIGHTS`. Idempotent: a replay (or a second
    /// block at the same timestamp) finds the terminal status and finalizes
    /// nothing, so it moves no state.
    pub fn finalize_due_at_height(
        &mut self,
        ledger: &mut StakingLedger,
        now: u64,
        cur_height: u64,
    ) -> Vec<u64> {
        let mut ids: Vec<u64> = self
            .proposals
            .values()
            .filter(|p| p.status == ProposalStatus::Open && now >= p.voting_end)
            .map(|p| p.id)
            .collect();
        ids.sort_unstable();
        let mut finalized = Vec::with_capacity(ids.len());
        for id in ids {
            match self.finalize_at_height(ledger, id, now, cur_height) {
                Ok(status) => {
                    tracing::info!(
                        "gov proposal {id} finalized at height {cur_height}: {status:?}"
                    );
                    finalized.push(id);
                }
                Err(e) => tracing::error!(
                    "gov finalize REFUSED at height {cur_height}: proposal {id}: {e} \
                     (proposal stays Open; retried on the next block)"
                ),
            }
        }
        finalized
    }

    /// Deterministic block-path executor for EVERY governance action type:
    /// finalization has already happened in
    /// [`Governance::finalize_due_at_height`], and this sweep runs every
    /// `Passed` action that is mature at `cur_height`, in ascending id order.
    ///
    /// Authority is re-derived from the committed tally (the same formula
    /// `finalize` used) so a smuggled status cannot execute. Execution is
    /// single-shot (`Passed -> Executed`); a replayed block finds no due
    /// action and changes nothing.
    ///
    /// Oracle actions (`register`/`unregister` publisher, breaker reset) go
    /// through [`Governance::execute_with_oracle_at_height`] so the governance
    /// and oracle domains are written all-or-nothing.
    pub fn execute_due_governance_at_height(
        &mut self,
        cur_height: u64,
        chain_id: u64,
        oracle: Option<&mut crate::oracle::OracleState>,
    ) -> UpgradeExecOutcome {
        let mut out = UpgradeExecOutcome::default();
        let due = self.due_governance_ids(cur_height);
        if due.is_empty() {
            return out;
        }
        let this_chain = crate::consensus::consensus_chain_id();
        let mut oracle = oracle;
        for id in due {
            out.checked += 1;
            let action = match self.proposals.get(&id) {
                Some(p) => p.action.clone(),
                None => continue,
            };
            // Upgrade plans are chain-bound (a plan is executable only on the
            // chain whose vote tallied it); parameter actions are not.
            if matches!(
                action,
                GovAction::SoftwareUpgrade { .. } | GovAction::CancelUpgrade
            ) && chain_id != this_chain
            {
                let reason = format!(
                    "plan is not executable on this chain: supplied chain id {chain_id} != \
                     this consensus chain id {this_chain} (a plan is bound to the chain whose \
                     vote tallied it)"
                );
                tracing::error!(
                    "gov execution REFUSED at height {cur_height}: proposal {id}: {reason}"
                );
                out.refused.push((id, reason));
                continue;
            }
            match self.execute_one_due_action(id, cur_height, oracle.as_deref_mut()) {
                Ok(()) => out.executed.push(id),
                Err(reason) => {
                    tracing::error!(
                        "gov execution REFUSED at height {cur_height}: proposal {id}: {reason} \
                         (proposal stays Passed; action not applied)"
                    );
                    out.refused.push((id, reason));
                }
            }
        }
        out
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
                    Some(ProposalStatus::Executed) => return Err(GovError::AlreadyExecuted),
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
                // PENTEST2 S5: this parameter has NO consumer. The wired
                // slashing primitives (`slash_equivocation_verified`,
                // the proposal/XMSS mirrors and `slash`) burn the frozen
                // `staking::EQUIVOCATION_SLASH_BPS`; persisting a different
                // value here would make the committed `applied` field claim
                // a rule the chain does not enforce — a silent no-op.
                //
                // Refuse deterministically at apply (every node identical,
                // `Passed -> Executed` never happens, the proposal stays
                // `Passed` for an explicit future migration) instead of
                // committing a decorative parameter. `v` is still range
                // checked first so an out-of-range action reports the same
                // invalid-action bound as every other parameter.
                if v > BPS_U64 {
                    return Err(GovError::InvalidAction);
                }
                tracing::error!(
                    "governance SetEquivocationSlashBps({v}) REFUSED: the equivocation slash \
                     rate has no wired consumer (slashing uses \
                     staking::EQUIVOCATION_SLASH_BPS); refusing instead of committing a \
                     parameter that does nothing"
                );
                return Err(GovError::InvalidAction);
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
                // PENTEST2 S7: the upgrade gate belongs HERE, in the one
                // executor every path funnels through (deterministic sweep,
                // direct RPC arm, legacy `execute`, oracle-aware variant).
                // `due_governance_ids` already filters upgrades while the gate
                // is closed, but a direct caller bypassed that filter and
                // installed a plan (and the halt predicate reads the committed
                // plan). A gated-off executor refuses fail-closed and leaves
                // the proposal `Passed`.
                if !upgrade_exec_active_at(cur_height.unwrap_or(0)) {
                    tracing::error!(
                        "upgrade execution REFUSED: `upgrade_exec_active_at` is false at \
                         height {:?} (activation {})",
                        cur_height,
                        upgrade_exec_activation_height(),
                    );
                    return Err(GovError::Timelocked);
                }
                // NO RETROACTIVE PLAN: installing a plan whose halt height is
                // already at/below the block being applied would be a local
                // "we should have halted yesterday" decision that a node
                // catching up could make differently from one that was live.
                // The height-aware path proves the current height; the legacy
                // height-less `execute` cannot, so it refuses a plan
                // fail-closed instead of guessing (CancelUpgrade stays
                // available). The sweep has the same rule before it calls
                // this executor.
                let Some(cur_height) = cur_height else {
                    tracing::error!(
                        "upgrade plan {name:?} REFUSED: legacy execute supplied no block height, \
                         so a retroactive halt height cannot be ruled out"
                    );
                    return Err(GovError::InvalidAction);
                };
                if height <= cur_height {
                    tracing::error!(
                        "upgrade plan {name:?} REFUSED: halt height {height} is not in the future \
                         at execution height {cur_height} (retroactive plans are not installable)"
                    );
                    return Err(GovError::InvalidAction);
                }
                self.applied.upgrade_plan = Some(UpgradePlan {
                    name,
                    height,
                    sha256,
                });
            }
            GovAction::CancelUpgrade => {
                // Cancellation is a SAFETY VALVE, not plan installation: it
                // can only remove a plan, never create or retarget one. It is
                // deliberately NOT behind the activation gate, so a passed
                // cancel works before AND after the gate opens (and can clear
                // a plan restored from a snapshot even while installs are
                // still inert). It remains a single-shot, committed action.
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

    // -----------------------------------------------------------------------
    // Block-carried governance migration (startup hook, in-memory only).
    //
    // Pre-activation proposals were opened by direct writes (not by block
    // ops) and are restored from storage as-is. Before block-carried
    // proposes can flow, the loaded state must satisfy the ONE invariant the
    // block scan assumes: every future propose mints a fresh id. The scan
    // requires `proposal_id == gov.next_id` and refuses anything else, so a
    // restored `next_id` at/below an existing id would make the next
    // block-carried propose refuse forever (liveness), and a `next_id`
    // colliding with a live id would overwrite it. The repair below is the
    // entire "import into the block-carried format": proposals themselves
    // need no rewrite (tally/electorate/timelock shapes are versioned
    // explicitly: `electorate_weights: None` keeps the documented live-
    // weight fallback, a missing `timelocks` entry keeps the documented
    // legacy-immediate execution — both load-bearing for pre-upgrade
    // proposals and deliberately NOT backfilled here, since the propose-time
    // weights are unknowable post-hoc and inventing a maturity would change
    // execution behavior).
    //
    // INVOKED once from the main.rs startup hook right after the persisted
    // state is installed. IN-MEMORY ONLY: no storage, disk, or network I/O
    // (takes `&mut self`, returns counts).
    // -----------------------------------------------------------------------

    /// Import pre-existing (pre-activation) proposals into the block-carried
    /// format: repairs `next_id` to `max(next_id, max_existing_id + 1, 1)`
    /// so block-minted proposes can never collide with (or stall behind)
    /// restored proposals, and reports the status census. IDEMPOTENT:
    /// running twice changes nothing — the second run finds `next_id`
    /// already sufficient and mutates zero bytes (only its
    /// `next_id_repaired` reads `false`).
    pub fn migrate_gov_proposals_to_genesis(&mut self) -> GovMigrationSummary {
        let max_id = self.proposals.keys().copied().max();
        let want = max_id.map(|m| m.saturating_add(1)).unwrap_or(1).max(1);
        let next_id_repaired = if self.next_id < want {
            self.next_id = want;
            true
        } else {
            false
        };
        GovMigrationSummary {
            proposals_seen: self.proposals.len(),
            next_id_repaired,
            open: self.count_status(ProposalStatus::Open),
            passed: self.count_status(ProposalStatus::Passed),
            rejected: self.count_status(ProposalStatus::Rejected),
            executed: self.count_status(ProposalStatus::Executed),
            invalid_actions: self
                .proposals
                .values()
                .filter(|p| p.action.validate().is_err())
                .count(),
        }
    }
}

/// Outcome of one [`Governance::execute_due_upgrades_at_height`] sweep.
///
/// Pure counts + the ids that moved state: NOT committed (it is a report, not
/// consensus state). `checked` counts the candidates the sweep considered,
/// `executed` the ones whose action was applied, and `refused` the loud
/// `(proposal id, reason)` pairs that stayed `Passed`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UpgradeExecOutcome {
    pub checked: usize,
    pub executed: Vec<u64>,
    pub refused: Vec<(u64, String)>,
    /// Proposals finalized by the same block-path sweep (empty for the
    /// upgrade-only entry point, which does not finalize). Not committed:
    /// the proposal status change it reports IS committed.
    pub finalized: Vec<u64>,
}

/// Outcome of one [`Governance::migrate_gov_proposals_to_genesis`] run: pure
/// counts. The ONLY state change a run may make is the `next_id` repair
/// (`next_id_repaired`); every other field reports what was seen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovMigrationSummary {
    /// Pre-existing proposals found (all statuses).
    pub proposals_seen: usize,
    /// `next_id` was below `max_id + 1` (or below 1) and was raised.
    pub next_id_repaired: bool,
    /// Proposals by status (observability for the startup log).
    pub open: usize,
    pub passed: usize,
    pub rejected: usize,
    pub executed: usize,
    /// Proposals whose action fails TODAY's `validate` (read-only count, no
    /// removal: locked stake releases at finalize, so dropping one would
    /// brick funds; execute-time backstops already refuse them fail-closed).
    pub invalid_actions: usize,
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
        let key = WalletSigningKey::falcon_from_seed(&[0xA1u8; 32]);
        let addr = key.address();
        let other = WalletSigningKey::falcon_from_seed(&[0xB2u8; 32]);
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
            .propose_signed(
                &mut l,
                addr,
                title.clone(),
                action.clone(),
                0,
                CHAIN,
                nonce,
                &sig,
            )
            .unwrap();
        assert_eq!(id, 1);
        assert!(g.propose_nonce_used(&addr, nonce));
        // Exact replay: same envelope, nonce already consumed.
        assert_eq!(
            g.propose_signed(
                &mut l,
                addr,
                title.clone(),
                action.clone(),
                0,
                CHAIN,
                nonce,
                &sig
            ),
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
            g.propose_signed(
                &mut l,
                addr,
                title.clone(),
                action.clone(),
                0,
                CHAIN,
                8,
                &wrong
            ),
            Err(GovError::BadSignature)
        );
        // Tampered title: sign one title, present for another.
        let tampered_msg = Governance::gov_propose_message(CHAIN, &addr, "tampered", &action, 9);
        let tampered_sig = key.sign_message(CHAIN, &tampered_msg).unwrap();
        assert_eq!(
            g.propose_signed(
                &mut l,
                addr,
                title.clone(),
                action.clone(),
                0,
                CHAIN,
                9,
                &tampered_sig
            ),
            Err(GovError::BadSignature)
        );
        // Wrong chain: minted elsewhere, refused here.
        let cross_msg = Governance::gov_propose_message(CHAIN + 1, &addr, &title, &action, 10);
        let cross = key.sign_message(CHAIN + 1, &cross_msg).unwrap();
        assert_eq!(
            g.propose_signed(
                &mut l,
                addr,
                title.clone(),
                action.clone(),
                0,
                CHAIN,
                10,
                &cross
            ),
            Err(GovError::BadSignature)
        );
        // Stakeless key with a PERFECTLY valid signature: NotStaker, not Open.
        let lone = WalletSigningKey::falcon_from_seed(&[0xC3u8; 32]);
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
        let voter_key = WalletSigningKey::falcon_from_seed(&[0xB2u8; 32]);
        let voter = voter_key.address();
        let proposer_key = WalletSigningKey::falcon_from_seed(&[0xA1u8; 32]);
        let proposer = proposer_key.address();
        let mut l = StakingLedger::new();
        l.bond(proposer, stell(10_000), DEFAULT_COMMISSION_BPS)
            .unwrap();
        l.bond(voter, stell(20_000), DEFAULT_COMMISSION_BPS)
            .unwrap();
        let mut g = Governance::new();
        let id = g
            .propose(
                &mut l,
                proposer,
                "x".into(),
                GovAction::Signal("t".into()),
                0,
            )
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
        let lone = WalletSigningKey::falcon_from_seed(&[0xC3u8; 32]);
        let lone_addr = lone.address();
        let lone_msg = Governance::gov_vote_message(CHAIN, id, VoteChoice::Yes, &lone_addr);
        let lone_sig = lone.sign_message(CHAIN, &lone_msg).unwrap();
        assert_eq!(
            g.vote_signed(&mut l, lone_addr, id, VoteChoice::Yes, 1, CHAIN, &lone_sig),
            Err(GovError::NotStaker)
        );
    }

    /// The read-only envelope checks agree with the signed paths exactly,
    /// and consume nothing: check-twice passes, the signed call then opens,
    /// and only afterwards does the check report the spent nonce.
    #[test]
    fn check_envelope_helpers_agree_with_signed_paths() {
        use crate::wallet_signing::WalletSigningKey;
        const CHAIN: u64 = 777;
        let key = WalletSigningKey::falcon_from_seed(&[0xA1u8; 32]);
        let addr = key.address();
        let mut l = StakingLedger::new();
        l.bond(addr, stell(10_000), DEFAULT_COMMISSION_BPS).unwrap();
        let mut g = Governance::new();
        let title = "t".to_string();
        let action = GovAction::Signal("s".into());
        let msg = Governance::gov_propose_message(CHAIN, &addr, &title, &action, 1);
        let sig = key.sign_message(CHAIN, &msg).unwrap();
        // Read-only: twice is fine, nothing consumed, nothing opened.
        assert!(g
            .check_propose_envelope(addr, &title, &action, CHAIN, 1, &sig)
            .is_ok());
        assert!(g
            .check_propose_envelope(addr, &title, &action, CHAIN, 1, &sig)
            .is_ok());
        assert!(!g.propose_nonce_used(&addr, 1));
        assert!(g.proposals.is_empty());
        // The signed path opens and consumes.
        let id = g
            .propose_signed(
                &mut l,
                addr,
                title.clone(),
                action.clone(),
                0,
                CHAIN,
                1,
                &sig,
            )
            .unwrap();
        // ...and only now does the check report the spent nonce.
        assert_eq!(
            g.check_propose_envelope(addr, &title, &action, CHAIN, 1, &sig),
            Err(GovError::ReplayedNonce)
        );
        // Vote checks verify without recording (tally unmoved).
        let vmsg = Governance::gov_vote_message(CHAIN, id, VoteChoice::Yes, &addr);
        let vsig = key.sign_message(CHAIN, &vmsg).unwrap();
        assert!(g
            .check_vote_envelope(addr, id, VoteChoice::Yes, CHAIN, &vsig)
            .is_ok());
        assert_eq!(g.proposals.get(&id).unwrap().yes, 0);
        let w = g
            .vote_signed(&mut l, addr, id, VoteChoice::Yes, 1, CHAIN, &vsig)
            .unwrap();
        assert_eq!(w, stell(10_000) as u128);
    }

    /// Block-carried opcode builders: enum NAMES (never discriminants),
    /// exact field shapes, fail-fast validation, and unsigned tx templates
    /// whose only missing piece is the caller's own PQ signature.
    #[test]
    fn gov_opcode_builders_use_names_and_validate() {
        let action = GovAction::SetBlockReward(stell(9));
        let op = Governance::gov_propose_opcode(4, "t".into(), action.clone(), 41).unwrap();
        match op {
            crate::svm::OpCode::SysCallGovPropose {
                proposal_id,
                title,
                action: a,
                height_observed,
            } => {
                assert_eq!(proposal_id, 4);
                assert_eq!(title, "t");
                assert_eq!(*a, action);
                assert_eq!(height_observed, 41);
            }
            other => panic!("propose builder must mint SysCallGovPropose, got: {other:?}"),
        }
        // Oversize title and out-of-bounds actions refuse HERE (fail-fast,
        // same `InvalidAction` the apply reports — never admitted blind).
        assert!(
            matches!(
                Governance::gov_propose_opcode(
                    4,
                    "x".repeat(MAX_PROPOSAL_TITLE_BYTES + 1),
                    action.clone(),
                    41
                ),
                Err(GovError::InvalidAction)
            ),
            "oversize title must refuse fail-fast"
        );
        assert!(
            matches!(
                Governance::gov_propose_opcode(
                    4,
                    "t".into(),
                    GovAction::SetBlockReward(u64::MAX),
                    41
                ),
                Err(GovError::InvalidAction)
            ),
            "out-of-bounds action must refuse fail-fast"
        );
        let vop = Governance::gov_vote_opcode(4, VoteChoice::No, 41);
        match vop {
            crate::svm::OpCode::SysCallGovVote {
                proposal_id,
                choice,
                height_observed,
            } => {
                assert_eq!(proposal_id, 4);
                assert_eq!(choice, VoteChoice::No);
                assert_eq!(height_observed, 41);
            }
            other => panic!("vote builder must mint SysCallGovVote, got: {other:?}"),
        }
        // Templates: self-directed carrier, caller nonce/gas/shards, empty
        // signature slot for the caller's own PQ signature, one-op payload.
        let from = [0xA1u8; 32];
        let tx =
            Governance::gov_propose_tx(from, 7, 100_000, 0, 0, 4, "t".into(), action, 41).unwrap();
        assert_eq!(tx.from, from);
        assert_eq!(tx.to, from);
        assert_eq!(tx.amount, 0);
        assert_eq!(tx.nonce, 7);
        assert_eq!(tx.gas_limit, 100_000);
        assert!(
            tx.signature.is_empty(),
            "template is unsigned: the caller signs"
        );
        assert_eq!(tx.payload.len(), 1);
        assert!(matches!(
            tx.payload[0],
            crate::svm::OpCode::SysCallGovPropose { .. }
        ));
        let vtx = Governance::gov_vote_tx(from, 8, 100_000, 0, 0, 4, VoteChoice::Yes, 41);
        assert_eq!((vtx.from, vtx.nonce), (from, 8));
        assert!(vtx.signature.is_empty());
        assert!(matches!(
            vtx.payload[0],
            crate::svm::OpCode::SysCallGovVote { .. }
        ));
    }

    /// Migration on a mixed-status chain with a stale `next_id` plus one
    /// smuggled invalid action: repairs the id, censuses every status, and
    /// counts (never removes) the invalid one.
    #[test]
    fn migrate_repairs_next_id_and_censuses() {
        let (mut l, ids) = ledger_with(3, 10_000);
        let mut g = Governance::new();
        let p1 = g
            .propose(&mut l, ids[0], "a".into(), GovAction::Signal("a".into()), 0)
            .unwrap();
        let p2 = g
            .propose(&mut l, ids[1], "b".into(), GovAction::Signal("b".into()), 0)
            .unwrap();
        let p3 = g
            .propose(&mut l, ids[2], "c".into(), GovAction::Signal("c".into()), 0)
            .unwrap();
        let end = GOVERNANCE_VOTING_PERIOD_SECS + 1;
        // p1 passes unanimously and executes; p2 gets no votes (rejected).
        for id in &ids {
            g.vote(&mut l, *id, p1, VoteChoice::Yes, 1).unwrap();
        }
        assert_eq!(g.finalize(&mut l, p1, end).unwrap(), ProposalStatus::Passed);
        g.execute([0xEu8; 32], p1).unwrap();
        assert_eq!(
            g.finalize(&mut l, p2, end).unwrap(),
            ProposalStatus::Rejected
        );
        // p3 stays Open. Smuggle one invalid action past propose-time checks
        // (direct map insert, as a pre-activation byte shape would).
        g.proposals.insert(
            9,
            Proposal {
                id: 9,
                proposer: ids[0],
                title: "smuggled".into(),
                action: GovAction::SetBlockReward(u64::MAX),
                created_at: 0,
                voting_end: end,
                yes: 0,
                no: 0,
                abstain: 0,
                voters: Default::default(),
                status: ProposalStatus::Open,
                electorate: 1,
                electorate_weights: None,
                proposer_lock: 0,
                weights: Default::default(),
            },
        );
        // Stale the id counter the way a pre-activation restore can.
        g.next_id = 2;
        let sum = g.migrate_gov_proposals_to_genesis();
        assert_eq!(sum.proposals_seen, 4);
        assert!(sum.next_id_repaired);
        assert_eq!(g.next_id, 10, "next_id must clear the highest restored id");
        assert_eq!(sum.open, 2);
        assert_eq!(sum.passed, 0);
        assert_eq!(sum.rejected, 1);
        assert_eq!(sum.executed, 1);
        assert_eq!(sum.invalid_actions, 1, "counted, never removed");
        assert!(
            g.proposals.contains_key(&9),
            "migration must not drop proposals"
        );
        assert!(g.proposals.contains_key(&p3));
    }

    /// Migration idempotency: running twice changes nothing. The second run
    /// reports identical counts with `next_id_repaired == false`, and the
    /// serialized state is byte-identical between runs.
    #[test]
    fn migrate_gov_proposals_to_genesis_is_idempotent() {
        let (mut l, ids) = ledger_with(1, 10_000);
        let mut g = Governance::new();
        g.propose(&mut l, ids[0], "a".into(), GovAction::Signal("a".into()), 0)
            .unwrap();
        g.next_id = 1; // stale restore: id 1 exists, counter claims 1
                       // Byte-compare via bincode (serde_json cannot map the nonce/proposal
                       // keys, which are not strings — same wire form the RPC tests use).
        let before = bincode::serialize(&g).expect("governance serializes");
        let first = g.migrate_gov_proposals_to_genesis();
        assert!(first.next_id_repaired);
        assert_eq!(g.next_id, 2);
        let mid = bincode::serialize(&g).expect("governance serializes");
        assert_ne!(before, mid, "the repair must actually change state once");
        let second = g.migrate_gov_proposals_to_genesis();
        let after = bincode::serialize(&g).expect("governance serializes");
        assert_eq!(mid, after, "second run must change zero bytes");
        assert!(!second.next_id_repaired);
        assert_eq!(
            (second.proposals_seen, second.open),
            (first.proposals_seen, first.open)
        );
        // Empty chain: nothing to repair, still idempotent.
        let mut fresh = Governance::new();
        let f1 = fresh.migrate_gov_proposals_to_genesis();
        assert_eq!((f1.proposals_seen, f1.next_id_repaired), (0, false));
        let f2 = fresh.migrate_gov_proposals_to_genesis();
        assert_eq!(f1, f2);
    }

    /// Migration never rewinds a healthy counter (a `next_id` already ahead
    /// of every restored id is left alone).
    #[test]
    fn migrate_never_rewinds_next_id() {
        let (mut l, ids) = ledger_with(1, 10_000);
        let mut g = Governance::new();
        g.propose(&mut l, ids[0], "a".into(), GovAction::Signal("a".into()), 0)
            .unwrap();
        g.next_id = 100;
        let sum = g.migrate_gov_proposals_to_genesis();
        assert!(!sum.next_id_repaired);
        assert_eq!(g.next_id, 100);
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
            .propose(
                &mut l,
                [1u8; 32],
                "x".into(),
                GovAction::Signal("t".into()),
                0,
            )
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

    /// S9 (vote weight removed before it is counted): a delegator that
    /// undelegates its ENTIRE propose-time position BEFORE voting must not
    /// vote at the snapshot weight — no lock exists yet, so the exit is
    /// legal — and must not record a governance lock with no stake behind it.
    ///
    /// On the vulnerable code this fails: `vote` returns `Ok(9_000)` and the
    /// tally counts 9k that already left the ledger.
    #[test]
    fn vote_cannot_count_stake_that_exited_before_the_vote() {
        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(10_000), DEFAULT_COMMISSION_BPS)
            .unwrap();
        l.bond(vid(2), stell(10_000), DEFAULT_COMMISSION_BPS)
            .unwrap();
        l.delegate(del(1), vid(1), stell(9_000)).unwrap();
        let mut g = Governance::new();
        // vid(2) proposes, so the delegator is not the proposer and holds no
        // propose-time lock of its own.
        let id = g
            .propose(&mut l, vid(2), "x".into(), GovAction::Signal("t".into()), 0)
            .unwrap();
        // The delegator exits BEFORE casting a vote: no lock exists yet.
        l.undelegate(del(1), vid(1), stell(9_000), 1).unwrap();
        assert_eq!(l.locked_governance_of(&del(1)), 0);

        assert_eq!(
            g.vote(&mut l, del(1), id, VoteChoice::Yes, 2),
            Err(GovError::NotStaker),
            "a vote must be backed by stake the voter still holds"
        );
        let p = g.get(id).unwrap();
        assert_eq!(p.turnout(), 0, "no unbacked weight may enter the tally");
        assert_eq!(
            l.locked_governance_of(&del(1)),
            0,
            "no lock may be recorded against departed stake"
        );
    }

    /// S9 partial exit: the recorded vote is capped at the LIVE position, so
    /// a partial undelegate lowers the weight and only the remaining stake is
    /// locked (still enough to keep the counted part from exiting).
    #[test]
    fn vote_weight_is_capped_at_the_live_position_after_a_partial_exit() {
        use crate::staking::StakingError;

        let mut l = StakingLedger::new();
        l.bond(vid(1), stell(10_000), DEFAULT_COMMISSION_BPS)
            .unwrap();
        l.bond(vid(2), stell(10_000), DEFAULT_COMMISSION_BPS)
            .unwrap();
        l.delegate(del(1), vid(1), stell(9_000)).unwrap();
        let mut g = Governance::new();
        let id = g
            .propose(&mut l, vid(2), "x".into(), GovAction::Signal("t".into()), 0)
            .unwrap();
        l.undelegate(del(1), vid(1), stell(4_000), 1).unwrap();

        let weight = g.vote(&mut l, del(1), id, VoteChoice::Yes, 2).unwrap();
        assert_eq!(
            weight,
            stell(5_000) as u128,
            "only the 5k still delegated out may back the vote"
        );
        assert_eq!(l.locked_governance_of(&del(1)), stell(5_000));
        // The remaining 5k cannot exit either: it is the vote's backing.
        assert_eq!(
            l.undelegate(del(1), vid(1), stell(5_000), 3),
            Err(StakingError::LockedInGovernanceVote)
        );
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
    fn timelock_const_is_six_hours_at_the_target_tempo_no_env() {
        // Ruleset v2: the invariant is WALL-CLOCK (six hours), not a height
        // count. 90_000 x 240 ms = 6 h. The commission window is separately
        // re-scaled to two hours (30_000 x 240 ms), so the two no longer share
        // a number -- they share a derivation.
        assert_eq!(GOV_TIMELOCK_HEIGHTS, 90_000);
        assert_eq!(GOV_TIMELOCK_HEIGHTS * 240, 21_600_000, "6 h in ms");
        assert_eq!(
            crate::staking::COMMISSION_EFFECT_DELAY_HEIGHTS * 240,
            7_200_000,
            "the commission window is 2 h in ms"
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
        // Exact maturity: pass_height + the ruleset-v3 timelock (90_000
        // heights = 6 h at 240 ms), boundary-checked both sides.
        let maturity = pass_height + GOV_TIMELOCK_HEIGHTS;
        assert_eq!(
            maturity,
            pass_height + 90_000,
            "ruleset v3 timelock is 90_000 heights"
        );
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

    /// Single-node write guard: the escape-flag truth table. `1` or
    /// case-insensitive `true` (trimmed) opts in; everything else — including
    /// unset — is OFF. Pure parser, no env touched.
    #[test]
    fn gov_write_guard_escape_flag_truth_table() {
        assert!(!is_gov_multinode_escape(None));
        assert!(is_gov_multinode_escape(Some("1")));
        assert!(is_gov_multinode_escape(Some("true")));
        assert!(is_gov_multinode_escape(Some("TRUE")));
        assert!(is_gov_multinode_escape(Some(" True ")));
        assert!(!is_gov_multinode_escape(Some("")));
        assert!(!is_gov_multinode_escape(Some("0")));
        assert!(!is_gov_multinode_escape(Some("false")));
        assert!(!is_gov_multinode_escape(Some("yes")));
        assert!(!is_gov_multinode_escape(Some("2")));
    }

    /// Single-node write guard: solo (0 or 1 validators — no peer to diverge
    /// from) allows local writes with or without the escape.
    #[test]
    fn gov_write_guard_solo_allows() {
        for n in [0usize, 1] {
            for escape in [false, true] {
                assert!(
                    governance_write_allowed(n, escape).is_ok(),
                    "solo set (size = {n}, escape = {escape}) must allow writes"
                );
            }
        }
    }

    /// Single-node write guard: multi-node without the escape refuses
    /// fail-closed, and the refusal is loud (names the size + the escape env
    /// + the default-OFF note).
    #[test]
    fn gov_write_guard_multi_refuses_without_escape() {
        for n in [2usize, 3, 100] {
            let err = governance_write_allowed(n, false)
                .expect_err("multi-node set without the escape must refuse writes");
            assert!(err.contains("REFUSED"), "refusal must be loud, got: {err}");
            assert!(
                err.contains(&n.to_string()),
                "refusal must name the validator set size, got: {err}"
            );
            assert!(
                err.contains(GOV_MULTINODE_WRITES_ENV),
                "refusal must name the escape env, got: {err}"
            );
            assert!(
                err.contains("default OFF"),
                "refusal must note the default, got: {err}"
            );
        }
    }

    /// Single-node write guard: the escape re-allows multi-node writes.
    #[test]
    fn gov_write_guard_escape_reallows_multi() {
        for n in [2usize, 3, 100] {
            assert!(
                governance_write_allowed(n, true).is_ok(),
                "armed escape (size = {n}) must re-allow writes"
            );
        }
    }
}
