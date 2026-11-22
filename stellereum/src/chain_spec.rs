//! Consolidated view of chain activation gates and protocol defaults across
//! `stellereum` and `infnode`, plus the genesis chain-spec values that are not
//! compiled into a per-subsystem constant.
//!
//! Most gates are inspected from the canonical constants defined in their
//! respective subsystems, so operators, diagnostics, and tests have a single
//! source of truth with zero duplicated literals. The upgrade-execution gate is
//! the exception: its EFFECTIVE value is [`GenesisChainSpec`], installed once
//! at genesis, with the compiled
//! [`crate::governance::UPGRADE_EXEC_ACTIVATION_HEIGHT`] as the default for
//! chains that do not set it.

use crate::consensus::{
    BEACON_DRAW_ACTIVATION_HEIGHT, CNVRF_V3_ACTIVATION_HEIGHT, QC_SPLIT_ACTIVATION_HEIGHT,
    QC_SPLIT_BY_SIZE_THRESHOLD,
};
use crate::consensus_net::COMPACT_GOSSIP_ACTIVATION_HEIGHT;
use crate::governance::UPGRADE_EXEC_ACTIVATION_HEIGHT;
use crate::mev_epoch::PQ_TRANSPORT_H_ACTIVATION_HEIGHT;
use crate::pq_registry::PQ_ROTATION_DELAY_HEIGHTS;
pub use crate::pq_registry::{
    effective_pq_lifecycle_activation_height, pq_lifecycle_active_at,
    PQ_LIFECYCLE_ACTIVATION_HEIGHT,
};
use crate::sharding::HEADER_COMMIT_ACTIVATION_HEIGHT;
use crate::state_engine::EVM_BINDINGS_STATE_ACTIVATION_HEIGHT;
use crate::tokenomics::EMISSIONCapEXACT_ACTIVATION_HEIGHT;
use crate::xshard2pc::XPC_ACTIVATION_HEIGHT;
use crate::zkml::DEFAULT_CHAIN_ID;

/// The compiled default for the upgrade-execution gate.
///
/// This is the value a chain gets when its genesis chain spec does not name
/// one. It is re-exported from [`crate::governance::UPGRADE_EXEC_ACTIVATION_HEIGHT`]
/// so there is exactly one compiled sentinel: `u64::MAX` (inert at every
/// reachable height) on chains that never opted in.
pub const DEFAULT_UPGRADE_EXEC_ACTIVATION_HEIGHT: u64 = UPGRADE_EXEC_ACTIVATION_HEIGHT;

/// Compiled default activation height for Ruleset v7 Execution Hardening v1
/// Ruleset v7 execution hardening activation height (`0` = active from genesis).
///
/// Covers `OpCode::Halt` barriers in block scanners, `SysCallCallContractArgs` /
/// `SysCallSubmitPqPriceFeed` rollback snapshots, `TX_INTRINSIC_GAS` minimum
/// billing, and CLOB `PlaceOrder`/`CancelOrder` gas & fill bounds.
pub const EXEC_HARDENING_V1_ACTIVATION_HEIGHT: u64 = 0;

/// Ruleset v7 WASM / XShard / PMM / Canonical-PQ1 Hardening activation height
/// (`0` = active from genesis).
///
/// Covers `SubCallSnapshot`, `caller()` vs `origin()`, `outbound_messages`
/// post-commit atomicity + `sync_contract_balance` + bounce conservation,
/// `deploy_with_nonce(tx.nonce)`, `validate_code`/`send_message` fuel,
/// `PMM`/`GenesisVault` `ZeroMint`/`ZeroPayout`, `cross_shard_completed` guard,
/// and strict canonical `PQ1` envelope decoding.
pub const WASM_XSHARD_PMM_HARDENING_ACTIVATION_HEIGHT: u64 = 0;

#[cfg(any(test, debug_assertions))]
thread_local! {
    static EXEC_HARDENING_V1_ACTIVATION_OVERRIDE: std::cell::Cell<Option<u64>> =
        const { std::cell::Cell::new(None) };
    static WASM_XSHARD_PMM_HARDENING_ACTIVATION_OVERRIDE: std::cell::Cell<Option<u64>> =
        const { std::cell::Cell::new(None) };
}

/// Set (or clear with `None`) the TEST-ONLY `EXEC_HARDENING_V1` activation
/// height override for the calling thread.
#[cfg(any(test, debug_assertions))]
pub fn set_exec_hardening_v1_activation_override(activation: Option<u64>) {
    EXEC_HARDENING_V1_ACTIVATION_OVERRIDE.with(|c| c.set(activation));
}

/// Set (or clear with `None`) the TEST-ONLY `WASM_XSHARD_PMM_HARDENING`
/// activation height override for the calling thread.
#[cfg(any(test, debug_assertions))]
pub fn set_wasm_xshard_pmm_hardening_activation_override(activation: Option<u64>) {
    WASM_XSHARD_PMM_HARDENING_ACTIVATION_OVERRIDE.with(|c| c.set(activation));
}

/// Effective `EXEC_HARDENING_V1` activation height for the calling thread.
pub fn exec_hardening_v1_activation_height() -> u64 {
    #[cfg(any(test, debug_assertions))]
    if let Some(h) = EXEC_HARDENING_V1_ACTIVATION_OVERRIDE.with(|c| c.get()) {
        return h;
    }
    EXEC_HARDENING_V1_ACTIVATION_HEIGHT
}

/// Effective `WASM_XSHARD_PMM_HARDENING` activation height for the calling thread.
pub fn wasm_xshard_pmm_hardening_activation_height() -> u64 {
    #[cfg(any(test, debug_assertions))]
    if let Some(h) = WASM_XSHARD_PMM_HARDENING_ACTIVATION_OVERRIDE.with(|c| c.get()) {
        return h;
    }
    WASM_XSHARD_PMM_HARDENING_ACTIVATION_HEIGHT
}

/// True iff `EXEC_HARDENING_V1` is active at `height`.
///
/// Strictly returns `false` for EVERY height (including `u64::MAX`) when the
/// effective gate is `u64::MAX` (`GatedOff`).
pub fn exec_hardening_v1_active_at(height: u64) -> bool {
    let gate = exec_hardening_v1_activation_height();
    gate != u64::MAX && height >= gate
}

/// True iff `WASM_XSHARD_PMM_HARDENING` is active at `height`.
///
/// Strictly returns `false` for EVERY height (including `u64::MAX`) when the
/// effective gate is `u64::MAX` (`GatedOff`).
pub fn wasm_xshard_pmm_hardening_active_at(height: u64) -> bool {
    let gate = wasm_xshard_pmm_hardening_activation_height();
    gate != u64::MAX && height >= gate
}

/// The parts of a chain's identity that are fixed when genesis is built.
///
/// Today the only field is the upgrade-execution activation height. It is
/// deliberately a *genesis* value, not an env knob: two nodes that disagree
/// about `upgrade_exec_activation_height` would disagree about whether a
/// passed `SoftwareUpgrade` installs its plan at a given height, which is a
/// consensus fork. [`install_genesis_chain_spec`] therefore allows exactly
/// one install per process, before any block is applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenesisChainSpec {
    /// Height at/above which `SoftwareUpgrade` plan installation is enabled.
    /// `CancelUpgrade` is a safety valve and stays available below it.
    /// `u64::MAX` is the compiled default (off).
    pub upgrade_exec_activation_height: u64,
}

impl GenesisChainSpec {
    /// Build a chain spec with an explicit upgrade-execution gate.
    pub const fn new(upgrade_exec_activation_height: u64) -> Self {
        Self {
            upgrade_exec_activation_height,
        }
    }

    /// The chain spec used when a chain does not set a value: the compiled
    /// [`DEFAULT_UPGRADE_EXEC_ACTIVATION_HEIGHT`] (`u64::MAX`, inert).
    pub const fn compiled_default() -> Self {
        Self::new(DEFAULT_UPGRADE_EXEC_ACTIVATION_HEIGHT)
    }

    /// True once the gate is open at `height` (`>=` activation semantics).
    pub const fn upgrade_exec_active_at(&self, height: u64) -> bool {
        height >= self.upgrade_exec_activation_height
    }
}

impl Default for GenesisChainSpec {
    fn default() -> Self {
        Self::compiled_default()
    }
}

/// The process-wide genesis chain spec. Installed at most once, before the
/// first block is applied; otherwise every read falls back to
/// [`GenesisChainSpec::compiled_default`].
static INSTALLED_GENESIS_CHAIN_SPEC: std::sync::OnceLock<GenesisChainSpec> =
    std::sync::OnceLock::new();

/// Fix the genesis chain spec for this process.
///
/// Returns `true` when this call installed the spec and `false` when one was
/// already installed (the first install wins; a second, different value is
/// never silently accepted). Call this BEFORE applying any block, with the
/// value covered by the chain's genesis identity. This module cannot enforce
/// that by itself: see the genesis-fingerprint guard and the note in
/// `docs/UPGRADE_AND_RECOVERY.md` §1.2.2.
pub fn install_genesis_chain_spec(spec: GenesisChainSpec) -> bool {
    INSTALLED_GENESIS_CHAIN_SPEC.set(spec).is_ok()
}

/// The genesis chain spec in force for this process/thread.
///
/// Precedence: the thread-scoped test/debug override (if any), then the
/// once-installed genesis spec, then the compiled default.
pub fn active_genesis_chain_spec() -> GenesisChainSpec {
    #[cfg(any(test, debug_assertions))]
    if let Some(spec) = GENESIS_CHAIN_SPEC_OVERRIDE.with(|c| c.get()) {
        return spec;
    }
    INSTALLED_GENESIS_CHAIN_SPEC
        .get()
        .copied()
        .unwrap_or_else(GenesisChainSpec::compiled_default)
}

// TEST-ONLY, thread-scoped override of the whole genesis chain spec (the
// `QC_SPLIT_ACTIVATION_HEIGHT` pattern used throughout the tree). Release
// builds have no override, so a process that never installs one behaves
// byte-identically to the compiled default.
#[cfg(any(test, debug_assertions))]
thread_local! {
    static GENESIS_CHAIN_SPEC_OVERRIDE: std::cell::Cell<Option<GenesisChainSpec>> =
        const { std::cell::Cell::new(None) };
}

/// Set (or clear with `None`) the TEST-ONLY genesis chain spec for the
/// CALLING THREAD. Available in test/debug builds only.
#[cfg(any(test, debug_assertions))]
pub fn set_genesis_chain_spec_override(spec: Option<GenesisChainSpec>) {
    GENESIS_CHAIN_SPEC_OVERRIDE.with(|c| c.set(spec));
}

/// Set (or clear with `None`) the TEST-ONLY genesis chain spec's
/// upgrade-execution gate for the CALLING THREAD. Kept as the narrow form of
/// [`set_genesis_chain_spec_override`] for existing upgrade tests.
#[cfg(any(test, debug_assertions))]
pub fn set_upgrade_exec_activation_override(activation: Option<u64>) {
    set_genesis_chain_spec_override(activation.map(GenesisChainSpec::new));
}

/// The upgrade-execution activation height in force: the genesis chain
/// spec's value. This is the ONE source of truth read by
/// [`crate::governance::upgrade_exec_active_at`] and every execution path.
pub fn upgrade_exec_activation_height() -> u64 {
    active_genesis_chain_spec().upgrade_exec_activation_height
}

/// True once the upgrade-execution gate is open at `height`.
pub fn upgrade_exec_active_at(height: u64) -> bool {
    active_genesis_chain_spec().upgrade_exec_active_at(height)
}

/// Activation status derived from a height-gated `u64` constant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivationStatus {
    /// Active starting at block height `0`.
    ActiveFromGenesis,
    /// Inactive below the height, active at/above the height.
    ActiveAt(u64),
    /// Disabled sentinel (`u64::MAX`), inactive at all reachable heights.
    GatedOff,
}

/// Metadata and current activation height for a single height-gated feature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActivationGate {
    pub name: &'static str,
    pub module: &'static str,
    pub activation_height: u64,
    pub status: ActivationStatus,
    pub note: &'static str,
}

impl ActivationGate {
    /// Construct an [`ActivationGate`], deriving [`ActivationStatus`] strictly
    /// from `activation_height` (`0` -> `ActiveFromGenesis`, `u64::MAX` ->
    /// `GatedOff`, otherwise `ActiveAt(h)`).
    pub const fn new(
        name: &'static str,
        module: &'static str,
        activation_height: u64,
        note: &'static str,
    ) -> Self {
        let status = match activation_height {
            0 => ActivationStatus::ActiveFromGenesis,
            u64::MAX => ActivationStatus::GatedOff,
            h => ActivationStatus::ActiveAt(h),
        };
        Self {
            name,
            module,
            activation_height,
            status,
            note,
        }
    }

    /// Whether this gate is active at `height`.
    pub const fn is_active_at(&self, height: u64) -> bool {
        match self.status {
            ActivationStatus::ActiveFromGenesis => true,
            ActivationStatus::ActiveAt(h) => height >= h,
            ActivationStatus::GatedOff => false,
        }
    }
}

/// Snapshot of the binary's compile-time chain defaults and height gates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainActivationSchedule {
    pub default_chain_id: u64,
    pub pq_rotation_delay_heights: u64,
    pub gates: Vec<ActivationGate>,
    /// Validator-set size at/above which the full-network QC (epoch/CEC) is
    /// mandatory — the C1 split's SIZE leg
    /// (`consensus::sortition::QC_SPLIT_BY_SIZE_THRESHOLD`, review F1). Not a
    /// height gate, so it lives beside `gates` rather than inside one.
    pub qc_split_by_size_threshold: usize,
}

impl ChainActivationSchedule {
    /// Returns whether the named gate is active at `height`, or `None` if no
    /// gate with `name` exists in this schedule.
    pub fn is_active(&self, name: &str, height: u64) -> Option<bool> {
        self.gates
            .iter()
            .find(|gate| gate.name == name)
            .map(|gate| gate.is_active_at(height))
    }

    /// Human-readable summary lines describing the chain defaults and every
    /// tracked activation gate.
    pub fn summary_lines(&self) -> Vec<String> {
        let mut lines = Vec::with_capacity(self.gates.len() + 1);
        lines.push(format!(
            "chain_spec: default_chain_id={}, pq_rotation_delay_heights={}, \
             qc_split_by_size_threshold={}",
            self.default_chain_id, self.pq_rotation_delay_heights, self.qc_split_by_size_threshold
        ));
        lines.push(format!(
            "QC_SPLIT_BY_SIZE_THRESHOLD [stellereum::consensus::sortition]: \
             mandatory_at_set_size({}) — full-network QC (CEC) required at/above \
             this validator count (review F1)",
            self.qc_split_by_size_threshold
        ));
        for gate in &self.gates {
            let status_desc = match gate.status {
                ActivationStatus::ActiveFromGenesis => "active_from_genesis (0)".to_string(),
                ActivationStatus::ActiveAt(h) => format!("active_at({h})"),
                ActivationStatus::GatedOff => "gated_off (u64::MAX)".to_string(),
            };
            lines.push(format!(
                "{} [{}]: {} — {}",
                gate.name, gate.module, status_desc, gate.note
            ));
        }
        lines
    }
}

/// Build the current compile-time activation schedule directly from the
/// canonical constants in `stellereum` and `infnode`.
pub fn current_activation_schedule() -> ChainActivationSchedule {
    ChainActivationSchedule {
        default_chain_id: DEFAULT_CHAIN_ID,
        pq_rotation_delay_heights: PQ_ROTATION_DELAY_HEIGHTS,
        qc_split_by_size_threshold: QC_SPLIT_BY_SIZE_THRESHOLD,
        gates: vec![
            ActivationGate::new(
                "QC_SPLIT_ACTIVATION_HEIGHT",
                "stellereum::consensus::sortition",
                QC_SPLIT_ACTIVATION_HEIGHT,
                "C1 micro-QC advisory vs full-network QC finality split",
            ),
            ActivationGate::new(
                "BEACON_DRAW_ACTIVATION_HEIGHT",
                "stellereum::consensus::sortition",
                BEACON_DRAW_ACTIVATION_HEIGHT,
                "Epoch-bound XMSS-VRF beacon committee draw",
            ),
            ActivationGate::new(
                "CNVRF_V3_ACTIVATION_HEIGHT",
                "stellereum::consensus::sortition",
                CNVRF_V3_ACTIVATION_HEIGHT,
                "30,000-block epoch CN-VRF v3 sortition and proposer beacon draw (ruleset v2 rescaled EPOCH_LEN from 7,200)",
            ),
            ActivationGate::new(
                "COMPACT_GOSSIP_ACTIVATION_HEIGHT",
                "stellereum::consensus_net",
                COMPACT_GOSSIP_ACTIVATION_HEIGHT,
                "Bitfield-indexed compact micro-QC gossip codec",
            ),
            ActivationGate::new(
                "EMISSIONCapEXACT_ACTIVATION_HEIGHT",
                "stellereum::tokenomics",
                EMISSIONCapEXACT_ACTIVATION_HEIGHT,
                "Cap-exact geometric block emission schedule",
            ),
            ActivationGate::new(
                "PQ_TRANSPORT_H_ACTIVATION_HEIGHT",
                "stellereum::mev_epoch",
                PQ_TRANSPORT_H_ACTIVATION_HEIGHT,
                "MEV DKG Falcon-authenticated ML-KEM-768 transport cutoff",
            ),
            ActivationGate::new(
                "XPC_ACTIVATION_HEIGHT",
                "stellereum::xshard2pc",
                XPC_ACTIVATION_HEIGHT,
                "Cross-shard two-phase commit (active from genesis: new transfers use prepare/vote/commit)",
            ),
            ActivationGate::new(
                "UPGRADE_EXEC_ACTIVATION_HEIGHT",
                "stellereum::chain_spec",
                upgrade_exec_activation_height(),
                "On-chain SoftwareUpgrade plan installation (genesis chain-spec value; compiled default is u64::MAX)",
            ),
            ActivationGate::new(
                "EXEC_HARDENING_V1_ACTIVATION_HEIGHT",
                "stellereum::state_engine::apply",
                exec_hardening_v1_activation_height(),
                "Ruleset v7 execution hardening: Halt barrier in scanners, CallContractArgs/SubmitPqPriceFeed rollback, TX_INTRINSIC_GAS floor, CLOB fill/cancel gas",
            ),
            ActivationGate::new(
                "WASM_XSHARD_PMM_HARDENING_ACTIVATION_HEIGHT",
                "stellereum::chain_spec",
                wasm_xshard_pmm_hardening_activation_height(),
                "Ruleset v7 WASM/XShard/PMM/PQ1 hardening: SubCallSnapshot, caller vs origin, outbound post-commit + balance sync, deploy_with_nonce, PMM ZeroMint/ZeroPayout, canonical PQ1",
            ),
            ActivationGate::new(
                "HEADER_COMMIT_ACTIVATION_HEIGHT",
                "stellereum::sharding::block",
                HEADER_COMMIT_ACTIVATION_HEIGHT,
                "Ruleset v7 two-level BlockHeader v4 + body_commitment binding state_root and prev_hash into block_hash",
            ),
            ActivationGate::new(
                "EVM_BINDINGS_STATE_ACTIVATION_HEIGHT",
                "stellereum::state_engine",
                EVM_BINDINGS_STATE_ACTIVATION_HEIGHT,
                "Ruleset v7 canonical Domain::EvmBindings state commitment and deterministic first-writer-wins apply",
            ),
            ActivationGate::new(
                "PQ_LIFECYCLE_ACTIVATION_HEIGHT",
                "stellereum::pq_registry",
                PQ_LIFECYCLE_ACTIVATION_HEIGHT,
                "Ruleset v7 PQ validator lifecycle: 3-key separation (withdrawal_address), Falcon-512 PoP rotation, and 720k-height evidence retention",
            ),
            ActivationGate::new(
                "BRIDGE_V2_ACTIVATION_HEIGHT",
                "stellereum::bridge",
                crate::bridge::BRIDGE_V2_ACTIVATION_HEIGHT,
                "Ruleset v7 bridge release authorization: verified payout receipts (ReleaseProof), refund tombstones, challengeable quorum-anchored deposits, retraction precedence",
            ),
            ActivationGate::new(
                "FEE_MARKET_V2_ACTIVATION_HEIGHT",
                "stellereum::tokenomics",
                crate::tokenomics::FEE_MARKET_V2_ACTIVATION_HEIGHT,
                "Ruleset v7 fee market: priority_fee_per_gas charge in apply plus burn/proposer/staking split",
            ),
            ActivationGate::new(
                "SUB_NANO_STRICT_ACTIVATION_HEIGHT",
                "stellereum::tokenomics",
                crate::tokenomics::SUB_NANO_STRICT_ACTIVATION_HEIGHT,
                "Ruleset v7 sub-nano exactness: EVM wei carrier boundary, reward-accumulator rescale carry, Q0.64 emission carry",
            ),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn gated_off_corresponds_strictly_to_u64_max() {
        assert_eq!(
            ActivationGate::new("g_max", "test", u64::MAX, "off").status,
            ActivationStatus::GatedOff
        );
        assert_eq!(
            ActivationGate::new("g_zero", "test", 0, "genesis").status,
            ActivationStatus::ActiveFromGenesis
        );
        assert_eq!(
            ActivationGate::new("g_one", "test", 1, "one").status,
            ActivationStatus::ActiveAt(1)
        );
        assert_eq!(
            ActivationGate::new("g_near_max", "test", u64::MAX - 1, "near_max").status,
            ActivationStatus::ActiveAt(u64::MAX - 1)
        );

        let schedule = current_activation_schedule();
        for gate in &schedule.gates {
            assert_eq!(
                gate.status == ActivationStatus::GatedOff,
                gate.activation_height == u64::MAX,
                "gate {} violated strict u64::MAX <-> GatedOff correspondence",
                gate.name
            );
            if gate.status == ActivationStatus::GatedOff {
                assert_eq!(schedule.is_active(gate.name, 0), Some(false));
                assert_eq!(schedule.is_active(gate.name, u64::MAX), Some(false));
            }
        }
    }

    /// The operator-visible gate comes from the genesis chain spec, not from a
    /// second hard-coded sentinel: setting a chain spec moves the registered
    /// gate and `upgrade_exec_active_at` together.
    #[test]
    fn upgrade_exec_gate_is_registered_from_the_genesis_chain_spec() {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                set_genesis_chain_spec_override(None);
            }
        }
        let _reset = Reset;
        assert_eq!(
            upgrade_exec_activation_height(),
            DEFAULT_UPGRADE_EXEC_ACTIVATION_HEIGHT
        );
        set_genesis_chain_spec_override(Some(GenesisChainSpec::new(4_242)));
        let schedule = current_activation_schedule();
        let below = schedule.is_active("UPGRADE_EXEC_ACTIVATION_HEIGHT", 4_241);
        let at = schedule.is_active("UPGRADE_EXEC_ACTIVATION_HEIGHT", 4_242);
        let active_below = upgrade_exec_active_at(4_241);
        let active_at = upgrade_exec_active_at(4_242);

        assert_eq!(below, Some(false));
        assert_eq!(at, Some(true));
        assert!(!active_below);
        assert!(active_at);
        let gate = schedule
            .gates
            .iter()
            .find(|g| g.name == "UPGRADE_EXEC_ACTIVATION_HEIGHT")
            .expect("the upgrade gate must be registered");
        assert_eq!(gate.module, "stellereum::chain_spec");
        assert_eq!(gate.activation_height, 4_242);
    }

    #[test]
    fn all_gate_names_are_unique() {
        let schedule = current_activation_schedule();
        let mut seen = HashSet::new();
        for gate in &schedule.gates {
            assert!(!gate.name.is_empty());
            assert!(!gate.module.is_empty());
            assert!(!gate.note.is_empty());
            assert!(seen.insert(gate.name), "duplicate gate name: {}", gate.name);
        }
        assert_eq!(seen.len(), schedule.gates.len());
    }

    #[test]
    fn current_activation_schedule_matches_module_constants() {
        let schedule = current_activation_schedule();
        assert_eq!(schedule.default_chain_id, DEFAULT_CHAIN_ID);
        assert_eq!(
            schedule.pq_rotation_delay_heights,
            PQ_ROTATION_DELAY_HEIGHTS
        );
        assert_eq!(
            schedule.qc_split_by_size_threshold, QC_SPLIT_BY_SIZE_THRESHOLD,
            "the C1 split's size leg must be registered from its owning constant"
        );
        // The registered value is the F1 crossing point: 191 is the last size
        // a 128-seat committee can still carry, 192 the first it cannot.
        assert_eq!(schedule.qc_split_by_size_threshold, 192);

        let expected = [
            ("QC_SPLIT_ACTIVATION_HEIGHT", QC_SPLIT_ACTIVATION_HEIGHT),
            (
                "COMPACT_GOSSIP_ACTIVATION_HEIGHT",
                COMPACT_GOSSIP_ACTIVATION_HEIGHT,
            ),
            (
                "EMISSIONCapEXACT_ACTIVATION_HEIGHT",
                EMISSIONCapEXACT_ACTIVATION_HEIGHT,
            ),
            (
                "BEACON_DRAW_ACTIVATION_HEIGHT",
                BEACON_DRAW_ACTIVATION_HEIGHT,
            ),
            ("CNVRF_V3_ACTIVATION_HEIGHT", CNVRF_V3_ACTIVATION_HEIGHT),
            (
                "PQ_TRANSPORT_H_ACTIVATION_HEIGHT",
                PQ_TRANSPORT_H_ACTIVATION_HEIGHT,
            ),
            ("XPC_ACTIVATION_HEIGHT", XPC_ACTIVATION_HEIGHT),
            (
                "UPGRADE_EXEC_ACTIVATION_HEIGHT",
                DEFAULT_UPGRADE_EXEC_ACTIVATION_HEIGHT,
            ),
            (
                "EXEC_HARDENING_V1_ACTIVATION_HEIGHT",
                EXEC_HARDENING_V1_ACTIVATION_HEIGHT,
            ),
            (
                "WASM_XSHARD_PMM_HARDENING_ACTIVATION_HEIGHT",
                WASM_XSHARD_PMM_HARDENING_ACTIVATION_HEIGHT,
            ),
            (
                "HEADER_COMMIT_ACTIVATION_HEIGHT",
                HEADER_COMMIT_ACTIVATION_HEIGHT,
            ),
            (
                "EVM_BINDINGS_STATE_ACTIVATION_HEIGHT",
                EVM_BINDINGS_STATE_ACTIVATION_HEIGHT,
            ),
            (
                "PQ_LIFECYCLE_ACTIVATION_HEIGHT",
                PQ_LIFECYCLE_ACTIVATION_HEIGHT,
            ),
            (
                "BRIDGE_V2_ACTIVATION_HEIGHT",
                crate::bridge::BRIDGE_V2_ACTIVATION_HEIGHT,
            ),
            (
                "FEE_MARKET_V2_ACTIVATION_HEIGHT",
                crate::tokenomics::FEE_MARKET_V2_ACTIVATION_HEIGHT,
            ),
            (
                "SUB_NANO_STRICT_ACTIVATION_HEIGHT",
                crate::tokenomics::SUB_NANO_STRICT_ACTIVATION_HEIGHT,
            ),
        ];

        assert_eq!(schedule.gates.len(), expected.len());
        for (name, constant_height) in expected {
            let gate = schedule
                .gates
                .iter()
                .find(|g| g.name == name)
                .unwrap_or_else(|| panic!("missing gate {name}"));
            assert_eq!(gate.activation_height, constant_height);
            assert_eq!(
                gate.status,
                ActivationGate::new(gate.name, gate.module, constant_height, gate.note).status
            );
        }

        for r2_r4_gate in [
            "EXEC_HARDENING_V1_ACTIVATION_HEIGHT",
            "WASM_XSHARD_PMM_HARDENING_ACTIVATION_HEIGHT",
            "HEADER_COMMIT_ACTIVATION_HEIGHT",
            "EVM_BINDINGS_STATE_ACTIVATION_HEIGHT",
            "PQ_LIFECYCLE_ACTIVATION_HEIGHT",
            "BRIDGE_V2_ACTIVATION_HEIGHT",
            "FEE_MARKET_V2_ACTIVATION_HEIGHT",
            "SUB_NANO_STRICT_ACTIVATION_HEIGHT",
        ] {
            let gate = schedule
                .gates
                .iter()
                .find(|g| g.name == r2_r4_gate)
                .expect("Ruleset v7 gate must be registered");
            assert_eq!(gate.activation_height, 0);
            assert_eq!(gate.status, ActivationStatus::ActiveFromGenesis);
        }
    }

    #[test]
    fn is_active_respects_boundaries_and_unknown_names() {
        let schedule = current_activation_schedule();

        assert_eq!(schedule.is_active("NONEXISTENT_GATE", 0), None);
        assert_eq!(schedule.is_active("NONEXISTENT_GATE", u64::MAX), None);

        assert_eq!(
            schedule.is_active(
                "PQ_TRANSPORT_H_ACTIVATION_HEIGHT",
                PQ_TRANSPORT_H_ACTIVATION_HEIGHT.saturating_sub(1)
            ),
            Some(false)
        );
        assert_eq!(
            schedule.is_active(
                "PQ_TRANSPORT_H_ACTIVATION_HEIGHT",
                PQ_TRANSPORT_H_ACTIVATION_HEIGHT
            ),
            Some(true)
        );

        let genesis_schedule = ChainActivationSchedule {
            default_chain_id: DEFAULT_CHAIN_ID,
            pq_rotation_delay_heights: PQ_ROTATION_DELAY_HEIGHTS,
            qc_split_by_size_threshold: QC_SPLIT_BY_SIZE_THRESHOLD,
            gates: vec![ActivationGate::new(
                "GENESIS_GATE",
                "test",
                0,
                "active from genesis",
            )],
        };
        assert_eq!(genesis_schedule.is_active("GENESIS_GATE", 0), Some(true));
        assert_eq!(
            genesis_schedule.is_active("GENESIS_GATE", u64::MAX),
            Some(true)
        );
    }

    #[test]
    fn xpc_gate_matches_the_runtime_switch() {
        let schedule = current_activation_schedule();
        let gate = schedule
            .gates
            .iter()
            .find(|g| g.name == "XPC_ACTIVATION_HEIGHT")
            .expect("the 2PC gate must be registered in the chain spec");
        assert_eq!(gate.activation_height, XPC_ACTIVATION_HEIGHT);
        assert_eq!(gate.module, "stellereum::xshard2pc");
        // Active from genesis: the compiled gate arms the 2PC at height 0.
        assert_eq!(gate.status, ActivationStatus::ActiveFromGenesis);
        for height in [0, 1, u64::MAX - 1, u64::MAX] {
            assert_eq!(
                schedule.is_active("XPC_ACTIVATION_HEIGHT", height),
                Some(true)
            );
        }
        // The production switch derived from the SAME constant can never be
        // half-armed: it is `FromHeight(0)`, not `Disabled`.
        let activation = crate::xshard2pc::XpcActivation::from_chain_spec();
        assert_eq!(activation, crate::xshard2pc::XpcActivation::FromHeight(0));
        assert_eq!(activation.boundary(), Some(0));
        assert_eq!(gate.is_active_at(0), activation.is_active_at(0));
        assert!(activation.is_active_at(0));
    }

    #[test]
    fn summary_lines_includes_header_and_all_gates() {
        let schedule = current_activation_schedule();
        let lines = schedule.summary_lines();
        // Header + the size-leg line + one line per height gate.
        assert_eq!(lines.len(), schedule.gates.len() + 2);
        assert!(lines[0].contains(&schedule.default_chain_id.to_string()));
        assert!(lines[0].contains(&schedule.pq_rotation_delay_heights.to_string()));
        assert!(lines[1].contains("QC_SPLIT_BY_SIZE_THRESHOLD"));
        assert!(lines[1].contains(&schedule.qc_split_by_size_threshold.to_string()));

        for (gate, line) in schedule.gates.iter().zip(lines.iter().skip(2)) {
            assert!(line.contains(gate.name));
            assert!(line.contains(gate.module));
        }
    }

    #[test]
    fn r1_hardening_gates_default_active_from_genesis_and_respect_overrides() {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                set_exec_hardening_v1_activation_override(None);
                set_wasm_xshard_pmm_hardening_activation_override(None);
            }
        }
        let _reset = Reset;

        assert_eq!(exec_hardening_v1_activation_height(), 0);
        assert_eq!(wasm_xshard_pmm_hardening_activation_height(), 0);
        assert!(exec_hardening_v1_active_at(0));
        assert!(exec_hardening_v1_active_at(u64::MAX));
        assert!(wasm_xshard_pmm_hardening_active_at(0));
        assert!(wasm_xshard_pmm_hardening_active_at(u64::MAX));

        set_exec_hardening_v1_activation_override(Some(u64::MAX));
        set_wasm_xshard_pmm_hardening_activation_override(Some(u64::MAX));
        assert!(!exec_hardening_v1_active_at(0));
        assert!(!exec_hardening_v1_active_at(u64::MAX));
        assert!(!wasm_xshard_pmm_hardening_active_at(0));
        assert!(!wasm_xshard_pmm_hardening_active_at(u64::MAX));

        set_exec_hardening_v1_activation_override(Some(10));
        set_wasm_xshard_pmm_hardening_activation_override(Some(10));
        assert!(!exec_hardening_v1_active_at(9));
        assert!(exec_hardening_v1_active_at(10));
        assert!(exec_hardening_v1_active_at(11));
        assert!(exec_hardening_v1_active_at(u64::MAX));
        assert!(!wasm_xshard_pmm_hardening_active_at(9));
        assert!(wasm_xshard_pmm_hardening_active_at(10));
        assert!(wasm_xshard_pmm_hardening_active_at(11));
        assert!(wasm_xshard_pmm_hardening_active_at(u64::MAX));
    }
}
