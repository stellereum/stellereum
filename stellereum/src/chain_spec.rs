//! Read-only consolidated view of compile-time chain activation gates and
//! protocol defaults across `stellereum` and `infnode`.
//!
//! This module does NOT own or override any activation constants; it inspects
//! the canonical constants defined in their respective subsystems so operators,
//! diagnostics, and tests have a single source of truth with zero duplicated
//! literals.

use crate::consensus::{
    BEACON_DRAW_ACTIVATION_HEIGHT, CNVRF_V3_ACTIVATION_HEIGHT, QC_SPLIT_ACTIVATION_HEIGHT,
};
use crate::consensus_net::COMPACT_GOSSIP_ACTIVATION_HEIGHT;
use crate::mev_epoch::PQ_TRANSPORT_H_ACTIVATION_HEIGHT;
use crate::pq_registry::PQ_ROTATION_DELAY_HEIGHTS;
use crate::tokenomics::EMISSIONCapEXACT_ACTIVATION_HEIGHT;
use crate::zkml::DEFAULT_CHAIN_ID;
use infnode::proto::PQ_CLASSICAL_REFUSE_AFTER_HEIGHT;

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
            "chain_spec: default_chain_id={}, pq_rotation_delay_heights={}",
            self.default_chain_id, self.pq_rotation_delay_heights
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
                "7,200-block epoch CN-VRF v3 sortition and proposer beacon draw",
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
                "PQ_CLASSICAL_REFUSE_AFTER_HEIGHT",
                "infnode::proto",
                PQ_CLASSICAL_REFUSE_AFTER_HEIGHT,
                "Fail-closed refusal of classical infnode handshake fallback",
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
            (
                "PQ_CLASSICAL_REFUSE_AFTER_HEIGHT",
                PQ_CLASSICAL_REFUSE_AFTER_HEIGHT,
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

        assert_eq!(
            schedule.is_active(
                "PQ_CLASSICAL_REFUSE_AFTER_HEIGHT",
                PQ_CLASSICAL_REFUSE_AFTER_HEIGHT.saturating_sub(1)
            ),
            Some(false)
        );
        assert_eq!(
            schedule.is_active(
                "PQ_CLASSICAL_REFUSE_AFTER_HEIGHT",
                PQ_CLASSICAL_REFUSE_AFTER_HEIGHT
            ),
            Some(true)
        );

        let genesis_schedule = ChainActivationSchedule {
            default_chain_id: DEFAULT_CHAIN_ID,
            pq_rotation_delay_heights: PQ_ROTATION_DELAY_HEIGHTS,
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
    fn summary_lines_includes_header_and_all_gates() {
        let schedule = current_activation_schedule();
        let lines = schedule.summary_lines();
        assert_eq!(lines.len(), schedule.gates.len() + 1);
        assert!(lines[0].contains(&schedule.default_chain_id.to_string()));
        assert!(lines[0].contains(&schedule.pq_rotation_delay_heights.to_string()));

        for (gate, line) in schedule.gates.iter().zip(lines.iter().skip(1)) {
            assert!(line.contains(gate.name));
            assert!(line.contains(gate.module));
        }
    }
}
