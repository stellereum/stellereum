//! Machine-readable activation gates (Wave 2 deliverable).
//!
//! Every height-gated protocol change lives in [`crate::chain_spec`] as a
//! `*_ACTIVATION_HEIGHT` / `*_HEIGHT` constant. A constant is fine for the code
//! and useless for an operator or an auditor, who need three things at once:
//! **which gate**, **what height it activates at**, and **which test proves the
//! behaviour behind it**. This module is the single source of truth for that
//! table; `stellereum gates` prints it and `stellereum gates --yaml` renders the
//! committed manifest `docs/feature_gates.yaml`, which a test pins to this file
//! so the document cannot drift from the code.
//!
//! Semantics of `value`:
//! * a concrete height — the gate turns on there;
//! * `0` — already active on this chain (activated at genesis);
//! * [`u64::MAX`] — deliberately inert; the code path exists but is not armed.

use crate::chain_spec;

/// One row of the gate table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gate {
    /// Stable identifier used by docs, CI and operators.
    pub id: &'static str,
    /// The Rust constant this row describes.
    pub symbol: &'static str,
    /// Current activation height (`0` = genesis, `u64::MAX` = inert).
    pub value: u64,
    /// Regression test that proves the gated behaviour, if one exists.
    pub test: Option<&'static str>,
    /// Why the gate exists / what must be true before arming it.
    pub note: &'static str,
}

impl Gate {
    /// `ACTIVE`, `INERT` (never fires) or `SCHEDULED` (a real future height).
    pub fn status(&self) -> &'static str {
        if self.value == u64::MAX {
            "INERT"
        } else if self.value == 0 {
            "ACTIVE"
        } else {
            "SCHEDULED"
        }
    }
}

/// The authoritative gate table. Keep in sync with `chain_spec` — the values are
/// read from the constants themselves, not duplicated.
pub fn table() -> Vec<Gate> {
    vec![
        Gate {
            id: "exec-hardening-v1",
            symbol: "EXEC_HARDENING_V1_ACTIVATION_HEIGHT",
            value: chain_spec::EXEC_HARDENING_V1_ACTIVATION_HEIGHT,
            test: Some("tests/r1_frozen_apply_svm_tests.rs"),
            note: "Hardened execution rules for the VM surface.",
        },
        Gate {
            id: "wasm-xshard-pmm-hardening",
            symbol: "WASM_XSHARD_PMM_HARDENING_ACTIVATION_HEIGHT",
            value: chain_spec::WASM_XSHARD_PMM_HARDENING_ACTIVATION_HEIGHT,
            test: Some("tests/r1_wasm_hardening_tests.rs"),
            note: "Cross-shard PMM hardening (fuel/limit accounting).",
        },
        Gate {
            id: "wasm-xshard-contract-send-refusal",
            symbol: "WASM_XSHARD_CONTRACT_SEND_REFUSAL_HEIGHT",
            value: chain_spec::WASM_XSHARD_CONTRACT_SEND_REFUSAL_HEIGHT,
            test: Some("tests/review_final_cross_shard_contract_send.rs"),
            note: "Contracts may not emit cross-shard sends they cannot account for.",
        },
        Gate {
            id: "wasm-table-elements-cap",
            symbol: "WASM_TABLE_ELEMENTS_CAP_HEIGHT",
            value: chain_spec::WASM_TABLE_ELEMENTS_CAP_HEIGHT,
            test: Some("tests/w7_svm_and_contracts_fixes.rs"),
            note: "Caps WASM table element counts (section-4 Table declarations and the \
                   wasmi StoreLimits table_elements budget) at MAX_CONTRACT_TABLE_ELEMENTS. \
                   INERT: consensus deploy/execute call sites route through validate_code_at \
                   / run_contract_hardened_at (byte-identical replay below H), and RPC \
                   pre-validation enforces the cap immediately. Before arming: pin replay \
                   of history that predates the cap and update tests/w4_engine_hardening_tests.rs.",
        },
        Gate {
            id: "falcon-host-fuel-v2",
            symbol: "FALCON_HOST_FUEL_V2_ACTIVATION_HEIGHT",
            value: chain_spec::FALCON_HOST_FUEL_V2_ACTIVATION_HEIGHT,
            test: Some("tests/w3_falcon_fuel_and_start_tests.rs"),
            note: "Raises host.falcon512_verify base fuel from FUEL_FALCON512_VERIFY (2_000) \
                   to FUEL_FALCON512_VERIFY_V2 (150_000, calibrated against the 50M block \
                   budget) and switches SysCallDeployContract to single-(start) validation \
                   while charging actual (start) fuel against caller gas_remaining. INERT \
                   at u64::MAX until calibrated bench numbers and rollout height are set.",
        },
        Gate {
            id: "contract-block-hash",
            symbol: "CONTRACT_BLOCK_HASH_ACTIVATION_HEIGHT",
            value: chain_spec::CONTRACT_BLOCK_HASH_ACTIVATION_HEIGHT,
            test: Some("tests/w3_activation_boundary_e2e_tests.rs"),
            note: "Exposes host.block_hash to contracts. Today the host call SUCCEEDS \
                   (~10 fuel) and returns 32 zero bytes because svm.rs substitutes zero \
                   while the gate is inert. The live apply path already threads \
                   block.prev_hash; what is missing is proof on the cross-node block path, \
                   across a reorg and across a restart, plus a decision for the \
                   single-tx / RPC-preview callers that would still pass zero.",
        },
        Gate {
            id: "bridge-target-address-cap",
            symbol: "BRIDGE_TARGET_ADDRESS_CAP_HEIGHT",
            value: chain_spec::BRIDGE_TARGET_ADDRESS_CAP_HEIGHT,
            test: Some("tests/w3_activation_boundary_e2e_tests.rs"),
            note: "128-byte cap on bridge target addresses. Enforced on Withdraw \
                   SETTLEMENT/parking, NOT on release (Release/Refund never inspect the \
                   length). Before arming: decide the rule for an already-parked \
                   oversized withdraw, and pin replay of history that predates the cap.",
        },
        Gate {
            id: "xshard-bounce-escrow",
            symbol: "XSHARD_BOUNCE_ESCROW_REQUIRED_HEIGHT",
            value: chain_spec::XSHARD_BOUNCE_ESCROW_REQUIRED_HEIGHT,
            test: None,
            note: "Requires a bounce escrow before a cross-shard transfer is accepted. \
                   BLOCKER: runtime/cluster.rs ChainState::apply_block still records every \
                   outbound unconditionally and refunds a timeout bounce without an \
                   escrow-leaf or 2PC check, so arming the gate today would refund money \
                   that was never escrowed. Also needs the {0,1} shard prerequisites and a \
                   fresh-genesis decision.",
        },
        Gate {
            id: "upgrade-exec",
            symbol: "DEFAULT_UPGRADE_EXEC_ACTIVATION_HEIGHT",
            value: chain_spec::DEFAULT_UPGRADE_EXEC_ACTIVATION_HEIGHT,
            test: Some("tests/upgrade_exec_gate_tests.rs"),
            note: "Governance-driven binary upgrade execution (exit 42 path).",
        },
        Gate {
            id: "actor-mailbox-hardening",
            symbol: "ACTOR_MAILBOX_HARDENING_HEIGHT",
            value: chain_spec::ACTOR_MAILBOX_HARDENING_HEIGHT,
            test: Some("tests/w7_svm_and_contracts_fixes.rs"),
            note: "Hardens actor mailbox delivery (rejects asset-debiting/state-mutating \
                   opcodes in non-self ActorSendBody deliveries and restricts ctx.balance to \
                   msg.value) and bounds/bills contract host.send_message ActorSendBody \
                   gas_budget <= MAX_CONTRACT_ACTOR_GAS_BUDGET (1_000_000) + GAS_ACTOR_DELIVER. \
                   INERT at u64::MAX for byte-identical legacy replay below H.",
        },
        Gate {
            id: "sortition-unbiased",
            symbol: "SORTITION_UNBIASED_ACTIVATION_HEIGHT",
            value: chain_spec::SORTITION_UNBIASED_ACTIVATION_HEIGHT,
            test: Some("tests/w10_sortition_and_jail_gates_tests.rs"),
            note:
                "Replaces modulo reduction in committee sortition (select_committee_from_seed_at) \
                   and proposer selection (proposer_from_digest_at) with exact 64-bit rejection \
                   sampling to eliminate modulo bias on non-power-of-two stake totals (W6-A7-7). \
                   INERT at u64::MAX for byte-identical legacy replay below H.",
        },
        Gate {
            id: "jail-budget-v2",
            symbol: "JAIL_BUDGET_V2_ACTIVATION_HEIGHT",
            value: chain_spec::JAIL_BUDGET_V2_ACTIVATION_HEIGHT,
            test: Some("tests/w10_sortition_and_jail_gates_tests.rs"),
            note: "Raises StakingLedger::note_missed_heights downtime slash/jail threshold from \
                   DOWNTIME_MISS_THRESHOLD (42) to DOWNTIME_MISS_THRESHOLD_V2 (200 heights = 80s \
                   at 400ms cadence). INERT at u64::MAX for byte-identical legacy replay below H.",
        },
        Gate {
            id: "contract-abi-onchain",
            symbol: "CONTRACT_ABI_ONCHAIN_ACTIVATION_HEIGHT",
            value: chain_spec::CONTRACT_ABI_ONCHAIN_ACTIVATION_HEIGHT,
            test: Some("tests/w10_deploy_contract_abi_tests.rs"),
            note: "Enables OpCode::SysCallDeployContractWithAbi (discriminant 65) to validate \
                   and persist ContractAbi on-chain at deploy time (committed to ContractRegistry, \
                   state_root, and stell_getContractAbi). INERT at u64::MAX for byte-identical \
                   legacy replay below H.",
        },
        Gate {
            id: "execution-pipeline-v1",
            symbol: "EXECUTION_PIPELINE_V1_ACTIVATION_HEIGHT",
            value: chain_spec::EXECUTION_PIPELINE_V1_ACTIVATION_HEIGHT,
            test: Some("tests/w12_pipeline_gate_tests.rs"),
            note: "Moves the consensus<->execution state-root binding from lag 1 to lag 2: \
                   committed_state_height_at(H) becomes H-2 (was H-1) and a post-state at \
                   height S is anchored by the header at S+2 (was S+1) for block persistence, \
                   snapshot restore verification, archive historical roots, light-client \
                   checkpoints, the sync anchor walk, VecDeque apply_in_flight, ApplyLane \
                   penalty snapshots, PendingExecView, and proposer/adopt lag-2 gating \
                   (tests/w12_pipeline_runtime_state_tests.rs). INERT at u64::MAX: every \
                   helper returns lag-1 / S+1 values below the gate for byte-identical replay. \
                   Before arming: coordinate rollout height and pin full-chain replay.",
        },
    ]
}

/// Human table for `stellereum gates`.
pub fn render_table() -> String {
    let mut out = String::from("ID                                STATUS     VALUE      TEST\n");
    for g in table() {
        out.push_str(&format!(
            "{:<33} {:<10} {:<10} {}\n",
            g.id,
            g.status(),
            if g.value == u64::MAX {
                "u64::MAX".to_string()
            } else {
                g.value.to_string()
            },
            g.test.unwrap_or("MISSING")
        ));
    }
    out.push_str(
        "\nINERT = the code exists but the gate never fires (needs a test + an \
         activation height).\n",
    );
    out
}

/// The committed manifest. A test pins `docs/feature_gates.yaml` to this output.
pub fn render_yaml() -> String {
    let mut out = String::from(
        "# GENERATED by `stellereum gates --yaml`. Do not edit by hand.\n\
         # Source of truth: stellereum/src/feature_gates.rs (values from chain_spec).\n\
         gates:\n",
    );
    for g in table() {
        out.push_str(&format!("  - id: {}\n", g.id));
        out.push_str(&format!("    symbol: {}\n", g.symbol));
        out.push_str(&format!("    activation_height: {}\n", g.value));
        out.push_str(&format!("    status: {}\n", g.status()));
        out.push_str(&format!("    test: {}\n", g.test.unwrap_or("MISSING")));
        out.push_str(&format!("    note: {:?}\n", g.note));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_gate_has_a_unique_id_and_a_symbol_that_exists() {
        let t = table();
        let mut ids: Vec<&str> = t.iter().map(|g| g.id).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len(), "duplicate gate id");
        for g in &t {
            assert!(!g.id.is_empty() && !g.symbol.is_empty());
            assert!(!g.note.is_empty(), "{} needs a note", g.id);
            // A gate that is LIVE must name its proving test. An inert gate may
            // carry one (it often proves the pre-activation behaviour) or say
            // MISSING when it has none — which is exactly the signal the three
            // activation-debt rows are supposed to broadcast.
            if g.status() != "INERT" {
                assert!(g.test.is_some(), "{} is live without a test", g.id);
            }
        }
    }

    #[test]
    fn committed_manifest_matches_the_table() {
        let committed = include_str!("../../docs/feature_gates.yaml");
        assert_eq!(
            committed,
            render_yaml(),
            "docs/feature_gates.yaml drifted from src/feature_gates.rs; \
             regenerate with `stellereum gates --yaml`"
        );
    }
}
