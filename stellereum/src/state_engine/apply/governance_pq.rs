use super::super::GovOpsOutcome;
use super::super::InMemoryStateEngine;
use std::sync::atomic::Ordering;

impl InMemoryStateEngine {
    /// Whether block-carried gov ops apply at `height` on this instance: the
    /// test-only override OR the ratified activation height.
    /// [`crate::governance::GOV_OPS_ACTIVATION_HEIGHT`] is `0` (active from
    /// genesis), so every reachable height activates on every node
    /// identically. Pure function of instance state + the block height: no
    /// env reads, no wall clock.
    pub fn gov_ops_active_at(&self, height: u64) -> bool {
        self.gov_ops_tests_on.load(Ordering::Relaxed)
            || crate::governance::gov_ops_active_at(height)
    }

    /// Test-only switch: open the block-carried gov gate on this instance.
    ///
    /// Never called on the live path (only `tests/` call it). Live
    /// activation flips [`GOV_OPS_ACTIVATION_HEIGHT`], never this flag.
    pub fn enable_gov_ops_for_tests(&self) {
        self.gov_ops_tests_on.store(true, Ordering::Release);
    }

    // -----------------------------------------------------------------------
    // Block-carried governance ops (active from genesis; see
    // `GOV_OPS_ACTIVATION_HEIGHT`).
    //
    // The SVM dispatch arms for `SysCallGovPropose` / `SysCallGovVote` are
    // PURE CARRIERS (charge + push, no state); THIS scan is the authoritative
    // apply, mirroring the equivocation step-5b wiring above: it re-derives
    // every verdict from block bytes alone, in block order, so finalized /
    // adopted / walked / replayed / re-applied blocks converge identically.
    // A refused op is counted loudly and never fails the block (hostile
    // bytes cost the reporter gas in step 1, never the chain).
    // -----------------------------------------------------------------------

    /// Open one block-carried proposal: the UNGATED core of the propose arm.
    ///
    /// Calls the DIRECT path (`Governance::propose`) with the block as the
    /// clock (`now = block.timestamp`) and the tx signer as the proposer, so
    /// title/action/stake validation, the electorate snapshot and the
    /// proposer lock are byte-identical to the direct path. The tx must name
    /// exactly the proposal it opens (`proposal_id == gov.next_id`): a
    /// replayed or racing propose with an already-consumed id refuses BEFORE
    /// any state is read, and can never move `next_id` past an unconsumed
    /// one. Pure function of committed gov + ledger state and tx bytes.
    fn apply_gov_propose_inner(
        gov: &mut crate::governance::Governance,
        ledger: &mut crate::staking::StakingLedger,
        sender: [u8; 32],
        proposal_id: u64,
        title: String,
        action: crate::governance::GovAction,
        now: u64,
    ) -> Result<u64, String> {
        if proposal_id != gov.next_id {
            return Err(format!(
                "gov propose refused: proposal_id {proposal_id} does not match next proposal id {}",
                gov.next_id
            ));
        }
        let id = gov
            .propose(ledger, sender, title, action, now)
            .map_err(|e| format!("gov propose refused: {e}"))?;
        // `propose` assigns `next_id` then bumps it: any other id here means
        // the direct path changed under us — fail closed rather than commit
        // a proposal the tx did not name.
        if id != proposal_id {
            return Err(format!(
                "gov propose refused: opened proposal id {id} != named proposal_id {proposal_id}"
            ));
        }
        Ok(id)
    }

    /// Record one block-carried vote: the UNGATED core of the vote arm.
    ///
    /// Calls the DIRECT path (`Governance::vote`) with the block as the
    /// clock and the tx signer as the voter, so the voting-window check, the
    /// one-vote rule (a different choice refuses `AlreadyVoted`; a
    /// same-choice replay is idempotent, exactly as the direct path), the
    /// snapshot-weighted tally and the stake lock are byte-identical to the
    /// direct path. Pure function of committed gov + ledger state and tx bytes.
    fn apply_gov_vote_inner(
        gov: &mut crate::governance::Governance,
        ledger: &mut crate::staking::StakingLedger,
        voter: [u8; 32],
        proposal_id: u64,
        choice: crate::governance::VoteChoice,
        now: u64,
    ) -> Result<u128, String> {
        gov.vote(ledger, voter, proposal_id, choice, now)
            .map_err(|e| format!("gov vote refused: {e}"))
    }

    /// Apply every block-carried gov op in `block`, in block order.
    ///
    /// Deterministic end to end (the same purity contract as
    /// [`InMemoryStateEngine::apply_equivocation_slash`]): the ONLY inputs
    /// are the committed gov + staking state, the block bytes (opcodes, the
    /// `from` signer of each tx, `block.height`, `block.timestamp`) and the
    /// step-1 `status` receipts derived from the same block + state. No env
    /// reads, no wall clock (`now` is the block timestamp, never
    /// `SystemTime::now` — the wall clock was the determinism bug being
    /// removed). `status` parallels `block.transactions`: ops from a
    /// step-1-failed transaction apply nothing (their carriers never ran).
    ///
    /// Lock order mirrors the RPC direct path (`governance_write` then
    /// `staking_write`); both guards are held across one synchronous apply
    /// loop (no `.await` inside), so the scan is a single critical section.
    /// The two write accessors bump `commitment_generation`, so an applied
    /// proposal/vote moves the state root exactly like the direct path.
    /// Maximum number of block-carried governance carriers (`GovPropose` /
    /// `GovVote`) one transaction may APPLY. Every one the VM ran has already
    /// paid its own `GAS_GOV_*` charge; the cap bounds the committed-state
    /// growth a single transaction can cause (S4) even when it declares a
    /// large gas limit. Deterministic: the same block bytes apply the same
    /// prefix on every node.
    pub const MAX_GOV_OPS_PER_TX: usize = 8;

    /// Maximum number of block-carried governance carriers one BLOCK may
    /// apply, across all transactions. Same rationale as
    /// [`Self::MAX_GOV_OPS_PER_TX`] at block granularity; the excess is
    /// counted as refused (and was still charged by the VM, which is
    /// fail-closed in the safe direction).
    pub const MAX_GOV_OPS_PER_BLOCK: usize = 32;

    pub async fn apply_gov_ops(
        &self,
        block: &crate::sharding::Block,
        status: &[bool],
    ) -> GovOpsOutcome {
        use crate::svm::OpCode::*;
        // EXECUTED-PREFIX ONLY (PENTEST2 S4). The SVM stops a transaction's
        // payload at `OpCode::Halt` (`Svm::execute_inner`: `if state.halted
        // { break }`), so only opcodes BEFORE the halt ran, were verified and
        // were charged gas. The authoritative scan must apply exactly that
        // set: a gov op after `Halt` has never been executed by the VM and
        // settling it would be a free, uncharged state write.
        //
        // COLLECT first (no locks): the scan order IS the apply order (tx
        // order, payload order), fixed by the block bytes. Per-tx and
        // per-block caps bound the number of proposals/votes one transaction
        // (and one block) can commit, so a floor-fee transaction cannot bloat
        // the governance domain without paying per-op gas (the VM charges
        // GAS_GOV_* for every pre-halt carrier) and without a hard ceiling.
        let mut ops: Vec<(usize, &crate::svm::OpCode)> = Vec::new();
        let mut out = GovOpsOutcome::default();
        for (i, tx) in block.transactions.iter().enumerate() {
            let mut per_tx = 0usize;
            for op in &tx.payload {
                if matches!(op, crate::svm::OpCode::Halt) {
                    break;
                }
                if matches!(op, SysCallGovPropose { .. } | SysCallGovVote { .. }) {
                    if per_tx >= Self::MAX_GOV_OPS_PER_TX
                        || ops.len() >= Self::MAX_GOV_OPS_PER_BLOCK
                    {
                        // Deterministic refusal: the VM may have executed and
                        // charged this carrier, but consensus applies at most
                        // the caps above. Charging more than is applied is
                        // fail-closed; applying more than is capped is not.
                        out.refused += 1;
                        continue;
                    }
                    ops.push((i, op));
                    per_tx += 1;
                }
            }
        }
        if ops.is_empty() {
            // Fast path: legacy blocks (and blocks whose only gov carriers
            // sit behind a `Halt`) queue nothing, so the scan takes no lock
            // and allocates nothing measurable.
            return out;
        }
        // Activation gate FIRST (before any lock, read or write):
        // pre-activation every gov op refuses and nothing moves — the
        // standard apply path stays byte-identical.
        if !self.gov_ops_active_at(block.height) {
            out.refused += ops.len();
            tracing::warn!(
                "gov ops refused: block-carried governance is inactive at height {} ({} op(s) skipped, activation = {})",
                block.height,
                ops.len(),
                crate::governance::gov_ops_activation_height(),
            );
            return out;
        }
        let mut gov = self.governance_write().await;
        let mut ledger = self.staking_write().await;
        for (tx_idx, op) in ops {
            // A step-1-failed transaction contributes no gov effect.
            if !status.get(tx_idx).copied().unwrap_or(false) {
                out.refused += 1;
                tracing::warn!("gov op skipped: tx #{tx_idx} failed step 1, no gov effect applies");
                continue;
            }
            // Authenticated transport: the signer is the tx signer (verified
            // in step 1 for every `status == true` tx) — never an opcode
            // field, so the proposer/voter cannot be forged.
            let sender = block.transactions[tx_idx].from;
            match op {
                SysCallGovPropose {
                    proposal_id,
                    title,
                    action,
                    height_observed,
                } => {
                    // Height pin: the op names the exact height it applies
                    // at; any other height refuses (no cross-height replay).
                    if *height_observed != block.height {
                        out.refused += 1;
                        tracing::warn!(
                            "gov propose refused: height_observed {height_observed} != block height {}",
                            block.height
                        );
                        continue;
                    }
                    match Self::apply_gov_propose_inner(
                        &mut gov,
                        &mut ledger,
                        sender,
                        *proposal_id,
                        title.clone(),
                        action.as_ref().clone(),
                        block.timestamp,
                    ) {
                        Ok(_) => out.proposed += 1,
                        Err(e) => {
                            out.refused += 1;
                            tracing::warn!("{e}");
                        }
                    }
                }
                SysCallGovVote {
                    proposal_id,
                    choice,
                    height_observed,
                } => {
                    if *height_observed != block.height {
                        out.refused += 1;
                        tracing::warn!(
                            "gov vote refused: height_observed {height_observed} != block height {}",
                            block.height
                        );
                        continue;
                    }
                    match Self::apply_gov_vote_inner(
                        &mut gov,
                        &mut ledger,
                        sender,
                        *proposal_id,
                        *choice,
                        block.timestamp,
                    ) {
                        Ok(_) => out.voted += 1,
                        Err(e) => {
                            out.refused += 1;
                            tracing::warn!("{e}");
                        }
                    }
                }
                _ => {}
            }
        }
        out
    }

    // -----------------------------------------------------------------------
    // Deterministic governance execution (block-carried path).
    //
    // The counterpart of the block-carried gov scan above, on the OUTPUT side:
    // a proposal whose voting window closed is finalized at a block, and a
    // passed, timelock-matured action of ANY type is executed by every node
    // applying the same block, at the same height, with no RPC and no
    // wall-clock trigger. Every applied parameter is committed in the state
    // root (`commitment::governance_digest`), so a node that skips (or
    // duplicates) the execution can no longer hide behind an identical root.
    // -----------------------------------------------------------------------

    /// Deterministically finalize due proposals and execute every due
    /// governance action at this block.
    ///
    /// Pure function of committed governance state + `block.height` +
    /// `block.timestamp` (the block timestamp is the same clock the
    /// block-carried propose/vote arms use — never wall time). Gated by
    /// [`crate::governance::gov_ops_active_at`] (`GOV_OPS_ACTIVATION_HEIGHT`
    /// is `0`, active from genesis, identical on every node).
    ///
    /// `SoftwareUpgrade`/`CancelUpgrade` additionally require the separate
    /// `upgrade_exec_active_at` gate, so a binary rollout never rides in on a
    /// parameter-change activation.
    ///
    /// The read-only fast path skips the write lock when nothing is due, which
    /// is what an ordinary block (and every replay of an already-executed
    /// proposal) hits: no generation bump, identical root.
    pub async fn apply_governance_transition(
        &self,
        block: &crate::sharding::Block,
    ) -> crate::governance::UpgradeExecOutcome {
        use crate::governance::UpgradeExecOutcome;
        if !self.gov_ops_active_at(block.height) {
            return UpgradeExecOutcome::default();
        }
        // GOVERNED MIN-BOND MIRROR (S5 completeness): the consensus-set filter
        // reads `staking.min_validator_bond`, while a governance action writes
        // `governance.applied.min_validator_bond` first. The block-path sweep
        // below mirrors it after an action it EXECUTED, but a value that
        // arrived by another route (a direct RPC execution on a solo node, a
        // restored snapshot) would otherwise never reach the ledger: the
        // filter would keep using the old bond while every reader of
        // `applied` believed the new one was in force. Mirror committed
        // governance into the ledger on EVERY block. This is a no-op (no write,
        // no generation bump, byte-identical root) while the two agree, which
        // is every block on an honest chain.
        if let Some(governed) = self.governance_read().await.applied.min_validator_bond {
            let needs_sync = self.staking_read().await.min_validator_bond != Some(governed);
            if needs_sync {
                self.staking_write().await.min_validator_bond = Some(governed);
            }
        }
        // Read-only pre-check with the guard scoped to its own statement: no
        // due finalization/action means no write lock and no generation bump.
        let due = self
            .governance_read()
            .await
            .has_due_governance(block.timestamp, block.height);
        if !due {
            return UpgradeExecOutcome::default();
        }
        // Same lock order as the direct governance path: governance, then
        // staking (finalize releases voter/proposer locks). The oracle write
        // lock is taken only when an oracle action is actually due.
        let mut gov = self.governance_write().await;
        let mut ledger = self.staking_write().await;
        let finalized = gov.finalize_due_at_height(&mut ledger, block.timestamp, block.height);
        let mut out = if gov.has_due_oracle_action(block.height) {
            let mut oracle = self.oracle_write().await;
            gov.execute_due_governance_at_height(
                block.height,
                crate::consensus::consensus_chain_id(),
                Some(&mut oracle),
            )
        } else {
            gov.execute_due_governance_at_height(
                block.height,
                crate::consensus::consensus_chain_id(),
                None,
            )
        };
        out.finalized = finalized;
        // PENTEST2 S5: a passed `SetMinValidatorBond` must actually change
        // the CONSENSUS SET FILTER, which reads `staking.min_validator_bond`
        // (`to_validator_set` / `elected_count`), not just the committed
        // `applied` snapshot the VM reads for new bonds. The write happens in
        // the same deterministic apply step, under the same governance+staking
        // lock order, only when an action EXECUTED in this block — so every
        // node applying the block derives the same set at the next height
        // boundary and an ordinary block is byte-identical.
        if !out.executed.is_empty() {
            if let Some(min_bond) = gov.applied.min_validator_bond {
                if ledger.min_validator_bond != Some(min_bond) {
                    ledger.min_validator_bond = Some(min_bond);
                }
            }
        }
        drop(ledger);
        drop(gov);
        if !out.refused.is_empty() {
            // The individual reasons are already logged loudly by the sweep;
            // this line names the height once so an operator can grep the block
            // and see that the state root did NOT move for these proposals.
            tracing::error!(
                "gov execution at height {}: {} of {} matured action(s) REFUSED, nothing applied (proposals stay Passed)",
                block.height,
                out.refused.len(),
                out.checked,
            );
        }
        out
    }

    /// Backwards-compatible alias for [`InMemoryStateEngine::apply_governance_transition`].
    ///
    /// The sweep used to execute upgrade actions only; it now covers every
    /// `GovAction`. Existing callers (and the upgrade-plan regression suite)
    /// keep the old entry point, whose upgrade arm is still gated by
    /// `upgrade_exec_active_at` inside the sweep.
    pub async fn apply_upgrade_execution(
        &self,
        block: &crate::sharding::Block,
    ) -> crate::governance::UpgradeExecOutcome {
        self.apply_governance_transition(block).await
    }

    /// W3 PQ lifecycle Step 0 (pre-tx): adopt any pre-W3 validators that have
    /// committed `validator_pq_keys` without a `PqRegistry` record, and promote
    /// every pending PQ key rotation due at `height` (`height >= effective_height`).
    pub(super) async fn apply_pq_lifecycle_step0(&self, height: u64) {
        if !crate::pq_registry::pq_lifecycle_active_at(height) {
            return;
        }
        let (needs_adopt, has_due) = {
            let ledger = self.staking.read().await;
            let pq_reg = self.pq_registry.read().await;
            let needs_adopt = ledger
                .validator_pq_keys
                .keys()
                .any(|id| ledger.validators.contains_key(id) && pq_reg.record_of(id).is_none());
            let has_due = pq_reg.records().values().any(|rec| {
                rec.pending
                    .as_ref()
                    .is_some_and(|p| height >= p.effective_height)
            });
            (needs_adopt, has_due)
        };
        if !needs_adopt && !has_due {
            return;
        }
        let mut ledger = self.staking_write().await;
        let mut pq_reg = self.pq_registry_write().await;
        if needs_adopt {
            let _ = ledger.pq_adopt_legacy_keys_at(&mut pq_reg, 0);
        }
        if has_due {
            let _ = ledger.pq_apply_due_rotations(&mut pq_reg, height);
        }
        // R3-F/runtime calls consensus::sync_committed_pq_registry
    }

    fn is_pq_lifecycle_op(op: &crate::svm::OpCode) -> bool {
        matches!(
            op,
            crate::svm::OpCode::SysCallRegisterValidator(_)
                | crate::svm::OpCode::SysCallRotateVotingKey(_)
                | crate::svm::OpCode::SysCallChangeWithdrawal(_)
                | crate::svm::OpCode::SysCallClaimWithdrawal(_)
                | crate::svm::OpCode::SysCallAnnounceCommission { .. }
                | crate::svm::OpCode::SysCallApplyCommission { .. }
        )
    }

    fn apply_single_pq_lifecycle_op(
        &self,
        ledger: &mut crate::staking::StakingLedger,
        pq_reg: &mut crate::pq_registry::PqRegistry,
        sender: [u8; 32],
        op: &crate::svm::OpCode,
        height: u64,
    ) -> bool {
        use crate::svm::OpCode::*;
        match op {
            SysCallRegisterValidator(p) => {
                if p.withdrawal_address == [0u8; 32] || sender != p.withdrawal_address {
                    tracing::warn!(
                        height,
                        "SysCallRegisterValidator refused in Step 5f: sender != withdrawal_address"
                    );
                    return false;
                }
                let validator_id = crate::pq_registry::derive_validator_id(
                    self.chain_id,
                    &p.withdrawal_address,
                    &p.voting_pubkey,
                );
                if !ledger.validators.contains_key(&validator_id) {
                    tracing::warn!(
                        height,
                        validator = %hex::encode(validator_id),
                        "SysCallRegisterValidator refused in Step 5f: validator bond missing"
                    );
                    return false;
                }
                if let Err(e) = crate::pq_registry::verify_voting_key_pop(
                    self.chain_id,
                    &validator_id,
                    &p.withdrawal_address,
                    0,
                    p.voting_scheme,
                    &p.voting_pubkey,
                    &p.voting_pop,
                ) {
                    tracing::warn!(
                        height,
                        validator = %hex::encode(validator_id),
                        "SysCallRegisterValidator PoP refused in Step 5f: {e}"
                    );
                    return false;
                }
                match pq_reg.register_with_seq(
                    validator_id,
                    crate::post_quantum::PqScheme::Falcon512,
                    p.voting_pubkey.clone(),
                    height,
                    height,
                    0,
                    true,
                ) {
                    Ok(()) => {
                        ledger.validator_pq_keys.insert(
                            validator_id,
                            (
                                crate::post_quantum::PqScheme::Falcon512,
                                p.voting_pubkey.clone(),
                            ),
                        );
                        true
                    }
                    Err(e) => {
                        tracing::warn!(
                            height,
                            validator = %hex::encode(validator_id),
                            "SysCallRegisterValidator registry commit refused in Step 5f: {e}"
                        );
                        false
                    }
                }
            }
            SysCallRotateVotingKey(p) => {
                let res = if p.cancel {
                    if !p.new_pubkey.is_empty() || !p.pop_signature.is_empty() {
                        tracing::warn!(
                            height,
                            validator = %hex::encode(p.validator_id),
                            "SysCallRotateVotingKey cancel refused in Step 5f: non-empty key/sig"
                        );
                        return false;
                    }
                    ledger.pq_cancel_rotation(
                        pq_reg,
                        p.validator_id,
                        sender,
                        p.rotation_seq,
                        height,
                    )
                } else {
                    ledger.pq_announce_rotation_with_seq(
                        pq_reg,
                        self.chain_id,
                        p.validator_id,
                        sender,
                        p.rotation_seq,
                        p.new_scheme,
                        &p.new_pubkey,
                        &p.pop_signature,
                        height,
                    )
                };
                match res {
                    Ok(()) => true,
                    Err(e) => {
                        tracing::warn!(
                            height,
                            validator = %hex::encode(p.validator_id),
                            cancel = p.cancel,
                            "SysCallRotateVotingKey refused in Step 5f: {e}"
                        );
                        false
                    }
                }
            }
            SysCallChangeWithdrawal(_) => {
                // `SysCallChangeWithdrawal` mutates `working_staking` directly in Step 1 via
                // SVM clone-commit so subsequent operations in the same payload/block see the
                // rotated `withdrawal_address` immediately.
                true
            }
            SysCallClaimWithdrawal(_) => {
                // `SysCallClaimWithdrawal` mutates `working_staking` directly in Step 1 via
                // SVM clone-commit so subsequent operations in the same payload/block see the
                // claimed `withdrawal_address` immediately and cannot double-claim in-block.
                true
            }
            SysCallAnnounceCommission { validator, new_bps } => {
                if let Err(e) = ledger.authorize_validator_owner(validator, &sender, true) {
                    tracing::warn!(
                        height,
                        validator = %hex::encode(validator),
                        "SysCallAnnounceCommission unauthorized in Step 5f: {e}"
                    );
                    return false;
                }
                match ledger.announce_commission(*validator, *new_bps, height) {
                    Ok(()) => true,
                    Err(e) => {
                        tracing::warn!(
                            height,
                            validator = %hex::encode(validator),
                            "SysCallAnnounceCommission refused in Step 5f: {e}"
                        );
                        false
                    }
                }
            }
            SysCallApplyCommission { validator } => {
                if let Err(e) = ledger.authorize_validator_owner(validator, &sender, true) {
                    tracing::warn!(
                        height,
                        validator = %hex::encode(validator),
                        "SysCallApplyCommission unauthorized in Step 5f: {e}"
                    );
                    return false;
                }
                match ledger.apply_commission(*validator, height) {
                    Ok(()) => true,
                    Err(e) => {
                        tracing::warn!(
                            height,
                            validator = %hex::encode(validator),
                            "SysCallApplyCommission refused in Step 5f: {e}"
                        );
                        false
                    }
                }
            }
            _ => false,
        }
    }

    /// W3 PQ lifecycle Step 5f: scan applied pre-`Halt` payload ops in block
    /// order and commit `PqRegistry` / height-gated staking transitions.
    pub async fn apply_pq_registry_ops(
        &self,
        block: &crate::sharding::Block,
        status: &[bool],
    ) -> usize {
        if !crate::pq_registry::pq_lifecycle_active_at(block.height) {
            return 0;
        }
        let mut ops: Vec<([u8; 32], &crate::svm::OpCode)> = Vec::new();
        for (i, tx) in block.transactions.iter().enumerate() {
            if !status.get(i).copied().unwrap_or(false) {
                continue;
            }
            for op in &tx.payload {
                if matches!(op, crate::svm::OpCode::Halt) {
                    break;
                }
                if Self::is_pq_lifecycle_op(op) {
                    ops.push((tx.from, op));
                }
            }
        }
        if ops.is_empty() {
            return 0;
        }
        let mut ledger = self.staking_write().await;
        let mut pq_reg = self.pq_registry_write().await;
        let mut applied = 0usize;
        for (sender, op) in ops {
            if self.apply_single_pq_lifecycle_op(&mut ledger, &mut pq_reg, sender, op, block.height)
            {
                applied += 1;
            }
        }
        // R3-F/runtime calls consensus::sync_committed_pq_registry
        applied
    }

    /// Single-transaction twin of [`Self::apply_pq_registry_ops`] for direct
    /// `apply_transaction_at_height` parity with `apply_block_transition`.
    pub(super) async fn apply_pq_lifecycle_tx_ops(
        &self,
        tx: &crate::sharding::Transaction,
        height: u64,
    ) {
        if !crate::pq_registry::pq_lifecycle_active_at(height) || tx.payload.is_empty() {
            return;
        }
        let mut ops: Vec<&crate::svm::OpCode> = Vec::new();
        for op in &tx.payload {
            if matches!(op, crate::svm::OpCode::Halt) {
                break;
            }
            if Self::is_pq_lifecycle_op(op) {
                ops.push(op);
            }
        }
        if ops.is_empty() {
            return;
        }
        let mut ledger = self.staking_write().await;
        let mut pq_reg = self.pq_registry_write().await;
        for op in ops {
            let _ =
                self.apply_single_pq_lifecycle_op(&mut ledger, &mut pq_reg, tx.from, op, height);
        }
    }
}
