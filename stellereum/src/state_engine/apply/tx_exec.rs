use super::super::types::contract_key;
use super::super::types::restore_oracle_after_failure;
use super::super::types::token_balance_key;
use super::super::types::token_supply_key;
use super::super::types::write_contract_trie_entries_for_addrs;
use super::super::types::ActorSnapshot;
use super::super::types::BridgeSnapshot;
use super::super::types::ClobQuoteMode;
use super::super::types::NativeAccountSnapshot;
use super::super::types::PayloadDomainSnapshot;
use super::super::verify_once::require_pq_tx_envelope_at_height;
use super::super::ExecPostActions;
use super::super::InMemoryStateEngine;
use super::GOV_PAYLOAD_SNAPSHOTS;
use crate::token::TokenRegistry;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::atomic::Ordering;

impl InMemoryStateEngine {
    /// Execute a transaction's SVM payload (contract / token / orderbook ops)
    /// against consensus state. Returns the gas consumed, or an error if the
    /// program reverts / runs out of gas. Mutations (tokens, orderbooks) are
    /// committed only on success (the SVM already uses clone-commit internally).
    ///
    /// `timestamp` is the BLOCK timestamp, supplied by the caller from the block
    /// being applied. It used to be hardcoded to `0`, which made every
    /// timestamp-dependent syscall consensus-quiet garbage: `SysCallUnbond`
    /// scheduled `release_at = UNBONDING_PERIOD_SECS` instead of
    /// `block.timestamp + UNBONDING_PERIOD_SECS`, contracts were created at
    /// epoch 0, orders were stamped with epoch 0 and session-key gas
    /// authorisation was checked against epoch 0.
    ///
    /// Determinism: the same block + payload + state yields identical results on
    /// every node. The timestamp is not a local wall clock, it is a field of the
    /// block every node applies, and there is no RNG in the host.
    pub async fn execute_payload(
        &self,
        tx: &crate::sharding::Transaction,
        timestamp: u64,
    ) -> Result<(crate::svm::VmExecutionResult, ExecPostActions), String> {
        self.execute_payload_with_preverify(tx, timestamp).await
    }

    /// Height-gated variant of [`Self::execute_payload`].
    pub async fn execute_payload_at_height(
        &self,
        tx: &crate::sharding::Transaction,
        timestamp: u64,
        chain_height: u64,
    ) -> Result<(crate::svm::VmExecutionResult, ExecPostActions), String> {
        self.execute_payload_with_preverify_at_height(tx, timestamp, chain_height)
            .await
    }

    /// Capture pre-execution state for exactly the domains this payload's
    /// opcodes can mutate (B1 atomicity). Plain transfers (empty payload)
    /// never call this: they touch no domain. Each clone is gated on the
    /// opcodes present so hot paths pay only for what they use.
    #[allow(dead_code)] // GATE: kept for pre-hardening direct callers alongside snapshot_payload_domains_at
    pub(in crate::state_engine) async fn snapshot_payload_domains(
        &self,
        payload: &[crate::svm::OpCode],
    ) -> PayloadDomainSnapshot {
        self.snapshot_payload_domains_at(payload, false).await
    }

    /// Height-gated variant of [`Self::snapshot_payload_domains`].
    /// When `exec_hardening` is true, stops scanning at the first `OpCode::Halt`
    /// and includes `SysCallCallContractArgs` (contracts) and
    /// `SysCallSubmitPqPriceFeed` (oracle).
    pub(in crate::state_engine) async fn snapshot_payload_domains_at(
        &self,
        payload: &[crate::svm::OpCode],
        exec_hardening: bool,
    ) -> PayloadDomainSnapshot {
        use crate::svm::OpCode::*;
        let mut touches_tokens = false;
        let mut touches_contracts = false;
        let mut touches_books = false;
        let mut touches_pmm = false;
        let mut touches_staking = false;
        let mut touches_oracle = false;
        let mut touches_session = false;
        let mut touches_zkml = false;
        for op in payload {
            if exec_hardening && matches!(op, Halt) {
                break;
            }
            match op {
                SysCallTokenTransfer { .. }
                | SysCallTokenTransferFrom { .. }
                | SysCallTokenMint { .. }
                | SysCallTokenBurn { .. }
                | SysCallTokenApprove { .. }
                | SysCallTokenBalanceOf { .. }
                | SysCallTokenCreate { .. } => touches_tokens = true,
                SysCallDeployContract { .. } | SysCallCallContract { .. } => {
                    touches_contracts = true
                }
                SysCallCallContractArgs { .. } if exec_hardening => touches_contracts = true,
                SysCallPlaceOrder { .. } | SysCallCancelOrder { .. } => {
                    touches_books = true;
                    // settle_clob_effects does token Transfer/Mint/Burn on the
                    // live registry, so the token domain must be snapshotted too.
                    touches_tokens = true;
                }
                SysCallPmmBuy { .. } | SysCallPmmSell { .. } => {
                    touches_books = true;
                    touches_pmm = true;
                    touches_tokens = true;
                }
                SysCallStake { .. }
                | SysCallStakeWithCommission { .. }
                | SysCallUnbond { .. }
                | SysCallDelegate { .. }
                | SysCallUndelegate { .. }
                | SysCallBeginUndelegate { .. }
                | SysCallClaimRewards { .. }
                | SysCallClaimDelegatorRewards { .. }
                | SysCallWithdrawSelfBond { .. }
                | SysCallRotateValidatorKey { .. }
                // Carrier only: the VM validates jail/bond and the block
                // apply performs the height-gated unjail, but the ledger is
                // still read inside the VM, so snapshot it for rollback.
                | SysCallUnjail { .. }
                | SysCallRegisterValidator(_)
                | SysCallRotateVotingKey(_)
                | SysCallChangeWithdrawal(_)
                | SysCallClaimWithdrawal(_)
                | SysCallAnnounceCommission { .. }
                | SysCallApplyCommission { .. }
                // The PQ equivocation report SLASHES the ledger inside the VM
                // (it must: the verdict depends on the accused validator's
                // registered post-quantum key), so the ledger must be
                // snapshotted for rollback exactly like every other staking
                // opcode.
                | SysCallReportPqEquivocation { .. } => touches_staking = true,
                SysCallSubmitPriceFeed { .. } => touches_oracle = true,
                SysCallSubmitPqPriceFeed { .. } if exec_hardening => touches_oracle = true,
                SysCallPublishSessionGrant { .. } | SysCallRevokeSession { .. } => {
                    touches_session = true
                }
                SysCallVerifyZkMl
                | SysCallVerifyZkMlReexec { .. }
                | SysCallRegisterZkMlModel { .. }
                | SysCallRegisterZkMlSpec { .. }
                | SysCallVerifyZkMlAttestation { .. } => touches_zkml = true,
                // Read-only or account-mirror ops: Transfer/Lookup move no
                // domain state; Bridge resolves through its own snapshot;
                // ActorSend settles coins (accounts map, undone by the
                // commit) and the mailbox pass (restored via ActorSnapshot).
                _ => {}
            }
        }
        let mut snap = PayloadDomainSnapshot {
            tokens: None,
            contracts: None,
            orderbooks: None,
            order_escrow: None,
            pmm: None,
            staking: None,
            oracle: None,
            session_keys: None,
            zkml_models: None,
        };
        if touches_tokens {
            snap.tokens = Some((*self.tokens_read().await).clone());
        }
        if touches_contracts {
            snap.contracts = Some((*self.contracts_read().await).clone());
        }
        if touches_books {
            snap.orderbooks = Some((*self.orderbooks_read().await).clone());
            snap.order_escrow = Some((*self.order_escrow_read().await).clone());
        }
        if touches_pmm {
            snap.pmm = Some((*self.pmm_read().await).clone());
        }
        if touches_staking {
            snap.staking = Some((*self.staking_read().await).clone());
        }
        if touches_oracle {
            snap.oracle = Some((*self.oracle_read().await).clone());
        }
        if touches_session {
            snap.session_keys = Some((*self.session_keys_read().await).clone());
        }
        if touches_zkml {
            snap.zkml_models = Some((*self.zkml_models_read().await).clone());
        }
        snap
    }

    /// Restore a [`PayloadDomainSnapshot`]: every domain the payload touched
    /// goes back to its pre-execution bytes, through the same write accessors
    /// (and `commitment_generation` bumps) as every other mutation. Called
    /// ONLY when the transaction as a whole is refused after the VM already
    /// ran — today, that is exactly the `commit_native` failure in both apply
    /// paths. Account-level legs (bridge/actor/PMM-native direct map writes)
    /// are restored separately via their own snapshots (see `ExecPostActions`
    /// at the call site); the accounts map itself is undone by `commit_native`.
    async fn restore_payload_domains(&self, snap: PayloadDomainSnapshot) {
        if let Some(v) = snap.tokens {
            *self.tokens_write().await = v;
        }
        if let Some(v) = snap.contracts {
            *self.contracts_write().await = v;
        }
        if let Some(v) = snap.orderbooks {
            *self.orderbooks_write().await = v;
        }
        if let Some(v) = snap.order_escrow {
            *self.order_escrow_write().await = v;
        }
        if let Some(v) = snap.pmm {
            *self.pmm_write().await = v;
        }
        if let Some(v) = snap.staking {
            *self.staking_write().await = v;
        }
        if let Some(v) = snap.oracle {
            // The breaker latch is sticky BY DESIGN (pinned by
            // `breaker_reset_requires_a_passed_executed_governance_action`):
            // a deviant feed trips it even when its own transaction is
            // refused, and only governance resets it. The latch is an alarm,
            // not value — B1 rolls back prices/feeds but preserves a latch
            // tripped by the failed payload (same rule as
            // `restore_oracle_after_failure`). Changing latch policy is E3,
            // a separate decision, not this rollback.
            let latched = self.oracle_read().await.breaker_tripped;
            let mut oracle = self.oracle_write().await;
            *oracle = v;
            oracle.breaker_tripped |= latched;
        }
        if let Some(v) = snap.session_keys {
            *self.session_keys_write().await = v;
        }
        if let Some(v) = snap.zkml_models {
            *self.zkml_models_write().await = v;
        }
    }

    /// Full rollback of a refused payload (B1): domains from `snap`,
    /// settlement account legs from `actions`, and trie entries recomputed.
    /// Token/contract trie keys touched by the failed payload are removed
    /// first (a failed mint must not leave an SPV-provable phantom balance),
    /// then `sync_aux_trie` re-adds exactly what the restored registries
    /// hold. Contract code-hash entries written speculatively by a deploy
    /// are removed the same way (the caller writes them only after a commit
    /// now, so this covers only pre-existing write paths).
    pub(in crate::state_engine) async fn rollback_payload(
        &self,
        snap: PayloadDomainSnapshot,
        actions: ExecPostActions,
    ) {
        // Diff BEFORE restoring (post-state is live right now). Scoped so
        // read guards drop before any write lock below (else deadlock).
        let mut dead_keys: HashSet<[u8; 32]> = HashSet::new();
        if snap.tokens.is_some() {
            let live = self.tokens_read().await;
            for (id, post) in &live.tokens {
                let pre = snap.tokens.as_ref().and_then(|t| t.tokens.get(id));
                let changed = match pre {
                    None => true,
                    Some(p) => {
                        p.metadata.total_supply != post.metadata.total_supply
                            || p.balances != post.balances
                    }
                };
                if changed {
                    for acct in post.balances.keys() {
                        dead_keys.insert(token_balance_key(id, acct));
                    }
                    if let Some(p) = pre {
                        for acct in p.balances.keys() {
                            dead_keys.insert(token_balance_key(id, acct));
                        }
                    }
                    dead_keys.insert(token_supply_key(id));
                }
            }
        }
        if snap.contracts.is_some() {
            let live = self.contracts_read().await;
            let mut ids: std::collections::HashSet<[u8; 32]> =
                live.contracts.keys().copied().collect();
            if let Some(pre) = snap.contracts.as_ref() {
                ids.extend(pre.contracts.keys().copied());
            }
            for addr in ids {
                let changed = match (
                    snap.contracts.as_ref().and_then(|c| c.contracts.get(&addr)),
                    live.contracts.get(&addr),
                ) {
                    (None, _) | (_, None) => true,
                    (Some(a), Some(b)) => a.code_hash != b.code_hash,
                };
                if changed {
                    dead_keys.insert(contract_key(&addr));
                }
            }
        }
        // Restore domains (overwrites the success-arm commits).
        self.restore_payload_domains(snap).await;
        // Settlement account legs (CLOB first: it settled last, so its
        // snapshot is the newest; the PMM snapshot is the oldest and is
        // restored last so an account touched by several legs ends pre-all).
        self.restore_clob_native(&actions.clob_native_snapshot)
            .await;
        self.restore_bridge_native(actions.bridge_snapshot.as_ref())
            .await;
        self.restore_actor_native(actions.actor_snapshot.as_ref())
            .await;
        // The PMM buy leg's supply reservation is part of what this payload
        // created: give it back with the balances (audit F5).
        if actions.pmm_minted_nano > 0 {
            self.release_mint_nano(actions.pmm_minted_nano);
        }
        self.restore_pmm_native(&actions.pmm_native_snapshot).await;
        // Trie: drop touched keys, then re-add exactly what restored state holds.
        if !dead_keys.is_empty() {
            let mut trie = self.state_trie.write().await;
            for k in dead_keys {
                trie.remove(&k);
            }
        }
        self.sync_aux_trie().await;
    }

    /// Payload execution through the block-path VM entry point
    /// ([`Svm::execute_with_confidential_and_sends`]).
    ///
    /// The name keeps the pre-excision `..._with_preverify` shape: the
    /// range-proof pre-verification cache for shielded transfers was removed
    /// with the shielded protocol, so every path now runs every check from
    /// scratch. Gas, settlement and commit behavior are unchanged.
    #[allow(clippy::type_complexity)]
    // GATE: execution snapshot uses account tuple layout shared with commit path.
    pub async fn execute_payload_with_preverify(
        &self,
        tx: &crate::sharding::Transaction,
        timestamp: u64,
    ) -> Result<(crate::svm::VmExecutionResult, ExecPostActions), String> {
        self.execute_payload_with_preverify_at_height(tx, timestamp, u64::MAX)
            .await
    }

    /// Height-gated variant of [`Self::execute_payload_with_preverify`].
    ///
    /// Callers WITHOUT a block context pass through here; the contract-visible
    /// block identifier is the default zero, which is exactly the pre-gate
    /// behaviour at every height.
    #[allow(clippy::type_complexity)]
    // GATE: execution snapshot uses account tuple layout shared with commit path.
    pub async fn execute_payload_with_preverify_at_height(
        &self,
        tx: &crate::sharding::Transaction,
        timestamp: u64,
        chain_height: u64,
    ) -> Result<(crate::svm::VmExecutionResult, ExecPostActions), String> {
        self.execute_payload_with_preverify_at_height_and_parent(
            tx,
            timestamp,
            chain_height,
            [0u8; 32],
        )
        .await
    }

    /// [`Self::execute_payload_with_preverify_at_height`] with an explicit
    /// PARENT block hash (`block.prev_hash`).
    ///
    /// The parent hash — never the current block hash — is what contracts see
    /// via `host.block_hash` once
    /// [`crate::chain_spec::CONTRACT_BLOCK_HASH_ACTIVATION_HEIGHT`] is active:
    /// the current block hash commits execution output (`body_commitment`
    /// includes `cross_shard_out`), so it cannot be known before the payloads
    /// run. The parent is identical on every node applying the same block and
    /// across repeated executions of that block.
    ///
    /// S4: standalone callers keep the conservative "the payload may not be
    /// restorable" execution mode (see
    /// `execute_payload_with_preverify_at_height_and_parent_restorable`).
    // GATE: execution snapshot uses account tuple layout shared with commit path.
    pub async fn execute_payload_with_preverify_at_height_and_parent(
        &self,
        tx: &crate::sharding::Transaction,
        timestamp: u64,
        chain_height: u64,
        parent_block_hash: [u8; 32],
    ) -> Result<(crate::svm::VmExecutionResult, ExecPostActions), String> {
        self.execute_payload_inner(tx, timestamp, chain_height, parent_block_hash, false)
            .await
    }

    /// [`Self::execute_payload_with_preverify_at_height_and_parent`] for a
    /// caller that ALREADY snapshotted this payload's consensus domains
    /// ([`Self::snapshot_payload_domains_at`]) and restores them through
    /// [`Self::rollback_payload`] on every `Err`.
    ///
    /// The ONLY difference is which atomicity mechanism the CLOB settlement
    /// uses (S4): with a restorable caller, `settle_clob_effects` applies its
    /// token ops to the live registry instead of first cloning the WHOLE
    /// `TokenRegistry` (every token, every balance) for a plan it then throws
    /// away. A refused plan leaves partial token writes behind, which the
    /// caller's domain restore reverts exactly like every other payload
    /// effect - the committed state root is identical either way.
    ///
    /// Both consensus apply paths (single-transaction and block) satisfy the
    /// contract: each takes `snapshot_payload_domains_at` before calling and
    /// rolls back on `Err`.
    // A refused CLOB plan on this path restores via `rollback_payload`, hence
    // the boolean name: the domains ARE restorable here.
    pub(in crate::state_engine) async fn execute_payload_with_preverify_at_height_and_parent_restorable(
        &self,
        tx: &crate::sharding::Transaction,
        timestamp: u64,
        chain_height: u64,
        parent_block_hash: [u8; 32],
    ) -> Result<(crate::svm::VmExecutionResult, ExecPostActions), String> {
        self.execute_payload_inner(tx, timestamp, chain_height, parent_block_hash, true)
            .await
    }

    /// Shared body of the payload entry points (see the two public wrappers
    /// above and [`Self::execute_payload`]).
    async fn execute_payload_inner(
        &self,
        tx: &crate::sharding::Transaction,
        timestamp: u64,
        chain_height: u64,
        parent_block_hash: [u8; 32],
        domains_restorable: bool,
    ) -> Result<(crate::svm::VmExecutionResult, ExecPostActions), String> {
        let exec_hardening = crate::chain_spec::exec_hardening_v1_active_at(chain_height);
        let wasm_pmm_hardening =
            crate::chain_spec::wasm_xshard_pmm_hardening_active_at(chain_height);
        let pq_lifecycle = crate::pq_registry::pq_lifecycle_active_at(chain_height);
        // Session-key gate at the BLOCK timestamp, checked BEFORE the
        // empty-payload early return below. A plain session transfer has no
        // payload, so without this it would never reach the session hook at
        // the end of the VM run and would execute unchecked. Deterministic
        // (block clock only); a legacy transaction passes unconditionally.
        //
        // Phase 2: this is the FULL gate - the grant policy AND the on-chain
        // registry (terminal revocation, the record's ceilings, cumulative
        // spend) - so an empty-payload session transfer cannot bypass the
        // budget any more than it can bypass expiry.
        self.session_gate(tx, timestamp).await?;

        // R7/S6 (consensus, not admission): re-derive the EVM payload's
        // agreement with its own transaction from block bytes alone. A
        // hand-built block that bypassed the mempool cannot settle a
        // different nonce/amount than the EVM intent signed, and a `Mixed`
        // payload is refused here too (the block path never called the
        // admission classifier before).
        crate::evm_adapter::verify_evm_payload_against_tx(tx)?;

        // R7/C2: one signed EVM intent settles at most ONCE. The nullifier
        // (keccak256 of the raw EVM intent) is committed state; the check is
        // here, before any value moves, and the mark is written by the apply
        // path only after the transaction commits successfully.
        if let Some(digest) = crate::evm_adapter::carrier_intent_digest(tx) {
            if self.evm_intent_is_settled(&digest).await {
                return Err(format!(
                    "EVM intent 0x{} already settled: refusing a second settlement of the \
                     same signed intent",
                    hex::encode(digest)
                ));
            }
        }

        // §1 CROSS-SHARD (out of scope for v1): an actor message is delivered
        // by the mailbox pass of the shard that runs this block, and there is
        // no address->shard routing yet, so a payload that would enqueue one
        // inside an OUTBOUND CROSS-SHARD transaction is refused outright -
        // before the VM runs, so the refusal leaves no payload effect at all.
        //
        // Deliberately a rule about the TRANSACTION's own fields, not about
        // `self.cross_shard_enabled`: that flag is node-local process config,
        // and a consensus rule that depends on it could make a sharded node
        // and a single-shard node disagree about the same block.
        if tx.source_shard != tx.target_shard
            && tx
                .payload
                .iter()
                .any(|op| matches!(op, crate::svm::OpCode::SysCallActorSend { .. }))
        {
            return Err(
                "actor send rejected: cross-shard actor messages are not supported (v1 is \
                 single-shard only)"
                    .to_string(),
            );
        }

        if tx.payload.is_empty() {
            return Ok((
                crate::svm::VmExecutionResult::Success {
                    gas_used: 0,
                    return_value: None,
                    new_balance: 0,
                    trades: vec![],
                    transfers: vec![],
                    token_events: vec![],
                    clob_events: vec![],
                    payouts: vec![],
                    burns: vec![],
                    outbound_messages: vec![],
                    events: vec![],
                },
                ExecPostActions {
                    bridge_snapshot: None,
                    actor_snapshot: None,
                    pmm_native_snapshot: Vec::new(),
                    pmm_minted_nano: 0,
                    clob_native_snapshot: Vec::new(),
                    outbound_messages: Vec::new(),
                },
            ));
        }

        let contract_keys_to_sync: Vec<[u8; 32]> = if wasm_pmm_hardening {
            let mut has_call = false;
            for op in &tx.payload {
                if exec_hardening && matches!(op, crate::svm::OpCode::Halt) {
                    break;
                }
                if matches!(
                    op,
                    crate::svm::OpCode::SysCallCallContract { .. }
                        | crate::svm::OpCode::SysCallCallContractArgs { .. }
                ) {
                    has_call = true;
                    break;
                }
            }
            if has_call {
                let mut keys: Vec<[u8; 32]> = self
                    .contracts_read()
                    .await
                    .contracts
                    .keys()
                    .copied()
                    .collect();
                keys.push(crate::contract::contract_address(&tx.from, tx.nonce));
                keys
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        let (sender_balance, outbound_budget_from_accounts) = {
            let accounts_guard = self.accounts.read().await;
            let sbal = accounts_guard.get(&tx.from).map(|a| a.balance).unwrap_or(0);
            let budgets = if wasm_pmm_hardening && !contract_keys_to_sync.is_empty() {
                let mut map = HashMap::with_capacity(contract_keys_to_sync.len());
                for addr in contract_keys_to_sync {
                    if let Some(acc) = accounts_guard.get(&addr) {
                        map.insert(addr, acc.balance);
                    }
                }
                Some(map)
            } else {
                None
            };
            (sbal, budgets)
        };

        let pq_registry_snap = if pq_lifecycle {
            let mut needs_pq_reg = false;
            for op in &tx.payload {
                if exec_hardening && matches!(op, crate::svm::OpCode::Halt) {
                    break;
                }
                if matches!(
                    op,
                    crate::svm::OpCode::SysCallRegisterValidator(_)
                        | crate::svm::OpCode::SysCallRotateVotingKey(_)
                        | crate::svm::OpCode::SysCallClaimWithdrawal(_)
                        | crate::svm::OpCode::SysCallReportPqEquivocation { .. }
                ) {
                    needs_pq_reg = true;
                    break;
                }
            }
            if needs_pq_reg {
                Some(self.pq_registry.read().await.clone())
            } else {
                None
            }
        } else {
            None
        };

        // Cross-shard contract-send refusal inputs, captured BEFORE the domain
        // write guards below. `shard_topology` is a separate lock: taking it
        // while holding the contracts/tokens guards would introduce a new lock
        // order. The snapshot is only needed when the gate is active; a node
        // that is not sharded has no cross-shard branch at all.
        let contract_send_refusal =
            crate::chain_spec::wasm_xshard_contract_send_refusal_active_at(chain_height);
        let contract_send_refusal_topology = if contract_send_refusal {
            Some(self.shard_topology.read().await.clone())
        } else {
            None
        };
        let contract_send_local_shard = self.shard_id();
        let contract_send_sharded = self.cross_shard_enabled();

        let mut tokens = self.tokens_write().await;
        let mut orderbooks = self.orderbooks_write().await;
        let mut contracts = self.contracts_write().await;
        let mut staking = self.staking_write().await;
        // The committed PMM, taken like the other domains: the VM advances the
        // curve through a clone of it (clone-commit, same as the staking
        // ledger) and the native leg below is settled while this guard is still
        // held, so the curve cannot move between "the swap was applied" and
        // "the coins moved".
        let mut pmm = self.pmm_write().await;
        // Pre-payload snapshot of the PMM AND the token registry, for payloads
        // that carry a PMM syscall. Settlement below can still refuse (only a
        // concurrent account mutation could make it, see the affordability
        // check), and refusing must undo BOTH halves the VM already committed -
        // the advanced curve and the burned/minted wUSDT - or the refusal
        // itself would have created value. Plain transfers never pay for the
        // clones.
        let mut pmm_before: Option<(crate::pmm::PrimaryMarketMaker, TokenRegistry)> = None;
        if tx.payload.iter().any(|op| {
            matches!(
                op,
                crate::svm::OpCode::SysCallPmmBuy { .. }
                    | crate::svm::OpCode::SysCallPmmSell { .. }
            )
        }) {
            pmm_before = Some(((*pmm).clone(), (*tokens).clone()));
        }
        // Oracle last: `commitment_snapshot` reads the subsystems in field
        // order starting at `tokens`, so taking the oracle only after every
        // other guard keeps lock acquisition ordered and a root read can never
        // deadlock against a payload in flight.
        let mut oracle = self.oracle_write().await;
        // Pre-payload snapshot of the oracle, for payloads that can touch it.
        // A failed payload must leave no committed price behind ("whole tx
        // rolls back"), while a breaker latch tripped by a gate inside that
        // same payload is a sticky alarm and survives its own transaction -
        // see `restore_oracle_after_failure`.
        let mut oracle_before = {
            let mut has_oracle_op = false;
            for op in &tx.payload {
                if exec_hardening && matches!(op, crate::svm::OpCode::Halt) {
                    break;
                }
                if matches!(
                    op,
                    crate::svm::OpCode::SysCallSubmitPriceFeed(_)
                        | crate::svm::OpCode::SysCallPlaceOrder { .. }
                ) || (exec_hardening
                    && matches!(op, crate::svm::OpCode::SysCallSubmitPqPriceFeed(_)))
                {
                    has_oracle_op = true;
                    break;
                }
            }
            if has_oracle_op {
                Some(oracle.clone())
            } else {
                None
            }
        };

        // A payload with order syscalls commits its book changes inside the VM.
        // If escrow settlement then fails, the book has to go back exactly as it
        // was, or the transaction would leave precisely the orphan the escrow
        // exists to prevent: an order in the book whose funds were never locked.
        // Snapshot only for payloads that can produce events - plain transfers
        // must not pay for the clone.
        let mut books_before: Option<
            std::collections::HashMap<u32, crate::orderbook::OrderbookActor>,
        > = None;
        if tx.payload.iter().any(|op| {
            matches!(
                op,
                crate::svm::OpCode::SysCallPlaceOrder { .. }
                    | crate::svm::OpCode::SysCallCancelOrder { .. }
            )
        }) {
            books_before = Some(orderbooks.books.clone());
        }

        // Session-key envelope, if any: the VM's end-of-execution hook then
        // re-checks expiry and the ACTUAL gas consumed against the grant's
        // budget (`verify_and_spend_gas`). `None` for a legacy transaction.
        let mut delegation = tx.delegation();

        // Session-key REGISTRY, cloned in only for payloads that can mutate
        // it (`SysCallRevokeSession`). Two properties this buys:
        //   * a revert / out-of-gas / failed escrow settlement never revokes
        //     anything, because the working copy is committed below only on the
        //     SUCCESS arm - and `execute_payload` returns `Err` on every other
        //     path, discarding it;
        //   * the consensus lock is held for nothing on the 99.99% of payloads
        //     that never mention a revoke (the same clone-on-demand shape as
        //     `oracle_before` and `books_before` above).
        let mut session_keys_work = if tx
            .payload
            .iter()
            .any(|op| matches!(op, crate::svm::OpCode::SysCallRevokeSession { .. }))
        {
            Some(self.session_keys.read().await.clone())
        } else {
            None
        };
        let session_keys_before = session_keys_work.clone();

        // §2 MODEL REGISTRY, cloned in only for payloads that can touch it
        // (`SysCallVerifyZkMlReexec` / `SysCallVerifyZkMlAttestation` read it,
        // `SysCallRegisterZkMlModel` / `SysCallRegisterZkMlSpec` write it) -
        // the same clone-on-demand shape as the session registry above, for
        // the same two reasons: a revert / out-of-gas / later settlement
        // failure discards a registration with everything else (the working
        // copy is written back ONLY on the SUCCESS arm), and the 99.99% of
        // payloads with no zkML opcode never take the lock or pay for the
        // clone. The VM reads/writes this copy in place through
        // `Svm::execute_with_confidential_and_sends`.
        let mut zkml_models_work = if tx.payload.iter().any(|op| {
            matches!(
                op,
                crate::svm::OpCode::SysCallVerifyZkMlReexec { .. }
                    | crate::svm::OpCode::SysCallRegisterZkMlModel { .. }
                    | crate::svm::OpCode::SysCallVerifyZkMlAttestation { .. }
                    | crate::svm::OpCode::SysCallRegisterZkMlSpec { .. }
            )
        }) {
            Some(self.zkml_models.read().await.clone())
        } else {
            None
        };
        let zkml_models_before = zkml_models_work.clone();

        // PREVENTIVE REVOCATION (tombstone). The VM's revoke handler fails
        // closed on an UNKNOWN session key (there is no record to authenticate
        // it against), so a grant that was never used could not be revoked at
        // all - and a later-presented copy of that still-valid grant would be
        // accepted. Here, before the payload runs, a LEGACY (master-signed)
        // revoke of an unused key is allowed to leave a committed tombstone,
        // but only when the SAME payload carries a `SysCallPublishSessionGrant`
        // for that exact key, signed by the same master. Publishing is already
        // a master-only, signature-verified announcement, so it is precisely
        // the proof of authority a preventive revocation needs; without it
        // nothing is seeded and the VM reverts exactly as before, so no third
        // party can tombstone a victim's unused key by guessing its pubkey.
        //
        // A session-keyed transaction can never get here with a revoke: the
        // `session_gate` above already rejected it (revocation is a master
        // capability). The clone-commit machinery still applies - a tombstone
        // only lands if the whole transaction succeeds.
        if !tx.is_session_keyed() {
            if let Some(work) = session_keys_work.as_mut() {
                for op in &tx.payload {
                    if let crate::svm::OpCode::SysCallRevokeSession { session_pubkey } = op {
                        if work.get(session_pubkey).is_none() {
                            let proof = tx.payload.iter().find_map(|o| match o {
                                crate::svm::OpCode::SysCallPublishSessionGrant(g)
                                    if g.session_pubkey == *session_pubkey
                                        && g.master_address == tx.from
                                        && g.chain_id == self.chain_id
                                        && g.verify_signature() =>
                                {
                                    Some(g.master_address)
                                }
                                _ => None,
                            });
                            if let Some(master) = proof {
                                work.note_tombstone(*session_pubkey, master);
                            }
                        }
                    }
                }
            }
        }

        // Governed policy for THIS payload: the PMM redemption buffer and the
        // two staking parameters the VM context needs, resolved from ONE
        // governance read (S4). They used to take three separate read guards
        // inside the struct literal below; one snapshot is both cheaper and
        // strictly more deterministic - every syscall of a payload already
        // had to see the same policy ("Read once per transaction (not per
        // opcode) so the policy cannot change mid-execution"), and three
        // separate acquisitions could in principle straddle a concurrent
        // writer. Consensus state cannot move mid-transaction here (payloads
        // apply one at a time), so the values are bit-identical to the live
        // reads they replace.
        let (gov_pmm_buffer_bps, gov_min_validator_bond, gov_default_commission_bps) = {
            let gov = self.governance.read().await;
            (
                gov.applied
                    .pmm_redemption_buffer_bps
                    .unwrap_or(crate::pmm::PMM_REDEMPTION_BUFFER_BPS),
                gov.applied
                    .min_validator_bond
                    .unwrap_or(crate::staking::MIN_VALIDATOR_BOND),
                gov.applied
                    .default_commission_bps
                    .unwrap_or(crate::staking::DEFAULT_COMMISSION_BPS),
            )
        };
        GOV_PAYLOAD_SNAPSHOTS.fetch_add(1, Ordering::Relaxed);

        let mut ctx = crate::svm::VmContext {
            sender: tx.from,
            balance: sender_balance,
            orderbooks: Some(&mut orderbooks.books),
            patricia_trie: None,
            session_auth: delegation.as_mut(),
            session_keys: session_keys_work.as_mut(),
            zkml_proof: None,
            timestamp,
            trades: Vec::new(),
            transfers: Vec::new(),
            token_registry: Some(&mut *tokens),
            token_events: Vec::new(),
            contracts: Some(&mut contracts),
            staking: Some(&mut staking),
            // The committed PMM plus the two things a PMM syscall needs to
            // know: which token is the quote asset and who may mint its
            // payout. The governed redemption buffer is resolved here, once
            // per transaction, exactly like the staking parameters below - a
            // passed `SetPmmRedemptionBufferBps` has to price the buys in the
            // same block that carried it, on every node.
            pmm: Some(crate::pmm::PmmVmContext {
                state: &mut pmm,
                usdt_token: *self.pmm_usdt_token.read().await,
                treasury: *self.pmm_treasury.read().await,
                redemption_buffer_bps: gov_pmm_buffer_bps,
                events: Vec::new(),
            }),
            // Governed staking policy, resolved here so every SysCallStake in this
            // transaction sees the same values. Read once per transaction (not per
            // opcode) so the policy cannot change mid-execution.
            min_validator_bond: gov_min_validator_bond,
            default_commission_bps: gov_default_commission_bps,
            payouts: Vec::new(),
            // The committed oracle, so `SysCallSubmitPriceFeed` and the
            // `SysCallPlaceOrder` priority gates read and write consensus
            // state instead of a node-local copy.
            oracle: Some(&mut *oracle),
        };

        // DETERMINISM: `timestamp` above is the BLOCK's timestamp, passed into
        // this function from the block being applied - never the local wall
        // clock. Every node applying this block supplies the same number, so
        // freshness and monotonicity checks in `commit_feed` agree everywhere.
        //
        // `actor_send_sink` is the channel for §1: the VM has no account
        // map, so a `SysCallActorSend` can only be validated there (bounce
        // rule, prepaid delivery gas, affordability against the balance
        // mirror) and RECORDED here. `settle_actor_sends` below then moves the
        // coins and enqueues exactly what the run recorded - which is what
        // keeps a send after a `Halt` (never executed) from being settled off
        // the raw payload bytes. A payload with no actor send never allocates
        // anything measurable (the sink stays empty).
        let mut actor_send_sink: Vec<crate::svm::ActorSendRequest> = Vec::new();
        let vm_opts = crate::svm::VmExecOptions {
            exec_hardening,
            wasm_pmm_hardening,
            tx_nonce: tx.nonce,
            outbound_budget_from_accounts,
            pq_lifecycle,
            chain_id: Some(self.chain_id),
            chain_height,
            pq_registry: pq_registry_snap,
            // PARENT block hash: deterministic, already fixed by the block
            // header and independent of this payload's execution output.
            contract_block_hash: parent_block_hash,
        };
        let res = crate::svm::Svm::execute_with_confidential_and_sends_at(
            &tx.payload,
            tx.gas_limit,
            &mut ctx,
            &mut actor_send_sink,
            zkml_models_work.as_mut(),
            &vm_opts,
        );
        // The PMM's native leg: the VM moved wUSDT and advanced the curve in
        // its clone-committed registries, but it cannot mint or burn native
        // STELL - that needs the engine's account/trie writes. Taken out of
        // the context before it is dropped, settled once on the SUCCESS arm.
        let pmm_events: Vec<crate::pmm::PmmEvent> = ctx
            .pmm
            .as_mut()
            .map(|p| std::mem::take(&mut p.events))
            .unwrap_or_default();
        drop(ctx);

        // SAFETY FIX (cross-shard contract sends): a contract that emitted an
        // outbound message for a NON-LOCAL shard cannot be delivered. The
        // legacy router built an unsigned, unproven record and the hardened
        // router debited the sender before enqueuing it — a silent burn with
        // no delivery and no bounce (no consumer of `cross_shard_out` can
        // verify it). Refuse the WHOLE payload BEFORE any settlement or native
        // commit, so `apply_transaction` / the block path revert it, the fee
        // path runs as for any revert, and the sender keeps the value.
        //
        // Same-shard contract messages are untouched: they keep taking the
        // actor-inbox path. Inbound cross-shard validation is untouched too.
        if contract_send_refusal {
            let has_cross_shard = match (&res, &contract_send_refusal_topology) {
                (
                    crate::svm::VmExecutionResult::Success {
                        outbound_messages, ..
                    },
                    Some(topology),
                ) => outbound_messages.iter().any(|m| {
                    crate::svm::contract_recipient_is_cross_shard(
                        &m.recipient,
                        contract_send_local_shard,
                        contract_send_sharded,
                        topology,
                    )
                }),
                _ => false,
            };
            if has_cross_shard {
                // Undo the domain halves the VM committed in place that this
                // function can restore locally (PMM + its quote-token leg, the
                // orderbook, the oracle). The caller's `rollback_payload`
                // restores the full domain snapshot, so both apply paths are
                // all-or-nothing.
                if let Some((before_pmm, before_tokens)) = pmm_before.take() {
                    *pmm = before_pmm;
                    *tokens = before_tokens;
                }
                if let Some(before) = books_before.take() {
                    orderbooks.books = before;
                }
                restore_oracle_after_failure(&mut oracle, oracle_before.take());
                return Err(crate::svm::CROSS_SHARD_CONTRACT_SEND_REFUSAL.to_string());
            }
        }

        // Bridge intents are read straight off the payload (the VM only
        // validates them - it has no account map). Settlement below is the
        // native leg: a deposit credit, or a withdrawal debit into escrow.
        let bridge_intents: Vec<crate::bridge::BridgeIntent> = {
            let mut intents = Vec::new();
            for op in &tx.payload {
                if exec_hardening && matches!(op, crate::svm::OpCode::Halt) {
                    break;
                }
                if let crate::svm::OpCode::SysCallBridge(intent) = op {
                    intents.push((**intent).clone());
                }
            }
            intents
        };

        // A failed payload restores the pre-payload oracle (no price survives
        // a revert), keeping only a breaker latch the payload managed to trip.
        if !matches!(res, crate::svm::VmExecutionResult::Success { .. }) {
            restore_oracle_after_failure(&mut oracle, oracle_before.take());
        }

        // Settle the PMM's NATIVE leg before anything else moves coins.
        //
        // The VM already did the wUSDT half (burn on a buy, mint on a sell) and
        // advanced the curve - both inside clone-committed registries. Native
        // STELL is the engine's to move, and it has to happen here rather than
        // in the Success arm because the escrow settlement below and the VM's
        // own `current_balance` mirror both treat the swap as already applied:
        // a payload that sells STELL and then rests an order must have the
        // escrow computed against the POST-swap balance, exactly as the VM
        // priced it.
        //
        // Both failure modes roll the whole swap back, because a swap
        // straddles native and wUSDT and half of it cannot be left behind: a
        // surviving wUSDT mint with no native debit would be free money, a
        // surviving burn with no mint would destroy it.
        let mut pmm_native_snapshot: NativeAccountSnapshot = Vec::new();
        // Global-supply reservation the PMM buy leg took (0 when no buy ran or
        // the swap was refused). Rolled back with the swap on a later failure.
        let mut pmm_minted_nano: u64 = 0;
        let mut clob_native_snapshot: NativeAccountSnapshot = Vec::new();
        // Same idea for the bridge's native leg: the account halves settle here
        // so the escrow settlement below is priced against post-bridge balances,
        // and a later failure restores exactly this snapshot - accounts AND the
        // committed bridge domain (replay set, queue, rate window) the plan
        // already wrote.
        let mut bridge_snapshot: Option<BridgeSnapshot> = None;
        if let crate::svm::VmExecutionResult::Success {
            transfers,
            clob_events,
            ..
        } = &res
        {
            if !pmm_events.is_empty() {
                // What `commit_native` will still demand for this transaction.
                // Only enforced here when NO order syscalls run: the escrow
                // settlement asserts the identical floor (and can only reduce
                // the balance further) when they do, so re-asserting it on a
                // pre-escrow balance would reject fills that are about to
                // credit the sender.
                let vm_out: u64 = transfers
                    .iter()
                    .map(|(_, a)| *a)
                    .fold(0u64, u64::saturating_add);
                let floor = if clob_events.is_empty() {
                    tx.amount
                        .saturating_add(tx.gas_limit)
                        .saturating_add(vm_out)
                } else {
                    0
                };
                match self.settle_pmm_native(&pmm_events, tx.from, floor).await {
                    Ok((snapshot, minted_nano)) => {
                        pmm_native_snapshot = snapshot;
                        pmm_minted_nano = minted_nano;
                    }
                    Err(e) => {
                        // Nothing native has moved yet, so undoing the
                        // clone-committed halves is the whole rollback.
                        if !pmm_events.is_empty() {
                            if let Some((before_pmm, before_tokens)) = pmm_before.take() {
                                *pmm = before_pmm;
                                *tokens = before_tokens;
                            }
                        }
                        if let Some(before) = books_before.take() {
                            orderbooks.books = before;
                        }
                        restore_oracle_after_failure(&mut oracle, oracle_before.take());
                        return Err(e);
                    }
                }
            }

            // Settle the bridge's native leg: credit a deposit recipient, or
            // debit a withdrawal sender into `BRIDGE_ESCROW`. Like the PMM leg
            // it runs on the SUCCESS arm and before the escrow settlement, and
            // its `floor` keeps the swap/withdrawal from eating the transaction
            // reservation (only when no order syscalls re-check it below).
            //
            // SINGLE-SHARD ASSUMPTION (audit 2026-10-06): the replay set and
            // mint counters are per-engine. In a multi-shard deploy the same
            // deposit settled on two shards would credit twice, so bridge
            // intents (and token creates, whose ids derive from the per-engine
            // registry nonce) are masterchain-only BY PROTOCOL — enforcement
            // (a shard gate here) lands with multi-shard activation, NOT here:
            // live single-shard txs carry legacy source=1 tags, so a naive
            // source==0 check would brick the live stand.
            if !bridge_intents.is_empty() {
                let vm_out: u64 = transfers
                    .iter()
                    .map(|(_, a)| *a)
                    .fold(0u64, u64::saturating_add);
                let floor = if clob_events.is_empty() {
                    tx.amount
                        .saturating_add(tx.gas_limit)
                        .saturating_add(vm_out)
                } else {
                    0
                };
                // The committed validator/relayer set: the deposit quorum is
                // counted against the SAME ledger every node derives its
                // validators from, so all of them reach the same verdict on
                // the same block.
                let bridge_validators: Vec<[u8; 32]> = staking.validators.keys().copied().collect();
                // R4: the release-receipt quorum resolves each signer's PQ key
                // AT the receipt's attested height out of COMMITTED state, not
                // the process-local `PQ_VALIDATOR_KEYS` map. The guard is
                // scoped to this leg so the later `pq_registry` writers in this
                // payload cannot deadlock against it.
                let bridge_pq_keys = self.pq_registry.read().await;
                let bridge_pq_lookup = (&*staking, &*bridge_pq_keys);
                // C7 shard gate: the bridge domain (replay set, escrow,
                // mint counters, disputes) lives on the masterchain ONLY.
                // Settling the same intents on a workchain would credit
                // twice against per-engine state. Fail closed here (not in
                // `plan`, which has no notion of shards).
                if !bridge_intents.is_empty()
                    && self.cross_shard_enabled()
                    && tx.source_shard != crate::sharding::MASTERCHAIN_SHARD
                {
                    // B1: the PMM native leg was settled ABOVE this gate, so a
                    // refusal here must undo it before returning. The caller
                    // receives `Err` and rolls back with an EMPTY
                    // `ExecPostActions` (it never got one), so leaving the
                    // native STELL movement and the supply reservation behind
                    // would make a rejected transaction net-mint (buy) or
                    // net-burn (sell). The two account/trie/counter writes are
                    // not covered by the caller's payload-domain snapshot; the
                    // domain halves are also restored here so a direct
                    // `execute_payload` caller sees the same all-or-nothing
                    // result as the apply paths.
                    //
                    // Rollback-only: the refusal VERDICT is unchanged; a
                    // rejected transaction simply leaves less state behind.
                    if pmm_minted_nano > 0 {
                        self.release_mint_nano(pmm_minted_nano);
                    }
                    self.restore_pmm_native(&pmm_native_snapshot).await;
                    if !pmm_events.is_empty() {
                        if let Some((before_pmm, before_tokens)) = pmm_before.take() {
                            *pmm = before_pmm;
                            *tokens = before_tokens;
                        }
                    }
                    if let Some(before) = books_before.take() {
                        orderbooks.books = before;
                    }
                    restore_oracle_after_failure(&mut oracle, oracle_before.take());
                    return Err("bridge intents settle on the masterchain only".to_string());
                }
                match self
                    .settle_bridge_native(
                        &bridge_intents,
                        tx.from,
                        floor,
                        timestamp,
                        &bridge_validators,
                        chain_height,
                        self.chain_id,
                        &bridge_pq_lookup,
                    )
                    .await
                {
                    Ok(snap) => bridge_snapshot = snap,
                    Err(e) => {
                        // A rejected bridge intent (sub-quorum deposit, replayed
                        // source tx, an unaffordable withdrawal, a rate-limit or
                        // time-lock refusal) must undo the PMM swap too: the VM
                        // already committed its clone halves, and the payload as
                        // a whole did not apply.
                        if pmm_minted_nano > 0 {
                            self.release_mint_nano(pmm_minted_nano);
                        }
                        self.restore_pmm_native(&pmm_native_snapshot).await;
                        if !pmm_events.is_empty() {
                            if let Some((before_pmm, before_tokens)) = pmm_before.take() {
                                *pmm = before_pmm;
                                *tokens = before_tokens;
                            }
                        }
                        if let Some(before) = books_before.take() {
                            orderbooks.books = before;
                        }
                        restore_oracle_after_failure(&mut oracle, oracle_before.take());
                        return Err(e);
                    }
                }
            }
        }

        // §1 ACTOR MAILBOX: settle the sends the VM recorded above - debit the
        // sender and enqueue one message per send into the RECIPIENT's inbox.
        //
        // Placement is load-bearing. It runs with the other settlement legs,
        // AFTER the PMM and bridge legs (their floors are asserted against the
        // pre-actor balance) and BEFORE the CLOB escrow below, for two
        // reasons: the escrow re-asserts `amount + gas + transfers` against
        // the POST-actor balance and can only fail the whole transaction -
        // which is safe exactly because `actor_snapshot` below puts the coins
        // AND the queued messages back - and nothing after the escrow
        // settlement can fail, so this is the last leg that ever needs a
        // rollback record. A refused settlement itself restores the PMM /
        // bridge / book halves exactly like a refused bridge intent.
        //
        // Value conservation: the sender is debited HERE (at payload
        // settlement), the recipient is credited by the mailbox pass at
        // delivery, and a bounce returns the value to the sender EXACTLY
        // once - never both.
        let mut actor_snapshot: Option<ActorSnapshot> = None;
        if let crate::svm::VmExecutionResult::Success {
            transfers,
            clob_events,
            outbound_messages,
            ..
        } = &res
        {
            if !actor_send_sink.is_empty() {
                let vm_out: u64 = transfers
                    .iter()
                    .map(|(_, a)| *a)
                    .fold(0u64, u64::saturating_add);
                // The bridge leg's floor rule, mirrored: when the CLOB escrow
                // settles below it demands `amount + declared gas + payload
                // transfers` from the POST-settlement balance, so a payload
                // whose actor send is funded by its own fills runs with no
                // floor here (and the escrow's assertion - or its rollback of
                // this snapshot - decides the transaction as a whole). When
                // no escrow assertion will run, the floor IS what
                // `commit_native` demands later, so requiring it now is what
                // keeps a refused native commit from finding messages already
                // queued and coins already moved.
                let floor = if clob_events.is_empty() {
                    tx.amount
                        .saturating_add(tx.gas_limit)
                        .saturating_add(vm_out)
                } else {
                    0
                };
                match self
                    .settle_actor_sends(&actor_send_sink, tx.from, floor)
                    .await
                {
                    Ok(snap) => actor_snapshot = snap,
                    Err(e) => {
                        // The settlement validates everything before it
                        // mutates, so nothing actor-side survived the
                        // refusal: undoing the legs that already committed -
                        // the PMM swap, the bridge transfer, the book - is
                        // the whole rollback, exactly like the bridge's own
                        // failure arm above.
                        if pmm_minted_nano > 0 {
                            self.release_mint_nano(pmm_minted_nano);
                        }
                        self.restore_pmm_native(&pmm_native_snapshot).await;
                        self.restore_bridge_native(bridge_snapshot.as_ref()).await;
                        if !pmm_events.is_empty() {
                            if let Some((before_pmm, before_tokens)) = pmm_before.take() {
                                *pmm = before_pmm;
                                *tokens = before_tokens;
                            }
                        }
                        if let Some(before) = books_before.take() {
                            orderbooks.books = before;
                        }
                        restore_oracle_after_failure(&mut oracle, oracle_before.take());
                        return Err(e);
                    }
                }
            }

            // Route any outbound contract messages produced by SysCallCallContract.
            // Pre-hardening (< H) this runs eagerly here; at >= H (`wasm_pmm_hardening`)
            // messages are deferred via `ExecPostActions::outbound_messages` and routed
            // strictly AFTER `commit_native` succeeds so CLOB/commit failures never leak.
            if !outbound_messages.is_empty() && !wasm_pmm_hardening {
                self.process_contract_outbound_messages(outbound_messages)
                    .await
                    .map_err(|e| format!("contract outbound message routing failed: {e}"))?;
            }
        }

        // Settle the order syscalls: lock escrow for what rests, move value for
        // what filled, refund what was cancelled. This runs inside
        // `execute_payload`, so BOTH apply paths (`apply_transaction` and the
        // live block path) perform the identical settlement - the escrow and
        // value movement are not a private side effect of one of them.
        //
        // The VM has already committed the book. Anything that fails here must
        // therefore roll the book back before reporting the error (the payload
        // then behaves like a revert: no book change, no escrow change, no
        // value moved).
        if let crate::svm::VmExecutionResult::Success {
            clob_events,
            trades,
            transfers,
            ..
        } = &res
        {
            if !clob_events.is_empty() {
                // `ctx.trades` is the VM's own record of every fill it executed
                // and the events are what settlement consumes; they are two
                // views of the SAME fills (the syscall pushes each trade list
                // into both). A divergence would mean value moving for fills the
                // events never described - or fills settling for nothing - so it
                // is an error here, not a cosmetic mismatch.
                let mut from_ctx: Vec<crate::orderbook::TradeExecution> = Vec::new();
                for e in clob_events {
                    if let crate::orderbook::ClobEvent::Place { trades: t, .. } = e {
                        from_ctx.extend_from_slice(t);
                    }
                }
                if &from_ctx != trades {
                    // Restore in reverse application order: the actor leg was
                    // settled LAST of the three, so it goes first (it also
                    // keeps working if a later restore overwrites an account
                    // they share - every one of these snapshots predates the
                    // actor debit).
                    self.restore_actor_native(actor_snapshot.as_ref()).await;
                    if pmm_minted_nano > 0 {
                        self.release_mint_nano(pmm_minted_nano);
                    }
                    self.restore_pmm_native(&pmm_native_snapshot).await;
                    self.restore_bridge_native(bridge_snapshot.as_ref()).await;
                    if !pmm_events.is_empty() {
                        if let Some((before_pmm, before_tokens)) = pmm_before.take() {
                            *pmm = before_pmm;
                            *tokens = before_tokens;
                        }
                    }
                    restore_oracle_after_failure(&mut oracle, oracle_before.take());
                    return Err(
                        "SVM: ctx.trades does not match the trades carried by the order events"
                            .to_string(),
                    );
                }
                // What `commit_native` will still demand AFTER the escrow lock:
                // the admission reservation (`amount` + the DECLARED limit,
                // which is what the block path charges) plus everything the
                // payload itself transfers out. An escrow lock that ate into
                // this would leave a transaction whose payload effects are
                // already committed but whose native commit then refuses it -
                // and the two paths disagree about that: the block path charges
                // the declared limit, `apply_transaction` charges only what was
                // consumed, so the same transaction could succeed on one and
                // fail on the other. Requiring the stricter of the two here is
                // what makes them agree on the settlement outcome.
                let vm_out: u64 = transfers
                    .iter()
                    .map(|(_, a)| *a)
                    .fold(0u64, u64::saturating_add);
                let reserve = tx
                    .amount
                    .saturating_add(tx.gas_limit)
                    .saturating_add(vm_out);
                let mut escrow = self.order_escrow_write().await;
                let quote_id = *self.pmm_usdt_token.read().await;
                let books = &orderbooks.books;
                let settled = self
                    .settle_clob_effects(
                        // Borrowed straight from the VM result: no per-transaction
                        // clone of the event vector (S4). Nothing below mutates
                        // `res`; the immutable borrow ends before `match res`.
                        clob_events,
                        ClobQuoteMode::NativeSvm,
                        quote_id,
                        &mut tokens,
                        &mut escrow,
                        tx.from,
                        reserve,
                        // This payload's domains were snapshotted by the caller
                        // (`apply_transaction_at_height` / the block path) and
                        // are restored on ANY `Err` below, so the settlement may
                        // run on the live registry instead of cloning the whole
                        // token registry first.
                        !domains_restorable,
                        |pair, id| books.get(&pair).is_none_or(|b| b.find_order(id).is_none()),
                    )
                    .await;
                match settled {
                    Ok(snap) => clob_native_snapshot = snap,
                    Err(e) => {
                        // The escrow settlement plans before it writes and its
                        // own native leg is atomic, so the swap, the bridge leg
                        // and the actor sends above are the only committed
                        // movements this payload made - undo them (actor first:
                        // it was settled last), then undo the VM's halves. The
                        // TOKEN effects of a failed plan (possible only on the
                        // in-place path above) are part of this payload's
                        // domains and are restored by the caller's rollback.
                        self.restore_actor_native(actor_snapshot.as_ref()).await;
                        if pmm_minted_nano > 0 {
                            self.release_mint_nano(pmm_minted_nano);
                        }
                        self.restore_pmm_native(&pmm_native_snapshot).await;
                        self.restore_bridge_native(bridge_snapshot.as_ref()).await;
                        if !pmm_events.is_empty() {
                            if let Some((before_pmm, before_tokens)) = pmm_before.take() {
                                *pmm = before_pmm;
                                *tokens = before_tokens;
                            }
                        }
                        if let Some(before) = books_before.take() {
                            orderbooks.books = before;
                        }
                        restore_oracle_after_failure(&mut oracle, oracle_before.take());
                        return Err(format!("CLOB settlement failed: {e}"));
                    }
                }
            }
        }

        match res {
            crate::svm::VmExecutionResult::Success { .. } => {
                // NOTE (B1): contract trie entries are deliberately NOT
                // written here. The trie has no undo, and a later
                // `commit_native` refusal must leave no trace, so the caller
                // writes them after the commit, iff it succeeded.
                // Commit a registry mutation (a `SysCallRevokeSession` this
                // payload performed) - and only here: every failure path
                // above returned `Err`, so a transaction that did not fully
                // apply revokes nothing. Deliberately stricter than the token
                // /orderbook clones the VM commits internally, which survive a
                // later settlement failure: revocation must be all-or-nothing
                // with the transaction that performs it.
                if let (Some(before), Some(work)) = (&session_keys_before, session_keys_work.take())
                {
                    if *before != work {
                        *self.session_keys_write().await = work;
                    }
                }
                // §2 MODEL REGISTRY, same all-or-nothing rule as the revoke
                // above: the working copy the VM mutated is written
                // back ONLY here, at the very end of a transaction that
                // settled completely. Every `Err` above dropped the copy
                // instead, so a registration can never survive a payload that
                // did not apply - and the write accessor bumps
                // `commitment_generation`, so the next root read folds the new
                // models into the state root.
                if let (Some(before), Some(work)) = (&zkml_models_before, zkml_models_work.take()) {
                    if *before != work {
                        *self.zkml_models_write().await = work;
                    }
                }
                // Hand the settlement undo records to the caller: if its
                // `commit_native` refuses afterwards, it rolls these back
                // (plus the domain snapshot it took before calling us),
                // closing the B1 hole where a rejected transaction kept
                // bridge/actor/PMM-native legs it had already settled.
                let deferred_outbound = if wasm_pmm_hardening {
                    if let crate::svm::VmExecutionResult::Success {
                        outbound_messages, ..
                    } = &res
                    {
                        outbound_messages.clone()
                    } else {
                        Vec::new()
                    }
                } else {
                    Vec::new()
                };
                Ok((
                    res,
                    ExecPostActions {
                        bridge_snapshot,
                        actor_snapshot,
                        pmm_native_snapshot,
                        pmm_minted_nano,
                        clob_native_snapshot,
                        outbound_messages: deferred_outbound,
                    },
                ))
            }
            crate::svm::VmExecutionResult::OutOfGas => Err("SVM: out of gas".to_string()),
            crate::svm::VmExecutionResult::Reverted(e) => Err(format!("SVM reverted: {e}")),
        }
    }

    /// Formally apply a transaction with full cryptographic signature verification,
    /// anti-double-spending checks, and nonce ordering.
    ///
    /// `timestamp` is the block timestamp the transaction is being applied at
    /// (see `execute_payload`).
    pub async fn apply_transaction(
        &self,
        tx: &crate::sharding::Transaction,
        timestamp: u64,
    ) -> Result<(), String> {
        // No block context on the single-transaction path: assume the worst
        // (post-activation) when the gate is armed — fail-closed. Default-off
        // (env unset) admits byte-identically to before, at every height.
        // Block application must use [`Self::apply_transaction_at_height`]
        // with the COMMITTED block height instead.
        self.apply_transaction_at_height(tx, timestamp, u64::MAX)
            .await
    }

    /// [`Self::apply_transaction`] at an explicit chain height (A14 phase 3:
    /// the chain-binding gate refuses unbound envelopes at/after the
    /// configured activation height).
    ///
    /// GATE: `chain_height` MUST be the COMMITTED block height the
    /// transaction is applied at — never a caller-supplied or wall-clock
    /// value — or mixed-version nodes diverge on the refusal (see
    /// `docs/REPLAY_ANALYSIS.md` scenario (f)).
    ///
    /// A refused envelope is an ADMISSION-stage refusal, exactly like the
    /// neighbouring chain-id mismatch: it returns `Err` before any floor,
    /// nonce or balance effect — no fee, no nonce consumption, nothing moves
    /// (see the failure-fee contract in `tests/failure_fee_contract_tests.rs`).
    pub async fn apply_transaction_at_height(
        &self,
        tx: &crate::sharding::Transaction,
        timestamp: u64,
        chain_height: u64,
    ) -> Result<(), String> {
        if tx.is_pq_implicit()
            && crate::sharding::Transaction::global_implicit_registry()
                .lookup(&tx.from)
                .is_none()
        {
            if let Some((scheme, pk, salt)) = self.get_pinned_pubkey_with_salt(&tx.from) {
                let _ = crate::sharding::Transaction::global_implicit_registry()
                    .register(tx.from, scheme, &pk, &salt);
            }
        }
        // 1. Cryptographic signature check (FULL-PQ first: classical
        // envelopes are refused before any crypto, fee, nonce or balance
        // effect — admission-stage, like the chain-id mismatch below).
        require_pq_tx_envelope_at_height(tx, chain_height)?;
        if !tx.verify_signature_at_height(chain_height) {
            return Err("Transaction signature verification failed (forged signature)".to_string());
        }
        if let Some(cid) = tx.chain_id() {
            if cid != self.chain_id {
                return Err(format!(
                    "Transaction chain_id mismatch: chain id {} does not match this chain ({})",
                    cid, self.chain_id
                ));
            }
        }
        // A14 phase 3 (chain binding, last line of defense): an unbound
        // envelope admitted pre-activation (or smuggled past ingress) is
        // refused here at/after the activation height, with the check's
        // message verbatim. Admission-stage, exactly like the chain-id
        // mismatch above: `Err` before any state effect — no fee, no nonce.
        crate::chain_binding::check_admission_from_env(
            tx.chain_id().is_some(),
            chain_height,
            self.chain_id,
        )?;

        // F-01 floor inputs BEFORE the accounts lock (lock order:
        // governance/penalty -> accounts, same as `commit_native`). They are
        // read BEFORE the session gate because a gate refusal is an
        // attributable failure that pays the floor.
        let (floor_base, surcharge) = self.consensus_floor_parts(tx).await;

        // 1b. Session-key gate against the BLOCK timestamp: grant validity,
        //     expiry, scope, value cap and remaining budget (stateless), plus
        //     the on-chain registry - terminal revocation, the registered
        //     record's ceilings and its CUMULATIVE gas spend. The identical
        //     predicate the block path (`apply_block_parallel_fees`) and the
        //     proposer filter apply, so all of them agree on the same
        //     transaction at the same time.
        //
        //     F-01: a REFUSAL here is an ADMISSION-STAGE refusal - the block
        //     path refuses the very same predicate in its admission pass
        //     (the stateless policy + the registry simulation), and an
        //     admission refusal moves NOTHING on either path (no fee, no
        //     nonce: the transaction never ran). So this path must not charge
        //     either - the block path's `fail_with_floor!` applies to the
        //     LIVE gate below, which is the one a transaction can pass
        //     admission with and then fail.
        self.session_gate(tx, timestamp).await?;

        // 1c. PAYMASTER live gate: the sponsor grant's POLICY
        // (expiry / allowlist / per-tx cap against the fee execution will
        // charge). A refusal here is an ADMISSION-STAGE refusal — the block
        // path refuses the same predicate in its admission pass, so it moves
        // NOTHING on either path (no fee, no nonce: the transaction never
        // ran). The funding legs are pre-checked below (step 4); the commit
        // re-checks both under the lock.
        let sponsor_fee_total: Option<u64> = if let Some(_auth) = tx.sponsored_grant() {
            let fee_total = tx
                .gas_limit
                .max(floor_base)
                .checked_add(surcharge)
                .ok_or_else(|| "Arithmetic overflow in transaction cost".to_string())?;
            if let Err(e) = tx.check_sponsor_policy(timestamp, fee_total) {
                return Err(format!("sponsor grant rejected: {e}"));
            }
            Some(fee_total)
        } else {
            None
        };

        let mut map = self.accounts.write().await;

        // 2. Fetch sender account
        let sender = map
            .get_mut(&tx.from)
            .ok_or_else(|| "Sender account does not exist".to_string())?;

        // 3. Anti-Replay Nonce check
        if tx.nonce != sender.nonce {
            return Err(format!(
                "Invalid nonce: expected {}, got {} (possible replay attack)",
                sender.nonce, tx.nonce
            ));
        }

        // 4. Double-spend balance check (amount + floored fee + surcharge).
        // F-01: `commit_native` charges at least the floor, so the pre-check
        // reserves the floor too — otherwise a below-floor transaction would
        // pass here and fail there for the same balance.
        //
        // PAYMASTER v1: split legs — the user pre-covers VALUE (`amount`;
        // the fee is the sponsor's, never the user's), the sponsor
        // pre-covers FEE. A short leg is refused WITHOUT charge (admission-
        // stage, like the legacy shortfall below); a failure past this point
        // charges the sponsor leg via `charge_failure_fee_and_commit`.
        let fee_reserved = tx.gas_limit.max(floor_base);
        if let Some(fee_total) = sponsor_fee_total {
            if sender.balance < tx.amount {
                return Err(format!(
                    "Insufficient balance: account has {} nano-STELL, requires {} (double spend rejected)",
                    sender.balance, tx.amount
                ));
            }
            let sponsor = tx.fee_payer();
            // `sender` is not used after the user-leg check above, so its
            // borrow has ended (NLL) and the sponsor leg reads disjointly.
            let sponsor_balance = map.get(&sponsor).map(|a| a.balance).unwrap_or(0);
            if sponsor_balance < fee_total {
                return Err(format!(
                    "Sponsor has insufficient balance for fee: sponsor has {sponsor_balance} nano-STELL, requires {fee_total}"
                ));
            }
        } else {
            let total_cost = tx
                .amount
                .checked_add(fee_reserved)
                .and_then(|t| t.checked_add(surcharge))
                .ok_or_else(|| "Arithmetic overflow in transaction cost".to_string())?;

            if sender.balance < total_cost {
                return Err(format!(
                    "Insufficient balance: account has {} nano-STELL, requires {} (double spend rejected)",
                    sender.balance, total_cost
                ));
            }
        }

        // 5. Execute the optional SVM payload BEFORE committing native balance
        //    changes, so a reverting/out-of-gas program leaves no partial effect
        //    (the SVM itself uses clone-commit for tokens/orderbooks). Release the
        //    account lock while the VM runs to avoid holding it across await.
        drop(map);
        // What the executor MEASURED (FEE-01): the VM's `gas_used` for a
        // payload, 0 when no VM ran. The fee is derived from it in
        // `commit_native`, never from the declared limit.
        let gas_charged;
        // Value movements the payload itself performed. These used to be thrown
        // away, so `OpCode::Transfer` (and the staking bond, which parks funds in
        // the staking pool) moved nothing on chain while still succeeding - a
        // free validator bond. They are applied below, together with the fee.
        let mut vm_transfers: Vec<([u8; 32], u64)> = Vec::new();
        let mut vm_payouts: Vec<([u8; 32], [u8; 32], u64)> = Vec::new();
        // Native coins the payload BURNED (`(account, amount)`): today only
        // the post-quantum equivocation slash, whose burn comes out of the
        // staking pool. Settled by `commit_native` alongside every other
        // native movement, so a refused transaction burns nothing.
        let mut vm_burns: Vec<([u8; 32], u64)> = Vec::new();
        // B1 atomicity: snapshot every domain the payload can mutate BEFORE
        // the VM runs. Any failure after this point - a VM revert, a
        // settlement refusal, or the native commit below - restores the
        // snapshot, so a rejected transaction leaves no free bond, no free
        // mint and no half-settled legs behind. Empty payloads touch no
        // domain and skip the snapshot.
        let exec_hardening = crate::chain_spec::exec_hardening_v1_active_at(chain_height);
        let domain_snap = if tx.payload.is_empty() {
            None
        } else {
            Some(
                self.snapshot_payload_domains_at(&tx.payload, exec_hardening)
                    .await,
            )
        };
        // Settlement undo records (bridge/actor/PMM-native direct map
        // writes), filled on VM success for the commit-failure path below.
        let mut post_actions: Option<ExecPostActions> = None;
        if !tx.payload.is_empty() {
            // Domains were snapshotted just above (`domain_snap`), so the
            // settlement may run in place: this caller restores them on `Err`.
            let exec = self
                .execute_payload_with_preverify_at_height_and_parent_restorable(
                    tx,
                    timestamp,
                    chain_height,
                    [0u8; 32],
                )
                .await;
            let (res, actions) = match exec {
                Ok(v) => v,
                // Settlement (or deeper) refused AFTER the VM committed its
                // working copies live: restore everything (B1), then report.
                // (A bare VM revert/OutOfGas needs no restore — the VM only
                // writes back on Success, and the working copies die with it.)
                Err(e) => {
                    if let Some(snap) = domain_snap {
                        self.rollback_payload(
                            snap,
                            ExecPostActions {
                                bridge_snapshot: None,
                                actor_snapshot: None,
                                pmm_native_snapshot: Vec::new(),
                                pmm_minted_nano: 0,
                                clob_native_snapshot: Vec::new(),
                                outbound_messages: Vec::new(),
                            },
                        )
                        .await;
                    }
                    // F-01: an attributable failure pays the failure fee and
                    // consumes the nonce, exactly like the block path.
                    self.charge_failure_fee_and_commit(tx, floor_base, surcharge)
                        .await;
                    return Err(e);
                }
            };
            match res {
                crate::svm::VmExecutionResult::Success {
                    gas_used,
                    transfers,
                    payouts,
                    burns,
                    ..
                } => {
                    gas_charged = gas_used;
                    vm_transfers = transfers;
                    vm_payouts = payouts;
                    vm_burns = burns;
                    post_actions = Some(actions);
                }
                crate::svm::VmExecutionResult::OutOfGas => {
                    // F-01: the failure fee + the nonce, like the block path.
                    self.charge_failure_fee_and_commit(tx, floor_base, surcharge)
                        .await;
                    return Err("SVM: out of gas".to_string());
                }
                crate::svm::VmExecutionResult::Reverted(e) => {
                    // F-01: the failure fee + the nonce, like the block path.
                    self.charge_failure_fee_and_commit(tx, floor_base, surcharge)
                        .await;
                    return Err(format!("SVM reverted: {e}"));
                }
            }
        } else {
            // FEE-01: no VM ran, so the executor measured 0 gas. The intrinsic
            // envelope cost is added by `billed_gas` at the commit below; the
            // declared limit is NOT the consumption.
            gas_charged = 0;
        }

        // 6. Commit the native movement (amount + fee + payload value) through
        //    the shared commit point, then write ONLY the touched accounts.
        //    B1: a refusal here rolls back EVERYTHING (see rollback_payload).
        let (mut touched, _fee) = match self
            .commit_native_at(
                tx,
                gas_charged,
                &vm_transfers,
                &vm_payouts,
                &vm_burns,
                timestamp,
                chain_height,
            )
            .await
        {
            Ok(v) => v,
            Err(e) => {
                if let (Some(snap), Some(actions)) = (domain_snap, post_actions) {
                    self.rollback_payload(snap, actions).await;
                }
                // F-01: the failure fee + the nonce, like the block path.
                self.charge_failure_fee_and_commit(tx, floor_base, surcharge)
                    .await;
                return Err(e);
            }
        };
        if let Some(ref actions) = post_actions {
            if !actions.outbound_messages.is_empty() {
                let outbound_touched = self
                    .process_contract_outbound_messages_hardened(
                        &actions.outbound_messages,
                        chain_height,
                    )
                    .await;
                touched.extend(outbound_touched);
            }
        }
        // Session budget: charged only now that the transaction has actually
        // applied, and with the gas it is BILLED for (`billed_gas`: the VM's
        // measurement for a payload, the intrinsic envelope cost for an
        // empty-payload transfer, both capped at the declared limit). The
        // block path files the same number, so the registry does not care
        // which path applied the transaction.
        self.session_note_applied(tx, Self::billed_gas_at(tx, gas_charged, exec_hardening))
            .await;
        // Contract deploys commit code hashes here — AFTER the native commit,
        // never speculatively inside execution (B1: the trie has no undo).
        // Read (never write-locked together with the trie below): lock order
        // is contracts-then-trie everywhere, or ABBA-deadlock with writers.
        let has_deploy = tx
            .payload
            .iter()
            .any(|op| matches!(op, crate::svm::OpCode::SysCallDeployContract { .. }));
        let pre_contracts = if has_deploy {
            domain_snap.as_ref().and_then(|s| s.contracts.as_ref())
        } else {
            None
        };
        let entries: Vec<([u8; 32], Vec<u8>)> = {
            let map = self.accounts.read().await;
            touched
                .into_iter()
                .map(|(addr, balance, nonce)| {
                    let data = if let Some(acc) = map.get(&addr) {
                        acc.to_trie_bytes()
                    } else {
                        let mut data = Vec::with_capacity(16);
                        data.extend_from_slice(&balance.to_be_bytes());
                        data.extend_from_slice(&nonce.to_be_bytes());
                        data
                    };
                    (addr, data)
                })
                .collect()
        };
        let contracts_guard = if pre_contracts.is_some() {
            Some(self.contracts_read().await)
        } else {
            None
        };
        let mut trie = self.state_trie.write().await;
        for (addr, data) in entries {
            trie.insert(&addr, &data);
        }
        if let (Some(contracts), Some(pre)) = (contracts_guard.as_deref(), pre_contracts) {
            let changed: Vec<[u8; 32]> = contracts
                .contracts
                .iter()
                .filter(|(addr, c)| {
                    pre.contracts.get(*addr).is_none_or(|prev| {
                        prev.code_hash != c.code_hash
                            || prev.abi != c.abi
                            || prev.source_hash != c.source_hash
                    })
                })
                .map(|(addr, _)| *addr)
                .collect();
            write_contract_trie_entries_for_addrs(&mut trie, contracts, &changed);
        }
        drop(trie);
        drop(contracts_guard);
        // R7/C2: the carrier committed, so consume its intent nullifier (the
        // check ran before execution in `execute_payload_with_preverify`).
        if let Some(digest) = crate::evm_adapter::carrier_intent_digest(tx) {
            self.mark_evm_intent_settled(&digest).await;
        }
        if crate::state_engine::evm_bindings_state_active_at(chain_height) {
            if let Some((evm, pq)) =
                crate::evm_adapter::verified_binding_from_tx_at(tx, exec_hardening)
            {
                let needs_insert = {
                    let guard = self.evm_bindings.read().await;
                    guard.get_pq(&evm).is_none() && guard.get_evm(&pq).is_none()
                };
                if needs_insert {
                    let _ = self.evm_bindings_write().await.bind(evm, pq);
                }
            }
        }
        // H1: a committed single transaction feeds the same routing/settlement
        // indexes as a block apply.
        self.observe_committed_evm_tx(tx);
        self.apply_pq_lifecycle_tx_ops(tx, chain_height).await;

        Ok(())
    }

    /// The full session gate: the stateless GRANT policy
    /// (`Transaction::check_session_policy` - signature, master binding, the
    /// grant's own expiry/scope/value/budget) plus the stateful REGISTRY
    /// policy (terminal revocation, master binding of the record, the record's
    /// ceilings, and cumulative spend).
    ///
    /// `sim` carries gas that earlier transactions of this SAME pass have
    /// already committed but not yet deducted (the deduction only lands when a
    /// transaction applies). Admission and the proposer filter thread one
    /// through; a plain live check passes an empty one.
    ///
    /// `now` is always the BLOCK timestamp in consensus - never wall time - so
    /// every node reaches the same verdict (see `check_session_policy`).
    pub async fn session_gate_with(
        &self,
        tx: &crate::sharding::Transaction,
        now: u64,
        sim: &mut crate::zkml::SessionSpendSim,
    ) -> Result<(), String> {
        if let Err(e) = tx.check_session_policy(now) {
            return Err(format!("session key delegation rejected: {e}"));
        }
        let Some(d) = tx.delegation() else {
            return Ok(()); // legacy transaction: nothing registered, nothing to gate
        };
        // CHAIN ID: the domain separator binds `chain_id` into the master's
        // signature, which makes a grant unambiguous between chains - but on
        // its own it only stops a grant from being REPLAYED, it does not stop
        // this node from ACCEPTING a grant minted for another chain. Compare
        // the grant's chain id against this node's configured id here, on the
        // consensus path, so every node on a network refuses the same foreign
        // grants. Node-local config, never committed: chain id must not move
        // the state root, or two chains could never share a genesis KAT.
        if d.chain_id != self.chain_id {
            return Err(format!(
                "session key delegation rejected: chain id {} does not match this chain ({})",
                d.chain_id, self.chain_id
            ));
        }
        // REVOCATION IS A MASTER CAPABILITY. A transaction that carries a
        // delegation envelope was authorized by a SESSION key, even though
        // `tx.from` is the master (`Transaction::sign_with_session` keeps the
        // master as the sender). The VM's `SysCallRevokeSession` only checks
        // `record.master == ctx.sender`, i.e. `record.master == tx.from`, which
        // for a delegated transaction is trivially true - so without this guard
        // a single leaked agent key could revoke EVERY OTHER grant its master
        // ever issued. Refuse it here, before the payload runs: revocation must
        // be signed by the master key itself (a legacy signature), never by a
        // key the master delegated to. Deterministic (payload + sender only).
        if tx
            .payload
            .iter()
            .any(|op| matches!(op, crate::svm::OpCode::SysCallRevokeSession { .. }))
        {
            return Err(
                "session key delegation rejected: a delegated session key may not revoke \
                 session keys; revocation requires the master signature"
                    .to_string(),
            );
        }
        // One definition (including the actor-mailbox scope), shared with the
        // block admission pass and the proposer filter - see
        // `Transaction::required_scope`.
        let required_scope = tx.required_scope();
        let reg = self.session_keys.read().await;
        if let Err(e) = reg.check(&d, tx.amount, tx.gas_limit, required_scope, now, sim) {
            return Err(format!("session key delegation rejected: {e}"));
        }
        Ok(())
    }

    /// The session gate against the state as it stands right now.
    pub async fn session_gate(
        &self,
        tx: &crate::sharding::Transaction,
        now: u64,
    ) -> Result<(), String> {
        let mut sim = crate::zkml::SessionSpendSim::default();
        self.session_gate_with(tx, now, &mut sim).await
    }

    /// Charge a session grant for a transaction that APPLIED, lazily
    /// registering it on first use.
    ///
    /// Called only after `commit_native` succeeded, so a refused transaction
    /// never consumes budget - and only for a transaction that carried a grant
    /// (legacy transactions have nothing to charge).
    pub(in crate::state_engine) async fn session_note_applied(
        &self,
        tx: &crate::sharding::Transaction,
        gas_used: u64,
    ) {
        let Some(d) = tx.delegation() else {
            return;
        };
        let mut reg = self.session_keys_write().await;
        reg.note_applied(&d, gas_used);
    }

    /// Hardened (`>= H`) contract outbound message processor called strictly
    /// AFTER `commit_native` succeeds. Debits `accounts[msg.sender]` before
    /// queuing or bouncing and returns `(addr, balance, nonce)` for `state_trie`.
    pub(in crate::state_engine) async fn process_contract_outbound_messages_hardened(
        &self,
        messages: &[crate::contract::ContractMessage],
        chain_height: u64,
    ) -> Vec<([u8; 32], u64, u64)> {
        if messages.is_empty() {
            return Vec::new();
        }
        let my_shard = self.shard_id();
        let sharded = self.cross_shard_enabled();
        let topology = self.shard_topology.read().await.clone();
        let mut map = self.accounts.write().await;
        let mut xout = self.cross_shard_out.write().await;
        crate::svm::Svm::route_contract_messages_hardened(
            messages,
            &mut map,
            &mut xout,
            my_shard,
            sharded,
            &topology,
            chain_height,
        )
    }
}
