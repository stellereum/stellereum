use super::types::{
    contract_key, decode_actor_body, encode_actor_body, hashpool_commitment_key,
    hashpool_nullifier_key, restore_oracle_after_failure, token_balance_key, token_supply_key,
    write_contract_trie_entries, ActorSnapshot, BridgeSnapshot, ClobQuoteMode, DeliveryCtx,
    MessageUndo, PayloadDomainSnapshot,
};
use super::verify_once::require_pq_tx_envelope_at_height;
use super::{
    AccountState, ActorMessage, BlockTransitionOutcome, ExecPostActions, GovOpsOutcome,
    HashPoolApplyOutcome, HashPoolBlockOps, HashPoolOpError, InMemoryStateEngine,
    HASH_POOL_ENABLED, MAX_ACTOR_MSGS_PER_BLOCK, MAX_ACTOR_ROUNDS,
};
use crate::token::TokenRegistry;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering;

impl InMemoryStateEngine {
    /// Asynchronously send a message to an actor's inbox
    pub async fn send_message(&self, msg: ActorMessage) -> Result<(), String> {
        let mut map = self.accounts.write().await;

        // SECURITY: a message MUST come from an existing actor. Otherwise a message
        // from a non-existent sender would credit the recipient without debiting
        // anyone — free money. (Previously the balance check was skipped when the
        // sender was absent, and the value was still enqueued.)
        let sender_acc = map
            .get_mut(&msg.sender)
            .ok_or_else(|| format!("Sender {:?} does not exist", msg.sender))?;
        if sender_acc.balance < msg.value {
            return Err(format!(
                "Sender {:?} has insufficient balance for message value {}",
                msg.sender, msg.value
            ));
        }
        sender_acc.balance -= msg.value;
        sender_acc.nonce += 1;

        // Enqueue to recipient inbox if recipient exists; otherwise handle bounce
        if let Some(recipient_acc) = map.get_mut(&msg.recipient) {
            recipient_acc.inbox.push_back(msg);
        } else if msg.bounce && !msg.bounced {
            // Bounce: return the value via a message in the sender's inbox.
            // The value is credited EXACTLY ONCE, when the execution step
            // processes this message (not immediately here — that caused a
            // double-credit and broke value conservation).
            if let Some(sender_acc) = map.get_mut(&msg.sender) {
                let bounce_msg = ActorMessage {
                    msg_id: msg.msg_id,
                    sender: msg.recipient,
                    recipient: msg.sender,
                    value: msg.value,
                    body: msg.body,
                    bounce: false,
                    bounced: true,
                };
                sender_acc.inbox.push_back(bounce_msg);
            }
        }

        Ok(())
    }

    /// Execute a discrete execution step across all actors processing inboxes
    /// Returns the number of messages successfully processed
    pub async fn step_actor_execution(&self) -> Result<usize, String> {
        let mut map = self.accounts.write().await;
        let mut processed = 0;
        let mut new_messages: Vec<ActorMessage> = Vec::new();

        let addresses: Vec<[u8; 32]> = map.keys().copied().collect();

        for addr in addresses {
            let mut messages_to_run = Vec::new();
            if let Some(actor) = map.get_mut(&addr) {
                while let Some(msg) = actor.inbox.pop_front() {
                    messages_to_run.push(msg);
                }
            }

            for msg in messages_to_run {
                if let Some(actor) = map.get_mut(&addr) {
                    actor.balance = actor.balance.saturating_add(msg.value);
                    processed += 1;

                    // If actor has generated outbox messages, collect them
                    while let Some(out) = actor.outbox.pop_front() {
                        new_messages.push(out);
                    }
                }
            }
        }

        // Route any newly generated outbox messages.
        // Value accounting: debit the emitting actor NOW, credit the recipient
        // when the message is processed in a later step. A bounce returns the
        // value via a message (credited once on the next step). This keeps
        // total value conserved (no double-credit, no free minting).
        for msg in new_messages {
            // SECURITY: refuse to route a message whose sender does not exist —
            // otherwise the recipient would be credited with value nobody paid.
            let Some(snd) = map.get_mut(&msg.sender) else {
                continue;
            };
            if snd.balance < msg.value {
                continue; // cannot fund the message -> drop
            }
            snd.balance -= msg.value;
            if let Some(rec) = map.get_mut(&msg.recipient) {
                rec.inbox.push_back(msg);
            } else if msg.bounce && !msg.bounced {
                if let Some(snd) = map.get_mut(&msg.sender) {
                    let bounce_msg = ActorMessage {
                        msg_id: msg.msg_id,
                        sender: msg.recipient,
                        recipient: msg.sender,
                        value: msg.value,
                        body: msg.body,
                        bounce: false,
                        bounced: true,
                    };
                    snd.inbox.push_back(bounce_msg);
                }
            }
        }

        // Update state trie for all accounts
        let mut trie = self.state_trie.write().await;
        for (addr, acc) in map.iter() {
            let data = acc.to_trie_bytes();
            trie.insert(addr, &data);
        }

        Ok(processed)
    }

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
    pub(super) async fn snapshot_payload_domains(
        &self,
        payload: &[crate::svm::OpCode],
    ) -> PayloadDomainSnapshot {
        self.snapshot_payload_domains_at(payload, false).await
    }

    /// Height-gated variant of [`Self::snapshot_payload_domains`].
    /// When `exec_hardening` is true, stops scanning at the first `OpCode::Halt`
    /// and includes `SysCallCallContractArgs` (contracts) and
    /// `SysCallSubmitPqPriceFeed` (oracle).
    pub(super) async fn snapshot_payload_domains_at(
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
    pub(super) async fn rollback_payload(
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
    #[allow(clippy::type_complexity)]
    // GATE: execution snapshot uses account tuple layout shared with commit path.
    pub async fn execute_payload_with_preverify_at_height(
        &self,
        tx: &crate::sharding::Transaction,
        timestamp: u64,
        chain_height: u64,
    ) -> Result<(crate::svm::VmExecutionResult, ExecPostActions), String> {
        let exec_hardening = crate::chain_spec::exec_hardening_v1_active_at(chain_height);
        let wasm_pmm_hardening =
            crate::chain_spec::wasm_xshard_pmm_hardening_active_at(chain_height);
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
                redemption_buffer_bps: {
                    let gov = self.governance.read().await;
                    gov.applied
                        .pmm_redemption_buffer_bps
                        .unwrap_or(crate::pmm::PMM_REDEMPTION_BUFFER_BPS)
                },
                events: Vec::new(),
            }),
            // Governed staking policy, resolved here so every SysCallStake in this
            // transaction sees the same values. Read once per transaction (not per
            // opcode) so the policy cannot change mid-execution.
            min_validator_bond: {
                let gov = self.governance.read().await;
                gov.applied
                    .min_validator_bond
                    .unwrap_or(crate::staking::MIN_VALIDATOR_BOND)
            },
            default_commission_bps: {
                let gov = self.governance.read().await;
                gov.applied
                    .default_commission_bps
                    .unwrap_or(crate::staking::DEFAULT_COMMISSION_BPS)
            },
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
        let mut pmm_native_snapshot: Vec<([u8; 32], Option<(u64, u64)>)> = Vec::new();
        // Global-supply reservation the PMM buy leg took (0 when no buy ran or
        // the swap was refused). Rolled back with the swap on a later failure.
        let mut pmm_minted_nano: u64 = 0;
        let mut clob_native_snapshot: Vec<([u8; 32], Option<(u64, u64)>)> = Vec::new();
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
                // C7 shard gate: the bridge domain (replay set, escrow,
                // mint counters, disputes) lives on the masterchain ONLY.
                // Settling the same intents on a workchain would credit
                // twice against per-engine state. Fail closed here (not in
                // `plan`, which has no notion of shards).
                if !bridge_intents.is_empty()
                    && self.cross_shard_enabled()
                    && tx.source_shard != crate::sharding::MASTERCHAIN_SHARD
                {
                    return Err("bridge intents settle on the masterchain only".to_string());
                }
                match self
                    .settle_bridge_native(
                        &bridge_intents,
                        tx.from,
                        floor,
                        timestamp,
                        &bridge_validators,
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
                let clob_events = clob_events.clone();
                let mut escrow = self.order_escrow_write().await;
                let quote_id = *self.pmm_usdt_token.read().await;
                let books = &orderbooks.books;
                let settled = self
                    .settle_clob_effects(
                        &clob_events,
                        ClobQuoteMode::NativeSvm,
                        quote_id,
                        &mut tokens,
                        &mut escrow,
                        tx.from,
                        reserve,
                        |pair, id| books.get(&pair).is_none_or(|b| b.find_order(id).is_none()),
                    )
                    .await;
                match settled {
                    Ok(snap) => clob_native_snapshot = snap,
                    Err(e) => {
                        // The escrow settlement committed nothing (it plans on
                        // private copies and only writes once the whole plan is
                        // funded), so the swap, the bridge leg and the actor sends
                        // above are the only native movements this payload made -
                        // undo them (actor first: it was settled last), then undo
                        // the VM's halves.
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
            let exec = self
                .execute_payload_with_preverify_at_height(tx, timestamp, chain_height)
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
                    .process_contract_outbound_messages_hardened(&actions.outbound_messages)
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
        let deployed_contracts = if tx
            .payload
            .iter()
            .any(|op| matches!(op, crate::svm::OpCode::SysCallDeployContract { .. }))
        {
            Some((*self.contracts_read().await).clone())
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
        let mut trie = self.state_trie.write().await;
        for (addr, data) in entries {
            trie.insert(&addr, &data);
        }
        if let Some(contracts) = deployed_contracts.as_ref() {
            write_contract_trie_entries(&mut trie, contracts);
        }
        drop(trie);
        // R7/C2: the carrier committed, so consume its intent nullifier (the
        // check ran before execution in `execute_payload_with_preverify`).
        if let Some(digest) = crate::evm_adapter::carrier_intent_digest(tx) {
            self.mark_evm_intent_settled(&digest).await;
        }
        if super::evm_bindings_state_active_at(chain_height) {
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

        Ok(())
    }

    /// F-01 consensus floor for `tx`, split into parts.
    ///
    /// MIRROR of admission `Mempool::effective_floor_for_tx` (mempool.rs):
    /// `base_fee + failed_penalty + (is_pq_activation ? 45k : 0)`. The three
    /// parts map onto consensus-visible inputs as follows:
    ///
    /// * BASE: the GOVERNED `min_gas_limit` (committed state, identical on
    ///   every node that applied the same chain). Admission uses
    ///   `max(frozen, governed)` (`Mempool::frozen_base_fee_floor` + the
    ///   per-finalize sync in main.rs); the frozen half is the same const on
    ///   every node by construction. When governance never raised the floor,
    ///   the two bases coincide at `FROZEN_MIN_GAS_FLOOR`, and a higher
    ///   governed value only ever makes admission STRICTER, never consensus
    ///   looser.
    /// * PENALTY: this engine's deterministic D2 mirror (`consensus_penalty`,
    ///   same step/cap/clear rule as `note_apply_feedback`), derived purely
    ///   from applied blocks, so all nodes that applied the same chain agree.
    /// * SURCHARGE: `PQ_ACTIVATION_SURCHARGE_GAS` under the same
    ///   `is_pq_activation()` predicate admission and packing use.
    ///
    /// Returns `(floor_base, surcharge)`; callers charge
    /// `max(declared, floor_base) + surcharge`, so execution never prices
    /// below the full admission floor. Fail-closed in one direction only:
    /// the floor can only ever raise what a transaction pays, never lower
    /// it (a zero governed floor + no penalty + no activation = floor 0,
    /// i.e. exactly today's behaviour).
    pub async fn consensus_floor_parts(&self, tx: &crate::sharding::Transaction) -> (u64, u64) {
        let governed = self
            .governance_read()
            .await
            .applied
            .min_gas_limit
            .unwrap_or(0);
        let penalty = self
            .consensus_penalty
            .read()
            .await
            .get(&tx.from)
            .copied()
            .unwrap_or(0);
        let floor_base = governed.saturating_add(penalty);
        // R6: ONE definition, the same one admission/reservation/packing use.
        // It includes the PQ activation surcharge AND the EVM carrier
        // surcharge, so an admitted carrier cannot be included below the
        // advertised floor: execution charges the surcharge too, not just
        // admission.
        let surcharge = crate::mempool::Mempool::surcharges_for_tx(tx);
        (floor_base, surcharge)
    }

    /// The D2 penalty map, read WITHOUT blocking (the proposal validation
    /// path is synchronous).
    ///
    /// Returns `Err` when the lock is contended: the caller MUST fail CLOSED
    /// on it (refuse the proposal), exactly like the mempool floor read in the
    /// same path - a contended read must never silently lower the floor the
    /// apply path will charge with.
    #[allow(clippy::result_unit_err)]
    // GATE: contended-lock signal uses unit error; custom type would change public API.
    pub fn consensus_penalty_try_read(&self) -> Result<HashMap<[u8; 32], u64>, ()> {
        self.consensus_penalty
            .try_read()
            .map(|p| p.clone())
            .map_err(|_| ())
    }

    /// The CONSENSUS fee floor inputs, snapshotted once: the governed
    /// `min_gas_limit` and the D2 penalty map.
    ///
    /// A caller that has to evaluate the floor for MANY transactions (the
    /// proposal validator) takes one snapshot and computes the floors from it,
    /// instead of taking the governance and penalty locks per transaction.
    /// The values are the ones [`Self::consensus_floor_parts`] reads, so the
    /// two can never disagree.
    pub async fn consensus_floor_snapshot(&self) -> (u64, HashMap<[u8; 32], u64>) {
        let governed = self
            .governance_read()
            .await
            .applied
            .min_gas_limit
            .unwrap_or(0);
        let penalties: HashMap<[u8; 32], u64> = self.consensus_penalty.read().await.clone();
        (governed, penalties)
    }

    /// Pure (sync) half of [`Self::consensus_floor_parts`] over pre-loaded
    /// inputs, for passes that must not await per transaction while holding
    /// the accounts/session guards (the block admission pass, the parallel
    /// plain fast path). Callers load the governed base + penalty snapshot
    /// once per block; the formula is identical to the async helper above.
    pub(super) fn floor_parts_for(
        governed_base: u64,
        penalties: &HashMap<[u8; 32], u64>,
        tx: &crate::sharding::Transaction,
    ) -> (u64, u64) {
        let floor_base =
            governed_base.saturating_add(penalties.get(&tx.from).copied().unwrap_or(0));
        // R6: identical to `consensus_floor_parts` (PQ activation + EVM carrier
        // surcharges), so the block path and the single-tx path charge the
        // same execution fee.
        let surcharge = crate::mempool::Mempool::surcharges_for_tx(tx);
        (floor_base, surcharge)
    }

    /// FEE-01: the INTRINSIC envelope gas every transaction consumes before a
    /// single payload opcode runs — signature verification, nonce ordering,
    /// fee/transfer bookkeeping.
    ///
    /// Priced at [`crate::svm::GAS_BASIC_TRANSFER`] because that is already
    /// the frozen admission floor (`Mempool::FROZEN_MIN_GAS_FLOOR`) and the
    /// price of the cheapest meaningful operation, and because the shipped
    /// RPC estimator (`rpc::reads::simulate_and_estimate_fee`) prices the
    /// same quantity for an empty-payload transaction. Keeping all three on
    /// one constant is what makes "estimate == charge" true.
    pub(crate) const TX_INTRINSIC_GAS: u64 = crate::svm::GAS_BASIC_TRANSFER;

    /// FEE-01: the gas a transaction is BILLED for, from the gas its
    /// execution actually consumed.
    ///
    /// ```text
    /// billed = min(tx.gas_limit, gas_used + intrinsic(tx))
    /// ```
    ///
    ///  * `gas_used` is the EXECUTOR's own measurement
    ///    (`VmExecutionResult::Success { gas_used }`) — never the declared
    ///    limit, which is a budget, not a consumption;
    ///  * `intrinsic(tx)` is [`Self::TX_INTRINSIC_GAS`] for an EMPTY-payload
    ///    transaction and for a payload that measured ZERO gas (only
    ///    zero-priced opcodes such as `Halt`), and 0 otherwise. No VM runs for
    ///    an empty payload, so the envelope is its WHOLE cost and 0 would make
    ///    a plain transfer free; the same is true of a successful payload
    ///    that consumed nothing (otherwise `[Halt]` was a zero-fee,
    ///    nonce-advancing spam transaction). A payload's opcode gas already
    ///    prices the envelope and the execution it performs (the cheapest
    ///    meaningful syscall is priced well above 0), so adding the intrinsic
    ///    to a NON-zero measurement would double-price every contract call,
    ///    make every RPC estimate under-charge by it, and re-introduce the
    ///    over-charge for the cheap staking ops (`SysCallStake` costs 2 000
    ///    gas, and the single-tx path correctly charged those 2 000, not the
    ///    10 000 declared — see `bonding_moves_real_funds_and_grants_validator_power`);
    ///  * `tx.gas_limit` is a CAP, never the price: everything above what the
    ///    transaction used is refunded.
    ///
    /// The consensus floor still applies ON TOP ([`Self::fee_for_gas`]), so a
    /// transaction that declares less than the floor is never executed below
    /// it.
    #[allow(dead_code)] // GATE: kept for legacy callers alongside billed_gas_at
    pub(super) fn billed_gas(tx: &crate::sharding::Transaction, gas_used: u64) -> u64 {
        Self::billed_gas_at(tx, gas_used, false)
    }

    /// Height-gated [`Self::billed_gas`]:
    /// - `< H` (`exec_hardening == false`): `gas_used + TX_INTRINSIC_GAS` when payload is empty or `gas_used == 0`, else `gas_used`, capped at `tx.gas_limit`.
    /// - `>= H` (`exec_hardening == true`): `gas_used.max(TX_INTRINSIC_GAS).min(tx.gas_limit)` so `[OpCode::Nop]` pays `280_000` without adding `280_000` on top of payloads with `gas_used > 280_000`.
    pub(super) fn billed_gas_at(
        tx: &crate::sharding::Transaction,
        gas_used: u64,
        exec_hardening: bool,
    ) -> u64 {
        if exec_hardening {
            gas_used.max(Self::TX_INTRINSIC_GAS).min(tx.gas_limit)
        } else {
            let intrinsic = if tx.payload.is_empty() || gas_used == 0 {
                Self::TX_INTRINSIC_GAS
            } else {
                0
            };
            gas_used.saturating_add(intrinsic).min(tx.gas_limit)
        }
    }

    /// FEE-01: the fee for one transaction.
    ///
    /// `max(min(gas_limit, gas_used + intrinsic), floor_base) + surcharge`
    /// — the exact rule both apply paths now share (the block path used to
    /// pass the DECLARED `gas_limit` and therefore charge it in full; see
    /// the `commit_native` docs). The floor is fail-closed: it can only
    /// raise the fee, never lower it, and the PQ surcharge is additive, as
    /// before.
    #[allow(dead_code)] // GATE: kept for legacy callers alongside fee_for_gas_at
    pub(super) fn fee_for_gas(
        tx: &crate::sharding::Transaction,
        gas_used: u64,
        floor_base: u64,
        surcharge: u64,
    ) -> u64 {
        Self::fee_for_gas_at(tx, gas_used, floor_base, surcharge, false)
    }

    /// Height-gated [`Self::fee_for_gas`].
    pub(super) fn fee_for_gas_at(
        tx: &crate::sharding::Transaction,
        gas_used: u64,
        floor_base: u64,
        surcharge: u64,
        exec_hardening: bool,
    ) -> u64 {
        Self::billed_gas_at(tx, gas_used, exec_hardening)
            .max(floor_base)
            .saturating_add(surcharge)
    }

    /// FEE-01: the fee an ATTRIBUTABLE FAILURE pays.
    ///
    /// The failure arm of [`crate::svm::VmExecutionResult`] (`OutOfGas`,
    /// `Reverted`) carries no consumption measurement — the VM drops its
    /// meter when it aborts — so the billed gas is [`Self::TX_INTRINSIC_GAS`]:
    /// the one quantity the executor is GUARANTEED to have consumed. It is not
    /// payload-conditional here (unlike [`Self::billed_gas`]): a FAILED
    /// payload did run, and the envelope is the part whose consumption is
    /// certain. The declared limit is deliberately NOT used as a stand-in —
    /// it is a budget, and charging it was the over-charge FEE-01 closes (a
    /// 10 000 000-gas declaration that reverted after 3 opcodes paid
    /// 10 000 000). The bill is still capped by the declaration, floored by
    /// consensus, surcharge additive.
    ///
    /// A failure is still strictly expensive: the fee is floored at the
    /// consensus floor (governed base + D2 penalty) plus the PQ surcharge,
    /// so the D2 free-failure loop stays closed — a failure costs at least a
    /// basic transfer. The one thing it can no longer do is price block
    /// space it did not use.
    ///
    /// PUBLIC so the wire-level contract tests (`tests/failure_fee_contract_tests.rs`
    /// and `tests/support`) compute their expectation with the engine's own
    /// rule instead of a copy that can drift from it.
    pub fn failure_fee_for(
        tx: &crate::sharding::Transaction,
        floor_base: u64,
        surcharge: u64,
    ) -> u64 {
        // The intrinsic envelope for EVERY transaction (payload or not) is the
        // guaranteed consumption; cap at the declaration, floor by consensus,
        // add the surcharge.
        Self::TX_INTRINSIC_GAS
            .min(tx.gas_limit)
            .max(floor_base)
            .saturating_add(surcharge)
    }

    /// SEC-07 failure fee, sync core: debit `fee` (base fee + gas consumed up to the
    /// failure point, saturating) for an attributable execution failure and consume
    /// the transaction's nonce.
    ///
    /// Even if a transaction reverts or fails execution (e.g. invalid opcode, assert
    /// fail, out of gas), the sender's balance is debited:
    /// `sender.balance = sender.balance.saturating_sub(fee)` and nonce is
    /// incremented to prevent free-failure DoS.
    ///
    /// THE AFFORDABILITY RULE: the fee is debited only when the sender CAN
    /// cover it. A failure they cannot pay for changes NOTHING - no debit,
    /// no nonce, no state change - because a transaction whose fee they
    /// cannot cover was never going to run, and charging their remaining dust
    /// for it would be a griefing surface, not a safety property (audit
    /// W6.6; the same rule the rest of the engine uses).
    ///
    /// Returns `(debited, Some((balance, nonce)))` with the sender's NEW
    /// state for the caller's trie write, or `(0, None)` when the failure
    /// moves nothing (missing sender, nonce mismatch, or an uncoverable
    /// fee).
    pub(super) fn apply_failure_fee_to_map(
        map: &mut HashMap<[u8; 32], AccountState>,
        tx: &crate::sharding::Transaction,
        fee: u64,
    ) -> (u64, Option<(u64, u64)>) {
        let Some(sender) = map.get_mut(&tx.from) else {
            return (0, None);
        };
        if tx.nonce != sender.nonce {
            return (0, None);
        }
        if fee == 0 || sender.balance < fee {
            // Nothing to charge (no floor, no declared gas) or the sender
            // cannot cover the fee: no pay, no state change.
            return (0, None);
        }
        sender.balance -= fee;
        sender.nonce += 1;
        (fee, Some((sender.balance, sender.nonce)))
    }

    /// Async wrapper around [`Self::apply_failure_fee_to_map`] for execution
    /// sites that hold no accounts lock (every block-path failure site
    /// except the parallel plain fast path, which holds the write guard and
    /// calls the sync core directly).
    pub(super) async fn charge_failure_fee(
        &self,
        tx: &crate::sharding::Transaction,
        fee: u64,
    ) -> (u64, Option<(u64, u64)>) {
        let mut map = self.accounts.write().await;
        Self::apply_failure_fee_to_map(&mut map, tx, fee)
    }

    /// PAYMASTER failure fee, sync core: the fee debits the SPONSOR, the
    /// USER's nonce advances.
    ///
    /// THE SAME CONTRACT as [`failure_fee_state`], with the legs split:
    /// * a replay or a gap (the USER's nonce does not match) is not
    ///   attributable: no pay, no state change at all;
    /// * an attributable failure the sponsor CAN cover: the fee debits the
    ///   sponsor and the USER's nonce is consumed (a sponsored failure is
    ///   not free to replay — the next retry needs a fresh sponsor grant
    ///   over the next nonce);
    /// * an attributable failure the sponsor CANNOT cover (missing sponsor
    ///   account, or a balance below the fee): NOTHING moves — no debit, no
    ///   nonce, no state change (the grief rule, applied to the fee-payer
    ///   leg; the user never pays for a fee they did not agree to fund).
    ///
    /// Returns `(debited, Some((user_balance, user_nonce, sponsor_balance,
    /// sponsor_nonce)))` with both accounts' new state, or `(0, None)` when
    /// the failure moves nothing.
    pub(super) fn apply_sponsored_failure_fee_to_map(
        map: &mut HashMap<[u8; 32], AccountState>,
        tx: &crate::sharding::Transaction,
        sponsor: &[u8; 32],
        fee: u64,
    ) -> (u64, Option<(u64, u64, u64, u64)>) {
        let Some(user) = map.get_mut(&tx.from) else {
            return (0, None);
        };
        if tx.nonce != user.nonce {
            return (0, None);
        }
        let Some(sponsor_acc) = map.get_mut(sponsor) else {
            return (0, None);
        };
        if fee == 0 || sponsor_acc.balance < fee {
            return (0, None);
        }
        sponsor_acc.balance -= fee;
        let sponsor_state = (sponsor_acc.balance, sponsor_acc.nonce);
        let Some(user) = map.get_mut(&tx.from) else {
            return (0, None);
        };
        user.nonce += 1;
        let user_state = (user.balance, user.nonce);
        (
            fee,
            Some((user_state.0, user_state.1, sponsor_state.0, sponsor_state.1)),
        )
    }

    /// Async wrapper around [`Self::apply_sponsored_failure_fee_to_map`].
    pub(super) async fn charge_sponsored_failure_fee(
        &self,
        tx: &crate::sharding::Transaction,
        sponsor: &[u8; 32],
        fee: u64,
    ) -> (u64, Option<(u64, u64, u64, u64)>) {
        let mut map = self.accounts.write().await;
        Self::apply_sponsored_failure_fee_to_map(&mut map, tx, sponsor, fee)
    }

    /// F-01 failure fee for the SINGLE-TRANSACTION path: debit the floor
    /// (capped at the sender's balance), consume the nonce, and write the
    /// sender's new leaf into the trie.
    ///
    /// WHY IT EXISTS: the block path charges the failure fee for every
    /// attributable failure (`fail_with_floor!` in
    /// `apply_block_parallel_fees_with_events`). The single-tx path used to
    /// return the error with NOTHING charged and NOTHING consumed, so the
    /// SAME transaction produced DIFFERENT state depending on which path
    /// applied it - a divergence between the block root and the direct-apply
    /// root (audit W6.6: "a failed transaction pays a fee and increments the
    /// nonce" must hold on BOTH paths).
    pub(super) async fn charge_failure_fee_and_commit(
        &self,
        tx: &crate::sharding::Transaction,
        floor_base: u64,
        surcharge: u64,
    ) {
        // FEE-01: a failure is priced by `failure_fee_for` — the intrinsic
        // envelope cost, floored at the consensus floor, plus the additive
        // surcharge. Never the declared limit (see the fn's docs).
        let fee = Self::failure_fee_for(tx, floor_base, surcharge);
        // PAYMASTER: the failure fee debits the sponsor and consumes the
        // USER's nonce (both leaves are written below). The self-sponsored
        // path (`sponsor == from`) is the plain path and uses the legacy
        // single-account core.
        if let Some(auth) = tx.sponsored_grant() {
            let (_debited, charged_state) = self
                .charge_sponsored_failure_fee(tx, &auth.sponsor, fee)
                .await;
            let Some((user_balance, user_nonce, sponsor_balance, sponsor_nonce)) = charged_state
            else {
                // Not attributable (no sender / nonce mismatch / sponsor
                // cannot cover): no pay, no state change.
                return;
            };
            let (user_data, sponsor_data) = {
                let map = self.accounts.read().await;
                let user_data = match map.get(&tx.from) {
                    Some(acc) => acc.to_trie_bytes(),
                    None => {
                        let mut d = Vec::with_capacity(16);
                        d.extend_from_slice(&user_balance.to_be_bytes());
                        d.extend_from_slice(&user_nonce.to_be_bytes());
                        d
                    }
                };
                let sponsor_data = match map.get(&auth.sponsor) {
                    Some(acc) => acc.to_trie_bytes(),
                    None => {
                        let mut d = Vec::with_capacity(16);
                        d.extend_from_slice(&sponsor_balance.to_be_bytes());
                        d.extend_from_slice(&sponsor_nonce.to_be_bytes());
                        d
                    }
                };
                (user_data, sponsor_data)
            };
            let mut trie = self.state_trie.write().await;
            trie.insert(&tx.from, &user_data);
            trie.insert(&auth.sponsor, &sponsor_data);
            return;
        }
        let (_debited, charged_state) = self.charge_failure_fee(tx, fee).await;
        let Some((balance, nonce)) = charged_state else {
            // Not attributable (no sender / nonce mismatch): no pay, no
            // state change - exactly like the block path.
            return;
        };
        // The trie write: the sender's FINAL leaf. Lock order accounts ->
        // trie, the same order the success path below uses.
        let data = {
            let map = self.accounts.read().await;
            match map.get(&tx.from) {
                Some(acc) => acc.to_trie_bytes(),
                None => {
                    let mut d = Vec::with_capacity(16);
                    d.extend_from_slice(&balance.to_be_bytes());
                    d.extend_from_slice(&nonce.to_be_bytes());
                    d
                }
            }
        };
        let mut trie = self.state_trie.write().await;
        trie.insert(&tx.from, &data);
    }

    /// Commit ONE transaction's native value movement under the accounts write
    /// lock: `tx.amount` + the fee to the recipient, the payload's own
    /// `transfers`, and the payload's `payouts`.
    ///
    /// This is the single commit point shared by `apply_transaction` and the
    /// block paths (`apply_block_parallel_fees`, and therefore
    /// `apply_block_transition` - the shared core of the live consensus path
    /// AND the reorg path), so the same transaction moves exactly the same
    /// value no matter which path applies it: the ordering (sender debit ->
    /// recipient credit -> payload transfers -> payload payouts), the balance
    /// checks and the failure handling are all defined here, once.
    ///
    /// `gas_used` is what execution consumed — the executor's own measurement
    /// (`VmExecutionResult::Success { gas_used }`), or 0 when no VM ran (an
    /// empty-payload transaction, whose cost is then the intrinsic envelope).
    /// The fee actually taken is
    /// `max(min(tx.gas_limit, gas_used + intrinsic), floor_base) + surcharge`
    /// ([`Self::fee_for_gas`]; F-01: never below the consensus floor — see
    /// `consensus_floor_parts`). `tx.gas_limit` is a CAP, not a price, so
    /// unused gas is refunded.
    ///
    /// FEE-01 (closed here): both callers used to pass DIFFERENT numbers —
    /// `apply_transaction` the consumed gas, EVERY block application the
    /// DECLARED `tx.gas_limit` ("admission reserved it, and `fees_collected`
    /// is the sum of declared limits"). That made the consensus path charge
    /// every transaction its full declaration with no refund, and made the
    /// reorg path and the producing node disagree about the fee of the same
    /// block before they were unified. Both paths now pass the measurement
    /// and this function applies the one rule; `fees_collected` is the sum of
    /// the fees actually charged (the proposer credit already uses the
    /// returned `fee`), and `fee_charged` in receipts equals what left the
    /// sender.
    ///
    /// Pinned by `block_apply_parity_tests::block_path_charges_consumed_gas_like_the_single_tx_api`
    /// (both paths charge the consumed gas, not the declaration) and by the
    /// golden FEE-01 cases in `tests/apply_floor_tests.rs`: an empty-payload
    /// transfer declaring 1 000 000 gas debits the 280 000 intrinsic envelope,
    /// one declaring 10 000 is capped at its 10 000, and a payload pays the
    /// VM's own `gas_used`.
    /// What MUST match, and does: a payload can never spend the fee, and a
    /// transaction whose movements are unaffordable is refused on both paths.
    ///
    /// Failure is atomic: if any leg cannot be funded the account map is
    /// restored before `Err` is returned, so a refused transaction moves no
    /// native value at all. The payload's domain effects are rolled back by
    /// the CALLER (see `rollback_payload`, invoked on this `Err` by both
    /// apply paths): a rejected transaction keeps nothing — no bond, no
    /// mint, no half-settled legs (B1, pinned by `tests/hunt_atomicity.rs`).
    ///
    /// Returns every account this transaction touched with its FINAL
    /// (balance, nonce), for the caller to write into the state trie, plus the
    /// fee actually debited (from the sender — or from the SPONSOR on a
    /// sponsored transaction, whose user pays VALUE only)
    /// (`max(min(gas_limit, gas_used + intrinsic), floor_base) + surcharge`,
    /// where `(floor_base, surcharge)` is [`Self::consensus_floor_parts`]; 0 is
    /// never returned here - failure is `Err`, and a refused transaction
    /// moved nothing, so its receipt files `fee_charged: 0`).
    #[allow(clippy::type_complexity)]
    // GATE: commit undo log mirrors account tuple layout; alias would churn callers.
    /// Batched-fee variant of [`Self::commit_native`]: the fee-floor inputs
    /// arrive precomputed instead of being re-read per transaction.
    ///
    /// The block path (`apply_block_parallel_fees`) snapshots the governed
    /// base, the D2 penalty mirror and the vesting floors ONCE per block and
    /// evaluates `floor_parts_for` per transaction up front; those inputs are
    /// passed here, so this variant performs ZERO lock acquisitions for the
    /// fee prefix. Bit-identical to `commit_native` on the deterministic
    /// block path: the penalty mirror is only folded at the end of the block
    /// function, the governed base has no in-block writer, and
    /// `vesting_schedules` has none either (register/unregister are
    /// test-setup only), so the block snapshot equals every per-transaction
    /// live read it replaces. Concurrent external writes racing a block
    /// apply are already non-deterministic today (sibling transactions of
    /// one block would observe different floors); batching only narrows the
    /// window to a single snapshot.
    ///
    /// Callers outside the block path must keep using `commit_native`, which
    /// reads the live inputs and delegates here.
    #[allow(clippy::too_many_arguments, dead_code)]
    // GATE: batching the fee prefix adds parameters; the shared commit core
    // below is untouched (moved verbatim), so semantics are provable by diff.
    pub(super) async fn commit_native_with_floor(
        &self,
        tx: &crate::sharding::Transaction,
        gas_used: u64,
        transfers: &[([u8; 32], u64)],
        payouts: &[([u8; 32], [u8; 32], u64)],
        burns: &[([u8; 32], u64)],
        floor_base: u64,
        surcharge: u64,
        sender_vesting_floor: Option<u64>,
        vesting_floors: &HashMap<[u8; 32], u64>,
    ) -> Result<(Vec<([u8; 32], u64, u64)>, u64), String> {
        self.commit_native_with_floor_at(
            tx,
            gas_used,
            transfers,
            payouts,
            burns,
            floor_base,
            surcharge,
            sender_vesting_floor,
            vesting_floors,
            u64::MAX,
        )
        .await
    }

    /// Height-gated variant of [`Self::commit_native_with_floor`].
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    // GATE: adds chain_height for EXEC_HARDENING_V1 / WASM_XSHARD_PMM_HARDENING gates; undo tuple mirrors account layout.
    pub(super) async fn commit_native_with_floor_at(
        &self,
        tx: &crate::sharding::Transaction,
        gas_used: u64,
        transfers: &[([u8; 32], u64)],
        payouts: &[([u8; 32], [u8; 32], u64)],
        burns: &[([u8; 32], u64)],
        floor_base: u64,
        surcharge: u64,
        sender_vesting_floor: Option<u64>,
        vesting_floors: &HashMap<[u8; 32], u64>,
        chain_height: u64,
    ) -> Result<(Vec<([u8; 32], u64, u64)>, u64), String> {
        let exec_hardening = crate::chain_spec::exec_hardening_v1_active_at(chain_height);
        // The VM ran against the sender's balance without knowing about the fee
        // and about the plain `amount` transfer, so the combined debit has to be
        // re-checked here, under the lock, or a payload could spend the fee twice.
        // `tx.amount` is deliberately already inside `charge`, so it is not added
        // to `vm_out` a second time.
        //
        // `now` is the BLOCK timestamp (never a wall clock): the team-vesting
        // locked floor below is time-based, so every node applying the block
        // must evaluate it at the same instant.
        let vm_out: u64 = transfers
            .iter()
            .fold(0u64, |acc, (_, a)| acc.saturating_add(*a));
        // F-01 consensus floor (defense in depth): never execute below the
        // floor — a transaction declaring less than `floor_base` is charged
        // the floor anyway. Same formula as admission
        // (`Mempool::effective_floor_for_tx`); see `consensus_floor_parts`.
        // Fail-closed: the floor can only raise the fee, never lower it.
        //
        // BATCHED: `floor_base`/`surcharge` arrive precomputed from the
        // block's one-time snapshot (`fee_floors`); see the fn docs for why
        // they equal the live reads they replace.
        //
        // FEE-01: the fee is the BILLED gas (`min(gas_limit, gas_used +
        // intrinsic)`, see `billed_gas`), raised to the consensus floor and
        // plus the additive PQ surcharge — NEVER the declared limit. Both
        // apply paths pass the executor's measurement, so a transaction
        // that declared more than it used is refunded the difference.
        let fee = Self::billed_gas_at(tx, gas_used, exec_hardening).max(floor_base);
        let fee_with_surcharge = fee.saturating_add(surcharge);
        let charge = tx
            .amount
            .checked_add(fee_with_surcharge)
            .ok_or_else(|| "Arithmetic overflow in transaction cost".to_string())?;
        // Everything the payload moves has to be affordable on top of the fee.
        let required = charge
            .checked_add(vm_out)
            .ok_or_else(|| "Arithmetic overflow in transaction cost".to_string())?;
        // The floored fee is what is actually debited, so the reservation
        // check prices it (not the declared limit): when the floor binds,
        // `fee > gas_limit` and the declared-limit check would under-reserve.
        let total_cost = tx
            .amount
            .checked_add(fee)
            .and_then(|t| t.checked_add(surcharge))
            .ok_or_else(|| "Arithmetic overflow in transaction cost".to_string())?;

        // Team-vesting locked floors, looked up in the caller-supplied
        // block snapshot (lock order concern gone: no locks are taken for
        // the fee prefix here). `None` = untracked = no gate. Empty on every
        // live chain today (no vested allocations exist), in which case this
        // is two empty lookups and the gate below is a no-op with zero
        // behavior change. Bit-identical to the live read: `vesting_schedules`
        // has no in-block writer, so the block snapshot taken before the
        // admission pass equals the per-transaction read at every commit.
        let payout_vesting_floors: Vec<([u8; 32], u64)> = {
            let mut floors = Vec::new();
            for (payer, _, _) in payouts {
                if let Some(floor) = vesting_floors.get(payer) {
                    if !floors.iter().any(|(p, _)| p == payer) {
                        floors.push((*payer, *floor));
                    }
                }
            }
            floors
        };

        let mut map = self.accounts.write().await;
        // Every account this transaction mutated, with the full leaf state it
        // had BEFORE the mutation (balance, nonce, PQ scheme + key hash);
        // `None` = the account did not exist. Walked backwards on failure, so
        // a refused transaction is a no-op — including for the post-commit PQ
        // pin below, which runs after this lock is dropped and must roll back
        // through the same log (fork-288000 atomicity: a pin write failure
        // must not leak the debit + nonce advance).
        let mut undo: Vec<(
            [u8; 32],
            Option<(u64, u64, crate::post_quantum::PqScheme, Option<[u8; 32]>)>,
        )> = Vec::new();
        // Accounts that ended up changed, for the caller's trie write.
        let mut touched: Vec<[u8; 32]> = Vec::new();

        // M2: an outbound cross-shard transfer debits the sender on its SOURCE
        // shard and must NOT credit `to` here — the recipient lives on the
        // target shard and is credited only when the committed CrossShardMessage
        // is consumed there. Gated on the sharding flag, so a single-shard
        // engine (every pre-sharding test) keeps the historical behaviour.
        let burn_for_cross_shard = self.cross_shard_enabled() && tx.source_shard != tx.target_shard;

        let outcome = {
            let mut f = || -> Result<(), String> {
                // PAYMASTER v1: an effective sponsor grant splits funding —
                // the USER covers VALUE (`amount` + what the payload moved),
                // the SPONSOR covers FEE. `tx.from` is the user account in
                // both paths, so the sender checks below run on the same
                // account with leg-appropriate thresholds; the sponsor leg
                // is checked against the sponsor account right after, under
                // the same lock (a concurrent commit may have moved either
                // balance since admission/propose).
                let sponsor_addr = tx.sponsored_grant().map(|a| a.sponsor);
                // The user's leg needs `amount` at minimum, `amount + vm_out`
                // once the payload's own movements are included.
                let user_need = tx
                    .amount
                    .checked_add(vm_out)
                    .ok_or_else(|| "Arithmetic overflow in transaction cost".to_string())?;
                let (ubal, unonce, uscheme, uhash) = map
                    .get(&tx.from)
                    .map(|a| (a.balance, a.nonce, a.scheme, a.pubkey_hash))
                    .ok_or_else(|| "Sender account does not exist".to_string())?;
                // Re-check nonce/balance under the lock we just re-acquired.
                if tx.nonce != unonce {
                    return Err("Invalid nonce (state changed during execution)".to_string());
                }
                // The sponsor's pre-mutation leaf for the undo log (its nonce
                // never advances: only the user's does).
                let sponsor_pre: Option<(
                    [u8; 32],
                    (u64, u64, crate::post_quantum::PqScheme, Option<[u8; 32]>),
                )> = if let Some(sponsor) = sponsor_addr {
                    if ubal < tx.amount {
                        return Err(
                            "Insufficient balance (state changed during execution)".to_string()
                        );
                    }
                    if ubal < user_need {
                        return Err(format!(
                            "Insufficient balance for payload: has {ubal}, needs {user_need}"
                        ));
                    }
                    let leaf = map
                        .get(&sponsor)
                        .map(|a| (a.balance, a.nonce, a.scheme, a.pubkey_hash))
                        .ok_or_else(|| "Sponsor account does not exist".to_string())?;
                    if leaf.0 < fee_with_surcharge {
                        return Err(
                                "Sponsor has insufficient balance for fee (state changed during execution)".to_string(),
                            );
                    }
                    Some((sponsor, leaf))
                } else {
                    if ubal < total_cost {
                        return Err(
                            "Insufficient balance (state changed during execution)".to_string()
                        );
                    }
                    if ubal < required {
                        return Err(format!(
                            "Insufficient balance for payload: has {ubal}, needs {required}"
                        ));
                    }
                    None
                };

                if tx.is_pq_activation() {
                    let env = tx
                        .pq_envelope_at_height(chain_height)
                        .ok_or_else(|| "Missing PQ activation envelope".to_string())?;
                    if env.is_implicit {
                        return Err("PQ activation envelope must not be implicit".to_string());
                    }
                    let pk = env.pubkey.as_deref().ok_or_else(|| {
                        "Missing public key in PQ activation envelope".to_string()
                    })?;
                    let salt = env.salt;
                    // Fork-288000 atomicity: every refusal `pin_pubkey` can
                    // produce must ALSO be produced here, BEFORE any mutation
                    // lands. The post-commit pin runs after this lock is
                    // dropped and can no longer refuse cheaply (it would need
                    // the rollback below); anything it checks deterministically
                    // belongs here instead. In particular a DISABLED scheme
                    // (today ML-DSA-44) must fail before the debit, exactly
                    // like the length / derivation / conflict checks.
                    if env.scheme.is_disabled() {
                        return Err(format!(
                            "{} is DISABLED: refusing PQ activation for address {}",
                            env.scheme.name(),
                            hex::encode(tx.from)
                        ));
                    }
                    if pk.len() != env.scheme.pubkey_size() {
                        return Err(format!(
                            "Invalid public key length for {}: expected {}, got {}",
                            env.scheme.name(),
                            env.scheme.pubkey_size(),
                            pk.len()
                        ));
                    }
                    let derived = crate::post_quantum::derive_pq_address(env.scheme, pk, &salt);
                    if derived != tx.from {
                        return Err(format!(
                            "Address mismatch: derived {} does not match address {}",
                            hex::encode(derived),
                            hex::encode(tx.from)
                        ));
                    }
                    let pk_hash = *blake3::hash(pk).as_bytes();
                    if let Some(existing_hash) = uhash {
                        if existing_hash != pk_hash || uscheme != env.scheme {
                            return Err(format!(
                                "Conflicting public key registration for address {}",
                                hex::encode(tx.from)
                            ));
                        }
                    }
                }

                // Deduct the user's leg and increment the USER's nonce. On the
                // sponsored path the fee leg debits the sponsor below; the
                // user's balance is NEVER touched for the fee (not base, not
                // gas, not failure-fee). Charge the fee (capped at the
                // declared gas_limit) plus the transfer amount, plus
                // everything the payload moved out — on the legacy path, all
                // from the sender.
                undo.push((tx.from, Some((ubal, unonce, uscheme, uhash))));
                touched.push(tx.from);
                {
                    let user = map
                        .get_mut(&tx.from)
                        .ok_or_else(|| "Sender account does not exist".to_string())?;
                    user.balance = ubal.saturating_sub(if sponsor_addr.is_some() {
                        user_need
                    } else {
                        required
                    });
                    user.nonce += 1;
                }
                // The sponsor's leg: FEE ONLY. Its nonce never advances.
                if let Some((sponsor, (sbal, snonce, sscheme, shash))) = sponsor_pre {
                    undo.push((sponsor, Some((sbal, snonce, sscheme, shash))));
                    touched.push(sponsor);
                    let sp = map
                        .get_mut(&sponsor)
                        .ok_or_else(|| "Sponsor account does not exist".to_string())?;
                    sp.balance = sbal.saturating_sub(fee_with_surcharge);
                }

                // Team-vesting claim gate (audit: TeamVestingSchedule was
                // CLI-only, no on-chain lock). A vesting-tracked sender may
                // not be left below its locked floor: spending above the
                // unlocked amount FAILS closed here. This covers amount +
                // fee + every payload/settlement debit at once, because
                // the post-settlement user balance is compared and
                // `required`/`user_need` is the remaining debit — cumulative
                // spends are bounded with no per-transfer claimed
                // bookkeeping. Refusal rolls back via the undo log (caller
                // also rolls back payload domains).
                if let Some(locked) = sender_vesting_floor {
                    let post_user_balance = map.get(&tx.from).map(|a| a.balance).unwrap_or(0);
                    if post_user_balance < locked {
                        let msg = format!(
                            "team vesting lock: sender {} balance {} would fall below locked {locked} (spending above the unlocked amount is refused)",
                            hex::encode(tx.from),
                            post_user_balance,
                        );
                        tracing::warn!("VESTING-LOCK REFUSED {msg}");
                        return Err(msg);
                    }
                }

                // Credit recipient. For an outbound cross-shard transfer this is
                // deliberately skipped: the amount leaves this shard and is
                // minted to the recipient by the target shard's consumption of
                // the committed message. Skipping it keeps value conserved
                // ACROSS shards once the target applies the message.
                if !burn_for_cross_shard {
                    undo.push((
                        tx.to,
                        map.get(&tx.to)
                            .map(|a| (a.balance, a.nonce, a.scheme, a.pubkey_hash)),
                    ));
                    touched.push(tx.to);
                    if let Some(recipient) = map.get_mut(&tx.to) {
                        recipient.balance =
                            recipient.balance.checked_add(tx.amount).ok_or_else(|| {
                                "Arithmetic overflow on recipient balance".to_string()
                            })?;
                    } else {
                        map.insert(tx.to, AccountState::new(tx.to, tx.amount));
                    }
                }

                // The payload's own value movements (this is what `OpCode::Transfer`
                // and the SysCallStake bond to the staking pool resolve to).
                for (to, amount) in transfers {
                    undo.push((
                        *to,
                        map.get(to)
                            .map(|a| (a.balance, a.nonce, a.scheme, a.pubkey_hash)),
                    ));
                    touched.push(*to);
                    if let Some(acc) = map.get_mut(to) {
                        acc.balance = acc.balance.checked_add(*amount).ok_or_else(|| {
                            "Arithmetic overflow crediting payload transfer".to_string()
                        })?;
                    } else {
                        map.insert(*to, AccountState::new(*to, *amount));
                    }
                }
                // Payouts are funded by a third party (the staking pool), so the
                // payer's balance is checked and debited here rather than assumed.
                for (payer, beneficiary, amount) in payouts {
                    undo.push((
                        *payer,
                        map.get(payer)
                            .map(|a| (a.balance, a.nonce, a.scheme, a.pubkey_hash)),
                    ));
                    let acc = map
                        .get_mut(payer)
                        .ok_or_else(|| "Payout payer account does not exist".to_string())?;
                    if acc.balance < *amount {
                        return Err(format!(
                            "Payout payer {} has {} but must pay {amount}",
                            hex::encode(&payer[..6]),
                            acc.balance
                        ));
                    }
                    acc.balance -= *amount;
                    touched.push(*payer);
                    // Same vesting gate for a tracked payout payer: pool
                    // accounts are never tracked, so this only fires for a
                    // directly-constructed payout naming a vested account.
                    if let Some((_, locked)) =
                        payout_vesting_floors.iter().find(|(p, _)| p == payer)
                    {
                        if acc.balance < *locked {
                            let msg = format!(
                                "team vesting lock: payout payer {} balance {} would fall below locked {locked}",
                                hex::encode(payer),
                                acc.balance,
                            );
                            tracing::warn!("VESTING-LOCK REFUSED {msg}");
                            return Err(msg);
                        }
                    }

                    undo.push((
                        *beneficiary,
                        map.get(beneficiary)
                            .map(|a| (a.balance, a.nonce, a.scheme, a.pubkey_hash)),
                    ));
                    touched.push(*beneficiary);
                    if let Some(b) = map.get_mut(beneficiary) {
                        b.balance = b
                            .balance
                            .checked_add(*amount)
                            .ok_or_else(|| "Arithmetic overflow crediting payout".to_string())?;
                    } else {
                        map.insert(*beneficiary, AccountState::new(*beneficiary, *amount));
                    }
                }
                // BURNS: coins that leave an account and are credited to
                // NOBODY - they are destroyed. Today the only producer is the
                // post-quantum equivocation slash, whose burn comes out of the
                // STAKING_POOL (the pool holds the bonded principal, so the
                // slashed stake leaves the chain instead of silently
                // inflating the pool against the ledger).
                //
                // FAIL-CLOSED: a burn the payer cannot cover REFUSES the
                // transaction (the undo log below then restores every
                // account, and the caller restores the ledger-side slash), so
                // the pool and the ledger can never drift apart by the burnt
                // amount.
                for (from, amount) in burns {
                    if *amount == 0 {
                        continue;
                    }
                    undo.push((
                        *from,
                        map.get(from)
                            .map(|a| (a.balance, a.nonce, a.scheme, a.pubkey_hash)),
                    ));
                    let acc = map
                        .get_mut(from)
                        .ok_or_else(|| "Burn account does not exist".to_string())?;
                    if acc.balance < *amount {
                        return Err(format!(
                            "Burn account {} has {} but must burn {amount}",
                            hex::encode(&from[..6]),
                            acc.balance
                        ));
                    }
                    acc.balance -= *amount;
                    touched.push(*from);
                }
                Ok(())
            };
            f()
        };

        if let Err(e) = outcome {
            // Undo newest-first so an account touched twice returns to its
            // original value, not to the intermediate one. Restores the full
            // leaf (balance, nonce, PQ scheme + key hash), not just money.
            for (addr, prev) in undo.iter().rev() {
                match prev {
                    Some((balance, nonce, scheme, pubkey_hash)) => {
                        if let Some(acc) = map.get_mut(addr) {
                            acc.balance = *balance;
                            acc.nonce = *nonce;
                            acc.scheme = *scheme;
                            acc.pubkey_hash = *pubkey_hash;
                        }
                    }
                    None => {
                        map.remove(addr);
                    }
                }
            }
            return Err(e);
        }

        // Final values, read under the same lock the mutations happened under.
        let mut out = Vec::with_capacity(touched.len());
        for addr in touched {
            if let Some(acc) = map.get(&addr) {
                out.push((addr, acc.balance, acc.nonce));
            }
        }
        drop(map);

        if tx.is_pq_activation() {
            if let Some(env) = tx.pq_envelope_at_height(chain_height) {
                if !env.is_implicit {
                    if let Some(ref pk) = env.pubkey {
                        let salt = env.salt;
                        if let Err(e) = self.pin_pubkey(tx.from, env.scheme, pk, &salt).await {
                            // Fork-288000 atomicity: the mutations above
                            // already landed under the dropped lock, and the
                            // only remaining failure mode here is node-local
                            // (the `pq_keys` disk write — every deterministic
                            // refusal already fired in the pre-check above).
                            // Roll the full leaf back through the undo log so
                            // a refused commit moves nothing, and say so
                            // LOUDLY: a silent partial commit is exactly how
                            // one node finalizes `(failed, fee 0)` + mutated
                            // state while its peers finalize success.
                            tracing::error!(
                                tx = %hex::encode(tx.compute_tx_hash()),
                                from = %hex::encode(tx.from),
                                "commit_native: post-commit PQ pin failed ({e}); rolling back the native mutation"
                            );
                            let mut map = self.accounts.write().await;
                            for (addr, prev) in undo.iter().rev() {
                                match prev {
                                    Some((balance, nonce, scheme, pubkey_hash)) => {
                                        if let Some(acc) = map.get_mut(addr) {
                                            acc.balance = *balance;
                                            acc.nonce = *nonce;
                                            acc.scheme = *scheme;
                                            acc.pubkey_hash = *pubkey_hash;
                                        }
                                    }
                                    None => {
                                        map.remove(addr);
                                    }
                                }
                            }
                            return Err(e);
                        }
                    }
                }
            }
        }

        Ok((out, fee_with_surcharge))
    }

    /// Shared native commit point (see [`Self::commit_native_with_floor`]
    /// for the full contract): reads the fee-floor inputs live and delegates
    /// to the batched variant. This is the single-transaction path
    /// (`apply_transaction`) and every non-block caller stays on these live
    /// reads — only the block path passes a block snapshot.
    #[allow(dead_code)] // GATE: kept for legacy callers alongside commit_native_at
    pub(super) async fn commit_native(
        &self,
        tx: &crate::sharding::Transaction,
        gas_used: u64,
        transfers: &[([u8; 32], u64)],
        payouts: &[([u8; 32], [u8; 32], u64)],
        burns: &[([u8; 32], u64)],
        now: u64,
    ) -> Result<(Vec<([u8; 32], u64, u64)>, u64), String> {
        self.commit_native_at(tx, gas_used, transfers, payouts, burns, now, u64::MAX)
            .await
    }

    /// Height-gated variant of [`Self::commit_native`].
    #[allow(clippy::too_many_arguments)] // GATE: mirrors commit_native with explicit chain_height
    pub(super) async fn commit_native_at(
        &self,
        tx: &crate::sharding::Transaction,
        gas_used: u64,
        transfers: &[([u8; 32], u64)],
        payouts: &[([u8; 32], [u8; 32], u64)],
        burns: &[([u8; 32], u64)],
        now: u64,
        chain_height: u64,
    ) -> Result<(Vec<([u8; 32], u64, u64)>, u64), String> {
        // Live fee-floor inputs: the governed base + this engine's D2
        // penalty mirror + the PQ surcharge predicate.
        let (floor_base, surcharge) = self.consensus_floor_parts(tx).await;
        // Live vesting floors at the block timestamp `now` (lock order:
        // staking -> accounts, same as before).
        let (sender_vesting_floor, vesting_floors): (Option<u64>, HashMap<[u8; 32], u64>) = {
            let ledger = self.staking.read().await;
            let sender_floor = ledger
                .vesting_schedules
                .get(&tx.from)
                .map(|s| s.locked_amount(now));
            let mut floors = HashMap::new();
            for (payer, _, _) in payouts {
                if let Some(s) = ledger.vesting_schedules.get(payer) {
                    floors.entry(*payer).or_insert_with(|| s.locked_amount(now));
                }
            }
            (sender_floor, floors)
        };
        self.commit_native_with_floor_at(
            tx,
            gas_used,
            transfers,
            payouts,
            burns,
            floor_base,
            surcharge,
            sender_vesting_floor,
            &vesting_floors,
            chain_height,
        )
        .await
    }

    /// The complete state transition of ONE block: its transactions, the fees
    /// they paid to the proposer, the block reward, matured unbondings and the
    /// downtime slash the block's own decision proof calls for.
    ///
    /// This is THE shared core. The live consensus path
    /// (`ValidatorRuntime::apply_block_fees_rewards`, reached from
    /// `try_finalize`, `apply_and_advance` and `replay_historical_block`) and
    /// the reorg path (`ChainState::apply_block`, reached from
    /// `ChainState::reorg`) both call this function and nothing else, so a
    /// reorg re-applies a block byte-identically to the node that finalized it
    /// instead of silently forking a second chain under the same height.
    ///
    /// Everything it reads is either block content (`transactions`,
    /// `timestamp`, `proposer`, `height`, `precommit_qc`) or COMMITTED state
    /// read from this engine at the block's own pre-state. Nothing is read
    /// from the caller's local consensus state (`HeightConsensus`) or from a
    /// caller-held governance copy, which is why the two paths cannot
    /// disagree about what a block does.
    ///
    /// BLOCK REWARD (PENTEST2 R1/DET-01): the reward is resolved HERE, from
    /// the governance state this block is applied against (the PRE-block
    /// state, before step 5e executes this block's actions), exactly like the
    /// downtime-attribution set above. The `default_block_reward` argument is
    /// a STATIC node configuration value used only while governance has never
    /// set `applied.block_reward`; it can never be a per-tick governance copy.
    /// Resolving the GOVERNED value in the caller made a `SetBlockReward`
    /// executed at 5e visible to the live path (which refreshes once per
    /// tick) but not to a catch-up/walk/restart path, so the same block paid
    /// different rewards and committed different state roots.
    ///
    /// Order is load-bearing and is exactly the order the live path has always
    /// run in: txs -> actor mailbox -> fees -> reward -> unbonding -> downtime
    /// slash. (The mailbox pass sits between the transactions that QUEUE
    /// messages and the fee credit, so a block delivers everything its own
    /// transactions enqueued - and nothing that a later step enqueues, which
    /// nothing after it does.)
    ///
    /// F5 ECONOMIC-ORDER AUDIT (slash-after-reward/unbonding): the order is
    /// CONSENSUS-CRITICAL (every path runs this one function, so all nodes
    /// agree bit-for-bit) and the "slash last" shape is a DETERMINISTIC
    /// economic edge, not a fork primitive. Reordering to slash-first was
    /// considered and REJECTED, for three pool-separation reasons that make
    /// the reorder a consensus-breaking no-op:
    /// * fees credit the proposer's NATIVE balance; the downtime slash burns
    ///   BONDED stake (`ValidatorStake::total = self_bond + delegated`) out
    ///   of STAKING_POOL. Different pools — moving the slash earlier changes
    ///   neither the fee credit nor the burn amount.
    /// * the block reward mints into `pending_rewards` (+ REWARDS_POOL
    ///   backing), which `slash()` never touches (no `pending_rewards`,
    ///   `withdrawable` or `unbonding` leg). A slashed proposer keeps the
    ///   just-credited reward under EITHER order; making downtime
    ///   net-unprofitable needs a staking-domain rule (slash pending
    ///   rewards), not a reorder here.
    /// * `unbond()` removes stake from the slashable total IMMEDIATELY (at
    ///   tx-apply time, step 1), not at maturation: entries maturing in step
    ///   4 left `self_bond` when their `unbond` applied (possibly many blocks
    ///   earlier). Maturation vs slash order is therefore a PROVEN no-op —
    ///   the "mature-then-escape" shape in the audit does not exist; the real
    ///   escape is a same-block `unbond` tx (step 1 runs before step 5), which
    ///   is equally deterministic under both orders and likewise needs the
    ///   staking-domain fix (slash unbonding/withdrawable legs).
    ///   Single-height misses never slash anyway (`DOWNTIME_MISS_THRESHOLD`
    ///   with cooldown in `note_missed_heights`), so the profitable-downtime
    ///   window needs a sustained outage PLUS the staking fix above. Pinned by
    ///   the F5 economic test (proposer-in-miss-set net outcome + matured-
    ///   unbonding-intact assertions).
    ///
    /// Node-local side effects are deliberately OUTSIDE this function, because
    /// they cannot move the state root and each caller mirrors them itself:
    /// mempool pruning, receipts / `applied_statuses` / `applied_txs`
    /// bookkeeping, the `finalized` list, `HeightConsensus` advance and the
    /// validator-set refresh (a read-only re-derivation from the staking
    /// ledger this commits, so both callers derive the same set from the same
    /// bytes).
    pub async fn apply_block_transition(
        &self,
        block: &crate::sharding::Block,
        default_block_reward: u64,
    ) -> BlockTransitionOutcome {
        // R1/DET-01: resolve the block reward from the COMMITTED governance
        // pre-state, inside the one function every apply path runs. The
        // caller-supplied value is only the static fallback for a chain whose
        // governance has never executed `SetBlockReward`; the governed value
        // itself is never taken from a caller copy.
        let block_reward = {
            let gov = self.governance_read().await;
            gov.applied.block_reward.unwrap_or(default_block_reward)
        };
        // Downtime-attribution oracle (W10.5 activation boundary): the
        // validator set the `last_qc` downtime evidence (height H-1) is
        // verified and attributed against is snapshotted HERE, from the
        // PRE-transition ledger — i.e. the ledger as of the end of H-1,
        // before this block's own transactions (bond / unbond / slash),
        // rewards and unbonding maturity mutate it.
        //
        // The evidence was formed UNDER that set, so it must be judged by
        // it: judging it by the post-transition set accepts quorums H-1
        // never had (a bond in this block raises the quorum out from under
        // a genuine QC, skipping the slash) and attributes misses to the
        // wrong membership. The snapshot is a pure function of the engine
        // pre-state, so every path that applies this block — local
        // finalize, adopt, walk, replay, reorg re-apply — derives the SAME
        // set and converges (unlike a runtime-history oracle, which differs
        // between nodes with different history depths).
        //
        // Residual, stated plainly: when the PARENT block itself rotated
        // the set, the pre-state already reflects that rotation while the
        // evidence was formed under the pre-rotation set. Attribution is
        // then uniform-but-lenient (the QC may fail the newer quorum and
        // the slash is skipped on every node identically) — never a fork.
        // The proposal gate (`check_last_qc_evidence`) uses the exact
        // at-height set and may therefore admit evidence this step skips;
        // that direction is fail-closed (forgiven downtime, never a
        // conflicting one).
        let pre_transition_set = self.staking.read().await.to_validator_set();
        // 0. Cross-shard INBOUND credits, committed by this block's
        //    `cross_shard_out` consumption records. This is a no-op unless the
        //    sharding gate is on (multi-shard process) AND the block actually
        //    carries inbound records, so every pre-sharding block is byte-for-
        //    byte unchanged. Outbound records are not applied here: the debit
        //    happens in step 1 via `commit_native`'s cross-shard branch.
        let _consumed = self.apply_cross_shard_consumptions(block).await;

        // 1. The transactions themselves (batched signature verify, admission,
        //    payload execution, native commit, trie write). The COMMITTED
        //    block height goes down as the chain-binding gate's clock (A14
        //    phase 3); see `apply_block_parallel_fees_with_events_at_height`.
        let (applied, failed, fees, status, tx_fees, events) = self
            .apply_block_parallel_fees_with_events_at_height(
                &block.transactions,
                block.timestamp,
                block.height,
            )
            .await;

        // 1a-TER (PENTEST2 H1/M1/S6): feed the deterministic routing /
        // settlement indexes from COMMITTED, APPLIED transactions and consume
        // the EVM-intent nullifier of every carrier that actually settled.
        // Both operations are pure functions of the block bytes + `status`;
        // they do not move the state root and every apply path (live, adopt,
        // walk, replay, reorg) runs them, so a restart/catch-up rebuilds the
        // same maps.
        //
        // A duplicate carrier with the same signed intent inside one block is
        // already refused by the sender nonce (the intent nonce must equal the
        // Stell nonce, which the first settlement consumes), so the nullifier
        // written here also protects the block boundary onward; the
        // pre-execution nullifier check covers every later block and every
        // hand-built replay.
        let exec_hardening = crate::chain_spec::exec_hardening_v1_active_at(block.height);
        let evm_bindings_active = super::evm_bindings_state_active_at(block.height);
        for (i, tx) in block.transactions.iter().enumerate() {
            if !status.get(i).copied().unwrap_or(false) {
                continue;
            }
            if let Some(digest) = crate::evm_adapter::carrier_intent_digest(tx) {
                self.mark_evm_intent_settled(&digest).await;
            }
            if evm_bindings_active {
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
            self.observe_committed_evm_tx(tx);
        }

        // 1a-BIS (pentest F6): record every validator that FULLY exited the
        // set in THIS block, with the power it held at the block's start.
        // The next block attributes this block's `last_qc` against the set
        // in force HERE, so a validator that unbonds in the evidence block
        // can no longer erase its own miss (the pre-state of H is already
        // the END of H-1 and would otherwise drop it).
        //
        // Pure function of (pre-transition set, post-transaction set): every
        // node applying the same block records the same ids and powers. A
        // rotated-away key is skipped (its record no longer exists), and a
        // record that is still bonded is not an exit. The ledger map is
        // bounded to the current + previous height by the recorder.
        let (exits, need_prune) = {
            // A validator can only fall out of the set through a full
            // `SysCallUnbond` (rotation moves the record, it does not create
            // an exit candidate). Gate the set diff on that opcode so an
            // ordinary block pays one O(1) payload scan, not a re-derivation.
            let has_unbond = block.transactions.iter().any(|tx| {
                tx.payload
                    .iter()
                    .any(|op| matches!(op, crate::svm::OpCode::SysCallUnbond { .. }))
            });
            let l = self.staking.read().await;
            let need_prune = l.full_exits_need_prune(block.height);
            if !has_unbond {
                (Vec::new(), need_prune)
            } else {
                let post_tx_set = l.to_validator_set();
                let min_bond = l
                    .min_validator_bond
                    .unwrap_or(crate::staking::MIN_VALIDATOR_BOND);
                let exits: Vec<([u8; 32], u64)> = pre_transition_set
                    .validators
                    .keys()
                    .filter(|v| !post_tx_set.validators.contains_key(*v))
                    .filter(|v| {
                        l.validators
                            .get(*v)
                            .map(|s| s.self_bond < min_bond)
                            .unwrap_or(false)
                    })
                    .map(|v| (*v, pre_transition_set.power_of(v)))
                    .collect();
                (exits, need_prune)
            }
        };
        if !exits.is_empty() || need_prune {
            self.staking_write()
                .await
                .record_full_exits_at(&exits, block.height);
        }

        // 1b-BIS (pentest F7): block-carried `SysCallUnjail`. The VM arm is a
        // validated carrier (sender/jail/bond); the release-height gate needs
        // the block height, which only this path knows. Runs after the
        // transactions so a `SysCallStake` top-up in the SAME payload is
        // already in the ledger, and before the downtime step so a validator
        // unjailed here is subject to this block's evidence like any other
        // member. Deterministic: pure function of block bytes + pre-state.
        let _unjailed = self.apply_staking_unjail_ops(block, &status).await;

        // 1a. §9 2PC, SOURCE side: the PREPARED state of every transfer this
        //     block ESCROWED. It runs AFTER the transactions, because the
        //     record means "the value is escrowed here" - which is only true
        //     for a transaction that really applied. A record written for a
        //     refused transaction would let the peer credit a value that was
        //     never escrowed (a mint).
        let _xpc_prepared = self.apply_xpc_source_prepares(block, &status).await;

        // 1b. §1 ACTOR MAILBOX: deliver every message this block's
        //     transactions queued (plus anything an earlier block left, which
        //     under Phase 1's drain-to-empty policy is nothing). ONCE per
        //     block, in one accounts write lock, in deterministic address
        //     order - the pass is what turns queued sends into credits,
        //     bounces and nested sends.
        let _actor_delivered = self.apply_actor_messages_at(block).await;

        // 2. Pay the collected fees to the proposer. The fees were already
        //    debited from senders in step 1, so this is a transfer, not a mint
        //    — and it deliberately uses the UNCAPPED credit: a block whose
        //    rewards filled the global supply cap must still be able to pay
        //    its proposer fees collected from existing balances.
        if fees > 0 {
            let _ = self.credit_native_transfer(&block.proposer, fees).await;
        }

        // 3. Block reward to the proposer out of the staking emission (paid as
        //    pending rewards, claimed by a later `SysCallClaimRewards`).
        //
        //    E2: the mint is explicit and capped. `distribute_reward` funds the
        //    ledger's rewards pool (fail-closed over REWARDS_EMISSION_CAP);
        //    the native leg mints the SAME amount into REWARDS_POOL, so every
        //    later claim is backed 1:1 and bonded principal in STAKING_POOL is
        //    never touched.
        //
        //    GLOBAL CAP FIRST (order is load-bearing): the engine reserves the
        //    mint headroom BEFORE the ledger leg. When the 1B supply cap is
        //    reached the block pays NO reward and the staking ledger is left
        //    byte-identical — critically, no `pending_rewards` was split, so
        //    there is nothing to unwind. Reversed (distribute-then-mint), a
        //    cap refusal would leave the validator's pending counter credited
        //    against a pool that holds no coins.
        if block_reward > 0 && self.reserve_mint(block_reward).await.is_ok() {
            let distributed = self
                .staking_write()
                .await
                .distribute_reward(block.proposer, block_reward)
                .is_ok();
            if !distributed {
                // Ledger refused (its own 350M cap, jailed or unknown
                // proposer): the coin was never created, give the global
                // headroom back.
                self.release_mint_nano(block_reward);
            } else if self
                .credit_reserved_native(&crate::staking::REWARDS_POOL, block_reward)
                .await
                .is_err()
            {
                // Defensive only: while the reservation above holds and the
                // REWARDS_POOL balance is supply-bounded (it is credited 1:1
                // by this same leg), the pool credit cannot overflow. Keep
                // the two legs 1:1 if it ever does.
                let mut l = self.staking_write().await;
                l.rewards_pool = l.rewards_pool.saturating_sub(block_reward);
                l.rewards_minted = l.rewards_minted.saturating_sub(block_reward);
            }
        }

        // 4. Mature unbondings. Deterministic: the clock is the block's own
        //    timestamp, never local wall time. Fail-closed (audit P2): an
        //    overflow refusal is logged LOUD and the entries stay pending
        //    (retried next block) — maturation never destroys dust, and the
        //    infallible apply path never halts the chain over it.
        if let Err(e) = self
            .staking_write()
            .await
            .process_unbonding(block.timestamp)
        {
            tracing::error!("unbonding maturation refused (funds stay pending): {e}");
        }

        // 5. Downtime slash, from the CANONICAL certificate the block carries.
        //
        // W10.5 canonical evidence: the evidence is `block.last_qc` — the
        // precommit QC that decided height-1, embedded once by this block's
        // proposer and covered by the block hash — NEVER the locally-assembled
        // `block.precommit_qc`. Two nodes that finalize the same block with
        // different quorate QC subsets (e.g. {A,C} vs {A,B,C}, both passing
        // the same quorum) used to bump different `missed` counters in the
        // committed staking ledger and fork the state root permanently (live
        // 2026-10-23 #292785/#292786). With proposer-chosen evidence every
        // node that applies this block attributes the SAME signers and
        // converges.
        //
        // The evidence is block content, so every node that applies this block
        // — locally finalized, adopted, walked, replayed or re-applied after a
        // reorg — burns the same amount out of the same pool. `None` (genesis
        // child, or a block proposed by a node that knew no parent decision)
        // skips attribution for that height — deterministic, since `None` is
        // canonical bytes.
        let evidence_height = block.height.saturating_sub(1);
        // F6: judge the evidence against the set IN FORCE at `evidence_height`
        // — the pre-transition set (which is the ledger as of the END of
        // H-1) PLUS every validator recorded as having fully exited DURING
        // H-1, restored with the power it held at H-1's start. Without the
        // second half a full `SysCallUnbond` in the evidence block removes
        // the offender from the set and its miss is never attributed.
        // Adding the pre-exit power (not the post-exit 0/delegated total)
        // keeps the quorum denominator identical to the one that formed the
        // certificate, so a genuine H-1 QC still verifies.
        let attribution_set = {
            let mut s = pre_transition_set.clone();
            let l = self.staking.read().await;
            for (validator, power) in l.full_exits_at(evidence_height) {
                s.add(validator, power);
            }
            s
        };
        // ROTATION ALIASES (SLASH-01): a key rotation applied by THIS block
        // removes the OLD id from `validators` before the downtime step below.
        // The evidence for H-1 names the OLD id, so without the alias the
        // ledger lookup misses and the miss is forgiven — rotating every
        // height evades downtime slashing. Derived from the block's own
        // applied rotation opcodes (pure block bytes + `status`), so every
        // node resolves the same alias. Empty on the common block.
        let rotation_aliases: HashMap<[u8; 32], [u8; 32]> = {
            let mut aliases = HashMap::new();
            for (i, tx) in block.transactions.iter().enumerate() {
                if !status.get(i).copied().unwrap_or(false) {
                    continue;
                }
                for op in &tx.payload {
                    if exec_hardening && matches!(op, crate::svm::OpCode::Halt) {
                        break;
                    }
                    if let crate::svm::OpCode::SysCallRotateValidatorKey {
                        old_validator,
                        new_validator,
                    } = op
                    {
                        aliases.insert(*old_validator, *new_validator);
                    }
                }
            }
            aliases
        };
        let slashed = self
            .apply_downtime_slash_with_set_alias(
                evidence_height,
                block.last_qc.as_ref(),
                &attribution_set,
                &rotation_aliases,
            )
            .await;

        // 5b. Equivocation slash, from block-carried evidence. The carrier is
        //     the block BODY: `OpCode::SysCallReportEquivocation` payloads in
        //     this block's own transactions, each envelope holding BOTH
        //     conflicting votes fully, so every node re-verifies from block
        //     bytes alone (no gossip, no external data). Same determinism
        //     contract as step 5: locally finalized, adopted, walked,
        //     replayed or re-applied-after-reorg all burn identically, or
        //     nothing at all when the block carries no (valid) evidence.
        let eq_slashed = self.apply_equivocation_slash(block).await;

        // 5c. Block-carried governance ops, from block-carried opcodes. Same
        //     verdict contract as 5b: the scan re-derives every propose/vote
        //     from block bytes alone (gate, height pin, duplicate/window/
        //     one-vote rules against committed state), in block order, so
        //     every route that applies this block opens the same proposals
        //     and records the same tallies. Pre-activation (or a block with
        //     no gov ops) this is a proven no-op. Refused ops never fail the
        //     block — the reporter already paid gas in step 1.
        let _gov_ops = self.apply_gov_ops(block, &status).await;

        // 5d. CN-VRF v3 state transition (commit admission, proposer slot reveal,
        //     leaky-bucket abort slash, epoch MinRoot VDF beacon, key-rotation
        //     migration, and epoch expiry). Strictly gated by
        //     `cnvrf_v3_is_active_at(block.height)` so pre-activation blocks
        //     remain 100% untouched.
        let cnvrf_slashed = if self.cnvrf_v3_is_active_at(block.height) {
            self.apply_cnvrf_v3(block, &status).await
        } else {
            0
        };

        // 5e. DETERMINISTIC GOVERNANCE EXECUTION: finalize every proposal
        //     whose voting window closed and execute every passed, matured
        //     `GovAction` at this exact height. This is the piece that used to
        //     be missing (actions were only ever executed by a node-local RPC
        //     call), so a passed parameter change now executes on EVERY node
        //     applying the same blocks — same height, same value, same
        //     committed state root. Gated by
        //     `GOV_OPS_ACTIVATION_HEIGHT` (0, active from genesis); a block
        //     with nothing due takes no write lock and leaves the root
        //     byte-identical.
        let _gov_exec = self.apply_governance_transition(block).await;

        BlockTransitionOutcome {
            applied,
            failed,
            fees_collected: fees,
            status,
            tx_fees,
            slashed: slashed
                .saturating_add(eq_slashed)
                .saturating_add(cnvrf_slashed),
            events,
        }
    }

    /// Deterministic CN-VRF v3 block transition (active only when
    /// `cnvrf_v3_is_active_at(block.height)` is true).
    async fn apply_cnvrf_v3(&self, block: &crate::sharding::Block, status: &[bool]) -> u64 {
        use crate::cn_vrf::{
            epoch_of_height, CommitCarrierV3, SlotRevealOutcome, CNVRF_PK_LEN, EPOCH_LEN,
            V3_COMMIT_LOOKAHEAD_BLOCKS,
        };

        let current_epoch = epoch_of_height(block.height);
        let mut pending_staking_burn = 0u64;
        let mut pending_rewards_burn = 0u64;

        let mut v3_state = self.cnvrf_v3.write().await;
        let mut abort_state = self.cnvrf_abort.write().await;
        let mut epoch_beacons = self.epoch_vdf_beacons.write().await;
        let mut freeze_inputs = self.cnvrf_freeze_inputs.write().await;

        let v3_before = v3_state.clone();
        let abort_before = abort_state.clone();
        let beacons_before = epoch_beacons.clone();

        // 1. Migrate CN-VRF v3 commitments and abort-slash debt for any applied
        //    `SysCallRotateValidatorKey` transactions in this block.
        let exec_hardening = crate::chain_spec::exec_hardening_v1_active_at(block.height);
        for (idx, tx) in block.transactions.iter().enumerate() {
            if !status.get(idx).copied().unwrap_or(false) {
                continue;
            }
            for op in &tx.payload {
                if exec_hardening && matches!(op, crate::svm::OpCode::Halt) {
                    break;
                }
                if let crate::svm::OpCode::SysCallRotateValidatorKey {
                    old_validator,
                    new_validator,
                } = op
                {
                    v3_state.migrate_validator(old_validator, new_validator, current_epoch);
                    abort_state.migrate_validator(old_validator, new_validator);
                }
            }
        }

        // 2. Admit CommitCarrierV3 entries in canonical sorted order `(validator_id, epoch_n)`.
        if let Some(payload) = &block.cnvrf_v3 {
            if !payload.commits.is_empty() {
                let mut commits: Vec<&CommitCarrierV3> = payload.commits.iter().collect();
                commits.sort_by(|a, b| {
                    a.validator_id
                        .cmp(&b.validator_id)
                        .then_with(|| a.epoch_n.cmp(&b.epoch_n))
                });
                let ledger = self.staking.read().await;
                for c in commits {
                    if !ledger.validators.contains_key(&c.validator_id) {
                        tracing::warn!(
                            validator = %hex::encode(c.validator_id),
                            epoch = c.epoch_n,
                            "cnvrf_v3 commit ignored: unknown validator"
                        );
                        continue;
                    }
                    let key_opt = ledger
                        .validator_pq_keys
                        .get(&c.validator_id)
                        .cloned()
                        .or_else(|| {
                            crate::consensus::pq_key_at_height(&c.validator_id, block.height)
                        })
                        .or_else(|| self.get_pinned_pubkey(&c.validator_id));
                    let Some((scheme, pk)) = key_opt else {
                        tracing::warn!(
                            validator = %hex::encode(c.validator_id),
                            epoch = c.epoch_n,
                            "cnvrf_v3 commit ignored: no active PQ key"
                        );
                        continue;
                    };
                    if scheme.is_disabled() || pk.len() != CNVRF_PK_LEN {
                        tracing::warn!(
                            validator = %hex::encode(c.validator_id),
                            epoch = c.epoch_n,
                            "cnvrf_v3 commit ignored: invalid PQ key scheme or length"
                        );
                        continue;
                    }
                    if let Err(e) = v3_state.admit_commit(c, block.height, self.chain_id, &pk) {
                        tracing::warn!(
                            validator = %hex::encode(c.validator_id),
                            epoch = c.epoch_n,
                            "cnvrf_v3 commit rejected: {e:?}"
                        );
                    }
                }
            }
        }

        // 3. Apply proposer slot reveal and update leaky-bucket abort state.
        let reveal_ref = block.cnvrf_v3.as_ref().and_then(|p| p.reveal.as_ref());
        match v3_state.apply_slot_reveal(self.chain_id, &block.proposer, block.height, reveal_ref) {
            SlotRevealOutcome::Revealed { .. } => {
                let ledger = self.staking.read().await;
                ledger.record_cnvrf_reveal_present(&mut abort_state, &block.proposer);
            }
            SlotRevealOutcome::CommittedMissingReveal => {
                if block.shard_id == crate::sharding::MASTERCHAIN_SHARD {
                    let mut ledger = self.staking_write().await;
                    let rewards_before = ledger.rewards_pool;
                    match ledger.record_cnvrf_reveal_abort(
                        &mut abort_state,
                        &block.proposer,
                        block.height,
                    ) {
                        Ok(burned) if burned > 0 => {
                            let rewards_burn = rewards_before.saturating_sub(ledger.rewards_pool);
                            let staking_burn = burned.saturating_sub(rewards_burn);
                            pending_rewards_burn =
                                pending_rewards_burn.saturating_add(rewards_burn);
                            pending_staking_burn =
                                pending_staking_burn.saturating_add(staking_burn);
                        }
                        Ok(_) => {}
                        Err(e) => {
                            tracing::warn!(
                                proposer = %hex::encode(block.proposer),
                                height = block.height,
                                "cnvrf_v3 reveal abort slash skipped: {e}"
                            );
                        }
                    }
                }
            }
            SlotRevealOutcome::AbsentNoCommit => {}
            SlotRevealOutcome::InvalidReveal => {
                tracing::warn!(
                    proposer = %hex::encode(block.proposer),
                    height = block.height,
                    "cnvrf_v3 invalid proposer reveal ignored"
                );
            }
            SlotRevealOutcome::UnexpectedReveal => {
                tracing::warn!(
                    proposer = %hex::encode(block.proposer),
                    height = block.height,
                    "cnvrf_v3 unexpected proposer reveal ignored"
                );
            }
        }

        // 4. Snapshot freeze-boundary `(freeze_block_hash, rolling_mix)` at `H_freeze`
        //    so the upcoming epoch's `EpochVdfBeacon::raw_seed` is verified against it.
        if block.height >= V3_COMMIT_LOOKAHEAD_BLOCKS {
            if let Some(boundary) = block.height.checked_add(V3_COMMIT_LOOKAHEAD_BLOCKS) {
                if boundary.is_multiple_of(EPOCH_LEN) {
                    let target_epoch = boundary / EPOCH_LEN;
                    let prev_epoch = target_epoch.saturating_sub(1);
                    let freeze_mix = v3_state.rolling_mix_for_epoch(prev_epoch);
                    freeze_inputs.insert(target_epoch, (block.compute_hash(), freeze_mix));
                }
            }
        }

        // 5. Verify and record finalized epoch VDF beacon, if carried.
        if let Some(vdf_beacon) = block.cnvrf_v3.as_ref().and_then(|p| p.epoch_vdf.as_ref()) {
            let e = vdf_beacon.epoch;
            if !epoch_beacons.contains_key(&e) && e <= current_epoch.saturating_add(1) {
                let seed_matches = if let Some((freeze_hash, freeze_mix)) = freeze_inputs.get(&e) {
                    // ONE derivation, shared with the producer (H_freeze
                    // dispatch in `runtime/anchors.rs`) and the proposal
                    // validator (`validate_cnvrf_v3_payload`): the bootstrap
                    // beacon chains the first post-activation epoch, a
                    // committed on-chain beacon chains every later one, and a
                    // missing VDF-era beacon fails closed on zeros. The local
                    // copy chained zeros for the FIRST boundary, which the
                    // producer never derived — the beacon chain could never
                    // start (review R1, finding F3).
                    let expected = crate::cn_vrf::epoch_seed(
                        self.chain_id,
                        e,
                        epoch_beacons.get(&e.saturating_sub(1)),
                        self.cnvrf_v3_is_active_at(crate::cn_vrf::freeze_height_of_epoch(
                            e.saturating_sub(1),
                        )),
                        freeze_hash,
                        freeze_mix,
                    );
                    vdf_beacon.raw_seed == expected
                } else {
                    true
                };
                if seed_matches {
                    if let Some(out) = crate::minroot_vdf::verify(
                        &vdf_beacon.raw_seed,
                        vdf_beacon.proof.steps,
                        &vdf_beacon.proof,
                    ) {
                        epoch_beacons.insert(e, out);
                    } else {
                        tracing::warn!(
                            epoch = e,
                            height = block.height,
                            "cnvrf_v3 epoch_vdf proof verification failed"
                        );
                    }
                } else {
                    tracing::warn!(
                        epoch = e,
                        height = block.height,
                        "cnvrf_v3 epoch_vdf raw_seed mismatch against freeze boundary"
                    );
                }
            }
        }

        // 6. Expire old epoch commits (keep current, previous, and current-2).
        v3_state.expire_before(current_epoch.saturating_sub(2));

        let cnvrf_changed = *v3_state != v3_before
            || *abort_state != abort_before
            || *epoch_beacons != beacons_before;

        drop(freeze_inputs);
        drop(epoch_beacons);
        drop(abort_state);
        drop(v3_state);

        if cnvrf_changed {
            self.bump_domain_generation(crate::commitment::Domain::CnVrf);
        }

        // SLASH-02: fail-closed, loud pool settlement (never a silent
        // `let _ =` on a value path); the split itself was derived from the
        // ledger's `rewards_pool` mirror above, so the two pools stay 1:1
        // with it.
        self.settle_slash_burn(
            crate::staking::STAKING_POOL,
            pending_staking_burn,
            "cnvrf-abort",
        )
        .await;
        self.settle_slash_burn(
            crate::staking::REWARDS_POOL,
            pending_rewards_burn,
            "cnvrf-abort-rewards",
        )
        .await;

        pending_staking_burn.saturating_add(pending_rewards_burn)
    }

    // -----------------------------------------------------------------------
    // HashPool note/nullifier apply wiring (default-OFF; see the section
    // above `HASH_POOL_ENABLED`). No other apply logic is touched: the
    // standard `apply_block_transition` body is unchanged, and the sidecar
    // below reuses it verbatim before applying pool ops.
    // -----------------------------------------------------------------------

    /// Whether the HashPool apply path is live on this instance: the const
    /// (always `false` in production builds) OR the test-only override.
    pub fn hashpool_enabled(&self) -> bool {
        HASH_POOL_ENABLED || self.hashpool_tests_on.load(Ordering::Relaxed)
    }

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

    /// Test-only switch: bind a FRESH empty pool to this engine's current
    /// `chain_id` and flip the per-instance gate on.
    ///
    /// Never called on the live path (only `tests/` call it). Rebinding on
    /// enable keeps the pool's chain binding exact even though `chain_id` is
    /// a plain public field: whatever chain this engine claims at enable
    /// time is what the pool commits to.
    pub async fn enable_hashpool_for_tests(&self) {
        *self.hashpool.write().await = crate::hashpool::HashPool::new(self.chain_id);
        self.hashpool_tests_on.store(true, Ordering::Release);
    }

    /// Real Falcon-512 owner-signature verifier for CoinJoin batches (the
    /// caller-supplied closure shape `coinjoin_verify` requires).
    fn hashpool_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        crate::post_quantum::verify_pq_signature(
            crate::post_quantum::PqScheme::Falcon512,
            pk,
            msg,
            sig,
        )
    }

    /// Number of deposited commitments (test accessor; no mutation).
    pub async fn hashpool_len(&self) -> usize {
        self.hashpool.read().await.len()
    }

    /// Number of spent nullifiers (test accessor; no mutation).
    pub async fn hashpool_spent_len(&self) -> usize {
        self.hashpool.read().await.spent_len()
    }

    /// True when `commitment` is registered (test accessor; no mutation).
    pub async fn hashpool_contains(&self, commitment: &[u8; 32]) -> bool {
        self.hashpool.read().await.contains(commitment)
    }

    /// True when `nullifier` is spent (test accessor; no mutation).
    pub async fn hashpool_is_spent(&self, nullifier: &[u8; 32]) -> bool {
        self.hashpool.read().await.is_spent(nullifier)
    }

    /// Register one note deposit. Refuses [`HashPoolOpError::Disabled`]
    /// while the gate is off (nothing read, nothing written); otherwise
    /// registers via `HashPool::deposit` and mirrors the commitment leaf
    /// into the state trie so the state root moves deterministically.
    pub async fn apply_hashpool_deposit(
        &self,
        commitment: [u8; 32],
        stealth: [u8; 32],
        nullifier: [u8; 32],
    ) -> Result<(), HashPoolOpError> {
        if !self.hashpool_enabled() {
            return Err(HashPoolOpError::Disabled);
        }
        let mut pool = self.hashpool.write().await;
        pool.deposit(commitment, stealth, nullifier)?;
        let mut trie = self.state_trie.write().await;
        trie.insert(&hashpool_commitment_key(&commitment), &stealth);
        Ok(())
    }

    /// Consume one note by revealing its opening. Refuses
    /// [`HashPoolOpError::Disabled`] while the gate is off; otherwise spends
    /// via `HashPool::spend` (double-spend refused with
    /// `HpError::AlreadySpent`, wrong serial with `HpError::SerialMismatch`)
    /// and mirrors the spent nullifier leaf into the state trie.
    /// Returns the spent nullifier.
    pub async fn apply_hashpool_spend(
        &self,
        commitment: &[u8; 32],
        serial: &[u8; 32],
        value: u64,
        blinding: &[u8; 32],
    ) -> Result<[u8; 32], HashPoolOpError> {
        if !self.hashpool_enabled() {
            return Err(HashPoolOpError::Disabled);
        }
        let mut pool = self.hashpool.write().await;
        let nf = pool.spend(commitment, serial, value, blinding)?;
        let mut trie = self.state_trie.write().await;
        trie.insert(&hashpool_nullifier_key(&nf), &[1u8]);
        Ok(nf)
    }

    /// Verify a CoinJoin batch with the REAL Falcon-512 verifier and, only
    /// on success, apply it: input nullifiers marked spent, output
    /// commitments registered, both mirrored into the state trie.
    /// Conservation (`sum_in == sum_out + fee`) is enforced by
    /// `coinjoin_verify`/`coinjoin_apply`; a refused batch leaves the pool
    /// and the trie untouched. Refuses [`HashPoolOpError::Disabled`] while
    /// the gate is off.
    pub async fn apply_hashpool_batch(
        &self,
        batch: &crate::hashpool::CoinJoinBatch,
    ) -> Result<(), HashPoolOpError> {
        if !self.hashpool_enabled() {
            return Err(HashPoolOpError::Disabled);
        }
        let mut pool = self.hashpool.write().await;
        crate::hashpool::coinjoin_verify(&pool, batch, &Self::hashpool_verify)?;
        crate::hashpool::coinjoin_apply(&mut pool, batch)?;
        let chain_id = pool.chain_id();
        let mut trie = self.state_trie.write().await;
        for inp in &batch.inputs {
            let nf = crate::hashpool::note_nullifier(&inp.opening.serial);
            trie.insert(&hashpool_nullifier_key(&nf), &[1u8]);
        }
        for out in &batch.outputs {
            let c = crate::hashpool::note_commit(chain_id, out.value, &out.blinding, &out.stealth);
            trie.insert(&hashpool_commitment_key(&c), &out.stealth);
        }
        Ok(())
    }

    /// Apply one explicit [`HashPoolBlockOps`] sidecar: deposits, then
    /// spends, then batches, each in order; refused ops are counted, never
    /// halting. While the gate is off the sidecar is skipped wholesale
    /// (`skipped_gate_off`, all counts zero, state untouched).
    pub async fn apply_hashpool_ops(&self, ops: &HashPoolBlockOps) -> HashPoolApplyOutcome {
        if !self.hashpool_enabled() {
            return HashPoolApplyOutcome {
                skipped_gate_off: true,
                ..Default::default()
            };
        }
        let mut out = HashPoolApplyOutcome::default();
        for d in &ops.deposits {
            match self
                .apply_hashpool_deposit(d.commitment, d.stealth, d.nullifier)
                .await
            {
                Ok(()) => out.deposits_applied += 1,
                Err(_) => out.deposits_refused += 1,
            }
        }
        for s in &ops.spends {
            match self
                .apply_hashpool_spend(&s.commitment, &s.serial, s.value, &s.blinding)
                .await
            {
                Ok(_) => out.spends_applied += 1,
                Err(_) => out.spends_refused += 1,
            }
        }
        for b in &ops.batches {
            match self.apply_hashpool_batch(b).await {
                Ok(()) => out.batches_applied += 1,
                Err(_) => out.batches_refused += 1,
            }
        }
        out
    }

    /// Block-apply entry point with an explicit HashPool sidecar: runs the
    /// UNCHANGED standard [`InMemoryStateEngine::apply_block_transition`]
    /// first (same outcome the live path records), then the gated
    /// [`HashPoolBlockOps`] sidecar. While the gate is off the second step
    /// is a proven no-op, so the returned base outcome and the resulting
    /// state root equal the plain path exactly.
    pub async fn apply_block_transition_with_hashpool(
        &self,
        block: &crate::sharding::Block,
        block_reward: u64,
        ops: &HashPoolBlockOps,
    ) -> (BlockTransitionOutcome, HashPoolApplyOutcome) {
        let base = self.apply_block_transition(block, block_reward).await;
        let hp = self.apply_hashpool_ops(ops).await;
        (base, hp)
    }

    /// §1 ACTOR MAILBOX: deliver the messages queued in every inbox, once per
    /// block, and return how many were delivered.
    ///
    /// Called EXACTLY once per block from [`Self::apply_block_transition`],
    /// between the transactions step and the fee credit - the transactions
    /// QUEUE their sends (settlement at payload commit), this pass CONSUMES
    /// them, and Phase 1's policy is drain-to-empty: every queue is empty at
    /// the block boundary, so there is no mailbox state to persist, no
    /// account-encoding change and the genesis KAT cannot move.
    ///
    /// PHASE 2 (deliberately NOT done here): if a queued message ever has to
    /// SURVIVE a block boundary as committed state - a pending message that
    /// outlives the block that created it, rather than a defensive leftover
    /// from the round/cap bounds below - the queues would have to join the
    /// state commitment, and the way to do that without breaking anything
    /// that exists is a CONDITIONAL account encoding: an `ACTORQ1` leaf shape
    /// used only by accounts that actually hold messages, appended so every
    /// pre-Phase-2 account leaf (balance || nonce, and the node-snapshot
    /// `AccountState` bincode) keeps decoding byte-for-byte, and writing no
    /// extra bytes for the overwhelmingly common empty queue (the same
    /// conditional-domain trick `bridge`/`confidential` use in the
    /// commitment digest, so the root of a chain that never queued anything
    /// stays pinned to the genesis KAT). Phase 1 buys the simpler world
    /// instead: bounded block, guaranteed quiescence, inbox contents never in
    /// the root at a boundary - which is exactly what makes this pass free
    /// for legacy blocks.
    ///
    /// Algorithm, and why each piece is where it is:
    ///
    ///  * ONE accounts write lock for the whole pass, so a delivery can never
    ///    interleave with another block, an RPC apply or a direct
    ///    `send_message` and observe a half-updated inbox.
    ///  * Recipients are collected from the `HashMap` and then
    ///    `sort_unstable`-ed by ADDRESS. Iterating the map directly would
    ///    deliver in a per-process random order, and order is observable here:
    ///    a body reads and moves the balance another body just changed, so
    ///    two nodes applying the same block could derive different states.
    ///  * FIFO within a recipient (each round pops from the front), so a
    ///    sender's own ordering is preserved.
    ///  * Rounds: a body may enqueue further sends, and one whose recipient
    ///    was already visited this round is picked up by the next - which is
    ///    what bounds recursion together with [`MAX_ACTOR_ROUNDS`].
    ///  * [`MAX_ACTOR_MSGS_PER_BLOCK`] bounds the pass's total work. It is a
    ///    defensive clamp (the proposer-side block gas limit keeps real blocks
    ///    far below it); a message still queued when it or the rounds run out
    ///    is never dropped and never delivered out of order - it drains in a
    ///    later block.
    ///
    /// Per-message atomicity: the delivery snapshots every account it touches
    /// (lazily, so third parties a body reaches are covered too), runs the
    /// body in the VM - whose own clone-commit already discards registry
    /// mutations on a revert - and on ANY failure (revert, out of gas,
    /// undecodable body, unaffordable effect) rolls the account map back to
    /// the pre-message state and bounces the message to its sender: value
    /// returned EXACTLY once, no partial effect. A bounced message is a pure
    /// refund whose body is never re-run, so a bounce can never bounce again.
    ///
    /// `block` is the block being applied: its `timestamp` is the clock a
    /// delivered body runs against (never local wall time - every node must
    /// reach the same verdict).
    pub async fn apply_actor_messages_at(&self, block: &crate::sharding::Block) -> usize {
        // The two governed staking parameters a VmContext wants, read BEFORE
        // the accounts lock (this is the only lock order the pass takes part
        // in: governance, then accounts, then the trie - nothing in the tree
        // takes accounts and then governance, so no deadlock is possible).
        // Unreachable for a body today - staking is deliberately not wired
        // into the delivery context, so every staking syscall reverts - but
        // the fields are non-optional and a node-local default would be the
        // wrong value to hard-code if that ever changes.
        let (min_validator_bond, default_commission_bps) = {
            let gov = self.governance.read().await;
            (
                gov.applied
                    .min_validator_bond
                    .unwrap_or(crate::staking::MIN_VALIDATOR_BOND),
                gov.applied
                    .default_commission_bps
                    .unwrap_or(crate::staking::DEFAULT_COMMISSION_BPS),
            )
        };
        let dctx = DeliveryCtx {
            timestamp: block.timestamp,
            min_validator_bond,
            default_commission_bps,
        };

        let mut map = self.accounts.write().await;
        // Fast path: the common block queues nothing, so the pass must not
        // take the trie lock or allocate a touched set at all.
        if map.values().all(|acc| acc.inbox.is_empty()) {
            return 0;
        }

        let mut touched: HashSet<[u8; 32]> = HashSet::new();
        let mut processed = 0usize;

        'rounds: for _round in 0..MAX_ACTOR_ROUNDS {
            // Every recipient with a queued message, in address order. The
            // collection is re-made each round because the previous round's
            // deliveries may have queued messages for accounts that were
            // empty when it started.
            let mut recipients: Vec<[u8; 32]> = map
                .iter()
                .filter(|(_, acc)| !acc.inbox.is_empty())
                .map(|(addr, _)| *addr)
                .collect();
            if recipients.is_empty() {
                break; // quiescent: drain-to-empty reached
            }
            recipients.sort_unstable();
            for recipient in recipients {
                loop {
                    if processed >= MAX_ACTOR_MSGS_PER_BLOCK {
                        break 'rounds;
                    }
                    let msg = match map
                        .get_mut(&recipient)
                        .and_then(|acc| acc.inbox.pop_front())
                    {
                        Some(m) => m,
                        None => break, // this recipient's queue is empty
                    };
                    processed += 1;
                    Self::deliver_actor_message(&mut map, &mut touched, recipient, msg, &dctx);
                }
            }
        }

        // Write ONLY the accounts the pass touched, with their final balances
        // (the same pattern as the transactions step): inboxes are not trie
        // state and nonces never move here.
        let mut trie = self.state_trie.write().await;
        for addr in &touched {
            if let Some(acc) = map.get(addr) {
                let data = acc.to_trie_bytes();
                trie.insert(addr, &data);
            }
        }
        processed
    }

    /// Deliver ONE queued message into the account whose inbox it sits in.
    ///
    /// Failure handling is the design's undo-then-bounce: every account the
    /// delivery touched is restored to its pre-message state (the lazy
    /// snapshot covers the recipient, the sender and any third party a body
    /// reached), and the message goes back to its SENDER marked `bounced` -
    /// where it is a pure refund, delivered later in this same pass.
    fn deliver_actor_message(
        map: &mut HashMap<[u8; 32], AccountState>,
        touched: &mut HashSet<[u8; 32]>,
        owner: [u8; 32],
        msg: ActorMessage,
        dctx: &DeliveryCtx,
    ) {
        // Invariant: every enqueue path pushes a message into ITS RECIPIENT's
        // inbox (settlement, `send_message`, and this pass's own bounces all
        // keep `owner == msg.recipient`), so the account it came out of is
        // the account to credit.
        debug_assert_eq!(owner, msg.recipient);

        if msg.bounced {
            // A bounce is a pure refund - its value was debited from the
            // sender when the original message was enqueued, so crediting it
            // here returns the value EXACTLY once. The original body is NOT
            // re-run: a failed body must not get a second attempt on the way
            // back, which is also why a bounce can never bounce again.
            if owner == msg.recipient {
                if let Some(acc) = map.get_mut(&owner) {
                    // `checked_add` cannot fail in practice: the sender paid
                    // exactly this amount out of a supply that fits in u64.
                    // Leaving the balance untouched rather than saturating is
                    // the fail-safe shape (no silent wrap).
                    if let Some(b) = acc.balance.checked_add(msg.value) {
                        acc.balance = b;
                    }
                    touched.insert(owner);
                }
            }
            return;
        }

        let mut undo = MessageUndo::default();
        if Self::try_deliver(map, &mut undo, touched, owner, &msg, dctx).is_err() {
            undo.rollback(map);
            // Reversed message, queued in the SENDER's inbox (which is its
            // own `recipient` field, so the pass will deliver it below) -
            // exactly the bounce shape the engine's `send_message` has always
            // used.
            if let Some(snd) = map.get_mut(&msg.sender) {
                snd.inbox.push_back(ActorMessage {
                    msg_id: msg.msg_id,
                    sender: msg.recipient,
                    recipient: msg.sender,
                    value: msg.value,
                    body: msg.body,
                    bounce: false,
                    bounced: true,
                });
            }
        }
    }

    /// The success path of one delivery: credit, run the prepaid body, settle
    /// its transfers and its sends. ANY `Err` means "the message failed" -
    /// the caller undoes the snapshot and bounces it; nothing here is allowed
    /// to half-apply.
    fn try_deliver(
        map: &mut HashMap<[u8; 32], AccountState>,
        undo: &mut MessageUndo,
        touched: &mut HashSet<[u8; 32]>,
        owner: [u8; 32],
        msg: &ActorMessage,
        dctx: &DeliveryCtx,
    ) -> Result<(), String> {
        // A message queued outside its recipient's inbox cannot be delivered
        // (and has no inbox to be put back into either). Unreachable by the
        // enqueue invariant above - fail closed if it is ever violated.
        if owner != msg.recipient {
            return Err("actor message queued outside its recipient's inbox".to_string());
        }

        // 1. Credit the delivered value. Snapshot FIRST, so a later failure
        //    takes the credit back with everything else - "delivery credits
        //    the recipient" only holds for a message that fully delivered.
        undo.note(map, owner);
        let balance = {
            let acc = map
                .get_mut(&owner)
                .ok_or_else(|| "actor recipient account does not exist".to_string())?;
            acc.balance = acc
                .balance
                .checked_add(msg.value)
                .ok_or_else(|| "actor delivery: recipient balance overflow".to_string())?;
            acc.balance
        };
        touched.insert(owner);

        // 2. The prepaid program + fuel the sender packed into the body.
        let body = decode_actor_body(&msg.body)?;

        // 3. Run it in the RECIPIENT's context: `ctx.sender` is the original
        //    sender (so a body can see who wrote to it), `ctx.balance` is the
        //    recipient's post-credit balance (a body spends the account it is
        //    delivered TO). Deliberately NO registries wired in - tokens,
        //    books, staking, PMM, oracle, shielded ledger are all `None`, so
        //    a body that touches them reverts the way a direct `Svm::execute`
        //    caller's would. That is v1 scope: a delivered body's entire
        //    effect set is `transfers` plus the sends it enqueues, both
        //    settled below, and the VM's own clone-commit discards anything
        //    it did internally on a revert or out-of-gas.
        let mut sends: Vec<crate::svm::ActorSendRequest> = Vec::new();
        let mut ctx = crate::svm::VmContext {
            sender: msg.sender,
            balance,
            orderbooks: None,
            patricia_trie: None,
            session_auth: None,
            session_keys: None,
            zkml_proof: None,
            timestamp: dctx.timestamp,
            trades: Vec::new(),
            transfers: Vec::new(),
            token_registry: None,
            token_events: Vec::new(),
            contracts: None,
            staking: None,
            pmm: None,
            min_validator_bond: dctx.min_validator_bond,
            default_commission_bps: dctx.default_commission_bps,
            payouts: Vec::new(),
            oracle: None,
        };
        // No registries wired by design (see the context above): in
        // particular `zkml_models` is `None`, so a delivered body can never
        // register or verify a model - all four zkML opcodes fail closed
        // there (both re-execution halves and both succinct halves).
        let res = crate::svm::Svm::execute_with_confidential_and_sends(
            &body.program,
            body.gas_budget,
            &mut ctx,
            &mut sends,
            None,
        );
        let (transfers, payouts) = match res {
            crate::svm::VmExecutionResult::Success {
                transfers, payouts, ..
            } => (transfers, payouts),
            crate::svm::VmExecutionResult::OutOfGas => {
                return Err("actor body ran out of gas".to_string())
            }
            crate::svm::VmExecutionResult::Reverted(e) => {
                return Err(format!("actor body reverted: {e}"))
            }
        };

        // 4. Settle the body's own value movements. The acting account pays;
        //    a recipient that does not exist yet is created, exactly like
        //    `commit_native` does for a payload transfer. The VM already
        //    priced these against its balance mirror (which started at the
        //    post-credit balance and cannot have drifted - this pass holds
        //    the accounts lock throughout), but this is where coins actually
        //    move, so the checks live here too.
        for (to, amount) in &transfers {
            undo.note(map, owner);
            {
                let from = map
                    .get_mut(&owner)
                    .ok_or_else(|| "actor recipient vanished mid-delivery".to_string())?;
                if from.balance < *amount {
                    return Err(format!(
                        "actor body transfer: {} holds {} but must pay {amount}",
                        hex::encode(&owner[..6]),
                        from.balance
                    ));
                }
                from.balance -= *amount;
            }
            undo.note(map, *to);
            match map.get_mut(to) {
                Some(acc) => {
                    acc.balance = acc.balance.checked_add(*amount).ok_or_else(|| {
                        "actor delivery: transfer recipient balance overflow".to_string()
                    })?;
                }
                None => {
                    map.insert(*to, AccountState::new(*to, *amount));
                }
            }
            touched.insert(*to);
        }
        // A delivered body has no staking ledger wired, so it cannot have
        // produced a payout; refuse rather than silently skip value that was
        // promised to somebody.
        if !payouts.is_empty() {
            return Err("actor body produced payouts with no payer wired".to_string());
        }

        // 5. Settle the sends the body enqueued - the recursion step. The
        //    acting account pays for each one (the VM debited its mirror), a
        //    missing recipient bounces immediately (value returns to the
        //    actor exactly once), and everything is snapshot-covered: a send
        //    that cannot be funded fails the WHOLE delivery, which then
        //    bounces the original message.
        for s in &sends {
            if !s.bounce {
                return Err("actor body produced a non-bounceable send".to_string());
            }
            undo.note(map, owner);
            {
                let from = map
                    .get_mut(&owner)
                    .ok_or_else(|| "actor recipient vanished mid-delivery".to_string())?;
                if from.balance < s.value {
                    return Err(format!(
                        "actor body cannot fund its own send of {} nano-STELL",
                        s.value
                    ));
                }
                from.balance -= s.value;
            }
            let encoded = encode_actor_body(&s.body, s.gas_budget);
            let nested = ActorMessage::new(owner, s.recipient, s.value, encoded, s.bounce);
            if map.contains_key(&s.recipient) {
                undo.note(map, s.recipient);
                map.get_mut(&s.recipient)
                    .expect("recipient existence checked above")
                    .inbox
                    .push_back(nested);
            } else {
                let bounce = ActorMessage {
                    msg_id: nested.msg_id,
                    sender: s.recipient,
                    recipient: owner,
                    value: nested.value,
                    body: nested.body,
                    bounce: false,
                    bounced: true,
                };
                map.get_mut(&owner)
                    .expect("owner exists (credited above)")
                    .inbox
                    .push_back(bounce);
            }
            touched.insert(owner);
        }

        touched.insert(owner);
        Ok(())
    }

    /// Burn the stake of validators that missed the quorum of `height`'s
    /// certificate, and debit the burned coins from the staking pool.
    ///
    /// Shared by `apply_block_transition` (which passes the block's own height
    /// and `precommit_qc`) and `ValidatorRuntime::apply_downtime_slashes`
    /// (which passes `hc.height` / `hc.precommit_qc` for tests that exercise
    /// the primitive directly). No certificate -> no slash, exactly as before.
    ///
    /// ELECTED-ONLY (audit M3 fail-closed): miss-counting/slashing is
    /// restricted to the CURRENT elected set (`to_validator_set`: self-bond >=
    /// MIN, top-250 by stake). Unelected keys (thin bonds, fully-exited
    /// records, never-elected entries) accumulate NOTHING — no `missed`
    /// increments, no cooldown-stamp moves, no slash. Cooldown/threshold math
    /// inside `note_missed_heights` is otherwise identical.
    pub async fn apply_downtime_slash(
        &self,
        height: u64,
        qc: Option<&crate::consensus::QuorumCertificate>,
    ) -> u64 {
        let Some(cert) = qc else {
            return 0;
        };
        let val_set = self.staking.read().await.to_validator_set();
        self.apply_downtime_slash_with_set(height, Some(cert), &val_set)
            .await
    }

    /// Apply every block-carried [`crate::svm::OpCode::SysCallUnjail`] whose
    /// transaction applied. This is the live entry point for
    /// [`crate::staking::StakingLedger::unjail`] (pentest F7).
    ///
    /// The VM arm validates everything that does NOT need the block height
    /// (sender == validator, the jail record exists, the self-bond is back at
    /// MIN+buffer) and reverts otherwise. The RELEASE-HEIGHT gate lives here
    /// because `VmContext` carries no height; `block.height` is the
    /// deterministic clock every node applies. A refusal (early release) is
    /// fail-closed: the jail record is untouched, the sender has already paid
    /// gas for the carrier exactly like a refused governance op, and the
    /// block itself never fails.
    ///
    /// Order matters: this runs AFTER the transaction pass, so a
    /// `SysCallStake` top-up in the same payload is already committed, and
    /// BEFORE the downtime step, so the re-admitted validator is subject to
    /// this block's evidence on the same terms as every other member.
    ///
    /// Returns the number of validators actually re-admitted (observability
    /// only; never consensus state).
    pub async fn apply_staking_unjail_ops(
        &self,
        block: &crate::sharding::Block,
        status: &[bool],
    ) -> usize {
        // Collect first: the common block carries no unjail op and must not
        // take the staking write lock at all.
        let exec_hardening = crate::chain_spec::exec_hardening_v1_active_at(block.height);
        let mut requests: Vec<([u8; 32], [u8; 32])> = Vec::new();
        for (i, tx) in block.transactions.iter().enumerate() {
            if !status.get(i).copied().unwrap_or(false) {
                continue;
            }
            for op in &tx.payload {
                if exec_hardening && matches!(op, crate::svm::OpCode::Halt) {
                    break;
                }
                if let crate::svm::OpCode::SysCallUnjail { validator } = op {
                    requests.push((tx.from, *validator));
                }
            }
        }
        if requests.is_empty() {
            return 0;
        }
        let mut ledger = self.staking_write().await;
        let mut unjailed = 0usize;
        for (sender, validator) in requests {
            // Defense in depth: the VM already refused a mismatch, but a
            // replayed/foreign envelope must never clear someone else's jail.
            if sender != validator {
                tracing::warn!(
                    "SysCallUnjail refused at height {}: sender {} is not validator {}",
                    block.height,
                    hex::encode(sender),
                    hex::encode(validator),
                );
                continue;
            }
            match ledger.unjail(validator, block.height) {
                Ok(()) => unjailed += 1,
                Err(e) => tracing::warn!(
                    "SysCallUnjail refused at height {} for {}: {e} (jail stays; add_bond with SysCallStake, retry at/after release_height)",
                    block.height,
                    hex::encode(validator),
                ),
            }
        }
        unjailed
    }

    /// SLASH-02: settle an engine-side slash's burn against its backing pool
    /// and return the amount that ACTUALLY left it.
    ///
    /// The ledger has already removed the stake and counted it in
    /// `total_burned` by the time this runs (there is no undo for a slash), so
    /// a dropped debit error — the old `let _ = self.debit_native(..)` — left
    /// the ledger claiming a burn that never happened: pool/ledger drift by
    /// exactly `claimed`, which the staking docs forbid and which makes later
    /// `withdraw` fail against a short pool.
    ///
    /// The rule here is fail-closed and LOUD, with no silent `let _ =` on a
    /// value path:
    ///
    ///  * debit the claimed amount; success returns it;
    ///  * on failure, take whatever the pool actually holds (never more);
    ///  * log the shortfall at ERROR with both numbers (a consistent ledger
    ///    preserves `STAKING_POOL == ledger_stake_supply()` and
    ///    `REWARDS_POOL == rewards_pool`, so the shortfall is unreachable
    ///    unless the state was already drifted);
    ///  * retire the unbacked part from `total_burned` so the committed
    ///    supply counter stops claiming coins that did not move.
    ///
    /// Deterministic: every node applies the same blocks to the same
    /// pre-state, so every node sees the same pool balance and takes the same
    /// branch.
    async fn settle_slash_burn(&self, pool: [u8; 32], claimed: u64, what: &str) -> u64 {
        if claimed == 0 {
            return 0;
        }
        match self.debit_native(&pool, claimed).await {
            Ok(()) => claimed,
            Err(e) => {
                let available = self
                    .get_account(&pool)
                    .await
                    .map(|a| a.balance)
                    .unwrap_or(0);
                let moved = available.min(claimed);
                tracing::error!(
                    "SLASH-POOL-DRIFT {what}: the ledger removed {claimed} nano but pool {} holds only {available} ({e}); capping the debit at {moved} and un-counting the unbacked shortfall",
                    hex::encode(pool),
                );
                if moved > 0 {
                    if let Err(e2) = self.debit_native(&pool, moved).await {
                        tracing::error!(
                            "SLASH-POOL-DRIFT {what}: the capped debit of {moved} nano from {} ALSO failed ({e2}); nothing left the pool",
                            hex::encode(pool),
                        );
                        return 0;
                    }
                }
                let shortfall = claimed.saturating_sub(moved);
                if shortfall > 0 {
                    self.staking_write().await.record_unbacked_burn(shortfall);
                }
                moved
            }
        }
    }

    /// Downtime attribution against an EXPLICIT validator set.
    ///
    /// W10.5 activation boundary: the evidence QC (height H-1) must be
    /// verified and attributed against the set IN FORCE AT ITS OWN HEIGHT,
    /// never the live set. [`Self::apply_block_transition`] passes its
    /// pre-transition snapshot (the ledger as of the end of H-1); the replay
    /// path derives the same oracle from the block's committed pre-state.
    /// Verifying against a set read after the transition accepts quorums
    /// the evidence height never had and attributes misses to the wrong
    /// membership (a bond in the applied block raises the quorum out from
    /// under a genuine QC and the slash is skipped; an unbonded-away member
    /// loses the miss it earned).
    ///
    /// The plain [`Self::apply_downtime_slash`] keeps the legacy oracle
    /// (the live ledger set) for the consensus-view test primitive and the
    /// pre-upgrade replay fallback, where no pre-state snapshot exists.
    pub async fn apply_downtime_slash_with_set(
        &self,
        height: u64,
        qc: Option<&crate::consensus::QuorumCertificate>,
        val_set: &crate::consensus::ValidatorSet,
    ) -> u64 {
        self.apply_downtime_slash_with_set_inner(height, qc, val_set, None)
            .await
    }

    /// [`Self::apply_downtime_slash_with_set`] plus the OLD -> NEW rotation
    /// aliases derived from the block being applied.
    ///
    /// ROTATION ESCAPE (SLASH-01): a validator that rotates its key in block
    /// H is removed from `validators` BEFORE the downtime step attributes
    /// H-1's evidence (the evidence was formed under the OLD id). Without the
    /// alias the ledger lookup misses and the deficit is silently forgiven, so
    /// rotating every height evades downtime slashing entirely. The alias map
    /// is a pure function of the applied rotation opcodes (block bytes +
    /// status), so every node attributes the same miss to the same record.
    pub async fn apply_downtime_slash_with_set_alias(
        &self,
        height: u64,
        qc: Option<&crate::consensus::QuorumCertificate>,
        val_set: &crate::consensus::ValidatorSet,
        rotation_aliases: &HashMap<[u8; 32], [u8; 32]>,
    ) -> u64 {
        self.apply_downtime_slash_with_set_inner(height, qc, val_set, Some(rotation_aliases))
            .await
    }

    async fn apply_downtime_slash_with_set_inner(
        &self,
        height: u64,
        qc: Option<&crate::consensus::QuorumCertificate>,
        val_set: &crate::consensus::ValidatorSet,
        rotation_aliases: Option<&HashMap<[u8; 32], [u8; 32]>>,
    ) -> u64 {
        let Some(cert) = qc else {
            return 0;
        };
        // V-P34 (R2 fail-closed): a certificate that does not verify is not
        // evidence of anything — it names no trustworthy signers AND proves
        // no quorum. Neither slashing nor forgiving on its strength: an
        // unverifiable marker must move no stake either way (the old
        // decode-only attribution let a REJECTED QC forgive downtime, and
        // the strict attribution alone would let it accuse EVERYONE).
        // Production blocks carry quorum-verified QCs (the finalize and adopt
        // paths both `verify` before applying), so this gate is a no-op on
        // the honest path and a firewall on every other path — replay,
        // reorg re-application under a rotated set, hand-built callers. No
        // certificate and a rejected certificate are treated alike.
        // COMMITTEE SCHEDULE (review R1, finding F2): at/after the CN-VRF v3
        // activation the evidence committee is drawn from the EPOCH BEACON,
        // not the parent hash — the same schedule the producer used. Below the
        // gate this is byte-identical to the plain verify/signers path.
        let cert_epoch = crate::cn_vrf::epoch_of_height(cert.height);
        let schedule = if self.cnvrf_v3_is_active_at(cert.height) {
            let committed = self
                .epoch_vdf_beacons_read()
                .await
                .get(&cert_epoch)
                .copied();
            let beacon = crate::cn_vrf::epoch_beacon_for_active(
                self.chain_id,
                cert_epoch,
                committed.as_ref(),
                self.cnvrf_v3_is_active_at(crate::cn_vrf::freeze_height_of_epoch(cert_epoch)),
            );
            crate::consensus::CommitteeSchedule::Beacon(beacon.map(|output| {
                crate::consensus::EpochBeacon {
                    epoch: cert_epoch,
                    output,
                }
            }))
        } else {
            crate::consensus::CommitteeSchedule::ParentHash
        };
        // `Beacon(None)` (a VDF-era beacon we have not committed) elects
        // nobody and verifies nothing — fail closed, exactly like every other
        // beacon consumer.
        if !cert.verify_with_schedule(val_set, schedule) {
            return 0;
        }
        let signers = cert.signers_set_with_schedule(val_set, schedule);
        let eligible: Vec<[u8; 32]> = val_set.validators.keys().copied().collect();
        // SLASH-02: settle BOTH backing pools from the ledger's own split.
        // `note_missed_heights` burns on the evidence scope (SLASH-01), so
        // part of `burned` may be unclaimed `pending_rewards` — backed by
        // `REWARDS_POOL` and mirrored in `ledger.rewards_pool`. The ledger
        // decrements that mirror by exactly the pending cut, so the difference
        // is the reward leg; the rest is staking principal.
        let (burned, rewards_cut) = {
            let mut ledger = self.staking_write().await;
            let rewards_before = ledger.rewards_pool;
            let burned = match rotation_aliases {
                Some(aliases) => ledger.note_missed_heights_with_alias(
                    height,
                    &|v: &[u8; 32]| signers.contains(v),
                    &eligible,
                    aliases,
                ),
                None => ledger.note_missed_heights(
                    height,
                    &|v: &[u8; 32]| signers.contains(v),
                    &eligible,
                ),
            };
            (burned, rewards_before.saturating_sub(ledger.rewards_pool))
        };
        if burned > 0 {
            let staking_cut = burned.saturating_sub(rewards_cut);
            let settled_staking = self
                .settle_slash_burn(crate::staking::STAKING_POOL, staking_cut, "downtime")
                .await;
            let settled_rewards = self
                .settle_slash_burn(
                    crate::staking::REWARDS_POOL,
                    rewards_cut,
                    "downtime-rewards",
                )
                .await;
            // Report what ACTUALLY left the pools (equal to `burned` unless the
            // state was already drifted); `outcome.slashed` claims destruction,
            // so it must not include a shortfall the pools could not fund.
            return settled_staking.saturating_add(settled_rewards);
        }
        burned
    }

    /// Burn 5% of every double-signer named by block-carried equivocation
    /// evidence, debiting the burned coins from the staking pool.
    ///
    /// THE WIRED PATH (audit O1/F4) for VOTES, plus the P3-EQ-ESCAPE wiring
    /// for PROPOSALS (double-propose). Deterministic end to end:
    ///
    ///  * CARRIER: the block BODY — `OpCode::SysCallReportEquivocation`
    ///    payloads in `block.transactions`, each envelope carrying BOTH
    ///    conflicting votes fully, AND
    ///    `OpCode::SysCallReportProposalEquivocation` payloads, each
    ///    envelope carrying BOTH conflicting blocks fully. Any node
    ///    re-verifies from the bytes alone; gossip observations
    ///    (`HeightConsensus::equivocations()`) are NEVER read here, so two
    ///    nodes applying the same block by different routes
    ///    (finalize/adopt/walk/replay/reorg) burn the same coins.
    ///    Carried-invalid evidence (bad shape, forged signature, unknown
    ///    voter/proposer, oversize) burns 0 loudly — it is skipped, never
    ///    fatal. Scanning covers EVERY transaction payload regardless of
    ///    per-transaction success: the SVM arms already revert invalid
    ///    reports at execution, but the scan re-verifies from bytes anyway,
    ///    so exec/scan skew can never move the slash.
    ///  * ORDER: [`crate::consensus::canonicalize_equivocation_evidence`]
    ///    (votes) and
    ///    [`crate::consensus::canonicalize_proposal_equivocation_evidence`]
    ///    (proposals) verify, sort by offense key and drop in-block
    ///    duplicates. Vote offenses slash first, proposal offenses second —
    ///    a fixed class order, so every node derives one verdict from one
    ///    block. Canonical order is consensus-critical: sequential 5% burns
    ///    for one offender do NOT commute (each burn is a fraction of the
    ///    remainder).
    ///  * DEDUP: [`crate::staking::StakingLedger::slash_equivocation_verified`]
    ///    / `slash_proposal_equivocation_verified` consume the per-offense
    ///    key on first processing — the same offense, re-included in any
    ///    later block, burns 0 on every node. Same offense slashed once per
    ///    chain. Vote and proposal keys live under distinct BLAKE3 domains
    ///    but share one set, so the classes can never collide.
    ///  * CAP: at most
    ///    [`crate::consensus::MAX_BLOCK_EQUIVOCATION_EVIDENCES`] vote offenses
    ///    and [`crate::consensus::MAX_BLOCK_PROPOSAL_EQUIVOCATION_EVIDENCES`]
    ///    proposal offenses per
    ///    block; extras are skipped loudly (and may ride a later block).
    ///
    /// Fail-closed throughout: when in doubt this refuses to slash and logs
    /// loudly (slash-wrongly is worse than slash-rarely). Never fails the
    /// block: hostile evidence costs the reporter gas, never the chain.
    pub async fn apply_equivocation_slash(&self, block: &crate::sharding::Block) -> u64 {
        let exec_hardening = crate::chain_spec::exec_hardening_v1_active_at(block.height);
        let mut items: Vec<crate::consensus::EquivocationEvidence> = Vec::new();
        let mut proposals: Vec<crate::consensus::ProposalEquivocationEvidence> = Vec::new();
        for tx in &block.transactions {
            for op in &tx.payload {
                if exec_hardening && matches!(op, crate::svm::OpCode::Halt) {
                    break;
                }
                if let crate::svm::OpCode::SysCallReportEquivocation { evidence } = op {
                    items.push((**evidence).clone());
                }
                if let crate::svm::OpCode::SysCallReportProposalEquivocation { evidence } = op {
                    proposals.push((**evidence).clone());
                }
            }
        }
        let mut total = 0u64;
        if !items.is_empty() {
            // Deterministic shaping against the CURRENT ledger membership. The
            // slash primitive re-verifies each envelope anyway (shape +
            // signatures + membership); this pass exists so every node slashes
            // in the same canonical order.
            let ordered = {
                let ledger = self.staking.read().await;
                crate::consensus::canonicalize_equivocation_evidence(items, &|v| {
                    ledger.validators.contains_key(v)
                })
            };
            if ordered.len() > crate::consensus::MAX_BLOCK_EQUIVOCATION_EVIDENCES {
                tracing::warn!(
                    "equivocation: {} valid evidences exceed per-block cap {} — extras skipped (may ride a later block)",
                    ordered.len(),
                    crate::consensus::MAX_BLOCK_EQUIVOCATION_EVIDENCES,
                );
            }
            for ev in ordered
                .into_iter()
                .take(crate::consensus::MAX_BLOCK_EQUIVOCATION_EVIDENCES)
            {
                // Fail-closed per evidence: an unknown voter (membership moved
                // since shaping) burns 0 with a loud WARN instead of failing
                // the block; a repeat offense burns 0 via the ledger dedup.
                // SLASH-02: the primitive burns on the evidence scope, so
                // the caller settles BOTH pools (staking principal split from
                // unclaimed rewards by the ledger's own mirror).
                let (burned, rewards_cut) = {
                    let mut ledger = self.staking_write().await;
                    let rewards_before = ledger.rewards_pool;
                    let burned = match ledger.slash_equivocation_verified(&ev) {
                        Ok(b) => b,
                        Err(e) => {
                            tracing::warn!(
                                "equivocation evidence for {} skipped ({e}): refusing to slash",
                                hex::encode(ev.voter),
                            );
                            0
                        }
                    };
                    (burned, rewards_before.saturating_sub(ledger.rewards_pool))
                };
                if burned > 0 {
                    let staking_cut = burned.saturating_sub(rewards_cut);
                    let settled_staking = self
                        .settle_slash_burn(
                            crate::staking::STAKING_POOL,
                            staking_cut,
                            "vote-equivocation",
                        )
                        .await;
                    let settled_rewards = self
                        .settle_slash_burn(
                            crate::staking::REWARDS_POOL,
                            rewards_cut,
                            "vote-equivocation-rewards",
                        )
                        .await;
                    total = total
                        .saturating_add(settled_staking)
                        .saturating_add(settled_rewards);
                }
            }
        }
        if !proposals.is_empty() {
            // PROPOSAL offenses (P3-EQ-ESCAPE variant 2): same verdict
            // contract as the vote pass above — re-verify from block bytes,
            // canonical order, per-offense dedup, pool debit. Runs AFTER the
            // vote pass so the combined order is fixed across classes.
            let ordered = {
                let ledger = self.staking.read().await;
                crate::consensus::canonicalize_proposal_equivocation_evidence(proposals, &|v| {
                    ledger.validators.contains_key(v)
                })
            };
            if ordered.len() > crate::consensus::MAX_BLOCK_PROPOSAL_EQUIVOCATION_EVIDENCES {
                tracing::warn!(
                    "proposal equivocation: {} valid evidences exceed per-block cap {} — extras skipped (may ride a later block)",
                    ordered.len(),
                    crate::consensus::MAX_BLOCK_PROPOSAL_EQUIVOCATION_EVIDENCES,
                );
            }
            for ev in ordered
                .into_iter()
                .take(crate::consensus::MAX_BLOCK_PROPOSAL_EQUIVOCATION_EVIDENCES)
            {
                // Fail-closed per evidence: an unknown proposer (membership
                // moved since shaping) burns 0 with a loud WARN instead of
                // failing the block; a repeat offense burns 0 via the ledger
                // dedup.
                // SLASH-02: same two-pool settlement as the vote pass.
                let (burned, rewards_cut) = {
                    let mut ledger = self.staking_write().await;
                    let rewards_before = ledger.rewards_pool;
                    let burned = match ledger.slash_proposal_equivocation_verified(&ev) {
                        Ok(b) => b,
                        Err(e) => {
                            tracing::warn!(
                                "proposal equivocation evidence for {} skipped ({e}): refusing to slash",
                                hex::encode(ev.proposer),
                            );
                            0
                        }
                    };
                    (burned, rewards_before.saturating_sub(ledger.rewards_pool))
                };
                if burned > 0 {
                    let staking_cut = burned.saturating_sub(rewards_cut);
                    let settled_staking = self
                        .settle_slash_burn(
                            crate::staking::STAKING_POOL,
                            staking_cut,
                            "proposal-equivocation",
                        )
                        .await;
                    let settled_rewards = self
                        .settle_slash_burn(
                            crate::staking::REWARDS_POOL,
                            rewards_cut,
                            "proposal-equivocation-rewards",
                        )
                        .await;
                    total = total
                        .saturating_add(settled_staking)
                        .saturating_add(settled_rewards);
                }
            }
        }
        total
    }

    /// Verify a block's signatures in one batch (parallel-friendly fast path).
    pub fn verify_block_signatures(txs: &[crate::sharding::Transaction]) -> bool {
        crate::sharding::Transaction::verify_signatures_batch(txs)
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
    pub(super) async fn session_note_applied(
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
    pub(super) async fn process_contract_outbound_messages_hardened(
        &self,
        messages: &[crate::contract::ContractMessage],
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
            messages, &mut map, &mut xout, my_shard, sharded, &topology,
        )
    }
}
