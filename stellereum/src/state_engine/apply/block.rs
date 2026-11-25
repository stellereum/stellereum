use super::super::BlockTransitionOutcome;
use super::super::InMemoryStateEngine;
use std::collections::HashMap;

impl InMemoryStateEngine {
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
        let gov_block_reward = {
            let gov = self.governance_read().await;
            gov.applied.block_reward
        };
        let block_reward = gov_block_reward.unwrap_or(default_block_reward);
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
        // 0-pre (W3 PQ lifecycle): one-time adoption of pre-W3 validators into
        // `PqRegistry` + deterministic promotion of any due `PendingPqRotation`
        // at `block.height >= effective_height` before block transactions execute.
        self.apply_pq_lifecycle_step0(block.height).await;

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
            .apply_block_parallel_fees_with_events_at_height_and_parent(
                &block.transactions,
                block.timestamp,
                block.height,
                block.prev_hash,
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
        let evm_bindings_active = crate::state_engine::evm_bindings_state_active_at(block.height);
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

        // 2. Pay the collected fees. Pre-activation (default) this is the
        //    historical 100% proposer transfer. Once `FEE_MARKET_V2` is active
        //    the same pot is split exactly, in u128, over the WHOLE block:
        //    burn (never credited — the fees were already debited), proposer,
        //    and the staking rewards pool. The proposer share is the remainder,
        //    so `burn + proposer + staking == fees` to the last nano; the
        //    staking leg is a TRANSFER of collected fees (`distribute_fee_reward`
        //    never touches `rewards_minted`), so neither the 350M emission cap
        //    nor the 1B supply cap is bypassed or unblocked.
        if fees > 0 {
            if crate::tokenomics::fee_market_v2_active_at(block.height) {
                let burn_bps = crate::tokenomics::DEFAULT_FEE_BURN_BPS as u128;
                let staking_bps = crate::tokenomics::DEFAULT_FEE_STAKING_BPS as u128;
                let denom = crate::staking::BPS_DENOMINATOR as u128;
                let burn = ((fees as u128) * burn_bps / denom) as u64;
                let staking = ((fees as u128) * staking_bps / denom) as u64;
                let mut proposer = fees.saturating_sub(burn).saturating_sub(staking);
                if staking > 0 {
                    let credited = self
                        .staking_write()
                        .await
                        .distribute_fee_reward_at_height(block.proposer, staking, block.height)
                        .is_ok();
                    if credited {
                        if self
                            .credit_native_transfer(&crate::staking::REWARDS_POOL, staking)
                            .await
                            .is_err()
                        {
                            // Defensive: keep the ledger's pool backing 1:1 if
                            // the native leg ever refuses.
                            let mut l = self.staking_write().await;
                            l.rewards_pool = l.rewards_pool.saturating_sub(staking);
                        }
                    } else {
                        // Jailed/unknown proposer: the staking share falls back
                        // to the proposer, keeping the split exact.
                        proposer = proposer.saturating_add(staking);
                    }
                }
                if proposer > 0 {
                    let _ = self.credit_native_transfer(&block.proposer, proposer).await;
                }
            } else {
                let _ = self.credit_native_transfer(&block.proposer, fees).await;
            }
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
        // W4 `SUB_NANO_STRICT` + `EMISSIONCapEXACT`: when both gates are active
        // (and governance has not overridden `block_reward`), emit via Q64.64
        // carry (`emit_with_q64_carry`) and persist `emission_carry_q64` in
        // `StakingLedger` on the exact success arm.
        #[allow(clippy::absurd_extreme_comparisons)]
        // GATE: `EMISSIONCapEXACT_ACTIVATION_HEIGHT` is compiled as `u64::MAX`
        // until the geometric emission rollout flips it to a reachable height.
        let use_geometric_carry = gov_block_reward.is_none()
            && crate::tokenomics::EMISSIONCapEXACT_ACTIVATION_HEIGHT != u64::MAX
            && block.height >= crate::tokenomics::EMISSIONCapEXACT_ACTIVATION_HEIGHT
            && crate::tokenomics::sub_nano_strict_active_at(block.height);
        let (effective_reward, next_carry_opt) = if use_geometric_carry {
            let carry_now = self.staking.read().await.emission_carry_q64;
            let (emit_nano, next_carry) = crate::tokenomics::emit_with_q64_carry(
                crate::tokenomics::CAP_EXACT_R0_NANO,
                crate::tokenomics::CAP_EXACT_HALF_LIFE_BLOCKS,
                block.height - crate::tokenomics::EMISSIONCapEXACT_ACTIVATION_HEIGHT,
                carry_now,
            );
            (emit_nano, Some(next_carry))
        } else {
            (block_reward, None)
        };

        if effective_reward > 0 && self.reserve_mint(effective_reward).await.is_ok() {
            let distributed = {
                let mut l = self.staking_write().await;
                let ok = l
                    .distribute_reward_at_height(block.proposer, effective_reward, block.height)
                    .is_ok();
                if ok {
                    if let Some(next_carry) = next_carry_opt {
                        l.emission_carry_q64 = next_carry;
                    }
                }
                ok
            };
            if !distributed {
                // Ledger refused (its own 350M cap, jailed or unknown
                // proposer): the coin was never created, give the global
                // headroom back.
                self.release_mint_nano(effective_reward);
            } else if self
                .credit_reserved_native(&crate::staking::REWARDS_POOL, effective_reward)
                .await
                .is_err()
            {
                // Defensive only: while the reservation above holds and the
                // REWARDS_POOL balance is supply-bounded (it is credited 1:1
                // by this same leg), the pool credit cannot overflow. Keep
                // the two legs 1:1 if it ever does.
                let mut l = self.staking_write().await;
                l.rewards_pool = l.rewards_pool.saturating_sub(effective_reward);
                l.rewards_minted = l.rewards_minted.saturating_sub(effective_reward);
            }
        } else if let Some(next_carry) = next_carry_opt {
            if effective_reward == 0 {
                let mut l = self.staking_write().await;
                if l.rewards_minted < crate::staking::REWARDS_EMISSION_CAP {
                    l.emission_carry_q64 = next_carry;
                }
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

        // 5f. W3 PQ validator lifecycle ops (`SysCallRegisterValidator`,
        //     `SysCallRotateVotingKey`, `SysCallClaimWithdrawal`,
        //     `SysCallAnnounceCommission`, `SysCallApplyCommission`), scanned in
        //     block order over applied pre-`Halt` payloads at `block.height`.
        let _pq_reg_ops = self.apply_pq_registry_ops(block, &status).await;

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
                let pq_reg_guard = if crate::pq_registry::pq_lifecycle_active_at(block.height) {
                    Some(self.pq_registry.read().await)
                } else {
                    None
                };
                for c in commits {
                    if !ledger.validators.contains_key(&c.validator_id) {
                        tracing::warn!(
                            validator = %hex::encode(c.validator_id),
                            epoch = c.epoch_n,
                            "cnvrf_v3 commit ignored: unknown validator"
                        );
                        continue;
                    }
                    let key_opt = if let Some(ref pq_reg) = pq_reg_guard {
                        if pq_reg.record_of(&c.validator_id).is_some() {
                            pq_reg.get_active_key(&c.validator_id, block.height)
                        } else {
                            crate::consensus::pq_key_at_height(&c.validator_id, block.height)
                                .or_else(|| ledger.validator_pq_keys.get(&c.validator_id).cloned())
                                .or_else(|| self.get_pinned_pubkey(&c.validator_id))
                        }
                    } else {
                        ledger
                            .validator_pq_keys
                            .get(&c.validator_id)
                            .cloned()
                            .or_else(|| {
                                crate::consensus::pq_key_at_height(&c.validator_id, block.height)
                            })
                            .or_else(|| self.get_pinned_pubkey(&c.validator_id))
                    };
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
                let h_freeze = crate::cn_vrf::freeze_height_of_epoch(e);
                let freeze_expected =
                    e >= 1 && block.height >= h_freeze && self.cnvrf_v3_is_active_at(h_freeze);
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
                    if freeze_expected {
                        tracing::warn!(
                            epoch = e,
                            height = block.height,
                            h_freeze,
                            "cnvrf_v3 epoch_vdf rejected: missing freeze_inputs after H_freeze"
                        );
                    }
                    !freeze_expected
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

        // 6. Expire old epoch commits and freeze inputs (keep current, previous, and current-2).
        v3_state.expire_before(current_epoch.saturating_sub(2));
        freeze_inputs.retain(|&e, _| e >= current_epoch.saturating_sub(2));

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
        let post_w3 = crate::pq_registry::pq_lifecycle_active_at(block.height);
        let mut ledger = self.staking_write().await;
        let mut unjailed = 0usize;
        for (sender, validator) in requests {
            // Defense in depth: the VM already refused a mismatch, but a
            // replayed/foreign envelope must never clear someone else's jail.
            if let Err(e) = ledger.authorize_validator_owner(&validator, &sender, post_w3) {
                tracing::warn!(
                    "SysCallUnjail refused at height {}: sender {} unauthorized for validator {} ({e})",
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
        let Some(signers) = cert.verify_and_signers_with_schedule(val_set, schedule) else {
            return 0;
        };
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
}
