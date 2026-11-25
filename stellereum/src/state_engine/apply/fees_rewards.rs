use super::super::AccountState;
use super::super::InMemoryStateEngine;
use std::collections::HashMap;

impl InMemoryStateEngine {
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
    pub(in crate::state_engine) fn floor_parts_for(
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
    pub(in crate::state_engine) fn billed_gas(
        tx: &crate::sharding::Transaction,
        gas_used: u64,
    ) -> u64 {
        Self::billed_gas_at(tx, gas_used, false)
    }

    /// Height-gated [`Self::billed_gas`]:
    /// - `< H` (`exec_hardening == false`): `gas_used + TX_INTRINSIC_GAS` when payload is empty or `gas_used == 0`, else `gas_used`, capped at `tx.gas_limit`.
    /// - `>= H` (`exec_hardening == true`): `gas_used.max(TX_INTRINSIC_GAS).min(tx.gas_limit)` so `[OpCode::Nop]` pays `280_000` without adding `280_000` on top of payloads with `gas_used > 280_000`.
    pub(in crate::state_engine) fn billed_gas_at(
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
    pub(in crate::state_engine) fn fee_for_gas(
        tx: &crate::sharding::Transaction,
        gas_used: u64,
        floor_base: u64,
        surcharge: u64,
    ) -> u64 {
        Self::fee_for_gas_at(tx, gas_used, floor_base, surcharge, false)
    }

    /// Height-gated [`Self::fee_for_gas`].
    pub(in crate::state_engine) fn fee_for_gas_at(
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

    /// W4 `FEE_MARKET_V2` twin of [`Self::fee_for_gas_at`].
    ///
    /// When the gate is active the declared `priority_fee_per_gas` is actually
    /// CHARGED as part of the core — capped by the signed `gas_limit`, floored
    /// by consensus, surcharge additive — instead of being handed back as
    /// unused gas. With `fee_market_v2 == false` (or a zero bid) the result is
    /// byte-identical to [`Self::fee_for_gas_at`], so every pre-activation
    /// block re-applies to the same root.
    pub(in crate::state_engine) fn fee_for_gas_at_v2(
        tx: &crate::sharding::Transaction,
        gas_used: u64,
        floor_base: u64,
        surcharge: u64,
        exec_hardening: bool,
        fee_market_v2: bool,
    ) -> u64 {
        if !fee_market_v2 || tx.priority_fee_per_gas == 0 {
            return Self::fee_for_gas_at(tx, gas_used, floor_base, surcharge, exec_hardening);
        }
        let core = Self::billed_gas_at(tx, gas_used, exec_hardening)
            .saturating_add(tx.priority_fee_per_gas)
            .min(tx.gas_limit.max(floor_base))
            .max(floor_base);
        core.saturating_add(surcharge)
    }

    /// W4 `FEE_MARKET_V2` twin of [`Self::failure_fee_for`]: the priority bid
    /// is charged on an attributable failure too (a reverted payload still
    /// bought block space), under the same cap/floor/surcharge rules.
    pub fn failure_fee_for_v2(
        tx: &crate::sharding::Transaction,
        floor_base: u64,
        surcharge: u64,
        fee_market_v2: bool,
    ) -> u64 {
        if !fee_market_v2 || tx.priority_fee_per_gas == 0 {
            return Self::failure_fee_for(tx, floor_base, surcharge);
        }
        let core = Self::TX_INTRINSIC_GAS
            .saturating_add(tx.priority_fee_per_gas)
            .min(tx.gas_limit.max(floor_base))
            .max(floor_base);
        core.saturating_add(surcharge)
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
    pub(in crate::state_engine) fn apply_failure_fee_to_map(
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
    pub(in crate::state_engine) async fn charge_failure_fee(
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
    pub(in crate::state_engine) fn apply_sponsored_failure_fee_to_map(
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
    pub(in crate::state_engine) async fn charge_sponsored_failure_fee(
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
    pub(in crate::state_engine) async fn charge_failure_fee_and_commit(
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
    pub(in crate::state_engine) async fn commit_native_with_floor(
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
    pub(in crate::state_engine) async fn commit_native_with_floor_at(
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
        self.commit_native_with_floor_at_opts(
            tx,
            gas_used,
            transfers,
            payouts,
            burns,
            floor_base,
            surcharge,
            sender_vesting_floor,
            vesting_floors,
            chain_height,
            true,
        )
        .await
    }

    /// Block-path / configurable variant of [`Self::commit_native_with_floor_at`]
    /// allowing the block apply loop to defer `pq_tree.flush()` (`fsync`) once
    /// per block instead of flushing per PQ-activation transaction.
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    // GATE: mirrors commit_native_with_floor_at with flush_pq flag for end-of-block batch flush.
    pub(in crate::state_engine) async fn commit_native_with_floor_at_opts(
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
        flush_pq: bool,
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
        let fee_market_v2 = crate::tokenomics::fee_market_v2_active_at(chain_height);
        let fee_with_surcharge = Self::fee_for_gas_at_v2(
            tx,
            gas_used,
            floor_base,
            surcharge,
            exec_hardening,
            fee_market_v2,
        );
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
        let total_cost = charge;

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
                        let pin_res = if flush_pq {
                            self.pin_pubkey(tx.from, env.scheme, pk, &salt).await
                        } else {
                            self.pin_pubkey_no_flush(tx.from, env.scheme, pk, &salt)
                                .await
                        };
                        if let Err(e) = pin_res {
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
    pub(in crate::state_engine) async fn commit_native(
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
    pub(in crate::state_engine) async fn commit_native_at(
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
}
