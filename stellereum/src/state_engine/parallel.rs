use super::types::{write_contract_trie_entries, PayloadDomainSnapshot};
use super::verify_once::verify_block_tx_signatures_at_height;
use super::{AccountState, ExecPostActions, InMemoryStateEngine, PQ_ACTIVATION_SURCHARGE_GAS};
use rayon::iter::ParallelIterator;
use rayon::slice::ParallelSlice;
use std::collections::{HashMap, HashSet};

/// Minimum number of transactions a wave must carry before the CONCURRENT
/// path (optimistic snapshot -> parallel plan on the rayon pool ->
/// compare-and-swap merge) is used.
///
/// Handing a wave to the thread pool costs tens of microseconds (the worker
/// threads are parked between waves and have to be woken), while planning
/// ONE plain transaction costs about a hundred nanoseconds. Below this
/// size the dispatch would dominate the work it parallelises, so a smaller
/// wave is applied under a SINGLE accounts write lock instead - the same
/// planner, the same result, without the dispatch overhead.
///
/// This is a PURE performance switch: both paths compute the same plans
/// from the same values and write the same final state, so the wave's
/// result never depends on which path ran.
const PARALLEL_WAVE_MIN_TX: usize = 32;

/// Granularity of the concurrent plan phase: the wave is split into
/// `par_chunks` of this many transactions, one rayon task per chunk.
///
/// Planning ONE plain transaction costs about a hundred nanoseconds, so
/// handing the pool one task per transaction would spend more time waking
/// workers and stealing work than planning. Chunking amortises the dispatch
/// over `PARALLEL_PLAN_CHUNK` plans per task. Overridable per process via
/// `STELL_PARALLEL_PLAN_CHUNK` (positive integer; unset/invalid falls back
/// to the default) so the speedup bench can sweep it in one binary.
///
/// This is a PURE performance switch like `PARALLEL_WAVE_MIN_TX`: chunking
/// only changes how the same pure `plan_plain_tx` calls are grouped into
/// tasks. The collect is order-preserving, so the plans - and the merged
/// final state - are byte-identical for every chunk size.
const PARALLEL_PLAN_CHUNK: usize = 128;

/// Effective plan chunk for one wave: the configured chunk, capped so a
/// wave always splits into at least four chunks (a wave smaller than the
/// chunk must still spread over workers instead of collapsing to one task).
fn parallel_plan_chunk() -> usize {
    std::env::var("STELL_PARALLEL_PLAN_CHUNK")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(PARALLEL_PLAN_CHUNK)
}

/// The plan of ONE plain (payload-free) transaction, computed from a
/// CONSISTENT snapshot of the accounts map.
///
/// A plan is a PURE function of the snapshot and of the transaction's own
/// immutable fields (amount, gas limit, nonce, delegation, shard). It can
/// therefore be computed on any worker thread, in any order, and two runs
/// over the same snapshot produce byte-identical plans - that is what makes
/// the final state of a wave independent of the intra-wave execution order.
///
/// The writes are ABSOLUTE final values (not deltas), so the apply phase is
/// a conflict-free merge instead of a read-modify-write: the scheduler
/// guarantees that the accounts of two transactions in one wave are
/// disjoint.
#[derive(Clone, Debug, Default)]
struct PlainTxPlan {
    /// The transaction applied (value moved, nonce consumed).
    applied: bool,
    /// Amount actually debited from the sender (0 when nothing was charged).
    fee: u64,
    /// Final `(address, balance, nonce)` of every account the transaction
    /// touched, in application order.
    writes: Vec<([u8; 32], u64, u64)>,
}

/// F-01 failure fee: the sender's post-fee state and the amount debited, or
/// `None` when the failure is NOT attributable (missing sender or nonce
/// mismatch). The exact contract of `apply_failure_fee_to_map`, so a
/// planned failure and an executed failure charge the same.
///
/// THE CONTRACT:
/// * a REPLAY or a GAP (the nonce does not match) is not attributable: no
///   pay, no state change at all;
/// * an attributable failure the sender CAN cover: the fee is debited and
///   the nonce is consumed (the failure is not free to replay);
/// * an attributable failure the sender CANNOT cover: NOTHING moves - no
///   fee, no nonce, no state change at all.
///
/// THE LAST CASE IS THE GRIEF RULE (audit W6.6). A partial charge ("pay what
/// you can") would consume the sender's remaining DUST for a transaction
/// they could not have known would fail - and it would do so for FREE of
/// any consideration, because a transaction whose fee they cannot cover was
/// never going to run. "No pay, no state change" is the atomic rule the rest
/// of the engine already uses, and it is what keeps the failed path from
/// being a griefing surface: a burned nonce on a failure the sender could
/// not have prevented is a way to make their NEXT transaction impossible.
fn failure_fee_state(
    tx: &crate::sharding::Transaction,
    sender: Option<(u64, u64)>,
    fee: u64,
) -> Option<(u64, u64, u64)> {
    let (balance, nonce) = sender?;
    if tx.nonce != nonce {
        // A replay or a gap is not attributable: no pay, no state change.
        return None;
    }
    if fee == 0 || balance < fee {
        // Nothing to charge (no floor, no declared gas) or the sender cannot
        // cover the fee: no pay, no state change. The failure is still
        // RECORDED by the D2 mirror (the status flag), which is what prices
        // the sender's next attempt.
        return None;
    }
    Some((fee, balance - fee, nonce + 1))
}

/// Plans ONE plain transaction against a snapshot of the accounts map.
///
/// The decisions mirror the sequential block path (`commit_native`) one for
/// one - the same admission, session-gate, floor, affordability, vesting and
/// overflow rules - so a wave applied through these plans leaves the SAME
/// state as the sequential path. The only difference is WHEN the values are
/// read: a consistent snapshot of the whole wave instead of the live map.
#[allow(clippy::too_many_arguments)]
// GATE: plan mirrors sequential admission parameters; splitting would risk divergence.
fn plan_plain_tx(
    tx: &crate::sharding::Transaction,
    admitted: bool,
    session_ok: bool,
    sender: Option<(u64, u64)>,
    recipient: Option<(u64, u64)>,
    floor_base: u64,
    surcharge: u64,
    vesting_locked: Option<u64>,
    cross_shard: bool,
    sponsor: Option<(u64, u64)>,
    exec_hardening: bool,
) -> PlainTxPlan {
    let mut plan = PlainTxPlan::default();

    if !admitted {
        // Refused at ADMISSION: it never ran, so it pays nothing and
        // consumes no nonce.
        return plan;
    }

    // FEE-01: a plain (empty-payload) transaction runs no VM, so execution
    // measured 0 gas; `billed_gas(tx, 0)` adds the INTRINSIC envelope cost and
    // caps it at the declaration — never the declaration itself (charging it
    // in full was the over-charge FEE-01 closes). F-01: the consensus floor
    // still raises the result. Both numbers come from the engine's helpers, so
    // they cannot drift from `commit_native`'s.
    let fee = InMemoryStateEngine::fee_for_gas_at(tx, 0, floor_base, 0, exec_hardening);
    // The failure price is `failure_fee_for` (the intrinsic envelope is
    // guaranteed consumption whether or not a payload ran); for a plain
    // transfer the two coincide, and the debug assertion pins that.
    let fail_fee = InMemoryStateEngine::failure_fee_for(tx, floor_base, surcharge);
    debug_assert_eq!(fail_fee, fee.saturating_add(surcharge));

    // A live session-gate refusal is attributable: the floor is charged and
    // the nonce is consumed (the sequential path's `fail_with_floor!`).
    if tx.delegation().is_some() && !session_ok {
        if let Some((debited, balance, nonce)) = failure_fee_state(tx, sender, fail_fee) {
            plan.fee = debited;
            plan.writes.push((tx.from, balance, nonce));
        }
        return plan;
    }

    // PAYMASTER v1: split-leg planning. The fee debits the SPONSOR, the
    // USER's nonce advances; the user pays VALUE only. The same contract
    // as `failure_fee_state`, with the legs split:
    // * success (user nonce matches, user covers `amount`, sponsor covers
    //   the fee): value moves, fee moves, user nonce advances;
    // * attributable failure the sponsor CAN cover (user nonce matches):
    //   the sponsor pays the fee and the user nonce advances (a sponsored
    //   failure is not free to replay);
    // * anything the sponsor cannot cover (missing sponsor, uncovered fee)
    //   moves NOTHING — the grief rule on the fee-payer leg.
    //
    // The expiry/allowlist/cap POLICY was enforced at admission against the
    // block timestamp (same clock this wave executes under); the planner
    // enforces funding split + nonce, like the legacy planner below.
    if let Some(auth) = tx.sponsored_grant() {
        let (Some((ubal, unonce)), Some((sbal, snonce))) = (sender, sponsor) else {
            return plan;
        };
        if tx.nonce != unonce {
            return plan;
        }
        // Success needs BOTH legs funded.
        if ubal < tx.amount || sbal < fail_fee {
            // Attributable failure the sponsor can cover: sponsor pays the
            // fee, user nonce advances. A zero fee — or one the sponsor
            // cannot cover — moves NOTHING (the grief rule on the
            // fee-payer leg).
            if fail_fee > 0 && sbal >= fail_fee {
                plan.fee = fail_fee;
                plan.writes.push((tx.from, ubal, unonce + 1));
                plan.writes.push((auth.sponsor, sbal - fail_fee, snonce));
            }
            return plan;
        }
        // Team-vesting claim gate on the user's post-value balance (the fee
        // is the sponsor's, so it never counts against the user's lock).
        if let Some(locked) = vesting_locked {
            if ubal.saturating_sub(tx.amount) < locked {
                tracing::warn!(
                    "VESTING-LOCK REFUSED team vesting lock: sender {} balance {} would fall below locked {locked}",
                    hex::encode(tx.from),
                    ubal,
                );
                if fail_fee > 0 && sbal >= fail_fee {
                    plan.fee = fail_fee;
                    plan.writes.push((tx.from, ubal, unonce + 1));
                    plan.writes.push((auth.sponsor, sbal - fail_fee, snonce));
                }
                return plan;
            }
        }
        plan.applied = true;
        plan.fee = fail_fee;
        if tx.from == tx.to {
            // A self-transfer only pays the fee (from the sponsor): the
            // value goes straight back, the user nonce still advances.
            plan.writes.push((tx.from, ubal, unonce + 1));
            plan.writes.push((auth.sponsor, sbal - fail_fee, snonce));
            return plan;
        }
        plan.writes
            .push((tx.from, ubal.saturating_sub(tx.amount), unonce + 1));
        if !cross_shard && auth.sponsor == tx.to {
            // The sponsor IS the recipient (`sponsored_grant()` only excludes
            // `sponsor == from`, so a third-party sponsor can name itself as
            // the payee). The sequential path debits the sponsor's fee FIRST
            // and credits the amount AFTERWARDS, so the final balance is
            // `(sbal - fail_fee) + tx.amount`. Emit ONE absolute write for
            // the sponsor: a separate recipient write would overwrite the fee
            // debit (last write wins in `commit_plain_plan`) and mint the fee.
            match (sbal - fail_fee).checked_add(tx.amount) {
                Some(final_balance) => plan.writes.push((tx.to, final_balance, snonce)),
                None => {
                    // The credit would overflow: the failure-fee path
                    // (sponsor pays, user nonce advances) - same shape as
                    // the recipient-overflow arm below.
                    plan.applied = false;
                    plan.fee = 0;
                    plan.writes.clear();
                    if fail_fee > 0 && sbal >= fail_fee {
                        plan.fee = fail_fee;
                        plan.writes.push((tx.from, ubal, unonce + 1));
                        plan.writes.push((auth.sponsor, sbal - fail_fee, snonce));
                    }
                }
            }
            return plan;
        }
        plan.writes.push((auth.sponsor, sbal - fail_fee, snonce));
        if !cross_shard {
            match recipient {
                Some((rbalance, rnonce)) => match rbalance.checked_add(tx.amount) {
                    Some(new_balance) => plan.writes.push((tx.to, new_balance, rnonce)),
                    None => {
                        // The credit would overflow: the failure-fee path
                        // (sponsor pays, user nonce advances).
                        plan.applied = false;
                        plan.fee = 0;
                        plan.writes.clear();
                        if fail_fee > 0 && sbal >= fail_fee {
                            plan.fee = fail_fee;
                            plan.writes.push((tx.from, ubal, unonce + 1));
                            plan.writes.push((auth.sponsor, sbal - fail_fee, snonce));
                        }
                    }
                },
                None => {
                    plan.writes.push((tx.to, tx.amount, 0));
                }
            }
        }
        return plan;
    }

    let Some(total_cost) = tx.amount.checked_add(fee) else {
        // Overflow: the amount plus the fee does not fit. Unreachable in
        // practice (admission reserves the same sum) and refused without a
        // charge, exactly like the sequential path's arithmetic refusal.
        return plan;
    };

    let Some((balance, nonce)) = sender else {
        // No sender account: nothing to charge (`apply_failure_fee_to_map`
        // is a no-op without a sender).
        return plan;
    };

    if tx.nonce != nonce || balance < total_cost {
        // A nonce mismatch pays nothing; an unaffordable transaction pays
        // the floor (capped at the balance) and consumes the nonce.
        if let Some((debited, balance, nonce)) = failure_fee_state(tx, sender, fail_fee) {
            plan.fee = debited;
            plan.writes.push((tx.from, balance, nonce));
        }
        return plan;
    }

    // Team-vesting claim gate: a tracked sender may not be left below its
    // locked floor. Fail-closed, exactly like the sequential path. A
    // self-transfer only debits the fee (the amount returns to self), so it
    // is checked against the fee alone.
    if let Some(locked) = vesting_locked {
        let vesting_debit = if tx.from == tx.to { fee } else { total_cost };
        if balance.saturating_sub(vesting_debit) < locked {
            tracing::warn!(
                "VESTING-LOCK REFUSED team vesting lock: sender {} balance {} would fall below locked {locked}",
                hex::encode(tx.from),
                balance,
            );
            if let Some((debited, balance, nonce)) = failure_fee_state(tx, sender, fail_fee) {
                plan.fee = debited;
                plan.writes.push((tx.from, balance, nonce));
            }
            return plan;
        }
    }

    plan.applied = true;
    plan.fee = fee;

    if tx.from == tx.to {
        // A self-transfer only pays the fee: the amount goes straight back.
        plan.writes
            .push((tx.from, balance.saturating_sub(fee), nonce + 1));
        return plan;
    }

    plan.writes
        .push((tx.from, balance.saturating_sub(total_cost), nonce + 1));

    if !cross_shard {
        match recipient {
            Some((rbalance, rnonce)) => match rbalance.checked_add(tx.amount) {
                Some(new_balance) => plan.writes.push((tx.to, new_balance, rnonce)),
                None => {
                    // The credit would overflow: the sender is refunded and
                    // the floor is charged (the sequential path rolls the
                    // commit back and charges the same floor).
                    plan.applied = false;
                    plan.fee = 0;
                    plan.writes.clear();
                    if let Some((debited, balance, nonce)) = failure_fee_state(tx, sender, fail_fee)
                    {
                        plan.fee = debited;
                        plan.writes.push((tx.from, balance, nonce));
                    }
                }
            },
            None => {
                // The recipient does not exist yet: it is created with the
                // transferred amount (nonce 0).
                plan.writes.push((tx.to, tx.amount, 0));
            }
        }
    }
    plan
}

/// Applies ONE plan to the accounts map and files its outcome (counters,
/// status flag, fee and trie entries).
#[allow(clippy::too_many_arguments)]
fn commit_plain_plan(
    map: &mut HashMap<[u8; 32], AccountState>,
    plan: &PlainTxPlan,
    idx: usize,
    applied: &mut usize,
    failed: &mut usize,
    fees_collected: &mut u64,
    status: &mut [bool],
    fees: &mut [u64],
    trie_dirty: &mut Vec<([u8; 32], u64, u64)>,
) {
    for (addr, balance, nonce) in &plan.writes {
        match map.get_mut(addr) {
            Some(acc) => {
                acc.balance = *balance;
                acc.nonce = *nonce;
            }
            None => {
                let mut acc = AccountState::new(*addr, *balance);
                acc.nonce = *nonce;
                map.insert(*addr, acc);
            }
        }
    }
    if plan.applied {
        *applied += 1;
        status[idx] = true;
    } else {
        *failed += 1;
    }
    fees[idx] = plan.fee;
    *fees_collected = fees_collected.saturating_add(plan.fee);
    // Trie: the FINAL value of every account this transaction touched.
    // Absolute values, so the last write per account is the account's final
    // state - the same rule the sequential path relies on.
    for (addr, balance, nonce) in &plan.writes {
        trie_dirty.push((*addr, *balance, *nonce));
    }
}

impl InMemoryStateEngine {
    /// Apply a whole block's transactions with **batched signature verification**
    /// and grouped execution (see `apply_block_parallel_fees`).
    ///
    /// Returns (applied, failed).
    pub async fn apply_block_parallel(
        &self,
        txs: &[crate::sharding::Transaction],
        timestamp: u64,
    ) -> (usize, usize) {
        let (applied, failed, _fees, _status, _tx_fees) =
            self.apply_block_parallel_fees(txs, timestamp).await;
        (applied, failed)
    }

    /// Applies ONE all-plain wave of the block path, CONCURRENTLY.
    ///
    /// This is the optimistic (compare-and-swap) execution pattern:
    ///
    ///  (a) SNAPSHOT - the accounts the wave touches are READ under a read
    ///      lock and their values are snapshotted. The snapshot is taken in
    ///      ONE lock acquisition, so every transaction of the wave sees the
    ///      same pre-state.
    ///  (b) PLAN - every transaction of the wave is planned IN PARALLEL on
    ///      the rayon pool from that snapshot. A plan is a pure function of
    ///      the snapshot and of the transaction itself, so the intra-wave
    ///      execution order CANNOT change the outcome: this is what keeps
    ///      the wave's final state deterministic.
    ///  (c) APPLY - the plans are merged under the accounts write lock.
    ///      The scheduler guarantees that the accounts of two transactions
    ///      in one wave are DISJOINT, so the merge is conflict-free: the
    ///      write lock is held for a pure map merge, not for the per
    ///      transaction work. A compare-and-swap check (the snapshotted
    ///      value must still be the live value) aborts the wave if a value
    ///      changed underneath; the wave is then RE-RUN SEQUENTIALLY, one
    ///      transaction at a time against the live map, exactly like the
    ///      sequential block path.
    ///
    /// The values written are the plan's ABSOLUTE final values, so the trie
    /// entries are the accounts' final state no matter in which order the
    /// wave's transactions ran.
    #[allow(clippy::too_many_arguments)]
    async fn apply_plain_wave(
        &self,
        txs: &[crate::sharding::Transaction],
        wave: &[usize],
        admitted: &[bool],
        session_valid: Option<&HashMap<usize, bool>>,
        fee_floors: &[(u64, u64)],
        vesting_floors: &HashMap<[u8; 32], u64>,
        exec_hardening: bool,
        applied: &mut usize,
        failed: &mut usize,
        fees_collected: &mut u64,
        status: &mut [bool],
        fees: &mut [u64],
        trie_dirty: &mut Vec<([u8; 32], u64, u64)>,
    ) {
        // (a) SNAPSHOT.
        //
        // The concurrent path pays a thread-pool dispatch per wave, so it is
        // used from `PARALLEL_WAVE_MIN_TX` transactions up; a smaller wave
        // is applied under a single accounts write lock (the same planner,
        // the same result, without the dispatch).
        let mut applied_concurrently = false;
        // The session spends are filed AFTER the accounts lock is dropped
        // (the registry has its own lock), and the cross-shard flag is
        // node-local - both are needed by either path.
        let burn_for_cross_shard = self.cross_shard_enabled();
        let mut session_notes: Vec<(&crate::sharding::Transaction, u64)> = Vec::new();
        if wave.len() >= PARALLEL_WAVE_MIN_TX {
            let snapshot: HashMap<[u8; 32], Option<(u64, u64)>> = {
                let map = self.accounts.read().await;
                let mut snap: HashMap<[u8; 32], Option<(u64, u64)>> =
                    HashMap::with_capacity(wave.len() * 2);
                for &i in wave {
                    let tx = &txs[i];
                    for addr in [tx.from, tx.to] {
                        snap.entry(addr)
                            .or_insert_with(|| map.get(&addr).map(|a| (a.balance, a.nonce)));
                    }
                    // PAYMASTER v1: the wave also mutates the sponsor
                    // account (the fee leg), so it joins the snapshot —
                    // and the compare-and-swap check below covers it, so a
                    // sponsor balance that moved underneath aborts the wave
                    // into the sequential path instead of double-spending.
                    if let Some(sponsor) = tx.effective_sponsor() {
                        snap.entry(sponsor)
                            .or_insert_with(|| map.get(&sponsor).map(|a| (a.balance, a.nonce)));
                    }
                }
                snap
            };

            // (b) PLAN - in parallel, on the rayon pool, in chunks of
            // `parallel_plan_chunk()` transactions per task. The collect is
            // order-preserving, so the chunking never changes the plans.
            let chunk = parallel_plan_chunk().min(wave.len().div_ceil(4).max(1));
            let plans: Vec<(usize, PlainTxPlan)> = wave
                .par_chunks(chunk)
                .flat_map(|c| {
                    c.iter()
                        .map(|&i| {
                            let tx = &txs[i];
                            let (floor_base, surcharge) = fee_floors[i];
                            let session_ok = session_valid
                                .map(|sv| sv.get(&i).copied().unwrap_or(false))
                                .unwrap_or(true);
                            let plan = plan_plain_tx(
                                tx,
                                admitted[i],
                                session_ok,
                                snapshot.get(&tx.from).copied().flatten(),
                                snapshot.get(&tx.to).copied().flatten(),
                                floor_base,
                                surcharge,
                                vesting_floors.get(&tx.from).copied(),
                                burn_for_cross_shard && tx.source_shard != tx.target_shard,
                                tx.effective_sponsor()
                                    .and_then(|s| snapshot.get(&s).copied().flatten()),
                                exec_hardening,
                            );
                            (i, plan)
                        })
                        .collect::<Vec<_>>()
                })
                .collect();

            // (c) APPLY - conflict-free merge under the write lock, guarded by
            // the compare-and-swap check.
            let mut cas_ok = true;
            {
                let mut map = self.accounts.write().await;
                for (addr, snap) in &snapshot {
                    let live = map.get(addr).map(|a| (a.balance, a.nonce));
                    if live != *snap {
                        cas_ok = false;
                        break;
                    }
                }
                if cas_ok {
                    applied_concurrently = true;
                    for (i, plan) in &plans {
                        commit_plain_plan(
                            &mut map,
                            plan,
                            *i,
                            applied,
                            failed,
                            fees_collected,
                            status,
                            fees,
                            trie_dirty,
                        );
                        if plan.applied && txs[*i].delegation().is_some() {
                            // Session budget follows the BILLED gas (FEE-01:
                            // intrinsic envelope capped at the declaration),
                            // not the floored money fee and not the declared
                            // limit: the sequential path records
                            // `billed_gas(tx, gas_used)` and the two paths
                            // must agree on the committed registry spend for
                            // the same block.
                            session_notes.push((
                                &txs[*i],
                                InMemoryStateEngine::billed_gas_at(&txs[*i], 0, exec_hardening),
                            ));
                        }
                    }
                }
            }
        }

        if !applied_concurrently {
            // Either the wave is too small to pay for a pool dispatch, or it
            // lost the race against another writer (the compare-and-swap
            // check failed): apply it SEQUENTIALLY, one transaction at a
            // time against the live map (the sequential block path's
            // semantics, bit for bit).
            tracing::debug!(
                wave = wave.len(),
                "wave applied sequentially (small wave or compare-and-swap failure)"
            );
            let mut map = self.accounts.write().await;
            for &i in wave {
                let tx = &txs[i];
                let (floor_base, surcharge) = fee_floors[i];
                let session_ok = session_valid
                    .map(|sv| sv.get(&i).copied().unwrap_or(false))
                    .unwrap_or(true);
                let sponsor = tx
                    .effective_sponsor()
                    .and_then(|s| map.get(&s).map(|a| (a.balance, a.nonce)));
                let plan = plan_plain_tx(
                    tx,
                    admitted[i],
                    session_ok,
                    map.get(&tx.from).map(|a| (a.balance, a.nonce)),
                    map.get(&tx.to).map(|a| (a.balance, a.nonce)),
                    floor_base,
                    surcharge,
                    vesting_floors.get(&tx.from).copied(),
                    burn_for_cross_shard && tx.source_shard != tx.target_shard,
                    sponsor,
                    exec_hardening,
                );
                commit_plain_plan(
                    &mut map,
                    &plan,
                    i,
                    applied,
                    failed,
                    fees_collected,
                    status,
                    fees,
                    trie_dirty,
                );
                if plan.applied && tx.delegation().is_some() {
                    session_notes.push((
                        tx,
                        InMemoryStateEngine::billed_gas_at(tx, 0, exec_hardening),
                    ));
                }
            }
        }

        for (tx, gas) in session_notes {
            self.session_note_applied(tx, gas).await;
        }
    }

    /// Apply a block's transactions, returning per-transaction success flags for
    /// receipts alongside the aggregate counters.
    ///
    /// The fifth element is the per-transaction fee actually charged, in block
    /// order (parallel to the flags): what `commit_native` debited on success
    /// (never below the F-01 consensus floor), or the F-01 failure fee on an
    /// attributable execution failure (the floor WHEN THE SENDER CAN COVER
    /// IT - a failure whose fee they cannot pay for moves nothing at all, and
    /// a replay or a gap moves nothing either; see
    /// `apply_failure_fee_to_map`). Receipts file these numbers, so every
    /// fee shown was actually debited from the sender and credited (via
    /// `fees_collected`) to the proposer: value is conserved, failures
    /// included.
    ///
    /// This is THE live consensus path: `ValidatorRuntime::try_finalize`,
    /// `apply_and_advance` and `replay_historical_block` all reach it through
    /// `apply_block_fees_rewards` -> `apply_block_transition`, and so does the
    /// reorg path (`ChainState::apply_block`). Its per-transaction semantics
    /// come from `commit_native` + `execute_payload`, the same code
    /// `apply_transaction` uses, so a block and the sequential path cannot
    /// disagree about what a transaction moved OR about what it cost (FEE-01:
    /// both charge `min(gas_limit, gas_used + intrinsic)`, floored, plus the
    /// additive surcharge — see `commit_native`).
    ///
    /// `timestamp` is `block.timestamp`, which the VM reads as "now" for
    /// unbonding maturity, contract creation, order stamps and session-key gas
    /// authorisation. Passing `0` here would make every node agree on the WRONG
    /// value, which is why it is a parameter and not a local default.
    ///
    /// The flags are recorded at the exact commit point. They must NOT be
    /// recomputed after the fact: once a transaction is applied the sender's
    /// nonce has moved on, so a post-hoc replay would mark it as failed.
    pub async fn apply_block_parallel_fees(
        &self,
        txs: &[crate::sharding::Transaction],
        timestamp: u64,
    ) -> (usize, usize, u64, Vec<bool>, Vec<u64>) {
        // No block context on the legacy path: assume post-activation when
        // armed (fail-closed); default-off is byte-identical at every height.
        self.apply_block_parallel_fees_at_height(txs, timestamp, u64::MAX)
            .await
    }

    /// [`Self::apply_block_parallel_fees`] at an explicit chain height (A14
    /// phase 3: the admission pass below refuses unbound envelopes at/after
    /// the configured activation height).
    ///
    /// GATE: `chain_height` MUST be the COMMITTED block height — never a
    /// caller-supplied value. [`Self::apply_block_transition`] passes
    /// `block.height`.
    pub async fn apply_block_parallel_fees_at_height(
        &self,
        txs: &[crate::sharding::Transaction],
        timestamp: u64,
        chain_height: u64,
    ) -> (usize, usize, u64, Vec<bool>, Vec<u64>) {
        let (applied, failed, fees, status, tx_fees, _events) = self
            .apply_block_parallel_fees_with_events_at_height(txs, timestamp, chain_height)
            .await;
        (applied, failed, fees, status, tx_fees)
    }

    pub async fn apply_block_parallel_fees_with_events(
        &self,
        txs: &[crate::sharding::Transaction],
        timestamp: u64,
    ) -> (
        usize,
        usize,
        u64,
        Vec<bool>,
        Vec<u64>,
        Vec<Vec<crate::contract::ContractEvent>>,
    ) {
        // No block context on the legacy path: assume post-activation when
        // armed (fail-closed); default-off is byte-identical at every height.
        self.apply_block_parallel_fees_with_events_at_height(txs, timestamp, u64::MAX)
            .await
    }

    /// [`Self::apply_block_parallel_fees_with_events`] at an explicit chain
    /// height (A14 phase 3).
    ///
    /// GATE: `chain_height` MUST be the COMMITTED block height — never a
    /// caller-supplied value. [`Self::apply_block_transition`] passes
    /// `block.height`.
    pub async fn apply_block_parallel_fees_with_events_at_height(
        &self,
        txs: &[crate::sharding::Transaction],
        timestamp: u64,
        chain_height: u64,
    ) -> (
        usize,
        usize,
        u64,
        Vec<bool>,
        Vec<u64>,
        Vec<Vec<crate::contract::ContractEvent>>,
    ) {
        if txs.is_empty() {
            return (0, 0, 0, Vec::new(), Vec::new(), Vec::new());
        }
        for tx in txs {
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
        }
        // 1) Batched signature verification (parallel across cores for big blocks).
        // Verify-once (PERF_PROFILE §6.1): transactions attested at mempool
        // admission with byte-identical content AND identical chain context
        // skip crypto here; every other transaction is batch-verified exactly
        // as before. Fail-closed: any attestation mismatch forces full
        // re-verification. Chain-id/binding/session/nonce/balance checks below
        // still run for EVERY transaction, attested or not.
        let exec_hardening = crate::chain_spec::exec_hardening_v1_active_at(chain_height);
        let sig_valid = verify_block_tx_signatures_at_height(txs, self.chain_id, chain_height);

        // 2) Group transaction indices by sender, preserving order.
        let mut order: Vec<[u8; 32]> = Vec::new();
        let mut groups: HashMap<[u8; 32], Vec<usize>> = HashMap::new();
        for (i, tx) in txs.iter().enumerate() {
            groups
                .entry(tx.from)
                .or_insert_with(|| {
                    order.push(tx.from);
                    Vec::new()
                })
                .push(i);
        }

        // 3) Pre-validate ADMISSION in deterministic order: signature,
        //    session-key delegation policy, per-sender nonce sequence and
        //    balance. This is CRITICAL: SVM payloads mutate shared
        //    token/orderbook state, so a transaction that will be rejected
        //    (bad nonce / insufficient balance / bad signature / expired,
        //    out-of-scope or over-budget session grant) must NOT have its
        //    payload executed. Otherwise an unfunded or replayed tx could
        //    still move tokens or place orders while being reported as failed.
        //
        //    The delegation check runs against `timestamp` = block.timestamp
        //    (never wall clock) and covers EMPTY-payload transactions too — a
        //    plain session transfer would otherwise skip the VM and its
        //    session hook entirely. It is the same predicate the proposer
        //    filter uses, so propose and apply agree.
        //
        //    PHASE 2: the stateless grant policy is joined by the on-chain
        //    REGISTRY check - terminal revocation, the registered record's
        //    ceilings and its cumulative spend - carried in `session_sim`, the
        //    gas THIS block has already committed to each grant. The overlay
        //    matters here because the real deduction only lands when a
        //    transaction applies, which happens later, in step 4: without it,
        //    three transactions of one two-transaction budget would all pass
        //    admission and only the third would fail at execution.
        //
        //    F-01 floor inputs, loaded once per block (no awaits per
        //    transaction while the guards below are held): the governed base
        //    + this engine's D2 penalty snapshot. Same formula as admission
        //    (`Mempool::effective_floor_for_tx`); see `consensus_floor_parts`.
        //    The block path consumes them through the `fee_floors` batch
        //    below (bit-identical: the mirror is only updated at the end of
        //    this function, never mid-block); only `commit_native` — the
        //    single-transaction path — re-reads the live map.
        let governed_base: u64 = self
            .governance_read()
            .await
            .applied
            .min_gas_limit
            .unwrap_or(0);
        let penalties: HashMap<[u8; 32], u64> = self.consensus_penalty.read().await.clone();
        // Team-vesting locked floors at the block timestamp, snapshotted once
        // per block (same shape as the penalty snapshot above): the parallel
        // PLAIN fast path below bypasses `commit_native`, so it enforces the
        // same gate inline from this snapshot. Empty on every live chain
        // today (no vested allocations exist) → collecting it is a no-op.
        let vesting_floors: HashMap<[u8; 32], u64> = {
            let ledger = self.staking.read().await;
            ledger
                .vesting_schedules
                .iter()
                .map(|(acct, sched)| (*acct, sched.locked_amount(timestamp)))
                .collect()
        };
        // FEE-PATH BATCH (execution 9.0): the per-transaction fee-floor
        // inputs, computed ONCE per block from the snapshot above.
        // `floor_parts_for` is pure in `(governed_base, penalties, tx)`, so
        // these are bit-identical to the per-transaction evaluations they
        // replace (admission, prechecks, `fail_with_floor!`,
        // `apply_plain_wave`, and — via `commit_native_with_floor` — the
        // commit fee prefix, which additionally skips three per-transaction
        // lock acquisitions whose live reads equal this snapshot: the
        // penalty mirror is only folded at the end of this function, the
        // governed base has no in-block writer, and `vesting_schedules`
        // has none either).
        let fee_floors: Vec<(u64, u64)> = txs
            .iter()
            .map(|tx| Self::floor_parts_for(governed_base, &penalties, tx))
            .collect();
        let mut admitted = vec![false; txs.len()];
        // A14 phase 3 (chain binding): read once per block — every
        // transaction of this block is judged against the same activation.
        // GATE: judged at `chain_height`, the COMMITTED block height passed
        // down from [`Self::apply_block_transition`] (`block.height`) — never
        // a caller-supplied value. Default-off (env unset) passes everything.
        let binding_activation = crate::chain_binding::ChainBindingActivation::from_chain_spec();
        {
            let map = self.accounts.read().await;
            // Held for the whole pass (it is read-only) so the loop stays
            // synchronous: no awaits while both guards are held.
            let session_reg = self.session_keys.read().await;
            let mut session_sim = crate::zkml::SessionSpendSim::default();
            // PAYMASTER v1: the sponsor's simulated balance. The user's
            // per-sender simulation above (`balance`) covers VALUE only; the
            // fee leg draws from THIS map, seeded from the committed state on
            // first use and decremented as the block's sponsored transactions
            // are admitted — so one sponsor funding backs exactly the
            // sponsored slots it can jointly pay for (no double-spend of the
            // sponsor across the block). A sponsor missing from committed
            // state admits nothing (the transaction never ran: no fee, no
            // nonce — the same shape as a missing sender).
            let mut sponsor_sim: HashMap<[u8; 32], u64> = HashMap::new();
            for addr in &order {
                let Some(sender) = map.get(addr) else {
                    continue;
                };
                let mut nonce = sender.nonce;
                let mut balance = sender.balance;
                for &i in &groups[addr] {
                    let tx = &txs[i];
                    if !sig_valid[i] {
                        continue;
                    }
                    if let Some(cid) = tx.chain_id() {
                        if cid != self.chain_id {
                            continue;
                        }
                    }
                    // A14 phase 3 (chain binding, last line of defense): an
                    // unbound envelope still pooled pre-activation (or
                    // smuggled past ingress) is NOT admitted at/after the
                    // activation height. Admission-stage, exactly like the
                    // neighbouring chain-id/signature/nonce refusals: plain
                    // `failed += 1` downstream — no fee, no nonce, nothing
                    // moves (see the `fail_with_floor!` comment and the
                    // failure-fee contract).
                    if crate::chain_binding::check_admission(
                        tx.chain_id().is_some(),
                        chain_height,
                        &binding_activation,
                        self.chain_id,
                    )
                    .is_err()
                    {
                        continue;
                    }
                    if tx.check_session_policy(timestamp).is_err() {
                        continue;
                    }
                    if let Some(d) = tx.delegation() {
                        // One definition (including the actor-mailbox scope),
                        // shared with the policy check above and the gate at
                        // execution - see `Transaction::required_scope`.
                        let required_scope = tx.required_scope();
                        if session_reg
                            .check(
                                &d,
                                tx.amount,
                                tx.gas_limit,
                                required_scope,
                                timestamp,
                                &mut session_sim,
                            )
                            .is_err()
                        {
                            continue;
                        }
                    }
                    // PAYMASTER v1: split-leg admission. The grant's policy
                    // (expiry / allowlist / per-tx cap against the fee
                    // execution will charge) is enforced at the BLOCK
                    // timestamp, and both legs must fit their funder's
                    // simulated balance. The user's nonce advances; the
                    // sponsor's never does.
                    if let Some(auth) = tx.sponsored_grant() {
                        let (floor_base, surcharge) = fee_floors[i];
                        let fee_reserved = tx.gas_limit.max(floor_base);
                        let Some(fee_total) = fee_reserved.checked_add(surcharge) else {
                            continue;
                        };
                        if tx.check_sponsor_policy(timestamp, fee_total).is_err() {
                            continue;
                        }
                        if tx.nonce != nonce {
                            continue;
                        }
                        if balance < tx.amount {
                            continue;
                        }
                        if let std::collections::hash_map::Entry::Vacant(e) =
                            sponsor_sim.entry(auth.sponsor)
                        {
                            let Some(sponsor_acc) = map.get(&auth.sponsor) else {
                                continue;
                            };
                            e.insert(sponsor_acc.balance);
                        }
                        let sponsor_balance = sponsor_sim[&auth.sponsor];
                        if sponsor_balance < fee_total {
                            continue;
                        }
                        sponsor_sim.insert(auth.sponsor, sponsor_balance.saturating_sub(fee_total));
                        admitted[i] = true;
                        nonce += 1;
                        balance = balance.saturating_sub(tx.amount);
                        continue;
                    }
                    if tx.nonce != nonce {
                        continue;
                    }
                    // F-01: reserve what execution will actually charge —
                    // `amount + max(declared, floor) + surcharge` — so a
                    // below-floor transaction is only admitted when its sender
                    // can pay the floor (`commit_native` charges it anyway).
                    // Same formula as admission; see `consensus_floor_parts`.
                    let (floor_base, surcharge) = fee_floors[i];
                    let fee_reserved = tx.gas_limit.max(floor_base);
                    let Some(total) = tx
                        .amount
                        .checked_add(fee_reserved)
                        .and_then(|t| t.checked_add(surcharge))
                    else {
                        continue;
                    };
                    if balance < total {
                        continue;
                    }
                    admitted[i] = true;
                    nonce += 1;
                    balance -= total;
                }
            }
        }

        // 4) Execute the payload and commit the native movement, ONE transaction
        //    at a time, in BLOCK ORDER. Payload execution and value movement are
        //    interleaved on purpose: `apply_transaction` runs the VM against the
        //    sender's balance as it stands when the transaction is applied, and
        //    running every payload first (which is what this used to do) let a
        //    later transaction of the same sender pass its in-VM affordability
        //    check against a balance an earlier transaction had already spent.
        //
        //    Each transaction is applied through `commit_native`, the same
        //    commit point `apply_transaction` uses, so ordering, balance
        //    checks, payload value movement and failure handling are literally
        //    the same code. (The fee NUMBER the two callers supply differs -
        //    see `commit_native`.)
        let mut applied = 0usize;
        let mut failed = 0usize;
        let mut fees_collected = 0u64;
        let mut trie_dirty: Vec<([u8; 32], u64, u64)> = Vec::with_capacity(txs.len() * 2);
        let mut status: Vec<bool> = vec![false; txs.len()];
        // Nano-STELL actually charged per transaction, in block order: what
        // `commit_native` debited on success, or the F-01 failure fee (the
        // floor when the failure is attributable and affordable, else 0) on
        // failure. Filed into receipts alongside `status`.
        let mut fees: Vec<u64> = vec![0; txs.len()];
        let mut events: Vec<Vec<crate::contract::ContractEvent>> = vec![Vec::new(); txs.len()];

        // F-01 failure-fee step for the two async execution branches below
        // (non-plain parallel waves + the sequential loop): an admitted
        // transaction that fails AFTER admission (live session-gate refusal,
        // payload out-of-gas/revert/rejection, native-commit refusal) still
        // pays the floor when attributable and covered — this is what kills
        // the D2 free-failure loop (audit F-01). Attributability, coverage
        // and the atomic debit-plus-nonce-advance live in
        // `apply_failure_fee_to_map` (and its sponsored twin
        // `apply_sponsored_failure_fee_to_map`); this just files the outcome
        // (fee receipt, proposer credit, trie write).
        // Admission-stage refusals (`!admitted[i]`: bad signature/chain-id,
        // nonce gap, sim-insolvent, session-sim refusal) and missing-sender
        // executions keep the plain `failed += 1`: they never ran, and there
        // is no head nonce to consume. The parallel PLAIN fast path above
        // cannot use this (it holds the accounts write guard) and inlines
        // the sync core instead.
        //
        // PAYMASTER: on a sponsored transaction the fee debits the sponsor
        // and the USER's nonce advances (both leaves hit the trie); a
        // failure the sponsor cannot cover moves NOTHING (the grief rule on
        // the fee-payer leg).
        //
        // Hygiene note: the per-transaction bindings (`tx`, `i`) are loop
        // locals invisible at this definition site, so they travel as macro
        // arguments; the block-level bindings resolve lexically.
        macro_rules! fail_with_floor {
            ($tx:expr, $idx:expr) => {{
                failed += 1;
                let (floor_base, surcharge) = fee_floors[$idx];
                // FEE-01: a failure pays the intrinsic envelope cost, floored
                // at the consensus floor, plus the additive surcharge — never
                // the declared limit (the failure arm of the VM result carries
                // no consumption measurement; see `failure_fee_for`).
                let fee = Self::failure_fee_for($tx, floor_base, surcharge);
                if let Some(auth) = $tx.sponsored_grant() {
                    let (debited, charged_state) = self
                        .charge_sponsored_failure_fee($tx, &auth.sponsor, fee)
                        .await;
                    if let Some((user_balance, user_nonce, sponsor_balance, sponsor_nonce)) =
                        charged_state
                    {
                        trie_dirty.push(($tx.from, user_balance, user_nonce));
                        trie_dirty.push((auth.sponsor, sponsor_balance, sponsor_nonce));
                    }
                    fees_collected = fees_collected.saturating_add(debited);
                    fees[$idx] = debited;
                } else {
                    let (debited, charged_state) = self.charge_failure_fee($tx, fee).await;
                    if let Some((balance, nonce)) = charged_state {
                        trie_dirty.push(($tx.from, balance, nonce));
                    }
                    fees_collected = fees_collected.saturating_add(debited);
                    fees[$idx] = debited;
                }
            }};
        }

        let waves = crate::parallel_exec::DisjointScheduler::schedule(txs);
        // The wave path is used for EVERY block when parallel execution is
        // on - including a single-wave block, which is the most parallel
        // shape there is (all of its transactions are disjoint, so the wave
        // is planned on the rayon pool and merged conflict-free). A wave is
        // applied in wave order, and the scheduler keeps the relative order
        // of every CONFLICTING pair, so the result is the sequential one.
        let use_parallel = self.is_parallel_exec_enabled() && !waves.is_empty();

        if use_parallel {
            for wave in waves {
                let wave_all_plain = wave
                    .iter()
                    .all(|&i| txs[i].payload.is_empty() && !txs[i].is_pq_activation());
                if wave_all_plain {
                    // CONCURRENT WAVE: every transaction of this wave is a
                    // plain value transfer, and the scheduler guarantees that
                    // their accounts are DISJOINT. The wave is therefore
                    // planned ON THE RAYON POOL from one consistent snapshot
                    // and merged conflict-free under a compare-and-swap check
                    // (see `apply_plain_wave`) - no transaction is applied
                    // while holding a global lock, and the wave's final state
                    // does not depend on the intra-wave execution order.
                    let has_delegation = wave.iter().any(|&i| txs[i].delegation().is_some());
                    let session_valid = if has_delegation {
                        let mut valid_map = HashMap::with_capacity(wave.len());
                        for &i in &wave {
                            let tx = &txs[i];
                            if admitted[i] && tx.delegation().is_some() {
                                let ok = self.session_gate(tx, timestamp).await.is_ok();
                                valid_map.insert(i, ok);
                            }
                        }
                        Some(valid_map)
                    } else {
                        None
                    };

                    self.apply_plain_wave(
                        txs,
                        &wave,
                        &admitted,
                        session_valid.as_ref(),
                        &fee_floors,
                        &vesting_floors,
                        exec_hardening,
                        &mut applied,
                        &mut failed,
                        &mut fees_collected,
                        &mut status,
                        &mut fees,
                        &mut trie_dirty,
                    )
                    .await;
                } else {
                    // DOMAIN ROLLBACK CLOBBERING FIX: a wave that carries a
                    // PAYLOAD never runs concurrently. `execute_payload`
                    // mutates live consensus domains in place (the VM
                    // clone-commits them WHOLESALE) and `rollback_payload`
                    // restores WHOLE domains, so two payload-bearing
                    // transactions running at the same time would let one
                    // tx's rollback wipe a sibling's committed effects
                    // (plus snapshot races and stale session-gate reads).
                    // The wave scheduler is now per-resource (a token, a
                    // pair, a contract), so such a wave may well hold
                    // several payload transactions - they still apply
                    // strictly in block order, with the same live checks as
                    // the sequential path below: bit-identical by
                    // construction. Concurrency is allowed ONLY for
                    // `wave_all_plain` waves above, whose transactions touch
                    // accounts and no consensus domain at all.
                    for &i in &wave {
                        let tx = &txs[i];
                        if !admitted[i] {
                            failed += 1;
                            continue;
                        }
                        if !tx.payload.is_empty() {
                            let precheck = {
                                let map = self.accounts.read().await;
                                // PAYMASTER v1: split-leg precheck — the user
                                // pre-covers VALUE (`amount`), the sponsor
                                // pre-covers FEE. A short sponsor (missing or
                                // spent down since admission) reports 4: the
                                // failure-fee core then moves NOTHING (the
                                // grief rule on the fee-payer leg), exactly
                                // like an uncoverable sender on the legacy
                                // path.
                                if let Some(auth) = tx.sponsored_grant() {
                                    if let Some(sender) = map.get(&tx.from) {
                                        if tx.nonce != sender.nonce {
                                            2
                                        } else if sender.balance < tx.amount {
                                            4
                                        } else {
                                            let (floor_base, surcharge) = fee_floors[i];
                                            let fee_total = tx
                                                .gas_limit
                                                .max(floor_base)
                                                .saturating_add(surcharge);
                                            let sponsor_balance = map
                                                .get(&auth.sponsor)
                                                .map(|a| a.balance)
                                                .unwrap_or(0);
                                            if sponsor_balance < fee_total {
                                                4
                                            } else {
                                                0
                                            }
                                        }
                                    } else {
                                        1
                                    }
                                } else if let Some(sender) = map.get(&tx.from) {
                                    if tx.nonce != sender.nonce {
                                        2
                                    } else {
                                        let surcharge = if tx.is_pq_activation() {
                                            PQ_ACTIVATION_SURCHARGE_GAS
                                        } else {
                                            0
                                        };
                                        let total = tx
                                            .amount
                                            .checked_add(tx.gas_limit)
                                            .and_then(|t| t.checked_add(surcharge));
                                        match total {
                                            None => 3,
                                            Some(tot) if sender.balance < tot => 4,
                                            _ => 0,
                                        }
                                    }
                                } else {
                                    1
                                }
                            };
                            match precheck {
                                1 => {
                                    failed += 1;
                                    continue;
                                }
                                2..=4 => {
                                    fail_with_floor!(tx, i);
                                    continue;
                                }
                                _ => {}
                            }
                        }
                        if let Err(e) = self.session_gate(tx, timestamp).await {
                            tracing::debug!(tx = i, "session gate: {e}");
                            fail_with_floor!(tx, i);
                            continue;
                        }
                        let mut domain_snap: Option<PayloadDomainSnapshot> = None;
                        let mut post_actions: Option<ExecPostActions> = None;
                        let (transfers, payouts, burns, gas_used, tx_events) =
                            if tx.payload.is_empty() {
                                // FEE-01: no VM ran, so execution measured 0
                                // gas; `billed_gas` adds the intrinsic
                                // envelope cost at the commit.
                                (Vec::new(), Vec::new(), Vec::new(), 0, Vec::new())
                            } else {
                                domain_snap = Some(
                                    self.snapshot_payload_domains_at(&tx.payload, exec_hardening)
                                        .await,
                                );
                                match self
                                    .execute_payload_with_preverify_at_height(
                                        tx,
                                        timestamp,
                                        chain_height,
                                    )
                                    .await
                                {
                                    Ok((
                                        crate::svm::VmExecutionResult::Success {
                                            transfers,
                                            payouts,
                                            burns,
                                            gas_used,
                                            events: evts,
                                            ..
                                        },
                                        actions,
                                    )) => {
                                        post_actions = Some(actions);
                                        (transfers, payouts, burns, gas_used, evts)
                                    }
                                    Ok((crate::svm::VmExecutionResult::OutOfGas, _)) => {
                                        fail_with_floor!(tx, i);
                                        continue;
                                    }
                                    Ok((crate::svm::VmExecutionResult::Reverted(e), _)) => {
                                        tracing::debug!(tx = i, "payload reverted: {e}");
                                        fail_with_floor!(tx, i);
                                        continue;
                                    }
                                    Err(e) => {
                                        tracing::debug!(tx = i, "payload rejected: {e}");
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
                                        fail_with_floor!(tx, i);
                                        continue;
                                    }
                                }
                            };
                        // FEE-01: the fee is priced from what execution
                        // MEASURED (`gas_used`), never from the declared
                        // limit — `commit_native_with_floor_at` caps it at the
                        // limit and refunds the rest.
                        match self
                            .commit_native_with_floor_at(
                                tx,
                                gas_used,
                                &transfers,
                                &payouts,
                                &burns,
                                fee_floors[i].0,
                                fee_floors[i].1,
                                vesting_floors.get(&tx.from).copied(),
                                &vesting_floors,
                                chain_height,
                            )
                            .await
                        {
                            Ok((mut touched, fee)) => {
                                if tx.is_pq_activation() {
                                    if let Some(env) = tx.pq_envelope_at_height(chain_height) {
                                        if !env.is_implicit {
                                            if let Some(ref pk) = env.pubkey {
                                                let salt = crate::post_quantum::DEFAULT_SALT;
                                                let _ = self
                                                    .pin_pubkey(tx.from, env.scheme, pk, &salt)
                                                    .await;
                                            }
                                        }
                                    }
                                }
                                if let Some(ref actions) = post_actions {
                                    if !actions.outbound_messages.is_empty() {
                                        let outbound_touched = self
                                            .process_contract_outbound_messages_hardened(
                                                &actions.outbound_messages,
                                            )
                                            .await;
                                        touched.extend(outbound_touched);
                                    }
                                }
                                trie_dirty.extend(touched);
                                fees_collected = fees_collected.saturating_add(fee);
                                applied += 1;
                                status[i] = true;
                                fees[i] = fee;
                                events[i] = tx_events;
                                self.session_note_applied(
                                    tx,
                                    InMemoryStateEngine::billed_gas_at(
                                        tx,
                                        gas_used,
                                        exec_hardening,
                                    ),
                                )
                                .await;
                            }
                            Err(e) => {
                                if let (Some(snap), Some(actions)) = (domain_snap, post_actions) {
                                    self.rollback_payload(snap, actions).await;
                                }
                                tracing::debug!(tx = i, "native commit rejected: {e}");
                                fail_with_floor!(tx, i);
                            }
                        }
                    }
                }
            }
        } else {
            for i in 0..txs.len() {
                let tx = &txs[i];
                if !admitted[i] {
                    failed += 1;
                    continue;
                }
                // Re-check admission under the lock BEFORE the payload runs (this is
                // `apply_transaction`'s steps 2-4): admission assumed every
                // predecessor from this sender would apply, and a predecessor can
                // have failed since. A payload must never execute for a transaction
                // that will be rejected (I9 / `rejected_tx_payload_is_not_executed`).
                //
                // Empty-payload transfers execute nothing, so they skip this
                // read-lock pass: `commit_native` re-checks the same nonce/balance
                // under the write lock and fails the transaction identically (same
                // verdict, same untouched state). Skipping it only removes a lock
                // round trip per plain transfer; payload-bearing transactions keep
                // the guard.
                if !tx.payload.is_empty() {
                    let precheck = {
                        let map = self.accounts.read().await;
                        // PAYMASTER v1: split-leg precheck (same shape as the
                        // parallel-wave precheck above).
                        if let Some(auth) = tx.sponsored_grant() {
                            if let Some(sender) = map.get(&tx.from) {
                                if tx.nonce != sender.nonce {
                                    2
                                } else if sender.balance < tx.amount {
                                    4
                                } else {
                                    let (floor_base, surcharge) = fee_floors[i];
                                    let fee_total =
                                        tx.gas_limit.max(floor_base).saturating_add(surcharge);
                                    let sponsor_balance =
                                        map.get(&auth.sponsor).map(|a| a.balance).unwrap_or(0);
                                    if sponsor_balance < fee_total {
                                        4
                                    } else {
                                        0
                                    }
                                }
                            } else {
                                1
                            }
                        } else if let Some(sender) = map.get(&tx.from) {
                            if tx.nonce != sender.nonce {
                                2
                            } else {
                                let surcharge = if tx.is_pq_activation() {
                                    PQ_ACTIVATION_SURCHARGE_GAS
                                } else {
                                    0
                                };
                                let total = tx
                                    .amount
                                    .checked_add(tx.gas_limit)
                                    .and_then(|t| t.checked_add(surcharge));
                                match total {
                                    None => 3,
                                    Some(tot) if sender.balance < tot => 4,
                                    _ => 0,
                                }
                            }
                        } else {
                            1
                        }
                    };
                    match precheck {
                        1 => {
                            failed += 1;
                            continue;
                        }
                        2..=4 => {
                            fail_with_floor!(tx, i);
                            continue;
                        }
                        _ => {}
                    }
                }

                // ...and the session gate against the registry AS IT STANDS NOW.
                // Admission above simulated this block's spend; here the earlier
                // transactions have actually applied and been deducted, so this
                // live check is the authoritative one - a predecessor can have
                // consumed the rest of the grant since admission, and a payload
                // must never execute for a transaction that will be rejected.
                // (Revocation is re-checked here too, so a revoke earlier in this
                // very block stops the ones after it.)
                if let Err(e) = self.session_gate(tx, timestamp).await {
                    tracing::debug!(tx = i, "session gate: {e}");
                    fail_with_floor!(tx, i);
                    continue;
                }

                // The payload itself: clone-commit, so a reverting or out-of-gas
                // program leaves no partial effect. Its `transfers` and `payouts`
                // are the value the payload moved, and they are NOT optional - the
                // whole point of the P0 this replaced was that they were dropped
                // here, so a Transfer, a SysCallStake bond or a reward claim moved
                // no coins while still reporting success.
                //
                // `gas_used` is what execution MEASURED: the VM's consumption
                // for a payload, 0 for an empty-payload transfer (no VM ran).
                // The session budget and the fee are charged the BILLED gas
                // (`billed_gas(tx, gas_used)` = the measurement plus the
                // intrinsic envelope cost, capped at the declaration), so a
                // plain session transfer still consumes budget — without it, it
                // would bypass the cap that phase 1 closed for the policy
                // checks — and is never charged its declared limit.
                //
                // B1 atomicity (mirrors `apply_transaction`): per-tx domain
                // snapshot + settlement undo records, restored if the commit
                // below refuses.
                let mut domain_snap: Option<PayloadDomainSnapshot> = None;
                let mut post_actions: Option<ExecPostActions> = None;
                let (transfers, payouts, burns, gas_used, tx_events) = if tx.payload.is_empty() {
                    // FEE-01: no VM ran, so execution measured 0 gas;
                    // `billed_gas` adds the intrinsic envelope cost.
                    (Vec::new(), Vec::new(), Vec::new(), 0, Vec::new())
                } else {
                    // B1 atomicity: snapshot domains BEFORE the VM runs; any
                    // failure after (including the native commit below) restores
                    // everything (see rollback_payload). NOTE: must stay in sync
                    // with the `apply_transaction` copy.
                    domain_snap = Some(
                        self.snapshot_payload_domains_at(&tx.payload, exec_hardening)
                            .await,
                    );
                    match self
                        .execute_payload_with_preverify_at_height(tx, timestamp, chain_height)
                        .await
                    {
                        Ok((
                            crate::svm::VmExecutionResult::Success {
                                transfers,
                                payouts,
                                burns,
                                gas_used,
                                events: evts,
                                ..
                            },
                            actions,
                        )) => {
                            // Stash for the commit-failure arm below.
                            // (transfers, payouts, burns, gas_used) flow into the
                            // commit; actions flow into the rollback.
                            post_actions = Some(actions);
                            (transfers, payouts, burns, gas_used, evts)
                        }
                        // `execute_payload` maps OutOfGas/Reverted to Err; the arms
                        // are kept exhaustive to match `apply_transaction`.
                        Ok((crate::svm::VmExecutionResult::OutOfGas, _)) => {
                            fail_with_floor!(tx, i);
                            continue;
                        }
                        Ok((crate::svm::VmExecutionResult::Reverted(e), _)) => {
                            tracing::debug!(tx = i, "payload reverted: {e}");
                            fail_with_floor!(tx, i);
                            continue;
                        }
                        Err(e) => {
                            tracing::debug!(tx = i, "payload rejected: {e}");
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
                            fail_with_floor!(tx, i);
                            continue;
                        }
                    }
                };

                // Commit: amount + fee + payload transfers + payload payouts.
                //
                // FEE-01: the block path hands `commit_native` the gas
                // execution MEASURED (`gas_used`: the VM's own number for a
                // payload, 0 when no VM ran) — never the DECLARED
                // `tx.gas_limit`, which is only the budget/admission
                // reservation. `commit_native` bills
                // `min(gas_limit, gas_used + intrinsic)`, raises it to the
                // consensus floor (F-01: a below-floor declaration is charged
                // the floor anyway, never executed below it) and credits the
                // sum of those fees to the proposer, so unused gas is
                // refunded and `fee_charged` equals what left the sender.
                match self
                    .commit_native_with_floor_at(
                        tx,
                        gas_used,
                        &transfers,
                        &payouts,
                        &burns,
                        fee_floors[i].0,
                        fee_floors[i].1,
                        vesting_floors.get(&tx.from).copied(),
                        &vesting_floors,
                        chain_height,
                    )
                    .await
                {
                    Ok((mut touched, fee)) => {
                        if tx.is_pq_activation() {
                            if let Some(env) = tx.pq_envelope_at_height(chain_height) {
                                if !env.is_implicit {
                                    if let Some(ref pk) = env.pubkey {
                                        let salt = crate::post_quantum::DEFAULT_SALT;
                                        let _ =
                                            self.pin_pubkey(tx.from, env.scheme, pk, &salt).await;
                                    }
                                }
                            }
                        }
                        if let Some(ref actions) = post_actions {
                            if !actions.outbound_messages.is_empty() {
                                let outbound_touched = self
                                    .process_contract_outbound_messages_hardened(
                                        &actions.outbound_messages,
                                    )
                                    .await;
                                touched.extend(outbound_touched);
                            }
                        }
                        // Later transactions may touch the same accounts again; the
                        // LAST tuple per account wins when the trie is written, and
                        // it is the one taken after the final mutation.
                        trie_dirty.extend(touched);
                        fees_collected = fees_collected.saturating_add(fee);
                        applied += 1;
                        status[i] = true;
                        fees[i] = fee;
                        events[i] = tx_events;
                        // Session budget: ONLY a transaction that actually applied
                        // is charged, and only now - a transaction refused above
                        // (nonce, balance, gate, payload, native commit) leaves the
                        // grant's budget untouched. This is the live path
                        // (`apply_block_transition` -> here), so the deduction is
                        // consensus state: it lands in the committed registry.
                        self.session_note_applied(
                            tx,
                            InMemoryStateEngine::billed_gas_at(tx, gas_used, exec_hardening),
                        )
                        .await;
                    }
                    Err(e) => {
                        // B1 atomicity (mirrors `apply_transaction`): the commit
                        // restored the accounts map itself; roll back everything
                        // the payload touched before it (domains + settlement
                        // legs + trie keys). F-01: the refusal itself still pays
                        // the floor when attributable (`fail_with_floor!`).
                        if let (Some(snap), Some(actions)) = (domain_snap, post_actions) {
                            self.rollback_payload(snap, actions).await;
                        }
                        tracing::debug!(tx = i, "native commit rejected: {e}");
                        fail_with_floor!(tx, i);
                    }
                }
            }
        }

        // 5) Commit touched accounts to the trie (only the touched ones).
        //
        // Deduplicate repeated accounts first: every transaction writes its
        // sender, so a block with K transactions from one sender carries K
        // writes for it (plus hot recipients), each rebuilding the trie path
        // from scratch — while only the LAST tuple per account survives. The
        // reverse walk keeps exactly that last tuple per account and restores
        // original relative order, so the final key/value set — and therefore
        // the root — is identical with far fewer inserts. With no duplicates
        // the original sequence is written unchanged. This runs BEFORE taking
        // the trie lock, so the deduplication CPU never extends the write
        // critical section.
        let writes: Vec<([u8; 32], u64, u64)> = if trie_dirty.len() > 1 {
            let mut seen: HashSet<[u8; 32]> = HashSet::with_capacity(trie_dirty.len());
            let mut uniq: Vec<([u8; 32], u64, u64)> = Vec::with_capacity(trie_dirty.len());
            let mut dup = false;
            for &(addr, balance, nonce) in trie_dirty.iter().rev() {
                if seen.insert(addr) {
                    uniq.push((addr, balance, nonce));
                } else {
                    dup = true;
                }
            }
            if dup {
                uniq.reverse();
                uniq
            } else {
                trie_dirty
            }
        } else {
            trie_dirty
        };
        // Contract deploys commit code hashes here — AFTER every commit in
        // this block, never speculatively inside execution (B1: the trie has
        // no undo). Cheap check per block: only runs when some tx deployed.
        // Lock order contracts-then-trie (see apply_transaction).
        let deployed_contracts = if txs.iter().any(|tx| {
            tx.payload
                .iter()
                .any(|op| matches!(op, crate::svm::OpCode::SysCallDeployContract { .. }))
        }) {
            Some((*self.contracts_read().await).clone())
        } else {
            None
        };
        let entries: Vec<([u8; 32], Vec<u8>)> = {
            let map = self.accounts.read().await;
            writes
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
        debug_assert_eq!(applied + failed, txs.len(), "every tx must get a verdict");
        drop(trie);

        // Fold the subsystems this block may have changed (staking via the
        // stake syscalls, order books, escrow, PMM, contract storage) into the
        // trie, so the block's own effects are committed as they are applied
        // rather than waiting for the next root read.
        self.commit_consensus_domains_if_stale().await;

        // 6) F-01: feed this block's verdicts into the CONSENSUS penalty
        //    mirror — the same rule the runtime feeds the mempool-local copy
        //    (`note_apply_feedback`, same step/cap/clear semantics), but
        //    derived purely from applied blocks: every `failed` sender that
        //    did not also succeed grows one bond step (capped), every
        //    `succeeded`-only sender is cleared, a sender in both lists keeps
        //    the penalty. Runs on EVERY apply path (live, adopt, walk,
        //    replay, reorg, tests), so all nodes that applied the same chain
        //    compute the same floor in `consensus_floor_parts` — unlike the
        //    mempool copy, which the live path alone feeds (see
        //    `record_apply_outcome`). Uses hash sets rather than the
        //    mempool's quadratic scans; verdicts are identical.
        {
            let mut failed_senders: HashSet<[u8; 32]> = HashSet::new();
            let mut succeeded_senders: HashSet<[u8; 32]> = HashSet::new();
            for (i, tx) in txs.iter().enumerate() {
                if status.get(i).copied().unwrap_or(false) {
                    succeeded_senders.insert(tx.from);
                } else {
                    failed_senders.insert(tx.from);
                }
            }
            let mut pen = self.consensus_penalty.write().await;
            for s in &failed_senders {
                if succeeded_senders.contains(s) {
                    continue;
                }
                let e = pen.entry(*s).or_insert(0);
                *e = (*e)
                    .saturating_add(crate::mempool::FAILED_SENDER_PENALTY)
                    .min(crate::mempool::MAX_FAILED_SENDER_PENALTY);
            }
            for s in &succeeded_senders {
                if !failed_senders.contains(s) {
                    pen.remove(s);
                }
            }
        }

        (applied, failed, fees_collected, status, fees, events)
    }
}
