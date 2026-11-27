use super::settlement::PlannedClobEffects;
use super::types::{
    token_balance_key, token_supply_key, write_contract_trie_entries_for_addrs, ActorSendBody,
    ClobQuoteMode, PayloadDomainSnapshot,
};
use super::verify_once::verify_block_tx_signatures_at_height;
use super::{AccountState, ExecPostActions, InMemoryStateEngine, PQ_ACTIVATION_SURCHARGE_GAS};
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

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
///
/// NOTE: deliberately NOT cached in a `OnceLock` because tests and benchmarks
/// (`tests/parallel_apply_parity_tests.rs`, `benches/apply_speedup.rs`) sweep
/// `STELL_PARALLEL_PLAN_CHUNK` dynamically at runtime within one process.
fn parallel_plan_chunk() -> usize {
    std::env::var("STELL_PARALLEL_PLAN_CHUNK")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(PARALLEL_PLAN_CHUNK)
}

/// Maximum number of Block-STM validation/re-execution retries for dirty
/// contract transactions in a single wave before falling back to sequential
/// execution for the remainder of the wave.
const MAX_STM_RETRIES: usize = 3;

/// Runtime toggle for Phase 13a/13b fine-grained parallel payload execution
/// (`STELL_PARALLEL_EXEC_V2`, default `true` when `parallel_exec` is enabled;
/// `0` or `false` falls back to the legacy sequential payload loop).
fn parallel_exec_v2_enabled() -> bool {
    match std::env::var("STELL_PARALLEL_EXEC_V2") {
        Ok(v) => {
            let trimmed = v.trim();
            !(trimmed == "0" || trimmed.eq_ignore_ascii_case("false"))
        }
        Err(_) => true,
    }
}

/// Wave planning for one block (O13).
///
/// The `DisjointScheduler` partition is a pure function of the transactions,
/// but it is only CONSUMED when parallel execution is enabled. Planning it
/// behind the flag keeps the scheduler out of the sequential path entirely;
/// when the flag is on the plan is identical, so `use_parallel` and every
/// resulting state write are unchanged.
fn planned_waves(parallel_enabled: bool, txs: &[crate::sharding::Transaction]) -> Vec<Vec<usize>> {
    if !parallel_enabled {
        return Vec::new();
    }
    #[cfg(test)]
    o13_schedule_probe_note_call();
    crate::parallel_exec::DisjointScheduler::schedule(txs)
}

/// Fine-grained Phase 13a/13b wave planning (`DisjointScheduler::schedule_v2`)
/// gated behind `parallel_enabled` (O13).
fn planned_waves_v2(
    parallel_enabled: bool,
    txs: &[crate::sharding::Transaction],
    stm_contracts: bool,
    exec_hardening: bool,
) -> Vec<Vec<usize>> {
    if !parallel_enabled {
        return Vec::new();
    }
    #[cfg(test)]
    o13_schedule_probe_note_call();
    crate::parallel_exec::DisjointScheduler::schedule_v2(txs, stm_contracts, exec_hardening)
}

#[derive(Clone)]
enum TxWaveKind<'a> {
    Plain,
    Token,
    Market {
        pair_id: u32,
    },
    Staking,
    Contract {
        contract: [u8; 32],
        method: &'a [u8],
        args: Vec<i64>,
        calldata: &'a [u8],
        nop_gas: u64,
    },
    Unsupported,
}

/// Deferred contract-call description gathered while classifying one tx.
///
/// Extracted into a struct so the classifier's local state stays readable and
/// clippy's `type_complexity` gate stays meaningful for real tuples.
struct ContractCallPlan<'a> {
    contract: [u8; 32],
    method: &'a [u8],
    args: Vec<i64>,
    calldata: &'a [u8],
}

fn classify_tx_v2(tx: &crate::sharding::Transaction, exec_hardening: bool) -> TxWaveKind<'_> {
    use crate::svm::OpCode;

    if tx.is_pq_activation() {
        return TxWaveKind::Unsupported;
    }
    if tx.payload.is_empty() {
        return TxWaveKind::Plain;
    }
    // Check EVM payload invariant up front (unsupported if any EVM carrier/mixed).
    if crate::evm_adapter::carrier_intent_digest(tx).is_some()
        || crate::evm_adapter::verify_evm_payload_against_tx(tx).is_err()
    {
        return TxWaveKind::Unsupported;
    }

    let mut has_token = false;
    let mut market_pair: Option<u32> = None;
    let mut staking_count = 0usize;
    let mut contract_call: Option<ContractCallPlan<'_>> = None;
    let mut nop_gas: u64 = 0;

    for op in &tx.payload {
        if matches!(op, OpCode::Halt) {
            if exec_hardening {
                break;
            } else {
                // Pre-hardening still halts at OpCode::Halt in VM, but scheduler
                // inspected post-Halt ops unless exec_hardening is true; be conservative.
                return TxWaveKind::Unsupported;
            }
        }
        match op {
            OpCode::Nop => {
                nop_gas = nop_gas.saturating_add(crate::svm::GAS_NOP);
            }
            OpCode::SysCallTokenTransfer { .. }
            | OpCode::SysCallTokenTransferFrom { .. }
            | OpCode::SysCallTokenApprove { .. }
            | OpCode::SysCallTokenMint { .. }
            | OpCode::SysCallTokenBurn { .. }
            | OpCode::SysCallTokenBalanceOf { .. } => {
                has_token = true;
            }
            OpCode::SysCallPlaceOrder { pair_id, .. } => match market_pair {
                None => market_pair = Some(*pair_id),
                Some(p) if p == *pair_id => {}
                Some(_) => return TxWaveKind::Unsupported,
            },
            OpCode::SysCallDelegate { .. }
            | OpCode::SysCallUnbond { .. }
            | OpCode::SysCallBeginUndelegate { .. }
            | OpCode::SysCallUndelegate { .. }
            | OpCode::SysCallClaimRewards { .. }
            | OpCode::SysCallClaimDelegatorRewards { .. }
            | OpCode::SysCallWithdrawSelfBond { .. } => {
                staking_count += 1;
            }
            OpCode::SysCallCallContract {
                contract,
                method,
                arg,
            } => {
                if contract_call.is_some() {
                    return TxWaveKind::Unsupported;
                }
                contract_call = Some(ContractCallPlan {
                    contract: *contract,
                    method: method.as_slice(),
                    args: vec![*arg],
                    calldata: &[],
                });
            }
            OpCode::SysCallCallContractArgs {
                contract,
                method,
                args,
                calldata,
            } => {
                if contract_call.is_some() {
                    return TxWaveKind::Unsupported;
                }
                contract_call = Some(ContractCallPlan {
                    contract: *contract,
                    method: method.as_slice(),
                    args: args.clone(),
                    calldata: calldata.as_slice(),
                });
            }
            _ => return TxWaveKind::Unsupported,
        }
    }

    let domain_kinds = usize::from(has_token)
        + usize::from(market_pair.is_some())
        + usize::from(staking_count > 0)
        + usize::from(contract_call.is_some());
    if domain_kinds != 1 {
        return TxWaveKind::Unsupported;
    }

    if has_token {
        return TxWaveKind::Token;
    }
    if let Some(pair_id) = market_pair {
        if nop_gas > 0 {
            return TxWaveKind::Unsupported;
        }
        return TxWaveKind::Market { pair_id };
    }
    if staking_count > 0 {
        if staking_count != 1 || nop_gas > 0 {
            return TxWaveKind::Unsupported;
        }
        return TxWaveKind::Staking;
    }
    if let Some(plan) = contract_call {
        return TxWaveKind::Contract {
            contract: plan.contract,
            method: plan.method,
            args: plan.args,
            calldata: plan.calldata,
            nop_gas,
        };
    }
    TxWaveKind::Unsupported
}

#[derive(Clone, Copy)]
enum PreGate {
    NotAdmitted,
    MissingSender,
    PrecheckFail,
    GateFail,
    Ready { sender_balance: u64 },
}

enum Phase13aPlan {
    Token {
        delta: crate::token::TokenTxDelta,
        token_ids: Vec<[u8; 32]>,
        gas_used: u64,
    },
    Market {
        pair_id: u32,
        book_after: crate::orderbook::OrderbookActor,
        clob: PlannedClobEffects,
        gas_used: u64,
    },
    MarketFailed {
        makers: HashSet<[u8; 32]>,
    },
    Staking {
        delta: crate::staking::StakingTxDelta,
        transfers: Vec<([u8; 32], u64)>,
        payouts: Vec<([u8; 32], [u8; 32], u64)>,
        gas_used: u64,
    },
    Failed,
}

fn plan_token_tx(
    tx: &crate::sharding::Transaction,
    tokens: &crate::token::TokenRegistry,
    timestamp: u64,
    exec_hardening: bool,
) -> Phase13aPlan {
    use crate::svm::OpCode;

    let mut gas_remaining = tx.gas_limit;
    let mut delta = crate::token::TokenTxDelta::default();
    let mut token_ids: Vec<[u8; 32]> = Vec::new();

    for op in &tx.payload {
        if exec_hardening && matches!(op, OpCode::Halt) {
            break;
        }
        match op {
            OpCode::Nop => {
                if gas_remaining < crate::svm::GAS_NOP {
                    return Phase13aPlan::Failed;
                }
                gas_remaining -= crate::svm::GAS_NOP;
            }
            OpCode::Halt => break,
            OpCode::SysCallTokenTransfer {
                token_id,
                to,
                amount,
            } => {
                if gas_remaining < crate::svm::GAS_TOKEN_TRANSFER {
                    return Phase13aPlan::Failed;
                }
                gas_remaining -= crate::svm::GAS_TOKEN_TRANSFER;
                if tokens
                    .plan_transfer_into(&mut delta, token_id, tx.from, *to, *amount)
                    .is_err()
                {
                    return Phase13aPlan::Failed;
                }
                if !token_ids.contains(token_id) {
                    token_ids.push(*token_id);
                }
            }
            OpCode::SysCallTokenTransferFrom {
                token_id,
                from,
                to,
                amount,
            } => {
                if gas_remaining < crate::svm::GAS_TOKEN_TRANSFER {
                    return Phase13aPlan::Failed;
                }
                gas_remaining -= crate::svm::GAS_TOKEN_TRANSFER;
                if tokens
                    .plan_transfer_from_into(&mut delta, token_id, tx.from, *from, *to, *amount)
                    .is_err()
                {
                    return Phase13aPlan::Failed;
                }
                if !token_ids.contains(token_id) {
                    token_ids.push(*token_id);
                }
            }
            OpCode::SysCallTokenApprove {
                token_id,
                spender,
                amount,
            } => {
                if gas_remaining < crate::svm::GAS_TOKEN_APPROVE {
                    return Phase13aPlan::Failed;
                }
                gas_remaining -= crate::svm::GAS_TOKEN_APPROVE;
                if tokens
                    .plan_approve_into(&mut delta, token_id, tx.from, *spender, *amount)
                    .is_err()
                {
                    return Phase13aPlan::Failed;
                }
                if !token_ids.contains(token_id) {
                    token_ids.push(*token_id);
                }
            }
            OpCode::SysCallTokenMint {
                token_id,
                to,
                amount,
            } => {
                if gas_remaining < crate::svm::GAS_TOKEN_MINT {
                    return Phase13aPlan::Failed;
                }
                gas_remaining -= crate::svm::GAS_TOKEN_MINT;
                if tokens
                    .plan_mint_into(&mut delta, token_id, tx.from, *to, *amount)
                    .is_err()
                {
                    return Phase13aPlan::Failed;
                }
                if !token_ids.contains(token_id) {
                    token_ids.push(*token_id);
                }
            }
            OpCode::SysCallTokenBurn {
                token_id,
                from,
                amount,
            } => {
                if gas_remaining < crate::svm::GAS_TOKEN_BURN {
                    return Phase13aPlan::Failed;
                }
                gas_remaining -= crate::svm::GAS_TOKEN_BURN;
                if tokens
                    .plan_burn_into(&mut delta, token_id, tx.from, *from, *amount)
                    .is_err()
                {
                    return Phase13aPlan::Failed;
                }
                if !token_ids.contains(token_id) {
                    token_ids.push(*token_id);
                }
            }
            OpCode::SysCallTokenBalanceOf { .. } => {
                if gas_remaining < crate::svm::GAS_TOKEN_BALANCE {
                    return Phase13aPlan::Failed;
                }
                gas_remaining -= crate::svm::GAS_TOKEN_BALANCE;
            }
            _ => return Phase13aPlan::Failed,
        }
    }

    let gas_used = tx.gas_limit - gas_remaining;
    if let Some(mut auth) = tx.delegation() {
        if auth.verify_and_spend_gas(gas_used, timestamp).is_err() {
            return Phase13aPlan::Failed;
        }
    }

    Phase13aPlan::Token {
        delta,
        token_ids,
        gas_used,
    }
}

#[allow(clippy::too_many_arguments)]
// GATE: market planner mirrors Svm::execute_inner + settle_clob_effects context for bit-exact parity.
fn plan_market_tx(
    tx: &crate::sharding::Transaction,
    target_pair_id: u32,
    sender_balance: u64,
    timestamp: u64,
    exec_hardening: bool,
    tokens: &crate::token::TokenRegistry,
    orderbooks: &crate::orderbook::OrderbookManager,
    escrow: &HashMap<(u32, u64), super::EscrowRecord>,
    oracle: &crate::oracle::OracleState,
    accounts: &HashMap<[u8; 32], AccountState>,
    quote_id: Option<[u8; 32]>,
) -> Phase13aPlan {
    use crate::orderbook::{ClobEvent, OrderSide, OrderType, OrderbookActor};
    use crate::svm::{OpCode, GAS_ORDER_PLACE, GAS_PER_MATCH_LEVEL, MAX_MATCH_LEVELS};

    let mut gas_remaining = tx.gas_limit;
    let mut current_balance = sender_balance;
    let mut clob_events: Vec<ClobEvent> = Vec::new();
    let mut book = orderbooks
        .clone_pair(target_pair_id)
        .unwrap_or_else(|| OrderbookActor::new(target_pair_id, 1000));
    let mut makers: HashSet<[u8; 32]> = HashSet::new();

    for op in &tx.payload {
        if exec_hardening && matches!(op, OpCode::Halt) {
            break;
        }
        match op {
            OpCode::Halt => break,
            OpCode::SysCallPlaceOrder {
                pair_id,
                is_buy,
                price,
                amount,
            } => {
                if *pair_id != target_pair_id || gas_remaining < GAS_ORDER_PLACE {
                    return Phase13aPlan::MarketFailed { makers };
                }
                gas_remaining -= GAS_ORDER_PLACE;
                if oracle.gate_order(*pair_id, *price).is_err() {
                    return Phase13aPlan::MarketFailed { makers };
                }
                let side = if *is_buy {
                    OrderSide::Buy
                } else {
                    OrderSide::Sell
                };
                let order_cost = if *is_buy {
                    let prod = (*price as u128) * (*amount as u128);
                    (prod / 1_000_000u128).min(u64::MAX as u128) as u64
                } else {
                    *amount
                };
                if order_cost > current_balance {
                    return Phase13aPlan::MarketFailed { makers };
                }
                let (placed_order, trade_events) = if exec_hardening {
                    book.submit_order_bounded_with_fills(
                        tx.from,
                        side.clone(),
                        OrderType::Limit,
                        *price,
                        *amount,
                        timestamp,
                        MAX_MATCH_LEVELS,
                        crate::orderbook::MAX_MATCH_FILLS_PER_ORDER,
                    )
                } else {
                    book.submit_order_bounded(
                        tx.from,
                        side.clone(),
                        OrderType::Limit,
                        *price,
                        *amount,
                        timestamp,
                        MAX_MATCH_LEVELS,
                    )
                };
                for t in &trade_events {
                    makers.insert(t.maker);
                }
                let level_gas = if exec_hardening {
                    (trade_events.len() as u64).saturating_mul(GAS_PER_MATCH_LEVEL)
                } else {
                    (trade_events.len() as u64).min(MAX_MATCH_LEVELS as u64) * GAS_PER_MATCH_LEVEL
                };
                if gas_remaining < level_gas {
                    return Phase13aPlan::MarketFailed { makers };
                }
                gas_remaining -= level_gas;
                current_balance -= order_cost;
                clob_events.push(ClobEvent::Place {
                    pair_id: *pair_id,
                    order_id: placed_order.order_id,
                    trader: tx.from,
                    side,
                    order_type: OrderType::Limit,
                    price: *price,
                    amount: *amount,
                    filled: placed_order.filled,
                    trades: trade_events,
                });
            }
            _ => return Phase13aPlan::MarketFailed { makers },
        }
    }

    let gas_used = tx.gas_limit - gas_remaining;
    if let Some(mut auth) = tx.delegation() {
        if auth.verify_and_spend_gas(gas_used, timestamp).is_err() {
            return Phase13aPlan::MarketFailed { makers };
        }
    }

    if clob_events.is_empty() {
        return Phase13aPlan::MarketFailed { makers };
    }

    let reserve = tx.amount.saturating_add(tx.gas_limit);
    match InMemoryStateEngine::plan_clob_effects(
        &clob_events,
        ClobQuoteMode::NativeSvm,
        quote_id,
        tokens,
        escrow,
        accounts,
        tx.from,
        reserve,
        |pair, id| pair != target_pair_id || book.find_order(id).is_none(),
    ) {
        Ok(clob) => Phase13aPlan::Market {
            pair_id: target_pair_id,
            book_after: book,
            clob,
            gas_used,
        },
        Err(_) => Phase13aPlan::MarketFailed { makers },
    }
}

fn plan_staking_tx(
    tx: &crate::sharding::Transaction,
    sender_balance: u64,
    timestamp: u64,
    exec_hardening: bool,
    pq_lifecycle: bool,
    staking: &crate::staking::StakingLedger,
) -> Phase13aPlan {
    use crate::staking::{StakingTxSliceOp, REWARDS_POOL, STAKING_POOL};
    use crate::svm::{OpCode, GAS_STAKE_BOND, GAS_STAKE_CLAIM, GAS_STAKE_UNBOND};

    let mut gas_remaining = tx.gas_limit;
    let mut transfers: Vec<([u8; 32], u64)> = Vec::new();
    let mut payouts: Vec<([u8; 32], [u8; 32], u64)> = Vec::new();
    let mut planned_delta = None;

    for op in &tx.payload {
        if exec_hardening && matches!(op, OpCode::Halt) {
            break;
        }
        match op {
            OpCode::Halt => break,
            OpCode::SysCallDelegate { validator, amount } => {
                if gas_remaining < GAS_STAKE_BOND {
                    return Phase13aPlan::Failed;
                }
                gas_remaining -= GAS_STAKE_BOND;
                if *amount == 0 || *amount > sender_balance {
                    return Phase13aPlan::Failed;
                }
                let Ok(delta) = staking.plan_tx_slice(StakingTxSliceOp::Delegate {
                    delegator: tx.from,
                    validator: *validator,
                    amount: *amount,
                }) else {
                    return Phase13aPlan::Failed;
                };
                transfers.push((STAKING_POOL, *amount));
                planned_delta = Some(delta);
            }
            OpCode::SysCallUnbond { validator, amount } => {
                if gas_remaining < GAS_STAKE_UNBOND {
                    return Phase13aPlan::Failed;
                }
                gas_remaining -= GAS_STAKE_UNBOND;
                if !pq_lifecycle && tx.from != *validator {
                    return Phase13aPlan::Failed;
                }
                if pq_lifecycle
                    && staking
                        .authorize_validator_owner(validator, &tx.from, true)
                        .is_err()
                {
                    return Phase13aPlan::Failed;
                }
                let Ok(delta) = staking.plan_tx_slice(StakingTxSliceOp::Unbond {
                    validator: *validator,
                    amount: *amount,
                    now: timestamp,
                }) else {
                    return Phase13aPlan::Failed;
                };
                planned_delta = Some(delta);
            }
            OpCode::SysCallBeginUndelegate { validator, amount } => {
                if gas_remaining < GAS_STAKE_UNBOND {
                    return Phase13aPlan::Failed;
                }
                gas_remaining -= GAS_STAKE_UNBOND;
                if *amount == 0 {
                    return Phase13aPlan::Failed;
                }
                let Ok(delta) = staking.plan_tx_slice(StakingTxSliceOp::BeginUndelegate {
                    delegator: tx.from,
                    validator: *validator,
                    amount: *amount,
                    now: timestamp,
                }) else {
                    return Phase13aPlan::Failed;
                };
                planned_delta = Some(delta);
            }
            OpCode::SysCallUndelegate { validator } => {
                if gas_remaining < GAS_STAKE_UNBOND {
                    return Phase13aPlan::Failed;
                }
                gas_remaining -= GAS_STAKE_UNBOND;
                let Ok(delta) = staking.plan_tx_slice(StakingTxSliceOp::Undelegate {
                    delegator: tx.from,
                    validator: *validator,
                }) else {
                    return Phase13aPlan::Failed;
                };
                let amt = delta.withdrawn_amount();
                payouts.push((STAKING_POOL, tx.from, amt));
                planned_delta = Some(delta);
            }
            OpCode::SysCallClaimRewards { validator } => {
                if gas_remaining < GAS_STAKE_CLAIM {
                    return Phase13aPlan::Failed;
                }
                gas_remaining -= GAS_STAKE_CLAIM;
                if !pq_lifecycle && tx.from != *validator {
                    return Phase13aPlan::Failed;
                }
                if pq_lifecycle
                    && staking
                        .authorize_validator_owner(validator, &tx.from, true)
                        .is_err()
                {
                    return Phase13aPlan::Failed;
                }
                let Ok(delta) = staking.plan_tx_slice(StakingTxSliceOp::ClaimRewards {
                    validator: *validator,
                }) else {
                    return Phase13aPlan::Failed;
                };
                let amt = delta.claimed_rewards();
                if amt > 0 {
                    payouts.push((REWARDS_POOL, tx.from, amt));
                }
                planned_delta = Some(delta);
            }
            OpCode::SysCallClaimDelegatorRewards { validator } => {
                if gas_remaining < GAS_STAKE_CLAIM {
                    return Phase13aPlan::Failed;
                }
                gas_remaining -= GAS_STAKE_CLAIM;
                let Ok(delta) = staking.plan_tx_slice(StakingTxSliceOp::ClaimDelegatorRewards {
                    delegator: tx.from,
                    validator: *validator,
                }) else {
                    return Phase13aPlan::Failed;
                };
                let amt = delta.claimed_rewards();
                if amt == 0 {
                    return Phase13aPlan::Failed;
                }
                payouts.push((REWARDS_POOL, tx.from, amt));
                planned_delta = Some(delta);
            }
            OpCode::SysCallWithdrawSelfBond { validator } => {
                if gas_remaining < GAS_STAKE_UNBOND {
                    return Phase13aPlan::Failed;
                }
                gas_remaining -= GAS_STAKE_UNBOND;
                if !pq_lifecycle && tx.from != *validator {
                    return Phase13aPlan::Failed;
                }
                if pq_lifecycle
                    && staking
                        .authorize_validator_owner(validator, &tx.from, true)
                        .is_err()
                {
                    return Phase13aPlan::Failed;
                }
                let Ok(delta) = staking.plan_tx_slice(StakingTxSliceOp::WithdrawSelfBond {
                    validator: *validator,
                }) else {
                    return Phase13aPlan::Failed;
                };
                let amt = delta.withdrawn_amount();
                payouts.push((STAKING_POOL, tx.from, amt));
                planned_delta = Some(delta);
            }
            _ => return Phase13aPlan::Failed,
        }
    }

    let Some(delta) = planned_delta else {
        return Phase13aPlan::Failed;
    };

    let gas_used = tx.gas_limit - gas_remaining;
    if let Some(mut auth) = tx.delegation() {
        if auth.verify_and_spend_gas(gas_used, timestamp).is_err() {
            return Phase13aPlan::Failed;
        }
    }

    Phase13aPlan::Staking {
        delta,
        transfers,
        payouts,
        gas_used,
    }
}

fn bill_outbound_actor_messages_v2(
    outbound: &[crate::contract::ContractMessage],
    gas_remaining: &mut u64,
) -> bool {
    use bincode::Options;
    for msg in outbound {
        if msg.payload.is_empty() {
            if *gas_remaining < crate::svm::GAS_ACTOR_DELIVER {
                return false;
            }
            *gas_remaining -= crate::svm::GAS_ACTOR_DELIVER;
            continue;
        }
        if let Ok(body) = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_limit(16 * 1024 * 1024)
            .deserialize::<ActorSendBody>(&msg.payload)
        {
            if body.gas_budget > crate::svm::MAX_CONTRACT_ACTOR_GAS_BUDGET {
                return false;
            }
            let prepay = crate::svm::GAS_ACTOR_DELIVER.saturating_add(body.gas_budget);
            if *gas_remaining < prepay {
                return false;
            }
            *gas_remaining -= prepay;
        }
    }
    true
}

#[derive(Clone)]
enum StmAttemptOutcome {
    Ok {
        outcome: crate::contract::ContractOutcome,
        trace: crate::contract::StmExecutionTrace,
        gas_used: u64,
    },
    SpeculativeFail,
    PermanentFail,
}

#[allow(clippy::too_many_arguments)]
// GATE: STM contract call executor mirrors Svm::execute_inner call_with_context_hardened_at parameters.
fn execute_one_stm_tx(
    contracts: &crate::contract::ContractRegistry,
    mv_memory: &Arc<crate::contract::ContractMvMemory>,
    tx: &crate::sharding::Transaction,
    tx_idx: usize,
    contract: &[u8; 32],
    method: &[u8],
    args: &[i64],
    calldata: &[u8],
    nop_gas: u64,
    timestamp: u64,
    contract_block_hash: [u8; 32],
    wasm_pmm_hardening: bool,
    enforce_table_cap: bool,
    falcon_fuel_v2: bool,
    actor_mailbox_hardening: bool,
    contract_send_refusal: bool,
    local_shard: u32,
    sharded: bool,
    topology: Option<&crate::sharding::ShardTopology>,
) -> StmAttemptOutcome {
    use crate::contract::{ContractCallOptions, ContractError, MAX_CONTRACT_CALL_ARGS};
    use crate::svm::{contract_call_gas, MAX_CONTRACT_CALLDATA_BYTES, MAX_CONTRACT_METHOD_LEN};

    if method.len() > MAX_CONTRACT_METHOD_LEN
        || calldata.len() > MAX_CONTRACT_CALLDATA_BYTES
        || args.len() > MAX_CONTRACT_CALL_ARGS
    {
        return StmAttemptOutcome::PermanentFail;
    }

    let base_gas =
        nop_gas.saturating_add(contract_call_gas(method.len(), args.len(), calldata.len()));
    if tx.gas_limit < base_gas {
        return StmAttemptOutcome::PermanentFail;
    }
    let mut gas_remaining = tx.gas_limit - base_gas;

    let Ok(method_str) = std::str::from_utf8(method) else {
        return StmAttemptOutcome::PermanentFail;
    };

    let opts = ContractCallOptions {
        caller: tx.from,
        origin: tx.from,
        value: 0,
        block_time: timestamp,
        block_hash: contract_block_hash,
        hardened: wasm_pmm_hardening,
    };

    match contracts.call_with_stm_trace_with_gates(
        contract,
        method_str,
        args,
        calldata,
        gas_remaining,
        &opts,
        tx_idx,
        Arc::clone(mv_memory) as Arc<dyn crate::contract::StmStateView>,
        enforce_table_cap,
        falcon_fuel_v2,
    ) {
        Ok((outcome, trace)) => {
            if gas_remaining < outcome.fuel_used {
                return StmAttemptOutcome::SpeculativeFail;
            }
            gas_remaining -= outcome.fuel_used;
            if actor_mailbox_hardening
                && !bill_outbound_actor_messages_v2(&outcome.outbound_messages, &mut gas_remaining)
            {
                return StmAttemptOutcome::SpeculativeFail;
            }
            let gas_used = tx.gas_limit - gas_remaining;
            if let Some(mut auth) = tx.delegation() {
                if auth.verify_and_spend_gas(gas_used, timestamp).is_err() {
                    return StmAttemptOutcome::SpeculativeFail;
                }
            }
            if contract_send_refusal {
                if let Some(topo) = topology {
                    if outcome.outbound_messages.iter().any(|m| {
                        crate::svm::contract_recipient_is_cross_shard(
                            &m.recipient,
                            local_shard,
                            sharded,
                            topo,
                        )
                    }) {
                        return StmAttemptOutcome::SpeculativeFail;
                    }
                }
            }
            StmAttemptOutcome::Ok {
                outcome,
                trace,
                gas_used,
            }
        }
        Err(ContractError::OutOfFuel | ContractError::Trapped) => {
            StmAttemptOutcome::SpeculativeFail
        }
        Err(_) => StmAttemptOutcome::PermanentFail,
    }
}

// TEST-ONLY probe (O13): counts how many times the wave scheduler was
// consulted on THIS thread. Thread-local so parallel lib tests cannot
// perturb one another.
#[cfg(test)]
thread_local! {
    static O13_SCHEDULE_CALLS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn o13_schedule_probe_note_call() {
    O13_SCHEDULE_CALLS.with(|c| c.set(c.get() + 1));
}

#[cfg(test)]
fn o13_schedule_probe_calls() -> u64 {
    O13_SCHEDULE_CALLS.with(|c| c.get())
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
    /// Number of occupied slots in `writes` (`0..=3`: sender, optional
    /// sponsor, optional recipient). Inline fixed array removes one heap
    /// allocation per planned transaction (`OPT-PARALLEL-WAVE`).
    write_len: u8,
    /// Final `(address, balance, nonce)` of every account the transaction
    /// touched, in application order.
    writes: [([u8; 32], u64, u64); 3],
}

impl PlainTxPlan {
    #[inline]
    fn push_write(&mut self, entry: ([u8; 32], u64, u64)) {
        let idx = self.write_len as usize;
        debug_assert!(idx < self.writes.len());
        if idx < self.writes.len() {
            self.writes[idx] = entry;
            self.write_len += 1;
        }
    }

    #[inline]
    fn clear_writes(&mut self) {
        self.write_len = 0;
    }

    #[inline]
    fn writes(&self) -> &[([u8; 32], u64, u64)] {
        &self.writes[..self.write_len as usize]
    }
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
    fee_market_v2: bool,
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
    let fee =
        InMemoryStateEngine::fee_for_gas_at_v2(tx, 0, floor_base, 0, exec_hardening, fee_market_v2);
    // The failure price is `failure_fee_for` (the intrinsic envelope is
    // guaranteed consumption whether or not a payload ran); for a plain
    // transfer the two coincide, and the debug assertion pins that.
    let fail_fee =
        InMemoryStateEngine::failure_fee_for_v2(tx, floor_base, surcharge, fee_market_v2);
    debug_assert_eq!(fail_fee, fee.saturating_add(surcharge));

    // A live session-gate refusal is attributable: the floor is charged and
    // the nonce is consumed (the sequential path's `fail_with_floor!`).
    if tx.delegation().is_some() && !session_ok {
        if let Some((debited, balance, nonce)) = failure_fee_state(tx, sender, fail_fee) {
            plan.fee = debited;
            plan.push_write((tx.from, balance, nonce));
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
                plan.push_write((tx.from, ubal, unonce + 1));
                plan.push_write((auth.sponsor, sbal - fail_fee, snonce));
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
                    plan.push_write((tx.from, ubal, unonce + 1));
                    plan.push_write((auth.sponsor, sbal - fail_fee, snonce));
                }
                return plan;
            }
        }
        plan.applied = true;
        plan.fee = fail_fee;
        if tx.from == tx.to {
            // A self-transfer only pays the fee (from the sponsor): the
            // value goes straight back, the user nonce still advances.
            plan.push_write((tx.from, ubal, unonce + 1));
            plan.push_write((auth.sponsor, sbal - fail_fee, snonce));
            return plan;
        }
        plan.push_write((tx.from, ubal.saturating_sub(tx.amount), unonce + 1));
        if !cross_shard && auth.sponsor == tx.to {
            // The sponsor IS the recipient (`sponsored_grant()` only excludes
            // `sponsor == from`, so a third-party sponsor can name itself as
            // the payee). The sequential path debits the sponsor's fee FIRST
            // and credits the amount AFTERWARDS, so the final balance is
            // `(sbal - fail_fee) + tx.amount`. Emit ONE absolute write for
            // the sponsor: a separate recipient write would overwrite the fee
            // debit (last write wins in `commit_plain_plan`) and mint the fee.
            match (sbal - fail_fee).checked_add(tx.amount) {
                Some(final_balance) => plan.push_write((tx.to, final_balance, snonce)),
                None => {
                    // The credit would overflow: the failure-fee path
                    // (sponsor pays, user nonce advances) - same shape as
                    // the recipient-overflow arm below.
                    plan.applied = false;
                    plan.fee = 0;
                    plan.clear_writes();
                    if fail_fee > 0 && sbal >= fail_fee {
                        plan.fee = fail_fee;
                        plan.push_write((tx.from, ubal, unonce + 1));
                        plan.push_write((auth.sponsor, sbal - fail_fee, snonce));
                    }
                }
            }
            return plan;
        }
        plan.push_write((auth.sponsor, sbal - fail_fee, snonce));
        if !cross_shard {
            match recipient {
                Some((rbalance, rnonce)) => match rbalance.checked_add(tx.amount) {
                    Some(new_balance) => plan.push_write((tx.to, new_balance, rnonce)),
                    None => {
                        // The credit would overflow: the failure-fee path
                        // (sponsor pays, user nonce advances).
                        plan.applied = false;
                        plan.fee = 0;
                        plan.clear_writes();
                        if fail_fee > 0 && sbal >= fail_fee {
                            plan.fee = fail_fee;
                            plan.push_write((tx.from, ubal, unonce + 1));
                            plan.push_write((auth.sponsor, sbal - fail_fee, snonce));
                        }
                    }
                },
                None => {
                    plan.push_write((tx.to, tx.amount, 0));
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
            plan.push_write((tx.from, balance, nonce));
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
                plan.push_write((tx.from, balance, nonce));
            }
            return plan;
        }
    }

    plan.applied = true;
    plan.fee = fee;

    if tx.from == tx.to {
        // A self-transfer only pays the fee: the amount goes straight back.
        plan.push_write((tx.from, balance.saturating_sub(fee), nonce + 1));
        return plan;
    }

    plan.push_write((tx.from, balance.saturating_sub(total_cost), nonce + 1));

    if !cross_shard {
        match recipient {
            Some((rbalance, rnonce)) => match rbalance.checked_add(tx.amount) {
                Some(new_balance) => plan.push_write((tx.to, new_balance, rnonce)),
                None => {
                    // The credit would overflow: the sender is refunded and
                    // the floor is charged (the sequential path rolls the
                    // commit back and charges the same floor).
                    plan.applied = false;
                    plan.fee = 0;
                    plan.clear_writes();
                    if let Some((debited, balance, nonce)) = failure_fee_state(tx, sender, fail_fee)
                    {
                        plan.fee = debited;
                        plan.push_write((tx.from, balance, nonce));
                    }
                }
            },
            None => {
                // The recipient does not exist yet: it is created with the
                // transferred amount (nonce 0).
                plan.push_write((tx.to, tx.amount, 0));
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
    for (addr, balance, nonce) in plan.writes() {
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
    for (addr, balance, nonce) in plan.writes() {
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
        fee_market_v2: bool,
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

            // (b) PLAN - in parallel, on the rayon pool, with a minimum chunk
            // size of `parallel_plan_chunk()` and ZERO intermediate per-chunk
            // `Vec` allocations (`OPT-PARALLEL-WAVE`). IndexedParallelIterator
            // collects directly in wave order.
            let chunk = parallel_plan_chunk().min(wave.len().div_ceil(4).max(1));
            let plans: Vec<(usize, PlainTxPlan)> = wave
                .par_iter()
                .with_min_len(chunk)
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
                        fee_market_v2,
                    );
                    (i, plan)
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
                    fee_market_v2,
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

    /// Execute ONE transaction sequentially against live engine state.
    /// Shared by the sequential block path, legacy payload waves, and Phase 13a/13b
    /// collision/retry fallbacks so every path executes identical semantics.
    #[allow(clippy::too_many_arguments)]
    // GATE: per-tx sequential apply mirrors block-loop accumulators and floor inputs for bit-exact parity.
    async fn apply_single_tx_sequential(
        &self,
        tx: &crate::sharding::Transaction,
        i: usize,
        timestamp: u64,
        chain_height: u64,
        parent_block_hash: [u8; 32],
        admitted: bool,
        fee_floor: (u64, u64),
        vesting_floors: &HashMap<[u8; 32], u64>,
        exec_hardening: bool,
        fee_market_v2: bool,
        applied: &mut usize,
        failed: &mut usize,
        fees_collected: &mut u64,
        status: &mut [bool],
        fees: &mut [u64],
        events: &mut [Vec<crate::contract::ContractEvent>],
        trie_dirty: &mut Vec<([u8; 32], u64, u64)>,
        pq_keys_pinned: &mut bool,
    ) {
        macro_rules! fail_with_floor {
            ($tx:expr, $idx:expr) => {{
                *failed += 1;
                let (floor_base, surcharge) = fee_floor;
                let fee = Self::failure_fee_for_v2($tx, floor_base, surcharge, fee_market_v2);
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
                    *fees_collected = fees_collected.saturating_add(debited);
                    fees[$idx] = debited;
                } else {
                    let (debited, charged_state) = self.charge_failure_fee($tx, fee).await;
                    if let Some((balance, nonce)) = charged_state {
                        trie_dirty.push(($tx.from, balance, nonce));
                    }
                    *fees_collected = fees_collected.saturating_add(debited);
                    fees[$idx] = debited;
                }
            }};
        }

        if !admitted {
            *failed += 1;
            return;
        }
        if !tx.payload.is_empty() {
            let precheck = {
                let map = self.accounts.read().await;
                if let Some(auth) = tx.sponsored_grant() {
                    if let Some(sender) = map.get(&tx.from) {
                        if tx.nonce != sender.nonce {
                            2
                        } else if sender.balance < tx.amount {
                            4
                        } else {
                            let (floor_base, surcharge) = fee_floor;
                            let fee_total = tx.gas_limit.max(floor_base).saturating_add(surcharge);
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
                    *failed += 1;
                    return;
                }
                2..=4 => {
                    fail_with_floor!(tx, i);
                    return;
                }
                _ => {}
            }
        }
        if let Err(e) = self.session_gate(tx, timestamp).await {
            tracing::debug!(tx = i, "session gate: {e}");
            fail_with_floor!(tx, i);
            return;
        }
        let mut domain_snap: Option<PayloadDomainSnapshot> = None;
        let mut post_actions: Option<ExecPostActions> = None;
        let (transfers, payouts, burns, gas_used, tx_events) = if tx.payload.is_empty() {
            (Vec::new(), Vec::new(), Vec::new(), 0, Vec::new())
        } else {
            domain_snap = Some(
                self.snapshot_payload_domains_at(&tx.payload, exec_hardening)
                    .await,
            );
            match self
                .execute_payload_with_preverify_at_height_and_parent_restorable(
                    tx,
                    timestamp,
                    chain_height,
                    parent_block_hash,
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
                    return;
                }
                Ok((crate::svm::VmExecutionResult::Reverted(e), _)) => {
                    tracing::debug!(tx = i, "payload reverted: {e}");
                    fail_with_floor!(tx, i);
                    return;
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
                    return;
                }
            }
        };
        match self
            .commit_native_with_floor_at_opts(
                tx,
                gas_used,
                &transfers,
                &payouts,
                &burns,
                fee_floor.0,
                fee_floor.1,
                vesting_floors.get(&tx.from).copied(),
                vesting_floors,
                chain_height,
                false,
            )
            .await
        {
            Ok((mut touched, fee)) => {
                if tx.is_pq_activation() {
                    if let Some(env) = tx.pq_envelope_at_height(chain_height) {
                        if !env.is_implicit && env.pubkey.is_some() {
                            *pq_keys_pinned = true;
                        }
                    }
                }
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
                trie_dirty.extend(touched);
                *fees_collected = fees_collected.saturating_add(fee);
                *applied += 1;
                status[i] = true;
                fees[i] = fee;
                events[i] = tx_events;
                self.session_note_applied(
                    tx,
                    InMemoryStateEngine::billed_gas_at(tx, gas_used, exec_hardening),
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

    /// Execute one non-plain payload wave with Phase 13a (parallel Token/Market/Staking)
    /// and Phase 13b (Block-STM `ContractMvMemory` for `CallContract`/`CallContractArgs`).
    ///
    /// Returns `true` if the wave was handled by v2, or `false` if any transaction
    /// in the wave uses an unsupported opcode / PQ activation and should fall back
    /// to the legacy sequential loop.
    #[allow(clippy::too_many_arguments)]
    // GATE: v2 wave executor mirrors block-loop accumulators and height-gated VM flags.
    async fn apply_v2_payload_wave(
        &self,
        txs: &[crate::sharding::Transaction],
        wave: &[usize],
        admitted: &[bool],
        fee_floors: &[(u64, u64)],
        vesting_floors: &HashMap<[u8; 32], u64>,
        timestamp: u64,
        chain_height: u64,
        parent_block_hash: [u8; 32],
        exec_hardening: bool,
        fee_market_v2: bool,
        applied: &mut usize,
        failed: &mut usize,
        fees_collected: &mut u64,
        status: &mut [bool],
        fees: &mut [u64],
        events: &mut [Vec<crate::contract::ContractEvent>],
        trie_dirty: &mut Vec<([u8; 32], u64, u64)>,
        pq_keys_pinned: &mut bool,
    ) -> bool {
        let wasm_pmm_hardening =
            crate::chain_spec::wasm_xshard_pmm_hardening_active_at(chain_height);
        let mut kinds: Vec<TxWaveKind<'_>> = Vec::with_capacity(wave.len());
        let mut has_token = false;
        let mut has_market = false;
        let mut has_staking = false;
        let mut has_contract = false;
        let mut called_contracts: HashSet<[u8; 32]> = HashSet::new();

        for &i in wave {
            let kind = classify_tx_v2(&txs[i], exec_hardening);
            match &kind {
                TxWaveKind::Unsupported => return false,
                TxWaveKind::Plain => {}
                TxWaveKind::Token => has_token = true,
                TxWaveKind::Market { .. } => has_market = true,
                TxWaveKind::Staking => has_staking = true,
                TxWaveKind::Contract { contract, .. } => {
                    if !wasm_pmm_hardening {
                        return false;
                    }
                    has_contract = true;
                    called_contracts.insert(*contract);
                }
            }
            kinds.push(kind);
        }

        // 1) Precheck & session gate in deterministic order.
        let mut pre_gates: Vec<PreGate> = Vec::with_capacity(wave.len());
        {
            let map = self.accounts.read().await;
            for (pos, &i) in wave.iter().enumerate() {
                let tx = &txs[i];
                if !admitted[i] {
                    pre_gates.push(PreGate::NotAdmitted);
                    continue;
                }
                if matches!(kinds[pos], TxWaveKind::Plain) {
                    let sbal = map.get(&tx.from).map(|a| a.balance).unwrap_or(0);
                    pre_gates.push(PreGate::Ready {
                        sender_balance: sbal,
                    });
                    continue;
                }
                let precheck = if let Some(auth) = tx.sponsored_grant() {
                    if let Some(sender) = map.get(&tx.from) {
                        if tx.nonce != sender.nonce {
                            2
                        } else if sender.balance < tx.amount {
                            4
                        } else {
                            let (floor_base, surcharge) = fee_floors[i];
                            let fee_total = tx.gas_limit.max(floor_base).saturating_add(surcharge);
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
                };
                match precheck {
                    1 => pre_gates.push(PreGate::MissingSender),
                    2..=4 => pre_gates.push(PreGate::PrecheckFail),
                    _ => {
                        let sbal = map.get(&tx.from).map(|a| a.balance).unwrap_or(0);
                        pre_gates.push(PreGate::Ready {
                            sender_balance: sbal,
                        });
                    }
                }
            }
        }
        for (pos, &i) in wave.iter().enumerate() {
            if matches!(pre_gates[pos], PreGate::Ready { .. })
                && txs[i].delegation().is_some()
                && self.session_gate(&txs[i], timestamp).await.is_err()
            {
                pre_gates[pos] = PreGate::GateFail;
            }
        }

        // 2) Phase 13a: parallel planning for Token, Market, and Staking txs.
        let p13a_indices: Vec<usize> = wave
            .iter()
            .enumerate()
            .filter_map(|(pos, _)| {
                if !matches!(pre_gates[pos], PreGate::Ready { .. }) {
                    return None;
                }
                match kinds[pos] {
                    TxWaveKind::Token | TxWaveKind::Market { .. } | TxWaveKind::Staking => {
                        Some(pos)
                    }
                    _ => None,
                }
            })
            .collect();

        let mut p13a_plans: Vec<Option<Phase13aPlan>> = (0..wave.len()).map(|_| None).collect();
        let mut initial_rewards_pool: u64 = 0;
        let mut market_quote_id: Option<[u8; 32]> = None;

        if !p13a_indices.is_empty() {
            let pq_lifecycle = crate::pq_registry::pq_lifecycle_active_at(chain_height);
            let tokens_guard = if has_token || has_market {
                Some(self.tokens.read().await)
            } else {
                None
            };
            let orderbooks_guard = if has_market {
                Some(self.orderbooks.read().await)
            } else {
                None
            };
            let staking_guard = if has_staking {
                let g = self.staking.read().await;
                initial_rewards_pool = g.rewards_pool;
                Some(g)
            } else {
                None
            };
            let oracle_guard = if has_market {
                Some(self.oracle.read().await)
            } else {
                None
            };
            let escrow_guard = if has_market {
                Some(self.order_escrow.read().await)
            } else {
                None
            };
            let accounts_guard = if has_market {
                Some(self.accounts.read().await)
            } else {
                None
            };
            if has_market {
                market_quote_id = *self.pmm_usdt_token.read().await;
            }

            let tokens_ref = tokens_guard.as_deref();
            let orderbooks_ref = orderbooks_guard.as_deref();
            let staking_ref = staking_guard.as_deref();
            let oracle_ref = oracle_guard.as_deref();
            let escrow_ref = escrow_guard.as_deref();
            let accounts_ref = accounts_guard.as_deref();

            let results: Vec<(usize, Phase13aPlan)> = p13a_indices
                .par_iter()
                .map(|&pos| {
                    let i = wave[pos];
                    let tx = &txs[i];
                    let PreGate::Ready { sender_balance } = pre_gates[pos] else {
                        return (pos, Phase13aPlan::Failed);
                    };
                    let plan = match kinds[pos] {
                        TxWaveKind::Token => {
                            if let Some(tokens) = tokens_ref {
                                plan_token_tx(tx, tokens, timestamp, exec_hardening)
                            } else {
                                Phase13aPlan::Failed
                            }
                        }
                        TxWaveKind::Market { pair_id } => {
                            if let (
                                Some(tokens),
                                Some(books),
                                Some(escrow),
                                Some(oracle),
                                Some(accts),
                            ) = (
                                tokens_ref,
                                orderbooks_ref,
                                escrow_ref,
                                oracle_ref,
                                accounts_ref,
                            ) {
                                plan_market_tx(
                                    tx,
                                    pair_id,
                                    sender_balance,
                                    timestamp,
                                    exec_hardening,
                                    tokens,
                                    books,
                                    escrow,
                                    oracle,
                                    accts,
                                    market_quote_id,
                                )
                            } else {
                                Phase13aPlan::Failed
                            }
                        }
                        TxWaveKind::Staking => {
                            if let Some(staking) = staking_ref {
                                plan_staking_tx(
                                    tx,
                                    sender_balance,
                                    timestamp,
                                    exec_hardening,
                                    pq_lifecycle,
                                    staking,
                                )
                            } else {
                                Phase13aPlan::Failed
                            }
                        }
                        _ => Phase13aPlan::Failed,
                    };
                    (pos, plan)
                })
                .collect();

            for (pos, plan) in results {
                p13a_plans[pos] = Some(plan);
            }
        } else if has_staking {
            initial_rewards_pool = self.staking.read().await.rewards_pool;
        }

        // 3) Phase 13b: Block-STM parallel execution for CallContract / CallContractArgs.
        struct StmSlot {
            pos: usize,
            tx_idx: usize,
            contract: [u8; 32],
            incarnation: u32,
            finalized: bool,
            finalized_round: usize,
            ran_at_round: usize,
            needs_rerun: bool,
            fallback_seq: bool,
            last_attempt: Option<StmAttemptOutcome>,
        }

        let mut stm_slots: Vec<StmSlot> = Vec::new();
        let mut stm_pos_to_slot: HashMap<usize, usize> = HashMap::new();
        for (pos, &i) in wave.iter().enumerate() {
            if matches!(pre_gates[pos], PreGate::Ready { .. }) {
                if let TxWaveKind::Contract { contract, .. } = kinds[pos] {
                    let sidx = stm_slots.len();
                    stm_pos_to_slot.insert(pos, sidx);
                    stm_slots.push(StmSlot {
                        pos,
                        tx_idx: i,
                        contract,
                        incarnation: 0,
                        finalized: false,
                        finalized_round: 0,
                        ran_at_round: 0,
                        needs_rerun: true,
                        fallback_seq: false,
                        last_attempt: None,
                    });
                }
            }
        }

        let mut synced_base_balances: HashMap<[u8; 32], u64> = HashMap::new();
        // Outbound `value` spent by each contract's committed STM calls, used
        // to land the same registry balance the sequential path would hold.
        let mut contract_balance_spent: HashMap<[u8; 32], u64> = HashMap::new();
        let mut mv_memory_opt: Option<Arc<crate::contract::ContractMvMemory>> = None;

        if has_contract && !stm_slots.is_empty() {
            let enforce_table_cap =
                crate::chain_spec::wasm_table_elements_cap_active_at(chain_height);
            let falcon_fuel_v2 = crate::chain_spec::falcon_host_fuel_v2_active_at(chain_height);
            let actor_mailbox_hardening =
                crate::chain_spec::actor_mailbox_hardening_active_at(chain_height);
            let contract_send_refusal =
                crate::chain_spec::wasm_xshard_contract_send_refusal_active_at(chain_height);
            let contract_block_hash =
                if crate::chain_spec::contract_block_hash_active_at(chain_height) {
                    parent_block_hash
                } else {
                    [0u8; 32]
                };
            let local_shard = self.shard_id();
            let sharded = self.cross_shard_enabled();
            let topology = if contract_send_refusal {
                Some(self.shard_topology.read().await.clone())
            } else {
                None
            };

            let contracts_guard = self.contracts.read().await;
            {
                let accts = self.accounts.read().await;
                for &addr in &called_contracts {
                    if let (Some(acc), Some(c)) = (accts.get(&addr), contracts_guard.get(&addr)) {
                        if acc.balance > c.balance {
                            synced_base_balances.insert(addr, acc.balance);
                        }
                    }
                }
            }

            let base_reg: Cow<'_, crate::contract::ContractRegistry> =
                if synced_base_balances.is_empty() {
                    Cow::Borrowed(&*contracts_guard)
                } else {
                    let mut cloned = (*contracts_guard).clone();
                    for (&addr, &bal) in &synced_base_balances {
                        if let Some(c) = cloned.contracts.get_mut(&addr) {
                            c.balance = bal;
                        }
                    }
                    Cow::Owned(cloned)
                };

            let mv_memory = Arc::new(crate::contract::ContractMvMemory::new(base_reg.as_ref()));
            drop(base_reg);

            for round in 0..=MAX_STM_RETRIES {
                let to_run: Vec<usize> = stm_slots
                    .iter()
                    .enumerate()
                    .filter_map(|(sidx, s)| (!s.finalized && s.needs_rerun).then_some(sidx))
                    .collect();
                if to_run.is_empty() {
                    break;
                }

                let round_results: Vec<(usize, StmAttemptOutcome)> = to_run
                    .par_iter()
                    .map(|&sidx| {
                        let slot = &stm_slots[sidx];
                        let tx = &txs[slot.tx_idx];
                        let TxWaveKind::Contract {
                            contract,
                            method,
                            args,
                            calldata,
                            nop_gas,
                        } = &kinds[slot.pos]
                        else {
                            return (sidx, StmAttemptOutcome::PermanentFail);
                        };
                        let out = execute_one_stm_tx(
                            &contracts_guard,
                            &mv_memory,
                            tx,
                            slot.tx_idx,
                            contract,
                            method,
                            args,
                            calldata,
                            *nop_gas,
                            timestamp,
                            contract_block_hash,
                            wasm_pmm_hardening,
                            enforce_table_cap,
                            falcon_fuel_v2,
                            actor_mailbox_hardening,
                            contract_send_refusal,
                            local_shard,
                            sharded,
                            topology.as_ref(),
                        );
                        (sidx, out)
                    })
                    .collect();

                for (sidx, out) in round_results {
                    let slot = &mut stm_slots[sidx];
                    slot.last_attempt = Some(out);
                    slot.ran_at_round = round;
                    slot.needs_rerun = false;
                }

                // Validate in ascending tx_idx order per contract.
                let mut blocked_by_unfinalized: HashSet<[u8; 32]> = HashSet::new();
                let mut last_write_round_below: HashMap<[u8; 32], usize> = HashMap::new();

                for slot in &mut stm_slots {
                    if slot.finalized {
                        if matches!(slot.last_attempt, Some(StmAttemptOutcome::Ok { .. })) {
                            let entry = last_write_round_below
                                .entry(slot.contract)
                                .or_insert(slot.finalized_round);
                            *entry = (*entry).max(slot.finalized_round);
                        }
                        continue;
                    }
                    if blocked_by_unfinalized.contains(&slot.contract) {
                        if round == MAX_STM_RETRIES {
                            slot.fallback_seq = true;
                        }
                        continue;
                    }
                    match slot.last_attempt.as_ref() {
                        None => {
                            slot.needs_rerun = true;
                            blocked_by_unfinalized.insert(slot.contract);
                        }
                        Some(StmAttemptOutcome::PermanentFail) => {
                            slot.finalized = true;
                        }
                        Some(StmAttemptOutcome::SpeculativeFail) => {
                            let earlier_wrote_since = last_write_round_below
                                .get(&slot.contract)
                                .is_some_and(|&w_round| w_round >= slot.ran_at_round);
                            if earlier_wrote_since {
                                mv_memory.invalidate_tx(slot.tx_idx);
                                slot.incarnation += 1;
                                slot.needs_rerun = true;
                                blocked_by_unfinalized.insert(slot.contract);
                            } else {
                                slot.finalized = true;
                            }
                        }
                        Some(StmAttemptOutcome::Ok { trace, .. }) => {
                            if mv_memory.validate_reads(slot.tx_idx, trace) {
                                mv_memory.record_incarnation(
                                    slot.tx_idx,
                                    slot.incarnation,
                                    slot.contract,
                                    trace,
                                );
                                slot.finalized = true;
                                slot.finalized_round = round;
                                last_write_round_below.insert(slot.contract, round);
                            } else {
                                mv_memory.invalidate_tx(slot.tx_idx);
                                slot.incarnation += 1;
                                slot.needs_rerun = true;
                                blocked_by_unfinalized.insert(slot.contract);
                            }
                        }
                    }
                    if !slot.finalized && round == MAX_STM_RETRIES {
                        slot.fallback_seq = true;
                    }
                }
            }

            drop(contracts_guard);
            mv_memory_opt = Some(mv_memory);
        }

        // 4) Deterministic ascending tx_idx commit pass.
        let mut committed_native_addrs: HashSet<[u8; 32]> = HashSet::new();
        let mut native_credited_contracts: HashSet<[u8; 32]> = HashSet::new();
        let mut wusdt_touched_in_wave = false;
        let mut committed_token_ids: HashSet<[u8; 32]> = HashSet::new();
        let mut remaining_rewards_pool = initial_rewards_pool;

        let mut pending_token_deltas: Vec<(crate::token::TokenTxDelta, Vec<[u8; 32]>)> = Vec::new();
        let mut pending_market_commits: Vec<(
            u32,
            crate::orderbook::OrderbookActor,
            PlannedClobEffects,
        )> = Vec::new();
        let mut pending_staking_deltas: Vec<crate::staking::StakingTxDelta> = Vec::new();
        let mut stm_committed_indices: Vec<(usize, [u8; 32], Vec<u8>)> = Vec::new();
        let mut stm_fallback_remainder = false;

        macro_rules! record_tx_addrs {
            ($tx:expr) => {{
                committed_native_addrs.insert($tx.from);
                committed_native_addrs.insert($tx.to);
                if let Some(sp) = $tx.effective_sponsor() {
                    committed_native_addrs.insert(sp);
                }
                if $tx.amount > 0 && called_contracts.contains(&$tx.to) {
                    native_credited_contracts.insert($tx.to);
                }
                if called_contracts.contains(&$tx.from) {
                    native_credited_contracts.insert($tx.from);
                }
                if let Some(sp) = $tx.effective_sponsor() {
                    if called_contracts.contains(&sp) {
                        native_credited_contracts.insert(sp);
                    }
                }
            }};
        }

        macro_rules! fail_tx_with_floor {
            ($tx:expr, $idx:expr) => {{
                *failed += 1;
                let (floor_base, surcharge) = fee_floors[$idx];
                let fee = Self::failure_fee_for_v2($tx, floor_base, surcharge, fee_market_v2);
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
                    *fees_collected = fees_collected.saturating_add(debited);
                    fees[$idx] = debited;
                } else {
                    let (debited, charged_state) = self.charge_failure_fee($tx, fee).await;
                    if let Some((balance, nonce)) = charged_state {
                        trie_dirty.push(($tx.from, balance, nonce));
                    }
                    *fees_collected = fees_collected.saturating_add(debited);
                    fees[$idx] = debited;
                }
                committed_native_addrs.insert($tx.from);
                if let Some(sp) = $tx.effective_sponsor() {
                    committed_native_addrs.insert(sp);
                }
            }};
        }

        macro_rules! flush_pending_domains {
            () => {{
                if !pending_token_deltas.is_empty() {
                    let mut tokens = self.tokens_write().await;
                    for (delta, _ids) in pending_token_deltas.drain(..) {
                        tokens.apply_tx_delta(delta);
                    }
                }
                if !pending_market_commits.is_empty() {
                    let mut books = self.orderbooks_write().await;
                    let mut escrow = self.order_escrow_write().await;
                    let has_tok = pending_market_commits
                        .iter()
                        .any(|(_, _, c)| c.token_delta.is_some());
                    let mut tokens_opt = if has_tok {
                        Some(self.tokens_write().await)
                    } else {
                        None
                    };
                    let mut trie_opt = if has_tok {
                        Some(self.state_trie.write().await)
                    } else {
                        None
                    };
                    for (pair_id, book_after, clob) in pending_market_commits.drain(..) {
                        books.apply_pair_book(pair_id, book_after);
                        for (k, v_opt) in clob.escrow_updates {
                            match v_opt {
                                Some(rec) => {
                                    escrow.insert(k, rec);
                                }
                                None => {
                                    escrow.remove(&k);
                                }
                            }
                        }
                        if let (Some(td), Some(tokens), Some(trie)) =
                            (clob.token_delta, tokens_opt.as_mut(), trie_opt.as_mut())
                        {
                            tokens.apply_tx_delta(td);
                            if let Some(q) = clob.quote_id {
                                for acct in &clob.token_touched {
                                    let bal = tokens.balance_of(&q, acct);
                                    let key = token_balance_key(&q, acct);
                                    if bal == 0 {
                                        trie.remove(&key);
                                    } else {
                                        trie.insert(&key, &bal.to_be_bytes());
                                    }
                                }
                                if clob.supply_dirty {
                                    if let Some(supply) =
                                        tokens.get(&q).map(|t| t.metadata.total_supply)
                                    {
                                        trie.insert(&token_supply_key(&q), &supply.to_be_bytes());
                                    }
                                }
                            }
                        }
                    }
                }
                if !pending_staking_deltas.is_empty() {
                    let mut ledger = self.staking_write().await;
                    for delta in pending_staking_deltas.drain(..) {
                        let _ = ledger.apply_tx_delta(delta);
                    }
                }
                if !stm_committed_indices.is_empty() {
                    if let Some(ref mv) = mv_memory_opt {
                        let mut contracts = self.contracts_write().await;
                        mv.commit_into_registry(&mut contracts);
                        for (idx, caddr, ret_data) in stm_committed_indices.drain(..) {
                            if let Some(&bal) = synced_base_balances.get(&caddr) {
                                if let Some(c) = contracts.contracts.get_mut(&caddr) {
                                    // Sequential `ensure_working` commits the
                                    // account-synced base and then debits the
                                    // value each call sent out. Reproduce that
                                    // exact registry balance (absolute writes,
                                    // so re-applying a flush is idempotent).
                                    let spent =
                                        contract_balance_spent.get(&caddr).copied().unwrap_or(0);
                                    c.balance = bal.saturating_sub(spent);
                                }
                            }
                            contracts.last_return_data = ret_data;
                            mv.invalidate_tx(idx);
                        }
                    }
                }
            }};
        }

        for (pos, &i) in wave.iter().enumerate() {
            let tx = &txs[i];

            if stm_fallback_remainder && matches!(kinds[pos], TxWaveKind::Contract { .. }) {
                flush_pending_domains!();
                self.apply_single_tx_sequential(
                    tx,
                    i,
                    timestamp,
                    chain_height,
                    parent_block_hash,
                    admitted[i],
                    fee_floors[i],
                    vesting_floors,
                    exec_hardening,
                    fee_market_v2,
                    applied,
                    failed,
                    fees_collected,
                    status,
                    fees,
                    events,
                    trie_dirty,
                    pq_keys_pinned,
                )
                .await;
                if let TxWaveKind::Contract { contract, .. } = &kinds[pos] {
                    committed_native_addrs.insert(*contract);
                }
                record_tx_addrs!(tx);
                continue;
            }

            let sender_collided = committed_native_addrs.contains(&tx.from)
                || tx
                    .effective_sponsor()
                    .is_some_and(|s| committed_native_addrs.contains(&s));

            match &kinds[pos] {
                TxWaveKind::Plain => {
                    if sender_collided || committed_native_addrs.contains(&tx.to) {
                        flush_pending_domains!();
                    }
                    self.apply_single_tx_sequential(
                        tx,
                        i,
                        timestamp,
                        chain_height,
                        parent_block_hash,
                        admitted[i],
                        fee_floors[i],
                        vesting_floors,
                        exec_hardening,
                        fee_market_v2,
                        applied,
                        failed,
                        fees_collected,
                        status,
                        fees,
                        events,
                        trie_dirty,
                        pq_keys_pinned,
                    )
                    .await;
                    record_tx_addrs!(tx);
                    continue;
                }
                TxWaveKind::Token => {
                    let touches_wusdt = market_quote_id.is_some_and(|qid| {
                        tx.payload.iter().any(|op| {
                            matches!(
                                op,
                                crate::svm::OpCode::SysCallTokenTransfer { token_id, .. }
                                    | crate::svm::OpCode::SysCallTokenTransferFrom { token_id, .. }
                                    | crate::svm::OpCode::SysCallTokenApprove { token_id, .. }
                                    | crate::svm::OpCode::SysCallTokenMint { token_id, .. }
                                    | crate::svm::OpCode::SysCallTokenBurn { token_id, .. }
                                    | crate::svm::OpCode::SysCallTokenBalanceOf { token_id, .. }
                                    if *token_id == qid
                            )
                        })
                    });
                    if sender_collided || (wusdt_touched_in_wave && touches_wusdt) {
                        flush_pending_domains!();
                        self.apply_single_tx_sequential(
                            tx,
                            i,
                            timestamp,
                            chain_height,
                            parent_block_hash,
                            admitted[i],
                            fee_floors[i],
                            vesting_floors,
                            exec_hardening,
                            fee_market_v2,
                            applied,
                            failed,
                            fees_collected,
                            status,
                            fees,
                            events,
                            trie_dirty,
                            pq_keys_pinned,
                        )
                        .await;
                        record_tx_addrs!(tx);
                        if touches_wusdt {
                            wusdt_touched_in_wave = true;
                        }
                        continue;
                    }
                }
                TxWaveKind::Market { .. } => {
                    let plan_collides = match p13a_plans[pos].as_ref() {
                        Some(Phase13aPlan::Market { clob, .. }) => {
                            sender_collided
                                || clob
                                    .native_touched_addrs
                                    .iter()
                                    .any(|a| committed_native_addrs.contains(a))
                                || ((clob.token_delta.is_some()
                                    || market_quote_id
                                        .is_some_and(|q| committed_token_ids.contains(&q)))
                                    && (wusdt_touched_in_wave
                                        || market_quote_id
                                            .is_some_and(|q| committed_token_ids.contains(&q))))
                        }
                        Some(Phase13aPlan::MarketFailed { makers }) => {
                            sender_collided
                                || makers.iter().any(|m| committed_native_addrs.contains(m))
                                || wusdt_touched_in_wave
                                || market_quote_id.is_some_and(|q| committed_token_ids.contains(&q))
                        }
                        _ => sender_collided || wusdt_touched_in_wave,
                    };
                    if plan_collides {
                        flush_pending_domains!();
                        self.apply_single_tx_sequential(
                            tx,
                            i,
                            timestamp,
                            chain_height,
                            parent_block_hash,
                            admitted[i],
                            fee_floors[i],
                            vesting_floors,
                            exec_hardening,
                            fee_market_v2,
                            applied,
                            failed,
                            fees_collected,
                            status,
                            fees,
                            events,
                            trie_dirty,
                            pq_keys_pinned,
                        )
                        .await;
                        record_tx_addrs!(tx);
                        if let Some(Phase13aPlan::Market { clob, .. }) = p13a_plans[pos].as_ref() {
                            committed_native_addrs.extend(&clob.native_touched_addrs);
                            for &addr in &clob.native_touched_addrs {
                                if called_contracts.contains(&addr) {
                                    native_credited_contracts.insert(addr);
                                }
                            }
                            if clob.token_delta.is_some() {
                                wusdt_touched_in_wave = true;
                            }
                        } else {
                            if let Some(Phase13aPlan::MarketFailed { makers }) =
                                p13a_plans[pos].as_ref()
                            {
                                committed_native_addrs.extend(makers);
                            }
                            native_credited_contracts.extend(&called_contracts);
                            wusdt_touched_in_wave = true;
                        }
                        continue;
                    }
                }
                TxWaveKind::Staking => {
                    if sender_collided {
                        flush_pending_domains!();
                        self.apply_single_tx_sequential(
                            tx,
                            i,
                            timestamp,
                            chain_height,
                            parent_block_hash,
                            admitted[i],
                            fee_floors[i],
                            vesting_floors,
                            exec_hardening,
                            fee_market_v2,
                            applied,
                            failed,
                            fees_collected,
                            status,
                            fees,
                            events,
                            trie_dirty,
                            pq_keys_pinned,
                        )
                        .await;
                        record_tx_addrs!(tx);
                        if let Some(Phase13aPlan::Staking {
                            transfers, payouts, ..
                        }) = p13a_plans[pos].as_ref()
                        {
                            for (to, amt) in transfers {
                                if *amt > 0 {
                                    committed_native_addrs.insert(*to);
                                    if called_contracts.contains(to) {
                                        native_credited_contracts.insert(*to);
                                    }
                                }
                            }
                            for (payer, bene, amt) in payouts {
                                if *amt > 0 {
                                    committed_native_addrs.insert(*payer);
                                    committed_native_addrs.insert(*bene);
                                    if called_contracts.contains(payer) {
                                        native_credited_contracts.insert(*payer);
                                    }
                                    if called_contracts.contains(bene) {
                                        native_credited_contracts.insert(*bene);
                                    }
                                }
                            }
                        }
                        remaining_rewards_pool = self.staking.read().await.rewards_pool;
                        continue;
                    }
                }
                TxWaveKind::Contract { contract, .. } => {
                    let slot = stm_pos_to_slot.get(&pos).map(|&sidx| &stm_slots[sidx]);
                    let need_fallback = sender_collided
                        || native_credited_contracts.contains(contract)
                        || slot.is_some_and(|s| s.fallback_seq);
                    if need_fallback {
                        stm_fallback_remainder = true;
                        // This contract tx and every LATER contract tx in the
                        // wave will run through the sequential executor. Drop
                        // their speculative mv write-sets first: the flush
                        // below would otherwise publish a not-yet-committed
                        // write-set into the live registry, and the sequential
                        // re-execution would apply it a second time.
                        if let Some(ref mv) = mv_memory_opt {
                            for s in &stm_slots {
                                if s.pos >= pos {
                                    mv.invalidate_tx(s.tx_idx);
                                }
                            }
                        }
                        flush_pending_domains!();
                        self.apply_single_tx_sequential(
                            tx,
                            i,
                            timestamp,
                            chain_height,
                            parent_block_hash,
                            admitted[i],
                            fee_floors[i],
                            vesting_floors,
                            exec_hardening,
                            fee_market_v2,
                            applied,
                            failed,
                            fees_collected,
                            status,
                            fees,
                            events,
                            trie_dirty,
                            pq_keys_pinned,
                        )
                        .await;
                        committed_native_addrs.insert(*contract);
                        record_tx_addrs!(tx);
                        continue;
                    }
                }
                TxWaveKind::Unsupported => unreachable!("checked above"),
            }

            // Pre-gate failures (identical to sequential).
            match pre_gates[pos] {
                PreGate::NotAdmitted | PreGate::MissingSender => {
                    *failed += 1;
                    continue;
                }
                PreGate::PrecheckFail | PreGate::GateFail => {
                    fail_tx_with_floor!(tx, i);
                    continue;
                }
                PreGate::Ready { .. } => {}
            }

            // Commit Phase 13a or Phase 13b outcome.
            match &kinds[pos] {
                TxWaveKind::Token => match p13a_plans[pos].take() {
                    Some(Phase13aPlan::Token {
                        delta,
                        token_ids,
                        gas_used,
                    }) => {
                        match self
                            .commit_native_with_floor_at_opts(
                                tx,
                                gas_used,
                                &[],
                                &[],
                                &[],
                                fee_floors[i].0,
                                fee_floors[i].1,
                                vesting_floors.get(&tx.from).copied(),
                                vesting_floors,
                                chain_height,
                                false,
                            )
                            .await
                        {
                            Ok((touched, fee)) => {
                                for tid in &token_ids {
                                    committed_token_ids.insert(*tid);
                                }
                                pending_token_deltas.push((delta, token_ids));
                                trie_dirty.extend(touched);
                                *fees_collected = fees_collected.saturating_add(fee);
                                *applied += 1;
                                status[i] = true;
                                fees[i] = fee;
                                self.session_note_applied(
                                    tx,
                                    InMemoryStateEngine::billed_gas_at(
                                        tx,
                                        gas_used,
                                        exec_hardening,
                                    ),
                                )
                                .await;
                                record_tx_addrs!(tx);
                            }
                            Err(_) => {
                                flush_pending_domains!();
                                self.sync_aux_trie().await;
                                fail_tx_with_floor!(tx, i);
                            }
                        }
                    }
                    _ => {
                        fail_tx_with_floor!(tx, i);
                    }
                },
                TxWaveKind::Market { .. } => match p13a_plans[pos].take() {
                    Some(Phase13aPlan::Market {
                        pair_id,
                        book_after,
                        clob,
                        gas_used,
                    }) => {
                        let native_res = self
                            .apply_planned_clob_native_moves(&clob.native_moves)
                            .await;
                        match native_res {
                            Err(_) => {
                                fail_tx_with_floor!(tx, i);
                            }
                            Ok((clob_touched, clob_snap)) => {
                                match self
                                    .commit_native_with_floor_at_opts(
                                        tx,
                                        gas_used,
                                        &[],
                                        &[],
                                        &[],
                                        fee_floors[i].0,
                                        fee_floors[i].1,
                                        vesting_floors.get(&tx.from).copied(),
                                        vesting_floors,
                                        chain_height,
                                        false,
                                    )
                                    .await
                                {
                                    Ok((commit_touched, fee)) => {
                                        committed_native_addrs.extend(&clob.native_touched_addrs);
                                        for &addr in &clob.native_touched_addrs {
                                            if called_contracts.contains(&addr) {
                                                native_credited_contracts.insert(addr);
                                            }
                                        }
                                        if clob.token_delta.is_some() {
                                            wusdt_touched_in_wave = true;
                                        }
                                        trie_dirty.extend(clob_touched);
                                        trie_dirty.extend(commit_touched);
                                        pending_market_commits.push((pair_id, book_after, clob));
                                        *fees_collected = fees_collected.saturating_add(fee);
                                        *applied += 1;
                                        status[i] = true;
                                        fees[i] = fee;
                                        self.session_note_applied(
                                            tx,
                                            InMemoryStateEngine::billed_gas_at(
                                                tx,
                                                gas_used,
                                                exec_hardening,
                                            ),
                                        )
                                        .await;
                                        record_tx_addrs!(tx);
                                    }
                                    Err(_) => {
                                        self.restore_native_accounts_snapshot(&clob_snap).await;
                                        fail_tx_with_floor!(tx, i);
                                    }
                                }
                            }
                        }
                    }
                    _ => {
                        fail_tx_with_floor!(tx, i);
                    }
                },
                TxWaveKind::Staking => match p13a_plans[pos].take() {
                    Some(Phase13aPlan::Staking {
                        delta,
                        transfers,
                        payouts,
                        gas_used,
                    }) => {
                        if delta.rewards_pool_debit > remaining_rewards_pool {
                            fail_tx_with_floor!(tx, i);
                        } else {
                            match self
                                .commit_native_with_floor_at_opts(
                                    tx,
                                    gas_used,
                                    &transfers,
                                    &payouts,
                                    &[],
                                    fee_floors[i].0,
                                    fee_floors[i].1,
                                    vesting_floors.get(&tx.from).copied(),
                                    vesting_floors,
                                    chain_height,
                                    false,
                                )
                                .await
                            {
                                Ok((touched, fee)) => {
                                    remaining_rewards_pool -= delta.rewards_pool_debit;
                                    for (to, amt) in &transfers {
                                        if *amt > 0 {
                                            committed_native_addrs.insert(*to);
                                            if called_contracts.contains(to) {
                                                native_credited_contracts.insert(*to);
                                            }
                                        }
                                    }
                                    for (payer, bene, amt) in &payouts {
                                        if *amt > 0 {
                                            committed_native_addrs.insert(*payer);
                                            committed_native_addrs.insert(*bene);
                                            if called_contracts.contains(payer) {
                                                native_credited_contracts.insert(*payer);
                                            }
                                            if called_contracts.contains(bene) {
                                                native_credited_contracts.insert(*bene);
                                            }
                                        }
                                    }
                                    pending_staking_deltas.push(delta);
                                    trie_dirty.extend(touched);
                                    *fees_collected = fees_collected.saturating_add(fee);
                                    *applied += 1;
                                    status[i] = true;
                                    fees[i] = fee;
                                    self.session_note_applied(
                                        tx,
                                        InMemoryStateEngine::billed_gas_at(
                                            tx,
                                            gas_used,
                                            exec_hardening,
                                        ),
                                    )
                                    .await;
                                    record_tx_addrs!(tx);
                                }
                                Err(_) => {
                                    fail_tx_with_floor!(tx, i);
                                }
                            }
                        }
                    }
                    _ => {
                        fail_tx_with_floor!(tx, i);
                    }
                },
                TxWaveKind::Contract { .. } => {
                    let sidx = stm_pos_to_slot[&pos];
                    // Copy the address out and take the owned outcome: no
                    // mutable borrow of `stm_slots` spills into the arms, so
                    // the fallback path below can invalidate later slots.
                    let slot_contract = stm_slots[sidx].contract;
                    let taken = stm_slots[sidx].last_attempt.take();
                    match taken {
                        Some(StmAttemptOutcome::Ok {
                            outcome,
                            trace,
                            gas_used,
                        }) => {
                            match self
                                .commit_native_with_floor_at_opts(
                                    tx,
                                    gas_used,
                                    &[],
                                    &[],
                                    &[],
                                    fee_floors[i].0,
                                    fee_floors[i].1,
                                    vesting_floors.get(&tx.from).copied(),
                                    vesting_floors,
                                    chain_height,
                                    false,
                                )
                                .await
                            {
                                Ok((mut touched, fee)) => {
                                    committed_native_addrs.insert(slot_contract);
                                    if !outcome.outbound_messages.is_empty() {
                                        let valued_outbound_count = outcome
                                            .outbound_messages
                                            .iter()
                                            .filter(|m| m.value > 0)
                                            .count();
                                        let outbound_touched = self
                                            .process_contract_outbound_messages_hardened(
                                                &outcome.outbound_messages,
                                                chain_height,
                                            )
                                            .await;
                                        if outbound_touched.len() < valued_outbound_count {
                                            native_credited_contracts.insert(slot_contract);
                                        }
                                        for &(addr, _, _) in &outbound_touched {
                                            committed_native_addrs.insert(addr);
                                        }
                                        touched.extend(outbound_touched);
                                    }
                                    let spent =
                                        contract_balance_spent.entry(slot_contract).or_insert(0);
                                    *spent = spent.saturating_add(trace.balance_delta_spent);
                                    stm_committed_indices.push((
                                        i,
                                        slot_contract,
                                        outcome.return_data,
                                    ));
                                    trie_dirty.extend(touched);
                                    *fees_collected = fees_collected.saturating_add(fee);
                                    *applied += 1;
                                    status[i] = true;
                                    fees[i] = fee;
                                    events[i] = outcome.events;
                                    self.session_note_applied(
                                        tx,
                                        InMemoryStateEngine::billed_gas_at(
                                            tx,
                                            gas_used,
                                            exec_hardening,
                                        ),
                                    )
                                    .await;
                                    record_tx_addrs!(tx);
                                }
                                Err(_) => {
                                    // The remainder of this wave runs
                                    // sequentially: drop the speculative
                                    // write-sets (this tx and every later
                                    // contract slot) so the flush below cannot
                                    // publish one that will be re-executed.
                                    if let Some(ref mv) = mv_memory_opt {
                                        for s in &stm_slots {
                                            if s.pos >= pos {
                                                mv.invalidate_tx(s.tx_idx);
                                            }
                                        }
                                    }
                                    stm_fallback_remainder = true;
                                    fail_tx_with_floor!(tx, i);
                                }
                            }
                        }
                        _ => {
                            fail_tx_with_floor!(tx, i);
                        }
                    }
                }
                TxWaveKind::Plain | TxWaveKind::Unsupported => unreachable!("handled above"),
            }
        }

        flush_pending_domains!();
        true
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
    /// `block.height` (and the parent-aware variant passes
    /// `block.prev_hash` for the contract-visible block identifier).
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
        self.apply_block_parallel_fees_with_events_at_height_and_parent(
            txs,
            timestamp,
            chain_height,
            [0u8; 32],
        )
        .await
    }

    /// [`Self::apply_block_parallel_fees_with_events_at_height`] with the
    /// PARENT block hash (`block.prev_hash`) threaded to contract execution.
    ///
    /// The parent hash is deterministic for the block being applied and does
    /// not depend on execution output; contracts observe it via
    /// `host.block_hash` only at/after
    /// [`crate::chain_spec::CONTRACT_BLOCK_HASH_ACTIVATION_HEIGHT`]. Callers
    /// without a block (the single-tx path, RPC preview) leave it zero.
    #[allow(clippy::type_complexity)]
    pub async fn apply_block_parallel_fees_with_events_at_height_and_parent(
        &self,
        txs: &[crate::sharding::Transaction],
        timestamp: u64,
        chain_height: u64,
        parent_block_hash: [u8; 32],
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
        // W4 FEE_MARKET_V2: one gate decision for the whole block, shared by the
        // sequential loop, the parallel plain wave and the failure fees, so the
        // parallel and sequential roots cannot diverge.
        let fee_market_v2 = crate::tokenomics::fee_market_v2_active_at(chain_height);
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
        // `OPT-PARALLEL-WAVE`: read ONLY the penalty and vesting entries for
        // the distinct senders present in this block (`order`), skipping full-map
        // clones completely when the maps are empty.
        let penalties: HashMap<[u8; 32], u64> = {
            let guard = self.consensus_penalty.read().await;
            if guard.is_empty() {
                HashMap::new()
            } else {
                let mut sub = HashMap::with_capacity(order.len().min(guard.len()));
                for sender in &order {
                    if let Some(&v) = guard.get(sender) {
                        sub.insert(*sender, v);
                    }
                }
                sub
            }
        };
        // Team-vesting locked floors at the block timestamp, snapshotted once
        // per block (same shape as the penalty snapshot above): the parallel
        // PLAIN fast path below bypasses `commit_native`, so it enforces the
        // same gate inline from this snapshot. Empty on every live chain
        // today (no vested allocations exist) → fast-path no-op.
        let vesting_floors: HashMap<[u8; 32], u64> = {
            let ledger = self.staking.read().await;
            if ledger.vesting_schedules.is_empty() {
                HashMap::new()
            } else {
                let mut sub =
                    HashMap::with_capacity(order.len().min(ledger.vesting_schedules.len()));
                for sender in &order {
                    if let Some(sched) = ledger.vesting_schedules.get(sender) {
                        sub.insert(*sender, sched.locked_amount(timestamp));
                    }
                }
                sub
            }
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
        let mut pq_keys_pinned = false;
        let pre_deploy_addrs: Option<HashSet<[u8; 32]>> = if txs.iter().any(|tx| {
            tx.payload.iter().any(|op| {
                matches!(
                    op,
                    crate::svm::OpCode::SysCallDeployContract { .. }
                        | crate::svm::OpCode::SysCallDeployContractWithAbi { .. }
                )
            })
        }) {
            Some(
                self.contracts_read()
                    .await
                    .contracts
                    .keys()
                    .copied()
                    .collect(),
            )
        } else {
            None
        };
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
                let fee = Self::failure_fee_for_v2($tx, floor_base, surcharge, fee_market_v2);
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

        // O13: plan the waves ONLY when parallel execution is enabled. The
        // scheduler result was previously computed unconditionally and then
        // discarded by the `&&` short-circuit on the flag, paying a full
        // access-key partition for every block on a sequential node.
        let parallel_enabled = self.is_parallel_exec_enabled();
        let v2_enabled = parallel_exec_v2_enabled();
        let waves = if v2_enabled {
            planned_waves_v2(parallel_enabled, txs, true, exec_hardening)
        } else {
            planned_waves(parallel_enabled, txs)
        };
        // The wave path is used for EVERY block when parallel execution is
        // on - including a single-wave block, which is the most parallel
        // shape there is (all of its transactions are disjoint, so the wave
        // is planned on the rayon pool and merged conflict-free). A wave is
        // applied in wave order, and the scheduler keeps the relative order
        // of every CONFLICTING pair, so the result is the sequential one.
        let use_parallel = !waves.is_empty();

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
                        fee_market_v2,
                        &mut applied,
                        &mut failed,
                        &mut fees_collected,
                        &mut status,
                        &mut fees,
                        &mut trie_dirty,
                    )
                    .await;
                } else {
                    let handled_v2 = if v2_enabled && wave.len() >= 2 {
                        self.apply_v2_payload_wave(
                            txs,
                            &wave,
                            &admitted,
                            &fee_floors,
                            &vesting_floors,
                            timestamp,
                            chain_height,
                            parent_block_hash,
                            exec_hardening,
                            fee_market_v2,
                            &mut applied,
                            &mut failed,
                            &mut fees_collected,
                            &mut status,
                            &mut fees,
                            &mut events,
                            &mut trie_dirty,
                            &mut pq_keys_pinned,
                        )
                        .await
                    } else {
                        false
                    };
                    if !handled_v2 {
                        for &i in &wave {
                            self.apply_single_tx_sequential(
                                &txs[i],
                                i,
                                timestamp,
                                chain_height,
                                parent_block_hash,
                                admitted[i],
                                fee_floors[i],
                                &vesting_floors,
                                exec_hardening,
                                fee_market_v2,
                                &mut applied,
                                &mut failed,
                                &mut fees_collected,
                                &mut status,
                                &mut fees,
                                &mut events,
                                &mut trie_dirty,
                                &mut pq_keys_pinned,
                            )
                            .await;
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
                        .execute_payload_with_preverify_at_height_and_parent_restorable(
                            tx,
                            timestamp,
                            chain_height,
                            parent_block_hash,
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
                    .commit_native_with_floor_at_opts(
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
                        false,
                    )
                    .await
                {
                    Ok((mut touched, fee)) => {
                        if tx.is_pq_activation() {
                            if let Some(env) = tx.pq_envelope_at_height(chain_height) {
                                if !env.is_implicit && env.pubkey.is_some() {
                                    pq_keys_pinned = true;
                                }
                            }
                        }
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
        // no undo). Only contracts newly deployed in this block are written to
        // `state_trie` without cloning `ContractRegistry`.
        // Lock order contracts-then-trie (see apply_transaction).
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
        let contracts_guard = if pre_deploy_addrs.is_some() {
            Some(self.contracts_read().await)
        } else {
            None
        };
        let mut trie = self.state_trie.write().await;
        for (addr, data) in entries {
            trie.insert(&addr, &data);
        }
        if let (Some(contracts), Some(pre_addrs)) =
            (contracts_guard.as_deref(), pre_deploy_addrs.as_ref())
        {
            let changed: Vec<[u8; 32]> = contracts
                .contracts
                .keys()
                .filter(|addr| !pre_addrs.contains(*addr))
                .copied()
                .collect();
            write_contract_trie_entries_for_addrs(&mut trie, contracts, &changed);
        }
        debug_assert_eq!(applied + failed, txs.len(), "every tx must get a verdict");
        drop(trie);
        drop(contracts_guard);

        if pq_keys_pinned {
            if let Err(e) = self.flush_pq_tree() {
                tracing::error!("pq_keys block flush failed: {e}");
            }
        }

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

#[cfg(test)]
mod o13_tests {
    use super::*;

    fn plain_tx(from: u8, to: u8, nonce: u64) -> crate::sharding::Transaction {
        crate::sharding::Transaction {
            from: [from; 32],
            to: [to; 32],
            amount: 1,
            gas_limit: 21_000,
            nonce,
            source_shard: 0,
            target_shard: 0,
            signature: Vec::new(),
            payload: Vec::new(),
            priority_fee_per_gas: 0,
        }
    }

    /// O13: with the flag OFF the scheduler is never consulted (thread-local
    /// probe), and the wave plan handed to the parallel branch is EXACTLY what
    /// the unconditional computation produced when the flag is ON.
    #[test]
    fn o13_scheduler_only_runs_when_parallel_enabled() {
        let txs = vec![
            plain_tx(1, 2, 0),
            plain_tx(3, 4, 0),
            plain_tx(1, 4, 1), // conflicts with both earlier txs
            plain_tx(5, 6, 0),
        ];

        let before = o13_schedule_probe_calls();
        let disabled = planned_waves(false, &txs);
        assert!(disabled.is_empty(), "sequential path has no waves");
        assert_eq!(
            o13_schedule_probe_calls(),
            before,
            "the scheduler must not be consulted when parallel exec is off"
        );

        let enabled = planned_waves(true, &txs);
        assert_eq!(
            o13_schedule_probe_calls(),
            before + 1,
            "the scheduler runs exactly once when parallel exec is on"
        );
        let reference = crate::parallel_exec::DisjointScheduler::schedule(&txs);
        assert_eq!(enabled, reference);
        // The old branch condition `enabled && !waves.is_empty()` is unchanged.
        for flag in [false, true] {
            let old_waves = crate::parallel_exec::DisjointScheduler::schedule(&txs);
            let old = flag && !old_waves.is_empty();
            let new = !planned_waves(flag, &txs).is_empty();
            assert_eq!(new, old, "use_parallel decision changed for flag={flag}");
        }
    }
}
