use super::memory_bounds;
use super::types::{
    bincode_deserialize_exact, bincode_deserialize_limited, write_contract_trie_entries,
    write_token_trie_entries,
};
use super::{
    AccountState, ActorMessage, EscrowRecord, InMemoryStateEngine, StateSnapshotV2,
    HASH_POOL_ENABLED, MAX_SMALL_RECORD_DECODE_BYTES, MAX_SNAPSHOT_DECODE_BYTES,
};
use crate::cell::{CellHash, MerkleProof, PatriciaTrie};
use crate::token::TokenRegistry;
use serde::Deserialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Serializes commitment-digest publication (S1-STATEROOT-CONCURRENT-STALE).
///
/// The commitment fold drops every domain lock across its `.await`s, so two
/// concurrent root reads can compute digests for different generations and race
/// the final `state_trie.write()`; the slower one used to overwrite a newer
/// digest with an older value. Holding this mutex makes fold+publish one
/// critical section. It is only ever acquired by
/// [`InMemoryStateEngine::commit_consensus_domains_if_stale`] and is never held
/// while acquiring a domain or trie lock from another path, so it cannot
/// deadlock; the section is short (one digest fold), so process-wide
/// serialization costs nothing measurable even in multi-shard processes.
static COMMIT_PUBLISH_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

/// Does `bytes` start with the CURRENT state-snapshot magic?
///
/// bincode's fixint encoding writes integers little-endian, so the magic is
/// read the same way. A legacy blob starts with a vector/map length (bounded by
/// the decode limit), never with this value; a TRUNCATED current blob always
/// keeps this prefix (truncation removes a suffix), which is what lets the
/// decoder refuse it instead of reinterpreting it as a legacy shape.
fn snapshot_has_magic(bytes: &[u8]) -> bool {
    if bytes.len() < 8 {
        return false;
    }
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&bytes[..8]);
    u64::from_le_bytes(raw) == super::types::STATE_SNAPSHOT_MAGIC
}

impl InMemoryStateEngine {
    pub fn new() -> Self {
        Self {
            accounts: Arc::new(RwLock::new(HashMap::new())),
            chain_id: crate::zkml::effective_chain_id(),
            state_trie: Arc::new(RwLock::new(PatriciaTrie::new())),
            tokens: Arc::new(RwLock::new(TokenRegistry::new())),
            orderbooks: Arc::new(RwLock::new(crate::orderbook::OrderbookManager::new())),
            contracts: Arc::new(RwLock::new(crate::contract::ContractRegistry::new())),
            pmm: Arc::new(RwLock::new(crate::pmm::PrimaryMarketMaker::new())),
            pmm_op: Arc::new(tokio::sync::Mutex::new(())),
            pmm_usdt_token: Arc::new(RwLock::new(None)),
            pmm_treasury: Arc::new(RwLock::new([0u8; 32])),
            order_escrow: Arc::new(RwLock::new(HashMap::new())),
            staking: Arc::new(RwLock::new(crate::staking::StakingLedger::new())),
            governance: Arc::new(RwLock::new(crate::governance::Governance::new())),
            oracle: Arc::new(RwLock::new(crate::oracle::OracleState::default())),
            session_keys: Arc::new(RwLock::new(crate::zkml::SessionKeyRegistry::default())),
            zkml_models: Arc::new(RwLock::new(crate::zkml::ZkMlModelRegistry::default())),
            commitment_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            committed_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            total_minted_nano: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            chain_mint_limit_nano: Arc::new(std::sync::atomic::AtomicU64::new(
                crate::tokenomics::TOTAL_SUPPLY_CAP,
            )),
            domain_gens: Arc::new(crate::commitment::DomainGenerations::default()),
            domain_cache: Arc::new(std::sync::Mutex::new(
                crate::commitment::DomainCache::default(),
            )),
            cross_shard_enabled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            finalized_headers: Arc::new(std::sync::RwLock::new(None)),
            cross_shard_consumed: Arc::new(RwLock::new(HashSet::new())),
            cross_shard_produced: Arc::new(RwLock::new(HashMap::new())),
            cross_shard_completed: Arc::new(RwLock::new(HashSet::new())),
            cross_shard_xpc: Arc::new(RwLock::new(HashMap::new())),
            bridge: Arc::new(RwLock::new(crate::bridge::BridgeState::default())),
            parallel_exec: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            pq_tree: Arc::new(std::sync::RwLock::new(None)),
            pq_db: Arc::new(std::sync::RwLock::new(None)),
            pq_keys_fallback: Arc::new(std::sync::RwLock::new(
                memory_bounds::BoundedLruCache::with_env(
                    "pq_keys_fallback",
                    "STELL_MAX_PQ_FALLBACK_ENTRIES",
                    memory_bounds::DEFAULT_MAX_PQ_FALLBACK_ENTRIES,
                ),
            )),
            consensus_penalty: Arc::new(RwLock::new(HashMap::new())),
            shard_id: Arc::new(std::sync::atomic::AtomicU32::new(
                crate::sharding::MASTERCHAIN_SHARD,
            )),
            shard_topology: Arc::new(RwLock::new(crate::sharding::ShardTopology::new())),
            cross_shard_out: Arc::new(RwLock::new(Vec::new())),
            hashpool: Arc::new(RwLock::new(crate::hashpool::HashPool::new(
                crate::zkml::effective_chain_id(),
            ))),
            hashpool_tests_on: Arc::new(std::sync::atomic::AtomicBool::new(HASH_POOL_ENABLED)),
            gov_ops_tests_on: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            cnvrf_v3: Arc::new(RwLock::new(crate::cn_vrf::CnVrfV3State::default())),
            cnvrf_abort: Arc::new(RwLock::new(crate::staking::CnVrfAbortState::default())),
            epoch_vdf_beacons: Arc::new(RwLock::new(std::collections::BTreeMap::new())),
            cnvrf_freeze_inputs: Arc::new(RwLock::new(std::collections::BTreeMap::new())),
            evm_bindings: Arc::new(RwLock::new(super::EvmBindingsState::default())),
            pq_registry: Arc::new(RwLock::new(crate::pq_registry::PqRegistry::default())),
            evm_settled: Arc::new(RwLock::new(std::collections::BTreeSet::new())),
            #[cfg(any(test, debug_assertions))]
            cnvrf_v3_activation_override: Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX)),
        }
    }

    /// Deep-clone engine state for sandbox simulation (read-only execution).
    pub async fn clone_for_simulation(&self) -> Self {
        let accounts = self.accounts.read().await.clone();
        let state_trie = self.state_trie.read().await.clone();
        let tokens = self.tokens.read().await.clone();
        let orderbooks = self.orderbooks.read().await.clone();
        let contracts = self.contracts.read().await.clone();
        let pmm = self.pmm.read().await.clone();
        let pmm_usdt_token = *self.pmm_usdt_token.read().await;
        let pmm_treasury = *self.pmm_treasury.read().await;
        let order_escrow = self.order_escrow.read().await.clone();
        let staking = self.staking.read().await.clone();
        let governance = self.governance.read().await.clone();
        let oracle = self.oracle.read().await.clone();
        let session_keys = self.session_keys.read().await.clone();
        let zkml_models = self.zkml_models.read().await.clone();
        let cross_shard_consumed = self.cross_shard_consumed.read().await.clone();
        let cross_shard_produced = self.cross_shard_produced.read().await.clone();
        let cross_shard_completed = self.cross_shard_completed.read().await.clone();
        let cross_shard_xpc = self.cross_shard_xpc.read().await.clone();
        let bridge = self.bridge.read().await.clone();
        let consensus_penalty = self.consensus_penalty.read().await.clone();
        let hashpool = self.hashpool.read().await.clone();
        let cnvrf_v3 = self.cnvrf_v3.read().await.clone();
        let cnvrf_abort = self.cnvrf_abort.read().await.clone();
        let epoch_vdf_beacons = self.epoch_vdf_beacons.read().await.clone();
        let cnvrf_freeze_inputs = self.cnvrf_freeze_inputs.read().await.clone();
        let evm_bindings = self.evm_bindings.read().await.clone();
        let pq_registry = self.pq_registry.read().await.clone();
        let evm_settled = self.evm_settled.read().await.clone();

        let pq_tree = self
            .pq_tree
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let pq_db = self.pq_db.read().unwrap_or_else(|e| e.into_inner()).clone();
        let pq_keys_fallback = self
            .pq_keys_fallback
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();

        Self {
            accounts: Arc::new(RwLock::new(accounts)),
            chain_id: self.chain_id,
            state_trie: Arc::new(RwLock::new(state_trie)),
            tokens: Arc::new(RwLock::new(tokens)),
            orderbooks: Arc::new(RwLock::new(orderbooks)),
            contracts: Arc::new(RwLock::new(contracts)),
            pmm: Arc::new(RwLock::new(pmm)),
            pmm_op: Arc::new(tokio::sync::Mutex::new(())),
            pmm_usdt_token: Arc::new(RwLock::new(pmm_usdt_token)),
            pmm_treasury: Arc::new(RwLock::new(pmm_treasury)),
            order_escrow: Arc::new(RwLock::new(order_escrow)),
            staking: Arc::new(RwLock::new(staking)),
            governance: Arc::new(RwLock::new(governance)),
            oracle: Arc::new(RwLock::new(oracle)),
            session_keys: Arc::new(RwLock::new(session_keys)),
            zkml_models: Arc::new(RwLock::new(zkml_models)),
            commitment_generation: Arc::new(std::sync::atomic::AtomicU64::new(
                self.commitment_generation
                    .load(std::sync::atomic::Ordering::Relaxed),
            )),
            committed_generation: Arc::new(std::sync::atomic::AtomicU64::new(
                self.committed_generation
                    .load(std::sync::atomic::Ordering::Relaxed),
            )),
            // DEEP COPY of the mint counter (never share it with the parent):
            // the sandbox must be free to mint against its own headroom
            // without consuming the live engine's, and the live engine's
            // counter must not move when the sandbox is discarded.
            total_minted_nano: Arc::new(std::sync::atomic::AtomicU64::new(
                self.total_minted_nano
                    .load(std::sync::atomic::Ordering::Relaxed),
            )),
            // The sandbox executes on behalf of the same shard: it inherits
            // the same static chain-wide share (a value, not a shared atomic,
            // so a sandbox cannot move the live engine's limit).
            chain_mint_limit_nano: Arc::new(std::sync::atomic::AtomicU64::new(
                self.chain_mint_limit_nano
                    .load(std::sync::atomic::Ordering::Relaxed),
            )),
            // FORK SAFETY: the deep copy holds equal state at equal
            // generations, but starts with an EMPTY preimage cache that
            // re-populates on demand. Copying the parent's cached BYTES here
            // would be equally correct today (equal state ⇒ equal bytes),
            // but an empty cache is robust by construction: no future
            // divergence path can serve one fork's bytes to the other.
            // (Shallow `Clone` keeps sharing the `Arc`s — same state, so the
            // shared cache stays sound there.)
            domain_gens: {
                let fresh = crate::commitment::DomainGenerations::default();
                self.domain_gens.copy_values_into(&fresh);
                Arc::new(fresh)
            },
            domain_cache: Arc::new(std::sync::Mutex::new(
                crate::commitment::DomainCache::default(),
            )),
            cross_shard_enabled: Arc::new(std::sync::atomic::AtomicBool::new(
                self.cross_shard_enabled
                    .load(std::sync::atomic::Ordering::Relaxed),
            )),
            finalized_headers: Arc::new(std::sync::RwLock::new(None)),
            cross_shard_consumed: Arc::new(RwLock::new(cross_shard_consumed)),
            cross_shard_produced: Arc::new(RwLock::new(cross_shard_produced)),
            cross_shard_completed: Arc::new(RwLock::new(cross_shard_completed)),
            cross_shard_xpc: Arc::new(RwLock::new(cross_shard_xpc)),
            bridge: Arc::new(RwLock::new(bridge)),
            parallel_exec: Arc::new(std::sync::atomic::AtomicBool::new(
                self.parallel_exec
                    .load(std::sync::atomic::Ordering::Relaxed),
            )),
            pq_tree: Arc::new(std::sync::RwLock::new(pq_tree)),
            pq_db: Arc::new(std::sync::RwLock::new(pq_db)),
            pq_keys_fallback: Arc::new(std::sync::RwLock::new(pq_keys_fallback)),
            consensus_penalty: Arc::new(RwLock::new(consensus_penalty)),
            shard_id: Arc::new(std::sync::atomic::AtomicU32::new(
                self.shard_id.load(std::sync::atomic::Ordering::Relaxed),
            )),
            shard_topology: Arc::new(RwLock::new(self.shard_topology.read().await.clone())),
            cross_shard_out: Arc::new(RwLock::new(Vec::new())),
            hashpool: Arc::new(RwLock::new(hashpool)),
            hashpool_tests_on: Arc::new(std::sync::atomic::AtomicBool::new(
                self.hashpool_tests_on
                    .load(std::sync::atomic::Ordering::Relaxed),
            )),
            gov_ops_tests_on: Arc::new(std::sync::atomic::AtomicBool::new(
                self.gov_ops_tests_on
                    .load(std::sync::atomic::Ordering::Relaxed),
            )),
            cnvrf_v3: Arc::new(RwLock::new(cnvrf_v3)),
            cnvrf_abort: Arc::new(RwLock::new(cnvrf_abort)),
            epoch_vdf_beacons: Arc::new(RwLock::new(epoch_vdf_beacons)),
            cnvrf_freeze_inputs: Arc::new(RwLock::new(cnvrf_freeze_inputs)),
            evm_bindings: Arc::new(RwLock::new(evm_bindings)),
            pq_registry: Arc::new(RwLock::new(pq_registry)),
            evm_settled: Arc::new(RwLock::new(evm_settled)),
            #[cfg(any(test, debug_assertions))]
            cnvrf_v3_activation_override: Arc::new(std::sync::atomic::AtomicU64::new(
                self.cnvrf_v3_activation_override
                    .load(std::sync::atomic::Ordering::Relaxed),
            )),
        }
    }

    /// Selective sandbox clone for read-only fee estimation (`stell_estimateFee`):
    /// skips `state_trie`, `pq_db`, `cross_shard_*`, `hashpool`, `cnvrf_*`, and
    /// any domain that `tx`'s payload and envelope cannot read or mutate.
    ///
    /// Equivalence contract: `apply_transaction_at_height(&tx, now, h)` returns
    /// the exact same gas / fee / error verdict as `clone_for_simulation()`,
    /// while avoiding deep-cloning untouched subsystems (`contracts`,
    /// `orderbooks`, `staking`, `zkml_models`, `bridge`, `state_trie`).
    pub async fn clone_for_simulation_for_tx(&self, tx: &crate::sharding::Transaction) -> Self {
        self.clone_for_simulation_inner(
            &tx.payload,
            tx.delegation().is_some(),
            crate::evm_adapter::is_evm_carrier_tx(tx) || crate::evm_adapter::is_evm_binding_tx(tx),
            tx.is_pq_implicit(),
        )
        .await
    }

    /// Payload-only entry point for [`Self::clone_for_simulation_for_tx`].
    pub async fn clone_for_simulation_for_payload(&self, payload: &[crate::svm::OpCode]) -> Self {
        self.clone_for_simulation_inner(payload, false, false, false)
            .await
    }

    async fn clone_for_simulation_inner(
        &self,
        payload: &[crate::svm::OpCode],
        has_delegation: bool,
        has_evm_envelope: bool,
        has_implicit_pq: bool,
    ) -> Self {
        use crate::svm::OpCode::*;
        let mut need_tokens = false;
        let mut need_contracts = false;
        let mut need_books = false;
        let mut need_pmm = false;
        let mut need_staking = false;
        let mut need_oracle = false;
        let mut need_session = has_delegation;
        let mut need_zkml = false;
        let mut need_bridge = false;
        let mut need_evm_bindings = has_evm_envelope;
        let mut need_pq_registry = false;

        for op in payload {
            match op {
                SysCallTokenTransfer { .. }
                | SysCallTokenTransferFrom { .. }
                | SysCallTokenMint { .. }
                | SysCallTokenBurn { .. }
                | SysCallTokenApprove { .. }
                | SysCallTokenBalanceOf { .. }
                | SysCallTokenCreate { .. } => need_tokens = true,
                SysCallDeployContract { .. } => need_contracts = true,
                SysCallCallContract { .. }
                | SysCallCallContractArgs { .. }
                | SysCallActorSend { .. } => {
                    // WASM contracts and actor bodies can invoke arbitrary host
                    // syscalls across domains, so clone all execution domains.
                    need_tokens = true;
                    need_contracts = true;
                    need_books = true;
                    need_pmm = true;
                    need_staking = true;
                    need_oracle = true;
                    need_session = true;
                    need_zkml = true;
                    need_bridge = true;
                    need_pq_registry = true;
                }
                SysCallPlaceOrder { .. } | SysCallCancelOrder { .. } => {
                    need_books = true;
                    need_tokens = true;
                }
                SysCallPmmBuy { .. } | SysCallPmmSell { .. } => {
                    need_books = true;
                    need_pmm = true;
                    need_tokens = true;
                    need_oracle = true;
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
                | SysCallUnjail { .. }
                | SysCallRegisterValidator(_)
                | SysCallRotateVotingKey(_)
                | SysCallChangeWithdrawal(_)
                | SysCallClaimWithdrawal(_)
                | SysCallAnnounceCommission { .. }
                | SysCallApplyCommission { .. }
                | SysCallReportPqEquivocation { .. }
                | SysCallGovPropose { .. }
                | SysCallGovVote { .. } => {
                    need_staking = true;
                    need_pq_registry = true;
                }
                SysCallBridge(_) => {
                    need_bridge = true;
                    need_staking = true;
                    need_pq_registry = true;
                }
                SysCallSubmitPriceFeed { .. } | SysCallSubmitPqPriceFeed { .. } => {
                    need_oracle = true;
                }
                SysCallPublishSessionGrant { .. } | SysCallRevokeSession { .. } => {
                    need_session = true;
                }
                SysCallVerifyZkMl
                | SysCallVerifyZkMlReexec { .. }
                | SysCallRegisterZkMlModel { .. }
                | SysCallRegisterZkMlSpec { .. }
                | SysCallVerifyZkMlAttestation { .. } => {
                    need_zkml = true;
                }
                SysCallEvmCarrier(_) | SysCallBindEvmAddress(_) => {
                    need_evm_bindings = true;
                }
                _ => {}
            }
        }

        let accounts = self.accounts.read().await.clone();
        let governance = self.governance.read().await.clone();
        let consensus_penalty = self.consensus_penalty.read().await.clone();
        let tokens = if need_tokens {
            self.tokens.read().await.clone()
        } else {
            TokenRegistry::new()
        };
        let orderbooks = if need_books {
            self.orderbooks.read().await.clone()
        } else {
            crate::orderbook::OrderbookManager::new()
        };
        let order_escrow = if need_books {
            self.order_escrow.read().await.clone()
        } else {
            HashMap::new()
        };
        let contracts = if need_contracts {
            self.contracts.read().await.clone()
        } else {
            crate::contract::ContractRegistry::new()
        };
        let (pmm, pmm_usdt_token, pmm_treasury) = if need_pmm {
            (
                self.pmm.read().await.clone(),
                *self.pmm_usdt_token.read().await,
                *self.pmm_treasury.read().await,
            )
        } else {
            (crate::pmm::PrimaryMarketMaker::default(), None, [0u8; 32])
        };
        let staking = if need_staking {
            self.staking.read().await.clone()
        } else {
            let l = self.staking.read().await;
            if l.vesting_schedules.is_empty() {
                crate::staking::StakingLedger::default()
            } else {
                crate::staking::StakingLedger {
                    vesting_schedules: l.vesting_schedules.clone(),
                    ..Default::default()
                }
            }
        };
        let oracle = if need_oracle {
            self.oracle.read().await.clone()
        } else {
            crate::oracle::OracleState::default()
        };
        let session_keys = if need_session {
            self.session_keys.read().await.clone()
        } else {
            crate::zkml::SessionKeyRegistry::default()
        };
        let zkml_models = if need_zkml {
            self.zkml_models.read().await.clone()
        } else {
            crate::zkml::ZkMlModelRegistry::default()
        };
        let bridge = if need_bridge {
            self.bridge.read().await.clone()
        } else {
            crate::bridge::BridgeState::default()
        };
        let evm_bindings = if need_evm_bindings {
            self.evm_bindings.read().await.clone()
        } else {
            Default::default()
        };
        let evm_settled = if need_evm_bindings {
            self.evm_settled.read().await.clone()
        } else {
            std::collections::BTreeSet::new()
        };
        let pq_registry = if need_pq_registry {
            self.pq_registry.read().await.clone()
        } else {
            crate::pq_registry::PqRegistry::default()
        };
        let pq_keys_fallback = if has_implicit_pq {
            self.pq_keys_fallback
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        } else {
            memory_bounds::BoundedLruCache::with_env(
                "pq_keys_fallback",
                "STELL_MAX_PQ_FALLBACK_ENTRIES",
                memory_bounds::DEFAULT_MAX_PQ_FALLBACK_ENTRIES,
            )
        };

        Self {
            accounts: Arc::new(RwLock::new(accounts)),
            chain_id: self.chain_id,
            state_trie: Arc::new(RwLock::new(PatriciaTrie::new())),
            tokens: Arc::new(RwLock::new(tokens)),
            orderbooks: Arc::new(RwLock::new(orderbooks)),
            contracts: Arc::new(RwLock::new(contracts)),
            pmm: Arc::new(RwLock::new(pmm)),
            pmm_op: Arc::new(tokio::sync::Mutex::new(())),
            pmm_usdt_token: Arc::new(RwLock::new(pmm_usdt_token)),
            pmm_treasury: Arc::new(RwLock::new(pmm_treasury)),
            order_escrow: Arc::new(RwLock::new(order_escrow)),
            staking: Arc::new(RwLock::new(staking)),
            governance: Arc::new(RwLock::new(governance)),
            oracle: Arc::new(RwLock::new(oracle)),
            session_keys: Arc::new(RwLock::new(session_keys)),
            zkml_models: Arc::new(RwLock::new(zkml_models)),
            commitment_generation: Arc::new(std::sync::atomic::AtomicU64::new(
                self.commitment_generation
                    .load(std::sync::atomic::Ordering::Relaxed),
            )),
            committed_generation: Arc::new(std::sync::atomic::AtomicU64::new(
                self.committed_generation
                    .load(std::sync::atomic::Ordering::Relaxed),
            )),
            total_minted_nano: Arc::new(std::sync::atomic::AtomicU64::new(
                self.total_minted_nano
                    .load(std::sync::atomic::Ordering::Relaxed),
            )),
            chain_mint_limit_nano: Arc::new(std::sync::atomic::AtomicU64::new(
                self.chain_mint_limit_nano
                    .load(std::sync::atomic::Ordering::Relaxed),
            )),
            domain_gens: {
                let fresh = crate::commitment::DomainGenerations::default();
                self.domain_gens.copy_values_into(&fresh);
                Arc::new(fresh)
            },
            domain_cache: Arc::new(std::sync::Mutex::new(
                crate::commitment::DomainCache::default(),
            )),
            cross_shard_enabled: Arc::new(std::sync::atomic::AtomicBool::new(
                self.cross_shard_enabled
                    .load(std::sync::atomic::Ordering::Relaxed),
            )),
            finalized_headers: Arc::new(std::sync::RwLock::new(None)),
            cross_shard_consumed: Arc::new(RwLock::new(HashSet::new())),
            cross_shard_produced: Arc::new(RwLock::new(Default::default())),
            cross_shard_completed: Arc::new(RwLock::new(HashSet::new())),
            cross_shard_xpc: Arc::new(RwLock::new(Default::default())),
            bridge: Arc::new(RwLock::new(bridge)),
            parallel_exec: Arc::new(std::sync::atomic::AtomicBool::new(
                self.parallel_exec
                    .load(std::sync::atomic::Ordering::Relaxed),
            )),
            pq_tree: Arc::new(std::sync::RwLock::new(None)),
            pq_db: Arc::new(std::sync::RwLock::new(None)),
            pq_keys_fallback: Arc::new(std::sync::RwLock::new(pq_keys_fallback)),
            consensus_penalty: Arc::new(RwLock::new(consensus_penalty)),
            shard_id: Arc::new(std::sync::atomic::AtomicU32::new(
                self.shard_id.load(std::sync::atomic::Ordering::Relaxed),
            )),
            shard_topology: Arc::new(RwLock::new(self.shard_topology.read().await.clone())),
            cross_shard_out: Arc::new(RwLock::new(Vec::new())),
            hashpool: Arc::new(RwLock::new(Default::default())),
            hashpool_tests_on: Arc::new(std::sync::atomic::AtomicBool::new(
                self.hashpool_tests_on
                    .load(std::sync::atomic::Ordering::Relaxed),
            )),
            gov_ops_tests_on: Arc::new(std::sync::atomic::AtomicBool::new(
                self.gov_ops_tests_on
                    .load(std::sync::atomic::Ordering::Relaxed),
            )),
            cnvrf_v3: Arc::new(RwLock::new(Default::default())),
            cnvrf_abort: Arc::new(RwLock::new(Default::default())),
            epoch_vdf_beacons: Arc::new(RwLock::new(Default::default())),
            cnvrf_freeze_inputs: Arc::new(RwLock::new(Default::default())),
            evm_bindings: Arc::new(RwLock::new(evm_bindings)),
            pq_registry: Arc::new(RwLock::new(pq_registry)),
            evm_settled: Arc::new(RwLock::new(evm_settled)),
            #[cfg(any(test, debug_assertions))]
            cnvrf_v3_activation_override: Arc::new(std::sync::atomic::AtomicU64::new(
                self.cnvrf_v3_activation_override
                    .load(std::sync::atomic::Ordering::Relaxed),
            )),
        }
    }

    /// Attach persistent storage tree for post-quantum public keys.
    pub fn attach_pq_tree(&self, tree: sled::Tree) {
        *self.pq_tree.write().unwrap_or_else(|e| e.into_inner()) = Some(tree);
    }

    /// Attach an external sled DB and use its `pq_keys` tree for persistent public key storage.
    pub fn attach_pq_storage(&self, db: &sled::Db) -> Result<(), sled::Error> {
        let tree = db.open_tree("pq_keys")?;
        self.attach_pq_tree(tree);
        *self.pq_db.write().unwrap_or_else(|e| e.into_inner()) = Some(db.clone());
        Ok(())
    }

    /// Open sled database at the specified directory path and attach `pq_keys` tree.
    pub fn open_pq_storage<P: AsRef<std::path::Path>>(&self, path: P) -> Result<(), sled::Error> {
        let db = crate::storage::sled_config_for(path.as_ref()).open()?;
        self.attach_pq_storage(&db)
    }

    /// Pin a counterfactual post-quantum public key to an account address.
    ///
    /// Validates that:
    /// 1. Public key length matches `scheme.pubkey_size()`.
    /// 2. `derive_pq_address(scheme, pubkey, salt) == address`.
    /// 3. Idempotent if already pinned with identical key; rejects conflicting keys.
    ///
    /// Once validated:
    /// - Sets `pubkey_hash` on `AccountState` in the accounts map.
    /// - Updates Patricia Trie leaf to 49-byte format.
    /// - Saves raw public key in persistent `pq_keys` storage.
    pub async fn pin_pubkey(
        &self,
        address: [u8; 32],
        scheme: crate::post_quantum::PqScheme,
        pubkey: &[u8],
        salt: &[u8; 16],
    ) -> Result<(), String> {
        self.pin_pubkey_inner(address, scheme, pubkey, salt, true)
            .await
    }

    /// Block-apply variant of [`Self::pin_pubkey`]: inserts into `pq_tree`
    /// without calling `tree.flush()` (`fsync`) per transaction so the block
    /// path can batch one `flush_pq_tree()` at the end of the block.
    pub(super) async fn pin_pubkey_no_flush(
        &self,
        address: [u8; 32],
        scheme: crate::post_quantum::PqScheme,
        pubkey: &[u8],
        salt: &[u8; 16],
    ) -> Result<(), String> {
        self.pin_pubkey_inner(address, scheme, pubkey, salt, false)
            .await
    }

    /// Flush pending `pq_tree` writes once at the end of block application.
    pub(super) fn flush_pq_tree(&self) -> Result<(), String> {
        if let Some(tree) = self
            .pq_tree
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            tree.flush()
                .map_err(|e| format!("pq_keys flush failed: {e}"))?;
        }
        Ok(())
    }

    async fn pin_pubkey_inner(
        &self,
        address: [u8; 32],
        scheme: crate::post_quantum::PqScheme,
        pubkey: &[u8],
        salt: &[u8; 16],
        flush: bool,
    ) -> Result<(), String> {
        // Disabled schemes pin nothing: ML-DSA-44's verifier is forgeable, so
        // admitting its keys would mint spendable-looking addresses.
        if scheme.is_disabled() {
            return Err(format!("{} is DISABLED: refusing to pin", scheme.name()));
        }
        if pubkey.len() != scheme.pubkey_size() {
            return Err(format!(
                "Invalid public key length for {}: expected {}, got {}",
                scheme.name(),
                scheme.pubkey_size(),
                pubkey.len()
            ));
        }

        let derived = crate::post_quantum::derive_pq_address(scheme, pubkey, salt);
        if derived != address {
            return Err(format!(
                "Address mismatch: derived {} does not match address {}",
                hex::encode(derived),
                hex::encode(address)
            ));
        }

        let pk_hash = *blake3::hash(pubkey).as_bytes();

        // Make leaf update and trie update atomic under a single synchronized block
        {
            let mut map = self.accounts.write().await;
            let mut trie = self.state_trie.write().await;

            let acc = map
                .entry(address)
                .or_insert_with(|| AccountState::new(address, 0));
            if let Some(existing_hash) = acc.pubkey_hash {
                if existing_hash != pk_hash || acc.scheme != scheme {
                    return Err(format!(
                        "Conflicting public key registration for address {}",
                        hex::encode(address)
                    ));
                }
            } else {
                acc.scheme = scheme;
                acc.pubkey_hash = Some(pk_hash);
            }
            let leaf_data = acc.to_trie_bytes();
            trie.insert(&address, &leaf_data);
        }

        // Persistent storage for (scheme, pubkey, salt) in `pq_keys` tree.
        // Namespaced keys (`a:` address record / `h:` pk-hash lookup) so an
        // address that equals some key's hash can never overwrite it.
        let val = bincode::serialize(&(scheme, pubkey, *salt))
            .map_err(|e| format!("Serialization error: {e}"))?;

        let has_tree = if let Some(tree) = self
            .pq_tree
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            let mut addr_key = Vec::with_capacity(34);
            addr_key.extend_from_slice(b"a:");
            addr_key.extend_from_slice(&address);
            tree.insert(addr_key, val.as_slice())
                .map_err(|e| format!("pq_keys address insert failed: {e}"))?;
            let mut hash_key = Vec::with_capacity(34);
            hash_key.extend_from_slice(b"h:");
            hash_key.extend_from_slice(&pk_hash);
            tree.insert(hash_key, pubkey)
                .map_err(|e| format!("pq_keys hash insert failed: {e}"))?;
            if flush {
                tree.flush()
                    .map_err(|e| format!("pq_keys flush failed: {e}"))?;
            }
            true
        } else {
            false
        };
        if !has_tree {
            // Sled unconfigured: the bounded LRU fallback is the ONLY store.
            // Eviction here is LOUD (throttled warn inside `insert`) and reads
            // fail open; size it for tests / diskless nodes only.
            self.pq_keys_fallback
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .insert(address, (scheme, pubkey.to_vec(), *salt));
        }

        let _ = crate::sharding::Transaction::global_implicit_registry()
            .register(address, scheme, pubkey, salt);

        Ok(())
    }

    /// Look up the pinned post-quantum scheme and raw public key for an account address.
    ///
    /// Reads directly from the persistent `pq_keys` tree if attached.
    /// Returns `None` if the account is dormant/unpinned or not registered.
    pub fn get_pinned_pubkey(
        &self,
        address: &[u8; 32],
    ) -> Option<(crate::post_quantum::PqScheme, Vec<u8>)> {
        self.get_pinned_pubkey_with_salt(address)
            .map(|(s, pk, _)| (s, pk))
    }

    /// Look up the pinned post-quantum scheme, raw public key, and salt for an account address.
    pub fn get_pinned_pubkey_with_salt(
        &self,
        address: &[u8; 32],
    ) -> Option<(crate::post_quantum::PqScheme, Vec<u8>, [u8; 16])> {
        // Read directly from pq_keys persistent tree (namespaced `a:` key,
        // with legacy 32-byte fallback for pre-prefix data dirs).
        if let Some(tree) = self
            .pq_tree
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            let mut addr_key = Vec::with_capacity(34);
            addr_key.extend_from_slice(b"a:");
            addr_key.extend_from_slice(address);
            let bytes_opt = match tree.get(&addr_key) {
                Ok(Some(v)) => Some(v),
                Ok(None) => tree.get(address).unwrap_or_default(),
                Err(_) => None,
            };
            if let Some(bytes) = bytes_opt {
                if let Ok((scheme, pk, salt)) = bincode_deserialize_limited::<(
                    crate::post_quantum::PqScheme,
                    Vec<u8>,
                    [u8; 16],
                )>(
                    &bytes, MAX_SMALL_RECORD_DECODE_BYTES
                ) {
                    return Some((scheme, pk, salt));
                }
                if let Ok((scheme, pk)) = bincode_deserialize_limited::<(
                    crate::post_quantum::PqScheme,
                    Vec<u8>,
                )>(&bytes, MAX_SMALL_RECORD_DECODE_BYTES)
                {
                    return Some((scheme, pk, crate::post_quantum::DEFAULT_SALT));
                }
                if bytes.len() > 1 {
                    if let Ok(scheme) = crate::post_quantum::PqScheme::from_id(bytes[0]) {
                        return Some((
                            scheme,
                            bytes[1..].to_vec(),
                            crate::post_quantum::DEFAULT_SALT,
                        ));
                    }
                }
            }
            return None;
        }

        // In-memory fallback when persistent sled tree is unconfigured.
        // `get` refreshes LRU recency (needs the write guard); a miss here is
        // fail-open `None`, never an error.
        if let Some((scheme, pk, salt)) = self
            .pq_keys_fallback
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .get(address)
        {
            return Some((scheme, pk, salt));
        }

        None
    }

    /// Set this node's chain id (builder-style). A session grant whose
    /// `chain_id` differs is refused by `session_gate_with`; the default is
    /// [`crate::zkml::DEFAULT_CHAIN_ID`].
    pub fn with_chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = chain_id;
        self
    }

    /// Set parallel block execution flag.
    pub fn set_parallel_exec(&self, enabled: bool) {
        self.parallel_exec
            .store(enabled, std::sync::atomic::Ordering::Release);
    }

    /// Check whether disjoint wave parallel execution is enabled.
    /// Gated by in-memory engine configuration or `STELL_PARALLEL_EXEC` env var.
    pub fn is_parallel_exec_enabled(&self) -> bool {
        static ENV_ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        if self
            .parallel_exec
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return true;
        }
        *ENV_ENABLED.get_or_init(|| {
            std::env::var("STELL_PARALLEL_EXEC")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false)
        })
    }

    /// Builder method to enable/disable parallel execution.
    pub fn with_parallel_exec(self, enabled: bool) -> Self {
        self.set_parallel_exec(enabled);
        self
    }

    pub async fn get_account(&self, address: &[u8; 32]) -> Option<AccountState> {
        self.accounts.read().await.get(address).cloned()
    }

    /// Lightweight paginated account projection for `stell_getProgramAccounts`
    /// (`program == "system"`). Never clones WASM bytecodes (`code`), mailboxes
    /// (`inbox`/`outbox`), or `consensus_penalty`.
    ///
    /// Returns `(items, next_cursor, has_more, scanned, scan_truncated)`.
    pub async fn accounts_page(
        &self,
        owner: Option<[u8; 32]>,
        min_balance: u64,
        cursor: Option<[u8; 32]>,
        limit: usize,
        scan_cap: usize,
    ) -> (Vec<AccountState>, Option<[u8; 32]>, bool, usize, bool) {
        let project = |acc: &AccountState| AccountState {
            address: acc.address,
            balance: acc.balance,
            nonce: acc.nonce,
            code: Vec::new(),
            code_hash: acc.code_hash,
            storage_root: acc.storage_root,
            inbox: VecDeque::new(),
            outbox: VecDeque::new(),
            scheme: acc.scheme,
            pubkey_hash: acc.pubkey_hash,
        };

        let map = self.accounts.read().await;
        if let Some(target) = owner {
            let mut items = Vec::new();
            let scanned = usize::from(map.contains_key(&target));
            if let Some(acc) = map.get(&target) {
                if cursor.is_none_or(|c| acc.address > c) && acc.balance >= min_balance && limit > 0
                {
                    items.push(project(acc));
                }
            }
            return (items, None, false, scanned, false);
        }

        let mut addrs: Vec<[u8; 32]> = map.keys().copied().collect();
        addrs.sort_unstable();
        let start = match cursor {
            Some(c) => addrs.partition_point(|a| *a <= c),
            None => 0,
        };

        let mut items = Vec::with_capacity(limit.min(addrs.len().saturating_sub(start)));
        let mut scanned = 0usize;
        let mut scan_truncated = false;
        let mut has_more = false;
        let mut last_scanned: Option<[u8; 32]> = None;

        for &addr in &addrs[start..] {
            if scanned >= scan_cap {
                scan_truncated = true;
                has_more = true;
                break;
            }
            let Some(acc) = map.get(&addr) else {
                continue;
            };
            scanned += 1;
            last_scanned = Some(addr);
            if acc.balance < min_balance {
                continue;
            }
            if items.len() >= limit {
                has_more = true;
                break;
            }
            items.push(project(acc));
        }

        let next_cursor = if has_more {
            items.last().map(|a| a.address).or(last_scanned)
        } else {
            None
        };
        (items, next_cursor, has_more, scanned, scan_truncated)
    }

    /// PAYMASTER: the sponsor's CURRENT balance for `tx`, for the admission
    /// coverage check.
    ///
    /// `Some(balance)` (0 for a missing account) when `tx` carries an
    /// EFFECTIVE sponsor grant (`sponsor != from`); `None` on the legacy and
    /// self-sponsored paths, which need no sponsor head. Admission call sites
    /// pass the `Some` value into
    /// [`crate::mempool::AdmissionCtx::with_sponsor_balance`] exactly like
    /// the sender balance they already read — one extra account read, under
    /// the same lock discipline (engine read BEFORE the pool write guard).
    pub async fn sponsor_balance_of(&self, tx: &crate::sharding::Transaction) -> Option<u64> {
        let grant = tx.sponsored_grant()?;
        Some(
            self.accounts
                .read()
                .await
                .get(&grant.sponsor)
                .map(|a| a.balance)
                .unwrap_or(0),
        )
    }

    pub async fn update_account(&self, state: AccountState) {
        let mut map = self.accounts.write().await;
        let mut trie = self.state_trie.write().await;

        let data = state.to_trie_bytes();
        trie.insert(&state.address, &data);
        map.insert(state.address, state);
    }

    /// The state root: the Patricia trie's root.
    ///
    /// The trie is the single root for two reasons. Merkle proofs and the
    /// block-sync comparison are defined against it, and a light client
    /// verifying an account proof must not need a second, separately sourced
    /// root to check the same trie against.
    ///
    /// For the trie to be a complete commitment it also has to cover the
    /// subsystems that used to live only in memory: the staking ledger, order
    /// books, order escrow, the PMM curve and contract storage. The validator
    /// set is re-derived from the staking ledger at every height boundary, so
    /// an uncommitted ledger let two nodes disagree about the validators while
    /// reporting the same root.
    ///
    /// Those subsystems are folded in as a single digest under one namespaced
    /// key, recomputed here rather than at each mutation site. There are
    /// dozens of mutation sites and each of them used to have to remember to
    /// commit - that is precisely how the gap opened. There is now nowhere to
    /// forget.
    ///
    /// This is not a pure read: it writes one trie key when the digest has
    /// changed. That is deliberate, and it is why the value is stable when
    /// nothing changes. Callers that only want to inspect the root without
    /// folding anything in should read `state_trie.root_hash()` directly.
    pub async fn get_state_root(&self) -> CellHash {
        self.commit_consensus_domains_if_stale().await;
        self.state_trie.read().await.root_hash()
    }

    /// Number of commitment folds that reused the cached `version || tokens`
    /// SHA-256 midstate. Observability/tests only — the value participates in
    /// no digest, root or consensus decision.
    pub fn commitment_midstate_reuse_hits(&self) -> u64 {
        self.domain_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .midstate_reuse_hits()
    }

    /// Write the commitment digest to the trie, skipping the O(state) recompute
    /// when no committed subsystem has been mutated since the last commit.
    ///
    /// The skip is sound only because the subsystem locks are private and every
    /// `*_write` accessor bumps `commitment_generation` before returning its guard.
    /// There is thus no way for a caller to mutate committed state without moving
    /// the generation, so an unchanged generation implies an unchanged digest.
    ///
    /// The digest is still written into the trie, so the trie remains the authority
    /// a reader can cross-check against the in-memory subsystems.
    pub(super) async fn commit_consensus_domains_if_stale(&self) {
        // S1-STATEROOT-CONCURRENT-STALE: the fold below drops every domain lock
        // across its `.await`s, so two concurrent root reads used to be able to
        // compute digests for different generations and race the final
        // `state_trie.write()`: the slower one could overwrite a newer digest
        // (and stamp it) with an older value. Serialize the whole fold+insert
        // (see COMMIT_PUBLISH_LOCK). The lock is only ever taken here, so it
        // cannot deadlock against the `*_write` accessors (which never take it).
        let _commit = COMMIT_PUBLISH_LOCK.lock().await;
        // Bounded retry: `*_write` mutations do not take the publish lock, so
        // one can still land while this fold runs. Publish only a digest whose
        // source generation is still current under the trie write lock, and
        // fold again for the newer generation instead of leaving the reader
        // with a stale root.
        const MAX_COMMIT_ATTEMPTS: usize = 4;
        for _ in 0..MAX_COMMIT_ATTEMPTS {
            let generation = self
                .commitment_generation
                .load(std::sync::atomic::Ordering::Acquire);
            let stamp = generation.wrapping_add(1);
            if self
                .committed_generation
                .load(std::sync::atomic::Ordering::Acquire)
                == stamp
            {
                return;
            }

            let digest = self.commit_consensus_domains_cached().await;
            let mut trie = self.state_trie.write().await;
            // Re-check UNDER the write lock: only publish the digest if no
            // committed subsystem moved while it was being folded. A racing
            // mutation makes this digest at best torn and at worst older than
            // what is already in the trie, so it must never be inserted.
            if self
                .commitment_generation
                .load(std::sync::atomic::Ordering::Acquire)
                != generation
            {
                drop(trie);
                continue;
            }
            trie.insert(&crate::commitment::commitment_key(), &digest);
            // Record the generation we observed. The store happens after the
            // insert (still under the trie write lock), so any later reader
            // either sees the committed stamp or recomputes -- never a digest
            // published for a different generation.
            self.committed_generation
                .store(stamp, std::sync::atomic::Ordering::Release);
            return;
        }
        // Continuous writer churn kept generation ahead of the fold for every
        // attempt. Publishing anything here could regress the root, so leave
        // both the trie and the stamp untouched; the next read (or the next
        // quiet moment on the consensus path) recomputes. Safe direction only.
        tracing::warn!(
            "[state] commitment fold raced mutations for {} attempts; deferring to the next root read",
            MAX_COMMIT_ATTEMPTS
        );
    }

    /// Recompute the commitment digest, reusing the cached preimage of every
    /// domain whose content generation is unchanged since its last build.
    ///
    /// A block that touches one domain (the common case) re-walks, re-sorts
    /// and re-hashes exactly that domain; the other thirteen are a cache hit
    /// (a `Vec` clone) plus one hasher update each. The assembled digest is
    /// bit-for-bit the streaming digest: the cache only replays captured
    /// bytes, never reinterpreted state.
    ///
    /// Lock discipline mirrors `commitment_snapshot` (same order, short-lived
    /// read guards, never held across another acquisition), so a root read
    /// still cannot deadlock against a payload in flight. No mutex guard is
    /// ever held across an `.await`.
    ///
    /// Under a racing mutation a domain's two generation loads may disagree;
    /// the bytes are still a valid snapshot of that domain at the clone
    /// instant (the same torn-read model as the uncached full snapshot) but
    /// they are NOT stored — a slot only ever serves generation-exact hits.
    /// The `committed_generation` stamp logic above then forces the next read
    /// to recompute, exactly as before.
    async fn commit_consensus_domains_cached(&self) -> [u8; 32] {
        use crate::commitment::Domain;

        // Tokens.
        let tokens_gen = self.domain_gens.load(Domain::Tokens);
        let tokens_hit = self
            .domain_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(Domain::Tokens, tokens_gen);
        let tokens = match tokens_hit {
            Some(b) => b,
            None => {
                let state = self.tokens.read().await.clone();
                let b = crate::commitment::tokens_preimage(&state);
                if self.domain_gens.load(Domain::Tokens) == tokens_gen {
                    self.domain_cache
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .put(Domain::Tokens, tokens_gen, b.clone());
                }
                b
            }
        };
        // PERF (per-block root read): the tokens domain is the first and
        // usually the largest preimage, while the domain that changes every
        // block is staking (the proposer's pending reward). Reuse the
        // SHA-256 state captured after `version || tokens` from the previous
        // fold while the tokens generation is unchanged, so the unchanged
        // registry is not re-hashed. Sound for the same reason the domain
        // cache is: an unchanged generation implies byte-identical tokens.
        let tokens_midstate = self
            .domain_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .tokens_midstate(tokens_gen);
        // Staking.
        let gen = self.domain_gens.load(Domain::Staking);
        let staking_hit = self
            .domain_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(Domain::Staking, gen);
        let staking = match staking_hit {
            Some(b) => b,
            None => {
                let state = self.staking.read().await.clone();
                let b = crate::commitment::staking_preimage(&state);
                if self.domain_gens.load(Domain::Staking) == gen {
                    self.domain_cache
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .put(Domain::Staking, gen, b.clone());
                }
                b
            }
        };
        // PMM (curve + USDT token id + treasury share one domain: the digest
        // folds all three, and any of the three accessors bumps `Pmm`).
        let gen = self.domain_gens.load(Domain::Pmm);
        let pmm_hit = self
            .domain_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(Domain::Pmm, gen);
        let pmm = match pmm_hit {
            Some(b) => b,
            None => {
                let p = self.pmm.read().await.clone();
                let u = *self.pmm_usdt_token.read().await;
                let t = *self.pmm_treasury.read().await;
                let b = crate::commitment::pmm_preimage(&p, &u, &t);
                if self.domain_gens.load(Domain::Pmm) == gen {
                    self.domain_cache
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .put(Domain::Pmm, gen, b.clone());
                }
                b
            }
        };
        // Contracts (with the per-contract ABI JSON cache: an unchanged
        // manifest reuses its exact JSON bytes).
        let gen = self.domain_gens.load(Domain::Contracts);
        let contracts_hit = self
            .domain_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(Domain::Contracts, gen);
        let contracts = match contracts_hit {
            Some(b) => b,
            None => {
                let state = self.contracts.read().await.clone();
                let mut dc = self.domain_cache.lock().unwrap_or_else(|e| e.into_inner());
                let b = crate::commitment::contracts_preimage_cached(&state, &mut dc.abi);
                drop(dc);
                if self.domain_gens.load(Domain::Contracts) == gen {
                    self.domain_cache
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .put(Domain::Contracts, gen, b.clone());
                }
                b
            }
        };
        // Order escrow.
        let gen = self.domain_gens.load(Domain::Escrow);
        let escrow_hit = self
            .domain_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(Domain::Escrow, gen);
        let escrow = match escrow_hit {
            Some(b) => b,
            None => {
                let state = self.order_escrow.read().await.clone();
                let b = crate::commitment::escrow_preimage(&state);
                if self.domain_gens.load(Domain::Escrow) == gen {
                    self.domain_cache
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .put(Domain::Escrow, gen, b.clone());
                }
                b
            }
        };
        // Governance.
        let gen = self.domain_gens.load(Domain::Governance);
        let governance_hit = self
            .domain_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(Domain::Governance, gen);
        let governance = match governance_hit {
            Some(b) => b,
            None => {
                let state = self.governance.read().await.clone();
                let b = crate::commitment::governance_preimage(&state);
                if self.domain_gens.load(Domain::Governance) == gen {
                    self.domain_cache
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .put(Domain::Governance, gen, b.clone());
                }
                b
            }
        };
        // Oracle.
        let gen = self.domain_gens.load(Domain::Oracle);
        let oracle_hit = self
            .domain_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(Domain::Oracle, gen);
        let oracle = match oracle_hit {
            Some(b) => b,
            None => {
                let state = self.oracle.read().await.clone();
                let b = crate::commitment::oracle_preimage(&state);
                if self.domain_gens.load(Domain::Oracle) == gen {
                    self.domain_cache
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .put(Domain::Oracle, gen, b.clone());
                }
                b
            }
        };
        // Session keys.
        let gen = self.domain_gens.load(Domain::SessionKeys);
        let session_keys_hit = self
            .domain_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(Domain::SessionKeys, gen);
        let session_keys = match session_keys_hit {
            Some(b) => b,
            None => {
                let state = self.session_keys.read().await.clone();
                let b = crate::commitment::session_keys_preimage(&state);
                if self.domain_gens.load(Domain::SessionKeys) == gen {
                    self.domain_cache
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .put(Domain::SessionKeys, gen, b.clone());
                }
                b
            }
        };
        // Orderbooks.
        let gen = self.domain_gens.load(Domain::Books);
        let books_hit = self
            .domain_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(Domain::Books, gen);
        let books = match books_hit {
            Some(b) => b,
            None => {
                let state = self.orderbooks.read().await.clone();
                let b = crate::commitment::books_preimage(&state);
                if self.domain_gens.load(Domain::Books) == gen {
                    self.domain_cache
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .put(Domain::Books, gen, b.clone());
                }
                b
            }
        };
        // Bridge.
        let gen = self.domain_gens.load(Domain::Bridge);
        let bridge_hit = self
            .domain_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(Domain::Bridge, gen);
        let bridge = match bridge_hit {
            Some(b) => b,
            None => {
                let state = self.bridge.read().await.clone();
                let b = crate::commitment::bridge_preimage(&state);
                if self.domain_gens.load(Domain::Bridge) == gen {
                    self.domain_cache
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .put(Domain::Bridge, gen, b.clone());
                }
                b
            }
        };
        // Cross-shard replay sets (one domain over three locks).
        let gen = self.domain_gens.load(Domain::CrossShard);
        let cross_shard_hit = self
            .domain_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(Domain::CrossShard, gen);
        let cross_shard = match cross_shard_hit {
            Some(b) => b,
            None => {
                let consumed = self.cross_shard_consumed_snapshot().await;
                let produced = self.cross_shard_produced_snapshot().await;
                let completed = self.cross_shard_completed_snapshot().await;
                let b = crate::commitment::cross_shard_preimage(&consumed, &produced, &completed);
                if self.domain_gens.load(Domain::CrossShard) == gen {
                    self.domain_cache
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .put(Domain::CrossShard, gen, b.clone());
                }
                b
            }
        };
        // §9 2PC.
        let gen = self.domain_gens.load(Domain::Xpc);
        let xpc_hit = self
            .domain_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(Domain::Xpc, gen);
        let xpc = match xpc_hit {
            Some(b) => b,
            None => {
                let state = self.xpc_snapshot().await;
                let b = crate::commitment::xpc_preimage(&state);
                if self.domain_gens.load(Domain::Xpc) == gen {
                    self.domain_cache
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .put(Domain::Xpc, gen, b.clone());
                }
                b
            }
        };
        // zkML (models, then verifying keys: one domain, one generation).
        let gen = self.domain_gens.load(Domain::Zkml);
        let zkml_hit = self
            .domain_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(Domain::Zkml, gen);
        let zkml = match zkml_hit {
            Some(b) => b,
            None => {
                let state = self.zkml_models.read().await.clone();
                let b = crate::commitment::zkml_preimage(&state);
                if self.domain_gens.load(Domain::Zkml) == gen {
                    self.domain_cache
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .put(Domain::Zkml, gen, b.clone());
                }
                b
            }
        };

        // CN-VRF v3 (commits, rolling mixes, abort counters, finalized epoch beacons).
        let gen = self.domain_gens.load(Domain::CnVrf);
        let cnvrf_hit = self
            .domain_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_cnvrf_silent(gen);
        let cnvrf = match cnvrf_hit {
            Some(b) => b,
            None => {
                let snap = self.cnvrf_v3_snapshot().await;
                let b = crate::commitment::cnvrf_v3_preimage(&snap);
                if self.domain_gens.load(Domain::CnVrf) == gen {
                    self.domain_cache
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .put_cnvrf_silent(gen, b.clone());
                }
                b
            }
        };

        // Canonical EVM bindings (Domain::EvmBindings).
        let gen = self.domain_gens.load(Domain::EvmBindings);
        let evm_bindings_hit = self
            .domain_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_evm_bindings_silent(gen);
        let evm_bindings = match evm_bindings_hit {
            Some(b) => b,
            None => {
                let state = self.evm_bindings.read().await.clone();
                let b = crate::commitment::evm_bindings_preimage(&state);
                if self.domain_gens.load(Domain::EvmBindings) == gen {
                    self.domain_cache
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .put_evm_bindings_silent(gen, b.clone());
                }
                b
            }
        };

        // Canonical PQ validator key registry (Domain::PqRegistry).
        let gen = self.domain_gens.load(Domain::PqRegistry);
        let pq_registry_hit = self
            .domain_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_pq_registry_silent(gen);
        let pq_registry = match pq_registry_hit {
            Some(b) => b,
            None => {
                let state = self.pq_registry.read().await.clone();
                let b = crate::commitment::pq_registry_preimage(&state);
                if self.domain_gens.load(Domain::PqRegistry) == gen {
                    self.domain_cache
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .put_pq_registry_silent(gen, b.clone());
                }
                b
            }
        };

        let (digest, tokens_midstate_after) =
            crate::commitment::assemble_cached_digest_with_all_domains_midstate(
                tokens_midstate,
                [
                    &tokens,
                    &staking,
                    &pmm,
                    &contracts,
                    &escrow,
                    &governance,
                    &oracle,
                    &session_keys,
                    &books,
                    &bridge,
                    &cross_shard,
                    &xpc,
                    &zkml,
                ],
                &cnvrf,
                self.total_minted_nano(),
                &evm_bindings,
                &pq_registry,
            );
        // Cache the midstate only while the tokens generation is still the
        // one whose bytes were folded. A racing mutation moves the counter, so
        // a stale midstate can never be keyed to newer bytes.
        if self.domain_gens.load(Domain::Tokens) == tokens_gen {
            self.domain_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .put_tokens_midstate(tokens_gen, tokens_midstate_after);
        }
        digest
    }

    /// Take a writer lock on a committed subsystem and mark the commitment dirty.
    ///
    /// Every mutation of consensus-visible state must go through this, not
    /// `field.write()` directly. Getting that wrong in one direction is benign (an
    /// extra recomputation); in the other it returns a STALE STATE ROOT, which is the
    /// kind of bug that splits a network with no attacker involved. Wrapping the lock
    /// makes the two impossible to separate by accident.
    ///
    /// PREFER `dom_guard` / the `*_write` accessors: this bumps only the
    /// global generation, so a mutation recorded through it alone would leave
    /// the per-domain cache believing its domain is unchanged. Kept for API
    /// compatibility; the engine itself no longer routes committed domains
    /// through it.
    #[allow(clippy::manual_async_fn)]
    // GATE: manual future keeps Sync bounds for lock guard; async fn would change signature.
    pub fn mut_guard<'a, T>(
        generation: &'a Arc<std::sync::atomic::AtomicU64>,
        lock: &'a RwLock<T>,
    ) -> impl std::future::Future<Output = tokio::sync::RwLockWriteGuard<'a, T>> + 'a {
        async move {
            let g = lock.write().await;
            generation.fetch_add(1, std::sync::atomic::Ordering::Release);
            g
        }
    }

    pub fn bump_commitment_generation(&self) {
        self.commitment_generation
            .fetch_add(1, std::sync::atomic::Ordering::Release);
    }

    /// Bump the global generation AND one domain's content generation.
    ///
    /// This is the ONLY correct way to record a committed-domain mutation
    /// that does not go through a `*_write` accessor: the two counters are
    /// always moved together, so the per-domain cache can never claim a
    /// domain is unchanged when the global generation says something moved.
    pub fn bump_domain_generation(&self, domain: crate::commitment::Domain) {
        self.domain_gens.bump(domain);
        self.bump_commitment_generation();
    }

    /// Force the next root read to recompute + re-insert the digest WITHOUT
    /// invalidating any per-domain cache slot.
    ///
    /// For trie-rebuild paths (snapshot restore) where the committed
    /// subsystem state is UNCHANGED but the trie lost its digest key: the
    /// recompute replays every cached preimage and re-inserts the identical
    /// digest. Callers that DO mutate a committed domain must use
    /// `bump_domain_generation` instead.
    pub fn force_commitment_recompute(&self) {
        self.bump_commitment_generation();
    }

    /// Domain-aware write guard: acquires the lock, then bumps the global
    /// generation and the domain's content generation together.
    ///
    /// Same lock-then-bump order as `mut_guard` (the mutation happens under
    /// the guard, so the bump must come after acquisition, never before).
    async fn dom_guard<'a, T>(
        &self,
        domain: crate::commitment::Domain,
        lock: &'a RwLock<T>,
    ) -> tokio::sync::RwLockWriteGuard<'a, T> {
        let g = lock.write().await;
        self.domain_gens.bump(domain);
        self.commitment_generation
            .fetch_add(1, std::sync::atomic::Ordering::Release);
        g
    }

    // ============ Committed subsystem accessors (private fields) ============
    //
    // The committed subsystem locks are private. A caller reaches them only
    // through these accessors, and every `*_write` accessor bumps
    // `commitment_generation` before returning the guard. That establishes the
    // invariant the digest skip depends on: obtaining a write guard on a
    // committed subsystem is impossible without bumping.

    pub async fn tokens_read(&self) -> tokio::sync::RwLockReadGuard<'_, TokenRegistry> {
        self.tokens.read().await
    }

    pub async fn tokens_write(&self) -> tokio::sync::RwLockWriteGuard<'_, TokenRegistry> {
        self.dom_guard(crate::commitment::Domain::Tokens, &self.tokens)
            .await
    }

    pub async fn staking_read(
        &self,
    ) -> tokio::sync::RwLockReadGuard<'_, crate::staking::StakingLedger> {
        self.staking.read().await
    }

    pub async fn staking_write(
        &self,
    ) -> tokio::sync::RwLockWriteGuard<'_, crate::staking::StakingLedger> {
        self.dom_guard(crate::commitment::Domain::Staking, &self.staking)
            .await
    }

    /// Non-blocking read of the staking ledger. No bump needed: reads cannot
    /// make the commitment stale.
    pub fn try_staking_read(
        &self,
    ) -> Option<tokio::sync::RwLockReadGuard<'_, crate::staking::StakingLedger>> {
        self.staking.try_read().ok()
    }

    /// Non-blocking write of the staking ledger. Bumps the commitment generation
    /// on success, so the write is visible to the root cache exactly like the
    /// blocking path.
    pub fn try_staking_write(
        &self,
    ) -> Option<tokio::sync::RwLockWriteGuard<'_, crate::staking::StakingLedger>> {
        match self.staking.try_write() {
            Ok(g) => {
                self.domain_gens.bump(crate::commitment::Domain::Staking);
                self.commitment_generation
                    .fetch_add(1, std::sync::atomic::Ordering::Release);
                Some(g)
            }
            Err(_) => None,
        }
    }

    /// Shared handle to the staking lock, for code that holds a long-lived alias
    /// (e.g. `ValidatorRuntime.staking`). READS through the handle are always safe.
    /// WRITES through the handle do NOT bump the commitment generation — every
    /// write site must go through `staking_write`/`try_staking_write` instead,
    /// or the state root can go stale.
    pub fn staking_handle(
        &self,
    ) -> std::sync::Arc<tokio::sync::RwLock<crate::staking::StakingLedger>> {
        std::sync::Arc::clone(&self.staking)
    }

    /// Shared handle to the governance lock. Same contract as `staking_handle`:
    /// reads are always safe; every write must go through `governance_write`.
    pub fn governance_handle(
        &self,
    ) -> std::sync::Arc<tokio::sync::RwLock<crate::governance::Governance>> {
        std::sync::Arc::clone(&self.governance)
    }

    pub async fn orderbooks_read(
        &self,
    ) -> tokio::sync::RwLockReadGuard<'_, crate::orderbook::OrderbookManager> {
        self.orderbooks.read().await
    }

    pub async fn orderbooks_write(
        &self,
    ) -> tokio::sync::RwLockWriteGuard<'_, crate::orderbook::OrderbookManager> {
        self.dom_guard(crate::commitment::Domain::Books, &self.orderbooks)
            .await
    }

    pub async fn order_escrow_read(
        &self,
    ) -> tokio::sync::RwLockReadGuard<'_, HashMap<(u32, u64), EscrowRecord>> {
        self.order_escrow.read().await
    }

    pub async fn order_escrow_write(
        &self,
    ) -> tokio::sync::RwLockWriteGuard<'_, HashMap<(u32, u64), EscrowRecord>> {
        self.dom_guard(crate::commitment::Domain::Escrow, &self.order_escrow)
            .await
    }

    pub async fn pmm_read(
        &self,
    ) -> tokio::sync::RwLockReadGuard<'_, crate::pmm::PrimaryMarketMaker> {
        self.pmm.read().await
    }

    pub async fn pmm_write(
        &self,
    ) -> tokio::sync::RwLockWriteGuard<'_, crate::pmm::PrimaryMarketMaker> {
        self.dom_guard(crate::commitment::Domain::Pmm, &self.pmm)
            .await
    }

    pub async fn pmm_usdt_token_read(&self) -> tokio::sync::RwLockReadGuard<'_, Option<[u8; 32]>> {
        self.pmm_usdt_token.read().await
    }

    pub async fn pmm_usdt_token_write(
        &self,
    ) -> tokio::sync::RwLockWriteGuard<'_, Option<[u8; 32]>> {
        self.dom_guard(crate::commitment::Domain::Pmm, &self.pmm_usdt_token)
            .await
    }

    pub async fn pmm_treasury_read(&self) -> tokio::sync::RwLockReadGuard<'_, [u8; 32]> {
        self.pmm_treasury.read().await
    }

    pub async fn pmm_treasury_write(&self) -> tokio::sync::RwLockWriteGuard<'_, [u8; 32]> {
        self.dom_guard(crate::commitment::Domain::Pmm, &self.pmm_treasury)
            .await
    }

    pub async fn contracts_read(
        &self,
    ) -> tokio::sync::RwLockReadGuard<'_, crate::contract::ContractRegistry> {
        self.contracts.read().await
    }

    pub async fn contracts_write(
        &self,
    ) -> tokio::sync::RwLockWriteGuard<'_, crate::contract::ContractRegistry> {
        self.dom_guard(crate::commitment::Domain::Contracts, &self.contracts)
            .await
    }

    pub async fn governance_read(
        &self,
    ) -> tokio::sync::RwLockReadGuard<'_, crate::governance::Governance> {
        self.governance.read().await
    }

    pub async fn governance_write(
        &self,
    ) -> tokio::sync::RwLockWriteGuard<'_, crate::governance::Governance> {
        self.dom_guard(crate::commitment::Domain::Governance, &self.governance)
            .await
    }

    pub async fn oracle_read(
        &self,
    ) -> tokio::sync::RwLockReadGuard<'_, crate::oracle::OracleState> {
        self.oracle.read().await
    }

    /// Write access to the committed oracle. Bumps `commitment_generation`
    /// like every other `*_write`, so a committed feed moves the state root
    /// on the very next root read - the whole point of folding the oracle into
    /// the commitment.
    pub async fn oracle_write(
        &self,
    ) -> tokio::sync::RwLockWriteGuard<'_, crate::oracle::OracleState> {
        self.dom_guard(crate::commitment::Domain::Oracle, &self.oracle)
            .await
    }

    /// Read the session-key registry (revocation lookups, the propose filter,
    /// the block admission pass). Reads cannot make the commitment stale.
    pub async fn session_keys_read(
        &self,
    ) -> tokio::sync::RwLockReadGuard<'_, crate::zkml::SessionKeyRegistry> {
        self.session_keys.read().await
    }

    /// Write access to the session-key registry: lazy registration, gas
    /// deduction and revocation all bump `commitment_generation`, so the very
    /// next root read folds them into the state root.
    pub async fn session_keys_write(
        &self,
    ) -> tokio::sync::RwLockWriteGuard<'_, crate::zkml::SessionKeyRegistry> {
        self.dom_guard(crate::commitment::Domain::SessionKeys, &self.session_keys)
            .await
    }

    /// Read the §2 model registry (the VM's clone source, the commitment
    /// fold, receipts). Reads cannot make the commitment stale, so this does
    /// NOT bump the generation - and the guard must be dropped before any
    /// other subsystem lock is taken, exactly like `commitment_snapshot`'s
    /// fields.
    pub async fn zkml_models_read(
        &self,
    ) -> tokio::sync::RwLockReadGuard<'_, crate::zkml::ZkMlModelRegistry> {
        self.zkml_models.read().await
    }

    /// Write access to the §2 model registry: registering a model bumps
    /// `commitment_generation`, so the very next root read folds the new
    /// models into the state root.
    pub async fn zkml_models_write(
        &self,
    ) -> tokio::sync::RwLockWriteGuard<'_, crate::zkml::ZkMlModelRegistry> {
        self.dom_guard(crate::commitment::Domain::Zkml, &self.zkml_models)
            .await
    }

    /// Read the committed CN-VRF v3 hash-chain state.
    pub async fn cnvrf_v3_read(
        &self,
    ) -> tokio::sync::RwLockReadGuard<'_, crate::cn_vrf::CnVrfV3State> {
        self.cnvrf_v3.read().await
    }

    /// Write access to the committed CN-VRF v3 hash-chain state (bumps
    /// `Domain::CnVrf` and `commitment_generation`).
    pub async fn cnvrf_v3_write(
        &self,
    ) -> tokio::sync::RwLockWriteGuard<'_, crate::cn_vrf::CnVrfV3State> {
        self.dom_guard(crate::commitment::Domain::CnVrf, &self.cnvrf_v3)
            .await
    }

    /// Read the committed CN-VRF v3 reveal-abort leaky-bucket counters.
    pub async fn cnvrf_abort_read(
        &self,
    ) -> tokio::sync::RwLockReadGuard<'_, crate::staking::CnVrfAbortState> {
        self.cnvrf_abort.read().await
    }

    /// Write access to the committed CN-VRF v3 reveal-abort counters (bumps
    /// `Domain::CnVrf` and `commitment_generation`).
    pub async fn cnvrf_abort_write(
        &self,
    ) -> tokio::sync::RwLockWriteGuard<'_, crate::staking::CnVrfAbortState> {
        self.dom_guard(crate::commitment::Domain::CnVrf, &self.cnvrf_abort)
            .await
    }

    /// Read the finalized CN-VRF v3 epoch VDF beacons (`epoch -> [u8; 48]`).
    pub async fn epoch_vdf_beacons_read(
        &self,
    ) -> tokio::sync::RwLockReadGuard<'_, std::collections::BTreeMap<u64, [u8; 48]>> {
        self.epoch_vdf_beacons.read().await
    }

    /// Write access to the finalized CN-VRF v3 epoch VDF beacons (bumps
    /// `Domain::CnVrf` and `commitment_generation`).
    pub async fn epoch_vdf_beacons_write(
        &self,
    ) -> tokio::sync::RwLockWriteGuard<'_, std::collections::BTreeMap<u64, [u8; 48]>> {
        self.dom_guard(crate::commitment::Domain::CnVrf, &self.epoch_vdf_beacons)
            .await
    }

    /// Capture a consistent snapshot of the CN-VRF v3 state, abort counters,
    /// and finalized epoch beacons.
    pub async fn cnvrf_v3_snapshot(&self) -> super::CnVrfV3EngineSnapshot {
        let v3_state = self.cnvrf_v3.read().await.clone();
        let abort_state = self.cnvrf_abort.read().await.clone();
        let epoch_beacons = self.epoch_vdf_beacons.read().await.clone();
        super::CnVrfV3EngineSnapshot {
            v3_state,
            abort_state,
            epoch_beacons,
        }
    }

    /// Restore a [`CnVrfV3EngineSnapshot`] and bump `Domain::CnVrf` +
    /// `commitment_generation`.
    pub async fn restore_cnvrf_v3_snapshot(&self, snap: &super::CnVrfV3EngineSnapshot) {
        *self.cnvrf_v3.write().await = snap.v3_state.clone();
        *self.cnvrf_abort.write().await = snap.abort_state.clone();
        *self.epoch_vdf_beacons.write().await = snap.epoch_beacons.clone();
        self.bump_domain_generation(crate::commitment::Domain::CnVrf);
    }

    /// Read the canonical on-chain EVM ↔ PQ address bindings (`Domain::EvmBindings`).
    pub async fn evm_bindings_read(
        &self,
    ) -> tokio::sync::RwLockReadGuard<'_, super::EvmBindingsState> {
        self.evm_bindings.read().await
    }

    /// Write access to the canonical on-chain EVM ↔ PQ address bindings (bumps
    /// `Domain::EvmBindings` and `commitment_generation`).
    pub async fn evm_bindings_write(
        &self,
    ) -> tokio::sync::RwLockWriteGuard<'_, super::EvmBindingsState> {
        self.dom_guard(crate::commitment::Domain::EvmBindings, &self.evm_bindings)
            .await
    }

    /// Capture a persistence snapshot of [`EvmBindingsState`].
    pub async fn evm_bindings_state_snapshot(&self) -> super::EvmBindingsSnapshot {
        self.evm_bindings.read().await.to_snapshot()
    }

    /// Serialize the canonical EVM bindings domain for persistence / SnapV4.
    /// Returns an empty `Vec` when the domain is empty (0 bytes invariant).
    pub async fn evm_bindings_snapshot(&self) -> Vec<u8> {
        let guard = self.evm_bindings.read().await;
        if guard.is_empty() {
            return Vec::new();
        }
        bincode::serialize(&guard.to_snapshot()).unwrap_or_default()
    }

    /// Install a persisted [`EvmBindingsSnapshot`] (fail-closed on duplicate PQ mappings)
    /// and bump `Domain::EvmBindings` + `commitment_generation`.
    pub async fn restore_evm_bindings_state(
        &self,
        snap: super::EvmBindingsSnapshot,
    ) -> Result<(), String> {
        let state = super::EvmBindingsState::from_snapshot(snap)?;
        *self.evm_bindings_write().await = state;
        Ok(())
    }

    /// Install serialized EVM bindings bytes (empty bytes install an empty state).
    pub async fn restore_evm_bindings(&self, bytes: &[u8]) -> Result<(), String> {
        if bytes.is_empty() {
            *self.evm_bindings_write().await = super::EvmBindingsState::default();
            return Ok(());
        }
        let snap: super::EvmBindingsSnapshot =
            bincode_deserialize_exact(bytes, MAX_SNAPSHOT_DECODE_BYTES)
                .map_err(|e| format!("restore evm_bindings failed: {e:?}"))?;
        self.restore_evm_bindings_state(snap).await
    }

    /// Read the canonical on-chain PQ validator key registry (`Domain::PqRegistry`).
    pub async fn pq_registry_read(
        &self,
    ) -> tokio::sync::RwLockReadGuard<'_, crate::pq_registry::PqRegistry> {
        self.pq_registry.read().await
    }

    /// Write access to the canonical on-chain PQ validator key registry (bumps
    /// `Domain::PqRegistry` and `commitment_generation`).
    pub async fn pq_registry_write(
        &self,
    ) -> tokio::sync::RwLockWriteGuard<'_, crate::pq_registry::PqRegistry> {
        self.dom_guard(crate::commitment::Domain::PqRegistry, &self.pq_registry)
            .await
    }

    /// Serialize the canonical PQ registry domain for persistence / SnapV4.
    /// Returns an empty `Vec` when the domain is empty (0 bytes invariant).
    pub async fn pq_registry_snapshot(&self) -> Vec<u8> {
        let guard = self.pq_registry.read().await;
        if guard.is_empty() {
            return Vec::new();
        }
        bincode::serialize(&*guard).unwrap_or_default()
    }

    /// Install a [`crate::pq_registry::PqRegistry`] directly and bump
    /// `Domain::PqRegistry` + `commitment_generation`.
    pub async fn restore_pq_registry_state(&self, reg: crate::pq_registry::PqRegistry) {
        *self.pq_registry_write().await = reg;
    }

    /// Install serialized PQ registry bytes (empty bytes install an empty registry).
    pub async fn restore_pq_registry(&self, bytes: &[u8]) -> Result<(), String> {
        if bytes.is_empty() {
            *self.pq_registry_write().await = crate::pq_registry::PqRegistry::default();
            return Ok(());
        }
        let reg: crate::pq_registry::PqRegistry =
            bincode_deserialize_exact(bytes, MAX_SNAPSHOT_DECODE_BYTES)
                .map_err(|e| format!("restore pq_registry failed: {e:?}"))?;
        self.restore_pq_registry_state(reg).await;
        Ok(())
    }

    /// Set the test/debug per-engine CN-VRF v3 activation height override.
    ///
    /// Keeps frozen `CNVRF_V3_ACTIVATION_HEIGHT` (`u64::MAX`) untouched.
    #[cfg(any(test, debug_assertions))]
    pub fn set_cnvrf_v3_activation_height_for_tests(&self, height: u64) {
        self.cnvrf_v3_activation_override
            .store(height, std::sync::atomic::Ordering::Release);
    }

    /// Returns `true` when CN-VRF v3 state transitions are active at `height`.
    pub fn cnvrf_v3_is_active_at(&self, height: u64) -> bool {
        if crate::consensus::cnvrf_v3_active_at(height) {
            return true;
        }
        #[cfg(any(test, debug_assertions))]
        {
            let ov = self
                .cnvrf_v3_activation_override
                .load(std::sync::atomic::Ordering::Acquire);
            if height >= ov {
                return true;
            }
        }
        false
    }

    /// Shared handle to the registry lock, for the one synchronous reader that
    /// cannot await: mempool admission. Like `staking_handle`, READS through
    /// the handle are safe; it exists so admission can consult revocation
    /// without turning every admission path async.
    pub fn session_keys_handle(
        &self,
    ) -> std::sync::Arc<tokio::sync::RwLock<crate::zkml::SessionKeyRegistry>> {
        std::sync::Arc::clone(&self.session_keys)
    }

    /// Serialize the registry for persistence (its own storage tree).
    pub async fn session_keys_snapshot(&self) -> Vec<u8> {
        bincode::serialize(&*self.session_keys.read().await).unwrap_or_default()
    }

    /// Install a persisted registry (startup restore). Bumps the commitment
    /// generation like every other domain install.
    pub async fn restore_session_keys(&self, bytes: &[u8]) -> Result<(), String> {
        let reg: crate::zkml::SessionKeyRegistry =
            bincode_deserialize_limited(bytes, MAX_SNAPSHOT_DECODE_BYTES)
                .map_err(|e| format!("restore session keys failed: {e:?}"))?;
        *self.session_keys_write().await = reg;
        Ok(())
    }

    /// Install a snapshot-sync `pq_keys` blob (audit F7).
    ///
    /// Wire format is `Storage::export_pq_keys_blob`: bincode of the raw
    /// `(key, value)` pairs of the `pq_keys` sled tree (namespaced `a:` /
    /// `h:` keys, see `storage.rs`). Install rule, in order:
    /// * every address record (`a:` + 32B, plus legacy bare-32B keys) is
    ///   validated fail-closed per entry — `blake3(pk)` must equal the
    ///   account leaf's pinned `pubkey_hash` AND
    ///   `derive_pq_address(scheme, pk, salt)` must equal the address. A
    ///   record that fails is skipped (counted + logged), never aborts the
    ///   whole restore;
    /// * attached persistent tree (`attach_pq_tree`): valid pairs install
    ///   verbatim — the synced node then serves the publisher's keys from
    ///   disk exactly as the publisher did. Hash-lookup (`h:`) records
    ///   install verbatim only when their hash belongs to a valid address
    ///   record, so a refused entry leaves no orphan behind;
    /// * diskless fallback: the valid address records decode into the
    ///   bounded in-memory LRU WITH their pinned salt (`h:` hash-lookup
    ///   records are skipped — they are derivable from the address records
    ///   and the LRU is keyed by address only). Bounded like every Phase-1
    ///   cache: past the cap the coldest entry is evicted LOUDLY and
    ///   re-served from... nothing (no disk) — which is why diskless nodes
    ///   are tests-only: an evicted key refuses its PQ-gated admission until
    ///   gossip re-pins it (availability, never a fork; a MISS here never
    ///   attests anything).
    ///
    /// Corrupt bytes are a hard error (fail closed — installing a truncated
    /// key set as complete would refuse honest PQ transactions silently).
    /// PQ keys are NOT part of the state root (they ride the accounts
    /// snapshot's pinned `pubkey_hash`), so installing them never moves the
    /// root and needs no generation bump.
    pub async fn restore_pq_keys(&self, bytes: &[u8]) -> Result<(), String> {
        let pairs: Vec<(Vec<u8>, Vec<u8>)> =
            bincode_deserialize_limited(bytes, MAX_SNAPSHOT_DECODE_BYTES)
                .map_err(|e| format!("restore pq_keys failed: {e:?}"))?;
        // Leaf snapshot for fail-closed per-entry validation (M-03): cloned
        // under one read guard so validation never holds the accounts lock
        // across sled I/O.
        let leaves: HashMap<[u8; 32], (crate::post_quantum::PqScheme, Option<[u8; 32]>)> = {
            let map = self.accounts.read().await;
            map.iter()
                .map(|(addr, acc)| (*addr, (acc.scheme, acc.pubkey_hash)))
                .collect()
        };
        // Decode one address-record value in every known shape (current
        // triple, legacy double, raw scheme-id prefix); `None` = undecodable.
        fn decode_record(
            bytes: &[u8],
        ) -> Option<(crate::post_quantum::PqScheme, Vec<u8>, [u8; 16])> {
            if let Ok((scheme, pk, salt)) = bincode_deserialize_limited::<(
                crate::post_quantum::PqScheme,
                Vec<u8>,
                [u8; 16],
            )>(bytes, MAX_SMALL_RECORD_DECODE_BYTES)
            {
                return Some((scheme, pk, salt));
            }
            if let Ok((scheme, pk)) = bincode_deserialize_limited::<(
                crate::post_quantum::PqScheme,
                Vec<u8>,
            )>(bytes, MAX_SMALL_RECORD_DECODE_BYTES)
            {
                return Some((scheme, pk, crate::post_quantum::DEFAULT_SALT));
            }
            if bytes.len() > 1 {
                if let Ok(scheme) = crate::post_quantum::PqScheme::from_id(bytes[0]) {
                    return Some((
                        scheme,
                        bytes[1..].to_vec(),
                        crate::post_quantum::DEFAULT_SALT,
                    ));
                }
            }
            None
        }
        // Fail-closed per-entry verdict: `Ok(())` installs, `Err(reason)`
        // skips (counted + logged) without aborting the restore.
        fn record_verdict(
            leaves: &HashMap<[u8; 32], (crate::post_quantum::PqScheme, Option<[u8; 32]>)>,
            addr: &[u8; 32],
            scheme: crate::post_quantum::PqScheme,
            pk: &[u8],
            salt: &[u8; 16],
        ) -> Result<(), String> {
            if scheme.is_disabled() {
                return Err(format!("disabled scheme {}", scheme.name()));
            }
            if pk.len() != scheme.pubkey_size() {
                return Err(format!(
                    "pubkey length {} != {} for {}",
                    pk.len(),
                    scheme.pubkey_size(),
                    scheme.name()
                ));
            }
            let Some((leaf_scheme, leaf_hash)) = leaves.get(addr) else {
                return Err("no account leaf for address".to_string());
            };
            if *leaf_scheme != scheme {
                return Err("leaf scheme mismatch".to_string());
            }
            let pk_hash = *blake3::hash(pk).as_bytes();
            if *leaf_hash != Some(pk_hash) {
                return Err("blake3(pk) != leaf pubkey_hash".to_string());
            }
            if crate::post_quantum::derive_pq_address(scheme, pk, salt) != *addr {
                return Err("derive(scheme,pk,salt) != address".to_string());
            }
            Ok(())
        }
        // First pass: decide the valid address records (fail-closed). The
        // valid set drives both install paths so disk and fallback agree.
        // First valid record wins a duplicated address; a conflicting
        // duplicate is itself a refused entry.
        let mut valid: HashMap<[u8; 32], (crate::post_quantum::PqScheme, Vec<u8>, [u8; 16])> =
            HashMap::new();
        let mut valid_hashes: HashSet<[u8; 32]> = HashSet::new();
        let mut skipped: u64 = 0;
        for (k, v) in &pairs {
            let addr_opt: Option<[u8; 32]> = if k.len() == 34 && k[0] == b'a' && k[1] == b':' {
                let mut addr = [0u8; 32];
                addr.copy_from_slice(&k[2..]);
                Some(addr)
            } else if k.len() == 32 {
                let mut addr = [0u8; 32];
                addr.copy_from_slice(k);
                Some(addr)
            } else {
                None
            };
            let Some(addr) = addr_opt else {
                continue;
            };
            let Some((scheme, pk, salt)) = decode_record(v) else {
                skipped += 1;
                tracing::debug!(
                    address = %hex::encode(addr),
                    "restore_pq_keys: refusing undecodable record"
                );
                continue;
            };
            if let Err(reason) = record_verdict(&leaves, &addr, scheme, &pk, &salt) {
                skipped += 1;
                tracing::debug!(
                    address = %hex::encode(addr),
                    "restore_pq_keys: refusing invalid record ({reason})"
                );
                continue;
            }
            if let Some((prev_scheme, prev_pk, prev_salt)) = valid.get(&addr) {
                if *prev_scheme != scheme || *prev_pk != pk || *prev_salt != salt {
                    skipped += 1;
                    tracing::debug!(
                        address = %hex::encode(addr),
                        "restore_pq_keys: refusing conflicting duplicate record"
                    );
                }
                continue;
            }
            valid_hashes.insert(*blake3::hash(&pk).as_bytes());
            valid.insert(addr, (scheme, pk, salt));
        }
        if let Some(tree) = self
            .pq_tree
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            // Second pass: valid address records install verbatim (the synced
            // node serves the publisher's bytes); hash-lookup records install
            // verbatim only for a valid address hash; unknown shapes pass
            // through verbatim (forward-compat, as before).
            let mut installed: u64 = 0;
            for (k, v) in &pairs {
                if k.len() == 34 && k[0] == b'a' && k[1] == b':' {
                    let mut addr = [0u8; 32];
                    addr.copy_from_slice(&k[2..]);
                    let keep = valid.get(&addr).is_some_and(|(s, pk, salt)| {
                        decode_record(v).is_some_and(|(ds, dpk, dsalt)| {
                            *s == ds && *pk == dpk && *salt == dsalt
                        })
                    });
                    if !keep {
                        continue;
                    }
                    tree.insert(k.as_slice(), v.as_slice())
                        .map_err(|e| format!("restore pq_keys tree insert failed: {e}"))?;
                    installed += 1;
                } else if k.len() == 32 {
                    let mut addr = [0u8; 32];
                    addr.copy_from_slice(k);
                    let keep = valid.get(&addr).is_some_and(|(s, pk, salt)| {
                        decode_record(v).is_some_and(|(ds, dpk, dsalt)| {
                            *s == ds && *pk == dpk && *salt == dsalt
                        })
                    });
                    if !keep {
                        continue;
                    }
                    tree.insert(k.as_slice(), v.as_slice())
                        .map_err(|e| format!("restore pq_keys tree insert failed: {e}"))?;
                    installed += 1;
                } else if k.len() == 34 && k[0] == b'h' && k[1] == b':' {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&k[2..]);
                    if !valid_hashes.contains(&hash) || *blake3::hash(v).as_bytes() != hash {
                        skipped += 1;
                        tracing::debug!(
                            hash = %hex::encode(hash),
                            "restore_pq_keys: refusing orphan hash-lookup record"
                        );
                        continue;
                    }
                    tree.insert(k.as_slice(), v.as_slice())
                        .map_err(|e| format!("restore pq_keys tree insert failed: {e}"))?;
                    installed += 1;
                } else {
                    tree.insert(k.as_slice(), v.as_slice())
                        .map_err(|e| format!("restore pq_keys tree insert failed: {e}"))?;
                    installed += 1;
                }
            }
            if skipped > 0 {
                tracing::warn!(
                    "restore_pq_keys: refused {skipped} invalid entries (installed {installed} valid)"
                );
            }
            return Ok(());
        }
        let mut fb = self
            .pq_keys_fallback
            .write()
            .unwrap_or_else(|e| e.into_inner());
        let installed = valid.len() as u64;
        for (addr, (scheme, pk, salt)) in valid {
            fb.insert(addr, (scheme, pk, salt));
        }
        if skipped > 0 {
            tracing::warn!(
                "restore_pq_keys: refused {skipped} invalid entries (fallback installed {installed} valid)"
            );
        }
        Ok(())
    }

    /// Fold every consensus subsystem that does not live in the trie into the
    /// trie, as a single digest under one namespaced key.
    ///
    /// Block application calls this so that a block's own state changes are
    /// committed as part of applying it, rather than relying on the next read.
    pub async fn commit_consensus_domains(&self) {
        let generation = self
            .commitment_generation
            .load(std::sync::atomic::Ordering::Acquire);
        let snapshot = self.commitment_snapshot().await;
        // §2 FOLD POINT (the unconditional twin of the one in
        // `commit_consensus_domains_if_stale`): same conditional domains, same
        // transient read guards, so both entry points commit byte-identical
        // digests for the same state.
        let zkml_models = self.zkml_models.read().await.clone();
        let cnvrf_snap = self.cnvrf_v3_snapshot().await;
        let evm_bindings = self.evm_bindings.read().await.clone();
        let pq_registry = self.pq_registry.read().await.clone();
        let digest = crate::commitment::commitment_digest_with_all_domains(
            &snapshot,
            &zkml_models,
            &cnvrf_snap,
            self.total_minted_nano(),
            &evm_bindings,
            &pq_registry,
        );
        self.state_trie
            .write()
            .await
            .insert(&crate::commitment::commitment_key(), &digest);
        self.committed_generation.store(
            generation.wrapping_add(1),
            std::sync::atomic::Ordering::Release,
        );
    }

    /// Clone the non-trie consensus state under each subsystem lock, so the
    /// digest is computed without holding seven locks at once.
    pub async fn commitment_snapshot(&self) -> crate::commitment::CommitmentSnapshot {
        crate::commitment::CommitmentSnapshot {
            tokens: self.tokens.read().await.clone(),
            staking: self.staking.read().await.clone(),
            orderbooks: self.orderbooks.read().await.clone(),
            order_escrow: self.order_escrow.read().await.clone(),
            pmm: self.pmm.read().await.clone(),
            pmm_usdt_token: *self.pmm_usdt_token.read().await,
            pmm_treasury: *self.pmm_treasury.read().await,
            contracts: self.contracts.read().await.clone(),
            governance: self.governance.read().await.clone(),
            oracle: self.oracle.read().await.clone(),
            session_keys: self.session_keys.read().await.clone(),
            // Bridge domain: cloned with the others (short critical section,
            // hashed without the lock). READ LAST - like every field here it
            // is only ever taken after the guards `execute_payload` holds, so
            // a root read can never deadlock against a payload in flight.
            bridge: self.bridge.read().await.clone(),
            // Cross-shard replay sets (audit F1): sorted vecs, cloned under
            // short-lived read guards like every other domain above. Read
            // after the bridge domain, for the same lock-ordering reason.
            cross_shard_consumed: self.cross_shard_consumed_snapshot().await,
            cross_shard_produced: self.cross_shard_produced_snapshot().await,
            cross_shard_completed: self.cross_shard_completed_snapshot().await,
            // §9 2PC: the committed two-phase-commit records (the
            // intermediate states of the cross-shard lifecycle). Read last,
            // for the same lock-ordering reason as the domains above.
            cross_shard_xpc: self.xpc_snapshot().await,
        }
    }

    /// Return the shard id this engine is operating on.
    pub fn shard_id(&self) -> u32 {
        self.shard_id.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Set the shard id for this engine.
    pub fn set_shard_id(&self, id: u32) {
        self.shard_id
            .store(id, std::sync::atomic::Ordering::Release);
    }

    /// Read the node's shard topology.
    ///
    /// The topology is the single source of truth of the address→shard rule
    /// (see `crate::sharding::ROUTING_RULE`).
    pub async fn shard_topology(
        &self,
    ) -> tokio::sync::RwLockReadGuard<'_, crate::sharding::ShardTopology> {
        self.shard_topology.read().await
    }

    /// Mutate the node's shard topology (the split/merge driver).
    pub async fn shard_topology_mut(
        &self,
    ) -> tokio::sync::RwLockWriteGuard<'_, crate::sharding::ShardTopology> {
        self.shard_topology.write().await
    }

    /// Resolve an address to its shard under this node's topology.
    ///
    /// THE rule, in one call: the masterchain is addressed explicitly
    /// (`ShardAddress::Masterchain`), a workchain address goes to the shard
    /// with the longest matching routing prefix.
    pub async fn route_address(&self, address: &crate::sharding::ShardAddress) -> u32 {
        let topology = self.shard_topology.read().await;
        crate::sharding::route_shard(&topology, address)
    }

    /// Build the MIGRATION MANIFEST for this shard: every trie key this
    /// shard holds, mapped to the address that owns it.
    ///
    /// The trie stores account leaves under the raw address, but it also
    /// stores namespaced DERIVED keys (a contract's code and ABI manifest, a
    /// token balance, a token's total supply). Those keys are hashes, so the
    /// owner cannot be recovered from the key alone — the migration needs
    /// this explicit map. A trie key the manifest does not classify aborts
    /// the migration (`MigrationError::UnclassifiedKey`): a split fails
    /// closed instead of silently dropping state.
    ///
    /// The consensus commitment key is deliberately NOT in the manifest: it
    /// is a digest over the whole state, so each child shard recomputes its
    /// own from its own state.
    pub async fn shard_migration_manifest(&self) -> crate::sharding::MigrationManifest {
        let mut manifest = crate::sharding::MigrationManifest::new();

        // 1. Account leaves, keyed by the raw address.
        for (addr, _acct) in self.accounts.read().await.iter() {
            manifest.own(*addr, *addr);
        }

        // 2. Contract code + ABI manifest, owned by the contract account.
        for (addr, contract) in self.contracts.read().await.contracts.iter() {
            manifest.own(crate::state_engine::contract_key(addr), *addr);
            if contract.abi.is_some() {
                manifest.own(crate::state_engine::contract_abi_key(addr), *addr);
            }
            if contract.source_hash.is_some() {
                manifest.own(crate::state_engine::contract_source_key(addr), *addr);
            }
        }

        // 3. Token balances, owned by the HOLDER; token supplies, owned by
        //    the token's minter (the address that created it).
        for (token_id, token) in self.tokens.read().await.tokens.iter() {
            for (holder, _bal) in token.balances.iter() {
                manifest.own(
                    crate::state_engine::token_balance_key(token_id, holder),
                    *holder,
                );
            }
            manifest.own(
                crate::state_engine::token_supply_key(token_id),
                token.metadata.minter,
            );
        }

        manifest
    }

    /// Persist the whole contract registry (mirrors the token snapshot API).
    pub async fn create_contract_snapshot(&self) -> Vec<u8> {
        let c = self.contracts.read().await;
        bincode::serialize(&*c).unwrap_or_default()
    }

    pub async fn restore_contract_snapshot(&self, bytes: &[u8]) -> Result<(), String> {
        let reg: crate::contract::ContractRegistry =
            bincode_deserialize_limited(bytes, MAX_SNAPSHOT_DECODE_BYTES)
                .map_err(|e| format!("Restore contract snapshot failed: {:?}", e))?;
        let mut contracts = self.contracts_write().await;
        *contracts = reg;
        let mut trie = self.state_trie.write().await;
        write_contract_trie_entries(&mut trie, &contracts);
        Ok(())
    }

    /// Re-commit token balances/supply and contract code hashes into the state
    /// trie. Used after restoring a domain snapshot so SPV proofs stay valid.
    pub async fn sync_aux_trie(&self) {
        let tokens = self.tokens.read().await;
        let contracts = self.contracts.read().await;
        let mut trie = self.state_trie.write().await;
        write_token_trie_entries(&mut trie, &tokens);
        write_contract_trie_entries(&mut trie, &contracts);
    }

    /// Cumulative nano-STELL ever minted by the engine (gross lifetime, never
    /// reduced by burns).
    ///
    /// WIRING REQUIRED (out of scope here, `commitment.rs`): this value is NOT
    /// yet folded into the consensus commitment. To commit it, add an
    /// APPENDED, self-gating domain (the zkML precedent) —
    /// `put_u64(h, b"total_minted_nano", v)` written from
    /// `InMemoryStateEngine::commit_consensus_domains_cached`
    /// (`state_engine/accounts.rs`) after the existing 13 domains — and
    /// extend `Domain::ALL` / `assemble_cached_digest_with_cnvrf` /
    /// `assemble_from_cache` in `commitment.rs`. Until then two nodes that
    /// disagree about minted supply can still report the same root.
    pub fn total_minted_nano(&self) -> u64 {
        self.total_minted_nano
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// Install this shard's CHAIN-WIDE mint share (nano-STELL).
    ///
    /// Called deterministically from the committed shard set (see
    /// [`crate::tokenomics::SupplyPartition`] and
    /// `ValidatorRuntime::with_shard`), never from an environment variable or
    /// a peer message. Idempotent and monotone in effect: a mint that already
    /// committed is never unwound; future mints are simply refused sooner.
    /// The effective ceiling is `min(TOTAL_SUPPLY_CAP, limit)`, so a caller
    /// can never widen the advertised global cap, only narrow this shard's
    /// slice of it.
    pub fn set_chain_mint_limit_nano(&self, limit: u64) {
        use std::sync::atomic::Ordering;
        let limit = limit.min(crate::tokenomics::TOTAL_SUPPLY_CAP);
        let mut current = self.chain_mint_limit_nano.load(Ordering::Acquire);
        // Monotone DOWNWARD: a second call can only narrow the shard's slice.
        // Without this, a stale or buggy caller could re-widen a limit that a
        // previous block already committed against, reopening headroom the
        // chain-wide accounting has already spent.
        loop {
            if limit >= current {
                return;
            }
            match self.chain_mint_limit_nano.compare_exchange_weak(
                current,
                limit,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(actual) => current = actual,
            }
        }
    }

    /// The effective chain-wide mint ceiling for THIS engine:
    /// `min(TOTAL_SUPPLY_CAP, the installed shard share)`.
    pub fn chain_mint_limit_nano(&self) -> u64 {
        self.chain_mint_limit_nano
            .load(std::sync::atomic::Ordering::Acquire)
            .min(crate::tokenomics::TOTAL_SUPPLY_CAP)
    }

    /// The shard's CUMULATIVE minted total INCLUDING its pre-mined genesis
    /// allocation, which is what the chain-wide accounting commits.
    ///
    /// [`Self::total_minted_nano`] is 0 until the first post-genesis mint
    /// folds the genesis baseline in (see [`Self::genesis_allocation_nano`]),
    /// so a freshly funded shard would otherwise report "minted nothing" and
    /// the masterchain aggregate would undercount its genesis allocation. This
    /// getter closes that: before the first mint it returns the committed
    /// native balance sum (exactly the baseline the first reservation will
    /// fold in); after it, the monotone counter.
    pub async fn committed_minted_nano(&self) -> u64 {
        let minted = self.total_minted_nano();
        if minted != 0 {
            return minted;
        }
        self.genesis_allocation_nano().await
    }

    /// Nano-STELL still mintable under [`crate::tokenomics::TOTAL_SUPPLY_CAP`].
    ///
    /// The counter is a committed, monotone scalar. Before the FIRST
    /// post-genesis reservation the pre-minted genesis allocation has not been
    /// folded in yet (see [`Self::genesis_allocation_nano`]), so this getter
    /// ALSO reads the committed balances in that state and subtracts the same
    /// baseline the first reserve will fold in - an over-allocated genesis
    /// therefore reports 0 headroom immediately, not a full cap.
    ///
    /// The balance read is `try_read` (never a blocking `read`): the getter is
    /// sync, and a caller that already holds the accounts lock or races a
    /// writer must not deadlock. In that case it falls back to the
    /// counter-only view; ENFORCEMENT is always in
    /// [`Self::reserve_mint_nano`], never in this read.
    pub fn remaining_mint_headroom_nano(&self) -> u64 {
        let limit = self.chain_mint_limit_nano();
        let minted = self.total_minted_nano();
        if minted != 0 {
            return limit.saturating_sub(minted);
        }
        match self.accounts.try_read() {
            Ok(map) => {
                let genesis = map
                    .values()
                    .fold(0u64, |sum, a| sum.saturating_add(a.balance));
                limit.saturating_sub(genesis)
            }
            Err(_) => limit,
        }
    }

    /// Native supply that was PRE-MINTED before the first post-genesis mint.
    ///
    /// Genesis funding (validators, staking pool, faucet) creates balances via
    /// `update_account` / `credit_native_transfer`, neither of which advances
    /// the mint counter. Without a baseline the advertised hard cap would be
    /// false at height 0: N validators x `GENESIS_VALIDATOR_BALANCE` can
    /// already exceed `TOTAL_SUPPLY_CAP` while the engine still reports a full
    /// cap of headroom (audit F4).
    ///
    /// The baseline is captured LAZILY, by the first reservation that moves
    /// the counter off zero, as the sum of every native balance committed at
    /// that instant. It is folded into `total_minted_nano` in the SAME CAS as
    /// that reserve, which gives the invariant
    ///
    /// ```text
    /// genesis_allocation + post_genesis_minted <= TOTAL_SUPPLY_CAP
    /// ```
    ///
    /// from the first mint onward:
    /// * it is counted exactly once - only one caller can win the `0 -> x`
    ///   CAS, and a loser sees `current != 0` and adds nothing;
    /// * no separate flag/field is needed, so genesis funding paths (which live
    ///   outside the state engine) cannot forget to report it;
    /// * a genesis allocation at/over the cap refuses EVERY mint (fail closed)
    ///   instead of letting emission create a second cap on top of it;
    /// * after the first mint the counter is non-zero, so this returns 0 and
    ///   later mints only add their own amount.
    ///
    /// Transfers conserve value, so summing the balances at the first
    /// reservation is exactly genesis + any pre-first-mint movement, all of
    /// which is pre-mined supply.
    pub async fn genesis_allocation_nano(&self) -> u64 {
        if self.total_minted_nano() != 0 {
            return 0;
        }
        let map = self.accounts.read().await;
        map.values()
            .fold(0u64, |sum, a| sum.saturating_add(a.balance))
    }

    /// Fail-closed global-supply reservation for one mint, folding the
    /// pre-minted genesis baseline in on the first reservation.
    ///
    /// CAS loop on the counter: concurrent mints can never both see the same
    /// headroom and overshoot. The reservation is taken BEFORE the balance
    /// credit and released by the caller if the credit itself fails, so the
    /// counter always bounds "value the engine committed to create".
    ///
    /// `genesis_nano` is added exactly once: only the reservation that moves
    /// the counter from zero may include it (see
    /// [`Self::genesis_allocation_nano`]). Callers that can be the first mint
    /// must use [`Self::reserve_mint`], which computes the baseline.
    ///
    /// `pub(super)` because the block-reward leg in `apply.rs` must reserve
    /// BEFORE it mutates the staking ledger: when the global cap is reached
    /// the ledger must never be touched (so there is no per-validator
    /// `pending_rewards` split to unwind).
    pub(super) fn reserve_mint_nano(&self, amount: u64, genesis_nano: u64) -> Result<(), String> {
        use std::sync::atomic::Ordering;
        let global_cap = crate::tokenomics::TOTAL_SUPPLY_CAP;
        // The chain-wide ceiling for THIS shard: its static share of the cap,
        // never above the advertised global cap. With `share_i` summing to at
        // most `global_cap`, no interleaving of shard mints can exceed it.
        let cap = self.chain_mint_limit_nano().min(global_cap);
        let mut current = self.total_minted_nano.load(Ordering::Acquire);
        loop {
            let base = if current == 0 { genesis_nano } else { 0 };
            let with_genesis = current
                .checked_add(base)
                .ok_or_else(|| "global supply counter overflows u64: refusing mint".to_string())?;
            let next = with_genesis
                .checked_add(amount)
                .ok_or_else(|| "global supply counter overflows u64: refusing mint".to_string())?;
            if next > cap {
                return Err(format!(
                    "global supply cap exceeded: minting {amount} nano-STELL would take this shard's total minted past {cap} (global cap {global_cap}, currently {current}, genesis allocation {base}, headroom {})",
                    cap.saturating_sub(current).saturating_sub(base)
                ));
            }
            match self.total_minted_nano.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    if next != current {
                        self.bump_commitment_generation();
                    }
                    return Ok(());
                }
                Err(actual) => current = actual,
            }
        }
    }

    /// Reserve `amount` nanos against the global cap, folding in the pre-minted
    /// genesis baseline on the first reservation.
    ///
    /// The async entry point every mint path uses ([`Self::mint_native`],
    /// block rewards, bridge deposits, PMM buys): it reads the account set to
    /// capture the append-only genesis baseline only while the counter is
    /// still zero, so steady-state reservations never take the accounts lock.
    pub(super) async fn reserve_mint(&self, amount: u64) -> Result<(), String> {
        let genesis = self.genesis_allocation_nano().await;
        self.reserve_mint_nano(amount, genesis)
    }

    /// Undo a reservation when the balance credit it paid for failed.
    pub(super) fn release_mint_nano(&self, amount: u64) {
        if amount != 0 {
            self.total_minted_nano
                .fetch_sub(amount, std::sync::atomic::Ordering::AcqRel);
            self.bump_commitment_generation();
        }
    }

    /// Credit a balance against an ALREADY-RESERVED mint.
    ///
    /// The caller took the global-supply reservation with
    /// [`Self::reserve_mint_nano`]. On a balance failure the reservation is
    /// released here, so headroom is never leaked.
    pub(super) async fn credit_reserved_native(
        &self,
        addr: &[u8; 32],
        amount: u64,
    ) -> Result<(), String> {
        match self.credit_balance_native(addr, amount).await {
            Ok(()) => Ok(()),
            Err(e) => {
                self.release_mint_nano(amount);
                Err(e)
            }
        }
    }

    /// Credit a balance + trie leaf WITHOUT touching the mint counter.
    ///
    /// Private on purpose: value-creating callers must go through
    /// [`Self::mint_native`]; value-moving callers through
    /// [`Self::credit_native_transfer`] / [`Self::transfer_native`]. This is
    /// the shared body so the two can never diverge on overflow behaviour.
    async fn credit_balance_native(&self, addr: &[u8; 32], amount: u64) -> Result<(), String> {
        let mut map = self.accounts.write().await;
        let acc = map
            .entry(*addr)
            .or_insert_with(|| AccountState::new(*addr, 0));
        acc.balance = acc.balance.checked_add(amount).ok_or("native overflow")?;
        let snap = acc.to_trie_bytes();
        drop(map);
        let mut trie = self.state_trie.write().await;
        trie.insert(addr, &snap);
        Ok(())
    }

    /// Credit native STELL to an account (**mint**) and commit to the trie.
    ///
    /// GLOBAL SUPPLY CAP: this is the ONE engine-level mint primitive. The
    /// amount is atomically reserved against [`crate::tokenomics::TOTAL_SUPPLY_CAP`]
    /// and the call fails closed (no balance change, no counter change) when
    /// the global total would exceed it. Local caps
    /// (`REWARDS_EMISSION_CAP`, `BRIDGE_MINT_CAP_NANO`, `GENESIS_VAULT_CAP`)
    /// remain the per-subsystem first line; this is the sum.
    ///
    /// Callers that are moving value that ALREADY exists (fee payout to the
    /// proposer, a refund from escrow, a pool payout, a cross-shard credit
    /// backed by a source-shard debit) must use
    /// [`Self::credit_native_transfer`] instead — a transfer must never be
    /// capped.
    pub async fn credit_native(&self, addr: &[u8; 32], amount: u64) -> Result<(), String> {
        self.mint_native(addr, amount).await
    }

    /// Mint `amount` nano-STELL into `addr`, fail-closed over the global cap.
    ///
    /// Same behaviour as [`Self::credit_native`]; the explicit name exists so
    /// mint intent is greppable at the call site.
    pub async fn mint_native(&self, addr: &[u8; 32], amount: u64) -> Result<(), String> {
        if amount == 0 {
            return Ok(());
        }
        self.reserve_mint(amount).await?;
        self.credit_reserved_native(addr, amount).await
    }

    /// Credit value that ALREADY exists on chain, without minting.
    ///
    /// For the credit half of a transfer whose debit already happened
    /// elsewhere (fees collected in `apply_block_transition`, escrow refunds,
    /// pool payouts). Not counted against [`crate::tokenomics::TOTAL_SUPPLY_CAP`]:
    /// capping a transfer is exactly the bug this split exists to prevent.
    /// Overflow is still refused fail-closed.
    pub async fn credit_native_transfer(&self, addr: &[u8; 32], amount: u64) -> Result<(), String> {
        if amount == 0 {
            return Ok(());
        }
        self.credit_balance_native(addr, amount).await
    }

    /// Atomically move existing nano-STELL between two accounts.
    ///
    /// A TRANSFER, not a mint: the global mint counter is untouched (the
    /// whole point — a transfer near the supply cap must still work), and the
    /// sender's debit and recipient's credit are validated BEFORE either is
    /// applied, so a refused transfer moves nothing. Both trie leaves are
    /// rewritten under the same post-lock batch.
    ///
    /// The recipient account is created on first credit (same as
    /// [`Self::credit_native`]); `from == to` is a no-op.
    pub async fn transfer_native(
        &self,
        from: &[u8; 32],
        to: &[u8; 32],
        amount: u64,
    ) -> Result<(), String> {
        if amount == 0 || from == to {
            return Ok(());
        }
        let mut map = self.accounts.write().await;
        let from_balance = map
            .get(from)
            .map(|a| a.balance)
            .ok_or_else(|| "account does not exist".to_string())?;
        if from_balance < amount {
            return Err("Insufficient native STELL balance".to_string());
        }
        let to_balance = map.get(to).map(|a| a.balance).unwrap_or(0);
        let new_to = to_balance
            .checked_add(amount)
            .ok_or_else(|| "native overflow".to_string())?;

        let from_snap = {
            let acc = map
                .get_mut(from)
                .ok_or_else(|| "account does not exist".to_string())?;
            acc.balance = from_balance - amount;
            acc.to_trie_bytes()
        };
        let to_snap = {
            let acc = map.entry(*to).or_insert_with(|| AccountState::new(*to, 0));
            acc.balance = new_to;
            acc.to_trie_bytes()
        };
        drop(map);

        let mut trie = self.state_trie.write().await;
        trie.insert(to, &to_snap);
        trie.insert(from, &from_snap);
        Ok(())
    }

    /// Debit native STELL from an account (burn) and commit to the trie.
    ///
    /// A burn does NOT restore headroom: [`Self::total_minted_nano`] is gross
    /// lifetime minting, so a burn-then-mint cycle can never create more than
    /// the cap over the life of the chain.
    pub async fn debit_native(&self, addr: &[u8; 32], amount: u64) -> Result<(), String> {
        let mut map = self.accounts.write().await;
        let acc = map
            .get_mut(addr)
            .ok_or_else(|| "account does not exist".to_string())?;
        if acc.balance < amount {
            return Err("Insufficient native STELL balance".to_string());
        }
        acc.balance -= amount;
        let snap = acc.to_trie_bytes();
        drop(map);
        let mut trie = self.state_trie.write().await;
        trie.insert(addr, &snap);
        Ok(())
    }

    /// Faucet (PQ) helpers: genesis funding with a PQ faucet key.
    ///
    /// The faucet's PQ account is the Falcon-512 address derived from the
    /// 32-byte faucet seed with the SAME raw derivation `rpc::Faucet::new`
    /// uses (`FalconKeypair::generate_from_seed_bytes`, no wallet KDF): a PQ
    /// drip (`Faucet::build_transfer` under pure-PQ, byte-identical to
    /// `sign_pq_explicit_transfer`) spends exactly this account, so genesis
    /// MUST credit it for PQ payouts to verify and finalize. The light-wallet
    /// KDF derives a DIFFERENT address from the same seed and cannot spend
    /// these funds.
    ///
    /// Default behavior is untouched: these are new primitives for PQ faucet
    /// flows and tests; no existing funding path calls them.
    pub fn faucet_pq_account_from_seed(seed: &[u8; 32]) -> [u8; 32] {
        let kp = crate::post_quantum::FalconKeypair::generate_from_seed_bytes(seed);
        crate::post_quantum::derive_pq_address(
            crate::post_quantum::PqScheme::Falcon512,
            &kp.public_key,
            &crate::post_quantum::DEFAULT_SALT,
        )
    }

    /// Genesis funding with a PQ faucet key: credit the PQ faucet account for
    /// `seed` (see [`Self::faucet_pq_account_from_seed`]). Mirrors the
    /// `credit_native(&faucet.account(), GENESIS_FAUCET_BALANCE)` step in
    /// `src/main.rs` for the pure-PQ serving account (under pure-PQ the two
    /// credit exactly the same address).
    pub async fn fund_faucet_genesis_pq(
        &self,
        seed: &[u8; 32],
        balance: u64,
    ) -> Result<(), String> {
        self.credit_native(&Self::faucet_pq_account_from_seed(seed), balance)
            .await
    }

    /// Read the committed bridge domain (the replay set, the parked
    /// withdrawal queue, the rate window). Reads cannot make the commitment
    /// stale, so this does NOT bump `commitment_generation`.
    pub async fn bridge_read(
        &self,
    ) -> tokio::sync::RwLockReadGuard<'_, crate::bridge::BridgeState> {
        self.bridge.read().await
    }

    /// Write access to the committed bridge domain. Bumps
    /// `commitment_generation` like every other `*_write`, so the very next
    /// root read folds the domain into the state root - the whole point of
    /// committing it (PROTOCOL.md I1).
    pub async fn bridge_write(
        &self,
    ) -> tokio::sync::RwLockWriteGuard<'_, crate::bridge::BridgeState> {
        self.dom_guard(crate::commitment::Domain::Bridge, &self.bridge)
            .await
    }

    /// Serialize the committed bridge domain for persistence.
    ///
    /// The domain gets its OWN storage tree, exactly like the session-key
    /// registry: `DomainSnapshot` is a bincode struct whose restore path
    /// hard-errors, so appending a field would stop every pre-bridge domain
    /// snapshot from decoding - a silent wipe of the whole non-account state
    /// of every existing node. An absent entry (a directory written before the
    /// bridge landed) correctly means "empty", which contributes zero bytes to
    /// the commitment digest and therefore restores to the root it was
    /// written with.
    pub async fn bridge_snapshot(&self) -> Vec<u8> {
        bincode::serialize(&*self.bridge.read().await).unwrap_or_default()
    }

    /// Install a persisted bridge domain (startup restore). Bumps the
    /// commitment generation like every other domain install, so the restored
    /// replay set, withdrawal queue and rate window are folded into the very
    /// next root read - a node that came back from disk still refuses a
    /// replayed `source_tx_hash` (the whole point of committing the set).
    pub async fn restore_bridge(&self, bytes: &[u8]) -> Result<(), String> {
        match bincode_deserialize_limited::<crate::bridge::BridgeState>(
            bytes,
            MAX_SNAPSHOT_DECODE_BYTES,
        ) {
            Ok(state) => {
                *self.bridge_write().await = state;
                return Ok(());
            }
            Err(_) => {
                // Fall through to the older formats below.
            }
        }
        if let Ok(v3) = bincode_deserialize_limited::<crate::bridge::BridgeStateV3>(
            bytes,
            MAX_SNAPSHOT_DECODE_BYTES,
        ) {
            // V3 = pre-Bridge-V2 layout (no release receipts / payout replay
            // set / refund tombstones). Upgrade LOUD: a pre-V2 `executed = true`
            // flag is NOT retroactively promoted to a verified receipt, so
            // those withdrawals stay unprovable exactly like deposits older
            // than `CHALLENGE_MAX_AGE_SECS`.
            tracing::warn!(
                "[bridge] restored pre-Bridge-V2 V3 state: no payout receipts exist for already-released withdrawals"
            );
            *self.bridge_write().await = v3.upgrade();
            return Ok(());
        }
        if let Ok(v2) = bincode_deserialize_limited::<crate::bridge::BridgeStateV2>(
            bytes,
            MAX_SNAPSHOT_DECODE_BYTES,
        ) {
            // Pre-dispute snapshot (no records/disputes): upgrade, LOUD —
            // deposits settled before the upgrade can never be challenged
            // (exactly like deposits older than CHALLENGE_MAX_AGE_SECS).
            tracing::warn!(
                "[bridge] restored pre-dispute V2 state: old deposits have no records and are unchallengeable"
            );
            *self.bridge_write().await = v2.upgrade();
            return Ok(());
        }
        let v1: crate::bridge::BridgeStateV1 =
            bincode_deserialize_limited(bytes, MAX_SNAPSHOT_DECODE_BYTES)
                .map_err(|e| format!("restore bridge state failed: {e:?}"))?;
        *self.bridge_write().await = v1.upgrade();
        // LOUD (audit 2026-10-06): the upgrade zeroes mint counters, so on a
        // chain that minted pre-upgrade the caps overstate headroom until an
        // out-of-band baseline audit. Operators must see this line.
        tracing::warn!(
            "[bridge] restored pre-F-H V1 state: mint counters start at ZERO — verify real minted supply out-of-band before trusting cap headroom (exact on fresh/test chains)"
        );
        Ok(())
    }

    /// Serialize the committed zkML model registry for persistence (audit F-B).
    ///
    /// Same reasoning as above: registered models (and their VKs) are
    /// committed state; dropping them on restart would change the root and
    /// un-register models the chain agreed on. Own tree, absent means empty.
    pub async fn zkml_models_snapshot(&self) -> Vec<u8> {
        bincode::serialize(&*self.zkml_models.read().await).unwrap_or_default()
    }

    /// Install a persisted zkML model registry (startup restore).
    pub async fn restore_zkml_models(&self, bytes: &[u8]) -> Result<(), String> {
        let reg: crate::zkml::ZkMlModelRegistry =
            bincode_deserialize_limited(bytes, MAX_SNAPSHOT_DECODE_BYTES)
                .map_err(|e| format!("restore zkML models failed: {e:?}"))?;
        *self.zkml_models_write().await = reg;
        Ok(())
    }

    /// Persist the whole token registry (separate from account snapshot).
    pub async fn create_token_snapshot(&self) -> Vec<u8> {
        let tokens = self.tokens.read().await;
        bincode::serialize(&*tokens).unwrap_or_default()
    }

    pub async fn restore_token_snapshot(&self, bytes: &[u8]) -> Result<(), String> {
        let reg: TokenRegistry = bincode_deserialize_limited(bytes, MAX_SNAPSHOT_DECODE_BYTES)
            .map_err(|e| format!("Restore token snapshot failed: {:?}", e))?;
        // Consistent lock order: tokens -> trie
        let mut tokens = self.tokens_write().await;
        *tokens = reg;
        let mut trie = self.state_trie.write().await;
        // Keep the state trie in sync so SPV proofs still work after restore.
        write_token_trie_entries(&mut trie, &tokens);
        Ok(())
    }

    /// Generate cryptographic Merkle inclusion proof for an account address
    pub async fn get_account_proof(&self, address: &[u8; 32]) -> Option<MerkleProof> {
        self.state_trie.read().await.generate_merkle_proof(address)
    }

    /// The CANONICAL state capture: the accounts (address-sorted) AND the D2
    /// consensus penalty map.
    ///
    /// ONE definition, used by every snapshot path (the inline
    /// [`Self::create_snapshot`] AND the off-tick persistence path in
    /// `crate::storage`), so the bytes a node WRITES are the bytes a node
    /// READS back. Two capture paths that disagree on the shape or the order
    /// would write a snapshot that restores into a different state - and a
    /// state root that differs from the one the snapshot was taken at.
    ///
    /// The penalty is part of the capture because it enters the CONSENSUS fee
    /// floor (`consensus_floor_parts`): a snapshot that carried only the
    /// accounts would restore a node with an EMPTY penalty map while a node
    /// that applied the blocks has the real one - the two would then charge
    /// DIFFERENT fees for the same transaction and end up with DIFFERENT
    /// state roots, i.e. a consensus split triggered by nothing more exotic
    /// than a node restarting (audit W6.6).
    ///
    /// LOCK ORDER: the penalty map is read BEFORE the accounts map (the
    /// documented order is penalty/governance -> accounts), the same order
    /// `commit_native` uses (it reads the floor before it takes the accounts
    /// lock) and the same order the restore path installs them in.
    pub async fn capture_state_snapshot(&self) -> StateSnapshotV2 {
        let penalty = self.consensus_penalty.read().await.clone();
        let map = self.accounts.read().await;
        let mut accounts: Vec<AccountState> = map.values().cloned().collect();
        // Address-sorted: the snapshot bytes must not depend on the hash map's
        // iteration order, or two nodes capturing the same state could write
        // different bytes (and a restore would not reproduce the root).
        accounts.sort_by_key(|a| a.address);
        StateSnapshotV2 {
            accounts,
            penalty,
            total_minted_nano: self.total_minted_nano(),
        }
    }

    /// Fast flush / snapshot serialization for async persistence
    ///
    /// The snapshot carries the accounts AND the D2 consensus penalty map
    /// (see [`StateSnapshotV2`]): the penalty enters the CONSENSUS fee floor
    /// (`consensus_floor_parts`), so it is consensus-critical state and must
    /// travel with the state, or a node that restores from a snapshot would
    /// charge a DIFFERENT fee than a node that applied the blocks - a
    /// different state root, i.e. a consensus split (audit W6.6).
    pub async fn create_snapshot(&self) -> Vec<u8> {
        bincode::serialize(&self.capture_state_snapshot().await).unwrap_or_default()
    }

    pub async fn restore_snapshot(&self, bytes: &[u8]) -> Result<(), String> {
        let (snapshot, penalty, total_minted_nano) = Self::parse_account_snapshot(bytes)?;
        // The restored snapshot is the WHOLE supply view a reorg replays from:
        // rebase the global mint counter to it before any block is re-applied,
        // so replayed mints are counted exactly once and a restarted node
        // cannot mint a second full cap from zero.
        self.set_total_minted_from_snapshot(total_minted_nano);
        // The penalty is restored BEFORE the accounts lock is taken: the
        // documented lock order is penalty/governance -> accounts, and the
        // reverse order here would be an ABBA deadlock against `commit_native`
        // (which reads the floor before it takes the accounts lock).
        *self.consensus_penalty.write().await = penalty;

        // This rebuilds the trie from scratch, which drops the commitment digest
        // key. Bump the generation so the next root read is forced to recompute and
        // re-insert it; otherwise the generation-guarded skip would serve a trie that
        // is missing the subsystem commitment. The replay sets below are
        // CLEARED (a committed domain), so this is a domain bump, not a bare
        // global one: the global moves with it.
        self.bump_domain_generation(crate::commitment::Domain::CrossShard);
        self.bump_domain_generation(crate::commitment::Domain::Xpc);
        self.bump_domain_generation(crate::commitment::Domain::EvmBindings);
        self.bump_domain_generation(crate::commitment::Domain::PqRegistry);

        // The cross-shard replay sets are derived from applied blocks and are
        // not part of the accounts snapshot: clear them so a reorg that
        // restores to a checkpoint and replays the canonical chain rebuilds
        // them from scratch rather than refusing a message the replayed chain
        // legitimately consumes again. ALL FOUR committed sets (including
        // `cross_shard_xpc`) are cleared together - clearing consumed while
        // keeping produced/completed/xpc (or vice versa) would rebuild a
        // frankenset whose linkage/completion/2PC phase no longer matches the
        // replayed blocks (and whose XPC trie leaves were wiped by rebuilding
        // the trie below). This clear is correct ONLY for the reorg-replay
        // path; snapshot-sync and boot MUST use
        // `restore_snapshot_preserve_replay_sets` plus the fail-closed
        // coverage gate (`cross_shard_replay_covers`), never this method.
        self.cross_shard_consumed.write().await.clear();
        self.cross_shard_produced.write().await.clear();
        self.cross_shard_completed.write().await.clear();
        self.cross_shard_xpc.write().await.clear();
        *self.evm_bindings.write().await = super::EvmBindingsState::default();
        *self.pq_registry.write().await = crate::pq_registry::PqRegistry::default();
        self.evm_settled.write().await.clear();

        // Consistent lock order: accounts -> tokens -> trie
        let mut map = self.accounts.write().await;
        let tokens = self.tokens.read().await;
        let mut trie = self.state_trie.write().await;
        map.clear();
        *trie = PatriciaTrie::new();

        for acc in snapshot {
            let data = acc.to_trie_bytes();
            trie.insert(&acc.address, &data);
            map.insert(acc.address, acc);
        }

        // CRITICAL: rebuilding the trie must not drop token entries, otherwise
        // token balances become SPV-unprovable after a restore.
        write_token_trie_entries(&mut trie, &tokens);

        Ok(())
    }

    /// Snapshot-sync / boot install of an accounts snapshot that MUST NOT
    /// disturb the cross-shard replay sets (audit F1).
    ///
    /// Byte-identical to `restore_snapshot` except the replay sets are
    /// PRESERVED, not cleared: the caller installs the snapshot's replay blob
    /// afterwards via `restore_cross_shard_replay` (extend-only), and the
    /// fail-closed coverage gate (`cross_shard_replay_covers`) runs BEFORE any
    /// mutation. The reorg-replay path keeps using `restore_snapshot` (clear +
    /// rebuild from replayed blocks). Two methods, not a flag: a flag at this
    /// call site is exactly how a future caller silently picks the wrong
    /// semantics and re-opens the double mint.
    pub async fn restore_snapshot_preserve_replay_sets(&self, bytes: &[u8]) -> Result<(), String> {
        let (snapshot, penalty, total_minted_nano) = Self::parse_account_snapshot(bytes)?;
        // Same rebase as `restore_snapshot`: the global mint counter tracks
        // the restored supply, not the pre-restore engine's.
        self.set_total_minted_from_snapshot(total_minted_nano);
        // The penalty travels with the state (see `create_snapshot`): install
        // it BEFORE the accounts lock (documented lock order).
        *self.consensus_penalty.write().await = penalty;

        // Same generation bump as `restore_snapshot`: the trie is rebuilt from
        // scratch, dropping the commitment digest key. Committed subsystem
        // state is UNCHANGED here (no replay-set clear), so only the global
        // moves: the next root read replays every cached preimage and
        // re-inserts the identical digest.
        self.force_commitment_recompute();

        // NO replay-set clear here - that is the entire point of this method
        // (see its docs). The caller owns the replay outcome via the coverage
        // gate + `restore_cross_shard_replay`.
        let xpc_records: Vec<crate::xshard2pc::XpcRecord> = self
            .cross_shard_xpc
            .read()
            .await
            .values()
            .cloned()
            .collect();
        let evm_settled: Vec<[u8; 32]> = self.evm_settled.read().await.iter().copied().collect();

        // Consistent lock order: accounts -> tokens -> trie
        let mut map = self.accounts.write().await;
        let tokens = self.tokens.read().await;
        let mut trie = self.state_trie.write().await;
        map.clear();
        *trie = PatriciaTrie::new();

        for acc in snapshot {
            let data = acc.to_trie_bytes();
            trie.insert(&acc.address, &data);
            map.insert(acc.address, acc);
        }

        // CRITICAL: rebuilding the trie must not drop token, 2PC, or settled EVM
        // intent entries, otherwise token balances, 2PC phase proofs, or
        // nullifier leaves become missing/unprovable after a restore.
        write_token_trie_entries(&mut trie, &tokens);
        for rec in &xpc_records {
            let key = crate::xshard2pc::xpc_state_key(&rec.tx_hash);
            let value = crate::xshard2pc::xpc_state_value(rec.phase, &rec.tx_hash);
            trie.insert(&key, &value);
        }
        for digest in &evm_settled {
            let key = Self::evm_settled_key(digest);
            trie.insert(&key, &[1u8]);
        }

        Ok(())
    }

    /// Rebase the global mint counter to the value carried by a snapshot.
    ///
    /// Used by both accounts restore paths. Without this, a node that
    /// restarts (or rewinds to a reorg checkpoint) would carry a counter of
    /// zero — or a stale higher value — while the accounts already hold the
    /// chain's supply, and could mint up to a full `TOTAL_SUPPLY_CAP` on top of
    /// it. The current snapshot format carries the counter explicitly (it is
    /// a committed scalar, so it cannot be re-derived from balances without
    /// counting the pre-mined genesis allocation as emission). A legacy
    /// snapshot that predates the field installs 0, and the first later
    /// reservation folds the pre-minted balances in exactly once, so the
    /// `genesis + minted <= cap` invariant also holds after a legacy restore.
    ///
    /// `restore_snapshot_chunked*` lives in `memory_bounds.rs` and calls this
    /// same setter, so the two restore shapes cannot disagree.
    pub(super) fn set_total_minted_from_snapshot(&self, total_minted_nano: u64) {
        self.total_minted_nano
            .store(total_minted_nano, std::sync::atomic::Ordering::Release);
    }

    /// Shared accounts-snapshot decoder for both restore methods (current
    /// shape, legacy fallback). One decoder so the two restore paths can never
    /// disagree on what bytes mean.
    ///
    /// Returns the accounts AND the D2 consensus penalty map. The penalty is
    /// consensus-critical (it enters the charged fee through
    /// `consensus_floor_parts`), so it MUST travel with the state: a node that
    /// restored only the accounts would charge a different fee than a node
    /// that applied the blocks (audit W6.6).
    ///
    /// FORMAT STRICTNESS (audit F10): a CURRENT snapshot is magic-prefixed and
    /// versioned, and is decoded with an EXACT length - every field, including
    /// the trailing `total_minted_nano`, is mandatory. A truncated current
    /// blob keeps its magic prefix, so it is detected as "versioned but
    /// corrupt" and REFUSED; it can never fall through to a legacy shape and
    /// silently read a missing mint counter as 0.
    ///
    /// LEGACY shapes (no magic, so they predate the versioned envelope) are
    /// still accepted, each with an exact-length decode:
    /// * the intermediate `accounts + penalty` V2 envelope (pre-`total_minted`;
    ///   reads as 0 and the first later reservation folds the pre-mined
    ///   balances in), and
    /// * the original bare `Vec<AccountState>` / bare V1-account vector (empty
    ///   penalty, counter 0).
    #[allow(clippy::type_complexity)]
    // GATE: snapshot decoder returns full state tuple; alias would churn restore paths.
    fn parse_account_snapshot(
        bytes: &[u8],
    ) -> Result<(Vec<AccountState>, HashMap<[u8; 32], u64>, u64), String> {
        // CURRENT format FIRST. Exact length + mandatory fields.
        match bincode_deserialize_exact::<StateSnapshotV2>(bytes, MAX_SNAPSHOT_DECODE_BYTES) {
            Ok(v2) => return Ok((v2.accounts, v2.penalty, v2.total_minted_nano)),
            Err(e) => {
                // A blob that STARTS with the magic is a versioned snapshot;
                // if it does not decode exactly it is truncated/corrupt and
                // must fail rather than be reinterpreted as a legacy shape.
                if snapshot_has_magic(bytes) {
                    return Err(format!("Restore snapshot failed: {e:?}"));
                }
            }
        }

        // Legacy intermediate V2 that already carried the counter but had no
        // magic prefix (the immediately preceding writer). Exact length.
        if let Ok(legacy) = bincode_deserialize_exact::<
            super::types::LegacyStateSnapshotV2WithCounter,
        >(bytes, MAX_SNAPSHOT_DECODE_BYTES)
        {
            return Ok((legacy.accounts, legacy.penalty, legacy.total_minted_nano));
        }

        // Legacy intermediate V2: accounts + penalty, no mint counter.
        if let Ok(legacy) = bincode_deserialize_exact::<super::types::LegacyStateSnapshotV2>(
            bytes,
            MAX_SNAPSHOT_DECODE_BYTES,
        ) {
            return Ok((legacy.accounts, legacy.penalty, 0));
        }

        // Legacy bare account vector(s). The current AccountState shape first,
        // then the pre-PQ-field shape.
        if let Ok(states) =
            bincode_deserialize_exact::<Vec<AccountState>>(bytes, MAX_SNAPSHOT_DECODE_BYTES)
        {
            return Ok((states, HashMap::new(), 0));
        }
        #[derive(Deserialize)]
        struct LegacyAccountState {
            address: [u8; 32],
            balance: u64,
            nonce: u64,
            code: Vec<u8>,
            code_hash: Option<CellHash>,
            storage_root: Option<CellHash>,
            inbox: VecDeque<ActorMessage>,
            outbox: VecDeque<ActorMessage>,
        }
        let legacy: Vec<LegacyAccountState> =
            bincode_deserialize_exact(bytes, MAX_SNAPSHOT_DECODE_BYTES)
                .map_err(|e| format!("Restore snapshot failed: {e:?}"))?;
        Ok((
            legacy
                .into_iter()
                .map(|l| AccountState {
                    address: l.address,
                    balance: l.balance,
                    nonce: l.nonce,
                    code: l.code,
                    code_hash: l.code_hash,
                    storage_root: l.storage_root,
                    inbox: l.inbox,
                    outbox: l.outbox,
                    scheme: crate::post_quantum::PqScheme::Falcon512,
                    pubkey_hash: None,
                })
                .collect(),
            HashMap::new(),
            0,
        ))
    }

    /// Decode the chunks produced by `create_snapshot_chunked` (validate phase,
    /// no locks held): the account groups AND the penalty map carried by the
    /// FIRST chunk.
    ///
    /// The first chunk is the magic-prefixed [`StateSnapshotV2`] shape
    /// (accounts + penalty + mint counter); the rest are bare account chunks.
    /// A legacy chunk set (no magic) is still accepted through the explicit
    /// legacy shapes - the penalty is then empty and the counter 0.
    ///
    /// STRICTNESS (audit F10): every chunk is decoded with an EXACT length. A
    /// first chunk that starts with the magic but does not decode exactly is a
    /// truncated/corrupt current snapshot and FAILS; it is never reinterpreted
    /// as a legacy chunk (which would restore a zero mint counter over live
    /// balances).
    #[allow(clippy::type_complexity)]
    // GATE: chunk decoder returns full state tuple; alias would churn restore paths.
    pub(super) fn decode_snapshot_chunks(
        chunks: &[Vec<u8>],
    ) -> Result<(Vec<Vec<AccountState>>, HashMap<[u8; 32], u64>, u64), String> {
        let mut decoded: Vec<Vec<AccountState>> = Vec::with_capacity(chunks.len());
        let mut penalty: HashMap<[u8; 32], u64> = HashMap::new();
        let mut total_minted_nano = 0u64;
        for (i, raw) in chunks.iter().enumerate() {
            if i == 0 {
                match bincode_deserialize_exact::<StateSnapshotV2>(raw, MAX_SNAPSHOT_DECODE_BYTES) {
                    Ok(v2) => {
                        decoded.push(v2.accounts);
                        penalty = v2.penalty;
                        total_minted_nano = v2.total_minted_nano;
                        continue;
                    }
                    Err(e) if snapshot_has_magic(raw) => {
                        return Err(format!(
                            "restore snapshot chunk 0 failed (versioned but truncated/corrupt): {e:?}"
                        ));
                    }
                    Err(_) => {}
                }
                // Legacy unversioned envelope that already carried the counter
                // (the immediately preceding writer), exact length.
                if let Ok(legacy) = bincode_deserialize_exact::<
                    super::types::LegacyStateSnapshotV2WithCounter,
                >(raw, MAX_SNAPSHOT_DECODE_BYTES)
                {
                    decoded.push(legacy.accounts);
                    penalty = legacy.penalty;
                    total_minted_nano = legacy.total_minted_nano;
                    continue;
                }
                // Legacy intermediate envelope (accounts + penalty, no mint
                // counter). Exact length; a truncated current chunk cannot
                // reach here because it carries the magic and returned above.
                if let Ok(legacy) = bincode_deserialize_exact::<super::types::LegacyStateSnapshotV2>(
                    raw,
                    MAX_SNAPSHOT_DECODE_BYTES,
                ) {
                    decoded.push(legacy.accounts);
                    penalty = legacy.penalty;
                    total_minted_nano = 0;
                    continue;
                }
            }
            let states: Vec<AccountState> =
                bincode_deserialize_exact(raw, MAX_SNAPSHOT_DECODE_BYTES)
                    .map_err(|e| format!("restore snapshot chunk {i} failed: {e:?}"))?;
            decoded.push(states);
        }
        Ok((decoded, penalty, total_minted_nano))
    }
}

// ============================================================================
// EVM address ↔ PQ account binding index — engine surface
// ============================================================================
//
// The INDEX ITSELF lives in the EVM domain
// (`crate::evm_adapter::binding::EvmBindingRegistry`): it is an address book
// for the EVM WRITE path, not consensus state, and its records are the
// committed `SysCallBindEvmAddress` / carrier transactions themselves.
//
// WHAT IT IS: a bounded, append-only `EVM address (20) → PQ account (32)` map
// plus its inverse, replayed deterministically from COMMITTED records in block
// order, FIRST-WRITER-WINS. A second claim on an already-bound EVM address is
// refused, never silently re-bound (a re-bind would let a thief redirect an EVM
// identity's routing).
//
// WHAT IT IS NOT: it is not folded into the state root, because the per
// transaction domain-commit hook lives in `state_engine/apply.rs` (owned
// elsewhere this wave). Every CONSENSUS fact is re-checked from signatures and
// payload bytes alone — `evm_adapter::verify_binding_claim` /
// `verify_carrier_intent` are PURE and the VM runs them at execution — so a
// stale, empty or wrong index can only change which transactions a node ADMITS
// and how it answers an address query. It can never make two nodes move
// different money, which is why execution never reads it.
//
// These methods are the engine-level accessors so the RPC/admission paths do
// not depend on the storage shape: replacing the process-local index with a
// state-root domain later is a change HERE, not at every call site.

impl InMemoryStateEngine {
    /// The PQ account an EVM address is bound to, as this node knows it.
    ///
    /// Reads the canonical on-chain [`Domain::EvmBindings`] state first (truth
    /// for `height >= EVM_BINDINGS_STATE_ACTIVATION_HEIGHT`), falling back to
    /// the pre-activation process-local index [`crate::evm_adapter::lookup_bound_pq`].
    pub async fn evm_binding_pq(&self, evm: &[u8; 20]) -> Option<[u8; 32]> {
        if let Some(pq) = self.evm_bindings.read().await.get_pq(evm) {
            return Some(pq);
        }
        crate::evm_adapter::lookup_bound_pq(evm)
    }

    /// The EVM address a PQ account is bound to, as this node knows it.
    ///
    /// Reads the canonical on-chain [`Domain::EvmBindings`] state first,
    /// falling back to the pre-activation process-local index
    /// [`crate::evm_adapter::lookup_bound_evm`].
    pub async fn evm_binding_for_pq(&self, pq: &[u8; 32]) -> Option<[u8; 20]> {
        if let Some(evm) = self.evm_bindings.read().await.get_evm(pq) {
            return Some(evm);
        }
        crate::evm_adapter::lookup_bound_evm(pq)
    }

    /// Replay a block's (or a window's) COMMITTED transactions into the index,
    /// in the order given. Returns how many binding statements were accepted.
    ///
    /// Deterministic and idempotent: replaying the same chain twice derives the
    /// same map, and a conflicting second claim is dropped (first wins) instead
    /// of overwriting.
    pub fn observe_committed_evm_txs(&self, txs: &[crate::sharding::Transaction]) -> usize {
        let Ok(mut idx) = crate::evm_adapter::evm_binding_index().write() else {
            return 0;
        };
        txs.iter()
            .filter(|tx| idx.observe_transaction(tx).is_some())
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sharding::Transaction;
    use crate::xshard2pc::XpcRecord;

    #[tokio::test]
    async fn restore_snapshot_clears_cross_shard_xpc_and_updates_domain() {
        let engine = InMemoryStateEngine::new();
        let user = [0x31u8; 32];
        engine
            .update_account(AccountState::new(user, 1_000_000))
            .await;

        let checkpoint = engine.create_snapshot().await;
        let expected_root = engine.get_state_root().await;

        let tx = Transaction {
            from: user,
            to: [0x32u8; 32],
            amount: 500,
            gas_limit: 280_000,
            nonce: 0,
            source_shard: 0,
            target_shard: 1,
            signature: vec![],
            payload: vec![],
            priority_fee_per_gas: 0,
        };
        let tx_hash = tx.compute_tx_hash();
        let rec = XpcRecord::prepared(tx, 0, 1, 5);
        engine.restore_xpc_records(&[rec]).await;
        assert_eq!(engine.xpc_len().await, 1);
        assert!(engine.get_xpc_proof(&tx_hash).await.is_some());
        assert_ne!(engine.get_state_root().await, expected_root);

        // Restoring the pre-branch checkpoint must clear cross_shard_xpc AND
        // invalidate Domain::Xpc so the state root matches the checkpoint.
        engine.restore_snapshot(&checkpoint).await.expect("restore");
        assert_eq!(engine.xpc_len().await, 0);
        assert!(engine.get_xpc_proof(&tx_hash).await.is_none());
        assert_eq!(engine.get_state_root().await, expected_root);
    }

    #[tokio::test]
    async fn restore_snapshot_clears_evm_bindings_and_updates_domain() {
        let engine = InMemoryStateEngine::new();
        let user = [0x41u8; 32];
        engine
            .update_account(AccountState::new(user, 1_000_000))
            .await;

        let checkpoint = engine.create_snapshot().await;
        let expected_root = engine.get_state_root().await;

        let evm = [0xAAu8; 20];
        assert!(engine.evm_bindings_write().await.bind(evm, user).unwrap());
        assert_eq!(engine.evm_binding_pq(&evm).await, Some(user));
        assert_eq!(engine.evm_binding_for_pq(&user).await, Some(evm));
        assert_ne!(engine.get_state_root().await, expected_root);

        engine.restore_snapshot(&checkpoint).await.expect("restore");
        assert!(engine.evm_bindings_read().await.is_empty());
        assert_eq!(engine.get_state_root().await, expected_root);
    }

    /// S1-STATEROOT-CONCURRENT-STALE regression.
    ///
    /// A root read that folds the commitment digest, then loses the race to a
    /// mutation before it writes the trie, must NOT publish its now-stale
    /// digest over the newer one. The old code inserted unconditionally, so a
    /// slow reader clobbered a newer root (and stamped it as committed).
    ///
    /// The interleaving is forced deterministically: block the read on the
    /// `state_trie` write lock AFTER its fold has run, mutate a committed
    /// domain while it is parked, then let it finish. The returned root must
    /// be the one for the mutated state, not the pre-mutation digest.
    #[tokio::test(flavor = "current_thread")]
    async fn concurrent_root_read_cannot_publish_a_stale_commitment() {
        use std::future::Future;
        use std::pin::Pin;
        use std::task::{Context, Poll, Waker};

        fn poll_once<F: Future>(fut: &mut Pin<Box<F>>) -> Poll<F::Output> {
            let mut cx = Context::from_waker(Waker::noop());
            fut.as_mut().poll(&mut cx)
        }

        let engine = InMemoryStateEngine::new();
        let base = engine.get_state_root().await;

        // Mutation A bumps the commitment generation.
        assert!(engine
            .evm_bindings_write()
            .await
            .bind([0xAA; 20], [0x11; 32])
            .unwrap());

        // Start a root read and hold the trie write lock, so the read runs its
        // whole fold and parks exactly at the publish step.
        let trie_guard = engine.state_trie.write().await;
        let mut pending = Box::pin(engine.get_state_root());
        assert!(
            poll_once(&mut pending).is_pending(),
            "the read must park on the trie write lock"
        );
        drop(trie_guard);

        // Mutation B lands while the fold for A is parked: A's digest is stale.
        assert!(engine
            .evm_bindings_write()
            .await
            .bind([0xBB; 20], [0x22; 32])
            .unwrap());

        let observed = pending.await;

        // Reference engine that saw exactly A then B.
        let reference = InMemoryStateEngine::new();
        assert!(reference
            .evm_bindings_write()
            .await
            .bind([0xAA; 20], [0x11; 32])
            .unwrap());
        assert!(reference
            .evm_bindings_write()
            .await
            .bind([0xBB; 20], [0x22; 32])
            .unwrap());
        let expected = reference.get_state_root().await;

        assert_ne!(observed, base, "the root must move with the mutations");
        assert_eq!(
            observed, expected,
            "a parked reader must not publish the digest it folded before mutation B"
        );
        assert_eq!(
            engine.get_state_root().await,
            expected,
            "the trie must hold the current digest after the race"
        );
    }
}
