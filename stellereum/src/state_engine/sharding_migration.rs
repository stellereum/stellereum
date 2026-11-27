//! Wave 14b: Dynamic shard split and merge state migration on [`InMemoryStateEngine`].
//!
//! Bridges the topology-level split/merge state machine ([`ShardTopology`],
//! [`TrieMigration`], [`MigrationManifest`]) with live [`InMemoryStateEngine`]
//! state (native accounts, deployed contracts, STS tokens, PQ registry/fallback
//! keys, D2 consensus penalties, and the Patricia state trie + consensus
//! commitment domains).

use super::types::{
    contract_abi_key, contract_key, contract_source_key, write_contract_trie_entries,
    write_token_trie_entries,
};
use super::{token_balance_key, token_supply_key, AccountState, InMemoryStateEngine};
use crate::cell::PatriciaTrie;
use crate::pq_registry::{PqKeyRecord, PqRegistry};
use crate::sharding::{
    address_prefix_bit, MergeRefusal, MergeTransition, MigrationError, ShardAccount, ShardId,
    ShardTopology, SplitRefusal, SplitTransition, TopologyError, TrieMigration, MASTERCHAIN_SHARD,
};
use crate::token::TokenActor;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Result of a dynamic shard split across [`InMemoryStateEngine`] state.
#[derive(Clone, Debug)]
pub struct ShardSplitResult {
    /// Topology-level transition record and balance/digest migration plan.
    pub transition: SplitTransition,
    /// Child state engine owning addresses whose split bit is `0`.
    pub child0: InMemoryStateEngine,
    /// Child state engine owning addresses whose split bit is `1`.
    pub child1: InMemoryStateEngine,
}

/// Result of a dynamic shard merge combining two sibling [`InMemoryStateEngine`]s.
#[derive(Clone, Debug)]
pub struct ShardMergeResult {
    /// Topology-level transition record and balance/digest migration plan.
    pub transition: MergeTransition,
    /// Merged state engine owning the combined parent prefix range.
    pub merged: InMemoryStateEngine,
}

/// Unified outcome for dynamic shard state transitions.
#[derive(Clone, Debug)]
pub enum ShardMigrationOutcome {
    Split(Box<ShardSplitResult>),
    Merge(Box<ShardMergeResult>),
}

/// Fail-closed error returned by [`InMemoryStateEngine::execute_shard_split`]
/// and [`InMemoryStateEngine::execute_shard_merge`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShardMigrationError {
    /// Masterchain shard (`MASTERCHAIN_SHARD`) never splits or merges.
    MasterchainForbidden,
    /// Engine `shard_id` did not match the requested shard id.
    ShardMismatch { expected: ShardId, actual: ShardId },
    /// State trie contains a key not classified by the migration manifest.
    UnclassifiedKey([u8; 32]),
    /// A non-migrated consensus domain is non-empty; migration fails closed.
    UnsupportedNonEmptyDomain(&'static str),
    /// Topology split preconditions refused the split.
    SplitRefused(SplitRefusal),
    /// Topology merge preconditions refused the merge.
    MergeRefused(MergeRefusal),
    /// Topology invariant verification failed.
    Topology(TopologyError),
    /// Trie-level migration or verification failed.
    Migration(MigrationError),
    /// An account appeared in both sibling shards or was duplicated.
    DuplicateAccount([u8; 32]),
    /// A contract appeared in both sibling shards.
    DuplicateContract([u8; 32]),
    /// A state/balance/supply/SPV conservation invariant failed.
    ConservationViolation(String),
}

impl std::fmt::Display for ShardMigrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MasterchainForbidden => {
                write!(
                    f,
                    "masterchain shard {MASTERCHAIN_SHARD} cannot split or merge"
                )
            }
            Self::ShardMismatch { expected, actual } => {
                write!(
                    f,
                    "shard id mismatch: expected {expected}, engine is on {actual}"
                )
            }
            Self::UnclassifiedKey(key) => {
                write!(
                    f,
                    "unclassified state trie key {}; refusing migration",
                    hex::encode(key)
                )
            }
            Self::UnsupportedNonEmptyDomain(domain) => {
                write!(
                    f,
                    "cannot migrate shard state: unsupported non-empty consensus domain '{domain}'"
                )
            }
            Self::SplitRefused(e) => write!(f, "shard split refused: {e}"),
            Self::MergeRefused(e) => write!(f, "shard merge refused: {e}"),
            Self::Topology(e) => write!(f, "shard topology invariant failed: {e}"),
            Self::Migration(e) => write!(f, "trie migration failed: {e}"),
            Self::DuplicateAccount(addr) => {
                write!(f, "duplicate account across shards: {}", hex::encode(addr))
            }
            Self::DuplicateContract(addr) => {
                write!(f, "duplicate contract across shards: {}", hex::encode(addr))
            }
            Self::ConservationViolation(msg) => {
                write!(f, "shard migration conservation violation: {msg}")
            }
        }
    }
}

impl std::error::Error for ShardMigrationError {}

impl From<SplitRefusal> for ShardMigrationError {
    fn from(e: SplitRefusal) -> Self {
        Self::SplitRefused(e)
    }
}

impl From<MergeRefusal> for ShardMigrationError {
    fn from(e: MergeRefusal) -> Self {
        Self::MergeRefused(e)
    }
}

impl From<TopologyError> for ShardMigrationError {
    fn from(e: TopologyError) -> Self {
        Self::Topology(e)
    }
}

impl From<MigrationError> for ShardMigrationError {
    fn from(e: MigrationError) -> Self {
        Self::Migration(e)
    }
}

type PqFallbackEntry = (crate::post_quantum::PqScheme, Vec<u8>, [u8; 16]);

async fn ensure_unsupported_domains_empty(
    engine: &InMemoryStateEngine,
) -> Result<(), ShardMigrationError> {
    {
        let s = engine.staking.read().await;
        if !s.validators.is_empty()
            || !s.delegations.is_empty()
            || !s.delegator_rewards.is_empty()
            || !s.unbonding.is_empty()
            || !s.withdrawable.is_empty()
            || s.total_burned != 0
            || s.rewards_pool != 0
            || s.rewards_minted != 0
            || !s.locked_governance.is_empty()
            || !s.pq_equivocation_dedup.is_empty()
            || !s.equivocation_dedup.is_empty()
            || !s.validator_pq_keys.is_empty()
            || s.min_validator_bond.is_some()
            || !s.vesting_schedules.is_empty()
            || !s.reward_accumulators.is_empty()
            || !s.delegator_reward_checkpoints.is_empty()
            || !s.jail.is_empty()
            || !s.commission_schedule.is_empty()
            || !s.redelegation_lock.is_empty()
            || !s.recent_full_exits.is_empty()
            || s.emission_carry_q64 != 0
        {
            return Err(ShardMigrationError::UnsupportedNonEmptyDomain("staking"));
        }
    }

    {
        let orderbooks = engine.orderbooks.read().await;
        if orderbooks.books.iter().any(|(pair_id, b)| {
            !b.bids.is_empty()
                || !b.asks.is_empty()
                || b.next_order_id != 1
                || b.version != 0
                || !matches!(
                    *pair_id,
                    crate::orderbook::PAIR_STELL_USDT
                        | crate::orderbook::PAIR_STELL_TON
                        | crate::orderbook::PAIR_STELL_GRAM
                )
        }) {
            return Err(ShardMigrationError::UnsupportedNonEmptyDomain("orderbooks"));
        }
    }

    if !engine.order_escrow.read().await.is_empty() {
        return Err(ShardMigrationError::UnsupportedNonEmptyDomain(
            "order_escrow",
        ));
    }

    {
        let pmm = engine.pmm.read().await;
        if *pmm != crate::pmm::PrimaryMarketMaker::new()
            || engine.pmm_usdt_token.read().await.is_some()
            || *engine.pmm_treasury.read().await != [0u8; 32]
        {
            return Err(ShardMigrationError::UnsupportedNonEmptyDomain("pmm"));
        }
    }

    {
        let oracle = engine.oracle.read().await;
        if !oracle.feeds.is_empty()
            || !oracle.publishers.is_empty()
            || !oracle.anchor_price_micro_usd.is_empty()
            || oracle.breaker_tripped
        {
            return Err(ShardMigrationError::UnsupportedNonEmptyDomain("oracle"));
        }
    }

    if !engine.session_keys.read().await.is_empty() {
        return Err(ShardMigrationError::UnsupportedNonEmptyDomain(
            "session_keys",
        ));
    }

    if !engine.zkml_models.read().await.is_empty() {
        return Err(ShardMigrationError::UnsupportedNonEmptyDomain(
            "zkml_models",
        ));
    }

    {
        let default_gov = crate::governance::Governance::new();
        let gov = engine.governance.read().await;
        if !gov.proposals.is_empty()
            || !gov.timelocks.is_empty()
            || !gov.gov_propose_nonces.is_empty()
            || gov.applied != default_gov.applied
            || gov.next_id != default_gov.next_id
            || gov.quorum_bps != default_gov.quorum_bps
        {
            return Err(ShardMigrationError::UnsupportedNonEmptyDomain("governance"));
        }
    }

    if *engine.bridge.read().await != crate::bridge::BridgeState::default() {
        return Err(ShardMigrationError::UnsupportedNonEmptyDomain("bridge"));
    }

    if !engine.evm_bindings.read().await.is_empty() {
        return Err(ShardMigrationError::UnsupportedNonEmptyDomain(
            "evm_bindings",
        ));
    }

    {
        let v3 = engine.cnvrf_v3.read().await;
        if !v3.records.is_empty()
            || !v3.epoch_rolling_mixes.is_empty()
            || v3.rolling_mix != [0u8; crate::cn_vrf::V3_LINK_LEN]
            || v3.rolling_mix_epoch != 0
        {
            return Err(ShardMigrationError::UnsupportedNonEmptyDomain("cnvrf_v3"));
        }
    }

    if !engine.cnvrf_abort.read().await.counters.is_empty() {
        return Err(ShardMigrationError::UnsupportedNonEmptyDomain(
            "cnvrf_abort",
        ));
    }

    if !engine.epoch_vdf_beacons.read().await.is_empty() {
        return Err(ShardMigrationError::UnsupportedNonEmptyDomain(
            "epoch_vdf_beacons",
        ));
    }

    if !engine.cnvrf_freeze_inputs.read().await.is_empty() {
        return Err(ShardMigrationError::UnsupportedNonEmptyDomain(
            "cnvrf_freeze_inputs",
        ));
    }

    if !engine.cross_shard_consumed.read().await.is_empty() {
        return Err(ShardMigrationError::UnsupportedNonEmptyDomain(
            "cross_shard_consumed",
        ));
    }
    if !engine.cross_shard_produced.read().await.is_empty() {
        return Err(ShardMigrationError::UnsupportedNonEmptyDomain(
            "cross_shard_produced",
        ));
    }
    if !engine.cross_shard_completed.read().await.is_empty() {
        return Err(ShardMigrationError::UnsupportedNonEmptyDomain(
            "cross_shard_completed",
        ));
    }
    if !engine.cross_shard_xpc.read().await.is_empty() {
        return Err(ShardMigrationError::UnsupportedNonEmptyDomain(
            "cross_shard_xpc",
        ));
    }
    if !engine.cross_shard_out.read().await.is_empty() {
        return Err(ShardMigrationError::UnsupportedNonEmptyDomain(
            "cross_shard_out",
        ));
    }

    {
        let hp = engine.hashpool.read().await;
        if !hp.is_empty() || hp.spent_len() > 0 {
            return Err(ShardMigrationError::UnsupportedNonEmptyDomain("hashpool"));
        }
    }

    if !engine.evm_settled.read().await.is_empty() {
        return Err(ShardMigrationError::UnsupportedNonEmptyDomain(
            "evm_settled",
        ));
    }

    Ok(())
}

fn build_pq_registry_from_map(
    map: &BTreeMap<[u8; 32], PqKeyRecord>,
) -> Result<PqRegistry, ShardMigrationError> {
    let bytes = bincode::serialize(map).map_err(|e| {
        ShardMigrationError::ConservationViolation(format!(
            "failed to serialize pq_registry partition: {e}"
        ))
    })?;
    let reg: PqRegistry = bincode::deserialize(&bytes).map_err(|e| {
        ShardMigrationError::ConservationViolation(format!(
            "failed to deserialize pq_registry partition: {e}"
        ))
    })?;
    if reg.records() != map {
        return Err(ShardMigrationError::ConservationViolation(
            "pq_registry partition roundtrip mismatch".into(),
        ));
    }
    Ok(reg)
}

fn read_pinned_pq_entry(engine: &InMemoryStateEngine, addr: &[u8; 32]) -> Option<PqFallbackEntry> {
    let has_tree = engine
        .pq_tree
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .is_some();
    if has_tree {
        engine.get_pinned_pubkey_with_salt(addr)
    } else {
        engine
            .pq_keys_fallback
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .peek(addr)
    }
}

fn verify_trie_keys_classified(
    trie: &PatriciaTrie,
    manifest: &crate::sharding::MigrationManifest,
) -> Result<(), ShardMigrationError> {
    let commitment_key = crate::commitment::commitment_key();
    let mut keys: Vec<[u8; 32]> = trie.compressed().entries.keys().copied().collect();
    keys.sort_unstable();
    for key in keys {
        if key == commitment_key {
            continue;
        }
        if manifest.owner_of(&key).is_none() {
            return Err(ShardMigrationError::UnclassifiedKey(key));
        }
    }
    Ok(())
}

fn sorted_shard_accounts(accounts: &HashMap<[u8; 32], AccountState>) -> Vec<ShardAccount> {
    let mut list: Vec<ShardAccount> = accounts
        .values()
        .map(|a| ShardAccount {
            address: a.address,
            balance: a.balance,
        })
        .collect();
    list.sort_by(|a, b| a.address.cmp(&b.address));
    list
}

fn sum_native_balances(
    accounts: &HashMap<[u8; 32], AccountState>,
) -> Result<u128, ShardMigrationError> {
    let mut total: u128 = 0;
    for acc in accounts.values() {
        total = total.checked_add(acc.balance as u128).ok_or_else(|| {
            ShardMigrationError::ConservationViolation("native balance u128 overflow".into())
        })?;
    }
    Ok(total)
}

fn sum_token_allowances(token: &TokenActor) -> Result<u128, ShardMigrationError> {
    let mut total: u128 = 0;
    for amt in token.allowances.values() {
        total = total.checked_add(*amt as u128).ok_or_else(|| {
            ShardMigrationError::ConservationViolation("token allowance u128 overflow".into())
        })?;
    }
    Ok(total)
}

fn verify_topology_descriptors_agree(
    next_topology: &ShardTopology,
    child_topo: &ShardTopology,
    child_label: &str,
) -> Result<(), ShardMigrationError> {
    if next_topology.manager.shards.len() != child_topo.manager.shards.len()
        || next_topology.manager.next_shard_id != child_topo.manager.next_shard_id
    {
        return Err(ShardMigrationError::ConservationViolation(format!(
            "{child_label} topology active shard set disagrees with parent topology"
        )));
    }
    for (sid, desc) in &next_topology.manager.shards {
        let Some(c_desc) = child_topo.manager.shards.get(sid) else {
            return Err(ShardMigrationError::ConservationViolation(format!(
                "{child_label} topology missing active shard {sid}"
            )));
        };
        if c_desc.shard_id != desc.shard_id
            || c_desc.workchain_id != desc.workchain_id
            || c_desc.prefix != desc.prefix
            || c_desc.prefix_len != desc.prefix_len
        {
            return Err(ShardMigrationError::ConservationViolation(format!(
                "{child_label} topology descriptor mismatch on shard {sid}"
            )));
        }
    }
    Ok(())
}

async fn verify_all_state_spv_proofs(
    engine: &InMemoryStateEngine,
    root: &crate::cell::CellHash,
    split_supply_filter: Option<(u8, u8)>,
    label: &str,
) -> Result<(), ShardMigrationError> {
    let accounts = engine.accounts.read().await.clone();
    let contracts = engine.contracts.read().await.clone();
    let tokens = engine.tokens.read().await.clone();
    let trie = engine.state_trie.read().await.clone();

    let mut addrs: Vec<[u8; 32]> = accounts.keys().copied().collect();
    addrs.sort_unstable();
    for addr in addrs {
        let acc = &accounts[&addr];
        let proof = trie.generate_merkle_proof(&addr).ok_or_else(|| {
            ShardMigrationError::ConservationViolation(format!(
                "missing SPV proof for account {} on {label}",
                hex::encode(addr)
            ))
        })?;
        if !PatriciaTrie::verify_merkle_proof(root, &addr, &acc.to_trie_bytes(), &proof) {
            return Err(ShardMigrationError::ConservationViolation(format!(
                "SPV proof failed for account {} on {label}",
                hex::encode(addr)
            )));
        }
    }

    for (addr, contract) in &contracts.contracts {
        let c_key = contract_key(addr);
        let c_proof = trie.generate_merkle_proof(&c_key).ok_or_else(|| {
            ShardMigrationError::ConservationViolation(format!(
                "missing SPV proof for contract {} code hash on {label}",
                hex::encode(addr)
            ))
        })?;
        if !PatriciaTrie::verify_merkle_proof(root, &c_key, &contract.code_hash, &c_proof) {
            return Err(ShardMigrationError::ConservationViolation(format!(
                "SPV proof failed for contract {} code hash on {label}",
                hex::encode(addr)
            )));
        }
        if let Some(abi) = &contract.abi {
            let a_key = contract_abi_key(addr);
            let a_proof = trie.generate_merkle_proof(&a_key).ok_or_else(|| {
                ShardMigrationError::ConservationViolation(format!(
                    "missing SPV proof for contract {} ABI on {label}",
                    hex::encode(addr)
                ))
            })?;
            if !PatriciaTrie::verify_merkle_proof(root, &a_key, abi.to_json().as_bytes(), &a_proof)
            {
                return Err(ShardMigrationError::ConservationViolation(format!(
                    "SPV proof failed for contract {} ABI on {label}",
                    hex::encode(addr)
                )));
            }
        }
        if let Some(sh) = &contract.source_hash {
            let s_key = contract_source_key(addr);
            let s_proof = trie.generate_merkle_proof(&s_key).ok_or_else(|| {
                ShardMigrationError::ConservationViolation(format!(
                    "missing SPV proof for contract {} source hash on {label}",
                    hex::encode(addr)
                ))
            })?;
            if !PatriciaTrie::verify_merkle_proof(root, &s_key, sh, &s_proof) {
                return Err(ShardMigrationError::ConservationViolation(format!(
                    "SPV proof failed for contract {} source hash on {label}",
                    hex::encode(addr)
                )));
            }
        }
        if !accounts.contains_key(addr) {
            if let Some(raw_code) = trie.get(addr) {
                let raw_proof = trie.generate_merkle_proof(addr).ok_or_else(|| {
                    ShardMigrationError::ConservationViolation(format!(
                        "missing SPV proof for contract {} raw code leaf on {label}",
                        hex::encode(addr)
                    ))
                })?;
                if !PatriciaTrie::verify_merkle_proof(root, addr, raw_code, &raw_proof) {
                    return Err(ShardMigrationError::ConservationViolation(format!(
                        "SPV proof failed for contract {} raw code leaf on {label}",
                        hex::encode(addr)
                    )));
                }
            }
        }
    }

    for (token_id, token) in &tokens.tokens {
        let mut holders: Vec<[u8; 32]> = token.balances.keys().copied().collect();
        holders.sort_unstable();
        for holder in holders {
            let bal = token.balances[&holder];
            if bal == 0 {
                continue;
            }
            let b_key = token_balance_key(token_id, &holder);
            let b_proof = trie.generate_merkle_proof(&b_key).ok_or_else(|| {
                ShardMigrationError::ConservationViolation(format!(
                    "missing SPV proof for token {} holder {} on {label}",
                    hex::encode(token_id),
                    hex::encode(holder)
                ))
            })?;
            if !PatriciaTrie::verify_merkle_proof(root, &b_key, &bal.to_be_bytes(), &b_proof) {
                return Err(ShardMigrationError::ConservationViolation(format!(
                    "SPV proof failed for token {} holder {} on {label}",
                    hex::encode(token_id),
                    hex::encode(holder)
                )));
            }
        }
        let check_supply = match split_supply_filter {
            None => true,
            Some((split_bit, expected_bit)) => {
                address_prefix_bit(&token.metadata.minter, split_bit) == expected_bit
            }
        };
        if check_supply {
            let s_key = token_supply_key(token_id);
            let s_proof = trie.generate_merkle_proof(&s_key).ok_or_else(|| {
                ShardMigrationError::ConservationViolation(format!(
                    "missing SPV proof for token {} supply on {label}",
                    hex::encode(token_id)
                ))
            })?;
            if !PatriciaTrie::verify_merkle_proof(
                root,
                &s_key,
                &token.metadata.total_supply.to_be_bytes(),
                &s_proof,
            ) {
                return Err(ShardMigrationError::ConservationViolation(format!(
                    "SPV proof failed for token {} supply on {label}",
                    hex::encode(token_id)
                )));
            }
        }
    }

    Ok(())
}

impl InMemoryStateEngine {
    /// Construct a fresh state engine scoped to `shard_id` with an explicit
    /// `chain_id` and pre-populated [`ShardTopology`].
    pub fn new_for_shard(chain_id: u64, shard_id: ShardId, topology: ShardTopology) -> Self {
        let mut engine = Self::new().with_chain_id(chain_id);
        engine.set_shard_id(shard_id);
        engine.shard_topology = Arc::new(RwLock::new(topology));
        engine
    }

    /// Synchronize [`ShardTopology`] account ownership for `self.shard_id()`
    /// from the live `self.accounts` map and record the shard's `tx_load`.
    pub async fn sync_topology_from_accounts(&self, tx_load: u64) {
        let shard_id = self.shard_id();
        let list = {
            let accounts = self.accounts.read().await;
            sorted_shard_accounts(&accounts)
        };
        let mut topology = self.shard_topology.write().await;
        if let Some(desc) = topology.manager.shards.get_mut(&shard_id) {
            desc.tx_load = tx_load;
            topology.ownership.insert(shard_id, list);
        }
    }

    /// Execute a fail-closed dynamic shard split of `source_shard` into two
    /// child [`InMemoryStateEngine`] instances (`child0`, `child1`).
    pub async fn execute_shard_split(
        &self,
        source_shard: ShardId,
    ) -> Result<ShardSplitResult, ShardMigrationError> {
        // 1. Verify source shard is a non-masterchain shard matching `self`,
        //    and fail closed if any non-migrated consensus domain is non-empty.
        if source_shard == MASTERCHAIN_SHARD {
            return Err(ShardMigrationError::MasterchainForbidden);
        }
        let actual_shard = self.shard_id();
        if actual_shard != source_shard {
            return Err(ShardMigrationError::ShardMismatch {
                expected: source_shard,
                actual: actual_shard,
            });
        }
        ensure_unsupported_domains_empty(self).await?;

        // 2. Build migration manifest and fail closed on any unclassified trie key.
        let manifest = self.shard_migration_manifest().await;
        let parent_trie = self.state_trie.read().await.clone();
        verify_trie_keys_classified(&parent_trie, &manifest)?;

        // 3. Snapshot live domain state without holding locks across awaits.
        let parent_accounts = self.accounts.read().await.clone();
        let parent_contracts = self.contracts.read().await.clone();
        let parent_tokens = self.tokens.read().await.clone();
        let parent_penalty = self.consensus_penalty.read().await.clone();
        let parent_pq_registry = self.pq_registry.read().await.clone();
        let mut next_topology = self.shard_topology.read().await.clone();

        // Sync live accounts into the cloned topology before precondition checks
        // while preserving recorded tx_load on `source_shard`.
        if next_topology.manager.shards.contains_key(&source_shard) {
            next_topology
                .ownership
                .insert(source_shard, sorted_shard_accounts(&parent_accounts));
        }

        // 4. Drive ShardTopology::check_and_split on the cloned topology first.
        next_topology.split_preconditions(source_shard)?;
        let transition = next_topology.check_and_split(source_shard).ok_or(
            ShardMigrationError::SplitRefused(SplitRefusal::UnknownShard),
        )?;
        next_topology.verify_invariants()?;

        let [desc0, desc1] = transition.children.clone();
        let split_bit = transition.plan.split_bit;
        if split_bit >= 64 {
            return Err(ShardMigrationError::Migration(MigrationError::BadSplitBit(
                split_bit,
            )));
        }

        // 5. Partition accounts, contracts, tokens, PQ registry, PQ fallback,
        //    consensus penalties, and supply counters/limits into child0 / child1.
        let child0 = Self::new_for_shard(self.chain_id, desc0.shard_id, next_topology.clone());
        let child1 = Self::new_for_shard(self.chain_id, desc1.shard_id, next_topology.clone());

        let xshard = self.cross_shard_enabled.load(Ordering::Acquire);
        child0.cross_shard_enabled.store(xshard, Ordering::Release);
        child1.cross_shard_enabled.store(xshard, Ordering::Release);

        let parallel = self.parallel_exec.load(Ordering::Acquire);
        child0.parallel_exec.store(parallel, Ordering::Release);
        child1.parallel_exec.store(parallel, Ordering::Release);

        let parent_limit = self.chain_mint_limit_nano();
        let lim0 = parent_limit / 2;
        let lim1 = parent_limit - lim0;
        child0.set_chain_mint_limit_nano(lim0);
        child1.set_chain_mint_limit_nano(lim1);

        let mut accounts0: HashMap<[u8; 32], AccountState> = HashMap::new();
        let mut accounts1: HashMap<[u8; 32], AccountState> = HashMap::new();
        let mut trie0 = PatriciaTrie::new();
        let mut trie1 = PatriciaTrie::new();

        for (addr, acc) in &parent_accounts {
            let leaf = acc.to_trie_bytes();
            if address_prefix_bit(addr, split_bit) == 0 {
                trie0.insert(addr, &leaf);
                accounts0.insert(*addr, acc.clone());
            } else {
                trie1.insert(addr, &leaf);
                accounts1.insert(*addr, acc.clone());
            }
        }

        let parent_minted = self.total_minted_nano();
        let parent_sum = sum_native_balances(&parent_accounts)?;
        let sum0 = sum_native_balances(&accounts0)?;
        let sum1 = sum_native_balances(&accounts1)?;
        let (minted0, minted1) = if parent_minted == 0 {
            (0u64, 0u64)
        } else if sum0 + sum1 == 0 {
            let m0 = parent_minted.div_ceil(2);
            (m0, parent_minted - m0)
        } else {
            let total_sum = sum0 + sum1;
            let mut m0 = ((parent_minted as u128 * sum0) / total_sum) as u64;
            let mut m1 = parent_minted - m0;
            if m0 == 0 && sum0 > 0 {
                m0 = 1;
                m1 = parent_minted - 1;
            } else if m1 == 0 && sum1 > 0 && m0 > 1 {
                m1 = 1;
                m0 = parent_minted - 1;
            }
            (m0, m1)
        };
        child0.total_minted_nano.store(minted0, Ordering::Release);
        child1.total_minted_nano.store(minted1, Ordering::Release);

        let mut penalty0: HashMap<[u8; 32], u64> = HashMap::new();
        let mut penalty1: HashMap<[u8; 32], u64> = HashMap::new();
        for (addr, val) in &parent_penalty {
            if address_prefix_bit(addr, split_bit) == 0 {
                penalty0.insert(*addr, *val);
            } else {
                penalty1.insert(*addr, *val);
            }
        }

        let mut pq_map0: BTreeMap<[u8; 32], PqKeyRecord> = BTreeMap::new();
        let mut pq_map1: BTreeMap<[u8; 32], PqKeyRecord> = BTreeMap::new();
        for (vid, rec) in parent_pq_registry.records() {
            if address_prefix_bit(vid, split_bit) == 0 {
                pq_map0.insert(*vid, rec.clone());
            } else {
                pq_map1.insert(*vid, rec.clone());
            }
        }
        let pq_reg0 = build_pq_registry_from_map(&pq_map0)?;
        let pq_reg1 = build_pq_registry_from_map(&pq_map1)?;

        let mut pq_fb0: Vec<([u8; 32], PqFallbackEntry)> = Vec::new();
        let mut pq_fb1: Vec<([u8; 32], PqFallbackEntry)> = Vec::new();
        {
            let mut sorted_addrs: Vec<[u8; 32]> = parent_accounts.keys().copied().collect();
            sorted_addrs.sort_unstable();
            for addr in sorted_addrs {
                if let Some(entry) = read_pinned_pq_entry(self, &addr) {
                    if address_prefix_bit(&addr, split_bit) == 0 {
                        pq_fb0.push((addr, entry));
                    } else {
                        pq_fb1.push((addr, entry));
                    }
                }
            }
        }

        let mut contracts0 = crate::contract::ContractRegistry {
            contracts: std::collections::BTreeMap::new(),
            next_nonce: parent_contracts.next_nonce,
            last_return_data: Vec::new(),
        };
        let mut contracts1 = crate::contract::ContractRegistry {
            contracts: std::collections::BTreeMap::new(),
            next_nonce: parent_contracts.next_nonce,
            last_return_data: Vec::new(),
        };
        for (addr, contract) in &parent_contracts.contracts {
            if address_prefix_bit(addr, split_bit) == 0 {
                contracts0.contracts.insert(*addr, contract.clone());
                if !accounts0.contains_key(addr) {
                    if let Some(raw_leaf) = parent_trie.get(addr) {
                        trie0.insert(addr, raw_leaf);
                    }
                }
            } else {
                contracts1.contracts.insert(*addr, contract.clone());
                if !accounts1.contains_key(addr) {
                    if let Some(raw_leaf) = parent_trie.get(addr) {
                        trie1.insert(addr, raw_leaf);
                    }
                }
            }
        }
        write_contract_trie_entries(&mut trie0, &contracts0);
        write_contract_trie_entries(&mut trie1, &contracts1);

        let mut tokens0 = crate::token::TokenRegistry {
            tokens: std::collections::BTreeMap::new(),
            next_nonce: parent_tokens.next_nonce,
        };
        let mut tokens1 = crate::token::TokenRegistry {
            tokens: std::collections::BTreeMap::new(),
            next_nonce: parent_tokens.next_nonce,
        };
        for (token_id, token) in &parent_tokens.tokens {
            let minter_in_0 = address_prefix_bit(&token.metadata.minter, split_bit) == 0;
            let mut balances0 = HashMap::new();
            let mut balances1 = HashMap::new();
            for (holder, bal) in &token.balances {
                if address_prefix_bit(holder, split_bit) == 0 {
                    balances0.insert(*holder, *bal);
                    if *bal > 0 {
                        trie0.insert(&token_balance_key(token_id, holder), &bal.to_be_bytes());
                    }
                } else {
                    balances1.insert(*holder, *bal);
                    if *bal > 0 {
                        trie1.insert(&token_balance_key(token_id, holder), &bal.to_be_bytes());
                    }
                }
            }

            let mut allowances0 = HashMap::new();
            let mut allowances1 = HashMap::new();
            for ((owner, spender), amt) in &token.allowances {
                if address_prefix_bit(owner, split_bit) == 0 {
                    allowances0.insert((*owner, *spender), *amt);
                } else {
                    allowances1.insert((*owner, *spender), *amt);
                }
            }

            // Preserve full token metadata (including `total_supply`) on every
            // child carrying the token so `burn()`, `sync_aux_trie()`, and
            // `restore_token_snapshot()` remain consistent. Only the minter's
            // shard holds `token_supply_key(token_id)` in the split trie.
            if minter_in_0 || !balances0.is_empty() || !allowances0.is_empty() {
                tokens0.tokens.insert(
                    *token_id,
                    TokenActor {
                        id: *token_id,
                        metadata: token.metadata.clone(),
                        balances: balances0,
                        allowances: allowances0,
                    },
                );
                if minter_in_0 {
                    trie0.insert(
                        &token_supply_key(token_id),
                        &token.metadata.total_supply.to_be_bytes(),
                    );
                }
            }

            if !minter_in_0 || !balances1.is_empty() || !allowances1.is_empty() {
                tokens1.tokens.insert(
                    *token_id,
                    TokenActor {
                        id: *token_id,
                        metadata: token.metadata.clone(),
                        balances: balances1,
                        allowances: allowances1,
                    },
                );
                if !minter_in_0 {
                    trie1.insert(
                        &token_supply_key(token_id),
                        &token.metadata.total_supply.to_be_bytes(),
                    );
                }
            }
        }

        // Verify trie-level split completeness before folding consensus commitment digests.
        TrieMigration::new(transition.plan.clone(), manifest).verify_split(
            &parent_trie,
            &trie0,
            &trie1,
        )?;

        // Install partitioned state into child0 and child1 and commit domains.
        *child0.consensus_penalty.write().await = penalty0.clone();
        *child0.pq_registry_write().await = pq_reg0.clone();
        {
            let mut fb = child0
                .pq_keys_fallback
                .write()
                .unwrap_or_else(|e| e.into_inner());
            for (addr, entry) in pq_fb0 {
                fb.insert(addr, entry);
            }
        }
        *child0.accounts.write().await = accounts0.clone();
        *child0.contracts_write().await = contracts0.clone();
        *child0.tokens_write().await = tokens0.clone();
        *child0.state_trie.write().await = trie0;
        child0.commit_consensus_domains().await;
        let root0 = child0.get_state_root().await;

        *child1.consensus_penalty.write().await = penalty1.clone();
        *child1.pq_registry_write().await = pq_reg1.clone();
        {
            let mut fb = child1
                .pq_keys_fallback
                .write()
                .unwrap_or_else(|e| e.into_inner());
            for (addr, entry) in pq_fb1 {
                fb.insert(addr, entry);
            }
        }
        *child1.accounts.write().await = accounts1.clone();
        *child1.contracts_write().await = contracts1.clone();
        *child1.tokens_write().await = tokens1.clone();
        *child1.state_trie.write().await = trie1;
        child1.commit_consensus_domains().await;
        let root1 = child1.get_state_root().await;

        // 6. Verify conservation invariants and SPV proofs before returning.
        if accounts0.len() + accounts1.len() != parent_accounts.len() {
            return Err(ShardMigrationError::ConservationViolation(format!(
                "account count mismatch: {} + {} != {}",
                accounts0.len(),
                accounts1.len(),
                parent_accounts.len()
            )));
        }

        if sum0.checked_add(sum1) != Some(parent_sum) {
            return Err(ShardMigrationError::ConservationViolation(format!(
                "native balance mismatch: {sum0} + {sum1} != {parent_sum}"
            )));
        }

        if penalty0.len() + penalty1.len() != parent_penalty.len() {
            return Err(ShardMigrationError::ConservationViolation(format!(
                "consensus penalty count mismatch: {} + {} != {}",
                penalty0.len(),
                penalty1.len(),
                parent_penalty.len()
            )));
        }

        if pq_reg0.len() + pq_reg1.len() != parent_pq_registry.len() {
            return Err(ShardMigrationError::ConservationViolation(format!(
                "pq_registry count mismatch: {} + {} != {}",
                pq_reg0.len(),
                pq_reg1.len(),
                parent_pq_registry.len()
            )));
        }

        if child0.chain_mint_limit_nano() + child1.chain_mint_limit_nano() != parent_limit {
            return Err(ShardMigrationError::ConservationViolation(format!(
                "chain_mint_limit_nano mismatch: {} + {} != {}",
                child0.chain_mint_limit_nano(),
                child1.chain_mint_limit_nano(),
                parent_limit
            )));
        }

        if contracts0.contracts.len() + contracts1.contracts.len()
            != parent_contracts.contracts.len()
        {
            return Err(ShardMigrationError::ConservationViolation(format!(
                "contract count mismatch: {} + {} != {}",
                contracts0.contracts.len(),
                contracts1.contracts.len(),
                parent_contracts.contracts.len()
            )));
        }

        for (token_id, p_tok) in &parent_tokens.tokens {
            let p_bal: u128 = p_tok.balances.values().map(|v| *v as u128).sum();
            let b0: u128 = tokens0
                .tokens
                .get(token_id)
                .map(|t| t.balances.values().map(|v| *v as u128).sum())
                .unwrap_or(0);
            let b1: u128 = tokens1
                .tokens
                .get(token_id)
                .map(|t| t.balances.values().map(|v| *v as u128).sum())
                .unwrap_or(0);
            if b0.checked_add(b1) != Some(p_bal) {
                return Err(ShardMigrationError::ConservationViolation(format!(
                    "token {} balance mismatch: {b0} + {b1} != {p_bal}",
                    hex::encode(token_id)
                )));
            }

            if let Some(t0) = tokens0.tokens.get(token_id) {
                if t0.metadata != p_tok.metadata {
                    return Err(ShardMigrationError::ConservationViolation(format!(
                        "token {} metadata mismatch on child0",
                        hex::encode(token_id)
                    )));
                }
            }
            if let Some(t1) = tokens1.tokens.get(token_id) {
                if t1.metadata != p_tok.metadata {
                    return Err(ShardMigrationError::ConservationViolation(format!(
                        "token {} metadata mismatch on child1",
                        hex::encode(token_id)
                    )));
                }
            }

            let p_allow_sum = sum_token_allowances(p_tok)?;
            let a0_sum = tokens0
                .tokens
                .get(token_id)
                .map(sum_token_allowances)
                .transpose()?
                .unwrap_or(0);
            let a1_sum = tokens1
                .tokens
                .get(token_id)
                .map(sum_token_allowances)
                .transpose()?
                .unwrap_or(0);
            let a0_len = tokens0
                .tokens
                .get(token_id)
                .map(|t| t.allowances.len())
                .unwrap_or(0);
            let a1_len = tokens1
                .tokens
                .get(token_id)
                .map(|t| t.allowances.len())
                .unwrap_or(0);
            if a0_len + a1_len != p_tok.allowances.len()
                || a0_sum.checked_add(a1_sum) != Some(p_allow_sum)
            {
                return Err(ShardMigrationError::ConservationViolation(format!(
                    "token {} allowance conservation violated across split",
                    hex::encode(token_id)
                )));
            }
        }

        child0.shard_topology.read().await.verify_invariants()?;
        child1.shard_topology.read().await.verify_invariants()?;

        verify_all_state_spv_proofs(&child0, &root0, Some((split_bit, 0)), "child0").await?;
        verify_all_state_spv_proofs(&child1, &root1, Some((split_bit, 1)), "child1").await?;

        // Commit updated topology on `self` only after all invariants pass.
        *self.shard_topology.write().await = next_topology;

        Ok(ShardSplitResult {
            transition,
            child0,
            child1,
        })
    }

    /// Execute the inverse of [`Self::execute_shard_split`]: merge two sibling
    /// shard engines (`child0`, `child1`) into one parent [`InMemoryStateEngine`].
    pub async fn execute_shard_merge(
        &self,
        child0: &InMemoryStateEngine,
        id0: ShardId,
        child1: &InMemoryStateEngine,
        id1: ShardId,
    ) -> Result<ShardMergeResult, ShardMigrationError> {
        if id0 == MASTERCHAIN_SHARD || id1 == MASTERCHAIN_SHARD {
            return Err(ShardMigrationError::MasterchainForbidden);
        }
        if child0.shard_id() != id0 {
            return Err(ShardMigrationError::ShardMismatch {
                expected: id0,
                actual: child0.shard_id(),
            });
        }
        if child1.shard_id() != id1 {
            return Err(ShardMigrationError::ShardMismatch {
                expected: id1,
                actual: child1.shard_id(),
            });
        }
        if child0.chain_id != child1.chain_id {
            return Err(ShardMigrationError::ConservationViolation(format!(
                "chain_id mismatch between sibling shards: {} != {}",
                child0.chain_id, child1.chain_id
            )));
        }

        ensure_unsupported_domains_empty(child0).await?;
        ensure_unsupported_domains_empty(child1).await?;

        // Fail closed if either child holds unclassified state trie keys.
        let manifest0 = child0.shard_migration_manifest().await;
        let trie0 = child0.state_trie.read().await.clone();
        verify_trie_keys_classified(&trie0, &manifest0)?;

        let manifest1 = child1.shard_migration_manifest().await;
        let trie1 = child1.state_trie.read().await.clone();
        verify_trie_keys_classified(&trie1, &manifest1)?;

        // Snapshot child states sequentially to avoid lock-order issues even if `self` aliases a child.
        let accounts0 = child0.accounts.read().await.clone();
        let accounts1 = child1.accounts.read().await.clone();
        let contracts0 = child0.contracts.read().await.clone();
        let contracts1 = child1.contracts.read().await.clone();
        let tokens0 = child0.tokens.read().await.clone();
        let tokens1 = child1.tokens.read().await.clone();
        let penalty0 = child0.consensus_penalty.read().await.clone();
        let penalty1 = child1.consensus_penalty.read().await.clone();
        let pq_reg0 = child0.pq_registry.read().await.clone();
        let pq_reg1 = child1.pq_registry.read().await.clone();

        let topo0 = child0.shard_topology.read().await.clone();
        let topo1 = child1.shard_topology.read().await.clone();
        let mut next_topology = self.shard_topology.read().await.clone();

        if !next_topology.manager.shards.contains_key(&id0) {
            return Err(ShardMigrationError::MergeRefused(
                MergeRefusal::UnknownShard(id0),
            ));
        }
        if !next_topology.manager.shards.contains_key(&id1) {
            return Err(ShardMigrationError::MergeRefused(
                MergeRefusal::UnknownShard(id1),
            ));
        }

        verify_topology_descriptors_agree(&next_topology, &topo0, "child0")?;
        verify_topology_descriptors_agree(&next_topology, &topo1, "child1")?;

        // Sync live ownership and propagate child loads unconditionally.
        next_topology
            .ownership
            .insert(id0, sorted_shard_accounts(&accounts0));
        if !std::ptr::eq(self, child0) {
            if let (Some(self_d), Some(c0_d)) = (
                next_topology.manager.shards.get_mut(&id0),
                topo0.manager.shards.get(&id0),
            ) {
                self_d.tx_load = c0_d.tx_load;
            }
        }
        next_topology
            .ownership
            .insert(id1, sorted_shard_accounts(&accounts1));
        if !std::ptr::eq(self, child1) {
            if let (Some(self_d), Some(c1_d)) = (
                next_topology.manager.shards.get_mut(&id1),
                topo1.manager.shards.get(&id1),
            ) {
                self_d.tx_load = c1_d.tx_load;
            }
        }

        next_topology.merge_preconditions(id0, id1)?;
        let transition =
            next_topology
                .check_and_merge(id0, id1)
                .ok_or(ShardMigrationError::MergeRefused(
                    MergeRefusal::UnknownShard(id0),
                ))?;
        next_topology.verify_invariants()?;

        // Combine accounts (asserting zero address overlap).
        let mut merged_accounts: HashMap<[u8; 32], AccountState> =
            HashMap::with_capacity(accounts0.len() + accounts1.len());
        let mut merged_trie = PatriciaTrie::new();

        for (addr, acc) in &accounts0 {
            merged_trie.insert(addr, &acc.to_trie_bytes());
            merged_accounts.insert(*addr, acc.clone());
        }
        for (addr, acc) in &accounts1 {
            if merged_accounts.contains_key(addr) {
                return Err(ShardMigrationError::DuplicateAccount(*addr));
            }
            merged_trie.insert(addr, &acc.to_trie_bytes());
            merged_accounts.insert(*addr, acc.clone());
        }

        // Combine consensus penalties (asserting zero overlap).
        let mut merged_penalty = penalty0.clone();
        for (addr, val) in &penalty1 {
            if merged_penalty.contains_key(addr) {
                return Err(ShardMigrationError::DuplicateAccount(*addr));
            }
            merged_penalty.insert(*addr, *val);
        }

        // Combine PQ registry records (asserting zero overlap).
        let mut merged_pq_map = pq_reg0.records().clone();
        for (vid, rec) in pq_reg1.records() {
            if merged_pq_map.contains_key(vid) {
                return Err(ShardMigrationError::DuplicateAccount(*vid));
            }
            merged_pq_map.insert(*vid, rec.clone());
        }
        let merged_pq_registry = build_pq_registry_from_map(&merged_pq_map)?;

        // Combine PQ fallback keys (asserting zero overlap).
        let mut merged_pq_fb: Vec<([u8; 32], PqFallbackEntry)> = Vec::new();
        {
            let mut addrs0: Vec<[u8; 32]> = accounts0.keys().copied().collect();
            addrs0.sort_unstable();
            for addr in addrs0 {
                let e0 = read_pinned_pq_entry(child0, &addr);
                let e1 = read_pinned_pq_entry(child1, &addr);
                match (e0, e1) {
                    (Some(_), Some(_)) => return Err(ShardMigrationError::DuplicateAccount(addr)),
                    (Some(entry), None) => merged_pq_fb.push((addr, entry)),
                    (None, Some(entry)) => merged_pq_fb.push((addr, entry)),
                    (None, None) => {}
                }
            }
            let mut addrs1: Vec<[u8; 32]> = accounts1.keys().copied().collect();
            addrs1.sort_unstable();
            for addr in addrs1 {
                let e0 = read_pinned_pq_entry(child0, &addr);
                let e1 = read_pinned_pq_entry(child1, &addr);
                match (e0, e1) {
                    (Some(_), Some(_)) => return Err(ShardMigrationError::DuplicateAccount(addr)),
                    (None, Some(entry)) => merged_pq_fb.push((addr, entry)),
                    (Some(entry), None) => merged_pq_fb.push((addr, entry)),
                    (None, None) => {}
                }
            }
        }

        // Combine contracts (asserting zero address overlap).
        let mut merged_contracts = crate::contract::ContractRegistry {
            contracts: contracts0.contracts.clone(),
            next_nonce: contracts0.next_nonce.max(contracts1.next_nonce),
            last_return_data: Vec::new(),
        };
        for addr in contracts0.contracts.keys() {
            if !merged_accounts.contains_key(addr) {
                if let Some(raw_leaf) = trie0.get(addr) {
                    merged_trie.insert(addr, raw_leaf);
                }
            }
        }
        for (addr, contract) in &contracts1.contracts {
            if merged_contracts.contracts.contains_key(addr) {
                return Err(ShardMigrationError::DuplicateContract(*addr));
            }
            merged_contracts.contracts.insert(*addr, contract.clone());
            if !merged_accounts.contains_key(addr) {
                if let Some(raw_leaf) = trie1.get(addr) {
                    merged_trie.insert(addr, raw_leaf);
                }
            }
        }
        write_contract_trie_entries(&mut merged_trie, &merged_contracts);

        // Combine tokens (asserting metadata equality and zero holder/allowance overlap).
        let mut merged_tokens = crate::token::TokenRegistry {
            tokens: tokens0.tokens.clone(),
            next_nonce: tokens0.next_nonce.max(tokens1.next_nonce),
        };
        for (token_id, t1) in &tokens1.tokens {
            if let Some(existing) = merged_tokens.tokens.get_mut(token_id) {
                if existing.metadata != t1.metadata {
                    return Err(ShardMigrationError::ConservationViolation(format!(
                        "token {} metadata mismatch between sibling shards",
                        hex::encode(token_id)
                    )));
                }
                for (holder, bal) in &t1.balances {
                    if existing.balances.contains_key(holder) {
                        return Err(ShardMigrationError::DuplicateAccount(*holder));
                    }
                    existing.balances.insert(*holder, *bal);
                }
                for (pair, amt) in &t1.allowances {
                    if existing.allowances.contains_key(pair) {
                        return Err(ShardMigrationError::ConservationViolation(format!(
                            "duplicate allowance for token {}",
                            hex::encode(token_id)
                        )));
                    }
                    existing.allowances.insert(*pair, *amt);
                }
            } else {
                merged_tokens.tokens.insert(*token_id, t1.clone());
            }
        }
        write_token_trie_entries(&mut merged_trie, &merged_tokens);

        let merged = Self::new_for_shard(
            child0.chain_id,
            transition.parent.shard_id,
            next_topology.clone(),
        );
        let xshard = child0.cross_shard_enabled.load(Ordering::Acquire)
            || child1.cross_shard_enabled.load(Ordering::Acquire);
        merged.cross_shard_enabled.store(xshard, Ordering::Release);
        let parallel = child0.parallel_exec.load(Ordering::Acquire)
            || child1.parallel_exec.load(Ordering::Acquire);
        merged.parallel_exec.store(parallel, Ordering::Release);

        let merged_minted = child0
            .total_minted_nano()
            .checked_add(child1.total_minted_nano())
            .ok_or_else(|| {
                ShardMigrationError::ConservationViolation(
                    "total_minted_nano u64 overflow on merge".into(),
                )
            })?;
        merged
            .total_minted_nano
            .store(merged_minted, Ordering::Release);

        let merged_limit = child0
            .chain_mint_limit_nano()
            .checked_add(child1.chain_mint_limit_nano())
            .ok_or_else(|| {
                ShardMigrationError::ConservationViolation(
                    "chain_mint_limit_nano u64 overflow on merge".into(),
                )
            })?
            .min(crate::tokenomics::TOTAL_SUPPLY_CAP);
        merged.set_chain_mint_limit_nano(merged_limit);

        *merged.consensus_penalty.write().await = merged_penalty.clone();
        *merged.pq_registry_write().await = merged_pq_registry.clone();
        {
            let mut fb = merged
                .pq_keys_fallback
                .write()
                .unwrap_or_else(|e| e.into_inner());
            for (addr, entry) in merged_pq_fb {
                fb.insert(addr, entry);
            }
        }
        *merged.accounts.write().await = merged_accounts.clone();
        *merged.contracts_write().await = merged_contracts.clone();
        *merged.tokens_write().await = merged_tokens.clone();

        // Verify trie-level merge completeness before inserting commitment digest.
        let merged_manifest = merged.shard_migration_manifest().await;
        TrieMigration::new(transition.plan.clone(), merged_manifest).verify_merge(
            &merged_trie,
            &trie0,
            &trie1,
        )?;

        *merged.state_trie.write().await = merged_trie;
        merged.commit_consensus_domains().await;
        let merged_root = merged.get_state_root().await;

        // Conservation invariants.
        if merged_accounts.len() != accounts0.len() + accounts1.len() {
            return Err(ShardMigrationError::ConservationViolation(format!(
                "merged account count mismatch: {} != {} + {}",
                merged_accounts.len(),
                accounts0.len(),
                accounts1.len()
            )));
        }

        let sum0 = sum_native_balances(&accounts0)?;
        let sum1 = sum_native_balances(&accounts1)?;
        let merged_sum = sum_native_balances(&merged_accounts)?;
        if sum0.checked_add(sum1) != Some(merged_sum) {
            return Err(ShardMigrationError::ConservationViolation(format!(
                "merged native balance mismatch: {merged_sum} != {sum0} + {sum1}"
            )));
        }

        if merged_penalty.len() != penalty0.len() + penalty1.len() {
            return Err(ShardMigrationError::ConservationViolation(format!(
                "merged penalty count mismatch: {} != {} + {}",
                merged_penalty.len(),
                penalty0.len(),
                penalty1.len()
            )));
        }

        if merged_pq_registry.len() != pq_reg0.len() + pq_reg1.len() {
            return Err(ShardMigrationError::ConservationViolation(format!(
                "merged pq_registry count mismatch: {} != {} + {}",
                merged_pq_registry.len(),
                pq_reg0.len(),
                pq_reg1.len()
            )));
        }

        if merged_contracts.contracts.len()
            != contracts0.contracts.len() + contracts1.contracts.len()
        {
            return Err(ShardMigrationError::ConservationViolation(format!(
                "merged contract count mismatch: {} != {} + {}",
                merged_contracts.contracts.len(),
                contracts0.contracts.len(),
                contracts1.contracts.len()
            )));
        }

        for (token_id, m_tok) in &merged_tokens.tokens {
            let m_bal: u128 = m_tok.balances.values().map(|v| *v as u128).sum();
            let b0: u128 = tokens0
                .tokens
                .get(token_id)
                .map(|t| t.balances.values().map(|v| *v as u128).sum())
                .unwrap_or(0);
            let b1: u128 = tokens1
                .tokens
                .get(token_id)
                .map(|t| t.balances.values().map(|v| *v as u128).sum())
                .unwrap_or(0);
            if m_bal != b0 + b1 {
                return Err(ShardMigrationError::ConservationViolation(format!(
                    "merged token {} balance mismatch: {m_bal} != {b0} + {b1}",
                    hex::encode(token_id)
                )));
            }
            if let Some(t0) = tokens0.tokens.get(token_id) {
                if m_tok.metadata != t0.metadata {
                    return Err(ShardMigrationError::ConservationViolation(format!(
                        "merged token {} metadata mismatch with child0",
                        hex::encode(token_id)
                    )));
                }
            }
            if let Some(t1) = tokens1.tokens.get(token_id) {
                if m_tok.metadata != t1.metadata {
                    return Err(ShardMigrationError::ConservationViolation(format!(
                        "merged token {} metadata mismatch with child1",
                        hex::encode(token_id)
                    )));
                }
            }
            let m_allow_sum = sum_token_allowances(m_tok)?;
            let a0_sum = tokens0
                .tokens
                .get(token_id)
                .map(sum_token_allowances)
                .transpose()?
                .unwrap_or(0);
            let a1_sum = tokens1
                .tokens
                .get(token_id)
                .map(sum_token_allowances)
                .transpose()?
                .unwrap_or(0);
            let a0_len = tokens0
                .tokens
                .get(token_id)
                .map(|t| t.allowances.len())
                .unwrap_or(0);
            let a1_len = tokens1
                .tokens
                .get(token_id)
                .map(|t| t.allowances.len())
                .unwrap_or(0);
            if m_tok.allowances.len() != a0_len + a1_len
                || Some(m_allow_sum) != a0_sum.checked_add(a1_sum)
            {
                return Err(ShardMigrationError::ConservationViolation(format!(
                    "merged token {} allowance conservation violated",
                    hex::encode(token_id)
                )));
            }
        }

        merged.shard_topology.read().await.verify_invariants()?;
        verify_all_state_spv_proofs(&merged, &merged_root, None, "merged").await?;

        // Commit updated topology on `self` only after all invariants pass.
        *self.shard_topology.write().await = next_topology;

        Ok(ShardMergeResult { transition, merged })
    }
}
