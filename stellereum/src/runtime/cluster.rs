use super::apply::sweep_gov_finalize;
use super::lanes::block_reward_for;
use super::{BlockHash, ValidatorRuntime};
use crate::consensus::{FalconKeypair, Height, ValidatorSet, Vote};
use crate::sharding::{
    Block, CrossShardKey, CrossShardMessage, ShardId, ShardRegistry, Transaction,
};
use crate::state_engine::InMemoryStateEngine;
use ed25519_dalek::SigningKey;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// In-process multi-validator cluster used for tests and the local simulator.
pub struct Cluster {
    pub nodes: Vec<ValidatorRuntime>,
}

impl Cluster {
    /// Build a cluster from (key, own state) pairs. Each validator must get its
    /// OWN state engine (nodes do not share mutable state in reality).
    pub fn new(nodes: Vec<(SigningKey, Arc<InMemoryStateEngine>)>) -> Self {
        let validators = ValidatorSet::from_list(
            nodes
                .iter()
                .map(|(k, _)| (k.verifying_key().to_bytes(), 1))
                .collect(),
        );
        // FULL-PQ: every runtime carries a deterministic Falcon-512 keypair
        // (index-seeded, mirrors `consensus::tests::vset_with_falcon` via
        // `ValidatorRuntime::with_falcon_key` which registers the pubkey
        // globally). Without it `make_prevote`/`make_precommit` mint Ed-only
        // votes that `Vote::verify` refuses ("bad vote signature").
        let runtimes = nodes
            .into_iter()
            .enumerate()
            .map(|(i, (k, st))| {
                let mut seed = [0u8; 32];
                seed[0] = i as u8;
                seed[31] = (i as u8).wrapping_mul(79);
                let fk = FalconKeypair::generate_from_seed_bytes(&seed);
                ValidatorRuntime::new(k, validators.clone(), st, 1).with_falcon_key(fk)
            })
            .collect();
        Self { nodes: runtimes }
    }

    /// Build a cluster whose runtimes all produce/validate blocks for one shard
    /// of a multi-shard process. With the default (`single`) registry this is
    /// indistinguishable from [`Cluster::new`] except for the block `shard_id`.
    pub fn new_sharded(
        nodes: Vec<(SigningKey, Arc<InMemoryStateEngine>)>,
        shard_id: ShardId,
        registry: ShardRegistry,
    ) -> Self {
        let validators = ValidatorSet::from_list(
            nodes
                .iter()
                .map(|(k, _)| (k.verifying_key().to_bytes(), 1))
                .collect(),
        );
        let runtimes = nodes
            .into_iter()
            .enumerate()
            .map(|(i, (k, st))| {
                // FULL-PQ: deterministic per-index Falcon key (see `Cluster::new`).
                let mut seed = [0u8; 32];
                seed[0] = i as u8;
                seed[31] = (i as u8).wrapping_mul(79);
                let fk = FalconKeypair::generate_from_seed_bytes(&seed);
                ValidatorRuntime::new(k, validators.clone(), st, 1)
                    .with_falcon_key(fk)
                    .with_shard(shard_id, registry.clone())
            })
            .collect();
        Self { nodes: runtimes }
    }

    /// Like [`Cluster::new_sharded`] but wires every runtime to the shared
    /// node-local cross-shard transport, so this shard can publish outbound
    /// messages and consume inbound ones.
    pub fn new_sharded_with_transport(
        nodes: Vec<(SigningKey, Arc<InMemoryStateEngine>)>,
        shard_id: ShardId,
        registry: ShardRegistry,
        transport: Arc<crate::network::CrossShardTransport>,
    ) -> Self {
        let mut c = Self::new_sharded(nodes, shard_id, registry);
        // C1 anchor: one registry per CLUSTER (not per process): every shard
        // in this process shares it (like production), but independent test
        // clusters never collide (a process-global would mix their geneses).
        let hdrs: Arc<std::sync::RwLock<crate::sharding::FinalizedHeaderRegistry>> = Arc::new(
            std::sync::RwLock::new(crate::sharding::FinalizedHeaderRegistry::default()),
        );
        for n in &mut c.nodes {
            n.cross_shard = Some(transport.clone());
            n.finalized_headers = Some(hdrs.clone());
            n.state.with_finalized_headers(hdrs.clone());
        }
        c
    }

    pub fn height(&self) -> Height {
        self.nodes.first().map(|n| n.height()).unwrap_or(0)
    }

    /// Seed every node's mempool with the same transaction.
    pub async fn broadcast_tx(&mut self, tx: Transaction) {
        for n in &mut self.nodes {
            n.add_tx(tx.clone()).await;
        }
    }

    /// Run one full consensus round at the current height and return the block hash.
    pub async fn run_height(&mut self, timestamp: u64) -> BlockHash {
        // 1. proposer builds and signs a block
        let proposer_idx = self
            .nodes
            .iter()
            .position(|n| n.is_proposer())
            .expect("no proposer for this height");
        let block = self.nodes[proposer_idx]
            .propose(timestamp)
            .await
            .expect("proposer failed to propose");
        let bh = block.compute_hash();
        let proposer_id = self.nodes[proposer_idx].id;

        // 2. distribute the proposal
        for (i, n) in self.nodes.iter_mut().enumerate() {
            if i != proposer_idx {
                let r = n.hc.round;
                n.on_proposal(proposer_id, block.clone(), r)
                    .await
                    .expect("proposal rejected");
            }
        }

        // 3. collect and distribute prevotes
        let prevotes: Vec<Vote> = self.nodes.iter().filter_map(|n| n.make_prevote()).collect();
        for v in &prevotes {
            for n in self.nodes.iter_mut() {
                let _ = n.on_prevote(v.clone());
            }
        }

        // 4. collect and distribute precommits (locking happens here)
        let precommits: Vec<Vote> = self
            .nodes
            .iter_mut()
            .filter_map(|n| n.make_precommit())
            .collect();
        for v in &precommits {
            for n in self.nodes.iter_mut() {
                let _ = n.on_precommit(v.clone());
            }
        }

        // 5. finalize + apply + advance
        for n in self.nodes.iter_mut() {
            let _ = n.try_finalize().await;
        }
        bh
    }
}

/// An in-process multi-shard harness: one [`Cluster`] per shard, all sharing a
/// single node-local [`crate::network::CrossShardTransport`].
///
/// This is the M2 analogue of [`Cluster`]: it proves a source shard and a
/// destination shard, running as two consensus instances in one process, can
/// move value atomically through committed cross-shard messages. It is also the
/// shape the production loop uses (`STELL_SHARDS=0,1` over one infnode `Node`).
pub struct ShardedCluster {
    pub shards: std::collections::BTreeMap<ShardId, Cluster>,
    pub transport: Arc<crate::network::CrossShardTransport>,
    pub registry: ShardRegistry,
}

impl ShardedCluster {
    #[allow(clippy::type_complexity)]
    // GATE: test-cluster constructor shape is fixed; alias would churn test harness without benefit.
    pub fn new(
        registry: ShardRegistry,
        shards: Vec<(ShardId, Vec<(SigningKey, Arc<InMemoryStateEngine>)>)>,
        transport: Arc<crate::network::CrossShardTransport>,
    ) -> Self {
        let mut map = std::collections::BTreeMap::new();
        for (shard_id, nodes) in shards {
            map.insert(
                shard_id,
                Cluster::new_sharded_with_transport(
                    nodes,
                    shard_id,
                    registry.clone(),
                    transport.clone(),
                ),
            );
        }
        // C1 anchor: ONE registry for the whole multi-shard process (both
        // shards read what either finalized). Per-Cluster registries from the
        // constructor above are replaced by the shared one.
        let hdrs: Arc<std::sync::RwLock<crate::sharding::FinalizedHeaderRegistry>> = Arc::new(
            std::sync::RwLock::new(crate::sharding::FinalizedHeaderRegistry::default()),
        );
        for c in map.values_mut() {
            for n in &mut c.nodes {
                n.finalized_headers = Some(hdrs.clone());
                n.state.with_finalized_headers(hdrs.clone());
            }
        }
        Self {
            shards: map,
            transport,
            registry,
        }
    }

    pub fn shard(&self, shard_id: ShardId) -> &Cluster {
        self.shards.get(&shard_id).expect("unknown shard")
    }

    pub fn shard_mut(&mut self, shard_id: ShardId) -> &mut Cluster {
        self.shards.get_mut(&shard_id).expect("unknown shard")
    }

    /// Set the §9 cross-shard two-phase-commit activation switch on every
    /// node of every shard.
    ///
    /// `XpcActivation::FromHeight(h)` makes every transfer PRODUCED at
    /// height `h` or later run the 2PC (prepare / vote / commit) instead of
    /// the legacy outbox/inbox/ack/bounce flow. Transfers produced before
    /// `h` keep running the legacy flow to completion, so the two protocols
    /// never interleave on one transfer and the already-deployed chain state
    /// keeps working.
    pub fn with_xpc_activation(
        &mut self,
        activation: crate::xshard2pc::XpcActivation,
    ) -> &mut Self {
        for c in self.shards.values_mut() {
            for n in &mut c.nodes {
                n.xpc_activation = activation;
            }
        }
        self
    }

    /// Seed every shard's mempool; the per-shard filter keeps the transaction
    /// only on its source shard.
    pub async fn broadcast_tx(&mut self, tx: Transaction) {
        for c in self.shards.values_mut() {
            c.broadcast_tx(tx.clone()).await;
        }
    }

    /// Run one consensus height for a single shard.
    pub async fn run_height(&mut self, shard_id: ShardId, timestamp: u64) -> BlockHash {
        // C1 genesis anchoring for sim clusters: note the zero-hash genesis
        // parent for EVERY shard (not just the running one) from each
        // engine's current root. Test engines are funded before first use,
        // so these roots are the exact pre-roots height-1 messages reference.
        // Idempotent (real finals overwrite nothing: different keys).
        for (sid, cluster) in self.shards.iter() {
            if let Some(n) = cluster.nodes.first() {
                if n.finalized.is_empty() {
                    if let Some(reg) = n.finalized_headers.as_ref() {
                        let root = n.state.get_state_root().await;
                        if let Ok(mut r) = reg.write() {
                            r.note_finalized(*sid, [0u8; 32], root);
                        }
                    }
                }
            }
        }
        self.shard_mut(shard_id).run_height(timestamp).await
    }
}

/// State manager with checkpointing, to support deterministic reorgs.
///
/// A checkpoint is a full state snapshot taken at the last finalized height.
/// On a reorg we restore that checkpoint and re-apply the new canonical blocks,
/// which is correct and simple (reorgs only ever touch non-finalized blocks).
///
/// REORG PARITY: `apply_block` delegates to the SAME core the live consensus
/// path uses (`InMemoryStateEngine::apply_block_transition`), fed with the SAME
/// inputs (the block itself, plus a reward resolved by `block_reward_for`), so
/// a re-applied block produces byte-identical state - state root, receipts and
/// applied counters - to the node that finalized it. It used to loop
/// `apply_transaction` over the transactions instead, which charged a different
/// fee (gas actually consumed rather than the declared limit) and skipped the
/// proposer fee credit, the block reward, unbonding maturity and the downtime
/// slash entirely: a reorg then silently forked a second chain under the same
/// height. Anything genuinely node-local (mempool, consensus bookkeeping) is
/// mirrored here field by field rather than dropped, and is documented on the
/// field it mirrors.
pub struct ChainState {
    pub state: Arc<InMemoryStateEngine>,
    pub checkpoint: Vec<u8>,
    /// Per-block proposer reward, mirroring `ValidatorRuntime::block_reward`.
    pub block_reward: u64,
    /// Governance copy used to resolve the reward, mirroring
    /// `ValidatorRuntime::governance`.
    pub governance: Option<crate::governance::Governance>,
    /// Transactions applied so far - mirrors `ValidatorRuntime::applied_txs`.
    pub applied_txs: u64,
    /// Receipts (per-transaction success flags) of the last applied block -
    /// mirrors `ValidatorRuntime::applied_statuses`.
    pub applied_statuses: Vec<bool>,
    /// Per-transaction fee actually charged by the last applied block -
    /// mirrors `ValidatorRuntime::applied_fees`.
    pub applied_fees: Vec<u64>,
    /// Per-transaction emitted contract events from the last applied block.
    pub applied_events: Vec<Vec<crate::contract::ContractEvent>>,
    /// Optional node-local mempool. The live path prunes included txs from its
    /// mempool on every apply; attach the same pool here to reproduce that.
    /// The mempool is NOT consensus state and is not committed, so leaving it
    /// unset cannot move the state root - it only decides whether an
    /// already-included transaction stays queued for re-proposal.
    mempool: Option<Arc<tokio::sync::RwLock<crate::mempool::Mempool>>>,
    /// §5 M3: mirrors of the live runtime's cross-shard sets, so a reorg
    /// re-apply derives the same linkage/timeout/completion verdicts — and
    /// the same bounce refunds — as the node that finalized the blocks.
    /// (No transport here: publishing and KV pruning are node-local effects
    /// of the live path, not state.)
    consumed_cross_shard: HashSet<CrossShardKey>,
    produced_cross_shard: HashMap<[u8; 32], (Transaction, u64)>,
    completed_cross_shard: HashSet<[u8; 32]>,
}

impl ChainState {
    pub fn new(state: Arc<InMemoryStateEngine>) -> Self {
        Self {
            state: state.clone(),
            checkpoint: Vec::new(),
            block_reward: 0,
            governance: None,
            applied_txs: 0,
            applied_statuses: Vec::new(),
            applied_fees: Vec::new(),
            applied_events: Vec::new(),
            mempool: None,
            consumed_cross_shard: HashSet::new(),
            produced_cross_shard: HashMap::new(),
            completed_cross_shard: HashSet::new(),
        }
    }

    /// Pay the governed/default block reward, exactly as the live path does.
    pub fn with_block_reward(mut self, reward: u64) -> Self {
        self.block_reward = reward;
        self
    }

    /// Use this governance copy when resolving the block reward (mirrors
    /// `ValidatorRuntime::with_governance`).
    pub fn with_governance(mut self, g: crate::governance::Governance) -> Self {
        self.governance = Some(g);
        self
    }

    /// Prune included transactions from this pool on apply, exactly as
    /// `apply_block_fees_rewards` does for the live path.
    pub fn with_mempool(
        mut self,
        mempool: Arc<tokio::sync::RwLock<crate::mempool::Mempool>>,
    ) -> Self {
        self.mempool = Some(mempool);
        self
    }

    /// Configure disjoint wave parallel block execution for historical replay / reorg.
    pub fn with_parallel_exec(self, enabled: bool) -> Self {
        self.state.set_parallel_exec(enabled);
        self
    }

    /// Apply a block to the state through the SHARED block transition - the
    /// same `InMemoryStateEngine::apply_block_transition` the live consensus
    /// path runs on finalize, adopt, walk and replay. Returns nothing; the
    /// per-block outcome is recorded in `applied_statuses` / `applied_txs`,
    /// the same bookkeeping `ValidatorRuntime` keeps for receipts.
    pub async fn apply_block(&mut self, block: &Block) {
        let reward = block_reward_for(self.governance.as_ref(), self.block_reward);
        let out = self.state.apply_block_transition(block, reward).await;
        self.applied_statuses = out.status;
        self.applied_fees = out.tx_fees;
        self.applied_events = out.events;
        self.applied_txs += out.applied as u64;
        // §5 M3 parity with `ValidatorRuntime::record_apply_outcome` (same
        // block -> same verdicts -> same refunds, in the same deterministic
        // key order). Transport effects (ack publish, KV prune) are live-path
        // node-local effects and are deliberately NOT mirrored: they cannot
        // move the state root.
        for msg in &block.cross_shard_out {
            if msg.is_transfer() && msg.is_outbound_for(block.shard_id) {
                let tx_hash = msg.tx.compute_tx_hash();
                self.produced_cross_shard
                    .entry(tx_hash)
                    .or_insert((msg.tx.clone(), block.height));
            }
        }
        let mut inbound_sorted: Vec<&CrossShardMessage> = block
            .cross_shard_out
            .iter()
            .filter(|m| m.is_inbound_for(block.shard_id))
            .collect();
        inbound_sorted.sort_by_key(|m| CrossShardKey::of(m));
        for msg in inbound_sorted {
            let key = CrossShardKey::of(msg);
            if msg.is_transfer() {
                self.consumed_cross_shard.insert(key);
            } else if msg.is_ack() || msg.is_bounce() {
                if msg.merkle_inclusion_proof.is_some() || msg.trusted {
                    continue;
                }
                if self
                    .completed_cross_shard
                    .contains(&msg.tx.compute_tx_hash())
                {
                    continue;
                }
                let linked = self
                    .produced_cross_shard
                    .contains_key(&msg.tx.compute_tx_hash());
                if !linked {
                    continue;
                }
                if msg.is_bounce() {
                    let hp = self.produced_cross_shard[&msg.tx.compute_tx_hash()].1;
                    if !crate::sharding::bounce_eligible(hp, block.height) {
                        continue;
                    }
                }
                if !self.consumed_cross_shard.insert(key) {
                    continue;
                }
                if !self.completed_cross_shard.insert(msg.tx.compute_tx_hash()) {
                    continue;
                }
                if msg.is_bounce() {
                    // REDEEM, not mint: the value was debited at produce time,
                    // so the capped mint path would drop the refund at the
                    // supply cap (pentest P2 / F2 handoff).
                    let _ = self
                        .state
                        .credit_native_transfer(&msg.tx.from, msg.tx.amount)
                        .await;
                }
            }
        }
        if let Some(mp) = &self.mempool {
            let included: Vec<[u8; 32]> = block
                .transactions
                .iter()
                .map(|t| t.compute_tx_hash())
                .collect();
            mp.write().await.prune_confirmed(&included);
            // CometBFT-style RECHECK after each commit (mirror of
            // `ValidatorRuntime::record_apply_outcome`): drop queued txs the
            // commit made permanently unexecutable. Snapshot-then-recheck
            // under separate short locks (never nested).
            let payers: Vec<[u8; 32]> = mp.read().await.fee_payers().into_iter().collect();
            let guard = self.state.accounts.read().await;
            let mut snap: HashMap<[u8; 32], (u64, u64)> = HashMap::with_capacity(payers.len());
            for a in &payers {
                if let Some(acct) = guard.get(a) {
                    snap.insert(*a, (acct.nonce, acct.balance));
                }
            }
            drop(guard);
            let dropped = mp
                .write()
                .await
                .recheck(crate::zkml::now_secs(), |a| snap.get(a).copied());
            if dropped > 0 {
                tracing::info!(
                    "[mempool] recheck after commit at height {}: dropped {dropped} stale tx(s)",
                    block.height,
                );
            }
        }
        // C-02: same deterministic gov-finalization sweep as the live path,
        // so a reorg re-apply converges with live-finalized nodes.
        sweep_gov_finalize(&self.state, block.height, block.timestamp).await;
    }

    /// The validator set this state implies: the same read-only derivation
    /// `ValidatorRuntime::refresh_validator_set_from_staking` performs after
    /// every live apply. `ChainState` holds no consensus view of its own (the
    /// proposer schedule and quorum live in `HeightConsensus`), so the caller
    /// re-derives from here after a reorg. Because the staking ledger is
    /// engine state committed by the shared transition, the derivation input is
    /// byte-identical on both paths.
    pub async fn validator_set(&self) -> crate::consensus::ValidatorSet {
        self.state.staking_read().await.to_validator_set()
    }

    /// Snapshot the current state (call at each finalized height).
    pub async fn save_checkpoint(&mut self) {
        self.checkpoint = self.state.create_snapshot().await;
    }

    /// Restore the last checkpoint (finalized state).
    pub async fn restore_checkpoint(&self) {
        if !self.checkpoint.is_empty() {
            let _ = self.state.restore_snapshot(&self.checkpoint).await;
        }
    }

    /// Perform a reorg: restore the finalized checkpoint, then re-apply the new
    /// canonical blocks from the reorg plan (ancestor-first).
    pub async fn reorg(&mut self, tree: &crate::chain::BlockTree, plan: &crate::chain::ReorgPlan) {
        self.restore_checkpoint().await;
        for h in &plan.apply {
            if let Some(b) = tree.get(h) {
                self.apply_block(b).await;
            }
        }
    }

    /// Perform a reorg and return the invalidation signal for the blocks
    /// that were rolled back.
    ///
    /// Same state execution as [`Self::reorg`], plus the signal: the
    /// rolled-back blocks are announced to the RPC / streaming layer, so a
    /// client that followed the old branch learns that it was rolled back.
    /// The `height` of the signal is the LOWEST rolled-back height — the
    /// first height a consumer has to re-sync from.
    pub async fn reorg_with_signal(
        &mut self,
        tree: &crate::chain::BlockTree,
        plan: &crate::chain::ReorgPlan,
    ) -> crate::chain::InvalidationSignal {
        self.reorg(tree, plan).await;
        let height = plan
            .rollback
            .last()
            .and_then(|h| tree.height_of(h))
            .unwrap_or(0);
        crate::chain::InvalidationSignal {
            orphaned_blocks: plan.rollback.clone(),
            reason: format!(
                "reorg: rolled back {} block(s), re-applying {} block(s) from height {height}",
                plan.rollback.len(),
                plan.apply.len()
            ),
            height,
        }
    }
}
