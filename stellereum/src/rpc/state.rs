use super::*;
use crate::mempool::Mempool;
use crate::sharding::{ShardId, ShardRegistry, Transaction};
use crate::state_engine::InMemoryStateEngine;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub(super) const MAX_RPC_BODY: usize = 1024 * 1024;

/// Max calls in one JSON-RPC batch array (overall cap, fail-closed).
///
/// Each batch item is a FULL `dispatch` (own auth check, own rate-budget
/// draws, own error shape), so the fan-out is bounded here: without a cap a
/// single HTTP request could buy unbounded expensive-read simulations.
pub const MAX_RPC_BATCH_ITEMS: usize = 64;

/// Max bytes of one batch request body, as a multiple of [`MAX_RPC_BODY`].
///
/// Kept at 1x on purpose: the axum extractor (`DefaultBodyLimit`) and the
/// in-handler check already refuse every body above [`MAX_RPC_BODY`], so a
/// batch can never be bigger than a single call's bound — no new DoS surface.
/// The named const makes the overall byte cap explicit next to the item cap
/// (and is the defense-in-depth check for callers that bypass the layer).
pub const MAX_RPC_BATCH_BYTES: usize = MAX_RPC_BODY;

/// Compact summary of a finalized block (for the explorer / RPC).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockSummary {
    pub height: u64,
    pub hash: String,
    pub tx_count: usize,
    pub timestamp: u64,
}

/// One shard of the network as `stell_getShards` reports it.
///
/// The analogue of TON's `liteServer.getShards` / Near's `shard_layout`: a
/// wallet or an indexer asks the node which shards exist, which chain each
/// one is, and where its head is — instead of assuming a single global chain
/// and guessing where a balance lives.
///
/// Every field is either a fact this node COMMITTED or `null`. A tip is never
/// invented for a shard this node has no committed block for (the audit rule
/// the rest of this file follows: never fabricate, answer "not available").
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShardHead {
    /// Shard id: `0` is the masterchain, `>= 1` are workchain shards.
    pub shard_id: ShardId,
    /// `"masterchain"` or `"workchain"` (JSON key `type`).
    #[serde(rename = "type")]
    pub shard_type: String,
    /// Height of this shard's committed head.
    pub tip_height: u64,
    /// Hash of this shard's committed head block, or `null` when this node
    /// has no committed head for the shard.
    pub tip_hash: Option<String>,
    /// State root after applying the head block, or `null` when unknown.
    pub state_root: Option<String>,
    /// True when this shard is the one THIS node's own engine runs.
    pub local: bool,
}

/// Read-only view of the node that the RPC layer serves.
pub struct RpcState {
    pub engine: Arc<InMemoryStateEngine>,
    pub mempool: Arc<RwLock<Mempool>>,
    /// current finalized height (shared with consensus)
    pub height: Arc<std::sync::atomic::AtomicU64>,
    /// node id (hex)
    pub node_id: String,
    pub chain_id: u64,
    /// Shared on-chain staking ledger (mutated by staking RPC methods).
    pub staking: Arc<RwLock<crate::staking::StakingLedger>>,
    /// Shared on-chain governance engine.
    pub governance: Arc<RwLock<crate::governance::Governance>>,
    /// Rolling window of the most recent finalized blocks (newest first).
    pub recent_blocks: Arc<RwLock<std::collections::VecDeque<BlockSummary>>>,
    /// Inclusion receipts by transaction hash, so a wallet can ask what happened
    /// to its transaction instead of guessing from the mempool.
    pub receipts: Arc<RwLock<ReceiptIndex>>,
    /// Optional API token gating the NON-public introspection/payload arms
    /// (`stell_mempoolDump`, `stell_submitPriceFeed`, `stell_pmmBuy`,
    /// `stell_pmmSell`). The submission paths (`stell_sendRawTransaction`,
    /// `eth_sendRawTransaction`) are OPEN by design — a caller can only submit
    /// a validly signed, funded, nonce-sane transaction — and the faucet has its
    /// own fail-closed `faucet_token`. When `None`, the gated arms stay open
    /// (local/dev mode) — EXCEPT the governance writes (`stell_submitProposal`,
    /// `stell_vote`, `stell_executeProposal`) and the contract previews
    /// (`stell_deployContract`, `stell_callContract`), which require a valid
    /// token on EVERY bind (N-02/N-03; see `require_gov_write_auth`).
    pub auth_token: Option<String>,

    /// Optional channel to forward validated raw transactions into P2P gossip
    pub tx_broadcast: Option<tokio::sync::mpsc::UnboundedSender<Transaction>>,
    /// Optional testnet faucet. `None` (the default, and on mainnet) the faucet
    /// RPC method is disabled entirely, so no node can mint out of thin air.
    pub faucet: Option<Arc<Faucet>>,
    /// Token that must be presented to use the faucet. Unlike `auth_token`
    /// this one is **fail-closed**: an enabled faucet with no token refuses to
    /// dispense, because "no token configured" must never mean "anyone who can
    /// reach the port may mint".
    pub faucet_token: Option<String>,
    /// Ed25519 seed the `stell_signMessage` / `stell_signTypedData` arms sign
    /// with: a SEPARATE ephemeral dev-only key (see
    /// [`dev_msg_signing_seed_from_env`]), NEVER the validator/consensus key.
    /// `None` (production default, and any node without explicit dev mode)
    /// makes both arms refuse fail-closed with `-32000`. Testing/devnet ONLY:
    /// a production wallet signs locally and never ships its key to a node.
    pub msg_signing_seed: Option<[u8; 32]>,
    /// Durable store handle serving per-key ARCHIVE proofs and historical
    /// roots (`stell_getArchiveProof`, `stell_getHistoricalRoot`).
    ///
    /// Archive proofs are rebuilt from the persisted snapshot history, never
    /// from the live trie. `None` (unit tests that never attach a store)
    /// makes both arms refuse fail-closed: a node that cannot consult its
    /// snapshots must say so, not prove from memory and label it history.
    pub archive_store: Option<Arc<crate::storage::Storage>>,
    /// The set of shards this process runs. Gated shard-aware admission on it:
    /// when [`ShardRegistry::is_sharded`] is false (the default, every
    /// pre-sharding test) the faucet serves any well-formed address exactly as
    /// before; when true, the faucet serves ONLY recipients that route to its
    /// own shard and refuses the rest at admission (a drip for another shard
    /// would be dropped by that shard's proposer as shard-filtered and could
    /// never execute).
    pub shard_registry: ShardRegistry,
}

/// One FINALIZED header, with the quorum certificate that decided it.
///
/// This is what an external light client needs: the header carries the
/// precommit quorum certificate, and the certificate is what makes the state
/// root the header commits to TRUSTWORTHY (a root the server merely asserts
/// is worth nothing — see the audit that added this).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FinalizedHeaderRecord {
    pub height: u64,
    pub block_hash: [u8; 32],
    pub prev_hash: [u8; 32],
    /// The state root this header COMMITS TO. Chain convention: a header
    /// commits to the state BEFORE its own block, so this is the root of the
    /// state as of `height - 1`.
    pub state_root: [u8; 32],
    pub proposer: [u8; 32],
    pub timestamp: u64,
    pub cert: crate::consensus::QuorumCertificate,
    /// The epoch-MMR root this block committed to (`Block::mmr_epoch_root`,
    /// V5 Tier-2): non-zero only on the first masterchain block of an epoch
    /// (committing the PREVIOUS epoch). Zero everywhere else — including on
    /// every record predating the MMR (`#[serde(default)]`).
    #[serde(default)]
    pub mmr_epoch_root: [u8; 32],
}

impl FinalizedHeaderRecord {
    /// The wire form: every hash is HEX (the RPC's convention) and the
    /// certificate is spelled out, so a light client can rebuild the
    /// [`crate::consensus::QuorumCertificate`] and verify it.
    pub fn to_json(&self) -> Value {
        json!({
            "height": self.height,
            "block_hash": hex::encode(self.block_hash),
            "prev_hash": hex::encode(self.prev_hash),
            "state_root": hex::encode(self.state_root),
            "proposer": hex::encode(self.proposer),
            "timestamp": self.timestamp,
            // The epoch-MMR root this block committed (V5 Tier-2): the MMR
            // root over the PREVIOUS epoch's finalized hashes on an
            // epoch-boundary block, zero everywhere else. A light client
            // checks a `stell_getEpochRoot` answer against THIS value (it is
            // inside the quorum-signed block hash) instead of trusting the
            // serving node.
            "mmr_epoch_root": hex::encode(self.mmr_epoch_root),
            "cert": {
                "height": self.cert.height,
                "round": self.cert.round,
                "kind": format!("{:?}", self.cert.kind),
                "block_hash": self.cert.block_hash.map(hex::encode),
                "signatures": self.cert.signatures.iter().map(|(v, s)| json!({
                    "validator": hex::encode(v),
                    "signature": hex::encode(s),
                })).collect::<Vec<Value>>(),
            },
        })
    }
}

/// Testnet-only token faucet.
///
/// Faucet funds are **not** written straight into the state engine: that would be
/// node-local and therefore non-deterministic across a multi-node network. The
/// faucet instead signs ordinary transfers from a dedicated, pre-funded genesis
/// account and submits them to the mempool, so the value movement is decided by
/// consensus exactly like any other transaction.
///
/// SHARD SCOPE (sharded networks): one faucet serves exactly ONE shard — the
/// shard in [`Faucet::shard`]. Every drip it builds is a same-shard transfer
/// Highest VERIFIED peer height + when it was seen (audit follow-up: a bare
/// max pinned `stell_syncing==true` forever on one faulty vote, and reset to
/// 0 on restart). Entries older than PEER_HEIGHT_STALE_SECS are ignored.
/// Vantage-local by design.
pub static PEER_HEIGHT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static PEER_HEIGHT_AT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub const PEER_HEIGHT_STALE_SECS: u64 = 300;

/// Record a verified peer height (monotonic max; never moves backwards).
/// Every sighting refreshes the freshness stamp, so a stale faulty vote
/// stops pinning `stell_syncing` after PEER_HEIGHT_STALE_SECS.
pub fn note_peer_height(h: u64) {
    PEER_HEIGHT.fetch_max(h, std::sync::atomic::Ordering::Relaxed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    PEER_HEIGHT_AT.store(now, std::sync::atomic::Ordering::Relaxed);
}

/// Fresh peer height, if any sighting is recent.
pub fn fresh_peer_height() -> Option<u64> {
    let h = PEER_HEIGHT.load(std::sync::atomic::Ordering::Relaxed);
    let at = PEER_HEIGHT_AT.load(std::sync::atomic::Ordering::Relaxed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if h == 0 || now.saturating_sub(at) > PEER_HEIGHT_STALE_SECS {
        None
    } else {
        Some(h)
    }
}

/// Live connected-peer count observed by this process.
///
/// `net_peerCount` must never invent a number (F8: it was the constant
/// `"0x2"` on a node with no peer observer). The RPC layer reads this
/// process-wide counter, which the node's network layer feeds via
/// [`note_peer_count`]; `0` therefore means "no peer observed by this
/// process", never "two peers".
pub static LIVE_PEER_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Record the live connected-peer count (`net_peerCount` source of truth).
///
/// Fed by [`crate::network::P2pNetworkAdapter::publish_live_peer_count`], the
/// single hook that reads the node's live peer table (`Node::peers_ready`) and
/// publishes it here. 0 means "no connected peer observed", never a guess.
pub fn note_peer_count(n: u64) {
    LIVE_PEER_COUNT.store(n, std::sync::atomic::Ordering::Relaxed);
}

/// The observed connected-peer count (0 = none observed, never a guess).
pub fn observed_peer_count() -> u64 {
    LIVE_PEER_COUNT.load(std::sync::atomic::Ordering::Relaxed)
}

/// Last connected-peer-reported chain id + when it was seen (0 = none yet).
/// A peer reporting a different chain id than ours is on a DIFFERENT network:
/// recording the sighting is not enough — the observer must abort (fail-closed,
/// loud), never silently partition. See [`note_peer_chain_id`].
pub static PEER_CHAIN_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static PEER_CHAIN_ID_AT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Record a connected peer's reported chain id and enforce the fail-closed
/// mismatch rule (task (c)): `Ok` records and returns when `peer == local`;
/// `Err` (loud, must abort the caller — at startup: refuse to start) when the
/// peer is on a different chain. The sighting is stored either way, so
/// [`fresh_peer_chain_id`] stays diagnostic.
pub fn note_peer_chain_id(local: u64, peer: u64) -> Result<(), String> {
    PEER_CHAIN_ID.store(peer, std::sync::atomic::Ordering::Relaxed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    PEER_CHAIN_ID_AT.store(now, std::sync::atomic::Ordering::Relaxed);
    crate::zkml::check_peer_chain_id(local, peer)
}

/// Fresh peer-reported chain id, if any sighting is recent (`Some(0)`/stale =
/// `None`: no usable report, not evidence of anything).
pub fn fresh_peer_chain_id() -> Option<u64> {
    let id = PEER_CHAIN_ID.load(std::sync::atomic::Ordering::Relaxed);
    let at = PEER_CHAIN_ID_AT.load(std::sync::atomic::Ordering::Relaxed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if id == 0 || now.saturating_sub(at) > PEER_HEIGHT_STALE_SECS {
        None
    } else {
        Some(id)
    }
}

/// Max number of recent blocks retained for the explorer.
pub const MAX_RECENT_BLOCKS: usize = 100;

/// The process-wide window of FINALIZED HEADERS (with their quorum
/// certificates), newest first.
///
/// This is the LIGHT CLIENT's view of the chain (audit W8.3 / production
/// blocker A10): an external verifier fetches a header here, checks its
/// quorum certificate against its OWN validator set, and only then trusts
/// the state root the header commits to. Without it the node could hand out
/// any root it liked and call it a proof.
///
/// It is process-wide (like the invalidation window) because a node has ONE
/// chain: the header stream is a property of the node, not of an RPC
/// instance. Bounded by [`MAX_FINALIZED_HEADERS`]; a header that is too old
/// to be served is an honest "not available" (the client re-anchors on a
/// newer one).
pub(super) static FINALIZED_HEADERS: std::sync::OnceLock<
    Arc<RwLock<std::collections::VecDeque<FinalizedHeaderRecord>>>,
> = std::sync::OnceLock::new();

/// The process-wide finalized-header window.
pub fn finalized_headers() -> Arc<RwLock<std::collections::VecDeque<FinalizedHeaderRecord>>> {
    FINALIZED_HEADERS
        .get_or_init(|| Arc::new(RwLock::new(std::collections::VecDeque::new())))
        .clone()
}

/// The process-wide PQ key registry view served by `stell_getPqKey` /
/// `stell_getPqRegistryStatus`.
///
/// A node has ONE PQ rotation story (like it has ONE header chain, see
/// [`finalized_headers`]): the registry is a property of the node, not of an
/// RPC instance, so the read arms consult this handle instead of a per-state
/// copy. The arms take only `.read()` — they never mutate. Writes arrive
/// through the staking hooks / future announcement wiring (and tests), never
/// through RPC: there is deliberately no state-mutating PQ endpoint.
pub fn pq_registry_handle() -> &'static RwLock<crate::pq_registry::PqRegistry> {
    static PQ_REGISTRY: std::sync::OnceLock<RwLock<crate::pq_registry::PqRegistry>> =
        std::sync::OnceLock::new();
    PQ_REGISTRY.get_or_init(|| RwLock::new(crate::pq_registry::PqRegistry::new()))
}

/// Max number of FINALIZED HEADERS (with their quorum certificates) retained
/// for the light client.
///
/// Bounded so a busy chain cannot exhaust memory. A light client that needs
/// an older header re-anchors on a newer one; the anchor only ever moves
/// forward.
pub const MAX_FINALIZED_HEADERS: usize = 512;

/// Max receipts retained; bounded so a busy chain cannot exhaust memory.
pub const MAX_RECEIPTS: usize = 50_000;

/// What a wallet gets back for a transaction it submitted.
///
/// `gas_limit` is the DECLARED limit; `fee_charged` is what the single real
/// application actually debited (0 for a failed transaction, whose commit is
/// atomic - it paid nothing). Wallets must account on `fee_charged`: the
/// limit overstates the cost of every failed transaction.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TxReceipt {
    pub tx_hash: [u8; 32],
    pub height: u64,
    pub block_hash: [u8; 32],
    pub index: u32,
    pub success: bool,
    pub gas_limit: u64,
    pub fee_charged: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_tx: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_value: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_used: Option<u64>,
    #[serde(default)]
    pub events: Vec<crate::contract::ContractEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_address: Option<[u8; 32]>,
}

/// Bounded LRU-ish index of transaction receipts, ordered by inclusion.
#[derive(Default)]
pub struct ReceiptIndex {
    pub order: std::collections::VecDeque<[u8; 32]>,
    pub map: HashMap<[u8; 32], TxReceipt>,
}

impl ReceiptIndex {
    pub fn insert(&mut self, r: TxReceipt) {
        let hash = r.tx_hash;
        if self.map.insert(hash, r).is_none() {
            self.order.push_back(hash);
            while self.order.len() > MAX_RECEIPTS {
                if let Some(old) = self.order.pop_front() {
                    self.map.remove(&old);
                }
            }
        }
    }

    pub fn get(&self, hash: &[u8; 32]) -> Option<&TxReceipt> {
        self.map.get(hash)
    }

    pub fn values(&self) -> impl Iterator<Item = &TxReceipt> {
        self.map.values()
    }

    pub fn for_height(&self, height: u64) -> Vec<&TxReceipt> {
        let mut rows: Vec<&TxReceipt> = self.map.values().filter(|r| r.height == height).collect();
        rows.sort_by_key(|r| r.index);
        rows
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl RpcState {
    /// Best-effort mempool durability after admissions: restarts between the
    /// 15s periodic save and execution silently drop fresh transactions
    /// (observed live: 1000-tx blasts vanishing). Throttled to once per 2s so
    /// a burst doesn't fsync per tx; the shutdown hook and periodic saver
    /// cover the rest. Path matches the loader in main.rs.
    pub async fn save_mempool_throttled(&self) {
        static LAST_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        if now.saturating_sub(LAST_MS.load(std::sync::atomic::Ordering::Relaxed)) < 2000 {
            return;
        }
        LAST_MS.store(now, std::sync::atomic::Ordering::Relaxed);
        let path = std::path::PathBuf::from("./data/mempool.bin");
        self.mempool.read().await.save(&path);
    }

    /// Record a newly finalized block. Called by the consensus loop.
    pub async fn record_block(&self, height: u64, hash: [u8; 32], tx_count: usize, timestamp: u64) {
        // Finalized-read cache: a (re)publish for this height (finalize, or a
        // late adopted body upgrading txs `0` to the real count) drops that
        // height's cached responses so the next read recomputes. Fail-closed.
        finalized_read_cache_evict_height(height);
        self.height
            .store(height, std::sync::atomic::Ordering::Relaxed);
        let mut rb = self.recent_blocks.write().await;
        rb.push_front(BlockSummary {
            height,
            hash: hex::encode(hash),
            tx_count,
            timestamp,
        });
        while rb.len() > MAX_RECENT_BLOCKS {
            rb.pop_back();
        }
        drop(rb);
        crate::evm_adapter::notify_block(crate::evm_adapter::stell_hash_to_evm(&hash));
        // Streaming: this IS the consensus finalize hook, so the `newHeads`
        // subscribers are notified here -- a subscriber sees every finalized
        // head of this node, in order, tagged `finality: "finalized"`.
        publish_new_head(
            height,
            hash,
            crate::sharding::MASTERCHAIN_SHARD,
            tx_count,
            timestamp,
        );
    }

    /// Record a FINALIZED header together with the quorum certificate that
    /// decided it.
    ///
    /// This is what makes the node's chain externally verifiable (audit W8.3 /
    /// production blocker A10): a light client fetches the header, checks the
    /// certificate against its OWN validator set, and only then believes the
    /// state root the header commits to.
    ///
    /// A block with NO precommit quorum certificate is not DECIDED, so it is
    /// not recorded: there is no evidence to serve, and serving a header
    /// without one would be exactly the "the node hands out the root it
    /// believes in" hole this closes.
    pub async fn record_finalized_header(&self, block: &crate::sharding::Block) {
        let Some(cert) = block.precommit_qc.clone() else {
            return;
        };
        let record = FinalizedHeaderRecord {
            height: block.height,
            block_hash: block.compute_hash(),
            prev_hash: block.prev_hash,
            state_root: block.state_root,
            proposer: block.proposer,
            timestamp: block.timestamp,
            cert,
            mmr_epoch_root: block.mmr_epoch_root,
        };
        let store = finalized_headers();
        let mut hs = store.write().await;
        // The newest first, like `recent_blocks`.
        hs.push_front(record);
        while hs.len() > MAX_FINALIZED_HEADERS {
            hs.pop_back();
        }
        drop(hs);
        // Finalized-read cache: this header can complete an epoch or supply
        // its boundary commitment, so cached epoch roots are dropped (they
        // recompute) and this height's cached header is dropped too.
        finalized_read_cache_evict_height(block.height);
        finalized_read_cache_evict_epoch_roots();
    }

    /// Record inclusion receipts for a finalized block's transactions.
    ///
    /// `fees` carries the nano-STELL each transaction was actually charged
    /// (parallel to `statuses`, in block order, from the single real
    /// application); a short `fees` falls back to `gas_limit`-on-success /
    /// 0-on-fail, which is exactly what the block path charged.
    pub async fn record_receipts(
        &self,
        height: u64,
        block_hash: [u8; 32],
        txs: &[crate::sharding::Transaction],
        statuses: &[bool],
        fees: &[u64],
    ) {
        self.record_receipts_with_events(height, block_hash, txs, statuses, fees, &[])
            .await;
    }

    /// Record inclusion receipts for a finalized block's transactions, including contract events.
    pub async fn record_receipts_with_events(
        &self,
        height: u64,
        block_hash: [u8; 32],
        txs: &[crate::sharding::Transaction],
        statuses: &[bool],
        fees: &[u64],
        events: &[Vec<crate::contract::ContractEvent>],
    ) {
        // Link EVM intents settled via secp envelopes BEFORE filing receipts,
        // so a reader that observes the receipt also observes the mapping.
        for tx in txs.iter() {
            crate::evm_adapter::link_secp_settlement(tx);
        }
        // Finalized-read cache: newly filed receipts change this height's
        // block-transactions answer (absent -> filed, e.g. a late adopted
        // body), so that height's cached responses are dropped. Fail-closed.
        finalized_read_cache_evict_height(height);
        let mut idx = self.receipts.write().await;
        // Batched hashing in a SINGLE pass: one reused hasher + one reused
        // payload scratch buffer + one reused serialization buffer, with the
        // hash output pre-sized — instead of one hasher + two payload buffers
        // per transaction. The hashes are byte-identical to per-transaction
        // `compute_tx_hash` (shared `hash_into` code, `finalize_reset`
        // restarts the hasher to the same initial state), and the raw-tx hex
        // is byte-identical to `bincode::serialize` (same options, cleared
        // scratch). Only the stored hex `String` itself is allocated per
        // transaction (it has to be: it is stored in the receipt).
        let mut batcher = crate::sharding::Transaction::batch_hasher();
        let mut raw_buf: Vec<u8> = Vec::new();
        let mut hashes: Vec<[u8; 32]> = Vec::with_capacity(txs.len());
        for (i, tx) in txs.iter().enumerate() {
            let success = statuses.get(i).copied().unwrap_or(false);
            raw_buf.clear();
            let raw_tx = bincode::serialize_into(&mut raw_buf, tx)
                .ok()
                .map(|_| hex::encode(&raw_buf));
            let h = batcher.hash_one(tx);
            hashes.push(h);
            let (rv, gu, ev, ca) = if let Some(existing) = idx.get(&h) {
                let evs = if !existing.events.is_empty() {
                    existing.events.clone()
                } else {
                    events.get(i).cloned().unwrap_or_default()
                };
                (
                    existing.return_value,
                    existing.gas_used,
                    evs,
                    existing.contract_address,
                )
            } else {
                (None, None, events.get(i).cloned().unwrap_or_default(), None)
            };
            idx.insert(TxReceipt {
                tx_hash: h,
                height,
                block_hash,
                index: i as u32,
                success,
                gas_limit: tx.gas_limit,
                fee_charged: fees
                    .get(i)
                    .copied()
                    .unwrap_or(if success { tx.gas_limit } else { 0 }),
                raw_tx,
                return_value: rv,
                gas_used: gu,
                events: ev,
                contract_address: ca,
            });
        }
        // Streaming: fan the included transactions out to the `newTxs`
        // subscribers and the emitted contract events to the `events`
        // subscribers. Done AFTER the receipt lock is released -- the fan-out
        // must never hold the receipt index while a subscriber is slow, and
        // the receipt index stays the source of truth for the RPC reads.
        drop(idx);
        for (i, tx) in txs.iter().enumerate() {
            let success = statuses.get(i).copied().unwrap_or(false);
            let hash = hashes[i];
            publish_new_tx(
                hash,
                tx.from,
                tx.to,
                tx.amount,
                if success { "confirmed" } else { "failed" },
            );
            if let Some(evs) = events.get(i) {
                for e in evs {
                    publish_contract_event(e, height, hash);
                }
            }
        }
    }

    /// Record an ADOPTED (or walked) block: the hook the adopt_committed /
    /// walk_chain paths call so a non-proposer serves identical bodies+receipts
    /// as the proposer (no more `txs=0` views, no missing receipts).
    ///
    /// Mechanics only: `txs` is the verified body the adopter already holds
    /// (hash-checked against the committed header before this is called) and
    /// `statuses` is the outcome of the SINGLE real application on this node
    /// (never re-execution output, never wire data -- see the parity test).
    /// Ordering matches the finalize path exactly (receipts before the block
    /// summary) so readers that observe height H see every receipt of H.
    /// `tx_count` is derived from the body (`txs.len()`), never passed as 0
    /// while a body is present -- that 0 is the exact `txs=0` view observed
    /// live. Runs behind/parallel to finalization; never blocks it.
    pub async fn record_adopted_block(
        &self,
        height: u64,
        block_hash: [u8; 32],
        txs: &[crate::sharding::Transaction],
        statuses: &[bool],
        fees: &[u64],
        timestamp: u64,
    ) {
        self.record_adopted_block_with_events(
            height,
            block_hash,
            txs,
            statuses,
            fees,
            &[],
            timestamp,
        )
        .await;
    }

    /// Record an adopted block including emitted contract events.
    #[allow(clippy::too_many_arguments)]
    // GATE: 8 receipt fields are required together; grouping would change index/record call sites.
    pub async fn record_adopted_block_with_events(
        &self,
        height: u64,
        block_hash: [u8; 32],
        txs: &[crate::sharding::Transaction],
        statuses: &[bool],
        fees: &[u64],
        events: &[Vec<crate::contract::ContractEvent>],
        timestamp: u64,
    ) {
        self.record_receipts_with_events(height, block_hash, txs, statuses, fees, events)
            .await;
        self.record_block(height, block_hash, txs.len(), timestamp)
            .await;
    }

    /// Import one durably stored receipt (restart hydration). Bounded by the
    /// same `MAX_RECEIPTS` cap as live inserts (oldest evicted first).
    pub async fn import_stored_receipt(&self, r: &crate::storage::StoredReceipt) {
        self.receipts.write().await.insert(TxReceipt {
            tx_hash: r.tx_hash,
            height: r.height,
            block_hash: r.block_hash,
            index: r.index,
            success: r.success,
            gas_limit: r.gas_limit,
            fee_charged: r.fee_charged,
            raw_tx: None,
            return_value: None,
            gas_used: None,
            events: r.events.clone(),
            contract_address: None,
        });
    }

    /// Programmatic RPC call helper (for testing and embedded harnesses).
    pub async fn call(&self, method: &str, params: serde_json::Value) -> serde_json::Value {
        let r = dispatch(
            self,
            serde_json::Value::from(1),
            method,
            &params,
            None,
            None,
        )
        .await;
        r.0.error
            .map(|e| serde_json::json!({"error": e.message}))
            .unwrap_or(r.0.result.unwrap_or(serde_json::Value::Null))
    }
}

/// Refill an RPC index from the durable receipt store (restart hydration).
///
/// Reads at most `MAX_RECEIPTS` receipts tip-ward (highest height first, so a
/// cold index serves the tip first) and imports them into `st`. Bounded:
/// never more than the in-memory cap. Pure orchestration over the two stores;
/// the durable side stays the source of truth.
pub async fn hydrate_rpc_from_store(st: &RpcState, store: &crate::storage::Storage) {
    let mut all = store.all_receipts_capped(MAX_RECEIPTS).unwrap_or_default();
    all.sort_by_key(|r| std::cmp::Reverse((r.height, r.index)));
    all.truncate(MAX_RECEIPTS);
    // Insert oldest-first so the index's VecDeque order ends tip-last like the
    // live path (insertion order = inclusion order within the window).
    all.reverse();
    for r in &all {
        st.import_stored_receipt(r).await;
    }
    // PENTEST2 H1: rebuild the process-local EVM binding + settlement indexes
    // from the PERSISTED, COMMITTED block window, in block order. The live
    // apply path feeds the same indexes (see
    // `InMemoryStateEngine::observe_committed_evm_block`), so a restart now
    // derives the same maps instead of starting empty. Only transactions whose
    // durable receipt says `success == true` are replayed: a refused claim is
    // not a binding and a refused carrier is not a settlement.
    {
        const EVM_INDEX_REPLAY_WINDOW: u64 = 50_000;
        let successful: std::collections::HashSet<[u8; 32]> = all
            .iter()
            .filter(|r| r.success)
            .map(|r| r.tx_hash)
            .collect();
        if let Ok(Some(tip_rec)) = store.latest_header() {
            let tip = tip_rec.height;
            let lo = tip.saturating_sub(EVM_INDEX_REPLAY_WINDOW - 1);
            let mut blocks = Vec::new();
            for h in lo..=tip {
                if let Ok(Some(rec)) = store.header_at(h) {
                    if let Ok(Some(block)) = store.get_block(&rec.block_hash) {
                        blocks.push(block);
                    }
                }
            }
            // EVM carriers/bindings are masterchain payloads; a workchain
            // hydrate must not clear the process-global index built by the
            // masterchain. Only rebuild when this window actually carries an
            // EVM payload.
            let has_evm = blocks.iter().any(|b| {
                b.transactions
                    .iter()
                    .any(|tx| crate::evm_adapter::classify_evm_payload(tx).is_some())
            });
            if has_evm {
                st.engine
                    .rebuild_evm_indexes_from_blocks(&blocks, &successful);
            }
        }
    }
    // Rebuild the explorer window from header records (which survive body
    // pruning), tip-ward, newest-first like `record_block` maintains.
    if let Ok(Some(tip_rec)) = store.latest_header() {
        let tip = tip_rec.height;
        let mut summaries: Vec<BlockSummary> = Vec::new();
        let lo = tip.saturating_sub(MAX_RECENT_BLOCKS as u64 - 1);
        for h in (lo..=tip).rev() {
            if let Ok(Some(rec)) = store.header_at(h) {
                summaries.push(BlockSummary {
                    height: rec.height,
                    hash: hex::encode(rec.block_hash),
                    tx_count: rec.tx_count as usize,
                    timestamp: rec.timestamp,
                });
            }
        }
        let mut rb = st.recent_blocks.write().await;
        rb.clear();
        for s in summaries {
            rb.push_back(s);
            while rb.len() > MAX_RECENT_BLOCKS {
                rb.pop_back();
            }
        }
        st.height.store(tip, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Serve fallback order for receipts and block-txs (documented, pinned by tests):
/// 1. local committed (in-memory receipts / recent window, fed by the single
///    real application via `record_receipts`/`record_block`/`record_adopted_block`);
/// 2. durable store import (`hydrate_rpc_from_store` after a restart);
/// 3. honest "not available yet" (`unknown` / `not available yet` error) --
///    never fabricated data, never a consensus stall.
pub const SERVE_FALLBACK_ORDER_DOC: &str =
    "local committed -> durable store -> honest not-available-yet (never fabricated)";

#[derive(Deserialize)]
pub struct RpcRequest {
    #[allow(dead_code)]
    pub jsonrpc: Option<String>,
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Serialize)]
pub struct RpcResponse {
    pub jsonrpc: &'static str,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

/// Handles a parsed RPC request directly against an `RpcState`.
pub async fn handle_rpc_call(st: &RpcState, req: &RpcRequest) -> RpcResponse {
    let id = req.id.clone().unwrap_or(Value::Null);
    let res = dispatch(st, id, &req.method, &req.params, None, None).await;
    res.0
}

/// Whole-batch refusal: the single error object the batch path answers when
/// the batch ITSELF is invalid (empty, too many items, too many bytes).
/// Per-item failures never come here — they are per-item `-32601`/`-32602`/
/// `-32000` entries inside the array (see [`handle_rpc_batch_call`]).
pub(super) fn batch_refused(message: impl Into<String>) -> RpcResponse {
    RpcResponse {
        jsonrpc: "2.0",
        id: Value::Null,
        result: None,
        error: Some(RpcError {
            code: -32600,
            message: message.into(),
            data: None,
        }),
    }
}

/// Dispatch one parsed JSON-RPC batch array.
///
/// * Overall caps (fail-closed, whole-batch refusal as a single `-32600`
///   error object): more than [`MAX_RPC_BATCH_ITEMS`] items, or a body over
///   [`MAX_RPC_BATCH_BYTES`], refuses the WHOLE batch.
/// * Per-item isolation: every item is parsed and dispatched independently
///   through the SAME `dispatch` as a single call (same `header_token`,
///   same `peer_ip`, same auth checks, same per-IP budgets, same error
///   shapes) — one bad/unknown/over-budget call never fails its siblings.
/// * Ordering: responses come back in request order, whatever the ids are.
/// * Notifications (no `id`, or `id: null`) get NO response entry, per the
///   JSON-RPC 2.0 spec (an all-notification batch yields an empty vec — the
///   HTTP handler answers that with `204 No Content`).
pub async fn handle_rpc_batch_call(
    st: &RpcState,
    items: &[Value],
    raw_len: usize,
    header_token: Option<&str>,
    peer_ip: Option<std::net::IpAddr>,
) -> Result<Vec<RpcResponse>, RpcResponse> {
    if items.is_empty() {
        return Err(batch_refused("empty batch"));
    }
    if items.len() > MAX_RPC_BATCH_ITEMS {
        return Err(batch_refused(format!(
            "batch too large: {} items (max {MAX_RPC_BATCH_ITEMS})",
            items.len()
        )));
    }
    if raw_len > MAX_RPC_BATCH_BYTES {
        return Err(batch_refused(format!(
            "batch too large: {raw_len} bytes (max {MAX_RPC_BATCH_BYTES})"
        )));
    }
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        // Borrow the item instead of cloning the whole JSON value: `&Value`
        // is itself a serde deserializer, so the request's own fields (method,
        // id) are read in place and only `params` is materialized inside the
        // request. The old `item.clone()` copied the ENTIRE item first — for a
        // batch of submission calls that duplicated every raw payload.
        let req: RpcRequest = match RpcRequest::deserialize(item) {
            Ok(r) => r,
            Err(e) => {
                out.push(batch_refused(format!("invalid request: {e}")));
                continue;
            }
        };
        // Notification: no response entry, per spec (siblings unaffected).
        let id = req.id.clone().unwrap_or(Value::Null);
        if id.is_null() {
            continue;
        }
        // Per-item transport budget: the HTTP middleware charged the batch
        // request once; every item draws the per-IP standalone budget again,
        // exactly as N single calls would. Over budget fails THIS item with
        // the per-item `-32000` rate shape (the socket stays answerable, the
        // siblings are unaffected) — never the whole batch.
        let ip = peer_ip.unwrap_or(LOCAL_BUCKET_IP);
        let limiter = STANDALONE_LIMITER
            .get_or_init(|| crate::explorer::RateLimiter::new(standalone_limit_per_sec()));
        if !limiter.check(ip) {
            out.push(RpcResponse {
                jsonrpc: "2.0",
                id,
                result: None,
                error: Some(RpcError {
                    code: -32000,
                    message: "rate limit exceeded (per-IP budget on standalone RPC)".to_string(),
                    data: None,
                }),
            });
            continue;
        }
        out.push(
            dispatch(st, id, &req.method, &req.params, header_token, peer_ip)
                .await
                .0,
        );
    }
    Ok(out)
}

#[derive(Serialize)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

pub(super) fn ok(id: Value, result: Value) -> Json<RpcResponse> {
    Json(RpcResponse {
        jsonrpc: "2.0",
        id,
        result: Some(result),
        error: None,
    })
}

pub(super) fn err(id: Value, code: i64, message: impl Into<String>) -> Json<RpcResponse> {
    Json(RpcResponse {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(RpcError {
            code,
            message: message.into(),
            data: None,
        }),
    })
}

/// Truncate caller-controlled text reflected in an error message.
///
/// Error strings are served back over the network, so reflecting an unbounded
/// caller string verbatim lets one request turn a ~1 MiB body into a ~1 MiB
/// error (bandwidth amplification and log bloat). Short legitimate inputs
/// (typos, wrong names) pass through byte-identical; only over-long
/// reflections are shortened, with an explicit marker.
pub(super) fn snip_for_error(s: &str) -> String {
    const MAX_REFLECTED_ERROR_CHARS: usize = 256;
    if s.len() <= MAX_REFLECTED_ERROR_CHARS {
        s.to_string()
    } else {
        let mut end = MAX_REFLECTED_ERROR_CHARS;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...[truncated {} chars]", &s[..end], s.len())
    }
}
