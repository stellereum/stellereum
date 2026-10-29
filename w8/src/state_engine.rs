//! Pipelined Execution & In-Memory State Engine
//! Actor Model: every account and smart contract operates as an isolated actor.
//! Actors communicate via asynchronous messages with bounce semantics (TON style).
//! Hot state maintained in RAM with cryptographic Patricia BoC Trie and background snapshots.

use crate::cell::{CellHash, MerkleProof, PatriciaTrie};
pub use crate::contract::{ContractEventJson, GetMethodResponse, GET_METHOD_SAFETY_FUEL_LIMIT};
use crate::token::{TokenError, TokenEvent, TokenMetadata, TokenOp, TokenRegistry};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Asynchronous message between actors
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorMessage {
    pub msg_id: [u8; 32],
    pub sender: [u8; 32],
    pub recipient: [u8; 32],
    pub value: u64, // nano-STELL attached to message
    pub body: Vec<u8>,
    pub bounce: bool,  // if recipient fails or does not exist, bounce funds back
    pub bounced: bool, // indicates whether this message is a bounced response
}

impl ActorMessage {
    pub fn new(
        sender: [u8; 32],
        recipient: [u8; 32],
        value: u64,
        body: Vec<u8>,
        bounce: bool,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(&sender);
        hasher.update(&recipient);
        hasher.update(value.to_be_bytes());
        hasher.update(&body);
        let msg_id: [u8; 32] = hasher.finalize().into();

        Self {
            msg_id,
            sender,
            recipient,
            value,
            body,
            bounce,
            bounced: false,
        }
    }
}

/// MAX_ACTOR_ROUNDS: how many sweep rounds one block's mailbox pass runs.
///
/// A round visits every recipient that has a queued message, in address
/// order, and drains its inbox; a body that enqueues a message for a recipient
/// ALREADY visited this round is therefore picked up by the NEXT round. This
/// is what bounds recursion (`A` sends to `B` sends to `A` sends to ...): a
/// chain of messages needs one round per hop, and a message still queued when
/// the rounds run out stays for the following block - it is never dropped and
/// never delivered out of order.
pub const MAX_ACTOR_ROUNDS: usize = 8;
/// MAX_ACTOR_MSGS_PER_BLOCK: hard cap on actor messages ONE block may deliver.
///
/// The anti-DoS bound that makes Phase 1's drain-to-empty policy affordable:
/// every message costs the sender prepaid gas on the way in
/// ([`crate::svm::GAS_ACTOR_SEND`] + [`crate::svm::GAS_ACTOR_DELIVER`] + the
/// body's `gas_budget`), the block's gas limit bounds how many can be bought
/// in one block, and this cap bounds how much work the pass itself may do
/// even if bodies spawn further sends. Hitting it stops the pass early
/// (defensively - the proposer-side block gas limit keeps honest blocks far
/// below it); leftovers drain in a later block, exactly like the round bound.
pub const MAX_ACTOR_MSGS_PER_BLOCK: usize = 4_096;

/// The encoded `body` of an actor message: the program a delivered message
/// runs, plus the fuel the sender prepaid for it.
///
/// `ActorMessage::body` is an opaque `Vec<u8>` (the struct is bincode'd into
/// node snapshots, so its layout must not grow), which is why the two fields
/// the mailbox needs are packed into it with bincode here rather than added
/// to `ActorMessage`. Round-trips are exact: the bytes are produced and
/// consumed by this same node, never by a counterparty.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActorSendBody {
    /// Program executed at delivery, with the recipient as the acting account.
    pub program: Vec<crate::svm::OpCode>,
    /// Fuel prepaid by the sender; also the delivery VM's gas limit.
    pub gas_budget: u64,
}

/// The block-clock inputs a delivered actor body's VM run needs: the block
/// timestamp (never local wall time) plus the two governed staking parameter
/// floors a `VmContext` carries (unreachable for a body today - staking is
/// not wired into the delivery context - but non-optional fields).
struct DeliveryCtx {
    timestamp: u64,
    min_validator_bond: u64,
    default_commission_bps: u64,
}

/// Pack a send into the bytes `ActorMessage::body` carries.
fn encode_actor_body(program: &[crate::svm::OpCode], gas_budget: u64) -> Vec<u8> {
    bincode::serialize(&ActorSendBody {
        program: program.to_vec(),
        gas_budget,
    })
    // Serialization of this struct cannot fail (fixed ints plus a Vec of
    // unit-like enums), exactly like the transaction envelope's own bincode.
    .expect("actor body serializes")
}

/// Unpack the bytes a queued message carries; anything else is a delivery
/// failure for that message (it bounces - it is never half-delivered).
fn decode_actor_body(bytes: &[u8]) -> Result<ActorSendBody, String> {
    bincode::deserialize(bytes).map_err(|e| format!("actor body does not decode: {e}"))
}

/// Pre-state of every account one actor-message delivery touched, taken the
/// first time it is touched and replayed in reverse if the delivery fails.
///
/// The design's per-message snapshot (recipient + sender) generalized to a
/// lazy touched-set: a body can also move value to third parties through
/// `Transfer` or a nested send, and THOSE must roll back with the message too
/// - "failed body leaves no partial effect" is only true if the snapshot
/// covers everything the body reached. `None` = the account did not exist
/// before (a delivery may create one by transferring to it; undo removes it).
#[derive(Default)]
struct MessageUndo {
    prev: HashMap<[u8; 32], Option<AccountState>>,
}

impl MessageUndo {
    /// Record `addr`'s pre-state, once, BEFORE it is mutated. Repeated calls
    /// are no-ops, so the FIRST pre-state - the state before this message's
    /// delivery began - is what an undo restores, which is exactly
    /// "walk the undo newest-first back to the original".
    fn note(&mut self, map: &HashMap<[u8; 32], AccountState>, addr: [u8; 32]) {
        self.prev.entry(addr).or_insert_with(|| map.get(&addr).cloned());
    }

    /// Put every touched account back where it was before this message.
    fn rollback(&self, map: &mut HashMap<[u8; 32], AccountState>) {
        for (addr, prev) in &self.prev {
            match prev {
                Some(acc) => {
                    map.insert(*addr, acc.clone());
                }
                None => {
                    map.remove(addr);
                }
            }
        }
    }
}

/// Record `addr`'s pre-state once, before it is mutated - the settlement-side
/// twin of [`MessageUndo::note`], kept as a free function so the borrow of
/// `map` ends with the call instead of spanning the mutations that follow.
/// An address absent from the map records nothing (settlement never creates
/// accounts), which is exactly its rollback state.
fn note_account_before(
    map: &HashMap<[u8; 32], AccountState>,
    snapshot: &mut Vec<([u8; 32], AccountState)>,
    noted: &mut HashSet<[u8; 32]>,
    addr: [u8; 32],
) {
    if noted.insert(addr) {
        if let Some(acc) = map.get(&addr) {
            snapshot.push((addr, acc.clone()));
        }
    }
}

fn default_account_scheme() -> crate::post_quantum::PqScheme {
    crate::post_quantum::PqScheme::Ed25519
}

/// Actor representing an Account or Smart Contract state
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountState {
    pub address: [u8; 32],
    pub balance: u64,
    pub nonce: u64,
    pub code: Vec<u8>,
    pub code_hash: Option<CellHash>,
    pub storage_root: Option<CellHash>,
    pub inbox: VecDeque<ActorMessage>,
    pub outbox: VecDeque<ActorMessage>,
    #[serde(default = "default_account_scheme")]
    pub scheme: crate::post_quantum::PqScheme,
    #[serde(default)]
    pub pubkey_hash: Option<[u8; 32]>,
}

impl AccountState {
    pub fn new(address: [u8; 32], initial_balance: u64) -> Self {
        Self {
            address,
            balance: initial_balance,
            nonce: 0,
            code: Vec::new(),
            code_hash: None,
            storage_root: None,
            inbox: VecDeque::new(),
            outbox: VecDeque::new(),
            scheme: crate::post_quantum::PqScheme::Ed25519,
            pubkey_hash: None,
        }
    }

    /// Push an incoming actor message into this account's inbox.
    pub fn push_inbox(&mut self, msg: ActorMessage) {
        self.inbox.push_back(msg);
    }

    /// Serializes the account state into the canonical trie leaf data format:
    /// - 16 bytes for dormant / unpinned accounts (balance || nonce)
    /// - 49 bytes for post-quantum pinned accounts (balance || nonce || scheme_id || pubkey_hash)
    pub fn to_trie_bytes(&self) -> Vec<u8> {
        if let Some(h) = self.pubkey_hash {
            let mut data = Vec::with_capacity(crate::cpat2::ACCOUNT_LEAF_LEN_PQ);
            data.extend_from_slice(&self.balance.to_be_bytes());
            data.extend_from_slice(&self.nonce.to_be_bytes());
            data.push(self.scheme.id());
            data.extend_from_slice(&h);
            data
        } else {
            let mut data = Vec::with_capacity(crate::cpat2::ACCOUNT_LEAF_LEN_LEGACY);
            data.extend_from_slice(&self.balance.to_be_bytes());
            data.extend_from_slice(&self.nonce.to_be_bytes());
            data
        }
    }
}

/// State Rent Surcharge gas for PQ activation transactions.
///
/// Canonical definition lives in [`crate::mempool::PQ_ACTIVATION_SURCHARGE_GAS`];
/// this re-export keeps `state_engine::PQ_ACTIVATION_SURCHARGE_GAS` resolving to
/// the same value so the admission check and the state application cannot drift.
pub use crate::mempool::PQ_ACTIVATION_SURCHARGE_GAS;

/// In-Memory Hot State Engine with Actor Model
#[derive(Clone)]
pub struct InMemoryStateEngine {
    pub accounts: Arc<RwLock<HashMap<[u8; 32], AccountState>>>,
    /// This node's chain id, compared against a session grant's `chain_id` at
    /// the consensus authorization check (`session_gate_with`). The grant's
    /// domain separator already BINDS `chain_id`, so a grant is unambiguous
    /// between chains; this field is what makes the node actually REJECT a
    /// grant minted for a different chain instead of merely being unable to
    /// replay it. Node-local policy: it is never folded into the state
    /// commitment, so two chains with identical state root identically.
    ///
    /// Defaults to [`crate::zkml::DEFAULT_CHAIN_ID`]; `with_chain_id` overrides.
    pub chain_id: u64,
    pub state_trie: Arc<RwLock<PatriciaTrie>>,
    /// On-chain fungible token registry (STS standard).
    ///
    /// PRIVATE on purpose: obtain a read guard through `tokens_read` or a write
    /// guard through `tokens_write` (which bumps `commitment_generation`).
    tokens: Arc<RwLock<TokenRegistry>>,
    /// On-chain orderbook (CLOB) registry: pair -> orderbook actor. Part of
    /// consensus state so orders/trades are deterministic across nodes.
    orderbooks: Arc<RwLock<crate::orderbook::OrderbookManager>>,
    /// On-chain WASM contract registry (validated, fuel-metered execution).
    contracts: Arc<RwLock<crate::contract::ContractRegistry>>,
    /// On-chain primary market maker (bonding curve). Minted STELL is real
    /// native balance; the USDT side is the bridged wUSDT token.
    pmm: Arc<RwLock<crate::pmm::PrimaryMarketMaker>>,
    /// Token id of the bridged USDT used as the PMM's quote asset.
    pmm_usdt_token: Arc<RwLock<Option<[u8; 32]>>>,
    /// Address holding the PMM's wUSDT liquidity (quote reserve). Buyers pay
    /// INTO this address, sellers are paid OUT of it. It is also the wUSDT
    /// minter so it can burn/mint against deposits/withdrawals.
    pmm_treasury: Arc<RwLock<[u8; 32]>>,
    /// Escrow for active resting limit orders on the CLOB: (pair_id, order_id) -> EscrowRecord
    order_escrow: Arc<RwLock<HashMap<(u32, u64), EscrowRecord>>>,
    /// On-chain governance: proposals, tallies and the applied parameters.
    ///
    /// Consensus-visible, so it lives here and is folded into the state commitment.
    /// It used to be a node-local `RpcState` field, which meant a node could apply a
    /// passed parameter change and its peer could not, with both still computing the
    /// same state root -- the split would only show up later, as a different validator
    /// set or block reward.
    governance: Arc<RwLock<crate::governance::Governance>>,
    /// On-chain staking ledger: bonds, delegations, unbonding, rewards.
    ///
    /// This lives INSIDE the state engine on purpose. It used to be a separate
    /// node-local lock shared with the RPC layer, which meant the validator set
    /// (derived from it at every height boundary) was whatever that one node
    /// had been told over RPC — two nodes could derive different sets and then
    /// never agree on a proposer. Consensus state has to be state.
    staking: Arc<RwLock<crate::staking::StakingLedger>>,
    /// Committed oracle state: trusted publishers, the latest signed feed per
    /// asset and the circuit-breaker latch.
    ///
    /// PRIVATE on purpose, like every other committed subsystem: reads go
    /// through `oracle_read`, mutations through `oracle_write` (which bumps
    /// `commitment_generation`). The only writer on the live path is the SVM's
    /// `SysCallSubmitPriceFeed`, executed while applying a BLOCK whose
    /// `timestamp` is passed down as the commit clock - never a wall clock.
    /// Gossip and RPC only ever get a feed in front of a proposer; a node that
    /// never saw the gossip derives identical state from the block alone.
    oracle: Arc<RwLock<crate::oracle::OracleState>>,
    /// On-chain session-key registry (phase 2): one record per session pubkey,
    /// holding the delegator, the copied grant ceilings, the CUMULATIVE gas
    /// spent by transactions that actually applied, and the terminal revocation
    /// flag.
    ///
    /// PRIVATE on purpose, like every other committed subsystem: reads go
    /// through `session_keys_read`, mutations through `session_keys_write`
    /// (which bumps `commitment_generation`). Lazy - a record appears when the
    /// first valid transaction under its grant applies, not when the grant is
    /// minted - and persisted in its own storage tree, deliberately NOT in
    /// `DomainSnapshot` (a new field there would stop every pre-phase-2 domain
    /// snapshot from decoding, and its restore path hard-errors).
    session_keys: Arc<RwLock<crate::zkml::SessionKeyRegistry>>,
    /// §9 shielded (confidential) balance ledger: `balances`, the spent-input
    /// nullifier set and the burned fee total.
    ///
    /// PRIVATE on purpose, like every other committed subsystem: reads go
    /// through `confidential_read`, mutations through `confidential_write`
    /// (which bumps `commitment_generation`). The only writer on the live path
    /// is the SVM's `SysCallConfidentialTransfer`, applied to a CLONE that
    /// `execute_payload` commits back only when the whole transaction applied
    /// - so a reverted, out-of-gas or later-refused transaction leaves the
    /// shielded ledger byte-for-byte where it was.
    ///
    /// CONDITIONAL in the commitment: `commit_consensus_domains*` routes the
    /// digest through `commitment::commitment_digest_with_confidential`, whose
    /// confidential domain writes ZERO bytes while the state is empty. A chain
    /// that has never made a confidential transfer therefore keeps a
    /// byte-identical root, which is what lets this domain join the digest
    /// WITHOUT bumping `COMMITMENT_VERSION` or re-pinning the genesis KAT.
    confidential: Arc<RwLock<crate::crypto_privacy::ConfidentialState>>,
    /// §2 zkML model registry: `model_id -> (code/weights hash, weights)`.
    ///
    /// PRIVATE on purpose, like every other committed subsystem: reads go
    /// through `zkml_models_read`, mutations through `zkml_models_write`
    /// (which bumps `commitment_generation`). The writers on the live path
    /// are the SVM's `SysCallRegisterZkMlModel` (append-only insert) and
    /// `SysCallRegisterZkMlSpec` (append-only key attach) - read-only -
    /// `SysCallVerifyZkMlReexec` and `SysCallVerifyZkMlAttestation`, applied to a CLONE
    /// that `execute_payload` commits back only when the whole transaction
    /// applied - so a reverted, out-of-gas or later-refused transaction
    /// leaves the registry byte-for-byte where it was.
    ///
    /// CONDITIONAL in the commitment: `commit_consensus_domains*` routes the
    /// digest through
    /// `commitment::commitment_digest_with_confidential_and_zkml`, whose zkML
    /// domain writes ZERO bytes while the registry is empty. A chain that has
    /// never registered a model therefore keeps a byte-identical root, which
    /// is what lets this domain join the digest WITHOUT bumping
    /// `COMMITMENT_VERSION` or re-pinning the genesis KAT. No separate
    /// persistence tree this wave (same as the shielded ledger): the registry
    /// is consensus state in memory and under the root, and a restart drops
    /// it - both nodes drop the same state, so agreement is preserved but
    /// models must be re-registered. A disk tree is the follow-up.
    zkml_models: Arc<RwLock<crate::zkml::ZkMlModelRegistry>>,
    /// Bumped by every mutation of a committed subsystem.
    ///
    /// A write guard can only be obtained through the `*_write` accessors below,
    /// and each of those bumps this counter before handing the guard back. There
    /// is therefore no way to mutate a committed subsystem without bumping, which
    /// is precisely what makes the counter a sound hint for skipping the O(state)
    /// digest in `commit_consensus_domains_if_stale`.
    commitment_generation: Arc<std::sync::atomic::AtomicU64>,
    /// Generation at which the commitment digest was last written to the trie.
    /// Stored as `generation + 1` so the derived `Default` value (0) means
    /// "nothing committed yet" and the first root read always recomputes.
    committed_generation: Arc<std::sync::atomic::AtomicU64>,
    /// M2 cross-shard execution gate.
    ///
    /// False (the default, and the only value a single-shard engine ever has)
    /// keeps the pre-sharding transaction semantics exactly: every transaction
    /// credits its `to` account. A multi-shard process flips it on via
    /// [`InMemoryStateEngine::enable_cross_shard`] when a runtime is scoped to a
    /// shard, and then a transaction whose `source_shard != target_shard` debits
    /// the sender on the SOURCE without crediting the recipient locally; the
    /// destination credits the recipient from the committed
    /// [`crate::sharding::CrossShardMessage`] consumption record instead.
    cross_shard_enabled: Arc<std::sync::atomic::AtomicBool>,
    /// Process-shared finalized-header registry (C1 anchor). `None`
    /// (single-shard nodes, most tests) fails anchored verification CLOSED.
    /// Set once via [`InMemoryStateEngine::with_finalized_headers`]; same
    /// `Arc` as every shard runtime in the process. Outer `Arc` keeps the
    /// derived `Clone` working (a `RwLock` alone is not `Clone`).
    finalized_headers: Arc<
        std::sync::RwLock<
            Option<Arc<std::sync::RwLock<crate::sharding::FinalizedHeaderRegistry>>>,
        >,
    >,
    /// Replay-protection set for consumed inbound cross-shard messages.
    ///
    /// COMMITTED domain (audit F1): `commit_consensus_domains*` folds the
    /// sorted keys into the digest via `commitment::write_cross_shard_domain`
    /// (conditional on non-emptiness, so single-shard chains root identically
    /// to before). Every mutation bumps `commitment_generation` through the
    /// helpers below, so the root cache can never go stale behind a consume.
    /// It exists so the same message can never be credited twice, including by
    /// a direct state-engine application that bypassed the runtime's filter.
    cross_shard_consumed: Arc<RwLock<HashSet<crate::sharding::CrossShardKey>>>,
    /// Engine mirror of produced outbound transfers: tx hash -> producing
    /// block height (first height wins, like the runtime's `or_insert`).
    ///
    /// COMMITTED alongside `cross_shard_consumed` (same conditional domain):
    /// the produce height decides the timeout-bounce linkage, so hashes alone
    /// would under-commit. Derived deterministically from applied blocks (same
    /// predicate as the runtime: transfer + outbound for the block's shard),
    /// so two nodes that applied the same chain hold the same map and derive
    /// the same root. Empty (and root-identical to before) on single-shard
    /// chains, where the cross-shard gate never opens.
    cross_shard_produced: Arc<RwLock<HashMap<[u8; 32], u64>>>,
    /// Engine mirror of completed lifecycles: tx hashes whose ack or bounce
    /// committed on this chain.
    ///
    /// COMMITTED alongside `cross_shard_consumed` (same conditional domain):
    /// completion decides whether the next ack/bounce for the same lifecycle
    /// applies. Derived deterministically from applied blocks with the same
    /// linkage rule the runtime enforces (proof-less control record, known
    /// produced entry, not already complete, bounce past timeout), processed
    /// in the same deterministic key order - so a synced node that installs
    /// the snapshot blob and a live node that applied the blocks agree byte
    /// for byte. No value movement here: the transfer credit stays in
    /// `apply_cross_shard_consumptions` and the bounce refund stays in the
    /// runtime; this set only records, never pays.
    cross_shard_completed: Arc<RwLock<HashSet<[u8; 32]>>>,
    /// §9 CROSS-SHARD 2PC: the per-transfer two-phase-commit state this
    /// shard owns, keyed by the transaction hash (the stable identity of the
    /// transfer across every phase and on every shard).
    ///
    /// COMMITTED domain (same conditional digest domain as the three sets
    /// above): the phase decides the DECISION of a transfer — whether the
    /// escrow is released or refunded on the source, whether the recipient is
    /// credited or not on the target. Two nodes that disagree about a phase
    /// disagree about who owns the value, so the phase must move the state
    /// root exactly as re-applying the deciding block would.
    ///
    /// The state is ALSO written into the state trie as one leaf per
    /// transfer (see [`crate::xshard2pc::xpc_state_key`]), because the peer
    /// shard proves its vote (PREPARE-ACK / ABORT-ACK) against a Merkle proof
    /// of that leaf at its committed state root.
    cross_shard_xpc: Arc<RwLock<HashMap<[u8; 32], crate::xshard2pc::XpcRecord>>>,
    /// Committed bridge domain: the §8 policy state behind
    /// `OpCode::SysCallBridge` - the source-tx replay set, the parked
    /// withdrawal queue, the hourly rate-limit window and the escrow mirror.
    ///
    /// PRIVATE on purpose, like every other committed subsystem: reads go
    /// through `bridge_read`, mutations through `bridge_write` (which bumps
    /// `commitment_generation`). The only writer on the live path is
    /// `settle_bridge_native`, reached from `execute_payload` while applying a
    /// BLOCK whose `timestamp` is the rate-limit/clock source - never a wall
    /// clock. Gossip and RPC only ever deliver a payload to a proposer; a node
    /// that never saw it derives identical state from the block alone.
    ///
    /// CONDITIONAL in the commitment (see `commitment.rs`): an untouched
    /// domain writes ZERO digest bytes, so the pinned genesis root - and
    /// `COMMITMENT_VERSION` - stay put; the moment a deposit or withdrawal
    /// lands, the whole domain is folded in and two nodes cannot disagree
    /// about a replayed source tx or a parked withdrawal under one root.
    bridge: Arc<RwLock<crate::bridge::BridgeState>>,
    /// Flag enabling disjoint wave parallel block execution.
    pub parallel_exec: Arc<std::sync::atomic::AtomicBool>,
    /// Persistent storage tree for raw post-quantum public keys (`pq_keys`).
    pub pq_tree: Arc<std::sync::RwLock<Option<sled::Tree>>>,
    /// Underlying sled database handle if attached.
    pub pq_db: Arc<std::sync::RwLock<Option<sled::Db>>>,
    /// In-memory fallback map for pinned keys when sled is unconfigured.
    ///
    /// PHASE 1 (memory audit): BOUNDED LRU (`STELL_MAX_PQ_FALLBACK_ENTRIES`,
    /// default 65536) with throttled-warn eviction. Reads prefer the sled
    /// tree whenever attached and never consult this map then, so `pin_pubkey`
    /// skips it in that case (it used to double every key in RAM for nothing).
    /// When sled is unconfigured this map is the ONLY store (fail-open reads,
    /// never fail-closed); size it for tests / diskless nodes only.
    pq_keys_fallback:
        Arc<std::sync::RwLock<memory_bounds::BoundedLruCache<[u8; 32], (crate::post_quantum::PqScheme, Vec<u8>)>>>,
    /// F-01 consensus D2 penalty mirror: sender -> extra floor added to the
    /// consensus base for their next transactions. Updated ONLY from applied
    /// block verdicts (end of `apply_block_parallel_fees`), so every node
    /// that applied the same chain holds the same map. MIRROR of the
    /// mempool-local `failed_penalty` (`mempool.rs::note_apply_feedback`):
    /// same step (`FAILED_SENDER_PENALTY`), same cap
    /// (`MAX_FAILED_SENDER_PENALTY`), same fail-only-grow / success-clear /
    /// mixed-keep rule. The mempool copy stays admission-local (live path
    /// only); THIS copy is what consensus charges, on every apply path.
    consensus_penalty: Arc<RwLock<HashMap<[u8; 32], u64>>>,
    /// Local shard id this state engine is assigned to (defaults to MASTERCHAIN_SHARD = 0).
    pub shard_id: Arc<std::sync::atomic::AtomicU32>,
    /// The node's SHARD TOPOLOGY: the active shard set, who owns which
    /// account, and the split/merge trigger state.
    ///
    /// Node-local configuration, like `shard_id` itself: the topology is a
    /// property of the NETWORK LAYOUT (which shard holds which address
    /// range), not of this shard's consensus state, so it is deliberately
    /// NOT folded into the state commitment — two nodes that disagree about
    /// the topology disagree about ROUTING, and that disagreement shows up
    /// as a cross-shard message that never arrives, not as a state-root
    /// mismatch.
    ///
    /// The topology is the single source of truth of the address→shard rule
    /// (see `crate::sharding::ROUTING_RULE`): the RPC layer, the SVM's
    /// cross-shard routing and the shard-id checks all read it from here.
    pub shard_topology: Arc<RwLock<crate::sharding::ShardTopology>>,
    /// Outbound cross-shard messages emitted during execution (e.g. cross-shard contract calls).
    pub cross_shard_out: Arc<RwLock<Vec<crate::sharding::CrossShardMessage>>>,
}

impl std::fmt::Debug for InMemoryStateEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryStateEngine")
            .field("chain_id", &self.chain_id)
            .finish()
    }
}

/// Escrow record locking funds for an active resting limit order in the CLOB.
///
/// Exactly one of the three locked fields is non-zero for a well-formed record,
/// because an order is one side of one pair:
///
/// * a resting SELL locks base STELL (`locked_base_stell`), whichever path
///   placed it;
/// * a resting BUY placed through `place_order_settled` locks its quote in
///   wUSDT (`locked_quote_wusdt`, burned at lock and minted back on release);
/// * a resting BUY placed through the SVM's `SysCallPlaceOrder` locks its
///   quote in native nano-STELL (`locked_quote_native`, debited at lock and
///   credited back on release) - the VM prices its `order_cost` in the
///   sender's native balance, so that is the asset the lock has to be in.
///
/// The settlement releases whichever asset was locked, to the counterparty,
/// so a record can never pay out in an asset nobody deposited.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowRecord {
    pub trader: [u8; 32],
    pub locked_base_stell: u64,
    pub locked_quote_wusdt: u64,
    /// Quote locked in native units for a BUY placed through the SVM path
    /// (`order_cost` = price * amount / 1_000_000, in nano-STELL).
    pub locked_quote_native: u64,
}

/// Which quote convention a CLOB placement settles under.
///
/// The two live entry points price the quote leg differently, and the
/// settlement core honours whichever one is calling it:
///
/// * `Wusdt` - `place_order_settled`: quote is wUSDT micro-units
///   (`price * amount / 1e9`), locked by burning the buyer's wUSDT.
/// * `NativeSvm` - the `SysCallPlaceOrder` syscall: quote is native
///   nano-STELL (`order_cost` = `price * amount / 1e6`), locked by debiting
///   the buyer's account. The VM only knows the sender's native balance, so
///   that is the asset its affordability check prices.
///
/// A maker's OWN escrow overrides the convention: whoever locked wUSDT pays
/// out wUSDT, whoever locked native pays native - a record can only ever
/// release the asset that was deposited into it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClobQuoteMode {
    Wusdt,
    NativeSvm,
}

impl ClobQuoteMode {
    /// The quote value of `base_nano` nano-STELL at `price_micro` under this
    /// convention. The two conventions are NOT convertible into each other
    /// here: each one prices the asset its own caller settles in, and a
    /// settlement only ever debits and credits the SAME convention, so value
    /// is conserved inside a trade.
    fn quote(self, price_micro: u64, base_nano: u64) -> u64 {
        match self {
            // wUSDT micro-units: (USD price * STELL) / 1e9.
            ClobQuoteMode::Wusdt => {
                let prod = (price_micro as u128) * (base_nano as u128);
                (prod / 1_000_000_000u128).min(u64::MAX as u128) as u64
            }
            // Native nano-STELL, calculated in u128 before dividing by 1,000,000
            // to prevent u64::MAX saturation on normal token trades.
            ClobQuoteMode::NativeSvm => {
                let prod = (price_micro as u128) * (base_nano as u128);
                (prod / 1_000_000u128).min(u64::MAX as u128) as u64
            }
        }
    }
}

/// One native STELL movement a settlement has decided on.
///
/// Applied under the accounts write lock with an undo log, BEFORE the staged
/// token and escrow state is committed, so a movement that cannot be funded
/// aborts the whole settlement with nothing changed anywhere.
enum NativeMove {
    Debit([u8; 32], u64),
    Credit([u8; 32], u64),
}

/// What one block transition did, as reported by
/// [`InMemoryStateEngine::apply_block_transition`].
///
/// The live consensus path and the reorg path record these same numbers into
/// their own bookkeeping (`ValidatorRuntime::applied_txs` /
/// `applied_statuses`, `ChainState::applied_txs` / `applied_statuses`), so the
/// two can be compared block by block - which is exactly what the differential
/// test does.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockTransitionOutcome {
    /// Transactions that were applied (admitted AND committed).
    pub applied: usize,
    /// Transactions that were rejected. `applied + failed == status.len()`.
    pub failed: usize,
    /// Fees actually collected from applied transactions and credited to the
    /// proposer in this transition.
    pub fees_collected: u64,
    /// Per-transaction success flags, in block order - the receipts vector.
    pub status: Vec<bool>,
    /// Per-transaction fee actually charged, in block order (parallel to
    /// `status`; the F-01 failure fee — floor or 0 — for failed transactions,
    /// never a fee that was not debited) - the receipts' `fee_charged`.
    pub tx_fees: Vec<u64>,
    /// Nano-STELL burned by slashing in this block's transition: the
    /// downtime slash of this block's certificate plus the equivocation
    /// slash of its block-carried evidence.
    pub slashed: u64,
    /// Per-transaction emitted contract events, in block order.
    pub events: Vec<Vec<crate::contract::ContractEvent>>,
}


/// Namespaced trie key for a token balance: sha256("STS_BAL" || token_id || account)
/// This commits token balances into the same state root as native STELL balances,
/// enabling SPV Merkle proofs for token holdings.
pub fn token_balance_key(token_id: &[u8; 32], account: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"STS_BAL");
    hasher.update(token_id);
    hasher.update(account);
    hasher.finalize().into()
}

/// Namespaced trie key for a token's total supply: sha256("STS_SUPPLY" || token_id)
pub fn token_supply_key(token_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"STS_SUPPLY");
    hasher.update(token_id);
    hasher.finalize().into()
}

/// Namespaced trie key committing a contract's code hash: sha256("STELL_CONTRACT_CODE" || addr)
pub fn contract_key(address: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"STELL_CONTRACT_CODE");
    hasher.update(address);
    hasher.finalize().into()
}

/// Namespaced trie key committing a contract's ABI manifest:
/// sha256("STELL_CONTRACT_ABI" || addr). The manifest is stored next to the
/// code hash so a client can discover the typed interface of a contract from
/// the state root alone.
pub fn contract_abi_key(address: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"STELL_CONTRACT_ABI");
    hasher.update(address);
    hasher.finalize().into()
}

/// Compute deterministic contract address following TON StateInit / BLAKE3 model:
/// BLAKE3("STELL_CONTRACT" || code_hash || salt)
pub fn compute_contract_address(code_hash: &[u8; 32], salt: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"STELL_CONTRACT");
    hasher.update(code_hash);
    hasher.update(salt);
    *hasher.finalize().as_bytes()
}

/// Structured outcome of a contract deployment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeployOutcome {
    pub contract_address: [u8; 32],
    pub contract_address_stl57: String,
    pub code_hash: [u8; 32],
}

/// Structured outcome of a contract call (Near receipt / TON observable outcome model).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractCallOutcome {
    pub status: String,
    pub return_value: Option<i64>,
    pub gas_used: u64,
    pub events: Vec<crate::contract::ContractEvent>,
    pub error: Option<String>,
}

/// Write every deployed contract's code hash into the Patricia trie so contract
/// existence is part of the state root and SPV-provable.
///
/// A contract's ABI manifest is committed next to its code hash.
fn write_contract_trie_entries(trie: &mut PatriciaTrie, contracts: &crate::contract::ContractRegistry) {
    for (addr, c) in &contracts.contracts {
        trie.insert(&contract_key(addr), &c.code_hash);
        match &c.abi {
            Some(abi) => {
                trie.insert(&contract_abi_key(addr), abi.to_json().as_bytes());
            }
            None => {
                trie.remove(&contract_abi_key(addr));
            }
        }
    }
}

/// Write every token balance + total supply into the Patricia trie.
/// Used on restore to keep the trie consistent with the token registry.
fn write_token_trie_entries(trie: &mut PatriciaTrie, tokens: &TokenRegistry) {
    for (id, token) in &tokens.tokens {
        for (acct, bal) in &token.balances {
            let key = token_balance_key(id, acct);
            if *bal == 0 {
                trie.remove(&key);
            } else {
                trie.insert(&key, &bal.to_be_bytes());
            }
        }
        trie.insert(&token_supply_key(id), &token.metadata.total_supply.to_be_bytes());
    }
}

/// Roll the oracle back after a failed payload, preserving only the breaker
/// latch.
///
/// The VM writes the oracle in place (it is the one domain whose failure mode
/// has to survive its own transaction), so `execute_payload` restores the
/// pre-payload snapshot on every failure path - a revert must not leave a
/// committed price behind. The EXCEPTION is `breaker_tripped`: a gate that
/// fired (depeg, deviation) keeps the alarm even though its transaction rolled
/// back, because a circuit breaker that silences itself when the attack fails
/// is not a circuit breaker. Both directions are deterministic: the same block
/// produces the same restore on every node.
fn restore_oracle_after_failure(
    oracle: &mut crate::oracle::OracleState,
    before: Option<crate::oracle::OracleState>,
) {
    let Some(before) = before else {
        return;
    };
    let latched = oracle.breaker_tripped;
    *oracle = before;
    oracle.breaker_tripped |= latched;
}

/// Rollback record for one applied bridge settlement: the pre-change native
/// balances AND the pre-change committed bridge domain, so a failure after the
/// bridge leg can undo the coins and the policy state together (a leftover
/// replay-set entry or phantom withdrawal would be consensus-visible state
/// belonging to a payload that never applied).
struct BridgeSnapshot {
    accounts: Vec<([u8; 32], Option<(u64, u64)>)>,
    domain: crate::bridge::BridgeState,
}

/// Rollback record for one applied actor-send settlement: the pre-change
/// balance AND inbox of every account the settlement touched.
///
/// The same shape and the same purpose as [`BridgeSnapshot`]: an actor send
/// debits the sender and enqueues the message INSIDE `execute_payload`, so a
/// failure of any later settlement step (the CLOB escrow runs after it) must
/// take the coins AND the queued message back together - a message left in an
/// inbox after its transaction was refused would deliver value nobody paid
/// for, and a debit left behind would charge for a payload that never
/// applied. The trie never sees the debit (only `commit_native` writes the
/// sender's balance, and only for transactions that commit), so restoring the
/// account map is the whole rollback.
struct ActorSnapshot {
    accounts: Vec<([u8; 32], AccountState)>,
}

impl Default for InMemoryStateEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Pre-execution snapshot of every consensus domain the payload path can
/// mutate (B1 atomicity). On ANY failure after the VM ran — including a
/// `commit_native` refusal in the caller — the caller restores from this,
/// so a rejected transaction leaves literally nothing behind: no free
/// validator bond, no free mint, no half-settled bridge/actor/PMM legs.
/// Domains with their own snapshot/rollback (bridge, actor, PMM-native,
/// oracle, books) keep it; this covers the ones that had none (tokens,
/// contracts, orderbooks, escrow, PMM curve, staking). Session,
/// confidential and zkML ride as working copies committed on success and
/// are restored from their `*_before` clones the same way.
struct PayloadDomainSnapshot {
    tokens: Option<crate::token::TokenRegistry>,
    contracts: Option<crate::contract::ContractRegistry>,
    orderbooks: Option<crate::orderbook::OrderbookManager>,
    order_escrow: Option<std::collections::HashMap<(u32, u64), EscrowRecord>>,
    pmm: Option<crate::pmm::PrimaryMarketMaker>,
    staking: Option<crate::staking::StakingLedger>,
    oracle: Option<crate::oracle::OracleState>,
    session_keys: Option<crate::zkml::SessionKeyRegistry>,
    confidential: Option<crate::crypto_privacy::ConfidentialState>,
    zkml_models: Option<crate::zkml::ZkMlModelRegistry>,
}

/// Account-level undo records created DURING execution, returned to the
/// caller so a `commit_native` failure can roll back settlement legs
/// (bridge/actor/PMM-native) that wrote the accounts map directly.
pub struct ExecPostActions {
    bridge_snapshot: Option<BridgeSnapshot>,
    actor_snapshot: Option<ActorSnapshot>,
    pmm_native_snapshot: Vec<([u8; 32], Option<(u64, u64)>)>,
    clob_native_snapshot: Vec<([u8; 32], Option<(u64, u64)>)>,
}

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
) -> PlainTxPlan {
    let mut plan = PlainTxPlan::default();

    if !admitted {
        // Refused at ADMISSION: it never ran, so it pays nothing and
        // consumes no nonce.
        return plan;
    }

    // F-01: never execute below the floor. The success fee is the declared
    // limit raised to the floor; a failure pays the same floor (plus the
    // PQ surcharge, which is 0 for a plain transaction).
    let fee = tx.gas_limit.max(floor_base);
    let fail_fee = fee.saturating_add(surcharge);

    // A live session-gate refusal is attributable: the floor is charged and
    // the nonce is consumed (the sequential path's `fail_with_floor!`).
    if tx.delegation().is_some() && !session_ok {
        if let Some((debited, balance, nonce)) = failure_fee_state(tx, sender, fail_fee) {
            plan.fee = debited;
            plan.writes.push((tx.from, balance, nonce));
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
        plan.writes.push((tx.from, balance.saturating_sub(fee), nonce + 1));
        return plan;
    }

    plan.writes.push((tx.from, balance.saturating_sub(total_cost), nonce + 1));

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
                    if let Some((debited, balance, nonce)) =
                        failure_fee_state(tx, sender, fail_fee)
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

#[allow(dead_code)]
struct WaveItemExec {
    idx: usize,
    ok: bool,
    transfers: Vec<([u8; 32], u64)>,
    payouts: Vec<([u8; 32], [u8; 32], u64)>,
    /// Native coins the payload BURNED (`(account, amount)`) - the post-quantum
    /// equivocation slash's burn out of the staking pool. MUST reach
    /// `commit_native` together with `transfers`/`payouts`: a burn dropped
    /// here would slash the ledger without taking the coins out of the pool
    /// (pool/ledger drift by the burnt amount).
    burns: Vec<([u8; 32], u64)>,
    gas_used: u64,
    domain_snap: Option<PayloadDomainSnapshot>,
    post_actions: Option<ExecPostActions>,
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
            pmm_usdt_token: Arc::new(RwLock::new(None)),
            pmm_treasury: Arc::new(RwLock::new([0u8; 32])),
            order_escrow: Arc::new(RwLock::new(HashMap::new())),
            staking: Arc::new(RwLock::new(crate::staking::StakingLedger::new())),
            governance: Arc::new(RwLock::new(crate::governance::Governance::new())),
            oracle: Arc::new(RwLock::new(crate::oracle::OracleState::default())),
            session_keys: Arc::new(RwLock::new(crate::zkml::SessionKeyRegistry::default())),
            confidential: Arc::new(RwLock::new(
                crate::crypto_privacy::ConfidentialState::new(),
            )),
            zkml_models: Arc::new(RwLock::new(crate::zkml::ZkMlModelRegistry::default())),
            commitment_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            committed_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
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
            shard_id: Arc::new(std::sync::atomic::AtomicU32::new(crate::sharding::MASTERCHAIN_SHARD)),
            shard_topology: Arc::new(RwLock::new(crate::sharding::ShardTopology::new())),
            cross_shard_out: Arc::new(RwLock::new(Vec::new())),
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
        let pmm_usdt_token = self.pmm_usdt_token.read().await.clone();
        let pmm_treasury = *self.pmm_treasury.read().await;
        let order_escrow = self.order_escrow.read().await.clone();
        let staking = self.staking.read().await.clone();
        let governance = self.governance.read().await.clone();
        let oracle = self.oracle.read().await.clone();
        let session_keys = self.session_keys.read().await.clone();
        let confidential = self.confidential.read().await.clone();
        let zkml_models = self.zkml_models.read().await.clone();
        let cross_shard_consumed = self.cross_shard_consumed.read().await.clone();
        let cross_shard_produced = self.cross_shard_produced.read().await.clone();
        let cross_shard_completed = self.cross_shard_completed.read().await.clone();
        let cross_shard_xpc = self.cross_shard_xpc.read().await.clone();
        let bridge = self.bridge.read().await.clone();
        let consensus_penalty = self.consensus_penalty.read().await.clone();

        let pq_tree = self.pq_tree.read().unwrap().clone();
        let pq_db = self.pq_db.read().unwrap().clone();
        let pq_keys_fallback = self.pq_keys_fallback.read().unwrap().clone();

        Self {
            accounts: Arc::new(RwLock::new(accounts)),
            chain_id: self.chain_id,
            state_trie: Arc::new(RwLock::new(state_trie)),
            tokens: Arc::new(RwLock::new(tokens)),
            orderbooks: Arc::new(RwLock::new(orderbooks)),
            contracts: Arc::new(RwLock::new(contracts)),
            pmm: Arc::new(RwLock::new(pmm)),
            pmm_usdt_token: Arc::new(RwLock::new(pmm_usdt_token)),
            pmm_treasury: Arc::new(RwLock::new(pmm_treasury)),
            order_escrow: Arc::new(RwLock::new(order_escrow)),
            staking: Arc::new(RwLock::new(staking)),
            governance: Arc::new(RwLock::new(governance)),
            oracle: Arc::new(RwLock::new(oracle)),
            session_keys: Arc::new(RwLock::new(session_keys)),
            confidential: Arc::new(RwLock::new(confidential)),
            zkml_models: Arc::new(RwLock::new(zkml_models)),
            commitment_generation: Arc::new(std::sync::atomic::AtomicU64::new(
                self.commitment_generation.load(std::sync::atomic::Ordering::Relaxed),
            )),
            committed_generation: Arc::new(std::sync::atomic::AtomicU64::new(
                self.committed_generation.load(std::sync::atomic::Ordering::Relaxed),
            )),
            cross_shard_enabled: Arc::new(std::sync::atomic::AtomicBool::new(
                self.cross_shard_enabled.load(std::sync::atomic::Ordering::Relaxed),
            )),
            finalized_headers: Arc::new(std::sync::RwLock::new(None)),
            cross_shard_consumed: Arc::new(RwLock::new(cross_shard_consumed)),
            cross_shard_produced: Arc::new(RwLock::new(cross_shard_produced)),
            cross_shard_completed: Arc::new(RwLock::new(cross_shard_completed)),
            cross_shard_xpc: Arc::new(RwLock::new(cross_shard_xpc)),
            bridge: Arc::new(RwLock::new(bridge)),
            parallel_exec: Arc::new(std::sync::atomic::AtomicBool::new(
                self.parallel_exec.load(std::sync::atomic::Ordering::Relaxed),
            )),
            pq_tree: Arc::new(std::sync::RwLock::new(pq_tree)),
            pq_db: Arc::new(std::sync::RwLock::new(pq_db)),
            pq_keys_fallback: Arc::new(std::sync::RwLock::new(pq_keys_fallback)),
            consensus_penalty: Arc::new(RwLock::new(consensus_penalty)),
            shard_id: Arc::new(std::sync::atomic::AtomicU32::new(
                self.shard_id.load(std::sync::atomic::Ordering::Relaxed),
            )),
            shard_topology: Arc::new(RwLock::new(
                self.shard_topology.read().await.clone(),
            )),
            cross_shard_out: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Attach persistent storage tree for post-quantum public keys.
    pub fn attach_pq_tree(&self, tree: sled::Tree) {
        *self.pq_tree.write().unwrap() = Some(tree);
    }

    /// Attach an external sled DB and use its `pq_keys` tree for persistent public key storage.
    pub fn attach_pq_storage(&self, db: &sled::Db) -> Result<(), sled::Error> {
        let tree = db.open_tree("pq_keys")?;
        self.attach_pq_tree(tree);
        *self.pq_db.write().unwrap() = Some(db.clone());
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

            let acc = map.entry(address).or_insert_with(|| AccountState::new(address, 0));
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

        if let Some(tree) = self.pq_tree.read().unwrap().as_ref() {
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
            tree.flush()
                .map_err(|e| format!("pq_keys flush failed: {e}"))?;
        }
        if self.pq_tree.read().unwrap().is_some() {
            // Disk is authoritative: reads prefer the tree and never consult
            // the fallback while attached, so populating it too would double
            // every key in RAM for nothing (memory audit #9).
        } else {
            // Sled unconfigured: the bounded LRU fallback is the ONLY store.
            // Eviction here is LOUD (throttled warn inside `insert`) and reads
            // fail open; size it for tests / diskless nodes only.
            self.pq_keys_fallback
                .write()
                .unwrap()
                .insert(address, (scheme, pubkey.to_vec()));
        }

        let _ = crate::sharding::Transaction::global_implicit_registry().register(
            address,
            scheme,
            pubkey,
            salt,
        );

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
        self.get_pinned_pubkey_with_salt(address).map(|(s, pk, _)| (s, pk))
    }

    /// Look up the pinned post-quantum scheme, raw public key, and salt for an account address.
    pub fn get_pinned_pubkey_with_salt(
        &self,
        address: &[u8; 32],
    ) -> Option<(crate::post_quantum::PqScheme, Vec<u8>, [u8; 16])> {
        // Read directly from pq_keys persistent tree (namespaced `a:` key,
        // with legacy 32-byte fallback for pre-prefix data dirs).
        if let Some(tree) = self.pq_tree.read().unwrap().as_ref() {
            let mut addr_key = Vec::with_capacity(34);
            addr_key.extend_from_slice(b"a:");
            addr_key.extend_from_slice(address);
            let bytes_opt = match tree.get(&addr_key) {
                Ok(Some(v)) => Some(v),
                Ok(None) => match tree.get(address) {
                    Ok(v) => v,
                    Err(_) => None,
                },
                Err(_) => None,
            };
            if let Some(bytes) = bytes_opt {
                if let Ok((scheme, pk, salt)) =
                    bincode::deserialize::<(crate::post_quantum::PqScheme, Vec<u8>, [u8; 16])>(&bytes)
                {
                    return Some((scheme, pk, salt));
                }
                if let Ok((scheme, pk)) =
                    bincode::deserialize::<(crate::post_quantum::PqScheme, Vec<u8>)>(&bytes)
                {
                    return Some((scheme, pk, crate::post_quantum::DEFAULT_SALT));
                }
                if bytes.len() > 1 {
                    if let Ok(scheme) = crate::post_quantum::PqScheme::from_id(bytes[0]) {
                        return Some((scheme, bytes[1..].to_vec(), crate::post_quantum::DEFAULT_SALT));
                    }
                }
            }
            return None;
        }

        // In-memory fallback when persistent sled tree is unconfigured.
        // `get` refreshes LRU recency (needs the write guard); a miss here is
        // fail-open `None`, never an error.
        if let Some((scheme, pk)) = self
            .pq_keys_fallback
            .write()
            .unwrap()
            .get(address)
        {
            return Some((scheme, pk, crate::post_quantum::DEFAULT_SALT));
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

    #[allow(dead_code)]
    async fn execute_wave_tx(
        &self,
        tx: &crate::sharding::Transaction,
        idx: usize,
        timestamp: u64,
        range_preverify: &HashMap<[u8; 32], bool>,
    ) -> WaveItemExec {
        if tx.payload.is_empty() {
            return WaveItemExec {
                idx,
                ok: true,
                transfers: Vec::new(),
                payouts: Vec::new(),
                burns: Vec::new(),
                gas_used: tx.gas_limit,
                domain_snap: None,
                post_actions: None,
            };
        }

        let map = self.accounts.read().await;
        let Some(sender) = map.get(&tx.from) else {
            return WaveItemExec {
                idx,
                ok: false,
                transfers: Vec::new(),
                payouts: Vec::new(),
                burns: Vec::new(),
                gas_used: 0,
                domain_snap: None,
                post_actions: None,
            };
        };
        if tx.nonce != sender.nonce {
            return WaveItemExec {
                idx,
                ok: false,
                transfers: Vec::new(),
                payouts: Vec::new(),
                burns: Vec::new(),
                gas_used: 0,
                domain_snap: None,
                post_actions: None,
            };
        }
        let Some(total) = tx.amount.checked_add(tx.gas_limit) else {
            return WaveItemExec {
                idx,
                ok: false,
                transfers: Vec::new(),
                payouts: Vec::new(),
                burns: Vec::new(),
                gas_used: 0,
                domain_snap: None,
                post_actions: None,
            };
        };
        if sender.balance < total {
            return WaveItemExec {
                idx,
                ok: false,
                transfers: Vec::new(),
                payouts: Vec::new(),
                burns: Vec::new(),
                gas_used: 0,
                domain_snap: None,
                post_actions: None,
            };
        }
        drop(map);

        if self.session_gate(tx, timestamp).await.is_err() {
            return WaveItemExec {
                idx,
                ok: false,
                transfers: Vec::new(),
                payouts: Vec::new(),
                burns: Vec::new(),
                gas_used: 0,
                domain_snap: None,
                post_actions: None,
            };
        }

        let domain_snap = Some(self.snapshot_payload_domains(&tx.payload).await);
        match self
            .execute_payload_with_preverify(tx, timestamp, Some(range_preverify))
            .await
        {
            Ok((
                crate::svm::VmExecutionResult::Success {
                    transfers,
                    payouts,
                    burns,
                    gas_used,
                    ..
                },
                actions,
            )) => WaveItemExec {
                idx,
                ok: true,
                transfers,
                payouts,
                burns,
                gas_used,
                domain_snap,
                post_actions: Some(actions),
            },
            Ok((crate::svm::VmExecutionResult::OutOfGas, _)) => WaveItemExec {
                idx,
                ok: false,
                transfers: Vec::new(),
                payouts: Vec::new(),
                burns: Vec::new(),
                gas_used: 0,
                domain_snap: None,
                post_actions: None,
            },
            Ok((crate::svm::VmExecutionResult::Reverted(_), _)) => WaveItemExec {
                idx,
                ok: false,
                transfers: Vec::new(),
                payouts: Vec::new(),
                burns: Vec::new(),
                gas_used: 0,
                domain_snap: None,
                post_actions: None,
            },
            Err(_) => {
                if let Some(snap) = domain_snap {
                    self.rollback_payload(
                        snap,
                        ExecPostActions {
                            bridge_snapshot: None,
                            actor_snapshot: None,
                            pmm_native_snapshot: Vec::new(),
                            clob_native_snapshot: Vec::new(),
                        },
                    )
                    .await;
                }
                WaveItemExec {
                    idx,
                    ok: false,
                    transfers: Vec::new(),
                    payouts: Vec::new(),
                    burns: Vec::new(),
                    gas_used: 0,
                    domain_snap: None,
                    post_actions: None,
                }
            }
        }
    }

    /// Set parallel block execution flag.
    pub fn set_parallel_exec(&self, enabled: bool) {
        self.parallel_exec.store(enabled, std::sync::atomic::Ordering::Release);
    }

    /// Check whether disjoint wave parallel execution is enabled.
    /// Gated by in-memory engine configuration or `STELL_PARALLEL_EXEC` env var.
    pub fn is_parallel_exec_enabled(&self) -> bool {
        self.parallel_exec.load(std::sync::atomic::Ordering::Acquire)
            || std::env::var("STELL_PARALLEL_EXEC")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false)
    }

    /// Builder method to enable/disable parallel execution.
    pub fn with_parallel_exec(self, enabled: bool) -> Self {
        self.set_parallel_exec(enabled);
        self
    }

    pub async fn get_account(&self, address: &[u8; 32]) -> Option<AccountState> {
        self.accounts.read().await.get(address).cloned()
    }

    pub async fn update_account(&self, state: AccountState) {
        let mut map = self.accounts.write().await;
        let mut trie = self.state_trie.write().await;

        let data = state.to_trie_bytes();
        trie.insert(&state.address, &data);
        map.insert(state.address, state);
    }

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
        self.execute_payload_with_preverify(tx, timestamp, None).await
    }

    /// Capture pre-execution state for exactly the domains this payload's
    /// opcodes can mutate (B1 atomicity). Plain transfers (empty payload)
    /// never call this: they touch no domain. Each clone is gated on the
    /// opcodes present so hot paths pay only for what they use.
    async fn snapshot_payload_domains(
        &self,
        payload: &[crate::svm::OpCode],
    ) -> PayloadDomainSnapshot {
        use crate::svm::OpCode::*;
        let mut touches_tokens = false;
        let mut touches_contracts = false;
        let mut touches_books = false;
        let mut touches_pmm = false;
        let mut touches_staking = false;
        let mut touches_oracle = false;
        let mut touches_session = false;
        let mut touches_conf = false;
        let mut touches_zkml = false;
        for op in payload {
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
                | SysCallUnbond { .. }
                | SysCallDelegate { .. }
                | SysCallUndelegate { .. }
                | SysCallBeginUndelegate { .. }
                | SysCallClaimRewards { .. }
                | SysCallClaimDelegatorRewards { .. }
                | SysCallWithdrawSelfBond { .. }
                | SysCallRotateValidatorKey { .. }
                // The PQ equivocation report SLASHES the ledger inside the VM
                // (it must: the verdict depends on the accused validator's
                // registered post-quantum key), so the ledger must be
                // snapshotted for rollback exactly like every other staking
                // opcode.
                | SysCallReportPqEquivocation { .. } => touches_staking = true,
                SysCallSubmitPriceFeed { .. } => touches_oracle = true,
                SysCallPublishSessionGrant { .. } | SysCallRevokeSession { .. } => {
                    touches_session = true
                }
                SysCallConfidentialTransfer { .. }
                | SysCallConfidentialTransfer2 { .. }
                | SysCallConfidentialShield { .. }
                | SysCallConfidentialUnshield { .. } => touches_conf = true,
                SysCallVerifyZkMl { .. }
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
            confidential: None,
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
        if touches_conf {
            snap.confidential = Some((*self.confidential_read().await).clone());
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
    async fn restore_payload_domains(&self, snap: PayloadDomainSnapshot) {        if let Some(v) = snap.tokens {
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
        if let Some(v) = snap.confidential {
            *self.confidential_write().await = v;
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
    async fn rollback_payload(
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
        self.restore_pmm_native(&actions.pmm_native_snapshot)
            .await;
        // Trie: drop touched keys, then re-add exactly what restored state holds.
        if !dead_keys.is_empty() {
            let mut trie = self.state_trie.write().await;
            for k in dead_keys {
                trie.remove(&k);
            }
        }
        self.sync_aux_trie().await;
    }

    /// Payload execution with an optional range-proof pre-verification cache
    /// (see [`Svm::execute_with_confidential_and_sends_with_preverify`]).
    ///
    /// `None` is the single-transaction path (`apply_transaction`, which calls
    /// through [`Self::execute_payload`]): it NEVER consults a cache and runs
    /// every check from scratch. `Some` is the block path
    /// (`apply_block_parallel_fees`), which hands over the verdict map its
    /// parallel pre-pass built — the handler still runs every state check
    /// (ownership, spent set, conservation, fees) and only skips re-verifying
    /// range proofs on a hit. Gas, settlement and commit behavior are identical
    /// either way: the cache only avoids recomputing a pure function.
    pub async fn execute_payload_with_preverify(
        &self,
        tx: &crate::sharding::Transaction,
        timestamp: u64,
        range_preverify: Option<&HashMap<[u8; 32], bool>>,
    ) -> Result<(crate::svm::VmExecutionResult, ExecPostActions), String> {
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
        if let Err(e) = self.session_gate(tx, timestamp).await {
            return Err(e);
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
            && tx.payload.iter().any(|op| {
                matches!(op, crate::svm::OpCode::SysCallActorSend { .. })
            })
        {
            return Err(
                "actor send rejected: cross-shard actor messages are not supported (v1 is \
                 single-shard only)"
                    .to_string(),
            );
        }

        if tx.payload.is_empty() {
            return Ok((crate::svm::VmExecutionResult::Success {
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
            }, ExecPostActions {
                bridge_snapshot: None,
                actor_snapshot: None,
                pmm_native_snapshot: Vec::new(),
                clob_native_snapshot: Vec::new(),
            }));
        }

        let sender_balance = self
            .get_account(&tx.from)
            .await
            .map(|a| a.balance)
            .unwrap_or(0);

        let mut tokens = Self::mut_guard(&self.commitment_generation, &self.tokens).await;
        let mut orderbooks = Self::mut_guard(&self.commitment_generation, &self.orderbooks).await;
        let mut contracts = Self::mut_guard(&self.commitment_generation, &self.contracts).await;
        let mut staking = Self::mut_guard(&self.commitment_generation, &self.staking).await;
        // The committed PMM, taken like the other domains: the VM advances the
        // curve through a clone of it (clone-commit, same as the staking
        // ledger) and the native leg below is settled while this guard is still
        // held, so the curve cannot move between "the swap was applied" and
        // "the coins moved".
        let mut pmm = Self::mut_guard(&self.commitment_generation, &self.pmm).await;
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
                crate::svm::OpCode::SysCallPmmBuy { .. } | crate::svm::OpCode::SysCallPmmSell { .. }
            )
        }) {
            pmm_before = Some(((*pmm).clone(), (*tokens).clone()));
        }
        // Oracle last: `commitment_snapshot` reads the subsystems in field
        // order starting at `tokens`, so taking the oracle only after every
        // other guard keeps lock acquisition ordered and a root read can never
        // deadlock against a payload in flight.
        let mut oracle = Self::mut_guard(&self.commitment_generation, &self.oracle).await;
        // Pre-payload snapshot of the oracle, for payloads that can touch it.
        // A failed payload must leave no committed price behind ("whole tx
        // rolls back"), while a breaker latch tripped by a gate inside that
        // same payload is a sticky alarm and survives its own transaction -
        // see `restore_oracle_after_failure`.
        let mut oracle_before = if tx.payload.iter().any(|op| {
            matches!(
                op,
                crate::svm::OpCode::SysCallSubmitPriceFeed(_)
                    | crate::svm::OpCode::SysCallPlaceOrder { .. }
            )
        }) {
            Some(oracle.clone())
        } else {
            None
        };

        // A payload with order syscalls commits its book changes inside the VM.
        // If escrow settlement then fails, the book has to go back exactly as it
        // was, or the transaction would leave precisely the orphan the escrow
        // exists to prevent: an order in the book whose funds were never locked.
        // Snapshot only for payloads that can produce events - plain transfers
        // must not pay for the clone.
        let mut books_before: Option<std::collections::HashMap<u32, crate::orderbook::OrderbookActor>> =
            None;
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
        let mut session_keys_work = if tx.payload.iter().any(|op| {
            matches!(
                op,
                crate::svm::OpCode::SysCallRevokeSession { .. }
            )
        }) {
            Some(self.session_keys.read().await.clone())
        } else {
            None
        };
        let session_keys_before = session_keys_work.clone();

        // §9 SHIELDED LEDGER, cloned in only for payloads that can touch it
        // (`SysCallConfidentialTransfer`) - the same clone-on-demand shape as
        // the session registry above, for the same two reasons: a revert /
        // out-of-gas / later settlement failure discards the transfer with
        // everything else (the working copy is written back ONLY on the SUCCESS
        // arm), and the 99.99% of payloads with no shielded opcode never take
        // the lock or pay for the clone. The VM mutates this copy in place
        // through `Svm::execute_with_confidential_and_sends`.
        let mut confidential_work = if tx.payload.iter().any(|op| {
            matches!(
                op,
                crate::svm::OpCode::SysCallConfidentialTransfer { .. }
                    | crate::svm::OpCode::SysCallConfidentialTransfer2 { .. }
                    | crate::svm::OpCode::SysCallConfidentialShield { .. }
                    | crate::svm::OpCode::SysCallConfidentialUnshield { .. }
            )
        }) {
            Some(self.confidential.read().await.clone())
        } else {
            None
        };
        let confidential_before = confidential_work.clone();

        // §2 MODEL REGISTRY, cloned in only for payloads that can touch it
        // (`SysCallVerifyZkMlReexec` / `SysCallVerifyZkMlAttestation` read it,
        // `SysCallRegisterZkMlModel` / `SysCallRegisterZkMlSpec` write it) -
        // the same clone-on-demand shape as the shielded ledger above, for
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
        // The shielded ledger rides in as `confidential_work` (a working COPY,
        // cloned above for payloads that carry the opcode): the handler applies
        // the transfer to the copy, and only the SUCCESS arm below writes it
        // back to the engine - so a revert, an out-of-gas or a failed escrow /
        // PMM / bridge settlement discards the transfer with everything else.
        //
        // `actor_send_sink` is the mirror image for §1: the VM has no account
        // map, so a `SysCallActorSend` can only be validated there (bounce
        // rule, prepaid delivery gas, affordability against the balance
        // mirror) and RECORDED here. `settle_actor_sends` below then moves the
        // coins and enqueues exactly what the run recorded - which is what
        // keeps a send after a `Halt` (never executed) from being settled off
        // the raw payload bytes. A payload with no actor send never allocates
        // anything measurable (the sink stays empty).
        let mut actor_send_sink: Vec<crate::svm::ActorSendRequest> = Vec::new();
        let res = crate::svm::Svm::execute_with_confidential_and_sends_with_preverify(
            &tx.payload,
            tx.gas_limit,
            &mut ctx,
            confidential_work.as_mut(),
            &mut actor_send_sink,
            zkml_models_work.as_mut(),
            range_preverify,
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
        let bridge_intents: Vec<crate::bridge::BridgeIntent> = tx
            .payload
            .iter()
            .filter_map(|op| match op {
                crate::svm::OpCode::SysCallBridge(intent) => Some((**intent).clone()),
                _ => None,
            })
            .collect();

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
                    Ok(snapshot) => pmm_native_snapshot = snapshot,
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
                let bridge_validators: Vec<[u8; 32]> =
                    staking.validators.keys().copied().collect();
                // C7 shard gate: the bridge domain (replay set, escrow,
                // mint counters, disputes) lives on the masterchain ONLY.
                // Settling the same intents on a workchain would credit
                // twice against per-engine state. Fail closed here (not in
                // `plan`, which has no notion of shards).
                if !bridge_intents.is_empty()
                    && self.cross_shard_enabled()
                    && tx.source_shard != crate::sharding::MASTERCHAIN_SHARD
                {
                    return Err(
                        "bridge intents settle on the masterchain only".to_string(),
                    );
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
            transfers, clob_events, outbound_messages, ..
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

            // Route any outbound contract messages produced by SysCallCallContract
            if !outbound_messages.is_empty() {
                self.process_contract_outbound_messages(outbound_messages).await
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
        if let crate::svm::VmExecutionResult::Success { clob_events, trades, transfers, .. } = &res {
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
                    self.restore_actor_native(actor_snapshot.as_ref())
                        .await;
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
                let mut escrow =
                    Self::mut_guard(&self.commitment_generation, &self.order_escrow).await;
                let quote_id = *self.pmm_usdt_token.read().await;
                let books = &orderbooks.books;
                let settled = self
                    .settle_clob_effects(
                        &clob_events,
                        ClobQuoteMode::NativeSvm,
                        quote_id,
                        &mut *tokens,
                        &mut *escrow,
                        tx.from,
                        reserve,
                        |pair, id| books.get(&pair).map_or(true, |b| b.find_order(id).is_none()),
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
                    self.restore_actor_native(actor_snapshot.as_ref())
                        .await;
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
                if let (Some(before), Some(work)) =
                    (&session_keys_before, session_keys_work.take())
                {
                    if *before != work {
                        *self.session_keys_write().await = work;
                    }
                }
                // §9 SHIELDED LEDGER, same all-or-nothing rule as the revoke
                // above and for the same reason: the working copy the VM
                // mutated is written back ONLY here, at the very end of a
                // transaction that settled completely. Every `Err` above
                // dropped the copy instead, so a transfer can never be half
                // remembered - and the write accessor bumps
                // `commitment_generation`, so the next root read folds the new
                // balances, spent inputs and fee total into the state root.
                if let (Some(before), Some(work)) =
                    (&confidential_before, confidential_work.take())
                {
                    if *before != work {
                        *self.confidential_write().await = work;
                    }
                }
                // §2 MODEL REGISTRY, same all-or-nothing rule as the shielded
                // ledger above: the working copy the VM mutated is written
                // back ONLY here, at the very end of a transaction that
                // settled completely. Every `Err` above dropped the copy
                // instead, so a registration can never survive a payload that
                // did not apply - and the write accessor bumps
                // `commitment_generation`, so the next root read folds the new
                // models into the state root.
                if let (Some(before), Some(work)) =
                    (&zkml_models_before, zkml_models_work.take())
                {
                    if *before != work {
                        *self.zkml_models_write().await = work;
                    }
                }
                // Hand the settlement undo records to the caller: if its
                // `commit_native` refuses afterwards, it rolls these back
                // (plus the domain snapshot it took before calling us),
                // closing the B1 hole where a rejected transaction kept
                // bridge/actor/PMM-native legs it had already settled.
                Ok((res, ExecPostActions {
                    bridge_snapshot,
                    actor_snapshot,
                    pmm_native_snapshot,
                    clob_native_snapshot,
                }))
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
        if tx.is_pq_implicit() {
            if crate::sharding::Transaction::global_implicit_registry().lookup(&tx.from).is_none() {
                if let Some((scheme, pk)) = self.get_pinned_pubkey(&tx.from) {
                    let _ = crate::sharding::Transaction::global_implicit_registry().register(
                        tx.from,
                        scheme,
                        &pk,
                        &crate::post_quantum::DEFAULT_SALT,
                    );
                }
            }
        }
        // 1. Cryptographic signature check
        if !tx.verify_signature() {
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
        if let Err(e) = self.session_gate(tx, timestamp).await {
            return Err(e);
        }

        let mut map = self.accounts.write().await;

        // 2. Fetch sender account
        let sender = map.get_mut(&tx.from)
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
        let fee_reserved = tx.gas_limit.max(floor_base);
        let total_cost = tx.amount.checked_add(fee_reserved)
            .and_then(|t| t.checked_add(surcharge))
            .ok_or_else(|| "Arithmetic overflow in transaction cost".to_string())?;

        if sender.balance < total_cost {
            return Err(format!(
                "Insufficient balance: account has {} nano-STELL, requires {} (double spend rejected)",
                sender.balance, total_cost
            ));
        }

        // 5. Execute the optional SVM payload BEFORE committing native balance
        //    changes, so a reverting/out-of-gas program leaves no partial effect
        //    (the SVM itself uses clone-commit for tokens/orderbooks). Release the
        //    account lock while the VM runs to avoid holding it across await.
        drop(map);
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
        let domain_snap = if tx.payload.is_empty() {
            None
        } else {
            Some(self.snapshot_payload_domains(&tx.payload).await)
        };
        // Settlement undo records (bridge/actor/PMM-native direct map
        // writes), filled on VM success for the commit-failure path below.
        let mut post_actions: Option<ExecPostActions> = None;
        if !tx.payload.is_empty() {
            let exec = self.execute_payload(tx, timestamp).await;
            let (res, actions) = match exec {
                Ok(v) => v,
                // Settlement (or deeper) refused AFTER the VM committed its
                // working copies live: restore everything (B1), then report.
                // (A bare VM revert/OutOfGas needs no restore — the VM only
                // writes back on Success, and the working copies die with it.)
                Err(e) => {
                    if let Some(snap) = domain_snap {
                        self.rollback_payload(snap, ExecPostActions {
                            bridge_snapshot: None,
                            actor_snapshot: None,
                            pmm_native_snapshot: Vec::new(),
                            clob_native_snapshot: Vec::new(),
                        }).await;
                    }
                    // F-01: an attributable failure pays the failure fee and
                    // consumes the nonce, exactly like the block path.
                    self.charge_failure_fee_and_commit(tx, floor_base, surcharge).await;
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
                    self.charge_failure_fee_and_commit(tx, floor_base, surcharge).await;
                    return Err("SVM: out of gas".to_string())
                }
                crate::svm::VmExecutionResult::Reverted(e) => {
                    // F-01: the failure fee + the nonce, like the block path.
                    self.charge_failure_fee_and_commit(tx, floor_base, surcharge).await;
                    return Err(format!("SVM reverted: {e}"))
                }
            }
        } else {
            gas_charged = tx.gas_limit;
        }

        // 6. Commit the native movement (amount + fee + payload value) through
        //    the shared commit point, then write ONLY the touched accounts.
        //    B1: a refusal here rolls back EVERYTHING (see rollback_payload).
        let (touched, _fee) = match self
            .commit_native(
                tx,
                gas_charged,
                &vm_transfers,
                &vm_payouts,
                &vm_burns,
                timestamp,
            )
            .await
        {
            Ok(v) => v,
            Err(e) => {
                if let (Some(snap), Some(actions)) = (domain_snap, post_actions) {
                    self.rollback_payload(snap, actions).await;
                }
                // F-01: the failure fee + the nonce, like the block path.
                self.charge_failure_fee_and_commit(tx, floor_base, surcharge).await;
                return Err(e);
            }
        };
        // Session budget: charged only now that the transaction has actually
        // applied, and with the gas this path consumed - the VM's `gas_used`
        // for a payload, the declared `gas_limit` for an empty-payload
        // transfer (no VM ran, so the declared limit is what it consumed).
        // Same numbers as the block path, so the registry does not care which
        // path applied the transaction.
        self.session_note_applied(tx, gas_charged).await;
        // Contract deploys commit code hashes here — AFTER the native commit,
        // never speculatively inside execution (B1: the trie has no undo).
        // Read (never write-locked together with the trie below): lock order
        // is contracts-then-trie everywhere, or ABBA-deadlock with writers.
        let deployed_contracts = if tx.payload.iter().any(|op| {
            matches!(op, crate::svm::OpCode::SysCallDeployContract { .. })
        }) {
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
    ///   `max(env, governed)` (`Mempool::read_base_fee_from_env` + the
    ///   per-finalize sync in main.rs), but the env half is node-local
    ///   process config and must not move consensus: when every operator
    ///   runs the default env the two bases coincide, and a higher env only
    ///   ever makes local admission STRICTER, never consensus looser.
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
        let surcharge = if tx.is_pq_activation() {
            PQ_ACTIVATION_SURCHARGE_GAS
        } else {
            0
        };
        (floor_base, surcharge)
    }

    /// The D2 penalty map, read WITHOUT blocking (the proposal validation
    /// path is synchronous).
    ///
    /// Returns `Err` when the lock is contended: the caller MUST fail CLOSED
    /// on it (refuse the proposal), exactly like the mempool floor read in the
    /// same path - a contended read must never silently lower the floor the
    /// apply path will charge with.
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
    fn floor_parts_for(
        governed_base: u64,
        penalties: &HashMap<[u8; 32], u64>,
        tx: &crate::sharding::Transaction,
    ) -> (u64, u64) {
        let floor_base = governed_base.saturating_add(penalties.get(&tx.from).copied().unwrap_or(0));
        let surcharge = if tx.is_pq_activation() {
            PQ_ACTIVATION_SURCHARGE_GAS
        } else {
            0
        };
        (floor_base, surcharge)
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
    fn apply_failure_fee_to_map(
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
    async fn charge_failure_fee(
        &self,
        tx: &crate::sharding::Transaction,
        fee: u64,
    ) -> (u64, Option<(u64, u64)>) {
        let mut map = self.accounts.write().await;
        Self::apply_failure_fee_to_map(&mut map, tx, fee)
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
    async fn charge_failure_fee_and_commit(
        &self,
        tx: &crate::sharding::Transaction,
        floor_base: u64,
        surcharge: u64,
    ) {
        let fee = tx.gas_limit.max(floor_base).saturating_add(surcharge);
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
    /// `gas_charged` is what execution consumed; the fee actually taken is
    /// `max(min(gas_charged, tx.gas_limit), floor_base) + surcharge` (F-01:
    /// never below the consensus floor — see `consensus_floor_parts`). The
    /// two kinds of caller deliberately pass different `gas_charged`, which
    /// is a PRE-EXISTING, PRESERVED divergence - and it is now the ONLY one
    /// between them:
    ///
    ///  * `apply_transaction` (the single-transaction API: RPC-level applies,
    ///    tests) passes the gas actually consumed (and the declared `gas_limit`
    ///    when the payload is empty), i.e. it charges what was used;
    ///  * EVERY block application passes the DECLARED `tx.gas_limit`, because
    ///    admission reserved exactly `amount + gas_limit` and `fees_collected`
    ///    (credited to the proposer inside `apply_block_transition`) is defined
    ///    as the sum of declared limits. The reorg path used to sit on the
    ///    `apply_transaction` side of this line and therefore silently charged
    ///    a different fee for the same block; it now delegates to
    ///    `apply_block_transition` and cannot.
    ///
    /// Both rules are pinned by green tests - `bonding_moves_real_funds_and_grants_validator_power`
    /// (single-tx charges `GAS_STAKE_BOND`, not the 10_000 declared) vs
    /// `block_execution_runs_payloads_and_conserves_native_value` (block charges
    /// the declared 560) - so unifying them would be an economic change, not the
    /// value-movement fix this function exists for. What MUST match, and does:
    /// a payload can never spend the fee, and a transaction whose movements are
    /// unaffordable is refused on both paths.
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
    /// fee actually debited from the sender
    /// (`max(min(gas_charged, gas_limit), floor_base) + surcharge`, where
    /// `(floor_base, surcharge)` is [`Self::consensus_floor_parts`]; 0 is
    /// never returned here - failure is `Err`, and a refused transaction
    /// moved nothing, so its receipt files `fee_charged: 0`).
    async fn commit_native(
        &self,
        tx: &crate::sharding::Transaction,
        gas_charged: u64,
        transfers: &[([u8; 32], u64)],
        payouts: &[([u8; 32], [u8; 32], u64)],
        burns: &[([u8; 32], u64)],
        now: u64,
    ) -> Result<(Vec<([u8; 32], u64, u64)>, u64), String> {
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
        let (floor_base, surcharge) = self.consensus_floor_parts(tx).await;
        let fee = gas_charged.min(tx.gas_limit).max(floor_base);
        let fee_with_surcharge = fee.saturating_add(surcharge);
        let charge = tx.amount.checked_add(fee_with_surcharge)
            .ok_or_else(|| "Arithmetic overflow in transaction cost".to_string())?;
        // Everything the payload moves has to be affordable on top of the fee.
        let required = charge
            .checked_add(vm_out)
            .ok_or_else(|| "Arithmetic overflow in transaction cost".to_string())?;
        // The floored fee is what is actually debited, so the reservation
        // check prices it (not the declared limit): when the floor binds,
        // `fee > gas_limit` and the declared-limit check would under-reserve.
        let total_cost = tx.amount.checked_add(fee)
            .and_then(|t| t.checked_add(surcharge))
            .ok_or_else(|| "Arithmetic overflow in transaction cost".to_string())?;

        // Team-vesting locked floors, snapshotted BEFORE the accounts lock
        // (lock order: staking -> accounts, same as `consensus_floor_parts`
        // above). `None` = untracked = no gate. The floor is evaluated at the
        // block timestamp `now`, so every node agrees on it for this block.
        // Empty on every live chain today (no vested allocations exist), in
        // which case this snapshot is two `None`s and the gate below is a
        // no-op with zero behavior change.
        let (sender_vesting_floor, payout_vesting_floors): (Option<u64>, Vec<([u8; 32], u64)>) = {
            let ledger = self.staking.read().await;
            let sender_floor = ledger
                .vesting_schedules
                .get(&tx.from)
                .map(|s| s.locked_amount(now));
            let mut floors = Vec::new();
            for (payer, _, _) in payouts {
                if let Some(s) = ledger.vesting_schedules.get(payer) {
                    if !floors.iter().any(|(p, _)| p == payer) {
                        floors.push((*payer, s.locked_amount(now)));
                    }
                }
            }
            (sender_floor, floors)
        };

        let mut map = self.accounts.write().await;
        // Every account this transaction mutated, with the (balance, nonce) it
        // had BEFORE the mutation; `None` = the account did not exist. Walked
        // backwards on failure, so a refused transaction is a no-op.
        let mut undo: Vec<([u8; 32], Option<(u64, u64)>)> = Vec::new();
        // Accounts that ended up changed, for the caller's trie write.
        let mut touched: Vec<[u8; 32]> = Vec::new();

        // M2: an outbound cross-shard transfer debits the sender on its SOURCE
        // shard and must NOT credit `to` here — the recipient lives on the
        // target shard and is credited only when the committed CrossShardMessage
        // is consumed there. Gated on the sharding flag, so a single-shard
        // engine (every pre-sharding test) keeps the historical behaviour.
        let burn_for_cross_shard =
            self.cross_shard_enabled() && tx.source_shard != tx.target_shard;

        let outcome = {
            let mut f = || -> Result<(), String> {
                let sender = map
                    .get_mut(&tx.from)
                    .ok_or_else(|| "Sender account does not exist".to_string())?;
                // Re-check nonce/balance under the lock we just re-acquired.
                if tx.nonce != sender.nonce {
                    return Err("Invalid nonce (state changed during execution)".to_string());
                }
                if sender.balance < total_cost {
                    return Err(
                        "Insufficient balance (state changed during execution)".to_string(),
                    );
                }
                if sender.balance < required {
                    return Err(format!(
                        "Insufficient balance for payload: has {}, needs {required}",
                        sender.balance
                    ));
                }

                if tx.is_pq_activation() {
                    let env = tx.pq_envelope()
                        .ok_or_else(|| "Missing PQ activation envelope".to_string())?;
                    if env.is_implicit {
                        return Err("PQ activation envelope must not be implicit".to_string());
                    }
                    let pk = env.pubkey.as_deref()
                        .ok_or_else(|| "Missing public key in PQ activation envelope".to_string())?;
                    let salt = env.salt;
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
                    if let Some(existing_hash) = sender.pubkey_hash {
                        if existing_hash != pk_hash || sender.scheme != env.scheme {
                            return Err(format!(
                                "Conflicting public key registration for address {}",
                                hex::encode(tx.from)
                            ));
                        }
                    }
                }

                // Deduct from sender and increment nonce. Charge the fee
                // (capped at the declared gas_limit) plus the transfer amount,
                // plus everything the payload moved out.
                undo.push((tx.from, Some((sender.balance, sender.nonce))));
                touched.push(tx.from);
                sender.balance = sender.balance.saturating_sub(required);
                sender.nonce += 1;

                // Team-vesting claim gate (audit: TeamVestingSchedule was
                // CLI-only, no on-chain lock). A vesting-tracked sender may
                // not be left below its locked floor: spending above the
                // unlocked amount FAILS closed here. This covers amount +
                // fee + every payload/settlement debit at once, because
                // `sender.balance` is post-settlement and `required` is the
                // remaining debit — cumulative spends are bounded with no
                // per-transfer claimed bookkeeping. Refusal rolls back via
                // the undo log (caller also rolls back payload domains).
                if let Some(locked) = sender_vesting_floor {
                    if sender.balance < locked {
                        let msg = format!(
                            "team vesting lock: sender {} balance {} would fall below locked {locked} (spending above the unlocked amount is refused)",
                            hex::encode(tx.from),
                            sender.balance,
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
                    undo.push((tx.to, map.get(&tx.to).map(|a| (a.balance, a.nonce))));
                    touched.push(tx.to);
                    if let Some(recipient) = map.get_mut(&tx.to) {
                        recipient.balance = recipient.balance.checked_add(tx.amount)
                            .ok_or_else(|| "Arithmetic overflow on recipient balance".to_string())?;
                    } else {
                        map.insert(tx.to, AccountState::new(tx.to, tx.amount));
                    }
                }

                // The payload's own value movements (this is what `OpCode::Transfer`
                // and the SysCallStake bond to the staking pool resolve to).
                for (to, amount) in transfers {
                    undo.push((*to, map.get(to).map(|a| (a.balance, a.nonce))));
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
                    undo.push((*payer, map.get(payer).map(|a| (a.balance, a.nonce))));
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
                    if let Some((_, locked)) = payout_vesting_floors.iter().find(|(p, _)| p == payer) {
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

                    undo.push((*beneficiary, map.get(beneficiary).map(|a| (a.balance, a.nonce))));
                    touched.push(*beneficiary);
                    if let Some(b) = map.get_mut(beneficiary) {
                        b.balance = b.balance.checked_add(*amount)
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
                    undo.push((*from, map.get(from).map(|a| (a.balance, a.nonce))));
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
            // original value, not to the intermediate one.
            for (addr, prev) in undo.iter().rev() {
                match prev {
                    Some((balance, nonce)) => {
                        if let Some(acc) = map.get_mut(addr) {
                            acc.balance = *balance;
                            acc.nonce = *nonce;
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
            if let Some(env) = tx.pq_envelope() {
                if !env.is_implicit {
                    if let Some(ref pk) = env.pubkey {
                        let salt = env.salt;
                        self.pin_pubkey(tx.from, env.scheme, pk, &salt).await?;
                    }
                }
            }
        }

        Ok((out, fee_with_surcharge))
    }

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
        governed_base: u64,
        penalties: &HashMap<[u8; 32], u64>,
        vesting_floors: &HashMap<[u8; 32], u64>,
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
                        snap.entry(addr).or_insert_with(|| {
                            map.get(&addr).map(|a| (a.balance, a.nonce))
                        });
                    }
                }
                snap
            };

            // (b) PLAN - in parallel, on the rayon pool.
            let plans: Vec<(usize, PlainTxPlan)> = wave
                .par_iter()
                .map(|&i| {
                    let tx = &txs[i];
                    let (floor_base, surcharge) = Self::floor_parts_for(governed_base, penalties, tx);
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
                            // Session budget follows the DECLARED gas, not the
                            // floored money fee: the sequential path records
                            // `gas_used` (= declared limit for an empty
                            // payload), and the two paths must agree on the
                            // committed registry spend for the same block.
                            session_notes.push((&txs[*i], txs[*i].gas_limit));
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
                let (floor_base, surcharge) = Self::floor_parts_for(governed_base, penalties, tx);
                let session_ok = session_valid
                    .map(|sv| sv.get(&i).copied().unwrap_or(false))
                    .unwrap_or(true);
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
                    session_notes.push((tx, tx.gas_limit));
                }
            }
        }

        for (tx, gas) in session_notes {
            self.session_note_applied(tx, gas).await;
        }
    }

    /// Block-path range-proof pre-verification (the CPU win for shielded TPS).
    ///
    /// Collects `(tx_idx, transfer, input_ranges, output_ranges)` for every
    /// ADMITTED transaction carrying `SysCallConfidentialTransfer2` and
    /// verifies the bundles' stateless proof check in parallel via
    /// [`crate::crypto_privacy::ConfidentialTransfer::batch_verify_balanced_with_ranges`]
    /// (rayon, order-preserving collect; sequential fast path below 4 bundles,
    /// the same shape as `PARALLEL_UNSEAL_MIN_TXS` / `PAR_VERIFY_MIN_PAIRS`).
    ///
    /// Returns digest -> verdict, keyed by
    /// [`crate::crypto_privacy::confidential_transfer2_preverify_digest`]. The
    /// SVM handler consults it to skip RE-VERIFICATION of range proofs only:
    /// ownership, spent-set, conservation and fee checks all still run per
    /// transaction, in block order, against live state — and a cache miss runs
    /// the full check as today. Determinism is load-bearing here: verification
    /// is a pure function of the bundle bytes, so 1-thread and N-thread
    /// verdicts are bit-identical, and only admitted transactions contribute
    /// (a rejected transaction's payload never executes, pre-pass or not).
    fn preverify_confidential_ranges(
        txs: &[crate::sharding::Transaction],
        admitted: &[bool],
    ) -> HashMap<[u8; 32], bool> {
        struct Item<'a> {
            tx_idx: usize,
            digest: [u8; 32],
            transfer: &'a crate::crypto_privacy::ConfidentialTransfer,
            input_ranges: &'a [crate::crypto_privacy::RangeProof],
            output_ranges: &'a [crate::crypto_privacy::RangeProof],
        }
        let mut items: Vec<Item<'_>> = Vec::new();
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        for (tx_idx, tx) in txs.iter().enumerate() {
            if !admitted.get(tx_idx).copied().unwrap_or(false) {
                continue;
            }
            for op in &tx.payload {
                if let crate::svm::OpCode::SysCallConfidentialTransfer2 {
                    transfer,
                    input_ranges,
                    output_ranges,
                    ..
                } = op
                {
                    let digest =
                        crate::crypto_privacy::confidential_transfer2_preverify_digest(
                            transfer,
                            input_ranges,
                            output_ranges,
                        );
                    // First occurrence wins: identical bundles verify
                    // identically, so verifying each digest once is exact and
                    // keeps the batch order deterministic (block order).
                    if seen.insert(digest) {
                        items.push(Item {
                            tx_idx,
                            digest,
                            transfer,
                            input_ranges,
                            output_ranges,
                        });
                    }
                }
            }
        }
        if items.is_empty() {
            return HashMap::new();
        }
        let refs: Vec<(
            &crate::crypto_privacy::ConfidentialTransfer,
            &[crate::crypto_privacy::RangeProof],
            &[crate::crypto_privacy::RangeProof],
        )> = items
            .iter()
            .map(|it| (it.transfer, it.input_ranges, it.output_ranges))
            .collect();
        let verdicts =
            crate::crypto_privacy::ConfidentialTransfer::batch_verify_balanced_with_ranges(
                &refs,
            );
        debug_assert_eq!(items.len(), verdicts.len());
        for (it, v) in items.iter().zip(verdicts.iter()) {
            tracing::trace!(tx = it.tx_idx, verdict = v, "confidential pre-pass verdict");
        }
        items
            .into_iter()
            .zip(verdicts.into_iter())
            .map(|(it, v)| (it.digest, v))
            .collect()
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
    /// disagree about what a transaction moved (the one deliberate difference -
    /// which gas number each charges as the fee - is documented on
    /// `commit_native`).
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
        let (applied, failed, fees, status, tx_fees, _events) =
            self.apply_block_parallel_fees_with_events(txs, timestamp).await;
        (applied, failed, fees, status, tx_fees)
    }

    pub async fn apply_block_parallel_fees_with_events(
        &self,
        txs: &[crate::sharding::Transaction],
        timestamp: u64,
    ) -> (usize, usize, u64, Vec<bool>, Vec<u64>, Vec<Vec<crate::contract::ContractEvent>>) {
        if txs.is_empty() {
            return (0, 0, 0, Vec::new(), Vec::new(), Vec::new());
        }
        for tx in txs {
            if tx.is_pq_implicit() {
                if crate::sharding::Transaction::global_implicit_registry().lookup(&tx.from).is_none() {
                    if let Some((scheme, pk)) = self.get_pinned_pubkey(&tx.from) {
                        let _ = crate::sharding::Transaction::global_implicit_registry().register(
                            tx.from,
                            scheme,
                            &pk,
                            &crate::post_quantum::DEFAULT_SALT,
                        );
                    }
                }
            }
        }
        // 1) Batched signature verification (parallel across cores for big blocks).
        let all_valid = crate::sharding::Transaction::verify_signatures_batch_parallel(txs);

        // 2) Group transaction indices by sender, preserving order.
        let mut order: Vec<[u8; 32]> = Vec::new();
        let mut groups: HashMap<[u8; 32], Vec<usize>> = HashMap::new();
        for (i, tx) in txs.iter().enumerate() {
            groups.entry(tx.from).or_insert_with(|| {
                order.push(tx.from);
                Vec::new()
            }).push(i);
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
        //    `commit_native` re-reads the live map, which still equals this
        //    snapshot — the mirror is only updated at the end of this
        //    function, never mid-block.
        let governed_base: u64 = self
            .governance_read()
            .await
            .applied
            .min_gas_limit
            .unwrap_or(0);
        let penalties: HashMap<[u8; 32], u64> =
            self.consensus_penalty.read().await.clone();
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
        let mut admitted = vec![false; txs.len()];
        {
            let map = self.accounts.read().await;
            // Held for the whole pass (it is read-only) so the loop stays
            // synchronous: no awaits while both guards are held.
            let session_reg = self.session_keys.read().await;
            let mut session_sim = crate::zkml::SessionSpendSim::default();
            for addr in &order {
                let Some(sender) = map.get(addr) else { continue };
                let mut nonce = sender.nonce;
                let mut balance = sender.balance;
                for &i in &groups[addr] {
                    let tx = &txs[i];
                    if !all_valid && !tx.verify_signature() {
                        continue;
                    }
                    if let Some(cid) = tx.chain_id() {
                        if cid != self.chain_id {
                            continue;
                        }
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
                    if tx.nonce != nonce {
                        continue;
                    }
                    // F-01: reserve what execution will actually charge —
                    // `amount + max(declared, floor) + surcharge` — so a
                    // below-floor transaction is only admitted when its sender
                    // can pay the floor (`commit_native` charges it anyway).
                    // Same formula as admission; see `consensus_floor_parts`.
                    let (floor_base, surcharge) =
                        Self::floor_parts_for(governed_base, &penalties, tx);
                    let fee_reserved = tx.gas_limit.max(floor_base);
                    let Some(total) = tx.amount.checked_add(fee_reserved).and_then(|t| t.checked_add(surcharge)) else {
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

        // 3b) Parallel range-proof PRE-PASS (block path only): verify the
        //     stateless shielded-proof bundles of the admitted transactions
        //     across cores, BEFORE the sequential execute loop. The loop below
        //     still executes payloads one at a time in block order against
        //     live state, and the SVM handler still runs every state check —
        //     the cached verdict only lets it skip re-verifying range proofs.
        //     Pure function of admitted bundle bytes, order-preserving, so the
        //     sequential loop observes bit-identical verdicts with or without
        //     the pre-pass (and on 1 thread vs N threads).
        let range_preverify = Self::preverify_confidential_ranges(txs, &admitted);

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
        // `apply_failure_fee_to_map`; this just files the outcome (fee
        // receipt, proposer credit, trie write).
        // Admission-stage refusals (`!admitted[i]`: bad signature/chain-id,
        // nonce gap, sim-insolvent, session-sim refusal) and missing-sender
        // executions keep the plain `failed += 1`: they never ran, and there
        // is no head nonce to consume. The parallel PLAIN fast path above
        // cannot use this (it holds the accounts write guard) and inlines
        // the sync core instead.
        //
        // Hygiene note: the per-transaction bindings (`tx`, `i`) are loop
        // locals invisible at this definition site, so they travel as macro
        // arguments; the block-level bindings resolve lexically.
        macro_rules! fail_with_floor {
            ($tx:expr, $idx:expr) => {{
                failed += 1;
                let (floor_base, surcharge) =
                    Self::floor_parts_for(governed_base, &penalties, $tx);
                let fee = $tx.gas_limit.max(floor_base).saturating_add(surcharge);
                let (debited, charged_state) = self
                    .charge_failure_fee($tx, fee)
                    .await;
                if let Some((balance, nonce)) = charged_state {
                    trie_dirty.push(($tx.from, balance, nonce));
                }
                fees_collected = fees_collected.saturating_add(debited);
                fees[$idx] = debited;
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
                let wave_all_plain = wave.iter().all(|&i| txs[i].payload.is_empty() && !txs[i].is_pq_activation());
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
                        governed_base,
                        &penalties,
                        &vesting_floors,
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
                                if let Some(sender) = map.get(&tx.from) {
                                    if tx.nonce != sender.nonce {
                                        2
                                    } else {
                                        let surcharge = if tx.is_pq_activation() {
                                            PQ_ACTIVATION_SURCHARGE_GAS
                                        } else {
                                            0
                                        };
                                        let total = tx.amount.checked_add(tx.gas_limit).and_then(|t| t.checked_add(surcharge));
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
                                2 | 3 | 4 => {
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
                        let (transfers, payouts, burns, gas_used, tx_events) = if tx.payload.is_empty() {
                            (Vec::new(), Vec::new(), Vec::new(), tx.gas_limit, Vec::new())
                        } else {
                            domain_snap =
                                Some(self.snapshot_payload_domains(&tx.payload).await);
                            match self.execute_payload_with_preverify(tx, timestamp, Some(&range_preverify)).await {
                                Ok((crate::svm::VmExecutionResult::Success {
                                    transfers,
                                    payouts,
                                    burns,
                                    gas_used,
                                    events: evts,
                                    ..
                                }, actions)) => {
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
                                        self.rollback_payload(snap, ExecPostActions {
                                            bridge_snapshot: None,
                                            actor_snapshot: None,
                                            pmm_native_snapshot: Vec::new(),
                                            clob_native_snapshot: Vec::new(),
                                        }).await;
                                    }
                                    fail_with_floor!(tx, i);
                                    continue;
                                }
                            }
                        };
                        match self.commit_native(tx, tx.gas_limit, &transfers, &payouts, &burns, timestamp).await {
                            Ok((touched, fee)) => {
                                if tx.is_pq_activation() {
                                    if let Some(env) = tx.pq_envelope() {
                                        if !env.is_implicit {
                                            if let Some(ref pk) = env.pubkey {
                                                let salt = crate::post_quantum::DEFAULT_SALT;
                                                let _ = self.pin_pubkey(tx.from, env.scheme, pk, &salt).await;
                                            }
                                        }
                                    }
                                }
                                trie_dirty.extend(touched);
                                fees_collected = fees_collected.saturating_add(fee);
                                applied += 1;
                                status[i] = true;
                                fees[i] = fee;
                                events[i] = tx_events;
                                self.session_note_applied(tx, gas_used).await;
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
                    if let Some(sender) = map.get(&tx.from) {
                        if tx.nonce != sender.nonce {
                            2
                        } else {
                            let surcharge = if tx.is_pq_activation() {
                                PQ_ACTIVATION_SURCHARGE_GAS
                            } else {
                                0
                            };
                            let total = tx.amount.checked_add(tx.gas_limit).and_then(|t| t.checked_add(surcharge));
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
                    2 | 3 | 4 => {
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
            // `gas_used` is what the session budget will be charged if this
            // transaction applies: the VM's consumption for a payload, the
            // DECLARED `gas_limit` for an empty-payload transfer (no VM ran,
            // so nothing else could measure it - and it must still consume
            // budget, or a plain session transfer would bypass the cap that
            // phase 1 closed for the policy checks).
            //
            // B1 atomicity (mirrors `apply_transaction`): per-tx domain
            // snapshot + settlement undo records, restored if the commit
            // below refuses.
            let mut domain_snap: Option<PayloadDomainSnapshot> = None;
            let mut post_actions: Option<ExecPostActions> = None;
            let (transfers, payouts, burns, gas_used, tx_events) = if tx.payload.is_empty() {
                (Vec::new(), Vec::new(), Vec::new(), tx.gas_limit, Vec::new())
            } else {
                // Block path: hand the pre-pass verdicts over. The single-tx
                // path (`apply_transaction` -> `execute_payload`) passes `None`
                // and never consults the cache.
                //
                // B1 atomicity: snapshot domains BEFORE the VM runs; any
                // failure after (including the native commit below) restores
                // everything (see rollback_payload). NOTE: must stay in sync
                // with the `apply_transaction` copy.
                domain_snap =
                    Some(self.snapshot_payload_domains(&tx.payload).await);
                match self.execute_payload_with_preverify(tx, timestamp, Some(&range_preverify)).await {
                    Ok((crate::svm::VmExecutionResult::Success {
                        transfers,
                        payouts,
                        burns,
                        gas_used,
                        events: evts,
                        ..
                    }, actions)) => {
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
                            self.rollback_payload(snap, ExecPostActions {
                                bridge_snapshot: None,
                                actor_snapshot: None,
                                pmm_native_snapshot: Vec::new(),
                                clob_native_snapshot: Vec::new(),
                            }).await;
                        }
                        fail_with_floor!(tx, i);
                        continue;
                    }
                }
            };

            // Commit: amount + fee + payload transfers + payload payouts.
            //
            // FEE: the block path hands `commit_native` the DECLARED
            // `tx.gas_limit` - that is what admission reserved and what
            // `fees_collected` credits to the proposer, and it is the rule this
            // path has always had. `apply_transaction` hands over the gas
            // actually consumed instead. The arithmetic is shared; only the
            // number the caller supplies differs. See `commit_native` for why
            // this divergence is preserved rather than papered over.
            // F-01: EITHER number is raised to at least the consensus floor
            // inside `commit_native` — a below-floor declaration is charged
            // the floor anyway, never executed below it.
            match self.commit_native(tx, tx.gas_limit, &transfers, &payouts, &burns, timestamp).await {
                Ok((touched, fee)) => {
                    if tx.is_pq_activation() {
                        if let Some(env) = tx.pq_envelope() {
                            if !env.is_implicit {
                                if let Some(ref pk) = env.pubkey {
                                    let salt = crate::post_quantum::DEFAULT_SALT;
                                    let _ = self.pin_pubkey(tx.from, env.scheme, pk, &salt).await;
                                }
                            }
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
                    self.session_note_applied(tx, gas_used).await;
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
            tx.payload.iter().any(|op| {
                matches!(op, crate::svm::OpCode::SysCallDeployContract { .. })
            })
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

    // ==================== M2: cross-shard gate and inbound credits ====================

    /// Turn on cross-shard execution for this engine. Called by
    /// `ValidatorRuntime::with_shard` exactly when the process runs more than one
    /// shard, so a single-shard engine never sees a behavioural change.
    pub fn enable_cross_shard(&self) {
        self.cross_shard_enabled
            .store(true, std::sync::atomic::Ordering::Release);
    }

    pub fn cross_shard_enabled(&self) -> bool {
        self.cross_shard_enabled.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Attach the process-shared finalized-header registry (C1 anchor).
    /// Same `Arc` as every shard runtime in the process.
    pub fn with_finalized_headers(
        &self,
        registry: Arc<std::sync::RwLock<crate::sharding::FinalizedHeaderRegistry>>,
    ) {
        if let Ok(mut slot) = self.finalized_headers.write() {
            *slot = Some(registry);
        }
    }

    /// The process-shared finalized-header registry, if one is attached.
    ///
    /// The registry holds the full header (height, block hash, state root,
    /// timestamp) of every shard this process COMMITTED, and is written only
    /// by the block-application paths — never from gossip, RPC or DHT blobs.
    /// The RPC reads it to answer `stell_getShards` with heads this node
    /// actually applied. `None` on a node with no registry attached (most
    /// single-shard setups and the unit tests): the caller then falls back to
    /// its own chain's height / head / state root.
    pub fn finalized_headers(
        &self,
    ) -> Option<Arc<std::sync::RwLock<crate::sharding::FinalizedHeaderRegistry>>> {
        self.finalized_headers.read().ok().and_then(|slot| slot.clone())
    }

    /// Anchored inclusion check for one inbound message (C1): proof AND a
    /// locally-finalized source header with the claimed root. `false` covers
    /// both "forged" and "not finalized here yet" — callers treat it as
    /// not-ready (skip + retry after catching up), never as verified.
    /// A poisoned lock here would wedge every apply, so a failed lock read
    /// fails closed (false) instead of blocking.
    pub fn verify_cross_shard_anchored(&self, msg: &crate::sharding::CrossShardMessage) -> bool {
        let guard = self
            .finalized_headers
            .read()
            .ok()
            .and_then(|slot| slot.clone());
        let Some(reg_arc) = guard else {
            return false;
        };
        let inner = reg_arc.read().ok();
        let Some(reg) = inner.as_deref() else {
            return false;
        };
        msg.verify_anchored(Some(reg))
    }

    /// True once the given message has been credited on this shard.
    pub async fn is_cross_shard_consumed(
        &self,
        key: &crate::sharding::CrossShardKey,
    ) -> bool {
        self.cross_shard_consumed.read().await.contains(key)
    }

    /// How many inbound cross-shard messages this engine has credited. A
    /// replay attempt must not move this number.
    pub async fn cross_shard_consumed_len(&self) -> usize {
        self.cross_shard_consumed.read().await.len()
    }

    /// Snapshot the engine's consumed set for persistence (audit F-I), sorted
    /// for deterministic bytes. The set gates the actual credit at apply time;
    /// without persisting it a restart re-opened every consumed message for a
    /// second credit (the runtime mirrors alone cannot stop the apply).
    pub async fn cross_shard_consumed_snapshot(&self) -> Vec<crate::sharding::CrossShardKey> {
        let mut v: Vec<crate::sharding::CrossShardKey> =
            self.cross_shard_consumed.read().await.iter().copied().collect();
        v.sort();
        v
    }

    /// Install persisted consumed keys (startup restore). Extends (never
    /// replaces: a live set may already hold entries committed after the
    /// snapshot was taken). Bumps the commitment generation: the set IS folded
    /// into the digest (audit F1), so restoring it moves the root exactly as
    /// re-applying the consuming blocks would.
    pub async fn restore_cross_shard_consumed(&self, keys: &[crate::sharding::CrossShardKey]) {
        self.cross_shard_consumed
            .write()
            .await
            .extend(keys.iter().copied());
        self.bump_commitment_generation();
    }

    /// How many outbound cross-shard transfers this engine has recorded.
    pub async fn cross_shard_produced_len(&self) -> usize {
        self.cross_shard_produced.read().await.len()
    }

    /// How many cross-shard lifecycles this engine has seen complete.
    pub async fn cross_shard_completed_len(&self) -> usize {
        self.cross_shard_completed.read().await.len()
    }

    // ============ §9 CROSS-SHARD 2PC ============

    /// The §9 two-phase-commit record of one transfer, if this shard owns it.
    pub async fn xpc_record(
        &self,
        tx_hash: &[u8; 32],
    ) -> Option<crate::xshard2pc::XpcRecord> {
        self.cross_shard_xpc.read().await.get(tx_hash).cloned()
    }

    /// Every §9 two-phase-commit record this shard owns, sorted by the
    /// transaction hash (deterministic bytes for the snapshot).
    pub async fn xpc_snapshot(&self) -> Vec<crate::xshard2pc::XpcRecord> {
        let mut v: Vec<crate::xshard2pc::XpcRecord> =
            self.cross_shard_xpc.read().await.values().cloned().collect();
        v.sort_by_key(|r| r.tx_hash);
        v
    }

    /// How many §9 two-phase-commit records this shard owns.
    pub async fn xpc_len(&self) -> usize {
        self.cross_shard_xpc.read().await.len()
    }

    /// The Merkle inclusion proof of the §9 2PC state leaf of one transfer,
    /// in this shard's state trie.
    ///
    /// This is what the peer shard verifies: the proof binds the phase this
    /// shard committed to (PREPARED / COMMITTED / ABORTED) to a state root
    /// this shard's quorum signed, so the peer's vote (PREPARE-ACK /
    /// ABORT-ACK) or decision (COMMIT) cannot be forged.
    pub async fn get_xpc_proof(&self, tx_hash: &[u8; 32]) -> Option<crate::cell::MerkleProof> {
        let key = crate::xshard2pc::xpc_state_key(tx_hash);
        self.state_trie.read().await.generate_merkle_proof(&key)
    }

    /// Install persisted §9 two-phase-commit records (startup restore).
    ///
    /// Extends (never replaces) the live map, and RE-INSERTS the state-trie
    /// leaf of every restored record: the trie is rebuilt from the accounts
    /// alone on a snapshot restore, so without this the peer's proofs (which
    /// are Merkle proofs of that leaf) would stop verifying after a restart
    /// and a prepared transfer could never be completed.
    pub async fn restore_xpc_records(&self, records: &[crate::xshard2pc::XpcRecord]) {
        if records.is_empty() {
            return;
        }
        {
            let mut map = self.cross_shard_xpc.write().await;
            for rec in records {
                map.entry(rec.tx_hash).or_insert_with(|| rec.clone());
            }
        }
        {
            let mut trie = self.state_trie.write().await;
            for rec in records {
                let key = crate::xshard2pc::xpc_state_key(&rec.tx_hash);
                let value = crate::xshard2pc::xpc_state_value(rec.phase, &rec.tx_hash);
                trie.insert(&key, &value);
            }
        }
        self.bump_commitment_generation();
    }

    /// Write a §9 two-phase-commit record: the committed map AND the
    /// state-trie leaf that the peer's proofs are made against.
    ///
    /// The two are written together so the leaf can never disagree with the
    /// map: a peer that proves the leaf proves the map's phase, and the map
    /// is what the commitment digest covers.
    pub(crate) async fn write_xpc_record(&self, rec: &crate::xshard2pc::XpcRecord) {
        {
            let mut map = self.cross_shard_xpc.write().await;
            map.insert(rec.tx_hash, rec.clone());
        }
        {
            let mut trie = self.state_trie.write().await;
            let key = crate::xshard2pc::xpc_state_key(&rec.tx_hash);
            let value = crate::xshard2pc::xpc_state_value(rec.phase, &rec.tx_hash);
            trie.insert(&key, &value);
        }
        self.bump_commitment_generation();
    }

    /// True once an ack or bounce for `tx_hash` committed on this chain.
    pub async fn is_cross_shard_completed(&self, tx_hash: &[u8; 32]) -> bool {
        self.cross_shard_completed.read().await.contains(tx_hash)
    }

    /// Snapshot the engine's produced map for persistence, sorted by tx hash
    /// for deterministic bytes.
    pub async fn cross_shard_produced_snapshot(&self) -> Vec<([u8; 32], u64)> {
        let mut v: Vec<([u8; 32], u64)> = self
            .cross_shard_produced
            .read()
            .await
            .iter()
            .map(|(h, height)| (*h, *height))
            .collect();
        v.sort();
        v
    }

    /// Snapshot the engine's completed set for persistence, sorted for
    /// deterministic bytes.
    pub async fn cross_shard_completed_snapshot(&self) -> Vec<[u8; 32]> {
        let mut v: Vec<[u8; 32]> =
            self.cross_shard_completed.read().await.iter().copied().collect();
        v.sort();
        v
    }

    /// Install a full persisted replay snapshot (snapshot-sync / startup
    /// restore). Extends every set, never replaces - same contract as
    /// `restore_cross_shard_consumed`, applied to all three committed sets at
    /// once so a partial install cannot leave the digest half-moved.
    ///
    /// Both the engine half (`engine_consumed`) and the runtime mirror half
    /// (`runtime_consumed`) feed the consumed set: on an honest chain the two
    /// coincide (the runtime mirrors exactly what the engine credited, plus
    /// the linkage-checked control records the engine records itself), and the
    /// union is idempotent. Produced heights keep first-wins (`or_insert`,
    /// the live path's rule), so reinstalling an older blob over newer live
    /// state cannot re-date an outbound.
    pub async fn restore_cross_shard_replay(
        &self,
        snap: &crate::sharding::CrossShardReplaySnapshot,
    ) {
        self.cross_shard_consumed
            .write()
            .await
            .extend(snap.engine_consumed.iter().copied());
        self.cross_shard_consumed
            .write()
            .await
            .extend(snap.runtime_consumed.iter().copied());
        {
            let mut produced = self.cross_shard_produced.write().await;
            for (h, _tx, height) in &snap.produced {
                produced.entry(*h).or_insert(*height);
            }
        }
        self.cross_shard_completed
            .write()
            .await
            .extend(snap.completed.iter().copied());
        // §9 2PC: the two-phase-commit records are restored too, and their
        // state-trie leaves are re-inserted, so a node that restarts
        // mid-2PC resumes to the SAME decision (and the peer's proofs of
        // this shard's vote still verify).
        self.restore_xpc_records(&snap.xpc).await;
        self.bump_commitment_generation();
    }

    /// True when the incoming snapshot provably covers the local replay
    /// state: every locally consumed key, every locally produced outbound
    /// (with the SAME produce height - a height disagreement means the two
    /// sides applied different chains) and every locally completed lifecycle
    /// is present incoming. Snapshot install may only fast-forward on `true`;
    /// anything else must be refused loudly, never silently dropped or
    /// silently kept (keeping would fork the root, dropping would double
    /// mint).
    pub async fn cross_shard_replay_covers(
        &self,
        snap: &crate::sharding::CrossShardReplaySnapshot,
    ) -> bool {
        let consumed = self.cross_shard_consumed.read().await;
        let incoming_consumed: HashSet<crate::sharding::CrossShardKey> = snap
            .engine_consumed
            .iter()
            .chain(snap.runtime_consumed.iter())
            .copied()
            .collect();
        if !consumed.iter().all(|k| incoming_consumed.contains(k)) {
            return false;
        }
        let produced = self.cross_shard_produced.read().await;
        let mut incoming_heights: HashMap<[u8; 32], u64> = HashMap::new();
        for (h, _tx, height) in &snap.produced {
            incoming_heights.entry(*h).or_insert(*height);
        }
        for (h, height) in produced.iter() {
            match incoming_heights.get(h) {
                Some(in_h) if in_h == height => {}
                _ => return false,
            }
        }
        let completed = self.cross_shard_completed.read().await;
        let incoming_completed: HashSet<[u8; 32]> =
            snap.completed.iter().copied().collect();
        if !completed.iter().all(|h| incoming_completed.contains(h)) {
            return false;
        }
        true
    }

    /// Credit every INBOUND cross-shard message this block commits to, in the
    /// block's own order, exactly once. Also records the block's OUTBOUND
    /// transfers (produced) and its linkage-valid ack/bounce completions, so
    /// the committed replay sets derive deterministically from applied blocks.
    ///
    /// A block only ever carries an inbound record for the shard it belongs to
    /// (a source block carries outbound records, which are applied by the
    /// transaction path, not here). Each credit requires the message's Merkle
    /// inclusion proof against the source state root — the local `trusted`
    /// shortcut is IGNORED because the flag is part of attacker-supplied block
    /// content. The replay key is inserted only after the credit succeeds, so a
    /// duplicate cannot mint a second time.
    ///
    /// Recording rules (all deterministic functions of the block, hence
    /// identical on every node that applied it):
    /// * produced: every transfer that is outbound for this block's shard,
    ///   first height wins - the same predicate the runtime uses, recorded
    ///   BEFORE the inbound pass so same-block linkage reads it, exactly like
    ///   the runtime's apply order;
    /// * consumed (transfers): unchanged - proof-checked credit, key inserted
    ///   only on success;
    /// * consumed + completed (acks/bounces): the runtime's linkage rule,
    ///   mirrored - proof-less, untrusted, produced entry known, lifecycle not
    ///   already complete, bounce past the height timeout - processed in the
    ///   same deterministic key order. NO value movement: the bounce refund
    ///   stays the runtime's job; the engine only records, never pays, so a
    ///   recorded bounce can never double-pay against the runtime's refund.
    pub async fn apply_cross_shard_consumptions(&self, block: &crate::sharding::Block) -> usize {
        if !self.cross_shard_enabled() || block.cross_shard_out.is_empty() {
            return 0;
        }
        let mut mutated = false;
        // Produced first: same-block linkage reads the map including this
        // block's own outbounds, exactly like the runtime's apply order.
        {
            let mut produced = self.cross_shard_produced.write().await;
            for msg in &block.cross_shard_out {
                if msg.is_transfer() && msg.is_outbound_for(block.shard_id) {
                    let tx_hash = msg.tx.compute_tx_hash();
                    if !produced.contains_key(&tx_hash) {
                        produced.insert(tx_hash, block.height);
                        mutated = true;
                    }
                }
            }
        }
        // §9 2PC, SOURCE side: a block that PRODUCES a PREPARE record also
        // records the PREPARED state of that transfer on this shard - the
        // escrow. The record is written HERE, in the state transition, so the
        // peer shard can prove it (the COMMIT record carries a Merkle proof
        // of this leaf) and so a restart resumes the same decision.
        for msg in &block.cross_shard_out {
            if msg.is_prepare() && msg.is_outbound_for(block.shard_id) {
                let tx = &msg.tx;
                let tx_hash = tx.compute_tx_hash();
                let existing = self.xpc_record(&tx_hash).await;
                let transition = crate::xshard2pc::source_prepare(
                    existing.as_ref(),
                    tx,
                    tx.source_shard,
                    tx.target_shard,
                    block.height,
                );
                if transition == crate::xshard2pc::XpcTransition::Created {
                    let rec = crate::xshard2pc::XpcRecord::prepared(
                        tx.clone(),
                        tx.source_shard,
                        tx.target_shard,
                        block.height,
                    );
                    self.write_xpc_record(&rec).await;
                    mutated = true;
                }
            }
        }
        // Deterministic order: sort by the replay key, so two independently
        // assembled target nodes that received the same set of messages derive
        // the same credit order and therefore the same state root, regardless
        // of KV enumeration order.
        let mut inbound: Vec<&crate::sharding::CrossShardMessage> = block
            .cross_shard_out
            .iter()
            .filter(|m| m.is_inbound_for(block.shard_id))
            .collect();
        inbound.sort_by_key(|m| crate::sharding::CrossShardKey::of(m));

        let mut credited = 0usize;
        for msg in inbound {
            let key = crate::sharding::CrossShardKey::of(msg);
            if msg.is_xpc() {
                // §9 2PC: the intermediate states. Every transition is a pure
                // function of the committed record, so a replay is a no-op and
                // a crash mid-2PC resumes to the SAME decision.
                if self.apply_xpc_record(msg, block.height).await {
                    mutated = true;
                }
                // The replay key is recorded for every 2PC record that reached
                // a terminal phase, so the audit trail (and the digest) show
                // which lifecycles were decided.
                continue;
            }
            if msg.is_ack() || msg.is_bounce() {
                // Control record: linkage-checked bookkeeping only, never a
                // credit. Mirrors `ValidatorRuntime::control_linkage_ok` at
                // apply height: proof-carrying control records are refused
                // (the engine would otherwise credit them to `tx.to` on the
                // source shard - a mint), unknown produced entries fail
                // closed, an already-completed lifecycle is skipped, and a
                // premature bounce waits for its timeout. Same-block
                // ack+bounce for one transaction resolves first-in-key-order,
                // exactly like the runtime: the consumed insert lands before
                // the completed insert, and the second record finds the
                // lifecycle complete.
                if msg.merkle_inclusion_proof.is_some() || msg.trusted {
                    continue;
                }
                let tx_hash = msg.tx.compute_tx_hash();
                {
                    let produced = self.cross_shard_produced.read().await;
                    let Some(produce_height) = produced.get(&tx_hash) else {
                        continue;
                    };
                    if msg.is_bounce()
                        && !crate::sharding::bounce_eligible(*produce_height, block.height)
                    {
                        continue;
                    }
                }
                if self.cross_shard_completed.read().await.contains(&tx_hash) {
                    continue;
                }
                {
                    let mut consumed = self.cross_shard_consumed.write().await;
                    if !consumed.insert(key) {
                        continue;
                    }
                }
                mutated = true;
                if !self.cross_shard_completed.write().await.insert(tx_hash) {
                    continue;
                }
                mutated = true;
                continue;
            }
            if self.is_cross_shard_consumed(&key).await {
                continue;
            }
            // Proof-checked here (not anchored): anchoring is a PROPOSAL-TIME
            // property enforced at propose+validate (runtime gates a block
            // through before it can finalize). Apply — including walk/adopt
            // replay of QC'd history — must accept proof-valid records: a
            // syncing node holds no headers for old heights yet, and the
            // block's QC is the trust for everything inside it. Requiring the
            // anchor here would make historical sync impossible (C1 design
            // note in `verify_anchored`).
            if !msg.verify_inclusion_strict() {
                continue;
            }
            if self.credit_native(&msg.tx.to, msg.tx.amount).await.is_err() {
                continue;
            }
            self.cross_shard_consumed.write().await.insert(key);
            mutated = true;
            credited += 1;
        }
        if mutated {
            // The replay sets are digest-covered (audit F1): any mutation must
            // move the commitment generation, or the next root read serves a
            // stale digest that cannot see the consume/produce/complete.
            self.bump_commitment_generation();
        }
        if credited > 0 {
            tracing::info!(
                "cross-shard inbound credited {credited} message(s) on shard {}",
                block.shard_id
            );
        }
        credited
    }

    /// Apply ONE inbound §9 two-phase-commit record to this shard's
    /// committed 2PC state. Returns true when the committed state changed.
    ///
    /// The record is the WHOLE state machine: every transition is a pure
    /// function of the committed record plus the message, so
    ///
    /// * a REPLAY of a record that was already applied is a no-op (the
    ///   record's phase is already past the transition), and
    /// * a CRASH mid-2PC resumes to the same decision, because the decision
    ///   lives in the committed record and not in the node's memory.
    ///
    /// The value movements live here too, so they are part of the canonical
    /// state transition (and therefore of the reorg replay path):
    ///
    /// * the TARGET credits the recipient exactly once, on the
    ///   `Prepared -> Committed` transition;
    /// * the SOURCE refunds the escrow exactly once, on the
    ///   `Prepared -> Aborted` transition.
    async fn apply_xpc_record(
        &self,
        msg: &crate::sharding::CrossShardMessage,
        height: u64,
    ) -> bool {
        use crate::sharding::CrossShardKind;
        use crate::xshard2pc::{XpcPhase, XpcRecord, XpcTransition};
        let tx = &msg.tx;
        let tx_hash = tx.compute_tx_hash();
        let existing = self.xpc_record(&tx_hash).await;
        match msg.kind() {
            // TARGET side: the source escrowed the value and asks us to
            // prepare. The proof is the SOURCE's account leaf - it proves the
            // sender really had the funds at the source's committed root.
            CrossShardKind::Prepare => {
                if !msg.verify_inclusion_strict() {
                    return false;
                }
                let transition = crate::xshard2pc::target_prepare(
                    existing.as_ref(),
                    tx,
                    tx.source_shard,
                    tx.target_shard,
                    height,
                );
                if transition != XpcTransition::Created {
                    return false;
                }
                let rec = XpcRecord::prepared(
                    tx.clone(),
                    tx.source_shard,
                    tx.target_shard,
                    height,
                );
                self.write_xpc_record(&rec).await;
                true
            }
            // SOURCE side: the target voted YES. The proof is the TARGET's
            // PREPARED leaf, so the vote is a fact of the target's committed
            // state (and not a claim the source could forge).
            CrossShardKind::PrepareAck => {
                if !msg.verify_xpc_proof(&[XpcPhase::Prepared]) {
                    return false;
                }
                let transition = crate::xshard2pc::source_on_prepare_ack(existing.as_ref(), height);
                if transition != XpcTransition::Advanced(XpcPhase::Committed) {
                    return false;
                }
                let Some(mut rec) = existing else {
                    return false;
                };
                rec.phase = XpcPhase::Committed;
                rec.decided_height = height;
                self.write_xpc_record(&rec).await;
                self.cross_shard_completed.write().await.insert(tx_hash);
                true
            }
            // TARGET side: the source decided COMMIT. The proof is the
            // SOURCE's PREPARED (or already COMMITTED) leaf: the source
            // really escrowed the value, so this is not a mint.
            CrossShardKind::Commit => {
                if !msg.verify_xpc_proof(&[XpcPhase::Prepared, XpcPhase::Committed]) {
                    return false;
                }
                let transition = crate::xshard2pc::target_on_commit(existing.as_ref(), height);
                if transition != XpcTransition::Advanced(XpcPhase::Committed) {
                    return false;
                }
                let Some(mut rec) = existing else {
                    return false;
                };
                // THE credit. Only reachable from PREPARED, so the recipient
                // is credited exactly once and never for an aborted transfer.
                if self.credit_native(&tx.to, tx.amount).await.is_err() {
                    return false;
                }
                rec.phase = XpcPhase::Committed;
                rec.decided_height = height;
                self.write_xpc_record(&rec).await;
                self.cross_shard_completed.write().await.insert(tx_hash);
                true
            }
            // TARGET side: the source asks us to abort. The proof is the
            // SOURCE's PREPARED leaf. A target that is already PREPARED
            // REFUSES: it has voted YES, and a 2PC participant that voted YES
            // must commit. That refusal is what blocks the double spend.
            CrossShardKind::AbortRequest => {
                if !msg.verify_xpc_proof(&[XpcPhase::Prepared, XpcPhase::Committed]) {
                    return false;
                }
                let transition = crate::xshard2pc::target_on_abort_request(existing.as_ref(), height);
                if transition != XpcTransition::Advanced(XpcPhase::Aborted) {
                    return false;
                }
                let rec = XpcRecord {
                    tx: tx.clone(),
                    tx_hash,
                    source_shard: tx.source_shard,
                    target_shard: tx.target_shard,
                    phase: XpcPhase::Aborted,
                    prepared_height: height,
                    decided_height: height,
                };
                self.write_xpc_record(&rec).await;
                true
            }
            // SOURCE side: the target authorises the abort. The proof is the
            // TARGET's ABORTED leaf - and the target can only hold that leaf
            // if it NEVER prepared, so a source that got a PREPARE-ACK can
            // never obtain this authorisation. THIS is the block on the
            // audit's double-spend attack.
            CrossShardKind::AbortAck => {
                if !msg.verify_xpc_proof(&[XpcPhase::Aborted]) {
                    return false;
                }
                let transition = crate::xshard2pc::source_on_abort_ack(existing.as_ref(), height);
                if transition != XpcTransition::Advanced(XpcPhase::Aborted) {
                    return false;
                }
                let Some(mut rec) = existing else {
                    return false;
                };
                // THE refund: the escrow goes back to the sender, exactly
                // once. A transfer that is already COMMITTED never reaches
                // this arm (the transition is refused above).
                if self.credit_native(&tx.from, tx.amount).await.is_err() {
                    return false;
                }
                rec.phase = XpcPhase::Aborted;
                rec.decided_height = height;
                self.write_xpc_record(&rec).await;
                self.cross_shard_completed.write().await.insert(tx_hash);
                true
            }
            _ => false,
        }
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
    /// `timestamp`, `proposer`, `height`, `precommit_qc`) or the one value the
    /// caller resolves from governance - see `crate::runtime::block_reward_for`,
    /// which both callers use. Nothing is read from the caller's local
    /// consensus state (`HeightConsensus`), which is why the two paths cannot
    /// disagree about what a block does.
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
    /// Single-height misses never slash anyway (`DOWNTIME_MISS_THRESHOLD`
    /// with cooldown in `note_missed_heights`), so the profitable-downtime
    /// window needs a sustained outage PLUS the staking fix above. Pinned by
    /// the F5 economic test (proposer-in-miss-set net outcome + matured-
    /// unbonding-intact assertions).
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
        block_reward: u64,
    ) -> BlockTransitionOutcome {
        // 0. Cross-shard INBOUND credits, committed by this block's
        //    `cross_shard_out` consumption records. This is a no-op unless the
        //    sharding gate is on (multi-shard process) AND the block actually
        //    carries inbound records, so every pre-sharding block is byte-for-
        //    byte unchanged. Outbound records are not applied here: the debit
        //    happens in step 1 via `commit_native`'s cross-shard branch.
        let _consumed = self.apply_cross_shard_consumptions(block).await;

        // 1. The transactions themselves (batched signature verify, admission,
        //    payload execution, native commit, trie write).
        let (applied, failed, fees, status, tx_fees, events) = self
            .apply_block_parallel_fees_with_events(&block.transactions, block.timestamp)
            .await;

        // 1b. §1 ACTOR MAILBOX: deliver every message this block's
        //     transactions queued (plus anything an earlier block left, which
        //     under Phase 1's drain-to-empty policy is nothing). ONCE per
        //     block, in one accounts write lock, in deterministic address
        //     order - the pass is what turns queued sends into credits,
        //     bounces and nested sends.
        let _actor_delivered = self.apply_actor_messages_at(block).await;

        // 2. Pay the collected fees to the proposer. The fees were already
        //    debited from senders in step 1, so this is a transfer, not a mint.
        if fees > 0 {
            let _ = self.credit_native(&block.proposer, fees).await;
        }

        // 3. Block reward to the proposer out of the staking emission (paid as
        //    pending rewards, claimed by a later `SysCallClaimRewards`).
        //
        //    E2: the mint is explicit and capped. `distribute_reward` funds the
        //    ledger's rewards pool (fail-closed over REWARDS_EMISSION_CAP);
        //    the native leg mints the SAME amount into REWARDS_POOL, so every
        //    later claim is backed 1:1 and bonded principal in STAKING_POOL is
        //    never touched. Mint native ONLY on Ok: a refused distribution
        //    (cap reached, unknown proposer) must not create coins.
        if block_reward > 0 {
            let distributed = self
                .staking_write()
                .await
                .distribute_reward(block.proposer, block_reward)
                .is_ok();
            if distributed {
                // Practically infallible (pool + reward < 2^64 by the cap),
                // but the two legs must stay 1:1: if the native mint ever
                // failed, the ledger mint is rolled back so a later claim
                // can never observe backing that has no coins.
                if self
                    .credit_native(&crate::staking::REWARDS_POOL, block_reward)
                    .await
                    .is_err()
                {
                    let mut l = self.staking_write().await;
                    l.rewards_pool = l.rewards_pool.saturating_sub(block_reward);
                    l.rewards_minted = l.rewards_minted.saturating_sub(block_reward);
                }
            }
        }

        // 4. Mature unbondings. Deterministic: the clock is the block's own
        //    timestamp, never local wall time.
        self.staking_write().await.process_unbonding(block.timestamp);

        // 5. Downtime slash, from the certificate the block carries. The
        //    evidence is block content, so every node that applies this block -
        //    locally finalized, adopted, walked, replayed or re-applied after a
        //    reorg - burns the same amount out of the same pool.
        let slashed = self
            .apply_downtime_slash(block.height, block.precommit_qc.as_ref())
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

        BlockTransitionOutcome {
            applied,
            failed,
            fees_collected: fees,
            status,
            tx_fees,
            slashed: slashed.saturating_add(eq_slashed),
            events,
        }
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
            None,
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
        let signers = cert.signers_set(&val_set);
        let eligible: Vec<[u8; 32]> = val_set
            .validators
            .keys()
            .copied()
            .collect();
        let burned = self.staking_write().await.note_missed_heights(
            height,
            &|v: &[u8; 32]| signers.contains(v),
            &eligible,
        );
        if burned > 0 {
            // The coins are real: take them out of the staking pool.
            let _ = self.debit_native(&crate::staking::STAKING_POOL, burned).await;
        }
        burned
    }

    /// Burn 5% of every double-signer named by block-carried equivocation
    /// evidence, debiting the burned coins from the staking pool.
    ///
    /// THE WIRED PATH (audit O1/F4). Deterministic end to end:
    ///
    ///  * CARRIER: the block BODY — `OpCode::SysCallReportEquivocation`
    ///    payloads in `block.transactions`, each envelope carrying BOTH
    ///    conflicting votes fully. Any node re-verifies from the bytes
    ///    alone; gossip observations (`HeightConsensus::equivocations()`)
    ///    are NEVER read here, so two nodes applying the same block by
    ///    different routes (finalize/adopt/walk/replay/reorg) burn the same
    ///    coins. Carried-invalid evidence (bad shape, forged signature,
    ///    unknown voter, oversize) burns 0 loudly — it is skipped, never
    ///    fatal. Scanning covers EVERY transaction payload regardless of
    ///    per-transaction success: the SVM arm already reverts invalid
    ///    reports at execution, but the scan re-verifies from bytes anyway,
    ///    so exec/scan skew can never move the slash.
    ///  * ORDER: [`crate::consensus::canonicalize_equivocation_evidence`]
    ///    verifies, sorts by offense key and drops in-block duplicates.
    ///    Canonical order is consensus-critical: sequential 5% burns for one
    ///    offender do NOT commute (each burn is a fraction of the remainder).
    ///  * DEDUP: [`crate::staking::StakingLedger::slash_equivocation_verified`]
    ///    consumes the per-offense key
    ///    (`offender ‖ height ‖ round ‖ kind ‖ conflicting hashes`) on first
    ///    processing — the same offense, re-included in any later block,
    ///    burns 0 on every node. Same offense slashed once per chain.
    ///  * CAP: at most
    ///    [`crate::consensus::MAX_BLOCK_EQUIVOCATION_EVIDENCES`] offenses per
    ///    block; extras are skipped loudly (and may ride a later block).
    ///
    /// Fail-closed throughout: when in doubt this refuses to slash and logs
    /// loudly (slash-wrongly is worse than slash-rarely). Never fails the
    /// block: hostile evidence costs the reporter gas, never the chain.
    pub async fn apply_equivocation_slash(&self, block: &crate::sharding::Block) -> u64 {
        let mut items: Vec<crate::consensus::EquivocationEvidence> = Vec::new();
        for tx in &block.transactions {
            for op in &tx.payload {
                if let crate::svm::OpCode::SysCallReportEquivocation { evidence } = op {
                    items.push((**evidence).clone());
                }
            }
        }
        if items.is_empty() {
            return 0;
        }
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
        if ordered.is_empty() {
            return 0;
        }
        if ordered.len() > crate::consensus::MAX_BLOCK_EQUIVOCATION_EVIDENCES {
            tracing::warn!(
                "equivocation: {} valid evidences exceed per-block cap {} — extras skipped (may ride a later block)",
                ordered.len(),
                crate::consensus::MAX_BLOCK_EQUIVOCATION_EVIDENCES,
            );
        }
        let mut total = 0u64;
        for ev in ordered
            .into_iter()
            .take(crate::consensus::MAX_BLOCK_EQUIVOCATION_EVIDENCES)
        {
            // Fail-closed per evidence: an unknown voter (membership moved
            // since shaping) burns 0 with a loud WARN instead of failing
            // the block; a repeat offense burns 0 via the ledger dedup.
            let burned = match self
                .staking_write()
                .await
                .slash_equivocation_verified(&ev)
            {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(
                        "equivocation evidence for {} skipped ({e}): refusing to slash",
                        hex::encode(ev.voter),
                    );
                    0
                }
            };
            if burned > 0 {
                // The coins are real: take them out of the staking pool,
                // exactly like the downtime path above.
                let _ = self
                    .debit_native(&crate::staking::STAKING_POOL, burned)
                    .await;
                total = total.saturating_add(burned);
            }
        }
        total
    }

    /// Verify a block's signatures in one batch (parallel-friendly fast path).
    pub fn verify_block_signatures(txs: &[crate::sharding::Transaction]) -> bool {
        crate::sharding::Transaction::verify_signatures_batch(txs)
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
    async fn commit_consensus_domains_if_stale(&self) {
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

        let snapshot = self.commitment_snapshot().await;
        // §9 + §2 FOLD POINT: the shielded ledger and the zkML model registry
        // join the digest here. Their read guards are TEMPORARIES - cloned and
        // released inside these statements, so they are never held across
        // `commitment_snapshot` (which awaits other subsystem locks while a
        // payload may be holding theirs and waiting for this one).
        // `commitment_digest_with_confidential_and_zkml` appends
        // `write_confidential_domain`, `write_zkml_models_domain` and
        // `write_zkml_vks_domain`, all of which write ZERO bytes while their
        // state is empty, so untouched domains digest byte-identically to
        // `commitment_digest`: no COMMITMENT_VERSION bump, no re-root of the
        // pinned genesis KAT.
        let confidential = self.confidential.read().await.clone();
        let zkml_models = self.zkml_models.read().await.clone();
        let digest = crate::commitment::commitment_digest_with_confidential_and_zkml(
            &snapshot,
            &confidential,
            &zkml_models,
        );
        self.state_trie
            .write()
            .await
            .insert(&crate::commitment::commitment_key(), &digest);

        // Record the generation we observed. If a mutation raced in after the load
        // but before this store, the stored stamp is stale and the next call
        // recomputes -- the safe direction.
        self.committed_generation
            .store(stamp, std::sync::atomic::Ordering::Release);
    }

    /// Take a writer lock on a committed subsystem and mark the commitment dirty.
    ///
    /// Every mutation of consensus-visible state must go through this, not
    /// `field.write()` directly. Getting that wrong in one direction is benign (an
    /// extra recomputation); in the other it returns a STALE STATE ROOT, which is the
    /// kind of bug that splits a network with no attacker involved. Wrapping the lock
    /// makes the two impossible to separate by accident.
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
        Self::mut_guard(&self.commitment_generation, &self.tokens).await
    }

    pub async fn staking_read(
        &self,
    ) -> tokio::sync::RwLockReadGuard<'_, crate::staking::StakingLedger> {
        self.staking.read().await
    }

    pub async fn staking_write(
        &self,
    ) -> tokio::sync::RwLockWriteGuard<'_, crate::staking::StakingLedger> {
        Self::mut_guard(&self.commitment_generation, &self.staking).await
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
    pub fn staking_handle(&self) -> std::sync::Arc<tokio::sync::RwLock<crate::staking::StakingLedger>> {
        std::sync::Arc::clone(&self.staking)
    }

    /// Shared handle to the governance lock. Same contract as `staking_handle`:
    /// reads are always safe; every write must go through `governance_write`.
    pub fn governance_handle(&self) -> std::sync::Arc<tokio::sync::RwLock<crate::governance::Governance>> {
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
        Self::mut_guard(&self.commitment_generation, &self.orderbooks).await
    }

    pub async fn order_escrow_read(
        &self,
    ) -> tokio::sync::RwLockReadGuard<'_, HashMap<(u32, u64), EscrowRecord>> {
        self.order_escrow.read().await
    }

    pub async fn order_escrow_write(
        &self,
    ) -> tokio::sync::RwLockWriteGuard<'_, HashMap<(u32, u64), EscrowRecord>> {
        Self::mut_guard(&self.commitment_generation, &self.order_escrow).await
    }

    pub async fn pmm_read(
        &self,
    ) -> tokio::sync::RwLockReadGuard<'_, crate::pmm::PrimaryMarketMaker> {
        self.pmm.read().await
    }

    pub async fn pmm_write(
        &self,
    ) -> tokio::sync::RwLockWriteGuard<'_, crate::pmm::PrimaryMarketMaker> {
        Self::mut_guard(&self.commitment_generation, &self.pmm).await
    }

    pub async fn pmm_usdt_token_read(&self) -> tokio::sync::RwLockReadGuard<'_, Option<[u8; 32]>> {
        self.pmm_usdt_token.read().await
    }

    pub async fn pmm_usdt_token_write(
        &self,
    ) -> tokio::sync::RwLockWriteGuard<'_, Option<[u8; 32]>> {
        Self::mut_guard(&self.commitment_generation, &self.pmm_usdt_token).await
    }

    pub async fn pmm_treasury_read(&self) -> tokio::sync::RwLockReadGuard<'_, [u8; 32]> {
        self.pmm_treasury.read().await
    }

    pub async fn pmm_treasury_write(&self) -> tokio::sync::RwLockWriteGuard<'_, [u8; 32]> {
        Self::mut_guard(&self.commitment_generation, &self.pmm_treasury).await
    }

    pub async fn contracts_read(
        &self,
    ) -> tokio::sync::RwLockReadGuard<'_, crate::contract::ContractRegistry> {
        self.contracts.read().await
    }

    pub async fn contracts_write(
        &self,
    ) -> tokio::sync::RwLockWriteGuard<'_, crate::contract::ContractRegistry> {
        Self::mut_guard(&self.commitment_generation, &self.contracts).await
    }

    pub async fn governance_read(
        &self,
    ) -> tokio::sync::RwLockReadGuard<'_, crate::governance::Governance> {
        self.governance.read().await
    }

    pub async fn governance_write(
        &self,
    ) -> tokio::sync::RwLockWriteGuard<'_, crate::governance::Governance> {
        Self::mut_guard(&self.commitment_generation, &self.governance).await
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
        Self::mut_guard(&self.commitment_generation, &self.oracle).await
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
        Self::mut_guard(&self.commitment_generation, &self.session_keys).await
    }

    /// Read the shielded ledger (the VM's clone source, the commitment fold,
    /// receipts). Reads cannot make the commitment stale, so this does NOT
    /// bump the generation - and the guard must be dropped before any other
    /// subsystem lock is taken, exactly like `commitment_snapshot`'s fields.
    pub async fn confidential_read(
        &self,
    ) -> tokio::sync::RwLockReadGuard<'_, crate::crypto_privacy::ConfidentialState> {
        self.confidential.read().await
    }

    /// Write access to the shielded ledger: applying a confidential transfer
    /// bumps `commitment_generation`, so the very next root read folds the new
    /// balances, spent inputs and fee total into the state root.
    pub async fn confidential_write(
        &self,
    ) -> tokio::sync::RwLockWriteGuard<'_, crate::crypto_privacy::ConfidentialState> {
        Self::mut_guard(&self.commitment_generation, &self.confidential).await
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
        Self::mut_guard(&self.commitment_generation, &self.zkml_models).await
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
        let reg: crate::zkml::SessionKeyRegistry = bincode::deserialize(bytes)
            .map_err(|e| format!("restore session keys failed: {e:?}"))?;
        *self.session_keys_write().await = reg;
        Ok(())
    }

    /// Install a snapshot-sync `pq_keys` blob (audit F7).
    ///
    /// Wire format is `Storage::export_pq_keys_blob`: bincode of the raw
    /// `(key, value)` pairs of the `pq_keys` sled tree (namespaced `a:` /
    /// `h:` keys, see `storage.rs`). Install rule, in order:
    /// * attached persistent tree (`attach_pq_tree`): insert every pair
    ///   verbatim — the synced node then serves the publisher's keys from
    ///   disk exactly as the publisher did;
    /// * diskless fallback: decode the `a:`-namespaced address records into
    ///   the bounded in-memory LRU (`h:` hash-lookup records are skipped —
    ///   they are derivable from the address records and the LRU is keyed by
    ///   address only). Bounded like every Phase-1 cache: past the cap the
    ///   coldest entry is evicted LOUDLY and re-served from... nothing (no
    ///   disk) — which is why diskless nodes are tests-only: an evicted key
    ///   refuses its PQ-gated admission until gossip re-pins it
    ///   (availability, never a fork; a MISS here never attests anything).
    ///
    /// Corrupt bytes are a hard error (fail closed — installing a truncated
    /// key set as complete would refuse honest PQ transactions silently).
    /// PQ keys are NOT part of the state root (they ride the accounts
    /// snapshot's pinned `pubkey_hash`), so installing them never moves the
    /// root and needs no generation bump.
    pub async fn restore_pq_keys(&self, bytes: &[u8]) -> Result<(), String> {
        let pairs: Vec<(Vec<u8>, Vec<u8>)> = bincode::deserialize(bytes)
            .map_err(|e| format!("restore pq_keys failed: {e:?}"))?;
        if let Some(tree) = self.pq_tree.read().unwrap().clone() {
            for (k, v) in &pairs {
                tree.insert(k.as_slice(), v.as_slice())
                    .map_err(|e| format!("restore pq_keys tree insert failed: {e}"))?;
            }
            return Ok(());
        }
        let mut fb = self.pq_keys_fallback.write().unwrap();
        for (k, v) in &pairs {
            // Address records only (`a:` + 32B); hash-lookup (`h:`) and
            // legacy/unknown shapes carry no address to index by.
            if k.len() != 34 || k[0] != b'a' || k[1] != b':' {
                continue;
            }
            let mut addr = [0u8; 32];
            addr.copy_from_slice(&k[2..]);
            let rec: Option<(crate::post_quantum::PqScheme, Vec<u8>)> =
                if let Ok((s, pk, _salt)) = bincode::deserialize::<(
                    crate::post_quantum::PqScheme,
                    Vec<u8>,
                    [u8; 16],
                )>(v)
                {
                    Some((s, pk))
                } else if let Ok((s, pk)) = bincode::deserialize::<(
                    crate::post_quantum::PqScheme,
                    Vec<u8>,
                )>(v)
                {
                    Some((s, pk))
                } else {
                    None
                };
            if let Some((scheme, pk)) = rec {
                fb.insert(addr, (scheme, pk));
            }
        }
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
        if tx.payload.iter().any(|op| {
            matches!(op, crate::svm::OpCode::SysCallRevokeSession { .. })
        }) {
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
    async fn session_note_applied(&self, tx: &crate::sharding::Transaction, gas_used: u64) {
        let Some(d) = tx.delegation() else {
            return;
        };
        let mut reg = self.session_keys_write().await;
        reg.note_applied(&d, gas_used);
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
        // §9 + §2 FOLD POINT (the unconditional twin of the one in
        // `commit_consensus_domains_if_stale`): same conditional domains, same
        // transient read guards, so both entry points commit byte-identical
        // digests for the same state.
        let confidential = self.confidential.read().await.clone();
        let zkml_models = self.zkml_models.read().await.clone();
        let digest = crate::commitment::commitment_digest_with_confidential_and_zkml(
            &snapshot,
            &confidential,
            &zkml_models,
        );
        self.state_trie
            .write()
            .await
            .insert(&crate::commitment::commitment_key(), &digest);
        self.committed_generation
            .store(generation.wrapping_add(1), std::sync::atomic::Ordering::Release);
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

    // ==================== Fungible Token (STS) Integration ====================

    /// Deploy a new on-chain fungible token. Returns its deterministic token ID.
    /// Initial balances and total supply are committed into the state trie.
    pub async fn create_token(
        &self,
        creator: [u8; 32],
        metadata: TokenMetadata,
        initial_supply: u64,
    ) -> Result<[u8; 32], TokenError> {
        let mut tokens = Self::mut_guard(&self.commitment_generation, &self.tokens).await;
        let id = tokens.create_token(creator, metadata, initial_supply)?;

        // Commit initial balances + supply into the state trie so they become
        // part of the consensus state root and are SPV-provable.
        let mut trie = self.state_trie.write().await;
        if let Some(token) = tokens.get(&id) {
            let accounts: Vec<[u8; 32]> = token.balances.keys().copied().collect();
            for acct in accounts {
                let bal = token.balance_of(&acct);
                let key = token_balance_key(&id, &acct);
                trie.insert(&key, &bal.to_be_bytes());
            }
            trie.insert(&token_supply_key(&id), &token.metadata.total_supply.to_be_bytes());
        }
        Ok(id)
    }

    // ==================== WASM Contracts (on-chain) ====================

    /// Deploy a validated WASM contract and commit its code hash to the state
    /// trie (SPV-provable). Returns the deterministic contract address.
    pub async fn deploy_contract(
        &self,
        creator: [u8; 32],
        code: Vec<u8>,
        now: u64,
    ) -> Result<[u8; 32], crate::contract::ContractError> {
        let mut contracts = Self::mut_guard(&self.commitment_generation, &self.contracts).await;
        let address = contracts.deploy(creator, code, now)?;
        let code_hash = contracts.get(&address).map(|c| c.code_hash).unwrap_or([0u8; 32]);
        let mut trie = self.state_trie.write().await;
        trie.insert(&contract_key(&address), &code_hash);
        Ok(address)
    }

    /// Deploy a validated WASM contract with a typed ABI manifest attached.
    ///
    /// The manifest is committed to the state trie next to the code hash.
    pub async fn deploy_contract_with_abi(
        &self,
        creator: [u8; 32],
        code: Vec<u8>,
        now: u64,
        abi: crate::contract_abi::ContractAbi,
    ) -> Result<[u8; 32], crate::contract::ContractError> {
        let mut contracts = Self::mut_guard(&self.commitment_generation, &self.contracts).await;
        let address = contracts.deploy_with_abi(creator, code, now, abi.clone())?;
        let code_hash = contracts.get(&address).map(|c| c.code_hash).unwrap_or([0u8; 32]);
        let mut trie = self.state_trie.write().await;
        trie.insert(&contract_key(&address), &code_hash);
        trie.insert(&contract_abi_key(&address), abi.to_json().as_bytes());
        Ok(address)
    }

    /// Attach (or replace) the ABI manifest of a deployed contract and commit
    /// it to the state trie next to the code hash.
    pub async fn set_contract_abi(
        &self,
        address: &[u8; 32],
        abi: crate::contract_abi::ContractAbi,
    ) -> Result<(), crate::contract::ContractError> {
        {
            let mut contracts = Self::mut_guard(&self.commitment_generation, &self.contracts).await;
            contracts.set_abi(address, abi.clone())?;
        }
        let mut trie = self.state_trie.write().await;
        trie.insert(&contract_abi_key(address), abi.to_json().as_bytes());
        Ok(())
    }

    /// The ABI manifest of a deployed contract, if one is attached.
    pub async fn get_contract_abi(&self, address: &[u8; 32]) -> Option<crate::contract_abi::ContractAbi> {
        self.contracts.read().await.abi(address).cloned()
    }

    /// The JSON ABI manifest of a deployed contract, if one is attached.
    pub async fn get_contract_abi_json(&self, address: &[u8; 32]) -> Option<String> {
        self.contracts.read().await.abi_json(address)
    }

    /// Deploy a validated WASM contract with deterministic address derivation:
    /// BLAKE3("STELL_CONTRACT" || code_hash || salt).
    /// Deploys WASM code to state trie under contract address and commits code_hash.
    pub async fn deploy_contract_deterministic(
        &self,
        creator: [u8; 32],
        code: Vec<u8>,
        salt: &[u8],
        now: u64,
    ) -> Result<DeployOutcome, crate::contract::ContractError> {
        self.deploy_contract_deterministic_inner(creator, code, salt, now, None)
            .await
    }

    /// Deploy a validated WASM contract with deterministic address derivation
    /// and a typed ABI manifest attached.
    pub async fn deploy_contract_deterministic_with_abi(
        &self,
        creator: [u8; 32],
        code: Vec<u8>,
        salt: &[u8],
        now: u64,
        abi: crate::contract_abi::ContractAbi,
    ) -> Result<DeployOutcome, crate::contract::ContractError> {
        self.deploy_contract_deterministic_inner(creator, code, salt, now, Some(abi))
            .await
    }

    async fn deploy_contract_deterministic_inner(
        &self,
        creator: [u8; 32],
        code: Vec<u8>,
        salt: &[u8],
        now: u64,
        abi: Option<crate::contract_abi::ContractAbi>,
    ) -> Result<DeployOutcome, crate::contract::ContractError> {
        crate::contract::ContractRegistry::validate_code(&code)?;
        if let Some(a) = &abi {
            a.validate()
                .map_err(|e| crate::contract::ContractError::InvalidAbi(e.to_string()))?;
        }
        let code_hash: [u8; 32] = *blake3::hash(&code).as_bytes();
        let address = compute_contract_address(&code_hash, salt);

        let mut contracts = Self::mut_guard(&self.commitment_generation, &self.contracts).await;
        if contracts.contracts.contains_key(&address) {
            return Err(crate::contract::ContractError::AlreadyExists);
        }
        contracts.contracts.insert(
            address,
            crate::contract::Contract {
                address,
                creator,
                code_hash,
                code: code.clone(),
                storage: std::collections::HashMap::new(),
                created_at: now,
                paused: false,
                balance: 0,
                abi: abi.clone(),
            },
        );
        drop(contracts);

        let mut trie = self.state_trie.write().await;
        // Deploy WASM code to state trie under contract address
        trie.insert(&address, &code);
        trie.insert(&contract_key(&address), &code_hash);
        match &abi {
            Some(a) => {
                trie.insert(&contract_abi_key(&address), a.to_json().as_bytes());
            }
            None => {
                trie.remove(&contract_abi_key(&address));
            }
        }
        drop(trie);

        let contract_address_stl57 = crate::address::encode_stl57_address(&address);
        Ok(DeployOutcome {
            contract_address: address,
            contract_address_stl57,
            code_hash,
        })
    }

    /// Retrieve WASM code deployed in state trie under contract address.
    pub async fn get_contract_code_from_trie(&self, address: &[u8; 32]) -> Option<Vec<u8>> {
        let trie = self.state_trie.read().await;
        trie.get(address).map(|b| b.to_vec())
    }

    /// Call an exported method on a deployed contract and return a structured outcome.
    /// Following the TON / Near receipt model: (status, return_value, gas_used, events).
    pub async fn call_contract_structured(
        &self,
        address: &[u8; 32],
        method: &str,
        arg: i64,
        fuel: u64,
    ) -> ContractCallOutcome {
        self.sync_contract_balance(address).await;
        let res = {
            let mut contracts = Self::mut_guard(&self.commitment_generation, &self.contracts).await;
            contracts.call(address, method, arg, fuel)
        };
        self.sync_account_balance_from_contract(address).await;
        match res {
            Ok((val, used, events, messages)) => {
                if !messages.is_empty() {
                    let _ = self.process_contract_outbound_messages(&messages).await;
                }
                ContractCallOutcome {
                    status: "success".to_string(),
                    return_value: Some(val),
                    gas_used: used,
                    events,
                    error: None,
                }
            }
            Err(e) => {
                let (gas_used, err_msg) = match &e {
                    crate::contract::ContractError::OutOfFuel => (fuel, e.to_string()),
                    _ => (0, e.to_string()),
                };
                ContractCallOutcome {
                    status: "failed".to_string(),
                    return_value: None,
                    gas_used,
                    events: Vec::new(),
                    error: Some(err_msg),
                }
            }
        }
    }

    /// Call an exported method with several `i64` parameters and return a
    /// structured outcome.
    pub async fn call_contract_args_structured(
        &self,
        address: &[u8; 32],
        method: &str,
        args: &[i64],
        fuel: u64,
    ) -> ContractCallOutcome {
        self.sync_contract_balance(address).await;
        let res = {
            let mut contracts = Self::mut_guard(&self.commitment_generation, &self.contracts).await;
            contracts.call_args(address, method, args, fuel)
        };
        self.sync_account_balance_from_contract(address).await;
        match res {
            Ok((val, used, events, messages)) => {
                if !messages.is_empty() {
                    let _ = self.process_contract_outbound_messages(&messages).await;
                }
                ContractCallOutcome {
                    status: "success".to_string(),
                    return_value: Some(val),
                    gas_used: used,
                    events,
                    error: None,
                }
            }
            Err(e) => {
                let (gas_used, err_msg) = match &e {
                    crate::contract::ContractError::OutOfFuel => (fuel, e.to_string()),
                    _ => (0, e.to_string()),
                };
                ContractCallOutcome {
                    status: "failed".to_string(),
                    return_value: None,
                    gas_used,
                    events: Vec::new(),
                    error: Some(err_msg),
                }
            }
        }
    }

    /// Call an exported method with typed ABI arguments and return a
    /// structured outcome. The contract's ABI manifest is authoritative.
    pub async fn call_contract_abi_structured(
        &self,
        address: &[u8; 32],
        method: &str,
        args: &[crate::contract_abi::AbiValue],
        fuel: u64,
    ) -> ContractCallOutcome {
        self.sync_contract_balance(address).await;
        let res = {
            let mut contracts = Self::mut_guard(&self.commitment_generation, &self.contracts).await;
            contracts.call_abi(address, method, args, fuel)
        };
        self.sync_account_balance_from_contract(address).await;
        match res {
            Ok(outcome) => {
                if !outcome.outbound_messages.is_empty() {
                    let _ = self.process_contract_outbound_messages(&outcome.outbound_messages).await;
                }
                ContractCallOutcome {
                    status: "success".to_string(),
                    return_value: Some(outcome.result),
                    gas_used: outcome.fuel_used,
                    events: outcome.events,
                    error: None,
                }
            }
            Err(e) => {
                let (gas_used, err_msg) = match &e {
                    crate::contract::ContractError::OutOfFuel => (fuel, e.to_string()),
                    _ => (0, e.to_string()),
                };
                ContractCallOutcome {
                    status: "failed".to_string(),
                    return_value: None,
                    gas_used,
                    events: Vec::new(),
                    error: Some(err_msg),
                }
            }
        }
    }

    /// Call a contract with structured outcome and optional value transfer.
    pub async fn call_contract_structured_with_value(
        &self,
        caller: Option<[u8; 32]>,
        address: &[u8; 32],
        method: &str,
        arg: i64,
        fuel: u64,
        value: u64,
    ) -> ContractCallOutcome {
        if value > 0 {
            if let Some(c) = caller {
                if let Err(e) = self.debit_native(&c, value).await {
                    return ContractCallOutcome {
                        status: "failed".to_string(),
                        return_value: None,
                        gas_used: 0,
                        events: Vec::new(),
                        error: Some(format!("insufficient funds to transfer value: {e}")),
                    };
                }
                let _ = self.credit_native(address, value).await;
            }
        }
        self.call_contract_structured(address, method, arg, fuel).await
    }

    /// Return the shard id this engine is operating on.
    pub fn shard_id(&self) -> u32 {
        self.shard_id.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Set the shard id for this engine.
    pub fn set_shard_id(&self, id: u32) {
        self.shard_id.store(id, std::sync::atomic::Ordering::Release);
    }

    /// Read the node's shard topology.
    ///
    /// The topology is the single source of truth of the address→shard rule
    /// (see `crate::sharding::ROUTING_RULE`).
    pub async fn shard_topology(&self) -> tokio::sync::RwLockReadGuard<'_, crate::sharding::ShardTopology> {
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
        }

        // 3. Token balances, owned by the HOLDER; token supplies, owned by
        //    the token's minter (the address that created it).
        for (token_id, token) in self.tokens.read().await.tokens.iter() {
            for (holder, _bal) in token.balances.iter() {
                manifest.own(crate::state_engine::token_balance_key(token_id, holder), *holder);
            }
            manifest.own(
                crate::state_engine::token_supply_key(token_id),
                token.metadata.minter,
            );
        }

        manifest
    }

    /// Process outbound contract messages:
    /// - If recipient is local, route to actor inbox (`inbox.push_back`).
    /// - If recipient is on another shard, route to `cross_shard_out` with bounce capability.
    pub async fn process_contract_outbound_messages(
        &self,
        messages: &[crate::contract::ContractMessage],
    ) -> Result<(), String> {
        if messages.is_empty() {
            return Ok(());
        }
        let my_shard = self.shard_id();
        let sharded = self.cross_shard_enabled();
        let topology = self.shard_topology.read().await.clone();
        let mut map = self.accounts.write().await;
        let mut xout = self.cross_shard_out.write().await;
        crate::svm::Svm::route_contract_messages_with_topology(
            messages,
            &mut *map,
            &mut *xout,
            my_shard,
            sharded,
            &topology,
        );
        Ok(())
    }

    /// Take and drain all queued outbound cross-shard messages.
    pub async fn take_cross_shard_out(&self) -> Vec<crate::sharding::CrossShardMessage> {
        let mut out = self.cross_shard_out.write().await;
        std::mem::take(&mut *out)
    }

    /// Retrieve a snapshot of queued outbound cross-shard messages without draining.
    pub async fn get_cross_shard_out(&self) -> Vec<crate::sharding::CrossShardMessage> {
        self.cross_shard_out.read().await.clone()
    }

    /// Call an exported `(i64) -> i64` method on a deployed contract.
    pub async fn call_contract(
        &self,
        address: &[u8; 32],
        method: &str,
        arg: i64,
        fuel: u64,
    ) -> Result<(i64, u64), crate::contract::ContractError> {
        self.sync_contract_balance(address).await;
        let (val, used, _events, messages) = Self::mut_guard(&self.commitment_generation, &self.contracts).await.call(address, method, arg, fuel)?;
        self.sync_account_balance_from_contract(address).await;
        if !messages.is_empty() {
            let _ = self.process_contract_outbound_messages(&messages).await;
        }
        Ok((val, used))
    }

    /// Call an exported method with several `i64` parameters on a deployed contract.
    pub async fn call_contract_args(
        &self,
        address: &[u8; 32],
        method: &str,
        args: &[i64],
        fuel: u64,
    ) -> Result<(i64, u64), crate::contract::ContractError> {
        self.sync_contract_balance(address).await;
        let (val, used, _events, messages) = Self::mut_guard(&self.commitment_generation, &self.contracts).await.call_args(address, method, args, fuel)?;
        self.sync_account_balance_from_contract(address).await;
        if !messages.is_empty() {
            let _ = self.process_contract_outbound_messages(&messages).await;
        }
        Ok((val, used))
    }

    /// Call a contract and return the emitted events.
    pub async fn call_contract_with_events(
        &self,
        address: &[u8; 32],
        method: &str,
        arg: i64,
        fuel: u64,
    ) -> Result<(i64, u64, Vec<crate::contract::ContractEvent>), crate::contract::ContractError> {
        self.sync_contract_balance(address).await;
        let (val, used, events, messages) = Self::mut_guard(&self.commitment_generation, &self.contracts).await.call(address, method, arg, fuel)?;
        self.sync_account_balance_from_contract(address).await;
        if !messages.is_empty() {
            let _ = self.process_contract_outbound_messages(&messages).await;
        }
        Ok((val, used, events))
    }

    /// Call a contract and return events along with outbound messages.
    pub async fn call_contract_with_messages(
        &self,
        address: &[u8; 32],
        method: &str,
        arg: i64,
        fuel: u64,
    ) -> Result<(i64, u64, Vec<crate::contract::ContractEvent>, Vec<crate::contract::ContractMessage>), crate::contract::ContractError> {
        self.sync_contract_balance(address).await;
        let (val, used, events, messages) = Self::mut_guard(&self.commitment_generation, &self.contracts).await.call(address, method, arg, fuel)?;
        self.sync_account_balance_from_contract(address).await;
        if !messages.is_empty() {
            let _ = self.process_contract_outbound_messages(&messages).await;
        }
        Ok((val, used, events, messages))
    }

    pub async fn sync_contract_balance(&self, address: &[u8; 32]) {
        if let Some(acc) = self.accounts.read().await.get(address) {
            let mut reg = Self::mut_guard(&self.commitment_generation, &self.contracts).await;
            if let Some(c) = reg.contracts.get_mut(address) {
                if acc.balance > c.balance {
                    c.balance = acc.balance;
                }
            }
        }
    }

    pub async fn sync_account_balance_from_contract(&self, address: &[u8; 32]) {
        let reg = self.contracts.read().await;
        if let Some(c) = reg.get(address) {
            let mut map = self.accounts.write().await;
            if let Some(acc) = map.get_mut(address) {
                acc.balance = c.balance;
            }
        }
    }

    /// Read-only getter execution against a cloned working state of the contract (matching TON runGetMethod / Near call_function / MultiversX vm-values/query).
    ///
    /// - Read-only execution against a cloned working state of the contract.
    /// - Zero state changes: mutations to storage or balances are immediately discarded.
    /// - Zero gas fee charged to any account.
    /// - Bounded by a safety fuel limit (e.g. 5,000,000 fuel) to prevent infinite loops.
    pub async fn run_get_method(
        &self,
        address: &[u8; 32],
        method: &str,
        args: &[i64],
        fuel_limit: Option<u64>,
    ) -> crate::contract::GetMethodResponse {
        let contracts = self.contracts.read().await;
        contracts.run_get_method(address, method, args, fuel_limit)
    }

    /// Read-only getter execution validated against the contract's ABI
    /// manifest: the method and its arguments must match the manifest, and
    /// the typed return value is decoded from the outcome.
    pub async fn run_get_method_typed(
        &self,
        address: &[u8; 32],
        method: &str,
        args: &[crate::contract_abi::AbiValue],
        fuel_limit: Option<u64>,
    ) -> crate::contract::GetMethodResponse {
        let contracts = self.contracts.read().await;
        contracts.run_get_method_typed(address, method, args, fuel_limit)
    }

    /// Read-only getter execution with a single `i64` argument.
    pub async fn run_get_method_single(
        &self,
        address: &[u8; 32],
        method: &str,
        arg: i64,
        fuel_limit: Option<u64>,
    ) -> crate::contract::GetMethodResponse {
        self.run_get_method(address, method, &[arg], fuel_limit).await
    }

    /// Read-only getter execution with optional block height pinning.
    pub async fn run_get_method_with_height(
        &self,
        address: &[u8; 32],
        method: &str,
        args: &[i64],
        fuel_limit: Option<u64>,
        current_height: u64,
        pin_height: Option<u64>,
    ) -> crate::contract::GetMethodResponse {
        if let Some(pin) = pin_height {
            if pin > current_height {
                return crate::contract::GetMethodResponse::error(
                    format!("pinned block height {pin} exceeds current finalized height {current_height}"),
                    0,
                );
            }
        }
        self.run_get_method(address, method, args, fuel_limit).await
    }

    pub async fn get_contract(&self, address: &[u8; 32]) -> Option<crate::contract::Contract> {
        self.contracts.read().await.get(address).cloned()
    }

    pub async fn contract_count(&self) -> usize {
        self.contracts.read().await.contracts.len()
    }

    pub async fn all_contract_addresses(&self) -> Vec<[u8; 32]> {
        self.contracts.read().await.contracts.keys().copied().collect()
    }

    /// Persist the whole contract registry (mirrors the token snapshot API).
    pub async fn create_contract_snapshot(&self) -> Vec<u8> {
        let c = self.contracts.read().await;
        bincode::serialize(&*c).unwrap_or_default()
    }

    pub async fn restore_contract_snapshot(&self, bytes: &[u8]) -> Result<(), String> {
        let reg: crate::contract::ContractRegistry = bincode::deserialize(bytes)
            .map_err(|e| format!("Restore contract snapshot failed: {:?}", e))?;
        let mut contracts = Self::mut_guard(&self.commitment_generation, &self.contracts).await;
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

    // ==================== CLOB settlement (A7) ====================

    /// Quote value (wUSDT micro-units) for `base_nano` STELL at `price_micro` USD.
    fn clob_quote_value(price_micro: u64, base_nano: u64) -> u64 {
        ClobQuoteMode::Wusdt.quote(price_micro, base_nano)
    }

    /// Quote value in native nano-STELL under the SVM path's convention - the
    /// same number `SysCallPlaceOrder` calls `order_cost`.
    fn clob_quote_native(price_micro: u64, base_nano: u64) -> u64 {
        let prod = (price_micro as u128) * (base_nano as u128);
        (prod / 1_000_000u128).min(u64::MAX as u128) as u64
    }

    /// Place an order on the native CLOB and SETTLE matched trades against real
    /// balances: the buyer pays wUSDT and receives native STELL; the seller pays
    /// native STELL and receives wUSDT. It is all-or-nothing: if any counterparty
    /// cannot fund its side, the whole call reverts (no partial settlement, no
    /// free fills). Previously the orderbook matched orders without moving any
    /// funds at all (A7).
    ///
    /// Resting (unfilled) limit remainders ARE escrowed at placement time: a
    /// sell locks its base STELL, a buy locks its quote - burned out of the
    /// trader's wUSDT under this entry point's convention. The SVM path
    /// (`SysCallPlaceOrder` -> `settle_clob_effects`) locks the same way but
    /// prices the quote in native units, because that is what its affordability
    /// check sees; whichever entry point placed an order, its escrow is released
    /// in the asset it was locked in (see `EscrowRecord`).
    pub async fn place_order_settled(
        &self,
        pair: u32,
        trader: [u8; 32],
        side: crate::orderbook::OrderSide,
        order_type: crate::orderbook::OrderType,
        price: u64,
        amount: u64,
        now: u64,
    ) -> Result<(u64, usize), String> {
        // Priority gates, FIRST and unchanged from the SVM path: breaker
        // latch, USDT peg, deviation against the committed price. This entry
        // point used to be a way to place an order without ever consulting the
        // oracle, i.e. a bypass; `OracleState::gate_order` is the same call
        // `SysCallPlaceOrder` makes, so the two can no longer disagree.
        // Read-only since E3 (an order never latches the breaker).
        {
            let oracle = self.oracle.read().await;
            oracle.gate_order(pair, price)?;
        }

        let quote_id = self
            .pmm_usdt_token
            .read()
            .await
            .ok_or_else(|| "CLOB quote (wUSDT) token not configured".to_string())?;

        // 1) Match on a CLONE of the book so nothing commits until settled.
        let mut book = self
            .orderbooks
            .read()
            .await
            .books
            .get(&pair)
            .cloned()
            .unwrap_or_else(|| crate::orderbook::OrderbookActor::new(pair, 1000));
        let (order, trades) = book.submit_order_bounded(
            trader,
            side.clone(),
            order_type.clone(),
            price,
            amount,
            now,
            crate::svm::MAX_MATCH_LEVELS,
        );
        let taker_is_buyer = matches!(side, crate::orderbook::OrderSide::Buy);
        let is_limit = matches!(order_type, crate::orderbook::OrderType::Limit);
        let unfilled = order.amount.saturating_sub(order.filled);

        if trades.is_empty() {
            // Resting limit order without immediate fills locks escrow immediately.
            // The order is locked for exactly what the BOOK holds of it: a full
            // book can silently refuse the newcomer (see `submit_order_bounded`),
            // and an escrow record for an order that is not resting is the very
            // orphan `cancel_order_settled` can never release (it looks the order
            // up in the book and finds nothing).
            if is_limit && unfilled > 0 && book.find_order(order.order_id).is_some() {
                if taker_is_buyer {
                    let q_escrow = Self::clob_quote_value(price, unfilled);
                    let mut tokens = Self::mut_guard(&self.commitment_generation, &self.tokens).await;
                    tokens
                        .execute(
                            &quote_id,
                            trader,
                            crate::token::TokenOp::Burn { from: trader, amount: q_escrow },
                        )
                        .map_err(|e| format!("CLOB taker escrow lock failed: {e}"))?;
                    let new_bal = tokens.balance_of(&quote_id, &trader);
                    let mut trie = self.state_trie.write().await;
                    trie.insert(&token_balance_key(&quote_id, &trader), &new_bal.to_be_bytes());
                    drop(trie);
                    drop(tokens);
                    Self::mut_guard(&self.commitment_generation, &self.order_escrow).await.insert(
                        (pair, order.order_id),
                        EscrowRecord {
                            trader,
                            locked_base_stell: 0,
                            locked_quote_wusdt: q_escrow,
                            locked_quote_native: 0,
                        },
                    );
                } else {
                    self.debit_native(&trader, unfilled).await?;
                    Self::mut_guard(&self.commitment_generation, &self.order_escrow).await.insert(
                        (pair, order.order_id),
                        EscrowRecord {
                            trader,
                            locked_base_stell: unfilled,
                            locked_quote_wusdt: 0,
                            locked_quote_native: 0,
                        },
                    );
                }
            }
            Self::mut_guard(&self.commitment_generation, &self.orderbooks).await.books.insert(pair, book);
            return Ok((order.order_id, 0));
        }

        // 2) Validate EVERY trade and resting order up-front so nothing fails midway.
        //    (A partial settlement would move funds but leave the book unfilled,
        //    enabling a re-match double spend.) Self-trades net to zero and are
        //    skipped; dust quote and a paused/missing quote token are rejected.
        {
            let tokens = self.tokens.read().await;
            match tokens.get(&quote_id) {
                Some(tok) if !tok.metadata.paused => {}
                _ => return Err("CLOB settlement: quote token missing or paused".to_string()),
            }
        }

        let escrows = self.order_escrow.read().await;
        let mut need_base: HashMap<[u8; 32], u64> = HashMap::new();
        let mut need_quote: HashMap<[u8; 32], u64> = HashMap::new();

        // Taker's resting unfilled remainder requires escrow up-front (only for
        // a remainder the book actually took - see step 1/4):
        let rests_in_book = is_limit && unfilled > 0 && book.find_order(order.order_id).is_some();
        if rests_in_book {
            if taker_is_buyer {
                let q_escrow = Self::clob_quote_value(price, unfilled);
                let e = need_quote.entry(trader).or_insert(0);
                *e = e.saturating_add(q_escrow);
            } else {
                let e = need_base.entry(trader).or_insert(0);
                *e = e.saturating_add(unfilled);
            }
        }

        for t in &trades {
            let (buyer, seller) =
                if taker_is_buyer { (t.taker, t.maker) } else { (t.maker, t.taker) };
            if buyer == seller {
                continue; // self-trade: no net transfer
            }
            let q = Self::clob_quote_value(t.price, t.amount);
            if q == 0 {
                return Err("CLOB settlement: zero quote value (dust)".to_string());
            }

            // A maker's OWN escrow funds its side of the trade - but only if it
            // actually holds enough of the asset this leg pays in. The old
            // `contains_key` test was an all-or-nothing assumption that every
            // record was a wUSDT record: a BUY locked in native (the SVM path)
            // passed the check with `locked_quote_wusdt == 0`, and the apply
            // step then `saturating_sub`'d zero and MINTED the quote out of
            // nothing. Coverage is now per asset.
            if taker_is_buyer {
                // Taker is buyer -> taker pays quote from live balance:
                let e = need_quote.entry(buyer).or_insert(0);
                *e = e.saturating_add(q);
                // Maker is seller -> base escrow covers it, else live balance:
                match escrows.get(&(pair, t.maker_order_id)) {
                    Some(r) if r.locked_base_stell > 0 => {
                        if r.locked_base_stell < t.amount {
                            return Err(format!(
                                "CLOB settlement: escrow for order {} cannot fund the base leg",
                                t.maker_order_id
                            ));
                        }
                    }
                    _ => {
                        let e = need_base.entry(seller).or_insert(0);
                        *e = e.saturating_add(t.amount);
                    }
                }
            } else {
                // Taker is seller -> taker pays base from live balance:
                let e = need_base.entry(seller).or_insert(0);
                *e = e.saturating_add(t.amount);
                // Maker is buyer -> its quote escrow covers it (in whichever
                // asset it locked), else the maker needs live wUSDT:
                let qn = Self::clob_quote_native(t.price, t.amount);
                match escrows.get(&(pair, t.maker_order_id)) {
                    Some(r) if r.locked_quote_wusdt > 0 || r.locked_quote_native > 0 => {
                        let covers = r.locked_quote_wusdt >= q
                            || (qn > 0 && r.locked_quote_native >= qn);
                        if !covers {
                            return Err(format!(
                                "CLOB settlement: escrow for order {} cannot fund the quote leg",
                                t.maker_order_id
                            ));
                        }
                    }
                    _ => {
                        let e = need_quote.entry(buyer).or_insert(0);
                        *e = e.saturating_add(q);
                    }
                }
            }
        }
        drop(escrows);

        for (a, need) in &need_base {
            let bal = self.get_account(a).await.map(|x| x.balance).unwrap_or(0);
            if bal < *need {
                return Err(format!("CLOB settlement: seller {a:?} lacks base STELL"));
            }
        }
        for (a, need) in &need_quote {
            let bal = self.token_balance(&quote_id, a).await;
            if bal < *need {
                return Err(format!("CLOB settlement: buyer {a:?} lacks wUSDT"));
            }
        }

        // 3) Apply settlement per trade and update/release maker escrows:
        let mut escrow_map = Self::mut_guard(&self.commitment_generation, &self.order_escrow).await;
        for t in &trades {
            let (buyer, seller) =
                if taker_is_buyer { (t.taker, t.maker) } else { (t.maker, t.taker) };

            // Self-trade: release maker's locked escrow back to self (net zero).
            // `min` rather than a plain subtraction: the fill can never consume
            // more than the record holds, and releasing exactly what it holds is
            // what keeps a drained record from outliving its order.
            if buyer == seller {
                let key = (pair, t.maker_order_id);
                if taker_is_buyer {
                    if let Some(rec) = escrow_map.get_mut(&key) {
                        let take = rec.locked_base_stell.min(t.amount);
                        rec.locked_base_stell -= take;
                        self.credit_native(&buyer, take).await?;
                    }
                } else {
                    let q = Self::clob_quote_value(t.price, t.amount);
                    let qn = Self::clob_quote_native(t.price, t.amount);
                    let take_wusdt = escrow_map
                        .get(&key)
                        .map(|r| r.locked_quote_wusdt.min(q))
                        .unwrap_or(0);
                    if take_wusdt > 0 {
                        escrow_map.get_mut(&key).unwrap().locked_quote_wusdt -= take_wusdt;
                        let mut tokens = Self::mut_guard(&self.commitment_generation, &self.tokens).await;
                        let token_minter = tokens.get(&quote_id).map(|tok| tok.metadata.minter).unwrap_or([0u8; 32]);
                        tokens
                            .execute(
                                &quote_id,
                                token_minter,
                                crate::token::TokenOp::Mint { to: buyer, amount: take_wusdt },
                            )
                            .map_err(|e| format!("CLOB escrow self-refund failed: {e}"))?;
                        let new_bal = tokens.balance_of(&quote_id, &buyer);
                        let mut trie = self.state_trie.write().await;
                        trie.insert(&token_balance_key(&quote_id, &buyer), &new_bal.to_be_bytes());
                    } else if let Some(rec) = escrow_map.get_mut(&key) {
                        let take = rec.locked_quote_native.min(qn);
                        rec.locked_quote_native -= take;
                        self.credit_native(&buyer, take).await?;
                    }
                }
                if let Some(rec) = escrow_map.get(&(pair, t.maker_order_id)) {
                    if rec.locked_base_stell == 0
                        && rec.locked_quote_wusdt == 0
                        && rec.locked_quote_native == 0
                    {
                        escrow_map.remove(&(pair, t.maker_order_id));
                    }
                }
                continue;
            }

            let q = Self::clob_quote_value(t.price, t.amount);

            // Handle quote payment (buyer -> seller):
            let maker_key = (pair, t.maker_order_id);
            // Only a maker that IS the buyer can fund this leg from escrow.
            let maker_escrowed_quote = if !taker_is_buyer {
                escrow_map
                    .get(&maker_key)
                    .map_or(false, |r| r.locked_quote_wusdt > 0 || r.locked_quote_native > 0)
            } else {
                false
            };
            if maker_escrowed_quote {
                // Maker buyer: pay seller from maker's locked quote escrow, in
                // whichever asset that record actually holds.
                let qn = Self::clob_quote_native(t.price, t.amount);
                let paid_wusdt = escrow_map.get(&maker_key).unwrap().locked_quote_wusdt >= q;
                if paid_wusdt {
                    let rec = escrow_map.get_mut(&maker_key).unwrap();
                    rec.locked_quote_wusdt -= q;
                    // Credit seller with wUSDT using minter authority:
                    let mut tokens = Self::mut_guard(&self.commitment_generation, &self.tokens).await;
                    let token_minter = tokens.get(&quote_id).map(|tok| tok.metadata.minter).unwrap_or([0u8; 32]);
                    tokens
                        .execute(
                            &quote_id,
                            token_minter,
                            crate::token::TokenOp::Mint { to: seller, amount: q },
                        )
                        .map_err(|e| format!("CLOB escrow quote release failed: {e}"))?;
                    let seller_qbal = tokens.balance_of(&quote_id, &seller);
                    let mut trie = self.state_trie.write().await;
                    trie.insert(&token_balance_key(&quote_id, &seller), &seller_qbal.to_be_bytes());
                } else if qn > 0 && escrow_map.get(&maker_key).unwrap().locked_quote_native >= qn {
                    let rec = escrow_map.get_mut(&maker_key).unwrap();
                    rec.locked_quote_native -= qn;
                    self.credit_native(&seller, qn).await?;
                } else {
                    // The record exists but cannot fund this fill. Refusing is
                    // the only safe answer: paying from live balance would take
                    // coins the trader already locked, and minting would print.
                    return Err(format!(
                        "CLOB settlement: escrow for order {} cannot fund the quote leg",
                        t.maker_order_id
                    ));
                }
            } else {
                // Taker buyer: transfers quote directly to seller
                let mut tokens = Self::mut_guard(&self.commitment_generation, &self.tokens).await;
                tokens
                    .execute(
                        &quote_id,
                        buyer,
                        crate::token::TokenOp::Transfer { to: seller, amount: q },
                    )
                    .map_err(|e| format!("CLOB quote settlement failed: {e}"))?;
                let buyer_qbal = tokens.balance_of(&quote_id, &buyer);
                let seller_qbal = tokens.balance_of(&quote_id, &seller);
                let mut trie = self.state_trie.write().await;
                trie.insert(&token_balance_key(&quote_id, &buyer), &buyer_qbal.to_be_bytes());
                trie.insert(&token_balance_key(&quote_id, &seller), &seller_qbal.to_be_bytes());
            }

            // Handle base payment (seller -> buyer):
            let maker_escrowed_base = if taker_is_buyer {
                escrow_map
                    .get(&maker_key)
                    .map_or(false, |r| r.locked_base_stell >= t.amount)
            } else {
                false
            };
            if maker_escrowed_base {
                // Maker seller: pay buyer from maker's locked base escrow
                let rec = escrow_map.get_mut(&maker_key).unwrap();
                rec.locked_base_stell -= t.amount;
                // Credit buyer with native STELL:
                self.credit_native(&buyer, t.amount).await?;
            } else {
                // Taker seller or non-escrowed maker: debit seller, credit buyer
                self.debit_native(&seller, t.amount).await?;
                self.credit_native(&buyer, t.amount).await?;
            }

            // If maker escrow is completely exhausted, clean it up:
            if let Some(rec) = escrow_map.get(&maker_key) {
                if rec.locked_base_stell == 0
                    && rec.locked_quote_wusdt == 0
                    && rec.locked_quote_native == 0
                {
                    escrow_map.remove(&maker_key);
                }
            }
        }

        // 4) If taker's limit order has an unfilled RESTING part, lock it into escrow:
        if rests_in_book {
            if taker_is_buyer {
                let q_escrow = Self::clob_quote_value(price, unfilled);
                // Burn/lock wUSDT from taker into escrow:
                let mut tokens = Self::mut_guard(&self.commitment_generation, &self.tokens).await;
                tokens
                    .execute(
                        &quote_id,
                        trader,
                        crate::token::TokenOp::Burn { from: trader, amount: q_escrow },
                    )
                    .map_err(|e| format!("CLOB taker escrow lock failed: {e}"))?;
                let new_bal = tokens.balance_of(&quote_id, &trader);
                let mut trie = self.state_trie.write().await;
                trie.insert(&token_balance_key(&quote_id, &trader), &new_bal.to_be_bytes());
                drop(trie);
                drop(tokens);
                escrow_map.insert(
                    (pair, order.order_id),
                    EscrowRecord {
                        trader,
                        locked_base_stell: 0,
                        locked_quote_wusdt: q_escrow,
                        locked_quote_native: 0,
                    },
                );
            } else {
                // Lock native STELL from taker into escrow:
                self.debit_native(&trader, unfilled).await?;
                escrow_map.insert(
                    (pair, order.order_id),
                    EscrowRecord {
                        trader,
                        locked_base_stell: unfilled,
                        locked_quote_wusdt: 0,
                        locked_quote_native: 0,
                    },
                );
            }
        }
        drop(escrow_map);

        // 5) Commit the matched book.
        Self::mut_guard(&self.commitment_generation, &self.orderbooks).await.books.insert(pair, book);
        Ok((order.order_id, trades.len()))
    }

    /// Cancel an active resting order from the CLOB and refund all escrowed funds.
    pub async fn cancel_order_settled(
        &self,
        pair: u32,
        order_id: u64,
        caller: [u8; 32],
    ) -> Result<Option<crate::orderbook::Order>, String> {
        // ---- Refund pre-validation: NOTHING is removed until it is known that
        // the whole refund can be paid. The wUSDT leg is the fallible one (no
        // token configured, paused, capped, minter gone) and it used to be
        // attempted AFTER the escrow record had already been removed and the
        // native part credited - a refusal then stranded the wUSDT half.
        //
        // The token is only needed when there IS wUSDT to give back: a purely
        // native escrow (base collateral, or the SVM path's native-locked
        // quote) must be refundable on a chain that never configured wUSDT.
        let quote_id = *self.pmm_usdt_token.read().await;
        let wusdt_refund = self
            .order_escrow
            .read()
            .await
            .get(&(pair, order_id))
            .map(|r| r.locked_quote_wusdt)
            .unwrap_or(0);
        if wusdt_refund > 0 {
            let qid = quote_id
                .ok_or_else(|| "CLOB quote token not configured".to_string())?;
            // Dry-run against a throwaway copy of the registry.
            let mut probe = self.tokens.read().await.clone();
            let minter = probe
                .get(&qid)
                .map(|t| t.metadata.minter)
                .ok_or_else(|| "CLOB quote token not configured".to_string())?;
            probe
                .execute(
                    &qid,
                    minter,
                    crate::token::TokenOp::Mint { to: caller, amount: wusdt_refund },
                )
                .map_err(|e| format!("CLOB cancel refund would fail: {e}"))?;
        }

        let mut books = Self::mut_guard(&self.commitment_generation, &self.orderbooks).await;
        // Ownership is checked BEFORE the order is pulled from the book: the
        // book guard is the live map (not a clone), so a check after the
        // removal would delete a foreign order and return Err with its escrow
        // still locked - exactly the orphan the escrow exists to prevent.
        let owner = books
            .books
            .get(&pair)
            .and_then(|b| b.find_order(order_id))
            .map(|o| o.trader);
        match owner {
            None => return Ok(None),
            Some(t) if t != caller => {
                return Err("Only the order owner may cancel and claim refund".to_string())
            }
            Some(_) => {}
        }
        let Some(book) = books.books.get_mut(&pair) else {
            return Ok(None);
        };
        let Some(cancelled) = book.cancel_order(order_id) else {
            return Ok(None);
        };
        drop(books);

        // Refund escrow: whatever the record holds goes back to its owner, in
        // the asset it was locked in (base, wUSDT or the SVM path's native
        // quote). A record can only release what was deposited into it.
        if let Some(escrow) = Self::mut_guard(&self.commitment_generation, &self.order_escrow).await.remove(&(pair, order_id)) {
            if escrow.locked_base_stell > 0 || escrow.locked_quote_native > 0 {
                self.credit_native(
                    &caller,
                    escrow.locked_base_stell.saturating_add(escrow.locked_quote_native),
                )
                .await?;
            }
            if escrow.locked_quote_wusdt > 0 {
                let qid = quote_id
                    .ok_or_else(|| "CLOB quote token not configured".to_string())?;
                let mut tokens = Self::mut_guard(&self.commitment_generation, &self.tokens).await;
                let token_minter = tokens.get(&qid).map(|tok| tok.metadata.minter).unwrap_or([0u8; 32]);
                tokens
                    .execute(
                        &qid,
                        token_minter,
                        crate::token::TokenOp::Mint {
                            to: caller,
                            amount: escrow.locked_quote_wusdt,
                        },
                    )
                    .map_err(|e| format!("CLOB cancel refund mint failed: {e}"))?;
                let new_bal = tokens.balance_of(&qid, &caller);
                drop(tokens);
                let mut trie = self.state_trie.write().await;
                trie.insert(&token_balance_key(&qid, &caller), &new_bal.to_be_bytes());
            }
        }

        Ok(Some(cancelled))
    }

    /// Planned native movement bookkeeping: `proj[addr]` is what the account is
    /// EXPECTED to hold once the whole plan is applied, seeded lazily from the
    /// live map. A debit that would take it below zero aborts the plan before
    /// anything has moved.
    fn plan_native_debit(
        proj: &mut HashMap<[u8; 32], i128>,
        live: &HashMap<[u8; 32], AccountState>,
        moves: &mut Vec<NativeMove>,
        addr: [u8; 32],
        amount: u64,
        what: &str,
    ) -> Result<(), String> {
        if amount == 0 {
            return Ok(());
        }
        let cur = proj
            .entry(addr)
            .or_insert_with(|| live.get(&addr).map(|a| a.balance as i128).unwrap_or(0));
        if *cur < amount as i128 {
            return Err(format!(
                "CLOB settlement: {what} {} holds {} and needs {amount}",
                hex::encode(&addr[..6]),
                (*cur).max(0)
            ));
        }
        *cur -= amount as i128;
        moves.push(NativeMove::Debit(addr, amount));
        Ok(())
    }

    fn plan_native_credit(
        proj: &mut HashMap<[u8; 32], i128>,
        live: &HashMap<[u8; 32], AccountState>,
        moves: &mut Vec<NativeMove>,
        addr: [u8; 32],
        amount: u64,
        what: &str,
    ) -> Result<(), String> {
        if amount == 0 {
            return Ok(());
        }
        let cur = proj
            .entry(addr)
            .or_insert_with(|| live.get(&addr).map(|a| a.balance as i128).unwrap_or(0));
        *cur += amount as i128;
        if *cur > u64::MAX as i128 {
            return Err(format!("CLOB settlement: {what} native balance overflow"));
        }
        moves.push(NativeMove::Credit(addr, amount));
        Ok(())
    }

    /// Apply a planned set of native movements under the accounts write lock.
    ///
    /// Failure is atomic: an undo log keyed by "the value BEFORE this leg" is
    /// walked newest-first, so an account touched twice returns to its original
    /// value rather than to an intermediate one, and no coin is left moved.
    /// Returns every touched account with its FINAL (balance, nonce) for the
    /// caller to write into the state trie, plus the pre-move snapshot
    /// (`None` = the account did not exist) for a later rollback by the
    /// caller if the enclosing transaction is refused after this leg.
    async fn apply_native_moves(
        &self,
        moves: &[NativeMove],
    ) -> Result<
        (
            Vec<([u8; 32], u64, u64)>,
            Vec<([u8; 32], Option<(u64, u64)>)>,
        ),
        String,
    > {
        if moves.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        let mut map = self.accounts.write().await;
        let mut undo: Vec<([u8; 32], Option<(u64, u64)>)> = Vec::with_capacity(moves.len());
        let mut failure: Option<String> = None;
        for m in moves {
            let (addr, amount, is_debit) = match m {
                NativeMove::Debit(a, n) => (*a, *n, true),
                NativeMove::Credit(a, n) => (*a, *n, false),
            };
            undo.push((addr, map.get(&addr).map(|a| (a.balance, a.nonce))));
            if is_debit {
                match map.get_mut(&addr) {
                    None => {
                        failure = Some(format!(
                            "CLOB settlement: account {} does not exist",
                            hex::encode(&addr[..6])
                        ));
                        break;
                    }
                    Some(acc) if acc.balance < amount => {
                        failure = Some(format!(
                            "CLOB settlement: account {} has {} but must pay {amount}",
                            hex::encode(&addr[..6]),
                            acc.balance
                        ));
                        break;
                    }
                    Some(acc) => acc.balance -= amount,
                }
            } else {
                let acc = map.entry(addr).or_insert_with(|| AccountState::new(addr, 0));
                match acc.balance.checked_add(amount) {
                    Some(v) => acc.balance = v,
                    None => {
                        failure = Some("CLOB settlement: native balance overflow".to_string());
                        break;
                    }
                }
            }
        }
        if let Some(e) = failure {
            for (addr, prev) in undo.iter().rev() {
                match prev {
                    Some((balance, nonce)) => {
                        if let Some(acc) = map.get_mut(addr) {
                            acc.balance = *balance;
                            acc.nonce = *nonce;
                        }
                    }
                    None => {
                        map.remove(addr);
                    }
                }
            }
            return Err(e);
        }

        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        let mut out = Vec::new();
        for m in moves {
            let addr = match m {
                NativeMove::Debit(a, _) | NativeMove::Credit(a, _) => *a,
            };
            if seen.insert(addr) {
                if let Some(acc) = map.get(&addr) {
                    out.push((addr, acc.balance, acc.nonce));
                }
            }
        }
        // First-touch pre-state per account (an account moved twice restores
        // to its original, not to an intermediate value).
        let mut snap_seen: HashSet<[u8; 32]> = HashSet::new();
        let mut snapshot = Vec::new();
        for (addr, prev) in undo {
            if snap_seen.insert(addr) {
                snapshot.push((addr, prev));
            }
        }
        Ok((out, snapshot))
    }

    /// Settle the value side of the SVM's order syscalls: lock escrow for what
    /// rests, move funds for what filled, refund what was cancelled.
    ///
    /// This is the hand-off from `OpCode::SysCallPlaceOrder` /
    /// `SysCallCancelOrder` - which mutate the book inside the VM but can see
    /// neither accounts, nor tokens, nor the escrow map - to consensus state.
    /// It runs inside `execute_payload`, the execution point `apply_transaction`
    /// AND the live block path (`apply_block_parallel_fees`) both go through, so
    /// both apply the IDENTICAL settlement; `ctx.trades` (the fills the VM
    /// recorded) reach it as `ClobEvent::Place::trades`.
    ///
    /// ALL-OR-NOTHING. Everything is planned against private copies first (the
    /// escrow working map, the staged token registry, projected native
    /// balances) and the whole plan is validated before a single balance moves;
    /// only then are the native movements applied under the accounts write lock
    /// with an undo log and the staged copies committed. A refused settlement
    /// therefore changes nothing anywhere - the caller only has to roll the
    /// BOOK back, because the VM already committed that (see `execute_payload`).
    ///
    /// Quote conventions: `mode` decides what a TAKER pays out of its live
    /// balance (the SVM path pays native, because that is what its `order_cost`
    /// affordability check prices), while a MAKER's own escrow always releases
    /// the asset it actually locked - a record can never pay out an asset
    /// nobody deposited into it.
    ///
    /// `reserve_floor` is what the sender must still hold once the plan is
    /// applied - the admission reservation plus the payload's own transfers -
    /// so the lock cannot leave a transaction whose payload already committed
    /// but whose `commit_native` then fails. See the call site in
    /// `execute_payload`.
    async fn settle_clob_effects(
        &self,
        events: &[crate::orderbook::ClobEvent],
        mode: ClobQuoteMode,
        quote_id: Option<[u8; 32]>,
        tokens: &mut TokenRegistry,
        escrow: &mut HashMap<(u32, u64), EscrowRecord>,
        sender: [u8; 32],
        reserve_floor: u64,
        order_absent: impl Fn(u32, u64) -> bool,
    ) -> Result<Vec<([u8; 32], Option<(u64, u64)>)>, String> {
        use crate::orderbook::{ClobEvent, OrderSide, OrderType};

        // ---- Phase 1: plan on private copies, validate the whole plan -------
        let mut work = escrow.clone();
        let mut staged = tokens.clone();
        let mut native_moves: Vec<NativeMove> = Vec::new();
        let mut token_touched: HashSet<[u8; 32]> = HashSet::new();
        let mut supply_dirty = false;
        let qid = quote_id;
        let minter: Option<[u8; 32]> =
            qid.and_then(|q| staged.get(&q).map(|t| t.metadata.minter));

        let live = self.accounts.read().await;
        let mut proj: HashMap<[u8; 32], i128> = HashMap::new();

        // Defined after the plan state so the identifiers they mention resolve.
        macro_rules! debit {
            ($addr:expr, $amount:expr, $what:expr) => {
                Self::plan_native_debit(&mut proj, &live, &mut native_moves, $addr, $amount, $what)?
            };
        }
        macro_rules! credit {
            ($addr:expr, $amount:expr, $what:expr) => {
                Self::plan_native_credit(&mut proj, &live, &mut native_moves, $addr, $amount, $what)?
            };
        }

        // One token operation against the staged registry. Failures here happen
        // during planning, so the real registry has not been touched yet.
        let mut tok_op = |caller: [u8; 32], op: TokenOp| -> Result<(), String> {
            let q = qid.ok_or_else(|| "CLOB settlement: quote token not configured".to_string())?;
            match &op {
                TokenOp::Transfer { to, .. } => {
                    token_touched.insert(caller);
                    token_touched.insert(*to);
                }
                TokenOp::Mint { to, .. } => {
                    token_touched.insert(*to);
                    supply_dirty = true;
                }
                TokenOp::Burn { from, .. } => {
                    token_touched.insert(*from);
                    supply_dirty = true;
                }
                _ => {}
            }
            staged
                .execute(&q, caller, op)
                .map_err(|e| format!("CLOB settlement: token op failed: {e}"))?;
            Ok(())
        };
        let minter_or_err = || -> Result<[u8; 32], String> {
            minter.ok_or_else(|| "CLOB settlement: quote token not configured".to_string())
        };

        for ev in events {
            match ev {
                ClobEvent::Place {
                    pair_id,
                    order_id,
                    trader,
                    side,
                    order_type,
                    price,
                    amount,
                    filled,
                    trades,
                } => {
                    let taker_is_buyer = matches!(side, OrderSide::Buy);
                    let maker_is_buyer = !taker_is_buyer;

                    for t in trades {
                        let mkey = (*pair_id, t.maker_order_id);
                        let (buyer, seller) = if taker_is_buyer {
                            (t.taker, t.maker)
                        } else {
                            (t.maker, t.taker)
                        };
                        // Snapshot taken before this trade mutates the record;
                        // the quote leg only touches a maker-BUYER record and
                        // the base leg only a maker-SELLER one, so the snapshot
                        // cannot go stale for the leg that reads it.
                        let maker_rec = work.get(&mkey).cloned();

                        // ---- Self-trade: both sides are the same account ----
                        // Nothing moves between parties, but the maker's escrow
                        // must still give back exactly what the fill consumed,
                        // or the record would outlive the order it secures.
                        if buyer == seller {
                            if let Some(rec) = work.get_mut(&mkey) {
                                if !maker_is_buyer {
                                    let take = rec.locked_base_stell.min(t.amount);
                                    rec.locked_base_stell -= take;
                                    credit!(buyer, take, "self-trade escrow refund");
                                } else if rec.locked_quote_wusdt > 0 {
                                    let q = ClobQuoteMode::Wusdt.quote(t.price, t.amount);
                                    let take = rec.locked_quote_wusdt.min(q);
                                    rec.locked_quote_wusdt -= take;
                                    tok_op(minter_or_err()?, TokenOp::Mint { to: buyer, amount: take })?;
                                } else {
                                    let qn = ClobQuoteMode::NativeSvm.quote(t.price, t.amount);
                                    let take = rec.locked_quote_native.min(qn);
                                    rec.locked_quote_native -= take;
                                    credit!(buyer, take, "self-trade escrow refund");
                                }
                            }
                            if work.get(&mkey).map_or(false, |r| {
                                r.locked_base_stell == 0
                                    && r.locked_quote_wusdt == 0
                                    && r.locked_quote_native == 0
                            }) {
                                work.remove(&mkey);
                            }
                            continue;
                        }

                        // ---- Quote leg: buyer pays seller ----
                        let q_wusdt = ClobQuoteMode::Wusdt.quote(t.price, t.amount);
                        let q_native = ClobQuoteMode::NativeSvm.quote(t.price, t.amount);
                        let maker_escrowed_quote = maker_is_buyer
                            && maker_rec.as_ref().map_or(false, |r| {
                                r.locked_quote_wusdt > 0 || r.locked_quote_native > 0
                            });
                        let pays_wusdt = if maker_escrowed_quote {
                            let r = maker_rec.as_ref().unwrap();
                            if r.locked_quote_wusdt >= q_wusdt {
                                true
                            } else if q_native > 0 && r.locked_quote_native >= q_native {
                                false
                            } else {
                                return Err(format!(
                                    "CLOB settlement: escrow for order {} cannot fund the quote leg",
                                    t.maker_order_id
                                ));
                            }
                        } else {
                            matches!(mode, ClobQuoteMode::Wusdt)
                        };
                        let q = if pays_wusdt { q_wusdt } else { q_native };
                        if q == 0 {
                            return Err("CLOB settlement: zero quote value (dust)".to_string());
                        }
                        if maker_escrowed_quote {
                            if pays_wusdt {
                                work.get_mut(&mkey).unwrap().locked_quote_wusdt -= q;
                                tok_op(minter_or_err()?, TokenOp::Mint { to: seller, amount: q })?;
                            } else {
                                work.get_mut(&mkey).unwrap().locked_quote_native -= q;
                                credit!(seller, q, "escrow quote release");
                            }
                        } else if pays_wusdt {
                            tok_op(buyer, TokenOp::Transfer { to: seller, amount: q })?;
                        } else {
                            debit!(buyer, q, "buyer");
                            credit!(seller, q, "quote settlement");
                        }

                        // ---- Base leg: seller pays buyer ----
                        let maker_escrowed_base = taker_is_buyer
                            && maker_rec.as_ref().map_or(false, |r| r.locked_base_stell > 0);
                        if maker_escrowed_base {
                            let r = maker_rec.as_ref().unwrap();
                            if r.locked_base_stell < t.amount {
                                return Err(format!(
                                    "CLOB settlement: escrow for order {} cannot fund the base leg",
                                    t.maker_order_id
                                ));
                            }
                            work.get_mut(&mkey).unwrap().locked_base_stell -= t.amount;
                            credit!(buyer, t.amount, "escrow base release");
                        } else {
                            debit!(seller, t.amount, "seller");
                            credit!(buyer, t.amount, "base settlement");
                        }

                        // Drop a record the fills have drained.
                        if work.get(&mkey).map_or(false, |r| {
                            r.locked_base_stell == 0
                                && r.locked_quote_wusdt == 0
                                && r.locked_quote_native == 0
                        }) {
                            work.remove(&mkey);
                        }
                    }

                    // ---- Lock what rests, exactly as place_order_settled does.
                    // The book the VM committed decides whether anything rests:
                    // a fully filled order holds nothing, and an order the book
                    // refused (depth saturation) must not be locked either, or
                    // its escrow would be unreachable by construction.
                    let unfilled = amount.saturating_sub(*filled);
                    if matches!(order_type, OrderType::Limit)
                        && unfilled > 0
                        && !order_absent(*pair_id, *order_id)
                    {
                        let rec = work
                            .entry((*pair_id, *order_id))
                            .or_insert_with(|| EscrowRecord {
                                trader: *trader,
                                locked_base_stell: 0,
                                locked_quote_wusdt: 0,
                                locked_quote_native: 0,
                            });
                        if taker_is_buyer {
                            let q = mode.quote(*price, unfilled);
                            if q > 0 {
                                debit!(*trader, q, "buyer escrow lock");
                                match mode {
                                    ClobQuoteMode::Wusdt => {
                                        rec.locked_quote_wusdt =
                                            rec.locked_quote_wusdt.saturating_add(q)
                                    }
                                    ClobQuoteMode::NativeSvm => {
                                        rec.locked_quote_native =
                                            rec.locked_quote_native.saturating_add(q)
                                    }
                                }
                            }
                        } else {
                            debit!(*trader, unfilled, "seller escrow lock");
                            rec.locked_base_stell =
                                rec.locked_base_stell.saturating_add(unfilled);
                        }
                    }
                }
                ClobEvent::Cancel {
                    pair_id,
                    order_id,
                    trader,
                } => {
                    // The syscall removed the order from its clone of the book,
                    // and that clone is what got committed: if it is somehow
                    // still resting, refunding would hand back funds that are
                    // still collateralising an order anyone can match against.
                    if !order_absent(*pair_id, *order_id) {
                        return Err(format!(
                            "CLOB settlement: cancelled order {} is still in the book",
                            order_id
                        ));
                    }
                    if let Some(rec) = work.remove(&(*pair_id, *order_id)) {
                        let native = rec
                            .locked_base_stell
                            .saturating_add(rec.locked_quote_native);
                        credit!(*trader, native, "cancel refund");
                        if rec.locked_quote_wusdt > 0 {
                            tok_op(
                                minter_or_err()?,
                                TokenOp::Mint { to: *trader, amount: rec.locked_quote_wusdt },
                            )?;
                        }
                    }
                }
            }
        }
        // The escrow lock must never eat the transaction's own reservation.
        // `commit_native` runs AFTER this settlement and demands
        // `amount + declared gas limit + payload transfers` from the sender; if
        // the lock took any of it, the payload effects would already be
        // committed while the native commit refuses - and the two apply paths
        // would disagree about that, because they charge different fee numbers.
        // Requiring the stricter (block-path) reservation here makes the
        // transaction succeed or fail as a whole, identically on both.
        let sender_after = proj
            .get(&sender)
            .copied()
            .unwrap_or_else(|| live.get(&sender).map(|a| a.balance as i128).unwrap_or(0));
        if sender_after < reserve_floor as i128 {
            return Err(format!(
                "CLOB settlement: the sender would keep {} of the {reserve_floor} reserved for the transfer and the fee",
                sender_after.max(0)
            ));
        }

        drop(live);

        // ---- Phase 2: commit the plan -------------------------------------
        // 1) Native first: it is the only leg that can still fail (everything
        //    else was validated against a private copy and is infallible).
        //    The snapshot is the caller's undo record if the enclosing
        //    transaction is refused after this leg (same shape and purpose as
        //    `pmm_native_snapshot`).
        let (touched, clob_snapshot) = self.apply_native_moves(&native_moves).await?;
        // 2) Staged copies become the truth.
        *tokens = staged;
        *escrow = work;
        // 3) Trie writes. Nothing below can fail.
        let mut trie = self.state_trie.write().await;
        if let Some(q) = qid {
            for acct in &token_touched {
                let bal = tokens.balance_of(&q, acct);
                let key = token_balance_key(&q, acct);
                if bal == 0 {
                    trie.remove(&key);
                } else {
                    trie.insert(&key, &bal.to_be_bytes());
                }
            }
            if supply_dirty {
                if let Some(supply) = tokens.get(&q).map(|t| t.metadata.total_supply) {
                    trie.insert(&token_supply_key(&q), &supply.to_be_bytes());
                }
            }
        }
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
        for (addr, data) in entries {
            trie.insert(&addr, &data);
        }
        Ok(clob_snapshot)
    }

    // ==================== Primary Market Maker (on-chain) ====================

    /// Read-only snapshot of the PMM for RPC (`stell_pmmState`).
    ///
    /// Returns `(curve, quote token id, treasury)`. The governed buffer is NOT
    /// part of this: it lives in governance (`stell_governanceParams`), so a
    /// reader sees the parameter and the curve separately rather than a
    /// possibly-stale copy of it baked into the PMM.
    pub async fn pmm_state(
        &self,
    ) -> (crate::pmm::PrimaryMarketMaker, Option<[u8; 32]>, [u8; 32]) {
        let pmm = self.pmm.read().await.clone();
        let usdt = *self.pmm_usdt_token.read().await;
        let treasury = *self.pmm_treasury.read().await;
        (pmm, usdt, treasury)
    }

    /// Register the bridged-USDT token used by the PMM as its quote asset and
    /// seed the reserve. Must be called once at genesis.
    ///
    /// SECURITY: idempotent-guarded — once initialised the quote token cannot be
    /// re-pointed, otherwise anyone could swap in a token they control (and thus
    /// mint the redemption payouts) after genesis.
    pub async fn pmm_init_usdt(&self, usdt_token_id: [u8; 32], reserve_micro: u64) {
        if self.pmm_usdt_token.read().await.is_some() {
            return;
        }
        // The wUSDT minter is the PMM treasury: redemptions mint wUSDT payouts
        // (purchases burn the buyer's wUSDT), so mint authority must belong to
        // the system PMM and never to a user account.
        let minter = self
            .tokens
            .read()
            .await
            .get(&usdt_token_id)
            .map(|t| t.metadata.minter)
            .unwrap_or([0u8; 32]);
        *Self::mut_guard(&self.commitment_generation, &self.pmm_treasury).await = minter;

        let mut pmm = Self::mut_guard(&self.commitment_generation, &self.pmm).await;
        *pmm = crate::pmm::PrimaryMarketMaker::with_reserve(reserve_micro);
        *Self::mut_guard(&self.commitment_generation, &self.pmm_usdt_token).await = Some(usdt_token_id);
    }

    /// Buy STELL with `usdt_micro` wUSDT. Atomically: debit the buyer's wUSDT
    /// (committed to the trie), advance the curve, mint native STELL to the
    /// buyer (committed to the trie). All-or-nothing.
    pub async fn pmm_buy(
        &self,
        buyer: [u8; 32],
        usdt_micro: u64,
    ) -> Result<crate::pmm::BuyReceipt, String> {
        let usdt_id = self
            .pmm_usdt_token
            .read()
            .await
            .ok_or_else(|| "PMM USDT token not initialised".to_string())?;

        // 1. Dry-run the bonding curve on a clone so a rejected buy (dust /
        //    reserve / overflow) can never mutate state or move user funds.
        //    The buffer share comes from governance, read once here so the
        //    direct call path prices exactly like `SysCallPmmBuy` does inside
        //    a block (both read `applied.pmm_redemption_buffer_bps`, both fall
        //    back to the protocol default when nothing has been passed).
        let (trial_pmm, receipt) = {
            let buffer_bps = self
                .governance
                .read()
                .await
                .applied
                .pmm_redemption_buffer_bps
                .unwrap_or(crate::pmm::PMM_REDEMPTION_BUFFER_BPS);
            let pmm = self.pmm.read().await;
            let mut trial = pmm.clone();
            let receipt = trial
                .buy_with_buffer(usdt_micro, buffer_bps)
                .map_err(|e| e.to_string())?;
            (trial, receipt)
        };

        // 2. Debit (burn) the buyer's wUSDT via the token CEI path + trie sync.
        {
            let mut tokens = Self::mut_guard(&self.commitment_generation, &self.tokens).await;
            let bal = tokens.balance_of(&usdt_id, &buyer);
            if bal < usdt_micro {
                return Err("Insufficient wUSDT balance for PMM buy".to_string());
            }
            tokens
                .execute(
                    &usdt_id,
                    buyer,
                    crate::token::TokenOp::Burn { from: buyer, amount: usdt_micro },
                )
                .map_err(|e| format!("wUSDT debit failed: {e}"))?;
            let new_bal = tokens.balance_of(&usdt_id, &buyer);
            let mut trie = self.state_trie.write().await;
            let key = token_balance_key(&usdt_id, &buyer);
            if new_bal == 0 {
                trie.remove(&key);
            } else {
                trie.insert(&key, &new_bal.to_be_bytes());
            }
        }

        // 3. Mint native STELL to the buyer. If the credit fails (overflow),
        //    refund the burned wUSDT (as the minter) so the buy is all-or-nothing.
        if let Err(e) = self.credit_native(&buyer, receipt.stell_minted).await {
            let treasury = *self.pmm_treasury.read().await;
            let mut tokens = Self::mut_guard(&self.commitment_generation, &self.tokens).await;
            let _ = tokens.execute(
                &usdt_id,
                treasury,
                crate::token::TokenOp::Mint { to: buyer, amount: usdt_micro },
            );
            return Err(e);
        }

        // 4. Commit the advanced curve only after every value movement succeeded.
        *Self::mut_guard(&self.commitment_generation, &self.pmm).await = trial_pmm;
        Ok(receipt)
    }

    /// Sell `stell_nano` STELL back to the PMM for wUSDT. Atomically: debit
    /// native STELL from the seller, pay out wUSDT bounded by the ring-fenced
    /// usable reserve. Refunds native STELL if the curve rejects the sale.
    pub async fn pmm_sell(
        &self,
        seller: [u8; 32],
        stell_nano: u64,
    ) -> Result<crate::pmm::SellReceipt, String> {
        let usdt_id = self
            .pmm_usdt_token
            .read()
            .await
            .ok_or_else(|| "PMM USDT token not initialised".to_string())?;

        // 1. Dry-run the bonding curve on a clone so a rejected sell (dust /
        //    insufficient reserve) never debits the seller.
        let (trial_pmm, receipt) = {
            let pmm = self.pmm.read().await;
            let mut trial = pmm.clone();
            let receipt = trial.sell_stell(stell_nano).map_err(|e| e.to_string())?;
            (trial, receipt)
        };

        // 2. Debit native STELL from the seller (must have it).
        self.debit_native(&seller, stell_nano).await?;

        // 3. Pay wUSDT out of the PMM treasury — the wUSDT MINTER. The seller is
        //    NOT the minter, so the payout must be issued by the system treasury;
        //    otherwise the mint is rejected and the seller's STELL would be lost.
        //    If the payout cannot be minted, refund the native STELL (all-or-nothing).
        let treasury = *self.pmm_treasury.read().await;
        let paid = {
            let mut tokens = Self::mut_guard(&self.commitment_generation, &self.tokens).await;
            match tokens.execute(
                &usdt_id,
                treasury,
                crate::token::TokenOp::Mint { to: seller, amount: receipt.usdt_paid },
            ) {
                Ok(_) => {
                    let new_bal = tokens.balance_of(&usdt_id, &seller);
                    let mut trie = self.state_trie.write().await;
                    trie.insert(&token_balance_key(&usdt_id, &seller), &new_bal.to_be_bytes());
                    true
                }
                Err(_) => false,
            }
        };
        if !paid {
            let _ = self.credit_native(&seller, stell_nano).await;
            return Err("wUSDT payout failed (PMM treasury lacks minter authority)".to_string());
        }

        // 4. Commit the advanced curve only after the payout succeeded.
        *Self::mut_guard(&self.commitment_generation, &self.pmm).await = trial_pmm;
        Ok(receipt)
    }

    /// Credit native STELL to an account (mint) and commit to the trie.
    pub async fn credit_native(&self, addr: &[u8; 32], amount: u64) -> Result<(), String> {
        if amount == 0 {
            return Ok(());
        }
        let mut map = self.accounts.write().await;
        let acc = map.entry(*addr).or_insert_with(|| AccountState::new(*addr, 0));
        acc.balance = acc.balance.checked_add(amount).ok_or("native overflow")?;
        let snap = acc.to_trie_bytes();
        drop(map);
        let mut trie = self.state_trie.write().await;
        trie.insert(addr, &snap);
        Ok(())
    }

    /// Debit native STELL from an account (burn) and commit to the trie.
    pub async fn debit_native(&self, addr: &[u8; 32], amount: u64) -> Result<(), String> {
        let mut map = self.accounts.write().await;
        let acc = map.get_mut(addr).ok_or_else(|| "account does not exist".to_string())?;
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


    /// Apply the native half of a PMM swap: mint STELL to buyers, burn it from
    /// sellers, and commit every touched account to the state trie.
    ///
    /// Validation runs BEFORE any write, so a refusal - an unaffordable sell,
    /// an overflowing buy, or a swap that would eat the transaction's own
    /// `amount + gas + payload transfers` reservation - moves no coins at all.
    /// Returns the pre-swap snapshot (`None` = the account did not exist),
    /// which is what a failure later in the SAME payload needs in order to
    /// undo exactly this and nothing else (created accounts are removed, not
    /// zeroed, mirroring `commit_native`'s own undo).
    async fn settle_pmm_native(
        &self,
        events: &[crate::pmm::PmmEvent],
        payer: [u8; 32],
        floor: u64,
    ) -> Result<Vec<([u8; 32], Option<(u64, u64)>)>, String> {
        // Net native delta per account. Every PMM syscall acts on
        // `ctx.sender`, so in practice this is one entry, but the map keeps
        // the code correct if that ever changes.
        let mut delta: HashMap<[u8; 32], i128> = HashMap::new();
        for ev in events {
            let (addr, d) = match ev {
                crate::pmm::PmmEvent::Buy { buyer, stell_minted, .. } => {
                    (*buyer, *stell_minted as i128)
                }
                crate::pmm::PmmEvent::Sell { seller, stell_nano, .. } => {
                    (*seller, -(*stell_nano as i128))
                }
            };
            *delta.entry(addr).or_insert(0) += d;
        }

        let mut map = self.accounts.write().await;

        // Pass 1: validate against one consistent view of the balances.
        let mut snapshot: Vec<([u8; 32], Option<(u64, u64)>)> =
            Vec::with_capacity(delta.len());
        for (addr, d) in &delta {
            let prev = map.get(addr).map(|a| (a.balance, a.nonce));
            let bal = prev.map(|(b, _)| b).unwrap_or(0);
            let after = (bal as i128) + *d;
            if after < 0 || after > u64::MAX as i128 {
                return Err(format!(
                    "PMM settlement: {} would hold {after} nano-STELL after the swap",
                    hex::encode(&addr[..6])
                ));
            }
            snapshot.push((*addr, prev));
        }
        // The swap may not eat what `commit_native` still has to charge for
        // this transaction - otherwise the transaction is refused AFTER the
        // coins moved. Only checked when the swap actually touches the payer
        // (and only where nothing else re-checks it: the escrow settlement
        // asserts the same floor for payloads that carry order syscalls).
        if delta.contains_key(&payer) {
            let after = map.get(&payer).map(|a| a.balance).unwrap_or(0) as i128
                + delta.get(&payer).copied().unwrap_or(0);
            if after < floor as i128 {
                return Err(format!(
                    "PMM swap would leave {after} nano-STELL, {floor} is reserved for amount + gas + payload transfers"
                ));
            }
        }

        // Pass 2: apply, then mirror into the trie in the same order
        // `credit_native`/`debit_native` do it, so the account map and the
        // state root never disagree about the swap.
        let mut touched: Vec<([u8; 32], Vec<u8>)> = Vec::with_capacity(delta.len());
        for (addr, d) in &delta {
            let acc = map
                .entry(*addr)
                .or_insert_with(|| AccountState::new(*addr, 0));
            acc.balance = ((acc.balance as i128) + *d) as u64;
            touched.push((*addr, acc.to_trie_bytes()));
        }
        drop(map);

        let mut trie = self.state_trie.write().await;
        for (addr, data) in touched {
            trie.insert(&addr, &data);
        }
        Ok(snapshot)
    }

    /// Put back the native balances [`Self::settle_pmm_native`] moved, undoing
    /// the swap exactly. Called only when something AFTER the swap fails
    /// (the escrow settlement), where the swap must not survive a payload that
    /// is being rejected. Reverts in the VM never reach here: clone-commit
    /// already discarded them. Accounts the swap created (`None` pre-state)
    /// are removed with their trie entries, mirroring `commit_native`.
    async fn restore_pmm_native(&self, snapshot: &[([u8; 32], Option<(u64, u64)>)]) {
        if snapshot.is_empty() {
            return;
        }
        let mut map = self.accounts.write().await;
        let mut touched: Vec<([u8; 32], Vec<u8>)> = Vec::with_capacity(snapshot.len());
        let mut removed: Vec<[u8; 32]> = Vec::new();
        for (addr, prev) in snapshot.iter().rev() {
            match prev {
                Some((balance, nonce)) => {
                    if let Some(acc) = map.get_mut(addr) {
                        acc.balance = *balance;
                        acc.nonce = *nonce;
                        touched.push((*addr, acc.to_trie_bytes()));
                    }
                }
                None => {
                    map.remove(addr);
                    removed.push(*addr);
                }
            }
        }
        drop(map);

        let mut trie = self.state_trie.write().await;
        for (addr, data) in touched {
            trie.insert(&addr, &data);
        }
        for addr in removed {
            trie.remove(&addr);
        }
    }

    /// Put back the native balances [`Self::settle_clob_effects`] moved
    /// (Phase 2 `apply_native_moves`). Same shape and same rule as
    /// [`Self::restore_pmm_native`]: the CLOB leg settled last, so on a later
    /// `commit_native` refusal its snapshot is restored with the other legs
    /// via [`Self::rollback_payload`]. Created accounts are removed, not zeroed.
    async fn restore_clob_native(&self, snapshot: &[([u8; 32], Option<(u64, u64)>)]) {
        self.restore_pmm_native(snapshot).await;
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
        Self::mut_guard(&self.commitment_generation, &self.bridge).await
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
        match bincode::deserialize::<crate::bridge::BridgeState>(bytes) {
            Ok(state) => {
                *self.bridge_write().await = state;
                return Ok(());
            }
            Err(_) => {
                // Fall through to the older formats below.
            }
        }
        if let Ok(v2) = bincode::deserialize::<crate::bridge::BridgeStateV2>(bytes) {
            // Pre-dispute snapshot (no records/disputes): upgrade, LOUD —
            // deposits settled before the upgrade can never be challenged
            // (exactly like deposits older than CHALLENGE_MAX_AGE_SECS).
            tracing::warn!(
                "[bridge] restored pre-dispute V2 state: old deposits have no records and are unchallengeable"
            );
            *self.bridge_write().await = v2.upgrade();
            return Ok(());
        }
        let v1: crate::bridge::BridgeStateV1 = bincode::deserialize(bytes)
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

    /// Serialize the committed shielded ledger for persistence (audit F-B).
    ///
    /// Own storage tree, exactly like session keys and the bridge domain: the
    /// spent set and shielded balances are consensus state (they move the
    /// root when non-empty), and a restart that dropped them would both
    /// re-open spent commitments for double-spend AND compute a different
    /// root than the network. Absent entry means "empty" (zero digest bytes).
    pub async fn confidential_snapshot(&self) -> Vec<u8> {
        bincode::serialize(&*self.confidential.read().await).unwrap_or_default()
    }

    /// Install a persisted shielded ledger (startup restore). Bumps the
    /// commitment generation like every other domain install, so the restored
    /// spent set is folded into the very next root read.
    pub async fn restore_confidential(&self, bytes: &[u8]) -> Result<(), String> {
        match bincode::deserialize::<crate::crypto_privacy::ConfidentialState>(bytes) {
            Ok(state) => {
                *self.confidential_write().await = state;
                return Ok(());
            }
            Err(_) => {
                // Pre-ownership snapshot (no `owned` map): upgrade instead of
                // refusing to start. Pre-fix outputs are unattributed and
                // therefore unspendable (frozen, not stealable) — see
                // `ConfidentialStateV1`. LOUD, like the bridge upgrade.
            }
        }
        let v1: crate::crypto_privacy::ConfidentialStateV1 = bincode::deserialize(bytes)
            .map_err(|e| format!("restore confidential state failed: {e:?}"))?;
        *self.confidential_write().await = v1.upgrade();
        tracing::warn!(
            "[confidential] restored pre-ownership V1 state: old shielded outputs are FROZEN (unspendable until migration); new outputs are fully owned"
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
        let reg: crate::zkml::ZkMlModelRegistry = bincode::deserialize(bytes)
            .map_err(|e| format!("restore zkML models failed: {e:?}"))?;
        *self.zkml_models_write().await = reg;
        Ok(())
    }

    /// Apply the native half of one transaction's bridge intents AND the §8
    /// policy that gates them: relayer/validator quorum + source-tx replay for
    /// a deposit, the hourly rate limit and the time-lock for a withdrawal,
    /// maturity for a release.
    ///
    /// POLICY FIRST: [`crate::bridge::BridgeState::plan`] runs the intent list
    /// against the COMMITTED domain (pure - it writes nothing) using the
    /// `TeleportBridgeEngine` rules, so the live verdict cannot drift from the
    /// offline model. Only then does the coin half run, in the
    /// [`Self::settle_pmm_native`] shape: one consistent snapshot of the
    /// balances, a validation pass that moves nothing, an apply pass that
    /// mirrors every write into the trie, and finally the planned domain
    /// (replay set, queue, rate window, refreshed escrow mirror) under
    /// `bridge_write`. A refusal anywhere - sub-quorum, replayed source tx, a
    /// rate-limit breach, a time-locked release, or a withdrawal that would
    /// leave the payer below `floor` (the transaction's own `amount + gas +
    /// payload transfers`) - returns `Err` with NOTHING written.
    ///
    /// `now` is the BLOCK timestamp (PROTOCOL.md I12 - never a wall clock) and
    /// `validators` is the committed staking set the quorum counts DISTINCT
    /// signers from. An empty set fails closed: `plan` refuses deposits rather
    /// than computing a 2/3 threshold of zero.
    ///
    /// `Ok(None)` means no intent moved anything (a payload carrying only
    /// attestations), so there is nothing to restore later. `Ok(Some(_))`
    /// carries the pre-change accounts AND pre-change domain for rollback by a
    /// failure after this point.
    async fn settle_bridge_native(
        &self,
        intents: &[crate::bridge::BridgeIntent],
        payer: [u8; 32],
        floor: u64,
        now: u64,
        validators: &[[u8; 32]],
    ) -> Result<Option<BridgeSnapshot>, String> {
        // Policy pass: clone the committed domain, plan against it, write
        // nothing. Refusals here leave the accounts AND the domain untouched.
        let before = self.bridge.read().await.clone();
        let plan = before.plan(intents, validators, payer, now)?;
        if plan.effects.is_empty() && plan.state == before {
            // Nothing a block could commit (a payload with only attestations
            // is not state): no write guard, no generation bump, no movement.
            return Ok(None);
        }
        if plan.effects.is_empty() {
            // A policy-only state change: a RELEASE finalizes a parked
            // withdrawal (queue entry flips to executed) and moves no coins,
            // so there is no account pass - but the domain change IS consensus
            // state and must land (or a later failure must be able to undo it).
            let mut domain = Self::mut_guard(&self.commitment_generation, &self.bridge).await;
            *domain = plan.state;
            return Ok(Some(BridgeSnapshot {
                accounts: Vec::new(),
                domain: before,
            }));
        }

        let mut delta: HashMap<[u8; 32], i128> = HashMap::new();
        for effect in &plan.effects {
            match effect {
                crate::bridge::BridgeEffect::Credit { recipient, amount } => {
                    *delta.entry(*recipient).or_insert(0) += *amount as i128;
                }
                crate::bridge::BridgeEffect::Park { amount } => {
                    // The payer default keeps the map correct if a future
                    // caller allows a different sender.
                    *delta.entry(payer).or_insert(0) -= *amount as i128;
                    *delta
                        .entry(crate::bridge::BRIDGE_ESCROW)
                        .or_insert(0) += *amount as i128;
                }
                crate::bridge::BridgeEffect::Unpark { recipient, amount } => {
                    // Refund (F-G): escrow back to the original depositor.
                    // Escrow sufficiency is enforced in Pass 1 below like
                    // every other debit (an underfunded escrow fails the
                    // whole tx — fail closed, never partial).
                    *delta
                        .entry(crate::bridge::BRIDGE_ESCROW)
                        .or_insert(0) -= *amount as i128;
                    *delta.entry(*recipient).or_insert(0) += *amount as i128;
                }
                crate::bridge::BridgeEffect::Clawback { account, amount } => {
                    // Challenge: pull the credited funds back into escrow.
                    // Pass 1 below fails the whole tx if the account already
                    // moved them (after < 0) — fail closed, never partial.
                    *delta.entry(*account).or_insert(0) -= *amount as i128;
                    *delta
                        .entry(crate::bridge::BRIDGE_ESCROW)
                        .or_insert(0) += *amount as i128;
                }
                crate::bridge::BridgeEffect::Burn { amount } => {
                    // Revoke: destroy escrowed funds (deflationary). Pass 1
                    // fails the whole tx if escrow cannot cover it — a burn
                    // of thin air is refused, never rounded to zero.
                    *delta
                        .entry(crate::bridge::BRIDGE_ESCROW)
                        .or_insert(0) -= *amount as i128;
                }
            }
        }

        let mut map = self.accounts.write().await;

        // Pass 1: validate against one consistent view of the balances.
        let mut snapshot: Vec<([u8; 32], Option<(u64, u64)>)> =
            Vec::with_capacity(delta.len());
        for (addr, d) in &delta {
            let prev = map.get(addr).map(|a| (a.balance, a.nonce));
            let bal = prev.map(|(b, _)| b).unwrap_or(0);
            let after = (bal as i128) + *d;
            if after < 0 || after > u64::MAX as i128 {
                return Err(format!(
                    "bridge settlement: {} would hold {after} nano-STELL after the transfer",
                    hex::encode(&addr[..6])
                ));
            }
            snapshot.push((*addr, prev));
        }
        if delta.contains_key(&payer) {
            let after = map.get(&payer).map(|a| a.balance).unwrap_or(0) as i128
                + delta.get(&payer).copied().unwrap_or(0);
            if after < floor as i128 {
                return Err(format!(
                    "bridge withdrawal would leave {after} nano-STELL, {floor} is reserved for amount + gas + payload transfers"
                ));
            }
        }

        // Pass 2: apply, then mirror the trie so the account map and the state
        // root never disagree.
        let mut touched: Vec<([u8; 32], Vec<u8>)> = Vec::with_capacity(delta.len());
        for (addr, d) in &delta {
            let acc = map.entry(*addr).or_insert_with(|| AccountState::new(*addr, 0));
            acc.balance = ((acc.balance as i128) + *d) as u64;
            touched.push((*addr, acc.to_trie_bytes()));
        }
        // Refresh the committed escrow mirror from the account that is the
        // authority for it, so the digest and the trie can never disagree
        // about how much the bridge has parked.
        let mut state = plan.state;
        state.escrow_balance = map
            .get(&crate::bridge::BRIDGE_ESCROW)
            .map(|a| a.balance)
            .unwrap_or(0);
        drop(map);

        // Commit the policy state (replay set, queue, rate window, mirror).
        // Written under `mut_guard` so `commitment_generation` moves and the
        // very next root read folds it into the digest.
        {
            let mut domain = Self::mut_guard(&self.commitment_generation, &self.bridge).await;
            *domain = state;
        }

        let mut trie = self.state_trie.write().await;
        for (addr, data) in touched {
            trie.insert(&addr, &data);
        }
        Ok(Some(BridgeSnapshot {
            accounts: snapshot,
            domain: before,
        }))
    }

    /// Put back what [`Self::settle_bridge_native`] moved: the native balances
    /// AND the committed bridge domain. Called only when something AFTER the
    /// bridge leg fails (the escrow settlement), where neither the coins nor
    /// the replay set / withdrawal queue / rate window of a rejected payload
    /// may survive - a leftover replay-set entry would block a legitimate
    /// re-submission, a leftover queue entry would be a phantom withdrawal.
    /// Accounts the leg created (`None` pre-state) are removed with their
    /// trie entries, mirroring `commit_native`'s own undo.
    async fn restore_bridge_native(&self, snap: Option<&BridgeSnapshot>) {
        let Some(snap) = snap else {
            return;
        };
        let mut map = self.accounts.write().await;
        let mut touched: Vec<([u8; 32], Vec<u8>)> = Vec::with_capacity(snap.accounts.len());
        let mut removed: Vec<[u8; 32]> = Vec::new();
        for (addr, prev) in snap.accounts.iter().rev() {
            match prev {
                Some((balance, nonce)) => {
                    if let Some(acc) = map.get_mut(addr) {
                        acc.balance = *balance;
                        acc.nonce = *nonce;
                        touched.push((*addr, acc.to_trie_bytes()));
                    }
                }
                None => {
                    map.remove(addr);
                    removed.push(*addr);
                }
            }
        }
        // Re-derive the escrow mirror from the RESTORED account, the same way
        // settlement derived it from the applied one.
        let mut domain = snap.domain.clone();
        domain.escrow_balance = map
            .get(&crate::bridge::BRIDGE_ESCROW)
            .map(|a| a.balance)
            .unwrap_or(0);
        drop(map);

        {
            let mut g = Self::mut_guard(&self.commitment_generation, &self.bridge).await;
            *g = domain;
        }

        let mut trie = self.state_trie.write().await;
        for (addr, data) in touched {
            trie.insert(&addr, &data);
        }
        for addr in removed {
            trie.remove(&addr);
        }
    }

    /// Settle ONE payload's actor sends: debit the sender for the total value
    /// and enqueue one message per send into the RECIPIENT's inbox - or, when
    /// the recipient account does not exist, bounce it straight back into the
    /// sender's inbox (the rule the engine's direct `send_message` API has
    /// always applied, so value is never parked against an address nothing
    /// can ever deliver to).
    ///
    /// Two-phase on purpose: EVERYTHING is validated first (all sends
    /// bounceable, no value overflow, sender can afford `floor + total`),
    /// then applied infallibly - so a refusal leaves the map untouched and
    /// the caller needs no rollback for a failure of THIS leg, only the
    /// returned [`ActorSnapshot`] for a failure of a LATER one.
    ///
    /// `floor` is what `commit_native` will still demand from the same sender
    /// after this payload (`amount + declared gas + payload transfers`; 0
    /// when the CLOB escrow below re-asserts that itself): the debit must not
    /// eat into it, or the native commit would refuse a transaction whose
    /// messages are already queued.
    ///
    /// Deliberately does NOT write the trie: the sender's balance reaches the
    /// trie through `commit_native` (which runs only for a transaction that
    /// commits), and inboxes are not trie state at all. A rollback therefore
    /// only has to put the account map back.
    async fn settle_actor_sends(
        &self,
        sends: &[crate::svm::ActorSendRequest],
        sender: [u8; 32],
        floor: u64,
    ) -> Result<Option<ActorSnapshot>, String> {
        if sends.is_empty() {
            return Ok(None);
        }
        // v1: every send must be bounceable. The VM already refuses one that
        // is not (before this leg, so the payload would have reverted) - this
        // is the settlement-side belt for the same rule, because refusing is
        // here exactly where value WOULD be destroyed.
        if sends.iter().any(|s| !s.bounce) {
            return Err("actor send rejected: bounce is required (v1)".to_string());
        }
        let total = sends
            .iter()
            .try_fold(0u64, |acc, s| acc.checked_add(s.value))
            .ok_or_else(|| "actor send: value overflow".to_string())?;
        let needed = floor
            .checked_add(total)
            .ok_or_else(|| "actor send: cost overflow".to_string())?;

        let mut map = self.accounts.write().await;
        {
            let snd = map
                .get(&sender)
                .ok_or_else(|| "actor send: sender account does not exist".to_string())?;
            if snd.balance < needed {
                return Err(format!(
                    "actor send: sender holds {} nano-STELL but {needed} is required \
                     ({floor} reserved for amount + gas + payload transfers)",
                    snd.balance
                ));
            }
        }

        // Pre-state of every account this settlement touches, for the caller's
        // rollback record. Recorded BEFORE each mutation; `noted` keeps the
        // FIRST (pre-settlement) value if an account is touched twice.
        let mut snapshot: Vec<([u8; 32], AccountState)> = Vec::with_capacity(sends.len() + 1);
        let mut noted: HashSet<[u8; 32]> = HashSet::with_capacity(sends.len() + 1);
        note_account_before(&map, &mut snapshot, &mut noted, sender);
        // One debit for the whole payload's sends (checked above).
        {
            let snd = map
                .get_mut(&sender)
                .expect("sender existence re-checked above");
            snd.balance -= total;
        }

        for s in sends {
            let encoded = encode_actor_body(&s.body, s.gas_budget);
            let msg = ActorMessage::new(sender, s.recipient, s.value, encoded, s.bounce);
            if map.contains_key(&s.recipient) {
                note_account_before(&map, &mut snapshot, &mut noted, s.recipient);
                // Enqueue is infallible; FIFO order for the recipient is the
                // payload's own program order.
                map.get_mut(&s.recipient)
                    .expect("recipient existence checked above")
                    .inbox
                    .push_back(msg);
            } else {
                // Missing recipient: the value is already debited above, and
                // the bounce below returns it - EXACTLY once, when the mailbox
                // pass delivers this message (never here, never again).
                let bounce = ActorMessage {
                    msg_id: msg.msg_id,
                    sender: s.recipient,
                    recipient: sender,
                    value: msg.value,
                    body: msg.body,
                    bounce: false,
                    bounced: true,
                };
                map.get_mut(&sender)
                    .expect("sender existence re-checked above")
                    .inbox
                    .push_back(bounce);
            }
        }

        Ok(Some(ActorSnapshot { accounts: snapshot }))
    }

    /// Put back what [`Self::settle_actor_sends`] moved: balances AND inboxes,
    /// for every account it touched. Called only when something AFTER the
    /// actor leg fails (the CLOB escrow), where neither the debit nor the
    /// queued messages of a refused payload may survive - a message left in an
    /// inbox would deliver value its transaction never paid for.
    ///
    /// No trie write: the settlement never wrote one (see
    /// `settle_actor_sends`), so the map is the only thing to restore.
    async fn restore_actor_native(&self, snap: Option<&ActorSnapshot>) {
        let Some(snap) = snap else {
            return;
        };
        if snap.accounts.is_empty() {
            return;
        }
        let mut map = self.accounts.write().await;
        for (addr, acc) in &snap.accounts {
            map.insert(*addr, acc.clone());
        }
    }

    /// Execute a token operation and commit every affected balance to the state trie.
    /// This is the canonical entry point for on-chain token activity.
    pub async fn token_execute(
        &self,
        token_id: &[u8; 32],
        caller: [u8; 32],
        op: TokenOp,
    ) -> Result<TokenEvent, TokenError> {
        let mut tokens = Self::mut_guard(&self.commitment_generation, &self.tokens).await;
        let event = tokens.execute(token_id, caller, op.clone())?;

        // Which accounts were affected? (used for trie synchronization)
        let affected: Vec<[u8; 32]> = match &op {
            TokenOp::Transfer { to, .. } => vec![caller, *to],
            TokenOp::TransferFrom { from, to, .. } => vec![*from, *to],
            TokenOp::Mint { to, .. } => vec![*to],
            TokenOp::Burn { from, .. } => vec![*from],
            TokenOp::Approve { .. }
            | TokenOp::IncreaseAllowance { .. }
            | TokenOp::DecreaseAllowance { .. }
            | TokenOp::SetMinter { .. }
            | TokenOp::RenounceMinter
            | TokenOp::Pause
            | TokenOp::Unpause => vec![],
        };

        let mut trie = self.state_trie.write().await;
        if let Some(token) = tokens.get(token_id) {
            for acct in affected {
                let bal = token.balance_of(&acct);
                let key = token_balance_key(token_id, &acct);
                if bal == 0 {
                    trie.remove(&key);
                } else {
                    trie.insert(&key, &bal.to_be_bytes());
                }
            }
            // Total supply changes on mint/burn
            if matches!(op, TokenOp::Mint { .. } | TokenOp::Burn { .. }) {
                trie.insert(&token_supply_key(token_id), &token.metadata.total_supply.to_be_bytes());
            }
        }
        Ok(event)
    }

    /// Query a token balance held by an account.
    pub async fn token_balance(&self, token_id: &[u8; 32], account: &[u8; 32]) -> u64 {
        self.tokens.read().await.balance_of(token_id, account)
    }

    pub async fn token_total_supply(&self, token_id: &[u8; 32]) -> Option<u64> {
        self.tokens.read().await.get(token_id).map(|t| t.metadata.total_supply)
    }

    pub async fn token_resolve(
        &self,
        creator: &[u8; 32],
        name: &str,
        symbol: &str,
    ) -> Option<[u8; 32]> {
        self.tokens.read().await.find_by_creator_name(creator, name, symbol)
    }

    pub async fn all_token_ids(&self) -> Vec<[u8; 32]> {
        self.tokens.read().await.all_token_ids()
    }

    /// Generate an SPV Merkle proof for a token balance (proves holdings against
    /// the consensus state root, exactly like a native STELL balance).
    pub async fn get_token_balance_proof(
        &self,
        token_id: &[u8; 32],
        account: &[u8; 32],
    ) -> Option<MerkleProof> {
        let key = token_balance_key(token_id, account);
        self.state_trie.read().await.generate_merkle_proof(&key)
    }

    /// Persist the whole token registry (separate from account snapshot).
    pub async fn create_token_snapshot(&self) -> Vec<u8> {
        let tokens = self.tokens.read().await;
        bincode::serialize(&*tokens).unwrap_or_default()
    }

    pub async fn restore_token_snapshot(&self, bytes: &[u8]) -> Result<(), String> {
        let reg: TokenRegistry = bincode::deserialize(bytes)
            .map_err(|e| format!("Restore token snapshot failed: {:?}", e))?;
        // Consistent lock order: tokens -> trie
        let mut tokens = Self::mut_guard(&self.commitment_generation, &self.tokens).await;
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
        StateSnapshotV2 { accounts, penalty }
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
        let (snapshot, penalty) = Self::parse_account_snapshot(bytes)?;
        // The penalty is restored BEFORE the accounts lock is taken: the
        // documented lock order is penalty/governance -> accounts, and the
        // reverse order here would be an ABBA deadlock against `commit_native`
        // (which reads the floor before it takes the accounts lock).
        *self.consensus_penalty.write().await = penalty;

        // This rebuilds the trie from scratch, which drops the commitment digest
        // key. Bump the generation so the next root read is forced to recompute and
        // re-insert it; otherwise the generation-guarded skip would serve a trie that
        // is missing the subsystem commitment.
        self.bump_commitment_generation();

        // The cross-shard replay sets are derived from applied blocks and are
        // not part of the accounts snapshot: clear them so a reorg that
        // restores to a checkpoint and replays the canonical chain rebuilds
        // them from scratch rather than refusing a message the replayed chain
        // legitimately consumes again. ALL THREE committed sets are cleared
        // together - clearing consumed while keeping produced/completed (or
        // vice versa) would rebuild a frankenset whose linkage/completion no
        // longer matches the replayed blocks. This clear is correct ONLY for
        // the reorg-replay path; snapshot-sync and boot MUST use
        // `restore_snapshot_preserve_replay_sets` plus the fail-closed
        // coverage gate (`cross_shard_replay_covers`), never this method.
        self.cross_shard_consumed.write().await.clear();
        self.cross_shard_produced.write().await.clear();
        self.cross_shard_completed.write().await.clear();

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
    pub async fn restore_snapshot_preserve_replay_sets(
        &self,
        bytes: &[u8],
    ) -> Result<(), String> {
        let (snapshot, penalty) = Self::parse_account_snapshot(bytes)?;
        // The penalty travels with the state (see `create_snapshot`): install
        // it BEFORE the accounts lock (documented lock order).
        *self.consensus_penalty.write().await = penalty;

        // Same generation bump as `restore_snapshot`: the trie is rebuilt from
        // scratch, dropping the commitment digest key.
        self.bump_commitment_generation();

        // NO replay-set clear here - that is the entire point of this method
        // (see its docs). The caller owns the replay outcome via the coverage
        // gate + `restore_cross_shard_replay`.

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
    /// The decoder accepts the versioned [`StateSnapshotV2`] form and the
    /// legacy bare-`Vec<AccountState>` form (whose penalty is empty - a
    /// snapshot written before the penalty existed carries none).
    fn parse_account_snapshot(
        bytes: &[u8],
    ) -> Result<(Vec<AccountState>, HashMap<[u8; 32], u64>), String> {
        // V2 FIRST: the legacy blob is a bare `Vec<AccountState>`, which
        // decodes as V2 only if the trailing penalty map happens to be
        // present - it never is, so a legacy blob fails here and falls
        // through to the legacy decoders below.
        if let Ok(v2) = bincode::deserialize::<StateSnapshotV2>(bytes) {
            return Ok((v2.accounts, v2.penalty));
        }
        match bincode::deserialize(bytes) {
            Ok(s) => Ok((s, HashMap::new())),
            Err(_) => {
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
                let legacy: Vec<LegacyAccountState> = bincode::deserialize(bytes)
                    .map_err(|e| format!("Restore snapshot failed: {:?}", e))?;
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
                ))
            }
        }
    }
}

/// The versioned state snapshot: the accounts PLUS the D2 consensus penalty
/// map.
///
/// WHY A NEW SHAPE: the penalty is not cosmetic - it enters the CONSENSUS fee
/// floor (`consensus_floor_parts` -> the fee `commit_native` charges -> the
/// sender's balance -> the state root). A state snapshot that carried only
/// the accounts would leave a restored node with an EMPTY penalty map while a
/// node that applied the blocks has the real one: the two would then charge
/// DIFFERENT fees for the same transaction and end up with DIFFERENT state
/// roots - a consensus split, triggered by nothing more exotic than a node
/// restarting or syncing from a snapshot (audit W6.6).
///
/// The legacy bare-`Vec<AccountState>` snapshot is still accepted (its
/// penalty is empty, exactly as before this shape existed); see
/// `parse_account_snapshot`.
///
/// PUBLIC because the OFF-TICK persistence path must write the SAME shape:
/// see [`InMemoryStateEngine::capture_state_snapshot`] and
/// `crate::storage::clone_account_snapshot`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StateSnapshotV2 {
    /// The accounts, address-sorted.
    pub accounts: Vec<AccountState>,
    /// The D2 consensus penalty map (sender -> penalty).
    pub penalty: HashMap<[u8; 32], u64>,
}

impl InMemoryStateEngine {
    /// Decode the chunks produced by `create_snapshot_chunked` (validate phase,
    /// no locks held): the account groups AND the penalty map carried by the
    /// FIRST chunk.
    ///
    /// The first chunk is the [`StateSnapshotV2`] shape (accounts + penalty);
    /// the rest are bare account chunks. A legacy chunk set (no penalty) is
    /// still accepted - the penalty is then empty, exactly as before the shape
    /// existed.
    fn decode_snapshot_chunks(
        chunks: &[Vec<u8>],
    ) -> Result<(Vec<Vec<AccountState>>, HashMap<[u8; 32], u64>), String> {
        let mut decoded: Vec<Vec<AccountState>> = Vec::with_capacity(chunks.len());
        let mut penalty: HashMap<[u8; 32], u64> = HashMap::new();
        for (i, raw) in chunks.iter().enumerate() {
            if i == 0 {
                if let Ok(v2) = bincode::deserialize::<StateSnapshotV2>(raw) {
                    decoded.push(v2.accounts);
                    penalty = v2.penalty;
                    continue;
                }
            }
            let states: Vec<AccountState> = bincode::deserialize(raw)
                .map_err(|e| format!("restore snapshot chunk {i} failed: {e:?}"))?;
            decoded.push(states);
        }
        Ok((decoded, penalty))
    }
}


// ============ Phase 1 memory bounds (audit: /tmp/opencode/memory-audit.md) ============
//
// At scale (tens of millions of accounts) every unbounded in-memory map is an
// OOM death. This module holds the Phase-1 primitives:
//
// * `BoundedLruCache` — generic bounded LRU with throttled-loud eviction and
//   disk read-through (`get_or_load`: a loader miss/error returns `None` —
//   reads fail OPEN via disk, never fail closed).
//   FAIL-OPEN AUDIT (per caller — a `None` here must never attest anything):
//   * PQ-key fallback: a miss (evicted, or loader error on a diskless node)
//     makes `get_pinned_pubkey` return `None`, and every caller treats `None`
//     as "no key" — PQ-gated admission REFUSES (fail-closed verification).
//     An eviction therefore costs availability (re-pin via gossip), never a
//     forged acceptance. The attached sled tree, when present, is the
//     authority and the fallback is not even consulted.
//   * `BlockBodyCache::get_or_load_block`: a miss returns `None` (honest
//     miss → refetch by hash, and `committed_body` re-hashes whatever the
//     disk serves). Bodies are hash-committed, so a wrong disk byte can never
//     become a believed body — it fails the hash check instead.
//   * Consensus-critical maps (accounts, staking ledger, replay sets,
//     validator sets) are NEVER behind this cache: the accounts map has no
//     eviction path at all (watermark warns only — see below), so eviction
//   cannot drop consensus state by construction.
// * `BlockBodyCache` — the block/body cache shape (`STELL_MAX_CACHED_BLOCKS`,
//   default 2048). Implemented + tested here; wiring into
//   `ValidatorRuntime.blocks` / `BlockTree` is Phase 2 (other agents' files).
// * `VoteRoundHistory` — keeps rounds `current-2..=current`, preserves locking
//   info across prune, `reset_for_height` stops cross-height accumulation.
//   (`HeightConsensus` already retains 8 rounds; adopting this is Phase 2.)
// * Chunked snapshots + account watermark accounting (methods on the engine).
//
// Every cap is env-overridable. Eviction is LOUD (`tracing::warn!`, throttled
// to one line per 60 s per cache instance). Nothing here ever fails closed.
pub mod memory_bounds {
    use std::collections::{BTreeMap, HashMap, VecDeque};

    /// Read a `usize` cap from the environment; unparseable/zero → default.
    /// Zero can never mean "store nothing" (that would fail closed), so it
    /// falls back to the default like any other bad value.
    pub fn env_usize(key: &str, default: usize) -> usize {
        std::env::var(key)
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(default)
    }

    /// `u64` variant of [`env_usize`].
    pub fn env_u64(key: &str, default: u64) -> u64 {
        std::env::var(key)
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(default)
    }

    /// Minimum milliseconds between two loud warnings from one source.
    pub const EVICT_WARN_INTERVAL_MS: u64 = 60_000;

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// Emit `msg` at warn level at most once per `interval_ms` (per counter).
    /// Lock-free; a lost CAS race only ever SKIPS a duplicate line.
    pub fn warn_throttled(
        last_ms: &std::sync::atomic::AtomicU64,
        interval_ms: u64,
        msg: &str,
    ) {
        let now = now_ms();
        let last = last_ms.load(std::sync::atomic::Ordering::Relaxed);
        if now.saturating_sub(last) < interval_ms {
            return;
        }
        if last_ms
            .compare_exchange_weak(
                last,
                now,
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
            )
            .is_ok()
        {
            tracing::warn!("[memory-bounds] {msg}");
        }
    }

    /// A bounded LRU cache with loud, throttled eviction and disk read-through.
    ///
    /// * Inserting past `cap` evicts the least-recently-used live entry and
    ///   warns (throttled) — the "eviction LOUD" rule.
    /// * `get_or_load` consults `loader` (the disk side) on a miss; a loader
    ///   miss or error yields `None` — reads fail OPEN, never closed.
    /// * Recency is sequence-based with lazy queue deletion: every op is
    ///   amortized O(1); the order queue holds at most (#inserts) stale
    ///   entries, reclaimed by the eviction scan.
    #[derive(Debug)]
    pub struct BoundedLruCache<K, V> {
        name: &'static str,
        cap: usize,
        map: HashMap<K, CacheEntry<V>>,
        order: VecDeque<(u64, K)>,
        next_seq: u64,
        hits: u64,
        misses: u64,
        evictions: u64,
        last_warn_ms: std::sync::atomic::AtomicU64,
    }

    #[derive(Debug, Clone)]
    struct CacheEntry<V> {
        value: V,
        seq: u64,
    }

    impl<K, V> Clone for BoundedLruCache<K, V>
    where
        K: Clone,
        V: Clone,
    {
        fn clone(&self) -> Self {
            Self {
                name: self.name,
                cap: self.cap,
                map: self.map.clone(),
                order: self.order.clone(),
                next_seq: self.next_seq,
                hits: self.hits,
                misses: self.misses,
                evictions: self.evictions,
                last_warn_ms: std::sync::atomic::AtomicU64::new(0),
            }
        }
    }

    impl<K, V> BoundedLruCache<K, V>
    where
        K: Clone + Eq + std::hash::Hash,
        V: Clone,
    {
        /// Create with an explicit cap (clamped to ≥ 1 — a zero cap would fail
        /// closed on every insert, which this module never does).
        pub fn new(name: &'static str, cap: usize) -> Self {
            Self {
                name,
                cap: cap.max(1),
                map: HashMap::new(),
                order: VecDeque::new(),
                next_seq: 0,
                hits: 0,
                misses: 0,
                evictions: 0,
                last_warn_ms: std::sync::atomic::AtomicU64::new(0),
            }
        }

        /// Create with the cap read from `env_key` (fallback `default`).
        pub fn with_env(name: &'static str, env_key: &str, default: usize) -> Self {
            Self::new(name, env_usize(env_key, default))
        }

        pub fn cap(&self) -> usize {
            self.cap
        }

        /// Resize the cap (env reload path); evicts down immediately if over.
        pub fn set_cap(&mut self, cap: usize) {
            self.cap = cap.max(1);
            while self.map.len() > self.cap {
                if !self.evict_oldest() {
                    break;
                }
            }
        }

        pub fn len(&self) -> usize {
            self.map.len()
        }

        pub fn is_empty(&self) -> bool {
            self.map.is_empty()
        }

        pub fn evictions(&self) -> u64 {
            self.evictions
        }

        pub fn hits(&self) -> u64 {
            self.hits
        }

        pub fn misses(&self) -> u64 {
            self.misses
        }

        pub fn contains(&self, key: &K) -> bool {
            self.map.contains_key(key)
        }

        /// LRU-get: returns a clone and refreshes recency. Needs `&mut`
        /// (recency is a write); use `peek` for a lock-free read.
        pub fn get(&mut self, key: &K) -> Option<V> {
            let seq = self.next_seq.wrapping_add(1);
            if let Some(e) = self.map.get_mut(key) {
                self.next_seq = seq;
                e.seq = seq;
                self.order.push_back((seq, key.clone()));
                self.hits += 1;
                return Some(e.value.clone());
            }
            None
        }

        /// Read without touching recency.
        pub fn peek(&self, key: &K) -> Option<V> {
            self.map.get(key).map(|e| e.value.clone())
        }

        /// Insert, evicting the coldest entry when over cap. Eviction warns
        /// (throttled) naming the cache, the cap and the lifetime count.
        pub fn insert(&mut self, key: K, value: V) {
            let seq = self.next_seq.wrapping_add(1);
            self.next_seq = seq;
            if let Some(e) = self.map.get_mut(&key) {
                e.value = value;
                e.seq = seq;
            } else {
                if self.map.len() >= self.cap {
                    self.evict_oldest();
                }
                self.map.insert(key.clone(), CacheEntry { value, seq });
            }
            self.order.push_back((seq, key));
        }

        /// Read-through: hit serves from memory; miss calls `loader` (the
        /// disk side) and admits what it returns. Loader miss/error → `None`
        /// (fail-open). An entry the loader serves is never treated as a
        /// failure even if it was previously evicted.
        pub fn get_or_load<E>(
            &mut self,
            key: K,
            loader: impl FnOnce(&K) -> Result<Option<V>, E>,
        ) -> Option<V> {
            if let Some(v) = self.get(&key) {
                return Some(v);
            }
            self.misses += 1;
            match loader(&key) {
                Ok(Some(v)) => {
                    self.insert(key, v.clone());
                    Some(v)
                }
                Ok(None) => None,
                Err(_) => None,
            }
        }

        /// Evict the oldest LIVE entry. Returns false when nothing evictable
        /// was found (stale queue drained without a live hit — cannot happen
        /// while `map.len() > 0`, but the loop must terminate regardless).
        fn evict_oldest(&mut self) -> bool {
            while let Some((seq, key)) = self.order.pop_front() {
                let live = self.map.get(&key).map(|e| e.seq) == Some(seq);
                if live {
                    self.map.remove(&key);
                    self.evictions += 1;
                    let n = self.evictions;
                    let name = self.name;
                    let cap = self.cap;
                    warn_throttled(
                        &self.last_warn_ms,
                        EVICT_WARN_INTERVAL_MS,
                        &format!(
                            "{name} over cap ({cap}): evicted coldest entry \
                             (lifetime evictions {n}) — size stays bounded, \
                             evicted entries are re-served from disk on demand"
                        ),
                    );
                    return true;
                }
            }
            false
        }
    }

    // ---------- block / body cache ----------

    /// Default cap for cached block bodies (bytes per body are whatever the
    /// chain produces; count-bound like every other Phase-1 cap).
    pub const DEFAULT_MAX_CACHED_BLOCKS: usize = 2048;

    /// Effective cap: `STELL_MAX_CACHED_BLOCKS`, default 2048.
    pub fn max_cached_blocks() -> usize {
        env_usize("STELL_MAX_CACHED_BLOCKS", DEFAULT_MAX_CACHED_BLOCKS)
    }

    /// Bounded LRU for block bodies keyed by block hash, with disk fallback
    /// read-through: a lookup the disk can serve never fails just because the
    /// entry was evicted. Phase-2 wiring target for `ValidatorRuntime.blocks`
    /// / `BlockTree` (out of Phase-1 file scope).
    #[derive(Debug, Clone)]
    pub struct BlockBodyCache {
        inner: BoundedLruCache<[u8; 32], Vec<u8>>,
    }

    impl BlockBodyCache {
        pub fn new(cap: usize) -> Self {
            Self { inner: BoundedLruCache::new("block_body_cache", cap) }
        }

        pub fn with_env() -> Self {
            Self::new(max_cached_blocks())
        }

        pub fn cap(&self) -> usize {
            self.inner.cap()
        }

        pub fn set_cap(&mut self, cap: usize) {
            self.inner.set_cap(cap);
        }

        pub fn len(&self) -> usize {
            self.inner.len()
        }

        pub fn is_empty(&self) -> bool {
            self.inner.is_empty()
        }

        pub fn evictions(&self) -> u64 {
            self.inner.evictions()
        }

        pub fn contains(&self, hash: &[u8; 32]) -> bool {
            self.inner.contains(hash)
        }

        pub fn insert(&mut self, hash: [u8; 32], body: Vec<u8>) {
            self.inner.insert(hash, body);
        }

        /// `loader` is the disk side (e.g. `Storage::get_block` bytes). Disk
        /// miss/error → `None`, never an error.
        pub fn get_or_load_block<E>(
            &mut self,
            hash: [u8; 32],
            loader: impl FnOnce(&[u8; 32]) -> Result<Option<Vec<u8>>, E>,
        ) -> Option<Vec<u8>> {
            self.inner.get_or_load(hash, loader)
        }
    }

    // ---------- PQ-key fallback bound ----------

    /// Default cap for the sled-less PQ-key fallback map.
    pub const DEFAULT_MAX_PQ_FALLBACK_ENTRIES: usize = 65_536;

    /// Effective cap: `STELL_MAX_PQ_FALLBACK_ENTRIES`, default 65536.
    pub fn max_pq_fallback_entries() -> usize {
        env_usize(
            "STELL_MAX_PQ_FALLBACK_ENTRIES",
            DEFAULT_MAX_PQ_FALLBACK_ENTRIES,
        )
    }

    // ---------- vote-set / round history ----------

    /// Rounds retained behind the current one: `current-2..=current`.
    pub const VOTE_HISTORY_KEEP_ROUNDS: u64 = 2;

    /// Bounded per-height round history. Inserting or advancing past the
    /// window prunes rounds older than `current - KEEP` while `lock_info`
    /// (the Tendermint lock: value + round) survives the prune untouched.
    /// `reset_for_height` drops every round bucket so history can never
    /// accumulate across heights; the lock record is kept for the caller to
    /// carry or clear explicitly.
    #[derive(Debug, Clone, Default)]
    pub struct VoteRoundHistory<V> {
        rounds: BTreeMap<u64, V>,
        current: u64,
        lock_info: Option<([u8; 32], u64)>,
    }

    impl<V> VoteRoundHistory<V> {
        pub fn new() -> Self {
            Self {
                rounds: BTreeMap::new(),
                current: 0,
                lock_info: None,
            }
        }

        pub fn current(&self) -> u64 {
            self.current
        }

        pub fn len(&self) -> usize {
            self.rounds.len()
        }

        pub fn is_empty(&self) -> bool {
            self.rounds.is_empty()
        }

        pub fn oldest(&self) -> Option<u64> {
            self.rounds.keys().next().copied()
        }

        /// Record the lock (value voted + round locked). Survives pruning.
        pub fn set_lock(&mut self, hash: [u8; 32], round: u64) {
            self.lock_info = Some((hash, round));
        }

        pub fn clear_lock(&mut self) {
            self.lock_info = None;
        }

        pub fn lock_info(&self) -> Option<([u8; 32], u64)> {
            self.lock_info
        }

        /// Move `current` forward (never backward) and prune everything older
        /// than `current - KEEP`. Late/backward calls only prune.
        pub fn advance_to(&mut self, round: u64) {
            if round > self.current {
                self.current = round;
            }
            self.prune();
        }

        /// Insert a round bucket. Returns false (dropped) when the round is
        /// already outside the retention window — history never grows it back.
        pub fn insert(&mut self, round: u64, votes: V) -> bool {
            let floor = self.current.saturating_sub(VOTE_HISTORY_KEEP_ROUNDS);
            if round < floor {
                return false;
            }
            if round > self.current {
                self.current = round;
            }
            self.rounds.insert(round, votes);
            self.prune();
            true
        }

        pub fn get(&self, round: u64) -> Option<&V> {
            self.rounds.get(&round)
        }

        /// New height: drop every round bucket. The lock record is preserved
        /// for the caller (height-scoped callers should `clear_lock` too).
        pub fn reset_for_height(&mut self) {
            self.rounds.clear();
            self.current = 0;
        }

        fn prune(&mut self) {
            let floor = self.current.saturating_sub(VOTE_HISTORY_KEEP_ROUNDS);
            self.rounds.retain(|&r, _| r >= floor);
        }
    }

    // ---------- account / trie hot-state accounting ----------

    /// Warn threshold for live account count (soft watermark — consensus state
    /// is NEVER evicted; evicting it would fork the chain).
    pub const DEFAULT_MAX_ACCOUNTS_WARN: u64 = 5_000_000;

    /// Effective watermark: `STELL_MAX_ACCOUNTS_WARN`, default 5_000_000.
    pub fn accounts_memory_warn_threshold() -> u64 {
        env_u64("STELL_MAX_ACCOUNTS_WARN", DEFAULT_MAX_ACCOUNTS_WARN)
    }

    /// Rough bytes per live account: 32 B key + ~200 B value + HashMap slot +
    /// heap + amortized compressed-trie path (~50–150 B). Deliberately coarse:
    /// it sizes orders of magnitude, not pages.
    pub const EST_BYTES_PER_ACCOUNT: u64 = 384;

    /// Rough hot-state bytes for `n_accounts` live accounts (map + trie).
    pub fn estimate_accounts_bytes(n_accounts: u64) -> u64 {
        n_accounts.saturating_mul(EST_BYTES_PER_ACCOUNT)
    }

    /// Pure watermark check (testable): true at/above the threshold.
    pub fn accounts_over_watermark(n_accounts: u64) -> bool {
        n_accounts >= accounts_memory_warn_threshold()
    }

    // ---------- snapshot chunking ----------

    /// Accounts serialized per snapshot chunk (peak ≈ one chunk in RAM).
    pub const DEFAULT_SNAPSHOT_CHUNK_ACCOUNTS: usize = 50_000;

    /// Effective chunk size: `STELL_SNAPSHOT_CHUNK_ACCOUNTS`, default 50_000.
    pub fn snapshot_chunk_accounts() -> usize {
        env_usize(
            "STELL_SNAPSHOT_CHUNK_ACCOUNTS",
            DEFAULT_SNAPSHOT_CHUNK_ACCOUNTS,
        )
    }

    static ACCOUNTS_WARN_LAST_MS: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(0);

    impl super::InMemoryStateEngine {
        /// Live PQ-fallback occupancy (bounded LRU size, not the disk tree).
        pub fn pq_fallback_len(&self) -> usize {
            self.pq_keys_fallback.read().unwrap().len()
        }

        /// Lifetime PQ-fallback evictions (0 while under cap / disk-attached).
        pub fn pq_fallback_evictions(&self) -> u64 {
            self.pq_keys_fallback.read().unwrap().evictions()
        }

        /// Soft-watermark check over live account count: LOUD (throttled)
        /// warn past `STELL_MAX_ACCOUNTS_WARN`, never an eviction — consensus
        /// state cannot be dropped. Returns the live count.
        pub async fn check_accounts_watermark(&self) -> usize {
            let n = self.accounts.read().await.len();
            if (n as u64) >= accounts_memory_warn_threshold() {
                warn_throttled(
                    &ACCOUNTS_WARN_LAST_MS,
                    EVICT_WARN_INTERVAL_MS,
                    &format!(
                        "live accounts {n} at/above STELL_MAX_ACCOUNTS_WARN watermark \
                         (~{} bytes hot state by estimate) — unbounded growth, \
                         Phase-2 disk-backed store required; NOT evicting (consensus state)",
                        estimate_accounts_bytes(n as u64),
                    ),
                );
            }
            n
        }

        /// Serialize accounts in address-sorted chunks of `chunk_accounts`
        /// (default `STELL_SNAPSHOT_CHUNK_ACCOUNTS`): peak transient memory is
        /// ≈ one chunk, not full state + all domains at once. Each chunk is an
        /// independent length-delimited unit; restore with
        /// [`Self::restore_snapshot_chunked`]. NOT byte-compatible with the
        /// monolithic [`Self::create_snapshot`] (which is kept for readers).
        ///
        /// The FIRST chunk carries the D2 consensus penalty map (the
        /// [`StateSnapshotV2`] shape); the rest are bare account chunks. The
        /// penalty is consensus-critical (it enters the charged fee), so it
        /// must travel with the state (audit W6.6).
        pub async fn create_snapshot_chunked(
            &self,
            chunk_accounts: Option<usize>,
        ) -> Vec<Vec<u8>> {
            let per = chunk_accounts.unwrap_or(snapshot_chunk_accounts()).max(1);
            let map = self.accounts.read().await;
            let mut addrs: Vec<[u8; 32]> = map.keys().copied().collect();
            addrs.sort();
            let mut out = Vec::new();
            for (i, group) in addrs.chunks(per).enumerate() {
                let states: Vec<super::AccountState> = group
                    .iter()
                    .filter_map(|a| map.get(a).cloned())
                    .collect();
                if i == 0 {
                    // The first chunk also carries the penalty map.
                    let penalty = self.consensus_penalty.read().await.clone();
                    out.push(
                        bincode::serialize(&super::StateSnapshotV2 { accounts: states, penalty })
                            .unwrap_or_default(),
                    );
                } else {
                    out.push(bincode::serialize(&states).unwrap_or_default());
                }
            }
            out
        }

        /// Install chunks produced by [`Self::create_snapshot_chunked`].
        /// Same restore semantics as [`Self::restore_snapshot`] (generation
        /// bump, replay-set clear, accounts→tokens→trie lock order, token
        /// entries re-synced) but inserts chunk by chunk, so peak transient
        /// memory stays ≈ one chunk plus the live map itself.
        ///
        /// Validate-then-commit (audit F10): EVERY chunk is deserialized
        /// BEFORE live state is touched. The old code cleared the map, the
        /// trie AND the replay sets first, so a corrupt middle chunk returned
        /// `Err` with live state already wiped — a local state-corruption
        /// primitive on the very path meant to recover state. Now a poisoned
        /// chunk leaves accounts, trie and replay sets byte-identical.
        ///
        /// Like `restore_snapshot` this is the REORG path: all three committed
        /// replay sets are cleared and rebuilt from replayed blocks. A sync
        /// caller must use `restore_snapshot_chunked_preserve_replay_sets`
        /// with the coverage gate.
        pub async fn restore_snapshot_chunked(
            &self,
            chunks: &[Vec<u8>],
        ) -> Result<(), String> {
            // Phase 1 (validate): decode every chunk with no locks held and
            // no mutation. Any failure returns with live state untouched.
            let (decoded, penalty) = Self::decode_snapshot_chunks(chunks)?;
            // Phase 2 (commit): all chunks are known-good; install.
            self.bump_commitment_generation();
            self.cross_shard_consumed.write().await.clear();
            self.cross_shard_produced.write().await.clear();
            self.cross_shard_completed.write().await.clear();
            // The penalty travels with the state; install it BEFORE the
            // accounts lock (documented lock order: penalty -> accounts).
            *self.consensus_penalty.write().await = penalty;

            let mut map = self.accounts.write().await;
            let tokens = self.tokens.read().await;
            let mut trie = self.state_trie.write().await;
            map.clear();
            *trie = crate::cell::PatriciaTrie::new();

            for states in decoded {
                for acc in states {
                    let data = acc.to_trie_bytes();
                    trie.insert(&acc.address, &data);
                    map.insert(acc.address, acc);
                }
            }

            super::write_token_trie_entries(&mut trie, &tokens);
            Ok(())
        }

        /// Chunked twin of [`Self::restore_snapshot_preserve_replay_sets`]
        /// for future snapshot-sync callers (audit F1+F10): validate-then-
        /// commit like [`Self::restore_snapshot_chunked`], but the cross-
        /// shard replay sets are PRESERVED, not cleared — the caller installs
        /// the snapshot's replay blob afterwards via
        /// `restore_cross_shard_replay` (extend-only) behind the fail-closed
        /// coverage gate (`cross_shard_replay_covers`). Two methods, not a
        /// flag, for the same reason as the monolithic pair: a flag at this
        /// call site is how a future caller silently picks the reorg
        /// semantics on the sync path and re-opens the double mint.
        pub async fn restore_snapshot_chunked_preserve_replay_sets(
            &self,
            chunks: &[Vec<u8>],
        ) -> Result<(), String> {
            let (decoded, penalty) = Self::decode_snapshot_chunks(chunks)?;
            // Same generation bump as the reorg twin; NO replay-set clear.
            self.bump_commitment_generation();
            // The penalty travels with the state (see `create_snapshot`).
            *self.consensus_penalty.write().await = penalty;

            let mut map = self.accounts.write().await;
            let tokens = self.tokens.read().await;
            let mut trie = self.state_trie.write().await;
            map.clear();
            *trie = crate::cell::PatriciaTrie::new();

            for states in decoded {
                for acc in states {
                    let data = acc.to_trie_bytes();
                    trie.insert(&acc.address, &data);
                    map.insert(acc.address, acc);
                }
            }

            super::write_token_trie_entries(&mut trie, &tokens);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::post_quantum::{derive_pq_address, PqScheme, PqSignatureEnvelope};
    use crate::sharding::Transaction;

    #[tokio::test]
    async fn test_dormant_account_activation_and_spend_pinned_pubkey() {
        let engine = InMemoryStateEngine::new();
        let scheme = PqScheme::Falcon512;
        let pubkey = vec![0x42u8; scheme.pubkey_size()];
        let salt = [0x01u8; 16];
        let address = derive_pq_address(scheme, &pubkey, &salt);

        // Phase 1: Dormant account receives funds
        engine.credit_native(&address, 10_000_000).await.unwrap();

        let acc_dormant = engine.get_account(&address).await.unwrap();
        assert_eq!(acc_dormant.balance, 10_000_000);
        assert_eq!(acc_dormant.nonce, 0);
        assert_eq!(acc_dormant.pubkey_hash, None);
        assert_eq!(acc_dormant.to_trie_bytes().len(), crate::cpat2::ACCOUNT_LEAF_LEN_LEGACY);
        assert_eq!(engine.get_pinned_pubkey(&address), None);

        // Phase 2: First spend pins public key
        engine.pin_pubkey(address, scheme, &pubkey, &salt).await.unwrap();

        let acc_pinned = engine.get_account(&address).await.unwrap();
        assert_eq!(acc_pinned.balance, 10_000_000);
        assert_eq!(acc_pinned.scheme, scheme);
        let expected_hash = *blake3::hash(&pubkey).as_bytes();
        assert_eq!(acc_pinned.pubkey_hash, Some(expected_hash));
        assert_eq!(acc_pinned.to_trie_bytes().len(), crate::cpat2::ACCOUNT_LEAF_LEN_PQ);

        // Phase 3: Second spend retrieves pinned public key
        let retrieved = engine.get_pinned_pubkey(&address);
        assert!(retrieved.is_some());
        let (ret_scheme, ret_pk) = retrieved.unwrap();
        assert_eq!(ret_scheme, scheme);
        assert_eq!(ret_pk, pubkey);
    }

    #[tokio::test]
    async fn test_address_preimage_mismatch_rejection() {
        let engine = InMemoryStateEngine::new();
        let scheme = PqScheme::Falcon512;
        let pubkey = vec![0x33u8; scheme.pubkey_size()];
        let salt = [0x55u8; 16];
        let correct_address = derive_pq_address(scheme, &pubkey, &salt);

        // Tampered address
        let mut tampered_address = correct_address;
        tampered_address[0] ^= 0xff;
        let res_tampered_addr = engine.pin_pubkey(tampered_address, scheme, &pubkey, &salt).await;
        assert!(res_tampered_addr.is_err());
        assert!(res_tampered_addr.unwrap_err().contains("Address mismatch"));

        // Tampered salt
        let tampered_salt = [0xaa; 16];
        let res_tampered_salt = engine.pin_pubkey(correct_address, scheme, &pubkey, &tampered_salt).await;
        assert!(res_tampered_salt.is_err());
        assert!(res_tampered_salt.unwrap_err().contains("Address mismatch"));

        // Invalid pubkey length
        let bad_pk = vec![0x11u8; 64];
        let res_bad_len = engine.pin_pubkey(correct_address, scheme, &bad_pk, &salt).await;
        assert!(res_bad_len.is_err());
        assert!(res_bad_len.unwrap_err().contains("Invalid public key length"));
    }

    #[tokio::test]
    async fn test_persistence_across_simulated_reopen() {
        let dir = std::env::temp_dir().join(format!(
            "stell_pq_sim_reopen_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let scheme = PqScheme::Falcon512;
        let pubkey = vec![0x77u8; scheme.pubkey_size()];
        let salt = [0x88u8; 16];
        let address = derive_pq_address(scheme, &pubkey, &salt);

        let snap_bytes = {
            let engine1 = InMemoryStateEngine::new();
            engine1.open_pq_storage(&dir).unwrap();

            engine1.credit_native(&address, 50_000_000).await.unwrap();
            engine1.pin_pubkey(address, scheme, &pubkey, &salt).await.unwrap();

            assert_eq!(engine1.get_pinned_pubkey(&address), Some((scheme, pubkey.clone())));
            engine1.create_snapshot().await
        };

        // Engine 1 is dropped; simulate re-open with Engine 2 pointing to the same storage
        {
            let engine2 = InMemoryStateEngine::new();
            engine2.open_pq_storage(&dir).unwrap();
            engine2.restore_snapshot(&snap_bytes).await.unwrap();

            let retrieved = engine2.get_pinned_pubkey(&address);
            assert_eq!(retrieved, Some((scheme, pubkey.clone())));

            let acc = engine2.get_account(&address).await.unwrap();
            assert_eq!(acc.scheme, scheme);
            assert_eq!(acc.pubkey_hash, Some(*blake3::hash(&pubkey).as_bytes()));
            assert_eq!(acc.balance, 50_000_000);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_ml_dsa_44_and_hybrid_and_ed25519_pinning() {
        let engine = InMemoryStateEngine::new();

        // ML-DSA-44 DISABLED (forgeable verifier): pinning refuses fail-closed.
        let scheme_mldsa = PqScheme::MlDsa44;
        let pk_mldsa = vec![0xa1u8; scheme_mldsa.pubkey_size()];
        let salt_mldsa = [0x12u8; 16];
        let addr_mldsa = derive_pq_address(scheme_mldsa, &pk_mldsa, &salt_mldsa);
        engine.credit_native(&addr_mldsa, 1_000).await.unwrap();
        assert!(engine.pin_pubkey(addr_mldsa, scheme_mldsa, &pk_mldsa, &salt_mldsa).await.is_err());
        assert_eq!(engine.get_pinned_pubkey(&addr_mldsa), None);

        // Hybrid
        let scheme_hybrid = PqScheme::Hybrid;
        let pk_hybrid = vec![0xb2u8; scheme_hybrid.pubkey_size()];
        let salt_hybrid = [0x34u8; 16];
        let addr_hybrid = derive_pq_address(scheme_hybrid, &pk_hybrid, &salt_hybrid);
        engine.credit_native(&addr_hybrid, 2_000).await.unwrap();
        engine.pin_pubkey(addr_hybrid, scheme_hybrid, &pk_hybrid, &salt_hybrid).await.unwrap();
        assert_eq!(engine.get_pinned_pubkey(&addr_hybrid), Some((scheme_hybrid, pk_hybrid)));

        // Ed25519
        let scheme_ed = PqScheme::Ed25519;
        let pk_ed = vec![0xc3u8; scheme_ed.pubkey_size()];
        let salt_ed = [0x56u8; 16];
        let addr_ed = derive_pq_address(scheme_ed, &pk_ed, &salt_ed);
        engine.credit_native(&addr_ed, 3_000).await.unwrap();
        engine.pin_pubkey(addr_ed, scheme_ed, &pk_ed, &salt_ed).await.unwrap();
        assert_eq!(engine.get_pinned_pubkey(&addr_ed), Some((scheme_ed, pk_ed)));
    }

    #[tokio::test]
    async fn test_idempotent_pinning_and_conflicting_rejection() {
        let engine = InMemoryStateEngine::new();
        let scheme = PqScheme::Falcon512;
        let pubkey = vec![0x10u8; scheme.pubkey_size()];
        let salt = [0x20u8; 16];
        let address = derive_pq_address(scheme, &pubkey, &salt);

        engine.credit_native(&address, 10_000).await.unwrap();
        engine.pin_pubkey(address, scheme, &pubkey, &salt).await.unwrap();

        // Re-pinning identical key is idempotent and succeeds
        assert!(engine.pin_pubkey(address, scheme, &pubkey, &salt).await.is_ok());

        // Conflicting registration (different key matching same address would fail address derivation,
        // but if someone bypassed derivation or tried different scheme):
        let mut map = engine.accounts.write().await;
        let acc = map.get_mut(&address).unwrap();
        acc.pubkey_hash = Some([0x99; 32]);
        drop(map);

        let err = engine.pin_pubkey(address, scheme, &pubkey, &salt).await;
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("Conflicting public key"));
    }

    #[tokio::test]
    async fn test_pinned_pubkey_persists_across_stop_and_restart() {
        let dir = std::env::temp_dir().join(format!(
            "stell_pq_persist_restart_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let scheme = PqScheme::Falcon512;
        let pubkey = vec![0x4au8; scheme.pubkey_size()];
        let salt = [0x9bu8; 16];
        let address = derive_pq_address(scheme, &pubkey, &salt);

        // Initial session: open storage, attach tree, pin key, verify, and stop engine
        {
            let storage = crate::storage::Storage::open(&dir).unwrap();
            let engine = InMemoryStateEngine::new();
            engine.attach_pq_tree(storage.pq_keys.clone());

            engine.credit_native(&address, 100_000).await.unwrap();
            engine.pin_pubkey(address, scheme, &pubkey, &salt).await.unwrap();

            assert_eq!(engine.get_pinned_pubkey(&address), Some((scheme, pubkey.clone())));
            storage.flush().unwrap();
            // engine and storage dropped here ("engine stop")
        }

        // Restart session: fresh engine, re-opened storage, re-attached tree
        {
            let storage_restarted = crate::storage::Storage::open(&dir).unwrap();
            let engine_restarted = InMemoryStateEngine::new();
            engine_restarted.attach_pq_tree(storage_restarted.pq_keys.clone());

            // Pinned public key persists across engine stop and restart
            let retrieved = engine_restarted.get_pinned_pubkey(&address);
            assert_eq!(
                retrieved,
                Some((scheme, pubkey.clone())),
                "pinned public key must persist across engine stop and restart"
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_get_pinned_pubkey_returns_exact_registered_key_after_reattaching_storage() {
        let dir = std::env::temp_dir().join(format!(
            "stell_pq_exact_key_reattach_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let storage = crate::storage::Storage::open(&dir).unwrap();

        let scheme_falcon = PqScheme::Falcon512;
        let pk_falcon = vec![0x1au8; scheme_falcon.pubkey_size()];
        let salt_falcon = [0x2bu8; 16];
        let addr_falcon = derive_pq_address(scheme_falcon, &pk_falcon, &salt_falcon);

        let scheme_mldsa = PqScheme::MlDsa44;
        let pk_mldsa = vec![0x3cu8; scheme_mldsa.pubkey_size()];
        let salt_mldsa = [0x4du8; 16];
        let addr_mldsa = derive_pq_address(scheme_mldsa, &pk_mldsa, &salt_mldsa);

        let scheme_ed = PqScheme::Ed25519;
        let pk_ed = vec![0x5eu8; scheme_ed.pubkey_size()];
        let salt_ed = [0x6fu8; 16];
        let addr_ed = derive_pq_address(scheme_ed, &pk_ed, &salt_ed);

        // Register keys via first engine
        {
            let engine = InMemoryStateEngine::new();
            engine.attach_pq_tree(storage.pq_keys.clone());

            engine.pin_pubkey(addr_falcon, scheme_falcon, &pk_falcon, &salt_falcon).await.unwrap();
            // ML-DSA-44 DISABLED: pinning refuses; the key is never stored.
            assert!(engine.pin_pubkey(addr_mldsa, scheme_mldsa, &pk_mldsa, &salt_mldsa).await.is_err());
            engine.pin_pubkey(addr_ed, scheme_ed, &pk_ed, &salt_ed).await.unwrap();
            storage.flush().unwrap();
        }

        // Re-attach storage to a brand new engine
        let fresh_engine = InMemoryStateEngine::new();
        // Before re-attaching, unpinned/unattached keys return None
        assert_eq!(fresh_engine.get_pinned_pubkey(&addr_falcon), None);
        assert_eq!(fresh_engine.get_pinned_pubkey(&addr_mldsa), None);
        assert_eq!(fresh_engine.get_pinned_pubkey(&addr_ed), None);

        // Re-attach persistent storage tree
        fresh_engine.attach_pq_tree(storage.pq_keys.clone());

        // Verify get_pinned_pubkey returns the exact registered keys
        let got_falcon = fresh_engine.get_pinned_pubkey(&addr_falcon).expect("falcon key must be retrieved");
        assert_eq!(got_falcon, (scheme_falcon, pk_falcon));

        let got_mldsa = fresh_engine.get_pinned_pubkey(&addr_mldsa);
        assert_eq!(got_mldsa, None, "disabled ML-DSA-44 keys are never stored");

        let got_ed = fresh_engine.get_pinned_pubkey(&addr_ed).expect("ed25519 key must be retrieved");
        assert_eq!(got_ed, (scheme_ed, pk_ed));

        // Unregistered address returns None
        let unpinned_addr = [0xffu8; 32];
        assert_eq!(fresh_engine.get_pinned_pubkey(&unpinned_addr), None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_block_execution_pq_activation_pinning_and_disk_persistence() {
        let dir = std::env::temp_dir().join(format!(
            "stell_block_exec_pq_pin_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let engine = InMemoryStateEngine::new();
        engine.open_pq_storage(&dir).unwrap();

        let scheme = PqScheme::Falcon512;
        let seed = 0x5D;
        let pk = Transaction::sample_falcon512_pubkey(seed);
        let salt = crate::post_quantum::DEFAULT_SALT;
        let from = derive_pq_address(scheme, &pk, &salt);
        let recipient = [0x77u8; 32];

        let initial_balance = 10_000_000u64;
        engine.credit_native(&from, initial_balance).await.unwrap();

        // Verify account is legacy / unpinned before execution
        let acc_before = engine.get_account(&from).await.unwrap();
        assert_eq!(acc_before.pubkey_hash, None);
        assert_eq!(acc_before.to_trie_bytes().len(), crate::cpat2::ACCOUNT_LEAF_LEN_LEGACY);
        let leaf_before = engine.state_trie.read().await.get(&from).unwrap().to_vec();
        assert_eq!(leaf_before.len(), crate::cpat2::ACCOUNT_LEAF_LEN_LEGACY);
        assert_eq!(engine.get_pinned_pubkey(&from), None);

        // Build PQ activation transaction
        let amount = 50_000u64;
        let gas_limit = 60_000u64;
        let mut tx = Transaction {
            from,
            to: recipient,
            amount,
            gas_limit,
            nonce: 0,
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload: Vec::new(),
            priority_fee_per_gas: 0,
        };
        let msg = tx.signing_message();
        let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
        let envelope = PqSignatureEnvelope::new_explicit(scheme, pk.clone(), sig);
        tx.signature = envelope.encode();

        assert!(tx.is_pq_activation());

        // Execute block with the PQ activation transaction
        let (applied, failed, _fees, status, _tx_fees) =
            engine.apply_block_parallel_fees(&[tx], 1000).await;
        assert_eq!(applied, 1);
        assert_eq!(failed, 0);
        assert!(status[0]);

        // 1. Verify AccountState.pubkey_hash is set to Some
        let acc_after = engine.get_account(&from).await.unwrap();
        let expected_hash = *blake3::hash(&pk).as_bytes();
        assert_eq!(acc_after.pubkey_hash, Some(expected_hash));
        assert_eq!(acc_after.scheme, scheme);
        assert_eq!(acc_after.nonce, 1);

        // Verify activation surcharge gas fee deducted from sender's balance in commit_native
        let expected_balance = initial_balance - amount - gas_limit - PQ_ACTIVATION_SURCHARGE_GAS;
        assert_eq!(acc_after.balance, expected_balance);

        // 2. Verify account leaf becomes 49 bytes (ACCOUNT_LEAF_LEN_PQ)
        assert_eq!(acc_after.to_trie_bytes().len(), crate::cpat2::ACCOUNT_LEAF_LEN_PQ);
        assert_eq!(acc_after.to_trie_bytes().len(), 49);
        let leaf_after = engine.state_trie.read().await.get(&from).unwrap().to_vec();
        assert_eq!(leaf_after.len(), crate::cpat2::ACCOUNT_LEAF_LEN_PQ);
        assert_eq!(leaf_after.len(), 49);

        // 3. Verify public key is persisted to disk
        let in_engine_pk = engine.get_pinned_pubkey(&from);
        assert_eq!(in_engine_pk, Some((scheme, pk.clone())));

        // Drop engine so sled releases the lock on the directory
        drop(engine);

        let fresh_engine = InMemoryStateEngine::new();
        fresh_engine.open_pq_storage(&dir).unwrap();
        let persisted_pk = fresh_engine.get_pinned_pubkey(&from);
        assert_eq!(
            persisted_pk,
            Some((scheme, pk)),
            "Public key must be persisted to disk and retrieved by fresh engine"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_steady_state_implicit_transactions_follow_activation_and_lookup_pinned_key() {
        let dir = std::env::temp_dir().join(format!(
            "stell_steady_state_implicit_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let engine = InMemoryStateEngine::new();
        engine.open_pq_storage(&dir).unwrap();

        let scheme = PqScheme::Falcon512;
        let seed = 0x82;
        let pk = Transaction::sample_falcon512_pubkey(seed);
        let salt = crate::post_quantum::DEFAULT_SALT;
        let from = derive_pq_address(scheme, &pk, &salt);
        let recipient = [0x99u8; 32];

        engine.credit_native(&from, 20_000_000).await.unwrap();

        // 1. Block 1: Apply PQ activation transaction (nonce 0, explicit pubkey)
        let mut tx_act = Transaction {
            from,
            to: recipient,
            amount: 10_000,
            gas_limit: 50_000,
            nonce: 0,
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload: Vec::new(),
            priority_fee_per_gas: 0,
        };
        let msg_act = tx_act.signing_message();
        let sig_act = Transaction::create_falcon512_test_signature(&pk, &msg_act, seed);
        tx_act.signature = PqSignatureEnvelope::new_explicit(scheme, pk.clone(), sig_act).encode();
        assert!(tx_act.is_pq_activation());

        let (applied1, failed1, _, _, _) = engine.apply_block_parallel_fees(&[tx_act], 1000).await;
        assert_eq!(applied1, 1);
        assert_eq!(failed1, 0);

        // Verify pinned key exists
        let (pinned_scheme, pinned_pk) = engine
            .get_pinned_pubkey(&from)
            .expect("Pinned key must exist after activation");
        assert_eq!(pinned_scheme, scheme);
        assert_eq!(pinned_pk, pk);

        // 2. Block 2: Steady-state implicit transaction (nonce 1, 0-byte pubkey on wire)
        let mut tx_imp = Transaction {
            from,
            to: recipient,
            amount: 20_000,
            gas_limit: 30_000,
            nonce: 1,
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload: Vec::new(),
            priority_fee_per_gas: 0,
        };
        let msg_imp = tx_imp.signing_message();
        let sig_imp = Transaction::create_falcon512_test_signature(&pk, &msg_imp, seed);
        tx_imp.signature = PqSignatureEnvelope::new_implicit(scheme, sig_imp).encode();

        assert!(!tx_imp.is_pq_activation());
        assert!(tx_imp.is_pq_implicit());

        let (applied2, failed2, _, status2, _) =
            engine.apply_block_parallel_fees(&[tx_imp], 1001).await;
        assert_eq!(applied2, 1, "Steady-state implicit transaction must succeed");
        assert_eq!(failed2, 0);
        assert!(status2[0]);

        // Verify account state and trie leaf format
        let acc_after2 = engine.get_account(&from).await.unwrap();
        assert_eq!(acc_after2.nonce, 2);
        assert_eq!(acc_after2.pubkey_hash, Some(*blake3::hash(&pk).as_bytes()));
        assert_eq!(acc_after2.to_trie_bytes().len(), crate::cpat2::ACCOUNT_LEAF_LEN_PQ);
        assert_eq!(engine.state_trie.read().await.get(&from).unwrap().len(), 49);

        // 3. Steady-state across engine restart: fresh engine with attached storage
        drop(engine);
        let storage = crate::storage::Storage::open(&dir).unwrap();
        let restarted_engine = InMemoryStateEngine::new();
        restarted_engine.attach_pq_tree(storage.pq_keys.clone());
        restarted_engine.update_account(acc_after2).await;

        // Verify restarted engine looks up the pinned key
        let looked_up = restarted_engine.get_pinned_pubkey(&from);
        assert_eq!(looked_up, Some((scheme, pk.clone())));

        // Next implicit transaction on restarted engine
        let mut tx_imp2 = Transaction {
            from,
            to: recipient,
            amount: 5_000,
            gas_limit: 25_000,
            nonce: 2,
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload: Vec::new(),
            priority_fee_per_gas: 0,
        };
        let msg_imp2 = tx_imp2.signing_message();
        let sig_imp2 = Transaction::create_falcon512_test_signature(&pk, &msg_imp2, seed);
        tx_imp2.signature = PqSignatureEnvelope::new_implicit(scheme, sig_imp2).encode();

        let (applied3, failed3, _, _, _) =
            restarted_engine.apply_block_parallel_fees(&[tx_imp2], 1002).await;
        assert_eq!(
            applied3, 1,
            "Steady-state implicit transaction on restarted engine must succeed"
        );
        assert_eq!(failed3, 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_sec03_downtime_slash_with_falcon_uqc_and_bls() {
        use crate::consensus::{
            derive_sortition_committee, encode_pq_micro_envelope, encode_qc_bls_envelope,
            PqMicroCertificate, QuorumCertificate, VoteKind, BLS_QC_MARKER_ID, PQ_UQC_MARKER_ID,
        };
        use crate::staking::{DOWNTIME_MISS_THRESHOLD, MIN_VALIDATOR_BOND, STELL_MIN_BOND_BUFFER};

        let engine = InMemoryStateEngine::new();
        let honest_id = [0x11; 32];
        let offline_id = [0x22; 32];
        let bond_amount = MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER;

        // Fund and bond two validators
        engine.credit_native(&honest_id, bond_amount * 2).await.unwrap();
        engine.credit_native(&offline_id, bond_amount * 2).await.unwrap();
        engine.credit_native(&crate::staking::STAKING_POOL, bond_amount * 10).await.unwrap();

        engine.staking_write().await.bond(honest_id, bond_amount, 0).unwrap();
        engine.staking_write().await.bond(offline_id, bond_amount, 0).unwrap();

        let vs = engine.staking_read().await.to_validator_set();
        assert_eq!(vs.len(), 2);

        // 1. Simulate Falcon µQC where only honest_id signs
        let committee = derive_sortition_committee(&vs, 1, 0, 2, &[0u8; 32]);
        let mut uqc = PqMicroCertificate::new(
            crate::post_quantum::PqScheme::Falcon512,
            1,
            0,
            2,
            vec![0u8; 1],
            vec![vec![1; 40]],
            [0u8; 32],
        );
        for (i, id) in committee.iter().enumerate() {
            if *id == honest_id {
                uqc.set_signer(i, true);
            }
        }
        let falcon_qc = QuorumCertificate {
            height: 1,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: Some([0xAA; 32]),
            signatures: vec![(PQ_UQC_MARKER_ID, encode_pq_micro_envelope(&uqc))],
        };

        // Apply downtime slash for heights 1..=threshold - 1
        for h in 1..DOWNTIME_MISS_THRESHOLD as u64 {
            let burned = engine.apply_downtime_slash(h, Some(&falcon_qc)).await;
            assert_eq!(burned, 0);
            let ledger = engine.staking_read().await;
            assert_eq!(ledger.validators[&honest_id].missed, 0, "honest signer must NOT accumulate missed blocks");
            assert_eq!(ledger.validators[&offline_id].missed, h as u32, "offline non-signer MUST accumulate missed blocks");
        }

        // At threshold, offline validator gets slashed
        let burned = engine.apply_downtime_slash(DOWNTIME_MISS_THRESHOLD as u64, Some(&falcon_qc)).await;
        assert!(burned > 0, "offline validator must be slashed at threshold");
        {
            let ledger = engine.staking_read().await;
            assert_eq!(ledger.validators[&honest_id].missed, 0);
            assert_eq!(ledger.validators[&honest_id].total_slashed, 0, "honest validator must NEVER be slashed");
            assert!(ledger.validators[&offline_id].total_slashed > 0, "offline validator must be slashed");
        }

        // 2. Now simulate BLS aggregate where offline_id comes back online and signs
        let mut ids: Vec<crate::consensus::ValidatorId> = vs.validators.keys().copied().collect();
        ids.sort_unstable();
        let mut bitvec = crate::bls::SignerBitVector::new(ids.len());
        for (i, id) in ids.iter().enumerate() {
            if *id == offline_id {
                bitvec.set(i, true);
            }
        }
        let dummy_sig = crate::bls::BlsSecretKey::generate().sign(b"msg");
        let dummy_agg = crate::bls::BlsAggregateSignature {
            signature: dummy_sig,
            participants: bitvec,
        };
        let bls_payload = encode_qc_bls_envelope(&dummy_agg, 20, 0, VoteKind::Precommit, Some([0xBB; 32]));
        let bls_qc = QuorumCertificate {
            height: 20,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: Some([0xBB; 32]),
            signatures: vec![(BLS_QC_MARKER_ID, bls_payload)],
        };

        engine.apply_downtime_slash(20, Some(&bls_qc)).await;
        let ledger = engine.staking_read().await;
        assert_eq!(ledger.validators[&offline_id].missed, 0, "signing in BLS aggregate forgives missed streak");
    }

    #[tokio::test]
    async fn test_sec07_free_failure_dos_charges_fee_and_increments_nonce() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        use crate::svm::OpCode;
        use crate::sharding::{Block, MASTERCHAIN_SHARD};

        let engine = InMemoryStateEngine::new();
        let alice = SigningKey::generate(&mut OsRng);
        let alice_addr = alice.verifying_key().to_bytes();
        let recipient = [0x55u8; 32];
        let proposer = SigningKey::generate(&mut OsRng);
        let proposer_addr = proposer.verifying_key().to_bytes();

        let initial_balance = 1_000_000u64;
        engine.credit_native(&alice_addr, initial_balance).await.unwrap();

        // 1. Transaction that fails execution (e.g. out of gas)
        // Admitted because sender covers amount (0) + gas_limit (50_000).
        // Fails at execution because 100 gas cannot run a 280k basic transfer opcode.
        let gas_limit = 50_000u64;
        let fail_tx = Transaction::sign_with_payload(
            &alice,
            recipient,
            0,
            gas_limit,
            0,
            1,
            1,
            vec![OpCode::Transfer { recipient: [0xCC; 32], amount: 1 }],
        );

        let transactions = vec![fail_tx.clone()];
        let order_merkle_root = crate::mev::compute_order_merkle_root(&transactions);
        let mut block = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: 1,
            prev_hash: [0u8; 32],
            state_root: [0u8; 32],
            transactions,
            cross_shard_out: vec![],
            timestamp: 1000,
            proposer: proposer_addr,
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            order_merkle_root,
        };
        block.sign_block(&proposer);

        let outcome = engine.apply_block_transition(&block, 0).await;

        // Verify:
        // 1. Status is "failed" (outcome.status[0] == false)
        assert_eq!(outcome.applied, 0);
        assert_eq!(outcome.failed, 1);
        assert_eq!(outcome.status, vec![false], "receipt records status failed");
        // 2. fee_charged equals the fee (gas_limit)
        assert_eq!(outcome.tx_fees, vec![gas_limit], "receipt records actual fee_charged");
        assert_eq!(outcome.fees_collected, gas_limit);

        // 3. Sender balance debited and nonce incremented
        let sender = engine.get_account(&alice_addr).await.unwrap();
        assert_eq!(sender.balance, initial_balance - gas_limit, "fee debited from sender");
        assert_eq!(sender.nonce, 1, "sender nonce incremented");

        // 4. Conservation of value: proposer receives fees, total supply unchanged
        let proposer_acc = engine.get_account(&proposer_addr).await.unwrap();
        assert_eq!(proposer_acc.balance, gas_limit, "proposer credited with failure fee");
        assert_eq!(sender.balance + proposer_acc.balance, initial_balance, "funds conserved");

        // 5. Test sender whose balance drops below fee during execution:
        // Tx1 spends balance, Tx2 was admitted but now cannot cover the full fee.
        // Balance saturates to 0, nonce increments, and actual fee_charged equals debited amount.
        let alice_drain = SigningKey::generate(&mut OsRng);
        let alice_drain_addr = alice_drain.verifying_key().to_bytes();
        let bob_addr = [0xB0; 32];
        engine.credit_native(&alice_drain_addr, 1_200_000).await.unwrap();

        let tx_drain = Transaction::sign_with_payload(
            &alice_drain,
            recipient,
            0,
            500_000,
            0,
            1,
            1,
            vec![OpCode::Transfer { recipient: bob_addr, amount: 600_000 }],
        );
        // Tx2 is admitted against simulated remainder (1.2M - 500k = 700k >= 200k),
        // but at execution time Tx1 left only 100k balance.
        let tx_broke = Transaction::sign_with_payload(
            &alice_drain,
            recipient,
            0,
            200_000,
            1,
            1,
            1,
            vec![OpCode::Transfer { recipient: [0xCC; 32], amount: 1 }],
        );

        let transactions = vec![tx_drain, tx_broke];
        let order_merkle_root = crate::mev::compute_order_merkle_root(&transactions);
        let mut block2 = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: 2,
            prev_hash: [0u8; 32],
            state_root: [0u8; 32],
            transactions,
            cross_shard_out: vec![],
            timestamp: 1001,
            proposer: proposer_addr,
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            order_merkle_root,
        };
        block2.sign_block(&proposer);

        let outcome2 = engine.apply_block_transition(&block2, 0).await;
        assert_eq!(outcome2.applied, 1);
        assert_eq!(outcome2.failed, 1);
        assert_eq!(outcome2.status, vec![true, false]);
        // Tx2 fails with only 100k left against its declared 200k fee: a
        // failure whose FEE the sender cannot cover moves NOTHING at all (no
        // dust burn, no nonce burn) - the grief rule. A failure the sender CAN
        // pay for is charged its declared fee and consumes the nonce (see
        // `broke_sender_failure_changes_nothing` and the block path).
        assert_eq!(
            outcome2.tx_fees,
            vec![500_000, 0],
            "an uncoverable failure fee moves nothing"
        );
        assert_eq!(outcome2.fees_collected, 500_000);

        let sender_drain = engine.get_account(&alice_drain_addr).await.unwrap();
        assert_eq!(
            sender_drain.balance,
            1_200_000 - 600_000 - 500_000,
            "the dust is not drained by an uncoverable failure"
        );
        assert_eq!(sender_drain.nonce, 1, "no pay, no advance: nonce untouched");

        let bob = engine.get_account(&bob_addr).await.unwrap();
        assert_eq!(bob.balance, 600_000);

        let proposer_acc2 = engine.get_account(&proposer_addr).await.unwrap();
        assert_eq!(proposer_acc2.balance, gas_limit + 500_000);

        // Value conservation: the drain sender's 1.2M is the sender's
        // remainder + bob's 600k + the fee the proposer collected for THIS
        // block. (The proposer's total also holds the first block's fee,
        // which came out of a different sender - so it is not part of this
        // balance.)
        assert_eq!(
            sender_drain.balance + bob.balance + 500_000,
            1_200_000,
            "funds conserved: every debit arrived somewhere"
        );
    }

    #[tokio::test]
    async fn test_block_execution_collects_contract_events() {
        let engine = InMemoryStateEngine::new();
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let from = sk.verifying_key().to_bytes();
        engine.update_account(AccountState::new(from, 10_000_000)).await;

        let code = wat::parse_str(
            r#"(module
                 (import "host" "emit" (func $emit (param i64 i64)))
                 (func (export "emit_val") (param $val i64) (result i64)
                   (call $emit (i64.const 999) (local.get $val))
                   (local.get $val)))"#,
        )
        .unwrap();

        let contract_addr = engine.deploy_contract(from, code, 100).await.unwrap();

        let tx = Transaction::sign_with_payload(
            &sk,
            contract_addr,
            0,
            500_000,
            0,
            1,
            1,
            vec![crate::svm::OpCode::SysCallCallContract {
                contract: contract_addr,
                method: b"emit_val".to_vec(),
                arg: 12345,
            }],
        );

        let proposer = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let transactions = vec![tx];
        let order_merkle_root = crate::mev::compute_order_merkle_root(&transactions);
        let mut block = crate::sharding::Block {
            shard_id: crate::sharding::MASTERCHAIN_SHARD,
            height: 1,
            prev_hash: [0u8; 32],
            state_root: [0u8; 32],
            transactions,
            cross_shard_out: vec![],
            timestamp: 1000,
            proposer: proposer.verifying_key().to_bytes(),
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            order_merkle_root,
        };
        block.sign_block(&proposer);

        let outcome = engine.apply_block_transition(&block, 0).await;
        assert_eq!(outcome.applied, 1);
        assert_eq!(outcome.status, vec![true]);
        assert_eq!(outcome.events.len(), 1);
        assert_eq!(outcome.events[0].len(), 1);
        assert_eq!(outcome.events[0][0].contract, contract_addr);
        assert_eq!(outcome.events[0][0].topic, 999);
        assert_eq!(outcome.events[0][0].value, 12345);
    }

    /// W5.3 (concurrent waves): the same wave, applied 20 times, must
    /// reproduce the SAME state root bit for bit.
    ///
    /// The fixture is 16 DISJOINT plain transfers, so the scheduler puts all
    /// of them into a single wave and the wave is executed CONCURRENTLY
    /// (planned on the rayon pool, merged conflict-free). If the concurrent
    /// path were order-dependent, one of these 20 runs would drift.
    #[tokio::test]
    async fn test_parallel_wave_execution_is_deterministic() {
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        // At least `PARALLEL_WAVE_MIN_TX` senders, so the wave really takes
        // the CONCURRENT path.
        const SENDERS: usize = 48;

        let mut rng = StdRng::seed_from_u64(0x5EED_5EED_5EED_5EED);
        let keys: Vec<ed25519_dalek::SigningKey> = (0..SENDERS)
            .map(|_| ed25519_dalek::SigningKey::generate(&mut rng))
            .collect();
        let recipients: Vec<[u8; 32]> = (0..SENDERS)
            .map(|_| ed25519_dalek::SigningKey::generate(&mut rng).verifying_key().to_bytes())
            .collect();

        let txs: Vec<Transaction> = keys
            .iter()
            .zip(recipients.iter())
            .enumerate()
            .map(|(i, (k, to))| Transaction::sign(k, *to, 100 + i as u64, 10, 0, 1, 1))
            .collect();

        // The fixture must really be ONE wave, otherwise the concurrent path
        // would not be exercised at all.
        let waves = crate::parallel_exec::DisjointScheduler::schedule(&txs);
        assert_eq!(waves.len(), 1, "the fixture must schedule into one wave");
        assert_eq!(waves[0].len(), txs.len());

        let mut roots: Vec<crate::cell::CellHash> = Vec::new();
        for run in 0..20u32 {
            let engine = InMemoryStateEngine::new().with_parallel_exec(true);
            for k in &keys {
                let addr = k.verifying_key().to_bytes();
                engine.update_account(AccountState::new(addr, 1_000_000)).await;
            }
            let res = engine.apply_block_parallel_fees(&txs, 1_700_000_000).await;
            assert_eq!(res.0, txs.len(), "run {run}: every transfer must apply");
            assert_eq!(res.1, 0, "run {run}: no transfer may fail");
            roots.push(engine.get_state_root().await);
        }
        for (run, root) in roots.iter().enumerate() {
            assert_eq!(
                *root, roots[0],
                "run {run} produced a different state root: the wave is not deterministic"
            );
        }
    }

    /// W5.3 (concurrent waves): the INTRA-WAVE ORDER does not change the
    /// final state.
    ///
    /// The same set of disjoint transfers is applied in 20 different block
    /// orders (each order is a different wave composition), and every order
    /// must produce the identical state root: the wave's final state is the
    /// merge of disjoint per-transaction plans, so it cannot depend on the
    /// order the plans were computed or applied in.
    #[tokio::test]
    async fn test_parallel_wave_order_independence() {
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        // At least `PARALLEL_WAVE_MIN_TX` senders, so the wave really takes
        // the CONCURRENT path.
        const SENDERS: usize = 40;

        let mut rng = StdRng::seed_from_u64(0xBEEF_BEEF_BEEF_BEEF);
        let keys: Vec<ed25519_dalek::SigningKey> = (0..SENDERS)
            .map(|_| ed25519_dalek::SigningKey::generate(&mut rng))
            .collect();
        let recipients: Vec<[u8; 32]> = (0..SENDERS)
            .map(|_| ed25519_dalek::SigningKey::generate(&mut rng).verifying_key().to_bytes())
            .collect();

        let base: Vec<Transaction> = keys
            .iter()
            .zip(recipients.iter())
            .enumerate()
            .map(|(i, (k, to))| Transaction::sign(k, *to, 7 + i as u64, 10, 0, 1, 1))
            .collect();

        let mut roots: Vec<crate::cell::CellHash> = Vec::new();
        for perm in 0..20usize {
            let mut txs = base.clone();
            let n = txs.len();
            txs.rotate_left(perm % n);
            if perm % 2 == 1 {
                txs.reverse();
            }

            let engine = InMemoryStateEngine::new().with_parallel_exec(true);
            for k in &keys {
                let addr = k.verifying_key().to_bytes();
                engine.update_account(AccountState::new(addr, 1_000_000)).await;
            }
            let res = engine.apply_block_parallel_fees(&txs, 1_700_000_000).await;
            assert_eq!(res.0, txs.len(), "perm {perm}: every transfer must apply");
            assert_eq!(res.1, 0, "perm {perm}: no transfer may fail");
            roots.push(engine.get_state_root().await);
        }
        for (perm, root) in roots.iter().enumerate() {
            assert_eq!(
                *root, roots[0],
                "order {perm} produced a different state root: the wave depends on the intra-wave order"
            );
        }
    }

    /// W5.3: the concurrent wave path and the sequential path must agree
    /// BIT for bit - same statuses, same fees, same state root.
    #[tokio::test]
    async fn test_concurrent_wave_matches_sequential_path() {
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let mut rng = StdRng::seed_from_u64(0x0BAD_C0DE_0BAD_C0DE);
        // At least `PARALLEL_WAVE_MIN_TX` senders per wave, so the waves
        // really take the CONCURRENT path.
        let keys: Vec<ed25519_dalek::SigningKey> = (0..40)
            .map(|_| ed25519_dalek::SigningKey::generate(&mut rng))
            .collect();
        let recipients: Vec<[u8; 32]> = (0..40)
            .map(|_| ed25519_dalek::SigningKey::generate(&mut rng).verifying_key().to_bytes())
            .collect();

        // Two rounds per sender: the second round conflicts with the first
        // (same sender), so the block schedules into several waves.
        let mut txs: Vec<Transaction> = Vec::new();
        for nonce in 0..2u64 {
            for (i, k) in keys.iter().enumerate() {
                txs.push(Transaction::sign(
                    k,
                    recipients[i],
                    50 + nonce * 10 + i as u64,
                    10,
                    nonce,
                    1,
                    1,
                ));
            }
        }
        // A transaction that cannot pay: it must fail on BOTH paths, with
        // the same F-01 failure fee.
        let broke = ed25519_dalek::SigningKey::generate(&mut rng);
        txs.push(Transaction::sign(&broke, recipients[0], 1, 10, 0, 1, 1));

        let seq = InMemoryStateEngine::new().with_parallel_exec(false);
        let par = InMemoryStateEngine::new().with_parallel_exec(true);
        for engine in [&seq, &par] {
            for k in &keys {
                let addr = k.verifying_key().to_bytes();
                engine.update_account(AccountState::new(addr, 1_000_000)).await;
            }
        }

        let res_seq = seq.apply_block_parallel_fees(&txs, 1_700_000_000).await;
        let res_par = par.apply_block_parallel_fees(&txs, 1_700_000_000).await;

        assert_eq!(res_seq.0, res_par.0, "applied count");
        assert_eq!(res_seq.1, res_par.1, "failed count");
        assert_eq!(res_seq.2, res_par.2, "fees collected");
        assert_eq!(res_seq.3, res_par.3, "status vector");
        assert_eq!(res_seq.4, res_par.4, "fee vector");
        assert_eq!(seq.get_state_root().await, par.get_state_root().await);
    }

    /// W5.3: the finer wave granularity must not change the OUTCOME.
    ///
    /// Two transactions on DIFFERENT tokens now share a wave (the token
    /// registry is keyed by token id, so the two transfers touch disjoint
    /// state). The block must still produce exactly the sequential result:
    /// same statuses, same fees, same token balances, same state root.
    #[tokio::test]
    async fn test_distinct_tokens_share_a_wave_and_match_sequential() {
        use crate::token::{TokenMetadata, TokenOp, ZERO_ADDRESS};
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        fn meta(name: &str, symbol: &str) -> TokenMetadata {
            TokenMetadata {
                name: name.to_string(),
                symbol: symbol.to_string(),
                decimals: 6,
                total_supply: 0,
                max_supply: None,
                minter: ZERO_ADDRESS,
                paused: false,
                description: String::new(),
            }
        }

        let mut rng = StdRng::seed_from_u64(0xC0FFEE_C0FFEE_0001);
        let minter = ed25519_dalek::SigningKey::generate(&mut rng);
        let user_a = ed25519_dalek::SigningKey::generate(&mut rng);
        let user_b = ed25519_dalek::SigningKey::generate(&mut rng);
        let (minter_addr, a_addr, b_addr) = (
            minter.verifying_key().to_bytes(),
            user_a.verifying_key().to_bytes(),
            user_b.verifying_key().to_bytes(),
        );
        let recipient_a = ed25519_dalek::SigningKey::generate(&mut rng).verifying_key().to_bytes();
        let recipient_b = ed25519_dalek::SigningKey::generate(&mut rng).verifying_key().to_bytes();

        let seq = InMemoryStateEngine::new().with_parallel_exec(false);
        let par = InMemoryStateEngine::new().with_parallel_exec(true);
        for engine in [&seq, &par] {
            for addr in [minter_addr, a_addr, b_addr] {
                engine.update_account(AccountState::new(addr, 10_000_000)).await;
            }
        }

        // Two DISTINCT tokens.
        let token_1 = seq
            .create_token(minter_addr, meta("Alpha", "ALPHA"), 1_000_000)
            .await
            .unwrap();
        let token_2 = seq
            .create_token(minter_addr, meta("Beta", "BETA"), 1_000_000)
            .await
            .unwrap();
        let _ = par
            .create_token(minter_addr, meta("Alpha", "ALPHA"), 1_000_000)
            .await
            .unwrap();
        let _ = par
            .create_token(minter_addr, meta("Beta", "BETA"), 1_000_000)
            .await
            .unwrap();
        for engine in [&seq, &par] {
            engine
                .token_execute(&token_1, minter_addr, TokenOp::Transfer { to: a_addr, amount: 20_000 })
                .await
                .unwrap();
            engine
                .token_execute(&token_2, minter_addr, TokenOp::Transfer { to: b_addr, amount: 30_000 })
                .await
                .unwrap();
        }

        // One transfer per token: with the per-resource keys these two
        // transactions are DISJOINT and land in the SAME wave.
        let txs = vec![
            Transaction::sign_with_payload(
                &user_a,
                recipient_a,
                0,
                500_000,
                0,
                1,
                1,
                vec![crate::svm::OpCode::SysCallTokenTransfer {
                    token_id: token_1,
                    to: recipient_a,
                    amount: 5_000,
                }],
            ),
            Transaction::sign_with_payload(
                &user_b,
                recipient_b,
                0,
                500_000,
                0,
                1,
                1,
                vec![crate::svm::OpCode::SysCallTokenTransfer {
                    token_id: token_2,
                    to: recipient_b,
                    amount: 4_000,
                }],
            ),
        ];

        let waves = crate::parallel_exec::DisjointScheduler::schedule(&txs);
        assert_eq!(waves.len(), 1, "two different tokens must share one wave");
        assert_eq!(waves[0], vec![0, 1]);

        let res_seq = seq.apply_block_parallel_fees(&txs, 1_700_000_000).await;
        let res_par = par.apply_block_parallel_fees(&txs, 1_700_000_000).await;
        assert_eq!(res_seq.0, 2);
        assert_eq!(res_par.0, 2);
        assert_eq!(res_seq.1, 0);
        assert_eq!(res_par.1, 0);
        assert_eq!(res_seq.3, res_par.3);
        assert_eq!(res_seq.4, res_par.4);
        assert_eq!(seq.get_state_root().await, par.get_state_root().await);

        assert_eq!(seq.token_balance(&token_1, &a_addr).await, 15_000);
        assert_eq!(par.token_balance(&token_1, &a_addr).await, 15_000);
        assert_eq!(seq.token_balance(&token_2, &b_addr).await, 26_000);
        assert_eq!(par.token_balance(&token_2, &b_addr).await, 26_000);
        assert_eq!(par.token_balance(&token_1, &recipient_a).await, 5_000);
        assert_eq!(par.token_balance(&token_2, &recipient_b).await, 4_000);
    }

    // ==================================================================
    // W6.6: the F-01 failure fee contract
    // ==================================================================

    /// THE failure-fee contract, pinned (audit W6.6, item 1):
    /// * an ATTRIBUTABLE failure the sender can pay for: the fee they
    ///   declared is charged and their nonce is consumed - the attempt is not
    ///   free (the "free failure" DoS);
    /// * an attributable failure the sender CANNOT pay for: NOTHING moves -
    ///   no fee, no nonce, no dust burn. A transaction whose fee they cannot
    ///   cover was never going to run, and charging their remaining balance
    ///   for it would be a griefing surface, not a safety property;
    /// * a REPLAY or a GAP: nothing moves (not attributable);
    /// * and the SINGLE-TX path and the BLOCK path agree on all of it.
    #[tokio::test]
    async fn failure_fee_contract_is_identical_on_both_paths() {
        use ed25519_dalek::SigningKey;

        const FLOOR: u64 = 100_000;
        let sk = SigningKey::from_bytes(&[0x21; 32]);
        let from = sk.verifying_key().to_bytes();

        // 1. An AFFORDABLE failure: the fee is charged, the nonce advances.
        {
            let engine = InMemoryStateEngine::new();
            engine.update_account(AccountState::new(from, 1_000_000)).await;
            // A payload that reverts (the token does not exist).
            let tx = Transaction::sign_with_payload(
                &sk,
                [0x44; 32],
                0,
                200_000,
                0,
                1,
                1,
                vec![crate::svm::OpCode::SysCallTokenTransfer {
                    token_id: [0xAB; 32],
                    to: [0x44; 32],
                    amount: 1,
                }],
            );
            let (_, failed, _, status, fees) =
                engine.apply_block_parallel_fees(&[tx], 1_700_000_000).await;
            assert_eq!((failed, status), (1, vec![false]));
            assert_eq!(fees, vec![200_000], "the declared fee is charged");
            let acc = engine.get_account(&from).await.unwrap();
            assert_eq!(acc.balance, 1_000_000 - 200_000);
            assert_eq!(acc.nonce, 1, "the failure consumes the nonce");
        }

        // 2. An UNCOVERABLE failure: nothing moves at all (no dust burn).
        {
            let engine = InMemoryStateEngine::new();
            // Only 1_000 left against a 200_000 declared fee.
            engine.update_account(AccountState::new(from, 1_000)).await;
            let tx = Transaction::sign_with_payload(
                &sk,
                [0x44; 32],
                0,
                200_000,
                0,
                1,
                1,
                vec![crate::svm::OpCode::SysCallTokenTransfer {
                    token_id: [0xAB; 32],
                    to: [0x44; 32],
                    amount: 1,
                }],
            );
            let (_, failed, _, status, fees) =
                engine.apply_block_parallel_fees(&[tx], 1_700_000_000).await;
            assert_eq!((failed, status), (1, vec![false]));
            assert_eq!(fees, vec![0], "an uncoverable failure pays nothing");
            let acc = engine.get_account(&from).await.unwrap();
            assert_eq!(acc.balance, 1_000, "the dust is NOT burned");
            assert_eq!(acc.nonce, 0, "no pay, no advance");
        }

        // 3. A REPLAY (a stale nonce) moves nothing.
        {
            let engine = InMemoryStateEngine::new();
            engine.update_account(AccountState::new(from, 1_000_000)).await;
            let tx = Transaction::sign_with_payload(
                &sk,
                [0x44; 32],
                0,
                200_000,
                0,
                1,
                1,
                vec![crate::svm::OpCode::SysCallTokenTransfer {
                    token_id: [0xAB; 32],
                    to: [0x44; 32],
                    amount: 1,
                }],
            );
            // Advance the nonce out of band, then replay the old transaction.
            engine
                .update_account(AccountState {
                    address: from,
                    balance: 1_000_000,
                    nonce: 7,
                    ..AccountState::new(from, 0)
                })
                .await;
            let (_, failed, _, status, fees) =
                engine.apply_block_parallel_fees(&[tx], 1_700_000_000).await;
            assert_eq!((failed, status), (1, vec![false]));
            assert_eq!(fees, vec![0], "a replay pays nothing");
            let acc = engine.get_account(&from).await.unwrap();
            assert_eq!(acc.balance, 1_000_000, "a replay moves nothing");
            assert_eq!(acc.nonce, 7, "a replay does not advance the nonce");
        }

        // 4. The SINGLE-TX path and the BLOCK path agree on a failing
        //    transaction (the equivalence the project pins in
        //    tests/live_block_path_tests.rs).
        {
            let payload = vec![crate::svm::OpCode::SysCallTokenTransfer {
                token_id: [0xAB; 32],
                to: [0x44; 32],
                amount: 1,
            }];
            let tx = Transaction::sign_with_payload(
                &sk,
                [0x44; 32],
                0,
                200_000,
                0,
                1,
                1,
                payload,
            );
            let single = InMemoryStateEngine::new();
            let block = InMemoryStateEngine::new();
            single.update_account(AccountState::new(from, 1_000_000)).await;
            block.update_account(AccountState::new(from, 1_000_000)).await;

            assert!(
                single.apply_transaction(&tx, 1_700_000_000).await.is_err(),
                "the single-tx path must refuse it too"
            );
            let _ = block.apply_block_parallel_fees(&[tx], 1_700_000_000).await;

            let a = single.get_account(&from).await.unwrap();
            let b = block.get_account(&from).await.unwrap();
            assert_eq!(
                (a.balance, a.nonce),
                (b.balance, b.nonce),
                "both paths must leave the same sender state"
            );
            assert_eq!(
                single.get_state_root().await,
                block.get_state_root().await,
                "both paths must commit identical state"
            );
        }
        let _ = FLOOR;
    }

    // ==================================================================
    // W6.6: the D2 consensus penalty must travel with the state
    // ==================================================================

    /// The D2 penalty enters the CONSENSUS fee floor, so it is
    /// consensus-critical state: it MUST be part of the snapshot. A node that
    /// restored only the accounts would hold an EMPTY penalty map while a node
    /// that applied the blocks holds the real one - and the two would then
    /// charge DIFFERENT fees for the same transaction, i.e. end up with
    /// DIFFERENT state roots (a consensus split triggered by nothing more
    /// exotic than a restart or a snapshot sync).
    #[tokio::test]
    async fn snapshot_carries_the_d2_penalty_so_a_restored_node_agrees() {
        use ed25519_dalek::SigningKey;

        let engine = InMemoryStateEngine::new();
        let alice = SigningKey::from_bytes(&[5u8; 32]);
        let alice_addr = alice.verifying_key().to_bytes();
        engine
            .update_account(AccountState::new(alice_addr, 10_000_000))
            .await;

        // A transaction that fails at execution records the failure (the D2
        // mirror), which is what raises the sender's floor.
        let fail = Transaction::sign_with_payload(
            &alice,
            [0x77; 32],
            0,
            50_000,
            0,
            1,
            1,
            vec![crate::svm::OpCode::Transfer {
                recipient: [0xCC; 32],
                amount: 1,
            }],
        );
        let (_, failed, _, status, fees) =
            engine.apply_block_parallel_fees(&[fail.clone()], 1_700_000_000).await;
        assert_eq!(failed, 1, "the transaction must fail");
        assert_eq!(status, vec![false]);
        assert_eq!(fees, vec![50_000], "a failure still pays its fee");

        // The floor of the penalized sender is now the penalty.
        let (floor_before, _) = engine.consensus_floor_parts(&fail).await;
        assert!(
            floor_before >= crate::mempool::FAILED_SENDER_PENALTY,
            "the failure must have raised the consensus floor (floor={floor_before})"
        );

        // Snapshot, restore into a fresh engine: the penalty MUST come with it.
        let snap = engine.create_snapshot().await;
        let restored = InMemoryStateEngine::new();
        restored.restore_snapshot(&snap).await.expect("restore");
        let (floor_after, _) = restored.consensus_floor_parts(&fail).await;
        assert_eq!(
            floor_after, floor_before,
            "a restored node must charge the SAME floor as a node that applied the blocks"
        );

        // ...and therefore the SAME fee for the same transaction.
        let restored_alice = restored.get_account(&alice_addr).await.unwrap();
        let live_alice = engine.get_account(&alice_addr).await.unwrap();
        assert_eq!(restored_alice.balance, live_alice.balance);
        assert_eq!(restored_alice.nonce, live_alice.nonce);
        assert_eq!(
            restored.get_state_root().await,
            engine.get_state_root().await,
            "a restored node must have the same state root"
        );

        // The chunked snapshot carries it too.
        let chunks = engine.create_snapshot_chunked(Some(2)).await;
        let chunked = InMemoryStateEngine::new();
        chunked
            .restore_snapshot_chunked(&chunks)
            .await
            .expect("chunked restore");
        let (chunk_floor, _) = chunked.consensus_floor_parts(&fail).await;
        assert_eq!(
            chunk_floor, floor_before,
            "the chunked snapshot must carry the penalty as well"
        );
    }

    /// The LEGACY snapshot shape (a bare `Vec<AccountState>`, written before
    /// the penalty existed) must still decode - with an empty penalty.
    #[tokio::test]
    async fn legacy_account_snapshot_still_decodes() {
        use ed25519_dalek::SigningKey;
        let engine = InMemoryStateEngine::new();
        let alice = SigningKey::from_bytes(&[6u8; 32]);
        let addr = alice.verifying_key().to_bytes();
        engine
            .update_account(AccountState::new(addr, 1_000_000))
            .await;
        // The legacy shape: the bare account vector.
        let legacy = bincode::serialize(&vec![AccountState::new(addr, 1_000_000)]).unwrap();
        let restored = InMemoryStateEngine::new();
        restored
            .restore_snapshot(&legacy)
            .await
            .expect("a legacy snapshot must still restore");
        let acc = restored.get_account(&addr).await.expect("account restored");
        assert_eq!(acc.balance, 1_000_000);
    }

    // ==================================================================
    // W6.6: the OPTIMISTIC (CAS) parallel wave path vs the sequential path
    // ==================================================================

    /// A deterministic xorshift RNG, so a failing property run is
    /// reproducible.
    struct WaveRng(u64);
    impl WaveRng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    /// THE property (audit W6.6, item 7): the optimistic concurrent wave must
    /// leave EXACTLY the state the sequential path leaves - same balances,
    /// same nonces, same per-transaction verdicts, same fees, same state root.
    ///
    /// The concurrent path plans a wave from a SNAPSHOT and merges it under a
    /// compare-and-swap check; the sequential path applies the same
    /// transactions one at a time against the live map. Any difference in the
    /// two is a consensus split waiting to happen (the state root is what the
    /// validators agree on).
    ///
    /// The wave must be big enough to actually take the CONCURRENT path
    /// (`PARALLEL_WAVE_MIN_TX` = 32 transactions in one wave), which is why
    /// this test uses 40+ disjoint senders per round - the pre-existing
    /// equivalence tests only ever produced waves of 10, i.e. they never
    /// exercised the optimistic path at all.
    #[tokio::test]
    async fn parallel_wave_matches_sequential_for_randomized_blocks() {
        use ed25519_dalek::SigningKey;

        for round in 0..8u64 {
            let mut rng = WaveRng(0x9E37_79B9_7F4A_7C15 ^ round.wrapping_mul(0x1234_5678));
            // 40 senders -> one wave of 40 disjoint plain transfers, above the
            // concurrent threshold.
            let n_senders = 40usize + (rng.below(10) as usize);
            let senders: Vec<SigningKey> = (0..n_senders)
                .map(|_| SigningKey::from_bytes(&{
                    let mut b = [0u8; 32];
                    b[..8].copy_from_slice(&rng.next().to_le_bytes());
                    b
                }))
                .collect();
            let recipients: Vec<[u8; 32]> = (0..n_senders)
                .map(|_| {
                    let mut b = [0u8; 32];
                    b[..8].copy_from_slice(&rng.next().to_le_bytes());
                    b
                })
                .collect();

            let mut seq = InMemoryStateEngine::new();
            let mut par = InMemoryStateEngine::new();
            seq.set_parallel_exec(false);
            par.set_parallel_exec(true);

            const BAL: u64 = 10_000_000;
            for sk in &senders {
                let addr = sk.verifying_key().to_bytes();
                seq.update_account(AccountState::new(addr, BAL)).await;
                par.update_account(AccountState::new(addr, BAL)).await;
            }

            // Random plain transfers. Every sender sends ONE transaction in
            // this round, so all of them are mutually disjoint and land in a
            // single wave; a few of them are SELF transfers and a few are
            // deliberately unaffordable (they must fail identically on both
            // paths - and pay the same failure fee).
            let mut txs = Vec::with_capacity(n_senders);
            for i in 0..n_senders {
                let sk = &senders[i];
                let amount = 1 + rng.below(1_000);
                let to = match rng.below(10) {
                    0 => sk.verifying_key().to_bytes(),
                    _ => recipients[i],
                };
                let gas = 10 + rng.below(100);
                txs.push(Transaction::sign(sk, to, amount, gas, 0, 1, 1));
            }
            // One transaction that cannot be afforded: it must fail on both
            // paths, pay the SAME failure fee and consume the SAME nonce.
            let broke = Transaction::sign(&senders[0], recipients[0], u64::MAX / 2, 10, 1, 1, 1);
            txs.push(broke);

            // The concurrent path is only taken for a wave of at least
            // `PARALLEL_WAVE_MIN_TX` plain transactions - assert the shape
            // first, so this test can never silently degrade into "the
            // sequential fallback was compared with itself".
            let waves = crate::parallel_exec::DisjointScheduler::schedule(&txs);
            assert!(
                waves.iter().any(|w| w.len() >= 32),
                "the test must produce a wave big enough for the CONCURRENT path (waves: {:?})",
                waves.iter().map(|w| w.len()).collect::<Vec<_>>()
            );

            let res_seq = seq.apply_block_parallel_fees(&txs, 1_700_000_000).await;
            let res_par = par.apply_block_parallel_fees(&txs, 1_700_000_000).await;

            assert_eq!(res_seq.0, res_par.0, "applied count differs (round {round})");
            assert_eq!(res_seq.1, res_par.1, "failed count differs (round {round})");
            assert_eq!(
                res_seq.2, res_par.2,
                "fees collected differ (round {round})"
            );
            assert_eq!(
                res_seq.3, res_par.3,
                "per-transaction status differs (round {round})"
            );
            assert_eq!(
                res_seq.4, res_par.4,
                "per-transaction fee differs (round {round})"
            );

            // Every account must end in exactly the same state.
            for sk in &senders {
                let addr = sk.verifying_key().to_bytes();
                let a = seq.get_account(&addr).await;
                let b = par.get_account(&addr).await;
                assert_eq!(
                    a.as_ref().map(|x| (x.balance, x.nonce)),
                    b.as_ref().map(|x| (x.balance, x.nonce)),
                    "account {addr:02x?} differs (round {round})"
                );
            }
            for r in &recipients {
                let a = seq.get_account(r).await;
                let b = par.get_account(r).await;
                assert_eq!(
                    a.as_ref().map(|x| (x.balance, x.nonce)),
                    b.as_ref().map(|x| (x.balance, x.nonce)),
                    "recipient differs (round {round})"
                );
            }
            assert_eq!(
                seq.get_state_root().await,
                par.get_state_root().await,
                "the state root differs between the sequential and the parallel path (round {round})"
            );
        }
    }

    /// Two CONFLICTING transactions must never land in the same wave, and the
    /// scheduler must preserve their relative order (the sequential result
    /// depends on it).
    #[test]
    fn scheduler_never_places_conflicting_transactions_in_one_wave() {
        use ed25519_dalek::SigningKey;
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let me = sk.verifying_key().to_bytes();
        let him = other.verifying_key().to_bytes();

        let txs = vec![
            Transaction::sign(&sk, him, 10, 10, 0, 1, 1),
            Transaction::sign(&other, me, 10, 10, 0, 1, 1),
            Transaction::sign(&sk, him, 10, 10, 1, 1, 1),
            Transaction::sign(&other, me, 10, 10, 1, 1, 1),
        ];
        let waves = crate::parallel_exec::DisjointScheduler::schedule(&txs);
        for (i, wave) in waves.iter().enumerate() {
            for &a in wave {
                for &b in wave {
                    if a == b {
                        continue;
                    }
                    let ka = crate::parallel_exec::extract_access_keys(&txs[a]);
                    let kb = crate::parallel_exec::extract_access_keys(&txs[b]);
                    assert!(
                        ka.iter().all(|x| !kb.contains(x)),
                        "transactions {a} and {b} share a resource key but share wave {i}"
                    );
                }
            }
        }
        // The relative order of every conflicting pair must be preserved.
        let wave_of = |idx: usize| {
            waves
                .iter()
                .position(|w| w.contains(&idx))
                .expect("every tx is in a wave")
        };
        assert!(wave_of(0) < wave_of(2), "same-sender order must be kept");
        assert!(wave_of(1) < wave_of(3), "same-sender order must be kept");
        assert!(wave_of(0) < wave_of(1), "the shared recipient orders them");
    }
}
