//! Pipelined Execution & In-Memory State Engine
//! Actor Model: every account and smart contract operates as an isolated actor.
//! Actors communicate via asynchronous messages with bounce semantics (TON style).
//! Hot state maintained in RAM with cryptographic Patricia BoC Trie and background snapshots.

use crate::cell::{CellHash, PatriciaTrie};
pub use crate::contract::{ContractEventJson, GetMethodResponse, GET_METHOD_SAFETY_FUEL_LIMIT};
pub use crate::mempool::PQ_ACTIVATION_SURCHARGE_GAS;
use crate::token::TokenRegistry;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;

mod accounts;
mod apply;
mod contracts;
pub mod memory_bounds;
mod parallel;
mod settlement;
mod types;
mod verify_once;
mod xshard;

#[cfg(test)]
mod tests;

pub use types::{
    compute_contract_address, contract_abi_key, contract_key, contract_source_key,
    hashpool_commitment_key, hashpool_nullifier_key, token_balance_key, token_supply_key,
    ActorMessage, ActorSendBody, BlockTransitionOutcome, ContractCallOutcome, DeployOutcome,
    EscrowRecord, EvmBindingsSnapshot, EvmBindingsState, ExecPostActions, GovOpsOutcome,
    HashPoolApplyOutcome, HashPoolBlockOps, HashPoolDepositOp, HashPoolOpError, HashPoolSpendOp,
    StateSnapshotV2,
};
pub use verify_once::{
    record_verified_signature, verified_signature_covers, verify_once_clear,
    verify_once_reset_stats, verify_once_stats,
};

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

/// Bounded snapshot / sync blob limit (512 MiB, matching `storage::DOMAIN_SNAPSHOT_STRICT_MAX_BYTES`).
pub(super) const MAX_SNAPSHOT_DECODE_BYTES: u64 = 512 * 1024 * 1024;
/// Bounded per-record / actor-body limit (16 MiB) for individual records inside
/// sled or actor messages so a corrupt length prefix cannot drive an OOM.
pub(super) const MAX_SMALL_RECORD_DECODE_BYTES: u64 = 16 * 1024 * 1024;

/// Default-OFF gate for the HashPool apply wiring.
///
/// Plain documented const, no env knob (mirrors the
/// `PREFER_PQ_MEV_TRANSPORT = false` precedent): `false` in every build, so
/// the standard apply path cannot observe the pool. Tests flip the
/// per-instance override via
/// [`InMemoryStateEngine::enable_hashpool_for_tests`] (never on the live
/// path); production flips this const only with a spec update + audit.
pub const HASH_POOL_ENABLED: bool = false;

/// Activation height for block-carried governance ops
/// (`OpCode::SysCallGovPropose` / `OpCode::SysCallGovVote`, applied by
/// [`InMemoryStateEngine::apply_gov_ops`]).
///
/// Re-exported from [`crate::governance::GOV_OPS_ACTIVATION_HEIGHT`], the
/// single source of truth: `0` (active from genesis). The gate is a plain
/// compile-time constant — never an env knob (every node applying the same
/// blocks must reach the same verdict; an env knob would fork the chain).
/// Tests can force a closed gate per thread through
/// [`crate::governance::set_gov_ops_activation_override`]; the per-instance
/// [`InMemoryStateEngine::enable_gov_ops_for_tests`] opener is retained for
/// the existing block-path fixtures.
pub use crate::governance::GOV_OPS_ACTIVATION_HEIGHT;

/// Compiled default activation height for Ruleset v7 canonical
/// `Domain::EvmBindings` state commitment and first-writer-wins consensus
/// transition in `apply()`.
///
/// Ruleset v7 canonical `Domain::EvmBindings` activation height (`0` = active from genesis).
pub const EVM_BINDINGS_STATE_ACTIVATION_HEIGHT: u64 = 0;

#[cfg(any(test, debug_assertions))]
thread_local! {
    static EVM_BINDINGS_STATE_ACTIVATION_OVERRIDE: std::cell::Cell<Option<u64>> =
        const { std::cell::Cell::new(None) };
}

/// Set (or clear with `None`) the TEST-ONLY `EVM_BINDINGS_STATE` activation
/// height override for the calling thread.
#[cfg(any(test, debug_assertions))]
pub fn set_evm_bindings_state_activation_override(activation: Option<u64>) {
    EVM_BINDINGS_STATE_ACTIVATION_OVERRIDE.with(|c| c.set(activation));
}

/// Effective `EVM_BINDINGS_STATE` activation height for the calling thread.
pub fn effective_evm_bindings_state_activation_height() -> u64 {
    #[cfg(any(test, debug_assertions))]
    if let Some(h) = EVM_BINDINGS_STATE_ACTIVATION_OVERRIDE.with(|c| c.get()) {
        return h;
    }
    EVM_BINDINGS_STATE_ACTIVATION_HEIGHT
}

/// True iff canonical `Domain::EvmBindings` state is active at `height`.
///
/// Strictly returns `false` for EVERY height (including `u64::MAX`) when the
/// effective gate is `u64::MAX` (`GatedOff`).
pub fn evm_bindings_state_active_at(height: u64) -> bool {
    let gate = effective_evm_bindings_state_activation_height();
    gate != u64::MAX && height >= gate
}

/// Default scheme tag for an account that has not pinned a public key.
///
/// FULL-PQ: this used to be Ed25519. Classical schemes are removed, so an
/// unpinned account is tagged with the fail-closed ML-DSA-44 value (no
/// verifier). The tag is metadata only until `pin_pubkey` writes the real
/// scheme; tagging it with a live scheme (Falcon-512) would imply a key that
/// was never proven.
fn default_account_scheme() -> crate::post_quantum::PqScheme {
    crate::post_quantum::PqScheme::MlDsa44
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
            scheme: default_account_scheme(),
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

/// In-Memory Hot State Engine with Actor Model
#[allow(clippy::type_complexity)]
// GATE: engine holds many commitment domains; splitting types would fork snapshot layout.
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
    /// Serializes PMM buy/sell transitions. Cheap market ops take a read lock,
    /// run the curve on a CLONE, move value, then overwrite under a write lock;
    /// without this mutex two concurrent calls both pass the reserve check
    /// against the same clone and both pay out (a real, reproduced reserve-cap
    /// violation: 8 concurrent sells drained more wUSDT than the usable
    /// reserve). PMM ops are rare relative to block rate, so a single mutex
    /// costs nothing measurable and makes the transition atomic per engine.
    pmm_op: Arc<tokio::sync::Mutex<()>>,
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
    /// digest through `commitment::commitment_digest_with_zkml`, whose zkML
    /// domain writes ZERO bytes while the registry is empty. A chain that has
    /// never registered a model therefore keeps a byte-identical root, which
    /// is what lets this domain join the digest WITHOUT bumping
    /// `COMMITMENT_VERSION` or re-pinning the genesis KAT. No separate
    /// persistence tree this wave: the registry is consensus state in memory
    /// and under the root, and a restart drops it - both nodes drop the same
    /// state, so agreement is preserved but models must be re-registered.
    /// A disk tree is the follow-up.
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
    /// Cumulative nano-STELL ever created by the engine's mint primitive.
    ///
    /// THE GLOBAL SUPPLY INVARIANT. Every mint ([`Self::mint_native`], and
    /// therefore [`Self::credit_native`], which delegates to it) atomically
    /// RESERVES `amount` from this counter and fails closed when the total
    /// would exceed [`crate::tokenomics::TOTAL_SUPPLY_CAP`]. Local caps
    /// (`REWARDS_EMISSION_CAP`, `BRIDGE_MINT_CAP_NANO`, `GENESIS_VAULT_CAP`)
    /// each bound one subsystem; this one bounds their SUM.
    ///
    /// Monotone by construction: burns ([`Self::debit_native`], PMM sells,
    /// slashes) do NOT restore headroom, so "minted" is gross-lifetime and a
    /// chain cannot mint, burn, and mint again forever. Transfers never touch
    /// it ([`Self::transfer_native`] / [`Self::credit_native_transfer`]).
    ///
    /// `Arc<AtomicU64>` (not a plain `u64`) so a shallow `Clone` — which
    /// shares every subsystem `Arc` — shares the counter too, while
    /// [`Self::clone_for_simulation`] deep-copies its VALUE so a sandbox can
    /// never consume the live engine's headroom.
    ///
    /// NOT YET IN THE STATE ROOT: `commitment.rs` is outside this change's
    /// scope. The getter the commitment must fold in is
    /// [`Self::total_minted_nano`]; until that lands, two nodes that disagree
    /// about minted supply still agree on the root (see the wiring note on
    /// the getter).
    total_minted_nano: Arc<std::sync::atomic::AtomicU64>,
    /// CHAIN-WIDE mint limit for THIS shard, in nano-STELL.
    ///
    /// The engine's [`Self::total_minted_nano`] is a PER-ENGINE counter; with
    /// N shard engines it would allow `N x TOTAL_SUPPLY_CAP`. This limit is
    /// the shard's static share of the chain-wide cap (see
    /// [`crate::tokenomics::SupplyPartition`]), installed deterministically
    /// from the committed shard set by `ValidatorRuntime::with_shard`. Every
    /// mint reserves against `min(TOTAL_SUPPLY_CAP, this limit)`, so no
    /// interleaving of shard mints can push the SUM over the chain cap.
    ///
    /// It is deliberately NOT serialized into the state snapshot: it is a
    /// chain-configuration value, identical on every node that runs the shard,
    /// and restoring it from a local blob would let a stale snapshot widen it.
    /// Default [`crate::tokenomics::TOTAL_SUPPLY_CAP`] (the single-shard
    /// pre-sharding behaviour).
    chain_mint_limit_nano: Arc<std::sync::atomic::AtomicU64>,
    /// Per-domain content-generation counters (see
    /// [`crate::commitment::DomainGenerations`]).
    ///
    /// PRIVATE on purpose, like the subsystem locks: every mutation of a
    /// committed domain bumps its domain counter together with the global
    /// `commitment_generation` (via the `*_write` accessors, `dom_guard` or
    /// `bump_domain_generation`). The per-domain commitment cache
    /// ([`crate::commitment::DomainCache`]) keys each cached preimage by
    /// (domain, counter), so a domain is re-hashed only when its own inputs
    /// changed — never by wall clock.
    domain_gens: Arc<crate::commitment::DomainGenerations>,
    /// Per-domain commitment-preimage cache (see
    /// [`crate::commitment::DomainCache`]).
    ///
    /// Per-engine-instance state, NEVER process-wide: a deep copy of an
    /// engine (fork, simulation clone, snapshot-install target) starts with
    /// an EMPTY cache (see `clone_for_simulation`), so one fork's preimage
    /// bytes can never be served to another. Shallow `Clone`s share the
    /// subsystem `Arc`s and therefore the state, so sharing the cache there
    /// is sound.
    domain_cache: Arc<std::sync::Mutex<crate::commitment::DomainCache>>,
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
        std::sync::RwLock<Option<Arc<std::sync::RwLock<crate::sharding::FinalizedHeaderRegistry>>>>,
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
    pq_keys_fallback: Arc<
        std::sync::RwLock<
            memory_bounds::BoundedLruCache<
                [u8; 32],
                (crate::post_quantum::PqScheme, Vec<u8>, [u8; 16]),
            >,
        >,
    >,
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
    /// HashPool note/nullifier sub-state (default-OFF apply wiring).
    ///
    /// PRIVATE on purpose, like every other committed subsystem: reads go
    /// through the `hashpool_*` accessors below, mutations go through the
    /// gated `apply_hashpool_*` entry points (which refuse with
    /// [`HashPoolOpError::Disabled`] while the gate is off and mirror every
    /// mutation into the state trie under [`hashpool_commitment_key`] /
    /// [`hashpool_nullifier_key`], so pool ops move the state root
    /// deterministically). Bound to the engine's `chain_id` at
    /// [`InMemoryStateEngine::enable_hashpool_for_tests`].
    hashpool: Arc<RwLock<crate::hashpool::HashPool>>,
    /// Test-only per-instance override of [`HASH_POOL_ENABLED`].
    ///
    /// Default `false` (the const value): flipped ONLY by
    /// [`InMemoryStateEngine::enable_hashpool_for_tests`], which is never
    /// called on the live path (grep-proof: only `tests/` call it).
    hashpool_tests_on: Arc<std::sync::atomic::AtomicBool>,
    /// Test-only per-instance override of [`GOV_OPS_ACTIVATION_HEIGHT`].
    ///
    /// Default `false` (gate closed): flipped ONLY by
    /// [`InMemoryStateEngine::enable_gov_ops_for_tests`], which is never
    /// called on the live path (grep-proof: only `tests/` call it). Live
    /// activation flips the const, never this flag.
    gov_ops_tests_on: Arc<std::sync::atomic::AtomicBool>,
    /// CN-VRF v3 reverse hash-chain commitments and rolling mix state.
    ///
    /// PRIVATE on purpose: reads go through `cnvrf_v3_read`, mutations through
    /// `cnvrf_v3_write` (which bumps `Domain::CnVrf` and `commitment_generation`).
    cnvrf_v3: Arc<RwLock<crate::cn_vrf::CnVrfV3State>>,
    /// CN-VRF v3 non-vote-resettable reveal-abort leaky-bucket counters.
    ///
    /// PRIVATE on purpose: reads go through `cnvrf_abort_read`, mutations through
    /// `cnvrf_abort_write` (which bumps `Domain::CnVrf` and `commitment_generation`).
    cnvrf_abort: Arc<RwLock<crate::staking::CnVrfAbortState>>,
    /// Finalized epoch-boundary MinRoot VDF beacon outputs (`epoch -> [u8; 48]`).
    ///
    /// PRIVATE on purpose: reads go through `epoch_vdf_beacons_read`, mutations
    /// through `epoch_vdf_beacons_write` (which bumps `Domain::CnVrf` and
    /// `commitment_generation`).
    epoch_vdf_beacons: Arc<RwLock<std::collections::BTreeMap<u64, [u8; 48]>>>,
    /// Per-epoch `(freeze_block_hash, rolling_mix_at_freeze)` captured at
    /// `H_freeze = epoch * EPOCH_LEN - V3_COMMIT_LOOKAHEAD_BLOCKS`.
    cnvrf_freeze_inputs: Arc<RwLock<std::collections::BTreeMap<u64, ([u8; 32], [u8; 48])>>>,
    /// Canonical on-chain EVM ↔ PQ address bijection (`Domain::EvmBindings`).
    ///
    /// PRIVATE on purpose: reads go through `evm_bindings_read`, mutations
    /// through `evm_bindings_write` (which bumps `Domain::EvmBindings` and
    /// `commitment_generation`). CONDITIONAL in the commitment (0 bytes while
    /// empty, preserving `COMMITMENT_VERSION = 5` and genesis KATs).
    evm_bindings: Arc<RwLock<EvmBindingsState>>,
    /// Canonical on-chain PQ validator key registry (`Domain::PqRegistry`).
    ///
    /// PRIVATE on purpose: reads go through `pq_registry_read`, mutations
    /// through `pq_registry_write` (which bumps `Domain::PqRegistry` and
    /// `commitment_generation`). CONDITIONAL in the commitment (0 bytes while
    /// empty, preserving `COMMITMENT_VERSION = 5` and genesis KATs).
    pq_registry: Arc<RwLock<crate::pq_registry::PqRegistry>>,
    /// Deterministic set of settled EVM carrier intent digests whose
    /// `STELL_EVM_SETTLED_V1 || digest -> [1u8]` leaves live in `state_trie`.
    /// Persisted in its own storage tree (`"evm_settled_state"`) without
    /// changing `StateSnapshotV2` or `DomainSnapshot` bincode layouts.
    evm_settled: Arc<RwLock<std::collections::BTreeSet<[u8; 32]>>>,
    /// Test/debug per-engine activation height override for CN-VRF v3
    /// (initialized to `u64::MAX`, keeping frozen `CNVRF_V3_ACTIVATION_HEIGHT` untouched).
    #[cfg(any(test, debug_assertions))]
    cnvrf_v3_activation_override: Arc<std::sync::atomic::AtomicU64>,
}

mod serde_epoch_beacons {
    use serde::de::{MapAccess, SeqAccess, Visitor};
    use serde::ser::{SerializeMap, SerializeTuple};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::BTreeMap;

    struct Beacon48([u8; 48]);

    impl Serialize for Beacon48 {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            let mut tup = s.serialize_tuple(48)?;
            for b in &self.0 {
                tup.serialize_element(b)?;
            }
            tup.end()
        }
    }

    impl<'de> Deserialize<'de> for Beacon48 {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = Beacon48;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("a 48-byte beacon array")
                }
                fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                    let mut out = [0u8; 48];
                    for (i, slot) in out.iter_mut().enumerate() {
                        *slot = seq
                            .next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                    }
                    Ok(Beacon48(out))
                }
            }
            d.deserialize_tuple(48, V)
        }
    }

    pub fn serialize<S: Serializer>(
        val: &BTreeMap<u64, [u8; 48]>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(Some(val.len()))?;
        for (k, v) in val {
            map.serialize_entry(k, &Beacon48(*v))?;
        }
        map.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<BTreeMap<u64, [u8; 48]>, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = BTreeMap<u64, [u8; 48]>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a map of epoch -> 48-byte beacon")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut out = BTreeMap::new();
                while let Some((k, v)) = map.next_entry::<u64, Beacon48>()? {
                    out.insert(k, v.0);
                }
                Ok(out)
            }
        }
        d.deserialize_map(V)
    }
}

/// Snapshot of the engine's CN-VRF v3 subsystem (`v3_state`, `abort_state`, and
/// finalized `epoch_beacons`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CnVrfV3EngineSnapshot {
    pub v3_state: crate::cn_vrf::CnVrfV3State,
    pub abort_state: crate::staking::CnVrfAbortState,
    #[serde(with = "serde_epoch_beacons")]
    pub epoch_beacons: std::collections::BTreeMap<u64, [u8; 48]>,
}

impl CnVrfV3EngineSnapshot {
    /// Returns `true` when all three CN-VRF v3 sub-states are completely empty/default.
    pub fn is_empty(&self) -> bool {
        self.v3_state.records.is_empty()
            && self.v3_state.epoch_rolling_mixes.is_empty()
            && self.v3_state.rolling_mix == [0u8; crate::cn_vrf::V3_LINK_LEN]
            && self.v3_state.rolling_mix_epoch == 0
            && self.abort_state.counters.is_empty()
            && self.epoch_beacons.is_empty()
    }
}

impl std::fmt::Debug for InMemoryStateEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryStateEngine")
            .field("chain_id", &self.chain_id)
            .finish()
    }
}

impl Default for InMemoryStateEngine {
    fn default() -> Self {
        Self::new()
    }
}
