//! Consensus runtime: wires the BFT engine to block production, the mempool and
//! the state engine, and provides an in-process multi-validator Cluster.
//!
//! This is the integration layer between `consensus` (pure state machine) and
//! the rest of the node. The P2P transport that carries proposals/votes between
//! real nodes is layered on top of this (next stage).

use crate::consensus::{
    CommitteeSchedule, FalconKeypair, Height, HeightConsensus, Round, ValidatorId, ValidatorSet,
    VoteSet,
};
use crate::mempool::Mempool;
use crate::sharding::{
    Block, CrossShardKey, MasterStakingLedger, ShardId, ShardRegistry, Transaction,
};
use crate::state_engine::InMemoryStateEngine;
use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

// =============================================================================
// Masterchain validator-set activation stamps
// =============================================================================
//
// A workchain has no staking registry of its own (its ledger is empty by
// design), so it derives its consensus set from the MASTERCHAIN's registry,
// shared process-wide through [`ValidatorRuntime::master_staking`]. The set
// alone is not enough: the workchain must also know AT WHICH HEIGHT that set
// becomes in force, and its own height is the wrong answer — the masterchain
// height at which the rotation was adopted is unrelated to the workchain's tip,
// so two shards that observed the same rotation at different local heights
// staged it at different boundaries and then disagreed about the proposer
// ("wrong proposer" on every round, no height ever advanced to heal it).
//
// The stamp below is the deterministic datum: the MASTERCHAIN publishes
// `(fingerprint of the set it derived, its own W10.5 activation height for that
// set)` on its own set-install path (which runs on apply, adopt, walk, restore
// and repair). The activation height is the height the masterchain block that
// adopted the rotation was finalized at, plus one — a pure function of the
// masterchain chain, identical on every node that applied it. A workchain binds
// the set it derived to the stamp with the matching fingerprint and uses the
// stamped boundary verbatim (see [`workchain_set_activation_height`]).

/// Where the MASTERCHAIN's consensus set became in force — the deterministic
/// datum a workchain binds a rotation to.
///
/// * [`set_fingerprint`] identifies the elected set (validator -> power).
/// * `activation_height` is the masterchain's own W10.5 activation height for
///   that set (`master ledger height + 1`): the masterchain block that adopted
///   the rotation, plus one.
///
/// Every node derives the same `(fingerprint, activation)` from the same
/// masterchain block, so every workchain stages and installs the rotation at
/// the same boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MasterSetStamp {
    /// [`set_fingerprint`] of the set this stamp describes.
    pub(crate) set_fingerprint: [u8; 32],
    /// Masterchain height at/after which that set is in force, expressed as the
    /// W10.5 activation boundary (`master ledger height + 1`).
    pub(crate) activation_height: u64,
}

/// Deterministic fingerprint of a consensus validator set.
///
/// Domain-separated SHA-256 over the canonical `(validator id, voting power)`
/// pairs. `ValidatorSet::validators` is a `BTreeMap`, so the iteration order is
/// identical on every node: two nodes that derived the same set from the same
/// master ledger compute the same 32 bytes. Binding on CONTENT (not on a read
/// timestamp) is what lets a workchain prove WHICH master state defined its set:
/// a shared ledger that moved past the masterchain's last derivation produces a
/// different fingerprint, so the older stamp cannot be paired with it.
pub(crate) fn set_fingerprint(set: &ValidatorSet) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"STELL-MASTER-SET-STAMP-V1");
    h.update((set.validators.len() as u32).to_be_bytes());
    for (id, power) in &set.validators {
        h.update(id);
        h.update(power.to_be_bytes());
    }
    h.finalize().into()
}

/// The boundary a workchain uses for a set the masterchain derived at
/// `master_ledger_height`.
///
/// DETERMINISTIC RULE (the workchain half of W10.5): `activation = master
/// ledger height + 1` — the masterchain's own activation boundary, published in
/// [`MasterSetStamp`] and used VERBATIM in the workchain's height space. It is
/// a pure function of the masterchain block that adopted the rotation, so two
/// workchain nodes at different local heights stage the same rotation at the
/// same activation height. A workchain below that boundary keeps its previous
/// set until it reaches it (it never runs ahead of the master's set); one
/// already past it installs immediately (the set is already in force on the
/// masterchain, so waiting would be a needless fork) — the recorded activation
/// is identical either way.
///
/// Re-basing the boundary per node (for example by adding the local
/// `workchain_tip - master_tip` offset) would reintroduce exactly the
/// per-observer divergence this rule removes.
///
/// The shard-head commitment path carries workchain heads MASTERCHAIN ->
/// workchain; the reverse datum (the masterchain height a workchain block was
/// built against) is not in the block commitment, and adding it is a wire-format
/// change (frozen). Until that path exists, the masterchain's own activation
/// boundary is the deterministic datum, and a workchain that cannot obtain it
/// fail-closes to observer instead of guessing.
pub fn workchain_set_activation_height(master_ledger_height: u64) -> u64 {
    master_ledger_height.saturating_add(1)
}

/// Bound on the per-process stamp table. One entry per live master ledger
/// handle (a process runs one masterchain, plus one independent cluster per
/// test), so this is generous; the bound only keeps a long test run from
/// growing it without limit.
const MASTER_SET_STAMP_CAP: usize = 64;

fn master_set_stamps() -> &'static std::sync::Mutex<BTreeMap<usize, MasterSetStamp>> {
    static STAMPS: std::sync::OnceLock<std::sync::Mutex<BTreeMap<usize, MasterSetStamp>>> =
        std::sync::OnceLock::new();
    STAMPS.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
}

/// Identity of a shared master ledger handle. `Arc::as_ptr` is stable for the
/// lifetime of the handle, and every shard runtime of a process receives the
/// SAME `Arc` clone, so the masterchain and its workchains agree on the key
/// without extra plumbing.
fn master_handle_key(handle: &MasterStakingLedger) -> usize {
    Arc::as_ptr(handle) as *const () as usize
}

/// Publish the stamp of the set the MASTERCHAIN derived from this ledger.
///
/// Called from the masterchain's own set-install path with the set it derived
/// and that set's W10.5 activation height. The update is IDEMPOTENT PER SET:
/// publishing the SAME fingerprint again keeps the originally published
/// activation, so a long-lived unchanged set is never re-dated to a later
/// master height (that would make the workchain's boundary depend on when the
/// master happened to refresh). A DIFFERENT fingerprint always overwrites,
/// because that is a real rotation (or a rotation back) with a new boundary.
///
/// Returns the stamp now in force for `handle`.
pub(crate) fn publish_master_set_stamp(
    handle: &MasterStakingLedger,
    fingerprint: [u8; 32],
    activation_height: u64,
) -> MasterSetStamp {
    let key = master_handle_key(handle);
    let mut table = match master_set_stamps().lock() {
        Ok(t) => t,
        // A poisoned lock means another thread panicked while publishing.
        // Recover the data (stamps are `Copy` and never partially applied);
        // the reader only ever trusts a full fingerprint match.
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some(existing) = table.get(&key) {
        if existing.set_fingerprint == fingerprint {
            return *existing;
        }
    }
    while table.len() >= MASTER_SET_STAMP_CAP && !table.contains_key(&key) {
        let Some(oldest) = table.keys().next().copied() else {
            break;
        };
        table.remove(&oldest);
    }
    let stamp = MasterSetStamp {
        set_fingerprint: fingerprint,
        activation_height,
    };
    table.insert(key, stamp);
    stamp
}

/// The stamp the masterchain published for `handle`, if any.
///
/// `None` means "this process never saw the masterchain derive a set from this
/// ledger" — a workchain that would have to adopt a DIFFERENT set must then
/// fail closed (observer, no votes) rather than invent a boundary.
pub(crate) fn master_set_stamp(handle: &MasterStakingLedger) -> Option<MasterSetStamp> {
    let table = match master_set_stamps().lock() {
        Ok(t) => t,
        Err(poisoned) => poisoned.into_inner(),
    };
    table.get(&master_handle_key(handle)).copied()
}

mod anchors;
mod apply;
mod cluster;
mod consensus_step;
mod lanes;
mod mev_sync;

pub use cluster::{ChainState, Cluster, ShardedCluster};
pub use consensus_step::{ParkedCommit, ParkedProposal};
pub use lanes::{
    count_block_actor_sends, fund_genesis, fund_shard_genesis, missing_sender_accounts,
    shard_genesis_block, ApplyCompleted, PackFilterCtx, PrebuiltSelection, SnapBundle,
    VdfJobOutput, VdfLane,
};
use lanes::{ApplyInflight, ApplyLane};

#[cfg(test)]
mod tests;

/// Tests for the TON `shard_hashes` model: a masterchain block publishes the
/// latest finalized header of every workchain shard, and the commitment is
/// covered by the block hash (so the BFT quorum signs it).
#[cfg(test)]
#[path = "tests/shard_header_commitment_tests.rs"]
mod shard_header_commitment_tests;

pub type BlockHash = [u8; 32];

/// Hard cap on transactions per block (anti-DoS: a malicious proposer must not
/// be able to craft an unbounded block).
pub const MAX_BLOCK_TXS: usize = 10_000;
/// Upper bound on signers in a peer-supplied commit certificate. The validator
/// set is far smaller than this; anything larger is an attempt to make us run an
/// unbounded signature-verification loop.
pub const MAX_COMMIT_CERT_SIGNERS: usize = 4_096;

/// Maximum number of DECIDED-but-not-yet-installed blocks the execution
/// pipeline keeps queued when
/// [`crate::chain_spec::EXECUTION_PIPELINE_V1_ACTIVATION_HEIGHT`] is armed.
/// Below the gate the effective depth is 1 (a single in-flight apply), which is
/// exactly the historical single-slot behaviour.
///
/// The queue is drained strictly FIFO by [`ValidatorRuntime::try_poll_apply`] /
/// [`ValidatorRuntime::await_apply_completion`], so the committed state is
/// always the post-state of the last INSTALLED height while at most this many
/// decided heights sit ahead of it.
pub const MAX_APPLY_IN_FLIGHT_DEPTH: usize = 2;

/// Capacity of the bounded post-state history rings
/// ([`ValidatorRuntime::post_state_roots`] /
/// [`ValidatorRuntime::consensus_penalties_at`]). The newest entry always
/// survives; older entries are pruned oldest-first so a long-lived runtime
/// cannot accumulate unbounded history.
pub const POST_STATE_HISTORY_CAP: usize = 64;

/// Cap on the validator-set activation history ([`ValidatorRuntime::validator_set_history`]).
/// Only actual set changes are recorded, so this is barely touched in
/// practice (a bond/slash/eject every entry); the cap only bounds a pathological
/// flapping registry. 1024 entries cover ~3M heights of churn at worst.
pub const VALIDATOR_SET_HISTORY_CAP: usize = 1024;

/// Retention window for in-memory block bodies ([`ValidatorRuntime::blocks`]).
/// Entries at or above `committed_height.saturating_sub(RUNTIME_BLOCK_CACHE_WINDOW as u64)`
/// and any block still referenced by active pipeline/consensus state are never evicted.
pub const RUNTIME_BLOCK_CACHE_WINDOW: usize = 2048;

/// Retention window for in-memory finalized `(height, hash)` entries
/// ([`ValidatorRuntime::finalized`]). Keeps the newest entries in monotonic order
/// with the finalized tip always intact.
pub const RUNTIME_FINALIZED_CACHE_WINDOW: usize = 4096;

/// Gas cap per block (A11). Bounds block work independently of tx count.
///
/// Calibrated post fee-x500 (audit: blocks troubles): every tx declares at
/// least GAS_BASIC_TRANSFER (280k), so the old 30M fit ~107 plain transfers.
/// The cap was later raised 120M -> 500M (commit 27b1bfb, "500M block gas
/// cap"): 500M fits ~1785 plain transfers (or fewer heavy ones); serial apply
/// (~26k native tx/s in-process) clears a full 1785-block in ~35 ms, and
/// 1785 minimal txs are ~205 KB on the wire (fat shielded blocks stay far
/// under the 32MB proposal cap thanks to the per-tx IO caps). Raise only with
/// a fat-block sync measurement.
///
/// Docs that quote this cap: docs/PERF_1K.md, docs/RPC.md.
pub const MAX_BLOCK_GAS: u64 = 500_000_000;

/// Deterministic ceiling for a block timestamp ahead of its parent (seconds).
///
/// Bounds proposer clock skew WITHOUT any wall-clock read: the verdict is a
/// pure function of (parent, child), so two validators with different local
/// times derive the same answer from the same two blocks. Must stay equal to
/// [`crate::protocol::MAX_BLOCK_TIMESTAMP_DRIFT_MS`] / 1000 (ruleset v4 S8:
/// one hour is ~15,000 slots at the 240 ms tempo, the envelope this repo's
/// suites use for honest gaps and catch-up, while still refusing stamps that
/// would poison timestamp-driven rules for days).
pub const MAX_TIMESTAMP_JUMP_SECS: u64 = 3_600;

/// Near-future proposal phase-alignment window (rounds).
///
/// When a GENUINE proposal for this height arrives early for a near-future
/// round owned by the same proposer, we align to the earliest such round and
/// accept it there instead of rejecting it as "wrong proposer" (the vote that
/// would have synced us often arrives after the proposal it should precede).
/// Widened +4 -> +8 (audit MED 2026-10-14: the hash-slot schedule rejects
/// ~20% of genuine early proposals at +4; a wider scan strictly widens local
/// acceptance, never consensus — the body is signature-authenticated before
/// the scan, only the slot owner can pull us to their own slots, and the jump
/// still runs through `sync_round_to`'s caps/budget). Pinned by test below.
pub const PROPOSAL_ALIGN_WINDOW_ROUNDS: u32 = 8;

/// Why a sealed transaction was dropped by the proposer.
///
/// Every reason is a FAIL-CLOSED drop: the transaction never enters a
/// block, it is evicted from the pool, and its sender is charged the
/// failure bond (the same penalty an execution failure costs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropReason {
    /// Not enough decryption partials arrived before the deadline (the
    /// timeout path: a member withheld its share).
    NotEnoughShares,
    /// The ciphertext did not authenticate (tampered, or sealed to
    /// another committee).
    Undecryptable,
    /// The unsealed payload is not a transaction.
    NotATransaction,
    /// The unsealed transaction does not hash to the envelope's hash.
    HashMismatch,
    /// The unsealed transaction contradicts the envelope's transparent
    /// metadata.
    MetaMismatch,
    /// The unsealed transaction carries an invalid signature.
    BadSignature,
}

/// How often the proposer polls for the peers' decryption partials while it
/// waits (bounded) for the share release.
///
/// The wait itself is bounded by `STELL_MEV_UNSEAL_WAIT_MS` (see
/// `ConsensusRuntime::seal_partial_wait_ms`): a member that withholds its
/// share must be able to DELAY the round, never to stall it.
pub const SEAL_PARTIAL_POLL_MS: u64 = 25;

/// How often the DKG contribution is re-published while the epoch key is
/// still missing.
///
/// The key generation is a gossip round: a peer that missed the first
/// publication (a restart, a dropped frame) would never receive the
/// contribution, and the epoch would have no key at all. Re-publishing on
/// an interval makes the round self-healing.
pub const DKG_REPUBLISH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// Bond amount for a genesis validator: bare MIN (v1 genesis bytes —
/// `bond_genesis` reproduces the pinned root `61336779...` exactly).
/// The runtime MIN+buffer floor applies to NEW stakes, not to founding.
pub const GENESIS_VALIDATOR_BOND: u64 = crate::staking::MIN_VALIDATOR_BOND;

/// Retained precommit votes for the already-decided parent height (`H-1`),
/// enabling late-arriving valid precommits from slower validators to enrich
/// `Block.last_qc` during `apply_in_flight` or after advancing to `H`.
#[derive(Clone, Debug)]
pub struct DecidedParentVotes {
    pub height: Height,
    pub round: Round,
    pub block_hash: BlockHash,
    pub shard_id: ShardId,
    pub validators: ValidatorSet,
    pub parent_hash: Option<[u8; 32]>,
    pub schedule: CommitteeSchedule,
    pub votes: VoteSet,
    pub decision_block_hash: BlockHash,
}

/// Node-local projection of the committed accounts as they will be once every
/// decided-but-not-yet-installed block has executed.
///
/// The sequenced worker is the only writer of committed state and it reports
/// back strictly FIFO, so at any instant `self.state` holds the post-state of
/// the last INSTALLED block while up to [`MAX_APPLY_IN_FLIGHT_DEPTH`] decided
/// blocks may still be queued ahead of it. A proposer that needs "the state my
/// next block will build on" can read this projection instead of waiting for
/// the queue to drain: it starts from the applied accounts and folds each
/// queued block's worst-case effects in submission order.
///
/// Everything here is a PURE projection of data already on this node (applied
/// accounts + decided block bytes). It is never hashed into a root and never
/// feeds block validity. Below `EXECUTION_PIPELINE_V1` the queue is empty
/// whenever this view is consulted, so the view is empty and every reader sees
/// exactly the committed state (the historical behaviour).
#[derive(Clone, Debug, Default)]
pub struct PendingExecView {
    /// address -> (predicted next nonce, predicted balance) after every
    /// decided-but-uninstalled transaction.
    accounts: BTreeMap<[u8; 32], (u64, u64)>,
    /// Hashes of transactions riding decided-but-uninstalled blocks.
    in_flight_txs: BTreeSet<[u8; 32]>,
}

impl PendingExecView {
    /// Drop every prediction (the committed state is authoritative again).
    pub fn clear(&mut self) {
        self.accounts.clear();
        self.in_flight_txs.clear();
    }

    /// Seed one committed account into the projection if not already tracked.
    pub fn seed_account(&mut self, addr: [u8; 32], nonce: u64, balance: u64) {
        self.accounts.entry(addr).or_insert((nonce, balance));
    }

    /// Fold one DECIDED block into the projection, in execution order.
    ///
    /// A transaction is marked in-flight unconditionally. Its nonce/balance
    /// effect is applied only to accounts already seeded from committed state
    /// (`seed_account` / `rebuild`) — unknown accounts are never fabricated
    /// with a zero balance — and its nonce advances only when it carries the
    /// sender's PREDICTED nonce AND the fee payer(s) cover the worst-case
    /// cost. For sponsored transactions, `tx.amount` is debited from `tx.from`
    /// and the fee leg is debited from `auth.sponsor`. Saturating throughout:
    /// the projection never underflows.
    ///
    /// `_height` is the decided height (kept for call-site symmetry and future
    /// per-height bookkeeping); ordering comes from the caller's FIFO.
    pub fn note_decided(&mut self, _height: u64, block: &Block) {
        for tx in &block.transactions {
            self.in_flight_txs.insert(tx.compute_tx_hash());
            if let Some(auth) = tx.sponsored_grant() {
                if let Some((user_cost, sponsor_cost)) = Mempool::sponsored_pure_legs(tx) {
                    let Some(&(u_nonce, u_bal)) = self.accounts.get(&tx.from) else {
                        continue;
                    };
                    if tx.nonce != u_nonce {
                        continue;
                    }
                    let user_ok = u_bal >= user_cost;
                    let sponsor_ok = self
                        .accounts
                        .get(&auth.sponsor)
                        .is_some_and(|&(_, s_bal)| s_bal >= sponsor_cost);
                    if let Some(u_entry) = self.accounts.get_mut(&tx.from) {
                        if user_ok && sponsor_ok {
                            u_entry.0 = u_entry.0.saturating_add(1);
                        }
                        u_entry.1 = u_entry.1.saturating_sub(user_cost);
                    }
                    if let Some(s_entry) = self.accounts.get_mut(&auth.sponsor) {
                        s_entry.1 = s_entry.1.saturating_sub(sponsor_cost);
                    }
                }
            } else {
                let cost = Mempool::tx_cost(tx);
                if let Some(entry) = self.accounts.get_mut(&tx.from) {
                    if tx.nonce == entry.0 {
                        if entry.1 >= cost {
                            entry.0 = entry.0.saturating_add(1);
                        }
                        entry.1 = entry.1.saturating_sub(cost);
                    }
                }
            }
        }
    }

    /// Rebuild from the APPLIED accounts plus the blocks still queued, oldest
    /// first. The applied map is the committed source of truth; the queued
    /// blocks are then folded over it in FIFO order.
    pub fn rebuild(
        &mut self,
        applied_accounts: &BTreeMap<[u8; 32], (u64, u64)>,
        blocks_in_flight: &[Block],
    ) {
        self.clear();
        for (addr, (nonce, balance)) in applied_accounts {
            self.accounts.insert(*addr, (*nonce, *balance));
        }
        for block in blocks_in_flight {
            self.note_decided(block.height, block);
        }
    }

    /// Predicted next nonce for `addr`, or `None` when the account is unknown
    /// to the projection.
    pub fn predicted_nonce(&self, addr: &[u8; 32]) -> Option<u64> {
        self.accounts.get(addr).map(|(nonce, _)| *nonce)
    }

    /// Predicted balance for `addr`, or `None` when the account is unknown to
    /// the projection.
    pub fn predicted_balance(&self, addr: &[u8; 32]) -> Option<u64> {
        self.accounts.get(addr).map(|(_, balance)| *balance)
    }

    /// True while `tx_hash` rides a decided-but-uninstalled block.
    pub fn is_in_flight(&self, tx_hash: &[u8; 32]) -> bool {
        self.in_flight_txs.contains(tx_hash)
    }
}

pub struct ValidatorRuntime {
    pub key: SigningKey,
    /// Optional out-of-process signer (HSM / KMS / remote service). When present it
    /// signs votes and proposals INSTEAD of `key`; there is no fallback, so a signer
    /// that is present but failing produces no vote at all rather than a locally
    /// signed one. See `src/remote_signer.rs` rule 1.
    pub remote_signer: Option<Arc<dyn crate::remote_signer::Signer>>,
    pub id: ValidatorId,
    pub validators: ValidatorSet,
    pub hc: HeightConsensus,
    pub state: Arc<InMemoryStateEngine>,
    pub mempool: Arc<tokio::sync::RwLock<Mempool>>,
    /// The transaction-gossip handle used to publish the epoch-seal frames
    /// (the DKG contribution, the order commitment and the share release).
    ///
    /// `None` when the node runs without a gossip transport (tests, the
    /// simulator): the epoch-seal protocol then runs node-locally and the
    /// plain path is unaffected.
    pub tx_gossip: Option<Arc<crate::consensus_net::TxGossip>>,
    /// Node-local MEV committee KEM registry (ML-KEM-768 encapsulation keys by
    /// validator id). `None` is the fail-closed default: node-side epoch DKG
    /// is refused, exactly as before this wiring existed.
    ///
    /// Supplied either directly via [`ValidatorRuntime::with_mev_kem`] or by
    /// bootstrap on the shared mempool (see
    /// [`crate::mempool::MevKemWiring`]).
    pub mev_kem_registry: Option<Arc<crate::mev_kem_registry::MevKemRegistry>>,
    /// THIS node's 64-byte ML-KEM-768 seed (`d || z`), derived by bootstrap
    /// from the node's persisted secret under the
    /// `STELL_MEV_KEM_SEED_V1` BLAKE3 derive-key domain.
    ///
    /// Wrapped in `Zeroizing` so the bytes are wiped on drop; the runtime has
    /// no `Clone` impl and its `Debug` prints only `[REDACTED]`, so the seed
    /// cannot be copied into a plain array or leaked into a log line.
    pub mev_kem_seed: Option<zeroize::Zeroizing<[u8; 64]>>,
    pub blocks: HashMap<BlockHash, Block>,
    /// VALUES our locked peers are stuck on (learned from nil-vote lock
    /// hints), keyed by the round-free [`crate::sharding::Block::value_id`]
    /// (ruleset v6) so a re-stamped body resolves to the same demand.
    /// Scoped to `demanded_height` (a finalize moves on, old demands die with
    /// it); capped so hint spam cannot grow memory. Served one-shot per hint
    /// batch: re-proposing re-validates, and a still-stuck peer re-hints.
    demanded: HashSet<[u8; 32]>,
    demanded_height: Height,
    /// Best-known peer head `(height, hash)` from structurally-valid proposals:
    /// a proposal at height H proves its author finalized H-1 (hash = prev_hash),
    /// REGARDLESS of whether we accept it (wrong height/round rejections carry
    /// true information too). Updated after authentication, before slot checks,
    /// so a lagging node learns where the network is even from proposals it
    /// must refuse. try_catch_up prefers it over the flaky DHT read.
    pub peer_hint: Option<(Height, BlockHash)>,
    /// The last peer round this node FOLLOWED (the height and the round of
    /// the vote that moved it).
    ///
    /// The same vote must never move the round TWICE: the round cap
    /// (`ROUND_LOOKBACK`) applies per jump, so a vote that is followed by
    /// the vote path AND by the drain would move the node twice as far as
    /// the cap allows. Remembering the last followed round makes the second
    /// follow a no-op.
    last_followed_round: Option<(Height, Round)>,
    pub finalized: Vec<(Height, BlockHash)>,
    pub applied_txs: u64,
    /// Per-transaction success flags from the last applied block, kept for
    /// receipts. Must not be recomputed by re-applying the block.
    pub applied_statuses: Vec<bool>,
    /// Per-transaction fee actually charged by the last applied block, in the
    /// same order as `applied_statuses` (0 for failed transactions). Filed
    /// into receipts alongside the flags.
    pub applied_fees: Vec<u64>,
    /// Per-transaction emitted contract events from the last applied block.
    pub applied_events: Vec<Vec<crate::contract::ContractEvent>>,
    /// Optional staking ledger. When present, equivocation evidence is slashed
    /// on finalization and voting power is derived from bonded stake.
    /// Shared on-chain staking ledger. This is an ALIAS of the ledger inside the
    /// state engine, not a second copy: consensus derives the validator set from
    /// it, so two copies could disagree about who the validators are.
    pub staking: Arc<tokio::sync::RwLock<crate::staking::StakingLedger>>,
    /// The MASTERCHAIN's staking ledger, shared process-wide between the
    /// masterchain runtime and every workchain runtime of the same process.
    ///
    /// The masterchain OWNS the staking registry: a bond, an unbond and a
    /// slash are masterchain transactions, and only the masterchain's ledger
    /// is committed chain state. A workchain has NO registry of its own (its
    /// genesis seeds an empty ledger — see [`fund_shard_genesis`]), so the
    /// workchain derived its validator set from an always-empty ledger and
    /// kept the config-defined set for the whole life of the process: the
    /// "validator set gap" the audit found. A masterchain rotation (bond,
    /// unbond, slash) was never transmitted to the workchains.
    ///
    /// With this handle the workchain reads the SAME ledger the masterchain
    /// commits, so the rotation is adopted at the next height boundary —
    /// no node restart, no separate registry to reconcile.
    ///
    /// `None` means "no master registry available": the runtime falls back to
    /// its own (local) ledger, which is the pre-sharding behaviour.
    pub master_staking: Option<MasterStakingLedger>,
    /// Optional governance engine. When present, proposals/votes can be driven
    /// through the node (and later applied to parameters).
    pub governance: Option<crate::governance::Governance>,
    /// Block reward (nano-STELL) paid to the proposer on each finalized block.
    /// Zero disables rewards.
    pub block_reward: u64,
    /// The last decision proof, stashed by `try_finalize` before it resets
    /// `hc`. The main loop consumes it for the commit broadcast that lets
    /// lagging peers catch up in place.
    pub last_decision: Option<(Height, Block, crate::consensus::QuorumCertificate)>,
    /// Retained precommits for the last decided parent block (`H-1`) so late
    /// 4th/N-th precommits can enrich `Block.last_qc` without mutating `hc` or
    /// `SafetyAuthority`.
    pub decided_parent_votes: Option<DecidedParentVotes>,
    /// DOWNTIME-RESTORE fail-closed gate: `true` when boot could not rebuild
    /// the finalized parent's decision QC from locally verifiable persisted
    /// data. `propose` refuses to build while set, so the node never emits a
    /// block that omits required downtime evidence; recording a verified
    /// decision again (restore / adopt / finalize / sync) clears it.
    pub parent_evidence_missing: bool,
    /// Which shard this runtime produces and validates blocks for. Defaults to
    /// `MASTERCHAIN_SHARD` so existing single-shard call sites are unchanged.
    pub shard_id: ShardId,
    /// The shards this process runs. Defaults to the single masterchain, so
    /// `is_sharded()` is false and every shard-aware check below is skipped.
    pub shard_registry: ShardRegistry,
    /// Node-local cross-shard transport (in-process mailbox or the shared
    /// infnode KV). `None` disables cross-shard flow entirely, which is the
    /// single-shard default and leaves every pre-sharding call site untouched.
    pub cross_shard: Option<Arc<crate::network::CrossShardTransport>>,
    /// Process-shared finalized-header registry (C1 anchor). `None` (unit
    /// tests, single-shard nodes) fails anchored verification CLOSED.
    /// Set once via [`Self::with_finalized_headers`]; shared (same `Arc`)
    /// with every shard runtime AND state engine in the process, so a header
    /// finalized on any shard anchors consumption on all of them.
    pub finalized_headers: Option<Arc<std::sync::RwLock<crate::sharding::FinalizedHeaderRegistry>>>,
    /// Inbound cross-shard messages this runtime has already committed and
    /// credited. A pure function of the applied chain (rebuilt block by block on
    /// replay), used to reject a replayed inbound message at proposal time
    /// synchronously. Not part of the state root; the state engine keeps its own
    /// copy so a direct apply is safe too.
    consumed_cross_shard: HashSet<CrossShardKey>,
    /// §5 M3: outbound transfers this chain committed, by transaction hash to
    /// (transaction, producing height). Rebuilt block by block in
    /// `record_apply_outcome` (every apply path funnels through it), so ack /
    /// bounce linkage checks and the height-based timeout rule are pure
    /// functions of the applied chain on every node.
    produced_cross_shard: HashMap<[u8; 32], (Transaction, u64)>,
    /// §5 M3: transaction hashes whose cross-shard lifecycle completed on this
    /// chain (an ack OR a bounce was committed). At most one completion per
    /// transaction, even across differing carrier hashes — the guard that
    /// keeps a late duplicate (or a bounce after an ack) from minting twice.
    completed_cross_shard: HashSet<[u8; 32]>,
    /// §9: the cross-shard TWO-PHASE-COMMIT activation switch.
    ///
    /// `Disabled` (the default) keeps the legacy outbox/inbox/ack/bounce
    /// flow for every transfer - the mode the already-deployed chain state
    /// runs in. `FromHeight(h)` switches transfers PRODUCED at height `h` or
    /// later to the 2PC; transfers produced before `h` keep running the
    /// legacy flow to completion, so one transfer is never half 2PC and half
    /// legacy.
    pub xpc_activation: crate::xshard2pc::XpcActivation,
    /// §9: the runtime's mirror of the committed 2PC records (tx hash ->
    /// record), keyed the same way the engine's map is.
    ///
    /// A NODE-LOCAL mirror of the engine's committed state, like
    /// `produced_cross_shard` and `completed_cross_shard` above: the
    /// proposal-validation path is SYNCHRONOUS and must not await, so it
    /// reads the mirror. The mirror is refreshed from the engine on every
    /// apply (the engine is the authority) and restored from the persisted
    /// replay snapshot on startup, so the two never disagree about a
    /// decision.
    xpc_records: HashMap<[u8; 32], crate::xshard2pc::XpcRecord>,
    /// §9/S10: node-local first-seen height of every inbound cross-shard
    /// message id currently in the mailbox. A message that keeps failing
    /// admission is quarantined and pruned once it has been seen for
    /// [`crate::xshard2pc::XPC_MAILBOX_QUARANTINE_HEIGHTS`] heights, so a peer
    /// cannot grow the mailbox with records that can never be admitted. The
    /// map is bounded to
    /// [`crate::xshard2pc::XPC_MAILBOX_MAX_TRACKED`] entries (oldest evicted
    /// and pruned first). It is transport bookkeeping, NOT consensus state:
    /// it is not hashed into the root and never changes block validity.
    xpc_mailbox_seen: HashMap<[u8; 32], u64>,
    /// §7 Phase 2: the single ordered execution worker (spawned lazily on the
    /// first submit, so construction never needs a tokio context) and the
    /// bounded FIFO of decided-but-not-yet-installed applies. Below
    /// `EXECUTION_PIPELINE_V1` the queue holds at most ONE entry (the historical
    /// single slot: a second submit is refused); at/above the gate it holds up
    /// to [`MAX_APPLY_IN_FLIGHT_DEPTH`] and a new decision is admitted only when
    /// the committed post-state it builds on is already recorded (see
    /// [`Self::can_accept_consensus_height`]). Every reader of post-H state
    /// checks [`Self::has_pending_apply`] first.
    apply_lane: Option<ApplyLane>,
    apply_in_flight: std::collections::VecDeque<ApplyInflight>,
    /// Worker-certified post-state roots by height, newest
    /// [`POST_STATE_HISTORY_CAP`] entries only (oldest pruned first).
    ///
    /// This is the "has the committed post-state this decision builds on been
    /// produced yet?" oracle used by
    /// [`Self::can_accept_consensus_height`] at/above the gate. Node-local
    /// bookkeeping: never hashed, never on the wire.
    pub post_state_roots: BTreeMap<u64, [u8; 32]>,
    /// D2 consensus-penalty snapshot by height (the exact map shape the engine
    /// exposes), newest [`POST_STATE_HISTORY_CAP`] entries only. Travels with
    /// [`Self::post_state_roots`] so a reader can reconstruct the consensus fee
    /// floor as of a recorded post-state. Local mirror only: never hashed.
    pub consensus_penalties_at: BTreeMap<u64, HashMap<[u8; 32], u64>>,
    /// Node-local projection over the committed accounts plus every queued
    /// decided block (see [`PendingExecView`]). Rebuilt on each install; also
    /// advanced optimistically by [`Self::try_finalize_submit`].
    pub pending_exec_view: PendingExecView,
    /// PARK-AND-REPLAY slots (liveness): the newest proposal / peer commit
    /// that arrived while `apply_in_flight` held post-H state. Each slot holds
    /// at most ONE item (a newer arrival overwrites the older one), so the
    /// pair is a hard bound of two entries and can never grow. Replayed
    /// through the normal fully-validating paths the moment the worker
    /// reports back (see `take_parked` and the driver hook); never applied
    /// from here.
    parked_proposal: Option<ParkedProposal>,
    parked_commit: Option<ParkedCommit>,
    /// Snapshot capture in flight (see `SnapBundle`): at most one queued or
    /// executing. A second submit while set is refused; the caller retries on
    /// a later height (labels stay exact — a skipped height simply snapshots
    /// later).
    snapshot_in_flight: Option<tokio::sync::oneshot::Receiver<Option<SnapBundle>>>,
    /// Parallel block execution enabled flag.
    pub parallel_exec: bool,
    /// Fail-closed stale-ledger gate (node C): when the staking ledger the
    /// validator set would be derived from lags the state beyond
    /// [`crate::storage::validator_set_freshness_max_lag`], the set is
    /// REFUSED for quorum use and the node runs as observer (no votes) with
    /// a loud log, instead of silently voting/verifying with a foreign set.
    /// Set by the checked refresh paths below; cleared by any fresh refresh.
    pub validator_set_stale: bool,
    /// Human-readable reason for [`Self::validator_set_stale`], for logs/RPC.
    pub validator_set_stale_reason: Option<String>,
    /// Heights the stale verdict was derived from (state, ledger).
    pub validator_set_state_height: Option<u64>,
    /// Heights the stale verdict was derived from (state, ledger).
    pub validator_set_ledger_height: Option<u64>,
    /// Node-local count of validator-set re-entry WARNs ever emitted by the
    /// refresh paths below (metric/counter, visibility only — never consensus).
    pub validator_reentry_warns_total: u64,
    /// Re-entrants under liveness watch: member -> height it rejoined the set.
    /// Fed by [`Self::note_validator_set_gains`] on every refresh; entries
    /// leave when the member votes again (ledger `missed` streak forgiven) or
    /// drops out of the derived set. Local policy + visibility ONLY: the
    /// derived set itself is never altered.
    pub reentry_watch: HashMap<ValidatorId, u64>,
    /// Optional Falcon-512 keypair for post-quantum consensus vote signing.
    pub falcon_key: Option<FalconKeypair>,
    /// Simulator-only flag: use seeded Falcon signing so identical cluster
    /// runs produce byte-identical `last_qc` commitments and block hashes.
    pub deterministic_sim_signing: bool,
    /// Last wall-clock instant finalization made progress (deadlock breaker).
    /// Stamped at construction and on every finalize/adopt; the breaker only
    /// fires after `STELL_DEADLOCK_TIMEOUT_SECS` (default 300) without it.
    pub last_progress_at: std::time::Instant,
    /// Last wall-clock instant the deadlock breaker jumped (rate limit: at
    /// most one jump per timeout window).
    pub last_breaker_at: Option<std::time::Instant>,
    /// Fork-choice / reorg state.
    ///
    /// The live node used to accept ONLY the blocks that continue the
    /// finalized head and to forget every competing branch it had seen: a
    /// fork was invisible, and nothing told a client that the block it was
    /// told about was not on the chain. This manager keeps the finalized
    /// chain plus the ALTERNATIVE candidate branches (recorded before
    /// finality), runs the fork-choice over them and produces the
    /// invalidation signal when a branch is pruned or rolled back.
    pub chain: crate::chain::ChainManager,
    /// Where the invalidation signals are published (the RPC / streaming
    /// layer). `None` means "no transport wired": the signals are then only
    /// logged, never silently dropped.
    pub invalidation_sink: Option<crate::chain::InvalidationSink>,
    /// The node's LIGHT CLIENT (audit W8.3 / production blocker A10).
    ///
    /// The trusted anchor every peer-supplied block is checked against: the
    /// chain this node itself finalized, carrying the quorum certificates
    /// that decided it. `None` until the node is given its genesis root (see
    /// [`ValidatorRuntime::set_light_client`]); from then on, a peer chain
    /// is applied only if it extends this anchor.
    pub light: Option<crate::light_client::LightClient>,
    /// Validator-set change STAGED but not yet in force (W10.5
    /// activation-boundary fix).
    ///
    /// A set derived from the staking ledger at ledger-height L takes effect
    /// at height L+1 — NEVER mid-flight. `install_validator_set_from_ledger`
    /// only stages here (`Some((activation, set))`); the set becomes the
    /// in-force consensus set when the node advances to `activation`
    /// (`install_due_validator_set`, called on every finalize/adopt advance
    /// and after every refresh). The quorum threshold for a height in
    /// progress therefore never jumps under a running round, and every node
    /// that applied the same prefix switches at the same agreed height.
    ///
    /// A WORKCHAIN's activation is NOT its own `height + 1`: it is the
    /// MASTERCHAIN's activation boundary for the same rotation, carried by
    /// [`MasterSetStamp`] (see [`workchain_set_activation_height`]), so two
    /// shards that observed the rotation at different local tips stage it for
    /// the SAME height instead of diverging on the proposer schedule.
    pub pending_validators: Option<(u64, ValidatorSet)>,
    /// Activation history of the in-force consensus set, oldest first:
    /// `(activation_height, set)` — the set took effect when the node
    /// advanced to `activation_height`.
    ///
    /// Used by [`Self::validator_set_for_height`] to answer "which set
    /// decided height H" for QC verification (adopt, sync, replay), so a
    /// certificate is always checked against the set in force AT ITS OWN
    /// height, never the live set. Bounded ([`VALIDATOR_SET_HISTORY_CAP`]);
    /// only actual changes are recorded, so in practice this holds a handful
    /// of entries.
    pub validator_set_history: std::collections::VecDeque<(u64, ValidatorSet)>,
    // --- C2 backpressure honesty (local only, never on the wire) ---
    /// Meter: proposal validations slower than
    /// [`SLOW_VALIDATION_THRESHOLD_MS`] (the node was too slow to validate,
    /// not the network). Alertable via metrics (`slow_validation_total`).
    pub slow_validation_total: u64,
    /// Per-stage timings (ms) of the LAST proposal validation, in run order:
    /// e.g. `proposer_sig_verify`, `state_root_check`, `order_commit`,
    /// `tx_batch_verify`, `fee_floor_mempool`, `header_checks`. Kept for the
    /// `[slow-validation]` log line that names the slow stage.
    pub validation_last_stages: Vec<(String, u64)>,
    // --- R-tempo pack/scan caches (local only, never on the wire) ---
    /// Per-(height, state-root) sender snapshot for block packing: sender ->
    /// (nonce, balance). Stored only under a root-equality gate (see
    /// `snapshot_roots_match`): the snapshot is built under ONE read guard
    /// (mutually consistent entries) bracketed by two root reads, and stored
    /// only when both roots match — so the entries are exactly the state at
    /// the key root. A later hit re-checks the CURRENT root against the key:
    /// equal roots mean equal state, so the entries are still exact. Any
    /// mutation (apply, faucet, test funding) changes the root and misses.
    /// Packing with a hit yields identical selection to a fresh scan for the
    /// same mempool (the refresh pass still fetches senders that arrived
    /// after the snapshot). Proposer-local only: validity rules untouched.
    #[allow(clippy::type_complexity)]
    // GATE: type alias would churn public cache shape; complexity is local-only.
    pack_snapshot: std::sync::Mutex<Option<(Height, BlockHash, HashMap<[u8; 32], (u64, u64)>)>>,
    /// Per-(height, state-root) actor-inbox total, same keying/soundness as
    /// `pack_snapshot`: the inbox sum is a pure function of state, so a hit
    /// returns exactly what a fresh full-map scan would prove. Turns the
    /// O(accounts) scan on the propose/validate/adopt paths into O(1) for
    /// repeat visits at the same height (every round after the first, every
    /// proposal validation after the first).
    actor_backlog_cache: std::sync::Mutex<Option<(Height, BlockHash, usize)>>,
    // --- STAB verify-once caches (local only, never on the wire) ---
    /// Order-root per block hash: `check_order_commitment` is a pure function
    /// of the block body, so the second validation of the same block (every
    /// round retry, demanded re-propose, adopt) hits O(1) instead of
    /// re-hashing O(txs). Keyed by block hash (which commits to the tx list).
    /// Bounded (cleared past 1024 entries): proposer-local only.
    order_root_cache: std::sync::Mutex<std::collections::HashMap<BlockHash, [u8; 32]>>,
    /// Batch ed25519 verdict per signature-committing key: a pure function
    /// of the tx list INCLUDING signatures (see `batch_verify_cache_key` —
    /// the block hash alone does not commit to signatures). Turns the
    /// timed-path re-verify from O(txs) crypto into O(1).
    batch_verify_cache: std::sync::Mutex<std::collections::HashMap<BlockHash, bool>>,
    /// Proposer-signature verdict per block hash: pure function of block bytes.
    proposer_sig_cache: std::sync::Mutex<std::collections::HashMap<BlockHash, bool>>,
    /// QC power per block hash (the `last_qc` embedded in that block):
    /// `check_last_qc_evidence` (validate) and the apply-time attribution
    /// share one crypto verification per block instead of three
    /// (validate power + apply verify + apply signers_set).
    qc_power_cache: std::sync::Mutex<std::collections::HashMap<BlockHash, (bool, u64)>>,
    // --- VEL-1 bounded proposer-prebuild (local only, never on the wire) ---
    /// Prebuilt plain-tx selection for [`Self::propose`]: the ordered
    /// candidate list from an earlier full selection run, reused after
    /// per-tx revalidation against live state (see
    /// [`Self::prebuild_next_proposal`]). Single slot (overwritten, never
    /// grown), txs bounded by `MAX_BLOCK_TXS`. `None` or a height mismatch
    /// means "build fresh" — the propose path is unchanged in that case.
    /// Bounded queue cap for pending outbound CN-VRF v3 commitments.
    prebuilt_selection: std::sync::Mutex<Option<PrebuiltSelection>>,
    // --- CN-VRF v3 runtime state (local custody + VDF lane + synchronous mirrors) ---
    /// Lazily-spawned off-tick sequential MinRoot VDF worker.
    vdf_lane: Option<VdfLane>,
    /// In-flight VDF job `(target_epoch, oneshot_rx)` submitted at `H_freeze`.
    pending_vdf_rx: Option<(u64, tokio::sync::oneshot::Receiver<Option<VdfJobOutput>>)>,
    /// Completed `EpochVdfBeacon`s ready to embed at epoch boundary `epoch * EPOCH_LEN`.
    ready_vdf_beacons: BTreeMap<u64, crate::sharding::EpochVdfBeacon>,
    /// Synchronous mirror of `state.epoch_vdf_beacons_read()` for sync validation paths.
    finalized_epoch_beacons: BTreeMap<u64, [u8; 48]>,
    /// Synchronous mirror of `state.cnvrf_v3_read()` for sync validation paths.
    cnvrf_v3_mirror: crate::cn_vrf::CnVrfV3State,
    /// Freeze-boundary `(freeze_block_hash, rolling_mix)` inputs recorded at `H_freeze`.
    cnvrf_freeze_inputs: BTreeMap<u64, ([u8; 32], [u8; 48])>,
    /// Local precomputed per-epoch CN-VRF v3 hash chains keyed by `epoch_n`.
    cnvrf_v3_chains: BTreeMap<u64, crate::cn_vrf::CnVrfV3Chain>,
    /// Epochs whose local secret custody failed verification against on-chain commitments.
    cnvrf_v3_disabled_epochs: HashSet<u64>,
    /// Outbound CN-VRF v3 commitments queued to ride proposals before `H_freeze`.
    pending_cnvrf_v3_commits: Vec<crate::cn_vrf::CommitCarrierV3>,
    /// Optional disk directory for `enc2:` encrypted per-epoch secret custody.
    cnvrf_v3_dir: Option<std::path::PathBuf>,
    /// Chain ID bound into CN-VRF v3 commitments, reveals, and epoch seeds.
    cnvrf_v3_chain_id: u64,
    /// Configured MinRoot VDF steps per epoch (defaults to `DEFAULT_VDF_STEPS_PER_EPOCH`).
    cnvrf_v3_vdf_steps: u64,
    /// Test/debug activation height override (keeps frozen `CNVRF_V3_ACTIVATION_HEIGHT` untouched).
    #[cfg(any(test, debug_assertions))]
    cnvrf_v3_activation_override: Option<u64>,
    /// Single serialized safety authority owning lock, floors, cross-kind
    /// prevote/precommit guard, and durable write-ahead persistence.
    pub safety: crate::safety::SafetyAuthority,
}

impl std::fmt::Debug for ValidatorRuntime {
    /// Deliberately NOT derived: the runtime owns signing keys and the
    /// node-local MEV KEM seed. Only non-secret identity/progress plus the
    /// WIRING PRESENCE is rendered; the seed itself is always redacted.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidatorRuntime")
            .field("id", &hex::encode(self.id))
            .field("height", &self.hc.height)
            .field("round", &self.hc.round)
            .field(
                "mev_kem_registry_entries",
                &self.mev_kem_registry.as_ref().map(|r| r.len()),
            )
            .field(
                "mev_kem_seed",
                &self.mev_kem_seed.as_ref().map(|_| "[REDACTED]"),
            )
            .finish_non_exhaustive()
    }
}

impl ValidatorRuntime {
    /// Install the node-local MEV KEM material explicitly.
    ///
    /// Bootstrap derives the seed from the node's persisted secret under the
    /// `STELL_MEV_KEM_SEED_V1` BLAKE3 derive-key domain and passes the registry
    /// handle; callers that already built a runtime can use this builder.
    /// Without it (and without the shared-pool wiring) node-side epoch DKG
    /// stays fail-closed exactly as before.
    pub fn with_mev_kem(
        mut self,
        registry: Arc<crate::mev_kem_registry::MevKemRegistry>,
        seed: [u8; 64],
    ) -> Self {
        self.mev_kem_registry = Some(registry);
        self.mev_kem_seed = Some(zeroize::Zeroizing::new(seed));
        self
    }

    /// Mutable setter for an already-built runtime (same contract as
    /// [`Self::with_mev_kem`]).
    pub fn set_mev_kem(
        &mut self,
        registry: Arc<crate::mev_kem_registry::MevKemRegistry>,
        seed: [u8; 64],
    ) {
        self.mev_kem_registry = Some(registry);
        self.mev_kem_seed = Some(zeroize::Zeroizing::new(seed));
    }
}

/// Hard cap on queued outbound CN-VRF v3 commitments held in memory.
pub const MAX_PENDING_CNVRF_V3_COMMITS: usize = 1024;
/// Hard cap on CN-VRF v3 commitments packed into a single proposed block.
pub const MAX_CNVRF_V3_COMMITS_PER_BLOCK: usize = 256;

/// Validation is "slow" (backpressure) when the whole check exceeds this.
///
/// 500ms: above the 50ms block floor and the live r0 happy-path budget, so a
/// validation that crosses it provably eats a full round budget on a slow
/// member. Local threshold only — the VERDICT is unchanged (accept or
/// refuse exactly as before); only the meter + log fire.
pub const SLOW_VALIDATION_THRESHOLD_MS: u64 = 500;
