//! Consensus runtime: wires the BFT engine to block production, the mempool and
//! the state engine, and provides an in-process multi-validator Cluster.
//!
//! This is the integration layer between `consensus` (pure state machine) and
//! the rest of the node. The P2P transport that carries proposals/votes between
//! real nodes is layered on top of this (next stage).

use crate::consensus::{
    FalconKeypair, Height, HeightConsensus, Round, Step, ValidatorId, ValidatorSet, Vote, VoteKind,
};
use crate::mempool::Mempool;
use crate::sharding::{
    Block, CrossShardKey, CrossShardMessage, MasterStakingLedger, ShardId, ShardRegistry,
    Transaction, ValidatorSetSource, MASTERCHAIN_SHARD,
};
use crate::state_engine::InMemoryStateEngine;
use ed25519_dalek::{Signer as _, SigningKey};
use futures::FutureExt as _;
use sha2::{Digest as _, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

pub type BlockHash = [u8; 32];

/// Hard cap on transactions per block (anti-DoS: a malicious proposer must not
/// be able to craft an unbounded block).
pub const MAX_BLOCK_TXS: usize = 10_000;
/// Upper bound on signers in a peer-supplied commit certificate. The validator
/// set is far smaller than this; anything larger is an attempt to make us run an
/// unbounded signature-verification loop.
pub const MAX_COMMIT_CERT_SIGNERS: usize = 4_096;

/// Cap on the validator-set activation history ([`ValidatorRuntime::validator_set_history`]).
/// Only actual set changes are recorded, so this is barely touched in
/// practice (a bond/slash/eject every entry); the cap only bounds a pathological
/// flapping registry. 1024 entries cover ~3M heights of churn at worst.
pub const VALIDATOR_SET_HISTORY_CAP: usize = 1024;

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
/// times derive the same answer from the same two blocks. One hour is generous
/// on purpose — honest proposers stamp seconds apart, and operational gaps and
/// catch-up produce ~1000s single-step jumps in this repo's own suites — while
/// still refusing absurd far-future stamps that would poison every
/// timestamp-driven rule (session expiry, unbonding maturity) for years.
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

/// Deterministic genesis: credit EVERY validator in `validators` the same fixed
/// balance. The validator set is a `BTreeMap` (sorted), so every node with the
/// same config credits the same accounts in the same order and derives an
/// identical genesis state root.
pub async fn fund_genesis(engine: &InMemoryStateEngine, validators: &ValidatorSet, balance: u64) {
    for v in validators.validators.keys() {
        engine
            .update_account(crate::state_engine::AccountState::new(*v, balance))
            .await;
    }

    // Bond them in the staking ledger too, not just fund them.
    //
    // The validator set is re-derived from this ledger at every height
    // boundary, so funding an account without bonding it leaves the set empty.
    // An empty set has zero total power, and a zero-power set can reach quorum
    // with a single vote, so the node would finalise every block by itself and
    // the chain would look healthy while having no consensus in it at all.
    //
    // Both nodes must derive an identical ledger, so the bond amount and
    // commission are fixed constants rather than derived from anything local.
    let bond = GENESIS_VALIDATOR_BOND.min(balance);
    let mut ledger = engine.staking_write().await;
    for v in validators.validators.keys() {
        // A genesis validator can only appear once; a repeated id is a config
        // error and must not silently double-bond.
        if ledger.validators.contains_key(v) {
            continue;
        }
        // Never silent: a failed genesis bond leaves a funded-but-unbonded
        // validator and a thin/empty set (Finding-8 class). Loud on both
        // channels; control flow unchanged (tests intentionally probe thin
        // sets with tiny balances).
        if let Err(e) = ledger.bond_genesis(*v, bond, 0) {
            let msg = format!(
                "[genesis] WARN bond failed for {} (bond {bond}): {e} — validator funded but NOT bonded",
                hex::encode(&v[..6])
            );
            eprintln!("{msg}");
            tracing::error!("{msg}");
        } else {
            // SEC-ECON-01: Transfer bond from validator account to STAKING_POOL
            // so genesis stake is fully backed and STAKING_POOL is solvent.
            // Strict-only (LEAD: no legacy branch): every genesis takes this
            // path unconditionally.
            let _ = engine.debit_native(v, bond).await;
            let _ = engine
                .credit_native(&crate::staking::STAKING_POOL, bond)
                .await;
        }
    }
}

/// Bond amount for a genesis validator: bare MIN (v1 genesis bytes —
/// `bond_genesis` reproduces the pinned root `61336779...` exactly).
/// The runtime MIN+buffer floor applies to NEW stakes, not to founding.
pub const GENESIS_VALIDATOR_BOND: u64 = crate::staking::MIN_VALIDATOR_BOND;

/// Genesis funding for a NON-masterchain shard.
///
/// Deliberately different from [`fund_genesis`]: it credits ONLY the supplied
/// dev/faucet account and never the validators. `fund_genesis` both funds and
/// bonds the validator set, and running it again on a second shard would
/// double-count validator balances and give that shard its own staking ledger.
/// A workchain instead keeps its staking ledger EMPTY, so
/// `ValidatorRuntime::refresh_validator_set_from_staking` falls back to the
/// config-defined validator set and both shards agree on one P2P namespace and
/// one validator schedule. Only the dev account may move value on that shard in
/// M1; cross-shard value flow is a later milestone.
pub async fn fund_shard_genesis(engine: &InMemoryStateEngine, dev_account: [u8; 32], balance: u64) {
    engine
        .update_account(crate::state_engine::AccountState::new(dev_account, balance))
        .await;
}

/// Build the height-0 block for a shard. Every shard roots its own chain at
/// `prev_hash == [0u8; 32]` with its own `state_root`; `shard_id` fixes the
/// block's identity so a shard-1 block can never validate as a shard-0 block.
pub fn shard_genesis_block(
    shard_id: ShardId,
    state_root: [u8; 32],
    proposer: [u8; 32],
    timestamp: u64,
) -> Block {
    Block {
        shard_id,
        height: 0,
        prev_hash: [0u8; 32],
        state_root,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp,
        proposer,
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        // Genesis (height 0) predates canonical downtime evidence: there is
        // no parent height to attest. `None` is also what every pre-upgrade
        // block decodes to — see `de_last_qc`.
        last_qc: None,
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
        // Genesis is never an epoch-committing boundary (see
        // `crate::mmr::commits_epoch_root`): it commits to no epoch root.
        mmr_epoch_root: [0u8; 32],
    }
}

/// The reward a block pays its proposer: the governed value when governance
/// has set one, else the node's configured default.
///
/// The governed value wins when set: a passed `SetBlockReward` proposal must
/// actually change what the next produced block pays, or governance is
/// decorative and the commitment records a parameter nothing reads.
///
/// SHARED by both block-apply paths - `ValidatorRuntime::apply_block_fees_rewards`
/// (live consensus) and `ChainState::apply_block` (reorg) - so a re-applied
/// block cannot pay a different reward than the node that produced it did.
pub fn block_reward_for(gov: Option<&crate::governance::Governance>, default: u64) -> u64 {
    gov.and_then(|g| g.applied.block_reward).unwrap_or(default)
}

/// Static actor-mailbox load of one block: every `SysCallActorSend` its
/// transactions carry, counting nested bodies transitively.
///
/// A top-level send enqueues one message; when that message is delivered its
/// body runs, and every send inside THAT body enqueues another — so the total
/// number of messages this block's content can ever generate is the recursive
/// count, not just the top-level one. This is an UPPER bound on what delivery
/// will do (a reverted payload or a failed body delivers less, never more),
/// which is exactly what a fail-closed validation check needs: it never
/// executes, it only counts bytes already committed in the block.
///
/// Pure function of the block alone — no clock, no state — so the proposer
/// and every validator derive the same number.
pub fn count_block_actor_sends(block: &Block) -> usize {
    block
        .transactions
        .iter()
        .map(|t| count_program_sends(&t.payload))
        .fold(0usize, |acc, n| acc.saturating_add(n))
}

/// Recursive half of [`count_block_actor_sends`]: sends in one program plus
/// every send inside the bodies those sends carry.
fn count_program_sends(program: &[crate::svm::OpCode]) -> usize {
    program
        .iter()
        .map(|op| match op {
            crate::svm::OpCode::SysCallActorSend { body, .. } => {
                1usize.saturating_add(count_program_sends(body))
            }
            _ => 0,
        })
        .fold(0usize, |acc, n| acc.saturating_add(n))
}

/// Senders present in the live pool but missing from a snapshot taken
/// earlier: they were admitted while the snapshot's account reads were in
/// flight. Pure helper for the r0-fullness refresh in [`ValidatorRuntime::propose`].
pub fn missing_sender_accounts(
    snapshot: &std::collections::HashMap<[u8; 32], (u64, u64)>,
    pool_senders: &[[u8; 32]],
) -> Vec<[u8; 32]> {
    pool_senders
        .iter()
        .copied()
        .filter(|s| !snapshot.contains_key(s))
        .collect()
}

/// Static half of the actor-mailbox cap check: a block whose OWN sends already
/// exceed the cap is rejected without reading any state. The backlog-inclusive
/// check lives in [`ValidatorRuntime::check_actor_cap`] (async, reads the
/// engine); both agree whenever the backlog is empty, which honest operation
/// maintains at every boundary.
fn block_actor_sends_exceed_cap(block: &Block) -> bool {
    count_block_actor_sends(block) > crate::state_engine::MAX_ACTOR_MSGS_PER_BLOCK
}

// ==================== §7 Phase 2: sequenced execution lane ====================
//
// `try_finalize` used to execute the decided block INLINE: the consensus tick
// awaited `apply_block_fees_rewards` → `apply_block_transition` to completion,
// so one slow apply stalled round timers, gossip handling and the next
// proposal. Phase 2 moves the WAITING off the tick without moving the work,
// the order or the bytes:
//
//   * `apply_decided` is the exact current finalize-apply sequence (reward
//     resolution → the shared `apply_block_transition` → the node-local
//     bookkeeping that cannot move the root). Every route that applies a
//     decided block — local finalize, sequenced submit, adopt/walk, replay —
//     funnels through the same transition and the same bookkeeping.
//   * Execution itself runs on ONE long-lived ordered worker ([`ApplyLane`]:
//     a single task, FIFO, never parallel, strictly in submission order).
//     Callers submit strictly height-ordered (enforced by the
//     `apply_in_flight` gates below), so the worker applies H before H+1.
//   * While the worker runs, the loop keeps draining inbound messages (votes
//     still count; they never read post-H state). Anything that WOULD read
//     post-H state — `propose` for the next height, the `on_proposal` root
//     check, `adopt_committed`, a second submit — refuses while
//     `apply_in_flight` is set. Nothing observing consensus (the `finalized`
//     list, the height advance, the commit broadcast, receipts) moves until
//     the worker reports back and the outcome is installed.
//
// What was deliberately NOT built (design P2a/P2b rejected, P2c skipped):
// speculative pre-execution of un-decided blocks (executing a proposal before
// its QC exists would make state a function of gossip order, and every node
// would certify a different root), and a side-effect-free staging cache keyed
// by block hash. The cache has no safe consumer: redelivery paths already
// short-circuit on height before executing, while reorg/replay MUST re-execute
// (restoring from a checkpoint or healing), so serving a cached outcome there
// would hide a divergence instead of reproducing it. No cache was added.

/// One execution job for the sequenced worker: the decided block plus the
/// already-resolved reward, so the worker never reads governance or consensus
/// state — only the engine it was spawned with and the bytes it was sent.
struct ApplyJob {
    block: Block,
    reward: u64,
    done: tokio::sync::oneshot::Sender<(crate::state_engine::BlockTransitionOutcome, [u8; 32])>,
}

/// A quiescent state capture: every root-committed domain cloned at a FIFO
/// idle point (after the previous apply installed, before the next starts),
/// so the bytes can never mix heights. The cross-shard replay set is NOT
/// captured here even though its engine halves ARE root-committed (see
/// `commitment::write_cross_shard_domain`): the tick captures it at submit
/// quiescence (the same post-`height` instant) and the poll site reuses those
/// bytes verbatim — a fresh read at poll would be newer state under this
/// height's label and brick the next boot in `verify_restored_root` (see the
/// snapshot block in main.rs).
pub struct SnapBundle {
    pub height: u64,
    /// The canonical state capture: the accounts (address-sorted) AND the D2
    /// consensus penalty map. The penalty is consensus-critical (it enters
    /// the charged fee), so it MUST travel with the accounts — a snapshot
    /// without it would restore a node that charges a different fee than a
    /// node that applied the blocks (audit W6.6). Serialized with the same
    /// shape `InMemoryStateEngine::create_snapshot` produces, so the bytes
    /// this bundle publishes are the bytes the restore path reads.
    pub accounts: crate::state_engine::StateSnapshotV2,
    pub domains: crate::storage::DomainSnapshot,
    pub session_keys: Vec<u8>,
    pub bridge: Vec<u8>,
    pub zkml_models: Vec<u8>,
}

/// Snapshot request/response on the sequenced lane (see `SnapBundle`).
/// `expected_root` is the worker-certified post-`height` root: the worker
/// captures ONLY if the live engine still roots there, so a snapshot labeled
/// H can never carry H+1 state no matter the queue order (mislabel is
/// impossible by construction, not by timing).
struct SnapshotJob {
    height: u64,
    expected_root: [u8; 32],
    done: tokio::sync::oneshot::Sender<Option<SnapBundle>>,
}

#[allow(clippy::large_enum_variant)]
// GATE: boxing ApplyJob would change memory layout without benefit; sizes are bounded and local-only.
enum LaneJob {
    Apply(ApplyJob),
    Snapshot(SnapshotJob),
}

/// The sequenced execution lane: one FIFO channel feeding one task.
///
/// Cloning the lane clones the sender only — every clone feeds the SAME queue
/// and therefore the same order (same contract as `ConsensusSender`).
#[derive(Clone)]
struct ApplyLane {
    tx: tokio::sync::mpsc::UnboundedSender<LaneJob>,
}

impl ApplyLane {
    /// Spawn the single worker for `state`. One task, one loop: take the next
    /// job, run the shared transition to completion, report the outcome plus
    /// the post-apply root, repeat. Two jobs can never overlap (the next
    /// `recv` happens only after the previous outcome is sent), and order is
    /// exactly submission order.
    fn spawn(state: &Arc<InMemoryStateEngine>) -> Self {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<LaneJob>();
        let state = Arc::clone(state);
        tokio::spawn(async move {
            while let Some(job) = rx.recv().await {
                match job {
                    LaneJob::Apply(job) => {
                        // Panic guard (audit follow-up): a DETERMINISTIC panic (same
                        // block bytes => same panic on every node) bricks finality
                        // identically everywhere across restarts. Never synthesize an
                        // outcome and never advance past an unapplied block — park
                        // LOUDLY (the Closed branch below already parks on worker
                        // death; this covers the panic itself). No outcome is
                        // reported, so `try_poll_apply` sees Closed and parks.
                        let outcome = std::panic::AssertUnwindSafe(async {
                            let outcome =
                                state.apply_block_transition(&job.block, job.reward).await;
                            // Captured HERE, on the worker, so the submitter learns the
                            // certified post-H root without recomputing the commitment a
                            // second time on the tick.
                            let root = state.get_state_root().await;
                            (outcome, root)
                        });
                        let result = outcome.catch_unwind().await;
                        match result {
                            Ok((outcome, root)) => {
                                let _ = job.done.send((outcome, root));
                            }
                            Err(_) => {
                                tracing::error!(
                            height = job.block.height,
                            "apply worker PANICKED — parking height, never advancing past an unapplied block"
                        );
                                // `done` is dropped unsent: `try_recv` sees Closed and
                                // parks (fail-closed, same as worker death).
                            }
                        }
                    }
                    LaneJob::Snapshot(job) => {
                        // Quiescent capture (audit 2026-10-06, chain-down
                        // incident): FIFO order usually lands this between two
                        // applies, but queue order alone cannot prove it (an
                        // H+1 apply submitted earlier this tick would run
                        // first). The ROOT check makes it airtight: capture
                        // only if the engine still roots at the certified
                        // post-`height` root; otherwise skip loudly and let a
                        // later height snapshot instead (labels stay exact —
                        // a skipped height simply snapshots later).
                        if state.get_state_root().await != job.expected_root {
                            tracing::warn!(
                                height = job.height,
                                "snapshot skipped: engine moved past the certified root (concurrent apply won the race)"
                            );
                            let _ = job.done.send(None);
                            continue;
                        }
                        // Quiescent capture (audit 2026-10-06, chain-down
                        // incident): FIFO order guarantees the previous apply
                        // installed and the next has not started, so these
                        // clones can never mix heights — unlike tick-side
                        // cloning, where the worker could slip an apply
                        // between the separate clone calls. Read locks only;
                        // uncontended (nothing else mutates mid-capture).
                        let accounts = crate::storage::clone_account_snapshot(&state).await;
                        let ledger = state.staking_read().await.clone();
                        let gov = state.governance_read().await.clone();
                        let domains =
                            crate::storage::DomainSnapshot::capture(&state, &ledger, &gov).await;
                        let session_keys = state.session_keys_snapshot().await;
                        let bridge = state.bridge_snapshot().await;
                        let zkml_models = state.zkml_models_snapshot().await;
                        let _ = job.done.send(Some(SnapBundle {
                            height: job.height,
                            accounts,
                            domains,
                            session_keys,
                            bridge,
                            zkml_models,
                        }));
                    }
                }
            }
        });
        Self { tx }
    }
}

/// A decided block whose execution is still on the worker: the decision is
/// final (QC attached, proof stashed) but NOTHING observable has moved yet —
/// no `finalized` entry, no height advance, no receipts. The outcome is
/// installed by `try_poll_apply` / `await_apply_completion`.
struct ApplyInflight {
    height: Height,
    hash: BlockHash,
    block: Block,
    done: tokio::sync::oneshot::Receiver<(crate::state_engine::BlockTransitionOutcome, [u8; 32])>,
}

/// What the worker reported back once its outcome is installed: the executed
/// height, its hash and the certified post-apply root (no recompute needed by
/// the caller).
pub struct ApplyCompleted {
    pub height: Height,
    pub hash: BlockHash,
    pub root: [u8; 32],
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
    pub blocks: HashMap<BlockHash, Block>,
    /// Bodies our locked peers are stuck on (learned from nil-vote lock hints).
    /// Scoped to `demanded_height` (a finalize moves on, old demands die with
    /// it); capped so hint spam cannot grow memory. Served one-shot per hint
    /// batch: re-proposing re-validates, and a still-stuck peer re-hints.
    demanded: HashSet<BlockHash>,
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
    /// §7 Phase 2: the single ordered execution worker (spawned lazily on the
    /// first submit, so construction never needs a tokio context) and the one
    /// in-flight apply, if any. At most one decided block is ever queued or
    /// executing: a second submit while this is set is refused, and every
    /// reader of post-H state checks this first.
    apply_lane: Option<ApplyLane>,
    apply_in_flight: Option<ApplyInflight>,
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
    prebuilt_selection: std::sync::Mutex<Option<PrebuiltSelection>>,
}

/// Validation is "slow" (backpressure) when the whole check exceeds this.
///
/// 500ms: above the 50ms block floor and the live r0 happy-path budget, so a
/// validation that crosses it provably eats a full round budget on a slow
/// member. Local threshold only — the VERDICT is unchanged (accept or
/// refuse exactly as before); only the meter + log fire.
pub const SLOW_VALIDATION_THRESHOLD_MS: u64 = 500;

// ============================================================================
// VEL-1 bounded proposer-prebuild (local only, never on the wire)
// ============================================================================

/// A prebuilt plain-transaction selection, cached for one height.
///
/// Produced ONLY by [`ValidatorRuntime::prebuild_next_proposal`] during an
/// idle window (`propose` itself never writes, so a round retry at the
/// current height can never evict a future-height prebuild), consumed by
/// `propose` after per-tx revalidation against live state. Single slot:
/// overwritten, never grown; `txs.len() <= MAX_BLOCK_TXS` by construction
/// (it came out of the capped selector). `None`/height-mismatch ⇒ build
/// fresh — the propose path is then byte-identical to before this cache.
#[derive(Clone, Debug)]
pub struct PrebuiltSelection {
    /// The height this selection was built for. Reused only when it equals
    /// the proposing height; anything else is discarded (stale parent).
    pub for_height: Height,
    /// Candidate transactions in selection order.
    pub txs: Vec<Transaction>,
}

/// Mutable filter state threaded through the pack admissibility predicate.
///
/// The predicate ([`ValidatorRuntime::pack_filter_accept`]) is a pure
/// function of (tx, this state): the same inputs always admit the same set
/// in the same order, whether it runs inside `propose`, inside the prebuild,
/// or during revalidation. Fresh `propose` builds this state from live
/// reads; reuse only ever REPLAYS the same predicate against fresh state —
/// so a reused selection is validity-identical to a fresh one, and any
/// composition difference is liveness-only (every kept tx passes the exact
/// checks a fresh build would apply, and receivers re-verify everything).
pub struct PackFilterCtx {
    /// Block timestamp the policy checks evaluate against.
    pub timestamp: u64,
    /// Shard scope of the proposing chain.
    pub sharded: bool,
    /// This chain's shard.
    pub my_shard: ShardId,
    /// Base fee leg of the admission floor.
    pub base_fee: u64,
    /// Per-sender D2 failure penalties.
    pub penalty_floors: HashMap<[u8; 32], u64>,
    /// Session-key registry snapshot (revocation + ceilings as of build).
    pub session_keys: crate::zkml::SessionKeyRegistry,
    /// Expected nonce + spendable balance per sender (live snapshot).
    pub next_nonce: std::cell::RefCell<HashMap<[u8; 32], (u64, u64)>>,
    /// Cumulative in-block session spend simulation.
    pub session_sim: std::cell::RefCell<crate::zkml::SessionSpendSim>,
    /// Senders already carrying an outbound cross-shard transfer in this block.
    pub used_senders: std::cell::RefCell<HashSet<[u8; 32]>>,
    /// Rejection census (diagnostics only, same counters as the inline path).
    pub rej_noacct: std::cell::Cell<u32>,
    /// Rejection census: nonce gap.
    pub rej_nonce: std::cell::Cell<u32>,
    /// Rejection census: insufficient funds.
    pub rej_funds: std::cell::Cell<u32>,
    /// Rejection census: session policy.
    pub rej_session: std::cell::Cell<u32>,
    /// Rejection census: shard scope.
    pub rej_shard: std::cell::Cell<u32>,
    /// Rejection census: fee floor.
    pub rej_basefee: std::cell::Cell<u32>,
    /// Rejection census: sponsor policy.
    pub rej_sponsor: std::cell::Cell<u32>,
}

impl PackFilterCtx {
    /// Fresh filter state over live inputs (what `propose` builds per block).
    ///
    /// `next_nonce`/`session_sim`/`used_senders` are the filter's starting
    /// point: a clean build passes the live snapshot and empty extras, while
    /// `propose` passes the post-sealed-loop state so plain selection
    /// continues exactly where the sealed path left off (byte-identical to
    /// the pre-factoring inline closure, which shared those same cells).
    #[allow(clippy::too_many_arguments)]
    // GATE: 9 filter inputs are required together; grouping would change call sites and packing semantics.
    pub fn new(
        timestamp: u64,
        sharded: bool,
        my_shard: ShardId,
        base_fee: u64,
        penalty_floors: HashMap<[u8; 32], u64>,
        session_keys: crate::zkml::SessionKeyRegistry,
        next_nonce: HashMap<[u8; 32], (u64, u64)>,
        session_sim: crate::zkml::SessionSpendSim,
        used_senders: HashSet<[u8; 32]>,
    ) -> Self {
        Self {
            timestamp,
            sharded,
            my_shard,
            base_fee,
            penalty_floors,
            session_keys,
            next_nonce: std::cell::RefCell::new(next_nonce),
            session_sim: std::cell::RefCell::new(session_sim),
            used_senders: std::cell::RefCell::new(used_senders),
            rej_noacct: std::cell::Cell::new(0),
            rej_nonce: std::cell::Cell::new(0),
            rej_funds: std::cell::Cell::new(0),
            rej_session: std::cell::Cell::new(0),
            rej_shard: std::cell::Cell::new(0),
            rej_basefee: std::cell::Cell::new(0),
            rej_sponsor: std::cell::Cell::new(0),
        }
    }
}

/// Height-driven governance finalization on the live path (neural audit
/// 2026-11-04 C-02, P0: `gov_finalize` was never called on the live path, so
/// voter/proposer staking locks were held forever).
///
/// After each decided block, finalizes every still-Open proposal whose voting
/// window closed (block time is `now`) via `finalize_at_height` at the decided
/// height: Passed proposals get their `GOV_TIMELOCK_HEIGHTS` (7200) maturity
/// scheduled, and every terminal transition releases its staking locks.
/// Inputs are pure block content (`height`, `timestamp`) plus the committed
/// pre-state, swept in proposal-id order, so every node finalizing the same
/// block derives the same transition and the same root — the mutation is a
/// deterministic function of the block, not an off-block RPC write (C-01
/// direction). Returns the finalized ids (logging/tests).
///
/// Lock order is governance-then-staking, matching the RPC handlers, so no
/// lock cycle is introduced. // GATE: C-02 live-path wiring.
async fn sweep_gov_finalize(
    state: &crate::state_engine::InMemoryStateEngine,
    cur_height: u64,
    now: u64,
) -> Vec<u64> {
    let due: Vec<u64> = {
        let g = state.governance_read().await;
        let mut ids: Vec<u64> = g
            .proposals
            .iter()
            .filter(|(_, p)| {
                p.status == crate::governance::ProposalStatus::Open && now >= p.voting_end
            })
            .map(|(id, _)| *id)
            .collect();
        ids.sort_unstable();
        ids
    };
    if due.is_empty() {
        return Vec::new();
    }
    let mut g = state.governance_write().await;
    let mut ledger = state.staking_write().await;
    let mut done = Vec::with_capacity(due.len());
    for pid in due {
        match g.finalize_at_height(&mut ledger, pid, now, cur_height) {
            Ok(_) => done.push(pid),
            Err(_) => {
                // Unreachable with the filter above (same `now`, and no other
                // finalizer exists on this path); skip fail-safe so one id can
                // never wedge the height — the next height retries with the
                // same deterministic inputs.
            }
        }
    }
    if !done.is_empty() {
        tracing::info!(
            "[gov] finalized {} proposal(s) at height {cur_height}: {done:?}",
            done.len()
        );
    }
    done
}

impl ValidatorRuntime {
    pub fn new(
        key: SigningKey,
        validators: ValidatorSet,
        state: Arc<InMemoryStateEngine>,
        start_height: Height,
    ) -> Self {
        let id = key.verifying_key().to_bytes();
        let hc = HeightConsensus::new(start_height, validators.clone());
        // The ledger is shared with the state engine, never copied out of it.
        let staking = state.staking_handle();
        // Same for the session-key registry (phase 2): the default pool gets
        // the engine's lock so admission can see revocations. A pool swapped in
        // via `with_mempool` carries its own handle (the node wires both).
        //
        // The DEFAULT pool has NO admission floor of its own: it is the
        // library default (`Mempool::default()`, floor 0) and the NODE always
        // injects its own floored pool through `with_mempool` (main.rs), so
        // the production pool carries the frozen `FROZEN_MIN_GAS_FLOOR`
        // floor. A runtime built WITHOUT an injected pool would accept
        // zero-fee transactions - that is a deployment hazard, not a code
        // path, and it is called out in the operations notes.
        let mempool = Arc::new(tokio::sync::RwLock::new(
            Mempool::default().with_session_registry(state.session_keys_handle()),
        ));
        Self {
            key,
            remote_signer: None,
            id,
            validators,
            hc,
            state: state.clone(),
            mempool,
            tx_gossip: None,
            blocks: HashMap::new(),
            demanded: HashSet::new(),
            demanded_height: start_height,
            peer_hint: None,
            last_followed_round: None,
            finalized: Vec::new(),
            applied_txs: 0,
            applied_statuses: Vec::new(),
            applied_fees: Vec::new(),
            applied_events: Vec::new(),
            staking,
            master_staking: None,
            governance: None,
            block_reward: 0,
            last_decision: None,
            shard_id: MASTERCHAIN_SHARD,
            shard_registry: ShardRegistry::single(),
            cross_shard: None,
            finalized_headers: None,
            consumed_cross_shard: HashSet::new(),
            produced_cross_shard: HashMap::new(),
            completed_cross_shard: HashSet::new(),
            xpc_activation: crate::xshard2pc::XpcActivation::Disabled,
            xpc_records: HashMap::new(),
            apply_lane: None,
            apply_in_flight: None,
            snapshot_in_flight: None,
            parallel_exec: state.is_parallel_exec_enabled(),
            validator_set_stale: false,
            validator_set_stale_reason: None,
            validator_set_state_height: None,
            validator_set_ledger_height: None,
            validator_reentry_warns_total: 0,
            reentry_watch: HashMap::new(),
            falcon_key: None,
            pending_validators: None,
            validator_set_history: std::collections::VecDeque::new(),
            slow_validation_total: 0,
            validation_last_stages: Vec::new(),
            pack_snapshot: std::sync::Mutex::new(None),
            actor_backlog_cache: std::sync::Mutex::new(None),
            order_root_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
            batch_verify_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
            proposer_sig_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
            qc_power_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
            prebuilt_selection: std::sync::Mutex::new(None),
            last_progress_at: std::time::Instant::now(),
            last_breaker_at: None,
            // The fork-choice tree starts EMPTY: the node learns its
            // finalized head from the consensus layer, and the first block
            // it finalizes becomes the root of the tree.
            chain: crate::chain::ChainManager::detached(),
            invalidation_sink: None,
            // The node's LIGHT CLIENT (audit W8.3 / blocker A10): the trusted
            // anchor every peer-supplied block is checked against. `None`
            // until the node knows its genesis root (see
            // `with_light_client`); from then on it is the quorum-certified
            // chain this node has finalized.
            light: None,
        }
    }

    /// Attach the node's LIGHT CLIENT, anchored at the chain's GENESIS.
    ///
    /// The genesis state root is the one this node built its own genesis
    /// from, so it is trusted BY CONSTRUCTION; every block above it must
    /// carry a quorum certificate, and every peer-supplied block is checked
    /// against this anchor before it is applied (see
    /// `crate::sync::verify_synced_blocks_against_anchor`).
    pub fn set_light_client(
        &mut self,
        validators: ValidatorSet,
        genesis_root: [u8; 32],
    ) -> Result<(), String> {
        self.light = Some(crate::light_client::LightClient::with_genesis_anchor(
            validators,
            crate::sync::genesis_light_anchor(genesis_root),
        )?);
        Ok(())
    }

    /// The node's light client, if it has one.
    pub fn light_client(&self) -> Option<&crate::light_client::LightClient> {
        self.light.as_ref()
    }

    /// Configure a Falcon-512 keypair for post-quantum consensus voting and proposal signing.
    pub fn with_falcon_key(mut self, key: FalconKeypair) -> Self {
        crate::consensus::register_validator_pq_key(
            self.id,
            crate::post_quantum::PqScheme::Falcon512,
            key.public_key.clone(),
        );
        let falcon_id = key.validator_id();
        if falcon_id != self.id {
            crate::consensus::register_validator_pq_key(
                falcon_id,
                crate::post_quantum::PqScheme::Falcon512,
                key.public_key.clone(),
            );
        }
        self.falcon_key = Some(key);
        self
    }

    /// Falcon keypair to sign a proposal or vote with, or `None` when signing
    /// must be REFUSED.
    ///
    /// Under Pure PQ a missing keypair is a hard stop, never a derivation
    /// fallback. The old fallback did
    /// `FalconKeypair::generate_from_seed(self.id[0])`, i.e. derived a PRIVATE
    /// key from a single byte of the PUBLIC validator id: 256 candidate
    /// keypairs total, so anyone who reads the validator's id out of
    /// `node.yaml` could reproduce its private key and forge its proposals and
    /// votes. That is exactly the failure `main.rs` warns about on the real key
    /// path ("deriving a PRIVATE key deterministically from a PUBLIC validator
    /// id would let anyone forge any validator's votes").
    ///
    /// Production always installs a persisted key via
    /// [`ValidatorRuntime::with_falcon_key`] before consensus starts, so this
    /// only fires for a misconfigured runtime - where not signing is the safe
    /// outcome: the set refuses to accept a vote it cannot attribute.
    fn falcon_signing_key(&self) -> Option<&FalconKeypair> {
        if let Some(k) = &self.falcon_key {
            return Some(k);
        }
        if crate::post_quantum::is_pure_pq_enforced() {
            tracing::error!(
                "[post-quantum] Pure PQ requires a persisted Falcon-512 keypair and this \
                 validator has none; refusing to sign proposals/votes (a derived key would \
                 be forgeable from the public validator id)"
            );
        }
        None
    }

    /// Run this runtime as a specific shard of a multi-shard process.
    ///
    /// With the default registry (`is_sharded() == false`) this only sets the
    /// block's `shard_id`; the shard-aware proposal checks and the mempool
    /// target filter stay off, so single-shard behaviour is unchanged.
    pub fn with_shard(mut self, shard_id: ShardId, registry: ShardRegistry) -> Self {
        self.shard_id = shard_id;
        // A genuine multi-shard process turns on cross-shard execution on the
        // engine. A single-shard registry leaves it off, so the historical
        // "always credit `to`" semantics (and every pre-sharding test) hold.
        if registry.is_sharded() {
            self.state.enable_cross_shard();
        }
        self.shard_registry = registry;
        self
    }

    /// Share the MASTERCHAIN's staking ledger with this runtime.
    ///
    /// The masterchain runtime passes its OWN ledger handle (its state
    /// engine's — the registry it commits), and every workchain runtime of
    /// the same process passes THE SAME handle. From then on a rotation on
    /// the masterchain (bond / unbond / slash) is visible to the workchain's
    /// consensus, which adopts the new [`ValidatorSet`] at its next height
    /// boundary — no restart, no second registry.
    ///
    /// The handle is an ALIAS, never a copy: two copies could disagree about
    /// who the validators are, and the validator set decides who proposes.
    pub fn with_master_staking(mut self, master: MasterStakingLedger) -> Self {
        self.master_staking = Some(master);
        self
    }

    /// Attach the node-local cross-shard transport (shared with the process's
    /// other shard runtimes). Without one, a sharded runtime produces and
    /// consumes no cross-shard messages.
    pub fn with_cross_shard(mut self, transport: Arc<crate::network::CrossShardTransport>) -> Self {
        self.cross_shard = Some(transport);
        self
    }

    /// Attach the process-shared finalized-header registry (C1 anchor).
    /// Same `Arc` for every shard runtime and engine in the process.
    pub fn with_finalized_headers(
        mut self,
        registry: Arc<std::sync::RwLock<crate::sharding::FinalizedHeaderRegistry>>,
    ) -> Self {
        self.finalized_headers = Some(registry);
        self
    }

    /// Record a finalized block's header for cross-shard anchoring. Called
    /// on every finalize path (live, adopt, walk); idempotent.
    ///
    /// The FULL header is recorded (height, block hash, state root,
    /// timestamp), not just the root: the masterchain reads the registry to
    /// publish the shard-head commitments (TON `shard_hashes`), and a
    /// commitment is only verifiable when it names the shard block it
    /// commits to.
    ///
    /// The ANCHOR map gets a second entry: the state root the shard reached
    /// AFTER applying this block. A cross-shard message carries the root its
    /// inclusion proof was made against, and it names the PARENT block - so
    /// the anchor it is checked against is the parent's POST-APPLY root. The
    /// block's own DECLARED root is its parent's pre-state, which is a
    /// different value; anchoring against it made every transfer produced
    /// after a state-changing block unverifiable at the target (the transfer
    /// was silently never consumed).
    pub async fn note_finalized_header(&self, block: &Block) {
        // The post-apply root: the state this shard is in NOW that the block
        // has been applied. Read BEFORE the lock (the lock guard is not
        // `Send`, so it may not be held across an await) and AFTER the apply
        // (this runs on the finalize path), so it is exactly the root the
        // next block will be built on - the root a cross-shard message
        // produced by the next block carries.
        let post_apply_root = self.state.get_state_root().await;
        if let Some(reg) = self.finalized_headers.as_ref() {
            if let Ok(mut r) = reg.write() {
                let block_hash = block.compute_hash();
                r.note_finalized_commitment(crate::sharding::ShardHeaderCommitment {
                    shard_id: block.shard_id,
                    height: block.height,
                    block_hash,
                    state_root: block.state_root,
                    timestamp: block.timestamp,
                });
                r.note_finalized_anchor(block.shard_id, block_hash, post_apply_root);
            }
        }
    }

    /// Keep the node's LIGHT CLIENT in step with the chain it finalizes.
    ///
    /// The light client is the node's TRUSTED ANCHOR: a peer chain is
    /// accepted only if it extends the quorum-certified chain this node
    /// finalized (see `crate::sync::verify_synced_blocks_against_anchor`),
    /// and the roots this node will answer proofs against are the ones a
    /// quorum committed to.
    ///
    /// Called on every finalize path (live, adopt, walk), right after the
    /// header was recorded. A block with no precommit quorum certificate is
    /// not DECIDED, so it is not an anchor and is ignored here.
    ///
    /// Three steps, in order, so a re-anchored chain (a rotation, a re-apply)
    /// can never leave the light client pointing at a chain the node has left:
    ///  1. accept the header on top of the current tip;
    ///  2. otherwise re-anchor on this finalized head (the window is full, or
    ///     the chain moved);
    ///  3. otherwise rebuild the client anchored at this finalized head.
    pub fn note_light_anchor(&mut self, block: &Block) {
        if self.light.is_none() {
            return;
        }
        let Some(header) = crate::light_client::LightHeader::of_block(block) else {
            // No quorum certificate: nothing decided, nothing to anchor on.
            return;
        };
        // The validator set rotates with the chain, and a certificate is
        // checked under the set that was in force at ITS height. The node's
        // current set is that set (the same simplification `validate_sync_chain`
        // makes — see its F5 note).
        if let Some(light) = self.light.as_mut() {
            light.validators = self.validators.clone();
            if light.apply_header(header.clone()).is_ok() {
                return;
            }
        }
        let cp = header.checkpoint();
        let rebuilt = match self.light.as_mut() {
            Some(light) => light.advance_to_checkpoint(cp.clone()).is_ok(),
            None => false,
        };
        if rebuilt {
            return;
        }
        // Last resort: rebuild the client anchored at this finalized head.
        // The chain BELOW the anchor was verified when this node finalized it,
        // and the anchor itself is quorum-certified, so the light client is
        // sound from here on.
        match crate::light_client::LightClient::new(self.validators.clone(), cp) {
            Ok(fresh) => {
                tracing::warn!(
                    "[light-client] rebuilt the anchor at height {} (the previous anchor was inconsistent)",
                    block.height
                );
                self.light = Some(fresh);
            }
            Err(e) => {
                tracing::error!(
                    "[light-client] could not anchor at height {}: {e}",
                    block.height
                );
            }
        }
    }

    /// Re-anchor the light client at a snapshot-sync boundary.
    ///
    /// `try_snapshot_sync` (main.rs) jumps the finalized head and the
    /// consensus height to a QC-verified boundary, but the light client
    /// stays anchored at genesis and expects block 1 next — so the
    /// subsequent body walk refuses every tail block ("leaves a gap;
    /// expected 1") and a node that jumped can never close its final gap
    /// (live 2026-10-25: B/D parked at 296000/297000, walk refused
    /// forever). This re-anchors the client AT the verified boundary using
    /// the boundary block's own precommit QC, verified against the set in
    /// force AT the boundary height (never the live set).
    ///
    /// Fail-closed on every mismatch (no light client, no QC on the block,
    /// height/hash/linkage mismatch, QC failure): the old anchor — and
    /// today's walk refusal — is left untouched, loudly.
    pub fn reanchor_light_client_at_snapshot(&mut self, boundary: u64, block: &Block) {
        if self.light.is_none() {
            return;
        }
        let vs = self.validator_set_for_height(boundary);
        let Some(header) = crate::light_client::LightHeader::of_block(block) else {
            tracing::error!(
                boundary,
                "REFUSING light-client re-anchor: boundary block carries no precommit QC"
            );
            eprintln!(
                "[light-client] REFUSING re-anchor at height {boundary}: boundary block carries no precommit QC"
            );
            return;
        };
        if header.height != boundary || header.block_hash != block.compute_hash() {
            tracing::error!(
                boundary,
                "REFUSING light-client re-anchor: boundary block height/hash mismatch"
            );
            eprintln!(
                "[light-client] REFUSING re-anchor at height {boundary}: boundary block height/hash mismatch"
            );
            return;
        }
        let expected_prev = self.finalized.last().map(|(_, h)| *h).unwrap_or([0u8; 32]);
        if header.block_hash != expected_prev {
            tracing::error!(
                boundary,
                "REFUSING light-client re-anchor: boundary block does not extend our finalized head"
            );
            eprintln!(
                "[light-client] REFUSING re-anchor at height {boundary}: boundary block does not extend our finalized head"
            );
            return;
        }
        if let Some(light) = self.light.as_mut() {
            light.validators = vs.clone();
            if light.apply_header(header.clone()).is_ok() {
                return;
            }
        }
        let cp = header.checkpoint();
        if let Some(light) = self.light.as_mut() {
            if light.advance_to_checkpoint(cp.clone()).is_ok() {
                tracing::warn!(
                    "[light-client] advanced the anchor to snapshot boundary {boundary}"
                );
                return;
            }
        }
        match crate::light_client::LightClient::new(vs, cp) {
            Ok(fresh) => {
                tracing::warn!("[light-client] rebuilt the anchor at snapshot boundary {boundary}");
                self.light = Some(fresh);
            }
            Err(e) => {
                tracing::error!(
                    boundary,
                    "REFUSING light-client re-anchor: could not anchor at snapshot boundary: {e}"
                );
                eprintln!(
                    "[light-client] REFUSING re-anchor at height {boundary}: could not anchor at snapshot boundary: {e}"
                );
            }
        }
    }

    /// The shard-head commitments a block of THIS shard publishes.
    ///
    /// Only a MASTERCHAIN block publishes shard heads, and only for the
    /// WORKCHAIN shards (id >= 1) — a block never commits to its own head.
    /// The set comes from the process-shared finalized-header registry, so it
    /// holds exactly the shards this process has finalized a header for, in
    /// ascending shard order (canonical — the set is hashed as a sequence,
    /// so a fixed order is what keeps the block hash deterministic).
    ///
    /// A missing or contended registry yields an EMPTY set: the block still
    /// proposes, it just commits to no shard head this round (the next block
    /// picks them up). That keeps a lock contention from stalling the
    /// masterchain.
    fn collect_shard_header_commitments(&self) -> Vec<crate::sharding::ShardHeaderCommitment> {
        if self.shard_id != MASTERCHAIN_SHARD {
            return Vec::new();
        }
        let Some(reg) = self.finalized_headers.as_ref() else {
            return Vec::new();
        };
        let Ok(guard) = reg.read() else {
            return Vec::new();
        };
        let mut out = guard.workchain_headers();
        // Canonical order (ascending shard id), stated explicitly so the
        // block hash never depends on the registry's internal iteration.
        out.sort_by_key(|h| h.shard_id);
        out
    }

    /// The epoch-MMR root this proposal commits to (V5 Tier-2), if any.
    ///
    /// Only the first masterchain block of an epoch commits (height H with
    /// `H > 0` and `H % 128 == 0`, committing epoch `H / 128 - 1`), and only
    /// when this node finalized all 128 heights of that epoch. Otherwise —
    /// workchain, non-boundary height, pruned history, fresh restart — the
    /// block carries the all-zero root and hashes exactly like a legacy
    /// block. A proposer commits to a root it derived from its own
    /// finalized chain, never to a root it cannot prove.
    fn epoch_mmr_commitment(&self) -> [u8; 32] {
        if self.shard_id != MASTERCHAIN_SHARD {
            return [0u8; 32];
        }
        let Some(epoch) = crate::mmr::commits_epoch_root(self.hc.height) else {
            return [0u8; 32];
        };
        self.chain
            .epoch_mmr_root(epoch)
            .map(|(root, _)| root)
            .unwrap_or([0u8; 32])
    }

    /// Check the epoch-MMR commitment of a proposal (V5 Tier-2).
    ///
    /// * a zero root is ALWAYS accepted: it means "not committed" (a
    ///   pre-MMR block, a non-boundary height, or a proposer that did not
    ///   know the epoch's bodies). Requiring a root would fork proposers
    ///   that pruned history from the ones that did not;
    /// * a non-zero root is accepted ONLY on a masterchain block at an
    ///   epoch-committing boundary height (the first height of an epoch,
    ///   committing the previous one — see `crate::mmr::commits_epoch_root`);
    /// * a non-zero root must not CONTRADICT this process's own finalized
    ///   chain: if we finalized all 128 heights of the committed epoch and
    ///   derive a different root, the proposal is refused. A node that has
    ///   not finalized the epoch yet has nothing to contradict, so it
    ///   accepts — the quorum that signs the block is the backstop.
    fn check_epoch_mmr_commitment(&self, block: &Block) -> Result<(), String> {
        if block.mmr_epoch_root == [0u8; 32] {
            return Ok(());
        }
        if block.shard_id != MASTERCHAIN_SHARD {
            return Err(
                "proposal: epoch MMR root published by a non-masterchain block".to_string(),
            );
        }
        let Some(epoch) = crate::mmr::commits_epoch_root(block.height) else {
            return Err("proposal: epoch MMR root on a non-boundary height".to_string());
        };
        if let Some((mine, _)) = self.chain.epoch_mmr_root(epoch) {
            if mine != block.mmr_epoch_root {
                return Err(format!(
                    "proposal: epoch {epoch} MMR root contradicts the finalized chain"
                ));
            }
        }
        Ok(())
    }

    /// Check the shard-head commitments of a proposal (TON `shard_hashes`).
    ///
    /// * only a masterchain block may publish shard heads;
    /// * the set must be CANONICAL: strictly ascending shard ids, no
    ///   duplicates, and never an entry for the masterchain itself (a block
    ///   cannot commit to its own head);
    /// * the set must not CONTRADICT this process's own finalized headers: if
    ///   we finalized shard S at height H with hash X, a proposal committing
    ///   shard S at height H with a different hash or root is refused (that
    ///   is a shard-chain equivocation dressed up as a commitment).
    ///
    /// A node that has NOT finalized that shard yet (or is behind) has
    /// nothing to contradict, so the proposal is accepted — the commitment is
    /// still checked by the quorum that signs the block.
    fn check_shard_header_commitments(&self, block: &Block) -> Result<(), String> {
        if block.shard_headers.is_empty() {
            return Ok(());
        }
        if block.shard_id != MASTERCHAIN_SHARD {
            return Err("proposal: shard heads published by a non-masterchain block".to_string());
        }
        if !block.shard_headers_canonical() {
            return Err("proposal: shard head set is not canonical".to_string());
        }
        if let Some(reg) = self.finalized_headers.as_ref().and_then(|r| r.read().ok()) {
            for h in &block.shard_headers {
                let Some(mine) = reg.latest_header(h.shard_id) else {
                    continue;
                };
                if mine.height == h.height
                    && (mine.block_hash != h.block_hash || mine.state_root != h.state_root)
                {
                    return Err(format!(
                        "proposal: shard {} head at height {} contradicts the finalized header",
                        h.shard_id, h.height
                    ));
                }
            }
        }
        Ok(())
    }

    /// Anchored inclusion check for one inbound message (C1): proof AND a
    /// locally-finalized source header with the claimed root. `false` covers
    /// both "forged" and "not finalized here yet" — callers treat it as
    /// not-ready (skip/refuse + retry after catching up), never as verified.
    pub fn verify_cross_shard_anchored(&self, msg: &CrossShardMessage) -> bool {
        let guard = self.finalized_headers.as_ref().and_then(|r| r.read().ok());
        let Some(reg) = guard.as_deref() else {
            return false;
        };
        msg.verify_anchored(Some(reg))
    }

    /// The §9 2PC admission rule for an OUTBOUND 2PC record.
    ///
    /// The outbound 2PC records (the target's vote, the source's decision,
    /// the abort request) are DERIVED from this shard's committed 2PC state,
    /// not from a transaction in the block. A validator therefore re-derives
    /// the same rule the proposer used:
    ///
    ///  * this shard holds the 2PC record of the transfer, in the phase the
    ///    record's kind implies (the target's vote only while PREPARED, the
    ///    source's decision only once COMMITTED, the abort request only
    ///    while PREPARED and past the prepare window);
    ///  * the record carries a valid Merkle proof of THAT state, against the
    ///    block's own state root, anchored to a finalized header of this
    ///    shard - so the peer can verify the vote;
    ///  * the direction matches the record (the target answers the source and
    ///    the other way round).
    ///
    /// A proposer that invents a vote the shard never made is refused.
    pub fn xpc_outbound_admissible(&self, msg: &CrossShardMessage, block: &Block) -> bool {
        use crate::sharding::CrossShardKind;
        use crate::xshard2pc::XpcPhase;
        let tx_hash = msg.tx.compute_tx_hash();
        // The OPENING record (the PREPARE) is the one 2PC record that is NOT
        // derived from an already-committed 2PC state: the source's PREPARED
        // record is created by the APPLICATION of this very block, so at
        // validation time it does not exist yet. It comes in TWO forms, and
        // both are admissible:
        //
        //   (a) the OPENING PREPARE: the TRANSACTION is in this block (so the
        //       debit that escrows the value happens in the same block that
        //       publishes the PREPARE), and the record proves the SENDER's
        //       leaf against the block's own state root (so the target can
        //       check that the sender really had the funds at the source's
        //       committed root);
        //
        //   (b) the RE-PUBLISHED PREPARE: the transaction is NOT in this
        //       block (it was escrowed by an earlier one), but this shard
        //       holds the transfer's PREPARED record and the record proves
        //       that leaf against the block's own state root. The PREPARED
        //       leaf IS the escrow, so the proof is strictly stronger than
        //       the account leaf: it says "the value is already escrowed
        //       here".
        //
        // A proposer that publishes a PREPARE for a transaction it is not
        // including and without holding the PREPARED record, or without the
        // matching proof, is refused.
        if msg.kind() == CrossShardKind::Prepare {
            let tx_present = block.transactions.iter().any(|t| {
                t.compute_tx_hash() == tx_hash
                    && crate::sharding::tx_is_outbound_cross_shard(t, self.shard_id)
            });
            if tx_present {
                if msg.source_state_root != block.state_root {
                    return false;
                }
                return msg.verify_inclusion_strict();
            }
            // Form (b): the re-published PREPARE.
            let Some(rec) = self.xpc_records.get(&tx_hash) else {
                return false;
            };
            if rec.source_shard != self.shard_id {
                return false;
            }
            if rec.phase != XpcPhase::Prepared {
                return false;
            }
            if !crate::xshard2pc::should_reprepare(rec, block.height) {
                return false;
            }
            if msg.source_state_root != block.state_root {
                return false;
            }
            return msg.verify_xpc_anchored(
                self.finalized_headers
                    .as_ref()
                    .and_then(|r| r.read().ok())
                    .as_deref(),
                &[XpcPhase::Prepared],
            );
        }
        let Some(rec) = self.xpc_records.get(&tx_hash) else {
            return false;
        };
        let (side_is_target, phase) = match msg.kind() {
            CrossShardKind::PrepareAck => (true, XpcPhase::Prepared),
            CrossShardKind::AbortAck => (true, XpcPhase::Aborted),
            CrossShardKind::Commit => (false, XpcPhase::Committed),
            CrossShardKind::AbortRequest => (false, XpcPhase::Prepared),
            _ => return false,
        };
        if side_is_target {
            if rec.target_shard != self.shard_id {
                return false;
            }
        } else if rec.source_shard != self.shard_id {
            return false;
        }
        if rec.phase != phase {
            return false;
        }
        // The abort request is only admissible once the prepare window
        // elapsed (the same rule the proposer used).
        if msg.kind() == CrossShardKind::AbortRequest
            && !matches!(
                crate::xshard2pc::source_action(rec, block.height),
                crate::xshard2pc::SourceAction::AbortRequest
            )
        {
            return false;
        }
        // The record must prove the state it claims, against the block's own
        // state root, and be anchored to a finalized header of this shard.
        if msg.source_state_root != block.state_root {
            return false;
        }
        msg.verify_xpc_anchored(
            self.finalized_headers
                .as_ref()
                .and_then(|r| r.read().ok())
                .as_deref(),
            &[phase],
        )
    }

    /// §5 M3: linkage rule for ack/bounce control records, checked at a given
    /// chain height (the proposed block's height at propose/validate time, the
    /// applied block's height at apply time).
    ///
    /// A control record is valid iff ALL hold:
    ///  * it carries NO Merkle proof and is NOT locally trusted. The engine
    ///    credits any proof-carrying inbound to `tx.to`, so a proof-carrying
    ///    reversed-direction record would mint on the source shard; refusing
    ///    it here (and skipping proof-less records in the engine) is what
    ///    makes the refund path safe without a state-engine change;
    ///  * its transaction's outbound transfer was committed on THIS chain
    ///    (`produced_cross_shard`, rebuilt from applied blocks);
    ///  * the transaction has not already completed (no ack/bounce committed);
    ///  * for a bounce, the height timeout has elapsed
    ///    (`bounce_eligible(produce_height, at_height)` — heights, not seconds).
    ///
    /// Unknown kinds fail closed (false).
    fn control_linkage_ok(&self, msg: &CrossShardMessage, at_height: u64) -> bool {
        if !msg.is_ack() && !msg.is_bounce() {
            return false;
        }
        if msg.merkle_inclusion_proof.is_some() || msg.trusted {
            return false;
        }
        let tx_hash = msg.tx.compute_tx_hash();
        if self.completed_cross_shard.contains(&tx_hash) {
            return false;
        }
        let Some((_, produce_height)) = self.produced_cross_shard.get(&tx_hash) else {
            return false;
        };
        if msg.is_bounce() {
            return crate::sharding::bounce_eligible(*produce_height, at_height);
        }
        true
    }

    // ==================== §9 CROSS-SHARD 2PC ====================

    /// Set the §9 two-phase-commit activation switch.
    ///
    /// `FromHeight(h)` makes every transfer PRODUCED at height `h` or later
    /// run the 2PC; transfers produced before `h` keep running the legacy
    /// outbox/inbox/ack/bounce flow. The switch is node configuration (like
    /// the shard registry), but the HEIGHT it names is consensus-visible: it
    /// decides which flow a transfer takes, so every node of a shard must
    /// agree on it.
    pub fn with_xpc_activation(mut self, activation: crate::xshard2pc::XpcActivation) -> Self {
        self.xpc_activation = activation;
        self
    }

    /// The §9 2PC activation switch in force on this shard.
    pub fn xpc_activation(&self) -> crate::xshard2pc::XpcActivation {
        self.xpc_activation
    }

    /// True when this shard holds a §9 2PC record for the transfer.
    pub async fn xpc_owns(&self, tx_hash: &[u8; 32]) -> bool {
        self.state.xpc_record(tx_hash).await.is_some()
    }

    /// The §9 2PC admission rule for an INBOUND 2PC record.
    ///
    /// Every 2PC record carries a Merkle proof of the PEER's committed 2PC
    /// state, and that proof must check out against a state root a LOCALLY
    /// FINALIZED header of the peer shard committed to (the C1 anchor). A
    /// record that fails either test is refused, so a malicious peer cannot
    /// make this shard credit a recipient (a COMMIT) or authorise a refund
    /// (an ABORT-ACK) out of thin air.
    ///
    /// The proof is checked against the phases that are legitimate for the
    /// record's kind:
    ///  * PREPARE: EITHER the source's ACCOUNT leaf (the opening PREPARE -
    ///    the same proof the legacy transfer carries - it proves the sender
    ///    had the funds) OR the source's PREPARED leaf (the re-published
    ///    PREPARE - it proves the value is already escrowed at the source);
    ///  * PREPARE-ACK: the target's PREPARED leaf (its vote);
    ///  * COMMIT: the source's PREPARED or COMMITTED leaf (the source really
    ///    escrowed the value);
    ///  * ABORT-REQUEST: the source's PREPARED or COMMITTED leaf;
    ///  * ABORT-ACK: the target's ABORTED leaf (its authorisation - and the
    ///    target can only hold that leaf if it NEVER prepared).
    pub fn xpc_admissible(&self, msg: &CrossShardMessage) -> bool {
        use crate::sharding::CrossShardKind;
        use crate::xshard2pc::XpcPhase;
        let guard = self.finalized_headers.as_ref().and_then(|r| r.read().ok());
        let Some(reg) = guard.as_deref() else {
            // No anchor registry: fail closed (the C1 rule).
            return false;
        };
        match msg.kind() {
            CrossShardKind::Prepare => {
                // The opening PREPARE (the sender's account leaf) or the
                // re-published one (the source's PREPARED leaf). Both are
                // anchored to a finalized header of the source shard.
                msg.verify_anchored(Some(reg))
                    || msg.verify_xpc_anchored(Some(reg), &[XpcPhase::Prepared])
            }
            CrossShardKind::PrepareAck => msg.verify_xpc_anchored(Some(reg), &[XpcPhase::Prepared]),
            CrossShardKind::Commit | CrossShardKind::AbortRequest => {
                msg.verify_xpc_anchored(Some(reg), &[XpcPhase::Prepared, XpcPhase::Committed])
            }
            CrossShardKind::AbortAck => msg.verify_xpc_anchored(Some(reg), &[XpcPhase::Aborted]),
            _ => false,
        }
    }

    /// Producing height of a committed outbound transfer on this chain, if any
    /// (§5 M3; test/debug introspection over `produced_cross_shard`).
    pub fn produced_cross_shard_height(&self, tx_hash: &[u8; 32]) -> Option<u64> {
        self.produced_cross_shard.get(tx_hash).map(|(_, h)| *h)
    }

    /// True once an ack or bounce for `tx_hash` committed on this chain (§5 M3).
    pub fn is_transfer_completed(&self, tx_hash: &[u8; 32]) -> bool {
        self.completed_cross_shard.contains(tx_hash)
    }

    /// Snapshot the whole cross-shard replay state for persistence (audit
    /// F-I): the engine credit gate plus the three runtime mirrors, sorted
    /// for deterministic bytes. Called where the runtime is alive (periodic
    /// snapshot block); a fresh runtime snapshots empty sets, which is correct
    /// (nothing committed yet to protect).
    pub async fn cross_shard_replay_snapshot(&self) -> crate::sharding::CrossShardReplaySnapshot {
        let mut engine_consumed = self.state.cross_shard_consumed_snapshot().await;
        engine_consumed.sort();
        let mut runtime_consumed: Vec<crate::sharding::CrossShardKey> =
            self.consumed_cross_shard.iter().copied().collect();
        runtime_consumed.sort();
        let mut produced: Vec<([u8; 32], Transaction, u64)> = self
            .produced_cross_shard
            .iter()
            .map(|(h, (tx, height))| (*h, tx.clone(), *height))
            .collect();
        produced.sort_by_key(|(h, _, _)| *h);
        let mut completed: Vec<[u8; 32]> = self.completed_cross_shard.iter().copied().collect();
        completed.sort();
        // §9 2PC: the committed two-phase-commit records travel with the
        // replay state, so a node that restarts mid-2PC resumes to the SAME
        // decision instead of re-opening the lifecycle.
        let xpc = self.state.xpc_snapshot().await;
        crate::sharding::CrossShardReplaySnapshot {
            engine_consumed,
            runtime_consumed,
            produced,
            completed,
            xpc,
        }
    }

    /// Install persisted replay state (startup restore). Extends (never
    /// replaces: live sets may already hold entries committed after the
    /// snapshot was taken). The engine half travels separately through the
    /// load paths (`restore_cross_shard_consumed`); calling both with the
    /// same blob is idempotent.
    pub fn restore_cross_shard_sets(&mut self, snap: &crate::sharding::CrossShardReplaySnapshot) {
        self.consumed_cross_shard
            .extend(snap.runtime_consumed.iter().copied());
        for (h, tx, height) in &snap.produced {
            self.produced_cross_shard.insert(*h, (tx.clone(), *height));
        }
        self.completed_cross_shard
            .extend(snap.completed.iter().copied());
        // §9 2PC: the mirror of the committed 2PC records.
        for rec in &snap.xpc {
            self.xpc_records
                .entry(rec.tx_hash)
                .or_insert_with(|| rec.clone());
        }
    }

    /// Seed the staking ledger (tests / genesis). The ledger lives in the state
    /// engine, so this writes there; there is deliberately no second copy on the
    /// runtime, because a second copy is a second opinion about who the
    /// validators are - and the validator set decides who proposes.
    pub fn with_staking(self, _ledger: crate::staking::StakingLedger) -> Self {
        // The ledger now lives in the state engine; this setter is kept so
        // existing call sites keep compiling, and seeds the engine if it can take
        // the lock synchronously.
        if let Some(mut guard) = self.state.try_staking_write() {
            *guard = _ledger;
        }
        self
    }

    /// Attach a governance engine (on-chain parameter control).
    pub fn with_governance(mut self, g: crate::governance::Governance) -> Self {
        self.governance = Some(g);
        self
    }

    /// Set the per-block proposer reward (nano-STELL). Requires a staking ledger
    /// to have any effect.
    /// Attach the transaction-gossip handle used to publish the epoch-seal
    /// frames (the DKG contribution, the order commitment, the share
    /// release). Without it the epoch-seal protocol runs node-locally and
    /// the plain path is unaffected.
    pub fn with_tx_gossip(mut self, gossip: Arc<crate::consensus_net::TxGossip>) -> Self {
        self.tx_gossip = Some(gossip);
        self
    }

    /// Use a mempool that is shared with the RPC layer, so a transaction
    /// submitted over RPC is the very same one the proposer selects.
    pub fn with_mempool(mut self, mempool: Arc<tokio::sync::RwLock<Mempool>>) -> Self {
        self.mempool = mempool;
        self
    }

    pub fn with_block_reward(mut self, reward: u64) -> Self {
        self.block_reward = reward;
        self
    }

    /// Configure disjoint wave parallel block execution for this runtime.
    pub fn with_parallel_exec(mut self, enabled: bool) -> Self {
        self.parallel_exec = enabled;
        self.state.set_parallel_exec(enabled);
        self
    }

    /// Set parallel block execution flag on this runtime and its state engine.
    pub fn set_parallel_exec(&mut self, enabled: bool) {
        self.parallel_exec = enabled;
        self.state.set_parallel_exec(enabled);
    }

    /// Attach the invalidation sink: the RPC / streaming layer.
    ///
    /// Every block this node invalidates (a branch that lost the
    /// fork-choice, a reorg that rolled a branch back) is published through
    /// this sink, so a client that was told about those blocks learns that
    /// they are not on the chain.
    pub fn with_invalidation_sink(mut self, sink: crate::chain::InvalidationSink) -> Self {
        self.invalidation_sink = Some(sink);
        self
    }

    /// Publish the invalidation signals to the sink.
    ///
    /// With no sink wired the signals are LOGGED, never silently dropped:
    /// a node that forgot to wire the transport must still leave a trace of
    /// the fact that it invalidated blocks.
    ///
    /// A signal without orphaned blocks carries no information (nothing was
    /// retracted) and is never published: the window would fill up with
    /// noise.
    fn publish_invalidations(&self, signals: &[crate::chain::InvalidationSignal]) {
        let signals: Vec<&crate::chain::InvalidationSignal> =
            signals.iter().filter(|s| !s.is_empty()).collect();
        if signals.is_empty() {
            return;
        }
        match &self.invalidation_sink {
            Some(sink) => {
                for s in signals {
                    sink(s.clone());
                }
            }
            None => {
                for s in signals {
                    tracing::warn!(
                        "[chain] invalidated {} block(s) at height {}: {}",
                        s.orphaned_blocks.len(),
                        s.height,
                        s.reason
                    );
                }
            }
        }
    }

    /// Record a VALID candidate block into the fork-choice tree, BEFORE it
    /// is finalized.
    ///
    /// This is what makes a fork observable in a live node. Without it the
    /// node only ever learns the branch it finalized, and the competing one
    /// disappears without a trace — so nobody can ever be told "that block
    /// you saw is not on the chain".
    ///
    /// The block is validated as an extension of a KNOWN block (parent
    /// known, height chained, proposer signature valid), so a forged or
    /// unrelated block can never pollute the tree. Returns true when the
    /// block was recorded.
    pub fn record_candidate_block(&mut self, block: &Block) -> bool {
        if self.chain.is_empty() {
            // The tree has no root yet. A node that joined mid-chain knows a
            // finalized head long before it finalizes anything itself: use
            // it as the root so the candidates that extend it are tracked.
            self.seed_chain_root();
            if self.chain.is_empty() {
                // No root and nothing to build one from: we cannot tell a
                // candidate from noise.
                return false;
            }
        }
        if block.height <= self.chain.finalized_height {
            // A block for an already-finalized height can never be applied.
            // It is invalidated on the spot (the honest answer, not silence).
            let signal = self.chain.invalidate_block(block);
            self.publish_invalidations(std::slice::from_ref(&signal));
            return false;
        }
        match self.chain.insert_candidate(block.clone()) {
            Ok(_) => {
                // The fork-choice's own candidate-window trim may have dropped
                // a branch to make room. That drop is a FORK the world has to
                // hear about: publish the parked signal (audit W6.4b — the
                // trim used to record the invalidation internally and nobody
                // ever published it, so a client following the trimmed branch
                // was never told it lost).
                let pending = self.chain.take_pending_invalidations();
                self.publish_invalidations(&pending);
                true
            }
            Err(e) => {
                tracing::debug!("[chain] candidate not recorded: {e}");
                false
            }
        }
    }

    /// Seed the fork-choice tree with the finalized head this runtime
    /// already knows, so a candidate that extends it can be validated.
    ///
    /// A node that joined mid-chain (or that restored from the store) has a
    /// finalized head long before it finalizes anything itself. Without
    /// this the tree would stay empty and the first competing candidates
    /// would go untracked — the fork would be invisible again.
    fn seed_chain_root(&mut self) {
        if !self.chain.is_empty() {
            return;
        }
        let Some((_, head)) = self.finalized.last().copied() else {
            return;
        };
        let Some(block) = self.blocks.get(&head).cloned() else {
            return;
        };
        let (_h, signals) = self.chain.adopt_root(block);
        self.publish_invalidations(&signals);
    }

    /// Fold a FINALIZED block into the fork-choice tree.
    ///
    /// The block becomes the new finality anchor, and every candidate branch
    /// it superseded is pruned: the orphaned blocks are published as
    /// invalidation signals, so a client that followed the losing branch
    /// learns that it lost.
    pub fn note_finalized_block(&mut self, block: &Block) -> Vec<crate::chain::InvalidationSignal> {
        let hash = block.compute_hash();
        if self.chain.is_empty() {
            // The first block we learn as FINALIZED becomes the root of our
            // tree: a node that joined mid-chain never saw the ancestors.
            let (_h, signals) = self.chain.adopt_root(block.clone());
            self.publish_invalidations(&signals);
            return signals;
        }
        // A block at or below the finalized height is either the block we
        // ALREADY finalized (a duplicate — idempotent, nothing to do) or a
        // CONFLICTING block for a height the chain already decided. The
        // second must NEVER re-root the fork-choice: the state has the
        // decided block applied, so re-rooting would make the canonical view
        // disagree with the applied state — and it would move the finality
        // ANCHOR backwards (the finalized height must never decrease).
        if block.height <= self.chain.finalized_height {
            let already = self.chain.finalized_at_height(block.height) == Some(hash);
            if already {
                // Duplicate finalize of the block we already decided: a
                // no-op, NOT a re-root.
                return Vec::new();
            }
            tracing::error!(
                height = block.height,
                finalized_height = self.chain.finalized_height,
                "refusing to re-root the fork-choice on a block at or below the finalized height"
            );
            return Vec::new();
        }
        self.chain.insert(block.clone());
        if let Err(e) = self.chain.finalize(hash) {
            // The finalized chain moved discontinuously (we never saw the
            // intermediate blocks): re-root on the new block instead of
            // keeping a chain we cannot vouch for.
            tracing::warn!("[chain] finalized block does not extend our chain ({e}); re-rooting");
            let (_h, signals) = self.chain.adopt_root(block.clone());
            self.publish_invalidations(&signals);
            return signals;
        }
        let signals = self.chain.prune_superseded_candidates();
        self.publish_invalidations(&signals);
        // The finalized history below the head is not needed by the
        // fork-choice any more: drop the bodies so a long-running node's
        // memory stays bounded (the hashes stay in the finalized index).
        self.chain.prune_below_finalized();
        signals
    }

    /// Fork-choice over the recorded candidate branches.
    ///
    /// When a LONGER branch appears, the reorg plan from the current
    /// candidate head to the new one is computed and EXECUTED: the head
    /// moves and the losing branch's blocks are invalidated (and published).
    ///
    /// A branch of the SAME length is NOT a reorg: the finalization (the
    /// quorum) decides which of the two is on the chain, so both stay live
    /// candidates until it does, and the loser is invalidated then (by the
    /// prune path). Switching the head between them would publish an
    /// invalidation for a block that may still be finalized — a lie.
    ///
    /// The rolled-back blocks are CANDIDATES — blocks that were validated
    /// but never applied — so the state needs no rollback: it is already
    /// exactly on the finalized chain, and the new branch is not applied
    /// until it is finalized in its own right. A plan that would roll back
    /// an APPLIED block is refused (see the check below): that would be a
    /// state rollback across finality, which BFT forbids.
    pub fn run_fork_choice(&mut self) -> Option<crate::chain::ReorgOutcome> {
        let new_head = self.chain.best_candidate()?;
        let current = self.chain.candidate_head;
        if current == Some(new_head) {
            return None;
        }
        // Only a STRICTLY deeper branch reorgs. A branch of the same
        // length is still alive (the quorum decides), so it must not be
        // invalidated here.
        let current_height = current.map(|h| self.chain.height_of(&h)).unwrap_or(0);
        let new_height = self.chain.height_of(&new_head);
        if new_height <= current_height {
            return None;
        }
        let plan = self.chain.candidate_reorg_plan(&new_head).ok().flatten()?;
        // SAFETY: refuse a reorg that would undo an APPLIED block. In the
        // BFT path the rolled-back blocks are candidates that were never
        // executed, so this never fires; it is the guard that keeps a
        // future non-finalizing path from silently rewinding committed
        // state.
        if plan
            .rollback
            .iter()
            .any(|h| self.finalized.iter().any(|(_, fh)| fh == h))
        {
            tracing::error!("[chain] refusing a reorg that would roll back an applied block");
            return None;
        }
        let signal = self.chain.commit_candidate_reorg(&plan, new_head);
        let invalidations = if signal.is_empty() {
            Vec::new()
        } else {
            vec![signal]
        };
        self.publish_invalidations(&invalidations);
        Some(crate::chain::ReorgOutcome {
            plan,
            invalidations,
        })
    }

    /// Check whether disjoint wave parallel execution is enabled.
    pub fn is_parallel_exec_enabled(&self) -> bool {
        self.parallel_exec || self.state.is_parallel_exec_enabled()
    }

    /// Slash the offenders named by THIS NODE'S local equivocation observations.
    /// Returns the total burned.
    ///
    /// SECURITY / F4: this is deliberately NOT called from any state-transition
    /// path (`try_finalize`, `apply_and_advance`, `replay_historical_block`).
    /// The evidence comes from `self.hc.equivocations()`, i.e. from whichever
    /// conflicting votes this node happened to receive over best-effort gossip.
    /// Two nodes that decide the SAME block by different routes (local finalize
    /// vs adopt vs walk vs replay) therefore observe different evidence, burn
    /// different stake, and commit different state roots — a chain split that a
    /// single Byzantine double-voter triggers at will by choosing gossip
    /// delivery (audit finding F4).
    ///
    /// Equivocation slashing therefore travels inside the block as verifiable
    /// content (approach "carry evidence in the block"): no new `Block` field
    /// was needed — the evidence rides the block BODY as
    /// `OpCode::SysCallReportEquivocation` payloads (appended terminal
    /// variant; old nodes fail closed on the unknown discriminant instead of
    /// misreading the block). Gossip-direct slashing stays DEAD: determinism
    /// is preserved by slashing ONLY from block bytes. Direct callers in
    /// tests exercise the primitive; production code must not call this from
    /// a transition.
    ///
    /// PRODUCT DECISION (audit O1 — gossip-direct equivocation stays
    /// unwired, stated without ambiguity): THIS function (local-observation
    /// slash) must never run in a state transition — double-signing observed
    /// only over gossip is still FREE by design, and only downtime slashing
    /// plus BLOCK-CARRIED equivocation slashing are live. The wired path is
    /// `InMemoryStateEngine::apply_block_transition` (step 5b), which meets
    /// all three preconditions together with fail-closed tests:
    ///   (1) block-carried, signature-verifiable equivocation evidence
    ///       (`SysCallReportEquivocation` payloads, both votes fully
    ///       included, re-verified from block bytes on every node);
    ///   (2) the live call site debits `STAKING_POOL` by `burned` (the
    ///       primitive mutates ledger fields only; without the debit
    ///       pool/ledger drift by `burned` per slash);
    ///   (3) per-offense (`BLAKE3(voter‖height‖round‖kind‖targets)`) dedup
    ///       in the ledger, so one offense slashes exactly once on every
    ///       node. Wire gossip evidence instead and nodes slash different
    ///       stake from the same height (audit finding F4).
    pub async fn apply_equivocation_slashes(&mut self) -> u64 {
        let mut guard = self.state.staking_write().await;
        let ledger = &mut *guard;
        let mut burned = 0u64;
        for ev in self.hc.equivocations() {
            if let Ok(b) = ledger.slash_equivocation(&ev) {
                burned = burned.saturating_add(b);
            }
        }
        burned
    }

    /// Block-carried equivocation feed: deterministic envelopes for the NEXT
    /// block this node helps build.
    ///
    /// Converts THIS node's local double-vote observations
    /// (`HeightConsensus::equivocations()` — which transactions may never
    /// read, audit F4) into canonical, verified
    /// [`crate::consensus::EquivocationEvidence`] envelopes ready to embed
    /// as `OpCode::SysCallReportEquivocation` payloads (permissionless: any
    /// funded account may report, like the price-feed path). Verified
    /// against the consensus validator set, sorted by offense key, in-block
    /// duplicates dropped, capped at
    /// [`crate::consensus::MAX_BLOCK_EQUIVOCATION_EVIDENCES`] — so every
    /// caller feeds the same bytes for the same observations.
    ///
    /// This feeds PROPOSAL content only. The slash itself fires at apply
    /// (`InMemoryStateEngine::apply_block_transition`, step 5b), which
    /// re-verifies every envelope from block bytes and dedupes per offense
    /// in the staking ledger — so a re-included (already-slashed) offense
    /// burns 0 and the feed needs no ledger access. Fail-closed: anything
    /// unverifiable never leaves this function.
    pub fn equivocation_feed_evidence(&self) -> Vec<crate::consensus::EquivocationEvidence> {
        let pairs = self.hc.equivocations();
        if pairs.is_empty() {
            return Vec::new();
        }
        let items: Vec<crate::consensus::EquivocationEvidence> = pairs
            .into_iter()
            .map(|(voter, a, b)| crate::consensus::EquivocationEvidence::new(voter, a, b))
            .collect();
        let mut out = crate::consensus::canonicalize_equivocation_evidence(items, &|v| {
            self.validators.validators.contains_key(v)
        });
        out.truncate(crate::consensus::MAX_BLOCK_EQUIVOCATION_EVIDENCES);
        out
    }

    // ==================== Staking lifecycle (on-chain) ====================

    /// Register a validator self-bond through the node.
    ///
    /// A8: the bonded STELL is actually DEBITED from the validator's account, so
    /// voting power is backed by real funds (previously the ledger was updated
    /// without moving any balance, letting a validator stake funds it never had).
    pub async fn stake_bond(
        &mut self,
        validator: ValidatorId,
        amount: u64,
        commission_bps: u64,
    ) -> Result<(), crate::staking::StakingError> {
        use crate::staking::StakingError;
        // The ledger lives in the state engine, so a bond through this helper
        // lands in exactly the place a SysCallStake bond does.
        self.state
            .debit_native(&validator, amount)
            .await
            .map_err(|_| StakingError::InsufficientBond)?;
        let _ = self
            .state
            .credit_native(&crate::staking::STAKING_POOL, amount)
            .await;
        let res = self
            .state
            .staking_write()
            .await
            .bond(validator, amount, commission_bps);
        if let Err(e) = res {
            // M2: the ledger refused AFTER the pool was credited — remove the
            // pool credit symmetrically (fail-closed) before refunding the
            // validator, or the pool keeps coins no ledger entry backs (mint).
            let _ = self
                .state
                .debit_native(&crate::staking::STAKING_POOL, amount)
                .await;
            let _ = self.state.credit_native(&validator, amount).await;
            return Err(e);
        }
        Ok(())
    }

    /// Begin unbonding self-bond (subject to cooldown). Funds are already held by
    /// the ledger from `stake_bond`, so nothing moves until withdrawal.
    pub async fn stake_unbond(
        &mut self,
        validator: ValidatorId,
        amount: u64,
        now: u64,
    ) -> Result<(), crate::staking::StakingError> {
        let mut engine = self.state.staking_write().await;
        let l = &mut *engine;
        l.unbond(validator, amount, now)
    }

    /// Delegate stake to a validator. The STELL is actually DEBITED from the
    /// delegator's account.
    ///
    /// M2: the debit is escrowed into [`crate::staking::STAKING_POOL`] exactly
    /// like `stake_bond`, so the delegated ledger entry is always pool-backed
    /// and a later `stake_withdraw_delegator` can debit the pool instead of
    /// minting. Every native leg unwinds symmetrically on failure.
    pub async fn stake_delegate(
        &mut self,
        delegator: [u8; 32],
        validator: ValidatorId,
        amount: u64,
    ) -> Result<(), crate::staking::StakingError> {
        // L2: the zero delegator would collide with the validator's own
        // matured self-bond key — refuse before moving any coins.
        if delegator == [0u8; 32] {
            return Err(crate::staking::StakingError::ZeroAddress);
        }
        use crate::staking::StakingError;
        self.state
            .debit_native(&delegator, amount)
            .await
            .map_err(|_| StakingError::InsufficientDelegation)?;
        if self
            .state
            .credit_native(&crate::staking::STAKING_POOL, amount)
            .await
            .is_err()
        {
            let _ = self.state.credit_native(&delegator, amount).await;
            return Err(StakingError::InsufficientDelegation);
        }
        let res = self
            .state
            .staking_write()
            .await
            .delegate(delegator, validator, amount);
        if let Err(e) = res {
            let _ = self
                .state
                .debit_native(&crate::staking::STAKING_POOL, amount)
                .await;
            let _ = self.state.credit_native(&delegator, amount).await;
            return Err(e);
        }
        Ok(())
    }

    /// Begin undelegating (subject to cooldown).
    pub async fn stake_undelegate(
        &mut self,
        delegator: [u8; 32],
        validator: ValidatorId,
        amount: u64,
        now: u64,
    ) -> Result<(), crate::staking::StakingError> {
        self.state
            .staking_write()
            .await
            .undelegate(delegator, validator, amount, now)
    }

    /// Mature any unbonding entries whose cooldown has elapsed (called on
    /// finalization so funds become withdrawable without an external trigger).
    /// Fail-closed (audit P2): an overflow refusal is logged LOUD and the
    /// entries stay pending (retried next finalization); maturation never
    /// destroys dust to keep liveness.
    pub async fn process_unbonding(&mut self, now: u64) {
        if let Err(e) = self.state.staking_write().await.process_unbonding(now) {
            tracing::error!("unbonding maturation refused (funds stay pending): {e}");
        }
    }

    /// Withdraw matured self-bond funds (credited back to the validator).
    ///
    /// M2: withdrawals are paid OUT OF [`crate::staking::STAKING_POOL`], never
    /// minted. The pool is debited FIRST (fail-closed on shortfall: the
    /// consumed ledger entry is restored and nothing is paid); if the final
    /// credit then fails, the pool debit is refunded AND the ledger entry is
    /// restored, so a failed withdrawal moves no coins anywhere.
    pub async fn stake_withdraw(
        &mut self,
        validator: ValidatorId,
    ) -> Result<u64, crate::staking::StakingError> {
        use crate::staking::StakingError;
        let amount = self.state.staking_write().await.withdraw(validator)?;
        if self
            .state
            .debit_native(&crate::staking::STAKING_POOL, amount)
            .await
            .is_err()
        {
            let mut l = self.state.staking_write().await;
            let key = (validator, [0u8; 32]);
            let back = l
                .withdrawable
                .get(&key)
                .copied()
                .unwrap_or(0)
                .saturating_add(amount);
            l.withdrawable.insert(key, back);
            return Err(StakingError::NothingToWithdraw);
        }
        if self.state.credit_native(&validator, amount).await.is_err() {
            let _ = self
                .state
                .credit_native(&crate::staking::STAKING_POOL, amount)
                .await;
            let mut l = self.state.staking_write().await;
            let key = (validator, [0u8; 32]);
            let back = l
                .withdrawable
                .get(&key)
                .copied()
                .unwrap_or(0)
                .saturating_add(amount);
            l.withdrawable.insert(key, back);
            return Err(StakingError::NothingToWithdraw);
        }
        Ok(amount)
    }

    /// Withdraw matured undelegated funds as a delegator (credited to delegator).
    ///
    /// M2: same pool-backed discipline as [`Self::stake_withdraw`] — the pool
    /// is debited first (fail-closed on shortfall, ledger entry restored) and
    /// both legs unwind on a failed credit.
    pub async fn stake_withdraw_delegator(
        &mut self,
        delegator: [u8; 32],
        validator: ValidatorId,
    ) -> Result<u64, crate::staking::StakingError> {
        use crate::staking::StakingError;
        let amount = self
            .state
            .staking_write()
            .await
            .withdraw_delegator(delegator, validator)?;
        if self
            .state
            .debit_native(&crate::staking::STAKING_POOL, amount)
            .await
            .is_err()
        {
            let mut l = self.state.staking_write().await;
            let key = (validator, delegator);
            let back = l
                .withdrawable
                .get(&key)
                .copied()
                .unwrap_or(0)
                .saturating_add(amount);
            l.withdrawable.insert(key, back);
            return Err(StakingError::NothingToWithdraw);
        }
        if self.state.credit_native(&delegator, amount).await.is_err() {
            let _ = self
                .state
                .credit_native(&crate::staking::STAKING_POOL, amount)
                .await;
            let mut l = self.state.staking_write().await;
            let key = (validator, delegator);
            let back = l
                .withdrawable
                .get(&key)
                .copied()
                .unwrap_or(0)
                .saturating_add(amount);
            l.withdrawable.insert(key, back);
            return Err(StakingError::NothingToWithdraw);
        }
        Ok(amount)
    }

    /// Claim accrued validator rewards (credited to the validator).
    ///
    /// E2: paid out of the minted [`crate::staking::REWARDS_POOL`], never out
    /// of bonded principal and never minted from thin air. The ledger claim
    /// already consumed the pool backing; the native leg debits the pool
    /// first (fail-closed on shortfall) and restores the ledger entry if
    /// either native leg fails.
    pub async fn stake_claim_rewards(
        &mut self,
        validator: ValidatorId,
    ) -> Result<u64, crate::staking::StakingError> {
        let amount = self
            .state
            .staking_write()
            .await
            .claim_validator_rewards(validator)?;
        if amount > 0 {
            if self
                .state
                .debit_native(&crate::staking::REWARDS_POOL, amount)
                .await
                .is_err()
            {
                // Restore pool backing + pending rewards: nothing was paid.
                let mut l = self.state.staking_write().await;
                l.rewards_pool = l.rewards_pool.saturating_add(amount);
                if let Some(v) = l.validators.get_mut(&validator) {
                    v.pending_rewards = v.pending_rewards.saturating_add(amount);
                }
                return Err(crate::staking::StakingError::RewardCreditFailed);
            }
            if let Err(_e) = self.state.credit_native(&validator, amount).await {
                // Refund the pool debit and restore the ledger entry.
                let _ = self
                    .state
                    .credit_native(&crate::staking::REWARDS_POOL, amount)
                    .await;
                let mut l = self.state.staking_write().await;
                l.rewards_pool = l.rewards_pool.saturating_add(amount);
                if let Some(v) = l.validators.get_mut(&validator) {
                    v.pending_rewards = v.pending_rewards.saturating_add(amount);
                }
                return Err(crate::staking::StakingError::RewardCreditFailed);
            }
        }
        Ok(amount)
    }

    /// Claim accrued delegator rewards (credited to the delegator).
    ///
    /// E2: same funding discipline as [`Self::stake_claim_rewards`] — the
    /// native leg debits [`crate::staking::REWARDS_POOL`], never principal.
    pub async fn stake_claim_delegator_rewards(
        &mut self,
        delegator: [u8; 32],
        validator: ValidatorId,
    ) -> u64 {
        let amount = self
            .state
            .staking_write()
            .await
            .claim_delegator_rewards(delegator, validator);
        if amount > 0 {
            if self
                .state
                .debit_native(&crate::staking::REWARDS_POOL, amount)
                .await
                .is_err()
            {
                // Restore pool backing + the consumed entry: nothing was paid.
                let mut l = self.state.staking_write().await;
                l.rewards_pool = l.rewards_pool.saturating_add(amount);
                *l.delegator_rewards
                    .entry((validator, delegator))
                    .or_insert(0) = l
                    .delegator_rewards
                    .get(&(validator, delegator))
                    .copied()
                    .unwrap_or(0)
                    .saturating_add(amount);
                return 0;
            }
            if self.state.credit_native(&delegator, amount).await.is_err() {
                // Refund the pool debit and restore the ledger entry.
                let _ = self
                    .state
                    .credit_native(&crate::staking::REWARDS_POOL, amount)
                    .await;
                {
                    let mut l = self.state.staking_write().await;
                    l.rewards_pool = l.rewards_pool.saturating_add(amount);
                    *l.delegator_rewards
                        .entry((validator, delegator))
                        .or_insert(0) = l
                        .delegator_rewards
                        .get(&(validator, delegator))
                        .copied()
                        .unwrap_or(0)
                        .saturating_add(amount);
                }
                return 0;
            }
        }
        amount
    }

    /// Whether a sealed transaction's transparent metadata matches the
    /// transaction it was sealed from.
    ///
    /// The metadata is what the mempool ordered by, so a wallet that lies about
    /// it could buy priority for free. The check happens right after the
    /// unseal, BEFORE the transaction can enter a block: a mismatch drops the
    /// transaction (fail closed).
    pub fn sealed_meta_matches(tx: &Transaction, meta: &crate::mev_epoch::TransparentMeta) -> bool {
        tx.from == meta.from
            && tx.nonce == meta.nonce
            && tx.gas_limit == meta.gas_limit
            && tx.priority_fee_per_gas == meta.priority_fee_per_gas
            && tx.source_shard == meta.source_shard
            && tx.target_shard == meta.target_shard
    }

    // ==================== Governance (on-chain) ====================

    /// Submit a governance proposal.
    pub fn gov_propose(
        &mut self,
        proposer: ValidatorId,
        title: String,
        action: crate::governance::GovAction,
        now: u64,
    ) -> Result<u64, crate::governance::GovError> {
        // Single-node write guard (fail-closed on multi-node deployments):
        // the in-force validator set size (`self.validators.len()`) is the
        // canonical multi-node signal — a local-only proposal here would
        // diverge the state root from peers that never saw it. The
        // deterministic finalize sweep is NOT gated (it derives from decided
        // blocks, identically on every node).
        if let Err(msg) =
            crate::governance::governance_write_allowed_from_env(self.validators.len())
        {
            return Err(crate::governance::GovError::MultiNodeRefused(msg));
        }
        let mut ledger = self
            .staking
            .try_write()
            .map_err(|_| crate::governance::GovError::NotStaker)?;
        let g = self
            .governance
            .as_mut()
            .ok_or(crate::governance::GovError::NotStaker)?;
        g.propose(&mut ledger, proposer, title, action, now)
    }

    /// Cast a governance vote.
    pub fn gov_vote(
        &mut self,
        voter: [u8; 32],
        proposal_id: u64,
        choice: crate::governance::VoteChoice,
        now: u64,
    ) -> Result<u128, crate::governance::GovError> {
        // Same single-node write guard as `gov_propose` (gate FIRST, before
        // any lock or lookup, so a multi-node vote is refused as
        // multi-node — never as some downstream UnknownProposal).
        if let Err(msg) =
            crate::governance::governance_write_allowed_from_env(self.validators.len())
        {
            return Err(crate::governance::GovError::MultiNodeRefused(msg));
        }
        // E7: `Governance::vote` locks the voter's stake in the ledger, so it
        // needs a write guard (via the state engine, which also bumps the
        // commitment generation — a bare handle write would leave the root
        // cache stale). Same underlying lock as `self.staking`.
        let mut ledger = self
            .state
            .try_staking_write()
            .ok_or(crate::governance::GovError::NotStaker)?;
        let g = self
            .governance
            .as_mut()
            .ok_or(crate::governance::GovError::NotStaker)?;
        g.vote(&mut ledger, voter, proposal_id, choice, now)
    }

    /// Finalize a proposal after its voting window.
    pub fn gov_finalize(
        &mut self,
        proposal_id: u64,
        now: u64,
    ) -> Result<crate::governance::ProposalStatus, crate::governance::GovError> {
        // E7: `Governance::finalize` releases voters' staking locks (see
        // `gov_vote` for why this goes through the state engine).
        let mut ledger = self
            .state
            .try_staking_write()
            .ok_or(crate::governance::GovError::NotStaker)?;
        let g = self
            .governance
            .as_mut()
            .ok_or(crate::governance::GovError::NotStaker)?;
        g.finalize(&mut ledger, proposal_id, now)
    }

    /// Execute a passed proposal's action.
    pub fn gov_execute(
        &mut self,
        executor: [u8; 32],
        proposal_id: u64,
    ) -> Result<crate::governance::AppliedParams, crate::governance::GovError> {
        let g = self
            .governance
            .as_mut()
            .ok_or(crate::governance::GovError::NotStaker)?;
        let applied = g.execute(executor, proposal_id).cloned()?;
        if let Some(min_bond) = applied.min_validator_bond {
            if let Ok(mut st) = self.staking.try_write() {
                st.min_validator_bond = Some(min_bond);
            }
        }
        Ok(applied)
    }

    pub fn height(&self) -> Height {
        self.hc.height
    }

    pub fn is_proposer(&self) -> bool {
        self.hc.proposer() == Some(self.id)
    }

    pub async fn add_tx(&mut self, tx: Transaction) {
        // Check the sender's balance so an unfunded tx can never occupy queue
        // space or evict a funded one at the mempool.
        let acct = self.state.get_account(&tx.from).await;
        let balance = acct.as_ref().map(|a| a.balance).unwrap_or(0);
        // F-02: carry the on-chain head so `insert` enforces the nonce-gap
        // fail-fast at the choke point itself (not just at the RPC/gossip
        // pre-checks). `None`-head callers keep legacy behavior; here the
        // head is already in hand, so enforce unconditionally. Node-local
        // admission only — never consensus.
        let onchain = acct.as_ref().map(|a| a.nonce).unwrap_or(0);
        // P2 shard gate: in a sharded process the pool only admits what this
        // shard owns, so foreign-shard spam cannot squat in pool space the
        // proposer must skip. Single-shard mode stays shard-blind (historical
        // source=1/target=1 traffic must keep admitting).
        let mut ctx = crate::mempool::AdmissionCtx::wall_now().with_onchain_nonce(onchain);
        // PAYMASTER: gossiped sponsored transactions carry their sponsor's
        // head too (fail-closed without it); legacy ignores the extra head.
        if let Some(sbal) = self.state.sponsor_balance_of(&tx).await {
            ctx = ctx.with_sponsor_balance(sbal);
        }
        if self.shard_registry.is_sharded() {
            ctx = ctx.with_shard(self.shard_id);
        }
        let _ = self.mempool.write().await.add_checked_ctx(tx, balance, ctx);
    }

    /// Plain-path pack admissibility: the exact predicate `propose` passes to
    /// `select_for_block_multi`, factored so the prebuild and the revalidation
    /// run THE SAME checks as a fresh build.
    ///
    /// Pure function of (tx, ctx, block timestamp): shard scope, session
    /// policy + registry (expiry, scope, remaining budget via the in-block
    /// spend simulation), nonce continuity, D2 failure-penalty + PQ
    /// surcharge + priority-bid fee floor, and balance — SKIP-only on every
    /// failure, mutating only the filter state (expected nonces, session
    /// spend, used senders, rejection census). Accepting here is necessary
    /// but not sufficient for block validity (caps, unseal gate, actor cap,
    /// state-root recompute and the proposer signature still run at propose);
    /// receivers re-verify all of it, so reuse can only ever change block
    /// COMPOSITION (liveness), never validity (safety).
    pub fn pack_filter_accept(ctx: &PackFilterCtx, t: &Transaction) -> bool {
        let timestamp = ctx.timestamp;
        if ctx.sharded && !crate::sharding::tx_belongs_to_shard(t, ctx.my_shard) {
            ctx.rej_shard.set(ctx.rej_shard.get() + 1);
            return false;
        }
        let is_cross = ctx.sharded && crate::sharding::tx_is_outbound_cross_shard(t, ctx.my_shard);
        if is_cross && ctx.used_senders.borrow().contains(&t.from) {
            ctx.rej_shard.set(ctx.rej_shard.get() + 1);
            return false;
        }
        // Session-key delegation policy against THIS block's timestamp (the
        // deterministic clock): expiry, scope, value cap and remaining
        // budget. The exact same predicate the apply path re-checks.
        if t.check_session_policy(timestamp).is_err() {
            ctx.rej_session.set(ctx.rej_session.get() + 1);
            return false;
        }
        // ...joined by the registry: a revoked key is refused here exactly
        // as it is at admission and at execution, and this block's own
        // in-flight session spend counts against the budget the same way the
        // apply path's simulation does.
        if let Some(d) = t.delegation() {
            // Same single definition the apply path uses (including the
            // actor-mailbox scope), so a proposer can never select a
            // transaction execution would refuse for scope.
            let required_scope = t.required_scope();
            if ctx
                .session_keys
                .check(
                    &d,
                    t.amount,
                    t.gas_limit,
                    required_scope,
                    timestamp,
                    &mut ctx.session_sim.borrow_mut(),
                )
                .is_err()
            {
                ctx.rej_session.set(ctx.rej_session.get() + 1);
                return false;
            }
        }
        let Some(&(expected, balance)) = ctx.next_nonce.borrow().get(&t.from) else {
            // No account means no balance, so it cannot pay.
            ctx.rej_noacct.set(ctx.rej_noacct.get() + 1);
            return false;
        };
        if t.nonce != expected {
            ctx.rej_nonce.set(ctx.rej_nonce.get() + 1);
            return false;
        }
        // Failure-penalized floor (D2) + PQ surcharge + explicit priority bid:
        // mirrors admission exactly, SKIP-only like every other condition.
        let pq_surch = if t.is_pq_activation() {
            crate::mempool::PQ_ACTIVATION_SURCHARGE_GAS
        } else {
            0
        };
        let floor = ctx
            .base_fee
            .saturating_add(ctx.penalty_floors.get(&t.from).copied().unwrap_or(0))
            .saturating_add(pq_surch)
            .saturating_add(t.priority_fee_per_gas);
        if t.gas_limit < floor {
            ctx.rej_basefee.set(ctx.rej_basefee.get() + 1);
            return false;
        }
        // PAYMASTER v1 (mid-mempool re-check, plain path): the legs split —
        // the user covers VALUE, the sponsor covers FEE — and the grant's
        // policy is re-checked at the block timestamp, SKIP-only.
        if let Some(auth) = t.sponsored_grant() {
            if t.sponsor_inner_sig().len() != 64 || !t.verify_sponsor_sig(&auth) {
                ctx.rej_sponsor.set(ctx.rej_sponsor.get() + 1);
                return false;
            }
            let fee = t.gas_limit.max(floor).saturating_add(pq_surch);
            if t.check_sponsor_policy(timestamp, fee).is_err() {
                ctx.rej_sponsor.set(ctx.rej_sponsor.get() + 1);
                return false;
            }
            if balance < t.amount {
                ctx.rej_funds.set(ctx.rej_funds.get() + 1);
                return false;
            }
            let Some(&(sponsor_nonce, sponsor_balance)) =
                ctx.next_nonce.borrow().get(&auth.sponsor)
            else {
                ctx.rej_funds.set(ctx.rej_funds.get() + 1);
                return false;
            };
            if sponsor_balance < fee {
                ctx.rej_funds.set(ctx.rej_funds.get() + 1);
                return false;
            }
            ctx.next_nonce
                .borrow_mut()
                .insert(t.from, (expected + 1, balance - t.amount));
            ctx.next_nonce
                .borrow_mut()
                .insert(auth.sponsor, (sponsor_nonce, sponsor_balance - fee));
            ctx.used_senders.borrow_mut().insert(t.from);
            return true;
        }
        // F-07: the pack balance check mirrors admission execution
        // (amount + gas_limit + PQ surcharge for activation txs).
        let cost = t
            .amount
            .saturating_add(t.gas_limit)
            .saturating_add(pq_surch);
        if balance < cost {
            ctx.rej_funds.set(ctx.rej_funds.get() + 1);
            return false;
        }
        // Accepting it advances this sender's nonce and debits its budget.
        ctx.next_nonce
            .borrow_mut()
            .insert(t.from, (expected + 1, balance - cost));
        ctx.used_senders.borrow_mut().insert(t.from);
        true
    }

    /// Enforce every block cap on a combined (kept + top-up) selection by
    /// dropping from the end. Kept transactions precede new ones and each
    /// run is internally selection-ordered, so suffix truncation preserves
    /// per-sender nonce contiguity and the survivors still satisfy the
    /// filter's own checks. A kept-only prefix always satisfied these same
    /// caps at prebuild time (identical constants), so truncation only ever
    /// sheds top-up transactions — liveness-only, never validity.
    fn truncate_to_block_caps(txs: &mut Vec<Transaction>) {
        let mut gas = 0u64;
        let mut wire = 0usize;
        let mut proofs = 0usize;
        let mut keep = 0usize;
        for t in txs.iter() {
            let g = gas.saturating_add(t.gas_limit);
            let w = wire.saturating_add(crate::mempool::Mempool::estimate_tx_wire_bytes(t));
            let p = proofs.saturating_add(crate::mempool::Mempool::count_tx_proof_units(t));
            if keep >= MAX_BLOCK_TXS
                || g > MAX_BLOCK_GAS
                || w > crate::mempool::Mempool::MAX_BLOCK_WIRE_BYTES
                || p > crate::mempool::Mempool::MAX_BLOCK_PROOF_UNITS
            {
                break;
            }
            gas = g;
            wire = w;
            proofs = p;
            keep += 1;
        }
        txs.truncate(keep);
    }

    /// Whether a prebuilt selection for `height` is cached.
    pub fn has_prebuild_for(&self, height: Height) -> bool {
        self.prebuilt_selection
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|c| c.for_height == height))
            .unwrap_or(false)
    }

    /// VEL-1 proposer-prebuild: run the plain-tx selection early (during the
    /// prevote idle window) and cache the ordered candidate list.
    ///
    /// Called by the tick when this node is about to need a proposal it has
    /// not built yet: either it owns the current round and is waiting out
    /// `min_block_time`, or it owns round 0 of the NEXT height (proposer
    /// lookahead is inherent to the hash schedule). The selection runs
    /// against CURRENT state with the CURRENT pool; `propose` revalidates
    /// every cached tx against LIVE state through the SAME predicate and
    /// tops up from the pool, so a parent that changed under the prebuild
    /// (the height finalized a different block, new txs arrived, a session
    /// expired) only shrinks or refreshes the reuse — validity is preserved
    /// by construction, and a total miss costs one bounded O(block)
    /// revalidation before falling back to a fresh build.
    ///
    /// Liveness-only, proposer-local: no wire bytes, no quorum input, no
    /// state transition. Skipped (no-op) while an apply is in flight (the
    /// state root would mislead the snapshot), when sealed txs are pending
    /// (the sealed path conditions plain selection on its own effects —
    /// reuse is disabled then, see `propose`), and when the cache already
    /// covers the target height.
    pub async fn prebuild_next_proposal(&mut self, timestamp: u64) {
        if self.apply_in_flight.is_some() {
            return;
        }
        // Target: our own imminent proposal — current round if we own it and
        // have not proposed, else round 0 of the next height if scheduled.
        let target = if self.is_proposer() && !self.hc.has_live_proposal() {
            self.hc.height
        } else if self.validators.proposer_for(self.hc.height + 1, 0) == Some(self.id) {
            self.hc.height + 1
        } else {
            return;
        };
        if self.has_prebuild_for(target) {
            return;
        }
        // Sealed path conditions plain selection: a pending sealed set at
        // prebuild time may differ at propose time, so skip caching then
        // (bounded waste avoided entirely; propose falls back to fresh).
        // Cheap gate: the sealed index is empty in the common case.
        let has_sealed = !self.mempool.read().await.sealed_candidates().is_empty();
        if has_sealed {
            return;
        }
        let Some(ctx) = self.pack_filter_ctx(timestamp).await else {
            return;
        };
        let txs =
            self.mempool
                .read()
                .await
                .select_for_block_multi(MAX_BLOCK_TXS, MAX_BLOCK_GAS, |t| {
                    Self::pack_filter_accept(&ctx, t)
                });
        if let Ok(mut g) = self.prebuilt_selection.lock() {
            *g = Some(PrebuiltSelection {
                for_height: target,
                txs,
            });
        }
    }

    /// Build a fresh [`PackFilterCtx`] over live state (snapshot + fees +
    /// registry). `None` only when the snapshot cannot be taken; callers fall
    /// back to a fresh build path that reports the miss.
    async fn pack_filter_ctx(&self, timestamp: u64) -> Option<PackFilterCtx> {
        let state_root = self.state.get_state_root().await;
        let senders: Vec<[u8; 32]> = self.mempool.read().await.fee_payers().into_iter().collect();
        let guard = self.state.accounts.read().await;
        let mut accounts: HashMap<[u8; 32], (u64, u64)> = HashMap::with_capacity(senders.len());
        for a in &senders {
            if let Some(acct) = guard.get(a) {
                accounts.insert(*a, (acct.nonce, acct.balance));
            }
        }
        drop(guard);
        // Soundness: only an exact root match means the entries are the live
        // state; anything else still yields a usable snapshot for the
        // revalidation/top-up (every kept tx is re-checked tx-by-tx below),
        // so no store gate is needed here.
        let _ = state_root;
        let fresh: Vec<[u8; 32]> = self.mempool.read().await.fee_payers().into_iter().collect();
        for s in missing_sender_accounts(&accounts, &fresh) {
            if let Some(acct) = self.state.get_account(&s).await {
                accounts.insert(s, (acct.nonce, acct.balance));
            }
        }
        let (base_fee, penalty_floors) = {
            let pool = self.mempool.read().await;
            (pool.base_fee, pool.penalty_snapshot())
        };
        let session_keys = self.state.session_keys_read().await.clone();
        Some(PackFilterCtx::new(
            timestamp,
            self.shard_registry.is_sharded(),
            self.shard_id,
            base_fee,
            penalty_floors,
            session_keys,
            accounts,
            crate::zkml::SessionSpendSim::default(),
            HashSet::new(),
        ))
    }

    // If we are the proposer, build a block from the mempool and sign it.
    // ==================================================================
    // Epoch seal (asymmetric, threshold-sealed transaction gossip)
    // ==================================================================

    /// How long the proposer waits for the peers' decryption partials.
    ///
    /// The share release is a network round trip (the peers release only
    /// after they see the order commitment), so the proposer waits for it —
    /// but BOUNDED, so a member that withholds its share can DELAY the
    /// round, never stall it. Zero disables the wait entirely (the sealed
    /// path then only ever unseals what the local node can unseal alone,
    /// which is nothing on a real committee).
    fn seal_partial_wait_ms() -> u64 {
        static BUDGET: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
        *BUDGET.get_or_init(|| {
            std::env::var("STELL_MEV_UNSEAL_WAIT_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(500)
        })
    }

    /// Move the node's epoch-seal state to the current epoch.
    ///
    /// Called from the tick: when the chain crosses an epoch boundary the
    /// node starts the epoch's DKG (publishing its own contribution) and
    /// rotates the epoch key. The plain path is untouched: a node that is
    /// not a committee member, or whose remote signer keeps the long-term
    /// secret away from this process, simply has no epoch key and keeps
    /// serving plain transactions.
    pub async fn sync_mev_epoch(&mut self) {
        let epoch = crate::mev_epoch::epoch_of_height(self.hc.height);
        let ids: Vec<[u8; 32]> = self.validators.validators.keys().copied().collect();
        let our_id = self.key.verifying_key().to_bytes();
        let seed = self.key.to_bytes();
        let now = std::time::Instant::now();
        let contribution = {
            let mut pool = self.mempool.write().await;
            pool.set_sealed_epoch(epoch);
            match pool.mev_seal.sync_epoch(epoch, &ids, our_id, &seed) {
                Ok(c) => {
                    if let Some(contribution) = &c {
                        // Ingest OUR OWN contribution locally: the epoch key
                        // is the aggregate over the WHOLE contributor set,
                        // and our own evaluation is one of its terms.
                        if let Err(e) = pool
                            .mev_seal
                            .ingest_contribution(contribution.clone(), &seed)
                        {
                            tracing::debug!("[mev-seal] our own dkg contribution refused: {e}");
                        }
                    }
                    if c.is_some() {
                        pool.mev_seal.note_published(now);
                    }
                    c
                }
                Err(e) => {
                    tracing::debug!("[mev-seal] epoch {epoch}: no dkg ({e})");
                    None
                }
            }
        };
        if let Some(contribution) = contribution {
            tracing::info!(
                "[mev-seal] epoch {epoch}: published our dkg contribution (index {})",
                contribution.index
            );
            self.gossip_mev_frame(crate::mev_epoch::MevFrame::Dkg(contribution))
                .await;
            // The DKG may have completed with our own contribution (we are
            // the last contributor the node was waiting for).
            self.publish_epoch_announcement().await;
            return;
        }
        // RE-PUBLISH: the contribution is re-sent on an interval until the
        // epoch key is ready. A peer that missed the first frame (a restart,
        // a dropped gossip message) would otherwise never receive it, and
        // the epoch's key generation would never complete.
        let republish = {
            let mut pool = self.mempool.write().await;
            if pool
                .mev_seal
                .should_publish_contribution(now, DKG_REPUBLISH_INTERVAL)
            {
                let c = pool.mev_seal.own_contribution().cloned();
                if c.is_some() {
                    pool.mev_seal.note_published(now);
                }
                c
            } else {
                None
            }
        };
        if let Some(c) = republish {
            tracing::debug!("[mev-seal] epoch {epoch}: re-publishing our dkg contribution");
            self.gossip_mev_frame(crate::mev_epoch::MevFrame::Dkg(c))
                .await;
        }
    }

    /// Publish the epoch-key announcement (the committee's agreement on the
    /// epoch key), once the DKG has completed.
    ///
    /// The announcement carries our signature over the epoch key; a light
    /// client collects the members' announcements, checks the quorum against
    /// the validator set and checks the commitment against the block.
    async fn publish_epoch_announcement(&mut self) {
        let announcement = {
            let pool = self.mempool.read().await;
            pool.mev_seal.build_announcement(&self.key).ok()
        };
        let Some(announcement) = announcement else {
            return;
        };
        tracing::info!(
            "[mev-seal] epoch {}: announcing the epoch key ({})",
            announcement.epoch,
            hex::encode(&announcement.commitment()[..6])
        );
        self.gossip_mev_frame(crate::mev_epoch::MevFrame::Announcement(announcement))
            .await;
    }

    /// Publish an epoch-seal frame on the transaction-gossip channel.
    async fn gossip_mev_frame(&self, frame: crate::mev_epoch::MevFrame) {
        let Some(gossip) = self.tx_gossip.as_ref() else {
            return;
        };
        gossip.broadcast_mev_frame(&frame).await;
    }

    /// Handle one epoch-seal frame received from a peer.
    ///
    /// * a DKG contribution joins the epoch's key generation;
    /// * an order commitment releases OUR decryption partials (the gate on
    ///   the reveal: the order is fixed before anybody can read the
    ///   transactions);
    /// * a share release adds the peer's partials to the pool we unseal
    ///   with.
    pub async fn on_mev_frame(&mut self, frame: crate::mev_epoch::MevFrame) {
        match frame {
            crate::mev_epoch::MevFrame::Sealed(envelope) => {
                let mut pool = self.mempool.write().await;
                if let Err(e) = pool.add_sealed(envelope) {
                    tracing::debug!("[mev-seal] sealed admission refused: {e}");
                }
            }
            crate::mev_epoch::MevFrame::Dkg(contribution) => {
                let seed = self.key.to_bytes();
                let (material, announcement) = {
                    let mut pool = self.mempool.write().await;
                    if let Err(e) = pool.mev_seal.ingest_contribution(contribution, &seed) {
                        tracing::debug!("[mev-seal] dkg contribution refused: {e}");
                        return;
                    }
                    let material = pool.mev_seal.material().cloned();
                    let announcement = material
                        .as_ref()
                        .and_then(|_| pool.mev_seal.build_announcement(&self.key).ok());
                    (material, announcement)
                };
                if let Some(material) = material {
                    tracing::info!(
                        "[mev-seal] epoch {} key ready (threshold {})",
                        material.epoch,
                        material.threshold
                    );
                }
                // Announce the epoch key: the committee's agreement, signed by
                // us, so a light client can check the key against the chain.
                if let Some(announcement) = announcement {
                    self.gossip_mev_frame(crate::mev_epoch::MevFrame::Announcement(announcement))
                        .await;
                }
            }
            crate::mev_epoch::MevFrame::OrderCommit(commitment) => {
                {
                    let mut pool = self.mempool.write().await;
                    if let Err(e) = pool.mev_seal.note_commitment(commitment.clone()) {
                        tracing::warn!("[mev-seal] order commitment refused: {e}");
                        return;
                    }
                }
                // The order is committed: release our decryption partials.
                self.release_sealed_partials(&commitment).await;
            }
            crate::mev_epoch::MevFrame::Release(release) => {
                let mut pool = self.mempool.write().await;
                match pool.mev_seal.ingest_release(release) {
                    Ok(n) => tracing::debug!("[mev-seal] accepted {n} decryption partial(s)"),
                    Err(e) => tracing::debug!("[mev-seal] share release refused: {e}"),
                }
            }
            crate::mev_epoch::MevFrame::Announcement(announcement) => {
                // The epoch-key announcement: the committee's agreement on
                // the epoch key. It is merged (its signatures only) so a
                // light client can check the quorum against the validator
                // set, and the commitment against the block.
                let mut pool = self.mempool.write().await;
                if let Err(e) = pool.mev_seal.merge_announcement(announcement) {
                    tracing::debug!("[mev-seal] epoch announcement refused: {e}");
                }
            }
        }
    }

    /// Release our decryption partials for the transactions of a committed
    /// order, and publish them.
    ///
    /// The release happens ONLY after the order commitment has been seen:
    /// that is the property the whole scheme exists for.
    async fn release_sealed_partials(&mut self, commitment: &crate::mev_epoch::OrderCommitment) {
        let height = commitment.height;
        let round = commitment.round;
        let epoch = commitment.epoch;
        let order_root = commitment.order_root;
        let mut release = crate::mev_epoch::ShareRelease {
            epoch,
            height,
            round,
            order_root,
            partials: Vec::new(),
        };
        for tx_hash in &commitment.tx_hashes {
            let envelope = {
                let pool = self.mempool.read().await;
                pool.sealed_envelope(tx_hash).cloned()
            };
            let Some(envelope) = envelope else {
                continue;
            };
            let partial = {
                let mut pool = self.mempool.write().await;
                pool.mev_seal.release_partial(height, round, &envelope)
            };
            match partial {
                Ok(p) => release.partials.push((*tx_hash, p)),
                Err(e) => tracing::debug!("[mev-seal] partial refused: {e}"),
            }
        }
        if release.partials.is_empty() {
            return;
        }
        tracing::info!(
            "[mev-seal] released {} decryption partial(s) for h={height} r={round}",
            release.partials.len()
        );
        self.gossip_mev_frame(crate::mev_epoch::MevFrame::Release(release))
            .await;
    }

    /// The EPOCH-SEAL proposer path: unseal the committed sealed
    /// transactions.
    /// THE ORDER OF OPERATIONS (the whole point of the scheme):
    ///
    /// 1. the candidate order (the sealed transaction hashes, in the pool's
    ///    order) is COMMITTED — signed and gossiped — BEFORE any content is
    ///    revealed;
    /// 2. only then are the decryption partials released and collected;
    /// 3. only then is the content unsealed.
    ///
    /// A sealed transaction whose partials never arrive is DROPPED (its
    /// sender is charged the failure bond): the round is never stalled by a
    /// member that withholds its share.
    async fn sealed_proposer_path(&mut self, timestamp: u64) -> Vec<Transaction> {
        let (committee_hash, threshold, candidates) = {
            let pool = self.mempool.read().await;
            let Some(material) = pool.mev_seal.material() else {
                return Vec::new();
            };
            let candidates = pool.sealed_candidates();
            if candidates.is_empty() {
                return Vec::new();
            }
            (material.committee_hash, material.threshold, candidates)
        };
        let height = self.hc.height;
        let round = self.hc.round;
        // 1. COMMIT the order.
        //
        //    The order of a HEIGHT is committed ONCE: a second round of the
        //    same height re-uses the commitment it already made, so a sealed
        //    transaction that arrives mid-height cannot silently re-order the
        //    round (it waits for the next height). The first commitment for
        //    the height is the one that is gossiped, and it is the one the
        //    members release their partials against.
        let (commitment, candidates) = {
            let mut pool = self.mempool.write().await;
            let existing = pool.mev_seal.height_commitment(height).cloned();
            match existing {
                Some(commitment) => {
                    // Re-use the committed order: only the transactions it
                    // names are unsealed, in ITS order.
                    let mut ordered = Vec::with_capacity(commitment.tx_hashes.len());
                    for tx_hash in &commitment.tx_hashes {
                        if let Some(envelope) = pool.sealed_envelope(tx_hash) {
                            ordered.push(envelope.clone());
                        }
                    }
                    (commitment, ordered)
                }
                None => {
                    let tx_hashes: Vec<[u8; 32]> = candidates.iter().map(|c| c.tx_hash).collect();
                    match pool
                        .mev_seal
                        .commit_order(height, round, tx_hashes, &self.key)
                    {
                        Ok(c) => (c, candidates),
                        Err(e) => {
                            tracing::warn!("[mev-seal] order commitment refused: {e}");
                            return Vec::new();
                        }
                    }
                }
            }
        };
        if candidates.is_empty() {
            return Vec::new();
        }
        // 2. Release our own partials and publish the commitment, so the
        //    peers can release theirs.
        self.gossip_mev_frame(crate::mev_epoch::MevFrame::OrderCommit(commitment.clone()))
            .await;
        self.release_sealed_partials(&commitment).await;
        // 2b. WAIT (BOUNDED) for the peers' partials.
        //
        // The share release is a network round trip: the peers can only
        // release after they have seen the commitment we just gossiped. The
        // proposer therefore waits — but only BOUNDED, and only when there
        // is something to unseal: a member that withholds its share must
        // never be able to stall the round (the timeout path below drops
        // the transaction and charges its sender).
        self.await_sealed_partials(&candidates, threshold).await;
        // 3. Unseal what we can.
        let mut out: Vec<Transaction> = Vec::new();
        let mut dropped: Vec<(crate::mev_epoch::SealedEnvelope, DropReason)> = Vec::new();
        for candidate in &candidates {
            let partials = {
                let pool = self.mempool.read().await;
                pool.mev_seal.partials_for(&candidate.tx_hash)
            };
            if partials.len() < threshold {
                // Not enough shares: the transaction is dropped (the sender
                // is charged the failure bond), never stalled.
                dropped.push((candidate.clone(), DropReason::NotEnoughShares));
                continue;
            }
            let plaintext = match crate::mev_epoch::unseal_transaction(
                candidate,
                &partials,
                threshold,
                &committee_hash,
            ) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!("[mev-seal] unseal failed: {e}");
                    dropped.push((candidate.clone(), DropReason::Undecryptable));
                    continue;
                }
            };
            let tx: Transaction = match bincode::deserialize(&plaintext) {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!("[mev-seal] unsealed payload is not a transaction: {e}");
                    dropped.push((candidate.clone(), DropReason::NotATransaction));
                    continue;
                }
            };
            // The plaintext MUST match the envelope: the hash binds the
            // content, and the transparent metadata binds the ordering
            // fields. A wallet that lies about either is dropped.
            if tx.compute_tx_hash() != candidate.tx_hash {
                tracing::warn!("[mev-seal] unsealed transaction does not match its envelope");
                dropped.push((candidate.clone(), DropReason::HashMismatch));
                continue;
            }
            if !Self::sealed_meta_matches(&tx, &candidate.meta) {
                tracing::warn!("[mev-seal] unsealed transaction does not match its metadata");
                dropped.push((candidate.clone(), DropReason::MetaMismatch));
                continue;
            }
            if !tx.verify_signature() {
                tracing::warn!("[mev-seal] unsealed transaction has an invalid signature");
                dropped.push((candidate.clone(), DropReason::BadSignature));
                continue;
            }
            out.push(tx);
        }
        // 4. The DROPPED transactions: evict them from the pool (a sealed
        //    transaction that can never be unsealed must not hold pool
        //    space) and charge their sender the failure bond, exactly like
        //    a transaction that fails at apply.
        {
            let mut pool = self.mempool.write().await;
            pool.mev_seal.unsealed += out.len() as u64;
            pool.mev_seal.unseal_failures += dropped.len() as u64;
            for (envelope, reason) in &dropped {
                pool.drop_sealed(&envelope.tx_hash, &envelope.meta.from);
                tracing::info!(
                    "[mev-seal] dropped sealed transaction {} ({reason:?}): the sender is charged the failure bond",
                    hex::encode(&envelope.tx_hash[..6])
                );
            }
        }
        if !dropped.is_empty() {
            crate::metrics::global().inc_mev_unsealed(out.len() as u64);
            crate::metrics::global().inc_mev_unseal_failed(dropped.len() as u64);
            tracing::info!(
                "[mev-seal] h={height} r={round}: unsealed {} of {} sealed transaction(s), dropped {}",
                out.len(),
                candidates.len(),
                dropped.len()
            );
        } else {
            crate::metrics::global().inc_mev_unsealed(out.len() as u64);
        }
        let _ = timestamp;
        out
    }

    /// Wait (BOUNDED) for the peers' decryption partials.
    ///
    /// The wait is bounded by [`seal_partial_wait_ms`] and is skipped
    /// entirely when every candidate already has enough partials. It is the
    /// only place the proposer BLOCKS on the private path, and it is
    /// bounded so that a member which withholds its share can delay the
    /// round but never stall it.
    async fn await_sealed_partials(
        &self,
        candidates: &[crate::mev_epoch::SealedEnvelope],
        threshold: usize,
    ) {
        let budget = Self::seal_partial_wait_ms();
        if budget == 0 {
            return;
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(budget);
        loop {
            let pending = {
                let pool = self.mempool.read().await;
                candidates
                    .iter()
                    .filter(|c| pool.mev_seal.partial_count(&c.tx_hash) < threshold)
                    .count()
            };
            if pending == 0 || std::time::Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(SEAL_PARTIAL_POLL_MS)).await;
        }
    }

    pub async fn propose(&mut self, timestamp: u64) -> Option<Block> {
        if self.parallel_exec {
            self.state.set_parallel_exec(true);
        }
        if !self.is_proposer() || self.hc.step != Step::Propose {
            return None;
        }
        // §7 Phase 2 gate: while a decided block is still executing on the
        // sequenced worker, our state root is PRE-H and every read below
        // (account snapshots for the filter, `state_root` for the header,
        // cross-shard proofs) would build on it. Building now produces a block
        // for the wrong parent state, so there is nothing to propose until the
        // worker reports back. ("Propose while apply pending" must stay None.)
        if self.apply_in_flight.is_some() {
            return None;
        }
        // Liveness: a locked proposer re-proposes its locked value. Building a
        // fresh block while locked is voted nil by every node locked on the old
        // value (including ourselves) while unlocked nodes vote the fresh one
        // -- no quorum either way, forever. Re-proposing the locked body lets
        // the network converge on it: unlocked nodes vote it, nodes locked on
        // it vote it, a QC forms, finalize. The lock is per-height (a new
        // height constructs a fresh HeightConsensus), bodies are retained, and
        // we only ever lock values we voted for, so the body is present; if it
        // is somehow gone, fall through to a fresh block rather than forfeit
        // our proposer rounds entirely.
        // C1 genesis anchor: first messages reference the zero-hash parent
        // with the current (genesis) root, which no finalize event ever
        // records. Note it here (idempotent, overwritten by real finals):
        // without this, height-1 cross-shard transfers can never anchor.
        // Root read FIRST, lock second: the guard must never be held across
        // the await (std guards are !Send).
        if self.finalized.is_empty() {
            if let Some(reg) = self.finalized_headers.clone() {
                let root = self.state.get_state_root().await;
                if let Ok(mut r) = reg.write() {
                    r.note_finalized(self.shard_id, [0u8; 32], root);
                }
            }
        }
        if let Some((locked_hash, _)) = self.hc.locked {
            if let Some(body) = self.blocks.get(&locked_hash).cloned() {
                // Info when bypassing a non-empty pool (audit: blocks
                // troubles): locked re-proposals skip fresh selection, so an
                // empty locked body with a full mempool looks identical to an
                // empty chain without this line.
                let pool_len = self.mempool.read().await.len();
                if pool_len > 0 {
                    tracing::info!(
                        "propose h={} r={}: path=locked txs={} mempool={} (bypasses fresh selection)",
                        self.hc.height,
                        self.hc.round,
                        body.transactions.len(),
                        pool_len,
                    );
                } else {
                    tracing::debug!(
                        "propose h={} r={}: path=locked txs={} mempool=0",
                        self.hc.height,
                        self.hc.round,
                        body.transactions.len(),
                    );
                }
                // Self-record like the fresh path: without this the section-1
                // gate (`!has_live_proposal`) refires every tick and
                // rebroadcasts the identical hash all round (refire spam).
                self.hc.receive_proposal(self.id, locked_hash).ok()?;
                return Some(body);
            }
        }
        // Rescue: a peer is locked on one of OUR bodies (learned via nil-vote
        // lock hints). Re-propose it verbatim at our own slot: receivers
        // validate it normally, the locked peer votes it (it matches its
        // lock), unlocked peers vote it, QC forms, finalize. One shot per
        // hint batch -- a still-stuck peer re-hints and we serve again.
        if self.demanded_height != self.hc.height {
            self.demanded.clear();
            self.demanded_height = self.hc.height;
        }
        if let Some(h) = self.demanded.iter().copied().min() {
            let demanded_body = self
                .blocks
                .get(&h)
                .filter(|b| b.height == self.hc.height && b.proposer == self.id)
                .cloned();
            match demanded_body {
                None => {
                    // Unknown or stale body (never seen, or a previous
                    // height): drop it and fall through to fresh selection
                    // below; a still-stuck peer re-hints on its next nil
                    // prevote.
                    self.demanded.remove(&h);
                }
                Some(body) => {
                    let root = self.state.get_state_root().await;
                    if self.validate_proposal_unaligned(&body, root).is_ok()
                        && self.check_actor_cap(&body).await.is_ok()
                    {
                        let pool_len = self.mempool.read().await.len();
                        if pool_len > 0 {
                            tracing::info!(
                            "propose h={} r={}: path=demanded txs={} mempool={} (bypasses fresh selection)",
                            self.hc.height,
                            self.hc.round,
                            body.transactions.len(),
                            pool_len,
                        );
                        } else {
                            tracing::debug!(
                                "propose h={} r={}: path=demanded txs={} mempool=0",
                                self.hc.height,
                                self.hc.round,
                                body.transactions.len(),
                            );
                        }
                        // Self-record like the fresh path (see the locked path).
                        let bh = body.compute_hash();
                        self.blocks.insert(bh, body.clone());
                        self.hc.receive_proposal(self.id, bh).ok()?;
                        // Served: consume one-shot (a still-stuck peer re-hints).
                        self.demanded.remove(&h);
                        return Some(body);
                    }
                    // Re-validation failed (transient state/backlog read):
                    // KEEP the demand so the next tick retries instead of
                    // waiting a full hint round-trip. The set stays bounded
                    // (MAX_DEMANDED) and height-scoped, so this cannot pile up.
                }
            }
        }
        let state_root = self.state.get_state_root().await;
        // Anti-DoS: bound the block by BOTH tx count and total gas.
        // Both caps plus the admission filter, so a flood of transactions that
        // cannot execute (spent nonce, drained balance) cannot occupy the block
        // and be paid for like real work. `evict_unexecutable` cleans these up
        // each round; this stops them costing anything in the meantime.
        //
        // Sender state is gathered first because the filter itself is
        // synchronous: it walks the fee-ordered index once and must not await
        // inside the loop.
        //
        // R-TEMPO pack cache: account (nonce, balance) is a pure function of
        // committed state, so for a FIXED state root every entry is exact. A
        // hit skips one `get_account` await per sender (measured ~0.4ms for
        // 1785 senders; more on contended/small stacks) AND replaces N
        // sequential lock acquisitions with one guarded scan; the refresh
        // pass below still fetches senders that arrived after the snapshot,
        // and any state mutation (finalize advances the height; faucet/test
        // funding moves the root) misses the cache. Selection output is
        // identical to a fresh scan for the same (state, mempool) —
        // proposer-local only.
        let mut accounts: std::collections::HashMap<[u8; 32], (u64, u64)> =
            match self.pack_snapshot.lock().ok().and_then(|g| {
                g.as_ref()
                    .filter(|(h, r, _)| *h == self.hc.height && *r == state_root)
                    .map(|(_, _, m)| m.clone())
            }) {
                Some(cached) => cached,
                None => {
                    // PAYMASTER: snapshot every fee payer — each sender PLUS
                    // each third-party sponsor backing a sponsored
                    // transaction — because the filter debits the fee leg
                    // from the sponsor. A sponsor missing from the snapshot
                    // reads as unfunded below (SKIP-only, like every other
                    // filter condition).
                    let senders: Vec<[u8; 32]> =
                        self.mempool.read().await.fee_payers().into_iter().collect();
                    // ONE guard, no awaits inside the loop: the snapshot is
                    // mutually consistent AND atomic against concurrent
                    // writers (a writer would move the root and miss the
                    // store gate below instead of poisoning it).
                    let guard = self.state.accounts.read().await;
                    let mut fresh: std::collections::HashMap<[u8; 32], (u64, u64)> =
                        std::collections::HashMap::with_capacity(senders.len());
                    for a in &senders {
                        if let Some(acct) = guard.get(a) {
                            fresh.insert(*a, (acct.nonce, acct.balance));
                        }
                    }
                    drop(guard);
                    // Store only if the state did not move under the snapshot.
                    let root1 = self.state.get_state_root().await;
                    if root1 == state_root {
                        if let Ok(mut g) = self.pack_snapshot.lock() {
                            *g = Some((self.hc.height, state_root, fresh.clone()));
                        }
                    }
                    fresh
                }
            };
        // R0-fullness refresh (packing mechanics, no consensus change): the
        // sender snapshot above is taken BEFORE the per-sender account reads,
        // and each read awaits. The RPC layer shares this mempool, so
        // transactions admitted DURING those reads have senders missing from
        // the map and the filter below rejects them as account-less — the
        // live shape was r0 carrying 52tx while r2 carried 200tx from the same
        // pool. One bounded refresh pass fetches exactly the senders that
        // arrived mid-build, so selection sees the pool as of select time.
        // No waiting is added (no artificial delay): this only stops using a
        // stale snapshot of what is ALREADY available.
        {
            // PAYMASTER: same fee-payer set as the snapshot above, so a
            // sponsor that arrived mid-build is fetched, not skipped.
            let fresh: Vec<[u8; 32]> = self.mempool.read().await.fee_payers().into_iter().collect();
            for s in missing_sender_accounts(&accounts, &fresh) {
                if let Some(acct) = self.state.get_account(&s).await {
                    accounts.insert(s, (acct.nonce, acct.balance));
                }
            }
        }
        // A block must carry a CONTIGUOUS nonce sequence per sender, so the
        // expected nonce advances as transactions are accepted. Comparing
        // against the account's nonce alone would admit a gap - a transaction
        // whose nonce is ahead of the next expected one cannot execute, and
        // would be included, fail at application, and still be paid for.
        let next_nonce = std::cell::RefCell::new(accounts.clone());
        // PHASE 2: the on-chain session-key registry, cloned out BEFORE the
        // filter runs because the closure is synchronous (it must not await).
        // The filter therefore evaluates exactly what execution will: terminal
        // revocation, the registered record's ceilings, and the CUMULATIVE
        // spend across the transactions it has already selected for THIS
        // block - in `SessionSpendSim`, so two transactions of one grant can
        // never both be selected against the same remaining budget.
        let session_keys = self.state.session_keys_read().await.clone();
        let session_sim = std::cell::RefCell::new(crate::zkml::SessionSpendSim::default());
        // Rejection census for the empty-block hunt (temporary diagnostics):
        // counts WHY the filter refuses, so a live empty-with-mempool names
        // its reason instead of staying silent.
        let rej_noacct = std::cell::Cell::new(0u32);
        let rej_nonce = std::cell::Cell::new(0u32);
        let rej_funds = std::cell::Cell::new(0u32);
        let rej_session = std::cell::Cell::new(0u32);
        let rej_shard = std::cell::Cell::new(0u32);
        let rej_basefee = std::cell::Cell::new(0u32);
        // PAYMASTER: sponsored transactions skipped for an expired/over-cap/
        // off-allowlist grant or a sponsor that spent down mid-mempool land
        // here (the mid-mempool re-check: admission is not the last word).
        let rej_sponsor = std::cell::Cell::new(0u32);
        // Admission floor, mirrored in the proposer filter: the mempool
        // refuses `gas_limit < effective_floor(sender)` on every admission
        // path, so a proposer must not pack such a transaction either.
        // SKIP-only like every other filter condition (never a hard reject):
        // selection stays a pure function of the same inputs on every node,
        // so proposers cannot diverge over it. The snapshot carries the D2
        // failure penalties: a sender whose transactions keep failing at
        // apply (paying nothing) is skipped until it over-posts.
        let (base_fee, penalty_floors) = {
            let pool = self.mempool.read().await;
            (pool.base_fee, pool.penalty_snapshot())
        };
        // SHARD SCOPE: a transaction belongs to the shard it is SOURCED from.
        // That includes outbound cross-shard transfers (source == this shard,
        // target != this shard): the source shard is the one that debits the
        // sender, emits the committed CrossShardMessage and burns the value off
        // this shard; the target credits the recipient from that message. Gated
        // on `is_sharded()`, so the single-shard path (where txs carry the
        // legacy source=1/target=1 tags while the chain's block shard is 0) is
        // untouched and keeps including exactly what it always did.
        let sharded = self.shard_registry.is_sharded();
        let my_shard = self.shard_id;
        // A sender may contribute at most ONE outbound cross-shard transfer per
        // block, and it must be its first accepted transaction. The inclusion
        // proof is generated against the PRE-block account leaf, so a second
        // cross-shard transfer from the same sender (at a later nonce) could
        // not be proven against the same root. Later sends wait for the next
        // block; nothing is lost, the mempool keeps them.
        let used_senders: std::cell::RefCell<std::collections::HashSet<[u8; 32]>> =
            std::cell::RefCell::new(std::collections::HashSet::new());
        // EPOCH-SEAL PATH (the private path the proposer PREFERS): the
        // sealed transactions are unsealed (after their order was
        // committed) and placed FIRST in the block; the plain selection
        // fills the remaining slots.
        //
        // The unsealed transactions go through the SAME admission filters
        // as the plain ones (shard scope, fee floor, nonce continuity,
        // funds), so a sealed transaction can never enter a block in a
        // state the plain path would have refused. Their nonce/funds
        // effects are applied to the filter state BEFORE the plain
        // selection, so the same sender's nonce is never packed twice.
        let sealed_txs = self.sealed_proposer_path(timestamp).await;
        let mut sealed_kept: Vec<Transaction> = Vec::with_capacity(sealed_txs.len());
        for t in sealed_txs {
            if sealed_kept.len() >= MAX_BLOCK_TXS {
                break;
            }
            if sharded && !crate::sharding::tx_belongs_to_shard(&t, my_shard) {
                rej_shard.set(rej_shard.get() + 1);
                continue;
            }
            if t.check_session_policy(timestamp).is_err() {
                rej_session.set(rej_session.get() + 1);
                continue;
            }
            // PAYMASTER v1 (mid-mempool re-check, sealed path): the grant's
            // policy (expiry / allowlist / per-tx cap at the BLOCK timestamp)
            // and BOTH funding legs are re-verified here, SKIP-only. A
            // sponsor that spent its balance down after admission (the
            // economic "revoke") is skipped here and again at apply; an
            // expired grant is skipped on time, not on funds.
            if let Some(auth) = t.sponsored_grant() {
                if t.sponsor_inner_sig().len() != 64 || !t.verify_sponsor_sig(&auth) {
                    rej_sponsor.set(rej_sponsor.get() + 1);
                    continue;
                }
                let pq_surch = if t.is_pq_activation() {
                    crate::mempool::PQ_ACTIVATION_SURCHARGE_GAS
                } else {
                    0
                };
                let floor = base_fee
                    .saturating_add(penalty_floors.get(&t.from).copied().unwrap_or(0))
                    .saturating_add(pq_surch)
                    .saturating_add(t.priority_fee_per_gas);
                if t.gas_limit < floor {
                    rej_basefee.set(rej_basefee.get() + 1);
                    continue;
                }
                let fee = t.gas_limit.max(floor).saturating_add(pq_surch);
                if t.check_sponsor_policy(timestamp, fee).is_err() {
                    rej_sponsor.set(rej_sponsor.get() + 1);
                    continue;
                }
                let Some(&(expected, user_balance)) = next_nonce.borrow().get(&t.from) else {
                    rej_noacct.set(rej_noacct.get() + 1);
                    continue;
                };
                if t.nonce != expected {
                    rej_nonce.set(rej_nonce.get() + 1);
                    continue;
                }
                if user_balance < t.amount {
                    rej_funds.set(rej_funds.get() + 1);
                    continue;
                }
                let Some(&(sponsor_nonce, sponsor_balance)) =
                    next_nonce.borrow().get(&auth.sponsor)
                else {
                    rej_funds.set(rej_funds.get() + 1);
                    continue;
                };
                if sponsor_balance < fee {
                    rej_funds.set(rej_funds.get() + 1);
                    continue;
                }
                next_nonce
                    .borrow_mut()
                    .insert(t.from, (expected + 1, user_balance - t.amount));
                next_nonce
                    .borrow_mut()
                    .insert(auth.sponsor, (sponsor_nonce, sponsor_balance - fee));
                used_senders.borrow_mut().insert(t.from);
                sealed_kept.push(t);
                continue;
            }
            let Some(&(expected, balance)) = next_nonce.borrow().get(&t.from) else {
                rej_noacct.set(rej_noacct.get() + 1);
                continue;
            };
            if t.nonce != expected {
                rej_nonce.set(rej_nonce.get() + 1);
                continue;
            }
            let floor = base_fee
                .saturating_add(penalty_floors.get(&t.from).copied().unwrap_or(0))
                .saturating_add(if t.is_pq_activation() {
                    crate::mempool::PQ_ACTIVATION_SURCHARGE_GAS
                } else {
                    0
                })
                .saturating_add(t.priority_fee_per_gas);
            if t.gas_limit < floor {
                rej_basefee.set(rej_basefee.get() + 1);
                continue;
            }
            let cost =
                t.amount
                    .saturating_add(t.gas_limit)
                    .saturating_add(if t.is_pq_activation() {
                        crate::mempool::PQ_ACTIVATION_SURCHARGE_GAS
                    } else {
                        0
                    });
            if balance < cost {
                rej_funds.set(rej_funds.get() + 1);
                continue;
            }
            next_nonce
                .borrow_mut()
                .insert(t.from, (expected + 1, balance - cost));
            used_senders.borrow_mut().insert(t.from);
            sealed_kept.push(t);
        }
        // VEL-1: run plain selection through the factored predicate over
        // filter state seeded from the post-sealed locals — the same cells
        // the inline closure above shared, so the fresh path below is
        // byte-identical to the pre-factoring build.
        let fctx = PackFilterCtx::new(
            timestamp,
            sharded,
            my_shard,
            base_fee,
            penalty_floors,
            session_keys,
            next_nonce.borrow().clone(),
            session_sim.borrow().clone(),
            used_senders.borrow().clone(),
        );
        // VEL-1 bounded proposer-prebuild reuse: a cached selection for THIS
        // height is revalidated tx-by-tx against live state (same predicate,
        // cached order replays the acceptance sequence) and topped up from
        // the pool; kept txs are skipped by hash in the top-up scan. A stale
        // cache (parent changed, txs evicted/spent, sessions expired) only
        // shrinks the kept set — validity is preserved by construction and
        // receivers re-verify everything, so the worst case is a bounded
        // O(cached) revalidation before a fresh-equivalent build.
        let plain_txs: Vec<Transaction> = if sealed_kept.is_empty() {
            if let Some(cached) = self.prebuilt_selection.lock().ok().and_then(|g| {
                g.as_ref()
                    .filter(|c| c.for_height == self.hc.height)
                    .map(|c| c.txs.clone())
            }) {
                let mut kept: Vec<Transaction> = Vec::with_capacity(cached.len());
                {
                    let pool = self.mempool.read().await;
                    for t in &cached {
                        if !pool.contains(&t.compute_tx_hash()) {
                            // Evicted since the prebuild: skip, do not stall on it.
                            continue;
                        }
                        if Self::pack_filter_accept(&fctx, t) {
                            kept.push(t.clone());
                        }
                    }
                }
                let kept_hashes: HashSet<[u8; 32]> =
                    kept.iter().map(|t| t.compute_tx_hash()).collect();
                let kept_gas: u64 = kept
                    .iter()
                    .map(|t| t.gas_limit)
                    .fold(0u64, |a, g| a.saturating_add(g));
                let mut new_txs = if kept.len() < MAX_BLOCK_TXS {
                    self.mempool.read().await.select_for_block_multi(
                        MAX_BLOCK_TXS - kept.len(),
                        MAX_BLOCK_GAS.saturating_sub(kept_gas),
                        |t| {
                            if kept_hashes.contains(&t.compute_tx_hash()) {
                                return false;
                            }
                            Self::pack_filter_accept(&fctx, t)
                        },
                    )
                } else {
                    Vec::new()
                };
                let mut combined = kept;
                combined.append(&mut new_txs);
                Self::truncate_to_block_caps(&mut combined);
                combined
            } else {
                // No usable prebuild (first visit, sealed-free): fresh build
                // through the same predicate. The slot is written ONLY by
                // `prebuild_next_proposal` (never here), so a future-height
                // prebuild cached during this height's voting is never
                // evicted by a round retry at the current height.
                self.mempool.read().await.select_for_block_multi(
                    MAX_BLOCK_TXS,
                    MAX_BLOCK_GAS,
                    |t| Self::pack_filter_accept(&fctx, t),
                )
            }
        } else {
            // The sealed path conditions plain selection on its own effects,
            // which the prebuild did not see: no reuse, fresh build, no store.
            self.mempool
                .read()
                .await
                .select_for_block_multi(MAX_BLOCK_TXS, MAX_BLOCK_GAS, |t| {
                    Self::pack_filter_accept(&fctx, t)
                })
        };
        // Fold the factored predicate's census into the shared counters so
        // the rejection log below keeps its shape (sealed + plain combined).
        rej_noacct.set(rej_noacct.get() + fctx.rej_noacct.get());
        rej_nonce.set(rej_nonce.get() + fctx.rej_nonce.get());
        rej_funds.set(rej_funds.get() + fctx.rej_funds.get());
        rej_session.set(rej_session.get() + fctx.rej_session.get());
        rej_shard.set(rej_shard.get() + fctx.rej_shard.get());
        rej_basefee.set(rej_basefee.get() + fctx.rej_basefee.get());
        rej_sponsor.set(rej_sponsor.get() + fctx.rej_sponsor.get());
        // The sealed transactions come first (the proposer prefers the
        // private path), the plain ones fill the rest.
        let txs: Vec<Transaction> = sealed_kept.into_iter().chain(plain_txs).collect();
        let mempool_len = self.mempool.read().await.len();
        // Empty block with a non-empty mempool is the shape to watch (usually
        // a per-sender nonce gap: filter needs exact nonces, evict keeps
        // future ones by design): log it at info, the rest at debug.
        if txs.is_empty() && mempool_len > 0 {
            tracing::info!(
                "propose h={} r={} shard={}: path=fresh selected=0 mempool={} (noacct={} nonce={} funds={} session={} shardfilter={} basefee={} sponsor={})",
                self.hc.height,
                self.hc.round,
                self.shard_id,
                mempool_len,
                rej_noacct.get(),
                rej_nonce.get(),
                rej_funds.get(),
                rej_session.get(),
                rej_shard.get(),
                rej_basefee.get(),
                rej_sponsor.get(),
            );
        } else {
            tracing::debug!(
                "propose h={} r={} shard={}: path=fresh selected={} mempool={}",
                self.hc.height,
                self.hc.round,
                self.shard_id,
                txs.len(),
                mempool_len,
            );
        }
        // MEV blind-round unseal gate: a transaction sealed at admission must
        // unseal to EXACTLY the bytes we are about to execute. Anything whose
        // envelope fails to open or whose pool copy no longer matches the
        // ciphertext is dropped here — fail closed, before it can waste block
        // space on a body every validator would reject. Transactions admitted
        // without an envelope (restored pools) pass through unchanged.
        let txs = {
            let pool = self.mempool.read().await;
            // The unseal check is a pure function of (envelope, transaction):
            // decrypt plus a byte-compare, with no shared mutation. Large
            // blocks therefore verify it across cores while the kept set, its
            // order and every verdict stay exactly the sequential ones (the
            // parallel pass returns verdicts in input order; filtering and the
            // drop warnings below run sequentially). Small blocks skip the
            // thread-pool round trip and run the original loop.
            const PARALLEL_UNSEAL_MIN_TXS: usize = 512;
            let selected_n: usize;
            let kept = if txs.len() >= PARALLEL_UNSEAL_MIN_TXS {
                use rayon::prelude::*;
                let checked: Vec<(Transaction, crate::mev::SealVerdict)> = txs
                    .into_par_iter()
                    .map(|tx| {
                        let verdict = pool.mev.verify_pool_tx(&tx);
                        (tx, verdict)
                    })
                    .collect();
                selected_n = checked.len();
                let mut kept = Vec::with_capacity(checked.len());
                for (tx, verdict) in checked {
                    match verdict {
                        crate::mev::SealVerdict::Match | crate::mev::SealVerdict::NotSealed => {
                            kept.push(tx)
                        }
                        _ => {
                            tracing::warn!(
                                tx = %hex::encode(tx.compute_tx_hash()),
                                ?verdict,
                                "propose: dropping transaction that failed the blind-round unseal gate"
                            );
                        }
                    }
                }
                kept
            } else {
                selected_n = txs.len();
                let mut kept = Vec::with_capacity(txs.len());
                for tx in txs {
                    match pool.mev.verify_pool_tx(&tx) {
                        crate::mev::SealVerdict::Match | crate::mev::SealVerdict::NotSealed => {
                            kept.push(tx)
                        }
                        verdict => {
                            tracing::warn!(
                                tx = %hex::encode(tx.compute_tx_hash()),
                                ?verdict,
                                "propose: dropping transaction that failed the blind-round unseal gate"
                            );
                        }
                    }
                }
                kept
            };
            // Post-unseal recount (audit: blocks troubles): the census above
            // counts SELECTED, but the gate can only shrink. Without this line
            // an emptied-by-unseal block looked identical to an empty mempool.
            if kept.len() != selected_n {
                tracing::info!(
                    "propose h={} r={} shard={}: unseal gate dropped {} of {} selected",
                    self.hc.height,
                    self.hc.round,
                    self.shard_id,
                    selected_n - kept.len(),
                    selected_n
                );
            }
            kept
        };
        let prev_hash = self.finalized.last().map(|(_, h)| *h).unwrap_or([0u8; 32]);
        // TRANSACTION-ORDER COMMITMENT: computed over the EXACT ordered list
        // this block packs, and put into the block BEFORE it is signed, so
        // the quorum that votes for the block votes for its ORDER too (the
        // root is inside `compute_hash`). A validator re-computes it from the
        // proposed body and refuses a proposal that does not match, so this
        // order cannot be changed after the votes.
        let order_merkle_root = crate::mev::compute_order_merkle_root(&txs);
        // Validation-layer close of the actor-mailbox gap (propose side): the
        // engine's mailbox pass is a defensive clamp — whatever is still
        // queued when `MAX_ACTOR_MSGS_PER_BLOCK` (or the round bound) runs out
        // stays for a later block, but inboxes are NOT trie state, so that
        // leftover is invisible to the state root and two nodes can queue
        // different leftovers behind the same root. An over-cap block is
        // therefore never built: the backlog this block would add to what is
        // already queued must fit the cap, or there is no proposal this round
        // (fail closed; every validator rejects such a block below, so no
        // honest node can be split by one).
        {
            let backlog = self.pending_actor_backlog().await;
            let sends: usize = txs
                .iter()
                .map(|t| count_program_sends(&t.payload))
                .fold(0usize, |acc, n| acc.saturating_add(n));
            if backlog.saturating_add(sends) > crate::state_engine::MAX_ACTOR_MSGS_PER_BLOCK {
                tracing::warn!(
                    "propose h={}: refusing to build an over-cap actor block ({} queued + {} in block)",
                    self.hc.height,
                    backlog,
                    sends,
                );
                return None;
            }
        }
        // Cross-shard commit records for this block. In a sharded process a
        // block carries BOTH directions in the one existing `cross_shard_out`
        // field:
        //   * OUTBOUND (source == this shard): one record per outbound
        //     transfer selected above, with a Merkle proof of the sender's
        //     pre-block leaf and the pre-block balance. Applying the block
        //     debits the sender here; the record is what lets the target mint.
        //   * INBOUND (target == this shard): messages pulled from the
        //     node-local KV, filtered against what this chain already
        //     consumed, each carrying its source inclusion proof. Applying the
        //     block credits each recipient exactly once.
        let mut cross_shard_out: Vec<CrossShardMessage> = Vec::new();
        if sharded {
            // §9 2PC: from the activation height on, a NEW cross-shard
            // transfer is published as a PREPARE record instead of a plain
            // transfer. The PREPARE does not credit anybody: it escrows the
            // value on the source and asks the target to prepare, and the
            // target votes with a PREPARE-ACK. Transfers produced BEFORE the
            // activation keep running the legacy outbox/inbox/ack/bounce
            // flow to completion, so the two never interleave on one
            // transfer.
            let xpc_on = self.xpc_activation.boundary().is_some();
            let xpc_active = xpc_on && self.xpc_activation.is_active_at(self.hc.height);
            for tx in &txs {
                if !crate::sharding::tx_is_outbound_cross_shard(tx, my_shard) {
                    continue;
                }
                let balance = self
                    .state
                    .get_account(&tx.from)
                    .await
                    .map(|a| a.balance)
                    .unwrap_or(0);
                let proof = self.state.get_account_proof(&tx.from).await;
                let msg = if xpc_active {
                    CrossShardMessage::new_xpc(
                        crate::xshard2pc::XPC_PREPARE,
                        my_shard,
                        tx.target_shard,
                        tx.clone(),
                        state_root,
                        prev_hash,
                        proof,
                    )
                    .with_source_balance(balance)
                } else {
                    CrossShardMessage::new(
                        my_shard,
                        tx.target_shard,
                        tx.clone(),
                        state_root,
                        prev_hash,
                        proof,
                    )
                    .with_source_balance(balance)
                };
                cross_shard_out.push(msg);
            }
            if let Some(transport) = &self.cross_shard {
                let mut inbound = transport.fetch_cross_shard_inbound(my_shard).await;
                // Deterministic order, independent of KV enumeration order.
                inbound.sort_by_key(CrossShardKey::of);
                let mut engine_hit_ids: Vec<[u8; 32]> = Vec::new();
                for msg in inbound {
                    if !msg.is_inbound_for(my_shard) {
                        continue;
                    }
                    let key = CrossShardKey::of(&msg);
                    if self.consumed_cross_shard.contains(&key) {
                        continue;
                    }
                    // Belt beyond the runtime mirrors: the PERSISTED engine
                    // set survives restarts (audit F-I) while the mirrors may
                    // be empty (fresh process). If the engine already credited
                    // this key, prune it from the mailbox so no future propose
                    // wastes a round on it, and skip it now. Without the prune
                    // a restarted proposer would re-propose it forever (its
                    // mirrors are empty) while every apply refuses it.
                    if self.state.is_cross_shard_consumed(&key).await {
                        engine_hit_ids.push(msg.msg_id);
                        continue;
                    }
                    // §5 M3 kind-dispatched admission: transfers prove
                    // inclusion against the source root; acks/bounces prove
                    // linkage to a committed outbound on this chain (plus the
                    // height timeout for bounces). Anything else fails closed.
                    if msg.is_ack() || msg.is_bounce() {
                        if !self.control_linkage_ok(&msg, self.hc.height) {
                            continue;
                        }
                    } else if msg.is_xpc() {
                        // §9 2PC admission. Every 2PC record carries a proof of
                        // the PEER's committed 2PC state (the peer is the
                        // message's `source_shard`), anchored to a locally
                        // finalized header of that peer shard - the same C1
                        // anchor the legacy flow uses, applied to the 2PC
                        // state instead of the account leaf. A record whose
                        // proof or anchor does not check out is refused.
                        if !xpc_on {
                            continue;
                        }
                        if !self.xpc_admissible(&msg) {
                            continue;
                        }
                    } else if msg.is_transfer() {
                        // C1 anchored (not just proof-checked): the root must
                        // be a locally-finalized source header, or the message
                        // waits for a later block (NOT-READY, not verified).
                        if !self.verify_cross_shard_anchored(&msg) {
                            continue;
                        }
                    } else {
                        continue;
                    }
                    // Stale after completion: the transaction already acked or
                    // bounced (e.g. a late duplicate lingering in the KV).
                    if self
                        .completed_cross_shard
                        .contains(&msg.tx.compute_tx_hash())
                    {
                        continue;
                    }
                    if cross_shard_out.iter().any(|m| m.msg_id == msg.msg_id) {
                        continue;
                    }
                    cross_shard_out.push(msg);
                }
                if !engine_hit_ids.is_empty() {
                    transport.prune_consumed(my_shard, &engine_hit_ids).await;
                }
                // §9 2PC: the OUTBOUND records of the transfers this shard
                // owns are a pure function of its committed 2PC state:
                //   * the TARGET of a PREPARED transfer answers with a
                //     PREPARE-ACK (its vote: "I am prepared, I will credit
                //     on the COMMIT"),
                //   * the TARGET of an ABORTED transfer answers with an
                //     ABORT-ACK (its authorisation for the source's refund),
                //   * the SOURCE of a COMMITTED transfer sends the COMMIT,
                //   * the SOURCE of a PREPARED transfer re-publishes the
                //     PREPARE (on the re-publication cadence) while it waits
                //     for the vote,
                //   * the SOURCE of a PREPARED transfer whose prepare window
                //     elapsed asks the target to abort.
                // Deriving them from the committed state (and not from a
                // message) is what makes the protocol RECOVERABLE: a node
                // that crashed mid-2PC re-derives exactly the same records
                // and reaches the same decision.
                if xpc_on {
                    let records: Vec<crate::xshard2pc::XpcRecord> =
                        self.xpc_records.values().cloned().collect();
                    for rec in records {
                        // The record decides, per side, what this shard owes
                        // the peer: the source owes a COMMIT (or an
                        // ABORT-REQUEST), the target owes a vote.
                        let (phase, from_shard, to_shard) = if rec.source_shard == my_shard {
                            match crate::xshard2pc::source_action(&rec, self.hc.height) {
                                crate::xshard2pc::SourceAction::Commit => (
                                    crate::xshard2pc::XPC_COMMIT,
                                    rec.source_shard,
                                    rec.target_shard,
                                ),
                                crate::xshard2pc::SourceAction::AbortRequest => (
                                    crate::xshard2pc::XPC_ABORT_REQUEST,
                                    rec.source_shard,
                                    rec.target_shard,
                                ),
                                crate::xshard2pc::SourceAction::Reprepare => {
                                    // The PREPARE is re-published on the
                                    // cadence only: the opening PREPARE went
                                    // out with the block that escrowed the
                                    // value, and the re-publication exists
                                    // only for the case where it never
                                    // arrived. Its proof is the source's
                                    // PREPARED leaf (the escrow), not the
                                    // sender's account leaf (which the
                                    // escrow already invalidated).
                                    if !crate::xshard2pc::should_reprepare(&rec, self.hc.height) {
                                        continue;
                                    }
                                    (
                                        crate::xshard2pc::XPC_PREPARE,
                                        rec.source_shard,
                                        rec.target_shard,
                                    )
                                }
                                crate::xshard2pc::SourceAction::Idle => continue,
                            }
                        } else if rec.target_shard == my_shard {
                            match crate::xshard2pc::target_action(&rec) {
                                crate::xshard2pc::TargetAction::PrepareAck => (
                                    crate::xshard2pc::XPC_PREPARE_ACK,
                                    rec.target_shard,
                                    rec.source_shard,
                                ),
                                crate::xshard2pc::TargetAction::AbortAck => (
                                    crate::xshard2pc::XPC_ABORT_ACK,
                                    rec.target_shard,
                                    rec.source_shard,
                                ),
                                crate::xshard2pc::TargetAction::Idle => continue,
                            }
                        } else {
                            continue;
                        };
                        // The proof of THIS shard's committed 2PC state: the
                        // peer verifies it against the peer's own state root
                        // and the anchor, so the vote cannot be forged.
                        let proof = self.state.get_xpc_proof(&rec.tx_hash).await;
                        if proof.is_none() {
                            continue;
                        }
                        let msg = CrossShardMessage::new_xpc(
                            phase,
                            from_shard,
                            to_shard,
                            rec.tx.clone(),
                            state_root,
                            prev_hash,
                            proof,
                        );
                        if cross_shard_out.iter().any(|m| m.msg_id == msg.msg_id) {
                            continue;
                        }
                        cross_shard_out.push(msg);
                    }
                }
                // §5 M3 timeout bounces: outbounds this chain produced that
                // never completed and aged past the height timeout are
                // refunded by committing a bounce-back record. Deterministic
                // in (tx hash, height): every node builds the same record for
                // the same chain, and `validate_proposal` re-checks the rule.
                //
                // §9 2PC: a transfer that runs the 2PC NEVER bounces. Its
                // abort is a two-sided decision (the target must confirm it
                // never prepared), and the unilateral timeout bounce is
                // exactly the double-spend the 2PC removes.
                let xpc_owned: std::collections::HashSet<[u8; 32]> = if xpc_on {
                    self.xpc_records.keys().copied().collect()
                } else {
                    std::collections::HashSet::new()
                };
                let mut expired: Vec<([u8; 32], Transaction)> = self
                    .produced_cross_shard
                    .iter()
                    .filter(|(tx_hash, (_, hp))| {
                        !self.completed_cross_shard.contains(*tx_hash)
                            && !xpc_owned.contains(*tx_hash)
                            && crate::sharding::bounce_eligible(*hp, self.hc.height)
                    })
                    .map(|(tx_hash, (tx, _))| (*tx_hash, tx.clone()))
                    .collect();
                expired.sort_by_key(|(tx_hash, _)| *tx_hash);
                for (tx_hash, tx) in expired {
                    if cross_shard_out
                        .iter()
                        .any(|m| m.tx.compute_tx_hash() == tx_hash)
                    {
                        continue;
                    }
                    cross_shard_out.push(CrossShardMessage::new_bounce(tx, prev_hash));
                }
            }
        }
        let timestamp = if let Some(parent_ts) = self
            .blocks
            .get(&prev_hash)
            .map(|b| b.timestamp)
            .or_else(|| {
                self.last_decision.as_ref().and_then(|(h, b, _)| {
                    if *h + 1 == self.hc.height && b.compute_hash() == prev_hash {
                        Some(b.timestamp)
                    } else {
                        None
                    }
                })
            }) {
            timestamp
                .min(parent_ts.saturating_add(MAX_TIMESTAMP_JUMP_SECS))
                .max(parent_ts)
        } else {
            timestamp
        };
        // The EPOCH-KEY commitment: the block pins the MEV epoch key that the
        // sealed transactions of this epoch are encrypted to (see
        // `crate::mev_epoch`). It is the chain's word on WHICH key the
        // network uses for this epoch: a wallet (or a light client) takes the
        // key from a full node and checks it against the block, so a single
        // node cannot hand out a key the network never agreed on.
        //
        // The commitment is the one of OUR epoch material, and only when the
        // material belongs to THIS block's epoch: a node whose DKG has not
        // completed (or whose view of the validator set diverged) commits to
        // nothing rather than to a key the network may not use.
        let epoch_key_commitment = {
            let pool = self.mempool.read().await;
            let manager = &pool.mev_seal;
            if manager.epoch == crate::mev_epoch::epoch_of_height(self.hc.height) {
                manager.epoch_commitment().unwrap_or([0u8; 32])
            } else {
                [0u8; 32]
            }
        };
        let mut block = Block {
            shard_id: self.shard_id,
            height: self.hc.height,
            prev_hash,
            state_root,
            transactions: txs,
            cross_shard_out,
            timestamp,
            proposer: self.id,
            validator_signatures: vec![],
            precommit_qc: None,
            // W10.5 CANONICAL DOWNTIME EVIDENCE: the QC that decided the
            // parent height, chosen once here — every applier attributes the
            // same evidence and converges. `None` only when this node knows
            // no parent decision yet (genesis child / fresh restore); see
            // `check_last_qc_evidence` for why validators accept that.
            last_qc: self.decided_parent_qc(),
            // SHARD-HEAD COMMITMENTS (TON `shard_hashes`): a masterchain block
            // publishes the latest finalized header of every workchain shard,
            // so a cross-shard state root becomes provable from a
            // masterchain block alone. A workchain block commits to nothing
            // but its own body.
            shard_headers: self.collect_shard_header_commitments(),
            // The order commitment over the exact list packed above.
            order_merkle_root,
            // The commitment to the epoch key this block's epoch uses.
            epoch_key_commitment,
            // THE EPOCH-MMR commitment (V5 Tier-2): the MMR root over the
            // previous epoch's finalized block hashes on a masterchain
            // epoch-boundary height, zero everywhere else (see
            // `epoch_mmr_commitment`). Zero keeps the legacy hash
            // byte-for-byte; non-zero is covered by the block hash the
            // quorum signs.
            mmr_epoch_root: self.epoch_mmr_commitment(),
        };
        // Sign the proposer slot with whichever signer is configured. `sign_block`
        // signs with an in-process key, so when a remote signer is present the
        // signature is produced out of process and pushed directly.
        // One hash for both the proposer signature and the order-commit /
        // block-store keys below: `compute_hash` intentionally excludes
        // `validator_signatures` (and `precommit_qc`), so pushing our own
        // signature cannot move it. Recomputing it would re-hash all 10k
        // transaction hashes (~25ms at MAX_BLOCK_TXS) for an identical value.
        let proposal_msg = block.compute_hash();
        if let Some(sig) = self.sign_bytes(&proposal_msg) {
            block.validator_signatures.push((self.id, sig));
        } else {
            return None; // no signer, no proposal
        }
        let fk_ref = self.falcon_signing_key();
        if let Some(fk) = fk_ref {
            let falcon_sig = fk.sign(&proposal_msg);
            let falcon_id = fk.validator_id();
            block.validator_signatures.push((falcon_id, falcon_sig));
        }
        // Proposer-side pre-gossip size check (packing/visibility only, no
        // consensus change): the `select_multi` wire estimate (~24MB) leaves
        // headroom under `MAX_CONSENSUS_MSG` (32MB), but it is an ESTIMATE, so
        // a block can still encode oversize and die in `broadcast_singles`
        // (silently dropped, height stalls with a full mempool). Check the
        // EXACT `ConsensusMsg::Proposal` encoding here and fall back to a
        // smaller block — drop fattest txs first — instead of proposing
        // un-sendable bytes. Trimming only shrinks `transactions` (and the
        // outbound cross-shard records that name dropped txs); it never
        // reorders, never touches apply/consensus logic.
        {
            let cap = crate::consensus_net::MAX_CONSENSUS_MSG;
            let mut encoded_len = crate::consensus_net::ConsensusMsg::Proposal {
                height: self.hc.height,
                round: self.hc.round,
                block: block.clone(),
            }
            .encode()
            .map(|b| b.len())
            .unwrap_or(usize::MAX);
            if encoded_len > cap {
                let orig_txs = block.transactions.len();
                // Fattest-first: indices by descending estimated wire bytes.
                let mut order: Vec<usize> = (0..block.transactions.len()).collect();
                order.sort_by_key(|&i| {
                    std::cmp::Reverse(Mempool::estimate_tx_wire_bytes(&block.transactions[i]))
                });
                let mut drop: Vec<bool> = vec![false; block.transactions.len()];
                let mut dropped = 0usize;
                for &i in &order {
                    if encoded_len <= cap {
                        break;
                    }
                    drop[i] = true;
                    dropped += 1;
                    // Re-encode the candidate survivor set each drop. O(drops)
                    // encodes, but this path only runs when the estimate
                    // already failed, i.e. essentially never on healthy blocks.
                    let kept: Vec<crate::sharding::Transaction> = block
                        .transactions
                        .iter()
                        .enumerate()
                        .filter(|(j, _)| !drop[*j])
                        .map(|(_, t)| t.clone())
                        .collect();
                    let probe = Block {
                        transactions: kept,
                        ..block.clone()
                    };
                    encoded_len = crate::consensus_net::ConsensusMsg::Proposal {
                        height: self.hc.height,
                        round: self.hc.round,
                        block: probe,
                    }
                    .encode()
                    .map(|b| b.len())
                    .unwrap_or(usize::MAX);
                }
                if encoded_len > cap {
                    // Even empty-of-txs is un-sendable (giant inbound
                    // cross-shard section). Fail closed: no proposal this
                    // round rather than bytes no peer can receive.
                    tracing::error!(
                        "propose h={} r={}: pre-gossip fallback FAILED ({} txs, {} bytes > {} cap even empty); proposing nothing",
                        self.hc.height,
                        self.hc.round,
                        orig_txs,
                        encoded_len,
                        cap,
                    );
                    return None;
                }
                let dropped_hashes: std::collections::HashSet<[u8; 32]> = block
                    .transactions
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| drop[*j])
                    .map(|(_, t)| t.compute_tx_hash())
                    .collect();
                let mut kept_txs = Vec::with_capacity(orig_txs - dropped);
                for (j, t) in block.transactions.into_iter().enumerate() {
                    if !drop[j] {
                        kept_txs.push(t);
                    }
                }
                block.transactions = kept_txs;
                // Outbound records naming a dropped tx would burn value with
                // nobody able to claim it (validate rejects tx-without-record
                // only in the outbound direction; the reverse — record without
                // tx — is equally unclaimable). Prune them with the txs.
                block
                    .cross_shard_out
                    .retain(|m| !dropped_hashes.contains(&m.tx.compute_tx_hash()));
                // The body changed, so the ORDER COMMITMENT must be recomputed
                // over the surviving (still ordered) list BEFORE the block is
                // re-signed below: the root is inside the signed hash, so a
                // stale root would make the proposal fail its own validators'
                // order check.
                block.order_merkle_root =
                    crate::mev::compute_order_merkle_root(&block.transactions);
                // The body changed, so the proposer signature must be remade
                // over the new hash (same rule as the fresh path above).
                block.validator_signatures.clear();
                let new_msg = block.compute_hash();
                if let Some(sig) = self.sign_bytes(&new_msg) {
                    block.validator_signatures.push((self.id, sig));
                } else {
                    return None;
                }
                let fk_ref = self.falcon_signing_key();
                if let Some(fk) = fk_ref {
                    let falcon_sig = fk.sign(&new_msg);
                    let falcon_id = fk.validator_id();
                    block.validator_signatures.push((falcon_id, falcon_sig));
                }
                let final_len = crate::consensus_net::ConsensusMsg::Proposal {
                    height: self.hc.height,
                    round: self.hc.round,
                    block: block.clone(),
                }
                .encode()
                .map(|b| b.len())
                .unwrap_or(usize::MAX);
                tracing::error!(
                    "propose h={} r={}: pre-gossip fallback SHRANK block {} -> {} txs ({} bytes now, cap {}); dropped fattest first, survivors kept in order",
                    self.hc.height,
                    self.hc.round,
                    orig_txs,
                    block.transactions.len(),
                    final_len,
                    cap,
                );
            }
        }
        // MEV order commitment at build: record (and sign) the exact execution
        // order BEFORE the block is proposed or voted on. `try_finalize`
        // re-verifies this commitment against the block it is about to apply,
        // so this node never executes an order it did not commit to build.
        // NOTE: recomputed AFTER the pre-gossip fallback above (which may have
        // shrunk the body and re-signed it); `compute_hash` excludes the
        // signatures, so this equals `proposal_msg` on the untrimmed path.
        let bh = block.compute_hash();
        {
            let mut pool = self.mempool.write().await;
            pool.mev.commit_block_order(
                self.hc.height,
                bh,
                &block.transactions,
                std::slice::from_ref(&self.key),
            );
        }
        self.blocks.insert(bh, block.clone());
        self.hc.receive_proposal(self.id, bh).ok()?;
        Some(block)
    }

    /// Validate a proposed block before accepting/prevoting it.
    /// SECURITY: rejects wrong height/proposer/prev_hash, oversized blocks and
    /// transactions with bad signatures.
    ///
    /// `expected_state_root` is OUR current root. The block header commits to the
    /// state it builds on - the root after the previous block, which is the
    /// standard convention and is what lets a chain be walked without replaying
    /// it - so that value is checkable, and it was not being checked at all. A
    /// proposer could put any root in the header and every validator accepted the
    /// block, which left the whole state commitment decorative on the live path.
    /// Fail-closed block-timestamp gate (A3): refuse on a bad or missing
    /// timestamp using deterministic rules only.
    ///
    /// The parent timestamp resolves from, in order: (1) the stored parent
    /// body (`blocks[prev_hash]`, the common live case); (2) `last_decision`
    /// when it names exactly this parent (hash AND height match, so a stale
    /// decision from an older height can never vouch for a new parent);
    /// (3) the zero parent of a height-1 block (`prev_hash == [0; 32]`
    /// anchors at 0). Anything else — a parent this node never saw — is
    /// refused rather than skipped: accepting first and hoping the parent
    /// turns up is the fail-open this closes.
    ///
    /// Pure function of (`self.blocks`, `self.last_decision`, `block`): no
    /// wall clock, so every validator derives the same verdict. Called on the
    /// proposal path AND the adopt path, so a Byzantine commit cannot smuggle
    /// past the decision boundary a timestamp no proposer could publish.
    fn check_block_timestamp(&self, block: &Block) -> Result<(), String> {
        if block.height == 0 {
            return Ok(()); // genesis carries no parent; nothing to be monotone against
        }
        if block.timestamp == 0 {
            return Err("proposal: missing block timestamp".to_string());
        }
        // Whether the parent resolved to the zero-genesis anchor rather than a
        // seen body: the first block after genesis legitimately jumps from the
        // anchor to the proposer's wall clock (billions of seconds), so the
        // forward jump bound below cannot apply to it. Monotonicity still
        // holds (any non-zero timestamp is past the anchor).
        let mut from_genesis_anchor = false;
        let parent_ts = self
            .blocks
            .get(&block.prev_hash)
            .map(|b| b.timestamp)
            .or_else(|| {
                self.last_decision.as_ref().and_then(|(h, b, _)| {
                    if *h + 1 == block.height && b.compute_hash() == block.prev_hash {
                        Some(b.timestamp)
                    } else {
                        None
                    }
                })
            })
            .or_else(|| {
                if block.height == 1 && block.prev_hash == [0u8; 32] {
                    from_genesis_anchor = true;
                    Some(0)
                } else {
                    None
                }
            });
        let Some(parent_ts) = parent_ts else {
            return Err("proposal: unknown parent timestamp (fail-closed)".to_string());
        };
        if block.timestamp < parent_ts {
            return Err("proposal: timestamp moved backwards".to_string());
        }
        if !from_genesis_anchor
            && block.timestamp > parent_ts.saturating_add(MAX_TIMESTAMP_JUMP_SECS)
        {
            return Err("proposal: timestamp too far ahead of parent".to_string());
        }
        Ok(())
    }

    /// The CONSENSUS-enforced transaction-order commitment check.
    ///
    /// The block carries the order Merkle root over its own transaction list
    /// (`Block::order_merkle_root`) and that root is inside the SIGNED block
    /// hash, so the BFT quorum that voted for the block voted for its ORDER
    /// as well. This check re-computes the root from the body on the wire and
    /// refuses anything that does not match: a proposer therefore cannot
    /// reorder a block after it has been signed and voted on, which is the
    /// whole point of committing to the order.
    ///
    /// PURE: a function of the block body alone (no state, no clock, no
    /// node-local key), so the proposer and every validator derive the SAME
    /// verdict from the SAME body. An EMPTY block commits to nothing and
    /// carries the all-zero root, which is what the recomputation returns for
    /// it.
    ///
    /// COORDINATED ROLLOUT: this is a hard rule, so every validator must run
    /// it before it votes — a block whose order root does not match its body
    /// is refused, not warned about.
    ///
    /// Cache-key soundness (STAB fix): `Block::compute_hash` deliberately
    /// EXCLUDES transaction signatures (they sign the hash), so two bodies
    /// that differ ONLY in tx signatures share a block hash. The batch-verify
    /// verdict is a pure function of exactly those signatures, so keying it
    /// on the block hash alone aliases a tampered body onto the genuine
    /// body's ACCEPT verdict (caught by
    /// `proposal_validation_rejects_tampering`). The key below commits to
    /// the signatures too: hashing 64 B x N is memcmp-cheap next to N
    /// Ed25519 verifies, so the verify-once speedup is kept and the verdict
    /// is a pure function of the key.
    fn batch_verify_cache_key(block: &Block) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(block.compute_hash());
        h.update((block.transactions.len() as u32).to_be_bytes());
        for tx in &block.transactions {
            h.update((tx.signature.len() as u32).to_be_bytes());
            h.update(&tx.signature);
        }
        h.finalize().into()
    }
    /// Same aliasing class as above: `compute_hash` excludes
    /// `validator_signatures` (evidence ABOUT the block, decided after the
    /// hash is fixed), so a body with a FORGED proposer signature shares the
    /// genuine block hash. The proposer-sig verdict is a pure function of
    /// (block hash, proposer, validator_signatures), which is exactly what
    /// this key commits to (`proposer` is hashed already; it is mixed in
    /// again so the key is self-describing).
    fn proposer_sig_cache_key(block: &Block) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(block.compute_hash());
        h.update(block.proposer);
        h.update((block.validator_signatures.len() as u32).to_be_bytes());
        for (id, sig) in &block.validator_signatures {
            h.update(id);
            h.update((sig.len() as u32).to_be_bytes());
            h.update(sig);
        }
        h.finalize().into()
    }
    fn check_order_commitment(&self, block: &Block) -> Result<(), String> {
        // STAB: per-block-hash cache — the root is a pure function of the body,
        // so repeat validations of the same block (round retries, demanded
        // re-propose, adopt) hit O(1) instead of re-hashing O(txs).
        let bh = block.compute_hash();
        if let Some(cached) = self
            .order_root_cache
            .lock()
            .ok()
            .and_then(|g| g.get(&bh).copied())
        {
            if block.order_merkle_root != cached {
                return Err(format!(
                    "proposal: transaction order does not match the committed order root (block {} != recomputed {})",
                    hex::encode(block.order_merkle_root),
                    hex::encode(cached)
                ));
            }
            return Ok(());
        }
        let expected = crate::mev::compute_order_merkle_root(&block.transactions);
        if let Ok(mut g) = self.order_root_cache.lock() {
            if g.len() > 1024 {
                g.clear();
            }
            g.insert(bh, expected);
        }
        if block.order_merkle_root != expected {
            return Err(format!(
                "proposal: transaction order does not match the committed order root (block {} != recomputed {})",
                hex::encode(block.order_merkle_root),
                hex::encode(expected)
            ));
        }
        Ok(())
    }

    /// CANONICAL DOWNTIME EVIDENCE (W10.5): verify the QC the proposer
    /// embedded for the PARENT height (`block.last_qc`).
    ///
    /// The transition attributes downtime for height H-1 from the certificate
    /// embedded in block H — chosen once, by H's proposer — so every node
    /// that applies the block attributes identically, no matter which quorate
    /// QC subset its own vote assembly observed (the 2026-10-23 #292786 fork:
    /// {A,C} vs {A,B,C} both passed the same quorum but bumped different
    /// `missed` counters and split the state root). The evidence is covered
    /// by the block hash, and this check pins it before any vote:
    /// * height linkage: evidence for exactly H-1, naming the parent hash;
    /// * finality shape: a precommit quorum (prevotes never prove finality);
    /// * quorum under the set IN FORCE AT H-1 (never the live set), with the
    ///   exact power shortfall on refusal.
    ///
    /// `None` is accepted ONLY when this node knows no decision for H-1
    /// (genesis child, or a node restored/healed without finalizing since —
    /// it cannot distinguish "predates evidence" from "withheld evidence",
    /// so it must not veto what the knowledgeable quorum accepts; the
    /// applier then skips attribution for that height — deterministic, since
    /// `None` is canonical bytes). A node that DID finalize H-1 (its
    /// `last_decision` names it) rejects `None` outright: the evidence exists
    /// and omitting it would silently suppress one height of downtime
    /// accounting.
    fn check_last_qc_evidence(&self, block: &Block) -> Result<(), String> {
        let Some(parent_h) = block.height.checked_sub(1) else {
            return Ok(());
        };
        let Some(qc) = &block.last_qc else {
            let knows_parent_decision = self
                .last_decision
                .as_ref()
                .is_some_and(|(h, b, _)| *h == parent_h && b.compute_hash() == block.prev_hash);
            if knows_parent_decision {
                return Err(format!(
                    "proposal: block at height {} omits the downtime evidence for decided height {parent_h}",
                    block.height
                ));
            }
            return Ok(());
        };
        if qc.height != parent_h {
            return Err(format!(
                "proposal: downtime evidence is for height {} not parent {parent_h}",
                qc.height
            ));
        }
        if qc.block_hash != Some(block.prev_hash) {
            return Err("proposal: downtime evidence names a different parent block".to_string());
        }
        if qc.kind != crate::consensus::VoteKind::Precommit {
            return Err("proposal: downtime evidence is not a precommit quorum".to_string());
        }
        // STAB verify-once: the QC power is a pure function of (block bytes,
        // validator history at parent_h). Round retries re-validate the same
        // block; the second+ visits hit O(1) instead of re-running
        // verify-grade `signers_set` crypto. Failures are NOT cached (a
        // history advance could turn a weak QC into a passing one).
        let bh = block.compute_hash();
        if let Some((ok, _)) = self
            .qc_power_cache
            .lock()
            .ok()
            .and_then(|g| g.get(&bh).copied())
        {
            if ok {
                return Ok(());
            }
        }
        let set = self.validator_set_for_height(parent_h);
        let signed = set.qc_signed_power(qc);
        let required = set.quorum_power();
        if signed < required {
            crate::metrics::global().inc_weak_qc_refused();
            return Err(format!(
                "proposal: downtime evidence carries only {signed} of {required} required power at height {parent_h}"
            ));
        }
        if let Ok(mut g) = self.qc_power_cache.lock() {
            if g.len() > 1024 {
                g.clear();
            }
            g.insert(bh, (true, signed));
        }
        Ok(())
    }

    /// The downtime-evidence QC to embed in a proposal for the current
    /// height: the QC that decided the parent (H-1), known from the last
    /// decision this node recorded (local finalize AND adopt both stash it).
    ///
    /// `None` when this node knows no parent decision yet: the genesis child
    /// (nothing decided before height 1), or a node restored/healed without
    /// finalizing since. Validators that DO know the parent decision reject
    /// the omission; validators that do not accept it and skip attribution
    /// for that height. Either way the verdict is a pure function of agreed
    /// inputs, so no fork.
    fn decided_parent_qc(&self) -> Option<crate::consensus::QuorumCertificate> {
        let h = self.hc.height.checked_sub(1)?;
        self.last_decision
            .as_ref()
            .and_then(|(dh, _, qc)| if *dh == h { Some(qc.clone()) } else { None })
    }

    /// Round-INDEPENDENT proposal checks: everything `validate_proposal` verifies
    /// except which round's proposer slot the block claims. Used by `on_proposal`
    /// to prove a block is genuine (signed by its declared proposer, building on
    /// our state) BEFORE any round alignment happens: aligning first and asking
    /// questions later would let a forged envelope shove us +64 rounds per
    /// message, wiping our live proposal each time -- a round-DoS.
    fn validate_proposal_unaligned(
        &self,
        block: &Block,
        expected_state_root: [u8; 32],
    ) -> Result<(), String> {
        if block.height != self.hc.height {
            return Err("proposal: wrong height".to_string());
        }
        // TIMESTAMP VALIDITY (A3, fail-closed): the proposer timestamp is
        // hashed into the block and used as the VM's "now" (session expiry,
        // unbonding, order stamps) — an unbounded proposer could skew all of
        // them. Both bounds are deterministic functions of (parent, child):
        // (a) monotone vs the parent block's timestamp (agreed state, no
        // clock involved); (b) at most MAX_TIMESTAMP_JUMP_SECS ahead of the
        // parent. There is deliberately NO wall-clock read here: a
        // `now_secs()` bound makes the verdict node-local (two validators
        // with skewed clocks disagree about the same block), and there is no
        // grace or skip path — a bad or unresolvable timestamp is refused.
        self.check_block_timestamp(block)?;
        // SHARD SCOPE (gated): in a multi-shard process each consensus instance
        // only accepts blocks for its own shard, and only transactions it OWNS
        // (`source_shard == this shard`). That covers same-shard transfers and
        // OUTBOUND cross-shard transfers; the destination receives value through
        // a committed consumption record, never through `transactions`.
        // Single-shard mode skips all of this, so the historical masterchain
        // blocks that carry source=1/target=1 txs still validate.
        if self.shard_registry.is_sharded() {
            if block.shard_id != self.shard_id {
                return Err(format!(
                    "proposal: wrong shard {} (expected {})",
                    block.shard_id, self.shard_id
                ));
            }
            if let Some(bad) = block
                .transactions
                .iter()
                .find(|t| !crate::sharding::tx_belongs_to_shard(t, self.shard_id))
            {
                return Err(format!(
                    "proposal: transaction targets shard {} not {}",
                    bad.source_shard, self.shard_id
                ));
            }
            // Cross-shard commit consistency: every OUTBOUND message must name a
            // transaction actually in this block (so the debit happens), and
            // every INBOUND consumption record must prove inclusion against the
            // source root and must not be a replay of a message already
            // credited on this chain.
            for msg in &block.cross_shard_out {
                if msg.is_outbound_for(self.shard_id) {
                    if msg.is_xpc() {
                        // §9 2PC: the outbound 2PC records are derived from
                        // this shard's committed 2PC state (not from a
                        // transaction in this block), so the rule is the
                        // re-derivation of that state, not "the transaction
                        // is in the block".
                        if !self.xpc_outbound_admissible(msg, block) {
                            return Err(format!(
                                "proposal: cross-shard 2PC record {} is not backed by this shard's 2PC state",
                                hex::encode(&msg.msg_id[..8])
                            ));
                        }
                        continue;
                    }
                    let tx_present = block
                        .transactions
                        .iter()
                        .any(|t| t.compute_tx_hash() == msg.tx.compute_tx_hash());
                    if !tx_present {
                        return Err(
                            "proposal: outbound cross-shard message has no transaction in the block"
                                .to_string(),
                        );
                    }
                    continue;
                }
                if msg.is_inbound_for(self.shard_id) {
                    let key = CrossShardKey::of(msg);
                    if self.consumed_cross_shard.contains(&key) {
                        return Err(format!(
                            "proposal: replayed cross-shard message {}",
                            hex::encode(&msg.msg_id[..8])
                        ));
                    }
                    // §5 M3 kind-dispatched validation (mirrors `propose`):
                    // transfers prove inclusion; acks/bounces prove linkage
                    // to a committed outbound (+ timeout for bounces); a
                    // record for an already-completed transaction is stale.
                    if msg.is_ack() || msg.is_bounce() {
                        if !self.control_linkage_ok(msg, block.height) {
                            return Err(format!(
                                "proposal: cross-shard ack/bounce {} fails linkage/timeout",
                                hex::encode(&msg.msg_id[..8])
                            ));
                        }
                    } else if msg.is_xpc() {
                        // §9 2PC: the inbound record must carry a valid proof
                        // of the PEER's committed 2PC state, anchored to a
                        // finalized header of the peer shard.
                        if !self.xpc_admissible(msg) {
                            return Err(format!(
                                "proposal: cross-shard 2PC record {} fails its proof or anchor",
                                hex::encode(&msg.msg_id[..8])
                            ));
                        }
                    } else if msg.is_transfer() {
                        if !self.verify_cross_shard_anchored(msg) {
                            return Err(format!(
                                "proposal: cross-shard message {} fails anchored inclusion (uncommitted source root or unfinalized source block)",
                                hex::encode(&msg.msg_id[..8])
                            ));
                        }
                    } else {
                        return Err(format!(
                            "proposal: cross-shard message {} has an unknown kind",
                            hex::encode(&msg.msg_id[..8])
                        ));
                    }
                    if self
                        .completed_cross_shard
                        .contains(&msg.tx.compute_tx_hash())
                    {
                        return Err(format!(
                            "proposal: cross-shard message {} is for a completed transfer",
                            hex::encode(&msg.msg_id[..8])
                        ));
                    }
                }
            }
            // The reverse direction too: an outbound cross-shard transaction
            // with no committed message would burn the value with nobody able
            // to claim it. Require the pair.
            for tx in &block.transactions {
                if !crate::sharding::tx_is_outbound_cross_shard(tx, self.shard_id) {
                    continue;
                }
                let committed = block.cross_shard_out.iter().any(|m| {
                    m.is_outbound_for(self.shard_id)
                        && m.tx.compute_tx_hash() == tx.compute_tx_hash()
                });
                if !committed {
                    return Err(
                        "proposal: outbound cross-shard transaction has no committed message"
                            .to_string(),
                    );
                }
            }
        }
        if block.state_root != expected_state_root {
            // CONSENSUS-SAFETY DIVERGENCE (2026-10-22 #288000): the quorum can
            // finalize a block hash WITHOUT agreeing on the post-state — the
            // hash commits to the PRE-state root only. When two nodes compute
            // different post-states for the same finalized hash, the next
            // proposals carry the proposer's post-state root and the other
            // side lands exactly here: same chain, same height, different
            // state, finalization stalled. This branch is the ONLY
            // in-protocol witness of that split, so it is LOUD on purpose: a
            // structured error log with a greppable DIVERGENCE tag (the
            // watchdog pages on it) plus a monotonic counter for dashboards.
            // Resync is deliberately NOT automatic here: picking which side is
            // canonical needs an operator with the offline `stelops diverge`
            // comparison, never a machine guessing from one side.
            let their_root = hex::encode(block.state_root);
            let our_root = hex::encode(expected_state_root);
            tracing::error!(
                target: "stellereum::consensus",
                "DIVERGENCE height={} block={} proposer={} their_root={} our_root={} \
                 same finalized hash, different post-state: execution diverged, resync the minority side from a canonical snapshot",
                block.height,
                hex::encode(block.compute_hash()),
                hex::encode(block.proposer),
                their_root,
                our_root,
            );
            crate::metrics::global().inc_divergence();
            return Err(format!(
                "proposal: state root {their_root} does not match our state {our_root}"
            ));
        }
        // SHARD-HEAD COMMITMENTS (TON `shard_hashes`): the masterchain's
        // published shard heads must be canonical and must not contradict a
        // header this process already finalized. The commitment itself is
        // covered by the block hash, so the quorum that signs the block
        // stands behind it.
        self.check_shard_header_commitments(block)?;
        // EPOCH-MMR COMMITMENT (V5 Tier-2): the masterchain boundary block's
        // root over the previous epoch's finalized hashes must be canonical
        // (boundary height only, masterchain only) and must not contradict
        // the root this process derives from its own finalized chain. A node
        // that has not finalized the epoch yet has nothing to contradict, so
        // the proposal is accepted — the commitment is still checked by the
        // quorum that signs the block.
        self.check_epoch_mmr_commitment(block)?;
        // TRANSACTION-ORDER COMMITMENT (consensus-enforced): the block
        // carries the order Merkle root over its transaction list and the
        // root is inside the signed block hash, so the quorum that votes for
        // the block votes for its ORDER. Re-compute the root from the body
        // on the wire and REFUSE the proposal when it does not match: a
        // proposer cannot reorder a block after it has been signed/voted on.
        // (This is what turns the order commitment from a node-local note
        // into a protocol rule — see `mev`.)
        //
        // It runs BEFORE the signature check on purpose: a body whose order
        // no longer matches the commitment is refused for the ORDER reason,
        // not for the incidental "the signature does not cover this body"
        // reason — the order commitment is the rule that is being violated.
        self.check_order_commitment(block)?;
        // CANONICAL DOWNTIME EVIDENCE (W10.5): the proposer-chosen QC for the
        // parent height — verified here (linkage, finality shape, quorum under
        // the set in force at H-1) so the evidence every applier attributes
        // from is byte-identical across the network.
        self.check_last_qc_evidence(block)?;
        // Authenticity: the block must actually be signed by its declared
        // proposer, otherwise a peer could propose on another validator's behalf.
        // STAB verify-once: cache the verdict per block hash (pure function
        // of block bytes); the timed attribution path below hits the cache
        // instead of re-verifying the same Ed25519/Falcon signature.
        {
            let bh = Self::proposer_sig_cache_key(block);
            let cached = self
                .proposer_sig_cache
                .lock()
                .ok()
                .and_then(|g| g.get(&bh).copied());
            let ok = match cached {
                Some(v) => v,
                None => {
                    let v = crate::consensus::verify_proposer_signature(block);
                    if let Ok(mut g) = self.proposer_sig_cache.lock() {
                        if g.len() > 1024 {
                            g.clear();
                        }
                        g.insert(bh, v);
                    }
                    v
                }
            };
            if !ok {
                return Err("proposal: invalid or missing proposer signature".to_string());
            }
        }
        let expected_prev = self.finalized.last().map(|(_, h)| *h).unwrap_or([0u8; 32]);
        if block.prev_hash != expected_prev {
            return Err("proposal: wrong prev_hash (not chained to finalized head)".to_string());
        }
        if block.transactions.len() > MAX_BLOCK_TXS {
            return Err("proposal: block too large".to_string());
        }
        // Actor-mailbox cap, block-static half (no state read, so it stays in
        // the synchronous validator): a block whose OWN sends already exceed
        // `MAX_ACTOR_MSGS_PER_BLOCK` can never drain-to-empty and is rejected
        // here. The backlog-inclusive half is checked by the async callers
        // (`on_proposal`, `adopt_committed`, `propose`), which agree with this
        // whenever the backlog is empty.
        if block_actor_sends_exceed_cap(block) {
            return Err(format!(
                "proposal: actor mailbox over cap ({} sends in block > {})",
                count_block_actor_sends(block),
                crate::state_engine::MAX_ACTOR_MSGS_PER_BLOCK
            ));
        }
        let total_gas = block
            .transactions
            .iter()
            .fold(0u64, |acc, t| acc.saturating_add(t.gas_limit));
        if total_gas > MAX_BLOCK_GAS {
            return Err("proposal: block gas limit exceeded".to_string());
        }
        // Batched Ed25519 verification: much faster than one-by-one for a full block.
        // STAB verify-once: cache per signature-committing key; the timed attribution re-run
        // below becomes an O(1) HashMap hit with a byte-identical verdict.
        {
            let bh = Self::batch_verify_cache_key(block);
            let cached = self
                .batch_verify_cache
                .lock()
                .ok()
                .and_then(|g| g.get(&bh).copied());
            let ok = match cached {
                Some(v) => v,
                None => {
                    // PERF_PROFILE §6.2: parallel intake batch — byte-identical
                    // verdict to the serial batch (par_chunks().all(serial);
                    // small blocks take the serial path verbatim).
                    let v =
                        Transaction::verify_signatures_batch_parallel(&block.transactions);
                    if let Ok(mut g) = self.batch_verify_cache.lock() {
                        if g.len() > 1024 {
                            g.clear();
                        }
                        g.insert(bh, v);
                    }
                    v
                }
            };
            if !ok {
                return Err("proposal: bad transaction signature".to_string());
            }
        }
        // F-01 CONSENSUS FEE FLOOR (fail-closed, cheap, before execution):
        // admission (`Mempool::insert`) and the honest proposer filter both
        // refuse `gas_limit` below the effective floor, but neither binds a
        // Byzantine proposer — and until now neither did this function, so a
        // custom-built block of valid-signature underpriced (or zero-fee)
        // transactions was accepted and executed by every honest validator,
        // with failures paying nothing. Refuse such blocks here.
        //
        // The verdict is THE single admission helper
        // (`Mempool::effective_floor_for_tx`: base + D2 failure penalty + PQ
        // activation surcharge where applicable), so the formula cannot drift
        // from admission. It reads this validator's mempool floor state via a
        // non-blocking lock: a contended pool fails CLOSED (the block is
        // refused, not skipped) rather than executing underpriced work. An
        // empty block passes vacuously.
        //
        // CONSENSUS NOTE: the base here is the admission base
        // (`max(frozen, governed)`, synced every finalize); the apply path
        // charges the governed base (see `consensus_floor_parts`) — the
        // frozen half is the same const on every node and cannot move
        // consensus. Validate is therefore
        // never looser than apply: anything apply would up-charge is either
        // refused here or arrives declaring at least the floor. The penalty
        // half converges across honest nodes that finalized the same chain
        // (identical verdict feeds in identical order); a node whose mempool
        // missed feedback (reorg/sync paths feed nothing) holds a LOWER floor
        // and may accept what peers refuse — fail-open for that node only,
        // never a network split, and closed the moment its live path
        // re-feeds. Coordinated rollout: all validators run the identical
        // floor config, exactly like admission today.
        {
            let pool = self
                .mempool
                .try_read()
                .map_err(|_| "proposal: fee floor unavailable (fail-closed)".to_string())?;
            // Snapshot once for the diagnostic breakdown below; the verdict
            // itself comes from the single helper (cannot drift).
            let penalty_snapshot = pool.penalty_snapshot();
            // The CONSENSUS floor the apply path will charge with (the D2
            // penalty - the governed base is already covered by `base_fee`,
            // which is synced to `max(frozen, governed)`), snapshotted once. The
            // validation floor is `max(admission floor, consensus floor)`: it
            // must NEVER be looser than the floor execution charges with,
            // otherwise a transaction whose fee depends on the penalty could
            // be packed by a node whose penalty view is stale and charged
            // DIFFERENTLY by two validators - a different balance, a
            // different state root, a consensus split (audit W6.6).
            //
            // A contended read fails CLOSED (the block is refused), exactly
            // like the mempool floor read above: a floor that cannot be read
            // must never be silently lowered.
            let consensus_penalties = self
                .state
                .consensus_penalty_try_read()
                .map_err(|_| "proposal: fee floor unavailable (fail-closed)".to_string())?;
            for tx in &block.transactions {
                // THE SAME FLOOR AS ADMISSION AND AS THE PROPOSER'S OWN
                // FILTER: `required_fee_for_tx` = base + D2 failure penalty +
                // PQ activation surcharge + the transaction's EXPLICIT PRIORITY
                // BID. The bid is a price, so it must be covered by the
                // transaction's own fee; the proposer filter already refuses a
                // transaction whose `gas_limit` does not cover it, so a
                // Byzantine proposer must not be able to sneak an UNFUNDED bid
                // into a block the honest validators accept (the bid would
                // then buy priority without paying for it).
                let surcharge = if tx.is_pq_activation() {
                    crate::mempool::PQ_ACTIVATION_SURCHARGE_GAS
                } else {
                    0
                };
                let consensus_floor = consensus_penalties
                    .get(&tx.from)
                    .copied()
                    .unwrap_or(0)
                    .saturating_add(surcharge);
                let floor = pool.required_fee_for_tx(tx).max(consensus_floor);
                if tx.gas_limit < floor {
                    return Err(format!(
                        "proposal: tx {} from {} below fee floor (gas_limit {} < floor {} = base {} + penalty {} + pq_surcharge {} + priority {} + consensus_penalty {})",
                        hex::encode(tx.compute_tx_hash()),
                        hex::encode(&tx.from[..6]),
                        tx.gas_limit,
                        floor,
                        pool.base_fee,
                        penalty_snapshot.get(&tx.from).copied().unwrap_or(0),
                        surcharge,
                        tx.priority_fee_per_gas,
                        consensus_penalties.get(&tx.from).copied().unwrap_or(0),
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn validate_proposal(
        &self,
        block: &Block,
        expected_state_root: [u8; 32],
    ) -> Result<(), String> {
        self.validate_proposal_unaligned(block, expected_state_root)?;
        if Some(block.proposer) != self.hc.proposer() {
            return Err("proposal: wrong proposer".to_string());
        }
        Ok(())
    }

    /// Timed proposal validation (BACKPRESSURE HONESTY).
    ///
    /// Runs the SAME verdict as [`Self::validate_proposal_unaligned`] but
    /// attributes wall time per stage so a node that is too slow to validate
    /// can SAY so instead of silently voting nil. Stages are deliberately the
    /// expensive ones an operator must distinguish: `proposer_sig_verify`
    /// (Ed25519/Falcon), `state_root_check` (state-root recompute / trie
    /// read), `order_commit`, `tx_batch_verify` (per-tx sig verifies),
    /// `fee_floor_mempool` (mempool filter), `header_checks` (everything
    /// else: timestamp, shard scope, gas caps, actor cap).
    ///
    /// MEASUREMENT ONLY: the `Instant`s here never enter round timing (see
    /// task 4 — the deterministic timeout takes no clock). The verdict is
    /// byte-identical to the untimed path: this function CALLS it once and
    /// attributes via the per-block verify-once caches (order root, batch
    /// verify, proposer sig) populated by that single run — no second
    /// O(txs) crypto pass, so verdicts cannot diverge and the tail is halved.
    pub fn validate_proposal_timed(
        &self,
        block: &Block,
        expected_state_root: [u8; 32],
    ) -> (Result<(), String>, Vec<(String, u64)>) {
        // Authoritative verdict: exactly one run, same order, same errors.
        // STAB verify-once: the verdict above populates the per-block caches
        // (order root, batch verify, proposer sig); attribution below reads
        // those caches O(1) instead of re-running O(txs) crypto, so the timed
        // path costs one verification per block, not two, with a
        // byte-identical verdict.
        let verdict = self.validate_proposal_unaligned(block, expected_state_root);
        let mut stages: Vec<(String, u64)> = Vec::with_capacity(6);
        let t = std::time::Instant::now();
        let _ = self
            .proposer_sig_cache
            .lock()
            .ok()
            .and_then(|g| g.get(&Self::proposer_sig_cache_key(block)).copied())
            .unwrap_or_else(|| crate::consensus::verify_proposer_signature(block));
        stages.push(("proposer_sig_verify".into(), t.elapsed().as_millis() as u64));
        let t = std::time::Instant::now();
        let _ = block.state_root == expected_state_root;
        stages.push(("state_root_check".into(), t.elapsed().as_millis() as u64));
        let t = std::time::Instant::now();
        // Cache hit: `check_order_commitment` already cached the root during
        // the verdict above, so this is a HashMap lookup, not O(txs) hashes.
        let _ = self.check_order_commitment(block);
        stages.push(("order_commit".into(), t.elapsed().as_millis() as u64));
        let t = std::time::Instant::now();
        let _ = self
            .batch_verify_cache
            .lock()
            .ok()
            .and_then(|g| g.get(&Self::batch_verify_cache_key(block)).copied())
            .unwrap_or_else(|| {
                Transaction::verify_signatures_batch_parallel(&block.transactions)
            });
        stages.push(("tx_batch_verify".into(), t.elapsed().as_millis() as u64));
        let t = std::time::Instant::now();
        {
            if let Ok(pool) = self.mempool.try_read() {
                for tx in &block.transactions {
                    let _ = pool.required_fee_for_tx(tx);
                }
            }
        }
        stages.push(("fee_floor_mempool".into(), t.elapsed().as_millis() as u64));
        let t = std::time::Instant::now();
        {
            let _ = self.check_block_timestamp(block);
            let _ = block_actor_sends_exceed_cap(block);
        }
        stages.push(("header_checks".into(), t.elapsed().as_millis() as u64));
        (verdict, stages)
    }

    /// Record one validation's timing: meter + loud log when slow.
    ///
    /// Fires when the SUM exceeds [`SLOW_VALIDATION_THRESHOLD_MS`]: increments
    /// `slow_validation_total` (+ metrics), and logs ONE line naming the
    /// slowest stage (`state-root recompute? sig verifies? trie? mempool
    /// filter?`) with the full breakdown. Never changes the verdict — the
    /// caller already accepted or refused the proposal.
    pub fn note_validation_timing(&mut self, stages: &[(String, u64)]) {
        self.validation_last_stages = stages.to_vec();
        let total: u64 = stages.iter().map(|(_, ms)| *ms).sum();
        if total < SLOW_VALIDATION_THRESHOLD_MS {
            return;
        }
        self.slow_validation_total = self.slow_validation_total.saturating_add(1);
        crate::metrics::global().inc_slow_validation();
        let slowest = stages.iter().max_by_key(|(_, ms)| *ms);
        let breakdown = stages
            .iter()
            .map(|(s, ms)| format!("{s}={ms}ms"))
            .collect::<Vec<_>>()
            .join(" ");
        let slow_name = slowest.map(|(s, _)| s.as_str()).unwrap_or("unknown");
        let msg = format!(
            "[slow-validation] h={} r={} total={}ms slowest={} ({}) slow_total={}",
            self.hc.height, self.hc.round, total, slow_name, breakdown, self.slow_validation_total,
        );
        eprintln!("{msg}");
        tracing::warn!("{msg}");
    }

    /// Record a peer's lock hint from a nil prevote: "I am stuck on the block
    /// `hint`, which you authored -- re-propose it". Only nil prevotes at our
    /// height qualify, and only hints naming OUR bodies for THIS height are
    /// kept (anything else is another author's turn, or junk). Bounded and
    /// height-scoped; serving is one-shot per hint (see `propose`).
    pub fn note_lock_hint(
        &mut self,
        vote_height: Height,
        kind: VoteKind,
        target: Option<BlockHash>,
        hint: Option<BlockHash>,
    ) {
        if vote_height != self.hc.height || kind != VoteKind::Prevote || target.is_some() {
            return;
        }
        let Some(h) = hint else { return };
        if self.demanded_height != self.hc.height {
            self.demanded.clear();
            self.demanded_height = self.hc.height;
        }
        // "OUR body" means we AUTHORED it, not merely that we happen to hold a
        // copy. A body another validator authored must never enter the
        // rescue set: serving it would re-propose somebody else's block under
        // OUR proposer slot, which every receiver rejects ("proposer field
        // mismatch") — the rescue would fail, the stuck peer would stay
        // stuck, and our own proposer round would be spent on a block the
        // network can never accept.
        let ours = self
            .blocks
            .get(&h)
            .is_some_and(|b| b.height == self.hc.height && b.proposer == self.id);
        if !ours {
            return;
        }
        const MAX_DEMANDED: usize = 8;
        if self.demanded.len() >= MAX_DEMANDED && !self.demanded.contains(&h) {
            return;
        }
        self.demanded.insert(h);
    }

    /// Record a peer's SIGNED round. Returns true when we moved.
    ///
    /// Tendermint future-round rule: a verified vote for a round ahead of ours
    /// carries us TO that round. A peer within a few rounds is normal
    /// operation, and jumping wipes per-round proposal state -- but NOT
    /// jumping left a PERSISTENT one-round offset between two honest nodes
    /// (they prevoted the SAME value at r15 and r16, so no same-round QC could
    /// ever form and each height burned ~10 rounds). The behind node must
    /// follow. The view-change hold separately keeps near nodes in phase, and
    /// proposal-acceptance carries its own atomic align (a sync that brings
    /// its proposal can never strand us proposalless). Jumps land exactly ON
    /// the peer's round, never past it, so following cannot overshoot into a
    /// leapfrog: landing near stops further syncing.
    pub fn note_peer_vote_round(&mut self, vote_height: Height, vote_round: Round) -> bool {
        // Any verified lead pulls us up -- including 1 round. Callers invoke this
        // only AFTER `Vote::verify` + membership (see the F2 fix in the drain),
        // and `sync_round_to` is capped at ROUND_LOOKBACK=8, so this cannot be
        // used for the round explosion we saw from unverified votes with a +64
        // cap. Suppressing near (1-3 round) sync instead left a PERSISTENT
        // one-round offset between two honest nodes: they prevoted the SAME
        // value at r15 and r16, so no same-round QC could ever form and each
        // height burned ~10 rounds (30s+). The behind node must follow.
        //
        // (A sit-while-armed variant was tried for 3-member WAN liveness and
        // reverted: refusing near jumps while holding a proposal deadlocks two
        // armed nodes on different rounds AND breaks the pinned
        // `round_nudge_reopens_gate_once_not_per_tick` convergence. The
        // 3-racer leapfrog cascade stays a known open issue for ≥3 WAN-skewed
        // equal-power members; the fix there is quorum-gated jumps (≥2
        // distinct voters), not unilateral sitting.)
        if vote_height != self.hc.height || vote_round <= self.hc.round {
            return false;
        }
        // The SAME vote must never move the round twice: the cap applies per
        // jump, and the vote path follows the round as well as the drain
        // (the vote path covers every consumer of the runtime, the drain
        // covers the node loop). Without this, one vote would move the node
        // twice as far as `ROUND_LOOKBACK` allows.
        //
        // CORROBORATION RE-OPENS THE CHASE (P3-R1): the dedup above is keyed
        // by (height, round), so a second DISTINCT validator vouching for the
        // same far round would be suppressed as a "replay" -- and the
        // corroboration gate below would never see the second witness. A
        // round reported by 2+ distinct validators (1 on a 2-member set) is
        // new evidence, not a replay, so it bypasses the dedup and re-runs
        // the chase. A lone liar replaying its own vote stays suppressed.
        let min_supporters = if self.validators.len() >= 3 { 2 } else { 1 };
        let corroborated = self.hc.supporting_peers_count(vote_round) >= min_supporters;
        if !corroborated && self.last_followed_round == Some((vote_height, vote_round)) {
            return false;
        }
        self.last_followed_round = Some((vote_height, vote_round));
        let before = self.hc.round;
        // CONVERGE, don't nudge (liveness fix, live 2026-10-19: the
        // masterchain parked at height 285027 while the node rounds drifted
        // ~30 apart and the network spent its life in view changes). One
        // `sync_round_to` moves at most ROUND_LOOKBACK rounds, so a single
        // call used to carry us one cap-step toward the peer while the dedup
        // above suppressed every further step for that (height, round): a
        // node 30 rounds behind advanced 8 and then had to grind its own
        // 3.5 s+ timeouts one round at a time for the rest -- each timeout
        // wiping its proposal -- so the skew never closed. Loop to the
        // peer's round instead, within the existing per-round jump budget.
        //
        // CORROBORATION GATE (P3-R1 round-DoS fix): the FIRST step is always
        // taken -- a genuinely-behind node must follow even a single peer --
        // but CONTINUING past one step needs the round corroborated by a
        // second DISTINCT validator (same rule as the deadlock breaker, which
        // already refuses single-reporter jumps). Without this, ONE Byzantine
        // vote 1000 rounds ahead dragged an honest node +64 in a single call
        // (8 jumps x 8 rounds), and a trickle of such votes walked it off the
        // network's cliff one budget at a time -- a round-DoS with a single
        // key. `peer_rounds` already includes this vote (`observe_peer_vote`
        // runs before this on the vote path), so an actually-ahead network
        // (2+ distinct voters at/above the target) still opens the full
        // chase, and a 2-member set still follows its single peer.
        //
        // Residual: a lone liar still buys +8 per vote (fresh round each
        // time, the dedup only covers replays). Each step is a signed,
        // attributable vote and the per-round jump budget caps the rate; a
        // quorum gate on the FIRST step would break behind-node catch-up, so
        // the +8 unilateral nudge stays by design.
        //
        // The bounds are otherwise unchanged in aggregate: at most
        // MAX_SYNC_JUMPS_PER_ROUND capped jumps per call (the documented
        // per-round bound), forward-only, verified-votes-only (callers gate),
        // landing exactly ON the peer's round. The dedup still means one
        // vote moves us once -- the vote-path + drain double stays a no-op
        // because we are already there.
        let mut first_step = true;
        while vote_round > self.hc.round {
            if !first_step && self.hc.supporting_peers_count(vote_round) < min_supporters {
                break; // lone reporter: keep the nudge, refuse the cliff
            }
            first_step = false;
            let r = self.hc.round;
            self.hc.sync_round_to(vote_round);
            if self.hc.round == r {
                break; // jump budget exhausted; our own view change refills it
            }
        }
        self.hc.round != before
    }

    /// Feed a (possibly stale/absurd) peer vote into round-sync WITHOUT voting
    /// (deadlock fix 2026-10-14).
    ///
    /// Verifies the vote (signature + validator membership) and requires
    /// `vote.height == hc.height`; on success records the peer's round via
    /// `HeightConsensus::observe_peer_round` (counter only, bounded
    /// `sync_round_to` chase). Returns true when our round moved. A vote for
    /// a stale round or beyond `MAX_ROUND_AHEAD` — both rejected by
    /// `on_prevote`/`on_precommit` — still teaches us the peer's round here,
    /// so a 1200-round desync collapses instead of being dropped both ways.
    pub fn observe_peer_vote(&mut self, vote: &Vote) -> bool {
        if vote.height != self.hc.height {
            return false;
        }
        if !vote.verify() {
            return false;
        }
        if self.validators.power_of(&vote.voter) == 0 {
            return false;
        }
        // RECORD ONLY. The chase (moving our round to the peer's) is the
        // future-round rule and lives in `note_peer_vote_round`, which the
        // vote path applies right after this. Keeping the two apart lets the
        // counter be updated for EVERY verified vote - accepted or not -
        // without also chasing on votes the caller has already accounted for.
        self.hc.note_peer_round(vote.voter, vote.round);
        true
    }

    /// Stamp finalization progress (call on every finalize/adopt).
    pub fn record_progress(&mut self) {
        self.last_progress_at = std::time::Instant::now();
    }

    /// Breaker timeout (`STELL_DEADLOCK_TIMEOUT_SECS`, default 300s).
    pub fn deadlock_timeout() -> std::time::Duration {
        std::time::Duration::from_secs(crate::consensus::HeightConsensus::deadlock_timeout_secs())
    }

    /// Deadlock circuit breaker (live 2026-10-14: A r1550 vs B r318 at h92078).
    ///
    /// Fires only when ALL hold (fail-safe):
    ///  * no finalization progress for the timeout window,
    ///  * a verified peer round ahead of us exists (`max_peer_round`),
    ///  * the jump is forward-only, and at most once per timeout window.
    ///
    /// On fire, performs the bounded jump to `max(peer rounds)`, stamps the
    /// rate limit, logs LOUDLY (tracing + stderr), and returns the new round.
    /// The caller must reset its round timer so it does not view-change past
    /// the peer it just joined.
    pub fn check_deadlock_breaker(&mut self) -> Option<Round> {
        let timeout = Self::deadlock_timeout();
        if self.last_progress_at.elapsed() < timeout {
            return None;
        }
        if let Some(last) = self.last_breaker_at {
            if last.elapsed() < timeout {
                return None;
            }
        }
        let no_progress_secs = self.last_progress_at.elapsed().as_secs();
        let timeout_secs = timeout.as_secs().max(1);
        let target = self
            .hc
            .deadlock_breaker_target(no_progress_secs, timeout_secs)?;
        let from = self.hc.round;
        if !self.hc.apply_deadlock_jump(target) {
            return None;
        }
        self.last_breaker_at = Some(std::time::Instant::now());
        tracing::error!(
            height = self.hc.height,
            from_round = from,
            to_round = target,
            no_progress_secs,
            "DEADLOCK-BREAKER: no finalization, jumping round forward to max(peer rounds)"
        );
        eprintln!(
            "[consensus][DEADLOCK-BREAKER] h={} r{} -> r{} after {}s without finalization (timeout {}s)",
            self.hc.height, from, target, no_progress_secs, timeout_secs
        );
        Some(target)
    }

    /// Receive a proposal from the (correct) proposer for the current round.
    pub async fn on_proposal(
        &mut self,
        proposer: ValidatorId,
        block: Block,
        envelope_round: Round,
    ) -> Result<BlockHash, String> {
        // §7 Phase 2 gate: the header's root check below reads OUR root, which
        // is PRE-H while a decided block is still executing. Checking now
        // would compare the proposal against the wrong parent state (a valid
        // H+1 proposal looks corrupt, a stale one looks fine), so the
        // proposal is deferred, not validated, until the worker reports back.
        // No state is read and none moves.
        if self.apply_in_flight.is_some() {
            return Err("proposal deferred: apply in flight".to_string());
        }
        // Read our root BEFORE accepting, so the header is checked against the
        // state the block would actually extend.
        let our_root = self.state.get_state_root().await;
        // Authenticity FIRST, before height/state checks: only the declared
        // proposer could have signed this, so a verified signature makes the
        // header's claims (height, prev_hash) attributable -- and worth
        // learning from even when we must refuse the block itself.
        if !crate::consensus::verify_proposer_signature(&block) {
            return Err("proposal: invalid or missing proposer signature".to_string());
        }
        // Record the peer head BEFORE any refusal below: a genuine proposal at
        // height H proves finalized H-1 even when it is not for us (wrong
        // height or round). Refused proposals previously taught us nothing, so
        // a node exactly one height behind never learned the head and spun in
        // view changes at its own height forever.
        //
        // VERIFICATION G1: attribution requires membership, not just a valid
        // signature — anyone can self-sign a proposal with their own key, so
        // a signature-only gate lets a zero-stake outsider plant hints and
        // force the catch-up timer every tick (forged H+1 proposals keeping
        // the node on loudly-failing DHT walks). A Byzantine MEMBER
        // advertising false heads only triggers loudly-failing walks, bounded
        // by caps.
        if block.height > 0
            && crate::consensus_net::proposal_hint_admissible(&block, &self.validators)
        {
            let h = (block.height - 1, block.prev_hash);
            if self.peer_hint.map(|(ph, _)| ph < h.0).unwrap_or(true) {
                self.peer_hint = Some(h);
            }
        }
        // Prove the block genuine BEFORE any round alignment: a forged envelope
        // must never move our round (see `validate_proposal_unaligned`).
        // C2 BACKPRESSURE HONESTY: run the TIMED validation (same verdict,
        // plus per-stage attribution). A node too slow to validate says WHICH
        // stage was slow instead of silently voting nil.
        let (vres, stages) = self.validate_proposal_timed(&block, our_root);
        self.note_validation_timing(&stages);
        vres?;
        // Actor-mailbox cap, backlog-inclusive half (async: reads the engine).
        // The static half already ran inside `validate_proposal_unaligned`;
        // this adds what is already queued, so a block that fits on its own
        // but overflows on top of leftovers is still rejected deterministically
        // instead of carried over.
        self.check_actor_cap(&block).await?;
        // Freshness: the envelope round is the sender's claimed round. A
        // genuine body arriving LATE (delayed in transit) must not be adopted
        // as the current round's value: the proposer has moved on, the rest of
        // the network votes something else, and voting the stale body spends
        // our one vote on a quorum that can never form -- observed live as two
        // nodes voting different bodies at the same round for hundreds of
        // rounds. The envelope is only a freshness hint (it is unsigned), and
        // it is consulted strictly AFTER authentication: a forged envelope on
        // garbage dies above without moving anything; a forged envelope on a
        // genuine body is indistinguishable from network delay, which is
        // harmless (idempotent at worst).
        if envelope_round < self.hc.round {
            return Err("proposal: stale round".to_string());
        }
        // Phase-align: if the block is genuinely this height's proposer's work
        // but for a NEAR-FUTURE round, we are simply behind -- jump to the
        // earliest round this proposer owns and accept it there instead of
        // rejecting it as "wrong proposer" and then missing it forever (the
        // vote that would have synced us arrives after the proposal it should
        // have preceded). Bounded to near rounds: a far claim is answered by
        // the vote path, not by an unsigned envelope.
        if Some(block.proposer) != self.hc.proposer() {
            // Near-future phase alignment (widened +4 -> +8, see
            // `PROPOSAL_ALIGN_WINDOW_ROUNDS`): early delivery of a
            // GENUINE future proposal must align, not reject — the scan is
            // deliberate, pinned by test. Abuse is bounded elsewhere: the
            // jump runs through `sync_round_to`, which caps each jump at
            // ROUND_LOOKBACK and budgets MAX_SYNC_JUMPS_PER_ROUND jumps per
            // round (audit 2026-10-06; per-round since the wall-clock
            // budget removal), and
            // the body is signature-authenticated before this point, so only
            // the slot owner can pull us to their own slots.
            let mut target = None;
            for r in (self.hc.round.saturating_add(1))
                ..=(self.hc.round.saturating_add(PROPOSAL_ALIGN_WINDOW_ROUNDS))
            {
                if self.validators.proposer_for(self.hc.height, r) == Some(block.proposer) {
                    target = Some(r);
                    break;
                }
            }
            match target {
                Some(r) => self.hc.sync_round_to(r),
                None => return Err("proposal: wrong proposer".to_string()),
            }
        }
        // R-TEMPO single validation (was: a SECOND full `validate_proposal`
        // here after `validate_proposal_timed` above — 2x order-commit +
        // 2x batch sig-verify + 2x fee-floor scan per proposal per node,
        // ~36ms on a loaded 1785-tx block, ~5x that on a 1-vCPU member).
        // `validate_proposal_timed` ALREADY returned the authoritative
        // `validate_proposal_unaligned` verdict for this exact
        // (block, our_root) above, and nothing between the two calls mutates
        // state (the actor-cap check is a read lock; the phase-align moves
        // only our local round counter). Re-running it can therefore only
        // repeat the same verdict at full cost. The only half of
        // `validate_proposal` not covered by the timed run is the
        // proposer-slot check against the ALIGNED round, kept here verbatim
        // so the accept/refuse verdict is byte-identical to before.
        if Some(block.proposer) != self.hc.proposer() {
            return Err("proposal: wrong proposer".to_string());
        }
        // EPOCH-KEY COMMITMENT: the block pins the MEV epoch key the network
        // uses for this epoch (see `crate::mev_epoch`). Record it: a node
        // whose OWN key differs from the committed one has DIVERGED (a
        // different validator view at the epoch boundary), and it must then
        // stop releasing decryption partials — its shares would reconstruct a
        // different shared point, and the ciphertext would not authenticate
        // for anybody.
        if block.epoch_key_commitment != [0u8; 32] {
            let mut pool = self.mempool.write().await;
            pool.mev_seal
                .note_committed_epoch_key(block.epoch_key_commitment);
        }
        if block.proposer != proposer {
            return Err("proposal: proposer field mismatch".to_string());
        }
        let bh = block.compute_hash();
        self.hc.receive_proposal(proposer, bh)?;
        // Fork-choice: the proposal is recorded as a CANDIDATE before it is
        // finalized, so a competing branch is KNOWN. When it loses (another
        // block is finalized at this height) the blocks that lost can be
        // signalled instead of vanishing.
        self.record_candidate_block(&block);
        let _ = self.run_fork_choice();
        self.blocks.insert(bh, block);
        Ok(bh)
    }

    /// Our prevote for the current round (applies the safety lock).
    /// Read the staking ledger through the state engine. Same lock the engine
    /// commits, so reads always see committed state.
    pub async fn staking_read(
        &self,
    ) -> tokio::sync::RwLockReadGuard<'_, crate::staking::StakingLedger> {
        self.state.staking_read().await
    }

    /// Write the staking ledger through the state engine, bumping the commitment
    /// generation so the state root cannot go stale.
    pub async fn staking_write(
        &self,
    ) -> tokio::sync::RwLockWriteGuard<'_, crate::staking::StakingLedger> {
        self.state.staking_write().await
    }

    /// Attach an out-of-process signer. Kept as a builder so every existing
    /// construction site (tests, simulator) is unaffected.
    ///
    /// Refuses a signer whose public key is not this node's identity. `self.id` is
    /// fixed at construction from `key` and is what the validator set and every vote's
    /// `voter` field are keyed on; a remote signer for a DIFFERENT key would produce
    /// signatures that verify against nothing (or worse, attribute a signature to the
    /// wrong validator), so it is rejected here rather than at vote time.
    pub fn with_remote_signer(
        mut self,
        signer: Arc<dyn crate::remote_signer::Signer>,
    ) -> Result<Self, String> {
        let remote_pk = signer.public_key();
        if remote_pk != self.id {
            return Err(format!(
                "remote signer key {} does not match this node's validator identity {}",
                hex::encode(&remote_pk[..8]),
                hex::encode(&self.id[..8])
            ));
        }
        self.remote_signer = Some(signer);
        Ok(self)
    }

    /// The public key this node votes with. For a remote signer this is the key the
    /// signer pinned at construction, so it is the same value `id` was set from.
    pub fn signer_public_key(&self) -> [u8; 32] {
        match &self.remote_signer {
            Some(s) => s.public_key(),
            None => self.key.verifying_key().to_bytes(),
        }
    }

    /// Produce a signature over `bytes`, via the remote signer when one is configured.
    ///
    /// Returns `None` on any signer failure. Deliberately NOT `unwrap_or`-style
    /// fallback to `self.key`: a node that believes its key is in an HSM while it
    /// quietly signs from a plaintext seed in its own heap is the exact failure this
    /// exists to prevent, so the caller must skip the vote instead.
    fn sign_bytes(&self, bytes: &[u8]) -> Option<Vec<u8>> {
        match &self.remote_signer {
            Some(s) => match s.sign(bytes) {
                Ok(sig) => Some(sig.to_vec()),
                Err(e) => {
                    eprintln!("[signer] refusing to vote, remote signer failed: {e}");
                    None
                }
            },
            None => Some(self.key.sign(bytes).to_vec()),
        }
    }

    /// Build a vote signed by whichever signer is configured.
    fn make_vote(&self, kind: VoteKind, target: Option<BlockHash>) -> Option<Vote> {
        self.make_vote_at(kind, target, self.hc.round)
    }

    /// Build a vote stamped with an explicit round. Precommits use the round
    /// of the POLKA they follow, not the local round: the decision needs the
    /// prevote QC and the precommit QC in the SAME bucket, and the two nodes
    /// are routinely one round apart (60% of sampled time on the live stand).
    fn make_vote_at(
        &self,
        kind: VoteKind,
        target: Option<BlockHash>,
        round: Round,
    ) -> Option<Vote> {
        let msg = crate::consensus::vote_sign_bytes(self.hc.height, round, kind, &target);
        let sig = self.sign_bytes(&msg)?;
        let mut vote = Vote::signed_with(self.id, self.hc.height, round, kind, target, sig);

        let fk_ref = self.falcon_signing_key();
        if let Some(fk) = fk_ref {
            crate::consensus::attach_vote_falcon(fk, &msg, &mut vote.signature);
        }

        Some(vote)
    }

    pub fn make_prevote(&self) -> Option<Vote> {
        if self.hc.step != Step::Propose && self.hc.step != Step::Prevote {
            return None;
        }
        let target = self.hc.decide_prevote();
        self.make_vote(VoteKind::Prevote, target)
    }

    pub fn on_prevote(&mut self, v: Vote) -> Result<(), String> {
        let res = self.hc.add_prevote(v.clone());
        // EVERY verified same-height vote feeds the peer-round counter, not
        // only the rejected ones. The counter is where the network is: the
        // deadlock breaker's corroboration and the quorum-scan anchor both
        // read it, and both were blind while only REJECTED votes updated it
        // (a healthy network rejects almost nothing, so the breaker never
        // fired and the anchor never moved).
        //
        // The return value says whether the vote VERIFIED (signature +
        // membership): only a verified vote is evidence that the network is
        // at that round.
        let verified = self.observe_peer_vote(&v);
        // FUTURE ROUND RULE (Tendermint): a node that receives a valid vote
        // for a round GREATER than its own must move to that round. Without
        // it a node that fell behind walks its rounds one timeout at a time
        // and never rejoins the network's round, so the two never prevote
        // the same value in the same round and no quorum can ever form.
        // The rule lives HERE (on the vote path) and not only in the node
        // loop, so every consumer of the runtime gets it - including the
        // in-process cluster, which is where the regression test lives.
        // Forward-only and bounded (`sync_round_to`): a node can never be
        // dragged backwards, and a single message cannot shove it far.
        //
        // ONLY A VERIFIED VOTE MAY MOVE THE ROUND. A vote that failed the
        // verification (a tampered body, a non-member) is not evidence of
        // anything, and a forged vote must never fast-forward a node (the
        // `round_converges_only_on_verified_peer_rounds` test pins this).
        // A verified vote that the round-window REFUSED (a vote absurdly far
        // ahead) still syncs, bounded: the F2 finding is that a verified far
        // vote is evidence of where the network is.
        if verified {
            self.note_peer_vote_round(v.height, v.round);
        }
        res
    }

    /// Once a prevote quorum exists, lock and produce our precommit.
    ///
    /// Audit F10: `try_prevote_quorum` scans back a window of rounds (so a late
    /// quorum still decides), but a precommit must be cast for the round we are
    /// actually in. Casting a precommit at the CURRENT round off a prevote QC
    /// that formed in an OLDER round would vote a round in which we never
    /// prevoted, and lock us at the wrong round -- a validator only precommits
    /// after prevoting in that same round. So require a prevote QC recorded for
    /// `self.hc.round` whose target is the quorum target we are about to
    /// precommit. Finalization of an older round is unaffected: `try_finalize`
    /// inspects the same lookback window and can still commit it.
    pub fn make_precommit(&mut self) -> Option<Vote> {
        // Cast at the polka's OWN round (Tendermint), not at `hc.round`.
        // The old rule ("the QC must be in my current round") meant that a
        // one-round skew -- the normal state of the two-node stand -- made BOTH
        // nodes refuse to precommit: each saw the QC one round behind, so a
        // full prevote QC never decided (31 of 180 wasted rounds, measured
        // live: prevote QC present, no precommit ever cast).
        //
        // The scan also runs the polka-UNLOCK rule (a polka for another block
        // at a higher round releases our lock), so it must run first.
        self.hc.try_prevote_quorum_at();
        // The precommit follows the newest POLKA -- a quorum of prevotes FOR A
        // BLOCK. It must NOT follow the newest quorum of any kind: a NIL
        // quorum (the network timed out in a later round) is not a polka and
        // used to SHADOW the real polka, so the node emitted a nil precommit
        // for the newer round instead of precommitting the certified block,
        // and the dedup key then suppressed the correct precommit forever.
        // Live 2026-10-21: the masterchain sat at height 285027 with a full
        // prevote QC formed and NO precommit QC.
        //
        // THE POLKA LEDGER (liveness fix, live 2026-10-21). `best_polka` is the
        // newest polka this node has OBSERVED -- the one whose quorum was
        // completed by a prevote that arrived -- or the newest one inside the
        // scan window, whichever is newer. The ledger is what makes a LATE
        // polka work: the quorum-completing prevote can arrive long after
        // this node raced ahead of the network, and a scan of the rounds
        // around the local counter cannot see that round at all. The live
        // cluster showed it exactly: the prevote QC for one block was in
        // every validator's vote set and only ONE of them ever cast a
        // precommit, so the precommit quorum never formed and the height
        // stayed parked for three days.
        let (qc_round, target) = self.hc.best_polka()?;
        let qc = self.hc.prevote_qc.get(&qc_round)?;
        if qc.block_hash != Some(target) {
            return None;
        }
        // SAFETY (lock rule): never precommit a block that contradicts our own
        // lock. The unlock rule above already released the lock when the
        // network certified a DIFFERENT block at a HIGHER round; a polka at or
        // below our lock round for another block is stale evidence and must
        // not be voted.
        if let Some((locked_block, locked_round)) = self.hc.locked {
            if locked_block != target && qc_round <= locked_round {
                return None;
            }
        }
        // Lock at the polka round too: the lock round is what the safety
        // check in `try_precommit_quorum` compares against.
        self.hc.locked = Some((target, qc_round));
        self.make_vote_at(VoteKind::Precommit, Some(target), qc_round)
    }

    pub fn on_precommit(&mut self, v: Vote) -> Result<(), String> {
        let res = self.hc.add_precommit(v.clone());
        // V-P34 (R1 verification gap): the round chase MUST be gated on
        // verification here, exactly as on the prevote path.
        // `observe_peer_vote` returns true only for a verified member vote
        // (signature + membership + same height); an unverified precommit —
        // forged signature or non-member voter — previously ran
        // `note_peer_vote_round` unconditionally and bought +8 per fresh
        // round with zero keys. The gate preserves the documented behavior
        // for verified votes (a far-ahead verified vote still syncs,
        // bounded) while forged votes move nothing.
        if self.observe_peer_vote(&v) {
            // FUTURE ROUND RULE: see `on_prevote`.
            self.note_peer_vote_round(v.height, v.round);
        }
        res
    }

    /// Downtime slash for the certificate this runtime currently holds in `hc`:
    /// punish validators that did not contribute to it and burn the slashed
    /// stake from the staking pool. The evidence is the certificate itself, so
    /// every node reaches the same verdict; a local timeout would be neither
    /// sound nor deterministic.
    ///
    /// The production state transition no longer comes here: it runs inside
    /// `InMemoryStateEngine::apply_block_transition`, from the BLOCK's own
    /// `precommit_qc` and `height`, so every route that applies a block -
    /// local finalize, adopt, walk, replay and a reorg re-apply - derives one
    /// verdict from one piece of block content and cannot fork. This entry
    /// point is kept for the consensus-view primitive: tests that build an
    /// `hc` by hand and want to observe what the certificate they hold burns.
    pub async fn apply_downtime_slashes(&mut self) -> u64 {
        // Snapshot the certificate and height BEFORE anything resets them.
        let Some(cert) = self.hc.precommit_qc.clone() else {
            return 0;
        };
        let height = self.hc.height;
        self.state.apply_downtime_slash(height, Some(&cert)).await
    }

    // ==================== §7 Phase 2: lane plumbing ====================

    /// True while a decided block's execution is still on the worker. Stage 1
    /// of the consensus loop and every reader of post-H state check this
    /// first: while set, our observable consensus state (height, `finalized`,
    /// the root a new proposal is checked against) is still PRE-H.
    pub fn has_pending_apply(&self) -> bool {
        self.apply_in_flight.is_some()
    }

    /// Messages currently queued in every inbox: defensive leftovers plus
    /// anything queued since. Honest operation keeps this at zero at every
    /// block boundary (drain-to-empty plus the cap check below refuses any
    /// block that would break it), so a non-zero value here is either a test
    /// setup or evidence of pre-fix history.
    pub async fn pending_actor_backlog(&self) -> usize {
        self.cached_actor_backlog().await
    }

    /// The inbox total with a per-(height, state-root) cache (R-tempo).
    ///
    /// SOUNDNESS: the inbox sum is a pure function of committed state. The
    /// scan runs under ONE read guard (mutually consistent entries) bracketed
    /// by two root reads; the total is stored only when both roots match the
    /// key (no mutation mid-scan — any mutation moves the root). A later hit
    /// re-checks the CURRENT root against the key, so it returns exactly what
    /// a fresh full-map scan would prove. The scan keeps the early exit of
    /// `check_actor_cap` (proving "over cap" needs no full sum), and an
    /// over-cap total is NOT stored (only exact totals are cached).
    async fn cached_actor_backlog(&self) -> usize {
        let height = self.hc.height;
        let root0 = self.state.get_state_root().await;
        if let Some(total) = self.actor_backlog_cache.lock().ok().and_then(|g| {
            g.as_ref()
                .filter(|(h, r, _)| *h == height && *r == root0)
                .map(|(_, _, t)| *t)
        }) {
            return total;
        }
        let guard = self.state.accounts.read().await;
        let mut total: usize = 0;
        for a in guard.values() {
            total = total.saturating_add(a.inbox.len());
            // Same bound as the cap check: proving "over cap" needs no full sum.
            if total > crate::state_engine::MAX_ACTOR_MSGS_PER_BLOCK {
                break;
            }
        }
        drop(guard);
        let root1 = self.state.get_state_root().await;
        // Store only a PROVEN total: the scan saw one consistent state, and
        // both bracketing roots match it. Anything else is used once (it is
        // still a consistent snapshot) but never cached.
        if root0 == root1 {
            if let Ok(mut g) = self.actor_backlog_cache.lock() {
                *g = Some((height, root1, total));
            }
        }
        total
    }

    /// Backlog-inclusive half of the actor-mailbox cap check: whatever is
    /// already queued plus whatever this block statically carries must fit
    /// `MAX_ACTOR_MSGS_PER_BLOCK`, or the block is rejected deterministically
    /// instead of carried over. Called on the propose path (fresh and
    /// demanded bodies), the proposal path and the adopt path, so every
    /// decision boundary refuses the same blocks for the same reason.
    pub async fn check_actor_cap(&self, block: &Block) -> Result<(), String> {
        let sends = count_block_actor_sends(block);
        // Static half first, WITHOUT touching state: an over-cap block dies on
        // block bytes alone. Previously the full inbox scan ran first, so even
        // a self-evidently over-cap commit paid a whole-state read-lock on a
        // weak node before being refused.
        if sends > crate::state_engine::MAX_ACTOR_MSGS_PER_BLOCK {
            return Err(format!(
                "actor mailbox over cap: 0 queued + {sends} in block > {} (rejected; leftovers never carry over)",
                crate::state_engine::MAX_ACTOR_MSGS_PER_BLOCK
            ));
        }
        // Backlog via the shared (height, root) cache: a hit returns exactly
        // what the scan below would prove (R-tempo). Same verdict as
        // `pending_actor_backlog() + sends > cap`, O(1) on repeat visits.
        let backlog = self.cached_actor_backlog().await;
        if backlog.saturating_add(sends) > crate::state_engine::MAX_ACTOR_MSGS_PER_BLOCK {
            return Err(format!(
                "actor mailbox over cap: {backlog} queued + {sends} in block > {} (rejected; leftovers never carry over)",
                crate::state_engine::MAX_ACTOR_MSGS_PER_BLOCK
            ));
        }
        Ok(())
    }

    /// Spawn-once accessor for the single ordered worker. Lazy so that
    /// construction never needs a tokio context; every apply below funnels
    /// through here, so there is exactly one worker per runtime — never a
    /// pool, never parallel.
    fn ensure_apply_lane(&mut self) -> ApplyLane {
        if self.apply_lane.is_none() {
            self.apply_lane = Some(ApplyLane::spawn(&self.state));
        }
        self.apply_lane.clone().expect("lane just spawned")
    }

    /// Run one decided block's state transition on the worker and wait for
    /// it. The worker runs one job at a time strictly in submission order,
    /// so even concurrent submitters can never interleave two applies: the
    /// second simply waits behind the first on the channel.
    async fn run_on_apply_lane(
        &mut self,
        block: &Block,
        reward: u64,
    ) -> (crate::state_engine::BlockTransitionOutcome, [u8; 32]) {
        let lane = self.ensure_apply_lane();
        let (tx, rx) = tokio::sync::oneshot::channel();
        lane.tx
            .send(LaneJob::Apply(ApplyJob {
                block: block.clone(),
                reward,
                done: tx,
            }))
            .expect("apply worker lives as long as the runtime holds its lane sender");
        rx.await.expect("apply worker answers every job it takes")
    }

    /// `apply_decided`: the exact current finalize-apply sequence — reward
    /// resolution, the shared `apply_block_transition` on the worker,
    /// then the node-local bookkeeping that cannot move the root (via
    /// [`Self::record_apply_outcome`]). Awaited inline: the caller blocks,
    /// but the execution still serializes on the single ordered lane, so it
    /// can never overlap a sequenced submit. Returns the transition outcome
    /// with the certified post-apply root.
    async fn apply_decided(
        &mut self,
        block: &Block,
    ) -> (crate::state_engine::BlockTransitionOutcome, [u8; 32]) {
        // `block.timestamp` is the VM's "now" for every payload in this block:
        // unbonding maturity, contract creation time, order stamps. Every node
        // applying this block passes the SAME value, so the resulting state is
        // deterministic.
        //
        // The reward is the governed value when governance set one, else the
        // node default - resolved by the SAME helper the reorg path uses.
        let reward = block_reward_for(self.governance.as_ref(), self.block_reward);
        let (outcome, root) = self.run_on_apply_lane(block, reward).await;
        self.record_apply_outcome(block, &outcome).await;
        (outcome, root)
    }

    /// Node-local half of the finalize-apply sequence: everything the old
    /// inline `apply_block_fees_rewards` did AFTER `apply_block_transition`
    /// (receipts / applied counters, mempool pruning, cross-shard
    /// bookkeeping). None of it can move the state root, and the reorg path
    /// mirrors it field by field — see `ChainState::apply_block`.
    async fn record_apply_outcome(
        &mut self,
        block: &Block,
        outcome: &crate::state_engine::BlockTransitionOutcome,
    ) {
        self.applied_statuses = outcome.status.clone();
        self.applied_fees = outcome.tx_fees.clone();
        self.applied_events = outcome.events.clone();
        self.applied_txs += outcome.applied as u64;
        // Node-local: remove included txs from our mempool so they are never
        // re-proposed. The mempool is not consensus state and is not part of
        // the state root, so the reorg path (which has no mempool) diverges
        // here without forking - see `ChainState::apply_block`.
        let included: Vec<[u8; 32]> = block
            .transactions
            .iter()
            .map(|t| t.compute_tx_hash())
            .collect();
        self.mempool.write().await.prune_confirmed(&included);
        // CometBFT-style RECHECK after each commit: the commit advanced
        // on-chain nonces, drained balances and may have moved the fee floor,
        // so queued txs valid at admission can now be permanently
        // unexecutable. `recheck` drops exactly those (spent nonce / drained
        // balance / fee below floor) against post-commit state; honest pools
        // come back with 0. Snapshot-then-recheck under SEPARATE short locks
        // (never nested): the accounts read drops before the mempool write is
        // taken, so no lock order is introduced.
        {
            let payers: Vec<[u8; 32]> =
                self.mempool.read().await.fee_payers().into_iter().collect();
            let guard = self.state.accounts.read().await;
            let mut snap: HashMap<[u8; 32], (u64, u64)> =
                HashMap::with_capacity(payers.len());
            for a in &payers {
                if let Some(acct) = guard.get(a) {
                    snap.insert(*a, (acct.nonce, acct.balance));
                }
            }
            drop(guard);
            let dropped = self
                .mempool
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
        // D2 free-failure gate: an included transaction that FAILED at apply
        // paid nothing (the native commit is atomic) while its bytes occupied
        // block wire/gas and burned verifier CPU. Feed the verdicts back so a
        // repeatedly-failing sender must over-post (bond in fee form) to
        // re-enter the pool or a future block; one success clears the sender.
        // PAYMASTER: the penalty stays keyed on the USER (whose nonce
        // advanced and whose failure history it prices) even when the
        // sponsor paid the failure fee — the sponsor is protected by their
        // explicit per-tx cap, not by the penalty.
        {
            let mut failed: Vec<[u8; 32]> = Vec::new();
            let mut succeeded: Vec<[u8; 32]> = Vec::new();
            for (i, tx) in block.transactions.iter().enumerate() {
                if outcome.status.get(i).copied().unwrap_or(false) {
                    succeeded.push(tx.from);
                } else {
                    failed.push(tx.from);
                }
            }
            self.mempool
                .write()
                .await
                .note_apply_feedback(&failed, &succeeded);
        }
        // M2 cross-shard bookkeeping, all a pure function of the block:
        //   * remember every INBOUND message this block credited, so a replay
        //     is refused by `validate_proposal` and skipped at proposal time;
        //   * publish every OUTBOUND message this block produced to the local
        //     transport, so the destination shard can consume it. Publishing is
        //     idempotent (keyed by msg_id) and is a no-op without a transport.
        // §5 M3 extends the same discipline to acks/bounces (all still riding
        // `cross_shard_out`, no new Block/Transaction fields):
        //   * outbound TRANSFERS are recorded in `produced_cross_shard`
        //     (tx hash -> (tx, height)) for linkage + timeout checks;
        //   * a newly consumed transfer publishes an ack to the transport, so
        //     the source shard can commit the completion;
        //   * a newly committed ack marks its transaction complete (no value
        //     movement — the value already moved on the target);
        //   * a newly committed bounce marks its transaction complete AND
        //     refunds `tx.amount` to `tx.from` on this (source) shard, exactly
        //     once (guarded by the consumed set, in deterministic key order);
        //   * every inbound record consumed here is pruned from the transport
        //     KV, so consumed entries cannot accumulate.
        // The engine itself skips proof-less control records (it only credits
        // proof-carrying inbound to `tx.to`), which is why the refund below is
        // the ONLY credit a bounce performs — and validation refuses
        // proof-carrying control records, closing the source-side mint.
        if self.shard_registry.is_sharded() {
            // §9 2PC: refresh the runtime's mirror of the committed 2PC
            // records from the engine (the authority). The mirror is what
            // the SYNCHRONOUS proposal-validation path reads.
            self.xpc_records = self
                .state
                .xpc_snapshot()
                .await
                .into_iter()
                .map(|r| (r.tx_hash, r))
                .collect();
            for msg in &block.cross_shard_out {
                if msg.is_transfer() && msg.is_outbound_for(self.shard_id) {
                    let tx_hash = msg.tx.compute_tx_hash();
                    self.produced_cross_shard
                        .entry(tx_hash)
                        .or_insert((msg.tx.clone(), block.height));
                }
            }
            let mut inbound_sorted: Vec<&CrossShardMessage> = block
                .cross_shard_out
                .iter()
                .filter(|m| m.is_inbound_for(self.shard_id))
                .collect();
            inbound_sorted.sort_by_key(|m| CrossShardKey::of(m));
            let mut pruned_ids: Vec<[u8; 32]> = Vec::new();
            for msg in inbound_sorted {
                let key = CrossShardKey::of(msg);
                if msg.is_xpc() {
                    // §9 2PC: the ENGINE applied the record (it owns the
                    // phase transitions and the value movements), so the
                    // runtime only records the replay key and prunes the
                    // message from the transport mailbox. The value movement
                    // is NOT repeated here - the engine is the single place
                    // that credits a recipient or refunds an escrow, so a
                    // replay can never pay twice.
                    self.consumed_cross_shard.insert(key);
                    pruned_ids.push(msg.msg_id);
                    continue;
                }
                if msg.is_transfer() {
                    // C4: mirror ONLY what the engine actually credited (its
                    // gate verifies + inserts on success). Recording a
                    // proof-less/invalid transfer here used to poison the
                    // mirror: the later VALID retry shared the replay key and
                    // was refused as already-consumed, burning the sender's
                    // funds until a timeout bounce. Engine-first, mirror
                    // second — never the reverse.
                    if !self.state.is_cross_shard_consumed(&key).await {
                        continue;
                    }
                    if self.consumed_cross_shard.insert(key) {
                        pruned_ids.push(msg.msg_id);
                        // Newly consumed: tell the source shard with an ack.
                        // Transport-local only; the committed form is the ack
                        // record the source includes in its own block.
                        let ack = CrossShardMessage::new_ack(msg.tx.clone(), block.compute_hash());
                        if let Some(transport) = &self.cross_shard {
                            if let Err(e) = transport.broadcast_cross_shard(&ack).await {
                                tracing::warn!(
                                    "cross-shard ack publish failed for {}: {e}",
                                    hex::encode(&msg.msg_id[..8])
                                );
                            }
                        }
                    }
                } else if msg.is_ack() || msg.is_bounce() {
                    // Re-check linkage at apply height (same rule validation
                    // used): an apply must never complete what validation
                    // would refuse, no matter which path (finalize / adopt /
                    // walk / replay) brought the block here.
                    if !self.control_linkage_ok(msg, block.height) {
                        continue;
                    }
                    if !self.consumed_cross_shard.insert(key) {
                        continue;
                    }
                    let tx_hash = msg.tx.compute_tx_hash();
                    // Same-block ack+bounce for one transaction: the first in
                    // key order completes it; the second finds it completed.
                    if !self.completed_cross_shard.insert(tx_hash) {
                        continue;
                    }
                    pruned_ids.push(msg.msg_id);
                    if msg.is_bounce() {
                        // The refund: exactly `tx.amount` back to the sender.
                        // Gas went to the source proposer at produce time and
                        // is not refunded. `credit_native` creates the account
                        // if it vanished, and commits to the trie, so every
                        // node applying this block derives the same root.
                        if let Err(e) = self.state.credit_native(&msg.tx.from, msg.tx.amount).await
                        {
                            tracing::warn!(
                                "cross-shard bounce refund failed for {}: {e}",
                                hex::encode(&msg.msg_id[..8])
                            );
                        }
                    }
                }
            }
            if let Some(transport) = &self.cross_shard {
                if !pruned_ids.is_empty() {
                    transport.prune_consumed(self.shard_id, &pruned_ids).await;
                }
                for msg in &block.cross_shard_out {
                    let outbound = if msg.is_transfer() {
                        msg.is_outbound_for(self.shard_id)
                    } else {
                        // §9 2PC: the outbound 2PC records (the vote, the
                        // decision, the abort request) are published the same
                        // way the legacy transfer is.
                        msg.is_xpc() && msg.is_outbound_for(self.shard_id)
                    };
                    if !outbound {
                        continue;
                    }
                    if let Err(e) = transport.broadcast_cross_shard(msg).await {
                        tracing::warn!(
                            "cross-shard publish failed for {}: {e}",
                            hex::encode(&msg.msg_id[..8])
                        );
                    } else {
                        tracing::info!(
                            "cross-shard outbound published {} shard {} -> {}",
                            hex::encode(&msg.msg_id[..8]),
                            self.shard_id,
                            msg.target_shard,
                        );
                    }
                }
            }
        }
    }

    /// Install a worker-reported outcome: the node-local bookkeeping above,
    /// then the consensus advance the old inline path did (finalized entry,
    /// validator-set rotation, next height). Runs exactly once per decided
    /// block, whether the decision was awaited inline or collected later.
    async fn install_apply_outcome(
        &mut self,
        height: Height,
        bh: BlockHash,
        block: &Block,
        outcome: &crate::state_engine::BlockTransitionOutcome,
    ) {
        self.record_apply_outcome(block, outcome).await;
        // C-02: height-driven gov finalization (locks release, 7200-height
        // timelocks schedule). Deterministic in (height, block.timestamp).
        sweep_gov_finalize(&self.state, height, block.timestamp).await;
        self.finalized.push((height, bh));
        // The block is final: it anchors the fork-choice tree, and every
        // candidate branch it superseded is pruned (and signalled).
        self.note_finalized_block(block);
        // Any finalize is progress: the deadlock breaker measures silence.
        self.last_progress_at = std::time::Instant::now();
        // C1 anchor: every finalized block (live, replayed, adopted) feeds
        // the process-shared header registry its own and sibling shards read.
        self.note_finalized_header(block).await;
        self.note_light_anchor(block);
        // Rotate the consensus validator set from bonded stake at the height
        // boundary. Deterministic: every node derives it from the same consensus
        // ledger, so all nodes agree on the new set/power for height+1.
        // W10.5: the refresh only STAGES the change (activation height+1);
        // it becomes in-force below, exactly when this node moves to the new
        // height — never mid-flight.
        self.refresh_validator_set_from_staking().await;
        self.hc = HeightConsensus::new(height + 1, self.validators.clone());
        self.install_due_validator_set();
        self.hc.validators = self.validators.clone();
        // The sortition committee of height+1 is elected from the PARENT
        // block hash — the block we just finalized. Every node of the network
        // must use the same parent, or they elect different committees.
        self.hc.set_parent_hash(bh);
    }

    /// Shared DECISION half of finalization: quorum, presence, order and cap
    /// gates, QC attachment and decision-proof stash. Both `try_finalize`
    /// (await inline) and `try_finalize_submit` (queue on the worker) decide
    /// through here, so the two can never disagree about what is decidable.
    /// Returns the decided height, hash and block (QC attached).
    async fn prepare_decided_block(&mut self) -> Option<(Height, BlockHash, Block)> {
        // One apply at a time, strictly height-ordered: while a decided block
        // is still on the worker our height has not advanced, so deciding
        // again now would queue the SAME height twice. Refuse; the next poll
        // collects the pending outcome and this retries then.
        if self.apply_in_flight.is_some() {
            return None;
        }
        let bh = self.hc.try_precommit_quorum()?;
        let height = self.hc.height;
        // The block must actually be here.
        //
        // This used to be `if let Some(block) = ... { apply }` followed by
        // committing to the height unconditionally. A peer could therefore send
        // three precommits for a hash of its choosing and never send the block:
        // the node skipped every check, skipped applying anything, still pushed
        // the height, still rotated the validator set from the ledger, and still
        // slashed - all on the strength of a block it had never received or
        // validated. It is a quorum of honest validators, so this is not a
        // byzantine scenario, it is what happens whenever a block is lost in
        // transit.
        let Some(block) = self.blocks.get(&bh).cloned() else {
            tracing::warn!(
                height,
                "quorum reached for a block this node does not have; refusing to finalize"
            );
            return None;
        };
        // Body integrity re-check (audit 2026-10-06): the map is keyed by hash
        // but the STORED bytes may have been corrupted/reordered after
        // insertion — executing a body whose hash no longer matches the voted
        // `bh` would finalize a DIFFERENT state than the quorum (a split).
        // Refuse, like the missing-body case above. (A mere ORDER-COMMITMENT
        // mismatch below is different: the body is byte-identical to what the
        // quorum voted, so execution converges everywhere.)
        if block.compute_hash() != bh {
            tracing::warn!(
                height,
                "stored body hash does not match the decided hash; refusing to finalize"
            );
            return None;
        }
        // MEV ORDER COMMITMENT (consensus-enforced): the block carries the
        // order Merkle root over its transaction list and the root is inside
        // the signed block hash, so the quorum that decided this block voted
        // for its ORDER as well. Re-compute the root from the body about to
        // execute and REFUSE to finalize a block that does not match.
        //
        // This used to be a warning: the commitment was node-local evidence
        // only (it was never in the block), so refusing would have stalled
        // ONLY the builder while the rest of the network moved on. Now the
        // commitment is on the wire and signed by the quorum, a mismatch is
        // real tamper evidence, and every node derives the same verdict — so
        // it is a hard refusal, not a log line.
        if let Err(e) = self.check_order_commitment(&block) {
            tracing::error!(height, "{e}; refusing to finalize");
            return None;
        }
        // The node-local build-time commitment stays as an OPTIMIZATION and
        // as a second, independent witness: if THIS NODE built the block
        // being decided, the order about to execute is compared against the
        // commitment it made at build time.
        //
        // It is a WARNING, never a refusal (policy change, audit 2026-10-06):
        // the body about to execute is byte-identical to the one the quorum
        // voted (the hash check above), so the ORDER is what the network
        // committed — and the consensus-level check above (`check_order_
        // commitment`, the root INSIDE the signed hash) has already proved
        // it. A stale LOCAL witness therefore says nothing about the chain,
        // and refusing on it stalls ONLY the builder at that height while
        // every other node moves on (the exact regression this policy
        // change fixed).
        if block.proposer == self.id {
            let pool = self.mempool.read().await;
            match pool
                .mev
                .verify_block_order(block.height, bh, &block.transactions)
            {
                crate::mev::OrderVerdict::NoCommit | crate::mev::OrderVerdict::Match => {}
                verdict => {
                    tracing::warn!(
                        height,
                        ?verdict,
                        "block order differs from this node's build-time commitment; \
                         finalizing anyway (the quorum-voted body is authoritative)"
                    );
                }
            }
        }
        // Actor-mailbox cap (finalize side): an over-cap block is never
        // executed, so the defensive clamp in the engine can never leave a
        // root-invisible leftover behind on this path either.
        if let Err(e) = self.check_actor_cap(&block).await {
            tracing::warn!(height, "{e}; refusing to finalize");
            return None;
        }
        // Attach the precommit QC that decided this block, so the decision travels
        // with the block. A block otherwise carries only the PROPOSER's signature,
        // and every other validator's agreement exists only as a vote -- which is over
        // `vote_sign_bytes`, a different message from the block hash, so those
        // signatures can never verify as block signatures and grafting them was
        // wrong. Block sync verifies the attached QC (kind, height, quorum) instead.
        let mut finalized_block = block;
        finalized_block.precommit_qc = self.hc.precommit_qc.clone();
        // Replace the proposal-only version so what we serve and republish carries
        // the decision proof and can be verified by anyone.
        self.blocks.insert(bh, finalized_block.clone());
        // Stash the decision proof for the commit broadcast: `try_finalize`
        // resets `hc` below, so reading `hc.precommit_qc` afterwards (as the
        // main loop once did) always finds None and the broadcast silently
        // never fires -- lagging peers then never learn outcomes.
        if let Some(qc) = self.hc.precommit_qc.clone() {
            self.last_decision = Some((height, finalized_block.clone(), qc));
        }
        // W10.5 HARDENING (fail LOUD, never finalize unilaterally): the QC
        // that decided this block must carry quorum power under the set IN
        // FORCE AT THIS HEIGHT. `try_precommit_quorum` already enforces
        // quorum, so a failure here means the in-force set moved mid-flight
        // (the activation-boundary bug) or the QC was assembled against a
        // foreign set — either way finalizing would fork the chain, so the
        // decision is refused with the exact shortfall attached. A node with
        // only its own vote in a multi-validator set can never pass this.
        {
            let in_force = self.validator_set_for_height(height);
            let Some(qc) = self.hc.precommit_qc.as_ref() else {
                tracing::error!(
                    height,
                    "REFUSING to finalize: decided without a precommit QC (unilateral finalization is never allowed)"
                );
                eprintln!(
                    "[quorum] REFUSING to finalize height {height}: decided without a precommit QC — unilateral finalization is never allowed"
                );
                crate::metrics::global().inc_weak_qc_refused();
                return None;
            };
            let signed = in_force.qc_signed_power(qc);
            let required = in_force.quorum_power();
            if signed < required {
                tracing::error!(
                    height,
                    signed,
                    required,
                    total = in_force.total_power(),
                    "REFUSING to finalize: deciding QC carries {signed} of {required} required power (total {}) — unilateral/weak finalization is never allowed",
                    in_force.total_power(),
                );
                eprintln!(
                    "[quorum] REFUSING to finalize height {height}: deciding QC carries {signed} of {required} required power — unilateral/weak finalization is never allowed"
                );
                crate::metrics::global().inc_weak_qc_refused();
                return None;
            }
        }
        let block = finalized_block;
        Some((height, bh, block))
    }

    pub async fn try_finalize(&mut self) -> Option<BlockHash> {
        let (height, bh, block) = self.prepare_decided_block().await?;
        // Economic security from block content: the transition runs the
        // downtime slash from `block.last_qc` (canonical proposer-chosen
        // evidence for height-1) AND the equivocation slash from the block's
        // `SysCallReportEquivocation` payloads (re-verified from block bytes,
        // pool-debited, per-offense deduped) inside `apply_block_transition` -
        // the same core the reorg path uses, so both burn the same coins.
        //
        // F4: LOCAL-observation equivocation is intentionally NOT slashed
        // here. Its evidence is a pair of conflicting votes this node
        // happened to observe on the local gossip path, not block content,
        // so a node that finalized locally and a node that
        // adopted/walked/replayed the same height would burn different
        // stake and commit different state roots. See
        // `apply_equivocation_slashes` for the full rationale; the WIRED
        // path is block-carried evidence via `apply_block_transition`.
        self.apply_block_fees_rewards(&block).await;
        // C-02: height-driven gov finalization (locks release, 7200-height
        // timelocks schedule). Deterministic in (height, block.timestamp).
        sweep_gov_finalize(&self.state, height, block.timestamp).await;
        self.finalized.push((height, bh));
        // The block is final: it anchors the fork-choice tree, and every
        // candidate branch it superseded is pruned (and signalled).
        self.note_finalized_block(&block);
        self.last_progress_at = std::time::Instant::now();
        self.note_finalized_header(&block).await;
        self.note_light_anchor(&block);
        // Rotate the consensus validator set from bonded stake at the height
        // boundary. Deterministic: every node derives it from the same consensus
        // ledger, so all nodes agree on the new set/power for height+1.
        // W10.5: the refresh only STAGES the change (activation height+1);
        // it becomes in-force below, exactly when this node moves to the new
        // height — never mid-flight.
        self.refresh_validator_set_from_staking().await;
        self.hc = HeightConsensus::new(height + 1, self.validators.clone());
        self.install_due_validator_set();
        self.hc.validators = self.validators.clone();
        // The sortition committee of height+1 is elected from the PARENT
        // block hash — the block we just finalized. Every node of the network
        // must use the same parent, or they elect different committees.
        self.hc.set_parent_hash(bh);
        Some(bh)
    }

    /// §7 Phase 2 sequenced submit: decide through the same
    /// [`Self::prepare_decided_block`] as [`Self::try_finalize`], then queue
    /// the execution on the single ordered worker WITHOUT awaiting it and
    /// return the decided hash immediately.
    ///
    /// Nothing observable moves here: no `finalized` entry, no height
    /// advance, no receipts. The caller keeps draining inbound messages and
    /// collects the outcome with [`Self::try_poll_apply`] (or
    /// [`Self::await_apply_completion`]), which installs it and advances.
    /// Returns `None` when there is nothing to decide (no quorum, missing
    /// body, failed order/cap gate) or when an apply is already in flight —
    /// at most one decided block is ever queued or executing.
    pub async fn try_finalize_submit(&mut self) -> Option<BlockHash> {
        if self.parallel_exec {
            self.state.set_parallel_exec(true);
        }
        let (height, bh, block) = self.prepare_decided_block().await?;
        // The reward is resolved NOW, from the same helper the inline path
        // uses, so the worker executes byte-identically with no governance
        // read of its own.
        let reward = block_reward_for(self.governance.as_ref(), self.block_reward);
        let lane = self.ensure_apply_lane();
        let (tx, rx) = tokio::sync::oneshot::channel();
        if lane
            .tx
            .send(LaneJob::Apply(ApplyJob {
                block: block.clone(),
                reward,
                done: tx,
            }))
            .is_err()
        {
            return None;
        }
        self.apply_in_flight = Some(ApplyInflight {
            height,
            hash: bh,
            block,
            done: rx,
        });
        Some(bh)
    }

    /// Non-blocking collect of the sequenced apply: when the worker has
    /// reported back, install the outcome (bookkeeping + height advance) and
    /// return it; when it is still executing, leave everything untouched and
    /// return `None` so the loop keeps draining. Safe to call every tick.
    pub async fn try_poll_apply(&mut self) -> Option<ApplyCompleted> {
        let mut inflight = self.apply_in_flight.take()?;
        match inflight.done.try_recv() {
            Ok((outcome, root)) => {
                self.install_apply_outcome(
                    inflight.height,
                    inflight.hash,
                    &inflight.block,
                    &outcome,
                )
                .await;
                Some(ApplyCompleted {
                    height: inflight.height,
                    hash: inflight.hash,
                    root,
                })
            }
            Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {
                self.apply_in_flight = Some(inflight);
                None
            }
            Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                // The worker only ends when every lane sender is gone, and one
                // lives in `self`, so this is unreachable without a worker
                // panic. Re-queueing blindly could double-apply; park the
                // height (loudly) instead of advancing past an unapplied block.
                tracing::error!(
                    "apply worker vanished mid-block at height {}; height stuck until restart",
                    inflight.height
                );
                self.apply_in_flight = Some(inflight);
                None
            }
        }
    }

    /// Blocking collect of the sequenced apply, for tests and startup paths
    /// that have nothing else to drain while they wait. Installs the outcome
    /// exactly like [`Self::try_poll_apply`] and returns it with the
    /// certified post-apply root.
    pub async fn await_apply_completion(&mut self) -> Option<ApplyCompleted> {
        let inflight = self.apply_in_flight.take()?;
        let (outcome, root) = inflight.done.await.ok()?;
        self.install_apply_outcome(inflight.height, inflight.hash, &inflight.block, &outcome)
            .await;
        Some(ApplyCompleted {
            height: inflight.height,
            hash: inflight.hash,
            root,
        })
    }

    /// Submit a quiescent snapshot capture to the sequenced lane (see
    /// `SnapBundle`). `expected_root` is the worker-certified post-`height`
    /// root: the worker captures only if the engine still roots there, so a
    /// mislabeled capture is impossible no matter the queue order.
    /// Non-blocking; at most one in flight (a second submit is refused).
    pub fn submit_snapshot(&mut self, height: u64, expected_root: [u8; 32]) -> bool {
        if self.snapshot_in_flight.is_some() {
            return false;
        }
        let lane = self.ensure_apply_lane();
        let (tx, rx) = tokio::sync::oneshot::channel();
        if lane
            .tx
            .send(LaneJob::Snapshot(SnapshotJob {
                height,
                expected_root,
                done: tx,
            }))
            .is_err()
        {
            return false;
        }
        self.snapshot_in_flight = Some(rx);
        true
    }

    /// Non-blocking collect of a submitted snapshot capture. `None` while the
    /// worker has not reached it yet — or when the worker SKIPPED it (engine
    /// moved past the certified root); either way the caller retries on a
    /// later height and labels stay exact.
    pub fn poll_snapshot(&mut self) -> Option<SnapBundle> {
        let mut rx = self.snapshot_in_flight.take()?;
        match rx.try_recv() {
            Ok(Some(bundle)) => Some(bundle),
            Ok(None) => None,
            Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {
                self.snapshot_in_flight = Some(rx);
                None
            }
            Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                // Worker died mid-capture: fail LOUD (fail-closed) so the gap
                // in snapshots is visible instead of silently missing.
                tracing::error!("snapshot capture lost: apply worker died mid-capture");
                None
            }
        }
    }

    /// Re-apply a HISTORICAL block during startup healing (engine behind head).
    ///
    /// Same effects as finalization minus consensus: the full block transition
    /// (`apply_block_transition`: fees/rewards, unbonding, downtime slash),
    /// validator-set rotation. Does NOT touch `finalized` (the head is already
    /// seeded from metadata) and does NOT reset `hc` (the caller owns height/round
    /// bookkeeping during replay).
    ///
    /// Every applied block must carry a verifiable precommit QC, and its header must
    /// commit to the engine state as it stands (F3.2). Blocks from before blocks
    /// carried QCs cannot be replayed and are an error -- that history predates
    /// verifiable sync and the node must be wiped, not guessed forward.
    pub async fn replay_historical_block(&mut self, block: &Block) -> Result<(), String> {
        // NOTE: the TRANSACTION-ORDER commitment is deliberately NOT re-checked
        // here. This path replays ALREADY-DECIDED history: the block's hash
        // commits to the transaction order (the tx hashes are hashed in
        // execution order), and the decision proof below binds that hash, so
        // the order of a historical block is as committed as the rest of its
        // body. Blocks decided BEFORE the order commitment existed carry no
        // root at all, and re-deriving one here would refuse the very history
        // the node is catching up on. The order root is enforced where it
        // matters: on the LIVE paths (proposal, finalize, adopt).
        let bh = block.compute_hash();
        let Some(qc) = &block.precommit_qc else {
            return Err(format!(
                "block {} carries no decision proof (predates verifiable history)",
                block.height
            ));
        };
        if qc.kind != crate::consensus::VoteKind::Precommit {
            return Err(format!(
                "block {} decision proof is not a precommit quorum",
                block.height
            ));
        }
        if qc.height != block.height {
            return Err(format!(
                "block {} decision proof is for height {}",
                block.height, qc.height
            ));
        }
        if qc.block_hash != Some(bh) {
            return Err(format!(
                "block {} decision proof commits to a different block",
                block.height
            ));
        }
        let root_before = self.state.get_state_root().await;
        if block.state_root != root_before {
            return Err(format!(
                "block {} commits to parent state root {} but engine is at {} (gap in replay range?)",
                block.height,
                hex::encode(block.state_root),
                hex::encode(root_before)
            ));
        }
        // W10.5: verify the historical QC against the set that was in force
        // AT THIS HEIGHT, not the current one. Replay gives us the exact
        // oracle for free: the engine is already at this block's committed
        // PRE-state, and the set in force for height H is derived from the
        // staking ledger at the end of H-1 -- i.e. exactly that pre-state. So
        // derive it here instead of trusting the live `self.validators`
        // (which, after a restart, starts from the config set rather than
        // the ledger at the replay anchor). The pure sync path
        // (`validate_sync_chain_with_sets`) cannot do this -- it has no state
        // engine -- so it threads per-height sets from the caller's
        // `validator_set_for_height` history instead (see the old F5 note it
        // resolves).
        //
        // Fall back to `self.validators` when staking is empty: a network that
        // never bonded uses its config-defined set, and `to_validator_set` would
        // be empty there.
        let historical_vs = {
            let ledger = self.state.staking_read().await;
            ledger.to_validator_set()
        };
        let verify_set = if historical_vs.is_empty() {
            self.validators.clone()
        } else {
            historical_vs
        };
        if !qc.binds_to_parent(&block.prev_hash) {
            return Err(format!(
                "block {} decision proof was elected with a different parent block",
                block.height
            ));
        }
        if !qc.verify(&verify_set) {
            return Err(format!(
                "block {} decision proof lacks a validator quorum at its height",
                block.height
            ));
        }
        // The verified certificate is installed into `hc` to keep the
        // consensus bookkeeping in step with the replay. NOTE (W10.5): it is
        // NOT downtime evidence anymore — the transition attributes from the
        // block's embedded `last_qc` (canonical, proposer-chosen), so a
        // replayed block converges with the live-applied one even when the
        // locally observed finality QC was a different quorate subset.
        //
        // `None` evidence skips attribution HERE exactly as on the live
        // path (`apply_block_transition` skips `None`; live
        // `try_finalize`/`apply_and_advance` add nothing further). The
        // replay path MUST NOT apply a legacy slash from the attached
        // finality QC for `None` blocks: post-upgrade proposers that knew
        // no parent decision (restored/healed nodes) emit `None`, the live
        // path skips those heights, and a replay that burned them anyway
        // landed on a different post-state root for identical block bytes
        // — the same-hash fork observed live (masterchain #304133 /
        // #304395). Pinned by `tests/none_evidence_parity_tests.rs`.
        //
        // Pre-upgrade history (blocks decided by a binary that attributed
        // from the finality QC) is NOT replayable across this boundary:
        // replaying it would reproduce the old subset-dependent
        // attribution the upgrade removed. Catch those heights up with a
        // verified snapshot, never with a walk (the same rule as blocks
        // that predate verifiable QCs entirely, above).
        //
        // F4: LOCAL-observation equivocation slashing is deliberately
        // skipped on EVERY path now, not just this one. It was never
        // replayable (votes are not persisted, and the block carries no
        // gossip evidence), so replaying it here while the local-finalize
        // path slashed it split the chain. See
        // `apply_equivocation_slashes`. The WIRED path is block-carried
        // evidence (`SysCallReportEquivocation` scanned from the decided
        // block in `apply_block_transition`), which every path applies
        // identically.
        self.hc.precommit_qc = Some(qc.clone());
        self.blocks.insert(bh, block.clone());
        self.apply_block_fees_rewards(block).await;
        // C-02: same deterministic gov-finalization sweep as the live path,
        // so a replayed catch-up converges with live-finalized nodes.
        sweep_gov_finalize(&self.state, block.height, block.timestamp).await;
        // The replayed block is canonical, finalized history: the
        // fork-choice tree follows it, so the candidates seen afterwards
        // are compared against the right chain.
        self.note_finalized_block(block);
        self.refresh_validator_set_from_staking().await;
        Ok(())
    }

    /// Apply a finalized block's transactions and distribute its fees/rewards.
    /// Shared by `try_finalize`, `apply_and_advance` and
    /// `replay_historical_block` so a block reaches the state engine identically
    /// no matter how it was decided.
    ///
    /// ALL of the state work now lives in one place:
    /// `InMemoryStateEngine::apply_block_transition`, the same function
    /// `ChainState::apply_block` (the reorg path) calls — executed here via
    /// [`Self::apply_decided`] (same sequence the sequenced submit runs, only
    /// awaited inline). This wrapper only adds the node-local bookkeeping
    /// that cannot move the state root: receipts / applied counters and
    /// mempool pruning.
    async fn apply_block_fees_rewards(&mut self, block: &Block) {
        if self.parallel_exec {
            self.state.set_parallel_exec(true);
        }
        let (_outcome, _root) = self.apply_decided(block).await;
    }

    /// Apply an adopted block and move to the next height, exactly as a locally
    /// finalized block would be handled. Also used by live catch-up, which must
    /// reproduce the identical transition (not just transaction effects).
    pub async fn apply_and_advance(&mut self, bh: BlockHash, block: &Block) {
        if self.parallel_exec {
            self.state.set_parallel_exec(true);
        }
        // The full transition (txs, fees, reward, unbonding, downtime slash)
        // runs inside `apply_block_fees_rewards` from the block's own content,
        // so adopting/walking a block is byte-identical to finalizing it and to
        // a reorg re-applying it.
        //
        // F4: no LOCAL-observation equivocation slash on the adopt/walk path
        // (or any other). It would read local vote observations, which are
        // not block content, and split the chain against the local-finalize
        // path. See `apply_equivocation_slashes`. Block-carried evidence
        // (`SysCallReportEquivocation`) slashes uniformly on every path via
        // `apply_block_transition`. Downtime evidence travels with the
        // block as `last_qc` (canonical, proposer-chosen, in the block
        // hash) — never the attached finality `precommit_qc`, whose signer
        // subset differs per observer. `None` evidence skips attribution
        // on this path exactly as on finalize and replay.
        self.apply_block_fees_rewards(block).await;
        let height = self.hc.height;
        // C-02: height-driven gov finalization (locks release, 7200-height
        // timelocks schedule). Deterministic in (height, block.timestamp).
        sweep_gov_finalize(&self.state, height, block.timestamp).await;
        self.finalized.push((height, bh));
        // The block is final: it anchors the fork-choice tree, and every
        // candidate branch it superseded is pruned (and signalled).
        self.note_finalized_block(block);
        self.last_progress_at = std::time::Instant::now();
        self.note_finalized_header(block).await;
        self.note_light_anchor(block);
        self.refresh_validator_set_from_staking().await;
        self.hc = HeightConsensus::new(height + 1, self.validators.clone());
        // W10.5: activate the set staged for the new height (never mid-flight).
        self.install_due_validator_set();
        self.hc.validators = self.validators.clone();
        // The sortition committee of height+1 is elected from the PARENT
        // block hash — the block we just finalized. Every node of the network
        // must use the same parent, or they elect different committees.
        self.hc.set_parent_hash(bh);
    }

    /// Whether the validator set is currently refused as STALE (fail-closed
    /// observer mode: the node follows and validates but must NOT vote).
    pub fn is_validator_set_stale(&self) -> bool {
        self.validator_set_stale
    }

    /// Human-readable stale reason, if any (see [`Self::is_validator_set_stale`]).
    pub fn validator_set_stale_reason(&self) -> Option<&str> {
        self.validator_set_stale_reason.as_deref()
    }

    /// Effective franchise: the static config flag AND ledger membership, MINUS
    /// the stale gate. A node with a stale ledger is an observer even if its
    /// key is in the (foreign) set — voting with a foreign set is exactly the
    /// node-C failure (silent wrong quorums instead of an honest observer).
    pub fn effective_can_vote(&self, config_is_validator: bool) -> bool {
        if self.validator_set_stale {
            return false;
        }
        config_is_validator || self.validators.validators.contains_key(&self.id)
    }

    /// Mark the set STALE (fail-closed to observer). LOUD on both channels;
    /// records both heights so the operator sees how far the ledger lags.
    pub fn mark_validator_set_stale(
        &mut self,
        state_height: u64,
        ledger_height: u64,
        reason: String,
    ) {
        self.validator_set_stale = true;
        self.validator_set_stale_reason = Some(reason.clone());
        self.validator_set_state_height = Some(state_height);
        self.validator_set_ledger_height = Some(ledger_height);
        tracing::warn!(
            "[validator-set] WARN stale validator set at state {state_height} (ledger {ledger_height}): {reason} — fail-closed to observer (no votes) until a fresh ledger arrives"
        );
        eprintln!(
            "[validator-set] WARN stale validator set at state {state_height} (ledger {ledger_height}): {reason} — fail-closed to observer (no votes) until a fresh ledger arrives"
        );
    }

    /// Clear the stale gate after a FRESH set was installed or verified.
    pub fn clear_validator_set_stale(&mut self) {
        self.validator_set_stale = false;
        self.validator_set_stale_reason = None;
    }

    /// Re-entry hysteresis sweep: LOUD-warn every member the derived set
    /// GAINS over the previous set, count it, watch it for liveness, and
    /// re-WARN watched re-entrants that still show no votes after N heights.
    ///
    /// ADDITIVE LOGGING ONLY — no logic change: the derived set the caller
    /// installs is never filtered, reordered or refused here. Both channels
    /// (tracing + stderr) because an offline re-entrant in a micro-quorum is
    /// a chain-halt precursor and must be unmissable.
    ///
    /// Liveness signal: the ledger's QC-derived `missed` streak (same
    /// evidence the downtime slasher uses — block content, identical on every
    /// node), via [`crate::staking::reentry_liveness_risk`]. A watched member
    /// leaves the watch when it drops out of the derived set again or its
    /// streak is forgiven (`missed == 0`, i.e. it signed a certificate).
    fn note_validator_set_gains(
        &mut self,
        derived: &crate::consensus::ValidatorSet,
        ledger: &crate::staking::StakingLedger,
    ) {
        let height = self.hc.height;
        // Snapshot the pre-existing watch BEFORE inserting this refresh's
        // gains: a member gained right now has a clean `missed` streak (it
        // could not miss certificates while unelected), so sweeping it in the
        // same pass would instantly unwatch it and the liveness watch would
        // never hold a fresh re-entrant.
        let watched: Vec<(ValidatorId, u64)> =
            self.reentry_watch.iter().map(|(m, h)| (*m, *h)).collect();
        for (member, power) in crate::staking::validator_set_gains(&self.validators, derived) {
            let msg = crate::staking::reentry_warn_message_for(&member, power, height);
            tracing::warn!("{msg}");
            eprintln!("{msg}");
            self.validator_reentry_warns_total =
                self.validator_reentry_warns_total.saturating_add(1);
            self.reentry_watch.insert(member, height);
        }
        let mut unwatched: Vec<ValidatorId> = Vec::new();
        for (member, rejoined_at) in &watched {
            let power = derived.validators.get(member).copied().unwrap_or(0);
            if power == 0 {
                // Re-ejected (or never installed): stop watching silently.
                unwatched.push(*member);
                continue;
            }
            let missed = ledger.validators.get(member).map(|v| v.missed).unwrap_or(0);
            if missed == 0 {
                // Signed a certificate since rejoining: healthy, stop watching.
                unwatched.push(*member);
                continue;
            }
            if crate::staking::reentry_liveness_risk(*rejoined_at, height, missed)
                && height.saturating_sub(*rejoined_at) % 10 == 0
            {
                let msg = crate::staking::reentry_liveness_warn_message_for(
                    member,
                    power,
                    *rejoined_at,
                    height,
                    missed,
                );
                tracing::warn!("{msg}");
                eprintln!("{msg}");
            }
        }
        for m in unwatched {
            self.reentry_watch.remove(&m);
        }
    }

    /// Core installer used by every refresh path: freshness-gated set install
    /// from an explicit ledger with explicit heights.
    ///
    /// * STALE (`ledger_height` lags `state_height` beyond
    ///   [`crate::storage::validator_set_freshness_max_lag`]): LOUD warn,
    ///   stale flag set, set NOT installed, returns `false`. The caller keeps
    ///   its old set for READS but must not vote (see
    ///   [`Self::effective_can_vote`]).
    /// * FRESH: derives the set from `ledger`; installs on change (with the
    ///   usual before/after warn), clears the stale flag, returns whether the
    ///   set changed. Empty stays a no-op (pre-bond network keeps its config
    ///   set), exactly like [`Self::refresh_validator_set_from_staking`].
    pub async fn refresh_validator_set_from_ledger(
        &mut self,
        ledger: &crate::staking::StakingLedger,
        state_height: u64,
        ledger_height: u64,
    ) -> bool {
        if let Err(reason) =
            crate::storage::check_validator_set_freshness(state_height, ledger_height)
        {
            self.mark_validator_set_stale(state_height, ledger_height, reason);
            return false;
        }
        self.install_validator_set_from_ledger(ledger, state_height, ledger_height)
            .await
    }

    /// Install the validator set derived from `ledger` (already known to be
    /// acceptable) into the runtime AND the height consensus.
    ///
    /// W10.5 ACTIVATION BOUNDARY: a set derived from the ledger at
    /// ledger-height L takes effect at height L+1, NEVER immediately. The
    /// derived set is STAGED in [`Self::pending_validators`]; it becomes the
    /// in-force consensus set when the node advances to the activation
    /// height ([`Self::install_due_validator_set`], called on every
    /// finalize/adopt advance and after every refresh). Deriving the same
    /// ledger at the same ledger-height stages the same activation on every
    /// node, so the whole network switches quorums at the same agreed height
    /// instead of each node jumping its threshold mid-flight whenever it
    /// happens to refresh (the 2026-10-23 #292785/#292786 stall: one node
    /// finalized unilaterally under a stale quorum while the rest had already
    /// moved on, and the quorum certificates never reconciled).
    ///
    /// Split out of [`Self::refresh_validator_set_from_ledger`] so the
    /// masterchain-registry path (a workchain reading the masterchain's
    /// ledger) can install a set WITHOUT the cross-chain height comparison
    /// the local path needs: the workchain's height and the masterchain's
    /// height are different chains, so comparing them is meaningless.
    ///
    /// Empty stays a no-op: a registry nobody has met the minimum bond in
    /// keeps the config-defined set (the pre-bond network behaviour).
    async fn install_validator_set_from_ledger(
        &mut self,
        ledger: &crate::staking::StakingLedger,
        state_height: u64,
        ledger_height: u64,
    ) -> bool {
        let vs = ledger.to_validator_set();
        // Re-entry hysteresis (local policy + visibility ONLY — the derived
        // set `vs` below is installed or compared verbatim, never filtered).
        // урок валидатора C: an ejected-then-topped-up validator silently
        // rejoined while offline and halted a micro-quorum. Every gain gets a
        // LOUD warn + counter + liveness watch; watched re-entrants with no
        // votes for N heights get a repeating liveness-risk WARN.
        self.note_validator_set_gains(&vs, ledger);
        if vs.is_empty() || vs.validators == self.validators.validators {
            // Fresh ledger that changes nothing proves we are NOT stale.
            // A staged pending set for the same content is redundant: drop
            // it so a flapping refresh cannot resurrect an older derivation.
            if let Some((_, ref pending)) = self.pending_validators {
                if pending.validators == vs.validators {
                    self.pending_validators = None;
                }
            }
            self.clear_validator_set_stale();
            self.validator_set_state_height = Some(state_height);
            self.validator_set_ledger_height = Some(ledger_height);
            // The in-force set is unchanged, but a due pending set (staged by
            // an earlier derivation) may now be installable at this height.
            self.install_due_validator_set();
            return false;
        }
        let activation = ledger_height.saturating_add(1);
        let fmt = |m: &std::collections::BTreeMap<ValidatorId, u64>| {
            m.iter()
                .map(|(k, p)| format!("{}:{}", hex::encode(&k[..4]), p))
                .collect::<Vec<_>>()
                .join(",")
        };
        tracing::warn!(
            "validator set change staged at ledger height {}: [{}] -> [{}] (takes effect at height {})",
            ledger_height,
            fmt(&self.validators.validators),
            fmt(&vs.validators),
            activation,
        );
        eprintln!(
            "[validator-set] shard {} staged a validator-set change at ledger height {} (in force from height {}): [{}] -> [{}]",
            self.shard_id,
            ledger_height,
            activation,
            fmt(&self.validators.validators),
            fmt(&vs.validators),
        );
        self.pending_validators = Some((activation, vs));
        self.clear_validator_set_stale();
        self.validator_set_state_height = Some(state_height);
        self.validator_set_ledger_height = Some(ledger_height);
        // A staged change whose activation is already reached (restore /
        // repair paths that derive from an old ledger while the consensus
        // height already moved past it) installs immediately: the network is
        // already voting that set, and running the previous one would fork.
        self.install_due_validator_set();
        true
    }

    /// Install the staged validator-set change if its activation height has
    /// been reached.
    ///
    /// Called after every refresh (covers restore/repair derivations whose
    /// activation is already due) and on every height advance (finalize,
    /// sequenced-apply completion, adopt): the set staged for H+1 becomes
    /// in-force exactly when the node moves to H+1. Returns true when a new
    /// set took effect.
    pub fn install_due_validator_set(&mut self) -> bool {
        let due = matches!(&self.pending_validators, Some((activation, _)) if *activation <= self.hc.height);
        if !due {
            return false;
        }
        let (activation, vs) = self.pending_validators.take().expect("checked above");
        // First install of this process: also record the set being superseded
        // as in force since height 0. Without it, `validator_set_for_height`
        // has no answer for heights below the first recorded activation and
        // falls back to the NEW set — which would verify PRE-change
        // certificates against post-change powers (fail-OPEN for ancient
        // windows). The superseded entry makes those heights verify against
        // the pre-change set instead (fail-CLOSED: a newer set may refuse an
        // ancient QC, never accept a quorum that was not one). Heights at or
        // above the first recorded activation are exact either way.
        if self.validator_set_history.is_empty() {
            self.validator_set_history
                .push_back((0, self.validators.clone()));
        }
        let fmt = |m: &std::collections::BTreeMap<ValidatorId, u64>| {
            m.iter()
                .map(|(k, p)| format!("{}:{}", hex::encode(&k[..4]), p))
                .collect::<Vec<_>>()
                .join(",")
        };
        tracing::warn!(
            "validator set activated at height {}: [{}] -> [{}]",
            activation,
            fmt(&self.validators.validators),
            fmt(&vs.validators),
        );
        eprintln!(
            "[validator-set] shard {} ACTIVATED the staged set at height {}: [{}] -> [{}]",
            self.shard_id,
            activation,
            fmt(&self.validators.validators),
            fmt(&vs.validators),
        );
        self.validators = vs.clone();
        self.hc.validators = vs.clone();
        self.validator_set_history.push_back((activation, vs));
        while self.validator_set_history.len() > VALIDATOR_SET_HISTORY_CAP {
            self.validator_set_history.pop_front();
        }
        true
    }

    /// Re-align the consensus-local validator set with the runtime's in-force
    /// set when they diverged without a height advance.
    ///
    /// INVARIANT: `hc.validators` is the in-force set for `hc.height`; it is
    /// rebuilt from `validators` on every height advance and mirrored by
    /// [`Self::install_due_validator_set`]. That covers every path that moves
    /// heights — but a refresh can move `validators` WITHOUT moving heights
    /// (restore from a lagging domains snapshot, then a live-ledger refresh
    /// that derives a newer set; or the reverse order). The consensus copy
    /// then strands on the older set: this node computes a different
    /// proposer schedule from peers that derived the same newer set, rejects
    /// their proposals as "wrong proposer", and no height ever advances to
    /// heal it (observed live: post-restart wedge at #388561, B on the
    /// post-change set vs C/D on the pre-change one, zero finality until the
    /// copies realigned).
    ///
    /// The runtime set is strictly fresher-or-equal here: every path that
    /// assigns `validators` derives it from a ledger at least as new as the
    /// consensus copy's basis (the copy is only ever written from
    /// `validators` itself — construction, height advance, install-due — so
    /// it cannot run ahead). Syncing the copy forward therefore completes an
    /// already-decided transition; it never reverts one. A staged future
    /// change is untouched: when its activation arrives,
    /// `install_due_validator_set` installs the same values (a no-op content
    /// change plus the history entry).
    ///
    /// Called from the periodic set-repair timer (no height advance needed).
    /// Returns true when a resync happened. LOUD: a resync means this node
    /// was voting a stale schedule.
    pub fn resync_consensus_set_to_runtime(&mut self) -> bool {
        if self.hc.validators.validators == self.validators.validators {
            return false;
        }
        let fmt = |m: &std::collections::BTreeMap<ValidatorId, u64>| {
            m.iter()
                .map(|(k, p)| format!("{}:{}", hex::encode(&k[..4]), p))
                .collect::<Vec<_>>()
                .join(",")
        };
        tracing::warn!(
            "validator-set resync at height {}: consensus copy [{}] -> runtime in-force [{}]",
            self.hc.height,
            fmt(&self.hc.validators.validators),
            fmt(&self.validators.validators),
        );
        eprintln!(
            "[validator-set] shard {} resync at height {}: consensus copy [{}] -> runtime in-force [{}]",
            self.shard_id,
            self.hc.height,
            fmt(&self.hc.validators.validators),
            fmt(&self.validators.validators),
        );
        self.hc.validators = self.validators.clone();
        true
    }

    /// The validator set IN FORCE at height `h`: the newest set whose
    /// activation height is at most `h`.
    ///
    /// W10.5: every quorum check for a certificate at height H — local
    /// decide, adopt, sync-chain verify, light-client anchor, replay, and the
    /// downtime-attribution gate — MUST use this, never the live set. A set
    /// change takes effect at a clean H+1 boundary on every node, so the set
    /// in force at H is a pure function of the chain (the prefix finalized
    /// before H), not of when this node happened to refresh.
    ///
    /// Heights at/above the current consensus height use the live in-force
    /// set; older heights walk the activation history. When the history does
    /// not reach back far enough (a change predates this process's start and
    /// no entry covers `h`), the OLDEST known set is returned: it is the
    /// current set, which is correct for every height since the last change —
    /// and a change older than the history can only make this conservative
    /// (verify against a newer set may refuse an ancient QC, never accept a
    /// quorum that was not one).
    pub fn validator_set_for_height(&self, h: u64) -> ValidatorSet {
        // A staged change already answers for heights at/above its
        // activation, even before the node advances there: the switch is
        // pre-agreed, not speculative.
        if let Some((activation, pending)) = &self.pending_validators {
            if *activation <= h {
                return pending.clone();
            }
        }
        if h >= self.hc.height {
            return self.validators.clone();
        }
        let mut best: Option<&ValidatorSet> = None;
        for (activation, vs) in &self.validator_set_history {
            if *activation <= h {
                best = Some(vs);
            }
        }
        best.cloned().unwrap_or_else(|| {
            self.validator_set_history
                .front()
                .map(|(_, vs)| vs.clone())
                .unwrap_or_else(|| self.validators.clone())
        })
    }

    /// Install a validator set derived from the MASTERCHAIN's staking ledger.
    ///
    /// This is the workchain path: the masterchain owns the staking registry
    /// (bond / unbond / slash are masterchain transactions) and the workchain
    /// has none of its own, so the workchain's consensus set is derived from
    /// the master's ledger, shared process-wide through
    /// [`Self::master_staking`].
    ///
    /// NO cross-chain height comparison here: the two heights belong to
    /// DIFFERENT chains (the workchain's and the masterchain's), so the
    /// freshness gate of [`Self::refresh_validator_set_from_ledger`] does not
    /// apply. What that gate protects against, a restored ledger that lags the
    /// state by more than the snapshot window, is the masterchain runtime's own
    /// business: it is the one that restores the ledger and the one that knows
    /// whether it is fresh (see [`Self::refresh_validator_set_from_staking_checked`]
    /// on the masterchain side, and the fail-closed observer mode it arms).
    ///
    /// The shared ledger is written by the masterchain runtime under the SAME
    /// lock this read takes, so the read is atomic and never torn: the
    /// workchain installs either the pre-rotation or the post-rotation set,
    /// never a mixture.
    pub async fn refresh_validator_set_from_master_ledger(
        &mut self,
        ledger: &crate::staking::StakingLedger,
        height: u64,
    ) -> bool {
        self.install_validator_set_from_ledger(ledger, height, height)
            .await
    }

    /// The MASTERCHAIN registry, when this runtime must take its consensus
    /// set from it.
    ///
    /// `Some` only for a WORKCHAIN with the shared handle wired and a
    /// registry that holds a set: the masterchain owns the staking registry,
    /// and a workchain's own ledger is empty by design, so deriving the set
    /// from it froze the workchain on the config-defined set for the whole
    /// life of the process (the audit's "validator set gap").
    ///
    /// An empty master registry (nobody bonded yet) yields `None`: the
    /// config-defined set is kept, exactly as before.
    async fn master_registry(&self) -> Option<crate::staking::StakingLedger> {
        if !ValidatorSetSource::for_shard(self.shard_id).uses_masterchain() {
            return None;
        }
        let master = self.master_staking.as_ref()?;
        let ledger = master.read().await.clone();
        if ledger.to_validator_set().is_empty() {
            return None;
        }
        Some(ledger)
    }

    /// Checked refresh from the live engine ledger with explicit heights.
    ///
    /// Restore / snapshot-refresh paths MUST call this (not the unchecked
    /// [`Self::refresh_validator_set_from_staking`]): it compares the ledger
    /// height against the state height and fail-closed to observer on
    /// staleness instead of silently installing a foreign set.
    ///
    /// A WORKCHAIN has no ledger of its own to be stale about: its set comes
    /// from the masterchain's registry (see [`Self::master_staking`]), whose
    /// freshness is the masterchain runtime's own business. The cross-chain
    /// height comparison is therefore skipped for it, because the workchain's
    /// height and the masterchain's height belong to different chains and
    /// comparing them would refuse a perfectly fresh set.
    pub async fn refresh_validator_set_from_staking_checked(
        &mut self,
        state_height: u64,
        ledger_height: u64,
    ) -> bool {
        if let Some(ledger) = self.master_registry().await {
            return self
                .refresh_validator_set_from_master_ledger(&ledger, self.hc.height)
                .await;
        }
        let ledger = self.state.staking_read().await.clone();
        self.refresh_validator_set_from_ledger(&ledger, state_height, ledger_height)
            .await
    }

    /// Refresh the set from FRESH domain-snapshot bytes fetched separately
    /// from blocks (the lagging-node repair path).
    ///
    /// Decodes `domain_bytes` (V0/V1 via
    /// [`crate::storage::decode_domain_snapshot`]) and installs its staking
    /// ledger through [`Self::refresh_validator_set_from_ledger`] with the
    /// snapshot's height as `ledger_height` and the node's current state
    /// height as `state_height`. Undecodable bytes are a loud `Err` and never
    /// touch the set. This is how a node whose bond predates every walkable
    /// body pulls the CURRENT set without replaying ancient history.
    ///
    /// A WORKCHAIN ignores its own snapshot's registry: the staking registry
    /// lives on the masterchain, so the masterchain's ledger is the only
    /// source of the consensus set (a workchain-local snapshot could never
    /// define who the workchain's validators are).
    pub async fn refresh_validator_set_from_domain_bytes(
        &mut self,
        domain_bytes: &[u8],
        state_height: u64,
        ledger_height: u64,
    ) -> Result<bool, String> {
        if let Some(ledger) = self.master_registry().await {
            return Ok(self
                .refresh_validator_set_from_master_ledger(&ledger, self.hc.height)
                .await);
        }
        let snap = crate::storage::decode_domain_snapshot(domain_bytes).map_err(|e| {
            format!("validator-set refresh: domain snapshot at {ledger_height} undecodable: {e}")
        })?;
        Ok(self
            .refresh_validator_set_from_ledger(&snap.staking, state_height, ledger_height)
            .await)
    }

    /// Recompute the validator set (and voting power) from the staking ledger.
    ///
    /// Reads the ledger out of the **state engine**, not from a node-local copy:
    /// consensus has to be a function of the block, otherwise two nodes that
    /// heard different bond transactions over RPC would derive different
    /// validators and deadlock on disagreeing about who proposes.
    ///
    /// No-op when nobody meets the minimum self-bond, so a network that has
    /// never been bonded keeps using its config-defined set.
    ///
    /// WORKCHAIN: the registry is the MASTERCHAIN's, shared process-wide (see
    /// [`Self::master_staking`]). A masterchain rotation is therefore adopted
    /// here at the height boundary, and the new set is in force from
    /// `height + 1` (see [`crate::sharding::validator_set_adoption_height`]) —
    /// no node restart, no separate registry to reconcile.
    ///
    /// Apply-path wrapper: the ledger just came out of the transition at the
    /// current height, so state and ledger heights coincide (always fresh).
    /// Restore / snapshot paths must use
    /// [`Self::refresh_validator_set_from_staking_checked`] with real heights
    /// instead, or a stale ledger installs silently (node C).
    pub async fn refresh_validator_set_from_staking(&mut self) -> bool {
        let h = self.hc.height;
        self.refresh_validator_set_from_staking_checked(h, h).await
    }

    /// Periodic workchain validator-set repair (R3 CODE-TAILS sweep).
    ///
    /// Every other refresh site sits on a height-advance path (live finalize,
    /// adopt, walk, snapshot-sync, restore): a workchain that stops finalizing
    /// — the wedged shard-1 state (`wrong proposer` rejects on a diverged set,
    /// no height ever advances) — therefore never re-reads the masterchain
    /// registry and can never converge on its own. This is the one call site
    /// that re-reads the master ledger WITHOUT requiring any height advance:
    /// it routes through [`Self::refresh_validator_set_from_staking`] (so a
    /// workchain with the master handle wired derives from
    /// [`Self::master_registry`], stages the change at the W10.5 activation
    /// boundary and clears/sets the stale gate exactly like the finalize
    /// path), then installs whatever is due. No-op (`false`, nothing touched)
    /// for the masterchain and single-shard nodes, so the consensus loop can
    /// call it unconditionally on a timer.
    ///
    /// The repair unblocks the wedge transitively: once the CURRENT master set
    /// is staged, the next walk verifies block H+1 against
    /// [`Self::validator_set_for_height`] (which answers pending sets at/above
    /// their activation), applies it, advances, and installs the set due —
    /// the same convergence the finalize path performs, without needing a
    /// finalize to start it.
    pub async fn refresh_workchain_set_from_master(&mut self) -> bool {
        if !crate::sharding::ValidatorSetSource::for_shard(self.shard_id).uses_masterchain() {
            return false;
        }
        if self.master_staking.is_none() {
            return false;
        }
        // Idempotence for the timer: an unchanged master registry re-derives
        // the same set every interval, and the installer below re-stages (and
        // re-WARNs) on every call. When the pending set already stages exactly
        // what the registry derives for the same activation, there is nothing
        // to stage — install whatever is due and report quiet.
        let h = self.hc.height;
        if let Some((activation, pending)) = self.pending_validators.clone() {
            if activation == h.saturating_add(1) {
                if let Some(ledger) = self.master_registry().await {
                    if pending.validators == ledger.to_validator_set().validators {
                        self.install_due_validator_set();
                        return false;
                    }
                }
            }
        }
        let changed = self.refresh_validator_set_from_staking().await;
        self.install_due_validator_set();
        changed
    }

    /// View change: move to the next round.
    pub fn next_round(&mut self) {
        self.hc.next_round();
    }

    /// Adopt a block a peer reports as committed, once its certificate proves a
    /// real quorum of our own validators signed it.
    ///
    /// This is the catch-up path for a node that fell a round behind: the
    /// certificate is checked against the *local* validator set, so a peer can
    /// only make us apply a block that the network genuinely finalized. A peer
    /// cannot invent one.
    pub async fn adopt_committed(
        &mut self,
        height: u64,
        mut block: Block,
        certificate: crate::consensus::QuorumCertificate,
    ) -> Result<crate::cell::CellHash, String> {
        if self.parallel_exec {
            self.state.set_parallel_exec(true);
        }
        // §7 Phase 2 gate: adopting means executing, and execution is still
        // running for the decided height. The checks below read our root
        // (PRE-H until the worker reports back) and `apply_and_advance` would
        // queue a second apply behind it — for a height we have not advanced
        // past. Deferred, not validated; the peer rebroadcasts (and catch-up
        // re-walks) until we are ready.
        if self.apply_in_flight.is_some() {
            return Err("committed block deferred: apply in flight".to_string());
        }
        // W10.5: verify against the set IN FORCE AT THIS HEIGHT, never the
        // live set. A peer can only make us apply a block the network genuinely
        // finalized — under the quorum rules every node used for this height.
        // (A validator-set change takes effect at a clean H+1 boundary on
        // every node; checking a height-H certificate against today's set
        // accepts quorums H never had and refuses quorums H genuinely reached.)
        let validators = self.validator_set_for_height(height);
        if height != self.hc.height {
            return Err(format!(
                "height mismatch (ours {}, peer {height})",
                self.hc.height
            ));
        }
        if block.height != height {
            return Err("block height does not match the commit".to_string());
        }
        // SECURITY: the certificate must be a COMMIT certificate. `certificate.kind`
        // was never read, and `QuorumCertificate::verify` signs over the
        // certificate's own fields, so a PREVOTE quorum verified just as well.
        // Prevotes are broadcast in the clear for every round, including rounds
        // that never finalize, so a passive peer could harvest one off the wire,
        // relabel the kind and ship it as proof of finality -- with zero stake of
        // its own. "2/3 saw this block" is not "2/3 committed to it".
        if certificate.kind != crate::consensus::VoteKind::Precommit {
            return Err("commit certificate is not a precommit quorum".to_string());
        }
        // SECURITY: bind the certificate to this height AND round. Both fields are
        // signed, so without this check a quorum harvested at any height or round
        // replayed as a commit for our current height. `height` is already pinned
        // to `self.hc.height` above, so this makes the certificate describe the
        // height it is being used to prove.
        if certificate.height != height {
            return Err(format!(
                "certificate is for height {} not {height}",
                certificate.height
            ));
        }
        // A commit that landed while we already timed out into a later round is
        // still a valid quorum for THIS height — refusing it forced a full
        // catch-up for a one-round skew ("60% of time 1 round apart"). Accept
        // anything within the same lookback the finalizer itself uses, so
        // adoption and finalization agree on what "recent" means.
        //
        // THE "BEHIND" BOUND IS THE SCAN SPAN, NOT THE LOOKBACK (liveness fix,
        // live 2026-10-21: the masterchain parked at height 285027 with a
        // prevote QC and NO precommit QC). The finalizer no longer restricts
        // itself to the recent rounds: a decision that was taken in an OLD
        // round (because the deciding quorum only completed long after the
        // network moved on) is still the decision of THIS height, and the node
        // that was the last one to see it MUST be able to adopt it — that is
        // how it gets the body it is missing. Refusing it here left the node
        // stuck in the "decided but no body" state forever: it could not
        // finalize (no body), it could not vote again (its step is Commit) and
        // it could not adopt the decision the peers kept offering it.
        //
        // The height is already bound above (the certificate must be for
        // `self.hc.height`) and the quorum is verified against our own
        // validator set below, so the round of the decision carries no
        // authority of its own: a height has ONE decision, and this is it.
        //
        // FUTURE rounds are normally refused (forward sync owns them, not
        // adoption) — with ONE exception: a certificate from a round that is
        // STRICTLY LATER than our own lock is the proof that the network moved
        // on without us. That is exactly the case a locked node must follow
        // (adopting it is the SEC-01 fix); refusing it as "forward" left the
        // node partitioned from the canonical chain forever. The exception is
        // bounded by the same lookback, so a certificate from an absurdly far
        // future round is still refused, and it still has to pass the
        // validator-quorum verification below.
        let lock_supersedes = self
            .hc
            .locked
            .map(|(_, locked_round)| certificate.round > locked_round)
            .unwrap_or(false);
        if certificate.round != self.hc.round {
            let behind = self.hc.round.saturating_sub(certificate.round);
            let lookback = crate::consensus::ROUND_LOOKBACK as u64;
            let forward = certificate.round.saturating_sub(self.hc.round);
            let forward_ok = lock_supersedes && forward as u64 <= lookback;
            if (certificate.round > self.hc.round && !forward_ok)
                || behind as u64 > crate::consensus::MAX_SCAN_SPAN as u64
            {
                return Err(format!(
                    "certificate is for round {} not {} (lookback {lookback})",
                    certificate.round, self.hc.round
                ));
            }
        }
        let bh = block.compute_hash();
        // Cheap binding check BEFORE the signature loop: `verify` runs one
        // Ed25519 verification per entry and the list is attacker-supplied and
        // uncapped, so checking the cheap thing first avoids an unbounded
        // signature-verification loop driven by one message.
        if certificate.block_hash != Some(bh) {
            return Err("certificate commits to a different block".to_string());
        }
        if certificate.signatures.len() > MAX_COMMIT_CERT_SIGNERS {
            return Err("commit certificate has an implausible number of signers".to_string());
        }
        // HOT-PATH ORDER (observer C, 2026-10-13): every check below is fail-closed,
        // so order changes cost, not safety. The expensive one is `certificate.verify`
        // (one Ed25519 + one Falcon-512 verify per signer on Pure PQ) — run ALL cheap
        // header checks first so a forked/misaddressed commit dies before burning
        // weak-CPU verifier time. Previously the QC verify ran before the linkage
        // checks and every stale commit paid full crypto cost.
        //
        // SECURITY: the proposer must be the one the schedule names for this
        // height/round, not merely a key that signed. Otherwise a peer names an
        // address it controls, and `apply_block_fees_rewards` credits the fees to
        // it with no membership test.
        if Some(block.proposer) != validators.proposer_for(height, certificate.round) {
            return Err("committed block's proposer is not the expected proposer".to_string());
        }
        // The block must still be a valid extension of what we finalized.
        // Checked here (before any signature loop) so a commit for a forked head
        // is refused on two hash comparisons, not on quorum verification.
        let expected_prev = self.finalized.last().map(|(_, h)| *h).unwrap_or([0u8; 32]);
        if block.prev_hash != expected_prev {
            return Err("committed block does not extend our finalized head".to_string());
        }
        if block.transactions.len() > MAX_BLOCK_TXS {
            return Err("committed block is oversized".to_string());
        }
        let total_gas = block
            .transactions
            .iter()
            .fold(0u64, |acc, t| acc.saturating_add(t.gas_limit));
        if total_gas > MAX_BLOCK_GAS {
            return Err("committed block exceeds the gas limit".to_string());
        }
        // Single proposer signature before the quorum loop: one Ed25519 verify
        // filters forged bodies before paying per-signer QC cost.
        if !crate::consensus::verify_proposer_signature(&block) {
            return Err("committed block has no valid proposer signature".to_string());
        }
        if !certificate.binds_to_parent(&block.prev_hash) {
            return Err("commit certificate was elected with a different parent block".to_string());
        }
        if !certificate.verify(&validators) {
            return Err("commit certificate does not carry a validator quorum".to_string());
        }
        // W10.5 HARDENING (fail LOUD): the power behind the certificate must
        // reach the quorum of the set in force at THIS height — with the
        // numbers attached, not just a boolean. `verify` above already
        // enforces quorum, so this fires only when the two disagree (a bug),
        // or names the exact shortfall for the operator when a peer serves a
        // weak certificate (e.g. a unilateral finalization carrying only the
        // joiner's power after the set already moved on). Either way it is
        // unmissable: error log + metric + refusal.
        {
            let signed = validators.qc_signed_power(&certificate);
            let required = validators.quorum_power();
            if signed < required {
                tracing::error!(
                    height,
                    signed,
                    required,
                    total = validators.total_power(),
                    "REFUSING weak commit certificate: carries {signed} of {required} required power (total {}) — unilateral finalization is never adopted",
                    validators.total_power(),
                );
                eprintln!(
                    "[quorum] REFUSING weak commit certificate at height {height}: carries {signed} of {required} required power — unilateral finalization is never adopted"
                );
                crate::metrics::global().inc_weak_qc_refused();
                return Err(format!(
                    "commit certificate carries only {signed} of {required} required power at height {height}"
                ));
            }
        }
        // SECURITY: do not let the adopt path decide a block that contradicts a lock
        // we already took.
        //
        // The lock is taken on a polka at round `locked_round`. A commit
        // certificate for a DIFFERENT block is only acceptable when it comes
        // from a STRICTLY LATER round: that is the proof that the network moved
        // on without us, so the lock is superseded and must be followed (the
        // old `locked_round <= certificate.round` test refused exactly that and
        // partitioned the node from every canonical commit after a single
        // lost vote).
        //
        // A certificate at the SAME round as the lock (or earlier) that names a
        // different block is a genuine safety conflict - two conflicting
        // polkas in one round need more than 1/3 Byzantine power - so it is
        // refused. A certificate for the SAME block is always fine: that is
        // our own lock being confirmed.
        if let Some((locked_block, locked_round)) = self.hc.locked {
            if certificate.round <= locked_round && locked_block != bh {
                return Err("refusing to adopt a block that contradicts our lock".to_string());
            }
        }
        // PREVOTE-QUORUM CONSISTENCY (parity with `try_precommit_quorum`):
        // the local path refuses to decide a block unless a prevote quorum for
        // the SAME block exists in the same round. The adopt path receives only
        // the precommit QC on the wire, so full parity is IMPOSSIBLE without a
        // wire change: the peer would have to ship a prevote QC for
        // (height, round, block) alongside the commit certificate (new param or
        // envelope field), and we would `verify` it against `self.validators`
        // exactly like the precommit QC above. The signature is deliberately
        // unchanged (main.rs + tests call `adopt_committed(height, block,
        // certificate)`), so what we CAN do soundly is consult `self.hc`'s
        // recorded prevotes for `certificate.round`: if we observed a quorum
        // for a DIFFERENT target (another block, or nil), adopting this block
        // contradicts evidence we already hold and is refused. If we observed
        // nothing -- the normal catching-up node -- the check is VACUOUS and
        // the precommit QC is trusted transitively (honest validators only
        // precommit after a prevote quorum, so 2/3 precommits imply one
        // existed). Residual gap, stated plainly: a Byzantine quorum (or key
        // compromise reaching quorum power) can fabricate precommits for a
        // block nobody prevoted, and a lagging node with empty prevote sets
        // cannot tell; closing it requires the wire change above, not a
        // stricter local check (refusing on empty local prevotes would make
        // catch-up impossible by construction).
        if let Some(set) = self.hc.prevote_set(certificate.round) {
            if let Some(local_target) = set.quorum_target(&validators) {
                if local_target != Some(bh) {
                    return Err("refusing to adopt: our prevote quorum for this round is for a different block".to_string());
                }
            }
        }
        // SECURITY: bind the block to the state it builds on. A block header commits
        // to the state root BEFORE it is applied, and the linkage check above already
        // forces the block to extend our own finalized head -- so the parent state IS
        // ours and our live root is the right thing to compare against. Without this
        // the adopt path applied blocks to a state the network never committed to,
        // and computed a root nobody else had.
        // (Linkage, size/gas and proposer-signature checks ran above, before the QC
        // verify — not repeated here: the hot path verifies each once.)
        let root_before = self.state.get_state_root().await;
        if block.state_root != root_before {
            return Err(format!(
                "committed block claims parent state root {} but our state is {}",
                hex::encode(block.state_root),
                hex::encode(root_before)
            ));
        }
        // PERF_PROFILE §6.2: parallel intake batch — byte-identical verdict
        // to the serial batch (see sharding.rs: same primitive apply uses).
        if !crate::sharding::Transaction::verify_signatures_batch_parallel(&block.transactions) {
            return Err("committed block contains a bad transaction signature".to_string());
        }
        // Actor-mailbox cap (adopt side): the same deterministic refusal as
        // propose/finalize, so a Byzantine commit carrying an over-cap block
        // cannot smuggle a root-invisible leftover past the decision boundary.
        self.check_actor_cap(&block).await?;
        // TRANSACTION-ORDER COMMITMENT (adopt side): the same rule the
        // proposal and finalize paths apply. The quorum certificate already
        // binds the block hash (which contains the order root), so on an
        // upgraded network this can only fire for a body whose order was
        // never committed — refused, never applied.
        self.check_order_commitment(&block)?;
        // Timestamp gate (adopt side, A3): the same fail-closed parent check
        // the proposal path runs, so a commit cannot smuggle a timestamp no
        // proposer could publish. Runs BEFORE the body is stored: the check
        // reads the parent out of `blocks`/`last_decision`, and storing first
        // would let a block vouch for itself.
        self.check_block_timestamp(&block)?;
        // CANONICAL DOWNTIME EVIDENCE (adopt side, W10.5): the same rule the
        // proposal path applies. The transition attributes downtime from the
        // embedded parent QC, so an adopted block must carry evidence the
        // network actually decided — verified against the set in force at H-1.
        self.check_last_qc_evidence(&block)?;

        // DOWNTIME PARITY with the local path: the transition reads its slash
        // evidence from `block.last_qc` (canonical, proposer-chosen — see
        // `check_last_qc_evidence`), and this body never ran the height's
        // rounds locally, so the body may arrive without a certificate while
        // the commit message carries the verified one. Attach the
        // just-verified certificate to the body BEFORE it is stored and applied
        // as the FINALITY proof (checkpoints, light clients, sync); it is no
        // longer slash evidence. A later reorg re-apply of this very body
        // reproduces the same burn from the same embedded evidence instead of
        // finding no evidence at all.
        // `Block::compute_hash` deliberately excludes the finality QC (it
        // commits to the header + transactions + canonical evidence), so
        // attaching it cannot change `bh`.
        // Without this, a node catching up skipped the burn (and the pool
        // debit) while a node that finalized locally applied it, and the two
        // reached different state roots from the same block.
        self.hc.precommit_qc = Some(certificate.clone());
        block.precommit_qc = Some(certificate.clone());
        // W10.5: record the decision exactly like the local-finalize path, so
        // the NEXT proposal embeds it as canonical downtime evidence.
        self.last_decision = Some((height, block.clone(), certificate));
        self.blocks.insert(bh, block.clone());
        self.apply_and_advance(bh, &block).await;
        Ok(bh)
    }

    pub async fn state_root(&self) -> [u8; 32] {
        self.state.get_state_root().await
    }
}

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
        let runtimes = nodes
            .into_iter()
            .map(|(k, st)| ValidatorRuntime::new(k, validators.clone(), st, 1))
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
            .map(|(k, st)| {
                ValidatorRuntime::new(k, validators.clone(), st, 1)
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
                    let _ = self.state.credit_native(&msg.tx.from, msg.tx.amount).await;
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
            let mut snap: HashMap<[u8; 32], (u64, u64)> =
                HashMap::with_capacity(payers.len());
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_engine::AccountState;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[tokio::test]
    async fn c2_timed_validation_verdict_identical_and_stages_named() {
        // TASK 5: timed path must accept/refuse EXACTLY like the untimed path,
        // while naming the slow stage.
        let key = SigningKey::generate(&mut OsRng);
        let me = key.verifying_key().to_bytes();
        let validators = ValidatorSet::from_list(vec![(me, 1)]);
        let mut rt = ValidatorRuntime::new(key, validators, funded_state(me).await, 1);
        let root = rt.state.get_state_root().await;
        let mut block = rt.propose(1_700_000_001).await.expect("propose");
        block.state_root = root;
        let plain = rt.validate_proposal_unaligned(&block, root);
        let (timed, stages) = rt.validate_proposal_timed(&block, root);
        assert_eq!(plain.is_ok(), timed.is_ok(), "verdicts must agree");
        let names: Vec<&str> = stages.iter().map(|(s, _)| s.as_str()).collect();
        for want in [
            "proposer_sig_verify",
            "state_root_check",
            "order_commit",
            "tx_batch_verify",
            "fee_floor_mempool",
        ] {
            assert!(
                names.contains(&want),
                "stage {want} must be attributed, got {names:?}"
            );
        }
        // A corrupt block is refused by BOTH paths identically.
        let mut bad = block.clone();
        bad.state_root = [0xFF; 32];
        assert!(rt.validate_proposal_unaligned(&bad, root).is_err());
        let (timed_bad, _) = rt.validate_proposal_timed(&bad, root);
        assert!(timed_bad.is_err());
    }

    #[tokio::test]
    async fn c2_slow_validation_meter_and_log_name_slow_stage() {
        let key = SigningKey::generate(&mut OsRng);
        let me = key.verifying_key().to_bytes();
        let validators = ValidatorSet::from_list(vec![(me, 1)]);
        let mut rt = ValidatorRuntime::new(key, validators, funded_state(me).await, 1);
        assert_eq!(rt.slow_validation_total, 0);
        // Fast validation: no meter.
        rt.note_validation_timing(&[
            ("proposer_sig_verify".into(), 5),
            ("tx_batch_verify".into(), 10),
        ]);
        assert_eq!(rt.slow_validation_total, 0);
        // Slow validation: meter + names the slow stage (trie vs sigs vs mempool).
        rt.note_validation_timing(&[
            ("proposer_sig_verify".into(), 20),
            ("state_root_check".into(), 900),
            ("tx_batch_verify".into(), 30),
            ("fee_floor_mempool".into(), 10),
        ]);
        assert_eq!(rt.slow_validation_total, 1);
        assert_eq!(rt.validation_last_stages.len(), 4);
        let slowest = rt
            .validation_last_stages
            .iter()
            .max_by_key(|(_, ms)| *ms)
            .unwrap();
        assert_eq!(slowest.0, "state_root_check");
    }

    /// C2 ACCEPTANCE: 4-node harness (live-like powers C1470/B1999/A1999/D2000,
    /// quorum 4980 of 7468) with ONE 5x-slow member (D) finalizes 20
    /// consecutive blocks with <= 2 view-changes per block.
    ///
    /// The slow member's proposal arrives one round late (it cannot keep a
    /// 3.5s round on 1 vCPU): the first round for its slots times out nil,
    /// the adaptive deterministic timeout then covers the late arrival and
    /// the NEXT round finalizes. Every other proposer's slot finalizes in
    /// round 0. This exercises the real `propose` / `on_proposal` /
    /// prevote / precommit / `try_finalize` paths on every node, not a stub.
    #[tokio::test]
    async fn c2_acceptance_20_blocks_one_slow_member_max_2_view_changes() {
        // Deterministic keys: same harness, same schedule, every run.
        let seeds: [u8; 4] = [0x0C, 0x0B, 0x0A, 0x0D]; // C, B, A, D
        let powers: [u64; 4] = [1470, 1999, 1999, 2000];
        let keys: Vec<SigningKey> = seeds
            .iter()
            .map(|s| SigningKey::from_bytes(&[*s; 32]))
            .collect();
        let ids: Vec<ValidatorId> = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();
        let slow_id = ids[3]; // D: largest power, 1 vCPU, historically nil-voting
        let validators = ValidatorSet::from_list(
            ids.iter()
                .zip(powers.iter())
                .map(|(id, p)| (*id, *p))
                .collect(),
        );
        assert_eq!(validators.total_power(), 7468);
        assert_eq!(validators.quorum_power(), 4979); // floor(2*7468/3)+1
        assert!(
            7468 - 2000 >= validators.quorum_power(),
            "any single nil-voter is survivable"
        );
        assert!(
            2000 + 1999 < validators.quorum_power(),
            "any TWO nil-voters stall (needs >=3 of 4)"
        );

        let mut nodes: Vec<ValidatorRuntime> = Vec::new();
        for (i, k) in keys.iter().enumerate() {
            let st = Arc::new(InMemoryStateEngine::new());
            crate::runtime::fund_genesis(&st, &validators, 1_000_000).await;
            // FULL-PQ: votes only verify with a Falcon half, so every node
            // carries a persisted Falcon key (deterministic per test).
            let fk = FalconKeypair::generate_from_seed(0xC0 + i as u8);
            let mut rt =
                ValidatorRuntime::new(k.clone(), validators.clone(), st, 1).with_falcon_key(fk);
            rt.hc.set_parent_hash([0u8; 32]);
            nodes.push(rt);
        }
        // Sanity: deterministic timeout really does extend slow-proposer rounds.
        let base = 3500u64;
        assert!(crate::consensus::deterministic_round_timeout_ms(base, 0, 4) > base);

        let mut table: Vec<(u64, u32)> = Vec::new(); // (height, view_changes)
        let mut ts: u64 = 1_700_000_000;
        for h in 1u64..=20 {
            ts += 1;
            debug_assert!(
                nodes.iter().all(|n| n.hc.height == h),
                "heights must stay in lockstep"
            );
            let mut view_changes: u32 = 0;
            // If the slot proposer is the slow member, burn exactly ONE nil
            // round first (its 5x-slow proposal cannot land in time), then
            // finalize in the next round under the adaptive timeout.
            let proposer0 = nodes[0]
                .hc
                .validators
                .proposer_for(h, nodes[0].hc.round)
                .unwrap();
            let slow_slot = proposer0 == slow_id;
            if slow_slot {
                for n in nodes.iter_mut() {
                    n.next_round(); // classified nil + proposer-miss inside hc
                }
                view_changes += 1;
            }
            // Propose at the (possibly advanced) round.
            let r = nodes[0].hc.round;
            let pidx = nodes
                .iter()
                .position(|n| n.validators.proposer_for(h, r) == Some(n.id))
                .expect("proposer");
            let block = nodes[pidx]
                .propose(ts)
                .await
                .expect("proposer failed to propose");
            let bh = block.compute_hash();
            let pid = nodes[pidx].id;
            for (i, n) in nodes.iter_mut().enumerate() {
                if i != pidx {
                    n.on_proposal(pid, block.clone(), r)
                        .await
                        .expect("proposal rejected");
                }
            }
            let prevotes: Vec<Vote> = nodes.iter().filter_map(|n| n.make_prevote()).collect();
            assert!(!prevotes.is_empty());
            for v in &prevotes {
                for n in nodes.iter_mut() {
                    let _ = n.on_prevote(v.clone());
                }
            }
            let precommits: Vec<Vote> = nodes
                .iter_mut()
                .filter_map(|n| n.make_precommit())
                .collect();
            assert!(
                !precommits.is_empty(),
                "polka must yield precommits at h={h}"
            );
            for v in &precommits {
                for n in nodes.iter_mut() {
                    let _ = n.on_precommit(v.clone());
                }
            }
            for n in nodes.iter_mut() {
                let got = n.try_finalize().await;
                assert_eq!(got, Some(bh), "all 4 nodes must finalize h={h}");
            }
            assert!(
                view_changes <= 2,
                "h={h}: {} view changes (>2)",
                view_changes
            );
            table.push((h, view_changes));
        }
        // Measured acceptance table (also printed for the report).
        println!("C2 ACCEPTANCE heights/rounds-per-block (slow=D 5x):");
        for (h, vc) in &table {
            println!("height={h} view_changes={vc}");
        }
        assert_eq!(table.len(), 20);
        assert!(table.iter().all(|(_, vc)| *vc <= 2));
        let slow_slots = table.iter().filter(|(_, vc)| *vc == 1).count();
        assert!(
            slow_slots >= 1,
            "the slow member must own slots in 20 heights (hash schedule)"
        );
    }

    async fn funded_state(owner: [u8; 32]) -> Arc<InMemoryStateEngine> {
        let st = Arc::new(InMemoryStateEngine::new());
        st.update_account(AccountState::new(owner, 10_000_000))
            .await;
        st
    }

    /// P3-CLOCK: the deterministic timestamp gate (`check_block_timestamp`)
    /// is monotone vs the parent and bounded +1h ahead. A Byzantine proposer
    /// with a skewed clock can fast-forward VM time (unbonding, sessions,
    /// dispute windows) only inside this envelope -- never backwards, never
    /// by more than one jump per block, never past an unknown parent.
    fn gate_block(height: u64, prev: [u8; 32], ts: u64, proposer: [u8; 32]) -> Block {
        Block {
            shard_id: crate::sharding::MASTERCHAIN_SHARD,
            height,
            prev_hash: prev,
            state_root: [0u8; 32],
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: ts,
            proposer,
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
            mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
        }
    }

    #[tokio::test]
    async fn p3_timestamp_gate_monotone_and_bounded() {
        let key = SigningKey::generate(&mut OsRng);
        let me = key.verifying_key().to_bytes();
        let validators = ValidatorSet::from_list(vec![(me, 1)]);
        let mut rt = ValidatorRuntime::new(key, validators, funded_state(me).await, 2);

        // Parent at height 1 with timestamp 1_000_000.
        let parent = gate_block(1, [0u8; 32], 1_000_000, me);
        let parent_hash = parent.compute_hash();
        rt.blocks.insert(parent_hash, parent);

        // Same timestamp: monotone OK.
        assert!(rt
            .check_block_timestamp(&gate_block(2, parent_hash, 1_000_000, me))
            .is_ok());
        // Exactly one max jump ahead: OK (the envelope's edge).
        assert!(rt
            .check_block_timestamp(&gate_block(
                2,
                parent_hash,
                1_000_000 + MAX_TIMESTAMP_JUMP_SECS,
                me
            ))
            .is_ok());
        // One second past the envelope: refused.
        assert!(rt
            .check_block_timestamp(&gate_block(
                2,
                parent_hash,
                1_000_000 + MAX_TIMESTAMP_JUMP_SECS + 1,
                me
            ))
            .is_err());
        // Backwards: refused.
        assert!(rt
            .check_block_timestamp(&gate_block(2, parent_hash, 999_999, me))
            .is_err());
        // Missing timestamp: refused.
        assert!(rt
            .check_block_timestamp(&gate_block(2, parent_hash, 0, me))
            .is_err());
        // Unknown parent: fail-closed, never skipped.
        assert!(rt
            .check_block_timestamp(&gate_block(2, [0xEE; 32], 1_000_000, me))
            .is_err());
    }

    #[tokio::test]
    async fn p3_timestamp_gate_genesis_anchor() {
        let key = SigningKey::generate(&mut OsRng);
        let me = key.verifying_key().to_bytes();
        let validators = ValidatorSet::from_list(vec![(me, 1)]);
        let rt = ValidatorRuntime::new(key, validators, funded_state(me).await, 1);
        // Height 1 off the zero parent: any non-zero timestamp is past the
        // anchor (the forward-jump bound does not apply to genesis).
        assert!(rt
            .check_block_timestamp(&gate_block(1, [0u8; 32], 1_700_000_000, me))
            .is_ok());
        assert!(rt
            .check_block_timestamp(&gate_block(1, [0u8; 32], 0, me))
            .is_err());
    }

    /// Regression: the RPC layer and the consensus loop once had SEPARATE
    /// mempools, so a transaction submitted over RPC was never selected by the
    /// proposer (it was only ever filled from the P2P overlay) and on a
    /// single-validator node it was never included at all. A shared mempool
    /// makes a submitted transaction the same object the proposer picks up.
    #[tokio::test]
    async fn rpc_mempool_is_the_mempool_the_proposer_uses() {
        let key = SigningKey::generate(&mut OsRng);
        let me = key.verifying_key().to_bytes();
        // FULL-PQ: the sender is a Falcon-512 identity; the classical
        // `Transaction::sign` fixture is refused at admission.
        const SENDER_SEED: u8 = 0xA1;
        let state = pq_funded_state(SENDER_SEED, 10_000_000).await;
        let validators = ValidatorSet::from_list(vec![(me, 1)]);

        // This is the handle the RPC layer writes to.
        let shared = Arc::new(tokio::sync::RwLock::new(crate::mempool::Mempool::default()));
        let rt =
            ValidatorRuntime::new(key.clone(), validators, state, 1).with_mempool(shared.clone());

        let tx = pq_tx(SENDER_SEED, [1u8; 32], 10, 1_000, 0);
        let balance = rt
            .state
            .get_account(&tx.from)
            .await
            .map(|a| a.balance)
            .unwrap_or(0);

        // Submit exactly the way the RPC handler does...
        shared
            .write()
            .await
            .add_checked(tx.clone(), balance)
            .unwrap();
        assert_eq!(
            shared.read().await.len(),
            1,
            "the RPC's mempool must hold it"
        );

        // ...and the proposer must select that very same transaction.
        let selected = rt.mempool.read().await.select_bounded(100, 30_000_000);
        assert_eq!(
            selected.len(),
            1,
            "proposer must see the transaction submitted over RPC"
        );
        assert_eq!(selected[0].compute_tx_hash(), tx.compute_tx_hash());

        // And a confirmed transaction leaves both views empty.
        rt.mempool
            .write()
            .await
            .prune_confirmed(&[tx.compute_tx_hash()]);
        assert!(rt.mempool.read().await.is_empty());
        assert!(
            shared.read().await.is_empty(),
            "RPC view must not keep a confirmed tx"
        );
    }

    #[test]
    fn missing_sender_accounts_names_exactly_the_race_arrivals() {
        // Pure helper for the r0-fullness refresh: only senders the snapshot
        // missed are returned, in pool order, deterministically.
        let mut snap = std::collections::HashMap::new();
        snap.insert([1u8; 32], (0u64, 100u64));
        let pool = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        assert_eq!(
            missing_sender_accounts(&snap, &pool),
            vec![[2u8; 32], [3u8; 32]]
        );
        assert!(missing_sender_accounts(&snap, &[[1u8; 32]]).is_empty());
        assert!(missing_sender_accounts(&std::collections::HashMap::new(), &[]).is_empty());
    }

    #[tokio::test]
    async fn demanded_demand_survives_transient_revalidation_failure() {
        // Lock-hint rescue liveness: a demand must be consumed exactly once —
        // on successful serve — never on a failed re-validation. Dropping it
        // on a transient failure costs a full hint round-trip (the peer only
        // re-hints on its next nil prevote) while the round keeps timing out.
        let valkey = SigningKey::generate(&mut OsRng);
        let me = valkey.verifying_key().to_bytes();
        let peer = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        let validators = ValidatorSet::from_list(vec![(me, 1), (peer, 1)]);
        let st = Arc::new(InMemoryStateEngine::new());
        st.update_account(AccountState::new(me, 100_000_000)).await;
        let mut rt = ValidatorRuntime::new(valkey.clone(), validators, st, 1);
        while rt.hc.proposer() != Some(me) {
            rt.next_round();
        }
        let body = rt.propose(1_000).await.expect("proposer must propose");
        let h = body.compute_hash();
        // Reopen the propose gate (the fresh path self-recorded a proposal).
        rt.hc.proposal = None;
        // The peer is stuck on our body and says so with a nil prevote hint.
        rt.note_lock_hint(rt.hc.height, VoteKind::Prevote, None, Some(h));
        assert!(rt.demanded.contains(&h), "hint must record the demand");
        // Corrupt the stored copy so the serve-time re-validation fails.
        rt.blocks
            .get_mut(&h)
            .expect("body must be stored")
            .state_root = [9u8; 32];
        rt.hc.proposal = None;
        let _ = rt.propose(1_000).await;
        assert!(
            rt.demanded.contains(&h),
            "transient re-validation failure must not consume the demand"
        );
        // Repair the stored copy: the still-queued demand serves exactly once.
        let root = rt.state.get_state_root().await;
        rt.blocks
            .get_mut(&h)
            .expect("body must be stored")
            .state_root = root;
        rt.hc.proposal = None;
        let served = rt.propose(1_000).await.expect("repaired demand must serve");
        assert_eq!(
            served.compute_hash(),
            h,
            "must re-propose the demanded body verbatim"
        );
        assert!(
            rt.demanded.is_empty(),
            "successful serve consumes the demand one-shot"
        );
    }

    /// The `lock_hint` envelope is SIGNATURE-EXTERNAL (review dim 5): it
    /// rides beside the vote in `ConsensusMsg::Vote { vote, locked }` and is
    /// NOT covered by `vote_sign_bytes`, so anyone can attach any hash to
    /// anyone's nil prevote. This pins the mitigations that keep that safe:
    /// only same-height nil prevotes naming OUR OWN height-H bodies are
    /// recorded (anything else — foreign bodies, value votes, precommits,
    /// wrong heights — is dropped), the set is bounded (8) and
    /// height-scoped, and serving re-validates the body before proposing it
    /// (pinned by `demanded_demand_survives_transient_revalidation_failure`).
    /// A forged hint can therefore at most make us re-propose our own
    /// already-validated body — a wasted proposal, never a fork and never a
    /// foreign body under our slot.
    #[tokio::test]
    async fn lock_hint_envelope_is_untrusted_and_mitigated() {
        let valkey = SigningKey::generate(&mut OsRng);
        let me = valkey.verifying_key().to_bytes();
        let validators = ValidatorSet::from_list(vec![(me, 1)]);
        let mut rt = ValidatorRuntime::new(valkey.clone(), validators, funded_state(me).await, 1);
        assert!(rt.is_proposer());

        // One genuine own body at this height.
        let body = rt.propose(1_000).await.expect("sole proposer must propose");
        let ours = body.compute_hash();
        rt.hc.proposal = None;
        let h = rt.hc.height;

        // A forged hint for a FOREIGN body (never authored, never held) is
        // dropped: serving it would re-propose somebody else's block under
        // OUR slot, which every receiver rejects.
        rt.note_lock_hint(h, VoteKind::Prevote, None, Some([0xF0; 32]));
        assert!(rt.demanded.is_empty(), "foreign-body hints must be dropped");

        // A hint on a VALUE vote (not nil) is dropped: only nil prevotes
        // carry rescue requests.
        rt.note_lock_hint(h, VoteKind::Prevote, Some(ours), Some(ours));
        assert!(rt.demanded.is_empty(), "value-vote hints must be dropped");

        // A hint on a PRECOMMIT is dropped: rescue rides nil prevotes only.
        rt.note_lock_hint(h, VoteKind::Precommit, None, Some(ours));
        assert!(rt.demanded.is_empty(), "precommit hints must be dropped");

        // A hint for a WRONG height is dropped (and must not wipe this
        // height's demands — the scope reset only runs for the live height).
        rt.note_lock_hint(h, VoteKind::Prevote, None, Some(ours));
        assert!(
            rt.demanded.contains(&ours),
            "genuine hint must record the demand"
        );
        rt.note_lock_hint(h + 1, VoteKind::Prevote, None, Some(ours));
        assert!(
            rt.demanded.contains(&ours),
            "wrong-height hints must neither record nor wipe live demands"
        );
        rt.demanded.clear();

        // The genuine shape records.
        rt.note_lock_hint(h, VoteKind::Prevote, None, Some(ours));
        assert!(rt.demanded.contains(&ours));
        rt.demanded.clear();

        // The set is bounded: 9 distinct own bodies, 8 slots. Build them by
        // proposing across rounds (each propose stores its body; the
        // timestamp varies so the bodies hash distinctly).
        let mut bodies = vec![ours];
        for i in 1..9u64 {
            rt.next_round();
            rt.hc.proposal = None;
            let b = rt.propose(1_000 + i).await.expect("must keep proposing");
            bodies.push(b.compute_hash());
            rt.hc.proposal = None;
        }
        assert_eq!(bodies.len(), 9);
        for bh in &bodies {
            rt.note_lock_hint(h, VoteKind::Prevote, None, Some(*bh));
        }
        assert_eq!(
            rt.demanded.len(),
            8,
            "hint spam must not grow the demand set without bound"
        );
    }

    #[tokio::test]
    async fn r0_proposal_packs_the_full_available_mempool_deterministically() {
        // Regression for the live partial-then-retry shape (r0 52tx, r2 200tx
        // from the same pool): the proposer must pack everything available at
        // select time, and rebuilding must yield the identical set.
        //
        // NOTE on scale: sequences are 10 deep per sender; the pass budget
        // lives in mempool.rs (`select_for_block_multi`, 64 passes) — an
        // adversarial fee-hash order completes one nonce per pass per sender,
        // so only chains deeper than 64 per sender select partially. This test
        // pins the proposer-side contract.
        let valkey = SigningKey::generate(&mut OsRng);
        let me = valkey.verifying_key().to_bytes();
        let st = Arc::new(InMemoryStateEngine::new());
        st.update_account(AccountState::new(me, 100_000_000)).await;
        let validators = ValidatorSet::from_list(vec![(me, 1)]);
        let mut rt = ValidatorRuntime::new(valkey.clone(), validators, st, 1);
        assert!(rt.is_proposer());

        // 5 senders x 10 contiguous nonces = 50 executable txs.
        // FULL-PQ: implicit Falcon-512 senders (domain-separated seeds);
        // classical `Transaction::sign` fixtures are refused at admission.
        let mut senders = Vec::new();
        for i in 0..5u8 {
            let seed = 0x10 + i;
            let (from, _pk) = pq_pair(seed);
            rt.state
                .update_account(AccountState::new(from, 100_000_000))
                .await;
            senders.push(seed);
        }
        for seed in &senders {
            for i in 0..10u64 {
                rt.add_tx(pq_tx(*seed, [1u8; 32], 10, 280_000, i)).await;
            }
        }
        assert_eq!(rt.mempool.read().await.len(), 50);

        let first = rt.propose(1_000).await.expect("sole proposer must propose");
        assert_eq!(
            first.transactions.len(),
            50,
            "r0 must carry the full available mempool, not a partial prefix"
        );
        // Deterministic rebuild: the same pool yields the same ordered set.
        let second = rt.propose(1_000).await.expect("rebuild must also propose");
        let h1: Vec<[u8; 32]> = first
            .transactions
            .iter()
            .map(|t| t.compute_tx_hash())
            .collect();
        let h2: Vec<[u8; 32]> = second
            .transactions
            .iter()
            .map(|t| t.compute_tx_hash())
            .collect();
        assert_eq!(h1, h2, "packing snapshot must be deterministic");
    }

    fn signer_keys(n: usize) -> Vec<SigningKey> {
        (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect()
    }

    /// FULL-PQ fixtures (PQ excision conversion).
    ///
    /// Mirrors the rpc.rs / state_engine.rs `pq_pair` / `pq_tx` idioms:
    /// an implicit Falcon-512 envelope with the key pre-registered globally
    /// (idempotent), so there is no activation surcharge and fee / balance /
    /// nonce assertions match the old classical fixtures exactly. Classical
    /// `Transaction::sign` outputs are refused by the Pure PQ mempool, so
    /// every fixture that must be admitted uses these.
    fn pq_pair(seed: u8) -> ([u8; 32], Vec<u8>) {
        let pk = Transaction::sample_falcon512_pubkey(seed);
        let from = crate::post_quantum::derive_pq_address(
            crate::post_quantum::PqScheme::Falcon512,
            &pk,
            &crate::post_quantum::DEFAULT_SALT,
        );
        Transaction::global_implicit_registry()
            .register(
                from,
                crate::post_quantum::PqScheme::Falcon512,
                &pk,
                &crate::post_quantum::DEFAULT_SALT,
            )
            .expect("PQ test key must register");
        (from, pk)
    }

    /// FULL-PQ replacement for `Transaction::sign(sk, to, amount, gas, nonce,
    /// 1, 1)` in tests: same shape, implicit Falcon-512 envelope.
    fn pq_tx(seed: u8, to: [u8; 32], amount: u64, gas: u64, nonce: u64) -> Transaction {
        let (from, pk) = pq_pair(seed);
        let mut tx = Transaction {
            from,
            to,
            amount,
            gas_limit: gas,
            nonce,
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload: Vec::new(),
            priority_fee_per_gas: 0,
        };
        let msg = tx.signing_message();
        let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
        tx.signature = crate::sharding::PqSignatureEnvelope::new_implicit(
            crate::post_quantum::PqScheme::Falcon512,
            sig,
        )
        .encode();
        tx
    }

    /// A funded state for one PQ sender (replaces `funded_state(classical)`).
    async fn pq_funded_state(seed: u8, balance: u64) -> Arc<InMemoryStateEngine> {
        let (from, _pk) = pq_pair(seed);
        let st = Arc::new(InMemoryStateEngine::new());
        st.update_account(AccountState::new(from, balance)).await;
        st
    }

    /// Falcon vote minting (mirrors `consensus::tests::fvote`): a classical
    /// `Vote::sign` no longer verifies under FULL-PQ, so every hand-driven
    /// quorum in these tests uses this.
    fn fvote(
        sk: &SigningKey,
        fk: &FalconKeypair,
        height: Height,
        round: Round,
        kind: VoteKind,
        bh: Option<BlockHash>,
    ) -> Vote {
        Vote::sign_with_falcon(sk, fk, height, round, kind, bh)
    }

    /// FULL-PQ cluster: runtimes with persisted Falcon keys (votes only
    /// verify with a Falcon half now) over one shared validator set,
    /// assembled as `Cluster { nodes }` so `broadcast_tx` / `run_height` are
    /// reused unchanged. `falcon_base` domain-separates the per-test keys.
    fn falcon_cluster(
        val_keys: &[SigningKey],
        states: Vec<Arc<InMemoryStateEngine>>,
        falcon_base: u8,
    ) -> Cluster {
        let validators = ValidatorSet::from_list(
            val_keys
                .iter()
                .map(|k| (k.verifying_key().to_bytes(), 1))
                .collect(),
        );
        let nodes = val_keys
            .iter()
            .zip(states)
            .enumerate()
            .map(|(i, (k, st))| {
                let fk = FalconKeypair::generate_from_seed(falcon_base.wrapping_add(i as u8));
                ValidatorRuntime::new(k.clone(), validators.clone(), st, 1).with_falcon_key(fk)
            })
            .collect();
        Cluster { nodes }
    }

    /// FULL-PQ QC (mirrors `sync::tests::pq_cert_for`): Ed list for
    /// membership/power plus a Falcon µQC envelope for crypto — exactly what
    /// `QuorumCertificate::verify` requires. `parent` must be the block's
    /// `prev_hash` (chain binding). `signers` selects which keys sign (a
    /// missing signer is the offline-member shape).
    fn pq_cert_for(
        vs: &ValidatorSet,
        keys: &[SigningKey],
        fks: &[FalconKeypair],
        height: Height,
        round: Round,
        bh: BlockHash,
        parent: BlockHash,
    ) -> crate::consensus::QuorumCertificate {
        let mut set = crate::consensus::VoteSet::new();
        for (sk, fk) in keys.iter().zip(fks.iter()) {
            let v = fvote(sk, fk, height, round, VoteKind::Precommit, Some(bh));
            set.add(v, vs, height, round, VoteKind::Precommit)
                .expect("falcon vote must ingest");
        }
        set.certificate_with_parent(Some(bh), vs, Some(&parent))
            .expect("quorum must compile a Falcon µQC")
    }

    /// Falcon keypairs for `keys`, registered globally so hand-minted votes
    /// verify (mirrors `consensus::tests::vset_with_falcon`).
    fn falcon_for_keys(keys: &[SigningKey], base: u8) -> Vec<FalconKeypair> {
        keys
            .iter()
            .enumerate()
            .map(|(i, k)| {
                let fk = FalconKeypair::generate_from_seed(base.wrapping_add(i as u8));
                crate::consensus::register_validator_pq_key(
                    k.verifying_key().to_bytes(),
                    crate::post_quantum::PqScheme::Falcon512,
                    fk.public_key.clone(),
                );
                fk
            })
            .collect()
    }

    #[tokio::test]
    async fn cluster_finalizes_blocks_and_applies_state() {
        let val_keys = signer_keys(4);
        // FULL-PQ: the user is a Falcon-512 sender; the classical
        // `Transaction::sign` fixture is refused at admission.
        const USER_SEED: u8 = 0xB0;
        let (from, _pk) = pq_pair(USER_SEED);
        let to = [9u8; 32];

        // Each validator gets its OWN identical state
        let mut states = Vec::new();
        for _ in &val_keys {
            states.push(pq_funded_state(USER_SEED, 10_000_000).await);
        }
        let mut cluster = falcon_cluster(&val_keys, states, 0xF0);

        // 3 heights, one tx each. The gas limit clears the admission floor
        // (the runtime's default pool carries the operator's floor).
        for h in 0..3u64 {
            let tx = pq_tx(USER_SEED, to, 1_000, 280_000, h);
            cluster.broadcast_tx(tx).await;
            let bh = cluster.run_height(1_000 + h).await;

            // every node finalized the same block at this height
            for n in &cluster.nodes {
                assert_eq!(n.finalized.last().unwrap().1, bh);
                assert_eq!(n.finalized.last().unwrap().0, h + 1);
            }
        }

        // all nodes converged to the same state root and balances
        let roots: Vec<[u8; 32]> = {
            let mut v = Vec::new();
            for n in &cluster.nodes {
                v.push(n.state_root().await);
            }
            v
        };
        assert!(
            roots.windows(2).all(|w| w[0] == w[1]),
            "nodes diverged on state root"
        );

        for n in &cluster.nodes {
            assert_eq!(n.applied_txs, 3, "each node applied 3 txs");
            let sender = n.state.get_account(&from).await.unwrap();
            let recipient = n.state.get_account(&to).await.unwrap();
            // Each transaction moves 1_000 AND pays its declared gas limit.
            assert_eq!(sender.balance, 10_000_000 - 3_000 - 3 * 280_000);
            assert_eq!(recipient.balance, 3_000);
        }
    }

    #[tokio::test]
    async fn cluster_survives_one_byzantine_validator() {
        // 4 validators, quorum = 3. Simulate one validator going silent.
        let val_keys = signer_keys(4);
        // FULL-PQ sender + Falcon-keyed runtimes (votes and admission both
        // refuse classical fixtures now).
        const USER_SEED: u8 = 0xB1;
        let mut states = Vec::new();
        for _ in &val_keys {
            states.push(pq_funded_state(USER_SEED, 10_000_000).await);
        }
        let mut cluster = falcon_cluster(&val_keys, states, 0xE0);

        let tx = pq_tx(USER_SEED, [9u8; 32], 500, 0, 0);
        cluster.broadcast_tx(tx).await;

        // Silence the LAST validator: it never contributes prevotes/precommits.
        // We emulate this by running the round manually with only 3 voters.
        let proposer_idx = cluster.nodes.iter().position(|n| n.is_proposer()).unwrap();
        let block = cluster.nodes[proposer_idx].propose(1_000).await.unwrap();
        let bh = block.compute_hash();
        let proposer_id = cluster.nodes[proposer_idx].id;
        for (i, n) in cluster.nodes.iter_mut().enumerate() {
            if i != proposer_idx {
                let r = n.hc.round;
                n.on_proposal(proposer_id, block.clone(), r).await.unwrap();
            }
        }

        // only the first 3 (a quorum) vote
        let prevotes: Vec<Vote> = cluster
            .nodes
            .iter()
            .take(3)
            .filter_map(|n| n.make_prevote())
            .collect();
        assert_eq!(prevotes.len(), 3);
        for v in &prevotes {
            for n in cluster.nodes.iter_mut() {
                let _ = n.on_prevote(v.clone());
            }
        }
        let precommits: Vec<Vote> = cluster
            .nodes
            .iter_mut()
            .take(3)
            .filter_map(|n| n.make_precommit())
            .collect();
        assert_eq!(precommits.len(), 3);
        for v in &precommits {
            for n in cluster.nodes.iter_mut() {
                let _ = n.on_precommit(v.clone());
            }
        }
        // 3-of-4 is a quorum -> the first 3 nodes finalize despite the 4th being silent
        let mut finalized_count = 0;
        for n in cluster.nodes.iter_mut().take(3) {
            if n.try_finalize().await == Some(bh) {
                finalized_count += 1;
            }
        }
        assert_eq!(finalized_count, 3, "quorum must finalize with 1/4 offline");
    }

    #[tokio::test]
    async fn no_finality_without_quorum() {
        let val_keys = signer_keys(4);
        let user = SigningKey::generate(&mut OsRng);
        let from = user.verifying_key().to_bytes();
        let mut nodes = Vec::new();
        for k in &val_keys {
            nodes.push((k.clone(), funded_state(from).await));
        }
        let mut cluster = Cluster::new(nodes);

        let tx = Transaction::sign(&user, [9u8; 32], 1, 0, 0, 1, 1);
        cluster.broadcast_tx(tx).await;

        let proposer_idx = cluster.nodes.iter().position(|n| n.is_proposer()).unwrap();
        let block = cluster.nodes[proposer_idx].propose(1_000).await.unwrap();
        let proposer_id = cluster.nodes[proposer_idx].id;
        for (i, n) in cluster.nodes.iter_mut().enumerate() {
            if i != proposer_idx {
                let r = n.hc.round;
                n.on_proposal(proposer_id, block.clone(), r).await.unwrap();
            }
        }
        // only 2 of 4 vote -> below quorum 3
        let prevotes: Vec<Vote> = cluster
            .nodes
            .iter()
            .take(2)
            .filter_map(|n| n.make_prevote())
            .collect();
        for v in &prevotes {
            for n in cluster.nodes.iter_mut() {
                let _ = n.on_prevote(v.clone());
            }
        }
        let precommits: Vec<Vote> = cluster
            .nodes
            .iter_mut()
            .take(2)
            .filter_map(|n| n.make_precommit())
            .collect();
        for v in &precommits {
            for n in cluster.nodes.iter_mut() {
                let _ = n.on_precommit(v.clone());
            }
        }
        for n in cluster.nodes.iter_mut() {
            assert_eq!(
                n.try_finalize().await,
                None,
                "must not finalize without quorum"
            );
        }
    }

    #[tokio::test]
    async fn proposal_validation_rejects_tampering() {
        let val_keys = signer_keys(4);
        // FULL-PQ sender + Falcon-keyed runtimes.
        const USER_SEED: u8 = 0xB2;
        let mut states = Vec::new();
        for _ in &val_keys {
            states.push(pq_funded_state(USER_SEED, 10_000_000).await);
        }
        let mut cluster = falcon_cluster(&val_keys, states, 0xD0);
        // The gas limit must clear the admission floor (the runtime's default
        // pool carries the operator's floor, exactly like the node's own).
        let tx = pq_tx(USER_SEED, [9u8; 32], 100, 280_000, 0);
        cluster.broadcast_tx(tx).await;

        let proposer_idx = cluster.nodes.iter().position(|n| n.is_proposer()).unwrap();
        let block = cluster.nodes[proposer_idx].propose(1).await.unwrap();
        let receiver_idx = (proposer_idx + 1) % cluster.nodes.len();
        let receiver = &cluster.nodes[receiver_idx];

        // The expected root is the state the block builds on: ours, right now.
        // Using the block's own value here would make the check vacuous, which is
        // exactly how it went unchecked in the first place.
        let root = receiver.state.get_state_root().await;
        assert_eq!(
            block.state_root, root,
            "a genuine block from the proposer must carry the shared state root"
        );

        // genuine block passes
        assert!(receiver.validate_proposal(&block, root).is_ok());

        // wrong height
        let mut b1 = block.clone();
        b1.height = 999;
        assert!(
            receiver.validate_proposal(&b1, root).is_err(),
            "wrong height must be rejected"
        );

        // wrong proposer
        let mut b2 = block.clone();
        b2.proposer = [0xEE; 32];
        assert!(
            receiver.validate_proposal(&b2, root).is_err(),
            "wrong proposer must be rejected"
        );

        // tampered tx signature
        let mut b3 = block.clone();
        if let Some(t) = b3.transactions.first_mut() {
            t.signature[0] ^= 0xFF;
        }
        assert!(
            receiver.validate_proposal(&b3, root).is_err(),
            "bad tx signature must be rejected"
        );

        // oversized block (count check happens before signatures)
        let mut b4 = block.clone();
        b4.transactions = (0..MAX_BLOCK_TXS + 1)
            .map(|i| Transaction {
                from: [0u8; 32],
                to: [0u8; 32],
                amount: 0,
                gas_limit: 0,
                nonce: i as u64,
                source_shard: 1,
                target_shard: 1,
                signature: vec![],
                payload: vec![],
                priority_fee_per_gas: 0,
            })
            .collect();
        assert!(
            receiver.validate_proposal(&b4, root).is_err(),
            "oversized block must be rejected"
        );

        // forged proposer signature: correct proposer FIELD, but the block is
        // signed by an attacker key -> authenticity check must reject it.
        use ed25519_dalek::Signer;
        let attacker = SigningKey::generate(&mut OsRng);
        let mut b5 = block.clone();
        let h = b5.compute_hash();
        let forged_sig = attacker.sign(&h).to_vec();
        b5.validator_signatures = vec![(attacker.verifying_key().to_bytes(), forged_sig)];
        assert!(
            receiver.validate_proposal(&b5, root).is_err(),
            "forged proposer signature must be rejected"
        );
    }

    /// MEV: the transaction ORDER is a CONSENSUS commitment, not a local note.
    ///
    /// A block whose transaction order was changed AFTER it was signed must be
    /// refused by the validators: the order root inside the signed hash no
    /// longer matches the body, so the quorum's signature no longer covers
    /// what the proposer is offering.
    #[tokio::test]
    async fn tampered_transaction_order_is_rejected() {
        let val_keys = signer_keys(4);
        // FULL-PQ sender + Falcon-keyed runtimes.
        const USER_SEED: u8 = 0xB3;
        let mut states = Vec::new();
        for _ in &val_keys {
            states.push(pq_funded_state(USER_SEED, 10_000_000).await);
        }
        let mut cluster = falcon_cluster(&val_keys, states, 0xC1);
        // Two transactions from the SAME sender (consecutive nonces) so both
        // are eligible and the ORDER is observable.
        let tx1 = pq_tx(USER_SEED, [9u8; 32], 100, 280_000, 0);
        let tx2 = pq_tx(USER_SEED, [8u8; 32], 200, 280_000, 1);
        cluster.broadcast_tx(tx1).await;
        cluster.broadcast_tx(tx2).await;

        let proposer_idx = cluster.nodes.iter().position(|n| n.is_proposer()).unwrap();
        let block = cluster.nodes[proposer_idx].propose(1).await.unwrap();
        assert_eq!(
            block.transactions.len(),
            2,
            "the proposer must pack both transactions"
        );
        // The proposer committed to the order it packed, and the commitment is
        // the very value every validator re-computes.
        assert_eq!(
            block.order_merkle_root,
            crate::mev::compute_order_merkle_root(&block.transactions),
            "the proposer must set the order root over the exact list it packed"
        );

        let receiver_idx = (proposer_idx + 1) % cluster.nodes.len();
        let receiver = &cluster.nodes[receiver_idx];
        let root = receiver.state.get_state_root().await;
        assert!(
            receiver.validate_proposal(&block, root).is_ok(),
            "the genuine block must be accepted"
        );

        // TAMPER: swap the two transactions, keeping the signed order
        // commitment (and the signature) exactly as the proposer made them.
        let mut tampered = block.clone();
        tampered.transactions.swap(0, 1);
        assert_ne!(
            tampered.compute_hash(),
            block.compute_hash(),
            "the tampered body is a different block"
        );
        let err = receiver
            .validate_proposal(&tampered, root)
            .expect_err("a reordered block must be refused");
        assert!(
            err.contains("order root"),
            "the ORDER commitment must be the reason for the refusal: {err}"
        );

        // A block that claims a root which is not the root of its body is
        // refused for the same reason (a proposer cannot zero the commitment
        // out to slip a reordered body through).
        let mut zeroed = block.clone();
        zeroed.order_merkle_root = [0u8; 32];
        let err = receiver
            .validate_proposal(&zeroed, root)
            .expect_err("a block without the order commitment must be refused");
        assert!(
            err.contains("order root"),
            "a missing order commitment must be refused: {err}"
        );
    }

    /// The proposer sets the order root over the EXACT list it packed, and
    /// the validators accept that block — the commitment is satisfied by the
    /// honest path (it must not be a rule that only rejects).
    #[tokio::test]
    async fn proposer_sets_the_order_root_over_the_packed_list() {
        let val_keys = signer_keys(4);
        // FULL-PQ sender + Falcon-keyed runtimes.
        const USER_SEED: u8 = 0xB4;
        let mut states = Vec::new();
        for _ in &val_keys {
            states.push(pq_funded_state(USER_SEED, 10_000_000).await);
        }
        let mut cluster = falcon_cluster(&val_keys, states, 0xC2);
        let tx = pq_tx(USER_SEED, [9u8; 32], 100, 280_000, 0);
        cluster.broadcast_tx(tx).await;

        let proposer_idx = cluster.nodes.iter().position(|n| n.is_proposer()).unwrap();
        let block = cluster.nodes[proposer_idx].propose(1).await.unwrap();
        assert_eq!(block.transactions.len(), 1);
        assert_eq!(
            block.order_merkle_root,
            crate::mev::compute_order_merkle_root(&block.transactions)
        );
        // The root is inside the signed hash: the quorum signs the ORDER.
        let receiver_idx = (proposer_idx + 1) % cluster.nodes.len();
        let receiver = &cluster.nodes[receiver_idx];
        let root = receiver.state.get_state_root().await;
        assert!(receiver.validate_proposal(&block, root).is_ok());
        assert!(receiver.validate_proposal(&block, root).is_ok());
    }

    /// A block with NO transactions commits to no order: the root is the
    /// all-zero value, on every node, deterministically.
    #[tokio::test]
    async fn empty_block_carries_the_empty_order_root() {
        let val_keys = signer_keys(4);
        let user = SigningKey::generate(&mut OsRng);
        let from = user.verifying_key().to_bytes();
        let mut nodes = Vec::new();
        for k in &val_keys {
            nodes.push((k.clone(), funded_state(from).await));
        }
        let mut cluster = Cluster::new(nodes);

        let proposer_idx = cluster.nodes.iter().position(|n| n.is_proposer()).unwrap();
        let block = cluster.nodes[proposer_idx].propose(1).await.unwrap();
        assert!(block.transactions.is_empty());
        assert_eq!(block.order_merkle_root, [0u8; 32]);
        assert_eq!(
            block.order_merkle_root,
            crate::mev::compute_order_merkle_root(&block.transactions)
        );
    }

    #[tokio::test]
    async fn reorg_restores_state_and_applies_new_chain() {
        use crate::chain::ChainManager;
        use crate::sharding::MASTERCHAIN_SHARD;

        let user = SigningKey::generate(&mut OsRng);
        // FULL-PQ: transfers are implicit Falcon-512 transactions; the
        // block bodies are still signed classically (`mk` unchanged).
        const USER_SEED: u8 = 0xB5;
        let (from, _pk) = pq_pair(USER_SEED);
        let b_addr = [0xB0u8; 32];
        let c_addr = [0xC0u8; 32];

        let state = Arc::new(InMemoryStateEngine::new());
        state
            .update_account(AccountState::new(from, 1_000_000))
            .await;

        let mk = |height: u64, prev: [u8; 32], txs: Vec<Transaction>, sk: &SigningKey| {
            let order_merkle_root = crate::mev::compute_order_merkle_root(&txs);
            let mut blk = Block {
                shard_id: MASTERCHAIN_SHARD,
                height,
                prev_hash: prev,
                state_root: [0u8; 32],
                transactions: txs,
                cross_shard_out: vec![],
                timestamp: height,
                proposer: sk.verifying_key().to_bytes(),
                validator_signatures: vec![],
                shard_headers: vec![],
                precommit_qc: None,
                last_qc: None,
                order_merkle_root,
                epoch_key_commitment: [0u8; 32],
                mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
            };
            blk.sign_block(sk);
            blk
        };

        let genesis = mk(0, [0u8; 32], vec![], &user);
        let mut cm = ChainManager::new(genesis);
        let g = cm.best_head();

        // Checkpoint = finalized (genesis) state.
        let cs = ChainState::new(state.clone());
        let mut cs = cs;
        cs.save_checkpoint().await;

        // Canonical chain A: two transfers of 100 to B.
        let blk1 = mk(1, g, vec![pq_tx(USER_SEED, b_addr, 100, 0, 0)], &user);
        let b1 = cm.insert(blk1.clone());
        let blk2 = mk(2, b1, vec![pq_tx(USER_SEED, b_addr, 100, 0, 1)], &user);
        let b2 = cm.insert(blk2.clone());
        cm.recompute_canonical();
        assert_eq!(cm.best_head(), b2);
        cs.apply_block(&blk1).await;
        cs.apply_block(&blk2).await;
        assert_eq!(state.get_account(&from).await.unwrap().balance, 999_800);
        assert_eq!(state.get_account(&b_addr).await.unwrap().balance, 200);

        // Longer fork B: three transfers of 50 to C.
        let f1 = mk(1, g, vec![pq_tx(USER_SEED, c_addr, 50, 0, 0)], &user);
        let fb1 = cm.insert(f1.clone());
        let f2 = mk(2, fb1, vec![pq_tx(USER_SEED, c_addr, 50, 0, 1)], &user);
        let fb2 = cm.insert(f2.clone());
        let f3 = mk(3, fb2, vec![pq_tx(USER_SEED, c_addr, 50, 0, 2)], &user);
        let fb3 = cm.insert(f3.clone());

        // Plan from canonical (b2) to the longer fork head (fb3).
        let plan = cm.reorg_plan(&fb3).unwrap().unwrap();
        assert_eq!(plan.rollback.len(), 2);
        assert_eq!(plan.apply.len(), 3);

        // Apply the reorg: state must reflect the new chain, not the old one.
        cs.reorg(&cm.tree, &plan).await;
        assert_eq!(
            state.get_account(&from).await.unwrap().balance,
            999_850,
            "from: -150 only"
        );
        assert_eq!(
            state.get_account(&c_addr).await.unwrap().balance,
            150,
            "C has the new transfers"
        );
        assert!(
            state.get_account(&b_addr).await.is_none(),
            "B's rolled-back transfers must be gone"
        );
    }

    /// The state-level reorg also REPORTS what it rolled back: the signal
    /// is what the RPC layer publishes to the subscribers.
    #[tokio::test]
    async fn the_state_reorg_reports_the_rolled_back_blocks() {
        use crate::chain::ChainManager;
        use crate::sharding::MASTERCHAIN_SHARD;

        let user = SigningKey::generate(&mut OsRng);
        let state = Arc::new(InMemoryStateEngine::new());
        // The tag makes every block distinct (it lands in the state root,
        // which the block hash commits to).
        let mk = |height: u64, prev: [u8; 32], tag: u8| {
            let mut blk = Block {
                shard_id: MASTERCHAIN_SHARD,
                height,
                prev_hash: prev,
                state_root: [tag; 32],
                transactions: vec![],
                cross_shard_out: vec![],
                timestamp: height,
                proposer: user.verifying_key().to_bytes(),
                validator_signatures: vec![],
                shard_headers: vec![],
                precommit_qc: None,
                last_qc: None,
                order_merkle_root: [0u8; 32],
                epoch_key_commitment: [0u8; 32],
                mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
            };
            blk.sign_block(&user);
            blk
        };
        let genesis = mk(0, [0u8; 32], 0x00);
        let mut cm = ChainManager::new(genesis);
        let g = cm.best_head();
        let a1 = cm.insert(mk(1, g, 0xA1));
        let _a2 = cm.insert(mk(2, a1, 0xA2));
        cm.recompute_canonical();
        let b1 = cm.insert(mk(1, g, 0xB1));
        let b2 = cm.insert(mk(2, b1, 0xB2));
        let b3 = cm.insert(mk(3, b2, 0xB3));
        let plan = cm.reorg_plan(&b3).unwrap().unwrap();
        assert_eq!(plan.rollback.len(), 2, "A2 and A1 are rolled back");

        let mut cs = ChainState::new(state);
        let signal = cs.reorg_with_signal(&cm.tree, &plan).await;
        assert_eq!(
            signal.orphaned_blocks, plan.rollback,
            "the rolled-back blocks"
        );
        assert_eq!(signal.height, 1, "the first invalidated height");
        assert!(signal.reason.contains("reorg"));
    }

    // ------------------------------------------------------------------
    // Fork-choice: candidates, reorg and invalidation signals
    // ------------------------------------------------------------------

    /// A signed block for the fork-choice tests. `tag` makes every block
    /// distinct (it lands in the state root and in the transaction).
    fn fork_block(height: u64, prev: [u8; 32], tag: u8, sk: &SigningKey) -> Block {
        use crate::sharding::MASTERCHAIN_SHARD;
        let tx = Transaction {
            from: [tag; 32],
            to: [0u8; 32],
            amount: tag as u64,
            gas_limit: 0,
            nonce: 0,
            source_shard: 1,
            target_shard: 1,
            signature: vec![],
            payload: vec![],
            priority_fee_per_gas: 0,
        };
        let transactions = vec![tx];
        let order_merkle_root = crate::mev::compute_order_merkle_root(&transactions);
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
            height,
            prev_hash: prev,
            state_root: [tag; 32],
            transactions,
            cross_shard_out: vec![],
            timestamp: height,
            proposer: sk.verifying_key().to_bytes(),
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            order_merkle_root,
            epoch_key_commitment: [0u8; 32],
            mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
        };
        b.sign_block(sk);
        b
    }

    /// A runtime with an invalidation sink that collects what is published.
    fn runtime_with_sink(
        key: SigningKey,
        state: Arc<InMemoryStateEngine>,
    ) -> (
        ValidatorRuntime,
        Arc<std::sync::Mutex<Vec<crate::chain::InvalidationSignal>>>,
    ) {
        let me = key.verifying_key().to_bytes();
        let validators = ValidatorSet::from_list(vec![(me, 1)]);
        let rt = ValidatorRuntime::new(key, validators, state, 1);
        let seen: Arc<std::sync::Mutex<Vec<crate::chain::InvalidationSignal>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = seen.clone();
        (
            rt.with_invalidation_sink(Arc::new(move |sig: crate::chain::InvalidationSignal| {
                sink.lock().unwrap().push(sig);
            })),
            seen,
        )
    }

    /// The live-node contract: a competing candidate is recorded BEFORE
    /// finality, and when another block is finalized at that height the
    /// candidate is invalidated and the signal is published.
    #[tokio::test]
    async fn a_competing_candidate_is_invalidated_when_another_block_is_finalized() {
        let key = SigningKey::generate(&mut OsRng);
        let state = Arc::new(InMemoryStateEngine::new());
        let (mut rt, seen) = runtime_with_sink(key.clone(), state);

        // A finalized block anchors the fork-choice tree.
        let f1 = fork_block(1, [0u8; 32], 0xF1, &key);
        let f1h = f1.compute_hash();
        rt.note_finalized_block(&f1);
        assert_eq!(rt.chain.finalized_height, 1);

        // Two competing candidates at height 2, both extending the
        // finalized head.
        let c1 = fork_block(2, f1h, 0xC1, &key);
        let c2 = fork_block(2, f1h, 0xC2, &key);
        assert!(
            rt.record_candidate_block(&c1),
            "a valid candidate must be recorded"
        );
        assert!(rt.record_candidate_block(&c2));
        assert_eq!(rt.chain.candidates_at(2).len(), 2);

        // A third block at height 2 is finalized: the candidates lost.
        let w = fork_block(2, f1h, 0xA7, &key);
        rt.note_finalized_block(&w);

        let published = seen.lock().unwrap().clone();
        assert_eq!(published.len(), 2, "one signal per lost branch");
        let mut orphaned: Vec<[u8; 32]> = published
            .iter()
            .flat_map(|s| s.orphaned_blocks.clone())
            .collect();
        orphaned.sort();
        let mut expected = vec![c1.compute_hash(), c2.compute_hash()];
        expected.sort();
        assert_eq!(orphaned, expected, "both candidates are invalidated");
        assert!(published.iter().all(|s| s.height == 2));
        assert!(
            !orphaned.contains(&w.compute_hash()),
            "the finalized block was applied, it is not orphaned"
        );
        assert!(
            rt.chain.candidates.is_empty(),
            "the lost branches are pruned"
        );
    }

    /// A LONGER candidate branch wins the fork-choice: the reorg plan is
    /// executed (the head moves, the losing branch is invalidated) and the
    /// state is untouched -- the candidates were never applied.
    #[tokio::test]
    async fn a_longer_candidate_branch_executes_the_reorg_plan() {
        let key = SigningKey::generate(&mut OsRng);
        let state = Arc::new(InMemoryStateEngine::new());
        let (mut rt, seen) = runtime_with_sink(key.clone(), state.clone());

        let f1 = fork_block(1, [0u8; 32], 0xF1, &key);
        let f1h = f1.compute_hash();
        rt.note_finalized_block(&f1);

        // Branch A: one block at height 2.
        let a1 = fork_block(2, f1h, 0xA1, &key);
        let a1h = a1.compute_hash();
        assert!(rt.record_candidate_block(&a1));
        // The fork-choice adopts the first candidate (nothing to roll back).
        let first = rt
            .run_fork_choice()
            .expect("the first candidate is adopted");
        assert!(first.plan.rollback.is_empty());
        assert!(first.invalidations.is_empty(), "nothing was orphaned yet");

        // Branch B: two blocks -> LONGER.
        let b1 = fork_block(2, f1h, 0xB1, &key);
        let b1h = b1.compute_hash();
        let b2 = fork_block(3, b1h, 0xB2, &key);
        let b2h = b2.compute_hash();
        assert!(rt.record_candidate_block(&b1));
        assert!(rt.record_candidate_block(&b2));

        let root_before = state.get_state_root().await;
        let outcome = rt.run_fork_choice().expect("a longer branch must reorg");
        assert_eq!(outcome.plan.rollback, vec![a1h], "branch A is rolled back");
        assert_eq!(outcome.plan.apply, vec![b1h, b2h], "branch B is applied");
        assert_eq!(outcome.invalidations.len(), 1);
        assert_eq!(outcome.invalidations[0].orphaned_blocks, vec![a1h]);
        assert_eq!(
            outcome.invalidations[0].height, 2,
            "the first invalidated height"
        );
        // The signal reached the transport.
        assert_eq!(seen.lock().unwrap().len(), 1);
        // The state is untouched: a candidate was never applied.
        assert_eq!(state.get_state_root().await, root_before);
    }

    /// A competitor at the SAME height does NOT invalidate anything: the
    /// finalization (the quorum) decides which one is on the chain, so both
    /// stay live candidates until it does. Announcing the loser early
    /// would be a lie — it may still be the block the chain finalizes.
    #[tokio::test]
    async fn a_same_height_competitor_does_not_invalidate_the_first_candidate() {
        let key = SigningKey::generate(&mut OsRng);
        let state = Arc::new(InMemoryStateEngine::new());
        let (mut rt, seen) = runtime_with_sink(key.clone(), state);

        let f1 = fork_block(1, [0u8; 32], 0xF1, &key);
        let f1h = f1.compute_hash();
        rt.note_finalized_block(&f1);

        let c1 = fork_block(2, f1h, 0xC1, &key);
        let c2 = fork_block(2, f1h, 0xC2, &key);
        assert!(rt.record_candidate_block(&c1));
        rt.run_fork_choice();
        assert!(rt.record_candidate_block(&c2));
        assert!(
            rt.run_fork_choice().is_none(),
            "a same-height competitor is not a reorg"
        );
        assert!(
            seen.lock().unwrap().is_empty(),
            "nothing is invalidated before the finalization decides"
        );
        assert_eq!(rt.chain.candidates_at(2).len(), 2, "both stay live");

        // The chain finalizes a third block at that height: now both lost.
        let w = fork_block(2, f1h, 0xA7, &key);
        rt.note_finalized_block(&w);
        let published = seen.lock().unwrap().clone();
        assert_eq!(published.len(), 2, "both candidates lost the fork-choice");
    }

    /// A candidate that arrives for an ALREADY finalized height can never
    /// be applied: it is invalidated on the spot, not silently dropped.
    #[tokio::test]
    async fn a_candidate_below_the_finalized_height_is_invalidated_on_the_spot() {
        let key = SigningKey::generate(&mut OsRng);
        let state = Arc::new(InMemoryStateEngine::new());
        let (mut rt, seen) = runtime_with_sink(key.clone(), state);

        let f1 = fork_block(1, [0u8; 32], 0xF1, &key);
        let f1h = f1.compute_hash();
        rt.note_finalized_block(&f1);

        // A block at the finalized height (it lost the fork-choice).
        let late = fork_block(1, [0u8; 32], 0xA1, &key);
        assert!(
            !rt.record_candidate_block(&late),
            "it must not become a candidate"
        );
        let published = seen.lock().unwrap().clone();
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].orphaned_blocks, vec![late.compute_hash()]);
        assert_eq!(published[0].height, 1);
        let _ = f1h;
    }

    /// The block that WAS finalized is never announced as invalidated: it
    /// was applied, and a retraction would be a lie to every client that
    /// follows this chain.
    #[tokio::test]
    async fn the_finalized_block_is_not_announced_as_invalidated() {
        let key = SigningKey::generate(&mut OsRng);
        let state = Arc::new(InMemoryStateEngine::new());
        let (mut rt, seen) = runtime_with_sink(key.clone(), state);

        let f1 = fork_block(1, [0u8; 32], 0xF1, &key);
        rt.note_finalized_block(&f1);
        // The same block comes back (gossip replay): it is the finalized one,
        // so it must not be announced as invalidated.
        assert!(!rt.record_candidate_block(&f1));
        assert!(
            seen.lock().unwrap().is_empty(),
            "an applied block is never announced as invalidated"
        );
    }

    /// Audit F5: `replay_historical_block` must verify a historical precommit QC
    /// against the validator set in force AT THAT HEIGHT, not the node's current
    /// (post-rotation / config) set. During replay the engine is already at the
    /// block's committed pre-state, so the staking ledger there IS the height's
    /// set -- this test proves replay consults it by making the two sets disjoint.
    #[tokio::test]
    async fn replay_verifies_qc_against_the_height_set_not_the_current_set() {
        use crate::staking::{MIN_VALIDATOR_BOND, STELL_MIN_BOND_BUFFER};

        // The set in force at the replayed height: bonded in the engine ledger.
        let historical = signer_keys(3);
        let engine = Arc::new(InMemoryStateEngine::new());
        {
            let mut ledger = engine.staking_write().await;
            for k in &historical {
                ledger
                    .bond(
                        k.verifying_key().to_bytes(),
                        MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER,
                        0,
                    )
                    .unwrap();
            }
        }
        let historical_vs = engine.staking_read().await.to_validator_set();
        assert_eq!(
            historical_vs.len(),
            3,
            "precondition: ledger holds the height's set"
        );

        // The runtime's current set is DIFFERENT. If replay verified against this
        // one it would reject a genuine historical certificate.
        let decoy = signer_keys(3);
        let decoy_vs = ValidatorSet::from_list(
            decoy
                .iter()
                .map(|k| (k.verifying_key().to_bytes(), 1))
                .collect(),
        );
        let mut rt = ValidatorRuntime::new(historical[0].clone(), decoy_vs, engine.clone(), 1);

        let root = engine.get_state_root().await;
        let mut block = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: 1,
            prev_hash: [0u8; 32],
            state_root: root,
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 1,
            proposer: historical[0].verifying_key().to_bytes(),
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
            mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
        };
        block.sign_block(&historical[0]);
        let bh = block.compute_hash();
        // FULL-PQ: the historical certificate is a Falcon µQC compiled from
        // genuine Falcon votes (mirrors `sync::tests::pq_cert_for`); a
        // classical `Vote::sign` QC no longer verifies. The parent is the
        // block's `prev_hash` (chain binding).
        let fks = falcon_for_keys(&historical, 0xA0);
        block.precommit_qc = Some(pq_cert_for(
            &historical_vs,
            &historical,
            &fks,
            1,
            0,
            bh,
            [0u8; 32],
        ));

        rt.replay_historical_block(&block)
            .await
            .expect("replay must verify the QC against the height's ledger-derived set");
        // And the rotation afterwards installs that same set.
        assert_eq!(rt.validators.len(), 3);
    }

    /// Audit F10: a prevote quorum from an OLDER round must not be turned into a
    /// precommit at the current round. `try_prevote_quorum` still inspects the
    /// lookback window (so a late quorum can decide), but `make_precommit` must
    /// only act on a QC formed in the round we are actually in.
    #[tokio::test]
    async fn make_precommit_stamps_the_polka_round_not_the_local_round() {
        let ks = signer_keys(2);
        let vs = ValidatorSet::from_list(
            ks.iter()
                .map(|k| (k.verifying_key().to_bytes(), 1))
                .collect(),
        );
        let me = ks[0].verifying_key().to_bytes();
        let state = funded_state(me).await;
        let mut rt = ValidatorRuntime::new(ks[0].clone(), vs, state, 1);
        let h = rt.hc.height;
        let target = [0x42u8; 32];

        // A full prevote quorum for `target` at round 0.
        // FULL-PQ: Falcon votes (classical `Vote::sign` is rejected).
        let fks = falcon_for_keys(&ks, 0xA0);
        for (k, fk) in ks.iter().zip(fks.iter()) {
            rt.on_prevote(fvote(k, fk, h, 0, VoteKind::Prevote, Some(target)))
                .unwrap();
        }
        // Move on to round 1 BEFORE precommitting: the round-0 QC is now
        // BEHIND us. We still precommit -- but stamped with round 0, the round
        // the polka formed in (Tendermint). Casting at our own round 1 would
        // file the vote into a different bucket than the peer's, and with the
        // two nodes routinely one round apart neither side's precommit ever
        // matched (31 of 180 wasted rounds on the live stand: a full prevote
        // QC whose precommit leg never landed).
        rt.next_round();
        assert_eq!(rt.hc.round, 1);
        let pc_old = rt
            .make_precommit()
            .expect("a polka behind us must still be precommitted");
        assert_eq!(
            pc_old.round, 0,
            "precommit is stamped with the POLKA's round"
        );
        assert_eq!(pc_old.block_hash, Some(target));
        assert_eq!(
            rt.hc.locked,
            Some((target, 0)),
            "the lock records the polka round, not the local round"
        );
        // Recasting for the same polka round is a duplicate, not a new vote:
        // main.rs dedups on (height, vote.round), and here we simply observe
        // that the same bytes come back (idempotent for the receiver).
        let again = rt.make_precommit().expect("idempotent re-cast");
        assert_eq!(again.round, 0);
        assert_eq!(again.block_hash, Some(target));

        // A polka in a NEWER round supersedes: we now precommit at round 1.
        for (k, fk) in ks.iter().zip(fks.iter()) {
            rt.on_prevote(fvote(k, fk, h, 1, VoteKind::Prevote, Some(target)))
                .unwrap();
        }
        let pc = rt
            .make_precommit()
            .expect("current-round QC must precommit");
        assert_eq!(pc.round, 1);
        assert_eq!(pc.block_hash, Some(target));
    }

    #[tokio::test]
    async fn parallel_exec_configuration_and_preservation() {
        let ks = signer_keys(1);
        let me = ks[0].verifying_key().to_bytes();
        let vs = ValidatorSet::from_list(vec![(me, 1)]);
        let state = funded_state(me).await;

        let mut rt = ValidatorRuntime::new(ks[0].clone(), vs, state.clone(), 1);
        assert!(!rt.parallel_exec, "default parallel_exec is false");
        assert!(!rt.is_parallel_exec_enabled(), "default is disabled");
        assert!(
            !rt.state.is_parallel_exec_enabled(),
            "state default is disabled"
        );

        // Enable parallel execution
        rt = rt.with_parallel_exec(true);
        assert!(rt.parallel_exec);
        assert!(rt.is_parallel_exec_enabled());
        assert!(rt.state.is_parallel_exec_enabled());

        // Temporarily clear on state directly; runtime preserves / restores it on propose
        rt.state.set_parallel_exec(false);
        assert!(!rt
            .state
            .parallel_exec
            .load(std::sync::atomic::Ordering::Acquire));
        let _ = rt.propose(1_000_000).await;
        assert!(
            rt.state.is_parallel_exec_enabled(),
            "propose preserves parallel exec on state"
        );

        // Set to false via runtime
        rt.set_parallel_exec(false);
        assert!(!rt.parallel_exec);
        assert!(!rt.is_parallel_exec_enabled());
        assert!(!rt.state.is_parallel_exec_enabled());

        // Re-enable and verify apply_and_advance preserves it
        rt = rt.with_parallel_exec(true);
        rt.state.set_parallel_exec(false);
        let blk = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: 1,
            prev_hash: [0u8; 32],
            state_root: rt.state.get_state_root().await,
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 1_000_000,
            proposer: me,
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
            mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
        };
        rt.apply_and_advance(blk.compute_hash(), &blk).await;
        assert!(
            rt.state.is_parallel_exec_enabled(),
            "apply_and_advance preserves parallel exec on state"
        );
    }

    #[tokio::test]
    async fn validator_runtime_with_falcon_key_produces_falcon_votes_and_proposals() {
        let key = SigningKey::generate(&mut OsRng);
        let me = key.verifying_key().to_bytes();
        let vs = ValidatorSet::from_list(vec![(me, 1)]);
        let state = funded_state(me).await;

        let fk = FalconKeypair::generate_from_seed(0x42);
        let mut rt = ValidatorRuntime::new(key.clone(), vs.clone(), state.clone(), 1)
            .with_falcon_key(fk.clone());

        assert!(rt.falcon_key.is_some());
        assert_eq!(rt.falcon_key.as_ref().unwrap().public_key, fk.public_key);

        // 1. propose FIRST, then prevote the proposal.
        //
        // A prevote cast BEFORE the proposal exists is a NIL prevote, and a
        // nil quorum is not a polka: the precommit follows a quorum of
        // prevotes FOR A BLOCK (a nil quorum is a timeout, and precommitting
        // it used to shadow the real polka). So the precommit leg of this
        // test needs a real target, and the test's subject — the Falcon half
        // of the vote — rides on the prevote of the proposal.
        let block = rt.propose(1_000_000).await.expect("propose must succeed");

        // 2. make_prevote produces vote with Falcon signature
        let prevote = rt.make_prevote().expect("prevote must be produced");
        assert_eq!(
            prevote.block_hash,
            Some(block.compute_hash()),
            "the prevote must be for the proposal we just made"
        );
        let falcon_sig = prevote
            .falcon_signature()
            .expect("vote must carry Falcon signature");
        assert_eq!(falcon_sig.len(), crate::post_quantum::FALCON512_SIG_LEN);

        let msg = crate::consensus::vote_sign_bytes(1, 0, VoteKind::Prevote, &prevote.block_hash);
        assert!(crate::post_quantum::verify_pq_signature(
            crate::post_quantum::PqScheme::Falcon512,
            &fk.public_key,
            &msg,
            falcon_sig,
        ));
        assert!(prevote.verify(), "vote with Falcon signature must verify");

        // 3. the proposal is signed with the Falcon key too
        let falcon_id = fk.validator_id();
        let proposal_msg = block.compute_hash();

        let falcon_prop_sig = block
            .validator_signatures
            .iter()
            .find(|(id, _)| *id == falcon_id)
            .map(|(_, sig)| sig)
            .expect("block validator signatures must contain Falcon signature");

        assert!(crate::post_quantum::verify_pq_signature(
            crate::post_quantum::PqScheme::Falcon512,
            &fk.public_key,
            &proposal_msg,
            falcon_prop_sig,
        ));

        // 4. make_precommit with polka produces precommit with Falcon signature
        assert!(rt.on_prevote(prevote).is_ok());
        let precommit = rt.make_precommit().expect("precommit must be produced");
        let pc_falcon_sig = precommit
            .falcon_signature()
            .expect("precommit must carry Falcon signature");
        let pc_msg =
            crate::consensus::vote_sign_bytes(1, 0, VoteKind::Precommit, &precommit.block_hash);
        assert!(crate::post_quantum::verify_pq_signature(
            crate::post_quantum::PqScheme::Falcon512,
            &fk.public_key,
            &pc_msg,
            pc_falcon_sig,
        ));
        assert!(precommit.verify());
    }

    #[tokio::test]
    async fn validator_runtime_falcon_votes_form_uqc_and_verify_unified() {
        let val_keys = signer_keys(4);
        // FULL-PQ sender (the known Pure-PQ-unwrap site: a classical
        // `Transaction::sign` fixture is refused at `add_checked`).
        const USER_SEED: u8 = 0xB6;
        let to = [9u8; 32];

        let mut nodes = Vec::new();
        for k in &val_keys {
            nodes.push((k.clone(), pq_funded_state(USER_SEED, 10_000_000).await));
        }

        let validators = ValidatorSet::from_list(
            nodes
                .iter()
                .map(|(k, _)| (k.verifying_key().to_bytes(), 1))
                .collect(),
        );

        let mut runtimes: Vec<ValidatorRuntime> = nodes
            .into_iter()
            .enumerate()
            .map(|(i, (k, st))| {
                let fk = FalconKeypair::generate_from_seed((i + 1) as u8);
                ValidatorRuntime::new(k, validators.clone(), st, 1).with_falcon_key(fk)
            })
            .collect();

        let tx = pq_tx(USER_SEED, to, 1_000, 280_000, 0);
        for rt in &runtimes {
            rt.mempool
                .write()
                .await
                .add_checked(tx.clone(), 10_000_000)
                .unwrap();
        }

        // 1. Propose from designated proposer
        let proposer_idx = runtimes
            .iter()
            .position(|rt| rt.is_proposer())
            .expect("must have proposer");
        let block = runtimes[proposer_idx]
            .propose(1_000)
            .await
            .expect("propose must succeed");
        let bh = block.compute_hash();

        // Ingest proposal on all nodes
        let proposer_id = runtimes[proposer_idx].id;
        for rt in &mut runtimes {
            assert!(rt.on_proposal(proposer_id, block.clone(), 0).await.is_ok());
        }

        // 2. Prevote
        let mut prevotes = Vec::new();
        for rt in &runtimes {
            let v = rt.make_prevote().expect("make_prevote");
            assert!(v.falcon_signature().is_some());
            prevotes.push(v);
        }

        for rt in &mut runtimes {
            for v in &prevotes {
                assert!(rt.on_prevote(v.clone()).is_ok());
            }
            let (polka_round, target) = rt.hc.try_prevote_quorum_at().expect("polka must form");
            assert_eq!(target, Some(bh));
            let prevote_qc = rt
                .hc
                .prevote_qc
                .get(&polka_round)
                .expect("prevote QC must exist");
            assert!(
                prevote_qc
                    .signatures
                    .iter()
                    .any(|(voter, _)| *voter == crate::consensus::PQ_UQC_MARKER_ID),
                "prevote QC must contain PQ_UQC_MARKER_ID"
            );
            assert!(prevote_qc.verify_unified(&validators));
        }

        // 3. Precommit
        let mut precommits = Vec::new();
        for rt in &mut runtimes {
            let v = rt.make_precommit().expect("make_precommit");
            assert!(v.falcon_signature().is_some());
            precommits.push(v);
        }

        for rt in &mut runtimes {
            for v in &precommits {
                assert!(rt.on_precommit(v.clone()).is_ok());
            }
            let decided = rt
                .hc
                .try_precommit_quorum()
                .expect("precommit quorum must decide");
            assert_eq!(decided, bh);
            let precommit_qc = rt
                .hc
                .precommit_qc
                .as_ref()
                .expect("precommit QC must exist");
            assert!(
                precommit_qc
                    .signatures
                    .iter()
                    .any(|(voter, _)| *voter == crate::consensus::PQ_UQC_MARKER_ID),
                "precommit QC must contain PQ_UQC_MARKER_ID"
            );
            assert!(precommit_qc.verify_unified(&validators));
            assert!(precommit_qc.verify(&validators));
        }

        // 4. Finalize the block across all nodes
        for rt in &mut runtimes {
            let finalized = rt.try_finalize().await.expect("finalization must succeed");
            assert_eq!(finalized, bh);
            assert!(rt.finalized.contains(&(1, bh)));
        }
    }

    #[tokio::test]
    async fn test_sec01_adopt_lock_superseded_by_equal_or_higher_round_qc() {
        let ks = signer_keys(4);
        let me = ks[0].verifying_key().to_bytes();
        let vs = ValidatorSet::from_list(
            ks.iter()
                .map(|k| (k.verifying_key().to_bytes(), 1))
                .collect(),
        );
        let st = funded_state(me).await;
        let mut rt = ValidatorRuntime::new(ks[0].clone(), vs.clone(), st, 1);

        let make_block = |round: Round, root: [u8; 32]| -> Block {
            let proposer = vs.proposer_for(1, round).unwrap();
            let pk = ks
                .iter()
                .find(|k| k.verifying_key().to_bytes() == proposer)
                .unwrap();
            let mut b = Block {
                shard_id: MASTERCHAIN_SHARD,
                height: 1,
                prev_hash: [0u8; 32],
                state_root: root,
                transactions: vec![],
                cross_shard_out: vec![],
                timestamp: 1_000_000,
                proposer,
                validator_signatures: vec![],
                shard_headers: vec![],
                precommit_qc: None,
                last_qc: None,
                order_merkle_root: [0u8; 32],
                epoch_key_commitment: [0u8; 32],
                mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
            };
            b.sign_block(pk);
            b
        };

        let fks = falcon_for_keys(&ks, 0xA0);
        let make_qc = |round: Round, bh: BlockHash| -> crate::consensus::QuorumCertificate {
            // FULL-PQ: the certificate is a Falcon µQC compiled from genuine
            // votes (a classical `Vote::sign` QC fails `verify` before the
            // lock check is ever reached). The parent is the block's
            // `prev_hash` (chain binding); all fixture blocks extend [0; 32].
            pq_cert_for(&vs, &ks, &fks, 1, round, bh, [0u8; 32])
        };

        let root = rt.state.get_state_root().await;
        rt.hc.round = 1;
        let blk0 = make_block(0, root);
        let bh0 = blk0.compute_hash();

        // 1. Lock taken at round 1 prevents adopting an older round 0 block contradicting the lock
        let locked_block = [0xAAu8; 32];
        assert_ne!(locked_block, bh0);
        rt.hc.locked = Some((locked_block, 1));
        let cert0 = make_qc(0, bh0);
        let res = rt.adopt_committed(1, blk0.clone(), cert0).await;
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("lock"));

        // 2. A certificate at the SAME round as the lock but for a DIFFERENT
        //    block is a genuine safety conflict (two conflicting polkas in one
        //    round need >1/3 Byzantine power) and must be refused.
        rt.hc.locked = Some((locked_block, 1));
        let cert_same = make_qc(1, bh0);
        let res = rt.adopt_committed(1, blk0.clone(), cert_same).await;
        assert!(
            res.is_err(),
            "same-round conflicting certificate must be refused"
        );
        assert!(res.unwrap_err().contains("lock"));

        // 3. A certificate from a STRICTLY LATER round proves the network moved
        //    on without us, so the lock is superseded and the canonical commit
        //    must be adopted (the pre-SEC-01 test refused it and partitioned
        //    the node from the chain). The block is the ROUND-2 proposer's:
        //    the adopt path checks the proposer against the certificate's
        //    round, so the block and the certificate must agree on it.
        let blk2 = make_block(2, root);
        let bh2 = blk2.compute_hash();
        assert_ne!(locked_block, bh2);
        rt.hc.locked = Some((locked_block, 1));
        let cert2 = make_qc(2, bh2);
        let res = rt.adopt_committed(1, blk2, cert2).await;
        assert_eq!(res, Ok(bh2));
    }

    // ---------------------------------------------------------------------
    // Validator-set synchronization between the masterchain and its
    // workchains (the audit's "validator set gap").
    //
    // The masterchain owns the staking registry; a workchain has none of its
    // own. The two share the master's ledger through
    // `ValidatorRuntime::master_staking`, so a rotation on the masterchain
    // (bond / unbond / slash) is adopted by the workchain's consensus at the
    // next height boundary — no node restart, no second registry.
    // ---------------------------------------------------------------------

    /// A masterchain + workchain pair in one process, sharing the master's
    /// staking registry. The workchain's own ledger stays EMPTY (there is no
    /// staking registry on a workchain) and it starts on the config-defined
    /// set, exactly like a real workchain.
    async fn masterchain_and_workchain(
        me: ValidatorId,
        newcomer: ValidatorId,
    ) -> (
        Arc<InMemoryStateEngine>,
        MasterStakingLedger,
        ValidatorRuntime,
        ValidatorRuntime,
    ) {
        let master_engine = Arc::new(InMemoryStateEngine::new());
        let master_handle = master_engine.staking_handle();
        let workchain_engine = Arc::new(InMemoryStateEngine::new());
        let registry = ShardRegistry::from_ids([MASTERCHAIN_SHARD, 1]);
        let config_set = ValidatorSet::from_list(vec![(me, 1)]);
        let key = SigningKey::generate(&mut OsRng);

        let master =
            ValidatorRuntime::new(key.clone(), config_set.clone(), master_engine.clone(), 1)
                .with_shard(MASTERCHAIN_SHARD, registry.clone())
                .with_master_staking(master_handle.clone());
        let workchain = ValidatorRuntime::new(key, config_set, workchain_engine.clone(), 1)
            .with_shard(1, registry)
            .with_master_staking(master_handle.clone());

        // The workchain's own registry is empty BY DESIGN — the masterchain
        // owns the staking registry. This is the state the audit found.
        assert!(
            workchain_engine
                .staking_read()
                .await
                .to_validator_set()
                .is_empty(),
            "a workchain must not seed a staking ledger of its own"
        );
        let _ = newcomer;
        (master_engine, master_handle, master, workchain)
    }

    /// Advance the test runtime across the height boundary, exactly like the
    /// live finalize/adopt paths do: the staged validator-set change becomes
    /// in-force at the new height (W10.5 activation boundary).
    fn advance_test_height(rt: &mut ValidatorRuntime) {
        rt.hc.height += 1;
        rt.install_due_validator_set();
        rt.hc.validators = rt.validators.clone();
    }

    /// A bond on the masterchain and an unbond are both adopted by the
    /// workchain's consensus set, live, with no node restart — at the NEXT
    /// height boundary (W10.5: staged at ledger-height L, in force from L+1;
    /// never mid-flight).
    #[tokio::test]
    async fn workchain_adopts_the_masterchain_bond_and_unbond_rotation() {
        let me = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        let newcomer = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        let bond = crate::staking::required_bond_floor_nano();
        let (master_engine, _handle, mut master, mut workchain) =
            masterchain_and_workchain(me, newcomer).await;

        // The masterchain's registry: one bonded validator.
        master_engine
            .staking_write()
            .await
            .bond(me, bond, 0)
            .expect("the masterchain bond must be accepted");

        // 1. The workchain STAGES the masterchain's set (its config-defined
        //    set stays in force for the height in progress).
        let h = workchain.hc.height;
        assert!(
            workchain.refresh_validator_set_from_staking().await,
            "the workchain must stage the masterchain's validator set"
        );
        assert_eq!(
            workchain.validators.validators.get(&me),
            Some(&1),
            "the in-force set must not jump mid-flight"
        );
        assert_eq!(
            workchain.pending_validators.as_ref().map(|(a, _)| *a),
            Some(h + 1),
            "the change activates at the next height boundary"
        );
        // ... and the set in force is height-pinned: H still votes the old
        // set, H+1 the new one.
        assert_eq!(
            workchain.validator_set_for_height(h).validators.get(&me),
            Some(&1)
        );
        assert_eq!(
            workchain
                .validator_set_for_height(h + 1)
                .validators
                .get(&me),
            Some(&bond)
        );
        // Across the boundary the staged set becomes in-force — consensus
        // view and bookkeeping copy together.
        advance_test_height(&mut workchain);
        assert_eq!(workchain.validators.validators.get(&me), Some(&bond));
        assert_eq!(workchain.hc.validators.validators.get(&me), Some(&bond));
        // The masterchain itself derives exactly the same set.
        assert!(master.refresh_validator_set_from_staking().await);
        advance_test_height(&mut master);
        assert_eq!(
            master.validators.validators,
            workchain.validators.validators
        );

        // 2. A NEW validator bonds on the masterchain: the workchain stages
        //    it, with the bonded stake as its voting power, in force next.
        master_engine
            .staking_write()
            .await
            .bond(newcomer, bond, 0)
            .expect("the newcomer bond must be accepted");
        let h = workchain.hc.height;
        assert!(
            workchain.refresh_validator_set_from_staking().await,
            "a masterchain bond must rotate the workchain's set"
        );
        assert!(
            !workchain.validators.validators.contains_key(&newcomer),
            "the newcomer must not join mid-flight"
        );
        assert_eq!(
            workchain
                .validator_set_for_height(h + 1)
                .validators
                .get(&newcomer),
            Some(&bond)
        );
        advance_test_height(&mut workchain);
        assert_eq!(workchain.validators.validators.get(&newcomer), Some(&bond));
        assert_eq!(
            workchain.hc.validators.validators.get(&newcomer),
            Some(&bond)
        );
        assert_eq!(workchain.validators.total_power(), 2 * bond);
        assert!(master.refresh_validator_set_from_staking().await);
        advance_test_height(&mut master);
        assert_eq!(
            master.validators.validators,
            workchain.validators.validators
        );

        // 3. The newcomer unbonds on the masterchain: the workchain drops it
        //    from its set (and from the consensus view) at the next boundary.
        master_engine
            .staking_write()
            .await
            .unbond(newcomer, bond, 0)
            .expect("the unbond must be accepted");
        assert!(
            workchain.refresh_validator_set_from_staking().await,
            "a masterchain unbond must rotate the workchain's set"
        );
        assert!(
            workchain.validators.validators.contains_key(&newcomer),
            "the unbonded validator stays in force until the boundary"
        );
        advance_test_height(&mut workchain);
        assert!(
            !workchain.validators.validators.contains_key(&newcomer),
            "the unbonded validator must leave the workchain's set"
        );
        assert!(
            !workchain.hc.validators.validators.contains_key(&newcomer),
            "the unbonded validator must leave the workchain's consensus view"
        );

        // 4. The rotated set is in force from the NEXT height — the boundary
        //    the apply path installs it at, with no restart in between.
        assert_eq!(
            crate::sharding::validator_set_adoption_height(workchain.hc.height),
            workchain.hc.height + 1
        );
        assert!(!workchain.is_validator_set_stale());
    }

    /// A slash on the masterchain is transmitted to the workchain as well:
    /// the slashed validator's voting power in the workchain's set is the
    /// post-slash stake, not the pre-slash one — from the NEXT height
    /// boundary (W10.5: staged, never mid-flight).
    #[tokio::test]
    async fn workchain_adopts_the_masterchain_slash_rotation() {
        let me = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        let newcomer = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        let bond = crate::staking::required_bond_floor_nano();
        let (master_engine, _handle, _master, mut workchain) =
            masterchain_and_workchain(me, newcomer).await;

        master_engine
            .staking_write()
            .await
            .bond(me, bond, 0)
            .expect("the masterchain bond must be accepted");
        master_engine
            .staking_write()
            .await
            .bond(newcomer, bond, 0)
            .expect("the newcomer bond must be accepted");
        assert!(workchain.refresh_validator_set_from_staking().await);
        advance_test_height(&mut workchain);
        assert_eq!(workchain.validators.total_power(), 2 * bond);

        // Slash the newcomer by 10%: its stake falls below the minimum bond,
        // so it leaves the elected set. The workchain must see THAT set, not
        // the pre-slash one — from the next boundary, not mid-flight.
        let burned = master_engine
            .staking_write()
            .await
            .slash(newcomer, 1_000)
            .expect("the slash must be accepted");
        assert!(burned > 0, "the slash must burn stake");
        assert!(
            workchain.refresh_validator_set_from_staking().await,
            "a masterchain slash must rotate the workchain's set"
        );
        assert!(
            workchain.validators.validators.contains_key(&newcomer),
            "the slashed validator stays in force until the boundary"
        );
        advance_test_height(&mut workchain);
        assert!(
            !workchain.validators.validators.contains_key(&newcomer),
            "the slashed validator must leave the workchain's set"
        );
        assert_eq!(
            workchain.validators.validators.get(&me),
            Some(&bond),
            "the untouched validator keeps its full power"
        );
    }

    /// Periodic workchain repair (R3 CODE-TAILS sweep): a workchain that stops
    /// finalizing — the wedged shard-1 state — never reaches any
    /// height-advance path, so without an advance-free re-read its set can
    /// never converge. `refresh_workchain_set_from_master` is that re-read:
    /// a masterchain rotation stages the new set with NO finalize, NO adopt,
    /// NO walk and NO height advance anywhere in between, and the next
    /// boundary installs it. The masterchain (and un-wired runtimes) are a
    /// silent no-op.
    #[tokio::test]
    async fn workchain_periodic_master_reread_converges_without_any_finalize() {
        let me = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        let newcomer = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        let bond = crate::staking::required_bond_floor_nano();
        let (master_engine, _handle, mut master, mut workchain) =
            masterchain_and_workchain(me, newcomer).await;

        // A bond lands on the masterchain while the workchain is wedged: it
        // finalizes nothing, advances nothing, walks nothing.
        master_engine
            .staking_write()
            .await
            .bond(me, bond, 0)
            .expect("the masterchain bond must be accepted");
        let wedged_height = workchain.hc.height;

        // The periodic repair — no height-advance path involved — stages the
        // master set.
        assert!(
            workchain.refresh_workchain_set_from_master().await,
            "the periodic repair must pick up the masterchain rotation"
        );
        assert_eq!(
            workchain.hc.height, wedged_height,
            "the repair must not move the height by itself"
        );
        assert_eq!(
            workchain.validators.validators.get(&me),
            Some(&1),
            "the in-force set must not jump mid-flight"
        );
        assert_eq!(
            workchain.pending_validators.as_ref().map(|(a, _)| *a),
            Some(wedged_height + 1),
            "the rotation stages at the next height boundary"
        );
        // A quiet interval changes nothing and reports nothing.
        assert!(
            !workchain.refresh_workchain_set_from_master().await,
            "a converged repair must be silent"
        );
        // The next boundary — however the node gets there — installs it.
        advance_test_height(&mut workchain);
        assert_eq!(
            workchain.validators.validators.get(&me),
            Some(&bond),
            "the boundary installs the master set the repair staged"
        );
        assert_eq!(
            workchain
                .validator_set_for_height(wedged_height + 1)
                .validators,
            workchain.validators.validators,
        );

        // Non-workchains are a silent no-op: the masterchain never reads a
        // foreign registry, wired handle or not.
        master_engine
            .staking_write()
            .await
            .bond(newcomer, bond, 0)
            .expect("the newcomer bond must be accepted");
        assert!(
            !master.refresh_workchain_set_from_master().await,
            "the masterchain must ignore the periodic workchain repair"
        );
        assert!(
            !master.validators.validators.contains_key(&newcomer),
            "the masterchain's own set moves only on its own refresh"
        );
    }

    /// Post-restart wedge repair: a refresh can move the runtime's in-force
    /// set without moving heights (restore from a lagging domains snapshot,
    /// then a live-ledger refresh), stranding the consensus copy on the older
    /// set. The node then schedules different proposers from converged peers
    /// and no height ever advances to rebuild the copy (observed live:
    /// #388561 with one node on the post-change set vs the rest on the
    /// pre-change one). `resync_consensus_set_to_runtime` realigns the copy
    /// without any finalize/adopt/walk; a second call is a silent no-op.
    #[tokio::test]
    async fn consensus_copy_resyncs_to_runtime_without_height_advance() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        use std::sync::Arc;
        let me = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        let other = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        let state = Arc::new(InMemoryStateEngine::new());
        let old_set = ValidatorSet::from_list(vec![(me, 100), (other, 100)]);
        let key = SigningKey::generate(&mut OsRng);
        let mut rt = ValidatorRuntime::new(key, old_set, state, 10);
        let wedged_height = rt.hc.height;
        // Simulate the wedge: the runtime set moved (live-ledger refresh)
        // while the consensus height — and its copy — did not.
        let new_set = ValidatorSet::from_list(vec![(me, 100), (other, 90)]);
        rt.validators = new_set.clone();
        assert_ne!(
            rt.hc.validators.validators, rt.validators.validators,
            "the test must start wedged"
        );
        assert!(rt.resync_consensus_set_to_runtime(), "the resync must fire");
        assert_eq!(rt.hc.height, wedged_height, "no height may move");
        assert_eq!(rt.hc.validators.validators, new_set.validators);
        assert!(
            !rt.resync_consensus_set_to_runtime(),
            "a converged copy must be silent"
        );
        // The copy now schedules exactly like a fresh node on the new set.
        for round in [0u32, 1, 7, 64] {
            rt.hc.round = round;
            assert_eq!(
                rt.hc.proposer(),
                new_set.proposer_for(wedged_height, round),
                "round {round} must schedule identically"
            );
        }
    }
}

/// Tests for the TON `shard_hashes` model: a masterchain block publishes the
/// latest finalized header of every workchain shard, and the commitment is
/// covered by the block hash (so the BFT quorum signs it).
#[cfg(test)]
mod shard_header_commitment_tests {
    use super::*;
    use crate::sharding::{FinalizedHeaderRegistry, ShardHeaderCommitment, ShardRegistry};
    use rand::rngs::OsRng;

    const SHARD1: ShardId = 1;

    /// Domain-separation seed for the VEL-1 pool sender (shared by the pool
    /// helper and the pack-filter fixture so both address the same sender).
    const VEL1_POOL_SEED: u8 = 0xE1;

    /// A funded state engine for the test validator (same shape as the
    /// helper of the main test module, which is private to it).
    async fn funded_state(owner: [u8; 32]) -> Arc<InMemoryStateEngine> {
        let st = Arc::new(InMemoryStateEngine::new());
        st.update_account(crate::state_engine::AccountState::new(owner, 10_000_000))
            .await;
        st
    }

    /// FULL-PQ sender (mirrors the main test module's `pq_pair` idiom):
    /// implicit Falcon-512 envelope, key pre-registered globally, so
    /// admission and packing behave exactly like the old classical fixture.
    fn pq_pair(seed: u8) -> ([u8; 32], Vec<u8>) {
        let pk = crate::sharding::Transaction::sample_falcon512_pubkey(seed);
        let from = crate::post_quantum::derive_pq_address(
            crate::post_quantum::PqScheme::Falcon512,
            &pk,
            &crate::post_quantum::DEFAULT_SALT,
        );
        crate::sharding::Transaction::global_implicit_registry()
            .register(
                from,
                crate::post_quantum::PqScheme::Falcon512,
                &pk,
                &crate::post_quantum::DEFAULT_SALT,
            )
            .expect("PQ test key must register");
        (from, pk)
    }

    /// FULL-PQ replacement for `Transaction::sign` in this module.
    fn pq_tx(seed: u8, to: [u8; 32], amount: u64, gas: u64, nonce: u64) -> crate::sharding::Transaction {
        let (from, pk) = pq_pair(seed);
        let mut tx = crate::sharding::Transaction {
            from,
            to,
            amount,
            gas_limit: gas,
            nonce,
            source_shard: crate::sharding::MASTERCHAIN_SHARD,
            target_shard: crate::sharding::MASTERCHAIN_SHARD,
            signature: Vec::new(),
            payload: Vec::new(),
            priority_fee_per_gas: 0,
        };
        let msg = tx.signing_message();
        let sig = crate::sharding::Transaction::create_falcon512_test_signature(&pk, &msg, seed);
        tx.signature = crate::sharding::PqSignatureEnvelope::new_implicit(
            crate::post_quantum::PqScheme::Falcon512,
            sig,
        )
        .encode();
        tx
    }

    /// Falcon vote minting (mirrors `consensus::tests::fvote`).
    fn fvote(
        sk: &SigningKey,
        fk: &crate::post_quantum::FalconKeypair,
        height: crate::consensus::Height,
        round: crate::consensus::Round,
        kind: crate::consensus::VoteKind,
        bh: Option<[u8; 32]>,
    ) -> crate::consensus::Vote {
        crate::consensus::Vote::sign_with_falcon(sk, fk, height, round, kind, bh)
    }

    /// FULL-PQ QC (mirrors `sync::tests::pq_cert_for`): `parent` must be the
    /// block's `prev_hash` (chain binding).
    fn pq_cert_for(
        vs: &crate::consensus::ValidatorSet,
        keys: &[SigningKey],
        fks: &[crate::post_quantum::FalconKeypair],
        height: u64,
        bh: [u8; 32],
        parent: [u8; 32],
    ) -> crate::consensus::QuorumCertificate {
        let mut set = crate::consensus::VoteSet::new();
        for (sk, fk) in keys.iter().zip(fks.iter()) {
            let v = fvote(
                sk,
                fk,
                height,
                0,
                crate::consensus::VoteKind::Precommit,
                Some(bh),
            );
            set.add(v, vs, height, 0, crate::consensus::VoteKind::Precommit)
                .expect("falcon vote must ingest");
        }
        set.certificate_with_parent(Some(bh), vs, Some(&parent))
            .expect("quorum must compile a Falcon µQC")
    }

    fn workchain_block(height: u64, root: [u8; 32]) -> Block {
        Block {
            shard_id: SHARD1,
            height,
            prev_hash: [0x11; 32],
            state_root: root,
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 1_700_000_000 + height,
            proposer: [0x33; 32],
            validator_signatures: vec![],
            precommit_qc: None,
            last_qc: None,
            shard_headers: vec![],
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
            mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
        }
    }

    /// A masterchain block must commit to the latest finalized header of
    /// every workchain shard: the shard id, the height, the block hash, the
    /// state root and the timestamp.
    #[tokio::test]
    async fn masterchain_block_commits_workchain_shard_headers_and_roots() {
        let key = SigningKey::generate(&mut OsRng);
        let me = key.verifying_key().to_bytes();
        let state = funded_state(me).await;
        let validators = ValidatorSet::from_list(vec![(me, 1)]);

        // One process, two shards: the masterchain and one workchain shard.
        let shard_registry = ShardRegistry::from_ids([MASTERCHAIN_SHARD, SHARD1]);
        let hdrs: Arc<std::sync::RwLock<FinalizedHeaderRegistry>> =
            Arc::new(std::sync::RwLock::new(FinalizedHeaderRegistry::default()));

        let mut rt = ValidatorRuntime::new(key.clone(), validators, state, 1)
            .with_shard(MASTERCHAIN_SHARD, shard_registry)
            .with_finalized_headers(hdrs.clone());

        // The workchain shard finalized a block: the masterchain must publish
        // its head in every block it produces.
        let shard_block = workchain_block(7, [0x22; 32]);
        {
            let mut reg = hdrs.write().expect("registry lock");
            reg.note_finalized_commitment(ShardHeaderCommitment {
                shard_id: SHARD1,
                height: shard_block.height,
                block_hash: shard_block.compute_hash(),
                state_root: shard_block.state_root,
                timestamp: shard_block.timestamp,
            });
        }

        let block = rt
            .propose(1_700_000_100)
            .await
            .expect("propose must succeed");
        assert_eq!(block.shard_id, MASTERCHAIN_SHARD);
        assert_eq!(
            block.shard_headers.len(),
            1,
            "the masterchain must publish the workchain shard head"
        );
        let head = &block.shard_headers[0];
        assert_eq!(head.shard_id, SHARD1);
        assert_eq!(head.height, 7);
        assert_eq!(head.block_hash, shard_block.compute_hash());
        assert_eq!(head.state_root, shard_block.state_root);
        assert_eq!(head.timestamp, shard_block.timestamp);
        assert!(block.shard_headers_canonical());
        assert_eq!(block.shard_head(SHARD1).map(|h| h.height), Some(7));

        // The commitment is CRYPTOGRAPHICALLY BOUND: the same body without the
        // shard head hashes differently, so a quorum signature over this block
        // signs the shard roots. A tampered root must move the hash too.
        let mut without = block.clone();
        without.shard_headers.clear();
        assert_ne!(block.compute_hash(), without.compute_hash());

        let mut tampered = block.clone();
        tampered.shard_headers[0].state_root = [0xEE; 32];
        assert_ne!(block.compute_hash(), tampered.compute_hash());
    }

    /// A workchain block commits to nothing but its own body: only the
    /// masterchain publishes shard heads.
    #[tokio::test]
    async fn workchain_block_publishes_no_shard_heads() {
        let key = SigningKey::generate(&mut OsRng);
        let me = key.verifying_key().to_bytes();
        let state = funded_state(me).await;
        let validators = ValidatorSet::from_list(vec![(me, 1)]);

        let shard_registry = ShardRegistry::from_ids([MASTERCHAIN_SHARD, SHARD1]);
        let hdrs: Arc<std::sync::RwLock<FinalizedHeaderRegistry>> =
            Arc::new(std::sync::RwLock::new(FinalizedHeaderRegistry::default()));
        {
            let mut reg = hdrs.write().expect("registry lock");
            reg.note_finalized_commitment(ShardHeaderCommitment {
                shard_id: SHARD1,
                height: 7,
                block_hash: [0x44; 32],
                state_root: [0x55; 32],
                timestamp: 1_700_000_007,
            });
        }

        let mut rt = ValidatorRuntime::new(key.clone(), validators, state, 1)
            .with_shard(SHARD1, shard_registry)
            .with_finalized_headers(hdrs);

        let block = rt
            .propose(1_700_000_100)
            .await
            .expect("propose must succeed");
        assert_eq!(block.shard_id, SHARD1);
        assert!(
            block.shard_headers.is_empty(),
            "a workchain block must not publish shard heads"
        );
    }

    /// A validator refuses a masterchain block whose shard-head set is not
    /// canonical, and one that contradicts a header it already finalized.
    #[tokio::test]
    async fn validator_refuses_a_contradicting_shard_head() {
        let key = SigningKey::generate(&mut OsRng);
        let me = key.verifying_key().to_bytes();
        let state = funded_state(me).await;
        let validators = ValidatorSet::from_list(vec![(me, 1)]);
        let shard_registry = ShardRegistry::from_ids([MASTERCHAIN_SHARD, SHARD1]);
        let hdrs: Arc<std::sync::RwLock<FinalizedHeaderRegistry>> =
            Arc::new(std::sync::RwLock::new(FinalizedHeaderRegistry::default()));

        let mut rt = ValidatorRuntime::new(key.clone(), validators, state, 1)
            .with_shard(MASTERCHAIN_SHARD, shard_registry)
            .with_finalized_headers(hdrs.clone());

        let shard_block = workchain_block(7, [0x22; 32]);
        {
            let mut reg = hdrs.write().expect("registry lock");
            reg.note_finalized_commitment(ShardHeaderCommitment {
                shard_id: SHARD1,
                height: shard_block.height,
                block_hash: shard_block.compute_hash(),
                state_root: shard_block.state_root,
                timestamp: shard_block.timestamp,
            });
        }

        let root = rt.state.get_state_root().await;
        let good = rt
            .propose(1_700_000_100)
            .await
            .expect("propose must succeed");
        assert!(rt.validate_proposal(&good, root).is_ok());

        // A head that contradicts the header we finalized at the same height
        // (same height, different root) is an equivocation: refused.
        let mut forged = good.clone();
        forged.shard_headers[0].state_root = [0x99; 32];
        forged.validator_signatures.clear();
        forged.sign_block(&key);
        let err = rt
            .validate_proposal(&forged, root)
            .expect_err("a contradicting shard head must be refused");
        assert!(err.contains("contradicts"), "got: {err}");

        // A NON-canonical set (descending shard ids) is refused as well.
        let mut unsorted = good.clone();
        unsorted.shard_headers.clear();
        unsorted.shard_headers.push(ShardHeaderCommitment {
            shard_id: 2,
            height: 1,
            block_hash: [0x01; 32],
            state_root: [0x02; 32],
            timestamp: 1,
        });
        unsorted.shard_headers.push(ShardHeaderCommitment {
            shard_id: 1,
            height: 1,
            block_hash: [0x03; 32],
            state_root: [0x04; 32],
            timestamp: 1,
        });
        unsorted.validator_signatures.clear();
        unsorted.sign_block(&key);
        let err = rt
            .validate_proposal(&unsorted, root)
            .expect_err("a non-canonical shard head set must be refused");
        assert!(err.contains("canonical"), "got: {err}");
    }

    /// A single-shard process (the default registry) publishes no shard head
    /// at all, so its block hashes stay byte-identical to the pre-sharding
    /// ones.
    #[tokio::test]
    async fn single_shard_process_publishes_no_shard_heads() {
        let key = SigningKey::generate(&mut OsRng);
        let me = key.verifying_key().to_bytes();
        let state = funded_state(me).await;
        let validators = ValidatorSet::from_list(vec![(me, 1)]);
        let mut rt = ValidatorRuntime::new(key.clone(), validators, state, 1);
        let block = rt
            .propose(1_700_000_100)
            .await
            .expect("propose must succeed");
        assert!(block.shard_headers.is_empty());
    }

    /// W10.5 heal (2026-10-25): snapshot-sync jumps consensus to a verified
    /// boundary but leaves the light client anchored at genesis (expecting
    /// block 1), so the body walk refuses the whole tail and the node never
    /// converges. `reanchor_light_client_at_snapshot` must move the anchor
    /// AT the boundary (from the boundary block's own QC) so the tail
    /// verifies; a boundary block WITHOUT a QC must leave the stale anchor
    /// alone (fail closed — the walk still refuses).
    #[tokio::test]
    async fn snapshot_jump_reanchors_light_client_for_tail_walk() {
        use crate::consensus::QuorumCertificate;

        fn qc_for(
            vs: &crate::consensus::ValidatorSet,
            ks: &[SigningKey],
            fks: &[crate::post_quantum::FalconKeypair],
            height: u64,
            bh: [u8; 32],
            parent: [u8; 32],
        ) -> QuorumCertificate {
            pq_cert_for(vs, ks, fks, height, bh, parent)
        }

        fn empty_block(height: u64, prev: [u8; 32], root: [u8; 32], proposer: [u8; 32]) -> Block {
            Block {
                shard_id: crate::sharding::MASTERCHAIN_SHARD,
                height,
                prev_hash: prev,
                state_root: root,
                transactions: vec![],
                cross_shard_out: vec![],
                timestamp: 1_700_000_000 + height,
                proposer,
                validator_signatures: vec![],
                shard_headers: vec![],
                precommit_qc: None,
                last_qc: None,
                order_merkle_root: crate::mev::compute_order_merkle_root(&[]),
                epoch_key_commitment: [0u8; 32],
                mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
            }
        }

        let ks: Vec<SigningKey> = (0..3).map(|_| SigningKey::generate(&mut OsRng)).collect();
        let ids: Vec<[u8; 32]> = ks.iter().map(|k| k.verifying_key().to_bytes()).collect();
        let vs = ValidatorSet::from_list(ids.iter().map(|id| (*id, 1_000_000)).collect());
        let me = ids[0];
        let mut rt = ValidatorRuntime::new(ks[0].clone(), vs.clone(), funded_state(me).await, 1);
        // FULL-PQ: register Falcon keys so the hand-minted µQC verifies (a
        // classical `Vote::sign` QC no longer does).
        let fks: Vec<crate::post_quantum::FalconKeypair> = ks
            .iter()
            .enumerate()
            .map(|(i, k)| {
                let fk = crate::post_quantum::FalconKeypair::generate_from_seed(0xA0 + i as u8);
                crate::consensus::register_validator_pq_key(
                    k.verifying_key().to_bytes(),
                    crate::post_quantum::PqScheme::Falcon512,
                    fk.public_key.clone(),
                );
                fk
            })
            .collect();
        let genesis_root = rt.state.get_state_root().await;
        rt.set_light_client(vs.clone(), genesis_root)
            .expect("anchor at genesis");

        // The boundary block at height 50 with a real 3/3 precommit QC.
        let boundary = 50u64;
        let mut blk = empty_block(boundary, [0x11; 32], genesis_root, ids[0]);
        let bh = blk.compute_hash();
        let qc = qc_for(&vs, &ks, &fks, boundary, bh, [0x11; 32]);
        assert!(qc.verify(&vs), "test QC must verify");
        blk.precommit_qc = Some(qc);

        // The tail block right after the boundary, also fully certified.
        // Like every real block it carries ONLY its proposer's block-hash
        // signature (votes sign `vote_sign_bytes`, never the block hash), so
        // its block-signature power (1M) is far below quorum (2M+1) — while
        // its precommit QC is a full 3/3.
        let mut tail = empty_block(boundary + 1, bh, genesis_root, ids[1]);
        tail.sign_block(&ks[1]);
        let th = tail.compute_hash();
        tail.precommit_qc = Some(qc_for(&vs, &ks, &fks, boundary + 1, th, bh));

        // Simulate the snapshot jump: finalized head + consensus move, but
        // the light client is still at genesis.
        rt.finalized.push((boundary, bh));
        rt.hc.height = boundary + 1;
        assert!(rt.light_client().unwrap().tip_height() < boundary);

        // The tail is refused before the re-anchor (genesis anchor, gap)...
        let refused = crate::sync::verify_synced_blocks_against_anchor_with_sets(
            rt.light_client().unwrap(),
            std::slice::from_ref(&tail),
            &|_| Some(vs.clone()),
        );
        assert!(refused.is_err(), "tail must be refused on the stale anchor");

        // ...and accepted after it. (The strict per-header check still
        // refuses the single-proposer block signature — pinning the protocol
        // reality the finality-only probe path works around.)
        let strict = crate::light_client::LightHeader::of_block(&tail).expect("tail carries a QC");
        assert!(
            strict.verify(&vs).is_err(),
            "a single proposer signature must not pass the block-signature quorum"
        );
        rt.reanchor_light_client_at_snapshot(boundary, &blk);
        assert_eq!(
            rt.light_client().unwrap().tip_height(),
            boundary,
            "anchor must sit AT the boundary"
        );
        crate::sync::verify_synced_blocks_against_anchor_with_sets(
            rt.light_client().unwrap(),
            std::slice::from_ref(&tail),
            &|_| Some(vs.clone()),
        )
        .expect("tail must verify after the re-anchor");

        // Fail-closed: a boundary block without a QC leaves the anchor alone.
        let mut rt2 = ValidatorRuntime::new(ks[0].clone(), vs.clone(), funded_state(me).await, 1);
        rt2.set_light_client(vs.clone(), genesis_root)
            .expect("anchor at genesis");
        rt2.finalized.push((boundary, bh));
        let bare = empty_block(boundary, [0x11; 32], genesis_root, ids[0]);
        rt2.reanchor_light_client_at_snapshot(boundary, &bare);
        assert_eq!(
            rt2.light_client().unwrap().tip_height(),
            0,
            "a QC-less boundary block must not move the anchor"
        );
    }

    // ========================================================================
    // VEL-1 bounded proposer-prebuild: reuse ≡ fresh, staleness fail-safe
    // ========================================================================

    async fn vel1_runtime_with_pool(key: &SigningKey, ntxs: u64) -> (ValidatorRuntime, [u8; 32]) {
        let txs: Vec<crate::sharding::Transaction> =
            (0..ntxs).map(|nonce| pq_tx(VEL1_POOL_SEED, [0x77u8; 32], 1_000, 21_000, nonce)).collect();
        vel1_runtime_with_cloned_pool(key, &txs).await
    }

    /// A runtime pre-loaded with CLONES of one caller-built pool.
    ///
    /// PQ necessity: Falcon-512 signing is randomized (FIPS 206), so two
    /// independently minted pools from the same seed carry different
    /// signature bytes (hence different tx hashes). Sharing one pool makes
    /// the reuse-vs-fresh inputs identical BY CONSTRUCTION — the property
    /// under test (same inputs ⇒ same selection) — instead of relying on
    /// the classical era's deterministic Ed25519 regeneration.
    async fn vel1_runtime_with_cloned_pool(
        key: &SigningKey,
        txs: &[crate::sharding::Transaction],
    ) -> (ValidatorRuntime, [u8; 32]) {
        let me = key.verifying_key().to_bytes();
        let validators = ValidatorSet::from_list(vec![(me, 1)]);
        let state = Arc::new(InMemoryStateEngine::new());
        // FULL-PQ: the pool sender is a Falcon-512 identity; classical
        // `Transaction::sign` outputs are refused at admission, so the pool
        // would stay empty.
        let (pq_from, _pk) = pq_pair(VEL1_POOL_SEED);
        state
            .update_account(crate::state_engine::AccountState::new(pq_from, 10_000_000))
            .await;
        let mut rt = ValidatorRuntime::new(key.clone(), validators, state, 1);
        for tx in txs {
            rt.add_tx(tx.clone()).await;
        }
        (rt, pq_from)
    }

    /// Reuse is byte-identical to a fresh build when nothing changed, and the
    /// cache never leaks across heights (stale ⇒ fresh path, no panic).
    #[tokio::test]
    async fn vel1_prebuild_reuse_is_byte_identical_to_fresh() {
        const TS: u64 = 1_700_000_001;
        // Same deterministic key for both runtimes: identical state, pool
        // and timestamp, so any selection divergence is a reuse bug.
        let key = SigningKey::generate(&mut OsRng);
        // A: prebuild during the idle window, then propose (reuse path).
        // The pool is minted ONCE and cloned into both runtimes (Falcon
        // signing is randomized, so independent minting would differ in
        // signature bytes and the inputs would not be identical).
        let txs: Vec<crate::sharding::Transaction> =
            (0..8u64).map(|n| pq_tx(VEL1_POOL_SEED, [0x77u8; 32], 1_000, 21_000, n)).collect();
        let (mut a, _) = vel1_runtime_with_cloned_pool(&key, &txs).await;
        let h = a.hc.height;
        assert!(!a.has_prebuild_for(h), "no prebuild before the idle window");
        a.prebuild_next_proposal(TS).await;
        assert!(
            a.has_prebuild_for(h),
            "idle-window prebuild must cache this height"
        );
        let ba = a
            .propose(TS)
            .await
            .expect("reuse-path propose must succeed");
        // B: no prebuild, straight to propose (fresh path).
        let (mut b, _) = vel1_runtime_with_cloned_pool(&key, &txs).await;
        assert!(!b.has_prebuild_for(h));
        let bb = b
            .propose(TS)
            .await
            .expect("fresh-path propose must succeed");
        // Same inputs ⇒ same selection, same header, same block hash.
        // (The pool is shared and proposer signing is deterministic, so
        // even the signatures agree; any divergence here is a reuse bug,
        // not nondeterminism.)
        assert_eq!(
            ba.transactions.len(),
            8,
            "all 8 funded contiguous txs must pack, reuse path"
        );
        assert_eq!(
            ba.transactions
                .iter()
                .map(|t| t.compute_tx_hash())
                .collect::<Vec<_>>(),
            bb.transactions
                .iter()
                .map(|t| t.compute_tx_hash())
                .collect::<Vec<_>>(),
            "reuse path must select exactly the fresh path's transactions in order"
        );
        assert_eq!(
            ba.compute_hash(),
            bb.compute_hash(),
            "reuse block must be byte-identical to the fresh block"
        );
        // The cache is height-scoped: a different height never reuses.
        assert!(
            !a.has_prebuild_for(h + 1),
            "no cross-height reuse without a prebuild"
        );
    }

    /// Staleness fail-safe: state that moved under the prebuild (funds spent
    /// elsewhere ⇒ the parent changed) only shrinks the reuse — the block
    /// still builds and still validates. No invalid proposal, no panic.
    #[tokio::test]
    async fn vel1_prebuild_stale_state_degrades_to_valid_block() {
        const TS: u64 = 1_700_000_002;
        let key = SigningKey::generate(&mut OsRng);
        let (mut rt, me) = vel1_runtime_with_pool(&key, 6).await;
        let h = rt.hc.height;
        rt.prebuild_next_proposal(TS).await;
        assert!(rt.has_prebuild_for(h));
        // Drain the sender elsewhere: every cached tx is now unfunded vs
        // live state (the "parent changed under the prebuild" shape).
        rt.state
            .update_account(crate::state_engine::AccountState::new(me, 0))
            .await;
        let b = rt
            .propose(TS)
            .await
            .expect("stale prebuild must still propose");
        let root = rt.state.get_state_root().await;
        assert!(
            b.transactions.is_empty(),
            "unfunded cached txs must be dropped by revalidation, got {}",
            b.transactions.len()
        );
        rt.validate_proposal_unaligned(&b, root)
            .expect("stale-prebuild block must still validate");
    }

    /// The pack predicate rejects exactly the invalid shapes (pins the
    /// factored filter: admission-parity, no silent acceptance).
    #[tokio::test]
    async fn vel1_pack_filter_accepts_valid_rejects_invalid() {
        const TS: u64 = 1_700_000_003;
        let key = SigningKey::generate(&mut OsRng);
        let (rt, me) = vel1_runtime_with_pool(&key, 0).await;
        let state_root = rt.state.get_state_root().await;
        let (base_fee, penalties) = {
            let pool = rt.mempool.read().await;
            (pool.base_fee, pool.penalty_snapshot())
        };
        let session_keys = rt.state.session_keys_read().await.clone();
        let mut accounts = HashMap::new();
        accounts.insert(me, (0u64, 10_000_000u64));
        let ctx = PackFilterCtx::new(
            TS,
            false,
            crate::sharding::MASTERCHAIN_SHARD,
            base_fee,
            penalties,
            session_keys,
            accounts,
            crate::zkml::SessionSpendSim::default(),
            HashSet::new(),
        );
        let to = [0x77u8; 32];
        // FULL-PQ fixture: the funded sender is the VEL-1 Falcon-512 pool
        // identity (same property, PQ envelope — the filter never checks
        // signatures, only nonce continuity and the fee floor).
        let good = pq_tx(VEL1_POOL_SEED, to, 1_000, 21_000, 0);
        assert!(
            ValidatorRuntime::pack_filter_accept(&ctx, &good),
            "funded nonce-0 tx must pass"
        );
        // Consumed: the same tx re-checked now fails the nonce (state moved).
        let gap = pq_tx(VEL1_POOL_SEED, to, 1_000, 21_000, 5);
        assert!(
            !ValidatorRuntime::pack_filter_accept(&ctx, &gap),
            "nonce gap must be skipped"
        );
        let _ = state_root;
    }

    /// Loaded-size differential (500 txs, multi-sender): reuse ≡ fresh at
    /// scale, with wall-clock timings printed for the report (host ms; the
    /// harness models the virtual-ms effect separately).
    #[tokio::test]
    async fn vel1_prebuild_loaded_pool_reuse_matches_fresh() {
        const TS: u64 = 1_700_000_004;
        // FULL-PQ: 10 Falcon-512 senders (domain-separated seeds); the
        // classical `SigningKey` fixtures are refused at admission, so the
        // loaded pool would stay empty.
        const BASE_SEED: u8 = 0x50;
        let valkey = SigningKey::generate(&mut OsRng);
        let me = valkey.verifying_key().to_bytes();
        let validators = ValidatorSet::from_list(vec![(me, 1)]);
        let mk = || {
            let state = Arc::new(InMemoryStateEngine::new());
            ValidatorRuntime::new(valkey.clone(), validators.clone(), state, 1)
        };
        let mut a = mk();
        let mut b = mk();
        // One shared pool: Falcon signing is randomized, so each runtime
        // must receive CLONES of the same mint (see the reuse test) for the
        // inputs to be identical.
        let pool: Vec<crate::sharding::Transaction> = (0..10u8)
            .flat_map(|s| {
                let seed = BASE_SEED + s;
                (0..50u64).map(move |n| pq_tx(seed, [0x77u8; 32], 1_000, 21_000, n))
            })
            .collect();
        for rt in [&mut a, &mut b] {
            for s in 0..10u8 {
                let (from, _pk) = pq_pair(BASE_SEED + s);
                rt.state
                    .update_account(crate::state_engine::AccountState::new(from, 100_000_000))
                    .await;
            }
            for tx in &pool {
                rt.add_tx(tx.clone()).await;
            }
        }
        // Reuse path: prebuild first, then time propose.
        a.prebuild_next_proposal(TS).await;
        assert!(a.has_prebuild_for(a.hc.height));
        let t0 = std::time::Instant::now();
        let ba = a.propose(TS).await.expect("reuse propose");
        let reuse_ms = t0.elapsed().as_secs_f64() * 1000.0;
        // Fresh path: straight to propose, timed.
        let t0 = std::time::Instant::now();
        let bb = b.propose(TS).await.expect("fresh propose");
        let fresh_ms = t0.elapsed().as_secs_f64() * 1000.0;
        println!(
            "[vel1] loaded-pool propose fresh={fresh_ms:.2}ms reuse={reuse_ms:.2}ms txs={}",
            bb.transactions.len()
        );
        assert_eq!(ba.transactions.len(), bb.transactions.len());
        assert_eq!(
            ba.compute_hash(),
            bb.compute_hash(),
            "loaded reuse must match fresh"
        );
        assert!(!bb.transactions.is_empty(), "loaded pool must pack");
    }

    /// Cap truncation keeps a valid prefix and respects every block cap.
    #[test]
    fn vel1_truncate_to_block_caps_keeps_valid_prefix() {
        use crate::sharding::Transaction;
        let key = SigningKey::generate(&mut OsRng);
        let to = [0x77u8; 32];
        let mut txs: Vec<Transaction> = (0..10u64)
            .map(|n| {
                Transaction::sign(
                    &key,
                    to,
                    1,
                    1_000_000,
                    n,
                    crate::sharding::MASTERCHAIN_SHARD,
                    crate::sharding::MASTERCHAIN_SHARD,
                )
            })
            .collect();
        // Within caps: untouched.
        let mut ok = txs.clone();
        ValidatorRuntime::truncate_to_block_caps(&mut ok);
        assert_eq!(ok.len(), 10);
        // Force over gas late in the list: truncation keeps the valid prefix.
        txs[8].gas_limit = u64::MAX / 2;
        let mut over = txs.clone();
        ValidatorRuntime::truncate_to_block_caps(&mut over);
        assert_eq!(
            over.len(),
            8,
            "over-cap selection must truncate to the fitting prefix"
        );
        assert_eq!(
            over[0].compute_tx_hash(),
            txs[0].compute_tx_hash(),
            "truncation must keep the prefix (nonce contiguity)"
        );
        let mut empty: Vec<Transaction> = Vec::new();
        ValidatorRuntime::truncate_to_block_caps(&mut empty);
        assert!(empty.is_empty());
    }

    /// C-02/P0: the live-path sweep finalizes due proposals at the decided
    /// height — locks release and the 7200-height timelock schedules.
    /// // GATE: proves the `sweep_gov_finalize` wiring; extends, never weakens.
    #[tokio::test]
    async fn sweep_gov_finalize_releases_locks_and_schedules_timelock() {
        use crate::governance::{
            GovAction, ProposalStatus, VoteChoice, GOVERNANCE_VOTING_PERIOD_SECS,
            GOV_TIMELOCK_HEIGHTS, PROPOSAL_MIN_STAKE_NANO,
        };
        let state = Arc::new(InMemoryStateEngine::new());
        let proposer = [0xA1u8; 32];
        let voter = [0xB2u8; 32];
        {
            let mut ledger = state.staking_write().await;
            ledger.bond(proposer, PROPOSAL_MIN_STAKE_NANO, 0).unwrap();
            ledger.bond(voter, PROPOSAL_MIN_STAKE_NANO, 0).unwrap();
        }
        let pid = {
            let mut gov = state.governance_write().await;
            let mut ledger = state.staking_write().await;
            let id = gov
                .propose(
                    &mut ledger,
                    proposer,
                    "t".into(),
                    GovAction::Signal("s".into()),
                    0,
                )
                .expect("propose");
            gov.vote(&mut ledger, proposer, id, VoteChoice::Yes, 1)
                .expect("proposer vote");
            gov.vote(&mut ledger, voter, id, VoteChoice::Yes, 1)
                .expect("voter vote");
            id
        };
        // Locks are held before finalization (the C-02 grief: never released).
        {
            let ledger = state.staking_read().await;
            assert!(ledger.locked_governance_of(&proposer) > 0);
            assert!(ledger.locked_governance_of(&voter) > 0);
        }
        // Not due yet (voting window still open): the sweep leaves it Open.
        let now_due = GOVERNANCE_VOTING_PERIOD_SECS + 1;
        let early =
            sweep_gov_finalize(&state, 999, GOVERNANCE_VOTING_PERIOD_SECS - 1).await;
        assert!(early.is_empty());
        assert_eq!(
            state.governance_read().await.get(pid).unwrap().status,
            ProposalStatus::Open
        );
        // Due at the decided height: finalized, locks released, timelock set.
        let pass_height = 41_000u64;
        let done = sweep_gov_finalize(&state, pass_height, now_due).await;
        assert_eq!(done, vec![pid]);
        assert_eq!(
            state.governance_read().await.get(pid).unwrap().status,
            ProposalStatus::Passed
        );
        assert!(
            state.staking_read().await.locked_governance.is_empty(),
            "finalize must release every gov lock"
        );
        assert_eq!(
            state.governance_read().await.executable_height_of(pid),
            Some(pass_height + GOV_TIMELOCK_HEIGHTS)
        );
        // Idempotent: a second sweep at a later height is a no-op.
        let again = sweep_gov_finalize(&state, pass_height + 1, now_due).await;
        assert!(again.is_empty());
    }

    /// Serializes the env-touching gate tests below: the escape hatch is
    /// process-global, so the set/restore in the escape test must never
    /// overlap the unset expectation of the refuse test (parallel lib tests
    /// share one process).
    static GOV_GATE_ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn lock_gate_env() -> std::sync::MutexGuard<'static, ()> {
        GOV_GATE_ENV_GUARD
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Build a runtime with `n` bonded stakers (>= propose minimum) and an
    /// attached governance engine. The runtime's in-force validator set has
    /// exactly `n` members, which is what the write guard reads.
    async fn gate_test_runtime(n: usize) -> (ValidatorRuntime, Vec<ValidatorId>) {
        use crate::governance::{Governance, PROPOSAL_MIN_STAKE_NANO};
        let keys: Vec<SigningKey> = (0..n)
            .map(|i| SigningKey::from_bytes(&[(i as u8).wrapping_add(1); 32]))
            .collect();
        let ids: Vec<ValidatorId> = keys
            .iter()
            .map(|k| k.verifying_key().to_bytes())
            .collect();
        let vs = ValidatorSet::from_list(ids.iter().map(|id| (*id, 1)).collect());
        let state = Arc::new(InMemoryStateEngine::new());
        {
            let mut ledger = state.staking_write().await;
            for id in &ids {
                ledger
                    .bond(
                        *id,
                        PROPOSAL_MIN_STAKE_NANO,
                        crate::staking::DEFAULT_COMMISSION_BPS,
                    )
                    .expect("test bond must succeed");
            }
        }
        let rt = ValidatorRuntime::new(keys[0].clone(), vs, state, 1)
            .with_governance(Governance::new());
        (rt, ids)
    }

    /// Solo runtime (1 validator): propose + vote go through (existing
    /// behavior preserved). Passes with or without the escape env, so no
    /// env guard is needed.
    #[tokio::test]
    async fn gov_write_gate_solo_allows_propose_and_vote() {
        use crate::governance::{GovAction, VoteChoice};
        let (mut rt, ids) = gate_test_runtime(1).await;
        let pid = rt
            .gov_propose(ids[0], "t".into(), GovAction::Signal("s".into()), 0)
            .expect("solo propose must succeed");
        rt.gov_vote(ids[0], pid, VoteChoice::Yes, 1)
            .expect("solo vote must succeed");
    }

    /// Multi-node runtime (3 validators): propose AND vote are refused as
    /// multi-node — the vote refusal proves the gate runs BEFORE any
    /// proposal lookup (an unknown id would otherwise fail as
    /// `UnknownProposal`, hiding the real reason).
    #[tokio::test]
    async fn gov_write_gate_multi_node_refuses_propose_and_vote() {
        use crate::governance::{GovAction, GovError, VoteChoice, GOV_MULTINODE_WRITES_ENV};
        // Built BEFORE arming the env guard: construction touches no env,
        // and the guard must never be held across an await.
        let (mut rt, ids) = gate_test_runtime(3).await;
        {
            let _guard = lock_gate_env();
            let saved = std::env::var(GOV_MULTINODE_WRITES_ENV).ok();
            std::env::remove_var(GOV_MULTINODE_WRITES_ENV);
            let propose_err = rt
                .gov_propose(ids[0], "t".into(), GovAction::Signal("s".into()), 0)
                .expect_err("multi-node propose must be refused");
            match &propose_err {
                GovError::MultiNodeRefused(msg) => assert!(
                    msg.contains(GOV_MULTINODE_WRITES_ENV),
                    "refusal must name the escape env, got: {msg}"
                ),
                other => panic!("expected MultiNodeRefused, got: {other:?}"),
            }
            let vote_err = rt
                .gov_vote(ids[0], 999_999, VoteChoice::Yes, 1)
                .expect_err("multi-node vote must be refused");
            assert!(
                matches!(vote_err, GovError::MultiNodeRefused(_)),
                "vote must fail at the gate, not at lookup; got: {vote_err:?}"
            );
            match saved {
                Some(v) => std::env::set_var(GOV_MULTINODE_WRITES_ENV, v),
                None => std::env::remove_var(GOV_MULTINODE_WRITES_ENV),
            }
        }
    }

    /// Escape hatch: with `STELL_GOV_ALLOW_MULTINODE_WRITES=1` the same
    /// 3-validator runtime proposes and votes (re-allowed explicitly).
    #[tokio::test]
    async fn gov_write_gate_escape_reallows_multi_node() {
        use crate::governance::{GovAction, VoteChoice, GOV_MULTINODE_WRITES_ENV};
        // Built BEFORE arming the env guard: construction touches no env,
        // and the guard must never be held across an await.
        let (mut rt, ids) = gate_test_runtime(3).await;
        {
            let _guard = lock_gate_env();
            let saved = std::env::var(GOV_MULTINODE_WRITES_ENV).ok();
            std::env::set_var(GOV_MULTINODE_WRITES_ENV, "1");
            let pid = rt
                .gov_propose(ids[0], "t".into(), GovAction::Signal("s".into()), 0)
                .expect("escaped propose must succeed");
            rt.gov_vote(ids[0], pid, VoteChoice::Yes, 1)
                .expect("escaped vote must succeed");
            match saved {
                Some(v) => std::env::set_var(GOV_MULTINODE_WRITES_ENV, v),
                None => std::env::remove_var(GOV_MULTINODE_WRITES_ENV),
            }
        }
    }
}
