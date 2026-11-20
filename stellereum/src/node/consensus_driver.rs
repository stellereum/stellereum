use ed25519_dalek::SigningKey;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::info;

use crate::liveness_alarm;
use crate::node::policy::*;
use crate::node::sync::*;
use stellereum::consensus::{ValidatorSet, VoteKind};
use stellereum::consensus_net::{parse_incoming, ConsensusMsg, ConsensusNetwork, TxGossip};
use stellereum::network::CrossShardTransport;
use stellereum::network::P2pNetworkAdapter;
use stellereum::runtime::ValidatorRuntime;
use stellereum::sharding::ShardRegistry;
use stellereum::state_engine::InMemoryStateEngine;
use stellereum::tokenomics::BLOCK_REWARD_NANO;

/// Re-enter the inbound drain as a FULL proposal.
///
/// A compact proposal resolves into a complete `Block`. Handing it straight to
/// `on_proposal` would duplicate the attribution, H+1 deferral, hint and vote
/// machinery of the plain-Proposal arm. Instead the resolved block is encoded
/// exactly like a wire `Proposal` and pushed back into the bounded deferred
/// queue, so it is parsed, verified and handled by the ONE existing path —
/// there is no second implementation to drift.
fn encode_full_proposal_loopback(
    block: &stellereum::sharding::Block,
    round: u32,
    src: &str,
) -> Option<String> {
    let msg = ConsensusMsg::Proposal {
        height: block.height,
        round,
        block: block.clone(),
    };
    let bytes = msg.encode().ok()?;
    // Carry the originating peer id so admission/accounting can attribute the
    // re-injected frame instead of charging a shared "broadcast" bucket. Local
    // loopbacks ride their own bounded queue and are not re-charged to the
    // bulk limiter (the compact frame already paid); attribution still lets
    // scoring/rate decisions see who caused the work.
    Some(serde_json::json!({ "data": hex::encode(bytes), "src": src }).to_string())
}

/// Signed-preimage kind tag of a vote (0 = prevote, 1 = precommit).
fn vote_watermark_kind(kind: VoteKind) -> u8 {
    match kind {
        VoteKind::Prevote => 0,
        VoteKind::Precommit => 1,
    }
}

/// WRITE-AHEAD the vote watermark BEFORE the vote can reach the wire.
///
/// The record carries the exact `(height, round, kind, target, shard)` the node
/// signed and is fsynced, so a crash right after the broadcast can never lose
/// it: on restart the node restores the watermark and refuses to vote again at
/// or below that round (Finding C). Failing to persist is LOUD; consensus is
/// not blocked, because a wedged disk must not stop the network — but an
/// operator sees the exact loss window.
fn persist_vote_watermark_before_broadcast(
    persistence: Option<&Arc<stellereum::storage::AsyncPersistence>>,
    vote: &stellereum::consensus::Vote,
) {
    let Some(ap) = persistence else {
        return;
    };
    let storage = ap.storage();
    let mut wm = match storage.vote_watermark() {
        Ok(Some(wm)) => wm,
        Ok(None) => stellereum::storage::VoteWatermark::default(),
        Err(e) => {
            tracing::error!(
                "[consensus] could not read the vote watermark ({e}); writing a fresh one \
                 (the new vote is still recorded)"
            );
            stellereum::storage::VoteWatermark::default()
        }
    };
    wm.note(stellereum::storage::VoteWatermarkEntry {
        height: vote.height,
        round: vote.round,
        kind: vote_watermark_kind(vote.kind),
        target: vote.block_hash,
        shard_id: vote.shard_id,
    });
    if let Err(e) = storage.persist_vote_watermark(&wm) {
        tracing::error!(
            "[consensus] FAILED to persist the write-ahead vote watermark for h={} r={} \
             ({e}): a crash before the next checkpoint could lose this vote",
            vote.height,
            vote.round
        );
    }
}

/// True when `round` is at or below the highest round already signed at
/// `height`. Such a vote is refused — the round was already used (possibly
/// before a crash), so re-voting there is exactly the double-sign the
/// watermark exists to prevent.
fn round_at_or_below_vote_floor(floor: Option<(u64, u32)>, height: u64, round: u32) -> bool {
    matches!(floor, Some((h, r)) if h == height && round <= r)
}

/// Liveness cap for the persisted CONSENSUS round on restart.
///
/// This is a LIVENESS bound only (a runaway view-change loop must not resume
/// at round 806 while peers sit at round 0). It is NEVER a cap on the vote
/// watermark: a round this node already signed must not be re-entered, so the
/// watermark is a hard FLOOR applied after this cap (Finding C).
const MAX_RESTORED_ROUND: u32 = 64;

/// The round a restart resumes at: the persisted consensus round clamped for
/// liveness, then raised — never lowered — to the vote watermark floor.
///
/// Pure and shared with the regression test, so the test exercises the exact
/// production arithmetic instead of re-deriving it.
fn restored_round(persisted_round: u32, vote_watermark_floor: Option<u32>) -> u32 {
    let capped = persisted_round.min(MAX_RESTORED_ROUND);
    vote_watermark_floor.map_or(capped, |floor| capped.max(floor))
}

/// The finalized tip a restart MUST use for a loaded engine state.
///
/// `snapshot_state_height` is the height whose POST-state the engine holds.
/// The stored `finalized` pointer is normally at or above it. It can be
/// BEHIND it: the finalize pointer is an asynchronously-queued job that may be
/// dropped under queue pressure (loudly, but dropped), while the state
/// snapshot of a later height did land — and the snapshot loader only installs
/// state at `S` when block `S + 1` anchors its root, so that state is already
/// final.
///
/// Running with `hc.height = S + 1` while `finalized` still says `F < S` is
/// the HEIGHT-SPLIT defect: `propose` builds at `S + 1` with `prev_hash` = the
/// hash of block `F`, a gap no peer accepts, and the catch-up walk anchors at
/// `F + 1`, whose block commits to the root the engine has already left
/// behind — so every walk is refused on parent-root continuity and the node
/// can never rejoin (only a wipe did).
///
/// Returns the tip the node must use. `resolve_parent_hash(S)` must return the
/// hash of the finalized block at `S`; `None` means the local store cannot
/// prove it, and the caller must fail closed rather than propose above an
/// unfinalized parent.
fn reconciled_finalized_tip(
    snapshot_state_height: u64,
    stored_finalized: Option<(u64, [u8; 32])>,
    resolve_parent_hash: impl Fn(u64) -> Option<[u8; 32]>,
) -> Result<Option<(u64, [u8; 32])>, String> {
    let stored_tip = stored_finalized.map(|(h, _)| h).unwrap_or(0);
    if snapshot_state_height <= stored_tip {
        return Ok(stored_finalized);
    }
    match resolve_parent_hash(snapshot_state_height) {
        Some(hash) => Ok(Some((snapshot_state_height, hash))),
        None => Err(format!(
            "engine state is at height {snapshot_state_height} but the stored finalized tip is \
             {stored_tip} and no local header/body proves the hash of block {snapshot_state_height}; \
             refusing to run (and propose) above an unfinalized parent"
        )),
    }
}

/// True when this node may build a proposal at `hc_height`.
///
/// A block's `prev_hash` is always our finalized tip, so proposing is only
/// meaningful at exactly `finalized_tip + 1` (height 1 at genesis). Any other
/// combination builds a block that skips heights or reuses a decided parent;
/// peers refuse it as a stale/wrong height, and the node burns rounds on a
/// proposal nobody can vote. This is the propose-side half of HEIGHT-SPLIT.
fn proposal_parent_is_finalized(finalized_tip: u64, hc_height: u64) -> bool {
    finalized_tip.checked_add(1) == Some(hc_height)
}

/// Raise the in-memory floor after a vote was cast this process.
fn advance_vote_floor(floor: &mut Option<(u64, u32)>, height: u64, round: u32) {
    match floor {
        Some((h, r)) if *h == height => {
            if round > *r {
                *r = round;
            }
        }
        _ => *floor = Some((height, round)),
    }
}

#[allow(clippy::too_many_arguments)]
// GATE: 15 consensus wiring inputs are required together; grouping would change call sites and sync semantics.
#[allow(unused_assignments)]
// GATE: restored-state height stores are crash-recovery bookkeeping; removing them would obscure healing flow.
#[allow(irrefutable_let_patterns)]
// GATE: PQ key conversion is fail-closed via copy; restructuring would risk changing validator registration.
#[allow(clippy::useless_conversion)]
// GATE: PQ address conversion is byte-identical; removing try_into would change error handling on malformed keys.
pub(crate) async fn run_consensus_node(
    adapter: Arc<P2pNetworkAdapter>,
    key: SigningKey,
    validators: ValidatorSet,
    state: Arc<InMemoryStateEngine>,
    shard: u32,
    // The chain this instance produces blocks for. Almost always the DHT
    // namespace `shard`, EXCEPT the main flow of any process, which is
    // pinned to the masterchain (a `--shard 1` process still produces
    // shard-0 blocks; workchains run as extras). Separate from `shard`
    // because conflating them stalled the stand twice (M1 regression +
    // the store-lock fight on sharding enablement).
    block_shard: u32,
    persistence: Option<Arc<stellereum::storage::AsyncPersistence>>,
    _shared_staking: Arc<tokio::sync::RwLock<stellereum::staking::StakingLedger>>,
    shared_gov: Arc<tokio::sync::RwLock<stellereum::governance::Governance>>,
    rpc: Arc<stellereum::rpc::RpcState>,
    remote_signer: Option<Arc<dyn stellereum::remote_signer::Signer>>,
    is_validator: bool,
    registry: ShardRegistry,
    header_registry: Arc<std::sync::RwLock<stellereum::sharding::FinalizedHeaderRegistry>>,
    // The MASTERCHAIN's staking registry, shared process-wide.
    //
    // The masterchain runtime passes its OWN registry (its state engine's —
    // the registry it commits); a workchain runtime passes THE SAME handle.
    // The workchain's consensus validator set is derived from it, so a
    // masterchain rotation (bond / unbond / slash) is adopted by the
    // workchain at its next height boundary — no restart.
    master_staking: stellereum::sharding::MasterStakingLedger,
) {
    // Shard-scoped topic: use block_shard so masterchain (0) and workchains (1..N)
    // strictly use disjoint topics and never cross-talk or flood each other.
    let net = Arc::new(ConsensusNetwork::new_for_shard(
        adapter.clone(),
        block_shard,
        &registry,
    ));
    // Dedicated ordered broadcast sender (P4): the tick enqueues drained chunks
    // and never awaits the peer's `request_to` round trip. See `flush_outbox`.
    let net_sender = net.start_sender();
    // The block shard arrives as a parameter (see signature): the main flow
    // passes MASTERCHAIN_SHARD, a workchain extra passes its own id. Never
    // derive it from the namespace here - that confusion stalled the stand.
    let mut rx = net.subscribe().await;
    let gossip = Arc::new(TxGossip::new(adapter.clone()));
    let mut tx_rx = gossip.subscribe().await;
    // ONE mempool, shared by the RPC and the consensus loop.
    //
    // These used to be two separate objects: a transaction submitted over RPC
    // landed in the RPC mempool, while the proposer selected from the runtime's
    // own mempool, which was only filled from the P2P overlay. So whether a
    // transaction was ever included depended on the network echoing it back —
    // on a single-validator node it never came back and transactions sat
    // pending forever, and the RPC's reported mempool size was fiction.
    // Sharing the object makes inclusion local and the reported size truthful.
    // Self id for the dynamic franchise check in the loop below (`key` moves
    // into the runtime on the next line).
    let self_vote_id = key.verifying_key().to_bytes();
    // FULL-PQ: always enforced. `--pure-pq` / `STELL_PURE_PQ` are dead
    // operator-compat knobs: parsed-and-ignored with a loud WARN (never gate).
    let has_pq_cli = std::env::args().any(|arg| arg == "--pure-pq");
    if has_pq_cli {
        eprintln!("[WARN] --pure-pq is a no-op (FULL-PQ always-on): flag ignored");
    }
    if std::env::var("STELL_PURE_PQ").is_ok() {
        eprintln!("[WARN] STELL_PURE_PQ is a no-op (FULL-PQ always-on): env ignored");
    }
    {
        stellereum::post_quantum::set_pure_pq_override(Some(true));
    }
    info!("[post-quantum] Pure PQ Mode: ENFORCED (Falcon-512 / ML-DSA)");
    let env_var = std::env::var("STELL_PARALLEL_EXEC").ok();
    let has_cli_flag = std::env::args().any(|arg| arg == "--parallel-exec");
    let parallel_exec = is_parallel_exec_active(
        env_var.as_deref(),
        has_cli_flag,
        state.is_parallel_exec_enabled(),
    );
    if parallel_exec {
        info!("[engine] parallel execution: enabled");
    } else {
        info!("[engine] parallel execution: sequential fallback");
    }
    state.set_parallel_exec(parallel_exec);
    // Post-quantum validator identity: persistent Falcon-512 keypair
    // (generated once, never derived from public data — deriving a
    // PRIVATE key deterministically from a PUBLIC validator id would let
    // anyone forge any validator's votes). Path via STELL_FALCON_KEY_FILE
    // (default ./keys/falcon.key, next to identity.key). Peers learn each
    // other's Falcon pubkeys via STELL_PEER_PQ_KEYS="edpubhex:pqpubhex,..."
    // (like the ed-pub entries in node.yaml). All keys are registered before
    // consensus starts.
    let falcon_path = std::env::var("STELL_FALCON_KEY_FILE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("./keys/falcon.key"));
    let our_falcon: stellereum::post_quantum::FalconKeypair =
        match stellereum::node_keys::load_or_generate_falcon_key(&falcon_path) {
            Ok(k) => k,
            Err(e) => {
                panic!(
                    "[fatal] failed to load or generate falcon key at {}: {e}",
                    falcon_path.display()
                );
            }
        };
    info!(
        "[post-quantum] validator Falcon-512 pubkey: {}",
        hex::encode(&our_falcon.public_key)
    );
    stellereum::consensus::register_validator_pq_key(
        self_vote_id,
        stellereum::post_quantum::PqScheme::Falcon512,
        our_falcon.public_key.clone(),
    );
    if let Ok(peers) = std::env::var("STELL_PEER_PQ_KEYS") {
        for entry in peers.split(',') {
            let mut parts = entry.split(':');
            if let (Some(ed_hex), Some(pq_hex)) = (parts.next(), parts.next()) {
                if let (Ok(ed), Ok(pq)) = (hex::decode(ed_hex.trim()), hex::decode(pq_hex.trim())) {
                    if let (Ok(ed_arr),) = (ed.as_slice().try_into().map(|a: &[u8]| {
                        let mut out = [0u8; 32];
                        out.copy_from_slice(a);
                        out
                    }),)
                    {
                        stellereum::consensus::register_validator_pq_key(
                            ed_arr,
                            stellereum::post_quantum::PqScheme::Falcon512,
                            pq,
                        );
                    }
                }
            }
        }
    }
    // Election is the canonical parent-hash draw (no key material provisioned).
    let mut rt = ValidatorRuntime::new(key, validators, state.clone(), 1)
        .with_mempool(rpc.mempool.clone())
        // The epoch-seal frames (the DKG contribution, the order commitment
        // and the share release) travel on the transaction-gossip channel.
        .with_tx_gossip(gossip.clone())
        .with_shard(block_shard, registry.clone())
        .with_block_reward(BLOCK_REWARD_NANO)
        .with_parallel_exec(parallel_exec)
        .with_falcon_key(our_falcon)
        // Fork-choice / invalidation wiring: the runtime records every
        // valid candidate branch it sees BEFORE finality and publishes an
        // invalidation signal whenever a branch is pruned (a competing
        // block was finalized) or rolled back by a reorg. The signal goes
        // to the RPC layer, which serves `stell_getInvalidations` and
        // streams it to the `invalidations` subscribers — so a client that
        // was told about a block learns when that block is not on the
        // chain.
        .with_invalidation_sink(std::sync::Arc::new(
            |sig: stellereum::chain::InvalidationSignal| {
                stellereum::rpc::publish_invalidation(&sig);
            },
        ))
        // The masterchain's staking registry, shared process-wide. On the
        // masterchain this IS its own registry (its state engine's ledger);
        // on a workchain it is the master's, so the workchain's consensus set
        // follows every masterchain rotation instead of freezing on the
        // config-defined set.
        .with_master_staking(master_staking.clone());
    // CN-VRF v3 secret custody: only when the gate is actually live at this
    // node's height. Write-ahead `enc2:` persistence lives beside the node
    // keys; the boot self-check refuses to reveal/propose if the on-disk
    // secret no longer matches the on-chain commitment (`sync_cnvrf_v3_on_boot`).
    if rt.cnvrf_v3_is_active_at(rt.height()) {
        // Ops-controlled location (the gate is off in production, so this is
        // only exercised by an activating rollout and by tests):
        // `STELL_CNVRF_V3_DIR`, else `data/cnvrf_v3` beside the node data.
        let custody_dir = std::env::var("STELL_CNVRF_V3_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::PathBuf::from("data/cnvrf_v3"));
        // The chain id MUST be the one the state engine commits to: the
        // commit-signature message and the beacon seed bind it, so pinning the
        // default constant instead would make a chain running a different
        // `STELL_CHAIN_ID` reject its own commitments.
        rt.configure_cnvrf_v3_custody(custody_dir, state.chain_id);
        rt.sync_cnvrf_v3_on_boot().await;
    }
    // P2 shard gate (pool level, defense in depth): the runtime and the RPC
    // layer share ONE pool (`with_mempool(rpc.mempool.clone())`), so pinning
    // it here covers EVERY admission path at the choke point — RPC, faucet,
    // gossip ingress and the restore below — even where the caller passes no
    // shard in its context. The per-call `with_shard` contexts stay as the
    // explicit first line; this is the backstop. Single-shard stays unpinned.
    if registry.is_sharded() {
        rpc.mempool
            .write()
            .await
            .set_admission_shard(Some(block_shard));
    }
    // LIGHT CLIENT ANCHOR (audit W8.3 / production blocker A10).
    //
    // The node now runs a light client of its own, anchored at the chain's
    // GENESIS (the state root this node built its genesis from — trusted by
    // CONSTRUCTION). Every peer-supplied block is checked against that
    // anchor, and every block this node finalizes moves the anchor up to the
    // quorum-certified finalized head. The anchor is what the node SERVES to
    // external verifiers (`stell_getFinalizedCheckpoint`), so a wallet can
    // check a proof against a root a quorum committed to instead of a root
    // the node merely asserted.
    {
        let genesis_root = state.get_state_root().await;
        let anchor_validators = rt.validators.clone();
        match rt.set_light_client(anchor_validators, genesis_root) {
            Ok(()) => info!(
                "[light-client] anchored at the genesis (root {})",
                hex::encode(&genesis_root[..6])
            ),
            Err(e) => eprintln!("[light-client] NOT anchored: {e}"),
        }
    }
    // Restore persisted mempool (survives restarts so pending transactions are
    // not silently lost with the in-memory pool). Re-admitted against current
    // state: stale entries drop, the rest resume waiting. Each shard owns its
    // own pool file, so one shard's pending set never leaks into another's.
    let mempool_path = mempool_path_for_shard(block_shard, registry.is_sharded());
    {
        let path = mempool_path.clone();
        // P2 shard gate: the restore re-admits through the pinned pool, and
        // the context carries the shard explicitly too — a persisted pool
        // file from another shard (copied data dir, shared volume) restores
        // zero transactions instead of polluting this shard's pool.
        let restore_ctx = if registry.is_sharded() {
            stellereum::mempool::AdmissionCtx::wall_now().with_shard(block_shard)
        } else {
            stellereum::mempool::AdmissionCtx::wall_now()
        };
        let n = rpc
            .mempool
            .write()
            .await
            .load_into(&path, &state, restore_ctx)
            .await;
        if n > 0 {
            info!("[mempool] restored {n} persisted transaction(s)");
        }
    }
    // When a remote signer is configured it signs every vote and proposal, and
    // `with_remote_signer` refuses a handle whose key is not this node's identity.
    if let Some(signer) = remote_signer {
        rt = rt
            .with_remote_signer(signer)
            .expect("remote signer key must match the validator identity");
        info!("[signer] consensus messages are signed by the REMOTE signer");
    }
    // §5 M3 production cross-shard wiring: a multi-shard process
    // (`STELL_SHARDS=0,1`) routes cross-shard flow through the shared infnode
    // node-local KV. Gated on `is_sharded()`, so the single-shard default
    // keeps `cross_shard == None` and behaves byte-identically to before.
    if registry.is_sharded() {
        rt = rt.with_cross_shard(CrossShardTransport::from_node(adapter.clone()));
        info!(
            "[shard {}] cross-shard transport wired (node-local KV)",
            block_shard
        );
        // §9 CROSS-SHARD 2PC: the activation switch. `STELL_XPC_ACTIVATION_HEIGHT`
        // names the height from which NEW cross-shard transfers run the
        // two-phase commit (prepare / vote / commit) instead of the legacy
        // outbox/inbox/ack/bounce flow. Unset => the legacy flow (the mode
        // the deployed chain state runs in). The height is CONSENSUS-VISIBLE
        // (it decides which flow a transfer takes), so every node of a shard
        // must be configured with the SAME value.
        let xpc_activation = xpc_activation_from_env();
        rt = rt.with_xpc_activation(xpc_activation);
        match xpc_activation.boundary() {
            Some(h) => info!(
                "[shard {}] cross-shard 2PC ACTIVE from height {} (new transfers use prepare/vote/commit)",
                block_shard,
                h
            ),
            None => info!(
                "[shard {}] cross-shard 2PC inactive (legacy outbox/inbox/ack/bounce flow)",
                block_shard
            ),
        }
        // C1 anchor: every shard runtime + engine in this process shares the
        // header registry passed in (one per process, built by main()).
        rt = rt.with_finalized_headers(header_registry.clone());
        rt.state.with_finalized_headers(header_registry);
    }

    // A14 chain-binding rollout, phase 3: the activation switch. Kept next to
    // the XPC activation above on purpose — same shape (an env height
    // boundary, default-off), same rule (every node of a deployment must be
    // configured with the SAME value; changing it mid-run needs a restart to
    // take effect uniformly). Unset/unparsable/`0` keeps phase-1 behaviour
    // (admit + meter) on every path; a set height arms refusal at RPC,
    // mempool and apply (see docs/PLAN-BINDING.md).
    match stellereum::chain_binding::ChainBindingActivation::from_chain_spec() {
        a if a.height == stellereum::chain_binding::CHAIN_BINDING_NEVER => info!(
            "[binding] chain-binding refusal inactive (STELL_CHAIN_BIND_ACTIVATION_HEIGHT unset): unbound transactions are admitted + metered"
        ),
        a => tracing::warn!(
            "[binding] chain-binding refusal ARMED from height {}: unbound transactions are refused at RPC, mempool and apply (see docs/PLAN-BINDING.md)",
            a.height
        ),
    }

    // Election is the canonical parent-hash draw on every height.
    info!("[sortition] canonical parent-hash draw: election on every height");

    // Restore the FULL persisted state (accounts + all domains) if available.
    // `restored_state_height` is the height whose post-state the engine holds (0 for
    // a fresh start). It can lag the finalized head below, and entering consensus
    // with engine < head forks the node -- see the healing block after seeding.
    let mut restored_state_height: u64 = 0;
    let mut restored_checkpoint: Option<stellereum::storage::ConsensusCheckpoint> = None;
    // Write-ahead vote watermark (Finding C): read inside the persistence
    // block below, consumed by the vote-history restore after it.
    let mut restored_watermark: Option<stellereum::storage::VoteWatermark> = None;
    if let Some(ap) = &persistence {
        match stellereum::storage::load_full_state_into(&ap.storage(), &rt.state).await {
            Ok(Some((h, ledger, mut gov))) => {
                restored_state_height = h;
                info!(
                    "[storage] restored full state from height {h}, resuming at {}",
                    h + 1
                );
                rt.hc = stellereum::consensus::HeightConsensus::new(h + 1, rt.validators.clone());
                // Sortition entropy for the resumed height: the parent block
                // hash of the restored state (the block at height `h`). The
                // finalized list is EMPTY at this point in startup (the
                // storage head is read further down), so the parent is
                // UNKNOWN here — and an unknown parent must NOT be faked
                // with the zero hash: the node would elect a committee no
                // other node elects and could never assemble a certificate
                // they accept (audit W6.4b). The reconciliation further down
                // sets it as soon as the head is known.
                if let Some((_, fh)) = rt.finalized.last().copied() {
                    rt.hc.set_parent_hash(fh);
                }
                // Block-carried governance migration (HDAE-GOV startup hook,
                // in-memory only): pre-activation proposals restored from
                // storage are normalized BEFORE install so engine, runtime
                // and RPC observe the migrated state identically (`next_id`
                // repair + status census; see
                // `Governance::migrate_gov_proposals_to_genesis`).
                // Idempotent: a second run changes nothing.
                let gov_migration = gov.migrate_gov_proposals_to_genesis();
                info!(
                    "[gov] migration: {} pre-existing proposal(s) (open={} passed={} rejected={} executed={} invalid_actions={}) next_id_repaired={}",
                    gov_migration.proposals_seen,
                    gov_migration.open,
                    gov_migration.passed,
                    gov_migration.rejected,
                    gov_migration.executed,
                    gov_migration.invalid_actions,
                    gov_migration.next_id_repaired,
                );
                *rt.state.governance_write().await = gov.clone();
                // The ledger is restored into the state engine (consensus state),
                // which the runtime shares by reference.
                *rt.state.staking_write().await = ledger;
                rt.governance = Some(gov);
                // Same convergence as the snapshot path below: the restored
                // ledger may name a different set than our config
                // (bonds/slashes/rotations since genesis, or a stake that
                // landed while this node was down). Without this, a node
                // restoring PAST a set change keeps the stale config set
                // until the NEXT change — and if the change added itself,
                // its dynamic franchise (can_vote) never engages. Observed
                // live: a staked newcomer restored past its own bond height
                // and sat silent while the chain waited one power short.
                //
                // STALE-LEDGER GUARD (node C): the ledger snapshot height is
                // compared against the state height before the set is trusted
                // for quorum use. A ledger lagging beyond
                // `validator_set_freshness_max_lag` (default: the 300-height
                // snapshot ring) is REFUSED — fail-closed to observer with a
                // loud WARN — instead of silently installing a foreign set
                // the block walk can never repair (ancient bond outside every
                // window + stale peer domains). Paired restores pass `h` for
                // both heights (always fresh); the gap probe below catches a
                // store whose NEWEST state ran ahead of its newest domains
                // (unpaired tail from a crash between the two snapshot jobs).
                let ledger_h_for_check: u64 = ap
                    .storage()
                    .latest_ledger_height()
                    .ok()
                    .flatten()
                    .unwrap_or(h);
                // Newest-state vs newest-domains gap (crash-tail detector).
                if let Ok(Some((s_newest, l_newest))) = ap.storage().ledger_state_gap() {
                    if let Err(reason) =
                        stellereum::storage::check_validator_set_freshness(s_newest, l_newest)
                    {
                        rt.mark_validator_set_stale(s_newest, l_newest, reason);
                    }
                }
                if !rt.is_validator_set_stale()
                    && rt
                        .refresh_validator_set_from_staking_checked(h, ledger_h_for_check)
                        .await
                {
                    info!("[storage] validator set converged to the restored ledger at height {h}");
                }
                if rt.is_validator_set_stale() {
                    eprintln!(
                        "[validator-set] WARN node runs as OBSERVER until a fresh ledger arrives (stale restore at state {h}); votes disabled, quorums not trusted"
                    );
                }
                log_quorum_safety("restored ledger set", &rt.validators);
                // Cross-shard replay restore (audit F-I): the engine credit
                // gate came back via the load path above; restore the runtime
                // mirrors (produced/completed/consumed) from the same height
                // so timeout bounces still fire for pre-restart outbounds and
                // replays stay refused at propose/validate, not just at apply.
                // Absent entry (pre-F-I directory, or single-shard chain that
                // never used it) means empty sets - also what a fresh process
                // holds. Extends, never replaces.
                match ap.storage().cross_shard_at(h) {
                    Ok(Some(bytes)) => match bincode::deserialize::<
                        stellereum::sharding::CrossShardReplaySnapshot,
                    >(&bytes)
                    {
                        Ok(snap) => {
                            rt.restore_cross_shard_sets(&snap);
                            info!("[storage] restored cross-shard replay sets from height {h}");
                        }
                        Err(e) => {
                            eprintln!("[storage] cross-shard replay blob undecodable: {e:?}")
                        }
                    },
                    Ok(None) => {}
                    Err(e) => eprintln!("[storage] cross-shard replay read failed: {e}"),
                }
            }
            Ok(None) => info!("[storage] no prior state, starting fresh"),
            // Fail CLOSED. Continuing on a failed restore used to mean consensus on
            // whatever happened to be in memory -- usually genesis state paired with a
            // non-genesis finalized head -- which forks the node off the network while
            // reporting healthy. A node that cannot prove its restored state must not
            // vote. The operator wipes or restores a verified backup; the error above
            // says which.
            Err(e) => {
                eprintln!(
                    "[storage] REFUSING to run on unverified state: {e} \
                     (wipe the data directory or restore a verified backup)"
                );
                std::process::exit(1);
            }
        }

        // Seed the finalized head AFTER the load, whatever its outcome.
        //
        // This used to sit inside the `Ok(Some(..))` arm, so a node without a
        // state snapshot came back at height 0 with an empty finalized chain -
        // proposing from genesis while its data dir held a real chain. Snapshots
        // are only written every 100 heights, so a node killed at height 38 hit
        // exactly that case and could never rejoin: it had a peer at 38, no way to
        // ask for the gap, and it would spin in view changes at height 1 forever.
        //
        // `finalized_height` is written on every finalized block, so it is the
        // authoritative tip even when no snapshot exists.
        //
        // HEALING OBLIGATION: if the restored engine state (snapshot height S) is
        // behind the finalized head F, the node MUST NOT join consensus yet. Voting
        // from S-state at height F+1 forks it off the network while reporting
        // healthy -- observed live as a node proposing with a 78-block-stale root
        // forever. The block below closes the gap from peers (snapshot first, then
        // bodies) and refuses to start if the gap cannot be closed.
        match ap.storage().finalized() {
            Ok(Some((fh, fhash))) => {
                rt.finalized.push((fh, fhash));
                if fh + 1 > rt.hc.height {
                    rt.hc =
                        stellereum::consensus::HeightConsensus::new(fh + 1, rt.validators.clone());
                    info!(
                        "[storage] finalized head at height {fh}, resuming at {}",
                        fh + 1
                    );
                }
                if fh + 1 == rt.hc.height {
                    // Sortition entropy for the resumed height: the finalized
                    // head hash is the parent of the height we resume at.
                    rt.hc.set_parent_hash(fhash);
                } else if fh + 1 < rt.hc.height {
                    // The restored state is AHEAD of the stored finalized
                    // head: the parent of the height we resume at is the
                    // block at `rt.hc.height - 1`, whose hash the store knows
                    // but the (stale) finalized metadata does not. Use the
                    // local header index; without it the parent stays
                    // UNKNOWN and no committee is elected (fail closed).
                    let parent_height = rt.hc.height.saturating_sub(1);
                    match ap.storage().header_at(parent_height) {
                        Ok(Some(hdr)) => {
                            rt.hc.set_parent_hash(hdr.block_hash);
                        }
                        Ok(None) => {
                            tracing::warn!(
                                height = parent_height,
                                "[storage] no local header for the parent of the resumed height: \
                                 the sortition committee stays unknown until it is learned"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                height = parent_height,
                                error = %e,
                                "[storage] could not read the parent header of the resumed height"
                            );
                        }
                    }
                }
            }
            Ok(None) => {}
            Err(e) => eprintln!("[storage] could not read the finalized head: {e}"),
        }

        // HEIGHT-SPLIT RECONCILIATION (restart): never run with `hc.height`
        // above our own finalized tip + 1. The stored finalize pointer is an
        // async job that can be dropped under queue pressure while a later
        // state snapshot landed; the loader already proved that state (block
        // S + 1 anchors its root), so the state height IS final even when the
        // pointer was not updated. Repair the pointer from the hash-linked
        // local header instead of proposing at S + 1 with F's parent (a gap
        // no peer accepts, and a catch-up walk anchored at F that our engine
        // is already past). The trusted parent is the one the verified anchor
        // at S + 1 names; the header at S is the fallback. No proof -> fail
        // closed, because a block above an unfinalized parent forks.
        {
            let stored = ap.storage().finalized().ok().flatten();
            let resolved = reconciled_finalized_tip(restored_state_height, stored, |s| {
                if let Ok(Some(hdr)) = ap.storage().header_at(s.saturating_add(1)) {
                    if hdr.height == s.saturating_add(1) {
                        return Some(hdr.prev_hash);
                    }
                }
                if let Ok(Some(hdr)) = ap.storage().header_at(s) {
                    if hdr.height == s {
                        return Some(hdr.block_hash);
                    }
                }
                None
            });
            match resolved {
                Ok(Some((tip, hash)))
                    if tip > rt.finalized.last().map(|(h, _)| *h).unwrap_or(0) =>
                {
                    info!(
                        "[storage] engine state at {restored_state_height} is ahead of the stored \
                         finalized tip {}; repaired the tip to {tip} from the verified local header \
                         (a stale finalize pointer must never make the node propose above its own \
                         finalized parent)",
                        rt.finalized.last().map(|(h, _)| *h).unwrap_or(0)
                    );
                    rt.finalized.push((tip, hash));
                    if rt.hc.height != tip.saturating_add(1) {
                        rt.hc = stellereum::consensus::HeightConsensus::new(
                            tip.saturating_add(1),
                            rt.validators.clone(),
                        );
                    }
                    rt.hc.set_parent_hash(hash);
                }
                Ok(_) => {}
                Err(e) => {
                    eprintln!(
                        "[storage] REFUSING to join consensus on an unprovable head: {e} \
                         (wipe the data directory or restore a verified backup)"
                    );
                    std::process::exit(1);
                }
            }
        }

        // If we resumed from a tip but had no snapshot for it, take one now.
        // Otherwise the next restart repeats the same loss: the state is only
        // ever written every 100 heights, so a node that dies in between starts
        // from genesis again no matter how long it had been running.
        //
        // Label it with the height the engine ACTUALLY holds
        // (`restored_state_height`), never the tip: snapshotting S-state as F
        // poisons the store -- the next restart loads "state at F" that is
        // really S, skips healing (S == F), and votes from stale state while
        // reporting healthy. Observed live: nodes snapshotted 201-state as
        // 273/274 and forked on state roots permanently.
        if rt.finalized.last().is_some_and(|(h, _)| *h > 0) {
            let fh = rt.finalized.last().map(|(h, _)| *h).unwrap_or(0);
            let has_snapshot = ap
                .storage()
                .latest_state()
                .ok()
                .flatten()
                .is_some_and(|(sh, _)| sh >= restored_state_height);
            if !has_snapshot {
                ap.snapshot_state(&rt.state, restored_state_height).await;
                let ledger = rt.staking_read().await.clone();
                let gov = rt.governance.clone().unwrap_or_default();
                ap.snapshot_domains(&rt.state, &ledger, &gov, restored_state_height)
                    .await;
                info!("[storage] wrote a snapshot of engine state at height {restored_state_height} (tip {fh})");
            }
        }

        // HEAL: bring the engine up to the finalized head before voting on
        // anything. See `heal_engine_to_head` for why joining consensus with
        // engine < head forks the node while reporting healthy.
        if let Some(ap) = &persistence {
            if let Some((fh, fhash)) = ap.storage().finalized().ok().flatten() {
                if restored_state_height < fh {
                    info!(
                        "[storage] engine at {restored_state_height}, head at {fh}: healing the gap before joining consensus"
                    );
                    // Missing bodies are TRANSIENT (a peer that just restarted
                    // is still publishing its window): retry with backoff
                    // instead of exiting, so a restart race doesn't permanently
                    // kill the node. Anything else (mismatch, corrupt,
                    // unverifiable history) is a real refusal: exit
                    // fail-closed. Observed live: both nodes restarted
                    // together, neither had published yet, both refused, chain
                    // dead until manual wipe.
                    let mut healed = false;
                    for attempt in 1..=HEAL_MAX_ATTEMPTS {
                        match heal_engine_to_head(
                            &adapter,
                            &mut rt,
                            &ap.storage(),
                            block_shard,
                            restored_state_height,
                            fh,
                            fhash,
                        )
                        .await
                        {
                            Ok(reached) => {
                                info!("[storage] healed engine to height {reached}");
                                ap.snapshot_state(&rt.state, reached).await;
                                let ledger = rt.staking_read().await.clone();
                                let gov = rt.governance.clone().unwrap_or_default();
                                ap.snapshot_domains(&rt.state, &ledger, &gov, reached).await;
                                info!("[storage] persisted healed engine snapshot at height {reached}");
                                restored_state_height = reached;
                                healed = true;
                                break;
                            }
                            Err(e) => {
                                if heal_failure_should_exit(attempt) {
                                    // Fail CLOSED: the engine is still at
                                    // `restored_state_height < fh` and its
                                    // history is unverifiable (pruned/missing
                                    // bodies). Labelling it with `fh` here
                                    // would poison the store: the next boot
                                    // loads "state at F" that is really S,
                                    // skips healing (S == F), and votes from
                                    // stale state while reporting healthy.
                                    // Refuse to join consensus instead; the
                                    // operator wipes or restores a verified
                                    // backup. Matches the restore-refusal
                                    // `process::exit(1)` pattern above.
                                    eprintln!(
                                        "[storage] REFUSING to join consensus on unhealed state: \
                                         healing failed after {HEAL_MAX_ATTEMPTS} attempts: {e} \
                                         (engine at {restored_state_height}, head at {fh}; \
                                         wipe the data directory or restore a verified backup)"
                                    );
                                    std::process::exit(1);
                                }
                                eprintln!(
                                    "[storage] healing waiting for bodies (attempt {attempt}/{HEAL_MAX_ATTEMPTS}): {e}"
                                );
                                tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
                            }
                        }
                    }
                    let _ = healed;
                }
            }
        }

        // Write-ahead vote watermark (Finding C). Read BEFORE the checkpoint
        // restore: the watermark is the authoritative record of the last
        // votes this node SIGNED, and it is the only record that survives a
        // crash between a vote and the next checkpoint.
        restored_watermark = ap.storage().vote_watermark().ok().flatten();

        // Restore the consensus safety checkpoint so a node that restarted
        // mid-height cannot double-vote / prevote a conflicting value for a
        // height it already locked (Tendermint safety across a crash).
        if let Ok(Some(cp)) = ap.storage().consensus() {
            if cp.height == rt.hc.height {
                // Restore the ROUND too, but with a LIVENESS cap.
                //
                // Safety needs the round: a node that restarted mid-height must not
                // prevote or precommit a conflicting value for a height at which it
                // already voted. Liveness needs the cap: a node that restarted after
                // sitting in a runaway view-change loop comes back at, say, round 806
                // while its peers are at round 0, and then nobody proposes at the
                // height either side is willing to accept -- it deadlocks until an
                // operator wipes both data directories, which is exactly what happened
                // on the stand.
                //
                // So a stale persisted CONSENSUS round is treated as stale: beyond
                // MAX_RESTORED_ROUND we restart at the current round and let the peers
                // pull us up through normal view changes. The cap is LIVENESS ONLY: it
                // must never rewind BELOW a round this node already VOTED in, or the
                // node would re-vote a round it used. The write-ahead vote watermark
                // below is therefore a hard FLOOR on the restored round. The lock is
                // still honoured unconditionally -- that is the safety half and it
                // does not expire.
                let watermark_floor = restored_watermark
                    .as_ref()
                    .and_then(|wm| wm.floor_round(cp.height));
                let capped = cp.round.min(MAX_RESTORED_ROUND);
                let restored = restored_round(cp.round, watermark_floor);
                if let Some(floor) = watermark_floor {
                    if restored > capped {
                        info!(
                            "[consensus] persisted round {} at height {} is below the vote \
                             watermark round {} (already signed this round); resuming at {} \
                             -- the liveness cap must never rewind below a cast vote",
                            cp.round, cp.height, floor, floor
                        );
                    }
                }
                rt.hc.round = restored;
                if capped != cp.round {
                    info!(
                        "[consensus] persisted round {} at height {} looks stale; resuming at \
                         round {} instead so peers can re-converge",
                        cp.round, cp.height, restored
                    );
                }
                if let Some(h) = cp.locked_hash {
                    rt.hc.locked = Some((h, cp.locked_round));
                    if let std::collections::hash_map::Entry::Vacant(e) = rt.blocks.entry(h) {
                        if let Ok(Some(blk)) = ap.storage().get_block(&h) {
                            e.insert(blk);
                        }
                    }
                    info!(
                        "[consensus] restored lock for height {} round {}",
                        cp.height, cp.locked_round
                    );
                }
                restored_checkpoint = Some(cp);
            }
        }

        // The watermark is a per-height floor even when there is NO matching
        // checkpoint (the crash happened before one was written): a node that
        // signed a prevote at round 300 must not come back at round 0.
        if let Some(floor) = restored_watermark
            .as_ref()
            .and_then(|wm| wm.floor_round(rt.hc.height))
        {
            if rt.hc.round < floor {
                info!(
                    "[consensus] vote watermark at height {} round {} raises the resumed round \
                     from {} (no checkpoint had recorded it yet)",
                    rt.hc.height, floor, rt.hc.round
                );
                rt.hc.round = floor;
            }
        }
    }

    /// Bring the engine's state up to the finalized head BEFORE joining consensus.
    ///
    /// A restart loads the newest PAIRED snapshot (state S) and seeds the finalized head
    /// (F) from metadata. Whenever S < F the engine is behind its own head, and voting
    /// from S-state at height F+1 forks the node while reporting healthy -- observed live
    /// as proposals carrying a 78-block-stale root forever. This closes the gap or
    /// refuses to start; it never lets the node vote from unproven state.
    ///
    /// Method, in order: (1) replay bodies S+1..F from the LOCAL block store (our own
    /// finalized history, archive mode keeps every body); bodies missing locally are
    /// fetched from peers; (2) every replayed block must carry a verifiable precommit QC
    /// and commit to the running engine root -- history that predates decision proofs
    /// cannot be replayed and fails here, which is correct: it is unverifiable by anyone.
    /// (3) If the gap cannot be closed, exit(1). A node that cannot prove its state must
    /// not vote; the operator wipes or restores a verified backup.
    ///
    /// Returns the engine height reached (== F on success).
    #[allow(clippy::blocks_in_conditions)]
    // GATE: behind-peer gate builds its predicate inline for auditability; hoisting would obscure the suppression logic.
    #[allow(unused_assignments)]
    // GATE: healing counters are observability-only; dead stores preserve restart-safe accounting without affecting consensus.
    #[allow(unused_variables)]
    // GATE: tick/phase counters are perf-visibility only; unused reads preserve timing attribution without behavior change.
    async fn heal_engine_to_head(
        adapter: &Arc<P2pNetworkAdapter>,
        rt: &mut ValidatorRuntime,
        store: &stellereum::storage::Storage,
        shard: u32,
        engine_height: u64,
        finalized_head: u64,
        finalized_hash: [u8; 32],
    ) -> Result<u64, String> {
        if engine_height >= finalized_head {
            return Ok(engine_height);
        }
        // Walk BACKWARD from the head collecting hashes, preferring local bodies and
        // falling back to the network per hash. Bounded by the same million-block cap
        // as the live catch-up path.
        let mut hashes: Vec<[u8; 32]> = vec![finalized_hash];
        let mut cur = finalized_hash;
        for _ in 0..1_000_000u64 {
            let h = hashes.len() as u64;
            // Height of `cur` = finalized_head - (hashes.len() - 1). Stop when we reach
            // engine_height's block (whose hash we anchor below).
            if finalized_head - (h - 1) <= engine_height {
                break;
            }
            let blk = match store.get_block(&cur) {
                Ok(Some(b)) => b,
                _ => match adapter.fetch_block(&cur).await {
                    Some(b) => b,
                    None => {
                        return Err(format!(
                            "healing stuck: body {} unavailable locally and from peers",
                            hex::encode(cur)
                        ))
                    }
                },
            };
            cur = blk.prev_hash;
            hashes.push(cur);
        }
        hashes.reverse();
        // hashes[0] must be the engine state's block (height == engine_height). We prove
        // it by hash-linkage below rather than by trusting labels: each applied block's
        // F3.2 root check ties it to the running engine, so a wrong anchor fails loudly
        // on the first apply instead of forking quietly.
        let _ = shard;
        let mut applied = engine_height;
        for (i, hash) in hashes.iter().enumerate().skip(1) {
            let expected_height = engine_height + i as u64;
            let blk = match store.get_block(hash) {
                Ok(Some(b)) => b,
                _ => match adapter.fetch_block(hash).await {
                    Some(b) => b,
                    None => {
                        return Err(format!(
                            "healing stuck: body {} unavailable locally and from peers",
                            hex::encode(hash)
                        ))
                    }
                },
            };
            if blk.height != expected_height {
                return Err(format!(
                    "healing broken: expected height {expected_height}, got {}",
                    blk.height
                ));
            }
            if blk.compute_hash() != *hash {
                return Err(format!(
                "healing broken: body at height {expected_height} does not hash to the linked hash"
            ));
            }
            if blk.prev_hash != hashes[i - 1] {
                return Err(format!(
                "healing broken: block at height {expected_height} prev_hash mismatch: expected {}, got {}",
                hex::encode(hashes[i - 1]),
                hex::encode(blk.prev_hash)
            ));
            }
            rt.replay_historical_block(&blk)
                .await
                .map_err(|e| format!("healing refused at height {expected_height}: {e}"))?;
            rt.blocks.insert(*hash, blk.clone());
            applied = expected_height;
        }
        Ok(applied)
    }

    // Announce where we are before anyone asks. A node that restarts has not
    // finalized anything since, so without this its head is invisible to peers
    // and a lagging peer has no way to learn that we are ahead of it.
    if let Some((fh, fhash)) = rt.finalized.last().copied() {
        if let Some(ap) = &persistence {
            if let Ok(Some(blk)) = ap.storage().get_block(&fhash) {
                rt.blocks.insert(fhash, blk);
            }
        }
        adapter.publish_head(block_shard, fh, fhash).await;
    }

    // Catch up once at startup, then continuously inside the loop below. A
    // node that is behind when it starts must not begin proposing at its own
    // height before it has asked the network where the chain actually is.
    // Bounded with a timeout so a slow/hung initial DHT query does not block
    // the node from ever entering the consensus loop.
    let startup_budget = Duration::from_secs(20);
    if let Ok(Some(h)) = tokio::time::timeout(
        startup_budget,
        try_catch_up(&adapter, &mut rt, block_shard, persistence.as_ref(), &rpc),
    )
    .await
    {
        info!("[sync] caught up to height {h} before joining consensus");
    }

    // BFT-02: Restore vote history from persisted checkpoint to guarantee crash-resilience
    // and strictly forbid accidental self-equivocation across restarts.
    //
    // The write-ahead watermark is the AUTHORITATIVE record: it was fsynced
    // before the vote hit the wire, so it is exact even when the crash landed
    // between the vote and the next checkpoint (Finding C). It overrides the
    // coarser checkpoint-derived values for the current height.
    let mut last_prevoted: Option<(u64, u32)> =
        restored_checkpoint.as_ref().map(|cp| (cp.height, cp.round));
    let mut last_precommitted: Option<(u64, u32)> =
        restored_checkpoint.as_ref().map(|cp| (cp.height, cp.round));
    if let Some(wm) = &restored_watermark {
        if let Some(e) = wm.prevote_at(rt.hc.height) {
            last_prevoted = Some((e.height, e.round));
        }
        if let Some(e) = wm.precommit_at(rt.hc.height) {
            last_precommitted = Some((e.height, e.round));
        }
    }
    // Hard floor: never cast a vote at a round <= the highest round already
    // SIGNED at this height. Enforced at the cast sites below (the prevote
    // sites are inherently above it because `rt.hc.round` starts at the
    // floor; the precommit site follows a POLKA round, which may be older).
    let mut vote_floor: Option<(u64, u32)> = restored_watermark
        .as_ref()
        .and_then(|wm| wm.floor_round(rt.hc.height))
        .map(|r| (rt.hc.height, r));
    // PRECOMMIT has its OWN floor (Finding C stores the two kinds
    // independently). A late polka may be precommitted at ITS round even when
    // this node has already prevoted (nil) in a later round: that precommit is
    // a different statement — a different (height, round, kind) — so it cannot
    // equivocate any signed prevote. Reusing the union floor here refused
    // exactly the late-polka rescue (the node at round 11 could never
    // precommit the polka of round 0, so the height parked). The precommit
    // floor still refuses re-entering a round this node already precommitted
    // in, which is the double-sign the write-ahead watermark exists to stop.
    let mut precommit_floor: Option<(u64, u32)> = restored_watermark
        .as_ref()
        .and_then(|wm| wm.precommit_at(rt.hc.height))
        .map(|e| (e.height, e.round));
    // Throttle for the finalize-blocker diagnostic below: one line per round.
    let mut last_blockers_log: Option<(u64, u32)> = None;
    // Throttle for the propose-gate diagnostic: one line per round.
    let mut last_gate_diag: Option<(u64, u32)> = None;
    // Unparseable inbound payload counter (see the drain below).
    let mut parse_fail_count: u64 = 0;
    // Times the per-tick inbound cap deferred messages (see the drain).
    let mut inbound_overcap_count: u64 = 0;
    // Bulk Batch envelopes deferred by the inbound limiter (audit-network F1,
    // SEC-06): parked here with scheduled wake_at time, NEVER dropped.
    // Bounded (see `INBOUND_DEFERRED_CAP`): on overflow the oldest
    // is handled inline with a loud count instead of growing memory.
    let mut inbound_deferred: std::collections::VecDeque<(Instant, String)> =
        std::collections::VecDeque::new();
    // Bounded LOCAL loopback queue for resolved compact proposals (pentest-2
    // F-1/H5): drained with priority, never behind future-dated peer traffic,
    // and independent of `INBOUND_DEFERRED_CAP` so a compact flood can never
    // grow memory without bound. Each entry carries the source peer id.
    let mut loopback_queue: std::collections::VecDeque<String> = std::collections::VecDeque::new();
    let mut loopback_dropped: u64 = 0;
    // Per-(height, prev_hash) short-id index cache (C2/F-8): the mempool is
    // cloned and hashed at most once per salt per TTL, not once per frame.
    let mut compact_index = stellereum::consensus_net::CompactIndexCache::new();
    // Per-peer per-tick compact work budgets, cleared at each tick top.
    let mut compact_peer_frames: std::collections::HashMap<String, u32> =
        std::collections::HashMap::new();
    let mut compact_peer_pulls: std::collections::HashMap<String, u32> =
        std::collections::HashMap::new();
    let mut compact_budget_dropped: u64 = 0;
    let mut compact_full_requests: u64 = 0;
    // Whole-node index-build budget for the current tick (see policy).
    let mut compact_index_builds_tick: u32 = 0;
    // When the current verified `rt.peer_hint` was planted (expiry below).
    // A hint restored/persisted before the loop gets a fresh lease; runtime
    // code that raises it later is covered by the same 60 s expiry (the lease
    // simply ages from here, which is the conservative choice).
    let mut peer_hint_at: Option<Instant> = rt.peer_hint.map(|_| Instant::now());
    let mut peer_hint_seen: Option<(u64, [u8; 32])> = rt.peer_hint;
    // Times an over-budget Batch was deferred (limiter pacing, not loss).
    let mut inbound_defer_count: u64 = 0;
    // Compact gossip is ACTIVE from genesis. A frame that fails validation is
    // counted and dropped LOUDLY — never reinterpreted as a full proposal.
    let mut inbound_compact_refused: u64 = 0;
    // One long-lived receiver (parked resolutions bounded) and one body server
    // (announced blocks bounded) per node.
    let mut compact_rx = stellereum::consensus_net::CompactReceiver::new();
    let mut compact_server = stellereum::consensus_net::CompactBodyServer::new();
    // Resolved compact proposals re-enter the drain as FULL proposals; counted
    // so a silent loopback failure is visible instead of a stalled round.
    let mut compact_looped: u64 = 0;
    let mut compact_served: u64 = 0;
    // Liveness probe timer (see probe_peers).
    let mut last_probe = std::time::Instant::now() - Duration::from_secs(60);
    // Mempool persistence timer (see the periodic save below).
    let mut last_mempool_save = std::time::Instant::now();
    // Workchain validator-set repair timer (R3 CODE-TAILS sweep): the finalize
    // paths all refresh the set, but a wedged workchain finalizes nothing, so
    // without this its set never re-reads the masterchain registry. The repair
    // itself is workchain-gated inside
    // `ValidatorRuntime::refresh_workchain_set_from_master` (no-op elsewhere),
    // so this tick stays unconditional.
    let mut last_workchain_set_repair = std::time::Instant::now();

    // The votes we actually put on the wire for the current round, so they can
    // be re-sent if a peer never received them (pubsub delivery is best-effort).
    let mut cast_prevote: Option<stellereum::consensus::Vote> = None;
    let mut cast_precommit: Option<stellereum::consensus::Vote> = None;
    // P3-H4 gossip batching: outbound consensus messages queue here and flush
    // as one Batch per timer window (large messages flush immediately).
    let mut outbox: std::collections::VecDeque<ConsensusMsg> = std::collections::VecDeque::new();
    let mut last_flush = std::time::Instant::now();
    // Periodic retransmit timer (see the block in the loop): pubsub is
    // best-effort and a single lost prevote/precommit costs the whole round.
    let mut last_rexmit = std::time::Instant::now();
    let mut round_started = std::time::Instant::now();
    // Round timeout base is a FROZEN protocol constant, not operator policy:
    // the base feeds the same-on-all-nodes deterministic ladder
    // (`stellereum::consensus::deterministic_round_timeout_ms`, spec
    // 04_NETWORK_AND_CONSENSUS_PHASE2 §2), so heterogeneous bases would fork
    // the timeout schedule. Former `STELL_ROUND_TIMEOUT_MS` env knob removed
    // by the protocol freeze 2026-11-03 (value = pre-freeze code default).
    let round_timeout = Duration::from_millis(stellereum::consensus::FROZEN_ROUND_TIMEOUT_BASE_MS);
    // Per-round backoff (audit 2026-10-06): a FIXED timeout on a persistently
    // slow network spins at constant cadence forever instead of converging
    // (Tendermint grows timeout with the round). The effective timeout for
    // round r is base + r * BACKOFF, capped — early rounds stay fast, wedged
    // rounds eventually allow even p99-slow votes to arrive and form a QC.
    let tick_ms = std::env::var("STELL_TICK_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(TICK_MS)
        .clamp(20, 1000);
    // Floor on how often a node may produce a block. `STELL_MIN_BLOCK_MS=0`
    // disables the guard (useful for the in-process simulator and benchmarks).
    let min_block_time = Duration::from_millis(
        std::env::var("STELL_MIN_BLOCK_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_MIN_BLOCK_MS),
    );
    let mut last_block_at = std::time::Instant::now() - min_block_time;
    let mut last_join = std::time::Instant::now() - Duration::from_secs(60);
    // Highest round at which a peer has been seen voting at OUR height, and when.
    //
    // This is the liveness rule that makes an even-sized validator set converge. Two
    // nodes time out independently, so they drift into opposite round PARITIES, and
    // `proposer_for` alternates by parity: each then expects the other to propose and
    // both reject every proposal as "wrong proposer" forever. Letting the AHEAD node
    // see that its peer is still active one round behind and WAIT stops the drift,
    // while the behind node still jumps forward on the ahead node's votes. Between the
    // two the rounds meet instead of chasing.
    let mut peer_round_seen: Option<(u64, u32, std::time::Instant)> = None;
    // Align snapshots to round hundreds so probes ((peer_height/100)*100) hit them.
    let mut last_snapshot_height: u64 = (rt.hc.height / 100) * 100;
    // Previous finalized height's worker-certified post-apply root, for the
    // adaptive snapshot cadence gate (`stellereum::snapshot_cadence`): a
    // candidate height whose certified root equals this one provably brought
    // no state change and may be skipped while the interval floor is not due.
    // `None` until the first finalize lands, so the gate starts conservative
    // (assumes changed) rather than assuming idleness.
    let mut prev_finalized_root: Option<[u8; 32]> = None;
    // Cross-shard replay bytes bound to the SUBMITTED snapshot height (see the
    // snapshot block below): captured at submit quiescence (post-`height`,
    // worker idle, before the next apply is submitted) and consumed verbatim
    // at poll. Single-flight (at most one submit outstanding), so one slot is
    // enough: every successful submit overwrites it before its poll reads it.
    let mut pending_snapshot_xshard: Option<(u64, Vec<u8>)> = None;
    // Highest height whose body is already on the DHT. A cursor, not a correctness
    // requirement: publishing is idempotent and content-addressed.
    let mut retro_published_upto: u64 = 0;
    let mut last_retro_publish: std::time::Instant = std::time::Instant::now();
    // How often to ask the network whether we are behind. This is now the
    // BACKSTOP only (default 30 s, was 2 s): the primary path is REACTIVE —
    // a verified peer message / head pointer naming a height above ours
    // schedules the attempt on the next tick. See `catchup_action` in policy.
    let catchup_interval = catchup_interval();
    let retro_publish_interval = retro_publish_interval();
    let mut last_catchup: std::time::Instant = std::time::Instant::now() - catchup_interval;
    // Reactive catch-up latch: set by the drain when a VERIFIED peer message
    // (Committed / Proposal / Vote) names a height above ours. Consumed at the
    // next tick top, so a lagging peer reacts to the push instead of waiting
    // out `catchup_interval`. Survives ticks where the attempt could not run
    // (apply in flight, live-adopt deferral) by being re-armed below.
    let mut catchup_pending = false;
    // Tallest height that VERIFIED peer traffic proves FINALIZED (a commit's
    // height, or a proposal/vote height minus one — a peer building/voting at
    // H has decided H-1). Together with `rt.peer_hint` it answers "is any peer
    // known to be ahead?" — the at-tip test that keeps an in-sync node from
    // polling the DHT on the backstop timer. Compared against our tip, so it
    // self-heals as we advance; never reset by hand.
    let mut peer_named_height: u64 = rt.finalized.last().map(|(h, _)| *h).unwrap_or(0);
    // Backstop ticks skipped because we were at the tip (visibility only).
    let mut catchup_at_tip_skips: u64 = 0;
    // Freshness of the LIVE adopt flow: stamped on every successful parent-match
    // `adopt_committed` in the drain below. Starts stale so the first intervals
    // behave exactly as before until live flow proves itself. Compared against
    // `LIVE_ADOPT_FRESH_MS` (2 s — deliberately NOT the 30 s backstop interval):
    // at chain tempo the next Committed lands well within it, so a fresh stamp
    // means "the DHT machine has nothing to add".
    let live_adopt_fresh_window = std::time::Duration::from_millis(LIVE_ADOPT_FRESH_MS);
    let mut last_live_adopt: std::time::Instant =
        std::time::Instant::now() - live_adopt_fresh_window;
    // Dead-peer retro-spin gate (local, zero new APIs): the last wall-clock
    // instant ANY parseable consensus message (vote/proposal/commit/batch)
    // arrived, plus the finalized tip as of the last retro pass. While the tip
    // hasn't advanced AND nothing inbound arrived for RETRO_SUPPRESS_IDLE_SECS,
    // retro-publish is suppressed (a returning peer announces itself via
    // votes/proposals first, restamping the clock, and retro resumes).
    // Starts fresh so the first intervals behave exactly as before.
    let mut last_inbound_msg: std::time::Instant = std::time::Instant::now();
    let mut retro_tip_at_last_pass: u64 = rt.finalized.last().map(|(h, _)| *h).unwrap_or(0);
    // Consensus-traffic RX clock for the fail-loud liveness alarm (audit
    // note: an isolated validator churned silently for 18 days on the wrong
    // pubsub topic). Stamped on EVERY consumed Proposal/Vote inner — accepted
    // or refused — because receipt alone proves the transport delivers this
    // node's topic. Starts fresh like `last_inbound_msg` above.
    let mut last_consensus_rx_ms: u64 = liveness_alarm::now_ms();
    // Throttle for the liveness alarm line: at most one per
    // LIVENESS_ALARM_THROTTLE_MS (None = never emitted, always due).
    let mut last_liveness_emit_ms: Option<u64> = None;
    // Behind-and-talking peer clock (behind-peer retro gate, local policy):
    // stamped when a VERIFIED vote/proposal arrives from a peer at a height
    // BELOW ours (accepted votes/proposals, plus verified-but-out-of-scope
    // votes — both prove the voter is alive AND behind, i.e. the only peer a
    // retro push can serve). Starts `None` so the first window suppresses
    // until such a peer proves itself; deep gaps use peer-initiated
    // snapshot-sync (unaffected by this gate), never retro.
    let mut last_behind_peer_seen: Option<std::time::Instant> = None;
    // Voters whose SIGNATURE-VERIFIED vote we observed at the current height
    // (accepted votes AND verified-but-out-of-scope votes — both prove the
    // voter is alive right now). Scoped to one height: cleared whenever the
    // height advances. Feeds the down-proposer fast-timeout predicate only.
    // Forged votes never land here (unverified), so an attacker cannot fake a
    // down proposer alive — worst case the fast timeout simply doesn't fire.
    let mut votes_seen_height: u64 = rt.hc.height;
    let mut votes_seen_voters: std::collections::HashSet<[u8; 32]> =
        std::collections::HashSet::new();
    // Last (height, round) the down-proposer fast timeout was loudly logged
    // for: the timeout itself fires every tick while stuck, the LOUD line must
    // fire once per round.
    let mut last_fast_timeout_logged: Option<(u64, u32)> = None;

    // Retention. Archive is the default because dropping a block body is
    // irreversible and removes the ability to re-execute that block later.
    // Opt in explicitly: `STELL_ARCHIVE=0` plus `STELL_KEEP_BLOCKS=<n>`.
    // Single source of truth (`RetentionConfig::from_env`): the RPC
    // archive-proof errors and this loop must never disagree on the mode.
    let retention = stellereum::storage::RetentionConfig::from_env();
    let (archive, keep_blocks) = (retention.archive, retention.keep_blocks);
    if archive {
        info!("[storage] archive mode: keeping every block body");
    } else {
        info!("[storage] pruning mode: block bodies older than {keep_blocks} blocks will be dropped, header records retained");
    }

    info!(
        "[consensus] loop started at height {} (proposer={})",
        rt.hc.height,
        rt.is_proposer()
    );
    info!(
        "[consensus] validator set: {}",
        rt.validators
            .validators
            .iter()
            .map(|(k, p)| format!("{}:{}", hex::encode(&k[..4]), p))
            .collect::<Vec<_>>()
            .join(",")
    );

    // Governance-write mode (visibility only; enforcement lives in the
    // propose/vote entry paths): a solo validator set allows local writes
    // (no peer to diverge from); a multi-node set refuses them unless the
    // documented escape env is armed (default OFF).
    {
        let gov_validators = rt.validators.len();
        let gov_escape = stellereum::governance::governance_multinode_escape_enabled();
        let gov_mode =
            match stellereum::governance::governance_write_allowed(gov_validators, gov_escape) {
                Ok(()) if gov_validators <= 1 => format!(
                    "ALLOWED (solo validator set size = {gov_validators}; no peer to diverge from)"
                ),
                Ok(()) => format!(
                    "ALLOWED via {}=1 (multi-node validator set size = {gov_validators}; \
                     local-only writes WILL diverge the state root — escape explicitly armed)",
                    stellereum::governance::GOV_MULTINODE_WRITES_ENV
                ),
                Err(e) => format!("REFUSED ({e})"),
            };
        info!("[gov] governance writes: {gov_mode}");
    }

    // §7 Phase 1: the two background lanes the tick submits to instead of
    // awaiting inline, plus the single-flight guards for the periodic blocking
    // jobs. Per node instance (this function runs once per shard), so one
    // shard's guard can never suppress another shard's save or prune.
    //
    //  * `publish_lane` carries every blob/DHT write the loop makes -- head
    //    pointer (finalize AND probe, so the advertised head can only move
    //    forward), retro body, header, snapshot -- in submission order.
    //  * `record_lane` carries the local RPC records (receipts + height).
    //  * `prune_lane` carries the DHT retention prune. It used to ride
    //    `record_lane`, but a prune pass fans out to `fetch_blob` + deletes
    //    over up to 2048 heights (seconds on a weak link), and the single FIFO
    //    held every receipt behind it — the record_lane clog. Prune work is
    //    local housekeeping, order-independent against receipts, so its own
    //    lane restores "record_lane carries only fast local work".
    // Three lanes, not one: `store_blob` can wait for a replica for seconds, and
    // a wallet's receipt lookup must never queue behind that, while a publish
    // must never queue behind a contended RPC lock either.
    let publish_lane = spawn_tick_lane();
    let record_lane = spawn_tick_lane();
    let prune_lane = spawn_tick_lane();
    let mempool_save_guard = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let prune_guard = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // Guard for the prune_lane retention-prune submits (see the finalize
    // block): at most one prune pass queued/running at a time.
    let prune_lane_guard = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // Independent cadence for sled retention (see the finalize block): it must
    // not starve with snapshots when the apply worker is continuously busy.
    let mut last_prune_height: u64 = 0;
    // A14 phase 3: one-shot mempool drain at the activation crossing (see the
    // gossip-ingress section). Set on the first tick at/after activation;
    // pre-activation ticks leave it false.
    let mut chain_binding_drained = false;

    // Push what we already have before waiting for anything from a peer.
    retro_publish_pass(
        adapter.clone(),
        &rt,
        persistence.as_ref(),
        &mut retro_published_upto,
        None,
    )
    .await;

    let mut _tick_no: u64 = 0;
    // Tick-split attribution (packing-perf visibility only, no behavior
    // change): cheap per-phase timing counters so slow ticks can be
    // attributed to catchup / retro-publish / probe / join instead of guessed
    // at. Deliberately NOT a log per tick (that would be ~10 lines/s of
    // noise): raw `Instant` deltas accumulate here and are reported as a
    // windowed average (see the `tick-split` report next to the slow-tick
    // line at the bottom of the loop).
    //
    // HOW TO READ: `[perf][tick-split] ticks=200 tick_avg=Xms catchup_avg=Yms
    // (n=Z) retro_avg=... probe_avg=... join_avg=...` — each `_avg` is the
    // mean per-TICK cost of that phase over the window (ticks where the phase
    // did not run contribute 0), and `n=` is how many ticks in the window
    // actually ran it. A phase with a high avg but n=1 fired once (a slow
    // fetch, not a trend); a phase with avg near the tick budget on most
    // ticks is the binding cost. `tick_avg` should stay well under TICK_MS
    // on an idle chain; when `tick_avg` approaches the round timeout, rounds
    // — not packing — are what is slow.
    let mut split_ticks: u64 = 0;
    let mut split_tick_ms: u64 = 0;
    let mut split_catchup_ms: u64 = 0;
    let mut split_retro_ms: u64 = 0;
    let mut split_probe_ms: u64 = 0;
    let mut split_join_ms: u64 = 0;
    let mut split_catchup_n: u64 = 0;
    let mut split_retro_n: u64 = 0;
    let mut split_probe_n: u64 = 0;
    let mut split_join_n: u64 = 0;
    loop {
        _tick_no += 1;
        // Per-peer compact-work budgets are per TICK (C2/F-8/H1): a peer can
        // force at most a bounded number of index lookups/pull replies each
        // tick, no matter how many envelopes its bucket admits.
        compact_peer_frames.clear();
        compact_peer_pulls.clear();
        compact_index_builds_tick = 0;
        let tick_t0 = std::time::Instant::now();
        let (mut catchup_ran, mut retro_ran, mut probe_ran, mut join_ran) =
            (false, false, false, false);
        let mut outbox_flushes: u32 = 0;
        // One settle path for a compact resolution (proposal AND body): every
        // outcome is handled identically, so the two receive arms cannot drift.
        // `$src` is the peer id that produced the compact frame (attribution).
        macro_rules! settle_compact {
            ($inbound:expr, $src:expr) => {{
                match $inbound {
                    stellereum::consensus_net::CompactInbound::Ready { round, block } => {
                        // Re-enter the SAME drain as a full proposal: attribution,
                        // H+1 deferral, hints, `on_proposal` and the vote all run
                        // once, in the one place they are already correct.
                        match encode_full_proposal_loopback(&block, round, $src) {
                            Some(raw) => {
                                // Bounded + priority-drained (F-1/H5): on overflow
                                // the oldest loopback goes (counted loudly), never
                                // unbounded memory.
                                if push_bounded_loopback(
                                    &mut loopback_queue,
                                    raw,
                                    LOOPBACK_QUEUE_CAP,
                                ) {
                                    loopback_dropped += 1;
                                    if loopback_dropped == 1 || loopback_dropped.is_multiple_of(50) {
                                        tracing::warn!(
                                            "[consensus] compact loopback queue full ({} entries); dropped the oldest resolved proposal ({loopback_dropped} dropped)",
                                            LOOPBACK_QUEUE_CAP
                                        );
                                    }
                                }
                                compact_looped += 1;
                                if compact_looped == 1 {
                                    info!(
                                        "[consensus] compact gossip LIVE: first proposal resolved from the local mempool and re-entered the drain as a full proposal"
                                    );
                                }
                            }
                            None => tracing::warn!(
                                "[consensus] compact gossip: resolved block #{} r{} could not be re-encoded for loopback",
                                block.height,
                                round,
                            ),
                        }
                    }
                    stellereum::consensus_net::CompactInbound::Pull(pull) => {
                        // H1: a pull is consensus traffic to EVERY peer. Cap the
                        // number one peer can force per tick, and never let a
                        // pull-born flood share the ordered vote/proposal queue
                        // without bound.
                        let budget = compact_peer_pulls
                            .entry($src.to_string())
                            .or_insert(0);
                        if compact_frame_within_peer_budget(
                            budget,
                            COMPACT_PULLS_PER_PEER_PER_TICK,
                        ) {
                            enqueue_outbox(&mut outbox, ConsensusMsg::BodyPull { pull });
                            flush_outbox(&net_sender, &mut outbox, rt.hc.height, rt.hc.round);
                            outbox_flushes += 1;
                            last_flush = std::time::Instant::now();
                        } else {
                            compact_budget_dropped += 1;
                        }
                    }
                    stellereum::consensus_net::CompactInbound::FetchFull {
                        height,
                        round,
                        block_hash,
                        reason,
                    } => {
                        // NEVER prevote a partial body. An UNRESOLVABLE compact
                        // announcement is not evidence: neither the block nor
                        // its proposer signature was ever checked, so this arm
                        // must not plant `peer_hint`/`peer_named_height` or
                        // re-arm catch-up (pentest-2 F-2/C1). It only asks the
                        // proposer for the full body through the existing
                        // pull frame; the normal Proposal arm authenticates it
                        // and only THEN may evidence be recorded.
                        tracing::warn!(
                            "[consensus] compact gossip fell back to the full proposal #{} r{} ({reason:?})",
                            height,
                            round,
                        );
                        compact_full_requests += 1;
                        if compact_full_requests == 1 {
                            info!(
                                "[consensus] compact gossip LIVE: first full-proposal fallback requested (the unresolved announcement is not treated as evidence)"
                            );
                        }
                        if full_proposal_request_is_relevant(
                            rt.hc.height,
                            height,
                        ) {
                            let pull = stellereum::consensus_net::compact_prop::BodyPull::full_request(
                                height, round, block_hash,
                            );
                            enqueue_outbox(
                                &mut outbox,
                                ConsensusMsg::BodyPull { pull },
                            );
                            flush_outbox(&net_sender, &mut outbox, rt.hc.height, rt.hc.round);
                            outbox_flushes += 1;
                            last_flush = std::time::Instant::now();
                        } else {
                            tracing::debug!(
                                "[sync] compact full-proposal request at #{height} ignored (local hc #{}, outside the live window); catch-up owns far-ahead announcements",
                                rt.hc.height
                            );
                        }
                    }
                    stellereum::consensus_net::CompactInbound::Refused(why) => {
                        inbound_compact_refused += 1;
                        if inbound_compact_refused % 20 == 1 {
                            tracing::warn!(
                                "[consensus] refused compact frame ({inbound_compact_refused} refused): {why}"
                            );
                        }
                    }
                }
            }};
        }
        // Per-section milliseconds for THIS tick (profiling only, no behavior
        // change): stamped next to each section and wired into the `[perf]
        // tick` line below, so a slow tick names its binding cost inline
        // instead of needing the windowed `tick-split` average to guess it.
        // (The `split_*` accumulators above still feed that windowed report.)
        let mut catchup_ms: u64 = 0;
        let mut retro_ms: u64 = 0;
        let probe_ms: u64 = 0;
        let join_ms: u64 = 0;
        // Height-scoped vote sightings reset (down-proposer fast timeout): a
        // new height means a new proposer schedule, so last height's
        // sightings must not leak into this height's "no vote observed" test.
        if rt.hc.height != votes_seen_height {
            votes_seen_height = rt.hc.height;
            votes_seen_voters.clear();
        }
        // Reactive evidence latched by the previous tick's drain: a VERIFIED
        // Committed/Proposal/Vote named a height above ours, or a peer head
        // pointer did. Consumed here so the attempt runs on THIS tick — never
        // waiting out the backstop interval.
        let reactive_catchup_due = std::mem::take(&mut catchup_pending);
        let height = rt.hc.height;
        let round = rt.hc.round;

        // Continuous catch-up. If a peer is ahead, replay the gap and re-anchor
        // before doing anything else this tick. Without this a node that fell a
        // single block behind could never rejoin: both nodes would sit in view
        // changes at their own heights, each rejecting the other's proposal as
        // `wrong height`, and the network would stay wedged until an operator
        // wiped both data directories. Throttled so a normal node does not ask
        // the DHT on every single tick.
        // Bound every periodic network call to half a round: this loop IS
        // consensus, and an unbounded DHT/body fetch inside it stalls round
        // timers too (measured: rounds took ~8s with an 800ms timeout because
        // the tick blocked on network I/O). A slow fetch is skipped and
        // retried next interval -- liveness beats freshness here.
        // Catch-up does DHT head+body walks (seconds on a slow net); the old
        // timeout/2 budget (~400ms live) always expired first, so a
        // 1-block-behind node never healed (audit 2026-10-06).
        let near_tip_net_ms = (round_timeout.as_millis() as u64 * 2).max(5_000);
        // Snapshot territory needs minutes, not seconds: a far-behind node
        // (gap > 100) fetching state+domains+anchor over a weak link can never
        // fit in 5s, so every attempt died at the budget with zero progress and
        // retried forever. While far behind, this node validates nothing
        // anyway (its height is useless to the network), so a long tick costs
        // nothing and is the only way to converge. Near-tip nodes keep the
        // tight budget (fast rounds matter there).
        //
        // The gap is the TALLEST verified evidence we hold: a peer head hint
        // (a QC-backed commit) and the at-tip evidence a verified vote or
        // proposal names. Using only the hint left a node rescued by vote
        // evidence on the at-tip/5 s path even when it was known to be behind.
        let our_tip_for_budget = rt.finalized.last().map(|(h, _)| *h).unwrap_or(0);
        let hint_gap_for_budget = rt
            .peer_hint
            .map(|(ph, _)| ph.saturating_sub(our_tip_for_budget))
            .unwrap_or(0);
        let budget_gap =
            hint_gap_for_budget.max(peer_named_height.saturating_sub(our_tip_for_budget));
        let net_budget = Duration::from_millis(catchup_pass_budget_ms(near_tip_net_ms, budget_gap));
        // §7 Phase 2: catch-up replays whole blocks through `apply_and_advance`.
        // While a decided block is still executing on the sequenced worker the
        // engine is mid-transition (PRE-H reads would misvalidate the walk),
        // so the walk waits a tick. Skipping only delays healing by one tick:
        // the head pointer and peer hints are re-read next tick, after the
        // worker reports back.
        //
        // LIVE-ADOPT FAST PATH (observer C, 2026-10-13): a Committed broadcast
        // carries the full block + QC — no DHT fetch needed. When live traffic
        // is queued AND the hint gap is live-sized, the drain below adopts it
        // at message cost; running the catch-up machine first holds the tick
        // on DHT fetches (2.5s+ each on a weak link) while adoptable blocks
        // wait in the channel. Defer catch-up one tick so live adopt runs
        // first. Far-behind nodes (gap > threshold) still run catch-up: tip
        // commits are for heights they cannot adopt yet.
        //
        // Remainder fix: the queue sample alone (`!rx.is_empty()`) misses
        // Committed messages still in transit — at 1 block/s most tick tops
        // see an empty inbox, so the DHT machine fired every interval for
        // heights the next Committed delivers free (the ~30s/block queueing
        // tail). A fresh live adopt (within one catch-up interval) proves the
        // flow is delivering and defers on its own.
        let defer_for_live = {
            let our_tip = rt.finalized.last().map(|(h, _)| *h).unwrap_or(0);
            let hint_gap = rt
                .peer_hint
                .map(|(ph, _)| ph.saturating_sub(our_tip))
                .unwrap_or(0);
            let live_adopt_fresh = last_live_adopt.elapsed() < live_adopt_fresh_window;
            // Never defer catchup if we have stalled into round > 0 or haven't adopted
            // recently. Deferring during a round stall causes a permanent deadlock where
            // peers wait for our vote at H+1 while we defer catchup of H because of peer traffic.
            if rt.hc.round > 0 || !live_adopt_fresh {
                false
            } else {
                stellereum::sync::should_defer_catchup_for_live_flow(
                    hint_gap,
                    !rx.is_empty(),
                    live_adopt_fresh,
                )
            }
        };
        // Event-driven decision (`policy::catchup_action`): reactive evidence
        // runs NOW; the periodic timer is only a backstop. At-tip nodes skip
        // the EXPENSIVE walk, but still run one cheap blind head/tip+1 probe
        // per `AT_TIP_PROBE_INTERVAL_MS` — silence is not equality (F-3/R8).
        let our_tip_now = rt.finalized.last().map(|(h, _)| *h).unwrap_or(0);
        // Expire/downgrade a stale peer hint BEFORE it can suppress the DHT
        // head read (F-2/C1). Only verified sources write `rt.peer_hint`, but
        // even a verified hint must not pin catch-up forever after a failed
        // walk or once our tip reaches it. The runtime can also plant one
        // inside `on_proposal`; detect the change so it gets a fresh lease.
        if rt.peer_hint != peer_hint_seen {
            peer_hint_seen = rt.peer_hint;
            peer_hint_at = rt.peer_hint.map(|_| Instant::now());
        }
        if let Some(hint) = rt.peer_hint {
            let age_ms = peer_hint_at
                .map(|t| t.elapsed().as_millis() as u64)
                .unwrap_or(u64::MAX);
            if peer_hint_effective(our_tip_now, Some(hint), age_ms).is_none() {
                tracing::debug!(
                    "[sync] dropping stale/reached peer hint #{:?} (ours=#{our_tip_now}, age={age_ms}ms)",
                    hint.0
                );
                rt.peer_hint = None;
                peer_hint_at = None;
                peer_hint_seen = None;
            }
        }
        let at_tip = node_is_at_tip(our_tip_now, peer_named_height, rt.peer_hint.map(|(h, _)| h));
        let catchup_decision = catchup_action(
            reactive_catchup_due,
            last_catchup.elapsed().as_millis() as u64,
            catchup_interval.as_millis() as u64,
            at_tip,
        );
        if catchup_decision == CatchupAction::SkipAtTip {
            // At the tip: skip the expensive DHT/body walk, but do NOT reset
            // `last_catchup` — the elapsed clock is what reaches the low-
            // frequency blind-probe window below. The next reactive message
            // still re-arms catch-up immediately.
            catchup_at_tip_skips += 1;
            if catchup_at_tip_skips.is_multiple_of(20) {
                tracing::debug!(
                    "[sync] backstop catch-up skipped at the tip #{our_tip_now} \
                     ({catchup_at_tip_skips} skips): no peer known to be ahead, \
                     blind probe due in {}ms",
                    AT_TIP_PROBE_INTERVAL_MS
                        .saturating_sub(last_catchup.elapsed().as_millis() as u64)
                );
            }
        }
        let catchup_due = matches!(
            catchup_decision,
            CatchupAction::Run | CatchupAction::BlindProbe
        );
        if catchup_due && !rt.has_pending_apply() && !defer_for_live {
            catchup_ran = true;
            last_catchup = std::time::Instant::now();
            let split_catchup_t0 = std::time::Instant::now();
            // The pass must be able to clear a whole live-sized burst (or, far
            // behind, fetch/snapshot at all): the configured value is the
            // at-tip floor, the gap scales it. A flat 250 ms admitted ~one
            // WAN round trip, while the chain now produces a block every
            // ~240 ms — a behind node retried forever without ever closing the
            // gap (and snapshot-sync could never fit at all).
            let catchup_budget = Duration::from_millis(catchup_pass_budget_ms(
                catchup_budget().as_millis() as u64,
                budget_gap,
            ));
            let caught = tokio::time::timeout(
                catchup_budget,
                try_catch_up(&adapter, &mut rt, block_shard, persistence.as_ref(), &rpc),
            )
            .await
            .unwrap_or_else(|_| {
                // A budget exhaustion is otherwise invisible (the inner future
                // is dropped mid-flight, so none of its own logs fire): a dead
                // transport looks exactly like "in sync". Throttled: this fires
                // every interval while peers are unreachable.
                static CATCHUP_TIMEOUT_N: std::sync::atomic::AtomicU64 =
                    std::sync::atomic::AtomicU64::new(0);
                let n = CATCHUP_TIMEOUT_N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if n.is_multiple_of(12) {
                    eprintln!(
                        "[sync] catch-up skipped (network budget of {}ms exhausted, {n} times; \
                         peers unreachable or DHT too slow)",
                        catchup_budget.as_millis()
                    );
                } else {
                    tracing::debug!("[sync] catch-up skipped (network budget exhausted)");
                }
                None
            });
            if let Some(peer_h) = caught {
                info!(
                    "[sync] caught up to height {peer_h} while running (was {height}); resumed consensus at {}",
                    rt.hc.height
                );
                // Fresh height: reset the per-round bookkeeping too, or the
                // first proposal on the new height would reuse the old timer
                // and the previous height's votes.
                last_prevoted = None;
                last_precommitted = None;
                cast_prevote = None;
                cast_precommit = None;
                round_started = std::time::Instant::now();
                last_block_at = std::time::Instant::now() - min_block_time;
                // Announce the new height immediately: this tick `continue`s
                // below, skipping the normal prevote section — without a vote
                // here, a catching-up node advances SILENTLY and tip nodes
                // never stamp it as behind-and-talking, so retro help never
                // flows (observed live: C grinding catchup with zero votes
                // while A/B suppressed retro for "no behind peer"). A nil
                // vote at the fresh height breaks the silence; it finalizes
                // nothing and is rate-limited by catchup_interval. Fresh
                // height + no proposal yet => the vote is nil by construction.
                // (`can_vote` is computed later at the propose gate; inline it
                // here — same franchise, same tick.)
                if rt.effective_can_vote(is_validator)
                    && !rt.hc.has_live_proposal()
                    && !round_at_or_below_vote_floor(vote_floor, rt.hc.height, rt.hc.round)
                {
                    if let Some(v) = rt.make_prevote() {
                        debug_assert!(
                            v.block_hash.is_none(),
                            "fresh catchup height has no proposal yet"
                        );
                        // WRITE-AHEAD before the vote can be enqueued.
                        persist_vote_watermark_before_broadcast(persistence.as_ref(), &v);
                        advance_vote_floor(&mut vote_floor, v.height, v.round);
                        let _ = rt.on_prevote(v.clone());
                        enqueue_outbox(
                            &mut outbox,
                            ConsensusMsg::Vote {
                                vote: v.clone(),
                                locked: lock_hint(&rt, &v),
                            },
                        );
                        cast_prevote = Some(v);
                        last_prevoted = Some((rt.hc.height, rt.hc.round));
                        tracing::debug!(
                            "[consensus] prevoted nil at fresh catchup height #{} r{}",
                            rt.hc.height,
                            rt.hc.round
                        );
                    }
                }
                // PERSISTENT EVIDENCE ACROSS A SUCCESSFUL PASS: this tick
                // `continue`s, so the end-of-tick latch re-arm never runs. A
                // pass can stop SHORT of the peer's head (snapshot-sync lands
                // on a boundary and hands the rest to the body walk); the
                // verified evidence that scheduled it is then still ahead.
                // Re-arm here so the next reactive tick continues the walk on
                // the 500 ms floor instead of dropping to the 30 s backstop.
                {
                    let tip = rt.finalized.last().map(|(h, _)| *h).unwrap_or(0);
                    if catchup_still_behind(tip, rt.peer_hint, peer_named_height) {
                        catchup_pending = true;
                    }
                }
                split_catchup_ms += split_catchup_t0.elapsed().as_millis() as u64;
                split_catchup_n += 1;
                split_ticks += 1;
                split_tick_ms += tick_t0.elapsed().as_millis() as u64;
                continue;
            }
            catchup_ms = split_catchup_t0.elapsed().as_millis() as u64;
            split_catchup_ms += catchup_ms;
            split_catchup_n += 1;
        } else if reactive_catchup_due {
            // A verified peer told us it is ahead, but the attempt could not
            // run this tick (apply in flight / live adopt deferral). KEEP the
            // event latched so the next tick retries — dropping it would put
            // the node back on the 30 s backstop.
            catchup_pending = true;
        }

        // Periodically push our own history so a peer behind us has something to
        // fetch. Bounded, and deliberately publishing bodies only.
        //
        // Storm guard 2026-10-13: a node far behind the network (e.g. C at
        // 72415 vs tip 74200) must NOT push its stale window. Its 128-body
        // pass + 8-body tip supplement spawn ~136 background replicators that
        // flood the tip's 256 stream slots while competing with its own
        // catch-up fetches for the same slots (fetch-vs-push self-excitation).
        // Skipping pushes while behind prioritizes consensus (fetch) over
        // replication (push); in-sync nodes are unaffected.
        if last_retro_publish.elapsed() >= retro_publish_interval {
            let our_tip = rt.finalized.last().map(|(h, _)| *h).unwrap_or(0);
            let peer_tip = rt.peer_hint.map(|(h, _)| h).unwrap_or(our_tip);
            // Hoisted behind-peer predicate (clippy::blocks_in_conditions): pure, no side effects.
            let behind_suppress = {
                let we_are_behind = peer_tip > our_tip
                    && peer_tip - our_tip > stellereum::sync::RETRO_SKIP_BEHIND_GAP;
                let behind_window = retro_behind_window_secs();
                let behind_idle = last_behind_peer_seen.map(|t| t.elapsed().as_secs());
                should_suppress_retro_no_behind_peer(behind_idle, behind_window, we_are_behind)
            };
            if stellereum::sync::should_skip_retro_while_behind(our_tip, peer_tip) {
                last_retro_publish = std::time::Instant::now();
                tracing::debug!(
                    "[retro-publish] skipping stale push while behind (ours={our_tip} peer={peer_tip})"
                );
            } else if should_suppress_retro_publish(
                our_tip,
                retro_tip_at_last_pass,
                last_inbound_msg.elapsed().as_secs(),
            ) {
                // Dead-peer spin gate (local policy, see the declaration
                // above): finalized tip hasn't advanced since the last pass
                // AND no consensus message arrived for 60s+ — the pass would
                // re-push the same Committed-block window at a peer that never
                // ACKs (nothing ever can: nobody is there). Suppressed LOUDLY
                // so "retro went quiet" is distinguishable from "retro is
                // broken". A returning peer's first vote/proposal restamps
                // `last_inbound_msg` and the next pass runs; a new
                // finalization advances `our_tip` and the next pass runs.
                last_retro_publish = std::time::Instant::now();
                let n = RETRO_SUPPRESSED_N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                eprintln!(
                    "[retro-publish] SUPPRESSED dead-peer pass #{n} (tip={our_tip} unchanged since last pass, inbound idle {}s >= {RETRO_SUPPRESS_IDLE_SECS}s; resumes on new finalization or first inbound vote/proposal)",
                    last_inbound_msg.elapsed().as_secs()
                );
                tracing::debug!(
                    "[retro-publish] suppressed dead-peer pass #{n} (tip={our_tip} idle={}s)",
                    last_inbound_msg.elapsed().as_secs()
                );
            } else if behind_suppress {
                last_retro_publish = std::time::Instant::now();
                let n = RETRO_BEHIND_SUPPRESSED_N
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    + 1;
                let behind_window = retro_behind_window_secs();
                let idle_txt = last_behind_peer_seen
                    .map(|t| format!("{}s", t.elapsed().as_secs()))
                    .unwrap_or_else(|| "never".to_string());
                eprintln!(
                    "[retro-publish] SUPPRESSED no-behind-peer pass #{n} (tip={our_tip}, no verified vote/proposal from a behind peer in last {behind_window}s (idle={idle_txt}); retro serves small gaps, deep gaps use snapshot-sync; resumes on first behind vote/proposal)"
                );
                tracing::debug!(
                    "[retro-publish] suppressed no-behind-peer pass #{n} (tip={our_tip} behind_idle={idle_txt})"
                );
            } else {
                retro_ran = true;
                let split_retro_t0 = std::time::Instant::now();
                last_retro_publish = std::time::Instant::now();
                retro_tip_at_last_pass = our_tip;
                let _ = tokio::time::timeout(
                    net_budget,
                    retro_publish_pass(
                        adapter.clone(),
                        &rt,
                        persistence.as_ref(),
                        &mut retro_published_upto,
                        Some(&publish_lane),
                    ),
                )
                .await;
                // Tip-first supplement: the backfill cursor above works bottom-up
                // and reaches a fresh tip last, but a recovering peer almost always
                // needs exactly the tip. Publish it every pass (one body, memory
                // first) so a restart never strands a peer for a whole window.
                // Publish the last few, not just the tip: a 1-8 block lag needs
                // middle children the tip-only publish would miss for hours.
                // OFF-TICK (observer C): `store_blob` waits on replicas — awaited
                // here it held the consensus tick for seconds every 30s pass. Same
                // bytes, same order, but on `publish_lane` behind the window above.
                {
                    let recent: Vec<_> = rt.finalized.iter().rev().take(8).copied().collect();
                    let mut bodies = Vec::with_capacity(recent.len());
                    for (_, thash) in recent {
                        if let Some(body) = rt.blocks.get(&thash).cloned().or_else(|| {
                            persistence
                                .as_ref()
                                .and_then(|ap| ap.storage().get_block(&thash).ok().flatten())
                        }) {
                            bodies.push(body);
                        }
                    }
                    if !bodies.is_empty() {
                        let a = adapter.clone();
                        publish_lane.submit(async move {
                            let _ = a.retro_publish_blocks(bodies.iter(), bodies.len()).await;
                        });
                    }
                }
                split_retro_ms += split_retro_t0.elapsed().as_millis() as u64;
                retro_ms = split_retro_t0.elapsed().as_millis() as u64;
                split_retro_n += 1;
            }
        }

        // Sync the shared staking ledger + governance into the runtime before
        // each iteration, so RPC-driven changes (bonds, votes, proposals) take
        // effect. The staking ledger is NOT copied here: it lives in the state
        // engine and is shared by reference, so a bond applied in a block is
        // visible to consensus without a node-local mirror.
        {
            let gov = shared_gov.read().await.clone();
            rt.governance = Some(gov);
        }

        // Re-register as a network subscriber periodically (until peers connect).
        // Re-subscription is idempotent plumbing for the case where peers
        // connected after we subscribed; it does not need to run every 5s.
        // Two join calls capped at 2s each made this a 4s tax on every tick
        // once peers answered slowly, and [perf] showed ticks of 8-11s with
        // join=true. Once connected it is pure overhead, so check rarely.
        //
        // Join backoff (local policy only): a join dial is a full request_to
        // round trip (handshake timeout ~1.7s to a dead endpoint), so dialing
        // a cooldown-skipped peer on every window re-creates the storm the
        // cooldown exists to suppress. Each dial below is gated by
        // `join_should_dial` over that network's `has_nonskipped_peers()`
        // (section-level equivalent: all-cooldown => skip the dial entirely,
        // join_ms stays 0). A returning peer re-announces via DHT/probe,
        // whose success clears its cooldown entry, so the next window
        // re-dials automatically. Never consensus, never wire.
        if last_join.elapsed() > Duration::from_secs(60) {
            let net_dial = stellereum::consensus_net::join_should_dial(!net.has_nonskipped_peers());
            let gossip_dial =
                stellereum::consensus_net::join_should_dial(!gossip.has_nonskipped_peers());
            if net_dial || gossip_dial {
                join_ran = true;
                let n_join = net.clone();
                let g_join = gossip.clone();
                tokio::spawn(async move {
                    if net_dial {
                        let _ = tokio::time::timeout(Duration::from_secs(2), n_join.join()).await;
                    }
                    if gossip_dial {
                        let _ = tokio::time::timeout(Duration::from_secs(2), g_join.join()).await;
                    }
                });
                last_join = std::time::Instant::now();
                split_join_n += 1;
            } else {
                tracing::debug!(
                    "[net] join skipped (all peers in failure cooldown, no dial on either network)"
                );
                last_join = std::time::Instant::now();
            }
        }
        // Liveness probe (visible outcome per peer) runs non-blocking off the tick.
        if last_probe.elapsed() > Duration::from_secs(30) {
            probe_ran = true;
            let n_probe = net.clone();
            tokio::spawn(async move {
                let _ = tokio::time::timeout(Duration::from_secs(2), n_probe.probe_peers()).await;
            });
            // F8: `net_peerCount` follows the live peer table. One read per
            // probe window, off the tick — the RPC then serves the observed
            // count (honest `0x0` when nothing was seen), never a constant.
            let a_peers = adapter.clone();
            tokio::spawn(async move {
                let _ = a_peers.publish_live_peer_count().await;
            });
            if let Some((fh, fhash)) = rt.finalized.last().copied() {
                let a = adapter.clone();
                let shard_id = block_shard;
                publish_lane.submit(async move {
                    a.publish_head(shard_id, fh, fhash).await;
                });
            }
            last_probe = std::time::Instant::now();
            split_probe_n += 1;
        }
        // Persist the mempool periodically (crash-safe pending transactions):
        // the pool is memory-only, so without this every restart silently
        // drops users' valid transactions (observed live: funded-but-never-
        // visible drips across every restart). Loaded back at startup above.
        // Every 15s bounds the loss window below the watchdog's stall
        // threshold, so a stall-restart cycle cannot eat a fresh blast.
        //
        // §7 Phase 1: fire-and-forget. The blocking bincode + fs::write (and
        // the read lock it used to hold across both) now run on the blocking
        // pool; this call only claims the single-flight guard, so an overdue
        // save can never overlap a still-running one.
        if last_mempool_save.elapsed() > Duration::from_secs(15) {
            let _ = schedule_mempool_save(&rt.mempool, &mempool_path, &mempool_save_guard);
            last_mempool_save = std::time::Instant::now();
        }

        // Periodic workchain validator-set repair (R3 CODE-TAILS sweep, see
        // the method docs): re-read the masterchain registry and stage/install
        // whatever is due, even when this shard has not finalized for a while.
        // Interval-gated (30s) and internally workchain-gated; a no-op for
        // the masterchain and single-shard nodes. Bounded: one shared-ledger
        // read plus a compare per interval, silent unless the set changes.
        if last_workchain_set_repair.elapsed() > Duration::from_secs(30) {
            last_workchain_set_repair = std::time::Instant::now();
            if rt.refresh_workchain_set_from_master().await {
                info!(
                    "[shard {}] workchain validator set converged from the masterchain registry (periodic repair)",
                    block_shard
                );
            }
            // Consensus-copy resync (post-restart wedge repair): a refresh can
            // move the runtime's in-force set without moving heights (restore
            // from a lagging domains snapshot, then a live-ledger refresh),
            // stranding the consensus copy on the older set. The node then
            // computes a different proposer schedule from converged peers and
            // the wedge never heals (no height advances to rebuild the copy).
            // The runtime set is agreed with peers (same live-ledger
            // derivation everywhere); aligning the copy completes the
            // transition instead of reverting one.
            if rt.resync_consensus_set_to_runtime() {
                info!(
                    "[shard {}] consensus validator set resynced to the runtime in-force set (periodic repair)",
                    block_shard
                );
            }
        }

        // Ingest gossiped transactions into the fee-priority mempool.
        // A14 phase 3 (chain binding): ingress height + one-shot activation
        // drain.
        // GATE: `ingress_height` is finalized-tip+1 — the earliest height a
        // newly admitted tx could be included at — derived from COMMITTED
        // `rt.finalized`, never gossip-supplied. The drain runs ONCE, on the
        // first tick at/after activation (a node starting post-activation
        // with unbound txs in its restored pool drains on its first tick,
        // before the propose section below); `insert` already refuses new
        // unbound arrivals while armed, so re-draining would only rescan.
        // Default-off: `refusal_active` is always false, so this whole block
        // is a no-op and every context below behaves byte-identically.
        let binding_activation =
            stellereum::chain_binding::ChainBindingActivation::from_chain_spec();
        let ingress_height = rt
            .finalized
            .last()
            .map(|(h, _)| (*h).saturating_add(1))
            .unwrap_or(0);
        if !chain_binding_drained && binding_activation.refusal_active(ingress_height) {
            let dropped = rt
                .mempool
                .write()
                .await
                .drop_unbound_at_activation(ingress_height, &binding_activation);
            if dropped > 0 {
                tracing::warn!(
                    "[binding] activation drain at height {ingress_height}: dropped {dropped} unbound tx(s) from the mempool (see docs/PLAN-BINDING.md)"
                );
            }
            chain_binding_drained = true;
        }
        while let Ok(raw) = tx_rx.try_recv() {
            // The epoch-seal frames share the transaction-gossip channel:
            // the sealed ciphertext, the DKG contribution, the order
            // commitment and the share release.
            match stellereum::consensus_net::parse_tx_gossip_payload(&raw) {
                Some(stellereum::consensus_net::TxGossipPayload::Mev(frame)) => {
                    rt.on_mev_frame(frame).await;
                    continue;
                }
                Some(stellereum::consensus_net::TxGossipPayload::Plain(tx)) => {
                    let acct = rt.state.get_account(&tx.from).await;
                    let bal = acct.as_ref().map(|a| a.balance).unwrap_or(0);
                    let onchain = acct.as_ref().map(|a| a.nonce).unwrap_or(0);
                    let mut pool = rt.mempool.write().await;
                    // Same nonce-gap fail-fast as the RPC path (audit:
                    // blocks troubles): gossiped far-future nonces clogged
                    // both pools behind unreachable heads.
                    if let Some(gap) = pool.check_nonce_gap(&tx.from, tx.nonce, onchain) {
                        tracing::debug!(
                            "[mempool] gossip tx gapped from {}: {gap}",
                            hex::encode(&tx.from[..6])
                        );
                        continue;
                    }
                    // P2 shard gate + F-02 nonce head, carried into the choke
                    // point (not just pre-checked above): foreign-shard
                    // gossip can no longer squat in this shard's pool. The
                    // pool-level pin is the backstop; this is the explicit
                    // first line.
                    let mut gctx = stellereum::mempool::AdmissionCtx::wall_now()
                        .with_onchain_nonce(onchain)
                        .with_chain_height(ingress_height);
                    // PAYMASTER: gossiped sponsored transactions carry their
                    // sponsor's balance head (fail-closed without it).
                    if let Some(sbal) = rt.state.sponsor_balance_of(&tx).await {
                        gctx = gctx.with_sponsor_balance(sbal);
                    }
                    if rt.shard_registry.is_sharded() {
                        gctx = gctx.with_shard(rt.shard_id);
                    }
                    if let Err(e) = pool.add_checked_ctx(tx.clone(), bal, gctx) {
                        tracing::debug!(
                            "[mempool] gossip admission refused from {} nonce={}: {e}",
                            hex::encode(&tx.from[..6]),
                            tx.nonce
                        );
                    }
                    continue;
                }
                None => continue,
            }
        }

        // 0. pull mempool txs from the infnode overlay into our mempool
        for tx in adapter.fetch_mempool_transactions(shard).await {
            let acct = rt.state.get_account(&tx.from).await;
            let bal = acct.as_ref().map(|a| a.balance).unwrap_or(0);
            let onchain = acct.as_ref().map(|a| a.nonce).unwrap_or(0);
            let mut pool = rt.mempool.write().await;
            if pool.check_nonce_gap(&tx.from, tx.nonce, onchain).is_some() {
                continue;
            }
            // Same P2/F-02 pinning as the gossip path above.
            let mut octx = stellereum::mempool::AdmissionCtx::wall_now()
                .with_onchain_nonce(onchain)
                .with_chain_height(ingress_height);
            // PAYMASTER: same sponsor head as the gossip path above.
            if let Some(sbal) = rt.state.sponsor_balance_of(&tx).await {
                octx = octx.with_sponsor_balance(sbal);
            }
            if rt.shard_registry.is_sharded() {
                octx = octx.with_shard(rt.shard_id);
            }
            let _ = pool.add_checked_ctx(tx, bal, octx);
        }

        // 1. propose if we are the proposer for this (height, round)
        //
        // Pacing guard: with a small validator set consensus completes instantly,
        // so without a floor the chain ran at ~5000 empty blocks/second and ate
        // the disk. Proposing later is always allowed (a block's validity does
        // not depend on when it was made), so this is local policy, not a
        // consensus rule — every validator still accepts whatever arrives.
        //
        // Dynamic franchise (see the longer note at the prevote gate below):
        // `is_validator` is the static config flag, but the LEDGER is
        // consensus truth — a node whose key entered the committed staking
        // set on-chain proposes and votes even as a config observer.
        // Without this, the first on-chain-added validator can never
        // participate and any quorum requiring it halts the chain.
        // STALE-LEDGER GATE (node C): a refused (stale) set must never vote,
        // even if the config flag or the foreign set names us. Fail-closed to
        // observer with an honest log instead of a silent foreign quorum.
        // `effective_can_vote` encodes exactly this (config-or-ledger minus
        // stale); the throttled line below keeps the observer state visible
        // without spamming every 100ms tick.
        let can_vote = rt.effective_can_vote(is_validator);
        if rt.is_validator_set_stale() {
            static STALE_VOTE_N: std::sync::atomic::AtomicU64 =
                std::sync::atomic::AtomicU64::new(0);
            let n = STALE_VOTE_N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if n.is_multiple_of(300) {
                eprintln!(
                    "[validator-set] WARN observer mode (stale set: {}); votes disabled until a fresh domain snapshot arrives",
                    rt.validator_set_stale_reason().unwrap_or("unknown reason")
                );
            }
        }
        //
        // §7 Phase 2 gate (stage 1): while the execution worker is still
        // applying the decided block, our state root is PRE-H and every read
        // in this section (the eviction snapshot, the filter's account map,
        // the header's `state_root`) would build on it. The section is
        // skipped — but the gossip drains above and the message drain below
        // still run every tick, so the loop never blocks on execution.
        // (`ValidatorRuntime::propose` enforces the same gate itself; this
        // keeps even the mempool-eviction reads off the pre-H state.)
        // Dynamic franchise (see can_vote above): a ledger-member newcomer
        // proposes in its own slots too, or every third round dies empty
        // while the network waits for a proposer that will never come
        // (observed live: 1/3 dead rounds + WAN skew = no QC for an hour).
        // Liveness diagnostic (once per round): expose WHY the propose gate
        // does or does not fire. A silent proposer is indistinguishable from
        // a dead network without this; it separates gate-blocked (values
        // below) from send-blocked (gate passes but nothing arrives).
        if last_gate_diag != Some((height, round)) {
            last_gate_diag = Some((height, round));
            tracing::warn!(
                "[consensus] propose-gate h={} r={} can_vote={} pending_apply={} is_proposer={} live_proposal={} min_time_ok={} parent_ready={} scheduled={}",
                height,
                round,
                can_vote,
                rt.has_pending_apply(),
                rt.is_proposer(),
                rt.hc.has_live_proposal(),
                last_block_at.elapsed() >= min_block_time,
                proposal_parent_is_finalized(
                    rt.finalized.last().map(|(h, _)| *h).unwrap_or(0),
                    rt.hc.height
                ),
                rt.hc
                    .proposer()
                    .map(|p| hex::encode(&p[..6]))
                    .unwrap_or_else(|| "none".into())
            );
        }
        // VEL-1 bounded proposer-prebuild: move the next build out of the
        // proposal critical path into this tick's idle window (before the
        // propose gate). `prebuild_next_proposal` is a bounded no-op unless
        // this node owns its imminent proposal (current round waiting out
        // `min_block_time`, or round 0 of the next height) and the cache
        // does not cover it yet: at most one selection run per height, local
        // only, no wire/quorum/state-transition effect. Staleness (parent
        // changed under the prebuild) is handled inside `propose` by
        // per-tx revalidation + top-up, so the worst case is one bounded
        // O(block) revalidation before a fresh-equivalent build.
        // PARENT-BOUND PROPOSAL GATE (HEIGHT-SPLIT, propose half): a block's
        // `prev_hash` is always our finalized tip, so the only height we may
        // build at is `tip + 1` (height 1 at genesis). Proposing at any other
        // height emits a block that either skips heights or reuses a decided
        // parent — peers refuse it as a stale/wrong height and ours burns the
        // round. This is also the backstop for a restored head that could not
        // be reconciled: fail closed (no proposal) rather than fork.
        let parent_is_finalized = proposal_parent_is_finalized(
            rt.finalized.last().map(|(h, _)| *h).unwrap_or(0),
            rt.hc.height,
        );
        if can_vote && !rt.has_pending_apply() && parent_is_finalized {
            rt.prebuild_next_proposal(now_secs()).await;
        }
        if can_vote
            && parent_is_finalized
            && !rt.has_pending_apply()
            && rt.is_proposer()
            && !rt.hc.has_live_proposal()
            && last_block_at.elapsed() >= min_block_time
        {
            // Drop transactions that can never execute (consumed nonce, or the
            // sender can no longer afford them). Otherwise a stale-nonce tx sits
            // in the mempool forever and blocks that account's later
            // transactions indefinitely.
            //
            // The clock is passed explicitly so the sweep can also reclaim
            // AGED FUTURE nonces (a transaction waiting behind a gap that
            // never filled — the sender controls that gap, so it is pool
            // pollution, not a pending payment; audit: nonce-stuffing
            // lockup).
            {
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let engine = rt.state.clone();
                let mut accounts: std::collections::HashMap<[u8; 32], (u64, u64)> =
                    std::collections::HashMap::new();
                let senders: Vec<[u8; 32]> = rt
                    .mempool
                    .read()
                    .await
                    .all()
                    .iter()
                    .map(|t| t.from)
                    .collect();
                for s in senders {
                    if let Some(a) = engine.get_account(&s).await {
                        accounts.insert(s, (a.nonce, a.balance));
                    }
                }
                let dropped = rt
                    .mempool
                    .write()
                    .await
                    .evict_unexecutable_at(now_secs, |s| {
                        // Unknown senders are skipped, never assumed broke: the
                        // snapshot may be partial or pre-height, and deleting a
                        // funded transaction here is irreversible (audit 2026-10-06).
                        accounts.get(s).copied()
                    });
                if dropped > 0 {
                    info!("[mempool] evicted {dropped} unexecutable transaction(s)");
                }
                // TTL sweep for stuck-gapped suffixes (audit: blocks troubles):
                // unexecutable AND old goes; executable stays whatever its age.
                // Same snapshot (no extra engine reads); wall clock is local
                // policy, never consensus.
                {
                    let swept = rt
                        .mempool
                        .write()
                        .await
                        .sweep_expired(now_secs, |s| accounts.get(s).copied());
                    if swept > 0 {
                        info!("[mempool] swept {swept} stuck transaction(s) past TTL");
                    }
                }
            }
            // EPOCH SEAL: keep the epoch key in step with the chain
            // (the DKG starts when the chain crosses an epoch boundary).
            // Cheap: the manager only does work when the epoch changed.
            rt.sync_mev_epoch().await;
            // Off-tick CN-VRF v3 VDF completion (cheap `try_recv`; the lane
            // itself runs on a blocking worker, never on this tick).
            rt.poll_vdf_lane();
            if let Some(block) = rt.propose(now_secs()).await {
                let bh = block.compute_hash();
                let ntx = block.transactions.len();
                // P3-H4: enqueue; proposals carry bodies so they flush at once.
                // COMPACT GOSSIP: announce the compact header; the announced
                // block stays servable for bounded body pulls AND for the
                // full-proposal fallback (same-height round-trip).
                // The block is stamped with `rt.hc.round` INSIDE `propose()`;
                // a view change earlier in this tick would leave the tick-local
                // `round` stale, so the envelope would name an older round and
                // every peer would refuse the frame as `stale round` while the
                // signed block was current. Always take the envelope round from
                // the block we just signed.
                compact_server.remember(&block, block.round);
                let msg = stellereum::consensus_net::proposal_gossip_msg(&block, block.round);
                let large = msg.is_large();
                enqueue_outbox(&mut outbox, msg);
                if large {
                    flush_outbox(&net_sender, &mut outbox, rt.hc.height, rt.hc.round);
                    outbox_flushes += 1;
                    last_flush = std::time::Instant::now();
                }
                last_block_at = std::time::Instant::now();
                info!(
                    "[consensus] proposed block #{} r{} {} txs={}",
                    height,
                    round,
                    hex::encode(&bh[..6]),
                    ntx
                );
            }
        }

        // An observer follows and validates but never proposes or votes. It still
        // drains incoming messages and applies finalized blocks, so it stays in sync
        // and can answer RPC/SPV queries.
        //
        // Dynamic franchise: see the note at the propose gate above (`can_vote`
        // is computed once per tick there). Proposing stays equally gated: a
        // newcomer that never proposes leaves every third round empty.
        // 2. prevote once we have a proposal.
        //
        // The vote round is the PROPOSAL's SIGNED round. Under ruleset v6 a
        // lock-rescue/demanded re-proposal is RE-STAMPED at the proposer's
        // current round (`restamp_for_round`), so the signed round IS the
        // round the network is voting the value in — not the old round it was
        // first signed under. The fsynced watermark is still checked against
        // the vote's own round: a node that already voted in a later round
        // stays silent rather than voting below its floor.
        let prevote_round = rt.prevote_round();
        if can_vote
            && rt.hc.has_live_proposal()
            && last_prevoted != Some((height, prevote_round))
            && !round_at_or_below_vote_floor(vote_floor, height, prevote_round)
        {
            if let Some(v) = rt.make_prevote() {
                // WRITE-AHEAD: the watermark is durable before the outbox can
                // flush this vote.
                persist_vote_watermark_before_broadcast(persistence.as_ref(), &v);
                advance_vote_floor(&mut vote_floor, v.height, v.round);
                let _ = rt.on_prevote(v.clone());
                // P3-H4: guards are set at ENQUEUE time, so the vote is cast
                // exactly once even though the wire flush happens later.
                enqueue_outbox(
                    &mut outbox,
                    ConsensusMsg::Vote {
                        vote: v.clone(),
                        locked: lock_hint(&rt, &v),
                    },
                );
                flush_outbox(&net_sender, &mut outbox, rt.hc.height, rt.hc.round);
                outbox_flushes += 1;
                last_flush = std::time::Instant::now();
                let cast_round = v.round;
                cast_prevote = Some(v);
                last_prevoted = Some((height, cast_round));
            }
        }
        // 2b. nil prevote on proposal-timeout (Tendermint liveness): a
        // validator with no proposal still speaks once per round. Without
        // this, a behind node is radio-silent: tip nodes never observe it,
        // their behind-peer trackers never stamp, and retro/catch-up help
        // never flows to it — a silent follower can never be rescued
        // (observed live: C ~200 heights behind voted for nothing while A/B
        // suppressed retro for "no behind peer"). Fires at 2x the base round
        // timeout (past even the view-change hold bound): a proposal arriving
        // before that still gets our value vote via (2) above. Nil votes
        // finalize nothing (a nil QC decides no block) and locked nodes
        // attach their lock hint, feeding the rescue path. Rate: once per
        // round via last_prevoted, shared with (2).
        //
        // PER-ROUND "WAIT FOR A PEER" (WAN liveness, live 2026-10-21): a
        // nil prevote SPENDS this node's one vote for the round, and a round
        // with a nil vote from a third of the power can never carry a polka
        // for the block the rest of the network is voting for. So a node must
        // not spend that vote while a peer is demonstrably ALIVE in this
        // round: the peer's proposal may be a second away, and the round is
        // decided by the value vote, not by our nil.
        //
        // The rule is LOCAL (it never moves our round) and it is the SAME
        // signal the view change uses (`peer_alive_recently`, below), so the
        // two agree: the node holds the round AND keeps its vote while a peer
        // is talking, and it gives up (nil vote + view change) when the peer
        // goes silent. NO 2-SUPPORTER GATE: the quorum-gated jump was tried
        // and reverted because in a 3-validator set the two nodes BEHIND
        // could never gather two supporters and never caught up - a
        // different deadlock. One live peer is enough.
        //
        // SAFETY: a nil prevote decides nothing, so withholding it can only
        // cost a nil quorum (liveness), never a fork: the value vote path (2)
        // is untouched.
        let peer_alive_in_round = matches!(
            peer_round_seen,
            Some((ph, pr, at))
                if ph == height
                    && pr + 1 >= round
                    && at.elapsed() < round_timeout
        );
        // Straggler grace on the nil wait (docs/PROPOSER_REWORK.md §2c): the
        // same bounded hold — don't nil a round whose scheduled value may
        // still be in flight. Default-off (grace 0 → zero added, the deadline
        // below is byte-identical to today).
        let nil_grace = {
            let g = straggler_grace_ms();
            if g == 0 {
                Duration::from_millis(0)
            } else {
                let seen = peer_round_seen.map(|(ph, pr, at)| {
                    let age_ms: u64 = at.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
                    (ph, pr, age_ms)
                });
                Duration::from_millis(straggler_hold_ms(
                    height,
                    round,
                    rt.hc.has_live_proposal(),
                    seen,
                    g,
                    straggler_grace_cap_ms(),
                    straggler_freshness_ms(round_timeout.as_millis() as u64),
                ))
            }
        };
        if can_vote
            && !rt.hc.has_live_proposal()
            && last_prevoted != Some((height, round))
            && round_started.elapsed() >= 2 * round_timeout + nil_grace
            && !peer_alive_in_round
            && !round_at_or_below_vote_floor(vote_floor, height, round)
        {
            if let Some(v) = rt.make_prevote() {
                debug_assert!(
                    v.block_hash.is_none(),
                    "no live proposal must prevote nil, never a value"
                );
                persist_vote_watermark_before_broadcast(persistence.as_ref(), &v);
                advance_vote_floor(&mut vote_floor, v.height, v.round);
                let _ = rt.on_prevote(v.clone());
                enqueue_outbox(
                    &mut outbox,
                    ConsensusMsg::Vote {
                        vote: v.clone(),
                        locked: lock_hint(&rt, &v),
                    },
                );
                cast_prevote = Some(v);
                last_prevoted = Some((height, round));
                tracing::debug!(
                    "[consensus] prevoted nil at #{} r{} (no proposal after {:?})",
                    height,
                    round,
                    2 * round_timeout
                );
            }
        }

        // 3. drain incoming consensus messages, capped per tick (audit
        // 2026-10-06): an unbounded drain lets a flood of max-size batches
        // stretch signature verification past the round timeout — the tick IS
        // the clock. TWO caps: at most MAX_INBOUND_PER_TICK envelopes are
        // CONSUMED per tick (the rest wait in the channel — deferred, never
        // dropped), and at most INNER_BUDGET flattened messages are VERIFIED
        // (a Batch fans out to 32 votes; counting envelopes alone let the
        // exact blowup through that the cap claims to stop). Past the inner
        // budget the flood tail is dropped loudly — honest traffic (tens/tick)
        // never reaches either cap (weak-node principle).
        let mut inner_verified = 0u32;
        let mut committed_admitted = 0u32;
        const INNER_BUDGET_PER_TICK: u32 = MAX_INBOUND_PER_TICK * 4;
        // SEC-06: prioritize draining live messages from rx.try_recv().
        // Deferred bulk messages wait in `inbound_deferred` until their scheduled
        // `wake_at` time and are only popped when `rx` has no immediate messages,
        // preventing bulk deferrals from starving real-time consensus votes.
        'drain: for _ in 0..MAX_INBOUND_PER_TICK {
            // LOCAL LOOPBACKS FIRST: a resolved compact proposal re-enters the
            // drain here, ahead of peer traffic, so an honest block is never
            // starved behind future-dated deferrals or a flood (F-1/H5). These
            // entries are local-only, bounded, and already accounted to the
            // compact frame that produced them; they skip the per-peer bulk
            // limiter (no double charge) but still pay the inner verify budget.
            let (raw, from_loopback): (String, bool) = if let Some(raw) = loopback_queue.pop_front()
            {
                (raw, true)
            } else {
                match rx.try_recv() {
                    Ok(r) => (r, false),
                    Err(_) => {
                        let now = Instant::now();
                        if inbound_deferred
                            .front()
                            .map(|(wake_at, _)| now >= *wake_at)
                            .unwrap_or(false)
                        {
                            (inbound_deferred.pop_front().unwrap().1, false)
                        } else {
                            break;
                        }
                    }
                }
            };
            let Some(msg) = parse_incoming(&raw) else {
                // Unparseable payloads on our own topic are a delivery-layer
                // bug (or garbage from a peer); silent drops here once hid a
                // one-directional blackout for hours. Count them loudly.
                parse_fail_count += 1;
                if parse_fail_count % 50 == 1 {
                    tracing::warn!(
                        "[consensus] dropped {parse_fail_count} unparseable inbound message(s); last len {} head {:?}",
                        raw.len(),
                        &raw[..raw.len().min(120)],
                    );
                }
                continue;
            };
            // Inbound bulk guard (audit-network F1 + pentest F2): EVERY
            // envelope is budget-checked against the SENDER's per-peer bucket
            // (`src`: infnode adds it — it is the only place that knows the
            // connection's peer id; `from` is the legacy spelling). Without a
            // sender every peer's bulk traffic shared ONE token bucket and one
            // noisy neighbour could defer everybody else's batches.
            //
            // Only Committed bypasses inside `admit_inbound` (the catch-up
            // proof must never wait). Votes and proposals are budget-checked
            // too: exempting every non-Batch message let an attacker trickle
            // singleton votes — never a Batch — and burn an Ed25519 verify
            // per message while the limiter saw nothing (pentest F2). A
            // deferred message is REQUEUED (bounded wait hint honored by
            // re-parking for a later tick), never dropped; per-peer buckets
            // mean an honest peer's votes still pass while the flooder's own
            // bucket is empty. The envelope already counted as liveness
            // evidence below even when deferred.
            //
            // A LOCAL LOOPBACK is already budgeted (it is the resolved block
            // for a compact frame that paid admission) and is bounded by
            // `LOOPBACK_QUEUE_CAP`, so it is not re-charged to the shared bulk
            // limiter. It still carries the originating `src` for attribution.
            let peer_key = stellereum::consensus_net::inbound_peer_key(&raw);
            if !from_loopback {
                match net.admit_inbound(&peer_key, &msg, raw.len()) {
                    stellereum::consensus_net::InboundDecision::Allow => {}
                    stellereum::consensus_net::InboundDecision::Defer { wait_ms } => {
                        inbound_defer_count += 1;
                        if inbound_defer_count % 20 == 1 {
                            tracing::warn!(
                                "[consensus] inbound bulk over budget; deferring message ({raw_len} bytes, retry in ~{wait_ms}ms) {inbound_defer_count} time(s) — catch-up Committed unaffected",
                                raw_len = raw.len(),
                            );
                        }
                        if inbound_deferred.len() < INBOUND_DEFERRED_CAP {
                            // SEC-06: Store deferred messages in time-gated queue with scheduled wake_at time.
                            let wake_at = Instant::now() + Duration::from_millis(wait_ms);
                            let pos = inbound_deferred
                                .iter()
                                .position(|(w, _)| *w > wake_at)
                                .unwrap_or(inbound_deferred.len());
                            inbound_deferred.insert(pos, (wake_at, raw));
                            continue;
                        }
                        // Park full: handle inline LOUDLY rather than drop
                        // or grow memory without bound. Only under a
                        // sustained bulk flood past 1024 parked messages.
                        tracing::warn!(
                            "[consensus] deferred park full ({INBOUND_DEFERRED_CAP}); handling an over-budget message inline (never dropped)"
                        );
                    }
                }
            }
            // Inbound liveness clock (dead-peer retro gate): ANY parseable
            // consensus message proves somebody is talking to us right now.
            // Stamped per envelope (before flattening): one Batch from a live
            // peer is liveness evidence even if every inner is later dropped.
            last_inbound_msg = std::time::Instant::now();
            {
                // P3-H4: a Batch flattens to its inners in sender order. Each
                // inner is isolated (one bad inner never drops its siblings)
                // and runs the full per-vote bookkeeping below.
                //
                // Audit-network F2 priority lane: `Committed` is the live
                // catch-up path (full block + QC, no DHT work) and must not
                // starve behind bulk junk. Flattened inners are reordered so
                // `Committed` verifies first, and `Committed` neither counts
                // against the verification budget nor is dropped as flood
                // tail — only Batch-carried votes/proposals burn the budget.
                // Scheduling only: validation below is untouched.
                for msg in
                    stellereum::consensus_net::prioritize_inbound_for_verify(flatten_incoming(msg))
                {
                    // Liveness-alarm RX clock: ANY consumed Proposal/Vote —
                    // accepted or refused, Batch-carried or singleton — proves
                    // the transport delivers our topic right now. Stamped
                    // BEFORE any verification/refusal below (a refusal still
                    // proves receipt); Committed is deliberately excluded (it
                    // is catch-up proof, and the alarm watches live traffic).
                    if matches!(
                        msg,
                        ConsensusMsg::Proposal { .. }
                            | ConsensusMsg::CompactProposal { .. }
                            | ConsensusMsg::Vote { .. }
                    ) {
                        last_consensus_rx_ms = liveness_alarm::now_ms();
                    }
                    // Event-driven catch-up: a message that NAMES a height above
                    // ours is potential "peer is ahead" evidence. It is acted on
                    // only AFTER the arm's own verification (QC / proposer
                    // signature / vote signature) — never on the raw claim.
                    let named_ahead = inbound_names_ahead(rt.hc.height, &msg);
                    let is_catchup = matches!(msg, ConsensusMsg::Committed { .. });
                    if is_catchup {
                        // VERIFICATION F2-hardening: Committed bypasses the
                        // byte limiter by design, so a single peer can emit
                        // unbounded fake proofs. The per-tick proof cap is
                        // the bound: excess proofs are dropped LOUDLY (not
                        // deferred — a deferred fake would just burn the next
                        // tick too), the rest of the drain continues, and the
                        // sender's rebroadcast + the DHT walk cover honest
                        // catch-up (which needs ~1 proof per finalize).
                        if !stellereum::consensus_net::committed_admit_this_tick(committed_admitted)
                        {
                            inbound_overcap_count += 1;
                            tracing::warn!(
                                "[consensus] dropping Committed proof over per-tick cap ({} proves/tick); flood tail, catch-up falls back to rebroadcast/DHT walk",
                                stellereum::consensus_net::COMMITTED_INNER_BUDGET_PER_TICK,
                            );
                            continue;
                        }
                        committed_admitted += 1;
                    } else {
                        inner_verified += 1;
                        if inner_verified > INNER_BUDGET_PER_TICK {
                            inbound_overcap_count += 1;
                            if inbound_overcap_count % 20 == 1 {
                                tracing::warn!(
                                    "[consensus] inbound verification over budget {INNER_BUDGET_PER_TICK}/tick {inbound_overcap_count} time(s); dropping flood tail (Committed catch-up still admitted)"
                                );
                            }
                            break 'drain;
                        }
                    }
                    match msg {
                        ConsensusMsg::Batch(_) => {}
                        // Compact proposal gossip (`CompactProposal` / `BodyPull`
                        // / `Body`): activation is frozen OFF at
                        // `COMPACT_GOSSIP_ACTIVATION_HEIGHT = u64::MAX`, and the
                        // receiver wiring lands with the lead's gate flip. Below
                        // the gate these frames MUST be refused loudly and
                        // dropped — never reinterpreted as a full proposal, never
                        // a panic. `ConsensusMsg::decode` already rejects them
                        // pre-activation; these arms are defense in depth for a
                        // frame that decoded while the gate says off.
                        // COMPACT GOSSIP is ACTIVE. Resolve against the local
                        // mempool; a complete resolution re-enters the drain as
                        // a FULL proposal (one code path for every check); a
                        // miss emits a BOUNDED pull; an unresolvable proposal
                        // falls back to the plain full fetch.
                        ConsensusMsg::CompactProposal { proposal } => {
                            // C2/F-8: authenticate/structurally pre-filter and
                            // budget BEFORE any mempool clone or index build.
                            // Far/stale heights and over-budget peers are
                            // dropped loudly without touching the pool.
                            let over = {
                                let count =
                                    compact_peer_frames.entry(peer_key.clone()).or_insert(0);
                                !compact_frame_within_peer_budget(
                                    count,
                                    COMPACT_FRAMES_PER_PEER_PER_TICK,
                                )
                            };
                            if over {
                                compact_budget_dropped += 1;
                                inbound_compact_refused += 1;
                                if compact_budget_dropped == 1
                                    || compact_budget_dropped.is_multiple_of(50)
                                {
                                    tracing::warn!(
                                        "[consensus] compact frame budget exceeded for peer {} ({compact_budget_dropped} dropped): per-tick cap {}",
                                        peer_key,
                                        COMPACT_FRAMES_PER_PEER_PER_TICK,
                                    );
                                }
                                continue;
                            }
                            if !compact_proposal_height_is_relevant(rt.hc.height, proposal.height) {
                                inbound_compact_refused += 1;
                                tracing::debug!(
                                    "[consensus] compact proposal #{} r{} outside live window (hc #{}) — catch-up owns it",
                                    proposal.height,
                                    proposal.round,
                                    rt.hc.height,
                                );
                                continue;
                            }
                            // STRUCTURAL VALIDATION FIRST (C2/F-8): a malformed
                            // frame must not be able to trigger an index build.
                            if let Err(why) = proposal.validate() {
                                inbound_compact_refused += 1;
                                if inbound_compact_refused % 20 == 1 {
                                    tracing::warn!(
                                        "[consensus] refused compact frame before mempool work ({} refused): {why}",
                                        inbound_compact_refused
                                    );
                                }
                                continue;
                            }
                            // Parent plausibility: at OUR height the header must
                            // build on our finalized tip, so a peer cannot mint
                            // unlimited distinct salts with random prev_hashes.
                            let (tip_h, tip_hash) =
                                rt.finalized.last().copied().unwrap_or((0, [0u8; 32]));
                            if !compact_parent_is_plausible(
                                proposal.height,
                                proposal.header.prev_hash,
                                rt.hc.height,
                                tip_hash,
                            ) {
                                inbound_compact_refused += 1;
                                tracing::debug!(
                                    "[consensus] compact proposal #{} does not build on our tip #{tip_h} (prev {}); dropped before mempool work",
                                    proposal.height,
                                    hex::encode(&proposal.header.prev_hash[..6]),
                                );
                                continue;
                            }
                            let inbound = if proposal.short_ids.is_empty() {
                                // Zero-id block: no index work at all.
                                compact_rx.on_proposal(proposal, std::iter::empty())
                            } else {
                                let now = Instant::now();
                                let cached = compact_index.get(&proposal.header, now).is_some();
                                let index = if cached {
                                    compact_index
                                        .get(&proposal.header, now)
                                        .expect("just checked")
                                } else {
                                    // Whole-node per-tick build budget: the
                                    // cache key is the salt, and a peer can
                                    // vary it; this is the hard bound on
                                    // whole-mempool work per tick.
                                    if compact_index_builds_tick >= COMPACT_INDEX_BUILDS_PER_TICK {
                                        compact_budget_dropped += 1;
                                        continue;
                                    }
                                    compact_index_builds_tick += 1;
                                    let txs = rt.mempool.read().await.all();
                                    compact_index.insert(&proposal.header, txs, now)
                                };
                                compact_rx.on_proposal_indexed(proposal, index)
                            };
                            settle_compact!(inbound, &peer_key);
                        }
                        // Serve missing txs for a block WE announced, from the
                        // cached announced body (bounded), never from arbitrary
                        // storage and never by cloning the whole mempool.
                        ConsensusMsg::BodyPull { pull } => {
                            let over = {
                                let count =
                                    compact_peer_frames.entry(peer_key.clone()).or_insert(0);
                                !compact_frame_within_peer_budget(
                                    count,
                                    COMPACT_FRAMES_PER_PEER_PER_TICK,
                                )
                            };
                            if over {
                                compact_budget_dropped += 1;
                                continue;
                            }
                            let now_ms = liveness_alarm::now_ms();
                            if pull.is_full_request() {
                                match compact_server.serve_full_for(&peer_key, &pull, now_ms) {
                                    Ok(Some(block)) => {
                                        let round = pull.round;
                                        enqueue_outbox(
                                            &mut outbox,
                                            ConsensusMsg::Proposal {
                                                height: block.height,
                                                round,
                                                block,
                                            },
                                        );
                                        flush_outbox(
                                            &net_sender,
                                            &mut outbox,
                                            rt.hc.height,
                                            rt.hc.round,
                                        );
                                        outbox_flushes += 1;
                                        last_flush = std::time::Instant::now();
                                        compact_served += 1;
                                        if compact_served == 1 {
                                            info!(
                                                "[consensus] compact gossip LIVE: first full-proposal fallback served from the announced body"
                                            );
                                        }
                                    }
                                    Ok(None) => {}
                                    Err(why) => {
                                        inbound_compact_refused += 1;
                                        if inbound_compact_refused % 20 == 1 {
                                            tracing::warn!(
                                                "[consensus] refused compact full-proposal request #{} r{}: {why}",
                                                pull.height,
                                                pull.round,
                                            );
                                        }
                                    }
                                }
                                continue;
                            }
                            match compact_server.serve_for(&peer_key, &pull, now_ms) {
                                Ok(Some(body)) => {
                                    // UNICAST REPLY (no broadcast amplification):
                                    // the requester is the inbound envelope's
                                    // peer id (`peer_key`, derived at the top of
                                    // this drain from `inbound_peer_key`), which
                                    // `serve_for` already used for the
                                    // served-once set and rate cap. A 40-hex id
                                    // gets one addressed send; an unknown key
                                    // (shared `broadcast` bucket, legacy short
                                    // src) keeps the bounded outbox broadcast.
                                    let counters = net.compact_reply_counters();
                                    let net_unicast = Arc::clone(&net);
                                    let route =
                                        stellereum::consensus_net::dispatch_compact_body_reply(
                                            &peer_key,
                                            ConsensusMsg::Body { body },
                                            &counters,
                                            |peer, msg| async move {
                                                match net_unicast.send_to_peer(peer, &msg).await {
                                                    Ok(()) => Ok(()),
                                                    Err(e) => Err((msg, e)),
                                                }
                                            },
                                            |msg| {
                                                enqueue_outbox(&mut outbox, msg);
                                                flush_outbox(
                                                    &net_sender,
                                                    &mut outbox,
                                                    rt.hc.height,
                                                    rt.hc.round,
                                                );
                                                outbox_flushes += 1;
                                                last_flush = std::time::Instant::now();
                                            },
                                        )
                                        .await;
                                    if let stellereum::consensus_net::BodyReplyRoute::BoundedBroadcast(
                                        why,
                                    ) = route
                                    {
                                        tracing::debug!(
                                            "[consensus] compact body reply #{} r{} used the bounded broadcast ({why:?})",
                                            pull.height,
                                            pull.round,
                                        );
                                    }
                                    compact_served += 1;
                                    if compact_served == 1 {
                                        info!(
                                            "[consensus] compact gossip LIVE: first body pull served from the announced block"
                                        );
                                    }
                                }
                                // We did not announce that block, or this
                                // (peer, pull) was already answered: silence.
                                Ok(None) => {}
                                Err(why) => {
                                    inbound_compact_refused += 1;
                                    if inbound_compact_refused % 20 == 1 {
                                        tracing::warn!(
                                            "[consensus] refused compact body pull #{} r{}: {why}",
                                            pull.height,
                                            pull.round,
                                        );
                                    }
                                }
                            }
                        }
                        // Complete a parked resolution with the served body.
                        ConsensusMsg::Body { body } => {
                            let over = {
                                let count =
                                    compact_peer_frames.entry(peer_key.clone()).or_insert(0);
                                !compact_frame_within_peer_budget(
                                    count,
                                    COMPACT_FRAMES_PER_PEER_PER_TICK,
                                )
                            };
                            if over {
                                compact_budget_dropped += 1;
                                continue;
                            }
                            // Cheap first: no parked proposal => no mempool
                            // clone and no index build (C2/F-8).
                            let Some(header) = compact_rx.parked_header(&body.block_hash).cloned()
                            else {
                                inbound_compact_refused += 1;
                                tracing::debug!(
                                    "[consensus] compact body for an un-parked proposal {} (ignored before mempool work)",
                                    hex::encode(&body.block_hash[..6]),
                                );
                                continue;
                            };
                            let now = Instant::now();
                            let cached = compact_index.get(&header, now).is_some();
                            let index = if cached {
                                compact_index.get(&header, now).expect("just checked")
                            } else {
                                let txs = rt.mempool.read().await.all();
                                compact_index.insert(&header, txs, now)
                            };
                            let inbound = compact_rx.on_body_indexed(&body, index);
                            settle_compact!(inbound, &peer_key);
                        }
                        ConsensusMsg::Proposal {
                            round: r, block, ..
                        } => {
                            info!(
                                "[consensus] RX proposal from {} #{} r{}",
                                hex::encode(&block.proposer[..6]),
                                block.height,
                                r
                            );
                            // Deliberately NOT advancing our round to match a peer's
                            // claim. A node advances rounds on its own 3s timeout
                            // (next_round), and nothing else. Syncing to a peer's
                            // claimed round sounds harmless but is what wedged the
                            // two-machine stand: one node timed out a round before the
                            // other, the follower adopted the leader's round, the
                            // leader then timed out again, and they drifted apart by
                            // one round permanently. At an offset of one, each
                            // expects the other to propose, every proposal is refused
                            // as "wrong proposer", the follower prevotes nil, and no
                            // prevote+precommit quorum for the same block ever forms.
                            // Local timeouts are the single source of round changes.
                            let proposer = block.proposer;
                            let height = block.height;
                            let round_of_block = r;
                            // Signature + membership check, computed ONLY when a
                            // consumer below needs it (a future proposal, the
                            // H+1 parent hint, or a behind peer). A proposal at
                            // OUR height is verified inside `on_proposal`, so
                            // the normal path pays no extra Falcon verification.
                            let needs_attribution = named_ahead.is_some()
                                || height < rt.hc.height
                                || (height == rt.hc.height + 1 && !rt.has_pending_apply());
                            let proposal_admissible = !needs_attribution
                                || stellereum::consensus_net::proposal_hint_admissible(
                                    &block,
                                    &rt.validators,
                                );
                            // Height-ahead deferral: peer finalized and proposed for H+1 while
                            // we are still applying H (or in tick transition). Defer instead of
                            // dropping, so H+1 proposals execute immediately on the next tick!
                            if height == rt.hc.height + 1 {
                                if rt.has_pending_apply() {
                                    if inbound_deferred.len() < INBOUND_DEFERRED_CAP {
                                        let wake_at = Instant::now() + Duration::from_millis(10);
                                        let pos = inbound_deferred
                                            .iter()
                                            .position(|(w, _)| *w > wake_at)
                                            .unwrap_or(inbound_deferred.len());
                                        inbound_deferred.insert(pos, (wake_at, raw));
                                    }
                                    continue 'drain;
                                } else if block.height > 0 {
                                    // We are not applying H: we missed block H! Record peer hint immediately
                                    // so try_catch_up can pull block H without waiting.
                                    //
                                    // VERIFICATION G1: the hint forces the
                                    // catch-up machine to run, so it must be
                                    // attributable — only a proposal with a valid
                                    // proposer signature from a staked member
                                    // plants it. A forged H+1 proposal previously
                                    // set this before any verification, keeping
                                    // the node on loudly-failing DHT walks.
                                    if proposal_admissible {
                                        let h = (block.height - 1, block.prev_hash);
                                        if rt.peer_hint.map(|(ph, _)| ph < h.0).unwrap_or(true) {
                                            rt.peer_hint = Some(h);
                                            peer_hint_at = Some(std::time::Instant::now());
                                        }
                                    }
                                }
                            }
                            // REACTIVE CATCH-UP TRIGGER (proposal): a VERIFIED
                            // proposal for a height above ours proves its author
                            // advanced ahead of us (it is building where we have
                            // not arrived). Same admissibility verdict as the
                            // parent hint above, so a forged far-ahead proposal
                            // can never drive DHT work. The latch is consumed at
                            // the NEXT tick top, not on the backstop timer.
                            if named_ahead.is_some() && proposal_admissible {
                                // A proposal AT height H says the author's
                                // FINALIZED tip is at least H-1 (the parent it
                                // builds on) — that is the at-tip evidence.
                                let tip = rt.finalized.last().map(|(h, _)| *h).unwrap_or(0);
                                peer_named_height = clamp_peer_named_height(
                                    tip,
                                    peer_named_height.max(height.saturating_sub(1)),
                                );
                                catchup_pending = true;
                                stellereum::rpc::note_peer_height(height);
                            }
                            // Behind-peer retro gate: a VERIFIED proposal
                            // (signature + membership) from below our height
                            // proves a lagging peer is talking — the only
                            // consumer a retro push can serve.
                            if height < rt.hc.height && proposal_admissible {
                                last_behind_peer_seen = Some(std::time::Instant::now());
                            }
                            match rt.on_proposal(proposer, block, round_of_block).await {
                                Ok(_) => {
                                    // VEL-2 vote-fan-in pipeline: vote in the SAME
                                    // drain instead of waiting for the next tick's
                                    // prevote step, overlapping the r-prevote
                                    // fan-in with the proposal processing that
                                    // triggered it. Timing-only: the vote content
                                    // is identical to what the next-tick step
                                    // would cast (same round — no timeout fires
                                    // mid-drain — same live proposal, same lock,
                                    // same `make_prevote`), the once-per-round
                                    // dedup (`last_prevoted`) is shared with that
                                    // step so no double vote is possible, and QCs
                                    // stay strictly per-round, so quorum
                                    // intersection is untouched: earlier arrival
                                    // can only form the same QC sooner, never a
                                    // different one. Refused proposals (the Err
                                    // arm) never vote.
                                    let cast_round = rt.prevote_round();
                                    if can_vote
                                        && rt.hc.has_live_proposal()
                                        && last_prevoted != Some((rt.hc.height, cast_round))
                                        && !round_at_or_below_vote_floor(
                                            vote_floor,
                                            rt.hc.height,
                                            cast_round,
                                        )
                                    {
                                        if let Some(v) = rt.make_prevote() {
                                            persist_vote_watermark_before_broadcast(
                                                persistence.as_ref(),
                                                &v,
                                            );
                                            advance_vote_floor(&mut vote_floor, v.height, v.round);
                                            let _ = rt.on_prevote(v.clone());
                                            enqueue_outbox(
                                                &mut outbox,
                                                ConsensusMsg::Vote {
                                                    vote: v.clone(),
                                                    locked: lock_hint(&rt, &v),
                                                },
                                            );
                                            flush_outbox(
                                                &net_sender,
                                                &mut outbox,
                                                rt.hc.height,
                                                rt.hc.round,
                                            );
                                            outbox_flushes += 1;
                                            last_flush = std::time::Instant::now();
                                            let voted_round = v.round;
                                            cast_prevote = Some(v);
                                            last_prevoted =
                                                Some((rt.hc.height, voted_round));
                                        }
                                    }
                                }
                                Err(e) => {
                                    // Never swallow this: a rejected proposal is the
                                    // difference between liveness and a silent stall.
                                    tracing::warn!(
                                        "[consensus] rejected proposal from {} at #{} r{}: {}",
                                        hex::encode(&proposer[..6]),
                                        height,
                                        round_of_block,
                                        e
                                    );
                                }
                            }
                        }
                        ConsensusMsg::Vote { vote: v, locked } => {
                            info!(
                                "[consensus] RX {:?} from {} #{} r{} target {}",
                                v.kind,
                                hex::encode(&v.voter[..6]),
                                v.height,
                                v.round,
                                v.block_hash
                                    .map(|h| hex::encode(&h[..4]))
                                    .unwrap_or_else(|| "nil".into())
                            );
                            // Audit F2/F9: authenticate FIRST. `on_prevote` /
                            // `on_precommit` run `Vote::verify` plus the
                            // membership/scope checks inside `VoteSet::add`. An
                            // unauthenticated (height, round) or lock hint must
                            // NEVER reach the round counter: a Batch of 32 junk
                            // votes previously moved our round up to 2048 rounds
                            // (MAX_SYNC_JUMP=64 each) with zero signatures, and a
                            // forged nil prevote could plant a lock hint.
                            let (vh, vk, vr, vbh, voter) =
                                (v.height, v.kind, v.round, v.block_hash, v.voter);
                            // Height-ahead deferral: peer cast a vote for H+1 while
                            // we are still finishing H. Defer so it applies immediately on H+1!
                            if vh == rt.hc.height + 1 && rt.has_pending_apply() {
                                if inbound_deferred.len() < INBOUND_DEFERRED_CAP {
                                    let wake_at = Instant::now() + Duration::from_millis(10);
                                    let pos = inbound_deferred
                                        .iter()
                                        .position(|(w, _)| *w > wake_at)
                                        .unwrap_or(inbound_deferred.len());
                                    inbound_deferred.insert(pos, (wake_at, raw));
                                }
                                continue 'drain;
                            }
                            let round_before = rt.hc.round;
                            let vcopy = v.clone();
                            let accepted = match vk {
                                VoteKind::Prevote => rt.on_prevote(v).is_ok(),
                                VoteKind::Precommit => rt.on_precommit(v).is_ok(),
                            };
                            // Falcon verification is the expensive part and the
                            // refusal branches below only need the VERDICT:
                            // signature plus staked membership. ACCEPTED votes
                            // were already verified inside
                            // `on_prevote`/`on_precommit`, so this runs on the
                            // refusal path only (unchanged cost profile).
                            if !accepted {
                                let vote_verified =
                                    vcopy.verify() && rt.validators.power_of(&vcopy.voter) != 0;
                                // Scope/signature failure: the vote does NOT count
                                // toward any quorum. BUT a verified same-height
                                // vote still feeds the peer-round counter
                                // (`ValidatorRuntime::observe_peer_vote` already
                                // ran inside `on_prevote`/`on_precommit`): a
                                // stale far-behind vote or an absurd far-ahead
                                // vote is true information about where the peer
                                // is, and dropping it is what wedged A r1550 vs
                                // B r318 forever (live 2026-10-14). Only verified
                                // votes update liveness/timer state here.
                                if vh == rt.hc.height && vote_verified {
                                    // Verified same-height vote (down-proposer
                                    // fast timeout): the voter is provably alive
                                    // right now, even though this vote itself is
                                    // not votable (stale round / too far ahead).
                                    votes_seen_voters.insert(vcopy.voter);
                                    peer_round_seen = Some((vh, vr, std::time::Instant::now()));
                                    if rt.hc.round != round_before {
                                        round_started = std::time::Instant::now();
                                    }
                                }
                                // REACTIVE CATCH-UP TRIGGER (vote): a verified
                                // vote at a height above ours proves the voter's
                                // chain is ahead — it is voting where we have not
                                // arrived. Signature + membership checked, so an
                                // unverified claim never drives DHT work.
                                if named_ahead.is_some() && vote_verified {
                                    // A vote AT height H says the voter has
                                    // decided H-1 at least — at-tip evidence.
                                    let tip = rt.finalized.last().map(|(h, _)| *h).unwrap_or(0);
                                    peer_named_height = clamp_peer_named_height(
                                        tip,
                                        peer_named_height.max(vh.saturating_sub(1)),
                                    );
                                    catchup_pending = true;
                                    stellereum::rpc::note_peer_height(vh);
                                }
                                // Behind-peer retro gate: a VERIFIED vote from
                                // below our height proves a lagging peer is
                                // talking — the only consumer a retro push can
                                // serve. Forged votes never land here (unverified),
                                // so an attacker cannot wake retro — worst case a
                                // real behind peer keeps it awake.
                                if vh < rt.hc.height && vote_verified {
                                    last_behind_peer_seen = Some(std::time::Instant::now());
                                }
                                continue;
                            }
                            // Verified-only height fast path: this vote passed
                            // signature + membership + scope checks, so a height
                            // above ours proves a peer finalized ahead of us.
                            // (Down-proposer fast timeout: an ACCEPTED vote is the
                            // strongest aliveness proof — record the voter before
                            // any of the bookkeeping below.)
                            if vh == rt.hc.height {
                                votes_seen_voters.insert(voter);
                            }
                            // Behind-peer retro gate: an ACCEPTED vote passed
                            // signature + membership + scope, so a height below
                            // ours proves a lagging peer is talking — stamp it.
                            if vh < rt.hc.height {
                                last_behind_peer_seen = Some(std::time::Instant::now());
                            }
                            // REACTIVE CATCH-UP TRIGGER (vote): an ACCEPTED vote
                            // for a height above ours is attributable evidence
                            // that the network moved on. Latch it; the next tick
                            // top runs the catch-up instead of waiting out the
                            // backstop interval while we burn view changes
                            // collecting "wrong height".
                            if named_ahead.is_some() {
                                let tip = rt.finalized.last().map(|(h, _)| *h).unwrap_or(0);
                                peer_named_height = clamp_peer_named_height(
                                    tip,
                                    peer_named_height.max(vh.saturating_sub(1)),
                                );
                                catchup_pending = true;
                                stellereum::rpc::note_peer_height(vh);
                            }
                            // A nil prevote carrying the sender's locked hash is a
                            // rescue request: it is stuck on one of OUR values.
                            // `note_lock_hint` resolves the (possibly older)
                            // signed hash to the round-free value id and records
                            // the demand; our next proposer slot re-stamps that
                            // value at the current round (see
                            // `ValidatorRuntime::propose`).
                            rt.note_lock_hint(vh, vk, vbh, locked);
                            // Adopt a peer's round when it is ahead, so the two stay in the
                            // same PHASE.
                            //
                            // This is subtle with an even validator count. `proposer_for`
                            // hash-schedules per round, so two validators walking their
                            // rounds independently still meet rounds where neither is
                            // the scheduled proposer while each waits for a proposal
                            // in its own round: every proposal is rejected as
                            // "wrong proposer", and the height never finalises --
                            // observed live as r78/r73, r80/r75, all "wrong proposer",
                            // forever. (Pre-hash-slot the schedule even alternated by
                            // round parity, making opposite phases PERMANENT.)
                            //
                            // Catching up one round at a time cannot fix that, because the
                            // offset (and its parity) is preserved. A node must move to the
                            // round its peers are in. `sync_round_to` is bounded (to
                            // ROUND_LOOKBACK rounds per message) and only moves forward,
                            // so this cannot drag a node backwards or jump it unreachably
                            // far; it only runs for a vote that already verified.
                            if vh == rt.hc.height {
                                peer_round_seen = Some((vh, vr, std::time::Instant::now()));
                                // SAME-VALUE COHERENCE: a vote for the body we
                                // already hold pulls us to the round the
                                // network is voting it in, and keeps the
                                // proposal live there; other votes use the
                                // conservative corroborated chase.
                                if rt.note_peer_vote_round_for(vh, vr, vbh) {
                                    // The round moved under us: restart the round
                                    // timer. Without this the elapsed-time check
                                    // already exceeded the timeout, so on the very
                                    // next tick the node view-changed straight past
                                    // the peer it had just aligned with -- measured
                                    // live as a view change 269ms after syncing.
                                    round_started = std::time::Instant::now();
                                }
                            }
                        }
                        ConsensusMsg::Committed {
                            height,
                            block,
                            certificate,
                        } => {
                            // PUSH-BASED PROPAGATION, receive side: a commit for
                            // a height ABOVE ours is peer evidence that the
                            // network finalized ahead of us. It cannot be adopted
                            // in place (`adopt_committed` requires OUR exact next
                            // height), so schedule catch-up NOW — reacting to the
                            // push is the whole point; waiting for the backstop
                            // timer is what stranded lagging nodes.
                            //
                            // ATTRIBUTION: only a commit whose certificate is a
                            // precommit quorum for THIS height and block, under
                            // the validator set in force at that height, may
                            // drive DHT work (and plant the head hint). A forged
                            // far-ahead commit is ignored here.
                            //
                            // "Above ours" is measured against our FINALIZED TIP,
                            // not `hc.height`: a commit for the height we are
                            // currently voting on is still one block ahead of what
                            // we have decided (and adopt refuses it when it does
                            // not extend our tip — the refusal must not strand
                            // us on the backstop timer).
                            let our_tip = rt.finalized.last().map(|(h, _)| *h).unwrap_or(0);
                            if height > our_tip {
                                // CHEAP HEIGHT GATE FIRST (F-5): `Committed` is
                                // byte-limiter-exempt and may carry a 32 MiB
                                // block plus thousands of µQC markers. A
                                // far-ahead height is not adoptable under ANY
                                // certificate (`adopt_committed` refuses it),
                                // so do not hash the block or verify the QC;
                                // the DHT head/walk is the catch-up path.
                                if !committed_height_is_cheaply_relevant(our_tip, height) {
                                    inbound_overcap_count += 1;
                                    if inbound_overcap_count % 20 == 1 {
                                        tracing::warn!(
                                            "[sync][push] ignoring far-ahead commit #{height} (tip #{our_tip}, max lookahead {MAX_COMMITTED_LOOKAHEAD}) BEFORE QC verification; {inbound_overcap_count} time(s)"
                                        );
                                    }
                                    // Still let `adopt_committed` cheaply refuse
                                    // it below (it checks height first); no
                                    // crypto was paid here.
                                    continue;
                                } else {
                                    let block_hash = block.compute_hash();
                                    let proven = certificate.kind == VoteKind::Precommit
                                        && certificate.height == height
                                        && certificate.block_hash == Some(block_hash)
                                        && certificate.verify_with_schedule(
                                            &rt.validator_set_for_height(height),
                                            rt.committee_schedule_at(height),
                                        );
                                    if proven {
                                        peer_named_height = clamp_peer_named_height(
                                            our_tip,
                                            peer_named_height.max(height),
                                        );
                                        if rt.peer_hint.map(|(ph, _)| ph < height).unwrap_or(true) {
                                            rt.peer_hint = Some((height, block_hash));
                                            peer_hint_at = Some(std::time::Instant::now());
                                        }
                                        catchup_pending = true;
                                        stellereum::rpc::note_peer_height(height);
                                        info!(
                                            "[sync][push] peer committed #{height} ahead of our tip #{our_tip}: catch-up scheduled for the next tick"
                                        );
                                    } else {
                                        tracing::debug!(
                                            "[sync][push] ignoring commit at #{height} above our tip #{our_tip}: certificate does not prove it"
                                        );
                                    }
                                }
                            }
                            // §7 Phase 2: adopting means executing, and the worker
                            // is still applying the decided height. The message is
                            // dropped, not queued: the peer rebroadcasts the commit
                            // at its next finalize and the periodic catch-up
                            // re-walks the same body, so a one-tick deferral loses
                            // nothing and can never double-apply a height.
                            if rt.has_pending_apply() {
                                info!(
                                "[consensus] deferring peer commit at #{height}: apply still in flight"
                            );
                                continue;
                            }
                            // A peer already committed this height. Adopt it (after
                            // checking the certificate) so a node that missed the
                            // deciding vote does not stall behind the network.
                            // `adopt_committed` checks the certificate against our own
                            // validator set internally, so a peer cannot nominate the
                            // quorum it is measured against.
                            match rt.adopt_committed(height, block.clone(), certificate).await {
                                Ok(bh) => {
                                    // Verified commit (QC checked inside adopt):
                                    // feed the syncing signal too (audit follow-up).
                                    stellereum::rpc::note_peer_height(height);
                                    // The live flow just delivered: stamp it so the
                                    // tick-top defer above keeps the DHT machine off
                                    // these heights even when the next Committed is
                                    // still in transit at the next tick top.
                                    last_live_adopt = std::time::Instant::now();
                                    // LIVE-ADOPT PUBLISH OFFLOAD (observer C, 2026-10-13):
                                    // `store_blob` can wait seconds for a replica. Awaited
                                    // here it held the drain while more Committed messages
                                    // queued behind it — ~30s/block at 1 block/s chain tempo
                                    // on empty blocks (execution trivial, publishes dominant).
                                    // Same order as the finalize path (body then header),
                                    // but on `publish_lane`: the tick keeps draining and the
                                    // next height adopts immediately.
                                    if let Some(body) = rt.blocks.get(&bh).cloned() {
                                        let a = adapter.clone();
                                        let shard_id = block_shard;
                                        publish_lane.submit(async move {
                                            let _ = a.retro_publish_blocks([&body], 1).await;
                                            a.persist_block_header(shard_id, &body).await;
                                        });
                                    }
                                    // Replication for adopters (bodies + receipts):
                                    // the adopted block carries its transactions
                                    // (adopt verified their signatures) and
                                    // `rt.applied_statuses` holds THIS application's
                                    // outcome (set by adopt's apply_and_advance).
                                    // File both so adopters serve real txs/receipts
                                    // instead of txs=0. Verified data only: the
                                    // block passed adopt_committed's QC/proposer/
                                    // root checks. Records ride `record_lane` (the
                                    // same FIFO the finalize path uses: receipts
                                    // before the block summary inside one job,
                                    // heights in order across jobs) instead of two
                                    // contended write locks awaited inline while
                                    // more Committed messages queue behind them.
                                    // The body itself is persisted by
                                    // `enqueue_block` below (async, finalize-path
                                    // parity): the synchronous sled
                                    // `committed_body` + `put_verified_block` round
                                    // trip that used to sit here re-hashed the block
                                    // twice and held the drain on disk I/O for bytes
                                    // the queue already carries. A not-yet-persisted
                                    // body is an honest serve-miss (fetch covers it),
                                    // never fabricated data.
                                    if rt.applied_statuses.len() == block.transactions.len() {
                                        let r = rpc.clone();
                                        let txs = block.transactions.clone();
                                        let statuses = rt.applied_statuses.clone();
                                        let fees = rt.applied_fees.clone();
                                        let events = rt.applied_events.clone();
                                        let ts = block.timestamp;
                                        let hdr = block.clone();
                                        record_lane.submit(async move {
                                            // LIGHT CLIENT (audit W8.3): the
                                            // adopted header's quorum certificate
                                            // is what makes its state root
                                            // externally verifiable.
                                            r.record_finalized_header(&hdr).await;
                                            r.record_adopted_block_with_events(
                                                height, bh, &txs, &statuses, &fees, &events, ts,
                                            )
                                            .await;
                                        });
                                    } else {
                                        eprintln!(
                                        "[repl] adopt #{}: statuses {}/{} txs, receipts skipped",
                                        height,
                                        rt.applied_statuses.len(),
                                        block.transactions.len()
                                    );
                                    }
                                    info!(
                                        "[consensus] adopted committed block #{} {} from a peer",
                                        height,
                                        hex::encode(&bh[..6])
                                    );
                                    // New height, new round timer: an adopted block
                                    // advanced us without a view change, so a stale
                                    // timer would fire a view change within
                                    // milliseconds and drop the peer's first vote
                                    // (live: 269ms from adopt to view change).
                                    round_started = std::time::Instant::now();
                                    // Persist adopted bodies like finalized ones:
                                    // they are anchor material for snapshot
                                    // verification and healing sources after a
                                    // restart. Without this, every adopted height
                                    // leaves a hole that refuses the next start.
                                    if let Some(ap) = &persistence {
                                        ap.enqueue_block(block);
                                    }
                                }
                                Err(e) => {
                                    info!("[consensus] refused peer commit at #{}: {}", height, e)
                                }
                            }
                        }
                    }
                }
            }
        }
        // SEC-06: deferred messages already reside in `inbound_deferred` with
        // their scheduled `wake_at` times; no re-parking needed.

        // FAIL-LOUD LIVENESS ALARM (audit note: a production validator sat
        // isolated 18 days on the wrong pubsub topic — zero votes/proposals,
        // nothing in any log). A validator with configured peers that
        // consumes no Proposal/Vote for the silence threshold screams on
        // stderr (throttled to one line per minute) instead of churning
        // silently. Liveness-only: reads clocks/counters, never touches
        // consensus, the wire, or quorum accounting. `can_vote` is the exact
        // franchise the propose/prevote gates above used — reused, not
        // reinvented — so observers and stale-set nodes stay silent by
        // construction, as do solo stands (no configured peers).
        {
            let peer_count = adapter.node.cfg.peers.len();
            let now_ms = liveness_alarm::now_ms();
            if liveness_alarm::should_liveness_alarm(
                last_consensus_rx_ms,
                now_ms,
                can_vote,
                peer_count,
                liveness_alarm::liveness_alarm_silence_ms(),
            ) && liveness_alarm::liveness_alarm_due(last_liveness_emit_ms, now_ms)
            {
                last_liveness_emit_ms = Some(now_ms);
                liveness_alarm::note_liveness_alarm();
                let n = liveness_alarm::liveness_alarm_count();
                let silent_s = now_ms.saturating_sub(last_consensus_rx_ms) / 1000;
                eprintln!(
                    "[liveness] ALARM #{n}: validator with {peer_count} configured peer(s) received no consensus Proposal/Vote for {silent_s}s; possible pubsub-topic isolation (e.g. wrong single-shard vs sharded topic) — check network/topic config"
                );
            }
        }

        // EVENT-DRIVEN CATCH-UP latch (round efficiency, no safety change):
        // the drain sets `catchup_pending` only on VERIFIED evidence that a
        // peer is ahead — a commit whose precommit quorum proves it, a
        // proposal that passed the proposer signature + membership check, a
        // vote that passed signature + membership (with or without joining a
        // quorum), or a peer head hint above our tip. The next tick top
        // consumes it (see `catchup_action`) and runs the attempt immediately,
        // instead of waiting out the backstop interval while burning view
        // changes at a stale height collecting "wrong height" rejects (154
        // view changes/10min live). The walk itself still verifies the full
        // chain (QC per height, anchored on our finalized head), so a false
        // hint costs at most one loudly-failing walk.
        //
        // A verified peer height above our tip is PERSISTENT evidence: keep
        // the latch armed so a node that stays behind retries (paced by
        // `REACTIVE_CATCHUP_MIN_GAP_MS`), never the timer. F-9: Vote and
        // far-ahead Proposal evidence only set `peer_named_height`, so testing
        // the hint alone dropped that evidence to the 30 s backstop after one
        // failed attempt.
        {
            let tip = rt.finalized.last().map(|(h, _)| *h).unwrap_or(0);
            peer_named_height = clamp_peer_named_height(tip, peer_named_height);
            if rt.peer_hint.is_some_and(|(ph, _)| ph > tip) || peer_named_height > tip {
                catchup_pending = true;
            }
        }

        // 4. precommit once a prevote quorum exists
        //
        // The vote is stamped with the POLKA's round (which may be behind our
        // local round when the two nodes are skewed), so the dedup key is
        // (height, v.round): casting per LOCAL round either skipped the cast
        // entirely when the QC sat one round back (the "prevote QC but no
        // precommit" case that cost 31 of 180 rounds live) or duplicated it.
        if can_vote {
            if let Some(v) = rt.make_precommit() {
                // FLOOR: a precommit is stamped with the POLKA's round, which
                // may be older than the local round — and after a crash the
                // node must not re-enter a round it already PRECOMMITTED in.
                // Compare the PRECOMMIT floor, not the prevote/union floor:
                // a late polka's round can be below a nil prevote this node
                // already signed, and precommitting it is a different
                // (height, round, kind) statement. See `precommit_floor`.
                if last_precommitted != Some((height, v.round))
                    && !round_at_or_below_vote_floor(precommit_floor, height, v.round)
                {
                    persist_vote_watermark_before_broadcast(persistence.as_ref(), &v);
                    advance_vote_floor(&mut vote_floor, v.height, v.round);
                    advance_vote_floor(&mut precommit_floor, v.height, v.round);
                    let _ = rt.on_precommit(v.clone());
                    // P3-H4: guards are set at ENQUEUE time (same reason as prevotes).
                    enqueue_outbox(
                        &mut outbox,
                        ConsensusMsg::Vote {
                            vote: v.clone(),
                            locked: None,
                        },
                    );
                    flush_outbox(&net_sender, &mut outbox, rt.hc.height, rt.hc.round);
                    outbox_flushes += 1;
                    last_flush = std::time::Instant::now();
                    cast_precommit = Some(v.clone());
                    last_precommitted = Some((height, v.round));
                    // Persist the lock so a restart cannot double-vote this height.
                    if let (Some(ap), Some((lh, lr))) = (&persistence, rt.hc.locked) {
                        let (fh, fhash) = rt.finalized.last().copied().unwrap_or((0, [0u8; 32]));
                        ap.enqueue_consensus(stellereum::storage::ConsensusCheckpoint {
                            height,
                            round,
                            locked_hash: Some(lh),
                            locked_round: lr,
                            finalized_height: fh,
                            finalized_hash: fhash,
                        });
                    }
                }
            }
        }

        // 5. finalize on a precommit quorum — §7 Phase 2 sequenced lane.
        //
        // `try_finalize_submit` DECIDES (quorum + body + order + actor-cap
        // gates, QC attach, decision-proof stash) and queues the execution on
        // the single ordered worker WITHOUT awaiting it, so this loop keeps
        // draining inbound messages while the block applies. `try_poll_apply`
        // below installs the outcome the moment the worker reports back —
        // that is the only place post-H state becomes observable — and runs
        // the publishes, records and persistence that used to follow the
        // inline apply. `propose` for the next height, the proposal root
        // check and the commit broadcast all wait for it (stage-1 gate,
        // `apply_in_flight` checks in the runtime).
        if let Some(decided) = rt.try_finalize_submit().await {
            info!(
                "[consensus] DECIDED block #{} {} (execution queued on the sequenced worker)",
                height,
                hex::encode(&decided[..6]),
            );
        }
        if let Some(completed) = rt.try_poll_apply().await {
            // The executed height: the tick-top `height` cannot have moved
            // past it (the height advance happens right here), but naming it
            // keeps every line below honest about what it publishes.
            let height = completed.height;
            let bh = completed.hash;
            let root = completed.root;
            // Governed fee floor (audit follow-up): admission floor =
            // max(frozen, governed), refreshed every finalized height so a passed
            // SetMinGasLimit takes effect network-wide without restarts.
            // Frozen floor stays the boot default; governance can only raise.
            {
                let gov_floor = rt
                    .state
                    .governance_read()
                    .await
                    .applied
                    .min_gas_limit
                    .unwrap_or(0);
                let env_floor = stellereum::mempool::Mempool::frozen_base_fee_floor();
                let want = env_floor.max(gov_floor);
                let mut mp = rpc.mempool.write().await;
                if mp.base_fee != want {
                    info!("[config] admission base_fee floor {0} -> {want} (frozen={env_floor} governed={gov_floor})", mp.base_fee);
                    mp.base_fee = want;
                }
            }
            info!(
                "[consensus] FINALIZED block #{} {} (state root {})",
                height,
                hex::encode(&bh[..6]),
                hex::encode(&root[..6])
            );
            // Local finalization proves live chain progress just as much as
            // `adopt_committed`: refreshing `last_live_adopt` prevents
            // synchronous `try_catch_up` DHT probes from stalling active rounds.
            last_live_adopt = std::time::Instant::now();
            // Republish the head pointer on every finalize, so a peer that is
            // behind can discover where we are. The local KV head is useless to
            // peers (see P2pNetworkAdapter::publish_head), this is the one they
            // can read.
            //
            // §7 Phase 1: these three used to be awaited `request_to`/DHT round
            // trips ON the tick (hundreds of ms each, and `store_blob` can wait
            // for a replica). They are submitted to `publish_lane` instead,
            // which runs them one at a time in submission order -- head, then
            // body, then header, exactly the order awaiting gave them.
            {
                let a = adapter.clone();
                let shard_id = block_shard;
                publish_lane.submit(async move {
                    a.publish_head(shard_id, height, bh).await;
                });
            }
            // Publish the fresh body immediately: the retro-publish cursor
            // works bottom-up and reaches the tip last, so without this a peer
            // that is exactly one block behind waits the whole window for the
            // single body it needs -- observed live as a permanent 1-height
            // stall with the body merely unpublished, never missing.
            if let Some(block) = rt.blocks.get(&bh).cloned() {
                let a = adapter.clone();
                let shard_id = block_shard;
                let h = block.height;
                publish_lane.submit(async move {
                    let _ = a.retro_publish_blocks([&block], 1).await;
                    // Publish the HEADER at every height too. The snapshot anchor
                    // (F1) walks headers from our finalized head to the snapshot's
                    // successor; that walk can only be proven if a header exists at
                    // every height, not just at 100-block snapshot boundaries.
                    a.persist_block_header(shard_id, &block).await;
                });
                // Retention prune rides its OWN lane (audit 2026-10-06, own lane
                // since the live-adopt tempo fix): on publish_lane it queued
                // behind replica-waiting store_blob jobs (seconds each), and on
                // record_lane its fetch_blob fan-out held every receipt behind
                // it — so one slow peer starved either lane with no
                // throttle-vs-starve distinction. prune_lane carries only this
                // pass; the pass itself is throttled (100 heights) and capped
                // inside maybe_prune_retained, and the guard keeps passes from
                // piling up.
                {
                    let a = adapter.clone();
                    let shard_id = block_shard;
                    let g = prune_lane_guard.clone();
                    prune_lane.submit(async move {
                        if g.swap(true, std::sync::atomic::Ordering::Relaxed) {
                            return;
                        }
                        a.maybe_prune_retained(shard_id, h).await;
                        g.store(false, std::sync::atomic::Ordering::Relaxed);
                    });
                }
            }
            // Tell peers what we committed. A node that missed the deciding
            // vote would otherwise never learn the outcome and would stall
            // behind us at this height forever. Reads the stashed decision
            // proof (`try_finalize` resets `hc`, so the proof must be read
            // from the stash, never from `hc.precommit_qc` afterwards).
            //
            // IMPORTANT (W10.5): NEVER clear `rt.last_decision` here — `propose()`
            // (`decided_parent_qc()`) and `check_last_qc_evidence()` depend on
            // `last_decision` holding `(height, block, qc)` for height + 1; clearing
            // it caused the next proposer to emit `last_qc: None` and trigger
            // `omits the downtime evidence` view-change stalls.
            if let Some((dh, block, certificate)) = rt.last_decision.clone() {
                if dh == height {
                    // PUSH-BASED PROPAGATION (Task 1): the commit goes to
                    // EVERY directly connected validator peer NOW, on its own
                    // detached task — not through the batched outbox FIFO,
                    // where it could queue behind votes/proposals behind a
                    // slow peer, and not via the DHT, where a lagging peer
                    // would only see it on its next poll. `ConsensusNetwork`
                    // delivers `pubsub.msg` per peer concurrently and logs
                    // every outcome; the DHT publication below (head pointer,
                    // body, header) is unchanged and remains the slow path.
                    spawn_committed_push(&net, height, block, certificate);
                }
            }
            // Publish the finalized block to the RPC/explorer height + feed, and
            // file a receipt per transaction so wallets can confirm.
            //
            // §7 Phase 1: submitted to `record_lane`, a FIFO lane of its own.
            // Both records are LOCAL (a lock and a vec push -- no `request_to`;
            // the round trips on this path are the publishes above), but they
            // still leave the tick, and the lane's FIFO is what preserves the
            // ordering RPC readers depend on: receipts for height H are filed
            // before `record_block(H)` publishes H, and the whole batch for H
            // runs before the batch for H+1, so the moment a reader sees
            // height H+1 every earlier receipt is already in the index.
            let block_ts = now_secs();
            if let Some(block) = rt.blocks.get(&bh).cloned() {
                let tx_count = block.transactions.len();
                // Use the statuses captured when the block was ACTUALLY applied;
                // re-applying here would execute every transaction a second time.
                let statuses = std::mem::take(&mut rt.applied_statuses);
                let fees = std::mem::take(&mut rt.applied_fees);
                let events = std::mem::take(&mut rt.applied_events);
                let r = rpc.clone();
                record_lane.submit(async move {
                    // LIGHT CLIENT (audit W8.3): publish the finalized header
                    // with its quorum certificate, so an external verifier can
                    // check a served proof against a root a QUORUM committed
                    // to.
                    r.record_finalized_header(&block).await;
                    r.record_receipts_with_events(
                        height,
                        bh,
                        &block.transactions,
                        &statuses,
                        &fees,
                        &events,
                    )
                    .await;
                    r.record_block(height, bh, tx_count, block_ts).await;
                });
            } else {
                let r = rpc.clone();
                record_lane.submit(async move {
                    r.record_block(height, bh, 0, block_ts).await;
                });
            }
            // Persist asynchronously: never block consensus on disk I/O.
            if let Some(ap) = &persistence {
                if let Some(block) = rt.blocks.get(&bh).cloned() {
                    ap.enqueue_block(block);
                }
                ap.enqueue_finalized(height, bh);
                // Periodic durability barrier (async, no consensus stall):
                // bounds the loss window on kill to a handful of heights so a
                // restart can heal from peers instead of refusing to run.
                if height % 25 == 0 {
                    ap.request_flush();
                }
                // Clear the lock for the next height in the checkpoint.
                ap.enqueue_consensus(stellereum::storage::ConsensusCheckpoint {
                    height: height + 1,
                    round: 0,
                    locked_hash: None,
                    locked_round: 0,
                    finalized_height: height,
                    finalized_hash: bh,
                });
                // Check if an on-chain governed software upgrade is scheduled for this height.
                let upgrade_plan = rt
                    .state
                    .governance_read()
                    .await
                    .applied
                    .upgrade_plan
                    .clone();
                if let Some(plan) = upgrade_plan {
                    // MISSED-EVENT SAFETY: `==` made the halt an EVENT — a node
                    // that was offline at the plan height, or that restarted
                    // past it, never fired and kept running the pre-upgrade
                    // rules while reporting healthy (the silent straggler,
                    // `docs/UPGRADE_AND_RECOVERY.md` §1.2.3). The predicate is
                    // `height >= plan.height`: the first block this node
                    // finalizes at/after the halt height halts it, and a late
                    // fire is LOUD because it means the node ran past the
                    // coordinated halt height.
                    if plan.height <= height {
                        if plan.height < height {
                            tracing::warn!(
                                "[upgrade] LATE halt at height {}: plan '{}' was scheduled at \
                                 height {} and this node finalized past it (offline at the halt, \
                                 or restarted after it). Halting now instead of continuing on the \
                                 pre-upgrade rules.",
                                height,
                                plan.name,
                                plan.height
                            );
                        }
                        info!(
                            "[upgrade] UPGRADE TRIGGERED at height {}: plan name='{}', target sha256={}",
                            height, plan.name, hex::encode(plan.sha256)
                        );
                        if let Some(ap) = &persistence {
                            ap.request_flush();
                            ap.snapshot_state(&rt.state, height).await;
                            let ledger = rt.staking_read().await.clone();
                            let gov = rt.governance.clone().unwrap_or_default();
                            ap.snapshot_domains(&rt.state, &ledger, &gov, height).await;
                        }

                        // DRAIN BEFORE EXIT (docs/UPGRADE_AND_RECOVERY.md
                        // §1.2.4): `request_flush` + the snapshot calls only
                        // ENQUEUE jobs, and `std::process::exit(42)` skips the
                        // SIGTERM drain, so the writer could still be holding
                        // the final blocks/snapshots when the process dies.
                        // Await the same bounded helper the SIGTERM path uses
                        // (240 s cap + 10 s settle) — BOUNDED, so a dead disk
                        // delays the halt but can never hang it.
                        if let Some(ap) = &persistence {
                            let outcome = crate::node::bootstrap::upgrade_halt::drain_for_halt(
                                || ap.pending(),
                                stellereum::storage::ShutdownDrainConfig::default(),
                            )
                            .await;
                            if outcome.drained {
                                info!(
                                    "[upgrade] persistence drained (queue empty) before the \
                                     upgrade halt at height {height}"
                                );
                            } else {
                                tracing::error!(
                                    "[upgrade] halt drain CAP reached with {} persist job(s) still \
                                     queued (wedged writer or dead disk); halting anyway — the \
                                     drain is bounded and the loss window is the pre-upgrade queue",
                                    outcome.last_pending
                                );
                            }
                        }

                        // DURABLE HALT MARKER (closes the missed-event hole):
                        // a node that is offline at the halt height (or that
                        // restarts past it) never runs the finalize lane at
                        // `plan.height`, so the halt itself must be a
                        // PREDICATE on disk, not only an event. Written after
                        // the drain (so it is never the only thing that
                        // survived a torn flush) and BEFORE any `execve`, so
                        // the NEW image's startup guard can validate and clear
                        // it. `target_version` is the plan's name: the upgraded
                        // binary proves it by matching the plan sha256 or by
                        // declaring STELL_UPGRADE_VERSION=<plan name>.
                        {
                            let marker_path = crate::node::bootstrap::upgrade_halt::marker_path();
                            let marker = crate::node::bootstrap::upgrade_halt::UpgradeHaltMarker {
                                height: plan.height,
                                halted_at_height: height,
                                plan_name: plan.name.clone(),
                                plan_sha256: plan.sha256,
                                target_version: plan.name.clone(),
                                running_version:
                                    crate::node::bootstrap::upgrade_halt::running_version(),
                                halted_unix: now_secs(),
                            };
                            let marker_written = crate::node::bootstrap::upgrade_halt::write_marker(
                                &marker_path,
                                &marker,
                            );
                            if let Err(e) = marker_written {
                                tracing::error!(
                                    "[upgrade] FAILED to write the halt marker {:?}: {e} — the \
                                     node still halts, but a restart cannot prove it is halted; \
                                     the finalize-lane predicate fires again on the next height",
                                    marker_path
                                );
                            } else {
                                info!(
                                    "[upgrade] halt marker written to {:?} (plan '{}' at height \
                                     {}, target version '{}'): a restarted node refuses to join \
                                     consensus until the upgraded binary is running",
                                    marker_path,
                                    marker.plan_name,
                                    marker.height,
                                    marker.target_version
                                );
                            }
                        }

                        // LIVE MIGRATION ARMING (audit W8.3 / production
                        // blocker A8): the live `execve` of a new binary is
                        // DISARMED unless the operator explicitly set
                        // `STELL_AUTO_UPGRADE=1` on THIS node. The old
                        // default was "armed unless told otherwise", which
                        // turned a quorum decision about the chain's RULES
                        // into a decision to replace the running binary on
                        // the operator's box. Unarmed, the node still halts
                        // at the upgrade height with exit code 42
                        // (Cosmovisor-compatible) and the supervisor restarts
                        // it — the graceful path is unchanged, only the
                        // in-place `execve` is now opt-in.
                        let auto_upgrade = stellereum::governance::auto_upgrade_armed();

                        // PATH SAFETY (audit W6.7): the plan's name is used to
                        // build the candidate path, so it must be a SAFE single
                        // path segment. A name carrying a separator (or a
                        // `..`) would resolve OUTSIDE `data/upgrades/` — a
                        // governance proposal could then point the upgrade at
                        // an arbitrary path on the box. `upgrade_candidate_paths`
                        // returns an EMPTY list for such a name, so the exec
                        // is skipped and the node exits 42 as usual.
                        let upgrade_candidates =
                            stellereum::governance::upgrade_candidate_paths(&plan);

                        if auto_upgrade {
                            if upgrade_candidates.is_empty() {
                                tracing::error!(
                                    "[upgrade] REFUSING upgrade plan '{}': the name is not a safe path segment",
                                    plan.name
                                );
                            }
                            for cand in &upgrade_candidates {
                                if !cand.exists() {
                                    continue;
                                }
                                // TOCTOU CLOSED (audit W6.7): the bytes that
                                // were HASHED are staged into a private
                                // directory, and THAT copy is executed. The
                                // old path read+hash'd the file and then
                                // exec'd it BY PATH, so the file could be
                                // swapped between the check and the exec.
                                // The staging also refuses a SYMLINKED
                                // candidate (and no longer chmod-s the
                                // candidate, which used to chmod the TARGET
                                // of a planted symlink).
                                match stellereum::governance::stage_verified_upgrade_binary(
                                    cand,
                                    &plan.sha256,
                                ) {
                                    Ok(staged) => {
                                        info!(
                                            "[upgrade] found verified new binary at {:?} (sha256 matches) — executing live zero-downtime swap!",
                                            cand
                                        );
                                        use std::os::unix::process::CommandExt;
                                        // `args_os` (not `args`): `args` PANICS
                                        // on a non-UTF-8 argv element, which
                                        // would kill the node instead of
                                        // exec'ing the new binary.
                                        let err = std::process::Command::new(&staged)
                                            .args(std::env::args_os().skip(1))
                                            .exec();
                                        eprintln!("[upgrade] live exec failed: {err}");
                                    }
                                    Err(e) => {
                                        tracing::error!(
                                            "[upgrade] candidate {:?} refused: {e}",
                                            cand
                                        );
                                    }
                                }
                            }
                        }

                        info!("[upgrade] halting node gracefully at height {} for upgrade plan '{}'. Exit code 42.", height, plan.name);
                        std::process::exit(42);
                    }
                }
                // Snapshot state every 100 heights (bounded disk growth).
                //
                // SYNC TRAP N5 (R3 CODE-TAILS sweep, P2P snapshot publication
                // gap): captures ride the FINALIZE path, so a shard that
                // stops finalizing publishes nothing new — a node that falls
                // behind the last published snapshot + the pruned
                // header/body windows has no in-band recovery (the wedge-side
                // half of the gap; the publish-side half — shed Bulk stores
                // holding the pointer fail-closed — is already handled in
                // `P2pNetworkAdapter::persist_state_snapshot`). There is no
                // code fix that publishes what was never finalized; the
                // repair is operational (restore finalization first) plus N3:
                // keep at least one GOOD snapshot per 100-height boundary
                // reachable (forever TTL) so catchers never depend on the
                // freshest one. If `try_snapshot_sync` probes every boundary
                // down the window and finds no state blob, the shard stopped
                // publishing — check finalization, not the fetcher.
                // CAPTURE rides the sequenced apply lane (see `SnapBundle` in
                // runtime.rs): the worker clones between two applies, so the
                // bytes can never mix heights — unlike the old tick-side
                // cloning, where the worker could slip an apply between the
                // separate clone calls (chain-down incident: every snapshot
                // in the window torn, both nodes refusing to restart). The
                // worker ALSO verifies the engine still roots at the
                // worker-certified post-`height` root before cloning, so a
                // mislabeled capture is impossible no matter the queue order;
                // a skipped capture simply snapshots a later height (labels
                // stay exact — `last_snapshot_height` advances only when a
                // bundle ARRIVES, never on submit).
                // Snapshots land on exact multiples of `snap_int` (plus the
                // 100-grid catch-up multiples), and `try_snapshot_sync` now
                // walks interval-spaced boundaries derived from the same
                // cadence, so probes find them without guessing offsets
                // (audit F4).
                let snap_int = snapshot_interval();
                // Adaptive cadence (`stellereum::snapshot_cadence`): the
                // candidate rule below is byte-identical to the old trigger;
                // the gate additionally skips a candidate that provably
                // brought no state change (certified post-`height` root equals
                // the previous height's root — asserted on real roots, never
                // assumed from tx count) unless the interval floor is due
                // (gap beyond one full `snap_int`, so the worst-case restore
                // distance never exceeds today's). On an active chain
                // `state_changed` is always true and this submits exactly as
                // before.
                let state_changed = prev_finalized_root != Some(root);
                let candidate = stellereum::snapshot_cadence::snapshot_candidate(
                    height,
                    last_snapshot_height,
                    snap_int,
                );
                if stellereum::snapshot_cadence::should_submit_snapshot(
                    height,
                    last_snapshot_height,
                    snap_int,
                    state_changed,
                ) {
                    // Submit-time cross-shard binding: the worker bundle holds
                    // accounts/domains/aux at post-`height` (root-gated), but
                    // the replay set is captured HERE, on the tick, at the
                    // same quiescent instant (this height just installed, the
                    // next apply is not submitted yet, so the worker is idle
                    // and nothing mutates the engine under the clone).
                    // Capturing at POLL time instead read a replay set
                    // advanced by later heights and persisted it under this
                    // height's label: the restored engine then rooted
                    // differently from `header(height+1)` and the next boot
                    // died in `verify_restored_root` (restore root mismatch
                    // crash-loop). The bytes travel with the submit
                    // (single-flight) and are never re-read at poll.
                    // A failed OR EMPTY cross-shard replay encode must never
                    // be published beside a snapshot (audit 2.6): the paired
                    // restore would then reject the whole snapshot loudly, but
                    // the height would burn and a good snapshot could be
                    // pruned. Treat empty as failure and SKIP this capture;
                    // the cadence retries at a later height.
                    let xshard = match bincode::serialize(&rt.cross_shard_replay_snapshot().await) {
                        Ok(bytes) if !bytes.is_empty() => Some(bytes),
                        Ok(_) => {
                            tracing::error!(
                                "[snapshot] height {height}: cross-shard replay encode \
                                 produced EMPTY bytes — SKIPPING this capture (an empty replay \
                                 set must never be published; restore would fail closed)"
                            );
                            None
                        }
                        Err(e) => {
                            tracing::error!(
                                "[snapshot] height {height}: cross-shard replay encode FAILED: \
                                 {e} — SKIPPING this capture (publishing an empty replay set \
                                 would fail every restore)"
                            );
                            None
                        }
                    };
                    if let Some(xshard) = xshard {
                        if rt.submit_snapshot(height, root) {
                            pending_snapshot_xshard = Some((height, xshard));
                            info!(
                                "[snapshot] submitted capture for height {height} \
                                 (last_snapshot_height={last_snapshot_height})"
                            );
                        } else {
                            // By design at most one capture is in flight (a
                            // refused submit snapshots a later height instead)
                            // — but a refusal on EVERY height means the worker
                            // never answers, so it stays LOUD, never silent.
                            tracing::warn!(
                                "[snapshot] submit REFUSED for height {height} \
                                 (a capture is still in flight; \
                                 last_snapshot_height={last_snapshot_height})"
                            );
                        }
                    }
                } else if candidate {
                    // Adaptive cadence skip: a candidate that provably brought
                    // no state change (certified root equals the previous
                    // height's) while the interval floor is not due. Stays
                    // LOUD (never silent): every skip names the height, the
                    // last snapshot, and the unchanged root.
                    info!(
                        "[snapshot] SKIPPED idle capture for height {height} \
                         (last_snapshot_height={last_snapshot_height} \
                         root={} snap_int={snap_int})",
                        hex::encode(&root[..6])
                    );
                }
                // Advance the idleness clock: the NEXT height compares against
                // this height's certified root.
                prev_finalized_root = Some(root);
                // Collect a ready capture (non-blocking): serialize + enqueue
                // + publish exactly like before, sourced from the bundle.
                // Cross-shard runtime mirrors + tip header are captured here
                // (tick): they are transport-driven and deliberately
                // uncommitted, so their raciness cannot move the root.
                if let Some(bundle) = rt.poll_snapshot() {
                    info!(
                        "[snapshot] capture ready for height {} \
                         (accounts={}, last_snapshot_height={last_snapshot_height})",
                        bundle.height,
                        bundle.accounts.accounts.len(),
                    );
                    last_snapshot_height = bundle.height;
                    // Submit-time bytes (see above): never a fresh read — a
                    // fresh read here is post-`bundle.height` state under an
                    // older label. A missing/mismatched stash is impossible
                    // (single-flight: the submit stashes before its poll
                    // reads); fall fail-closed (empty bytes fail the restore
                    // loudly) rather than substituting newer state.
                    let cross_shard = match pending_snapshot_xshard.take() {
                        Some((h, bytes)) if h == bundle.height => bytes,
                        Some((h, _)) => {
                            tracing::error!(
                                "[snapshot] height {}: cross-shard stash mismatch (stashed for {h}); persisting empty so the restore fails closed instead of mixing heights",
                                bundle.height,
                            );
                            Vec::new()
                        }
                        None => {
                            tracing::error!(
                                "[snapshot] height {}: no submit-time cross-shard stash (submit/poll desync?); persisting empty so the restore fails closed instead of mixing heights",
                                bundle.height,
                            );
                            Vec::new()
                        }
                    };
                    let tip_header = rt
                        .finalized
                        .last()
                        .and_then(|(_, h)| rt.blocks.get(h).cloned());
                    let ap2 = ap.clone();
                    let adapter2 = adapter.clone();
                    let shard_id = block_shard;
                    let lane = publish_lane.clone();
                    tokio::spawn(async move {
                        let stellereum::runtime::SnapBundle {
                            height,
                            accounts,
                            domains,
                            session_keys,
                            bridge,
                            zkml_models,
                            cnvrf_v3,
                        } = bundle;
                        // Serialize on the blocking pool. Bytes are identical to
                        // the old inline `create_snapshot`/`bincode::serialize`
                        // (same cloned values, same order) -- pinned by
                        // tests/tick_offload_tests.rs.
                        let bytes = stellereum::storage::serialize_off_tick(accounts)
                            .await
                            .unwrap_or_default();
                        if bytes.is_empty() {
                            // bincode of even an empty account vec is 8 bytes
                            // (the length prefix), so empty here means the
                            // blocking encode FAILED — loud, not a silent
                            // empty publish (fetchers would reject it loudly
                            // at the root check, but the height still burns).
                            tracing::error!(
                                "[snapshot] height {height}: account serialize \
                                 FAILED (publishing empty bytes; see [snapshot-publish] \
                                 outcome below)"
                            );
                        }
                        ap2.enqueue_state(height, bytes.clone());
                        info!(
                            "[snapshot] height {height}: local persist enqueued \
                             (state {} bytes); handing to publish_lane",
                            bytes.len()
                        );
                        // A9: persist every non-account domain too.
                        if let Some(domain_bytes) =
                            stellereum::storage::serialize_off_tick(domains).await
                        {
                            ap2.enqueue_cnvrf_v3(height, cnvrf_v3.clone());
                            ap2.enqueue_domains(
                                height,
                                domain_bytes.clone(),
                                session_keys.clone(),
                                bridge.clone(),
                                zkml_models.clone(),
                                cross_shard.clone(),
                            );
                            // Publish the SAME domain blobs beside the state
                            // snapshot (audit follow-up F-J): without them a
                            // far-behind node restores accounts only and fails
                            // the trusted-root check on any live chain. One job
                            // per the shared kind list
                            // (`network::SNAPSHOT_PUBLISH_DOMAIN_KINDS`), so the
                            // publish set cannot drift from what
                            // `sync::SYNC_DOMAIN_KINDS` fetches without failing
                            // the parity test in
                            // tests/observer_and_recovery_tests.rs.
                            // Separate adapter clone: the state publish below
                            // moves its own.
                            let adapter3 = adapter2.clone();
                            // Every blob beside the state snapshot carries the
                            // effectively-non-expiring TTL (see
                            // `persist_domain_snapshot`): snapshots must stay
                            // FOREVER (one per 100 heights), because a node
                            // thousands of blocks behind anchors on a recent
                            // one long after every body/header window elapsed.
                            let by_kind: Vec<(&'static str, Vec<u8>)> = vec![
                                ("domains", domain_bytes.clone()),
                                ("session", session_keys.clone()),
                                ("bridge", bridge.clone()),
                                ("zkml", zkml_models.clone()),
                                ("cross_shard", cross_shard.clone()),
                                ("cnvrf_v3", cnvrf_v3.clone()),
                            ];
                            debug_assert!(
                                {
                                    let mut got: Vec<&str> =
                                        by_kind.iter().map(|(k, _)| *k).collect();
                                    got.sort_unstable();
                                    let mut want: Vec<&str> = stellereum::network::SNAPSHOT_PUBLISH_DOMAIN_KINDS.to_vec();
                                    want.sort_unstable();
                                    got == want
                                },
                                "snapshot domain publish set drifted from SNAPSHOT_PUBLISH_DOMAIN_KINDS"
                            );
                            if !lane.submit(async move {
                                for (kind, data) in &by_kind {
                                    if !adapter3
                                        .persist_domain_snapshot(shard_id, height, kind, data)
                                        .await
                                    {
                                        // The persist fn already logged LOUDLY;
                                        // this caller-side line ties the
                                        // failure to the snapshot height.
                                        tracing::error!(
                                            "[snapshot] height {height}: domain \
                                             blob kind={kind} did NOT land \
                                             (fetchers will miss it; pointer \
                                             unaffected — domains carry no pointer)"
                                        );
                                    }
                                    tokio::time::sleep(std::time::Duration::from_millis(40)).await;
                                }
                            }) {
                                // `TickLane::submit` is false only when the
                                // lane task is gone: every later publish on
                                // this lane dies the same way, so this is a
                                // node-restart-class alarm, not a retryable miss.
                                tracing::error!(
                                    "[snapshot] height {height}: domain \
                                     publish_lane submit FAILED (lane dead? \
                                     domain blobs unpublished)"
                                );
                            }
                        } else {
                            // The state snapshot below still publishes, but a
                            // far-behind node restoring accounts-only fails
                            // the trusted-root check on any live chain — one
                            // LOUD line per occurrence (1 per 100 heights max).
                            tracing::error!(
                                "[snapshot] height {height}: domain serialize \
                                 FAILED (no local domain persist, no domain \
                                 publish; state snapshot still publishes)"
                            );
                        }
                        if !lane.submit(async move {
                            // Publish the SAME snapshots to the network. This is what makes
                            // catching up independent of how far back the block-retro-publish
                            // window reaches: a node thousands of blocks behind can take the
                            // state at this height and the block headers above it, instead of
                            // walking every body from genesis. The snapshot is verified
                            // against the trusted state root before it is applied
                            // (`sync::fast_sync_state`), so a poisoned snapshot is rejected
                            // rather than committed.
                            if !adapter2
                                .persist_state_snapshot(shard_id, height, &bytes)
                                .await
                            {
                                // The persist fn already logged LOUDLY (and
                                // held the pointer fail-closed); this
                                // caller-side line ties it to the height.
                                tracing::error!(
                                    "[snapshot] height {height}: state snapshot \
                                     did NOT land (pointer held; catchers will \
                                     keep probing older boundaries)"
                                );
                            }
                            // The HEADER at the same height. A cold node uses the snapshot
                            // to skip execution but still has to chain headers from the
                            // snapshot up to the head to be convinced it is on the right
                            // chain, and headers carry the statthat binding.
                            if let Some(b) = tip_header {
                                adapter2.persist_block_header(shard_id, &b).await;
                            }
                        }) {
                            // `TickLane::submit` is false only when the lane
                            // task is gone: every later publish on this lane
                            // dies the same way — node-restart-class alarm.
                            tracing::error!(
                                "[snapshot] height {height}: state \
                                 publish_lane submit FAILED (lane dead? \
                                 snapshot + header unpublished)"
                            );
                        }
                    });
                }
                // Retention has its OWN cadence guard (audit follow-up): it
                // used to ride inside the snapshot block, so a continuously
                // busy apply worker starved sled pruning together with
                // snapshots — bodies/receipts growing unbounded. Prune is
                // safe on a busy chain (height-keyed deletes below the
                // retention window), only the snapshot capture needs
                // quiescence.
                if !retention.archive && height >= last_prune_height + 100 {
                    last_prune_height = height;
                    {
                        let keep_from = height.saturating_sub(retention.keep_blocks);
                        ap.enqueue_prune(keep_from);
                        // Older state/domain snapshots only help a reorg, and
                        // `load_state_into` reads only the newest, so a small
                        // ring is plenty.
                        //
                        // §7 Phase 1: these two were synchronous sled scans
                        // INLINE in the consensus loop. Same functions, same
                        // arguments, same ignored errors -- only the thread
                        // moves (blocking pool), with a single-flight guard so
                        // a slow pass can never be joined by a second one.
                        let keep_states = height.saturating_sub(snap_int * 3);
                        let store = ap.storage();
                        spawn_guarded_blocking(&prune_guard, move || {
                            let _ = store.prune_state_below(keep_states);
                            let _ = store.prune_domains_below(keep_states);
                        });
                    }
                }
            }
            last_prevoted = None;
            last_precommitted = None;
            let elapsed_round = round_started.elapsed();
            round_started = std::time::Instant::now();
            last_block_at = std::time::Instant::now()
                .checked_sub(elapsed_round.min(min_block_time))
                .unwrap_or_else(std::time::Instant::now);
            // SPD proposal-fast-forward (empty-block fast path): the next
            // VEL-1 proposal-fast-forward (prebuild hit): the next proposer
            // pre-broadcasts its proposal IN THE SAME TICK as finalize
            // instead of waiting for the next tick's propose gate. Saves one
            // tick (TICK_MS) per height and, for a slow 1-vCPU proposer whose
            // build + schedule would otherwise miss the round-zero proposal
            // window (650ms), keeps the proposal under the window and avoids
            // a full timeout-ladder round (~3.5s waste).
            // SAFE (liveness-only, no wire/quorum change): same gates as the
            // top-of-tick propose (can_vote, !has_pending_apply, is_proposer,
            // !has_live_proposal, min_block_time), same parent (finalized head)
            // and same post-apply state root (poll_apply completed, so
            // has_pending_apply is false), same Proposal bytes, idempotent via
            // the propose gate (`has_live_proposal` set by self-record refuses
            // a second build for the same (height, round)). Gated on the
            // prebuild cache (`has_prebuild_for`): the selection was packed
            // during the prevote idle window and `propose` revalidates it
            // against live state + tops up, so a same-tick build stays cheap
            // (O(block) revalidation + bounded top-up) instead of paying a
            // full multi-pass scan inside the finalize tick; on a cache miss
            // the height falls back to the normal next-tick path. Empty
            // blocks hit trivially (empty selection revalidates vacuously).
            // Timeouts never move safety (lock rules untouched); earlier
            // proposals only improve liveness.
            if can_vote
                && proposal_parent_is_finalized(
                    rt.finalized.last().map(|(h, _)| *h).unwrap_or(0),
                    rt.hc.height,
                )
                && !rt.has_pending_apply()
                && rt.is_proposer()
                && !rt.hc.has_live_proposal()
                && last_block_at.elapsed() >= min_block_time
                && rt.has_prebuild_for(rt.hc.height)
            {
                rt.poll_vdf_lane();
                if let Some(block) = rt.propose(now_secs()).await {
                    let height = rt.hc.height;
                    let round = rt.hc.round;
                    let bh = block.compute_hash();
                    let ntx = block.transactions.len();
                    compact_server.remember(&block, round);
                    let msg = stellereum::consensus_net::proposal_gossip_msg(&block, round);
                    let large = msg.is_large();
                    enqueue_outbox(&mut outbox, msg);
                    if large {
                        flush_outbox(&net_sender, &mut outbox, rt.hc.height, rt.hc.round);
                        outbox_flushes += 1;
                        last_flush = std::time::Instant::now();
                    }
                    last_block_at = std::time::Instant::now();
                    info!("[consensus][ff] fast-forward proposed block #{} r{} {} txs={} (same-tick after finalize, prebuild hit)", height, round, hex::encode(&bh[..6]), ntx);
                }
            }
            continue;
        } else if !rt.has_pending_apply() && last_blockers_log != Some((height, round)) {
            // try_finalize found nothing. Say WHY (throttled: once per round)
            // instead of failing silently: precommit activity without finality
            // is exactly the stuck shape, and the reason (missing prevote QC
            // with per-side presence, lock refusal, missing body) tells which
            // layer to fix. Quiet when nobody precommits at all (healthy wait).
            if let Some(msg) = rt.hc.finalize_blockers() {
                tracing::warn!("[consensus] FINALIZE-BLOCKED {msg}");
                last_blockers_log = Some((height, round));
            }
        }

        // 6. view change on timeout (liveness)
        //
        // Hold the view change while a peer is demonstrably active within one round of
        // us. Without this, two nodes time out in lockstep, stay one round apart, and
        // with an even validator count sit in opposite proposer phases forever. The
        // hold is bounded by the same timeout, so a silent peer still lets us advance.
        // Hold ONLY if we are the AHEAD one. A node that is BEHIND must be free to
        // time out and advance toward its peer -- holding it too was a bug: a node
        // resuming on round 8 (from its checkpoint) faced a peer on round 0, the peer
        // held its own view change waiting for us, and neither ever moved.
        //
        // So: wait only when the peer is at or behind us but still active (it is about
        // to propose or vote where we are), which is exactly when leaving would abandon
        // a live round. If the peer is clearly ahead, advancing is the right move.
        // The hold window is deliberately TWICE the round timeout. With a window equal
        // to the timeout, two nodes leapfrog: each times out just as the peer's last
        // vote ages out, so the hold never engages and the pair advances in lockstep
        // one round apart forever. A 2x window means a live peer's votes always hold
        // us; a truly dead peer releases us after two timeouts, which only costs one
        // extra round of waiting.
        // STRICTLY ahead only (`pr < our round`). At equal rounds both nodes
        // held each other: neither timer ran, a proposal that never arrived
        // (one transport timeout) was never re-made, and the pair sat frozen
        // until the watchdog restarted it -- observed live as a 180s stall at
        // identical heights with every check green. With near-round vote sync
        // restored (verified votes pull us to the peer's round) an offset is
        // fixed by following, not by holding, so the hold only needs to keep
        // the genuinely-ahead node from abandoning a live near-behind peer.
        // The hold covers BOTH cases now -- peer BEHIND us (wait for it) and
        // peer IN OUR ROUND (wait for the exchange to finish instead of
        // leaping out from under it) -- but it is BOUNDED: after
        // 2 * round_timeout from our round start we advance no matter what.
        // The upper bound is what makes holding at equal rounds safe: the
        // 600ms retransmit gets several attempts to deliver the proposal and
        // the votes, and if nothing does (dead peer, wedged transport) the
        // round still expires instead of freezing the pair forever.
        let peer_is_active_nearby = matches!(
            peer_round_seen,
            Some((ph, pr, at))
                if ph == rt.hc.height
                    && at.elapsed() < 2 * round_timeout
                    && pr <= rt.hc.round
                    // Tightened +3 -> +1 (audit 2026-10-06): "nearby" must mean
                    // nearby — a peer 2-3 rounds behind is not keeping phase
                    // with us, it is behind, and waiting for it only extends
                    // a remotely-triggerable hold. One-round skew (the normal
                    // two-node state) still holds.
                    && pr + 1 >= rt.hc.round
        );
        // PER-ROUND "WAIT FOR A PEER" (WAN liveness, live 2026-10-21): a
        // SINGLE peer that is demonstrably alive - we heard a verified vote
        // from it inside this round's timeout window - is enough reason to
        // hold the view change for one more round. That peer may be exactly
        // one vote short of the quorum that would decide this height, and
        // abandoning the round is what strands it.
        //
        // NO 2-SUPPORTER GATE: the quorum-gated jump was tried and reverted
        // because in a 3-validator set the two nodes BEHIND could never
        // gather two supporters and never caught up - a different deadlock.
        // This rule is LOCAL (it never moves our round, so it cannot drag the
        // node off the network) and BOUNDED (at most 2x the timeout, so it
        // cannot freeze the node either). It only ever delays a round we were
        // about to abandon, and the peer it waits for is a peer we have
        // actually heard from.
        let peer_alive_recently = matches!(
            peer_round_seen,
            Some((ph, _, at)) if ph == rt.hc.height && at.elapsed() < round_timeout
        );
        let hold_bounded = (peer_is_active_nearby || peer_alive_recently)
            && round_started.elapsed() < 2 * round_timeout;
        // C2 DETERMINISTIC ROUND TIMING: the timeout VALUE for (height, round)
        // is a pure function of (base env, round, proposer ledger-missed) —
        // see `deterministic_timeout_for`. Two honest nodes at the same
        // (height, round) compute the SAME duration even with different wall
        // clocks. The old input `hc.timeouts` (a LOCAL failure count that
        // diverges: following a peer does not increment it, timing out does)
        // made two honest nodes compute different timeouts for the same
        // round — removed here. The peer-active HOLD below stays, but it is
        // EXECUTION (delaying the firing), never part of the timeout value.
        let scheduled = rt.hc.proposer();
        let missed_streak = match scheduled {
            Some(p) => rt
                .staking_read()
                .await
                .validators
                .get(&p)
                .map(|s| s.missed)
                .unwrap_or(0),
            None => 0,
        };
        let backoff_ms =
            deterministic_timeout_for(round_timeout.as_millis() as u64, rt.hc.round, missed_streak);
        // C-SLOT FAST TIMEOUT (local policy only — timeouts are never
        // consensus): when the scheduled proposer for the CURRENT round is
        // proven down (ledger missed-streak >= DOWNTIME_MISS_THRESHOLD) the
        // full backoff ladder is pure dead air — cap this round's timeout at
        // STELL_DOWN_PROPOSER_TIMEOUT_MS (default 800ms). DETERMINISTIC gate:
        // ledger evidence ONLY (no `vote_seen` — a local observation flag
        // that diverges across honest nodes and made the timeout value
        // node-local). Skipped while we hold a live proposal for this round:
        // a merely-slow proposer's proposal still arrives first and seats it,
        // so the race resolves toward waiting (normal backoff), never toward
        // a fork — a timeout can only move OUR round, never the chain.
        let fast_down_proposer = !rt.hc.has_live_proposal()
            && scheduled.is_some()
            && should_use_down_proposer_timeout_deterministic(missed_streak);
        if fast_down_proposer && last_fast_timeout_logged != Some((rt.hc.height, rt.hc.round)) {
            last_fast_timeout_logged = Some((rt.hc.height, rt.hc.round));
            eprintln!(
                "[consensus] DOWN-PROPOSER fast timeout h={} r{} proposer={} missed={} (cap {}ms, no backoff)",
                rt.hc.height,
                rt.hc.round,
                scheduled
                    .map(|p| hex::encode(&p[..6]))
                    .unwrap_or_else(|| "none".into()),
                missed_streak,
                down_proposer_timeout_ms(),
            );
            tracing::warn!(
                "[consensus] DOWN-PROPOSER fast timeout h={} r={} missed={}",
                rt.hc.height,
                rt.hc.round,
                missed_streak,
            );
        }
        let effective_timeout = Duration::from_millis(if fast_down_proposer {
            backoff_ms.min(down_proposer_timeout_ms())
        } else if !rt.hc.has_live_proposal() && rt.hc.round == 0 {
            // In round 0, online proposers deliver within 50ms. Cap round 0 wait at
            // STELL_ROUND_ZERO_TIMEOUT_MS (default 650ms) to eliminate 1.5s dead air spikes.
            backoff_ms.min(round_zero_timeout_ms())
        } else {
            backoff_ms
        });
        // Straggler grace (docs/PROPOSER_REWORK.md §2c): bounded ADDITIVE hold
        // past the deterministic deadline while fresh evidence shows a live
        // straggler (behind peer vote, or no live proposal with a peer live
        // at our height). The deterministic core above stays byte-identical
        // (same-on-all-nodes); this only ever WIDENS honest-round overlap, so
        // heterogeneous holds cannot fork (safety is time-free). Default-off
        // (grace 0 → zero added, the gate below is byte-identical to today).
        // Dead peers age out of the freshness window, so they cannot park us.
        let straggler_hold = {
            let g = straggler_grace_ms();
            if g == 0 {
                Duration::from_millis(0)
            } else {
                let seen = peer_round_seen.map(|(ph, pr, at)| {
                    let age_ms: u64 = at.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
                    (ph, pr, age_ms)
                });
                Duration::from_millis(straggler_hold_ms(
                    rt.hc.height,
                    rt.hc.round,
                    rt.hc.has_live_proposal(),
                    seen,
                    g,
                    straggler_grace_cap_ms(),
                    straggler_freshness_ms(round_timeout.as_millis() as u64),
                ))
            }
        };
        // ROUND-TIMER ACCOUNTING (docs/TEMPO_PROFILE.md §5.3 root cause): the
        // gate below fires at `max(effective_timeout, 2 * round_timeout)`
        // while a peer is active, so an unsubsumed grace stacks PAST the 2×
        // bound (`effective + grace`) instead of filling it. Cap the hold to
        // the slack between the deterministic deadline and that bound — the
        // hold still holds (peer-active wait, grace-while-evidence-fresh),
        // the timeout still times out, and with grace unset the hold is
        // already zero so this `min` is a no-op (default behavior
        // byte-identical). The nil wait is NOT a dwell term (it spends the
        // vote but never gates the view change), so it is untouched.
        let hold_slack = (2 * round_timeout)
            .checked_sub(effective_timeout)
            .unwrap_or_default();
        let straggler_hold = straggler_hold.min(hold_slack);
        if !straggler_hold.is_zero() && round_started.elapsed() > effective_timeout {
            stellereum::metrics::global().inc_straggler_grace_extends();
        }
        if round_started.elapsed() > effective_timeout + straggler_hold && !hold_bounded {
            // infnode pubsub is best-effort: a vote can be dropped in transit.
            // Broadcasting each vote exactly once means a single lost message
            // leaves the peer one signature short forever, and since the two
            // sides then sit in different rounds neither can ever finalize —
            // the chain stalls at that height permanently. Re-send this round's
            // votes before moving on so a peer that missed them can still
            // reach quorum (the same reason Tendermint re-propagates on timeout).
            // P3-H4: timeout re-sends RE-ENQUEUE rebuilt votes (fresh
            // lock_hint: the node may have locked since casting) and force
            // flushes. Never a direct broadcast from this path.
            let mut requeued = false;
            for v in [cast_prevote.clone(), cast_precommit.clone()]
                .into_iter()
                .flatten()
            {
                requeued |= enqueue_outbox(
                    &mut outbox,
                    ConsensusMsg::Vote {
                        vote: v.clone(),
                        locked: lock_hint(&rt, &v),
                    },
                );
            }
            // Re-send OUR proposal for this round as well. If that one message
            // was lost, the peer never votes it, the proposal gate stays shut
            // (has_live_proposal) for the whole round, and nothing retries it
            // until the round changes -- one dropped datagram cost a full round.
            // Same bytes, idempotent on the receiver.
            if rt.hc.has_live_proposal() {
                if let Some((_, ph)) = rt.hc.proposal {
                    if let Some(b) = rt.blocks.get(&ph).cloned() {
                        compact_server.remember(&b, rt.hc.round);
                        requeued |= enqueue_outbox(
                            &mut outbox,
                            stellereum::consensus_net::proposal_gossip_msg(&b, rt.hc.round),
                        );
                    }
                }
            }
            // Flush only when something NEW was actually queued. The old
            // force-flush re-emitted the same bytes on EVERY view change even
            // when dedup collapsed both requeues, so a wedged round (one view
            // change per `round_timeout`) amplified into a retry storm on top
            // of the 2s TIMEOUTs. Loss recovery stays on the periodic
            // retransmit below, which backs off while stuck instead.
            if requeued {
                flush_outbox(&net_sender, &mut outbox, rt.hc.height, rt.hc.round);
                outbox_flushes += 1;
                last_flush = std::time::Instant::now();
            }
            rt.next_round();
            last_prevoted = None;
            last_precommitted = None;
            cast_prevote = None;
            cast_precommit = None;
            round_started = std::time::Instant::now();
            info!(
                "[consensus] view change -> height {} round {}",
                rt.hc.height, rt.hc.round
            );
            // C2 NIL-STORM CIRCUIT BREAKER (one-shot per streak, K=3): after K
            // consecutive nil-rounds, (a) re-broadcast the highest-QC-backed
            // proposal body we hold (same bytes, idempotent), (b) widen the
            // vote-collection window ONCE (inside `apply_nil_convergence`),
            // (c) resume normal timing. SAFE: casts no vote (never
            // double-votes), moves no round (never rewinds); only the window
            // widens, once. The node that already holds the network's polka
            // body re-shares it; nodes that don't hold it only widen.
            if rt.hc.nil_breaker_due() {
                let target = rt.hc.apply_nil_convergence();
                let have_body = target.and_then(|h| rt.blocks.get(&h).cloned());
                if let Some(body) = have_body {
                    let h = body.compute_hash();
                    compact_server.remember(&body, rt.hc.round);
                    enqueue_outbox(
                        &mut outbox,
                        stellereum::consensus_net::proposal_gossip_msg(&body, rt.hc.round),
                    );
                    flush_outbox(&net_sender, &mut outbox, rt.hc.height, rt.hc.round);
                    outbox_flushes += 1;
                    last_flush = std::time::Instant::now();
                    eprintln!(
                        "[consensus][nil-breaker] h={} r{} K={} re-broadcast QC-backed {} (window widened once)",
                        rt.hc.height,
                        rt.hc.round,
                        stellereum::consensus::NIL_CIRCUIT_BREAKER_K,
                        hex::encode(&h[..6]),
                    );
                    tracing::warn!(
                        "[consensus][nil-breaker] h={} r{} re-broadcast QC-backed proposal",
                        rt.hc.height,
                        rt.hc.round,
                    );
                } else {
                    eprintln!(
                        "[consensus][nil-breaker] h={} r{} K={} no QC-backed body held (window widened once, waiting for votes)",
                        rt.hc.height,
                        rt.hc.round,
                        stellereum::consensus::NIL_CIRCUIT_BREAKER_K,
                    );
                    tracing::warn!(
                        "[consensus][nil-breaker] h={} r{} widened vote-collection window (no body to re-share)",
                        rt.hc.height,
                        rt.hc.round,
                    );
                }
            }
        }

        // Deadlock circuit breaker (live 2026-10-14: A r1550 vs B r318 at
        // h92078, `sync_round_to` +8/4s + `MAX_ROUND_AHEAD` made convergence
        // impossible). Fires only after `STELL_DEADLOCK_TIMEOUT_SECS`
        // (default 300) without finalization while verified peer rounds are
        // ahead: one bounded forward-only jump to max(peer rounds), at most
        // once per timeout window. `check_deadlock_breaker` owns the
        // fail-safe + loud log; here we only reset per-round bookkeeping so
        // the fresh round is not view-changed instantly.
        //
        // Follow-up (live: A r1595 vs B r412, EMPTY peer rounds, mutually deaf
        // forever): when NO verified peer is ahead (empty/default peer rounds)
        // the jump path above can never fire. The `else` below is the pure
        // no-progress fallback: same timeout + same once-per-window rate limit,
        // but a bounded LOCAL RE-PHASE — advance the round (never rewind: a
        // re-vote in an already-used round is a self-equivocation), widen the
        // quorum-scan window so the round the network is actually in becomes
        // committable, and drop only a bodyless lock. Local policy only, no
        // wire-protocol change.
        if let Some(new_round) = rt.check_deadlock_breaker() {
            info!(
                "[consensus] DEADLOCK-BREAKER jumped to round {} at height {}",
                new_round, rt.hc.height
            );
            round_started = std::time::Instant::now();
            last_prevoted = None;
            last_precommitted = None;
            cast_prevote = None;
            cast_precommit = None;
        } else {
            let timeout = ValidatorRuntime::deadlock_timeout();
            let timeout_secs = timeout.as_secs().max(1);
            let no_progress_secs = rt.last_progress_at.elapsed().as_secs();
            let rate_ok = rt
                .last_breaker_at
                .map(|t| t.elapsed() >= timeout)
                .unwrap_or(true);
            if rate_ok
                && rt
                    .hc
                    .deadlock_local_reset_due(no_progress_secs, timeout_secs)
            {
                let height_before = rt.hc.height;
                let from_round = rt.hc.round;
                // HOLD-SET LOOKUP BY VALUE (ruleset v6, site 8): the lock may
                // name a signed hash we have since re-stamped away from. The
                // body is present when ANY held body has the lock's
                // round-free value id, not only when the exact hash is in
                // the store — otherwise a re-proposal would look "bodyless"
                // and the re-phase would drop a lock it still holds.
                let locked_body_present = rt
                    .hc
                    .locked
                    .map(|(h, _)| {
                        rt.blocks.contains_key(&h)
                            || rt.hc.value_id_of(&h).is_some_and(|vid| {
                                rt.blocks.values().any(|b| b.value_id() == vid)
                            })
                    })
                    .unwrap_or(true);
                if rt.hc.apply_deadlock_local_reset(locked_body_present) {
                    rt.last_breaker_at = Some(std::time::Instant::now());
                    debug_assert_eq!(
                        rt.hc.height, height_before,
                        "breaker must never move height"
                    );
                    debug_assert!(
                        rt.hc.round > from_round,
                        "re-phase must never rewind the round (self-equivocation)"
                    );
                    tracing::warn!(
                        height = rt.hc.height,
                        from_round,
                        to_round = rt.hc.round,
                        scan_lookback = rt.hc.scan_lookback,
                        no_progress_secs,
                        "DEADLOCK-BREAKER (local re-phase): no finalization and no peer ahead, \
                         advancing the round and widening the quorum-scan window"
                    );
                    eprintln!(
                        "[consensus][DEADLOCK-BREAKER][local-rephase] h={} r{} -> r{} (scan window {} rounds) after {}s without finalization (timeout {}s)",
                        height_before, from_round, rt.hc.round, rt.hc.scan_lookback, no_progress_secs, timeout_secs
                    );
                    info!(
                        "[consensus] DEADLOCK-BREAKER local re-phase to round {} at height {}",
                        rt.hc.round, rt.hc.height
                    );
                    round_started = std::time::Instant::now();
                    last_prevoted = None;
                    last_precommitted = None;
                    cast_prevote = None;
                    cast_precommit = None;
                }
            }
        }

        // Periodic retransmit of what we already cast. pubsub is best-effort:
        // measurements on the live stand attributed 26.7% of wasted rounds to
        // a message that simply never arrived (18.8% of proposals, 31 rounds
        // with a full prevote QC whose precommit leg was lost). Re-enqueueing
        // is idempotent -- `enqueue_outbox` dedups votes still pending, and
        // re-sent bytes are identical, so the receiver's VoteSet treats them
        // as the same vote (never as equivocation).
        //
        // The cadence BACKS OFF the longer a round is stuck (fast while
        // fresh for loss recovery, relaxing toward 2x timeout): a fixed
        // cadence re-sent at full rate forever, and each wedged round added
        // its own storm on top of the 2s TIMEOUTs. `round_started` resets on
        // every round change, so a new round automatically retries fast.
        let rexmit_every =
            Duration::from_millis(stellereum::consensus_net::retransmit_interval_ms(
                round_timeout.as_millis() as u64,
                round_started.elapsed().as_millis() as u64,
            ));
        if last_rexmit.elapsed() >= rexmit_every {
            last_rexmit = std::time::Instant::now();
            let mut resent = false;
            for v in [cast_prevote.clone(), cast_precommit.clone()]
                .into_iter()
                .flatten()
            {
                resent |= enqueue_outbox(
                    &mut outbox,
                    ConsensusMsg::Vote {
                        vote: v.clone(),
                        locked: lock_hint(&rt, &v),
                    },
                );
            }
            // Thin blocks only (<=32 txs): re-sending a full block every window
            // would amplify traffic, while a large block that is lost simply
            // gets re-proposed by the next round's gate anyway. Guarded
            // against pushing the identical body twice: the outbox already
            // holding this round's proposal means the wire copy is queued.
            if rt.hc.has_live_proposal() {
                if let Some((_, ph)) = rt.hc.proposal {
                    if let Some(b) = rt.blocks.get(&ph).cloned() {
                        if b.transactions.len() <= 32
                            && !outbox_has_proposal(&outbox, rt.hc.height, rt.hc.round)
                        {
                            compact_server.remember(&b, rt.hc.round);
                            outbox.push_back(stellereum::consensus_net::proposal_gossip_msg(
                                &b,
                                rt.hc.round,
                            ));
                            resent = true;
                        }
                    }
                }
            }
            if resent {
                flush_outbox(&net_sender, &mut outbox, rt.hc.height, rt.hc.round);
                outbox_flushes += 1;
                last_flush = std::time::Instant::now();
            }
        }

        // P3-H4 timer flush: pack this tick's votes into one Batch.
        if !outbox.is_empty() && last_flush.elapsed() >= Duration::from_millis(BATCH_MS) {
            flush_outbox(&net_sender, &mut outbox, rt.hc.height, rt.hc.round);
            outbox_flushes += 1;
            last_flush = std::time::Instant::now();
        }

        // NO governance write-back here. It was copying a clone of the shared
        // governance object back into the SAME lock it was cloned from, which
        // (a) did nothing useful -- RPC mutations already land in that lock --
        // and (b) worse, `governance_write` bumps the commitment generation, so
        // every tick forced `get_state_root` to recompute the FULL commitment
        // (clone every domain + SHA-256 + trie insert). That was the dominant
        // CPU cost on the single-core stand (both nodes together at ~83% CPU
        // on an otherwise idle chain) and made every proposal pay it too. It
        // could also clobber a newer RPC mutation with a stale clone.

        // Name the slow tick instead of guessing: report how long the tick
        // took and which network blocks fired inside it. Rounds looked ~10x
        // slower than ROUND_TIMEOUT for hours because the tick -- not the
        // timer -- was the clock, and nothing logged it.
        let tick_dt = tick_t0.elapsed();
        if tick_dt >= Duration::from_millis(400) {
            tracing::info!(
                "[perf] tick h={} r={} took {:?} (catchup={} retro={} probe={} join={} flushes={} catchup_ms={} retro_ms={} probe_ms={} join_ms={})",
                rt.hc.height,
                rt.hc.round,
                tick_dt,
                catchup_ran,
                retro_ran,
                probe_ran,
                join_ran,
                outbox_flushes,
                catchup_ms,
                retro_ms,
                probe_ms,
                join_ms,
            );
        }
        // Windowed tick-split report (see the HOW TO READ note where the
        // counters are declared): one line per 300 ticks (~30s at TICK_MS),
        // never per tick. Resets after each report so every line describes
        // exactly its own window.
        split_ticks += 1;
        split_tick_ms += tick_dt.as_millis() as u64;
        if split_ticks >= 300 {
            tracing::info!(
                "[perf][tick-split] ticks={} tick_avg_ms={} catchup_avg_ms={} (n={}) retro_avg_ms={} (n={}) probe_avg_ms={} (n={}) join_avg_ms={} (n={})",
                split_ticks,
                split_tick_ms / split_ticks.max(1),
                split_catchup_ms / split_ticks.max(1),
                split_catchup_n,
                split_retro_ms / split_ticks.max(1),
                split_retro_n,
                split_probe_ms / split_ticks.max(1),
                split_probe_n,
                split_join_ms / split_ticks.max(1),
                split_join_n,
            );
            split_ticks = 0;
            split_tick_ms = 0;
            split_catchup_ms = 0;
            split_retro_ms = 0;
            split_probe_ms = 0;
            split_join_ms = 0;
            split_catchup_n = 0;
            split_retro_n = 0;
            split_probe_n = 0;
            split_join_n = 0;
        }
        tokio::time::sleep(Duration::from_millis(tick_ms)).await;
    }
}

#[cfg(test)]
mod vote_watermark_tests {
    use super::*;
    use stellereum::storage::{ConsensusCheckpoint, Storage, VoteWatermark, VoteWatermarkEntry};

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "stell-vote-watermark-{tag}-{}-{nanos}",
            std::process::id()
        ))
    }

    /// FINDING C: a crash AFTER a prevote at round 300 but BEFORE the next
    /// consensus checkpoint must not lose the vote. The write-ahead watermark
    /// survives the reopen, raises the resumed round above the liveness cap
    /// (64), and forbids every vote at a round <= 300 for that height.
    ///
    /// (Fails before the fix: there was no watermark at all — only the
    /// checkpoint, which still says round 0 — so the node resumed at round 0
    /// and could re-vote 0..=300.)
    #[test]
    fn crash_after_prevote_never_rewinds_or_revotes() {
        let dir = temp_dir("prevote300");
        {
            let st = Storage::open(&dir).expect("open");
            // The checkpoint predates the vote: round 0 at height 7.
            st.set_consensus(&ConsensusCheckpoint {
                height: 7,
                round: 0,
                locked_hash: None,
                locked_round: 0,
                finalized_height: 6,
                finalized_hash: [9u8; 32],
            })
            .expect("checkpoint");
            // The vote was cast at round 300, fsynced BEFORE the broadcast.
            let mut wm = VoteWatermark::default();
            wm.note(VoteWatermarkEntry {
                height: 7,
                round: 300,
                kind: 0, // prevote
                target: Some([1u8; 32]),
                shard_id: 1,
            });
            st.persist_vote_watermark(&wm).expect("watermark durable");
        } // "crash": drop the storage handle

        let st = Storage::open(&dir).expect("reopen after crash");
        let wm = st
            .vote_watermark()
            .expect("read watermark")
            .expect("watermark survived the crash");
        let cp = st
            .consensus()
            .expect("read checkpoint")
            .expect("checkpoint");
        assert_eq!(cp.round, 0, "the checkpoint still predates the vote");
        let entry = wm.prevote_at(7).expect("prevote at height 7");
        assert_eq!(entry.round, 300);
        assert_eq!(entry.shard_id, 1);
        assert_eq!(entry.target, Some([1u8; 32]));

        // The restore rule (the PRODUCTION helper): `min(cap)` is LIVENESS;
        // the vote watermark is a hard FLOOR that the cap must never rewind
        // below.
        let floor = wm.floor_round(7).expect("floor at height 7");
        let restored = restored_round(cp.round, Some(floor));
        assert_eq!(
            restored, 300,
            "the resumed round must not rewind below the cast vote"
        );

        // And no vote at any round <= 300 for this height may be cast.
        for round in 0..=300u32 {
            assert!(
                round_at_or_below_vote_floor(Some((7, floor)), 7, round),
                "round {round} must be refused"
            );
        }
        assert!(!round_at_or_below_vote_floor(Some((7, floor)), 7, 301));
        // A different height is not governed by this height's floor.
        assert!(!round_at_or_below_vote_floor(Some((7, floor)), 8, 0));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// FINDING C: the precommit watermark is independent of the prevote one,
    /// so a crash between the two does not let the node lose (or duplicate)
    /// either statement.
    #[test]
    fn prevote_and_precommit_watermarks_are_independent() {
        let dir = temp_dir("two-kinds");
        {
            let st = Storage::open(&dir).expect("open");
            let mut wm = VoteWatermark::default();
            wm.note(VoteWatermarkEntry {
                height: 4,
                round: 11,
                kind: 0,
                target: Some([2u8; 32]),
                shard_id: 0,
            });
            st.persist_vote_watermark(&wm).expect("prevote");
            wm.note(VoteWatermarkEntry {
                height: 4,
                round: 11,
                kind: 1,
                target: Some([2u8; 32]),
                shard_id: 0,
            });
            st.persist_vote_watermark(&wm).expect("precommit");
        }
        let st = Storage::open(&dir).expect("reopen");
        let wm = st.vote_watermark().unwrap().unwrap();
        assert_eq!(wm.prevote_at(4).unwrap().round, 11);
        assert_eq!(wm.precommit_at(4).unwrap().round, 11);
        assert_eq!(wm.floor_round(4), Some(11));

        // A nil prevote is a real signed statement: `target == None` must
        // round-trip (it is not "no vote").
        let mut wm2 = wm.clone();
        wm2.note(VoteWatermarkEntry {
            height: 5,
            round: 12,
            kind: 0,
            target: None,
            shard_id: 0,
        });
        st.persist_vote_watermark(&wm2).unwrap();
        let wm3 = st.vote_watermark().unwrap().unwrap();
        assert_eq!(wm3.prevote_at(5).unwrap().target, None);
        assert_eq!(wm3.floor_round(5), Some(12));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A LATE POLKA'S PRECOMMIT IS NOT BLOCKED BY THE PREVOTE FLOOR.
    ///
    /// The live shape: a validator raced to round 11 and signed nil prevotes
    /// there, then the quorum-completing prevotes of round 0 arrive. The
    /// polka is precommitted at r0 (its own round). The union `floor_round`
    /// is 11 and would refuse that precommit, parking the height even though
    /// the precommit is a different (height, round, kind) statement and the
    /// node signed no precommit below it. The PRECOMMIT floor is still
    /// enforced: a round this node already precommitted in is refused.
    #[test]
    fn late_polka_precommit_ignores_the_prevote_floor() {
        // Prevoted nil at r11, never precommitted at this height.
        let prevote_floor = Some((7, 11));
        let precommit_floor: Option<(u64, u32)> = None;
        assert!(round_at_or_below_vote_floor(prevote_floor, 7, 0));
        assert!(
            !round_at_or_below_vote_floor(precommit_floor, 7, 0),
            "the r0 precommit of a late polka must not be refused by the r11 prevote floor"
        );
        // ...but a precommit at a round already precommitted is still refused.
        let precommit_floor = Some((7, 11));
        assert!(round_at_or_below_vote_floor(precommit_floor, 7, 0));
        assert!(round_at_or_below_vote_floor(precommit_floor, 7, 11));
        assert!(!round_at_or_below_vote_floor(precommit_floor, 7, 12));
        // A different height is governed by its own floor.
        assert!(!round_at_or_below_vote_floor(precommit_floor, 8, 0));
    }
}

#[cfg(test)]
mod restart_height_tests {
    use super::*;

    /// The stored finalize pointer normally wins; the engine state can only be
    /// older (slower) than it, and that gap is healed elsewhere.
    #[test]
    fn a_snapshot_at_or_below_the_finalized_tip_keeps_the_stored_tip() {
        let stored = Some((40u64, [7u8; 32]));
        for state in [0u64, 39, 40] {
            assert_eq!(
                reconciled_finalized_tip(state, stored, |_| panic!("must not resolve")),
                Ok(stored),
                "state {state} must not override a finalized tip at 40"
            );
        }
        assert_eq!(
            reconciled_finalized_tip(0, None, |_| panic!("must not resolve")),
            Ok(None)
        );
    }

    /// HEIGHT-SPLIT: when the state snapshot is AHEAD of the stored pointer,
    /// the state height is final (the loader verified its root against block
    /// S+1) and must become the tip — never leave `hc.height = S+1` paired
    /// with a parent F we did not finalize.
    #[test]
    fn an_engine_ahead_of_the_pointer_repairs_the_tip_from_the_local_header() {
        let hash = [0x5Au8; 32];
        let got = reconciled_finalized_tip(55, Some((50, [0x11; 32])), |s| {
            assert_eq!(s, 55);
            Some(hash)
        });
        assert_eq!(got, Ok(Some((55, hash))));
        // No pointer at all + a restored state: same repair.
        let got = reconciled_finalized_tip(9, None, |_| Some([0x99; 32]));
        assert_eq!(got, Ok(Some((9, [0x99; 32]))));
    }

    /// No local proof of the state height's block hash -> fail closed. Running
    /// with the stale parent would propose above an unfinalized parent and the
    /// catch-up walk would anchor behind the engine, wedging both paths.
    #[test]
    fn an_unprovable_ahead_state_is_refused() {
        let got = reconciled_finalized_tip(55, Some((50, [0x11; 32])), |_| None);
        assert!(got.is_err(), "an unprovable head must never be used");
    }

    /// Proposing is only meaningful at exactly `finalized_tip + 1`; every
    /// other relationship builds a block peers refuse (a height gap or a
    /// reused parent).
    #[test]
    fn proposals_only_at_the_next_finalized_parent() {
        assert!(proposal_parent_is_finalized(0, 1), "genesis child");
        assert!(proposal_parent_is_finalized(5, 6));
        assert!(
            !proposal_parent_is_finalized(5, 5),
            "parent already decided"
        );
        assert!(!proposal_parent_is_finalized(5, 7), "skips a height");
        assert!(!proposal_parent_is_finalized(5, 4));
        assert!(!proposal_parent_is_finalized(u64::MAX, u64::MAX));
    }
}
