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
        rt.configure_cnvrf_v3_custody(custody_dir, stellereum::zkml::DEFAULT_CHAIN_ID);
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
    match stellereum::chain_binding::ChainBindingActivation::from_env() {
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

        // Restore the consensus safety checkpoint so a node that restarted
        // mid-height cannot double-vote / prevote a conflicting value for a
        // height it already locked (Tendermint safety across a crash).
        if let Ok(Some(cp)) = ap.storage().consensus() {
            if cp.height == rt.hc.height {
                // Restore the ROUND too, but with a cap.
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
                // So a stale persisted round is treated as stale: beyond
                // MAX_RESTORED_ROUND we restart at the current round and let the peers
                // pull us up through normal view changes. The lock is still honoured
                // unconditionally -- that is the safety half and it does not expire.
                const MAX_RESTORED_ROUND: u32 = 64;
                let restored = cp.round.min(MAX_RESTORED_ROUND);
                rt.hc.round = restored;
                if restored != cp.round {
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
    let mut last_prevoted: Option<(u64, u32)> =
        restored_checkpoint.as_ref().map(|cp| (cp.height, cp.round));
    let mut last_precommitted: Option<(u64, u32)> =
        restored_checkpoint.as_ref().map(|cp| (cp.height, cp.round));
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
    // Times an over-budget Batch was deferred (limiter pacing, not loss).
    let mut inbound_defer_count: u64 = 0;
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
    // How often to ask the network whether we are behind. Cheap but not free,
    // so it is throttled rather than run every tick. Env is read once here,
    // like `round_timeout`/`min_block_time` above.
    let catchup_interval = catchup_interval();
    let retro_publish_interval = retro_publish_interval();
    let mut last_catchup: std::time::Instant = std::time::Instant::now() - catchup_interval;
    // Freshness of the LIVE adopt flow: stamped on every successful parent-match
    // `adopt_committed` in the drain below. Starts stale so the first intervals
    // behave exactly as before until live flow proves itself. Compared against
    // `catchup_interval`: at chain tempo the next Committed lands well within
    // one interval, so a fresh stamp means "the DHT machine has nothing to add".
    let mut last_live_adopt: std::time::Instant = std::time::Instant::now() - catchup_interval;
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
        let tick_t0 = std::time::Instant::now();
        let (mut catchup_ran, mut retro_ran, mut probe_ran, mut join_ran) =
            (false, false, false, false);
        let mut outbox_flushes: u32 = 0;
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
        // Set when this tick observes VERIFIED evidence of a peer ahead of us
        // (a signature+member-checked vote, or a signature-checked proposal,
        // for a future height). Consumed after the drain to run catch-up on
        // the next tick instead of waiting out the catch-up interval.
        let mut catchup_due = false;
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
        let net_budget = Duration::from_millis(
            // Catch-up does DHT head+body walks (seconds on a slow net); the
            // old timeout/2 budget (~400ms live) always expired first, so a
            // 1-block-behind node never healed (audit 2026-10-06).
            (round_timeout.as_millis() as u64 * 2).max(5_000),
        );
        // Snapshot territory needs minutes, not seconds: a far-behind node
        // (hint gap > 100) fetching state+domains+anchor over a weak link
        // can never fit in 5s, so every attempt died at the budget with zero
        // progress and retried forever. While far behind, this node validates
        // nothing anyway (its height is useless to the network), so a long
        // tick costs nothing and is the only way to converge. Near-tip nodes
        // keep the tight budget (fast rounds matter there).
        let our_tip_for_budget = rt.finalized.last().map(|(h, _)| *h).unwrap_or(0);
        let hint_gap_for_budget = rt
            .peer_hint
            .map(|(ph, _)| ph.saturating_sub(our_tip_for_budget))
            .unwrap_or(0);
        const SNAPSHOT_BUDGET_MS: u64 = 180_000;
        let net_budget = if hint_gap_for_budget > 100 {
            Duration::from_millis(SNAPSHOT_BUDGET_MS)
        } else if hint_gap_for_budget > 0 {
            // A node 10-99 blocks behind needs ~100-200ms per block body over
            // WAN (40 blocks = ~8s). The 5s budget expired before the walk could
            // complete, discarding progress and retrying forever. Allow 30s so
            // small-to-medium gaps heal in one pass.
            Duration::from_millis(30_000)
        } else {
            net_budget
        };
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
            let live_adopt_fresh = last_live_adopt.elapsed() < catchup_interval;
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
        if last_catchup.elapsed() >= catchup_interval && !rt.has_pending_apply() && !defer_for_live
        {
            catchup_ran = true;
            last_catchup = std::time::Instant::now();
            let split_catchup_t0 = std::time::Instant::now();
            let catchup_budget = std::time::Duration::from_millis(
                std::env::var("STELL_CATCHUP_BUDGET_MS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(250),
            );
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
                        net_budget.as_millis()
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
                if rt.effective_can_vote(is_validator) && !rt.hc.has_live_proposal() {
                    if let Some(v) = rt.make_prevote() {
                        debug_assert!(
                            v.block_hash.is_none(),
                            "fresh catchup height has no proposal yet"
                        );
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
                split_catchup_ms += split_catchup_t0.elapsed().as_millis() as u64;
                split_catchup_n += 1;
                split_ticks += 1;
                split_tick_ms += tick_t0.elapsed().as_millis() as u64;
                continue;
            }
            catchup_ms = split_catchup_t0.elapsed().as_millis() as u64;
            split_catchup_ms += catchup_ms;
            split_catchup_n += 1;
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
        let binding_activation = stellereum::chain_binding::ChainBindingActivation::from_env();
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
                "[consensus] propose-gate h={} r={} can_vote={} pending_apply={} is_proposer={} live_proposal={} min_time_ok={} scheduled={}",
                height,
                round,
                can_vote,
                rt.has_pending_apply(),
                rt.is_proposer(),
                rt.hc.has_live_proposal(),
                last_block_at.elapsed() >= min_block_time,
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
        if can_vote && !rt.has_pending_apply() {
            rt.prebuild_next_proposal(now_secs()).await;
        }
        if can_vote
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
                let msg = ConsensusMsg::Proposal {
                    height,
                    round,
                    block,
                };
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
        // 2. prevote once we have a proposal
        if can_vote && rt.hc.has_live_proposal() && last_prevoted != Some((height, round)) {
            if let Some(v) = rt.make_prevote() {
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
                cast_prevote = Some(v);
                last_prevoted = Some((height, round));
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
        {
            if let Some(v) = rt.make_prevote() {
                debug_assert!(
                    v.block_hash.is_none(),
                    "no live proposal must prevote nil, never a value"
                );
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
            let raw: String = match rx.try_recv() {
                Ok(r) => r,
                Err(_) => {
                    let now = Instant::now();
                    if inbound_deferred
                        .front()
                        .map(|(wake_at, _)| now >= *wake_at)
                        .unwrap_or(false)
                    {
                        inbound_deferred.pop_front().unwrap().1
                    } else {
                        break;
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
            {
                // Per-peer bucket: the pubsub envelope carries the SENDER's
                // node id in `src` (infnode adds it — it is the only place
                // that knows the connection's peer id), `from` is the legacy
                // spelling. Without it every peer's bulk traffic shared ONE
                // token bucket and one noisy neighbour could defer everybody
                // else's batches.
                let peer_key = stellereum::consensus_net::inbound_peer_key(&raw);
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
                        ConsensusMsg::Proposal { .. } | ConsensusMsg::Vote { .. }
                    ) {
                        last_consensus_rx_ms = liveness_alarm::now_ms();
                    }
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
                                    // catch-up timer every tick, so it must be
                                    // attributable — only a proposal with a valid
                                    // proposer signature from a staked member
                                    // plants it. A forged H+1 proposal previously
                                    // set this before any verification, keeping
                                    // the node on loudly-failing DHT walks.
                                    if stellereum::consensus_net::proposal_hint_admissible(
                                        &block,
                                        &rt.validators,
                                    ) {
                                        let h = (block.height - 1, block.prev_hash);
                                        if rt.peer_hint.map(|(ph, _)| ph < h.0).unwrap_or(true) {
                                            rt.peer_hint = Some(h);
                                        }
                                    }
                                }
                            }
                            // Behind-peer retro gate: a VERIFIED proposal (signature
                            // + membership) from below our height proves a lagging
                            // peer is talking — the only consumer a retro push can
                            // serve. Stamped BEFORE any refusal below (wrong
                            // proposer/round still proves liveness); forgeries never
                            // land here (unverified).
                            if height < rt.hc.height
                                && stellereum::consensus::verify_proposer_signature(&block)
                                && rt.validators.power_of(&proposer) != 0
                            {
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
                                    if can_vote
                                        && rt.hc.has_live_proposal()
                                        && last_prevoted != Some((rt.hc.height, rt.hc.round))
                                    {
                                        if let Some(v) = rt.make_prevote() {
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
                                            cast_prevote = Some(v);
                                            last_prevoted = Some((rt.hc.height, rt.hc.round));
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
                            if !accepted {
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
                                if vh == rt.hc.height
                                    && vcopy.verify()
                                    && rt.validators.power_of(&vcopy.voter) != 0
                                {
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
                                // Behind-peer retro gate: a VERIFIED vote from
                                // below our height proves a lagging peer is
                                // talking — the only consumer a retro push can
                                // serve. Forged votes never land here (unverified),
                                // so an attacker cannot wake retro — worst case a
                                // real behind peer keeps it awake.
                                if vh < rt.hc.height
                                    && vcopy.verify()
                                    && rt.validators.power_of(&vcopy.voter) != 0
                                {
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
                            // Flag it; the post-drain block forces the catch-up
                            // timer instead of waiting out the catch-up interval while
                            // we burn view changes collecting "wrong height".
                            if vh > rt.hc.height {
                                catchup_due = true;
                                stellereum::rpc::note_peer_height(vh);
                            }
                            // A nil prevote carrying the sender's locked hash is a
                            // rescue request: it is stuck on one of OUR bodies.
                            // Record the demand; our next proposer slot re-proposes
                            // that body verbatim (see `ValidatorRuntime::propose`).
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
                                // `note_peer_vote_round` skips the jump while we hold a
                                // live proposal for a near round (accept-wipe livelock),
                                // and jumps otherwise (phase alignment).
                                if rt.note_peer_vote_round(vh, vr) {
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

        // Verified-only catch-up fast path (round efficiency, no safety
        // change): `catchup_due` is set only by votes that passed signature +
        // membership + scope checks, and `peer_hint` is written only after
        // `verify_proposer_signature` — so a future height here is
        // attributable evidence that a peer finalized ahead of us, never an
        // unverified claim. Without this the loop waits up to
        // catch-up interval (2s default) while burning view changes at a stale height
        // and collecting "wrong height" rejects (154 view changes/10min
        // live). Forcing the timer runs the check on the next tick; the walk
        // itself still verifies the full chain (QC per height, anchored on
        // our finalized head), so a false hint costs at most one
        // loudly-failing walk.
        if catchup_due
            || rt
                .peer_hint
                .is_some_and(|(ph, _)| ph > rt.finalized.last().map(|(h, _)| *h).unwrap_or(0))
        {
            last_catchup = std::time::Instant::now()
                .checked_sub(catchup_interval)
                .unwrap_or(std::time::Instant::now());
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
                if last_precommitted != Some((height, v.round)) {
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
                    // P3-H4: commits enqueue then force-flush so lagging peers
                    // learn the outcome on this tick, not the next window.
                    enqueue_outbox(
                        &mut outbox,
                        ConsensusMsg::Committed {
                            height,
                            block,
                            certificate,
                        },
                    );
                    flush_outbox(&net_sender, &mut outbox, rt.hc.height, rt.hc.round);
                    outbox_flushes += 1;
                    last_flush = std::time::Instant::now();
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
                    if plan.height == height {
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
                // Align snapshot boundaries to exact multiples of 100 so
                // that `try_snapshot_sync`'s `(peer_height / 100) * 100` probes
                // find them reliably on any peer without needing to guess offsets.
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
                    let xshard = bincode::serialize(&rt.cross_shard_replay_snapshot().await)
                        .unwrap_or_default();
                    if rt.submit_snapshot(height, root) {
                        pending_snapshot_xshard = Some((height, xshard));
                        info!(
                            "[snapshot] submitted capture for height {height} \
                             (last_snapshot_height={last_snapshot_height})"
                        );
                    } else {
                        // By design at most one capture is in flight (a
                        // refused submit snapshots a later height instead) —
                        // but a refusal on EVERY height means the worker never
                        // answers, so it stays LOUD, never silent.
                        tracing::warn!(
                            "[snapshot] submit REFUSED for height {height} \
                             (a capture is still in flight; \
                             last_snapshot_height={last_snapshot_height})"
                        );
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
                    let msg = ConsensusMsg::Proposal {
                        height,
                        round,
                        block,
                    };
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
                        requeued |= enqueue_outbox(
                            &mut outbox,
                            ConsensusMsg::Proposal {
                                height: rt.hc.height,
                                round: rt.hc.round,
                                block: b,
                            },
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
                    enqueue_outbox(
                        &mut outbox,
                        ConsensusMsg::Proposal {
                            height: rt.hc.height,
                            round: rt.hc.round,
                            block: body,
                        },
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
                let locked_body_present = rt
                    .hc
                    .locked
                    .map(|(h, _)| rt.blocks.contains_key(&h))
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
                            outbox.push_back(ConsensusMsg::Proposal {
                                height: rt.hc.height,
                                round: rt.hc.round,
                                block: b,
                            });
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
