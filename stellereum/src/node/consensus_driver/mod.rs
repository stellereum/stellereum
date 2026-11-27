use ed25519_dalek::SigningKey;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::info;

use crate::node::policy::*;
use crate::node::sync::*;
use stellereum::consensus::ValidatorSet;
use stellereum::consensus_net::{ConsensusMsg, ConsensusNetwork, ConsensusSender, TxGossip};
use stellereum::network::CrossShardTransport;
use stellereum::network::P2pNetworkAdapter;
use stellereum::runtime::ValidatorRuntime;
use stellereum::sharding::ShardRegistry;
use stellereum::state_engine::InMemoryStateEngine;
use stellereum::tokenomics::BLOCK_REWARD_NANO;

mod adopt;
mod catchup;
mod propose;
mod tick;

#[cfg(test)]
mod tests;

/// Immutable configuration and shared handles for the consensus tick loop.
pub(super) struct DriverConfig {
    pub(super) adapter: Arc<P2pNetworkAdapter>,
    pub(super) shard: u32,
    pub(super) block_shard: u32,
    pub(super) persistence: Option<Arc<stellereum::storage::AsyncPersistence>>,
    pub(super) shared_gov: Arc<tokio::sync::RwLock<stellereum::governance::Governance>>,
    pub(super) rpc: Arc<stellereum::rpc::RpcState>,
    pub(super) is_validator: bool,
    pub(super) net: Arc<ConsensusNetwork>,
    pub(super) net_sender: ConsensusSender,
    pub(super) gossip: Arc<TxGossip>,
    pub(super) self_vote_id: [u8; 32],
    pub(super) mempool_path: std::path::PathBuf,
    pub(super) retention: stellereum::storage::RetentionConfig,
    pub(super) publish_lane: TickLane,
    pub(super) backfill_lane: TickLane,
    pub(super) record_lane: TickLane,
    pub(super) prune_lane: TickLane,
    pub(super) mempool_save_guard: Arc<std::sync::atomic::AtomicBool>,
    pub(super) prune_guard: Arc<std::sync::atomic::AtomicBool>,
    pub(super) prune_lane_guard: Arc<std::sync::atomic::AtomicBool>,
    pub(super) round_timeout: Duration,
    pub(super) tick_ms: u64,
    pub(super) min_block_time: Duration,
    pub(super) catchup_interval: Duration,
    pub(super) retro_publish_interval: Duration,
    pub(super) live_adopt_fresh_window: Duration,
}

/// Mutable state carried across consensus ticks.
pub(super) struct DriverState {
    pub(super) rt: ValidatorRuntime,
    pub(super) rx: tokio::sync::mpsc::UnboundedReceiver<String>,
    pub(super) tx_rx: tokio::sync::mpsc::UnboundedReceiver<String>,
    pub(super) last_prevoted: Option<(u64, u32)>,
    pub(super) last_precommitted: Option<(u64, u32)>,
    pub(super) vote_floor: Option<(u64, u32)>,
    pub(super) precommit_floor: Option<(u64, u32)>,
    pub(super) last_blockers_log: Option<(u64, u32)>,
    pub(super) last_gate_diag: Option<(u64, u32)>,
    pub(super) parse_fail_count: u64,
    pub(super) inbound_overcap_count: u64,
    pub(super) inbound_deferred: std::collections::VecDeque<(Instant, String)>,
    pub(super) loopback_queue: std::collections::VecDeque<String>,
    pub(super) loopback_dropped: u64,
    pub(super) compact_index: stellereum::consensus_net::CompactIndexCache,
    pub(super) compact_peer_frames: std::collections::HashMap<String, u32>,
    pub(super) compact_peer_pulls: std::collections::HashMap<String, u32>,
    pub(super) compact_budget_dropped: u64,
    pub(super) compact_full_requests: u64,
    pub(super) compact_index_builds_tick: u32,
    pub(super) peer_hint_at: Option<Instant>,
    pub(super) peer_hint_seen: Option<(u64, [u8; 32])>,
    pub(super) inbound_defer_count: u64,
    pub(super) inbound_compact_refused: u64,
    pub(super) compact_rx: stellereum::consensus_net::CompactReceiver,
    pub(super) compact_server: stellereum::consensus_net::CompactBodyServer,
    pub(super) compact_looped: u64,
    pub(super) compact_served: u64,
    pub(super) last_probe: Instant,
    pub(super) last_mempool_save: Instant,
    pub(super) last_mempool_kv_poll: Instant,
    pub(super) last_workchain_set_repair: Instant,
    pub(super) cast_prevote: Option<stellereum::consensus::Vote>,
    pub(super) cast_precommit: Option<stellereum::consensus::Vote>,
    pub(super) outbox: std::collections::VecDeque<ConsensusMsg>,
    pub(super) last_flush: Instant,
    pub(super) last_rexmit: Instant,
    pub(super) round_started: Instant,
    pub(super) last_block_at: Instant,
    pub(super) apply_in_flight_since: Option<Instant>,
    pub(super) cpu_at_last_block: Option<f64>,
    pub(super) last_join: Instant,
    pub(super) peer_round_seen: Option<(u64, u32, Instant)>,
    pub(super) last_snapshot_height: u64,
    pub(super) prev_finalized_root: Option<[u8; 32]>,
    pub(super) pending_snapshot_xshard: Option<(u64, Vec<u8>)>,
    pub(super) retro_published_upto: u64,
    pub(super) last_retro_publish: Instant,
    pub(super) last_catchup: Instant,
    pub(super) catchup_pending: bool,
    pub(super) peer_named_height: u64,
    pub(super) catchup_at_tip_skips: u64,
    pub(super) last_live_adopt: Instant,
    pub(super) last_inbound_msg: Instant,
    pub(super) retro_tip_at_last_pass: u64,
    pub(super) last_consensus_rx_ms: u64,
    pub(super) last_consensus_frame_ms: u64,
    pub(super) last_silence_probe_ms: u64,
    pub(super) last_liveness_emit_ms: Option<u64>,
    pub(super) last_behind_peer_seen: Option<Instant>,
    pub(super) votes_seen_height: u64,
    pub(super) votes_seen_voters: std::collections::HashSet<[u8; 32]>,
    pub(super) last_fast_timeout_logged: Option<(u64, u32)>,
    pub(super) last_prune_height: u64,
    pub(super) chain_binding_drained: bool,
    pub(super) tick_no: u64,
    pub(super) split_ticks: u64,
    pub(super) split_tick_ms: u64,
    pub(super) split_catchup_ms: u64,
    pub(super) split_retro_ms: u64,
    pub(super) split_probe_ms: u64,
    pub(super) split_join_ms: u64,
    pub(super) split_catchup_n: u64,
    pub(super) split_retro_n: u64,
    pub(super) split_probe_n: u64,
    pub(super) split_join_n: u64,
}

/// Per-tick transient metrics and flags.
pub(super) struct TickStep {
    pub(super) tick_t0: Instant,
    pub(super) height: u64,
    pub(super) round: u32,
    pub(super) reactive_catchup_due: bool,
    pub(super) net_budget: Duration,
    pub(super) catchup_ran: bool,
    pub(super) retro_ran: bool,
    pub(super) probe_ran: bool,
    pub(super) join_ran: bool,
    pub(super) outbox_flushes: u32,
    pub(super) catchup_ms: u64,
    pub(super) retro_ms: u64,
    pub(super) probe_ms: u64,
    pub(super) join_ms: u64,
    pub(super) can_vote: bool,
}

/// True when `round` is at or below the highest round already signed at
/// `height`. Such a vote is refused — the round was already used (possibly
/// before a crash), so re-voting there is exactly the double-sign the
/// watermark exists to prevent.
pub(super) fn round_at_or_below_vote_floor(
    floor: Option<(u64, u32)>,
    height: u64,
    round: u32,
) -> bool {
    matches!(floor, Some((h, r)) if h == height && round <= r)
}

/// Liveness cap for the persisted CONSENSUS round on restart.
///
/// This is a LIVENESS bound only (a runaway view-change loop must not resume
/// at round 806 while peers sit at round 0). It is NEVER a cap on the vote
/// watermark: a round this node already signed must not be re-entered, so the
/// watermark is a hard FLOOR applied after this cap (Finding C).
pub(super) const MAX_RESTORED_ROUND: u32 = 64;

/// The round a restart resumes at: the persisted consensus round clamped for
/// liveness, then raised — never lowered — to the vote watermark floor.
///
/// Pure and shared with the regression test, so the test exercises the exact
/// production arithmetic instead of re-deriving it.
pub(super) fn restored_round(persisted_round: u32, vote_watermark_floor: Option<u32>) -> u32 {
    let capped = persisted_round.min(MAX_RESTORED_ROUND);
    vote_watermark_floor.map_or(capped, |floor| capped.max(floor))
}

/// Boot-time validator self-check text for THIS node's local validator id.
///
/// Returns `(loud_eprintln, message)`:
///  * a record with a cold `withdrawal_address` -> `None` (healthy, no log);
///  * a record with `withdrawal_address == None` -> LOUD: every owner
///    operation (unjail/unbond/claim/withdraw/commission/rotation) is
///    impossible until the one-time `SysCallClaimWithdrawal` migration;
///  * no record at all -> explicit WARN that this node is not bonded (or the
///    restored ledger lags), never a silent skip.
///
/// Read-only and never fatal: the check exists so the nodeB failure mode (a
/// jailed validator whose release height passed while every unjail was
/// refused because the record had no cold address) is visible at boot
/// instead of only under a refusal. It MUST NOT mutate state or block startup.
pub(super) fn local_validator_self_check_message(
    local_id: &[u8; 32],
    ledger: &stellereum::staking::StakingLedger,
) -> Option<(bool, String)> {
    match ledger.validators.get(local_id) {
        None => Some((
            false,
            format!(
                "[validator-self-check] local validator {} has NO staking record in the restored \
                 ledger: this node is not bonded (yet), so it cannot earn voting power from stake. \
                 No state was modified; if this node is supposed to validate, bond it once the \
                 ledger is fully synced",
                hex::encode(local_id)
            ),
        )),
        Some(v) if v.withdrawal_address.is_none() => Some((
            true,
            format!(
                "[validator-self-check] UNMANAGEABLE: local validator {} has NO cold \
                 withdrawal_address. Every owner operation (unjail, unbond, claim-rewards, \
                 withdraw self-bond, commission change, voting-key rotation) is refused until \
                 SysCallClaimWithdrawal (OpCode 62) claims one. Recover with: `stellereum \
                 validator claim-withdrawal --validator-id {} --voting-key-file ./keys/falcon.key \
                 --withdrawal-key-file <cold-withdrawal-key>` (use --dry-run first). No state was \
                 modified and startup continues",
                hex::encode(local_id),
                hex::encode(local_id)
            ),
        )),
        Some(_) => None,
    }
}

/// Emit [`local_validator_self_check_message`] once at startup. The
/// unmanageable case also goes to stderr so an operator sees it even when
/// `tracing` is filtered to a file, exactly like the other LOUD startup
/// warnings in this driver.
pub(super) fn log_local_validator_self_check(
    local_id: &[u8; 32],
    ledger: &stellereum::staking::StakingLedger,
) {
    if let Some((loud, msg)) = local_validator_self_check_message(local_id, ledger) {
        tracing::warn!("{msg}");
        if loud {
            eprintln!("{msg}");
        }
    }
}

/// Process CPU seconds (utime + stime) from `/proc/self/stat`.
///
/// Linux `USER_HZ` is 100 on every mainstream build; a different value would
/// scale every reading by a constant, never distort a comparison. `None` off
/// Linux or when the file cannot be parsed, so the metric simply stays absent.
pub(super) fn process_cpu_seconds() -> Option<f64> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let close = stat.rfind(')')?;
    let fields: Vec<&str> = stat.get(close + 1..)?.split_whitespace().collect();
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    Some((utime + stime) as f64 / 100.0)
}

/// Exact field-wise comparison for `Governance` so the 50ms consensus tick skips
/// cloning `shared_gov` when no field changed.
pub(super) fn governance_equal(
    a: &stellereum::governance::Governance,
    b: &stellereum::governance::Governance,
) -> bool {
    a.next_id == b.next_id
        && a.quorum_bps == b.quorum_bps
        && a.applied == b.applied
        && a.proposals.len() == b.proposals.len()
        && a.timelocks.len() == b.timelocks.len()
        && a.gov_propose_nonces.len() == b.gov_propose_nonces.len()
        && a.proposals == b.proposals
        && a.timelocks == b.timelocks
        && a.gov_propose_nonces == b.gov_propose_nonces
}

/// Immediate DHT body/head publish gate on finalize/adopt: the block's proposer
/// always publishes immediately, 1–2 validator setups always publish, and other
/// nodes reinforce every 4th height (periodic `retro_publish_pass` covers any
/// lagging peer). Cuts redundant `dht.store` storms by ~3-4x on 4-node clusters.
pub(super) fn should_publish_body_now(
    validator_count: usize,
    is_proposer: bool,
    height: u64,
) -> bool {
    validator_count <= 2 || is_proposer || height.is_multiple_of(4)
}

/// Immediate DHT header publish gate on finalize/adopt: the block's proposer
/// always persists the header immediately (keeping every height's header
/// present for snapshot-anchor walks), 1–2 validator setups always persist, and
/// non-proposers reinforce every 8th height.
pub(super) fn should_publish_header_now(
    validator_count: usize,
    is_proposer: bool,
    height: u64,
) -> bool {
    validator_count <= 2 || is_proposer || height.is_multiple_of(8)
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
/// True ONLY when `restore_last_decision_from_finalized_block` actually
/// verified and retained a precommit QC for `fh` (not when it degraded to
/// `last_decision = None` on a missing/forged/degenerate QC).
pub(super) fn finalize_restore_qc_verified(rt: &ValidatorRuntime, fh: u64) -> bool {
    rt.last_decision.as_ref().is_some_and(|(h, _, _)| *h == fh)
}

pub(super) async fn write_ahead_finalized_block(
    ap: &stellereum::storage::AsyncPersistence,
    height: u64,
    bh: [u8; 32],
    block: stellereum::sharding::Block,
    flush_now: bool,
) -> Result<(), String> {
    let store = ap.storage();
    tokio::task::spawn_blocking(move || {
        store.put_block(&block)?;
        store.set_finalized(height, &bh)?;
        if flush_now {
            store.flush()?;
        }
        Ok::<(), anyhow::Error>(())
    })
    .await
    .map_err(|e| format!("persist task panicked: {e}"))?
    .map_err(|e| format!("{e}"))
}

pub(super) fn reconciled_finalized_tip(
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

/// Raise the in-memory floor after a vote was cast this process.
pub(super) fn advance_vote_floor(floor: &mut Option<(u64, u32)>, height: u64, round: u32) {
    match floor {
        Some((h, r)) if *h == height => {
            if round > *r {
                *r = round;
            }
        }
        _ => *floor = Some((height, round)),
    }
}

pub(crate) fn apply_peer_pq_keys_env_at(init_height: u64, peers_env: Option<&str>) {
    if stellereum::pq_registry::pq_lifecycle_active_at(init_height) {
        if peers_env.is_some_and(|s| !s.trim().is_empty()) {
            tracing::warn!(
                init_height,
                "[post-quantum] ignoring STELL_PEER_PQ_KEYS: W3 PQ lifecycle is active at height {init_height}; committed on-chain PqRegistry is authoritative"
            );
            eprintln!(
                "[WARN] ignoring STELL_PEER_PQ_KEYS at height {init_height}: W3 PQ lifecycle is active; committed on-chain PqRegistry is authoritative"
            );
        }
        return;
    }
    if let Some(peers) = peers_env {
        for entry in peers.split(',') {
            let mut parts = entry.split(':');
            if let (Some(ed_hex), Some(pq_hex)) = (parts.next(), parts.next()) {
                if let (Ok(ed), Ok(pq)) = (hex::decode(ed_hex.trim()), hex::decode(pq_hex.trim())) {
                    if let Ok(ed_arr) = ed.as_slice().try_into() {
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
}

#[allow(clippy::too_many_arguments)]
// GATE: 16 consensus wiring inputs are required together; grouping would change call sites and sync semantics.
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
    pq_signer: Option<Arc<dyn stellereum::remote_signer::PqSigner>>,
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
    let rx = net.subscribe().await;
    let gossip = Arc::new(TxGossip::new(adapter.clone()));
    let tx_rx = gossip.subscribe().await;
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
    // Post-quantum validator identity: persistent Falcon-512 keypair or
    // v2 remote signer (`STELL_REMOTE_SIGNER_URL`). When a v2 signer is
    // supplied (or `STELL_REMOTE_SIGNER_URL` is configured), NEVER open or
    // generate `./keys/falcon.key`. At/after `PQ_LIFECYCLE_ACTIVATION_HEIGHT`,
    // `STELL_PEER_PQ_KEYS` is ignored with a loud WARN and committed
    // on-chain `PqRegistry` is authoritative.
    let init_height = persistence
        .as_ref()
        .map(|ap| {
            let s = ap.storage();
            let fin = s.finalized().ok().flatten().map(|(h, _)| h).unwrap_or(0);
            let st = s.latest_state_height().ok().flatten().unwrap_or(0);
            fin.max(st)
        })
        .unwrap_or(0);
    let w3_active_at_init = stellereum::pq_registry::pq_lifecycle_active_at(init_height);
    let our_falcon: Option<stellereum::post_quantum::FalconKeypair> =
        if let Some(ref ps) = pq_signer {
            info!(
                "[post-quantum] validator Falcon-512 pubkey (v2 signer): {}",
                hex::encode(ps.public_key())
            );
            if !w3_active_at_init {
                stellereum::consensus::register_validator_pq_key(
                    self_vote_id,
                    ps.scheme(),
                    ps.public_key().to_vec(),
                );
            }
            None
        } else if std::env::var(stellereum::remote_signer::REMOTE_SIGNER_URL_ENV)
            .ok()
            .is_some_and(|s| !s.trim().is_empty())
        {
            panic!(
                "[fatal] STELL_REMOTE_SIGNER_URL is configured but no v2 PqSigner was wired; \
             refusing to open local ./keys/falcon.key (zero local fallback)"
            );
        } else {
            let falcon_path = std::env::var("STELL_FALCON_KEY_FILE")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| std::path::PathBuf::from("./keys/falcon.key"));
            let k: stellereum::post_quantum::FalconKeypair =
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
                hex::encode(&k.public_key)
            );
            if !w3_active_at_init {
                stellereum::consensus::register_validator_pq_key(
                    self_vote_id,
                    stellereum::post_quantum::PqScheme::Falcon512,
                    k.public_key.clone(),
                );
            }
            Some(k)
        };
    apply_peer_pq_keys_env_at(
        init_height,
        std::env::var("STELL_PEER_PQ_KEYS").ok().as_deref(),
    );
    // Election is the canonical parent-hash draw (no key material provisioned).
    let mut rt = ValidatorRuntime::new(key, validators, state.clone(), 1)
        .with_mempool(rpc.mempool.clone())
        // The epoch-seal frames (the DKG contribution, the order commitment
        // and the share release) travel on the transaction-gossip channel.
        .with_tx_gossip(gossip.clone())
        .with_shard(block_shard, registry.clone())
        .with_block_reward(BLOCK_REWARD_NANO)
        .with_parallel_exec(parallel_exec)
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
                // Publication is a synchronous, non-blocking fan-out into a
                // bounded broadcast: no `state.accounts` / `receipts` lock is
                // held here, so a slow consumer cannot stall the fork-choice
                // path. Account/token deltas of finalized blocks travel the
                // same way from the record lane (`publish_block_deltas`).
                stellereum::rpc::publish_invalidation(&sig);
            },
        ))
        // The masterchain's staking registry, shared process-wide. On the
        // masterchain this IS its own registry (its state engine's ledger);
        // on a workchain it is the master's, so the workchain's consensus set
        // follows every masterchain rotation instead of freezing on the
        // config-defined set.
        .with_master_staking(master_staking.clone());
    if let Some(ps) = pq_signer {
        rt = rt
            .with_pq_signer(ps)
            .expect("pq signer validator_id must match the validator identity");
    } else if let Some(fk) = our_falcon {
        if w3_active_at_init {
            let local_pq = stellereum::remote_signer::LocalPqSigner::new(fk, self_vote_id)
                .expect("local falcon key must produce valid LocalPqSigner");
            rt = rt
                .with_pq_signer(Arc::new(local_pq))
                .expect("local pq signer validator_id must match the validator identity");
        } else {
            rt = rt.with_falcon_key(fk);
        }
    }
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
                {
                    let pq_reg = rt.state.pq_registry_read().await;
                    let active = stellereum::pq_registry::pq_lifecycle_active_at(h);
                    if active || !pq_reg.is_empty() {
                        stellereum::consensus::sync_committed_pq_registry(&pq_reg, active);
                    }
                }
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
                let legacy_ledger_h: Option<u64> =
                    ap.storage().latest_ledger_height().ok().flatten();
                let snap_v4_authority = ap
                    .storage()
                    .latest_snap_committed()
                    .ok()
                    .flatten()
                    .is_some_and(|m| m.height == h)
                    && legacy_ledger_h.is_none_or(|lh| lh < h);
                let ledger_h_for_check: u64 = if snap_v4_authority {
                    h
                } else {
                    legacy_ledger_h.unwrap_or(h)
                };
                // Newest-state vs newest-domains gap (crash-tail detector).
                if !snap_v4_authority {
                    if let Ok(Some((s_newest, l_newest))) = ap.storage().ledger_state_gap() {
                        if let Err(reason) =
                            stellereum::storage::check_validator_set_freshness(s_newest, l_newest)
                        {
                            rt.mark_validator_set_stale(s_newest, l_newest, reason);
                        }
                    }
                }
                if let Ok(Some(hist)) = ap.storage().load_validator_set_history() {
                    if !hist.is_empty() {
                        info!(
                            "[storage] restored {} validator_set_history entries",
                            hist.len()
                        );
                        rt.restore_validator_set_history(hist);
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
                let gov = match &rt.governance {
                    Some(g) => g.clone(),
                    None => rt.state.governance_read().await.clone(),
                };
                ap.snapshot_domains(&rt.state, &ledger, &gov, restored_state_height)
                    .await;
                info!(
                    "[storage] wrote a snapshot of engine state at height {restored_state_height} (tip {fh})"
                );
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
                    let mut current_height = restored_state_height;
                    let mut healed = false;
                    for attempt in 1..=HEAL_MAX_ATTEMPTS {
                        // Track `current_height` in-place rather than reading
                        // `rt.finalized.last()` (which already holds `fh` from
                        // boot seeding) so partial progress S+1..=S+k is never
                        // replayed from stale S on retry.
                        let attempt_res = match tokio::time::timeout(
                            HEAL_ENGINE_TIMEOUT,
                            catchup::heal_engine_to_head(
                                &adapter,
                                &mut rt,
                                &ap.storage(),
                                block_shard,
                                &mut current_height,
                                fh,
                                fhash,
                            ),
                        )
                        .await
                        {
                            Ok(res) => res,
                            Err(_) => Err(format!(
                                "healing timed out after {}s (engine progressed to {current_height})",
                                HEAL_ENGINE_TIMEOUT.as_secs()
                            )),
                        };
                        match attempt_res {
                            Ok(reached) => {
                                info!("[storage] healed engine to height {reached}");
                                {
                                    let pq_reg = rt.state.pq_registry_read().await;
                                    let active =
                                        stellereum::pq_registry::pq_lifecycle_active_at(reached);
                                    if active || !pq_reg.is_empty() {
                                        stellereum::consensus::sync_committed_pq_registry(
                                            &pq_reg, active,
                                        );
                                    }
                                }
                                ap.snapshot_state(&rt.state, reached).await;
                                let ledger = rt.staking_read().await.clone();
                                let gov = match &rt.governance {
                                    Some(g) => g.clone(),
                                    None => rt.state.governance_read().await.clone(),
                                };
                                ap.snapshot_domains(&rt.state, &ledger, &gov, reached).await;
                                info!("[storage] persisted healed engine snapshot at height {reached}");
                                restored_state_height = reached;
                                healed = true;
                                break;
                            }
                            Err(e) => {
                                // Retain any partial replay progress S+1..=S+k
                                // across retries and fail-closed reporting.
                                restored_state_height = current_height;
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

        // P0-SAFETY-BOOT-ONE-BLOCK: Fail-closed, proof-carrying reconciliation
        // when hard `SIGKILL` / power loss left `safety_record_v1.finalized_height`
        // ahead of `storage.finalized()` (including `fh == 0` / height 1).
        // Never lowers `safety_record_v1`; only advances `storage.finalized()` and
        // engine state forward if every intervening block exists locally, links to
        // `safety_record_v1.finalized_hash`, and passes precommit QC verification.
        let mut sigkill_reconcile_failed: Option<String> = None;
        if let Some(ap) = &persistence {
            if let Ok(Some(genesis_bytes)) = ap.storage().get_meta("genesis_state_root") {
                if genesis_bytes.len() == 32 {
                    let mut genesis_root = [0u8; 32];
                    genesis_root.copy_from_slice(&genesis_bytes);
                    let identity = stellereum::storage::SafetyRecordIdentity {
                        validator: self_vote_id,
                        chain: stellereum::safety::derive_safety_chain_id(
                            stellereum::consensus::consensus_chain_id(),
                            &genesis_root,
                        ),
                        shard: block_shard,
                    };
                    match stellereum::safety::reconcile_boot_sigkill_gap(
                        &ap.storage(),
                        identity,
                        &mut rt,
                        restored_state_height,
                    )
                    .await
                    {
                        Ok(stellereum::safety::BootReconcileOutcome::NoGap) => {}
                        Ok(stellereum::safety::BootReconcileOutcome::Reconciled {
                            from_height,
                            to_height,
                            finalized_hash: _,
                            replayed_to_height,
                        }) => {
                            if replayed_to_height > restored_state_height {
                                let pq_reg = rt.state.pq_registry_read().await;
                                let active = stellereum::pq_registry::pq_lifecycle_active_at(
                                    replayed_to_height,
                                );
                                if active || !pq_reg.is_empty() {
                                    stellereum::consensus::sync_committed_pq_registry(
                                        &pq_reg, active,
                                    );
                                }
                                drop(pq_reg);
                                ap.snapshot_state(&rt.state, replayed_to_height).await;
                                let ledger = rt.staking_read().await.clone();
                                let gov = match &rt.governance {
                                    Some(g) => g.clone(),
                                    None => rt.state.governance_read().await.clone(),
                                };
                                ap.snapshot_domains(&rt.state, &ledger, &gov, replayed_to_height)
                                    .await;
                                restored_state_height = replayed_to_height;
                            }
                            info!(
                                "[storage] reconciled SIGKILL gap: recovered finalized tip {from_height} -> {to_height} \
                                 and engine state to {restored_state_height} from durable QC-verified blocks"
                            );
                        }
                        Err(e) => {
                            let msg =
                                format!("safety_record_v1 boot reconciliation failed closed: {e}");
                            eprintln!("[safety] {msg}");
                            tracing::error!("{msg}");
                            sigkill_reconcile_failed = Some(msg);
                        }
                    }
                }
            }
        }

        // EXECUTION_PIPELINE_V1: seed `post_state_roots` from the restored/healed
        // engine state (or genesis when starting fresh) plus the lag-2 predecessor
        // root from storage so lag-2 proposing and validation work immediately
        // across genesis and restarts.
        if restored_state_height == 0 && rt.finalized.is_empty() {
            rt.ensure_genesis_root_seeded().await;
        } else if restored_state_height > 0 {
            let restored_root = rt.state.get_state_root().await;
            rt.note_post_state_root(restored_state_height, restored_root);
            let needed = stellereum::chain_spec::committed_state_height_at(rt.hc.height);
            if !rt.post_state_roots.contains_key(&needed) {
                if let Some(ap) = &persistence {
                    if let Ok(Some(prev_root)) = ap.storage().finalized_post_root_at(needed) {
                        rt.note_post_state_root(needed, prev_root);
                    } else if needed == 0 {
                        if let Ok(Some(g_bytes)) = ap.storage().get_meta("genesis_state_root") {
                            if let Ok(g_arr) = <[u8; 32]>::try_from(g_bytes.as_slice()) {
                                rt.note_post_state_root(0, g_arr);
                            }
                        }
                    } else if let Ok(Some(hdr)) = ap.storage().header_at(
                        stellereum::chain_spec::anchor_height_for_post_state_at(needed),
                    ) {
                        rt.note_post_state_root(needed, hdr.state_root);
                    }
                }
            }
        }

        // BOOT VALIDATOR SELF-CHECK (validator resilience). Runs on the
        // masterchain only (the staking registry lives there; a workchain's
        // ledger is intentionally empty) and after the restore/heal above, so
        // it sees the ledger this node will actually vote with. Read-only:
        // warns loudly when THIS node's record exists without a cold
        // withdrawal address (every owner op impossible until ClaimWithdrawal)
        // or when the record is missing, and never fails startup.
        if is_validator && block_shard == stellereum::sharding::MASTERCHAIN_SHARD {
            let ledger = rt.staking_read().await;
            log_local_validator_self_check(&self_vote_id, &ledger);
        }

        // DOWNTIME-RESTORE (P0): rebuild the parent-decision stash from the
        // PERSISTED finalized tip before this node may propose again.
        //
        // `last_decision` is in-memory only, so a plain restart at the tip
        // used to come back with `None`; the next proposal then omitted the
        // canonical downtime QC for the parent and every peer that decided
        // that parent rejected the block ("omits the downtime evidence for
        // decided height..."), stalling the chain while this node held the
        // slot. The tip body and the precommit QC embedded in it are durable
        // and locally verifiable, so reconstruct from those - never from a
        // peer's claim.
        //
        // If the stored body predates embedded decision proofs there is
        // nothing to verify: FAIL CLOSED (arm `parent_evidence_missing`, which
        // makes `propose` skip the slot) instead of emitting an invalid block.
        // A later verified adopt/sync/finalize restores the evidence.
        let mut restored_finalized_qc_verified = false;
        if let Some((fh, fhash)) = rt.finalized.last().copied() {
            if fh > 0 {
                match ap.storage().get_block(&fhash) {
                    Ok(Some(block)) => {
                        match rt.restore_last_decision_from_finalized_block(&block) {
                            Ok(()) => {
                                restored_finalized_qc_verified =
                                    finalize_restore_qc_verified(&rt, fh);
                                if restored_finalized_qc_verified {
                                    info!(
                                        "[storage] DOWNTIME-RESTORE: rebuilt the parent decision evidence \
                                         for finalized height {fh} ({}) from the persisted block",
                                        hex::encode(fhash)
                                    );
                                } else {
                                    tracing::warn!(
                                        height = fh,
                                        hash = %hex::encode(fhash),
                                        "DOWNTIME-RESTORE: finalized block lacks a verifiable precommit QC; \
                                         degraded to no-decision state (restored_finalized_qc_verified=false)"
                                    );
                                }
                            }
                            Err(e) => {
                                eprintln!(
                                    "[storage] DOWNTIME-RESTORE: cannot rebuild the downtime \
                                     evidence for finalized height {fh} ({}): {e}; REFUSING to \
                                     propose until a verified peer decision restores it \
                                     (fail closed)",
                                    hex::encode(fhash)
                                );
                                tracing::error!(
                                    height = fh,
                                    hash = %hex::encode(fhash),
                                    error = %e,
                                    "DOWNTIME-RESTORE: parent decision evidence unreconstructible; proposals disabled (fail closed)"
                                );
                            }
                        }
                    }
                    Ok(None) => {
                        rt.parent_evidence_missing = true;
                        eprintln!(
                            "[storage] DOWNTIME-RESTORE: the persisted finalized tip {fh} ({}) \
                             has no local body; REFUSING to propose until a verified peer \
                             decision restores the evidence (fail closed)",
                            hex::encode(fhash)
                        );
                        tracing::error!(
                            height = fh,
                            hash = %hex::encode(fhash),
                            "DOWNTIME-RESTORE: finalized tip body missing from the store; proposals disabled (fail closed)"
                        );
                    }
                    Err(e) => {
                        rt.parent_evidence_missing = true;
                        eprintln!(
                            "[storage] DOWNTIME-RESTORE: cannot READ the persisted finalized tip \
                             {fh} ({}): {e}; REFUSING to propose until a verified peer \
                             decision restores the evidence (fail closed)",
                            hex::encode(fhash)
                        );
                    }
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
                    let mut restored_body = None;
                    if !rt.blocks.contains_key(&h) {
                        restored_body = ap.storage().get_block(&h).ok().flatten();
                        if restored_body.is_none() {
                            // The lock BODY is durable state too: without it
                            // the restored lock can never be compared to a
                            // re-stamp (`same_value` needs both value ids) and
                            // the locked node nils every proposal for the rest
                            // of the height. Old checkpoints may predate
                            // lock-body persistence, so fetch it before
                            // giving up.
                            restored_body = adapter.fetch_block(&h).await;
                        }
                    }
                    if let Some(blk) = restored_body {
                        rt.blocks.insert(h, blk);
                    }
                    // Rebuild the round-free value identity of the lock. It
                    // is not part of the checkpoint, and a re-stamped rescue
                    // body has a DIFFERENT signed hash for the SAME value, so
                    // without this a restored node would nil its own lock's
                    // re-proposal (RESTART-SPLIT).
                    if let Some(blk) = rt.blocks.get(&h) {
                        let vid = blk.value_id();
                        rt.hc.note_value_id(h, vid);
                    } else {
                        tracing::warn!(
                            "[consensus] restored lock for height {} round {} but its body {} is missing; \
                             the lock cannot be re-proposed until the body is recovered",
                            cp.height,
                            cp.locked_round,
                            hex::encode(&h[..6]),
                        );
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

        // Durable SafetyAuthority boot reconciliation (`05_LOCK_SAFETY_P0.md` §2.4):
        // Production driver MUST use `SafetyBackend::Durable`. Clean-genesis
        // auto-init happens ONLY with `STELL_NEW_CHAIN=1` on a pristine store;
        // any legacy/absent/corrupt/mismatched store quarantines fail-closed
        // to non-signing Observer until explicit `stellereum safety-init`.
        let observer_env =
            stellereum::bootstrap::is_observer_env(std::env::var("STELL_OBSERVER").ok().as_deref());
        match ap.storage().get_meta("genesis_state_root") {
            Ok(Some(genesis_bytes)) if genesis_bytes.len() == 32 => {
                let mut genesis_root = [0u8; 32];
                genesis_root.copy_from_slice(&genesis_bytes);
                let identity = stellereum::storage::SafetyRecordIdentity {
                    validator: self_vote_id,
                    chain: stellereum::safety::derive_safety_chain_id(
                        stellereum::consensus::consensus_chain_id(),
                        &genesis_root,
                    ),
                    shard: block_shard,
                };
                let restored_finalized = if sigkill_reconcile_failed.is_some() {
                    ap.storage().finalized().ok().flatten()
                } else {
                    rt.finalized.last().copied()
                };
                let boot_ctx = stellereum::safety::SafetyBootContext {
                    is_validator,
                    is_observer_env: observer_env,
                    new_chain_explicit: stellereum::bootstrap::is_new_chain_explicit_env(),
                    restored_finalized,
                    restored_state_height: Some(restored_state_height),
                    restored_finalized_qc_verified,
                    legacy_checkpoint: restored_checkpoint.clone(),
                    legacy_watermark: restored_watermark.clone(),
                };
                rt.safety = stellereum::safety::SafetyAuthority::open_from_storage(
                    ap.storage(),
                    identity,
                    boot_ctx,
                );
                if let Some(reason) = sigkill_reconcile_failed.take() {
                    if matches!(rt.safety.mode(), stellereum::safety::AuthorityMode::Active) {
                        rt.safety.quarantine(reason);
                    }
                }
            }
            Ok(Some(other)) => {
                rt.safety = stellereum::safety::SafetyAuthority::new_quarantined(format!(
                    "genesis_state_root has invalid length {} (expected 32)",
                    other.len()
                ));
            }
            Ok(None) => {
                if !is_validator || observer_env {
                    rt.safety = stellereum::safety::SafetyAuthority::new_observer();
                } else {
                    rt.safety = stellereum::safety::SafetyAuthority::new_quarantined(
                        "missing genesis_state_root metadata; cannot derive safety record identity",
                    );
                }
            }
            Err(e) => {
                rt.safety = stellereum::safety::SafetyAuthority::new_quarantined(format!(
                    "failed to read genesis_state_root metadata: {e}"
                ));
            }
        }

        if let Some(srec) = rt.safety.current_state() {
            if srec.height != rt.hc.height {
                rt.safety.quarantine(format!(
                    "safety_record_v1 height {} disagrees with runtime height {}",
                    srec.height, rt.hc.height
                ));
            } else {
                if let Some(floor) = [srec.highest_prevote_round, srec.highest_precommit_round]
                    .into_iter()
                    .flatten()
                    .max()
                {
                    if rt.hc.round < floor {
                        rt.hc.round = floor;
                    }
                }
                if let Some(lock) = srec.locked {
                    rt.hc.locked = Some((lock.block_hash, lock.round));
                    rt.hc.note_value_id(lock.block_hash, lock.value_id);
                    match ap.storage().get_block(&lock.block_hash) {
                        Ok(Some(blk))
                            if blk.height == srec.height
                                && blk.compute_hash() == lock.block_hash
                                && blk.value_id() == lock.value_id =>
                        {
                            rt.blocks.insert(lock.block_hash, blk);
                        }
                        Ok(Some(_)) => {
                            rt.safety.quarantine(format!(
                                "corrupt/mismatched durable lock body {} at height {} (staying locked, signing disabled)",
                                hex::encode(&lock.block_hash[..6]),
                                srec.height
                            ));
                        }
                        Ok(None) => {
                            rt.safety.quarantine(format!(
                                "missing durable lock body {} at height {} (staying locked, signing disabled)",
                                hex::encode(&lock.block_hash[..6]),
                                srec.height
                            ));
                        }
                        Err(e) => {
                            rt.safety.quarantine(format!(
                                "failed reading durable lock body {} at height {}: {e}",
                                hex::encode(&lock.block_hash[..6]),
                                srec.height
                            ));
                        }
                    }
                }
            }
        }
    } else {
        let observer_env =
            stellereum::bootstrap::is_observer_env(std::env::var("STELL_OBSERVER").ok().as_deref());
        if !is_validator || observer_env {
            rt.safety = stellereum::safety::SafetyAuthority::new_observer();
        } else {
            rt.safety = stellereum::safety::SafetyAuthority::new_quarantined(
                "durable persistence unavailable for validator",
            );
        }
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

    // Ensure `post_state_roots` covers `committed_state_height_at(rt.hc.height)`
    // after startup catch-up (genesis, snapshot sync, or tail walk).
    if rt.finalized.is_empty() && rt.apply_in_flight_depth() == 0 {
        rt.ensure_genesis_root_seeded().await;
    } else {
        let needed = stellereum::chain_spec::committed_state_height_at(rt.hc.height);
        if !rt.post_state_roots.contains_key(&needed) {
            if let Some(ap) = &persistence {
                if let Ok(Some(prev_root)) = ap.storage().finalized_post_root_at(needed) {
                    rt.note_post_state_root(needed, prev_root);
                } else if needed == 0 {
                    if let Ok(Some(g_bytes)) = ap.storage().get_meta("genesis_state_root") {
                        if let Ok(g_arr) = <[u8; 32]>::try_from(g_bytes.as_slice()) {
                            rt.note_post_state_root(0, g_arr);
                        }
                    }
                } else if let Ok(Some(hdr)) =
                    ap.storage()
                        .header_at(stellereum::chain_spec::anchor_height_for_post_state_at(
                            needed,
                        ))
                {
                    rt.note_post_state_root(needed, hdr.state_root);
                }
            }
        }
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
    // Seed liveness dedup hints from the authoritative SafetyAuthority state.
    if let Some(srec) = rt.safety.current_state() {
        if let Some(pr) = srec.highest_prevote_round {
            advance_vote_floor(&mut vote_floor, srec.height, pr);
            last_prevoted = Some((srec.height, pr));
        }
        if let Some(pcr) = srec.highest_precommit_round {
            advance_vote_floor(&mut vote_floor, srec.height, pcr);
            advance_vote_floor(&mut precommit_floor, srec.height, pcr);
            last_precommitted = Some((srec.height, pcr));
        }
    }
    let peer_hint_at = rt.peer_hint.map(|_| Instant::now());
    let peer_hint_seen = rt.peer_hint;
    let round_timeout = Duration::from_millis(stellereum::consensus::FROZEN_ROUND_TIMEOUT_BASE_MS);
    let tick_ms = std::env::var("STELL_TICK_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(TICK_MS)
        .clamp(20, 1000);
    let min_block_time = Duration::from_millis(
        std::env::var("STELL_MIN_BLOCK_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_MIN_BLOCK_MS),
    );
    let last_snapshot_height = (rt.hc.height / 100) * 100;
    let mut retro_published_upto: u64 = 0;
    let catchup_interval = catchup_interval();
    let retro_publish_interval = retro_publish_interval();
    let peer_named_height = rt.finalized.last().map(|(h, _)| *h).unwrap_or(0);
    let live_adopt_fresh_window = std::time::Duration::from_millis(LIVE_ADOPT_FRESH_MS);
    let retro_tip_at_last_pass = rt.finalized.last().map(|(h, _)| *h).unwrap_or(0);
    let votes_seen_height = rt.hc.height;

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
    //  * `publish_lane` carries strictly live tip writes -- tip `publish_head`,
    //    tip `persist_block_header`, and tip single-body publish -- in submission
    //    order so live finality announcements never queue behind backfill.
    //  * `backfill_lane` carries periodic/startup `retro_publish_pass`, multi-body
    //    backfill supplements, and snapshot/domain uploads.
    //  * `record_lane` carries the local RPC records (receipts + height).
    //  * `prune_lane` carries the DHT retention prune.
    let publish_lane = spawn_tick_lane();
    let backfill_lane = spawn_tick_lane();
    let record_lane = spawn_tick_lane();
    let prune_lane = spawn_tick_lane();
    let mempool_save_guard = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let prune_guard = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // Guard for the prune_lane retention-prune submits (see the finalize
    // block): at most one prune pass queued/running at a time.
    let prune_lane_guard = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Push what we already have onto `backfill_lane` without blocking node
    // startup awaiting up to 128 DHT body stores.
    retro_publish_pass(
        adapter.clone(),
        &rt,
        persistence.as_ref(),
        &mut retro_published_upto,
        Some(&backfill_lane),
    )
    .await;

    let cfg = DriverConfig {
        adapter,
        shard,
        block_shard,
        persistence,
        shared_gov,
        rpc,
        is_validator,
        net,
        net_sender,
        gossip,
        self_vote_id,
        mempool_path,
        retention,
        publish_lane,
        backfill_lane,
        record_lane,
        prune_lane,
        mempool_save_guard,
        prune_guard,
        prune_lane_guard,
        round_timeout,
        tick_ms,
        min_block_time,
        catchup_interval,
        retro_publish_interval,
        live_adopt_fresh_window,
    };

    let now_wall = Instant::now();
    let now_epoch_ms = stellereum::liveness_alarm::now_ms();
    let mut st = DriverState {
        rt,
        rx,
        tx_rx,
        last_prevoted,
        last_precommitted,
        vote_floor,
        precommit_floor,
        last_blockers_log: None,
        last_gate_diag: None,
        parse_fail_count: 0,
        inbound_overcap_count: 0,
        inbound_deferred: std::collections::VecDeque::new(),
        loopback_queue: std::collections::VecDeque::new(),
        loopback_dropped: 0,
        compact_index: stellereum::consensus_net::CompactIndexCache::new(),
        compact_peer_frames: std::collections::HashMap::new(),
        compact_peer_pulls: std::collections::HashMap::new(),
        compact_budget_dropped: 0,
        compact_full_requests: 0,
        compact_index_builds_tick: 0,
        peer_hint_at,
        peer_hint_seen,
        inbound_defer_count: 0,
        inbound_compact_refused: 0,
        compact_rx: stellereum::consensus_net::CompactReceiver::new(),
        compact_server: stellereum::consensus_net::CompactBodyServer::new(),
        compact_looped: 0,
        compact_served: 0,
        last_probe: now_wall - Duration::from_secs(60),
        last_mempool_save: now_wall,
        last_mempool_kv_poll: now_wall - Duration::from_millis(MEMPOOL_KV_POLL_INTERVAL_MS),
        last_workchain_set_repair: now_wall,
        cast_prevote: None,
        cast_precommit: None,
        outbox: std::collections::VecDeque::new(),
        last_flush: now_wall,
        last_rexmit: now_wall,
        round_started: now_wall,
        last_block_at: now_wall - min_block_time,
        apply_in_flight_since: None,
        cpu_at_last_block: None,
        last_join: now_wall - Duration::from_secs(60),
        peer_round_seen: None,
        last_snapshot_height,
        prev_finalized_root: None,
        pending_snapshot_xshard: None,
        retro_published_upto,
        last_retro_publish: now_wall,
        last_catchup: now_wall - catchup_interval,
        catchup_pending: false,
        peer_named_height,
        catchup_at_tip_skips: 0,
        last_live_adopt: now_wall - live_adopt_fresh_window,
        last_inbound_msg: now_wall,
        retro_tip_at_last_pass,
        last_consensus_rx_ms: now_epoch_ms,
        last_consensus_frame_ms: now_epoch_ms,
        last_silence_probe_ms: now_epoch_ms,
        last_liveness_emit_ms: None,
        last_behind_peer_seen: None,
        votes_seen_height,
        votes_seen_voters: std::collections::HashSet::new(),
        last_fast_timeout_logged: None,
        last_prune_height: 0,
        chain_binding_drained: false,
        tick_no: 0,
        split_ticks: 0,
        split_tick_ms: 0,
        split_catchup_ms: 0,
        split_retro_ms: 0,
        split_probe_ms: 0,
        split_join_ms: 0,
        split_catchup_n: 0,
        split_retro_n: 0,
        split_probe_n: 0,
        split_join_n: 0,
    };

    tick::run_tick_loop(&cfg, &mut st).await;
}

#[cfg(test)]
mod w7_mod_tests {
    use super::*;

    #[test]
    fn degraded_restore_sets_restored_finalized_qc_verified_false_and_quarantines() {
        let sk = SigningKey::from_bytes(&[0x31u8; 32]);
        let vid = sk.verifying_key().to_bytes();
        let vset = ValidatorSet::from_list(vec![(vid, 10)]);
        let engine = Arc::new(InMemoryStateEngine::new());
        let mut rt = ValidatorRuntime::new(sk, vset, engine, 0);

        let mut b1 = stellereum::sharding::Block {
            height: 1,
            prev_hash: [0u8; 32],
            proposer: vid,
            timestamp: 1_700_000_001,
            precommit_qc: None,
            ..Default::default()
        };
        let bh1 = b1.compute_hash();
        // Deliberately forged/empty QC: restore_last_decision_from_finalized_block
        // degrades to last_decision = None and returns Ok(()).
        b1.precommit_qc = Some(stellereum::consensus::QuorumCertificate {
            height: 1,
            round: 0,
            kind: stellereum::consensus::VoteKind::Precommit,
            block_hash: Some(bh1),
            signatures: vec![],
            shard_id: 0,
        });
        rt.finalized.push((1, bh1));
        rt.hc.height = 2;

        rt.restore_last_decision_from_finalized_block(&b1)
            .expect("degrades to Ok(())");
        assert!(rt.last_decision.is_none());
        let qc_verified = finalize_restore_qc_verified(&rt, 1);
        assert!(
            !qc_verified,
            "degraded restore without a valid QC must keep restored_finalized_qc_verified=false"
        );

        let dir = std::env::temp_dir().join(format!(
            "stell_w6_a1_2_driver_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let storage = Arc::new(stellereum::storage::Storage::open(&dir).expect("open storage"));
        let identity = stellereum::storage::SafetyRecordIdentity {
            validator: vid,
            chain: [0x55u8; 32],
            shard: 0,
        };
        // Seed safety_record_v1 at finalized_height=0, height=1.
        let init_ctx = stellereum::safety::SafetyBootContext {
            is_validator: true,
            is_observer_env: false,
            new_chain_explicit: true,
            restored_finalized: None,
            restored_state_height: Some(0),
            restored_finalized_qc_verified: true,
            legacy_checkpoint: None,
            legacy_watermark: None,
        };
        let auth0 = stellereum::safety::SafetyAuthority::open_from_storage(
            storage.clone(),
            identity.clone(),
            init_ctx,
        );
        assert_eq!(auth0.mode(), stellereum::safety::AuthorityMode::Active);
        drop(auth0);

        // Reboot with restored_fh=1 > safety.finalized_height=0 and qc_verified=false: MUST quarantine!
        let reboot_ctx = stellereum::safety::SafetyBootContext {
            is_validator: true,
            is_observer_env: false,
            new_chain_explicit: false,
            restored_finalized: Some((1, bh1)),
            restored_state_height: Some(1),
            restored_finalized_qc_verified: qc_verified,
            legacy_checkpoint: None,
            legacy_watermark: None,
        };
        let auth1 = stellereum::safety::SafetyAuthority::open_from_storage(
            storage.clone(),
            identity,
            reboot_ctx,
        );
        assert!(
            matches!(
                auth1.mode(),
                stellereum::safety::AuthorityMode::Quarantined(_)
            ),
            "must quarantine when restored_fh > safety.finalized_height without verified QC"
        );
        drop(auth1);
        drop(storage);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
