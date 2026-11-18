use ed25519_dalek::SigningKey;
use infnode::config as node_config;
use infnode::node::Node;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

use crate::node::consensus_driver::run_consensus_node;
use crate::node::policy::*;
use stellereum::consensus::ValidatorSet;
use stellereum::mev::MevPreemptionEngine;
use stellereum::network::P2pNetworkAdapter;
use stellereum::orderbook::OrderbookManager;
use stellereum::sharding::{Block, ShardRegistry};
use stellereum::state_engine::InMemoryStateEngine;

// Upgrade-halt durability + startup guard (`docs/UPGRADE_AND_RECOVERY.md`
// §1.2.3/§1.2.4). Declared here rather than in `node/mod.rs` so the module
// travels with the guard that owns it; `tests/upgrade_halt_tests.rs` includes
// the same file by path to test the real logic, not a copy.
#[path = "upgrade_halt.rs"]
pub(crate) mod upgrade_halt;

/// Hydrate the process-shared C1 anchor registry from this shard's store and
/// arm it with the node's persistence queue.
///
/// Must run BEFORE the shard's runtime starts voting or syncing: a restarted
/// node has to be able to verify cross-shard messages produced before the
/// restart. A corrupt blob FAILS CLOSED (loud error, registry left empty) —
/// never a silently accepted anchor.
fn hydrate_finalized_header_registry(
    header_registry: &Arc<std::sync::RwLock<stellereum::sharding::FinalizedHeaderRegistry>>,
    storage: &stellereum::storage::Storage,
    persistence: &Arc<stellereum::storage::AsyncPersistence>,
    label: &str,
    arm_sink: bool,
) {
    match header_registry.write() {
        Ok(mut r) => {
            if let Err(e) = storage.hydrate_finalized_headers(&mut r) {
                eprintln!(
                    "[xshard] {label}: finalized-header registry hydration FAILED CLOSED: {e}; \
                     starting with an EMPTY registry (older cross-shard messages will not verify \
                     until they are re-anchored by a re-sync)"
                );
                tracing::error!(
                    "[xshard] {label}: finalized-header registry hydration FAILED CLOSED: {e} \
                     (registry left empty)"
                );
            }
            // The registry is process-shared, so ONE sink (the main store)
            // persists every shard's anchors; attaching one per shard would
            // multiply the same bounded snapshot by the shard count without
            // adding durability. Workchain stores are still hydrated so an
            // older snapshot there cannot be silently ignored.
            if arm_sink {
                // Arm persistence AFTER hydration so the first snapshot
                // extends the restored state instead of replacing it with an
                // empty one.
                let sink: Arc<dyn stellereum::sharding::FinalizedHeaderSink> = persistence.clone();
                r.attach_persistence(sink);
            }
        }
        Err(e) => {
            eprintln!("[xshard] {label}: finalized-header registry lock poisoned: {e}");
            tracing::error!("[xshard] {label}: finalized-header registry lock poisoned: {e}");
        }
    }
}

/// Start consensus for a NON-masterchain shard inside the same process and over
/// the same infnode `Node` as the masterchain.
///
/// Deliberately different from the masterchain bootstrap:
///  * it does NOT call `fund_genesis`, so validator balances are never
///    double-counted across shards, and the staking ledger stays EMPTY — the
///    masterchain owns the staking registry;
///  * the workchain's consensus validator set is derived from the
///    MASTERCHAIN's ledger (`master_staking`, shared process-wide), so a
///    masterchain rotation (bond / unbond / slash) reaches the workchain at
///    its next height boundary instead of being stranded on the masterchain;
///  * only a deterministic dev/faucet account is funded, so the shard has value
///    to move (cross-shard value flow itself is a later milestone);
///  * it does NOT reset the chain epoch: that was derived from the shard-0
///    genesis so both consensus instances share one P2P namespace, with the
///    shard id making the topics and blob names disjoint.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn start_workchain_shard(
    adapter: Arc<P2pNetworkAdapter>,
    validator_key: SigningKey,
    _validator_pub: [u8; 32],
    vset: ValidatorSet,
    is_validator: bool,
    shard: u32,
    registry: ShardRegistry,
    remote_signer: Option<Arc<dyn stellereum::remote_signer::Signer>>,
    header_registry: Arc<std::sync::RwLock<stellereum::sharding::FinalizedHeaderRegistry>>,
    master_staking: stellereum::sharding::MasterStakingLedger,
) -> anyhow::Result<()> {
    let state_engine = Arc::new(InMemoryStateEngine::new());
    // The dev/faucet account is the ONLY funded account on a workchain.
    // Key file (STELL_FAUCET_KEY_FILE, 0600-checked, zeroized) wins when set;
    // the public test key is refused without STELL_DEV_UNSAFE_TESTKEY=1.
    let workchain_seed: Option<[u8; 32]> = stellereum::rpc::try_load_faucet_seed_opt_for_genesis()
        .map_err(|e| {
            eprintln!("{e}");
            tracing::error!("{e}");
            anyhow::anyhow!("[shard {shard}] workchain faucet genesis key error: {e}")
        })?;
    if let Some(seed) = workchain_seed {
        // Own the seed in a wiping wrapper: the copy handed to Faucet::new is
        // wiped with its frame there; this binding is wiped on scope exit.
        let seed = zeroize::Zeroizing::new(seed);
        let faucet = stellereum::rpc::Faucet::new(
            *seed,
            shard,
            stellereum::rpc::Faucet::default_drip_nano(),
            FAUCET_LIFETIME_CAP,
        );
        stellereum::runtime::fund_shard_genesis(
            &state_engine,
            faucet.account(),
            GENESIS_FAUCET_BALANCE,
        )
        .await;
    }
    debug_assert!(
        state_engine
            .staking_read()
            .await
            .to_validator_set()
            .is_empty(),
        "workchain genesis must not seed a staking ledger"
    );
    let genesis_root = state_engine.get_state_root().await;
    let genesis_block =
        stellereum::runtime::shard_genesis_block(shard, genesis_root, [0u8; 32], 1758800000);
    adapter
        .broadcast_block(&genesis_block)
        .await
        .map_err(|e| anyhow::anyhow!("shard {shard} genesis publish: {e}"))?;
    adapter.persist_block_header(shard, &genesis_block).await;
    adapter
        .publish_head(shard, 0, genesis_block.compute_hash())
        .await;
    // C1 anchor: note our own genesis so height-1 messages referencing it
    // verify. Cross-node height-1 messages reference the PROPOSER's genesis
    // (timestamp/proposer differ per node by construction); a validator that
    // built a different genesis fails those closed until height 2+, when
    // every header is consensus-agreed. Cross-shard transfers at literal
    // height 1 are vanishingly rare (nothing is funded yet); deterministic
    // genesis construction would close even that (future genesis rotation).
    {
        // Scoped: the write guard must drop before any await (std RwLock
        // guards are !Send across tasks).
        if let Ok(mut r) = header_registry.write() {
            // The genesis is also the shard's FIRST shard head: the
            // masterchain publishes it (TON `shard_hashes`) until the shard
            // finalizes its first real block.
            r.note_finalized_commitment(stellereum::sharding::ShardHeaderCommitment {
                shard_id: shard,
                height: genesis_block.height,
                block_hash: genesis_block.compute_hash(),
                state_root: genesis_root,
                timestamp: genesis_block.timestamp,
            });
        }
    }

    let store_dir = store_path_for_shard(shard, registry.is_sharded());
    let storage = Arc::new(
        stellereum::storage::Storage::open(&store_dir)
            .map_err(|e| anyhow::anyhow!("storage open shard {shard}: {e}"))?,
    );
    match storage.get_meta("genesis_state_root") {
        Ok(Some(prev)) if prev != genesis_root => {
            anyhow::bail!(
                "{}",
                stellereum::bootstrap::genesis_mismatch_msg(Some(shard), &genesis_root, &prev)
            );
        }
        _ => {
            let _ = storage.set_meta("genesis_state_root", &genesis_root);
        }
    }
    let persistence = Arc::new(stellereum::storage::AsyncPersistence::start(storage));
    persistence.enqueue_block(genesis_block);
    // C1 anchor durability: hydrate anchors written before a restart. Runs
    // BEFORE `run_consensus_node` below, so the runtime never verifies against
    // a cold registry. The shared registry already has a sink armed by the
    // masterchain bootstrap (one sink persists every shard's anchors).
    hydrate_finalized_header_registry(
        &header_registry,
        &persistence.storage(),
        &persistence,
        &format!("shard {shard}"),
        false,
    );

    let shared_staking = state_engine.staking_handle();
    let shared_gov = state_engine.governance_handle();
    let mev_engine = MevPreemptionEngine::new();
    let (tx_bcast_tx, mut tx_bcast_rx) = tokio::sync::mpsc::unbounded_channel();
    let gossip_bcast =
        std::sync::Arc::new(stellereum::consensus_net::TxGossip::new(adapter.clone()));
    // The epoch-seal path publishes SEALED ciphertexts (and the DKG /
    // order-commitment / share-release frames) through the same channel.
    stellereum::consensus_net::set_global_tx_gossip(gossip_bcast.clone());
    let gossip_bcast_task = gossip_bcast.clone();
    tokio::spawn(async move {
        while let Some(tx) = tx_bcast_rx.recv().await {
            gossip_bcast_task.broadcast(&tx).await;
        }
    });
    let base_fee = stellereum::mempool::Mempool::frozen_base_fee_floor();
    info!("[config] admission base_fee floor={base_fee} (FROZEN_MIN_GAS_FLOOR; same on all validators by construction)");
    let init_height = persistence
        .storage()
        .finalized()
        .ok()
        .flatten()
        .map(|(h, _)| h)
        .unwrap_or(0);
    let rpc_state = Arc::new(stellereum::rpc::RpcState {
        engine: state_engine.clone(),
        mempool: Arc::new(tokio::sync::RwLock::new(
            stellereum::mempool::Mempool::default()
                .with_mev_engine(mev_engine)
                .with_base_fee(base_fee)
                .with_session_registry(state_engine.session_keys_handle())
                // P2 shard gate (pool level): a sharded workchain pool admits
                // only its own shard on EVERY path (RPC, gossip, restore).
                // Single-shard stays unpinned (legacy traffic).
                .pin_admission_shard(registry.is_sharded().then_some(shard)),
        )),
        height: Arc::new(std::sync::atomic::AtomicU64::new(init_height)),
        node_id: adapter.node.id_hex.clone(),
        chain_id: stellereum::zkml::effective_chain_id(),
        staking: shared_staking.clone(),
        governance: shared_gov.clone(),
        recent_blocks: Arc::new(tokio::sync::RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(tokio::sync::RwLock::new(
            stellereum::rpc::ReceiptIndex::default(),
        )),
        auth_token: std::env::var("STELL_RPC_AUTH_TOKEN")
            .ok()
            .filter(|s| !s.is_empty()),
        faucet_token: std::env::var("STELL_FAUCET_TOKEN")
            .ok()
            .filter(|s| !s.is_empty()),
        tx_broadcast: Some(tx_bcast_tx),
        faucet: None,
        // GATE: H-02 — `stell_signMessage` / `stell_signTypedData` NEVER use
        // the validator key. Separate ephemeral dev-only key (present only
        // with STELL_DEV_UNSAFE_TESTKEY=1), else disabled; production wallets
        // sign locally.
        msg_signing_seed: stellereum::rpc::dev_msg_signing_seed_from_env(),
        // Archive proofs + historical roots are served from the persisted
        // snapshot history, never from the live trie.
        archive_store: Some(persistence.storage()),
        // Sharded admission: the faucet on this endpoint serves ONLY this
        // shard's recipients (a drip for another shard would be dropped as
        // shard-filtered and could never execute).
        shard_registry: registry.clone(),
    });
    stellereum::rpc::hydrate_rpc_from_store(&rpc_state, &persistence.storage()).await;
    info!(
        "[shard {shard}] workchain genesis {} (staking registry lives on the masterchain, dev-funded)",
        hex::encode(&genesis_root[..6])
    );
    tokio::spawn(async move {
        run_consensus_node(
            adapter,
            validator_key,
            vset,
            state_engine,
            shard,
            // Workchain extra produces its OWN shard's blocks.
            shard,
            Some(persistence),
            shared_staking,
            shared_gov,
            rpc_state,
            remote_signer,
            is_validator,
            registry,
            header_registry,
            // The masterchain's registry, shared process-wide: the workchain
            // derives its consensus validator set from it, so a masterchain
            // rotation is adopted at the next height boundary.
            master_staking,
        )
        .await;
    });
    Ok(())
}

/// Build the consensus validator set from the config.
///
/// The set must be identical on every node sharing the same `validators:` list,
/// or the genesis state roots differ and the network splits. It is therefore
/// derived purely from the config, never from "which node is running this":
///
/// * `validators` EMPTY -> solo / dev mode: this node is its own sole validator
///   (quorum = 1). This is the backwards-compatible single-node behaviour.
/// * `validators` NON-EMPTY -> add this node's key ONLY if its own node id is
///   listed, plus every configured peer whose node id is listed.
///
/// Derive this node's validator set from its config, and whether we are in it.
///
/// # The convention
/// `validators:` is a list of CONSENSUS ids, where an id is
/// `blake3(consensus_pub)[..20]` (the frozen Ed-keyed validator set).
/// Transport identity is the separate PQ `NodeId`
/// (`proto::pq_id_from_pub(falcon_pk)`), never this list.
/// Two shapes are supported, and they must not be mixed across a network:
///
///   * **all members listed** -- `validators:` names EVERY validator including this
///     node. Preferred: the set is then a pure function of the file, and a node whose
///     key is not listed is unambiguously an observer.
///   * **others only** -- `validators:` names the OTHER validators and this node's key
///     is added implicitly. This is what the deployed two-node stand uses
///     (`nodeA.validators = [nodeB]`), and it cannot express observers at all.
///
/// So self is added when EITHER the list is empty (single-node / dev), OR our own id
/// is listed, OR our key matches a listed peer entry.
///
/// Returns `(set, is_validator)`.
pub(crate) fn build_validator_set(
    cfg: &infnode::config::NodeConfig,
    self_ed: [u8; 32],
    self_node_id_hex: &str,
    observer: bool,
) -> (ValidatorSet, bool) {
    // Peers whose consensus-key-derived id is listed in `validators:`
    // (`blake3(consensus_pub)[..20]`). FULL-PQ: peer configs no longer carry
    // a declared `node-id` (transport identity is PQ-only via `pq_pub`), so
    // there is nothing to lie about. The frozen validator set is Ed-keyed:
    // a peer contributes its `consensus-pub`/`ed-pub` iff its derived id is
    // listed. A malformed peer is skipped.
    let mut from_peers: Vec<[u8; 32]> = Vec::new();
    for p in &cfg.peers {
        // `consensus-pub`/`ed-pub` is the consensus-only Ed25519 validator
        // key — NOT transport identity. Peers without it simply contribute
        // no consensus key.
        let Some(ed) = p.consensus_bytes().ok().flatten() else {
            continue;
        };
        let computed = blake3::hash(&ed);
        let raw_hex = hex::encode(&computed.as_bytes()[..20]);
        let listed = cfg
            .validators
            .iter()
            .any(|v| v.strip_prefix("inf1:").unwrap_or(v) == raw_hex);
        if listed {
            // F6 binding: the listed id MUST be blake3(consensus_pub)[..20].
            if ed == self_ed {
                continue; // a peer entry for ourselves; handled below
            }
            from_peers.push(ed);
        }
    }
    // Typo tripwire (F6 spirit): a listed id matching NO peer key is almost
    // certainly a doctored config — loud, but non-fatal (the set stays a pure
    // function of the file; an unknown id simply contributes nobody).
    {
        use std::collections::HashSet;
        let known: HashSet<String> = cfg
            .peers
            .iter()
            .filter_map(|p| p.consensus_bytes().ok().flatten())
            .map(|ed| hex::encode(&blake3::hash(&ed).as_bytes()[..20]))
            .collect();
        for v in &cfg.validators {
            let listed = v.strip_prefix("inf1:").unwrap_or(v);
            if !known.contains(listed)
                && listed
                    != self_node_id_hex
                        .strip_prefix("inf1:")
                        .unwrap_or(self_node_id_hex)
            {
                eprintln!(
                    "[config] WARNING: validators entry {v} matches no peer key (nor self); SKIPPING (contributes nobody)"
                );
            }
        }
    }

    let we_are_listed = {
        let self_hex = self_node_id_hex
            .strip_prefix("inf1:")
            .unwrap_or(self_node_id_hex);
        cfg.validators
            .iter()
            .any(|v| v.strip_prefix("inf1:").unwrap_or(v) == self_hex)
    };

    let mut vs = ValidatorSet::new();
    // Empty list = solo/dev: the node is its own validator, as before.
    let empty = cfg.validators.is_empty();
    // Self is included when the list is empty, when we are explicitly named, or when
    // the list names only OTHERS (the deployed convention): in that last case every
    // listed id resolves to a peer entry whose key is not ours, and we still have to be
    // one of the validators or there would be nobody to propose.
    let list_names_only_others =
        !empty && !we_are_listed && from_peers.len() == cfg.validators.len();
    // Observer override (opt-in via STELL_OBSERVER=1): a fresh node that must
    // FOLLOW an existing chain skips the implicit self-add, so its bootstrap
    // set — and therefore its genesis state root — exactly matches the live
    // network (e.g. {A,B} instead of {C,A,B}). Without this, any fresh key
    // derives its own 3-member genesis and can never validate live QCs
    // (structural join trap). Validators never set this flag; default off,
    // so existing stands behave byte-identically. Passed as a parameter (not
    // read from env here) so tests are deterministic and race-free.
    if observer && (empty || we_are_listed) {
        // Fail-loud against typo'd roles: the flag just silenced a REAL
        // membership (solo-dev or explicitly listed). At N=2/3 every vote
        // counts — a validator starting as observer halts the chain.
        eprintln!(
            "[config] WARNING: STELL_OBSERVER=1 suppresses an actual validator \
             membership (solo/empty list or our id is listed). This node will NOT \
             propose or vote. Unset the flag if this machine should validate."
        );
    }
    let is_validator = (empty || we_are_listed || list_names_only_others) && !observer;

    if is_validator {
        vs.add(self_ed, 1);
    }
    for ed in from_peers {
        vs.add(ed, 1);
    }
    (vs, is_validator)
}

#[allow(clippy::type_complexity)]
// GATE: faucet saver closure type is fixed by persistence hook; alias would churn CLI bootstrap without benefit.
#[allow(clippy::cmp_owned)]
// GATE: PathBuf comparison is explicit for bootstrap gate; string comparison would change path normalization.
pub(crate) async fn run_node(
    config: PathBuf,
    shard: u32,
    parallel_exec: bool,
    pure_pq: bool,
) -> anyhow::Result<()> {
    // FULL-PQ: `--pure-pq` parsed-and-ignored with WARN (compat).
    if pure_pq {
        eprintln!("[WARN] --pure-pq is a no-op (FULL-PQ always-on): flag ignored");
    }
    info!("Initializing Stellereum Node on Shard {}...", shard);
    // LIVE MIGRATION ARMING — printed at STARTUP, before the node does
    // anything, so the operator can see the state of a switch that
    // ends in `execve` of a new binary. When it is ARMED this is a
    // banner, not a line: the consequence (an on-chain proposal
    // replacing the running binary IN PLACE) must never be something
    // an operator discovers from a log line they happened to be
    // reading at the wrong moment. When it is DISARMED the node says
    // so too, so "why did my node exit 42 instead of upgrading?" has
    // an answer in the startup log.
    {
        let armed = stellereum::governance::auto_upgrade_armed();
        if armed {
            let banner = format!(
                "\n\
================= STELLEREUM: LIVE MIGRATION ARMED =================\n\
{} \n\
At an approved (quorum-ratified) software-upgrade height this node will\n\
exec() the SHA-256-verified new binary IN PLACE, without a supervisor.\n\
This is operator-local policy: arm it on EVERY node deliberately, or leave\n\
it off everywhere and let the exit-code-42 path do the restart.\n\
==================================================================\n",
                stellereum::governance::auto_upgrade_state_line()
            );
            eprintln!("{banner}");
            tracing::warn!(
                "[upgrade] LIVE MIGRATION ARMED ({}): an approved upgrade height will exec \
                 the verified new binary in place; unset the variable to fall back to the \
                 exit-42 halt",
                stellereum::governance::AUTO_UPGRADE_ENV
            );
        } else {
            info!(
                "[upgrade] live migration DISARMED ({} not set to 1/true): an approved \
                 upgrade height halts this node with exit code 42 for the supervisor to \
                 restart",
                stellereum::governance::AUTO_UPGRADE_ENV
            );
        }
    }
    let is_parallel = is_parallel_exec_active(
        std::env::var("STELL_PARALLEL_EXEC").ok().as_deref(),
        parallel_exec,
        false,
    );
    // Which shards this ONE process runs. `STELL_SHARDS=0,1[,2...]`
    // runs the masterchain plus every configured workchain over a
    // single infnode node (the cross-shard KV helpers are node-local,
    // so they must share a process). Unset/empty => just the CLI
    // shard, i.e. the pre-sharding behaviour with `is_sharded() == false`.
    //
    // An EXPLICITLY set list parses fail-closed (`parse_list`: every
    // entry must be a shard id, ids unique, masterchain 0 present in
    // every multi-shard set, at most MAX_SHARDS entries) — garbage
    // refuses startup instead of silently shrinking to the default.
    let registry = match std::env::var(stellereum::sharding::SHARD_REGISTRY_ENV) {
        Ok(v) if !v.trim().is_empty() => stellereum::sharding::ShardRegistry::parse_list(&v)
            .map_err(|e| anyhow::anyhow!("{e}"))?,
        _ => ShardRegistry::from_env_or(shard),
    };
    // Protocol-freeze boot guard (docs/PUBLIC_TESTNET_CODE_GAPS.md §1):
    // single-shard {0} canonical for public launch. Any other registry
    // (STELL_SHARDS != {0}) refuses startup unless the local
    // soak/test hatch STELL_EXPERIMENTAL_SHARDS=1 is set (loudly
    // logged below). Fail-closed; the default {0} path is untouched.
    if let Err(e) = stellereum::sharding::check_workchain_boot_guard(&registry) {
        eprintln!("{e}");
        tracing::error!("{e}");
        anyhow::bail!("{e}");
    }
    if registry != ShardRegistry::single() && !stellereum::sharding::is_public_shard_pair(&registry)
    {
        // Hatch path only: the guard above refuses every set except the
        // supported `{0,1}` pair, so this branch now covers ONLY the
        // experimental hatch (and never mislabels the public pair).
        tracing::warn!(
            "[workchain-guard] EXPERIMENTAL multishard boot: shards {{{}}} \
             allowed only by {}=1 (local soak/tests, NOT public protocol; \
             see docs/PUBLIC_TESTNET_CODE_GAPS.md §1)",
            registry
                .ids()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(","),
            stellereum::sharding::EXPERIMENTAL_SHARDS_ENV
        );
    }
    // Copy out once: the shutdown handler below moves it into an
    // `async move` block, and the extras loop still needs the registry.
    let sharded = registry.is_sharded();
    // C1 anchor: one finalized-header registry for the whole
    // process (main chain + workchain extras share it).
    let header_registry: Arc<std::sync::RwLock<stellereum::sharding::FinalizedHeaderRegistry>> =
        Arc::new(std::sync::RwLock::new(
            stellereum::sharding::FinalizedHeaderRegistry::default(),
        ));
    let state_engine = Arc::new(InMemoryStateEngine::new().with_parallel_exec(is_parallel));
    let _orderbooks = Arc::new(tokio::sync::Mutex::new(OrderbookManager::new()));
    // MEV preemption engine, handed to the shared mempool below: it
    // seals every admitted transaction and records the build-time order
    // commitment the finalize path verifies (see `mempool::Mempool`).
    let mev_engine = MevPreemptionEngine::new();

    // Persistent keys: PQ node identity/transport (`pq-identity.key`) plus
    // the consensus-only Ed25519 validator key (`validator.key`, migrated
    // once from a legacy identity.key). The consensus key never touches
    // infnode transport/auth.
    let data_dir = PathBuf::from("./data");
    let keys_dir = PathBuf::from("./keys");
    let falcon_path = std::env::var("STELL_FALCON_KEY_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| keys_dir.join("falcon.key"));
    let key_bundle =
        stellereum::node_keys::NodeKeyBundle::load_or_generate(&keys_dir, &falcon_path)?;
    let keys = key_bundle.node_keys;
    let pq_keys = key_bundle.pq_identity;
    let validator_key = stellereum::node_keys::load_or_generate_consensus_key(&keys_dir)?;
    let validator_pub = validator_key.verifying_key().to_bytes();
    // NOTE: genesis accounts are funded AFTER the validator set is known
    // (see below), so every node credits exactly the same accounts.

    // Remote / HSM signing. `STELL_REMOTE_SIGNER_URL` (and the optional
    // `STELL_REMOTE_SIGNER_TOKEN`) move the validator key out of this
    // process. Construction resolves and pins the remote public key, so
    // an unreachable signer, a wrong-width key or a value that is not a
    // curve point aborts startup HERE. There is deliberately no path
    // back to the plaintext `validator_key` below: rule 1 of the
    // remote_signer module is that a configured remote signer must never
    // fall back to a local key.
    let validator_signer =
        stellereum::remote_signer::validator_signer_from_env(validator_key.to_bytes())
            .map_err(|e| anyhow::anyhow!("remote signer rejected at startup: {e}"))?;
    // Threaded all the way through now: `ValidatorRuntime` signs votes and
    // the proposal through this handle instead of the in-process key, and a
    // signer failure produces NO vote rather than a locally signed one.
    let remote_signer = validator_signer.into_remote();

    if config.exists() {
        info!("Bootstrapping infnode P2P transport from {:?}", config);
        let node_cfg = node_config::load(&config)?;
        let node = Node::new(node_cfg, keys, pq_keys, data_dir, config.clone()).await?;
        let adapter = Arc::new(P2pNetworkAdapter::new(node));

        // NODE IDENTITY: id is the PQ-only transport id
        // (`ceremony_local_id`); ed is the consensus validator key;
        // kem is the blake3 fingerprint of the ML-KEM-768 ek (the full
        // 1184B key is never printed — it travels the protocol, not logs).
        let kem_fp = hex::encode(&blake3::hash(&adapter.node.keys.kem_ek).as_bytes()[..8]);
        info!(
            "NODE IDENTITY: id={} pq_pub={} kem_fp={} listen={}",
            adapter.node.id_hex,
            adapter.node.pq.pq_pub_hex(),
            kem_fp,
            adapter.node.cfg.listen
        );

        // Start the infnode listener + reconnect loop so validators can
        // exchange proposals/votes over the real network.
        let serve_node = adapter.node.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_node.serve().await {
                eprintln!("[stellereum] infnode serve error: {e}");
            }
        });

        info!("Stellereum P2P Network Adapter connected to infnode DHT overlay.");

        // DNS seed discovery (opt-in via STELL_DNS_SEEDS): bootstrap
        // peers from public DNS TXT records so a fresh node can find
        // the network without a hand-edited `peers:` list. One pass
        // runs now (before consensus needs anyone), then every 10
        // minutes. SECURITY: discovered peers land in the runtime
        // peer-set only — never in `cfg.validators` — so the validator
        // set built below stays a pure function of the config file and
        // discovery poisoning cannot touch the quorum or genesis.
        // With STELL_DNS_SEEDS unset/empty this is a no-op: no DNS
        // module code runs, no network calls are made.
        let dns_domains = stellereum::dns_seeds::seed_domains_from_env();
        if dns_domains.is_empty() {
            info!("[dns-seeds] disabled (STELL_DNS_SEEDS not set)");
        } else {
            info!(
                "[dns-seeds] enabled for {} domain(s): {:?} (discovery peers are NOT validators)",
                dns_domains.len(),
                dns_domains
            );
            stellereum::dns_seeds::spawn_dns_seed_discovery(
                adapter.node.clone(),
                Duration::from_secs(600),
            );
        }

        // Deployment identity (task (c)): one binary serves any number of
        // networks, distinguished by STELL_CHAIN_ID (default 5757). Loud
        // so testnet/mainnet mix-ups are visible in the log, not silent.
        let local_chain_id = stellereum::zkml::effective_chain_id();
        info!(
            "[chain-id] local chain id {local_chain_id} (STELL_CHAIN_ID or default {}); \
             a connected peer reporting any other chain id is refused, never silently partitioned",
            stellereum::zkml::DEFAULT_CHAIN_ID
        );
        // Startup abort on an already-sighted peer chain-id mismatch
        // (task (c)): a recorded foreign id means we are pointed at a
        // different network — refuse to start on it.
        if let Some(sighted) = stellereum::rpc::fresh_peer_chain_id() {
            stellereum::zkml::check_peer_chain_id(local_chain_id, sighted).map_err(|e| {
                eprintln!("{e}");
                anyhow::anyhow!("{e}")
            })?;
        }

        // Fail-closed fresh-join guard (task (a)): an EMPTY data dir
        // with peers/DNS seeds configured means JOIN, not found —
        // minting a new genesis here would fork off the network
        // SILENTLY (the old guard only caught restarts). A dirty dir
        // is a restart (genesis-fingerprint guard owns it); a clean
        // dir with no peer pointer is a genuine founding.
        //
        // Observer join is EXEMPT and proceeds to mint: with
        // STELL_OBSERVER=1 the node skips the implicit self-add, so
        // the minted genesis is the NETWORK's ({A,B}, not {C,A,B})
        // and snapshot-sync advances past it — there is nothing to
        // fork. A fresh VALIDATOR-config key with peers is still
        // refused: it must join as observer first (STELL_OBSERVER=1),
        // sync, then promote — otherwise it mints a private 3-member
        // genesis and can never validate live QCs (structural trap).
        {
            // `data_dir` moved into `Node::new` above; this is the same
            // historical `./data` it was built from.
            let dir_clean =
                stellereum::bootstrap::data_dir_is_clean_fs(std::path::Path::new("./data"));
            let peer_pointer = !adapter.node.cfg.peers.is_empty()
                || !stellereum::dns_seeds::seed_domains_from_env().is_empty();
            let observer = std::env::var("STELL_OBSERVER")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if observer && dir_clean && peer_pointer {
                tracing::warn!(
                    "[bootstrap] fresh observer join: minting the network-matching observer genesis (no self-add); snapshot-sync will advance past it — no fork possible"
                );
            } else {
                stellereum::bootstrap::guard_fresh_data_dir_from_env(dir_clean, peer_pointer)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
            }
        }

        // Deterministic genesis: build the validator set FIRST, then credit
        // every validator the same fixed balance. All nodes with the same
        // config therefore compute an identical state root.
        let self_ed = validator_key.verifying_key().to_bytes();
        // `validators:` entries are consensus ids (`blake3(ed_pub)[..20]`),
        // NOT the PQ transport id.
        let self_consensus_id = format!(
            "inf1:{}",
            hex::encode(&blake3::hash(&self_ed).as_bytes()[..20])
        );
        let (vset, is_validator) = build_validator_set(
            &adapter.node.cfg,
            self_ed,
            &self_consensus_id,
            std::env::var("STELL_OBSERVER")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
        );
        if !is_validator {
            // Observer / RPC-only node: it follows and serves the chain but
            // never proposes or votes. Genesis still credits the SAME
            // validator accounts, so its state root matches every validator.
            info!(
                "[genesis] this node is NOT in the validator set ({} members); \
                 running as an observer and will not propose or vote",
                vset.len()
            );
        }
        // SUPPLY INVARIANT AT BOOT (fail closed): the pre-mined genesis
        // allocation is folded into the engine's minted-supply counter on the
        // first post-genesis mint, so a genesis above `TOTAL_SUPPLY_CAP` would
        // refuse EVERY later reward, bridge deposit and PMM buy. Detect that
        // here, loudly, instead of letting the node boot into a chain that can
        // never emit again.
        {
            let genesis_nano = (vset.len() as u128)
                .saturating_mul(GENESIS_VALIDATOR_BALANCE as u128)
                .saturating_add(GENESIS_FAUCET_BALANCE as u128);
            let cap = stellereum::tokenomics::TOTAL_SUPPLY_CAP as u128;
            if genesis_nano > cap {
                anyhow::bail!(
                    "REFUSING genesis: the pre-mined allocation ({} validators x {} + faucet = {} nano-STELL) exceeds TOTAL_SUPPLY_CAP ({}). Lower GENESIS_VALIDATOR_BALANCE / GENESIS_FAUCET_BALANCE or the validator count; every post-genesis mint would otherwise fail closed.",
                    vset.len(),
                    GENESIS_VALIDATOR_BALANCE,
                    genesis_nano,
                    cap
                );
            }
        }
        stellereum::runtime::fund_genesis(&state_engine, &vset, GENESIS_VALIDATOR_BALANCE).await;
        // A testnet faucet needs pre-funded genesis balance, and that
        // credit MUST be identical on every node or the genesis state
        // roots diverge and the chain splits. So the funding keys off
        // the faucet seed (which every node in the network must share),
        // while STELL_FAUCET only decides which node serves the endpoint.
        // Key file (STELL_FAUCET_KEY_FILE, 0600-checked, zeroized) wins
        // when set; the public test key is refused without
        // STELL_DEV_UNSAFE_TESTKEY=1 (loud, fail-closed, no silent split).
        //
        // F3 (audit-state-sync): this used to fall back to NO faucet
        // funding on a missing/misconfigured key, while
        // `node-bootstrap` preflight REFUSES without a faucet key
        // (`faucet_key_present` gate) — a fresh `run` without the key
        // minted a faucet-less genesis where bootstrap would refuse,
        // forking silently. Aligned to the SAFER direction (same
        // refusal in both flows): on a FRESH data dir, a missing or
        // misconfigured key is a loud startup refusal, never a
        // silent fallback. On a DIRTY dir (restart) the old path
        // stands and the genesis-fingerprint guard below owns
        // consistency (it bails on any recomputed-root mismatch).
        // Freshness reuses the same `./data` clean check as the
        // fresh-join guard above, so the two gates can never disagree.
        let fresh_dir = stellereum::bootstrap::data_dir_is_clean_fs(std::path::Path::new("./data"));
        let faucet_seed_opt = match stellereum::rpc::try_load_faucet_seed_opt_for_genesis() {
            Ok(opt) => opt,
            Err(e) => {
                eprintln!("{e}");
                tracing::error!("{e}");
                if fresh_dir {
                    anyhow::bail!(
                        "[genesis] REFUSING: fresh data directory with a misconfigured faucet key \
                         (see the line above). `node-bootstrap` preflight refuses this too: minting \
                         genesis now would fork onto a faucet-less chain SILENTLY. Recovery: set \
                         STELL_FAUCET_KEY_FILE (0600 file, preferred) or STELL_FAUCET_KEY to the \
                         network's shared seed and restart."
                    );
                }
                None
            }
        };
        if faucet_seed_opt.is_none() && fresh_dir {
            anyhow::bail!(
                "[genesis] REFUSING: fresh data directory with no faucet key configured \
                 (STELL_FAUCET_KEY / STELL_FAUCET_KEY_FILE). `node-bootstrap` preflight refuses \
                 this too (faucet_key_present gate): minting genesis without the faucet credit \
                 diverges from every keyed node SILENTLY. Recovery: set STELL_FAUCET_KEY_FILE \
                 (0600 file, preferred) or STELL_FAUCET_KEY to the network's shared seed and restart."
            );
        }
        let faucet_key = faucet_seed_opt.map(|seed| {
            let seed = zeroize::Zeroizing::new(seed);
            let faucet = stellereum::rpc::Faucet::new(
                *seed,
                shard,
                stellereum::rpc::Faucet::default_drip_nano(),
                FAUCET_LIFETIME_CAP,
            );
            faucet.account()
        });
        if let Some(faucet_addr) = faucet_key {
            let _ = state_engine
                // GENESIS ALLOCATION (pre-mined): the faucet balance is part of
                // the fixed 1B allocation, so it is credited with the UNCAPPED
                // transfer primitive and does NOT advance the post-genesis
                // emission counter. `TOTAL_SUPPLY_CAP` bounds everything minted
                // AFTER genesis (rewards, bridge, faucet drips).
                .credit_native_transfer(&faucet_addr, GENESIS_FAUCET_BALANCE)
                .await;
            info!(
                "Genesis: funded faucet account {} with {} STELL",
                hex::encode(&faucet_addr[..6]),
                GENESIS_FAUCET_BALANCE / 1_000_000_000
            );
        }
        info!(
            "Genesis: funded {} validator account(s); state root {}",
            vset.len(),
            hex::encode(state_engine.get_state_root().await)
        );

        // Scope the network namespace to this chain BEFORE anything is
        // published: the genesis block and its header below are the first
        // writes, and tagging them with the wrong epoch would make a fresh
        // node invisible to itself.
        let genesis_root_early = state_engine.get_state_root().await;
        adapter.set_epoch(stellereum::network::EpochTag::from_genesis(
            &genesis_root_early,
        ));
        info!(
            "[network] chain epoch {} (blobs from other chains are ignored)",
            adapter.epoch().as_str()
        );

        let genesis_block = Block {
            shard_id: shard,
            height: 0,
            prev_hash: [0u8; 32],
            state_root: genesis_root_early,
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: now_secs(),
            proposer: validator_pub,
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
            mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
            cnvrf_v3: None,
        };

        let block_hash = adapter
            .broadcast_block(&genesis_block)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        // The genesis HEADER is the anchor a cold node verifies a header chain
        // against. It is recomputed locally by every node from the same config,
        // so a cold node does not have to trust a peer for it: it derives the
        // same header and then checks that the chain a peer offers descends
        // from it. Main flow is always the masterchain (block_shard pin).
        adapter
            .persist_block_header(stellereum::sharding::MASTERCHAIN_SHARD, &genesis_block)
            .await;
        info!(
            "Published Block #0 to infnode DHT: {}",
            hex::encode(block_hash)
        );
        // C1 anchor: note our own genesis (see the workchain note
        // above for the divergent-genesis height-1 limit).
        {
            if let Ok(mut r) = header_registry.write() {
                r.note_finalized(
                    stellereum::sharding::MASTERCHAIN_SHARD,
                    block_hash,
                    genesis_root_early,
                );
            }
        }

        // Per-shard directory (this process's main chain is always the
        // masterchain, which keeps the historical ./data/store): a
        // hardcoded ./data/store here made the main flow collide with
        // the masterchain "extra" the moment sharding was enabled
        // (lock fight, both units down).
        let store_dir = store_path_for_shard(
            stellereum::sharding::MASTERCHAIN_SHARD,
            registry.is_sharded(),
        );
        let storage = Arc::new(
            stellereum::storage::Storage::open(&store_dir)
                .map_err(|e| anyhow::anyhow!("storage open: {e}"))?,
        );
        // Genesis fingerprint. A data directory from a run with DIFFERENT
        // genesis parameters (different validator set, different faucet
        // key, changed balances) used to be loaded silently: the node
        // restored the old state, discarded the freshly computed genesis,
        // and carried on on a chain its own config no longer described —
        // with no error anywhere. It now refuses to start instead, because
        // continuing on an inconsistent chain is worse than not starting.
        let genesis_root = state_engine.get_state_root().await;
        const LEGACY_V1_GENESIS_ROOT_HEX: &str =
            "c840d1dc2e6c70eb7c639a193715c0a57375fc78ae1f9749dc3cc73cb4c8ee77";
        let legacy_v1_root = hex::decode(LEGACY_V1_GENESIS_ROOT_HEX).unwrap_or_default();

        match storage.get_meta("genesis_state_root") {
            Ok(Some(prev)) if prev == genesis_root => {
                info!("Genesis fingerprint matches the persisted chain");
            }
            Ok(Some(prev)) if prev.as_slice() == legacy_v1_root.as_slice() => {
                info!(
                    "Genesis fingerprint matches legacy v1 testnet chain: {}",
                    hex::encode(&prev)
                );
                if let Ok(arr) = prev.as_slice().try_into() {
                    adapter.set_epoch(stellereum::network::EpochTag::from_genesis(&arr));
                }
            }
            Ok(Some(prev)) => {
                anyhow::bail!(
                    "{}",
                    stellereum::bootstrap::genesis_mismatch_msg(None, &genesis_root, &prev)
                );
            }
            _ => {
                let _ = storage.set_meta("genesis_state_root", &genesis_root);
                info!(
                    "Recorded genesis state root {} for this chain",
                    hex::encode(genesis_root)
                );
            }
        }
        let persistence = Arc::new(stellereum::storage::AsyncPersistence::start(storage));
        persistence.enqueue_block(genesis_block.clone());
        // C1 anchor durability: hydrate anchors written before a restart, then
        // arm the async persistence sink. The consensus runtime is spawned
        // later, so it never starts voting/syncing against a cold registry.
        hydrate_finalized_header_registry(
            &header_registry,
            &persistence.storage(),
            &persistence,
            "masterchain",
            true,
        );
        // UPGRADE HALT SAFETY (missed-event hole, `docs/UPGRADE_AND_RECOVERY.md`
        // §1.2.3): the finalize-lane trigger is an EVENT, so a node that was
        // offline at the plan height -- or that restarted past it -- never
        // fired and kept running the pre-upgrade rules while reporting
        // healthy. The halt lane writes a durable marker before it exits 42;
        // this guard is the PREDICATE that makes the halt un-missable. It runs
        // before consensus is spawned (and before the RPC serves), so a stale
        // marker can never turn into votes. With no marker the guard is a
        // single `stat` and the old startup path is unchanged.
        {
            let marker_path = upgrade_halt::marker_path();
            let store = persistence.storage();
            let running_version = upgrade_halt::running_version();
            let decision = upgrade_halt::guard_upgrade_halt(
                &marker_path,
                || {
                    store
                        .finalized()
                        .map(|found| found.map(|(h, _)| h))
                        .map_err(|e| format!("{e}"))
                },
                &running_version,
                upgrade_halt::running_exe_sha256,
            );
            match decision {
                upgrade_halt::HaltDecision::Proceed => {}
                upgrade_halt::HaltDecision::Pending { marker } => info!(
                    "[upgrade] halt marker {:?} names height {}; the finalized head is below it, \
                     so this node halts when it reaches that height",
                    marker_path, marker.height
                ),
                upgrade_halt::HaltDecision::Cleared { marker } => info!(
                    "[upgrade] cleared the upgrade-halt marker {:?}: the running binary reports \
                     the plan's target version '{}' — joining consensus normally",
                    marker_path, marker.target_version
                ),
                upgrade_halt::HaltDecision::Refuse { message } => {
                    eprintln!("{message}");
                    tracing::error!("{message}");
                    anyhow::bail!("{message}");
                }
            }
        }
        // Graceful shutdown: persistence is a background queue, and a
        // SIGTERM used to drop queued bodies/snapshots on the floor --
        // the next start then missed bodies it had finalized (observed:
        // healing stuck on a body finalized minutes before the kill).
        // On signal, push a flush barrier and give the writer time to
        // drain before exiting.
        // (Mempool is saved separately below, once rpc_state exists.)
        {
            let ap = persistence.clone();
            tokio::spawn(async move {
                #[cfg(unix)]
                {
                    use tokio::signal::unix::{signal, SignalKind};
                    let mut term = signal(SignalKind::terminate()).ok();
                    let ctrlc = tokio::signal::ctrl_c();
                    if let Some(t) = term.as_mut() {
                        tokio::select! {
                            _ = t.recv() => {},
                            _ = ctrlc => {},
                        }
                    } else {
                        let _ = ctrlc.await;
                    }
                }
                #[cfg(not(unix))]
                {
                    let _ = tokio::signal::ctrl_c().await;
                }
                eprintln!("[storage] signal received; flushing persistence...");
                ap.request_flush();
                // Wait-for-drain (not a fixed sleep): real flushes take
                // 55-110s+, so the old fixed 15s sleep exited mid-write
                // and bricked the node on next boot (torn sled state:
                // snapshot at S vs headers past S). The helper polls
                // the persist queue with an overall cap (240s) plus a
                // settle grace after it reads empty, staying inside
                // systemd's TimeoutStopSec=300s. Keeps exit(0).
                let outcome = stellereum::storage::wait_for_persist_drain(|| ap.pending()).await;
                if outcome.drained {
                    eprintln!("[storage] persistence drained; exiting");
                } else {
                    eprintln!(
                        "[storage] shutdown drain cap reached ({} blocks pending); exiting",
                        outcome.last_pending
                    );
                }
                std::process::exit(0);
            });
        }

        // Real BFT consensus loop: proposal -> prevote -> precommit -> finality
        info!(
            "Consensus: {} validator(s), quorum power {}, proposer for height 1 = {}",
            vset.len(),
            vset.quorum_power(),
            vset.proposer_for(1, 0) == Some(validator_key.verifying_key().to_bytes())
        );
        log_quorum_safety("startup config set", &vset);
        let c_adapter = adapter.clone();
        let c_key = validator_key.clone();
        let c_state = state_engine.clone();
        let c_persist = persistence.clone();
        // Shared economic state: staking ledger + governance, owned by
        // the node and readable/writable by RPC and consensus.
        let shared_staking = state_engine.staking_handle();
        // Governance lives IN the state engine now, so it is part of the
        // state commitment. `shared_gov` is the same object, kept only so
        // the existing plumbing keeps compiling -- writing through either
        // handle reaches the committed one.
        let shared_gov = state_engine.governance_handle();
        let c_staking = shared_staking.clone();
        let c_gov = shared_gov.clone();
        // The masterchain's staking registry, shared with every
        // workchain runtime of this process. On the masterchain it is
        // the state engine's own ledger (the registry it commits);
        // the workchain runtimes below get THE SAME handle, so a
        // masterchain rotation reaches them at their next height
        // boundary.
        let master_staking = shared_staking.clone();

        // Mempool gossip forwarder: transactions submitted via RPC on this node
        // are broadcast immediately over P2P gossip to all other validators.
        let (tx_bcast_tx, mut tx_bcast_rx) = tokio::sync::mpsc::unbounded_channel();
        let gossip_bcast = stellereum::consensus_net::TxGossip::new(adapter.clone());
        tokio::spawn(async move {
            while let Some(tx) = tx_bcast_rx.recv().await {
                gossip_bcast.broadcast(&tx).await;
            }
        });

        let init_height = persistence
            .storage()
            .finalized()
            .ok()
            .flatten()
            .map(|(h, _)| h)
            .unwrap_or(0);
        // JSON-RPC + explorer/gateway state. Shared with the consensus
        // loop so the finalized height and recent-block feed stay live.
        let rpc_state = Arc::new(stellereum::rpc::RpcState {
            engine: state_engine.clone(),
            // A zero base fee makes a block of free spam possible: a
            // transaction with `gas_limit: 0` is charged nothing, still
            // occupies a slot, and the proposer is paid exactly as much as
            // for real work. A node therefore needs a real floor.
            // `FROZEN_MIN_GAS_FLOOR` sets it; the value matches
            // `GAS_BASIC_TRANSFER`, the cheapest real transfer.
            mempool: Arc::new(tokio::sync::RwLock::new(
                stellereum::mempool::Mempool::default()
                    .with_mev_engine(mev_engine)
                    .with_base_fee(stellereum::mempool::Mempool::frozen_base_fee_floor())
                    // Session-key phase 2: this ONE pool is shared with
                    // the consensus loop (`with_mempool`), so handing it
                    // the engine's registry is what lets admission see a
                    // revocation the moment it lands in a block.
                    .with_session_registry(state_engine.session_keys_handle())
                    // P2 shard gate (pool level): the main flow is the
                    // masterchain; when sharded, its pool admits only
                    // shard 0 on EVERY path (RPC, gossip, restore).
                    .pin_admission_shard(
                        registry
                            .is_sharded()
                            .then_some(stellereum::sharding::MASTERCHAIN_SHARD),
                    ),
            )),
            height: Arc::new(std::sync::atomic::AtomicU64::new(init_height)),
            node_id: adapter.node.id_hex.clone(),
            chain_id: stellereum::zkml::effective_chain_id(),
            staking: shared_staking.clone(),
            governance: shared_gov.clone(),
            recent_blocks: Arc::new(tokio::sync::RwLock::new(std::collections::VecDeque::new())),
            receipts: Arc::new(tokio::sync::RwLock::new(
                stellereum::rpc::ReceiptIndex::default(),
            )),
            auth_token: std::env::var("STELL_RPC_AUTH_TOKEN")
                .ok()
                .filter(|s| !s.is_empty()),
            // Fail-closed: an enabled faucet with no token refuses to serve.
            faucet_token: std::env::var("STELL_FAUCET_TOKEN")
                .ok()
                .filter(|s| !s.is_empty()),
            tx_broadcast: Some(tx_bcast_tx),
            // GATE: H-02 — `stell_signMessage` / `stell_signTypedData`
            // NEVER use the validator key. Separate ephemeral dev-only
            // key (present only with STELL_DEV_UNSAFE_TESTKEY=1), else
            // disabled; production wallets sign locally and never ask
            // a node to sign.
            msg_signing_seed: stellereum::rpc::dev_msg_signing_seed_from_env(),
            // Archive proofs + historical roots are served from the
            // persisted snapshot history, never from the live trie.
            archive_store: Some(persistence.storage()),
            // Sharded admission: the faucet on this endpoint serves ONLY
            // this shard's recipients (a drip for another shard would
            // be dropped as shard-filtered and could never execute).
            shard_registry: registry.clone(),
            // Testnet faucet is opt-in; disabled by default so a public
            // mainnet node can never be used to mint supply. Funds are
            // transferred by a signed tx from a pre-funded dev account,
            // so the value movement goes through consensus.
            faucet: std::env::var("STELL_FAUCET")
                .ok()
                .filter(|s| s == "1" || s.eq_ignore_ascii_case("true"))
                .and_then(|_| {
                    // Faucet key: STELL_FAUCET_KEY_FILE is REQUIRED
                    // (0600-checked, zeroized). Inline STELL_FAUCET_KEY
                    // alone leaves the faucet DISABLED fail-closed
                    // (genesis-funding only). Fail-closed: a bad file,
                    // or the PUBLIC test key without
                    // STELL_DEV_UNSAFE_TESTKEY=1, refuses to start the
                    // faucet LOUDLY (no silent money-printing on a
                    // guessable key).
                    let seed = match stellereum::rpc::load_faucet_seed() {
                        Ok(seed) => zeroize::Zeroizing::new(seed),
                        Err(e) => {
                            eprintln!("{e}");
                            tracing::error!("{e}");
                            return None;
                        }
                    };
                    // Lifetime caps and the nonce must survive a restart, or
                    // every previously-capped address can draw its full cap
                    // again (and the nonce sequence restarts at 0). The state
                    // is a small blob under a meta key; a corrupt record fails
                    // closed to empty, which can only UNDER-serve, never
                    // over-mint.
                    let store = persistence.storage();
                    let faucet = stellereum::rpc::Faucet::new(
                        *seed,
                        shard,
                        stellereum::rpc::Faucet::default_drip_nano(),
                        FAUCET_LIFETIME_CAP,
                    );
                    // NOTE: the persisted state is loaded asynchronously just
                    // below, once rpc_state exists; the hook is attached here
                    // so no drip can slip through unpersisted.
                    let saver: std::sync::Arc<dyn Fn(&[u8]) + Send + Sync> =
                        std::sync::Arc::new(move |bytes: &[u8]| {
                            let _ = store.set_meta(stellereum::rpc::FAUCET_STATE_META_KEY, bytes);
                        });
                    Some(Arc::new(faucet.with_persist(saver)))
                }),
        });
        // Restore lifetime caps / nonce saved by the previous run, if any.
        // Without this, every capped address redraws its full cap after each
        // restart. A missing or corrupt record loads as empty (fail closed).
        if let Some(f) = rpc_state.faucet.as_ref() {
            if let Ok(Some(bytes)) = persistence
                .storage()
                .get_meta(stellereum::rpc::FAUCET_STATE_META_KEY)
            {
                f.load_bytes(&bytes).await;
            }
            // Reconcile the durable nonce with the chain: drips reserved
            // (nonce advanced + persisted) but never executed -- e.g. the
            // mempool was wiped by a restart before inclusion -- leave a
            // permanent gap, because the account's on-chain nonce never
            // advances to meet the reservation. New drips then wait
            // forever behind phantom predecessors. Observed live: faucet
            // nonce 20+, on-chain 0, every drip stuck. The on-chain
            // nonce is authoritative at startup (the mempool never
            // survives a restart, so nothing reserved-but-unexecuted can
            // still be pending); clamp down to it, never up (in-flight
            // drips built but not yet submitted keep their nonces, and
            // the faucet is single-writer).
            let onchain = state_engine
                .get_account(&f.account())
                .await
                .map(|a| a.nonce)
                .unwrap_or(0);
            f.clamp_nonce_down(onchain).await;
        }

        stellereum::rpc::hydrate_rpc_from_store(&rpc_state, &persistence.storage()).await;

        let c_rpc = rpc_state.clone();
        let c_remote_signer = remote_signer.clone();
        // Persist the mempool on shutdown too (not just every 15s): a
        // restart between submit and the next periodic save otherwise
        // silently drops fresh transactions. Best-effort and tiny.
        {
            let mp = rpc_state.mempool.clone();
            tokio::spawn(async move {
                #[cfg(unix)]
                {
                    use tokio::signal::unix::{signal, SignalKind};
                    let mut term = signal(SignalKind::terminate()).ok();
                    let ctrlc = tokio::signal::ctrl_c();
                    if let Some(t) = term.as_mut() {
                        tokio::select! {
                            _ = t.recv() => {},
                            _ = ctrlc => {},
                        }
                    } else {
                        let _ = ctrlc.await;
                    }
                }
                #[cfg(not(unix))]
                {
                    let _ = tokio::signal::ctrl_c().await;
                }
                mp.read().await.save(&mempool_path_for_shard(
                    stellereum::sharding::MASTERCHAIN_SHARD,
                    sharded,
                ));
            });
        }
        // Additional shards in this process (`STELL_SHARDS=0,1[,2...]`):
        // EACH configured workchain runs its own run_consensus_node
        // instance over the SAME infnode node, so their
        // per-shard state/mempool/store never share, but the node-local
        // cross-shard KV helpers they use in M2+ do. The main flow
        // above is ALWAYS the masterchain; extras are the remaining
        // registry shards, spawned ONLY in sharded mode (a
        // single-shard `--shard 1` process has registry {1} and must
        // spawn nothing - filtering by namespace here once started a
        // masterchain "extra" that fought the main flow over the store
        // lock and took both units down).
        for extra in registry
            .ids()
            .filter(|s| registry.is_sharded() && stellereum::sharding::is_workchain_shard(*s))
            .collect::<Vec<_>>()
        {
            // Allow nodes to follow workchain shards as observers while fully
            // validating the masterchain (STELL_WORKCHAIN_OBSERVER=1), preventing
            // N=3 equal-power quorum deadlocks on workchains. Keep the full
            // validator set intact so `quorum_power` and `proposer_for` match
            // validating peers, and only disable local voting/proposing.
            let wc_obs = std::env::var("STELL_WORKCHAIN_OBSERVER")
                .map(|v| v == "1" || v == "true")
                .unwrap_or(false);
            let wc_vset = vset.clone();
            let wc_is_val = if wc_obs { false } else { is_validator };

            start_workchain_shard(
                adapter.clone(),
                validator_key.clone(),
                validator_pub,
                wc_vset,
                wc_is_val,
                extra,
                registry.clone(),
                remote_signer.clone(),
                header_registry.clone(),
                // The masterchain's registry: the workchain's
                // consensus set follows it, so a masterchain
                // rotation is adopted at the workchain's next height
                // boundary.
                master_staking.clone(),
            )
            .await?;
        }

        let c_registry = registry.clone();
        let c_headers = header_registry.clone();
        tokio::spawn(async move {
            run_consensus_node(
                c_adapter,
                c_key,
                vset,
                c_state,
                shard,
                stellereum::sharding::MASTERCHAIN_SHARD,
                Some(c_persist),
                c_staking,
                c_gov,
                c_rpc,
                c_remote_signer,
                is_validator,
                c_registry,
                c_headers,
                master_staking,
            )
            .await;
        });

        // JSON-RPC API for wallets, explorers and bots.
        let rpc_listen =
            std::env::var("STELL_RPC_LISTEN").unwrap_or_else(|_| "127.0.0.1:8545".to_string());
        let rpc_addr = rpc_listen.clone();
        let rpc_for_server = rpc_state.clone();
        tokio::spawn(async move {
            match stellereum::rpc::serve(&rpc_addr, rpc_for_server).await {
                Ok(()) => {}
                Err(e) => eprintln!("[rpc] server error: {e}"),
            }
        });
        info!("JSON-RPC listening on {rpc_listen}");
        // Fail-LOUD, not fail-open silently (audit 2026-10-06): a
        // non-loopback bind without an auth token exposes mempool
        // writes to the network with no gate. Still starts (dev /
        // proxied setups are legitimate), but screams.
        if !rpc_listen.starts_with("127.0.0.1")
            && !rpc_listen.starts_with("localhost")
            && std::env::var("STELL_RPC_AUTH_TOKEN")
                .ok()
                .filter(|t| !t.is_empty())
                .is_none()
        {
            tracing::warn!(
                "[security] JSON-RPC on {rpc_listen} with NO STELL_RPC_AUTH_TOKEN: sendRawTransaction/mempoolDump are open to the network. Bind loopback or set the token."
            );
        }

        // Public explorer + rate-limited gateway.
        let explorer_listen =
            std::env::var("STELL_EXPLORER_LISTEN").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
        let explorer_rate: u32 = stellereum::explorer::default_rate_limit_per_sec();
        let gateway = Arc::new(stellereum::explorer::GatewayState::new(
            rpc_state.clone(),
            explorer_rate,
        ));
        let explorer_addr = explorer_listen.clone();
        tokio::spawn(async move {
            match stellereum::explorer::serve(&explorer_addr, gateway).await {
                Ok(()) => {}
                Err(e) => eprintln!("[explorer] server error: {e}"),
            }
        });
        info!("Explorer + gateway listening on {explorer_listen}");
    } else {
        info!(
            "No infnode config found at {:?}. Running in local memory mode.",
            config
        );
    }

    info!("Stellereum Node operational and processing orders.");
    tokio::signal::ctrl_c().await?;
    info!("Stellereum Node shutting down cleanly.");
    Ok(())
}
