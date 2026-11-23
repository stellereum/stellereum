//! LIVENESS-FIX L1: a behind / jailed node must catch up from a VERIFIED
//! far-ahead peer head instead of spinning view changes forever.
//!
//! # The live incident (2026-11-23)
//!
//! nodeC sat at finalized height **90 858** for hours while the tip moved past
//! **120 000**. Its log was an endless `view change -> height 90858 round
//! 1161..1166`; it received peer pubsub traffic but never advanced, never
//! attempted a snapshot, and a restart did not help. Replacing the store with
//! the published snapshot fixed it.
//!
//! # Root cause pinned here
//!
//! A far-ahead VERIFIED proposal/vote/commit DID record a head, but the driver
//! tick top ran `policy::peer_hint_effective`, which reused the 64-height
//! *pre-hash* gate (`MAX_COMMITTED_LOOKAHEAD`) as a hint bound and therefore
//! **deleted every hint more than 64 heights ahead**. With no hint,
//! `try_catch_up` fell back to:
//!   1. a DHT head read — last-writer-wins, so it can read back our OWN stale
//!      head (the documented "echo chamber"); and
//!   2. the blind-QC probe at `tip + 1` — whose sidecar is pruned on a node
//!      30 000 heights behind.
//!
//! It returned `None` before ever reaching the snapshot-first path for the
//! material gap.
//!
//! The earlier "ladder" only probed *from our own tip*, so it could not help
//! when our local history/sidecars were the pruned part.
//!
//! These tests use the PRODUCTION predicate (`node::policy`), the PRODUCTION
//! catch-up entry point (`node::sync::try_catch_up`), real Falcon-signed blocks
//! and real precommit quorums. The only simulated part is the driver tick's
//! "retain or drop the recorded hint" call, which is exactly the gate under
//! test.

use ed25519_dalek::SigningKey;
use std::sync::Arc;

use stellereum::consensus::{register_validator_pq_key, ValidatorSet, Vote, VoteKind, VoteSet};
use stellereum::post_quantum::{FalconKeypair, PqScheme};
use stellereum::runtime::ValidatorRuntime;
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};
use stellereum::state_engine::InMemoryStateEngine;

#[path = "../src/node/policy.rs"]
#[allow(dead_code)]
pub(crate) mod node_policy;

/// `src/node/sync.rs` imports `crate::node::policy::*`; re-export the included
/// policy module under that path so the PRODUCTION sync code compiles verbatim.
#[allow(dead_code)]
mod node {
    pub(crate) use crate::node_policy as policy;
}

#[path = "../src/node/sync.rs"]
#[allow(dead_code)]
mod node_sync;

use node::policy::{
    clamp_peer_evidence_height, clamp_peer_named_height, node_is_at_tip, peer_hint_effective,
    verified_head_hint, CatchupAction, PEER_HINT_MAX_LOOKAHEAD, PEER_HINT_TTL_MS,
};
use node_sync::try_catch_up;

/// A tick budget that is deliberately tiny: one verified far-ahead head must
/// close the gap on the FIRST pass (the snapshot attempt falls back to the
/// verified body walk when no snapshot is published in this fixture).
const MAX_TICKS: usize = 4;

fn vset(ks: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    )
}

fn fks_for(ks: &[SigningKey]) -> Vec<FalconKeypair> {
    ks.iter()
        .enumerate()
        .map(|(i, _)| FalconKeypair::generate_from_seed(i as u8))
        .collect()
}

fn attach_quorum(
    b: &mut Block,
    ks: &[SigningKey],
    fks: &[FalconKeypair],
    vs: &ValidatorSet,
    height: u64,
    bh: [u8; 32],
    parent: [u8; 32],
) {
    for (k, fk) in ks.iter().zip(fks.iter()) {
        register_validator_pq_key(
            k.verifying_key().to_bytes(),
            PqScheme::Falcon512,
            fk.public_key.clone(),
        );
    }
    let mut set = VoteSet::new();
    for (k, fk) in ks.iter().zip(fks.iter()) {
        let v = Vote::sign_with_falcon(k, fk, height, 0, VoteKind::Precommit, Some(bh));
        set.add(v, vs, height, 0, VoteKind::Precommit)
            .expect("genuine vote admits");
    }
    b.precommit_qc = set.certificate_with_parent(Some(bh), vs, Some(&parent));
}

async fn seed_engine_pq_keys(
    engine: &InMemoryStateEngine,
    ks: &[SigningKey],
    fks: &[FalconKeypair],
) {
    let mut ledger = engine.staking_write().await;
    let mut pq_reg = engine.pq_registry_write().await;
    for (k, fk) in ks.iter().zip(fks.iter()) {
        let id = k.verifying_key().to_bytes();
        ledger
            .validator_pq_keys
            .insert(id, (PqScheme::Falcon512, fk.public_key.clone()));
        let _ = pq_reg.adopt_legacy_key_at(id, PqScheme::Falcon512, fk.public_key.clone(), 0, true);
    }
    stellereum::consensus::sync_committed_pq_registry(&pq_reg, true);
}

/// Build a contiguous chain with the SAME full transition the walk applies, so
/// every block's committed parent root is exactly the root a node holding the
/// prefix has.
async fn build_chain(ks: &[SigningKey], fks: &[FalconKeypair], n: u64) -> (Vec<Block>, [u8; 32]) {
    let vs = vset(ks);
    let engine = Arc::new(InMemoryStateEngine::new());
    seed_engine_pq_keys(&engine, ks, fks).await;
    let mut builder = ValidatorRuntime::new(ks[0].clone(), vs.clone(), engine, 1);
    let mut blocks = Vec::with_capacity(n as usize);
    let mut prev = [0u8; 32];
    for h in 1..=n {
        let root = builder.state.get_state_root().await;
        let proposer_id = vs.proposer_for(h, 0).expect("non-empty set has a proposer");
        let proposer_idx = ks
            .iter()
            .position(|k| k.verifying_key().to_bytes() == proposer_id)
            .expect("proposer is a member");
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: h,
            prev_hash: prev,
            state_root: root,
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 1_000 + h,
            proposer: proposer_id,
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            cnvrf_v3: None,
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
            round: 0,
        };
        b.sign_block_with_falcon(&ks[proposer_idx], &fks[proposer_idx]);
        let bh = b.compute_hash();
        attach_quorum(&mut b, ks, fks, &vs, h, bh, prev);
        builder.apply_and_advance(bh, &b).await;
        prev = bh;
        blocks.push(b);
    }
    let tip_root = builder.state.get_state_root().await;
    (blocks, tip_root)
}

async fn test_adapter(tag: &str) -> (stellereum::network::P2pNetworkAdapter, std::path::PathBuf) {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "stell-l1-far-ahead-{tag}-{}-{n}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("tmpdir");
    let cfg = infnode::config::NodeConfig {
        name: "test".to_string(),
        listen: "127.0.0.1:0".to_string(),
        client_listen: None,
        advertise: None,
        peers: vec![],
        allow_unknown: false,
        unknown_allow: vec![],
        metrics_listen: None,
        log_level: Some(0),
        roles: Default::default(),
        outbox_ttl_secs: 3600,
        storage_roles: vec![],
        validators: vec![],
        domain: None,
        web_listen: None,
        wallet: None,
        web_static: None,
    };
    let node = infnode::node::Node::new(
        cfg,
        infnode::keyring::NodeKeys::generate(),
        infnode::keyring::PqKeys::generate(),
        dir.clone(),
        std::path::PathBuf::new(),
    )
    .await
    .expect("test node");
    let adapter = stellereum::network::P2pNetworkAdapter::new(node);
    adapter.set_epoch(stellereum::network::EpochTag::from_genesis(&[0x77u8; 32]));
    (adapter, dir)
}

fn test_rpc_state() -> Arc<stellereum::rpc::RpcState> {
    Arc::new(stellereum::rpc::RpcState {
        engine: Arc::new(InMemoryStateEngine::new()),
        mempool: Arc::new(tokio::sync::RwLock::new(
            stellereum::mempool::Mempool::default(),
        )),
        height: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        node_id: "l1-far-ahead-test".to_string(),
        chain_id: stellereum::zkml::DEFAULT_CHAIN_ID,
        staking: Arc::new(tokio::sync::RwLock::new(
            stellereum::staking::StakingLedger::new(),
        )),
        governance: Arc::new(tokio::sync::RwLock::new(
            stellereum::governance::Governance::new(),
        )),
        recent_blocks: Arc::new(tokio::sync::RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(tokio::sync::RwLock::new(
            stellereum::rpc::ReceiptIndex::default(),
        )),
        auth_token: None,
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        msg_signing_seed: None,
        archive_store: None,
        shard_registry: stellereum::sharding::ShardRegistry::single(),
    })
}

/// The lagging node: an OUTSIDER key (not in the validator set — the jailed
/// nodeC shape), synced only through `prefix`.
async fn lagging_runtime(
    ks: &[SigningKey],
    fks: &[FalconKeypair],
    vs: &ValidatorSet,
    prefix: &[Block],
    outsider: SigningKey,
) -> ValidatorRuntime {
    let engine = Arc::new(InMemoryStateEngine::new());
    seed_engine_pq_keys(&engine, ks, fks).await;
    let mut rt = ValidatorRuntime::new(outsider, vs.clone(), engine, 1);
    for b in prefix {
        let bh = b.compute_hash();
        rt.apply_and_advance(bh, b).await;
    }
    rt
}

/// Publish ONLY bodies (no head pointer, no `_hq_` QC sidecars). That is the
/// live shape of a node whose own DHT head is a stale echo and whose old
/// `tip+1` QC sidecars are pruned: the body data for the far chain is
/// available, but no "cheap" probe at our own tip can find any of it.
async fn publish_bodies(
    adapter: &stellereum::network::P2pNetworkAdapter,
    blocks: &[Block],
    above: u64,
) {
    for b in blocks.iter().filter(|b| b.height > above) {
        let bytes = bincode::serialize(b).expect("block serializes");
        adapter
            .retro_publish_block_by_hash(b.compute_hash(), &bytes)
            .await
            .expect("body publishes by hash");
    }
}

/// ONE simulated driver tick's hint gate, then the PRODUCTION catch-up pass.
/// Returns the new finalized height (if the pass advanced us).
async fn tick_catch_up(
    adapter: &Arc<stellereum::network::P2pNetworkAdapter>,
    rt: &mut ValidatorRuntime,
    rpc: &Arc<stellereum::rpc::RpcState>,
    evidence: (u64, [u8; 32]),
) -> Option<u64> {
    let tip = rt.finalized.last().map(|(h, _)| *h).unwrap_or(0);
    // THE GATE UNDER TEST: the driver drops/keeps the verified hint here.
    rt.peer_hint = peer_hint_effective(tip, Some(evidence), 0);
    try_catch_up(adapter, rt, MASTERCHAIN_SHARD, None, rpc).await
}

/// Run the tick loop until the far head is reached or the (tiny) budget is
/// exhausted. Returns the number of passes used.
async fn run_until_head(
    adapter: &Arc<stellereum::network::P2pNetworkAdapter>,
    rt: &mut ValidatorRuntime,
    rpc: &Arc<stellereum::rpc::RpcState>,
    head: u64,
    head_hash: [u8; 32],
) -> usize {
    for tick in 1..=MAX_TICKS {
        tick_catch_up(adapter, rt, rpc, (head, head_hash)).await;
        if rt.finalized.last().map(|(h, _)| *h).unwrap_or(0) >= head {
            return tick;
        }
    }
    MAX_TICKS
}

// ===========================================================================
// 1. THE REPRODUCTION
// ===========================================================================

/// A node at `H`, NOT in the active set, with only a verified far-ahead head
/// (gap far beyond the 64-height pre-hash gate) and published bodies must
/// reach that head within the bounded tick budget.
///
/// Pre-fix this returns `None` on every pass: `peer_hint_effective` deletes
/// the hint (30 858 > 64), the DHT head is a stale echo/absent, and the
/// tip+1 blind probe has no sidecar; the snapshot path is never reached.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)] // GATE: process-global PQ registry tests serialize
async fn l1_far_ahead_verified_head_closes_the_gap() {
    let _global = node::policy::test_support::global_lock();

    const H: u64 = 30;
    const N: u64 = 140; // gap 110 > 100: the snapshot-first threshold
    let ks = vec![SigningKey::from_bytes(&[0x71; 32])];
    let fks = fks_for(&ks);
    let vs = vset(&ks);
    let (blocks, tip_root) = build_chain(&ks, &fks, N).await;
    let head_hash = blocks[(N - 1) as usize].compute_hash();

    let (adapter, dir) = test_adapter("gap").await;
    let adapter = Arc::new(adapter);
    publish_bodies(&adapter, &blocks, H).await;

    // Outsider key: this node's votes would be refused ("vote from
    // non-validator") exactly like the jailed nodeC.
    let outsider = SigningKey::from_bytes(&[0xEE; 32]);
    let mut rt = lagging_runtime(&ks, &fks, &vs, &blocks[..H as usize], outsider).await;
    assert_eq!(rt.finalized.last().map(|(h, _)| *h), Some(H));
    assert_eq!(
        vs.power_of(&rt.id),
        0,
        "fixture node must be NOT in the set"
    );

    let rpc = test_rpc_state();
    let ticks = run_until_head(&adapter, &mut rt, &rpc, N, head_hash).await;

    assert_eq!(
        rt.finalized.last().map(|(h, _)| *h),
        Some(N),
        "a behind, not-in-set node with a VERIFIED far-ahead head must catch up \
         within {MAX_TICKS} ticks (used {ticks}); the pre-fix code dropped the \
         hint at the 64-height gate and never reached catch-up/snapshot"
    );
    assert_eq!(
        rt.state.get_state_root().await,
        tip_root,
        "catch-up must land on the same state root as the source chain"
    );

    std::fs::remove_dir_all(&dir).ok();
}

// ===========================================================================
// 2. EVIDENCE RECORDING (proposal refused for height still teaches the head)
// ===========================================================================

/// A far-ahead proposal is refused for our stale height, but it is
/// signature+membership verified and MUST record its parent as the peer head;
/// the resulting hint must then survive the driver's retention gate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)] // GATE: process-global PQ registry tests serialize
async fn l1_far_ahead_proposal_records_hint_even_when_refused() {
    let _global = node::policy::test_support::global_lock();

    const H: u64 = 20;
    const N: u64 = 160; // 140 above H, far past the 64-height gate
    let ks = vec![SigningKey::from_bytes(&[0x72; 32])];
    let fks = fks_for(&ks);
    let vs = vset(&ks);
    let (blocks, _root) = build_chain(&ks, &fks, N).await;

    let outsider = SigningKey::from_bytes(&[0xED; 32]);
    let mut rt = lagging_runtime(&ks, &fks, &vs, &blocks[..H as usize], outsider).await;
    assert_eq!(rt.finalized.last().map(|(h, _)| *h), Some(H));

    let far = blocks[(N - 1) as usize].clone();
    let parent_hash = far.prev_hash;
    let res = rt.on_proposal(far.proposer, far, 0).await;
    assert!(
        res.is_err(),
        "a proposal 140 heights ahead must be REFUSED for the current height"
    );
    assert_eq!(
        rt.peer_hint,
        Some((N - 1, parent_hash)),
        "the verified far-ahead proposal must still record its parent as the peer head"
    );

    // ... and the driver tick must RETAIN it (this is the nodeC gate).
    let retained = peer_hint_effective(H, rt.peer_hint, 0);
    assert_eq!(
        retained,
        Some((N - 1, parent_hash)),
        "a verified far-ahead hint must not be deleted by the 64-height pre-hash gate"
    );
}

// ===========================================================================
// 3. HIGH ROUND STILL CATCHES UP
// ===========================================================================

/// The incident log showed `round 1161..1166` at the stale height. A high
/// local round must never starve catch-up: the pass must still advance.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)] // GATE: process-global PQ registry tests serialize
async fn l1_high_round_node_still_catches_up() {
    let _global = node::policy::test_support::global_lock();

    const H: u64 = 25;
    const N: u64 = 135;
    let ks = vec![SigningKey::from_bytes(&[0x73; 32])];
    let fks = fks_for(&ks);
    let vs = vset(&ks);
    let (blocks, _root) = build_chain(&ks, &fks, N).await;
    let head_hash = blocks[(N - 1) as usize].compute_hash();

    let (adapter, dir) = test_adapter("high-round").await;
    let adapter = Arc::new(adapter);
    publish_bodies(&adapter, &blocks, H).await;

    let outsider = SigningKey::from_bytes(&[0xEC; 32]);
    let mut rt = lagging_runtime(&ks, &fks, &vs, &blocks[..H as usize], outsider).await;
    // The live shape: a runaway round at a stale height.
    rt.hc.round = 1_166;
    assert_eq!(rt.hc.round, 1_166);

    let rpc = test_rpc_state();
    let ticks = run_until_head(&adapter, &mut rt, &rpc, N, head_hash).await;

    assert_eq!(
        rt.finalized.last().map(|(h, _)| *h),
        Some(N),
        "a high-round node must still catch up (used {ticks}/{MAX_TICKS} ticks)"
    );
    std::fs::remove_dir_all(&dir).ok();
}

// ===========================================================================
// 4. JAILED / NOT-IN-SET NODE CATCHES UP
// ===========================================================================

/// A node absent from the active set cannot vote, but it MUST still follow:
/// catch-up is a sync path, never gated on franchise.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)] // GATE: process-global PQ registry tests serialize
async fn l1_not_in_set_node_catches_up() {
    let _global = node::policy::test_support::global_lock();

    const H: u64 = 15;
    const N: u64 = 125;
    let ks = vec![SigningKey::from_bytes(&[0x74; 32])];
    let fks = fks_for(&ks);
    let vs = vset(&ks);
    let (blocks, tip_root) = build_chain(&ks, &fks, N).await;
    let head_hash = blocks[(N - 1) as usize].compute_hash();

    let (adapter, dir) = test_adapter("not-in-set").await;
    let adapter = Arc::new(adapter);
    publish_bodies(&adapter, &blocks, H).await;

    let outsider = SigningKey::from_bytes(&[0xEB; 32]);
    let mut rt = lagging_runtime(&ks, &fks, &vs, &blocks[..H as usize], outsider).await;
    assert_eq!(vs.power_of(&rt.id), 0);
    assert!(
        !rt.effective_can_vote(false),
        "the jailed/outsider node must not be able to vote"
    );

    let rpc = test_rpc_state();
    let ticks = run_until_head(&adapter, &mut rt, &rpc, N, head_hash).await;

    assert_eq!(
        rt.finalized.last().map(|(h, _)| *h),
        Some(N),
        "a not-in-set node must still catch up (used {ticks}/{MAX_TICKS} ticks)"
    );
    assert_eq!(rt.state.get_state_root().await, tip_root);
    std::fs::remove_dir_all(&dir).ok();
}

// ===========================================================================
// 5. NO REGRESSION AT THE TIP / HINT POLICY BOUNDS
// ===========================================================================

/// A verified VOTE names only a height (no hash), so it cannot anchor a walk —
/// but its height must survive as persistent catch-up evidence instead of
/// being clamped back to `tip + 64` every tick.
#[test]
fn l1_verified_vote_height_survives_the_cheap_clamp() {
    let tip = 90_858u64;
    let named = 120_000u64;
    assert_eq!(
        clamp_peer_evidence_height(tip, named),
        named,
        "a verified far-ahead vote height must remain catch-up evidence"
    );
    // The cheap at-tip predicate keeps its own (smaller) bound.
    assert_eq!(
        clamp_peer_named_height(tip, named),
        tip + node::policy::MAX_COMMITTED_LOOKAHEAD
    );
    // ... and the credible ceiling still bounds an absurd signed claim.
    let absurd = tip + PEER_HINT_MAX_LOOKAHEAD + 1;
    assert_eq!(
        clamp_peer_evidence_height(tip, absurd),
        tip + PEER_HINT_MAX_LOOKAHEAD
    );
}

/// A node already at the tip must stay quiet: a hint at our own tip is not
/// "ahead", the at-tip predicate holds, and the expensive catch-up does not
/// run on the backstop.
#[test]
fn l1_at_tip_node_is_unchanged() {
    let tip = 90_858u64;
    let hash = [0x31u8; 32];
    assert_eq!(
        peer_hint_effective(tip, Some((tip, hash)), 0),
        None,
        "a hint AT our finalized tip is not ahead and must be dropped"
    );
    assert!(node_is_at_tip(tip, tip, Some(tip)));
    assert_eq!(
        node::policy::catchup_action(false, 0, 30_000, true),
        CatchupAction::Wait,
        "an idle at-tip node must not run a catch-up walk"
    );
}

/// The hint bound is BIG enough to carry the live 90 858 -> 120 000 gap and
/// still rejects an absurd signed claim, with the TTL unchanged.
#[test]
fn l1_verified_hint_bound_matches_the_live_gap() {
    let hash = [0x41u8; 32];

    // The live incident gap (~29 142) is retained.
    assert_eq!(
        peer_hint_effective(90_858, Some((120_000, hash)), 0),
        Some((120_000, hash)),
        "the live nodeC gap must be retained as catch-up evidence"
    );
    assert_eq!(
        verified_head_hint(90_858, 120_000, hash),
        Some((120_000, hash))
    );

    // A reached hint is still dropped (no at-tip suppression).
    assert_eq!(peer_hint_effective(120_000, Some((120_000, hash)), 0), None);

    // The TTL still bounds a failed walk.
    assert_eq!(
        peer_hint_effective(90_858, Some((120_000, hash)), PEER_HINT_TTL_MS + 1),
        None
    );

    // An absurd signed claim cannot pin the at-tip predicate / DHT forever.
    assert_eq!(
        peer_hint_effective(100, Some((100 + PEER_HINT_MAX_LOOKAHEAD + 1, hash)), 0),
        None,
        "an implausibly far-ahead hint must still be refused"
    );
}
