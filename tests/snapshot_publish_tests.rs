//! Snapshot take→publish regression (live incident 2026-10-15).
//!
//! Live symptoms pinned here:
//! * a fresh node read the latest-snapshot pointer (112420) and probed down
//!   %100 boundaries (112320/220/120/020): EVERY height missed with
//!   `snapshot-fetch manifest miss ... DHT sweep found nothing; boundary
//!   likely unpublished`, while the pointer kept existing;
//! * the validators' journals contained no snapshot-taken/published lines at
//!   all, so the take-or-publish path was unverifiable in production.
//!
//! The break (see `P2pNetworkAdapter::persist_state_snapshot`): the state blob
//! (Bulk lane) and the latest-snapshot pointer (Pointer lane) published
//! independently — a shed/dropped Bulk store left NO manifest anywhere while
//! the pointer write still succeeded, so the pointer advertised heights no
//! fetcher could ever resolve. The pointer is now fail-closed (advances only
//! when the blob demonstrably landed) and every take/publish step is LOUD.
//!
//! These tests pin the healthy path end to end:
//! 1. `submit_snapshot` → `poll_snapshot` yields the bundle at the submitted
//!    height (the SnapBundle lane never swallows a correct-root capture), and
//!    a stale-root submit skips WITHOUT wedging the lane;
//! 2. a published state snapshot (and every published domain kind) is
//!    retrievable through the PRODUCTION fetch path the sync uses
//!    (`fetch_state_snapshot` / `fetch_domain_snapshot`: manifest sweep +
//!    resumable chunk assembly + decrypt — no mocks, a real in-process Node,
//!    loopback via the local manifest, exactly like the in-tree
//!    pointer-overwrite tests do it);
//! 3. the retention prune never deletes snapshots or the pointer height:
//!    `plan_retained_prune` never names them, and applying a prune pass's
//!    deletes to a live node leaves the snapshot AND the pointer retrievable.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;
use std::time::Duration;
use stellereum::consensus::ValidatorSet;
use stellereum::network::{
    plan_retained_prune, EpochTag, P2pNetworkAdapter, SNAPSHOT_PUBLISH_DOMAIN_KINDS,
};
use stellereum::runtime::ValidatorRuntime;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

fn keys(n: usize) -> Vec<SigningKey> {
    (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect()
}

fn vset(ks: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    )
}

/// Poll until a submitted capture arrives (the worker answers in ms on an
/// idle engine; the bound only fails a wedged lane, never a slow one).
async fn poll_until_bundle(
    rt: &mut ValidatorRuntime,
    deadline: Duration,
) -> Option<stellereum::runtime::SnapBundle> {
    let t0 = std::time::Instant::now();
    loop {
        if let Some(bundle) = rt.poll_snapshot() {
            return Some(bundle);
        }
        if t0.elapsed() > deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// A correct-root submit must yield its bundle at the submitted height: the
/// sequenced lane never swallows a capture.
#[tokio::test]
async fn submit_poll_yields_bundle_at_submitted_height() {
    let ks = keys(1);
    let vs = vset(&ks);
    let engine = Arc::new(InMemoryStateEngine::new());
    engine
        .update_account(AccountState::new([0x09u8; 32], 500))
        .await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vs, engine.clone(), 1);

    let root = engine.get_state_root().await;
    assert!(
        rt.submit_snapshot(200, root),
        "first submit must be accepted"
    );
    let bundle = poll_until_bundle(&mut rt, Duration::from_secs(10))
        .await
        .expect("correct-root capture must yield a bundle (lane wedged?)");
    assert_eq!(bundle.height, 200, "bundle must carry the submitted height");
    assert!(
        !bundle.accounts.accounts.is_empty(),
        "bundle must carry the funded account"
    );
}

/// A stale-root submit must SKIP (root check) without wedging the lane: the
/// next correct submit is accepted and yields. A lane that stayed wedged
/// would starve every later snapshot exactly like the live outage.
#[tokio::test]
async fn stale_root_submit_skips_without_wedging_lane() {
    let ks = keys(1);
    let vs = vset(&ks);
    let engine = Arc::new(InMemoryStateEngine::new());
    engine
        .update_account(AccountState::new([0x09u8; 32], 500))
        .await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vs, engine.clone(), 1);

    // Wrong expected root: the worker must refuse this capture (labels stay
    // exact — a mislabeled snapshot is impossible by construction).
    assert!(rt.submit_snapshot(300, [0xFFu8; 32]));
    // Drain until the skip is consumed: the lane is provably free again the
    // moment a fresh submit is accepted.
    let root = engine.get_state_root().await;
    let mut resubmitted = false;
    for _ in 0..200 {
        let _ = rt.poll_snapshot();
        if rt.submit_snapshot(300, root) {
            resubmitted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        resubmitted,
        "lane must accept a new submit after a skipped capture (wedged?)"
    );
    let bundle = poll_until_bundle(&mut rt, Duration::from_secs(10))
        .await
        .expect("correct-root capture after a skip must yield");
    assert_eq!(bundle.height, 300);
    assert!(!bundle.accounts.accounts.is_empty());
}

// ==================== publish → production-fetch roundtrip ====================

static TEST_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

async fn test_adapter(tag: &str) -> (P2pNetworkAdapter, std::path::PathBuf) {
    let n = TEST_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "stell-snapshot-publish-{tag}-{}-{n}",
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
        dir.clone(),
        std::path::PathBuf::new(),
    )
    .await
    .expect("test node");
    let adapter = P2pNetworkAdapter::new(node);
    adapter.set_epoch(EpochTag::from_genesis(&[0x77u8; 32]));
    (adapter, dir)
}

/// Deterministic multi-chunk payload (2.5MB → 3 × 1MB chunks): exercises the
/// manifest + chunk-assembly + decrypt path, not just the 1-chunk shape.
fn multi_chunk_bytes(seed: u64) -> Vec<u8> {
    const LEN: usize = 2_500_000;
    let mut out = Vec::with_capacity(LEN);
    let mut x = seed;
    for _ in 0..LEN {
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        out.push((x >> 33) as u8);
    }
    out
}

/// A published state snapshot must come back through the EXACT fetch the sync
/// uses (`fetch_state_snapshot`: manifest sweep + resumable assembly), and
/// the pointer must name exactly that height. This is the live shape that
/// broke: pointer present, manifest missing.
#[tokio::test]
async fn state_snapshot_published_is_retrievable_via_production_fetch() {
    let (adapter, dir) = test_adapter("state").await;
    let adapter = Arc::new(adapter);
    const SHARD: u32 = 0;
    const HEIGHT: u64 = 112_420;

    let bytes = multi_chunk_bytes(0xC0FFEE);
    assert!(
        adapter.persist_state_snapshot(SHARD, HEIGHT, &bytes).await,
        "local publish must land"
    );

    let latest = adapter
        .fetch_latest_snapshot(SHARD)
        .await
        .expect("pointer must name the published height");
    assert_eq!(
        latest, HEIGHT,
        "pointer must advance to the landed snapshot"
    );

    let got = adapter
        .fetch_state_snapshot(SHARD, HEIGHT)
        .await
        .expect("published snapshot must be retrievable via the production fetch path");
    assert_eq!(got, bytes, "fetched bytes must equal published bytes");

    let _ = std::fs::remove_dir_all(&dir);
}

/// Every published domain kind must roundtrip through `fetch_domain_snapshot`
/// — the same call `fast_sync_state` makes per `SYNC_DOMAIN_KINDS` entry.
#[tokio::test]
async fn domain_snapshots_published_are_retrievable_via_production_fetch() {
    let (adapter, dir) = test_adapter("domains").await;
    let adapter = Arc::new(adapter);
    const SHARD: u32 = 0;
    const HEIGHT: u64 = 112_420;

    assert!(
        !SNAPSHOT_PUBLISH_DOMAIN_KINDS.is_empty(),
        "publish set must not be empty"
    );
    for (i, kind) in SNAPSHOT_PUBLISH_DOMAIN_KINDS.iter().enumerate() {
        let data = multi_chunk_bytes(0xD001u64 ^ (i as u64));
        assert!(
            adapter
                .persist_domain_snapshot(SHARD, HEIGHT, kind, &data)
                .await,
            "domain publish must land for kind={kind}"
        );
        let got = adapter
            .fetch_domain_snapshot(SHARD, HEIGHT, kind)
            .await
            .unwrap_or_else(|| panic!("published domain must be retrievable for kind={kind}"));
        assert_eq!(got, data, "domain bytes must roundtrip for kind={kind}");
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// The retention prune must never delete snapshots or the pointer height:
/// the plan never names them, and applying a prune pass's deletes to a live
/// node leaves the snapshot AND the pointer retrievable.
#[tokio::test]
async fn prune_never_deletes_snapshot_or_pointer_height() {
    let epoch = EpochTag::from_genesis(&[0x77u8; 32]);
    const SHARD: u32 = 0;
    const SNAP_HEIGHT: u64 = 112_420;

    // Pure plan pin across snapshot and non-snapshot heights, with and
    // without a resolvable body hash: no plan may ever name a snapshot blob
    // or the latest-snapshot pointer.
    for h in [1u64, 100, SNAP_HEIGHT, SNAP_HEIGHT + 1, 900_000] {
        for body in [None, Some("ab12cd34")] {
            let plan = plan_retained_prune(&epoch, SHARD, h, body);
            for (bucket, name) in &plan.blobs {
                assert!(
                    !name.contains("_snap_"),
                    "prune plan must never name a snapshot/pointer blob \
                     (height={h} bucket={bucket} name={name})"
                );
            }
        }
    }

    // Live proof: publish at the pointer height, apply exactly what a prune
    // pass at a far-future tip would delete for that height, then fetch.
    let (adapter, dir) = test_adapter("prune").await;
    let adapter = Arc::new(adapter);
    let bytes = multi_chunk_bytes(0x9A17);
    assert!(
        adapter
            .persist_state_snapshot(SHARD, SNAP_HEIGHT, &bytes)
            .await
    );
    assert!(
        adapter
            .persist_domain_snapshot(SHARD, SNAP_HEIGHT, "domains", &bytes)
            .await
    );

    // What `maybe_prune_retained` would delete for SNAP_HEIGHT once the tip
    // is far past it (same `delete_blob_local` / `kv_remove_local`
    // primitives, same plan).
    let plan = plan_retained_prune(&epoch, SHARD, SNAP_HEIGHT, None);
    assert!(
        !plan.blobs.is_empty(),
        "plan must still cover headers at the snapshot height"
    );
    for (bucket, name) in &plan.blobs {
        adapter.node.delete_blob_local(bucket, name).await;
    }
    for k in &plan.kv {
        adapter.node.kv_remove_local(k).await;
    }

    assert_eq!(
        adapter.fetch_latest_snapshot(SHARD).await,
        Some(SNAP_HEIGHT),
        "pointer height must survive the prune pass"
    );
    assert_eq!(
        adapter
            .fetch_state_snapshot(SHARD, SNAP_HEIGHT)
            .await
            .expect("snapshot must survive the prune pass"),
        bytes
    );
    assert_eq!(
        adapter
            .fetch_domain_snapshot(SHARD, SNAP_HEIGHT, "domains")
            .await
            .expect("domain snapshot must survive the prune pass"),
        bytes
    );

    let _ = std::fs::remove_dir_all(&dir);
}
