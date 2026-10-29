//! Readiness (`/healthz` + `/readyz` + `stell_ready`) and log-rotation tests.
//!
//! Background: a "running" node can be useless — stuck pre-consensus in DHT
//! warmup, answering RPC at height 0 forever, spinning view changes at
//! opposite round parity with zero finalizes, or holding no peer at all.
//! These tests pin the supervisor-visible surface: liveness stays cheap and
//! always-ok, readiness names WHICH condition failed, and the rotating writer
//! keeps a bounded file chain without losing a line.

use std::collections::HashSet;
use std::sync::Arc;
use stellereum::explorer::{
    render_metrics_with_readiness, GatewayState, ReadinessConfig, ReadinessState,
};
use stellereum::metrics::{SizeRotatingWriter, DEFAULT_LOG_MAX_BYTES, DEFAULT_LOG_MAX_FILES};
use stellereum::rpc::RpcState;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const STALL: u64 = 30;

// ============================================================================
// Helpers
// ============================================================================

async fn test_rpc_state() -> Arc<RpcState> {
    let engine = Arc::new(stellereum::state_engine::InMemoryStateEngine::new());
    Arc::new(RpcState {
        engine,
        mempool: Arc::new(tokio::sync::RwLock::new(
            stellereum::mempool::Mempool::default(),
        )),
        height: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        node_id: "inf1:readiness".to_string(),
        chain_id: 5757,
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
        archive_store: None,
        msg_signing_seed: None,
        shard_registry: stellereum::sharding::ShardRegistry::single(),
    })
}

fn test_config() -> ReadinessConfig {
    ReadinessConfig {
        max_stall_secs: STALL,
        min_peers: 1,
    }
}

async fn spawn_gateway(gw: Arc<GatewayState>) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            stellereum::explorer::router(gw)
                .into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    addr
}

async fn http_get(addr: std::net::SocketAddr, path: &str) -> (String, String) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or(("", &text));
    (
        head.lines().next().unwrap_or("").to_string(),
        body.to_string(),
    )
}

// ============================================================================
// Readiness logic (no HTTP)
// ============================================================================

#[test]
fn ready_is_false_with_no_peers() {
    let r = ReadinessState::new(test_config());
    // Even with a fresh finalize and advancing height, zero peers is unready.
    r.note_finalized_at(3, 1_000);
    let rep = r.evaluate_at(1_001);
    assert!(!rep.ready, "no peers must be unready");
    assert!(
        rep.failed_checks.contains(&"no_peers".to_string()),
        "must name no_peers: {rep:?}"
    );
}

#[test]
fn ready_is_false_on_stalled_height() {
    let r = ReadinessState::new(test_config());
    r.set_peers(2);
    r.note_finalized_at(9, 1_000);
    // Just inside the window: still ready.
    assert!(r.evaluate_at(1_000 + STALL).ready);
    // Past the window with nothing new: stalled on both signals.
    let rep = r.evaluate_at(1_000 + STALL + 1);
    assert!(!rep.ready, "stalled height must be unready");
    assert!(
        rep.failed_checks.contains(&"finality_stalled".to_string()),
        "must name finality_stalled: {rep:?}"
    );
    assert!(
        rep.failed_checks.contains(&"height_stalled".to_string()),
        "must name height_stalled: {rep:?}"
    );
}

#[test]
fn ready_is_false_before_any_finality() {
    let r = ReadinessState::new(test_config());
    r.set_peers(3);
    // Peers but nothing ever finalized (e.g. stuck in DHT warmup at height 0).
    let rep = r.evaluate_at(5_000);
    assert!(!rep.ready);
    assert!(
        rep.failed_checks.contains(&"no_finality".to_string()),
        "{rep:?}"
    );
    assert!(
        rep.failed_checks.contains(&"height_zero".to_string()),
        "{rep:?}"
    );
}

#[test]
fn ready_is_true_with_peers_and_advancing_height() {
    let r = ReadinessState::new(test_config());
    r.set_peers(1);
    r.note_finalized_at(1, 2_000);
    r.note_finalized_at(2, 2_005);
    let rep = r.evaluate_at(2_006);
    assert!(rep.ready, "peers + recent finalize must be ready: {rep:?}");
    assert!(rep.failed_checks.is_empty(), "{rep:?}");
    assert_eq!(rep.height, 2);
    assert_eq!(rep.peers, 1);
    assert_eq!(rep.secs_since_finalized, Some(1));
}

#[test]
fn repeated_finalize_at_same_height_refreshes_finality_not_height() {
    let r = ReadinessState::new(test_config());
    r.set_peers(1);
    r.note_finalized_at(4, 1_000);
    // Same height re-reported later (e.g. duplicate commit gossip): finality is
    // fresh, but the height has not advanced.
    r.note_finalized_at(4, 1_000 + STALL);
    let rep = r.evaluate_at(1_000 + STALL);
    assert!(rep.ready, "{rep:?}");
    let late = r.evaluate_at(1_000 + STALL + 1);
    // Height signal (from t=1000) is now stale while finality (t=1030) is not.
    assert!(!late.ready);
    assert!(
        late.failed_checks.contains(&"height_stalled".to_string()),
        "{late:?}"
    );
    assert!(
        !late.failed_checks.contains(&"finality_stalled".to_string()),
        "{late:?}"
    );
}

#[test]
fn readiness_config_defaults_and_env() {
    let d = ReadinessConfig::default();
    assert_eq!(d.max_stall_secs, 30);
    assert_eq!(d.min_peers, 1);
    assert_eq!(DEFAULT_LOG_MAX_BYTES, 10 * 1024 * 1024);
    assert_eq!(DEFAULT_LOG_MAX_FILES, 5);
    // from_env falls back to defaults when unset.
    std::env::remove_var("STELL_READY_MAX_STALL_SECS");
    std::env::remove_var("STELL_READY_MIN_PEERS");
    assert_eq!(ReadinessConfig::from_env(), ReadinessConfig::default());
}

// ============================================================================
// HTTP surface: /healthz (liveness) vs /readyz (readiness)
// ============================================================================

#[tokio::test]
async fn healthz_is_always_ok_even_when_unready() {
    let gw = Arc::new(GatewayState::with_readiness(
        test_rpc_state().await,
        10_000,
        test_config(),
    ));
    let addr = spawn_gateway(gw).await;
    // No peers, no finality: liveness must still answer 200, cheaply.
    let (status, body) = http_get(addr, "/healthz").await;
    assert!(status.contains("200"), "healthz status: {status}");
    assert!(body.contains("\"status\":\"ok\""), "healthz body: {body}");
}

#[tokio::test]
async fn readyz_names_the_failing_condition_then_recovers() {
    let gw = Arc::new(GatewayState::with_readiness(
        test_rpc_state().await,
        10_000,
        test_config(),
    ));
    let addr = spawn_gateway(gw.clone()).await;

    // Fresh node: no peers, nothing finalized.
    let (status, body) = http_get(addr, "/readyz").await;
    assert!(
        status.contains("503"),
        "unready must be 503: {status} {body}"
    );
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["ready"], false);
    let failed: Vec<String> = serde_json::from_value(v["failed_checks"].clone()).unwrap();
    assert!(
        failed.contains(&"no_peers".to_string()),
        "must name no_peers: {body}"
    );
    assert!(
        failed.contains(&"no_finality".to_string()),
        "must name no_finality: {body}"
    );

    // Peers join and a block finalizes: the same endpoint flips to 200.
    gw.set_ready_peers(2);
    gw.note_ready_finalized(1);
    let (status, body) = http_get(addr, "/readyz").await;
    assert!(status.contains("200"), "ready must be 200: {status} {body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["ready"], true);
    assert_eq!(v["failed_checks"].as_array().unwrap().len(), 0);
    assert_eq!(v["height"], 1);
    assert_eq!(v["peers"], 2);
}

#[tokio::test]
async fn metrics_carries_stell_ready_gauge_matching_readyz() {
    let gw = Arc::new(GatewayState::with_readiness(
        test_rpc_state().await,
        10_000,
        test_config(),
    ));
    let addr = spawn_gateway(gw.clone()).await;

    let (_, body) = http_get(addr, "/metrics").await;
    assert!(
        body.contains("stell_ready 0"),
        "unready node must export 0:\n{body}"
    );

    gw.set_ready_peers(1);
    gw.note_ready_finalized(5);
    let (_, body) = http_get(addr, "/metrics").await;
    assert!(
        body.contains("stell_ready 1"),
        "ready node must export 1:\n{body}"
    );
}

#[test]
fn render_metrics_with_readiness_reports_the_gauge() {
    let reg = stellereum::metrics::Registry::new();
    let off = render_metrics_with_readiness(&reg, 7, 0, 0, 0, false);
    assert!(off.contains("# TYPE stell_ready gauge"), "{off}");
    assert!(off.contains("stell_ready 0\n"), "{off}");
    let on = render_metrics_with_readiness(&reg, 7, 0, 0, 0, true);
    assert!(on.contains("stell_ready 1\n"), "{on}");
}

// ============================================================================
// Log rotation: bounded files, no lost lines
// ============================================================================

fn unique_tmp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "stell-readiness-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn collect_lines(dir: &std::path::Path) -> (usize, Vec<String>) {
    let mut files = 0usize;
    let mut lines = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let p = entry.unwrap().path();
        if p.is_file() {
            files += 1;
            let text = std::fs::read_to_string(&p).unwrap();
            for l in text.lines() {
                lines.push(l.to_string());
            }
        }
    }
    (files, lines)
}

#[test]
fn rotation_keeps_at_most_n_files_and_loses_no_line() {
    let dir = unique_tmp_dir("bounded");
    let base = dir.join("node.log");
    let mut w = SizeRotatingWriter::new(base.clone(), 256, 4).unwrap();

    const N: usize = 500;
    for i in 0..N {
        w.write_line(&format!("line-{i:04}-payload-xxxxxxxxxx"))
            .unwrap();
    }
    drop(w);

    let (files, lines) = collect_lines(&dir);
    assert!(files <= 4, "must keep at most 4 files, found {files}");
    assert!(
        files >= 2,
        "256-byte budget over 500 lines must rotate at least once"
    );
    // Bounded rotation evicts whole files from the head: the survivors must be
    // a CONTIGUOUS SUFFIX of what was written — no gaps, no duplicates, every
    // line whole. Eviction may drop old lines; rotation itself must never tear
    // or skip one in flight.
    assert!(!lines.is_empty());
    assert_eq!(
        lines.len(),
        lines.iter().collect::<HashSet<_>>().len(),
        "no line may be duplicated"
    );
    let mut idx: Vec<usize> = lines
        .iter()
        .map(|l| l[5..9].parse::<usize>().unwrap())
        .collect();
    idx.sort_unstable();
    assert_eq!(
        *idx.last().unwrap(),
        N - 1,
        "newest line must survive rotation"
    );
    assert_eq!(
        idx,
        (idx[0]..N).collect::<Vec<_>>(),
        "survivors must be a gapless suffix"
    );
    for l in &lines {
        assert_eq!(
            l.len(),
            "line-0000-payload-xxxxxxxxxx".len(),
            "line must be whole: {l:?}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rotation_never_splits_a_line_mid_rotation() {
    let dir = unique_tmp_dir("nosplit");
    let base = dir.join("node.log");
    // Tiny budget so nearly every line forces a rotation decision.
    let mut w = SizeRotatingWriter::new(base.clone(), 32, 3).unwrap();
    for i in 0..50 {
        w.write_line(&format!("event-{i:03}")).unwrap();
    }
    drop(w);

    // Re-read raw bytes: each file must be a whole number of newline-terminated
    // lines — a split line would show up as a chunk without a trailing newline
    // or a fragment glued to the next file's first line.
    let mut all = HashSet::new();
    let mut files = 0usize;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let p = entry.unwrap().path();
        if p.is_file() {
            files += 1;
            let raw = std::fs::read(&p).unwrap();
            assert!(
                raw.ends_with(b"\n"),
                "file {p:?} must end on a line boundary"
            );
            for l in String::from_utf8(raw).unwrap().lines() {
                assert!(l.starts_with("event-"), "fragment found: {l:?}");
                all.insert(l.to_string());
            }
        }
    }
    assert!(files <= 3, "bounded files: {files}");
    // Only the newest 3 files' worth survive a 32-byte budget; what survives
    // must be whole, ordered-parseable lines — check the newest line survived.
    assert!(
        all.contains("event-049"),
        "newest line must survive rotation"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rotation_survives_an_oversized_single_line() {
    let dir = unique_tmp_dir("oversize");
    let base = dir.join("node.log");
    let mut w = SizeRotatingWriter::new(base.clone(), 16, 2).unwrap();
    w.write_line("small").unwrap();
    // One line bigger than the whole budget: lands whole in a fresh file.
    let big = "X".repeat(10_000);
    w.write_line(&big).unwrap();
    drop(w);

    let (_, lines) = collect_lines(&dir);
    assert!(
        lines.iter().any(|l| l == &big),
        "oversized line must land whole"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rotation_is_bounded_under_concurrent_writers() {
    let dir = unique_tmp_dir("concurrent");
    let base = dir.join("node.log");
    let log = stellereum::metrics::RotatingLog::new(base.clone(), 512, 4).unwrap();
    let mut handles = Vec::new();
    for t in 0..4 {
        let log = log.clone();
        handles.push(std::thread::spawn(move || {
            for i in 0..200 {
                log.write_line(&format!("t{t}-{i:03}")).unwrap();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let (files, lines) = collect_lines(&dir);
    assert!(files <= 4, "bounded under concurrency: {files}");
    // Every survivor must be a whole, well-formed line, unique, and per thread
    // the survivors must be a SUFFIX of that thread's sequence: eviction
    // removes a prefix of the global order, so it must never punch holes or
    // tear a line.
    assert_eq!(
        lines.len(),
        lines.iter().collect::<HashSet<_>>().len(),
        "no line may be duplicated"
    );
    for t in 0..4 {
        for l in lines.iter().filter(|l| l.starts_with(&format!("t{t}-"))) {
            assert_eq!(l.len(), 6, "line must be whole: {l:?}");
        }
        let mut idx: Vec<usize> = lines
            .iter()
            .filter_map(|l| l.strip_prefix(&format!("t{t}-"))?.parse::<usize>().ok())
            .collect();
        idx.sort_unstable();
        if !idx.is_empty() {
            assert_eq!(
                idx,
                (*idx.first().unwrap()..200).collect::<Vec<_>>(),
                "thread {t}: survivors must be a gapless suffix"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
