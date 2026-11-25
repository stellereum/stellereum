//! Public block explorer + rate-limited gateway.
//!
//! Serves a tiny self-contained HTML explorer and a read-only JSON API on top of
//! the node's `RpcState`, and mounts the JSON-RPC endpoint under `/rpc`. The
//! whole surface is protected by a per-IP fixed-window rate limiter so it can be
//! exposed publicly without being trivially DoS-able.
//!
//! This module is deliberately dependency-light (no template engine): the page
//! is a static string that calls the JSON API with `fetch`. That keeps the
//! attack surface small and the build reproducible.

use crate::rpc::{configured_secret, constant_time_eq, extract_header_token, RpcState};
use axum::{
    extract::{ConnectInfo, Path as AxumPath, Query, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

/// Default requests/second allowed per IP on the public gateway. Default 30;
/// override with `STELL_RATE_LIMIT_PER_SEC`. Per-node abuse guard, not
/// consensus — nodes MAY differ.
pub const DEFAULT_RATE_LIMIT_PER_SEC: u32 = 30;

/// Effective gateway per-IP budget (`STELL_RATE_LIMIT_PER_SEC`, default 30).
pub fn default_rate_limit_per_sec() -> u32 {
    std::env::var("STELL_RATE_LIMIT_PER_SEC")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_RATE_LIMIT_PER_SEC)
}

const RATE_LIMITER_SHARDS: usize = 16;
pub const RATE_LIMITER_MAX_ENTRIES_PER_SHARD: usize = 100_000 / RATE_LIMITER_SHARDS;

#[inline]
fn rate_limiter_shard_index(ip: IpAddr) -> usize {
    let mut x: u64 = match ip {
        IpAddr::V4(v4) => u32::from(v4) as u64,
        IpAddr::V6(v6) => {
            let n = u128::from(v6);
            (n as u64) ^ ((n >> 64) as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)
        }
    };
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^= x >> 31;
    (x as usize) & (RATE_LIMITER_SHARDS - 1)
}

/// Per-IP fixed-window rate limiter (no external dependency), sharded across
/// 16 buckets by canonical IP to minimize lock contention.
pub struct RateLimiter {
    per_sec: u32,
    shards: [Mutex<HashMap<IpAddr, (u64, u32)>>; RATE_LIMITER_SHARDS],
}

impl RateLimiter {
    pub fn new(per_sec: u32) -> Self {
        Self {
            per_sec: per_sec.max(1),
            shards: std::array::from_fn(|_| Mutex::new(HashMap::new())),
        }
    }

    /// Returns true if the request is allowed (and counts it).
    pub fn check(&self, ip: IpAddr) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.check_at(ip, now)
    }

    /// Deterministic core (audit follow-up: the old test flaked on second
    /// boundaries under load — time is injected here so tests pin behavior).
    pub fn check_at(&self, ip: IpAddr, now: u64) -> bool {
        // IPv6 is bucketed by /64 (see `rpc::budget_bucket_ip`), so rotating
        // the low 64 bits cannot mint a fresh per-second budget.
        let ip = crate::rpc::budget_bucket_ip(ip);
        let idx = rate_limiter_shard_index(ip);
        let mut m = self.shards[idx].lock().unwrap_or_else(|e| e.into_inner());
        // Bound memory: with many distinct source IPs the map could grow without
        // limit. Drop stale windows when at the shard cap, and fail closed for
        // unseen IPs if the shard remains full within the active window.
        if m.len() >= RATE_LIMITER_MAX_ENTRIES_PER_SHARD && !m.contains_key(&ip) {
            m.retain(|_, (t, _)| now.saturating_sub(*t) < 2);
            if m.len() >= RATE_LIMITER_MAX_ENTRIES_PER_SHARD {
                return false;
            }
        }
        let entry = m.entry(ip).or_insert((now, 0));
        if entry.0 != now {
            *entry = (now, 0);
        }
        entry.1 = entry.1.saturating_add(1);
        entry.1 <= self.per_sec
    }

    /// Total number of tracked IP buckets across all shards (for diagnostics/tests).
    pub fn total_tracked_entries(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.lock().unwrap_or_else(|e| e.into_inner()).len())
            .sum()
    }

    /// Drop stale windows (call periodically to bound memory).
    pub fn prune(&self, now: u64) {
        for shard in &self.shards {
            let mut m = shard.lock().unwrap_or_else(|e| e.into_inner());
            m.retain(|_, (t, _)| now.saturating_sub(*t) < 2);
        }
    }
}

/// Env var tuning how long a node may go without finalizing before `/readyz`
/// reports unready. Default 30 s. Example: `STELL_READY_MAX_STALL_SECS=60`.
pub const READY_MAX_STALL_SECS_ENV: &str = "STELL_READY_MAX_STALL_SECS";
/// Env var tuning how many peers `/readyz` requires. Default 1.
///
/// Solo / dev nodes hold no peers by construction: run them with
/// `STELL_READY_MIN_PEERS=0`, otherwise they are (correctly) never ready.
pub const READY_MIN_PEERS_ENV: &str = "STELL_READY_MIN_PEERS";

/// Thresholds for `/readyz`, env-tunable with sane defaults.
///
/// | variable | default | meaning |
/// |---|---|---|
/// | `STELL_READY_MAX_STALL_SECS` | `30` | max seconds since the last finalized block before unready |
/// | `STELL_READY_MIN_PEERS` | `1` | minimum connected peers (`0` for solo/dev) |
///
/// A node that is "running" but useless — stuck pre-consensus in DHT warmup,
/// answering RPC at height 0 forever, spinning view changes with zero
/// finalizes, or holding no peer at all — fails one of these checks, and the
/// response names which one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadinessConfig {
    /// Max seconds since the last finalized block (and since the last height
    /// advance) before the node counts as stalled.
    pub max_stall_secs: u64,
    /// Minimum connected peers for the node to count as ready.
    pub min_peers: usize,
}

impl Default for ReadinessConfig {
    fn default() -> Self {
        Self {
            max_stall_secs: 30,
            min_peers: 1,
        }
    }
}

impl ReadinessConfig {
    /// Read thresholds from the environment, falling back to [`Default`].
    pub fn from_env() -> Self {
        let base = Self::default();
        let max_stall_secs = std::env::var(READY_MAX_STALL_SECS_ENV)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(base.max_stall_secs);
        let min_peers = std::env::var(READY_MIN_PEERS_ENV)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(base.min_peers);
        Self {
            max_stall_secs,
            min_peers,
        }
    }
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug, Default)]
struct ReadinessInner {
    peers: usize,
    height: u64,
    last_finalized_at_secs: Option<u64>,
    last_height_change_at_secs: Option<u64>,
}

/// Live readiness input, shared between the node loop (writers) and the
/// `/readyz` handler (reader). A plain `Mutex` is enough: it is never held
/// across `.await`, and a poisoned lock is recovered rather than propagated
/// so a panicking writer cannot wedge the probe.
pub struct ReadinessState {
    config: ReadinessConfig,
    inner: Mutex<ReadinessInner>,
}

impl ReadinessState {
    pub fn new(config: ReadinessConfig) -> Self {
        Self {
            config,
            inner: Mutex::new(ReadinessInner::default()),
        }
    }

    pub fn config(&self) -> ReadinessConfig {
        self.config
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ReadinessInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Current connected-peer count. Called from the supervisor/loop.
    pub fn set_peers(&self, n: usize) {
        self.lock().peers = n;
    }

    /// Record a finalized block at the real wall-clock time.
    pub fn note_finalized(&self, height: u64) {
        self.note_finalized_at(height, unix_now_secs());
    }

    /// Record a finalized block at an explicit time (deterministic tests).
    pub fn note_finalized_at(&self, height: u64, now_secs: u64) {
        let mut g = self.lock();
        if height != g.height {
            g.height = height;
            g.last_height_change_at_secs = Some(now_secs);
        }
        g.last_finalized_at_secs = Some(now_secs);
    }

    /// Evaluate against the real wall-clock time.
    pub fn evaluate(&self) -> ReadinessReport {
        self.evaluate_at(unix_now_secs())
    }

    /// Evaluate against an explicit time (deterministic tests).
    pub fn evaluate_at(&self, now_secs: u64) -> ReadinessReport {
        let g = self.lock();
        let mut failed_checks: Vec<String> = Vec::new();
        if g.peers < self.config.min_peers {
            failed_checks.push("no_peers".to_string());
        }
        let secs_since_finalized = g.last_finalized_at_secs.map(|t| now_secs.saturating_sub(t));
        match secs_since_finalized {
            None => failed_checks.push("no_finality".to_string()),
            Some(age) if age > self.config.max_stall_secs => {
                failed_checks.push("finality_stalled".to_string())
            }
            _ => {}
        }
        if g.height == 0 {
            failed_checks.push("height_zero".to_string());
        } else if let Some(t) = g.last_height_change_at_secs {
            if now_secs.saturating_sub(t) > self.config.max_stall_secs {
                failed_checks.push("height_stalled".to_string());
            }
        }
        ReadinessReport {
            ready: failed_checks.is_empty(),
            failed_checks,
            height: g.height,
            peers: g.peers,
            secs_since_finalized,
            max_stall_secs: self.config.max_stall_secs,
            min_peers: self.config.min_peers,
        }
    }
}

/// The outcome of one readiness evaluation. `failed_checks` names WHICH
/// condition failed (`no_peers`, `no_finality`, `finality_stalled`,
/// `height_zero`, `height_stalled`) so a supervisor can tell a peerless node
/// from a stalled chain without guessing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadinessReport {
    pub ready: bool,
    pub failed_checks: Vec<String>,
    pub height: u64,
    pub peers: usize,
    pub secs_since_finalized: Option<u64>,
    pub max_stall_secs: u64,
    pub min_peers: usize,
}

// ============================================================================
// Operational health surface (`GET /health`, `GET /status`)
// ============================================================================
//
// One payload, one verdict. Every value is either observed or `null` with a
// reason; a threshold or a missing producer never becomes a fabricated zero.
// The verdict is computed by [`evaluate_verdict`] from the SAME measured values
// the payload reports, so a dashboard cannot disagree with the exposed reasons.

/// Rolling window for the block-rate sample.
pub const HEALTH_BLOCK_RATE_WINDOW_SECS: u64 = 60;
/// How long one `/health` sample is reused. Short on purpose: health is a
/// liveness signal, and a longer TTL would hide a stall.
pub const DEFAULT_HEALTH_CACHE_TTL_MS: u64 = 1_000;
/// Disk-size samples are the expensive part; cache them separately and longer.
pub const HEALTH_DATA_DIR_CACHE_TTL_MS: u64 = 30_000;

/// Thresholds for the health verdict. All are operator-tunable via `STELL_HEALTH_*`
/// (see [`HealthOptions::from_env`]); defaults are documented in `docs/OBSERVABILITY.md`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HealthThresholds {
    /// Wall-clock age of the last finalization above which the node is `degraded`.
    pub max_finalization_lag_secs: u64,
    /// Same age above which the node is `critical`.
    pub critical_finalization_lag_secs: u64,
    /// Network-tip-vs-local-finalized gap above which the node is `degraded`.
    pub max_finalization_lag_blocks: u64,
    /// Connected peers required for `ok` (`0` = solo/dev node).
    pub min_peers: u64,
    /// Oldest pending mempool transaction above which the node is `degraded`.
    pub max_mempool_oldest_age_secs: u64,
    /// Last successful persist above which the node is `degraded`.
    pub max_persist_age_secs: u64,
    /// Snapshot block age above which the node is `degraded`.
    pub max_snapshot_age_secs: u64,
}

impl Default for HealthThresholds {
    fn default() -> Self {
        Self {
            max_finalization_lag_secs: 5,
            critical_finalization_lag_secs: 60,
            max_finalization_lag_blocks: 5,
            min_peers: 1,
            max_mempool_oldest_age_secs: 300,
            max_persist_age_secs: 120,
            max_snapshot_age_secs: 3_600,
        }
    }
}

/// Runtime knobs for the health surface (thresholds, cache TTL, disk scan).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealthOptions {
    pub thresholds: HealthThresholds,
    pub cache_ttl_ms: u64,
    /// `None` disables the data-dir size scan (tests / deployments that do not
    /// want `/health` to touch the filesystem).
    pub data_dir: Option<std::path::PathBuf>,
}

impl Default for HealthOptions {
    fn default() -> Self {
        Self {
            thresholds: HealthThresholds::default(),
            cache_ttl_ms: DEFAULT_HEALTH_CACHE_TTL_MS,
            data_dir: Some(data_dir_path()),
        }
    }
}

impl HealthOptions {
    fn env_u64(name: &str, default: u64) -> u64 {
        std::env::var(name)
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(default)
    }

    /// Read every knob from the environment. Unknown/garbage values fall back
    /// to the documented default; a zero cache TTL is clamped to 1 ms so a
    /// misconfiguration cannot turn `/health` into an unbounded scan per hit.
    pub fn from_env() -> Self {
        let d = HealthThresholds::default();
        let min_peers = std::env::var("STELL_HEALTH_MIN_PEERS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .or_else(|| {
                std::env::var(READY_MIN_PEERS_ENV)
                    .ok()
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .map(|v| v as u64)
            })
            .unwrap_or(d.min_peers);
        Self {
            thresholds: HealthThresholds {
                max_finalization_lag_secs: Self::env_u64(
                    "STELL_HEALTH_MAX_FINALIZATION_LAG_SECS",
                    d.max_finalization_lag_secs,
                ),
                critical_finalization_lag_secs: Self::env_u64(
                    "STELL_HEALTH_CRITICAL_FINALIZATION_LAG_SECS",
                    d.critical_finalization_lag_secs,
                ),
                max_finalization_lag_blocks: Self::env_u64(
                    "STELL_HEALTH_MAX_FINALIZATION_LAG_BLOCKS",
                    d.max_finalization_lag_blocks,
                ),
                min_peers,
                max_mempool_oldest_age_secs: Self::env_u64(
                    "STELL_HEALTH_MAX_MEMPOOL_AGE_SECS",
                    d.max_mempool_oldest_age_secs,
                ),
                max_persist_age_secs: Self::env_u64(
                    "STELL_HEALTH_MAX_PERSIST_AGE_SECS",
                    d.max_persist_age_secs,
                ),
                max_snapshot_age_secs: Self::env_u64(
                    "STELL_HEALTH_MAX_SNAPSHOT_AGE_SECS",
                    d.max_snapshot_age_secs,
                ),
            },
            cache_ttl_ms: Self::env_u64("STELL_HEALTH_CACHE_MS", DEFAULT_HEALTH_CACHE_TTL_MS)
                .max(1),
            data_dir: Some(data_dir_path()),
        }
    }
}

/// A measured value with its unit, or an explicit `null` + reason.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Measured<T> {
    pub value: Option<T>,
    pub unit: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<&'static str>,
}

impl<T> Measured<T> {
    pub fn observed(value: T, unit: &'static str) -> Self {
        Self {
            value: Some(value),
            unit,
            reason: None,
            source: None,
        }
    }

    pub fn missing(unit: &'static str, reason: impl Into<String>) -> Self {
        Self {
            value: None,
            unit,
            reason: Some(reason.into()),
            source: None,
        }
    }

    pub fn with_source(mut self, source: &'static str) -> Self {
        self.source = Some(source);
        self
    }

    pub fn as_ref(&self) -> Option<&T> {
        self.value.as_ref()
    }
}

/// Rolling block-rate sample. `samples` and `window_seconds` are part of the
/// answer because a rate without its window is not a measurement.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct BlockRate {
    pub value: Option<f64>,
    pub unit: &'static str,
    pub window_seconds: u64,
    pub samples: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct IdentityHealth {
    pub chain_id: u64,
    pub protocol_major: u16,
    pub protocol_minor: u16,
    pub fork_id: u32,
    pub node_id: String,
    pub shards: Measured<Vec<u64>>,
    pub software: SoftwareHealth,
    pub timestamp_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SoftwareHealth {
    pub version: &'static str,
    pub git_hash: String,
    pub dirty: String,
    /// Human-readable one-liner for headers/log lines.
    pub string: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct FinalizationLag {
    pub blocks: Measured<u64>,
    pub seconds: Measured<u64>,
    pub timestamp_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ChainHealth {
    pub height: Measured<u64>,
    pub finalized_height: Measured<u64>,
    /// Highest VERIFIED peer-reported height (this node's view), when fresh.
    pub network_tip_height: Measured<u64>,
    pub finalization_lag: FinalizationLag,
    pub blocks_per_second: BlockRate,
    pub last_finalize_age: Measured<u64>,
    pub timestamp_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CatchUpHealth {
    pub mode: Measured<String>,
    pub last_catch_up_age: Measured<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ConsensusHealth {
    pub round: Measured<u64>,
    pub last_finalized_round: Measured<u64>,
    pub view_changes_last_5m: Measured<u64>,
    pub rejected_proposals_total: Measured<u64>,
    /// Real cumulative counters that DO have producers. Kept next to the
    /// unavailable ones so the payload never hides what it can prove.
    pub forks_total: Measured<u64>,
    pub divergences_total: Measured<u64>,
    pub catch_up: CatchUpHealth,
    pub timestamp_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct MeshHealth {
    pub members: Measured<u64>,
    pub direct_targets: Measured<u64>,
    pub last_delivery: Measured<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct P2pBytesHealth {
    pub inbound_total: Measured<u64>,
    pub outbound_total: Measured<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct P2pHealth {
    pub peer_count: Measured<u64>,
    pub peer_states: Measured<Vec<serde_json::Value>>,
    pub mesh: MeshHealth,
    pub bytes: P2pBytesHealth,
    pub timestamp_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct MempoolHealth {
    pub size: Measured<u64>,
    pub oldest_pending_age: Measured<u64>,
    pub timestamp_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SnapshotHealth {
    pub height: Measured<u64>,
    pub lag_blocks: Measured<u64>,
    /// Age of the snapshot's height by its stored block timestamp. This is the
    /// age of the CONTENT, not the wall-clock write time (which storage does not
    /// export yet).
    pub age_secs: Measured<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct StorageHealth {
    pub data_dir_bytes: Measured<u64>,
    pub snapshot_files: Measured<u64>,
    pub last_persist_age: Measured<u64>,
    pub snapshot: SnapshotHealth,
    pub timestamp_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Ok,
    Degraded,
    Critical,
}

/// The verdict plus every reason that produced it. `reasons` is empty only for
/// `ok`; `unknown` names diagnostics that were unavailable but did NOT change
/// the verdict (they are not required for the measured checks).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HealthVerdict {
    pub status: HealthStatus,
    pub reasons: Vec<String>,
    pub unknown: Vec<String>,
}

/// The values the verdict is allowed to depend on. Built strictly from the
/// payload fields; no clocks, env lookups or hidden state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HealthFacts {
    pub height: Option<u64>,
    pub finalization_lag_blocks: Option<u64>,
    pub finalization_lag_secs: Option<u64>,
    pub last_finalize_age_secs: Option<u64>,
    pub peer_count: Option<u64>,
    pub mempool_size: Option<u64>,
    pub mempool_oldest_age_secs: Option<u64>,
    pub last_persist_age_secs: Option<u64>,
    pub snapshot_age_secs: Option<u64>,
    pub consensus_round: Option<u64>,
    pub view_changes_last_5m: Option<u64>,
    pub rejected_proposals_total: Option<u64>,
    pub catch_up_mode: Option<String>,
}

fn push_unique(v: &mut Vec<String>, s: String) {
    if !v.contains(&s) {
        v.push(s);
    }
}

/// Pure verdict function: same facts + same thresholds = same answer, always.
///
/// Rules (documented in `docs/OBSERVABILITY.md`):
///  * `critical`: finalization lag seconds > `critical_finalization_lag_secs`,
///    or zero peers observed while `min_peers > 0`.
///  * `degraded`: height 0 / no finalization, finalization lag > max (seconds
///    or blocks), fewer peers than the minimum, oldest mempool tx too old, last
///    persist too old, snapshot too old, or a required value unavailable.
///  * `ok`: none of the above. Missing diagnostics are listed in `unknown`.
pub fn evaluate_verdict(facts: &HealthFacts, th: &HealthThresholds) -> HealthVerdict {
    let mut critical: Vec<String> = Vec::new();
    let mut degraded: Vec<String> = Vec::new();
    let mut unknown: Vec<String> = Vec::new();

    match facts.height {
        None => push_unique(&mut degraded, "height unavailable".to_string()),
        Some(0) => push_unique(
            &mut degraded,
            "height 0: no finalized block yet".to_string(),
        ),
        Some(_) => {}
    }

    if let Some(lag) = facts.finalization_lag_secs {
        if lag > th.critical_finalization_lag_secs {
            push_unique(
                &mut critical,
                format!(
                    "finalization lag {lag} s > {} s",
                    th.critical_finalization_lag_secs
                ),
            );
        } else if lag > th.max_finalization_lag_secs {
            push_unique(
                &mut degraded,
                format!(
                    "finalization lag {lag} s > {} s",
                    th.max_finalization_lag_secs
                ),
            );
        }
    } else if let Some(age) = facts.last_finalize_age_secs {
        if age > th.critical_finalization_lag_secs {
            push_unique(
                &mut critical,
                format!(
                    "last finalize age {age} s > {} s",
                    th.critical_finalization_lag_secs
                ),
            );
        } else if age > th.max_finalization_lag_secs {
            push_unique(
                &mut degraded,
                format!(
                    "last finalize age {age} s > {} s",
                    th.max_finalization_lag_secs
                ),
            );
        }
    } else {
        push_unique(&mut degraded, "no finalized block observed".to_string());
    }

    if let Some(lag) = facts.finalization_lag_blocks {
        if lag > th.max_finalization_lag_blocks {
            push_unique(
                &mut degraded,
                format!(
                    "finalization lag {lag} blocks > {} blocks",
                    th.max_finalization_lag_blocks
                ),
            );
        }
    } else {
        push_unique(
            &mut unknown,
            "finalization block lag unavailable (no fresh peer tip)".to_string(),
        );
    }

    match facts.peer_count {
        None => push_unique(&mut degraded, "peer count unavailable".to_string()),
        Some(n) if n < th.min_peers => {
            if n == 0 {
                push_unique(
                    &mut critical,
                    format!("0 peers observed (minimum {})", th.min_peers),
                );
            } else {
                push_unique(
                    &mut degraded,
                    format!("{n} peers < minimum {}", th.min_peers),
                );
            }
        }
        Some(_) => {}
    }

    if facts.mempool_size.is_none() {
        push_unique(&mut degraded, "mempool size unavailable".to_string());
    }

    if let Some(age) = facts.mempool_oldest_age_secs {
        if age > th.max_mempool_oldest_age_secs {
            push_unique(
                &mut degraded,
                format!(
                    "oldest mempool tx {age} s > {} s",
                    th.max_mempool_oldest_age_secs
                ),
            );
        }
    } else {
        push_unique(
            &mut unknown,
            "mempool oldest-pending age unavailable".to_string(),
        );
    }

    if let Some(age) = facts.last_persist_age_secs {
        if age > th.max_persist_age_secs {
            push_unique(
                &mut degraded,
                format!("last persist age {age} s > {} s", th.max_persist_age_secs),
            );
        }
    } else {
        push_unique(&mut unknown, "last persist age unavailable".to_string());
    }

    if let Some(age) = facts.snapshot_age_secs {
        if age > th.max_snapshot_age_secs {
            push_unique(
                &mut degraded,
                format!("snapshot age {age} s > {} s", th.max_snapshot_age_secs),
            );
        }
    } else {
        push_unique(&mut unknown, "snapshot age unavailable".to_string());
    }

    if facts.consensus_round.is_none() {
        push_unique(&mut unknown, "consensus round unavailable".to_string());
    }
    if facts.view_changes_last_5m.is_none() {
        push_unique(
            &mut unknown,
            "view changes over 5 min unavailable (no timestamped counter)".to_string(),
        );
    }
    if facts.rejected_proposals_total.is_none() {
        push_unique(
            &mut unknown,
            "rejected proposals unavailable (no counter)".to_string(),
        );
    }
    if facts.catch_up_mode.is_none() {
        push_unique(&mut unknown, "catch-up mode unavailable".to_string());
    }

    if !critical.is_empty() {
        HealthVerdict {
            status: HealthStatus::Critical,
            reasons: critical,
            unknown,
        }
    } else if !degraded.is_empty() {
        HealthVerdict {
            status: HealthStatus::Degraded,
            reasons: degraded,
            unknown,
        }
    } else {
        HealthVerdict {
            status: HealthStatus::Ok,
            reasons: Vec::new(),
            unknown,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct HealthCacheInfo {
    pub ttl_ms: u64,
    pub hit: bool,
    pub age_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct HealthPayload {
    pub schema: &'static str,
    /// Wall-clock time this sample was collected.
    pub sampled_at_ms: u64,
    /// Wall-clock time this response is being served (>= sampled_at_ms).
    pub served_at_ms: u64,
    pub cache: HealthCacheInfo,
    pub identity: IdentityHealth,
    pub chain: ChainHealth,
    pub consensus: ConsensusHealth,
    pub p2p: P2pHealth,
    pub mempool: MempoolHealth,
    pub storage: StorageHealth,
    pub verdict: HealthVerdict,
}

/// TTL cache for one health sample. A stale entry is NEVER served past its TTL;
/// callers recompute and overwrite it.
#[derive(Debug, Default)]
pub struct HealthCache {
    inner: Mutex<Option<(u64, HealthPayload)>>,
}

impl HealthCache {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<(u64, HealthPayload)>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `Some` only while `now_ms - stored_at < ttl_ms` (strict: the entry is
    /// stale AT the TTL boundary, which the cache test pins).
    pub fn lookup(&self, now_ms: u64, ttl_ms: u64) -> Option<HealthPayload> {
        let ttl = ttl_ms.max(1);
        match self.lock().as_ref() {
            Some((at, payload)) if now_ms.saturating_sub(*at) < ttl => Some(payload.clone()),
            _ => None,
        }
    }

    pub fn store(&self, now_ms: u64, payload: HealthPayload) {
        *self.lock() = Some((now_ms, payload));
    }

    pub fn clear(&self) {
        *self.lock() = None;
    }

    pub fn stored_at_ms(&self) -> Option<u64> {
        self.lock().as_ref().map(|(at, _)| *at)
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn measured_u64(value: Option<u64>, unit: &'static str, reason: &str) -> Measured<u64> {
    match value {
        Some(v) => Measured::observed(v, unit),
        None => Measured::missing(unit, reason),
    }
}

/// Env var disabling non-essential telemetry/status-banner exposure
/// (set by `-t`/`--no-telemetry` on `run`, or `telemetry = false` in TOML).
/// Keeps `/health`, `/healthz`, `/readyz`, and `/metrics` operational while
/// disabling the `/status` HTML dashboard.
pub const NO_TELEMETRY_ENV: &str = "STELL_NO_TELEMETRY";

/// Returns true when non-essential telemetry/status-banner exposure is disabled.
pub fn no_telemetry_enabled() -> bool {
    matches!(
        std::env::var(NO_TELEMETRY_ENV)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

pub struct GatewayState {
    pub rpc: Arc<RpcState>,
    pub limiter: Arc<RateLimiter>,
    /// Dedicated limiter for the nested /rpc router (audit follow-up): a
    /// second layer on the SAME instance double-counted every hit; a static
    /// ignored the configured rate. Same budget, separate bucket.
    pub rpc_limiter: Arc<RateLimiter>,
    /// Shared consensus metrics. Defaults to the process-wide registry in
    /// [`crate::metrics::global`] so the two-argument constructor the node
    /// binary already uses keeps working, while a caller that *does* hold the
    /// consensus driver's registry can still be given the same instance.
    pub metrics: Arc<crate::metrics::Registry>,
    /// Readiness input for `/readyz` and `stell_ready`. Written by the node
    /// loop through [`GatewayState::set_ready_peers`] /
    /// [`GatewayState::note_ready_finalized`], read by the HTTP handlers.
    pub readiness: Arc<ReadinessState>,
    /// Cloudflare Turnstile gate for the public faucet
    /// (`POST /api/faucet-public/:address`). Loaded from `STELL_TURNSTILE_*`
    /// env; `Disabled` when unset (legacy IP-throttle-only behaviour).
    pub captcha: Arc<crate::turnstile::CaptchaGate>,
    /// Health thresholds, cache TTL and optional disk-scan target.
    pub health_options: HealthOptions,
    /// One-sample TTL cache for `/health` / `/status`.
    pub health_cache: HealthCache,
    /// Whether optional telemetry/status-banner endpoints (`/status`) are enabled.
    /// Initialized from `!no_telemetry_enabled()`.
    pub telemetry_enabled: bool,
    /// Separate, longer-lived cache for the data-dir scan: the one part of the
    /// payload expensive enough to matter.
    health_data_dir_cache: Mutex<Option<(u64, (u64, u64))>>,
    /// Serializes cold data-dir scans so N simultaneous cache misses cannot
    /// start N filesystem walks.
    health_data_dir_scan_gate: tokio::sync::Mutex<()>,
}

impl GatewayState {
    pub fn new(rpc: Arc<RpcState>, per_sec: u32) -> Self {
        Self::with_readiness(rpc, per_sec, ReadinessConfig::from_env())
    }

    /// Same as [`GatewayState::new`] with explicit readiness thresholds
    /// (tests, or callers that do not want env dependence).
    pub fn with_readiness(rpc: Arc<RpcState>, per_sec: u32, config: ReadinessConfig) -> Self {
        Self {
            rpc,
            limiter: Arc::new(RateLimiter::new(per_sec)),
            rpc_limiter: Arc::new(RateLimiter::new(per_sec)),
            metrics: crate::metrics::global(),
            readiness: Arc::new(ReadinessState::new(config)),
            // Env-loaded: logs the "no captcha configured" warning once per
            // process when the keys are absent, so a forgotten config on a
            // public node is visible at startup.
            captcha: Arc::new(crate::turnstile::CaptchaGate::from_env()),
            health_options: HealthOptions::from_env(),
            health_cache: HealthCache::new(),
            telemetry_enabled: !no_telemetry_enabled(),
            health_data_dir_cache: Mutex::new(None),
            health_data_dir_scan_gate: tokio::sync::Mutex::new(()),
        }
    }

    /// Same as [`GatewayState::with_readiness`] with an explicit captcha gate
    /// (tests inject a mock verifier here; no env, no network).
    pub fn with_captcha(
        rpc: Arc<RpcState>,
        per_sec: u32,
        config: ReadinessConfig,
        captcha: Arc<crate::turnstile::CaptchaGate>,
    ) -> Self {
        Self {
            rpc,
            limiter: Arc::new(RateLimiter::new(per_sec)),
            rpc_limiter: Arc::new(RateLimiter::new(per_sec)),
            metrics: crate::metrics::global(),
            readiness: Arc::new(ReadinessState::new(config)),
            captcha,
            health_options: HealthOptions::from_env(),
            health_cache: HealthCache::new(),
            telemetry_enabled: !no_telemetry_enabled(),
            health_data_dir_cache: Mutex::new(None),
            health_data_dir_scan_gate: tokio::sync::Mutex::new(()),
        }
    }

    /// Override optional telemetry/status-banner exposure (for tests/embedders).
    pub fn with_telemetry_enabled(mut self, enabled: bool) -> Self {
        self.telemetry_enabled = enabled;
        self
    }

    /// Override health thresholds/cache/disk for tests or explicit deployments.
    /// Returns `self` so it composes with the existing constructors.
    pub fn with_health_options(mut self, options: HealthOptions) -> Self {
        self.health_options = options;
        self.health_cache.clear();
        *self
            .health_data_dir_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        self
    }

    /// Set the current connected-peer count for `/readyz` (call from the
    /// node/supervisor loop, e.g. once per consensus tick).
    pub fn set_ready_peers(&self, n: usize) {
        self.readiness.set_peers(n);
    }

    /// Record a finalized block for `/readyz` (call from the finalize path).
    pub fn note_ready_finalized(&self, height: u64) {
        self.readiness.note_finalized(height);
    }
}

/// Per-IP gate for the whole surface (audit 2026-10-14 F8/F10 interplay:
/// the bucket key is the RESOLVED client IP, and resolution honors proxy
/// headers ONLY from a trusted peer — so a remote spoofer's forged XFF is
/// ignored and they stay in their own TCP-peer's bucket; they cannot hop
/// into (or flood) anyone else's. The nested `/rpc` router carries its own
/// separate bucket below for the same reason).
async fn rate_limit(
    State(st): State<Arc<GatewayState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    // Real client IP behind a trusted reverse proxy (X-Forwarded-For /
    // Forwarded only when the TCP peer is in STELL_TRUSTED_PROXY_CIDRS,
    // loopback-only by default); otherwise the TCP peer. Without this every
    // client behind nginx/Cloudflare shared one bucket.
    let client = crate::client_ip::resolve_client_ip(req.headers(), addr.ip()).addr;
    if !st.limiter.check(client) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
    }
    next.run(req).await
}

async fn nested_rpc_rate_limit(
    State(st): State<Arc<GatewayState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut req: Request,
    next: Next,
) -> Response {
    let client = crate::client_ip::resolve_client_ip(req.headers(), addr.ip());
    if !st.rpc_limiter.check(client.addr) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
    }
    req.extensions_mut().insert(client);
    req.extensions_mut().insert(Arc::clone(&st.rpc_limiter));
    next.run(req).await
}

/// Explorer HTML template. `%TS_SCRIPT%` / `%TS_WIDGET%` / `%TS_REQUIRED%`
/// are substituted by [`render_index`] (plain `str::replace`, no template
/// engine — the page must keep working byte-for-byte identical when the
/// captcha is off).
const INDEX_HTML: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Stellereum Explorer</title>
<style>
 body{background:#0b0e14;color:#d7dae0;font-family:ui-monospace,Menlo,monospace;margin:0;padding:2rem}
 h1{color:#59d0ff} .card{background:#141924;border:1px solid #222a38;border-radius:10px;padding:1rem;margin:1rem 0}
 input,button{background:#0b0e14;color:#d7dae0;border:1px solid #2a3345;border-radius:6px;padding:.5rem}
 button{cursor:pointer;color:#7CFFB2} a{color:#59d0ff} .k{color:#8b95a7} pre{white-space:pre-wrap;word-break:break-all}
 .warn{color:#ffb86b}
</style>%TS_SCRIPT%</head><body>
<h1>Stellereum Explorer</h1>
<div class="card"><div id="stats">loading…</div></div>
<div class="card">
  <input id="q" placeholder="address (hex)" size="70">
  <button onclick="lookup()">Lookup balance / SPV</button>
  <pre id="out"></pre>
</div>
<div class="card"><h3>Public faucet</h3>
  <div class="k">5 STELL per address every 45 minutes</div>
  <input id="fa" placeholder="address (hex)" size="70">
  <button onclick="faucetGo()">Request 5 STELL</button>
  %TS_WIDGET%
  <pre id="fout"></pre>
</div>
<div class="card"><h3>Recent blocks</h3><div id="blocks">loading…</div></div>
<script>
const TS_REQUIRED=%TS_REQUIRED%;
async function j(u){const r=await fetch(u);return await r.json();}
async function loadStats(){
  try{const s=await j('/api/stats');
   document.getElementById('stats').innerHTML =
     '<span class="k">chainId</span> '+s.chain_id+' &nbsp; <span class="k">height</span> '+s.height+
     ' &nbsp; <span class="k">mempool</span> '+s.mempool+' &nbsp; <span class="k">stateRoot</span> '+s.state_root;
  }catch(e){document.getElementById('stats').textContent='error: '+e;}
}
async function loadBlocks(){
  try{const b=await j('/api/blocks');
   document.getElementById('blocks').innerHTML = b.length? b.map(x=>
     '<div>#'+x.height+' <span class="k">'+x.hash.slice(0,18)+'…</span> txs='+x.txs+' ts='+x.timestamp+'</div>').join('')
     : '<span class="k">no finalized blocks yet</span>';
  }catch(e){document.getElementById('blocks').textContent='error: '+e;}
}
async function lookup(){
  const a=document.getElementById('q').value.trim();
  if(!a){return;}
  try{const r=await j('/api/spv/'+a);
   document.getElementById('out').textContent=JSON.stringify(r,null,2);
  }catch(e){document.getElementById('out').textContent='error: '+e;}
}
async function faucetGo(){
  const out=document.getElementById('fout');
  const a=document.getElementById('fa').value.trim();
  if(!a){out.textContent='enter an address';return;}
  let token=null;
  if(TS_REQUIRED){
    if(typeof turnstile==='undefined'){
      out.innerHTML='<span class="warn">captcha failed to load — check your connection/adblocker and reload the page</span>';
      return;
    }
    token=turnstile.getResponse();
    if(!token){out.innerHTML='<span class="warn">solve the captcha first</span>';return;}
  }
  out.textContent='requesting…';
  try{
    const body=token?JSON.stringify({'cf-turnstile-response':token}):'';
    const r=await fetch('/api/faucet-public/'+a,{method:'POST',headers:{'content-type':'application/json'},body:body});
    out.textContent=r.status+' '+(await r.text());
    if(r.ok&&typeof turnstile!=='undefined'){turnstile.reset();}
  }catch(e){out.textContent='error: '+e;}
}
loadStats();loadBlocks();setInterval(()=>{loadStats();loadBlocks();},4000);
</script></body></html>"#;

/// Substitute the Turnstile placeholders in [`INDEX_HTML`]. With
/// `site_key = None` (captcha disabled) the page is the pre-captcha explorer
/// plus a plain faucet form; no external script is referenced.
fn render_index(site_key: Option<&str>) -> String {
    match site_key {
        Some(key) => INDEX_HTML
            .replace(
                "%TS_SCRIPT%",
                "\n<script src=\"https://challenges.cloudflare.com/turnstile/v0/api.js\" async defer></script>",
            )
            .replace(
                "%TS_WIDGET%",
                &format!(
                    "\n  <div class=\"cf-turnstile\" data-sitekey=\"{}\" data-theme=\"dark\" data-size=\"flexible\"></div>",
                    // Attribute-context escaping (defense in depth: the key is
                    // operator-controlled, but the page is served as HTML, so a
                    // pasted key must never break out of the attribute).
                    key.replace('&', "&amp;")
                        .replace('"', "&quot;")
                        .replace('<', "&lt;")
                        .replace('>', "&gt;")
                        .replace('\'', "&#x27;")
                ),
            )
            .replace("%TS_REQUIRED%", "true"),
        None => INDEX_HTML
            .replace("%TS_SCRIPT%", "")
            .replace("%TS_WIDGET%", "")
            .replace("%TS_REQUIRED%", "false"),
    }
}

async fn index(State(st): State<Arc<GatewayState>>) -> (HeaderMap, Html<String>) {
    let mut headers = HeaderMap::new();
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("x-frame-options", "SAMEORIGIN".parse().unwrap());
    headers.insert(
        "referrer-policy",
        "strict-origin-when-cross-origin".parse().unwrap(),
    );
    headers.insert(
        "permissions-policy",
        "geolocation=(), microphone=(), camera=()".parse().unwrap(),
    );
    (headers, Html(render_index(st.captcha.site_key())))
}

async fn api_stats(State(st): State<Arc<GatewayState>>) -> Json<serde_json::Value> {
    let height = st.rpc.height.load(std::sync::atomic::Ordering::Relaxed);
    let root = st.rpc.engine.get_state_root().await;
    let mempool = st.rpc.mempool.read().await.len();
    // The MEV (epoch-seal) view: how much of the pool takes the private
    // path, and which epoch key the network currently uses.
    let (sealed, plain, sealed_share, mev_epoch, epoch_key) = {
        let pool = st.rpc.mempool.read().await;
        let manager = &pool.mev_seal;
        (
            pool.sealed_count(),
            pool.len(),
            pool.sealed_share(),
            pool.sealed_epoch(),
            manager
                .epoch_commitment()
                .map(hex::encode)
                .unwrap_or_default(),
        )
    };
    Json(json!({
        "chain_id": st.rpc.chain_id,
        "node_id": st.rpc.node_id,
        "height": height,
        "mempool": mempool,
        "state_root": hex::encode(root),
        "contracts": st.rpc.engine.contract_count().await,
        "mev": {
            "epoch": mev_epoch,
            "sealed": sealed,
            "plain": plain,
            "sealed_share": sealed_share,
            "epoch_key_commitment": epoch_key,
        },
    }))
}

async fn api_blocks(State(st): State<Arc<GatewayState>>) -> Json<serde_json::Value> {
    let rb = st.rpc.recent_blocks.read().await;
    let list: Vec<serde_json::Value> = rb
        .iter()
        .map(|b| json!({ "height": b.height, "hash": b.hash, "txs": b.tx_count, "timestamp": b.timestamp }))
        .collect();
    Json(json!(list))
}

/// Parse a 32-byte hex address (with or without a `0x` prefix).
pub fn parse_addr(s: &str) -> Option<[u8; 32]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 64 {
        return None;
    }
    hex::decode(s).ok()?.try_into().ok()
}

/// Explorer-facing counterpart of `rpc::reads::foreign_shard_refusal`.
///
/// The gateway serves this process's ONE engine/trie. A balance, SPV proof or
/// account view for an address that routes to another shard must be refused,
/// not answered with a locally-verifiable zero/exclusion answer. Single-shard
/// nodes (the default) are unchanged.
async fn foreign_shard_response(st: &GatewayState, address: [u8; 32]) -> Option<Response> {
    if !st.rpc.shard_registry.is_sharded() {
        return None;
    }
    let target = {
        let topology = st.rpc.engine.shard_topology().await;
        crate::sharding::route_shard(
            &topology,
            &crate::sharding::ShardAddress::Workchain(address),
        )
    };
    let local = st.rpc.engine.shard_id();
    if target == local {
        return None;
    }
    Some(
        (
            StatusCode::NOT_FOUND,
            format!("address belongs to shard {target}, but this node serves shard {local}"),
        )
            .into_response(),
    )
}

/// GET hint for the POST-only faucet (see the route above).
async fn faucet_get_hint() -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        "faucet is POST-only (GET would let crawlers mint); POST to this URL with the token in the Authorization header",
    )
        .into_response()
}

fn faucet_drip_error_response(err: crate::rpc::FaucetDripError) -> Response {
    match err {
        crate::rpc::FaucetDripError::LifetimeCapExhausted => (
            StatusCode::TOO_MANY_REQUESTS,
            "faucet limit reached for this address",
        )
            .into_response(),
        crate::rpc::FaucetDripError::Cooldown { retry_after_secs } => (
            StatusCode::TOO_MANY_REQUESTS,
            format!(
                "public drip cooling down for this address, retry in {retry_after_secs} seconds"
            ),
        )
            .into_response(),
        crate::rpc::FaucetDripError::IpRateLimited => (
            StatusCode::TOO_MANY_REQUESTS,
            "per-IP faucet budget exhausted for this hour",
        )
            .into_response(),
        crate::rpc::FaucetDripError::Quarantined { reason } => {
            tracing::error!("[faucet] quarantined drip refused: {reason}");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "faucet is temporarily unavailable (fail-closed quarantine)",
            )
                .into_response()
        }
        crate::rpc::FaucetDripError::PersistFailed { reason } => {
            tracing::error!("[faucet] persist failure refused drip: {reason}");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "faucet state could not be persisted; drip refused",
            )
                .into_response()
        }
    }
}

async fn api_faucet(
    State(st): State<Arc<GatewayState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    AxumPath(addr_param): AxumPath<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let Some(faucet) = st.rpc.faucet.clone() else {
        return (StatusCode::NOT_FOUND, "faucet is disabled on this node").into_response();
    };
    // Real client IP: proxy headers only from a trusted peer (see
    // crate::client_ip); feeds the per-IP faucet budget and the logs below.
    let client_ip = crate::client_ip::resolve_client_ip(&headers, addr.ip()).addr;
    // Fail-closed: the faucet mints money, so "no token configured" must never
    // degrade into "anyone who can reach this gateway may mint". This mirrors
    // the `stell_faucet` JSON-RPC gate exactly and accepts the token either as
    // `?token=`/`?apiKey=` or via the conventional auth headers.
    let Some(expected) = configured_secret(st.rpc.faucet_token.as_deref()) else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "faucet is enabled but STELL_FAUCET_TOKEN is not set; refusing to dispense",
        )
            .into_response();
    };
    let provided = query
        .get("token")
        .or_else(|| query.get("apiKey"))
        .map(|s| s.as_str())
        .or_else(|| extract_header_token(&headers));
    if query.contains_key("token") || query.contains_key("apiKey") {
        // Tokens in URLs land in access/proxy logs and browser history;
        // headers are the safe path (audit 2026-10-06). Still accepted.
        tracing::warn!(
            "[faucet] token passed via URL query from {}; prefer Authorization header",
            client_ip
        );
    }
    if !provided
        .map(|p| constant_time_eq(p, expected))
        .unwrap_or(false)
    {
        return (
            StatusCode::UNAUTHORIZED,
            "unauthorized: missing or invalid faucet token",
        )
            .into_response();
    }
    // Address validation + shard scope BEFORE the per-IP throttle below:
    // validation is free, quota is not — malformed requests must never
    // consume budget (same order as the public faucet path). On a sharded
    // node a recipient that routes to another shard is refused here — the
    // drip could never execute there, and queuing it would only burn the
    // faucet's nonce sequence.
    let (a, drip_shard) =
        match crate::rpc::resolve_faucet_recipient(&st.rpc, &faucet, &addr_param).await {
            Ok(v) => v,
            Err(e) if e.starts_with("invalid address") => {
                return (StatusCode::BAD_REQUEST, e).into_response();
            }
            Err(e) => {
                return (StatusCode::SERVICE_UNAVAILABLE, e).into_response();
            }
        };
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Atomic mex-reconcile + single-lock cap/IP-budget reservation:
    // cap/quarantine refusals do not burn the per-IP hourly budget, and
    // mempool admission failure rolls the entire grant (nonce, cap, IP
    // budget) back via `rollback_grant`.
    let faucet_addr = faucet.account();
    let onchain = st
        .rpc
        .engine
        .get_account(&faucet_addr)
        .await
        .map(|acc| acc.nonce)
        .unwrap_or(0);
    let pending: Vec<u64> = st
        .rpc
        .mempool
        .read()
        .await
        .all()
        .iter()
        .filter(|t| t.from == faucet_addr)
        .map(|t| t.nonce)
        .collect();
    let chain_id = faucet
        .chain_id()
        .unwrap_or_else(crate::consensus::consensus_chain_id);
    let grant = match faucet
        .request_drip_for_chain(
            crate::rpc::FaucetDripRequest::token(
                a,
                None,
                Some((onchain, pending)),
                now_secs,
                Some(client_ip),
            ),
            Some(chain_id),
        )
        .await
    {
        Ok(g) => g,
        Err(e) => return faucet_drip_error_response(e),
    };
    let balance = st
        .rpc
        .engine
        .get_account(&faucet.account())
        .await
        .map(|acc| acc.balance)
        .unwrap_or(0);
    let next_height = st
        .rpc
        .height
        .load(std::sync::atomic::Ordering::Relaxed)
        .saturating_add(1);
    let tx_hash = match st.rpc.mempool.write().await.add_checked_ctx(
        grant.tx.clone(),
        balance,
        crate::mempool::AdmissionCtx::wall_now().with_chain_height(next_height),
    ) {
        Ok(h) => h,
        Err(e) => {
            let _ = faucet.rollback_grant(&grant).await;
            return (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response();
        }
    };
    if let Some(bcast) = &st.rpc.tx_broadcast {
        let _ = bcast.send(grant.tx);
    }
    Json(json!({
        "status": "pending",
        "credited_nano": grant.amount.to_string(),
        "recipient": hex::encode(a),
        "tx_hash": hex::encode(tx_hash),
        "shard": drip_shard,
    }))
    .into_response()
}

/// Pull the Turnstile token out of a public-faucet request: either the
/// conventional `cf-turnstile-response` JSON/body field (what the widget's
/// form POST carries), the alias `turnstile_token`, or the headers
/// `CF-Turnstile-Response` / `X-Turnstile-Token` for API clients that do not
/// want to build a JSON body. Empty/blank values count as absent.
fn extract_turnstile_token(headers: &HeaderMap, body: &[u8]) -> Option<String> {
    let from_headers = ["cf-turnstile-response", "x-turnstile-token"]
        .iter()
        .find_map(|name| headers.get(*name))
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty());
    if from_headers.is_some() {
        return from_headers.map(str::to_string);
    }
    if body.is_empty() {
        return None;
    }
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    ["cf-turnstile-response", "turnstile_token"]
        .iter()
        .find_map(|k| v.get(*k).and_then(|x| x.as_str()))
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

/// Public testnet faucet (TON-style, tokenless): fixed 5 STELL per address
/// per 45 minutes. Deliberately POST-only (GET would let crawlers drain it).
/// Defenses, all enforced before any mint:
/// - per-address 45-minute cooldown (persisted, survives restarts);
/// - per-IP hourly budget (shared throttle with the token faucet path);
/// - Cloudflare Turnstile captcha, REQUIRED on non-loopback claims.
///
/// OPERATOR CONTRACT (fail-closed):
/// - Set BOTH `STELL_TURNSTILE_SITE_KEY` (public, embedded in the explorer
///   HTML) and `STELL_TURNSTILE_SECRET_KEY` (server-only, verified via
///   Cloudflare `siteverify`) to enable the captcha; the gate then verifies
///   every public claim BEFORE any budget is consumed or funds move.
/// - When NEITHER key is set (`CaptchaConfig::Disabled`) public claims from
///   non-loopback client IPs are refused with `503 captcha not configured`
///   and nothing dispenses (no throttle consumed, no mint queued).
/// - Loopback clients (`client_ip.is_loopback()`, i.e. local dev/tests over
///   `127.0.0.0/8` or `::1`) keep the legacy IP-throttle-only path so the
///   existing faucet tests stay green without weakening asserts.
/// - Exactly ONE key set (`CaptchaConfig::Misconfigured`) is always `503`,
///   loopback included: refusing beats dispensing while the operator believes
///   the captcha is on.
///
/// Check order (deliberate):
/// 1. address validation — free; a malformed address must never reach
///    siteverify or consume any budget;
/// 2. Turnstile captcha (when configured) — fail-closed: verified BEFORE
///    consuming IP throttle quota to prevent quota exhaustion on shared NAT IPs
///    (missing token → 400, Cloudflare rejection → 403, siteverify unreachable → 503);
///    unconfigured + non-loopback → 503 "captcha not configured";
/// 3. per-IP hourly throttle;
/// 4. mint/dispense.
async fn api_faucet_public(
    State(st): State<Arc<GatewayState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    AxumPath(addr_param): AxumPath<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let Some(faucet) = st.rpc.faucet.clone() else {
        return (StatusCode::NOT_FOUND, "faucet is disabled on this node").into_response();
    };
    // (1) Address validation + shard scope first: garbage never burns a
    // siteverify call, and a recipient that routes to another shard is refused
    // here (same rule as `stell_faucet`) — the drip could never execute there,
    // and queuing it would only burn the faucet's nonce sequence.
    let (a, drip_shard) =
        match crate::rpc::resolve_faucet_recipient(&st.rpc, &faucet, &addr_param).await {
            Ok(v) => v,
            Err(e) if e.starts_with("invalid address") => {
                return (StatusCode::BAD_REQUEST, e).into_response();
            }
            Err(e) => {
                return (StatusCode::SERVICE_UNAVAILABLE, e).into_response();
            }
        };
    // Real client IP behind a trusted proxy (see crate::client_ip): feeds the
    // per-IP faucet budget and Turnstile `remoteip` below.
    let resolved = crate::client_ip::resolve_client_ip(&headers, addr.ip());
    let client_ip = resolved.addr;
    if resolved.source == crate::client_ip::ClientIpSource::ForwardedLoopbackRejected {
        // Provenance is security-relevant: a proxy forwarded a loopback claim
        // but the deployment has not opted in, so the claim is discarded and
        // the local (captcha-exempt) branch below stays CLOSED.
        tracing::warn!(
            "[faucet] discarded forwarded loopback IP claim from peer {} (set {}=1 only for a trusted overwriting proxy)",
            addr.ip(),
            crate::client_ip::TRUST_LOOPBACK_FORWARDED_ENV,
        );
    }
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // (2) Cloudflare Turnstile: verify BEFORE consuming IP throttle quota
    // to prevent quota exhaustion on shared NAT IPs. Misconfigured (secret
    // without site key) fails closed: better to refuse than to dispense
    // unprotected while the operator believes the captcha is on.
    match st.captcha.config() {
        crate::turnstile::CaptchaConfig::Misconfigured => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "faucet captcha is misconfigured on this node (STELL_TURNSTILE_SECRET_KEY without STELL_TURNSTILE_SITE_KEY); refusing to dispense",
            )
                .into_response();
        }
        crate::turnstile::CaptchaConfig::Enabled { .. } => {
            let Some(token) = extract_turnstile_token(&headers, &body) else {
                return (
                    StatusCode::BAD_REQUEST,
                    "captcha token required: send the cf-turnstile-response body field or the CF-Turnstile-Response header",
                )
                    .into_response();
            };
            match st.captcha.verify(&token, Some(client_ip)).await {
                crate::turnstile::CaptchaVerdict::Success => {}
                crate::turnstile::CaptchaVerdict::Rejected { error_codes } => {
                    // Error codes are Cloudflare's vocabulary (safe to show);
                    // the token itself is never echoed or logged.
                    return (
                        StatusCode::FORBIDDEN,
                        format!(
                            "captcha failed (error-codes: {}); solve a fresh captcha and retry",
                            if error_codes.is_empty() {
                                "unknown".to_string()
                            } else {
                                error_codes.join(", ")
                            }
                        ),
                    )
                        .into_response();
                }
                crate::turnstile::CaptchaVerdict::Unavailable { reason } => {
                    // Fail-closed: an unreachable siteverify must not dispense.
                    tracing::warn!(
                        "[faucet] turnstile siteverify unavailable from {}: {reason}",
                        client_ip
                    );
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "captcha verification is temporarily unavailable; try again shortly",
                    )
                        .into_response();
                }
            }
        }
        crate::turnstile::CaptchaConfig::Disabled => {
            // Fail-closed default: an unconfigured captcha must not dispense to
            // the public internet. Only a DIRECT loopback TCP peer (local
            // dev/tests) keeps the legacy IP-throttle-only path: a loopback
            // address claimed in a forwarding header is not local, so a
            // same-host proxy cannot be talked into opening this branch by a
            // client-supplied `CF-Connecting-IP: 127.0.0.1` (F11). Behind a
            // reverse proxy the operator must forward the real client IP
            // (STELL_TRUSTED_PROXY_CIDRS / X-Forwarded-For) so public traffic
            // is not misread as loopback.
            if !resolved.is_local_client() {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "public faucet captcha is not configured on this node (set STELL_TURNSTILE_SITE_KEY and STELL_TURNSTILE_SECRET_KEY); refusing to dispense",
                )
                    .into_response();
            }
        }
    }
    // (3) Atomic cooldown + lifetime cap + per-IP budget + mex-reconcile
    // under ONE faucet lock: cooldown/cap/quarantine refusals never burn the
    // per-IP hourly budget, and mempool admission failure rolls the entire
    // grant back via `rollback_grant`.
    let faucet_addr = faucet.account();
    let onchain = st
        .rpc
        .engine
        .get_account(&faucet_addr)
        .await
        .map(|acc| acc.nonce)
        .unwrap_or(0);
    let pending: Vec<u64> = st
        .rpc
        .mempool
        .read()
        .await
        .all()
        .iter()
        .filter(|t| t.from == faucet_addr)
        .map(|t| t.nonce)
        .collect();
    let chain_id = faucet
        .chain_id()
        .unwrap_or_else(crate::consensus::consensus_chain_id);
    let grant = match faucet
        .request_drip_for_chain(
            crate::rpc::FaucetDripRequest::public(
                a,
                Some((onchain, pending)),
                now_secs,
                Some(client_ip),
            ),
            Some(chain_id),
        )
        .await
    {
        Ok(g) => g,
        Err(e) => return faucet_drip_error_response(e),
    };
    let balance = st
        .rpc
        .engine
        .get_account(&faucet.account())
        .await
        .map(|acc| acc.balance)
        .unwrap_or(0);
    let next_height = st
        .rpc
        .height
        .load(std::sync::atomic::Ordering::Relaxed)
        .saturating_add(1);
    let tx_hash = match st.rpc.mempool.write().await.add_checked_ctx(
        grant.tx.clone(),
        balance,
        crate::mempool::AdmissionCtx::wall_now().with_chain_height(next_height),
    ) {
        Ok(h) => h,
        Err(e) => {
            let _ = faucet.rollback_grant(&grant).await;
            return (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response();
        }
    };
    if let Some(bcast) = &st.rpc.tx_broadcast {
        let _ = bcast.send(grant.tx);
    }
    Json(json!({
        "status": "pending",
        "credited_nano": grant.amount.to_string(),
        "recipient": hex::encode(a),
        "tx_hash": hex::encode(tx_hash),
        "shard": drip_shard,
        "next_drip_in_seconds": crate::rpc::public_drip_cooldown_secs(),
    }))
    .into_response()
}

async fn api_balance(
    State(st): State<Arc<GatewayState>>,
    AxumPath(addr): AxumPath<String>,
) -> Response {
    let Some(a) = parse_addr(&addr) else {
        return (StatusCode::BAD_REQUEST, "bad address").into_response();
    };
    if let Some(denied) = foreign_shard_response(&st, a).await {
        return denied;
    }
    let acc = st.rpc.engine.get_account(&a).await;
    let (balance, nonce) = acc.map(|x| (x.balance, x.nonce)).unwrap_or((0, 0));
    Json(json!({ "address": hex::encode(a), "balance": balance.to_string(), "nonce": nonce }))
        .into_response()
}

async fn api_spv(
    State(st): State<Arc<GatewayState>>,
    AxumPath(addr): AxumPath<String>,
) -> Response {
    let Some(a) = parse_addr(&addr) else {
        return (StatusCode::BAD_REQUEST, "bad address").into_response();
    };
    if let Some(denied) = foreign_shard_response(&st, a).await {
        return denied;
    }
    let acc = st.rpc.engine.get_account(&a).await;
    let (balance, nonce) = acc.map(|x| (x.balance, x.nonce)).unwrap_or((0, 0));
    let root = st.rpc.engine.get_state_root().await;
    let proof = st.rpc.engine.get_account_proof(&a).await;
    Json(json!({
        "address": hex::encode(a),
        "balance": balance.to_string(),
        "nonce": nonce,
        "state_root": hex::encode(root),
        "proof": proof,
    }))
    .into_response()
}

async fn api_contracts(
    State(st): State<Arc<GatewayState>>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    // Paginated like stell_listTokens (audit 2026-10-06): permissionless
    // deploys grow this list; `limit` default 100, hard max 1000.
    let limit: usize = query
        .get("limit")
        .and_then(|s| s.parse().ok())
        .map(|n: usize| n.min(1000))
        .unwrap_or(100);
    let offset: usize = query
        .get("offset")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let after = match query
        .get("after")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        Some(raw) => {
            let Some(cursor) = parse_addr(raw) else {
                return (
                    StatusCode::BAD_REQUEST,
                    "invalid after cursor (expected 32-byte hex contract address)",
                )
                    .into_response();
            };
            Some(cursor)
        }
        None => None,
    };
    let contracts = st.rpc.engine.contracts_read().await;
    let total = contracts.contracts.len();
    if let Some(cursor) = after {
        let mut keys: Vec<[u8; 32]> = contracts
            .contracts
            .keys()
            .copied()
            .filter(|k| *k > cursor)
            .collect();
        keys.sort_unstable();
        let has_more = keys.len() > limit;
        let page: Vec<[u8; 32]> = keys.into_iter().take(limit).collect();
        let next_cursor = if has_more {
            page.last().map(hex::encode)
        } else {
            None
        };
        let addrs: Vec<String> = page.iter().map(hex::encode).collect();
        return Json(json!({
            "contracts": addrs,
            "total": total,
            "offset": 0,
            "next_cursor": next_cursor,
            "has_more": has_more,
        }))
        .into_response();
    }
    // Sort contract IDs deterministically before skip/take so pages are
    // reproducible across requests/restarts while keeping the default shape
    // (`contracts`, `total`, `offset`) unchanged.
    let addrs: Vec<String> = if limit == 0 || offset >= total {
        Vec::new()
    } else {
        let mut keys: Vec<[u8; 32]> = contracts.contracts.keys().copied().collect();
        keys.sort_unstable();
        keys.into_iter()
            .skip(offset)
            .take(limit)
            .map(hex::encode)
            .collect()
    };
    Json(json!({ "contracts": addrs, "total": total, "offset": offset })).into_response()
}

/// Hard cap for `GET /api/finals?limit=` (fail-closed: oversized clamps,
/// zero/non-numeric refuses). Small: the backing window itself is capped at
/// `MAX_RECENT_BLOCKS` (100), so a larger limit could never return more.
pub const MAX_FINALS_LIMIT: usize = 100;
/// Default rows for `GET /api/finals` without `?limit=`.
pub const DEFAULT_FINALS_LIMIT: usize = 20;
/// Max tx refs returned by `GET /api/account/:address`.
pub const MAX_ACCOUNT_TXS: usize = 20;
/// Max delegations returned by `GET /api/account/:address`.
pub const MAX_ACCOUNT_DELEGATIONS: usize = 50;
/// Scan budget for the staking-map walks in the account view (bounded
/// iteration: a hostile ledger must not pin the handler).
const ACCOUNT_SCAN_BUDGET: usize = 20_000;

/// `GET /api/validator/:address` — human validator summary.
///
/// Read-only over the indexed staking ledger (`RpcState::staking`, same
/// derivation as `stell_getValidators` so the power/set can never disagree
/// with RPC). Unknown addresses are DATA (`known: false`), not an error;
/// malformed addresses fail closed (400). No new index, no env knob.
async fn api_validator(
    State(st): State<Arc<GatewayState>>,
    AxumPath(addr): AxumPath<String>,
) -> Response {
    let Some(a) = parse_addr(&addr) else {
        return (StatusCode::BAD_REQUEST, "bad address").into_response();
    };
    let ledger = st.rpc.staking.read().await;
    let rec = ledger.validators.get(&a).cloned();
    let jail = ledger.jail_record(&a);
    let in_set = ledger.to_validator_set().validators.contains_key(&a);
    let pending = ledger
        .commission_schedule_of(&a)
        .and_then(|s| s.pending)
        .map(|p| {
            json!({
                "new_bps": p.new_bps,
                "announced_height": p.announced_height,
                "effective_height": p.effective_height,
            })
        })
        .unwrap_or(serde_json::Value::Null);
    let hex_addr = hex::encode(a);
    let moniker = format!("val-{}", &hex_addr[..8]);
    match rec {
        Some(r) => Json(json!({
            "validator": hex_addr,
            "known": true,
            "moniker": moniker,
            "in_set": in_set,
            "power": r.total().to_string(),
            "self_bond": r.self_bond.to_string(),
            "delegated": r.delegated.to_string(),
            "commission_bps": r.commission_bps,
            "jailed": jail.is_some(),
            "jailed_at_height": jail.map(|j| j.jailed_at_height),
            "release_height": jail.map(|j| j.release_height),
            "pending_commission": pending,
        }))
        .into_response(),
        None => Json(json!({
            "validator": hex_addr,
            "known": false,
            "moniker": moniker,
            "in_set": false,
            "power": "0",
            "self_bond": null,
            "delegated": null,
            "commission_bps": null,
            "jailed": false,
            "jailed_at_height": null,
            "release_height": null,
            "pending_commission": null,
        }))
        .into_response(),
    }
}

/// `GET /api/finals[?limit=N]` — recent-finals feed, newest first.
///
/// Each row joins the `recent_blocks` window with the receipt index
/// (`receipts` count per height) and the inter-block interval. `limit`
/// defaults to [`DEFAULT_FINALS_LIMIT`], clamps to [`MAX_FINALS_LIMIT`];
/// zero/non-numeric fails closed (400). Empty store is `[]`.
async fn api_finals(
    State(st): State<Arc<GatewayState>>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let limit: usize = match query.get("limit") {
        None => DEFAULT_FINALS_LIMIT,
        Some(raw) => match raw.parse::<usize>() {
            Ok(n) if n >= 1 => n.min(MAX_FINALS_LIMIT),
            _ => {
                return (StatusCode::BAD_REQUEST, "limit must be an integer 1..=100")
                    .into_response()
            }
        },
    };
    let blocks: Vec<crate::rpc::BlockSummary> = {
        let rb = st.rpc.recent_blocks.read().await;
        rb.iter().take(limit).cloned().collect()
    };
    if blocks.is_empty() {
        return Json(json!([])).into_response();
    }
    let counts: std::collections::HashMap<u64, usize> = {
        let receipts = st.rpc.receipts.read().await;
        let mut m: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
        for r in receipts.values() {
            *m.entry(r.height).or_insert(0) += 1;
        }
        m
    };
    let rows: Vec<serde_json::Value> = blocks
        .iter()
        .enumerate()
        .map(|(i, b)| {
            let interval = if i + 1 < blocks.len() {
                let prev_ts = blocks[i + 1].timestamp;
                Some(b.timestamp.saturating_sub(prev_ts))
            } else {
                None
            };
            json!({
                "height": b.height,
                "hash": b.hash,
                "txs": b.tx_count,
                "timestamp": b.timestamp,
                "interval_secs": interval,
                "receipts": counts.get(&b.height).copied().unwrap_or(0),
            })
        })
        .collect();
    Json(json!(rows)).into_response()
}

/// `GET /api/account/:address` — human account summary.
///
/// Balances/nonce from the state engine, staking position from the indexed
/// staking ledger, tx refs from the pending mempool (bounded to
/// [`MAX_ACCOUNT_TXS`], newest nonce first). Unknown addresses are DATA
/// (zero balance, empty position), not an error; malformed fails closed
/// (400). All ledger walks are scan-budgeted; outputs are capped with
/// `*_truncated` flags.
async fn api_account(
    State(st): State<Arc<GatewayState>>,
    AxumPath(addr): AxumPath<String>,
) -> Response {
    let Some(a) = parse_addr(&addr) else {
        return (StatusCode::BAD_REQUEST, "bad address").into_response();
    };
    if let Some(denied) = foreign_shard_response(&st, a).await {
        return denied;
    }
    let hex_addr = hex::encode(a);
    let (balance, nonce) = st
        .rpc
        .engine
        .get_account(&a)
        .await
        .map(|acc| (acc.balance, acc.nonce))
        .unwrap_or((0, 0));
    let ledger = st.rpc.staking.read().await;
    let as_validator = match ledger.validators.get(&a) {
        Some(r) => json!({
            "self_bond": r.self_bond.to_string(),
            "delegated": r.delegated.to_string(),
            "power": r.total().to_string(),
            "commission_bps": r.commission_bps,
            "jailed": ledger.jail.contains_key(&a),
            "in_set": ledger.to_validator_set().validators.contains_key(&a),
        }),
        None => serde_json::Value::Null,
    };
    let mut delegations: Vec<(String, u64)> = Vec::new();
    let mut delegation_count: usize = 0;
    let mut delegations_truncated = false;
    let mut scanned: usize = 0;
    for ((v, d), amt) in ledger.delegations.iter() {
        scanned += 1;
        if scanned > ACCOUNT_SCAN_BUDGET {
            delegations_truncated = true;
            break;
        }
        if *d == a {
            delegation_count += 1;
            if delegations.len() <= MAX_ACCOUNT_DELEGATIONS {
                delegations.push((hex::encode(v), *amt));
            }
        }
    }
    if delegations.len() > MAX_ACCOUNT_DELEGATIONS {
        delegations.truncate(MAX_ACCOUNT_DELEGATIONS);
        delegations_truncated = true;
    }
    delegations.sort_by(|x, y| x.0.cmp(&y.0));
    let mut withdrawable: u64 = 0;
    let mut wscanned: usize = 0;
    for ((v, o), amt) in ledger.withdrawable.iter() {
        wscanned += 1;
        if wscanned > ACCOUNT_SCAN_BUDGET {
            break;
        }
        if (*v == a && *o == [0u8; 32]) || *o == a {
            withdrawable = withdrawable.saturating_add(*amt);
        }
    }
    drop(ledger);
    let pending: Vec<crate::sharding::Transaction> = {
        let pool = st.rpc.mempool.read().await;
        pool.all()
            .into_iter()
            .filter(|t| t.from == a || t.to == a)
            .collect()
    };
    let recent_tx_count = pending.len();
    let mut pending_sorted = pending;
    pending_sorted.sort_by(|x, y| y.nonce.cmp(&x.nonce));
    let truncated = recent_tx_count > MAX_ACCOUNT_TXS;
    let recent: Vec<serde_json::Value> = pending_sorted
        .into_iter()
        .take(MAX_ACCOUNT_TXS)
        .map(|t| {
            let out = t.from == a;
            json!({
                "tx_hash": hex::encode(t.compute_tx_hash()),
                "direction": if out { "out" } else { "in" },
                "counterparty": hex::encode(if out { t.to } else { t.from }),
                "amount": t.amount.to_string(),
                "nonce": t.nonce,
                "status": "pending",
            })
        })
        .collect();
    let delegation_rows: Vec<serde_json::Value> = delegations
        .into_iter()
        .map(|(v, amt)| json!({ "validator": v, "amount": amt.to_string() }))
        .collect();
    Json(json!({
        "address": hex_addr,
        "balance": balance.to_string(),
        "nonce": nonce,
        "as_validator": as_validator,
        "delegation_count": delegation_count,
        "delegations": delegation_rows,
        "delegations_truncated": delegations_truncated,
        "withdrawable": withdrawable.to_string(),
        "recent_tx_count": recent_tx_count,
        "recent_txs": recent,
        "recent_txs_truncated": truncated,
    }))
    .into_response()
}

/// Human-readable rendering of one full transaction: a transparent summary.
/// Read-only.
pub fn describe_transaction(tx: &crate::sharding::Transaction) -> serde_json::Value {
    let tx_hash = hex::encode(tx.compute_tx_hash());
    json!({
        "kind": "transparent",
        "sender": hex::encode(tx.from),
        "recipient": hex::encode(tx.to),
        "amount": tx.amount,
        // Honest naming (audit 2026-10-06): this is the DECLARED limit, not
        // the charged fee (charged <= limit; receipts don't store gas_used).
        // The old "fee" key overstated the charge, so it is gone.
        "fee_limit": tx.gas_limit,
        "nonce": tx.nonce,
        "gas_limit": tx.gas_limit,
        "tx_hash": tx_hash,
        "payload_ops": tx.payload.len(),
    })
}

/// `GET /api/tx/:hash` — human-readable transaction view.
///
/// Serve order: mempool body (the only place a full pre-finalization payload
/// lives on this node) rendered via `describe_transaction` + receipt status
/// when finalized; else the finalized receipt alone (no payload to render, so
/// `kind` is `receipt-only`); else 404 `{"status":"unknown"}` — never
/// fabricated.
async fn api_tx(
    State(st): State<Arc<GatewayState>>,
    AxumPath(hash_hex): AxumPath<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let s = hash_hex.strip_prefix("0x").unwrap_or(&hash_hex);
    if s.len() != 64 {
        return (StatusCode::BAD_REQUEST, "bad tx hash").into_response();
    }
    let Ok(raw) = hex::decode(s) else {
        return (StatusCode::BAD_REQUEST, "bad tx hash").into_response();
    };
    let Ok(hash): Result<[u8; 32], _> = raw.try_into() else {
        return (StatusCode::BAD_REQUEST, "bad tx hash").into_response();
    };
    let found = st.rpc.mempool.read().await.get(&hash).cloned();
    if let Some(tx) = found {
        let mut view = describe_transaction(&tx);
        let receipts = st.rpc.receipts.read().await;
        if let Some(r) = receipts.get(&hash) {
            view["status"] = json!(if r.success { "success" } else { "failed" });
            view["height"] = json!(r.height);
            view["block_hash"] = json!(hex::encode(r.block_hash));
            view["index"] = json!(r.index);
            view["fee_charged"] = json!(r.fee_charged.to_string());
        } else {
            // Pending bodies are non-public, same as `stell_mempoolDump`:
            // unauthenticated callers get hash/nonce/status only, never the
            // full pre-finalization payload (front-running aid).
            let authed = match configured_secret(st.rpc.auth_token.as_deref()) {
                None => false,
                Some(expected) => {
                    if query.contains_key("token") || query.contains_key("apiKey") {
                        // Tokens in URLs land in access/proxy logs and browser
                        // history; headers are the safe path (same rule as the
                        // faucet gate above). Still accepted for compat.
                        tracing::warn!(
                            "[explorer] auth token passed via URL query on /api/tx; prefer Authorization header"
                        );
                    }
                    let provided = query
                        .get("token")
                        .or_else(|| query.get("apiKey"))
                        .map(|s| s.as_str())
                        .or_else(|| extract_header_token(&headers));
                    provided
                        .map(|p| constant_time_eq(p, expected))
                        .unwrap_or(false)
                }
            };
            if !authed {
                return Json(json!({
                    "tx_hash": hex::encode(hash),
                    "nonce": tx.nonce,
                    "status": "pending",
                }))
                .into_response();
            }
            view["status"] = json!("pending");
        }
        return Json(view).into_response();
    }
    let receipts = st.rpc.receipts.read().await;
    if let Some(r) = receipts.get(&hash) {
        return Json(json!({
            "kind": "receipt-only",
            "tx_hash": hex::encode(r.tx_hash),
            "height": r.height,
            "block_hash": hex::encode(r.block_hash),
            "index": r.index,
            "status": if r.success { "success" } else { "failed" },
            "gas_limit": r.gas_limit.to_string(),
            "fee_charged": r.fee_charged.to_string(),
        }))
        .into_response();
    }
    (StatusCode::NOT_FOUND, Json(json!({ "status": "unknown" }))).into_response()
}

/// Max payload ops labeled by `GET /api/tx-detail/:hash` (decoded intent is
/// a bounded summary, never a full program dump).
pub const MAX_TXDETAIL_INTENT_OPS: usize = 50;
/// Max receipt events rendered by `GET /api/tx-detail/:hash`.
pub const MAX_TXDETAIL_EVENTS: usize = 20;
/// Max tx refs returned by `GET /api/block-detail/:query`.
pub const MAX_BLOCKDETAIL_TXS: usize = 100;
/// Max QC signer keys returned by `GET /api/block-detail/:query`.
pub const MAX_BLOCKDETAIL_QC_KEYS: usize = 20;

/// Truncate free text to `max_chars` characters (bounded rendering of
/// operator-controlled strings: token names, method names).
fn truncate_text(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        s.chars().take(max_chars).collect()
    }
}

/// One-line human label for a single payload opcode (the decoded-intent leg
/// of the tx-detail view). Indexed data only: addresses render as hex,
/// numbers as numbers, free text truncated, and byte blobs (code, proofs,
/// calldata, evidence envelopes) render as lengths — never echoed raw, so the
/// view stays bounded no matter what the payload carries.
pub fn describe_intent_op(op: &crate::svm::OpCode) -> String {
    use crate::svm::OpCode as Op;
    match op {
        Op::Nop => "nop".to_string(),
        Op::Push(v) => format!("push {v}"),
        Op::Pop => "pop".to_string(),
        Op::Add => "add".to_string(),
        Op::Sub => "sub".to_string(),
        Op::Mul => "mul".to_string(),
        Op::Div => "div".to_string(),
        Op::LoadBalance => "load-balance".to_string(),
        Op::Transfer { recipient, amount } => {
            format!("transfer to={} amount={amount}", hex::encode(recipient))
        }
        Op::SysCallPlaceOrder {
            pair_id,
            is_buy,
            price,
            amount,
        } => format!(
            "place-order pair={pair_id} side={} price={price} amount={amount}",
            if *is_buy { "buy" } else { "sell" }
        ),
        Op::SysCallCancelOrder { order_id } => format!("cancel-order {order_id}"),
        Op::SysCallVerifyZkMl => "verify-zkml-legacy".to_string(),
        Op::SysCallPatriciaLookup(_) => "patricia-lookup".to_string(),
        Op::SysCallTokenTransfer {
            token_id,
            to,
            amount,
        } => format!(
            "token-transfer token={} to={} amount={amount}",
            hex::encode(token_id),
            hex::encode(to)
        ),
        Op::SysCallTokenTransferFrom {
            token_id,
            from,
            to,
            amount,
        } => format!(
            "token-transfer-from token={} from={} to={} amount={amount}",
            hex::encode(token_id),
            hex::encode(from),
            hex::encode(to)
        ),
        Op::SysCallTokenMint {
            token_id,
            to,
            amount,
        } => format!(
            "token-mint token={} to={} amount={amount}",
            hex::encode(token_id),
            hex::encode(to)
        ),
        Op::SysCallTokenBurn {
            token_id,
            from,
            amount,
        } => format!(
            "token-burn token={} from={} amount={amount}",
            hex::encode(token_id),
            hex::encode(from)
        ),
        Op::SysCallTokenApprove {
            token_id,
            spender,
            amount,
        } => format!(
            "token-approve token={} spender={} amount={amount}",
            hex::encode(token_id),
            hex::encode(spender)
        ),
        Op::SysCallTokenBalanceOf { token_id, account } => format!(
            "token-balance-of token={} account={}",
            hex::encode(token_id),
            hex::encode(account)
        ),
        Op::SysCallDeployContract { code } => {
            format!("deploy-contract bytes={}", code.len())
        }
        Op::SysCallCallContract {
            contract,
            method,
            arg,
        } => format!(
            "call-contract contract={} method={} arg={arg}",
            hex::encode(contract),
            truncate_text(&String::from_utf8_lossy(method), 64)
        ),
        Op::SysCallStake { validator, amount } => {
            format!("stake validator={} amount={amount}", hex::encode(validator))
        }
        Op::SysCallUnbond { validator, amount } => format!(
            "unbond validator={} amount={amount}",
            hex::encode(validator)
        ),
        Op::SysCallDelegate { validator, amount } => format!(
            "delegate validator={} amount={amount}",
            hex::encode(validator)
        ),
        Op::SysCallUndelegate { validator } => {
            format!("undelegate validator={}", hex::encode(validator))
        }
        Op::SysCallClaimRewards { validator } => {
            format!("claim-rewards validator={}", hex::encode(validator))
        }
        Op::Halt => "halt".to_string(),
        Op::SysCallSubmitPriceFeed(_) => "submit-price-feed".to_string(),
        // PQ price feed (appended variant): indexed label only, no byte
        // blobs echoed (publisher key/signature render as lengths elsewhere).
        Op::SysCallSubmitPqPriceFeed(_) => "submit-pq-price-feed".to_string(),
        Op::SysCallRevokeSession { session_pubkey } => {
            format!("revoke-session key={}", hex::encode(session_pubkey))
        }
        Op::SysCallPmmBuy { usdt_micro } => format!("pmm-buy usdt_micro={usdt_micro}"),
        Op::SysCallPmmSell { stell_nano } => format!("pmm-sell stell_nano={stell_nano}"),
        Op::SysCallPublishSessionGrant(_) => "publish-session-grant".to_string(),
        Op::SysCallBridge(_) => "bridge-intent".to_string(),
        Op::SysCallActorSend {
            recipient,
            value,
            body,
            bounce,
            gas_budget,
        } => format!(
            "actor-send to={} value={value} ops={} bounce={bounce} gas_budget={gas_budget}",
            hex::encode(recipient),
            body.len()
        ),
        Op::SysCallVerifyZkMlReexec { model_id, .. } => {
            format!("verify-zkml-reexec model={}", hex::encode(model_id))
        }
        Op::SysCallRegisterZkMlModel { model_id, .. } => {
            format!("register-zkml-model model={}", hex::encode(model_id))
        }
        Op::SysCallRegisterZkMlSpec { model_id, .. } => {
            format!("register-zkml-spec model={}", hex::encode(model_id))
        }
        Op::SysCallVerifyZkMlAttestation { model_id, .. } => {
            format!("verify-zkml-attestation model={}", hex::encode(model_id))
        }
        Op::SysCallTokenCreate {
            name,
            symbol,
            decimals,
            initial_supply,
            max_supply,
        } => format!(
            "token-create {}({}) decimals={decimals} supply={initial_supply} max={}",
            truncate_text(name, 64),
            truncate_text(symbol, 64),
            max_supply
                .map(|m| m.to_string())
                .unwrap_or_else(|| "none".to_string())
        ),
        Op::SysCallRotateValidatorKey {
            old_validator,
            new_validator,
        } => format!(
            "rotate-validator-key old={} new={}",
            hex::encode(old_validator),
            hex::encode(new_validator)
        ),
        Op::SysCallBeginUndelegate { validator, amount } => format!(
            "begin-undelegate validator={} amount={amount}",
            hex::encode(validator)
        ),
        Op::SysCallClaimDelegatorRewards { validator } => format!(
            "claim-delegator-rewards validator={}",
            hex::encode(validator)
        ),
        Op::SysCallVerifyPqSignature {
            scheme_id,
            pubkey,
            message,
            signature,
        } => format!(
            "verify-pq-signature scheme={scheme_id} pubkey_bytes={} msg_bytes={} sig_bytes={}",
            pubkey.len(),
            message.len(),
            signature.len()
        ),
        Op::SysCallWithdrawSelfBond { validator } => {
            format!("withdraw-self-bond validator={}", hex::encode(validator))
        }
        Op::SysCallReportEquivocation { .. } => "report-equivocation".to_string(),
        Op::SysCallReportPqEquivocation { .. } => "report-pq-equivocation".to_string(),
        Op::SysCallCallContractArgs {
            contract,
            method,
            args,
            calldata,
        } => format!(
            "call-contract-args contract={} method={} args={} calldata_bytes={}",
            hex::encode(contract),
            truncate_text(&String::from_utf8_lossy(method), 64),
            args.len(),
            calldata.len()
        ),
        Op::SysCallReportProposalEquivocation { .. } => "report-proposal-equivocation".to_string(),
        Op::SysCallStakeWithCommission {
            validator,
            amount,
            commission_bps,
        } => format!(
            "stake-with-commission validator={} amount={amount} commission_bps={commission_bps}",
            hex::encode(validator)
        ),
        // Block-carried governance (appended OpCode variants): indexed labels
        // only, same bounded-text rule as every arm above (title truncated,
        // no byte blobs echoed). Required for exhaustiveness: the variants
        // were appended at the enum end, so this match must name them.
        Op::SysCallGovPropose {
            proposal_id, title, ..
        } => format!(
            "gov-propose id={proposal_id} title={}",
            truncate_text(title, 64)
        ),
        Op::SysCallGovVote {
            proposal_id,
            choice,
            ..
        } => format!("gov-vote id={proposal_id} choice={choice:?}"),
        Op::SysCallUnjail { validator } => {
            format!("unjail validator={}", hex::encode(validator))
        }
        // EVM write path (appended at the enum end): the carrier's EVM intent is
        // summarised by its sender + digest (never the raw bytes), and the
        // binding claim by the EVM address it binds — both bounded, indexed data.
        Op::SysCallEvmCarrier(carrier) => format!(
            "evm-carrier from=0x{} evm={} bytes digest=0x{}",
            hex::encode(carrier.evm_address),
            carrier.evm_tx.len(),
            hex::encode(crate::evm_adapter::evm_intent_digest(&carrier.evm_tx)),
        ),
        Op::SysCallBindEvmAddress(claim) => format!(
            "evm-bind evm=0x{} pq-key={} bytes",
            hex::encode(claim.evm_address),
            claim.pq_pubkey.len(),
        ),
        // W3 PQ validator lifecycle opcodes (59..=64, appended at enum end):
        // bounded indexed labels only, never raw pubkey/PoP byte blobs.
        Op::SysCallRegisterValidator(p) => format!(
            "register-validator withdrawal={} amount={} commission_bps={}",
            hex::encode(p.withdrawal_address),
            p.amount,
            p.commission_bps,
        ),
        Op::SysCallRotateVotingKey(p) => format!(
            "rotate-voting-key validator={} seq={} cancel={}",
            hex::encode(p.validator_id),
            p.rotation_seq,
            p.cancel,
        ),
        Op::SysCallChangeWithdrawal(p) => format!(
            "change-withdrawal validator={} new_withdrawal={}",
            hex::encode(p.validator_id),
            hex::encode(p.new_withdrawal_address),
        ),
        Op::SysCallClaimWithdrawal(p) => format!(
            "claim-withdrawal validator={} withdrawal={}",
            hex::encode(p.validator_id),
            hex::encode(p.withdrawal_address),
        ),
        Op::SysCallAnnounceCommission { validator, new_bps } => format!(
            "announce-commission validator={} new_bps={new_bps}",
            hex::encode(validator),
        ),
        Op::SysCallApplyCommission { validator } => {
            format!("apply-commission validator={}", hex::encode(validator),)
        }
        Op::Reserved33ConfidentialTransfer(_)
        | Op::Reserved40ConfidentialTransfer2(_)
        | Op::Reserved41ConfidentialShield(_)
        | Op::Reserved42ConfidentialUnshield(_) => "reserved-removed-confidential".to_string(),
    }
}

/// First `MAX_TXDETAIL_INTENT_OPS` intent labels plus whether the payload
/// held more (bounded summary, never a full program dump).
fn capped_intent_ops(payload: &[crate::svm::OpCode]) -> (Vec<String>, bool) {
    let truncated = payload.len() > MAX_TXDETAIL_INTENT_OPS;
    let rows = payload
        .iter()
        .take(MAX_TXDETAIL_INTENT_OPS)
        .map(describe_intent_op)
        .collect();
    (rows, truncated)
}

/// First `MAX_TXDETAIL_EVENTS` receipt events plus whether more were indexed.
fn capped_tx_events(events: &[crate::contract::ContractEvent]) -> (Vec<serde_json::Value>, bool) {
    let truncated = events.len() > MAX_TXDETAIL_EVENTS;
    let rows = events
        .iter()
        .take(MAX_TXDETAIL_EVENTS)
        .map(|e| {
            json!({
                "contract": hex::encode(e.contract),
                "topic": e.topic,
                "value": e.value,
            })
        })
        .collect();
    (rows, truncated)
}

/// `GET /api/tx-detail/:hash` — human transaction detail.
///
/// Same indexed sources as `GET /api/tx/:hash` (mempool body + finalized
/// receipts, no new pipeline) with a stable human shape: status, parties,
/// fees, decoded intent. `memo` is always `null`: the node indexes no memo
/// bytes, and a view must say so instead of inventing one. `intent` reuses
/// `describe_transaction`; `intent_ops` is the
/// first [`MAX_TXDETAIL_INTENT_OPS`] per-op labels; receipt events are capped
/// at [`MAX_TXDETAIL_EVENTS`].
///
/// The pending-body redaction of `/api/tx/:hash` applies unchanged:
/// unauthenticated callers see `tx_hash`/`nonce`/`status` only, never the
/// pre-finalization payload. Unknown hashes are 404 `{"status":"unknown"}`;
/// malformed hashes are 400. Nothing is fabricated.
async fn api_tx_detail(
    State(st): State<Arc<GatewayState>>,
    AxumPath(hash_hex): AxumPath<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let s = hash_hex.strip_prefix("0x").unwrap_or(&hash_hex);
    if s.len() != 64 {
        return (StatusCode::BAD_REQUEST, "bad tx hash").into_response();
    }
    let Ok(raw) = hex::decode(s) else {
        return (StatusCode::BAD_REQUEST, "bad tx hash").into_response();
    };
    let Ok(hash): Result<[u8; 32], _> = raw.try_into() else {
        return (StatusCode::BAD_REQUEST, "bad tx hash").into_response();
    };
    let body = st.rpc.mempool.read().await.get(&hash).cloned();
    let receipt = st.rpc.receipts.read().await.get(&hash).cloned();
    // No body: receipt-only when finalized, else fail closed.
    let Some(tx) = body else {
        if let Some(r) = receipt {
            let (events, events_truncated) = capped_tx_events(&r.events);
            return Json(json!({
                "tx_hash": hex::encode(r.tx_hash),
                "status": if r.success { "success" } else { "failed" },
                "height": r.height,
                "block_hash": hex::encode(r.block_hash),
                "index": r.index,
                "sender": null,
                "recipient": null,
                "amount": null,
                "nonce": null,
                "gas_limit": r.gas_limit.to_string(),
                "fee_charged": r.fee_charged.to_string(),
                "priority_fee_per_gas": null,
                "source_shard": null,
                "target_shard": null,
                "memo": null,
                "intent": null,
                "intent_summary": "receipt-only",
                "intent_ops": Vec::<String>::new(),
                "intent_ops_truncated": false,
                "payload_ops": null,
                "return_value": r.return_value,
                "gas_used": r.gas_used,
                "contract_address": r.contract_address.map(hex::encode),
                "events": events,
                "events_truncated": events_truncated,
            }))
            .into_response();
        }
        return (StatusCode::NOT_FOUND, Json(json!({ "status": "unknown" }))).into_response();
    };
    // Body present: finalized receipts are public; pending bodies keep the
    // `/api/tx/:hash` redaction (same token check, same fail-closed default
    // when no auth token is configured).
    let authed = match configured_secret(st.rpc.auth_token.as_deref()) {
        None => receipt.is_some(),
        Some(expected) => {
            if receipt.is_some() {
                true
            } else {
                let provided = query
                    .get("token")
                    .or_else(|| query.get("apiKey"))
                    .map(|v| v.as_str())
                    .or_else(|| extract_header_token(&headers));
                provided
                    .map(|p| constant_time_eq(p, expected))
                    .unwrap_or(false)
            }
        }
    };
    if !authed {
        return Json(json!({
            "tx_hash": hex::encode(hash),
            "nonce": tx.nonce,
            "status": "pending",
        }))
        .into_response();
    }
    let intent = describe_transaction(&tx);
    let (intent_ops, intent_ops_truncated) = capped_intent_ops(&tx.payload);
    let intent_summary = if tx.payload.is_empty() {
        "value-transfer".to_string()
    } else {
        describe_intent_op(&tx.payload[0])
    };
    let (
        status,
        height,
        block_hash,
        index,
        fee_charged,
        return_value,
        gas_used,
        contract_address,
        events,
    ) = match receipt {
        Some(r) => (
            if r.success { "success" } else { "failed" },
            Some(r.height),
            Some(hex::encode(r.block_hash)),
            Some(r.index),
            Some(r.fee_charged.to_string()),
            r.return_value,
            r.gas_used,
            r.contract_address.map(hex::encode),
            r.events,
        ),
        None => (
            "pending",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Vec::new(),
        ),
    };
    let (events, events_truncated) = capped_tx_events(&events);
    Json(json!({
        "tx_hash": hex::encode(hash),
        "status": status,
        "height": height,
        "block_hash": block_hash,
        "index": index,
        "sender": hex::encode(tx.from),
        "recipient": hex::encode(tx.to),
        "amount": tx.amount.to_string(),
        "nonce": tx.nonce,
        "gas_limit": tx.gas_limit.to_string(),
        "fee_charged": fee_charged,
        "priority_fee_per_gas": tx.priority_fee_per_gas.to_string(),
        "source_shard": tx.source_shard,
        "target_shard": tx.target_shard,
        "memo": null,
        "intent": intent,
        "intent_summary": intent_summary,
        "intent_ops": intent_ops,
        "intent_ops_truncated": intent_ops_truncated,
        "payload_ops": tx.payload.len(),
        "return_value": return_value,
        "gas_used": gas_used,
        "contract_address": contract_address,
        "events": events,
        "events_truncated": events_truncated,
    }))
    .into_response()
}

/// `GET /api/block-detail/:query` — human block detail.
///
/// `query` is a decimal height (`14`) or a 64-hex block hash (optional `0x`
/// prefix). The `recent_blocks` window supplies height/hash/txs/timestamp;
/// the finalized-header window adds proposer/round/QC summary (matched by
/// height AND hash, so a same-height mismatch enriches nothing); the receipt
/// index supplies tx refs at that height (capped at [`MAX_BLOCKDETAIL_TXS`]).
/// Finality latency is the timestamp delta to the greatest lower height in
/// the window (`null` when this node holds no predecessor). Unknown
/// heights/hashes are 404 `{"status":"unknown"}`; malformed input is 400.
/// Read-only, bounded, never fabricated.
async fn api_block_detail(
    State(st): State<Arc<GatewayState>>,
    AxumPath(query): AxumPath<String>,
) -> Response {
    enum Key {
        Height(u64),
        Hash([u8; 32]),
    }
    let key = match query.parse::<u64>() {
        Ok(h) => Key::Height(h),
        Err(_) => {
            let s = query.strip_prefix("0x").unwrap_or(&query);
            if s.len() != 64 {
                return (StatusCode::BAD_REQUEST, "bad block height or hash").into_response();
            }
            let Ok(raw) = hex::decode(s) else {
                return (StatusCode::BAD_REQUEST, "bad block height or hash").into_response();
            };
            let Ok(h): Result<[u8; 32], _> = raw.try_into() else {
                return (StatusCode::BAD_REQUEST, "bad block height or hash").into_response();
            };
            Key::Hash(h)
        }
    };
    let rows: Vec<crate::rpc::BlockSummary> =
        st.rpc.recent_blocks.read().await.iter().cloned().collect();
    let row = match &key {
        Key::Height(h) => rows.iter().find(|b| b.height == *h).cloned(),
        Key::Hash(h) => {
            let hx = hex::encode(h);
            rows.iter()
                .find(|b| b.hash.eq_ignore_ascii_case(&hx))
                .cloned()
        }
    };
    let Some(row) = row else {
        return (StatusCode::NOT_FOUND, Json(json!({ "status": "unknown" }))).into_response();
    };
    let header = crate::rpc::finalized_headers()
        .read()
        .await
        .iter()
        .find(|r| {
            r.height == row.height && hex::encode(r.block_hash).eq_ignore_ascii_case(&row.hash)
        })
        .cloned();
    let latency = rows
        .iter()
        .filter(|b| b.height < row.height)
        .max_by_key(|b| b.height)
        .map(|prev| row.timestamp.saturating_sub(prev.timestamp));
    let (refs_total, refs_capped, refs_truncated) = {
        let idx = st.rpc.receipts.read().await;
        let mut all: Vec<([u8; 32], u32)> = idx
            .for_height(row.height)
            .iter()
            .map(|r| (r.tx_hash, r.index))
            .collect();
        all.sort_by_key(|(_, i)| *i);
        let total = all.len();
        let truncated = total > MAX_BLOCKDETAIL_TXS;
        let capped: Vec<String> = all
            .into_iter()
            .take(MAX_BLOCKDETAIL_TXS)
            .map(|(h, _)| hex::encode(h))
            .collect();
        (total, capped, truncated)
    };
    let (proposer, round, qc) = match header {
        Some(h) => {
            let n = h.cert.signatures.len();
            let keys_truncated = n > MAX_BLOCKDETAIL_QC_KEYS;
            let keys: Vec<String> = h
                .cert
                .signatures
                .iter()
                .take(MAX_BLOCKDETAIL_QC_KEYS)
                .map(|(v, _)| hex::encode(v))
                .collect();
            (
                Some(hex::encode(h.proposer)),
                Some(h.cert.round),
                Some(json!({
                    "kind": format!("{:?}", h.cert.kind),
                    "signatures": n,
                    "keys": keys,
                    "keys_truncated": keys_truncated,
                })),
            )
        }
        None => (None, None, None),
    };
    Json(json!({
        "height": row.height,
        "hash": row.hash,
        "timestamp": row.timestamp,
        "tx_count": row.tx_count,
        "proposer": proposer,
        "round": round,
        "qc": qc,
        "finality_latency_secs": latency,
        "tx_refs": refs_capped,
        "tx_refs_total": refs_total,
        "tx_refs_truncated": refs_truncated,
    }))
    .into_response()
}

/// Data-dir scan with its own TTL. Returns `(bytes, snapshot_files)`, each
/// either observed or `null` with a reason. The scan is capped by
/// [`DATA_DIR_SCAN_FILE_CAP`] and runs off the async worker thread.
async fn data_dir_health(st: &GatewayState, now_ms: u64) -> (Measured<u64>, Measured<u64>) {
    let Some(dir) = st.health_options.data_dir.clone() else {
        return (
            Measured::missing("bytes", "data-dir scan disabled"),
            Measured::missing("files", "data-dir scan disabled"),
        );
    };
    {
        let cache = st
            .health_data_dir_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some((at, (bytes, snaps))) = *cache {
            if now_ms.saturating_sub(at) < HEALTH_DATA_DIR_CACHE_TTL_MS {
                return (
                    Measured::observed(bytes, "bytes"),
                    Measured::observed(snaps, "files"),
                );
            }
        }
    }
    // One cold scan at a time; the first waiter fills the cache and the rest
    // re-check it instead of walking the directory again.
    let _scan_gate = st.health_data_dir_scan_gate.lock().await;
    {
        let cache = st
            .health_data_dir_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some((at, (bytes, snaps))) = *cache {
            if now_ms.saturating_sub(at) < HEALTH_DATA_DIR_CACHE_TTL_MS {
                return (
                    Measured::observed(bytes, "bytes"),
                    Measured::observed(snaps, "files"),
                );
            }
        }
    }
    if !dir.is_dir() {
        return (
            Measured::missing("bytes", "configured data directory does not exist"),
            Measured::missing("files", "configured data directory does not exist"),
        );
    }
    let scan_dir = dir.clone();
    match tokio::task::spawn_blocking(move || data_dir_stats(&scan_dir)).await {
        Ok((bytes, snaps)) => {
            *st.health_data_dir_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = Some((now_ms, (bytes, snaps)));
            (
                Measured::observed(bytes, "bytes"),
                Measured::observed(snaps, "files"),
            )
        }
        Err(_) => (
            Measured::missing("bytes", "data-dir scan task failed"),
            Measured::missing("files", "data-dir scan task failed"),
        ),
    }
}

/// Collect one health sample at `now_ms`. All values are read from this
/// process's existing observability handles; nothing is invented and no chain
/// walk is performed. The only potentially expensive step (data-dir metadata)
/// has its own longer cache in [`GatewayState`].
pub async fn collect_health(st: &GatewayState, now_ms: u64) -> HealthPayload {
    let now_secs = now_ms / 1000;
    let height = st.rpc.height.load(std::sync::atomic::Ordering::Relaxed);
    // One lock for both pool readings: size and the oldest admission stamp.
    // The age read is a pure timestamp scan, never a transaction-content walk.
    let (mempool_size, mempool_oldest_age) = {
        let pool = st.rpc.mempool.read().await;
        (pool.len(), pool.oldest_pending_age_secs(now_secs))
    };

    // Recent finalized blocks; timestamps here are the FINALIZE wall-clock
    // (`RpcState::record_block` stores `now_secs()`), which is what health ages
    // need. Bounded by MAX_RECENT_BLOCKS.
    let recent: Vec<(u64, u64)> = {
        let rb = st.rpc.recent_blocks.read().await;
        rb.iter().map(|b| (b.height, b.timestamp)).collect()
    };

    // Latest quorum-certified header: gives us the last finalized round.
    let latest_header = {
        let store = crate::rpc::finalized_headers();
        let hs = store.read().await;
        hs.front().map(|h| (h.height, h.cert.round))
    };

    let last_finalize_age = recent
        .iter()
        .map(|(_, ts)| *ts)
        .filter(|ts| *ts > 0)
        .max()
        .map(|ts| now_secs.saturating_sub(ts));
    let network_tip = crate::rpc::fresh_peer_height();
    let finalization_lag_blocks = network_tip.map(|tip| tip.saturating_sub(height));

    let blocks_per_second = {
        let window = HEALTH_BLOCK_RATE_WINDOW_SECS;
        let mut times: Vec<u64> = recent
            .iter()
            .map(|(_, ts)| *ts)
            .filter(|ts| *ts > 0 && now_secs.saturating_sub(*ts) <= window)
            .collect();
        times.sort_unstable();
        let samples = times.len();
        if samples >= 2 {
            let span = times[samples - 1].saturating_sub(times[0]);
            if span > 0 {
                BlockRate {
                    value: Some((samples - 1) as f64 / span as f64),
                    unit: "blocks/second",
                    window_seconds: window,
                    samples,
                    reason: None,
                }
            } else {
                BlockRate {
                    value: None,
                    unit: "blocks/second",
                    window_seconds: window,
                    samples,
                    reason: Some("all sampled finalizations share a timestamp".to_string()),
                }
            }
        } else {
            BlockRate {
                value: None,
                unit: "blocks/second",
                window_seconds: window,
                samples,
                reason: Some(format!(
                    "need at least two finalizations in the last {window} s"
                )),
            }
        }
    };

    // Snapshot metadata comes from the durable store when it is attached.
    let (snap_height, snap_ts, snap_reason) = match &st.rpc.archive_store {
        None => (
            None,
            None,
            Some("archive_store not attached (no durable storage on this node)".to_string()),
        ),
        Some(store) => {
            let store = store.clone();
            match tokio::task::spawn_blocking(move || match store.latest_state_height() {
                Ok(Some(h)) => {
                    let ts = store
                        .header_at(h)
                        .ok()
                        .flatten()
                        .map(|record| record.timestamp);
                    (Some(h), ts, None)
                }
                Ok(None) => (None, None, Some("no state snapshot stored".to_string())),
                Err(e) => (
                    None,
                    None,
                    Some(format!("snapshot height read failed: {e}")),
                ),
            })
            .await
            {
                Ok(v) => v,
                Err(_) => (None, None, Some("snapshot read task failed".to_string())),
            }
        }
    };
    let snapshot_height = measured_u64(
        snap_height,
        "blocks",
        snap_reason.as_deref().unwrap_or("no state snapshot stored"),
    );
    let snapshot_lag = match (snap_height, height) {
        (Some(snap), h) if h >= snap => Some(h - snap),
        _ => None,
    };
    let snapshot_age = match (snap_height, snap_ts) {
        (Some(_), Some(ts)) if ts > 0 => Some(now_secs.saturating_sub(ts)),
        _ => None,
    };
    let snapshot_block_reason = if snap_height.is_none() {
        snap_reason
            .as_deref()
            .unwrap_or("no state snapshot stored")
            .to_string()
    } else {
        "snapshot block header not retained; storage does not expose snapshot write time"
            .to_string()
    };

    let (data_dir_bytes, snapshot_files) = data_dir_health(st, now_ms).await;
    let metrics = st.metrics.snapshot();
    // Producer-less phase-1 counters: `None` until a phase-2 writer records
    // the first event. Never substitute 0 — an operator cannot distinguish
    // "measured zero" from "nobody writes this" otherwise.
    let health_counters = crate::metrics::snapshot_health_counters();
    let last_persist_age = health_counters
        .last_persist_ms
        .map(|ms| now_ms.saturating_sub(ms) / 1000);
    // Prefer the writer's stamp when it exists (true write age); the stored
    // block timestamp remains the fallback for nodes without that writer.
    let snapshot_age = health_counters
        .last_snapshot_ms
        .map(|ms| now_ms.saturating_sub(ms) / 1000)
        .or(snapshot_age);
    let shards: Vec<u64> = st.rpc.shard_registry.ids().map(u64::from).collect();
    let software = SoftwareHealth {
        version: crate::metrics::BUILD_VERSION,
        git_hash: crate::metrics::build_hash_resolved(),
        dirty: crate::metrics::build_dirty_resolved(),
        string: format!(
            "stellereum/{} ({}{})",
            crate::metrics::BUILD_VERSION,
            crate::metrics::build_hash_resolved(),
            match crate::metrics::build_dirty_resolved().as_str() {
                "true" => ", dirty",
                _ => "",
            }
        ),
    };

    let mut payload = HealthPayload {
        schema: "stellereum.health.v1",
        sampled_at_ms: now_ms,
        served_at_ms: now_ms,
        cache: HealthCacheInfo {
            ttl_ms: st.health_options.cache_ttl_ms,
            hit: false,
            age_ms: 0,
        },
        identity: IdentityHealth {
            chain_id: st.rpc.chain_id,
            protocol_major: crate::protocol::PROTOCOL_MAJOR,
            protocol_minor: crate::protocol::PROTOCOL_MINOR,
            fork_id: crate::protocol::FORK_ID,
            node_id: st.rpc.node_id.clone(),
            shards: Measured::observed(shards, "shard ids"),
            software,
            timestamp_ms: now_ms,
        },
        chain: ChainHealth {
            height: Measured::observed(height, "blocks"),
            finalized_height: measured_u64(
                (height > 0).then_some(height),
                "blocks",
                "no finalized block yet (height 0)",
            ),
            network_tip_height: measured_u64(
                network_tip,
                "blocks",
                "no fresh verified peer tip",
            ),
            finalization_lag: FinalizationLag {
                blocks: measured_u64(
                    finalization_lag_blocks,
                    "blocks",
                    "no fresh verified peer tip to compare against",
                ),
                seconds: measured_u64(
                    last_finalize_age,
                    "seconds",
                    "no finalized block observed",
                ),
                timestamp_ms: now_ms,
            },
            blocks_per_second,
            last_finalize_age: measured_u64(
                last_finalize_age,
                "seconds",
                "no finalized block observed",
            ),
            timestamp_ms: now_ms,
        },
        consensus: ConsensusHealth {
            // The registry seeds round at 0 and has no producer today. A
            // positive value is real; 0 is not reported as "the round" because
            // it cannot be distinguished from the unset default.
            round: if metrics.round > 0.0 {
                Measured::observed(metrics.round as u64, "round")
            } else {
                Measured::missing(
                    "round",
                    "no consensus round observed (Registry::set_round has no producer)",
                )
            },
            last_finalized_round: measured_u64(
                latest_header.map(|(_, round)| u64::from(round)),
                "round",
                "no finalized header retained",
            ),
            view_changes_last_5m: Measured::missing(
                "view changes",
                "cumulative counter exists but no 5-minute window is wired yet; see docs/OBSERVABILITY.md (Phase 2 wiring)",
            ),
            rejected_proposals_total: measured_u64(
                health_counters.rejected_proposals_total,
                "proposals",
                "no rejected proposal has been recorded yet (no producer has written the counter)",
            ),
            forks_total: Measured::observed(metrics.forks as u64, "events"),
            divergences_total: Measured::observed(metrics.divergences as u64, "events"),
            catch_up: CatchUpHealth {
                mode: Measured::missing(
                    "mode",
                    "catch-up mode lives in driver-local state; export policy::CatchupAction at src/node/consensus_driver.rs:1596",
                ),
                last_catch_up_age: Measured::missing(
                    "seconds",
                    "no last-catch-up timestamp; record it where catchup_action is applied",
                ),
            },
            timestamp_ms: now_ms,
        },
        p2p: P2pHealth {
            peer_count: Measured::observed(crate::rpc::observed_peer_count(), "peers")
                .with_source("rpc::LIVE_PEER_COUNT (0 = none observed)"),
            peer_states: Measured::missing(
                "peers",
                "per-peer live/suspected/cooldown state is driver-local; export the peer_health map (src/consensus_net.rs:707) or ValidatorMesh snapshot (src/network.rs:729)",
            ),
            mesh: MeshHealth {
                members: Measured::missing(
                    "members",
                    "ValidatorMesh state is not process-global; export members()/direct_targets() as a snapshot",
                ),
                direct_targets: Measured::missing(
                    "targets",
                    "ValidatorMesh state is not process-global; export direct_targets() as a snapshot",
                ),
                last_delivery: Measured::missing(
                    "outcome",
                    "last MeshDelivery is not recorded globally; store the latest result at src/consensus_net.rs:1722",
                ),
            },
            bytes: P2pBytesHealth {
                inbound_total: measured_u64(
                    health_counters.bytes_inbound_total,
                    "bytes",
                    "no inbound consensus bytes recorded yet (no producer has written the counter)",
                ),
                outbound_total: measured_u64(
                    health_counters.bytes_outbound_total,
                    "bytes",
                    "no outbound consensus bytes recorded yet (no producer has written the counter)",
                ),
            },
            timestamp_ms: now_ms,
        },
        mempool: MempoolHealth {
            size: Measured::observed(mempool_size as u64, "transactions"),
            oldest_pending_age: measured_u64(
                mempool_oldest_age,
                "seconds",
                "mempool is empty (no pending transaction to age)",
            ),
            timestamp_ms: now_ms,
        },
        storage: StorageHealth {
            data_dir_bytes,
            snapshot_files,
            last_persist_age: measured_u64(
                last_persist_age,
                "seconds",
                "no successful persist recorded yet (no producer has written the counter)",
            ),
            snapshot: SnapshotHealth {
                height: snapshot_height,
                lag_blocks: measured_u64(
                    snapshot_lag,
                    "blocks",
                    "snapshot height unavailable",
                ),
                age_secs: measured_u64(snapshot_age, "seconds", &snapshot_block_reason),
            },
            timestamp_ms: now_ms,
        },
        verdict: HealthVerdict {
            status: HealthStatus::Ok,
            reasons: Vec::new(),
            unknown: Vec::new(),
        },
    };

    // Verdict is a PURE function of the values the payload reports. Build the
    // fact set from the payload itself so the two can never disagree.
    let facts = HealthFacts {
        height: payload.chain.height.as_ref().copied(),
        finalization_lag_blocks: payload.chain.finalization_lag.blocks.as_ref().copied(),
        finalization_lag_secs: payload.chain.finalization_lag.seconds.as_ref().copied(),
        last_finalize_age_secs: payload.chain.last_finalize_age.as_ref().copied(),
        peer_count: payload.p2p.peer_count.as_ref().copied(),
        mempool_size: payload.mempool.size.as_ref().copied(),
        mempool_oldest_age_secs: payload.mempool.oldest_pending_age.as_ref().copied(),
        last_persist_age_secs: payload.storage.last_persist_age.as_ref().copied(),
        snapshot_age_secs: payload.storage.snapshot.age_secs.as_ref().copied(),
        consensus_round: payload.consensus.round.as_ref().copied(),
        view_changes_last_5m: payload.consensus.view_changes_last_5m.as_ref().copied(),
        rejected_proposals_total: payload.consensus.rejected_proposals_total.as_ref().copied(),
        catch_up_mode: payload.consensus.catch_up.mode.value.clone(),
    };
    payload.verdict = evaluate_verdict(&facts, &st.health_options.thresholds);
    payload
}

/// Serve one sample, honoring the short TTL cache.
async fn health_current(st: &GatewayState) -> HealthPayload {
    let now = now_ms();
    let ttl = st.health_options.cache_ttl_ms;
    if let Some(mut payload) = st.health_cache.lookup(now, ttl) {
        payload.served_at_ms = now;
        payload.cache.hit = true;
        payload.cache.age_ms = now.saturating_sub(payload.sampled_at_ms);
        return payload;
    }
    let mut payload = collect_health(st, now).await;
    payload.served_at_ms = now;
    payload.cache.hit = false;
    payload.cache.age_ms = 0;
    st.health_cache.store(now, payload.clone());
    payload
}

/// `GET /health` — the operator-facing health payload. Always HTTP 200: the
/// verdict (not the status code) says whether the node is healthy, so a
/// dashboard can distinguish "endpoint unreachable" from "node unhealthy".
async fn health(State(st): State<Arc<GatewayState>>) -> (HeaderMap, Json<HealthPayload>) {
    let mut headers = HeaderMap::new();
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("cache-control", "no-store".parse().unwrap());
    (headers, Json(health_current(&st).await))
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Summary scalars parsed from [`crate::metrics::Registry::render`] for
/// [`status_page`].
#[derive(Clone, Debug, Default, PartialEq)]
pub struct MetricsStatusSummary {
    pub validator_efficiency_ratio: Option<f64>,
    pub block_interval_sum_secs: Option<f64>,
    pub block_interval_count: Option<u64>,
}

/// Extract `stell_validator_efficiency_ratio` and `stell_block_interval_seconds`
/// (`_sum` / `_count`) from Prometheus exposition text.
pub fn parse_metrics_status_summary(rendered: &str) -> MetricsStatusSummary {
    let mut out = MetricsStatusSummary::default();
    for line in rendered.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let Some(name) = parts.next() else {
            continue;
        };
        let Some(val) = parts.next() else {
            continue;
        };
        match name {
            n if n == crate::metrics::VALIDATOR_EFFICIENCY_RATIO => {
                out.validator_efficiency_ratio = val.parse::<f64>().ok();
            }
            "stell_block_interval_seconds_sum" => {
                out.block_interval_sum_secs = val.parse::<f64>().ok();
            }
            "stell_block_interval_seconds_count" => {
                out.block_interval_count = val.parse::<u64>().ok();
            }
            _ => {}
        }
    }
    out
}

async fn status_page(State(st): State<Arc<GatewayState>>) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("cache-control", "no-store".parse().unwrap());
    if !st.telemetry_enabled || no_telemetry_enabled() {
        return (
            StatusCode::NOT_FOUND,
            headers,
            Html("status page disabled (STELL_NO_TELEMETRY=1)".to_string()),
        )
            .into_response();
    }
    let p = health_current(&st).await;
    let ready_rep = st.readiness.evaluate();
    let ready_html = if ready_rep.ready {
        "ready".to_string()
    } else if ready_rep.failed_checks.is_empty() {
        "not ready".to_string()
    } else {
        format!(
            "not ready ({})",
            html_escape(&ready_rep.failed_checks.join(", "))
        )
    };
    let metrics_summary = parse_metrics_status_summary(&st.metrics.render());
    let efficiency_html = match metrics_summary.validator_efficiency_ratio {
        Some(r) => format!("{:.1}% ({r:.4})", r * 100.0),
        None => "n/a".to_string(),
    };
    let block_interval_html = match (
        metrics_summary.block_interval_sum_secs,
        metrics_summary.block_interval_count,
    ) {
        (Some(sum), Some(count)) if count > 0 => {
            format!("{:.3} s avg ({count} blocks)", sum / count as f64)
        }
        (Some(_), Some(0)) => "n/a (0 blocks observed)".to_string(),
        _ => "n/a".to_string(),
    };
    let status = match p.verdict.status {
        HealthStatus::Ok => "ok",
        HealthStatus::Degraded => "degraded",
        HealthStatus::Critical => "critical",
    };
    let reasons = if p.verdict.reasons.is_empty() {
        "<li>none</li>".to_string()
    } else {
        p.verdict
            .reasons
            .iter()
            .map(|r| format!("<li>{}</li>", html_escape(r)))
            .collect::<Vec<_>>()
            .join("")
    };
    let fmt_u64 = |m: &Measured<u64>| match m.value {
        Some(v) => format!("{v} {}", m.unit),
        None => format!(
            "n/a ({})",
            html_escape(m.reason.as_deref().unwrap_or("unavailable"))
        ),
    };
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>stellereum status</title>\
         <style>body{{font:14px/1.4 system-ui,sans-serif;margin:2rem;max-width:60rem}}\
         .ok{{color:#087f23}}.degraded{{color:#9a6700}}.critical{{color:#b42318}}\
         table{{border-collapse:collapse}}td,th{{padding:.25rem .6rem;text-align:left;border-bottom:1px solid #ddd}}\
         code{{background:#f4f4f4;padding:0 .2rem}}</style></head><body>\
         <h1>stellereum status: <span class=\"{status}\">{status}</span></h1>\
         <p>sampled <code>{sampled}</code> ms &middot; served <code>{served}</code> ms &middot; cache {cache}</p>\
         <h2>reasons</h2><ul>{reasons}</ul>\
         <h2>node</h2><table>\
         <tr><th>chain id</th><td>{chain_id}</td></tr>\
         <tr><th>node id</th><td><code>{node_id}</code></td></tr>\
         <tr><th>software</th><td>{software}</td></tr>\
         <tr><th>ready (/readyz)</th><td>{ready_html}</td></tr>\
         <tr><th>height</th><td>{height}</td></tr>\
         <tr><th>finalized height</th><td>{finalized}</td></tr>\
         <tr><th>finalization lag</th><td>{lag_s} / {lag_b}</td></tr>\
         <tr><th>blocks/s</th><td>{rate}</td></tr>\
         <tr><th>block interval</th><td>{block_interval_html}</td></tr>\
         <tr><th>validator efficiency</th><td>{efficiency_html}</td></tr>\
         <tr><th>last finalize age</th><td>{last_fin}</td></tr>\
         <tr><th>peers</th><td>{peers}</td></tr>\
         <tr><th>mempool</th><td>{mempool}</td></tr>\
         <tr><th>data dir</th><td>{disk}</td></tr>\
         </table>\
         <p><a href=\"/health\">/health</a> &middot; <a href=\"/readyz\">/readyz</a> &middot; <a href=\"/metrics\">/metrics</a></p>\
         </body></html>",
        sampled = p.sampled_at_ms,
        served = p.served_at_ms,
        cache = if p.cache.hit {
            format!("hit ({} ms old)", p.cache.age_ms)
        } else {
            "miss".to_string()
        },
        chain_id = p.identity.chain_id,
        node_id = html_escape(&p.identity.node_id),
        software = html_escape(&p.identity.software.string),
        height = fmt_u64(&p.chain.height),
        finalized = fmt_u64(&p.chain.finalized_height),
        lag_s = fmt_u64(&p.chain.finalization_lag.seconds),
        lag_b = fmt_u64(&p.chain.finalization_lag.blocks),
        last_fin = fmt_u64(&p.chain.last_finalize_age),
        rate = match p.chain.blocks_per_second.value {
            Some(v) => format!(
                "{v:.3} blocks/s over {} s ({} samples)",
                p.chain.blocks_per_second.window_seconds,
                p.chain.blocks_per_second.samples
            ),
            None => format!(
                "n/a ({})",
                html_escape(
                    p.chain
                        .blocks_per_second
                        .reason
                        .as_deref()
                        .unwrap_or("unavailable")
                )
            ),
        },
        peers = fmt_u64(&p.p2p.peer_count),
        mempool = fmt_u64(&p.mempool.size),
        disk = fmt_u64(&p.storage.data_dir_bytes),
    );
    (headers, Html(body)).into_response()
}

/// Liveness probe: the process is up and answering HTTP. Deliberately cheap —
/// no locks, no state reads — so a wedged subsystem cannot fail it. Use
/// `/readyz` to ask whether the node is actually useful.
async fn healthz() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::OK,
        Json(json!({ "status": "ok", "service": "stellereum-gateway" })),
    )
}

/// Readiness probe: 200 when the node has finalized recently, holds peers and
/// its height is advancing; 503 with a JSON body naming WHICH condition
/// failed (`failed_checks`: `no_peers`, `no_finality`, `finality_stalled`,
/// `height_zero`, `height_stalled`).
async fn readyz(State(st): State<Arc<GatewayState>>) -> (StatusCode, Json<serde_json::Value>) {
    let rep = st.readiness.evaluate();
    let code = if rep.ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        code,
        Json(json!({
            "ready": rep.ready,
            "failed_checks": rep.failed_checks,
            "height": rep.height,
            "peers": rep.peers,
            "secs_since_finalized": rep.secs_since_finalized,
            "max_stall_secs": rep.max_stall_secs,
            "min_peers": rep.min_peers,
        })),
    )
}

/// Render a scrape for the gateway.
///
/// The consensus [`Registry`](crate::metrics::Registry) is the primary source:
/// it owns the whole consensus story (round, height, vote counters, fork
/// counter, block/tx histograms, latency) plus the disk/state/validator
/// observability families (`stell_data_dir_bytes`, `stell_snapshot_count`,
/// `stell_state_entries`, `stell_persist_queue_*`, `stell_peer_round_lag`,
/// `stell_validator_power_total`, `stell_validator_quorum_power`,
/// `stell_validator_set_fragile`, `stell_build_info`), and is written to by
/// the consensus driver through the same process-wide `Arc`. The four
/// explorer-local gauges are folded in on top:
///
///  * `height` and `mempool` are also pushed into the registry, so a caller
///    reading `stell_consensus_height` / `stell_mempool_size` sees them.
///  * `contracts` and `tokens` have no family in the consensus registry, so
///    they are appended below in the same exposition format (one HELP/TYPE
///    pair each, LF-terminated) under their existing public names.
///  * The disk/validator/state values the gateway *can* see (staking ledger,
///    account map, data-dir scan, build identity) are pushed into the registry
///    by the `/metrics` handler before rendering; families with no producer
///    yet (persist queue, per-peer round lag) keep their pre-seeded zeros so
///    a scrape is stable until wiring lands — see the NOTE on their setters.
///
/// Splitting it into a free function keeps the HTTP handler a thin adapter and
/// makes the exact bytes a scrape produces testable without spinning up an
/// `RpcState` or a server.
pub fn render_metrics(
    registry: &crate::metrics::Registry,
    height: u64,
    mempool: usize,
    contracts: usize,
    tokens: usize,
) -> String {
    // Legacy entry point: no readiness input, so `stell_ready` reports 0
    // (fail-closed: unknown counts as not ready). Handlers that know the
    // readiness use `render_metrics_with_readiness`.
    render_metrics_with_readiness(registry, height, mempool, contracts, tokens, false)
}

/// Like [`render_metrics`], but carries the gateway readiness as the
/// `stell_ready` gauge (1 = ready to serve, 0 = not ready), mirroring
/// `/readyz`. The gauge is appended here — next to the other explorer-local
/// gauges — rather than registered in the consensus [`Registry`], because it
/// describes the gateway's view of the node, not consensus internals.
pub fn render_metrics_with_readiness(
    registry: &crate::metrics::Registry,
    height: u64,
    mempool: usize,
    contracts: usize,
    tokens: usize,
    ready: bool,
) -> String {
    registry.set_height(height);
    registry.set_mempool_size(mempool as u64);

    let mut out = registry.render();
    let ready_int = if ready { 1 } else { 0 };
    out.push_str(&format!(
        "# HELP stellereum_block_height Current finalized block height\n\
         # TYPE stellereum_block_height gauge\n\
         stellereum_block_height {height}\n\
         # HELP stellereum_mempool_size Pending transactions in mempool\n\
         # TYPE stellereum_mempool_size gauge\n\
         stellereum_mempool_size {mempool}\n\
         # HELP stellereum_contracts_total Deployed WASM smart contracts count\n\
         # TYPE stellereum_contracts_total gauge\n\
         stellereum_contracts_total {contracts}\n\
         # HELP stellereum_tokens_total Fungible STS tokens count\n\
         # TYPE stellereum_tokens_total gauge\n\
         stellereum_tokens_total {tokens}\n\
         # HELP stell_ready Node readiness for serving traffic (1 = ready, 0 = not ready)\n\
         # TYPE stell_ready gauge\n\
         stell_ready {ready_int}\n"
    ));
    out
}

/// Env var overriding the data directory scanned for the disk gauges.
pub const DATA_DIR_ENV: &str = "STELL_DATA_DIR";
/// Cap on directory entries visited per scrape: bounds scrape latency when the
/// data dir grows (archive default is unbounded — see the disk-risk note).
const DATA_DIR_SCAN_FILE_CAP: usize = 100_000;

/// Data directory scanned for the disk gauges (`STELL_DATA_DIR`, else `./data`).
pub fn data_dir_path() -> std::path::PathBuf {
    std::env::var(DATA_DIR_ENV)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("./data"))
}

/// Best-effort `(bytes, snapshot_files)` under `dir`.
///
/// Never fails a scrape: unreadable entries are skipped, symlinks are not
/// followed, traversal is capped, and a missing dir reads as `(0, 0)`.
/// `snapshot_files` counts files whose name contains `snapshot` — an estimate
/// for dashboards, not the sled tree count.
pub fn data_dir_stats(dir: &std::path::Path) -> (u64, u64) {
    let mut bytes = 0u64;
    let mut snaps = 0u64;
    let mut visited = 0usize;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(path) = stack.pop() {
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.is_symlink() {
            continue;
        }
        if meta.is_dir() {
            let Ok(entries) = std::fs::read_dir(&path) else {
                continue;
            };
            for entry in entries.flatten() {
                if visited >= DATA_DIR_SCAN_FILE_CAP {
                    return (bytes, snaps);
                }
                visited += 1;
                stack.push(entry.path());
            }
        } else if meta.is_file() {
            bytes = bytes.saturating_add(meta.len());
            let is_snapshot = path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.contains("snapshot"))
                .unwrap_or(false);
            if is_snapshot {
                snaps = snaps.saturating_add(1);
            }
        }
    }
    (bytes, snaps)
}

/// `GET /api/version` — build identity of this binary.
///
/// Same values as the `stell_build_info` series in `/metrics`: crate version,
/// git hash (build-script `STELL_BUILD_HASH`, else runtime `git rev-parse`
/// fallback logged once, else `"unknown"`), and the dirty flag — plus the live
/// height and node id so a deploy record (`docs/handoff/LIVE_VERSIONS.txt`)
/// can be filled from one call.
async fn api_version(State(st): State<Arc<GatewayState>>) -> Json<serde_json::Value> {
    let mut v = crate::metrics::build_info_json();
    v["height"] = json!(st.rpc.height.load(std::sync::atomic::Ordering::Relaxed));
    v["node_id"] = json!(st.rpc.node_id.clone());
    Json(v)
}

async fn prometheus_metrics(
    State(st): State<Arc<GatewayState>>,
) -> (StatusCode, [(&'static str, &'static str); 1], String) {
    let height = st.rpc.height.load(std::sync::atomic::Ordering::Relaxed);
    let mempool = st.rpc.mempool.read().await.len();
    let contracts = st.rpc.engine.contract_count().await;
    let tokens = st.rpc.engine.tokens_read().await.token_count();
    // The SEALED / PLAIN split of the pool: how much of the traffic actually
    // takes the private (epoch-seal) path. A network whose sealed share is
    // zero is a network whose MEV protection protects nothing, so the split
    // is an operator-visible gauge, not a curiosity.
    {
        let pool = st.rpc.mempool.read().await;
        st.metrics
            .set_mempool_sealed_split(pool.sealed_count() as u64, pool.len() as u64);
    }
    // Validator-set story, same derivation as `stell_getValidators` (rpc.rs) so
    // the gauge can never disagree with RPC: size, power, quorum, fragile flag.
    {
        let ledger = st.rpc.engine.staking_read().await;
        let vs = ledger.to_validator_set();
        let fragile = ledger.quorum_fragility().is_some();
        st.metrics.set_validator_set_full(
            vs.len() as u64,
            vs.total_power(),
            vs.quorum_power(),
            fragile,
        );
    }
    // State-entries estimate: live accounts plus the two committed registries
    // that already have their own gauges above.
    {
        let accounts = st.rpc.engine.accounts.read().await.len() as u64;
        st.metrics.set_state_entries(
            accounts
                .saturating_add(contracts as u64)
                .saturating_add(tokens as u64),
        );
    }
    // Disk footprint: reuse the TTL-cached, single-flight `data_dir_health`
    // helper shared with `/health` so `/metrics` scrapes do not re-walk up to
    // `DATA_DIR_SCAN_FILE_CAP` files on every request.
    {
        let (bytes_m, snaps_m) = data_dir_health(&st, now_ms()).await;
        st.metrics.set_data_dir_bytes(bytes_m.value.unwrap_or(0));
        st.metrics.set_snapshot_count(snaps_m.value.unwrap_or(0));
    }
    // Build identity (runtime git fallback inside the resolver, logged once).
    // Persist-queue depth/dropped and per-peer round-lag have no producer yet
    // (see the NOTE on their setters): the registry keeps their last values,
    // pre-seeded at zero, so a scrape is stable until wiring lands.
    st.metrics.set_build_info(
        crate::metrics::BUILD_VERSION,
        &crate::metrics::build_hash_resolved(),
        &crate::metrics::build_dirty_resolved(),
    );
    let ready = st.readiness.evaluate().ready;
    let text =
        render_metrics_with_readiness(&st.metrics, height, mempool, contracts, tokens, ready);
    (
        StatusCode::OK,
        [("content-type", crate::metrics::CONTENT_TYPE)],
        text,
    )
}

async fn cors_middleware(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    headers.insert("access-control-allow-origin", "*".parse().unwrap());
    headers.insert(
        "access-control-allow-methods",
        "GET, POST, OPTIONS".parse().unwrap(),
    );
    headers.insert(
        "access-control-allow-headers",
        "content-type, authorization, x-requested-with, cf-turnstile-response, x-turnstile-token"
            .parse()
            .unwrap(),
    );
    resp
}

/// Build the gateway router (explorer UI + JSON API + JSON-RPC under /rpc).
pub fn router(gateway: Arc<GatewayState>) -> Router {
    // Rate limiting on `/rpc` uses a DEDICATED limiter instance (`rpc_limiter`,
    // separate from the explorer routes' `limiter` below): nesting after
    // `rate_limit` + `with_state` guarantees `/rpc` never hits `rate_limit`,
    // while mounting `/rpc` BEFORE the shared CORS + anti-slow-loris
    // `ServiceBuilder` puts `/rpc`, `/rpc/ws`, and `/rpc/events` under the
    // same `TimeoutLayer(30s)` and `ConcurrencyLimitLayer(512)` as the rest
    // of the gateway.
    let rpc_router = crate::rpc::router(gateway.rpc.clone()).layer(middleware::from_fn_with_state(
        gateway.clone(),
        nested_rpc_rate_limit,
    ));
    let explorer_routes = Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/status", get(status_page))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(prometheus_metrics))
        .route("/api/stats", get(api_stats))
        .route("/api/version", get(api_version))
        .route("/api/blocks", get(api_blocks))
        .route("/api/block-detail/:query", get(api_block_detail))
        .route("/api/balance/:address", get(api_balance))
        .route("/api/tx/:hash", get(api_tx))
        .route("/api/tx-detail/:hash", get(api_tx_detail))
        // State-changing on GET is a crawler/prefetch/CSRF footgun (audit
        // 2026-10-06): the faucet mints money, so it is POST-only. GET keeps
        // a 405 with a hint instead of silently minting.
        .route(
            "/api/faucet/:address",
            post(api_faucet).get(faucet_get_hint),
        )
        // Public testnet drip (TON-style, tokenless): POST-only, 5 STELL per
        // address per 45 minutes. Separate route so the token gate on the
        // operator faucet above is never weakened.
        .route(
            "/api/faucet-public/:address",
            post(api_faucet_public).get(faucet_get_hint),
        )
        .route("/api/spv/:address", get(api_spv))
        .route("/api/contracts", get(api_contracts))
        .route("/api/validator/:address", get(api_validator))
        .route("/api/finals", get(api_finals))
        .route("/api/account/:address", get(api_account))
        // SSE transport of the streaming subscriptions (`text/event-stream`).
        // The same handler the RPC server exposes on `/events`; mounted here
        // so a browser can `EventSource("/events")` against the public
        // gateway without going through the `/rpc` prefix. Idle streams are
        // reaped on the handler's configured window (SSE_IDLE_TIMEOUT_SECS /
        // STELL_SSE_IDLE_TIMEOUT_SECS), and concurrent streams are bounded by
        // `SSE_MAX_CONNECTIONS`, `SSE_MAX_CONNECTIONS_PER_CLIENT`, and
        // `MAX_ATTACHED_PER_SUB` via RAII guards released on stream drop.
        .route("/events", get(crate::rpc::sse_handler))
        .layer(middleware::from_fn_with_state(gateway.clone(), rate_limit))
        .with_state(gateway);

    explorer_routes
        .nest("/rpc", rpc_router)
        .layer(middleware::from_fn(cors_middleware))
        // Same anti-slow-loris layers as the standalone RPC (audit 2026-10-06),
        // covering both explorer routes and the nested `/rpc` mount.
        .layer(
            tower::ServiceBuilder::new()
                .layer(axum::error_handling::HandleErrorLayer::new(
                    |_: axum::BoxError| async { axum::http::StatusCode::REQUEST_TIMEOUT },
                ))
                .layer(tower::timeout::TimeoutLayer::new(
                    std::time::Duration::from_secs(30),
                ))
                .layer(tower::limit::ConcurrencyLimitLayer::new(512)),
        )
}

/// Serve the gateway with per-IP connect info for the rate limiter.
/// Process-wide readiness handle.
///
/// WHY A GLOBAL: the consensus driver is spawned BEFORE the explorer gateway
/// exists (bootstrap order), and threading an `Arc` through `run_consensus_node`
/// would touch every call site and test for no behavioural gain. The exporter is
/// process-wide already (`metrics::global`), so the readiness handle follows the
/// same shape. Unset until `serve()` installs it; the setters then become no-ops,
/// which is exactly the behaviour a process without an explorer wants.
static READINESS: std::sync::OnceLock<Arc<ReadinessState>> = std::sync::OnceLock::new();

/// Install the handle the consensus loop reports into (called by `serve`).
pub fn register_readiness(readiness: Arc<ReadinessState>) {
    let _ = READINESS.set(readiness);
}

/// Record a finalized block for `/readyz` and the `stell_ready` gauge.
///
/// No-op when no gateway is serving this process. P0-READINESS-DEAD: before
/// this existed, nothing produced the readiness state at all, so `/readyz`
/// reported 0 forever and any consumer (a load balancer) would drop a healthy
/// node.
pub fn note_readiness_finalized(height: u64) {
    if let Some(r) = READINESS.get() {
        r.note_finalized(height);
    }
}

/// Report the current connected-peer count for `/readyz`.
pub fn set_readiness_peers(peers: usize) {
    if let Some(r) = READINESS.get() {
        r.set_peers(peers);
    }
}

pub async fn serve(addr: &str, gateway: Arc<GatewayState>) -> anyhow::Result<()> {
    register_readiness(gateway.readiness.clone());
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        router(gateway).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_enforces_per_ip_window() {
        let rl = RateLimiter::new(2);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let t = 1_700_000_000u64;
        assert!(rl.check_at(ip, t));
        assert!(rl.check_at(ip, t));
        assert!(
            !rl.check_at(ip, t),
            "third request in the same second must be rejected"
        );
        // a different IP has its own bucket
        assert!(rl.check_at("5.6.7.8".parse().unwrap(), t));
        // next second resets the window
        assert!(rl.check_at(ip, t + 1));
    }

    #[test]
    fn parse_addr_validates_length() {
        assert!(parse_addr("0x00").is_none());
        let good = hex::encode([9u8; 32]);
        assert_eq!(parse_addr(&good), Some([9u8; 32]));
        assert_eq!(parse_addr(&format!("0x{good}")), Some([9u8; 32]));
    }

    #[test]
    fn parse_metrics_status_summary_extracts_efficiency_and_interval() {
        let reg = crate::metrics::Registry::new();
        reg.inc_validator_proposal_expected();
        reg.inc_validator_proposal_produced();
        reg.inc_validator_proposal_expected();
        reg.observe_block_interval(0.25);
        reg.observe_block_interval(0.75);
        let summary = parse_metrics_status_summary(&reg.render());
        assert_eq!(summary.validator_efficiency_ratio, Some(0.5));
        assert_eq!(summary.block_interval_sum_secs, Some(1.0));
        assert_eq!(summary.block_interval_count, Some(2));
    }

    #[tokio::test]
    async fn status_page_enrichment_and_no_telemetry_flag() {
        let rpc = Arc::new(RpcState {
            engine: Arc::new(crate::state_engine::InMemoryStateEngine::new()),
            mempool: Arc::new(tokio::sync::RwLock::new(crate::mempool::Mempool::default())),
            height: Arc::new(std::sync::atomic::AtomicU64::new(5)),
            node_id: "inf1:status-test".to_string(),
            chain_id: 5757,
            staking: Arc::new(tokio::sync::RwLock::new(
                crate::staking::StakingLedger::new(),
            )),
            governance: Arc::new(tokio::sync::RwLock::new(
                crate::governance::Governance::new(),
            )),
            recent_blocks: Arc::new(tokio::sync::RwLock::new(std::collections::VecDeque::new())),
            receipts: Arc::new(tokio::sync::RwLock::new(crate::rpc::ReceiptIndex::default())),
            auth_token: None,
            tx_broadcast: None,
            faucet: None,
            faucet_token: None,
            archive_store: None,
            msg_signing_seed: None,
            shard_registry: crate::sharding::ShardRegistry::single(),
        });
        let reg = crate::metrics::Registry::shared();
        reg.observe_block_interval(0.4);
        reg.observe_block_interval(0.6);

        let mut gw = GatewayState::with_captcha(
            rpc.clone(),
            100,
            ReadinessConfig {
                max_stall_secs: 30,
                min_peers: 0,
            },
            Arc::new(crate::turnstile::CaptchaGate::disabled()),
        )
        .with_health_options(HealthOptions {
            data_dir: None,
            ..Default::default()
        })
        .with_telemetry_enabled(true);
        gw.metrics = reg.clone();
        gw.note_ready_finalized(5);
        let gw = Arc::new(gw);

        let resp = status_page(State(gw.clone())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("validator efficiency"), "{html}");
        assert!(html.contains("100.0%"), "{html}");
        assert!(html.contains("0.500 s avg (2 blocks)"), "{html}");
        assert!(html.contains("ready (/readyz)"), "{html}");
        assert!(html.contains(">ready<"), "{html}");

        // Disabled telemetry disables /status while keeping /health and /readyz alive.
        let gw_off = Arc::new(
            GatewayState::with_captcha(
                rpc,
                100,
                ReadinessConfig::default(),
                Arc::new(crate::turnstile::CaptchaGate::disabled()),
            )
            .with_telemetry_enabled(false),
        );
        let disabled_resp = status_page(State(gw_off.clone())).await;
        assert_eq!(disabled_resp.status(), StatusCode::NOT_FOUND);
        let (ready_code, _) = readyz(State(gw_off.clone())).await;
        assert_eq!(ready_code, StatusCode::SERVICE_UNAVAILABLE);
        let (health_headers, _) = health(State(gw_off)).await;
        assert!(health_headers.contains_key("cache-control"));
    }
}
