//! Metrics collection, rate control and the final report.
//!
//! Percentiles are nearest-rank-with-linear-interpolation over the measured
//! samples; every number in the report is derived from a counter or a sample
//! that this process observed, never from a claim in a doc.

use crate::rpc::RpcError;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq)]
pub struct Distribution {
    pub n: usize,
    pub min: f64,
    pub max: f64,
    pub mean: f64,
    pub p50: f64,
    pub p95: f64,
    pub p99: f64,
}

pub fn percentile_sorted(sorted: &[f64], q: f64) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }
    let q = q.clamp(0.0, 1.0);
    let pos = q * (sorted.len() - 1) as f64;
    let lo = pos.floor() as usize;
    let hi = pos.ceil() as usize;
    if lo == hi {
        Some(sorted[lo])
    } else {
        let w = pos - lo as f64;
        Some(sorted[lo] * (1.0 - w) + sorted[hi] * w)
    }
}

pub fn distribution(values: &[f64]) -> Option<Distribution> {
    if values.is_empty() {
        return None;
    }
    let mut v: Vec<f64> = values.iter().copied().filter(|x| x.is_finite()).collect();
    if v.is_empty() {
        return None;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let sum: f64 = v.iter().sum();
    Some(Distribution {
        n: v.len(),
        min: v[0],
        max: v[v.len() - 1],
        mean: sum / v.len() as f64,
        p50: percentile_sorted(&v, 0.50).unwrap_or(0.0),
        p95: percentile_sorted(&v, 0.95).unwrap_or(0.0),
        p99: percentile_sorted(&v, 0.99).unwrap_or(0.0),
    })
}

#[derive(Debug, Clone)]
pub struct BlockObs {
    pub height: u64,
    pub txs: Option<u64>,
    pub node_ts: Option<u64>,
    pub first_seen_ns: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct MempoolSample {
    pub at_ns: u64,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct SenderOutcome {
    pub index: u64,
    pub address: String,
    pub init_nonce: u64,
    pub next_nonce: u64,
    pub onchain_nonce_after: u64,
    pub accepted: u64,
    pub failed: u64,
    pub retries: u64,
    pub last_hash: Option<String>,
    pub stop_reason: Option<String>,
}

impl SenderOutcome {
    pub fn included(&self) -> u64 {
        self.onchain_nonce_after
            .saturating_sub(self.init_nonce)
            .min(self.accepted)
    }

    pub fn backlog(&self) -> u64 {
        self.accepted.saturating_sub(self.included())
    }
}

#[derive(Debug, Clone, Default)]
pub struct ReceiptSample {
    pub queried: u64,
    pub success: u64,
    pub failed: u64,
    pub unknown: u64,
    pub details: Vec<(String, String, Option<u64>)>,
}

pub struct Stats {
    pub submitted: AtomicU64,
    pub accepted: AtomicU64,
    pub failed: AtomicU64,
    pub duplicates: AtomicU64,
    pub retries: AtomicU64,
    pub http_429: AtomicU64,
    pub bad_signatures: AtomicU64,
    pub hash_mismatch: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub read_errors: AtomicU64,
    pub stalls: AtomicBool,
    pub lagged: AtomicBool,
    pub aborted: AtomicBool,
    pub send_end_ns: AtomicU64,
    pub initial_height: AtomicU64,
    pub final_height: AtomicU64,
    pub initial_nonce_sum: AtomicU64,
    pub base_fee: AtomicU64,
    pub watch_lag: AtomicU64,
    pub errors: Mutex<BTreeMap<String, u64>>,
    pub first_error: Mutex<Option<String>>,
    pub block_intervals: Mutex<Vec<(u64, f64)>>,
    pub blocks: Mutex<BTreeMap<u64, BlockObs>>,
    pub mempool: Mutex<Vec<MempoolSample>>,
    pub watch_heights: Mutex<BTreeMap<String, u64>>,
}

impl Stats {
    pub fn new(initial_height: u64, initial_nonce_sum: u64, base_fee: u64) -> Self {
        Self {
            submitted: AtomicU64::new(0),
            accepted: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            duplicates: AtomicU64::new(0),
            retries: AtomicU64::new(0),
            http_429: AtomicU64::new(0),
            bad_signatures: AtomicU64::new(0),
            hash_mismatch: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            read_errors: AtomicU64::new(0),
            stalls: AtomicBool::new(false),
            lagged: AtomicBool::new(false),
            aborted: AtomicBool::new(false),
            send_end_ns: AtomicU64::new(0),
            initial_height: AtomicU64::new(initial_height),
            final_height: AtomicU64::new(initial_height),
            initial_nonce_sum: AtomicU64::new(initial_nonce_sum),
            base_fee: AtomicU64::new(base_fee),
            watch_lag: AtomicU64::new(0),
            errors: Mutex::new(BTreeMap::new()),
            first_error: Mutex::new(None),
            block_intervals: Mutex::new(Vec::new()),
            blocks: Mutex::new(BTreeMap::new()),
            mempool: Mutex::new(Vec::new()),
            watch_heights: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn record_error(&self, err: &RpcError) {
        self.record_error_message(&err.message());
    }

    pub fn record_error_message(&self, message: &str) {
        let class = crate::rpc::classify_message(message);
        let mut map = self.errors.lock().unwrap_or_else(|e| e.into_inner());
        *map.entry(class).or_insert(0) += 1;
        drop(map);
        let mut first = self.first_error.lock().unwrap_or_else(|e| e.into_inner());
        if first.is_none() {
            *first = Some(message.to_string());
        }
    }

    pub fn add_interval(&self, at_ns: u64, seconds: f64) {
        if seconds.is_finite() && seconds >= 0.0 {
            self.block_intervals
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((at_ns, seconds));
        }
    }

    pub fn add_block(&self, obs: BlockObs) {
        let mut blocks = self.blocks.lock().unwrap_or_else(|e| e.into_inner());
        match blocks.get_mut(&obs.height) {
            Some(existing) => {
                if obs.txs.is_some() {
                    existing.txs = obs.txs;
                }
                if obs.node_ts.is_some() {
                    existing.node_ts = obs.node_ts;
                }
            }
            None => {
                blocks.insert(obs.height, obs);
            }
        }
    }

    pub fn add_mempool(&self, at_ns: u64, size: u64) {
        self.mempool
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(MempoolSample { at_ns, size });
    }

    pub fn add_watch_height(&self, url: &str, height: u64) {
        let mut map = self.watch_heights.lock().unwrap_or_else(|e| e.into_inner());
        map.insert(url.to_string(), height);
    }

    pub fn mempool_stats(&self) -> Option<(u64, u64, u64)> {
        let samples = self.mempool.lock().unwrap_or_else(|e| e.into_inner());
        if samples.is_empty() {
            return None;
        }
        let first = samples[0].size;
        let last = samples[samples.len() - 1].size;
        let peak = samples.iter().map(|s| s.size).max().unwrap_or(0);
        Some((first, peak, last))
    }

    /// True when the mempool has stayed above `size` for `window_secs`.
    pub fn backlog_sustained(&self, size: u64, window_secs: u64) -> bool {
        if size == 0 || window_secs == 0 {
            return false;
        }
        let samples = self.mempool.lock().unwrap_or_else(|e| e.into_inner());
        let Some(last) = samples.last() else {
            return false;
        };
        let cutoff_ns = last
            .at_ns
            .saturating_sub(window_secs.saturating_mul(1_000_000_000));
        let window: Vec<&MempoolSample> = samples.iter().filter(|s| s.at_ns >= cutoff_ns).collect();
        if window.len() < 2 {
            return false;
        }
        let span_ns = window
            .last()
            .map(|s| s.at_ns)
            .unwrap_or(0)
            .saturating_sub(window.first().map(|s| s.at_ns).unwrap_or(0));
        if span_ns < window_secs.saturating_mul(1_000_000_000) / 2 {
            return false;
        }
        window.iter().all(|s| s.size >= size)
    }
}

#[derive(Debug)]
pub struct RunMeta {
    pub live: bool,
    pub endpoints: Vec<String>,
    pub watch_urls: Vec<String>,
    pub chain_id: u64,
    pub senders: usize,
    pub target_rate: f64,
    pub requested_duration: f64,
    pub actual_duration: f64,
    pub initial_height: u64,
    pub final_height: u64,
    pub base_fee: u64,
    pub pq_mode: String,
    pub validator_count: usize,
    pub stall_seconds: u64,
    pub max_lag_blocks: u64,
    pub started_unix: u64,
    /// Optional Prometheus scrape: (mean block interval seconds, sample count).
    pub metrics_block_interval: Option<(f64, u64)>,
}

pub struct Report {
    pub text: String,
    pub json: Value,
    pub exit_code: i32,
}

fn fmt(v: f64, decimals: usize) -> String {
    format!("{v:.decimals$}")
}

fn dist_line(label: &str, d: Option<&Distribution>, unit: &str, decimals: usize) -> String {
    match d {
        None => format!("{label}: no samples"),
        Some(d) => format!(
            "{label}: n={} min={} p50={} p95={} p99={} max={} mean={}{}",
            d.n,
            fmt(d.min, decimals),
            fmt(d.p50, decimals),
            fmt(d.p95, decimals),
            fmt(d.p99, decimals),
            fmt(d.max, decimals),
            fmt(d.mean, decimals),
            unit
        ),
    }
}

fn dist_json(d: Option<&Distribution>) -> Value {
    match d {
        None => Value::Null,
        Some(d) => json!({
            "n": d.n,
            "min": d.min,
            "p50": d.p50,
            "p95": d.p95,
            "p99": d.p99,
            "max": d.max,
            "mean": d.mean,
        }),
    }
}

pub fn build_report(
    meta: &RunMeta,
    stats: &Stats,
    outcomes: &[SenderOutcome],
    receipts: &ReceiptSample,
    fail_ratio: f64,
) -> Report {
    let accepted = stats.accepted.load(Ordering::Relaxed);
    let failed = stats.failed.load(Ordering::Relaxed);
    let submitted = stats.submitted.load(Ordering::Relaxed);
    let duplicates = stats.duplicates.load(Ordering::Relaxed);
    let retries = stats.retries.load(Ordering::Relaxed);
    let http_429 = stats.http_429.load(Ordering::Relaxed);
    let bytes_sent = stats.bytes_sent.load(Ordering::Relaxed);
    let unresolved = submitted.saturating_sub(accepted.saturating_add(failed));
    let included: u64 = outcomes.iter().map(SenderOutcome::included).sum();
    let backlog: u64 = outcomes.iter().map(SenderOutcome::backlog).sum();
    let duration = meta.actual_duration.max(0.001);
    let accepted_tps = accepted as f64 / duration;
    let included_tps = included as f64 / duration;

    let send_end_ns = stats.send_end_ns.load(Ordering::Relaxed);
    let window_end = if send_end_ns == 0 {
        u64::MAX
    } else {
        send_end_ns
    };

    let interval_values: Vec<f64> = {
        let iv = stats
            .block_intervals
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        iv.iter()
            .filter(|(at, _)| *at <= window_end)
            .map(|(_, s)| *s)
            .collect()
    };
    let block_time = distribution(&interval_values);

    let blocks: Vec<BlockObs> = {
        let b = stats.blocks.lock().unwrap_or_else(|e| e.into_inner());
        b.values().cloned().collect()
    };
    let measured_blocks: Vec<&BlockObs> = blocks
        .iter()
        .filter(|b| b.height > meta.initial_height && b.first_seen_ns <= window_end)
        .collect();
    let tx_per_block_values: Vec<f64> = measured_blocks
        .iter()
        .filter_map(|b| b.txs.map(|t| t as f64))
        .collect();
    let tx_per_block = distribution(&tx_per_block_values);
    let zero_tx_blocks = tx_per_block_values.iter().filter(|v| **v == 0.0).count();
    let total_txs_in_blocks: u64 = measured_blocks.iter().filter_map(|b| b.txs).sum();

    // The node's own report: timestamps are whole seconds, so this is a coarse
    // cross-check, not a replacement for the observed arrival intervals.
    let mut node_diffs = Vec::new();
    let mut node_zero = 0u64;
    for w in blocks.windows(2) {
        if w[1].height == w[0].height + 1 {
            if let (Some(a), Some(b)) = (w[0].node_ts, w[1].node_ts) {
                if b >= a {
                    if b == a {
                        node_zero += 1;
                    } else {
                        node_diffs.push((b - a) as f64);
                    }
                }
            }
        }
    }
    let node_interval = distribution(&node_diffs);

    let mempool = stats.mempool_stats();
    let final_height = meta.final_height;
    let watch_lag = stats.watch_lag.load(Ordering::Relaxed);
    let stall = stats.stalls.load(Ordering::Relaxed);
    let lagged = stats.lagged.load(Ordering::Relaxed);
    let aborted = stats.aborted.load(Ordering::Relaxed);

    let rejected_share = if accepted + failed == 0 {
        0.0
    } else {
        failed as f64 / (accepted + failed) as f64
    };

    let verdict = if aborted || stall || lagged {
        "ABORTED"
    } else if rejected_share > fail_ratio || backlog > 0 || unresolved > 0 {
        "FAIL"
    } else {
        "PASS"
    };
    let exit_code = match verdict {
        "PASS" => 0,
        "FAIL" => 1,
        _ => 4,
    };

    let errors: Vec<(String, u64)> = {
        let map = stats.errors.lock().unwrap_or_else(|e| e.into_inner());
        map.iter().map(|(k, v)| (k.clone(), *v)).collect()
    };
    let first_error = stats
        .first_error
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();

    let mut text = String::with_capacity(4096);
    let _ = writeln!(text, "=== Stellereum load-test report ===");
    let _ = writeln!(
        text,
        "mode: {}   verdict: {}   exit: {}",
        if meta.live { "LIVE" } else { "DRY-RUN" },
        verdict,
        exit_code
    );
    let _ = writeln!(text, "endpoints: {}", meta.endpoints.join(", "));
    if meta.watch_urls != meta.endpoints {
        let _ = writeln!(text, "watch:     {}", meta.watch_urls.join(", "));
    }
    let _ = writeln!(
        text,
        "chain_id: {}   validators: {}   pq_mode: {}",
        meta.chain_id, meta.validator_count, meta.pq_mode
    );
    let _ = writeln!(
        text,
        "senders: {}   target: {} tx/s   requested window: {} s   actual send window: {} s",
        meta.senders,
        fmt(meta.target_rate, 2),
        fmt(meta.requested_duration, 1),
        fmt(meta.actual_duration, 3)
    );
    let _ = writeln!(
        text,
        "base_fee: {} gas   height: {} -> {} (+{})   mempool: {}",
        meta.base_fee,
        meta.initial_height,
        final_height,
        final_height.saturating_sub(meta.initial_height),
        match mempool {
            Some((a, p, b)) => format!("start={a} peak={p} end={b}"),
            None => "unavailable".to_string(),
        }
    );
    let _ = writeln!(text);
    let _ = writeln!(text, "submitted (unique signed txs): {submitted}");
    let _ = writeln!(
        text,
        "accepted: {accepted}   failed: {failed}   duplicates: {duplicates}   retries: {retries}   429s: {http_429}   unresolved: {unresolved}"
    );
    let _ = writeln!(
        text,
        "achieved accepted rate: {} tx/s",
        fmt(accepted_tps, 2)
    );
    let _ = writeln!(
        text,
        "included (on-chain nonce delta): {included}   included rate: {} tx/s   backlog after drain: {backlog}",
        fmt(included_tps, 2)
    );
    let _ = writeln!(
        text,
        "wire bytes sent: {bytes_sent}   rejected share: {}%",
        fmt(rejected_share * 100.0, 3)
    );
    if meta.live {
        let _ = writeln!(
            text,
            "receipt sample: queried={} success={} failed={} unknown={}",
            receipts.queried, receipts.success, receipts.failed, receipts.unknown
        );
        for (hash, status, height) in &receipts.details {
            let _ = writeln!(
                text,
                "  {hash}  {status}  height={}",
                height
                    .map(|h| h.to_string())
                    .unwrap_or_else(|| "-".to_string())
            );
        }
    }
    let _ = writeln!(text);
    let _ = writeln!(
        text,
        "{}",
        dist_line("block time observed (s)", block_time.as_ref(), " s", 3)
    );
    let _ = writeln!(
        text,
        "{}",
        dist_line("tx per block", tx_per_block.as_ref(), "", 2)
    );
    let _ = writeln!(
        text,
        "blocks counted: {}   zero-tx: {}   txs in counted blocks: {}",
        measured_blocks.len(),
        zero_tx_blocks,
        total_txs_in_blocks
    );
    match &node_interval {
        Some(d) => {
            let _ = writeln!(
                text,
                "node-reported interval (1 s timestamps): positive n={} zero-diff n={} mean={} s p50={} s",
                d.n,
                node_zero,
                fmt(d.mean, 3),
                fmt(d.p50, 3)
            );
        }
        None => {
            let _ = writeln!(
                text,
                "node-reported interval (1 s timestamps): unavailable ({} zero-diff pairs)",
                node_zero
            );
        }
    }
    if let Some((mean, count)) = meta.metrics_block_interval {
        let _ = writeln!(
            text,
            "node metrics interval: mean={} s over {} samples (stell_block_interval_seconds)",
            fmt(mean, 3),
            count
        );
    }
    if watch_lag > 0 {
        let _ = writeln!(
            text,
            "watch height spread: {watch_lag} blocks (stop threshold {})",
            if meta.max_lag_blocks == 0 {
                "disabled".to_string()
            } else {
                meta.max_lag_blocks.to_string()
            }
        );
    }
    if stall {
        let _ = writeln!(
            text,
            "STOP CONDITION: chain stall (no new block for >= {} s)",
            meta.stall_seconds
        );
    }
    if lagged {
        let _ = writeln!(
            text,
            "STOP CONDITION: watch endpoint lag > {} blocks",
            meta.max_lag_blocks
        );
    }
    if !errors.is_empty() {
        let _ = writeln!(text);
        let _ = writeln!(text, "error classes:");
        for (class, n) in &errors {
            let _ = writeln!(text, "  {class}: {n}");
        }
        if let Some(e) = &first_error {
            let _ = writeln!(text, "first error: {e}");
        }
    }
    let stopped: Vec<&SenderOutcome> = outcomes
        .iter()
        .filter(|o| o.stop_reason.is_some())
        .collect();
    if !stopped.is_empty() {
        let _ = writeln!(text);
        let _ = writeln!(
            text,
            "senders stopped early: {} of {}",
            stopped.len(),
            outcomes.len()
        );
        for o in stopped.iter().take(20) {
            let _ = writeln!(
                text,
                "  sender[{}] {} accepted={} failed={} reason={}",
                o.index,
                o.address,
                o.accepted,
                o.failed,
                o.stop_reason.as_deref().unwrap_or("-")
            );
        }
    }
    let _ = writeln!(text);
    let _ = writeln!(
        text,
        "{}",
        match verdict {
            "PASS" => "PASS: the wave met its acceptance and drain targets.",
            "FAIL" => "FAIL: rejections or an un-drained backlog exceeded the target; inspect the report and runbook stop conditions.",
            _ => "ABORTED: a stop condition fired; do not raise the rate until the cause is understood.",
        }
    );

    let sender_json: Vec<Value> = outcomes
        .iter()
        .map(|o| {
            json!({
                "index": o.index,
                "address": o.address,
                "init_nonce": o.init_nonce,
                "next_nonce": o.next_nonce,
                "onchain_nonce_after": o.onchain_nonce_after,
                "accepted": o.accepted,
                "failed": o.failed,
                "included": o.included(),
                "backlog": o.backlog(),
                "retries": o.retries,
                "last_hash": o.last_hash,
                "stop_reason": o.stop_reason,
            })
        })
        .collect();
    let errors_json: BTreeMap<String, u64> = errors.iter().cloned().collect();
    let json = json!({
        "mode": if meta.live { "live" } else { "dry-run" },
        "verdict": verdict,
        "exit_code": exit_code,
        "endpoints": meta.endpoints,
        "watch_urls": meta.watch_urls,
        "chain_id": meta.chain_id,
        "validators": meta.validator_count,
        "pq_mode": meta.pq_mode,
        "senders": meta.senders,
        "target_rate": meta.target_rate,
        "requested_duration_s": meta.requested_duration,
        "actual_duration_s": meta.actual_duration,
        "base_fee": meta.base_fee,
        "initial_nonce_sum": stats.initial_nonce_sum.load(Ordering::Relaxed),
        "stats_initial_height": stats.initial_height.load(Ordering::Relaxed),
        "height": {
            "start": meta.initial_height,
            "end": final_height,
            "delta": final_height.saturating_sub(meta.initial_height),
        },
        "counts": {
            "submitted": submitted,
            "accepted": accepted,
            "failed": failed,
            "duplicates": duplicates,
            "retries": retries,
            "http_429": http_429,
            "unresolved": unresolved,
            "bad_signatures": stats.bad_signatures.load(Ordering::Relaxed),
            "hash_mismatch": stats.hash_mismatch.load(Ordering::Relaxed),
            "wire_bytes": bytes_sent,
            "read_errors": stats.read_errors.load(Ordering::Relaxed),
        },
        "rates": {
            "accepted_tps": accepted_tps,
            "included_tps": included_tps,
            "rejected_share": rejected_share,
        },
        "included": included,
        "backlog": backlog,
        "receipt_sample": {
            "queried": receipts.queried,
            "success": receipts.success,
            "failed": receipts.failed,
            "unknown": receipts.unknown,
        },
        "block_time_s": dist_json(block_time.as_ref()),
        "node_block_interval_s": dist_json(node_interval.as_ref()),
        "node_zero_diff_pairs": node_zero,
        "node_metrics_block_interval_s": match meta.metrics_block_interval {
            Some((mean, count)) => json!({"mean": mean, "count": count}),
            None => Value::Null,
        },
        "tx_per_block": dist_json(tx_per_block.as_ref()),
        "blocks_counted": measured_blocks.len(),
        "zero_tx_blocks": zero_tx_blocks,
        "txs_in_counted_blocks": total_txs_in_blocks,
        "mempool": match mempool {
            Some((start, peak, end)) => json!({"start": start, "peak": peak, "end": end}),
            None => Value::Null,
        },
        "watch_height_spread": watch_lag,
        "stop_conditions": {
            "chain_stall": stall,
            "node_lag": lagged,
            "aborted": aborted,
        },
        "errors": errors_json,
        "first_error": first_error,
        "senders_detail": sender_json,
        "started_unix": meta.started_unix,
    });

    Report {
        text,
        json,
        exit_code,
    }
}

/// Token bucket shared by every sender. `capacity` of 1.0 means no burst: the
/// instantaneous rate can never exceed `rate`.
pub struct RateGate {
    rate: f64,
    capacity: f64,
    state: Mutex<GateState>,
}

struct GateState {
    tokens: f64,
    last: Instant,
}

impl RateGate {
    pub fn new(rate: f64, capacity: f64) -> Self {
        Self {
            rate,
            capacity: capacity.max(1.0),
            state: Mutex::new(GateState {
                tokens: capacity.max(1.0),
                last: Instant::now(),
            }),
        }
    }

    /// Acquire one permit, or return false when the deadline/stop arrives
    /// first. The wait is capped at 50 ms so stop conditions are polled often.
    pub fn acquire(&self, deadline: Option<Instant>, stop: &AtomicBool) -> bool {
        loop {
            let wait = {
                let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
                let now = Instant::now();
                let elapsed = now.duration_since(st.last).as_secs_f64();
                st.tokens = (st.tokens + elapsed * self.rate).min(self.capacity);
                st.last = now;
                if st.tokens >= 1.0 {
                    st.tokens -= 1.0;
                    return true;
                }
                (1.0 - st.tokens) / self.rate
            };
            if stop.load(Ordering::Relaxed) {
                return false;
            }
            if let Some(d) = deadline {
                let now = Instant::now();
                if now >= d {
                    return false;
                }
                let remaining = d.saturating_duration_since(now).as_secs_f64();
                if wait > remaining {
                    return false;
                }
            }
            std::thread::sleep(Duration::from_secs_f64(wait.clamp(0.001, 0.05)));
        }
    }
}

/// Bounded concurrent requests. Senders hold a permit only while the HTTP
/// request is in flight (including same-bytes retries), never while waiting for
/// a nonce window or for inclusion.
pub struct Inflight {
    max: usize,
    state: Mutex<usize>,
    cv: Condvar,
}

impl Inflight {
    pub fn new(max: usize) -> Self {
        Self {
            max: max.max(1),
            state: Mutex::new(0),
            cv: Condvar::new(),
        }
    }

    pub fn acquire(&self, stop: &AtomicBool) -> bool {
        let mut n = self.state.lock().unwrap_or_else(|e| e.into_inner());
        while *n >= self.max {
            if stop.load(Ordering::Relaxed) {
                return false;
            }
            let (guard, _timeout) = self
                .cv
                .wait_timeout(n, Duration::from_millis(100))
                .unwrap_or_else(|e| e.into_inner());
            n = guard;
        }
        if stop.load(Ordering::Relaxed) {
            return false;
        }
        *n += 1;
        true
    }

    pub fn release(&self) {
        let mut n = self.state.lock().unwrap_or_else(|e| e.into_inner());
        *n = n.saturating_sub(1);
        drop(n);
        self.cv.notify_one();
    }

    #[allow(dead_code)] // GATE: read by the unit test that pins the semaphore invariant.
    pub fn current(&self) -> usize {
        *self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_interpolates_and_handles_edges() {
        let v = [1.0, 2.0, 3.0, 4.0, 5.0];
        assert_eq!(percentile_sorted(&v, 0.0), Some(1.0));
        assert_eq!(percentile_sorted(&v, 1.0), Some(5.0));
        assert_eq!(percentile_sorted(&v, 0.5), Some(3.0));
        assert_eq!(percentile_sorted(&[], 0.5), None);
        let d = distribution(&v).unwrap();
        assert_eq!(d.n, 5);
        assert_eq!(d.mean, 3.0);
        assert_eq!(d.p50, 3.0);
    }

    #[test]
    fn distribution_ignores_non_finite() {
        let d = distribution(&[1.0, f64::NAN, 3.0]).unwrap();
        assert_eq!(d.n, 2);
        assert_eq!(d.mean, 2.0);
    }

    #[test]
    fn sender_outcome_accounts_for_backlog() {
        let o = SenderOutcome {
            index: 0,
            address: "0x00".into(),
            init_nonce: 10,
            next_nonce: 14,
            onchain_nonce_after: 12,
            accepted: 4,
            failed: 0,
            retries: 0,
            last_hash: None,
            stop_reason: None,
        };
        assert_eq!(o.included(), 2);
        assert_eq!(o.backlog(), 2);
    }

    #[test]
    fn rate_gate_never_exceeds_capacity_in_a_short_window() {
        let gate = RateGate::new(100.0, 1.0);
        let stop = AtomicBool::new(false);
        let start = Instant::now();
        for _ in 0..10 {
            assert!(gate.acquire(None, &stop));
        }
        // 10 permits at 100/s with capacity 1 cannot complete instantly.
        assert!(start.elapsed() >= Duration::from_millis(80));
    }

    #[test]
    fn inflight_caps_and_releases() {
        let inflight = Inflight::new(1);
        let stop = AtomicBool::new(false);
        assert!(inflight.acquire(&stop));
        assert_eq!(inflight.current(), 1);
        inflight.release();
        assert_eq!(inflight.current(), 0);
    }
}
