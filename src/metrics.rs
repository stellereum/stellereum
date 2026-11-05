//! Prometheus exposition-format metrics for the consensus engine.
//!
//! Hand-rolled on purpose. The `prometheus` crate is deliberately NOT a
//! dependency: this node already ships a hand-written rate limiter in
//! `explorer` and a hand-written block explorer page, and the same reasoning
//! applies here — a metrics endpoint is a scraped, public, untrusted-input
//! surface, and the amount of format we need (gauge, counter, histogram with
//! buckets) is small enough that owning it outright is cheaper than the
//! dependency and the global-registry ergonomics that come with it.
//!
//! What this buys us, and what it costs, is spelled out in the design notes on
//! [`Registry`]. The short version:
//!
//!  - Text format only (no protobuf negotiation). `CONTENT_TYPE` below is the
//!    only content type we advertise.
//!  - The metric *set* is fixed at construction. This node exports one
//!    well-defined consensus story; a runtime-registered metric family would
//!    only widen the surface a hostile peer can influence.
//!  - Labels are rendered in a deterministic order and every value is
//!    sanitised, because a scrape is parsed by machines and diffed by humans.
//!
//! Wiring (the HTTP layer stays in `explorer`): build a [`Registry`], share it
//! as `Arc<Registry>` with the consensus driver, call the setters from the
//! consensus paths, and serve [`Registry::render`] under the existing
//! `/metrics` route with [`CONTENT_TYPE`].
//!
//! EXPOSURE ENUMERATION (audit 2026-10-14 F10 — what a scrape contains, exactly):
//!
//! * Consensus story: `stell_consensus_round`, `stell_consensus_height`,
//!   `stell_block_interval_seconds{histogram}`, `stell_consensus_votes_total{kind}`,
//!   `stell_fork_total`, `stell_mempool_size`, `stell_block_txs{histogram}`,
//!   `stell_state_root_commits_total`, `stell_validator_set_size`,
//!   `stell_validator_power_total`, `stell_validator_quorum_power`,
//!   `stell_validator_set_fragile` — all mirror already-public RPC
//!   (`stell_getValidators` etc.); no secret in any of them.
//! * Node-local observability: `stell_data_dir_bytes`, `stell_snapshot_count`,
//!   `stell_state_entries`, `stell_persist_queue_depth`,
//!   `stell_persist_queue_dropped_total`, `stell_build_info{version,hash,dirty}`
//!   (also on `/api/version`), plus the four explorer-folded gauges
//!   (`stellereum_block_height`, `stellereum_mempool_size`,
//!   `stellereum_contracts_total`, `stellereum_tokens_total`, `stell_ready`).
//! * Peer-labeled series: `stell_peer_latency_seconds{peer}` and
//!   `stell_peer_round_lag{peer}` — SELF-MEASURED (our latency/lag view of a
//!   peer id), never peer-reported topology; peer ids are attacker-chosen so
//!   every value passes through [`sanitize_label_value`]. No peer IPs, no
//!   keys, no tokens, no mempool contents, no balances anywhere in the scrape.
//!   Prune verdict: nothing sensitive to remove.

use serde_json::json;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Write as _;
use std::sync::{Arc, Mutex, OnceLock};

/// Content type for the Prometheus text exposition format.
///
/// Prometheus ignores parameters on text scrapes, and the parameter is what
/// tells a scraper which of the two encodings it is looking at; sending it
/// costs nothing and avoids a "unrecognized content type" warning on servers
/// configured with strict text-format checking.
pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4";

// ============================================================================
// Metric names
// ============================================================================

/// Round the engine is currently voting in, for the active height.
pub const CONSENSUS_ROUND: &str = "stell_consensus_round";
/// Height the engine is currently working on.
pub const CONSENSUS_HEIGHT: &str = "stell_consensus_height";
/// Seconds between two consecutively finalized blocks.
pub const BLOCK_INTERVAL_SECONDS: &str = "stell_block_interval_seconds";
/// Votes observed, split by kind.
pub const CONSENSUS_VOTES_TOTAL: &str = "stell_consensus_votes_total";
/// Round-trip latency to a consensus peer, per peer id.
pub const PEER_LATENCY_SECONDS: &str = "stell_peer_latency_seconds";
/// Blocks seen that conflict with our finalized chain.
pub const FORK_TOTAL: &str = "stell_fork_total";
/// Proposals refused because the proposer's post-state root disagrees with
/// ours (execution divergence on the same finalized hash, 2026-10-22 #288000).
/// Monotonic counter, never reset: alert on `increase(...) > 0`.
pub const DIVERGENCE_TOTAL: &str = "stell_divergence_total";
/// Quorum certificates refused because they carry less power than the quorum
/// of the validator set in force at the certificate's height (W10.5: the
/// unilateral/weak-finalization firewall — a node must never finalize with
/// only its own vote when the set requires more). Monotonic counter, never
/// reset: alert on `increase(...) > 0`.
pub const WEAK_QC_REFUSED_TOTAL: &str = "stell_weak_qc_refused_total";
pub const STRAGGLER_GRACE_EXTENDS_TOTAL: &str = "stell_straggler_grace_extends_total";
/// Transactions pending in the mempool.
pub const MEMPOOL_SIZE: &str = "stell_mempool_size";
/// Transactions in the pool that took the SEALED (epoch-seal) path.
pub const MEMPOOL_SEALED: &str = "stell_mempool_sealed";
/// Transactions in the pool that took the PLAIN path.
pub const MEMPOOL_PLAIN: &str = "stell_mempool_plain";
/// Sealed transactions unsealed and packed into a block.
pub const MEV_UNSEALED_TOTAL: &str = "stell_mev_unsealed_total";
/// Sealed transactions dropped because they could not be unsealed.
pub const MEV_UNSEAL_FAILED_TOTAL: &str = "stell_mev_unseal_failed_total";
/// Transactions per finalized block.
pub const BLOCK_TXS: &str = "stell_block_txs";
/// State-root commitments folded into the chain.
pub const STATE_ROOT_COMMITS_TOTAL: &str = "stell_state_root_commits_total";
/// Size of the active consensus validator set.
pub const VALIDATOR_SET_SIZE: &str = "stell_validator_set_size";
/// Total voting power of the active validator set.
pub const VALIDATOR_POWER_TOTAL: &str = "stell_validator_power_total";
/// Power-weighted quorum threshold of the active validator set.
pub const VALIDATOR_QUORUM_POWER: &str = "stell_validator_quorum_power";
/// Quorum fragility of the active validator set (1 = fragile, 0 = healthy).
pub const VALIDATOR_SET_FRAGILE: &str = "stell_validator_set_fragile";
/// Bytes under the node's data directory (disk footprint).
pub const DATA_DIR_BYTES: &str = "stell_data_dir_bytes";
/// State/domain snapshots retained on disk.
pub const SNAPSHOT_COUNT: &str = "stell_snapshot_count";
/// Estimated state entries (accounts + contracts + tokens, see explorer wiring).
pub const STATE_ENTRIES: &str = "stell_state_entries";
/// Depth of the background persist queue (slow disk backpressure signal).
pub const PERSIST_QUEUE_DEPTH: &str = "stell_persist_queue_depth";
/// Persist jobs dropped because the bounded queue was full (disk too slow).
pub const PERSIST_QUEUE_DROPPED_TOTAL: &str = "stell_persist_queue_dropped_total";
/// How many rounds behind us a consensus peer was last seen, per peer id.
pub const PEER_ROUND_LAG: &str = "stell_peer_round_lag";
/// Build identity (always 1; version/hash/dirty ride as labels).
pub const BUILD_INFO: &str = "stell_build_info";
/// Rounds that ended nil (no block prevote QC): consecutive nil-rounds stall
/// finality. Monotonic counter, never reset: alert on `increase(...) >= 3`.
pub const NIL_ROUNDS_TOTAL: &str = "stell_nil_rounds_total";
/// Nil-storm circuit-breaker fires (one per consecutive-nil streak, K=3).
/// Monotonic counter, never reset: alert on any increase.
pub const NIL_BREAKER_FIRES_TOTAL: &str = "stell_nil_breaker_fires_total";
/// Scheduled-proposer slots that went empty (observability only, no protocol
/// punishment). Monotonic counter, never reset.
pub const PROPOSER_MISSED_TOTAL: &str = "stell_proposer_missed_total";
/// Proposal validations slower than the backpressure threshold (the node was
/// too slow to validate, not the network). Monotonic counter, never reset:
/// alert on any increase.
pub const SLOW_VALIDATION_TOTAL: &str = "stell_slow_validation_total";
/// Unbound (replayable, no chain id) transactions admitted by the RPC
/// (A14 chain-binding rollout, phase 1: warn+meter). Monotonic counter,
/// never reset: alert on any increase while the rollout is in phase 1;
/// phase 3 refuses unbound admission outright, so the series going flat is
/// the rollout completing.
pub const UNBOUND_TX_TOTAL: &str = "stell_unbound_tx_total";
/// Unbound (replayable, no chain id) transactions REFUSED by the chain-binding
/// gate once refusal is active (A14 rollout, phase 3: RPC submit, mempool
/// insert, block-apply admission and the activation drain all count here).
/// Monotonic counter, never reset: alert on any increase before the published
/// activation height (it means a node armed the gate early); after activation
/// it counts blocked replays.
pub const UNBOUND_REFUSED_TOTAL: &str = "stell_unbound_refused_total";

/// Label carrying the vote kind (`prevote` / `precommit`).
pub const LABEL_KIND: &str = "kind";
/// Label carrying a peer id.
pub const LABEL_PEER: &str = "peer";
/// Label carrying the binary's semantic version.
pub const LABEL_VERSION: &str = "version";
/// Label carrying the build's git hash.
pub const LABEL_HASH: &str = "hash";
/// Label carrying the build's dirty flag.
pub const LABEL_DIRTY: &str = "dirty";
/// Synthetic histogram-boundary label mandated by the text format.
pub const LABEL_LE: &str = "le";

// ============================================================================
// Default bucket boundaries
// ============================================================================
//
// Exposed as constants so an operator can reason about them without reading
// the renderer, and so the tests can assert the `le` values that actually show
// up in a scrape. Each family gets boundaries tuned to what it measures:
// block intervals are bounded by how fast this chain finalizes, peer latency
// is bounded by the network's round-trip, and block size is a plain count.

/// Sub-second block timing through to a stalled-but-not-dead minute.
pub const DEFAULT_BLOCK_INTERVAL_BUCKETS: &[f64] =
    &[0.1, 0.25, 0.5, 1.0, 2.0, 3.0, 5.0, 10.0, 20.0, 30.0, 60.0];

/// Same-clock round-trip (ms) through to a five-second outlier.
pub const DEFAULT_PEER_LATENCY_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
];

/// Empty block through a very large one.
pub const DEFAULT_BLOCK_TXS_BUCKETS: &[f64] =
    &[0.0, 1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0];

// ============================================================================
// Internal model
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MetricKind {
    Gauge,
    Counter,
    Histogram,
}

impl MetricKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Gauge => "gauge",
            Self::Counter => "counter",
            Self::Histogram => "histogram",
        }
    }
}

/// Immutable description of one exported metric family.
///
/// `name` doubles as the Prometheus lookup key, so it must be exactly the
/// public constant above. All HELP strings are compile-time constants of ours,
/// never derived from peer input — see [`Registry::new`] for why that is
/// asserted rather than merely intended.
struct MetricDef {
    name: &'static str,
    help: &'static str,
    kind: MetricKind,
    /// Label names in declaration order; the exposition sorts them at render.
    labels: &'static [&'static str],
    /// Upper bounds, ascending. Only meaningful for histograms.
    buckets: &'static [f64],
}

/// One stored sample: either a single number or a histogram's accumulators.
enum Value {
    /// Gauge/counter value.
    ///
    /// Stored as `f64` because the text format renders every sample as a float
    /// anyway. Every non-histogram value we keep is a count or a height, all
    /// far inside the range where `f64` is exact, so nothing is lost.
    Scalar(f64),
    /// Per-bucket (NOT cumulative) counts, plus the running total and sum.
    Histogram {
        counts: Vec<u64>,
        sum: f64,
        count: u64,
    },
}

impl Value {
    fn scalar(v: f64) -> Self {
        Self::Scalar(v)
    }

    fn histogram(bucket_count: usize) -> Self {
        Self::Histogram {
            counts: vec![0; bucket_count],
            sum: 0.0,
            count: 0,
        }
    }

    /// Fold one observation (or `n` units of a counter) into this sample.
    fn add(&mut self, n: f64, buckets: &[f64]) {
        match self {
            Value::Scalar(v) => *v += n,
            Value::Histogram { counts, sum, count } => {
                *sum += n;
                *count = count.saturating_add(1);
                // Cumulative counts are computed at render time by prefix sum,
                // so a bucket holds only the samples that fall in it. Anything
                // above every bound is represented solely by `_count`, which is
                // also what the `+Inf` bucket reports.
                for (i, bound) in buckets.iter().enumerate() {
                    if n <= *bound {
                        counts[i] = counts[i].saturating_add(1);
                        break;
                    }
                }
            }
        }
    }

    fn render(&self, def: &MetricDef, labels: &[(String, String)], out: &mut String) {
        match self {
            Value::Scalar(v) => {
                let _ = writeln!(out, "{}{} {}", def.name, labels_suffix(labels), fmt_f64(*v));
            }
            Value::Histogram { counts, sum, count } => {
                let mut cumulative: u64 = 0;
                for (i, observed) in counts.iter().enumerate() {
                    cumulative = cumulative.saturating_add(*observed);
                    let mut with_le = labels.to_vec();
                    with_le.push((LABEL_LE.to_string(), fmt_f64(def.buckets[i])));
                    sort_labels(&mut with_le);
                    let _ = writeln!(
                        out,
                        "{}_bucket{} {}",
                        def.name,
                        render_labels(&with_le),
                        cumulative
                    );
                }
                // The `+Inf` bucket is required by the format and is by
                // definition the total number of observations.
                let mut with_inf = labels.to_vec();
                with_inf.push((LABEL_LE.to_string(), "+Inf".to_string()));
                sort_labels(&mut with_inf);
                let _ = writeln!(
                    out,
                    "{}_bucket{} {}",
                    def.name,
                    render_labels(&with_inf),
                    count
                );
                let suffix = labels_suffix(labels);
                let _ = writeln!(out, "{}_sum{} {}", def.name, suffix, fmt_f64(*sum));
                let _ = writeln!(out, "{}_count{} {}", def.name, suffix, count);
            }
        }
    }
}

/// Series identity: which family, plus its label set.
///
/// `Vec<(String, String)>` rather than a `HashMap` because it is `Ord`, which
/// is what makes the render order deterministic (see [`Registry`]).
type SeriesKey = (usize, Vec<(String, String)>);

fn sort_labels(labels: &mut [(String, String)]) {
    // By label name, then value — the same rule the reference Prometheus
    // client uses, so a scrape here is indistinguishable from a scrape of a
    // client-library registry.
    labels.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
}

fn normalize_labels(raw: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut labels: Vec<(String, String)> = raw
        .iter()
        .map(|(k, v)| (k.to_string(), sanitize_label_value(v)))
        .collect();
    sort_labels(&mut labels);
    labels
}

/// Render `{k="v",k2="v2"}`, or nothing when there are no labels.
fn render_labels(labels: &[(String, String)]) -> String {
    if labels.is_empty() {
        return String::new();
    }
    let mut out = String::with_capacity(2 + labels.len() * 24);
    out.push('{');
    for (i, (k, v)) in labels.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(out, "{k}=\"{v}\"");
    }
    out.push('}');
    out
}

fn labels_suffix(labels: &[(String, String)]) -> String {
    if labels.is_empty() {
        String::new()
    } else {
        render_labels(labels)
    }
}

/// Format a float the way the text format wants it.
///
/// Rust's `Display` for `f64` is the shortest representation that round-trips,
/// which is both valid exposition syntax and the least surprising thing to read
/// in a diff. The non-finite cases need spelling out because `inf`/`-inf` are
/// not accepted where `+Inf`/`-Inf` are.
fn fmt_f64(v: f64) -> String {
    if v.is_nan() {
        "NaN".to_string()
    } else if v == f64::INFINITY {
        "+Inf".to_string()
    } else if v == f64::NEG_INFINITY {
        "-Inf".to_string()
    } else {
        format!("{v}")
    }
}

/// Make an arbitrary external string safe to embed in a label value.
///
/// This is the only function in the module where bytes we do not control meet a
/// line-oriented output format that a scraper will parse. A peer id is attacker-
/// chosen: without this, a peer announcing itself as
/// `evil"\nstell_fake_metric 1\n` would terminate the current sample line and
/// have the remainder of its label read as a genuine, perfectly well-formed
/// sample of a metric that does not exist. That is not a cosmetic bug — it
/// lets a remote peer forge arbitrary counters, and alerting rules that fire on
/// a counter reading a fake spike are a real incident.
///
/// Two independent layers, because the cheap one is enough and the correct one
/// alone is easy to break later:
///
///  1. Anything that is not printable ASCII or a space becomes `_`. Newline and
///     carriage return are the characters that end a line and thus the ones
///     that matter; dropping the whole control range also removes the NUL/DEL
///     tricks that make downstream tooling mis-parse a "single" sample.
///  2. `"` and `\` are backslash-escaped per the text format, so the value can
///     never close its own quoted string — even if a future change widens
///     layer 1's allowlist back toward accepting punctuation.
pub fn sanitize_label_value(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_ascii_graphic() || c == ' ' => out.push(c),
            _ => out.push('_'),
        }
    }
    out
}

// ============================================================================
// Registry
// ============================================================================

/// A shareable set of consensus metrics.
///
/// Share it as `Arc<Registry>`; every method takes `&self` and mutates through
/// a `Mutex`, so the consensus driver can hold a clone without a channel or an
/// async hop in the middle of a voting round.
///
/// Two design points worth stating outright:
///
///  * **The metric set is fixed.** Families and their HELP strings are chosen
///    once, in [`Registry::new`], from compile-time constants. A runtime
///    `register()` would let any code path — including one reachable from peer
///    input — add a family to the scrape, and a scrape is exactly what an
///    operator trusts. Pre-declaring the whole story means a metric is present
///    from the first scrape, so `rate()` and `increase()` are well defined
///    across a restart instead of appearing mid-window.
///  * **Order is deterministic.** Samples live in a `BTreeMap` keyed by
///    (family index, sorted labels), and families are rendered in declaration
///    order, so the same data always produces the same bytes. Prometheus does
///    not care, but dashboard diffs, `curl | diff` debugging and byte-level
///    assertions all do, and a scrape that reshuffles between two requests is
///    indistinguishable from one where a value actually changed.
pub struct Registry {
    /// Declaration order == exposition order.
    defs: Vec<MetricDef>,
    /// Live samples. A poisoned lock is recovered rather than propagated: a
    /// panic while recording a metric must not make the metrics endpoint (and
    /// with it the operator's only view of consensus health) return 500.
    series: Mutex<BTreeMap<SeriesKey, Value>>,
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

impl Registry {
    /// A registry with every family declared and every series pre-seeded at
    /// zero.
    pub fn new() -> Self {
        let defs = vec![
            MetricDef {
                name: CONSENSUS_ROUND,
                help: "Consensus round currently being voted on at the active height",
                kind: MetricKind::Gauge,
                labels: &[],
                buckets: &[],
            },
            MetricDef {
                name: CONSENSUS_HEIGHT,
                help: "Block height the consensus engine is currently working on",
                kind: MetricKind::Gauge,
                labels: &[],
                buckets: &[],
            },
            MetricDef {
                name: BLOCK_INTERVAL_SECONDS,
                help: "Seconds between two consecutively finalized blocks",
                kind: MetricKind::Histogram,
                labels: &[],
                buckets: DEFAULT_BLOCK_INTERVAL_BUCKETS,
            },
            MetricDef {
                name: CONSENSUS_VOTES_TOTAL,
                help: "Consensus votes observed, by kind (prevote or precommit)",
                kind: MetricKind::Counter,
                labels: &[LABEL_KIND],
                buckets: &[],
            },
            MetricDef {
                name: PEER_LATENCY_SECONDS,
                help: "Round-trip latency to a consensus peer, by peer id",
                kind: MetricKind::Histogram,
                labels: &[LABEL_PEER],
                buckets: DEFAULT_PEER_LATENCY_BUCKETS,
            },
            MetricDef {
                name: FORK_TOTAL,
                help: "Blocks observed that conflict with this node's finalized chain",
                kind: MetricKind::Counter,
                labels: &[],
                buckets: &[],
            },
            MetricDef {
                name: DIVERGENCE_TOTAL,
                help: "Proposals refused over a post-state root mismatch (execution divergence)",
                kind: MetricKind::Counter,
                labels: &[],
                buckets: &[],
            },
            MetricDef {
                name: WEAK_QC_REFUSED_TOTAL,
                help: "Quorum certificates refused for carrying less power than the quorum of the set in force at the certificate height",
                kind: MetricKind::Counter,
                labels: &[],
                buckets: &[],
            },
            MetricDef {
                name: STRAGGLER_GRACE_EXTENDS_TOTAL,
                help: "Ticks a straggler grace hold kept a round open past its deterministic timeout (docs/PROPOSER_REWORK.md)",
                kind: MetricKind::Counter,
                labels: &[],
                buckets: &[],
            },
            MetricDef {
                name: MEMPOOL_SIZE,
                help: "Transactions currently pending in the mempool",
                kind: MetricKind::Gauge,
                labels: &[],
                buckets: &[],
            },
            MetricDef {
                name: BLOCK_TXS,
                help: "Transactions included per finalized block",
                kind: MetricKind::Histogram,
                labels: &[],
                buckets: DEFAULT_BLOCK_TXS_BUCKETS,
            },
            MetricDef {
                name: STATE_ROOT_COMMITS_TOTAL,
                help: "State-root commitments folded into the chain",
                kind: MetricKind::Counter,
                labels: &[],
                buckets: &[],
            },
            MetricDef {
                name: VALIDATOR_SET_SIZE,
                help: "Number of validators in the active consensus validator set",
                kind: MetricKind::Gauge,
                labels: &[],
                buckets: &[],
            },
            MetricDef {
                name: VALIDATOR_POWER_TOTAL,
                help: "Total voting power of the active consensus validator set",
                kind: MetricKind::Gauge,
                labels: &[],
                buckets: &[],
            },
            MetricDef {
                name: VALIDATOR_QUORUM_POWER,
                help: "Power-weighted quorum threshold of the active validator set",
                kind: MetricKind::Gauge,
                labels: &[],
                buckets: &[],
            },
            MetricDef {
                name: VALIDATOR_SET_FRAGILE,
                help: "Quorum fragility of the active validator set (1 fragile, 0 healthy)",
                kind: MetricKind::Gauge,
                labels: &[],
                buckets: &[],
            },
            MetricDef {
                name: DATA_DIR_BYTES,
                help: "Bytes under the node data directory (disk footprint estimate)",
                kind: MetricKind::Gauge,
                labels: &[],
                buckets: &[],
            },
            MetricDef {
                name: SNAPSHOT_COUNT,
                help: "State and domain snapshots retained on disk (estimate)",
                kind: MetricKind::Gauge,
                labels: &[],
                buckets: &[],
            },
            MetricDef {
                name: STATE_ENTRIES,
                help: "Estimated state entries (accounts plus contracts plus tokens)",
                kind: MetricKind::Gauge,
                labels: &[],
                buckets: &[],
            },
            MetricDef {
                name: PERSIST_QUEUE_DEPTH,
                help: "Pending jobs in the background storage persist queue",
                kind: MetricKind::Gauge,
                labels: &[],
                buckets: &[],
            },
            MetricDef {
                name: PERSIST_QUEUE_DROPPED_TOTAL,
                help: "Persist jobs dropped because the bounded queue was full",
                kind: MetricKind::Counter,
                labels: &[],
                buckets: &[],
            },
            MetricDef {
                name: PEER_ROUND_LAG,
                help: "Rounds a consensus peer lags behind this node, by peer id",
                kind: MetricKind::Gauge,
                labels: &[LABEL_PEER],
                buckets: &[],
            },
            MetricDef {
                name: MEMPOOL_SEALED,
                help: "Transactions in the mempool that took the sealed (epoch-seal) path",
                kind: MetricKind::Gauge,
                labels: &[],
                buckets: &[],
            },
            MetricDef {
                name: MEMPOOL_PLAIN,
                help: "Transactions in the mempool that took the plain (unsealed) path",
                kind: MetricKind::Gauge,
                labels: &[],
                buckets: &[],
            },
            MetricDef {
                name: MEV_UNSEALED_TOTAL,
                help: "Sealed transactions unsealed and packed into a block",
                kind: MetricKind::Counter,
                labels: &[],
                buckets: &[],
            },
            MetricDef {
                name: MEV_UNSEAL_FAILED_TOTAL,
                help: "Sealed transactions dropped because they could not be unsealed",
                kind: MetricKind::Counter,
                labels: &[],
                buckets: &[],
            },
            MetricDef {
                name: NIL_ROUNDS_TOTAL,
                help: "Rounds that ended nil (no block prevote quorum formed)",
                kind: MetricKind::Counter,
                labels: &[],
                buckets: &[],
            },
            MetricDef {
                name: NIL_BREAKER_FIRES_TOTAL,
                help: "Nil-storm circuit-breaker convergence actions applied (one per streak)",
                kind: MetricKind::Counter,
                labels: &[],
                buckets: &[],
            },
            MetricDef {
                name: PROPOSER_MISSED_TOTAL,
                help: "Scheduled-proposer slots that went empty (observability only)",
                kind: MetricKind::Counter,
                labels: &[],
                buckets: &[],
            },
            MetricDef {
                name: SLOW_VALIDATION_TOTAL,
                help: "Proposal validations slower than the backpressure threshold",
                kind: MetricKind::Counter,
                labels: &[],
                buckets: &[],
            },
            MetricDef {
                name: UNBOUND_TX_TOTAL,
                help: "Unbound replayable transactions admitted by the RPC (chain-binding rollout)",
                kind: MetricKind::Counter,
                labels: &[],
                buckets: &[],
            },
            MetricDef {
                name: UNBOUND_REFUSED_TOTAL,
                help: "Unbound replayable transactions refused by the chain-binding gate (RPC, mempool, apply, activation drain)",
                kind: MetricKind::Counter,
                labels: &[],
                buckets: &[],
            },
            MetricDef {
                name: BUILD_INFO,
                help: "Build identity of this binary (always 1; see version, hash and dirty labels)",
                kind: MetricKind::Gauge,
                labels: &[LABEL_VERSION, LABEL_HASH, LABEL_DIRTY],
                buckets: &[],
            },
        ];

        for def in &defs {
            // Cheap, and it turns "someone edited a HELP string and forgot the
            // escape" from a silent scraper failure into a failed test.
            debug_assert!(
                !def.help.contains('\n') && !def.help.contains('\\'),
                "{}: HELP must be a single escaped line",
                def.name
            );
        }

        let reg = Self {
            defs,
            series: Mutex::new(BTreeMap::new()),
        };

        // Pre-seed every series whose label set is known up front, so the first
        // scrape already describes the whole node. Pre-seeding both vote kinds
        // matters most: a `rate(...[5m])` over a series that only appears once
        // a vote is cast reads as "no data", not as "zero", and those two look
        // identical on a dashboard until the first vote lands.
        //
        // Per-peer latency is deliberately NOT pre-seeded: its label set is
        // discovered at runtime, and inventing a placeholder peer would put a
        // series in the scrape that no peer can ever match. The family still
        // declares itself (see `render`).
        for name in [
            CONSENSUS_ROUND,
            CONSENSUS_HEIGHT,
            BLOCK_INTERVAL_SECONDS,
            FORK_TOTAL,
            DIVERGENCE_TOTAL,
            WEAK_QC_REFUSED_TOTAL,
            STRAGGLER_GRACE_EXTENDS_TOTAL,
            MEMPOOL_SIZE,
            BLOCK_TXS,
            STATE_ROOT_COMMITS_TOTAL,
            VALIDATOR_SET_SIZE,
            VALIDATOR_POWER_TOTAL,
            VALIDATOR_QUORUM_POWER,
            VALIDATOR_SET_FRAGILE,
            DATA_DIR_BYTES,
            SNAPSHOT_COUNT,
            STATE_ENTRIES,
            PERSIST_QUEUE_DEPTH,
            PERSIST_QUEUE_DROPPED_TOTAL,
            UNBOUND_TX_TOTAL,
            UNBOUND_REFUSED_TOTAL,
        ] {
            reg.seed(name, &[]);
        }
        // Build identity is a singleton series: exactly one sample whose labels
        // carry the version. Seeded here from compile-time values; the gateway
        // re-sets it with runtime-resolved values (git fallback) on each scrape.
        reg.set_build_info(
            BUILD_VERSION,
            build_hash_compile_time(),
            build_dirty_compile_time(),
        );
        for kind in [VoteKind::Prevote, VoteKind::Precommit] {
            reg.seed(CONSENSUS_VOTES_TOTAL, &[(LABEL_KIND, kind.as_str())]);
        }
        reg
    }

    /// Convenience for the common wiring: one `Arc`, no construction ceremony.
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    /// Index of a family, looked up by name.
    ///
    /// Every internal call site passes the public name constant, so a wrong
    /// family is a panic here rather than a series silently written to the
    /// wrong metric — which would be invisible in the code and obvious in a
    /// dashboard, in that order of how long it takes to notice.
    fn idx(&self, name: &str) -> usize {
        self.defs
            .iter()
            .position(|d| d.name == name)
            .expect("unknown metric family")
    }

    fn seed(&self, name: &str, labels: &[(&str, &str)]) {
        let idx = self.idx(name);
        let def = &self.defs[idx];
        debug_assert_eq!(labels.len(), def.labels.len(), "{name}: wrong label arity");
        let value = match def.kind {
            MetricKind::Histogram => Value::histogram(def.buckets.len()),
            _ => Value::scalar(0.0),
        };
        let mut series = self.lock();
        series.insert((idx, normalize_labels(labels)), value);
    }

    /// A poisoned lock means some other thread panicked while holding it. The
    /// data behind it is still structurally sound (every update is a single
    /// locked section, and the BTreeMap cannot be observed half-updated), so we
    /// take the inner value and keep serving rather than propagating a panic
    /// into the HTTP handler.
    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<SeriesKey, Value>> {
        self.series.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Assign a gauge's current value.
    ///
    /// Deliberately an assignment and not an increment. The consensus engine
    /// reports the same height on every tick, so an accumulating gauge would
    /// report the sum of everything ever observed — a number that only ever
    /// grows and means nothing. Keeping the two operations as separate
    /// functions, each asserting the metric kind it belongs to, is what stops
    /// a counter and a gauge from being confused at a call site.
    fn set_scalar(&self, name: &str, labels: &[(&str, &str)], v: f64) {
        let idx = self.idx(name);
        let def = &self.defs[idx];
        debug_assert_eq!(labels.len(), def.labels.len(), "{name}: wrong label arity");
        debug_assert_eq!(def.kind, MetricKind::Gauge, "{name} is not a gauge");
        let key = (idx, normalize_labels(labels));
        let mut series = self.lock();
        match series.entry(key) {
            std::collections::btree_map::Entry::Occupied(mut slot) => {
                *slot.get_mut() = Value::Scalar(v)
            }
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(Value::Scalar(v));
            }
        }
    }

    /// Add `n` to a counter, or record one histogram observation of `n`.
    fn add(&self, name: &str, labels: &[(&str, &str)], n: f64) {
        let idx = self.idx(name);
        let def = &self.defs[idx];
        debug_assert_eq!(labels.len(), def.labels.len(), "{name}: wrong label arity");
        debug_assert_ne!(
            def.kind,
            MetricKind::Gauge,
            "{name} is a gauge: use an assignment, not a sum"
        );
        let key = (idx, normalize_labels(labels));
        let mut series = self.lock();
        let slot = series.entry(key).or_insert_with(|| match def.kind {
            MetricKind::Histogram => Value::histogram(def.buckets.len()),
            _ => Value::scalar(0.0),
        });
        slot.add(n, def.buckets);
    }

    // -- gauges ------------------------------------------------------------

    /// Current consensus round. Resets on every new height, so a jump to 0 with
    /// a rising [`Registry::set_height`] is normal, not a restart.
    pub fn set_round(&self, round: u32) {
        self.set_scalar(CONSENSUS_ROUND, &[], round as f64);
    }

    /// Current height being worked on.
    pub fn set_height(&self, height: u64) {
        self.set_scalar(CONSENSUS_HEIGHT, &[], height as f64);
    }

    /// Pending mempool transactions.
    pub fn set_mempool_size(&self, size: u64) {
        self.set_scalar(MEMPOOL_SIZE, &[], size as f64);
    }

    /// Validators in the active set.
    pub fn set_validator_set_size(&self, size: u64) {
        self.set_scalar(VALIDATOR_SET_SIZE, &[], size as f64);
    }

    /// Total voting power of the active set.
    pub fn set_validator_power_total(&self, power: u64) {
        self.set_scalar(VALIDATOR_POWER_TOTAL, &[], power as f64);
    }

    /// Power-weighted quorum threshold of the active set.
    pub fn set_validator_quorum_power(&self, power: u64) {
        self.set_scalar(VALIDATOR_QUORUM_POWER, &[], power as f64);
    }

    /// Quorum fragility of the active set (`true` = 1 = fragile).
    pub fn set_validator_set_fragile(&self, fragile: bool) {
        self.set_scalar(VALIDATOR_SET_FRAGILE, &[], if fragile { 1.0 } else { 0.0 });
    }

    /// Whole validator-set story in one call (size, power, quorum, fragile).
    pub fn set_validator_set_full(
        &self,
        size: u64,
        total_power: u64,
        quorum_power: u64,
        fragile: bool,
    ) {
        self.set_validator_set_size(size);
        self.set_validator_power_total(total_power);
        self.set_validator_quorum_power(quorum_power);
        self.set_validator_set_fragile(fragile);
    }

    /// Bytes under the node's data directory (disk footprint estimate).
    pub fn set_data_dir_bytes(&self, bytes: u64) {
        self.set_scalar(DATA_DIR_BYTES, &[], bytes as f64);
    }

    /// State/domain snapshots retained on disk (estimate).
    pub fn set_snapshot_count(&self, count: u64) {
        self.set_scalar(SNAPSHOT_COUNT, &[], count as f64);
    }

    /// Estimated state entries (accounts + contracts + tokens; see explorer).
    pub fn set_state_entries(&self, entries: u64) {
        self.set_scalar(STATE_ENTRIES, &[], entries as f64);
    }

    /// Pending jobs in the background storage persist queue.
    ///
    /// Wired (audit-state-sync F2): `AsyncPersistence` (storage.rs) refreshes
    /// this on every push (hot path, atomic counter) and every dequeue, via
    /// the process-global registry — dashboards can alert on the name AND get
    /// a live value. Pre-seeded at zero (see the registry constructor).
    pub fn set_persist_queue_depth(&self, depth: u64) {
        self.set_scalar(PERSIST_QUEUE_DEPTH, &[], depth as f64);
    }

    // -- counters ----------------------------------------------------------

    /// One vote of `kind` seen (broadcast, received, or self-cast).
    pub fn inc_vote(&self, kind: VoteKind) {
        self.add_votes(kind, 1);
    }

    /// `n` votes of `kind`.
    pub fn add_votes(&self, kind: VoteKind, n: u64) {
        self.add(
            CONSENSUS_VOTES_TOTAL,
            &[(LABEL_KIND, kind.as_str())],
            n as f64,
        );
    }

    /// The sealed/plain split of the mempool.
    ///
    /// The operator's view of how much of the traffic actually takes the
    /// private path: a network where the sealed share is zero is a network
    /// where the MEV protection protects nothing.
    pub fn set_mempool_sealed_split(&self, sealed: u64, plain: u64) {
        self.set_scalar(MEMPOOL_SEALED, &[], sealed as f64);
        self.set_scalar(MEMPOOL_PLAIN, &[], plain as f64);
    }

    /// One sealed transaction unsealed and packed.
    pub fn inc_mev_unsealed(&self, n: u64) {
        self.add(MEV_UNSEALED_TOTAL, &[], n as f64);
    }

    /// One sealed transaction dropped (it could not be unsealed).
    pub fn inc_mev_unseal_failed(&self, n: u64) {
        self.add(MEV_UNSEAL_FAILED_TOTAL, &[], n as f64);
    }

    /// A block arrived that conflicts with our finalized chain. This is the
    /// signal an operator most wants to alert on, so it is a monotonic counter
    /// and never reset by anything in this module.
    pub fn inc_fork(&self) {
        self.add(FORK_TOTAL, &[], 1.0);
    }

    /// A quorum certificate was refused for carrying less power than the
    /// quorum of the validator set in force at the certificate's height
    /// (W10.5 unilateral/weak-finalization firewall). Monotonic counter,
    /// never reset: alert on any increase.
    pub fn inc_weak_qc_refused(&self) {
        self.add(WEAK_QC_REFUSED_TOTAL, &[], 1.0);
    }

    /// One tick a straggler grace hold kept the round open past its
    /// deterministic timeout (docs/PROPOSER_REWORK.md §2c). Monotonic counter,
    /// never reset: the extends/sec rate is the liveness signal that the
    /// grace is engaging (vs a silent stall).
    pub fn inc_straggler_grace_extends(&self) {
        self.add(STRAGGLER_GRACE_EXTENDS_TOTAL, &[], 1.0);
    }

    /// A proposal was refused because its post-state root disagrees with ours
    /// (same finalized hash, different execution outcome — the 2026-10-22
    /// #288000 split). Monotonic counter, never reset: alert on any increase.
    pub fn inc_divergence(&self) {
        self.add(DIVERGENCE_TOTAL, &[], 1.0);
    }

    /// One state-root commitment folded into the chain.
    pub fn inc_state_root_commit(&self) {
        self.add_state_root_commits(1);
    }

    /// `n` state-root commitments folded in.
    pub fn add_state_root_commits(&self, n: u64) {
        self.add(STATE_ROOT_COMMITS_TOTAL, &[], n as f64);
    }

    /// One persist job dropped because the bounded queue was full.
    ///
    /// Wired (audit-state-sync F2): the drop path in `storage`
    /// (`AsyncPersistence::push`) increments this on the process-global
    /// registry alongside the stderr line. Monotonic counter, never reset.
    pub fn inc_persist_queue_dropped(&self) {
        self.add_persist_queue_dropped(1);
    }

    /// One round ended nil (no block prevote QC). Alertable: consecutive
    /// nil-rounds stall finality; the breaker fires at K=3.
    pub fn inc_nil_round(&self) {
        self.add(NIL_ROUNDS_TOTAL, &[], 1.0);
    }

    /// One nil-storm convergence action applied (one per streak max).
    pub fn inc_nil_breaker_fire(&self) {
        self.add(NIL_BREAKER_FIRES_TOTAL, &[], 1.0);
    }

    /// One scheduled-proposer slot went empty (observability only).
    pub fn inc_proposer_miss(&self) {
        self.add(PROPOSER_MISSED_TOTAL, &[], 1.0);
    }

    /// One proposal validation exceeded the backpressure threshold.
    pub fn inc_slow_validation(&self) {
        self.add(SLOW_VALIDATION_TOTAL, &[], 1.0);
    }

    /// One unbound (replayable, no chain id) transaction admitted by the RPC.
    /// A14 chain-binding rollout, phase 1: admitted + metered + warned (see
    /// `note_unbound_admission`); monotonic counter, never reset.
    pub fn inc_unbound_tx(&self) {
        self.add(UNBOUND_TX_TOTAL, &[], 1.0);
    }

    /// One unbound (replayable, no chain id) transaction REFUSED by the
    /// chain-binding gate while refusal is active (see [`UNBOUND_REFUSED_TOTAL`]);
    /// monotonic counter, never reset.
    pub fn inc_unbound_refused(&self) {
        self.add(UNBOUND_REFUSED_TOTAL, &[], 1.0);
    }

    /// `n` persist jobs dropped because the bounded queue was full.
    pub fn add_persist_queue_dropped(&self, n: u64) {
        self.add(PERSIST_QUEUE_DROPPED_TOTAL, &[], n as f64);
    }

    // -- histograms --------------------------------------------------------

    /// Seconds since the previously finalized block. Observe once per finalised
    /// block, not once per proposal — proposal cadence is a different (and much
    /// noisier) story than how fast the chain actually commits.
    pub fn observe_block_interval(&self, seconds: f64) {
        self.add(BLOCK_INTERVAL_SECONDS, &[], seconds);
    }

    /// Transactions in a finalized block.
    pub fn observe_block_txs(&self, txs: u64) {
        self.add(BLOCK_TXS, &[], txs as f64);
    }

    /// Round-trip latency to `peer`, in seconds. The peer id is sanitised
    /// before it reaches the exposition — see [`sanitize_label_value`].
    pub fn observe_peer_latency(&self, peer: &str, seconds: f64) {
        self.add(PEER_LATENCY_SECONDS, &[(LABEL_PEER, peer)], seconds);
    }

    /// Rounds `peer` lags behind this node (assignment, not a sum — same
    /// reasoning as every other gauge here). The peer id is sanitised.
    ///
    /// NOTE: no call site wires this yet (peer-round sightings live in the
    /// consensus loop, which holds no registry handle today). Declared with the
    /// family so a scrape already names it; live values appear once a producer
    /// calls this setter. Deliberately NOT pre-seeded: like latency, its label
    /// set is discovered at runtime.
    pub fn set_peer_round_lag(&self, peer: &str, lag_rounds: u64) {
        self.set_scalar(PEER_ROUND_LAG, &[(LABEL_PEER, peer)], lag_rounds as f64);
    }

    /// Record a finalized block: its size and how long it took to arrive.
    pub fn observe_block(&self, txs: u64, interval_seconds: f64) {
        self.observe_block_txs(txs);
        self.observe_block_interval(interval_seconds);
    }

    // -- build identity ----------------------------------------------------

    /// (Re)set the singleton [`BUILD_INFO`] series.
    ///
    /// Exactly one sample ever exists: any previous series of this family is
    /// removed first, so a re-resolve (compile-time `unknown` -> runtime git
    /// fallback) never leaves two `stell_build_info` samples behind.
    pub fn set_build_info(&self, version: &str, hash: &str, dirty: &str) {
        let idx = self.idx(BUILD_INFO);
        let labels = normalize_labels(&[
            (LABEL_VERSION, version),
            (LABEL_HASH, hash),
            (LABEL_DIRTY, dirty),
        ]);
        let mut series = self.lock();
        series.retain(|(i, _), _| *i != idx);
        series.insert((idx, labels), Value::Scalar(1.0));
    }

    // -- exposition --------------------------------------------------------

    /// Render the whole registry in the Prometheus text exposition format.
    ///
    /// Takes the lock once for the entire output, so a scrape is a consistent
    /// snapshot: a reader never sees a counter that has been incremented but
    /// whose matching histogram has not.
    pub fn render(&self) -> String {
        let series = self.lock();
        let mut out = String::with_capacity(8 * 1024);
        // Walk the declarations, not the samples, and drain each family's
        // samples as we reach it. That makes "samples of one family are
        // contiguous" a structural property rather than something to assert,
        // and lets a family with no series yet still declare itself: a node
        // that has never measured a peer still says it has a latency metric,
        // so a scrape diff between two nodes (or two times) shows a change in
        // values, never a change in what the node claims to measure.
        let mut it = series.iter().peekable();
        for (idx, def) in self.defs.iter().enumerate() {
            let _ = writeln!(out, "# HELP {} {}", def.name, def.help);
            let _ = writeln!(out, "# TYPE {} {}", def.name, def.kind.as_str());
            while let Some((&(sample_idx, _), _)) = it.peek() {
                if sample_idx != idx {
                    break;
                }
                let Some(((_, labels), value)) = it.next() else {
                    break;
                };
                value.render(def, labels, &mut out);
            }
        }
        out
    }

    /// Scalar values as plain numbers, for a JSON status endpoint.
    ///
    /// Deliberately shallow: this is the whole snapshot surface, not a query
    /// API. Histograms are omitted because answering "give me the p99" here
    /// would mean shipping quantile estimation, and Prometheus already does
    /// that job from the buckets we just exposed.
    pub fn snapshot(&self) -> Snapshot {
        let series = self.lock();
        let scalar = |name: &str, labels: &[(&str, &str)]| -> f64 {
            match series.get(&(self.idx(name), normalize_labels(labels))) {
                Some(Value::Scalar(v)) => *v,
                _ => 0.0,
            }
        };
        Snapshot {
            round: scalar(CONSENSUS_ROUND, &[]),
            height: scalar(CONSENSUS_HEIGHT, &[]),
            mempool_size: scalar(MEMPOOL_SIZE, &[]),
            validator_set_size: scalar(VALIDATOR_SET_SIZE, &[]),
            validator_power_total: scalar(VALIDATOR_POWER_TOTAL, &[]),
            validator_quorum_power: scalar(VALIDATOR_QUORUM_POWER, &[]),
            validator_set_fragile: scalar(VALIDATOR_SET_FRAGILE, &[]),
            data_dir_bytes: scalar(DATA_DIR_BYTES, &[]),
            snapshot_count: scalar(SNAPSHOT_COUNT, &[]),
            state_entries: scalar(STATE_ENTRIES, &[]),
            persist_queue_depth: scalar(PERSIST_QUEUE_DEPTH, &[]),
            persist_queue_dropped: scalar(PERSIST_QUEUE_DROPPED_TOTAL, &[]),
            votes_prevote: scalar(CONSENSUS_VOTES_TOTAL, &[(LABEL_KIND, "prevote")]),
            votes_precommit: scalar(CONSENSUS_VOTES_TOTAL, &[(LABEL_KIND, "precommit")]),
            forks: scalar(FORK_TOTAL, &[]),
            divergences: scalar(DIVERGENCE_TOTAL, &[]),
            state_root_commits: scalar(STATE_ROOT_COMMITS_TOTAL, &[]),
            unbound_tx: scalar(UNBOUND_TX_TOTAL, &[]),
            unbound_refused: scalar(UNBOUND_REFUSED_TOTAL, &[]),
            straggler_grace_extends: scalar(STRAGGLER_GRACE_EXTENDS_TOTAL, &[]),
        }
    }
}

/// Process-wide default registry.
///
/// The HTTP gateway (`explorer::GatewayState`) and, if it is wired up, the
/// consensus driver both need the *same* registry for a scrape to show the
/// engine's writes. [`Registry::new`] is cheap, but constructing a second one
/// per call site would silently split the story in two: votes recorded on one
/// instance would never appear in a scrape served from the other. This hands
/// out one lazily-built `Arc` for the whole process, so a caller that can only
/// say `GatewayState::new(rpc, per_sec)` still shares state with anyone else
/// that calls [`global`].
pub fn global() -> Arc<Registry> {
    static GLOBAL: OnceLock<Arc<Registry>> = OnceLock::new();
    GLOBAL.get_or_init(|| Arc::new(Registry::new())).clone()
}

/// Flat view of the scalar metrics, cheap enough to build per request.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Snapshot {
    pub round: f64,
    pub height: f64,
    pub mempool_size: f64,
    pub validator_set_size: f64,
    pub validator_power_total: f64,
    pub validator_quorum_power: f64,
    pub validator_set_fragile: f64,
    pub data_dir_bytes: f64,
    pub snapshot_count: f64,
    pub state_entries: f64,
    pub persist_queue_depth: f64,
    pub persist_queue_dropped: f64,
    pub votes_prevote: f64,
    pub votes_precommit: f64,
    pub forks: f64,
    pub divergences: f64,
    pub state_root_commits: f64,
    pub unbound_tx: f64,
    pub unbound_refused: f64,
    pub straggler_grace_extends: f64,
}

impl Snapshot {
    /// JSON encoding, for the explorer's stats endpoint.
    pub fn to_json(&self) -> String {
        json!({
            "consensus_round": self.round,
            "consensus_height": self.height,
            "mempool_size": self.mempool_size,
            "validator_set_size": self.validator_set_size,
            "validator_power_total": self.validator_power_total,
            "validator_quorum_power": self.validator_quorum_power,
            "validator_set_fragile": self.validator_set_fragile,
            "data_dir_bytes": self.data_dir_bytes,
            "snapshot_count": self.snapshot_count,
            "state_entries": self.state_entries,
            "persist_queue_depth": self.persist_queue_depth,
            "persist_queue_dropped": self.persist_queue_dropped,
            "votes_prevote": self.votes_prevote,
            "votes_precommit": self.votes_precommit,
            "forks": self.forks,
            "divergences": self.divergences,
            "state_root_commits": self.state_root_commits,
            "unbound_tx": self.unbound_tx,
            "unbound_refused": self.unbound_refused,
            "straggler_grace_extends": self.straggler_grace_extends,
        })
        .to_string()
    }
}

// ============================================================================
// Build identity
// ============================================================================
//
// One `BUILD_HASH` per deploy window (session 2026-10-14 §8.4): every binary
// shipped in a window carries the same hash, and the live versions of all
// nodes are recorded in `docs/handoff/LIVE_VERSIONS.txt` at deploy time.
//
// A `build.rs` may set `STELL_BUILD_HASH` / `STELL_BUILD_DIRTY` via
// `cargo:rustc-env`. There is no build script today, so the compile-time
// values fall back to `CARGO_PKG_VERSION` + `"unknown"`, and the gateway
// resolves the git hash once at runtime (see [`build_hash_resolved`]).

/// Crate version (`Cargo.toml`): always present, no build script needed.
pub const BUILD_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Git hash baked in by the build script, when one exists.
pub fn build_hash_compile_time() -> &'static str {
    option_env!("STELL_BUILD_HASH").unwrap_or("unknown")
}

/// Dirty flag baked in by the build script, when one exists.
pub fn build_dirty_compile_time() -> &'static str {
    option_env!("STELL_BUILD_DIRTY").unwrap_or("unknown")
}

/// Best-effort runtime git hash, logged once.
///
/// Precedence: compile-time `STELL_BUILD_HASH` (build script) →
/// `STELL_BUILD_HASH` env at runtime → `git rev-parse --short HEAD` in the
/// process working directory → `"unknown"`. The resolution runs at most once
/// per process (the deploy-time value cannot change under a running binary)
/// and is logged once so the fallback is visible in journals.
pub fn build_hash_resolved() -> String {
    static RESOLVED: OnceLock<String> = OnceLock::new();
    RESOLVED
        .get_or_init(|| {
            let hash = if build_hash_compile_time() != "unknown" {
                build_hash_compile_time().to_string()
            } else if let Ok(env_hash) = std::env::var("STELL_BUILD_HASH") {
                let trimmed = env_hash.trim().to_string();
                if trimmed.is_empty() {
                    "unknown".to_string()
                } else {
                    trimmed
                }
            } else {
                std::process::Command::new("git")
                    .args(["rev-parse", "--short", "HEAD"])
                    .output()
                    .ok()
                    .filter(|o| o.status.success())
                    .and_then(|o| String::from_utf8(o.stdout).ok())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "unknown".to_string())
            };
            tracing::info!(
                "[build] version={} hash={} dirty={}",
                BUILD_VERSION,
                hash,
                build_dirty_resolved()
            );
            hash
        })
        .clone()
}

/// Best-effort runtime dirty flag (no `git` invocation: `git diff` on a live
/// checkout is slow and racy; `"unknown"` unless a build script or the
/// `STELL_BUILD_DIRTY` env says otherwise).
pub fn build_dirty_resolved() -> String {
    if build_dirty_compile_time() != "unknown" {
        return build_dirty_compile_time().to_string();
    }
    std::env::var("STELL_BUILD_DIRTY")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// JSON build identity for the `/api/version` endpoint.
pub fn build_info_json() -> serde_json::Value {
    json!({
        "version": BUILD_VERSION,
        "git_hash": build_hash_resolved(),
        "dirty": build_dirty_resolved(),
    })
}

/// The two BFT vote phases, mirroring `consensus::VoteKind`.
///
/// Declared here rather than imported so this module stays free of a
/// dependency on the consensus engine — a metrics registry that cannot be
/// compiled without the thing it measures is harder to test and to reuse from
/// the sync path. The `as_str` values are the label values in the exposition
/// and are part of the scrape contract: renaming one breaks every dashboard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoteKind {
    Prevote,
    Precommit,
}

impl VoteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prevote => "prevote",
            Self::Precommit => "precommit",
        }
    }
}

impl From<crate::consensus::VoteKind> for VoteKind {
    fn from(k: crate::consensus::VoteKind) -> Self {
        use crate::consensus::VoteKind as Engine;
        match k {
            Engine::Prevote => Self::Prevote,
            Engine::Precommit => Self::Precommit,
        }
    }
}

// ============================================================================
// Size-based rotating log writer
// ============================================================================
//
// Node logs grow unbounded (7 MB/hour observed): without rotation a
// long-running node fills its disk and dies. This is a dependency-free,
// line-safe rotating writer. It lives in this module — not in `explorer` —
// because it is process infrastructure, not gateway logic.
//
// Guarantees:
//
//  * rotates by size: once the active file would exceed `max_bytes`, the
//    chain `<base>.1 .. <base>.(max_files-1)` shifts down, `<base>` becomes
//    `<base>.1`, and a fresh `<base>` is opened. At most `max_files` files
//    (active + rotated) ever exist, so disk use is bounded by
//    `max_files * max_bytes` plus one line.
//  * never loses a line mid-rotation: `write_line` rotates BEFORE the write
//    when the line would overflow, so a line always lands whole in exactly
//    one file. (The raw `io::Write` impl rotates on byte boundaries instead —
//    it cannot lose bytes, but only `write_line` keeps lines intact. Log
//    through `write_line`, or through `tracing`, which writes whole events.)
//  * a single line larger than `max_bytes` still lands whole in a fresh file
//    rather than being split or dropped.
//
// Env tuning (see [`SizeRotatingWriter::from_env`]):
//
// | variable | default | meaning |
// |---|---|---|
// | `STELL_LOG_MAX_BYTES` | `10485760` (10 MiB) | rotate once the active file exceeds this |
// | `STELL_LOG_MAX_FILES` | `5` | total files kept, active + rotated |

/// Env var for the per-file rotation threshold in bytes.
pub const LOG_MAX_BYTES_ENV: &str = "STELL_LOG_MAX_BYTES";
/// Env var for how many files (active + rotated) are kept.
pub const LOG_MAX_FILES_ENV: &str = "STELL_LOG_MAX_FILES";
/// Default per-file threshold: 10 MiB.
pub const DEFAULT_LOG_MAX_BYTES: u64 = 10 * 1024 * 1024;
/// Default file budget: 1 active + 4 rotated.
pub const DEFAULT_LOG_MAX_FILES: usize = 5;

/// A file that rotates by size, keeping a bounded chain of files.
///
/// Open question the constructor answers once: parent directories are created,
/// and an existing `<base>` is resumed (its current length seeds the budget)
/// rather than truncated, so a restart does not lose the tail.
pub struct SizeRotatingWriter {
    base: std::path::PathBuf,
    max_bytes: u64,
    max_files: usize,
    file: std::fs::File,
    written: u64,
}

impl SizeRotatingWriter {
    /// Open (or resume) `<base>` with an explicit budget.
    pub fn new(
        base: impl Into<std::path::PathBuf>,
        max_bytes: u64,
        max_files: usize,
    ) -> std::io::Result<Self> {
        let base = base.into();
        let max_bytes = max_bytes.max(1);
        let max_files = max_files.max(1);
        if let Some(parent) = base.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let written = std::fs::metadata(&base).map(|m| m.len()).unwrap_or(0);
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&base)?;
        Ok(Self {
            base,
            max_bytes,
            max_files,
            file,
            written,
        })
    }

    /// Open with env-tuned thresholds (`STELL_LOG_MAX_BYTES`,
    /// `STELL_LOG_MAX_FILES`), falling back to the defaults above.
    pub fn from_env(base: impl Into<std::path::PathBuf>) -> std::io::Result<Self> {
        let max_bytes = std::env::var(LOG_MAX_BYTES_ENV)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_LOG_MAX_BYTES);
        let max_files = std::env::var(LOG_MAX_FILES_ENV)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_LOG_MAX_FILES);
        Self::new(base, max_bytes, max_files)
    }

    /// Path of the `index`-th rotated file (`<base>.1`, `<base>.2`, ...).
    pub fn rotated_path(&self, index: usize) -> std::path::PathBuf {
        let mut s = self.base.clone().into_os_string();
        s.push(format!(".{index}"));
        std::path::PathBuf::from(s)
    }

    /// Rotate now: shift the chain down, move `<base>` to `<base>.1`, open a
    /// fresh `<base>`. Called automatically before an overflowing write; also
    /// usable directly (e.g. on SIGHUP, when that is wired up).
    pub fn rotate(&mut self) -> std::io::Result<()> {
        if self.max_files <= 1 {
            // Single-file budget: truncate and start over. Bounded by
            // construction; the alternative (unbounded growth) is the bug.
            self.file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&self.base)?;
            self.written = 0;
            return Ok(());
        }
        // Drop the oldest file that would fall off the budget, then shift the
        // rest down from the oldest so no rename ever clobbers a live file.
        let oldest = self.rotated_path(self.max_files - 1);
        if oldest.exists() {
            let _ = std::fs::remove_file(&oldest);
        }
        for i in (1..self.max_files - 1).rev() {
            let src = self.rotated_path(i);
            if src.exists() {
                std::fs::rename(&src, self.rotated_path(i + 1))?;
            }
        }
        // The open handle still points at the old inode after the rename, so
        // reopen immediately: between the two calls `&mut self` is held and no
        // write can interleave, hence no byte is lost or duplicated.
        if self.base.exists() {
            std::fs::rename(&self.base, self.rotated_path(1))?;
        }
        self.file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.base)?;
        self.written = 0;
        Ok(())
    }

    /// Append one line (a trailing newline is added when missing). Rotates
    /// BEFORE the write when the line would overflow, so the line lands whole
    /// in exactly one file — never split across a rotation boundary.
    pub fn write_line(&mut self, line: &str) -> std::io::Result<()> {
        let needs_nl = !line.ends_with('\n');
        let len = line.len() as u64 + u64::from(needs_nl);
        if self.written > 0 && self.written + len > self.max_bytes {
            self.rotate()?;
        }
        self.file.write_all(line.as_bytes())?;
        if needs_nl {
            self.file.write_all(b"\n")?;
        }
        self.written = self.written.saturating_add(len);
        Ok(())
    }

    /// Bytes written to the active file since it was opened/rotated.
    pub fn written(&self) -> u64 {
        self.written
    }

    /// Active file path.
    pub fn path(&self) -> &std::path::Path {
        &self.base
    }
}

impl std::io::Write for SizeRotatingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        // Byte stream: rotate before overflowing so no byte is lost, but a
        // multi-byte logical line MAY straddle files. Prefer `write_line`.
        if self.written > 0 && self.written + buf.len() as u64 > self.max_bytes {
            self.rotate()?;
        }
        self.file.write_all(buf)?;
        self.written = self.written.saturating_add(buf.len() as u64);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

/// Cloneable, thread-safe handle over [`SizeRotatingWriter`].
///
/// This is the piece `main.rs` hands to `tracing_subscriber`: it is `Clone +
/// Send + io::Write`, so `with_writer(move || log.clone())` compiles, and
/// every tracing event (written as one `write` call per formatted event)
/// passes through the same size budget and rotation.
#[derive(Clone)]
pub struct RotatingLog {
    inner: Arc<Mutex<SizeRotatingWriter>>,
}

impl RotatingLog {
    pub fn new(
        base: impl Into<std::path::PathBuf>,
        max_bytes: u64,
        max_files: usize,
    ) -> std::io::Result<Self> {
        Ok(Self {
            inner: Arc::new(Mutex::new(SizeRotatingWriter::new(
                base, max_bytes, max_files,
            )?)),
        })
    }

    /// Env-tuned constructor; see [`SizeRotatingWriter::from_env`].
    pub fn from_env(base: impl Into<std::path::PathBuf>) -> std::io::Result<Self> {
        Ok(Self {
            inner: Arc::new(Mutex::new(SizeRotatingWriter::from_env(base)?)),
        })
    }

    /// Append one whole line (never split across a rotation).
    pub fn write_line(&self, line: &str) -> std::io::Result<()> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .write_line(line)
    }

    /// Rotate on demand.
    pub fn rotate(&self) -> std::io::Result<()> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .rotate()
    }
}

impl std::io::Write for RotatingLog {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        (&mut *g as &mut SizeRotatingWriter).write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_are_sorted_and_finite() {
        for set in [
            DEFAULT_BLOCK_INTERVAL_BUCKETS,
            DEFAULT_PEER_LATENCY_BUCKETS,
            DEFAULT_BLOCK_TXS_BUCKETS,
        ] {
            assert!(!set.is_empty());
            assert!(
                set.windows(2).all(|w| w[0] < w[1]),
                "bucket bounds must strictly ascend"
            );
            assert!(set.iter().all(|b| b.is_finite() && *b >= 0.0));
        }
    }

    #[test]
    fn sanitize_keeps_line_structure_intact() {
        assert_eq!(sanitize_label_value("peer-1"), "peer-1");
        assert_eq!(sanitize_label_value("a\nb"), "a_b");
        assert_eq!(sanitize_label_value("a\rb"), "a_b");
        assert_eq!(sanitize_label_value("evil\"x"), "evil\\\"x");
        assert_eq!(sanitize_label_value("a\\b"), "a\\\\b");
    }

    #[test]
    fn fmt_f64_spells_non_finite_values_the_prometheus_way() {
        assert_eq!(fmt_f64(1.0), "1");
        assert_eq!(fmt_f64(0.25), "0.25");
        assert_eq!(fmt_f64(f64::INFINITY), "+Inf");
        assert_eq!(fmt_f64(f64::NEG_INFINITY), "-Inf");
        assert_eq!(fmt_f64(f64::NAN), "NaN");
    }

    /// The #288000 hardening: the divergence counter exists, starts at zero,
    /// increments monotonically, and renders in the Prometheus exposition so
    /// `increase(stell_divergence_total[5m]) > 0` is a working alert.
    #[test]
    fn divergence_counter_is_exposed_and_monotonic() {
        let r = Registry::new();
        assert_eq!(r.snapshot().divergences, 0.0);
        r.inc_divergence();
        r.inc_divergence();
        assert_eq!(r.snapshot().divergences, 2.0);
        assert!(r.snapshot().to_json().contains("\"divergences\":2"));
        let text = r.render();
        assert!(
            text.lines()
                .any(|l| l.starts_with("stell_divergence_total ")),
            "stell_divergence_total must be scraped:\n{text}"
        );
    }

}
