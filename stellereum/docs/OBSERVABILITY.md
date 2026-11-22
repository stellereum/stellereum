# Observability: `/health` and `/status`

This document is the contract for the operator health surface served by the
explorer/gateway. It is read-only, lives on the **same listener** as the rest of
the explorer (`STELL_EXPLORER_LISTEN`, default `127.0.0.1:8080`), and inherits
the explorer's per-IP rate limiter and CORS model. It adds no authentication
bypass, no write route and no public bind of its own.

| route | shape | purpose |
|---|---|---|
| `GET /health` | JSON (`stellereum.health.v1`) | one complete health sample for a dashboard/operator |
| `GET /status` | compact HTML | the same sample rendered for a human |
| `GET /healthz` | JSON `{"status":"ok"}` | process liveness only; deliberately does not read state |
| `GET /readyz` | JSON | pre-existing readiness probe (may be 503) |
| `GET /metrics` | Prometheus text | pre-existing scrape surface |

`/health` always returns HTTP **200**. The verdict is inside the payload:
"the endpoint answered" and "the node is healthy" are different questions, and
collapsing them makes a dashboard unable to tell an unreachable node from a
critically stalled one. `/healthz` remains the cheap liveness probe; it never
reads a lock or a chain value.

## Cost and caching

* One sample is cached for `STELL_HEALTH_CACHE_MS` (default **1000 ms**,
  minimum 1). A request inside the TTL returns the cached sample and reports
  `cache.hit=true` plus `cache.age_ms`.
* The cache is **strict**: an entry is stale at the TTL boundary. A stale
  `critical` is never extended as `ok` (or vice versa); the next request
  recomputes and overwrites it. This is pinned by
  `tests/explorer_health_tests.rs::health_cache_never_extends_a_stale_verdict_past_ttl`.
* No request walks the chain, scans the mempool contents, or allocates
  per-transaction data. `recent_blocks` is the bounded (100-entry) finalize
  ring; the finalized-header window is bounded (512).
* The data-directory size scan is the only filesystem work and has its own
  cache (`HEALTH_DATA_DIR_CACHE_TTL_MS = 30 s`) and the existing bounded
  traversal cap (`DATA_DIR_SCAN_FILE_CAP = 100_000`). Set
  `STELL_HEALTH_DISABLED`-style deployments by passing
  `HealthOptions { data_dir: None, .. }`; the endpoint is constructed by
  `GatewayState`, so tests/embedders can disable the scan without an env var.
* Snapshot metadata is two bounded sled key reads (`latest_state_height`,
  `header_at`) performed on a blocking worker, not a snapshot scan.

## Payload schema

Every measured datum is an object with `value`, `unit`, and — when unavailable
— `value: null` and a `reason`. **A missing producer is never encoded as `0`.**
Identity/software fields are plain values because they are not measurements.

```json
{
  "schema": "stellereum.health.v1",
  "sampled_at_ms": 1763540000123,
  "served_at_ms": 1763540000456,
  "cache": { "ttl_ms": 1000, "hit": false, "age_ms": 0 },

  "identity": {
    "chain_id": 5757,
    "protocol_major": 1,
    "protocol_minor": 0,
    "fork_id": 123456789,
    "node_id": "inf1:...",
    "shards": { "value": [0], "unit": "shard ids" },
    "software": {
      "version": "0.1.0",
      "git_hash": "abc1234",
      "dirty": "unknown",
      "string": "stellereum/0.1.0 (abc1234)"
    },
    "timestamp_ms": 1763540000123
  },

  "chain": {
    "height": { "value": 42, "unit": "blocks" },
    "finalized_height": { "value": 42, "unit": "blocks" },
    "network_tip_height": {
      "value": null,
      "unit": "blocks",
      "reason": "no fresh verified peer tip"
    },
    "finalization_lag": {
      "blocks": {
        "value": null,
        "unit": "blocks",
        "reason": "no fresh verified peer tip to compare against"
      },
      "seconds": { "value": 2, "unit": "seconds" },
      "timestamp_ms": 1763540000123
    },
    "blocks_per_second": {
      "value": 1.2,
      "unit": "blocks/second",
      "window_seconds": 60,
      "samples": 12
    },
    "last_finalize_age": { "value": 2, "unit": "seconds" },
    "timestamp_ms": 1763540000123
  },

  "consensus": {
    "round": {
      "value": null,
      "unit": "round",
      "reason": "no consensus round observed (Registry::set_round has no producer)"
    },
    "last_finalized_round": { "value": 41, "unit": "round" },
    "view_changes_last_5m": {
      "value": null,
      "unit": "view changes",
      "reason": "no timestamped view-change counter; ..."
    },
    "rejected_proposals_total": {
      "value": null,
      "unit": "proposals",
      "reason": "no rejected-proposal counter; ..."
    },
    "forks_total": { "value": 0, "unit": "events" },
    "divergences_total": { "value": 0, "unit": "events" },
    "catch_up": {
      "mode": { "value": null, "unit": "mode", "reason": "..." },
      "last_catch_up_age": { "value": null, "unit": "seconds", "reason": "..." }
    },
    "timestamp_ms": 1763540000123
  },

  "p2p": {
    "peer_count": { "value": 3, "unit": "peers" },
    "peer_states": { "value": null, "unit": "peers", "reason": "..." },
    "mesh": {
      "members": { "value": null, "unit": "members", "reason": "..." },
      "direct_targets": { "value": null, "unit": "targets", "reason": "..." },
      "last_delivery": { "value": null, "unit": "outcome", "reason": "..." }
    },
    "bytes": {
      "inbound_total": { "value": null, "unit": "bytes", "reason": "..." },
      "outbound_total": { "value": null, "unit": "bytes", "reason": "..." }
    },
    "timestamp_ms": 1763540000123
  },

  "mempool": {
    "size": { "value": 0, "unit": "transactions" },
    "oldest_pending_age": { "value": null, "unit": "seconds", "reason": "..." },
    "timestamp_ms": 1763540000123
  },

  "storage": {
    "data_dir_bytes": { "value": 123456, "unit": "bytes" },
    "snapshot_files": { "value": 2, "unit": "files" },
    "last_persist_age": { "value": null, "unit": "seconds", "reason": "..." },
    "snapshot": {
      "height": { "value": 40, "unit": "blocks" },
      "lag_blocks": { "value": 2, "unit": "blocks" },
      "age_secs": { "value": 2, "unit": "seconds" }
    },
    "timestamp_ms": 1763540000123
  },

  "verdict": {
    "status": "ok",
    "reasons": [],
    "unknown": [
      "finalization block lag unavailable (no fresh peer tip)",
      "consensus round unavailable",
      "mempool oldest-pending age unavailable",
      "last persist age unavailable",
      "view changes over 5 min unavailable (no timestamped counter)"
    ]
  }
}
```

### Field meanings and sources

| field | meaning | source |
|---|---|---|
| `identity.chain_id` | configured chain id | `RpcState::chain_id` (`src/rpc/state.rs:75`) |
| `identity.protocol_major/minor` | wire protocol version | `src/protocol.rs:51,58` |
| `identity.fork_id` | compile-time consensus-ruleset id | `src/protocol.rs:157` |
| `identity.node_id` | this node's public id | `RpcState::node_id` (`src/rpc/state.rs:74`) |
| `identity.shards` | shards this process runs | `RpcState::shard_registry` (`src/rpc/state.rs:129`), `ShardRegistry::ids` (`src/sharding/topology.rs:292`) |
| `identity.software.*` | crate version, git hash, dirty flag | `src/metrics.rs:1515,1531` |
| `chain.height` | latest **finalized** height published to RPC | `RpcState::height` (`src/rpc/state.rs:72`), written by `record_block` (`src/rpc/state.rs:442`) |
| `chain.finalized_height` | same finalized head; `null` at height 0 | `RpcState::height` |
| `chain.network_tip_height` | highest VERIFIED peer-reported height, only if fresh (<300 s) | `fresh_peer_height` (`src/rpc/state.rs:222`) |
| `chain.finalization_lag.blocks` | network tip minus local finalized height | derived from the two fields above |
| `chain.finalization_lag.seconds` | wall-clock age of the last local finalization | latest `recent_blocks` timestamp; `record_block` stores `now_secs()` as the finalize time (`src/rpc/state.rs:442`) |
| `chain.blocks_per_second` | `(samples-1) / span` of finalize timestamps in the last 60 s | `recent_blocks` (bounded 100) |
| `chain.last_finalize_age` | seconds since the newest finalize timestamp | same |
| `consensus.round` | current engine round, **only if a producer has set a positive value** | `Registry::snapshot().round` (`src/metrics.rs:1169`); no production `set_round` today |
| `consensus.last_finalized_round` | round of the newest quorum-certified header | `finalized_headers()` (`src/rpc/state.rs:486`) |
| `consensus.forks_total` / `divergences_total` | cumulative counters that DO have producers | `Registry::snapshot()` |
| `p2p.peer_count` | connected peers observed by this process (`0` = none observed) | `rpc::LIVE_PEER_COUNT` (`src/rpc/state.rs:243,255`), fed by `publish_live_peer_count` (`src/network.rs:4493`) |
| `mempool.size` | pending transactions | `Mempool::len` via `RpcState::mempool` |
| `mempool.oldest_pending_age` | age of the oldest admission stamp in the pool, **not** of any transaction contents | `Mempool::oldest_pending_age_secs` (`src/mempool.rs`); `None` only when the pool is empty |
| `storage.data_dir_bytes` | metadata size under `STELL_DATA_DIR`/`./data`, cached 30 s | `data_dir_stats` (`src/explorer.rs:3241`) |
| `storage.snapshot.height` | newest durable state snapshot height | `Storage::latest_state_height` (`src/storage.rs:987`) |
| `storage.snapshot.lag_blocks` | finalized height minus snapshot height | derived |
| `storage.snapshot.age_secs` | write age once `last_snapshot_ms` has a producer; else age of the snapshot's stored block timestamp (content age) | `metrics::snapshot_last_snapshot_ms` or `Storage::header_at` (`src/storage.rs:636`) |
| `verdict` | pure function of the fields above | `evaluate_verdict` (`src/explorer.rs:600`) |

## Verdict rules

The verdict is a **pure function** of the reported fields plus the thresholds.
It never reads a clock, an env var at evaluation time, or hidden state. It is
table-tested in `tests/explorer_health_tests.rs`.

Thresholds (all `STELL_HEALTH_*`, all optional):

| variable | default | meaning |
|---|---|---|
| `STELL_HEALTH_MAX_FINALIZATION_LAG_SECS` | `5` | lag above which the node is `degraded` |
| `STELL_HEALTH_CRITICAL_FINALIZATION_LAG_SECS` | `60` | lag above which the node is `critical` |
| `STELL_HEALTH_MAX_FINALIZATION_LAG_BLOCKS` | `5` | network-tip gap above which `degraded` |
| `STELL_HEALTH_MIN_PEERS` (falls back to `STELL_READY_MIN_PEERS`) | `1` | peers required for `ok`; `0` for solo/dev |
| `STELL_HEALTH_MAX_MEMPOOL_AGE_SECS` | `300` | oldest pending tx age for `degraded` |
| `STELL_HEALTH_MAX_PERSIST_AGE_SECS` | `120` | last successful persist age for `degraded` |
| `STELL_HEALTH_MAX_SNAPSHOT_AGE_SECS` | `3600` | snapshot content age for `degraded` |
| `STELL_HEALTH_CACHE_MS` | `1000` | `/health` sample TTL |

Evaluation order:

1. **critical** if any critical reason exists:
   * `finalization lag N s > CRITICAL s` (seconds);
   * `0 peers observed (minimum M)` when `M > 0`.
2. **degraded** if no critical reason but any degraded reason exists:
   * `height 0: no finalized block yet`;
   * `no finalized block observed`;
   * `finalization lag N s > MAX s`;
   * `finalization lag N blocks > MAX blocks`;
   * `N peers < minimum M`;
   * `oldest mempool tx N s > MAX s`;
   * `last persist age N s > MAX s`;
   * `snapshot age N s > MAX s`;
   * `height unavailable`, `peer count unavailable`, `mempool size unavailable`.
3. **ok** only when no critical/degraded reason exists.

`verdict.reasons` contains the exact reasons that produced the status, with the
crossed threshold quoted (e.g. `"finalization lag 14 s > 5 s"`). `ok` carries an
empty `reasons` list. `verdict.unknown` lists diagnostics that are unavailable
but are **not** required for the measured checks (for example the current
consensus round, view-change rate, per-peer state). Missing diagnostics never
turn into a fabricated zero and never silently disappear.

## Deliberately NOT included

* **No keys, seeds, tokens, passwords or signing material.** Software identity
  is version/hash only.
* **No peer IP addresses or endpoints.** The payload exposes this node's
  aggregate peer count; per-peer identity/state is not exported until a global
  snapshot exists. The configured peer set itself is not echoed.
* **No transaction contents, senders, receivers, mempool hashes or balances.**
  Only the pool size (and, once the accessor exists, an age).
* **No chain scan / archive contents.** Snapshots are represented by height and
  bounded metadata only; no block bodies, receipts or state values.
* **No auth credentials or request headers.**
* **No write endpoint.** `/health` and `/status` are `GET`-only and read-only.
* `/health` does not expose the data-directory path, env values, or error
  strings from storage beyond a generic reason.

## Missing instrumentation (reported, not invented)

The payload currently returns `null` + a `reason` for these data. The minimal
producer to add is named here so the owner of that subsystem can wire it:

| datum | current state | minimal addition |
|---|---|---|
| current consensus round | `Registry::set_round` has no production caller (`src/metrics.rs:844`) | call it once per tick in `src/node/consensus_driver.rs` where the engine round is known |
| view changes last 5 min | cumulative counter defined (phase 1) but no writer or 5-min window | increment `metrics::record_view_change_at` in the engine's view-change path and read `metrics::view_changes_last_5m` |
| rejected proposals | only a warning log (`src/node/consensus_driver.rs:2988`) | increment `metrics::record_rejected_proposal()` in that `Err` arm (counter defined in phase 1) |
| catch-up mode / last catch-up age | driver-local `policy::catchup_action` result (`src/node/consensus_driver.rs:1596`) | publish via `explorer::health_signals` (see Phase 2 wiring) |
| per-peer live/suspected/cooldown | `peer_health` map is instance-local (`src/consensus_net.rs:707`) | publish a bounded snapshot (id prefix + state only, **no endpoints**) |
| mesh members/direct targets/last delivery | `ValidatorMesh` is instance-local (`src/network.rs:699,719`); `MeshDelivery` result is per-call (`src/network.rs:880`) | publish the latest counts/outcome via `explorer::health_signals` |
| inbound/outbound byte totals | counters defined (phase 1) but no writers | call `metrics::record_bytes_inbound/outbound` on the admit/send paths |
| mempool oldest pending age | **shipped in phase 1** | `pub fn oldest_pending_age_secs(&self, now_secs: u64) -> Option<u64>`; `/health` reads it |
| last persist age | `AsyncPersistence` tracks queue depth only (`src/storage.rs:3244`) | store `record_last_persist_ms` after a successful writer job |
| snapshot write age | storage exposes the height, not the write time | call `record_last_snapshot_ms` after a successful `State`/`Domains` job |

Until those producers exist, the endpoint says `null` **with a reason**. That
is intentional: an operator dashboard must be able to trust an `ok`, and a
fabricated zero would make it untrustworthy. Phase 1 ships the mempool
accessor and the counter *definitions* only; no phase-2 file is touched here.

## Phase 2 wiring

Everything below is **not implemented in phase 1**; it is the exact plan for the
files owned by the other agent. Line numbers are HEAD anchors (the quoted
symbol/expression is the durable reference). Phase 1 already provides:

* `metrics::record_{view_change, rejected_proposal, bytes_inbound,
  bytes_outbound, last_persist_ms, last_snapshot_ms}` and the matching
  `metrics::snapshot_*` accessors — all `None` until the first write;
* `Mempool::oldest_pending_age_secs`, already read by `collect_health`;
* honest `null` + reason for every counter that still has no writer.

### Helper block A — `stellereum/src/metrics.rs` (5-minute view-change window)

Insert immediately after `pub static HEALTH_COUNTERS` (metrics.rs:1376). The
cumulative `view_changes_total` stays as-is; this adds the windowed read:

```rust
struct ViewWindow {
    lock: AtomicBool,
    minutes: [AtomicU64; 5],
    counts: [AtomicU64; 5],
    seen: AtomicBool,
}

impl ViewWindow {
    const fn new() -> Self {
        Self {
            lock: AtomicBool::new(false),
            minutes: [AtomicU64::new(0); 5],
            counts: [AtomicU64::new(0); 5],
            seen: AtomicBool::new(false),
        }
    }
    fn acquire(&self) {
        while self
            .lock
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            std::hint::spin_loop();
        }
    }
    fn release(&self) {
        self.lock.store(false, Ordering::Release);
    }
    fn record(&self, now_ms: u64) {
        self.acquire();
        let minute = now_ms / 60_000;
        let slot = (minute % 5) as usize;
        if self.minutes[slot].load(Ordering::Relaxed) != minute {
            self.minutes[slot].store(minute, Ordering::Relaxed);
            self.counts[slot].store(0, Ordering::Relaxed);
        }
        let c = self.counts[slot].load(Ordering::Relaxed);
        self.counts[slot].store(c.saturating_add(1), Ordering::Relaxed);
        self.seen.store(true, Ordering::Release);
        self.release();
    }
    fn last_5m(&self, now_ms: u64) -> Option<u64> {
        if !self.seen.load(Ordering::Acquire) {
            return None;
        }
        self.acquire();
        let now_minute = now_ms / 60_000;
        let mut total = 0u64;
        for back in 0..5u64 {
            let minute = now_minute.saturating_sub(back);
            let slot = (minute % 5) as usize;
            if self.minutes[slot].load(Ordering::Relaxed) == minute {
                total = total.saturating_add(self.counts[slot].load(Ordering::Relaxed));
            }
        }
        self.release();
        Some(total)
    }
}

static VIEW_WINDOW: ViewWindow = ViewWindow::new();

/// Phase-2 writer entry point: cumulative counter + 5 one-minute buckets.
pub fn record_view_change_at(now_ms: u64) {
    HEALTH_COUNTERS.record_view_change();
    VIEW_WINDOW.record(now_ms);
}

/// `None` until the first view change; then the count in the last 5 minutes.
pub fn view_changes_last_5m(now_ms: u64) -> Option<u64> {
    VIEW_WINDOW.last_5m(now_ms)
}
```

### Helper block B — `stellereum/src/explorer.rs` (instance-owned signals)

Insert above `collect_health` (explorer.rs:2638). No endpoint or key material
is exported; peer rows carry a **hex id prefix only**.

```rust
/// Process-global signals whose owners are driver/network instances.
pub mod health_signals {
    use std::sync::{Mutex, OnceLock};

    #[derive(Default)]
    struct Signals {
        catch_up_mode: Option<String>,
        catch_up_at_ms: Option<u64>,
        peers: Option<Vec<serde_json::Value>>,
        mesh: Option<(u64, u64)>,
        mesh_last: Option<String>,
    }

    static SIGNALS: OnceLock<Mutex<Signals>> = OnceLock::new();

    fn signals() -> &'static Mutex<Signals> {
        SIGNALS.get_or_init(|| Mutex::new(Signals::default()))
    }
    fn update(f: impl FnOnce(&mut Signals)) {
        if let Ok(mut s) = signals().lock() {
            f(&mut s);
        }
    }
    pub fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
    pub fn record_catch_up_mode(mode: &str) {
        update(|s| s.catch_up_mode = Some(mode.to_string()));
    }
    pub fn record_catch_up_run(at_ms: u64) {
        update(|s| s.catch_up_at_ms = Some(at_ms));
    }
    /// `rows` = `(hex id prefix, consecutive failures)`; capped at 32 rows.
    pub fn record_peer_health(rows: impl IntoIterator<Item = (String, u32)>) {
        let mut v: Vec<_> = rows
            .into_iter()
            .take(32)
            .map(|(id, fails)| {
                serde_json::json!({
                    "peer": id,
                    "state": if fails == 0 { "live" } else if fails < 3 { "failing" } else { "cooldown" },
                    "fails": fails,
                })
            })
            .collect();
        v.sort_by(|a, b| a["peer"].as_str().cmp(&b["peer"].as_str()));
        update(|s| s.peers = Some(v));
    }
    pub fn record_mesh(members: u64, targets: u64) {
        update(|s| s.mesh = Some((members, targets)));
    }
    pub fn record_mesh_delivery(targets: u64, ok: u64, failed: u64, fallback_ok: bool) {
        update(|s| {
            s.mesh_last = Some(format!(
                "{ok}/{targets} direct, {failed} failed, fallback {}",
                if fallback_ok { "ok" } else { "not used/failed" }
            ))
        });
    }
    pub fn catch_up() -> (Option<String>, Option<u64>) {
        signals()
            .lock()
            .map(|s| (s.catch_up_mode.clone(), s.catch_up_at_ms))
            .unwrap_or((None, None))
    }
    pub fn peers() -> Option<Vec<serde_json::Value>> {
        signals().lock().ok().and_then(|s| s.peers.clone())
    }
    pub fn mesh() -> (Option<u64>, Option<u64>) {
        signals()
            .lock()
            .ok()
            .and_then(|s| s.mesh)
            .map_or((None, None), |(m, t)| (Some(m), Some(t)))
    }
    pub fn mesh_last() -> Option<String> {
        signals().lock().ok().and_then(|s| s.mesh_last.clone())
    }
}
```

### Producer insertions (phase-2 files)

| datum | exact insertion point (HEAD) | change (1–3 lines) |
|---|---|---|
| current round | `node/consensus_driver.rs:1484`, after `let round = rt.hc.round;` | `crate::metrics::global().set_round(round);` |
| view changes / 5 min | `consensus/engine.rs:2315`, after `self.round = self.round.saturating_add(1);` | `crate::metrics::record_view_change_at(crate::zkml::now_secs().saturating_mul(1000));` |
| rejected proposals | `node/consensus_driver.rs:2988`, first line of `Err(e) => {` | `crate::metrics::record_rejected_proposal();` |
| catch-up mode | `node/consensus_driver.rs:1601`, after the `catchup_action(...)` call closes | `crate::explorer::health_signals::record_catch_up_mode(&format!("{catchup_decision:?}"));` |
| catch-up age | `node/consensus_driver.rs:1624`, after `last_catchup = std::time::Instant::now();` | `crate::explorer::health_signals::record_catch_up_run(crate::explorer::health_signals::now_ms());` |
| per-peer health | `consensus_net.rs:1338`, inside the `Ok(mut h)` arm of `record_health`, after the `if ok { … } else { … }` block | `crate::explorer::health_signals::record_peer_health(h.iter().map(\|(id, p)\| (hex::encode(&id[..6]), p.fails)));` |
| mesh members/targets | `network.rs:881`, after `let targets = self.direct_targets(now_ms);` | `crate::explorer::health_signals::record_mesh(self.len() as u64, targets.len() as u64);` |
| mesh last delivery | `network.rs:924`, immediately before the final `delivery` expression | `crate::explorer::health_signals::record_mesh_delivery(delivery.targets as u64, delivery.direct_ok as u64, delivery.direct_failed as u64, delivery.fallback_ok);` |
| bytes inbound | `consensus_net.rs:6724`, after `shed.observe(bytes as u64, now);` | `crate::metrics::record_bytes_inbound(bytes as u64);` |
| bytes outbound (per-peer) | `consensus_net.rs:1971`, after `let t = std::time::Instant::now();` (payload still owned) | `crate::metrics::record_bytes_outbound(payload.len() as u64);` |
| bytes outbound (mesh direct) | `network.rs:895`, inside the `Ok(())` arm before `delivery.direct_ok += 1;` | `crate::metrics::record_bytes_outbound(data.len() as u64);` |
| oldest pending age | **shipped in phase 1** | no phase-2 change; `collect_health` reads `Mempool::oldest_pending_age_secs(now_secs)` |
| last persist | `storage.rs:3478`, after `decrement_queue_depth(&depth_worker);` and before `let res = match job {` | `let is_snapshot_job = matches!(&job, PersistJob::State { .. } \| PersistJob::Domains { .. });` |
| last persist / snapshot stamp | `storage.rs:3531`, after the `let res = match job { … };` expression and before `if let Err(e) = res {` | `if res.is_ok() { let now_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(\|d\| d.as_millis() as u64).unwrap_or(0); crate::metrics::record_last_persist_ms(now_ms); if is_snapshot_job { crate::metrics::record_last_snapshot_ms(now_ms); } }` |

### Reader patches — `stellereum/src/explorer.rs`

1. At the top of `collect_health`, next to the other reads:
   `let (catch_up_mode, catch_up_at_ms) = health_signals::catch_up();`
   `let (mesh_members, mesh_targets) = health_signals::mesh();`
2. `consensus.view_changes_last_5m` (explorer.rs:2868): replace the
   `Measured::missing(...)` with
   `measured_u64(crate::metrics::view_changes_last_5m(now_ms), "view changes", "no view change recorded yet")`.
3. `consensus.catch_up` (explorer.rs:2879–2887):
   `mode: catch_up_mode.map(|m| Measured::observed(m, "mode")).unwrap_or_else(|| Measured::missing("mode", "no catch-up decision recorded yet"))`;
   `last_catch_up_age: measured_u64(catch_up_at_ms.map(|ms| now_ms.saturating_sub(ms) / 1000), "seconds", "no catch-up run recorded yet")`.
4. `p2p.peer_states` (explorer.rs:2894): replace `Measured::missing(...)` with
   `health_signals::peers().map(|rows| Measured::observed(rows, "peers")).unwrap_or_else(|| Measured::missing("peers", "no peer health outcome recorded yet"))`.
5. `p2p.mesh` (explorer.rs:2898–2910):
   `members: measured_u64(mesh_members, "members", "no mesh snapshot recorded yet")`,
   `direct_targets: measured_u64(mesh_targets, "targets", "no mesh snapshot recorded yet")`,
   `last_delivery: health_signals::mesh_last().map(|d| Measured::observed(d, "outcome")).unwrap_or_else(|| Measured::missing("outcome", "no mesh delivery recorded yet"))`.
6. `storage.last_persist_age` and `storage.snapshot.age_secs`, and
   `consensus.rejected_proposals_total` / `p2p.bytes.*`, already read the
   phase-1 accessors — no reader change is needed once the writers land.

## Tests

* `tests/explorer_health_tests.rs::verdict_is_pure_and_table_tested` — table of
  ok/degraded/critical cases, including the exact lag reason.
* `tests/explorer_health_tests.rs::health_endpoint_is_shaped_and_safe_on_a_fresh_node`
  — fresh node (height 0, empty mempool, no storage/peers) returns 200, the
  documented fields, `null` + reasons, and no panic.
* `tests/explorer_health_tests.rs::health_reports_degraded_when_finalization_lag_exceeds_threshold`
  — a 14 s finalize age against a 5 s threshold yields `degraded` with
  `"finalization lag ... > 5 s"`.
* `tests/explorer_health_tests.rs::health_cache_never_extends_a_stale_verdict_past_ttl`
  — the cache serves an old sample only inside the TTL; after it, both a stale
  `critical` and a stale `ok` are replaced by a fresh evaluation.
* `tests/explorer_smoke_tests.rs` — `/healthz` remains the liveness probe and
  `/health` serves the v1 schema over real HTTP.
