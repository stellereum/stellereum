use crate::db::{
    normalize_contract_key, to_stl57, BlockRecord, ContractRecord, Database, EventRecord,
    TokenBalanceRecord, TxRecord,
};
use crate::events::{event_from_json, AbiCache, RawEvent};
use crate::server::{IndexerStreamHub, StreamPublishInput};
use anyhow::Result;
use reqwest::Client;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Notify, RwLock};
use tracing::{info, warn};

/// Maximum buffered bytes per SSE frame/chunk sequence in the node push client
/// (OOM bound against malformed or unbounded event streams).
pub const MAX_SSE_EVENT_BYTES: usize = 1024 * 1024;

/// Idle read timeout for the node SSE subscription before triggering reconnect
/// + HTTP backfill fallback.
pub const SSE_READ_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

const SSE_RECONNECT_BASE: Duration = Duration::from_secs(1);
const SSE_RECONNECT_MAX: Duration = Duration::from_secs(5);

/// Live sync health shared between `Syncer` and `AppState`.
#[derive(Clone, Debug, Default)]
pub struct SyncStatus {
    pub node_tip_height: Option<u64>,
    pub last_sync_at: Option<u64>,
    pub last_error: Option<String>,
}

/// One parsed Server-Sent Event frame from the node's `/events` endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SseFrame {
    pub event: Option<String>,
    pub id: Option<String>,
    pub data: String,
}

/// Bounded incremental SSE parser over arbitrary TCP/HTTP chunks.
pub struct SseFrameParser {
    buf: Vec<u8>,
    event: Option<String>,
    id: Option<String>,
    data_lines: Vec<String>,
    max_bytes: usize,
}

impl Default for SseFrameParser {
    fn default() -> Self {
        Self::new()
    }
}

impl SseFrameParser {
    pub fn new() -> Self {
        Self::with_max_bytes(MAX_SSE_EVENT_BYTES)
    }

    pub fn with_max_bytes(max_bytes: usize) -> Self {
        Self {
            buf: Vec::new(),
            event: None,
            id: None,
            data_lines: Vec::new(),
            max_bytes: max_bytes.max(64),
        }
    }

    /// Feed a raw HTTP body chunk and return any complete SSE frames.
    /// Fails closed (clears internal state and returns `Err`) if buffered bytes
    /// exceed `max_bytes`.
    pub fn feed(&mut self, chunk: &[u8]) -> std::result::Result<Vec<SseFrame>, String> {
        let pending_data_bytes: usize = self.data_lines.iter().map(String::len).sum();
        if self
            .buf
            .len()
            .saturating_add(chunk.len())
            .saturating_add(pending_data_bytes)
            > self.max_bytes
        {
            self.buf.clear();
            self.event = None;
            self.id = None;
            self.data_lines.clear();
            return Err(format!(
                "SSE frame buffer exceeded {} bytes",
                self.max_bytes
            ));
        }
        self.buf.extend_from_slice(chunk);

        let mut frames = Vec::new();
        while let Some(pos) = self.buf.iter().position(|b| *b == b'\n') {
            let mut line_bytes: Vec<u8> = self.buf.drain(..=pos).collect();
            if line_bytes.last() == Some(&b'\n') {
                line_bytes.pop();
            }
            if line_bytes.last() == Some(&b'\r') {
                line_bytes.pop();
            }
            let line = String::from_utf8_lossy(&line_bytes);
            if line.is_empty() {
                if !self.data_lines.is_empty() || self.event.is_some() {
                    frames.push(SseFrame {
                        event: self.event.take(),
                        id: self.id.take(),
                        data: self.data_lines.join("\n"),
                    });
                    self.data_lines.clear();
                } else {
                    self.event = None;
                    self.id = None;
                }
                continue;
            }
            if line.starts_with(':') {
                continue;
            }
            let (field, value) = match line.split_once(':') {
                Some((f, v)) => (f, v.strip_prefix(' ').unwrap_or(v)),
                None => (line.as_ref(), ""),
            };
            match field {
                "event" => self.event = Some(value.to_string()),
                "data" => self.data_lines.push(value.to_string()),
                "id" => self.id = Some(value.to_string()),
                _ => {}
            }
        }
        Ok(frames)
    }
}

/// Typed representation of a node Geyser-lite SSE notification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeSseEvent {
    NewHead {
        shard_id: u32,
        height: u64,
        hash: String,
    },
    Invalidation {
        height: Option<u64>,
        orphaned_blocks: Vec<String>,
        reason: Option<String>,
    },
    Lagged {
        skipped: u64,
        oldest_available_seq: Option<u64>,
    },
    NewTx,
    ContractEvent,
    Other,
}

/// Reason an SSE stream read loop returned cleanly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SseDisconnectReason {
    Closed,
    Lagged,
}

/// Parse one [`SseFrame`] emitted by the node's `/events` stream.
pub fn parse_node_sse_frame(frame: &SseFrame) -> Option<NodeSseEvent> {
    if frame.event.as_deref() == Some("lagged") {
        let val: Value = serde_json::from_str(&frame.data).unwrap_or(Value::Null);
        let skipped = val["lagged"].as_u64().unwrap_or(0);
        let oldest = val["oldest_available_seq"].as_u64();
        return Some(NodeSseEvent::Lagged {
            skipped,
            oldest_available_seq: oldest,
        });
    }

    let trimmed = frame.data.trim();
    if trimmed.is_empty() {
        return None;
    }
    let val: Value = serde_json::from_str(trimmed).ok()?;
    if val.get("lagged").is_some() {
        return Some(NodeSseEvent::Lagged {
            skipped: val["lagged"].as_u64().unwrap_or(0),
            oldest_available_seq: val["oldest_available_seq"].as_u64(),
        });
    }

    let payload = val.get("result").unwrap_or(&val);
    if let Some(arr) = payload.get("orphaned_blocks").and_then(|v| v.as_array()) {
        let orphaned_blocks = arr
            .iter()
            .filter_map(|v| v.as_str().map(str::trim))
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        return Some(NodeSseEvent::Invalidation {
            height: payload.get("height").and_then(|v| v.as_u64()),
            orphaned_blocks,
            reason: payload
                .get("reason")
                .and_then(|v| v.as_str())
                .map(str::to_string),
        });
    }

    if let (Some(height), Some(hash)) = (
        payload.get("height").and_then(|v| v.as_u64()),
        payload.get("hash").and_then(|v| v.as_str()),
    ) {
        if payload.get("from").is_none() && payload.get("tx_hash").is_none() {
            let shard_id = payload
                .get("shard_id")
                .or_else(|| val.get("shard_id"))
                .and_then(|v| v.as_u64())
                .and_then(|v| u32::try_from(v).ok())
                .unwrap_or(0);
            return Some(NodeSseEvent::NewHead {
                shard_id,
                height,
                hash: hash.to_string(),
            });
        }
    }

    if payload.get("contract").and_then(|v| v.as_str()).is_some()
        && (payload.get("topics").is_some()
            || payload.get("topic0").is_some()
            || payload.get("topic").is_some())
    {
        return Some(NodeSseEvent::ContractEvent);
    }

    if payload.get("from").is_some()
        && payload.get("to").is_some()
        && (payload.get("hash").is_some() || payload.get("tx_hash").is_some())
    {
        return Some(NodeSseEvent::NewTx);
    }

    Some(NodeSseEvent::Other)
}

pub struct Syncer {
    db: Database,
    client: Client,
    sse_client: Client,
    node_url: String,
    rpc_url: String,
    /// The contract ABI manifests the indexer knows about. They are what makes
    /// the indexed events DECODED instead of raw.
    abis: Arc<AbiCache>,
    sync_status: Arc<RwLock<SyncStatus>>,
    stream_hub: Arc<IndexerStreamHub>,
}

/// How many receipts of one block are fetched at the same time.
const RECEIPT_FETCH_CONCURRENCY: usize = 8;

/// Upper bound on the receipts fetched per block (a pathological block cannot
/// make the indexer open an unbounded number of connections).
const MAX_RECEIPTS_PER_BLOCK: usize = 256;

/// Maximum blocks backfilled in a single sync tick so catch-up stays bounded.
const MAX_BACKFILL_PER_TICK: u64 = 64;

/// Concurrency for RPC block fetches during backfill catch-up.
const BACKFILL_FETCH_CONCURRENCY: usize = 8;

impl Syncer {
    pub fn new(db: Database, node_url: String, rpc_url: String) -> Self {
        Self::new_with_abis(db, node_url, rpc_url, Arc::new(AbiCache::new()))
    }

    /// A syncer that shares the ABI cache with the API server, so the API can
    /// decode an event whose manifest was fetched after the event was indexed.
    pub fn new_with_abis(
        db: Database,
        node_url: String,
        rpc_url: String,
        abis: Arc<AbiCache>,
    ) -> Self {
        Self::new_with_state(
            db,
            node_url,
            rpc_url,
            abis,
            Arc::new(RwLock::new(SyncStatus::default())),
        )
    }

    pub fn new_with_state(
        db: Database,
        node_url: String,
        rpc_url: String,
        abis: Arc<AbiCache>,
        sync_status: Arc<RwLock<SyncStatus>>,
    ) -> Self {
        Self {
            db,
            client: Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap_or_else(|_| Client::new()),
            sse_client: Client::builder()
                .connect_timeout(Duration::from_secs(5))
                .build()
                .unwrap_or_else(|_| Client::new()),
            node_url,
            rpc_url,
            abis,
            sync_status,
            stream_hub: Arc::new(IndexerStreamHub::new()),
        }
    }

    pub fn with_stream_hub(mut self, stream_hub: Arc<IndexerStreamHub>) -> Self {
        self.stream_hub = stream_hub;
        self
    }

    /// The ABI cache this syncer fills.
    pub fn abis(&self) -> Arc<AbiCache> {
        Arc::clone(&self.abis)
    }

    pub fn sync_status(&self) -> Arc<RwLock<SyncStatus>> {
        Arc::clone(&self.sync_status)
    }

    pub fn stream_hub(&self) -> Arc<IndexerStreamHub> {
        Arc::clone(&self.stream_hub)
    }

    pub async fn run(&self) {
        info!("Starting Stellereum Lightweight Indexer Syncer loop (SSE push + 400ms HTTP backfill fallback)...");
        let wake = Arc::new(Notify::new());
        let sse_fut = self.sse_push_loop(&wake);
        let poll_fut = self.poll_and_backfill_loop(&wake);
        tokio::join!(sse_fut, poll_fut);
    }

    async fn poll_and_backfill_loop(&self, wake: &Notify) {
        let mut interval = tokio::time::interval(Duration::from_millis(400));
        loop {
            match self.sync_step().await {
                Ok(caught_up) => {
                    if !caught_up {
                        // Still catching up: yield and immediately run the next backfill batch.
                        tokio::task::yield_now().await;
                        continue;
                    }
                }
                Err(e) => {
                    warn!("[syncer] sync step warning: {e}");
                    let mut st = self.sync_status.write().await;
                    st.last_error = Some(e.to_string());
                }
            }
            tokio::select! {
                _ = interval.tick() => {}
                _ = wake.notified() => {}
            }
        }
    }

    async fn sse_push_loop(&self, wake: &Notify) {
        let mut backoff = SSE_RECONNECT_BASE;
        loop {
            let candidates = [
                format!(
                    "{}/events?topics=newHeads,newTxs,events,invalidations",
                    self.node_url.trim_end_matches('/')
                ),
                format!(
                    "{}/events?topics=newHeads,newTxs,events,invalidations",
                    self.rpc_url.trim_end_matches('/')
                ),
            ];
            let mut connected_any = false;
            for url in &candidates {
                match self
                    .consume_sse_once(url, SSE_READ_IDLE_TIMEOUT, Some(wake))
                    .await
                {
                    Ok(reason) => {
                        connected_any = true;
                        backoff = SSE_RECONNECT_BASE;
                        warn!("[syncer] node SSE stream ended ({reason:?}), triggering HTTP backfill fallback");
                        wake.notify_one();
                        break;
                    }
                    Err(e) => {
                        warn!("[syncer] node SSE error on {url}: {e}");
                    }
                }
            }
            if !connected_any {
                wake.notify_one();
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(SSE_RECONNECT_MAX);
        }
    }

    /// Connect to `sse_url`, parse Geyser-lite SSE frames with bounded buffering,
    /// handle `newHeads`/`invalidations`/`lagged`, and return cleanly on EOF or lag.
    pub async fn consume_sse_once(
        &self,
        sse_url: &str,
        idle_timeout: Duration,
        wake: Option<&Notify>,
    ) -> Result<SseDisconnectReason> {
        let mut resp = self.sse_client.get(sse_url).send().await?;
        if !resp.status().is_success() {
            anyhow::bail!("SSE endpoint {sse_url} returned HTTP {}", resp.status());
        }
        let mut parser = SseFrameParser::new();
        loop {
            let chunk_res = tokio::time::timeout(idle_timeout, resp.chunk()).await;
            let chunk_opt = match chunk_res {
                Ok(r) => r?,
                Err(_) => anyhow::bail!("SSE read idle timeout after {:?}", idle_timeout),
            };
            let Some(chunk) = chunk_opt else {
                return Ok(SseDisconnectReason::Closed);
            };
            let frames = parser
                .feed(&chunk)
                .map_err(|e| anyhow::anyhow!("SSE parse error: {e}"))?;
            for frame in frames {
                if let Some(ev) = parse_node_sse_frame(&frame) {
                    let keep_going = self.handle_node_sse_event(ev, wake).await?;
                    if !keep_going {
                        return Ok(SseDisconnectReason::Lagged);
                    }
                }
            }
        }
    }

    /// Handle one parsed [`NodeSseEvent`]. Returns `Ok(false)` when a `Lagged`
    /// notice requires reconnect + backfill.
    pub async fn handle_node_sse_event(
        &self,
        ev: NodeSseEvent,
        wake: Option<&Notify>,
    ) -> Result<bool> {
        match ev {
            NodeSseEvent::NewHead { .. } => {
                if let Some(w) = wake {
                    w.notify_one();
                } else {
                    while !self.sync_step().await? {}
                }
                Ok(true)
            }
            NodeSseEvent::Invalidation {
                height,
                orphaned_blocks,
                reason,
            } => {
                let invalidated = self.db.invalidate_block_hashes(&orphaned_blocks)?;
                for (sid, h) in &invalidated {
                    self.stream_hub.publish(StreamPublishInput {
                        topic: "invalidations",
                        shard_id: *sid,
                        height: *h,
                        contract: None,
                        addresses: Vec::new(),
                        payload: json!({
                            "shard_id": sid,
                            "height": h,
                            "orphaned_blocks": orphaned_blocks,
                            "reason": reason,
                        }),
                    });
                }
                if invalidated.is_empty() {
                    if let Some(h) = height {
                        if self.db.invalidate_shard_height(0, h)? {
                            self.stream_hub.publish(StreamPublishInput {
                                topic: "invalidations",
                                shard_id: 0,
                                height: h,
                                contract: None,
                                addresses: Vec::new(),
                                payload: json!({
                                    "shard_id": 0,
                                    "height": h,
                                    "orphaned_blocks": orphaned_blocks,
                                    "reason": reason,
                                }),
                            });
                        }
                    }
                }
                if let Some(w) = wake {
                    w.notify_one();
                } else {
                    while !self.sync_step().await? {}
                }
                Ok(true)
            }
            NodeSseEvent::Lagged { skipped, .. } => {
                warn!("[syncer] node SSE lagged ({skipped} events skipped); running HTTP backfill");
                if let Some(w) = wake {
                    w.notify_one();
                } else {
                    while !self.sync_step().await? {}
                }
                Ok(false)
            }
            NodeSseEvent::NewTx | NodeSseEvent::ContractEvent | NodeSseEvent::Other => Ok(true),
        }
    }

    async fn fetch_rpc_tip_height(&self) -> Option<u64> {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "stell_blockNumber",
            "params": {},
            "id": 1
        });
        let resp = self
            .client
            .post(&self.rpc_url)
            .json(&payload)
            .send()
            .await
            .ok()?;
        let data: Value = resp.json().await.ok()?;
        let raw = data["result"].as_str()?;
        if let Some(hex_s) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
            u64::from_str_radix(hex_s, 16).ok()
        } else {
            raw.parse::<u64>().ok()
        }
    }

    async fn fetch_rpc_shards(&self) -> Option<(u32, Vec<ShardHeadInfo>)> {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "stell_getShards",
            "params": {},
            "id": 1
        });
        let resp = self
            .client
            .post(&self.rpc_url)
            .json(&payload)
            .send()
            .await
            .ok()?;
        let data: Value = resp.json().await.ok()?;
        let shards_arr = data["result"]["shards"].as_array()?;
        let mut local_shard = 0u32;
        let mut out = Vec::with_capacity(shards_arr.len());
        for s in shards_arr {
            let Some(shard_id) = s["shard_id"].as_u64().and_then(|v| u32::try_from(v).ok()) else {
                continue;
            };
            let tip_height = s["tip_height"].as_u64().unwrap_or(0);
            let tip_hash = s["tip_hash"]
                .as_str()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(str::to_string);
            let state_root = s["state_root"]
                .as_str()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(str::to_string);
            let local = s["local"].as_bool().unwrap_or(false);
            if local {
                local_shard = shard_id;
            }
            out.push(ShardHeadInfo {
                shard_id,
                tip_height,
                tip_hash,
                state_root,
                local,
            });
        }
        Some((local_shard, out))
    }

    pub async fn sync_step(&self) -> Result<bool> {
        let rpc_tip = self.fetch_rpc_tip_height().await;
        let shards_info = self.fetch_rpc_shards().await;
        let local_shard = shards_info.as_ref().map(|(l, _)| *l).unwrap_or(0);

        // 1. Fetch recent blocks from the explorer API (optional; may fail if only RPC is reachable)
        let url = format!("{}/api/blocks", self.node_url);
        let blocks_json: Vec<Value> = match self.client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => resp.json().await.unwrap_or_default(),
            Ok(resp) if rpc_tip.is_some() => {
                warn!(
                    "[syncer] explorer /api/blocks returned HTTP {}, falling back to RPC",
                    resp.status()
                );
                Vec::new()
            }
            Ok(resp) => anyhow::bail!("Node API returned HTTP {}", resp.status()),
            Err(_) if rpc_tip.is_some() => Vec::new(),
            Err(e) => return Err(e.into()),
        };

        let rest_tip = blocks_json
            .iter()
            .filter(|b| b["shard_id"].as_u64().unwrap_or(0) as u32 == local_shard)
            .filter_map(|b| b["height"].as_u64())
            .max();
        let node_tip = match (rpc_tip, rest_tip) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };

        // 2. Backfill any missed heights for the node's local shard via RPC (concurrently)
        let mut backfill_progressed = false;
        let mut more_backfill = false;
        if let Some(target_tip) = node_tip {
            let db_tip = self.db.get_shard_tip_height(local_shard).unwrap_or(0);
            if db_tip < target_tip {
                let start_h = db_tip + 1;
                let end_h = target_tip.min(start_h.saturating_add(MAX_BACKFILL_PER_TICK - 1));
                more_backfill = end_h < target_tip;
                let mut fetched: Vec<RpcBlockSummary> = Vec::new();
                let mut chunk_start = start_h;
                while chunk_start <= end_h {
                    let chunk_end = end_h
                        .min(chunk_start.saturating_add(BACKFILL_FETCH_CONCURRENCY as u64 - 1));
                    let mut set = tokio::task::JoinSet::new();
                    for h in chunk_start..=chunk_end {
                        let client = self.client.clone();
                        let rpc_url = self.rpc_url.clone();
                        set.spawn(async move {
                            fetch_rpc_block_with(&client, &rpc_url, h, local_shard).await
                        });
                    }
                    while let Some(res) = set.join_next().await {
                        if let Ok(Some(blk)) = res {
                            fetched.push(blk);
                        }
                    }
                    chunk_start = chunk_end.saturating_add(1);
                }
                fetched.sort_by_key(|b| b.height);
                for blk in fetched {
                    let should_index = match self
                        .db
                        .get_block_by_shard_and_height(blk.shard_id, blk.height)?
                    {
                        Some(known) => known.hash != blk.hash,
                        None => true,
                    };
                    if should_index {
                        let proposer_stl57 = blk.proposer.as_deref().and_then(crate::db::to_stl57);
                        let block_record = BlockRecord {
                            shard_id: blk.shard_id,
                            height: blk.height,
                            hash: blk.hash.clone(),
                            timestamp: blk.timestamp,
                            tx_count: blk.tx_count,
                            proposer: blk.proposer,
                            proposer_stl57,
                            state_root: blk.state_root,
                        };
                        self.db.insert_block(&block_record)?;
                        self.publish_block_event(&block_record);
                        backfill_progressed = true;
                        info!(
                            "[syncer] Backfilled Block Shard {} #{} ({} txs, {})",
                            blk.shard_id, blk.height, blk.tx_count, blk.hash
                        );
                        if blk.tx_count > 0 {
                            self.index_block_transactions_in_shard(
                                blk.shard_id,
                                blk.height,
                                &blk.hash,
                                blk.timestamp,
                            )
                            .await;
                        }
                    }
                }
            }
        }

        // 3. Process recent blocks from /api/blocks (carries shard_id / proposer / state_root)
        for b in blocks_json.iter().rev() {
            let height = b["height"].as_u64().unwrap_or(0);
            let hash = b["hash"].as_str().unwrap_or("").to_string();
            let timestamp = b["timestamp"].as_u64().unwrap_or(0);
            let tx_count = b["txs"].as_u64().unwrap_or(0);

            if hash.is_empty() {
                continue;
            }

            let shard_id = b["shard_id"].as_u64().unwrap_or(0) as u32;
            let proposer = b["proposer"]
                .as_str()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| crate::db::normalize_address_info(s).hex_clean);
            let proposer_stl57 = proposer.as_deref().and_then(crate::db::to_stl57);
            let state_root = b["state_root"]
                .as_str()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string);

            // Skip only the IDENTICAL block; a different hash at a known
            // (shard,height) is a reorg — re-process so insert_block
            // replaces it and dependents re-index (audit B-IDX-2).
            if let Some(known) = self.db.get_block_by_shard_and_height(shard_id, height)? {
                if known.hash == hash {
                    continue;
                }
            }

            let block_record = BlockRecord {
                shard_id,
                height,
                hash: hash.clone(),
                timestamp,
                tx_count,
                proposer,
                proposer_stl57,
                state_root,
            };

            self.db.insert_block(&block_record)?;
            self.publish_block_event(&block_record);
            info!("[syncer] Indexed Block Shard {shard_id} #{height} ({tx_count} txs, {hash})");

            // If block carries transactions, fetch and index them
            if tx_count > 0 {
                self.index_block_transactions_in_shard(shard_id, height, &hash, timestamp)
                    .await;
            }
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // 4. Record committed heads for non-local shards reported by `stell_getShards`
        //    (e.g. shard 1 when node runs with `STELL_SHARDS=0,1`).
        if let Some((_, shards)) = shards_info {
            for sh in shards {
                if sh.local || sh.shard_id == local_shard || sh.tip_height == 0 {
                    continue;
                }
                let Some(tip_hash) = sh.tip_hash else {
                    continue;
                };
                let should_insert = match self
                    .db
                    .get_block_by_shard_and_height(sh.shard_id, sh.tip_height)?
                {
                    Some(known) => known.hash != tip_hash,
                    None => true,
                };
                if should_insert {
                    let block_record = BlockRecord {
                        shard_id: sh.shard_id,
                        height: sh.tip_height,
                        hash: tip_hash.clone(),
                        timestamp: now,
                        tx_count: 0,
                        proposer: None,
                        proposer_stl57: None,
                        state_root: sh.state_root,
                    };
                    self.db.insert_block(&block_record)?;
                    self.publish_block_event(&block_record);
                    info!(
                        "[syncer] Indexed Shard {} committed head #{} ({})",
                        sh.shard_id, sh.tip_height, tip_hash
                    );
                }
            }
        }

        let mut st = self.sync_status.write().await;
        st.node_tip_height = node_tip;
        st.last_sync_at = Some(now);
        st.last_error = None;

        Ok(!(more_backfill && backfill_progressed))
    }

    fn publish_block_event(&self, b: &BlockRecord) {
        self.stream_hub.publish(StreamPublishInput {
            topic: "newHeads",
            shard_id: b.shard_id,
            height: b.height,
            contract: None,
            addresses: b
                .proposer
                .iter()
                .map(|p| normalize_contract_key(p))
                .collect(),
            payload: serde_json::to_value(b).unwrap_or(Value::Null),
        });
    }

    fn publish_tx_event(&self, shard_id: u32, tx: &TxRecord) {
        let mut addrs = Vec::with_capacity(2);
        let from_norm = normalize_contract_key(&tx.from_addr);
        if !from_norm.is_empty() {
            addrs.push(from_norm);
        }
        let to_norm = normalize_contract_key(&tx.to_addr);
        if !to_norm.is_empty() && !addrs.contains(&to_norm) {
            addrs.push(to_norm);
        }
        self.stream_hub.publish(StreamPublishInput {
            topic: "newTxs",
            shard_id,
            height: tx.block_height,
            contract: None,
            addresses: addrs,
            payload: serde_json::to_value(tx).unwrap_or(Value::Null),
        });
    }

    async fn index_block_transactions_in_shard(
        &self,
        shard_id: u32,
        height: u64,
        _block_hash: &str,
        timestamp: u64,
    ) {
        // Prefer native `stell_getBlockTransactions` so full 32-byte PQ
        // addresses (`from_addr`/`to_addr` + `Stl57`), nano-STELL amounts, and
        // true `status`/`fee_charged` are preserved without EVM 20-byte truncation.
        let mut native_metas = self
            .index_native_block_txs(shard_id, height, timestamp)
            .await;

        let mut indexed_hashes: Vec<String> =
            native_metas.iter().map(|m| m.tx_hash.clone()).collect();

        if indexed_hashes.is_empty() {
            // Fallback: try eth_getBlockByNumber with full txs
            let payload = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_getBlockByNumber",
                "params": [format!("0x{:x}", height), true],
                "id": 1
            });

            if let Ok(resp) = self.client.post(&self.rpc_url).json(&payload).send().await {
                if let Ok(data) = resp.json::<Value>().await {
                    if let Some(txs) = data["result"]["transactions"].as_array() {
                        for (i, tx) in txs.iter().enumerate() {
                            let tx_hash = tx["hash"].as_str().unwrap_or("").to_string();
                            let raw_from = tx["from"].as_str().unwrap_or("");
                            let raw_to = tx["to"].as_str().unwrap_or("");
                            let from_norm = crate::db::normalize_address_info(raw_from);
                            let to_norm = crate::db::normalize_address_info(raw_to);
                            let from_addr = if from_norm.hex_0x.is_empty() {
                                raw_from.to_string()
                            } else {
                                from_norm.hex_0x
                            };
                            let to_addr = if to_norm.hex_0x.is_empty() {
                                raw_to.to_string()
                            } else {
                                to_norm.hex_0x
                            };
                            let value = tx["value"].as_str().unwrap_or("0x0").to_string();
                            let gas_limit = tx["gas"].as_str().unwrap_or("0x0").to_string();

                            if !tx_hash.is_empty() {
                                let tx_rec = TxRecord {
                                    tx_hash: tx_hash.clone(),
                                    block_height: height,
                                    tx_index: i as u32,
                                    from_addr: from_addr.clone(),
                                    to_addr,
                                    from_stl57: from_norm.stl57,
                                    to_stl57: to_norm.stl57,
                                    amount: value,
                                    fee_charged: "0".to_string(),
                                    gas_limit,
                                    status: "success".to_string(),
                                    timestamp,
                                };
                                let _ = self.db.insert_transaction_in_shard(shard_id, &tx_rec);
                                self.publish_tx_event(shard_id, &tx_rec);
                                native_metas.push(NativeTxMeta {
                                    tx_hash: tx_hash.clone(),
                                    from_addr,
                                    succeeded: true,
                                    deployed_code_hash: None,
                                    token_touches: Vec::new(),
                                });
                                indexed_hashes.push(tx_hash);
                            }
                        }
                    }
                }
            }
        }

        // Contract events, deployed contracts & touched STS-20 token balances.
        self.index_block_receipts_and_state(shard_id, height, &native_metas)
            .await;

        info!("[syncer] Finished indexing txs for Block Shard {shard_id} #{height}");
    }

    /// Fetch and store native transactions of a block from `stell_getBlockTransactions`.
    async fn index_native_block_txs(
        &self,
        shard_id: u32,
        height: u64,
        timestamp: u64,
    ) -> Vec<NativeTxMeta> {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "stell_getBlockTransactions",
            "params": { "height": height, "shard_id": shard_id },
            "id": 1
        });
        let resp = match self.client.post(&self.rpc_url).json(&payload).send().await {
            Ok(r) => r,
            Err(e) => {
                warn!("[syncer] native block listing failed at {height}: {e}");
                return Vec::new();
            }
        };
        let data: Value = match resp.json().await {
            Ok(d) => d,
            Err(_) => return Vec::new(),
        };
        let Some(txs) = data["result"]["txs"].as_array() else {
            return Vec::new();
        };
        let mut metas = Vec::with_capacity(txs.len());
        for (i, t) in txs.iter().enumerate() {
            let Some((rec, meta)) = decode_native_tx_with_meta(height, i, t, timestamp) else {
                continue;
            };
            let _ = self.db.insert_transaction_in_shard(shard_id, &rec);
            self.publish_tx_event(shard_id, &rec);
            metas.push(meta);
        }
        metas
    }

    /// Fetch the receipts of a block's transactions and index their events,
    /// deployed contracts (`contracts`), and touched STS-20 token balances
    /// (`token_balances`).
    async fn index_block_receipts_and_state(
        &self,
        shard_id: u32,
        height: u64,
        tx_metas: &[NativeTxMeta],
    ) {
        if tx_metas.is_empty() {
            return;
        }
        let meta_by_hash: HashMap<&str, &NativeTxMeta> =
            tx_metas.iter().map(|m| (m.tx_hash.as_str(), m)).collect();

        let mut set = tokio::task::JoinSet::new();
        let mut pending = 0usize;
        for meta in tx_metas.iter().take(MAX_RECEIPTS_PER_BLOCK) {
            if pending >= RECEIPT_FETCH_CONCURRENCY {
                while let Some(res) = set.join_next().await {
                    pending = pending.saturating_sub(1);
                    if let Ok(Some(details)) = res {
                        self.apply_receipt_details(shard_id, height, &meta_by_hash, details)
                            .await;
                    }
                }
            }
            let hash = meta.tx_hash.clone();
            let client = self.client.clone();
            let rpc_url = self.rpc_url.clone();
            set.spawn(async move { fetch_receipt_details(&client, &rpc_url, &hash).await });
            pending += 1;
        }
        while let Some(res) = set.join_next().await {
            if let Ok(Some(details)) = res {
                self.apply_receipt_details(shard_id, height, &meta_by_hash, details)
                    .await;
            }
        }

        // Refresh touched token balances from the node's authoritative state.
        let mut unique_touches: Vec<(String, String)> = Vec::new();
        let mut seen: HashSet<(String, String)> = HashSet::new();
        for meta in tx_metas.iter().take(MAX_RECEIPTS_PER_BLOCK) {
            if !meta.succeeded {
                continue;
            }
            for (tok, owner) in &meta.token_touches {
                if seen.insert((tok.clone(), owner.clone())) {
                    unique_touches.push((tok.clone(), owner.clone()));
                }
                if unique_touches.len() >= MAX_RECEIPTS_PER_BLOCK {
                    break;
                }
            }
            if unique_touches.len() >= MAX_RECEIPTS_PER_BLOCK {
                break;
            }
        }
        for (tok, owner) in unique_touches {
            if let Some(bal) = fetch_token_balance(&self.client, &self.rpc_url, &tok, &owner).await
            {
                let rec = TokenBalanceRecord {
                    shard_id,
                    token_id: tok,
                    owner: owner.clone(),
                    owner_stl57: to_stl57(&owner),
                    balance: bal,
                    updated_height: height,
                };
                if let Err(e) = self.db.upsert_token_balance(&rec) {
                    warn!("[syncer] failed to store token balance: {e}");
                }
            }
        }
    }

    async fn apply_receipt_details(
        &self,
        shard_id: u32,
        height: u64,
        meta_by_hash: &HashMap<&str, &NativeTxMeta>,
        details: ReceiptDetails,
    ) {
        if let Some(contract_addr) = details.contract_address.as_deref() {
            let norm_addr = normalize_contract_key(contract_addr);
            if !norm_addr.is_empty() {
                if !self.abis.contains(&norm_addr) {
                    let abi = self.fetch_abi(&norm_addr).await;
                    self.abis.put(&norm_addr, abi);
                }
                let has_abi = self.abis.get(&norm_addr).is_some();
                let meta = meta_by_hash.get(details.tx_hash.as_str()).copied();
                let creator = meta
                    .map(|m| normalize_contract_key(&m.from_addr))
                    .filter(|s| !s.is_empty());
                let creator_stl57 = creator.as_deref().and_then(to_stl57);
                let code_hash = meta.and_then(|m| m.deployed_code_hash.clone());
                let rec = ContractRecord {
                    shard_id,
                    address: norm_addr.clone(),
                    address_stl57: to_stl57(&norm_addr),
                    creator,
                    creator_stl57,
                    code_hash,
                    deploy_height: height,
                    has_abi,
                };
                if let Err(e) = self.db.upsert_contract(&rec) {
                    warn!("[syncer] failed to upsert contract {norm_addr}: {e}");
                }
            }
        }
        if !details.events.is_empty() {
            self.store_events(shard_id, height, details.events).await;
        }
    }

    /// Store the events of one receipt, decoding them with the ABI when it is
    /// known.
    async fn store_events(&self, shard_id: u32, height: u64, events: Vec<(String, RawEvent)>) {
        if events.is_empty() {
            return;
        }
        let mut records: Vec<EventRecord> = Vec::with_capacity(events.len());
        let mut abi_contracts: HashSet<String> = HashSet::new();
        for (tx_hash, raw) in events {
            let contract = crate::events::normalize_address(&raw.contract);
            // The manifest is fetched once per contract and then cached, so a
            // busy contract does not turn into an RPC storm.
            if !self.abis.contains(&contract) {
                let abi = self.fetch_abi(&contract).await;
                self.abis.put(&contract, abi);
            }
            let abi = self.abis.get(&contract);
            if abi.is_some() {
                abi_contracts.insert(contract.clone());
            }
            let decoded = crate::events::decode_event(abi.as_ref(), &raw);
            let topics_json =
                serde_json::to_string(&decoded.topics).unwrap_or_else(|_| "[]".to_string());
            let data_json =
                serde_json::to_string(&decoded.data).unwrap_or_else(|_| "null".to_string());
            let decoded_json = decoded
                .args
                .as_ref()
                .and_then(|a| serde_json::to_string(a).ok());
            records.push(EventRecord {
                tx_hash: tx_hash.clone(),
                block_height: height,
                log_index: 0,
                contract,
                topic0: decoded.topic0,
                topics_json,
                data: data_json,
                event_name: decoded.event_name,
                decoded_json,
            });
        }
        // The log index is the position of the event inside the transaction.
        let mut per_tx: HashMap<String, u32> = HashMap::new();
        for r in records.iter_mut() {
            let idx = per_tx.entry(r.tx_hash.clone()).or_insert(0);
            r.log_index = *idx;
            *idx += 1;
        }
        if let Err(e) = self.db.insert_events_in_shard(shard_id, &records) {
            warn!("[syncer] failed to store contract events: {e}");
        } else {
            for contract in abi_contracts {
                let _ = self.db.mark_contract_has_abi(&contract, true);
            }
            for r in &records {
                self.stream_hub.publish(StreamPublishInput {
                    topic: "events",
                    shard_id,
                    height,
                    contract: Some(r.contract.clone()),
                    addresses: vec![r.contract.clone()],
                    payload: serde_json::to_value(r).unwrap_or(Value::Null),
                });
            }
            info!(
                "[syncer] Indexed {} contract events in shard {} at height {}",
                records.len(),
                shard_id,
                height
            );
        }
    }

    /// Fetch the ABI manifest of a contract from the node.
    ///
    /// The manifest is committed to the state trie, so every node serves the
    /// SAME one — the explorer's decoder and the contract agree by
    /// construction.
    async fn fetch_abi(&self, contract: &str) -> Option<stellereum::contract_abi::ContractAbi> {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "stell_getContractAbi",
            "params": { "contract": contract },
            "id": 1
        });
        let resp = match self.client.post(&self.rpc_url).json(&payload).send().await {
            Ok(r) => r,
            Err(e) => {
                warn!("[syncer] ABI fetch failed for {contract}: {e}");
                return None;
            }
        };
        let data: Value = match resp.json().await {
            Ok(d) => d,
            Err(e) => {
                warn!("[syncer] ABI fetch gave no JSON for {contract}: {e}");
                return None;
            }
        };
        AbiCache::parse_abi(&data)
    }
}

struct ShardHeadInfo {
    shard_id: u32,
    tip_height: u64,
    tip_hash: Option<String>,
    state_root: Option<String>,
    local: bool,
}

struct RpcBlockSummary {
    shard_id: u32,
    height: u64,
    hash: String,
    timestamp: u64,
    tx_count: u64,
    proposer: Option<String>,
    state_root: Option<String>,
}

struct NativeTxMeta {
    tx_hash: String,
    from_addr: String,
    succeeded: bool,
    deployed_code_hash: Option<String>,
    token_touches: Vec<(String, String)>,
}

struct ReceiptDetails {
    tx_hash: String,
    contract_address: Option<String>,
    events: Vec<(String, RawEvent)>,
}

async fn fetch_rpc_block_with(
    client: &Client,
    rpc_url: &str,
    height: u64,
    default_shard_id: u32,
) -> Option<RpcBlockSummary> {
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "stell_getBlock",
        "params": { "height": height },
        "id": 1
    });
    let resp = client.post(rpc_url).json(&payload).send().await.ok()?;
    let data: Value = resp.json().await.ok()?;
    let res = data.get("result")?;
    if res.is_null() {
        return None;
    }
    let hash = res["hash"].as_str()?.to_string();
    if hash.is_empty() {
        return None;
    }
    let shard_id = res["shard_id"]
        .as_u64()
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(default_shard_id);
    let timestamp = res["timestamp"].as_u64().unwrap_or(0);
    let tx_count = res["txs"].as_u64().unwrap_or(0);
    let proposer = res["proposer"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| crate::db::normalize_address_info(s).hex_clean);
    let state_root = res["state_root"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    Some(RpcBlockSummary {
        shard_id,
        height,
        hash,
        timestamp,
        tx_count,
        proposer,
        state_root,
    })
}

/// Decode one entry from `stell_getBlockTransactions` into a [`TxRecord`].
///
/// Handles both live `raw_tx` hex-encoded `bincode(Transaction)` strings (preserving
/// full 32-byte `from`/`to` addresses, `Stl57` encoding, and nano-STELL `amount`)
/// and structured JSON `raw_tx` objects.
#[cfg(test)]
pub(crate) fn decode_native_tx_record(
    height: u64,
    fallback_index: usize,
    t: &Value,
    timestamp: u64,
) -> Option<TxRecord> {
    decode_native_tx_with_meta(height, fallback_index, t, timestamp).map(|(rec, _)| rec)
}

fn decode_native_tx_with_meta(
    height: u64,
    fallback_index: usize,
    t: &Value,
    timestamp: u64,
) -> Option<(TxRecord, NativeTxMeta)> {
    use bincode::Options;
    use stellereum::svm::OpCode;

    let raw_hash = t["tx_hash"].as_str().filter(|s| !s.is_empty())?;
    let tx_hash = if raw_hash.starts_with("0x") || raw_hash.starts_with("0X") {
        format!("0x{}", raw_hash[2..].to_lowercase())
    } else {
        format!("0x{}", raw_hash.to_lowercase())
    };
    let tx_index = t["index"].as_u64().unwrap_or(fallback_index as u64) as u32;
    let status = t["status"].as_str().unwrap_or("success").to_string();
    let succeeded =
        status.eq_ignore_ascii_case("success") || status.eq_ignore_ascii_case("confirmed");
    let fee_charged = t["fee_charged"].as_str().unwrap_or("0").to_string();
    let gas_limit = t["gas_limit"].as_str().unwrap_or("0").to_string();

    let mut deployed_code_hash: Option<String> = None;
    let mut token_touches: Vec<(String, String)> = Vec::new();

    let raw = &t["raw_tx"];
    let (from_addr, to_addr, amount) = if let Some(raw_hex) = raw.as_str() {
        let clean = raw_hex
            .strip_prefix("0x")
            .or_else(|| raw_hex.strip_prefix("0X"))
            .unwrap_or(raw_hex);
        if clean.len() <= 512 * 1024 {
            if let Ok(bytes) = hex::decode(clean) {
                let opts = bincode::DefaultOptions::new()
                    .with_fixint_encoding()
                    .allow_trailing_bytes()
                    .with_limit(262_144);
                if let Ok(tx) = opts.deserialize::<stellereum::sharding::Transaction>(&bytes) {
                    if succeeded {
                        for op in &tx.payload {
                            match op {
                                OpCode::SysCallDeployContract { code } => {
                                    deployed_code_hash = Some(hex::encode(
                                        stellereum::contract_source::code_hash_sha256(code),
                                    ));
                                }
                                OpCode::SysCallTokenTransfer { token_id, to, .. } => {
                                    let tid = hex::encode(token_id);
                                    token_touches.push((tid.clone(), hex::encode(tx.from)));
                                    token_touches.push((tid, hex::encode(to)));
                                }
                                OpCode::SysCallTokenTransferFrom {
                                    token_id, from, to, ..
                                } => {
                                    let tid = hex::encode(token_id);
                                    token_touches.push((tid.clone(), hex::encode(from)));
                                    token_touches.push((tid, hex::encode(to)));
                                }
                                OpCode::SysCallTokenMint { token_id, to, .. } => {
                                    token_touches.push((hex::encode(token_id), hex::encode(to)));
                                }
                                OpCode::SysCallTokenBurn { token_id, from, .. } => {
                                    token_touches.push((hex::encode(token_id), hex::encode(from)));
                                }
                                _ => {}
                            }
                        }
                    }
                    (
                        format!("0x{}", hex::encode(tx.from)),
                        format!("0x{}", hex::encode(tx.to)),
                        tx.amount.to_string(),
                    )
                } else {
                    (String::new(), String::new(), "0".to_string())
                }
            } else {
                (String::new(), String::new(), "0".to_string())
            }
        } else {
            (String::new(), String::new(), "0".to_string())
        }
    } else {
        let raw_from = raw["from"].as_str().unwrap_or("");
        let raw_to = raw["to"].as_str().unwrap_or("");
        let from_norm = crate::db::normalize_address_info(raw_from);
        let to_norm = crate::db::normalize_address_info(raw_to);
        let from_addr = if from_norm.hex_0x.is_empty() {
            raw_from.to_string()
        } else {
            from_norm.hex_0x
        };
        let to_addr = if to_norm.hex_0x.is_empty() {
            raw_to.to_string()
        } else {
            to_norm.hex_0x
        };
        let amount = raw["amount"]
            .as_str()
            .map(|s| s.to_string())
            .or_else(|| raw["amount"].as_u64().map(|n| n.to_string()))
            .unwrap_or_else(|| "0".to_string());
        (from_addr, to_addr, amount)
    };

    let from_stl57 = crate::db::to_stl57(&from_addr);
    let to_stl57 = crate::db::to_stl57(&to_addr);

    let meta = NativeTxMeta {
        tx_hash: tx_hash.clone(),
        from_addr: from_addr.clone(),
        succeeded,
        deployed_code_hash,
        token_touches,
    };

    let rec = TxRecord {
        tx_hash,
        block_height: height,
        tx_index,
        from_addr,
        to_addr,
        from_stl57,
        to_stl57,
        amount,
        fee_charged,
        gas_limit,
        status,
        timestamp,
    };

    Some((rec, meta))
}

/// Fetch the receipt events and deployed contract address (if any) of one transaction.
async fn fetch_receipt_details(
    client: &Client,
    rpc_url: &str,
    tx_hash: &str,
) -> Option<ReceiptDetails> {
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "stell_getTransactionReceipt",
        "params": { "hash": tx_hash },
        "id": 1
    });
    let resp = client.post(rpc_url).json(&payload).send().await.ok()?;
    let data: Value = resp.json().await.ok()?;
    let result = data.get("result")?;
    if result.is_null() {
        return None;
    }
    let contract_address = result
        .get("contract_address")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let mut out = Vec::new();
    if let Some(events) = result.get("events").and_then(|v| v.as_array()) {
        out.reserve(events.len());
        for e in events {
            if let Some(raw) = event_from_json(e) {
                out.push((tx_hash.to_string(), raw));
            }
        }
    }
    Some(ReceiptDetails {
        tx_hash: tx_hash.to_string(),
        contract_address,
        events: out,
    })
}

async fn fetch_token_balance(
    client: &Client,
    rpc_url: &str,
    token: &str,
    account: &str,
) -> Option<String> {
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "stell_tokenBalance",
        "params": { "token": token, "account": account },
        "id": 1
    });
    let resp = client.post(rpc_url).json(&payload).send().await.ok()?;
    let data: Value = resp.json().await.ok()?;
    let res = data.get("result")?;
    let raw = res
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| res.as_u64().map(|n| n.to_string()))?;
    if raw.bytes().all(|b| b.is_ascii_digit()) {
        Some(crate::db::canonical_decimal_string(&raw))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_native_tx_record_preserves_32b_addresses_and_stl57() {
        let kp = stellereum::post_quantum::FalconKeypair::generate();
        let to = [0xA0u8; 32];
        let tx = stellereum::sharding::Transaction::new_pq_explicit(
            stellereum::post_quantum::PqScheme::Falcon512,
            kp.public_key.clone(),
            vec![0x42u8; 666],
            to,
            5_000_000_000,
            325_000,
            0,
            0,
            0,
            vec![],
            &[0u8; 16],
        );
        let raw_hex = hex::encode(bincode::serialize(&tx).expect("serialize tx"));
        let entry = serde_json::json!({
            "tx_hash": hex::encode(tx.compute_tx_hash()),
            "index": 0,
            "status": "success",
            "gas_limit": "325000",
            "fee_charged": "370000",
            "raw_tx": raw_hex,
        });
        let rec = decode_native_tx_record(8, 0, &entry, 1700000000).expect("decode");
        assert_eq!(rec.from_addr, format!("0x{}", hex::encode(tx.from)));
        assert_eq!(rec.to_addr, format!("0x{}", hex::encode(to)));
        assert_eq!(
            rec.from_stl57.as_deref(),
            Some(stellereum::address::encode_stl57_address(&tx.from).as_str())
        );
        assert_eq!(
            rec.to_stl57.as_deref(),
            Some(stellereum::address::encode_stl57_address(&to).as_str())
        );
        assert_eq!(rec.amount, "5000000000");
        assert_eq!(rec.fee_charged, "370000");
    }

    #[tokio::test]
    async fn sync_step_indexes_multi_shard_blocks_without_stalling() {
        use axum::{routing::get, routing::post, Json, Router};

        let db = Database::open(":memory:").unwrap();

        let mock_rest = Router::new().route(
            "/api/blocks",
            get(|| async {
                Json(serde_json::json!([
                    { "shard_id": 0, "height": 2, "hash": "0xs0_b2", "txs": 0, "timestamp": 1792000002 },
                    { "shard_id": 1, "height": 5, "hash": "0xs1_b5", "txs": 0, "timestamp": 1792000005 }
                ]))
            }),
        );
        let rest_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rest_url = format!("http://{}", rest_listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(rest_listener, mock_rest).await.unwrap() });

        let mock_rpc = Router::new().route(
            "/",
            post(|Json(body): Json<Value>| async move {
                let method = body["method"].as_str().unwrap_or("");
                let result = match method {
                    "stell_blockNumber" => serde_json::json!("0x2"),
                    "stell_getShards" => serde_json::json!({
                        "shards": [
                            {
                                "shard_id": 0,
                                "type": "masterchain",
                                "tip_height": 2,
                                "tip_hash": "0xs0_b2",
                                "state_root": "0xroot0",
                                "local": true
                            },
                            {
                                "shard_id": 1,
                                "type": "workchain",
                                "tip_height": 7,
                                "tip_hash": "0xs1_b7",
                                "state_root": "0xroot1",
                                "local": false
                            }
                        ],
                        "total_shards": 2,
                        "routing_prefix_bits": 1
                    }),
                    "stell_getBlock" => {
                        let h = body["params"]["height"].as_u64().unwrap_or(0);
                        serde_json::json!({
                            "height": h,
                            "hash": format!("0xs0_b{h}"),
                            "txs": 0,
                            "timestamp": 1792000000 + h
                        })
                    }
                    _ => Value::Null,
                };
                Json(serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": result }))
            }),
        );
        let rpc_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rpc_url = format!("http://{}", rpc_listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(rpc_listener, mock_rpc).await.unwrap() });

        let syncer = Syncer::new(db.clone(), rest_url, rpc_url);
        let caught_up = syncer.sync_step().await.expect("sync_step");
        assert!(caught_up);

        // Shard 0 backfilled heights 1 and 2 even though shard 1 is at height 7
        assert_eq!(db.get_shard_tip_height(0).unwrap(), 2);
        assert!(db.get_block_by_shard_and_height(0, 1).unwrap().is_some());
        assert!(db.get_block_by_shard_and_height(0, 2).unwrap().is_some());

        // Shard 1 indexed both REST block #5 and stell_getShards committed head #7
        assert_eq!(db.get_shard_tip_height(1).unwrap(), 7);
        assert_eq!(
            db.get_block_by_shard_and_height(1, 5)
                .unwrap()
                .unwrap()
                .hash,
            "0xs1_b5"
        );
        let s1_head = db.get_block_by_shard_and_height(1, 7).unwrap().unwrap();
        assert_eq!(s1_head.hash, "0xs1_b7");
        assert_eq!(s1_head.state_root.as_deref(), Some("0xroot1"));
    }
}
