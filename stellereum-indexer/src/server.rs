use crate::db::{
    address_match_candidates, normalize_contract_key, parse_account_tokens_cursor,
    parse_block_cursor, parse_contracts_cursor, parse_contracts_program_cursor, parse_event_cursor,
    parse_token_holders_cursor, parse_token_program_cursor, parse_tx_cursor_v2, Database,
    EventFilter, EventRecord, VerifiedSource,
};
use crate::events::{decode_event, AbiCache, RawEvent};
use crate::syncer::SyncStatus;
use axum::{
    extract::{ConnectInfo, Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{
        sse::{Event as SseEvent, KeepAlive, Sse},
        IntoResponse, Json, Response,
    },
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::Duration;
use tokio::sync::{broadcast, RwLock, Semaphore};
use tower_http::cors::CorsLayer;

/// Maximum number of events one page may carry.
pub const MAX_EVENT_PAGE: u32 = 200;

/// Maximum number of history items (blocks/txs/tokens) one page may carry.
pub const MAX_HISTORY_PAGE: u32 = 200;

/// Maximum number of items returned by `/api/v2/program/:program/accounts`.
pub const MAX_PROGRAM_ACCOUNTS_LIMIT: u32 = 100;

/// Maximum accounts when `with_proof=true` is requested on program accounts.
pub const MAX_PROGRAM_ACCOUNTS_PROOFS: u32 = 16;

/// Capacity of the internal indexer SSE broadcast channel.
pub const STREAM_BROADCAST_CAPACITY: usize = 1024;

/// Maximum concurrent SSE clients allowed on `GET /api/v2/stream`.
pub const MAX_INDEXER_SSE_CLIENTS: usize = 256;

/// Maximum concurrent SSE clients per IP / IPv6 `/64` bucket on `GET /api/v2/stream`.
pub const MAX_INDEXER_SSE_PER_IP: usize = 8;

/// Maximum concurrent in-flight HTTP requests on the indexer API router.
pub const MAX_INDEXER_CONCURRENT_REQUESTS: usize = 512;

/// Request timeout (seconds) enforced by the indexer API middleware.
pub const INDEXER_REQUEST_TIMEOUT_SECS: u64 = 30;

/// Default per-IP request rate limit (requests/sec) on the indexer API router.
pub const INDEXER_RATE_LIMIT_PER_SEC_DEFAULT: u32 = 120;

/// Default per-IP rate limit (requests/sec) on `/api/v2/program/:program/accounts`.
pub const INDEXER_PROGRAM_ACCOUNTS_RATE_LIMIT_DEFAULT: u32 = 20;

/// Idle reap timeout (seconds) for `GET /api/v2/stream`.
pub const SSE_IDLE_TIMEOUT_SECS: u64 = 300;

/// Bounded in-memory replay window for `after_seq` on `GET /api/v2/stream`.
pub const INDEXER_REPLAY_WINDOW: usize = 512;

/// Maximum number of replayed events sent in a single `after_seq` attach burst.
pub const MAX_REPLAY_BURST: usize = 256;

/// One event published by the indexer's `GET /api/v2/stream` SSE hub.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndexerStreamEvent {
    pub seq: u64,
    pub topic: String,
    pub shard_id: u32,
    pub height: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<String>,
    pub payload: Value,
}

/// Input payload passed to [`IndexerStreamHub::publish`].
#[derive(Clone, Debug)]
pub struct StreamPublishInput {
    pub topic: &'static str,
    pub shard_id: u32,
    pub height: u64,
    pub contract: Option<String>,
    pub addresses: Vec<String>,
    pub payload: Value,
}

/// Reason an SSE stream acquire failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SseAcquireError {
    GlobalLimit,
    PerIpLimit,
}

/// RAII guard tracking an active SSE client slot in [`IndexerStreamHub`].
pub struct SseClientGuard {
    active_clients: Arc<AtomicUsize>,
    ip_clients: Arc<Mutex<HashMap<IpAddr, usize>>>,
    bucket_ip: IpAddr,
}

impl Drop for SseClientGuard {
    fn drop(&mut self) {
        let mut map = self.ip_clients.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(cnt) = map.get_mut(&self.bucket_ip) {
            if *cnt <= 1 {
                map.remove(&self.bucket_ip);
            } else {
                *cnt -= 1;
            }
        }
        drop(map);
        self.active_clients.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Bounded broadcast + replay ring-buffer for `GET /api/v2/stream`.
pub struct IndexerStreamHub {
    tx: broadcast::Sender<IndexerStreamEvent>,
    next_seq: AtomicU64,
    replay: Mutex<VecDeque<IndexerStreamEvent>>,
    active_clients: Arc<AtomicUsize>,
    ip_clients: Arc<Mutex<HashMap<IpAddr, usize>>>,
    max_clients: usize,
    max_clients_per_ip: usize,
    idle_timeout: Duration,
}

impl IndexerStreamHub {
    pub fn new() -> Self {
        Self::with_limits(
            MAX_INDEXER_SSE_CLIENTS,
            Duration::from_secs(SSE_IDLE_TIMEOUT_SECS),
        )
    }

    pub fn with_limits(max_clients: usize, idle_timeout: Duration) -> Self {
        Self::with_all_limits(max_clients, MAX_INDEXER_SSE_PER_IP, idle_timeout)
    }

    pub fn with_all_limits(
        max_clients: usize,
        max_clients_per_ip: usize,
        idle_timeout: Duration,
    ) -> Self {
        let (tx, _rx) = broadcast::channel(STREAM_BROADCAST_CAPACITY);
        Self {
            tx,
            next_seq: AtomicU64::new(1),
            replay: Mutex::new(VecDeque::with_capacity(INDEXER_REPLAY_WINDOW)),
            active_clients: Arc::new(AtomicUsize::new(0)),
            ip_clients: Arc::new(Mutex::new(HashMap::new())),
            max_clients,
            max_clients_per_ip: max_clients_per_ip.max(1),
            idle_timeout,
        }
    }

    /// Publish an event into the bounded replay buffer and broadcast channel.
    /// Never blocks on slow or disconnected SSE consumers.
    pub fn publish(&self, input: StreamPublishInput) -> u64 {
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let ev = IndexerStreamEvent {
            seq,
            topic: input.topic.to_string(),
            shard_id: input.shard_id,
            height: input.height,
            contract: input.contract,
            addresses: input.addresses,
            payload: input.payload,
        };
        {
            let mut ring = self.replay.lock().unwrap_or_else(|e| e.into_inner());
            ring.push_back(ev.clone());
            while ring.len() > INDEXER_REPLAY_WINDOW {
                ring.pop_front();
            }
        }
        let _ = self.tx.send(ev);
        seq
    }

    pub fn subscribe(&self) -> broadcast::Receiver<IndexerStreamEvent> {
        self.tx.subscribe()
    }

    pub fn oldest_available_seq(&self) -> Option<u64> {
        let ring = self.replay.lock().unwrap_or_else(|e| e.into_inner());
        ring.front().map(|e| e.seq)
    }

    pub fn latest_seq(&self) -> u64 {
        self.next_seq.load(Ordering::Relaxed).saturating_sub(1)
    }

    pub fn active_clients(&self) -> usize {
        self.active_clients.load(Ordering::Acquire)
    }

    pub fn active_clients_for_ip(&self, ip: IpAddr) -> usize {
        let bucket = stellereum::rpc::budget_bucket_ip(ip);
        self.ip_clients
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&bucket)
            .copied()
            .unwrap_or(0)
    }

    pub fn max_clients(&self) -> usize {
        self.max_clients
    }

    pub fn max_clients_per_ip(&self) -> usize {
        self.max_clients_per_ip
    }

    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    /// Attempt to reserve a client slot (`None` if at `max_clients` or `max_clients_per_ip`).
    pub fn try_acquire_client(&self) -> Option<SseClientGuard> {
        self.try_acquire_client_for_ip(stellereum::rpc::LOCAL_BUCKET_IP)
            .ok()
    }

    /// Attempt to reserve both a global slot and a per-IP/bucket slot.
    pub fn try_acquire_client_for_ip(&self, ip: IpAddr) -> Result<SseClientGuard, SseAcquireError> {
        loop {
            let cur = self.active_clients.load(Ordering::Acquire);
            if cur >= self.max_clients {
                return Err(SseAcquireError::GlobalLimit);
            }
            if self
                .active_clients
                .compare_exchange(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break;
            }
        }
        let bucket_ip = stellereum::rpc::budget_bucket_ip(ip);
        let mut map = self.ip_clients.lock().unwrap_or_else(|e| e.into_inner());
        let held = map.get(&bucket_ip).copied().unwrap_or(0);
        if held >= self.max_clients_per_ip {
            drop(map);
            self.active_clients.fetch_sub(1, Ordering::AcqRel);
            return Err(SseAcquireError::PerIpLimit);
        }
        map.insert(bucket_ip, held + 1);
        Ok(SseClientGuard {
            active_clients: Arc::clone(&self.active_clients),
            ip_clients: Arc::clone(&self.ip_clients),
            bucket_ip,
        })
    }

    /// Snapshot replay events strictly after `after_seq`.
    /// Returns `Err(oldest_seq)` when `after_seq` predates the bounded window.
    pub fn replay_since(&self, after_seq: u64) -> Result<Vec<IndexerStreamEvent>, Option<u64>> {
        let ring = self.replay.lock().unwrap_or_else(|e| e.into_inner());
        let Some(oldest) = ring.front().map(|e| e.seq) else {
            return Ok(Vec::new());
        };
        if oldest > 1 && after_seq < oldest.saturating_sub(1) {
            return Err(Some(oldest));
        }
        let events = ring.iter().filter(|e| e.seq > after_seq).cloned().collect();
        Ok(events)
    }
}

impl Default for IndexerStreamHub {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    /// The contract ABI manifests the indexer knows about, filled by the
    /// syncer from the node's `stell_getContractAbi` and used to DECODE the
    /// contract events the API serves.
    pub abis: Arc<AbiCache>,
    /// The node's JSON-RPC endpoint. The indexer proxies the LIVE
    /// chain-shaped reads (the shard topology, the validator set) from it, so
    /// the explorer never has to talk to the node directly.
    pub rpc_url: String,
    /// Bearer token gating the state-changing verify endpoint (audit B-IDX-3).
    /// `None` = endpoint refuses everything (default-deny); set
    /// `INDEXER_VERIFY_TOKEN` to enable operator/API use. Reads stay public.
    pub verify_token: Option<String>,
    /// Shared syncer health state (`node_tip_height`, `last_sync_at`).
    pub sync_status: Arc<RwLock<SyncStatus>>,
    /// Reused HTTP client for RPC proxy calls.
    pub http_client: reqwest::Client,
    /// Bounded SSE broadcast + replay hub for `GET /api/v2/stream`.
    pub stream_hub: Arc<IndexerStreamHub>,
}

impl AppState {
    /// A state with an empty ABI cache.
    pub fn new(db: Database) -> Self {
        Self::with_rpc(
            db,
            std::env::var("INDEXER_RPC_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8545".to_string()),
        )
    }

    /// A state with an empty ABI cache and an explicit node RPC endpoint.
    pub fn with_rpc(db: Database, rpc_url: String) -> Self {
        Self {
            db,
            abis: Arc::new(AbiCache::new()),
            rpc_url,
            verify_token: None,
            sync_status: Arc::new(RwLock::new(SyncStatus::default())),
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            stream_hub: Arc::new(IndexerStreamHub::new()),
        }
    }

    /// Override the stream hub (used in `main.rs` and stream limit tests).
    pub fn with_stream_hub(mut self, stream_hub: Arc<IndexerStreamHub>) -> Self {
        self.stream_hub = stream_hub;
        self
    }
}

#[derive(Deserialize)]
pub struct Pagination {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub cursor: Option<String>,
}

#[derive(Deserialize)]
pub struct BlocksQuery {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub cursor: Option<String>,
    pub shard_id: Option<u32>,
    pub shard: Option<u32>,
}

#[derive(Deserialize)]
pub struct BlockQuery {
    pub shard_id: Option<u32>,
    pub shard: Option<u32>,
}

#[derive(Deserialize)]
pub struct ShardsQuery {
    pub address: Option<String>,
}

#[derive(Deserialize)]
pub struct SearchQuery {
    pub q: Option<String>,
}

/// Filters of `GET /api/v2/events`.
#[derive(Deserialize)]
pub struct EventsQuery {
    pub from_block: Option<u64>,
    pub to_block: Option<u64>,
    pub contract: Option<String>,
    pub shard_id: Option<u32>,
    pub shard: Option<u32>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub cursor: Option<String>,
}

#[derive(Deserialize)]
pub struct TxsQuery {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub cursor: Option<String>,
    pub shard_id: Option<u32>,
    pub shard: Option<u32>,
}

#[derive(Deserialize)]
pub struct ContractsQuery {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub cursor: Option<String>,
    pub shard_id: Option<u32>,
    pub shard: Option<u32>,
}

#[derive(Deserialize)]
pub struct AccountTokensQuery {
    pub token: Option<String>,
    pub include_zero: Option<bool>,
    pub shard_id: Option<u32>,
    pub limit: Option<u32>,
    pub cursor: Option<String>,
}

#[derive(Deserialize)]
pub struct TokenHoldersQuery {
    pub include_zero: Option<bool>,
    pub shard_id: Option<u32>,
    pub limit: Option<u32>,
    pub cursor: Option<String>,
}

#[derive(Deserialize)]
pub struct ProgramAccountsQuery {
    pub token: Option<String>,
    pub contract: Option<String>,
    pub owner: Option<String>,
    pub creator: Option<String>,
    pub min_balance: Option<u64>,
    pub slot_from: Option<i64>,
    pub slot_to: Option<i64>,
    pub with_proof: Option<bool>,
    pub source: Option<String>,
    pub shard_id: Option<u32>,
    pub limit: Option<u32>,
    pub cursor: Option<String>,
}

#[derive(Deserialize)]
pub struct StreamQuery {
    #[serde(alias = "kind")]
    pub topics: Option<String>,
    pub contract: Option<String>,
    pub address: Option<String>,
    pub shard_id: Option<u32>,
    pub after_seq: Option<u64>,
}

/// Maximum pagination offset (audit B-IDX-4): an unbounded OFFSET forces a
/// full table scan for an empty page (CPU DoS). Bounded at 100,000 rows;
/// deeper pagination uses keyset cursors.
const MAX_OFFSET: u32 = 100_000;

/// Fail-closed offset gate: `Err(response)` on absurd offsets.
#[allow(clippy::result_large_err)] // GATE: axum Response is the framework's
                                   // native error carrier (handlers return it by value everywhere); boxing
                                   // would only add noise.
fn check_offset(offset: u32) -> Result<u32, axum::response::Response> {
    if offset > MAX_OFFSET {
        Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "offset exceeds cap 100000"})),
        )
            .into_response())
    } else {
        Ok(offset)
    }
}

#[allow(clippy::result_large_err)] // GATE: axum Response is the framework's native error carrier.
fn bad_request(msg: impl Into<String>) -> axum::response::Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": msg.into() })),
    )
        .into_response()
}

#[allow(clippy::result_large_err)] // GATE: axum Response is the framework's native error carrier.
fn resolve_cursor_or_offset(
    cursor: Option<&str>,
    offset: Option<u32>,
) -> Result<(Option<String>, u32), axum::response::Response> {
    let clean_cursor = cursor
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let off = check_offset(offset.unwrap_or(0))?;
    if clean_cursor.is_some() && off > 0 {
        return Err(bad_request("cannot combine cursor and nonzero offset"));
    }
    Ok((clean_cursor, off))
}

/// Migration deadline advertised on the legacy `/api/...` aliases.
///
/// RFC 8594 `Sunset` value; kept in sync with `API_VERSIONING.md`.
pub const LEGACY_API_SUNSET: &str = "Wed, 30 Jun 2027 00:00:00 GMT";

/// Response headers attached to legacy `/api/...` routes only.
///
/// The v2 routes are the canonical surface and never carry these headers.
async fn legacy_api_deprecation(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert("deprecation", HeaderValue::from_static("true"));
    headers.insert("sunset", HeaderValue::from_static(LEGACY_API_SUNSET));
    headers.insert(
        "link",
        HeaderValue::from_static("</api/v2>; rel=\"successor-version\""),
    );
    response
}

/// Build the API router.
///
/// Every handler is registered once under its version-independent relative
/// path; that router is then nested twice:
///
/// * `/api/v2` — canonical, no deprecation headers;
/// * `/api` — legacy alias, same handlers plus `Deprecation` / `Sunset` /
///   `Link` headers.
///
/// Nesting the same router keeps both surfaces from drifting: a new route is
/// automatically reachable under both prefixes, and a handler can never exist
/// on one prefix only by accident. The relative path set is the union of the
/// historical v2 spellings (`/account/:address`, `/tx/:hash`, `/txs`, ...) and
/// the historical legacy spellings (`/accounts/:address`, `/transactions/:hash`,
/// `/blocks/latest`, ...), so both old and new clients keep working during the
/// migration window.
#[derive(Clone)]
struct IndexerRouterGuard {
    limiter: Arc<stellereum::explorer::RateLimiter>,
    concurrency: Arc<Semaphore>,
    request_timeout: Duration,
}

fn resolve_indexer_client_ip(headers: &HeaderMap, peer: Option<IpAddr>) -> IpAddr {
    match peer {
        Some(ip) => stellereum::client_ip::resolve_client_ip(headers, ip).addr,
        None => stellereum::rpc::LOCAL_BUCKET_IP,
    }
}

async fn indexer_guard_middleware(
    State(guard): State<IndexerRouterGuard>,
    req: Request,
    next: Next,
) -> Response {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip());
    let client_ip = resolve_indexer_client_ip(req.headers(), peer);
    if !guard.limiter.check(client_ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "rate limit exceeded"})),
        )
            .into_response();
    }
    let Ok(_permit) = guard.concurrency.clone().try_acquire_owned() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "server busy: concurrency limit reached"})),
        )
            .into_response();
    };
    match tokio::time::timeout(guard.request_timeout, next.run(req)).await {
        Ok(resp) => resp,
        Err(_) => (
            StatusCode::REQUEST_TIMEOUT,
            Json(json!({"error": "request timed out"})),
        )
            .into_response(),
    }
}

async fn program_accounts_rate_limit_middleware(
    State(limiter): State<Arc<stellereum::explorer::RateLimiter>>,
    req: Request,
    next: Next,
) -> Response {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip());
    let client_ip = resolve_indexer_client_ip(req.headers(), peer);
    if !limiter.check(client_ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "program accounts rate limit exceeded"})),
        )
            .into_response();
    }
    next.run(req).await
}

fn indexer_rate_limit_per_sec() -> u32 {
    std::env::var("INDEXER_RATE_LIMIT_PER_SEC")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(INDEXER_RATE_LIMIT_PER_SEC_DEFAULT)
}

fn indexer_program_accounts_rate_limit_per_sec() -> u32 {
    std::env::var("INDEXER_PROGRAM_ACCOUNTS_RATE_LIMIT_PER_SEC")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(INDEXER_PROGRAM_ACCOUNTS_RATE_LIMIT_DEFAULT)
}

pub fn create_router(state: AppState) -> Router {
    create_router_with_limits(
        state,
        MAX_INDEXER_CONCURRENT_REQUESTS,
        Duration::from_secs(INDEXER_REQUEST_TIMEOUT_SECS),
        indexer_rate_limit_per_sec(),
        indexer_program_accounts_rate_limit_per_sec(),
    )
}

/// Build the API router with explicit concurrency, timeout, and per-IP rate limits.
pub fn create_router_with_limits(
    state: AppState,
    max_concurrency: usize,
    request_timeout: Duration,
    rate_limit_per_sec: u32,
    program_accounts_rate_limit_per_sec: u32,
) -> Router {
    let prog_limiter = Arc::new(stellereum::explorer::RateLimiter::new(
        program_accounts_rate_limit_per_sec,
    ));
    let api = Router::new()
        // Core network endpoints
        .route("/overview", get(get_overview))
        .route("/stats", get(get_network_stats))
        .route("/price", get(get_price))
        .route("/status", get(get_status))
        // Validators & Staking (gram.org/validators)
        .route("/validators", get(get_validators))
        .route("/staking", get(get_staking))
        // Blocks
        .route("/blocks/latest", get(get_blocks))
        .route("/blocks", get(get_blocks))
        .route("/blocks/:param", get(get_block))
        .route("/block/:param", get(get_block))
        // Transactions
        .route("/transactions/latest", get(get_recent_txs))
        .route("/txs", get(get_recent_txs))
        .route("/transactions/:hash", get(get_tx))
        .route("/tx/:hash", get(get_tx))
        // Contract events (logs)
        .route("/contract/:address/events", get(get_contract_events))
        .route("/tx/:hash/events", get(get_tx_events))
        .route("/events", get(get_events))
        // Contract source verification (audit P2-15, Sourcify-style)
        .route("/contract/:address/verify", post(verify_contract_source))
        .route("/contract/:address/source", get(get_contract_source))
        // Contracts, program accounts, and LIVE shard topology
        .route("/contracts", get(get_contracts))
        .route(
            "/program/:program/accounts",
            get(get_program_accounts).route_layer(middleware::from_fn_with_state(
                prog_limiter,
                program_accounts_rate_limit_middleware,
            )),
        )
        .route("/shards", get(get_shards))
        // Accounts, tokens, holders & History
        .route("/accounts/:address", get(get_account_info))
        .route("/account/:address", get(get_account_info))
        .route("/accounts/:address/actions", get(get_account_actions))
        .route("/accounts/:address/activity", get(get_account_actions))
        .route("/account/:address/txs", get(get_account_actions))
        .route("/account/:address/tokens", get(get_account_tokens))
        .route("/token/:token/holders", get(get_token_holders))
        .route("/whales", get(get_whales))
        // Verified Contracts & Tokens (gram.org/verified)
        .route("/verified", get(get_verified))
        .route("/verified/stats", get(get_verified_stats))
        .route("/tokens", get(get_tokens))
        // Live Geyser-lite SSE stream
        .route("/stream", get(stream_events))
        // Search & Charts
        .route("/search", get(search))
        .route("/stats/charts", get(get_charts));

    let legacy = api
        .clone()
        .layer(middleware::from_fn(legacy_api_deprecation));

    let guard = IndexerRouterGuard {
        limiter: Arc::new(stellereum::explorer::RateLimiter::new(rate_limit_per_sec)),
        concurrency: Arc::new(Semaphore::new(max_concurrency.max(1))),
        request_timeout,
    };

    Router::new()
        .nest("/api/v2", api)
        .nest("/api", legacy)
        .layer(middleware::from_fn_with_state(
            guard,
            indexer_guard_middleware,
        ))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn fetch_live_validators(state: &AppState) -> Option<Value> {
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "stell_getValidators",
        "params": {},
        "id": 1
    });
    let resp = state
        .http_client
        .post(&state.rpc_url)
        .json(&payload)
        .send()
        .await
        .ok()?;
    let data: Value = resp.json().await.ok()?;
    let res = data.get("result")?;
    if res.is_null() {
        None
    } else {
        Some(res.clone())
    }
}

fn configured_chain_id() -> u64 {
    std::env::var("INDEXER_CHAIN_ID")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(5757)
}

// 1. Overview (gram.org/api/overview)
async fn get_overview(State(state): State<AppState>) -> impl IntoResponse {
    let db = state.db.clone();
    let db_res = tokio::task::spawn_blocking(move || {
        let stats = db.get_stats().unwrap_or(crate::db::NetworkStats {
            tip_height: 0,
            total_blocks: 0,
            total_transactions: 0,
            total_accounts: 0,
            current_tps: 0.0,
            avg_block_time: 0.0,
        });

        let charts = db
            .get_charts()
            .unwrap_or_else(|_| json!({"hours":[], "days":[]}));
        let mc_stats = db
            .get_stats_for_shard(0)
            .unwrap_or(crate::db::NetworkStats {
                tip_height: 0,
                total_blocks: 0,
                total_transactions: 0,
                total_accounts: stats.total_accounts,
                current_tps: 0.0,
                avg_block_time: 0.0,
            });
        let current_tps = if stats.total_blocks == 0 {
            0.0
        } else {
            let mut tps = mc_stats.current_tps;
            for (sid, _, _) in db.get_shard_index_stats().unwrap_or_default() {
                if sid > 0 {
                    if let Ok(sh) = db.get_stats_for_shard(sid) {
                        tps += sh.current_tps;
                    }
                }
            }
            tps
        };
        let event_total = db.count_events(&EventFilter::default()).unwrap_or(0);
        let latest_rows = db
            .get_events(&EventFilter::default(), 10, 0)
            .unwrap_or_default();
        (
            stats,
            charts,
            mc_stats,
            current_tps,
            event_total,
            latest_rows,
        )
    })
    .await;

    let (stats, charts, mc_stats, current_tps, event_total, latest_rows) = match db_res {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "overview query task failed"})),
            )
                .into_response();
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let today_start = (now / 86400) * 86400;
    let yesterday_start = today_start.saturating_sub(86400);
    let yesterday_txs = charts["days"]
        .as_array()
        .and_then(|days| {
            days.iter().find_map(|entry| {
                let arr = entry.as_array()?;
                if arr.first()?.as_u64()? == yesterday_start {
                    arr.get(1)?.as_u64()
                } else {
                    None
                }
            })
        })
        .unwrap_or(0);
    let mc_seqno = mc_stats.tip_height;
    let avg_block_time = if mc_stats.total_blocks < 2 {
        0.0
    } else {
        mc_stats.avg_block_time
    };
    let chain_id = configured_chain_id();

    let live_staked = fetch_live_validators(&state)
        .await
        .and_then(|v| v["total_power"].as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "0".to_string());

    // The explorer advertises what it can serve: the ABI manifests (which
    // make the events DECODED rather than raw) and the event endpoints.
    let latest_events = latest_rows
        .iter()
        .map(|e| event_json(e, &state.abis))
        .collect::<Vec<Value>>();

    let overview = json!({
        "supply": {
            "counted": now,
            "total": "1000000000000000000", // 1B STELL in nano
            "circulating": "250000000000000000", // 250M STELL
            "staked": live_staked,
            "genesis_vault": "250000000000000000",
            "validator_rewards": "350000000000000000",
            "ecosystem": "150000000000000000",
            "team": "100000000000000000"
        },
        "transactions": {
            "daily_average": stats.total_transactions,
            "today": stats.total_transactions,
            "yesterday": yesterday_txs,
            "today_start": today_start,
            "tps": current_tps,
            "current_tps": current_tps,
            "hours": charts["hours"],
            "days": charts["days"]
        },
        "price": Value::Null,
        "network": {
            "chain_id": chain_id,
            "consensus": "Pure PQ Falcon-512 BFT",
            "tip_height": stats.tip_height,
            "mc_seqno": mc_seqno,
            "avg_block_time": avg_block_time,
            "block_time": avg_block_time,
            "total_blocks": stats.total_blocks,
            "indexed_blocks": stats.total_blocks,
            "total_transactions": stats.total_transactions,
            "indexed_txs": stats.total_transactions,
            "total_accounts": stats.total_accounts,
            "tps": current_tps,
            "current_tps": current_tps
        },
        "tps": current_tps,
        "current_tps": current_tps,
        "block_time": avg_block_time,
        "avg_block_time": avg_block_time,
        "mc_seqno": mc_seqno,
        "tip_height": stats.tip_height,
        "indexed_blocks": stats.total_blocks,
        "total_blocks": stats.total_blocks,
        "indexed_txs": stats.total_transactions,
        "total_transactions": stats.total_transactions,
        "total_accounts": stats.total_accounts,
        "abi": {
            "supported": true,
            "method": "stell_getContractAbi",
            "description": "contract ABI manifests are committed to the state trie and served by the node; the explorer uses them to decode contract events",
            "known_contracts": state.abis.len(),
            "events_decoded": true,
        },
        "events": {
            "total": event_total,
            "endpoints": {
                "by_contract": "/api/v2/contract/:address/events",
                "by_tx": "/api/v2/tx/:hash/events",
                "by_block_range": "/api/v2/events?from_block=&to_block=&contract=",
            },
            "shape": {
                "tx_hash": "hash of the transaction that emitted the event",
                "block_height": "height of the block that carried the transaction",
                "log_index": "position of the event inside the transaction",
                "contract": "emitting contract address",
                "topic0": "event signature word (32-byte hex)",
                "topics": "indexed fields",
                "data": "non-indexed fields",
                "event_name": "event name, when the contract ABI is known",
                "decoded": "true when the event was decoded with the contract ABI",
                "args": "named fields: {topics: {...}, data: {...}}",
            },
            "latest": latest_events,
        },
        "updated": now
    });

    (StatusCode::OK, Json(overview)).into_response()
}

async fn fetch_live_shards_count(state: &AppState) -> Option<u64> {
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "stell_getShards",
        "params": {},
        "id": 1
    });
    let resp = state
        .http_client
        .post(&state.rpc_url)
        .json(&payload)
        .send()
        .await
        .ok()?;
    let data: Value = resp.json().await.ok()?;
    data["result"]["total_shards"]
        .as_u64()
        .or_else(|| data["result"]["shards"].as_array().map(|a| a.len() as u64))
}

// 2. Stats (/api/v2/stats)
async fn get_network_stats(State(state): State<AppState>) -> impl IntoResponse {
    let db = state.db.clone();
    let db_res = tokio::task::spawn_blocking(move || {
        let stats = db.get_stats().unwrap_or(crate::db::NetworkStats {
            tip_height: 0,
            total_blocks: 0,
            total_transactions: 0,
            total_accounts: 0,
            current_tps: 0.0,
            avg_block_time: 0.0,
        });
        let mc_stats = db
            .get_stats_for_shard(0)
            .unwrap_or(crate::db::NetworkStats {
                tip_height: 0,
                total_blocks: 0,
                total_transactions: 0,
                total_accounts: stats.total_accounts,
                current_tps: 0.0,
                avg_block_time: 0.0,
            });

        let mut wc_blocks: u64 = 0;
        let mut wc_txs: u64 = 0;
        let mut wc_block_time_sum: f64 = 0.0;
        let mut wc_block_time_shards: u64 = 0;
        let mut wc_tps_sum: f64 = 0.0;
        for (sid, _, _) in db.get_shard_index_stats().unwrap_or_default() {
            if sid == 0 {
                continue;
            }
            if let Ok(sh) = db.get_stats_for_shard(sid) {
                wc_blocks = wc_blocks.saturating_add(sh.total_blocks);
                wc_txs = wc_txs.saturating_add(sh.total_transactions);
                wc_tps_sum += sh.current_tps;
                if sh.total_blocks >= 2 && sh.avg_block_time > 0.0 {
                    wc_block_time_sum += sh.avg_block_time;
                    wc_block_time_shards += 1;
                }
            }
        }
        (
            stats,
            mc_stats,
            wc_blocks,
            wc_txs,
            wc_block_time_sum,
            wc_block_time_shards,
            wc_tps_sum,
        )
    })
    .await;

    let (stats, mc_stats, wc_blocks, wc_txs, wc_block_time_sum, wc_block_time_shards, wc_tps_sum) =
        match db_res {
            Ok(v) => v,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "stats query task failed"})),
                )
                    .into_response();
            }
        };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let shards = fetch_live_shards_count(&state).await.unwrap_or(1);
    let validators_count = fetch_live_validators(&state)
        .await
        .and_then(|v| v["validators"].as_array().map(|a| a.len() as u64));

    let current_tps = if stats.total_blocks == 0 {
        0.0
    } else {
        mc_stats.current_tps + wc_tps_sum
    };
    let avg_block_time = if mc_stats.total_blocks < 2 {
        0.0
    } else {
        mc_stats.avg_block_time
    };
    let wc_block_time = if wc_block_time_shards > 0 {
        wc_block_time_sum / wc_block_time_shards as f64
    } else {
        0.0
    };
    let mc_block_txs = if mc_stats.total_blocks > 0 {
        mc_stats.total_transactions as f64 / mc_stats.total_blocks as f64
    } else {
        0.0
    };
    let wc_block_txs = if wc_blocks > 0 {
        wc_txs as f64 / wc_blocks as f64
    } else {
        0.0
    };
    let out = json!({
        "chain_id": configured_chain_id(),
        "mc_seqno": mc_stats.tip_height,
        "tip_height": mc_stats.tip_height,
        "mc_utime": now,
        "shards": shards,
        "validators_count": validators_count,
        "tps": current_tps,
        "current_tps": current_tps,
        "block_time": avg_block_time,
        "avg_block_time": avg_block_time,
        "wc_block_time": wc_block_time,
        "mc_block_txs": mc_block_txs,
        "wc_block_txs": wc_block_txs,
        "indexed_txs": stats.total_transactions,
        "total_transactions": stats.total_transactions,
        "indexed_blocks": stats.total_blocks,
        "total_blocks": stats.total_blocks,
        "total_accounts": stats.total_accounts
    });

    (StatusCode::OK, Json(out)).into_response()
}

// 3. Price
async fn get_price() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "price_usd": 0.25,
            "currency": "USD",
            "symbol": "STELL",
            "source": "Stellereum Genesis Vault & PMM",
            "fixed": true,
            "updated": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
        })),
    )
}

// 4. Status
async fn get_status(State(state): State<AppState>) -> impl IntoResponse {
    let db = state.db.clone();
    let (shard0_tip, max_tip) = match tokio::task::spawn_blocking(move || {
        let s0 = db.get_shard_tip_height(0).unwrap_or(0);
        let max_all = db
            .get_shard_index_stats()
            .unwrap_or_default()
            .into_iter()
            .map(|(_, h, _)| h)
            .max()
            .unwrap_or(s0);
        (s0, max_all)
    })
    .await
    {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "status query task failed"})),
            )
                .into_response();
        }
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let sync = state.sync_status.read().await.clone();
    let tip = if sync.node_tip_height.is_some() {
        shard0_tip
    } else {
        max_tip
    };
    let fresh = sync
        .last_sync_at
        .map(|ts| now.saturating_sub(ts) <= 60)
        .unwrap_or(false);
    let lag = sync.node_tip_height.map(|n| n.saturating_sub(tip));
    let synced = match (sync.node_tip_height, fresh) {
        (Some(node_tip), true) => tip.saturating_add(2) >= node_tip,
        _ => false,
    };
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "chain_id": configured_chain_id(),
            "tip_height": tip,
            "node_tip_height": sync.node_tip_height,
            "lag": lag,
            "synced": synced,
            "last_sync_at": sync.last_sync_at,
            "last_error": sync.last_error,
            "version": "0.1.0-pq-fips206",
            "time": now
        })),
    )
        .into_response()
}

// 5. Validators (live from node RPC `stell_getValidators`)
async fn get_validators(State(state): State<AppState>) -> impl IntoResponse {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let Some(res) = fetch_live_validators(&state).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": "live validator set is not available from node RPC",
                "source": "rpc",
                "validators": [],
            })),
        )
            .into_response();
    };

    let total_power_str = res["total_power"].as_str().unwrap_or("0").to_string();
    let total_power_num: f64 = total_power_str.parse::<u128>().unwrap_or(0) as f64;
    let quorum_str = res["quorum"].as_str().unwrap_or("0").to_string();
    let fragile = res["fragile"].as_bool().unwrap_or(false);
    let fragile_reason = res["fragile_reason"].clone();

    let mut raw_vals: Vec<(String, u128, String, String)> = res["validators"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| {
                    let addr = v["validator"].as_str()?.to_string();
                    let power_str = v["power"].as_str().unwrap_or("0").to_string();
                    let power_u128 = power_str.parse::<u128>().unwrap_or(0);
                    let falcon_pubkey = v["falcon_pubkey"].as_str().unwrap_or("").to_string();
                    Some((addr, power_u128, power_str, falcon_pubkey))
                })
                .collect()
        })
        .unwrap_or_default();

    raw_vals.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let validators_json: Vec<Value> = raw_vals
        .iter()
        .enumerate()
        .map(|(idx, (addr, power_u128, power_str, falcon_pubkey))| {
            let weight = if total_power_num > 0.0 {
                ((*power_u128 as f64) / total_power_num * 10000.0).round() / 10000.0
            } else {
                0.0
            };
            let stl57 = crate::db::to_stl57(addr).unwrap_or_default();
            json!({
                "rank": idx + 1,
                "address": addr,
                "address_stl57": stl57,
                "name": format!("Validator {}", &addr.chars().take(8).collect::<String>()),
                "stake": power_str,
                "self_bond": power_str,
                "delegated": "0",
                "weight": weight,
                "main": true,
                "status": "active",
                "uptime": 100.0,
                "commission_bps": 0,
                "falcon_pubkey": falcon_pubkey,
                "blocks_proposed": 0
            })
        })
        .collect();

    let out = json!({
        "source": "rpc",
        "limits": {
            "min_stake": "1100000000000",
            "max_stake": "2000000000000"
        },
        "round": {
            "total_stake": total_power_str,
            "validators": validators_json.len(),
            "min_stake": "1100000000000",
            "max_stake": "2000000000000",
            "quorum": quorum_str,
            "fragile": fragile,
            "fragile_reason": fragile_reason,
            "apy": 0.145
        },
        "validators": validators_json,
        "updated": now
    });

    (StatusCode::OK, Json(out)).into_response()
}

// 6. Staking (live from node RPC `stell_getValidators`)
async fn get_staking(State(state): State<AppState>) -> impl IntoResponse {
    let Some(res) = fetch_live_validators(&state).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": "live staking state is not available from node RPC",
                "source": "rpc",
            })),
        )
            .into_response();
    };
    let total_staked = res["total_power"].as_str().unwrap_or("0");
    let count = res["validators"].as_array().map(|a| a.len()).unwrap_or(0);
    let total_num: f64 = total_staked.parse::<u128>().unwrap_or(0) as f64;
    let staked_pct = if total_num > 0.0 {
        total_num / 1_000_000_000_000_000_000.0
    } else {
        0.0
    };
    (
        StatusCode::OK,
        Json(json!({
            "source": "rpc",
            "total_staked": total_staked,
            "staked_percentage": staked_pct,
            "validators_count": count,
            "quorum": res["quorum"],
            "fragile": res["fragile"],
            "cooldown_period_secs": 172800,
            "min_validator_bond": "1100000000000",
            "estimated_apy": 0.145,
            "slashing_penalty_bps": {
                "downtime": 10,
                "equivocation": 500
            }
        })),
    )
        .into_response()
}

// 7. Verified Smart Contracts & Actors (gram.org/api/verified)
async fn get_verified() -> impl IntoResponse {
    let items = json!([
        {
            "name": "Stellereum Genesis Vault",
            "symbol": "GVAULT",
            "category": "system",
            "address": "0000000000000000000000000000000000000000000000000000000000000001",
            "language": "SVM / Rust Native",
            "code_hash": "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
            "abi": true,
            "verified_at": 1792000000,
            "version": "1.0.0",
            "description": "Public fixed-rate exchange vault ($0.25 USD) for TON/USDT to STELL"
        },
        {
            "name": "Teleport Bridge Escrow",
            "symbol": "TELEPORT",
            "category": "bridge",
            "address": "0000000000000000000000000000000000000000000000000000000000000002",
            "language": "SVM / Rust Native",
            "code_hash": "b2c3d4e5f6a7890123456789abcdef0123456789abcdef0123456789abcdef01",
            "abi": true,
            "verified_at": 1792000000,
            "version": "1.0.0",
            "description": "Optimistic decentralized cross-chain bridge to TON, Ethereum and Solana"
        },
        {
            "name": "CLOB Central Limit Orderbook",
            "symbol": "CLOB",
            "category": "exchange",
            "address": "0000000000000000000000000000000000000000000000000000000000000003",
            "language": "SVM / Rust Native",
            "code_hash": "c3d4e5f6a7b890123456789abcdef0123456789abcdef0123456789abcdef012",
            "abi": true,
            "verified_at": 1792000000,
            "version": "1.0.0",
            "description": "In-VM decentralized high-frequency orderbook actor with micro-gas"
        },
        {
            "name": "Proactive Market Maker (PMM)",
            "symbol": "PMM",
            "category": "amm",
            "address": "0000000000000000000000000000000000000000000000000000000000000004",
            "language": "SVM / Rust Native",
            "code_hash": "d4e5f6a7b8c90123456789abcdef0123456789abcdef0123456789abcdef0123",
            "abi": true,
            "verified_at": 1792000000,
            "version": "1.0.0",
            "description": "Automated liquidity maker with oracle price anchoring and circuit breaker"
        },
        {
            "name": "Stellereum Staking Pool",
            "symbol": "STAKE",
            "category": "staking",
            "address": "5354414b494e475f504f4f4c0000000000000000000000000000000000000000",
            "language": "SVM / Rust Native",
            "code_hash": "e5f6a7b8c9d0123456789abcdef0123456789abcdef0123456789abcdef01234",
            "abi": true,
            "verified_at": 1792000000,
            "version": "1.0.0",
            "description": "Validator bonding and delegation pool with cooldown protection"
        }
    ]);

    (
        StatusCode::OK,
        Json(json!({
            "items": items,
            "total": 5,
            "limit": 20,
            "offset": 0
        })),
    )
}

async fn get_verified_stats() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "total_verified": 5,
            "languages": { "SVM": 5, "Wasm": 0 },
            "categories": { "system": 1, "bridge": 1, "exchange": 1, "amm": 1, "staking": 1 }
        })),
    )
}

// 8. Tokens (native STELL + live `stell_listTokens` from node RPC)
async fn get_tokens(
    State(state): State<AppState>,
    Query(p): Query<Pagination>,
) -> impl IntoResponse {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let limit = p.limit.unwrap_or(100).min(MAX_HISTORY_PAGE);
    let (cursor, offset) = match resolve_cursor_or_offset(p.cursor.as_deref(), p.offset) {
        Ok(v) => v,
        Err(r) => return r,
    };

    let mut tokens = Vec::new();
    if cursor.is_none() && offset == 0 {
        tokens.push(json!({
            "address": "0000000000000000000000000000000000000000000000000000000000000000",
            "name": "Stellereum",
            "symbol": "STELL",
            "decimals": 9,
            "price": 0.25,
            "change_24h": 0.0,
            "market_cap": 250000000.0,
            "verified": true,
            "image": "/assets/img/logo.svg"
        }));
    }

    let mut rpc_params = json!({ "limit": limit, "offset": offset });
    if let Some(ref cur) = cursor {
        rpc_params["cursor"] = json!(cur);
    }
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "stell_listTokens",
        "params": rpc_params,
        "id": 1
    });
    let mut next_cursor: Option<String> = None;
    let mut has_more = false;
    if let Ok(resp) = state
        .http_client
        .post(&state.rpc_url)
        .json(&payload)
        .send()
        .await
    {
        if let Ok(data) = resp.json::<Value>().await {
            if let Some(ids) = data["result"]["tokens"].as_array() {
                for id_val in ids {
                    if let Some(addr) = id_val.as_str() {
                        tokens.push(json!({
                            "address": addr,
                            "address_stl57": crate::db::to_stl57(addr),
                            "verified": false,
                        }));
                    }
                }
            }
            next_cursor = data["result"]["next_cursor"].as_str().map(str::to_string);
            has_more = data["result"]["has_more"].as_bool().unwrap_or(false);
        }
    }

    (
        StatusCode::OK,
        Json(json!({
            "source": "Stellereum Token Registry",
            "tokens": tokens,
            "total": tokens.len(),
            "limit": limit,
            "offset": offset,
            "next_cursor": next_cursor,
            "has_more": has_more,
            "updated": now
        })),
    )
        .into_response()
}

fn parse_shard_height(param: &str) -> Option<(u32, u64)> {
    let (prefix, rest) = param.trim().split_once(':')?;
    let shard_id = if prefix.trim() == "-1" {
        0
    } else {
        prefix.trim().parse::<u32>().ok()?
    };
    let height = rest.trim().parse::<u64>().ok()?;
    Some((shard_id, height))
}

// 9. Blocks
async fn get_blocks(
    State(state): State<AppState>,
    Query(p): Query<BlocksQuery>,
) -> impl IntoResponse {
    let limit = p.limit.unwrap_or(50).min(MAX_HISTORY_PAGE);
    let (cursor_str, offset) = match resolve_cursor_or_offset(p.cursor.as_deref(), p.offset) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let shard_filter = p.shard_id.or(p.shard);
    if cursor_str.is_some() || offset == 0 {
        let parsed = match cursor_str.as_deref().map(parse_block_cursor).transpose() {
            Ok(c) => c,
            Err(e) => return bad_request(e),
        };
        let db = state.db.clone();
        let res = tokio::task::spawn_blocking(move || {
            db.get_blocks_by_shard_keyset(shard_filter, limit, parsed)
        })
        .await;
        match res {
            Ok(Ok(page)) => (
                StatusCode::OK,
                Json(json!({
                    "blocks": page.items,
                    "shard_id": shard_filter,
                    "limit": limit,
                    "offset": 0,
                    "next_cursor": page.next_cursor,
                    "has_more": page.has_more,
                })),
            )
                .into_response(),
            Ok(Err(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response(),
            Err(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "blocks query task failed"})),
            )
                .into_response(),
        }
    } else {
        let db = state.db.clone();
        let res = tokio::task::spawn_blocking(move || {
            db.get_blocks_by_shard(shard_filter, limit, offset)
        })
        .await;
        match res {
            Ok(Ok(blocks)) => {
                let next_cursor = if blocks.len() == limit as usize && limit > 0 {
                    blocks.last().map(|b| {
                        if shard_filter.is_some() {
                            b.height.to_string()
                        } else {
                            format!("{}:{}", b.height, b.shard_id)
                        }
                    })
                } else {
                    None
                };
                (
                    StatusCode::OK,
                    Json(json!({
                        "blocks": blocks,
                        "shard_id": shard_filter,
                        "limit": limit,
                        "offset": offset,
                        "next_cursor": next_cursor,
                    })),
                )
                    .into_response()
            }
            Ok(Err(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response(),
            Err(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "blocks query task failed"})),
            )
                .into_response(),
        }
    }
}

async fn get_block(
    State(state): State<AppState>,
    Path(param): Path<String>,
    Query(q): Query<BlockQuery>,
) -> impl IntoResponse {
    let shard_filter = q.shard_id.or(q.shard);
    if let Some((_, h)) = parse_shard_height(&param) {
        if h > i64::MAX as u64 {
            return bad_request("block height exceeds maximum supported range");
        }
    } else if let Ok(h) = param.trim().parse::<u64>() {
        if h > i64::MAX as u64 {
            return bad_request("block height exceeds maximum supported range");
        }
    }

    let db = state.db.clone();
    let param_owned = param.clone();
    let res = tokio::task::spawn_blocking(move || {
        let block_opt = if let Some((sid, h)) = parse_shard_height(&param_owned) {
            if shard_filter.is_some_and(|expected| expected != sid) {
                Ok(None)
            } else {
                db.get_block_by_shard_and_height(sid, h)
            }
        } else if let Ok(h) = param_owned.trim().parse::<u64>() {
            db.get_block_by_shard_and_height(shard_filter.unwrap_or(0), h)
        } else {
            match db.get_block_by_hash(&param_owned) {
                Ok(Some(b)) if shard_filter.is_some_and(|expected| expected != b.shard_id) => {
                    Ok(None)
                }
                other => other,
            }
        };
        match block_opt {
            Ok(Some(b)) => {
                let txs = db
                    .get_block_txs_for_shard(b.shard_id, b.height)
                    .unwrap_or_default();
                Ok(Some((b, txs)))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    })
    .await;

    match res {
        Ok(Ok(Some((b, txs)))) => (
            StatusCode::OK,
            Json(json!({ "block": b, "transactions": txs })),
        )
            .into_response(),
        Ok(Ok(None)) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Block not found"})),
        )
            .into_response(),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "block query task failed"})),
        )
            .into_response(),
    }
}

// 10. Transactions
async fn get_recent_txs(
    State(state): State<AppState>,
    Query(p): Query<TxsQuery>,
) -> impl IntoResponse {
    let limit = p.limit.unwrap_or(50).min(MAX_HISTORY_PAGE);
    let shard_filter = p.shard_id.or(p.shard);
    let (cursor_str, offset) = match resolve_cursor_or_offset(p.cursor.as_deref(), p.offset) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if cursor_str.is_some() || offset == 0 {
        let parsed = match cursor_str.as_deref().map(parse_tx_cursor_v2).transpose() {
            Ok(c) => c,
            Err(e) => return bad_request(e),
        };
        let db = state.db.clone();
        let res = tokio::task::spawn_blocking(move || {
            db.get_account_txs_by_shard_keyset("", shard_filter, limit, parsed)
        })
        .await;
        match res {
            Ok(Ok(page)) => (
                StatusCode::OK,
                Json(json!({
                    "transactions": page.items,
                    "shard_id": shard_filter,
                    "limit": limit,
                    "offset": 0,
                    "next_cursor": page.next_cursor,
                    "has_more": page.has_more,
                })),
            )
                .into_response(),
            Ok(Err(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response(),
            Err(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "transactions query task failed"})),
            )
                .into_response(),
        }
    } else {
        let db = state.db.clone();
        let res = tokio::task::spawn_blocking(move || {
            db.get_account_txs_by_shard("", shard_filter, limit, offset)
        })
        .await;
        let txs = match res {
            Ok(Ok(rows)) => rows,
            Ok(Err(_)) => Vec::new(),
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "transactions query task failed"})),
                )
                    .into_response();
            }
        };
        (
            StatusCode::OK,
            Json(json!({
                "transactions": txs,
                "shard_id": shard_filter,
                "limit": limit,
                "offset": offset
            })),
        )
            .into_response()
    }
}

async fn get_tx(State(state): State<AppState>, Path(hash): Path<String>) -> impl IntoResponse {
    let db = state.db.clone();
    let res = tokio::task::spawn_blocking(move || db.get_tx_by_hash(&hash)).await;
    match res {
        Ok(Ok(Some(tx))) => (StatusCode::OK, Json(json!({ "transaction": tx }))).into_response(),
        Ok(Ok(None)) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Transaction not found"})),
        )
            .into_response(),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "tx query task failed"})),
        )
            .into_response(),
    }
}

// 11. Accounts
async fn get_account_info(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    let norm = crate::db::normalize_address_info(&address);
    let db = state.db.clone();
    let addr = address.clone();
    let tx_count = match tokio::task::spawn_blocking(move || {
        db.get_account_tx_count(&addr).unwrap_or(0)
    })
    .await
    {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "account info query task failed"})),
            )
                .into_response();
        }
    };
    (
        StatusCode::OK,
        Json(json!({
            "address": norm.hex_clean,
            "address_0x": norm.hex_0x,
            "stl57": norm.stl57,
            "tx_count": tx_count,
            "status": "active"
        })),
    )
        .into_response()
}

async fn get_account_actions(
    State(state): State<AppState>,
    Path(address): Path<String>,
    Query(p): Query<Pagination>,
) -> impl IntoResponse {
    let norm = crate::db::normalize_address_info(&address);
    let limit = p.limit.unwrap_or(50).min(MAX_HISTORY_PAGE);
    let (cursor_str, offset) = match resolve_cursor_or_offset(p.cursor.as_deref(), p.offset) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if cursor_str.is_some() || offset == 0 {
        let parsed = match cursor_str.as_deref().map(parse_tx_cursor_v2).transpose() {
            Ok(c) => c,
            Err(e) => return bad_request(e),
        };
        let db = state.db.clone();
        let addr = address.clone();
        let res =
            tokio::task::spawn_blocking(move || db.get_account_txs_keyset(&addr, limit, parsed))
                .await;
        match res {
            Ok(Ok(page)) => (
                StatusCode::OK,
                Json(json!({
                    "address": norm.hex_clean,
                    "address_0x": norm.hex_0x,
                    "stl57": norm.stl57,
                    "actions": page.items,
                    "transactions": page.items,
                    "limit": limit,
                    "offset": 0,
                    "next_cursor": page.next_cursor,
                    "has_more": page.has_more,
                })),
            )
                .into_response(),
            Ok(Err(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response(),
            Err(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "account actions query task failed"})),
            )
                .into_response(),
        }
    } else {
        let db = state.db.clone();
        let addr = address.clone();
        let res =
            tokio::task::spawn_blocking(move || db.get_account_txs(&addr, limit, offset)).await;
        match res {
            Ok(Ok(txs)) => (
                StatusCode::OK,
                Json(json!({
                    "address": norm.hex_clean,
                    "address_0x": norm.hex_0x,
                    "stl57": norm.stl57,
                    "actions": txs,
                    "transactions": txs,
                    "limit": limit,
                    "offset": offset
                })),
            )
                .into_response(),
            Ok(Err(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response(),
            Err(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "account actions query task failed"})),
            )
                .into_response(),
        }
    }
}

async fn get_whales(State(state): State<AppState>) -> impl IntoResponse {
    // Derive top active addresses from indexed transactions instead of fabricated balances.
    let db = state.db.clone();
    let txs = match tokio::task::spawn_blocking(move || {
        db.get_account_txs("", 200, 0).unwrap_or_default()
    })
    .await
    {
        Ok(rows) => rows,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "whales query task failed"})),
            )
                .into_response();
        }
    };
    let mut counts: std::collections::HashMap<String, (Option<String>, u64)> =
        std::collections::HashMap::new();
    for t in txs {
        for raw_addr in [t.from_addr, t.to_addr] {
            if raw_addr.trim().is_empty() {
                continue;
            }
            let norm = crate::db::normalize_address_info(&raw_addr);
            if norm.hex_clean.is_empty() {
                continue;
            }
            let entry = counts.entry(norm.hex_clean).or_insert((None, 0));
            if entry.0.is_none() {
                entry.0 = norm.stl57;
            }
            entry.1 += 1;
        }
    }
    let mut ranked: Vec<(String, Option<String>, u64)> = counts
        .into_iter()
        .map(|(addr, (stl57, count))| (addr, stl57, count))
        .collect();
    ranked.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));
    ranked.truncate(20);
    let whales: Vec<Value> = ranked
        .into_iter()
        .map(|(address, address_stl57, tx_count)| {
            json!({
                "address": address,
                "address_stl57": address_stl57,
                "tx_count": tx_count,
            })
        })
        .collect();
    (
        StatusCode::OK,
        Json(json!({
            "source": "db",
            "whales": whales,
        })),
    )
        .into_response()
}

// 12. Search & Charts
async fn search(State(state): State<AppState>, Query(q): Query<SearchQuery>) -> impl IntoResponse {
    let Some(query) = q.q else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "missing query parameter 'q'"})),
        )
            .into_response();
    };
    let trimmed = query.trim().to_string();
    let db = state.db.clone();
    let res = tokio::task::spawn_blocking(move || {
        if let Some((sid, h)) = parse_shard_height(&trimmed) {
            if let Ok(Some(b)) = db.get_block_by_shard_and_height(sid, h) {
                return Some(json!({ "type": "block", "result": b }));
            }
        }

        if let Ok(h) = trimmed.parse::<u64>() {
            if let Ok(Some(b)) = db.get_block_by_shard_and_height(0, h) {
                return Some(json!({ "type": "block", "result": b }));
            }
        }

        if let Ok(Some(tx)) = db.get_tx_by_hash(&trimmed) {
            return Some(json!({ "type": "transaction", "result": tx }));
        }

        if let Ok(Some(b)) = db.get_block_by_hash(&trimmed) {
            return Some(json!({ "type": "block", "result": b }));
        }

        let norm = crate::db::normalize_address_info(&trimmed);
        if norm.bytes32.is_some() {
            let tx_count = db.get_account_tx_count(&trimmed).unwrap_or(0);
            return Some(json!({
                "type": "account",
                "address": norm.hex_clean,
                "address_0x": norm.hex_0x,
                "stl57": norm.stl57,
                "tx_count": tx_count,
            }));
        }

        None
    })
    .await;

    match res {
        Ok(Some(body)) => (StatusCode::OK, Json(body)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "No match found"})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "search query task failed"})),
        )
            .into_response(),
    }
}

async fn get_charts(State(state): State<AppState>) -> impl IntoResponse {
    let db = state.db.clone();
    let res = tokio::task::spawn_blocking(move || db.get_charts()).await;
    match res {
        Ok(Ok(charts)) => (StatusCode::OK, Json(charts)).into_response(),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "charts query task failed"})),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// Contract events
// ---------------------------------------------------------------------------

/// The JSON shape of one contract event.
///
/// The event is DECODED when the emitting contract's ABI is known: `args`
/// then holds the NAMED fields (`{"topics": {...}, "data": {...}}`). When the
/// ABI is unknown the raw parts (`topic0`, `topics`, `data`) are still served
/// — never a blob, never a guess.
fn event_json(rec: &EventRecord, abis: &AbiCache) -> Value {
    let topics: Value = serde_json::from_str(&rec.topics_json).unwrap_or_else(|_| json!([]));
    let data: Value = serde_json::from_str(&rec.data).unwrap_or(Value::Null);

    // The stored decoded form wins; when it is absent but the ABI is known
    // NOW (it may have been fetched after the event was indexed) the event is
    // decoded on the spot.
    let mut args: Option<Value> = rec
        .decoded_json
        .as_ref()
        .and_then(|s| serde_json::from_str::<Value>(s).ok());
    let mut event_name = rec.event_name.clone();
    if args.is_none() {
        if let Some(abi) = abis.get(&rec.contract) {
            let raw = RawEvent {
                contract: rec.contract.clone(),
                topic0: Some(rec.topic0.clone()),
                topics: topics.as_array().cloned().unwrap_or_default(),
                data: Some(data.clone()),
                topic: topic_index_of(&rec.topic0),
                value: None,
                event_name: rec.event_name.clone(),
            };
            let decoded = decode_event(Some(&abi), &raw);
            args = decoded.args;
            if event_name.is_none() {
                event_name = decoded.event_name;
            }
        }
    }

    json!({
        "tx_hash": rec.tx_hash,
        "block_height": rec.block_height,
        "log_index": rec.log_index,
        "contract": rec.contract,
        "contract_stl57": crate::db::to_stl57(&rec.contract),
        "topic0": rec.topic0,
        "topics": topics,
        "data": data,
        "event_name": event_name,
        "decoded": args.is_some(),
        "args": args,
    })
}

/// The event index encoded in a topic0 word, when it is one.
///
/// The native VM emits an integer topic id, which the indexer renders as a
/// 32-byte word (`0x` + 64 hex digits). A real signature hash is far larger
/// than any event index, so it never resolves to one.
fn topic_index_of(topic0: &str) -> Option<i64> {
    let clean = topic0.trim().strip_prefix("0x").unwrap_or(topic0.trim());
    if clean.len() != 64 || !clean.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let idx = u64::from_str_radix(clean, 16).ok()?;
    if idx > u32::MAX as u64 {
        return None;
    }
    Some(idx as i64)
}

/// `GET /api/v2/contract/:address/events` — the events of one contract.
async fn get_contract_events(
    State(state): State<AppState>,
    Path(address): Path<String>,
    Query(p): Query<Pagination>,
) -> impl IntoResponse {
    let norm = crate::db::normalize_address_info(&address);
    let limit = p.limit.unwrap_or(50).min(MAX_EVENT_PAGE);
    let (cursor_str, offset) = match resolve_cursor_or_offset(p.cursor.as_deref(), p.offset) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let filter = EventFilter {
        contract: Some(address.clone()),
        ..Default::default()
    };
    if cursor_str.is_some() || offset == 0 {
        let parsed = match cursor_str.as_deref().map(parse_event_cursor).transpose() {
            Ok(c) => c,
            Err(e) => return bad_request(e),
        };
        let db = state.db.clone();
        let res = tokio::task::spawn_blocking(move || {
            let page = db.get_events_keyset(&filter, limit, parsed)?;
            let total = db.count_events(&filter).unwrap_or(page.items.len() as u64);
            Ok::<_, rusqlite::Error>((page, total))
        })
        .await;
        match res {
            Ok(Ok((page, total))) => {
                let events: Vec<Value> = page
                    .items
                    .iter()
                    .map(|e| event_json(e, &state.abis))
                    .collect();
                (
                    StatusCode::OK,
                    Json(json!({
                        "contract": norm.hex_clean,
                        "contract_stl57": norm.stl57,
                        "events": events,
                        "count": events.len(),
                        "total": total,
                        "limit": limit,
                        "offset": 0,
                        "next_cursor": page.next_cursor,
                        "has_more": page.has_more,
                    })),
                )
                    .into_response()
            }
            Ok(Err(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response(),
            Err(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "contract events query task failed"})),
            )
                .into_response(),
        }
    } else {
        let db = state.db.clone();
        let res = tokio::task::spawn_blocking(move || {
            let rows = db.get_events(&filter, limit, offset)?;
            let total = db.count_events(&filter).unwrap_or(rows.len() as u64);
            Ok::<_, rusqlite::Error>((rows, total))
        })
        .await;
        match res {
            Ok(Ok((rows, total))) => {
                let events: Vec<Value> = rows.iter().map(|e| event_json(e, &state.abis)).collect();
                (
                    StatusCode::OK,
                    Json(json!({
                        "contract": norm.hex_clean,
                        "contract_stl57": norm.stl57,
                        "events": events,
                        "count": events.len(),
                        "total": total,
                        "limit": limit,
                        "offset": offset,
                    })),
                )
                    .into_response()
            }
            Ok(Err(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response(),
            Err(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "contract events query task failed"})),
            )
                .into_response(),
        }
    }
}

/// `GET /api/v2/tx/:hash/events` — the events of one transaction.
async fn get_tx_events(
    State(state): State<AppState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    let filter = EventFilter {
        tx_hash: Some(hash.clone()),
        ..Default::default()
    };
    let db = state.db.clone();
    let res =
        tokio::task::spawn_blocking(move || db.get_events_keyset(&filter, MAX_EVENT_PAGE, None))
            .await;
    match res {
        Ok(Ok(page)) => {
            let events: Vec<Value> = page
                .items
                .iter()
                .map(|e| event_json(e, &state.abis))
                .collect();
            (
                StatusCode::OK,
                Json(json!({
                    "tx_hash": hash,
                    "events": events,
                    "count": events.len(),
                    "has_more": page.has_more,
                })),
            )
                .into_response()
        }
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "tx events query task failed"})),
        )
            .into_response(),
    }
}

/// `GET /api/v2/events?from_block=&to_block=&contract=&shard_id=&cursor=&limit=` — filtered events.
async fn get_events(
    State(state): State<AppState>,
    Query(q): Query<EventsQuery>,
) -> impl IntoResponse {
    let limit = q.limit.unwrap_or(50).min(MAX_EVENT_PAGE);
    let shard_filter = q.shard_id.or(q.shard);
    let (cursor_str, offset) = match resolve_cursor_or_offset(q.cursor.as_deref(), q.offset) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let filter = EventFilter {
        from_block: q.from_block,
        to_block: q.to_block,
        contract: q.contract.clone(),
        tx_hash: None,
        shard_id: shard_filter,
    };
    if cursor_str.is_some() || offset == 0 {
        let parsed = match cursor_str.as_deref().map(parse_event_cursor).transpose() {
            Ok(c) => c,
            Err(e) => return bad_request(e),
        };
        let db = state.db.clone();
        let res = tokio::task::spawn_blocking(move || {
            let page = db.get_events_keyset(&filter, limit, parsed)?;
            let total = db.count_events(&filter).unwrap_or(page.items.len() as u64);
            Ok::<_, rusqlite::Error>((page, total))
        })
        .await;
        match res {
            Ok(Ok((page, total))) => {
                let events: Vec<Value> = page
                    .items
                    .iter()
                    .map(|e| event_json(e, &state.abis))
                    .collect();
                (
                    StatusCode::OK,
                    Json(json!({
                        "events": events,
                        "count": events.len(),
                        "total": total,
                        "from_block": q.from_block,
                        "to_block": q.to_block,
                        "contract": q.contract,
                        "shard_id": shard_filter,
                        "limit": limit,
                        "offset": 0,
                        "next_cursor": page.next_cursor,
                        "has_more": page.has_more,
                    })),
                )
                    .into_response()
            }
            Ok(Err(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response(),
            Err(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "events query task failed"})),
            )
                .into_response(),
        }
    } else {
        let db = state.db.clone();
        let res = tokio::task::spawn_blocking(move || {
            let rows = db.get_events(&filter, limit, offset)?;
            let total = db.count_events(&filter).unwrap_or(rows.len() as u64);
            Ok::<_, rusqlite::Error>((rows, total))
        })
        .await;
        match res {
            Ok(Ok((rows, total))) => {
                let events: Vec<Value> = rows.iter().map(|e| event_json(e, &state.abis)).collect();
                (
                    StatusCode::OK,
                    Json(json!({
                        "events": events,
                        "count": events.len(),
                        "total": total,
                        "from_block": q.from_block,
                        "to_block": q.to_block,
                        "contract": q.contract,
                        "shard_id": shard_filter,
                        "limit": limit,
                        "offset": offset,
                    })),
                )
                    .into_response()
            }
            Ok(Err(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response(),
            Err(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "events query task failed"})),
            )
                .into_response(),
        }
    }
}

/// `GET /api/v2/contracts` — indexed contracts (deployed contracts and event
/// emitters), bounded and keyset-paginated.
async fn get_contracts(
    State(state): State<AppState>,
    Query(p): Query<ContractsQuery>,
) -> impl IntoResponse {
    let limit = p.limit.unwrap_or(50).min(MAX_EVENT_PAGE);
    let shard_filter = p.shard_id.or(p.shard);
    let (cursor_str, offset) = match resolve_cursor_or_offset(p.cursor.as_deref(), p.offset) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let map_summary = |c: &crate::db::ContractSummary| {
        json!({
            "contract": c.contract,
            "contract_stl57": c.contract_stl57,
            "event_count": c.event_count,
            "tx_count": c.tx_count,
            "first_block": c.first_block,
            "last_block": c.last_block,
            "last_event_name": c.last_event_name,
            "events_url": format!("/api/v2/contract/{}/events", c.contract),
        })
    };
    if cursor_str.is_some() || offset == 0 {
        let parsed = match cursor_str
            .as_deref()
            .map(parse_contracts_cursor)
            .transpose()
        {
            Ok(c) => c,
            Err(e) => return bad_request(e),
        };
        let db = state.db.clone();
        let res = tokio::task::spawn_blocking(move || {
            let page = db.list_contracts_in_shard_keyset(shard_filter, limit, parsed)?;
            let total = db
                .count_contracts_in_shard(shard_filter)
                .unwrap_or(page.items.len() as u64);
            Ok::<_, rusqlite::Error>((page, total))
        })
        .await;
        match res {
            Ok(Ok((page, total))) => {
                let contracts: Vec<Value> = page.items.iter().map(map_summary).collect();
                (
                    StatusCode::OK,
                    Json(json!({
                        "contracts": contracts,
                        "count": contracts.len(),
                        "total": total,
                        "shard_id": shard_filter,
                        "limit": limit,
                        "offset": 0,
                        "next_cursor": page.next_cursor,
                        "has_more": page.has_more,
                    })),
                )
                    .into_response()
            }
            Ok(Err(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response(),
            Err(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "contracts query task failed"})),
            )
                .into_response(),
        }
    } else {
        let db = state.db.clone();
        let res = tokio::task::spawn_blocking(move || {
            let rows = db.list_contracts_in_shard(shard_filter, limit, offset)?;
            let total = db
                .count_contracts_in_shard(shard_filter)
                .unwrap_or(rows.len() as u64);
            Ok::<_, rusqlite::Error>((rows, total))
        })
        .await;
        match res {
            Ok(Ok((rows, total))) => {
                let contracts: Vec<Value> = rows.iter().map(map_summary).collect();
                (
                    StatusCode::OK,
                    Json(json!({
                        "contracts": contracts,
                        "count": contracts.len(),
                        "total": total,
                        "shard_id": shard_filter,
                        "limit": limit,
                        "offset": offset,
                    })),
                )
                    .into_response()
            }
            Ok(Err(e)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response(),
            Err(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "contracts query task failed"})),
            )
                .into_response(),
        }
    }
}

/// Constant-time comparison using fixed-length SHA-256 digests so token
/// length or prefix differences do not leak through timing.
fn constant_time_eq(a: &str, b: &str) -> bool {
    stellereum::rpc::constant_time_eq(a, b)
}

async fn get_shards(
    State(state): State<AppState>,
    Query(q): Query<ShardsQuery>,
) -> impl IntoResponse {
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "stell_getShards",
        "params": {},
        "id": 1
    });
    let fetched = match state
        .http_client
        .post(&state.rpc_url)
        .json(&payload)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(resp) => resp.json::<Value>().await.ok(),
        Err(_) => None,
    };
    match fetched.as_ref().map(|d| d["result"].clone()) {
        Some(result) if !result.is_null() => {
            let mut out = result;
            let db = state.db.clone();
            let shard_stats = match tokio::task::spawn_blocking(move || {
                db.get_shard_index_stats().unwrap_or_default()
            })
            .await
            {
                Ok(s) => s,
                Err(_) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "shards query task failed"})),
                    )
                        .into_response();
                }
            };
            let indexed_map: std::collections::HashMap<u32, (u64, u64)> = shard_stats
                .into_iter()
                .map(|(sid, tip, cnt)| (sid, (tip, cnt)))
                .collect();
            struct ShardPrefixInfo {
                shard_id: u32,
                prefix: u64,
                prefix_len: u8,
                has_prefix: bool,
            }

            let mut workchain_shards: Vec<ShardPrefixInfo> = Vec::new();
            let mut shard_len: usize = 0;

            if let Some(obj) = out.as_object_mut() {
                if let Some(arr) = obj.get_mut("shards").and_then(|v| v.as_array_mut()) {
                    shard_len = arr.len();
                    for item in arr.iter_mut() {
                        if let Some(sid) = item["shard_id"]
                            .as_u64()
                            .and_then(|v| u32::try_from(v).ok())
                        {
                            if sid > 0 {
                                let explicit_len = item
                                    .get("prefix_len")
                                    .and_then(|v| v.as_u64())
                                    .and_then(|v| u8::try_from(v).ok());
                                let explicit_prefix = item.get("prefix").and_then(|v| v.as_u64());
                                let (prefix, prefix_len, has_prefix) =
                                    if explicit_len.is_some() || explicit_prefix.is_some() {
                                        (
                                            explicit_prefix.unwrap_or(0),
                                            explicit_len.unwrap_or(0),
                                            true,
                                        )
                                    } else if let Some(bits) =
                                        item.get("prefix_bits").and_then(|v| v.as_str())
                                    {
                                        let trimmed = bits.trim();
                                        if trimmed.is_empty() {
                                            (0, 0, true)
                                        } else if trimmed.len() <= 64
                                            && trimmed.bytes().all(|b| b == b'0' || b == b'1')
                                        {
                                            let len = trimmed.len() as u8;
                                            let val = u64::from_str_radix(trimmed, 2).unwrap_or(0);
                                            let shift = 64u32.saturating_sub(u32::from(len));
                                            let word = if shift >= 64 { 0 } else { val << shift };
                                            (word, len, true)
                                        } else {
                                            (0, 0, false)
                                        }
                                    } else {
                                        (0, 0, false)
                                    };
                                workchain_shards.push(ShardPrefixInfo {
                                    shard_id: sid,
                                    prefix,
                                    prefix_len,
                                    has_prefix,
                                });
                            }
                            let (indexed_tip, indexed_blocks) =
                                indexed_map.get(&sid).copied().unwrap_or((0, 0));
                            if let Some(item_obj) = item.as_object_mut() {
                                item_obj
                                    .insert("indexed_tip_height".to_string(), json!(indexed_tip));
                                item_obj
                                    .insert("indexed_blocks".to_string(), json!(indexed_blocks));
                            }
                        }
                    }
                }
                if !obj.contains_key("total_shards") || obj["total_shards"].is_null() {
                    obj.insert("total_shards".to_string(), json!(shard_len));
                }
                obj.insert("source".to_string(), json!("rpc"));
                if let Some(raw_addr) = q
                    .address
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    let norm = crate::db::normalize_address_info(raw_addr);
                    let routed_shard = if let Some(hint) = norm.shard_hint {
                        Some(hint)
                    } else if let Some(addr32) = norm.bytes32 {
                        if workchain_shards.len() == 1 {
                            Some(workchain_shards[0].shard_id)
                        } else if workchain_shards.len() >= 2 {
                            if workchain_shards.iter().any(|s| s.has_prefix) {
                                let mut best: Option<&ShardPrefixInfo> = None;
                                for s in &workchain_shards {
                                    let desc = stellereum::sharding::ShardDescriptor::new(
                                        s.shard_id,
                                        0,
                                        s.prefix,
                                        s.prefix_len,
                                    );
                                    if !desc.contains_address(&addr32) {
                                        continue;
                                    }
                                    best = match best {
                                        None => Some(s),
                                        Some(b)
                                            if s.prefix_len > b.prefix_len
                                                || (s.prefix_len == b.prefix_len
                                                    && s.shard_id < b.shard_id) =>
                                        {
                                            Some(s)
                                        }
                                        other => other,
                                    };
                                }
                                best.map(|s| s.shard_id)
                                    .or_else(|| workchain_shards.iter().map(|s| s.shard_id).min())
                            } else {
                                None
                            }
                        } else if shard_len == 1 {
                            Some(0)
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    obj.insert(
                        "address_lookup".to_string(),
                        json!({
                            "address": norm.hex_clean,
                            "address_0x": norm.hex_0x,
                            "stl57": norm.stl57,
                            "shard_hint": norm.shard_hint,
                            "routed_shard": routed_shard,
                        }),
                    );
                }
            }
            (StatusCode::OK, Json(out)).into_response()
        }
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": "the node's shard topology is not available",
                "source": "rpc",
                "shards": [],
                "total_shards": 0,
            })),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// Contract source verification (audit P2-15, Sourcify-style)
// ---------------------------------------------------------------------------

/// Maximum accepted source submission (1 MiB — mirrors the node's
/// `MAX_CONTRACT_SOURCE_SIZE`; the explorer never forwards more).
const MAX_VERIFY_SOURCE_SIZE: usize = 1024 * 1024;

/// Body of `POST /api/v2/contract/:address/verify`.
///
/// `source` is the canonical `.wat` text inline; `source_hex` is hex of the
/// same UTF-8 text. `compiler` defaults to `wat2wasm-1.0`, `compiler_flags`
/// (alias `flags`) to the empty string — the same defaults the node applies.
#[derive(Deserialize)]
pub struct VerifyRequest {
    pub source: Option<String>,
    pub source_hex: Option<String>,
    pub compiler: Option<String>,
    pub compiler_flags: Option<String>,
    pub flags: Option<String>,
}

/// Exact source text the node will rebuild, from the two accepted forms.
///
/// Mirrors `stellereum/src/contract_source.rs::decode_source_bytes`:
/// `source_hex` WINS when both are supplied. The indexer stores this text in
/// the verified-source registry only after the node says `verified: true`, so
/// a pair whose halves disagree is refused instead of storing an unverified
/// lookalike.
fn source_text_from_request(body: &VerifyRequest) -> Result<String, String> {
    match (body.source.as_deref(), body.source_hex.as_deref()) {
        (Some(text), Some(hex_text)) => {
            let bytes = decode_source_hex(hex_text)?;
            if bytes != text.as_bytes() {
                return Err(
                    "source and source_hex disagree; send exactly one form (they must encode the same .wat text)"
                        .to_string(),
                );
            }
            Ok(text.to_string())
        }
        (Some(text), None) => Ok(text.to_string()),
        (None, Some(hex_text)) => {
            let bytes = decode_source_hex(hex_text)?;
            String::from_utf8(bytes).map_err(|_| "source_hex is not UTF-8 .wat text".to_string())
        }
        (None, None) => Err("missing source: provide 'source' or 'source_hex'".to_string()),
    }
}

fn decode_source_hex(hex_text: &str) -> Result<Vec<u8>, String> {
    let trimmed = hex_text.trim();
    let clean = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if clean.is_empty() || !clean.len().is_multiple_of(2) {
        return Err("source_hex: expected even-length hex".to_string());
    }
    let bytes = hex::decode(clean).map_err(|e| format!("source_hex: bad hex: {e}"))?;
    if bytes.is_empty() {
        return Err("source_hex is empty".to_string());
    }
    if bytes.len() > MAX_VERIFY_SOURCE_SIZE {
        return Err("source_hex exceeds 1 MiB of source text".to_string());
    }
    Ok(bytes)
}

/// Ask the NODE to verify a claimed contract source.
///
/// The indexer NEVER decides locally: the submission is forwarded to the
/// node's `stell_verifyContractSource`, and a row is stored ONLY when the
/// node answers `verified: true`. When the node is unreachable (or refuses)
/// the endpoint says so explicitly instead of inventing a verdict.
async fn verify_contract_source(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(address): Path<String>,
    Json(body): Json<VerifyRequest>,
) -> impl IntoResponse {
    // Audit B-IDX-3: the only state-changing endpoint requires the operator
    // token (anonymous 1MiB writes = DB-fill + node-RPC spend). Default-deny:
    // unset or empty/whitespace token refuses everything with 401.
    let authorized = match state
        .verify_token
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(expected) => headers
            .get("x-api-key")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .is_some_and(|got| constant_time_eq(got, expected)),
        _ => false,
    };
    if !authorized {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "verify endpoint requires X-Api-Key (set INDEXER_VERIFY_TOKEN)"})),
        )
            .into_response();
    }
    let key = normalize_contract_key(&address);
    if key.is_empty() || key.len() > 64 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid contract address"})),
        )
            .into_response();
    }
    if let Some(s) = body.source.as_ref() {
        if s.is_empty() || s.len() > MAX_VERIFY_SOURCE_SIZE {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(json!({"error": "source is empty or exceeds 1 MiB"})),
            )
                .into_response();
        }
    }
    if let Some(h) = body.source_hex.as_ref() {
        if h.len() > 2 * MAX_VERIFY_SOURCE_SIZE + 2 {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(json!({"error": "source_hex exceeds 1 MiB of source text"})),
            )
                .into_response();
        }
    }
    if body.source.is_none() && body.source_hex.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "missing source: provide 'source' (wat text) or 'source_hex'"})),
        )
            .into_response();
    }

    // R2-X: the NODE prefers `source_hex` over `source` when BOTH are sent
    // (`contract_source::decode_source_bytes`). A verified row's `source_text`
    // must be exactly the text the node rebuilt; otherwise a caller holding
    // the operator token could get legitimate bytes verified while the
    // explorer stores (and later serves) a different, unverified source.
    // Refuse an ambiguous pair (or undecodable/non-UTF-8 hex) fail-closed.
    let verified_source_text = match source_text_from_request(&body) {
        Ok(text) => text,
        Err(msg) => return bad_request(msg),
    };

    let compiler = body.compiler.as_deref().unwrap_or("wat2wasm-1.0");
    let flags = body
        .compiler_flags
        .as_deref()
        .or(body.flags.as_deref())
        .unwrap_or("");
    let mut params = serde_json::Map::new();
    params.insert("contract".to_string(), json!(key));
    if let Some(s) = body.source.as_ref() {
        params.insert("source".to_string(), json!(s));
    }
    if let Some(h) = body.source_hex.as_ref() {
        params.insert("source_hex".to_string(), json!(h));
    }
    params.insert("compiler".to_string(), json!(compiler));
    params.insert("compiler_flags".to_string(), json!(flags));
    let payload = json!({
        "jsonrpc": "2.0",
        "method": "stell_verifyContractSource",
        "params": params,
        "id": 1,
    });

    let node_reply: Value = match state
        .http_client
        .post(&state.rpc_url)
        .json(&payload)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
    {
        Ok(resp) => match resp.json::<Value>().await {
            Ok(v) => v,
            Err(_) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({"error": "the node returned an unreadable verification reply"})),
                )
                    .into_response()
            }
        },
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "error": "the node is not reachable: verification is decided by the node, never locally",
                    "source": "rpc",
                })),
            )
                .into_response()
        }
    };
    if let Some(err) = node_reply.get("error") {
        // The node REFUSED the submission (unknown contract, bad params):
        // forward the refusal, store nothing.
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "contract": key,
                "verified": false,
                "error": err,
            })),
        )
            .into_response();
    }
    let result = node_reply.get("result").cloned().unwrap_or(Value::Null);
    if result.get("verified").and_then(|v| v.as_bool()) == Some(true) {
        // The node confirmed the rebuild: NOW (and only now) the source is
        // stored. The text is the exact bytes the node rebuilt (see
        // `source_text_from_request`; a mismatched `source`/`source_hex` pair
        // was already refused), never a caller-supplied lookalike.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let row = VerifiedSource {
            contract: key.clone(),
            source_text: verified_source_text,
            compiler: result
                .get("compiler")
                .and_then(|v| v.as_str())
                .unwrap_or(compiler)
                .to_string(),
            flags: result
                .get("compiler_flags")
                .and_then(|v| v.as_str())
                .unwrap_or(flags)
                .to_string(),
            source_hash: result
                .get("source_hash")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            code_hash: result
                .get("onchain_code_hash")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            verified_at: now,
        };
        let db = state.db.clone();
        match tokio::task::spawn_blocking(move || db.upsert_verified_source(&row)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": e.to_string()})),
                )
                    .into_response();
            }
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "verify source save task failed"})),
                )
                    .into_response();
            }
        }
        let mut out = result;
        if let Some(obj) = out.as_object_mut() {
            obj.insert("contract".to_string(), json!(key));
            obj.insert("verified_at".to_string(), json!(now));
        }
        return (StatusCode::OK, Json(out)).into_response();
    }
    // `verified: false` (tampered source, wrong compiler, …): return the
    // node's verdict, store nothing.
    (StatusCode::OK, Json(result)).into_response()
}

/// `GET /api/v2/contract/:address/source` — the VERIFIED source of a
/// contract, or an honest 404 when the node never confirmed one.
async fn get_contract_source(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    let key = normalize_contract_key(&address);
    let db = state.db.clone();
    let key_owned = key.clone();
    match tokio::task::spawn_blocking(move || db.get_verified_source(&key_owned)).await {
        Ok(Ok(Some(v))) => (
            StatusCode::OK,
            Json(json!({
                "contract": v.contract,
                "contract_stl57": crate::db::to_stl57(&v.contract),
                "verified": true,
                "source": v.source_text,
                "compiler": v.compiler,
                "compiler_flags": v.flags,
                "source_hash": v.source_hash,
                "code_hash": v.code_hash,
                "verified_at": v.verified_at,
            })),
        )
            .into_response(),
        Ok(Ok(None)) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "contract": key,
                "verified": false,
                "error": "no verified source for this contract",
            })),
        )
            .into_response(),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "contract source query task failed"})),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// STS-20 token balances, holders & bounded program accounts (W4 contract)
// ---------------------------------------------------------------------------

/// `GET /api/v2/account/:address/tokens?cursor=&limit=&token=&include_zero=&shard_id=`
async fn get_account_tokens(
    State(state): State<AppState>,
    Path(address): Path<String>,
    Query(q): Query<AccountTokensQuery>,
) -> impl IntoResponse {
    let norm = crate::db::normalize_address_info(&address);
    let limit = q.limit.unwrap_or(50).min(MAX_HISTORY_PAGE);
    let cursor = match q
        .cursor
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(parse_account_tokens_cursor)
        .transpose()
    {
        Ok(c) => c,
        Err(e) => return bad_request(e),
    };
    let include_zero = q.include_zero.unwrap_or(false);
    let db = state.db.clone();
    let addr_owned = address.clone();
    let token_opt = q.token.clone();
    let shard_id = q.shard_id;
    let res = tokio::task::spawn_blocking(move || {
        db.get_account_tokens_keyset(
            &addr_owned,
            token_opt.as_deref(),
            include_zero,
            shard_id,
            limit,
            cursor,
        )
    })
    .await;
    match res {
        Ok(Ok(page)) => (
            StatusCode::OK,
            Json(json!({
                "address": norm.hex_clean,
                "address_0x": norm.hex_0x,
                "stl57": norm.stl57,
                "tokens": page.items,
                "count": page.items.len(),
                "limit": limit,
                "next_cursor": page.next_cursor,
                "has_more": page.has_more,
            })),
        )
            .into_response(),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "account tokens query task failed"})),
        )
            .into_response(),
    }
}

/// `GET /api/v2/token/:token/holders?cursor=&limit=&include_zero=&shard_id=`
async fn get_token_holders(
    State(state): State<AppState>,
    Path(token): Path<String>,
    Query(q): Query<TokenHoldersQuery>,
) -> impl IntoResponse {
    let norm = crate::db::normalize_address_info(&token);
    let limit = q.limit.unwrap_or(50).min(MAX_HISTORY_PAGE);
    let cursor = match q
        .cursor
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(parse_token_holders_cursor)
        .transpose()
    {
        Ok(c) => c,
        Err(e) => return bad_request(e),
    };
    let include_zero = q.include_zero.unwrap_or(false);
    let db = state.db.clone();
    let token_owned = token.clone();
    let shard_id = q.shard_id;
    let res = tokio::task::spawn_blocking(move || {
        db.get_token_holders_keyset(&token_owned, include_zero, shard_id, limit, cursor)
    })
    .await;
    match res {
        Ok(Ok(page)) => (
            StatusCode::OK,
            Json(json!({
                "token": norm.hex_clean,
                "token_0x": norm.hex_0x,
                "token_stl57": norm.stl57,
                "holders": page.items,
                "count": page.items.len(),
                "limit": limit,
                "next_cursor": page.next_cursor,
                "has_more": page.has_more,
            })),
        )
            .into_response(),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "token holders query task failed"})),
        )
            .into_response(),
    }
}

/// `GET /api/v2/program/:program/accounts?...&cursor=&limit=`
///
/// Bounded Solana-style `getProgramAccounts` analogue (`limit <= 100`,
/// `with_proof` capped at `16`, unfiltered dumps rejected with 400).
async fn get_program_accounts(
    State(state): State<AppState>,
    Path(program): Path<String>,
    Query(q): Query<ProgramAccountsQuery>,
) -> impl IntoResponse {
    let prog = program.trim().to_ascii_lowercase();
    if !matches!(prog.as_str(), "token" | "contract" | "system") {
        return bad_request("unknown program: expected 'token', 'contract', or 'system'");
    }

    let with_proof = q.with_proof.unwrap_or(false);
    let cap = if with_proof {
        MAX_PROGRAM_ACCOUNTS_PROOFS
    } else {
        MAX_PROGRAM_ACCOUNTS_LIMIT
    };
    let limit = q.limit.unwrap_or(50).min(cap);

    let has_token = q.token.as_deref().is_some_and(|s| !s.trim().is_empty());
    let has_owner = q.owner.as_deref().is_some_and(|s| !s.trim().is_empty());
    let has_contract = q.contract.as_deref().is_some_and(|s| !s.trim().is_empty());
    let has_creator = q.creator.as_deref().is_some_and(|s| !s.trim().is_empty());
    let has_min_bal = q.min_balance.is_some_and(|v| v > 0);
    let force_rpc = q
        .source
        .as_deref()
        .is_some_and(|s| s.eq_ignore_ascii_case("rpc"))
        || with_proof
        || q.slot_from.is_some()
        || q.slot_to.is_some();

    match prog.as_str() {
        "token" => {
            if !has_token && !has_owner {
                return bad_request("program=token requires 'token' or 'owner' filter");
            }
            if force_rpc {
                return proxy_program_accounts_rpc(&state, &prog, &q, limit, with_proof).await;
            }
            let cursor = match q
                .cursor
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(parse_token_program_cursor)
                .transpose()
            {
                Ok(c) => c,
                Err(e) => return bad_request(e),
            };
            let db = state.db.clone();
            let token_opt = q.token.clone();
            let owner_opt = q.owner.clone();
            let min_bal = q.min_balance;
            let shard_id = q.shard_id;
            let res = tokio::task::spawn_blocking(move || {
                db.query_token_program_accounts_keyset(
                    token_opt.as_deref(),
                    owner_opt.as_deref(),
                    min_bal,
                    shard_id,
                    limit,
                    cursor,
                )
            })
            .await;
            match res {
                Ok(Ok(page)) => (
                    StatusCode::OK,
                    Json(json!({
                        "program": "token",
                        "source": "db",
                        "items": page.items,
                        "count": page.items.len(),
                        "limit": limit,
                        "next_cursor": page.next_cursor,
                        "has_more": page.has_more,
                        "scan_truncated": false,
                    })),
                )
                    .into_response(),
                Ok(Err(e)) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": e.to_string()})),
                )
                    .into_response(),
                Err(_) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "program accounts query task failed"})),
                )
                    .into_response(),
            }
        }
        "contract" => {
            if !has_contract && !has_creator {
                return bad_request("program=contract requires 'contract' or 'creator' filter");
            }
            if force_rpc {
                return proxy_program_accounts_rpc(&state, &prog, &q, limit, with_proof).await;
            }
            let cursor = match q
                .cursor
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(parse_contracts_program_cursor)
                .transpose()
            {
                Ok(c) => c,
                Err(e) => return bad_request(e),
            };
            let db = state.db.clone();
            let creator_opt = q.creator.clone();
            let contract_opt = q.contract.clone();
            let shard_id = q.shard_id;
            let res = tokio::task::spawn_blocking(move || {
                db.get_contracts_by_filter_keyset(
                    creator_opt.as_deref(),
                    contract_opt.as_deref(),
                    shard_id,
                    limit,
                    cursor,
                )
            })
            .await;
            match res {
                Ok(Ok(page)) => (
                    StatusCode::OK,
                    Json(json!({
                        "program": "contract",
                        "source": "db",
                        "items": page.items,
                        "count": page.items.len(),
                        "limit": limit,
                        "next_cursor": page.next_cursor,
                        "has_more": page.has_more,
                        "scan_truncated": false,
                    })),
                )
                    .into_response(),
                Ok(Err(e)) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": e.to_string()})),
                )
                    .into_response(),
                Err(_) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "program accounts query task failed"})),
                )
                    .into_response(),
            }
        }
        "system" => {
            if !has_owner && !has_min_bal {
                return bad_request(
                    "program=system requires 'owner' or nonzero 'min_balance' filter",
                );
            }
            proxy_program_accounts_rpc(&state, &prog, &q, limit, with_proof).await
        }
        _ => bad_request("unknown program"),
    }
}

async fn proxy_program_accounts_rpc(
    state: &AppState,
    program: &str,
    q: &ProgramAccountsQuery,
    limit: u32,
    with_proof: bool,
) -> axum::response::Response {
    let mut rpc_params = serde_json::Map::new();
    rpc_params.insert("program".to_string(), json!(program));
    rpc_params.insert("limit".to_string(), json!(limit));
    rpc_params.insert("with_proof".to_string(), json!(with_proof));
    if let Some(v) = q.token.as_deref().filter(|s| !s.trim().is_empty()) {
        rpc_params.insert("token".to_string(), json!(v));
    }
    if let Some(v) = q.contract.as_deref().filter(|s| !s.trim().is_empty()) {
        rpc_params.insert("contract".to_string(), json!(v));
    }
    if let Some(v) = q.owner.as_deref().filter(|s| !s.trim().is_empty()) {
        rpc_params.insert("owner".to_string(), json!(v));
    }
    if let Some(v) = q.creator.as_deref().filter(|s| !s.trim().is_empty()) {
        rpc_params.insert("creator".to_string(), json!(v));
    }
    if let Some(v) = q.min_balance {
        rpc_params.insert("min_balance".to_string(), json!(v.to_string()));
    }
    if let Some(v) = q.slot_from {
        rpc_params.insert("slot_from".to_string(), json!(v));
    }
    if let Some(v) = q.slot_to {
        rpc_params.insert("slot_to".to_string(), json!(v));
    }
    if let Some(v) = q.cursor.as_deref().filter(|s| !s.trim().is_empty()) {
        rpc_params.insert("cursor".to_string(), json!(v));
    }
    if let Some(v) = q.shard_id {
        rpc_params.insert("shard_id".to_string(), json!(v));
    }
    let payload = json!({
        "jsonrpc": "2.0",
        "method": "stell_getProgramAccounts",
        "params": rpc_params,
        "id": 1,
    });
    match state
        .http_client
        .post(&state.rpc_url)
        .json(&payload)
        .send()
        .await
    {
        Ok(resp) => match resp.json::<Value>().await {
            Ok(data) => {
                if let Some(err) = data.get("error") {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({ "error": err, "source": "rpc" })),
                    )
                        .into_response();
                }
                let mut res = data.get("result").cloned().unwrap_or(Value::Null);
                if let Some(obj) = res.as_object_mut() {
                    obj.insert("source".to_string(), json!("rpc"));
                }
                (StatusCode::OK, Json(res)).into_response()
            }
            Err(_) => (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": "unreadable stell_getProgramAccounts reply from node"})),
            )
                .into_response(),
        },
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": "node RPC unavailable for stell_getProgramAccounts",
                "source": "rpc",
            })),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// Public SSE stream: GET /api/v2/stream (Geyser-lite indexer fan-out)
// ---------------------------------------------------------------------------

struct StreamFilter {
    topics: HashSet<String>,
    contract_candidates: HashSet<String>,
    address_candidates: HashSet<String>,
    shard_id: Option<u32>,
}

impl StreamFilter {
    fn from_query(q: &StreamQuery) -> Result<Self, String> {
        let raw_topics = q.topics.as_deref().unwrap_or("newHeads");
        let mut topics = HashSet::new();
        for tok in raw_topics.split(',') {
            let t = tok.trim();
            if t.is_empty() {
                continue;
            }
            let canonical = match t {
                "newHeads" | "new_heads" | "heads" => "newHeads",
                "newTxs" | "new_txs" | "transactions" => "newTxs",
                "events" | "logs" | "contractEvents" => "events",
                "invalidations" | "invalidation" | "reorgs" => "invalidations",
                other => return Err(format!("unknown stream topic: {other}")),
            };
            topics.insert(canonical.to_string());
        }
        if topics.is_empty() {
            topics.insert("newHeads".to_string());
        }

        let contract_candidates: HashSet<String> = q
            .contract
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|c| address_match_candidates(c).into_iter().collect())
            .unwrap_or_default();

        let address_candidates: HashSet<String> = q
            .address
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|a| address_match_candidates(a).into_iter().collect())
            .unwrap_or_default();

        Ok(Self {
            topics,
            contract_candidates,
            address_candidates,
            shard_id: q.shard_id,
        })
    }

    fn matches(&self, ev: &IndexerStreamEvent) -> bool {
        if !self.topics.contains(&ev.topic) {
            return false;
        }
        if let Some(sid) = self.shard_id {
            if ev.shard_id != sid {
                return false;
            }
        }
        if !self.contract_candidates.is_empty() {
            let Some(ev_contract) = ev.contract.as_deref() else {
                return false;
            };
            let matched = address_match_candidates(ev_contract)
                .into_iter()
                .any(|c| self.contract_candidates.contains(&c));
            if !matched {
                return false;
            }
        }
        if !self.address_candidates.is_empty() {
            let mut matched = ev.addresses.iter().any(|addr| {
                address_match_candidates(addr)
                    .into_iter()
                    .any(|c| self.address_candidates.contains(&c))
            });
            if !matched {
                if let Some(c) = ev.contract.as_deref() {
                    matched = address_match_candidates(c)
                        .into_iter()
                        .any(|cand| self.address_candidates.contains(&cand));
                }
            }
            if !matched {
                return false;
            }
        }
        true
    }
}

struct StreamLoopState {
    rx: broadcast::Receiver<IndexerStreamEvent>,
    filter: StreamFilter,
    _guard: SseClientGuard,
    /// Overflow notice emitted BEFORE the replay burst when `after_seq`
    /// matched more than `MAX_REPLAY_BURST` windowed events (pre-rendered
    /// JSON body of the `lagged` frame).
    pending_lag: Option<String>,
    pending_replay: VecDeque<IndexerStreamEvent>,
    last_sent_seq: u64,
    deadline: tokio::time::Instant,
    idle_timeout: Duration,
    hub: Arc<IndexerStreamHub>,
}

fn build_sse_event(ev: &IndexerStreamEvent) -> SseEvent {
    SseEvent::default()
        .id(ev.seq.to_string())
        .event(ev.topic.clone())
        .json_data(ev)
        .unwrap_or_else(|_| SseEvent::default().data("{}"))
}

type IndexerSseStream =
    Pin<Box<dyn futures::stream::Stream<Item = Result<SseEvent, Infallible>> + Send>>;

/// `GET /api/v2/stream?topics=newHeads,newTxs,events&contract=&address=&shard_id=&after_seq=`
async fn stream_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
    Query(q): Query<StreamQuery>,
) -> impl IntoResponse {
    let filter = match StreamFilter::from_query(&q) {
        Ok(f) => f,
        Err(e) => return bad_request(e),
    };

    let client_ip = resolve_indexer_client_ip(&headers, peer.map(|ConnectInfo(a)| a.ip()));
    let guard = match state.stream_hub.try_acquire_client_for_ip(client_ip) {
        Ok(g) => g,
        Err(SseAcquireError::GlobalLimit) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "error": "stream client limit reached",
                    "max_clients": state.stream_hub.max_clients(),
                })),
            )
                .into_response();
        }
        Err(SseAcquireError::PerIpLimit) => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({
                    "error": "per-IP stream client limit reached",
                    "max_clients_per_ip": state.stream_hub.max_clients_per_ip(),
                })),
            )
                .into_response();
        }
    };

    // Subscribe BEFORE snapshotting replay so no live event is missed in between.
    let rx = state.stream_hub.subscribe();
    let mut pending_replay = VecDeque::new();
    let mut replay_overflow = 0usize;
    let after_seq = q.after_seq.or_else(|| {
        headers
            .get("last-event-id")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<u64>().ok())
    });
    if let Some(after_seq) = after_seq {
        match state.stream_hub.replay_since(after_seq) {
            Ok(events) => {
                for ev in events {
                    if filter.matches(&ev) {
                        if pending_replay.len() < MAX_REPLAY_BURST {
                            pending_replay.push_back(ev);
                        } else {
                            // MAX_REPLAY_BURST is a hard cap (the node's stream
                            // has the same one), but the events beyond it are
                            // NOT in the live receiver either: they were
                            // published before this subscription. Count them so
                            // the client is TOLD to backfill instead of
                            // resuming with a silent hole.
                            replay_overflow += 1;
                        }
                    }
                }
            }
            Err(oldest) => {
                drop(guard);
                return (
                    StatusCode::GONE,
                    Json(json!({
                        "error": "replay cursor expired; backfill via REST API",
                        "oldest_available_seq": oldest,
                    })),
                )
                    .into_response();
            }
        }
    }
    let pending_lag = if replay_overflow == 0 {
        None
    } else {
        let payload = json!({
            "lagged": replay_overflow,
            "oldest_available_seq": state.stream_hub.oldest_available_seq(),
            "action": "backfill_required",
        });
        Some(serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string()))
    };

    let idle_timeout = state.stream_hub.idle_timeout();
    let init_state = StreamLoopState {
        rx,
        filter,
        _guard: guard,
        pending_lag,
        pending_replay,
        last_sent_seq: 0,
        deadline: tokio::time::Instant::now() + idle_timeout,
        idle_timeout,
        hub: Arc::clone(&state.stream_hub),
    };

    let stream: IndexerSseStream =
        Box::pin(futures::stream::unfold(init_state, |mut st| async move {
            if let Some(lag_body) = st.pending_lag.take() {
                st.deadline = tokio::time::Instant::now() + st.idle_timeout;
                return Some((Ok(SseEvent::default().event("lagged").data(lag_body)), st));
            }
            if let Some(ev) = st.pending_replay.pop_front() {
                st.last_sent_seq = st.last_sent_seq.max(ev.seq);
                st.deadline = tokio::time::Instant::now() + st.idle_timeout;
                let sse_ev = build_sse_event(&ev);
                return Some((Ok(sse_ev), st));
            }

            loop {
                match tokio::time::timeout_at(st.deadline, st.rx.recv()).await {
                    Err(_elapsed) => return None,
                    Ok(Ok(ev)) => {
                        st.deadline = tokio::time::Instant::now() + st.idle_timeout;
                        if ev.seq <= st.last_sent_seq || !st.filter.matches(&ev) {
                            continue;
                        }
                        st.last_sent_seq = ev.seq;
                        let sse_ev = build_sse_event(&ev);
                        return Some((Ok(sse_ev), st));
                    }
                    Ok(Err(broadcast::error::RecvError::Lagged(skipped))) => {
                        st.deadline = tokio::time::Instant::now() + st.idle_timeout;
                        let oldest = st.hub.oldest_available_seq();
                        let payload = json!({
                            "lagged": skipped,
                            "oldest_available_seq": oldest,
                            "action": "backfill_required",
                        });
                        let sse_ev = SseEvent::default()
                            .event("lagged")
                            .json_data(payload)
                            .unwrap_or_else(|_| SseEvent::default().data("{}"));
                        return Some((Ok(sse_ev), st));
                    }
                    Ok(Err(broadcast::error::RecvError::Closed)) => return None,
                }
            }
        }));

    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response()
}
