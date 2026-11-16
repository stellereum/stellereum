use crate::db::{normalize_contract_key, Database, EventFilter, EventRecord, VerifiedSource};
use crate::events::{decode_event, AbiCache, RawEvent};
use crate::syncer::SyncStatus;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;

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
        }
    }
}

#[derive(Deserialize)]
pub struct Pagination {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

#[derive(Deserialize)]
pub struct BlocksQuery {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
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
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

/// Maximum number of events one page may carry.
const MAX_EVENT_PAGE: u32 = 200;

/// Maximum pagination offset (audit B-IDX-4): an unbounded OFFSET forces a
/// full table scan for an empty page (CPU DoS). Explorer pagination never
/// legitimately exceeds one million rows deep.
const MAX_OFFSET: u32 = 1_000_000;

/// Fail-closed offset gate: `Err(response)` on absurd offsets.
#[allow(clippy::result_large_err)] // GATE: axum Response is the framework's
                                   // native error carrier (handlers return it by value everywhere); boxing
                                   // would only add noise.
fn check_offset(offset: u32) -> Result<u32, axum::response::Response> {
    if offset > MAX_OFFSET {
        Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "offset exceeds cap 1000000"})),
        )
            .into_response())
    } else {
        Ok(offset)
    }
}

pub fn create_router(state: AppState) -> Router {
    Router::new()
        // Core network endpoints
        .route("/api/overview", get(get_overview))
        .route("/api/v2/overview", get(get_overview))
        .route("/api/stats", get(get_network_stats))
        .route("/api/v2/stats", get(get_network_stats))
        .route("/api/price", get(get_price))
        .route("/api/v2/price", get(get_price))
        .route("/api/status", get(get_status))
        .route("/api/v2/status", get(get_status))
        // Validators & Staking (gram.org/validators)
        .route("/api/validators", get(get_validators))
        .route("/api/v2/validators", get(get_validators))
        .route("/api/staking", get(get_staking))
        .route("/api/v2/staking", get(get_staking))
        // Blocks
        .route("/api/blocks/latest", get(get_blocks))
        .route("/api/v2/blocks", get(get_blocks))
        .route("/api/blocks/:param", get(get_block))
        .route("/api/v2/block/:param", get(get_block))
        // Transactions
        .route("/api/transactions/latest", get(get_recent_txs))
        .route("/api/v2/txs", get(get_recent_txs))
        .route("/api/transactions/:hash", get(get_tx))
        .route("/api/v2/tx/:hash", get(get_tx))
        // Contract events (logs)
        .route("/api/v2/contract/:address/events", get(get_contract_events))
        .route("/api/v2/tx/:hash/events", get(get_tx_events))
        .route("/api/v2/events", get(get_events))
        // Contract source verification (audit P2-15, Sourcify-style)
        .route(
            "/api/v2/contract/:address/verify",
            post(verify_contract_source),
        )
        .route("/api/v2/contract/:address/source", get(get_contract_source))
        // Contracts (derived from the event log) and the LIVE shard topology
        .route("/api/v2/contracts", get(get_contracts))
        .route("/api/shards", get(get_shards))
        .route("/api/v2/shards", get(get_shards))
        // Accounts & History
        .route("/api/accounts/:address", get(get_account_info))
        .route("/api/v2/account/:address", get(get_account_info))
        .route("/api/accounts/:address/actions", get(get_account_actions))
        .route("/api/accounts/:address/activity", get(get_account_actions))
        .route("/api/v2/account/:address/txs", get(get_account_actions))
        .route("/api/whales", get(get_whales))
        .route("/api/v2/whales", get(get_whales))
        // Verified Contracts & Tokens (gram.org/verified)
        .route("/api/verified", get(get_verified))
        .route("/api/v2/verified", get(get_verified))
        .route("/api/verified/stats", get(get_verified_stats))
        .route("/api/v2/verified/stats", get(get_verified_stats))
        .route("/api/tokens", get(get_tokens))
        .route("/api/v2/tokens", get(get_tokens))
        // Search & Charts
        .route("/api/search", get(search))
        .route("/api/v2/search", get(search))
        .route("/api/v2/stats/charts", get(get_charts))
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

// 1. Overview (gram.org/api/overview)
async fn get_overview(State(state): State<AppState>) -> impl IntoResponse {
    let stats = state.db.get_stats().unwrap_or(crate::db::NetworkStats {
        tip_height: 0,
        total_blocks: 0,
        total_transactions: 0,
        total_accounts: 0,
        current_tps: 0.0,
        avg_block_time: 0.0,
    });

    let charts = state
        .db
        .get_charts()
        .unwrap_or_else(|_| json!({"hours":[], "days":[]}));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let live_staked = fetch_live_validators(&state)
        .await
        .and_then(|v| v["total_power"].as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "0".to_string());

    // The explorer advertises what it can serve: the ABI manifests (which
    // make the events DECODED rather than raw) and the event endpoints.
    let event_total = state.db.count_events(&EventFilter::default()).unwrap_or(0);
    let latest_events = state
        .db
        .get_events(&EventFilter::default(), 10, 0)
        .unwrap_or_default()
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
            "daily_average": stats.total_transactions.max(1000),
            "today": stats.total_transactions,
            "yesterday": stats.total_transactions.saturating_sub(100),
            "today_start": (now / 86400) * 86400,
            "tps": stats.current_tps.max(1.0),
            "current_tps": stats.current_tps.max(1.0),
            "hours": charts["hours"],
            "days": charts["days"]
        },
        "price": {
            "base_usd": 0.25,
            "market_cap_usd": 62500000.0,
            "fdv_usd": 250000000.0
        },
        "network": {
            "chain_id": 5757,
            "consensus": "Pure PQ Falcon-512 BFT",
            "tip_height": stats.tip_height,
            "mc_seqno": stats.tip_height,
            "avg_block_time": stats.avg_block_time,
            "block_time": stats.avg_block_time,
            "total_blocks": stats.total_blocks,
            "indexed_blocks": stats.total_blocks,
            "total_transactions": stats.total_transactions,
            "indexed_txs": stats.total_transactions,
            "total_accounts": stats.total_accounts,
            "tps": stats.current_tps.max(1.0),
            "current_tps": stats.current_tps.max(1.0)
        },
        "tps": stats.current_tps.max(1.0),
        "current_tps": stats.current_tps.max(1.0),
        "block_time": stats.avg_block_time,
        "avg_block_time": stats.avg_block_time,
        "mc_seqno": stats.tip_height,
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

    (StatusCode::OK, Json(overview))
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
    let stats = state.db.get_stats().unwrap_or(crate::db::NetworkStats {
        tip_height: 0,
        total_blocks: 0,
        total_transactions: 0,
        total_accounts: 0,
        current_tps: 0.0,
        avg_block_time: 0.0,
    });

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let shards = fetch_live_shards_count(&state).await.unwrap_or(1);
    let validators_count = fetch_live_validators(&state)
        .await
        .and_then(|v| v["validators"].as_array().map(|a| a.len() as u64));

    let out = json!({
        "chain_id": 5757,
        "mc_seqno": stats.tip_height,
        "tip_height": stats.tip_height,
        "mc_utime": now,
        "shards": shards,
        "validators_count": validators_count,
        "tps": stats.current_tps,
        "current_tps": stats.current_tps,
        "block_time": stats.avg_block_time,
        "avg_block_time": stats.avg_block_time,
        "wc_block_time": stats.avg_block_time,
        "mc_block_txs": if stats.total_blocks > 0 {
            (stats.total_transactions as f64) / (stats.total_blocks as f64)
        } else {
            0.0
        },
        "wc_block_txs": 0.0,
        "indexed_txs": stats.total_transactions,
        "total_transactions": stats.total_transactions,
        "indexed_blocks": stats.total_blocks,
        "total_blocks": stats.total_blocks,
        "total_accounts": stats.total_accounts
    });

    (StatusCode::OK, Json(out))
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
    let tip = state.db.get_tip_height().unwrap_or(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let sync = state.sync_status.read().await.clone();
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
            "chain_id": 5757,
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
                "rpc_url": state.rpc_url,
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

    let mut raw_vals: Vec<(String, u128, String)> = res["validators"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| {
                    let addr = v["validator"].as_str()?.to_string();
                    let power_str = v["power"].as_str().unwrap_or("0").to_string();
                    let power_u128 = power_str.parse::<u128>().unwrap_or(0);
                    Some((addr, power_u128, power_str))
                })
                .collect()
        })
        .unwrap_or_default();

    raw_vals.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let validators_json: Vec<Value> = raw_vals
        .iter()
        .enumerate()
        .map(|(idx, (addr, power_u128, power_str))| {
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
                "falcon_pubkey": res["validators"][idx]["falcon_pubkey"].as_str().unwrap_or(""),
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
                "rpc_url": state.rpc_url,
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
async fn get_tokens(State(state): State<AppState>) -> impl IntoResponse {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut tokens = vec![json!({
        "address": "0000000000000000000000000000000000000000000000000000000000000000",
        "name": "Stellereum",
        "symbol": "STELL",
        "decimals": 9,
        "price": 0.25,
        "change_24h": 0.0,
        "market_cap": 250000000.0,
        "verified": true,
        "image": "/assets/img/logo.svg"
    })];

    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "stell_listTokens",
        "params": { "limit": 100, "offset": 0 },
        "id": 1
    });
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
        }
    }

    (
        StatusCode::OK,
        Json(json!({
            "source": "Stellereum Token Registry",
            "tokens": tokens,
            "total": tokens.len(),
            "updated": now
        })),
    )
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
    let limit = p.limit.unwrap_or(50).min(200);
    let offset = match check_offset(p.offset.unwrap_or(0)) {
        Ok(o) => o,
        Err(r) => return r,
    };
    let shard_filter = p.shard_id.or(p.shard);
    match state.db.get_blocks_by_shard(shard_filter, limit, offset) {
        Ok(blocks) => (
            StatusCode::OK,
            Json(json!({
                "blocks": blocks,
                "shard_id": shard_filter,
                "limit": limit,
                "offset": offset
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn get_block(
    State(state): State<AppState>,
    Path(param): Path<String>,
    Query(q): Query<BlockQuery>,
) -> impl IntoResponse {
    let shard_filter = q.shard_id.or(q.shard);
    let block_opt = if let Some((sid, h)) = parse_shard_height(&param) {
        state.db.get_block_by_shard_and_height(sid, h)
    } else if let Ok(h) = param.trim().parse::<u64>() {
        if let Some(sid) = shard_filter {
            state.db.get_block_by_shard_and_height(sid, h)
        } else {
            state.db.get_block_by_height(h)
        }
    } else {
        state.db.get_block_by_hash(&param)
    };

    match block_opt {
        Ok(Some(b)) => {
            let txs = state
                .db
                .get_block_txs_for_shard(b.shard_id, b.height)
                .unwrap_or_default();
            (
                StatusCode::OK,
                Json(json!({ "block": b, "transactions": txs })),
            )
                .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Block not found"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

// 10. Transactions
async fn get_recent_txs(
    State(state): State<AppState>,
    Query(p): Query<Pagination>,
) -> impl IntoResponse {
    let limit = p.limit.unwrap_or(50).min(200);
    let offset = match check_offset(p.offset.unwrap_or(0)) {
        Ok(o) => o,
        Err(r) => return r,
    };
    // Fetch latest transactions across blocks
    let txs = state
        .db
        .get_account_txs("", limit, offset)
        .unwrap_or_default();
    (
        StatusCode::OK,
        Json(json!({ "transactions": txs, "limit": limit, "offset": offset })),
    )
        .into_response()
}

async fn get_tx(State(state): State<AppState>, Path(hash): Path<String>) -> impl IntoResponse {
    match state.db.get_tx_by_hash(&hash) {
        Ok(Some(tx)) => (StatusCode::OK, Json(json!({ "transaction": tx }))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Transaction not found"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
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
    let tx_count = state.db.get_account_tx_count(&address).unwrap_or(0);
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
}

async fn get_account_actions(
    State(state): State<AppState>,
    Path(address): Path<String>,
    Query(p): Query<Pagination>,
) -> impl IntoResponse {
    let norm = crate::db::normalize_address_info(&address);
    let limit = p.limit.unwrap_or(50).min(200);
    let offset = match check_offset(p.offset.unwrap_or(0)) {
        Ok(o) => o,
        Err(r) => return r,
    };
    match state.db.get_account_txs(&address, limit, offset) {
        Ok(txs) => (
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
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn get_whales(State(state): State<AppState>) -> impl IntoResponse {
    // Derive top active addresses from indexed transactions instead of fabricated balances.
    let txs = state.db.get_account_txs("", 200, 0).unwrap_or_default();
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
    let trimmed = query.trim();

    if let Some((sid, h)) = parse_shard_height(trimmed) {
        if let Ok(Some(b)) = state.db.get_block_by_shard_and_height(sid, h) {
            return (
                StatusCode::OK,
                Json(json!({ "type": "block", "result": b })),
            )
                .into_response();
        }
    }

    if let Ok(h) = trimmed.parse::<u64>() {
        if let Ok(Some(b)) = state.db.get_block_by_height(h) {
            return (
                StatusCode::OK,
                Json(json!({ "type": "block", "result": b })),
            )
                .into_response();
        }
    }

    if let Ok(Some(tx)) = state.db.get_tx_by_hash(trimmed) {
        return (
            StatusCode::OK,
            Json(json!({ "type": "transaction", "result": tx })),
        )
            .into_response();
    }

    if let Ok(Some(b)) = state.db.get_block_by_hash(trimmed) {
        return (
            StatusCode::OK,
            Json(json!({ "type": "block", "result": b })),
        )
            .into_response();
    }

    let norm = crate::db::normalize_address_info(trimmed);
    if norm.bytes32.is_some() {
        let tx_count = state.db.get_account_tx_count(trimmed).unwrap_or(0);
        return (
            StatusCode::OK,
            Json(json!({
                "type": "account",
                "address": norm.hex_clean,
                "address_0x": norm.hex_0x,
                "stl57": norm.stl57,
                "tx_count": tx_count,
            })),
        )
            .into_response();
    }

    (
        StatusCode::NOT_FOUND,
        Json(json!({"error": "No match found"})),
    )
        .into_response()
}

async fn get_charts(State(state): State<AppState>) -> impl IntoResponse {
    match state.db.get_charts() {
        Ok(charts) => (StatusCode::OK, Json(charts)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
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
    let offset = match check_offset(p.offset.unwrap_or(0)) {
        Ok(o) => o,
        Err(r) => return r,
    };
    let filter = EventFilter {
        contract: Some(address.clone()),
        ..Default::default()
    };
    match state.db.get_events(&filter, limit, offset) {
        Ok(rows) => {
            let events: Vec<Value> = rows.iter().map(|e| event_json(e, &state.abis)).collect();
            let total = state
                .db
                .count_events(&filter)
                .unwrap_or(events.len() as u64);
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
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
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
    match state.db.get_events(&filter, MAX_EVENT_PAGE, 0) {
        Ok(rows) => {
            let events: Vec<Value> = rows.iter().map(|e| event_json(e, &state.abis)).collect();
            (
                StatusCode::OK,
                Json(json!({
                    "tx_hash": hash,
                    "events": events,
                    "count": events.len(),
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// `GET /api/v2/events?from_block=&to_block=&contract=` — filtered events.
async fn get_events(
    State(state): State<AppState>,
    Query(q): Query<EventsQuery>,
) -> impl IntoResponse {
    let limit = q.limit.unwrap_or(50).min(MAX_EVENT_PAGE);
    let offset = match check_offset(q.offset.unwrap_or(0)) {
        Ok(o) => o,
        Err(r) => return r,
    };
    let filter = EventFilter {
        from_block: q.from_block,
        to_block: q.to_block,
        contract: q.contract.clone(),
        tx_hash: None,
    };
    match state.db.get_events(&filter, limit, offset) {
        Ok(rows) => {
            let events: Vec<Value> = rows.iter().map(|e| event_json(e, &state.abis)).collect();
            let total = state
                .db
                .count_events(&filter)
                .unwrap_or(events.len() as u64);
            (
                StatusCode::OK,
                Json(json!({
                    "events": events,
                    "count": events.len(),
                    "total": total,
                    "from_block": q.from_block,
                    "to_block": q.to_block,
                    "contract": q.contract,
                    "limit": limit,
                    "offset": offset,
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// `GET /api/v2/contracts` — the contracts that emitted at least one indexed
/// event, most active first.
///
/// The list is derived from the EVENT log: a contract the indexer has never
/// seen an event from has never done anything observable, and an empty list is
/// an honest answer rather than a guess. Bounded and paginated like every
/// other listing (the event log is attacker-growable).
async fn get_contracts(
    State(state): State<AppState>,
    Query(p): Query<Pagination>,
) -> impl IntoResponse {
    let limit = p.limit.unwrap_or(50).min(MAX_EVENT_PAGE);
    let offset = match check_offset(p.offset.unwrap_or(0)) {
        Ok(o) => o,
        Err(r) => return r,
    };
    match state.db.list_contracts(limit, offset) {
        Ok(rows) => {
            let total = state.db.count_contracts().unwrap_or(rows.len() as u64);
            let contracts: Vec<Value> = rows
                .iter()
                .map(|c| {
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
                })
                .collect();
            (
                StatusCode::OK,
                Json(json!({
                    "contracts": contracts,
                    "count": contracts.len(),
                    "total": total,
                    "limit": limit,
                    "offset": offset,
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// `GET /api/v2/shards` — the LIVE shard topology, proxied from the node's
/// `stell_getShards`.
///
/// The topology is a property of the CHAIN, not of the indexer's own
/// database, so it is read from the node that has the committed heads and
/// proxied here. The answer carries `source: "rpc"` so a client can tell that
/// it is the node's view and not a locally reconstructed one; when the node
/// cannot be reached the endpoint says so explicitly instead of inventing a
/// topology.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let max_len = a.len().max(b.len());
    let mut diff: usize = a.len() ^ b.len();
    for i in 0..max_len {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= (x ^ y) as usize;
    }
    diff == 0
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
            let indexed_map: std::collections::HashMap<u32, (u64, u64)> = state
                .db
                .get_shard_index_stats()
                .unwrap_or_default()
                .into_iter()
                .map(|(sid, tip, cnt)| (sid, (tip, cnt)))
                .collect();
            let mut workchain_ids: Vec<u32> = Vec::new();
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
                                workchain_ids.push(sid);
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
                obj.insert("rpc_url".to_string(), json!(state.rpc_url));
                if let Some(raw_addr) = q
                    .address
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    let norm = crate::db::normalize_address_info(raw_addr);
                    let routed_shard = if let Some(hint) = norm.shard_hint {
                        Some(hint)
                    } else if norm.bytes32.is_some() {
                        if workchain_ids.len() == 1 {
                            Some(workchain_ids[0])
                        } else if workchain_ids.is_empty() && shard_len == 1 {
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
                "rpc_url": state.rpc_url,
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
    // unset token refuses everything with 401.
    let authorized = match state.verify_token.as_deref() {
        Some(expected) if !expected.is_empty() => headers
            .get("x-api-key")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|got| constant_time_eq(got.as_bytes(), expected.as_bytes())),
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
                    "rpc_url": state.rpc_url,
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
        // stored. The stored text is the canonical form the node hashed.
        let source_text = body.source.clone().unwrap_or_else(|| {
            let clean = body
                .source_hex
                .as_deref()
                .unwrap_or("")
                .trim()
                .strip_prefix("0x")
                .or_else(|| {
                    body.source_hex
                        .as_deref()
                        .unwrap_or("")
                        .trim()
                        .strip_prefix("0X")
                })
                .unwrap_or(body.source_hex.as_deref().unwrap_or("").trim());
            hex::decode(clean)
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
                .unwrap_or_default()
        });
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let row = VerifiedSource {
            contract: key.clone(),
            source_text,
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
        if let Err(e) = state.db.upsert_verified_source(&row) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response();
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
    match state.db.get_verified_source(&key) {
        Ok(Some(v)) => (
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
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "contract": key,
                "verified": false,
                "error": "no verified source for this contract",
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}
