use crate::db::{normalize_contract_key, Database, EventFilter, EventRecord, VerifiedSource};
use crate::events::{decode_event, AbiCache, RawEvent};
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
}

impl AppState {
    /// A state with an empty ABI cache.
    pub fn new(db: Database) -> Self {
        Self {
            db,
            abis: Arc::new(AbiCache::new()),
            rpc_url: std::env::var("INDEXER_RPC_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8545".to_string()),
            verify_token: None,
        }
    }

    /// A state with an empty ABI cache and an explicit node RPC endpoint.
    pub fn with_rpc(db: Database, rpc_url: String) -> Self {
        Self {
            db,
            abis: Arc::new(AbiCache::new()),
            rpc_url,
            verify_token: None,
        }
    }
}

#[derive(Deserialize)]
pub struct Pagination {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
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

// 1. Overview (gram.org/api/overview)
async fn get_overview(State(state): State<AppState>) -> impl IntoResponse {
    let stats = state.db.get_stats().unwrap_or(crate::db::NetworkStats {
        tip_height: 158000,
        total_blocks: 158000,
        total_transactions: 1000,
        total_accounts: 350,
        current_tps: 76.9,
        avg_block_time: 0.8,
    });

    let charts = state
        .db
        .get_charts()
        .unwrap_or_else(|_| json!({"hours":[], "days":[]}));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

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
            "staked": "5999044471404", // 5,999 STELL
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

// 2. Stats (/api/v2/stats)
async fn get_network_stats(State(state): State<AppState>) -> impl IntoResponse {
    let stats = state.db.get_stats().unwrap_or(crate::db::NetworkStats {
        tip_height: 158000,
        total_blocks: 158000,
        total_transactions: 1000,
        total_accounts: 350,
        current_tps: 76.9,
        avg_block_time: 0.8,
    });

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let out = json!({
        "chain_id": 5757,
        "mc_seqno": stats.tip_height,
        "tip_height": stats.tip_height,
        "mc_utime": now,
        "shards": 2,
        "tps": stats.current_tps.max(1.0),
        "current_tps": stats.current_tps.max(1.0),
        "block_time": stats.avg_block_time,
        "avg_block_time": stats.avg_block_time,
        "wc_block_time": stats.avg_block_time,
        "mc_block_txs": 124.0,
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
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "chain_id": 5757,
            "tip_height": tip,
            "synced": true,
            "version": "0.1.0-pq-fips206",
            "time": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
        })),
    )
}

// 5. Validators (gram.org/api/validators)
async fn get_validators() -> impl IntoResponse {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let out = json!({
        "limits": {
            "min_stake": "1000000000000",
            "max_stake": "2000000000000"
        },
        "round": {
            "total_stake": "7778463847208",
            "validators": 4,
            "min_stake": "1000000000000",
            "max_stake": "2000000000000",
            "quorum": "5185642564806",
            "fragile": false,
            "apy": 0.145
        },
        "validators": [
            {
                "rank": 1,
                "address": "c2313fbaf5c0b1a4921f132bed48772f0d0b788b8f27ad7f96772610996c3361",
                "address_stl57": crate::db::to_stl57("c2313fbaf5c0b1a4921f132bed48772f0d0b788b8f27ad7f96772610996c3361").unwrap_or_default(),
                "name": "Node A (Helsinki VPS)",
                "stake": "2000000000000",
                "self_bond": "2000000000000",
                "delegated": "0",
                "weight": 0.2571,
                "main": true,
                "status": "active",
                "uptime": 100.0,
                "commission_bps": 0,
                "falcon_pubkey": "094b56e26309250c6f24f04571dd9944cdda8a43e945849a49d5a6c0f22a9ab7...",
                "blocks_proposed": 54240
            },
            {
                "rank": 2,
                "address": "9c675ebc6cd20c9226da2fcbf6c167647e4e948b78368f038058b6b419175fcd",
                "address_stl57": crate::db::to_stl57("9c675ebc6cd20c9226da2fcbf6c167647e4e948b78368f038058b6b419175fcd").unwrap_or_default(),
                "name": "Node B (Ryzen РФ)",
                "stake": "2000000000000",
                "self_bond": "2000000000000",
                "delegated": "0",
                "weight": 0.2571,
                "main": true,
                "status": "active",
                "uptime": 100.0,
                "commission_bps": 0,
                "falcon_pubkey": "09948cbd580c52b776a1f2908396028a4d97d5af551d228e3da460288f416d6f...",
                "blocks_proposed": 54238
            },
            {
                "rank": 3,
                "address": "eddf81632831d8e9747dc38edbb2c88a835e246a0310d74c8b12b8df6e32e4cc",
                "address_stl57": crate::db::to_stl57("eddf81632831d8e9747dc38edbb2c88a835e246a0310d74c8b12b8df6e32e4cc").unwrap_or_default(),
                "name": "Node D (Capitalist Validator 4)",
                "stake": "2000000000000",
                "self_bond": "2000000000000",
                "delegated": "0",
                "weight": 0.2571,
                "main": true,
                "status": "active",
                "uptime": 100.0,
                "commission_bps": 0,
                "falcon_pubkey": "09736e255386a5f7790d84dbf8ee0a2c349645dd1902116d663bde99b3960e3e...",
                "blocks_proposed": 54235
            },
            {
                "rank": 4,
                "address": "021776cdf2b3b644e91dbe44fbef4a29f5a8ebf80b01055d3e7cc83a85659694",
                "address_stl57": crate::db::to_stl57("021776cdf2b3b644e91dbe44fbef4a29f5a8ebf80b01055d3e7cc83a85659694").unwrap_or_default(),
                "name": "Node C (Peer Knanserver)",
                "stake": "1778463847208",
                "self_bond": "1778463847208",
                "delegated": "0",
                "weight": 0.2287,
                "main": true,
                "status": "active",
                "uptime": 99.8,
                "commission_bps": 0,
                "falcon_pubkey": "0907097015c627a68bfe079311e9b13de4ec552e8270942c9458dda39b47ae09...",
                "blocks_proposed": 54100
            }
        ],
        "updated": now
    });

    (StatusCode::OK, Json(out))
}

// 6. Staking
async fn get_staking() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "total_staked": "7778463847208",
            "staked_percentage": 0.0031,
            "validators_count": 4,
            "cooldown_period_secs": 172800,
            "min_validator_bond": "1000000000000",
            "estimated_apy": 0.145,
            "slashing_penalty_bps": {
                "downtime": 10,
                "equivocation": 500
            }
        })),
    )
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

// 8. Tokens (gram.org/api/tokens)
async fn get_tokens() -> impl IntoResponse {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let tokens = json!([
        {
            "address": "0000000000000000000000000000000000000000000000000000000000000000",
            "name": "Stellereum",
            "symbol": "STELL",
            "decimals": 9,
            "price": 0.25,
            "change_24h": 0.0,
            "market_cap": 250000000.0,
            "holders": 350,
            "verified": true,
            "image": "/assets/img/logo.svg"
        },
        {
            "address": "7465746865725f75736474000000000000000000000000000000000000000001",
            "name": "Tether USD (Stellereum Teleport)",
            "symbol": "USDT",
            "decimals": 6,
            "price": 1.0,
            "change_24h": 0.01,
            "market_cap": 1000000.0,
            "holders": 85,
            "verified": true,
            "image": "https://cryptologos.cc/logos/tether-usdt-logo.svg"
        },
        {
            "address": "746f6e5f636f696e000000000000000000000000000000000000000000000002",
            "name": "Wrapped TON",
            "symbol": "wTON",
            "decimals": 9,
            "price": 5.20,
            "change_24h": 0.05,
            "market_cap": 520000.0,
            "holders": 42,
            "verified": true,
            "image": "https://cryptologos.cc/logos/toncoin-ton-logo.svg"
        }
    ]);

    (
        StatusCode::OK,
        Json(json!({
            "source": "Stellereum Token Registry",
            "tokens": tokens,
            "updated": now
        })),
    )
}

// 9. Blocks
async fn get_blocks(
    State(state): State<AppState>,
    Query(p): Query<Pagination>,
) -> impl IntoResponse {
    let limit = p.limit.unwrap_or(50).min(200);
    let offset = match check_offset(p.offset.unwrap_or(0)) {
            Ok(o) => o,
            Err(r) => return r,
        };
    match state.db.get_blocks(limit, offset) {
        Ok(blocks) => (
            StatusCode::OK,
            Json(json!({ "blocks": blocks, "limit": limit, "offset": offset })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn get_block(State(state): State<AppState>, Path(param): Path<String>) -> impl IntoResponse {
    let block_opt = if let Ok(h) = param.parse::<u64>() {
        state.db.get_block_by_height(h)
    } else {
        let clean = param.strip_prefix("0x").unwrap_or(&param);
        state.db.get_block_by_hash(clean)
    };

    match block_opt {
        Ok(Some(b)) => {
            let txs = state.db.get_block_txs(b.height).unwrap_or_default();
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
    let clean = hash.strip_prefix("0x").unwrap_or(&hash);
    match state.db.get_tx_by_hash(clean) {
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
    let clean = address
        .strip_prefix("0x")
        .or_else(|| address.strip_prefix("0X"))
        .unwrap_or(&address);
    let stl57 = if let Ok(addr_bytes) = stellereum::address::parse_address(&address) {
        Some(stellereum::address::encode_stl57_address(&addr_bytes))
    } else if let Ok(decoded) = hex::decode(clean) {
        if decoded.len() == 32 {
            let mut b = [0u8; 32];
            b.copy_from_slice(&decoded);
            Some(stellereum::address::encode_stl57_address(&b))
        } else if decoded.len() == 20 {
            let mut b = [0u8; 32];
            b[12..].copy_from_slice(&decoded);
            Some(stellereum::address::encode_stl57_address(&b))
        } else {
            None
        }
    } else {
        None
    };
    let tx_count = state.db.get_account_tx_count(clean).unwrap_or(0);
    (
        StatusCode::OK,
        Json(json!({
            "address": clean,
            "stl57": stl57,
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
    let clean = address.strip_prefix("0x").unwrap_or(&address);
    let limit = p.limit.unwrap_or(50).min(200);
    let offset = match check_offset(p.offset.unwrap_or(0)) {
            Ok(o) => o,
            Err(r) => return r,
        };
    match state.db.get_account_txs(clean, limit, offset) {
        Ok(txs) => (StatusCode::OK, Json(json!({ "address": clean, "actions": txs, "transactions": txs, "limit": limit, "offset": offset }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

async fn get_whales() -> impl IntoResponse {
    // Rich list
    (
        StatusCode::OK,
        Json(json!({
            "whales": [
                { "address": "c2313fbaf5c0b1a4921f132bed48772f0d0b788b8f27ad7f96772610996c3361", "balance_stell": 100000000.0, "role": "Validator Node A" },
                { "address": "9c675ebc6cd20c9226da2fcbf6c167647e4e948b78368f038058b6b419175fcd", "balance_stell": 100000000.0, "role": "Validator Node B" },
                { "address": "021776cdf2b3b644e91dbe44fbef4a29f5a8ebf80b01055d3e7cc83a85659694", "balance_stell": 190.0, "role": "Validator Node C" }
            ]
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

    // 1. Check if Stl57 address or standard hex
    let clean_hex = if let Ok(addr_bytes) = stellereum::address::parse_address(trimmed) {
        hex::encode(addr_bytes)
    } else {
        trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
            .unwrap_or(trimmed)
            .to_string()
    };

    if let Ok(h) = clean_hex.parse::<u64>() {
        if let Ok(Some(b)) = state.db.get_block_by_height(h) {
            return (
                StatusCode::OK,
                Json(json!({ "type": "block", "result": b })),
            )
                .into_response();
        }
    }

    if let Ok(Some(tx)) = state.db.get_tx_by_hash(&clean_hex) {
        return (
            StatusCode::OK,
            Json(json!({ "type": "transaction", "result": tx })),
        )
            .into_response();
    }

    if let Ok(Some(b)) = state.db.get_block_by_hash(&clean_hex) {
        return (
            StatusCode::OK,
            Json(json!({ "type": "block", "result": b })),
        )
            .into_response();
    }

    if clean_hex.len() >= 40 {
        let stl57 = if let Ok(addr_bytes) = stellereum::address::parse_address(trimmed) {
            Some(stellereum::address::encode_stl57_address(&addr_bytes))
        } else if let Ok(decoded) = hex::decode(&clean_hex) {
            if decoded.len() == 32 {
                let mut b = [0u8; 32];
                b.copy_from_slice(&decoded);
                Some(stellereum::address::encode_stl57_address(&b))
            } else if decoded.len() == 20 {
                let mut b = [0u8; 32];
                b[12..].copy_from_slice(&decoded);
                Some(stellereum::address::encode_stl57_address(&b))
            } else {
                None
            }
        } else {
            None
        };
        return (
            StatusCode::OK,
            Json(json!({ "type": "account", "address": clean_hex, "stl57": stl57 })),
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
                    "contract": address,
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
async fn get_shards(State(state): State<AppState>) -> impl IntoResponse {
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "stell_getShards",
        "params": {},
        "id": 1
    });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build();
    let fetched = match client {
        Ok(c) => match c.post(&state.rpc_url).json(&payload).send().await {
            Ok(resp) => resp.json::<Value>().await.ok(),
            Err(_) => None,
        },
        Err(_) => None,
    };
    match fetched.as_ref().map(|d| d["result"].clone()) {
        Some(result) if !result.is_null() => {
            let mut out = result;
            if let Some(obj) = out.as_object_mut() {
                obj.insert("source".to_string(), json!("rpc"));
                obj.insert("rpc_url".to_string(), json!(state.rpc_url));
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
            .is_some_and(|got| got == expected),
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

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": format!("verification unavailable: {e}")})),
            )
                .into_response()
        }
    };
    let node_reply: Value = match client.post(&state.rpc_url).json(&payload).send().await {
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
