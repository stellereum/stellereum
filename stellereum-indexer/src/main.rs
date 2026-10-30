use anyhow::Result;
use std::net::SocketAddr;
use stellereum_indexer::db::Database;
use stellereum_indexer::events::AbiCache;
use stellereum_indexer::server::{create_router, AppState};
use stellereum_indexer::syncer::Syncer;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    info!("╔═══════════════════════════════════════════════════════════════╗");
    info!("║         ⚡ STELLEREUM LIGHTWEIGHT RUST INDEXER V1.0           ║");
    info!("╚═══════════════════════════════════════════════════════════════╝");

    let db_path = std::env::var("INDEXER_DB_PATH").unwrap_or_else(|_| "indexer.db".to_string());
    let node_url =
        std::env::var("INDEXER_NODE_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
    let rpc_url =
        std::env::var("INDEXER_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8545".to_string());
    let listen_port: u16 = std::env::var("INDEXER_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8088);

    info!("Opening SQLite database at '{db_path}'...");
    let db = Database::open(&db_path)?;
    info!("SQLite DB opened successfully with WAL mode enabled.");

    // The ABI cache is shared: the syncer fills it from the node's
    // `stell_getContractAbi` and the API reads it to DECODE contract events.
    let abis = std::sync::Arc::new(AbiCache::new());

    // Start background syncer
    let syncer = Syncer::new_with_abis(db.clone(), node_url, rpc_url.clone(), abis.clone());
    tokio::spawn(async move {
        syncer.run().await;
    });

    // Start Axum REST server
    // Audit B-IDX-3: the verify endpoint is default-deny without this.
    let verify_token = std::env::var("INDEXER_VERIFY_TOKEN").ok();
    if verify_token.is_none() {
        info!("verify endpoint DISABLED (set INDEXER_VERIFY_TOKEN to enable contract-source verification)");
    }
    let app_state = AppState {
        db,
        abis,
        rpc_url: rpc_url.clone(),
        verify_token,
    };
    let app = create_router(app_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], listen_port));
    info!("🚀 Stellereum Indexer API listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
