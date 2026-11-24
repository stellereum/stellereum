//! Stellereum Node Runner & CLI Entry Point
//! Runs Stellereum L1 node utilizing infnode as transparent P2P network transport.
//! Includes built-in Local Testnet Simulator, Wallet Manager, CLOB Orderbook CLI,
//! 3-Tier Oracle Engine, Teleport Bridge Interface, and Genesis Vault Exchange.

use clap::Parser;

mod cli;
mod node;

/// Fail-loud consensus-traffic liveness alarm (tiny helper, no consensus/wire
/// impact). Included by path so `src/lib.rs` stays untouched; the drain loop
/// below owns all state and wiring, this only decides and counts — and the
/// same file is included by `tests/liveness_alarm_tests.rs` for the pure-fn
/// matrix.
#[path = "liveness_alarm.rs"]
pub(crate) mod liveness_alarm;

#[cfg(test)]
mod bin_tests;

// multi_thread, NOT the default current_thread: the node multiplexes the
// consensus loop, quinn's UDP receive path, DHT and storage on one runtime.
// On a single core a current_thread runtime lets the consensus loop starve
// quinn's IO -- the UDP socket queue backed up to 35KB (ss Recv-Q), incoming
// handshakes timed out ("handshake timeout" in both directions), and every
// request then cost 0.4-1.8s while established connections limped along.
// IO-bound tasks block; giving them their own workers costs nothing on an
// idle box and is the difference between a liveness stall and a live chain.
//
// SIZING (single-vCPU thread explosion): the pool sizes now come from
// `node::runtime_limits` instead of a hard-coded 4 workers plus Tokio's
// default 512-thread blocking pool. On a four-or-more-core host the async
// worker count is unchanged (4); on one vCPU it drops to 2 and the blocking
// pool to 8, which bounds a process that was observed at 539 threads. Thread
// counts are scheduling resources only -- no consensus input, wire byte or
// hash reads them.
fn main() -> anyhow::Result<()> {
    // Logs go to STDERR, data to STDOUT. Without this split every command that
    // prints machine-readable output (`status --json`, `gates --yaml`) emitted
    // two INFO lines first and the consumer could not parse it. journald and
    // the shipped units capture both streams, so the node loses nothing.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let limits = node::runtime_limits::detect();
    tracing::info!(
        "[runtime] worker_threads={} max_blocking_threads={} (derived from available_parallelism)",
        limits.worker_threads,
        limits.max_blocking_threads,
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(limits.worker_threads)
        .max_blocking_threads(limits.max_blocking_threads)
        .enable_all()
        .build()
        .map_err(|e| anyhow::anyhow!("tokio runtime: {e}"))?;
    runtime.block_on(run())
}

async fn run() -> anyhow::Result<()> {
    // Protocol identity MUST be installed before any node handshake: it is
    // what every peer compares against (fork id mismatch = consensus refused,
    // loudly). Startup visibility is part of the contract.
    stellereum::protocol::install_chain_identity()
        .map_err(|e| anyhow::anyhow!("protocol identity: {e}"))?;
    tracing::info!("{}", stellereum::protocol::startup_line());
    let cli = cli::args::Cli::parse();
    cli::handlers::handle_command(cli.command).await
}
