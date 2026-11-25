//! Stellereum Node Runner & CLI Entry Point
//! Runs Stellereum L1 node utilizing infnode as transparent P2P network transport.
//! Includes built-in Local Testnet Simulator, Wallet Manager, CLOB Orderbook CLI,
//! 3-Tier Oracle Engine, Teleport Bridge Interface, and Genesis Vault Exchange.

use clap::Parser;

mod cli;
mod node;

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
    // Parse CLI and apply optional TOML defaults + `-t`/`--no-telemetry` BEFORE
    // reading `runtime_limits` or spawning the Tokio runtime / any threads so
    // `std::env::set_var` executes strictly single-threaded.
    let cli = cli::args::Cli::parse();
    if let cli::args::Commands::Run {
        ref node_toml,
        no_telemetry,
        ..
    } = cli.command
    {
        let toml_source = stellereum::node_config::discover_toml_path(node_toml.as_deref())?;
        let loaded_cfg = if let Some(path) = toml_source.path() {
            let cfg = stellereum::node_config::NodeTomlConfig::from_file(path)?;
            let applied = cfg.apply_defaults_to_env();
            tracing::info!(
                "[config] loaded {} (source={}, applied={} env defaults)",
                path.display(),
                toml_source.label(),
                applied.len(),
            );
            Some(cfg)
        } else {
            None
        };
        if no_telemetry {
            std::env::set_var(stellereum::node_config::NO_TELEMETRY_ENV, "1");
            tracing::info!(
                "[telemetry] disabled via -t/--no-telemetry ({}=1): /status dashboard disabled; /health, /healthz, /readyz, /metrics remain active",
                stellereum::node_config::NO_TELEMETRY_ENV,
            );
        }
        if let Some(cfg) = loaded_cfg {
            let report = cfg.validate();
            for warn in &report.warnings {
                tracing::warn!("[config] {warn}");
            }
            if !report.is_ok() {
                for err in &report.errors {
                    tracing::error!("[config] {err}");
                }
                anyhow::bail!(
                    "node TOML config validation failed ({} error(s)): {}",
                    report.errors.len(),
                    report.errors.join("; "),
                );
            }
        }
    }
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
    runtime.block_on(run(cli))
}

async fn run(cli: cli::args::Cli) -> anyhow::Result<()> {
    // Protocol identity MUST be installed before any node handshake: it is
    // what every peer compares against (fork id mismatch = consensus refused,
    // loudly). Startup visibility is part of the contract.
    stellereum::protocol::install_chain_identity()
        .map_err(|e| anyhow::anyhow!("protocol identity: {e}"))?;
    tracing::info!("{}", stellereum::protocol::startup_line());
    cli::handlers::handle_command(cli.command).await
}
