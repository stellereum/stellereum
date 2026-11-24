//! Typed TOML node configuration + env-override bridge + validation.
//!
//! Stellereum reads ~75 `STELL_*` environment variables across the codebase.
//! Rather than rewriting every call site, [`NodeTomlConfig`] parses an optional
//! TOML file (`--node-toml <PATH>`, `STELL_NODE_TOML`, or `./stellereum.toml`),
//! validates invariants, and calls [`NodeTomlConfig::apply_defaults_to_env`]
//! early in `main()` — BEFORE spawning the Tokio runtime or any worker threads.
//! Any variable already present in the process environment is NEVER overwritten,
//! so environment variables always override TOML, and TOML overrides compiled
//! defaults.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Environment variable pointing to the Stellereum TOML node config file.
pub const NODE_TOML_ENV: &str = "STELL_NODE_TOML";
/// Default auto-discovered TOML filename in the current working directory.
pub const DEFAULT_NODE_TOML_FILE: &str = "stellereum.toml";
/// Environment variable disabling non-essential telemetry/status-banner exposure.
pub const NO_TELEMETRY_ENV: &str = "STELL_NO_TELEMETRY";

// Compiled defaults matching `node::policy` and crate constants.
pub const DEFAULT_TICK_MS: u64 = 50;
pub const DEFAULT_MIN_BLOCK_MS: u64 = 50;
pub const DEFAULT_ROUND_TIMEOUT_MS: u64 = crate::consensus::FROZEN_ROUND_TIMEOUT_BASE_MS;
pub const DEFAULT_ROUND_ZERO_TIMEOUT_MS: u64 = 650;
pub const DEFAULT_DOWN_PROPOSER_TIMEOUT_MS: u64 = 800;
pub const DEFAULT_STRAGGLER_GRACE_MS: u64 = 0;
pub const DEFAULT_STRAGGLER_GRACE_CAP_MS: u64 = 30_000;
pub const DEFAULT_CATCHUP_INTERVAL_MS: u64 = 30_000;
pub const DEFAULT_CATCHUP_BUDGET_MS: u64 = 250;
pub const DEFAULT_RETRO_PUBLISH_INTERVAL_MS: u64 = 30_000;
pub const DEFAULT_RETRO_BEHIND_WINDOW_SECS: u64 = 120;
pub const DEFAULT_DEADLOCK_TIMEOUT_SECS: u64 = 300;

pub const DEFAULT_SHARDS: &str = "0";
pub const DEFAULT_DATA_DIR: &str = "./data";
pub const DEFAULT_ARCHIVE: bool = true;
pub const DEFAULT_KEEP_BLOCKS: u64 = 50_000;
pub const DEFAULT_SNAPSHOT_INTERVAL: u64 = 1000;

pub const DEFAULT_SEND_TIMEOUT_MS: u64 = 2000;
pub const DEFAULT_BROADCAST_JOIN_MS: u64 = 500;
pub const DEFAULT_PROBE_EVICT_AFTER: u32 = 3;
pub const DEFAULT_DIAL_BACKOFF_BASE_MS: u64 = 2000;
pub const DEFAULT_DIAL_BACKOFF_MAX_MS: u64 = 300_000;
pub const DEFAULT_DIAL_BUDGET_PER_SEC: u32 = 4;
pub const DEFAULT_CONS_BCAST_MIN_INTERVAL_MS: u64 = 25;
pub const DEFAULT_CONS_PROBE_MIN_INTERVAL_MS: u64 = 5000;
pub const DEFAULT_INBOUND_BULK_BYTES_PER_SEC: u64 = 512 * 1024;
pub const DEFAULT_INBOUND_BULK_BURST_BYTES: u64 = 1024 * 1024;
pub const DEFAULT_DHT_KEEP_BLOCKS_DEFAULT: u64 = 8000;
pub const DEFAULT_DHT_PRUNE_INTERVAL_HEIGHTS: u64 = 100;
pub const DEFAULT_DHT_PRUNE_MAX_PER_RUN: usize = 2048;
pub const DEFAULT_DHT_FOREVER_TTL_MS: i64 = 100 * 365 * 24 * 3600 * 1000;

pub const DEFAULT_RPC_LISTEN: &str = "127.0.0.1:8545";
pub const DEFAULT_EXPLORER_LISTEN: &str = "127.0.0.1:8080";
pub const DEFAULT_TRUSTED_PROXY_CIDRS: &str = "127.0.0.0/8,::1/128";
pub const DEFAULT_XFF_MODE: &str = "rightmost";
pub const DEFAULT_MEMPOOL_CAP: usize = 50_000;
pub const DEFAULT_MEMPOOL_PER_SENDER: usize = 1024;

pub const DEFAULT_FAUCET_DRIP_STELL: u64 = 2;
pub const DEFAULT_FAUCET_LIFETIME_CAP_STELL: u64 = 50;
pub const DEFAULT_FALCON_KEY_FILE: &str = "./keys/falcon.key";
pub const DEFAULT_LIVENESS_ALARM_MS: u64 = 300_000;
pub const DEFAULT_MAX_CACHED_BLOCKS: usize = 2048;
pub const DEFAULT_MAX_PQ_FALLBACK_ENTRIES: usize = 65_536;
pub const DEFAULT_MAX_ACCOUNTS_WARN: u64 = 5_000_000;
pub const DEFAULT_SNAPSHOT_CHUNK_ACCOUNTS: usize = 50_000;

/// Root TOML node configuration.
///
/// Every section uses `#[serde(deny_unknown_fields)]` so typos fail loudly.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NodeTomlConfig {
    /// Optional shorthand `telemetry = false` or full `[telemetry]` table.
    pub telemetry: Option<TelemetryEntry>,
    pub tempo: TempoConfig,
    pub consensus: ConsensusConfig,
    pub storage: StorageConfig,
    pub network: NetworkConfig,
    pub rpc: RpcConfig,
    pub mempool: MempoolConfig,
    pub faucet: FaucetConfig,
    pub signer: SignerConfig,
    pub execution: ExecutionConfig,
}

/// Supports both `telemetry = false` at top level and `[telemetry] enabled = false`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TelemetryEntry {
    Flag(bool),
    Table(Box<TelemetryConfig>),
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TempoConfig {
    pub tick_ms: Option<u64>,
    pub min_block_ms: Option<u64>,
    pub round_timeout_ms: Option<u64>,
    pub round_zero_timeout_ms: Option<u64>,
    pub down_proposer_timeout_ms: Option<u64>,
    pub straggler_grace_ms: Option<u64>,
    pub straggler_grace_cap_ms: Option<u64>,
    pub straggler_freshness_ms: Option<u64>,
    pub catchup_interval_ms: Option<u64>,
    pub catchup_budget_ms: Option<u64>,
    pub retro_publish_interval_ms: Option<u64>,
    pub retro_behind_window_secs: Option<u64>,
    pub deadlock_timeout_secs: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConsensusConfig {
    pub chain_id: Option<u64>,
    pub observer: Option<bool>,
    pub workchain_observer: Option<bool>,
    pub new_chain: Option<bool>,
    pub shards: Option<String>,
    pub experimental_shards: Option<bool>,
    pub pure_pq: Option<bool>,
    pub auto_upgrade: Option<bool>,
    pub wait_supermajority: Option<u64>,
    pub wait_supermajority_timeout_secs: Option<u64>,
    pub gov_allow_multinode_writes: Option<bool>,
    pub xpc_activation_height: Option<u64>,
    pub chain_bind_activation_height: Option<u64>,
    pub upgrade_exec_activation_height: Option<u64>,
    pub min_bond_buffer: Option<u64>,
    pub slash_eject_warn_gap: Option<u64>,
    pub mev_v4: Option<bool>,
    pub mev_unseal_wait_ms: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageConfig {
    pub data_dir: Option<String>,
    pub archive: Option<bool>,
    pub keep_blocks: Option<u64>,
    pub snapshot_interval: Option<u64>,
    pub sled_cache_bytes: Option<u64>,
    pub sled_flush_ms: Option<u64>,
    pub sled_compression: Option<bool>,
    pub schema_downgrade_allowed: Option<bool>,
    pub validator_set_max_lag: Option<u64>,
    pub max_cached_blocks: Option<usize>,
    pub max_pq_fallback_entries: Option<usize>,
    pub max_accounts_warn: Option<u64>,
    pub snapshot_chunk_accounts: Option<usize>,
    pub upgrade_halt_marker: Option<String>,
    pub cnvrf_v3_dir: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkConfig {
    pub dns_seeds: Option<String>,
    pub peer_pq_keys: Option<String>,
    pub send_timeout_ms: Option<u64>,
    pub broadcast_join_ms: Option<u64>,
    pub probe_evict_after: Option<u32>,
    pub dial_backoff_base_ms: Option<u64>,
    pub dial_backoff_max_ms: Option<u64>,
    pub dial_budget_per_sec: Option<u32>,
    pub cons_bcast_min_interval_ms: Option<u64>,
    pub cons_probe_min_interval_ms: Option<u64>,
    pub inbound_bulk_bytes_per_sec: Option<u64>,
    pub inbound_bulk_burst_bytes: Option<u64>,
    pub inbound_critical_bytes_per_sec: Option<u64>,
    pub inbound_critical_burst_bytes: Option<u64>,
    pub dht_keep_blocks_default: Option<u64>,
    pub dht_prune_interval_heights: Option<u64>,
    pub dht_prune_max_per_run: Option<usize>,
    pub dht_forever_ttl_ms: Option<i64>,
    pub repl_max_concurrent: Option<usize>,
    pub repl_min_interval_ms: Option<u64>,
    pub repl_head_min_interval_ms: Option<u64>,
    pub repl_store_timeout_ms: Option<u64>,
    pub repl_store_max_attempts: Option<u32>,
    pub repl_circuit_threshold: Option<u32>,
    pub repl_circuit_cooldown_ms: Option<u64>,
    pub repl_queue_wait_ms: Option<u64>,
    pub repl_pace_wait_ms: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RpcConfig {
    pub rpc_listen: Option<String>,
    pub explorer_listen: Option<String>,
    pub auth_token: Option<String>,
    pub rate_limit_per_sec: Option<u32>,
    pub standalone_rate_limit: Option<u32>,
    pub rpc_rate_limit_per_sec: Option<u32>,
    pub estimate_fee_rate_limit: Option<u32>,
    pub ws_expensive_read_rate_limit: Option<u32>,
    pub http_expensive_read_concurrency: Option<usize>,
    pub ws_idle_timeout_secs: Option<u64>,
    pub sse_idle_timeout_secs: Option<u64>,
    pub trusted_proxy_cidrs: Option<String>,
    pub xff_mode: Option<String>,
    pub trust_loopback_forwarded: Option<bool>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MempoolConfig {
    pub cap: Option<usize>,
    pub per_sender: Option<usize>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FaucetConfig {
    pub enabled: Option<bool>,
    pub faucet_key: Option<String>,
    pub faucet_key_file: Option<String>,
    pub faucet_token: Option<String>,
    pub faucet_drip_stell: Option<u64>,
    pub faucet_lifetime_cap_stell: Option<u64>,
    pub faucet_ip_max_per_hour: Option<u32>,
    pub public_drip_nano: Option<u64>,
    pub public_drip_cooldown_secs: Option<u64>,
    pub turnstile_site_key: Option<String>,
    pub turnstile_secret_key: Option<String>,
    pub dev_unsafe_testkey: Option<bool>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SignerConfig {
    pub falcon_key_file: Option<String>,
    pub remote_signer_url: Option<String>,
    pub remote_signer_token: Option<String>,
    pub key_plaintext: Option<bool>,
    pub key_prompt: Option<bool>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelemetryConfig {
    pub enabled: Option<bool>,
    pub liveness_alarm_ms: Option<u64>,
    pub log_max_bytes: Option<u64>,
    pub log_max_files: Option<usize>,
    pub ready_max_stall_secs: Option<u64>,
    pub ready_min_peers: Option<usize>,
    pub health_cache_ms: Option<u64>,
    pub health_min_peers: Option<u64>,
    pub health_max_finalization_lag_secs: Option<u64>,
    pub health_critical_finalization_lag_secs: Option<u64>,
    pub health_max_finalization_lag_blocks: Option<u64>,
    pub health_max_mempool_age_secs: Option<u64>,
    pub health_max_persist_age_secs: Option<u64>,
    pub health_max_snapshot_age_secs: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExecutionConfig {
    pub parallel_exec: Option<bool>,
    pub parallel_plan_chunk: Option<usize>,
    pub runtime_workers: Option<usize>,
    pub runtime_max_blocking: Option<usize>,
    pub register_source: Option<bool>,
}

/// Where a TOML path was resolved from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TomlPathSource {
    CliFlag(PathBuf),
    EnvVar(PathBuf),
    AutoDiscovered(PathBuf),
    None,
}

impl TomlPathSource {
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::CliFlag(p) | Self::EnvVar(p) | Self::AutoDiscovered(p) => Some(p.as_path()),
            Self::None => None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::CliFlag(_) => "cli",
            Self::EnvVar(_) => "env",
            Self::AutoDiscovered(_) => "auto",
            Self::None => "none",
        }
    }
}

/// Discover the optional TOML configuration file path.
///
/// Precedence:
/// 1. Explicit CLI flag (`--node-toml` or `config check --file`): MUST exist.
/// 2. `STELL_NODE_TOML` env var (if non-empty): MUST exist.
/// 3. `./stellereum.toml` in the current working directory if it exists.
/// 4. `TomlPathSource::None` (env + compiled defaults only).
pub fn discover_toml_path(explicit: Option<&Path>) -> anyhow::Result<TomlPathSource> {
    discover_toml_path_with_env(
        explicit,
        std::env::var(NODE_TOML_ENV).ok().as_deref(),
        Path::new(DEFAULT_NODE_TOML_FILE),
    )
}

fn discover_toml_path_with_env(
    explicit: Option<&Path>,
    env_path: Option<&str>,
    auto_path: &Path,
) -> anyhow::Result<TomlPathSource> {
    if let Some(p) = explicit {
        if !p.is_file() {
            anyhow::bail!("node TOML config file not found: {}", p.display());
        }
        return Ok(TomlPathSource::CliFlag(p.to_path_buf()));
    }
    if let Some(raw) = env_path.map(str::trim).filter(|s| !s.is_empty()) {
        let p = PathBuf::from(raw);
        if !p.is_file() {
            anyhow::bail!(
                "{NODE_TOML_ENV} points to missing config file: {}",
                p.display()
            );
        }
        return Ok(TomlPathSource::EnvVar(p));
    }
    if auto_path.is_file() {
        return Ok(TomlPathSource::AutoDiscovered(auto_path.to_path_buf()));
    }
    Ok(TomlPathSource::None)
}

/// Source of an effective configuration setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfigSource {
    Toml,
    Env,
    Default,
}

/// One resolved configuration setting with its provenance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EffectiveSetting {
    pub key: &'static str,
    pub env_var: &'static str,
    pub value: String,
    pub source: ConfigSource,
    pub secret: bool,
}

/// Validation result returned by [`NodeTomlConfig::validate`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigReport {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl ConfigReport {
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Merged view of TOML + env + compiled defaults plus validation report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ResolvedConfig {
    pub settings: Vec<EffectiveSetting>,
    pub report: ConfigReport,
}

fn bool_to_env(b: bool) -> &'static str {
    if b {
        "1"
    } else {
        "0"
    }
}

fn parse_env_bool(raw: &str) -> Result<bool, String> {
    let v = raw.trim().to_ascii_lowercase();
    match v.as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(format!("invalid boolean '{raw}' (expected 1/0/true/false)")),
    }
}

fn set_env_if_unset(key: &'static str, val: String, applied: &mut Vec<&'static str>) {
    if std::env::var_os(key).is_none() {
        std::env::set_var(key, val);
        applied.push(key);
    }
}

fn is_loopback_listen(listen: &str) -> bool {
    let trimmed = listen.trim();
    if let Ok(sock) = trimmed.parse::<SocketAddr>() {
        return sock.ip().is_loopback();
    }
    if let Some((host, _port)) = trimmed.rsplit_once(':') {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if host.eq_ignore_ascii_case("localhost") {
            return true;
        }
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            return ip.is_loopback();
        }
    }
    trimmed.eq_ignore_ascii_case("localhost")
}

impl NodeTomlConfig {
    /// Extract the normalized `[telemetry]` configuration, whether written as
    /// `telemetry = false` or `[telemetry] enabled = false`.
    pub fn telemetry_config(&self) -> TelemetryConfig {
        match &self.telemetry {
            Some(TelemetryEntry::Flag(enabled)) => TelemetryConfig {
                enabled: Some(*enabled),
                ..Default::default()
            },
            Some(TelemetryEntry::Table(t)) => (**t).clone(),
            None => TelemetryConfig::default(),
        }
    }

    /// Parse a [`NodeTomlConfig`] from a TOML string, failing loudly on syntax
    /// errors, duplicate keys/tables, or unknown fields.
    pub fn from_toml_str(input: &str) -> anyhow::Result<Self> {
        let json_val = parse_toml_to_json(input).map_err(|e| anyhow::anyhow!("{e}"))?;
        let cfg: Self = serde_json::from_value(json_val)
            .map_err(|e| anyhow::anyhow!("invalid node TOML config: {e}"))?;
        Ok(cfg)
    }

    /// Load and parse a [`NodeTomlConfig`] from disk.
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
        Self::from_toml_str(&content).map_err(|e| anyhow::anyhow!("in {}: {e}", path.display()))
    }

    /// Apply configured TOML values to process environment variables ONLY when
    /// the variable is currently unset (`std::env::var_os(key).is_none()`).
    ///
    /// MUST be called in `main()` before spawning the Tokio runtime or threads.
    pub fn apply_defaults_to_env(&self) -> Vec<&'static str> {
        let mut applied = Vec::new();
        macro_rules! push_num {
            ($key:expr, $val:expr $(,)?) => {
                if let Some(n) = $val {
                    set_env_if_unset($key, n.to_string(), &mut applied);
                }
            };
        }
        macro_rules! push_bool {
            ($key:expr, $val:expr $(,)?) => {
                if let Some(b) = $val {
                    set_env_if_unset($key, bool_to_env(b).to_string(), &mut applied);
                }
            };
        }
        macro_rules! push_str {
            ($key:expr, $val:expr $(,)?) => {
                if let Some(s) = $val {
                    set_env_if_unset($key, s.to_string(), &mut applied);
                }
            };
        }

        // [tempo]
        push_num!("STELL_TICK_MS", self.tempo.tick_ms);
        push_num!("STELL_MIN_BLOCK_MS", self.tempo.min_block_ms);
        push_num!("STELL_ROUND_TIMEOUT_MS", self.tempo.round_timeout_ms);
        push_num!(
            "STELL_ROUND_ZERO_TIMEOUT_MS",
            self.tempo.round_zero_timeout_ms,
        );
        push_num!(
            "STELL_DOWN_PROPOSER_TIMEOUT_MS",
            self.tempo.down_proposer_timeout_ms,
        );
        push_num!("STELL_STRAGGLER_GRACE_MS", self.tempo.straggler_grace_ms);
        push_num!(
            "STELL_STRAGGLER_GRACE_CAP_MS",
            self.tempo.straggler_grace_cap_ms,
        );
        push_num!(
            "STELL_STRAGGLER_FRESHNESS_MS",
            self.tempo.straggler_freshness_ms,
        );
        push_num!("STELL_CATCHUP_INTERVAL_MS", self.tempo.catchup_interval_ms);
        push_num!("STELL_CATCHUP_BUDGET_MS", self.tempo.catchup_budget_ms);
        push_num!(
            "STELL_RETRO_PUBLISH_INTERVAL_MS",
            self.tempo.retro_publish_interval_ms,
        );
        push_num!(
            "STELL_RETRO_BEHIND_WINDOW_SECS",
            self.tempo.retro_behind_window_secs,
        );
        push_num!(
            "STELL_DEADLOCK_TIMEOUT_SECS",
            self.tempo.deadlock_timeout_secs,
        );

        // [consensus]
        push_num!("STELL_CHAIN_ID", self.consensus.chain_id);
        push_bool!("STELL_OBSERVER", self.consensus.observer);
        push_bool!(
            "STELL_WORKCHAIN_OBSERVER",
            self.consensus.workchain_observer,
        );
        push_bool!("STELL_NEW_CHAIN", self.consensus.new_chain);
        push_str!("STELL_SHARDS", self.consensus.shards.as_deref());
        push_bool!(
            "STELL_EXPERIMENTAL_SHARDS",
            self.consensus.experimental_shards,
        );
        if self.consensus.pure_pq == Some(true) {
            push_bool!("STELL_PURE_PQ", Some(true));
        }
        push_bool!("STELL_AUTO_UPGRADE", self.consensus.auto_upgrade);
        push_num!(
            "STELL_WAIT_SUPERMAJORITY",
            self.consensus.wait_supermajority,
        );
        push_num!(
            "STELL_WAIT_SUPERMAJORITY_TIMEOUT_SECS",
            self.consensus.wait_supermajority_timeout_secs,
        );
        push_bool!(
            "STELL_GOV_ALLOW_MULTINODE_WRITES",
            self.consensus.gov_allow_multinode_writes,
        );
        push_num!(
            "STELL_XPC_ACTIVATION_HEIGHT",
            self.consensus.xpc_activation_height,
        );
        push_num!(
            "STELL_CHAIN_BIND_ACTIVATION_HEIGHT",
            self.consensus.chain_bind_activation_height,
        );
        push_num!(
            "STELL_UPGRADE_EXEC_ACTIVATION_HEIGHT",
            self.consensus.upgrade_exec_activation_height,
        );
        push_num!("STELL_MIN_BOND_BUFFER", self.consensus.min_bond_buffer);
        push_num!(
            "STELL_SLASH_EJECT_WARN_GAP",
            self.consensus.slash_eject_warn_gap,
        );
        push_bool!("STELL_MEV_V4", self.consensus.mev_v4);
        push_num!(
            "STELL_MEV_UNSEAL_WAIT_MS",
            self.consensus.mev_unseal_wait_ms,
        );

        // [storage]
        push_str!("STELL_DATA_DIR", self.storage.data_dir.as_deref());
        push_bool!("STELL_ARCHIVE", self.storage.archive);
        push_num!("STELL_KEEP_BLOCKS", self.storage.keep_blocks);
        push_num!("STELL_SNAPSHOT_INTERVAL", self.storage.snapshot_interval);
        push_num!("STELL_SLED_CACHE_BYTES", self.storage.sled_cache_bytes);
        push_num!("STELL_SLED_FLUSH_MS", self.storage.sled_flush_ms);
        push_bool!("STELL_SLED_COMPRESSION", self.storage.sled_compression);
        push_bool!(
            "STELL_ALLOW_SCHEMA_DOWNGRADE",
            self.storage.schema_downgrade_allowed,
        );
        push_num!(
            "STELL_VALIDATOR_SET_MAX_LAG",
            self.storage.validator_set_max_lag,
        );
        push_num!("STELL_MAX_CACHED_BLOCKS", self.storage.max_cached_blocks);
        push_num!(
            "STELL_MAX_PQ_FALLBACK_ENTRIES",
            self.storage.max_pq_fallback_entries,
        );
        push_num!("STELL_MAX_ACCOUNTS_WARN", self.storage.max_accounts_warn);
        push_num!(
            "STELL_SNAPSHOT_CHUNK_ACCOUNTS",
            self.storage.snapshot_chunk_accounts,
        );
        push_str!(
            "STELL_UPGRADE_HALT_MARKER",
            self.storage.upgrade_halt_marker.as_deref(),
        );
        push_str!("STELL_CNVRF_V3_DIR", self.storage.cnvrf_v3_dir.as_deref());

        // [network]
        push_str!("STELL_DNS_SEEDS", self.network.dns_seeds.as_deref());
        push_str!("STELL_PEER_PQ_KEYS", self.network.peer_pq_keys.as_deref());
        push_num!("STELL_SEND_TIMEOUT_MS", self.network.send_timeout_ms);
        push_num!("STELL_BROADCAST_JOIN_MS", self.network.broadcast_join_ms);
        push_num!("STELL_PROBE_EVICT_AFTER", self.network.probe_evict_after);
        push_num!(
            "STELL_DIAL_BACKOFF_BASE_MS",
            self.network.dial_backoff_base_ms,
        );
        push_num!(
            "STELL_DIAL_BACKOFF_MAX_MS",
            self.network.dial_backoff_max_ms,
        );
        push_num!(
            "STELL_DIAL_BUDGET_PER_SEC",
            self.network.dial_budget_per_sec,
        );
        push_num!(
            "STELL_CONS_BCAST_MIN_INTERVAL_MS",
            self.network.cons_bcast_min_interval_ms,
        );
        push_num!(
            "STELL_CONS_PROBE_MIN_INTERVAL_MS",
            self.network.cons_probe_min_interval_ms,
        );
        push_num!(
            "STELL_INBOUND_BULK_BYTES_PER_SEC",
            self.network.inbound_bulk_bytes_per_sec,
        );
        push_num!(
            "STELL_INBOUND_BULK_BURST_BYTES",
            self.network.inbound_bulk_burst_bytes,
        );
        push_num!(
            "STELL_INBOUND_CRITICAL_BYTES_PER_SEC",
            self.network.inbound_critical_bytes_per_sec,
        );
        push_num!(
            "STELL_INBOUND_CRITICAL_BURST_BYTES",
            self.network.inbound_critical_burst_bytes,
        );
        push_num!(
            "STELL_DHT_KEEP_BLOCKS_DEFAULT",
            self.network.dht_keep_blocks_default,
        );
        push_num!(
            "STELL_DHT_PRUNE_INTERVAL_HEIGHTS",
            self.network.dht_prune_interval_heights,
        );
        push_num!(
            "STELL_DHT_PRUNE_MAX_PER_RUN",
            self.network.dht_prune_max_per_run,
        );
        push_num!("STELL_DHT_FOREVER_TTL_MS", self.network.dht_forever_ttl_ms);
        push_num!(
            "STELL_REPL_MAX_CONCURRENT",
            self.network.repl_max_concurrent,
        );
        push_num!(
            "STELL_REPL_MIN_INTERVAL_MS",
            self.network.repl_min_interval_ms,
        );
        push_num!(
            "STELL_REPL_HEAD_MIN_INTERVAL_MS",
            self.network.repl_head_min_interval_ms,
        );
        push_num!(
            "STELL_REPL_STORE_TIMEOUT_MS",
            self.network.repl_store_timeout_ms,
        );
        push_num!(
            "STELL_REPL_STORE_MAX_ATTEMPTS",
            self.network.repl_store_max_attempts,
        );
        push_num!(
            "STELL_REPL_CIRCUIT_THRESHOLD",
            self.network.repl_circuit_threshold,
        );
        push_num!(
            "STELL_REPL_CIRCUIT_COOLDOWN_MS",
            self.network.repl_circuit_cooldown_ms,
        );
        push_num!("STELL_REPL_QUEUE_WAIT_MS", self.network.repl_queue_wait_ms);
        push_num!("STELL_REPL_PACE_WAIT_MS", self.network.repl_pace_wait_ms);

        // [rpc]
        push_str!("STELL_RPC_LISTEN", self.rpc.rpc_listen.as_deref());
        push_str!("STELL_EXPLORER_LISTEN", self.rpc.explorer_listen.as_deref());
        push_str!("STELL_RPC_AUTH_TOKEN", self.rpc.auth_token.as_deref());
        push_num!("STELL_RATE_LIMIT_PER_SEC", self.rpc.rate_limit_per_sec);
        push_num!(
            "STELL_STANDALONE_RATE_LIMIT",
            self.rpc.standalone_rate_limit,
        );
        push_num!(
            "STELL_RPC_RATE_LIMIT_PER_SEC",
            self.rpc.rpc_rate_limit_per_sec,
        );
        push_num!(
            "STELL_ESTIMATE_FEE_RATE_LIMIT",
            self.rpc.estimate_fee_rate_limit,
        );
        push_num!(
            "STELL_WS_EXPENSIVE_READ_RATE_LIMIT",
            self.rpc.ws_expensive_read_rate_limit,
        );
        push_num!(
            "STELL_HTTP_EXPENSIVE_READ_CONCURRENCY",
            self.rpc.http_expensive_read_concurrency,
        );
        push_num!("STELL_WS_IDLE_TIMEOUT_SECS", self.rpc.ws_idle_timeout_secs);
        push_num!(
            "STELL_SSE_IDLE_TIMEOUT_SECS",
            self.rpc.sse_idle_timeout_secs,
        );
        push_str!(
            "STELL_TRUSTED_PROXY_CIDRS",
            self.rpc.trusted_proxy_cidrs.as_deref(),
        );
        push_str!("STELL_XFF_MODE", self.rpc.xff_mode.as_deref());
        push_bool!(
            "STELL_TRUST_LOOPBACK_FORWARDED",
            self.rpc.trust_loopback_forwarded,
        );

        // [mempool]
        push_num!("STELL_MEMPOOL_CAP", self.mempool.cap);
        push_num!("STELL_MEMPOOL_PER_SENDER", self.mempool.per_sender);

        // [faucet]
        push_bool!("STELL_FAUCET", self.faucet.enabled);
        push_str!("STELL_FAUCET_KEY", self.faucet.faucet_key.as_deref());
        push_str!(
            "STELL_FAUCET_KEY_FILE",
            self.faucet.faucet_key_file.as_deref(),
        );
        push_str!("STELL_FAUCET_TOKEN", self.faucet.faucet_token.as_deref());
        push_num!("STELL_FAUCET_DRIP_STELL", self.faucet.faucet_drip_stell);
        push_num!(
            "STELL_FAUCET_LIFETIME_CAP_STELL",
            self.faucet.faucet_lifetime_cap_stell,
        );
        push_num!(
            "STELL_FAUCET_IP_MAX_PER_HOUR",
            self.faucet.faucet_ip_max_per_hour,
        );
        push_num!("STELL_PUBLIC_DRIP_NANO", self.faucet.public_drip_nano);
        push_num!(
            "STELL_PUBLIC_DRIP_COOLDOWN_SECS",
            self.faucet.public_drip_cooldown_secs,
        );
        push_str!(
            "STELL_TURNSTILE_SITE_KEY",
            self.faucet.turnstile_site_key.as_deref(),
        );
        push_str!(
            "STELL_TURNSTILE_SECRET_KEY",
            self.faucet.turnstile_secret_key.as_deref(),
        );
        push_bool!("STELL_DEV_UNSAFE_TESTKEY", self.faucet.dev_unsafe_testkey);

        // [signer]
        push_str!(
            "STELL_FALCON_KEY_FILE",
            self.signer.falcon_key_file.as_deref(),
        );
        push_str!(
            "STELL_REMOTE_SIGNER_URL",
            self.signer.remote_signer_url.as_deref(),
        );
        push_str!(
            "STELL_REMOTE_SIGNER_TOKEN",
            self.signer.remote_signer_token.as_deref(),
        );
        push_bool!("STELL_KEY_PLAINTEXT", self.signer.key_plaintext);
        push_bool!("STELL_KEY_PROMPT", self.signer.key_prompt);

        // [telemetry]
        let tel = self.telemetry_config();
        if let Some(enabled) = tel.enabled {
            set_env_if_unset(
                NO_TELEMETRY_ENV,
                bool_to_env(!enabled).to_string(),
                &mut applied,
            );
        }
        push_num!("STELL_LIVENESS_ALARM_MS", tel.liveness_alarm_ms);
        push_num!("STELL_LOG_MAX_BYTES", tel.log_max_bytes);
        push_num!("STELL_LOG_MAX_FILES", tel.log_max_files);
        push_num!("STELL_READY_MAX_STALL_SECS", tel.ready_max_stall_secs);
        push_num!("STELL_READY_MIN_PEERS", tel.ready_min_peers);
        push_num!("STELL_HEALTH_CACHE_MS", tel.health_cache_ms);
        push_num!("STELL_HEALTH_MIN_PEERS", tel.health_min_peers);
        push_num!(
            "STELL_HEALTH_MAX_FINALIZATION_LAG_SECS",
            tel.health_max_finalization_lag_secs,
        );
        push_num!(
            "STELL_HEALTH_CRITICAL_FINALIZATION_LAG_SECS",
            tel.health_critical_finalization_lag_secs,
        );
        push_num!(
            "STELL_HEALTH_MAX_FINALIZATION_LAG_BLOCKS",
            tel.health_max_finalization_lag_blocks,
        );
        push_num!(
            "STELL_HEALTH_MAX_MEMPOOL_AGE_SECS",
            tel.health_max_mempool_age_secs,
        );
        push_num!(
            "STELL_HEALTH_MAX_PERSIST_AGE_SECS",
            tel.health_max_persist_age_secs,
        );
        push_num!(
            "STELL_HEALTH_MAX_SNAPSHOT_AGE_SECS",
            tel.health_max_snapshot_age_secs,
        );

        // [execution]
        push_bool!("STELL_PARALLEL_EXEC", self.execution.parallel_exec);
        push_num!(
            "STELL_PARALLEL_PLAN_CHUNK",
            self.execution.parallel_plan_chunk,
        );
        push_num!("STELL_RUNTIME_WORKERS", self.execution.runtime_workers);
        push_num!(
            "STELL_RUNTIME_MAX_BLOCKING",
            self.execution.runtime_max_blocking,
        );
        push_bool!("STELL_REGISTER_SOURCE", self.execution.register_source);

        applied
    }

    /// Merge TOML with the current process `STELL_*` environment and validate.
    pub fn resolve_effective(&self) -> ResolvedConfig {
        self.resolve_effective_with_env(|k| std::env::var(k).ok())
    }

    /// Validate invariants against TOML merged with the current process env.
    pub fn validate(&self) -> ConfigReport {
        self.resolve_effective().report
    }

    /// Pure validation against a caller-supplied environment lookup (testable
    /// without mutating process-global env).
    pub fn validate_with_env<F>(&self, env_get: F) -> ConfigReport
    where
        F: Fn(&str) -> Option<String>,
    {
        self.resolve_effective_with_env(env_get).report
    }

    /// Resolve every setting (value + source) and evaluate all validation rules.
    pub fn resolve_effective_with_env<F>(&self, env_get: F) -> ResolvedConfig
    where
        F: Fn(&str) -> Option<String>,
    {
        let mut settings = Vec::new();
        let mut report = ConfigReport::default();

        let resolve_u64 = |settings: &mut Vec<EffectiveSetting>,
                           report: &mut ConfigReport,
                           key: &'static str,
                           env_var: &'static str,
                           toml_val: Option<u64>,
                           default: u64|
         -> u64 {
            if let Some(raw) = env_get(env_var) {
                match raw.trim().parse::<u64>() {
                    Ok(v) => {
                        settings.push(EffectiveSetting {
                            key,
                            env_var,
                            value: v.to_string(),
                            source: ConfigSource::Env,
                            secret: false,
                        });
                        return v;
                    }
                    Err(_) => {
                        report
                            .errors
                            .push(format!("{env_var}='{raw}' is not a valid u64 integer"));
                        let fallback = toml_val.unwrap_or(default);
                        settings.push(EffectiveSetting {
                            key,
                            env_var,
                            value: raw,
                            source: ConfigSource::Env,
                            secret: false,
                        });
                        return fallback;
                    }
                }
            }
            if let Some(v) = toml_val {
                settings.push(EffectiveSetting {
                    key,
                    env_var,
                    value: v.to_string(),
                    source: ConfigSource::Toml,
                    secret: false,
                });
                v
            } else {
                settings.push(EffectiveSetting {
                    key,
                    env_var,
                    value: default.to_string(),
                    source: ConfigSource::Default,
                    secret: false,
                });
                default
            }
        };

        let resolve_opt_u64 = |settings: &mut Vec<EffectiveSetting>,
                               report: &mut ConfigReport,
                               key: &'static str,
                               env_var: &'static str,
                               toml_val: Option<u64>|
         -> Option<u64> {
            if let Some(raw) = env_get(env_var).filter(|s| !s.trim().is_empty()) {
                match raw.trim().parse::<u64>() {
                    Ok(v) => {
                        settings.push(EffectiveSetting {
                            key,
                            env_var,
                            value: v.to_string(),
                            source: ConfigSource::Env,
                            secret: false,
                        });
                        return Some(v);
                    }
                    Err(_) => {
                        report
                            .errors
                            .push(format!("{env_var}='{raw}' is not a valid u64 integer"));
                        settings.push(EffectiveSetting {
                            key,
                            env_var,
                            value: raw,
                            source: ConfigSource::Env,
                            secret: false,
                        });
                        return toml_val;
                    }
                }
            }
            if let Some(v) = toml_val {
                settings.push(EffectiveSetting {
                    key,
                    env_var,
                    value: v.to_string(),
                    source: ConfigSource::Toml,
                    secret: false,
                });
                Some(v)
            } else {
                settings.push(EffectiveSetting {
                    key,
                    env_var,
                    value: "<unset>".to_string(),
                    source: ConfigSource::Default,
                    secret: false,
                });
                None
            }
        };

        let resolve_bool = |settings: &mut Vec<EffectiveSetting>,
                            report: &mut ConfigReport,
                            key: &'static str,
                            env_var: &'static str,
                            toml_val: Option<bool>,
                            default: bool|
         -> bool {
            if let Some(raw) = env_get(env_var).filter(|s| !s.trim().is_empty()) {
                match parse_env_bool(&raw) {
                    Ok(v) => {
                        settings.push(EffectiveSetting {
                            key,
                            env_var,
                            value: v.to_string(),
                            source: ConfigSource::Env,
                            secret: false,
                        });
                        return v;
                    }
                    Err(err) => {
                        report.errors.push(format!("{env_var}: {err}"));
                        settings.push(EffectiveSetting {
                            key,
                            env_var,
                            value: raw,
                            source: ConfigSource::Env,
                            secret: false,
                        });
                        return toml_val.unwrap_or(default);
                    }
                }
            }
            if let Some(v) = toml_val {
                settings.push(EffectiveSetting {
                    key,
                    env_var,
                    value: v.to_string(),
                    source: ConfigSource::Toml,
                    secret: false,
                });
                v
            } else {
                settings.push(EffectiveSetting {
                    key,
                    env_var,
                    value: default.to_string(),
                    source: ConfigSource::Default,
                    secret: false,
                });
                default
            }
        };

        let resolve_str = |settings: &mut Vec<EffectiveSetting>,
                           key: &'static str,
                           env_var: &'static str,
                           toml_val: Option<&str>,
                           default: &str|
         -> String {
            if let Some(raw) = env_get(env_var).filter(|s| !s.trim().is_empty()) {
                settings.push(EffectiveSetting {
                    key,
                    env_var,
                    value: raw.clone(),
                    source: ConfigSource::Env,
                    secret: false,
                });
                return raw;
            }
            if let Some(v) = toml_val {
                settings.push(EffectiveSetting {
                    key,
                    env_var,
                    value: v.to_string(),
                    source: ConfigSource::Toml,
                    secret: false,
                });
                v.to_string()
            } else {
                settings.push(EffectiveSetting {
                    key,
                    env_var,
                    value: default.to_string(),
                    source: ConfigSource::Default,
                    secret: false,
                });
                default.to_string()
            }
        };

        let resolve_opt_str = |settings: &mut Vec<EffectiveSetting>,
                               key: &'static str,
                               env_var: &'static str,
                               toml_val: Option<&str>,
                               secret: bool|
         -> Option<String> {
            let fmt_val = |v: &str| -> String {
                if secret {
                    "<redacted>".to_string()
                } else {
                    v.to_string()
                }
            };
            if let Some(raw) = env_get(env_var).filter(|s| !s.trim().is_empty()) {
                settings.push(EffectiveSetting {
                    key,
                    env_var,
                    value: fmt_val(&raw),
                    source: ConfigSource::Env,
                    secret,
                });
                return Some(raw);
            }
            if let Some(v) = toml_val.filter(|s| !s.trim().is_empty()) {
                settings.push(EffectiveSetting {
                    key,
                    env_var,
                    value: fmt_val(v),
                    source: ConfigSource::Toml,
                    secret,
                });
                Some(v.to_string())
            } else {
                settings.push(EffectiveSetting {
                    key,
                    env_var,
                    value: "<unset>".to_string(),
                    source: ConfigSource::Default,
                    secret,
                });
                None
            }
        };

        // [tempo]
        let tick_ms = resolve_u64(
            &mut settings,
            &mut report,
            "tempo.tick_ms",
            "STELL_TICK_MS",
            self.tempo.tick_ms,
            DEFAULT_TICK_MS,
        );
        let min_block_ms = resolve_u64(
            &mut settings,
            &mut report,
            "tempo.min_block_ms",
            "STELL_MIN_BLOCK_MS",
            self.tempo.min_block_ms,
            DEFAULT_MIN_BLOCK_MS,
        );
        let round_timeout_ms = resolve_u64(
            &mut settings,
            &mut report,
            "tempo.round_timeout_ms",
            "STELL_ROUND_TIMEOUT_MS",
            self.tempo.round_timeout_ms,
            DEFAULT_ROUND_TIMEOUT_MS,
        );
        let _round_zero_timeout_ms = resolve_u64(
            &mut settings,
            &mut report,
            "tempo.round_zero_timeout_ms",
            "STELL_ROUND_ZERO_TIMEOUT_MS",
            self.tempo.round_zero_timeout_ms,
            DEFAULT_ROUND_ZERO_TIMEOUT_MS,
        );
        let _down_proposer_timeout_ms = resolve_u64(
            &mut settings,
            &mut report,
            "tempo.down_proposer_timeout_ms",
            "STELL_DOWN_PROPOSER_TIMEOUT_MS",
            self.tempo.down_proposer_timeout_ms,
            DEFAULT_DOWN_PROPOSER_TIMEOUT_MS,
        );
        let straggler_grace_ms = resolve_u64(
            &mut settings,
            &mut report,
            "tempo.straggler_grace_ms",
            "STELL_STRAGGLER_GRACE_MS",
            self.tempo.straggler_grace_ms,
            DEFAULT_STRAGGLER_GRACE_MS,
        );
        let straggler_grace_cap_ms = resolve_u64(
            &mut settings,
            &mut report,
            "tempo.straggler_grace_cap_ms",
            "STELL_STRAGGLER_GRACE_CAP_MS",
            self.tempo.straggler_grace_cap_ms,
            DEFAULT_STRAGGLER_GRACE_CAP_MS,
        );
        let _straggler_freshness_ms = resolve_u64(
            &mut settings,
            &mut report,
            "tempo.straggler_freshness_ms",
            "STELL_STRAGGLER_FRESHNESS_MS",
            self.tempo.straggler_freshness_ms,
            round_timeout_ms.saturating_mul(5),
        );
        let _catchup_interval_ms = resolve_u64(
            &mut settings,
            &mut report,
            "tempo.catchup_interval_ms",
            "STELL_CATCHUP_INTERVAL_MS",
            self.tempo.catchup_interval_ms,
            DEFAULT_CATCHUP_INTERVAL_MS,
        );
        let _catchup_budget_ms = resolve_u64(
            &mut settings,
            &mut report,
            "tempo.catchup_budget_ms",
            "STELL_CATCHUP_BUDGET_MS",
            self.tempo.catchup_budget_ms,
            DEFAULT_CATCHUP_BUDGET_MS,
        );
        let _retro_publish_interval_ms = resolve_u64(
            &mut settings,
            &mut report,
            "tempo.retro_publish_interval_ms",
            "STELL_RETRO_PUBLISH_INTERVAL_MS",
            self.tempo.retro_publish_interval_ms,
            DEFAULT_RETRO_PUBLISH_INTERVAL_MS,
        );
        let _retro_behind_window_secs = resolve_u64(
            &mut settings,
            &mut report,
            "tempo.retro_behind_window_secs",
            "STELL_RETRO_BEHIND_WINDOW_SECS",
            self.tempo.retro_behind_window_secs,
            DEFAULT_RETRO_BEHIND_WINDOW_SECS,
        );
        let _deadlock_timeout_secs = resolve_u64(
            &mut settings,
            &mut report,
            "tempo.deadlock_timeout_secs",
            "STELL_DEADLOCK_TIMEOUT_SECS",
            self.tempo.deadlock_timeout_secs,
            DEFAULT_DEADLOCK_TIMEOUT_SECS,
        );

        // [consensus]
        let chain_id = resolve_u64(
            &mut settings,
            &mut report,
            "consensus.chain_id",
            "STELL_CHAIN_ID",
            self.consensus.chain_id,
            crate::zkml::DEFAULT_CHAIN_ID,
        );
        let _observer = resolve_bool(
            &mut settings,
            &mut report,
            "consensus.observer",
            "STELL_OBSERVER",
            self.consensus.observer,
            false,
        );
        let _workchain_observer = resolve_bool(
            &mut settings,
            &mut report,
            "consensus.workchain_observer",
            "STELL_WORKCHAIN_OBSERVER",
            self.consensus.workchain_observer,
            false,
        );
        let _new_chain = resolve_bool(
            &mut settings,
            &mut report,
            "consensus.new_chain",
            "STELL_NEW_CHAIN",
            self.consensus.new_chain,
            false,
        );
        let _shards = resolve_str(
            &mut settings,
            "consensus.shards",
            "STELL_SHARDS",
            self.consensus.shards.as_deref(),
            DEFAULT_SHARDS,
        );
        let _experimental_shards = resolve_bool(
            &mut settings,
            &mut report,
            "consensus.experimental_shards",
            "STELL_EXPERIMENTAL_SHARDS",
            self.consensus.experimental_shards,
            false,
        );
        let pure_pq = resolve_bool(
            &mut settings,
            &mut report,
            "consensus.pure_pq",
            "STELL_PURE_PQ",
            self.consensus.pure_pq,
            true,
        );
        let _auto_upgrade = resolve_bool(
            &mut settings,
            &mut report,
            "consensus.auto_upgrade",
            "STELL_AUTO_UPGRADE",
            self.consensus.auto_upgrade,
            false,
        );
        let _wait_supermajority = resolve_opt_u64(
            &mut settings,
            &mut report,
            "consensus.wait_supermajority",
            "STELL_WAIT_SUPERMAJORITY",
            self.consensus.wait_supermajority,
        );
        let _gov_multinode = resolve_bool(
            &mut settings,
            &mut report,
            "consensus.gov_allow_multinode_writes",
            "STELL_GOV_ALLOW_MULTINODE_WRITES",
            self.consensus.gov_allow_multinode_writes,
            false,
        );

        // [storage]
        let _data_dir = resolve_str(
            &mut settings,
            "storage.data_dir",
            "STELL_DATA_DIR",
            self.storage.data_dir.as_deref(),
            DEFAULT_DATA_DIR,
        );
        let archive = resolve_bool(
            &mut settings,
            &mut report,
            "storage.archive",
            "STELL_ARCHIVE",
            self.storage.archive,
            DEFAULT_ARCHIVE,
        );
        let keep_blocks = resolve_u64(
            &mut settings,
            &mut report,
            "storage.keep_blocks",
            "STELL_KEEP_BLOCKS",
            self.storage.keep_blocks,
            DEFAULT_KEEP_BLOCKS,
        );
        let snapshot_interval = resolve_u64(
            &mut settings,
            &mut report,
            "storage.snapshot_interval",
            "STELL_SNAPSHOT_INTERVAL",
            self.storage.snapshot_interval,
            DEFAULT_SNAPSHOT_INTERVAL,
        );
        let _sled_cache = resolve_u64(
            &mut settings,
            &mut report,
            "storage.sled_cache_bytes",
            "STELL_SLED_CACHE_BYTES",
            self.storage.sled_cache_bytes,
            crate::storage::DEFAULT_SLED_CACHE_BYTES,
        );
        let _sled_flush = resolve_u64(
            &mut settings,
            &mut report,
            "storage.sled_flush_ms",
            "STELL_SLED_FLUSH_MS",
            self.storage.sled_flush_ms,
            crate::storage::DEFAULT_SLED_FLUSH_MS,
        );
        let _sled_compression = resolve_bool(
            &mut settings,
            &mut report,
            "storage.sled_compression",
            "STELL_SLED_COMPRESSION",
            self.storage.sled_compression,
            false,
        );
        let schema_downgrade_allowed = resolve_bool(
            &mut settings,
            &mut report,
            "storage.schema_downgrade_allowed",
            "STELL_ALLOW_SCHEMA_DOWNGRADE",
            self.storage.schema_downgrade_allowed,
            false,
        );
        let _vset_max_lag = resolve_u64(
            &mut settings,
            &mut report,
            "storage.validator_set_max_lag",
            "STELL_VALIDATOR_SET_MAX_LAG",
            self.storage.validator_set_max_lag,
            crate::storage::VALIDATOR_SET_FRESHNESS_DEFAULT_LAG,
        );
        let _max_cached_blocks = resolve_u64(
            &mut settings,
            &mut report,
            "storage.max_cached_blocks",
            "STELL_MAX_CACHED_BLOCKS",
            self.storage.max_cached_blocks.map(|v| v as u64),
            DEFAULT_MAX_CACHED_BLOCKS as u64,
        );
        let _max_pq_fallback = resolve_u64(
            &mut settings,
            &mut report,
            "storage.max_pq_fallback_entries",
            "STELL_MAX_PQ_FALLBACK_ENTRIES",
            self.storage.max_pq_fallback_entries.map(|v| v as u64),
            DEFAULT_MAX_PQ_FALLBACK_ENTRIES as u64,
        );
        let _max_accounts_warn = resolve_u64(
            &mut settings,
            &mut report,
            "storage.max_accounts_warn",
            "STELL_MAX_ACCOUNTS_WARN",
            self.storage.max_accounts_warn,
            DEFAULT_MAX_ACCOUNTS_WARN,
        );
        let _snapshot_chunk = resolve_u64(
            &mut settings,
            &mut report,
            "storage.snapshot_chunk_accounts",
            "STELL_SNAPSHOT_CHUNK_ACCOUNTS",
            self.storage.snapshot_chunk_accounts.map(|v| v as u64),
            DEFAULT_SNAPSHOT_CHUNK_ACCOUNTS as u64,
        );

        // [network]
        let _dns_seeds = resolve_opt_str(
            &mut settings,
            "network.dns_seeds",
            "STELL_DNS_SEEDS",
            self.network.dns_seeds.as_deref(),
            false,
        );
        let _send_timeout_ms = resolve_u64(
            &mut settings,
            &mut report,
            "network.send_timeout_ms",
            "STELL_SEND_TIMEOUT_MS",
            self.network.send_timeout_ms,
            DEFAULT_SEND_TIMEOUT_MS,
        );
        let _broadcast_join_ms = resolve_u64(
            &mut settings,
            &mut report,
            "network.broadcast_join_ms",
            "STELL_BROADCAST_JOIN_MS",
            self.network.broadcast_join_ms,
            DEFAULT_BROADCAST_JOIN_MS,
        );
        let _probe_evict = resolve_u64(
            &mut settings,
            &mut report,
            "network.probe_evict_after",
            "STELL_PROBE_EVICT_AFTER",
            self.network.probe_evict_after.map(u64::from),
            u64::from(DEFAULT_PROBE_EVICT_AFTER),
        );
        let _dial_backoff_base = resolve_u64(
            &mut settings,
            &mut report,
            "network.dial_backoff_base_ms",
            "STELL_DIAL_BACKOFF_BASE_MS",
            self.network.dial_backoff_base_ms,
            DEFAULT_DIAL_BACKOFF_BASE_MS,
        );
        let _dial_backoff_max = resolve_u64(
            &mut settings,
            &mut report,
            "network.dial_backoff_max_ms",
            "STELL_DIAL_BACKOFF_MAX_MS",
            self.network.dial_backoff_max_ms,
            DEFAULT_DIAL_BACKOFF_MAX_MS,
        );
        let _dial_budget = resolve_u64(
            &mut settings,
            &mut report,
            "network.dial_budget_per_sec",
            "STELL_DIAL_BUDGET_PER_SEC",
            self.network.dial_budget_per_sec.map(u64::from),
            u64::from(DEFAULT_DIAL_BUDGET_PER_SEC),
        );
        let _dht_keep = resolve_u64(
            &mut settings,
            &mut report,
            "network.dht_keep_blocks_default",
            "STELL_DHT_KEEP_BLOCKS_DEFAULT",
            self.network.dht_keep_blocks_default,
            DEFAULT_DHT_KEEP_BLOCKS_DEFAULT,
        );

        // [rpc]
        let rpc_listen = resolve_str(
            &mut settings,
            "rpc.rpc_listen",
            "STELL_RPC_LISTEN",
            self.rpc.rpc_listen.as_deref(),
            DEFAULT_RPC_LISTEN,
        );
        let _explorer_listen = resolve_str(
            &mut settings,
            "rpc.explorer_listen",
            "STELL_EXPLORER_LISTEN",
            self.rpc.explorer_listen.as_deref(),
            DEFAULT_EXPLORER_LISTEN,
        );
        let rpc_auth_token = resolve_opt_str(
            &mut settings,
            "rpc.auth_token",
            "STELL_RPC_AUTH_TOKEN",
            self.rpc.auth_token.as_deref(),
            true,
        );
        let _rate_limit = resolve_u64(
            &mut settings,
            &mut report,
            "rpc.rate_limit_per_sec",
            "STELL_RATE_LIMIT_PER_SEC",
            self.rpc.rate_limit_per_sec.map(u64::from),
            u64::from(crate::explorer::DEFAULT_RATE_LIMIT_PER_SEC),
        );
        let _standalone_rate = resolve_u64(
            &mut settings,
            &mut report,
            "rpc.standalone_rate_limit",
            "STELL_STANDALONE_RATE_LIMIT",
            self.rpc.standalone_rate_limit.map(u64::from),
            u64::from(crate::rpc::STANDALONE_RATE_LIMIT_DEFAULT),
        );
        let _trusted_proxies = resolve_str(
            &mut settings,
            "rpc.trusted_proxy_cidrs",
            "STELL_TRUSTED_PROXY_CIDRS",
            self.rpc.trusted_proxy_cidrs.as_deref(),
            DEFAULT_TRUSTED_PROXY_CIDRS,
        );
        let _xff_mode = resolve_str(
            &mut settings,
            "rpc.xff_mode",
            "STELL_XFF_MODE",
            self.rpc.xff_mode.as_deref(),
            DEFAULT_XFF_MODE,
        );

        // [mempool]
        let _mempool_cap = resolve_u64(
            &mut settings,
            &mut report,
            "mempool.cap",
            "STELL_MEMPOOL_CAP",
            self.mempool.cap.map(|v| v as u64),
            DEFAULT_MEMPOOL_CAP as u64,
        );
        let _mempool_per_sender = resolve_u64(
            &mut settings,
            &mut report,
            "mempool.per_sender",
            "STELL_MEMPOOL_PER_SENDER",
            self.mempool.per_sender.map(|v| v as u64),
            DEFAULT_MEMPOOL_PER_SENDER as u64,
        );

        // [faucet]
        let _faucet_enabled = resolve_bool(
            &mut settings,
            &mut report,
            "faucet.enabled",
            "STELL_FAUCET",
            self.faucet.enabled,
            false,
        );
        let _faucet_key = resolve_opt_str(
            &mut settings,
            "faucet.faucet_key",
            "STELL_FAUCET_KEY",
            self.faucet.faucet_key.as_deref(),
            true,
        );
        let _faucet_key_file = resolve_opt_str(
            &mut settings,
            "faucet.faucet_key_file",
            "STELL_FAUCET_KEY_FILE",
            self.faucet.faucet_key_file.as_deref(),
            false,
        );
        let _faucet_token = resolve_opt_str(
            &mut settings,
            "faucet.faucet_token",
            "STELL_FAUCET_TOKEN",
            self.faucet.faucet_token.as_deref(),
            true,
        );
        let faucet_drip_stell = resolve_u64(
            &mut settings,
            &mut report,
            "faucet.faucet_drip_stell",
            "STELL_FAUCET_DRIP_STELL",
            self.faucet.faucet_drip_stell,
            DEFAULT_FAUCET_DRIP_STELL,
        );
        let faucet_lifetime_cap_stell = resolve_u64(
            &mut settings,
            &mut report,
            "faucet.faucet_lifetime_cap_stell",
            "STELL_FAUCET_LIFETIME_CAP_STELL",
            self.faucet.faucet_lifetime_cap_stell,
            DEFAULT_FAUCET_LIFETIME_CAP_STELL,
        );
        let _faucet_ip_max = resolve_u64(
            &mut settings,
            &mut report,
            "faucet.faucet_ip_max_per_hour",
            "STELL_FAUCET_IP_MAX_PER_HOUR",
            self.faucet.faucet_ip_max_per_hour.map(u64::from),
            u64::from(crate::rpc::FAUCET_IP_MAX_PER_HOUR),
        );
        let _public_drip_nano = resolve_u64(
            &mut settings,
            &mut report,
            "faucet.public_drip_nano",
            "STELL_PUBLIC_DRIP_NANO",
            self.faucet.public_drip_nano,
            crate::rpc::PUBLIC_DRIP_NANO,
        );
        let _public_drip_cooldown = resolve_u64(
            &mut settings,
            &mut report,
            "faucet.public_drip_cooldown_secs",
            "STELL_PUBLIC_DRIP_COOLDOWN_SECS",
            self.faucet.public_drip_cooldown_secs,
            crate::rpc::PUBLIC_DRIP_COOLDOWN_SECS,
        );
        let ts_site = resolve_opt_str(
            &mut settings,
            "faucet.turnstile_site_key",
            "STELL_TURNSTILE_SITE_KEY",
            self.faucet.turnstile_site_key.as_deref(),
            false,
        );
        let ts_secret = resolve_opt_str(
            &mut settings,
            "faucet.turnstile_secret_key",
            "STELL_TURNSTILE_SECRET_KEY",
            self.faucet.turnstile_secret_key.as_deref(),
            true,
        );

        // [signer]
        let _falcon_key_file = resolve_str(
            &mut settings,
            "signer.falcon_key_file",
            "STELL_FALCON_KEY_FILE",
            self.signer.falcon_key_file.as_deref(),
            DEFAULT_FALCON_KEY_FILE,
        );
        let remote_signer_url = resolve_opt_str(
            &mut settings,
            "signer.remote_signer_url",
            "STELL_REMOTE_SIGNER_URL",
            self.signer.remote_signer_url.as_deref(),
            false,
        );
        let _remote_signer_token = resolve_opt_str(
            &mut settings,
            "signer.remote_signer_token",
            "STELL_REMOTE_SIGNER_TOKEN",
            self.signer.remote_signer_token.as_deref(),
            true,
        );
        let _key_plaintext = resolve_bool(
            &mut settings,
            &mut report,
            "signer.key_plaintext",
            "STELL_KEY_PLAINTEXT",
            self.signer.key_plaintext,
            false,
        );

        // [telemetry] (STELL_NO_TELEMETRY=1 inverts telemetry.enabled)
        let tel = self.telemetry_config();
        let no_telemetry = resolve_bool(
            &mut settings,
            &mut report,
            "telemetry.no_telemetry",
            NO_TELEMETRY_ENV,
            tel.enabled.map(|e| !e),
            false,
        );
        settings.push(EffectiveSetting {
            key: "telemetry.enabled",
            env_var: NO_TELEMETRY_ENV,
            value: (!no_telemetry).to_string(),
            source: settings
                .last()
                .map(|s| s.source)
                .unwrap_or(ConfigSource::Default),
            secret: false,
        });
        let _liveness_alarm = resolve_u64(
            &mut settings,
            &mut report,
            "telemetry.liveness_alarm_ms",
            "STELL_LIVENESS_ALARM_MS",
            tel.liveness_alarm_ms,
            DEFAULT_LIVENESS_ALARM_MS,
        );
        let ready_defaults = crate::explorer::ReadinessConfig::default();
        let _ready_stall = resolve_u64(
            &mut settings,
            &mut report,
            "telemetry.ready_max_stall_secs",
            "STELL_READY_MAX_STALL_SECS",
            tel.ready_max_stall_secs,
            ready_defaults.max_stall_secs,
        );
        let _ready_peers = resolve_u64(
            &mut settings,
            &mut report,
            "telemetry.ready_min_peers",
            "STELL_READY_MIN_PEERS",
            tel.ready_min_peers.map(|v| v as u64),
            ready_defaults.min_peers as u64,
        );
        let _health_cache = resolve_u64(
            &mut settings,
            &mut report,
            "telemetry.health_cache_ms",
            "STELL_HEALTH_CACHE_MS",
            tel.health_cache_ms,
            crate::explorer::DEFAULT_HEALTH_CACHE_TTL_MS,
        );

        // [execution]
        let _parallel_exec = resolve_bool(
            &mut settings,
            &mut report,
            "execution.parallel_exec",
            "STELL_PARALLEL_EXEC",
            self.execution.parallel_exec,
            false,
        );
        let _runtime_workers = resolve_opt_u64(
            &mut settings,
            &mut report,
            "execution.runtime_workers",
            "STELL_RUNTIME_WORKERS",
            self.execution.runtime_workers.map(|v| v as u64),
        );
        let _runtime_blocking = resolve_opt_u64(
            &mut settings,
            &mut report,
            "execution.runtime_max_blocking",
            "STELL_RUNTIME_MAX_BLOCKING",
            self.execution.runtime_max_blocking.map(|v| v as u64),
        );

        // ====================================================================
        // Invariant checks
        // ====================================================================
        if min_block_ms > round_timeout_ms {
            report.errors.push(format!(
                "tempo.min_block_ms ({min_block_ms}) must be <= tempo.round_timeout_ms ({round_timeout_ms})"
            ));
        }
        if !(10..=1000).contains(&tick_ms) {
            report
                .errors
                .push(format!("tempo.tick_ms ({tick_ms}) must be in 10..=1000"));
        }
        if straggler_grace_ms > 0
            && straggler_grace_cap_ms > 0
            && straggler_grace_ms > straggler_grace_cap_ms
        {
            report.errors.push(format!(
                "tempo.straggler_grace_ms ({straggler_grace_ms}) must be <= tempo.straggler_grace_cap_ms ({straggler_grace_cap_ms})"
            ));
        }
        if !archive && keep_blocks == 0 {
            report
                .errors
                .push("storage.keep_blocks must be > 0 when storage.archive is false".to_string());
        }
        if faucet_drip_stell > faucet_lifetime_cap_stell {
            report.errors.push(format!(
                "faucet.faucet_drip_stell ({faucet_drip_stell}) must be <= faucet.faucet_lifetime_cap_stell ({faucet_lifetime_cap_stell})"
            ));
        }
        if chain_id == 0 {
            report
                .errors
                .push("consensus.chain_id must be > 0".to_string());
        }
        if !is_loopback_listen(&rpc_listen) && rpc_auth_token.is_none() {
            report.warnings.push(format!(
                "rpc.rpc_listen ({rpc_listen}) is non-loopback without STELL_RPC_AUTH_TOKEN set; write/admin RPC methods are exposed without token protection"
            ));
        }
        if schema_downgrade_allowed {
            report.warnings.push(
                "storage.schema_downgrade_allowed (STELL_ALLOW_SCHEMA_DOWNGRADE) is true: downgrading across schema versions may misread newer keys".to_string(),
            );
        }
        if !pure_pq {
            report.warnings.push(
                "consensus.pure_pq=false is ignored: FULL-PQ mode is always enforced".to_string(),
            );
        }
        if snapshot_interval < 50 {
            report.warnings.push(format!(
                "storage.snapshot_interval ({snapshot_interval}) is below the minimum 50 and will be clamped to 50"
            ));
        }
        if ts_site.is_some() ^ ts_secret.is_some() {
            report.warnings.push(
                "Turnstile captcha is misconfigured: only one of STELL_TURNSTILE_SITE_KEY / STELL_TURNSTILE_SECRET_KEY is set (public faucet will fail closed with 503)".to_string(),
            );
        }
        if let Some(url) = &remote_signer_url {
            if !url.starts_with("http://") && !url.starts_with("https://") {
                report.errors.push(format!(
                    "signer.remote_signer_url ('{url}') must start with http:// or https://"
                ));
            }
        }

        ResolvedConfig { settings, report }
    }
}

// ============================================================================
// Self-contained strict TOML -> serde_json::Value parser (zero external crate)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
struct TomlParseError {
    line: usize,
    msg: String,
}

impl std::fmt::Display for TomlParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TOML parse error at line {}: {}", self.line, self.msg)
    }
}

struct TomlParser<'a> {
    src: &'a [u8],
    pos: usize,
    line: usize,
}

impl<'a> TomlParser<'a> {
    fn new(input: &'a str) -> Self {
        let stripped = input.strip_prefix('\u{FEFF}').unwrap_or(input);
        Self {
            src: stripped.as_bytes(),
            pos: 0,
            line: 1,
        }
    }

    fn err(&self, msg: impl Into<String>) -> TomlParseError {
        TomlParseError {
            line: self.line,
            msg: msg.into(),
        }
    }

    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn peek_n(&self, n: usize) -> Option<&'a [u8]> {
        self.src.get(self.pos..self.pos + n)
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        if b == b'\n' {
            self.line += 1;
        }
        Some(b)
    }

    fn skip_inline_ws(&mut self) {
        while let Some(b) = self.peek() {
            if b == b' ' || b == b'\t' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn skip_ws_and_comments(&mut self) {
        loop {
            match self.peek() {
                Some(b' ' | b'\t' | b'\r') => {
                    self.pos += 1;
                }
                Some(b'\n') => {
                    self.pos += 1;
                    self.line += 1;
                }
                Some(b'#') => {
                    while let Some(b) = self.bump() {
                        if b == b'\n' {
                            break;
                        }
                    }
                }
                _ => break,
            }
        }
    }

    fn expect_line_end(&mut self) -> Result<(), TomlParseError> {
        self.skip_inline_ws();
        match self.peek() {
            None => Ok(()),
            Some(b'\n') => {
                self.bump();
                Ok(())
            }
            Some(b'\r') => {
                self.bump();
                if self.peek() == Some(b'\n') {
                    self.bump();
                }
                Ok(())
            }
            Some(b'#') => {
                while let Some(b) = self.bump() {
                    if b == b'\n' {
                        break;
                    }
                }
                Ok(())
            }
            Some(c) => Err(self.err(format!("unexpected trailing character '{}'", c as char))),
        }
    }

    fn parse_bare_key(&mut self) -> Result<String, TomlParseError> {
        let start = self.pos;
        while let Some(b) = self.peek() {
            if b.is_ascii_alphanumeric() || b == b'_' || b == b'-' {
                self.pos += 1;
            } else {
                break;
            }
        }
        if self.pos == start {
            return Err(self.err("expected key"));
        }
        Ok(std::str::from_utf8(&self.src[start..self.pos])
            .map_err(|_| self.err("invalid UTF-8 in key"))?
            .to_string())
    }

    fn parse_key_part(&mut self) -> Result<String, TomlParseError> {
        self.skip_inline_ws();
        match self.peek() {
            Some(b'"') => self.parse_basic_string(),
            Some(b'\'') => self.parse_literal_string(),
            _ => self.parse_bare_key(),
        }
    }

    fn parse_dotted_key(&mut self) -> Result<Vec<String>, TomlParseError> {
        let mut parts = vec![self.parse_key_part()?];
        loop {
            self.skip_inline_ws();
            if self.peek() == Some(b'.') {
                self.pos += 1;
                parts.push(self.parse_key_part()?);
            } else {
                break;
            }
        }
        Ok(parts)
    }

    fn parse_basic_string(&mut self) -> Result<String, TomlParseError> {
        if self.peek_n(3) == Some(b"\"\"\"") {
            self.pos += 3;
            if self.peek() == Some(b'\r') {
                self.pos += 1;
            }
            if self.peek() == Some(b'\n') {
                self.bump();
            }
            return self.parse_basic_string_body(true);
        }
        self.bump(); // opening "
        self.parse_basic_string_body(false)
    }

    fn parse_basic_string_body(&mut self, multiline: bool) -> Result<String, TomlParseError> {
        let mut out = String::new();
        loop {
            if multiline && self.peek_n(3) == Some(b"\"\"\"") {
                self.pos += 3;
                return Ok(out);
            }
            let Some(b) = self.bump() else {
                return Err(self.err("unterminated string"));
            };
            if !multiline && b == b'"' {
                return Ok(out);
            }
            if !multiline && (b == b'\n' || b == b'\r') {
                return Err(self.err("newline inside single-line string"));
            }
            if b == b'\\' {
                let Some(esc) = self.bump() else {
                    return Err(self.err("unterminated escape"));
                };
                match esc {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'b' => out.push('\u{0008}'),
                    b'f' => out.push('\u{000C}'),
                    b'u' => out.push(self.parse_unicode_escape(4)?),
                    b'U' => out.push(self.parse_unicode_escape(8)?),
                    b'\n' | b'\r' | b' ' | b'\t' if multiline => {
                        if esc == b'\r' && self.peek() == Some(b'\n') {
                            self.bump();
                        }
                        while let Some(c) = self.peek() {
                            if matches!(c, b' ' | b'\t' | b'\r' | b'\n') {
                                self.bump();
                            } else {
                                break;
                            }
                        }
                    }
                    other => {
                        return Err(self.err(format!("invalid escape '\\{}'", other as char)));
                    }
                }
            } else if b < 0x80 {
                out.push(b as char);
            } else {
                // Multi-byte UTF-8 sequence starting at pos - 1
                let start = self.pos - 1;
                let width = if b & 0b1110_0000 == 0b1100_0000 {
                    2
                } else if b & 0b1111_0000 == 0b1110_0000 {
                    3
                } else if b & 0b1111_1000 == 0b1111_0000 {
                    4
                } else {
                    return Err(self.err("invalid UTF-8 byte in string"));
                };
                for _ in 1..width {
                    if self.bump().is_none() {
                        return Err(self.err("truncated UTF-8 sequence"));
                    }
                }
                let s = std::str::from_utf8(&self.src[start..self.pos])
                    .map_err(|_| self.err("invalid UTF-8 in string"))?;
                out.push_str(s);
            }
        }
    }

    fn parse_unicode_escape(&mut self, digits: usize) -> Result<char, TomlParseError> {
        let mut hex = String::with_capacity(digits);
        for _ in 0..digits {
            let Some(b) = self.bump() else {
                return Err(self.err("truncated unicode escape"));
            };
            hex.push(b as char);
        }
        let code = u32::from_str_radix(&hex, 16)
            .map_err(|_| self.err(format!("invalid unicode escape '{hex}'")))?;
        char::from_u32(code).ok_or_else(|| self.err("invalid unicode scalar"))
    }

    fn parse_literal_string(&mut self) -> Result<String, TomlParseError> {
        if self.peek_n(3) == Some(b"'''") {
            self.pos += 3;
            if self.peek() == Some(b'\r') {
                self.pos += 1;
            }
            if self.peek() == Some(b'\n') {
                self.bump();
            }
            let start = self.pos;
            while self.pos < self.src.len() {
                if self.peek_n(3) == Some(b"'''") {
                    let s = std::str::from_utf8(&self.src[start..self.pos])
                        .map_err(|_| self.err("invalid UTF-8 in literal string"))?
                        .to_string();
                    self.pos += 3;
                    return Ok(s);
                }
                self.bump();
            }
            return Err(self.err("unterminated multiline literal string"));
        }
        self.bump(); // opening '
        let start = self.pos;
        while let Some(b) = self.bump() {
            if b == b'\'' {
                return Ok(std::str::from_utf8(&self.src[start..self.pos - 1])
                    .map_err(|_| self.err("invalid UTF-8 in literal string"))?
                    .to_string());
            }
            if b == b'\n' || b == b'\r' {
                return Err(self.err("newline inside single-line literal string"));
            }
        }
        Err(self.err("unterminated literal string"))
    }

    fn parse_value(&mut self) -> Result<Value, TomlParseError> {
        self.skip_inline_ws();
        match self.peek() {
            Some(b'"') => Ok(Value::String(self.parse_basic_string()?)),
            Some(b'\'') => Ok(Value::String(self.parse_literal_string()?)),
            Some(b'[') => self.parse_array(),
            Some(b'{') => self.parse_inline_table(),
            Some(_) => self.parse_primitive(),
            None => Err(self.err("expected value")),
        }
    }

    fn parse_array(&mut self) -> Result<Value, TomlParseError> {
        self.bump(); // '['
        let mut items = Vec::new();
        loop {
            self.skip_ws_and_comments();
            if self.peek() == Some(b']') {
                self.bump();
                return Ok(Value::Array(items));
            }
            items.push(self.parse_value()?);
            self.skip_ws_and_comments();
            match self.peek() {
                Some(b',') => {
                    self.bump();
                }
                Some(b']') => {
                    self.bump();
                    return Ok(Value::Array(items));
                }
                Some(c) => {
                    return Err(self.err(format!(
                        "expected ',' or ']' in array, found '{}'",
                        c as char
                    )));
                }
                None => return Err(self.err("unterminated array")),
            }
        }
    }

    fn parse_inline_table(&mut self) -> Result<Value, TomlParseError> {
        self.bump(); // '{'
        let mut map = Map::new();
        let mut seen = HashSet::new();
        self.skip_inline_ws();
        if self.peek() == Some(b'}') {
            self.bump();
            return Ok(Value::Object(map));
        }
        loop {
            let key_parts = self.parse_dotted_key()?;
            self.skip_inline_ws();
            if self.bump() != Some(b'=') {
                return Err(self.err("expected '=' in inline table"));
            }
            let val = self.parse_value()?;
            insert_dotted_key(&mut map, &mut seen, &key_parts, val, self.line)?;
            self.skip_inline_ws();
            match self.bump() {
                Some(b',') => {
                    self.skip_inline_ws();
                }
                Some(b'}') => return Ok(Value::Object(map)),
                _ => return Err(self.err("expected ',' or '}' in inline table")),
            }
        }
    }

    fn parse_primitive(&mut self) -> Result<Value, TomlParseError> {
        let start = self.pos;
        while let Some(b) = self.peek() {
            if matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b'#' | b',' | b']' | b'}') {
                break;
            }
            self.pos += 1;
        }
        if self.pos == start {
            return Err(self.err("expected value"));
        }
        let token = std::str::from_utf8(&self.src[start..self.pos])
            .map_err(|_| self.err("invalid UTF-8 in value"))?;
        match token {
            "true" => return Ok(Value::Bool(true)),
            "false" => return Ok(Value::Bool(false)),
            _ => {}
        }
        if let Some(hex) = token.strip_prefix("0x") {
            let clean = strip_toml_underscores(hex, 16)
                .ok_or_else(|| self.err(format!("invalid hex integer '{token}'")))?;
            let n = u64::from_str_radix(&clean, 16)
                .map_err(|_| self.err(format!("invalid hex integer '{token}'")))?;
            return Ok(Value::Number(Number::from(n)));
        }
        if let Some(oct) = token.strip_prefix("0o") {
            let clean = strip_toml_underscores(oct, 8)
                .ok_or_else(|| self.err(format!("invalid octal integer '{token}'")))?;
            let n = u64::from_str_radix(&clean, 8)
                .map_err(|_| self.err(format!("invalid octal integer '{token}'")))?;
            return Ok(Value::Number(Number::from(n)));
        }
        if let Some(bin) = token.strip_prefix("0b") {
            let clean = strip_toml_underscores(bin, 2)
                .ok_or_else(|| self.err(format!("invalid binary integer '{token}'")))?;
            let n = u64::from_str_radix(&clean, 2)
                .map_err(|_| self.err(format!("invalid binary integer '{token}'")))?;
            return Ok(Value::Number(Number::from(n)));
        }
        if token.contains('.') || token.contains('e') || token.contains('E') {
            let clean = token.replace('_', "");
            let f: f64 = clean
                .parse()
                .map_err(|_| self.err(format!("invalid float '{token}'")))?;
            let num = Number::from_f64(f)
                .ok_or_else(|| self.err(format!("non-finite float '{token}'")))?;
            return Ok(Value::Number(num));
        }
        let (sign, digits) = if let Some(rest) = token.strip_prefix('+') {
            (false, rest)
        } else if let Some(rest) = token.strip_prefix('-') {
            (true, rest)
        } else {
            (false, token)
        };
        let clean = strip_toml_underscores(digits, 10)
            .ok_or_else(|| self.err(format!("invalid value '{token}' (strings must be quoted)")))?;
        if sign {
            let signed_str = format!("-{clean}");
            let n: i64 = signed_str
                .parse()
                .map_err(|_| self.err(format!("integer out of range '{token}'")))?;
            Ok(Value::Number(Number::from(n)))
        } else {
            let n: u64 = clean
                .parse()
                .map_err(|_| self.err(format!("integer out of range '{token}'")))?;
            Ok(Value::Number(Number::from(n)))
        }
    }
}

fn strip_toml_underscores(s: &str, radix: u32) -> Option<String> {
    if s.is_empty() || s.starts_with('_') || s.ends_with('_') || s.contains("__") {
        return None;
    }
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch == '_' {
            continue;
        }
        if !ch.is_digit(radix) {
            return None;
        }
        out.push(ch);
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn insert_dotted_key(
    root: &mut Map<String, Value>,
    seen_keys: &mut HashSet<String>,
    parts: &[String],
    val: Value,
    line: usize,
) -> Result<(), TomlParseError> {
    let full = parts.join(".");
    if !seen_keys.insert(full.clone()) {
        return Err(TomlParseError {
            line,
            msg: format!("duplicate key '{full}'"),
        });
    }
    let mut cur = root;
    for part in &parts[..parts.len() - 1] {
        let entry = cur
            .entry(part.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        cur = match entry {
            Value::Object(m) => m,
            _ => {
                return Err(TomlParseError {
                    line,
                    msg: format!("key '{part}' conflicts with non-table value"),
                });
            }
        };
    }
    let leaf = parts.last().unwrap().clone();
    if cur.contains_key(&leaf) {
        return Err(TomlParseError {
            line,
            msg: format!("duplicate key '{full}'"),
        });
    }
    cur.insert(leaf, val);
    Ok(())
}

fn parse_toml_to_json(input: &str) -> Result<Value, TomlParseError> {
    let mut p = TomlParser::new(input);
    let mut root = Map::new();
    let mut current_table: Vec<String> = Vec::new();
    let mut defined_tables: HashSet<Vec<String>> = HashSet::new();
    let mut seen_keys: HashSet<String> = HashSet::new();

    loop {
        p.skip_ws_and_comments();
        let Some(b) = p.peek() else {
            break;
        };
        if b == b'[' {
            p.bump();
            if p.peek() == Some(b'[') {
                return Err(p.err("array-of-tables [[...]] is not supported"));
            }
            let table_parts = p.parse_dotted_key()?;
            p.skip_inline_ws();
            if p.bump() != Some(b']') {
                return Err(p.err("expected ']' after table header"));
            }
            p.expect_line_end()?;
            if !defined_tables.insert(table_parts.clone()) {
                return Err(p.err(format!("duplicate table [{}]", table_parts.join("."))));
            }
            // Ensure the table exists in `root` even if it has zero keys.
            let mut cur = &mut root;
            for part in &table_parts {
                let entry = cur
                    .entry(part.clone())
                    .or_insert_with(|| Value::Object(Map::new()));
                cur = match entry {
                    Value::Object(m) => m,
                    _ => {
                        return Err(p.err(format!(
                            "table [{}] conflicts with non-table value",
                            table_parts.join(".")
                        )));
                    }
                };
            }
            current_table = table_parts;
            continue;
        }

        let key_parts = p.parse_dotted_key()?;
        p.skip_inline_ws();
        if p.bump() != Some(b'=') {
            return Err(p.err("expected '=' after key"));
        }
        let val = p.parse_value()?;
        let line = p.line;
        p.expect_line_end()?;

        let mut full_path = current_table.clone();
        full_path.extend(key_parts);
        insert_dotted_key(&mut root, &mut seen_keys, &full_path, val, line)?;
    }

    Ok(Value::Object(root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    static ENV_TEST_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }

    impl EnvGuard {
        fn new(keys: &[&'static str]) -> Self {
            let saved = keys
                .iter()
                .map(|&k| (k, std::env::var_os(k)))
                .collect::<Vec<_>>();
            for &k in keys {
                std::env::remove_var(k);
            }
            Self { saved }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (k, v) in self.saved.drain(..) {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    #[test]
    fn toml_parses_all_sections_and_comments() {
        let toml = r#"
# Top-level comment
[tempo]
tick_ms = 50
min_block_ms = 50
round_timeout_ms = 3_000
straggler_grace_ms = 500
straggler_grace_cap_ms = 10_000

[consensus]
chain_id = 5757
observer = false
shards = "0"

[storage]
data_dir = "./data"
archive = false
keep_blocks = 8_000
schema_downgrade_allowed = false

[network]
send_timeout_ms = 2500

[rpc]
rpc_listen = "127.0.0.1:8545"
explorer_listen = "127.0.0.1:8080"
rate_limit_per_sec = 60

[mempool]
cap = 50_000
per_sender = 1024

[faucet]
enabled = false
faucet_drip_stell = 5
faucet_lifetime_cap_stell = 50

[signer]
falcon_key_file = "./keys/falcon.key"

[telemetry]
enabled = false
liveness_alarm_ms = 300_000

[execution]
parallel_exec = true
runtime_workers = 4
"#;
        let cfg = NodeTomlConfig::from_toml_str(toml).expect("valid TOML must parse");
        assert_eq!(cfg.tempo.tick_ms, Some(50));
        assert_eq!(cfg.tempo.round_timeout_ms, Some(3000));
        assert_eq!(cfg.storage.archive, Some(false));
        assert_eq!(cfg.storage.keep_blocks, Some(8000));
        assert_eq!(cfg.faucet.faucet_drip_stell, Some(5));
        assert_eq!(cfg.telemetry_config().enabled, Some(false));
        assert_eq!(cfg.execution.parallel_exec, Some(true));
        let rep = cfg.validate_with_env(|_| None);
        assert!(rep.is_ok(), "unexpected errors: {:?}", rep.errors);
        assert!(
            rep.warnings.is_empty(),
            "unexpected warnings: {:?}",
            rep.warnings
        );
    }

    #[test]
    fn toml_supports_top_level_telemetry_flag() {
        let cfg = NodeTomlConfig::from_toml_str("telemetry = false\n").expect("flag must parse");
        assert_eq!(cfg.telemetry_config().enabled, Some(false));
        assert!(cfg.validate_with_env(|_| None).is_ok());
    }

    #[test]
    fn toml_rejects_unknown_section_and_unknown_field() {
        let bad_section = "[bogus_section]\nfoo = 1\n";
        let err = NodeTomlConfig::from_toml_str(bad_section).unwrap_err();
        assert!(
            err.to_string().contains("unknown field"),
            "must reject unknown section: {err}"
        );

        let bad_field = "[tempo]\ntck_ms = 50\n";
        let err = NodeTomlConfig::from_toml_str(bad_field).unwrap_err();
        assert!(
            err.to_string().contains("unknown field"),
            "must reject unknown field: {err}"
        );
    }

    #[test]
    fn toml_rejects_duplicate_keys_and_syntax_errors() {
        assert!(NodeTomlConfig::from_toml_str("[tempo]\ntick_ms = 50\ntick_ms = 60\n").is_err());
        assert!(NodeTomlConfig::from_toml_str("[tempo\ntick_ms = 50\n").is_err());
        assert!(NodeTomlConfig::from_toml_str("[tempo]\ntick_ms = unquoted\n").is_err());
    }

    #[test]
    fn env_always_overrides_toml_in_apply_defaults() {
        let _lock = ENV_TEST_LOCK.lock().unwrap();
        let _guard = EnvGuard::new(&[
            "STELL_TICK_MS",
            "STELL_MIN_BLOCK_MS",
            "STELL_NO_TELEMETRY",
            "STELL_ARCHIVE",
        ]);
        // Pre-set STELL_TICK_MS in env; TOML must NOT overwrite it.
        std::env::set_var("STELL_TICK_MS", "100");
        let cfg = NodeTomlConfig::from_toml_str(
            r#"
telemetry = false
[tempo]
tick_ms = 40
min_block_ms = 60
[storage]
archive = false
"#,
        )
        .unwrap();

        let applied = cfg.apply_defaults_to_env();
        assert_eq!(std::env::var("STELL_TICK_MS").unwrap(), "100");
        assert!(!applied.contains(&"STELL_TICK_MS"));
        assert_eq!(std::env::var("STELL_MIN_BLOCK_MS").unwrap(), "60");
        assert_eq!(std::env::var("STELL_NO_TELEMETRY").unwrap(), "1");
        assert_eq!(std::env::var("STELL_ARCHIVE").unwrap(), "0");
        assert!(applied.contains(&"STELL_MIN_BLOCK_MS"));
        assert!(applied.contains(&"STELL_NO_TELEMETRY"));
        assert!(applied.contains(&"STELL_ARCHIVE"));
    }

    #[test]
    fn validation_catches_errors_and_warnings() {
        let bad = NodeTomlConfig::from_toml_str(
            r#"
[tempo]
tick_ms = 5
min_block_ms = 4000
round_timeout_ms = 3000
straggler_grace_ms = 2000
straggler_grace_cap_ms = 1000
[storage]
archive = false
keep_blocks = 0
schema_downgrade_allowed = true
[faucet]
faucet_drip_stell = 100
faucet_lifetime_cap_stell = 50
[rpc]
rpc_listen = "0.0.0.0:8545"
"#,
        )
        .unwrap();

        let rep = bad.validate_with_env(|_| None);
        assert!(!rep.is_ok());
        assert!(rep.errors.iter().any(|e| e.contains("min_block_ms")));
        assert!(rep.errors.iter().any(|e| e.contains("tick_ms")));
        assert!(rep.errors.iter().any(|e| e.contains("straggler_grace_ms")));
        assert!(rep.errors.iter().any(|e| e.contains("keep_blocks")));
        assert!(rep.errors.iter().any(|e| e.contains("faucet_drip_stell")));
        assert!(rep
            .warnings
            .iter()
            .any(|w| w.contains("STELL_RPC_AUTH_TOKEN")));
        assert!(rep
            .warnings
            .iter()
            .any(|w| w.contains("schema_downgrade_allowed")));

        // Setting STELL_RPC_AUTH_TOKEN in env silences the non-loopback warning.
        let mut env = HashMap::new();
        env.insert("STELL_RPC_AUTH_TOKEN", "supersecret".to_string());
        let resolved = bad.resolve_effective_with_env(|k| env.get(k).cloned());
        assert!(
            !resolved
                .report
                .warnings
                .iter()
                .any(|w| w.contains("STELL_RPC_AUTH_TOKEN")),
            "auth token in env must clear the warning"
        );
        let auth_entry = resolved
            .settings
            .iter()
            .find(|s| s.env_var == "STELL_RPC_AUTH_TOKEN")
            .unwrap();
        assert_eq!(auth_entry.source, ConfigSource::Env);
        assert_eq!(auth_entry.value, "<redacted>");
    }

    #[test]
    fn tick_ms_upper_bound_checked() {
        let bad = NodeTomlConfig::from_toml_str("[tempo]\ntick_ms = 1001\n").unwrap();
        let rep = bad.validate_with_env(|_| None);
        assert!(!rep.is_ok());
        assert!(rep.errors.iter().any(|e| e.contains("10..=1000")));

        let ok = NodeTomlConfig::from_toml_str("[tempo]\ntick_ms = 10\n").unwrap();
        assert!(ok.validate_with_env(|_| None).is_ok());
    }

    #[test]
    fn discover_toml_path_errors_when_explicit_or_env_missing() {
        let missing = Path::new("/tmp/definitely_missing_stellereum_test_12345.toml");
        assert!(discover_toml_path_with_env(Some(missing), None, missing).is_err());
        assert!(
            discover_toml_path_with_env(None, Some(missing.to_str().unwrap()), missing).is_err()
        );
        assert_eq!(
            discover_toml_path_with_env(None, None, missing).unwrap(),
            TomlPathSource::None
        );
    }
}
