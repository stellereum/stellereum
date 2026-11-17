//! Argument parsing for the load harness.
//!
//! No clap: the option surface is small and every flag is security-relevant, so
//! the parser is explicit and testable. Unknown flags are fatal rather than
//! silently ignored.

use crate::txgen::{PqMode, Recipient};

#[derive(Debug, Clone)]
pub struct Config {
    pub urls: Vec<String>,
    pub watch_urls: Vec<String>,
    pub metrics_url: Option<String>,
    pub rate: f64,
    pub duration: f64,
    pub senders: usize,
    pub amount: u64,
    pub gas_limit: u64,
    pub gas_margin: u64,
    pub recipient: Recipient,
    pub chain_id: u64,
    pub shard: u32,
    pub pq_mode: PqMode,
    pub allow_live: bool,
    pub allow_remote: bool,
    pub operator_order: bool,
    pub force_dry_run: bool,
    pub seed: String,
    pub max_inflight: usize,
    pub inflight_per_sender: u64,
    pub retry_max: u32,
    pub retry_base_ms: u64,
    pub timeout_ms: u64,
    pub poll_ms: u64,
    pub nonce_poll_ms: u64,
    pub drain_timeout: f64,
    pub drain_poll_ms: u64,
    pub stall_seconds: u64,
    pub max_lag_blocks: u64,
    pub read_rate: f64,
    pub funds_check: bool,
    pub preflight_rps: f64,
    pub receipt_sample: usize,
    pub fail_ratio: f64,
    pub backlog_stop_size: u64,
    pub backlog_stop_secs: u64,
    pub json_out: Option<String>,
    pub print_senders: bool,
    pub preflight_only: bool,
    pub quiet: bool,
    pub dry_run_count: usize,
    pub dry_run_base_fee: u64,
    pub help: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            urls: Vec::new(),
            watch_urls: Vec::new(),
            metrics_url: None,
            rate: 10.0,
            duration: 60.0,
            senders: 16,
            amount: 1,
            gas_limit: 0,
            gas_margin: 1_000,
            recipient: Recipient::SelfAddress,
            chain_id: 0,
            shard: 0,
            pq_mode: PqMode::Auto,
            allow_live: false,
            allow_remote: false,
            operator_order: false,
            force_dry_run: false,
            seed: "stellereum-loadtest-v1".to_string(),
            max_inflight: 0,
            inflight_per_sender: 4,
            retry_max: 6,
            retry_base_ms: 100,
            timeout_ms: 5_000,
            poll_ms: 200,
            nonce_poll_ms: 250,
            drain_timeout: 120.0,
            drain_poll_ms: 1_000,
            stall_seconds: 30,
            max_lag_blocks: 500,
            read_rate: 200.0,
            funds_check: true,
            preflight_rps: 50.0,
            receipt_sample: 32,
            fail_ratio: 0.01,
            backlog_stop_size: 0,
            backlog_stop_secs: 10,
            json_out: None,
            print_senders: false,
            preflight_only: false,
            quiet: false,
            dry_run_count: 8,
            dry_run_base_fee: 280_000,
            help: false,
        }
    }
}

/// Parse `--flag value` / `--flag=value` / bare boolean flags.
pub fn parse(args: Vec<String>) -> Result<Config, String> {
    let mut cfg = Config::default();
    let mut i = 0usize;
    while i < args.len() {
        let raw = &args[i];
        if raw == "-h" || raw == "--help" {
            cfg.help = true;
            i += 1;
            continue;
        }
        if !raw.starts_with("--") {
            return Err(format!(
                "unexpected argument {raw:?} (options start with --)"
            ));
        }
        let (key, inline) = match raw.split_once('=') {
            Some((k, v)) => (k, Some(v.to_string())),
            None => (raw.as_str(), None),
        };
        let mut take_value = |name: &str| -> Result<String, String> {
            if let Some(v) = inline.clone() {
                return Ok(v);
            }
            i += 1;
            args.get(i)
                .cloned()
                .ok_or_else(|| format!("{name} requires a value"))
        };
        match key {
            "--url" => cfg.urls.push(take_value("--url")?),
            "--watch-url" => cfg.watch_urls.push(take_value("--watch-url")?),
            "--metrics-url" => cfg.metrics_url = Some(take_value("--metrics-url")?),
            "--rate" => cfg.rate = parse_f64("--rate", &take_value("--rate")?)?,
            "--duration" => cfg.duration = parse_f64("--duration", &take_value("--duration")?)?,
            "--senders" => cfg.senders = parse_usize("--senders", &take_value("--senders")?)?,
            "--amount" => cfg.amount = parse_u64("--amount", &take_value("--amount")?)?,
            "--gas-limit" => cfg.gas_limit = parse_u64("--gas-limit", &take_value("--gas-limit")?)?,
            "--gas-margin" => {
                cfg.gas_margin = parse_u64("--gas-margin", &take_value("--gas-margin")?)?
            }
            "--recipient" => {
                cfg.recipient = Recipient::parse(&take_value("--recipient")?)?;
            }
            "--chain-id" => cfg.chain_id = parse_u64("--chain-id", &take_value("--chain-id")?)?,
            "--shard" => cfg.shard = parse_u32("--shard", &take_value("--shard")?)?,
            "--pq-mode" => cfg.pq_mode = PqMode::parse(&take_value("--pq-mode")?)?,
            "--seed" => cfg.seed = take_value("--seed")?,
            "--max-inflight" => {
                cfg.max_inflight = parse_usize("--max-inflight", &take_value("--max-inflight")?)?
            }
            "--inflight-per-sender" => {
                cfg.inflight_per_sender = parse_u64(
                    "--inflight-per-sender",
                    &take_value("--inflight-per-sender")?,
                )?
            }
            "--retry-max" => cfg.retry_max = parse_u32("--retry-max", &take_value("--retry-max")?)?,
            "--retry-base-ms" => {
                cfg.retry_base_ms = parse_u64("--retry-base-ms", &take_value("--retry-base-ms")?)?
            }
            "--timeout-ms" => {
                cfg.timeout_ms = parse_u64("--timeout-ms", &take_value("--timeout-ms")?)?
            }
            "--poll-ms" => cfg.poll_ms = parse_u64("--poll-ms", &take_value("--poll-ms")?)?,
            "--nonce-poll-ms" => {
                cfg.nonce_poll_ms = parse_u64("--nonce-poll-ms", &take_value("--nonce-poll-ms")?)?
            }
            "--drain-timeout" => {
                cfg.drain_timeout = parse_f64("--drain-timeout", &take_value("--drain-timeout")?)?
            }
            "--drain-poll-ms" => {
                cfg.drain_poll_ms = parse_u64("--drain-poll-ms", &take_value("--drain-poll-ms")?)?
            }
            "--stall-seconds" => {
                cfg.stall_seconds = parse_u64("--stall-seconds", &take_value("--stall-seconds")?)?
            }
            "--max-lag-blocks" => {
                cfg.max_lag_blocks =
                    parse_u64("--max-lag-blocks", &take_value("--max-lag-blocks")?)?
            }
            "--read-rate" => cfg.read_rate = parse_f64("--read-rate", &take_value("--read-rate")?)?,
            "--preflight-rps" => {
                cfg.preflight_rps = parse_f64("--preflight-rps", &take_value("--preflight-rps")?)?
            }
            "--receipt-sample" => {
                cfg.receipt_sample =
                    parse_usize("--receipt-sample", &take_value("--receipt-sample")?)?
            }
            "--fail-ratio" => {
                cfg.fail_ratio = parse_f64("--fail-ratio", &take_value("--fail-ratio")?)?
            }
            "--backlog-stop-size" => {
                cfg.backlog_stop_size =
                    parse_u64("--backlog-stop-size", &take_value("--backlog-stop-size")?)?
            }
            "--backlog-stop-secs" => {
                cfg.backlog_stop_secs =
                    parse_u64("--backlog-stop-secs", &take_value("--backlog-stop-secs")?)?
            }
            "--json-out" => cfg.json_out = Some(take_value("--json-out")?),
            "--dry-run-count" => {
                cfg.dry_run_count = parse_usize("--dry-run-count", &take_value("--dry-run-count")?)?
            }
            "--dry-run-base-fee" => {
                cfg.dry_run_base_fee =
                    parse_u64("--dry-run-base-fee", &take_value("--dry-run-base-fee")?)?
            }
            "--allow-live" => cfg.allow_live = parse_bool_flag(key, inline.as_deref())?,
            "--allow-remote" => cfg.allow_remote = parse_bool_flag(key, inline.as_deref())?,
            "--operator-order" => cfg.operator_order = parse_bool_flag(key, inline.as_deref())?,
            "--dry-run" => cfg.force_dry_run = parse_bool_flag(key, inline.as_deref())?,
            "--funds-check" => cfg.funds_check = parse_bool_flag(key, inline.as_deref())?,
            "--print-senders" => cfg.print_senders = parse_bool_flag(key, inline.as_deref())?,
            "--preflight-only" => cfg.preflight_only = parse_bool_flag(key, inline.as_deref())?,
            "--quiet" => cfg.quiet = parse_bool_flag(key, inline.as_deref())?,
            other => return Err(format!("unknown option {other:?} (see --help)")),
        }
        i += 1;
    }

    if cfg.urls.is_empty() {
        cfg.urls.push("http://127.0.0.1:8545".to_string());
    }
    if cfg.watch_urls.is_empty() {
        cfg.watch_urls = cfg.urls.clone();
    }
    validate(&cfg)?;
    Ok(cfg)
}

fn validate(cfg: &Config) -> Result<(), String> {
    if !cfg.rate.is_finite() || cfg.rate <= 0.0 {
        return Err("--rate must be a positive finite number".to_string());
    }
    if !cfg.duration.is_finite() || cfg.duration <= 0.0 {
        return Err("--duration must be a positive finite number of seconds".to_string());
    }
    if cfg.senders == 0 || cfg.senders > 4_096 {
        return Err("--senders must be between 1 and 4096".to_string());
    }
    if cfg.inflight_per_sender == 0 || cfg.inflight_per_sender > 4 {
        return Err(
            "--inflight-per-sender must be 1..=4 (the node's NONCE_FUTURE_WINDOW is 4; \
             a larger value would be rejected as a nonce gap)"
                .to_string(),
        );
    }
    if cfg.timeout_ms < 50 || cfg.timeout_ms > 120_000 {
        return Err("--timeout-ms must be 50..=120000".to_string());
    }
    if cfg.poll_ms < 20 || cfg.poll_ms > 10_000 {
        return Err("--poll-ms must be 20..=10000".to_string());
    }
    if cfg.drain_timeout < 0.0 || !cfg.drain_timeout.is_finite() {
        return Err("--drain-timeout must be a non-negative number".to_string());
    }
    if cfg.drain_poll_ms < 100 {
        return Err("--drain-poll-ms must be >= 100".to_string());
    }
    if !cfg.read_rate.is_finite() || cfg.read_rate <= 0.0 {
        return Err("--read-rate must be a positive finite number".to_string());
    }
    if !cfg.preflight_rps.is_finite() || cfg.preflight_rps <= 0.0 {
        return Err("--preflight-rps must be a positive finite number".to_string());
    }
    if cfg.fail_ratio < 0.0 || cfg.fail_ratio > 1.0 || !cfg.fail_ratio.is_finite() {
        return Err("--fail-ratio must be 0.0..=1.0".to_string());
    }
    if cfg.retry_max == 0 {
        return Err("--retry-max must be >= 1".to_string());
    }
    if cfg.seed.is_empty() {
        return Err("--seed must not be empty".to_string());
    }
    if cfg.dry_run_count == 0 {
        return Err("--dry-run-count must be >= 1".to_string());
    }
    if cfg.allow_live && cfg.force_dry_run {
        return Err("--allow-live and --dry-run are mutually exclusive".to_string());
    }
    if cfg.operator_order && !cfg.allow_live {
        return Err("--operator-order is only meaningful with --allow-live".to_string());
    }
    if (cfg.print_senders || cfg.preflight_only) && !cfg.allow_live {
        return Err(
            "--print-senders/--preflight-only read the node; pass --allow-live".to_string(),
        );
    }
    if let Some(ref p) = cfg.json_out {
        if p.trim().is_empty() {
            return Err("--json-out must not be empty".to_string());
        }
    }
    Ok(())
}

fn parse_bool_flag(name: &str, inline: Option<&str>) -> Result<bool, String> {
    match inline {
        None => Ok(true),
        Some("true" | "1" | "yes") => Ok(true),
        Some("false" | "0" | "no") => Ok(false),
        Some(v) => Err(format!("{name} expects true/false, got {v:?}")),
    }
}

fn parse_u64(name: &str, raw: &str) -> Result<u64, String> {
    let raw = raw.trim().replace('_', "");
    if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|e| format!("{name}: bad hex integer {raw:?}: {e}"))
    } else {
        raw.parse::<u64>()
            .map_err(|e| format!("{name}: bad integer {raw:?}: {e}"))
    }
}

fn parse_u32(name: &str, raw: &str) -> Result<u32, String> {
    let v = parse_u64(name, raw)?;
    u32::try_from(v).map_err(|_| format!("{name}: {v} does not fit in u32"))
}

fn parse_usize(name: &str, raw: &str) -> Result<usize, String> {
    let v = parse_u64(name, raw)?;
    usize::try_from(v).map_err(|_| format!("{name}: {v} does not fit in usize"))
}

fn parse_f64(name: &str, raw: &str) -> Result<f64, String> {
    let raw = raw.trim();
    let v: f64 = raw
        .parse()
        .map_err(|e| format!("{name}: bad number {raw:?}: {e}"))?;
    if !v.is_finite() {
        return Err(format!("{name}: number must be finite"));
    }
    Ok(v)
}

pub fn help() -> &'static str {
    r#"stell-loadtest -- dry-run-first load harness for Stellereum JSON-RPC

SAFETY
  The harness never sends a transaction unless --allow-live is present.
  Known live-cluster hosts additionally require --operator-order.
  Non-loopback endpoints additionally require --allow-remote.

MODE
  --dry-run                 Force the local self-test (default when --allow-live is absent)
  --allow-live              Permit sending stell_sendRawTransaction
  --allow-remote            Permit a non-loopback endpoint
  --operator-order           Acknowledge an operator order for a blocked live host
  --preflight-only          Read chain id/base fee/sender balances, send nothing, exit
  --print-senders           Print every deterministic sender address and balance

LOAD
  --url <URL>               Submit endpoint; repeatable, senders are load-balanced (default 127.0.0.1:8545)
  --watch-url <URL>         Height-lag watcher; repeatable (default: --url values)
  --rate <tx/s>             Target accepted submissions per second (default 10)
  --duration <seconds>      Sending window (default 60)
  --senders <n>             Sender keypairs / threads (default 16)
  --inflight-per-sender <n> Outstanding nonces per sender, max 4 (default 4)
  --max-inflight <n>        Global concurrent requests, 0 = senders (default 0)
  --amount <n>              Transfer amount per tx (default 1)
  --gas-limit <n>           Fixed gas_limit; 0 = auto from stell_baseFee (default 0)
  --gas-margin <n>          Extra gas above base fee + surcharge when auto (default 1000)
  --recipient <hex|self|sink>  Default self (self-transfer: only the fee leaves the sender)
  --chain-id <n>            Expected chain id; 0 = read stell_chainId (default 0)
  --shard <n>               Source/target shard id (default 0)
  --pq-mode <auto|explicit|implicit>  auto = explicit activation then implicit (default auto)
  --seed <text>             Deterministic sender seed (default stellereum-loadtest-v1)

TIMING / RETRIES
  --retry-max <n>           Retries for one signed tx, always the SAME bytes (default 6)
  --retry-base-ms <n>       Exponential backoff base (default 100)
  --timeout-ms <n>          HTTP timeout (default 5000)
  --poll-ms <n>             Block-height poll interval (default 200)
  --nonce-poll-ms <n>       Minimum spacing for on-chain nonce reads (default 250)
  --drain-timeout <seconds> Wait for accepted txs to be included (default 120)
  --drain-poll-ms <n>       Drain poll interval (default 1000)
  --stall-seconds <n>       Abort sending if no new block for n seconds; 0 disables (default 30)
  --max-lag-blocks <n>      Abort if watch endpoints differ by more than n; 0 disables (default 500)
  --read-rate <rps>         Cap on auxiliary reads (nonce/status), not submissions (default 200)
  --preflight-rps <rps>     Balance-read rate before the run (default 50)
  --backlog-stop-size <n>   Abort if mempool exceeds n for --backlog-stop-secs; 0 disables
  --backlog-stop-secs <n>   Sustained backlog window (default 10)

REPORT
  --receipt-sample <n>      Last-tx receipt status samples at the end (default 32)
  --fail-ratio <r>          FAIL verdict above this rejected share (default 0.01)
  --json-out <path>         Also write a machine-readable summary
  --metrics-url <URL>       Optional Prometheus endpoint for the node's own block-interval histogram
  --quiet                   Suppress progress lines and the dry-run wire dump

SELF-TEST
  --dry-run-count <n>       Transactions built/signed/serialized in the local batch (default 8)
  --dry-run-base-fee <n>    Base fee assumed by the local self-test (default 280000)
  -h, --help                This text
"#
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Config, String> {
        parse(args.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn defaults_are_dry_run_and_loopback() {
        let c = p(&[]).unwrap();
        assert!(!c.allow_live);
        assert_eq!(c.urls, vec!["http://127.0.0.1:8545".to_string()]);
        assert_eq!(c.watch_urls, c.urls);
    }

    #[test]
    fn repeated_urls_are_preserved() {
        let c = p(&["--url", "http://127.0.0.1:1", "--url=http://127.0.0.1:2"]).unwrap();
        assert_eq!(c.urls.len(), 2);
        assert_eq!(c.urls[1], "http://127.0.0.1:2");
    }

    #[test]
    fn contradictory_mode_is_refused() {
        assert!(p(&["--allow-live", "--dry-run"]).is_err());
        assert!(p(&["--operator-order"]).is_err());
    }

    #[test]
    fn inflight_window_is_capped_at_node_limit() {
        assert!(p(&["--inflight-per-sender", "5"]).is_err());
        assert!(p(&["--inflight-per-sender", "4"]).is_ok());
    }

    #[test]
    fn unknown_flags_fail_closed() {
        assert!(p(&["--allow-everything"]).is_err());
    }

    #[test]
    fn booleans_accept_only_explicit_values() {
        assert!(p(&["--allow-live=false"]).is_ok());
        assert!(p(&["--allow-live=maybe"]).is_err());
    }

    #[test]
    fn recipient_sink_and_hex_parse() {
        assert!(p(&["--recipient", "sink"]).is_ok());
        assert!(p(&["--recipient", "self"]).is_ok());
        assert!(p(&["--recipient", "0xdeadbeef"]).is_err());
        assert!(p(&["--recipient", &format!("0x{}", "11".repeat(32))]).is_ok());
    }
}
