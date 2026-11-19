//! `stell-loadtest` -- dry-run-first load harness for the Stellereum JSON-RPC.
//!
//! See `scripts/loadtest/README.md` and `docs/LOADTEST_RUNBOOK.md`.
//!
//! The load path is deliberately simple and conservative:
//!
//! * one OS thread per sender, so a sender's nonces are strictly ordered and
//!   only one signed byte string per nonce is ever in flight;
//! * at most `NONCE_FUTURE_WINDOW` (4) accepted-but-not-executed nonces per
//!   sender, mirroring `Mempool::NONCE_FUTURE_WINDOW`;
//! * transport retries resend the CACHED BYTES for the same nonce, never a
//!   freshly signed transaction, so a retry is idempotent;
//! * a global token bucket enforces the requested tx/s, and a global
//!   semaphore bounds concurrent HTTP requests;
//! * automatic `PQ_ACTIVATION_SURCHARGE_GAS` accounting for explicit envelopes
//!   and a `stell_baseFee`-derived gas limit, mirroring mempool admission.

mod cli;
mod rpc;
mod safety;
mod stats;
mod txgen;

// The node tree is currently mid-refactor: `post_quantum.rs` removed the
// classical scheme variants while `wallet.rs`/`wallet_signing.rs` still refer
// to them, so `stellereum` cannot be used as a path dependency right now.
// These two files are self-contained and are included VERBATIM, so Falcon-512
// signing, address derivation and the PQ1 envelope are still the node's own
// implementation, not a second one.
//
// GATE: allow(warnings) only because these are external node sources included
// without edits; their lints are the node's responsibility.
#[allow(warnings, clippy::all)]
#[path = "../../../../stellereum/src/sharding/envelope.rs"]
mod envelope;
#[allow(warnings, clippy::all)]
#[path = "../../../../stellereum/src/post_quantum.rs"]
mod post_quantum;
// `envelope.rs` pins the chain id against these two modules at compile time.
#[allow(dead_code)]
mod evm_adapter {
    pub const CHAIN_ID: u64 = 5757;
}
#[allow(dead_code)]
mod zkml {
    pub const DEFAULT_CHAIN_ID: u64 = 5757;
}
mod wire;

use cli::Config;
use rpc::{parse_balance, parse_chain_id, parse_hex_u64, parse_u64_any, RpcClient, RpcError};
use serde_json::{json, Value};
use stats::{
    build_report, BlockObs, Inflight, RateGate, ReceiptSample, RunMeta, SenderOutcome, Stats,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use txgen::{
    auto_gas_limit, build_signed_tx, envelope_facts, gas_floor, generate_senders, master_seed,
    signing_message, verify_explicit, verify_implicit, PqMode, SenderSpec, TxSpec,
};
use wire::{decode_wire, encode_wire, tx_hash_hex, wire_hex, PQ_ACTIVATION_SURCHARGE_GAS};

const DEFAULT_DRY_RUN_CHAIN_ID: u64 = 5757;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match run(args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            2
        }
    };
    std::process::exit(code);
}

fn run(args: Vec<String>) -> Result<i32, String> {
    let cfg = cli::parse(args)?;
    if cfg.help {
        print!("{}", cli::help());
        return Ok(0);
    }
    let live = cfg.allow_live && !cfg.force_dry_run;
    if live {
        live_run(&cfg)
    } else {
        dry_run(&cfg)
    }
}

// ============================================================================
// Dry run: keygen -> build -> sign -> serialize -> decode -> verify
// ============================================================================

fn dry_run(cfg: &Config) -> Result<i32, String> {
    let started = Instant::now();
    let master = master_seed(&cfg.seed);
    let senders = generate_senders(&master, cfg.senders);
    let chain_id = if cfg.chain_id == 0 {
        DEFAULT_DRY_RUN_CHAIN_ID
    } else {
        cfg.chain_id
    };
    let base_fee = cfg.dry_run_base_fee;
    let first_mode = match cfg.pq_mode {
        PqMode::Implicit => PqMode::Implicit,
        _ => PqMode::Explicit,
    };
    let first_gas = if cfg.gas_limit > 0 {
        cfg.gas_limit
    } else {
        auto_gas_limit(base_fee, first_mode, cfg.gas_margin)
    };
    let to = cfg.recipient.resolve(&senders[0].address);
    let first_nonce = 7u64;
    let first_spec = TxSpec {
        to,
        amount: cfg.amount,
        gas_limit: first_gas,
        nonce: first_nonce,
        source_shard: cfg.shard,
        target_shard: cfg.shard,
        chain_id,
    };

    let tx = build_signed_tx(&senders[0], &first_spec, first_mode);
    let message = signing_message(&senders[0], &first_spec);
    let wire = encode_wire(&tx)?;
    let decoded = decode_wire(&wire)?;
    let facts = envelope_facts(&tx)?;
    let hash = tx_hash_hex(&tx);
    let signature_ok = match first_mode {
        PqMode::Explicit => verify_explicit(&tx),
        PqMode::Implicit => verify_implicit(&tx, &senders[0])?,
        PqMode::Auto => false,
    };
    let roundtrip_hash = tx_hash_hex(&decoded);
    if !signature_ok {
        return Err("dry-run self-test: the produced signature did not verify".to_string());
    }
    if roundtrip_hash != hash {
        return Err(format!(
            "dry-run self-test: wire roundtrip changed the tx hash ({hash} != {roundtrip_hash})"
        ));
    }
    if decoded.from != senders[0].address || decoded.nonce != first_nonce {
        return Err("dry-run self-test: wire roundtrip changed sender or nonce".to_string());
    }
    if facts.chain_id != Some(chain_id) {
        return Err("dry-run self-test: chain binding missing from the envelope".to_string());
    }

    println!("=== Stellereum load harness: DRY RUN (no network) ===");
    println!(
        "senders: {} (deterministic from --seed {:?})",
        senders.len(),
        cfg.seed
    );
    println!("chain_id: {chain_id}   base_fee assumed: {base_fee}");
    println!(
        "pq mode: {}   first tx mode: {}   amount: {}   shard: {}",
        cfg.pq_mode.label(),
        match first_mode {
            PqMode::Explicit => "explicit",
            PqMode::Implicit => "implicit",
            PqMode::Auto => "auto",
        },
        cfg.amount,
        cfg.shard
    );
    println!("recipient: 0x{}", hex::encode(to));
    println!("first sender: {}", senders[0].address_hex());
    for s in senders.iter().take(8) {
        println!("  sender[{:>3}] {}", s.index, s.address_hex());
    }
    if senders.len() > 8 {
        println!(
            "  ... {} more (live preflight prints all)",
            senders.len() - 8
        );
    }
    println!();
    println!("first transaction:");
    println!("  from:             {}", senders[0].address_hex());
    println!("  to:               0x{}", hex::encode(first_spec.to));
    println!("  nonce:            {}", first_spec.nonce);
    println!("  amount:           {}", first_spec.amount);
    println!("  gas_limit:        {}", first_spec.gas_limit);
    println!(
        "  source/target:    {}/{}",
        first_spec.source_shard, first_spec.target_shard
    );
    println!("  chain_id:         {chain_id} (signed + envelope-bound)");
    println!(
        "  envelope:         {} {} (pubkey={}B, signature={}B, total={}B)",
        facts.scheme,
        if facts.is_implicit {
            "implicit"
        } else {
            "explicit"
        },
        facts.pubkey_len,
        facts.signature_len,
        facts.encoded_len
    );
    println!("  signing message:  {} bytes", message.len());
    println!(
        "  signing digest:   {}",
        hex::encode(blake3::hash(&message).as_bytes())
    );
    println!("  wire bytes:       {} bytes", wire.len());
    println!("  tx hash:          {hash}");
    println!("  signature:        OK");
    println!("  wire roundtrip:   OK (node decoder + re-encoded hash match)");
    if !cfg.quiet {
        println!("  wire hex:         {}", wire_hex(&wire));
    } else {
        println!("  wire hex:         suppressed by --quiet");
    }

    // The next nonce exercises the steady-state implicit path. On a node this
    // key is in the registry after the explicit activation above.
    let second_mode = match cfg.pq_mode {
        PqMode::Explicit => PqMode::Explicit,
        _ => PqMode::Implicit,
    };
    let second_gas = if cfg.gas_limit > 0 {
        cfg.gas_limit
    } else {
        auto_gas_limit(base_fee, second_mode, cfg.gas_margin)
    };
    let second_spec = TxSpec {
        nonce: first_nonce + 1,
        gas_limit: second_gas,
        ..first_spec
    };
    let second = build_signed_tx(&senders[0], &second_spec, second_mode);
    let second_ok = match second_mode {
        PqMode::Explicit => verify_explicit(&second),
        PqMode::Implicit => verify_implicit(&second, &senders[0])?,
        PqMode::Auto => false,
    };
    let second_facts = envelope_facts(&second)?;
    if !second_ok {
        return Err("dry-run self-test: the steady-state envelope did not verify".to_string());
    }
    println!();
    println!(
        "steady-state tx (nonce {}): {} envelope, {} bytes, signature OK",
        second_spec.nonce,
        if second_facts.is_implicit {
            "implicit"
        } else {
            "explicit"
        },
        second_facts.encoded_len
    );

    // Batch construction: contiguously increasing nonces and globally unique
    // hashes prove the per-sender nonce assignment cannot collide.
    let mut hashes = std::collections::BTreeSet::new();
    let mut built = 0usize;
    let rounds = cfg.dry_run_count.div_ceil(senders.len());
    for round in 0..rounds {
        for sender in &senders {
            if built >= cfg.dry_run_count {
                break;
            }
            let spec = TxSpec {
                nonce: 1_000 + round as u64,
                gas_limit: if cfg.gas_limit > 0 {
                    cfg.gas_limit
                } else {
                    auto_gas_limit(base_fee, PqMode::Explicit, cfg.gas_margin)
                },
                ..first_spec
            };
            let tx = build_signed_tx(sender, &spec, PqMode::Explicit);
            if !verify_explicit(&tx) {
                return Err(format!(
                    "dry-run self-test: batch signature {} did not verify",
                    sender.index
                ));
            }
            let h = tx.compute_tx_hash();
            if !hashes.insert(h) {
                return Err("dry-run self-test: duplicate tx hash in the batch".to_string());
            }
            let w = encode_wire(&tx)?;
            let d = decode_wire(&w)?;
            if d.compute_tx_hash() != h {
                return Err("dry-run self-test: batch wire roundtrip changed the hash".to_string());
            }
            built += 1;
        }
    }
    println!(
        "batch: {built}/{built} unique hashes, contiguous per-sender nonces, signatures + wire roundtrip OK"
    );
    println!();
    println!(
        "DRY RUN OK in {:.2}s. No RPC endpoint was contacted. \
         Add --allow-live (and --operator-order for the live cluster) to send.",
        started.elapsed().as_secs_f64()
    );
    Ok(0)
}

// ============================================================================
// Live run
// ============================================================================

#[derive(Debug, Clone)]
struct PreflightSender {
    index: u64,
    address: String,
    init_nonce: u64,
    balance: u64,
}

fn live_run(cfg: &Config) -> Result<i32, String> {
    // ---- safety gate (before any network I/O) ----
    let (audit, warnings) = safety::gate_live(&cfg.urls, cfg.allow_remote, cfg.operator_order)?;
    for w in &warnings {
        eprintln!("WARNING: {w}");
    }
    let watch_audit = safety::audit(&cfg.watch_urls);
    if watch_audit.touches_live_cluster() && !cfg.operator_order {
        return Err(format!(
            "refusing to contact LIVE cluster watch host(s) {:?} without --operator-order",
            watch_audit.live_hosts
        ));
    }
    if watch_audit.has_remote() && !cfg.allow_remote {
        return Err(format!(
            "refusing non-loopback watch endpoint(s) {:?} without --allow-remote",
            watch_audit.remote_hosts
        ));
    }
    if let Some(metrics) = &cfg.metrics_url {
        let a = safety::audit(std::slice::from_ref(metrics));
        if a.touches_live_cluster() && !cfg.operator_order {
            return Err(format!(
                "refusing to contact LIVE cluster metrics host(s) {:?} without --operator-order",
                a.live_hosts
            ));
        }
        if a.has_remote() && !cfg.allow_remote {
            return Err(format!(
                "refusing non-loopback metrics endpoint(s) {:?} without --allow-remote",
                a.remote_hosts
            ));
        }
    }
    if !audit.touches_live_cluster() && !audit.has_remote() {
        eprintln!("safety: loopback endpoint(s) only");
    }
    if cfg.rate > 250.0 {
        eprintln!(
            "WARNING: target {:.0} tx/s is above the node's default standalone RPC budget (300/s per IP). \
             The operator must raise STELL_STANDALONE_RATE_LIMIT on the target node for a Wave-2 run.",
            cfg.rate
        );
    }

    let started_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // ---- deterministic keys (before preflight: addresses are needed) ----
    let master = master_seed(&cfg.seed);
    let senders = generate_senders(&master, cfg.senders);
    let clients: Vec<RpcClient> = cfg
        .urls
        .iter()
        .map(|u| RpcClient::new(u, cfg.timeout_ms))
        .collect();

    // ---- chain facts ----
    let primary = &clients[0];
    let chain_id = parse_chain_id(&primary.call_retry("stell_chainId", json!([]), 4, 250)?)
        .ok_or_else(|| "stell_chainId returned a non-integer".to_string())?;
    if cfg.chain_id != 0 && cfg.chain_id != chain_id {
        return Err(format!(
            "configured --chain-id {} does not match the node's stell_chainId {}",
            cfg.chain_id, chain_id
        ));
    }
    let eth_chain = parse_chain_id(&primary.call_retry("eth_chainId", json!([]), 4, 250)?)
        .ok_or_else(|| "eth_chainId returned a non-integer".to_string())?;
    if eth_chain != chain_id {
        return Err(format!(
            "node chain id disagreement: stell_chainId={chain_id} eth_chainId={eth_chain}"
        ));
    }
    let base_fee = read_base_fee(primary)?;
    let initial_height = read_height(primary)?;
    let validator_count = primary
        .call_retry("stell_getValidators", json!([]), 3, 200)
        .ok()
        .and_then(|v| {
            v.get("validators")
                .and_then(Value::as_array)
                .map(|a| a.len())
        })
        .unwrap_or(0);
    let mempool_start = read_mempool(primary).unwrap_or(0);

    let initial_mode = match cfg.pq_mode {
        PqMode::Implicit => PqMode::Implicit,
        _ => PqMode::Explicit,
    };
    let gas_explicit = gas_limit_for(cfg, base_fee, PqMode::Explicit);
    let gas_implicit = gas_limit_for(cfg, base_fee, PqMode::Implicit);
    if let Some(floor) = fixed_gas_error(cfg, base_fee, initial_mode) {
        return Err(floor);
    }

    // ---- sender preflight: nonces + funding ----
    let mut pre = Vec::with_capacity(senders.len());
    let pre_start = Instant::now();
    for (i, sender) in senders.iter().enumerate() {
        let client = &clients[i % clients.len()];
        let (balance, nonce) = read_balance(client, &sender.address_hex())
            .map_err(|e| format!("preflight balance for {}: {e}", sender.address_hex()))?;
        pre.push(PreflightSender {
            index: sender.index,
            address: sender.address_hex(),
            init_nonce: nonce,
            balance,
        });
        let due = pre_start + Duration::from_secs_f64((i + 1) as f64 / cfg.preflight_rps.max(0.1));
        let now = Instant::now();
        if due > now {
            std::thread::sleep(due - now);
        }
    }

    let needed_gas = gas_limit_for(cfg, base_fee, initial_mode);
    let needed =
        cfg.amount
            .saturating_add(needed_gas)
            .saturating_add(if initial_mode == PqMode::Explicit {
                PQ_ACTIVATION_SURCHARGE_GAS
            } else {
                0
            });
    let unfunded: Vec<&PreflightSender> = pre.iter().filter(|p| p.balance < needed).collect();

    println!("=== Stellereum load harness: LIVE PLAN ===");
    println!("endpoints:     {}", cfg.urls.join(", "));
    println!("watch:         {}", cfg.watch_urls.join(", "));
    println!("chain_id:      {chain_id} (stell + eth agree)   validators: {validator_count}");
    println!("height:        {initial_height}   mempool: {mempool_start}");
    println!(
        "base_fee:      {base_fee} gas   explicit gas: {gas_explicit}   implicit gas: {gas_implicit}"
    );
    println!(
        "senders:       {}   initial nonce sum: {}   initial mode: {}",
        senders.len(),
        pre.iter().map(|p| p.init_nonce).sum::<u64>(),
        initial_mode.label()
    );
    println!(
        "target:        {:.2} tx/s for {:.1}s  (~{} unique txs)",
        cfg.rate,
        cfg.duration,
        (cfg.rate * cfg.duration).round() as u64
    );
    println!(
        "funding:       each sender needs >= {needed} (amount {} + gas {} + activation surcharge)",
        cfg.amount, needed_gas
    );
    println!(
        "estimated gas: explicit gas_limit {gas_explicit}, implicit gas_limit {gas_implicit}; \
         activation adds the 45,000 surcharge on top at execution"
    );

    let total_balance: u128 = pre.iter().map(|p| p.balance as u128).sum();
    let est_txs = (cfg.rate * cfg.duration).round().max(0.0) as u128;
    let per_tx_gas: u128 = match cfg.pq_mode {
        PqMode::Explicit => (gas_explicit + PQ_ACTIVATION_SURCHARGE_GAS) as u128,
        _ => gas_implicit as u128,
    };
    let activation_extra: u128 = if cfg.pq_mode == PqMode::Auto {
        (pre.len() as u128).saturating_mul(
            ((gas_explicit + PQ_ACTIVATION_SURCHARGE_GAS) as u128)
                .saturating_sub(gas_implicit as u128),
        )
    } else {
        0
    };
    let value_cost: u128 = if matches!(cfg.recipient, txgen::Recipient::SelfAddress) {
        0
    } else {
        est_txs.saturating_mul(cfg.amount as u128)
    };
    let estimated_wave_cost = est_txs
        .saturating_mul(per_tx_gas)
        .saturating_add(activation_extra)
        .saturating_add(value_cost);
    println!(
        "wave budget:   ~{} gas estimated; aggregate sender balance {} ({})",
        estimated_wave_cost,
        total_balance,
        if total_balance >= estimated_wave_cost {
            "sufficient"
        } else {
            "SHORT: top up before the wave"
        }
    );
    if total_balance < estimated_wave_cost {
        eprintln!(
            "WARNING: aggregate balance {} is below the estimated wave cost {}; \
             the wave will run out of funds before the window ends",
            total_balance, estimated_wave_cost
        );
    }

    if !unfunded.is_empty() {
        println!();
        println!(
            "REFUSING TO START: {} of {} senders are below the per-tx balance requirement {needed}.",
            unfunded.len(),
            pre.len()
        );
        for p in unfunded.iter().take(50) {
            println!(
                "  sender[{:>3}] {} balance={} required={}",
                p.index, p.address, p.balance, needed
            );
        }
        if unfunded.len() > 50 {
            println!("  ... {} more", unfunded.len() - 50);
        }
        println!(
            "Fund these deterministic addresses from a testnet faucet/treasury, then rerun. \
             This harness never funds accounts itself."
        );
        return Ok(3);
    }

    if cfg.print_senders || cfg.preflight_only {
        println!();
        for p in &pre {
            println!(
                "sender[{:>3}] {} nonce={} balance={}",
                p.index, p.address, p.init_nonce, p.balance
            );
        }
        println!(
            "\npreflight only: no transaction sent. {} senders ready.",
            pre.len()
        );
        return Ok(0);
    }

    // ---- run ----
    println!();
    println!(
        "starting in 1s; Ctrl-C stops new submissions (accepted txs may already be in the pool)"
    );
    std::thread::sleep(Duration::from_secs(1));

    let run_start = Instant::now();
    let deadline = run_start + Duration::from_secs_f64(cfg.duration);
    let stop = Arc::new(AtomicBool::new(false));
    let poller_stop = Arc::new(AtomicBool::new(false));
    let initial_nonce_sum = pre.iter().map(|p| p.init_nonce).sum::<u64>();
    let stats = Arc::new(Stats::new(initial_height, initial_nonce_sum, base_fee));
    let send_gate = Arc::new(RateGate::new(cfg.rate, 1.0));
    let read_gate = Arc::new(RateGate::new(cfg.read_rate, 4.0));
    let max_inflight = if cfg.max_inflight == 0 {
        cfg.senders
    } else {
        cfg.max_inflight
    };
    let inflight = Arc::new(Inflight::new(max_inflight));

    let poller = {
        let cfg = cfg.clone();
        let stats = Arc::clone(&stats);
        let stop = Arc::clone(&stop);
        let poller_stop = Arc::clone(&poller_stop);
        std::thread::spawn(move || {
            poll_loop(
                &cfg,
                &stats,
                &stop,
                &poller_stop,
                run_start,
                initial_height,
                mempool_start,
            )
        })
    };

    let mut handles = Vec::with_capacity(senders.len());
    for (sender, p) in senders.into_iter().zip(pre.iter()) {
        let endpoint = cfg.urls[(sender.index as usize) % cfg.urls.len()].clone();
        let cfg = cfg.clone();
        let gate = Arc::clone(&send_gate);
        let read = Arc::clone(&read_gate);
        let inflight = Arc::clone(&inflight);
        let stop = Arc::clone(&stop);
        let stats = Arc::clone(&stats);
        let init_nonce = p.init_nonce;
        handles.push(std::thread::spawn(move || {
            sender_loop(
                sender, init_nonce, endpoint, chain_id, cfg, gate, read, inflight, stop, stats,
                deadline,
            )
        }));
    }

    let mut outcomes: Vec<SenderOutcome> = Vec::with_capacity(handles.len());
    for h in handles {
        match h.join() {
            Ok(o) => outcomes.push(o),
            Err(_) => {
                stats.record_error_message("sender thread panicked (see stderr)");
                stats.aborted.store(true, Ordering::SeqCst);
                stop.store(true, Ordering::SeqCst);
            }
        }
    }
    outcomes.sort_by_key(|o| o.index);
    let send_end = run_start.elapsed();
    stats.send_end_ns.store(
        send_end.as_nanos().min(u64::MAX as u128) as u64,
        Ordering::SeqCst,
    );

    // ---- drain: wait until accepted nonces are executed or the timeout hits ----
    drain(cfg, &clients, &mut outcomes, &read_gate, &stop, &stats);

    // ---- receipt sample: status of the last accepted tx per sampled sender ----
    let receipts = sample_receipts(cfg, &clients, &outcomes, &read_gate, &stats);

    poller_stop.store(true, Ordering::SeqCst);
    if poller.join().is_err() {
        eprintln!("warning: block poller thread panicked");
    }

    let final_height = stats.final_height.load(Ordering::SeqCst);
    let metrics_block_interval = cfg.metrics_url.as_ref().and_then(|url| {
        let client = RpcClient::new(&cfg.urls[0], cfg.timeout_ms);
        match client.get_text(url) {
            Ok(text) => parse_metrics_block_interval(&text),
            Err(e) => {
                eprintln!("warning: --metrics-url scrape failed: {e}");
                None
            }
        }
    });
    let meta = RunMeta {
        live: true,
        endpoints: cfg.urls.clone(),
        watch_urls: cfg.watch_urls.clone(),
        chain_id,
        senders: cfg.senders,
        target_rate: cfg.rate,
        requested_duration: cfg.duration,
        actual_duration: send_end.as_secs_f64(),
        initial_height,
        final_height,
        base_fee,
        pq_mode: cfg.pq_mode.label().to_string(),
        validator_count,
        stall_seconds: cfg.stall_seconds,
        max_lag_blocks: cfg.max_lag_blocks,
        started_unix,
        metrics_block_interval,
    };
    let report = build_report(&meta, &stats, &outcomes, &receipts, cfg.fail_ratio);
    print!("{}", report.text);
    if let Some(path) = &cfg.json_out {
        match serde_json::to_string_pretty(&report.json) {
            Ok(s) => {
                if let Err(e) = std::fs::write(path, s) {
                    eprintln!("warning: could not write --json-out {path}: {e}");
                }
            }
            Err(e) => eprintln!("warning: could not serialize report: {e}"),
        }
    }
    Ok(report.exit_code)
}

fn gas_limit_for(cfg: &Config, base_fee: u64, mode: PqMode) -> u64 {
    if cfg.gas_limit > 0 {
        cfg.gas_limit
    } else {
        auto_gas_limit(base_fee, mode, cfg.gas_margin)
    }
}

fn fixed_gas_error(cfg: &Config, base_fee: u64, mode: PqMode) -> Option<String> {
    if cfg.gas_limit == 0 {
        return None;
    }
    let floor = gas_floor(base_fee, mode);
    if cfg.gas_limit < floor {
        Some(format!(
            "--gas-limit {} is below the node's admission floor {} \
             (base_fee {} + {} surcharge for mode {}); use --gas-limit 0 for auto",
            cfg.gas_limit,
            floor,
            base_fee,
            if mode == PqMode::Explicit {
                PQ_ACTIVATION_SURCHARGE_GAS
            } else {
                0
            },
            mode.label()
        ))
    } else {
        None
    }
}

fn read_height(client: &RpcClient) -> Result<u64, RpcError> {
    let v = client.call_retry("stell_blockNumber", json!([]), 4, 200)?;
    parse_hex_u64(&v)
        .ok_or_else(|| RpcError::Shape("stell_blockNumber is not a hex quantity".to_string()))
}

fn read_base_fee(client: &RpcClient) -> Result<u64, String> {
    let v = client
        .call_retry("stell_baseFee", json!([]), 4, 200)
        .map_err(|e| format!("stell_baseFee: {e}"))?;
    v.get("base_fee")
        .and_then(parse_u64_any)
        .ok_or_else(|| format!("stell_baseFee: missing base_fee in {v}"))
}

fn read_mempool(client: &RpcClient) -> Result<u64, RpcError> {
    let v = client.call_retry("stell_mempoolSize", json!([]), 2, 100)?;
    parse_u64_any(&v)
        .ok_or_else(|| RpcError::Shape("stell_mempoolSize is not an integer".to_string()))
}

fn read_balance(client: &RpcClient, address: &str) -> Result<(u64, u64), RpcError> {
    let v = client.call_retry("stell_getBalance", json!({ "address": address }), 4, 200)?;
    parse_balance(&v)
        .ok_or_else(|| RpcError::Shape(format!("stell_getBalance shape for {address}: {v}")))
}

fn read_nonce(client: &RpcClient, address: &str) -> Result<u64, RpcError> {
    let (_, nonce) = read_balance(client, address)?;
    Ok(nonce)
}

/// Parse the node's own `stell_block_interval_seconds` histogram into
/// `(mean seconds, sample count)`. The exposition is the node's Prometheus
/// text, not JSON-RPC; this is the optional `--metrics-url` cross-check.
fn parse_metrics_block_interval(text: &str) -> Option<(f64, u64)> {
    let mut sum: Option<f64> = None;
    let mut count: Option<u64> = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("stell_block_interval_seconds_sum") {
            if !rest.starts_with('{') {
                sum = rest.trim().parse::<f64>().ok();
            }
        } else if let Some(rest) = line.strip_prefix("stell_block_interval_seconds_count") {
            if !rest.starts_with('{') {
                count = rest.trim().parse::<u64>().ok();
            }
        }
    }
    match (sum, count) {
        (Some(s), Some(c)) if c > 0 && s.is_finite() => Some((s / c as f64, c)),
        _ => None,
    }
}

// ============================================================================
// Sender loop
// ============================================================================

#[allow(clippy::too_many_arguments)]
// GATE: the sender needs the full immutable config plus the shared run handles;
// bundling them into a struct would only hide the ownership boundaries.
fn sender_loop(
    sender: SenderSpec,
    init_nonce: u64,
    endpoint: String,
    chain_id: u64,
    cfg: Config,
    gate: Arc<RateGate>,
    read_gate: Arc<RateGate>,
    inflight: Arc<Inflight>,
    stop: Arc<AtomicBool>,
    stats: Arc<Stats>,
    deadline: Instant,
) -> SenderOutcome {
    let client = RpcClient::new(&endpoint, cfg.timeout_ms);
    let address = sender.address_hex();
    let to = cfg.recipient.resolve(&sender.address);
    let mut nonce = init_nonce;
    let mut onchain = init_nonce;
    let mut accepted = 0u64;
    let mut failed = 0u64;
    let mut retries = 0u64;
    let mut last_hash: Option<String> = None;
    let mut stop_reason: Option<String> = None;
    let mut mode = match cfg.pq_mode {
        PqMode::Implicit => PqMode::Implicit,
        _ => PqMode::Explicit,
    };
    let mut activation_pending = cfg.pq_mode == PqMode::Auto && mode == PqMode::Explicit;

    'outer: loop {
        if stop.load(Ordering::Relaxed) {
            if Instant::now() < deadline {
                stop_reason = Some("global stop condition (stall/lag/backlog)".to_string());
            }
            break;
        }
        let now = Instant::now();
        if now >= deadline {
            break;
        }

        // --- nonce window: never exceed the node's NONCE_FUTURE_WINDOW ---
        while nonce >= onchain.saturating_add(cfg.inflight_per_sender) {
            if stop.load(Ordering::Relaxed) || Instant::now() >= deadline {
                if Instant::now() < deadline {
                    stop_reason =
                        Some("global stop condition while waiting for a nonce".to_string());
                }
                break 'outer;
            }
            if !read_gate.acquire(Some(deadline), &stop) {
                break 'outer;
            }
            match read_nonce(&client, &address) {
                Ok(n) => onchain = n,
                Err(e) => {
                    stats.read_errors.fetch_add(1, Ordering::Relaxed);
                    stats.record_error(&e);
                    std::thread::sleep(Duration::from_millis(cfg.nonce_poll_ms));
                }
            }
        }

        // --- global rate limit ---
        if !gate.acquire(Some(deadline), &stop) {
            break;
        }

        let base = stats.base_fee.load(Ordering::Relaxed);
        let gas_limit = gas_limit_for(&cfg, base, mode);
        let mut spec = TxSpec {
            to,
            amount: cfg.amount,
            gas_limit,
            nonce,
            source_shard: cfg.shard,
            target_shard: cfg.shard,
            chain_id,
        };
        let mut tx = build_signed_tx(&sender, &spec, mode);
        let mut wire = match encode_wire(&tx) {
            Ok(w) => w,
            Err(e) => {
                stop_reason = Some(format!("local encode failed: {e}"));
                failed += 1;
                stats.failed.fetch_add(1, Ordering::Relaxed);
                break;
            }
        };
        let mut computed_hash = tx_hash_hex(&tx);
        let mut wire_hex_str = wire_hex(&wire);
        stats.submitted.fetch_add(1, Ordering::Relaxed);
        stats
            .bytes_sent
            .fetch_add(wire.len() as u64, Ordering::Relaxed);

        let mut attempt = 0u32;
        let mut resigned = false;
        let mut accepted_this = false;
        let mut rebuild_explicit = false;
        let mut rebuild_fee = false;
        let mut send_error: Option<String> = None;

        loop {
            if stop.load(Ordering::Relaxed) {
                send_error = Some("stopped before retry".to_string());
                break;
            }
            if !inflight.acquire(&stop) {
                send_error = Some("stopped while waiting for an in-flight slot".to_string());
                break;
            }
            let result = client.send_raw_once(&wire_hex_str);
            inflight.release();

            match result {
                Ok(node_hash) => {
                    if node_hash != computed_hash {
                        stats.hash_mismatch.fetch_add(1, Ordering::Relaxed);
                    }
                    accepted += 1;
                    stats.accepted.fetch_add(1, Ordering::Relaxed);
                    last_hash = Some(computed_hash.clone());
                    accepted_this = true;
                    if activation_pending {
                        match wait_for_nonce(
                            &client,
                            &address,
                            nonce.saturating_add(1),
                            deadline,
                            &stop,
                            &read_gate,
                            &stats,
                            cfg.nonce_poll_ms,
                        ) {
                            Ok(n) => {
                                onchain = n;
                                mode = PqMode::Implicit;
                                activation_pending = false;
                            }
                            Err(e) => {
                                nonce = nonce.saturating_add(1);
                                stop_reason = Some(format!("activation tx not included: {e}"));
                                break 'outer;
                            }
                        }
                    }
                    break;
                }
                Err(e) if e.is_duplicate() => {
                    accepted += 1;
                    stats.accepted.fetch_add(1, Ordering::Relaxed);
                    stats.duplicates.fetch_add(1, Ordering::Relaxed);
                    last_hash = Some(computed_hash.clone());
                    accepted_this = true;
                    if activation_pending {
                        match wait_for_nonce(
                            &client,
                            &address,
                            nonce.saturating_add(1),
                            deadline,
                            &stop,
                            &read_gate,
                            &stats,
                            cfg.nonce_poll_ms,
                        ) {
                            Ok(n) => {
                                onchain = n;
                                mode = PqMode::Implicit;
                                activation_pending = false;
                            }
                            Err(err) => {
                                nonce = nonce.saturating_add(1);
                                stop_reason = Some(format!("activation tx not included: {err}"));
                                break 'outer;
                            }
                        }
                    }
                    break;
                }
                Err(e) if e.retryable() => {
                    retries += 1;
                    stats.retries.fetch_add(1, Ordering::Relaxed);
                    let rate_limited = matches!(e, RpcError::Http(429, _))
                        || e.message().to_ascii_lowercase().contains("rate limit");
                    if rate_limited {
                        stats.http_429.fetch_add(1, Ordering::Relaxed);
                    }
                    attempt += 1;
                    // A rate-limited node is a MEASUREMENT, not a reason to
                    // abandon the wave: keep retrying the same bytes until the
                    // send deadline. Transport errors keep the bounded
                    // --retry-max budget so a dead endpoint cannot spin.
                    if !rate_limited && attempt >= cfg.retry_max {
                        send_error = Some(format!("retry budget exhausted: {e}"));
                        break;
                    }
                    if rate_limited && Instant::now() >= deadline {
                        send_error = Some(format!("rate-limited until deadline: {e}"));
                        break;
                    }
                    rpc::sleep_backoff(cfg.retry_base_ms, attempt.saturating_sub(1));
                }
                Err(e) if e.is_bad_signature() && mode == PqMode::Implicit && !resigned => {
                    // The node lost its in-memory implicit registry (typically a
                    // restart). This nonce was NOT accepted, so re-signing the
                    // SAME nonce with the public key attached is safe and keeps
                    // the nonce sequence intact.
                    resigned = true;
                    rebuild_explicit = true;
                    stats.retries.fetch_add(1, Ordering::Relaxed);
                    retries += 1;
                }
                Err(e) if e.is_fee_too_low() && attempt < 2 => {
                    rebuild_fee = true;
                    attempt += 1;
                    stats.retries.fetch_add(1, Ordering::Relaxed);
                    retries += 1;
                }
                Err(e) => {
                    stats.record_error(&e);
                    send_error = Some(e.message());
                    break;
                }
            }

            if rebuild_explicit {
                mode = PqMode::Explicit;
                activation_pending = true;
                spec = TxSpec {
                    gas_limit: gas_limit_for(&cfg, stats.base_fee.load(Ordering::Relaxed), mode),
                    ..spec
                };
                tx = build_signed_tx(&sender, &spec, mode);
                wire = encode_wire(&tx).unwrap_or_default();
                computed_hash = tx_hash_hex(&tx);
                wire_hex_str = wire_hex(&wire);
                rebuild_explicit = false;
                continue;
            }
            if rebuild_fee {
                if let Ok(v) = client.call_retry("stell_baseFee", json!([]), 2, 150) {
                    if let Some(bf) = v.get("base_fee").and_then(parse_u64_any) {
                        stats.base_fee.store(bf, Ordering::Relaxed);
                    }
                }
                let new_gas = gas_limit_for(&cfg, stats.base_fee.load(Ordering::Relaxed), mode);
                if new_gas <= spec.gas_limit {
                    send_error = Some(format!(
                        "fee too low and gas limit cannot be raised ({} <= {})",
                        new_gas, spec.gas_limit
                    ));
                    break;
                }
                spec = TxSpec {
                    gas_limit: new_gas,
                    ..spec
                };
                tx = build_signed_tx(&sender, &spec, mode);
                wire = encode_wire(&tx).unwrap_or_default();
                computed_hash = tx_hash_hex(&tx);
                wire_hex_str = wire_hex(&wire);
                rebuild_fee = false;
                continue;
            }
        }

        if accepted_this {
            nonce = nonce.saturating_add(1);
        } else {
            let reason = send_error.unwrap_or_else(|| "send failed".to_string());
            if reason.starts_with("stopped") {
                stop_reason = Some(reason);
                break;
            }
            failed += 1;
            stats.failed.fetch_add(1, Ordering::Relaxed);
            stop_reason = Some(reason);
            break;
        }
    }

    SenderOutcome {
        index: sender.index,
        address,
        init_nonce,
        next_nonce: nonce,
        onchain_nonce_after: onchain,
        accepted,
        failed,
        retries,
        last_hash,
        stop_reason,
    }
}

#[allow(clippy::too_many_arguments)]
// GATE: mirrors the sender's waits; an argument struct would not reduce state.
fn wait_for_nonce(
    client: &RpcClient,
    address: &str,
    target: u64,
    deadline: Instant,
    stop: &AtomicBool,
    read_gate: &RateGate,
    stats: &Stats,
    poll_ms: u64,
) -> Result<u64, String> {
    loop {
        if stop.load(Ordering::Relaxed) {
            return Err("global stop condition".to_string());
        }
        if Instant::now() >= deadline {
            return Err("send window ended".to_string());
        }
        if !read_gate.acquire(Some(deadline), stop) {
            return Err("send window ended".to_string());
        }
        match client.call_retry("stell_getBalance", json!({ "address": address }), 2, 100) {
            Ok(v) => match parse_balance(&v) {
                Some((_, n)) if n >= target => return Ok(n),
                Some(_) => {}
                None => {
                    stats.read_errors.fetch_add(1, Ordering::Relaxed);
                    stats.record_error_message("stell_getBalance shape during activation wait");
                }
            },
            Err(e) => {
                stats.read_errors.fetch_add(1, Ordering::Relaxed);
                stats.record_error(&e);
            }
        }
        std::thread::sleep(Duration::from_millis(poll_ms.max(50)));
    }
}

// ============================================================================
// Drain and receipt sampling
// ============================================================================

fn drain(
    cfg: &Config,
    clients: &[RpcClient],
    outcomes: &mut [SenderOutcome],
    read_gate: &RateGate,
    stop: &AtomicBool,
    stats: &Stats,
) {
    if cfg.drain_timeout <= 0.0 {
        for o in outcomes.iter_mut() {
            o.onchain_nonce_after = o.init_nonce;
        }
        return;
    }
    let deadline = Instant::now() + Duration::from_secs_f64(cfg.drain_timeout);
    let targets: Vec<u64> = outcomes.iter().map(|o| o.next_nonce).collect();
    let mut onchain: Vec<u64> = outcomes.iter().map(|o| o.init_nonce).collect();

    loop {
        let mut all_done = true;
        for (i, o) in outcomes.iter().enumerate() {
            if onchain[i] >= targets[i] {
                continue;
            }
            all_done = false;
            if stop.load(Ordering::Relaxed) {
                break;
            }
            if !read_gate.acquire(Some(deadline), stop) {
                break;
            }
            let client = &clients[i % clients.len()];
            match read_nonce(client, &o.address) {
                Ok(n) => {
                    if n > onchain[i] {
                        onchain[i] = n.min(targets[i]);
                    }
                }
                Err(e) => {
                    stats.read_errors.fetch_add(1, Ordering::Relaxed);
                    stats.record_error(&e);
                }
            }
            if Instant::now() >= deadline || stop.load(Ordering::Relaxed) {
                break;
            }
        }
        if all_done || Instant::now() >= deadline || stop.load(Ordering::Relaxed) {
            break;
        }
        std::thread::sleep(Duration::from_millis(cfg.drain_poll_ms));
    }

    for (i, o) in outcomes.iter_mut().enumerate() {
        o.onchain_nonce_after = onchain[i];
    }
}

/// Receipt sampling is deliberately patient: drain only means the on-chain
/// nonce caught up, while the receipt index is filed by the application on
/// finalize/adopt and can lag by a block. One immediate query used to report
/// `unknown` for receipts that appeared a moment later; sample with a short
/// bounded backoff instead (total wait is further capped by the deadline).
const RECEIPT_SAMPLE_ATTEMPTS: u32 = 6;
const RECEIPT_SAMPLE_BASE_MS: u64 = 100;

fn receipt_retry_delay_ms(attempt: u32) -> u64 {
    RECEIPT_SAMPLE_BASE_MS
        .saturating_mul(1u64 << attempt.min(4))
        .min(2_000)
}

fn sample_receipts(
    cfg: &Config,
    clients: &[RpcClient],
    outcomes: &[SenderOutcome],
    read_gate: &RateGate,
    stats: &Stats,
) -> ReceiptSample {
    let mut sample = ReceiptSample::default();
    if cfg.receipt_sample == 0 {
        return sample;
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    let stop = AtomicBool::new(false);
    let mut n = 0usize;
    for o in outcomes {
        if n >= cfg.receipt_sample {
            break;
        }
        let Some(hash) = o.last_hash.as_ref() else {
            continue;
        };
        n += 1;
        sample.queried += 1;
        let client = &clients[(o.index as usize) % clients.len()];
        let mut status = "unknown".to_string();
        for attempt in 0..RECEIPT_SAMPLE_ATTEMPTS {
            if Instant::now() >= deadline || stop.load(Ordering::Relaxed) {
                break;
            }
            if !read_gate.acquire(Some(deadline), &stop) {
                break;
            }
            match client.call("stell_getTransactionStatus", json!({ "hash": hash })) {
                Ok(v) => {
                    let s = v.as_str().unwrap_or("unknown").to_string();
                    if s != "unknown" {
                        status = s;
                        break;
                    }
                }
                Err(e) => {
                    // Transport/HTTP errors are transient too; keep the
                    // bounded retry (the deadline still applies).
                    stats.read_errors.fetch_add(1, Ordering::Relaxed);
                    stats.record_error(&e);
                }
            }
            if attempt + 1 < RECEIPT_SAMPLE_ATTEMPTS {
                std::thread::sleep(Duration::from_millis(receipt_retry_delay_ms(attempt)));
            }
        }
        match status.as_str() {
            "success" => sample.success += 1,
            "failed" => sample.failed += 1,
            _ => sample.unknown += 1,
        }
        let height = if sample.details.len() < 3 && status != "unknown" {
            let mut height = None;
            for attempt in 0..3u32 {
                if let Ok(v) = client.call_retry(
                    "stell_getTransactionReceipt",
                    json!({ "hash": hash }),
                    1,
                    100,
                ) {
                    height = v.get("height").and_then(parse_u64_any);
                    if height.is_some() {
                        break;
                    }
                }
                if attempt < 2 {
                    std::thread::sleep(Duration::from_millis(receipt_retry_delay_ms(attempt)));
                }
            }
            height
        } else {
            None
        };
        if sample.details.len() < 8 {
            sample.details.push((hash.clone(), status, height));
        }
    }
    sample
}

// ============================================================================
// Block / mempool poller
// ============================================================================

#[allow(clippy::too_many_arguments)]
// GATE: the poller is the one reader of every shared run handle.
fn poll_loop(
    cfg: &Config,
    stats: &Stats,
    stop: &AtomicBool,
    poller_stop: &AtomicBool,
    run_start: Instant,
    initial_height: u64,
    mempool_start: u64,
) {
    let primary = RpcClient::new(&cfg.urls[0], cfg.timeout_ms);
    let watchers: Vec<(String, RpcClient)> = cfg
        .watch_urls
        .iter()
        .map(|u| (u.clone(), RpcClient::new(u, cfg.timeout_ms)))
        .collect();
    let mut last_height: Option<u64> = Some(initial_height);
    let mut last_arrival = run_start;
    let mut first_height_change = true;
    let mut last_height_read = run_start;
    let mut last_progress = run_start;
    let mut last_mempool = run_start;
    let mut last_base = run_start;
    let mut lag_streak = 0u32;
    stats.add_mempool(0, mempool_start);

    while !poller_stop.load(Ordering::Relaxed) {
        let now = run_start.elapsed();

        // --- target height ---
        match primary.call_retry("stell_blockNumber", json!([]), 2, 100) {
            Ok(v) => {
                if let Some(h) = parse_hex_u64(&v) {
                    last_height_read = Instant::now();
                    stats.final_height.store(h, Ordering::SeqCst);
                    if let Some(prev) = last_height {
                        if h > prev {
                            let delta = h - prev;
                            let elapsed = Instant::now().duration_since(last_arrival).as_secs_f64();
                            let per = if delta > 0 {
                                elapsed / delta as f64
                            } else {
                                elapsed
                            };
                            // The first change is measured from the preflight
                            // height, whose exact arrival time is unknown. Do
                            // not invent an interval from it.
                            if first_height_change {
                                first_height_change = false;
                            } else {
                                for _ in 0..delta.min(128) {
                                    stats.add_interval(now.as_nanos() as u64, per);
                                }
                            }
                            // Exact tx counts for the new heights, bounded so a
                            // long stall cannot turn one poll into a burst.
                            let from = prev.saturating_add(1);
                            let to = h.min(prev.saturating_add(32));
                            for height in from..=to {
                                fetch_block(&primary, height, now.as_nanos() as u64, stats);
                            }
                            if delta > 32 {
                                merge_latest(&primary, now.as_nanos() as u64, stats);
                            }
                            last_height = Some(h);
                            last_arrival = Instant::now();
                        }
                    } else {
                        last_height = Some(h);
                        last_arrival = Instant::now();
                    }
                }
            }
            Err(e) => {
                stats.read_errors.fetch_add(1, Ordering::Relaxed);
                stats.record_error(&e);
            }
        }

        // --- watch endpoints (height lag, read-only) ---
        for (url, client) in &watchers {
            if let Ok(v) = client.call_retry("stell_blockNumber", json!([]), 1, 100) {
                if let Some(h) = parse_hex_u64(&v) {
                    stats.add_watch_height(url, h);
                }
            }
        }
        let (min_h, max_h) = {
            let map = stats
                .watch_heights
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if map.len() < 2 {
                (0, 0)
            } else {
                let min = *map.values().min().unwrap_or(&0);
                let max = *map.values().max().unwrap_or(&0);
                (min, max)
            }
        };
        let spread = max_h.saturating_sub(min_h);
        stats.watch_lag.store(spread, Ordering::Relaxed);
        if cfg.max_lag_blocks > 0 && spread > cfg.max_lag_blocks {
            lag_streak += 1;
            if lag_streak >= 3 && !stats.lagged.swap(true, Ordering::SeqCst) {
                eprintln!(
                    "STOP: watch endpoint spread {spread} blocks > {} (node lag)",
                    cfg.max_lag_blocks
                );
                stats.aborted.store(true, Ordering::SeqCst);
                stop.store(true, Ordering::SeqCst);
            }
        } else {
            lag_streak = 0;
        }

        // --- chain stall (only when height reads themselves are succeeding) ---
        if cfg.stall_seconds > 0 {
            let silent = Instant::now().duration_since(last_arrival).as_secs();
            let reads_alive = last_height_read.elapsed().as_secs() < cfg.stall_seconds;
            if reads_alive
                && silent >= cfg.stall_seconds
                && !stats.stalls.swap(true, Ordering::SeqCst)
            {
                eprintln!(
                    "STOP: no new block for {silent}s (threshold {}s)",
                    cfg.stall_seconds
                );
                stats.aborted.store(true, Ordering::SeqCst);
                stop.store(true, Ordering::SeqCst);
            }
        }

        // --- mempool size / base fee / progress ---
        if last_mempool.elapsed() >= Duration::from_secs(1) {
            last_mempool = Instant::now();
            if let Ok(v) = primary.call_retry("stell_mempoolSize", json!([]), 1, 100) {
                if let Some(n) = parse_u64_any(&v) {
                    stats.add_mempool(now.as_nanos() as u64, n);
                    if cfg.backlog_stop_size > 0
                        && stats.backlog_sustained(cfg.backlog_stop_size, cfg.backlog_stop_secs)
                        && !stats.aborted.swap(true, Ordering::SeqCst)
                    {
                        eprintln!(
                            "STOP: mempool stayed >= {} for {}s (backlog without drain)",
                            cfg.backlog_stop_size, cfg.backlog_stop_secs
                        );
                        stop.store(true, Ordering::SeqCst);
                    }
                }
            }
        }
        if last_base.elapsed() >= Duration::from_secs(5) {
            last_base = Instant::now();
            if let Ok(v) = primary.call_retry("stell_baseFee", json!([]), 1, 100) {
                if let Some(bf) = v.get("base_fee").and_then(parse_u64_any) {
                    stats.base_fee.store(bf, Ordering::Relaxed);
                }
            }
        }
        if !cfg.quiet && last_progress.elapsed() >= Duration::from_secs(5) {
            last_progress = Instant::now();
            let accepted = stats.accepted.load(Ordering::Relaxed);
            let failed = stats.failed.load(Ordering::Relaxed);
            let elapsed = run_start.elapsed().as_secs_f64();
            let height = stats.final_height.load(Ordering::Relaxed);
            let mp = stats
                .mempool_stats()
                .map(|(_, p, b)| format!("{b}/{p}"))
                .unwrap_or_default();
            eprintln!(
                "[t={:6.1}s] accepted={accepted} ({:.1}/s) failed={failed} height={height} mempool={mp}",
                elapsed,
                accepted as f64 / elapsed.max(0.001)
            );
        }

        std::thread::sleep(Duration::from_millis(cfg.poll_ms));
    }

    // One last read so the report's final height is not one poll stale.
    if let Ok(v) = primary.call_retry("stell_blockNumber", json!([]), 2, 100) {
        if let Some(h) = parse_hex_u64(&v) {
            stats.final_height.store(h, Ordering::SeqCst);
        }
    }
    merge_latest(&primary, run_start.elapsed().as_nanos() as u64, stats);
}

fn fetch_block(client: &RpcClient, height: u64, at_ns: u64, stats: &Stats) {
    if let Ok(v) = client.call_retry("stell_getBlock", json!({ "height": height }), 1, 100) {
        let h = v.get("height").and_then(parse_u64_any);
        if let Some(h) = h {
            stats.add_block(BlockObs {
                height: h,
                txs: v.get("txs").and_then(parse_u64_any),
                node_ts: v.get("timestamp").and_then(parse_u64_any),
                first_seen_ns: at_ns,
            });
        }
    }
}

fn merge_latest(client: &RpcClient, at_ns: u64, stats: &Stats) {
    if let Ok(v) = client.call_retry("stell_latestBlocks", json!({ "limit": 256 }), 1, 100) {
        if let Some(list) = v.as_array() {
            for item in list {
                let Some(h) = item.get("height").and_then(parse_u64_any) else {
                    continue;
                };
                stats.add_block(BlockObs {
                    height: h,
                    txs: item.get("txs").and_then(parse_u64_any),
                    node_ts: item.get("timestamp").and_then(parse_u64_any),
                    first_seen_ns: at_ns,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gas_limit_respects_a_fixed_operator_override() {
        let cfg = Config {
            gas_limit: 400_000,
            ..Config::default()
        };
        assert_eq!(gas_limit_for(&cfg, 100, PqMode::Explicit), 400_000);
        let cfg = Config::default();
        assert_eq!(
            gas_limit_for(&cfg, 280_000, PqMode::Explicit),
            280_000 + 45_000 + cfg.gas_margin
        );
        assert_eq!(
            gas_limit_for(&cfg, 280_000, PqMode::Implicit),
            280_000 + cfg.gas_margin
        );
    }

    #[test]
    fn a_fixed_gas_below_the_floor_is_refused_before_the_run() {
        let cfg = Config {
            gas_limit: 300_000,
            ..Config::default()
        };
        assert!(fixed_gas_error(&cfg, 280_000, PqMode::Explicit).is_some());
        assert!(fixed_gas_error(&cfg, 280_000, PqMode::Implicit).is_none());
        let cfg = Config::default();
        assert!(fixed_gas_error(&cfg, 280_000, PqMode::Explicit).is_none());
    }

    #[test]
    fn receipt_sampling_backoff_is_short_and_bounded() {
        let delays: Vec<u64> = (0..RECEIPT_SAMPLE_ATTEMPTS)
            .map(receipt_retry_delay_ms)
            .collect();
        assert!(
            delays[0] >= 50,
            "first retry must wait a little: {delays:?}"
        );
        for w in delays.windows(2) {
            assert!(w[1] >= w[0], "backoff must be non-decreasing: {delays:?}");
        }
        assert!(
            delays.iter().all(|d| *d <= 2_000),
            "per-attempt backoff must stay bounded: {delays:?}"
        );
        let total: u64 = delays.iter().sum();
        assert!(
            total < 6_000,
            "total sample retry wait stays short: {total}"
        );
        assert_eq!(receipt_retry_delay_ms(0), 100);
        assert_eq!(receipt_retry_delay_ms(99), 1_600);
    }

    #[test]
    fn prometheus_interval_is_parsed_only_from_sum_and_count() {
        let text = "\
# HELP stell_block_interval_seconds Seconds between blocks
# TYPE stell_block_interval_seconds histogram
stell_block_interval_seconds_bucket{le=\"1\"} 50
stell_block_interval_seconds_bucket{le=\"+Inf\"} 100
stell_block_interval_seconds_sum 123.5
stell_block_interval_seconds_count 100
";
        let (mean, count) = parse_metrics_block_interval(text).unwrap();
        assert!((mean - 1.235).abs() < 1e-9);
        assert_eq!(count, 100);
        assert!(parse_metrics_block_interval("stell_block_interval_seconds_count 0").is_none());
    }
}
