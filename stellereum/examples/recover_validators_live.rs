//! LIVE validator-set recovery (masterchain).
//!
//! Restores A (top-up) then bonds D (fresh stake), funded DIRECTLY from the
//! network-shared faucet key (STELL_FAUCET_SEED_HEX) instead of `stell_faucet`.
//!
//! WHY NOT THE FAUCET ENDPOINT: on this sharded cluster the faucet builds
//! `source_shard=1` drips. Those are shard-filtered out of masterchain
//! blocks forever (proven live: a drip sat `pending` 10+ min on a ~1 blk/s
//! chain, balance stayed 0 on the served chain, 3 faucet nonces pile up in
//! the masterchain mempool). A `SysCallStake` MUST execute on the masterchain
//! (shard 0 owns the only staking ledger), so every tx here uses
//! `source_shard=0, target_shard=0`. Direct faucet-key transfers debit the
//! same genesis-funded account the endpoint would — no minting, no new keys.
//!
//! SAFETY: sequential nonces read live before each submit; expected-nonce
//! guard aborts on mismatch (never poison the account); any on-chain
//! `failed` receipt aborts the run with the full receipt printed.

use anyhow::{anyhow, Context, Result};
use std::thread::sleep;
use std::time::{Duration, Instant};

use stellereum::post_quantum::{FalconKeypair, PqScheme, PqSignatureEnvelope, DEFAULT_SALT};
use stellereum::sharding::Transaction;
use stellereum::svm::OpCode;

const VAL_A: &str = "c2313fbaf5c0b1a4921f132bed48772f0d0b788b8f27ad7f96772610996c3361";
const VAL_D: &str = "eddf81632831d8e9747dc38edbb2c88a835e246a0310d74c8b12b8df6e32e4cc";
const STELL: u64 = 1_000_000_000;

fn rpc_call(rpc_url: &str, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    })
    .to_string();
    let resp: serde_json::Value = ureq::post(rpc_url)
        .send_string(&body)
        .with_context(|| format!("RPC {method} unreachable at {rpc_url}"))?
        .into_json()
        .context("RPC returned non-JSON")?;
    if let Some(err) = resp.get("error") {
        return Err(anyhow!("node rejected {method}: {err}"));
    }
    Ok(resp
        .get("result")
        .cloned()
        .unwrap_or(serde_json::Value::Null))
}

fn build_pq_tx(
    key: &FalconKeypair,
    to: [u8; 32],
    amount: u64,
    gas_limit: u64,
    nonce: u64,
    payload: Vec<OpCode>,
) -> Transaction {
    let scheme = PqScheme::Falcon512;
    let from = stellereum::post_quantum::derive_pq_address(scheme, key.public_key(), &DEFAULT_SALT);
    let mut tx = Transaction {
        from,
        to,
        amount,
        gas_limit,
        nonce,
        source_shard: 0,
        target_shard: 0,
        signature: Vec::new(),
        payload,
        priority_fee_per_gas: 0,
    };
    let msg = tx.signing_message();
    let sig_bytes = key.sign(&msg);
    // Explicit envelope (same as the faucet's own drips): registers the key
    // on first use, verifies fine afterwards.
    let envelope = PqSignatureEnvelope::new_explicit(scheme, key.public_key().to_vec(), sig_bytes);
    tx.signature = envelope.encode();
    tx
}

fn submit(rpc_url: &str, tx: &Transaction) -> Result<String> {
    let raw = hex::encode(bincode::serialize(tx)?);
    let res = rpc_call(
        rpc_url,
        "stell_sendRawTransaction",
        serde_json::json!({ "tx": raw }),
    )?;
    let h = res["hash"]
        .as_str()
        .or_else(|| res.as_str())
        .context("no hash in sendRawTransaction response")?
        .to_string();
    Ok(h)
}

/// Poll a receipt up to `budget_secs`. Returns full receipt JSON on
/// success; errors on on-chain failure (with receipt printed) or timeout.
fn wait_for_tx(rpc_url: &str, tx_hash: &str, budget_secs: u64) -> Result<serde_json::Value> {
    print!("    waiting up to {budget_secs}s for {tx_hash:.16}... ");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let t0 = Instant::now();
    let mut last_status = String::new();
    loop {
        sleep(Duration::from_secs(2));
        let res = rpc_call(
            rpc_url,
            "stell_getTransactionReceipt",
            serde_json::json!({ "hash": tx_hash }),
        );
        if let Ok(val) = res {
            if let Some(status) = val.get("status").and_then(|s| s.as_str()) {
                if status != last_status {
                    print!("[{status}]");
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                    last_status = status.to_string();
                }
                if status == "success" {
                    println!(" OK");
                    return Ok(val);
                } else if status == "failed" {
                    println!(" FAILED");
                    return Err(anyhow!("tx {tx_hash} FAILED on-chain. receipt={val}"));
                }
            }
        }
        if t0.elapsed() > Duration::from_secs(budget_secs) {
            println!(" TIMEOUT");
            return Err(anyhow!("timeout ({budget_secs}s) waiting for {tx_hash}"));
        }
    }
}

fn faucet_balance(rpc_url: &str, faucet_hex: &str) -> Result<(u64, u64)> {
    let b = rpc_call(
        rpc_url,
        "stell_getBalance",
        serde_json::json!({ "address": faucet_hex }),
    )?;
    let bal: u64 = b["balance"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .or_else(|| b["balance"].as_u64())
        .unwrap_or(0);
    let nonce: u64 = b["nonce"].as_u64().unwrap_or(0);
    Ok((bal, nonce))
}

fn show_set(rpc_url: &str) -> Result<()> {
    let v = rpc_call(rpc_url, "stell_getValidators", serde_json::json!({}))?;
    println!("    validator set: {}", serde_json::to_string(&v)?);
    Ok(())
}

/// Poll until `validator_hex` shows `expected_total` (nano STELL) or timeout.
fn wait_for_power(
    rpc_url: &str,
    validator_hex: &str,
    expected_total: u64,
    budget_secs: u64,
) -> Result<()> {
    let t0 = Instant::now();
    loop {
        let v = rpc_call(rpc_url, "stell_getValidators", serde_json::json!({}))?;
        let found = v["validators"].as_array().map(|arr| {
            arr.iter().any(|e| {
                e["validator"] == validator_hex
                    && e["power"].as_str().and_then(|s| s.parse::<u64>().ok())
                        == Some(expected_total)
            })
        });
        if found == Some(true) {
            println!("    confirmed in set: {validator_hex:.16} power={expected_total}");
            return Ok(());
        }
        if t0.elapsed() > Duration::from_secs(budget_secs) {
            println!("    NOTE: power not yet visible after {budget_secs}s; continuing");
            return Ok(());
        }
        sleep(Duration::from_secs(5));
    }
}

fn main() -> Result<()> {
    let rpc_url =
        std::env::var("STELL_RPC_URL").unwrap_or("https://rpc.stellereum.org".to_string());
    let seed_hex = std::env::var("STELL_FAUCET_SEED_HEX")
        .context("STELL_FAUCET_SEED_HEX must be set (never logged)")?;
    let seed: [u8; 32] = hex::decode(seed_hex.trim())
        .context("bad seed hex")?
        .try_into()
        .map_err(|_| anyhow!("seed must be 32 bytes"))?;
    let t_run = Instant::now();

    let faucet_key = FalconKeypair::generate_from_seed_bytes(&seed);
    let faucet_addr = stellereum::post_quantum::derive_pq_address(
        PqScheme::Falcon512,
        faucet_key.public_key(),
        &DEFAULT_SALT,
    );
    let faucet_hex = hex::encode(faucet_addr);
    println!("faucet account: {faucet_hex} (balance/nonce are public chain data)");

    println!("== BEFORE ==");
    show_set(&rpc_url)?;
    let (bal0, nonce0) = faucet_balance(&rpc_url, &faucet_hex)?;
    println!(
        "    faucet: balance={} nonce={nonce0}",
        bal0 as f64 / STELL as f64
    );
    let a0 = rpc_call(
        &rpc_url,
        "stell_stakeOf",
        serde_json::json!({ "validator": VAL_A }),
    )?;
    let d0 = rpc_call(
        &rpc_url,
        "stell_stakeOf",
        serde_json::json!({ "validator": VAL_D }),
    )?;
    println!("    stakeOf(A)={a0} stakeOf(D)={d0}");

    // STEP 0 — path validation: dust self-transfer from the faucet nonce head.
    println!("[0/3] Path check: dust self-transfer (shard 0->0) nonce={nonce0} ...");
    let t0 = Instant::now();
    let test_tx = build_pq_tx(&faucet_key, faucet_addr, 1, 350_000, nonce0, vec![]);
    let h0 = submit(&rpc_url, &test_tx)?;
    println!("    submitted {h0}");
    let r0 = wait_for_tx(&rpc_url, &h0, 600)?;
    println!("    receipt: {r0}");
    println!("    step 0 took {:.0}s", t0.elapsed().as_secs_f64());

    // STEP 1 — re-bond Node A: top-up 1000 STELL (999 + 1000 = 1999).
    let (_, nonce1) = faucet_balance(&rpc_url, &faucet_hex)?;
    if nonce1 != nonce0 + 1 {
        return Err(anyhow!(
            "nonce moved unexpectedly (want {}, got {nonce1}); aborting to avoid a gap",
            nonce0 + 1
        ));
    }
    let val_a: [u8; 32] = hex::decode(VAL_A)?.try_into().unwrap();
    println!("[1/3] Re-bond A: SysCallStake 1000 STELL nonce={nonce1} ...");
    let t1 = Instant::now();
    let stake_a = build_pq_tx(
        &faucet_key,
        [0u8; 32],
        0,
        500_000,
        nonce1,
        vec![OpCode::SysCallStake {
            validator: val_a,
            amount: 1_000 * STELL,
        }],
    );
    let h1 = submit(&rpc_url, &stake_a)?;
    println!("    submitted {h1}");
    let r1 = wait_for_tx(&rpc_url, &h1, 600)?;
    println!("    receipt: {r1}");
    println!("    step 1 took {:.0}s", t1.elapsed().as_secs_f64());
    let a1 = rpc_call(
        &rpc_url,
        "stell_stakeOf",
        serde_json::json!({ "validator": VAL_A }),
    )?;
    println!("    stakeOf(A) after: {a1}");
    show_set(&rpc_url)?;
    wait_for_power(&rpc_url, VAL_A, 1_999 * STELL, 180)?;

    // STEP 2 — stake Node D: fresh 2000 STELL bond.
    let (_, nonce2) = faucet_balance(&rpc_url, &faucet_hex)?;
    if nonce2 != nonce1 + 1 {
        return Err(anyhow!(
            "nonce moved unexpectedly (want {}, got {nonce2}); aborting to avoid a gap",
            nonce1 + 1
        ));
    }
    let val_d: [u8; 32] = hex::decode(VAL_D)?.try_into().unwrap();
    println!("[2/3] Bond D: SysCallStake 2000 STELL nonce={nonce2} ...");
    let t2 = Instant::now();
    let stake_d = build_pq_tx(
        &faucet_key,
        [0u8; 32],
        0,
        500_000,
        nonce2,
        vec![OpCode::SysCallStake {
            validator: val_d,
            amount: 2_000 * STELL,
        }],
    );
    let h2 = submit(&rpc_url, &stake_d)?;
    println!("    submitted {h2}");
    let r2 = wait_for_tx(&rpc_url, &h2, 600)?;
    println!("    receipt: {r2}");
    println!("    step 2 took {:.0}s", t2.elapsed().as_secs_f64());

    println!("== AFTER ==");
    let a3 = rpc_call(
        &rpc_url,
        "stell_stakeOf",
        serde_json::json!({ "validator": VAL_A }),
    )?;
    let d3 = rpc_call(
        &rpc_url,
        "stell_stakeOf",
        serde_json::json!({ "validator": VAL_D }),
    )?;
    println!("    stakeOf(A)={a3} stakeOf(D)={d3}");
    show_set(&rpc_url)?;
    wait_for_power(&rpc_url, VAL_D, 2_000 * STELL, 180)?;
    println!("total run time: {:.0}s", t_run.elapsed().as_secs_f64());
    Ok(())
}
