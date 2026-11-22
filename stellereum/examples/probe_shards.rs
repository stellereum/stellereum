//! Live probe: which shard executes faucet drips and plain transfers?
//! Drips 5 STELL to a fresh key, then sends one tiny shard-0 and one tiny
//! shard-1 self-transfer, reporting every receipt in full.

use anyhow::{anyhow, Context, Result};
use std::thread::sleep;
use std::time::Duration;

use stellereum::post_quantum::{FalconKeypair, PqScheme, PqSignatureEnvelope, DEFAULT_SALT};
use stellereum::sharding::Transaction;
use stellereum::svm::OpCode;

fn rpc_call(rpc_url: &str, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    })
    .to_string();

    let mut req = ureq::post(rpc_url);
    if let Ok(tok) = std::env::var("STELL_RPC_AUTH_TOKEN").map(|s| s.trim().to_string()) {
        if !tok.is_empty() {
            req = req.set("Authorization", &format!("Bearer {tok}"));
        }
    }
    let resp: serde_json::Value = req
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

#[allow(clippy::too_many_arguments)] // GATE: example builder mirrors Transaction field order
fn build_pq_tx(
    key: &FalconKeypair,
    to: [u8; 32],
    amount: u64,
    gas_limit: u64,
    nonce: u64,
    is_activation: bool,
    payload: Vec<OpCode>,
    src: u32,
    dst: u32,
) -> Transaction {
    let scheme = PqScheme::Falcon512;
    let from = stellereum::post_quantum::derive_pq_address(scheme, key.public_key(), &DEFAULT_SALT);
    let mut tx = Transaction {
        from,
        to,
        amount,
        gas_limit,
        nonce,
        source_shard: src,
        target_shard: dst,
        signature: Vec::new(),
        payload,
        priority_fee_per_gas: 0,
    };
    let msg = tx.signing_message();
    let sig_bytes = key.sign(&msg);
    let envelope = if is_activation {
        PqSignatureEnvelope::new_explicit(scheme, key.public_key().to_vec(), sig_bytes)
    } else {
        PqSignatureEnvelope::new_implicit(scheme, sig_bytes)
    };
    tx.signature = envelope.encode();
    tx
}

/// Poll up to `budget_secs` for a receipt; returns (status, full_receipt_json).
fn wait_for_tx_verbose(
    rpc_url: &str,
    tx_hash: &str,
    budget_secs: u64,
) -> Result<(String, serde_json::Value)> {
    print!("    Waiting {budget_secs}s for tx {tx_hash:.16}... ");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let polls = budget_secs / 2;
    for _ in 0..polls {
        sleep(Duration::from_secs(2));
        let res = rpc_call(
            rpc_url,
            "stell_getTransactionReceipt",
            serde_json::json!({ "hash": tx_hash }),
        );
        if let Ok(val) = res {
            if let Some(status) = val.get("status").and_then(|s| s.as_str()) {
                if status == "success" || status == "failed" {
                    println!("[{status}]");
                    return Ok((status.to_string(), val));
                }
                // pending/unknown: keep waiting, but note pending
                if status == "pending" {
                    print!("p");
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                }
            }
        }
    }
    println!("[TIMEOUT]");
    Err(anyhow!("timeout waiting for transaction receipt"))
}

fn tip(rpc_url: &str) -> String {
    rpc_call(rpc_url, "eth_blockNumber", serde_json::json!({}))
        .map(|v| v.as_str().unwrap_or("?").to_string())
        .unwrap_or_else(|_| "?".to_string())
}

fn main() -> Result<()> {
    let rpc_url =
        std::env::var("STELL_RPC_URL").unwrap_or("https://rpc.stellereum.org".to_string());
    let faucet_token =
        std::env::var("STELL_FAUCET_TOKEN").unwrap_or_else(|_| "REPLACE-ME".to_string());
    let rpc_url = rpc_url.as_str();
    let faucet_token = faucet_token.as_str();
    println!("tip before: {}", tip(rpc_url));

    let k1 = FalconKeypair::generate();
    let a1 = stellereum::post_quantum::derive_pq_address(
        PqScheme::Falcon512,
        k1.public_key(),
        &DEFAULT_SALT,
    );
    let a1_hex = hex::encode(a1);
    println!("[1/4] Drip 5 STELL to probe account {a1_hex}...");
    let f1 = rpc_call(
        rpc_url,
        "stell_faucet",
        serde_json::json!({
            "address": a1_hex,
            "token": faucet_token,
            "amount": 5_000_000_000u64,
        }),
    )?;
    println!("    faucet response: {f1}");
    let fhash = f1["tx_hash"].as_str().unwrap();
    let (st, receipt) = wait_for_tx_verbose(rpc_url, fhash, 600)?;
    println!("    drip receipt status={st} body={receipt}");

    let bal = rpc_call(
        rpc_url,
        "stell_getBalance",
        serde_json::json!({ "address": a1_hex }),
    )?;
    println!("[2/4] balance on served chain: {bal}");
    let nonce: u64 = bal["nonce"].as_u64().unwrap_or(0);

    println!("[3/4] Tiny self-transfer shard 0->0 ...");
    let tx0 = build_pq_tx(&k1, a1, 1_000_000u64, 350_000, nonce, false, vec![], 0, 0);
    let raw0 = hex::encode(bincode::serialize(&tx0)?);
    match rpc_call(
        rpc_url,
        "stell_sendRawTransaction",
        serde_json::json!({ "tx": raw0 }),
    ) {
        Ok(res) => {
            let h = res["hash"]
                .as_str()
                .or_else(|| res.as_str())
                .unwrap()
                .to_string();
            println!("    admitted: {h}");
            let (st, receipt) = wait_for_tx_verbose(rpc_url, &h, 600)?;
            println!("    shard0 receipt status={st} body={receipt}");
        }
        Err(e) => println!("    shard0 SUBMIT REJECTED: {e}"),
    }

    let bal2 = rpc_call(
        rpc_url,
        "stell_getBalance",
        serde_json::json!({ "address": a1_hex }),
    )?;
    println!("    balance now: {bal2}");
    let nonce2: u64 = bal2["nonce"].as_u64().unwrap_or(nonce + 1);

    println!("[4/4] Tiny self-transfer shard 1->1 ...");
    let tx1 = build_pq_tx(&k1, a1, 1_000_000u64, 350_000, nonce2, false, vec![], 1, 1);
    let raw1 = hex::encode(bincode::serialize(&tx1)?);
    match rpc_call(
        rpc_url,
        "stell_sendRawTransaction",
        serde_json::json!({ "tx": raw1 }),
    ) {
        Ok(res) => {
            let h = res["hash"]
                .as_str()
                .or_else(|| res.as_str())
                .unwrap()
                .to_string();
            println!("    admitted: {h}");
            let (st, receipt) = wait_for_tx_verbose(rpc_url, &h, 300)?;
            println!("    shard1 receipt status={st} body={receipt}");
        }
        Err(e) => println!("    shard1 SUBMIT REJECTED: {e}"),
    }

    println!("tip after: {}", tip(rpc_url));
    Ok(())
}
