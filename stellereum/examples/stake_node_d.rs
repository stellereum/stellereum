//! Stake 2,000 STELL for Node D to elect it as the 4th validator on-chain.

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

fn build_pq_tx(
    key: &FalconKeypair,
    to: [u8; 32],
    amount: u64,
    gas_limit: u64,
    nonce: u64,
    is_activation: bool,
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
        source_shard: 1,
        target_shard: 1,
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

fn wait_for_tx(rpc_url: &str, tx_hash: &str) -> Result<u64> {
    print!("    Waiting for tx {tx_hash} finalization");
    for _ in 1..=45 {
        sleep(Duration::from_millis(600));
        print!(".");
        let _ = std::io::Write::flush(&mut std::io::stdout());
        let res = rpc_call(
            rpc_url,
            "stell_getTransactionReceipt",
            serde_json::json!({ "hash": tx_hash }),
        );
        if let Ok(val) = res {
            if let Some(status) = val.get("status").and_then(|s| s.as_str()) {
                if status == "success" {
                    let block_num = val
                        .get("height")
                        .or_else(|| val.get("block_number"))
                        .and_then(|b| {
                            b.as_u64()
                                .or_else(|| b.as_str().and_then(|s| s.parse::<u64>().ok()))
                        })
                        .unwrap_or(0);
                    println!(" [FINALIZED at block #{block_num}]");
                    return Ok(block_num);
                } else if status == "failed" {
                    println!(" [FAILED]");
                    return Err(anyhow!("tx execution failed on-chain"));
                }
            }
        }
    }
    println!(" [TIMEOUT]");
    Err(anyhow!("timeout waiting for transaction receipt"))
}

fn main() -> Result<()> {
    let rpc_url = "https://rpc.stellereum.org";
    let faucet_token: String =
        std::env::var("STELL_FAUCET_TOKEN").unwrap_or_else(|_| "REPLACE-ME".to_string());
    let val_d_hex = "eddf81632831d8e9747dc38edbb2c88a835e246a0310d74c8b12b8df6e32e4cc";
    let val_d_bytes: [u8; 32] = hex::decode(val_d_hex)?.try_into().unwrap();

    println!("============================================================");
    println!("  ONBOARDING 4TH VALIDATOR (NODE D) — 2,000 STELL STAKE");
    println!("============================================================");
    println!("Target RPC: {rpc_url}");

    // Generate 3 Falcon keypairs to accumulate 2,000+ STELL from faucet
    let k1 = FalconKeypair::generate();
    let k2 = FalconKeypair::generate();
    let k3 = FalconKeypair::generate();

    let a1_hex = hex::encode(stellereum::post_quantum::derive_pq_address(
        PqScheme::Falcon512,
        k1.public_key(),
        &DEFAULT_SALT,
    ));
    let a2_hex = hex::encode(stellereum::post_quantum::derive_pq_address(
        PqScheme::Falcon512,
        k2.public_key(),
        &DEFAULT_SALT,
    ));
    let a3 = stellereum::post_quantum::derive_pq_address(
        PqScheme::Falcon512,
        k3.public_key(),
        &DEFAULT_SALT,
    );
    let a3_hex = hex::encode(a3);

    println!("[1/6] Drip 1,000 STELL to helper 1 ({a1_hex})...");
    let f1 = rpc_call(
        rpc_url,
        "stell_faucet",
        serde_json::json!({
            "address": a1_hex,
            "token": faucet_token,
            "amount": 1_000_000_000_000u64,
        }),
    )?;
    wait_for_tx(rpc_url, f1["tx_hash"].as_str().unwrap())?;

    println!("[2/6] Drip 1,000 STELL to helper 2 ({a2_hex})...");
    let f2 = rpc_call(
        rpc_url,
        "stell_faucet",
        serde_json::json!({
            "address": a2_hex,
            "token": faucet_token,
            "amount": 1_000_000_000_000u64,
        }),
    )?;
    wait_for_tx(rpc_url, f2["tx_hash"].as_str().unwrap())?;

    println!("[3/6] Drip 1,000 STELL to helper 3 ({a3_hex})...");
    let f3 = rpc_call(
        rpc_url,
        "stell_faucet",
        serde_json::json!({
            "address": a3_hex,
            "token": faucet_token,
            "amount": 1_000_000_000_000u64,
        }),
    )?;
    wait_for_tx(rpc_url, f3["tx_hash"].as_str().unwrap())?;

    // Consolidate k1 and k2 funds into k3
    println!("[4/6] Consolidating funds into master staking account...");
    let tx_send1 = build_pq_tx(&k1, a3, 999_000_000_000u64, 350_000, 0, true, vec![]);
    let res1 = rpc_call(
        rpc_url,
        "stell_sendRawTransaction",
        serde_json::json!({ "tx": hex::encode(bincode::serialize(&tx_send1)?) }),
    )?;
    wait_for_tx(
        rpc_url,
        res1["hash"].as_str().or_else(|| res1.as_str()).unwrap(),
    )?;

    let tx_send2 = build_pq_tx(&k2, a3, 999_000_000_000u64, 350_000, 0, true, vec![]);
    let res2 = rpc_call(
        rpc_url,
        "stell_sendRawTransaction",
        serde_json::json!({ "tx": hex::encode(bincode::serialize(&tx_send2)?) }),
    )?;
    wait_for_tx(
        rpc_url,
        res2["hash"].as_str().or_else(|| res2.as_str()).unwrap(),
    )?;

    let bal_info = rpc_call(
        rpc_url,
        "stell_getBalance",
        serde_json::json!({ "address": a3_hex }),
    )?;
    println!("Master staking account balance: {}", bal_info["balance"]);

    // Submit SysCallStake for Node D (2,000 STELL)
    println!("[5/6] Submitting SysCallStake for Node D (2,000 STELL)...");
    let stake_amount = 2_000_000_000_000u64; // 2,000 STELL
    let payload = vec![OpCode::SysCallStake {
        validator: val_d_bytes,
        amount: stake_amount,
    }];
    let gas_limit = 500_000u64;
    let nonce: u64 = bal_info["nonce"].as_u64().unwrap_or(0);
    let stake_tx = build_pq_tx(&k3, [0u8; 32], 0, gas_limit, nonce, true, payload);
    let stake_raw = hex::encode(bincode::serialize(&stake_tx)?);
    let res = rpc_call(
        rpc_url,
        "stell_sendRawTransaction",
        serde_json::json!({ "tx": stake_raw }),
    )?;
    let stake_hash = res["hash"].as_str().or_else(|| res.as_str()).unwrap();
    wait_for_tx(rpc_url, stake_hash)?;

    // Verify 4 validators active
    println!("[6/6] Verifying 4-validator set on chain...");
    let validators = rpc_call(rpc_url, "stell_getValidators", serde_json::json!({}))?;
    println!(
        "Live Validator Set:\n{}",
        serde_json::to_string_pretty(&validators)?
    );

    let count = validators["validators"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);
    let is_fragile = validators["fragile"].as_bool().unwrap_or(true);
    let total_power = validators["total_power"].as_str().unwrap_or("0");
    println!("------------------------------------------------------------");
    println!("Validators Count = {count}, Fragile = {is_fragile}, Total Power = {total_power}");
    if count == 4 && !is_fragile {
        println!("🎉 SUCCESS! N=4 BFT Validator Set is LIVE!");
    }
    Ok(())
}
