//! Top up Validator C's bond to restore 3/3 non-fragile BFT quorum.

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
        source_shard: 0,
        target_shard: 0,
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
    let val_c_hex = "021776cdf2b3b644e91dbe44fbef4a29f5a8ebf80b01055d3e7cc83a85659694";
    let val_c_bytes: [u8; 32] = hex::decode(val_c_hex)?.try_into().unwrap();

    println!("============================================================");
    println!("  RESTORE VALIDATOR C: TOPPING UP BOND TO 2,000 STELL");
    println!("============================================================");
    println!("Target RPC: {rpc_url}");

    // Check current stake of Validator C
    let stake_info = rpc_call(
        rpc_url,
        "stell_stakeOf",
        serde_json::json!({ "validator": val_c_hex }),
    )?;
    println!("Current Validator C stake info: {stake_info}");

    // 1. Generate 2 Falcon-512 keypairs to accumulate required funding
    let k1 = FalconKeypair::generate();
    let k2 = FalconKeypair::generate();

    let a1 = stellereum::post_quantum::derive_pq_address(
        PqScheme::Falcon512,
        k1.public_key(),
        &DEFAULT_SALT,
    );
    let a2 = stellereum::post_quantum::derive_pq_address(
        PqScheme::Falcon512,
        k2.public_key(),
        &DEFAULT_SALT,
    );

    let a1_hex = hex::encode(a1);
    let a2_hex = hex::encode(a2);

    println!("[1/5] Drip #1 from faucet to helper account 1 ({a1_hex})...");
    let f1 = rpc_call(
        rpc_url,
        "stell_faucet",
        serde_json::json!({
            "address": a1_hex,
            "token": faucet_token,
            "amount": 1_000_000_000_000u64,
        }),
    )?;
    let tx1 = f1["tx_hash"].as_str().unwrap();
    wait_for_tx(rpc_url, tx1)?;

    println!("[2/5] Drip #2 from faucet to helper account 2 ({a2_hex})...");
    let f2 = rpc_call(
        rpc_url,
        "stell_faucet",
        serde_json::json!({
            "address": a2_hex,
            "token": faucet_token,
            "amount": 1_000_000_000_000u64,
        }),
    )?;
    let tx2 = f2["tx_hash"].as_str().unwrap();
    wait_for_tx(rpc_url, tx2)?;

    // 2. Transfer from a1 to a2 so a2 has ~1999 STELL
    println!("[3/5] Consolidating funds: transfer from account 1 to account 2...");
    let send_amount = 999_000_000_000u64; // ~999 STELL (leave gas)
    let transfer_tx = build_pq_tx(&k1, a2, send_amount, 350_000, 0, true, vec![]);
    let raw_hex = hex::encode(bincode::serialize(&transfer_tx)?);
    let res = rpc_call(
        rpc_url,
        "stell_sendRawTransaction",
        serde_json::json!({ "tx": raw_hex }),
    )?;
    let t_hash = res["hash"].as_str().or_else(|| res.as_str()).unwrap();
    wait_for_tx(rpc_url, t_hash)?;

    let bal_info = rpc_call(
        rpc_url,
        "stell_getBalance",
        serde_json::json!({ "address": a2_hex }),
    )?;
    let nonce2: u64 = bal_info["nonce"].as_u64().unwrap_or(0);
    println!(
        "Account 2 consolidated balance: {} (nonce: {})",
        bal_info["balance"], nonce2
    );

    // 3. From account 2, submit SysCallStake for Validator C
    println!("[4/5] Submitting SysCallStake for Validator C (1,000 STELL)...");
    let stake_amount = 1_500_000_000_000u64; // 1,500 STELL
    let payload = vec![OpCode::SysCallStake {
        validator: val_c_bytes,
        amount: stake_amount,
    }];
    let gas_limit = 500_000u64;
    let stake_tx = build_pq_tx(&k2, [0u8; 32], 0, gas_limit, nonce2, true, payload);
    let stake_raw = hex::encode(bincode::serialize(&stake_tx)?);
    let res = rpc_call(
        rpc_url,
        "stell_sendRawTransaction",
        serde_json::json!({ "tx": stake_raw }),
    )?;
    let stake_hash = res["hash"].as_str().or_else(|| res.as_str()).unwrap();
    wait_for_tx(rpc_url, stake_hash)?;

    // 4. Verify new stake and validator set
    println!("[5/5] Verifying validator set on chain...");
    let new_stake = rpc_call(
        rpc_url,
        "stell_stakeOf",
        serde_json::json!({ "validator": val_c_hex }),
    )?;
    println!("Validator C updated stake: {new_stake}");

    let validators = rpc_call(rpc_url, "stell_getValidators", serde_json::json!({}))?;
    println!(
        "Live Validator Set:\n{}",
        serde_json::to_string_pretty(&validators)?
    );

    let is_fragile = validators["fragile"].as_bool().unwrap_or(true);
    let total_power = validators["total_power"].as_str().unwrap_or("0");
    println!("------------------------------------------------------------");
    println!("Result: Fragile = {is_fragile}, Total Power = {total_power}");
    if !is_fragile {
        println!("🎉 SUCCESS! 3/3 Quorum fully restored!");
    } else {
        println!(
            "⚠️ Set is still marked fragile. Reason: {}",
            validators["fragile_reason"]
        );
    }
    Ok(())
}
