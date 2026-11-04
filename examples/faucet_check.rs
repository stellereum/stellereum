//! Read-only preflight: derive the faucet PQ account from the shared seed
//! (STELL_FAUCET_SEED_HEX, never logged), print its address/balance/nonce
//! plus the live validator set and stakeOf(A/D). No submissions.

use anyhow::{Context, Result};

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
        .with_context(|| format!("RPC {method} unreachable"))?
        .into_json()
        .context("RPC returned non-JSON")?;
    if let Some(err) = resp.get("error") {
        anyhow::bail!("node rejected {method}: {err}");
    }
    Ok(resp
        .get("result")
        .cloned()
        .unwrap_or(serde_json::Value::Null))
}

fn main() -> Result<()> {
    let rpc_url =
        std::env::var("STELL_RPC_URL").unwrap_or("https://rpc.stellereum.org".to_string());
    let seed_hex = std::env::var("STELL_FAUCET_SEED_HEX")
        .context("STELL_FAUCET_SEED_HEX must be set (32-byte hex, never logged)")?;
    let seed: [u8; 32] = hex::decode(seed_hex.trim())
        .context("bad seed hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("seed must be 32 bytes"))?;

    // Mirror the node's own derivation (legacy flag + pure-PQ honored via env).
    let pq_key = stellereum::post_quantum::FalconKeypair::generate_from_seed_bytes(&seed);
    let faucet_addr = stellereum::post_quantum::derive_pq_address(
        stellereum::post_quantum::PqScheme::Falcon512,
        pq_key.public_key(),
        &stellereum::post_quantum::DEFAULT_SALT,
    );
    let faucet_hex = hex::encode(faucet_addr);
    println!("faucet_addr: {faucet_hex}");

    let bal = rpc_call(
        &rpc_url,
        "stell_getBalance",
        serde_json::json!({ "address": faucet_hex }),
    )?;
    println!("faucet balance/nonce: {bal}");

    let vals = rpc_call(&rpc_url, "stell_getValidators", serde_json::json!({}))?;
    println!("validators: {}", serde_json::to_string_pretty(&vals)?);

    for (name, v) in [
        (
            "A",
            "c2313fbaf5c0b1a4921f132bed48772f0d0b788b8f27ad7f96772610996c3361",
        ),
        (
            "D",
            "eddf81632831d8e9747dc38edbb2c88a835e246a0310d74c8b12b8df6e32e4cc",
        ),
        (
            "B",
            "9c675ebc6cd20c9226da2fcbf6c167647e4e948b78368f038058b6b419175fcd",
        ),
        (
            "C",
            "021776cdf2b3b644e91dbe44fbef4a29f5a8ebf80b01055d3e7cc83a85659694",
        ),
    ] {
        let s = rpc_call(
            &rpc_url,
            "stell_stakeOf",
            serde_json::json!({ "validator": v }),
        )?;
        println!("stakeOf({name}): {s}");
    }
    println!(
        "tip: {}",
        rpc_call(&rpc_url, "eth_blockNumber", serde_json::json!({}))?
    );
    Ok(())
}
