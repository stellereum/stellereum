//! Deploy Ecosystem Smart Contracts (STS-20, AMM Liquidity Pool, Account Object AA)
//! to the live Stellereum testnet over RPC.

use anyhow::{anyhow, Context, Result};
use std::fs;
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

fn get_latest_contract_addr(rpc_url: &str) -> Result<[u8; 32]> {
    let gateway_url = rpc_url
        .replace(":8545", ":8080")
        .replace(":8546", ":8081")
        .replace("https://rpc.", "https://explorer.");
    let url = format!("{}/api/contracts", gateway_url);
    let resp = ureq::get(&url).call()?.into_json::<serde_json::Value>()?;
    let list = resp
        .get("contracts")
        .and_then(|c| c.as_array())
        .ok_or_else(|| anyhow!("no contracts list"))?;
    let last = list
        .last()
        .and_then(|s| s.as_str())
        .ok_or_else(|| anyhow!("empty contracts list"))?;
    let raw = hex::decode(last)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn wait_for_tx(rpc_url: &str, tx_hash: &str) -> Result<u64> {
    print!("    Waiting for tx {tx_hash} finalization");
    for _ in 1..=30 {
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
    let rpc_url =
        std::env::var("STELL_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8546".to_string());
    let faucet_token =
        std::env::var("STELL_FAUCET_TOKEN").unwrap_or_else(|_| "REPLACE-ME".to_string());

    println!("============================================================");
    println!("  STELLEREUM LIVE ECOSYSTEM SMART CONTRACTS DEPLOYER");
    println!("============================================================");
    println!("Target RPC: {rpc_url}");

    // 1. Generate new Falcon-512 deployer keypair
    let deployer_key = FalconKeypair::generate();
    let deployer_addr = stellereum::post_quantum::derive_pq_address(
        PqScheme::Falcon512,
        deployer_key.public_key(),
        &DEFAULT_SALT,
    );
    let deployer_addr_hex = hex::encode(deployer_addr);
    println!("Deployer Falcon-512 Address: 0x{deployer_addr_hex}");

    // 2. Request faucet drip
    println!("\n[1/6] Requesting 100 STELL faucet drip for deployer...");
    let faucet_res = rpc_call(
        &rpc_url,
        "stell_faucet",
        serde_json::json!({
            "address": deployer_addr_hex,
            "token": faucet_token,
            "amount": 100_000_000_000u64, // 100 STELL
        }),
    )?;
    let faucet_tx_hash = faucet_res
        .get("tx_hash")
        .and_then(|s| s.as_str())
        .unwrap_or("");
    println!("    Faucet drip tx submitted: {faucet_tx_hash}");
    wait_for_tx(&rpc_url, faucet_tx_hash)?;

    // 3. Check deployer balance & nonce
    let bal_info = rpc_call(
        &rpc_url,
        "stell_getBalance",
        serde_json::json!({ "address": deployer_addr_hex }),
    )?;
    let balance = bal_info
        .get("balance")
        .and_then(|b| {
            b.as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .or_else(|| b.as_u64())
        })
        .unwrap_or(0);
    let mut nonce = bal_info
        .get("nonce")
        .and_then(|n| {
            n.as_u64()
                .or_else(|| n.as_str().and_then(|s| s.parse::<u64>().ok()))
        })
        .unwrap_or(0);
    println!(
        "    Deployer confirmed balance: {} nano-STELL (nonce: {nonce})",
        balance
    );
    assert!(balance >= 10_000_000_000, "Deployer balance insufficient");

    // 4. Compile contracts from WAT
    println!("\n[2/6] Compiling contracts from WebAssembly Text format (WAT)...");
    let sts20_wat =
        fs::read_to_string("contracts/sts20_token.wat").context("reading sts20_token.wat")?;
    let sts20_wasm = wat::parse_str(&sts20_wat).context("parsing sts20_token.wat")?;
    println!(
        "    • STS-20 Token: compiled successfully ({} bytes)",
        sts20_wasm.len()
    );

    let pool_wat =
        fs::read_to_string("contracts/liquidity_pool.wat").context("reading liquidity_pool.wat")?;
    let pool_wasm = wat::parse_str(&pool_wat).context("parsing liquidity_pool.wat")?;
    println!(
        "    • Liquidity Pool AMM: compiled successfully ({} bytes)",
        pool_wasm.len()
    );

    let aa_wat =
        fs::read_to_string("contracts/account_object.wat").context("reading account_object.wat")?;
    let aa_wasm = wat::parse_str(&aa_wat).context("parsing account_object.wat")?;
    println!(
        "    • Account Object AA: compiled successfully ({} bytes)",
        aa_wasm.len()
    );

    // 5. Deploy STS-20 Token (Activation transaction with explicit pubkey)
    println!("\n[3/6] Deploying STS-20 Token contract on-chain...");
    let deploy_sts20_tx = build_pq_tx(
        &deployer_key,
        [0u8; 32],
        0,
        15_000_000, // gas limit
        nonce,
        true, // is_activation: registers Falcon-512 public key on-chain!
        vec![OpCode::SysCallDeployContract { code: sts20_wasm }],
    );
    let raw_sts20 = hex::encode(bincode::serialize(&deploy_sts20_tx)?);
    let submit_sts20 = rpc_call(
        &rpc_url,
        "stell_sendRawTransaction",
        serde_json::json!({ "tx": raw_sts20 }),
    )?;
    let sts20_tx_hash = submit_sts20.as_str().unwrap_or("");
    println!("    Deploy tx submitted: {sts20_tx_hash}");
    let sts20_block = wait_for_tx(&rpc_url, sts20_tx_hash)?;
    let sts20_addr = get_latest_contract_addr(&rpc_url)?;
    println!(
        "    >>> STS-20 Token Contract Address: 0x{} (Block #{sts20_block})",
        hex::encode(sts20_addr)
    );
    nonce += 1;

    // Initialize STS-20 Token (1,000,000 supply)
    println!("\n[4/6] Initializing STS-20 Token supply (1,000,000 units)...");
    let init_sts20_tx = build_pq_tx(
        &deployer_key,
        [0u8; 32],
        0,
        5_000_000,
        nonce,
        false, // implicit PQ
        vec![OpCode::SysCallCallContract {
            contract: sts20_addr,
            method: b"init".to_vec(),
            arg: 1_000_000,
        }],
    );
    let raw_init_sts20 = hex::encode(bincode::serialize(&init_sts20_tx)?);
    let submit_init = rpc_call(
        &rpc_url,
        "stell_sendRawTransaction",
        serde_json::json!({ "tx": raw_init_sts20 }),
    )?;
    let init_tx_hash = submit_init.as_str().unwrap_or("");
    wait_for_tx(&rpc_url, init_tx_hash)?;
    println!("    >>> STS-20 Token Initialized: 1,000,000 tokens minted to creator!");
    nonce += 1;

    // 6. Deploy Liquidity Pool AMM
    println!("\n[5/6] Deploying Liquidity Pool AMM contract on-chain...");
    let deploy_pool_tx = build_pq_tx(
        &deployer_key,
        [0u8; 32],
        0,
        15_000_000,
        nonce,
        false,
        vec![OpCode::SysCallDeployContract { code: pool_wasm }],
    );
    let raw_pool = hex::encode(bincode::serialize(&deploy_pool_tx)?);
    let submit_pool = rpc_call(
        &rpc_url,
        "stell_sendRawTransaction",
        serde_json::json!({ "tx": raw_pool }),
    )?;
    let pool_tx_hash = submit_pool.as_str().unwrap_or("");
    println!("    Deploy tx submitted: {pool_tx_hash}");
    let pool_block = wait_for_tx(&rpc_url, pool_tx_hash)?;
    let pool_addr = get_latest_contract_addr(&rpc_url)?;
    println!(
        "    >>> Liquidity Pool AMM Address: 0x{} (Block #{pool_block})",
        hex::encode(pool_addr)
    );
    nonce += 1;

    // Initialize Pool with 30 BPS (0.3% swap fee)
    let init_pool_tx = build_pq_tx(
        &deployer_key,
        [0u8; 32],
        0,
        5_000_000,
        nonce,
        false,
        vec![OpCode::SysCallCallContract {
            contract: pool_addr,
            method: b"init".to_vec(),
            arg: 30, // 0.3% fee
        }],
    );
    let raw_init_pool = hex::encode(bincode::serialize(&init_pool_tx)?);
    let submit_init_pool = rpc_call(
        &rpc_url,
        "stell_sendRawTransaction",
        serde_json::json!({ "tx": raw_init_pool }),
    )?;
    let init_pool_hash = submit_init_pool.as_str().unwrap_or("");
    wait_for_tx(&rpc_url, init_pool_hash)?;
    println!("    >>> AMM Liquidity Pool Initialized with 0.3% swap fee!");
    nonce += 1;

    // 7. Deploy Account Object (AA) Smart Account
    println!("\n[6/6] Deploying Account Object (AA) Smart Contract on-chain...");
    let deploy_aa_tx = build_pq_tx(
        &deployer_key,
        [0u8; 32],
        0,
        15_000_000,
        nonce,
        false,
        vec![OpCode::SysCallDeployContract { code: aa_wasm }],
    );
    let raw_aa = hex::encode(bincode::serialize(&deploy_aa_tx)?);
    let submit_aa = rpc_call(
        &rpc_url,
        "stell_sendRawTransaction",
        serde_json::json!({ "tx": raw_aa }),
    )?;
    let aa_tx_hash = submit_aa.as_str().unwrap_or("");
    println!("    Deploy tx submitted: {aa_tx_hash}");
    let aa_block = wait_for_tx(&rpc_url, aa_tx_hash)?;
    let aa_addr = get_latest_contract_addr(&rpc_url)?;
    println!(
        "    >>> Account Object (AA) Address: 0x{} (Block #{aa_block})",
        hex::encode(aa_addr)
    );
    nonce += 1;

    // Initialize Account Object for Owner 42
    let init_aa_tx = build_pq_tx(
        &deployer_key,
        [0u8; 32],
        0,
        5_000_000,
        nonce,
        false,
        vec![OpCode::SysCallCallContract {
            contract: aa_addr,
            method: b"init".to_vec(),
            arg: 42,
        }],
    );
    let raw_init_aa = hex::encode(bincode::serialize(&init_aa_tx)?);
    let submit_init_aa = rpc_call(
        &rpc_url,
        "stell_sendRawTransaction",
        serde_json::json!({ "tx": raw_init_aa }),
    )?;
    let init_aa_hash = submit_init_aa.as_str().unwrap_or("");
    wait_for_tx(&rpc_url, init_aa_hash)?;
    println!("    >>> Account Object Initialized for Owner 42!");

    println!("\n============================================================");
    println!("  DEPLOYMENT SUCCESSFUL! ALL ECOSYSTEM CONTRACTS ARE LIVE!");
    println!("============================================================");
    println!("1. STS-20 Token:       0x{}", hex::encode(sts20_addr));
    println!("2. Liquidity Pool AMM: 0x{}", hex::encode(pool_addr));
    println!("3. Account Object AA:  0x{}", hex::encode(aa_addr));
    println!("Explorer Links:");
    println!("  https://explorer.stellereum.org");
    println!("  https://explorer.stellereum.org/api/v2/blocks");
    println!("============================================================");

    Ok(())
}
