//! W10.3: re-bond Node A (top-up 1000 STELL) and stake Node D (2000 STELL).
//!
//! TEMPORARY operator script (deleted after the run, never committed).
//! Funding path: the `stell_faucet` RPC on every live node is shard-pinned
//! and cannot serve shard-0 (masterchain) recipients — verified live:
//!   * A: `-1:` refused ("faucet on shard 1 cannot serve an address on shard 0")
//!   * A: bare drip built but mempool-rejected ("belongs to shard 1 but this
//!     pool is pinned to shard 0")
//!   * B, D: faucet disabled.
//!     So this script spends directly from the faucet account (same seed the
//!     faucet would sign with, same 1000-STELL drip size, fresh helpers only)
//!     with shard 0/0 transfers, then submits shard-0/0 SysCallStake transactions.
//!
//! Env: RPC_URL (default http://127.0.0.1:8546), FAUCET_SEED (64-hex, required).
//! Usage: cargo run --example w10_3_rebond -- [fund|stakeA|stakeD|stakeB|all]
//! (W10.6-retry adds stakeB: top-up 1000 STELL to ejected Node B.)
//! State: /tmp/w10_3_keys.json (0600, shredded at the end of a full run).

use anyhow::{anyhow, Context, Result};
use std::io::Write;
use std::thread::sleep;
use std::time::Duration;

use stellereum::post_quantum::{
    derive_pq_address, FalconKeypair, PqScheme, PqSignatureEnvelope, DEFAULT_SALT,
};
use stellereum::sharding::Transaction;
use stellereum::svm::OpCode;

const VAL_A: &str = "c2313fbaf5c0b1a4921f132bed48772f0d0b788b8f27ad7f96772610996c3361";
const VAL_D: &str = "eddf81632831d8e9747dc38edbb2c88a835e246a0310d74c8b12b8df6e32e4cc";
const VAL_B: &str = "9c675ebc6cd20c9226da2fcbf6c167647e4e948b78368f038058b6b419175fcd";
const STELL: u64 = 1_000_000_000;
const DRIP: u64 = 1_000 * STELL;
const CONSOLIDATE: u64 = 999 * STELL;
const STAKE_A: u64 = 1_000 * STELL;
const STAKE_D: u64 = 2_000 * STELL;
// W10.6-retry: B self-bond is 999 (1 below MIN). Per-tx admission floor is the
// governed minimum (default MIN = 1000 STELL; svm.rs rejects opcode amounts
// below it), so a +101 top-up would REVERT — the minimum viable single-tx
// top-up is 1000, landing at 1999 (mirrors A's 999->1999 re-bond, comfortably
// above MIN+buffer=1100).
const STAKE_B: u64 = 1_000 * STELL;
const KEYS_FILE: &str = "/tmp/w10_3_keys.json";
// 15-minute receipt budget per tx (brief demands >= 10 min).
const WAIT_ITERS: u32 = 900;

fn rpc_url() -> String {
    std::env::var("RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8546".to_string())
}

fn rpc_call(method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
    let url = rpc_url();
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    })
    .to_string();
    let resp: serde_json::Value = ureq::post(&url)
        .send_string(&body)
        .with_context(|| format!("RPC {method} unreachable at {url}"))?
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
    // Explicit envelope (carries pubkey): correct for first-send pin-from-None
    // AND for long-registered accounts; matches what the faucet itself builds.
    let from = derive_pq_address(PqScheme::Falcon512, key.public_key(), &DEFAULT_SALT);
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
    let envelope = PqSignatureEnvelope::new_explicit(
        PqScheme::Falcon512,
        key.public_key().to_vec(),
        sig_bytes,
    );
    tx.signature = envelope.encode();
    tx
}

fn send_tx(
    key: &FalconKeypair,
    to: [u8; 32],
    amount: u64,
    gas: u64,
    nonce: u64,
    payload: Vec<OpCode>,
) -> Result<String> {
    let tx = build_pq_tx(key, to, amount, gas, nonce, payload);
    let raw = hex::encode(bincode::serialize(&tx)?);
    let res = rpc_call("stell_sendRawTransaction", serde_json::json!({ "tx": raw }))?;
    res.as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("sendRaw returned non-string: {res}"))
}

fn wait_for_tx(tag: &str, tx_hash: &str) -> Result<u64> {
    print!("    [{tag}] waiting for {tx_hash} ");
    std::io::stdout().flush().ok();
    for i in 1..=WAIT_ITERS {
        sleep(Duration::from_secs(1));
        if i % 30 == 0 {
            print!("{i}s.");
            std::io::stdout().flush().ok();
        }
        let res = rpc_call(
            "stell_getTransactionReceipt",
            serde_json::json!({ "hash": tx_hash }),
        );
        if let Ok(val) = res {
            if let Some(status) = val.get("status").and_then(|s| s.as_str()) {
                if status == "success" {
                    let h = val
                        .get("height")
                        .or_else(|| val.get("block_number"))
                        .and_then(|b| {
                            b.as_u64()
                                .or_else(|| b.as_str().and_then(|s| s.parse::<u64>().ok()))
                        })
                        .unwrap_or(0);
                    println!(" FINALIZED at #{h}");
                    return Ok(h);
                } else if status == "failed" {
                    println!(" FAILED on-chain. receipt={val}");
                    return Err(anyhow!("tx {tx_hash} failed on-chain: {val}"));
                }
            }
        }
    }
    println!(" TIMEOUT after {WAIT_ITERS}s");
    Err(anyhow!("timeout waiting for {tx_hash}"))
}

fn balance_of(addr_hex: &str) -> Result<(u64, u64)> {
    let v = rpc_call(
        "stell_getBalance",
        serde_json::json!({ "address": addr_hex }),
    )?;
    let bal = v["balance"]
        .as_str()
        .and_then(|s| s.parse::<u64>().ok())
        .or_else(|| v["balance"].as_u64())
        .unwrap_or(0);
    let nonce = v["nonce"].as_u64().unwrap_or(0);
    Ok((bal, nonce))
}

fn stake_of(val_hex: &str) -> Result<u64> {
    let v = rpc_call("stell_stakeOf", serde_json::json!({ "validator": val_hex }))?;
    v["total"]
        .as_str()
        .and_then(|s| s.parse::<u64>().ok())
        .or_else(|| v["total"].as_u64())
        .ok_or_else(|| anyhow!("bad stakeOf reply: {v}"))
}

fn print_validators(tag: &str) -> Result<()> {
    let v = rpc_call("stell_getValidators", serde_json::json!({}))?;
    println!(
        "--- validator set ({tag}) ---\n{}",
        serde_json::to_string_pretty(&v)?
    );
    Ok(())
}

struct Helpers {
    keys: Vec<FalconKeypair>,
    addrs: Vec<String>,
}

fn load_or_create_helpers() -> Result<(Helpers, bool)> {
    if let Ok(data) = std::fs::read(KEYS_FILE) {
        let v: serde_json::Value = serde_json::from_slice(&data)?;
        let mut keys = Vec::new();
        let mut addrs = Vec::new();
        if let Some(arr) = v["seeds"].as_array() {
            for sk in arr {
                let bytes: [u8; 32] = hex::decode(sk.as_str().unwrap_or(""))
                    .context("bad saved seed hex")?
                    .try_into()
                    .map_err(|_| anyhow!("saved seed not 32 bytes"))?;
                let key = FalconKeypair::generate_from_seed_bytes(&bytes);
                addrs.push(hex::encode(derive_pq_address(
                    PqScheme::Falcon512,
                    key.public_key(),
                    &DEFAULT_SALT,
                )));
                keys.push(key);
            }
        }
        if keys.len() == 5 {
            println!("resumed 5 helpers from {KEYS_FILE}");
            return Ok((Helpers { keys, addrs }, true));
        }
        println!("key file has {} keys, regenerating", keys.len());
    }
    // Fresh OS-entropy seeds (32 bytes each); keys re-derived deterministically
    // via generate_from_seed_bytes so a rerun can resume from the saved seeds.
    use std::io::Read as _;
    let mut f = std::fs::File::open("/dev/urandom").context("no /dev/urandom")?;
    let mut raw = vec![0u8; 160];
    f.read_exact(&mut raw).context("short urandom read")?;
    let mut keys = Vec::new();
    let mut addrs = Vec::new();
    let mut secs = Vec::new();
    for i in 0..5 {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&raw[i * 32..(i + 1) * 32]);
        let k = FalconKeypair::generate_from_seed_bytes(&seed);
        addrs.push(hex::encode(derive_pq_address(
            PqScheme::Falcon512,
            k.public_key(),
            &DEFAULT_SALT,
        )));
        secs.push(hex::encode(seed));
        keys.push(k);
    }
    let doc = serde_json::json!({ "seeds": secs });
    std::fs::write(KEYS_FILE, serde_json::to_vec(&doc)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(KEYS_FILE, std::fs::Permissions::from_mode(0o600))?;
    }
    for (i, a) in addrs.iter().enumerate() {
        println!("  helper[{i}] = {a}");
    }
    Ok((Helpers { keys, addrs }, false))
}

fn faucet_keypair() -> Result<FalconKeypair> {
    let seed_hex = std::env::var("FAUCET_SEED").map_err(|_| anyhow!("FAUCET_SEED env missing"))?;
    let seed: [u8; 32] = hex::decode(seed_hex.trim())
        .context("FAUCET_SEED not hex")?
        .try_into()
        .map_err(|_| anyhow!("FAUCET_SEED not 32 bytes"))?;
    Ok(FalconKeypair::generate_from_seed_bytes(&seed))
}

fn fund_helpers(h: &Helpers, fk: &FalconKeypair, faucet_addr: &str) -> Result<()> {
    let (fbal, mut fnonce) = balance_of(faucet_addr)?;
    println!(
        "faucet account shard-0 balance={} nonce={fnonce}",
        fbal as f64 / STELL as f64
    );
    if fbal < 5_100 * STELL {
        return Err(anyhow!("faucet shard-0 balance too low: {fbal}"));
    }
    // Reconcile: our key file may predate some spends; live-read is authoritative
    // only if no other writer exists (single-writer: this script).
    for (i, addr) in h.addrs.iter().enumerate() {
        let (bal, _) = balance_of(addr)?;
        if bal >= DRIP - STELL {
            println!(
                "  helper[{i}] already funded ({})",
                bal as f64 / STELL as f64
            );
            continue;
        }
        let (_, live_nonce) = balance_of(faucet_addr)?;
        if live_nonce != fnonce {
            println!("  faucet nonce moved on-chain ({fnonce}->{live_nonce}), adopting");
            fnonce = live_nonce;
        }
        let to: [u8; 32] = hex::decode(addr)?.try_into().unwrap();
        println!("  drip 1000 -> helper[{i}] (faucet nonce {fnonce})...");
        let hash = send_tx(fk, to, DRIP, 350_000, fnonce, vec![])?;
        fnonce += 1;
        wait_for_tx(&format!("drip-H{i}"), &hash)?;
    }
    Ok(())
}

fn consolidate(h: &Helpers) -> Result<()> {
    // H0->H1 (A pot), H2->H4 and H3->H4 (D pot). helper roles:
    // A-pot: H0 source, H1 staker. D-pot: H2,H3 sources, H4 staker.
    let jobs = [(0usize, 1usize), (2, 4), (3, 4)];
    for (s, d) in jobs {
        let (sbal, snonce) = balance_of(&h.addrs[s])?;
        let (dbal, _) = balance_of(&h.addrs[d])?;
        if sbal < CONSOLIDATE {
            if dbal >= DRIP {
                println!("  H{s}->H{d}: source low ({sbal}) but dest already has {dbal}, skipping");
                continue;
            }
            return Err(anyhow!(
                "H{s} balance {sbal} < 999 STELL and dest not funded; abort"
            ));
        }
        if dbal >= 2_900 * STELL {
            println!("  H{s}->H{d}: dest already consolidated ({dbal}), skipping");
            continue;
        }
        let to: [u8; 32] = hex::decode(&h.addrs[d])?.try_into().unwrap();
        println!("  consolidate H{s}->H{d} 999 (nonce {snonce})...");
        let hash = send_tx(&h.keys[s], to, CONSOLIDATE, 350_000, snonce, vec![])?;
        wait_for_tx(&format!("consol-H{s}H{d}"), &hash)?;
    }
    Ok(())
}

fn stake_a(h: &Helpers) -> Result<()> {
    let before = stake_of(VAL_A)?;
    println!("stakeOf(A) before = {}", before as f64 / STELL as f64);
    if before >= 1_999 * STELL {
        println!("A already re-bonded, skipping");
        return print_validators("after-A-skip");
    }
    let (bal, nonce) = balance_of(&h.addrs[1])?;
    println!("H1 balance={} nonce={nonce}", bal as f64 / STELL as f64);
    if bal < STAKE_A {
        return Err(anyhow!("H1 balance {bal} < 1000 STELL; fund first"));
    }
    let val: [u8; 32] = hex::decode(VAL_A)?.try_into().unwrap();
    let payload = vec![OpCode::SysCallStake {
        validator: val,
        amount: STAKE_A,
    }];
    println!("submitting SysCallStake A +1000...");
    // NOTE (W10.5-retry5): tx `amount` MUST be 0 for stake txs. The bond is
    // debited by the opcode alone (pinned by
    // `bonding_moves_real_funds_and_grants_validator_power`); a nonzero
    // `amount` is a second, native debit to `to` (here the zero address),
    // i.e. it BURNS an extra STAKE_A on top of bonding it. stakeA only
    // landed because H1 had been over-funded past the double debit.
    let hash = send_tx(&h.keys[1], [0u8; 32], 0, 500_000, nonce, payload)?;
    let hgt = wait_for_tx("stake-A", &hash)?;
    println!("stake-A tx {hash} finalized at #{hgt}");
    sleep(Duration::from_secs(10));
    let after = stake_of(VAL_A)?;
    println!("stakeOf(A) after = {}", after as f64 / STELL as f64);
    print_validators("after-A")?;
    if after < 1_999 * STELL {
        return Err(anyhow!("A top-up did not land (after={after})"));
    }
    Ok(())
}

fn stake_d(h: &Helpers) -> Result<()> {
    let before = stake_of(VAL_D)?;
    println!("stakeOf(D) before = {}", before as f64 / STELL as f64);
    if before >= 2_000 * STELL {
        println!("D already staked, skipping");
        return print_validators("after-D-skip");
    }
    let (bal, nonce) = balance_of(&h.addrs[4])?;
    println!("H4 balance={} nonce={nonce}", bal as f64 / STELL as f64);
    if bal < STAKE_D {
        return Err(anyhow!("H4 balance {bal} < 2000 STELL; fund first"));
    }
    let val: [u8; 32] = hex::decode(VAL_D)?.try_into().unwrap();
    let payload = vec![OpCode::SysCallStake {
        validator: val,
        amount: STAKE_D,
    }];
    println!("submitting SysCallStake D +2000...");
    // NOTE (W10.5-retry5): tx `amount` MUST be 0 for stake txs (see stake_a
    // note): the opcode debits the bond, a nonzero `amount` would burn an
    // extra STAKE_D to the zero address and price H4 (2998) out of the tx.
    // Gas 1M: admission floor is base_fee (280k live) + the D2 failure bond
    // (280k/step) left by the reverted double-debit attempt, so the old 500k
    // limit no longer clears it. The block path charges the consumed gas
    // against this limit; the extra headroom costs ~nothing (H4 holds 2998).
    let hash = send_tx(&h.keys[4], [0u8; 32], 0, 1_000_000, nonce, payload)?;
    let hgt = wait_for_tx("stake-D", &hash)?;
    println!("stake-D tx {hash} finalized at #{hgt}");
    sleep(Duration::from_secs(10));
    let after = stake_of(VAL_D)?;
    println!("stakeOf(D) after = {}", after as f64 / STELL as f64);
    print_validators("after-D")?;
    if after < 2_000 * STELL {
        return Err(anyhow!("D stake did not land (after={after})"));
    }
    Ok(())
}

fn stake_b(h: &Helpers, fk: &FalconKeypair, faucet_addr: &str) -> Result<()> {
    // W10.6-retry: re-bond ejected Node B. Staker = H3 (fresh 1000.0, nonce 0
    // after the A/D runs; topped up from the faucet so stake+gas clears).
    let before = stake_of(VAL_B)?;
    println!("stakeOf(B) before = {}", before as f64 / STELL as f64);
    if before >= 1_999 * STELL {
        println!("B already re-bonded, skipping");
        return print_validators("after-B-skip");
    }
    let need = STAKE_B + STELL; // stake opcode debit + gas headroom
    let (bal, _) = balance_of(&h.addrs[3])?;
    println!(
        "H3 balance={} nonce=? need>={}",
        bal as f64 / STELL as f64,
        need as f64 / STELL as f64
    );
    if bal < need {
        let top = need - bal + STELL;
        let (_, live_nonce) = balance_of(faucet_addr)?;
        let to: [u8; 32] = hex::decode(&h.addrs[3])?.try_into().unwrap();
        println!(
            "topping up H3 by {} (faucet nonce {live_nonce})...",
            top as f64 / STELL as f64
        );
        let (_, faucet_nonce_now) = balance_of(faucet_addr)?;
        let hash = send_tx(fk, to, top, 350_000, faucet_nonce_now, vec![])?;
        wait_for_tx("topup-H3", &hash)?;
    }
    let (bal2, nonce3) = balance_of(&h.addrs[3])?;
    println!(
        "H3 funded balance={} nonce={nonce3}",
        bal2 as f64 / STELL as f64
    );
    if bal2 < STAKE_B {
        return Err(anyhow!(
            "H3 balance {bal2} < 1000 STELL after top-up; abort"
        ));
    }
    let val: [u8; 32] = hex::decode(VAL_B)?.try_into().unwrap();
    let payload = vec![OpCode::SysCallStake {
        validator: val,
        amount: STAKE_B,
    }];
    println!("submitting SysCallStake B +1000 (tx amount=0, gas=1M, shard 0/0)...");
    // tx `amount` MUST be 0 (value travels via the opcode; nonzero burns extra
    // to the zero address). Gas 1M: admission floor is base_fee + failure-bond
    // residue, same as the D2 bond.
    let hash = send_tx(&h.keys[3], [0u8; 32], 0, 1_000_000, nonce3, payload)?;
    let hgt = wait_for_tx("stake-B", &hash)?;
    println!("stake-B tx {hash} finalized at #{hgt}");
    sleep(Duration::from_secs(10));
    let after = stake_of(VAL_B)?;
    println!("stakeOf(B) after = {}", after as f64 / STELL as f64);
    print_validators("after-B")?;
    if after < 1_999 * STELL {
        return Err(anyhow!("B top-up did not land (after={after})"));
    }
    Ok(())
}

fn main() -> Result<()> {
    let stage = std::env::args().nth(1).unwrap_or_else(|| "all".to_string());
    println!("W10.3 rebond: stage={stage} rpc={}", rpc_url());
    let fk = faucet_keypair()?;
    let faucet_addr = hex::encode(derive_pq_address(
        PqScheme::Falcon512,
        fk.public_key(),
        &DEFAULT_SALT,
    ));
    println!("faucet account (shard-0 scope): {faucet_addr}");
    print_validators("before")?;
    println!(
        "stakeOf(A)={} stakeOf(D)={} stakeOf(B)={}",
        stake_of(VAL_A)? as f64 / STELL as f64,
        stake_of(VAL_D)? as f64 / STELL as f64,
        stake_of(VAL_B)? as f64 / STELL as f64
    );
    let (h, _resumed) = load_or_create_helpers()?;
    for (i, a) in h.addrs.iter().enumerate() {
        let (b, n) = balance_of(a)?;
        println!(
            "  helper[{i}] {a} balance={} nonce={n}",
            b as f64 / STELL as f64
        );
    }
    match stage.as_str() {
        "check" => {
            let (fbal, fnonce) = balance_of(&faucet_addr)?;
            println!(
                "faucet shard-0 PQ balance={} nonce={fnonce}",
                fbal as f64 / STELL as f64
            );
            // Also probe the ed25519 form (in case genesis predates pure-PQ).
            let seed_hex = std::env::var("FAUCET_SEED").unwrap();
            let seed: [u8; 32] = hex::decode(seed_hex.trim())?.try_into().unwrap();
            let ed = ed25519_dalek::SigningKey::from_bytes(&seed)
                .verifying_key()
                .to_bytes();
            let ed_hex = hex::encode(ed);
            let (ebal, enonce) = balance_of(&ed_hex)?;
            println!(
                "faucet shard-0 ED address={ed_hex} balance={} nonce={enonce}",
                ebal as f64 / STELL as f64
            );
        }
        "fund" => {
            fund_helpers(&h, &fk, &faucet_addr)?;
            consolidate(&h)?;
        }
        "stakeA" => stake_a(&h)?,
        "stakeD" => stake_d(&h)?,
        "stakeB" => stake_b(&h, &fk, &faucet_addr)?,
        "all" => {
            fund_helpers(&h, &fk, &faucet_addr)?;
            consolidate(&h)?;
            stake_a(&h)?;
            stake_d(&h)?;
            // Final report + shred secrets.
            print_validators("final")?;
            let zeros = serde_json::json!({ "seeds": ["00","00","00","00","00"] });
            std::fs::write(KEYS_FILE, serde_json::to_vec(&zeros)?)?;
            std::fs::remove_file(KEYS_FILE)?;
            println!("helper key file shredded.");
        }
        _ => return Err(anyhow!("unknown stage {stage}")),
    }
    Ok(())
}
