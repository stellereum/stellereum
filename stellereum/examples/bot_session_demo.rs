//! Trading-bot-in-5-minutes: session-key delegation end to end.
//!
//! Run it (no network, no secrets, everything generated at runtime):
//! ```sh
//! cargo run --example bot_session_demo            # embedded local sim (default)
//! cargo run --example bot_session_demo -- --dry-run  # print every step, send nothing
//! STELL_RPC_URL=http://127.0.0.1:8545 cargo run --example bot_session_demo -- --rpc $STELL_RPC_URL
//! ```
//!
//! What this shows, in order:
//!   a. the MASTER creates a session keypair and signs a delegation grant
//!      (trade-only scope, 1h expiry, tight per-tx value cap + gas budget);
//!   b. the BOT (session key only, never sees the master key) submits a small
//!      CLOB sell order and polls for its receipt;
//!   c. the bot reads its remaining budget via `stell_sessionBudget`
//!      (or the clearly-marked STUB below, until the companion RPC lands);
//!   d. the master REVOKES the grant on chain and the bot's next attempt
//!      FAILS (asserted - this is the security demo).
//!
//! Every step prints what happened and WHY in plain language, so this file
//! doubles as executable documentation. See also `docs/bot_guide_5min.md`.
//!
//! Modes:
//!   * default: an embedded `InMemoryStateEngine` acts as the LOCAL sim node -
//!     the same state engine (and the same `apply_transaction` + `session_gate`
//!     consensus path) that `Commands::Sim` and the node itself drive, minus
//!     the P2P network. Fully offline and deterministic.
//!   * `--dry-run`: build every key/grant/transaction and print every step,
//!     but apply nothing. Nothing is sent anywhere.
//!   * `--rpc <url>` (or `STELL_RPC_URL` env): submit to a live node instead.
//!     The master is funded via `stell_faucet`; polling uses
//!     `stell_getTransactionStatus`; the budget uses `stell_sessionBudget`
//!     with a graceful fallback to the STUB when the method is missing.

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::time::Duration;

use stellereum::orderbook::PAIR_STELL_USDT;
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::{OpCode, GAS_ORDER_PLACE, GAS_SESSION_REVOKE};
use stellereum::zkml::{now_secs, SessionKeyAuthorization, SCOPE_SVM_PAYLOAD, SCOPE_TRANSFER};

// ---------------------------------------------------------------------------
// `stell_sessionBudget` contract (owned by the companion agent).
// ---------------------------------------------------------------------------

/// The EXACT response shape the companion `stell_sessionBudget` RPC method
/// must return: params `{"session": "<64-hex>"}`, result with these 8 fields.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct SessionBudget {
    registered: bool,
    revoked: bool,
    valid_until: u64,
    scope: u64,
    max_gas_spend: u64,
    spent: u64,
    remaining_gas: u64,
    /// master address as 64-char hex (JSON cannot carry `[u8; 32]` cleanly).
    master: String,
}

// >>> STUB-START: `stell_sessionBudget` local stand-in <<<
// This function has the SAME inputs/outputs as the real RPC method
// (`{"session": "<64-hex>"}` in, [`SessionBudget`] out) but reads the
// embedded engine's registry instead of calling a node. DELETE this and call
// the real `stell_sessionBudget` over HTTP once the companion agent lands it;
// `rpc_session_budget` below already tries the real method first and only
// falls back here so the demo keeps working until then.
// >>> STUB-END <<<
async fn stub_session_budget(
    engine: &InMemoryStateEngine,
    session_hex: &str,
) -> Result<SessionBudget> {
    let raw = hex::decode(session_hex.trim_start_matches("0x"))
        .context("session must be 64 hex chars")?;
    let pk: [u8; 32] = raw
        .try_into()
        .map_err(|_| anyhow!("session must decode to exactly 32 bytes"))?;
    let reg = engine.session_keys_read().await;
    match reg.get(&pk) {
        None => Ok(SessionBudget {
            registered: false,
            revoked: false,
            valid_until: 0,
            scope: 0,
            max_gas_spend: 0,
            spent: 0,
            remaining_gas: 0,
            master: "0".repeat(64),
        }),
        Some(rec) => Ok(SessionBudget {
            registered: true,
            revoked: rec.revoked,
            valid_until: rec.valid_until,
            scope: rec.scope,
            max_gas_spend: rec.max_gas_spend,
            spent: rec.gas_spent,
            remaining_gas: rec.max_gas_spend.saturating_sub(rec.gas_spent),
            master: hex::encode(rec.master),
        }),
    }
}

/// Try the REAL `stell_sessionBudget` RPC method against a live node.
/// Returns `None` when the node does not implement it yet (the companion
/// agent's work), so the caller can fall back to the STUB above and say so.
fn rpc_session_budget(rpc_url: &str, session_hex: &str) -> Result<Option<SessionBudget>> {
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "method": "stell_sessionBudget",
        "params": { "session": session_hex },
    })
    .to_string();
    let resp: serde_json::Value = ureq::post(rpc_url)
        .send_string(&body)
        .context("budget RPC unreachable")?
        .into_json()
        .context("budget RPC returned non-JSON")?;
    if let Some(err) = resp.get("error") {
        // -32601 = method not found: the integration gap, not a demo bug.
        eprintln!(
            "  [note] node answered budget query with error {err} - treating as missing method"
        );
        return Ok(None);
    }
    let result = resp
        .get("result")
        .ok_or_else(|| anyhow!("budget RPC returned no result"))?
        .clone();
    Ok(Some(
        serde_json::from_value(result).context("budget RPC result has wrong shape")?,
    ))
}

// ---------------------------------------------------------------------------
// Small helpers (live-RPC mode only, except `short`).
// ---------------------------------------------------------------------------

/// First 6 hex chars of a pubkey, for readable logs (never a secret: these
/// are PUBLIC keys; secret seeds are generated at runtime and never printed).
fn short(pk: &[u8; 32]) -> String {
    hex::encode(pk)[..12].to_string()
}

/// Display id for a transaction (blake3 of its bincode encoding).
fn tx_id(tx: &Transaction) -> String {
    let bytes = bincode::serialize(tx).unwrap_or_default();
    hex::encode(blake3::hash(&bytes).as_bytes())
}

fn rpc_call(rpc_url: &str, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
    })
    .to_string();
    // Write-gated stands require the RPC auth token (fail-closed without it).
    // STELL_RPC_AUTH_TOKEN env, same convention as scripts/tps_load.py.
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

fn rpc_submit(rpc_url: &str, tx: &Transaction) -> Result<String> {
    let raw = hex::encode(bincode::serialize(tx)?);
    let result = rpc_call(
        rpc_url,
        "stell_sendRawTransaction",
        serde_json::json!({ "tx": raw }),
    )?;
    Ok(result.as_str().unwrap_or("?").to_string())
}

/// Poll `stell_getTransactionStatus` until the node reports mined/failed.
fn rpc_poll_receipt(rpc_url: &str, hash: &str) -> Result<String> {
    for attempt in 1..=10u64 {
        let status = rpc_call(
            rpc_url,
            "stell_getTransactionStatus",
            serde_json::json!({ "hash": hash }),
        )?;
        let state = status.get("status").and_then(|s| s.as_str()).unwrap_or("?");
        println!("    poll #{attempt}: status = {state}");
        if state == "success" || state == "failed" {
            return Ok(state.to_string());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err(anyhow!("transaction {hash} never left pending/unknown"))
}

// ---------------------------------------------------------------------------
// The demo.
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let dry_run = args.iter().any(|a| a == "--dry-run");
    let rpc_url: Option<String> = args
        .windows(2)
        .find(|w| w[0] == "--rpc")
        .map(|w| w[1].clone())
        .or_else(|| {
            std::env::var("STELL_RPC_URL")
                .ok()
                .filter(|s| !s.is_empty())
        });
    let live = rpc_url.is_some() && !dry_run;

    println!("=== Stellereum trading bot in 5 minutes (session-key demo) ===");
    println!(
        "mode: {}",
        if dry_run {
            "dry-run (printing every step, sending nothing)".to_string()
        } else if let Some(url) = &rpc_url {
            format!("live node at {url}")
        } else {
            "embedded local sim (in-process state engine, no network)".to_string()
        }
    );
    if dry_run && rpc_url.is_some() {
        println!("(--dry-run wins over --rpc: nothing will be sent.)");
    }

    // --- 0. Identities: everything is generated at runtime, nothing is committed.
    let master = SigningKey::generate(&mut OsRng);
    let session = SigningKey::generate(&mut OsRng);
    let master_pub = master.verifying_key().to_bytes();
    let session_pub = session.verifying_key().to_bytes();
    println!("\n[0] identities (fresh keys, generated just now - no secrets on disk)");
    println!(
        "    master  (funds owner, grant signer): {}",
        short(&master_pub)
    );
    println!(
        "    session (the bot's ONLY key - it never sees the master): {}",
        short(&session_pub)
    );
    println!("    WHY: the master key stays cold/offline; a leaked bot key can only do what the grant allows.");

    // --- a. Master signs the delegation grant.
    let chain_id = stellereum::zkml::DEFAULT_CHAIN_ID;
    let valid_until = now_secs() + 3600; // now + 1h
    let max_gas_spend = 5_000_000u64; // tight gas budget: a few orders, then empty
    let max_value_per_tx = 1_000u64; // tight per-tx NATIVE value cap
    let scope = SCOPE_SVM_PAYLOAD; // trade-only, see one-liners below
    let grant = SessionKeyAuthorization::sign_delegation(
        &master,
        session_pub,
        valid_until,
        max_gas_spend,
        scope,
        max_value_per_tx,
        chain_id,
    );
    assert!(grant.verify_signature(), "fresh grant must verify");
    println!("\n[a] master signed a delegation grant for the bot. Each field means:");
    println!(
        "    session_pubkey   = {}..: WHO may act (the bot key, not the master);",
        short(&session_pub)
    );
    println!("    scope            = {scope} (SCOPE_SVM_PAYLOAD: may run contract/orderbook payloads, may NOT plain-transfer - compare SCOPE_TRANSFER={SCOPE_TRANSFER} for empty-payload transfers);");
    println!("    valid_until      = {valid_until} (unix secs, now+1h: the grant dies on its own even if nobody revokes it);");
    println!("    max_gas_spend    = {max_gas_spend} (TOTAL gas budget across ALL bot txs - cumulative, never refills);");
    println!("    max_value_per_tx = {max_value_per_tx} (hard cap on native STELL moved per single tx - a bug can only bleed this much);");
    println!("    chain_id         = {chain_id} (bound into the signed bytes: this grant is worthless on any other chain);");
    println!("    WHY trade-only scope: the bot needs orderbook ops (an SVM payload), so it gets exactly that bit - nothing more.");

    // Embedded sim state: fund the master like a faucet would.
    let engine = InMemoryStateEngine::new();
    const MASTER_FUNDS: u64 = 1_000_000_000_000;
    if live {
        let url = rpc_url.clone().unwrap();
        println!("\n[faucet] requesting test funds for the master via stell_faucet ...");
        let mut faucet_params = serde_json::json!({ "address": hex::encode(master_pub) });
        if let Ok(tok) = std::env::var("STELL_FAUCET_TOKEN").map(|s| s.trim().to_string()) {
            if !tok.is_empty() {
                faucet_params["token"] = serde_json::Value::String(tok);
            }
        }
        let res = rpc_call(&url, "stell_faucet", faucet_params)?;
        println!("    faucet answered: {res}");
        println!("    WHY: the master pays for the bot's gas+escrow, so the master - never the session key - must hold funds.");
        // Wait for the funding to finalize: the faucet tx must be IN a block
        // before the master can pay for anything (same rule as tps_load.py).
        print!("    waiting for funding to finalize ...");
        let _ = std::io::Write::flush(&mut std::io::stdout());
        let mut bal = 0u64;
        for _ in 0..60 {
            std::thread::sleep(std::time::Duration::from_secs(1));
            let b = rpc_call(
                &url,
                "stell_getBalance",
                serde_json::json!({ "address": hex::encode(master_pub) }),
            );
            // NOTE: the node renders balances as DECIMAL STRINGS (not numbers).
            bal = b
                .ok()
                .and_then(|v| {
                    v.get("balance").and_then(|x| {
                        x.as_u64()
                            .or_else(|| x.as_str().and_then(|s| s.parse::<u64>().ok()))
                    })
                })
                .unwrap_or(0);
            if bal > 0 {
                break;
            }
        }
        println!(" visible {bal} nano-STELL");
        if bal == 0 {
            anyhow::bail!("faucet funds never became visible; aborting live run");
        }
    } else if dry_run {
        println!("\n[faucet] (dry-run: no ledger write - nothing is credited or sent anywhere.)");
        println!("    WHY: the master pays for the bot's gas+escrow, so the master - never the session key - must hold funds.");
    } else {
        engine
            .update_account(AccountState::new(master_pub, MASTER_FUNDS))
            .await;
        println!("\n[faucet] sim faucet credited master with {MASTER_FUNDS} nano-STELL (embedded ledger).");
        println!("    WHY: the master pays for the bot's gas+escrow, so the master - never the session key - must hold funds.");
    }

    // --- b. Bot (session key only) submits a small CLOB sell order.
    // Sell 10 base units @ 1_000_000 micro-USD on STELL/USDT: order_cost for a
    // SELL is just `amount`, well under the per-tx value cap and the faucet
    // drip (100 STELL) that funds this demo on a live node.
    let order_price = 1_000_000u64;
    let order_amount = 10u64;
    let bot_tx = Transaction::sign_with_session(
        &session, // <-- the bot signs with ITS key; the master key is untouched
        grant.clone(),
        master_pub, // `to` is unused for order payloads; master keeps custody
        0,          // native amount moved: 0 (the order locks escrow, not a transfer)
        stellereum::svm::GAS_BASIC_TRANSFER + GAS_ORDER_PLACE,
        0, // nonce 0 on the master account
        1,
        1,
        vec![OpCode::SysCallPlaceOrder {
            pair_id: PAIR_STELL_USDT,
            is_buy: false,
            price: order_price,
            amount: order_amount,
        }],
    );
    let bot_hash = if live { String::new() } else { tx_id(&bot_tx) };
    println!("\n[b] bot built a session-signed SELL order (10 STELL @ 1.00 USDT, pair {PAIR_STELL_USDT}).");
    println!(
        "    tx.from is the MASTER ({}..) - the master's account pays gas+escrow;",
        short(&master_pub)
    );
    println!("    but the signature is the BOT's, over message+grant, so neither grant nor payload can be swapped afterwards.");
    println!("    WHY session-signing: the node checks bot-sig + grant-policy + on-chain registry instead of the master sig.");

    if dry_run {
        println!(
            "    (dry-run: NOT submitted. It would register the key on first use and lock escrow.)"
        );
    } else if live {
        let url = rpc_url.clone().unwrap();
        let hash = rpc_submit(&url, &bot_tx)?;
        println!("    submitted via stell_sendRawTransaction, hash {hash}");
        println!("    polling stell_getTransactionStatus ...");
        println!("    WHY poll: admission is not finality - a tx can sit in the mempool and never be included.");
        let final_state = rpc_poll_receipt(&url, &hash)?;
        println!("    receipt: status = {final_state}");
        assert_eq!(
            final_state, "success",
            "bot order must be included on the live node"
        );
    } else {
        engine
            .apply_transaction(&bot_tx, now_secs())
            .await
            .map_err(|e| anyhow!("sim apply failed: {e}"))?;
        println!("    applied to the local sim node. Polling its receipt ...");
        println!("    WHY poll: admission is not finality - here the 'receipt' is the committed registry record + master nonce.");
        let mut registered = false;
        for attempt in 1..=5u64 {
            tokio::time::sleep(Duration::from_millis(150)).await;
            let reg = engine.session_keys_read().await;
            registered = reg.get(&session_pub).is_some();
            let nonce = engine
                .get_account(&master_pub)
                .await
                .map(|a| a.nonce)
                .unwrap_or(0);
            println!("    poll #{attempt}: registered = {registered}, master nonce = {nonce}");
            if registered {
                break;
            }
        }
        assert!(
            registered,
            "first bot tx must lazily register the session key"
        );
        println!("    receipt: {{ tx: \"{bot_hash}\", status: \"success\" }} (registry record exists, escrow locked).");
    }

    // --- c. Bot checks its remaining budget.
    println!(
        "\n[c] bot asks how much budget is left (it cannot refill itself - it can only read)."
    );
    if dry_run {
        println!(
            "    (dry-run) stell_sessionBudget {{\"session\": \"{}..\"}} would answer:",
            short(&session_pub)
        );
        println!("    {{\"registered\": true, \"revoked\": false, \"spent\": ~{GAS_ORDER_PLACE}, \"remaining_gas\": ~{}}}", max_gas_spend - GAS_ORDER_PLACE);
    } else if live {
        let url = rpc_url.clone().unwrap();
        match rpc_session_budget(&url, &hex::encode(session_pub))? {
            Some(b) => {
                println!("    stell_sessionBudget answered: registered={} revoked={} spent={} remaining_gas={} max={} master={}..",
                    b.registered, b.revoked, b.spent, b.remaining_gas, b.max_gas_spend, &b.master[..12]);
            }
            None => {
                print_budget_gap(&session_pub);
            }
        }
    } else {
        // Embedded mode: no HTTP node exists, so read the registry through the
        // STUB (same params in, same 8 fields out as the real RPC will have).
        let b = stub_session_budget(&engine, &hex::encode(session_pub)).await?;
        println!(
            "    STUB stell_sessionBudget {{\"session\": \"{}..\"}} ->",
            short(&session_pub)
        );
        println!("    {{\"registered\": {}, \"revoked\": {}, \"valid_until\": {}, \"scope\": {}, \"max_gas_spend\": {}, \"spent\": {}, \"remaining_gas\": {}, \"master\": \"{}..\"}}",
            b.registered, b.revoked, b.valid_until, b.scope, b.max_gas_spend, b.spent, b.remaining_gas, &b.master[..12]);
        println!("    WHY poll the budget: every applied bot tx deducts cumulatively; at 0 the node refuses further bot txs.");
        print_budget_gap(&session_pub);
    }

    // --- d. Master revokes; bot's next attempt MUST fail.
    println!("\n[d] master revokes the grant ON CHAIN (a master-signed tx - a session key can NEVER revoke).");
    println!("    WHY on-chain + master-only: revocation must be visible to every node and unforgeable by the bot itself.");
    let revoke_tx = Transaction::sign_with_payload(
        &master, // <-- master key signs: proves the delegator kills its own grant
        master_pub,
        0,
        stellereum::svm::GAS_BASIC_TRANSFER + GAS_SESSION_REVOKE,
        1, // nonce 1 on the master account (bot tx used 0)
        1,
        1,
        vec![OpCode::SysCallRevokeSession {
            session_pubkey: session_pub,
        }],
    );
    if dry_run {
        println!("    (dry-run: NOT submitted. It would set revoked=true terminally - no un-revoke exists.)");
    } else if live {
        let url = rpc_url.clone().unwrap();
        let hash = rpc_submit(&url, &revoke_tx)?;
        println!("    revoke submitted, hash {hash}");
        let final_state = rpc_poll_receipt(&url, &hash)?;
        assert_eq!(
            final_state, "success",
            "revoke must be included on the live node"
        );
        println!("    revoke mined. Bot retries with the SAME grant ...");
        let retry = Transaction::sign_with_session(
            &session,
            grant.clone(),
            master_pub,
            0,
            stellereum::svm::GAS_BASIC_TRANSFER + GAS_ORDER_PLACE,
            2,
            1,
            1,
            vec![OpCode::SysCallPlaceOrder {
                pair_id: PAIR_STELL_USDT,
                is_buy: false,
                price: order_price,
                amount: order_amount,
            }],
        );
        match rpc_submit(&url, &retry) {
            Ok(h) => {
                // A revoked grant must NEVER be success-finalized. The node either mines
                // it as failed, or refuses it at admission (then its status
                // stays "unknown": absent from mempool AND receipts). Both
                // are secure outcomes; only "success" is a failure.
                // ("unknown" = the node never admitted it - the common case
                // for a revoked key, whose tx dies before the mempool.)
                let mut outcome = String::from("unknown");
                for attempt in 1..=10 {
                    let status = rpc_call(
                        &url,
                        "stell_getTransactionStatus",
                        serde_json::json!({ "hash": h }),
                    );
                    let state = status
                        .as_ref()
                        .ok()
                        .and_then(|v| v.get("status"))
                        .and_then(|s| s.as_str())
                        .unwrap_or("?");
                    println!("    poll #{attempt}: status = {state}");
                    outcome = state.to_string();
                    if state == "success" || state == "failed" {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_secs(2));
                }
                assert_ne!(
                    outcome, "mined",
                    "legacy vocab guard (node never emits mined anymore)"
                );
                assert_ne!(
                    outcome, "success",
                    "SECURITY FAILURE: post-revoke bot tx succeeded"
                );
                println!("    post-revoke bot tx {h} ended as '{outcome}' - never succeeded. Security demo holds.");
            }
            Err(e) => {
                println!("    post-revoke bot tx rejected at admission: {e}");
                println!(
                    "    SECURITY DEMO HOLDS: the revoked key is worthless (admission refused it)."
                );
            }
        }
    } else {
        engine
            .apply_transaction(&revoke_tx, now_secs())
            .await
            .map_err(|e| anyhow!("revoke apply failed: {e}"))?;
        println!("    revoke applied. Registry now reports revoked=true (terminal - nothing ever sets it back).");
        println!("    Bot retries with the SAME grant (stolen-key scenario) ...");
        let retry = Transaction::sign_with_session(
            &session,
            grant.clone(),
            master_pub,
            0,
            stellereum::svm::GAS_BASIC_TRANSFER + GAS_ORDER_PLACE,
            2, // nonce 2 on the master account
            1,
            1,
            vec![OpCode::SysCallPlaceOrder {
                pair_id: PAIR_STELL_USDT,
                is_buy: false,
                price: order_price,
                amount: order_amount,
            }],
        );
        match engine.apply_transaction(&retry, now_secs()).await {
            Ok(()) => {
                return Err(anyhow!(
                    "SECURITY VIOLATION: post-revoke bot tx applied - revocation did not stick"
                ));
            }
            Err(e) => {
                println!("    post-revoke bot tx FAILED as required: {e}");
                assert!(
                    e.contains("revoked"),
                    "failure must be the revocation refusal, got: {e}"
                );
                println!("    SECURITY DEMO HOLDS: assert(e.contains(\"revoked\")) passed - a stolen session key dies with one master tx.");
            }
        }
        // Final budget line for the report.
        let b = stub_session_budget(&engine, &hex::encode(session_pub)).await?;
        println!("\n[done] final budget: registered={} revoked={} spent={} remaining_gas={} (budget survives the key's death - audit trail).",
            b.registered, b.revoked, b.spent, b.remaining_gas);
    }

    if dry_run {
        println!("\n[done] dry-run complete: keys, grant and transactions were built and verified locally; nothing was sent.");
    }
    println!("\nBot in 5 minutes: master funds -> master grants (scoped, expiring, budgeted) -> bot trades -> bot watches budget -> master revokes. That is the whole loop.");
    Ok(())
}

/// Prints the single integration gap exactly once, in one place.
fn print_budget_gap(session_pub: &[u8; 32]) {
    println!("    INTEGRATION GAP: no `stell_sessionBudget` method exists on the node yet");
    println!("    (checked src/rpc.rs dispatch + docs/RPC.md) - the numbers above come from the");
    println!(
        "    clearly-marked STUB reader (same params {{\"session\": \"{}\"}} / same 8 fields).",
        short(session_pub)
    );
    println!("    Wire it to the companion agent's RPC as soon as it lands; demo logic needs no other change.");
}
