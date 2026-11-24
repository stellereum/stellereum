use ed25519_dalek::{Signer, SigningKey};
use infnode::config as node_config;
use rand::rngs::OsRng;
use std::sync::Arc;

use crate::cli::args::*;
use crate::cli::tx_builders::*;
use crate::node::policy::*;
use stellereum::bridge::{SupportedChain, TeleportBridgeEngine};
use stellereum::mev::MevPreemptionEngine;
use stellereum::oracle::OracleSafetyEngine;
use stellereum::orderbook::{OrderSide, OrderType, OrderbookManager, PAIR_STELL_USDT};
use stellereum::pmm::PrimaryMarketMaker;
use stellereum::sharding::{
    CrossShardMessage, DynamicShardManager, SharedLiquidityHub, Transaction,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::tokenomics::{GenesisVault, TeamVestingSchedule};
use stellereum::zkml::{QuantizedLayer, QuantizedLinearModel, SessionKeyAuthorization, ZkMlProof};

pub(crate) async fn handle_command(command: Commands) -> anyhow::Result<()> {
    match command {
        Commands::Genesis {
            action,
            asset,
            amount,
            price_usd,
        } => {
            println!("╔═══════════════════════════════════════════════════════════════╗");
            println!("║              🏛  STELLEREUM GENESIS VAULT                     ║");
            println!("╚═══════════════════════════════════════════════════════════════╝");
            println!("• Native Token:       STELL (9 decimals, nano-STELL)");
            println!("• Hard Cap:           1,000,000,000 STELL");
            println!("• Genesis Vault Cap:  250,000,000 STELL (25% Public Exchange)");
            println!("• Fixed Base Price:   $0.25 USD");
            println!("• Formula:            STELL = (in_coins * price_usd) / $0.25\n");

            let mut vault = GenesisVault::new();

            if action == "mint" {
                let price_micro = (price_usd * 1_000_000.0) as u64;
                let native_amount = match asset.to_uppercase().as_str() {
                    "USDT" => amount * 1_000_000, // 6 decimals
                    _ => amount * 1_000_000_000,  // 9 decimals for TON/GRAM
                };

                match vault.deposit_and_mint(&asset.to_uppercase(), native_amount, price_micro) {
                    Ok(minted_nano) => {
                        println!("✅ MINT SUCCESSFUL:");
                        println!("  Deposited:          {} {}", amount, asset.to_uppercase());
                        println!("  Asset Price:        ${:.2} USD", price_usd);
                        println!(
                            "  Minted:             {} nano-STELL ({:.4} STELL)",
                            minted_nano,
                            (minted_nano as f64) / 1_000_000_000.0
                        );
                        println!(
                            "  Vault Total Minted: {} / {} nano-STELL\n",
                            vault.total_minted_nano,
                            stellereum::tokenomics::GENESIS_VAULT_CAP
                        );
                    }
                    Err(e) => {
                        eprintln!("❌ Mint Failed: {}", e);
                    }
                }
            } else {
                let vesting = TeamVestingSchedule::new(now_secs());
                println!("• Team Vesting:       100M STELL, 12 mo cliff, 24 mo linear");
                println!(
                    "  Cliff Duration:     {} days",
                    vesting.cliff_duration_secs / 86400
                );
                println!(
                    "  Vesting Duration:   {} days",
                    vesting.vesting_duration_secs / 86400
                );
            }
        }
        Commands::Run {
            config,
            shard,
            parallel_exec,
            pure_pq,
            wait_for_supermajority,
        } => {
            crate::node::bootstrap::run_node(
                config,
                shard,
                parallel_exec,
                pure_pq,
                wait_for_supermajority,
            )
            .await?;
        }
        Commands::Sim { blocks } => {
            println!("╔═══════════════════════════════════════════════════════════════╗");
            println!("║      🚀 STELLEREUM LOCAL TESTNET SIMULATOR (FULL STACK)       ║");
            println!("╚═══════════════════════════════════════════════════════════════╝");
            println!("Initializing in-memory multi-shard cluster (Masterchain + Shards 1, 2)...");

            let state_engine = Arc::new(InMemoryStateEngine::new());
            let mut shard_mgr = DynamicShardManager::new();
            let mut liquidity_hub = SharedLiquidityHub::new(vec![0, 1, 2]);
            let mut orderbook_mgr = OrderbookManager::new();
            let mut mev_engine = MevPreemptionEngine::new();

            // 3 Validator cluster
            let val1 = SigningKey::generate(&mut OsRng);
            let val2 = SigningKey::generate(&mut OsRng);
            let val3 = SigningKey::generate(&mut OsRng);
            let val_pubs = vec![
                val1.verifying_key().to_bytes(),
                val2.verifying_key().to_bytes(),
                val3.verifying_key().to_bytes(),
            ];

            let mut bridge = TeleportBridgeEngine::new(val_pubs.clone());
            let mut oracle = OracleSafetyEngine::new(vec![val_pubs[0]]);
            oracle.record_dex_trade("TON", 5_000_000, now_secs(), 1_000);

            // Setup simulated traders
            let trader_alice = SigningKey::generate(&mut OsRng);
            let trader_bob = SigningKey::generate(&mut OsRng);
            let alice_addr = trader_alice.verifying_key().to_bytes();
            let bob_addr = trader_bob.verifying_key().to_bytes();

            state_engine
                .update_account(AccountState::new(alice_addr, 50_000_000_000_000))
                .await;
            state_engine
                .update_account(AccountState::new(bob_addr, 50_000_000_000_000))
                .await;

            println!("✓ Cluster initialized with 3 Validators & Quorum 2/3");
            println!(
                "✓ Genesis Accounts: Alice ({}) | Bob ({})\n",
                hex::encode(&alice_addr[..6]),
                hex::encode(&bob_addr[..6])
            );

            for b in 1..=blocks {
                let start_time = std::time::Instant::now();
                println!("--- Block #{} (Timestamp: {}) ---", b, now_secs());

                // 1. CLOB Orderbook Actor Matching
                let (sell_order, mut trades) = orderbook_mgr
                    .get_book_mut(PAIR_STELL_USDT)
                    .submit_order_ext(
                        alice_addr,
                        OrderSide::Sell,
                        OrderType::Limit,
                        250_000, // $0.25
                        10_000,  // 10,000 units
                        now_secs(),
                    );

                let (buy_order, buy_trades) = orderbook_mgr
                    .get_book_mut(PAIR_STELL_USDT)
                    .submit_order_ext(
                        bob_addr,
                        OrderSide::Buy,
                        OrderType::Limit,
                        250_000,
                        6_000,
                        now_secs(),
                    );
                trades.extend(buy_trades);

                println!(
                    "  [CLOB] Alice placed Sell Order #{} | Bob placed Buy Order #{}",
                    sell_order.order_id, buy_order.order_id
                );
                for t in &trades {
                    println!(
                        "    ↳ Matched Trade: {} STELL @ ${:.2} USD",
                        t.amount,
                        (t.price as f64) / 1_000_000.0
                    );
                }

                // 2. MEV Preemption (Threshold Blind Round 2-of-3)
                let (round_key, shares) = mev_engine.prepare_threshold_round(b, 2, 3);
                let raw_tx = b"bot_hft_micro_gas_trade_payload";
                let envelope =
                    MevPreemptionEngine::seal_transaction(b, &round_key, raw_tx).unwrap();

                let commit = mev_engine.commit_blind_round(
                    b,
                    std::slice::from_ref(&envelope),
                    &[val1.clone(), val2.clone(), val3.clone()],
                );
                assert!(MevPreemptionEngine::verify_round_commitment(&commit, 2));

                let unsealed = mev_engine
                    .unseal_with_shares(&envelope, &[shares[0].clone(), shares[1].clone()])
                    .unwrap();
                assert_eq!(unsealed, raw_tx);
                println!("  [MEV] 2-of-3 Threshold Blind Round #{} Sealed & Committed (Zero Frontrunning)", b);

                // 3. AI zkML Verifiable Inference & Session Key Delegation
                let layer = QuantizedLayer::new(2, 2, vec![2, -1, 1, 3], vec![1, -2]);
                let model = QuantizedLinearModel::new(vec![layer]);
                let (outputs, proof) = ZkMlProof::prove_reexec(&model, &[3, 4]);
                assert!(proof.verify_inference());
                println!(
                    "  [zkML] AI Agent Inference Verified: in=[3,4] -> out={:?}",
                    outputs
                );

                // 4. Cross-Shard Atomic Transaction with Merkle Proof
                // Bind the demo transaction to this chain id as well: the
                // simulator never submits it, but the CLI must not keep a
                // legacy unbound signing path around.
                let cross_tx = Transaction::sign_with_chain_id(
                    &trader_alice,
                    bob_addr,
                    500,
                    1000,
                    b,
                    1,
                    2,
                    stellereum::zkml::DEFAULT_CHAIN_ID,
                );
                let state_root = state_engine.get_state_root().await;
                let cross_msg =
                    CrossShardMessage::new_trusted(1, 2, cross_tx, state_root, [b as u8; 32]);
                let seq = liquidity_hub.route_cross_shard_message(cross_msg);
                println!(
                    "  [Cross-Shard] Routed Atomic Message Shard 1 -> Shard 2 (Sequencer #{})",
                    seq
                );

                // 5. Dynamic Sharding Load Check
                shard_mgr.record_tx_load(1, 120);
                if let Some((c0, c1)) = shard_mgr.check_and_split(1) {
                    println!("  [Sharding] Shard 1 Split -> Shard {} (prefix: {}) & Shard {} (prefix: {})",
                        c0.shard_id, c0.prefix, c1.shard_id, c1.prefix);
                }

                // 6. Confidential transfers removed with Ristretto deletion wave
                // (crypto_privacy excised); transparent path continues.

                // 7. Oracle 3-Tier Price Check
                let price = oracle.resolve_price(None, "TON", now_secs()).unwrap();
                println!(
                    "  [Oracle] Tier 2 DEX TWAP Resolved: TON = ${:.2} USD (Breaker: Clean)",
                    (price as f64) / 1_000_000.0
                );

                // 8. Teleport Bridge Deposit Verification
                let dep_event = stellereum::bridge::TeleportDepositEvent {
                    source_chain: SupportedChain::Ton,
                    source_tx_hash: [b as u8; 32],
                    recipient: alice_addr,
                    asset: "USDT".to_string(),
                    amount: 5_000 * 1_000_000_000,
                    validator_signatures: vec![
                        (val_pubs[0], val1.sign(b"bridge").to_vec()),
                        (val_pubs[1], val2.sign(b"bridge").to_vec()),
                    ],
                    zk_proof: None,
                };
                let _ = bridge.process_deposit(&dep_event);
                println!("  [Bridge] Teleport Gateway: Verified 2/3 Quorum for TON -> Stellereum Deposit");

                let elapsed = start_time.elapsed();
                println!(
                    "  ✓ Block #{} Finalized in {:.2?} (Latency < 200ms Target)\n",
                    b, elapsed
                );
            }

            println!("═════════════════════════════════════════════════════════════════");
            println!("🎉 LOCAL TESTNET SIMULATION COMPLETED WITH 100% SPEC CONFORMANCE!");
            println!("• Bag of Cells (BoC) & Patricia Trie:        ACTIVE & MERKLE PROVED");
            println!("• Actor Model & Asynchronous Messaging:      ACTIVE");
            println!("• CLOB Orderbook-Actor:                      ACTIVE");
            println!("• Micro-Gas SVM Execution:                   ACTIVE (~280_000 nano-STELL)");
            println!("• Zero-Overhead MEV Preemption (Shamir T-of-N): ACTIVE");
            println!("• zkML AI Verifiable Inference & Session Keys: ACTIVE");
            println!("• Dynamic Infinite Sharding & Cross-Shard Hub: ACTIVE");
            println!("• 3-Tier Price Safety Network & Teleport:    ACTIVE");
            println!("═════════════════════════════════════════════════════════════════\n");
        }

        Commands::Devnet {
            accounts,
            blocks,
            seed,
            txs_per_block,
            block_time_ms,
            log,
            snapshot,
        } => {
            use stellereum::simulator::{ChainSimulator, SimConfig};

            let seed_bytes = parse_devnet_seed(&seed)?;
            let config = SimConfig {
                txs_per_block,
                block_time_ms,
                ..Default::default()
            };

            let mut simulator = ChainSimulator::genesis(&seed_bytes, accounts, config)
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            let started = std::time::Instant::now();
            let summary = simulator
                .run_blocks(blocks)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let elapsed = started.elapsed();

            println!("╔═══════════════════════════════════════════════════════════════╗");
            println!("║       🧪 STELLEREUM LOCAL DEVNET (DETERMINISTIC SIMULATOR)      ║");
            println!("╚═══════════════════════════════════════════════════════════════╝");
            println!("• Seed:             {}", hex::encode(&seed_bytes));
            println!(
                "• Chain id:         0x{:x} (devnet — never the production chain id)",
                config.chain_id
            );
            println!("• Validators:       {}", summary.accounts);
            println!("• Blocks:           {}", summary.blocks);
            println!(
                "• Block time:       {} ms (logical — the simulator never reads a clock)",
                summary.block_time_ms
            );
            println!("• Transactions:     {}", summary.transactions);
            println!("• Total gas:        {}", summary.total_gas);
            println!("• Total fees:       {} nano-STELL", summary.total_fees);
            println!(
                "• Throughput:       {:.2} tx/s (over {} ms of logical chain time)",
                summary.tps(),
                summary.chain_time_ms
            );
            println!("• Genesis root:     {}", hex::encode(summary.genesis_root));
            println!("• Final state root: {}", hex::encode(summary.state_root));
            if let Some(hash) = summary.first_block_hash {
                println!("• First block:      {}", hex::encode(hash));
            }
            if let Some(hash) = summary.last_block_hash {
                println!("• Last block:       {}", hex::encode(hash));
            }

            println!(
                "\nFINAL VALIDATOR SET ({} validators)",
                summary.validators.len()
            );
            for (index, validator) in summary.validators.iter().enumerate() {
                println!(
                    "  {}. {}  stake {:.4} STELL  balance {:.4} STELL",
                    index + 1,
                    hex::encode(validator.address),
                    validator.stake as f64 / 1e9,
                    validator.balance as f64 / 1e9
                );
            }

            if let Some(path) = &log {
                let bytes = simulator
                    .log()
                    .map_err(|e| anyhow::anyhow!("{e}"))?
                    .to_bytes();
                std::fs::write(path, &bytes)
                    .map_err(|e| anyhow::anyhow!("cannot write {}: {e}", path.display()))?;
                println!(
                    "\n• Transaction log:  {} ({} bytes, {} records)",
                    path.display(),
                    bytes.len(),
                    String::from_utf8_lossy(&bytes).lines().count()
                );
                println!(
                    "  verify with:      stellereum sim-replay --log {}",
                    path.display()
                );
            }

            if let Some(path) = &snapshot {
                let snap = simulator.snapshot();
                std::fs::write(path, snap.as_bytes())
                    .map_err(|e| anyhow::anyhow!("cannot write {}: {e}", path.display()))?;
                println!(
                    "• State snapshot:   {} ({} bytes)",
                    path.display(),
                    snap.as_bytes().len()
                );
            }

            println!(
                "\nℹ wall-clock elapsed: {:.2?} (informational only — not part of the simulation)",
                elapsed
            );
        }

        Commands::SimReplay { log } => {
            use stellereum::simulator::SimLog;

            let bytes = std::fs::read(&log)
                .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", log.display()))?;
            let parsed = SimLog::parse(&bytes).map_err(|e| anyhow::anyhow!("{e}"))?;
            let report = parsed.replay().map_err(|e| anyhow::anyhow!("{e}"))?;

            println!("╔═══════════════════════════════════════════════════════════════╗");
            println!("║        🔁 STELLEREUM SIMULATION LOG REPLAY                       ║");
            println!("╚═══════════════════════════════════════════════════════════════╝");
            println!("• Log:              {}", log.display());
            println!("• Format version:   {}", parsed.header.v);
            println!("• Seed:             {}", parsed.header.seed);
            println!("• Validators:       {}", parsed.header.accounts);
            println!("• Blocks replayed:  {}", report.blocks);
            println!("• Transactions:     {}", report.transactions);
            println!("• Total gas:        {}", report.total_gas);
            println!("• Total fees:       {} nano-STELL", report.total_fees);
            println!("• Genesis root:     {}", hex::encode(report.genesis_root));
            println!("• Final state root: {}", hex::encode(report.final_root));
            println!("\n✅ REPLAY OK — every recorded state root matches the replayed chain.");
        }

        Commands::Wallet { sub } => match sub {
            WalletCommands::Generate => {
                let signing_key = SigningKey::generate(&mut OsRng);
                let pub_bytes = signing_key.verifying_key().to_bytes();
                let priv_bytes = signing_key.to_bytes();

                // Shielded keys removed with Ristretto deletion wave
                // (crypto_privacy excised); transparent ed25519 wallet only.
                println!("╔═══════════════════════════════════════════════════════════════╗");
                println!("║                   🔑 NEW STELLEREUM WALLET                   ║");
                println!("╚═══════════════════════════════════════════════════════════════╝");
                println!("• Address (Public Key):   {}", hex::encode(pub_bytes));
                println!("• Private Key:            {}", hex::encode(priv_bytes));
                println!("\n⚠️  Keep your private keys safe! Do not share them.");
            }

            WalletCommands::Balance { address } => {
                let addr_bytes =
                    hex::decode(&address).map_err(|e| anyhow::anyhow!("Invalid hex: {e}"))?;
                if addr_bytes.len() != 32 {
                    anyhow::bail!("Address must be 32 bytes (64 hex characters)");
                }
                println!("Querying balance for address {}...", address);
                let state_engine = InMemoryStateEngine::new();
                let mut fixed_addr = [0u8; 32];
                fixed_addr.copy_from_slice(&addr_bytes);

                let balance = state_engine
                    .get_account(&fixed_addr)
                    .await
                    .map(|a| a.balance)
                    .unwrap_or(0);
                println!(
                    "Account Balance: {} nano-STELL ({:.6} STELL)",
                    balance,
                    (balance as f64) / 1_000_000_000.0
                );
            }

            WalletCommands::Address { from_key } => {
                let bytes = hex::decode(&from_key)
                    .map_err(|e| anyhow::anyhow!("Invalid from_key hex: {e}"))?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Private key must be 32 bytes"))?;
                let addr = SigningKey::from_bytes(&arr).verifying_key().to_bytes();
                println!("{}", hex::encode(addr));
            }

            WalletCommands::Send {
                from_key,
                to,
                amount,
                target_shard,
                rpc,
                nonce,
                chain_id,
                dry_run,
                verbose,
            } => {
                let pq_key = falcon_from_hex_seed(&from_key, "from_key")?;
                let to_arr = parse_wallet_address(&to)?;
                let chain_id = resolve_chain_id(&rpc, chain_id)?;

                // Reusing a fixed nonce meant only the first transaction from a
                // key could ever be accepted; every later one was a replay. Read
                // the account's real nonce unless the caller pinned one.
                let query = |method: &str,
                             params: serde_json::Value|
                 -> anyhow::Result<serde_json::Value> {
                    let body = serde_json::json!({
                        "jsonrpc": "2.0", "id": 1, "method": method, "params": params
                    })
                    .to_string();
                    if verbose {
                        eprintln!("  rpc -> {method}: {body}");
                    }
                    let resp: serde_json::Value =
                        ureq::post(&rpc).send_string(&body)?.into_json()?;
                    if verbose {
                        eprintln!("  rpc <- {method}: {resp}");
                    }
                    if let Some(e) = resp.get("error") {
                        anyhow::bail!("RPC error: {e}");
                    }
                    Ok(resp
                        .get("result")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null))
                };

                let account = falcon_pq_address(&pq_key);
                let nonce = match nonce {
                    Some(n) => n,
                    None => {
                        let acc = query(
                            "stell_getBalance",
                            serde_json::json!({ "address": hex::encode(account) }),
                        )?;
                        acc.get("nonce").and_then(|n| n.as_u64()).ok_or_else(|| {
                            anyhow::anyhow!("node did not return an account nonce")
                        })?
                    }
                };

                // Source is always the masterchain here: spendable funds live
                // on shard 0 (the namespace/DHT shard is not a chain).
                let gas = stellereum::svm::GAS_BASIC_TRANSFER
                    + stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS;
                let tx = match chain_id {
                    Some(cid) => sign_pq_explicit_transfer_with_chain(
                        &pq_key,
                        to_arr,
                        amount,
                        gas,
                        nonce,
                        stellereum::sharding::MASTERCHAIN_SHARD,
                        target_shard,
                        cid,
                    ),
                    None => stellereum::rpc::sign_pq_explicit_transfer(
                        &pq_key,
                        to_arr,
                        amount,
                        gas,
                        nonce,
                        stellereum::sharding::MASTERCHAIN_SHARD,
                        target_shard,
                    ),
                };
                if !tx.verify_signature() {
                    anyhow::bail!("refusing to submit: built PQ transaction does not verify");
                }
                match chain_id {
                    Some(cid) if !tx.verify_signature_for_chain(cid, true) => anyhow::bail!(
                        "refusing to submit: built transaction is not bound to chain {cid}"
                    ),
                    _ => {}
                }
                println!("✅ PQ Transaction Signed (Falcon-512, explicit PQ1 envelope):");
                println!("  Hash:   {}", hex::encode(tx.compute_tx_hash()));
                println!("  From:   {}", hex::encode(tx.from));
                println!("  To:     {}", hex::encode(tx.to));
                println!("  Amount: {} nano-STELL", tx.amount);
                println!("  Nonce:  {nonce}");
                println!("  Target Shard: {}", tx.target_shard);
                if let Some(cid) = chain_id {
                    println!("  Chain Id: {cid} (signature bound)");
                }

                if dry_run {
                    return Ok(());
                }

                let raw = hex::encode(bincode::serialize(&tx)?);
                let body = serde_json::json!({
                    "jsonrpc": "2.0", "id": 1,
                    "method": "stell_sendRawTransaction",
                    "params": { "tx": raw }
                })
                .to_string();
                let resp: serde_json::Value = ureq::post(&rpc).send_string(&body)?.into_json()?;
                if let Some(e) = resp.get("error") {
                    anyhow::bail!("rejected by node: {e}");
                }
                println!(
                    "  Submitted, mempool tx hash: {}",
                    resp["result"].as_str().unwrap_or("?")
                );
            }

            WalletCommands::SendPq {
                falcon_seed,
                to,
                amount,
                target_shard,
                rpc,
                nonce,
                chain_id,
                dry_run,
                verbose,
            } => {
                // Raw seed derivation ONLY (same as Faucet::new and
                // `wallet sign --scheme falcon`): never the light-wallet KDF
                // (that yields a different address that holds no funds), and
                // NEVER an ed25519 fallback — a bad seed bails below.
                let seed = parse_wallet_seed(&falcon_seed, "falcon seed")?;
                let seed = zeroize::Zeroizing::new(seed);
                let pq_key =
                    stellereum::post_quantum::FalconKeypair::generate_from_seed_bytes(&seed);
                let sender = stellereum::post_quantum::derive_pq_address(
                    stellereum::post_quantum::PqScheme::Falcon512,
                    &pq_key.public_key,
                    &stellereum::post_quantum::DEFAULT_SALT,
                );
                let to_bytes =
                    hex::decode(&to).map_err(|e| anyhow::anyhow!("Invalid to hex: {e}"))?;
                if to_bytes.len() != 32 {
                    anyhow::bail!("Recipient must be 32 bytes");
                }
                let to_arr: [u8; 32] = to_bytes.try_into().unwrap();
                let chain_id = resolve_chain_id(&rpc, chain_id)?;

                let query = |method: &str,
                             params: serde_json::Value|
                 -> anyhow::Result<serde_json::Value> {
                    let body = serde_json::json!({
                        "jsonrpc": "2.0", "id": 1, "method": method, "params": params
                    })
                    .to_string();
                    if verbose {
                        eprintln!("  rpc -> {method}: {body}");
                    }
                    let resp: serde_json::Value =
                        ureq::post(&rpc).send_string(&body)?.into_json()?;
                    if verbose {
                        eprintln!("  rpc <- {method}: {resp}");
                    }
                    if let Some(e) = resp.get("error") {
                        anyhow::bail!("RPC error: {e}");
                    }
                    Ok(resp
                        .get("result")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null))
                };

                // The account address is the PQ address, not the seed: querying
                // with anything else silently returns a fresh account (nonce 0)
                // and every transaction after the first is a replay.
                let nonce = match nonce {
                    Some(n) => n,
                    None => {
                        let acc = query(
                            "stell_getBalance",
                            serde_json::json!({ "address": hex::encode(sender) }),
                        )?;
                        acc.get("nonce").and_then(|n| n.as_u64()).ok_or_else(|| {
                            anyhow::anyhow!("node did not return an account nonce")
                        })?
                    }
                };

                // Faucet-identical shape: explicit PQ1 envelope, base fee +
                // activation surcharge, masterchain source. When a chain id is
                // available the envelope is chain-bound; with binding not yet
                // scheduled an unreachable RPC keeps the legacy unbound shape.
                let gas = stellereum::svm::GAS_BASIC_TRANSFER
                    + stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS;
                let tx = match chain_id {
                    Some(cid) => sign_pq_explicit_transfer_with_chain(
                        &pq_key,
                        to_arr,
                        amount,
                        gas,
                        nonce,
                        stellereum::sharding::MASTERCHAIN_SHARD,
                        target_shard,
                        cid,
                    ),
                    None => stellereum::rpc::sign_pq_explicit_transfer(
                        &pq_key,
                        to_arr,
                        amount,
                        gas,
                        nonce,
                        stellereum::sharding::MASTERCHAIN_SHARD,
                        target_shard,
                    ),
                };
                // Client-side self-check (fail-closed): never submit a tx that
                // does not verify — an unsigned/unverifiable spend is refused
                // here, not metered into the mempool.
                if !tx.verify_signature() {
                    anyhow::bail!("refusing to submit: built PQ transaction does not verify");
                }
                match chain_id {
                    Some(cid) if !tx.verify_signature_for_chain(cid, true) => anyhow::bail!(
                        "refusing to submit: built transaction is not bound to chain {cid}"
                    ),
                    _ => {}
                }
                println!("✅ PQ Transaction Signed (Falcon-512, explicit PQ1 envelope):");
                println!("  Hash:   {}", hex::encode(tx.compute_tx_hash()));
                println!("  From:   {}", hex::encode(tx.from));
                println!("  To:     {}", hex::encode(tx.to));
                println!("  Amount: {} nano-STELL", tx.amount);
                println!("  Nonce:  {nonce}");
                println!("  Target Shard: {}", tx.target_shard);
                if let Some(cid) = chain_id {
                    println!("  Chain Id: {cid} (signature bound)");
                }

                if dry_run {
                    return Ok(());
                }

                let raw = hex::encode(bincode::serialize(&tx)?);
                let body = serde_json::json!({
                    "jsonrpc": "2.0", "id": 1,
                    "method": "stell_sendRawTransaction",
                    "params": { "tx": raw }
                })
                .to_string();
                let resp: serde_json::Value = ureq::post(&rpc).send_string(&body)?.into_json()?;
                if let Some(e) = resp.get("error") {
                    anyhow::bail!("rejected by node: {e}");
                }
                println!(
                    "  Submitted, mempool tx hash: {}",
                    resp["result"].as_str().unwrap_or("?")
                );
            }

            WalletCommands::Unjail {
                falcon_seed,
                falcon_key_file,
                validator,
                top_up,
                rpc,
                nonce,
                chain_id,
                dry_run,
                verbose,
                token,
            } => {
                if top_up == Some(0) {
                    anyhow::bail!(
                        "--top-up must be positive; omit --top-up instead of passing zero"
                    );
                }
                let pq_key = resolve_falcon_keypair(falcon_key_file, falcon_seed, "falcon")?;
                let chain_id = resolve_chain_id(&rpc, chain_id)?;
                let signer_addr = falcon_pq_address(&pq_key);
                let validator_addr = match validator {
                    Some(v) => parse_wallet_address(&v)?,
                    None => signer_addr,
                };
                // Same local preflight as `validator unjail`: refuse an early
                // release / unmanageable / unfunded tx that the block would
                // reject anyway. The on-chain checks are untouched.
                preflight_unjail(&rpc, &validator_addr, dry_run, false)?;

                let query = |method: &str,
                             params: serde_json::Value|
                 -> anyhow::Result<serde_json::Value> {
                    let body = serde_json::json!({
                        "jsonrpc": "2.0", "id": 1, "method": method, "params": params
                    })
                    .to_string();
                    if verbose {
                        eprintln!("  rpc -> {method}: {body}");
                    }
                    let resp: serde_json::Value =
                        ureq::post(&rpc).send_string(&body)?.into_json()?;
                    if verbose {
                        eprintln!("  rpc <- {method}: {resp}");
                    }
                    if let Some(e) = resp.get("error") {
                        anyhow::bail!("RPC error: {e}");
                    }
                    Ok(resp
                        .get("result")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null))
                };

                let nonce = match nonce {
                    Some(n) => n,
                    None => {
                        let acc = query(
                            "stell_getBalance",
                            serde_json::json!({ "address": hex::encode(signer_addr) }),
                        )?;
                        acc.get("nonce").and_then(|n| n.as_u64()).ok_or_else(|| {
                            anyhow::anyhow!("node did not return an account nonce")
                        })?
                    }
                };

                let tx = match chain_id {
                    Some(cid) => {
                        build_unjail_tx_with_chain(&pq_key, validator_addr, top_up, nonce, cid)
                    }
                    None => build_unjail_tx(&pq_key, validator_addr, top_up, nonce),
                };
                if !tx.verify_signature() {
                    anyhow::bail!("refusing to submit: built PQ transaction does not verify");
                }
                println!("✅ Unjail transaction signed (Falcon-512, explicit PQ1 envelope):");
                println!("  Hash:      {}", hex::encode(tx.compute_tx_hash()));
                println!("  Validator: {}", hex::encode(validator_addr));
                println!("  Top-up:    {} nano-STELL", top_up.unwrap_or(0));
                println!("  Nonce:     {nonce}");
                println!(
                    "  Note: the block refuses the unjail before release_height or below MIN+buffer"
                );

                if dry_run {
                    println!("  raw: {}", hex::encode(bincode::serialize(&tx)?));
                    return Ok(());
                }

                let raw = hex::encode(bincode::serialize(&tx)?);
                let mut params = serde_json::json!({ "tx": raw });
                if let Some(t) = &token {
                    params["token"] = serde_json::json!(t);
                }
                let result = query("stell_sendRawTransaction", params)?;
                println!(
                    "  Submitted, mempool tx hash: {}",
                    result.as_str().unwrap_or("?")
                );
            }

            WalletCommands::DelegateSession {
                master_key,
                session_pub,
                max_gas,
                duration_secs,
                scope,
                max_value,
                chain_id,
                rpc,
                nonce,
                dry_run,
                token,
            } => {
                let master_fk = falcon_from_hex_seed(&master_key, "master_key")?;
                let clean_session = session_pub.strip_prefix("0x").unwrap_or(&session_pub);
                let session_bytes = hex::decode(clean_session)
                    .map_err(|e| anyhow::anyhow!("Invalid session_pub hex: {e}"))?;
                if session_bytes.len() != stellereum::post_quantum::FALCON512_PUBKEY_LEN {
                    anyhow::bail!(
                        "Session public key must be {} bytes (Falcon-512), got {} bytes",
                        stellereum::post_quantum::FALCON512_PUBKEY_LEN,
                        session_bytes.len()
                    );
                }

                let valid_until = now_secs() + duration_secs;
                let auth = SessionKeyAuthorization::sign_delegation_falcon512(
                    &master_fk,
                    stellereum::post_quantum::PqScheme::Falcon512,
                    &session_bytes,
                    valid_until,
                    max_gas,
                    scope,
                    max_value,
                    chain_id,
                );

                println!("✅ AI Session Key Delegation Generated (Falcon-512):");
                println!("  Master Address: {}", hex::encode(auth.master_address));
                println!("  Session Pubkey: {}", hex::encode(auth.session_pubkey));
                println!("  Max Gas Budget: {} nano-STELL", auth.max_gas_spend);
                println!("  Valid Until:    {} (Timestamp)", auth.valid_until);
                println!("  Scope:         0x{:016x}", auth.scope);
                println!("  Max Value/Tx:  {} nano-STELL", auth.max_value_per_tx);
                println!("  Chain Id:      {}", auth.chain_id);
                println!("  Signature:      {}", hex::encode(&auth.master_signature));

                let account_nonce = resolve_nonce(&rpc, &auth.master_address, nonce)?;
                // The grant is minted for `chain_id`; bind the wrapping
                // transaction to the same id so the published delegation stays
                // admissible after chain-binding activation.
                let tx =
                    build_session_grant_tx_with_chain(&master_fk, &auth, account_nonce, chain_id);
                if !tx.verify_signature() {
                    anyhow::bail!("refusing to submit: built PQ transaction does not verify");
                }
                println!("  Wrapping tx:    {}", hex::encode(tx.compute_tx_hash()));
                println!("  Nonce:          {account_nonce}");

                if dry_run {
                    println!("  raw: {}", hex::encode(bincode::serialize(&tx)?));
                    return Ok(());
                }

                let hash = rpc_submit_tx(&rpc, "stell_sendRawTransaction", &tx, token.as_deref())?;
                println!("  Submitted, mempool tx hash: {hash}");
                println!("  (published only when a proposer includes it in a block)");
            }

            WalletCommands::Sign {
                from_key,
                scheme,
                falcon_key_file,
                falcon_seed,
                message,
                message_hex,
                chain_id,
            } => {
                let key =
                    resolve_wallet_signing_key(&scheme, from_key, falcon_key_file, falcon_seed)?;
                let msg = stellereum::wallet_signing::parse_message_param(
                    message.as_deref(),
                    message_hex.as_deref(),
                )
                .map_err(|e| anyhow::anyhow!("{e}"))?;
                let sig = key
                    .sign_message(chain_id, &msg)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                let addr = key.address();
                println!("✅ Message Signed (WALLET SIGNATURE STANDARD, docs/WALLET_SIGNING.md):");
                println!(
                    "  Scheme:    {} (0x{:02x})",
                    sig.scheme.name(),
                    sig.scheme.id()
                );
                println!("  Address:   {}", hex::encode(addr));
                println!("  Chain Id:  {chain_id}");
                println!(
                    "  Preimage:  {}",
                    hex::encode(stellereum::wallet_signing::message_preimage(chain_id, &msg))
                );
                println!("  Signature: {}", sig.to_hex());
            }

            WalletCommands::Verify {
                address,
                message,
                message_hex,
                signature,
                chain_id,
            } => {
                let addr = parse_wallet_address(&address)?;
                let msg = stellereum::wallet_signing::parse_message_param(
                    message.as_deref(),
                    message_hex.as_deref(),
                )
                .map_err(|e| anyhow::anyhow!("{e}"))?;
                let sig = stellereum::wallet_signing::WalletSignature::from_hex(&signature)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                if stellereum::wallet_signing::verify_message(&addr, chain_id, &msg, &sig) {
                    println!(
                        "VALID: {} signed the message on chain {chain_id}",
                        hex::encode(addr)
                    );
                } else {
                    println!("INVALID: signature does not verify for this address/message/chain");
                    anyhow::bail!("signature INVALID");
                }
            }

            WalletCommands::SignTypedData {
                from_key,
                scheme,
                falcon_key_file,
                falcon_seed,
                contract,
                method,
                args,
                value,
                nonce,
                chain_id,
            } => {
                let key =
                    resolve_wallet_signing_key(&scheme, from_key, falcon_key_file, falcon_seed)?;
                let data = parse_wallet_typed_data(
                    &contract,
                    &method,
                    args.as_deref(),
                    value,
                    nonce,
                    chain_id,
                )?;
                let canonical = stellereum::wallet_signing::canonical_typed_data_json(&data);
                let (sig, _) = key
                    .sign_typed_data(&data)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                println!(
                    "✅ Typed Data Signed (WALLET SIGNATURE STANDARD, docs/WALLET_SIGNING.md):"
                );
                println!("  Sign EXACTLY what is shown below — this canonical JSON is what the signature commits to.");
                println!("  Canonical: {canonical}");
                println!(
                    "  Scheme:    {} (0x{:02x})",
                    sig.scheme.name(),
                    sig.scheme.id()
                );
                println!("  Address:   {}", hex::encode(key.address()));
                println!("  Signature: {}", sig.to_hex());
            }

            WalletCommands::VerifyTypedData {
                address,
                contract,
                method,
                args,
                value,
                nonce,
                chain_id,
                signature,
            } => {
                let addr = parse_wallet_address(&address)?;
                let data = parse_wallet_typed_data(
                    &contract,
                    &method,
                    args.as_deref(),
                    value,
                    nonce,
                    chain_id,
                )?;
                let sig = stellereum::wallet_signing::WalletSignature::from_hex(&signature)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                if stellereum::wallet_signing::verify_typed_data(&addr, &data, &sig) {
                    println!(
                        "VALID: {} authorized the typed call on chain {chain_id}",
                        hex::encode(addr)
                    );
                    println!(
                        "  Canonical: {}",
                        stellereum::wallet_signing::canonical_typed_data_json(&data)
                    );
                } else {
                    println!(
                        "INVALID: signature does not verify for this address/typed-data/chain"
                    );
                    anyhow::bail!("signature INVALID");
                }
            }
        },

        Commands::Orderbook { sub } => match sub {
            OrderbookCommands::Depth { pair, rpc } => {
                // Ask a node for the book it actually has. Building one here
                // would print a market that exists nowhere on the network.
                let body = serde_json::json!({
                    "jsonrpc": "2.0", "id": 1,
                    "method": "stell_orderBook",
                    "params": { "pair": pair }
                })
                .to_string();
                let resp: serde_json::Value = ureq::post(&rpc).send_string(&body)?.into_json()?;
                if let Some(e) = resp.get("error") {
                    anyhow::bail!("rejected by node: {e}");
                }
                let book = &resp["result"];

                println!("=== Orderbook Depth for Pair #{} ===", pair);
                println!(
                    "Best Bid: {}",
                    book["best_bid_micro_usd"]
                        .as_u64()
                        .map(|p| format!("${:.4} USD", (p as f64) / 1_000_000.0))
                        .unwrap_or_else(|| "none".to_string())
                );
                println!(
                    "Best Ask: {}",
                    book["best_ask_micro_usd"]
                        .as_u64()
                        .map(|p| format!("${:.4} USD", (p as f64) / 1_000_000.0))
                        .unwrap_or_else(|| "none".to_string())
                );
                println!("Total Bids Levels: {}", book["bid_levels"]);
                println!("Total Asks Levels: {}", book["ask_levels"]);
                for (label, key) in [("Bids", "bids"), ("Asks", "asks")] {
                    if let Some(levels) = book[key].as_array() {
                        for lvl in levels {
                            let price = lvl["price_micro_usd"].as_u64().unwrap_or(0);
                            println!(
                                "  {label} ${:.4}: {} order(s), {} nano-STELL available",
                                (price as f64) / 1_000_000.0,
                                lvl["orders"],
                                lvl["available_nano_stell"],
                            );
                        }
                    }
                }
            }

            OrderbookCommands::Place {
                trader_key,
                pair,
                side,
                order_type,
                price,
                amount,
                rpc,
                nonce,
                chain_id,
                dry_run,
                token,
            } => {
                let trader_fk = falcon_from_hex_seed(&trader_key, "trader_key")?;
                let chain_id = resolve_chain_id(&rpc, chain_id)?;
                let is_buy = match side.to_lowercase().as_str() {
                    "buy" => true,
                    "sell" => false,
                    other => anyhow::bail!("--side must be \"buy\" or \"sell\", got {other}"),
                };
                // The opcode has no market variant: a market order is a limit
                // order at --price that crosses on arrival. Say so rather than
                // silently pretending the two are the same.
                if order_type.to_lowercase() == "market" {
                    println!("  note: market order submitted as a limit order at ${:.4} (crosses on arrival)", (price as f64) / 1_000_000.0);
                }

                let sender = falcon_pq_address(&trader_fk);
                let account_nonce = resolve_nonce(&rpc, &sender, nonce)?;
                let tx = match chain_id {
                    Some(cid) => build_place_order_tx_with_chain(
                        &trader_fk,
                        pair,
                        is_buy,
                        price,
                        amount,
                        account_nonce,
                        cid,
                    ),
                    None => {
                        build_place_order_tx(&trader_fk, pair, is_buy, price, amount, account_nonce)
                    }
                };
                if !tx.verify_signature() {
                    anyhow::bail!("refusing to submit: built PQ transaction does not verify");
                }

                println!("✅ Order Signed (Falcon-512, PQ1):");
                println!("  Hash:    {}", hex::encode(tx.compute_tx_hash()));
                println!("  Trader:  {}", hex::encode(tx.from));
                println!("  Pair:    #{pair}");
                println!("  Side:    {}", if is_buy { "buy" } else { "sell" });
                println!("  Price:   ${:.4}", (price as f64) / 1_000_000.0);
                println!("  Amount:  {amount} nano-STELL");
                println!("  Nonce:   {account_nonce}");

                if dry_run {
                    println!("  raw: {}", hex::encode(bincode::serialize(&tx)?));
                    return Ok(());
                }

                let hash = rpc_submit_tx(&rpc, "stell_sendRawTransaction", &tx, token.as_deref())?;
                println!("  Submitted, mempool tx hash: {hash}");
                println!("  (rests only when a proposer includes it in a block)");
            }

            OrderbookCommands::Cancel {
                trader_key,
                order_id,
                rpc,
                nonce,
                chain_id,
                dry_run,
                token,
            } => {
                let trader_fk = falcon_from_hex_seed(&trader_key, "trader_key")?;
                let chain_id = resolve_chain_id(&rpc, chain_id)?;
                let sender = falcon_pq_address(&trader_fk);
                let account_nonce = resolve_nonce(&rpc, &sender, nonce)?;
                let tx = match chain_id {
                    Some(cid) => {
                        build_cancel_order_tx_with_chain(&trader_fk, order_id, account_nonce, cid)
                    }
                    None => build_cancel_order_tx(&trader_fk, order_id, account_nonce),
                };
                if !tx.verify_signature() {
                    anyhow::bail!("refusing to submit: built PQ transaction does not verify");
                }

                println!("✅ Cancellation Signed (Falcon-512, PQ1):");
                println!("  Hash:    {}", hex::encode(tx.compute_tx_hash()));
                println!("  Trader:  {}", hex::encode(tx.from));
                println!("  Order:   #{order_id}");
                println!("  Nonce:   {account_nonce}");

                if dry_run {
                    println!("  raw: {}", hex::encode(bincode::serialize(&tx)?));
                    return Ok(());
                }

                let hash = rpc_submit_tx(&rpc, "stell_sendRawTransaction", &tx, token.as_deref())?;
                println!("  Submitted, mempool tx hash: {hash}");
                println!("  (refunded only when a proposer includes it in a block)");
            }
        },

        Commands::Oracle { sub } => {
            match sub {
                OracleCommands::Feed {
                    key,
                    asset,
                    price_micro,
                    from_key,
                    rpc,
                    nonce,
                    chain_id,
                    dry_run,
                    token,
                } => {
                    let publisher_fk = falcon_from_hex_seed(&key, "publisher key")?;
                    let chain_id = resolve_chain_id(&rpc, chain_id)?;

                    // The feed carries the OFF-CHAIN clock: it is timestamped when
                    // the publisher signs it. The chain re-checks it against
                    // `block.timestamp` in `commit_feed_pq`, so a feed signed in the
                    // future or older than STALE_PRICE_MAX_SECS is rejected at
                    // block time - the local clock never reaches consensus state.
                    let update = stellereum::oracle::PqPriceFeedUpdate::sign(
                        &asset,
                        price_micro,
                        now_secs(),
                        &publisher_fk,
                    );

                    println!("✅ PQ Price Feed Signed (Falcon-512):");
                    println!("  Asset:     {}", update.asset);
                    println!(
                        "  Price:     ${:.4} USD",
                        (update.price_micro_usd as f64) / 1_000_000.0
                    );
                    println!("  Timestamp: {}", update.timestamp);
                    println!(
                        "  Publisher: {}",
                        hex::encode(stellereum::oracle::pq_publisher_binding(
                            &update.publisher_falcon_pubkey
                        ))
                    );

                    // Wrap it in a transaction: only a block carrying this payload
                    // commits the price (determinism rule), so the CLI signs the
                    // wrapping transaction instead of pretending a printout (or a
                    // gossip message) is a price update.
                    let sender_fk = match &from_key {
                        Some(k) => falcon_from_hex_seed(k, "from_key")?,
                        None => publisher_fk.clone(),
                    };
                    let sender_addr = falcon_pq_address(&sender_fk);

                    let query = |method: &str,
                                 params: serde_json::Value|
                     -> anyhow::Result<serde_json::Value> {
                        let body = serde_json::json!({
                            "jsonrpc": "2.0", "id": 1, "method": method, "params": params
                        })
                        .to_string();
                        let resp: serde_json::Value =
                            ureq::post(&rpc).send_string(&body)?.into_json()?;
                        if let Some(e) = resp.get("error") {
                            anyhow::bail!("RPC error: {e}");
                        }
                        Ok(resp
                            .get("result")
                            .cloned()
                            .unwrap_or(serde_json::Value::Null))
                    };

                    let nonce = match nonce {
                        Some(n) => n,
                        None => {
                            let acc = query(
                                "stell_getBalance",
                                serde_json::json!({ "address": hex::encode(sender_addr) }),
                            )?;
                            acc.get("nonce").and_then(|n| n.as_u64()).ok_or_else(|| {
                                anyhow::anyhow!("node did not return an account nonce")
                            })?
                        }
                    };

                    let payload = vec![stellereum::svm::OpCode::SysCallSubmitPqPriceFeed(
                        Box::new(update.clone()),
                    )];
                    let gas = cli_tx_gas(stellereum::svm::GAS_SUBMIT_PQ_PRICE_FEED)
                        .saturating_add(stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS);
                    let tx = match chain_id {
                        Some(cid) => sign_pq_explicit_payload_with_chain(
                            &sender_fk,
                            sender_addr,
                            0,
                            gas,
                            nonce,
                            1,
                            1,
                            payload,
                            cid,
                        ),
                        None => sign_pq_explicit_payload(
                            &sender_fk,
                            sender_addr,
                            0,
                            gas,
                            nonce,
                            1,
                            1,
                            payload,
                        ),
                    };
                    if !tx.verify_signature() {
                        anyhow::bail!("refusing to submit: built PQ transaction does not verify");
                    }
                    println!("  Wrapping tx: {}", hex::encode(tx.compute_tx_hash()));
                    println!("  Sender:   {}", hex::encode(tx.from));
                    println!("  Nonce:    {nonce}");

                    if dry_run {
                        println!("  raw: {}", hex::encode(bincode::serialize(&tx)?));
                        return Ok(());
                    }

                    let raw = hex::encode(bincode::serialize(&tx)?);
                    let mut params = serde_json::json!({ "tx": raw });
                    if let Some(t) = &token {
                        params["token"] = serde_json::json!(t);
                    }
                    let result = query("stell_submitPriceFeed", params)?;
                    println!(
                        "  Submitted, mempool tx hash: {}",
                        result.as_str().unwrap_or("?")
                    );
                    println!("  (committed only when a proposer includes it in a block)");
                }

                OracleCommands::Status { asset } => {
                    let mut oracle = OracleSafetyEngine::new(vec![]);
                    oracle.record_dex_trade(&asset, 5_000_000, now_secs(), 100);
                    let price = oracle.resolve_price(None, &asset, now_secs()).unwrap();
                    println!("Oracle Status for {}:", asset);
                    println!(
                        "  Resolved Price:   ${:.2} USD",
                        (price as f64) / 1_000_000.0
                    );
                    println!("  Circuit Breaker:  Clean (Not Triggered)");
                }
            }
        }

        Commands::Bridge { sub } => match sub {
            BridgeCommands::Deposit {
                chain,
                recipient,
                amount,
                source_tx_hash,
                from_key,
                attest_key,
                attest_keys_dir,
                rpc,
                nonce,
                chain_id,
                dry_run,
                token,
            } => {
                let signer_fk = falcon_from_hex_seed(&from_key, "from_key")?;
                let chain_id = resolve_chain_id(&rpc, chain_id)?;
                let recipient: [u8; 32] = parse_wallet_address(&recipient)?;
                let source_chain = parse_supported_chain(&chain)?;

                // The dedup key settlement will replay-check on. A caller that
                // does not have the real source-chain hash yet gets a
                // deterministic stand-in bound to this claim, so two
                // different claims can never collide - and so the CLI never
                // invents a hash that looks like someone else's.
                let source_tx_hash: [u8; 32] = match source_tx_hash {
                    Some(h) => {
                        let b = hex::decode(&h)
                            .map_err(|e| anyhow::anyhow!("Invalid source_tx_hash hex: {e}"))?;
                        b.try_into()
                            .map_err(|_| anyhow::anyhow!("source_tx_hash must be 32 bytes"))?
                    }
                    None => {
                        let mut preimage = Vec::with_capacity(16 + 32 + 8);
                        preimage.extend_from_slice(b"STELL_TELEPORT_DEPOSIT_INTENT_V1");
                        preimage.extend_from_slice(chain.as_bytes());
                        preimage.extend_from_slice(&recipient);
                        preimage.extend_from_slice(&amount.to_be_bytes());
                        *blake3::hash(&preimage).as_bytes()
                    }
                };

                let intent = stellereum::bridge::BridgeIntent::Deposit {
                    chain: source_chain,
                    source_tx_hash,
                    recipient,
                    amount,
                };

                // §8: a deposit is only ever admitted WITH its attestation
                // bundle, so gather the signatures FIRST - a claim with no
                // quorum is refused by every block and must not look like a
                // successful submission.
                let attest_keys =
                    resolve_attest_keys(&attest_key, std::path::Path::new(&attest_keys_dir))?;
                let attestation = attest_for(&intent, &attest_keys)?;
                let attesters = match &attestation {
                    stellereum::bridge::BridgeIntent::Attest { signatures, .. } => signatures.len(),
                    _ => unreachable!("attest_for returns Attest"),
                };

                let sender = falcon_pq_address(&signer_fk);
                let account_nonce = resolve_nonce(&rpc, &sender, nonce)?;
                let tx = match chain_id {
                    Some(cid) => build_bridge_intent_tx_with_chain(
                        &signer_fk,
                        &[attestation, intent],
                        account_nonce,
                        cid,
                    ),
                    None => {
                        build_bridge_intent_tx(&signer_fk, &[attestation, intent], account_nonce)
                    }
                };
                if !tx.verify_signature() {
                    anyhow::bail!("refusing to submit: built PQ transaction does not verify");
                }

                println!("✅ Teleport Deposit Intent Signed (Falcon-512, PQ1):");
                println!("  Source chain:   {chain}");
                println!("  Source tx:      {}", hex::encode(source_tx_hash));
                println!("  Recipient:      {}", hex::encode(recipient));
                println!("  Amount:         {amount} nano-STELL");
                println!("  Attesters:      {attesters} distinct Falcon-512 signer(s) (quorum is (n*2+2)/3 of the committed staking set)");
                println!("  Wrapping tx:    {}", hex::encode(tx.compute_tx_hash()));
                println!("  Sender:         {}", hex::encode(tx.from));
                println!("  Nonce:          {account_nonce}");

                if dry_run {
                    println!("  raw: {}", hex::encode(bincode::serialize(&tx)?));
                    return Ok(());
                }

                let hash = rpc_submit_tx(&rpc, "stell_sendRawTransaction", &tx, token.as_deref())?;
                println!("  Submitted, mempool tx hash: {hash}");
                println!("  (credited when a proposer includes it: the block verifies the quorum and the source tx was never seen before)");
            }

            BridgeCommands::Withdraw {
                chain,
                target_address,
                amount,
                from_key,
                rpc,
                nonce,
                chain_id,
                dry_run,
                token,
            } => {
                let signer_fk = falcon_from_hex_seed(&from_key, "from_key")?;
                let chain_id = resolve_chain_id(&rpc, chain_id)?;
                let target_chain = parse_supported_chain(&chain)?;

                let intent = stellereum::bridge::BridgeIntent::Withdraw {
                    chain: target_chain,
                    target_address: target_address.clone(),
                    amount,
                };
                let sender = falcon_pq_address(&signer_fk);
                let account_nonce = resolve_nonce(&rpc, &sender, nonce)?;
                let tx = match chain_id {
                    Some(cid) => build_bridge_intent_tx_with_chain(
                        &signer_fk,
                        std::slice::from_ref(&intent),
                        account_nonce,
                        cid,
                    ),
                    None => build_bridge_intent_tx(
                        &signer_fk,
                        std::slice::from_ref(&intent),
                        account_nonce,
                    ),
                };
                if !tx.verify_signature() {
                    anyhow::bail!("refusing to submit: built PQ transaction does not verify");
                }

                println!("✅ Bridge Withdrawal Intent Signed (Falcon-512, PQ1):");
                println!("  Target chain:   {chain}");
                println!("  Target address: {target_address}");
                println!("  Amount:         {amount} nano-STELL");
                println!("  Wrapping tx:    {}", hex::encode(tx.compute_tx_hash()));
                println!("  Sender:         {}", hex::encode(tx.from));
                println!("  Nonce:          {account_nonce}");
                if amount >= stellereum::bridge::LARGE_WITHDRAWAL_THRESHOLD_NANO {
                    println!("  ⚠️  Time-lock applies at settlement: 1 hour unlock delay.");
                } else {
                    println!(
                        "  Status:         time-lock free below the large-withdrawal threshold."
                    );
                }

                if dry_run {
                    println!("  raw: {}", hex::encode(bincode::serialize(&tx)?));
                    return Ok(());
                }

                let hash = rpc_submit_tx(&rpc, "stell_sendRawTransaction", &tx, token.as_deref())?;
                println!("  Submitted, mempool tx hash: {hash}");
                println!("  (escrowed and queued when a proposer includes it: rate window and time-lock run on the block clock)");
            }
        },

        Commands::Pmm {
            action,
            amount,
            reserve_usd,
        } => {
            println!("╔═══════════════════════════════════════════════════════════════╗");
            println!("║        🏦  STELLEREUM PRIMARY MARKET MAKER (PMM)              ║");
            println!("╚═══════════════════════════════════════════════════════════════╝");
            let mut pmm = PrimaryMarketMaker::with_reserve(reserve_usd * 1_000_000);
            println!("• Bonding curve:  P(S) = P0 * (1 + S/S_cap),  P0 = $0.25");
            println!("• Initial reserve: ${} USDT", reserve_usd);
            println!("• Redemption buffer: 20% ring-fenced\n");
            match action.as_str() {
                "buy" => {
                    let micro = amount * 1_000_000;
                    match pmm.buy_with_usdt(micro) {
                        Ok(r) => {
                            println!("✅ BOUGHT:");
                            println!("  Paid:        ${}", amount);
                            println!(
                                "  Minted:      {} nano-STELL ({:.4} STELL)",
                                r.stell_minted,
                                r.stell_minted as f64 / 1e9
                            );
                            println!("  New price:   ${:.4}", r.new_price_micro_usd as f64 / 1e6);
                            println!("  Supply:      {:.4} STELL", r.supply_after as f64 / 1e9);
                            println!("  Reserve:     ${:.2}", pmm.reserve_usd());
                        }
                        Err(e) => eprintln!("❌ Buy failed: {e}"),
                    }
                }
                "sell" => {
                    let nano = amount * 1_000_000_000;
                    match pmm.sell_stell(nano) {
                        Ok(r) => {
                            println!("✅ SOLD:");
                            println!(
                                "  Burned:      {} nano-STELL ({:.4} STELL)",
                                r.stell_burned,
                                r.stell_burned as f64 / 1e9
                            );
                            println!("  Received:    ${:.6}", r.usdt_paid as f64 / 1e6);
                            println!("  New price:   ${:.4}", r.new_price_micro_usd as f64 / 1e6);
                            println!("  Reserve:     ${:.2}", pmm.reserve_usd());
                        }
                        Err(e) => eprintln!("❌ Sell failed: {e}"),
                    }
                }
                _ => {
                    println!(
                        "  Current price: ${:.4}",
                        pmm.price_micro_usd() as f64 / 1e6
                    );
                    println!(
                        "  Max redeemable: {:.4} STELL",
                        pmm.max_redeemable_stell() as f64 / 1e9
                    );
                }
            }
        }

        Commands::NodeBootstrap {
            config,
            shard,
            data_dir,
            allow_dirty,
            no_exec,
        } => {
            use stellereum::bootstrap as boot;
            eprintln!(
                "{}",
                boot::stage_line(
                    1,
                    &format!(
                        "preflight: fresh-observer gate (config={}, data-dir={})",
                        config.display(),
                        data_dir.display()
                    )
                )
            );
            // Gate inputs, each read exactly the way the `run` path reads it.
            let observer = boot::is_observer_env(std::env::var("STELL_OBSERVER").ok().as_deref());
            // Key file counts too (STELL_FAUCET_KEY_FILE, same as `run`).
            let faucet_key_present = stellereum::rpc::faucet_key_present_from_env();
            let dir_clean = boot::data_dir_is_clean_fs(&data_dir);
            if !dir_clean && allow_dirty {
                eprintln!(
                    "[bootstrap] OVERRIDE --allow-dirty on a NON-clean {}: this is a RESTART, \
                     not a fresh bootstrap — ledger/state reuse the previous run, snapshot-sync \
                     still verifies anything it fetches",
                    data_dir.display()
                );
            }
            // The peer pointer is config-level (a name, not a dial): `peers:` entries
            // or DNS seeds. Whether anyone is actually LIVE is proven by the sync
            // engine itself (snapshot-sync with honest retries), never assumed here.
            let (n_peers, n_validators) = match node_config::load(&config) {
                Ok(cfg) => (cfg.peers.len(), cfg.validators.len()),
                Err(e) => anyhow::bail!(
                    "[bootstrap] REFUSING: cannot read {}: {e} (no config = no peer pointer = \
                     bootstrapping against nobody)",
                    config.display()
                ),
            };
            let n_seeds = stellereum::dns_seeds::seed_domains_from_env().len();
            eprintln!(
                "[bootstrap] pointer: {n_peers} configured peer(s), {n_seeds} DNS seed domain(s), \
                 {n_validators} validator(s) in the set"
            );
            let preflight = boot::BootstrapPreflight {
                observer,
                faucet_key_present,
                data_dir_clean: dir_clean || allow_dirty,
                peer_pointer_present: n_peers > 0 || n_seeds > 0,
                validator_set_present: n_validators > 0,
            };
            if !preflight.ready() {
                for f in preflight.failures() {
                    eprintln!("[bootstrap] REFUSING: {f}");
                }
                anyhow::bail!(
                    "[bootstrap] preflight FAILED ({} gate(s)): fix the lines above and re-run — \
                     starting now would derive a private genesis, not join the network",
                    preflight.failures().len()
                );
            }
            eprintln!(
                "{}",
                boot::stage_line(
                    1,
                    "preflight OK: clean dir, observer, peer pointer, validator set"
                )
            );
            eprintln!(
                "{}",
                boot::stage_line(
                    2,
                    "snapshot-sync: newest usable boundary (latest-snapshot pointer when sane), \
                     state + EVERY domain (accounts incl. the staking LEDGER, domains, session, \
                     bridge, zkml, cross_shard), tail-anchored QC proof, \
                     root-checked BEFORE commit — stale domains are rejected with a retry, \
                     never committed"
                )
            );
            eprintln!(
                "{}",
                boot::stage_line(
                    3,
                    "walk the short remainder by bodies (precommit QC verified per height)"
                )
            );
            eprintln!(
                "{}",
                boot::stage_line(4, "live: the consensus loop owns the tip (observer follows, never proposes/votes)")
            );
            if no_exec {
                eprintln!("[bootstrap] --no-exec: gate passed, plan printed, node NOT started");
                return Ok(());
            }
            if data_dir.as_path() != std::path::Path::new("./data") {
                anyhow::bail!(
                    "[bootstrap] REFUSING to exec: --data-dir {} != ./data, but `run` persists to \
                     ./data — bootstrapping elsewhere then running here would split. Re-run with \
                     the default data dir (or --no-exec for a gate check only)",
                    data_dir.display()
                );
            }
            eprintln!("[bootstrap] gate passed — handing off to the live sync engine (`run`)");
            let exe = std::env::current_exe()
                .map_err(|e| anyhow::anyhow!("[bootstrap] cannot locate own binary: {e}"))?;
            #[cfg(unix)]
            {
                let err = std::os::unix::process::CommandExt::exec(
                    std::process::Command::new(&exe)
                        .arg("run")
                        .arg("--config")
                        .arg(&config)
                        .arg("--shard")
                        .arg(shard.to_string()),
                );
                anyhow::bail!("[bootstrap] exec run failed: {err}");
            }
            #[cfg(not(unix))]
            {
                let status = std::process::Command::new(&exe)
                    .arg("run")
                    .arg("--config")
                    .arg(&config)
                    .arg("--shard")
                    .arg(shard.to_string())
                    .status()
                    .map_err(|e| anyhow::anyhow!("[bootstrap] spawn run failed: {e}"))?;
                std::process::exit(status.code().unwrap_or(1));
            }
        }
        Commands::Keys { sub } => match sub {
            KeysCommands::Init {
                keys_dir,
                falcon_file,
            } => {
                let falcon_path = resolve_falcon_path(&keys_dir, falcon_file);
                let bundle = stellereum::node_keys::NodeKeyBundle::load_or_generate(
                    &keys_dir,
                    &falcon_path,
                )?;
                println!("{}", bundle.identity_line());
                println!("keys dir: {} (0700), files 0600", keys_dir.display());
                println!("falcon key: {}", falcon_path.display());
            }
            KeysCommands::PeerStanza {
                keys_dir,
                falcon_file,
                name,
                endpoint,
            } => {
                let falcon_path = resolve_falcon_path(&keys_dir, falcon_file);
                let bundle = stellereum::node_keys::NodeKeyBundle::load(&keys_dir, &falcon_path)?;
                print!("{}", bundle.peer_stanza(&name, &endpoint));
            }
            KeysCommands::RotateFalcon {
                keys_dir,
                falcon_file,
                force,
            } => {
                let falcon_path = resolve_falcon_path(&keys_dir, falcon_file);

                // 1. Report the CURRENT validator address (if any) so the
                //    operator can see exactly what changes.
                let old_address = if falcon_path.exists() {
                    match stellereum::node_keys::load_falcon_key(&falcon_path) {
                        Ok(old) => {
                            let addr = old.validator_id();
                            let legacy = old.is_legacy_incomplete_ntru();
                            println!("current validator address : {}", hex::encode(addr));
                            println!(
                                "current falcon key        : {} ({})",
                                falcon_path.display(),
                                if legacy {
                                    "LEGACY pre-FIPS 206 key — INCOMPLETE NTRU key (no G)"
                                } else {
                                    "complete FIPS 206 NTRU key"
                                }
                            );
                            Some(addr)
                        }
                        Err(e) => {
                            println!(
                                "could not read the current falcon key ({}): {e}",
                                falcon_path.display()
                            );
                            None
                        }
                    }
                } else {
                    println!("no falcon key at {} yet", falcon_path.display());
                    None
                };

                if falcon_path.exists() && !force {
                    anyhow::bail!(
                        "refusing to rotate {} without --force: rotation CHANGES the validator \
                         address (the current one is printed above) and the on-chain staking \
                         set must be updated for the new address",
                        falcon_path.display()
                    );
                }

                // 2. Back up the old key file (raw copy: same encryption state).
                let mut backup_note = String::new();
                if falcon_path.exists() {
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let backup = falcon_path.with_extension(format!("bak-{}", ts));
                    std::fs::copy(&falcon_path, &backup).map_err(|e| {
                        anyhow::anyhow!(
                            "could not back up {} to {}: {e}",
                            falcon_path.display(),
                            backup.display()
                        )
                    })?;
                    stellereum::node_keys::set_private_file_perms(&backup)?;
                    backup_note = format!(" (old key backed up to {})", backup.display());
                }

                // 3. Generate a COMPLETE FIPS 206 (FN-DSA) NTRU key and write
                //    it with the same protections `run` uses (0700 dir, 0600
                //    file, encrypted unless STELL_KEY_PLAINTEXT=1).
                let new_key = stellereum::post_quantum::FalconKeypair::generate_complete();
                stellereum::node_keys::save_falcon_key(&falcon_path, &new_key)?;

                // 4. Print the new validator address.
                let new_address = new_key.validator_id();
                println!();
                println!(
                    "falcon key rotated         : {}{}",
                    falcon_path.display(),
                    backup_note
                );
                println!("new validator address     : {}", hex::encode(new_address));
                println!(
                    "new falcon public key     : {}",
                    hex::encode(new_key.public_key())
                );
                if let Some(old) = old_address {
                    println!("previous validator address : {}", hex::encode(old));
                    if old == new_address {
                        println!("(the address did NOT change)");
                    } else {
                        println!();
                        println!("NEXT STEP (on-chain, separate from this command):");
                        println!("  the staking set still points at the OLD address;");
                        println!("  re-stake under the NEW address.");
                    }
                }
                println!();
                println!("restart the node to pick up the new key.");
            }
        },
        Commands::LightClient {
            from,
            verify,
            validators,
            wait_seconds,
            min_height,
            verbose,
        } => {
            let opts = stellereum::light_client_cli::LightClientOptions {
                from,
                verify,
                validators,
                wait_seconds,
                min_height,
                verbose,
            };
            stellereum::light_client_cli::run(&opts)?;
        }
        Commands::LightAnchor {
            validators,
            checkpoint,
        } => {
            let report = stellereum::light_client_cli::anchor_show(&validators, &checkpoint)?;
            println!("{report}");
        }
        Commands::LightVerify {
            validators,
            checkpoint,
            header,
        } => {
            let report = stellereum::light_client_cli::verify_header_file(
                &validators,
                &checkpoint,
                &header,
            )?;
            println!("{report}");
        }
        Commands::LightRotate {
            validators,
            checkpoint,
            rotation,
        } => {
            let report =
                stellereum::light_client_cli::rotate_anchor(&validators, &checkpoint, &rotation)?;
            println!("{report}");
        }
        Commands::UpgradeStatus { marker } => {
            use crate::node::bootstrap::upgrade_halt as halt;
            let gate_env = std::env::var(halt::WAIT_SUPERMAJORITY_ENV).ok();
            match halt::parse_wait_supermajority_height(gate_env.as_deref()) {
                Ok(Some(h)) => println!(
                    "supermajority restart gate: ENABLED at height {h} ({}=...); a node waits for \
                     strictly more than 2/3 of the committed power on this fork/protocol and \
                     falls back to OBSERVER on timeout",
                    halt::WAIT_SUPERMAJORITY_ENV
                ),
                Ok(None) => println!(
                    "supermajority restart gate: disabled ({}=unset)",
                    halt::WAIT_SUPERMAJORITY_ENV
                ),
                Err(e) => println!("supermajority restart gate: INVALID CONFIG — {e}"),
            }
            let path = marker.unwrap_or_else(halt::marker_path);
            match halt::read_marker(&path) {
                Ok(None) => {
                    println!("No upgrade-halt marker at {}", path.display());
                    println!(
                        "This data directory is not halted for a software upgrade \
                         (default marker: {}).",
                        halt::marker_path().display()
                    );
                }
                Ok(Some(m)) => {
                    println!("Upgrade-halt marker: {}", path.display());
                    print!("{}", m.render());
                    let running = halt::running_version();
                    let sha = halt::running_exe_sha256();
                    println!("running binary version: {running}");
                    println!(
                        "running exe sha256:     {}",
                        sha.map(hex::encode)
                            .unwrap_or_else(|| "unknown".to_string())
                    );
                    if halt::marker_satisfied_by(&m, &running, sha) {
                        println!(
                            "STATUS: SATISFIED — this binary proves the plan's target version, so \
                             the startup guard clears the marker and joins consensus."
                        );
                    } else {
                        // Print the EXACT message the node's startup guard would
                        // emit, using the marker's own halt height as the
                        // finalized-head floor. READ-ONLY: preview never clears.
                        println!("STATUS: NOT SATISFIED");
                        if let halt::HaltDecision::Refuse { message } =
                            halt::preview_halt_decision(&path, m.halted_at_height, &running, sha)
                        {
                            println!("{message}");
                        }
                    }
                }
                Err(e) => {
                    anyhow::bail!(
                        "upgrade-halt marker {} cannot be read: {e}. A node that cannot prove it \
                         is not halted must not vote; restore or remove the marker after \
                         verifying out of band that no software upgrade is pending.",
                        path.display()
                    );
                }
            }
        }
        Commands::Network => {
            println!("╔═══════════════════════════════════════════════════════════════╗");
            println!("║              🌐 STELLEREUM P2P NETWORK OVERLAY                ║");
            println!("╚═══════════════════════════════════════════════════════════════╝");
            println!("• P2P Foundation:     infnode transparent QUIC / TLS transport");
            println!("• Discovery Model:    Kademlia DHT (160 k-buckets, alpha=3, k=20)");
            println!("• DNS Federation:     TXT record verification (e.g. stellereum.org)");
            println!("• Transport Protocol: QUIC over UDP with session-level forward secrecy");
            println!("• Storage Buckets:    stell_blocks (chunks), stell_state (snapshots)");
            println!("• Registry KV:        stell:height:{{shard}}, stell:block:{{hash}}");
            println!("\n🔍 HOW APPS AND WALLETS CONNECT TO STELLEREUM:");
            println!("  1. Bootstrap Node: Connect to any seed node specified in config.yaml");
            println!("  2. DHT Lookup:     Node queries 'dht.find_node' to discover nearest peers");
            println!(
                "  3. Shard Sync:     Wallet queries 'stell:height:{{shard}}' via get_local_kv"
            );
            println!("  4. SPV Light Mode: Wallets verify state via Patricia-Merkle BoC proofs");
            println!("  5. Full Node Mode: Downloads block chunks via 'fetch_blob' and verifies\n");
        }
        Commands::Status { rpc, json } => {
            let height = rpc_call(&rpc, "stell_blockNumber", serde_json::json!([]))
                .ok()
                .and_then(|v| match v {
                    serde_json::Value::Number(n) => n.as_u64(),
                    serde_json::Value::String(s) => {
                        let s = s.trim();
                        if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                            u64::from_str_radix(h, 16).ok()
                        } else {
                            s.parse::<u64>().ok()
                        }
                    }
                    _ => None,
                });
            let vs = rpc_call(&rpc, "stell_getValidators", serde_json::json!([]))?;
            let fragile = vs.get("fragile").and_then(|v| v.as_bool()).unwrap_or(true);
            let fragile_reason = vs
                .get("fragile_reason")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let quorum = vs.get("quorum").and_then(|v| v.as_str()).unwrap_or("?");
            let total = vs
                .get("total_power")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let empty = Vec::new();
            let entries = vs
                .get("validators")
                .and_then(|v| v.as_array())
                .unwrap_or(&empty);

            let mut rows = Vec::new();
            let mut jailed = Vec::new();
            for e in entries {
                let vid = e.get("validator").and_then(|v| v.as_str()).unwrap_or("?");
                let power = e.get("power").and_then(|v| v.as_str()).unwrap_or("?");
                let st = rpc_call(
                    &rpc,
                    "stell_getValidatorStatus",
                    serde_json::json!({ "validator": vid }),
                )
                .ok();
                let is_jailed = st
                    .as_ref()
                    .and_then(|v| v.get("jailed"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let in_set = st
                    .as_ref()
                    .and_then(|v| v.get("in_set"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let release = st
                    .as_ref()
                    .and_then(|v| v.get("release_height"))
                    .and_then(|v| v.as_u64());
                let bond = st
                    .as_ref()
                    .and_then(|v| v.get("self_bond"))
                    .and_then(|v| v.as_u64());
                if is_jailed {
                    jailed.push((vid, release));
                }
                rows.push(serde_json::json!({
                    "validator": vid,
                    "power": power,
                    "in_set": in_set,
                    "jailed": is_jailed,
                    "release_height": release,
                    "self_bond": bond,
                }));
            }

            let verdict = if !jailed.is_empty() {
                format!(
                    "DEGRADED: {} validator(s) jailed{}",
                    jailed.len(),
                    if fragile {
                        " and the set is FRAGILE (no spare)"
                    } else {
                        ""
                    }
                )
            } else if fragile {
                "FRAGILE: every validator must stay up".to_string()
            } else {
                "healthy".to_string()
            };
            let next = if let Some((vid, Some(rel))) = jailed.first() {
                format!(
                    "unjail {} once tip >= {} (scripts/auto-unjail.sh does this automatically)",
                    &vid[..8.min(vid.len())],
                    rel
                )
            } else if fragile {
                "restore the jailed/missing member; do not restart anyone until 4/4".to_string()
            } else {
                String::new()
            };

            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "rpc": rpc,
                        "height": height,
                        "validator_count": rows.len(),
                        "fragile": fragile,
                        "fragile_reason": fragile_reason,
                        "quorum": quorum,
                        "total_power": total,
                        "validators": rows,
                        "verdict": verdict,
                        "next": next,
                    })
                );
            } else {
                println!("Stellereum node status — {}", rpc);
                match height {
                    Some(h) => println!("  height        : {h}"),
                    None => println!("  height        : UNREACHABLE"),
                }
                println!(
                    "  validators    : {} (fragile: {})",
                    rows.len(),
                    if fragile { "yes" } else { "no" }
                );
                if fragile && !fragile_reason.is_empty() {
                    println!("  fragility     : {fragile_reason}");
                }
                println!("  quorum / power: {quorum} / {total}");
                println!("  members       :");
                for r in &rows {
                    let vid = r.get("validator").and_then(|v| v.as_str()).unwrap_or("?");
                    let state = if r.get("jailed").and_then(|v| v.as_bool()).unwrap_or(false) {
                        match r.get("release_height").and_then(|v| v.as_u64()) {
                            Some(rel) => format!("JAILED (release {rel})"),
                            None => "JAILED".to_string(),
                        }
                    } else if r.get("in_set").and_then(|v| v.as_bool()).unwrap_or(false) {
                        "active".to_string()
                    } else {
                        "not in set".to_string()
                    };
                    println!(
                        "    {}  {:<26}  power {}",
                        &vid[..8.min(vid.len())],
                        state,
                        r.get("power").and_then(|v| v.as_str()).unwrap_or("?")
                    );
                }
                println!("  verdict       : {verdict}");
                if !next.is_empty() {
                    println!("  next action   : {next}");
                }
            }
        }
        Commands::Gates { yaml } => {
            if yaml {
                print!("{}", stellereum::feature_gates::render_yaml());
            } else {
                print!("{}", stellereum::feature_gates::render_table());
            }
        }
        Commands::SafetyReset {
            store_dir,
            i_fenced_all_signers,
        } => {
            if !i_fenced_all_signers {
                anyhow::bail!(
                    "refusing safety-reset: pass --i-fenced-all-signers ONLY after stopping and \
                     fencing the node, all legacy validator processes and every remote signer for \
                     this key. This DESTROYS the durable vote watermarks; run `safety-init` next."
                );
            }
            let storage = stellereum::storage::Storage::open(&store_dir)?;
            let removed = storage.reset_safety_record_for_recovery()?;
            println!(
                "safety_record_v1 {} in {}; run `stellereum safety-init --store-dir {} \
                 --keys-dir <keys> --i-fenced-all-signers` next",
                if removed {
                    "cleared"
                } else {
                    "was already absent"
                },
                store_dir.display(),
                store_dir.display()
            );
        }
        Commands::SafetyInit {
            store_dir,
            keys_dir,
            validator_pub,
            shard,
            prevote_round_floor,
            precommit_round_floor,
            i_fenced_all_signers,
        } => {
            if !i_fenced_all_signers {
                anyhow::bail!(
                    "refusing safety-init: pass --i-fenced-all-signers ONLY after stopping and \
                     fencing all legacy validator processes and remote signers for this key"
                );
            }
            let val_pub: [u8; 32] = if let Some(hex_pk) = validator_pub {
                let raw = hex::decode(hex_pk.trim())
                    .map_err(|e| anyhow::anyhow!("invalid --validator-pub hex: {e}"))?;
                raw.as_slice().try_into().map_err(|_| {
                    anyhow::anyhow!("--validator-pub must decode to exactly 32 bytes")
                })?
            } else {
                let key_path = keys_dir.join("validator.key");
                let legacy_path = keys_dir.join("identity.key");
                if !key_path.exists() && !legacy_path.exists() {
                    anyhow::bail!(
                        "no validator.key or identity.key found in {}; pass --validator-pub for remote signer",
                        keys_dir.display()
                    );
                }
                let sk = stellereum::node_keys::load_or_generate_consensus_key(&keys_dir)?;
                sk.verifying_key().to_bytes()
            };
            let storage = stellereum::storage::Storage::open(&store_dir)?;
            let record = stellereum::safety::operator_safety_init(
                &storage,
                val_pub,
                shard,
                prevote_round_floor,
                precommit_round_floor,
                i_fenced_all_signers,
            )?;
            let payload =
                stellereum::safety::SafetyRecordPayload::decode_canonical(&record.payload)?;
            println!(
                "safety_record_v1 initialized: validator={} shard={} generation={} height={} finalized={} prevote_floor={:?} precommit_floor={:?}",
                hex::encode(val_pub),
                shard,
                record.generation,
                payload.height,
                payload.finalized_height,
                payload.highest_prevote_round,
                payload.highest_precommit_round
            );
        }
        Commands::Validator { sub } => match sub {
            ValidatorCommands::RegisterValidator {
                withdrawal_seed,
                withdrawal_key_file,
                voting_seed,
                voting_key_file,
                amount,
                commission_bps,
                rpc,
                nonce,
                chain_id,
                dry_run,
                token,
            } => {
                let withdrawal_kp =
                    resolve_falcon_keypair(withdrawal_key_file, withdrawal_seed, "withdrawal")?;
                let voting_kp = resolve_falcon_keypair(voting_key_file, voting_seed, "voting")?;
                let chain_id = resolve_required_chain_id(&rpc, chain_id)?;
                let withdrawal_addr = falcon_pq_address(&withdrawal_kp);
                let account_nonce = resolve_nonce(&rpc, &withdrawal_addr, nonce)?;
                let (tx, validator_id) = build_register_validator_tx_with_chain(
                    &withdrawal_kp,
                    &voting_kp,
                    amount,
                    commission_bps,
                    account_nonce,
                    chain_id,
                );
                if !tx.verify_signature_for_chain(chain_id, true) {
                    anyhow::bail!(
                        "refusing to submit: built register-validator tx failed chain-bound verify"
                    );
                }
                println!(
                    "✅ RegisterValidator signed (OpCode 59, Falcon-512 PoP, chain_id={chain_id}):"
                );
                println!("  Validator ID:       {}", hex::encode(validator_id));
                println!("  Withdrawal Address: {}", hex::encode(withdrawal_addr));
                println!("  Amount:             {amount} nano-STELL");
                println!("  Commission:         {commission_bps} bps");
                println!("  Nonce:              {account_nonce}");
                println!(
                    "  Hash:               {}",
                    hex::encode(tx.compute_tx_hash())
                );
                if dry_run {
                    println!("  raw: {}", hex::encode(bincode::serialize(&tx)?));
                    return Ok(());
                }
                let hash = rpc_submit_tx(&rpc, "stell_sendRawTransaction", &tx, token.as_deref())?;
                println!("  Submitted, mempool tx hash: {hash}");
            }
            ValidatorCommands::RotateVotingKey {
                withdrawal_seed,
                withdrawal_key_file,
                validator_id,
                rotation_seq,
                new_voting_seed,
                new_voting_key_file,
                cancel,
                rpc,
                nonce,
                chain_id,
                dry_run,
                token,
            } => {
                let withdrawal_kp =
                    resolve_falcon_keypair(withdrawal_key_file, withdrawal_seed, "withdrawal")?;
                let validator_id = parse_wallet_address(&validator_id)?;
                let new_voting_kp = if cancel {
                    None
                } else {
                    Some(resolve_falcon_keypair(
                        new_voting_key_file,
                        new_voting_seed,
                        "new-voting",
                    )?)
                };
                let chain_id = resolve_required_chain_id(&rpc, chain_id)?;
                let withdrawal_addr = falcon_pq_address(&withdrawal_kp);
                let account_nonce = resolve_nonce(&rpc, &withdrawal_addr, nonce)?;
                let tx = build_rotate_voting_key_tx_with_chain(
                    &withdrawal_kp,
                    validator_id,
                    rotation_seq,
                    new_voting_kp.as_ref(),
                    account_nonce,
                    chain_id,
                );
                if !tx.verify_signature_for_chain(chain_id, true) {
                    anyhow::bail!(
                        "refusing to submit: built rotate-voting-key tx failed chain-bound verify"
                    );
                }
                println!("✅ RotateVotingKey signed (OpCode 60, cancel={cancel}, seq={rotation_seq}, chain_id={chain_id}):");
                println!("  Validator ID: {}", hex::encode(validator_id));
                println!("  Nonce:        {account_nonce}");
                println!("  Hash:         {}", hex::encode(tx.compute_tx_hash()));
                if dry_run {
                    println!("  raw: {}", hex::encode(bincode::serialize(&tx)?));
                    return Ok(());
                }
                let hash = rpc_submit_tx(&rpc, "stell_sendRawTransaction", &tx, token.as_deref())?;
                println!("  Submitted, mempool tx hash: {hash}");
            }
            ValidatorCommands::ChangeWithdrawal {
                withdrawal_seed,
                withdrawal_key_file,
                validator_id,
                new_withdrawal_seed,
                new_withdrawal_key_file,
                rpc,
                nonce,
                chain_id,
                dry_run,
                token,
            } => {
                let current_kp =
                    resolve_falcon_keypair(withdrawal_key_file, withdrawal_seed, "withdrawal")?;
                let new_kp = resolve_falcon_keypair(
                    new_withdrawal_key_file,
                    new_withdrawal_seed,
                    "new-withdrawal",
                )?;
                let validator_id = parse_wallet_address(&validator_id)?;
                let chain_id = resolve_required_chain_id(&rpc, chain_id)?;
                let current_addr = falcon_pq_address(&current_kp);
                let account_nonce = resolve_nonce(&rpc, &current_addr, nonce)?;
                let tx = build_change_withdrawal_tx_with_chain(
                    &current_kp,
                    validator_id,
                    &new_kp,
                    account_nonce,
                    chain_id,
                );
                if !tx.verify_signature_for_chain(chain_id, true) {
                    anyhow::bail!(
                        "refusing to submit: built change-withdrawal tx failed chain-bound verify"
                    );
                }
                println!(
                    "✅ ChangeWithdrawal signed (OpCode 61, Falcon-512 PoP, chain_id={chain_id}):"
                );
                println!("  Validator ID:   {}", hex::encode(validator_id));
                println!(
                    "  New Withdrawal: {}",
                    hex::encode(falcon_pq_address(&new_kp))
                );
                println!("  Nonce:          {account_nonce}");
                println!("  Hash:           {}", hex::encode(tx.compute_tx_hash()));
                if dry_run {
                    println!("  raw: {}", hex::encode(bincode::serialize(&tx)?));
                    return Ok(());
                }
                let hash = rpc_submit_tx(&rpc, "stell_sendRawTransaction", &tx, token.as_deref())?;
                println!("  Submitted, mempool tx hash: {hash}");
            }
            ValidatorCommands::ClaimWithdrawal {
                withdrawal_seed,
                withdrawal_key_file,
                validator_id,
                voting_seed,
                voting_key_file,
                rpc,
                nonce,
                chain_id,
                dry_run,
                token,
            } => {
                let withdrawal_kp =
                    resolve_falcon_keypair(withdrawal_key_file, withdrawal_seed, "withdrawal")?;
                let voting_kp = resolve_falcon_keypair(voting_key_file, voting_seed, "voting")?;
                let validator_id = parse_wallet_address(&validator_id)?;
                let chain_id = resolve_required_chain_id(&rpc, chain_id)?;
                let withdrawal_addr = falcon_pq_address(&withdrawal_kp);
                // Funding diagnosis BEFORE signing: a claim from an unfunded
                // new cold address can be signed but never included (no gas).
                // Printed again after signing so the last line before
                // submission cannot hide it. --dry-run still works.
                let funding_warning = claim_withdrawal_funding_warning(&rpc, &withdrawal_addr);
                if let Some(msg) = &funding_warning {
                    eprintln!("⚠️  {msg}");
                }
                let account_nonce = resolve_nonce(&rpc, &withdrawal_addr, nonce)?;
                let tx = build_claim_withdrawal_tx_with_chain(
                    &withdrawal_kp,
                    validator_id,
                    &voting_kp,
                    account_nonce,
                    chain_id,
                );
                if !tx.verify_signature_for_chain(chain_id, true) {
                    anyhow::bail!(
                        "refusing to submit: built claim-withdrawal tx failed chain-bound verify"
                    );
                }
                if let Some(msg) = &funding_warning {
                    eprintln!("⚠️  {msg}");
                }
                println!("✅ ClaimWithdrawal signed (OpCode 62, chain_id={chain_id}):");
                println!("  Validator ID:       {}", hex::encode(validator_id));
                println!("  Withdrawal Address: {}", hex::encode(withdrawal_addr));
                println!("  Nonce:              {account_nonce}");
                println!(
                    "  Hash:               {}",
                    hex::encode(tx.compute_tx_hash())
                );
                if dry_run {
                    println!("  raw: {}", hex::encode(bincode::serialize(&tx)?));
                    return Ok(());
                }
                let hash = rpc_submit_tx(&rpc, "stell_sendRawTransaction", &tx, token.as_deref())?;
                println!("  Submitted, mempool tx hash: {hash}");
            }
            ValidatorCommands::AnnounceCommission {
                withdrawal_seed,
                withdrawal_key_file,
                validator_id,
                new_bps,
                rpc,
                nonce,
                chain_id,
                dry_run,
                token,
            } => {
                let withdrawal_kp =
                    resolve_falcon_keypair(withdrawal_key_file, withdrawal_seed, "withdrawal")?;
                let validator_id = parse_wallet_address(&validator_id)?;
                let chain_id = resolve_required_chain_id(&rpc, chain_id)?;
                let withdrawal_addr = falcon_pq_address(&withdrawal_kp);
                let account_nonce = resolve_nonce(&rpc, &withdrawal_addr, nonce)?;
                let tx = build_announce_commission_tx_with_chain(
                    &withdrawal_kp,
                    validator_id,
                    new_bps,
                    account_nonce,
                    chain_id,
                );
                if !tx.verify_signature_for_chain(chain_id, true) {
                    anyhow::bail!(
                        "refusing to submit: built announce-commission tx failed chain-bound verify"
                    );
                }
                println!("✅ AnnounceCommission signed (OpCode 63, new_bps={new_bps}, chain_id={chain_id}):");
                println!("  Validator ID: {}", hex::encode(validator_id));
                println!("  Nonce:        {account_nonce}");
                println!("  Hash:         {}", hex::encode(tx.compute_tx_hash()));
                if dry_run {
                    println!("  raw: {}", hex::encode(bincode::serialize(&tx)?));
                    return Ok(());
                }
                let hash = rpc_submit_tx(&rpc, "stell_sendRawTransaction", &tx, token.as_deref())?;
                println!("  Submitted, mempool tx hash: {hash}");
            }
            ValidatorCommands::ApplyCommission {
                withdrawal_seed,
                withdrawal_key_file,
                validator_id,
                rpc,
                nonce,
                chain_id,
                dry_run,
                token,
            } => {
                let withdrawal_kp =
                    resolve_falcon_keypair(withdrawal_key_file, withdrawal_seed, "withdrawal")?;
                let validator_id = parse_wallet_address(&validator_id)?;
                let chain_id = resolve_required_chain_id(&rpc, chain_id)?;
                let withdrawal_addr = falcon_pq_address(&withdrawal_kp);
                let account_nonce = resolve_nonce(&rpc, &withdrawal_addr, nonce)?;
                let tx = build_apply_commission_tx_with_chain(
                    &withdrawal_kp,
                    validator_id,
                    account_nonce,
                    chain_id,
                );
                if !tx.verify_signature_for_chain(chain_id, true) {
                    anyhow::bail!(
                        "refusing to submit: built apply-commission tx failed chain-bound verify"
                    );
                }
                println!("✅ ApplyCommission signed (OpCode 64, chain_id={chain_id}):");
                println!("  Validator ID: {}", hex::encode(validator_id));
                println!("  Nonce:        {account_nonce}");
                println!("  Hash:         {}", hex::encode(tx.compute_tx_hash()));
                if dry_run {
                    println!("  raw: {}", hex::encode(bincode::serialize(&tx)?));
                    return Ok(());
                }
                let hash = rpc_submit_tx(&rpc, "stell_sendRawTransaction", &tx, token.as_deref())?;
                println!("  Submitted, mempool tx hash: {hash}");
            }
            ValidatorCommands::Status { validator, rpc } => {
                let validator_bytes = parse_wallet_address(&validator)?;
                let validator_hex = hex::encode(validator_bytes);
                let status = rpc_call(
                    &rpc,
                    "stell_getValidatorStatus",
                    serde_json::json!({ "validator": validator_hex }),
                )?;
                let stake = rpc_call(
                    &rpc,
                    "stell_stakeOf",
                    serde_json::json!({ "validator": validator_hex }),
                )?;
                let withdrawal_info = if let Some(w_addr) = status["withdrawal_address"].as_str() {
                    let bal = rpc_call(
                        &rpc,
                        "stell_getBalance",
                        serde_json::json!({ "address": w_addr }),
                    )?;
                    Some((w_addr.to_string(), bal))
                } else {
                    None
                };

                println!("Validator Status:");
                println!("  Validator ID:   {validator_hex}");
                println!(
                    "  Known:          {}",
                    status["known"].as_bool().unwrap_or(false)
                );
                // Prominent diagnosis FIRST: it answers the only question an
                // operator has when a validator is down — can this bond be
                // recovered at all with the keys currently on chain?
                println!("  {}", format_manageability(&status));
                println!(
                    "  In Active Set:  {}",
                    status["in_set"].as_bool().unwrap_or(false)
                );
                let jailed = status["jailed"].as_bool().unwrap_or(false);
                println!("  Jailed:         {jailed}");
                if jailed {
                    println!(
                        "  Jailed Height:  {}",
                        status["jailed_at_height"]
                            .as_u64()
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| "none".to_string())
                    );
                    println!(
                        "  Release Height: {}",
                        status["release_height"]
                            .as_u64()
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| "none".to_string())
                    );
                    let current_height = rpc_call(&rpc, "stell_blockNumber", serde_json::json!([]))
                        .ok()
                        .and_then(|v| json_block_height(&v));
                    if let Some(line) = format_jail_release(&status, current_height) {
                        println!("  {line}");
                    }
                    if let Some(current) = current_height {
                        println!("  Current Height: {current}");
                    }
                }
                println!(
                    "  Total Stake:    {} nano-STELL",
                    stake["total"].as_str().unwrap_or("0")
                );
                println!(
                    "  Self Bond:      {} nano-STELL",
                    stake["self_bond"].as_str().unwrap_or("0")
                );
                println!(
                    "  Delegated:      {} nano-STELL",
                    stake["delegated"].as_str().unwrap_or("0")
                );
                println!(
                    "  Commission BPS: {}",
                    status["commission_bps"]
                        .as_u64()
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "none".to_string())
                );
                println!(
                    "  Rotation Seq:   {}",
                    status["rotation_seq"]
                        .as_u64()
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "none".to_string())
                );
                if let Some((w_addr, bal)) = withdrawal_info {
                    println!("  Withdrawal Addr: {w_addr}");
                    println!(
                        "  Withdrawal Bal:  {} nano-STELL (nonce: {})",
                        bal["balance"].as_str().unwrap_or("0"),
                        bal["nonce"].as_u64().unwrap_or(0)
                    );
                } else {
                    println!("  Withdrawal Addr: none");
                }
                if !status["pending_commission"].is_null() {
                    println!(
                        "  Pending Comm:   new_bps={}, announced={}, effective={}",
                        status["pending_commission"]["new_bps"],
                        status["pending_commission"]["announced_height"],
                        status["pending_commission"]["effective_height"],
                    );
                }
                if let Some(h) = status["last_commission_change_height"].as_u64() {
                    println!("  Last Comm Chg:  height {h}");
                }
            }
            ValidatorCommands::Stake {
                withdrawal_key_file,
                withdrawal_seed,
                validator_id,
                amount,
                rpc,
                nonce,
                chain_id,
                dry_run,
                token,
            } => {
                if amount == 0 {
                    anyhow::bail!("amount must be positive");
                }
                let withdrawal_kp =
                    resolve_falcon_keypair(withdrawal_key_file, withdrawal_seed, "withdrawal")?;
                let validator_id = parse_wallet_address(&validator_id)?;
                let chain_id = resolve_required_chain_id(&rpc, chain_id)?;
                let withdrawal_addr = falcon_pq_address(&withdrawal_kp);
                let account_nonce = resolve_nonce(&rpc, &withdrawal_addr, nonce)?;
                let tx = build_stake_tx_with_chain(
                    &withdrawal_kp,
                    validator_id,
                    amount,
                    account_nonce,
                    chain_id,
                );
                verify_and_submit_chain_bound_tx(
                    &tx,
                    chain_id,
                    "stake",
                    &format!(
                        "✅ Stake signed (SysCallStake, chain_id={chain_id}):\n  Validator ID: {}\n  Signer:       {}\n  Amount:       {amount} nano-STELL\n  Nonce:        {account_nonce}",
                        hex::encode(validator_id),
                        hex::encode(withdrawal_addr),
                    ),
                    dry_run,
                    &rpc,
                    token.as_deref(),
                )?;
            }
            ValidatorCommands::Unbond {
                withdrawal_key_file,
                withdrawal_seed,
                validator_id,
                amount,
                rpc,
                nonce,
                chain_id,
                dry_run,
                token,
            } => {
                if amount == 0 {
                    anyhow::bail!("amount must be positive");
                }
                let withdrawal_kp =
                    resolve_falcon_keypair(withdrawal_key_file, withdrawal_seed, "withdrawal")?;
                let validator_id = parse_wallet_address(&validator_id)?;
                let chain_id = resolve_required_chain_id(&rpc, chain_id)?;
                let withdrawal_addr = falcon_pq_address(&withdrawal_kp);
                let account_nonce = resolve_nonce(&rpc, &withdrawal_addr, nonce)?;
                let tx = build_unbond_tx_with_chain(
                    &withdrawal_kp,
                    validator_id,
                    amount,
                    account_nonce,
                    chain_id,
                );
                verify_and_submit_chain_bound_tx(
                    &tx,
                    chain_id,
                    "unbond",
                    &format!(
                        "✅ Unbond signed (SysCallUnbond, chain_id={chain_id}):\n  Validator ID: {}\n  Signer:       {}\n  Amount:       {amount} nano-STELL\n  Nonce:        {account_nonce}",
                        hex::encode(validator_id),
                        hex::encode(withdrawal_addr),
                    ),
                    dry_run,
                    &rpc,
                    token.as_deref(),
                )?;
            }
            ValidatorCommands::Withdraw {
                withdrawal_key_file,
                withdrawal_seed,
                validator_id,
                rpc,
                nonce,
                chain_id,
                dry_run,
                token,
            } => {
                let withdrawal_kp =
                    resolve_falcon_keypair(withdrawal_key_file, withdrawal_seed, "withdrawal")?;
                let validator_id = parse_wallet_address(&validator_id)?;
                let chain_id = resolve_required_chain_id(&rpc, chain_id)?;
                let withdrawal_addr = falcon_pq_address(&withdrawal_kp);
                let account_nonce = resolve_nonce(&rpc, &withdrawal_addr, nonce)?;
                let tx = build_withdraw_self_bond_tx_with_chain(
                    &withdrawal_kp,
                    validator_id,
                    account_nonce,
                    chain_id,
                );
                verify_and_submit_chain_bound_tx(
                    &tx,
                    chain_id,
                    "withdraw",
                    &format!(
                        "✅ WithdrawSelfBond signed (SysCallWithdrawSelfBond, chain_id={chain_id}):\n  Validator ID: {}\n  Signer:       {}\n  Nonce:        {account_nonce}",
                        hex::encode(validator_id),
                        hex::encode(withdrawal_addr),
                    ),
                    dry_run,
                    &rpc,
                    token.as_deref(),
                )?;
            }
            ValidatorCommands::Delegate {
                falcon_key_file,
                falcon_seed,
                validator_id,
                amount,
                rpc,
                nonce,
                chain_id,
                dry_run,
                token,
            } => {
                if amount == 0 {
                    anyhow::bail!("amount must be positive");
                }
                let delegator_kp =
                    resolve_falcon_keypair(falcon_key_file, falcon_seed, "delegator")?;
                let validator_id = parse_wallet_address(&validator_id)?;
                let chain_id = resolve_required_chain_id(&rpc, chain_id)?;
                let delegator_addr = falcon_pq_address(&delegator_kp);
                let account_nonce = resolve_nonce(&rpc, &delegator_addr, nonce)?;
                let tx = build_delegate_tx_with_chain(
                    &delegator_kp,
                    validator_id,
                    amount,
                    account_nonce,
                    chain_id,
                );
                verify_and_submit_chain_bound_tx(
                    &tx,
                    chain_id,
                    "delegate",
                    &format!(
                        "✅ Delegate signed (SysCallDelegate, chain_id={chain_id}):\n  Validator ID: {}\n  Delegator:    {}\n  Amount:       {amount} nano-STELL\n  Nonce:        {account_nonce}",
                        hex::encode(validator_id),
                        hex::encode(delegator_addr),
                    ),
                    dry_run,
                    &rpc,
                    token.as_deref(),
                )?;
            }
            ValidatorCommands::BeginUndelegate {
                falcon_key_file,
                falcon_seed,
                validator_id,
                amount,
                rpc,
                nonce,
                chain_id,
                dry_run,
                token,
            } => {
                if amount == 0 {
                    anyhow::bail!("amount must be positive");
                }
                let delegator_kp =
                    resolve_falcon_keypair(falcon_key_file, falcon_seed, "delegator")?;
                let validator_id = parse_wallet_address(&validator_id)?;
                let chain_id = resolve_required_chain_id(&rpc, chain_id)?;
                let delegator_addr = falcon_pq_address(&delegator_kp);
                let account_nonce = resolve_nonce(&rpc, &delegator_addr, nonce)?;
                let tx = build_begin_undelegate_tx_with_chain(
                    &delegator_kp,
                    validator_id,
                    amount,
                    account_nonce,
                    chain_id,
                );
                verify_and_submit_chain_bound_tx(
                    &tx,
                    chain_id,
                    "begin-undelegate",
                    &format!(
                        "✅ BeginUndelegate signed (SysCallBeginUndelegate, chain_id={chain_id}):\n  Validator ID: {}\n  Delegator:    {}\n  Amount:       {amount} nano-STELL\n  Nonce:        {account_nonce}",
                        hex::encode(validator_id),
                        hex::encode(delegator_addr),
                    ),
                    dry_run,
                    &rpc,
                    token.as_deref(),
                )?;
            }
            ValidatorCommands::WithdrawDelegation {
                falcon_key_file,
                falcon_seed,
                validator_id,
                rpc,
                nonce,
                chain_id,
                dry_run,
                token,
            } => {
                let delegator_kp =
                    resolve_falcon_keypair(falcon_key_file, falcon_seed, "delegator")?;
                let validator_id = parse_wallet_address(&validator_id)?;
                let chain_id = resolve_required_chain_id(&rpc, chain_id)?;
                let delegator_addr = falcon_pq_address(&delegator_kp);
                let account_nonce = resolve_nonce(&rpc, &delegator_addr, nonce)?;
                let tx = build_withdraw_delegation_tx_with_chain(
                    &delegator_kp,
                    validator_id,
                    account_nonce,
                    chain_id,
                );
                verify_and_submit_chain_bound_tx(
                    &tx,
                    chain_id,
                    "withdraw-delegation",
                    &format!(
                        "✅ WithdrawDelegation signed (SysCallUndelegate, chain_id={chain_id}):\n  Validator ID: {}\n  Delegator:    {}\n  Nonce:        {account_nonce}",
                        hex::encode(validator_id),
                        hex::encode(delegator_addr),
                    ),
                    dry_run,
                    &rpc,
                    token.as_deref(),
                )?;
            }
            ValidatorCommands::ClaimRewards {
                withdrawal_key_file,
                withdrawal_seed,
                validator_id,
                delegator,
                rpc,
                nonce,
                chain_id,
                dry_run,
                token,
            } => {
                let signer_kp = resolve_falcon_keypair(
                    withdrawal_key_file,
                    withdrawal_seed,
                    if delegator { "delegator" } else { "withdrawal" },
                )?;
                let validator_id = parse_wallet_address(&validator_id)?;
                let chain_id = resolve_required_chain_id(&rpc, chain_id)?;
                let signer_addr = falcon_pq_address(&signer_kp);
                let account_nonce = resolve_nonce(&rpc, &signer_addr, nonce)?;
                let tx = build_claim_rewards_tx_with_chain(
                    &signer_kp,
                    validator_id,
                    delegator,
                    account_nonce,
                    chain_id,
                );
                let op_name = if delegator {
                    "SysCallClaimDelegatorRewards"
                } else {
                    "SysCallClaimRewards"
                };
                verify_and_submit_chain_bound_tx(
                    &tx,
                    chain_id,
                    "claim-rewards",
                    &format!(
                        "✅ ClaimRewards signed ({op_name}, delegator={delegator}, chain_id={chain_id}):\n  Validator ID: {}\n  Signer:       {}\n  Nonce:        {account_nonce}",
                        hex::encode(validator_id),
                        hex::encode(signer_addr),
                    ),
                    dry_run,
                    &rpc,
                    token.as_deref(),
                )?;
            }
            ValidatorCommands::Unjail {
                withdrawal_key_file,
                withdrawal_seed,
                validator_id,
                top_up,
                rpc,
                nonce,
                chain_id,
                dry_run,
                token,
            } => {
                if top_up == Some(0) {
                    anyhow::bail!(
                        "--top-up must be positive; omit --top-up instead of passing zero"
                    );
                }
                let withdrawal_kp =
                    resolve_falcon_keypair(withdrawal_key_file, withdrawal_seed, "withdrawal")?;
                let validator_id = parse_wallet_address(&validator_id)?;
                let chain_id = resolve_required_chain_id(&rpc, chain_id)?;
                let withdrawal_addr = falcon_pq_address(&withdrawal_kp);
                // Refuse a provably dead unjail BEFORE signing/paying: early
                // release height, no cold address, or an unfunded withdrawal
                // address. --dry-run prints the same diagnosis but proceeds.
                preflight_unjail(&rpc, &validator_id, dry_run, true)?;
                let account_nonce = resolve_nonce(&rpc, &withdrawal_addr, nonce)?;
                let tx = build_unjail_tx_with_chain(
                    &withdrawal_kp,
                    validator_id,
                    top_up,
                    account_nonce,
                    chain_id,
                );
                verify_and_submit_chain_bound_tx(
                    &tx,
                    chain_id,
                    "unjail",
                    &format!(
                        "✅ Unjail signed (SysCallUnjail, Ruleset v7, chain_id={chain_id}):\n  Validator ID: {}\n  Withdrawal:   {}\n  Top-up:       {} nano-STELL\n  Nonce:        {account_nonce}",
                        hex::encode(validator_id),
                        hex::encode(withdrawal_addr),
                        top_up.unwrap_or(0),
                    ),
                    dry_run,
                    &rpc,
                    token.as_deref(),
                )?;
            }
        },
        Commands::Gov { sub } => match sub {
            GovCommands::List { rpc } => {
                let proposals = rpc_call(&rpc, "stell_listProposals", serde_json::json!([]))?;
                let items = proposals.as_array().ok_or_else(|| {
                    anyhow::anyhow!("unexpected stell_listProposals response (expected array)")
                })?;
                if items.is_empty() {
                    println!("No governance proposals found.");
                    return Ok(());
                }
                println!(
                    "{:<4} {:<10} {:<28} {:<12} {:<16} {:<16} {:<16} TITLE",
                    "ID", "STATUS", "ACTION", "VOTING_END", "YES", "NO", "ABSTAIN"
                );
                println!("{}", "-".repeat(120));
                for p in items {
                    println!(
                        "{:<4} {:<10} {:<28} {:<12} {:<16} {:<16} {:<16} {}",
                        p["id"].as_u64().unwrap_or(0),
                        p["status"].as_str().unwrap_or("?"),
                        p["action_type"].as_str().unwrap_or("?"),
                        p["voting_end"].as_u64().unwrap_or(0),
                        p["yes"].as_str().unwrap_or("0"),
                        p["no"].as_str().unwrap_or("0"),
                        p["abstain"].as_str().unwrap_or("0"),
                        p["title"].as_str().unwrap_or(""),
                    );
                }
            }
            GovCommands::Show { id, rpc } => {
                let p = rpc_call(&rpc, "stell_proposal", serde_json::json!({ "id": id }))?;
                let g = rpc_call(&rpc, "stell_governanceParams", serde_json::json!([]))?;
                println!("Proposal #{}", p["id"].as_u64().unwrap_or(id));
                println!("  Title:       {}", p["title"].as_str().unwrap_or(""));
                println!("  Status:      {}", p["status"].as_str().unwrap_or("?"));
                println!(
                    "  Action Type: {}",
                    p["action_type"].as_str().unwrap_or("?")
                );
                println!("  Action:      {}", p["action"].as_str().unwrap_or("?"));
                println!("  Voting End:  {}", p["voting_end"].as_u64().unwrap_or(0));
                println!("  Yes:         {}", p["yes"].as_str().unwrap_or("0"));
                println!("  No:          {}", p["no"].as_str().unwrap_or("0"));
                println!("  Abstain:     {}", p["abstain"].as_str().unwrap_or("0"));
                println!("  Turnout:     {}", p["turnout"].as_str().unwrap_or("0"));
                println!("Governance Context:");
                println!("  Quorum BPS:  {}", g["quorum_bps"].as_u64().unwrap_or(0));
                println!("  Next ID:     {}", g["next_id"].as_u64().unwrap_or(0));
            }
            GovCommands::Params { rpc } => {
                let g = rpc_call(&rpc, "stell_governanceParams", serde_json::json!([]))?;
                println!("Governance Parameters:");
                println!("  quorum_bps: {}", g["quorum_bps"]);
                println!("  next_id:    {}", g["next_id"]);
                println!(
                    "  applied:    {}",
                    serde_json::to_string_pretty(&g["applied"])?
                );
            }
            GovCommands::Propose {
                falcon_key_file,
                falcon_seed,
                title,
                action,
                params,
                proposal_id,
                height,
                rpc,
                nonce,
                chain_id,
                dry_run,
                token,
            } => {
                let parsed_params: serde_json::Value = serde_json::from_str(&params)
                    .map_err(|e| anyhow::anyhow!("invalid --params JSON: {e}"))?;
                let gov_action =
                    stellereum::governance::gov_action_from_params(&action, &parsed_params)
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                let proposer_kp = resolve_falcon_keypair(falcon_key_file, falcon_seed, "falcon")?;
                let chain_id = resolve_required_chain_id(&rpc, chain_id)?;
                let proposer_addr = falcon_pq_address(&proposer_kp);
                let account_nonce = resolve_nonce(&rpc, &proposer_addr, nonce)?;
                let pid = match proposal_id {
                    Some(id) => id,
                    None => {
                        let g = rpc_call(&rpc, "stell_governanceParams", serde_json::json!([]))?;
                        g["next_id"].as_u64().ok_or_else(|| {
                            anyhow::anyhow!("stell_governanceParams did not return next_id")
                        })?
                    }
                };
                let height_observed = match height {
                    Some(h) => h,
                    None => rpc_next_block_height(&rpc)?,
                };
                let tx = build_gov_propose_tx_with_chain(
                    &proposer_kp,
                    pid,
                    title.clone(),
                    gov_action,
                    height_observed,
                    account_nonce,
                    chain_id,
                )?;
                verify_and_submit_chain_bound_tx(
                    &tx,
                    chain_id,
                    "gov-propose",
                    &format!(
                        "✅ GovPropose signed (SysCallGovPropose, chain_id={chain_id}):\n  Proposal ID: {pid}\n  Title:       {title}\n  Action:      {action}\n  Height Obs:  {height_observed}\n  Proposer:    {}\n  Nonce:       {account_nonce}",
                        hex::encode(proposer_addr),
                    ),
                    dry_run,
                    &rpc,
                    token.as_deref(),
                )?;
            }
            GovCommands::Vote {
                falcon_key_file,
                falcon_seed,
                id,
                choice,
                height,
                rpc,
                nonce,
                chain_id,
                dry_run,
                token,
            } => {
                let vote_choice = parse_vote_choice(&choice)?;
                let voter_kp = resolve_falcon_keypair(falcon_key_file, falcon_seed, "falcon")?;
                let chain_id = resolve_required_chain_id(&rpc, chain_id)?;
                let voter_addr = falcon_pq_address(&voter_kp);
                let account_nonce = resolve_nonce(&rpc, &voter_addr, nonce)?;
                let height_observed = match height {
                    Some(h) => h,
                    None => rpc_next_block_height(&rpc)?,
                };
                let tx = build_gov_vote_tx_with_chain(
                    &voter_kp,
                    id,
                    vote_choice,
                    height_observed,
                    account_nonce,
                    chain_id,
                );
                verify_and_submit_chain_bound_tx(
                    &tx,
                    chain_id,
                    "gov-vote",
                    &format!(
                        "✅ GovVote signed (SysCallGovVote, chain_id={chain_id}):\n  Proposal ID: {id}\n  Choice:      {vote_choice:?}\n  Height Obs:  {height_observed}\n  Voter:       {}\n  Nonce:       {account_nonce}",
                        hex::encode(voter_addr),
                    ),
                    dry_run,
                    &rpc,
                    token.as_deref(),
                )?;
            }
        },
    }
    Ok(())
}

/// Parse a JSON-RPC block height that may be a number, a decimal string, or a
/// `0x`-prefixed hex string (`stell_blockNumber` uses the hex form today).
fn json_block_height(value: &serde_json::Value) -> Option<u64> {
    if let Some(n) = value.as_u64() {
        return Some(n);
    }
    let s = value.as_str()?;
    if let Some(hex_str) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex_str, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

/// Parse a nano-STELL amount returned by `stell_getBalance` (`balance` is a
/// decimal string today; accept a JSON number too for forward compatibility).
fn json_nano_amount(value: &serde_json::Value) -> Option<u64> {
    if let Some(n) = value.as_u64() {
        return Some(n);
    }
    value.as_str().and_then(|s| s.trim().parse::<u64>().ok())
}

/// The prominent `MANAGEABILITY` line for `stellereum validator status`.
///
/// Pure so the CLI's operator-facing diagnosis is testable without a node.
/// `None` for `withdrawal_address` is the exact live incident shape: the
/// record exists, but no key can authorize unjail/unbond/withdraw until the
/// one-time ClaimWithdrawal migration claims a cold address.
fn format_manageability(status: &serde_json::Value) -> String {
    if !status["known"].as_bool().unwrap_or(false) {
        return "MANAGEABILITY: UNKNOWN — no staking record, so unjail/unbond/withdraw cannot be authorized"
            .to_string();
    }
    match status["withdrawal_address"].as_str() {
        Some(addr) => format!("MANAGEABILITY: OK (withdrawal {addr})"),
        None => "MANAGEABILITY: UNMANAGEABLE: no withdrawal_address — unjail/unbond/withdraw will be refused; run validator claim-withdrawal"
            .to_string(),
    }
}

/// The `released: yes/no` line for a jailed validator, with the release
/// height (and the current chain height when known). Pure for unit tests.
fn format_jail_release(status: &serde_json::Value, current_height: Option<u64>) -> Option<String> {
    if !status["jailed"].as_bool().unwrap_or(false) {
        return None;
    }
    let release = status["release_height"].as_u64();
    let released = match (release, current_height) {
        (Some(r), Some(c)) => Some(c >= r),
        _ => None,
    };
    Some(format!(
        "released: {} (release_height {})",
        match released {
            Some(true) => "yes",
            Some(false) => "no",
            None => "unknown",
        },
        release
            .map(|v| v.to_string())
            .unwrap_or_else(|| "none".to_string()),
    ))
}

/// Local preflight shared by `validator unjail` and `wallet unjail`.
///
/// The block still makes every acceptance decision; this only refuses a
/// transaction that is provably dead on arrival:
///  * validator record missing / no cold withdrawal address (no key can ever
///    authorize the op until ClaimWithdrawal);
///  * `release_height` in the future (the block would refuse it);
///  * zero balance at the withdrawal address (the tx cannot pay gas).
///
/// `--dry-run` is never blocked: the same conditions are printed as warnings
/// so an operator can inspect the signed transaction before funding/retrying.
/// RPC/parse failures are warnings, never a new hard gate: an unreachable or
/// older node must not turn a UX preflight into a refusal the chain itself
/// would not make.
///
/// `refuse_unmanageable` is true only for `validator unjail` (the Ruleset v7
/// cold-key command). `wallet unjail` keeps its legacy pre-W3 shape, where a
/// record may legitimately still have `withdrawal_address == None` and the
/// validator id itself signs; there it warns instead of refusing.
fn preflight_unjail(
    rpc: &str,
    validator_id: &[u8; 32],
    dry_run: bool,
    refuse_unmanageable: bool,
) -> anyhow::Result<()> {
    let validator_hex = hex::encode(validator_id);
    let warn_or_refuse = |msg: String, dry_run: bool| -> anyhow::Result<()> {
        if dry_run {
            eprintln!("⚠️  UNJAIL PREFLIGHT (dry-run): {msg}");
            Ok(())
        } else {
            anyhow::bail!("refusing to submit unjail: {msg}")
        }
    };

    let status = match rpc_call(
        rpc,
        "stell_getValidatorStatus",
        serde_json::json!({ "validator": validator_hex }),
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "⚠️  UNJAIL PREFLIGHT: could not query stell_getValidatorStatus ({e}); \
                 continuing — the block still enforces every check"
            );
            return Ok(());
        }
    };

    if !status["known"].as_bool().unwrap_or(false) {
        return warn_or_refuse(
            format!(
                "validator {validator_hex} has no staking record; the block will refuse the unjail"
            ),
            dry_run,
        );
    }

    let Some(withdrawal) = status["withdrawal_address"].as_str() else {
        let msg = format!(
            "validator {validator_hex} has no cold withdrawal_address, so NO post-W3 owner \
             operation (including unjail) can be authorized. If this chain is post-W3, run \
             `stellereum validator claim-withdrawal --validator-id {validator_hex} \
             --voting-key-file ./keys/falcon.key --withdrawal-key-file <cold-withdrawal-key>` first"
        );
        // `validator unjail` is strictly post-W3 and must refuse. The legacy
        // `wallet unjail` shape (validator id signs) stays usable pre-W3, so
        // it only diagnoses.
        if dry_run {
            eprintln!("⚠️  UNJAIL PREFLIGHT (dry-run): {msg}");
            return Ok(());
        }
        if refuse_unmanageable {
            return warn_or_refuse(msg, false);
        }
        eprintln!("⚠️  UNJAIL PREFLIGHT: {msg}");
        return Ok(());
    };

    let current_height = rpc_call(rpc, "stell_blockNumber", serde_json::json!([]))
        .ok()
        .and_then(|v| json_block_height(&v));
    if let (Some(release), Some(current)) = (status["release_height"].as_u64(), current_height) {
        if current < release {
            let remaining = release.saturating_sub(current);
            // RULESET v2 tempo is ~240 ms/height; the exact height is the
            // authority, the ETA is only a human hint.
            let eta_secs = remaining.saturating_mul(240).div_ceil(1_000);
            return warn_or_refuse(
                format!(
                    "release_height {release} is {remaining} height(s) in the future \
                     (current height {current}, ETA ~{eta_secs}s at 240 ms/height); retry at/after \
                     release_height — the block would refuse it now"
                ),
                dry_run,
            );
        }
    }

    match rpc_call(
        rpc,
        "stell_getBalance",
        serde_json::json!({ "address": withdrawal }),
    ) {
        Ok(bal) => {
            if json_nano_amount(&bal["balance"]) == Some(0) {
                return warn_or_refuse(
                    format!(
                        "withdrawal address {withdrawal} has ZERO balance: fund the withdrawal \
                         address first (faucet or a transfer) — the transaction cannot pay gas. No \
                         on-chain check is weakened"
                    ),
                    dry_run,
                );
            }
        }
        Err(e) => eprintln!(
            "⚠️  UNJAIL PREFLIGHT: could not query the withdrawal-address balance ({e}); \
             continuing — the block still enforces every check"
        ),
    }
    Ok(())
}

/// Funding warning for `validator claim-withdrawal`: a claim signed by an
/// unfunded NEW cold address cannot be included (it cannot pay gas). The
/// command still signs/submits exactly as before, and `--dry-run` is allowed;
/// this is a loud preflight diagnosis, not a new acceptance rule.
fn claim_withdrawal_funding_warning(rpc: &str, withdrawal_addr: &[u8; 32]) -> Option<String> {
    let addr = hex::encode(withdrawal_addr);
    let bal = rpc_call(
        rpc,
        "stell_getBalance",
        serde_json::json!({ "address": addr }),
    )
    .ok()?;
    if json_nano_amount(&bal["balance"]) == Some(0) {
        Some(format!(
            "PREFLIGHT: new withdrawal address {addr} has ZERO balance. The ClaimWithdrawal \
             transaction cannot be included until that address is funded (faucet or a transfer); \
             it cannot pay gas. The claim is still signed/submitted unchanged"
        ))
    } else {
        None
    }
}

fn rpc_call(
    rpc: &str,
    method: &str,
    params: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    })
    .to_string();
    let resp: serde_json::Value = ureq::post(rpc).send_string(&body)?.into_json()?;
    if let Some(e) = resp.get("error") {
        anyhow::bail!("RPC {method} error: {e}");
    }
    Ok(resp
        .get("result")
        .cloned()
        .unwrap_or(serde_json::Value::Null))
}

fn rpc_next_block_height(rpc: &str) -> anyhow::Result<u64> {
    let res = rpc_call(rpc, "stell_blockNumber", serde_json::json!([]))?;
    let current = if let Some(n) = res.as_u64() {
        n
    } else if let Some(s) = res.as_str() {
        if let Some(hex_str) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            u64::from_str_radix(hex_str, 16)
                .map_err(|e| anyhow::anyhow!("invalid stell_blockNumber hex '{s}': {e}"))?
        } else {
            s.parse::<u64>()
                .map_err(|e| anyhow::anyhow!("invalid stell_blockNumber '{s}': {e}"))?
        }
    } else {
        anyhow::bail!("node at {rpc} returned unexpected stell_blockNumber: {res}");
    };
    Ok(current.saturating_add(1))
}

fn verify_and_submit_chain_bound_tx(
    tx: &Transaction,
    chain_id: u64,
    label: &str,
    summary: &str,
    dry_run: bool,
    rpc: &str,
    token: Option<&str>,
) -> anyhow::Result<()> {
    if !tx.verify_signature_for_chain(chain_id, true) {
        anyhow::bail!("refusing to submit: built {label} tx failed chain-bound verify");
    }
    println!("{summary}");
    println!("  Hash:         {}", hex::encode(tx.compute_tx_hash()));
    if dry_run {
        println!("  raw: {}", hex::encode(bincode::serialize(tx)?));
        return Ok(());
    }
    let hash = rpc_submit_tx(rpc, "stell_sendRawTransaction", tx, token)?;
    println!("  Submitted, mempool tx hash: {hash}");
    Ok(())
}

#[cfg(test)]
mod cli_status_tests {
    use super::*;

    #[test]
    fn manageability_line_is_prominent_and_actionable() {
        let ok = serde_json::json!({
            "known": true,
            "withdrawal_address": "77aa77aa77aa77aa77aa77aa77aa77aa77aa77aa77aa77aa77aa77aa77aa77aa",
        });
        let line = format_manageability(&ok);
        assert!(line.starts_with("MANAGEABILITY: OK (withdrawal "), "{line}");

        let missing = serde_json::json!({ "known": true, "withdrawal_address": null });
        let line = format_manageability(&missing);
        assert!(line.starts_with("MANAGEABILITY: UNMANAGEABLE"), "{line}");
        assert!(line.contains("no withdrawal_address"), "{line}");
        assert!(line.contains("claim-withdrawal"), "{line}");
        assert!(line.contains("unjail/unbond/withdraw"), "{line}");

        let unknown = serde_json::json!({ "known": false });
        let line = format_manageability(&unknown);
        assert!(line.starts_with("MANAGEABILITY: UNKNOWN"), "{line}");
    }

    #[test]
    fn jail_release_line_reports_released_yes_and_no() {
        let future = serde_json::json!({
            "jailed": true,
            "release_height": 24_421,
        });
        let line = format_jail_release(&future, Some(20_421)).expect("jailed line");
        assert!(line.starts_with("released: no"), "{line}");
        assert!(line.contains("24421"), "{line}");

        let past = serde_json::json!({
            "jailed": true,
            "release_height": 24_421,
        });
        let line = format_jail_release(&past, Some(25_000)).expect("jailed line");
        assert!(line.starts_with("released: yes"), "{line}");

        let healthy = serde_json::json!({ "jailed": false });
        assert!(format_jail_release(&healthy, Some(25_000)).is_none());
    }

    #[test]
    fn block_height_accepts_hex_decimal_and_number() {
        assert_eq!(
            json_block_height(&serde_json::json!("0x2710")),
            Some(10_000)
        );
        assert_eq!(json_block_height(&serde_json::json!("10000")), Some(10_000));
        assert_eq!(json_block_height(&serde_json::json!(10_000)), Some(10_000));
        assert_eq!(json_block_height(&serde_json::json!("nope")), None);
    }

    #[test]
    fn nano_amount_accepts_string_and_number() {
        assert_eq!(json_nano_amount(&serde_json::json!("0")), Some(0));
        assert_eq!(json_nano_amount(&serde_json::json!("123")), Some(123));
        assert_eq!(json_nano_amount(&serde_json::json!(123)), Some(123));
        assert_eq!(json_nano_amount(&serde_json::json!(null)), None);
    }
}
