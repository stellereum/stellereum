use crate::db::{BlockRecord, Database, EventRecord, TxRecord};
use crate::events::{event_from_json, AbiCache, RawEvent};
use anyhow::Result;
use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

pub struct Syncer {
    db: Database,
    client: Client,
    node_url: String,
    rpc_url: String,
    /// The contract ABI manifests the indexer knows about. They are what makes
    /// the indexed events DECODED instead of raw.
    abis: Arc<AbiCache>,
}

/// How many receipts of one block are fetched at the same time.
const RECEIPT_FETCH_CONCURRENCY: usize = 8;

/// Upper bound on the receipts fetched per block (a pathological block cannot
/// make the indexer open an unbounded number of connections).
const MAX_RECEIPTS_PER_BLOCK: usize = 256;

impl Syncer {
    pub fn new(db: Database, node_url: String, rpc_url: String) -> Self {
        Self::new_with_abis(db, node_url, rpc_url, Arc::new(AbiCache::new()))
    }

    /// A syncer that shares the ABI cache with the API server, so the API can
    /// decode an event whose manifest was fetched after the event was indexed.
    pub fn new_with_abis(
        db: Database,
        node_url: String,
        rpc_url: String,
        abis: Arc<AbiCache>,
    ) -> Self {
        Self {
            db,
            client: Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
            node_url,
            rpc_url,
            abis,
        }
    }

    /// The ABI cache this syncer fills.
    pub fn abis(&self) -> Arc<AbiCache> {
        Arc::clone(&self.abis)
    }

    pub async fn run(&self) {
        info!("Starting Stellereum Lightweight Indexer Syncer loop...");
        let mut interval = tokio::time::interval(Duration::from_millis(400));

        loop {
            interval.tick().await;
            if let Err(e) = self.sync_step().await {
                warn!("[syncer] sync step warning: {e}");
            }
        }
    }

    async fn sync_step(&self) -> Result<()> {
        // 1. Fetch recent blocks from the explorer API
        let url = format!("{}/api/blocks", self.node_url);
        let resp = self.client.get(&url).send().await?;
        if !resp.status().is_success() {
            anyhow::bail!("Node API returned HTTP {}", resp.status());
        }

        let blocks_json: Vec<Value> = resp.json().await?;
        for b in blocks_json.iter().rev() {
            let height = b["height"].as_u64().unwrap_or(0);
            let hash = b["hash"].as_str().unwrap_or("").to_string();
            let timestamp = b["timestamp"].as_u64().unwrap_or(0);
            let tx_count = b["txs"].as_u64().unwrap_or(0);

            if hash.is_empty() {
                continue;
            }

            let shard_id = b["shard_id"].as_u64().unwrap_or(0) as u32;

            // Skip only the IDENTICAL block; a different hash at a known
            // (shard,height) is a reorg — re-process so insert_block
            // replaces it and dependents re-index (audit B-IDX-2).
            if let Some(known) = self
                .db
                .get_block_by_shard_and_height(shard_id, height)?
            {
                if known.hash == hash {
                    continue;
                }
            }

            let block_record = BlockRecord {
                shard_id,
                height,
                hash: hash.clone(),
                timestamp,
                tx_count,
                proposer: None,
                proposer_stl57: None,
                state_root: None,
            };

            self.db.insert_block(&block_record)?;
            info!("[syncer] Indexed Block Shard {shard_id} #{height} ({tx_count} txs, {hash})");

            // If block carries transactions, fetch and index them
            if tx_count > 0 {
                self.index_block_transactions(height, &hash, timestamp)
                    .await;
            }
        }

        Ok(())
    }

    async fn index_block_transactions(&self, height: u64, _block_hash: &str, timestamp: u64) {
        // Try eth_getBlockByNumber with full txs
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getBlockByNumber",
            "params": [format!("0x{:x}", height), true],
            "id": 1
        });

        let mut indexed_hashes: Vec<String> = Vec::new();

        if let Ok(resp) = self.client.post(&self.rpc_url).json(&payload).send().await {
            if let Ok(data) = resp.json::<Value>().await {
                if let Some(txs) = data["result"]["transactions"].as_array() {
                    for (i, tx) in txs.iter().enumerate() {
                        let tx_hash = tx["hash"].as_str().unwrap_or("").to_string();
                        let from_addr = tx["from"].as_str().unwrap_or("").to_string();
                        let to_addr = tx["to"].as_str().unwrap_or("").to_string();
                        let value = tx["value"].as_str().unwrap_or("0x0").to_string();
                        let gas_limit = tx["gas"].as_str().unwrap_or("0x0").to_string();

                        if !tx_hash.is_empty() {
                            let from_stl57 = crate::db::to_stl57(&from_addr);
                            let to_stl57 = crate::db::to_stl57(&to_addr);
                            let tx_rec = TxRecord {
                                tx_hash: tx_hash.clone(),
                                block_height: height,
                                tx_index: i as u32,
                                from_addr,
                                to_addr,
                                from_stl57,
                                to_stl57,
                                amount: value,
                                fee_charged: "370000".to_string(),
                                gas_limit,
                                status: "success".to_string(),
                                timestamp,
                            };
                            let _ = self.db.insert_transaction(&tx_rec);
                            indexed_hashes.push(tx_hash);
                        }
                    }
                }
            }
        }

        // Contract events: every receipt carries the events its transaction
        // emitted. They are indexed per transaction so the explorer can serve
        // them per contract, per transaction and per block range.
        if indexed_hashes.is_empty() {
            // The EVM-shaped block listing did not yield the transactions;
            // fall back to the NATIVE listing, which is served from the same
            // receipt index the events live in.
            indexed_hashes = self.native_block_tx_hashes(height).await;
        }
        self.index_block_events(height, &indexed_hashes).await;

        // Fallback: check receipts
        info!("[syncer] Finished indexing txs for Block #{height}");
    }

    /// The native transaction hashes of a block, from the node's own receipt
    /// index.
    async fn native_block_tx_hashes(&self, height: u64) -> Vec<String> {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "stell_getBlockTransactions",
            "params": { "height": height },
            "id": 1
        });
        let resp = match self.client.post(&self.rpc_url).json(&payload).send().await {
            Ok(r) => r,
            Err(e) => {
                warn!("[syncer] native block listing failed at {height}: {e}");
                return Vec::new();
            }
        };
        let data: Value = match resp.json().await {
            Ok(d) => d,
            Err(_) => return Vec::new(),
        };
        data["result"]["txs"]
            .as_array()
            .map(|txs| {
                txs.iter()
                    .filter_map(|t| t["tx_hash"].as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Fetch the receipts of a block's transactions and index their events.
    async fn index_block_events(&self, height: u64, tx_hashes: &[String]) {
        if tx_hashes.is_empty() {
            return;
        }
        let mut set = tokio::task::JoinSet::new();
        let mut pending = 0usize;
        for hash in tx_hashes.iter().take(MAX_RECEIPTS_PER_BLOCK) {
            if pending >= RECEIPT_FETCH_CONCURRENCY {
                while let Some(res) = set.join_next().await {
                    pending = pending.saturating_sub(1);
                    if let Ok(Some(events)) = res {
                        self.store_events(height, events).await;
                    }
                }
            }
            let hash = hash.clone();
            let client = self.client.clone();
            let rpc_url = self.rpc_url.clone();
            set.spawn(async move { fetch_receipt_events(&client, &rpc_url, &hash).await });
            pending += 1;
        }
        while let Some(res) = set.join_next().await {
            if let Ok(Some(events)) = res {
                self.store_events(height, events).await;
            }
        }
    }

    /// Store the events of one receipt, decoding them with the ABI when it is
    /// known.
    async fn store_events(&self, height: u64, events: Vec<(String, RawEvent)>) {
        if events.is_empty() {
            return;
        }
        let mut records: Vec<EventRecord> = Vec::with_capacity(events.len());
        for (tx_hash, raw) in events {
            let contract = crate::events::normalize_address(&raw.contract);
            // The manifest is fetched once per contract and then cached, so a
            // busy contract does not turn into an RPC storm.
            if !self.abis.contains(&contract) {
                let abi = self.fetch_abi(&contract).await;
                self.abis.put(&contract, abi);
            }
            let abi = self.abis.get(&contract);
            let decoded = crate::events::decode_event(abi.as_ref(), &raw);
            let topics_json =
                serde_json::to_string(&decoded.topics).unwrap_or_else(|_| "[]".to_string());
            let data_json =
                serde_json::to_string(&decoded.data).unwrap_or_else(|_| "null".to_string());
            let decoded_json = decoded
                .args
                .as_ref()
                .and_then(|a| serde_json::to_string(a).ok());
            records.push(EventRecord {
                tx_hash: tx_hash.clone(),
                block_height: height,
                log_index: 0,
                contract,
                topic0: decoded.topic0,
                topics_json,
                data: data_json,
                event_name: decoded.event_name,
                decoded_json,
            });
        }
        // The log index is the position of the event inside the transaction.
        let mut per_tx: HashMap<String, u32> = HashMap::new();
        for r in records.iter_mut() {
            let idx = per_tx.entry(r.tx_hash.clone()).or_insert(0);
            r.log_index = *idx;
            *idx += 1;
        }
        if let Err(e) = self.db.insert_events(&records) {
            warn!("[syncer] failed to store contract events: {e}");
        } else {
            info!(
                "[syncer] Indexed {} contract events at height {}",
                records.len(),
                height
            );
        }
    }

    /// Fetch the ABI manifest of a contract from the node.
    ///
    /// The manifest is committed to the state trie, so every node serves the
    /// SAME one — the explorer's decoder and the contract agree by
    /// construction.
    async fn fetch_abi(&self, contract: &str) -> Option<stellereum::contract_abi::ContractAbi> {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "stell_getContractAbi",
            "params": { "contract": contract },
            "id": 1
        });
        let resp = match self.client.post(&self.rpc_url).json(&payload).send().await {
            Ok(r) => r,
            Err(e) => {
                warn!("[syncer] ABI fetch failed for {contract}: {e}");
                return None;
            }
        };
        let data: Value = match resp.json().await {
            Ok(d) => d,
            Err(e) => {
                warn!("[syncer] ABI fetch gave no JSON for {contract}: {e}");
                return None;
            }
        };
        AbiCache::parse_abi(&data)
    }
}

/// Fetch the events of one transaction's receipt.
async fn fetch_receipt_events(
    client: &Client,
    rpc_url: &str,
    tx_hash: &str,
) -> Option<Vec<(String, RawEvent)>> {
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "stell_getTransactionReceipt",
        "params": { "hash": tx_hash },
        "id": 1
    });
    let resp = client.post(rpc_url).json(&payload).send().await.ok()?;
    let data: Value = resp.json().await.ok()?;
    let events = data["result"]["events"].as_array()?;
    let mut out = Vec::with_capacity(events.len());
    for e in events {
        if let Some(raw) = event_from_json(e) {
            out.push((tx_hash.to_string(), raw));
        }
    }
    Some(out)
}
