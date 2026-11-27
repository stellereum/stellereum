//! Lightweight SPV Network Client for Stellereum Wallet
//!
//! Two modes:
//!
//! - **Local (in-process) mode** (default, no `--rpc-url`): queries and
//!   applies against an embedded `InMemoryStateEngine` (+ optional infnode
//!   P2P adapter). Anything this mode reports is SELF-CONSISTENT with the
//!   local cache only — it is NOT chain inclusion and is labelled as such.
//! - **HTTP-RPC mode** (`--rpc-url http://host:port`): queries a real node
//!   over JSON-RPC (stdlib-only HTTP, see `rpc.rs`), verifies Merkle proofs
//!   locally against the NODE's state root, submits raw transactions, and
//!   polls `stell_getTransactionReceipt` to finality.

use crate::rpc::{self, RpcConfig, SpvAnswer, TokenSpvAnswer, TxFinality};
use ed25519_dalek::SigningKey;
use infnode::config as node_config;
use infnode::node::Node;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use stellereum::cell::PatriciaTrie;
use stellereum::network::P2pNetworkAdapter;
use stellereum::orderbook::{OrderSide, OrderType, OrderbookManager};
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::token::TokenOp;

/// Trait for key types that can authorize post-quantum transactions
pub trait PqSigner {
    fn scheme(&self) -> stellereum::post_quantum::PqScheme;
    fn public_key(&self) -> &[u8];
    fn derive_address(&self, salt: &[u8; 16]) -> [u8; 32] {
        stellereum::post_quantum::derive_pq_address(self.scheme(), self.public_key(), salt)
    }
    fn sign(&self, message: &[u8]) -> Vec<u8>;
    fn try_sign(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        let sig = self.sign(message);
        if sig.is_empty() {
            Err(format!(
                "signing failed or scheme {:?} is unsupported",
                self.scheme()
            ))
        } else {
            Ok(sig)
        }
    }
}

impl<T: PqSigner> PqSigner for &T {
    fn scheme(&self) -> stellereum::post_quantum::PqScheme {
        (*self).scheme()
    }
    fn public_key(&self) -> &[u8] {
        (*self).public_key()
    }
    fn derive_address(&self, salt: &[u8; 16]) -> [u8; 32] {
        (*self).derive_address(salt)
    }
    fn sign(&self, message: &[u8]) -> Vec<u8> {
        (*self).sign(message)
    }
    fn try_sign(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        (*self).try_sign(message)
    }
}

/// Free function alias for `LightClient::build_pq_transfer_tx`
#[allow(dead_code)]
pub fn build_pq_transfer_tx<K: PqSigner>(
    key: &K,
    to: [u8; 32],
    amount: u64,
    nonce: u64,
    shard: u32,
    is_activation: bool,
) -> Result<Transaction, String> {
    LightClient::build_pq_transfer_tx(key, to, amount, nonce, shard, is_activation)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxRecord {
    pub timestamp: u64,
    pub tx_hash: String,
    pub from: String,
    pub to: String,
    pub amount_stell: f64,
    pub fee_stell: f64,
    pub is_confidential: bool,
    pub status: String,
}

/// Maximum number of transactions retained in `recent_local_txs` / `local_txs.bin`.
pub const MAX_LOCAL_TX_HISTORY: usize = 200;

#[derive(Clone)]
pub struct LightClient {
    pub state_engine: Arc<InMemoryStateEngine>,
    pub network_adapter: Option<Arc<P2pNetworkAdapter>>,
    pub orderbook_mgr: Arc<tokio::sync::Mutex<OrderbookManager>>,
    pub cache_path: PathBuf,
    pub history_path: PathBuf,
    /// `Some` when talking to a remote node over HTTP-RPC.
    pub rpc: Option<RpcConfig>,
    /// Seconds to wait for `stell_getTransactionReceipt` finality.
    pub receipt_timeout_secs: u64,
    /// Seconds between receipt polls.
    pub receipt_poll_secs: u64,
    /// In-flight nonce hints (addr -> (next nonce, unix secs recorded)).
    /// RPC `nonce_of` sees only ON-CHAIN state, so two rapid submits reuse
    /// one nonce and the second pays a fee to fail (audit 2026-10-06). The
    /// hint reserves nonces locally; it expires after 10 min (a dropped tx
    /// must not pin a gap forever) and the chain value always wins upward.
    #[allow(clippy::type_complexity)]
    // GATE: client cache shape is fixed by mempool/nonce tracking
    pub inflight_nonce:
        std::sync::Arc<std::sync::Mutex<std::collections::HashMap<[u8; 32], (u64, u64)>>>,
    pub recent_local_txs: std::sync::Arc<std::sync::Mutex<Vec<Transaction>>>,
}

impl LightClient {
    /// Initialize light client with optional infnode configuration file
    /// (local in-process mode).
    pub async fn connect(config_path: Option<&Path>) -> Result<Self, String> {
        let mut client = Self::base().await?;
        client.network_adapter = Self::maybe_p2p_adapter(config_path).await?;
        Ok(client)
    }

    /// Initialize an HTTP-RPC client against a live node.
    /// No local state is trusted in this mode.
    pub async fn connect_rpc(
        url: &str,
        auth_token: Option<String>,
        faucet_token: Option<String>,
        receipt_timeout_secs: u64,
        receipt_poll_secs: u64,
    ) -> Result<Self, String> {
        let mut client = Self::base().await?;
        client.rpc = Some(RpcConfig::from_opts(url, auth_token, faucet_token));
        client.receipt_timeout_secs = receipt_timeout_secs.max(1);
        client.receipt_poll_secs = receipt_poll_secs.max(1);
        Ok(client)
    }

    async fn base() -> Result<Self, String> {
        let state_engine = Arc::new(InMemoryStateEngine::new());
        let orderbook_mgr = Arc::new(tokio::sync::Mutex::new(OrderbookManager::new()));
        let cache_path = stellereum::wallet::default_wallet_dir().join("state_cache.bin");
        let ob_cache_path = stellereum::wallet::default_wallet_dir().join("orderbook_cache.json");
        let history_path = stellereum::wallet::default_wallet_dir().join("tx_history.json");

        if cache_path.exists() {
            if let Ok(bytes) = std::fs::read(&cache_path) {
                let _ = state_engine.restore_snapshot(&bytes).await;
            }
        }

        if ob_cache_path.exists() {
            if let Ok(raw) = std::fs::read_to_string(&ob_cache_path) {
                if let Ok(loaded_ob) = serde_json::from_str::<OrderbookManager>(&raw) {
                    *orderbook_mgr.lock().await = loaded_ob;
                }
            }
        }

        let local_txs_path = stellereum::wallet::default_wallet_dir().join("local_txs.bin");
        let mut initial_local_txs = Vec::new();
        if local_txs_path.exists() {
            if let Ok(bytes) = std::fs::read(&local_txs_path) {
                if let Ok(txs) = bincode::deserialize::<Vec<Transaction>>(&bytes) {
                    initial_local_txs = txs;
                }
            }
        }
        if initial_local_txs.len() > MAX_LOCAL_TX_HISTORY {
            let excess = initial_local_txs.len() - MAX_LOCAL_TX_HISTORY;
            initial_local_txs.drain(..excess);
        }

        Ok(Self {
            state_engine,
            network_adapter: None,
            orderbook_mgr,
            cache_path,
            history_path,
            rpc: None,
            receipt_timeout_secs: 360,
            receipt_poll_secs: 2,
            inflight_nonce: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            recent_local_txs: std::sync::Arc::new(std::sync::Mutex::new(initial_local_txs)),
        })
    }

    async fn maybe_p2p_adapter(
        config_path: Option<&Path>,
    ) -> Result<Option<Arc<P2pNetworkAdapter>>, String> {
        if let Some(path) = config_path {
            if path.exists() {
                let node_cfg = node_config::load(path)
                    .map_err(|e| format!("Failed to parse config {:?}: {e}", path))?;
                let keys = infnode::keyring::NodeKeys::generate();
                let pq_keys = infnode::keyring::PqKeys::generate();
                let data_dir = PathBuf::from("./wallet_data");
                let keys_dir = PathBuf::from("./wallet_keys");
                let node = Node::new(node_cfg, keys, pq_keys, keys_dir, data_dir)
                    .await
                    .map_err(|e| format!("Failed to initialize infnode: {e}"))?;
                return Ok(Some(Arc::new(P2pNetworkAdapter::new(node))));
            }
        }
        Ok(None)
    }

    /// True when talking to a remote node (chain-authoritative mode).
    pub fn is_rpc(&self) -> bool {
        self.rpc.is_some()
    }

    fn rpc_cfg(&self) -> Result<&RpcConfig, String> {
        self.rpc
            .as_ref()
            .ok_or_else(|| "not in RPC mode (pass --rpc-url)".to_string())
    }

    /// Human-readable mode line for command output.
    pub fn mode_line(&self) -> String {
        match &self.rpc {
            Some(cfg) => format!("RPC mode (node {})", cfg.url),
            None => "Local mode (in-process simulation)".to_string(),
        }
    }

    /// Record a transaction in local history
    pub fn record_tx(&self, record: TxRecord) {
        let mut history = self.get_tx_history();
        history.insert(0, record);
        if history.len() > 100 {
            history.truncate(100);
        }
        if let Ok(json) = serde_json::to_string_pretty(&history) {
            let _ = write_private_file(&self.history_path, json.as_bytes());
        }
    }

    /// Retrieve transaction history
    pub fn get_tx_history(&self) -> Vec<TxRecord> {
        if let Ok(raw) = std::fs::read_to_string(&self.history_path) {
            serde_json::from_str(&raw).unwrap_or_default()
        } else {
            Vec::new()
        }
    }

    /// Persist current state cache to disk
    pub async fn persist_cache(&self) {
        let snapshot = self.state_engine.create_snapshot().await;
        let _ = write_private_file(&self.cache_path, &snapshot);
    }

    /// Current nonce for an address: on-chain via RPC (or local cache),
    /// raised by any unexpired in-flight reservation from this client.
    pub async fn nonce_of(&self, address: &[u8; 32]) -> Result<u64, String> {
        let base = if let Some(cfg) = &self.rpc {
            let addr_hex = hex::encode(address);
            let (_, nonce) = rpc::get_balance(cfg, &addr_hex)?;
            nonce
        } else {
            self.state_engine
                .get_account(address)
                .await
                .map(|a| a.nonce)
                .unwrap_or(0)
        };
        let now = now_secs();
        let mut m = self
            .inflight_nonce
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        m.retain(|_, (_, t)| now.saturating_sub(*t) < 600);
        let hint = m.get(address).map(|(n, _)| *n).unwrap_or(0);
        Ok(base.max(hint))
    }

    /// Reserve the nonce after a tx: the next `nonce_of` for this sender
    /// returns at least `nonce + 1` until the hint expires.
    pub fn reserve_nonce(&self, sender: &[u8; 32], nonce: u64) {
        let mut m = self
            .inflight_nonce
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let e = m.entry(*sender).or_insert((0, 0));
        let next = nonce.saturating_add(1);
        if next > e.0 {
            *e = (next, now_secs());
        }
    }

    /// Chain id: from the node in RPC mode, default otherwise.
    /// Propagates RPC errors via [`Self::try_chain_id`].
    #[allow(dead_code)]
    // GATE: test helper retained on LightClient alongside error-propagating try_chain_id.
    pub fn chain_id(&self) -> anyhow::Result<u64> {
        let id = self.try_chain_id()?;
        Ok(id)
    }

    /// Resolve a signing chain without substituting a default for an RPC error.
    pub fn try_chain_id(&self) -> anyhow::Result<u64> {
        match &self.rpc {
            Some(cfg) => {
                rpc::chain_id(cfg).map_err(|e| anyhow::anyhow!("chain ID lookup failed: {e}"))
            }
            None => Ok(stellereum::zkml::DEFAULT_CHAIN_ID),
        }
    }

    /// Query account balance and nonce with SPV Merkle inclusion proof
    /// verification.
    ///
    /// - RPC mode: balance/root/proof come FROM THE NODE
    ///   (`stell_getBalanceSpv`) and the proof is verified LOCALLY against
    ///   the node's root. `verified == true` means chain inclusion under a
    ///   root the node served.
    /// - Local mode: verified against the LOCAL state root only
    ///   (self-consistency, NOT chain inclusion).
    pub async fn get_balance_spv(
        &self,
        address: &[u8; 32],
        _shard_id: u32,
    ) -> Result<(u64, u64, bool), String> {
        if let Some(cfg) = &self.rpc {
            let addr_hex = hex::encode(address);
            let answer: SpvAnswer = rpc::get_balance_spv(cfg, &addr_hex)?;
            // Strict: only a checking proof counts as verified. An absent
            // account (no record, zero by protocol) reports false here -
            // callers that display to humans use the 3-state verdict directly
            // (Absent renders neutral, not red).
            let verified =
                rpc::verify_spv_balance_answer(address, &answer) == rpc::SpvVerdict::Verified;
            return Ok((answer.balance, answer.nonce, verified));
        }

        let account = self.state_engine.get_account(address).await;
        let (balance, nonce) = match &account {
            Some(a) => (a.balance, a.nonce),
            None => (0, 0),
        };

        // SPV Merkle verification against LOCAL state root only.
        let root = self.state_engine.get_state_root().await;
        let proof_opt = self.state_engine.get_account_proof(address).await;

        let verified = if let Some(proof) = proof_opt {
            if let Some(acc) = &account {
                let bytes = acc.to_trie_bytes();
                PatriciaTrie::verify_merkle_proof(&root, address, &bytes, &proof)
            } else {
                let mut expected_bytes = Vec::with_capacity(16);
                expected_bytes.extend_from_slice(&balance.to_be_bytes());
                expected_bytes.extend_from_slice(&nonce.to_be_bytes());
                PatriciaTrie::verify_merkle_proof(&root, address, &expected_bytes, &proof)
            }
        } else {
            balance == 0 && nonce == 0 // Uninitialized zero account is implicitly clean
        };

        Ok((balance, nonce, verified))
    }

    /// Full SPV answer in RPC mode (exposes the node-served root for display).
    pub async fn get_balance_spv_rpc_full(&self, address: &[u8; 32]) -> Result<SpvAnswer, String> {
        let cfg = self.rpc_cfg()?;
        rpc::get_balance_spv(cfg, &hex::encode(address))
    }

    /// Set account balance in local state cache (for testnet simulation and offline tracking)
    pub async fn set_balance(&self, address: [u8; 32], balance: u64, nonce: u64) {
        let mut acc = AccountState::new(address, balance);
        acc.nonce = nonce;
        self.state_engine.update_account(acc).await;
        self.persist_cache().await;
    }

    /// Request testnet funds from the node's faucet (RPC mode only).
    /// Returns `(credited_nano, faucet_tx_hash_hex)`.
    pub async fn faucet_drip_rpc(
        &self,
        address: &[u8; 32],
        amount_nano: Option<u64>,
    ) -> Result<(u64, String), String> {
        let cfg = self.rpc_cfg()?;
        rpc::faucet_drip(cfg, &hex::encode(address), amount_nano)
    }

    /// Submit an already-signed transaction and resolve its finality honestly.
    ///
    /// - RPC mode: admitted to the node mempool, then the receipt is polled
    ///   to FINALIZED. The returned `TxFinality` is Pending/Confirmed/Failed/
    ///   Unknown — never "Confirmed" before a success receipt exists.
    /// - Local mode: applied to the local state cache and recorded as a
    ///   LOCAL SIMULATION (explicitly not chain finality).
    pub async fn broadcast_tx(&self, tx: &Transaction) -> Result<([u8; 32], TxFinality), String> {
        if !tx.verify_signature() {
            return Err("Transaction signature verification failed".to_string());
        }
        let tx_hash = tx.compute_tx_hash();
        {
            let mut list = self
                .recent_local_txs
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if !list.iter().any(|t| t.compute_tx_hash() == tx_hash) {
                list.push(tx.clone());
            }
            if list.len() > MAX_LOCAL_TX_HISTORY {
                let excess = list.len() - MAX_LOCAL_TX_HISTORY;
                list.drain(..excess);
            }
            if let Ok(bytes) = bincode::serialize(&*list) {
                let local_txs_path = stellereum::wallet::default_wallet_dir().join("local_txs.bin");
                let _ = write_private_file(&local_txs_path, &bytes);
            }
        }

        if let Some(cfg) = &self.rpc {
            let raw = bincode::serialize(tx)
                .map_err(|e| format!("transaction serialization failed: {e}"))?;
            let admitted_hex = rpc::send_raw_transaction(cfg, &hex::encode(raw))?;
            let admitted: [u8; 32] = hex::decode(&admitted_hex)
                .map_err(|e| format!("node returned bad tx hash: {e}"))?
                .try_into()
                .map_err(|_| "node returned bad-length tx hash".to_string())?;
            // Always compare (audit 2026-10-06): a debug-only assert let a
            // hash mismatch record one hash in history while returning
            // another in release builds.
            if admitted != tx_hash {
                return Err("node admitted a different tx hash than computed locally".to_string());
            }

            // Reserve the nonce immediately (audit 2026-10-06): a second
            // rapid submit must not reuse it while the first is still
            // mempool-pending (RPC nonce reads are on-chain only).
            self.reserve_nonce(&tx.from, tx.nonce);

            // Async poll (audit 2026-10-06): the sync poll_receipt parks the
            // thread, blocking a tokio worker this deep in async code.
            let finality = rpc::poll_receipt_async(
                cfg,
                &admitted_hex,
                self.receipt_timeout_secs,
                self.receipt_poll_secs,
            )
            .await;
            self.record_tx(TxRecord {
                timestamp: now_secs(),
                tx_hash: admitted_hex,
                from: hex::encode(tx.from),
                to: hex::encode(tx.to),
                amount_stell: (tx.amount as f64) / 1_000_000_000.0,
                fee_stell: (tx.gas_limit as f64) / 1_000_000_000.0,
                is_confidential: false,
                status: finality.status_label(),
            });
            return Ok((tx_hash, finality));
        }

        // Local simulation path.
        // Snapshot for rollback (audit 2026-10-06): the old code took the
        // native fee first and failed the token leg after — chain mode is
        // atomic, local must be too.
        let total_cost = tx
            .amount
            .checked_add(tx.gas_limit)
            .ok_or_else(|| "Transaction amount + gas_limit overflows u64".to_string())?;
        let snap = self.state_engine.get_account(&tx.from).await;
        if let Some(mut sender_acc) = self.state_engine.get_account(&tx.from).await {
            if sender_acc.balance < total_cost {
                return Err(format!(
                    "Insufficient balance: have {} nano-STELL, need {}",
                    sender_acc.balance, total_cost
                ));
            }
            // Token/contract payloads move no native value beyond gas: the
            // native `amount` leg still settles against the local cache.
            sender_acc.balance -= total_cost;
            sender_acc.nonce = sender_acc
                .nonce
                .checked_add(1)
                .ok_or_else(|| "Sender nonce overflows u64".to_string())?;
            self.state_engine.update_account(sender_acc).await;
        } else if total_cost > 0 {
            return Err("Insufficient balance: unknown sender has 0 nano-STELL".to_string());
        }

        let rec_snap = if tx.amount > 0 {
            self.state_engine.get_account(&tx.to).await
        } else {
            None
        };
        if tx.amount > 0 {
            if let Some(mut rec_acc) = rec_snap.clone() {
                let new_rec_balance = match rec_acc.balance.checked_add(tx.amount) {
                    Some(b) => b,
                    None => {
                        if let Some(acc) = snap {
                            self.state_engine.update_account(acc).await;
                        }
                        return Err("Recipient balance overflows u64".to_string());
                    }
                };
                rec_acc.balance = new_rec_balance;
                self.state_engine.update_account(rec_acc).await;
            } else {
                self.state_engine
                    .update_account(AccountState::new(tx.to, tx.amount))
                    .await;
            }
        }

        // Token payloads also execute against the LOCAL token registry so the
        // simulation stays self-consistent (still not chain state). Any
        // failure rolls the native leg back (see snapshot above).
        let token_res: Result<(), String> = async {
            for op in &tx.payload {
                match op {
                    stellereum::svm::OpCode::SysCallTokenTransfer {
                        token_id,
                        to,
                        amount,
                    } => {
                        self.state_engine
                            .token_execute(
                                token_id,
                                tx.from,
                                TokenOp::Transfer {
                                    to: *to,
                                    amount: *amount,
                                },
                            )
                            .await
                            .map_err(|e| format!("local token transfer failed: {e}"))?;
                    }
                    stellereum::svm::OpCode::SysCallTokenApprove {
                        token_id,
                        spender,
                        amount,
                    } => {
                        self.state_engine
                            .token_execute(
                                token_id,
                                tx.from,
                                TokenOp::Approve {
                                    spender: *spender,
                                    amount: *amount,
                                },
                            )
                            .await
                            .map_err(|e| format!("local token approve failed: {e}"))?;
                    }
                    stellereum::svm::OpCode::SysCallTokenTransferFrom {
                        token_id,
                        from,
                        to,
                        amount,
                    } => {
                        self.state_engine
                            .token_execute(
                                token_id,
                                tx.from,
                                TokenOp::TransferFrom {
                                    from: *from,
                                    to: *to,
                                    amount: *amount,
                                },
                            )
                            .await
                            .map_err(|e| format!("local token transfer-from failed: {e}"))?;
                    }
                    _ => {}
                }
            }
            Ok(())
        }
        .await;
        if let Err(e) = token_res {
            if tx.amount > 0 && tx.to != tx.from {
                if let Some(rec_acc) = rec_snap {
                    self.state_engine.update_account(rec_acc).await;
                } else {
                    self.state_engine.accounts.write().await.remove(&tx.to);
                }
            }
            if let Some(acc) = snap {
                self.state_engine.update_account(acc).await;
            }
            return Err(e);
        }

        self.persist_cache().await;

        let finality = TxFinality::Pending;
        let honest_status =
            "Applied locally (simulated — NOT chain-finalized; use --rpc-url for chain finality)"
                .to_string();
        self.record_tx(TxRecord {
            timestamp: now_secs(),
            tx_hash: hex::encode(tx_hash),
            from: hex::encode(tx.from),
            to: hex::encode(tx.to),
            amount_stell: (tx.amount as f64) / 1_000_000_000.0,
            fee_stell: (tx.gas_limit as f64) / 1_000_000_000.0,
            is_confidential: false,
            status: honest_status,
        });

        // If P2P adapter is active, broadcast to overlay (still not finality).
        if let Some(adapter) = &self.network_adapter {
            adapter.broadcast_transaction(tx).await?;
        }

        Ok((tx_hash, finality))
    }

    // ---------------- tokens (STS standard) ----------------

    /// Native token balance: on-chain in RPC mode, local registry otherwise.
    pub async fn token_balance(
        &self,
        token_id: &[u8; 32],
        account: &[u8; 32],
    ) -> Result<u64, String> {
        if let Some(cfg) = &self.rpc {
            rpc::get_token_balance(cfg, &hex::encode(token_id), &hex::encode(account))
        } else {
            Ok(self.state_engine.token_balance(token_id, account).await)
        }
    }

    /// Token SPV proof from the node, verified locally (RPC mode only).
    pub async fn token_balance_spv_verified(
        &self,
        token_id: &[u8; 32],
        account: &[u8; 32],
    ) -> Result<(u64, bool, String), String> {
        let cfg = self.rpc_cfg()?;
        let answer: TokenSpvAnswer =
            rpc::get_token_balance_spv(cfg, &hex::encode(token_id), &hex::encode(account))?;
        let verified = rpc::verify_token_spv_answer(token_id, account, &answer);
        Ok((answer.balance, verified, hex::encode(answer.state_root)))
    }

    /// Build a post-quantum transfer transaction using Falcon-512.
    ///
    /// - Computes sender's 32-byte address using PQ-BFT v4 address derivation
    ///   `derive_pq_address(scheme, pubkey, salt)`.
    /// - Signs the standard transaction message using the post-quantum keypair.
    /// - Packs the signature into `PqSignatureEnvelope` format (`b"PQ1"`).
    /// - `is_activation == true`: explicit public key carrier mode (Tx #1 account activation).
    /// - `is_activation == false`: implicit mode (steady-state spends, omitting public key from wire).
    pub fn build_pq_transfer_tx<K: PqSigner>(
        key: &K,
        to: [u8; 32],
        amount: u64,
        nonce: u64,
        shard: u32,
        is_activation: bool,
    ) -> Result<Transaction, String> {
        Self::build_pq_transfer_tx_with_gas(
            key,
            to,
            amount,
            stellereum::svm::GAS_BASIC_TRANSFER,
            nonce,
            shard,
            shard,
            is_activation,
        )
    }

    /// Build a post-quantum transfer transaction with full gas and shard controls.
    #[allow(clippy::too_many_arguments)] // GATE: PQ transfer builder needs full gas+shard controls
    pub fn build_pq_transfer_tx_with_gas<K: PqSigner>(
        key: &K,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: u32,
        target_shard: u32,
        is_activation: bool,
    ) -> Result<Transaction, String> {
        use stellereum::post_quantum::{PqScheme, DEFAULT_SALT};
        use stellereum::sharding::PqSignatureEnvelope;

        let scheme = key.scheme();
        if scheme != PqScheme::Falcon512 {
            return Err(format!(
                "build_pq_transfer_tx_with_gas requires PqScheme::Falcon512, got: {:?}",
                scheme
            ));
        }

        let from = key.derive_address(&DEFAULT_SALT);
        let mut tx = Transaction {
            from,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            signature: Vec::new(),
            payload: Vec::new(),
            // No explicit priority bid (legacy behaviour: order by gas_limit).
            priority_fee_per_gas: 0,
        };

        let msg = tx.signing_message();
        let sig_bytes = key.try_sign(&msg)?;

        let envelope = if is_activation {
            PqSignatureEnvelope::new_explicit_with_salt(
                scheme,
                key.public_key().to_vec(),
                sig_bytes,
                DEFAULT_SALT,
            )
        } else {
            PqSignatureEnvelope::new_implicit(scheme, sig_bytes)
        };

        tx.signature = envelope.encode();
        Ok(tx)
    }

    /// Build a post-quantum transaction carrying an SVM payload AND bound to
    /// `chain_id` (A14 chain-binding rollout: the wallet default).
    ///
    /// Identical to [`Self::build_pq_payload_tx`] except the signature
    /// commits `chain_id` (CH1-style envelope via
    /// `PqSignatureEnvelope::{new_explicit_with_chain,
    /// new_implicit_with_chain}`), so the transaction verifies only on the
    /// chain it was minted for. Verification is unchanged on the node side:
    /// `signing_message()` re-derives the same commitment from
    /// `chain_id()`, so `verify_signature()` and the strict
    /// `verify_signature_for_chain(chain_id, true)` both pass on the bound
    /// chain and the strict check fails everywhere else.
    #[allow(clippy::too_many_arguments)]
    pub fn build_pq_payload_tx_bound<K: PqSigner>(
        key: &K,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: u32,
        target_shard: u32,
        is_activation: bool,
        payload: Vec<stellereum::svm::OpCode>,
        chain_id: u64,
    ) -> Result<Transaction, String> {
        // NOTE: the CHAIN-BEARING envelope lives in `sharding` (salt +
        // chain_id); the legacy `post_quantum` envelope cannot carry a
        // chain id. Both decode through the same `pq_envelope()` path.
        use stellereum::post_quantum::{PqScheme, DEFAULT_SALT};
        use stellereum::sharding::PqSignatureEnvelope;

        let scheme = key.scheme();
        if scheme != PqScheme::Falcon512 {
            return Err(format!(
                "build_pq_payload_tx_bound requires PqScheme::Falcon512, got: {:?}",
                scheme
            ));
        }

        let from = key.derive_address(&DEFAULT_SALT);
        let mut tx = Transaction {
            from,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            signature: Vec::new(),
            payload,
            // No explicit priority bid (legacy behaviour: order by gas_limit).
            priority_fee_per_gas: 0,
        };

        let msg = tx.signing_message_for_chain(chain_id);
        let sig_bytes = key.try_sign(&msg)?;

        let envelope = if is_activation {
            PqSignatureEnvelope::new_explicit_with_chain(
                scheme,
                key.public_key().to_vec(),
                sig_bytes,
                DEFAULT_SALT,
                chain_id,
            )
        } else {
            PqSignatureEnvelope::new_implicit_with_chain(scheme, sig_bytes, chain_id)
        };

        tx.signature = envelope.encode();
        Ok(tx)
    }

    /// Build a post-quantum transfer transaction bound to `chain_id`
    /// (A14 chain-binding rollout: the wallet default). Same binding
    /// contract as [`Self::build_pq_payload_tx_bound`].
    #[allow(clippy::too_many_arguments)]
    pub fn build_pq_transfer_tx_bound<K: PqSigner>(
        key: &K,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: u32,
        target_shard: u32,
        is_activation: bool,
        chain_id: u64,
    ) -> Result<Transaction, String> {
        // NOTE: the CHAIN-BEARING envelope lives in `sharding` (salt +
        // chain id); the legacy `post_quantum` envelope cannot carry a
        // chain id. Both decode through the same `pq_envelope()` path.
        use stellereum::post_quantum::{PqScheme, DEFAULT_SALT};
        use stellereum::sharding::PqSignatureEnvelope;

        let scheme = key.scheme();
        if scheme != PqScheme::Falcon512 {
            return Err(format!(
                "build_pq_transfer_tx_bound requires PqScheme::Falcon512, got: {:?}",
                scheme
            ));
        }

        let from = key.derive_address(&DEFAULT_SALT);
        let mut tx = Transaction {
            from,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            signature: Vec::new(),
            payload: Vec::new(),
            // No explicit priority bid (legacy behaviour: order by gas_limit).
            priority_fee_per_gas: 0,
        };

        let msg = tx.signing_message_for_chain(chain_id);
        let sig_bytes = key.try_sign(&msg)?;

        let envelope = if is_activation {
            PqSignatureEnvelope::new_explicit_with_chain(
                scheme,
                key.public_key().to_vec(),
                sig_bytes,
                DEFAULT_SALT,
                chain_id,
            )
        } else {
            PqSignatureEnvelope::new_implicit_with_chain(scheme, sig_bytes, chain_id)
        };

        tx.signature = envelope.encode();
        Ok(tx)
    }

    /// Build a post-quantum transaction carrying an SVM payload (e.g.
    /// `SysCallStake` / `SysCallDelegate`). The payload is committed into the
    /// signed message exactly like the classical path, so the node executes
    /// it identically — only the signature envelope differs (PQ1). Required
    /// on Pure-PQ networks where classical signatures are rejected.
    ///
    /// UNBOUND (legacy): the signature covers no chain id — see
    /// [`Self::build_pq_payload_tx_bound`] for the bound default.
    #[allow(clippy::too_many_arguments)] // GATE: PQ payload builder mirrors full tx fields
    pub fn build_pq_payload_tx<K: PqSigner>(
        key: &K,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: u32,
        target_shard: u32,
        is_activation: bool,
        payload: Vec<stellereum::svm::OpCode>,
    ) -> Result<Transaction, String> {
        use stellereum::post_quantum::{PqScheme, DEFAULT_SALT};
        use stellereum::sharding::PqSignatureEnvelope;

        let scheme = key.scheme();
        if scheme != PqScheme::Falcon512 {
            return Err(format!(
                "build_pq_payload_tx requires PqScheme::Falcon512, got: {:?}",
                scheme
            ));
        }

        let from = key.derive_address(&DEFAULT_SALT);
        let mut tx = Transaction {
            from,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            signature: Vec::new(),
            payload,
            // No explicit priority bid (legacy behaviour: order by gas_limit).
            priority_fee_per_gas: 0,
        };

        let msg = tx.signing_message();
        let sig_bytes = key.try_sign(&msg)?;

        let envelope = if is_activation {
            PqSignatureEnvelope::new_explicit_with_salt(
                scheme,
                key.public_key().to_vec(),
                sig_bytes,
                DEFAULT_SALT,
            )
        } else {
            PqSignatureEnvelope::new_implicit(scheme, sig_bytes)
        };

        tx.signature = envelope.encode();
        Ok(tx)
    }

    /// Build a PQ-signed token-transfer transaction (`SysCallTokenTransfer`).
    pub fn build_pq_token_transfer_tx<K: PqSigner>(
        signer: &K,
        token_id: [u8; 32],
        to: [u8; 32],
        amount: u64,
        nonce: u64,
        shard: u32,
        chain_id: u64,
    ) -> Result<Transaction, String> {
        let from = signer.derive_address(&crate::pq::DEFAULT_SALT);
        let gas = stellereum::token::GAS_TOKEN_TRANSFER
            .max(stellereum::svm::GAS_BASIC_TRANSFER)
            .saturating_add(stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS);
        Self::build_pq_payload_tx_bound(
            signer,
            from,
            0,
            gas,
            nonce,
            shard,
            shard,
            true,
            vec![stellereum::svm::OpCode::SysCallTokenTransfer {
                token_id,
                to,
                amount,
            }],
            chain_id,
        )
    }

    /// Build a PQ-signed token-approve transaction (`SysCallTokenApprove`).
    pub fn build_pq_token_approve_tx<K: PqSigner>(
        signer: &K,
        token_id: [u8; 32],
        spender: [u8; 32],
        amount: u64,
        nonce: u64,
        shard: u32,
        chain_id: u64,
    ) -> Result<Transaction, String> {
        let from = signer.derive_address(&crate::pq::DEFAULT_SALT);
        let gas = stellereum::token::GAS_TOKEN_APPROVE
            .max(stellereum::svm::GAS_BASIC_TRANSFER)
            .saturating_add(stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS);
        Self::build_pq_payload_tx_bound(
            signer,
            from,
            0,
            gas,
            nonce,
            shard,
            shard,
            true,
            vec![stellereum::svm::OpCode::SysCallTokenApprove {
                token_id,
                spender,
                amount,
            }],
            chain_id,
        )
    }

    /// Build a PQ-signed token-create transaction (`SysCallTokenCreate`).
    #[allow(clippy::too_many_arguments)] // GATE: token-create builder needs full mint context
    pub fn build_pq_token_create_tx<K: PqSigner>(
        signer: &K,
        name: String,
        symbol: String,
        decimals: u8,
        initial_supply: u64,
        max_supply: Option<u64>,
        nonce: u64,
        shard: u32,
        chain_id: u64,
    ) -> Result<Transaction, String> {
        let from = signer.derive_address(&crate::pq::DEFAULT_SALT);
        let gas = stellereum::token::GAS_TOKEN_CREATE
            .max(stellereum::svm::GAS_BASIC_TRANSFER)
            .saturating_add(stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS);
        Self::build_pq_payload_tx_bound(
            signer,
            from,
            0,
            gas,
            nonce,
            shard,
            shard,
            true,
            vec![stellereum::svm::OpCode::SysCallTokenCreate {
                name,
                symbol,
                decimals,
                initial_supply,
                max_supply,
            }],
            chain_id,
        )
    }

    /// Build a PQ-signed delegation transaction (`SysCallDelegate`).
    pub fn build_pq_delegate_tx<K: PqSigner>(
        signer: &K,
        validator: [u8; 32],
        amount: u64,
        nonce: u64,
        chain_id: u64,
    ) -> Result<Transaction, String> {
        let from = signer.derive_address(&crate::pq::DEFAULT_SALT);
        let gas = (stellereum::svm::GAS_STAKE_BOND + stellereum::svm::GAS_BASIC_TRANSFER)
            .saturating_add(stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS);
        Self::build_pq_payload_tx_bound(
            signer,
            from,
            0,
            gas,
            nonce,
            stellereum::sharding::MASTERCHAIN_SHARD,
            stellereum::sharding::MASTERCHAIN_SHARD,
            true,
            vec![stellereum::svm::OpCode::SysCallDelegate { validator, amount }],
            chain_id,
        )
    }

    /// Build a PQ-signed begin-unbond transaction (`SysCallBeginUndelegate`).
    pub fn build_pq_begin_unbond_tx<K: PqSigner>(
        signer: &K,
        validator: [u8; 32],
        amount: u64,
        nonce: u64,
        chain_id: u64,
    ) -> Result<Transaction, String> {
        let from = signer.derive_address(&crate::pq::DEFAULT_SALT);
        let gas = (stellereum::svm::GAS_STAKE_UNBOND + stellereum::svm::GAS_BASIC_TRANSFER)
            .saturating_add(stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS);
        Self::build_pq_payload_tx_bound(
            signer,
            from,
            0,
            gas,
            nonce,
            stellereum::sharding::MASTERCHAIN_SHARD,
            stellereum::sharding::MASTERCHAIN_SHARD,
            true,
            vec![stellereum::svm::OpCode::SysCallBeginUndelegate { validator, amount }],
            chain_id,
        )
    }

    /// Build a PQ-signed withdraw-unbond transaction (`SysCallUndelegate`).
    pub fn build_pq_withdraw_unbond_tx<K: PqSigner>(
        signer: &K,
        validator: [u8; 32],
        nonce: u64,
        chain_id: u64,
    ) -> Result<Transaction, String> {
        let from = signer.derive_address(&crate::pq::DEFAULT_SALT);
        let gas = (stellereum::svm::GAS_STAKE_UNBOND + stellereum::svm::GAS_BASIC_TRANSFER)
            .saturating_add(stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS);
        Self::build_pq_payload_tx_bound(
            signer,
            from,
            0,
            gas,
            nonce,
            stellereum::sharding::MASTERCHAIN_SHARD,
            stellereum::sharding::MASTERCHAIN_SHARD,
            true,
            vec![stellereum::svm::OpCode::SysCallUndelegate { validator }],
            chain_id,
        )
    }

    /// Build a PQ-signed claim-rewards transaction.
    pub fn build_pq_claim_rewards_tx<K: PqSigner>(
        signer: &K,
        validator: [u8; 32],
        is_delegator: bool,
        nonce: u64,
        chain_id: u64,
    ) -> Result<Transaction, String> {
        let from = signer.derive_address(&crate::pq::DEFAULT_SALT);
        let gas = (stellereum::svm::GAS_STAKE_CLAIM + stellereum::svm::GAS_BASIC_TRANSFER)
            .saturating_add(stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS);
        let op = if is_delegator {
            stellereum::svm::OpCode::SysCallClaimDelegatorRewards { validator }
        } else {
            stellereum::svm::OpCode::SysCallClaimRewards { validator }
        };
        Self::build_pq_payload_tx_bound(
            signer,
            from,
            0,
            gas,
            nonce,
            stellereum::sharding::MASTERCHAIN_SHARD,
            stellereum::sharding::MASTERCHAIN_SHARD,
            true,
            vec![op],
            chain_id,
        )
    }

    /// Resolve a token id by (creator, name, symbol). RPC mode only: local
    /// state has no committed registry nonce to predict the id from.
    pub fn token_resolve(
        &self,
        creator: &[u8; 32],
        name: &str,
        symbol: &str,
    ) -> Result<String, String> {
        let cfg = self.rpc_cfg()?;
        rpc::get_token_resolve(cfg, &hex::encode(creator), name, symbol)
    }

    /// Paginated token id listing: chain registry in RPC mode (parsed as the
    /// `{tokens, total, offset}` object shape), local registry otherwise.
    /// Returns `(token_hex_ids, total, offset)`.
    pub async fn token_list(
        &self,
        limit: u64,
        offset: u64,
    ) -> Result<(Vec<String>, u64, u64), String> {
        if let Some(cfg) = &self.rpc {
            let a = rpc::list_tokens(cfg, limit, offset)?;
            return Ok((a.tokens, a.total, a.offset));
        }
        let all = self.state_engine.all_token_ids().await;
        let total = all.len() as u64;
        let off = (offset as usize).min(all.len());
        let lim = (limit.clamp(1, 1000) as usize).min(all.len().saturating_sub(off));
        let ids = all[off..off + lim].iter().map(hex::encode).collect();
        Ok((ids, total, offset))
    }

    /// Place order on CLOB Orderbook-Actor
    pub async fn place_order(
        &self,
        trader_key: &SigningKey,
        pair: u32,
        side: OrderSide,
        order_type: OrderType,
        price: u64,
        amount: u64,
    ) -> Result<(u64, usize), String> {
        let trader_pub = ed25519_dalek::Signer::sign(trader_key, b"auth");
        let trader_addr = trader_key.verifying_key().to_bytes();
        let _ = trader_pub;

        let now = now_secs();

        let mut ob = self.orderbook_mgr.lock().await;
        let (order, trades) = ob.get_book_mut(pair).submit_order_ext(
            trader_addr,
            side,
            order_type,
            price,
            amount,
            now,
        );

        let ob_cache_path = stellereum::wallet::default_wallet_dir().join("orderbook_cache.json");
        if let Ok(json) = serde_json::to_string(&*ob) {
            let _ = write_private_file(&ob_cache_path, json.as_bytes());
        }

        Ok((order.order_id, trades.len()))
    }

    /// Cancel order on CLOB Orderbook-Actor at micro-gas
    pub async fn cancel_order(&self, pair: u32, order_id: u64) -> Result<bool, String> {
        let mut ob = self.orderbook_mgr.lock().await;
        let cancelled = ob.get_book_mut(pair).cancel_order(order_id);

        let ob_cache_path = stellereum::wallet::default_wallet_dir().join("orderbook_cache.json");
        if let Ok(json) = serde_json::to_string(&*ob) {
            let _ = write_private_file(&ob_cache_path, json.as_bytes());
        }

        Ok(cancelled.is_some())
    }

    /// Query orderbook depth and spread
    pub async fn get_orderbook_depth(
        &self,
        pair: u32,
    ) -> Result<(Option<u64>, Option<u64>, usize, usize), String> {
        let ob = self.orderbook_mgr.lock().await;
        let book = ob
            .get_book(pair)
            .ok_or_else(|| format!("Pair {pair} not found"))?;
        let (best_bid, best_ask) = book.get_best_bid_ask();
        let (bids_count, asks_count) = book.depth();
        Ok((best_bid, best_ask, bids_count, asks_count))
    }

    /// Discover known peers in the P2P overlay
    pub async fn get_network_peers(&self) -> Vec<String> {
        if let Some(adapter) = &self.network_adapter {
            adapter.discover_peers().await
        } else {
            // Honest empty (audit 2026-10-06): the old placeholder rendered
            // as a live "Active Peer".
            vec![
                "(no P2P adapter configured — no live peers; pass --config to connect)".to_string(),
            ]
        }
    }
}

/// Atomically persist private wallet state/cache data with POSIX 0600 permissions.
pub fn write_private_file(path: &Path, data: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create parent directory {:?}: {e}", parent))?;
    }

    let file_name = path
        .file_name()
        .ok_or_else(|| format!("Invalid file path {:?}", path))?
        .to_string_lossy();
    let tmp_name = format!("{}.tmp.{}", file_name, std::process::id());
    let tmp_path = match path.parent() {
        Some(parent) => parent.join(tmp_name),
        None => PathBuf::from(tmp_name),
    };

    {
        use std::io::Write;
        let mut open_opts = std::fs::OpenOptions::new();
        open_opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open_opts.mode(0o600);
        }

        let mut file = open_opts
            .open(&tmp_path)
            .map_err(|e| format!("Failed to open temp file {:?}: {e}", tmp_path))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("Failed to set 0600 permissions on {:?}: {e}", tmp_path))?;
        }

        file.write_all(data)
            .map_err(|e| format!("Failed to write temp file {:?}: {e}", tmp_path))?;
        file.sync_all()
            .map_err(|e| format!("Failed to sync temp file {:?}: {e}", tmp_path))?;
    }

    std::fs::rename(&tmp_path, path)
        .map_err(|e| format!("Failed to rename {:?} to {:?}: {e}", tmp_path, path))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Failed to enforce 0600 permissions on {:?}: {e}", path))?;
    }

    Ok(())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
