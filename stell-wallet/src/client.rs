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
use stellereum::cell::PatriciaTrie;
use stellereum::crypto_privacy::{ConfidentialTransfer, StealthAddress};
use stellereum::network::P2pNetworkAdapter;
use stellereum::orderbook::{OrderSide, OrderType, OrderbookManager};
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::token::TokenOp;
use stellereum::wallet::WalletAccount;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Trait for key types that can authorize post-quantum transactions
pub trait PqSigner {
    fn scheme(&self) -> stellereum::post_quantum::PqScheme;
    fn public_key(&self) -> &[u8];
    fn derive_address(&self, salt: &[u8; 16]) -> [u8; 32] {
        stellereum::post_quantum::derive_pq_address(self.scheme(), self.public_key(), salt)
    }
    fn sign(&self, message: &[u8]) -> Vec<u8>;
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
) -> Transaction {
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
    #[allow(clippy::type_complexity)] // GATE: client cache shape is fixed by mempool/nonce tracking
    pub inflight_nonce: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<[u8; 32], (u64, u64)>>>,
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

        Ok(Self {
            state_engine,
            network_adapter: None,
            orderbook_mgr,
            cache_path,
            history_path,
            rpc: None,
            receipt_timeout_secs: 360,
            receipt_poll_secs: 2,
            inflight_nonce: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
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
                let data_dir = PathBuf::from("./wallet_data");
                let keys_dir = PathBuf::from("./wallet_keys");
                let node = Node::new(node_cfg, keys, data_dir, keys_dir)
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
        if let Some(parent) = self.history_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(&history) {
            let _ = std::fs::write(&self.history_path, json);
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
        if let Some(parent) = self.cache_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&self.cache_path, snapshot);
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
        let mut m = self.inflight_nonce.lock().unwrap_or_else(|e| e.into_inner());
        m.retain(|_, (_, t)| now.saturating_sub(*t) < 600);
        let hint = m.get(address).map(|(n, _)| *n).unwrap_or(0);
        Ok(base.max(hint))
    }

    /// Reserve the nonce after a tx: the next `nonce_of` for this sender
    /// returns at least `nonce + 1` until the hint expires.
    pub fn reserve_nonce(&self, sender: &[u8; 32], nonce: u64) {
        let mut m = self.inflight_nonce.lock().unwrap_or_else(|e| e.into_inner());
        let e = m.entry(*sender).or_insert((0, 0));
        if nonce + 1 > e.0 {
            *e = (nonce + 1, now_secs());
        }
    }

    /// Chain id: from the node in RPC mode, default otherwise.
    pub fn chain_id(&self) -> u64 {
        if let Some(cfg) = &self.rpc {
            rpc::chain_id(cfg).unwrap_or(stellereum::zkml::DEFAULT_CHAIN_ID)
        } else {
            stellereum::zkml::DEFAULT_CHAIN_ID
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
                rpc::verify_spv_balance_answer(address, &answer)
                    == rpc::SpvVerdict::Verified;
            return Ok((answer.balance, answer.nonce, verified));
        }

        let account = self.state_engine.get_account(address).await;
        let (balance, nonce) = match account {
            Some(a) => (a.balance, a.nonce),
            None => (0, 0),
        };

        // SPV Merkle verification against LOCAL state root only.
        let root = self.state_engine.get_state_root().await;
        let proof_opt = self.state_engine.get_account_proof(address).await;

        let verified = if let Some(proof) = proof_opt {
            let mut expected_bytes = Vec::new();
            expected_bytes.extend_from_slice(&balance.to_be_bytes());
            expected_bytes.extend_from_slice(&nonce.to_be_bytes());
            PatriciaTrie::verify_merkle_proof(&root, address, &expected_bytes, &proof)
        } else {
            balance == 0 // Uninitialized zero balance is implicitly clean
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
    pub async fn broadcast_tx(
        &self,
        tx: &Transaction,
    ) -> Result<([u8; 32], TxFinality), String> {
        if !tx.verify_signature() {
            return Err("Transaction signature verification failed".to_string());
        }
        let tx_hash = tx.compute_tx_hash();
        {
            let mut list = self.recent_local_txs.lock().unwrap();
            if !list.iter().any(|t| t.compute_tx_hash() == tx_hash) {
                list.push(tx.clone());
            }
            if let Ok(bytes) = bincode::serialize(&*list) {
                let local_txs_path = stellereum::wallet::default_wallet_dir().join("local_txs.bin");
                let _ = std::fs::write(local_txs_path, bytes);
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
        let snap = self.state_engine.get_account(&tx.from).await;
        if let Some(mut sender_acc) = self.state_engine.get_account(&tx.from).await {
            let total_cost = tx.amount + tx.gas_limit;
            if sender_acc.balance < total_cost {
                return Err(format!(
                    "Insufficient balance: have {} nano-STELL, need {}",
                    sender_acc.balance, total_cost
                ));
            }
            // Token/contract payloads move no native value beyond gas: the
            // native `amount` leg still settles against the local cache.
            sender_acc.balance -= total_cost;
            sender_acc.nonce += 1;
            self.state_engine.update_account(sender_acc).await;
        } else if tx.amount + tx.gas_limit > 0 {
            return Err("Insufficient balance: unknown sender has 0 nano-STELL".to_string());
        }

        if tx.amount > 0 {
            if let Some(mut rec_acc) = self.state_engine.get_account(&tx.to).await {
                rec_acc.balance += tx.amount;
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
                stellereum::svm::OpCode::SysCallTokenTransfer { token_id, to, amount } => {
                    self.state_engine
                        .token_execute(token_id, tx.from, TokenOp::Transfer { to: *to, amount: *amount })
                        .await
                        .map_err(|e| format!("local token transfer failed: {e}"))?;
                }
                stellereum::svm::OpCode::SysCallTokenApprove { token_id, spender, amount } => {
                    self.state_engine
                        .token_execute(
                            token_id,
                            tx.from,
                            TokenOp::Approve { spender: *spender, amount: *amount },
                        )
                        .await
                        .map_err(|e| format!("local token approve failed: {e}"))?;
                }
                stellereum::svm::OpCode::SysCallTokenTransferFrom { token_id, from, to, amount } => {
                    self.state_engine
                        .token_execute(
                            token_id,
                            tx.from,
                            TokenOp::TransferFrom { from: *from, to: *to, amount: *amount },
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

    /// Broadcast zero-knowledge confidential transfer (legacy local-only demo
    /// path kept for compatibility). Records an explicitly SIMULATED status:
    /// nothing here is chain-finalized. Prefer `broadcast_confidential_tx`.
    #[allow(dead_code)]
    pub async fn broadcast_confidential(
        &self,
        transfer: &ConfidentialTransfer,
    ) -> Result<[u8; 32], String> {
        if !transfer.verify_balance_conservation() {
            return Err("Homomorphic balance conservation check failed".to_string());
        }

        let mut hasher = sha2::Sha256::new();
        hasher.update(transfer.fee.to_be_bytes());
        for c in &transfer.input_commitments {
            hasher.update(c.commitment);
        }
        for c in &transfer.output_commitments {
            hasher.update(c.commitment);
        }
        use sha2::Digest;
        let tx_hash: [u8; 32] = hasher.finalize().into();

        self.record_tx(TxRecord {
            timestamp: now_secs(),
            tx_hash: hex::encode(tx_hash),
            from: "Confidential".to_string(),
            to: "Stealth One-Time".to_string(),
            amount_stell: 0.0,
            fee_stell: (transfer.fee as f64) / 1_000_000_000.0,
            is_confidential: true,
            status: "Simulated locally (NOT chain-finalized; use confidential-pay --rpc-url)"
                .to_string(),
        });

        Ok(tx_hash)
    }

    /// Build a real stealth payment transaction: derives a one-time stealth address
    /// using recipient's view and spend public keys and signs the transfer.
    /// The ephemeral public key `stealth.ephemeral_pub` is carried on-chain in `tx.payload`
    /// via `SysCallPatriciaLookup` so the recipient can detect the payment when scanning.
    /// Returns the signed transaction and the derived StealthAddress.
    pub fn build_stealth_pay_tx(
        sender: &WalletAccount,
        recipient_view_pub: &[u8; 32],
        recipient_spend_pub: &[u8; 32],
        amount_nano: u64,
        nonce: u64,
        shard: u32,
    ) -> Result<(Transaction, StealthAddress), String> {
        let stealth = StealthAddress::generate(recipient_view_pub, recipient_spend_pub)
            .ok_or_else(|| "Failed to derive StealthAddress from view and spend keys".to_string())?;
        let payload = vec![stellereum::svm::OpCode::SysCallPatriciaLookup(stealth.ephemeral_pub)];
        let gas_limit = 10_000 + stellereum::svm::GAS_PATRICIA_LOOKUP;
        let tx = Transaction::sign_with_payload(
            &sender.signing_key,
            stealth.one_time_pub,
            amount_nano,
            gas_limit,
            nonce,
            shard,
            shard,
            payload,
        );
        Ok((tx, stealth))
    }

    /// Extract 32-byte ephemeral public key from transaction payload if present.
    pub fn extract_ephemeral_pub(payload: &[stellereum::svm::OpCode]) -> Option<[u8; 32]> {
        for op in payload {
            if let stellereum::svm::OpCode::SysCallPatriciaLookup(bytes) = op { return Some(*bytes) }
        }
        if payload.len() == 4 {
            if let (
                stellereum::svm::OpCode::Push(w0),
                stellereum::svm::OpCode::Push(w1),
                stellereum::svm::OpCode::Push(w2),
                stellereum::svm::OpCode::Push(w3),
            ) = (&payload[0], &payload[1], &payload[2], &payload[3]) {
                let mut bytes = [0u8; 32];
                bytes[0..8].copy_from_slice(&w0.to_le_bytes());
                bytes[8..16].copy_from_slice(&w1.to_le_bytes());
                bytes[16..24].copy_from_slice(&w2.to_le_bytes());
                bytes[24..32].copy_from_slice(&w3.to_le_bytes());
                return Some(bytes);
            }
        }
        None
    }

    /// Build and sign a transaction spending from a stealth one-time address using the
    /// derived one-time private key (Schnorr signature over Ristretto255).
    pub fn build_stealth_spend_tx(
        one_time_priv: &curve25519_dalek::scalar::Scalar,
        one_time_pub: [u8; 32],
        to: [u8; 32],
        amount_nano: u64,
        gas_limit: u64,
        nonce: u64,
        shard: u32,
    ) -> Transaction {
        let payload = Vec::new();
        let mut tx = Transaction {
            from: one_time_pub,
            to,
            amount: amount_nano,
            gas_limit,
            nonce,
            source_shard: shard,
            target_shard: shard,
            signature: Vec::new(),
            payload,
            // No explicit priority bid (legacy behaviour: order by gas_limit).
            priority_fee_per_gas: 0,
        };
        let msg = tx.signing_message();
        let sig = stellereum::crypto_privacy::sign_stealth_message(one_time_priv, &msg);
        tx.signature = sig.to_vec();
        tx
    }

    /// Scan blocks / transactions for stealth payments matching the recipient's viewing key and spend pubkey.
    /// Returns a list of detected stealth transactions: (StealthAddress, amount_nano, height, tx_hash).
    pub async fn scan_stealth_payments(
        &self,
        view_priv: &curve25519_dalek::scalar::Scalar,
        spend_pub: &[u8; 32],
    ) -> Result<Vec<(StealthAddress, u64, u64, [u8; 32])>, String> {
        let mut detected = Vec::new();
        if let Some(cfg) = &self.rpc {
            let blocks = rpc::latest_blocks(cfg)?;
            for block in blocks {
                let tx_records = rpc::get_block_transactions(cfg, block.height).unwrap_or_default();
                for r in tx_records {
                    let raw_opt = r.raw_tx.or_else(|| {
                        rpc::get_transaction_raw(cfg, &r.tx_hash).unwrap_or(None)
                    });
                    if let Some(raw_hex) = raw_opt {
                        if let Ok(raw_bytes) = hex::decode(raw_hex) {
                            if let Ok(tx) = bincode::deserialize::<Transaction>(&raw_bytes) {
                                if let Some(ephem_bytes) = Self::extract_ephemeral_pub(&tx.payload) {
                                    let stealth = StealthAddress {
                                        one_time_pub: tx.to,
                                        ephemeral_pub: ephem_bytes,
                                    };
                                    if stealth.is_for_recipient(view_priv, spend_pub) == Some(true) {
                                        let tx_hash = tx.compute_tx_hash();
                                        if !detected.iter().any(|(_, _, _, h)| *h == tx_hash) {
                                            detected.push((stealth, tx.amount, block.height, tx_hash));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else {
            // Local mode: scan transactions submitted in this session
            let local_txs = self.recent_local_txs.lock().unwrap().clone();
            for tx in local_txs {
                if let Some(ephem_bytes) = Self::extract_ephemeral_pub(&tx.payload) {
                    let stealth = StealthAddress {
                        one_time_pub: tx.to,
                        ephemeral_pub: ephem_bytes,
                    };
                    if stealth.is_for_recipient(view_priv, spend_pub) == Some(true) {
                        let tx_hash = tx.compute_tx_hash();
                        if !detected.iter().any(|(_, _, _, h)| *h == tx_hash) {
                            detected.push((stealth, tx.amount, 0, tx_hash));
                        }
                    }
                }
            }
        }
        Ok(detected)
    }

    /// Build + submit a real confidential transfer: ONE tx carrying
    /// [Shield, Transfer2] (audit 2026-10-06 F-A) — atomic funding + spend,
    /// the only shape the enforced pool accepts. Conservation AND range
    /// proofs are built and checked before signing, then the tx goes through
    /// `broadcast_tx` (RPC polling / honest local simulation).
    #[allow(clippy::too_many_arguments)] // GATE: confidential-tx builder needs full proof+fee context
    pub async fn broadcast_confidential_tx(
        &self,
        signing_key: &SigningKey,
        recipient: [u8; 32],
        transfer: ConfidentialTransfer,
        amount: u64,
        fee: u64,
        blinding: [u8; 32],
        nonce: u64,
        shard: u32,
    ) -> Result<([u8; 32], TxFinality), String> {
        use curve25519_dalek::scalar::Scalar;
        use stellereum::crypto_privacy::RangeProof;
        if !transfer.verify_balance_conservation() {
            return Err("Homomorphic balance conservation check failed".to_string());
        }
        let r = Scalar::from_canonical_bytes(blinding)
            .into_option()
            .ok_or_else(|| "bad blinding for confidential transfer".to_string())?;
        let in_val = amount
            .checked_add(fee)
            .ok_or_else(|| "confidential amount+fee overflows".to_string())?;
        // Auto width per commitment (audit: speed): 32 bits below 2^32
        // (halves bytes + verify work), 64 above. Mixed widths verify fine.
        // (Old comment retired: fixed 32-bit panicked on 5 STELL = 5e9 nano;
        // auto-select makes that class impossible.)
        let prove_one = |c: &stellereum::crypto_privacy::PedersenCommitment, v: u64| {
            RangeProof::prove_auto(c, v, &r)
        };
        let input_ranges: Vec<RangeProof> =
            transfer.input_commitments.iter().map(|c| prove_one(c, in_val)).collect();
        let output_ranges: Vec<RangeProof> =
            transfer.output_commitments.iter().map(|c| prove_one(c, amount)).collect();
        if !transfer.verify_balanced_with_ranges(&input_ranges, &output_ranges) {
            return Err("Range proofs failed locally — refusing to submit".to_string());
        }
        let shield_in = transfer.input_commitments.first().cloned().ok_or_else(|| {
            "confidential transfer needs at least one input (shield entry)".to_string()
        })?;
        // Real charge, not max() padding (audit: speed): shield base +
        // exact per-proof cost from the proofs just built. Still floored by
        // the base transfer fee (admission floor).
        let gas = stellereum::svm::GAS_CONFIDENTIAL_SHIELD
            .saturating_add(stellereum::svm::confidential_transfer2_gas(
                &input_ranges,
                &output_ranges,
            ))
            .max(stellereum::svm::GAS_BASIC_TRANSFER);
        let tx = Transaction::sign_with_payload(
            signing_key,
            recipient,
            0,
            gas.max(fee),
            nonce,
            shard,
            shard,
            vec![
                stellereum::svm::OpCode::SysCallConfidentialShield {
                    commitment: shield_in.commitment,
                    amount: in_val,
                    blinding,
                },
                stellereum::svm::OpCode::SysCallConfidentialTransfer2 {
                    recipient,
                    transfer: Box::new(transfer.clone()),
                    input_ranges,
                    output_ranges,
                },
            ],
        );
        let (hash, finality) = self.broadcast_tx(&tx).await?;
        // Mark the history row as confidential with the viewing hint.
        let mut history = self.get_tx_history();
        if let Some(row) = history.first_mut() {
            row.is_confidential = true;
        }
        if let Ok(json) = serde_json::to_string_pretty(&history) {
            let _ = std::fs::write(&self.history_path, json);
        }
        Ok((hash, finality))
    }

    /// Build + submit a shield entry (`SysCallConfidentialShield`).
    /// Returns (tx hash, finality, commitment hex). The caller MUST persist
    /// the blinding: without it the coin can never be transferred or exited.
    pub async fn broadcast_shield_tx(
        &self,
        signing_key: &SigningKey,
        amount: u64,
        blinding: [u8; 32],
        nonce: u64,
        shard: u32,
    ) -> Result<([u8; 32], TxFinality, String), String> {
        use curve25519_dalek::scalar::Scalar;
        use stellereum::crypto_privacy::PedersenCommitment;
        let r = Scalar::from_canonical_bytes(blinding)
            .into_option()
            .ok_or_else(|| "bad blinding (not canonical)".to_string())?;
        let c = PedersenCommitment::commit(amount, &r);
        let gas = stellereum::svm::GAS_CONFIDENTIAL_SHIELD
            .max(stellereum::svm::GAS_BASIC_TRANSFER);
        let tx = Transaction::sign_with_payload(
            signing_key,
            signing_key.verifying_key().to_bytes(),
            0,
            gas,
            nonce,
            shard,
            shard,
            vec![stellereum::svm::OpCode::SysCallConfidentialShield {
                commitment: c.commitment,
                amount,
                blinding,
            }],
        );
        let (hash, finality) = self.broadcast_tx(&tx).await?;
        Ok((hash, finality, hex::encode(c.commitment)))
    }

    /// Build + submit an unshield exit (`SysCallConfidentialUnshield`).
    /// Lengths of commitments/amounts/blindings must match.
    pub async fn broadcast_unshield_tx(
        &self,
        signing_key: &SigningKey,
        commitments: Vec<[u8; 32]>,
        amounts: Vec<u64>,
        blindings: Vec<[u8; 32]>,
        nonce: u64,
        shard: u32,
    ) -> Result<([u8; 32], TxFinality), String> {
        use stellereum::crypto_privacy::UnshieldInput;
        if commitments.len() != amounts.len() || amounts.len() != blindings.len() || commitments.is_empty() {
            return Err("commitments/amounts/blindings must be non-empty and same length".to_string());
        }
        let inputs = commitments
            .into_iter()
            .zip(amounts)
            .zip(blindings)
            .map(|((commitment, amount), blinding)| UnshieldInput { commitment, amount, blinding })
            .collect::<Vec<_>>();
        // Local pre-check: every opening must recompute (cheap, saves a fee).
        for inp in &inputs {
            if !stellereum::crypto_privacy::ConfidentialState::verify_opening(
                &inp.commitment, inp.amount, &inp.blinding,
            ) {
                return Err("local opening check failed — refusing to submit".to_string());
            }
        }
        let gas = stellereum::svm::GAS_CONFIDENTIAL_UNSHIELD
            .saturating_add((inputs.len() as u64).saturating_mul(stellereum::svm::GAS_CONFIDENTIAL_UNSHIELD_PER_INPUT))
            .max(stellereum::svm::GAS_BASIC_TRANSFER);
        let tx = Transaction::sign_with_payload(
            signing_key,
            signing_key.verifying_key().to_bytes(),
            0,
            gas,
            nonce,
            shard,
            shard,
            vec![stellereum::svm::OpCode::SysCallConfidentialUnshield { inputs }],
        );
        self.broadcast_tx(&tx).await
    }

    // ---------------- tokens (STS standard) ----------------

    /// Native token balance: on-chain in RPC mode, local registry otherwise.
    pub async fn token_balance(&self, token_id: &[u8; 32], account: &[u8; 32]) -> Result<u64, String> {
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
        let answer: TokenSpvAnswer = rpc::get_token_balance_spv(
            cfg,
            &hex::encode(token_id),
            &hex::encode(account),
        )?;
        let verified = rpc::verify_token_spv_answer(token_id, account, &answer);
        Ok((answer.balance, verified, hex::encode(answer.state_root)))
    }

    /// Build a post-quantum transfer transaction using Falcon-512 or Hybrid scheme.
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
    ) -> Transaction {
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
    ) -> Transaction {
        use stellereum::post_quantum::{PqScheme, PqSignatureEnvelope, DEFAULT_SALT};

        let scheme = key.scheme();
        assert!(
            scheme == PqScheme::Falcon512 || scheme == PqScheme::Hybrid,
            "build_pq_transfer_tx supports PqScheme::Falcon512 or PqScheme::Hybrid, got: {:?}",
            scheme
        );

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
        let sig_bytes = key.sign(&msg);

        let envelope = if is_activation {
            PqSignatureEnvelope::new_explicit(scheme, key.public_key().to_vec(), sig_bytes)
        } else {
            PqSignatureEnvelope::new_implicit(scheme, sig_bytes)
        };

        tx.signature = envelope.encode();
        tx
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
    ) -> Transaction {
        // NOTE: the CHAIN-BEARING envelope lives in `sharding` (salt +
        // chain_id); the legacy `post_quantum` envelope cannot carry a
        // chain id. Both decode through the same `pq_envelope()` path.
        use stellereum::post_quantum::{PqScheme, DEFAULT_SALT};
        use stellereum::sharding::PqSignatureEnvelope;

        let scheme = key.scheme();
        assert!(
            scheme == PqScheme::Falcon512 || scheme == PqScheme::Hybrid,
            "build_pq_payload_tx_bound supports PqScheme::Falcon512 or PqScheme::Hybrid, got: {:?}",
            scheme
        );

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
        let sig_bytes = key.sign(&msg);

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
        tx
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
    ) -> Transaction {
        // NOTE: the CHAIN-BEARING envelope lives in `sharding` (salt +
        // chain id); the legacy `post_quantum` envelope cannot carry a
        // chain id. Both decode through the same `pq_envelope()` path.
        use stellereum::post_quantum::{PqScheme, DEFAULT_SALT};
        use stellereum::sharding::PqSignatureEnvelope;

        let scheme = key.scheme();
        assert!(
            scheme == PqScheme::Falcon512 || scheme == PqScheme::Hybrid,
            "build_pq_transfer_tx_bound supports PqScheme::Falcon512 or PqScheme::Hybrid, got: {:?}",
            scheme
        );

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
        let sig_bytes = key.sign(&msg);

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
        tx
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
    ) -> Transaction {
        use stellereum::post_quantum::{PqScheme, PqSignatureEnvelope, DEFAULT_SALT};

        let scheme = key.scheme();
        assert!(
            scheme == PqScheme::Falcon512 || scheme == PqScheme::Hybrid,
            "build_pq_payload_tx supports PqScheme::Falcon512 or PqScheme::Hybrid, got: {:?}",
            scheme
        );

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
        let sig_bytes = key.sign(&msg);

        let envelope = if is_activation {
            PqSignatureEnvelope::new_explicit(scheme, key.public_key().to_vec(), sig_bytes)
        } else {
            PqSignatureEnvelope::new_implicit(scheme, sig_bytes)
        };

        tx.signature = envelope.encode();
        tx
    }

    /// Build a token-transfer transaction (`SysCallTokenTransfer`).
    /// Native `amount` is 0; value moves inside the token registry.
    /// `to_native` is the tx-level recipient (conventionally self).
    pub fn build_token_transfer_tx(
        signing_key: &SigningKey,
        token_id: [u8; 32],
        to: [u8; 32],
        amount: u64,
        nonce: u64,
        shard: u32,
    ) -> Transaction {
        let from = signing_key.verifying_key().to_bytes();
        let gas = stellereum::token::GAS_TOKEN_TRANSFER.max(stellereum::svm::GAS_BASIC_TRANSFER);
        Transaction::sign_with_payload(
            signing_key,
            from,
            0,
            gas,
            nonce,
            shard,
            shard,
            vec![stellereum::svm::OpCode::SysCallTokenTransfer {
                token_id,
                to,
                amount,
            }],
        )
    }

    /// Build a token-approve transaction (`SysCallTokenApprove`).
    pub fn build_token_approve_tx(
        signing_key: &SigningKey,
        token_id: [u8; 32],
        spender: [u8; 32],
        amount: u64,
        nonce: u64,
        shard: u32,
    ) -> Transaction {
        let from = signing_key.verifying_key().to_bytes();
        let gas = stellereum::token::GAS_TOKEN_APPROVE.max(stellereum::svm::GAS_BASIC_TRANSFER);
        Transaction::sign_with_payload(
            signing_key,
            from,
            0,
            gas,
            nonce,
            shard,
            shard,
            vec![stellereum::svm::OpCode::SysCallTokenApprove {
                token_id,
                spender,
                amount,
            }],
        )
    }

    /// Build a token-create transaction (`SysCallTokenCreate`). Caller
    /// becomes minter, credited the full initial supply. Gas floor is the
    /// base transfer fee (280k dominates the 5k create charge).
    #[allow(clippy::too_many_arguments)] // GATE: token-create builder needs full mint context
    pub fn build_token_create_tx(
        signing_key: &SigningKey,
        name: String,
        symbol: String,
        decimals: u8,
        initial_supply: u64,
        max_supply: Option<u64>,
        nonce: u64,
        shard: u32,
    ) -> Transaction {
        let from = signing_key.verifying_key().to_bytes();
        let gas = stellereum::token::GAS_TOKEN_CREATE.max(stellereum::svm::GAS_BASIC_TRANSFER);
        Transaction::sign_with_payload(
            signing_key,
            from,
            0,
            gas,
            nonce,
            shard,
            shard,
            vec![stellereum::svm::OpCode::SysCallTokenCreate {
                name,
                symbol,
                decimals,
                initial_supply,
                max_supply,
            }],
        )
    }

    /// Build a delegation transaction (`SysCallDelegate`).
    pub fn build_delegate_tx(
        account: &WalletAccount,
        validator: [u8; 32],
        amount: u64,
        nonce: u64,
    ) -> Transaction {
        account.create_payload_transaction(
            vec![stellereum::svm::OpCode::SysCallDelegate { validator, amount }],
            stellereum::svm::GAS_STAKE_BOND + stellereum::svm::GAS_BASIC_TRANSFER,
            nonce,
        )
    }

    /// Build a begin-unbond transaction (`SysCallBeginUndelegate`).
    pub fn build_begin_unbond_tx(
        account: &WalletAccount,
        validator: [u8; 32],
        amount: u64,
        nonce: u64,
    ) -> Transaction {
        account.create_payload_transaction(
            vec![stellereum::svm::OpCode::SysCallBeginUndelegate { validator, amount }],
            stellereum::svm::GAS_STAKE_UNBOND + stellereum::svm::GAS_BASIC_TRANSFER,
            nonce,
        )
    }

    /// Build a withdraw-unbond transaction (`SysCallUndelegate`).
    pub fn build_withdraw_unbond_tx(
        account: &WalletAccount,
        validator: [u8; 32],
        nonce: u64,
    ) -> Transaction {
        account.create_payload_transaction(
            vec![stellereum::svm::OpCode::SysCallUndelegate { validator }],
            stellereum::svm::GAS_STAKE_UNBOND + stellereum::svm::GAS_BASIC_TRANSFER,
            nonce,
        )
    }

    /// Build a claim-rewards transaction (`SysCallClaimRewards` when claiming
    /// validator rewards, or `SysCallClaimDelegatorRewards` when claiming
    /// delegator rewards from a validator).
    pub fn build_claim_rewards_tx(
        account: &WalletAccount,
        validator: [u8; 32],
        is_delegator: bool,
        nonce: u64,
    ) -> Transaction {
        if is_delegator {
            Self::build_claim_delegator_rewards_tx(account, validator, nonce)
        } else {
            Self::build_claim_validator_rewards_tx(account, validator, nonce)
        }
    }

    /// Build a claim-delegator-rewards transaction (`SysCallClaimDelegatorRewards`).
    pub fn build_claim_delegator_rewards_tx(
        account: &WalletAccount,
        validator: [u8; 32],
        nonce: u64,
    ) -> Transaction {
        account.create_payload_transaction(
            vec![stellereum::svm::OpCode::SysCallClaimDelegatorRewards { validator }],
            stellereum::svm::GAS_STAKE_CLAIM + stellereum::svm::GAS_BASIC_TRANSFER,
            nonce,
        )
    }

    /// Build a claim-validator-rewards transaction (`SysCallClaimRewards`).
    pub fn build_claim_validator_rewards_tx(
        account: &WalletAccount,
        validator: [u8; 32],
        nonce: u64,
    ) -> Transaction {
        account.create_payload_transaction(
            vec![stellereum::svm::OpCode::SysCallClaimRewards { validator }],
            stellereum::svm::GAS_STAKE_CLAIM + stellereum::svm::GAS_BASIC_TRANSFER,
            nonce,
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
    pub async fn token_list(&self, limit: u64, offset: u64) -> Result<(Vec<String>, u64, u64), String> {
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
            let _ = std::fs::write(ob_cache_path, json);
        }

        Ok((order.order_id, trades.len()))
    }

    /// Cancel order on CLOB Orderbook-Actor at micro-gas
    pub async fn cancel_order(&self, pair: u32, order_id: u64) -> Result<bool, String> {
        let mut ob = self.orderbook_mgr.lock().await;
        let cancelled = ob.get_book_mut(pair).cancel_order(order_id);

        let ob_cache_path = stellereum::wallet::default_wallet_dir().join("orderbook_cache.json");
        if let Ok(json) = serde_json::to_string(&*ob) {
            let _ = std::fs::write(ob_cache_path, json);
        }

        Ok(cancelled.is_some())
    }

    /// Query orderbook depth and spread
    pub async fn get_orderbook_depth(
        &self,
        pair: u32,
    ) -> Result<(Option<u64>, Option<u64>, usize, usize), String> {
        let ob = self.orderbook_mgr.lock().await;
        let book = ob.get_book(pair).ok_or_else(|| format!("Pair {pair} not found"))?;
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
            vec!["(no P2P adapter configured — no live peers; pass --config to connect)".to_string()]
        }
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
