//! Ethereum JSON-RPC surface: read views are REAL, the EVM write path is an
//! honest FULL-PQ refusal.
//!
//! # Design: what this module does, and why the write path refuses
//!
//! Stellereum's consensus credential is a post-quantum signature. Every
//! admission path funnels through `Mempool::insert` -> `add_checked_ctx` ->
//! `Transaction::verify_signature`, which requires a `PQ1` (Falcon-512)
//! envelope (or an `SF1` Falcon session grant) and requires
//! `tx.from == derive_pq_address(scheme, pubkey, salt)`. A secp256k1 signature
//! is **not** a consensus credential and there is no mode that makes it one.
//!
//! A `MetaMask` EIP-155 transaction is signed by a secp256k1 key and its
//! sender is the EVM address derived from that key. Two facts make an honest
//! one-step conversion impossible without a consensus change:
//!
//! 1. `EV1` (the old Phase-2 carrier) embeds the raw EVM bytes inside
//!    `Transaction.signature`; `Transaction::verify_inner_with_registry`
//!    explicitly returns `false` for `EV1` in FULL-PQ builds, so the mempool
//!    must refuse it (see the dedicated `EV1` branch in `mempool::insert`).
//! 2. A PQ envelope's `from` is a PQ-derived address, not the zero-padded
//!    20-byte EVM address, and no on-chain PQ<->EVM address binding exists.
//!    Letting the node sign with its own configured key would spend the
//!    NODE's funds (a custodial relayer), not the user's, and would turn the
//!    node key into an authority over user transfers — not acceptable. The
//!    only node-side PQ key path wired to a transaction builder today is the
//!    optional faucet key (`rpc::faucet::Faucet`,
//!    `sign_pq_explicit_transfer`); it would debit the
//!    faucet account (testnet-only) rather than the EVM sender, so it is not
//!    a settlement path for `eth_sendRawTransaction`.
//!
//! Therefore `eth_sendRawTransaction`:
//! * decodes and strictly verifies the EVM intent (chain id, low-s,
//!   ecrecover) so malformed / malleable / foreign-chain / unprotected input
//!   keeps a precise error;
//! * then refuses a WELL-FORMED intent with `-32000`, naming the exact PQ
//!   requirement and the replacement call, and **files no pending intent**
//!   (the old path left an intent that could never settle);
//! * returns `error.data = { reason: "full-pq-admission", requires, submitWith,
//!   evmHash, readOnly }` so a wallet can act on it programmatically.
//!
//! The full EVM execution path needs a consensus-level change, not a
//! client-compatibility shim: an EVM state trie + execution domain, and an
//! on-chain, PQ-signed binding between a PQ account and an EVM address (or a
//! `PQEVM` carrier whose PQ envelope signs `keccak(EVM intent)` and whose
//! source account is the bound PQ account). Until such a binding is committed
//! and verified by every node, the only truthful write answer is the refusal
//! above plus the native PQ path `stell_sendRawTransaction`.
//!
//! Read-only methods stay fully served: `eth_call`, `eth_getProof` (real
//! cpat2 inclusion/exclusion proof from the state trie), `eth_getCode` (real
//! committed bytecode), `eth_getBalance`, `eth_getTransactionCount`,
//! `eth_getLogs`, block/receipt lookups.
//!
//! `eth_subscribe` is refused honestly: the WebSocket transport
//! (`rpc/streams.rs::ws_handle_text`) only tracks `stell_subscribe` and frames
//! notifications as `{"subscription","result"}`; it has no EIP-1193
//! `eth_subscription` envelope or EVM header/log materialiser. `stell_subscribe`
//! (newHeads / events) and polling `eth_getLogs` are the supported paths.

use super::*;
use axum::Json;
use serde_json::{json, Value};

impl RpcState {
    /// Returns the current finalized block height in hex quantity.
    pub fn eth_block_number(&self) -> String {
        let h = self.height.load(std::sync::atomic::Ordering::Relaxed);
        crate::evm_adapter::eth_block_number(h)
    }

    /// Alias matching JSON-RPC casing for `eth_block_number`.
    #[allow(non_snake_case)]
    pub fn eth_blockNumber(&self) -> String {
        self.eth_block_number()
    }

    /// Translates a block by number or tag ("latest", "earliest", "pending", hex) to `EvmBlock`.
    pub async fn eth_get_block_by_number(
        &self,
        block_tag: &str,
        full_tx: bool,
    ) -> Result<Option<crate::evm_adapter::EvmBlock>, crate::evm_adapter::JsonRpcError> {
        let tag = crate::evm_adapter::BlockTag::parse_str(block_tag)?;
        let cur_h = self.height.load(std::sync::atomic::Ordering::Relaxed);
        let want = tag.resolve(cur_h);
        let rb = self.recent_blocks.read().await;
        if let Some(b) = rb.iter().find(|b| b.height == want) {
            let parent_hash = if b.height > 0 {
                rb.iter()
                    .find(|p| p.height == b.height - 1)
                    .map(|p| p.hash.as_str())
            } else {
                None
            };
            let idx = self.receipts.read().await;
            let rows = idx.for_height(want);
            let evm_block =
                crate::evm_adapter::stell_block_summary_to_evm_full(b, parent_hash, &rows, full_tx);
            Ok(Some(evm_block))
        } else {
            Ok(crate::evm_adapter::global_adapter().get_block_by_number(&tag, full_tx))
        }
    }

    /// Alias matching JSON-RPC casing for `eth_get_block_by_number`.
    #[allow(non_snake_case)]
    pub async fn eth_getBlockByNumber(
        &self,
        block_tag: &str,
        full_tx: bool,
    ) -> Result<Option<crate::evm_adapter::EvmBlock>, crate::evm_adapter::JsonRpcError> {
        self.eth_get_block_by_number(block_tag, full_tx).await
    }

    /// Translates a block by hash to `EvmBlock`.
    pub async fn eth_get_block_by_hash(
        &self,
        hash: &str,
        full_tx: bool,
    ) -> Result<Option<crate::evm_adapter::EvmBlock>, crate::evm_adapter::JsonRpcError> {
        let norm = crate::evm_adapter::normalize_hash(hash)
            .map_err(crate::evm_adapter::JsonRpcError::invalid_params)?;
        let stripped = norm.strip_prefix("0x").unwrap_or(&norm);
        let rb = self.recent_blocks.read().await;
        if let Some(b) = rb.iter().find(|b| {
            let b_stripped = b.hash.strip_prefix("0x").unwrap_or(&b.hash);
            b_stripped.eq_ignore_ascii_case(stripped)
        }) {
            let parent_hash = if b.height > 0 {
                rb.iter()
                    .find(|p| p.height == b.height - 1)
                    .map(|p| p.hash.as_str())
            } else {
                None
            };
            let idx = self.receipts.read().await;
            let rows = idx.for_height(b.height);
            let evm_block =
                crate::evm_adapter::stell_block_summary_to_evm_full(b, parent_hash, &rows, full_tx);
            Ok(Some(evm_block))
        } else {
            Ok(crate::evm_adapter::global_adapter().get_block_by_hash(&norm, full_tx))
        }
    }

    /// Alias matching JSON-RPC casing for `eth_get_block_by_hash`.
    #[allow(non_snake_case)]
    pub async fn eth_getBlockByHash(
        &self,
        hash: &str,
        full_tx: bool,
    ) -> Result<Option<crate::evm_adapter::EvmBlock>, crate::evm_adapter::JsonRpcError> {
        self.eth_get_block_by_hash(hash, full_tx).await
    }

    /// Translates a transaction receipt by transaction hash to standard `EvmReceipt`.
    ///
    /// Accepts BOTH stell hashes and EVM intent hashes (`keccak(EVM raw)`):
    /// an EVM hash settled via a secp envelope resolves through the
    /// bidirectional map to its L1 receipt and is reported with the QUERIED
    /// (EVM) `transactionHash`, full `blockNumber`/`blockHash`, `status`
    /// (`0x1`/`0x0`) and `gasUsed` — never null once finalized.
    pub async fn eth_get_transaction_receipt(
        &self,
        tx_hash: &str,
    ) -> Result<Option<crate::evm_adapter::EvmReceipt>, crate::evm_adapter::JsonRpcError> {
        let norm = crate::evm_adapter::normalize_hash(tx_hash)
            .map_err(crate::evm_adapter::JsonRpcError::invalid_params)?;
        let h_bytes = crate::evm_adapter::parse_hash_bytes(&norm)
            .map_err(crate::evm_adapter::JsonRpcError::invalid_params)?;
        // Resolve EVM intent -> stell tx hash for the lookup, keeping the
        // queried (EVM) hash for the response body.
        let lookup_bytes: [u8; 32] =
            crate::evm_adapter::evm_to_stell_hash(&norm).unwrap_or(h_bytes);
        let is_settled_evm = lookup_bytes != h_bytes;
        let idx = self.receipts.read().await;
        if let Some(r) = idx.get(&lookup_bytes) {
            let mut receipt = if is_settled_evm {
                crate::evm_adapter::settled_receipt_for_evm(&norm, r)
            } else {
                crate::evm_adapter::stell_receipt_to_evm(r)
            };
            let block_receipts = idx.for_height(r.height);
            let cumulative: u64 = block_receipts
                .iter()
                .filter(|br| br.index <= r.index)
                .fold(0u64, |acc, br| acc.saturating_add(br.fee_charged));
            receipt.cumulative_gas_used = crate::evm_adapter::format_u64_hex(cumulative);
            if receipt.from == "0x0000000000000000000000000000000000000000" {
                drop(idx);
                let mp = self.mempool.read().await;
                if let Some(tx) = mp.get(&lookup_bytes) {
                    receipt.from = crate::evm_adapter::stell_address_to_evm(&tx.from);
                    receipt.to = Some(crate::evm_adapter::stell_address_to_evm(&tx.to));
                }
            }
            Ok(Some(receipt))
        } else {
            // Global adapter fallback (direct hit, then settled-EVM rewrite).
            if let Some(r) = crate::evm_adapter::global_adapter().get_transaction_receipt(&norm) {
                return Ok(Some(r.clone()));
            }
            if let Some(r) = crate::evm_adapter::global_adapter().get_settled_receipt(&norm) {
                return Ok(Some(r));
            }
            Ok(None)
        }
    }

    /// Alias matching JSON-RPC casing for `eth_get_transaction_receipt`.
    #[allow(non_snake_case)]
    pub async fn eth_getTransactionReceipt(
        &self,
        tx_hash: &str,
    ) -> Result<Option<crate::evm_adapter::EvmReceipt>, crate::evm_adapter::JsonRpcError> {
        self.eth_get_transaction_receipt(tx_hash).await
    }

    /// Translates a transaction by transaction hash to standard `EvmTransaction`.
    ///
    /// Accepts BOTH stell hashes and EVM intent hashes: a settled EVM hash
    /// resolves to its mined L1 transaction (with `blockNumber`/`blockHash`),
    /// which takes precedence over the pending intent view.
    pub async fn eth_get_transaction_by_hash(
        &self,
        tx_hash: &str,
    ) -> Result<Option<crate::evm_adapter::EvmTransaction>, crate::evm_adapter::JsonRpcError> {
        let norm = crate::evm_adapter::normalize_hash(tx_hash)
            .map_err(crate::evm_adapter::JsonRpcError::invalid_params)?;
        let h_bytes = crate::evm_adapter::parse_hash_bytes(&norm)
            .map_err(crate::evm_adapter::JsonRpcError::invalid_params)?;
        let lookup_bytes: [u8; 32] =
            crate::evm_adapter::evm_to_stell_hash(&norm).unwrap_or(h_bytes);
        let is_settled_evm = lookup_bytes != h_bytes;
        let idx = self.receipts.read().await;
        // Mined view first (settled EVM intents included): pending must not
        // shadow a finalized transaction.
        if let Some(r) = idx.get(&lookup_bytes) {
            if is_settled_evm {
                if let Some(evm_tx) =
                    crate::evm_adapter::settled_tx_for_evm(&norm, r, self.chain_id)
                {
                    return Ok(Some(evm_tx));
                }
            } else if let Some(evm_tx) =
                crate::evm_adapter::stell_receipt_to_evm_tx_with_chain(r, self.chain_id)
            {
                return Ok(Some(evm_tx));
            }
        }
        drop(idx);
        let mp = self.mempool.read().await;
        if let Some(tx) = mp.get(&lookup_bytes) {
            let mut evm_tx =
                crate::evm_adapter::stell_tx_to_evm_with_chain(tx, None, None, None, self.chain_id);
            if is_settled_evm {
                evm_tx.hash = norm.clone();
            }
            return Ok(Some(evm_tx));
        }
        drop(mp);
        if let Some(cached) = crate::evm_adapter::global_adapter().get_settled_transaction(&norm) {
            return Ok(Some(cached));
        }
        // Phase 1 EVM intent pool (eth_sendRawTransaction pending).
        if let Some(pending) = crate::evm_adapter::eth_pending_tx(&norm) {
            return Ok(Some(pending));
        }
        Ok(None)
    }

    /// Alias matching JSON-RPC casing for `eth_get_transaction_by_hash`.
    #[allow(non_snake_case)]
    pub async fn eth_getTransactionByHash(
        &self,
        tx_hash: &str,
    ) -> Result<Option<crate::evm_adapter::EvmTransaction>, crate::evm_adapter::JsonRpcError> {
        self.eth_get_transaction_by_hash(tx_hash).await
    }

    pub async fn handle_get_block_by_number(
        &self,
        params: &Value,
    ) -> Result<Option<crate::evm_adapter::EvmBlock>, crate::evm_adapter::JsonRpcError> {
        let (tag, full) = crate::evm_adapter::parse_get_block_by_number_params(params)?;
        let cur_h = self.height.load(std::sync::atomic::Ordering::Relaxed);
        let want = tag.resolve(cur_h);
        let rb = self.recent_blocks.read().await;
        if let Some(b) = rb.iter().find(|b| b.height == want) {
            let parent_hash = if b.height > 0 {
                rb.iter()
                    .find(|p| p.height == b.height - 1)
                    .map(|p| p.hash.as_str())
            } else {
                None
            };
            let idx = self.receipts.read().await;
            let rows = idx.for_height(want);
            let evm_block =
                crate::evm_adapter::stell_block_summary_to_evm_full(b, parent_hash, &rows, full);
            Ok(Some(evm_block))
        } else {
            Ok(crate::evm_adapter::global_adapter().get_block_by_number(&tag, full))
        }
    }

    pub async fn handle_get_block_by_hash(
        &self,
        params: &Value,
    ) -> Result<Option<crate::evm_adapter::EvmBlock>, crate::evm_adapter::JsonRpcError> {
        let (hash_str, full) = crate::evm_adapter::parse_get_block_by_hash_params(params)?;
        self.eth_get_block_by_hash(&hash_str, full).await
    }

    pub async fn handle_get_transaction_receipt(
        &self,
        params: &Value,
    ) -> Result<Option<crate::evm_adapter::EvmReceipt>, crate::evm_adapter::JsonRpcError> {
        let hash_str = crate::evm_adapter::parse_single_hash_param(params)?;
        self.eth_get_transaction_receipt(&hash_str).await
    }

    pub async fn handle_get_transaction_by_hash(
        &self,
        params: &Value,
    ) -> Result<Option<crate::evm_adapter::EvmTransaction>, crate::evm_adapter::JsonRpcError> {
        let hash_str = crate::evm_adapter::parse_single_hash_param(params)?;
        self.eth_get_transaction_by_hash(&hash_str).await
    }

    /// Number of transactions in a block looked up by hash.
    /// Serve order: recent window (`tx_count`) -> global adapter maps -> null.
    pub async fn eth_get_block_transaction_count_by_hash(
        &self,
        hash: &str,
    ) -> Result<Option<String>, crate::evm_adapter::JsonRpcError> {
        let norm = crate::evm_adapter::normalize_hash(hash)
            .map_err(crate::evm_adapter::JsonRpcError::invalid_params)?;
        let stripped = norm.strip_prefix("0x").unwrap_or(&norm);
        let rb = self.recent_blocks.read().await;
        if let Some(b) = rb.iter().find(|b| {
            let b_stripped = b.hash.strip_prefix("0x").unwrap_or(&b.hash);
            b_stripped.eq_ignore_ascii_case(stripped)
        }) {
            return Ok(Some(crate::evm_adapter::format_u64_hex(b.tx_count as u64)));
        }
        drop(rb);
        crate::evm_adapter::global_adapter().get_block_transaction_count_by_hash(&norm)
    }

    /// Number of transactions in a block looked up by tag/number.
    /// Serve order: recent window (`tx_count`) -> global adapter maps -> null.
    pub async fn eth_get_block_transaction_count_by_number(
        &self,
        tag: &crate::evm_adapter::BlockTag,
    ) -> Result<Option<String>, crate::evm_adapter::JsonRpcError> {
        let cur_h = self.height.load(std::sync::atomic::Ordering::Relaxed);
        let want = tag.resolve(cur_h);
        let rb = self.recent_blocks.read().await;
        if let Some(b) = rb.iter().find(|b| b.height == want) {
            return Ok(Some(crate::evm_adapter::format_u64_hex(b.tx_count as u64)));
        }
        drop(rb);
        crate::evm_adapter::global_adapter().get_block_transaction_count_by_number(tag)
    }

    /// Transaction at `index` inside the block looked up by hash.
    /// Serve order: recent window receipts -> global adapter maps -> null.
    pub async fn eth_get_transaction_by_block_hash_and_index(
        &self,
        hash: &str,
        index: u64,
    ) -> Result<Option<crate::evm_adapter::EvmTransaction>, crate::evm_adapter::JsonRpcError> {
        let norm = crate::evm_adapter::normalize_hash(hash)
            .map_err(crate::evm_adapter::JsonRpcError::invalid_params)?;
        let stripped = norm.strip_prefix("0x").unwrap_or(&norm);
        let (height, block_hash_bytes) = {
            let rb = self.recent_blocks.read().await;
            match rb.iter().find(|b| {
                let b_stripped = b.hash.strip_prefix("0x").unwrap_or(&b.hash);
                b_stripped.eq_ignore_ascii_case(stripped)
            }) {
                Some(b) => {
                    let h = b.height;
                    let hb = hex::decode(b.hash.strip_prefix("0x").unwrap_or(&b.hash))
                        .ok()
                        .and_then(|v| <[u8; 32]>::try_from(v).ok());
                    (Some(h), hb)
                }
                None => (None, None),
            }
        };
        if let Some(h) = height {
            let idx = self.receipts.read().await;
            let rows = idx.for_height(h);
            if let Some(r) = rows.iter().find(|r| r.index as u64 == index) {
                let _ = block_hash_bytes;
                if let Some(evm_tx) =
                    crate::evm_adapter::stell_receipt_to_evm_tx_with_chain(r, self.chain_id)
                {
                    return Ok(Some(evm_tx));
                }
                return Ok(None);
            }
            // Known block but index out of range (or no receipts yet): null.
            // Fall through to the global adapter only when the block itself is unknown.
            if rows.is_empty() {
                let rb = self.recent_blocks.read().await;
                let known_tx_count = rb
                    .iter()
                    .find(|b| b.height == h)
                    .map(|b| b.tx_count)
                    .unwrap_or(0);
                if known_tx_count == 0 {
                    return Ok(None);
                }
                // Non-zero tx_count but no receipts indexed yet: honest null.
                return Ok(None);
            }
            return Ok(None);
        }
        crate::evm_adapter::global_adapter().get_transaction_by_block_hash_and_index(&norm, index)
    }

    /// Transaction at `index` inside the block looked up by tag/number.
    /// Serve order: recent window receipts -> global adapter maps -> null.
    pub async fn eth_get_transaction_by_block_number_and_index(
        &self,
        tag: &crate::evm_adapter::BlockTag,
        index: u64,
    ) -> Result<Option<crate::evm_adapter::EvmTransaction>, crate::evm_adapter::JsonRpcError> {
        let cur_h = self.height.load(std::sync::atomic::Ordering::Relaxed);
        let want = tag.resolve(cur_h);
        let known = {
            let rb = self.recent_blocks.read().await;
            rb.iter().any(|b| b.height == want)
        };
        if known {
            let idx = self.receipts.read().await;
            let rows = idx.for_height(want);
            if let Some(r) = rows.iter().find(|r| r.index as u64 == index) {
                if let Some(evm_tx) =
                    crate::evm_adapter::stell_receipt_to_evm_tx_with_chain(r, self.chain_id)
                {
                    return Ok(Some(evm_tx));
                }
                return Ok(None);
            }
            return Ok(None);
        }
        crate::evm_adapter::global_adapter().get_transaction_by_block_number_and_index(tag, index)
    }

    /// Uncle count by block hash. Stellereum never produces uncles:
    /// known block -> `"0x0"`, unknown block -> null.
    pub async fn eth_get_uncle_count_by_block_hash(
        &self,
        hash: &str,
    ) -> Result<Option<String>, crate::evm_adapter::JsonRpcError> {
        let norm = crate::evm_adapter::normalize_hash(hash)
            .map_err(crate::evm_adapter::JsonRpcError::invalid_params)?;
        let stripped = norm.strip_prefix("0x").unwrap_or(&norm);
        let rb = self.recent_blocks.read().await;
        if rb.iter().any(|b| {
            let b_stripped = b.hash.strip_prefix("0x").unwrap_or(&b.hash);
            b_stripped.eq_ignore_ascii_case(stripped)
        }) {
            return Ok(Some("0x0".to_string()));
        }
        drop(rb);
        crate::evm_adapter::global_adapter().get_uncle_count_by_block_hash(&norm)
    }

    /// Uncle count by tag/number. See [`Self::eth_get_uncle_count_by_block_hash`].
    pub async fn eth_get_uncle_count_by_block_number(
        &self,
        tag: &crate::evm_adapter::BlockTag,
    ) -> Result<Option<String>, crate::evm_adapter::JsonRpcError> {
        let cur_h = self.height.load(std::sync::atomic::Ordering::Relaxed);
        let want = tag.resolve(cur_h);
        let rb = self.recent_blocks.read().await;
        if rb.iter().any(|b| b.height == want) {
            return Ok(Some("0x0".to_string()));
        }
        drop(rb);
        crate::evm_adapter::global_adapter().get_uncle_count_by_block_number(tag)
    }

    /// Uncle at `index` by block hash. Stellereum never produces uncles: always null.
    /// The block hash is still validated so malformed requests error with -32602.
    pub async fn eth_get_uncle_by_block_hash_and_index(
        &self,
        hash: &str,
        _index: u64,
    ) -> Result<Option<Value>, crate::evm_adapter::JsonRpcError> {
        crate::evm_adapter::normalize_hash(hash)
            .map_err(crate::evm_adapter::JsonRpcError::invalid_params)?;
        Ok(None)
    }

    /// Uncle at `index` by tag/number. Always null (no uncles on Stellereum).
    pub async fn eth_get_uncle_by_block_number_and_index(
        &self,
        _tag: &crate::evm_adapter::BlockTag,
        _index: u64,
    ) -> Result<Option<Value>, crate::evm_adapter::JsonRpcError> {
        Ok(None)
    }

    pub async fn handle_get_block_transaction_count_by_hash(
        &self,
        params: &Value,
    ) -> Result<Option<String>, crate::evm_adapter::JsonRpcError> {
        let hash_str = crate::evm_adapter::parse_single_hash_param(params)?;
        self.eth_get_block_transaction_count_by_hash(&hash_str)
            .await
    }

    pub async fn handle_get_block_transaction_count_by_number(
        &self,
        params: &Value,
    ) -> Result<Option<String>, crate::evm_adapter::JsonRpcError> {
        let tag = crate::evm_adapter::parse_single_block_tag_param(params)?;
        self.eth_get_block_transaction_count_by_number(&tag).await
    }

    pub async fn handle_get_transaction_by_block_hash_and_index(
        &self,
        params: &Value,
    ) -> Result<Option<crate::evm_adapter::EvmTransaction>, crate::evm_adapter::JsonRpcError> {
        let (hash_str, index) = crate::evm_adapter::parse_block_hash_and_index_params(params)?;
        self.eth_get_transaction_by_block_hash_and_index(&hash_str, index)
            .await
    }

    pub async fn handle_get_transaction_by_block_number_and_index(
        &self,
        params: &Value,
    ) -> Result<Option<crate::evm_adapter::EvmTransaction>, crate::evm_adapter::JsonRpcError> {
        let (tag, index) = crate::evm_adapter::parse_block_number_and_index_params(params)?;
        self.eth_get_transaction_by_block_number_and_index(&tag, index)
            .await
    }

    pub async fn handle_get_uncle_count_by_block_hash(
        &self,
        params: &Value,
    ) -> Result<Option<String>, crate::evm_adapter::JsonRpcError> {
        let hash_str = crate::evm_adapter::parse_single_hash_param(params)?;
        self.eth_get_uncle_count_by_block_hash(&hash_str).await
    }

    pub async fn handle_get_uncle_count_by_block_number(
        &self,
        params: &Value,
    ) -> Result<Option<String>, crate::evm_adapter::JsonRpcError> {
        let tag = crate::evm_adapter::parse_single_block_tag_param(params)?;
        self.eth_get_uncle_count_by_block_number(&tag).await
    }

    pub async fn handle_get_uncle_by_block_hash_and_index(
        &self,
        params: &Value,
    ) -> Result<Option<Value>, crate::evm_adapter::JsonRpcError> {
        let (hash_str, index) = crate::evm_adapter::parse_block_hash_and_index_params(params)?;
        self.eth_get_uncle_by_block_hash_and_index(&hash_str, index)
            .await
    }

    pub async fn handle_get_uncle_by_block_number_and_index(
        &self,
        params: &Value,
    ) -> Result<Option<Value>, crate::evm_adapter::JsonRpcError> {
        let (tag, index) = crate::evm_adapter::parse_block_number_and_index_params(params)?;
        self.eth_get_uncle_by_block_number_and_index(&tag, index)
            .await
    }

    /// One-shot `eth_getLogs` over the node's committed history.
    ///
    /// Serve order: local committed (`recent_blocks` window + `receipts`
    /// index, via [`crate::evm_adapter::stell_receipt_to_evm`]) merged with
    /// the global EVM adapter's committed receipts, filtered by
    /// `fromBlock` / `toBlock` / `address` / `topics` through
    /// [`crate::evm_adapter::FilterCriteria::matches`], sorted
    /// deterministically and capped at 1000 logs.
    ///
    /// Honest emptiness: Stellereum executes no EVM logs today, so
    /// [`crate::evm_adapter::stell_receipt_to_evm`] carries `logs: []` and a
    /// node with no EVM receipts returns `[]` (never fabricated logs).
    pub async fn eth_get_logs(
        &self,
        params: &Value,
    ) -> Result<Value, crate::evm_adapter::JsonRpcError> {
        use crate::evm_adapter as evm;
        let criteria = evm::FilterCriteria::from_value(params)?;
        let block_hash_filter = evm::extract_block_hash_filter(params);
        // Touch the recent window so the query is scoped to committed history
        // (heights outside it are still served via the global adapter below).
        let _head = self.height.load(std::sync::atomic::Ordering::Relaxed);
        let _window_len = self.recent_blocks.read().await.len();
        // Local committed receipts (currently log-free, kept for when execution emits logs).
        let mut out: Vec<evm::EvmLog> = {
            let idx = self.receipts.read().await;
            let mut local = Vec::new();
            for r in idx.map.values() {
                let evm_receipt = evm::stell_receipt_to_evm(r);
                for log in &evm_receipt.logs {
                    if let Some(ref want) = block_hash_filter {
                        match &log.block_hash {
                            Some(have) if have.to_lowercase() == want.to_lowercase() => {}
                            _ => continue,
                        }
                    }
                    if criteria.matches(log) {
                        local.push(log.clone());
                        if local.len() >= evm::MAX_GET_LOGS_RESULTS {
                            break;
                        }
                    }
                }
                if local.len() >= evm::MAX_GET_LOGS_RESULTS {
                    break;
                }
            }
            local
        };
        // Global EVM adapter receipts (EVM intents / bridged logs).
        if out.len() < evm::MAX_GET_LOGS_RESULTS {
            let mut global = evm::global_adapter()
                .collect_matching_logs(&criteria, block_hash_filter.as_deref());
            out.append(&mut global);
        }
        out.sort_by_key(evm::log_sort_key);
        out.truncate(evm::MAX_GET_LOGS_RESULTS);
        Ok(serde_json::json!(out))
    }

    /// Alias matching JSON-RPC casing for `eth_get_logs`.
    #[allow(non_snake_case)]
    pub async fn eth_getLogs(
        &self,
        params: &Value,
    ) -> Result<Value, crate::evm_adapter::JsonRpcError> {
        self.eth_get_logs(params).await
    }

    /// `eth_getStorageAt(address, position, tag)`: no EVM state trie exists,
    /// so every slot honestly reads as empty (32 zero bytes). Validates params,
    /// never fabricates state.
    pub async fn eth_get_storage_at(
        &self,
        params: &Value,
    ) -> Result<String, crate::evm_adapter::JsonRpcError> {
        crate::evm_adapter::global_adapter().eth_get_storage_at(params)
    }

    /// Alias matching JSON-RPC casing for `eth_get_storage_at`.
    #[allow(non_snake_case)]
    pub async fn eth_getStorageAt(
        &self,
        params: &Value,
    ) -> Result<String, crate::evm_adapter::JsonRpcError> {
        self.eth_get_storage_at(params).await
    }
}

pub(super) async fn dispatch_eth(
    st: &RpcState,
    id: Value,
    method: &str,
    params: &Value,
) -> Option<Json<RpcResponse>> {
    Some(match method {
        "eth_chainId" => ok(id, json!(crate::evm_adapter::eth_chain_id())),
        "net_version" => ok(id, json!(crate::evm_adapter::net_version())),
        "web3_clientVersion" => ok(id, json!(crate::evm_adapter::web3_client_version())),
        "net_listening" => ok(id, json!(crate::evm_adapter::net_listening())),
        // REAL peer count (F8): the process-wide counter the network layer
        // feeds via `P2pNetworkAdapter::publish_live_peer_count` →
        // `rpc::note_peer_count`. `0x0` means "no peer observed by this
        // process" — never an invented positive like the old constant `0x2`.
        "net_peerCount" => ok(
            id,
            json!(crate::evm_adapter::format_peer_count_hex(
                observed_peer_count()
            )),
        ),
        // LIVE (cheap): same rule as `stell_syncing` — a recent verified peer
        // height above ours means syncing. Was a hardcoded `false`.
        "eth_syncing" => {
            let ours = st.height.load(std::sync::atomic::Ordering::Relaxed);
            ok(
                id,
                json!(crate::evm_adapter::eth_syncing_for_heights(
                    ours,
                    fresh_peer_height()
                )),
            )
        }
        // TESTNET-KNOWN default: the mempool `base_fee` is an admission floor
        // in gas units, not a wei price — mapping it here would mix units.
        "eth_gasPrice" => ok(id, json!(crate::evm_adapter::eth_gas_price())),
        "eth_maxPriorityFeePerGas" => ok(
            id,
            json!(crate::evm_adapter::eth_max_priority_fee_per_gas()),
        ),
        // ADMISSION-FLOOR ESTIMATE (audit F4 + pentest F10): the EVM
        // 21k-style figure alone disagrees with every component of this
        // node's admission floor, so a wallet forwarding `gas_limit ==
        // estimate` was refused as `FeeTooLow`. The served figure is
        //   max(pure EVM figure, base_fee + sender D2 failure bond)
        //   + PQ activation surcharge (when the request declares one)
        // which is exactly `Mempool::required_fee_for_tx` for a zero priority
        // bid — every admission floor component, nothing invented:
        //   * `from` present  -> that sender's live `effective_floor`
        //     (base + accumulated failure bond);
        //   * `from` absent   -> the WORST-CASE bond (`MAX_FAILED_SENDER_PENALTY`),
        //     so the quote is never below any real sender's floor;
        //   * `pq_activation: true` -> plus `PQ_ACTIVATION_SURCHARGE_GAS`.
        // Still an admission estimate, not execution metering (calldata is
        // never executed).
        "eth_estimateGas" => {
            let sender = match estimate_sender(params) {
                Ok(v) => v,
                Err(e) => return Some(err(id, -32602, e)),
            };
            let floor = {
                let pool = st.mempool.read().await;
                match sender {
                    Some(s) => pool.effective_floor(&s),
                    None => pool
                        .base_fee
                        .saturating_add(crate::mempool::MAX_FAILED_SENDER_PENALTY),
                }
            };
            let surcharge = if wants_pq_activation(params) {
                crate::mempool::PQ_ACTIVATION_SURCHARGE_GAS
            } else {
                0
            };
            match crate::evm_adapter::eth_estimate_gas_amount(params) {
                Ok(pure) => ok(
                    id,
                    json!(crate::evm_adapter::format_u64_hex(
                        pure.max(floor).saturating_add(surcharge)
                    )),
                ),
                Err(e) => err(id, e.code, e.message),
            }
        }
        // REFUSED (F9): this chain commits no EVM fee market — no per-block
        // base fee and no per-block gas-used figure exist, so any
        // `baseFeePerGas`/`reward` series would be invented (the old answer
        // priced blocks the same node served as `null`). There is nothing to
        // derive from committed state, and substituting the mempool's
        // admission floor (gas units) for a wei price would mix units. Advice
        // the caller can actually use instead of a fabricated market.
        "eth_feeHistory" => err(
            id,
            -32000,
            "eth_feeHistory is not served: this node commits no EVM fee market \
             (no per-block base fee / gas-used history). Price with eth_gasPrice \
             and eth_maxPriorityFeePerGas; the admission floor is stell_baseFee",
        ),
        "eth_getCode" => match crate::evm_adapter::eth_get_code_rpc(st, params).await {
            Ok(code) => ok(id, json!(code)),
            Err(e) => err(id, e.code, e.message),
        },
        "eth_getBalance" => match crate::evm_adapter::eth_get_balance(&st.engine, params).await {
            Ok(bal) => ok(id, json!(bal)),
            Err(e) => err(id, e.code, e.message),
        },
        "eth_getTransactionCount" => {
            match crate::evm_adapter::eth_get_transaction_count(&st.engine, params).await {
                Ok(cnt) => ok(id, json!(cnt)),
                Err(e) => err(id, e.code, e.message),
            }
        }
        "eth_blockNumber" => ok(id, json!(st.eth_block_number())),
        "eth_getBlockByNumber" => match st.handle_get_block_by_number(params).await {
            Ok(Some(b)) => ok(id, json!(b)),
            Ok(None) => ok(id, Value::Null),
            Err(e) => err(id, e.code, e.message),
        },
        "eth_getBlockByHash" => match st.handle_get_block_by_hash(params).await {
            Ok(Some(b)) => ok(id, json!(b)),
            Ok(None) => ok(id, Value::Null),
            Err(e) => err(id, e.code, e.message),
        },
        "eth_getTransactionReceipt" => match st.handle_get_transaction_receipt(params).await {
            Ok(Some(r)) => ok(id, json!(r)),
            Ok(None) => ok(id, Value::Null),
            Err(e) => err(id, e.code, e.message),
        },
        "eth_getTransactionByHash" => match st.handle_get_transaction_by_hash(params).await {
            Ok(Some(tx)) => ok(id, json!(tx)),
            Ok(None) => ok(id, Value::Null),
            Err(e) => err(id, e.code, e.message),
        },
        "eth_getBlockTransactionCountByHash" => {
            match st.handle_get_block_transaction_count_by_hash(params).await {
                Ok(Some(c)) => ok(id, json!(c)),
                Ok(None) => ok(id, Value::Null),
                Err(e) => err(id, e.code, e.message),
            }
        }
        "eth_getBlockTransactionCountByNumber" => {
            match st
                .handle_get_block_transaction_count_by_number(params)
                .await
            {
                Ok(Some(c)) => ok(id, json!(c)),
                Ok(None) => ok(id, Value::Null),
                Err(e) => err(id, e.code, e.message),
            }
        }
        "eth_getTransactionByBlockHashAndIndex" => {
            match st
                .handle_get_transaction_by_block_hash_and_index(params)
                .await
            {
                Ok(Some(tx)) => ok(id, json!(tx)),
                Ok(None) => ok(id, Value::Null),
                Err(e) => err(id, e.code, e.message),
            }
        }
        "eth_getTransactionByBlockNumberAndIndex" => {
            match st
                .handle_get_transaction_by_block_number_and_index(params)
                .await
            {
                Ok(Some(tx)) => ok(id, json!(tx)),
                Ok(None) => ok(id, Value::Null),
                Err(e) => err(id, e.code, e.message),
            }
        }
        "eth_getUncleCountByBlockHash" => {
            match st.handle_get_uncle_count_by_block_hash(params).await {
                Ok(Some(c)) => ok(id, json!(c)),
                Ok(None) => ok(id, Value::Null),
                Err(e) => err(id, e.code, e.message),
            }
        }
        "eth_getUncleCountByBlockNumber" => {
            match st.handle_get_uncle_count_by_block_number(params).await {
                Ok(Some(c)) => ok(id, json!(c)),
                Ok(None) => ok(id, Value::Null),
                Err(e) => err(id, e.code, e.message),
            }
        }
        "eth_getUncleByBlockHashAndIndex" => {
            match st.handle_get_uncle_by_block_hash_and_index(params).await {
                Ok(_) => ok(id, Value::Null),
                Err(e) => err(id, e.code, e.message),
            }
        }
        "eth_getUncleByBlockNumberAndIndex" => {
            match st.handle_get_uncle_by_block_number_and_index(params).await {
                Ok(_) => ok(id, Value::Null),
                Err(e) => err(id, e.code, e.message),
            }
        }
        "eth_call" => match crate::evm_adapter::eth_call_with_engine(&st.engine, params).await {
            Ok(v) => ok(id, v),
            Err(e) => err(id, e.code, e.message),
        },
        "eth_newBlockFilter" => ok(id, json!(crate::evm_adapter::eth_new_block_filter())),
        "eth_newPendingTransactionFilter" => ok(
            id,
            json!(crate::evm_adapter::eth_new_pending_transaction_filter()),
        ),
        "eth_newFilter" => match crate::evm_adapter::eth_new_filter(params) {
            Ok(v) => ok(id, json!(v)),
            Err(e) => err(id, e.code, e.message),
        },
        "eth_getFilterChanges" => match crate::evm_adapter::eth_get_filter_changes(params) {
            Ok(v) => ok(id, v),
            Err(e) => err(id, e.code, e.message),
        },
        "eth_getFilterLogs" => match crate::evm_adapter::eth_get_filter_logs(params) {
            Ok(v) => ok(id, v),
            Err(e) => err(id, e.code, e.message),
        },
        "eth_uninstallFilter" => match crate::evm_adapter::eth_uninstall_filter(params) {
            Ok(v) => ok(id, json!(v)),
            Err(e) => err(id, e.code, e.message),
        },
        "eth_getLogs" => match st.eth_get_logs(params).await {
            Ok(v) => ok(id, v),
            Err(e) => err(id, e.code, e.message),
        },
        "eth_getStorageAt" => match st.eth_get_storage_at(params).await {
            Ok(v) => ok(id, json!(v)),
            Err(e) => err(id, e.code, e.message),
        },
        "eth_sendRawTransaction" => {
            // FULL-PQ HONESTY CONTRACT (see the module header):
            //  1. Decode + strictly verify the EVM intent (Phase-1 gate:
            //     chain id, low-s, ecrecover). Malformed / malleable /
            //     foreign-chain / unprotected input keeps its precise error.
            //  2. A well-formed intent is REFUSED with the PQ requirement and
            //     the replacement call. No pending intent is filed (the old
            //     path pooled an EV1 transaction the mempool must reject, and
            //     an intent that could never settle).
            // Read-only eth_call / eth_getProof / eth_getCode stay served.
            let evm_hash = match crate::evm_adapter::extract_raw_evm_bytes(params)
                .and_then(|raw| crate::evm_adapter::verify_raw_evm_intent(&raw))
            {
                Ok(h) => h,
                Err(e) => return Some(rpc_error(id, e)),
            };
            rpc_error(id, crate::evm_adapter::evm_send_refusal(Some(&evm_hash)))
        }
        "eth_getProof" => match crate::evm_adapter::eth_get_proof_rpc(st, params).await {
            Ok(v) => ok(id, v),
            Err(e) => rpc_error(id, e),
        },
        // REFUSED honestly: the WebSocket plumbing frames only
        // `stell_subscribe` notifications and has no EIP-1193
        // `eth_subscription` envelope / EVM header payload. Issuing an id
        // would promise notifications this transport can never shape.
        "eth_subscribe" => rpc_error(id, crate::evm_adapter::eth_subscribe_refusal(params)),
        "eth_unsubscribe" => rpc_error(id, crate::evm_adapter::eth_unsubscribe_refusal()),
        _ => return None,
    })
}

/// Render a [`crate::evm_adapter::JsonRpcError`] as a JSON-RPC response,
/// preserving its `data` (the refusal contract carries machine-readable
/// fields there; the plain `err()` helper drops them).
fn rpc_error(id: Value, e: crate::evm_adapter::JsonRpcError) -> Json<RpcResponse> {
    Json(RpcResponse {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(RpcError {
            code: e.code,
            message: e.message,
            data: e.data,
        }),
    })
}

/// The `from` address of an `eth_estimateGas` call object, when present.
///
/// `eth_estimateGas` accepts the same call object as `eth_call`; `from` is
/// what selects the sender-specific admission floor (F10). A malformed `from`
/// is a parameter error, never silently ignored.
fn estimate_sender(params: &Value) -> Result<Option<[u8; 32]>, String> {
    let obj = match params {
        Value::Null => return Ok(None),
        Value::Array(arr) => match arr.first() {
            None => return Ok(None),
            Some(Value::Object(map)) => map,
            Some(Value::Null) => return Ok(None),
            Some(_) => return Err("call object must be an object".to_string()),
        },
        Value::Object(map) => map,
        _ => return Err("params must be array or object".to_string()),
    };
    match obj.get("from") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => crate::evm_adapter::parse_evm_or_stell_address(s)
            .map(Some)
            .map_err(|e| format!("invalid from address: {e}")),
        Some(_) => Err("invalid from address: expected a hex address string".to_string()),
    }
}

/// True when an `eth_estimateGas` call object declares a PQ ACTIVATION (a tx
/// that attaches a raw public key and therefore pays the state-rent
/// surcharge). A plain EVM intent never is one, so this defaults to `false`.
fn wants_pq_activation(params: &Value) -> bool {
    let obj = match params {
        Value::Array(arr) => match arr.first() {
            Some(Value::Object(map)) => map,
            _ => return false,
        },
        Value::Object(map) => map,
        _ => return false,
    };
    obj.get("pq_activation")
        .or_else(|| obj.get("activation"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}
