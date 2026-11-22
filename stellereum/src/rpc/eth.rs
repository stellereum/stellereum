//! Ethereum JSON-RPC surface: read views are REAL, and the EVM write path is a
//! FULL-PQ **carrier** path (value transfers) with honest refusals everywhere
//! else.
//!
//! # Design: what this module does
//!
//! Stellereum's consensus credential is a post-quantum signature. Every
//! admission path funnels through `Mempool::insert` -> `add_checked_ctx` ->
//! `Transaction::verify_signature`, which requires a `PQ1` (Falcon-512)
//! envelope (or an `SF1` Falcon session grant) and requires
//! `tx.from == derive_pq_address(scheme, pubkey, salt)`. A secp256k1 signature
//! is **not** a consensus credential and there is no mode that makes it one.
//!
//! A MetaMask EIP-155 transaction is signed by a secp256k1 key whose EVM
//! address is `keccak256(pubkey)[12..]`; no Falcon-512 key derives that
//! address, and `EV1` (the old Phase-2 envelope that embedded raw EVM bytes in
//! `Transaction.signature`) is refused by `verify_inner_with_registry`, so the
//! node can never let the secp signature decide anything. What DOES work is a
//! two-part statement that only the user's PQ key can make:
//!
//! 1. **binding** — `SysCallBindEvmAddress` commits
//!    `EVM address → PQ account`, Falcon-signed by the PQ account over
//!    `keccak256("STELL_EVM_BIND_V1" || chain_id || evm || pq)`. It is the
//!    on-chain record that lets this RPC route an EVM address to the account
//!    that can spend its funds (`eth_getBalance` / `eth_getTransactionCount`
//!    serve that account too).
//! 2. **carrier** — a normal PQ1 transaction whose `SysCallEvmCarrier` payload
//!    carries the canonical EIP-155 bytes, the EVM sender, the bound
//!    Falcon-512 key and that key's signature over `keccak256(EVM tx)`.
//!    `tx.from` is the bound PQ account, `tx.to` is the recipient's bound PQ
//!    account, `tx.amount` is the EVM value in nano-STELL and `tx.nonce` is
//!    the EVM nonce. Two independent Falcon statements must both verify (the
//!    envelope's, over the whole Stell transaction including the payload, and
//!    the payload's, over the EVM intent); the secp256k1 signature inside the
//!    EVM bytes is verified for routing and UI only.
//!
//! So `eth_sendRawTransaction`:
//! * decodes and strictly verifies the EVM intent (chain id, low-s,
//!   ecrecover), so malformed / malleable / foreign-chain / unprotected input
//!   keeps a precise error;
//! * with NO on-chain binding for the EVM sender, keeps the historical honest
//!   refusal (`reason: "full-pq-admission"`, the native PQ path named,
//!   **no pending intent filed**);
//! * with a binding, refuses with `reason:
//!   "pq-carrier-authorization-required"` and the exact bytes to Falcon-sign
//!   (`intentSignThis`, then `signThis` once the intent signature is supplied),
//!   and settles the transfer when both signatures arrive in the optional
//!   `carrier` parameter (returning the EVM hash MetaMask tracks);
//! * refuses contract creation and calldata honestly
//!   (`evm-contract-execution-unsupported`): there is no EVM interpreter or
//!   EVM state trie in this wave, so executing bytecode would be a lie;
//! * refuses an EVM recipient with no PQ binding
//!   (`recipient-evm-address-unbound`): crediting the bare 20-byte address
//!   would make the funds unspendable.
//!
//! Operator surface: `stell_getEvmBinding` (read the binding),
//! `stell_evmBindingSubmit` (submit a signed claim) and `stell_evmCarrierSubmit`
//! (submit a signed carrier in one call). All three are self-authenticating —
//! nothing moves without a Falcon signature from the bound key.
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

/// Refuse a HISTORICAL state tag honestly.
///
/// This node keeps no historical EVM state window (no archive trie, no
/// per-height account snapshots): the live engine is the only state it has.
/// Answering a numeric/`earliest` tag from the CURRENT state would silently
/// label today's balance/code/storage as another height's — exactly the
/// fabricated-default failure this surface must not have. `latest`,
/// `pending`, `safe` and `finalized` all mean this node's finalized head
/// (single-block BFT finality), and a numeric tag equal to the head is the
/// same committed state. Everything else is `-32004`.
fn require_current_state_tag(
    tag: Option<&crate::evm_adapter::BlockTag>,
    head: u64,
) -> Result<(), crate::evm_adapter::JsonRpcError> {
    use crate::evm_adapter::BlockTag;
    match tag {
        None => Ok(()),
        Some(BlockTag::Latest)
        | Some(BlockTag::Pending)
        | Some(BlockTag::Safe)
        | Some(BlockTag::Finalized) => Ok(()),
        Some(BlockTag::Number(n)) if *n == head => Ok(()),
        Some(BlockTag::Earliest) if head == 0 => Ok(()),
        Some(BlockTag::Number(n)) => Err(crate::evm_adapter::JsonRpcError::new(
            -32004,
            format!(
                "historical state at block {n} is not available on this node: it serves only \
                 its current finalized head ({head}). Use \"latest\" or a historical-root \
                 proof instead of relabeling current state."
            ),
        )),
        Some(BlockTag::Earliest) => Err(crate::evm_adapter::JsonRpcError::new(
            -32004,
            format!(
                "historical state at block 0 is not available on this node: it serves only \
                 its current finalized head ({head}). Use \"latest\" or a historical-root \
                 proof instead of relabeling current state."
            ),
        )),
    }
}

/// The block selector of an `eth_call` shape, if one was supplied.
fn eth_call_block_tag(
    params: &Value,
) -> Result<Option<crate::evm_adapter::BlockTag>, crate::evm_adapter::JsonRpcError> {
    use crate::evm_adapter::BlockTag;
    let raw = match params {
        Value::Array(arr) => arr.get(1),
        Value::Object(obj) => obj
            .get("blockTag")
            .or_else(|| obj.get("block_tag"))
            .or_else(|| obj.get("block")),
        _ => None,
    };
    match raw {
        None | Some(Value::Null) => Ok(None),
        Some(v) => BlockTag::parse(v).map(Some),
    }
}

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

    /// Reconstruct the native transaction body behind a receipt.
    ///
    /// Live receipts carry `raw_tx`; receipts hydrated after a restart do not
    /// (`StoredReceipt` keeps no raw bytes). In that case the committed block
    /// body in the archive store is authoritative. `None` means this node
    /// genuinely cannot reconstruct it (body pruned / no store attached);
    /// callers must then answer with fewer fields, never with zeroed ones.
    fn receipt_body_tx(&self, r: &crate::rpc::TxReceipt) -> Option<crate::sharding::Transaction> {
        if let Some(ref raw_hex) = r.raw_tx {
            let stripped = raw_hex
                .strip_prefix("0x")
                .or_else(|| raw_hex.strip_prefix("0X"))
                .unwrap_or(raw_hex);
            if let Ok(bytes) = hex::decode(stripped) {
                if let Ok(tx) = bincode::deserialize::<crate::sharding::Transaction>(&bytes) {
                    return Some(tx);
                }
            }
        }
        let store = self.archive_store.as_ref()?;
        let block = store.get_block(&r.block_hash).ok().flatten()?;
        block
            .transactions
            .into_iter()
            .find(|tx| tx.compute_tx_hash() == r.tx_hash)
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
                // Restart-hydrated receipts have no raw bytes: recover the
                // committed body from the archive store before falling back to
                // the (unfinalized) mempool copy. A pruned body stays unknown;
                // the zero address is the honest "not reconstructed" marker
                // this view already documented, never a real sender.
                if let Some(tx) = self.receipt_body_tx(r) {
                    receipt.from = crate::evm_adapter::stell_address_to_evm(&tx.from);
                    receipt.to = Some(crate::evm_adapter::stell_address_to_evm(&tx.to));
                } else {
                    drop(idx);
                    let mp = self.mempool.read().await;
                    if let Some(tx) = mp.get(&lookup_bytes) {
                        receipt.from = crate::evm_adapter::stell_address_to_evm(&tx.from);
                        receipt.to = Some(crate::evm_adapter::stell_address_to_evm(&tx.to));
                    }
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
        let mined_meta = idx
            .get(&lookup_bytes)
            .map(|r| (r.block_hash, r.height, r.index));
        if let Some(r) = idx.get(&lookup_bytes) {
            // Never synthesise a zero-valued transaction for a receipt whose
            // body this node does not hold (audit F-11). A live receipt carries
            // `raw_tx`; a restart-hydrated one is reconstructed from the
            // committed block body. If neither exists, the honest answer is
            // `null` — the receipt/status methods still report finality.
            if let Some(tx) = self.receipt_body_tx(r) {
                let mut evm_tx = crate::evm_adapter::stell_tx_to_evm_with_chain(
                    &tx,
                    Some(r.block_hash),
                    Some(r.height),
                    Some(r.index),
                    self.chain_id,
                );
                if is_settled_evm {
                    evm_tx.hash = norm.clone();
                }
                return Ok(Some(evm_tx));
            }
        }
        drop(idx);
        let mp = self.mempool.read().await;
        if let Some(tx) = mp.get(&lookup_bytes) {
            // A pool copy of a FINALIZED transaction (not swept yet) must still
            // report its committed block, not `null` as if it were pending.
            let (bh, bn, ti) = match mined_meta {
                Some((bh, h, i)) => (Some(bh), Some(h), Some(i)),
                None => (None, None, None),
            };
            let mut evm_tx =
                crate::evm_adapter::stell_tx_to_evm_with_chain(tx, bh, bn, ti, self.chain_id);
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

/// Resolve `evm -> pq` using canonical `Domain::EvmBindings` first (via
/// `st.engine.evm_binding_pq`), falling back to the persistent `"evm_bindings"`
/// sled index when `archive_store` is attached.
async fn resolve_evm_binding_pq(st: &RpcState, evm: &[u8; 20]) -> Option<[u8; 32]> {
    if let Some(pq) = st.engine.evm_binding_pq(evm).await {
        return Some(pq);
    }
    st.archive_store
        .as_ref()
        .and_then(|store| store.evm_binding_by_evm(evm).ok().flatten())
}

/// Resolve `pq -> evm` using canonical `Domain::EvmBindings` first (via
/// `st.engine.evm_binding_for_pq`), falling back to the persistent `"evm_bindings"`
/// sled index when `archive_store` is attached.
async fn resolve_evm_binding_for_pq(st: &RpcState, pq: &[u8; 32]) -> Option<[u8; 20]> {
    if let Some(evm) = st.engine.evm_binding_for_pq(pq).await {
        return Some(evm);
    }
    st.archive_store
        .as_ref()
        .and_then(|store| store.evm_binding_by_pq(pq).ok().flatten())
}

/// Resolve a 20-byte EVM or 32-byte Stellereum address to the owning PQ account,
/// consulting canonical `st.engine.evm_binding_pq` first and `archive_store` on miss.
async fn resolve_evm_account_rpc(
    st: &RpcState,
    addr: &str,
) -> Result<[u8; 32], crate::evm_adapter::JsonRpcError> {
    let trimmed = addr.trim();
    let bare = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if bare.len() == 40 {
        let evm = crate::evm_adapter::evm_address_from_hex(bare).map_err(|e| {
            crate::evm_adapter::JsonRpcError::invalid_params(format!(
                "invalid address '{addr}': {e}"
            ))
        })?;
        if let Some(pq) = resolve_evm_binding_pq(st, &evm).await {
            return Ok(pq);
        }
    }
    crate::evm_adapter::parse_evm_or_stell_address(addr).map_err(|e| {
        crate::evm_adapter::JsonRpcError::invalid_params(format!("invalid address '{addr}': {e}"))
    })
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
                Ok(Some(raw)) => match resolve_evm_account_rpc(st, &raw).await {
                    Ok(a) => Some(a),
                    Err(e) => return Some(err(id, -32602, format!("invalid from address: {e}"))),
                },
                Ok(None) => None,
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
        "eth_getCode" => {
            let tag = match crate::evm_adapter::parse_address_and_tag_params(params) {
                Ok((_, tag)) => tag,
                Err(e) => return Some(err(id, e.code, e.message)),
            };
            if let Err(e) = require_current_state_tag(
                tag.as_ref(),
                st.height.load(std::sync::atomic::Ordering::Relaxed),
            ) {
                return Some(err(id, e.code, e.message));
            }
            match crate::evm_adapter::eth_get_code_rpc(st, params).await {
                Ok(code) => ok(id, json!(code)),
                Err(e) => err(id, e.code, e.message),
            }
        }
        "eth_getBalance" => {
            let (addr_str, tag) = match crate::evm_adapter::parse_address_and_tag_params(params) {
                Ok(v) => v,
                Err(e) => return Some(err(id, e.code, e.message)),
            };
            if let Err(e) = require_current_state_tag(
                tag.as_ref(),
                st.height.load(std::sync::atomic::Ordering::Relaxed),
            ) {
                return Some(err(id, e.code, e.message));
            }
            let stell_addr = match resolve_evm_account_rpc(st, &addr_str).await {
                Ok(a) => a,
                Err(e) => return Some(err(id, e.code, e.message)),
            };
            let acc = st.engine.get_account(&stell_addr).await;
            let balance_nano = acc.map(|a| a.balance).unwrap_or(0);
            ok(id, json!(crate::evm_adapter::nano_to_wei_hex(balance_nano)))
        }
        "eth_getTransactionCount" => {
            // On-chain nonce for the resolved account (a 20-byte EVM address
            // resolves to its BOUND PQ account), plus — for the `pending` tag,
            // which is what a wallet asks for when it composes the next
            // transaction — the pooled head. Without the pending head a wallet
            // that sends twice in a row reuses the same nonce and the second
            // carrier is refused.
            let (account, want_pending) =
                match crate::evm_adapter::parse_address_and_tag_params(params) {
                    Ok((addr, tag)) => {
                        if let Err(e) = require_current_state_tag(
                            tag.as_ref(),
                            st.height.load(std::sync::atomic::Ordering::Relaxed),
                        ) {
                            return Some(err(id, e.code, e.message));
                        }
                        let want_pending = tag
                            .map(|t| matches!(t, crate::evm_adapter::BlockTag::Pending))
                            .unwrap_or(false);
                        match resolve_evm_account_rpc(st, &addr).await {
                            Ok(a) => (a, want_pending),
                            Err(e) => return Some(rpc_error(id, e)),
                        }
                    }
                    Err(e) => return Some(rpc_error(id, e)),
                };
            let onchain = st
                .engine
                .get_account(&account)
                .await
                .map(|a| a.nonce)
                .unwrap_or(0);
            if !want_pending {
                ok(id, json!(crate::evm_adapter::format_u64_hex(onchain)))
            } else {
                let pooled = st
                    .mempool
                    .read()
                    .await
                    .next_pending_nonce(&account)
                    .unwrap_or(0);
                ok(
                    id,
                    json!(crate::evm_adapter::format_u64_hex(onchain.max(pooled))),
                )
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
        "eth_call" => {
            let tag = match eth_call_block_tag(params) {
                Ok(t) => t,
                Err(e) => return Some(err(id, e.code, e.message)),
            };
            if let Err(e) = require_current_state_tag(
                tag.as_ref(),
                st.height.load(std::sync::atomic::Ordering::Relaxed),
            ) {
                return Some(err(id, e.code, e.message));
            }
            match crate::evm_adapter::eth_call_with_engine(&st.engine, params).await {
                Ok(v) => ok(id, v),
                Err(e) => err(id, e.code, e.message),
            }
        }
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
        "eth_getStorageAt" => {
            let tag = match crate::evm_adapter::parse_get_storage_at_params(params) {
                Ok((_, _, tag)) => tag,
                Err(e) => return Some(err(id, e.code, e.message)),
            };
            if let Err(e) = require_current_state_tag(
                Some(&tag),
                st.height.load(std::sync::atomic::Ordering::Relaxed),
            ) {
                return Some(err(id, e.code, e.message));
            }
            match st.eth_get_storage_at(params).await {
                Ok(v) => ok(id, json!(v)),
                Err(e) => err(id, e.code, e.message),
            }
        }
        "eth_sendRawTransaction" => {
            // FULL-PQ EVM WRITE PATH. What this method can and cannot do:
            //
            //  * a secp256k1/EIP-155 signature is NEVER a consensus
            //    credential here, so a bare EVM intent can not move value;
            //  * if the EVM sender has NO on-chain PQ binding, the historical
            //    honest refusal stays verbatim (`full-pq-admission`) — there
            //    is no account to debit and nothing to authorise;
            //  * if it HAS a binding, the intent is refused with
            //    `pq-carrier-authorization-required` naming the exact carrier
            //    signing message (`error.data.signThis`) unless the caller
            //    supplies the bound PQ account's Falcon-512 signatures in the
            //    optional `carrier` parameter — in which case the carrier
            //    transaction is built, verified and admitted, and the EVM hash
            //    MetaMask tracks is returned.
            //
            // Malformed / malleable / foreign-chain / unprotected input keeps
            // its precise Phase-1 error on every path.
            let raw = match crate::evm_adapter::extract_raw_evm_bytes(params) {
                Ok(r) => r,
                Err(e) => return Some(rpc_error(id, e)),
            };
            let view = match crate::evm_adapter::decode_verify_raw_evm(&raw) {
                Ok(v) => v,
                Err(e) => return Some(rpc_error(id, e)),
            };
            let evm_from = match crate::evm_adapter::evm_address_from_hex(&view.from) {
                Ok(a) => a,
                Err(e) => {
                    return Some(err(
                        id,
                        -32603,
                        format!("decoded EVM sender is not an address: {e}"),
                    ))
                }
            };
            let evm_hash = view.hash.clone();
            let evm_from_hex = crate::evm_adapter::evm_address_to_hex(&evm_from);
            // 1. No binding => the historical, unchanged refusal.
            let Some(bound_pq) = resolve_evm_binding_pq(st, &evm_from).await else {
                return Some(rpc_error(
                    id,
                    crate::evm_adapter::evm_send_refusal(Some(&evm_hash)),
                ));
            };
            // 2. A binding exists: the intent must be settleable at all.
            let facts = match crate::evm_adapter::evm_transfer_facts_at(&raw, true) {
                Ok(f) => f,
                Err(e) => {
                    return Some(rpc_error(
                        id,
                        crate::evm_adapter::evm_intent_unsupported(Some(&evm_hash), &e),
                    ))
                }
            };
            // 3. The recipient must be routable: a bare EVM address has no PQ
            //    key, so crediting it would burn the funds.
            let recipient_evm = crate::evm_adapter::evm_address_to_hex(&facts.to);
            let Some(to_pq) = resolve_evm_binding_pq(st, &facts.to).await else {
                return Some(rpc_error(
                    id,
                    crate::evm_adapter::recipient_unbound(&recipient_evm, Some(&evm_hash)),
                ));
            };
            if to_pq == bound_pq {
                // Self-send: allowed, but the carrier still has to be paid for
                // and no binding can route a 20-byte address to itself. Keep
                // the semantics explicit (the value leg is a no-op transfer).
                tracing::debug!(
                    "[evm] carrier self-send for {} (bound account {})",
                    evm_from_hex,
                    hex::encode(bound_pq)
                );
            }
            // 4. Fee cap: the EVM gas figure is a resource cap, never the Stell
            //    fee. Cover the live admission floor (which already includes
            //    the PQ activation + carrier surcharges) and keep the builder
            //    deterministic for a wallet that cannot query the floor.
            let floor = {
                let pool = st.mempool.read().await;
                pool.effective_floor(&bound_pq)
            };
            let live_gas = floor
                .saturating_add(crate::mempool::PQ_ACTIVATION_SURCHARGE_GAS)
                .saturating_add(crate::mempool::EVM_CARRIER_SURCHARGE_GAS)
                .max(crate::evm_adapter::EVM_CARRIER_MIN_GAS);
            let auth = match carrier_auth_params(params) {
                Ok(a) => a,
                Err(e) => return Some(err(id, -32602, e)),
            };
            let gas_limit = auth
                .as_ref()
                .and_then(|a| a.gas_limit)
                .unwrap_or(live_gas)
                .max(facts.gas_limit);
            let intent_digest = crate::evm_adapter::evm_intent_digest(&raw);
            // Step 1: no PQ key / no intent signature yet. Report the digest to
            // Falcon-sign; the carrier message does not exist until then.
            let Some(auth) = auth else {
                return Some(rpc_error(
                    id,
                    crate::evm_adapter::carrier_authorization_required(
                        &evm_hash,
                        &evm_from_hex,
                        &bound_pq,
                        &recipient_evm,
                        &to_pq,
                        facts.value_nano,
                        gas_limit,
                        facts.nonce,
                        &intent_digest,
                        None,
                    ),
                ));
            };
            let pq_from = crate::post_quantum::derive_pq_address(
                crate::post_quantum::PqScheme::Falcon512,
                &auth.pq_pubkey,
                &crate::post_quantum::DEFAULT_SALT,
            );
            if pq_from != bound_pq {
                return Some(rpc_error(
                    id,
                    crate::evm_adapter::JsonRpcError::with_data(
                        -32000,
                        format!(
                            "carrier refused: the supplied PQ public key derives {}, but EVM \
                             address {evm_from_hex} is bound to {}",
                            hex::encode(pq_from),
                            hex::encode(bound_pq)
                        ),
                        json!({
                            "reason": "pq-key-not-the-bound-key",
                            "evmFrom": evm_from_hex,
                            "boundPqAddress": format!("0x{}", hex::encode(bound_pq)),
                            "derivedPqAddress": format!("0x{}", hex::encode(pq_from)),
                        }),
                    ),
                ));
            }
            let Some(intent_signature) = auth.intent_signature.as_deref() else {
                return Some(rpc_error(
                    id,
                    crate::evm_adapter::carrier_authorization_required(
                        &evm_hash,
                        &evm_from_hex,
                        &bound_pq,
                        &recipient_evm,
                        &to_pq,
                        facts.value_nano,
                        gas_limit,
                        facts.nonce,
                        &intent_digest,
                        None,
                    ),
                ));
            };
            // Step 2: the intent signature is known, so the payload (and the
            // exact carrier message that covers it) is deterministic.
            let sign_this = match crate::evm_adapter::carrier_template_message_at(
                &raw,
                &auth.pq_pubkey,
                intent_signature,
                to_pq,
                gas_limit,
                true,
            ) {
                Ok(m) => m,
                Err(e) => return Some(err(id, -32602, e)),
            };
            let Some(tx_signature) = auth.tx_signature.as_deref() else {
                return Some(rpc_error(
                    id,
                    crate::evm_adapter::carrier_authorization_required(
                        &evm_hash,
                        &evm_from_hex,
                        &bound_pq,
                        &recipient_evm,
                        &to_pq,
                        facts.value_nano,
                        gas_limit,
                        facts.nonce,
                        &intent_digest,
                        Some(&sign_this),
                    ),
                ));
            };
            // 3. Build exactly the transaction the signing message described.
            let tx = match crate::evm_adapter::build_carrier_transaction_at(
                &raw,
                &auth.pq_pubkey,
                intent_signature,
                to_pq,
                gas_limit,
                tx_signature,
                true,
            ) {
                Ok(t) => t,
                Err(e) => {
                    return Some(rpc_error(
                        id,
                        carrier_signature_refusal(&e, &sign_this, &evm_hash),
                    ))
                }
            };
            match submit_carrier(st, tx).await {
                Ok(_stell_hash) => {
                    // PENTEST2 H1: the EVM↔Stell settlement map is written by
                    // the COMMITTED block apply (and rebuilt at startup), never
                    // by admission. A pooled carrier is not settled yet, so
                    // mapping it here would make `eth_getTransactionReceipt`
                    // claim a settlement the chain does not have.
                    ok(id, json!(evm_hash))
                }
                Err(e) => rpc_error(id, e),
            }
        }
        // EVM WRITE PATH — address binding (read).
        //
        // `stell_getEvmBinding(address)` accepts a 20-byte EVM address or a
        // 32-byte PQ address and reports the current on-chain binding exactly as
        // this node's deterministic index knows it. `bound: false` is the
        // honest answer for an address this node has seen no committed claim
        // for (it is never invented).
        "stell_getEvmBinding" | "eth_getEvmBinding" => {
            let arg = match params {
                Value::Array(arr) => arr.first().and_then(|v| v.as_str()),
                Value::String(s) => Some(s.as_str()),
                _ => None,
            };
            let Some(arg) = arg else {
                return Some(err(id, -32602, "missing address parameter"));
            };
            let trimmed = arg.trim();
            let bare = trimmed
                .strip_prefix("0x")
                .or_else(|| trimmed.strip_prefix("0X"))
                .unwrap_or(trimmed);
            let result = if bare.len() == 40 {
                let evm = match crate::evm_adapter::evm_address_from_hex(bare) {
                    Ok(a) => a,
                    Err(e) => return Some(err(id, -32602, e)),
                };
                let pq = resolve_evm_binding_pq(st, &evm).await;
                json!({
                    "evmAddress": format!("0x{}", hex::encode(evm)),
                    "pqAddress": pq.map(|p| format!("0x{}", hex::encode(p))),
                    "bound": pq.is_some(),
                    "source": "committed EVM binding index (node-local replay of \
                               APPLIED SysCallBindEvmAddress / carrier transactions only; \
                               mempool-only claims are never reported as bound)",
                })
            } else if bare.len() == 64 {
                let mut pq = [0u8; 32];
                if let Err(e) = hex::decode_to_slice(bare, &mut pq) {
                    return Some(err(id, -32602, format!("invalid PQ address: {e}")));
                }
                let evm = resolve_evm_binding_for_pq(st, &pq).await;
                json!({
                    "evmAddress": evm.map(|e| format!("0x{}", hex::encode(e))),
                    "pqAddress": format!("0x{}", hex::encode(pq)),
                    "bound": evm.is_some(),
                    "source": "committed EVM binding index (node-local replay of \
                               APPLIED SysCallBindEvmAddress / carrier transactions only; \
                               mempool-only claims are never reported as bound)",
                })
            } else {
                return Some(err(
                    id,
                    -32602,
                    "address must be a 20-byte EVM address (0x + 40 hex) or a 32-byte PQ \
                     address (0x + 64 hex)",
                ));
            };
            ok(id, result)
        }
        // EVM WRITE PATH — binding registration.
        //
        // params: { "pqPublicKey": "0x<897 bytes>", "evmAddress": "0x<20 bytes>",
        //           "bindingSignature": "0x<666 bytes Falcon over the claim>",
        //           "txSignature": "0x<666 bytes Falcon over the tx message>",
        //           "nonce": <u64, optional — defaults to the account's next nonce>,
        //           "gasLimit": <u64, optional> }
        //
        // Self-authenticating (no API token): nothing can be bound without the
        // PQ key's signature, and the transaction is admitted through the same
        // mempool gate as any other. Returns the Stell transaction hash.
        //
        // The two signatures cover DIFFERENT preimages and the wallet must
        // build them with the same `nonce`/`gasLimit` that are submitted:
        //   claimSignThis = keccak256("STELL_EVM_BIND_V1" || chain_id ||
        //                            evm_address || pq_address)
        //   txSignThis    = the binding transaction's signing message
        // A wrong preimage is refused with BOTH hex preimages in
        // `error.data.claimSignThis` / `error.data.txSignThis` (plus the
        // nonce/gasLimit that were used), so a wallet can sign exactly those
        // and resubmit without guessing.
        "stell_evmBindingSubmit" => {
            let pq_pubkey = match hex_param(params, &["pqPublicKey", "pq_public_key"]) {
                Ok(v) => v,
                Err(e) => return Some(err(id, -32602, e)),
            };
            let evm_address: [u8; 20] =
                match hex_param(params, &["evmAddress", "evm_address", "evm"]) {
                    Ok(v) if v.len() == 20 => {
                        let mut a = [0u8; 20];
                        a.copy_from_slice(&v);
                        a
                    }
                    Ok(v) => {
                        return Some(err(
                            id,
                            -32602,
                            format!("evmAddress must be 20 bytes, got {}", v.len()),
                        ))
                    }
                    Err(e) => return Some(err(id, -32602, e)),
                };
            let binding_signature = match hex_param(
                params,
                &["bindingSignature", "binding_signature", "claimSignature"],
            ) {
                Ok(v) => v,
                Err(e) => return Some(err(id, -32602, e)),
            };
            // C1/S1: proof of possession of the EVM key. Without it the claim
            // is refused (consensus and admission both require it).
            let evm_signature =
                match hex_param(params, &["evmSignature", "evm_signature", "evmProof"]) {
                    Ok(v) => v,
                    Err(e) => return Some(err(id, -32602, e)),
                };
            let tx_signature =
                match hex_param(params, &["txSignature", "tx_signature", "signature"]) {
                    Ok(v) => v,
                    Err(e) => return Some(err(id, -32602, e)),
                };
            let pq_from = crate::post_quantum::derive_pq_address(
                crate::post_quantum::PqScheme::Falcon512,
                &pq_pubkey,
                &crate::post_quantum::DEFAULT_SALT,
            );
            // A conflict is refused before any signature work: first claim wins.
            if let Some(existing) = resolve_evm_binding_pq(st, &evm_address).await {
                if existing != pq_from {
                    return Some(rpc_error(
                        id,
                        crate::evm_adapter::JsonRpcError::with_data(
                            -32000,
                            format!(
                                "binding refused: EVM address 0x{} is already bound to PQ \
                                 account {} (first claim wins)",
                                hex::encode(evm_address),
                                hex::encode(existing)
                            ),
                            json!({
                                "reason": "evm-binding-conflict",
                                "evmAddress": format!("0x{}", hex::encode(evm_address)),
                                "boundPqAddress": format!("0x{}", hex::encode(existing)),
                            }),
                        ),
                    ));
                }
            }
            let acct = st.engine.get_account(&pq_from).await;
            let nonce = match optional_u64(params, &["nonce"]) {
                Ok(Some(n)) => n,
                Ok(None) => acct.as_ref().map(|a| a.nonce).unwrap_or(0),
                Err(e) => return Some(err(id, -32602, e)),
            };
            let floor = {
                let pool = st.mempool.read().await;
                pool.effective_floor(&pq_from)
            };
            let gas_limit = match optional_u64(params, &["gasLimit", "gas_limit"]) {
                Ok(Some(g)) => g,
                Ok(None) => floor
                    .saturating_add(crate::mempool::PQ_ACTIVATION_SURCHARGE_GAS)
                    .max(crate::evm_adapter::EVM_BINDING_MIN_GAS),
                Err(e) => return Some(err(id, -32602, e)),
            };
            let tx = match crate::evm_adapter::build_binding_transaction(
                &pq_pubkey,
                evm_address,
                &binding_signature,
                &evm_signature,
                nonce,
                gas_limit,
                &tx_signature,
            ) {
                Ok(t) => t,
                Err(e) => {
                    let sign_this = crate::evm_adapter::binding_template_message(
                        &pq_pubkey,
                        evm_address,
                        &binding_signature,
                        &evm_signature,
                        nonce,
                        gas_limit,
                    )
                    .unwrap_or_default();
                    let claim_msg = crate::evm_adapter::binding_message(
                        crate::evm_adapter::effective_chain_id(),
                        &evm_address,
                        &pq_from,
                    );
                    return Some(rpc_error(
                        id,
                        crate::evm_adapter::JsonRpcError::with_data(
                            -32000,
                            format!("binding refused: {e}"),
                            json!({
                                "reason": "evm-binding-signature-rejected",
                                "evmAddress": format!("0x{}", hex::encode(evm_address)),
                                "pqAddress": format!("0x{}", hex::encode(pq_from)),
                                "claimSignThis": format!("0x{}", hex::encode(claim_msg)),
                                "txSignThis": format!("0x{}", hex::encode(sign_this)),
                                "nonce": nonce,
                                "gasLimit": gas_limit,
                            }),
                        ),
                    ));
                }
            };
            match submit_carrier(st, tx).await {
                Ok(hash) => {
                    // PENTEST2 M1/H1: do NOT write the binding index here. The
                    // claim is only admitted, not committed; the index is fed
                    // from applied blocks (and rebuilt from persisted blocks at
                    // startup), so `stell_getEvmBinding` never reports an
                    // uncommitted claim as bound and mempool-only claims do
                    // not freeze routing.
                    ok(id, json!(hex::encode(hash)))
                }
                Err(e) => rpc_error(id, e),
            }
        }
        // EVM WRITE PATH — carrier submission in one call.
        //
        // params: { "rawTransaction": "0x<canonical EIP-155/1559>",
        //           "pqPublicKey": "0x<897 bytes>",
        //           "intentSignature": "0x<666 bytes Falcon over keccak256(raw)>",
        //           "txSignature": "0x<666 bytes Falcon over the carrier message>",
        //           "gasLimit": <u64, optional> }
        //
        // Same construction as `eth_sendRawTransaction` with a `carrier` object;
        // exposed under a `stell_` name so a wallet can use the native surface.
        // Returns the EVM transaction hash.
        "stell_evmCarrierSubmit" => {
            let raw = match crate::evm_adapter::extract_raw_evm_bytes(params) {
                Ok(r) => r,
                Err(e) => return Some(rpc_error(id, e)),
            };
            let view = match crate::evm_adapter::decode_verify_raw_evm(&raw) {
                Ok(v) => v,
                Err(e) => return Some(rpc_error(id, e)),
            };
            let evm_from = match crate::evm_adapter::evm_address_from_hex(&view.from) {
                Ok(a) => a,
                Err(e) => return Some(err(id, -32603, e)),
            };
            let evm_from_hex = crate::evm_adapter::evm_address_to_hex(&evm_from);
            let facts = match crate::evm_adapter::evm_transfer_facts_at(&raw, true) {
                Ok(f) => f,
                Err(e) => {
                    return Some(rpc_error(
                        id,
                        crate::evm_adapter::evm_intent_unsupported(Some(&view.hash), &e),
                    ))
                }
            };
            let Some(bound_pq) = resolve_evm_binding_pq(st, &evm_from).await else {
                return Some(rpc_error(
                    id,
                    crate::evm_adapter::evm_send_refusal(Some(&view.hash)),
                ));
            };
            let recipient_evm = crate::evm_adapter::evm_address_to_hex(&facts.to);
            let Some(to_pq) = resolve_evm_binding_pq(st, &facts.to).await else {
                return Some(rpc_error(
                    id,
                    crate::evm_adapter::recipient_unbound(&recipient_evm, Some(&view.hash)),
                ));
            };
            let pq_pubkey = match hex_param(params, &["pqPublicKey", "pq_public_key"]) {
                Ok(v) => v,
                Err(e) => return Some(err(id, -32602, e)),
            };
            let intent_signature = match hex_param(params, &["intentSignature", "intent_signature"])
            {
                Ok(v) => v,
                Err(e) => return Some(err(id, -32602, e)),
            };
            let tx_signature =
                match hex_param(params, &["txSignature", "tx_signature", "signature"]) {
                    Ok(v) => v,
                    Err(e) => return Some(err(id, -32602, e)),
                };
            let pq_from = crate::post_quantum::derive_pq_address(
                crate::post_quantum::PqScheme::Falcon512,
                &pq_pubkey,
                &crate::post_quantum::DEFAULT_SALT,
            );
            if pq_from != bound_pq {
                return Some(err(
                    id,
                    -32000,
                    format!(
                        "carrier refused: the supplied PQ public key derives {}, but EVM \
                         address {evm_from_hex} is bound to {}",
                        hex::encode(pq_from),
                        hex::encode(bound_pq)
                    ),
                ));
            }
            let floor = {
                let pool = st.mempool.read().await;
                pool.effective_floor(&bound_pq)
            };
            let gas_limit = match optional_u64(params, &["gasLimit", "gas_limit"]) {
                Ok(Some(g)) => g.max(facts.gas_limit),
                Ok(None) => floor
                    .saturating_add(crate::mempool::PQ_ACTIVATION_SURCHARGE_GAS)
                    .saturating_add(crate::mempool::EVM_CARRIER_SURCHARGE_GAS)
                    .max(crate::evm_adapter::EVM_CARRIER_MIN_GAS)
                    .max(facts.gas_limit),
                Err(e) => return Some(err(id, -32602, e)),
            };
            let sign_this = match crate::evm_adapter::carrier_template_message_at(
                &raw,
                &pq_pubkey,
                &intent_signature,
                to_pq,
                gas_limit,
                true,
            ) {
                Ok(m) => m,
                Err(e) => return Some(err(id, -32602, e)),
            };
            let tx = match crate::evm_adapter::build_carrier_transaction_at(
                &raw,
                &pq_pubkey,
                &intent_signature,
                to_pq,
                gas_limit,
                &tx_signature,
                true,
            ) {
                Ok(t) => t,
                Err(e) => {
                    return Some(rpc_error(
                        id,
                        carrier_signature_refusal(&e, &sign_this, &view.hash),
                    ))
                }
            };
            match submit_carrier(st, tx).await {
                Ok(_stell_hash) => {
                    // H1/M1: settlement is recorded only from committed blocks.
                    ok(id, json!(view.hash))
                }
                Err(e) => rpc_error(id, e),
            }
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
fn estimate_sender(params: &Value) -> Result<Option<String>, String> {
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
        // Validated + resolved by the caller through `resolve_evm_account`, so a
        // 20-byte EVM address quotes the BOUND PQ account's floor (F10: the
        // floor is per sender, so quoting the wrong account is a wrong quote).
        Some(Value::String(s)) => Ok(Some(s.clone())),
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

// ---------------------------------------------------------------------------
// EVM WRITE PATH: carrier helpers
// ---------------------------------------------------------------------------

/// The Falcon authorisation a caller attaches to an EVM submission.
///
/// Two signatures are required and both come from the BOUND PQ key:
/// `intent_signature` over `keccak256(EVM raw)` (the EVM-intent authorisation
/// carried in the payload) and `tx_signature` over the carrier signing message
/// (the PQ1 consensus credential). Neither can be produced by a relayer, and
/// neither is a node-held secret: the node only ever verifies them.
struct CarrierAuth {
    pq_pubkey: Vec<u8>,
    /// Falcon-512 over `keccak256(EVM raw)`; absent on the first step.
    intent_signature: Option<Vec<u8>>,
    /// Falcon-512 over the carrier signing message; absent until the intent
    /// signature exists (the message commits to it).
    tx_signature: Option<Vec<u8>>,
    gas_limit: Option<u64>,
}

/// Locate the optional `carrier` object on an `eth_sendRawTransaction` call.
///
/// Accepted shapes (MetaMask sends `[raw]`; a PQ signer sends
/// `[raw, {"carrier": {...}}]` or `[raw, {...}]`):
/// * `["0x.."]` -> `None` (no PQ authorisation attached);
/// * `["0x..", {"carrier": {"pqPublicKey", "intentSignature", "txSignature"}}]`;
/// * `["0x..", {"pqPublicKey", ...}]` (the object itself).
///
/// A `carrier` object that is present but malformed is a parameter error: it is
/// never silently ignored (that would report a missing authorisation for an
/// authorisation the caller actually tried to send).
fn carrier_auth_params(params: &Value) -> Result<Option<CarrierAuth>, String> {
    let outer = match params {
        Value::Array(arr) => match arr.get(1) {
            None | Some(Value::Null) => return Ok(None),
            Some(Value::Object(map)) => map,
            Some(_) => return Err("second parameter must be an object".to_string()),
        },
        Value::Object(map) => map,
        Value::String(_) | Value::Null => return Ok(None),
        _ => return Err("params must be an array or object".to_string()),
    };
    // Accept both `[{...carrier: {...}}]` and a bare `{...}` authorisation object.
    let obj = match outer.get("carrier") {
        Some(Value::Object(inner)) => inner,
        Some(_) => return Err("carrier must be an object".to_string()),
        None => outer,
    };
    // A plain second object without any carrier key is not an authorisation.
    let has_any = [
        "pqPublicKey",
        "pq_public_key",
        "intentSignature",
        "intent_signature",
    ]
    .iter()
    .any(|k| obj.contains_key(*k));
    if !has_any {
        return Ok(None);
    }
    Ok(Some(CarrierAuth {
        pq_pubkey: object_hex(obj, &["pqPublicKey", "pq_public_key"])?,
        intent_signature: object_optional_hex(obj, &["intentSignature", "intent_signature"])?,
        tx_signature: object_optional_hex(obj, &["txSignature", "tx_signature", "signature"])?,
        gas_limit: object_u64(obj, &["gasLimit", "gas_limit"])?,
    }))
}

/// Decode a required `0x`-hex byte parameter from a params object.
fn object_hex(obj: &serde_json::Map<String, Value>, keys: &[&str]) -> Result<Vec<u8>, String> {
    let raw = keys
        .iter()
        .find_map(|k| obj.get(*k).and_then(|v| v.as_str()))
        .ok_or_else(|| format!("missing {} parameter", keys[0]))?;
    let bare = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .unwrap_or(raw);
    hex::decode(bare).map_err(|e| format!("invalid {} hex: {e}", keys[0]))
}

/// Optional `0x`-hex bytes from a params object.
fn object_optional_hex(
    obj: &serde_json::Map<String, Value>,
    keys: &[&str],
) -> Result<Option<Vec<u8>>, String> {
    if !keys.iter().any(|k| obj.contains_key(*k)) {
        return Ok(None);
    }
    object_hex(obj, keys).map(Some)
}

/// Optional u64 from a params object (`0x`-hex or decimal string, or a number).
fn object_u64(obj: &serde_json::Map<String, Value>, keys: &[&str]) -> Result<Option<u64>, String> {
    for k in keys {
        match obj.get(*k) {
            None | Some(Value::Null) => continue,
            Some(Value::Number(n)) => {
                return n
                    .as_u64()
                    .map(Some)
                    .ok_or_else(|| format!("{k} must be a non-negative integer"))
            }
            Some(Value::String(s)) => {
                let parsed = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                    Some(h) => u64::from_str_radix(h, 16),
                    None => s.parse::<u64>(),
                };
                return parsed.map(Some).map_err(|e| format!("invalid {k}: {e}"));
            }
            Some(_) => return Err(format!("{k} must be a number or a numeric string")),
        }
    }
    Ok(None)
}

/// Decode a required `0x`-hex byte parameter from top-level params.
fn hex_param(params: &Value, keys: &[&str]) -> Result<Vec<u8>, String> {
    let obj = match params {
        Value::Array(arr) => arr.first().and_then(|v| v.as_object()),
        Value::Object(map) => Some(map),
        _ => None,
    };
    // Accept either a positional single parameter or a named one.
    if let Some(raw) = keys
        .iter()
        .find_map(|k| obj.and_then(|o| o.get(*k)).and_then(|v| v.as_str()))
    {
        let bare = raw
            .strip_prefix("0x")
            .or_else(|| raw.strip_prefix("0X"))
            .unwrap_or(raw);
        return hex::decode(bare).map_err(|e| format!("invalid {} hex: {e}", keys[0]));
    }
    if let Value::Object(map) = params {
        if let Some(Value::String(raw)) = map.get("data") {
            let bare = raw
                .strip_prefix("0x")
                .or_else(|| raw.strip_prefix("0X"))
                .unwrap_or(raw);
            return hex::decode(bare).map_err(|e| format!("invalid data hex: {e}"));
        }
    }
    Err(format!("missing {} parameter", keys[0]))
}

/// Optional u64 from top-level params.
fn optional_u64(params: &Value, keys: &[&str]) -> Result<Option<u64>, String> {
    let obj = match params {
        Value::Array(arr) => arr.first().and_then(|v| v.as_object()),
        Value::Object(map) => Some(map),
        _ => None,
    };
    match obj {
        Some(map) => object_u64(map, keys),
        None => Ok(None),
    }
}

/// Refusal for a carrier whose signatures do not verify: names the exact
/// preimages so the signer can retry with the right bytes.
fn carrier_signature_refusal(
    reason: &str,
    sign_this: &[u8],
    evm_hash: &str,
) -> crate::evm_adapter::JsonRpcError {
    crate::evm_adapter::JsonRpcError::with_data(
        -32000,
        format!("carrier refused: {reason}"),
        json!({
            "reason": "evm-carrier-signature-rejected",
            "detail": reason,
            "evmHash": evm_hash,
            "signThis": format!("0x{}", hex::encode(sign_this)),
            "requires": "Falcon-512 from the bound PQ key over keccak256(EVM transaction) \
                         (intentSignature) and over signThis (txSignature)",
        }),
    )
}

/// Admit a fully built carrier to the mempool, mirroring
/// `stell_sendRawTransaction` exactly (balance head, admission clock, chain
/// binding gate, nonce-gap fail-fast, broadcast, throttled save).
///
/// The signature is verified once more here, so no caller can slip an
/// unverified carrier into the pool through this helper.
async fn submit_carrier(
    st: &RpcState,
    tx: crate::sharding::Transaction,
) -> Result<[u8; 32], crate::evm_adapter::JsonRpcError> {
    if !tx.verify_signature() {
        return Err(crate::evm_adapter::JsonRpcError::with_data(
            -32000,
            "carrier refused: the PQ1 envelope signature does not verify".to_string(),
            json!({"reason": "evm-carrier-signature-rejected"}),
        ));
    }
    let next_height = st
        .height
        .load(std::sync::atomic::Ordering::Relaxed)
        .saturating_add(1);
    if let Some(reason) = crate::chain_binding::check_admission_from_env(
        tx.chain_id().is_some(),
        next_height,
        st.chain_id,
    )
    .err()
    {
        crate::metrics::global().inc_unbound_refused();
        return Err(crate::evm_adapter::JsonRpcError::new(-32000, reason));
    }
    let acct = st.engine.get_account(&tx.from).await;
    let balance = acct.as_ref().map(|a| a.balance).unwrap_or(0);
    let onchain_nonce = acct.as_ref().map(|a| a.nonce).unwrap_or(0);
    let mut actx = crate::mempool::AdmissionCtx::wall_now().with_chain_height(next_height);
    if let Some(sbal) = st.engine.sponsor_balance_of(&tx).await {
        actx = actx.with_sponsor_balance(sbal);
    }
    let admitted = {
        let mut pool = st.mempool.write().await;
        if let Some(gap) = pool.check_nonce_gap(&tx.from, tx.nonce, onchain_nonce) {
            return Err(crate::evm_adapter::JsonRpcError::with_data(
                -32000,
                format!("rejected: {gap}"),
                json!({"reason": "evm-carrier-nonce"}),
            ));
        }
        pool.add_checked_ctx(tx.clone(), balance, actx)
    };
    match admitted {
        Ok(hash) => {
            if let Some(bcast) = &st.tx_broadcast {
                let _ = bcast.send(tx);
            }
            crate::evm_adapter::notify_pending_tx(crate::evm_adapter::stell_hash_to_evm(&hash));
            st.save_mempool_throttled().await;
            Ok(hash)
        }
        Err(e) => {
            tracing::warn!(
                "[mempool] EVM carrier admission refused from {} nonce={} gas={}: {e}",
                hex::encode(&tx.from[..6]),
                tx.nonce,
                tx.gas_limit
            );
            Err(crate::evm_adapter::JsonRpcError::with_data(
                -32000,
                format!("rejected: {e}"),
                json!({"reason": "evm-carrier-admission-refused", "detail": e.to_string()}),
            ))
        }
    }
}
