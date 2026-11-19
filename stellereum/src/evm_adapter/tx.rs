use super::*;
use serde_json::Value;

lazy_static::lazy_static! {
    static ref EVM_PENDING_TXS: std::sync::Mutex<std::collections::HashMap<String, EvmTransaction>> =
        std::sync::Mutex::new(std::collections::HashMap::new());
}

/// Phase-1 EVM intent-pool helper (stateless library / embedded adapters).
///
/// Decodes RLP (legacy EIP-155 or EIP-1559 type-2), strictly verifies
/// `chain_id == effective_chain_id()` + low-s + ecrecover, stores the pending
/// `EvmTransaction` so `eth_getTransactionByHash` / filters see it, notifies
/// pending-tx filters, and returns the keccak hash.
///
/// NOT an admission path: FULL-PQ consensus has no settlement for a secp256k1
/// signature, so the node's `eth_sendRawTransaction` RPC never calls this and
/// refuses well-formed intents via [`evm_send_refusal`] instead of leaving a
/// pending intent that can never settle. The stateless `EvmAdapter` dispatch
/// uses the same refusal.
pub fn eth_send_raw_transaction(params: &Value) -> Result<String, JsonRpcError> {
    let raw = extract_raw_evm_bytes(params)?;
    eth_send_raw_transaction_bytes(&raw)
}

/// Extract canonical raw EVM bytes from `eth_sendRawTransaction` params
/// (array / bare hex string / object with `rawTransaction` aliases).
/// Shared by the stateless intent path and the RPC refusal path so both decode
/// exactly the same bytes.
pub fn extract_raw_evm_bytes(params: &Value) -> Result<Vec<u8>, JsonRpcError> {
    let raw_hex = match params {
        Value::Array(arr) => arr
            .first()
            .and_then(|v| v.as_str())
            .ok_or_else(|| JsonRpcError::invalid_params("missing raw transaction"))?,
        Value::String(s) => s.as_str(),
        Value::Object(map) => map
            .get("rawTransaction")
            .or_else(|| map.get("rawTx"))
            .or_else(|| map.get("tx"))
            .or_else(|| map.get("data"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| JsonRpcError::invalid_params("missing raw transaction"))?,
        _ => return Err(JsonRpcError::invalid_params("invalid params")),
    };
    let clean = raw_hex
        .strip_prefix("0x")
        .or_else(|| raw_hex.strip_prefix("0X"))
        .unwrap_or(raw_hex);
    let raw = hex::decode(clean).map_err(|e| JsonRpcError::invalid_params(e.to_string()))?;
    if raw.is_empty() || raw.len() > MAX_EVM_RAW_TX_BYTES {
        return Err(JsonRpcError::invalid_params(
            "empty or oversized raw transaction",
        ));
    }
    Ok(raw)
}

/// Decode + strictly verify already-extracted raw EVM bytes (chain_id,
/// low-s, ecrecover) and return the Phase-1 `EvmTransaction` view.
///
/// PURE: no pending-intent write, no filter notification, no mempool touch.
/// [`eth_send_raw_transaction_bytes`] adds the stateless intent-pool write;
/// the RPC refusal path calls [`verify_raw_evm_intent`] for the hash only.
///
/// Verification compares against [`effective_chain_id`] (single source,
/// M-02): served identity and admission agree on every deployment.
pub fn decode_verify_raw_evm(raw: &[u8]) -> Result<EvmTransaction, JsonRpcError> {
    if raw.is_empty() || raw.len() > MAX_EVM_RAW_TX_BYTES {
        return Err(JsonRpcError::invalid_params(
            "empty or oversized raw transaction",
        ));
    }
    let tx_hash = format!("0x{}", hex::encode(keccak256(raw)));

    // Decode + strictly verify (chain_id, low-s, ecrecover).
    Ok(if !raw.is_empty() && raw[0] == 0x02 {
        let decoded =
            parse_eip1559_envelope(raw).map_err(|e| JsonRpcError::invalid_params(e.to_string()))?;
        let from = decoded
            .verify_signature()
            .map_err(|e| JsonRpcError::server_error(INTERNAL_ERROR_CODE, e.to_string()))?;
        let expected_chain = effective_chain_id();
        if decoded.chain_id != expected_chain {
            return Err(JsonRpcError::server_error(
                INTERNAL_ERROR_CODE,
                format!(
                    "EIP-155 replay protection mismatch: expected chain {}, got {}",
                    expected_chain, decoded.chain_id
                ),
            ));
        }
        EvmTransaction {
            hash: tx_hash.clone(),
            nonce: format_u64_hex(decoded.nonce),
            block_hash: None,
            block_number: None,
            transaction_index: None,
            from: evm_address_to_hex(&from),
            to: decoded.to.map(|a| evm_address_to_hex(&a)),
            value: format!("0x{:x}", decoded.value),
            gas_price: Some(format!("0x{:x}", decoded.max_fee_per_gas)),
            gas: format_u64_hex(decoded.gas_limit),
            input: format!("0x{}", hex::encode(&decoded.data)),
            v: format!("0x{:x}", decoded.v),
            r: format!("0x{}", hex::encode(decoded.r)),
            s: format!("0x{}", hex::encode(decoded.s)),
            tx_type: Some("0x2".to_string()),
            chain_id: Some(eth_chain_id_for(effective_chain_id())),
            max_fee_per_gas: Some(format!("0x{:x}", decoded.max_fee_per_gas)),
            max_priority_fee_per_gas: Some(format!("0x{:x}", decoded.max_priority_fee_per_gas)),
            access_list: None,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        }
    } else {
        let decoded = parse_legacy_transaction(raw)
            .map_err(|e| JsonRpcError::invalid_params(e.to_string()))?;
        let from = decoded
            .verify_signature()
            .map_err(|e| JsonRpcError::server_error(INTERNAL_ERROR_CODE, e.to_string()))?;
        let expected_chain = effective_chain_id();
        match decoded.chain_id {
            Some(cid) if cid == expected_chain => {}
            Some(cid) => {
                return Err(JsonRpcError::server_error(
                    INTERNAL_ERROR_CODE,
                    format!("EIP-155 replay protection mismatch: expected chain {expected_chain}, got {cid}"),
                ))
            }
            None => {
                return Err(JsonRpcError::server_error(
                    INTERNAL_ERROR_CODE,
                    "EIP-155 replay protection required (unprotected legacy v=27/28 rejected)",
                ))
            }
        }
        EvmTransaction {
            hash: tx_hash.clone(),
            nonce: format_u64_hex(decoded.nonce),
            block_hash: None,
            block_number: None,
            transaction_index: None,
            from: evm_address_to_hex(&from),
            to: decoded.to.map(|a| evm_address_to_hex(&a)),
            value: format!("0x{:x}", decoded.value),
            gas_price: Some(format!("0x{:x}", decoded.gas_price)),
            gas: format_u64_hex(decoded.gas_limit),
            input: format!("0x{}", hex::encode(&decoded.data)),
            v: format!("0x{:x}", decoded.v),
            r: format!("0x{}", hex::encode(decoded.r)),
            s: format!("0x{}", hex::encode(decoded.s)),
            tx_type: Some("0x0".to_string()),
            chain_id: Some(eth_chain_id_for(effective_chain_id())),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            access_list: None,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        }
    })
}

/// Phase-1 admission gate, PURE: decode + strictly verify the EVM intent and
/// return its keccak hash without writing the pending-intent pool.
///
/// `eth_sendRawTransaction` uses this to give precise errors for malformed /
/// high-s / wrong-chain / unprotected envelopes while keeping the FULL-PQ
/// refusal side-effect free: no intent is filed for a transaction that
/// consensus admission can never settle.
pub fn verify_raw_evm_intent(raw: &[u8]) -> Result<String, JsonRpcError> {
    decode_verify_raw_evm(raw).map(|tx| tx.hash)
}

/// Store a verified EVM intent in the Phase-1 pool and notify filters.
///
/// NOTE: this is the STATELESS library path (tests, embedded adapters). The
/// node's `eth_sendRawTransaction` RPC does **not** call it: FULL-PQ admission
/// can never settle an EVM intent, so the RPC must never leave one pending
/// forever (see [`evm_send_refusal`]).
pub fn eth_send_raw_transaction_bytes(raw: &[u8]) -> Result<String, JsonRpcError> {
    let evm_tx = decode_verify_raw_evm(raw)?;
    let tx_hash = evm_tx.hash.clone();
    if let Ok(mut pending) = EVM_PENDING_TXS.lock() {
        // Bound pending pool (DoS guard): evict oldest arbitrary entry past 10k.
        if pending.len() >= 10_000 {
            if let Some(k) = pending.keys().next().cloned() {
                pending.remove(&k);
            }
        }
        pending.insert(tx_hash.clone(), evm_tx);
    }
    global_adapter().notify_pending_tx(tx_hash.clone());
    Ok(tx_hash)
}

/// The stable reason tag returned in `error.data.reason` for a refused EVM
/// write. Clients match this instead of a prose message.
pub const EVM_WRITE_REFUSAL_REASON: &str = "full-pq-admission";

/// Exact requirement an EVM write must meet before it can be admitted.
pub const EVM_WRITE_PQ_REQUIREMENT: &str =
    "PQ1 envelope (Falcon-512) or an SF1 Falcon session grant";

/// The honest `eth_sendRawTransaction` refusal for a FULL-PQ chain.
///
/// The EVM intent is decoded and its secp256k1 signature is verified (Phase 1
/// compatibility layer), but a classical signature is **not** a consensus
/// credential: `Mempool::add_checked_ctx` admits only envelopes whose
/// `Transaction::verify_signature` passes, and that requires a post-quantum
/// scheme whose `from` is `derive_pq_address(scheme, pubkey, salt)`. No
/// conversion can turn a secp256k1 key into that address, so the write is
/// refused with the exact replacement path instead of being pooled forever.
///
/// `evm_hash` is the keccak hash of the verified intent when the bytes were
/// well-formed (`None` only for error paths that already failed decoding).
pub fn evm_send_refusal(evm_hash: Option<&str>) -> JsonRpcError {
    let intent = match evm_hash {
        Some(h) => {
            format!(" The intent is well-formed (keccak {h}) but no PQ authorisation covers it.")
        }
        None => String::new(),
    };
    JsonRpcError::with_data(
        -32000,
        format!(
            "eth_sendRawTransaction is not admitted: this is a FULL-PQ chain and a \
             secp256k1/EIP-155 signature is not a consensus credential.{intent} \
             Submit the transfer as a Falcon-512 {requirement} with \
             stell_sendRawTransaction (params {{\"tx\":\"0x<bincode(Transaction)>\"}}); \
             fund the PQ account derive_pq_address(Falcon512, pubkey, DEFAULT_SALT), not \
             the EVM-derived address. Read-only eth_call / eth_getProof / eth_getCode / \
             eth_getBalance remain available. See the design header of src/rpc/eth.rs.",
            requirement = EVM_WRITE_PQ_REQUIREMENT
        ),
        serde_json::json!({
            "reason": EVM_WRITE_REFUSAL_REASON,
            "requires": EVM_WRITE_PQ_REQUIREMENT,
            "submitWith": "stell_sendRawTransaction",
            "evmHash": evm_hash,
            // The EVM WRITE path exists, but only for an address with an
            // on-chain PQ binding: a bare secp256k1 account has no PQ account
            // to debit. Naming the registration call keeps the refusal
            // actionable without changing its historical reason tag.
            "registerBinding": {
                "method": "stell_evmBindingSubmit",
                "requires": "Falcon-512 signature over keccak256(STELL_EVM_BIND_V1 || chain_id || evm_address || pq_address) plus the binding transaction envelope signature",
                "readWith": "stell_getEvmBinding"
            },
            "readOnly": [
                "eth_call",
                "eth_getProof",
                "eth_getCode",
                "eth_getBalance",
                "eth_getTransactionCount",
                "eth_getLogs"
            ],
        }),
    )
}

/// Decode/verify `params` and return the honest FULL-PQ refusal.
///
/// Malformed / malleable / wrong-chain / unprotected envelopes keep their
/// precise Phase-1 error; a well-formed intent gets the PQ requirement. No
/// pending intent is created on either path.
pub fn evm_send_refusal_from_params(params: &Value) -> JsonRpcError {
    match extract_raw_evm_bytes(params).and_then(|raw| verify_raw_evm_intent(&raw)) {
        Ok(hash) => evm_send_refusal(Some(&hash)),
        Err(e) => e,
    }
}

/// Map verified raw EVM bytes onto the legacy Phase-2 `EV1` carrier.
///
/// DECODE/SIMULATION ONLY — this is NOT an admission path in FULL-PQ builds.
/// `Transaction::verify_signature` refuses every `EV1` inner envelope and
/// `mempool::insert` refuses it explicitly with
/// [`crate::mempool::EVM_ENVELOPE_REFUSAL`], so a
/// transaction built here can never enter the consensus mempool or a block.
/// It remains useful for read-only simulation (`stell_estimateFee` decodes raw
/// EVM input) and for tests that pin the historical mapping.
///
/// Decodes RLP (legacy EIP-155 or EIP-1559 type-2), strictly verifies
/// `chain_id == effective_chain_id()` (single source, M-02) + low-s +
/// ecrecover via [`DecodedTransaction::verify_signature`], then maps through
/// `evm_to_stell_address` (sender/recipient), `wei_to_nano` (value, sub-nano
/// wei truncated deterministically) and verbatim nonce/gas_limit, sealing the
/// canonical raw inside the `EV1` envelope of
/// [`crate::sharding::Transaction::new_evm`].
///
/// * contract creation (`to == None`) is rejected — there is no Stell
///   recipient to invent for a deployment;
/// * calldata (if any) is NOT executed — the carrier is a plain transfer of
///   the mapped value;
/// * shards are masterchain (single-shard carrier lane).
pub fn evm_raw_to_stell_transaction(raw: &[u8]) -> Result<crate::sharding::Transaction, String> {
    if raw.is_empty() || raw.len() > MAX_EVM_RAW_TX_BYTES {
        return Err("empty or oversized raw transaction".to_string());
    }
    let decoded = parse_raw_transaction(raw)?;
    // Strict chain_id == effective_chain_id() + low-s + ecrecover (both
    // variants enforce it; unprotected legacy v=27/28 fails here).
    let evm_from = decoded.verify_signature().map_err(|e| e.to_string())?;
    let evm_to = decoded.to().ok_or_else(|| {
        "EVM contract creation is not settled in Phase 2 (value transfers only)".to_string()
    })?;
    Ok(crate::sharding::Transaction::new_evm(
        evm_to_stell_address(&evm_from),
        evm_to_stell_address(&evm_to),
        wei_to_nano(decoded.value()),
        decoded.gas_limit(),
        decoded.nonce(),
        crate::sharding::MASTERCHAIN_SHARD,
        crate::sharding::MASTERCHAIN_SHARD,
        raw.to_vec(),
    ))
}

/// Lookup a pending EVM-intent transaction by hash (Phase 1 pool).
pub fn eth_pending_tx(hash: &str) -> Option<EvmTransaction> {
    let norm = normalize_hash(hash).ok()?;
    EVM_PENDING_TXS
        .lock()
        .ok()
        .and_then(|m| m.get(&norm).cloned())
}

// ============================================================================
// EVM intent -> L1 settlement bridge (keccak(EVM raw) <-> stell tx hash)
// ============================================================================

lazy_static::lazy_static! {
    static ref EVM_TO_STELL: std::sync::Mutex<std::collections::HashMap<String, [u8; 32]>> =
        std::sync::Mutex::new(std::collections::HashMap::new());
    static ref STELL_TO_EVM: std::sync::Mutex<std::collections::HashMap<[u8; 32], String>> =
        std::sync::Mutex::new(std::collections::HashMap::new());
}

/// Magic prefix of a secp256k1 settlement envelope carried in
/// `Transaction.signature`: `b"SC1" || evm_hash(32) || r(32) || s(32) || recid(1)`.
pub const SECP_ENVELOPE_MAGIC: &[u8; 3] = b"SC1";
/// Total wire length of a secp settlement envelope (3 + 32 + 64 + 1).
pub const SECP_ENVELOPE_LEN: usize = 100;

fn secp_sub_n_minus_s(s: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow: i32 = 0;
    for i in (0..32).rev() {
        let v = SECP256K1_N[i] as i32 - s[i] as i32 - borrow;
        if v < 0 {
            out[i] = (v + 256) as u8;
            borrow = 1;
        } else {
            out[i] = v as u8;
            borrow = 0;
        }
    }
    out
}

/// Cap for the settlement maps (matches the receipts window; unbounded
/// growth on a long-lived node otherwise).
pub const MAX_SETTLED_EVM_MAP: usize = 50_000;

/// Register a bidirectional mapping `keccak(EVM raw) <-> stell tx hash`.
///
/// Both directions are queryable via [`evm_to_stell_hash`] /
/// [`stell_to_evm_hash`]. Overwrites any previous entry for either key.
/// Also drops the settled hash from the pending intent pool so
/// `pending -> mined` reads observe the mined view first.
pub fn register_evm_settlement(evm_hash_hex: &str, stell_hash: &[u8; 32]) {
    let norm = match normalize_hash(evm_hash_hex) {
        Ok(n) => n,
        Err(_) => return,
    };
    if let Ok(mut fwd) = EVM_TO_STELL.lock() {
        // Bounded: evict an arbitrary entry past the cap (same DoS-guard
        // policy as the pending pool; mappings are redundant hints — the
        // canonical receipt lookup does not depend on them).
        if fwd.len() >= MAX_SETTLED_EVM_MAP {
            if let Some(k) = fwd.keys().next().cloned() {
                fwd.remove(&k);
            }
        }
        fwd.insert(norm.clone(), *stell_hash);
    }
    if let Ok(mut rev) = STELL_TO_EVM.lock() {
        if rev.len() >= MAX_SETTLED_EVM_MAP {
            if let Some(k) = rev.keys().next().cloned() {
                rev.remove(&k);
            }
        }
        rev.insert(*stell_hash, norm.clone());
    }
    // Best-effort: the intent is now mined; free the pending slot.
    if let Ok(mut pending) = EVM_PENDING_TXS.lock() {
        pending.remove(&norm);
    }
}

/// Drop both settlement maps (process-local; used by tests and by an
/// operator/diagnostic reset before a deterministic rebuild).
pub fn clear_evm_settlements() {
    if let Ok(mut fwd) = EVM_TO_STELL.lock() {
        fwd.clear();
    }
    if let Ok(mut rev) = STELL_TO_EVM.lock() {
        rev.clear();
    }
}

/// Resolve `keccak(EVM raw)` -> stell `compute_tx_hash()`, if settled.
pub fn evm_to_stell_hash(evm_hash_hex: &str) -> Option<[u8; 32]> {
    let norm = normalize_hash(evm_hash_hex).ok()?;
    EVM_TO_STELL.lock().ok()?.get(&norm).copied()
}

/// Resolve stell `compute_tx_hash()` -> `keccak(EVM raw)`, if settled.
pub fn stell_to_evm_hash(stell_hash: &[u8; 32]) -> Option<String> {
    STELL_TO_EVM.lock().ok()?.get(stell_hash).cloned()
}

/// True when `tx.signature` carries a secp settlement envelope (`SC1` magic).
pub fn is_secp_settlement_tx(tx: &crate::sharding::Transaction) -> bool {
    tx.signature.len() == SECP_ENVELOPE_LEN && tx.signature.starts_with(SECP_ENVELOPE_MAGIC)
}

/// Extract the embedded EVM hash (`0x...` lowercase) from a secp envelope.
pub fn secp_envelope_evm_hash(tx: &crate::sharding::Transaction) -> Option<String> {
    if !is_secp_settlement_tx(tx) {
        return None;
    }
    let raw: [u8; 32] = tx.signature[3..35].try_into().ok()?;
    Some(format!("0x{}", hex::encode(raw)))
}

/// Verify a secp settlement envelope: ecrecover over `keccak(signing_message)`
/// must equal the EVM address derived from `tx.from` (left-padded Stell addr).
pub fn verify_secp_settlement(tx: &crate::sharding::Transaction) -> Result<[u8; 20], String> {
    if !is_secp_settlement_tx(tx) {
        return Err("not a secp settlement envelope".to_string());
    }
    // Audit B-VM: bind the FULL address. `stell_to_evm_address` compares only
    // the low 20 bytes, so a hostile nonzero 12-byte prefix would alias any
    // EVM identity. EVM-derived Stell addresses are always zero-prefixed.
    if tx.from[..12] != [0u8; 12] {
        return Err("secp envelope Stell prefix must be zero".to_string());
    }
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&tx.signature[35..67]);
    s.copy_from_slice(&tx.signature[67..99]);
    let recid = tx.signature[99];
    if recid > 1 {
        return Err(format!("invalid secp recovery id: {recid}"));
    }
    if r == [0u8; 32] || s == [0u8; 32] {
        return Err("invalid secp signature (zero r/s)".to_string());
    }
    if !is_low_s(&s) {
        return Err("secp signature s is not canonical (EIP-2)".to_string());
    }
    let sighash = keccak256(&tx.signing_message());
    let recovered = ecrecover(&sighash, recid as u64, &r, &s)
        .map_err(|e| format!("secp ecrecover failed: {e}"))?;
    let expected = stell_to_evm_address(&tx.from);
    if recovered != expected {
        return Err("secp envelope recovers a different sender than tx.from".to_string());
    }
    Ok(recovered)
}

/// Build a Stellereum L1 transaction that settles `evm_hash_hex`.
///
/// `secp_key` is the SAME secp256k1 key that signed the EVM intent, so
/// `tx.from` (padded EVM sender) is authenticated by the envelope itself.
/// The envelope signs `keccak(Stell signing_message)` with low-s normalization.
pub fn build_secp_settlement_tx(
    secp_key: &k256::ecdsa::SigningKey,
    evm_hash_hex: &str,
    to: [u8; 32],
    amount: u64,
    gas_limit: u64,
    nonce: u64,
) -> Result<crate::sharding::Transaction, String> {
    let norm = normalize_hash(evm_hash_hex).map_err(|e| format!("bad evm hash: {e}"))?;
    let evm_bytes = parse_hash_bytes(&norm).map_err(|e| format!("bad evm hash: {e}"))?;
    let sender20 = pubkey_to_address(secp_key.verifying_key().to_encoded_point(false).as_bytes())
        .map_err(|e| e.to_string())?;
    let from32 = evm_to_stell_address(&sender20);
    // Signing bytes of the unsigned body (empty signature => base message).
    let unsigned = crate::sharding::Transaction {
        from: from32,
        to,
        amount,
        gas_limit,
        nonce,
        source_shard: 0,
        target_shard: 0,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let sighash = keccak256(&unsigned.signing_message());
    let (sig, recid) = secp_key
        .sign_prehash_recoverable(&sighash)
        .map_err(|e| format!("secp sign failed: {e}"))?;
    let raw = sig.to_bytes();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&raw[..32]);
    s.copy_from_slice(&raw[32..64]);
    let mut recid_byte = recid.to_byte();
    // Normalize to low-s (EIP-2) so L1 verification is strict.
    if !is_low_s(&s) {
        s = secp_sub_n_minus_s(&s);
        recid_byte ^= 1;
    }
    let mut envelope = Vec::with_capacity(SECP_ENVELOPE_LEN);
    envelope.extend_from_slice(SECP_ENVELOPE_MAGIC);
    envelope.extend_from_slice(&evm_bytes);
    envelope.extend_from_slice(&r);
    envelope.extend_from_slice(&s);
    envelope.push(recid_byte);
    Ok(crate::sharding::Transaction {
        from: from32,
        to,
        amount,
        gas_limit,
        nonce,
        source_shard: 0,
        target_shard: 0,
        signature: envelope,
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    })
}

/// Link a settled secp transaction into the bidirectional map.
///
/// Returns `(evm_hash, stell_hash)` when `tx` carries a valid envelope,
/// after registering. Invalid envelopes return `None` (fail-closed, no link).
pub fn link_secp_settlement(tx: &crate::sharding::Transaction) -> Option<(String, [u8; 32])> {
    // PQ EVM CARRIER (FULL-PQ write path). This function is the RPC's ONLY
    // per-committed-transaction hook (`record_receipts_with_events` calls it for
    // every transaction of a finalized block), so BOTH settlement shapes are
    // linked here — otherwise an EVM receipt would only be resolvable on the
    // node that submitted the carrier:
    //
    //  * the carrier's `keccak256(EVM tx)` (exactly what the wallet tracks) is
    //    registered against the L1 transaction hash, so
    //    `eth_getTransactionReceipt(evmHash)` resolves after inclusion;
    //  * a binding statement (claim or carrier) is replayed into the
    //    deterministic binding index in block order, which is what makes the
    //    index chain-derived on every node instead of admission-derived.
    //
    // Both legs re-verify their own signatures from block bytes (they never
    // trust the caller), and neither writes consensus state.
    if let Some(linked) = link_evm_carrier_settlement(tx) {
        return Some(linked);
    }
    let evm_hash = secp_envelope_evm_hash(tx)?;
    if verify_secp_settlement(tx).is_err() {
        return None;
    }
    let stell_hash = tx.compute_tx_hash();
    register_evm_settlement(&evm_hash, &stell_hash);
    Some((evm_hash, stell_hash))
}

/// Link one PQ EVM carrier / binding transaction into the EVM hash map and the
/// binding index (`None` for every non-EVM transaction).
fn link_evm_carrier_settlement(tx: &crate::sharding::Transaction) -> Option<(String, [u8; 32])> {
    use crate::evm_adapter::{classify_evm_payload, EvmPayload};
    let payload = classify_evm_payload(tx)?;
    // Replay the statement into the (node-local, non-consensus) index. A claim
    // that does not verify, or a conflicting first claim, is dropped: the index
    // is first-writer-wins, and the committed transaction stays authoritative
    // either way.
    if let Ok(mut idx) = crate::evm_adapter::evm_binding_index().write() {
        idx.observe_transaction(tx);
    }
    let stell_hash = tx.compute_tx_hash();
    match payload {
        EvmPayload::Carrier(carrier) => {
            let evm_hash = format!(
                "0x{}",
                hex::encode(crate::evm_adapter::evm_intent_digest(&carrier.evm_tx))
            );
            register_evm_settlement(&evm_hash, &stell_hash);
            Some((evm_hash, stell_hash))
        }
        // A claim settles no EVM intent: there is no EVM hash to link.
        EvmPayload::Binding(_) | EvmPayload::Mixed => None,
    }
}

/// Build the EVM receipt view for an EVM hash settled by `stell_receipt`.
///
/// Same body as [`stell_receipt_to_evm`] but `transaction_hash` is the queried
/// EVM hash (what MetaMask asked for), while block/ gas fields come from L1.
pub fn settled_receipt_for_evm(
    evm_hash_hex: &str,
    stell_receipt: &crate::rpc::TxReceipt,
) -> EvmReceipt {
    let mut receipt = stell_receipt_to_evm(stell_receipt);
    if let Ok(norm) = normalize_hash(evm_hash_hex) {
        receipt.transaction_hash = norm;
    }
    receipt
}

/// Build the mined EVM transaction view for an EVM hash settled by `stell_receipt`.
pub fn settled_tx_for_evm(
    evm_hash_hex: &str,
    stell_receipt: &crate::rpc::TxReceipt,
    chain_id: u64,
) -> Option<EvmTransaction> {
    let mut evm_tx = stell_receipt_to_evm_tx_with_chain(stell_receipt, chain_id)?;
    if let Ok(norm) = normalize_hash(evm_hash_hex) {
        evm_tx.hash = norm;
    }
    Some(evm_tx)
}

/// Converts a 32-byte Stellereum address to a 20-byte EVM hex address.
pub fn stell_address_to_evm(addr: &[u8; 32]) -> String {
    evm_address_to_hex(&stell_to_evm_address(addr))
}

/// Converts a 32-byte hash to a 0x-prefixed hex string.
pub fn stell_hash_to_evm(hash: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(hash))
}

/// Converts a Stellereum transaction to an EVM JSON-RPC transaction with a custom chain ID.
pub fn stell_tx_to_evm_with_chain(
    tx: &crate::sharding::Transaction,
    block_hash: Option<[u8; 32]>,
    block_number: Option<u64>,
    tx_index: Option<u32>,
    chain_id: u64,
) -> EvmTransaction {
    let tx_hash = tx.compute_tx_hash();
    // A PQ EVM CARRIER is served as the EVM transaction the wallet knows: its
    // `from` is the bound EVM address, its `to`/`value` come from the canonical
    // EIP-155 intent (not from the Stell accounting legs, whose addresses are
    // 32-byte PQ accounts). That is what makes
    // `eth_getTransactionByHash(evmHash)` and block transaction lists readable
    // by MetaMask instead of showing a PQ address it has never seen.
    let carrier_facts = match crate::evm_adapter::classify_evm_payload(tx) {
        Some(crate::evm_adapter::EvmPayload::Carrier(c)) => {
            Some((c, evm_transfer_facts(&c.evm_tx).ok()))
        }
        _ => None,
    };
    if let Some((carrier, facts)) = carrier_facts {
        let (from_hex, to_hex, value_hex, input) = match facts {
            Some(f) => (
                evm_address_to_hex(&carrier.evm_address),
                Some(evm_address_to_hex(&f.to)),
                format_u128_hex(f.value_wei),
                "0x".to_string(),
            ),
            // Undecodable intent (never admitted, but a corrupted view must stay
            // honest): show the carried EVM sender and no invented recipient.
            None => (
                evm_address_to_hex(&carrier.evm_address),
                None,
                nano_to_wei_hex(tx.amount),
                "0x".to_string(),
            ),
        };
        return EvmTransaction {
            hash: stell_hash_to_evm(&tx_hash),
            nonce: format_u64_hex(tx.nonce),
            block_hash: block_hash.map(|h| stell_hash_to_evm(&h)),
            block_number: block_number.map(format_u64_hex),
            transaction_index: tx_index.map(|i| format_u64_hex(i as u64)),
            from: from_hex,
            to: to_hex,
            value: value_hex,
            gas_price: Some("0x1".to_string()),
            gas: format_u64_hex(tx.gas_limit),
            input,
            v: format!("0x{:x}", chain_id * 2 + 35),
            r: "0x0".to_string(),
            s: "0x0".to_string(),
            tx_type: Some("0x0".to_string()),
            chain_id: Some(format!("0x{:x}", chain_id)),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            access_list: None,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };
    }
    let r = if tx.signature.len() >= 32 {
        format!("0x{}", hex::encode(&tx.signature[0..32]))
    } else {
        "0x0".to_string()
    };
    let s = if tx.signature.len() >= 64 {
        format!("0x{}", hex::encode(&tx.signature[32..64]))
    } else {
        "0x0".to_string()
    };
    // EIP-155 formula: v = {0,1} + chainId * 2 + 35
    let v = format!("0x{:x}", chain_id * 2 + 35);

    let input = if !tx.payload.is_empty() {
        match bincode::serialize(&tx.payload) {
            Ok(bytes) => format!("0x{}", hex::encode(bytes)),
            Err(_) => "0x".to_string(),
        }
    } else {
        "0x".to_string()
    };

    EvmTransaction {
        hash: stell_hash_to_evm(&tx_hash),
        nonce: format_u64_hex(tx.nonce),
        block_hash: block_hash.map(|h| stell_hash_to_evm(&h)),
        block_number: block_number.map(format_u64_hex),
        transaction_index: tx_index.map(|i| format_u64_hex(i as u64)),
        from: stell_address_to_evm(&tx.from),
        to: Some(stell_address_to_evm(&tx.to)),
        value: nano_to_wei_hex(tx.amount),
        gas_price: Some("0x1".to_string()),
        gas: format_u64_hex(tx.gas_limit),
        input,
        v,
        r,
        s,
        tx_type: Some("0x0".to_string()),
        chain_id: Some(format!("0x{:x}", chain_id)),
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        access_list: None,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    }
}

/// Converts a Stellereum transaction to an EVM JSON-RPC transaction.
///
/// Served-identity default: [`effective_chain_id`] (STELL_CHAIN_ID-aware), so
/// block/tx views agree with `eth_chainId` on every deployment. Admission
/// and verification use the same [`effective_chain_id`] (single source,
/// M-02). Callers that need an explicit id use
/// [`stell_tx_to_evm_with_chain`] directly.
pub fn stell_tx_to_evm(
    tx: &crate::sharding::Transaction,
    block_hash: Option<[u8; 32]>,
    block_number: Option<u64>,
    tx_index: Option<u32>,
) -> EvmTransaction {
    stell_tx_to_evm_with_chain(tx, block_hash, block_number, tx_index, effective_chain_id())
}

/// Converts a Stellereum TxReceipt to an EVM JSON-RPC receipt.
pub fn stell_receipt_to_evm(r: &crate::rpc::TxReceipt) -> EvmReceipt {
    let (from, to) = if let Some(ref raw_hex) = r.raw_tx {
        let stripped = raw_hex
            .strip_prefix("0x")
            .or_else(|| raw_hex.strip_prefix("0X"))
            .unwrap_or(raw_hex);
        if let Ok(bytes) = hex::decode(stripped) {
            if let Ok(tx) = bincode::deserialize::<crate::sharding::Transaction>(&bytes) {
                (
                    stell_address_to_evm(&tx.from),
                    Some(stell_address_to_evm(&tx.to)),
                )
            } else {
                (
                    "0x0000000000000000000000000000000000000000".to_string(),
                    None,
                )
            }
        } else {
            (
                "0x0000000000000000000000000000000000000000".to_string(),
                None,
            )
        }
    } else {
        (
            "0x0000000000000000000000000000000000000000".to_string(),
            None,
        )
    };

    EvmReceipt {
        transaction_hash: stell_hash_to_evm(&r.tx_hash),
        transaction_index: format_u64_hex(r.index as u64),
        block_hash: stell_hash_to_evm(&r.block_hash),
        block_number: format_u64_hex(r.height),
        from,
        to,
        cumulative_gas_used: format_u64_hex(r.fee_charged),
        gas_used: format_u64_hex(r.fee_charged),
        contract_address: None,
        logs: Vec::new(),
        logs_bloom: EMPTY_LOGS_BLOOM.to_string(),
        status: Some(if r.success {
            "0x1".to_string()
        } else {
            "0x0".to_string()
        }),
        root: None,
        tx_type: Some("0x0".to_string()),
        effective_gas_price: Some("0x1".to_string()),
        blob_gas_used: None,
        blob_gas_price: None,
    }
}

/// Converts a Stellereum TxReceipt to an EVM JSON-RPC receipt with explicit transaction details.
pub fn stell_receipt_with_tx_to_evm(
    r: &crate::rpc::TxReceipt,
    tx: Option<&crate::sharding::Transaction>,
) -> EvmReceipt {
    let mut receipt = stell_receipt_to_evm(r);
    if let Some(t) = tx {
        receipt.from = stell_address_to_evm(&t.from);
        receipt.to = Some(stell_address_to_evm(&t.to));
    }
    receipt
}

/// Reconstructs an EVM transaction from a Stellereum `TxReceipt` if it contains `raw_tx`.
/// Defaults to [`effective_chain_id`] (single source, M-02) so the view
/// agrees with `eth_chainId` on every deployment.
pub fn stell_receipt_to_evm_tx(r: &crate::rpc::TxReceipt) -> Option<EvmTransaction> {
    stell_receipt_to_evm_tx_with_chain(r, effective_chain_id())
}

/// Reconstructs an EVM transaction from a Stellereum `TxReceipt` with a custom chain ID.
pub fn stell_receipt_to_evm_tx_with_chain(
    r: &crate::rpc::TxReceipt,
    chain_id: u64,
) -> Option<EvmTransaction> {
    if let Some(ref raw_hex) = r.raw_tx {
        let stripped = raw_hex
            .strip_prefix("0x")
            .or_else(|| raw_hex.strip_prefix("0X"))
            .unwrap_or(raw_hex);
        if let Ok(bytes) = hex::decode(stripped) {
            if let Ok(tx) = bincode::deserialize::<crate::sharding::Transaction>(&bytes) {
                return Some(stell_tx_to_evm_with_chain(
                    &tx,
                    Some(r.block_hash),
                    Some(r.height),
                    Some(r.index),
                    chain_id,
                ));
            }
        }
    }
    Some(EvmTransaction {
        hash: stell_hash_to_evm(&r.tx_hash),
        nonce: "0x0".to_string(),
        block_hash: Some(stell_hash_to_evm(&r.block_hash)),
        block_number: Some(format_u64_hex(r.height)),
        transaction_index: Some(format_u64_hex(r.index as u64)),
        from: "0x0000000000000000000000000000000000000000".to_string(),
        to: None,
        value: "0x0".to_string(),
        gas_price: Some("0x1".to_string()),
        gas: format_u64_hex(r.gas_limit.max(r.fee_charged)),
        input: "0x".to_string(),
        v: format!("0x{:x}", chain_id * 2 + 35),
        r: "0x0".to_string(),
        s: "0x0".to_string(),
        tx_type: Some("0x0".to_string()),
        chain_id: Some(format!("0x{:x}", chain_id)),
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        access_list: None,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    })
}

/// Translates a Stellereum `BlockSummary` into an `EvmBlock`.
pub fn stell_block_summary_to_evm(summary: &crate::rpc::BlockSummary) -> EvmBlock {
    stell_block_summary_to_evm_with_parent(summary, None)
}

/// Translates a Stellereum `BlockSummary` with an optional parent hash into an `EvmBlock`.
pub fn stell_block_summary_to_evm_with_parent(
    summary: &crate::rpc::BlockSummary,
    parent_hash: Option<&str>,
) -> EvmBlock {
    let hash = ensure_0x(&summary.hash);
    let p_hash = if summary.height == 0 {
        "0x0000000000000000000000000000000000000000000000000000000000000000".to_string()
    } else {
        parent_hash
            .map(ensure_0x)
            .unwrap_or_else(|| EMPTY_ROOT_HASH.to_string())
    };

    EvmBlock {
        number: Some(format_u64_hex(summary.height)),
        hash: Some(hash),
        parent_hash: p_hash,
        nonce: Some("0x0000000000000000".to_string()),
        sha3_uncles: EMPTY_UNCLES_HASH.to_string(),
        logs_bloom: Some(EMPTY_LOGS_BLOOM.to_string()),
        transactions_root: EMPTY_ROOT_HASH.to_string(),
        state_root: EMPTY_ROOT_HASH.to_string(),
        receipts_root: EMPTY_ROOT_HASH.to_string(),
        miner: "0x0000000000000000000000000000000000000000".to_string(),
        difficulty: "0x0".to_string(),
        total_difficulty: Some("0x0".to_string()),
        extra_data: "0x".to_string(),
        size: format_u64_hex(1024),
        gas_limit: format_u64_hex(30_000_000),
        gas_used: format_u64_hex(0),
        timestamp: format_u64_hex(summary.timestamp),
        transactions: BlockTransactions::Hashes(Vec::new()),
        uncles: Vec::new(),
        base_fee_per_gas: Some("0x7".to_string()),
        mix_hash: Some(EMPTY_ROOT_HASH.to_string()),
        withdrawals: None,
        withdrawals_root: None,
        blob_gas_used: None,
        excess_blob_gas: None,
        parent_beacon_block_root: None,
    }
}

/// Translates a Stellereum `BlockSummary` into an `EvmBlock` with full receipts/transactions and parent hash.
pub fn stell_block_summary_to_evm_full(
    summary: &crate::rpc::BlockSummary,
    parent_hash: Option<&str>,
    receipts: &[&crate::rpc::TxReceipt],
    full_tx: bool,
) -> EvmBlock {
    let mut block = stell_block_summary_to_evm_with_parent(summary, parent_hash);
    let total_gas: u64 = receipts.iter().map(|r| r.fee_charged).sum();
    block.gas_used = format_u64_hex(total_gas);
    if full_tx {
        let full_tx_list: Vec<EvmTransaction> = receipts
            .iter()
            .filter_map(|r| stell_receipt_to_evm_tx(r))
            .collect();
        block.transactions = BlockTransactions::Full(full_tx_list);
    } else {
        let tx_hashes: Vec<String> = receipts
            .iter()
            .map(|r| stell_hash_to_evm(&r.tx_hash))
            .collect();
        block.transactions = BlockTransactions::Hashes(tx_hashes);
    }
    block
}

/// Translates a Stellereum `BlockSummary` into an `EvmBlock` with hydrated transaction flag.
pub fn stell_block_summary_to_evm_block(
    summary: &crate::rpc::BlockSummary,
    full_tx: bool,
) -> EvmBlock {
    let mut block = stell_block_summary_to_evm(summary);
    if full_tx {
        block.transactions = BlockTransactions::Full(Vec::new());
    } else {
        block.transactions = BlockTransactions::Hashes(Vec::new());
    }
    block
}

/// Converts a Stellereum Block to an EVM JSON-RPC block.
pub fn stell_block_to_evm(b: &crate::sharding::Block, full_txs: bool) -> EvmBlock {
    let block_hash = b.compute_hash();
    let tx_hashes: Vec<String> = b
        .transactions
        .iter()
        .map(|tx| stell_hash_to_evm(&tx.compute_tx_hash()))
        .collect();

    let transactions = if full_txs {
        let full: Vec<EvmTransaction> = b
            .transactions
            .iter()
            .enumerate()
            .map(|(idx, tx)| {
                stell_tx_to_evm(tx, Some(block_hash), Some(b.height), Some(idx as u32))
            })
            .collect();
        BlockTransactions::Full(full)
    } else {
        BlockTransactions::Hashes(tx_hashes)
    };

    let total_gas_limit: u64 = b.transactions.iter().map(|tx| tx.gas_limit).sum();
    let gas_limit = if total_gas_limit > 0 {
        total_gas_limit
    } else {
        30_000_000
    };

    EvmBlock {
        number: Some(format_u64_hex(b.height)),
        hash: Some(stell_hash_to_evm(&block_hash)),
        parent_hash: stell_hash_to_evm(&b.prev_hash),
        nonce: Some("0x0000000000000000".to_string()),
        sha3_uncles: EMPTY_UNCLES_HASH.to_string(),
        logs_bloom: Some(EMPTY_LOGS_BLOOM.to_string()),
        transactions_root: EMPTY_ROOT_HASH.to_string(),
        state_root: stell_hash_to_evm(&b.state_root),
        receipts_root: EMPTY_ROOT_HASH.to_string(),
        miner: stell_address_to_evm(&b.proposer),
        difficulty: "0x0".to_string(),
        total_difficulty: Some("0x0".to_string()),
        extra_data: "0x".to_string(),
        size: format_u64_hex(1024),
        gas_limit: format_u64_hex(gas_limit),
        gas_used: format_u64_hex(0),
        timestamp: format_u64_hex(b.timestamp),
        transactions,
        uncles: Vec::new(),
        base_fee_per_gas: Some("0x7".to_string()),
        mix_hash: Some(EMPTY_ROOT_HASH.to_string()),
        withdrawals: None,
        withdrawals_root: None,
        blob_gas_used: None,
        excess_blob_gas: None,
        parent_beacon_block_root: None,
    }
}

impl EvmTransaction {
    /// Recovers the 20-byte sender address from this transaction's hash and signature (v, r, s).
    /// If this transaction has a chain_id, EIP-155 replay protection is verified.
    pub fn recover_sender(&self) -> Result<[u8; 20], EvmError> {
        let hash = parse_h256(&self.hash)?;
        let v = parse_v_str(&self.v)?;
        let r = parse_h256(&self.r)?;
        let s = parse_h256(&self.s)?;

        let expected_chain_id = match &self.chain_id {
            Some(cid_str) => parse_v_str(cid_str).ok(),
            None => None,
        };

        ecrecover_with_chain_id(&hash, v, &r, &s, expected_chain_id)
    }

    /// Verifies that the recovered sender address matches the `from` address in this transaction.
    pub fn verify_sender(&self) -> Result<bool, EvmError> {
        let recovered = self.recover_sender()?;
        let from_addr = parse_address(&self.from)?;
        Ok(recovered == from_addr)
    }
}
