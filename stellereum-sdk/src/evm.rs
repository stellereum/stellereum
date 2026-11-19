//! EVM ↔ PQ binding statements and the PQ **carrier** payload.
//!
//! # FULL-PQ, in one paragraph
//!
//! A secp256k1 key is never a consensus credential on Stellereum. Value moves
//! only under a Falcon-512 signature whose derived address is the debited
//! account. A MetaMask identity (`keccak256(secp_pubkey)[12..]`) and a PQ
//! account can therefore only be joined by an explicit PQ-signed **binding**,
//! and that binding must also carry the EVM key's own secp256k1 **proof of
//! possession**: without it any PQ key could first-claim an EVM address it
//! does not control (the node refuses that, and so does this builder).
//!
//! The node's canonical definitions live in
//! `stellereum/src/evm_adapter/binding.rs` and
//! `stellereum/src/svm.rs:{EvmAddressClaim,EvmCarrierIntent}`; every byte here
//! is pinned by `tests/parity.rs` against those types.
//!
//! # What is settled
//!
//! Value transfers only: a present recipient, empty calldata and a positive
//! value. There is no EVM interpreter and no EVM state trie, so a contract
//! creation or a call cannot be executed honestly and is refused with
//! [`EVM_CONTRACT_EXECUTION_REFUSAL`].
//!
//! # What the SDK verifies before signing
//!
//! * a binding proof is exactly 65 bytes `r || s || recovery_id`, EIP-2 low-s,
//!   and recovers the EVM address being bound;
//! * an EVM intent decodes, names the configured chain, carries an empty
//!   calldata, a present recipient and a positive nano-STELL value, and its
//!   secp256k1 signature recovers the carried EVM sender;
//! * the carrier transaction's `nonce` and `amount` equal the EVM intent's
//!   `nonce` and `wei_to_nano(value)` EXACTLY.

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use sha3::{Digest, Keccak256};

use crate::error::{Result, SdkError};
use crate::key::{
    derive_pq_address, FalconKeypair, DEFAULT_SALT, FALCON512_PUBKEY_LEN, FALCON512_SIG_LEN,
};

/// Domain separator of the EVM↔PQ binding statement
/// (`stellereum/src/evm_adapter/binding.rs:EVM_BINDING_DOMAIN`).
pub const EVM_BINDING_DOMAIN: &[u8] = b"STELL_EVM_BIND_V1";
/// Length of the secp256k1 proof of possession: `r(32) || s(32) || recid(1)`.
pub const EVM_BINDING_PROOF_LEN: usize = 65;
/// Maximum EVM raw transaction size (`evm_adapter/types.rs`).
pub const MAX_EVM_RAW_TX_BYTES: usize = 128 * 1024;
/// Wei per nano-STELL (`evm_adapter/types.rs:WEI_PER_NANO`).
pub const WEI_PER_NANO: u128 = 1_000_000_000;
/// Builder floor for a carrier's declared `gas_limit`
/// (`evm_adapter/binding.rs:EVM_CARRIER_MIN_GAS`).
pub const EVM_CARRIER_MIN_GAS: u64 = 700_000;
/// Builder floor for a binding claim's declared `gas_limit`.
pub const EVM_BINDING_MIN_GAS: u64 = 600_000;

/// Stable refusal for EVM contract creation / calldata (the node's exact
/// wording, so a wallet can surface it unchanged).
pub const EVM_CONTRACT_EXECUTION_REFUSAL: &str =
    "EVM contract calls and contract creation are not settled by this chain: it has no EVM \
     interpreter and no EVM state trie, so executing bytecode here would be a lie. Only \
     value transfers (empty calldata, an existing recipient) are carried; deploy and call \
     contracts with the native SVM (stell_deployContract / stell_callContract).";

/// Payload of `OpCode::SysCallEvmCarrier` (field order is the node's bincode
/// layout).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvmCarrierIntent {
    pub chain_id: u64,
    pub evm_tx: Vec<u8>,
    pub evm_address: [u8; 20],
    pub pq_pubkey: Vec<u8>,
    pub evm_signature: Vec<u8>,
}

/// Payload of `OpCode::SysCallBindEvmAddress`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvmAddressClaim {
    pub chain_id: u64,
    pub evm_address: [u8; 20],
    pub pq_pubkey: Vec<u8>,
    pub binding_signature: Vec<u8>,
    pub evm_signature: Vec<u8>,
}

pub(crate) fn put_vec(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// `keccak256(data)` — the node's EVM hash.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    h.finalize().into()
}

/// The exact 32-byte digest the bound PQ key signs for a binding statement:
/// `keccak256("STELL_EVM_BIND_V1" || chain_id_be(8) || evm(20) || pq(32))`.
pub fn binding_message(chain_id: u64, evm: &[u8; 20], pq: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(EVM_BINDING_DOMAIN.len() + 8 + 20 + 32);
    buf.extend_from_slice(EVM_BINDING_DOMAIN);
    buf.extend_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(evm);
    buf.extend_from_slice(pq);
    keccak256(&buf)
}

/// `keccak256(EVM raw bytes)` — the digest a carrier's Falcon authorisation
/// covers.
pub fn evm_intent_digest(evm_tx: &[u8]) -> [u8; 32] {
    keccak256(evm_tx)
}

/// The value-transfer facts a carrier settles, as decoded by the SDK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvmIntentFacts {
    /// EVM sender recovered from the intent's secp256k1 signature.
    pub from: [u8; 20],
    /// EVM recipient.
    pub to: [u8; 20],
    /// EVM value in Wei (exact, as signed).
    pub value_wei: u128,
    /// EVM value in nano-STELL (truncated; refused when it truncates to 0).
    pub value_nano: u64,
    /// EVM nonce. A carrier MUST declare this same nonce.
    pub nonce: u64,
    /// EVM gas limit (a resource cap; NOT the Stell fee).
    pub gas_limit: u64,
    /// EVM chain id from the intent (EIP-155 / EIP-1559).
    pub chain_id: u64,
}

/// `wei / 1e9`, saturating at `u64::MAX` like the node.
pub fn wei_to_nano(wei: u128) -> u64 {
    let nano = wei / WEI_PER_NANO;
    if nano > u64::MAX as u128 {
        u64::MAX
    } else {
        nano as u64
    }
}

// ============================================================================
// Strict RLP (the subset an EVM transaction needs)
// ============================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
enum RlpItem {
    Bytes(Vec<u8>),
    List(Vec<RlpItem>),
}

impl RlpItem {
    fn as_bytes(&self) -> Result<&[u8]> {
        match self {
            RlpItem::Bytes(b) => Ok(b),
            RlpItem::List(_) => Err(evm_err("rlp", "expected a byte string, got a list")),
        }
    }

    fn as_u128(&self) -> Result<u128> {
        let b = self.as_bytes()?;
        if b.len() > 16 {
            return Err(evm_err("rlp", "integer field is wider than 128 bits"));
        }
        let mut v = 0u128;
        for byte in b {
            v = (v << 8) | *byte as u128;
        }
        Ok(v)
    }

    fn as_u64(&self) -> Result<u64> {
        let v = self.as_u128()?;
        u64::try_from(v).map_err(|_| evm_err("rlp", "integer field exceeds u64"))
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            RlpItem::Bytes(b) => encode_rlp_bytes(out, b),
            RlpItem::List(items) => {
                let mut payload = Vec::new();
                for item in items {
                    item.encode_into(&mut payload);
                }
                encode_rlp_header(out, 0xc0, payload.len());
                out.extend_from_slice(&payload);
            }
        }
    }
}

fn encode_rlp_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        out.push(bytes[0]);
        return;
    }
    encode_rlp_header(out, 0x80, bytes.len());
    out.extend_from_slice(bytes);
}

fn encode_rlp_header(out: &mut Vec<u8>, short_base: u8, len: usize) {
    if len < 56 {
        out.push(short_base + len as u8);
    } else {
        let len_bytes = len.to_be_bytes();
        let first_nonzero = len_bytes.iter().position(|b| *b != 0).unwrap_or(7);
        let trimmed = &len_bytes[first_nonzero..];
        out.push(short_base + 55 + trimmed.len() as u8);
        out.extend_from_slice(trimmed);
    }
}

fn rlp_decode(input: &[u8]) -> Result<RlpItem> {
    let (item, rest) = rlp_decode_with_rest(input, 0)?;
    if !rest.is_empty() {
        return Err(evm_err("rlp", "trailing bytes after RLP item"));
    }
    Ok(item)
}

fn rlp_decode_with_rest(input: &[u8], depth: usize) -> Result<(RlpItem, &[u8])> {
    if depth > 64 {
        return Err(evm_err("rlp", "nesting depth exceeded"));
    }
    let first = *input
        .first()
        .ok_or_else(|| evm_err("rlp", "unexpected end of input"))?;
    if first < 0x80 {
        return Ok((RlpItem::Bytes(vec![first]), &input[1..]));
    }
    if first <= 0xb7 {
        let len = (first - 0x80) as usize;
        let payload = take(input, 1, len)?;
        if len == 1 && payload[0] < 0x80 {
            return Err(evm_err("rlp", "non-canonical single byte"));
        }
        return Ok((RlpItem::Bytes(payload.to_vec()), &input[1 + len..]));
    }
    if first <= 0xbf {
        let len_of_len = (first - 0xb7) as usize;
        let len = read_length(input, 1, len_of_len)?;
        if len < 56 {
            return Err(evm_err("rlp", "non-canonical long string length"));
        }
        let payload = take(input, 1 + len_of_len, len)?;
        return Ok((
            RlpItem::Bytes(payload.to_vec()),
            &input[1 + len_of_len + len..],
        ));
    }
    if first <= 0xf7 {
        let len = (first - 0xc0) as usize;
        let payload = take(input, 1, len)?;
        let items = rlp_decode_list(payload, depth + 1)?;
        return Ok((RlpItem::List(items), &input[1 + len..]));
    }
    let len_of_len = (first - 0xf7) as usize;
    let len = read_length(input, 1, len_of_len)?;
    if len < 56 {
        return Err(evm_err("rlp", "non-canonical long list length"));
    }
    let payload = take(input, 1 + len_of_len, len)?;
    let items = rlp_decode_list(payload, depth + 1)?;
    Ok((RlpItem::List(items), &input[1 + len_of_len + len..]))
}

fn rlp_decode_list(payload: &[u8], depth: usize) -> Result<Vec<RlpItem>> {
    let mut items = Vec::new();
    let mut rest = payload;
    while !rest.is_empty() {
        let (item, next) = rlp_decode_with_rest(rest, depth)?;
        items.push(item);
        rest = next;
    }
    Ok(items)
}

fn read_length(input: &[u8], offset: usize, len_of_len: usize) -> Result<usize> {
    if len_of_len == 0 || len_of_len > 8 {
        return Err(evm_err("rlp", "invalid length-of-length"));
    }
    let bytes = take(input, offset, len_of_len)?;
    if bytes[0] == 0 {
        return Err(evm_err("rlp", "leading zero in length"));
    }
    let mut len = 0usize;
    for b in bytes {
        len = len
            .checked_mul(256)
            .and_then(|v| v.checked_add(*b as usize))
            .ok_or_else(|| evm_err("rlp", "length overflow"))?;
    }
    Ok(len)
}

fn take(input: &[u8], offset: usize, len: usize) -> Result<&[u8]> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| evm_err("rlp", "length overflow"))?;
    input
        .get(offset..end)
        .ok_or_else(|| evm_err("rlp", "unexpected end of input"))
}

fn evm_err(reason: &str, detail: &str) -> SdkError {
    SdkError::InvalidEvmIntent {
        reason: reason.to_string(),
        detail: detail.to_string(),
    }
}

// ============================================================================
// EVM transaction decoding + sender recovery
// ============================================================================

struct DecodedEvm {
    chain_id: u64,
    nonce: u64,
    gas_limit: u64,
    to: [u8; 20],
    value_wei: u128,
    data: Vec<u8>,
    signing_items: Vec<RlpItem>,
    typed: bool,
    r: [u8; 32],
    s: [u8; 32],
    recovery_id: u8,
}

fn to_item_address(item: &RlpItem) -> Result<[u8; 20]> {
    let bytes = item.as_bytes()?;
    if bytes.len() != 20 {
        return Err(evm_err(
            "contract-creation",
            "EVM contract creation (to == null) is not supported",
        ));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn fixed32(item: &RlpItem) -> Result<[u8; 32]> {
    let bytes = item.as_bytes()?;
    if bytes.len() > 32 {
        return Err(evm_err("rlp", "signature scalar wider than 32 bytes"));
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(out)
}

fn decode_evm_tx(raw: &[u8]) -> Result<DecodedEvm> {
    if raw.is_empty() || raw.len() > MAX_EVM_RAW_TX_BYTES {
        return Err(evm_err("size", "empty or oversized EVM transaction"));
    }
    if raw[0] == 0x02 {
        let item = rlp_decode(&raw[1..])?;
        let items = match item {
            RlpItem::List(items) => items,
            RlpItem::Bytes(_) => return Err(evm_err("rlp", "EIP-1559 payload is not a list")),
        };
        if items.len() != 12 {
            return Err(evm_err(
                "eip1559",
                "expected chainId, nonce, maxPriorityFee, maxFee, gasLimit, to, value, data, accessList, yParity, r, s",
            ));
        }
        let chain_id = items[0].as_u64()?;
        let nonce = items[1].as_u64()?;
        let gas_limit = items[4].as_u64()?;
        let to = to_item_address(&items[5])?;
        let value_wei = items[6].as_u128()?;
        let data = items[7].as_bytes()?.to_vec();
        let y_parity = items[9].as_u64()?;
        if y_parity > 1 {
            return Err(evm_err("signature", "EIP-1559 yParity must be 0 or 1"));
        }
        return Ok(DecodedEvm {
            chain_id,
            nonce,
            gas_limit,
            to,
            value_wei,
            data,
            signing_items: items[..9].to_vec(),
            typed: true,
            r: fixed32(&items[10])?,
            s: fixed32(&items[11])?,
            recovery_id: y_parity as u8,
        });
    }
    // Legacy / EIP-155.
    let item = rlp_decode(raw)?;
    let items = match item {
        RlpItem::List(items) => items,
        RlpItem::Bytes(_) => return Err(evm_err("rlp", "legacy payload is not a list")),
    };
    if items.len() != 9 {
        return Err(evm_err(
            "legacy",
            "expected nonce, gasPrice, gasLimit, to, value, data, v, r, s",
        ));
    }
    let nonce = items[0].as_u64()?;
    let gas_limit = items[2].as_u64()?;
    let to = to_item_address(&items[3])?;
    let value_wei = items[4].as_u128()?;
    let data = items[5].as_bytes()?.to_vec();
    let v = items[6].as_u64()?;
    if v < 35 {
        return Err(evm_err(
            "eip155",
            "legacy pre-EIP-155 signature carries no chain id",
        ));
    }
    let chain_id = (v - 35) / 2;
    let recovery_id = ((v - 35) % 2) as u8;
    let signing_items = vec![
        items[0].clone(),
        items[1].clone(),
        items[2].clone(),
        items[3].clone(),
        items[4].clone(),
        items[5].clone(),
        RlpItem::Bytes(
            chain_id
                .to_be_bytes()
                .iter()
                .skip_while(|b| **b == 0)
                .copied()
                .collect(),
        ),
        RlpItem::Bytes(Vec::new()),
        RlpItem::Bytes(Vec::new()),
    ];
    Ok(DecodedEvm {
        chain_id,
        nonce,
        gas_limit,
        to,
        value_wei,
        data,
        signing_items,
        typed: false,
        r: fixed32(&items[7])?,
        s: fixed32(&items[8])?,
        recovery_id,
    })
}

fn signing_hash(decoded: &DecodedEvm) -> [u8; 32] {
    let mut out = Vec::new();
    if decoded.typed {
        out.push(0x02);
    }
    RlpItem::List(decoded.signing_items.clone()).encode_into(&mut out);
    keccak256(&out)
}

fn recover_sender(decoded: &DecodedEvm) -> Result<[u8; 20]> {
    let sig = Signature::from_scalars(decoded.r, decoded.s)
        .map_err(|e| SdkError::InvalidEvmProof(format!("invalid secp256k1 r/s: {e}")))?;
    if sig.normalize_s().is_some() {
        return Err(SdkError::InvalidEvmProof(
            "secp256k1 signature s is not canonical (EIP-2 low-s required)".into(),
        ));
    }
    let recovery = RecoveryId::from_byte(decoded.recovery_id)
        .ok_or_else(|| SdkError::InvalidEvmProof("invalid recovery id".into()))?;
    let key = VerifyingKey::recover_from_prehash(&signing_hash(decoded), &sig, recovery)
        .map_err(|e| SdkError::InvalidEvmProof(format!("ecrecover failed: {e}")))?;
    let point = key.to_encoded_point(false);
    let hash = keccak256(&point.as_bytes()[1..]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[12..]);
    Ok(out)
}

/// Decode an EVM intent, recover its sender and return the value transfer it
/// settles. Refuses contract creation, calldata, zero value and sub-nano
/// value exactly like the node's `evm_transfer_facts`.
pub fn decode_evm_intent(raw: &[u8]) -> Result<EvmIntentFacts> {
    let decoded = decode_evm_tx(raw)?;
    if !decoded.data.is_empty() {
        return Err(evm_err(
            "contract-execution",
            EVM_CONTRACT_EXECUTION_REFUSAL,
        ));
    }
    if decoded.value_wei == 0 {
        return Err(evm_err(
            "zero-value",
            "an EVM carrier settles value transfers only: the intent carries no value",
        ));
    }
    let value_nano = wei_to_nano(decoded.value_wei);
    if value_nano == 0 {
        return Err(evm_err(
            "sub-nano",
            "EVM value is below one nano-STELL and cannot be settled",
        ));
    }
    Ok(EvmIntentFacts {
        from: recover_sender(&decoded)?,
        to: decoded.to,
        value_wei: decoded.value_wei,
        value_nano,
        nonce: decoded.nonce,
        gas_limit: decoded.gas_limit,
        chain_id: decoded.chain_id,
    })
}

/// Recover the EVM address that produced a 65-byte binding proof.
///
/// `proof` is `r(32) || s(32) || recovery_id(1)`, EIP-2 low-s, over
/// [`binding_message`]. Strictly fail-closed.
pub fn recover_binding_claim_signer(
    chain_id: u64,
    evm: &[u8; 20],
    pq: &[u8; 32],
    proof: &[u8],
) -> Result<[u8; 20]> {
    if proof.len() != EVM_BINDING_PROOF_LEN {
        return Err(SdkError::MissingEvmProof {
            expected: EVM_BINDING_PROOF_LEN,
            got: proof.len(),
        });
    }
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&proof[..32]);
    s.copy_from_slice(&proof[32..64]);
    let recovery_id = proof[64];
    if recovery_id > 1 {
        return Err(SdkError::InvalidEvmProof(format!(
            "recovery id must be 0 or 1, got {recovery_id}"
        )));
    }
    if r == [0u8; 32] || s == [0u8; 32] {
        return Err(SdkError::InvalidEvmProof("zero r/s".into()));
    }
    let sig = Signature::from_scalars(r, s)
        .map_err(|e| SdkError::InvalidEvmProof(format!("invalid r/s: {e}")))?;
    if sig.normalize_s().is_some() {
        return Err(SdkError::InvalidEvmProof(
            "s is not canonical (EIP-2)".into(),
        ));
    }
    let recovery = RecoveryId::from_byte(recovery_id)
        .ok_or_else(|| SdkError::InvalidEvmProof("invalid recovery id".into()))?;
    let digest = binding_message(chain_id, evm, pq);
    let key = VerifyingKey::recover_from_prehash(&digest, &sig, recovery)
        .map_err(|e| SdkError::InvalidEvmProof(format!("ecrecover failed: {e}")))?;
    let point = key.to_encoded_point(false);
    let hash = keccak256(&point.as_bytes()[1..]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[12..]);
    Ok(out)
}

/// Verify that `proof` is the EVM key's possession proof for `evm`, bound to
/// the PQ account derived from `pq_pubkey`. Pure and fail-closed.
pub fn verify_binding_proof(
    chain_id: u64,
    evm: &[u8; 20],
    pq_pubkey: &[u8],
    proof: &[u8],
) -> Result<()> {
    if pq_pubkey.len() != FALCON512_PUBKEY_LEN {
        return Err(SdkError::InvalidKey(format!(
            "Falcon-512 public key must be {FALCON512_PUBKEY_LEN} bytes, got {}",
            pq_pubkey.len()
        )));
    }
    let pq = derive_pq_address(pq_pubkey, &DEFAULT_SALT)?;
    let recovered = recover_binding_claim_signer(chain_id, evm, &pq, proof)?;
    if recovered != *evm {
        return Err(SdkError::EvmProofMismatch {
            expected: format!("0x{}", hex::encode(evm)),
            recovered: format!("0x{}", hex::encode(recovered)),
        });
    }
    Ok(())
}

// ============================================================================
// Builders
// ============================================================================

/// Why a carrier was refused before signing.
fn validate_carrier_shape(to_pq: &[u8; 32]) -> Result<()> {
    if *to_pq == [0u8; 32] {
        return Err(SdkError::InvalidArgument(
            "carrier recipient must be a real PQ account (zero address refused)".into(),
        ));
    }
    Ok(())
}

/// Falcon-sign `keccak256(evm_tx)` and seal the carrier transaction.
///
/// The transaction is deterministic in `(raw, key, to_pq, gas_limit)`: its
/// nonce and amount are taken from the EVM intent, never from a caller
/// argument. [`EvmCarrierBuilder::nonce`] and
/// [`EvmCarrierBuilder::amount_nano`] let a caller pin the declared values and
/// receive a specific refusal on mismatch.
#[derive(Clone, Debug)]
pub struct EvmCarrierBuilder {
    identity: crate::protocol::ProtocolIdentity,
    raw: Vec<u8>,
    to_pq: [u8; 32],
    gas_limit: u64,
    expected_nonce: Option<u64>,
    expected_amount_nano: Option<u64>,
    intent_signature: Option<Vec<u8>>,
}

impl EvmCarrierBuilder {
    pub fn new(
        identity: crate::protocol::ProtocolIdentity,
        raw: Vec<u8>,
        to_pq: [u8; 32],
    ) -> Result<Self> {
        identity.verify()?;
        validate_carrier_shape(&to_pq)?;
        let facts = decode_evm_intent(&raw)?;
        if facts.chain_id != identity.chain_id {
            return Err(SdkError::EvmChainIdMismatch {
                expected: identity.chain_id,
                got: facts.chain_id,
            });
        }
        Ok(Self {
            identity,
            raw,
            to_pq,
            gas_limit: EVM_CARRIER_MIN_GAS.saturating_add(crate::tx::PQ_ACTIVATION_SURCHARGE_GAS),
            expected_nonce: None,
            expected_amount_nano: None,
            intent_signature: None,
        })
    }

    /// Declare the nonce the carrier must use. Defaults to the EVM nonce.
    pub fn nonce(mut self, nonce: u64) -> Self {
        self.expected_nonce = Some(nonce);
        self
    }

    /// Declare the nano-STELL amount the carrier must move. Defaults to the
    /// EVM value.
    pub fn amount_nano(mut self, amount: u64) -> Self {
        self.expected_amount_nano = Some(amount);
        self
    }

    /// Override the declared `gas_limit` (it is a resource cap, not a price).
    pub fn gas_limit(mut self, gas_limit: u64) -> Self {
        self.gas_limit = gas_limit;
        self
    }

    /// Supply the Falcon signature over `keccak256(evm_tx)` instead of
    /// computing it from the signing key.
    pub fn intent_signature(mut self, signature: Vec<u8>) -> Self {
        self.intent_signature = Some(signature);
        self
    }

    /// The exact bytes a wallet must Falcon-sign for the carrier envelope.
    pub fn signing_message(&self, key: &FalconKeypair) -> Result<Vec<u8>> {
        let facts = decode_evm_intent(&self.raw)?;
        let intent_signature = match &self.intent_signature {
            Some(sig) => sig.clone(),
            None => key.sign(&evm_intent_digest(&self.raw))?,
        };
        let payload = self.payload(key, facts, intent_signature);
        let tx = crate::tx::Transaction {
            from: key.address(),
            to: self.to_pq,
            amount: facts.value_nano,
            gas_limit: self.gas_limit,
            nonce: facts.nonce,
            source_shard: crate::tx::MASTERCHAIN_SHARD,
            target_shard: crate::tx::MASTERCHAIN_SHARD,
            signature: Vec::new(),
            payload: crate::opcode::encode_payload(&[payload]),
            priority_fee_per_gas: 0,
        };
        Ok(tx.signing_message_for_chain(self.identity.chain_id))
    }

    fn payload(
        &self,
        key: &FalconKeypair,
        facts: EvmIntentFacts,
        evm_signature: Vec<u8>,
    ) -> crate::opcode::Op {
        crate::opcode::Op::EvmCarrier {
            chain_id: self.identity.chain_id,
            evm_tx: self.raw.clone(),
            evm_address: facts.from,
            pq_pubkey: key.public_key().to_vec(),
            evm_signature,
        }
    }

    /// Validate every pin and return the UNSIGNED carrier transaction.
    ///
    /// Envelope signing is deliberately separate so a test (or a wallet that
    /// uses another signer) can compare the unsigned bytes and the exact
    /// signing preimage against the node's builder.
    pub fn build_unsigned(&self, key: &FalconKeypair) -> Result<crate::tx::Transaction> {
        self.identity.verify()?;
        let facts = decode_evm_intent(&self.raw)?;
        if facts.chain_id != self.identity.chain_id {
            return Err(SdkError::EvmChainIdMismatch {
                expected: self.identity.chain_id,
                got: facts.chain_id,
            });
        }
        if let Some(nonce) = self.expected_nonce {
            if nonce != facts.nonce {
                return Err(SdkError::CarrierNonceMismatch {
                    evm: facts.nonce,
                    tx: nonce,
                });
            }
        }
        if let Some(amount) = self.expected_amount_nano {
            if amount != facts.value_nano {
                return Err(SdkError::CarrierValueMismatch {
                    evm: facts.value_nano,
                    tx: amount,
                });
            }
        }
        validate_carrier_shape(&self.to_pq)?;
        let intent_signature = match &self.intent_signature {
            Some(sig) => {
                if sig.len() != FALCON512_SIG_LEN {
                    return Err(SdkError::InvalidArgument(format!(
                        "carrier authorisation must be a {FALCON512_SIG_LEN}-byte Falcon-512 signature, got {}",
                        sig.len()
                    )));
                }
                sig.clone()
            }
            None => key.sign(&evm_intent_digest(&self.raw))?,
        };
        let payload = self.payload(key, facts, intent_signature);
        Ok(crate::tx::Transaction {
            from: key.address(),
            to: self.to_pq,
            amount: facts.value_nano,
            gas_limit: self.gas_limit,
            nonce: facts.nonce,
            source_shard: crate::tx::MASTERCHAIN_SHARD,
            target_shard: crate::tx::MASTERCHAIN_SHARD,
            signature: Vec::new(),
            payload: crate::opcode::encode_payload(&[payload]),
            priority_fee_per_gas: 0,
        })
    }

    /// Validate, Falcon-sign the intent and envelope, and return the carrier.
    pub fn sign(self, key: &FalconKeypair) -> Result<crate::tx::SignedTx> {
        let tx = self.build_unsigned(key)?;
        crate::tx::sign_unsigned(
            tx,
            key,
            crate::envelope::EnvelopeMode::Explicit,
            Some(self.identity.chain_id),
        )
    }
}

/// Build the EVM↔PQ binding claim transaction.
///
/// The claim REQUIRES the EVM key's 65-byte proof of possession; an empty or
/// malformed proof is refused before anything is signed. The claim moves no
/// value (`amount == 0`, `to == from`) and carries exactly one payload opcode.
pub struct EvmBindingBuilder {
    identity: crate::protocol::ProtocolIdentity,
    evm_address: [u8; 20],
    evm_proof: Vec<u8>,
    nonce: u64,
    gas_limit: u64,
    binding_signature: Option<Vec<u8>>,
}

impl EvmBindingBuilder {
    pub fn new(
        identity: crate::protocol::ProtocolIdentity,
        evm_address: [u8; 20],
        evm_proof: Vec<u8>,
    ) -> Result<Self> {
        identity.verify()?;
        if evm_proof.len() != EVM_BINDING_PROOF_LEN {
            return Err(SdkError::MissingEvmProof {
                expected: EVM_BINDING_PROOF_LEN,
                got: evm_proof.len(),
            });
        }
        Ok(Self {
            identity,
            evm_address,
            evm_proof,
            nonce: 0,
            gas_limit: EVM_BINDING_MIN_GAS.saturating_add(crate::tx::PQ_ACTIVATION_SURCHARGE_GAS),
            binding_signature: None,
        })
    }

    /// Supply the Falcon signature over [`Self::binding_message`] instead of
    /// computing it from the signing key (deterministic parity vectors).
    pub fn binding_signature(mut self, signature: Vec<u8>) -> Self {
        self.binding_signature = Some(signature);
        self
    }

    /// The PQ account's committed nonce.
    pub fn nonce(mut self, nonce: u64) -> Self {
        self.nonce = nonce;
        self
    }

    /// Override the declared `gas_limit`.
    pub fn gas_limit(mut self, gas_limit: u64) -> Self {
        self.gas_limit = gas_limit;
        self
    }

    /// The canonical binding digest for this claim and signing key.
    pub fn binding_message(&self, key: &FalconKeypair) -> [u8; 32] {
        binding_message(self.identity.chain_id, &self.evm_address, &key.address())
    }

    /// Verify the proof and return the UNSIGNED claim transaction.
    pub fn build_unsigned(&self, key: &FalconKeypair) -> Result<crate::tx::Transaction> {
        self.identity.verify()?;
        let pq = key.address();
        verify_binding_proof(
            self.identity.chain_id,
            &self.evm_address,
            key.public_key(),
            &self.evm_proof,
        )?;
        let digest = binding_message(self.identity.chain_id, &self.evm_address, &pq);
        let binding_signature = match &self.binding_signature {
            Some(sig) => {
                if sig.len() != FALCON512_SIG_LEN {
                    return Err(SdkError::InvalidArgument(format!(
                        "binding authorisation must be a {FALCON512_SIG_LEN}-byte Falcon-512 signature, got {}",
                        sig.len()
                    )));
                }
                sig.clone()
            }
            None => key.sign(&digest)?,
        };
        let claim = crate::opcode::Op::BindEvmAddress {
            chain_id: self.identity.chain_id,
            evm_address: self.evm_address,
            pq_pubkey: key.public_key().to_vec(),
            binding_signature,
            evm_signature: self.evm_proof.clone(),
        };
        Ok(crate::tx::Transaction {
            from: pq,
            to: pq,
            amount: 0,
            gas_limit: self.gas_limit,
            nonce: self.nonce,
            source_shard: crate::tx::MASTERCHAIN_SHARD,
            target_shard: crate::tx::MASTERCHAIN_SHARD,
            signature: Vec::new(),
            payload: crate::opcode::encode_payload(&[claim]),
            priority_fee_per_gas: 0,
        })
    }

    /// Verify the proof, Falcon-sign the statement + envelope, and return the
    /// claim transaction.
    pub fn sign(self, key: &FalconKeypair) -> Result<crate::tx::SignedTx> {
        let tx = self.build_unsigned(key)?;
        crate::tx::sign_unsigned(
            tx,
            key,
            crate::envelope::EnvelopeMode::Explicit,
            Some(self.identity.chain_id),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A well-formed legacy EIP-155 transaction with a deliberately invalid
    /// (but canonical) signature: decoding/nonce/value checks do not need the
    /// key, while sender recovery does.
    fn legacy_raw(nonce: u64, value_wei: u128, chain_id: u64) -> Vec<u8> {
        fn u(v: u128) -> RlpItem {
            let bytes = v.to_be_bytes();
            let first = bytes.iter().position(|b| *b != 0).unwrap_or(16);
            RlpItem::Bytes(bytes[first..].to_vec())
        }
        let v = chain_id * 2 + 35;
        let items = vec![
            u(nonce as u128),
            u(20_000_000_000),
            u(21_000),
            RlpItem::Bytes(vec![0x88; 20]),
            u(value_wei),
            RlpItem::Bytes(Vec::new()),
            u(v as u128),
            RlpItem::Bytes(vec![0x01; 32]),
            RlpItem::Bytes(vec![0x01; 32]),
        ];
        let mut out = Vec::new();
        RlpItem::List(items).encode_into(&mut out);
        out
    }

    #[test]
    fn legacy_fields_decode() {
        let raw = legacy_raw(9, 5 * WEI_PER_NANO, 5757);
        let decoded = decode_evm_tx(&raw).unwrap();
        assert_eq!(decoded.nonce, 9);
        assert_eq!(decoded.chain_id, 5757);
        assert_eq!(decoded.to, [0x88; 20]);
        assert_eq!(decoded.value_wei, 5 * WEI_PER_NANO);
    }

    #[test]
    fn calldata_is_refused() {
        let mut raw = legacy_raw(1, WEI_PER_NANO, 5757);
        // Replace the empty data field by a non-empty canonical byte string.
        let mut items = match rlp_decode(&raw).unwrap() {
            RlpItem::List(items) => items,
            _ => unreachable!(),
        };
        items[5] = RlpItem::Bytes(vec![0xAA]);
        raw.clear();
        RlpItem::List(items).encode_into(&mut raw);
        let err = decode_evm_intent(&raw).unwrap_err();
        assert!(matches!(err, SdkError::InvalidEvmIntent { .. }));
    }

    #[test]
    fn sub_nano_value_is_refused() {
        let raw = legacy_raw(1, 999, 5757);
        let err = decode_evm_intent(&raw).unwrap_err();
        assert!(matches!(
            err,
            SdkError::InvalidEvmIntent { ref reason, .. } if reason == "sub-nano"
        ));
    }

    #[test]
    fn binding_proof_length_is_required() {
        let err =
            verify_binding_proof(5757, &[1u8; 20], &[0u8; FALCON512_PUBKEY_LEN], &[]).unwrap_err();
        assert!(matches!(
            err,
            SdkError::MissingEvmProof {
                expected: 65,
                got: 0
            }
        ));
    }

    #[test]
    fn carrier_nonce_and_value_are_pinned_to_the_intent() {
        let identity = crate::protocol::ProtocolIdentity::local();
        let raw = legacy_raw(9, 5 * WEI_PER_NANO, 5757);
        let builder = EvmCarrierBuilder::new(identity, raw, [0x77; 32])
            .unwrap()
            .nonce(8);
        let key = FalconKeypair::generate().unwrap();
        let err = builder.sign(&key).unwrap_err();
        assert_eq!(err, SdkError::CarrierNonceMismatch { evm: 9, tx: 8 });

        let raw = legacy_raw(9, 5 * WEI_PER_NANO, 5757);
        let builder = EvmCarrierBuilder::new(identity, raw, [0x77; 32])
            .unwrap()
            .amount_nano(6);
        let err = builder.sign(&key).unwrap_err();
        assert_eq!(err, SdkError::CarrierValueMismatch { evm: 5, tx: 6 });
    }

    #[test]
    fn carrier_chain_mismatch_is_refused() {
        let identity = crate::protocol::ProtocolIdentity::local();
        let raw = legacy_raw(1, WEI_PER_NANO, 5758);
        let err = EvmCarrierBuilder::new(identity, raw, [0x77; 32]).unwrap_err();
        assert_eq!(
            err,
            SdkError::EvmChainIdMismatch {
                expected: 5757,
                got: 5758
            }
        );
    }
}
