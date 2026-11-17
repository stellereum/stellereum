//! The exact empty-payload `Transaction` wire form and signing/hash preimage.
//!
//! WHY THIS FILE EXISTS: `stellereum` cannot currently be used as a path
//! dependency because its working tree is mid-refactor (`post_quantum.rs`
//! removed the classical schemes while `wallet.rs`/`wallet_signing.rs` still
//! reference them, so the lib does not compile). The harness still must use
//! the node's REAL cryptography, so `post_quantum.rs` and
//! `sharding/envelope.rs` are included verbatim by `#[path]` in `main.rs`.
//! Only the small container below is mirrored here.
//!
//! SOURCE OF TRUTH for every line in this module:
//!
//! * `stellereum/src/sharding/transaction.rs` -- `TransactionWire`,
//!   `base_signing_message`, `append_payload_commitment`,
//!   `append_chain_id_commitment`, `encode/split_priority_envelope`,
//!   `hash_into`, `compute_tx_hash`, `new_pq_explicit_with_chain`,
//!   `new_pq_implicit_with_chain`, `pq_envelope`, `verify_inner_with_registry`.
//! * `stellereum/src/mempool.rs` -- `PQ_ACTIVATION_SURCHARGE_GAS`.
//!
//! SCOPE: this harness submits empty-payload value transfers only. `payload`
//! is therefore serialized as an empty `Vec` (one bincode length word), which
//! is byte-identical to the node's empty `Vec<OpCode>`. `encode_wire` refuses a
//! non-empty payload rather than emit bytes the node's `Vec<OpCode>` decoder
//! would misread.

use crate::envelope::PqSignatureEnvelope;
use crate::post_quantum::{
    derive_pq_address, verify_pq_signature, PqScheme, StatefulImplicitKeyRegistry,
    PQ_ENVELOPE_MAGIC,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub type ShardId = u32;

/// Mirror of `mempool::PQ_ACTIVATION_SURCHARGE_GAS`.
pub const PQ_ACTIVATION_SURCHARGE_GAS: u64 = 45_000;
pub const PRIORITY_FEE_COMMITMENT_TAG: &[u8; 8] = b"PRIORITY";
pub const CHAIN_ID_COMMITMENT_TAG: &[u8; 8] = b"CHAIN_ID";
pub const MAX_WIRE_BYTES: usize = 1024 * 1024;

/// Same positional layout as `sharding::transaction::TransactionWire`.
/// `payload` is `Vec<u8>` here only to keep the empty-vector encoding exact.
#[derive(Serialize, Deserialize)]
struct TransactionWire {
    from: [u8; 32],
    to: [u8; 32],
    amount: u64,
    gas_limit: u64,
    nonce: u64,
    source_shard: ShardId,
    target_shard: ShardId,
    signature: Vec<u8>,
    #[serde(default)]
    payload: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Transaction {
    pub from: [u8; 32],
    pub to: [u8; 32],
    pub amount: u64,
    pub gas_limit: u64,
    pub nonce: u64,
    pub source_shard: ShardId,
    pub target_shard: ShardId,
    pub signature: Vec<u8>,
    pub payload: Vec<u8>,
    pub priority_fee_per_gas: u64,
}

impl Serialize for Transaction {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        TransactionWire {
            from: self.from,
            to: self.to,
            amount: self.amount,
            gas_limit: self.gas_limit,
            nonce: self.nonce,
            source_shard: self.source_shard,
            target_shard: self.target_shard,
            signature: Self::encode_priority_envelope(&self.signature, self.priority_fee_per_gas),
            payload: self.payload.clone(),
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for Transaction {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let wire = TransactionWire::deserialize(d)?;
        let (signature, priority_fee_per_gas) = Self::split_priority_envelope(&wire.signature);
        Ok(Transaction {
            from: wire.from,
            to: wire.to,
            amount: wire.amount,
            gas_limit: wire.gas_limit,
            nonce: wire.nonce,
            source_shard: wire.source_shard,
            target_shard: wire.target_shard,
            signature,
            payload: wire.payload,
            priority_fee_per_gas,
        })
    }
}

impl Transaction {
    const PRIORITY_ENVELOPE_LEN: usize = 16;

    fn split_priority_envelope(blob: &[u8]) -> (Vec<u8>, u64) {
        if blob.len() >= Self::PRIORITY_ENVELOPE_LEN {
            let split = blob.len() - Self::PRIORITY_ENVELOPE_LEN;
            if &blob[split..split + 8] == PRIORITY_FEE_COMMITMENT_TAG {
                let mut bid = [0u8; 8];
                bid.copy_from_slice(&blob[split + 8..]);
                return (blob[..split].to_vec(), u64::from_be_bytes(bid));
            }
        }
        (blob.to_vec(), 0)
    }

    fn encode_priority_envelope(body: &[u8], priority_fee_per_gas: u64) -> Vec<u8> {
        if priority_fee_per_gas == 0 {
            return body.to_vec();
        }
        let mut out = Vec::with_capacity(body.len() + Self::PRIORITY_ENVELOPE_LEN);
        out.extend_from_slice(body);
        out.extend_from_slice(PRIORITY_FEE_COMMITMENT_TAG);
        out.extend_from_slice(&priority_fee_per_gas.to_be_bytes());
        out
    }

    #[allow(clippy::too_many_arguments)]
    // GATE: mirrors the node's constructor signature field-for-field.
    pub fn new_pq_explicit_with_chain(
        scheme: PqScheme,
        pubkey: Vec<u8>,
        signature_bytes: Vec<u8>,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        payload: Vec<u8>,
        salt: &[u8; 16],
        chain_id: u64,
    ) -> Self {
        let from = derive_pq_address(scheme, &pubkey, salt);
        let envelope = PqSignatureEnvelope::new_explicit_with_chain(
            scheme,
            pubkey,
            signature_bytes,
            *salt,
            chain_id,
        );
        Self {
            from,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            signature: envelope.encode(),
            payload,
            priority_fee_per_gas: 0,
        }
    }

    #[allow(clippy::too_many_arguments)]
    // GATE: mirrors the node's constructor signature field-for-field.
    pub fn new_pq_implicit_with_chain(
        from: [u8; 32],
        scheme: PqScheme,
        signature_bytes: Vec<u8>,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        payload: Vec<u8>,
        chain_id: u64,
    ) -> Self {
        let envelope =
            PqSignatureEnvelope::new_implicit_with_chain(scheme, signature_bytes, chain_id);
        Self {
            from,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            signature: envelope.encode(),
            payload,
            priority_fee_per_gas: 0,
        }
    }

    fn base_signing_message(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(115);
        msg.extend_from_slice(&self.from);
        msg.extend_from_slice(&self.to);
        msg.extend_from_slice(&self.amount.to_be_bytes());
        msg.extend_from_slice(&self.gas_limit.to_be_bytes());
        msg.extend_from_slice(&self.nonce.to_be_bytes());
        msg.extend_from_slice(&self.source_shard.to_be_bytes());
        msg.extend_from_slice(&self.target_shard.to_be_bytes());
        self.append_payload_commitment(&mut msg);
        if self.priority_fee_per_gas != 0 {
            msg.extend_from_slice(PRIORITY_FEE_COMMITMENT_TAG);
            msg.extend_from_slice(&self.priority_fee_per_gas.to_be_bytes());
        }
        msg
    }

    fn append_payload_commitment(&self, msg: &mut Vec<u8>) {
        msg.extend_from_slice(b"PAYLOAD");
        match bincode::serialize(&self.payload) {
            Ok(bytes) => {
                msg.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                msg.extend_from_slice(&bytes);
            }
            Err(_) => msg.extend_from_slice(&u32::MAX.to_be_bytes()),
        }
    }

    fn append_chain_id_commitment(msg: &mut Vec<u8>, chain_id: u64) {
        msg.extend_from_slice(CHAIN_ID_COMMITMENT_TAG);
        msg.extend_from_slice(&chain_id.to_be_bytes());
    }

    /// The exact bytes signed for a chain-bound transaction. The online
    /// constructor signs `signing_message_for_chain(chain_id)`; verification
    /// uses the chain id carried INSIDE the envelope.
    pub fn signing_message_for_chain(&self, chain_id: u64) -> Vec<u8> {
        self.signing_message_for_optional_chain(Some(chain_id))
    }

    fn signing_message_for_optional_chain(&self, chain_id: Option<u64>) -> Vec<u8> {
        let mut msg = self.base_signing_message();
        if let Some(cid) = chain_id {
            Self::append_chain_id_commitment(&mut msg, cid);
        }
        msg
    }

    pub fn is_pq(&self) -> bool {
        self.signature.starts_with(PQ_ENVELOPE_MAGIC)
    }

    pub fn pq_envelope(&self) -> Option<PqSignatureEnvelope> {
        if !self.is_pq() {
            return None;
        }
        let env = PqSignatureEnvelope::decode(&self.signature).ok()?;
        if env.encoded_len() != self.signature.len()
            && env.legacy_encode_len() != self.signature.len()
        {
            return None;
        }
        Some(env)
    }

    pub fn is_pq_activation(&self) -> bool {
        self.pq_envelope()
            .map(|e| !e.is_implicit && e.pubkey.is_some())
            .unwrap_or(false)
    }

    pub fn is_pq_implicit(&self) -> bool {
        self.pq_envelope()
            .map(|e| e.is_implicit || e.pubkey.is_none())
            .unwrap_or(false)
    }

    pub fn chain_id(&self) -> Option<u64> {
        self.pq_envelope().and_then(|e| e.chain_id)
    }

    pub fn compute_tx_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.from);
        hasher.update(self.to);
        hasher.update(self.amount.to_be_bytes());
        hasher.update(self.gas_limit.to_be_bytes());
        hasher.update(self.nonce.to_be_bytes());
        hasher.update(self.source_shard.to_be_bytes());
        hasher.update(self.target_shard.to_be_bytes());
        hasher.update(b"PAYLOAD");
        match bincode::serialize(&self.payload) {
            Ok(bytes) => {
                hasher.update((bytes.len() as u32).to_be_bytes());
                hasher.update(&bytes);
            }
            Err(_) => hasher.update(u32::MAX.to_be_bytes()),
        }
        if self.priority_fee_per_gas != 0 {
            hasher.update(PRIORITY_FEE_COMMITMENT_TAG);
            hasher.update(self.priority_fee_per_gas.to_be_bytes());
        }
        if self.is_pq() {
            hasher.update(b"PQ_ENV");
            hasher.update(&self.signature);
        }
        hasher.finalize().into()
    }

    pub fn verify_signature(&self) -> bool {
        self.verify_signature_with_registry(crate::envelope::global_implicit_key_registry())
    }

    /// The PQ branch of `Transaction::verify_inner_with_registry`, restricted
    /// to this harness's empty-payload, non-sponsored, non-EVM transactions.
    pub fn verify_signature_with_registry(&self, registry: &StatefulImplicitKeyRegistry) -> bool {
        let Some(env) = self.pq_envelope() else {
            return false;
        };
        if !env.scheme.is_post_quantum() {
            return false;
        }
        if env.signature_bytes.len() != env.scheme.signature_size() {
            return false;
        }
        let msg = self.signing_message_for_optional_chain(env.chain_id);
        if env.is_implicit {
            if env.pubkey.is_some() {
                return false;
            }
            let Some((scheme, pk)) = registry.lookup(&self.from) else {
                return false;
            };
            if scheme != env.scheme {
                return false;
            }
            verify_pq_signature(scheme, &pk, &msg, &env.signature_bytes)
        } else {
            let Some(pk) = env.pubkey.as_ref() else {
                return false;
            };
            if pk.len() != env.scheme.pubkey_size() {
                return false;
            }
            let derived = derive_pq_address(env.scheme, pk, &env.salt);
            if derived != self.from {
                return false;
            }
            if !verify_pq_signature(env.scheme, pk, &msg, &env.signature_bytes) {
                return false;
            }
            let _ = registry.register(self.from, env.scheme, pk, &env.salt);
            true
        }
    }
}

/// Encode with the node's exact bincode configuration and refuse payloads the
/// harness cannot represent on the node wire.
pub fn encode_wire(tx: &Transaction) -> Result<Vec<u8>, String> {
    use bincode::Options;
    if !tx.is_pq() {
        return Err("encode_wire: refusing a non-PQ transaction".to_string());
    }
    if !tx.is_pq_activation() && !tx.is_pq_implicit() {
        return Err("encode_wire: refusing a transaction with no PQ1 envelope".to_string());
    }
    if tx.chain_id().is_none() {
        return Err(
            "encode_wire: refusing an unbound transaction (the node's chain-binding gate \
             expects a chain id in the envelope)"
                .to_string(),
        );
    }
    if !tx.payload.is_empty() {
        return Err(
            "encode_wire: this harness only submits empty-payload transfers; \
             a non-empty payload would need the node's Vec<OpCode> encoding"
                .to_string(),
        );
    }
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .serialize(tx)
        .map_err(|e| format!("bincode encode: {e}"))
}

/// The node's `network::decode_wire_limited` configuration, verbatim.
pub fn decode_wire(bytes: &[u8]) -> Result<Transaction, String> {
    use bincode::Options;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_WIRE_BYTES as u64)
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|e| format!("wire decode: {e}"))
}

pub fn tx_hash_hex(tx: &Transaction) -> String {
    hex::encode(tx.compute_tx_hash())
}

pub fn wire_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::post_quantum::{FalconKeypair, DEFAULT_SALT};

    fn keypair(seed: u8) -> (FalconKeypair, [u8; 32], Vec<u8>) {
        let kp = FalconKeypair::generate_from_seed(seed);
        let pk = kp.public_key().to_vec();
        let addr = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);
        (kp, addr, pk)
    }

    fn draft(from: [u8; 32], nonce: u64) -> Transaction {
        Transaction {
            from,
            to: [0x11; 32],
            amount: 1,
            gas_limit: 326_000,
            nonce,
            source_shard: 0,
            target_shard: 0,
            signature: Vec::new(),
            payload: Vec::new(),
            priority_fee_per_gas: 0,
        }
    }

    #[test]
    fn explicit_wire_is_byte_exact_and_roundtrips() {
        let (kp, addr, pk) = keypair(7);
        let d = draft(addr, 9);
        let msg = d.signing_message_for_chain(5757);
        let sig = kp.sign(&msg);
        let tx = Transaction::new_pq_explicit_with_chain(
            PqScheme::Falcon512,
            pk,
            sig,
            d.to,
            d.amount,
            d.gas_limit,
            d.nonce,
            0,
            0,
            Vec::new(),
            &DEFAULT_SALT,
            5757,
        );
        assert!(tx.is_pq_activation());
        assert_eq!(tx.chain_id(), Some(5757));
        assert!(tx.verify_signature());
        let wire = encode_wire(&tx).unwrap();
        // 32+32+8+8+8+4+4 + (8+1596 envelope) + 8 payload length
        assert_eq!(wire.len(), 1_708);
        let decoded = decode_wire(&wire).unwrap();
        assert_eq!(decoded.from, tx.from);
        assert_eq!(decoded.nonce, 9);
        assert_eq!(decoded.chain_id(), Some(5757));
        assert_eq!(decoded.compute_tx_hash(), tx.compute_tx_hash());
        assert!(decoded.verify_signature());
        assert!(decode_wire(&[&wire[..], b"x"].concat()).is_err());
    }

    #[test]
    fn implicit_wire_roundtrips_and_verifies_against_registry() {
        let (kp, addr, pk) = keypair(8);
        let d = draft(addr, 1);
        let msg = d.signing_message_for_chain(5757);
        let sig = kp.sign(&msg);
        let tx = Transaction::new_pq_implicit_with_chain(
            addr,
            PqScheme::Falcon512,
            sig,
            d.to,
            d.amount,
            d.gas_limit,
            1,
            0,
            0,
            Vec::new(),
            5757,
        );
        assert!(tx.is_pq_implicit());
        assert!(!tx.is_pq_activation());
        let reg = StatefulImplicitKeyRegistry::new();
        reg.register(addr, PqScheme::Falcon512, &pk, &DEFAULT_SALT)
            .unwrap();
        assert!(tx.verify_signature_with_registry(&reg));
        let wire = encode_wire(&tx).unwrap();
        // 100 fixed + (8 + 683 envelope) + 8 payload length
        assert_eq!(wire.len(), 795);
        let decoded = decode_wire(&wire).unwrap();
        assert!(decoded.verify_signature_with_registry(&reg));
        assert_eq!(decoded.compute_tx_hash(), tx.compute_tx_hash());
    }

    #[test]
    fn chain_id_is_inside_the_signature_and_message() {
        let (kp, addr, _pk) = keypair(9);
        let d = draft(addr, 3);
        let m1 = d.signing_message_for_chain(5757);
        let m2 = d.signing_message_for_chain(5758);
        assert_ne!(m1, m2);
        let sig = kp.sign(&m1);
        let tx = Transaction::new_pq_explicit_with_chain(
            PqScheme::Falcon512,
            kp.public_key().to_vec(),
            sig,
            d.to,
            d.amount,
            d.gas_limit,
            d.nonce,
            0,
            0,
            Vec::new(),
            &DEFAULT_SALT,
            5757,
        );
        assert!(tx.verify_signature());
        let env = tx.pq_envelope().unwrap();
        assert_eq!(env.chain_id, Some(5757));
    }

    #[test]
    fn nonce_changes_message_and_hash() {
        let (kp, addr, pk) = keypair(10);
        let mut hashes = std::collections::BTreeSet::new();
        for nonce in 0..4 {
            let d = draft(addr, nonce);
            let msg = d.signing_message_for_chain(5757);
            let sig = kp.sign(&msg);
            let tx = Transaction::new_pq_explicit_with_chain(
                PqScheme::Falcon512,
                pk.clone(),
                sig,
                d.to,
                d.amount,
                d.gas_limit,
                nonce,
                0,
                0,
                Vec::new(),
                &DEFAULT_SALT,
                5757,
            );
            assert!(hashes.insert(tx.compute_tx_hash()));
        }
    }

    #[test]
    fn signing_preimage_layout_is_pinned() {
        let (_kp, addr, _pk) = keypair(12);
        let tx = draft(addr, 7);
        let msg = tx.signing_message_for_chain(5757);
        // from(32)+to(32)+amount(8)+gas(8)+nonce(8)+src(4)+tgt(4)
        // + "PAYLOAD"(7)+len(4)+empty Vec(8) + "CHAIN_ID"(8)+chain(8)
        assert_eq!(msg.len(), 131);
        assert_eq!(&msg[0..32], &addr[..]);
        assert_eq!(&msg[32..64], &[0x11u8; 32][..]);
        assert_eq!(&msg[64..72], &1u64.to_be_bytes());
        assert_eq!(&msg[72..80], &326_000u64.to_be_bytes());
        assert_eq!(&msg[80..88], &7u64.to_be_bytes());
        assert_eq!(&msg[88..92], &0u32.to_be_bytes());
        assert_eq!(&msg[92..96], &0u32.to_be_bytes());
        assert_eq!(&msg[96..103], b"PAYLOAD");
        assert_eq!(&msg[103..107], &8u32.to_be_bytes());
        assert_eq!(&msg[107..115], &[0u8; 8][..]);
        assert_eq!(&msg[115..123], b"CHAIN_ID");
        assert_eq!(&msg[123..131], &5757u64.to_be_bytes());
    }

    #[test]
    fn non_empty_payload_is_refused_by_the_encoder() {
        let (kp, addr, pk) = keypair(11);
        let d = draft(addr, 0);
        let sig = kp.sign(&d.signing_message_for_chain(5757));
        let mut tx = Transaction::new_pq_explicit_with_chain(
            PqScheme::Falcon512,
            pk,
            sig,
            d.to,
            d.amount,
            d.gas_limit,
            0,
            0,
            0,
            Vec::new(),
            &DEFAULT_SALT,
            5757,
        );
        tx.payload = vec![1, 2, 3];
        assert!(encode_wire(&tx).is_err());
    }
}
