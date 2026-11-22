use super::envelope::{
    global_implicit_key_registry, PqSignatureEnvelope, CHAIN_ID_COMMITMENT_TAG, CHAIN_SIG_TAG,
    EVM_CHAIN_ID, EVM_SIG_TAG, MAX_EVM_ENVELOPE_BYTES, SESSION_FALCON_SIG_TAG, SESSION_SIG_TAG,
    SPONSOR_AUTH_MAX_BYTES, SPONSOR_COMMITMENT_TAG, SPONSOR_FEE_DOMAIN, SPONSOR_MAX_TARGETS,
    SPONSOR_SIG_TAG,
};
use super::topology::ShardId;
use super::{SessionPolicyError, SponsorAuthorization, SponsorPolicyError};
use crate::post_quantum::{
    derive_pq_address, verify_pq_signature, FalconKeypair, PqScheme, StatefulImplicitKeyRegistry,
    DEFAULT_SALT, ED25519_SIG_LEN, FALCON512_SIG_LEN, PQ_ENVELOPE_MAGIC,
};
use crate::zkml::SessionKeyAuthorization;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain separator for the explicit mempool priority bid inside the signed
/// message and the transaction hash.
///
/// VERSIONING: the commitment is mixed in ONLY when the bid is non-zero, so a
/// legacy transaction (no bid) keeps byte-identical bytes, signatures, hashes
/// and block hashes. The tag keeps the commitment from ever colliding with
/// another part of the preimage.
pub const PRIORITY_FEE_COMMITMENT_TAG: &[u8; 8] = b"PRIORITY";

/// Wire form of a transaction: the EXACT byte layout of the legacy
/// transaction, so a legacy transaction's bytes are unchanged, with the
/// explicit priority bid carried INSIDE the (length-prefixed) signature blob.
///
/// WHY NOT A PLAIN STRUCT FIELD: bincode is POSITIONAL. A new fixed-size
/// field appended to `Transaction` would be read from the bytes that FOLLOW
/// the transaction in its container — a block's next field, the next
/// transaction in the vector — so every container that holds a transaction
/// (every block, every gossip batch, the chain's own persisted history)
/// would mis-parse, and a legacy transaction could no longer be decoded at
/// all. The signature blob is length-prefixed, so a suffix inside it is
/// SELF-DELIMITING: a legacy transaction's bytes are byte-identical, a
/// transaction with a bid simply carries a longer signature blob, and every
/// container still decodes exactly as before.
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
    /// Optional SVM program (micro-gas ops) executed against the sender's account
    /// during block application. Empty = a plain value transfer.
    #[serde(default)]
    payload: Vec<crate::svm::OpCode>,
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
    /// The signature blob WITHOUT the trailing priority envelope (the
    /// envelope is split off at decode time and lives in
    /// `priority_fee_per_gas`).
    pub signature: Vec<u8>,
    /// Optional SVM program (micro-gas ops) executed against the sender's account
    /// during block application. Empty = a plain value transfer.
    pub payload: Vec<crate::svm::OpCode>,
    /// EXPLICIT MEMPOOL PRIORITY BID (audit: priority inversion).
    ///
    /// `gas_limit` is a RESOURCE CAP (it bounds the work a transaction may
    /// do) that historically doubled as the price, so a transaction that
    /// simply declared a huge `gas_limit` took the top of the mempool without
    /// paying any extra: a cap was silently acting as a price. This field is
    /// the EXPLICIT price. The mempool orders by it FIRST (see
    /// `crate::mempool::Mempool`), and admission refuses a bid the sender has
    /// not funded — the bid must be covered by `gas_limit`, so priority is
    /// never free (see `Mempool::required_fee_for_tx`).
    ///
    /// DEFAULT 0 = LEGACY BEHAVIOUR: the bid is mixed into the signed message
    /// and the transaction hash ONLY when it is non-zero, so every legacy
    /// transaction keeps byte-identical bytes, signatures, hashes and block
    /// hashes.
    ///
    /// ON THE WIRE it travels as a trailing envelope INSIDE the signature
    /// blob (see [`TransactionWire`]), never as a separate struct field.
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
            signature: Transaction::encode_priority_envelope(
                &self.signature,
                self.priority_fee_per_gas,
            ),
            payload: self.payload.clone(),
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for Transaction {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let wire = TransactionWire::deserialize(d)?;
        let (signature, priority_fee_per_gas) =
            Transaction::split_priority_envelope(&wire.signature);
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
    /// Length of the trailing priority envelope: an 8-byte tag plus the
    /// big-endian bid.
    const PRIORITY_ENVELOPE_LEN: usize = 16;

    /// Split the trailing priority envelope off a signature blob.
    ///
    /// Returns `(body, bid)`. A blob that does not end with the envelope tag
    /// is a legacy signature: it is returned unchanged with a bid of 0. The
    /// tag is 8 bytes, so a legacy blob that coincidentally ends with it is
    /// 2^-64 unlikely — and it fails closed anyway (the shortened body no
    /// longer verifies).
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

    /// Append the priority envelope to a signature blob (a no-op for a bid of
    /// 0, which keeps a legacy transaction's bytes byte-identical).
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

    pub fn sign(
        from_key: &SigningKey,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
    ) -> Self {
        Self::sign_with_payload(
            from_key,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            Vec::new(),
        )
    }

    /// Sign a transaction that carries an EXPLICIT MEMPOOL PRIORITY BID.
    ///
    /// The bid is the price the mempool orders by FIRST (audit: priority
    /// inversion — `gas_limit` is a resource cap, not a price). It is signed
    /// with the rest of the transaction, so it cannot be inflated by anyone
    /// but the sender, and admission requires the bid to be FUNDED (the
    /// declared `gas_limit` must cover `floor + bid`), so priority is never
    /// free. A bid of 0 is exactly the legacy behaviour (byte-identical
    /// signing bytes and transaction hash).
    #[allow(clippy::too_many_arguments)]
    pub fn sign_with_priority(
        from_key: &SigningKey,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        priority_fee_per_gas: u64,
    ) -> Self {
        Self::sign_with_payload_and_priority(
            from_key,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            Vec::new(),
            priority_fee_per_gas,
        )
    }

    /// Sign a transaction carrying an SVM payload (contract call / token syscalls /
    /// orderbook ops). The payload is committed into the signature, so a payload
    /// cannot be swapped after signing.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_with_payload(
        from_key: &SigningKey,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        payload: Vec<crate::svm::OpCode>,
    ) -> Self {
        Self::sign_with_payload_and_priority(
            from_key,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            payload,
            0,
        )
    }

    /// Sign a transaction carrying an SVM payload AND an explicit mempool
    /// priority bid. See [`Transaction::sign_with_priority`] for the bid's
    /// semantics.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_with_payload_and_priority(
        from_key: &SigningKey,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        payload: Vec<crate::svm::OpCode>,
        priority_fee_per_gas: u64,
    ) -> Self {
        let from_pub = from_key.verifying_key().to_bytes();
        let msg = Self::base_signing_message(
            &from_pub,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            &payload,
            priority_fee_per_gas,
        );

        let sig = from_key.sign(&msg);

        Self {
            from: from_pub,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            signature: sig.to_vec(),
            payload,
            priority_fee_per_gas,
        }
    }

    /// Sign a transaction bound to a specific chain_id (Finding F1: anti cross-chain replay).
    #[allow(clippy::too_many_arguments)]
    // GATE: signing needs full tx context; struct params would change public API.
    pub fn sign_with_chain_id(
        from_key: &SigningKey,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        chain_id: u64,
    ) -> Self {
        Self::sign_with_payload_and_chain_id(
            from_key,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            Vec::new(),
            chain_id,
        )
    }

    /// Sign a transaction carrying an SVM payload and bound to a specific chain_id.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_with_payload_and_chain_id(
        from_key: &SigningKey,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        payload: Vec<crate::svm::OpCode>,
        chain_id: u64,
    ) -> Self {
        let from_pub = from_key.verifying_key().to_bytes();
        let mut msg = Self::base_signing_message(
            &from_pub,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            &payload,
            0,
        );
        Self::append_chain_id_commitment(&mut msg, chain_id);

        let sig = from_key.sign(&msg);
        let mut signature = sig.to_vec();
        signature.extend_from_slice(CHAIN_SIG_TAG);
        signature.extend_from_slice(&chain_id.to_be_bytes());

        Self {
            from: from_pub,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            signature,
            payload,
            priority_fee_per_gas: 0,
        }
    }

    /// Sign a transaction with a DELEGATED session key instead of the master
    /// key. The master's grant rides inside `signature` as an envelope:
    /// `session_sig(64B) || b"SK1" || bincode(grant)`.
    ///
    /// `tx.from` stays the master address (the master's account is the one
    /// debited), and both the grant and the payload are committed into what
    /// the session key signs, so neither can be swapped after signing: grafting
    /// this envelope onto another sender's transaction, or grafting another
    /// grant onto this one, invalidates the signature.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_with_session(
        session_key: &SigningKey,
        delegation: SessionKeyAuthorization,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        payload: Vec<crate::svm::OpCode>,
    ) -> Self {
        // The grant must have been minted FOR this session key: verification
        // selects the verifying key from `delegation.session_pubkey`, so a
        // mismatch could only ever produce a transaction nobody can verify.
        debug_assert_eq!(
            session_key.verifying_key().to_bytes(),
            delegation.session_pubkey,
            "session key must match the delegation it is used with"
        );
        let from_pub = delegation.master_address;
        let mut msg = Self::base_signing_message(
            &from_pub,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            &payload,
            0,
        );
        Self::append_delegation_commitment(&mut msg, &delegation);

        let sig = session_key.sign(&msg);
        let mut signature = sig.to_vec();
        signature.extend_from_slice(SESSION_SIG_TAG);
        // Serialization of this struct cannot realistically fail (fixed-size
        // fields plus one Vec). If it somehow did, the envelope would not
        // parse and the transaction fails closed at verification.
        signature.extend_from_slice(&bincode::serialize(&delegation).unwrap_or_default());

        Self {
            from: from_pub,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            signature,
            payload,
            priority_fee_per_gas: 0,
        }
    }

    /// Sign a transaction with a Falcon-512 DELEGATED session key: the PQ
    /// mirror of [`Self::sign_with_session`] with IDENTICAL semantics — only
    /// the signature scheme changes.
    ///
    /// Envelope: `Falcon-512 session sig (666B)` ++ `b"SF1"` ++
    /// `bincode(SessionKeyAuthorization)` (see [`SESSION_FALCON_SIG_TAG`]).
    /// `tx.from` stays the master address, and both the grant and the payload
    /// are committed into what the session key signs
    /// (`base_signing_message` + `delegation commitment`), so neither can be
    /// swapped after signing — exactly like the `SK1` envelope.
    ///
    /// The grant MUST already be Falcon-delegated
    /// ([`SessionKeyAuthorization::sign_delegation_falcon512`], both schemes
    /// post-quantum): an Ed grant, or a session key that does not match the
    /// grant's registered Falcon session pubkey, can only ever produce a
    /// transaction the verifier refuses.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_with_session_falcon512(
        session_key: &FalconKeypair,
        delegation: SessionKeyAuthorization,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        payload: Vec<crate::svm::OpCode>,
    ) -> Self {
        // The grant must have been minted FOR this session key: verification
        // selects the session public key from the grant's
        // `session_pubkey_bytes`, so a mismatch could only ever produce a
        // transaction nobody can verify.
        debug_assert_eq!(
            delegation.session_pubkey_bytes.as_deref(),
            Some(session_key.public_key()),
            "session key must match the delegation it is used with"
        );
        let from_pub = delegation.master_address;
        let mut msg = Self::base_signing_message(
            &from_pub,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            &payload,
            0,
        );
        Self::append_delegation_commitment(&mut msg, &delegation);

        let sig = session_key.sign(&msg);
        debug_assert_eq!(
            sig.len(),
            FALCON512_SIG_LEN,
            "Falcon-512 session signature must be {FALCON512_SIG_LEN} bytes"
        );
        let mut signature = sig;
        signature.extend_from_slice(SESSION_FALCON_SIG_TAG);
        // Serialization of this struct cannot realistically fail (fixed-size
        // fields plus a few Vecs). If it somehow did, the envelope would not
        // parse and the transaction fails closed at verification.
        signature.extend_from_slice(&bincode::serialize(&delegation).unwrap_or_default());

        Self {
            from: from_pub,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            signature,
            payload,
            priority_fee_per_gas: 0,
        }
    }

    /// The signed message WITHOUT the delegation commitment: every legacy
    /// transaction's exact signing bytes, kept byte-identical so old
    /// signatures, old hashes and the python client's layout still hold.
    ///
    /// The explicit priority bid is part of this base preimage, but only when
    /// it is non-zero: a legacy transaction (no bid) signs exactly the bytes
    /// it always signed, while a bid is BOUND to the sender's signature (a
    /// third party cannot inflate someone else's priority bid).
    #[allow(clippy::too_many_arguments)]
    // GATE: signing preimage needs full tx fields; splitting risks hash mismatch.
    fn base_signing_message(
        from: &[u8; 32],
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        payload: &[crate::svm::OpCode],
        priority_fee_per_gas: u64,
    ) -> Vec<u8> {
        let mut msg = Vec::with_capacity(115);
        msg.extend_from_slice(from);
        msg.extend_from_slice(&to);
        msg.extend_from_slice(&amount.to_be_bytes());
        msg.extend_from_slice(&gas_limit.to_be_bytes());
        msg.extend_from_slice(&nonce.to_be_bytes());
        msg.extend_from_slice(&source_shard.to_be_bytes());
        msg.extend_from_slice(&target_shard.to_be_bytes());
        Self::append_payload_commitment(&mut msg, payload);
        Self::append_priority_commitment(&mut msg, priority_fee_per_gas);
        msg
    }

    /// Commitment of the explicit priority bid, bound into BOTH the signed
    /// message and the tx hash. Nothing is appended for a bid of 0, which is
    /// what keeps every pre-bid transaction byte-identical.
    fn append_priority_commitment(msg: &mut Vec<u8>, priority_fee_per_gas: u64) {
        if priority_fee_per_gas == 0 {
            return;
        }
        msg.extend_from_slice(PRIORITY_FEE_COMMITMENT_TAG);
        msg.extend_from_slice(&priority_fee_per_gas.to_be_bytes());
    }

    /// Deterministic commitment of the payload bound into the signed message.
    fn append_payload_commitment(msg: &mut Vec<u8>, payload: &[crate::svm::OpCode]) {
        msg.extend_from_slice(b"PAYLOAD");
        match bincode::serialize(payload) {
            Ok(bytes) => {
                msg.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                msg.extend_from_slice(&bytes);
            }
            Err(_) => {
                // Unserializable payload -> bind an impossible marker so the
                // signature can never validate (fail closed).
                msg.extend_from_slice(&u32::MAX.to_be_bytes());
            }
        }
    }

    /// Parse the master's grant out of the signature envelope, if this
    /// transaction carries one. `None` for a legacy signature — and for any
    /// blob that does not parse as an exact-fit envelope, which then fails
    /// `Signature::from_slice` (wrong length), so malformed input fails closed.
    ///
    /// Two framings, same rules (see [`SESSION_SIG_TAG`] /
    /// [`SESSION_FALCON_SIG_TAG`]): the Falcon (`SF1`, 666-byte leading
    /// signature) framing is tried first, then the legacy Ed (`SK1`, 64-byte)
    /// framing. A blob can satisfy at most one exact-fit framing (the offsets
    /// and lengths differ), so the order is only a tie-break for
    /// non-parsing blobs, never a semantic choice.
    fn delegation_from_inner(sig: &[u8]) -> Option<(SessionKeyAuthorization, &[u8])> {
        for (sig_len, tag) in [
            (FALCON512_SIG_LEN, SESSION_FALCON_SIG_TAG),
            (ED25519_SIG_LEN, SESSION_SIG_TAG),
        ] {
            let tag_len = tag.len();
            if sig.len() <= sig_len + tag_len || sig[sig_len..sig_len + tag_len] != tag[..] {
                continue;
            }
            let grant: SessionKeyAuthorization =
                bincode::deserialize(&sig[sig_len + tag_len..]).ok()?;
            // Exact fit: the envelope is exactly `sig || tag || grant`, with
            // no trailing junk — otherwise one transaction could carry two
            // byte encodings under a single hash.
            let expected = sig_len + tag_len + bincode::serialized_size(&grant).ok()? as usize;
            if expected != sig.len() {
                return None;
            }
            return Some((grant, &sig[..sig_len]));
        }
        None
    }

    pub fn delegation(&self) -> Option<SessionKeyAuthorization> {
        Self::delegation_from_inner(self.sponsor_inner_sig()).map(|(grant, _)| grant)
    }

    /// True when this transaction carries a session-key envelope.
    pub fn is_session_keyed(&self) -> bool {
        self.delegation().is_some()
    }

    /// Commitment of the grant, bound into BOTH the signed message and the tx
    /// hash. Empty for legacy transactions (`delegation()` is `None`), which is
    /// what keeps every pre-envelope byte string — tx bytes, tx hashes, block
    /// hashes — unchanged.
    fn delegation_commitment_bytes(delegation: &SessionKeyAuthorization) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"SESSION");
        match bincode::serialize(delegation) {
            Ok(bytes) => {
                out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                out.extend_from_slice(&bytes);
            }
            Err(_) => out.extend_from_slice(&u32::MAX.to_be_bytes()),
        }
        out
    }

    fn append_delegation_commitment(msg: &mut Vec<u8>, delegation: &SessionKeyAuthorization) {
        msg.extend_from_slice(&Self::delegation_commitment_bytes(delegation));
    }

    /// Append chain_id commitment to signing message (Finding F1).
    fn append_chain_id_commitment(msg: &mut Vec<u8>, chain_id: u64) {
        msg.extend_from_slice(CHAIN_ID_COMMITMENT_TAG);
        msg.extend_from_slice(&chain_id.to_be_bytes());
    }

    /// True if transaction carries an Ed25519 chain_id envelope (CH1).
    pub fn is_chain_id_bound(&self) -> bool {
        Self::chain_id_from_inner(self.sponsor_inner_sig()).is_some()
    }

    fn chain_id_from_inner(inner_sig: &[u8]) -> Option<u64> {
        let tag_len = CHAIN_SIG_TAG.len();
        if inner_sig.len() == 64 + tag_len + 8 && inner_sig[64..64 + tag_len] == CHAIN_SIG_TAG[..] {
            let offset = 64 + tag_len;
            let bytes: [u8; 8] = inner_sig[offset..offset + 8].try_into().ok()?;
            Some(u64::from_be_bytes(bytes))
        } else {
            None
        }
    }

    /// Extract chain_id from CH1 envelope if present.
    pub fn chain_id_from_envelope(&self) -> Option<u64> {
        Self::chain_id_from_inner(self.sponsor_inner_sig())
    }

    fn is_evm_inner(inner_sig: &[u8]) -> bool {
        inner_sig.len() > EVM_SIG_TAG.len() && inner_sig[..EVM_SIG_TAG.len()] == EVM_SIG_TAG[..]
    }

    /// True when this transaction carries a Phase-2 EVM (secp256k1)
    /// settlement envelope (`b"EV1"` prefix). Never 64 bytes long, so every
    /// pre-EV1 verifier fails it closed at `Signature::from_slice`.
    pub fn is_evm(&self) -> bool {
        Self::is_evm_inner(self.sponsor_inner_sig())
    }

    /// Raw canonical EVM bytes carried by the envelope (`None` for non-EVM
    /// transactions).
    pub fn evm_raw(&self) -> Option<&[u8]> {
        let inner = self.sponsor_inner_sig();
        if !Self::is_evm_inner(inner) {
            return None;
        }
        Some(&inner[EVM_SIG_TAG.len()..])
    }

    /// Decode the EVM envelope into its separate-enum view
    /// ([`crate::evm_adapter::DecodedTransaction`], legacy or EIP-1559).
    /// Fail-closed: oversized envelopes and any RLP parse error yield `None`.
    pub fn evm_decoded(&self) -> Option<crate::evm_adapter::DecodedTransaction> {
        let raw = self.evm_raw()?;
        if raw.is_empty() || raw.len() > MAX_EVM_ENVELOPE_BYTES {
            return None;
        }
        crate::evm_adapter::parse_raw_transaction(raw).ok()
    }

    /// Assemble a Phase-2 EVM settlement transaction. `raw_evm_tx` must be
    /// the canonical EVM wire bytes; every consensus check re-derives from
    /// them, so any mismatch with the mapped fields fails closed in
    /// [`Self::verify_evm_signature`]. The SVM payload stays empty: Phase-2
    /// settles value movement, calldata is not executed.
    #[allow(clippy::too_many_arguments)]
    // GATE: EVM constructor mirrors full tx fields; struct params would change public API.
    pub fn new_evm(
        from: [u8; 32],
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        raw_evm_tx: Vec<u8>,
    ) -> Self {
        let mut signature = Vec::with_capacity(EVM_SIG_TAG.len() + raw_evm_tx.len());
        signature.extend_from_slice(EVM_SIG_TAG);
        signature.extend_from_slice(&raw_evm_tx);
        Self {
            from,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            signature,
            payload: Vec::new(),
            priority_fee_per_gas: 0,
        }
    }

    /// Phase-2 EVM (secp256k1) envelope verification.
    ///
    /// Re-derives EVERYTHING from the canonical raw bytes in the envelope, so
    /// block data alone decides — no RPC trust, no wall clock, no state:
    ///
    /// * the raw parses as legacy-EIP-155 or EIP-1559 type-2 AND re-encodes
    ///   byte-exact (non-canonical RLP / trailing junk fails closed);
    /// * [`crate::evm_adapter::DecodedTransaction::verify_signature`] passes —
    ///   strict `chain_id == 5757` (EIP-155 replay protection required, never
    ///   `v = 27/28`), EIP-2 low-s, secp256k1 ecrecover;
    /// * contract creation (`to == None`) is rejected — Phase-2 settles value
    ///   transfers and there is no Stell recipient to invent for a deployment;
    /// * `tx.from` equals `evm_to_stell_address(recovered)`: the mapping the
    ///   mempool nonce/balance checks and the engine apply path then use;
    /// * `tx.nonce` / `gas_limit` / `amount` / `to` equal the mapped EVM
    ///   fields (`amount = wei_to_nano(value)`, sub-nano wei truncated
    ///   deterministically; `gas_limit` is carried verbatim as the nano fee
    ///   so consensus verification stays a pure function of the tx bytes).
    pub fn verify_evm_signature(&self) -> bool {
        // Legacy entry point: the pre-activation (truncating) sub-nano policy,
        // byte-identical to the historical behaviour. Consensus callers that
        // KNOW the block height use `verify_evm_signature_at_height`.
        self.verify_evm_signature_at(false)
    }

    /// Height-aware [`Self::verify_evm_signature`]: once
    /// `SUB_NANO_STRICT_ACTIVATION_HEIGHT` is reached a Wei value that is not a
    /// whole nano-STELL is refused (`wei_to_nano_exact`), instead of being
    /// silently truncated. Below the gate the legacy truncation is preserved so
    /// historical blocks re-apply deterministically.
    pub fn verify_evm_signature_at_height(&self, height: u64) -> bool {
        self.verify_evm_signature_at(crate::tokenomics::sub_nano_strict_active_at(height))
    }

    fn verify_evm_signature_at(&self, strict_sub_nano: bool) -> bool {
        let Some(raw) = self.evm_raw() else {
            return false;
        };
        if raw.is_empty() || raw.len() > MAX_EVM_ENVELOPE_BYTES {
            return false;
        }
        let Ok(decoded) = crate::evm_adapter::parse_raw_transaction(raw) else {
            return false;
        };
        // Exact-fit: the envelope commits to canonical bytes only.
        if decoded.encode() != raw {
            return false;
        }
        // Strict chain_id == 5757 + low-s + ecrecover (enforced inside for
        // both the legacy and the EIP-1559 variant).
        let Ok(evm_from) = decoded.verify_signature() else {
            return false;
        };
        // No recipient to map for a deployment — fail closed, don't invent one.
        let Some(evm_to) = decoded.to() else {
            return false;
        };
        if crate::evm_adapter::evm_to_stell_address(&evm_from) != self.from {
            return false;
        }
        if crate::evm_adapter::evm_to_stell_address(&evm_to) != self.to {
            return false;
        }
        if decoded.nonce() != self.nonce {
            return false;
        }
        if decoded.gas_limit() != self.gas_limit {
            return false;
        }
        if strict_sub_nano {
            // No silent truncation: a 1.5-nano intent is refused outright.
            match crate::evm_adapter::wei_to_nano_exact(decoded.value()) {
                Ok(nano) if nano == self.amount => {}
                _ => return false,
            }
        } else if crate::evm_adapter::wei_to_nano(decoded.value()) != self.amount {
            return false;
        }
        // EVM-settled transactions carry no SVM payload (no mixed execution
        // model under one signature).
        if !self.payload.is_empty() {
            return false;
        }
        true
    }

    fn chain_id_from_parsed_inner(inner_sig: &[u8]) -> Option<u64> {
        if let Some((d, _)) = Self::delegation_from_inner(inner_sig) {
            Some(d.chain_id)
        } else if let Some(cid) = Self::chain_id_from_inner(inner_sig) {
            Some(cid)
        } else if let Some(env) = Self::pq_envelope_from_inner(inner_sig) {
            env.chain_id
        } else if Self::is_evm_inner(inner_sig) {
            Some(EVM_CHAIN_ID)
        } else {
            None
        }
    }

    /// Returns the chain_id bound to this transaction, if any.
    ///
    /// - For session key transactions: returns `delegation.chain_id`.
    /// - For chain-bound Ed25519 transactions: returns envelope `chain_id`.
    /// - For PQ transactions with chain binding: returns `envelope.chain_id`.
    /// - For EVM (secp256k1) settlement transactions: returns `EVM_CHAIN_ID`.
    /// - For legacy transactions: returns `None`.
    pub fn chain_id(&self) -> Option<u64> {
        // A sponsor grant carries the replay-protection domain for sponsored
        // transactions (the grant is committed into both signatures).
        let (inner_len, sponsor_auth, _) = Self::split_sponsor_envelope(&self.signature);
        if let Some(auth) = sponsor_auth {
            return Some(auth.chain_id);
        }
        let inner_sig = &self.signature[..inner_len];
        Self::chain_id_from_parsed_inner(inner_sig)
    }

    pub fn compute_tx_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        let mut payload_buf = Vec::new();
        self.hash_into(&mut hasher, &mut payload_buf);
        hasher.finalize().into()
    }

    /// Feed this transaction's hash preimage into `hasher`, reusing
    /// `payload_buf` as scratch for the bincode payload encoding.
    ///
    /// Split out of [`Self::compute_tx_hash`] so a batch can reuse ONE
    /// hasher (via `finalize_reset`) and ONE scratch buffer across every
    /// transaction instead of allocating both per transaction. The update
    /// sequence is identical, so the hashes are byte-identical.
    fn hash_into(&self, hasher: &mut Sha256, payload_buf: &mut Vec<u8>) {
        use sha2::Digest;
        hasher.update(self.from);
        hasher.update(self.to);
        hasher.update(self.amount.to_be_bytes());
        hasher.update(self.gas_limit.to_be_bytes());
        hasher.update(self.nonce.to_be_bytes());
        hasher.update(self.source_shard.to_be_bytes());
        hasher.update(self.target_shard.to_be_bytes());
        hasher.update(b"PAYLOAD");
        payload_buf.clear();
        match bincode::serialize_into(&mut *payload_buf, &self.payload) {
            Ok(()) => {
                hasher.update((payload_buf.len() as u32).to_be_bytes());
                hasher.update(&payload_buf[..]);
            }
            Err(_) => hasher.update(u32::MAX.to_be_bytes()),
        }
        // Conditional commitment: the explicit priority bid is mixed in ONLY
        // when it is non-zero, so a legacy transaction (no bid) keeps its
        // byte-identical hash — and every block hash built from it — while a
        // bid is bound into the transaction's identity (two transactions that
        // differ ONLY in their bid are different transactions).
        if self.priority_fee_per_gas != 0 {
            hasher.update(PRIORITY_FEE_COMMITMENT_TAG);
            hasher.update(self.priority_fee_per_gas.to_be_bytes());
        }
        // Parse the trailing sponsor envelope ONCE and inspect the inner slice
        // directly (identical to calling `delegation()`, `is_chain_id_bound()`,
        // `chain_id_from_envelope()`, `sponsor_auth()`, `is_evm()`, `is_pq()`).
        let (inner_len, sponsor_auth, _) = Self::split_sponsor_envelope(&self.signature);
        let inner_sig = &self.signature[..inner_len];
        // Conditional commitment: nothing is appended for a legacy signature,
        // so legacy tx hashes (and every block hash built from them) are
        // byte-identical to before session keys existed.
        if let Some((d, _)) = Self::delegation_from_inner(inner_sig) {
            hasher.update(b"SESSION");
            payload_buf.clear();
            match bincode::serialize_into(&mut *payload_buf, &d) {
                Ok(()) => {
                    hasher.update((payload_buf.len() as u32).to_be_bytes());
                    hasher.update(&payload_buf[..]);
                }
                Err(_) => hasher.update(u32::MAX.to_be_bytes()),
            }
        }
        if let Some(cid) = Self::chain_id_from_inner(inner_sig) {
            hasher.update(CHAIN_ID_COMMITMENT_TAG);
            hasher.update(cid.to_be_bytes());
        }
        // Conditional commitment: nothing is appended for a legacy
        // transaction, so legacy tx hashes (and every block hash built from
        // them) are byte-identical to before sponsorship existed.
        if let Some(ref auth) = sponsor_auth {
            hasher.update(SPONSOR_COMMITMENT_TAG);
            payload_buf.clear();
            match bincode::serialize_into(&mut *payload_buf, auth) {
                Ok(()) => {
                    hasher.update((payload_buf.len() as u32).to_be_bytes());
                    hasher.update(&payload_buf[..]);
                }
                Err(_) => hasher.update(u32::MAX.to_be_bytes()),
            }
        }
        // EVM settlement commits the full envelope (tag + canonical raw), so
        // an EVM transaction can never share a hash with a legacy transaction
        // over identical mapped fields (legacy hashes ignore `signature`).
        if Self::is_evm_inner(inner_sig) {
            hasher.update(b"EVM_TX");
            hasher.update(&self.signature);
        }
        if Self::is_pq_inner(inner_sig) {
            hasher.update(b"PQ_ENV");
            hasher.update(&self.signature);
        }
    }

    /// Hash every transaction in one pass, reusing a single hasher (reset per
    /// transaction) and a single pre-sized scratch buffer.
    ///
    /// The output is byte-identical to mapping [`Self::compute_tx_hash`]
    /// over the slice: the per-transaction update sequence is shared code
    /// (`hash_into`), and `finalize_reset` restarts the hasher to the
    /// identical initial state `Sha256::new()` would give. `out` is
    /// pre-sized to `txs.len()` so the batch allocates once.
    pub fn compute_tx_hashes_batched(txs: &[Transaction]) -> Vec<[u8; 32]> {
        let mut batch = TxHashBatch::new();
        let mut out = Vec::with_capacity(txs.len());
        for tx in txs {
            out.push(batch.hash_one(tx));
        }
        out
    }

    /// Reusable batch-hashing state for callers that hash inline (a single
    /// pass that also serializes): one hasher + one scratch buffer instead
    /// of one pair per transaction. Output is byte-identical to
    /// [`Self::compute_tx_hash`].
    pub fn batch_hasher() -> TxHashBatch {
        TxHashBatch::new()
    }

    fn is_pq_inner(inner_sig: &[u8]) -> bool {
        inner_sig.starts_with(PQ_ENVELOPE_MAGIC)
    }

    /// True if the transaction signature begins with the PQ1 framing marker.
    pub fn is_pq(&self) -> bool {
        Self::is_pq_inner(self.sponsor_inner_sig())
    }

    fn pq_envelope_from_inner_with_mode(
        inner_sig: &[u8],
        canonical: bool,
    ) -> Option<PqSignatureEnvelope> {
        if !Self::is_pq_inner(inner_sig) {
            return None;
        }
        let env = PqSignatureEnvelope::decode_at_height(inner_sig, canonical).ok()?;
        if canonical {
            if env.encoded_len() != inner_sig.len() {
                return None;
            }
        } else if env.encoded_len() != inner_sig.len() && env.legacy_encode_len() != inner_sig.len()
        {
            return None;
        }
        Some(env)
    }

    fn pq_envelope_from_inner(inner_sig: &[u8]) -> Option<PqSignatureEnvelope> {
        Self::pq_envelope_from_inner_with_mode(inner_sig, false)
    }

    /// Decode the post-quantum signature envelope if present, ensuring exact fit (no trailing bytes).
    pub fn pq_envelope(&self) -> Option<PqSignatureEnvelope> {
        Self::pq_envelope_from_inner(self.sponsor_inner_sig())
    }

    /// Decode the post-quantum signature envelope strictly in canonical layout (`>= H`).
    pub fn pq_envelope_canonical(&self) -> Option<PqSignatureEnvelope> {
        Self::pq_envelope_from_inner_with_mode(self.sponsor_inner_sig(), true)
    }

    /// Decode the post-quantum signature envelope with height-gated canonical strictness.
    pub fn pq_envelope_at_height(&self, height: u64) -> Option<PqSignatureEnvelope> {
        let canonical = crate::chain_spec::wasm_xshard_pmm_hardening_active_at(height);
        Self::pq_envelope_from_inner_with_mode(self.sponsor_inner_sig(), canonical)
    }

    /// True if this transaction carries a raw public key in a PQ envelope (activation tx).
    pub fn is_pq_activation(&self) -> bool {
        self.pq_envelope()
            .map(|e| !e.is_implicit && e.pubkey.is_some())
            .unwrap_or(false)
    }

    /// True if this transaction is an implicit PQ transaction (public key omitted from wire).
    pub fn is_pq_implicit(&self) -> bool {
        self.pq_envelope()
            .map(|e| e.is_implicit || e.pubkey.is_none())
            .unwrap_or(false)
    }

    /// Returns a reference to the global in-memory implicit key registry.
    pub fn global_implicit_registry() -> &'static StatefulImplicitKeyRegistry {
        global_implicit_key_registry()
    }

    /// Create a post-quantum transaction with an explicit public key attached (activation tx).
    #[allow(clippy::too_many_arguments)]
    // GATE: PQ constructor needs full tx plus key material; splitting changes public API.
    pub fn new_pq_explicit(
        scheme: PqScheme,
        pubkey: Vec<u8>,
        signature_bytes: Vec<u8>,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        payload: Vec<crate::svm::OpCode>,
        salt: &[u8; 16],
    ) -> Self {
        let from = derive_pq_address(scheme, &pubkey, salt);
        let envelope =
            PqSignatureEnvelope::new_explicit_with_salt(scheme, pubkey, signature_bytes, *salt);
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

    /// Create a post-quantum transaction with an implicit public key (pubkey omitted from wire).
    #[allow(clippy::too_many_arguments)]
    // GATE: PQ constructor needs full tx plus key material; splitting changes public API.
    pub fn new_pq_implicit(
        from: [u8; 32],
        scheme: PqScheme,
        signature_bytes: Vec<u8>,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        payload: Vec<crate::svm::OpCode>,
    ) -> Self {
        let envelope = PqSignatureEnvelope::new_implicit(scheme, signature_bytes);
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

    /// Create a post-quantum transaction with an explicit public key and chain_id attached.
    #[allow(clippy::too_many_arguments)]
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
        payload: Vec<crate::svm::OpCode>,
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

    /// Create a post-quantum transaction with an implicit public key and chain_id attached.
    #[allow(clippy::too_many_arguments)]
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
        payload: Vec<crate::svm::OpCode>,
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

    /// Create a REAL Falcon-512 signature for a given message and pubkey.
    ///
    /// AUDIT W6.1 (the test backdoor is GONE): this helper used to be able to
    /// fall back to the BLAKE3 "check digest" pseudo-signature that only the
    /// `#[cfg(test)]` branch of `verify_falcon_signature_or_test` accepted —
    /// a 1/256 forge probability that also made the tamper-detection tests
    /// flaky. It now ALWAYS produces an authentic FIPS 206 signature from the
    /// seeded keypair, and it CHECKS that the public key handed in really is
    /// the public key of that keypair (otherwise the signature would not
    /// verify and the test would fail for the wrong reason).
    #[cfg(any(test, debug_assertions))]
    pub fn create_falcon512_test_signature(pubkey: &[u8], message: &[u8], seed: u8) -> Vec<u8> {
        let kp = crate::post_quantum::FalconKeypair::generate_from_seed(seed);
        assert_eq!(
            kp.public_key(),
            pubkey,
            "create_falcon512_test_signature: the public key must be the one of the \
             seeded keypair (sample_falcon512_pubkey(seed))"
        );
        let sig = kp.sign(message);
        assert!(
            crate::post_quantum::verify_pq_signature(
                crate::post_quantum::PqScheme::Falcon512,
                pubkey,
                message,
                &sig,
            ),
            "create_falcon512_test_signature: the produced signature must verify"
        );
        sig
    }

    /// Generate a sample Falcon-512 public key with canonical header byte.
    #[cfg(any(test, debug_assertions))]
    pub fn sample_falcon512_pubkey(seed: u8) -> Vec<u8> {
        crate::post_quantum::FalconKeypair::generate_from_seed(seed)
            .public_key
            .clone()
    }

    /// Envelope-aware signature verification.
    ///
    /// * legacy  : `tx.from` is the verifying key over `signing_message()`.
    /// * envelope: the delegation must be minted FOR this sender
    ///   (`master_address == tx.from` — the graft-attack guard), the master's
    ///   grant must verify, and the SESSION key must sign `signing_message()`
    ///   (which commits to the grant). Two framings: legacy-Ed `SK1` (always
    ///   refused — Ed grants fail closed) and Falcon-512 `SF1` (verified
    ///   through the post-quantum API).
    /// * post-quantum (PQ1 envelope):
    ///   - If explicit pubkey in envelope: verify signature using provided pubkey,
    ///     and verify `derive_pq_address(scheme, pubkey, salt) == self.from`.
    ///     The key is registered into the implicit key registry.
    ///   - If implicit (pubkey omitted from wire): verify signature against the
    ///     address's implicit key registry (`StatefulImplicitKeyRegistry`).
    ///
    /// Malformed input (including a bare 64-byte signature followed by junk)
    /// fails closed: a pre-envelope node rejects the envelope at
    /// `Signature::from_slice`, and so does the legacy branch here.
    pub fn verify_signature(&self) -> bool {
        self.verify_signature_with_registry(Self::global_implicit_registry())
    }

    /// Height-gated signature verification (`decode_canonical` when
    /// `wasm_xshard_pmm_hardening_active_at(height)` is true).
    pub fn verify_signature_at_height(&self, height: u64) -> bool {
        self.verify_signature_with_registry_at_height(Self::global_implicit_registry(), height)
    }

    /// Verify signature against a caller-supplied implicit key registry with default salt.
    pub fn verify_signature_with_registry(&self, registry: &StatefulImplicitKeyRegistry) -> bool {
        self.verify_signature_with_registry_and_salt(registry, &DEFAULT_SALT)
    }

    /// Height-gated signature verification against a caller-supplied implicit key registry.
    pub fn verify_signature_with_registry_at_height(
        &self,
        registry: &StatefulImplicitKeyRegistry,
        height: u64,
    ) -> bool {
        let canonical_pq = crate::chain_spec::wasm_xshard_pmm_hardening_active_at(height);
        self.verify_signature_with_registry_and_salt_inner(registry, &DEFAULT_SALT, canonical_pq)
    }

    /// Verify signature against a caller-supplied implicit key registry and salt.
    ///
    /// Malformed sponsor suffixes fail closed; a well-formed sponsor envelope
    /// additionally requires the v1 composition (plain legacy ed25519 inner)
    /// AND a valid sponsor signature — BOTH signatures must verify.
    pub fn verify_signature_with_registry_and_salt(
        &self,
        registry: &StatefulImplicitKeyRegistry,
        salt: &[u8; 16],
    ) -> bool {
        self.verify_signature_with_registry_and_salt_inner(registry, salt, false)
    }

    fn verify_signature_with_registry_and_salt_inner(
        &self,
        registry: &StatefulImplicitKeyRegistry,
        salt: &[u8; 16],
        canonical_pq: bool,
    ) -> bool {
        let (inner_len, sponsor_auth, sponsor_malformed) =
            Self::split_sponsor_envelope(&self.signature);
        if sponsor_malformed {
            return false;
        }
        let inner_sig = &self.signature[..inner_len];
        let (inner_ok, is_pq_inner) = self.verify_inner_with_registry(
            registry,
            salt,
            inner_sig,
            sponsor_auth.as_ref(),
            canonical_pq,
        );
        if !inner_ok {
            return false;
        }
        match sponsor_auth {
            None => true,
            Some(auth) => {
                // FULL-PQ Paymaster v2: the sponsor rides ONLY on a valid PQ1
                // post-quantum inner envelope. Classical Ed25519 / session /
                // EVM inners refuse here.
                if !is_pq_inner {
                    return false;
                }
                self.verify_sponsor_sig(&auth)
            }
        }
    }

    /// The pre-sponsor signature check, run on the sponsor-inner blob (the
    /// full signature for legacy transactions). All envelope helpers it uses
    /// are sponsor-strip-aware, so this is byte-identical to the historical
    /// check on legacy inputs.
    ///
    /// Returns `(inner_valid, is_pq_sponsor_inner)` so the caller avoids
    /// re-splitting the sponsor suffix or re-decoding the PQ1 envelope.
    fn verify_inner_with_registry(
        &self,
        registry: &StatefulImplicitKeyRegistry,
        _salt: &[u8; 16],
        inner_sig: &[u8],
        sponsor_auth: Option<&SponsorAuthorization>,
        canonical_pq: bool,
    ) -> (bool, bool) {
        let build_pq_signing_message = |chain_id: Option<u64>| {
            let mut msg = Self::base_signing_message(
                &self.from,
                self.to,
                self.amount,
                self.gas_limit,
                self.nonce,
                self.source_shard,
                self.target_shard,
                &self.payload,
                self.priority_fee_per_gas,
            );
            if let Some(auth) = sponsor_auth {
                Self::append_sponsor_commitment(&mut msg, auth);
            } else if let Some(cid) = chain_id {
                Self::append_chain_id_commitment(&mut msg, cid);
            }
            msg
        };
        // Session-keyed envelopes (`SK1` legacy-Ed / `SF1` Falcon-512) verify
        // against the GRANT, not `tx.from`: the grant must be minted for this
        // sender, the master's grant signature must verify, and the SESSION
        // key must have signed `signing_message()` (which commits to the
        // grant, so it cannot be swapped after signing). Ed (`SK1`) grants
        // stay refused — `verify_signature`/`verify_session_signature` fail
        // closed on non-post-quantum schemes — while Falcon (`SF1`) grants
        // verify through the post-quantum API. This branch runs first so a
        // session envelope always takes the session path deterministically;
        // anything below it behaves byte-identically to before for
        // non-session inputs (`delegation()` is `None` there).
        if let Some((d, session_sig)) = Self::delegation_from_inner(inner_sig) {
            if d.master_address != self.from {
                return (false, false);
            }
            if !d.verify_signature() {
                return (false, false);
            }
            let mut msg = Self::base_signing_message(
                &self.from,
                self.to,
                self.amount,
                self.gas_limit,
                self.nonce,
                self.source_shard,
                self.target_shard,
                &self.payload,
                self.priority_fee_per_gas,
            );
            Self::append_delegation_commitment(&mut msg, &d);
            if let Some(auth) = sponsor_auth {
                Self::append_sponsor_commitment(&mut msg, auth);
            }
            return (d.verify_session_signature(&msg, session_sig), false);
        }
        // FULL-PQ: EVM settlement removed (no secp fallback).
        if inner_sig.len() > EVM_SIG_TAG.len() && inner_sig[..EVM_SIG_TAG.len()] == EVM_SIG_TAG[..]
        {
            return (false, false);
        }
        if inner_sig.starts_with(PQ_ENVELOPE_MAGIC) {
            let Ok(env) = PqSignatureEnvelope::decode_at_height(inner_sig, canonical_pq) else {
                return (false, false);
            };
            let exact_len = if canonical_pq {
                env.encoded_len() == inner_sig.len()
            } else {
                env.encoded_len() == inner_sig.len() || env.legacy_encode_len() == inner_sig.len()
            };
            if !exact_len {
                return (false, false);
            }
            // FULL-PQ: non-PQ schemes always refused (no classical fallback).
            if !env.scheme.is_post_quantum() {
                return (false, false);
            }
            if env.signature_bytes.len() != env.scheme.signature_size() {
                return (false, true);
            }
            if !env.is_implicit {
                let Some(ref pk) = env.pubkey else {
                    return (false, true);
                };
                if pk.len() != env.scheme.pubkey_size() {
                    return (false, true);
                }
                let derived = derive_pq_address(env.scheme, pk, &env.salt);
                if derived != self.from {
                    return (false, true);
                }
                let msg = build_pq_signing_message(env.chain_id);
                let valid = if env.scheme == PqScheme::Falcon512 {
                    crate::consensus::verify_falcon_signature(pk, &msg, &env.signature_bytes)
                } else {
                    verify_pq_signature(env.scheme, pk, &msg, &env.signature_bytes)
                };
                if !valid {
                    return (false, true);
                }
                let _ = registry.register(self.from, env.scheme, pk, &env.salt);
                (true, true)
            } else {
                if env.pubkey.is_some() {
                    return (false, true);
                }
                let Some((scheme, pk)) = registry.lookup(&self.from) else {
                    return (false, true);
                };
                if scheme != env.scheme {
                    return (false, true);
                }
                let msg = build_pq_signing_message(env.chain_id);
                let valid = if scheme == PqScheme::Falcon512 {
                    crate::consensus::verify_falcon_signature(&pk, &msg, &env.signature_bytes)
                } else {
                    verify_pq_signature(scheme, &pk, &msg, &env.signature_bytes)
                };
                (valid, true)
            }
        } else {
            // FULL-PQ: legacy (non-PQ) transactions always refused.
            // Classical ed/delegation fallback deleted.
            (false, false)
        }
    }

    /// The exact bytes that the sender signs (used for both single and batch
    /// verify). For an envelope transaction this INCLUDES the grant or chain_id
    /// commitment, so the grant / chain_id cannot be swapped after signing.
    pub fn signing_message(&self) -> Vec<u8> {
        let mut msg = Self::base_signing_message(
            &self.from,
            self.to,
            self.amount,
            self.gas_limit,
            self.nonce,
            self.source_shard,
            self.target_shard,
            &self.payload,
            self.priority_fee_per_gas,
        );
        let (inner_len, sponsor_auth, _) = Self::split_sponsor_envelope(&self.signature);
        let inner_sig = &self.signature[..inner_len];
        // EVM-settled transactions are never verified against this preimage
        // (their envelope IS the secp256k1-signed raw); return the base
        // message deterministically with no grant/chain commitment appended.
        if Self::is_evm_inner(inner_sig) {
            return msg;
        }
        if let Some((d, _)) = Self::delegation_from_inner(inner_sig) {
            Self::append_delegation_commitment(&mut msg, &d);
        } else if sponsor_auth.is_none() {
            // Sponsored transactions bind their chain through the sponsor
            // commitment below (single commitment, no ambiguity); the
            // chain-id branch stays legacy-only.
            if let Some(cid) = Self::chain_id_from_parsed_inner(inner_sig) {
                Self::append_chain_id_commitment(&mut msg, cid);
            }
        }
        // The sponsor grant is bound into the USER's signed message (and the
        // tx hash), so it cannot be swapped after signing. Nothing is
        // appended for legacy transactions.
        if let Some(auth) = sponsor_auth {
            Self::append_sponsor_commitment(&mut msg, &auth);
        }
        msg
    }

    /// Construct signing message for a specific chain_id (before attaching an envelope).
    pub fn signing_message_for_chain(&self, chain_id: u64) -> Vec<u8> {
        let mut msg = Self::base_signing_message(
            &self.from,
            self.to,
            self.amount,
            self.gas_limit,
            self.nonce,
            self.source_shard,
            self.target_shard,
            &self.payload,
            self.priority_fee_per_gas,
        );
        if let Some(d) = self.delegation() {
            Self::append_delegation_commitment(&mut msg, &d);
        } else {
            Self::append_chain_id_commitment(&mut msg, chain_id);
        }
        msg
    }

    /// Verify signature and enforce chain_id binding (Finding F1: anti cross-chain replay).
    /// If `require_chain_id` is true, legacy transactions without chain_id are rejected.
    pub fn verify_signature_for_chain(
        &self,
        expected_chain_id: u64,
        require_chain_id: bool,
    ) -> bool {
        if require_chain_id && self.chain_id().is_none() {
            return false;
        }
        if let Some(cid) = self.chain_id() {
            if cid != expected_chain_id {
                return false;
            }
        }
        self.verify_signature()
    }

    /// The session scope THIS transaction's payload requires of a grant.
    ///
    /// One definition, used by every path that asks the question, so propose,
    /// mempool admission, block admission and the execution-time gate can
    /// never disagree about which capability a transaction needs:
    ///
    ///  * empty payload -> [`crate::zkml::SCOPE_TRANSFER`];
    ///  * a payload carrying an actor-mailbox send ->
    ///    `SCOPE_SVM_PAYLOAD | SCOPE_ACTOR_SEND` - BOTH bits, because the
    ///    actor send is an extra capability layered on top of "may run a
    ///    payload", never a substitute for it (see `SCOPE_ACTOR_SEND`);
    ///  * any other payload -> [`crate::zkml::SCOPE_SVM_PAYLOAD`].
    ///
    /// Deterministic from the payload bytes alone (no clock, no state), which
    /// is what lets it be mirrored at propose time against the block clock.
    pub fn required_scope(&self) -> u64 {
        if self.payload.is_empty() {
            crate::zkml::SCOPE_TRANSFER
        } else if self
            .payload
            .iter()
            .any(|op| matches!(op, crate::svm::OpCode::SysCallActorSend { .. }))
        {
            crate::zkml::SCOPE_SVM_PAYLOAD | crate::zkml::SCOPE_ACTOR_SEND
        } else {
            crate::zkml::SCOPE_SVM_PAYLOAD
        }
    }

    /// Delegation policy check for this transaction at a given time.
    ///
    /// `now` must be a DETERMINISTIC clock — the block timestamp at propose
    /// selection and at execution, the admission context's time at mempool
    /// entry. Never the local wall clock inside consensus execution.
    ///
    /// Legacy transactions pass unconditionally. Session-keyed transactions
    /// need a grant minted for this sender, not expired, in scope for this
    /// transaction kind, within the per-transaction value cap, and with enough
    /// remaining gas budget for the declared `gas_limit`.
    ///
    /// The signature itself is NOT re-checked here (that is
    /// `verify_signature`); this is the grant's POLICY.
    pub fn check_session_policy(&self, now: u64) -> Result<(), SessionPolicyError> {
        let Some(d) = self.delegation() else {
            // Legacy signature. Anything that claims envelope shape but did
            // not parse is rejected by `verify_signature` instead.
            return Ok(());
        };
        // FULL-PQ: non-PQ grants always refused (no classical fallback).
        if !d.master_scheme.is_post_quantum() || !d.session_scheme.is_post_quantum() {
            return Err(SessionPolicyError::BadGrant);
        }
        if d.master_address != self.from {
            return Err(SessionPolicyError::BadGrant);
        }
        if !d.verify_signature() {
            return Err(SessionPolicyError::BadGrant);
        }
        if now > d.valid_until {
            return Err(SessionPolicyError::Expired);
        }
        let required_scope = self.required_scope();
        if !d.grants_scope(required_scope) {
            return Err(SessionPolicyError::OutOfScope);
        }
        if self.amount > d.max_value_per_tx {
            return Err(SessionPolicyError::OutOfScope);
        }
        if self.gas_limit > d.remaining_gas() {
            return Err(SessionPolicyError::BudgetExhausted);
        }
        Ok(())
    }

    /// PAYMASTER (sponsored transactions): envelope parsing, signing, policy.
    ///
    /// The envelope is a TRAILING suffix on `signature`:
    /// `inner ++ bincode(SponsorAuthorization) ++ len_be32 ++ b"SP1"`.
    /// The tag sits at the very end (like the priority envelope), so parsing
    /// is unambiguous and composes with every inner shape: strip the sponsor
    /// suffix FIRST, then run the legacy parsers on the inner blob.
    ///
    /// INVARIANTS (all fail closed):
    /// * malformed suffix (bad length, undecodable, over-bound auth) makes
    ///   the WHOLE transaction invalid — never silently legacy;
    /// * v1 sponsors ONLY a plain legacy ed25519 inner (`inner.len() == 64`);
    ///   session/PQ/EVM/chain-bound inners with a sponsor envelope refuse;
    /// * the user's message commits to the full auth (incl. `sponsor_sig`);
    ///   the sponsor's message commits to the tx core + caps. Neither side
    ///   can be swapped or grafted.
    ///   Split the trailing sponsor suffix off a signature blob.
    ///
    /// Returns `(inner_len, auth, malformed)`: `inner_len` is the byte length
    /// of the inner signature blob, `auth` is the parsed grant (when the
    /// suffix is present AND well-formed), `malformed` is true when the tag
    /// is present but the suffix does not parse (fail closed upstream).
    /// A blob without the trailing tag returns `(blob.len(), None, false)` —
    /// the legacy path, byte-identical to before.
    pub fn split_sponsor_envelope(blob: &[u8]) -> (usize, Option<SponsorAuthorization>, bool) {
        let tag_len = SPONSOR_SIG_TAG.len();
        // tag + u32 length + at least 1 auth byte.
        if blob.len() < tag_len + 4 + 1 || blob[blob.len() - tag_len..] != SPONSOR_SIG_TAG[..] {
            return (blob.len(), None, false);
        }
        let len_off = blob.len() - tag_len - 4;
        let auth_len = u32::from_be_bytes([
            blob[len_off],
            blob[len_off + 1],
            blob[len_off + 2],
            blob[len_off + 3],
        ]) as usize;
        if auth_len == 0 || auth_len > SPONSOR_AUTH_MAX_BYTES || len_off < auth_len {
            return (blob.len(), None, true);
        }
        let inner_len = len_off - auth_len;
        // A legit inner signature is at least a 64-byte ed25519 signature.
        if inner_len < 64 {
            return (blob.len(), None, true);
        }
        let auth_bytes = &blob[inner_len..len_off];
        match bincode::deserialize::<SponsorAuthorization>(auth_bytes) {
            Ok(auth) => {
                // DoS bounds, enforced at parse (fail closed, never truncate).
                // Allow both 666-byte Falcon-512 and 64-byte legacy Ed25519 sig
                // lengths so legacy Ed25519 sponsor sigs fail signature
                // verification cleanly as `SponsorBadSignature`, while
                // arbitrary garbage lengths still set `malformed = true`.
                if (auth.sponsor_sig.len() != FALCON512_SIG_LEN && auth.sponsor_sig.len() != 64)
                    || auth.allowed_targets.len() > SPONSOR_MAX_TARGETS
                {
                    return (blob.len(), None, true);
                }
                (inner_len, Some(auth), false)
            }
            Err(_) => (blob.len(), None, true),
        }
    }

    /// The inner signature blob (the full blob when no well-formed sponsor
    /// suffix is present).
    pub fn sponsor_inner_sig(&self) -> &[u8] {
        let (inner_len, _, _) = Self::split_sponsor_envelope(&self.signature);
        &self.signature[..inner_len]
    }

    /// True when the sponsor-inner signature is a well-formed PQ1 envelope
    /// using a post-quantum scheme.
    pub fn has_pq_sponsor_inner(&self) -> bool {
        self.pq_envelope()
            .is_some_and(|env| env.scheme.is_post_quantum())
    }

    /// True when the trailing sponsor tag is present, regardless of whether
    /// the suffix parses (use [`Self::sponsor_malformed`] to distinguish).
    pub fn has_sponsor_envelope(&self) -> bool {
        let b = &self.signature;
        b.len() > SPONSOR_SIG_TAG.len() + 4
            && b[b.len() - SPONSOR_SIG_TAG.len()..] == SPONSOR_SIG_TAG[..]
    }

    /// True when the sponsor suffix is present but does not parse: the
    /// transaction is invalid and must be refused (never silently legacy).
    pub fn sponsor_malformed(&self) -> bool {
        Self::split_sponsor_envelope(&self.signature).2
    }

    /// The parsed sponsor grant, if a well-formed sponsor envelope is present.
    /// `None` on the legacy path — and on a malformed suffix (check
    /// [`Self::sponsor_malformed`] to tell the two apart).
    pub fn sponsor_auth(&self) -> Option<SponsorAuthorization> {
        Self::split_sponsor_envelope(&self.signature).1
    }

    /// True when this transaction carries a well-formed sponsor envelope
    /// (including a self-sponsored one, which fee-routes as plain).
    pub fn is_sponsored(&self) -> bool {
        self.sponsor_auth().is_some()
    }

    /// The EFFECTIVE sponsor grant: a well-formed envelope whose sponsor is a
    /// THIRD PARTY (`sponsor != from`).
    ///
    /// `None` on the legacy path AND on the self-sponsored path
    /// (`sponsor == from`, which fee-routes as plain per the paymaster
    /// contract: the user pays their own fee, the envelope is signature-only
    /// and changes no balance routing). Every fee-routing decision —
    /// admission coverage, execution debit, proposer accounting — branches on
    /// THIS predicate, so `sponsor == from` can never divert a fee.
    pub fn sponsored_grant(&self) -> Option<SponsorAuthorization> {
        let auth = self.sponsor_auth()?;
        if auth.sponsor == self.from {
            None
        } else {
            Some(auth)
        }
    }

    /// The account debited the fee: the sponsor, or the user when there is no
    /// grant or the grant names the user itself (`sponsor == from` is the
    /// plain path per the paymaster contract).
    pub fn effective_sponsor(&self) -> Option<[u8; 32]> {
        self.sponsor_auth().and_then(|a| {
            if a.sponsor == self.from {
                None
            } else {
                Some(a.sponsor)
            }
        })
    }

    /// The account that pays the fee for this transaction (sponsor or user).
    pub fn fee_payer(&self) -> [u8; 32] {
        self.effective_sponsor().unwrap_or(self.from)
    }

    /// Encode one sponsor suffix (`bincode(auth) ++ len_be32 ++ "SP1"`).
    fn encode_sponsor_suffix(auth: &SponsorAuthorization) -> Vec<u8> {
        // Serialization of this struct cannot realistically fail (fixed-size
        // fields plus bounded vecs). If it somehow did, the envelope would
        // not parse and the transaction fails closed at verification.
        let body = bincode::serialize(auth).unwrap_or_default();
        let mut out = Vec::with_capacity(body.len() + 7);
        out.extend_from_slice(&body);
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(SPONSOR_SIG_TAG);
        out
    }

    /// Commitment of the sponsor grant, bound into BOTH the user's signed
    /// message and the tx hash. Empty for legacy transactions, which is what
    /// keeps every pre-sponsor byte string unchanged.
    fn sponsor_commitment_bytes(auth: &SponsorAuthorization) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(SPONSOR_COMMITMENT_TAG);
        match bincode::serialize(auth) {
            Ok(bytes) => {
                out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                out.extend_from_slice(&bytes);
            }
            Err(_) => out.extend_from_slice(&u32::MAX.to_be_bytes()),
        }
        out
    }

    fn append_sponsor_commitment(msg: &mut Vec<u8>, auth: &SponsorAuthorization) {
        msg.extend_from_slice(&Self::sponsor_commitment_bytes(auth));
    }

    /// The exact bytes the SPONSOR signs: domain tag + sponsor + the full tx
    /// core (so the grant is bound to THIS action) + the caps (so the grant
    /// cannot be inflated after signing). The user's message separately
    /// commits to the full auth, so the grant cannot be re-targeted either.
    pub fn sponsor_message(&self, auth: &SponsorAuthorization) -> Vec<u8> {
        let mut msg = Vec::with_capacity(256);
        msg.extend_from_slice(SPONSOR_FEE_DOMAIN);
        msg.extend_from_slice(&auth.sponsor);
        msg.extend_from_slice(&self.from);
        msg.extend_from_slice(&self.to);
        msg.extend_from_slice(&self.amount.to_be_bytes());
        msg.extend_from_slice(&self.gas_limit.to_be_bytes());
        msg.extend_from_slice(&self.nonce.to_be_bytes());
        msg.extend_from_slice(&self.source_shard.to_be_bytes());
        msg.extend_from_slice(&self.target_shard.to_be_bytes());
        Self::append_payload_commitment(&mut msg, &self.payload);
        msg.extend_from_slice(&self.priority_fee_per_gas.to_be_bytes());
        msg.extend_from_slice(&auth.max_fee_per_tx.to_be_bytes());
        msg.extend_from_slice(&auth.valid_until.to_be_bytes());
        msg.extend_from_slice(b"ALLOWLIST");
        msg.extend_from_slice(&(auth.allowed_targets.len() as u32).to_be_bytes());
        for t in &auth.allowed_targets {
            msg.extend_from_slice(t);
        }
        msg.extend_from_slice(&auth.chain_id.to_be_bytes());
        msg
    }

    /// Verify ONLY the sponsor's signature over [`Self::sponsor_message`].
    /// Fail-closed: rejects classical Ed25519, wrong signature/pubkey length,
    /// wrong scheme, address mismatch, or invalid Falcon-512 signature.
    /// (The user's side is verified separately; BOTH must pass.)
    pub fn verify_sponsor_sig(&self, auth: &SponsorAuthorization) -> bool {
        if auth.sponsor_sig.len() != FALCON512_SIG_LEN {
            return false;
        }
        let Some(scheme) = auth.sponsor_scheme else {
            return false;
        };
        if scheme != PqScheme::Falcon512 {
            return false;
        }
        let Some(ref pk) = auth.sponsor_pubkey else {
            return false;
        };
        if pk.len() != scheme.pubkey_size() {
            return false;
        }
        let salt = auth.sponsor_salt.unwrap_or(DEFAULT_SALT);
        if derive_pq_address(scheme, pk, &salt) != auth.sponsor {
            return false;
        }
        verify_pq_signature(scheme, pk, &self.sponsor_message(auth), &auth.sponsor_sig)
    }

    /// Stateless sponsor policy for this transaction at time `now`.
    ///
    /// `fee_to_charge` is the fee execution will actually debit
    /// (`max(gas_limit, floor) + surcharge`); the per-tx cap is checked
    /// against THAT number, not the declared limit, so a below-floor
    /// declaration cannot smuggle an over-cap fee past the sponsor.
    ///
    /// `now` must be a DETERMINISTIC clock — the admission context's time at
    /// mempool entry, the block timestamp at propose/apply. Legacy (and
    /// self-sponsored) transactions pass unconditionally.
    pub fn check_sponsor_policy(
        &self,
        now: u64,
        fee_to_charge: u64,
    ) -> Result<(), SponsorPolicyError> {
        let Some(auth) = self.sponsor_auth() else {
            return Ok(());
        };
        // Self-sponsored: fee-routing is plain, the user pays their own fee.
        if auth.sponsor == self.from {
            return Ok(());
        }
        // FULL-PQ Paymaster v2 composition (mirrors the verify gate): requires a
        // valid post-quantum PQ1 inner envelope; classical/session/EVM refuse.
        if !self.has_pq_sponsor_inner() {
            return Err(SponsorPolicyError::BadGrant);
        }
        if now > auth.valid_until {
            return Err(SponsorPolicyError::Expired);
        }
        if !auth.allowed_targets.is_empty() && !auth.allowed_targets.contains(&self.to) {
            return Err(SponsorPolicyError::OutOfScope);
        }
        if fee_to_charge > auth.max_fee_per_tx {
            return Err(SponsorPolicyError::CapExceeded);
        }
        Ok(())
    }

    /// Sign a transaction whose FEE is paid by a sponsor (gasless path).
    ///
    /// * `user_key` signs the action (and binds the sponsor grant: the grant
    ///   cannot be swapped after signing);
    /// * `sponsor_key` signs the fee authorization for THIS exact transaction
    ///   with THESE caps (it cannot be grafted onto another transaction).
    ///
    /// `allowed_targets` longer than [`SPONSOR_MAX_TARGETS`] is truncated
    /// (narrowing = the fail-closed direction) with a debug assertion for
    /// wallet developers.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_with_sponsor(
        user_key: &SigningKey,
        sponsor_key: &SigningKey,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        payload: Vec<crate::svm::OpCode>,
        priority_fee_per_gas: u64,
        max_fee_per_tx: u64,
        valid_until: u64,
        allowed_targets: Vec<[u8; 32]>,
        chain_id: u64,
    ) -> Self {
        let from_pub = user_key.verifying_key().to_bytes();
        let sponsor_pub = sponsor_key.verifying_key().to_bytes();
        debug_assert!(
            allowed_targets.len() <= SPONSOR_MAX_TARGETS,
            "sponsor allowlist truncated to SPONSOR_MAX_TARGETS"
        );
        let mut targets = allowed_targets;
        targets.truncate(SPONSOR_MAX_TARGETS);
        let mut auth = SponsorAuthorization {
            sponsor: sponsor_pub,
            max_fee_per_tx,
            valid_until,
            allowed_targets: targets,
            chain_id,
            sponsor_sig: Vec::new(),
            sponsor_scheme: None,
            sponsor_pubkey: None,
            sponsor_salt: None,
        };
        // The sponsor signs FIRST (the user's message commits to the full
        // auth including this signature, fixing the signing order).
        let provisional = Transaction {
            from: from_pub,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            signature: Vec::new(),
            payload: payload.clone(),
            priority_fee_per_gas,
        };
        let sponsor_msg = provisional.sponsor_message(&auth);
        auth.sponsor_sig = sponsor_key.sign(&sponsor_msg).to_vec();
        // The user signs the action + the grant binding.
        let mut msg = Self::base_signing_message(
            &from_pub,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            &payload,
            priority_fee_per_gas,
        );
        Self::append_sponsor_commitment(&mut msg, &auth);
        let sig = user_key.sign(&msg);
        // The in-memory `signature` holds the raw 64-byte user signature
        // plus the sponsor suffix ONLY: the priority envelope is appended by
        // the custom `Serialize` impl at wire time (and stripped back into
        // the struct field at parse time), so encoding it here as well would
        // double-envelope the bid and push the inner blob off the v1 64-byte
        // shape. The bid still binds both signatures (it is committed into
        // `base_signing_message` and `sponsor_message`) and into the hash.
        let mut blob = sig.to_vec();
        blob.extend_from_slice(&Self::encode_sponsor_suffix(&auth));
        Self {
            from: from_pub,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            signature: blob,
            payload,
            priority_fee_per_gas,
        }
    }

    /// Sign a FULL-PQ Paymaster v2 transaction whose FEE is paid by a
    /// Falcon-512 sponsor (`PQ1` explicit Falcon-512 user inner + `SP1`
    /// Falcon-512 sponsor suffix, using [`DEFAULT_SALT`]).
    ///
    /// * `user_key` signs the action + sponsor commitment inside a `PQ1`
    ///   explicit envelope (`from = derive_pq_address(Falcon512, user_pk, DEFAULT_SALT)`);
    /// * `sponsor_key` signs `sponsor_message` (`sponsor = derive_pq_address(Falcon512, sponsor_pk, DEFAULT_SALT)`).
    #[allow(clippy::too_many_arguments)]
    // GATE: PQ paymaster constructor needs full tx + keypairs + grant caps; splitting changes public API.
    pub fn sign_with_sponsor_falcon512(
        user_key: &FalconKeypair,
        sponsor_key: &FalconKeypair,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        payload: Vec<crate::svm::OpCode>,
        priority_fee_per_gas: u64,
        max_fee_per_tx: u64,
        valid_until: u64,
        allowed_targets: Vec<[u8; 32]>,
        chain_id: u64,
    ) -> Self {
        let user_pk = user_key.public_key();
        let sponsor_pk = sponsor_key.public_key();
        let from_addr = derive_pq_address(PqScheme::Falcon512, user_pk, &DEFAULT_SALT);
        let sponsor_addr = derive_pq_address(PqScheme::Falcon512, sponsor_pk, &DEFAULT_SALT);
        debug_assert!(
            allowed_targets.len() <= SPONSOR_MAX_TARGETS,
            "sponsor allowlist truncated to SPONSOR_MAX_TARGETS"
        );
        let mut targets = allowed_targets;
        targets.truncate(SPONSOR_MAX_TARGETS);
        let mut auth = SponsorAuthorization {
            sponsor: sponsor_addr,
            max_fee_per_tx,
            valid_until,
            allowed_targets: targets,
            chain_id,
            sponsor_sig: Vec::new(),
            sponsor_scheme: Some(PqScheme::Falcon512),
            sponsor_pubkey: Some(sponsor_pk.to_vec()),
            sponsor_salt: Some(DEFAULT_SALT),
        };
        // The sponsor signs FIRST (the user's message commits to the full
        // auth including this signature, fixing the signing order).
        let provisional = Transaction {
            from: from_addr,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            signature: Vec::new(),
            payload: payload.clone(),
            priority_fee_per_gas,
        };
        let sponsor_msg = provisional.sponsor_message(&auth);
        auth.sponsor_sig = sponsor_key.sign(&sponsor_msg);
        debug_assert_eq!(
            auth.sponsor_sig.len(),
            FALCON512_SIG_LEN,
            "Falcon-512 sponsor signature must be {FALCON512_SIG_LEN} bytes"
        );
        // The user signs the action + the grant binding.
        let mut msg = Self::base_signing_message(
            &from_addr,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            &payload,
            priority_fee_per_gas,
        );
        Self::append_sponsor_commitment(&mut msg, &auth);
        let user_sig = user_key.sign(&msg);
        debug_assert_eq!(
            user_sig.len(),
            FALCON512_SIG_LEN,
            "Falcon-512 user signature must be {FALCON512_SIG_LEN} bytes"
        );
        let envelope = PqSignatureEnvelope::new_explicit_with_salt(
            PqScheme::Falcon512,
            user_pk.to_vec(),
            user_sig,
            DEFAULT_SALT,
        );
        let mut blob = envelope.encode();
        blob.extend_from_slice(&Self::encode_sponsor_suffix(&auth));
        Self {
            from: from_addr,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            signature: blob,
            payload,
            priority_fee_per_gas,
        }
    }

    /// Batched verification of many transactions at once (PQ-only).
    /// FULL-PQ: classical ed batch removed. Returns true iff EVERY tx is a
    /// valid PQ transaction (scalar `verify_signature` per item, which is
    /// PQ-only). Any EVM, non-PQ-scheme, or legacy tx fails the batch.
    ///
    /// Envelope transactions contribute their SESSION key (not `tx.from`) to
    /// the batch, and their grant is checked (sender binding + master
    /// signature) before batching, so mixed plain + session batches work.
    pub fn verify_signatures_batch(txs: &[Transaction]) -> bool {
        txs.iter().all(Transaction::verify_signature)
    }

    /// Height-gated sequential batch signature verification.
    pub fn verify_signatures_batch_at_height(txs: &[Transaction], height: u64) -> bool {
        txs.iter().all(|tx| tx.verify_signature_at_height(height))
    }

    /// Parallel batched verification across CPU cores (rayon).
    /// Splits the block into chunks and batch-verifies each chunk in parallel.
    /// Falls back to the sequential batch for tiny inputs. Returns true iff ALL valid.
    pub fn verify_signatures_batch_parallel(txs: &[Transaction]) -> bool {
        use rayon::prelude::*;
        const CHUNK: usize = 16;
        if txs.len() < CHUNK {
            return Self::verify_signatures_batch(txs);
        }
        txs.par_chunks(CHUNK).all(Self::verify_signatures_batch)
    }

    /// Height-gated parallel batched verification across CPU cores (rayon).
    pub fn verify_signatures_batch_parallel_at_height(txs: &[Transaction], height: u64) -> bool {
        use rayon::prelude::*;
        const CHUNK: usize = 16;
        if txs.len() < CHUNK {
            return Self::verify_signatures_batch_at_height(txs, height);
        }
        txs.par_chunks(CHUNK)
            .all(|chunk| Self::verify_signatures_batch_at_height(chunk, height))
    }

    /// Per-transaction validity for a batch of transactions (Ed25519 batch verify
    /// with deterministic scalar fallback).
    ///
    /// Fallback semantics (TRANSACTIONS — keep the good ones): a batch MUST fail
    /// closed, but one bad neighbor must NOT sink honest transactions (mempool
    /// admission, proposer filtering and block execution all keep per-tx
    /// outcomes). So: the fast path batch-verifies everything at once; if the
    /// batch rejects, each transaction is re-checked with the scalar
    /// `verify_signature` in INPUT order and only the bad ones are marked
    /// `false`. `verify_signatures_batch(txs)` is exactly
    /// `partitioned(txs).iter().all(|b| *b)` — same verdict, with the offenders
    /// identified.
    ///
    /// Determinism: per-item validity never depends on batch ORDER (each item
    /// verifies against its own message/key); the fallback iterates input order,
    /// so the returned vector is stable for a given input regardless of which
    /// path was taken.
    ///
    /// No behavior change: element `i` of the result equals
    /// `txs[i].verify_signature()` in all cases (the batch path can only be
    /// stricter than the scalar one, never looser, and any batch rejection
    /// falls back to the scalar verdict per item).
    pub fn verify_signatures_partitioned(txs: &[Transaction]) -> Vec<bool> {
        use rayon::prelude::*;
        // FULL-PQ: classical ed batch removed. Per-item scalar PQ verdict.
        if txs.is_empty() {
            return Vec::new();
        }
        if txs.len() < 16 {
            txs.iter().map(Transaction::verify_signature).collect()
        } else {
            txs.par_iter().map(Transaction::verify_signature).collect()
        }
    }

    /// The valid subset of `txs`, in input (stable) order.
    ///
    /// Convenience over [`Self::verify_signatures_partitioned`] for proposer
    /// filtering / gossip batching: keeps every transaction whose scalar
    /// `verify_signature` passes, drops only the bad ones.
    pub fn filter_valid_transactions(txs: &[Transaction]) -> Vec<Transaction> {
        let keep = Self::verify_signatures_partitioned(txs);
        txs.iter()
            .zip(keep.iter())
            .filter(|(_, k)| **k)
            .map(|(tx, _)| tx.clone())
            .collect()
    }
}

/// Reusable per-batch transaction-hashing state (see
/// [`Transaction::batch_hasher`]). Not `Send`-critical: it holds no locks and
/// is used thread-locally inside one pass.
pub struct TxHashBatch {
    hasher: Sha256,
    payload_buf: Vec<u8>,
}

impl TxHashBatch {
    fn new() -> Self {
        Self {
            hasher: Sha256::new(),
            payload_buf: Vec::new(),
        }
    }

    /// Hash one transaction, resetting the hasher for the next call.
    pub fn hash_one(&mut self, tx: &Transaction) -> [u8; 32] {
        use sha2::Digest;
        tx.hash_into(&mut self.hasher, &mut self.payload_buf);
        self.hasher.finalize_reset().into()
    }
}
