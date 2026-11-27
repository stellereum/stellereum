//! Canonical transaction construction and Falcon-512 signing.
//!
//! # Wire contract
//!
//! Every byte here is taken from the node and pinned by `tests/parity.rs`
//! against the node's own `Transaction`:
//!
//! * `Transaction` bincode layout: `stellereum/src/sharding/transaction.rs:36-64`
//!   (frame/codec) and `:128-158` (field order).
//! * Signed message: `base_signing_message` at `transaction.rs:521-543`,
//!   payload commitment at `:553-567`, chain commitment at `:637-641`.
//! * PQ verification and address check: `transaction.rs:1210-1310`.
//! * Transaction hash: `transaction.rs:813-862`.
//! * Session (`SF1`) envelope: `transaction.rs:437-500`.
//!
//! # Fee rule
//!
//! A transaction is admitted only when
//! `gas_limit >= base_fee + failure_penalty + PQ_ACTIVATION_SURCHARGE_GAS
//! (only for explicit PQ1) + priority_fee_per_gas`
//! (`Mempool::required_fee_for_tx`, `stellereum/src/mempool.rs:1051-1073`;
//! surcharge = 45,000 at `mempool.rs:24`). The builder's default gas limit is
//! the same formula with `failure_penalty = 0`; callers that have read
//! `stell_baseFee` / `stell_estimateFee` can pass the node's exact numbers.

use sha2::{Digest as _, Sha256};

use crate::envelope::{EnvelopeMode, PqEnvelope};
use crate::error::{Result, SdkError};
use crate::governance::{GovAction, VoteChoice};
use crate::key::{
    derive_pq_address, FalconKeypair, DEFAULT_SALT, FALCON512_PUBKEY_LEN, FALCON512_SIG_LEN,
};
use crate::opcode::{encode_payload, payload_gas, Op, GAS_BASIC_TRANSFER};
use crate::protocol::ProtocolIdentity;
use crate::session::SessionGrant;

/// Chain id used by this deployment unless the node is configured otherwise
/// (`stellereum/src/zkml.rs:191`, `DEFAULT_CHAIN_ID = 5757`).
pub const DEFAULT_CHAIN_ID: u64 = 5757;

/// State-rent surcharge for a transaction that carries the raw PQ public key
/// (`stellereum/src/mempool.rs:24`).
pub const PQ_ACTIVATION_SURCHARGE_GAS: u64 = 45_000;

/// Frozen admission floor (`stellereum/src/mempool.rs:1394`).
pub const FROZEN_MIN_GAS_FLOOR: u64 = GAS_BASIC_TRANSFER;

/// Chain-id commitment tag (`stellereum/src/sharding/envelope.rs:436`).
pub const CHAIN_ID_COMMITMENT_TAG: &[u8; 8] = b"CHAIN_ID";
/// Priority-bid commitment tag (`stellereum/src/sharding/transaction.rs:39`).
pub const PRIORITY_FEE_COMMITMENT_TAG: &[u8; 8] = b"PRIORITY";
/// Payload commitment tag (`stellereum/src/sharding/transaction.rs:555`).
pub const PAYLOAD_COMMITMENT_TAG: &[u8; 7] = b"PAYLOAD";
/// Session commitment tag (`stellereum/src/sharding/transaction.rs:619`).
pub const SESSION_COMMITMENT_TAG: &[u8; 7] = b"SESSION";
/// Falcon session-envelope tag (`stellereum/src/sharding/envelope.rs:395`).
pub const SESSION_FALCON_SIG_TAG: &[u8; 3] = b"SF1";
/// Transaction-hash domain for PQ envelopes
/// (`stellereum/src/sharding/transaction.rs:885`).
pub const PQ_ENVELOPE_HASH_TAG: &[u8; 6] = b"PQ_ENV";
/// Trailing sponsor envelope tag (`stellereum/src/sharding/envelope.rs:613`).
pub const SPONSOR_SIG_TAG: &[u8; 3] = b"SP1";
/// Commitment tag bound into the user's signed message AND the tx hash for
/// sponsored transactions (`stellereum/src/sharding/envelope.rs:617`).
pub const SPONSOR_COMMITMENT_TAG: &[u8; 8] = b"SPONSOR_";
/// Domain separator for the sponsor's fee authorization signature
/// (`stellereum/src/sharding/envelope.rs:620`).
pub const SPONSOR_FEE_DOMAIN: &[u8; 14] = b"SPONSOR_FEE_V1";
/// Hard cap on decoded sponsor auth bytes (`stellereum/src/sharding/envelope.rs:625`).
pub const SPONSOR_AUTH_MAX_BYTES: usize = 4096;
/// Hard cap on allowlisted targets per sponsor grant
/// (`stellereum/src/sharding/envelope.rs:628`).
pub const SPONSOR_MAX_TARGETS: usize = 64;

/// Masterchain shard id (`stellereum/src/sharding/topology.rs:7-8`).
pub const MASTERCHAIN_SHARD: u32 = 0;

/// Post-quantum signature scheme tag matching `stellereum::post_quantum::PqScheme`.
///
/// Variant order MUST remain `Falcon512` then `MlDsa44` so `bincode`'s derived
/// `u32` variant indices match the node's `SponsorAuthorization` wire layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum PqScheme {
    /// Post-quantum Falcon-512 (897-byte public key, 666-byte signature).
    Falcon512 = 2,
    /// Disabled ML-DSA-44 tag (always rejected fail-closed).
    MlDsa44 = 3,
}

/// A sponsor's fee authorization for one transaction (`SP1` envelope,
/// `stellereum/src/sharding/envelope.rs:708-739`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SponsorAuthorization {
    pub sponsor: [u8; 32],
    pub max_fee_per_tx: u64,
    pub valid_until: u64,
    #[serde(default)]
    pub allowed_targets: Vec<[u8; 32]>,
    pub chain_id: u64,
    pub sponsor_sig: Vec<u8>,
    #[serde(default)]
    pub sponsor_scheme: Option<PqScheme>,
    #[serde(default)]
    pub sponsor_pubkey: Option<Vec<u8>>,
    #[serde(default)]
    pub sponsor_salt: Option<[u8; 16]>,
}

impl SponsorAuthorization {
    /// Serialize with `bincode`, enforcing `SPONSOR_MAX_TARGETS` and `SPONSOR_AUTH_MAX_BYTES`.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.allowed_targets.len() > SPONSOR_MAX_TARGETS {
            return Err(SdkError::InvalidArgument(format!(
                "sponsor allowed_targets has {} entries, max {SPONSOR_MAX_TARGETS}",
                self.allowed_targets.len()
            )));
        }
        let bytes = bincode::serialize(self)
            .map_err(|e| SdkError::InvalidArgument(format!("sponsor auth serialize: {e}")))?;
        if bytes.is_empty() || bytes.len() > SPONSOR_AUTH_MAX_BYTES {
            return Err(SdkError::InvalidArgument(format!(
                "sponsor auth is {} bytes, max {SPONSOR_AUTH_MAX_BYTES}",
                bytes.len()
            )));
        }
        Ok(bytes)
    }
}

/// Split the trailing `SP1` sponsor suffix off a signature blob, matching
/// `Transaction::split_sponsor_envelope` (`stellereum/src/sharding/transaction.rs:1614-1652`).
///
/// Returns `(inner_len, auth, malformed)`.
pub fn split_sponsor_envelope(blob: &[u8]) -> (usize, Option<SponsorAuthorization>, bool) {
    let tag_len = SPONSOR_SIG_TAG.len();
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
    if inner_len < 64 {
        return (blob.len(), None, true);
    }
    let auth_bytes = &blob[inner_len..len_off];
    match bincode::deserialize::<SponsorAuthorization>(auth_bytes) {
        Ok(auth) => {
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

/// Exact preimage signed by the sponsor (`Transaction::sponsor_message`).
pub fn sponsor_message(tx: &Transaction, auth: &SponsorAuthorization) -> Vec<u8> {
    tx.sponsor_message(auth)
}

/// Exact preimage signed by the user for a sponsored transaction
/// (`base_signing_message` + `SPONSOR_` commitment).
pub fn sponsored_signing_message(tx: &Transaction, auth: &SponsorAuthorization) -> Vec<u8> {
    tx.sponsored_signing_message(auth)
}

/// A canonical Stellereum transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub from: [u8; 32],
    pub to: [u8; 32],
    pub amount: u64,
    pub gas_limit: u64,
    pub nonce: u64,
    pub source_shard: u32,
    pub target_shard: u32,
    /// Envelope/signature blob WITHOUT the trailing priority suffix, exactly
    /// like the node's in-memory field after `split_priority_envelope`
    /// (`stellereum/src/sharding/transaction.rs:147-172`).
    pub signature: Vec<u8>,
    /// Bincode `Vec<OpCode>` bytes (may be empty). This is the FULL bincode
    /// encoding, including its `u64` element count. Builders always set it
    /// with `opcode::encode_payload`; hand-built transactions must do the
    /// same (an empty `Vec<OpCode>` is eight zero bytes, not zero bytes).
    pub payload: Vec<u8>,
    pub priority_fee_per_gas: u64,
}

impl Transaction {
    /// Wire bytes (`bincode` of the node's `Transaction`). This is what
    /// `stell_sendRawTransaction` decodes (`stellereum/src/rpc/writes.rs:695-707`).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(&self.from);
        out.extend_from_slice(&self.to);
        out.extend_from_slice(&self.amount.to_le_bytes());
        out.extend_from_slice(&self.gas_limit.to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out.extend_from_slice(&self.source_shard.to_le_bytes());
        out.extend_from_slice(&self.target_shard.to_le_bytes());
        let sig = self.wire_signature();
        out.extend_from_slice(&(sig.len() as u64).to_le_bytes());
        out.extend_from_slice(&sig);
        // `self.payload` is already `bincode(Vec<OpCode>)`: the u64 count
        // followed by the elements. `TransactionWire` serializes that Vec
        // directly, so do NOT prepend another length here. A hand-built
        // transaction with an empty buffer is treated as an empty Vec.
        if self.payload.is_empty() {
            out.extend_from_slice(&0u64.to_le_bytes());
        } else {
            out.extend_from_slice(&self.payload);
        }
        out
    }

    /// Decode the node's `bincode(Transaction)` wire form.
    ///
    /// The payload is kept as its opaque bincode `Vec<OpCode>` bytes (the SDK
    /// does not decode every opcode), exactly like the in-memory field. The
    /// trailing `PRIORITY` envelope is split off the signature blob the same
    /// way the node does it.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut cur = bytes;
        fn take<'a>(cur: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
            if cur.len() < n {
                return Err(SdkError::Decode("truncated transaction".into()));
            }
            let (head, tail) = cur.split_at(n);
            *cur = tail;
            Ok(head)
        }
        fn array32(cur: &mut &[u8]) -> Result<[u8; 32]> {
            let mut out = [0u8; 32];
            out.copy_from_slice(take(cur, 32)?);
            Ok(out)
        }
        fn u64le(cur: &mut &[u8]) -> Result<u64> {
            let mut b = [0u8; 8];
            b.copy_from_slice(take(cur, 8)?);
            Ok(u64::from_le_bytes(b))
        }
        fn u32le(cur: &mut &[u8]) -> Result<u32> {
            let mut b = [0u8; 4];
            b.copy_from_slice(take(cur, 4)?);
            Ok(u32::from_le_bytes(b))
        }
        let from = array32(&mut cur)?;
        let to = array32(&mut cur)?;
        let amount = u64le(&mut cur)?;
        let gas_limit = u64le(&mut cur)?;
        let nonce = u64le(&mut cur)?;
        let source_shard = u32le(&mut cur)?;
        let target_shard = u32le(&mut cur)?;
        let sig_len = usize::try_from(u64le(&mut cur)?)
            .map_err(|_| SdkError::Decode("signature length exceeds usize".into()))?;
        let blob = take(&mut cur, sig_len)?.to_vec();
        let (signature, priority_fee_per_gas) = split_priority_envelope(&blob);
        let payload = cur.to_vec();
        Ok(Self {
            from,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            signature,
            payload,
            priority_fee_per_gas,
        })
    }

    /// Signature blob with the optional trailing `PRIORITY` suffix.
    fn wire_signature(&self) -> Vec<u8> {
        if self.priority_fee_per_gas == 0 {
            return self.signature.clone();
        }
        let mut out = Vec::with_capacity(self.signature.len() + 16);
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(PRIORITY_FEE_COMMITMENT_TAG);
        out.extend_from_slice(&self.priority_fee_per_gas.to_be_bytes());
        out
    }

    /// Split the trailing `SP1` sponsor suffix off a signature blob.
    pub fn split_sponsor_envelope(blob: &[u8]) -> (usize, Option<SponsorAuthorization>, bool) {
        split_sponsor_envelope(blob)
    }

    /// Strip the optional trailing `SP1` sponsor suffix and return the inner
    /// signature slice (or the full signature when no well-formed suffix is
    /// present).
    pub fn sponsor_inner_sig(&self) -> &[u8] {
        let (inner_len, _, _) = split_sponsor_envelope(&self.signature);
        &self.signature[..inner_len]
    }

    /// True when the trailing `SP1` sponsor tag is present, regardless of
    /// whether the suffix parses.
    pub fn has_sponsor_envelope(&self) -> bool {
        let b = &self.signature;
        b.len() > SPONSOR_SIG_TAG.len() + 4
            && b[b.len() - SPONSOR_SIG_TAG.len()..] == SPONSOR_SIG_TAG[..]
    }

    /// True when the `SP1` suffix is present but malformed (must fail closed).
    pub fn sponsor_malformed(&self) -> bool {
        split_sponsor_envelope(&self.signature).2
    }

    /// Parsed sponsor authorization when a well-formed `SP1` suffix is present.
    pub fn sponsor_auth(&self) -> Option<SponsorAuthorization> {
        split_sponsor_envelope(&self.signature).1
    }

    /// True when a well-formed `SP1` sponsor suffix is present.
    pub fn is_sponsored(&self) -> bool {
        self.sponsor_auth().is_some()
    }

    /// The exact preimage the sponsor signs (`Transaction::sponsor_message`).
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
        let payload = self.payload_bytes_normalized();
        msg.extend_from_slice(PAYLOAD_COMMITMENT_TAG);
        msg.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        msg.extend_from_slice(payload);
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

    /// The exact preimage the user signs for a sponsored transaction:
    /// `base_signing_message` + `SPONSOR_` commitment.
    pub fn sponsored_signing_message(&self, auth: &SponsorAuthorization) -> Vec<u8> {
        let mut msg = self.base_signing_message();
        msg.extend_from_slice(&sponsor_commitment(auth));
        msg
    }

    /// Verify only the sponsor's Falcon-512 signature over `sponsor_message`.
    pub fn verify_sponsor_sig(&self, auth: &SponsorAuthorization) -> bool {
        if auth.sponsor_sig.len() != FALCON512_SIG_LEN {
            return false;
        }
        if auth.sponsor_scheme != Some(PqScheme::Falcon512) {
            return false;
        }
        let Some(ref pk) = auth.sponsor_pubkey else {
            return false;
        };
        if pk.len() != FALCON512_PUBKEY_LEN {
            return false;
        }
        let salt = auth.sponsor_salt.unwrap_or(DEFAULT_SALT);
        let Ok(derived) = derive_pq_address(pk, &salt) else {
            return false;
        };
        if derived != auth.sponsor {
            return false;
        }
        crate::key::verify_pq_signature(pk, &self.sponsor_message(auth), &auth.sponsor_sig)
    }

    /// The exact preimage the credential signs.
    ///
    /// Matches the node's `Transaction::signing_message()`
    /// (`transaction.rs:1438-1475`) for PQ1, SF1, and SP1-sponsored envelopes.
    pub fn signing_message(&self) -> Vec<u8> {
        let mut msg = self.base_signing_message();
        let (inner_len, sponsor_auth, _) = split_sponsor_envelope(&self.signature);
        let inner = &self.signature[..inner_len];
        if let Some(grant) = session_grant_from_inner(inner) {
            msg.extend_from_slice(&session_commitment(&grant));
        } else if sponsor_auth.is_none() {
            if let Some(cid) = pq_envelope_from_inner(inner).and_then(|e| e.chain_id) {
                msg.extend_from_slice(CHAIN_ID_COMMITMENT_TAG);
                msg.extend_from_slice(&cid.to_be_bytes());
            }
        }
        if let Some(ref auth) = sponsor_auth {
            msg.extend_from_slice(&sponsor_commitment(auth));
        }
        msg
    }

    /// Signing message for a chain id before the envelope is attached.
    pub fn signing_message_for_chain(&self, chain_id: u64) -> Vec<u8> {
        let mut msg = self.base_signing_message();
        msg.extend_from_slice(CHAIN_ID_COMMITMENT_TAG);
        msg.extend_from_slice(&chain_id.to_be_bytes());
        msg
    }

    /// Signing message for a delegated transaction before the `SF1`
    /// envelope is attached: base + `SESSION` commitment.
    pub fn signing_message_with_session(&self, grant: &SessionGrant) -> Vec<u8> {
        let mut msg = self.base_signing_message();
        msg.extend_from_slice(&session_commitment(grant));
        msg
    }

    fn payload_bytes_normalized(&self) -> &[u8] {
        if self.payload.is_empty() {
            &[0u8; 8]
        } else {
            &self.payload
        }
    }

    fn base_signing_message(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(128);
        msg.extend_from_slice(&self.from);
        msg.extend_from_slice(&self.to);
        msg.extend_from_slice(&self.amount.to_be_bytes());
        msg.extend_from_slice(&self.gas_limit.to_be_bytes());
        msg.extend_from_slice(&self.nonce.to_be_bytes());
        msg.extend_from_slice(&self.source_shard.to_be_bytes());
        msg.extend_from_slice(&self.target_shard.to_be_bytes());
        let payload = self.payload_bytes_normalized();
        msg.extend_from_slice(PAYLOAD_COMMITMENT_TAG);
        msg.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        msg.extend_from_slice(payload);
        if self.priority_fee_per_gas != 0 {
            msg.extend_from_slice(PRIORITY_FEE_COMMITMENT_TAG);
            msg.extend_from_slice(&self.priority_fee_per_gas.to_be_bytes());
        }
        msg
    }

    /// Parse the `PQ1` envelope, if this is a PQ transaction (stripping any
    /// trailing `SP1` sponsor suffix).
    pub fn pq_envelope(&self) -> Option<PqEnvelope> {
        pq_envelope_from_inner(self.sponsor_inner_sig())
    }

    /// Parse the `SF1` session grant, if this is a session transaction
    /// (stripping any trailing `SP1` sponsor suffix).
    pub fn session_grant(&self) -> Option<SessionGrant> {
        session_grant_from_inner(self.sponsor_inner_sig())
    }

    /// The credential's chain id: `auth.chain_id` for `SP1`, `grant.chain_id`
    /// for `SF1`, `envelope.chain_id` for `PQ1`, or `None` for unbound.
    pub fn chain_id(&self) -> Option<u64> {
        let (inner_len, sponsor_auth, _) = split_sponsor_envelope(&self.signature);
        if let Some(auth) = sponsor_auth {
            return Some(auth.chain_id);
        }
        let inner = &self.signature[..inner_len];
        if let Some(g) = session_grant_from_inner(inner) {
            return Some(g.chain_id);
        }
        pq_envelope_from_inner(inner).and_then(|e| e.chain_id)
    }

    /// True for an explicit PQ1 activation transaction (the node only charges
    /// the surcharge for these, `mempool.rs:1066-1072`).
    pub fn is_pq_activation(&self) -> bool {
        self.pq_envelope().map(|e| e.is_explicit()).unwrap_or(false)
    }

    /// Canonical SHA-256 transaction hash, byte-identical to
    /// `Transaction::compute_tx_hash` (`transaction.rs:847-936`).
    pub fn compute_tx_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.from);
        h.update(self.to);
        h.update(self.amount.to_be_bytes());
        h.update(self.gas_limit.to_be_bytes());
        h.update(self.nonce.to_be_bytes());
        h.update(self.source_shard.to_be_bytes());
        h.update(self.target_shard.to_be_bytes());
        let payload = self.payload_bytes_normalized();
        h.update(PAYLOAD_COMMITMENT_TAG);
        h.update((payload.len() as u32).to_be_bytes());
        h.update(payload);
        if self.priority_fee_per_gas != 0 {
            h.update(PRIORITY_FEE_COMMITMENT_TAG);
            h.update(self.priority_fee_per_gas.to_be_bytes());
        }
        let (inner_len, sponsor_auth, _) = split_sponsor_envelope(&self.signature);
        let inner_sig = &self.signature[..inner_len];
        if let Some(grant) = session_grant_from_inner(inner_sig) {
            h.update(session_commitment(&grant));
        }
        if let Some(ref auth) = sponsor_auth {
            h.update(sponsor_commitment(auth));
        }
        // `is_pq_inner()` is true iff the inner signature starts with "PQ1",
        // and the node hashes the full `self.signature` (including any `SP1` suffix).
        if inner_sig.starts_with(crate::envelope::PQ_ENVELOPE_MAGIC) {
            h.update(PQ_ENVELOPE_HASH_TAG);
            h.update(&self.signature);
        }
        h.finalize().into()
    }
}

fn pq_envelope_from_inner(inner: &[u8]) -> Option<PqEnvelope> {
    if !inner.starts_with(crate::envelope::PQ_ENVELOPE_MAGIC) {
        return None;
    }
    PqEnvelope::decode(inner).ok()
}

fn session_grant_from_inner(inner: &[u8]) -> Option<SessionGrant> {
    let sig_len = FALCON512_SIG_LEN;
    let tag_len = SESSION_FALCON_SIG_TAG.len();
    if inner.len() <= sig_len + tag_len {
        return None;
    }
    if &inner[sig_len..sig_len + tag_len] != SESSION_FALCON_SIG_TAG {
        return None;
    }
    SessionGrant::decode(&inner[sig_len + tag_len..]).ok()
}

fn session_commitment(grant: &SessionGrant) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(SESSION_COMMITMENT_TAG);
    match grant.encode() {
        Ok(bytes) => {
            out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(&bytes);
        }
        Err(_) => out.extend_from_slice(&u32::MAX.to_be_bytes()),
    }
    out
}

fn sponsor_commitment(auth: &SponsorAuthorization) -> Vec<u8> {
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

fn encode_sponsor_suffix(auth: &SponsorAuthorization) -> Result<Vec<u8>> {
    let body = auth.encode()?;
    let mut out = Vec::with_capacity(body.len() + 4 + SPONSOR_SIG_TAG.len());
    out.extend_from_slice(&body);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(SPONSOR_SIG_TAG);
    Ok(out)
}

/// Split the optional trailing `PRIORITY` envelope off a signature blob,
/// exactly like `Transaction::split_priority_envelope`.
fn split_priority_envelope(blob: &[u8]) -> (Vec<u8>, u64) {
    const ENVELOPE_LEN: usize = PRIORITY_FEE_COMMITMENT_TAG.len() + 8;
    if blob.len() >= ENVELOPE_LEN {
        let split = blob.len() - ENVELOPE_LEN;
        if &blob[split..split + PRIORITY_FEE_COMMITMENT_TAG.len()] == PRIORITY_FEE_COMMITMENT_TAG {
            let mut bid = [0u8; 8];
            bid.copy_from_slice(&blob[split + PRIORITY_FEE_COMMITMENT_TAG.len()..]);
            return (blob[..split].to_vec(), u64::from_be_bytes(bid));
        }
    }
    (blob.to_vec(), 0)
}

/// Attach a `PQ1` envelope to an UNSIGNED transaction, validating against
/// [`ProtocolIdentity::local`].
///
/// Used when the caller targets the compiled-in default chain identity; see
/// [`sign_unsigned_with_identity`] when an explicit [`ProtocolIdentity`] is
/// supplied.
pub fn sign_unsigned(
    tx: Transaction,
    key: &FalconKeypair,
    mode: EnvelopeMode,
    chain_id: Option<u64>,
) -> Result<SignedTx> {
    sign_unsigned_with_identity(tx, key, mode, ProtocolIdentity::local(), chain_id)
}

/// Attach a `PQ1` envelope to an UNSIGNED transaction, validating against the
/// caller-supplied [`ProtocolIdentity`].
///
/// Used by the signer sidecar's `sign_prepared` arm: the TypeScript package
/// builds the unsigned transaction bytes, the Rust process owns the Falcon
/// key and produces the envelope. Refuses an `SF1` payload here (session
/// grants need the grant object, not a bare envelope).
pub fn sign_unsigned_with_identity(
    mut tx: Transaction,
    key: &FalconKeypair,
    mode: EnvelopeMode,
    identity: ProtocolIdentity,
    chain_id: Option<u64>,
) -> Result<SignedTx> {
    if !tx.signature.is_empty() {
        return Err(SdkError::InvalidArgument(
            "sign_unsigned expects an unsigned transaction (empty signature)".into(),
        ));
    }
    if tx.from != key.address() {
        return Err(SdkError::InvalidArgument(format!(
            "unsigned transaction from 0x{} is not the signing key's address 0x{}",
            hex::encode(tx.from),
            hex::encode(key.address())
        )));
    }
    identity.verify()?;
    if let Some(cid) = chain_id {
        identity.verify_chain_id(cid)?;
    }
    let msg = match chain_id {
        Some(cid) => tx.signing_message_for_chain(cid),
        None => tx.signing_message(),
    };
    let sig = key.sign(&msg)?;
    let envelope = match mode {
        EnvelopeMode::Explicit => match chain_id {
            Some(cid) => PqEnvelope::explicit_with_chain(key.public_key().to_vec(), sig, cid),
            None => PqEnvelope::explicit(key.public_key().to_vec(), sig),
        },
        EnvelopeMode::Implicit => match chain_id {
            Some(cid) => PqEnvelope::implicit_with_chain(sig, cid),
            None => PqEnvelope::implicit(sig),
        },
    };
    tx.signature = envelope.encode()?;
    let signed = SignedTx { tx };
    signed
        .verify_with_key(key)
        .map_err(|e| SdkError::VerificationFailed(e.to_string()))?;
    Ok(signed)
}

/// Builder for the four wallet shapes in scope.
///
/// All setters are chainable and consume `self`.
#[derive(Clone, Debug)]
pub struct TxBuilder {
    to: Option<[u8; 32]>,
    amount: u64,
    ops: Vec<Op>,
    nonce: u64,
    source_shard: u32,
    target_shard: u32,
    chain_id: Option<u64>,
    identity: ProtocolIdentity,
    mode: EnvelopeMode,
    gas_limit: Option<u64>,
    base_fee: u64,
    priority_fee_per_gas: u64,
}

impl TxBuilder {
    fn payload_builder(ops: Vec<Op>, amount: u64) -> Self {
        Self {
            to: None,
            amount,
            ops,
            nonce: 0,
            source_shard: MASTERCHAIN_SHARD,
            target_shard: MASTERCHAIN_SHARD,
            chain_id: Some(DEFAULT_CHAIN_ID),
            identity: ProtocolIdentity::local(),
            mode: EnvelopeMode::Explicit,
            gas_limit: None,
            base_fee: FROZEN_MIN_GAS_FLOOR,
            priority_fee_per_gas: 0,
        }
    }

    /// A payload-only transaction (used by the EVM and governance builders).
    pub(crate) fn payload_tx(ops: Vec<Op>, amount: u64) -> Self {
        Self::payload_builder(ops, amount)
    }

    /// Make the transaction self-addressed (`to == from`), the convention for
    /// claims and governance ops that move no tokens.
    pub(crate) fn self_addressed(mut self) -> Self {
        self.to = None;
        self
    }

    /// Native transfer `{ to, amount }` (empty SVM payload).
    pub fn transfer(to: [u8; 32], amount: u64) -> Self {
        let mut b = Self::payload_builder(Vec::new(), amount);
        b.to = Some(to);
        b
    }

    /// Deploy a WASM smart contract (`OpCode::SysCallDeployContract`).
    /// Self-addressed (`to == from`) with `amount == 0`.
    pub fn contract_deploy(code: Vec<u8>) -> Self {
        Self::payload_builder(vec![Op::DeployContract { code }], 0)
    }

    /// Deploy a WASM smart contract with an inline JSON ABI manifest
    /// (`OpCode::SysCallDeployContractWithAbi`, discriminant 65).
    /// Self-addressed (`to == from`) with `amount == 0`.
    pub fn contract_deploy_with_abi(code: Vec<u8>, abi_json: Vec<u8>) -> Self {
        Self::payload_builder(vec![Op::DeployContractWithAbi { code, abi_json }], 0)
    }

    /// Call a WASM contract method with typed ABI arguments. `value` is the
    /// native amount sent with the call (rides in `Transaction.amount`).
    pub fn contract_call(
        contract: [u8; 32],
        method: &str,
        args: &[crate::opcode::CallArg],
        value: u64,
    ) -> Result<Self> {
        let op = Op::call(contract, method, args)?;
        let mut b = Self::payload_builder(vec![op], value);
        b.to = Some(contract);
        Ok(b)
    }

    /// Call a WASM contract method with raw `host.calldata` bytes (for `*_pq`
    /// entrypoints that decode binary layouts directly). `value` is the native
    /// amount sent with the call (rides in `Transaction.amount`).
    pub fn contract_call_raw(
        contract: [u8; 32],
        method: &str,
        args: &[i64],
        calldata: Vec<u8>,
        value: u64,
    ) -> Result<Self> {
        let op = Op::call_raw(contract, method, args, calldata)?;
        let mut b = Self::payload_builder(vec![op], value);
        b.to = Some(contract);
        Ok(b)
    }

    /// Bond (or top up) a validator. The amount leaves the sender.
    pub fn stake(validator: [u8; 32], amount: u64) -> Self {
        Self::payload_builder(vec![Op::Stake { validator, amount }], amount)
    }

    /// Bond (or top up) a validator with an explicit commission rate in basis
    /// points (`<= 10_000`). The amount leaves the sender.
    pub fn stake_with_commission(
        validator: [u8; 32],
        amount: u64,
        commission_bps: u64,
    ) -> Result<Self> {
        if commission_bps > 10_000 {
            return Err(SdkError::InvalidArgument(format!(
                "commission_bps {commission_bps} exceeds 10_000"
            )));
        }
        Ok(Self::payload_builder(
            vec![Op::StakeWithCommission {
                validator,
                amount,
                commission_bps,
            }],
            amount,
        ))
    }

    /// Re-admit a jailed validator. `top_up` emits the CLI's `SysCallStake`
    /// before `SysCallUnjail` in the same payload
    /// (`stellereum/src/cli/tx_builders.rs:205-226`).
    pub fn unjail(validator: [u8; 32], top_up: Option<u64>) -> Self {
        let mut ops = Vec::with_capacity(2);
        let amount = match top_up {
            Some(0) => 0,
            Some(a) => {
                ops.push(Op::Stake {
                    validator,
                    amount: a,
                });
                a
            }
            None => 0,
        };
        ops.push(Op::Unjail { validator });
        Self::payload_builder(ops, amount)
    }

    /// Sender nonce. Read it with [`crate::rpc::RpcClient::nonce`].
    pub fn nonce(mut self, nonce: u64) -> Self {
        self.nonce = nonce;
        self
    }

    /// Override the gas limit. By default the builder uses
    /// `max(opcode_gas, base_fee) + activation_surcharge + priority_fee`.
    pub fn gas_limit(mut self, gas_limit: u64) -> Self {
        self.gas_limit = Some(gas_limit);
        self
    }

    /// Base fee to price against (default: the frozen 280,000 floor).
    pub fn base_fee(mut self, base_fee: u64) -> Self {
        self.base_fee = base_fee;
        self
    }

    /// Explicit priority bid. It is signed and must be covered by `gas_limit`.
    pub fn priority_fee_per_gas(mut self, bid: u64) -> Self {
        self.priority_fee_per_gas = bid;
        self
    }

    /// Bind to a chain id (default [`DEFAULT_CHAIN_ID`]).
    ///
    /// The id is checked against the configured [`ProtocolIdentity`] when the
    /// builder signs: a foreign chain id is refused with
    /// [`SdkError::ChainIdMismatch`] instead of producing bytes the node will
    /// reject.
    pub fn chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = Some(chain_id);
        self
    }

    /// Configure the identity of the node this builder targets.
    ///
    /// [`ProtocolIdentity::local`] is the default. Pass the node's advertised
    /// identity (when the RPC exposes it) to make a stale wallet fail loudly:
    /// a different fork id, protocol version or chain id is refused with a
    /// specific [`SdkError`] before anything is signed.
    pub fn identity(mut self, identity: ProtocolIdentity) -> Self {
        self.identity = identity;
        if self.chain_id.is_none() {
            self.chain_id = Some(identity.chain_id);
        }
        self
    }

    /// Block-carried governance proposal.
    ///
    /// `proposal_id` MUST be the `next_id` the chain will hold when the
    /// transaction applies, and `height_observed` MUST be the block height it
    /// applies at (the node refuses any other height: no cross-height
    /// replay). The transaction sender (`tx.from`, filled from the signing
    /// key) is the proposer; `to == from`, `amount == 0`.
    pub fn gov_propose(
        proposal_id: u64,
        title: String,
        action: GovAction,
        height_observed: u64,
    ) -> Result<Self> {
        if title.len() > crate::governance::MAX_PROPOSAL_TITLE_BYTES {
            return Err(SdkError::InvalidArgument(format!(
                "proposal title is {} bytes, max {}",
                title.len(),
                crate::governance::MAX_PROPOSAL_TITLE_BYTES
            )));
        }
        action.validate()?;
        Ok(Self::payload_tx(
            vec![Op::GovPropose {
                proposal_id,
                title,
                action,
                height_observed,
            }],
            0,
        )
        .self_addressed())
    }

    /// Block-carried governance vote. The sender is the voter.
    ///
    /// The voting window, one-vote rule and weight snapshot are enforced by
    /// the node at apply (a vote for an unknown/closed proposal refuses
    /// there); the builder only pins the proposal and the height.
    pub fn gov_vote(proposal_id: u64, choice: VoteChoice, height_observed: u64) -> Self {
        Self::payload_tx(
            vec![Op::GovVote {
                proposal_id,
                choice,
                height_observed,
            }],
            0,
        )
        .self_addressed()
    }

    /// Build an UNBOUND envelope (no replay domain). The node currently
    /// admits these with a warning and a metric until a scheduled activation
    /// height, then refuses them (`stellereum/src/chain_binding.rs:1-60`).
    /// Never use this in production.
    pub fn unbound(mut self) -> Self {
        eprintln!(
            "WARNING stellereum-sdk: building an UNBOUND (replayable) transaction; \
             bind to chain_id {} unless you are deliberately testing legacy admission",
            DEFAULT_CHAIN_ID
        );
        self.chain_id = None;
        self
    }

    /// Use an implicit `PQ1` envelope (public key omitted). Only valid after
    /// the address's key is registered; the activation surcharge is not
    /// charged for these.
    pub fn implicit(mut self) -> Self {
        self.mode = EnvelopeMode::Implicit;
        self
    }

    /// Use an explicit `PQ1` envelope (the default).
    pub fn explicit(mut self) -> Self {
        self.mode = EnvelopeMode::Explicit;
        self
    }

    /// Override shards (default masterchain -> masterchain).
    pub fn shards(mut self, source: u32, target: u32) -> Self {
        self.source_shard = source;
        self.target_shard = target;
        self
    }

    /// Override the recipient. Payload-only shapes default to the sender.
    pub fn to(mut self, to: [u8; 32]) -> Self {
        self.to = Some(to);
        self
    }

    /// True when the builder will bind a chain id.
    pub fn is_bound(&self) -> bool {
        self.chain_id.is_some()
    }

    /// The gas limit this builder will use.
    pub fn effective_gas_limit(&self) -> u64 {
        self.gas_limit.unwrap_or_else(|| {
            let exec = if self.ops.is_empty() {
                GAS_BASIC_TRANSFER
            } else {
                payload_gas(&self.ops)
            };
            let surcharge = if self.mode == EnvelopeMode::Explicit {
                PQ_ACTIVATION_SURCHARGE_GAS
            } else {
                0
            };
            exec.max(self.base_fee)
                .max(FROZEN_MIN_GAS_FLOOR)
                .saturating_add(surcharge)
                .saturating_add(self.priority_fee_per_gas)
        })
    }

    /// Refuse a chain/fork that does not match the configured node identity.
    fn validate_identity(&self) -> Result<()> {
        self.identity.verify()?;
        if let Some(cid) = self.chain_id {
            self.identity.verify_chain_id(cid)?;
        }
        Ok(())
    }

    fn unsigned(&self, from: [u8; 32], to: [u8; 32]) -> Transaction {
        Transaction {
            from,
            to,
            amount: self.amount,
            gas_limit: self.effective_gas_limit(),
            nonce: self.nonce,
            source_shard: self.source_shard,
            target_shard: self.target_shard,
            signature: Vec::new(),
            payload: encode_payload(&self.ops),
            priority_fee_per_gas: self.priority_fee_per_gas,
        }
    }

    /// The UNSIGNED transaction this builder would sign for `from` (the
    /// sender's 32-byte address). Exposed for byte-parity vectors and
    /// alternate signers; `sign` is the normal path.
    pub fn unsigned_transaction(&self, from: [u8; 32]) -> Transaction {
        let to = self.to.unwrap_or(from);
        self.unsigned(from, to)
    }

    /// Sign with a first-party Falcon-512 key (`PQ1` envelope).
    pub fn sign(self, key: &FalconKeypair) -> Result<SignedTx> {
        self.validate_identity()?;
        let from = key.address();
        let to = self.to.unwrap_or(from);
        let mut tx = self.unsigned(from, to);
        if self.mode == EnvelopeMode::Implicit && self.chain_id.is_none() {
            // The node's implicit envelope can be unbound too; this is only a
            // documentation guard, not a refusal.
        }
        let msg = match self.chain_id {
            Some(cid) => tx.signing_message_for_chain(cid),
            None => tx.signing_message(),
        };
        let sig = key.sign(&msg)?;
        let envelope = match self.mode {
            EnvelopeMode::Explicit => match self.chain_id {
                Some(cid) => PqEnvelope::explicit_with_chain(key.public_key().to_vec(), sig, cid),
                None => PqEnvelope::explicit(key.public_key().to_vec(), sig),
            },
            EnvelopeMode::Implicit => match self.chain_id {
                Some(cid) => PqEnvelope::implicit_with_chain(sig, cid),
                None => PqEnvelope::implicit(sig),
            },
        };
        tx.signature = envelope.encode()?;
        let signed = SignedTx { tx };
        signed
            .verify_with_key(key)
            .map_err(|e| SdkError::VerificationFailed(e.to_string()))?;
        Ok(signed)
    }

    /// Required session-grant scope bits for this builder's payload, matching
    /// `Transaction::required_scope` (`stellereum/src/sharding/transaction.rs:1531`).
    pub fn required_scope(&self) -> u64 {
        if self.ops.is_empty() {
            crate::session::SCOPE_TRANSFER
        } else {
            // Note: `Op` in `opcode.rs` does not currently define an actor-send
            // variant (`SysCallActorSend`); if one is added, it must require
            // `crate::session::SCOPE_SVM_PAYLOAD | crate::session::SCOPE_ACTOR_SEND`.
            crate::session::SCOPE_SVM_PAYLOAD
        }
    }

    /// Sign with a delegated Falcon-512 session key (`SF1` envelope).
    ///
    /// `tx.from` is the grant's master address; the nonce, balance and fee
    /// are the master account's. The grant must be minted for `session_key`
    /// and for the same chain id the builder binds.
    pub fn sign_with_session(
        self,
        session_key: &FalconKeypair,
        grant: &SessionGrant,
    ) -> Result<SignedTx> {
        self.validate_identity()?;
        if !grant.verify_master() {
            return Err(SdkError::VerificationFailed(
                "session grant's master signature does not verify".into(),
            ));
        }
        if grant.session_pubkey_bytes != session_key.public_key() {
            return Err(SdkError::InvalidArgument(
                "session key does not match the grant's session_pubkey_bytes".into(),
            ));
        }
        let derived_session = derive_pq_address(&grant.session_pubkey_bytes, &DEFAULT_SALT)?;
        if derived_session != grant.session_pubkey {
            return Err(SdkError::InvalidArgument(
                "session key address does not match the grant's session_pubkey".into(),
            ));
        }
        if let Some(cid) = self.chain_id {
            if cid != grant.chain_id {
                return Err(SdkError::InvalidArgument(format!(
                    "builder chain_id {cid} != grant chain_id {}",
                    grant.chain_id
                )));
            }
        }
        let required = self.required_scope();
        if !grant.grants_scope(required) {
            return Err(SdkError::InvalidArgument(format!(
                "grant scope 0x{:x} does not cover required scope 0x{required:x}",
                grant.scope
            )));
        }
        if self.amount > grant.max_value_per_tx {
            return Err(SdkError::InvalidArgument(format!(
                "amount {} exceeds grant max_value_per_tx {}",
                self.amount, grant.max_value_per_tx
            )));
        }
        let grant_bytes = grant.encode()?;
        let from = grant.master_address;
        let to = self.to.unwrap_or(from);
        let mut tx = self.unsigned(from, to);
        let msg = tx.signing_message_with_session(grant);
        let sig = session_key.sign(&msg)?;
        let mut signature =
            Vec::with_capacity(sig.len() + SESSION_FALCON_SIG_TAG.len() + grant_bytes.len());
        signature.extend_from_slice(&sig);
        signature.extend_from_slice(SESSION_FALCON_SIG_TAG);
        signature.extend_from_slice(&grant_bytes);
        tx.signature = signature;
        let signed = SignedTx { tx };
        signed
            .verify_session(session_key)
            .map_err(|e| SdkError::VerificationFailed(e.to_string()))?;
        Ok(signed)
    }

    /// Sign a FULL-PQ Paymaster v2 sponsored transaction (`PQ1` user inner +
    /// `SP1` Falcon-512 sponsor suffix), matching
    /// `Transaction::sign_with_sponsor_falcon512`.
    ///
    /// The sponsor signs `sponsor_message` first, then the user signs
    /// `sponsored_signing_message` (which commits to the full `SponsorAuthorization`
    /// including `sponsor_sig`).
    pub fn sign_with_sponsor(
        self,
        user_key: &FalconKeypair,
        sponsor_key: &FalconKeypair,
        max_fee_per_tx: u64,
        valid_until: u64,
        allowed_targets: Vec<[u8; 32]>,
    ) -> Result<SignedTx> {
        self.validate_identity()?;
        let chain_id = self.chain_id.ok_or_else(|| {
            SdkError::InvalidArgument("sponsored transactions require a chain_id".into())
        })?;
        if allowed_targets.len() > SPONSOR_MAX_TARGETS {
            return Err(SdkError::InvalidArgument(format!(
                "allowed_targets has {} entries, max {SPONSOR_MAX_TARGETS}",
                allowed_targets.len()
            )));
        }
        let from = user_key.address();
        let to = self.to.unwrap_or(from);
        let mut tx = self.unsigned(from, to);
        let mut auth = SponsorAuthorization {
            sponsor: sponsor_key.address(),
            max_fee_per_tx,
            valid_until,
            allowed_targets,
            chain_id,
            sponsor_sig: Vec::new(),
            sponsor_scheme: Some(PqScheme::Falcon512),
            sponsor_pubkey: Some(sponsor_key.public_key().to_vec()),
            sponsor_salt: Some(DEFAULT_SALT),
        };
        let sponsor_msg = tx.sponsor_message(&auth);
        auth.sponsor_sig = sponsor_key.sign(&sponsor_msg)?;
        let user_msg = tx.sponsored_signing_message(&auth);
        let user_sig = user_key.sign(&user_msg)?;
        let envelope = match self.mode {
            EnvelopeMode::Explicit => {
                PqEnvelope::explicit(user_key.public_key().to_vec(), user_sig)
            }
            EnvelopeMode::Implicit => PqEnvelope::implicit(user_sig),
        };
        let mut blob = envelope.encode()?;
        blob.extend_from_slice(&encode_sponsor_suffix(&auth)?);
        tx.signature = blob;
        let signed = SignedTx { tx };
        signed
            .verify_with_key(user_key)
            .map_err(|e| SdkError::VerificationFailed(e.to_string()))?;
        Ok(signed)
    }

    /// Sign the user half of a sponsored transaction given a pre-signed
    /// [`SponsorAuthorization`] from the paymaster.
    pub fn sign_with_sponsor_auth(
        self,
        user_key: &FalconKeypair,
        auth: &SponsorAuthorization,
    ) -> Result<SignedTx> {
        self.validate_identity()?;
        let chain_id = self.chain_id.ok_or_else(|| {
            SdkError::InvalidArgument("sponsored transactions require a chain_id".into())
        })?;
        if chain_id != auth.chain_id {
            return Err(SdkError::InvalidArgument(format!(
                "builder chain_id {chain_id} != sponsor auth chain_id {}",
                auth.chain_id
            )));
        }
        if auth.allowed_targets.len() > SPONSOR_MAX_TARGETS {
            return Err(SdkError::InvalidArgument(format!(
                "allowed_targets has {} entries, max {SPONSOR_MAX_TARGETS}",
                auth.allowed_targets.len()
            )));
        }
        let from = user_key.address();
        let to = self.to.unwrap_or(from);
        let mut tx = self.unsigned(from, to);
        if !tx.verify_sponsor_sig(auth) {
            return Err(SdkError::VerificationFailed(
                "sponsor authorization signature does not verify for this transaction".into(),
            ));
        }
        let user_msg = tx.sponsored_signing_message(auth);
        let user_sig = user_key.sign(&user_msg)?;
        let envelope = match self.mode {
            EnvelopeMode::Explicit => {
                PqEnvelope::explicit(user_key.public_key().to_vec(), user_sig)
            }
            EnvelopeMode::Implicit => PqEnvelope::implicit(user_sig),
        };
        let mut blob = envelope.encode()?;
        blob.extend_from_slice(&encode_sponsor_suffix(auth)?);
        tx.signature = blob;
        let signed = SignedTx { tx };
        signed
            .verify_with_key(user_key)
            .map_err(|e| SdkError::VerificationFailed(e.to_string()))?;
        Ok(signed)
    }
}

/// A signed transaction ready for estimation or submission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTx {
    tx: Transaction,
}

impl SignedTx {
    /// Decode a wire transaction and verify its explicit `PQ1` (and optional
    /// `SP1`) signature(s).
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let tx = Transaction::decode(bytes)?;
        let signed = Self { tx };
        signed.verify()?;
        Ok(signed)
    }

    /// Borrow the canonical transaction.
    pub fn transaction(&self) -> &Transaction {
        &self.tx
    }

    /// Wire bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.tx.encode()
    }

    /// Hex wire bytes (no `0x`, as `stell_sendRawTransaction` accepts either).
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Canonical transaction hash.
    pub fn tx_hash(&self) -> [u8; 32] {
        self.tx.compute_tx_hash()
    }

    /// Canonical transaction hash (alias for `tx_hash`).
    pub fn compute_tx_hash(&self) -> [u8; 32] {
        self.tx.compute_tx_hash()
    }

    /// Hex transaction hash.
    pub fn tx_hash_hex(&self) -> String {
        hex::encode(self.tx_hash())
    }

    /// Sender address.
    pub fn from(&self) -> [u8; 32] {
        self.tx.from
    }

    /// Recipient address.
    pub fn to(&self) -> [u8; 32] {
        self.tx.to
    }

    /// Sender nonce. It is immutable in this object: retries send the SAME
    /// bytes, never a re-signed transaction.
    pub fn nonce(&self) -> u64 {
        self.tx.nonce
    }

    /// Declared fee (`gas_limit`).
    pub fn gas_limit(&self) -> u64 {
        self.tx.gas_limit
    }

    /// Amount moved.
    pub fn amount(&self) -> u64 {
        self.tx.amount
    }

    /// Priority bid.
    pub fn priority_fee_per_gas(&self) -> u64 {
        self.tx.priority_fee_per_gas
    }

    /// Bound chain id, if any.
    pub fn chain_id(&self) -> Option<u64> {
        self.tx.chain_id()
    }

    /// True when the envelope commits a chain id.
    pub fn is_bound(&self) -> bool {
        self.tx.chain_id().is_some()
    }

    /// True for an explicit activation transaction (surcharge applies).
    pub fn is_pq_activation(&self) -> bool {
        self.tx.is_pq_activation()
    }

    /// Decoded `PQ1` envelope, if present (stripping any trailing `SP1` suffix).
    pub fn pq_envelope(&self) -> Option<PqEnvelope> {
        self.tx.pq_envelope()
    }

    /// Decoded `SF1` session grant, if present (stripping any trailing `SP1` suffix).
    pub fn session_grant(&self) -> Option<SessionGrant> {
        self.tx.session_grant()
    }

    /// Decoded `SP1` sponsor authorization, if present and well-formed.
    pub fn sponsor_authorization(&self) -> Option<SponsorAuthorization> {
        self.tx.sponsor_auth()
    }

    /// True when a well-formed `SP1` sponsor suffix is present.
    pub fn is_sponsored(&self) -> bool {
        self.tx.is_sponsored()
    }

    /// Exact credential signing message (`Transaction::signing_message`).
    pub fn signing_message(&self) -> Vec<u8> {
        self.tx.signing_message()
    }

    /// The raw SVM payload bytes.
    pub fn payload_bytes(&self) -> &[u8] {
        &self.tx.payload
    }

    /// Attach or replace a sponsor authorization on a `PQ1` transaction by
    /// signing the sponsor side first and re-signing the user's `PQ1` envelope
    /// over `sponsored_signing_message`.
    pub fn cosign_with_sponsor(
        self,
        user_key: &FalconKeypair,
        sponsor_key: &FalconKeypair,
        max_fee_per_tx: u64,
        valid_until: u64,
        allowed_targets: Vec<[u8; 32]>,
    ) -> Result<SignedTx> {
        if user_key.address() != self.tx.from {
            return Err(SdkError::InvalidArgument(
                "user_key address does not match tx.from".into(),
            ));
        }
        let chain_id = self.chain_id().ok_or_else(|| {
            SdkError::InvalidArgument("sponsored transactions require a chain_id".into())
        })?;
        if allowed_targets.len() > SPONSOR_MAX_TARGETS {
            return Err(SdkError::InvalidArgument(format!(
                "allowed_targets has {} entries, max {SPONSOR_MAX_TARGETS}",
                allowed_targets.len()
            )));
        }
        let mode = match self.tx.pq_envelope() {
            Some(env) => env.mode,
            None => {
                return Err(SdkError::InvalidArgument(
                    "sponsor cosigning requires a PQ1 inner envelope".into(),
                ));
            }
        };
        let mut tx = self.tx;
        tx.signature.clear();
        let mut auth = SponsorAuthorization {
            sponsor: sponsor_key.address(),
            max_fee_per_tx,
            valid_until,
            allowed_targets,
            chain_id,
            sponsor_sig: Vec::new(),
            sponsor_scheme: Some(PqScheme::Falcon512),
            sponsor_pubkey: Some(sponsor_key.public_key().to_vec()),
            sponsor_salt: Some(DEFAULT_SALT),
        };
        let sponsor_msg = tx.sponsor_message(&auth);
        auth.sponsor_sig = sponsor_key.sign(&sponsor_msg)?;
        let user_msg = tx.sponsored_signing_message(&auth);
        let user_sig = user_key.sign(&user_msg)?;
        let envelope = match mode {
            EnvelopeMode::Explicit => {
                PqEnvelope::explicit(user_key.public_key().to_vec(), user_sig)
            }
            EnvelopeMode::Implicit => PqEnvelope::implicit(user_sig),
        };
        let mut blob = envelope.encode()?;
        blob.extend_from_slice(&encode_sponsor_suffix(&auth)?);
        tx.signature = blob;
        let signed = SignedTx { tx };
        signed
            .verify_with_key(user_key)
            .map_err(|e| SdkError::VerificationFailed(e.to_string()))?;
        Ok(signed)
    }

    /// Verify an explicit `PQ1` transaction locally, exactly like node
    /// admission: rejects malformed `SP1` suffixes, decodes `PQ1`, checks the
    /// derived sender address, verifies the user's signature, and (when
    /// sponsored) verifies the sponsor's Falcon-512 signature as well.
    pub fn verify(&self) -> Result<()> {
        let (inner_len, sponsor_auth, sponsor_malformed) =
            split_sponsor_envelope(&self.tx.signature);
        if sponsor_malformed {
            return Err(SdkError::VerificationFailed(
                "malformed SP1 sponsor envelope".into(),
            ));
        }
        let env = pq_envelope_from_inner(&self.tx.signature[..inner_len])
            .ok_or_else(|| SdkError::VerificationFailed("not a PQ1 envelope".into()))?;
        if !env.is_explicit() {
            return Err(SdkError::VerificationFailed(
                "implicit envelope needs the original key; use verify_with_key".into(),
            ));
        }
        let pk = env
            .pubkey
            .as_ref()
            .ok_or_else(|| SdkError::VerificationFailed("envelope has no pubkey".into()))?;
        let addr = derive_pq_address(pk, &env.salt)?;
        if addr != self.tx.from {
            return Err(SdkError::VerificationFailed(
                "envelope pubkey does not derive to tx.from".into(),
            ));
        }
        let msg = if let Some(ref auth) = sponsor_auth {
            self.tx.sponsored_signing_message(auth)
        } else {
            match env.chain_id {
                Some(cid) => self.tx.signing_message_for_chain(cid),
                None => self.tx.signing_message(),
            }
        };
        if !crate::key::verify_pq_signature(pk, &msg, &env.signature) {
            return Err(SdkError::VerificationFailed(
                "Falcon-512 signature does not verify".into(),
            ));
        }
        if let Some(ref auth) = sponsor_auth {
            if !self.tx.verify_sponsor_sig(auth) {
                return Err(SdkError::VerificationFailed(
                    "sponsor Falcon-512 signature does not verify".into(),
                ));
            }
        }
        Ok(())
    }

    /// Verify with the original key (needed for implicit envelopes).
    pub fn verify_with_key(&self, key: &FalconKeypair) -> Result<()> {
        if key.address() != self.tx.from {
            return Err(SdkError::VerificationFailed(
                "key address != tx.from".into(),
            ));
        }
        let (inner_len, sponsor_auth, sponsor_malformed) =
            split_sponsor_envelope(&self.tx.signature);
        if sponsor_malformed {
            return Err(SdkError::VerificationFailed(
                "malformed SP1 sponsor envelope".into(),
            ));
        }
        let env = pq_envelope_from_inner(&self.tx.signature[..inner_len])
            .ok_or_else(|| SdkError::VerificationFailed("not a PQ1 envelope".into()))?;
        if env.is_explicit() {
            if let Some(pk) = &env.pubkey {
                if pk != key.public_key() {
                    return Err(SdkError::VerificationFailed(
                        "envelope carries a different public key".into(),
                    ));
                }
            }
        }
        let msg = if let Some(ref auth) = sponsor_auth {
            self.tx.sponsored_signing_message(auth)
        } else {
            match env.chain_id {
                Some(cid) => self.tx.signing_message_for_chain(cid),
                None => self.tx.signing_message(),
            }
        };
        if !crate::key::verify_pq_signature(key.public_key(), &msg, &env.signature) {
            return Err(SdkError::VerificationFailed(
                "Falcon-512 signature does not verify".into(),
            ));
        }
        if let Some(ref auth) = sponsor_auth {
            if !self.tx.verify_sponsor_sig(auth) {
                return Err(SdkError::VerificationFailed(
                    "sponsor Falcon-512 signature does not verify".into(),
                ));
            }
        }
        Ok(())
    }

    /// Verify an `SF1` transaction against the session key.
    pub fn verify_session(&self, session_key: &FalconKeypair) -> Result<()> {
        if self.tx.sponsor_malformed() || self.tx.is_sponsored() {
            return Err(SdkError::VerificationFailed(
                "SF1 session transactions cannot carry an SP1 sponsor envelope".into(),
            ));
        }
        let grant = self
            .tx
            .session_grant()
            .ok_or_else(|| SdkError::VerificationFailed("not an SF1 envelope".into()))?;
        if !grant.verify_master() {
            return Err(SdkError::VerificationFailed(
                "grant master signature does not verify".into(),
            ));
        }
        let derived_session = derive_pq_address(&grant.session_pubkey_bytes, &DEFAULT_SALT)
            .map_err(|e| SdkError::VerificationFailed(e.to_string()))?;
        if derived_session != grant.session_pubkey {
            return Err(SdkError::VerificationFailed(
                "grant session_pubkey_bytes does not derive to grant session_pubkey".into(),
            ));
        }
        if grant.session_pubkey_bytes != session_key.public_key() {
            return Err(SdkError::VerificationFailed(
                "session key != grant session_pubkey_bytes".into(),
            ));
        }
        if grant.master_address != self.tx.from {
            return Err(SdkError::VerificationFailed(
                "grant master_address != tx.from".into(),
            ));
        }
        let sig = &self.tx.sponsor_inner_sig()[..FALCON512_SIG_LEN];
        let msg = self.tx.signing_message_with_session(&grant);
        if crate::key::verify_pq_signature(session_key.public_key(), &msg, sig) {
            Ok(())
        } else {
            Err(SdkError::VerificationFailed(
                "session signature does not verify".into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opcode::CallArg;

    #[test]
    fn transfer_default_gas_includes_surcharge() {
        let to = [7u8; 32];
        let b = TxBuilder::transfer(to, 1_000);
        assert_eq!(
            b.effective_gas_limit(),
            FROZEN_MIN_GAS_FLOOR + PQ_ACTIVATION_SURCHARGE_GAS
        );
    }

    #[test]
    fn implicit_transfer_has_no_surcharge() {
        let b = TxBuilder::transfer([7u8; 32], 1_000).implicit();
        assert_eq!(b.effective_gas_limit(), FROZEN_MIN_GAS_FLOOR);
    }

    #[test]
    fn low_base_fee_is_clamped_to_the_frozen_floor() {
        let b = TxBuilder::stake([9u8; 32], 5_000).base_fee(1);
        assert_eq!(
            b.effective_gas_limit(),
            FROZEN_MIN_GAS_FLOOR + PQ_ACTIVATION_SURCHARGE_GAS
        );
    }

    #[test]
    fn stake_gas_is_floored() {
        let b = TxBuilder::stake([9u8; 32], 5_000);
        assert_eq!(
            b.effective_gas_limit(),
            FROZEN_MIN_GAS_FLOOR + PQ_ACTIVATION_SURCHARGE_GAS
        );
    }

    #[test]
    fn contract_call_gas_covers_opcode_cost() {
        let b = TxBuilder::contract_call([3u8; 32], "sum", &[CallArg::U64(1)], 0).unwrap();
        assert!(b.effective_gas_limit() >= FROZEN_MIN_GAS_FLOOR + PQ_ACTIVATION_SURCHARGE_GAS);
    }

    #[test]
    fn sign_and_verify_transfer() {
        let key = FalconKeypair::generate().unwrap();
        let signed = TxBuilder::transfer([7u8; 32], 42)
            .nonce(3)
            .sign(&key)
            .unwrap();
        assert_eq!(signed.nonce(), 3);
        assert_eq!(signed.chain_id(), Some(DEFAULT_CHAIN_ID));
        signed.verify().unwrap();
        let hash = signed.tx_hash();
        assert_eq!(signed.transaction().compute_tx_hash(), hash);
    }

    #[test]
    fn signing_message_binds_chain_id() {
        let key = FalconKeypair::generate().unwrap();
        // A non-default chain requires an explicit identity for that chain;
        // the fork id still has to be this build's ruleset.
        let identity = crate::protocol::ProtocolIdentity {
            chain_id: 2,
            ..crate::protocol::ProtocolIdentity::local()
        };
        let a = TxBuilder::transfer([7u8; 32], 1)
            .nonce(1)
            .identity(identity)
            .chain_id(2)
            .sign(&key)
            .unwrap();
        let b = TxBuilder::transfer([7u8; 32], 1)
            .nonce(1)
            .identity(identity)
            .chain_id(2)
            .priority_fee_per_gas(7)
            .sign(&key)
            .unwrap();
        assert_ne!(a.to_hex(), b.to_hex());
        assert_eq!(a.chain_id(), Some(2));
    }

    #[test]
    fn foreign_chain_is_refused_before_signing() {
        let key = FalconKeypair::generate().unwrap();
        let err = TxBuilder::transfer([7u8; 32], 1)
            .chain_id(1)
            .sign(&key)
            .unwrap_err();
        assert!(matches!(
            err,
            SdkError::ChainIdMismatch {
                expected: 5757,
                got: 1
            }
        ));
    }

    #[test]
    fn foreign_fork_is_refused_before_signing() {
        let key = FalconKeypair::generate().unwrap();
        let mut identity = crate::protocol::ProtocolIdentity::local();
        identity.fork_id ^= 1;
        let err = TxBuilder::transfer([7u8; 32], 1)
            .identity(identity)
            .sign(&key)
            .unwrap_err();
        assert!(matches!(err, SdkError::ForkIdMismatch { .. }));
    }

    #[test]
    fn gov_propose_and_vote_build_self_addressed_zero_value_txs() {
        let key = FalconKeypair::generate().unwrap();
        let propose = TxBuilder::gov_propose(
            4,
            "raise the floor".into(),
            crate::governance::GovAction::SetMinGasLimit(300_000),
            99,
        )
        .unwrap()
        .nonce(3)
        .sign(&key)
        .unwrap();
        assert_eq!(propose.from(), propose.to());
        assert_eq!(propose.amount(), 0);
        propose.verify().unwrap();

        let vote = TxBuilder::gov_vote(4, crate::governance::VoteChoice::Yes, 99)
            .nonce(4)
            .sign(&key)
            .unwrap();
        assert_eq!(vote.from(), vote.to());
        assert_eq!(vote.amount(), 0);
        vote.verify().unwrap();
    }

    #[test]
    fn unsigned_transaction_roundtrips_through_decode() {
        let key = FalconKeypair::generate().unwrap();
        let signed = TxBuilder::transfer([7u8; 32], 42)
            .nonce(5)
            .priority_fee_per_gas(9)
            .sign(&key)
            .unwrap();
        let decoded = Transaction::decode(&signed.to_bytes()).unwrap();
        assert_eq!(decoded, *signed.transaction());
        assert_eq!(decoded.encode(), signed.to_bytes());

        let mut unsigned = signed.transaction().clone();
        unsigned.signature.clear();
        let resaved = crate::tx::sign_unsigned(
            unsigned,
            &key,
            EnvelopeMode::Explicit,
            Some(DEFAULT_CHAIN_ID),
        )
        .unwrap();
        resaved.verify().unwrap();
        assert_eq!(resaved.from(), signed.from());
        assert_eq!(resaved.to(), signed.to());
        assert_eq!(resaved.nonce(), signed.nonce());
        assert_eq!(resaved.gas_limit(), signed.gas_limit());
        assert_eq!(
            resaved.priority_fee_per_gas(),
            signed.priority_fee_per_gas()
        );
        let decoded = Transaction::decode(&resaved.to_bytes()).unwrap();
        assert_eq!(decoded, *resaved.transaction());
    }

    #[test]
    fn sign_unsigned_with_identity_respects_custom_chain_and_priority_fee() {
        let key = FalconKeypair::generate().unwrap();
        let identity = crate::protocol::ProtocolIdentity {
            chain_id: 2,
            ..crate::protocol::ProtocolIdentity::local()
        };
        let mut unsigned = TxBuilder::transfer([7u8; 32], 42)
            .nonce(5)
            .identity(identity)
            .chain_id(2)
            .priority_fee_per_gas(11)
            .unsigned_transaction(key.address());
        let encoded_unsigned = unsigned.encode();
        unsigned = Transaction::decode(&encoded_unsigned).unwrap();
        assert_eq!(unsigned.priority_fee_per_gas, 11);

        let signed = crate::tx::sign_unsigned_with_identity(
            unsigned,
            &key,
            EnvelopeMode::Explicit,
            identity,
            Some(2),
        )
        .unwrap();
        signed.verify().unwrap();
        assert_eq!(signed.chain_id(), Some(2));
        assert_eq!(signed.priority_fee_per_gas(), 11);
    }

    #[test]
    fn contract_deploy_builds_and_signs_cleanly() {
        let key = FalconKeypair::generate().unwrap();
        let small_code = b"\0asm\x01\0\0\0".to_vec();
        let signed = TxBuilder::contract_deploy(small_code.clone())
            .nonce(2)
            .sign(&key)
            .unwrap();
        signed.verify().unwrap();
        assert_eq!(signed.from(), signed.to());
        assert_eq!(signed.amount(), 0);
        assert_eq!(signed.nonce(), 2);
        assert_eq!(
            signed.gas_limit(),
            FROZEN_MIN_GAS_FLOOR + PQ_ACTIVATION_SURCHARGE_GAS
        );
        assert_eq!(
            signed.payload_bytes(),
            encode_payload(&[Op::DeployContract { code: small_code }])
        );

        // Large bytecode scales deploy gas above TX_INTRINSIC_GAS (FROZEN_MIN_GAS_FLOOR).
        let big_code = vec![0x00u8; 200_000];
        let big_builder = TxBuilder::contract_deploy(big_code);
        assert_eq!(
            big_builder.effective_gas_limit(),
            crate::opcode::contract_deploy_gas(200_000) + PQ_ACTIVATION_SURCHARGE_GAS
        );
        assert!(big_builder.effective_gas_limit() > FROZEN_MIN_GAS_FLOOR);
    }

    #[test]
    fn contract_deploy_with_abi_builds_and_signs_cleanly() {
        let key = FalconKeypair::generate().unwrap();
        let small_code = b"\0asm\x01\0\0\0".to_vec();
        let small_abi =
            br#"{"methods":[{"name":"get","params":[],"returns":"i64","mutates_state":false}],"events":[]}"#
                .to_vec();
        let signed = TxBuilder::contract_deploy_with_abi(small_code.clone(), small_abi.clone())
            .nonce(7)
            .sign(&key)
            .unwrap();
        signed.verify().unwrap();
        assert_eq!(signed.from(), signed.to());
        assert_eq!(signed.amount(), 0);
        assert_eq!(signed.nonce(), 7);
        assert_eq!(
            signed.gas_limit(),
            FROZEN_MIN_GAS_FLOOR + PQ_ACTIVATION_SURCHARGE_GAS
        );
        assert_eq!(
            signed.payload_bytes(),
            encode_payload(&[Op::DeployContractWithAbi {
                code: small_code,
                abi_json: small_abi,
            }])
        );

        // Large bytecode + ABI scales deploy gas above FROZEN_MIN_GAS_FLOOR.
        let big_code = vec![0x00u8; 150_000];
        let big_abi = vec![b' '; 20_000];
        let big_builder = TxBuilder::contract_deploy_with_abi(big_code, big_abi);
        assert_eq!(
            big_builder.effective_gas_limit(),
            crate::opcode::contract_deploy_with_abi_gas(150_000, 20_000)
                + PQ_ACTIVATION_SURCHARGE_GAS
        );
        assert!(big_builder.effective_gas_limit() > FROZEN_MIN_GAS_FLOOR);
    }

    #[test]
    fn stake_with_commission_builds_signs_and_rejects_oversize_bps() {
        let key = FalconKeypair::generate().unwrap();
        let validator = [0x55u8; 32];
        let signed = TxBuilder::stake_with_commission(validator, 5_000, 750)
            .unwrap()
            .nonce(3)
            .sign(&key)
            .unwrap();
        signed.verify().unwrap();
        assert_eq!(signed.from(), signed.to());
        assert_eq!(signed.amount(), 5_000);
        assert_eq!(signed.nonce(), 3);
        assert_eq!(
            signed.payload_bytes(),
            encode_payload(&[Op::StakeWithCommission {
                validator,
                amount: 5_000,
                commission_bps: 750,
            }])
        );

        assert!(TxBuilder::stake_with_commission(validator, 5_000, 10_000).is_ok());
        assert!(matches!(
            TxBuilder::stake_with_commission(validator, 5_000, 10_001),
            Err(SdkError::InvalidArgument(_))
        ));
    }

    #[test]
    fn empty_payload_normalization_matches_encoded_empty_vec() {
        let key = FalconKeypair::generate().unwrap();
        let hand_built = Transaction {
            from: key.address(),
            to: [0x22u8; 32],
            amount: 100,
            gas_limit: 325_000,
            nonce: 1,
            source_shard: MASTERCHAIN_SHARD,
            target_shard: MASTERCHAIN_SHARD,
            signature: Vec::new(),
            payload: Vec::new(),
            priority_fee_per_gas: 50,
        };
        let mut builder_tx = hand_built.clone();
        builder_tx.payload = encode_payload(&[]);

        assert_eq!(hand_built.encode(), builder_tx.encode());
        assert_eq!(
            hand_built.base_signing_message(),
            builder_tx.base_signing_message()
        );
        assert_eq!(hand_built.signing_message(), builder_tx.signing_message());
        assert_eq!(
            hand_built.signing_message_for_chain(DEFAULT_CHAIN_ID),
            builder_tx.signing_message_for_chain(DEFAULT_CHAIN_ID)
        );
        assert_eq!(hand_built.compute_tx_hash(), builder_tx.compute_tx_hash());

        let auth = SponsorAuthorization {
            sponsor: [0x33u8; 32],
            max_fee_per_tx: 500_000,
            valid_until: 4_000_000_000,
            allowed_targets: vec![[0x22u8; 32]],
            chain_id: DEFAULT_CHAIN_ID,
            sponsor_sig: vec![0x29; FALCON512_SIG_LEN],
            sponsor_scheme: Some(PqScheme::Falcon512),
            sponsor_pubkey: Some(vec![0x09; FALCON512_PUBKEY_LEN]),
            sponsor_salt: Some(DEFAULT_SALT),
        };
        assert_eq!(
            hand_built.sponsor_message(&auth),
            builder_tx.sponsor_message(&auth)
        );
    }

    #[test]
    fn sponsor_sign_verify_roundtrip_and_tamper_rejected() {
        let user = FalconKeypair::generate().unwrap();
        let sponsor = FalconKeypair::generate().unwrap();
        let to = [0x44u8; 32];

        let signed = TxBuilder::transfer(to, 1_234)
            .nonce(7)
            .priority_fee_per_gas(99)
            .sign_with_sponsor(&user, &sponsor, 500_000, 4_000_000_000, vec![to])
            .unwrap();

        signed.verify().unwrap();
        assert!(signed.is_sponsored());
        assert!(signed.is_pq_activation());
        assert_eq!(signed.chain_id(), Some(DEFAULT_CHAIN_ID));
        assert!(signed.pq_envelope().is_some());
        assert!(signed.session_grant().is_none());
        let auth = signed.sponsor_authorization().unwrap();
        assert_eq!(auth.sponsor, sponsor.address());
        assert_eq!(auth.allowed_targets, vec![to]);

        // Wire roundtrip + decode + verify.
        let decoded = SignedTx::decode(&signed.to_bytes()).unwrap();
        assert_eq!(decoded, signed);
        assert_eq!(decoded.compute_tx_hash(), signed.tx_hash());
        assert_eq!(decoded.signing_message(), signed.signing_message());

        // `cosign_with_sponsor` on a plain PQ1 transaction produces a valid sponsored tx.
        let plain = TxBuilder::transfer(to, 1_234).nonce(8).sign(&user).unwrap();
        let cosigned = plain
            .cosign_with_sponsor(&user, &sponsor, 500_000, 4_000_000_000, vec![to])
            .unwrap();
        cosigned.verify().unwrap();
        assert!(cosigned.is_sponsored());
        assert_eq!(
            cosigned.sponsor_authorization().unwrap().sponsor,
            sponsor.address()
        );

        // Tamper with user PQ1 byte -> verify fails.
        let mut bad_user = signed.transaction().clone();
        bad_user.signature[20] ^= 0xff;
        assert!(SignedTx { tx: bad_user }.verify().is_err());

        // Tamper with SP1 suffix -> malformed -> verify fails.
        let mut bad_sp1 = signed.transaction().clone();
        let last = bad_sp1.signature.len() - 4;
        bad_sp1.signature[last] ^= 0x01;
        assert!(bad_sp1.sponsor_malformed());
        assert!(SignedTx { tx: bad_sp1 }.verify().is_err());

        // Unbound builder cannot sponsor.
        assert!(matches!(
            TxBuilder::transfer(to, 1).unbound().sign_with_sponsor(
                &user,
                &sponsor,
                500_000,
                4_000_000_000,
                vec![]
            ),
            Err(SdkError::InvalidArgument(_))
        ));

        // Too many allowed_targets rejected.
        assert!(matches!(
            TxBuilder::transfer(to, 1).sign_with_sponsor(
                &user,
                &sponsor,
                500_000,
                4_000_000_000,
                vec![[0x11u8; 32]; SPONSOR_MAX_TARGETS + 1]
            ),
            Err(SdkError::InvalidArgument(_))
        ));
    }

    #[test]
    fn verify_session_enforces_key_binding_and_refuses_sponsor_suffix() {
        let master = FalconKeypair::generate().unwrap();
        let session = FalconKeypair::generate().unwrap();
        let sponsor = FalconKeypair::generate().unwrap();
        let grant = SessionGrant::new(
            &master,
            session.public_key(),
            4_000_000_000,
            10_000_000,
            crate::session::SCOPE_ALL,
            1_000_000,
            DEFAULT_CHAIN_ID,
        )
        .unwrap();
        let signed = TxBuilder::transfer([0x22u8; 32], 50)
            .nonce(1)
            .sign_with_session(&session, &grant)
            .unwrap();
        signed.verify_session(&session).unwrap();

        // Attaching an SP1 suffix to an SF1 tx must be rejected by verify_session.
        let mut sponsored_sf1 = signed.transaction().clone();
        let mut auth = SponsorAuthorization {
            sponsor: sponsor.address(),
            max_fee_per_tx: 500_000,
            valid_until: 4_000_000_000,
            allowed_targets: Vec::new(),
            chain_id: DEFAULT_CHAIN_ID,
            sponsor_sig: Vec::new(),
            sponsor_scheme: Some(PqScheme::Falcon512),
            sponsor_pubkey: Some(sponsor.public_key().to_vec()),
            sponsor_salt: Some(DEFAULT_SALT),
        };
        auth.sponsor_sig = sponsor.sign(&sponsored_sf1.sponsor_message(&auth)).unwrap();
        sponsored_sf1
            .signature
            .extend_from_slice(&encode_sponsor_suffix(&auth).unwrap());
        assert!(SignedTx { tx: sponsored_sf1 }
            .verify_session(&session)
            .is_err());

        // Grant with mismatched session_pubkey vs session_pubkey_bytes is rejected.
        let mut bad_grant = grant;
        bad_grant.session_pubkey = [0xAAu8; 32];
        // Re-sign master signature over the tampered session_pubkey so verify_master passes.
        let msg = SessionGrant::grant_message(
            &bad_grant.master_address,
            &bad_grant.session_pubkey,
            bad_grant.valid_until,
            bad_grant.max_gas_spend,
            bad_grant.scope,
            bad_grant.max_value_per_tx,
            bad_grant.chain_id,
        );
        bad_grant.master_signature = master.sign(&msg).unwrap();
        assert!(TxBuilder::transfer([0x22u8; 32], 50)
            .nonce(2)
            .sign_with_session(&session, &bad_grant)
            .is_err());
    }
}
