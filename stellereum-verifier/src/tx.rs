//! Clean-room transaction envelope and signature verification.
//!
//! Enforces FULL-PQ (Falcon-512 only) fail-closed semantics:
//! - Canonical `PQ1` envelopes (`decode_canonical`, explicit & implicit, custom salt, `chain_id`)
//! - `SF1` Falcon-512 session-key delegation grants & policy checks
//! - `SP1` Paymaster v2 (Falcon-512 sponsor over `PQ1` inner)
//! - `PRIORITY` explicit mempool priority bid commitment
//! - Deterministic `compute_tx_hash` and `chain_id` replay protection
//! - Unconditional rejection of Ed25519, `SK1`, `CH1`, `EV1`, ML-DSA-44, and legacy envelopes

use crate::falcon512::{derive_pq_address, verify_falcon512, DEFAULT_SALT, FALCON512_SIG_LEN};
use crate::wire::{
    OpCode, PqScheme, SessionKeyAuthorization, ShardId, SponsorAuthorization, Transaction,
    CHAIN_ID_COMMITMENT_TAG, PQ_ENVELOPE_MAGIC, PRIORITY_FEE_COMMITMENT_TAG,
    SESSION_FALCON_SIG_TAG, SPONSOR_COMMITMENT_TAG,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Replay-protection domain of EVM-settled transactions.
///
/// Mirrors `stellereum::sharding::EVM_CHAIN_ID` (5757), which the node pins to
/// the canonical chain id. Kept local so this crate does not need to import
/// the node's sharding module; the differential test suite checks the
/// envelope verdict against the reference implementation.
pub const EVM_CHAIN_ID: u64 = crate::wire::DEFAULT_CHAIN_ID;

pub const SESSION_KEY_DOMAIN: &[u8] = b"STELL_SESSKEY_V1";
pub const SPONSOR_FEE_DOMAIN: &[u8; 14] = b"SPONSOR_FEE_V1";

pub const SCOPE_TRANSFER: u64 = 1 << 0;
pub const SCOPE_SVM_PAYLOAD: u64 = 1 << 1;
pub const SCOPE_ACTOR_SEND: u64 = 1 << 2;
pub const SCOPE_ALL: u64 = u64::MAX;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSignatureEnvelope {
    pub scheme: PqScheme,
    pub is_implicit: bool,
    pub pubkey: Option<Vec<u8>>,
    pub signature_bytes: Vec<u8>,
    pub salt: [u8; 16],
    #[serde(default)]
    pub chain_id: Option<u64>,
}

impl PqSignatureEnvelope {
    pub fn new_explicit(scheme: PqScheme, pubkey: Vec<u8>, signature_bytes: Vec<u8>) -> Self {
        Self {
            scheme,
            is_implicit: false,
            pubkey: Some(pubkey),
            signature_bytes,
            salt: DEFAULT_SALT,
            chain_id: None,
        }
    }

    pub fn new_explicit_with_salt(
        scheme: PqScheme,
        pubkey: Vec<u8>,
        signature_bytes: Vec<u8>,
        salt: [u8; 16],
    ) -> Self {
        Self {
            scheme,
            is_implicit: false,
            pubkey: Some(pubkey),
            signature_bytes,
            salt,
            chain_id: None,
        }
    }

    pub fn new_explicit_with_chain(
        scheme: PqScheme,
        pubkey: Vec<u8>,
        signature_bytes: Vec<u8>,
        salt: [u8; 16],
        chain_id: u64,
    ) -> Self {
        Self {
            scheme,
            is_implicit: false,
            pubkey: Some(pubkey),
            signature_bytes,
            salt,
            chain_id: Some(chain_id),
        }
    }

    pub fn new_implicit(scheme: PqScheme, signature_bytes: Vec<u8>) -> Self {
        Self {
            scheme,
            is_implicit: true,
            pubkey: None,
            signature_bytes,
            salt: DEFAULT_SALT,
            chain_id: None,
        }
    }

    pub fn new_implicit_with_chain(
        scheme: PqScheme,
        signature_bytes: Vec<u8>,
        chain_id: u64,
    ) -> Self {
        Self {
            scheme,
            is_implicit: true,
            pubkey: None,
            signature_bytes,
            salt: DEFAULT_SALT,
            chain_id: Some(chain_id),
        }
    }

    pub fn encoded_len(&self) -> usize {
        let salt_len = if !self.is_implicit { 16 } else { 0 };
        let pk_len = self.pubkey.as_ref().map_or(0, |k| k.len());
        let chain_len = if self.chain_id.is_some() { 8 } else { 0 };
        3 + 1 + 1 + 2 + pk_len + salt_len + 2 + self.signature_bytes.len() + chain_len
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        out.extend_from_slice(PQ_ENVELOPE_MAGIC);
        out.push(self.scheme.id());
        out.push(if self.is_implicit { 1 } else { 0 });

        if let Some(pk) = &self.pubkey {
            let pk_len_u16 = pk.len() as u16;
            out.extend_from_slice(&pk_len_u16.to_le_bytes());
            out.extend_from_slice(pk);
        } else {
            out.extend_from_slice(&0u16.to_le_bytes());
        }

        if !self.is_implicit {
            out.extend_from_slice(&self.salt);
        }

        let sig_len = self.signature_bytes.len() as u16;
        out.extend_from_slice(&sig_len.to_le_bytes());
        out.extend_from_slice(&self.signature_bytes);
        if let Some(cid) = self.chain_id {
            out.extend_from_slice(&cid.to_be_bytes());
        }
        out
    }

    /// Strict canonical `PQ1` decoder (matches `stellereum::sharding::PqSignatureEnvelope::decode_canonical`).
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 7 {
            return Err("Envelope bytes too short".to_string());
        }
        if &bytes[0..3] != PQ_ENVELOPE_MAGIC {
            return Err("Missing PQ1 magic header".to_string());
        }

        let scheme = PqScheme::from_id(bytes[3])?;
        if bytes[4] > 1 {
            return Err("Envelope flag byte must be 0 (explicit) or 1 (implicit)".to_string());
        }
        let is_implicit = bytes[4] == 1;
        let pk_len = u16::from_le_bytes([bytes[5], bytes[6]]) as usize;

        if is_implicit {
            if pk_len != 0 {
                return Err("Implicit envelope must not carry a public key".to_string());
            }
            let mut cursor = 7;
            if bytes.len() < cursor + 2 {
                return Err("Truncated signature length in envelope".to_string());
            }
            let sig_len = u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
            cursor += 2;
            if sig_len != scheme.signature_size() {
                return Err(format!(
                    "Envelope signature length mismatch for {}: expected {}, got {}",
                    scheme.name(),
                    scheme.signature_size(),
                    sig_len
                ));
            }
            if bytes.len() < cursor + sig_len {
                return Err("Truncated signature bytes in envelope".to_string());
            }
            if bytes.len() != cursor + sig_len && bytes.len() != cursor + sig_len + 8 {
                return Err("Canonical envelope has trailing bytes".to_string());
            }
            let signature_bytes = bytes[cursor..cursor + sig_len].to_vec();
            cursor += sig_len;
            let chain_id = if bytes.len() == cursor + 8 {
                Some(u64::from_be_bytes(
                    bytes[cursor..cursor + 8].try_into().unwrap(),
                ))
            } else {
                None
            };
            return Ok(Self {
                scheme,
                is_implicit: true,
                pubkey: None,
                signature_bytes,
                salt: DEFAULT_SALT,
                chain_id,
            });
        }

        let expected_pk_len = scheme.pubkey_size();
        if pk_len != expected_pk_len {
            return Err(format!(
                "Canonical explicit envelope public key length mismatch for {}: expected {}, got {}",
                scheme.name(),
                expected_pk_len,
                pk_len
            ));
        }

        let mut cursor = 7;
        if bytes.len() < cursor + pk_len + 16 + 2 {
            return Err("Truncated canonical explicit envelope bytes".to_string());
        }
        let pubkey = bytes[cursor..cursor + pk_len].to_vec();
        cursor += pk_len;

        let mut salt = [0u8; 16];
        salt.copy_from_slice(&bytes[cursor..cursor + 16]);
        cursor += 16;

        let sig_len = u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
        cursor += 2;
        if sig_len != scheme.signature_size() {
            return Err(format!(
                "Envelope signature length mismatch for {}: expected {}, got {}",
                scheme.name(),
                scheme.signature_size(),
                sig_len
            ));
        }
        if bytes.len() < cursor + sig_len {
            return Err("Truncated signature bytes in canonical envelope".to_string());
        }
        if bytes.len() != cursor + sig_len && bytes.len() != cursor + sig_len + 8 {
            return Err("Canonical envelope has trailing bytes".to_string());
        }

        let signature_bytes = bytes[cursor..cursor + sig_len].to_vec();
        cursor += sig_len;
        let chain_id = if bytes.len() == cursor + 8 {
            Some(u64::from_be_bytes(
                bytes[cursor..cursor + 8].try_into().unwrap(),
            ))
        } else {
            None
        };

        Ok(Self {
            scheme,
            is_implicit: false,
            pubkey: Some(pubkey),
            signature_bytes,
            salt,
            chain_id,
        })
    }
}

/// Clean-room implicit PQ key registry mapping 32-byte addresses to pinned Falcon-512 pubkeys.
#[derive(Clone, Debug, Default)]
pub struct ImplicitKeyRegistry {
    entries: HashMap<[u8; 32], (PqScheme, Vec<u8>)>,
}

impl ImplicitKeyRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(
        &mut self,
        address: [u8; 32],
        scheme: PqScheme,
        pubkey: &[u8],
        salt: &[u8; 16],
    ) -> Result<(), String> {
        if scheme.is_disabled() {
            return Err("Refused disabled post-quantum scheme".to_string());
        }
        if pubkey.len() != scheme.pubkey_size() {
            return Err(format!(
                "Invalid public key length for {}: expected {}, got {}",
                scheme.name(),
                scheme.pubkey_size(),
                pubkey.len()
            ));
        }
        let derived = derive_pq_address(scheme.id(), pubkey, salt);
        if derived != address {
            return Err("Address mismatch during implicit key registration".to_string());
        }
        if let Some((existing_scheme, existing_key)) = self.entries.get(&address) {
            if *existing_scheme != scheme || existing_key.as_slice() != pubkey {
                return Err("Conflicting public key registration for address".to_string());
            }
            return Ok(());
        }
        self.entries.insert(address, (scheme, pubkey.to_vec()));
        Ok(())
    }

    pub fn lookup(&self, address: &[u8; 32]) -> Option<(PqScheme, Vec<u8>)> {
        self.entries.get(address).cloned()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionPolicyError {
    Expired,
    OutOfScope,
    BudgetExhausted,
    BadGrant,
}

impl core::fmt::Display for SessionPolicyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            SessionPolicyError::Expired => "session key delegation has expired",
            SessionPolicyError::OutOfScope => {
                "session key delegation does not cover this transaction (scope/value cap)"
            }
            SessionPolicyError::BudgetExhausted => {
                "session key delegation has no remaining gas budget"
            }
            SessionPolicyError::BadGrant => "invalid session key delegation grant",
        };
        write!(f, "{s}")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SponsorPolicyError {
    Expired,
    OutOfScope,
    CapExceeded,
    BadGrant,
}

impl core::fmt::Display for SponsorPolicyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            SponsorPolicyError::Expired => "sponsor grant has expired",
            SponsorPolicyError::OutOfScope => {
                "sponsor grant does not cover this recipient (allowlist)"
            }
            SponsorPolicyError::CapExceeded => {
                "sponsor grant per-tx fee cap does not cover this transaction's fee"
            }
            SponsorPolicyError::BadGrant => "invalid sponsor grant",
        };
        write!(f, "{s}")
    }
}

/// Deterministic transaction hash matching `stellereum::sharding::Transaction::compute_tx_hash`.
pub fn compute_tx_hash(tx: &Transaction) -> [u8; 32] {
    tx.compute_tx_hash()
}

fn append_payload_commitment(msg: &mut Vec<u8>, payload: &[OpCode]) {
    msg.extend_from_slice(b"PAYLOAD");
    match bincode::serialize(payload) {
        Ok(bytes) => {
            msg.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            msg.extend_from_slice(&bytes);
        }
        Err(_) => {
            msg.extend_from_slice(&u32::MAX.to_be_bytes());
        }
    }
}

fn append_priority_commitment(msg: &mut Vec<u8>, priority_fee_per_gas: u64) {
    if priority_fee_per_gas == 0 {
        return;
    }
    msg.extend_from_slice(PRIORITY_FEE_COMMITMENT_TAG);
    msg.extend_from_slice(&priority_fee_per_gas.to_be_bytes());
}

fn append_chain_id_commitment(msg: &mut Vec<u8>, chain_id: u64) {
    msg.extend_from_slice(CHAIN_ID_COMMITMENT_TAG);
    msg.extend_from_slice(&chain_id.to_be_bytes());
}

#[allow(clippy::too_many_arguments)]
pub fn base_signing_message(
    from: &[u8; 32],
    to: [u8; 32],
    amount: u64,
    gas_limit: u64,
    nonce: u64,
    source_shard: ShardId,
    target_shard: ShardId,
    payload: &[OpCode],
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
    append_payload_commitment(&mut msg, payload);
    append_priority_commitment(&mut msg, priority_fee_per_gas);
    msg
}

pub fn delegation_commitment_bytes(delegation: &SessionKeyAuthorization) -> Vec<u8> {
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

pub fn sponsor_commitment_bytes(auth: &SponsorAuthorization) -> Vec<u8> {
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

pub fn session_grant_message(
    master_address: &[u8; 32],
    session_pubkey: &[u8; 32],
    valid_until: u64,
    max_gas_spend: u64,
    scope: u64,
    max_value_per_tx: u64,
    chain_id: u64,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(SESSION_KEY_DOMAIN.len() + 8 * 5 + 64);
    msg.extend_from_slice(SESSION_KEY_DOMAIN);
    msg.extend_from_slice(&chain_id.to_be_bytes());
    msg.extend_from_slice(master_address);
    msg.extend_from_slice(session_pubkey);
    msg.extend_from_slice(&valid_until.to_be_bytes());
    msg.extend_from_slice(&max_gas_spend.to_be_bytes());
    msg.extend_from_slice(&scope.to_be_bytes());
    msg.extend_from_slice(&max_value_per_tx.to_be_bytes());
    msg
}

pub fn verify_session_grant(grant: &SessionKeyAuthorization) -> bool {
    if grant.master_scheme != PqScheme::Falcon512 || grant.session_scheme != PqScheme::Falcon512 {
        return false;
    }
    let Some(ref pk) = grant.master_pubkey else {
        return false;
    };
    if derive_pq_address(grant.master_scheme.id(), pk, &DEFAULT_SALT) != grant.master_address {
        return false;
    }
    let msg = session_grant_message(
        &grant.master_address,
        &grant.session_pubkey,
        grant.valid_until,
        grant.max_gas_spend,
        grant.scope,
        grant.max_value_per_tx,
        grant.chain_id,
    );
    verify_falcon512(pk, &msg, &grant.master_signature)
}

pub fn verify_session_signature(
    grant: &SessionKeyAuthorization,
    message: &[u8],
    signature_bytes: &[u8],
) -> bool {
    if grant.master_scheme != PqScheme::Falcon512 || grant.session_scheme != PqScheme::Falcon512 {
        return false;
    }
    let Some(ref pk) = grant.session_pubkey_bytes else {
        return false;
    };
    if derive_pq_address(grant.session_scheme.id(), pk, &DEFAULT_SALT) != grant.session_pubkey {
        return false;
    }
    verify_falcon512(pk, message, signature_bytes)
}

pub fn sponsor_message(tx: &Transaction, auth: &SponsorAuthorization) -> Vec<u8> {
    let mut msg = Vec::with_capacity(256);
    msg.extend_from_slice(SPONSOR_FEE_DOMAIN);
    msg.extend_from_slice(&auth.sponsor);
    msg.extend_from_slice(&tx.from);
    msg.extend_from_slice(&tx.to);
    msg.extend_from_slice(&tx.amount.to_be_bytes());
    msg.extend_from_slice(&tx.gas_limit.to_be_bytes());
    msg.extend_from_slice(&tx.nonce.to_be_bytes());
    msg.extend_from_slice(&tx.source_shard.to_be_bytes());
    msg.extend_from_slice(&tx.target_shard.to_be_bytes());
    append_payload_commitment(&mut msg, &tx.payload);
    msg.extend_from_slice(&tx.priority_fee_per_gas.to_be_bytes());
    msg.extend_from_slice(&auth.max_fee_per_tx.to_be_bytes());
    msg.extend_from_slice(&auth.valid_until.to_be_bytes());
    msg.extend_from_slice(b"ALLOWLIST");
    msg.extend_from_slice(&(auth.allowed_targets.len() as u32).to_be_bytes());
    for target in &auth.allowed_targets {
        msg.extend_from_slice(target);
    }
    msg.extend_from_slice(&auth.chain_id.to_be_bytes());
    msg
}

pub fn verify_sponsor_sig(tx: &Transaction, auth: &SponsorAuthorization) -> bool {
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
    if derive_pq_address(scheme.id(), pk, &salt) != auth.sponsor {
        return false;
    }
    verify_falcon512(pk, &sponsor_message(tx, auth), &auth.sponsor_sig)
}

pub fn pq_envelope_canonical(inner_sig: &[u8]) -> Option<PqSignatureEnvelope> {
    if !Transaction::is_pq_inner(inner_sig) {
        return None;
    }
    let env = PqSignatureEnvelope::decode_canonical(inner_sig).ok()?;
    if env.encoded_len() != inner_sig.len() {
        return None;
    }
    Some(env)
}

pub fn tx_chain_id(tx: &Transaction) -> Option<u64> {
    let (inner_len, sponsor_auth, sponsor_malformed) =
        Transaction::split_sponsor_envelope(&tx.signature);
    if sponsor_malformed {
        return None;
    }
    if let Some(auth) = sponsor_auth {
        return Some(auth.chain_id);
    }
    let inner_sig = &tx.signature[..inner_len];
    if let Some((d, _)) = Transaction::delegation_from_inner(inner_sig) {
        Some(d.chain_id)
    } else if let Some(cid) = Transaction::chain_id_from_inner(inner_sig) {
        Some(cid)
    } else if let Some(env) = pq_envelope_canonical(inner_sig) {
        env.chain_id
    } else if Transaction::is_evm_inner(inner_sig) {
        Some(EVM_CHAIN_ID)
    } else {
        None
    }
}

pub fn signing_message(tx: &Transaction) -> Vec<u8> {
    let mut msg = base_signing_message(
        &tx.from,
        tx.to,
        tx.amount,
        tx.gas_limit,
        tx.nonce,
        tx.source_shard,
        tx.target_shard,
        &tx.payload,
        tx.priority_fee_per_gas,
    );
    let (inner_len, sponsor_auth, _) = Transaction::split_sponsor_envelope(&tx.signature);
    let inner_sig = &tx.signature[..inner_len];
    if Transaction::is_evm_inner(inner_sig) {
        return msg;
    }
    if let Some((d, _)) = Transaction::delegation_from_inner(inner_sig) {
        msg.extend_from_slice(&delegation_commitment_bytes(&d));
    } else if sponsor_auth.is_none() {
        let cid = Transaction::chain_id_from_inner(inner_sig)
            .or_else(|| pq_envelope_canonical(inner_sig).and_then(|e| e.chain_id));
        if let Some(cid) = cid {
            append_chain_id_commitment(&mut msg, cid);
        }
    }
    if let Some(auth) = sponsor_auth {
        msg.extend_from_slice(&sponsor_commitment_bytes(&auth));
    }
    msg
}

pub fn required_scope(tx: &Transaction) -> u64 {
    if tx.payload.is_empty() {
        SCOPE_TRANSFER
    } else if tx
        .payload
        .iter()
        .any(|op| matches!(op, OpCode::SysCallActorSend { .. }))
    {
        SCOPE_SVM_PAYLOAD | SCOPE_ACTOR_SEND
    } else {
        SCOPE_SVM_PAYLOAD
    }
}

pub fn check_session_policy(tx: &Transaction, now: u64) -> Result<(), SessionPolicyError> {
    let (inner_len, _, sponsor_malformed) = Transaction::split_sponsor_envelope(&tx.signature);
    if sponsor_malformed {
        return Err(SessionPolicyError::BadGrant);
    }
    let inner_sig = &tx.signature[..inner_len];
    let Some((d, session_sig)) = Transaction::delegation_from_inner(inner_sig) else {
        return Ok(());
    };
    if session_sig.len() != FALCON512_SIG_LEN
        || inner_sig.len() <= FALCON512_SIG_LEN + SESSION_FALCON_SIG_TAG.len()
        || &inner_sig[FALCON512_SIG_LEN..FALCON512_SIG_LEN + SESSION_FALCON_SIG_TAG.len()]
            != SESSION_FALCON_SIG_TAG
    {
        return Err(SessionPolicyError::BadGrant);
    }
    if d.master_scheme != PqScheme::Falcon512 || d.session_scheme != PqScheme::Falcon512 {
        return Err(SessionPolicyError::BadGrant);
    }
    if d.master_address != tx.from {
        return Err(SessionPolicyError::BadGrant);
    }
    if !verify_session_grant(&d) {
        return Err(SessionPolicyError::BadGrant);
    }
    if now > d.valid_until {
        return Err(SessionPolicyError::Expired);
    }
    let req = required_scope(tx);
    if d.scope & req != req {
        return Err(SessionPolicyError::OutOfScope);
    }
    if tx.amount > d.max_value_per_tx {
        return Err(SessionPolicyError::OutOfScope);
    }
    let remaining = d.max_gas_spend.saturating_sub(d.gas_spent);
    if tx.gas_limit > remaining {
        return Err(SessionPolicyError::BudgetExhausted);
    }
    Ok(())
}

pub fn check_sponsor_policy(
    tx: &Transaction,
    now: u64,
    fee_to_charge: u64,
) -> Result<(), SponsorPolicyError> {
    let (inner_len, sponsor_auth, sponsor_malformed) =
        Transaction::split_sponsor_envelope(&tx.signature);
    if sponsor_malformed {
        return Err(SponsorPolicyError::BadGrant);
    }
    let Some(auth) = sponsor_auth else {
        return Ok(());
    };
    if auth.sponsor == tx.from {
        return Ok(());
    }
    let inner_sig = &tx.signature[..inner_len];
    let Some(env) = pq_envelope_canonical(inner_sig) else {
        return Err(SponsorPolicyError::BadGrant);
    };
    if env.scheme != PqScheme::Falcon512 {
        return Err(SponsorPolicyError::BadGrant);
    }
    if now > auth.valid_until {
        return Err(SponsorPolicyError::Expired);
    }
    if !auth.allowed_targets.is_empty() && !auth.allowed_targets.contains(&tx.to) {
        return Err(SponsorPolicyError::OutOfScope);
    }
    if fee_to_charge > auth.max_fee_per_tx {
        return Err(SponsorPolicyError::CapExceeded);
    }
    Ok(())
}

/// Verify a transaction's PQ signature (`PQ1` canonical or `SF1` Falcon session key,
/// optionally composed with `SP1` Paymaster v2 over `PQ1`).
///
/// Fails closed on all Ed25519, `SK1`, `CH1`, `EV1`, ML-DSA-44, non-canonical `PQ1`,
/// or legacy envelopes.
pub fn verify_transaction_signature(tx: &Transaction, registry: &mut ImplicitKeyRegistry) -> bool {
    let (inner_len, sponsor_auth, sponsor_malformed) =
        Transaction::split_sponsor_envelope(&tx.signature);
    if sponsor_malformed {
        return false;
    }
    let inner_sig = &tx.signature[..inner_len];

    // SF1 Falcon-512 session-key delegation (SK1/Ed25519 refused fail-closed).
    if let Some((d, session_sig)) = Transaction::delegation_from_inner(inner_sig) {
        if sponsor_auth.is_some() {
            return false;
        }
        if session_sig.len() != FALCON512_SIG_LEN
            || inner_sig.len() <= FALCON512_SIG_LEN + SESSION_FALCON_SIG_TAG.len()
            || &inner_sig[FALCON512_SIG_LEN..FALCON512_SIG_LEN + SESSION_FALCON_SIG_TAG.len()]
                != SESSION_FALCON_SIG_TAG
        {
            return false;
        }
        if d.master_address != tx.from {
            return false;
        }
        if !verify_session_grant(&d) {
            return false;
        }
        let mut msg = base_signing_message(
            &tx.from,
            tx.to,
            tx.amount,
            tx.gas_limit,
            tx.nonce,
            tx.source_shard,
            tx.target_shard,
            &tx.payload,
            tx.priority_fee_per_gas,
        );
        msg.extend_from_slice(&delegation_commitment_bytes(&d));
        return verify_session_signature(&d, &msg, session_sig);
    }

    // Refuse EV1 and non-PQ1 envelopes fail-closed.
    if Transaction::is_evm_inner(inner_sig) || !Transaction::is_pq_inner(inner_sig) {
        return false;
    }

    let Some(env) = pq_envelope_canonical(inner_sig) else {
        return false;
    };
    if env.scheme != PqScheme::Falcon512 || env.signature_bytes.len() != FALCON512_SIG_LEN {
        return false;
    }

    let mut msg = base_signing_message(
        &tx.from,
        tx.to,
        tx.amount,
        tx.gas_limit,
        tx.nonce,
        tx.source_shard,
        tx.target_shard,
        &tx.payload,
        tx.priority_fee_per_gas,
    );
    if let Some(ref auth) = sponsor_auth {
        msg.extend_from_slice(&sponsor_commitment_bytes(auth));
    } else if let Some(cid) = env.chain_id {
        append_chain_id_commitment(&mut msg, cid);
    }

    let inner_ok = if !env.is_implicit {
        let Some(ref pk) = env.pubkey else {
            return false;
        };
        if pk.len() != env.scheme.pubkey_size() {
            return false;
        }
        if derive_pq_address(env.scheme.id(), pk, &env.salt) != tx.from {
            return false;
        }
        if !verify_falcon512(pk, &msg, &env.signature_bytes) {
            return false;
        }
        let _ = registry.register(tx.from, env.scheme, pk, &env.salt);
        true
    } else {
        if env.pubkey.is_some() {
            return false;
        }
        let Some((scheme, pk)) = registry.lookup(&tx.from) else {
            return false;
        };
        if scheme != env.scheme || scheme != PqScheme::Falcon512 {
            return false;
        }
        verify_falcon512(&pk, &msg, &env.signature_bytes)
    };

    if !inner_ok {
        return false;
    }

    match sponsor_auth {
        None => true,
        Some(ref auth) => verify_sponsor_sig(tx, auth),
    }
}

/// Verify transaction signature, chain-id binding, and stateless session/sponsor policies.
pub fn verify_transaction_for_chain(
    tx: &Transaction,
    expected_chain_id: u64,
    require_chain_id: bool,
    registry: &mut ImplicitKeyRegistry,
) -> bool {
    verify_tx(tx, expected_chain_id, require_chain_id, registry).is_ok()
}

/// Verify transaction signature, chain-id binding, and session/sponsor policies at `now`.
pub fn verify_transaction_for_chain_at(
    tx: &Transaction,
    expected_chain_id: u64,
    require_chain_id: bool,
    now: u64,
    registry: &mut ImplicitKeyRegistry,
) -> bool {
    verify_tx_at(tx, expected_chain_id, require_chain_id, now, registry).is_ok()
}

/// Detailed transaction verification returning descriptive refusal reasons.
///
/// Checks chain-id binding, stateless session (`SF1`) and sponsor (`SP1`) policies
/// (`scope`, `max_value_per_tx`, `max_gas_spend`, `allowed_targets`, `max_fee_per_tx`),
/// and PQ signature verification. Call [`verify_tx_at`] when a block timestamp is known
/// to also enforce `valid_until` expiry.
pub fn verify_tx(
    tx: &Transaction,
    expected_chain_id: u64,
    require_chain_id: bool,
    registry: &mut ImplicitKeyRegistry,
) -> Result<(), String> {
    verify_tx_at(tx, expected_chain_id, require_chain_id, 0, registry)
}

/// Detailed transaction verification at an explicit deterministic timestamp `now`.
pub fn verify_tx_at(
    tx: &Transaction,
    expected_chain_id: u64,
    require_chain_id: bool,
    now: u64,
    registry: &mut ImplicitKeyRegistry,
) -> Result<(), String> {
    let cid = tx_chain_id(tx);
    if require_chain_id && cid.is_none() {
        return Err(format!(
            "rejected: unbound transaction refused (expected chain_id {expected_chain_id})"
        ));
    }
    if let Some(bound) = cid {
        if bound != expected_chain_id {
            return Err(format!(
                "rejected: transaction chain-id mismatch: envelope binds chain {bound} but this chain is {expected_chain_id}"
            ));
        }
    }
    check_session_policy(tx, now).map_err(|e| format!("rejected: {e}"))?;
    check_sponsor_policy(tx, now, tx.gas_limit).map_err(|e| format!("rejected: {e}"))?;
    if !verify_transaction_signature(tx, registry) {
        return Err("rejected: transaction PQ signature/envelope verification failed".to_string());
    }
    Ok(())
}
