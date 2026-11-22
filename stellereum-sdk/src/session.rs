//! Falcon-512 session grants (`SF1` framing).
//!
//! The chain accepts two PQ credentials: a first-party `PQ1` envelope, or a
//! transaction signed by a delegated Falcon key that carries its master's
//! grant in an `SF1` envelope
//! (`stellereum/src/sharding/transaction.rs:437-500`).
//!
//! The grant struct is reproduced field-for-field from
//! `stellereum/src/zkml.rs:276-306`, including the bincode field order (a
//! `Serialize` impl, not a derived one, at `zkml.rs:308-365`). The master's
//! signature covers
//! `STELL_SESSKEY_V1 || chain_id || master_address || session_pubkey ||
//! valid_until || max_gas_spend || scope || max_value_per_tx`
//! (`zkml.rs:554-573`); `gas_spent` is deliberately excluded.

use crate::error::{Result, SdkError};
use crate::key::{derive_pq_address, verify_pq_signature, FalconKeypair, FALCON512_SIG_LEN};

/// Domain separator for grant signatures (`stellereum/src/zkml.rs:180`).
pub const SESSION_KEY_DOMAIN: &[u8] = b"STELL_SESSKEY_V1";

/// Scope bit: plain transfers (`stellereum/src/zkml.rs:247`).
pub const SCOPE_TRANSFER: u64 = 1 << 0;
/// Scope bit: any SVM payload (`stellereum/src/zkml.rs:249`).
pub const SCOPE_SVM_PAYLOAD: u64 = 1 << 1;
/// Scope bit: actor mailbox sends (`stellereum/src/zkml.rs:261`).
pub const SCOPE_ACTOR_SEND: u64 = 1 << 2;
/// Everything (`stellereum/src/zkml.rs:263`).
pub const SCOPE_ALL: u64 = u64::MAX;

/// A master-signed Falcon-512 session grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionGrant {
    pub master_address: [u8; 32],
    pub session_pubkey: [u8; 32],
    pub valid_until: u64,
    pub max_gas_spend: u64,
    pub gas_spent: u64,
    pub scope: u64,
    pub max_value_per_tx: u64,
    pub chain_id: u64,
    pub master_signature: Vec<u8>,
    pub master_pubkey: Vec<u8>,
    pub session_pubkey_bytes: Vec<u8>,
}

impl SessionGrant {
    /// Mint a grant: derives both addresses, signs the grant message with the
    /// master key and stores both public keys (the node's verifier requires
    /// them, `zkml.rs:686-696`).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        master: &FalconKeypair,
        session_public_key: &[u8],
        valid_until: u64,
        max_gas_spend: u64,
        scope: u64,
        max_value_per_tx: u64,
        chain_id: u64,
    ) -> Result<Self> {
        let master_address = master.address();
        let session_pubkey = derive_pq_address(session_public_key, &crate::key::DEFAULT_SALT)?;
        let msg = Self::grant_message(
            &master_address,
            &session_pubkey,
            valid_until,
            max_gas_spend,
            scope,
            max_value_per_tx,
            chain_id,
        );
        let master_signature = master.sign(&msg)?;
        Ok(Self {
            master_address,
            session_pubkey,
            valid_until,
            max_gas_spend,
            gas_spent: 0,
            scope,
            max_value_per_tx,
            chain_id,
            master_signature,
            master_pubkey: master.public_key().to_vec(),
            session_pubkey_bytes: session_public_key.to_vec(),
        })
    }

    /// The exact bytes the master signs.
    #[allow(clippy::too_many_arguments)]
    pub fn grant_message(
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

    /// Verify the master's signature and that the stored master key derives
    /// to `master_address`.
    pub fn verify_master(&self) -> bool {
        if self.master_signature.len() != FALCON512_SIG_LEN {
            return false;
        }
        let Ok(expected) = derive_pq_address(&self.master_pubkey, &crate::key::DEFAULT_SALT) else {
            return false;
        };
        if expected != self.master_address {
            return false;
        }
        verify_pq_signature(
            &self.master_pubkey,
            &Self::grant_message(
                &self.master_address,
                &self.session_pubkey,
                self.valid_until,
                self.max_gas_spend,
                self.scope,
                self.max_value_per_tx,
                self.chain_id,
            ),
            &self.master_signature,
        )
    }

    /// `true` when `gas_spent` still leaves the declared budget.
    pub fn remaining_gas(&self) -> u64 {
        self.max_gas_spend.saturating_sub(self.gas_spent)
    }

    /// `true` when the scope mask covers every requested bit.
    pub fn grants_scope(&self, required: u64) -> bool {
        self.scope & required == required
    }

    /// Bincode bytes exactly as the node serializes the grant
    /// (`zkml.rs:347-363`). `PqScheme` is written as its one-byte id.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.master_address);
        out.extend_from_slice(&self.session_pubkey);
        out.extend_from_slice(&self.valid_until.to_le_bytes());
        out.extend_from_slice(&self.max_gas_spend.to_le_bytes());
        out.extend_from_slice(&self.gas_spent.to_le_bytes());
        out.extend_from_slice(&self.scope.to_le_bytes());
        out.extend_from_slice(&self.max_value_per_tx.to_le_bytes());
        out.extend_from_slice(&self.chain_id.to_le_bytes());
        out.extend_from_slice(&(self.master_signature.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.master_signature);
        out.push(crate::key::PQ_SCHEME_FALCON512);
        out.push(crate::key::PQ_SCHEME_FALCON512);
        out.push(1);
        out.extend_from_slice(&(self.master_pubkey.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.master_pubkey);
        out.push(1);
        out.extend_from_slice(&(self.session_pubkey_bytes.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.session_pubkey_bytes);
        out
    }

    /// Decode the node's bincode grant bytes (used by the CLI and tests).
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut c = Cursor { b: bytes, i: 0 };
        let master_address = c.array32()?;
        let session_pubkey = c.array32()?;
        let valid_until = c.u64()?;
        let max_gas_spend = c.u64()?;
        let gas_spent = c.u64()?;
        let scope = c.u64()?;
        let max_value_per_tx = c.u64()?;
        let chain_id = c.u64()?;
        let master_signature = c.vec()?;
        let master_scheme = c.u8()?;
        let session_scheme = c.u8()?;
        if master_scheme != crate::key::PQ_SCHEME_FALCON512
            || session_scheme != crate::key::PQ_SCHEME_FALCON512
        {
            return Err(SdkError::Decode(
                "only Falcon-512 session grants are live".into(),
            ));
        }
        let master_pubkey = c
            .option_vec()?
            .ok_or_else(|| SdkError::Decode("grant is missing the master public key".into()))?;
        let session_pubkey_bytes = c
            .option_vec()?
            .ok_or_else(|| SdkError::Decode("grant is missing the session public key".into()))?;
        if c.i != bytes.len() {
            return Err(SdkError::Decode("trailing bytes after grant".into()));
        }
        Ok(Self {
            master_address,
            session_pubkey,
            valid_until,
            max_gas_spend,
            gas_spent,
            scope,
            max_value_per_tx,
            chain_id,
            master_signature,
            master_pubkey,
            session_pubkey_bytes,
        })
    }
}

struct Cursor<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.b.len() < self.i + n {
            return Err(SdkError::Decode("truncated grant".into()));
        }
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("8-byte slice"),
        ))
    }
    fn array32(&mut self) -> Result<[u8; 32]> {
        Ok(self.take(32)?.try_into().expect("32-byte slice"))
    }
    fn vec(&mut self) -> Result<Vec<u8>> {
        let n = self.u64()?;
        let n = usize::try_from(n).map_err(|_| SdkError::Decode("length overflow".into()))?;
        Ok(self.take(n)?.to_vec())
    }
    fn option_vec(&mut self) -> Result<Option<Vec<u8>>> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.vec()?)),
            v => Err(SdkError::Decode(format!("bad Option tag {v}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_roundtrip_and_verify() {
        let master = FalconKeypair::generate().unwrap();
        let session = FalconKeypair::generate().unwrap();
        let grant = SessionGrant::new(
            &master,
            session.public_key(),
            4_000_000_000,
            10_000_000,
            SCOPE_ALL,
            1_000_000,
            5757,
        )
        .unwrap();
        assert!(grant.verify_master());
        assert_eq!(SessionGrant::decode(&grant.encode()).unwrap(), grant);
        assert_eq!(grant.remaining_gas(), 10_000_000);
    }
}
