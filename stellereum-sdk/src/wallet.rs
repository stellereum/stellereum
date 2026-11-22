//! Wallet helper: key + RPC + a conservative nonce cache.
//!
//! The nonce cache exists to make sequential sends convenient, NOT to make
//! retries safe: submission retries resend one already-signed [`SignedTx`]
//! and never touch this cache or the signer. The cache advances only after
//! the node accepted the transaction (or answered "already in mempool").

use std::time::Duration;

use crate::error::{Result, SdkError};
use crate::key::FalconKeypair;
use crate::opcode::CallArg;
use crate::rpc::{Receipt, RetryPolicy, RpcClient, SubmitOutcome};
use crate::session::SessionGrant;
use crate::tx::{SignedTx, TxBuilder, DEFAULT_CHAIN_ID, FROZEN_MIN_GAS_FLOOR};

/// A signing key bound to an RPC endpoint and an optional chain id.
#[derive(Clone, Debug)]
pub struct Wallet {
    key: FalconKeypair,
    rpc: RpcClient,
    chain_id: u64,
    identity: crate::protocol::ProtocolIdentity,
    next_nonce: Option<u64>,
}

impl Wallet {
    /// New wallet using the default chain id (5757).
    pub fn new(key: FalconKeypair, rpc: RpcClient) -> Self {
        Self {
            key,
            rpc,
            chain_id: DEFAULT_CHAIN_ID,
            identity: crate::protocol::ProtocolIdentity::local(),
            next_nonce: None,
        }
    }

    /// Convenience: build the RPC client from a URL.
    pub fn connect(key: FalconKeypair, url: impl Into<String>) -> Self {
        Self::new(key, RpcClient::new(url))
    }

    /// Override the chain id this wallet binds.
    pub fn with_chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = chain_id;
        self.identity.chain_id = chain_id;
        self
    }

    /// Configure the node's advertised protocol identity. A fork/protocol
    /// mismatch makes every `build`/`sign` fail before signing.
    pub fn with_identity(mut self, identity: crate::protocol::ProtocolIdentity) -> Self {
        self.chain_id = identity.chain_id;
        self.identity = identity;
        self
    }

    /// The configured node identity.
    pub fn identity(&self) -> crate::protocol::ProtocolIdentity {
        self.identity
    }

    /// The signing key.
    pub fn key(&self) -> &FalconKeypair {
        &self.key
    }

    /// The RPC client.
    pub fn rpc(&self) -> &RpcClient {
        &self.rpc
    }

    /// The bound chain id.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// The wallet's 32-byte address.
    pub fn address(&self) -> [u8; 32] {
        self.key.address()
    }

    /// Read balance and on-chain nonce.
    pub fn account(&self) -> Result<crate::rpc::Account> {
        self.rpc.account(&self.address())
    }

    /// Drop the cached nonce; the next send reads `stell_getBalance`.
    pub fn reset_nonce(&mut self) {
        self.next_nonce = None;
    }

    /// The nonce the next transaction will use, reading the node if the cache
    /// is empty.
    pub fn next_nonce(&mut self) -> Result<u64> {
        if let Some(n) = self.next_nonce {
            return Ok(n);
        }
        let n = self.rpc.nonce(&self.address())?;
        self.next_nonce = Some(n);
        Ok(n)
    }

    /// Fill nonce, chain id and the node's current base floor into a builder.
    /// This does NOT sign; [`Wallet::sign`] does.
    pub fn prepare(&mut self, builder: TxBuilder) -> Result<TxBuilder> {
        let nonce = self.next_nonce()?;
        let base = self
            .rpc
            .base_fee()
            .unwrap_or(crate::tx::FROZEN_MIN_GAS_FLOOR);
        Ok(builder
            .nonce(nonce)
            .identity(self.identity)
            .chain_id(self.chain_id)
            .base_fee(base))
    }

    /// Sign a prepared builder with this wallet's key.
    pub fn sign(&self, builder: TxBuilder) -> Result<SignedTx> {
        builder
            .identity(self.identity)
            .chain_id(self.chain_id)
            .sign(&self.key)
    }

    /// Prepare and sign in one call.
    pub fn build(&mut self, builder: TxBuilder) -> Result<SignedTx> {
        let prepared = self.prepare(builder)?;
        self.sign(prepared)
    }

    /// Sign a delegated transaction with an `SF1` grant. The wallet's key is
    /// the SESSION key; the master address and nonce come from the grant's
    /// master account, which the caller must track (use a separate wallet
    /// whose key is the master, or pass the nonce explicitly).
    pub fn build_session(
        &mut self,
        builder: TxBuilder,
        session_key: &FalconKeypair,
        grant: &SessionGrant,
    ) -> Result<SignedTx> {
        let nonce = self.rpc.nonce(&grant.master_address)?;
        let base = self
            .rpc
            .base_fee()
            .unwrap_or(crate::tx::FROZEN_MIN_GAS_FLOOR);
        let prepared = builder
            .nonce(nonce)
            .identity(self.identity)
            .chain_id(grant.chain_id)
            .base_fee(base);
        prepared.sign_with_session(session_key, grant)
    }

    /// Transfer `amount` to `to`.
    pub fn transfer(&mut self, to: [u8; 32], amount: u64) -> Result<SignedTx> {
        self.build(TxBuilder::transfer(to, amount))
    }

    /// Call a contract with typed arguments and an optional native value.
    pub fn contract_call(
        &mut self,
        contract: [u8; 32],
        method: &str,
        args: &[CallArg],
        value: u64,
    ) -> Result<SignedTx> {
        let b = TxBuilder::contract_call(contract, method, args, value)?;
        self.build(b)
    }

    /// Bond or top up a validator.
    pub fn stake(&mut self, validator: [u8; 32], amount: u64) -> Result<SignedTx> {
        self.build(TxBuilder::stake(validator, amount))
    }

    /// Unjail a validator, optionally with a top-up in the same payload.
    pub fn unjail(&mut self, validator: [u8; 32], top_up: Option<u64>) -> Result<SignedTx> {
        self.build(TxBuilder::unjail(validator, top_up))
    }

    /// Register `evm_address` for this wallet's PQ account.
    ///
    /// `evm_proof` is the 65-byte secp256k1 proof of possession
    /// (`r || s || recovery_id`) over the canonical binding digest; a missing
    /// or non-recovering proof is refused before signing.
    pub fn evm_binding(&mut self, evm_address: [u8; 20], evm_proof: Vec<u8>) -> Result<SignedTx> {
        let nonce = self.next_nonce()?;
        let base = self.rpc.base_fee().unwrap_or(FROZEN_MIN_GAS_FLOOR);
        let gas = crate::evm::EVM_BINDING_MIN_GAS
            .max(base)
            .saturating_add(crate::tx::PQ_ACTIVATION_SURCHARGE_GAS);
        crate::evm::EvmBindingBuilder::new(self.identity, evm_address, evm_proof)?
            .nonce(nonce)
            .gas_limit(gas)
            .sign(&self.key)
    }

    /// Settle an EVM value-transfer intent. The carrier nonce and amount are
    /// taken from the intent; `to_pq` is the recipient's bound PQ account.
    pub fn evm_carrier(&mut self, raw_evm_tx: Vec<u8>, to_pq: [u8; 32]) -> Result<SignedTx> {
        let base = self.rpc.base_fee().unwrap_or(FROZEN_MIN_GAS_FLOOR);
        let gas = crate::evm::EVM_CARRIER_MIN_GAS
            .max(base)
            .saturating_add(crate::tx::PQ_ACTIVATION_SURCHARGE_GAS);
        crate::evm::EvmCarrierBuilder::new(self.identity, raw_evm_tx, to_pq)?
            .gas_limit(gas)
            .sign(&self.key)
    }

    /// Block-carried governance proposal from this wallet's account.
    pub fn gov_propose(
        &mut self,
        proposal_id: u64,
        title: String,
        action: crate::governance::GovAction,
        height_observed: u64,
    ) -> Result<SignedTx> {
        let builder = TxBuilder::gov_propose(proposal_id, title, action, height_observed)?;
        self.build(builder)
    }

    /// Block-carried governance vote from this wallet's account.
    pub fn gov_vote(
        &mut self,
        proposal_id: u64,
        choice: crate::governance::VoteChoice,
        height_observed: u64,
    ) -> Result<SignedTx> {
        self.build(TxBuilder::gov_vote(proposal_id, choice, height_observed))
    }

    /// Submit a signed transaction with retries. The nonce cache advances
    /// only on success (including "already in mempool").
    pub fn submit(&mut self, signed: &SignedTx, policy: &RetryPolicy) -> Result<SubmitOutcome> {
        let outcome = self.rpc.send_with_retry(signed, policy)?;
        if self.next_nonce.is_none_or(|n| signed.nonce() >= n) {
            self.next_nonce = Some(signed.nonce().saturating_add(1));
        }
        Ok(outcome)
    }

    /// Submit and wait for a receipt.
    pub fn submit_and_wait(
        &mut self,
        signed: &SignedTx,
        policy: &RetryPolicy,
        timeout: Duration,
        poll: Duration,
    ) -> Result<(SubmitOutcome, Receipt)> {
        let outcome = self.submit(signed, policy)?;
        let receipt = self.rpc.wait_for_receipt(&outcome.tx_hash, timeout, poll)?;
        Ok((outcome, receipt))
    }

    /// Ensure the on-chain balance covers `amount + gas_limit (+ surcharge)`,
    /// exactly the node's `tx_cost` (`stellereum/src/mempool.rs:859-867`).
    pub fn check_affordable(&self, signed: &SignedTx) -> Result<()> {
        let account = self.account()?;
        let need = signed
            .amount()
            .saturating_add(signed.gas_limit())
            .saturating_add(if signed.is_pq_activation() {
                crate::tx::PQ_ACTIVATION_SURCHARGE_GAS
            } else {
                0
            });
        if account.balance < need {
            return Err(SdkError::InsufficientBalance {
                need,
                have: account.balance,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_cost_includes_activation_surcharge() {
        let key = FalconKeypair::generate().unwrap();
        let signed = TxBuilder::transfer([1u8; 32], 10)
            .nonce(0)
            .sign(&key)
            .unwrap();
        let need = signed.amount()
            + signed.gas_limit()
            + if signed.is_pq_activation() {
                crate::tx::PQ_ACTIVATION_SURCHARGE_GAS
            } else {
                0
            };
        assert_eq!(
            need,
            10 + crate::tx::FROZEN_MIN_GAS_FLOOR + 2 * crate::tx::PQ_ACTIVATION_SURCHARGE_GAS
        );
    }
}
