//! Minimal canonical transaction-builder SDK for Stellereum (kills B2:
//! "no SDK, wallets hand-roll bincode").
//!
//! Five shapes, nothing more: [`TxBuilder::transfer`], [`TxBuilder::token_transfer`]
//! (+ [`TxBuilder::token_approve`] / [`TxBuilder::token_transfer_from`] /
//! [`TxBuilder::token_mint`] / [`TxBuilder::token_burn`] /
//! [`TxBuilder::token_create`]), [`TxBuilder::stake_bond`]
//! [`TxBuilder::stake_bond`] (+ [`TxBuilder::delegate`] /
//! [`TxBuilder::begin_undelegate`] / [`TxBuilder::undelegate_withdraw`]),
//! [`TxBuilder::contract_deploy`], [`TxBuilder::contract_call`].
//!
//! Rules, all inherited from the node (read-only reuse, nothing reimplemented):
//!
//! * Envelopes are **chain-id BOUND by default** ([`TxBuilder::unbound_legacy`]
//!   is the explicit, loudly-warned escape hatch mirroring `wallet.rs`).
//! * Contract addresses come from the node's own
//!   [`predict_contract_address`] (which is `stellereum::contract::contract_address`,
//!   imported — never reimplemented).
//! * Contract calldata comes from the node's own
//!   [`stellereum::contract_abi::ContractAbi`] encoder.
//! * Signing covers Ed25519, Falcon-512 and Hybrid via the node's
//!   `post_quantum` primitives (same salts, same envelopes the node verifies).
//! * [`SignedTx::fee_estimate_params`] builds exactly the `{"tx": hex}`
//!   shape `stell_estimateFee` expects (`src/rpc.rs` `handle_estimate_fee`,
//!   raw-transaction arm); [`SignedTx::submit`] POSTs exactly the
//!   `{"tx": hex}` shape `stell_sendRawTransaction` expects (`src/rpc.rs`
//!   dispatch arm) and returns the hex tx hash.
//!
//! No live writes happen inside this crate: network calls only fire when the
//! caller explicitly invokes [`SignedTx::fee_estimate`] / [`SignedTx::submit`].

use ed25519_dalek::{Signer as _, SigningKey};
use stellereum::contract_abi::{AbiValue, ContractAbi};
use stellereum::post_quantum::{derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT};
use stellereum::sharding::{PqSignatureEnvelope, Transaction, MASTERCHAIN_SHARD};
use stellereum::svm::{opcode_gas, OpCode, GAS_BASIC_TRANSFER};
use stellereum::zkml::DEFAULT_CHAIN_ID;

// ---------------------------------------------------------------------------
// Re-exports (callers need these types to use the builders)
// ---------------------------------------------------------------------------

pub use stellereum::contract_abi::{AbiError, AbiType};
pub use stellereum::contract_abi::{AbiMethod, AbiParam, ContractAbi as AbiManifest};
pub use stellereum::post_quantum::PqScheme as KeyScheme;

/// Default chain id the SDK binds to: the same constant the node serves as
/// `stell_chainId` unless `STELL_CHAIN_ID` overrides it
/// (`stellereum::zkml::DEFAULT_CHAIN_ID`, 5757 on this deployment).
pub const SDK_DEFAULT_CHAIN_ID: u64 = DEFAULT_CHAIN_ID;

/// Deterministic contract address for `(creator, nonce)`: the SAME function
/// the node uses (`stellereum::contract::contract_address` =
/// `sha256("STELL_CONTRACT" || creator || nonce)`). Imported, not reimplemented.
pub fn predict_contract_address(creator: &[u8; 32], nonce: u64) -> [u8; 32] {
    stellereum::contract::contract_address(creator, nonce)
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/// A wallet signing key for one of the three live schemes.
///
/// Seeds only: the Falcon-512 keypair is re-derived deterministically from
/// `falcon_seed` on every signature via the node's own
/// [`FalconKeypair::generate_from_seed_bytes`], so the SDK never invents key
/// material and never stores a second key format.
#[derive(Clone, Debug)]
pub struct SdkKey {
    scheme: PqScheme,
    ed_seed: [u8; 32],
    falcon_seed: [u8; 32],
}

impl SdkKey {
    /// Classic fast Ed25519 key from a 32-byte seed.
    pub fn ed25519(seed: [u8; 32]) -> Self {
        Self {
            scheme: PqScheme::Ed25519,
            ed_seed: seed,
            falcon_seed: [0u8; 32],
        }
    }

    /// Post-quantum Falcon-512 key, deterministically derived from a 32-byte seed.
    pub fn falcon_from_seed(seed: [u8; 32]) -> Self {
        Self {
            scheme: PqScheme::Falcon512,
            ed_seed: [0u8; 32],
            falcon_seed: seed,
        }
    }

    /// Hybrid dual-signature key (Ed25519 + Falcon-512).
    pub fn hybrid(ed_seed: [u8; 32], falcon_seed: [u8; 32]) -> Self {
        Self {
            scheme: PqScheme::Hybrid,
            ed_seed,
            falcon_seed,
        }
    }

    /// Which scheme this key signs with.
    pub fn scheme(&self) -> PqScheme {
        self.scheme
    }

    fn falcon_keypair(&self) -> FalconKeypair {
        FalconKeypair::generate_from_seed_bytes(&self.falcon_seed)
    }

    fn ed_signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.ed_seed)
    }

    /// Canonical public key bytes (`scheme.pubkey_size()` long).
    pub fn pubkey_bytes(&self) -> Vec<u8> {
        match self.scheme {
            PqScheme::Ed25519 => self.ed_signing_key().verifying_key().to_bytes().to_vec(),
            PqScheme::Falcon512 => self.falcon_keypair().public_key().to_vec(),
            PqScheme::Hybrid => {
                let mut pk = Vec::with_capacity(stellereum::post_quantum::HYBRID_PUBKEY_LEN);
                pk.extend_from_slice(&self.ed_signing_key().verifying_key().to_bytes());
                pk.extend_from_slice(self.falcon_keypair().public_key());
                pk
            }
            // Disabled at the node too (`PqScheme::from_id` refuses 0x03);
            // fail closed here as well.
            PqScheme::MlDsa44 => panic!("stellereum-sdk: ML-DSA-44 (0x03) is disabled"),
        }
    }

    /// The wallet address for this key: the raw public key for Ed25519,
    /// `derive_pq_address(scheme, pubkey, ZERO_SALT)` otherwise — the same
    /// rule `wallet_signing` uses, with the same zero salt.
    pub fn address(&self) -> [u8; 32] {
        match self.scheme {
            PqScheme::Ed25519 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&self.pubkey_bytes());
                a
            }
            s => derive_pq_address(s, &self.pubkey_bytes(), &DEFAULT_SALT),
        }
    }
}

// ---------------------------------------------------------------------------
// Unsigned builder (five shapes, nothing more)
// ---------------------------------------------------------------------------

/// Unsigned transaction under construction.
///
/// Bound to [`SDK_DEFAULT_CHAIN_ID`] unless changed with
/// [`TxBuilder::chain_id`] — or explicitly unbound with
/// [`TxBuilder::unbound_legacy`] (never in production).
#[derive(Clone, Debug)]
pub struct TxBuilder {
    to: Option<[u8; 32]>,
    amount: u64,
    gas_limit: u64,
    nonce: u64,
    source_shard: u32,
    target_shard: u32,
    payload: Vec<OpCode>,
    chain_id: Option<u64>,
}

impl TxBuilder {
    fn payload_tx(payload: Vec<OpCode>, gas_limit: u64, chain_id: Option<u64>) -> Self {
        Self {
            to: None, // resolved to the signer at `sign` (wallet convention)
            amount: 0,
            gas_limit,
            nonce: 0,
            source_shard: MASTERCHAIN_SHARD,
            target_shard: MASTERCHAIN_SHARD,
            payload,
            chain_id,
        }
    }

    /// Plain native transfer `{ to, amount }`.
    pub fn transfer(to: [u8; 32], amount: u64) -> Self {
        Self {
            to: Some(to),
            amount,
            gas_limit: GAS_BASIC_TRANSFER,
            nonce: 0,
            source_shard: MASTERCHAIN_SHARD,
            target_shard: MASTERCHAIN_SHARD,
            payload: Vec::new(),
            chain_id: Some(SDK_DEFAULT_CHAIN_ID),
        }
    }

    /// STS fungible-token transfer `{ token_id, to, amount }`.
    pub fn token_transfer(token_id: [u8; 32], to: [u8; 32], amount: u64) -> Self {
        let op = OpCode::SysCallTokenTransfer {
            token_id,
            to,
            amount,
        };
        let gas = opcode_gas(&op);
        Self::payload_tx(vec![op], gas, Some(SDK_DEFAULT_CHAIN_ID))
    }

    /// STS approve `{ token_id, spender, amount }`.
    pub fn token_approve(token_id: [u8; 32], spender: [u8; 32], amount: u64) -> Self {
        let op = OpCode::SysCallTokenApprove {
            token_id,
            spender,
            amount,
        };
        let gas = opcode_gas(&op);
        Self::payload_tx(vec![op], gas, Some(SDK_DEFAULT_CHAIN_ID))
    }

    /// STS delegated transfer `{ token_id, from, to, amount }`.
    pub fn token_transfer_from(
        token_id: [u8; 32],
        from: [u8; 32],
        to: [u8; 32],
        amount: u64,
    ) -> Self {
        let op = OpCode::SysCallTokenTransferFrom {
            token_id,
            from,
            to,
            amount,
        };
        let gas = opcode_gas(&op);
        Self::payload_tx(vec![op], gas, Some(SDK_DEFAULT_CHAIN_ID))
    }

    /// STS mint `{ token_id, to, amount }` (the minter key must sign).
    pub fn token_mint(token_id: [u8; 32], to: [u8; 32], amount: u64) -> Self {
        let op = OpCode::SysCallTokenMint {
            token_id,
            to,
            amount,
        };
        let gas = opcode_gas(&op);
        Self::payload_tx(vec![op], gas, Some(SDK_DEFAULT_CHAIN_ID))
    }

    /// STS burn `{ token_id, from, amount }` (the holder's key signs a
    /// self-burn; the minter's key signs an admin burn of another account).
    pub fn token_burn(token_id: [u8; 32], from: [u8; 32], amount: u64) -> Self {
        let op = OpCode::SysCallTokenBurn {
            token_id,
            from,
            amount,
        };
        let gas = opcode_gas(&op);
        Self::payload_tx(vec![op], gas, Some(SDK_DEFAULT_CHAIN_ID))
    }

    /// STS token creation `{ name, symbol, decimals, initial_supply,
    /// max_supply }` (the signer becomes the minter; the id commits the
    /// registry nonce, so resolve it with `stell_tokenResolve` after
    /// inclusion).
    pub fn token_create(
        name: String,
        symbol: String,
        decimals: u8,
        initial_supply: u64,
        max_supply: Option<u64>,
    ) -> Self {
        let op = OpCode::SysCallTokenCreate {
            name,
            symbol,
            decimals,
            initial_supply,
            max_supply,
        };
        let gas = opcode_gas(&op);
        Self::payload_tx(vec![op], gas, Some(SDK_DEFAULT_CHAIN_ID))
    }

    /// Stake (bond / top-up) `{ validator, amount }`.
    pub fn stake_bond(validator: [u8; 32], amount: u64) -> Self {
        let op = OpCode::SysCallStake { validator, amount };
        let gas = opcode_gas(&op);
        Self::payload_tx(vec![op], gas, Some(SDK_DEFAULT_CHAIN_ID))
    }

    /// Delegate stake to a validator `{ validator, amount }`.
    pub fn delegate(validator: [u8; 32], amount: u64) -> Self {
        let op = OpCode::SysCallDelegate { validator, amount };
        let gas = opcode_gas(&op);
        Self::payload_tx(vec![op], gas, Some(SDK_DEFAULT_CHAIN_ID))
    }

    /// Start unbonding `{ validator, amount }` (funds mature after cooldown).
    pub fn begin_undelegate(validator: [u8; 32], amount: u64) -> Self {
        let op = OpCode::SysCallBeginUndelegate { validator, amount };
        let gas = opcode_gas(&op);
        Self::payload_tx(vec![op], gas, Some(SDK_DEFAULT_CHAIN_ID))
    }

    /// Withdraw matured unbonding `{ validator }`.
    pub fn undelegate_withdraw(validator: [u8; 32]) -> Self {
        let op = OpCode::SysCallUndelegate { validator };
        let gas = opcode_gas(&op);
        Self::payload_tx(vec![op], gas, Some(SDK_DEFAULT_CHAIN_ID))
    }

    /// Deploy a WASM contract `{ code, abi? }`.
    ///
    /// The on-chain address is deterministic:
    /// [`predict_contract_address`]`(sender, sender_nonce)` — pass the
    /// sender's current nonce to predict where this deploy lands.
    pub fn contract_deploy(code: Vec<u8>) -> Self {
        let op = OpCode::SysCallDeployContract { code };
        let gas = opcode_gas(&op);
        Self::payload_tx(vec![op], gas, Some(SDK_DEFAULT_CHAIN_ID))
    }

    /// Call a contract method with ABI-typed args `{ contract, method, args, value? }`.
    ///
    /// Encodes via the node's own [`ContractAbi`]: `calldata =
    /// abi.encode_args(method, args)` and scalar `args =
    /// args.map(as_i64)` — byte-for-byte the mapping `stell_callContract`
    /// applies in `src/rpc.rs` before execution, so a node replaying the
    /// transaction executes exactly the same call.
    pub fn contract_call(
        contract: [u8; 32],
        method: &str,
        abi: &ContractAbi,
        args: &[AbiValue],
        value: u64,
    ) -> Result<Self, String> {
        let calldata = abi.encode_args(method, args).map_err(|e| e.to_string())?;
        let scalars: Vec<i64> = args.iter().map(|v| v.as_i64().unwrap_or(0)).collect();
        let op = OpCode::SysCallCallContractArgs {
            contract,
            method: method.as_bytes().to_vec(),
            args: scalars,
            calldata,
        };
        let gas = opcode_gas(&op);
        let mut b = Self::payload_tx(vec![op], gas, Some(SDK_DEFAULT_CHAIN_ID));
        b.to = Some(contract);
        b.amount = value;
        Ok(b)
    }

    /// Sender nonce (default 0 — read it from `stell_getBalance`).
    pub fn nonce(mut self, nonce: u64) -> Self {
        self.nonce = nonce;
        self
    }

    /// Override the gas limit (default: the node's own `opcode_gas` /
    /// `GAS_BASIC_TRANSFER` for the shape — the same floor the mempool enforces).
    pub fn gas_limit(mut self, gas_limit: u64) -> Self {
        self.gas_limit = gas_limit;
        self
    }

    /// Override shards (default: masterchain → masterchain).
    pub fn shards(mut self, source: u32, target: u32) -> Self {
        self.source_shard = source;
        self.target_shard = target;
        self
    }

    /// Override the recipient (payload shapes default to the signer, the
    /// wallet convention for syscall-carrying transactions).
    pub fn to(mut self, to: [u8; 32]) -> Self {
        self.to = Some(to);
        self
    }

    /// Bind to a different chain id (default [`SDK_DEFAULT_CHAIN_ID`]).
    pub fn chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = Some(chain_id);
        self
    }

    /// LEGACY escape hatch: build the old UNBOUND (replayable, no chain id)
    /// envelope. Mirrors `wallet.rs::unbound_legacy_*`: every use prints a
    /// loud warning, and the rollout plan ends with admission refusing
    /// unbound transactions outright. **Never use in production.**
    pub fn unbound_legacy(mut self) -> Self {
        eprintln!(
            "WARNING stellereum-sdk: building an UNBOUND (replayable, no chain id) \
             transaction — prefer the bound default; unbound admission is metered \
             and will be refused (wallet rule, A14 rollout phase 1)"
        );
        self.chain_id = None;
        self
    }

    /// `true` when this builder will produce a chain-bound envelope.
    pub fn is_bound(&self) -> bool {
        self.chain_id.is_some()
    }

    /// Sign with any of the three live schemes and return the sealed transaction.
    ///
    /// The signature is verified against the freshly built transaction before
    /// returning (fail-closed self-check), so a `SignedTx` from this function
    /// always passes node admission's `verify_signature`.
    pub fn sign(self, key: &SdkKey) -> Result<SignedTx, String> {
        let from = key.address();
        let to = self.to.unwrap_or(from);
        let tx = match key.scheme {
            PqScheme::Ed25519 => {
                let sk = key.ed_signing_key();
                if let Some(cid) = self.chain_id {
                    Transaction::sign_with_payload_and_chain_id(
                        &sk,
                        to,
                        self.amount,
                        self.gas_limit,
                        self.nonce,
                        self.source_shard,
                        self.target_shard,
                        self.payload,
                        cid,
                    )
                } else {
                    Transaction::sign_with_payload(
                        &sk,
                        to,
                        self.amount,
                        self.gas_limit,
                        self.nonce,
                        self.source_shard,
                        self.target_shard,
                        self.payload,
                    )
                }
            }
            scheme @ (PqScheme::Falcon512 | PqScheme::Hybrid) => {
                // Same flow the node's own PQ tests use: probe the signing
                // message (which commits the chain id when bound), sign it,
                // then wrap in the explicit PQ envelope the node verifies.
                let probe = Transaction {
                    from,
                    to,
                    amount: self.amount,
                    gas_limit: self.gas_limit,
                    nonce: self.nonce,
                    source_shard: self.source_shard,
                    target_shard: self.target_shard,
                    signature: Vec::new(),
                    payload: self.payload.clone(),
                    priority_fee_per_gas: 0,
                };
                let msg = match self.chain_id {
                    Some(cid) => probe.signing_message_for_chain(cid),
                    None => probe.signing_message(),
                };
                let sig = match scheme {
                    PqScheme::Falcon512 => key.falcon_keypair().sign(&msg),
                    _ => {
                        let mut s = Vec::with_capacity(stellereum::post_quantum::HYBRID_SIG_LEN);
                        s.extend_from_slice(&key.ed_signing_key().sign(&msg).to_bytes());
                        s.extend_from_slice(&key.falcon_keypair().sign(&msg));
                        s
                    }
                };
                let pubkey = key.pubkey_bytes();
                let envelope = match self.chain_id {
                    Some(cid) => PqSignatureEnvelope::new_explicit_with_chain(
                        scheme,
                        pubkey,
                        sig,
                        DEFAULT_SALT,
                        cid,
                    ),
                    None => PqSignatureEnvelope::new_explicit(scheme, pubkey, sig),
                };
                Transaction {
                    from,
                    to,
                    amount: self.amount,
                    gas_limit: self.gas_limit,
                    nonce: self.nonce,
                    source_shard: self.source_shard,
                    target_shard: self.target_shard,
                    signature: envelope.encode(),
                    payload: self.payload,
                    priority_fee_per_gas: 0,
                }
            }
            PqScheme::MlDsa44 => {
                return Err("stellereum-sdk: ML-DSA-44 (0x03) is disabled".to_string())
            }
        };
        if !tx.verify_signature() {
            return Err(
                "stellereum-sdk: freshly signed transaction failed verification".to_string(),
            );
        }
        Ok(SignedTx { tx })
    }
}

// ---------------------------------------------------------------------------
// Signed transaction
// ---------------------------------------------------------------------------

/// A signed, sealed transaction ready for fee estimation, hashing and submission.
#[derive(Clone, Debug)]
pub struct SignedTx {
    tx: Transaction,
}

impl SignedTx {
    /// Exact wire bytes: `bincode` of the node `Transaction` struct — the same
    /// bytes `stell_sendRawTransaction` decodes.
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self.tx).expect("Transaction always serializes")
    }

    /// Hex of [`SignedTx::to_bytes`] (what the RPC takes, `0x` optional).
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Canonical transaction hash (`Transaction::compute_tx_hash`).
    pub fn tx_hash(&self) -> [u8; 32] {
        self.tx.compute_tx_hash()
    }

    /// Hex of [`SignedTx::tx_hash`] (what the node returns on submit).
    pub fn tx_hash_hex(&self) -> String {
        hex::encode(self.tx_hash())
    }

    /// `true` when the envelope commits a chain id.
    pub fn is_bound(&self) -> bool {
        self.tx.chain_id().is_some()
    }

    /// The bound chain id, if any.
    pub fn chain_id(&self) -> Option<u64> {
        self.tx.chain_id()
    }

    /// Verify the signature (and the chain binding when bound) exactly like
    /// node admission does.
    pub fn verify(&self) -> bool {
        match self.tx.chain_id() {
            Some(cid) => self.tx.verify_signature_for_chain(cid, true),
            None => self.tx.verify_signature(),
        }
    }

    /// Borrow the underlying node transaction (for advanced use).
    pub fn as_node_tx(&self) -> &Transaction {
        &self.tx
    }

    /// The exact `params` object `stell_estimateFee` expects for a raw
    /// transaction: `{"tx": "<hex>"}` — verified against the
    /// `handle_estimate_fee` raw-transaction arm in `src/rpc.rs` and the
    /// `test_estimate_fee_*` vectors in `docs/RPC.md` §4.
    pub fn fee_estimate_params(&self) -> serde_json::Value {
        serde_json::json!({ "tx": self.to_hex() })
    }

    /// Ask the node what this transaction will cost (`stell_estimateFee`
    /// with [`SignedTx::fee_estimate_params`]). Read-only: no state moves.
    pub fn fee_estimate(&self, rpc_url: &str) -> Result<FeeEstimate, String> {
        let v = rpc_call(rpc_url, "stell_estimateFee", self.fee_estimate_params())?;
        FeeEstimate::from_json(&v)
    }

    /// Submit to the mempool (`stell_sendRawTransaction` with
    /// `{"tx": "<hex>"}` — verified against the dispatch arm in `src/rpc.rs`).
    /// Returns the hex tx hash on admission.
    pub fn submit(&self, rpc_url: &str) -> Result<String, String> {
        let v = rpc_call(
            rpc_url,
            "stell_sendRawTransaction",
            serde_json::json!({ "tx": self.to_hex() }),
        )?;
        v.as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| format!("stell_sendRawTransaction: unexpected result shape: {v}"))
    }
}

/// The node's fee answer: `gas_limit`, `estimated_fee`, `base_fee`
/// (decimal-or-number `u64`s), shard routing and the simulation budget.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeEstimate {
    pub gas_limit: u64,
    pub estimated_fee: u64,
    pub base_fee: u64,
    pub source_shard: u32,
    pub target_shard: u32,
    pub is_cross_shard: bool,
}

impl FeeEstimate {
    fn u64_field(v: &serde_json::Value, name: &str) -> Result<u64, String> {
        let f = v
            .get(name)
            .ok_or_else(|| format!("stell_estimateFee: missing field {name:?}"))?;
        if let Some(n) = f.as_u64() {
            return Ok(n);
        }
        if let Some(s) = f.as_str() {
            return s
                .parse::<u64>()
                .map_err(|_| format!("stell_estimateFee: field {name:?} is not a u64"));
        }
        Err(format!("stell_estimateFee: field {name:?} is not a u64"))
    }

    /// Parse the `result` object of a `stell_estimateFee` answer.
    pub fn from_json(v: &serde_json::Value) -> Result<Self, String> {
        Ok(Self {
            gas_limit: Self::u64_field(v, "gas_limit")?,
            estimated_fee: Self::u64_field(v, "estimated_fee")?,
            base_fee: Self::u64_field(v, "base_fee")?,
            source_shard: Self::u64_field(v, "source_shard")? as u32,
            target_shard: Self::u64_field(v, "target_shard")? as u32,
            is_cross_shard: v
                .get("is_cross_shard")
                .and_then(|b| b.as_bool())
                .unwrap_or(false),
        })
    }
}

/// One JSON-RPC call over HTTP POST. Pure transport: no signing, no state.
fn rpc_call(
    rpc_url: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let resp = ureq::post(rpc_url)
        .send_json(body)
        .map_err(|e| format!("{method}: transport error: {e}"))?;
    let v: serde_json::Value = resp
        .into_json()
        .map_err(|e| format!("{method}: bad JSON response: {e}"))?;
    if let Some(err) = v.get("error") {
        return Err(format!("{method}: node refused: {err}"));
    }
    v.get("result")
        .cloned()
        .ok_or_else(|| format!("{method}: missing result in response: {v}"))
}

// ---------------------------------------------------------------------------
// Notes on what is deliberately NOT in scope
// ---------------------------------------------------------------------------
//
// * `SysCallClaimRewards` / `SysCallClaimDelegatorRewards` /
//   `SysCallRotateValidatorKey`: real opcodes, but claiming and key rotation
//   are operator flows, not the five wallet shapes — left out, use a raw
//   `OpCode` payload via the node wallet instead.
// * Priority bids (`priority_fee_per_gas`), session-key envelopes and EVM
//   settlement envelopes: consensus-level envelope variants the SDK does not
//   mint; every SDK transaction is a plain first-party signature (Ed25519 CH1
//   or PQ explicit-with-chain).
