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
use crate::key::{derive_pq_address, FalconKeypair, DEFAULT_SALT, FALCON512_SIG_LEN};
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

/// Masterchain shard id (`stellereum/src/sharding/topology.rs:7-8`).
pub const MASTERCHAIN_SHARD: u32 = 0;

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

    /// The exact preimage the credential signs.
    ///
    /// This is the node's `Transaction::signing_message()`
    /// (`transaction.rs:1319-1376`) for PQ and session envelopes: base
    /// fields, `PAYLOAD` commitment, optional `PRIORITY` commitment, then
    /// either the `SESSION` commitment (SF1) or the `CHAIN_ID` commitment
    /// (PQ1). A PQ envelope's chain id is also carried in the envelope, but
    /// it is committed into the message (and therefore into the signature)
    /// by the same tag.
    pub fn signing_message(&self) -> Vec<u8> {
        let mut msg = self.base_signing_message();
        if let Some(grant) = self.session_grant() {
            msg.extend_from_slice(&session_commitment(&grant));
        } else if let Some(cid) = self.bound_chain_id() {
            msg.extend_from_slice(CHAIN_ID_COMMITMENT_TAG);
            msg.extend_from_slice(&cid.to_be_bytes());
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

    fn base_signing_message(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(128);
        msg.extend_from_slice(&self.from);
        msg.extend_from_slice(&self.to);
        msg.extend_from_slice(&self.amount.to_be_bytes());
        msg.extend_from_slice(&self.gas_limit.to_be_bytes());
        msg.extend_from_slice(&self.nonce.to_be_bytes());
        msg.extend_from_slice(&self.source_shard.to_be_bytes());
        msg.extend_from_slice(&self.target_shard.to_be_bytes());
        msg.extend_from_slice(PAYLOAD_COMMITMENT_TAG);
        msg.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        msg.extend_from_slice(&self.payload);
        if self.priority_fee_per_gas != 0 {
            msg.extend_from_slice(PRIORITY_FEE_COMMITMENT_TAG);
            msg.extend_from_slice(&self.priority_fee_per_gas.to_be_bytes());
        }
        msg
    }

    /// Parse the `PQ1` envelope, if this is a PQ transaction.
    pub fn pq_envelope(&self) -> Option<PqEnvelope> {
        if !self
            .signature
            .starts_with(crate::envelope::PQ_ENVELOPE_MAGIC)
        {
            return None;
        }
        PqEnvelope::decode(&self.signature).ok()
    }

    /// Parse the `SF1` session grant, if this is a session transaction.
    pub fn session_grant(&self) -> Option<SessionGrant> {
        let sig_len = FALCON512_SIG_LEN;
        let tag_len = SESSION_FALCON_SIG_TAG.len();
        if self.signature.len() <= sig_len + tag_len {
            return None;
        }
        if &self.signature[sig_len..sig_len + tag_len] != SESSION_FALCON_SIG_TAG {
            return None;
        }
        SessionGrant::decode(&self.signature[sig_len + tag_len..]).ok()
    }

    /// The credential's chain id: the envelope's for PQ1, the grant's for
    /// `SF1`, `None` for an unbound envelope.
    pub fn chain_id(&self) -> Option<u64> {
        if let Some(g) = self.session_grant() {
            return Some(g.chain_id);
        }
        self.pq_envelope().and_then(|e| e.chain_id)
    }

    fn bound_chain_id(&self) -> Option<u64> {
        self.chain_id()
    }

    /// True for an explicit PQ1 activation transaction (the node only charges
    /// the surcharge for these, `mempool.rs:1066-1072`).
    pub fn is_pq_activation(&self) -> bool {
        self.pq_envelope().map(|e| e.is_explicit()).unwrap_or(false)
    }

    /// Canonical SHA-256 transaction hash, byte-identical to
    /// `Transaction::compute_tx_hash` (`transaction.rs:813-890`).
    pub fn compute_tx_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.from);
        h.update(self.to);
        h.update(self.amount.to_be_bytes());
        h.update(self.gas_limit.to_be_bytes());
        h.update(self.nonce.to_be_bytes());
        h.update(self.source_shard.to_be_bytes());
        h.update(self.target_shard.to_be_bytes());
        h.update(PAYLOAD_COMMITMENT_TAG);
        h.update((self.payload.len() as u32).to_be_bytes());
        h.update(&self.payload);
        if self.priority_fee_per_gas != 0 {
            h.update(PRIORITY_FEE_COMMITMENT_TAG);
            h.update(self.priority_fee_per_gas.to_be_bytes());
        }
        if let Some(grant) = self.session_grant() {
            h.update(session_commitment(&grant));
        }
        // `is_pq()` is true iff the inner signature starts with "PQ1".
        if self
            .signature
            .starts_with(crate::envelope::PQ_ENVELOPE_MAGIC)
        {
            h.update(PQ_ENVELOPE_HASH_TAG);
            h.update(&self.signature);
        }
        h.finalize().into()
    }
}

fn session_commitment(grant: &SessionGrant) -> Vec<u8> {
    let bytes = grant.encode();
    let mut out = Vec::with_capacity(SESSION_COMMITMENT_TAG.len() + 4 + bytes.len());
    out.extend_from_slice(SESSION_COMMITMENT_TAG);
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&bytes);
    out
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

/// Attach a `PQ1` envelope to an UNSIGNED transaction.
///
/// Used by the signer sidecar's `sign_prepared` arm: the TypeScript package
/// builds the unsigned transaction bytes, the Rust process owns the Falcon
/// key and produces the envelope. Refuses an `SF1` payload here (session
/// grants need the grant object, not a bare envelope).
pub fn sign_unsigned(
    mut tx: Transaction,
    key: &FalconKeypair,
    mode: EnvelopeMode,
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
    if let Some(cid) = chain_id {
        ProtocolIdentity::local().verify_for_chain(cid)?;
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

    /// Bond (or top up) a validator. The amount leaves the sender.
    pub fn stake(validator: [u8; 32], amount: u64) -> Self {
        Self::payload_builder(vec![Op::Stake { validator, amount }], amount)
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
        if let Ok(addr) = derive_pq_address(session_key.public_key(), &DEFAULT_SALT) {
            if addr != grant.session_pubkey {
                return Err(SdkError::InvalidArgument(
                    "session key address does not match the grant's session_pubkey".into(),
                ));
            }
        } else {
            return Err(SdkError::InvalidKey(
                "session key is not a 897-byte Falcon-512 public key".into(),
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
        let required = if self.ops.is_empty() {
            crate::session::SCOPE_TRANSFER
        } else {
            crate::session::SCOPE_SVM_PAYLOAD
        };
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
        let from = grant.master_address;
        let to = self.to.unwrap_or(from);
        let mut tx = self.unsigned(from, to);
        let msg = tx.signing_message_with_session(grant);
        let sig = session_key.sign(&msg)?;
        let mut signature = Vec::with_capacity(sig.len() + 3 + grant.encode().len());
        signature.extend_from_slice(&sig);
        signature.extend_from_slice(SESSION_FALCON_SIG_TAG);
        signature.extend_from_slice(&grant.encode());
        tx.signature = signature;
        let signed = SignedTx { tx };
        signed
            .verify_session(session_key)
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

    /// The raw SVM payload bytes.
    pub fn payload_bytes(&self) -> &[u8] {
        &self.tx.payload
    }

    /// Verify an explicit `PQ1` transaction locally, exactly like node
    /// admission: envelope decodes, address derives from the carried key,
    /// chain id matches, signature verifies over the signing message.
    pub fn verify(&self) -> Result<()> {
        let env = self
            .tx
            .pq_envelope()
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
        let msg = match env.chain_id {
            Some(cid) => self.tx.signing_message_for_chain(cid),
            None => self.tx.signing_message(),
        };
        if crate::key::verify_pq_signature(pk, &msg, &env.signature) {
            Ok(())
        } else {
            Err(SdkError::VerificationFailed(
                "Falcon-512 signature does not verify".into(),
            ))
        }
    }

    /// Verify with the original key (needed for implicit envelopes).
    pub fn verify_with_key(&self, key: &FalconKeypair) -> Result<()> {
        if key.address() != self.tx.from {
            return Err(SdkError::VerificationFailed(
                "key address != tx.from".into(),
            ));
        }
        let env = self
            .tx
            .pq_envelope()
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
        let msg = match env.chain_id {
            Some(cid) => self.tx.signing_message_for_chain(cid),
            None => self.tx.signing_message(),
        };
        if crate::key::verify_pq_signature(key.public_key(), &msg, &env.signature) {
            Ok(())
        } else {
            Err(SdkError::VerificationFailed(
                "Falcon-512 signature does not verify".into(),
            ))
        }
    }

    /// Verify an `SF1` transaction against the session key.
    pub fn verify_session(&self, session_key: &FalconKeypair) -> Result<()> {
        let grant = self
            .tx
            .session_grant()
            .ok_or_else(|| SdkError::VerificationFailed("not an SF1 envelope".into()))?;
        if !grant.verify_master() {
            return Err(SdkError::VerificationFailed(
                "grant master signature does not verify".into(),
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
        let sig = &self.tx.signature[..FALCON512_SIG_LEN];
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
}
