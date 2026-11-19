//! EVM address ↔ post-quantum account BINDING and the PQ **carrier** envelope
//! (the EVM WRITE path).
//!
//! # Why a binding at all
//!
//! On this chain a secp256k1 signature is never a consensus credential
//! (FULL-PQ): value moves only under a Falcon-512 signature whose derived
//! address (`derive_pq_address(Falcon512, pubkey, DEFAULT_SALT)`) IS the
//! debited account. A MetaMask account is a secp256k1 key whose EVM address is
//! `keccak256(pubkey)[12..]`, which no PQ key derives. The two identities can
//! therefore only be joined by an explicit, PQ-signed STATEMENT, never by
//! arithmetic on the addresses.
//!
//! That statement is a **binding**: `EVM address (20) → PQ address (32)`,
//! signed by BOTH keys — a Falcon-512 signature by the PQ account AND a
//! secp256k1 proof of possession by the EVM key whose address is being bound
//! (without the latter, any PQ key could first-claim somebody else's EVM
//! identity; see [`verify_binding_claim`]):
//!
//! ```text
//! binding_message(chain_id, evm, pq) =
//!     keccak256("STELL_EVM_BIND_V1" || chain_id_be(8) || evm(20) || pq(32))
//! ```
//!
//! It rides a block as [`crate::svm::OpCode::SysCallBindEvmAddress`], so it is
//! committed, ordered, and re-verifiable from block bytes alone.
//!
//! # The carrier
//!
//! An EVM intent is settled by a **carrier transaction**: a normal PQ1
//! (Falcon-512) Stellereum transaction whose
//! [`crate::svm::OpCode::SysCallEvmCarrier`] payload carries
//!
//! * `evm_tx` — the canonical EIP-155 / EIP-1559 bytes MetaMask produced;
//! * `evm_address` — the EVM sender (`keccak256(secp_pubkey)[12..]`);
//! * `pq_pubkey` — the Falcon-512 key of the debited PQ account;
//! * `evm_signature` — Falcon-512 over `keccak256(evm_tx)`.
//!
//! The transaction's own `from` is the bound PQ account, `to` is the
//! recipient's PQ account, `amount` is the EVM value in nano-STELL and `nonce`
//! is the EVM intent's nonce. Two independent PQ statements must therefore
//! both verify for money to move:
//!
//! 1. the **envelope** (`Transaction.signature`, PQ1): Falcon-512 over the
//!    Stell signing message, which commits to `from`, `to`, `amount`, `nonce`
//!    AND the whole payload (hence the EVM bytes) — this is the consensus
//!    credential, checked by `Transaction::verify_signature` on every path;
//! 2. the **intent authorisation** (`evm_signature`): Falcon-512 over
//!    `keccak256(evm_tx)` by the same PQ key. It is what makes the EVM intent
//!    self-contained — a light client, an audit, or the RPC can check that the
//!    PQ account authorised THIS EVM transaction without knowing Stell's
//!    signing-message format.
//!
//! The secp256k1 signature inside `evm_tx` is verified too (chain id, low-s,
//! ecrecover) but it is **advisory**: it proves the classical key agrees, and
//! it is what routes the intent to the right EVM address. It never authorises
//! the movement.
//!
//! # Value transfers only (this wave)
//!
//! * `to` present, `data` empty, `value > 0` — settled as a plain transfer
//!   from the bound PQ account to the recipient's PQ account;
//! * contract creation (`to == None`) and any calldata are refused honestly
//!   ([`EVM_CONTRACT_EXECUTION_REFUSAL`]): there is no EVM interpreter and no
//!   EVM state trie in this wave, so a "successful" call would be a lie.
//!
//! # What the binding registry is (and is not)
//!
//! The registry ([`EvmBindingRegistry`]) is a **deterministic replay index**
//! over committed binding records (exposed to the engine as
//! `InMemoryStateEngine::evm_binding_pq` / `observe_committed_evm_txs`), not a
//! state-root domain: writing one needs a per-transaction hook in
//! `state_engine/apply.rs`, which this wave does not own. It is used to
//! resolve an EVM address to its PQ account for RPC reads
//! (`eth_getBalance`, `eth_getTransactionCount`), for the recipient leg, and
//! for admission policy. Correctness never depends on it: every consensus
//! fact is re-checked from the signature + payload alone by the VM
//! ([`verify_carrier_intent`], [`verify_binding_claim`] are pure functions),
//! so a stale or empty index can refuse a transaction but can never fork a
//! node into moving money it should not.

use super::*;
use crate::post_quantum::{
    derive_pq_address, verify_pq_signature, PqScheme, DEFAULT_SALT, FALCON512_PUBKEY_LEN,
    FALCON512_SIG_LEN,
};
use crate::sharding::{Transaction, MASTERCHAIN_SHARD};
use crate::svm::{EvmAddressClaim, EvmCarrierIntent, OpCode};
use std::collections::{HashMap, VecDeque};

/// Domain separator of the EVM↔PQ binding statement (versioned).
pub const EVM_BINDING_DOMAIN: &[u8] = b"STELL_EVM_BIND_V1";

/// Gas limit a PQ-built carrier declares when the EVM intent asks for less.
///
/// The declared `gas_limit` is a RESOURCE CAP that also has to cover the
/// admission floor (`base_fee + D2 penalty + PQ activation surcharge + carrier
/// surcharge`), so a MetaMask `21000` cannot be carried verbatim. The builder
/// uses `max(evm.gas_limit, floor + surcharge, this)`; the constant is the
/// floor for a healthy (unpenalised) sender and keeps the carrier message
/// reproducible by a wallet that has not queried the node yet.
pub const EVM_CARRIER_MIN_GAS: u64 = 700_000;

/// Gas limit the binding-registration builder declares. Same reasoning as
/// [`EVM_CARRIER_MIN_GAS`]: the claim moves no value, so only the fee matters.
pub const EVM_BINDING_MIN_GAS: u64 = 600_000;

/// Stable refusal for EVM contract creation / calldata on the carrier path.
pub const EVM_CONTRACT_EXECUTION_REFUSAL: &str =
    "EVM contract calls and contract creation are not settled by this chain: it has no EVM \
     interpreter and no EVM state trie, so executing bytecode here would be a lie. Only \
     value transfers (empty calldata, an existing recipient) are carried; deploy and call \
     contracts with the native SVM (stell_deployContract / stell_callContract).";

/// The transfer facts a carrier settles, extracted from the EVM intent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvmTransferFacts {
    /// EVM sender, recovered from the secp256k1 signature (`advisory`, not a
    /// consensus credential).
    pub from: [u8; 20],
    /// EVM recipient.
    pub to: [u8; 20],
    /// EVM value in Wei (exact, as signed).
    pub value_wei: u128,
    /// EVM value in nano-STELL (truncated; refused when it truncates to 0).
    pub value_nano: u64,
    /// EVM nonce. A carrier must declare this same nonce on the Stell tx.
    pub nonce: u64,
    /// EVM gas limit (a resource cap; NOT the Stell fee).
    pub gas_limit: u64,
}

/// The exact bytes the bound PQ key signs to authorise a binding statement.
pub fn binding_message(chain_id: u64, evm: &[u8; 20], pq: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(EVM_BINDING_DOMAIN.len() + 8 + 20 + 32);
    buf.extend_from_slice(EVM_BINDING_DOMAIN);
    buf.extend_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(evm);
    buf.extend_from_slice(pq);
    keccak256(&buf)
}

/// `keccak256(EVM raw bytes)` — the digest the carrier's `evm_signature` covers.
pub fn evm_intent_digest(evm_tx: &[u8]) -> [u8; 32] {
    keccak256(evm_tx)
}

/// Decode + strictly verify an EVM intent and return the value transfer it
/// settles. Refuses everything this chain cannot settle.
///
/// Strictness (inherited from [`DecodedTransaction::verify_signature`]):
/// `chain_id == effective_chain_id()`, EIP-2 low-s, and a recoverable
/// secp256k1 signature. Then, on top:
/// * contract creation (`to == None`) and calldata are refused — no EVM
///   interpreter exists ([`EVM_CONTRACT_EXECUTION_REFUSAL`]);
/// * a zero value is refused (nothing to settle);
/// * a value below one nano-STELL is refused instead of silently truncating
///   the transfer to nothing.
pub fn evm_transfer_facts(raw: &[u8]) -> Result<EvmTransferFacts, String> {
    if raw.is_empty() || raw.len() > MAX_EVM_RAW_TX_BYTES {
        return Err("empty or oversized EVM transaction".to_string());
    }
    let decoded =
        parse_raw_transaction(raw).map_err(|e| format!("EVM transaction does not decode: {e}"))?;
    let from = decoded
        .verify_signature()
        .map_err(|e| format!("EVM intent signature rejected: {e}"))?;
    let to = decoded.to().ok_or_else(|| {
        format!(
            "{} (contract creation: to == null)",
            EVM_CONTRACT_EXECUTION_REFUSAL
        )
    })?;
    if !decoded.data().is_empty() {
        return Err(format!(
            "{} (intent carries {} bytes of calldata)",
            EVM_CONTRACT_EXECUTION_REFUSAL,
            decoded.data().len()
        ));
    }
    let value_wei = decoded.value();
    if value_wei == 0 {
        return Err(
            "EVM carrier settles value transfers only: the intent carries no value".to_string(),
        );
    }
    let value_nano = wei_to_nano(value_wei);
    if value_nano == 0 {
        return Err(format!(
            "EVM value {} wei is below one nano-STELL ({} wei): sub-nano value cannot be settled",
            value_wei, WEI_PER_NANO
        ));
    }
    Ok(EvmTransferFacts {
        from,
        to,
        value_wei,
        value_nano,
        nonce: decoded.nonce(),
        gas_limit: decoded.gas_limit(),
    })
}

/// Verify a carrier intent against the claiming (sender) PQ address — PURE.
///
/// This is the function every verifier runs (mempool admission, the VM
/// handler, the RPC builder), so all of them agree bit-for-bit:
///
/// 1. the carried Falcon-512 key derives `sender` under the default salt;
/// 2. `evm_signature` is a Falcon-512 signature by that key over
///    `keccak256(evm_tx)` (the EVM-intent authorisation);
/// 3. the intent decodes, its chain id is this chain's, its secp signature
///    recovers the carried `evm_address`, and it is a pure value transfer
///    (see [`evm_transfer_facts`]);
/// 4. the carrier names this chain (`chain_id`).
///
/// It deliberately reads NO registry, NO clock and NO state: an EVM address
/// with no on-chain binding still yields a cryptographically true statement
/// ("this PQ key authorises this EVM intent"), and admitting-or-not based on
/// the index is policy ([`crate::mempool`]), never consensus.
pub fn verify_carrier_intent(
    carrier: &EvmCarrierIntent,
    sender: &[u8; 32],
) -> Result<EvmTransferFacts, String> {
    if carrier.pq_pubkey.len() != FALCON512_PUBKEY_LEN {
        return Err(format!(
            "carrier PQ public key must be a {FALCON512_PUBKEY_LEN}-byte Falcon-512 key, got {}",
            carrier.pq_pubkey.len()
        ));
    }
    if carrier.evm_signature.len() != FALCON512_SIG_LEN {
        return Err(format!(
            "carrier EVM authorisation must be a {FALCON512_SIG_LEN}-byte Falcon-512 signature, got {}",
            carrier.evm_signature.len()
        ));
    }
    let derived = derive_pq_address(PqScheme::Falcon512, &carrier.pq_pubkey, &DEFAULT_SALT);
    if derived != *sender {
        return Err(
            "carrier PQ public key does not own the sending account (FULL-PQ: the debited \
             account is derive_pq_address(Falcon512, pubkey, DEFAULT_SALT))"
                .to_string(),
        );
    }
    let digest = evm_intent_digest(&carrier.evm_tx);
    if !verify_pq_signature(
        PqScheme::Falcon512,
        &carrier.pq_pubkey,
        &digest,
        &carrier.evm_signature,
    ) {
        return Err(
            "carrier authorisation rejected: the Falcon-512 signature over keccak256(EVM tx) \
             does not verify against the carried PQ key"
                .to_string(),
        );
    }
    let chain = effective_chain_id();
    if carrier.chain_id != chain {
        return Err(format!(
            "carrier chain id {} does not match this chain ({chain})",
            carrier.chain_id
        ));
    }
    let facts = evm_transfer_facts(&carrier.evm_tx)?;
    if facts.from != carrier.evm_address {
        return Err(format!(
            "EVM intent sender {} does not match the carried EVM address {}",
            evm_address_to_hex(&facts.from),
            evm_address_to_hex(&carrier.evm_address)
        ));
    }
    Ok(facts)
}

/// Length of the secp256k1 proof-of-possession carried by a binding claim:
/// `r(32) || s(32) || recovery_id(1)`.
pub const EVM_BINDING_PROOF_LEN: usize = 65;

/// The chain id a binding claim is verified against.
///
/// Deliberately NOT a caller-supplied argument (PENTEST2 S7 tautology): every
/// verifier used to compare `claim.chain_id` against a value the caller passed
/// as `claim.chain_id`, which proved nothing. The expected id now comes from
/// [`effective_chain_id`] in one place, so a claim minted for another chain is
/// refused on every path.
fn expected_binding_chain_id() -> u64 {
    effective_chain_id()
}

/// Recover the EVM address that produced a claim's proof of possession.
///
/// `proof` is `r(32) || s(32) || recovery_id(1)`, low-s (EIP-2), over the
/// canonical [`binding_message`] digest. Strictly fail-closed: wrong length,
/// zero r/s, high-s or a bad recovery id is an error.
pub fn recover_binding_claim_signer(
    chain_id: u64,
    evm: &[u8; 20],
    pq: &[u8; 32],
    proof: &[u8],
) -> Result<[u8; 20], String> {
    if proof.len() != EVM_BINDING_PROOF_LEN {
        return Err(format!(
            "binding EVM proof of possession must be {EVM_BINDING_PROOF_LEN} bytes \
             (r || s || recovery_id), got {}",
            proof.len()
        ));
    }
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&proof[..32]);
    s.copy_from_slice(&proof[32..64]);
    let recid = proof[64];
    if recid > 1 {
        return Err(format!("invalid binding EVM recovery id: {recid}"));
    }
    if r == [0u8; 32] || s == [0u8; 32] {
        return Err("invalid binding EVM signature (zero r/s)".to_string());
    }
    if !is_low_s(&s) {
        return Err("binding EVM signature s is not canonical (EIP-2)".to_string());
    }
    let msg = binding_message(chain_id, evm, pq);
    ecrecover(&msg, recid as u64, &r, &s)
        .map_err(|e| format!("binding EVM signature does not recover a sender: {e}"))
}

/// Verify a binding claim against the claiming PQ address — PURE.
///
/// The claim must be signed by the very key that owns `sender` (Falcon-512)
/// AND by the EVM key whose address is being bound (secp256k1 proof of
/// possession over the same [`binding_message`]). The EVM half is what stops
/// an unrelated PQ key from claiming somebody else's address (PENTEST2
/// C1/S1). No registry is read: a claim that conflicts with an existing
/// binding is refused by the admission policy, and the *first* committed
/// claim in block order is the one the index keeps.
pub fn verify_binding_claim(claim: &EvmAddressClaim, sender: &[u8; 32]) -> Result<(), String> {
    if claim.pq_pubkey.len() != FALCON512_PUBKEY_LEN {
        return Err(format!(
            "binding PQ public key must be a {FALCON512_PUBKEY_LEN}-byte Falcon-512 key, got {}",
            claim.pq_pubkey.len()
        ));
    }
    if claim.binding_signature.len() != FALCON512_SIG_LEN {
        return Err(format!(
            "binding authorisation must be a {FALCON512_SIG_LEN}-byte Falcon-512 signature, got {}",
            claim.binding_signature.len()
        ));
    }
    let derived = derive_pq_address(PqScheme::Falcon512, &claim.pq_pubkey, &DEFAULT_SALT);
    if derived != *sender {
        return Err(
            "binding PQ public key does not own the sending account (the claim must come from \
             the PQ account it binds)"
                .to_string(),
        );
    }
    let chain = expected_binding_chain_id();
    if claim.chain_id != chain {
        return Err(format!(
            "binding chain id {} does not match this chain ({chain})",
            claim.chain_id
        ));
    }
    let msg = binding_message(claim.chain_id, &claim.evm_address, sender);
    if !verify_pq_signature(
        PqScheme::Falcon512,
        &claim.pq_pubkey,
        &msg,
        &claim.binding_signature,
    ) {
        return Err(
            "binding authorisation rejected: the Falcon-512 signature over \
             keccak256(STELL_EVM_BIND_V1 || chain_id || evm_address || pq_address) does not verify"
                .to_string(),
        );
    }
    // C1/S1: PROOF OF POSSESSION of the EVM key. The recovered secp256k1
    // signer must be exactly the address being bound, otherwise any PQ key
    // could first-claim an unrelated EVM identity and poison routing.
    let recovered = recover_binding_claim_signer(
        claim.chain_id,
        &claim.evm_address,
        sender,
        &claim.evm_signature,
    )?;
    if recovered != claim.evm_address {
        return Err(format!(
            "binding EVM proof of possession rejected: the secp256k1 signature recovers {}, \
             not the EVM address being bound {}",
            evm_address_to_hex(&recovered),
            evm_address_to_hex(&claim.evm_address)
        ));
    }
    Ok(())
}

/// What an EVM payload opcode is, after classification.
#[derive(Clone, Copy, Debug)]
pub enum EvmPayload<'a> {
    /// A value-transfer carrier.
    Carrier(&'a EvmCarrierIntent),
    /// A binding claim.
    Binding(&'a EvmAddressClaim),
    /// An EVM opcode mixed with other operations: refused (a carrier's
    /// accounting must be the whole transaction, or a payload could hide value
    /// movement next to an intent that does not describe it).
    Mixed,
}

/// Classify a transaction's payload as an EVM carrier / binding claim.
///
/// `None` when the payload carries no EVM opcode (every non-EVM transaction,
/// including the empty payload).
pub fn classify_evm_payload(tx: &Transaction) -> Option<EvmPayload<'_>> {
    let mut found: Option<EvmPayload<'_>> = None;
    let mut others = false;
    for op in &tx.payload {
        match op {
            OpCode::SysCallEvmCarrier(c) => {
                if found.is_some() {
                    return Some(EvmPayload::Mixed);
                }
                found = Some(EvmPayload::Carrier(c));
            }
            OpCode::SysCallBindEvmAddress(c) => {
                if found.is_some() {
                    return Some(EvmPayload::Mixed);
                }
                found = Some(EvmPayload::Binding(c));
            }
            _ => others = true,
        }
    }
    match found {
        Some(_) if others => Some(EvmPayload::Mixed),
        Some(p) => Some(p),
        None => None,
    }
}

/// CONSENSUS re-check of an EVM payload against its OWN transaction — the
/// block-path enforcement of the invariants admission also enforces
/// (PENTEST2 R7/S6).
///
/// Admission is node-local policy: a hand-built block can bypass the mempool.
/// Execution must therefore re-derive, from the same bytes every node sees,
/// that the payload and the native leg describe the SAME payment:
///
/// * `Mixed` payloads are refused (a carrier's accounting is the whole tx);
/// * a carrier's EVM `nonce`/`value_nano` MUST equal `tx.nonce`/`tx.amount`,
///   and its recipient must be a real PQ account (non-zero);
/// * a binding claim moves no value (`amount == 0`, `to == from`) and both
///   signatures (Falcon + EVM proof of possession) verify.
///
/// This is deterministic and pure; it reads no registry, no clock, no state.
pub fn verify_evm_payload_against_tx(tx: &Transaction) -> Result<(), String> {
    match classify_evm_payload(tx) {
        None => Ok(()),
        Some(EvmPayload::Mixed) => Err(
            "EVM carrier/binding opcode must be the transaction's whole payload: the value leg \
             (to/amount) IS the settlement, so it cannot be mixed with other operations"
                .to_string(),
        ),
        Some(EvmPayload::Binding(claim)) => {
            verify_binding_claim(claim, &tx.from)?;
            if tx.amount != 0 {
                return Err("a binding claim moves no value: amount must be 0".to_string());
            }
            if tx.to != tx.from {
                return Err(
                    "a binding claim must be a self-addressed transaction (to == from)".to_string(),
                );
            }
            Ok(())
        }
        Some(EvmPayload::Carrier(carrier)) => {
            let facts = verify_carrier_intent(carrier, &tx.from)?;
            if facts.nonce != tx.nonce {
                return Err(format!(
                    "carrier nonce mismatch at execution: the EVM intent says {}, the \
                     transaction says {} (they must be equal so the intent can settle exactly \
                     once)",
                    facts.nonce, tx.nonce
                ));
            }
            if facts.value_nano != tx.amount {
                return Err(format!(
                    "carrier amount mismatch at execution: the EVM intent is worth {} \
                     nano-STELL, the transaction moves {}",
                    facts.value_nano, tx.amount
                ));
            }
            if tx.to == [0u8; 32] {
                return Err(
                    "carrier recipient must be a real PQ account (zero address refused)"
                        .to_string(),
                );
            }
            Ok(())
        }
    }
}

/// The settlement nullifier of a carrier transaction: `keccak256(EVM raw)`.
///
/// `None` for every non-carrier transaction. This is the SAME digest the
/// Falcon intent authorisation signs, so it identifies the signed EVM intent
/// uniquely and is the key the committed settled-intent set uses to enforce
/// exactly-once settlement.
pub fn carrier_intent_digest(tx: &Transaction) -> Option<[u8; 32]> {
    match classify_evm_payload(tx)? {
        EvmPayload::Carrier(carrier) => Some(evm_intent_digest(&carrier.evm_tx)),
        _ => None,
    }
}

/// True when `tx` carries a PQ EVM carrier opcode.
pub fn is_evm_carrier_tx(tx: &Transaction) -> bool {
    matches!(classify_evm_payload(tx), Some(EvmPayload::Carrier(_)))
}

/// True when `tx` carries a binding claim opcode.
pub fn is_evm_binding_tx(tx: &Transaction) -> bool {
    matches!(classify_evm_payload(tx), Some(EvmPayload::Binding(_)))
}

/// Build the carrier transaction a bound PQ key authorises for `raw`.
///
/// Deterministic: the same inputs always produce the same transaction bytes
/// (and therefore the same signing message), which is what lets a wallet sign
/// the message the node reports and have the node rebuild exactly that
/// transaction. The caller resolves `to_pq` (the recipient's bound PQ account)
/// and `gas_limit` (the admission floor) — both are part of the message the
/// wallet signs.
pub fn build_carrier_transaction(
    raw: &[u8],
    pq_pubkey: &[u8],
    intent_signature: &[u8],
    to_pq: [u8; 32],
    gas_limit: u64,
    carrier_signature: &[u8],
) -> Result<Transaction, String> {
    let chain = effective_chain_id();
    let facts = evm_transfer_facts(raw)?;
    if to_pq == [0u8; 32] {
        return Err(
            "carrier recipient must be a real PQ account (zero address refused)".to_string(),
        );
    }
    let sender = derive_pq_address(PqScheme::Falcon512, pq_pubkey, &DEFAULT_SALT);
    let carrier = EvmCarrierIntent {
        chain_id: chain,
        evm_tx: raw.to_vec(),
        evm_address: facts.from,
        pq_pubkey: pq_pubkey.to_vec(),
        evm_signature: intent_signature.to_vec(),
    };
    verify_carrier_intent(&carrier, &sender)?;
    let tx = Transaction::new_pq_explicit_with_chain(
        PqScheme::Falcon512,
        pq_pubkey.to_vec(),
        carrier_signature.to_vec(),
        to_pq,
        facts.value_nano,
        gas_limit,
        facts.nonce,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        vec![OpCode::SysCallEvmCarrier(Box::new(carrier))],
        &DEFAULT_SALT,
        chain,
    );
    if !tx.verify_signature() {
        return Err(
            "carrier envelope rejected: the Falcon-512 signature does not verify over the \
             carrier signing message (from, to, amount, gas_limit, nonce, payload)"
                .to_string(),
        );
    }
    Ok(tx)
}

/// Build the binding-claim transaction.
///
/// `to == from` and `amount == 0`: the claim moves no value, it only commits
/// the statement. `nonce` must be the PQ account's current nonce and
/// `gas_limit` must cover the admission floor. `evm_signature` is the 65-byte
/// secp256k1 proof of possession (see [`EvmAddressClaim::evm_signature`]).
#[allow(clippy::too_many_arguments)]
// GATE: the binding builder threads (PQ key, EVM address, PQ signature, EVM
// proof, nonce, gas limit, carrier signature); grouping would just add a type
// with the same fields.
pub fn build_binding_transaction(
    pq_pubkey: &[u8],
    evm_address: [u8; 20],
    binding_signature: &[u8],
    evm_signature: &[u8],
    nonce: u64,
    gas_limit: u64,
    carrier_signature: &[u8],
) -> Result<Transaction, String> {
    let chain = effective_chain_id();
    let from = derive_pq_address(PqScheme::Falcon512, pq_pubkey, &DEFAULT_SALT);
    let claim = EvmAddressClaim {
        chain_id: chain,
        evm_address,
        pq_pubkey: pq_pubkey.to_vec(),
        binding_signature: binding_signature.to_vec(),
        evm_signature: evm_signature.to_vec(),
    };
    verify_binding_claim(&claim, &from)?;
    let tx = Transaction::new_pq_explicit_with_chain(
        PqScheme::Falcon512,
        pq_pubkey.to_vec(),
        carrier_signature.to_vec(),
        from,
        0,
        gas_limit,
        nonce,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        vec![OpCode::SysCallBindEvmAddress(Box::new(claim))],
        &DEFAULT_SALT,
        chain,
    );
    if !tx.verify_signature() {
        return Err(
            "binding envelope rejected: the Falcon-512 signature does not verify over the \
             binding signing message (from, to, amount, gas_limit, nonce, payload)"
                .to_string(),
        );
    }
    Ok(tx)
}

/// The `refusing` half of the EVM write path: machine-readable refusals that
/// tell a wallet exactly which PQ authorisation is missing.
///
/// The EVM JSON-RPC intent alone can never authorise value movement (FULL-PQ),
/// so every refusal names the exact bytes to sign and the method to submit
/// with. `error.data.reason` is the stable tag wallets match on.
pub const EVM_CARRIER_AUTH_REASON: &str = "pq-carrier-authorization-required";

/// `error.data.reason` when the EVM intent is not a value transfer.
pub const EVM_INTENT_UNSUPPORTED_REASON: &str = "evm-contract-execution-unsupported";

/// `error.data.reason` when the EVM recipient has no PQ binding (funds sent to
/// the bare 20-byte address would be unspendable: no PQ key derives it).
pub const EVM_RECIPIENT_UNBOUND_REASON: &str = "recipient-evm-address-unbound";

/// Refusal: the intent is well-formed and the sender IS bound, but the Falcon
/// authorisation is missing (or half-supplied).
///
/// The EVM write path needs TWO Falcon signatures from the same bound key, in
/// this order, because each one is part of the next one's preimage:
///
/// 1. `intentSignature` over `keccak256(EVM transaction)` — carried in the
///    payload, so it is inside the carrier's signed message;
/// 2. `txSignature` over the carrier signing message — the PQ1 consensus
///    credential.
///
/// `carrier_message` is `None` on the first step (the payload — and therefore
/// the message — does not exist until the intent signature does), in which case
/// `error.data.intentSignThis` is the bytes to sign and `error.data.next` says
/// to call again with `intentSignature`.
// GATE: a refusal carries every field a wallet needs to sign (ids, amounts,
// addresses, both signing preimages); grouping them into a struct would just
// add a type nobody reuses.
#[allow(clippy::too_many_arguments)]
pub fn carrier_authorization_required(
    evm_hash: &str,
    evm_from: &str,
    bound_pq: &[u8; 32],
    recipient_evm: &str,
    recipient_pq: &[u8; 32],
    amount_nano: u64,
    gas_limit: u64,
    nonce: u64,
    intent_digest: &[u8; 32],
    carrier_message: Option<&[u8]>,
) -> JsonRpcError {
    let mut data = serde_json::json!({
        "reason": EVM_CARRIER_AUTH_REASON,
        "requires": "Falcon-512 signatures from the bound PQ account: (1) over \
                     keccak256(EVM transaction), (2) over the carrier signing message",
        "evmHash": evm_hash,
        "evmFrom": evm_from,
        "boundPqAddress": format!("0x{}", hex::encode(bound_pq)),
        "recipientEvm": recipient_evm,
        "recipientPq": format!("0x{}", hex::encode(recipient_pq)),
        "amountNano": amount_nano,
        "gasLimit": gas_limit,
        "nonce": nonce,
        "intentSignThis": format!("0x{}", hex::encode(intent_digest)),
        "submitWith": "eth_sendRawTransaction",
    });
    let (detail, next) = match carrier_message {
        Some(_msg) => (
            "Sign error.data.signThis with the bound Falcon-512 key, then resubmit with \
             {\"pqPublicKey\", \"intentSignature\", \"txSignature\"}.",
            "carrier-signature",
        ),
        None => (
            "Sign error.data.intentSignThis with the bound Falcon-512 key, then resubmit \
             with {\"pqPublicKey\", \"intentSignature\"} to receive the carrier message.",
            "intent-signature",
        ),
    };
    data["next"] = serde_json::json!(next);
    if let Some(msg) = carrier_message {
        data["signThis"] = serde_json::json!(format!("0x{}", hex::encode(msg)));
    }
    JsonRpcError::with_data(
        -32000,
        format!(
            "eth_sendRawTransaction cannot settle this intent on its own: EVM address {evm_from} \
             is bound to the post-quantum account {}, and only that account's Falcon-512 \
             signatures can authorise value movement. {detail}",
            hex::encode(bound_pq)
        ),
        data,
    )
}

/// Refusal: the EVM intent is not a value transfer this chain can settle.
pub fn evm_intent_unsupported(evm_hash: Option<&str>, reason: &str) -> JsonRpcError {
    JsonRpcError::with_data(
        -32000,
        format!("eth_sendRawTransaction refused: {reason}"),
        serde_json::json!({
            "reason": EVM_INTENT_UNSUPPORTED_REASON,
            "evmHash": evm_hash,
            "requires": "a value transfer: empty calldata, an existing recipient, value > 0",
        }),
    )
}

/// Refusal: the EVM recipient has no PQ binding.
pub fn recipient_unbound(recipient_evm: &str, evm_hash: Option<&str>) -> JsonRpcError {
    JsonRpcError::with_data(
        -32000,
        format!(
            "eth_sendRawTransaction refused: recipient 0x{recipient_evm} has no on-chain PQ \
             binding, and this chain has no EVM accounts — crediting the bare 20-byte address \
             would make the funds unspendable (no Falcon-512 key derives it). The recipient must \
             register a binding first (stell_evmBindingSubmit); the sender's own binding is not \
             enough."
        ),
        serde_json::json!({
            "reason": EVM_RECIPIENT_UNBOUND_REASON,
            "recipientEvm": format!("0x{recipient_evm}"),
            "evmHash": evm_hash,
            "requires": "the recipient EVM address must be bound to a PQ account \
                         (stell_getEvmBinding reports the current binding)",
        }),
    )
}

/// The exact bytes a wallet must Falcon-sign for `tx` to be admissible.
///
/// `tx` may carry an EMPTY signature: this is
/// [`Transaction::signing_message_for_chain`], the same preimage
/// `verify_signature` reconstructs from the PQ1 envelope's chain id.
pub fn carrier_signing_message(tx: &Transaction) -> Vec<u8> {
    tx.signing_message_for_chain(effective_chain_id())
}

/// The carrier's signing message WITHOUT the envelope signature, for a wallet
/// that has produced the EVM-intent signature but not the carrier one yet.
///
/// Deterministic in `(raw, pq_pubkey, to_pq, gas_limit)`, exactly like
/// [`build_carrier_transaction`], so a wallet that signs the bytes returned
/// here gets a transaction the node rebuilds byte-identically (including the
/// EVM nonce, which the builder takes from the intent).
pub fn carrier_template_message(
    raw: &[u8],
    pq_pubkey: &[u8],
    intent_signature: &[u8],
    to_pq: [u8; 32],
    gas_limit: u64,
) -> Result<Vec<u8>, String> {
    if pq_pubkey.len() != FALCON512_PUBKEY_LEN {
        return Err(format!(
            "carrier PQ public key must be a {FALCON512_PUBKEY_LEN}-byte Falcon-512 key, got {}",
            pq_pubkey.len()
        ));
    }
    if to_pq == [0u8; 32] {
        return Err(
            "carrier recipient must be a real PQ account (zero address refused)".to_string(),
        );
    }
    let chain = effective_chain_id();
    let facts = evm_transfer_facts(raw)?;
    let carrier = EvmCarrierIntent {
        chain_id: chain,
        evm_tx: raw.to_vec(),
        evm_address: facts.from,
        pq_pubkey: pq_pubkey.to_vec(),
        // The payload — signatures INCLUDED — is covered by the signing
        // message, so the template must carry the very same intent signature
        // the built transaction will. That is why the intent signature is an
        // input here: a wallet signs `keccak256(EVM tx)` first, then the
        // carrier message that commits to it.
        evm_signature: intent_signature.to_vec(),
    };
    let tx = Transaction::new_pq_explicit_with_chain(
        PqScheme::Falcon512,
        pq_pubkey.to_vec(),
        Vec::new(),
        to_pq,
        facts.value_nano,
        gas_limit,
        facts.nonce,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        vec![OpCode::SysCallEvmCarrier(Box::new(carrier))],
        &DEFAULT_SALT,
        chain,
    );
    Ok(carrier_signing_message(&tx))
}

/// The binding claim's signing message WITHOUT the envelope signature, for a
/// wallet that has produced the claim signature but not the transaction one
/// yet (deterministic in `(pq_pubkey, evm_address, binding_signature,
/// evm_signature, nonce, gas_limit)`).
pub fn binding_template_message(
    pq_pubkey: &[u8],
    evm_address: [u8; 20],
    binding_signature: &[u8],
    evm_signature: &[u8],
    nonce: u64,
    gas_limit: u64,
) -> Result<Vec<u8>, String> {
    if pq_pubkey.len() != FALCON512_PUBKEY_LEN {
        return Err(format!(
            "binding PQ public key must be a {FALCON512_PUBKEY_LEN}-byte Falcon-512 key, got {}",
            pq_pubkey.len()
        ));
    }
    let chain = effective_chain_id();
    let from = derive_pq_address(PqScheme::Falcon512, pq_pubkey, &DEFAULT_SALT);
    let claim = EvmAddressClaim {
        chain_id: chain,
        evm_address,
        pq_pubkey: pq_pubkey.to_vec(),
        // Same rule as the carrier: the claim signatures are part of the
        // signed payload, so the template takes both as inputs.
        binding_signature: binding_signature.to_vec(),
        evm_signature: evm_signature.to_vec(),
    };
    let tx = Transaction::new_pq_explicit_with_chain(
        PqScheme::Falcon512,
        pq_pubkey.to_vec(),
        Vec::new(),
        from,
        0,
        gas_limit,
        nonce,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        vec![OpCode::SysCallBindEvmAddress(Box::new(claim))],
        &DEFAULT_SALT,
        chain,
    );
    Ok(carrier_signing_message(&tx))
}

// ============================================================================
// EVM address ↔ PQ account binding index (the EVM WRITE path's address book)
// ============================================================================
//
// WHAT THIS IS: a bounded, append-only map `EVM address (20) → PQ account (32)`
// plus its inverse, replayed deterministically from COMMITTED binding records
// (`svm::OpCode::SysCallBindEvmAddress`, and any carrier intent, which proves
// the same statement). Insertion is FIRST-WRITER-WINS in block order, so the
// map a node derives from the same chain is the same map, and a second claim on
// an already-bound EVM address is a refusal (never a silent re-bind, which
// would let a thief redirect an EVM identity's routing).
//
// WHAT THIS IS NOT: it is not folded into the state root, because the write
// hook lives in `state_engine/apply.rs` (a per-transaction domain commit) and
// that file is owned elsewhere this wave. Every CONSENSUS fact is therefore
// re-checked from signatures and payload bytes alone — by the VM
// (`evm_adapter::verify_binding_claim` / `verify_carrier_intent` are pure) and
// by `Transaction::verify_signature` — so a stale, empty or wrong index can
// only change which transactions a node ADMITS or how it answers an address
// query. It can never make two nodes move different money, which is why this
// index is deliberately not consulted inside execution.
//
// HOW IT IS FED (committed-only, PENTEST2 H1/M1):
//   * `state_engine` feeds every APPLIED binding/carrier at its commit point
//     (`observe_committed_evm_tx`), on every apply path;
//   * startup replays the persisted committed block window through
//     `rebuild_evm_indexes_from_blocks`, so a restart derives the same map;
//   * mempool admission NEVER writes it: an admitted-but-unmined claim is not
//     a binding and must not freeze routing or be reported as committed.
//
// The map is process-local and bounded so a flood of binds cannot grow it
// without limit.

/// Upper bound on index entries (DoS guard). Binding is a per-address
/// COMMITTED fact, so the cap is generous and there is NO eviction: evicting a
/// live binding would reopen first-writer-wins and let anybody claim the
/// address again (PENTEST2 S1/M1). Overflow refuses the new claim instead,
/// deterministically; the authoritative record is always the committed claim.
pub const EVM_BINDING_INDEX_CAP: usize = 100_000;

/// Deterministic, bounded `EVM address → PQ account` index. See the module
/// note above for exactly what it does and does not guarantee.
#[derive(Clone, Debug, Default)]
pub struct EvmBindingRegistry {
    by_evm: HashMap<[u8; 20], [u8; 32]>,
    by_pq: HashMap<[u8; 32], [u8; 20]>,
    order: VecDeque<[u8; 20]>,
}

impl EvmBindingRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// The PQ account an EVM address is bound to, if the index knows it.
    pub fn pq_for(&self, evm: &[u8; 20]) -> Option<[u8; 32]> {
        self.by_evm.get(evm).copied()
    }

    /// The EVM address a PQ account bound, if the index knows it.
    pub fn evm_for(&self, pq: &[u8; 32]) -> Option<[u8; 20]> {
        self.by_pq.get(pq).copied()
    }

    pub fn is_empty(&self) -> bool {
        self.by_evm.is_empty()
    }

    pub fn len(&self) -> usize {
        self.by_evm.len()
    }

    /// Bind `evm` to `pq`, first-writer-wins.
    ///
    /// Returns `Ok(true)` when the pair was NEWLY recorded, `Ok(false)` when it
    /// was already recorded (idempotent), and `Err` when the EVM address (or
    /// the PQ account) is already bound to a DIFFERENT counterparty — a
    /// conflict the caller must refuse, never overwrite.
    pub fn bind(&mut self, evm: [u8; 20], pq: [u8; 32]) -> Result<bool, String> {
        if let Some(existing) = self.by_evm.get(&evm) {
            if *existing == pq {
                return Ok(false);
            }
            return Err(format!(
                "EVM address 0x{} is already bound to PQ account {} (refusing to re-bind it to {})",
                hex::encode(evm),
                hex::encode(existing),
                hex::encode(pq)
            ));
        }
        if let Some(existing_evm) = self.by_pq.get(&pq) {
            if *existing_evm != evm {
                return Err(format!(
                    "PQ account {} is already bound to EVM address 0x{} (refusing a second \
                     address for the same account; withdraw the first claim instead)",
                    hex::encode(pq),
                    hex::encode(existing_evm)
                ));
            }
        }
        // NO EVICTION (PENTEST2 S1/M1): a committed binding is permanent.
        // Popping the oldest entry would make the evicted address claimable
        // again by anyone (first-writer-wins only among remembered entries)
        // and could silently redirect routing. Refuse the NEW claim instead.
        if self.order.len() >= EVM_BINDING_INDEX_CAP {
            return Err(format!(
                "EVM binding index is full ({} entries): refusing a new binding instead of \
                 evicting a committed one (eviction would reopen first-writer-wins)",
                EVM_BINDING_INDEX_CAP
            ));
        }
        self.by_evm.insert(evm, pq);
        self.by_pq.insert(pq, evm);
        self.order.push_back(evm);
        Ok(true)
    }

    /// Replay one COMMITTED transaction into the index.
    ///
    /// Returns `Some((evm, pq))` when the transaction carried a binding
    /// statement this index accepted. Both statement kinds are re-verified from
    /// the transaction alone (the claim's Falcon signature, or the carrier's
    /// key/EVM-intent authorisation), so a caller cannot seed the index with a
    /// transaction that never proved anything.
    pub fn observe_transaction(
        &mut self,
        tx: &crate::sharding::Transaction,
    ) -> Option<EvmBindingStatement> {
        match crate::evm_adapter::classify_evm_payload(tx)? {
            crate::evm_adapter::EvmPayload::Binding(claim) => {
                if crate::evm_adapter::verify_binding_claim(claim, &tx.from).is_err() {
                    return None;
                }
                if self.bind(claim.evm_address, tx.from).is_err() {
                    return None;
                }
                Some((claim.evm_address, tx.from))
            }
            crate::evm_adapter::EvmPayload::Carrier(carrier) => {
                let facts = crate::evm_adapter::verify_carrier_intent(carrier, &tx.from).ok()?;
                if self.bind(carrier.evm_address, tx.from).is_err() {
                    return None;
                }
                Some((facts.from, tx.from))
            }
            crate::evm_adapter::EvmPayload::Mixed => None,
        }
    }
}

/// One verified `(EVM address, PQ account)` statement: what admission hands to
/// the index after a claim or carrier has been accepted, and what
/// [`EvmBindingRegistry::observe_transaction`] returns for a committed one.
pub type EvmBindingStatement = ([u8; 20], [u8; 32]);

/// The process-wide binding index.
pub fn evm_binding_index() -> &'static std::sync::RwLock<EvmBindingRegistry> {
    static INDEX: std::sync::OnceLock<std::sync::RwLock<EvmBindingRegistry>> =
        std::sync::OnceLock::new();
    INDEX.get_or_init(|| std::sync::RwLock::new(EvmBindingRegistry::new()))
}

/// Look up the PQ account bound to an EVM address (index only).
pub fn lookup_bound_pq(evm: &[u8; 20]) -> Option<[u8; 32]> {
    evm_binding_index().read().ok()?.pq_for(evm)
}

/// Look up the EVM address bound to a PQ account (index only).
pub fn lookup_bound_evm(pq: &[u8; 32]) -> Option<[u8; 20]> {
    evm_binding_index().read().ok()?.evm_for(pq)
}

/// Record a binding this node has just VERIFIED (admission path).
///
/// Returns the index verdict: `Ok(true)` new, `Ok(false)` already present,
/// `Err` conflicting (the caller refuses the transaction).
pub fn record_evm_binding(evm: [u8; 20], pq: [u8; 32]) -> Result<bool, String> {
    evm_binding_index()
        .write()
        .map_err(|_| "EVM binding index is poisoned".to_string())?
        .bind(evm, pq)
}

/// True once the index has observed at least one binding.
///
/// Admission uses this to distinguish "this EVM address is unbound" from "this
/// node has not replayed any bindings yet" (a fresh node must not refuse every
/// carrier: the underlying Falcon authorisation is what makes a carrier safe,
/// the index only routes it).
pub fn evm_binding_index_armed() -> bool {
    evm_binding_index()
        .read()
        .map(|i| !i.is_empty())
        .unwrap_or(false)
}

/// Drop every index entry. PROCESS-LOCAL and non-consensus: it changes which
/// address queries this node can route, never what a block does. Used by tests
/// (which share one process) and by an operator reset.
pub fn clear_evm_bindings() {
    if let Ok(mut idx) = evm_binding_index().write() {
        *idx = EvmBindingRegistry::new();
    }
}
