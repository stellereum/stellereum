//! EVM WRITE PATH — PQ↔EVM address binding + carrier admission.
//!
//! These tests are the regression gate for the FULL-PQ EVM write path:
//!
//! * a binding (`EVM address → PQ account`) is registered by a Falcon-signed
//!   claim and becomes visible on chain / in the routing index;
//! * a carrier (EIP-155 the wallet signed + a Falcon-512 authorisation over
//!   `keccak256(EVM tx)` + the PQ1 envelope) is ADMITTED, APPLIED and MOVES
//!   VALUE: the bound PQ account is debited, the recipient's bound PQ account
//!   is credited;
//! * a carrier for an UNBOUND EVM address is refused;
//! * a carrier with a WRONG PQ signature is refused;
//! * a REPLAY is refused (duplicate hash, consumed nonce, and the
//!   `evm.nonce != tx.nonce` re-wrap shape);
//! * an EVM contract call / creation is refused honestly (no EVM interpreter);
//! * the fee must cover the admission floor PLUS the carrier surcharge;
//! * the RPC surface reports the binding, refuses with the exact
//!   machine-readable authorisation requirement, and settles when the
//!   authorisation is supplied.
//!
//! Every fixture key is unique per test: the binding index is process-wide
//! (node-local routing, like `EVM_PENDING_TXS`), so tests must never share an
//! EVM address.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use stellereum::evm_adapter::{self, EvmTransaction, LegacyTransaction};
use stellereum::mempool::Mempool;
use stellereum::post_quantum::{derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT};
use stellereum::rpc::{ReceiptIndex, RpcState};
use stellereum::sharding::{ShardRegistry, Transaction};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::OpCode;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const START_BALANCE: u64 = 1_000_000_000_000; // 1000 STELL in nano
const TRANSFER_NANO: u64 = 5_000_000_000; // 5 STELL

fn falcon(seed_byte: u8) -> ([u8; 32], Vec<u8>) {
    let mut seed = [0u8; 32];
    seed[0] = seed_byte;
    seed[31] = 0xA5;
    let kp = FalconKeypair::generate_from_seed_bytes(&seed);
    let pk = kp.public_key().to_vec();
    let addr = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);
    (addr, pk)
}

fn falcon_kp(seed_byte: u8) -> FalconKeypair {
    let mut seed = [0u8; 32];
    seed[0] = seed_byte;
    seed[31] = 0xA5;
    FalconKeypair::generate_from_seed_bytes(&seed)
}

fn secp_signer(seed_byte: u8) -> (k256::ecdsa::SigningKey, [u8; 20]) {
    let key = k256::ecdsa::SigningKey::from_slice(&[seed_byte; 32]).expect("secp key");
    let addr =
        evm_adapter::pubkey_to_address(key.verifying_key().to_encoded_point(false).as_bytes())
            .expect("secp address");
    (key, addr)
}

/// A canonical, fully signed EIP-155 legacy transfer.
// GATE: fixture builder mirrors the EVM transaction shape (nonce, recipient,
// value, gas, calldata); a struct would be more ceremony than the test needs.
#[allow(clippy::too_many_arguments)]
fn evm_transfer_raw(
    signer: &k256::ecdsa::SigningKey,
    chain_id: u64,
    nonce: u64,
    to: [u8; 20],
    value_wei: u128,
    gas_limit: u64,
    data: Vec<u8>,
) -> Vec<u8> {
    let unsigned = LegacyTransaction {
        nonce,
        gas_price: 20_000_000_000,
        gas_limit,
        to: Some(to),
        value: value_wei,
        data,
        v: 0,
        r: [0u8; 32],
        s: [0u8; 32],
        chain_id: Some(chain_id),
    };
    let sighash = unsigned.signing_hash();
    let (sig, recid) = signer
        .sign_prehash_recoverable(&sighash)
        .expect("recoverable sign");
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig.to_bytes()[..32]);
    s.copy_from_slice(&sig.to_bytes()[32..64]);
    let mut rec = recid.to_byte();
    if !evm_adapter::is_low_s(&s) {
        let n = evm_adapter::SECP256K1_N;
        let mut out = [0u8; 32];
        let mut borrow: i32 = 0;
        for i in (0..32).rev() {
            let v = n[i] as i32 - s[i] as i32 - borrow;
            if v < 0 {
                out[i] = (v + 256) as u8;
                borrow = 1;
            } else {
                out[i] = v as u8;
                borrow = 0;
            }
        }
        s = out;
        rec ^= 1;
    }
    LegacyTransaction {
        v: chain_id * 2 + 35 + rec as u64,
        r,
        s,
        ..unsigned
    }
    .encode()
}

/// 65-byte `r || s || recovery_id` EVM proof of possession over the canonical
/// binding message (C1/S1).
fn evm_binding_proof(
    secp: &k256::ecdsa::SigningKey,
    chain: u64,
    evm: &[u8; 20],
    pq: &[u8; 32],
) -> Vec<u8> {
    let msg = evm_adapter::binding_message(chain, evm, pq);
    let (sig, recid) = secp
        .sign_prehash_recoverable(&msg)
        .expect("recoverable sign");
    let raw = sig.to_bytes();
    let mut s = [0u8; 32];
    s.copy_from_slice(&raw[32..64]);
    let mut rec = recid.to_byte();
    if !evm_adapter::is_low_s(&s) {
        // Normalize to low-s (EIP-2) exactly like the secp envelope builder.
        let n = evm_adapter::SECP256K1_N;
        let mut out = [0u8; 32];
        let mut borrow: i32 = 0;
        for i in (0..32).rev() {
            let v = n[i] as i32 - s[i] as i32 - borrow;
            if v < 0 {
                out[i] = (v + 256) as u8;
                borrow = 1;
            } else {
                out[i] = v as u8;
                borrow = 0;
            }
        }
        s = out;
        rec ^= 1;
    }
    let mut proof = Vec::with_capacity(65);
    proof.extend_from_slice(&raw[..32]);
    proof.extend_from_slice(&s);
    proof.push(rec);
    proof
}

/// Build and sign a binding claim transaction for `(evm → pq)`.
fn signed_binding_tx(
    kp: &FalconKeypair,
    secp: &k256::ecdsa::SigningKey,
    evm_address: [u8; 20],
    nonce: u64,
    gas_limit: u64,
) -> Transaction {
    let chain = evm_adapter::effective_chain_id();
    let pk = kp.public_key().to_vec();
    let pq = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);
    let claim_msg = evm_adapter::binding_message(chain, &evm_address, &pq);
    let binding_sig = kp.sign(&claim_msg);
    let evm_proof = evm_binding_proof(secp, chain, &evm_address, &pq);
    let sign_this = evm_adapter::binding_template_message(
        &pk,
        evm_address,
        &binding_sig,
        &evm_proof,
        nonce,
        gas_limit,
    )
    .expect("template");
    let tx_sig = kp.sign(&sign_this);
    evm_adapter::build_binding_transaction(
        &pk,
        evm_address,
        &binding_sig,
        &evm_proof,
        nonce,
        gas_limit,
        &tx_sig,
    )
    .expect("binding transaction")
}

/// Build and sign a carrier for `raw`.
fn signed_carrier_tx(
    kp: &FalconKeypair,
    raw: &[u8],
    to_pq: [u8; 32],
    gas_limit: u64,
) -> Transaction {
    let pk = kp.public_key().to_vec();
    let intent_sig = kp.sign(&evm_adapter::evm_intent_digest(raw));
    let sign_this = evm_adapter::carrier_template_message(raw, &pk, &intent_sig, to_pq, gas_limit)
        .expect("carrier template");
    let tx_sig = kp.sign(&sign_this);
    evm_adapter::build_carrier_transaction(raw, &pk, &intent_sig, to_pq, gas_limit, &tx_sig)
        .expect("carrier transaction")
}

fn admission_ctx() -> stellereum::mempool::AdmissionCtx {
    stellereum::mempool::AdmissionCtx::wall_now()
}

async fn fund(engine: &InMemoryStateEngine, addr: [u8; 32], nano: u64) {
    engine.update_account(AccountState::new(addr, nano)).await;
}

async fn balance(engine: &InMemoryStateEngine, addr: [u8; 32]) -> u64 {
    engine
        .get_account(&addr)
        .await
        .map(|a| a.balance)
        .unwrap_or(0)
}

/// A pool with the flags a live node sets, so admission is exercised exactly
/// as it is on the real path.
fn pool() -> Mempool {
    Mempool::new(4096, 64).with_base_fee(280_000)
}

// ---------------------------------------------------------------------------
// 1. The whole path: bind → carrier → transfer → balances
// ---------------------------------------------------------------------------

#[tokio::test]
async fn binding_then_carrier_moves_value_between_bound_accounts() {
    let engine = InMemoryStateEngine::new();
    let mut mem = pool();
    let chain = evm_adapter::effective_chain_id();

    // Sender: PQ account + its EVM identity. Recipient: same shape.
    let sender_kp = falcon_kp(0x11);
    let (sender_pq, sender_pk) = falcon(0x11);
    assert_eq!(
        sender_pq,
        derive_pq_address(PqScheme::Falcon512, &sender_pk, &DEFAULT_SALT)
    );
    let recipient_kp = falcon_kp(0x12);
    let (recipient_pq, _) = falcon(0x12);
    let (sender_secp, sender_evm) = secp_signer(0x71);
    let (recipient_secp, recipient_evm) = secp_signer(0x72);

    fund(&engine, sender_pq, START_BALANCE).await;

    // --- binding 1: sender EVM address → sender PQ account --------------
    let bind_tx = signed_binding_tx(&sender_kp, &sender_secp, sender_evm, 0, 600_000);
    assert!(bind_tx.verify_signature(), "binding envelope must verify");
    assert!(
        evm_adapter::is_evm_binding_tx(&bind_tx),
        "the payload is the binding claim"
    );
    mem.add_checked_ctx(bind_tx.clone(), START_BALANCE, admission_ctx())
        .expect("binding claim admitted");
    engine
        .apply_transaction(&bind_tx, 1_700_000_000)
        .await
        .expect("binding claim applies");
    assert_eq!(
        evm_adapter::lookup_bound_pq(&sender_evm),
        Some(sender_pq),
        "the binding is indexed once admitted"
    );

    // --- binding 2: recipient EVM address → recipient PQ account --------
    fund(&engine, recipient_pq, START_BALANCE).await;
    let recipient_bind =
        signed_binding_tx(&recipient_kp, &recipient_secp, recipient_evm, 0, 600_000);
    mem.add_checked_ctx(recipient_bind.clone(), START_BALANCE, admission_ctx())
        .expect("recipient binding admitted");
    engine
        .apply_transaction(&recipient_bind, 1_700_000_000)
        .await
        .expect("recipient binding applies");
    assert_eq!(
        evm_adapter::lookup_bound_pq(&recipient_evm),
        Some(recipient_pq)
    );

    // --- the EVM intent MetaMask produced -------------------------------
    let value_wei = (TRANSFER_NANO as u128) * evm_adapter::WEI_PER_NANO;
    let raw = evm_transfer_raw(
        &sender_secp,
        chain,
        1,
        recipient_evm,
        value_wei,
        21_000,
        vec![],
    );
    // The intent is strictly verified (chain id, low-s, ecrecover).
    let view: EvmTransaction =
        evm_adapter::decode_verify_raw_evm(&raw).expect("EVM intent verifies");
    let facts = evm_adapter::evm_transfer_facts(&raw).expect("value transfer facts");
    assert_eq!(facts.from, sender_evm);
    assert_eq!(facts.to, recipient_evm);
    assert_eq!(facts.value_nano, TRANSFER_NANO);
    assert_eq!(facts.nonce, 1);
    assert_eq!(view.from, evm_adapter::evm_address_to_hex(&sender_evm));

    // --- carrier --------------------------------------------------------
    let carrier = signed_carrier_tx(&sender_kp, &raw, recipient_pq, 1_200_000);
    assert_eq!(carrier.from, sender_pq, "the carrier debits the PQ account");
    assert_eq!(
        carrier.to, recipient_pq,
        "and credits the recipient's PQ account"
    );
    assert_eq!(carrier.amount, TRANSFER_NANO);
    assert_eq!(carrier.nonce, 1, "the EVM nonce IS the Stell nonce");
    assert!(carrier.verify_signature(), "PQ1 envelope must verify");

    let before_sender = balance(&engine, sender_pq).await;
    let before_recipient = balance(&engine, recipient_pq).await;
    mem.add_checked_ctx(carrier.clone(), before_sender, admission_ctx())
        .expect("carrier admitted");
    assert!(mem.contains(&carrier.compute_tx_hash()));
    engine
        .apply_transaction(&carrier, 1_700_000_100)
        .await
        .expect("carrier applies");

    let after_sender = balance(&engine, sender_pq).await;
    let after_recipient = balance(&engine, recipient_pq).await;
    assert_eq!(
        after_recipient - before_recipient,
        TRANSFER_NANO,
        "the recipient's bound PQ account is credited the EVM value"
    );
    let fee = before_sender - after_sender - TRANSFER_NANO;
    assert!(fee >= 45_000, "the PQ activation surcharge is charged");
    assert!(
        fee <= 1_200_000,
        "the fee is capped by the declared gas_limit"
    );

    // --- the EVM view of the carrier is the intent the wallet signed ----
    let evm_view = evm_adapter::stell_tx_to_evm(&carrier, Some([0x11u8; 32]), Some(7), Some(0));
    assert_eq!(
        evm_view.from,
        format!("0x{}", hex::encode(sender_evm)),
        "eth_getTransactionByHash must show the BOUND EVM sender, not a PQ address"
    );
    assert_eq!(
        evm_view.to,
        Some(format!("0x{}", hex::encode(recipient_evm)))
    );
    assert_eq!(evm_view.value, evm_adapter::nano_to_wei_hex(TRANSFER_NANO));
    assert_eq!(evm_view.input, "0x", "a carrier is a pure value transfer");

    // --- the settlement hook links the committed carrier ----------------
    // `record_receipts` calls this for every committed transaction, so
    // `eth_getTransactionReceipt(evmHash)` resolves on ANY node after
    // inclusion (not only on the node that submitted the carrier) and the
    // binding index is replayed from block order.
    let linked = evm_adapter::link_secp_settlement(&carrier)
        .expect("a committed carrier links its EVM hash");
    assert_eq!(
        linked.0,
        format!("0x{}", hex::encode(evm_adapter::evm_intent_digest(&raw)))
    );
    assert_eq!(linked.1, carrier.compute_tx_hash());

    // --- the read surface routes the EVM address to the PQ account ------
    let bal =
        evm_adapter::eth_get_balance(&engine, &json!([format!("0x{}", hex::encode(sender_evm))]))
            .await
            .expect("eth_getBalance");
    assert_eq!(
        bal,
        evm_adapter::nano_to_wei_hex(after_sender),
        "eth_getBalance(EVM address) serves the BOUND PQ account's balance"
    );
    let nonce = evm_adapter::eth_get_transaction_count(
        &engine,
        &json!([format!("0x{}", hex::encode(sender_evm))]),
    )
    .await
    .expect("eth_getTransactionCount");
    assert_eq!(nonce, "0x2", "nonce = binding claim + carrier");
}

// ---------------------------------------------------------------------------
// 2. An UNBOUND EVM address is refused
// ---------------------------------------------------------------------------

#[tokio::test]
async fn carrier_for_unbound_evm_address_is_refused() {
    let engine = InMemoryStateEngine::new();
    let mut mem = pool();
    let chain = evm_adapter::effective_chain_id();

    // Arm the index with a DIFFERENT binding, exactly like a node that has
    // replayed some bindings: an address it has never seen is unroutable.
    let (other_pq, _) = falcon(0x21);
    let (_other_secp, other_evm) = secp_signer(0x73);
    evm_adapter::record_evm_binding(other_evm, other_pq).expect("arm index");

    let sender_kp = falcon_kp(0x22);
    let (sender_pq, _) = falcon(0x22);
    let (secp, sender_evm) = secp_signer(0x74);
    let (recipient_pq, _) = falcon(0x23);
    fund(&engine, sender_pq, START_BALANCE).await;

    let raw = evm_transfer_raw(
        &secp,
        chain,
        0,
        [0x99u8; 20],
        (TRANSFER_NANO as u128) * evm_adapter::WEI_PER_NANO,
        21_000,
        vec![],
    );
    let carrier = signed_carrier_tx(&sender_kp, &raw, recipient_pq, 1_200_000);
    let err = mem
        .add_checked_ctx(carrier, START_BALANCE, admission_ctx())
        .expect_err("an unbound EVM sender must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("no on-chain PQ binding") && msg.contains(&hex::encode(sender_evm)),
        "the refusal must name the unbound address, got: {msg}"
    );
    assert!(mem.is_empty(), "nothing was admitted");
}

// ---------------------------------------------------------------------------
// 3. A wrong PQ signature is refused
// ---------------------------------------------------------------------------

#[tokio::test]
async fn carrier_with_wrong_pq_signature_is_refused() {
    let engine = InMemoryStateEngine::new();
    let mut mem = pool();
    let chain = evm_adapter::effective_chain_id();

    let sender_kp = falcon_kp(0x31);
    let (sender_pq, sender_pk) = falcon(0x31);
    let attacker_kp = falcon_kp(0x32);
    let (secp, sender_evm) = secp_signer(0x75);
    let (recipient_pq, _) = falcon(0x33);
    fund(&engine, sender_pq, START_BALANCE).await;
    evm_adapter::record_evm_binding(sender_evm, sender_pq).expect("binding");

    let raw = evm_transfer_raw(
        &secp,
        chain,
        0,
        [0x98u8; 20],
        (TRANSFER_NANO as u128) * evm_adapter::WEI_PER_NANO,
        21_000,
        vec![],
    );

    // (a) the EVM-intent authorisation signed by the WRONG key: refused by the
    //     builder itself (fail-closed before any transaction exists).
    let wrong_intent = attacker_kp.sign(&evm_adapter::evm_intent_digest(&raw));
    let sign_this = evm_adapter::carrier_template_message(
        &raw,
        &sender_pk,
        &wrong_intent,
        recipient_pq,
        1_200_000,
    )
    .expect("template");
    let tx_sig = sender_kp.sign(&sign_this);
    let err = evm_adapter::build_carrier_transaction(
        &raw,
        &sender_pk,
        &wrong_intent,
        recipient_pq,
        1_200_000,
        &tx_sig,
    )
    .expect_err("a foreign intent signature must be refused");
    assert!(
        err.contains("does not verify"),
        "the refusal names the signature, got: {err}"
    );

    // (b) a hand-built carrier whose payload signature is the attacker's, with
    //     a VALID envelope from the bound key: the mempool refuses it too (the
    //     payload and the envelope are independent statements).
    let carrier = stellereum::svm::EvmCarrierIntent {
        chain_id: chain,
        evm_tx: raw.clone(),
        evm_address: sender_evm,
        pq_pubkey: sender_pk.clone(),
        evm_signature: wrong_intent.clone(),
    };
    let facts = evm_adapter::evm_transfer_facts(&raw).expect("facts");
    let sign_this = evm_adapter::carrier_template_message(
        &raw,
        &sender_pk,
        &wrong_intent,
        recipient_pq,
        1_200_000,
    )
    .unwrap();
    let tx = Transaction::new_pq_explicit_with_chain(
        PqScheme::Falcon512,
        sender_pk.clone(),
        sender_kp.sign(&sign_this),
        recipient_pq,
        facts.value_nano,
        1_200_000,
        facts.nonce,
        0,
        0,
        vec![OpCode::SysCallEvmCarrier(Box::new(carrier))],
        &DEFAULT_SALT,
        chain,
    );
    assert!(tx.verify_signature());
    let err = mem
        .add_checked_ctx(tx, START_BALANCE, admission_ctx())
        .expect_err("a forged intent signature must be refused at admission");
    assert!(
        err.to_string().contains("does not verify"),
        "the admission refusal names the signature, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// 4. Replays are refused
// ---------------------------------------------------------------------------

#[tokio::test]
async fn carrier_replays_are_refused() {
    let engine = InMemoryStateEngine::new();
    let mut mem = pool();
    let chain = evm_adapter::effective_chain_id();

    let sender_kp = falcon_kp(0x41);
    let (sender_pq, sender_pk) = falcon(0x41);
    let (secp, sender_evm) = secp_signer(0x76);
    let (recipient_pq, _) = falcon(0x42);
    fund(&engine, sender_pq, START_BALANCE).await;
    evm_adapter::record_evm_binding(sender_evm, sender_pq).expect("binding");

    let raw = evm_transfer_raw(
        &secp,
        chain,
        0,
        [0x97u8; 20],
        (TRANSFER_NANO as u128) * evm_adapter::WEI_PER_NANO,
        21_000,
        vec![],
    );
    let carrier = signed_carrier_tx(&sender_kp, &raw, recipient_pq, 1_200_000);
    mem.add_checked_ctx(carrier.clone(), START_BALANCE, admission_ctx())
        .expect("first submission admitted");

    // (a) byte-identical replay: same hash, refused.
    let err = mem
        .add_checked_ctx(carrier.clone(), START_BALANCE, admission_ctx())
        .expect_err("duplicate carrier");
    assert!(matches!(err, stellereum::mempool::MempoolError::Duplicate));

    // (b) replay after inclusion: the nonce is consumed, so the SAME signed
    //     carrier can never settle twice.
    engine
        .apply_transaction(&carrier, 1_700_000_200)
        .await
        .expect("carrier applies once");
    let err = engine
        .apply_transaction(&carrier, 1_700_000_300)
        .await
        .expect_err("a replayed carrier must not apply");
    assert!(
        err.contains("Invalid nonce"),
        "execution refuses the replay on the consumed nonce, got: {err}"
    );

    // (c) the relayer shape: the same signed EVM intent re-wrapped in a carrier
    //     with a DIFFERENT Stell nonce (fresh hash, valid envelope from the
    //     bound key). The intent says nonce 0; admission refuses the mismatch,
    //     so one signed EVM transaction settles exactly once.
    let facts = evm_adapter::evm_transfer_facts(&raw).expect("facts");
    let intent_sig = sender_kp.sign(&evm_adapter::evm_intent_digest(&raw));
    let rewritten = stellereum::svm::EvmCarrierIntent {
        chain_id: chain,
        evm_tx: raw.clone(),
        evm_address: sender_evm,
        pq_pubkey: sender_pk.clone(),
        evm_signature: intent_sig,
    };
    let payload = vec![OpCode::SysCallEvmCarrier(Box::new(rewritten))];
    // The message depends only on the unsigned fields, so build it once with an
    // empty signature and then attach the real one.
    let template = Transaction::new_pq_explicit_with_chain(
        PqScheme::Falcon512,
        sender_pk.clone(),
        Vec::new(),
        recipient_pq,
        facts.value_nano,
        1_200_000,
        facts.nonce + 1, // a different outer nonce => a different tx hash
        0,
        0,
        payload.clone(),
        &DEFAULT_SALT,
        chain,
    );
    let msg = template.signing_message_for_chain(chain);
    let tx = Transaction::new_pq_explicit_with_chain(
        PqScheme::Falcon512,
        sender_pk.clone(),
        sender_kp.sign(&msg),
        recipient_pq,
        facts.value_nano,
        1_200_000,
        facts.nonce + 1,
        0,
        0,
        payload,
        &DEFAULT_SALT,
        chain,
    );
    assert!(tx.verify_signature(), "the re-wrap is validly signed");
    let err = mem
        .add_checked_ctx(tx, START_BALANCE, admission_ctx())
        .expect_err("a re-wrapped intent must be refused");
    assert!(
        err.to_string().contains("carrier nonce mismatch"),
        "the refusal names the nonce binding, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// 5. Contract calls / creation are refused honestly
// ---------------------------------------------------------------------------

#[tokio::test]
async fn carrier_refuses_contract_calls_and_creation() {
    let chain = evm_adapter::effective_chain_id();
    let (secp, _) = secp_signer(0x77);

    // (a) calldata => an EVM call this chain cannot execute.
    let call_raw = evm_transfer_raw(
        &secp,
        chain,
        0,
        [0x11u8; 20],
        1,
        100_000,
        vec![0xa9, 0x05, 0x9c, 0xbb],
    );
    let err = evm_adapter::evm_transfer_facts(&call_raw).expect_err("calldata refused");
    assert!(
        err.contains("no EVM interpreter"),
        "the refusal explains why, got: {err}"
    );
    assert!(err.contains("value transfers"));
    assert!(evm_adapter::EVM_CONTRACT_EXECUTION_REFUSAL.contains("no EVM interpreter"));

    // (b) contract creation (`to == null`).
    let unsigned = LegacyTransaction {
        nonce: 0,
        gas_price: 1,
        gas_limit: 100_000,
        to: None,
        value: 1,
        data: vec![],
        v: 0,
        r: [0u8; 32],
        s: [0u8; 32],
        chain_id: Some(chain),
    };
    let sighash = unsigned.signing_hash();
    let (sig, recid) = secp.sign_prehash_recoverable(&sighash).expect("sign");
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig.to_bytes()[..32]);
    s.copy_from_slice(&sig.to_bytes()[32..64]);
    let creation = LegacyTransaction {
        v: chain * 2 + 35 + recid.to_byte() as u64,
        r,
        s,
        ..unsigned
    }
    .encode();
    let err = evm_adapter::evm_transfer_facts(&creation).expect_err("creation refused");
    assert!(err.contains("contract creation"), "got: {err}");

    // (c) zero-value and sub-nano intents carry nothing to settle.
    let zero_raw = evm_transfer_raw(&secp, chain, 0, [0x11u8; 20], 0, 21_000, vec![]);
    let err = evm_adapter::evm_transfer_facts(&zero_raw).expect_err("zero value refused");
    assert!(err.contains("no value"), "got: {err}");
    let dust_raw = evm_transfer_raw(&secp, chain, 0, [0x11u8; 20], 1, 21_000, vec![]);
    let err = evm_adapter::evm_transfer_facts(&dust_raw).expect_err("sub-nano refused");
    assert!(err.contains("below one nano-STELL"), "got: {err}");
}

// ---------------------------------------------------------------------------
// 6. The fee must cover the floor PLUS the carrier surcharge
// ---------------------------------------------------------------------------

#[tokio::test]
async fn carrier_fee_must_cover_floor_plus_carrier_surcharge() {
    let engine = InMemoryStateEngine::new();
    let mut mem = pool(); // base_fee 280_000
    let chain = evm_adapter::effective_chain_id();

    let sender_kp = falcon_kp(0x51);
    let (sender_pq, _) = falcon(0x51);
    let (secp, sender_evm) = secp_signer(0x78);
    let (recipient_pq, _) = falcon(0x52);
    fund(&engine, sender_pq, START_BALANCE).await;
    evm_adapter::record_evm_binding(sender_evm, sender_pq).expect("binding");

    let raw = evm_transfer_raw(
        &secp,
        chain,
        0,
        [0x96u8; 20],
        (TRANSFER_NANO as u128) * evm_adapter::WEI_PER_NANO,
        21_000,
        vec![],
    );

    // A carrier that declares exactly the bare base fee: the PQ activation
    // surcharge AND the carrier surcharge are still owed.
    let bare = signed_carrier_tx(&sender_kp, &raw, recipient_pq, 280_000);
    let err = mem
        .add_checked_ctx(bare, START_BALANCE, admission_ctx())
        .expect_err("a carrier below floor+surcharge is refused");
    assert!(
        matches!(err, stellereum::mempool::MempoolError::FeeTooLow),
        "got: {err}"
    );

    // Declaring exactly floor + activation + carrier surcharge is admitted.
    let exact = 280_000 + 45_000 + stellereum::mempool::EVM_CARRIER_SURCHARGE_GAS;
    let ok = signed_carrier_tx(&sender_kp, &raw, recipient_pq, exact);
    mem.add_checked_ctx(ok, START_BALANCE, admission_ctx())
        .expect("the exact floor is admitted");
}

// ---------------------------------------------------------------------------
// 7. RPC surface: binding read, actionable refusal, one-call settlement
// ---------------------------------------------------------------------------

struct RpcHarness {
    st: Arc<RpcState>,
    addr: SocketAddr,
}

fn rpc_state(engine: Arc<InMemoryStateEngine>, mempool: Mempool) -> Arc<RpcState> {
    Arc::new(RpcState {
        engine,
        mempool: Arc::new(tokio::sync::RwLock::new(mempool)),
        height: Arc::new(std::sync::atomic::AtomicU64::new(100)),
        node_id: "test:evm-carrier".to_string(),
        chain_id: evm_adapter::effective_chain_id(),
        staking: Arc::new(tokio::sync::RwLock::new(
            stellereum::staking::StakingLedger::new(),
        )),
        governance: Arc::new(tokio::sync::RwLock::new(
            stellereum::governance::Governance::new(),
        )),
        recent_blocks: Arc::new(tokio::sync::RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(tokio::sync::RwLock::new(ReceiptIndex::default())),
        auth_token: None,
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        msg_signing_seed: None,
        archive_store: None,
        shard_registry: ShardRegistry::single(),
    })
}

async fn rpc_harness(engine: Arc<InMemoryStateEngine>, mempool: Mempool) -> RpcHarness {
    let st = rpc_state(engine, mempool);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let router = stellereum::rpc::router(st.clone());
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    RpcHarness { st, addr }
}

async fn rpc_call(addr: SocketAddr, method: &str, params: Value) -> Value {
    let body = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string();
    let mut s = TcpStream::connect(addr).await.expect("connect");
    let req = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = s.write_all(req.as_bytes()).await;
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf).await;
    let text = String::from_utf8_lossy(&buf).to_string();
    let (_head, rsp) = text.split_once("\r\n\r\n").unwrap_or(("", &text));
    serde_json::from_str(rsp).unwrap_or_else(|e| {
        panic!("response is not JSON ({e}); raw = {text:?}");
    })
}

#[tokio::test]
async fn rpc_binding_and_carrier_roundtrip() {
    let engine = Arc::new(InMemoryStateEngine::new());
    let h = rpc_harness(engine.clone(), pool()).await;
    let chain = evm_adapter::effective_chain_id();

    let sender_kp = falcon_kp(0x61);
    let (sender_pq, sender_pk) = falcon(0x61);
    let (recipient_pq, _) = falcon(0x62);
    let (secp, sender_evm) = secp_signer(0x79);
    let (rsecp, recipient_evm) = secp_signer(0x7a);
    fund(&engine, sender_pq, START_BALANCE).await;

    // --- bind the sender through the RPC ---------------------------------
    let claim_msg = evm_adapter::binding_message(chain, &sender_evm, &sender_pq);
    let claim_sig = sender_kp.sign(&claim_msg);
    let evm_proof = evm_binding_proof(&secp, chain, &sender_evm, &sender_pq);
    let bind_sign_this = evm_adapter::binding_template_message(
        &sender_pk, sender_evm, &claim_sig, &evm_proof, 0, 600_000,
    )
    .expect("tpl");
    let bind_tx_sig = sender_kp.sign(&bind_sign_this);
    let r = rpc_call(
        h.addr,
        "stell_evmBindingSubmit",
        json!([{
            "pqPublicKey": format!("0x{}", hex::encode(&sender_pk)),
            "evmAddress": format!("0x{}", hex::encode(sender_evm)),
            "bindingSignature": format!("0x{}", hex::encode(&claim_sig)),
            "evmSignature": format!("0x{}", hex::encode(&evm_proof)),
            "txSignature": format!("0x{}", hex::encode(&bind_tx_sig)),
            "nonce": 0,
            "gasLimit": 600_000,
        }]),
    )
    .await;
    let submitted = r["result"]
        .as_str()
        .unwrap_or_else(|| panic!("stell_evmBindingSubmit returns the Stell tx hash, got {r}"));
    let submitted: [u8; 32] = hex::decode(submitted)
        .expect("hash hex")
        .try_into()
        .expect("32-byte hash");

    // M1: an ADMITTED (mempool-only) claim is not committed, so it must not be
    // reported as bound yet...
    let r = rpc_call(
        h.addr,
        "stell_getEvmBinding",
        json!([format!("0x{}", hex::encode(sender_evm))]),
    )
    .await;
    assert_eq!(
        r["result"]["bound"],
        json!(false),
        "a mempool-only claim must not be reported as committed: {r}"
    );

    // ...and once the block path applies it, the routing index is exact.
    let bind_tx =
        h.st.mempool
            .read()
            .await
            .get(&submitted)
            .cloned()
            .expect("the submitted claim is pooled");
    engine
        .apply_transaction(&bind_tx, 1_700_000_000)
        .await
        .expect("committed binding applies");
    let r = rpc_call(
        h.addr,
        "stell_getEvmBinding",
        json!([format!("0x{}", hex::encode(sender_evm))]),
    )
    .await;
    assert_eq!(r["result"]["bound"], json!(true), "got {r}");
    assert_eq!(
        r["result"]["pqAddress"],
        json!(format!("0x{}", hex::encode(sender_pq)))
    );

    // Bind the recipient (it must exist on chain to be credited, and a
    // committed binding pays its own gas).
    fund(&engine, recipient_pq, START_BALANCE).await;
    let recipient_kp = falcon_kp(0x62);
    let recipient_bind = signed_binding_tx(&recipient_kp, &rsecp, recipient_evm, 0, 600_000);
    h.st.mempool
        .write()
        .await
        .add_checked_ctx(recipient_bind.clone(), START_BALANCE, admission_ctx())
        .expect("recipient binding admitted");
    // M1/H1: routing is fed by COMMITTED blocks, so the recipient must be
    // applied before the sender's carrier can route to it.
    engine
        .apply_transaction(&recipient_bind, 1_700_000_000)
        .await
        .expect("recipient binding applies");

    // --- an EVM-only submission: no Falcon authorisation yet -------------
    let raw = evm_transfer_raw(
        &secp,
        chain,
        1,
        recipient_evm,
        (TRANSFER_NANO as u128) * evm_adapter::WEI_PER_NANO,
        21_000,
        vec![],
    );
    let r = rpc_call(
        h.addr,
        "eth_sendRawTransaction",
        json!([format!("0x{}", hex::encode(&raw))]),
    )
    .await;
    assert_eq!(r["error"]["code"], json!(-32000), "got {r}");
    assert_eq!(
        r["error"]["data"]["reason"],
        json!(evm_adapter::EVM_CARRIER_AUTH_REASON),
        "the refusal is machine-readable and names the missing PQ authorisation"
    );
    assert_eq!(
        r["error"]["data"]["boundPqAddress"],
        json!(format!("0x{}", hex::encode(sender_pq)))
    );
    // Step 1 reports the EVM-intent digest (the carrier message cannot exist
    // until that signature is part of the payload).
    assert_eq!(
        r["error"]["data"]["next"],
        json!("intent-signature"),
        "got {r}"
    );
    let intent_digest_hex = r["error"]["data"]["intentSignThis"]
        .as_str()
        .expect("step 1 reports the intent digest")
        .to_string();
    let intent_digest = hex::decode(intent_digest_hex.trim_start_matches("0x")).expect("hex");
    assert_eq!(
        intent_digest,
        evm_adapter::evm_intent_digest(&raw),
        "the reported digest is keccak256(EVM raw)"
    );
    let intent_sig = sender_kp.sign(&intent_digest);

    // Step 2 (with the intent signature) reports the exact carrier message.
    let r = rpc_call(
        h.addr,
        "eth_sendRawTransaction",
        json!([format!("0x{}", hex::encode(&raw)), {
            "carrier": {
                "pqPublicKey": format!("0x{}", hex::encode(&sender_pk)),
                "intentSignature": format!("0x{}", hex::encode(&intent_sig)),
            }
        }]),
    )
    .await;
    assert_eq!(
        r["error"]["data"]["reason"],
        json!(evm_adapter::EVM_CARRIER_AUTH_REASON),
        "got {r}"
    );
    assert_eq!(
        r["error"]["data"]["next"],
        json!("carrier-signature"),
        "got {r}"
    );
    let sign_this_hex = r["error"]["data"]["signThis"]
        .as_str()
        .expect("step 2 carries the exact bytes to sign")
        .to_string();
    let sign_this = hex::decode(sign_this_hex.trim_start_matches("0x")).expect("hex");
    let tx_sig = sender_kp.sign(&sign_this);

    // Step 3: both signatures => the carrier settles.
    let r = rpc_call(
        h.addr,
        "eth_sendRawTransaction",
        json!([format!("0x{}", hex::encode(&raw)), {
            "carrier": {
                "pqPublicKey": format!("0x{}", hex::encode(&sender_pk)),
                "intentSignature": format!("0x{}", hex::encode(&intent_sig)),
                "txSignature": format!("0x{}", hex::encode(&tx_sig)),
            }
        }]),
    )
    .await;
    let evm_hash = match r["result"].as_str() {
        Some(s) => s.to_string(),
        None => panic!("carrier settled, expected the EVM hash, got {r}"),
    };
    assert_eq!(
        evm_hash,
        format!("0x{}", hex::encode(evm_adapter::keccak256(&raw))),
        "the answer is the hash MetaMask tracks"
    );
    let pool_len = h.st.mempool.read().await.len();
    assert!(pool_len >= 1, "the carrier is in the mempool");

    // `pending` nonce must skip what is already pooled, or a wallet sending
    // twice in a row would reuse nonce 0 and be refused.
    let latest = rpc_call(
        h.addr,
        "eth_getTransactionCount",
        json!([format!("0x{}", hex::encode(sender_evm)), "latest"]),
    )
    .await;
    assert_eq!(latest["result"], json!("0x1"), "got {latest}");
    let pending = rpc_call(
        h.addr,
        "eth_getTransactionCount",
        json!([format!("0x{}", hex::encode(sender_evm)), "pending"]),
    )
    .await;
    assert_eq!(
        pending["result"],
        json!("0x2"),
        "the pending nonce skips the pooled carrier, got {pending}"
    );

    // --- the carrier applies and moves the value -------------------------
    let carrier_tx: Transaction =
        h.st.mempool
            .read()
            .await
            .all()
            .into_iter()
            .find(|t| t.amount == TRANSFER_NANO)
            .expect("carrier in the pool");
    let recipient_before = balance(&engine, recipient_pq).await;
    engine
        .apply_transaction(&carrier_tx, 1_700_000_400)
        .await
        .expect("carrier applies");
    assert_eq!(
        balance(&engine, recipient_pq).await,
        recipient_before + TRANSFER_NANO
    );

    // The EVM hash resolves to the carrier (so a wallet polling
    // eth_getTransactionByHash does not see null).
    assert_eq!(
        evm_adapter::evm_to_stell_hash(&evm_hash),
        Some(carrier_tx.compute_tx_hash())
    );

    // --- refusals that must survive the new path -------------------------
    // An EVM intent from an address with NO binding keeps the historical
    // `full-pq-admission` refusal verbatim.
    let other_key = k256::ecdsa::SigningKey::from_slice(&[0x7cu8; 32]).expect("key");
    let unbound_raw = evm_transfer_raw(
        &other_key,
        chain,
        0,
        recipient_evm,
        (TRANSFER_NANO as u128) * evm_adapter::WEI_PER_NANO,
        21_000,
        vec![],
    );
    let r = rpc_call(
        h.addr,
        "eth_sendRawTransaction",
        json!([format!("0x{}", hex::encode(&unbound_raw))]),
    )
    .await;
    assert_eq!(
        r["error"]["data"]["reason"],
        json!("full-pq-admission"),
        "no binding => the historical honest refusal, got {r}"
    );

    // An intent to an UNBOUND recipient is refused (the funds would burn).
    let (_r2secp, unbound_recipient) = secp_signer(0x7d);
    let to_nowhere = evm_transfer_raw(
        &secp,
        chain,
        1,
        unbound_recipient,
        (TRANSFER_NANO as u128) * evm_adapter::WEI_PER_NANO,
        21_000,
        vec![],
    );
    let r = rpc_call(
        h.addr,
        "eth_sendRawTransaction",
        json!([format!("0x{}", hex::encode(&to_nowhere))]),
    )
    .await;
    assert_eq!(
        r["error"]["data"]["reason"],
        json!(evm_adapter::EVM_RECIPIENT_UNBOUND_REASON),
        "recipient routing is explicit, got {r}"
    );
}

// ---------------------------------------------------------------------------
// 8. The binding index replays committed records and refuses conflicts
// ---------------------------------------------------------------------------

#[tokio::test]
async fn binding_index_replays_committed_records_and_refuses_conflicts() {
    let engine = InMemoryStateEngine::new();
    let mut mem = pool();

    let kp_a = falcon_kp(0x81);
    let (pq_a, _) = falcon(0x81);
    let kp_b = falcon_kp(0x82);
    let (pq_b, _) = falcon(0x82);
    let (sx, evm_x) = secp_signer(0x91);

    fund(&engine, pq_a, START_BALANCE).await;
    let bind_a = signed_binding_tx(&kp_a, &sx, evm_x, 0, 600_000);

    // Deterministic replay of a COMMITTED record reconstructs the binding (the
    // restart path: the index is derived, never authoritative).
    assert_eq!(
        engine.observe_committed_evm_txs(std::slice::from_ref(&bind_a)),
        1
    );
    assert_eq!(evm_adapter::lookup_bound_pq(&evm_x), Some(pq_a));
    // Idempotent: replaying the same chain again derives the same map.
    assert_eq!(
        engine.observe_committed_evm_txs(std::slice::from_ref(&bind_a)),
        1
    );
    assert_eq!(evm_adapter::lookup_bound_pq(&evm_x), Some(pq_a));

    // A claim settles no EVM intent: the settlement hook indexes it but links
    // no EVM transaction hash.
    assert!(evm_adapter::link_secp_settlement(&bind_a).is_none());
    assert_eq!(evm_adapter::lookup_bound_pq(&evm_x), Some(pq_a));

    mem.add_checked_ctx(bind_a, START_BALANCE, admission_ctx())
        .expect("the first claim is admissible");

    // A second claim on an ALREADY-BOUND EVM address is refused: first claim
    // wins, so a thief cannot re-point an EVM identity's routing.
    assert_ne!(pq_a, pq_b);
    let hostile = signed_binding_tx(&kp_b, &sx, evm_x, 0, 600_000);
    let err = mem
        .add_checked_ctx(hostile, START_BALANCE, admission_ctx())
        .expect_err("a conflicting claim must be refused");
    assert!(
        err.to_string().contains("already bound"),
        "the refusal names the conflict, got: {err}"
    );
    assert_eq!(
        evm_adapter::lookup_bound_pq(&evm_x),
        Some(pq_a),
        "the index still points at the first claimant"
    );
}
