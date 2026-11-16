use super::*;
use crate::post_quantum::{derive_pq_address, PqScheme, PqSignatureEnvelope};
use crate::sharding::Transaction;

mod commit_cache;
mod gov_ops;
mod parallel_waves;
mod pq_pinning;
mod slashing_and_events;

/// FULL-PQ test helper: implicit Falcon-512 keypair for a seed, with the
/// key pre-registered globally (idempotent) for apply-path verification.
/// Returns (sender address, raw pubkey).
pub(super) fn pq_pair(seed: u8) -> ([u8; 32], Vec<u8>) {
    let pk = Transaction::sample_falcon512_pubkey(seed);
    let salt = crate::post_quantum::DEFAULT_SALT;
    let from = derive_pq_address(PqScheme::Falcon512, &pk, &salt);
    Transaction::global_implicit_registry()
        .register(from, PqScheme::Falcon512, &pk, &salt)
        .expect("PQ test key must register");
    (from, pk)
}

/// FULL-PQ replacement for `Transaction::sign` in tests: implicit
/// Falcon-512 envelope (NO activation surcharge, so fee/balance/nonce
/// assertions match the old classical fixtures exactly). Returns
/// (tx, sender address, raw pubkey).
pub(super) fn pq_tx(
    seed: u8,
    to: [u8; 32],
    amount: u64,
    gas: u64,
    nonce: u64,
) -> (Transaction, [u8; 32], Vec<u8>) {
    pq_tx_payload(seed, to, amount, gas, nonce, Vec::new())
}

/// FULL-PQ replacement for `Transaction::sign_with_payload` in tests.
pub(super) fn pq_tx_payload(
    seed: u8,
    to: [u8; 32],
    amount: u64,
    gas: u64,
    nonce: u64,
    payload: Vec<crate::svm::OpCode>,
) -> (Transaction, [u8; 32], Vec<u8>) {
    let (from, pk) = pq_pair(seed);
    let mut tx = Transaction {
        from,
        to,
        amount,
        gas_limit: gas,
        nonce,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload,
        priority_fee_per_gas: 0,
    };
    let msg = tx.signing_message();
    let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
    tx.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig).encode();
    (tx, from, pk)
}
