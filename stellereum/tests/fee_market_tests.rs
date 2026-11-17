//! A11: transaction fees are collected and paid to the block proposer, and
//! value is conserved end-to-end.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;

use stellereum::post_quantum::{derive_pq_address, PqScheme, PqSignatureEnvelope, DEFAULT_SALT};
use stellereum::runtime::Cluster;
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

/// FULL-PQ sender fixture: an implicit Falcon-512 transaction with the key
/// registered globally, so it is not an ACTIVATION tx and pays only its
/// declared `gas_limit` (no 45k state-rent surcharge).
fn pq_tx(seed: u8, to: [u8; 32], amount: u64, gas: u64, nonce: u64) -> Transaction {
    let pk = Transaction::sample_falcon512_pubkey(seed);
    let from = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);
    Transaction::global_implicit_registry()
        .register(from, PqScheme::Falcon512, &pk, &DEFAULT_SALT)
        .expect("PQ test key must register");
    let mut tx = Transaction {
        from,
        to,
        amount,
        gas_limit: gas,
        nonce,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg = tx.signing_message();
    let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
    tx.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig).encode();
    tx
}

#[tokio::test]
async fn proposer_collects_transaction_fees_and_value_is_conserved() {
    let val = SigningKey::generate(&mut OsRng);
    let val_addr = val.verifying_key().to_bytes();
    let to = [9u8; 32];

    let st = Arc::new(InMemoryStateEngine::new());

    // amount 100, fee(=gas_limit) 1_000
    let tx = pq_tx(7, to, 100, 1_000, 0);
    let from = tx.from;
    st.update_account(AccountState::new(from, 1_000_000)).await;
    st.update_account(AccountState::new(val_addr, 0)).await;

    let mut cluster = Cluster::new(vec![(val.clone(), st.clone())]);
    cluster.broadcast_tx(tx).await;
    cluster.run_height(1).await;

    let proposer = st.get_account(&val_addr).await.unwrap();
    let sender = st.get_account(&from).await.unwrap();
    let recipient = st.get_account(&to).await.unwrap();

    assert_eq!(proposer.balance, 1_000, "proposer must collect the fee");
    assert_eq!(sender.balance, 1_000_000 - 100 - 1_000);
    assert_eq!(recipient.balance, 100);
    // Value conservation: everything that left the sender arrived somewhere.
    assert_eq!(
        proposer.balance + sender.balance + recipient.balance,
        1_000_000
    );
}
