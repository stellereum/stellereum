//! A11: transaction fees are collected and paid to the block proposer, and
//! value is conserved end-to-end.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;

use stellereum::runtime::Cluster;
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

#[tokio::test]
async fn proposer_collects_transaction_fees_and_value_is_conserved() {
    let val = SigningKey::generate(&mut OsRng);
    let val_addr = val.verifying_key().to_bytes();
    let user = SigningKey::generate(&mut OsRng);
    let from = user.verifying_key().to_bytes();
    let to = [9u8; 32];

    let st = Arc::new(InMemoryStateEngine::new());
    st.update_account(AccountState::new(from, 1_000_000)).await;
    st.update_account(AccountState::new(val_addr, 0)).await;

    let mut cluster = Cluster::new(vec![(val.clone(), st.clone())]);
    // amount 100, fee(=gas_limit) 1_000
    let tx = Transaction::sign(&user, to, 100, 1_000, 0, 1, 1);
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
