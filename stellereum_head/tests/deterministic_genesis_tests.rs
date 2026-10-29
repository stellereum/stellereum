//! P1: deterministic genesis — all nodes with the same validator set derive an
//! identical genesis state root.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;

use stellereum::consensus::ValidatorSet;
use stellereum::runtime::fund_genesis;
use stellereum::state_engine::InMemoryStateEngine;

const BAL: u64 = 100_000_000_000_000_000;

#[tokio::test]
async fn same_validator_set_yields_identical_state_root() {
    let keys: Vec<SigningKey> = (0..3).map(|_| SigningKey::generate(&mut OsRng)).collect();
    let ids: Vec<[u8; 32]> = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();

    // Node A builds the set in one order, node B in a different order: the
    // resulting state root must still match (BTreeMap sorts by id).
    let vs_a = ValidatorSet::from_list(ids.iter().map(|i| (*i, 1)).collect());
    let mut rev = ids.clone();
    rev.reverse();
    let vs_b = ValidatorSet::from_list(rev.iter().map(|i| (*i, 1)).collect());

    let a = Arc::new(InMemoryStateEngine::new());
    let b = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&a, &vs_a, BAL).await;
    fund_genesis(&b, &vs_b, BAL).await;

    assert_eq!(
        a.get_state_root().await,
        b.get_state_root().await,
        "genesis state root must be identical across nodes"
    );
    for id in &ids {
        assert_eq!(a.get_account(id).await.unwrap().balance, BAL);
    }
}

#[tokio::test]
async fn different_validator_sets_diverge() {
    let k1 = SigningKey::generate(&mut OsRng);
    let k2 = SigningKey::generate(&mut OsRng);
    let a = Arc::new(InMemoryStateEngine::new());
    let b = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&a, &ValidatorSet::from_list(vec![(k1.verifying_key().to_bytes(), 1)]), BAL).await;
    fund_genesis(&b, &ValidatorSet::from_list(vec![(k1.verifying_key().to_bytes(), 1), (k2.verifying_key().to_bytes(), 1)]), BAL).await;
    assert_ne!(a.get_state_root().await, b.get_state_root().await);
}
