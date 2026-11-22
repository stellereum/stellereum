//! Tests for batched + parallel block application.
//! Must produce exactly the same state as sequential apply_transaction.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use stellereum::post_quantum::{
    derive_pq_address, FalconKeypair, PqScheme, PqSignatureEnvelope, DEFAULT_SALT,
};
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::OpCode;
use stellereum::token::{TokenMetadata, TokenOp, ZERO_ADDRESS};

/// FULL-PQ sender identity: implicit Falcon-512, registered globally.
fn pq_key(seed: u8) -> (FalconKeypair, [u8; 32]) {
    let kp = FalconKeypair::generate_from_seed(seed);
    let addr = derive_pq_address(PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT);
    Transaction::global_implicit_registry()
        .register(addr, PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT)
        .expect("PQ test key must register");
    (kp, addr)
}

fn addr_of(kp: &FalconKeypair) -> [u8; 32] {
    derive_pq_address(PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT)
}

/// FULL-PQ replacement for `Transaction::sign`.
fn pq_transfer(kp: &FalconKeypair, to: [u8; 32], amount: u64, gas: u64, nonce: u64) -> Transaction {
    let from = addr_of(kp);
    let mut t = Transaction {
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
    let msg = t.signing_message();
    let sig = kp.sign(&msg);
    t.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig).encode();
    t
}

/// FULL-PQ replacement for `Transaction::sign_with_payload`.
fn pq_payload_tx(kp: &FalconKeypair, gas: u64, nonce: u64, payload: Vec<OpCode>) -> Transaction {
    let from = addr_of(kp);
    let mut t = Transaction {
        from,
        to: from,
        amount: 0,
        gas_limit: gas,
        nonce,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload,
        priority_fee_per_gas: 0,
    };
    let msg = t.signing_message();
    let sig = kp.sign(&msg);
    t.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig).encode();
    t
}

fn funded_engine(n: usize, bal: u64, seed_base: u8) -> (InMemoryStateEngine, Vec<FalconKeypair>) {
    let engine = InMemoryStateEngine::new();
    let mut keys = Vec::new();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        for i in 0..n {
            let (kp, a) = pq_key(seed_base.wrapping_add(i as u8));
            engine.update_account(AccountState::new(a, bal)).await;
            keys.push(kp);
        }
    });
    (engine, keys)
}

fn run_rt<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Runtime::new().unwrap().block_on(f)
}

#[test]
fn parallel_block_matches_sequential_for_distinct_senders() {
    // Build ONE key set and mirror it into two funded engines.
    let rt = tokio::runtime::Runtime::new().unwrap();
    let keys: Vec<FalconKeypair> = (0..20).map(|i| pq_key(0x20 + i).0).collect();
    let e1 = InMemoryStateEngine::new();
    let e2 = InMemoryStateEngine::new();
    rt.block_on(async {
        for kp in &keys {
            let a = addr_of(kp);
            e1.update_account(AccountState::new(a, 1_000_000)).await;
            e2.update_account(AccountState::new(a, 1_000_000)).await;
        }
    });

    // distinct senders, each sends a few sequential txs
    let mut txs = Vec::new();
    for (i, kp) in keys.iter().enumerate() {
        let to = addr_of(&keys[(i + 1) % keys.len()]);
        for nonce in 0..3u64 {
            txs.push(pq_transfer(kp, to, 100, 0, nonce));
        }
    }

    // sequential baseline
    run_rt(async {
        for tx in &txs {
            e1.apply_transaction(tx, 0).await.unwrap();
        }
    });
    let (applied, failed) = run_rt(e2.apply_block_parallel(&txs, 0));
    assert_eq!(applied, txs.len());
    assert_eq!(failed, 0);

    let root1 = run_rt(e1.get_state_root());
    let root2 = run_rt(e2.get_state_root());
    assert_eq!(root1, root2, "parallel state root must equal sequential");
    for kp in &keys {
        let a = addr_of(kp);
        let b1 = run_rt(e1.get_account(&a)).unwrap();
        let b2 = run_rt(e2.get_account(&a)).unwrap();
        assert_eq!(b1.balance, b2.balance);
        assert_eq!(b1.nonce, b2.nonce);
    }
}

#[test]
fn parallel_block_rejects_bad_nonce_and_bad_sig() {
    let (e, keys) = funded_engine(5, 1_000_000, 0x40);
    let mut txs = Vec::new();
    // valid
    txs.push(pq_transfer(&keys[0], addr_of(&keys[1]), 10, 0, 0));
    // bad nonce (should be 1 after the above if same sender; use wrong nonce)
    txs.push(pq_transfer(&keys[0], addr_of(&keys[1]), 10, 0, 5));
    // bad signature
    let mut bad = pq_transfer(&keys[2], addr_of(&keys[3]), 10, 0, 0);
    bad.signature[0] ^= 0xFF;
    txs.push(bad);

    let (applied, failed) = run_rt(e.apply_block_parallel(&txs, 0));
    assert_eq!(applied, 1, "only the valid tx applied");
    assert_eq!(failed, 2, "bad nonce + bad sig rejected");
}

#[test]
fn parallel_block_conserves_total_value() {
    let (e, keys) = funded_engine(10, 1_000, 0x50);
    let total_before: u64 = run_rt(async {
        let mut s = 0;
        for kp in &keys {
            s += e.get_account(&addr_of(kp)).await.unwrap().balance;
        }
        s
    });
    let mut txs = Vec::new();
    for (i, kp) in keys.iter().enumerate() {
        let to = addr_of(&keys[(i + 3) % keys.len()]);
        txs.push(pq_transfer(kp, to, 50, 0, 0));
    }
    let (applied, _) = run_rt(e.apply_block_parallel(&txs, 0));
    assert_eq!(applied, txs.len());
    let total_after: u64 = run_rt(async {
        let mut s = 0;
        for kp in &keys {
            if let Some(a) = e.get_account(&addr_of(kp)).await {
                s += a.balance;
            }
        }
        s
    });
    // fee = gas_limit = 0 here, so total conserved exactly
    assert_eq!(total_before, total_after, "value must be conserved");
}

fn token_meta() -> TokenMetadata {
    TokenMetadata {
        name: "T".to_string(),
        symbol: "T".to_string(),
        decimals: 6,
        total_supply: 0,
        max_supply: None,
        minter: ZERO_ADDRESS,
        paused: false,
        description: String::new(),
    }
}

#[test]
fn rejected_tx_payload_is_not_executed() {
    // SECURITY: an SVM payload must never run for a transaction that is rejected
    // by admission (wrong nonce / insufficient balance). Otherwise a replayed or
    // unfunded tx could still move tokens while being reported as failed.
    let rt = tokio::runtime::Runtime::new().unwrap();
    let engine = InMemoryStateEngine::new();
    let minter = SigningKey::generate(&mut OsRng);
    let minter_addr = minter.verifying_key().to_bytes();
    let (victim, victim_addr) = pq_key(0xC1);
    let thief = [0x77u8; 32];

    let token_id = rt.block_on(async {
        engine
            .update_account(AccountState::new(victim_addr, 1_000_000))
            .await;
        let id = engine
            .create_token(minter_addr, token_meta(), 1_000)
            .await
            .unwrap();
        engine
            .token_execute(
                &id,
                minter_addr,
                TokenOp::Transfer {
                    to: victim_addr,
                    amount: 100,
                },
            )
            .await
            .unwrap();
        id
    });

    // Valid payload (steals the victim's tokens) but WRONG nonce (5, actual 0).
    let payload = vec![OpCode::SysCallTokenTransfer {
        token_id,
        to: thief,
        amount: 100,
    }];
    let tx = pq_payload_tx(&victim, 10_000, 5, payload);

    let (applied, failed) = rt.block_on(engine.apply_block_parallel(&[tx], 0));
    assert_eq!(applied, 0, "bad-nonce tx must not be applied");
    assert_eq!(failed, 1);
    assert_eq!(
        rt.block_on(engine.token_balance(&token_id, &victim_addr)),
        100,
        "victim tokens untouched"
    );
    assert_eq!(
        rt.block_on(engine.token_balance(&token_id, &thief)),
        0,
        "no tokens reach the thief"
    );
}

#[test]
fn underfunded_tx_payload_is_not_executed() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let engine = InMemoryStateEngine::new();
    let minter = SigningKey::generate(&mut OsRng);
    let minter_addr = minter.verifying_key().to_bytes();
    let (victim, victim_addr) = pq_key(0xC2);
    let thief = [0x66u8; 32];

    let token_id = rt.block_on(async {
        // NO native balance -> cannot pay gas -> admission must fail.
        engine
            .update_account(AccountState::new(victim_addr, 0))
            .await;
        let id = engine
            .create_token(minter_addr, token_meta(), 1_000)
            .await
            .unwrap();
        engine
            .token_execute(
                &id,
                minter_addr,
                TokenOp::Transfer {
                    to: victim_addr,
                    amount: 100,
                },
            )
            .await
            .unwrap();
        id
    });

    let payload = vec![OpCode::SysCallTokenTransfer {
        token_id,
        to: thief,
        amount: 100,
    }];
    let tx = pq_payload_tx(&victim, 10_000, 0, payload);

    let (applied, failed) = rt.block_on(engine.apply_block_parallel(&[tx], 0));
    assert_eq!(applied, 0, "unfunded tx must not be applied");
    assert_eq!(failed, 1);
    assert_eq!(
        rt.block_on(engine.token_balance(&token_id, &victim_addr)),
        100,
        "victim tokens untouched"
    );
    assert_eq!(
        rt.block_on(engine.token_balance(&token_id, &thief)),
        0,
        "no tokens reach the thief"
    );
}

#[test]
fn admitted_tx_payload_is_executed() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let engine = InMemoryStateEngine::new();
    let minter = SigningKey::generate(&mut OsRng);
    let minter_addr = minter.verifying_key().to_bytes();
    let (sender, sender_addr) = pq_key(0xC3);
    let dest = [0x55u8; 32];

    let token_id = rt.block_on(async {
        engine
            .update_account(AccountState::new(sender_addr, 1_000_000))
            .await;
        let id = engine
            .create_token(minter_addr, token_meta(), 1_000)
            .await
            .unwrap();
        engine
            .token_execute(
                &id,
                minter_addr,
                TokenOp::Transfer {
                    to: sender_addr,
                    amount: 100,
                },
            )
            .await
            .unwrap();
        id
    });

    let payload = vec![OpCode::SysCallTokenTransfer {
        token_id,
        to: dest,
        amount: 100,
    }];
    // The gas limit must cover the token operation: the token table is priced
    // at the native floor (audit W6.6, item 4), so a token transfer costs
    // 280_000 gas like a native transfer.
    let tx = pq_payload_tx(&sender, 300_000, 0, payload);

    let (applied, failed) = rt.block_on(engine.apply_block_parallel(&[tx], 0));
    assert_eq!(applied, 1, "valid tx must be applied");
    assert_eq!(failed, 0);
    assert_eq!(
        rt.block_on(engine.token_balance(&token_id, &sender_addr)),
        0
    );
    assert_eq!(rt.block_on(engine.token_balance(&token_id, &dest)), 100);
}

#[test]
fn block_signature_batch_helper() {
    let (_, keys) = funded_engine(3, 1000, 0x60);
    let txs = vec![
        pq_transfer(&keys[0], addr_of(&keys[1]), 1, 0, 0),
        pq_transfer(&keys[1], addr_of(&keys[2]), 1, 0, 0),
    ];
    assert!(InMemoryStateEngine::verify_block_signatures(&txs));
    let mut bad = txs.clone();
    bad[1].amount = 999;
    assert!(!InMemoryStateEngine::verify_block_signatures(&bad));
}

#[test]
fn parallel_batch_verify_equals_sequential() {
    let (_, keys) = funded_engine(50, 1000, 0x80);
    // > CHUNK (256) to trigger the parallel path
    let mut txs = Vec::new();
    for i in 0..600 {
        let kp = &keys[i % keys.len()];
        txs.push(pq_transfer(kp, [9u8; 32], 1, 0, i as u64));
    }
    assert!(Transaction::verify_signatures_batch_parallel(&txs));
    assert_eq!(
        Transaction::verify_signatures_batch(&txs),
        Transaction::verify_signatures_batch_parallel(&txs)
    );
    // corrupt one -> both reject
    let mut bad = txs.clone();
    bad[400].signature[0] ^= 1;
    assert!(!Transaction::verify_signatures_batch_parallel(&bad));
    assert!(!Transaction::verify_signatures_batch(&bad));
}
