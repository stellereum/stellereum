//! Mempool economics hardening (audit-mempool F-03 + F-04, MEDIUM).
//!
//! F-03 — balance never reserved: admission checked each tx individually
//! against the balance, so ONE funding backed all 256 per-sender slots with
//! mutually unaffordable txs (Sybil squatting). Fix: the checked path refuses
//! when `reserved_for(sender) + tx_cost(new) > balance` (fail-closed
//! `InsufficientBalance`).
//!
//! F-04 — eviction at fee+1: a full pool churned for a linear premium.
//! Fix: eviction only at >= 2x the lowest pooled fee (stateless premium, no
//! clock state; honest traffic never touches it — see honest_burst below).
//!
//! All three tests are local policy only: height/acceptance untouched.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use stellereum::mempool::{Mempool, MempoolError};
use stellereum::sharding::Transaction;

fn key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

/// amount 100 + fee 1_000 => cost 1_100 per tx.
fn tx(sk: &SigningKey, fee: u64, nonce: u64) -> Transaction {
    Transaction::sign(sk, [1u8; 32], 100, fee, nonce, 1, 1)
}

const TX_COST: u64 = 100 + 1_000;

#[test]
fn squat_256_with_one_funding_is_refused() {
    // One funding covering exactly 2 txs must not back 256 per-sender slots.
    let sk = key();
    let me = sk.verifying_key().to_bytes();
    let mut mp = Mempool::new(1024, 256);
    let balance = 2 * TX_COST;

    let h0 = mp.add_checked(tx(&sk, 1_000, 0), balance).expect("tx0 fits");
    let h1 = mp.add_checked(tx(&sk, 1_000, 1), balance).expect("tx1 fits");
    assert_eq!(mp.reserved_for(&me), balance, "both txs fully reserved");

    // Slot 3 and every slot after: fail closed, never silently admitted.
    for n in 2..256u64 {
        assert_eq!(
            mp.add_checked(tx(&sk, 1_000, n), balance),
            Err(MempoolError::InsufficientBalance),
            "nonce {n} must be refused: funding exhausted"
        );
    }
    assert_eq!(mp.len(), 2, "exactly the 2 affordable txs are pooled");
    assert!(mp.contains(&h0) && mp.contains(&h1));

    // Reservation is claim-backed, not a leak: freeing a slot re-opens it.
    mp.remove(&h0);
    assert_eq!(mp.reserved_for(&me), TX_COST);
    mp.add_checked(tx(&sk, 1_000, 2), balance)
        .expect("freed funds must be re-admittable");
    assert_eq!(mp.len(), 2);
}

#[test]
fn full_pool_churn_costs_2x_or_more() {
    // Pool of 4 honest txs at fee 100 (total honest spend 400 + amounts).
    let mut mp = Mempool::new(4, 100);
    for _ in 0..4u64 {
        let k = key();
        mp.add_checked(Transaction::sign(&k, [1u8; 32], 10, 100, 0, 1, 1), 1_000_000)
            .unwrap();
    }
    assert_eq!(mp.len(), 4);

    let attacker = key();
    let rich = 1_000_000u64;
    // fee+1 (the old churn price) no longer displaces anything...
    assert_eq!(
        mp.add_checked(Transaction::sign(&attacker, [2u8; 32], 10, 101, 0, 1, 1), rich),
        Err(MempoolError::Full)
    );
    // ...nor does anything below 2x the floor (199 < 2*100)...
    assert_eq!(
        mp.add_checked(Transaction::sign(&attacker, [2u8; 32], 10, 199, 0, 1, 1), rich),
        Err(MempoolError::Full)
    );
    assert_eq!(mp.len(), 4, "pool untouched by sub-2x bids");

    // ...but exactly 2x evicts. Replacing the whole pool costs 4x200 = 800 in
    // fees alone vs the honest 4x100 = 400: churn costs 2x+.
    let mut attacker_fees = 0u64;
    for n in 0..4u64 {
        mp.add_checked(Transaction::sign(&attacker, [2u8; 32], 10, 200, n, 1, 1), rich)
            .unwrap_or_else(|e| panic!("2x bid at step {n} must evict: {e:?}"));
        attacker_fees += 200;
    }
    assert_eq!(mp.len(), 4);
    let honest_fees = 4 * 100u64;
    assert!(
        attacker_fees >= 2 * honest_fees,
        "churn must cost 2x+: attacker {attacker_fees} vs honest {honest_fees}"
    );
    let min_fee: u64 = mp.all().iter().map(|t| t.gas_limit).min().unwrap();
    assert!(min_fee >= 200, "floor ratcheted to the 2x premium, got {min_fee}");
}

#[test]
fn honest_burst_is_unaffected() {
    // Normal traffic never hits either bound: a non-full pool admits every
    // floor-passing tx (no eviction gate runs), and funded per-sender bursts
    // within quota + balance admit in full.
    let mut mp = Mempool::new(1000, 256);

    // 10 honest senders x 20 sequential txs, fees at/near the floor.
    for _ in 0..10u64 {
        let kk = key();
        let balance = 20 * (100 + 1_002) + 50_000;
        for n in 0..20u64 {
            let fee = 1_000 + (n % 3); // small honest fee jitter
            mp.add_checked(Transaction::sign(&kk, [9u8; 32], 100, fee, n, 1, 1), balance)
                .unwrap_or_else(|e| panic!("honest burst tx n={n} refused: {e:?}"));
        }
    }
    assert_eq!(mp.len(), 200, "whole honest burst must be pooled");

    // One sender's 50-deep sequential burst within funding: all admitted.
    let solo = key();
    let solo_balance = 50 * TX_COST + 1_000;
    for n in 0..50u64 {
        mp.add_checked(tx(&solo, 1_000, n), solo_balance)
            .unwrap_or_else(|e| panic!("funded sequential nonce {n} refused: {e:?}"));
    }
    assert_eq!(mp.len(), 250);
}
