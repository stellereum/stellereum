//! Fee-batching parity: the apply-FEE batched path charges byte-identical
//! fees to the live-read path.
//!
//! * `plain_block_matches_sequential singles` (differential, self-validating):
//!   an all-success plain-transfer block applied via
//!   `apply_block_parallel_fees` (the batched path under test) must agree
//!   EXACTLY with the same transactions applied one by one via
//!   `apply_transaction` (the untouched live-read path through
//!   `commit_native`): per-tx fees, fee total, status flags, and every
//!   account's final (balance, nonce). For empty-payload transfers both
//!   callers hand `commit_native` the declared `gas_limit`, so the numbers
//!   must coincide by construction.
//! * `mixed_fee_vectors_are_pinned`: a fixed mixed fixture (floor-binding
//!   success, above-floor success, admission refusal, attributable OOM
//!   failure, sponsored success, nonce-gap refusal) pins the EXACT
//!   `(status, tx_fees, fees_collected, balances, nonces)`. Any 1-wei
//!   divergence in the fee path fails this test.
//! * `mixed_fee_vectors_parallel_waves`: the same pinned vectors with
//!   parallel wave execution on (the `apply_plain_wave` path).

use ed25519_dalek::SigningKey;
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::{OpCode, GAS_BASIC_TRANSFER};
use stellereum::zkml::effective_chain_id;

mod support;
use support::{balance_of, nonce_of};

const TS: u64 = 1_760_000_000;
const BAL: u64 = 10_000_000;
const SPON_BAL: u64 = 10_000_000;
/// Governed consensus floor: above the 280k default transfer cost, so the
/// floor (not the operation price) is what binds.
const FLOOR: u64 = 500_000;
const RECIPIENT: [u8; 32] = [0xB0; 32];

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn addr_of(seed: u8) -> [u8; 32] {
    key(seed).verifying_key().to_bytes()
}

fn rt_block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime builds")
        .block_on(f)
}

async fn engine_with_floor(floor: u64) -> InMemoryStateEngine {
    let e = InMemoryStateEngine::new();
    e.governance_write().await.applied.min_gas_limit = Some(floor);
    e
}

fn oom_payload() -> Vec<OpCode> {
    vec![OpCode::Transfer {
        recipient: [0xCC; 32],
        amount: 1,
    }]
}

#[test]
fn plain_block_matches_sequential_singles() {
    rt_block_on(async {
        const N: usize = 64;
        let txs: Vec<Transaction> = (0..N as u64)
            .map(|i| {
                Transaction::sign(
                    &key((100 + i) as u8),
                    RECIPIENT,
                    1,
                    GAS_BASIC_TRANSFER,
                    0,
                    1,
                    1,
                )
            })
            .collect();

        // Block path (batched fee inputs).
        let block_engine = engine_with_floor(FLOOR).await;
        for i in 0..N as u64 {
            block_engine
                .update_account(AccountState::new(addr_of((100 + i) as u8), BAL))
                .await;
        }
        block_engine
            .update_account(AccountState::new(RECIPIENT, 0))
            .await;
        let (applied, failed, block_fees_collected, block_status, block_fees) =
            block_engine.apply_block_parallel_fees(&txs, TS).await;
        assert_eq!((applied, failed), (N, 0));

        // Sequential single-tx path (untouched live-read fee inputs).
        let seq_engine = engine_with_floor(FLOOR).await;
        for i in 0..N as u64 {
            seq_engine
                .update_account(AccountState::new(addr_of((100 + i) as u8), BAL))
                .await;
        }
        seq_engine
            .update_account(AccountState::new(RECIPIENT, 0))
            .await;
        let mut seq_ok = 0usize;
        for tx in &txs {
            seq_engine
                .apply_transaction(tx, TS)
                .await
                .expect("plain funded transfer must apply");
            seq_ok += 1;
        }
        assert_eq!(seq_ok, N);

        // Same verdicts.
        assert_eq!(block_status, vec![true; N]);
        // Same per-tx fees: derived from the OLD path's state (balance delta),
        // never from an analytic formula.
        let mut seq_fees = Vec::with_capacity(N);
        let mut seq_collected = 0u64;
        for i in 0..N as u64 {
            let addr = addr_of((100 + i) as u8);
            let bal = balance_of(&seq_engine, &addr).await;
            let fee = BAL - 1 - bal;
            seq_fees.push(fee);
            seq_collected += fee;
            // Nonce advanced exactly once on both paths.
            assert_eq!(nonce_of(&seq_engine, &addr).await, 1);
            assert_eq!(nonce_of(&block_engine, &addr).await, 1);
            assert_eq!(balance_of(&block_engine, &addr).await, bal);
        }
        assert_eq!(block_fees, seq_fees);
        assert_eq!(block_fees_collected, seq_collected);
        // Floor binds: every tx pays the governed floor, not the declared gas.
        assert!(seq_fees.iter().all(|&f| f == FLOOR));
        assert_eq!(seq_collected, N as u64 * FLOOR);
        assert_eq!(
            balance_of(&block_engine, &RECIPIENT).await,
            balance_of(&seq_engine, &RECIPIENT).await
        );
    });
}

/// The fixed mixed fixture: (status, fee) intent per row.
/// 0: plain success, declared gas below the floor -> fee = FLOOR.
/// 1: plain success, declared gas above the floor -> fee = declared.
/// 2: plain, covers amount+declared but NOT amount+floor -> admission
///    refusal: failed, fee 0, no state change.
/// 3: OOM payload, funded -> attributable failure: fee = FLOOR (the floor
///    binds the failure fee too), nonce consumed.
/// 4: sponsored plain success -> fee = FLOOR debited from the SPONSOR, user
///    pays value only, user nonce advances, sponsor nonce untouched.
/// 5: nonce gap -> refusal: failed, fee 0, no state change.
fn mixed_fixture() -> (Vec<Transaction>, [u8; 32], [u8; 32]) {
    let user = addr_of(15);
    let sponsor = addr_of(16);
    let txs = vec![
        Transaction::sign(&key(11), RECIPIENT, 1, GAS_BASIC_TRANSFER, 0, 1, 1),
        Transaction::sign(&key(12), RECIPIENT, 2, 600_000, 0, 1, 1),
        Transaction::sign(&key(13), RECIPIENT, BAL - 50, 100, 0, 1, 1),
        Transaction::sign_with_payload(&key(14), RECIPIENT, 1, 100, 0, 1, 1, oom_payload()),
        Transaction::sign_with_sponsor(
            &key(15),
            &key(16),
            RECIPIENT,
            7,
            GAS_BASIC_TRANSFER,
            0,
            1,
            1,
            Vec::new(),
            0,
            1_000_000,
            u64::MAX,
            Vec::new(),
            effective_chain_id(),
        ),
        Transaction::sign(&key(17), RECIPIENT, 1, GAS_BASIC_TRANSFER, 5, 1, 1),
    ];
    (txs, user, sponsor)
}

async fn funded_mixed_engine(parallel: bool) -> InMemoryStateEngine {
    let e = engine_with_floor(FLOOR).await;
    e.set_parallel_exec(parallel);
    for seed in [11u8, 12, 14, 15, 17] {
        e.update_account(AccountState::new(addr_of(seed), BAL)).await;
    }
    // s2 covers amount+declared but not amount+floor.
    e.update_account(AccountState::new(addr_of(13), BAL)).await;
    e.update_account(AccountState::new(addr_of(16), SPON_BAL)).await;
    e.update_account(AccountState::new(RECIPIENT, 0)).await;
    e
}

#[test]
fn mixed_fee_vectors_are_pinned() {
    rt_block_on(async {
        let (txs, _user, _sponsor) = mixed_fixture();
        let e = funded_mixed_engine(false).await;
        let (applied, failed, fees_collected, status, fees) =
            e.apply_block_parallel_fees(&txs, TS).await;
        // Pinned fee vectors (captured from the pre-optimization run —
        // byte-identical balances/fees are the gate: 1 wei of divergence
        // fails this test).
        assert_eq!((applied, failed), (3, 3));
        assert_eq!(status, vec![true, true, false, false, true, false]);
        assert_eq!(fees, vec![500_000, 600_000, 0, 500_000, 500_000, 0]);
        assert_eq!(fees_collected, 2_100_000);
        let pinned: [([u8; 32], u64, u64); 8] = [
            (addr_of(11), 9_499_999, 1),
            (addr_of(12), 9_399_998, 1),
            (addr_of(13), BAL, 0),
            (addr_of(14), 9_500_000, 1),
            (addr_of(15), 9_999_993, 1),
            (addr_of(16), 9_500_000, 0),
            (addr_of(17), BAL, 0),
            (RECIPIENT, 10, 0),
        ];
        for (addr, bal, nonce) in pinned {
            assert_eq!(balance_of(&e, &addr).await, bal, "bal {addr:?}");
            assert_eq!(nonce_of(&e, &addr).await, nonce, "nonce {addr:?}");
        }
    });
}

#[test]
fn mixed_fee_vectors_parallel_waves() {
    rt_block_on(async {
        let (txs, _user, _sponsor) = mixed_fixture();
        let e_seq = funded_mixed_engine(false).await;
        let seq = e_seq.apply_block_parallel_fees(&txs, TS).await;
        let e_par = funded_mixed_engine(true).await;
        let par = e_par.apply_block_parallel_fees(&txs, TS).await;
        assert_eq!((seq.0, seq.1, seq.2, seq.3, seq.4), (par.0, par.1, par.2, par.3, par.4));
        for seed in [11u8, 12, 13, 14, 15, 16, 17] {
            let addr = addr_of(seed);
            assert_eq!(
                balance_of(&e_seq, &addr).await,
                balance_of(&e_par, &addr).await,
                "seed {seed}"
            );
            assert_eq!(
                nonce_of(&e_seq, &addr).await,
                nonce_of(&e_par, &addr).await,
                "seed {seed}"
            );
        }
    });
}
