//! Packing-math pin for the 1k-TPS recipe: 1785 plain transfers fit 500M gas.
//!
//! COMPUTE, don't execute: this builds a synthetic pool and runs the real
//! producer selection (`select_for_block_multi`) — no engine, no apply, no
//! timing. If `GAS_BASIC_TRANSFER` or `MAX_BLOCK_GAS` ever change, the
//! asserted count (derived, not hardcoded) follows automatically, and this
//! test fails loudly instead of letting docs/PERF_1K.md rot.

use ed25519_dalek::SigningKey;
use stellereum::mempool::Mempool;
use stellereum::runtime::{MAX_BLOCK_GAS, MAX_BLOCK_TXS};
use stellereum::sharding::Transaction;
use stellereum::svm::GAS_BASIC_TRANSFER;

const BAL: u64 = 1_000_000_000_000;
const RECIPIENT: [u8; 32] = [9u8; 32];

fn det_key(i: u64) -> SigningKey {
    let mut seed = [0xA5u8; 32];
    seed[..8].copy_from_slice(&i.to_le_bytes());
    SigningKey::from_bytes(&seed)
}

#[test]
fn packing_plain_transfers_fit_max_gas() {
    // Derived, not hardcoded: 500_000_000 / 280_000 = 1785 (remainder 200k).
    let expect = (MAX_BLOCK_GAS / GAS_BASIC_TRANSFER) as usize;
    assert_eq!(expect, 1785, "recipe math assumes 1785 plain/block");
    assert_eq!(MAX_BLOCK_TXS, 10_000, "count cap must not bind before gas");

    // Oversupply the pool: 1800 distinct senders x nonce 0, every tx at the
    // cheapest real gas price, so selection stops on the GAS cap exactly.
    let mut pool = Mempool::new(2048, 2048);
    for i in 0..1800u64 {
        let sk = det_key(310_000 + i);
        let tx = Transaction::sign(&sk, RECIPIENT, 1, GAS_BASIC_TRANSFER, 0, 1, 1);
        pool.add_checked(tx, BAL)
            .expect("funded admission must succeed");
    }
    assert_eq!(pool.len(), 1800);

    let sel = pool.select_for_block_multi(MAX_BLOCK_TXS, MAX_BLOCK_GAS, |_| true);
    assert_eq!(
        sel.len(),
        expect,
        "gas cap must pack exactly {expect} plain txs"
    );

    // The 429th genuinely does not fit: packed gas is within one tx of full.
    let gas: u64 = sel.iter().map(|t| t.gas_limit).sum();
    assert!(gas <= MAX_BLOCK_GAS, "packed gas must respect the cap");
    assert!(
        gas.saturating_add(GAS_BASIC_TRANSFER) > MAX_BLOCK_GAS,
        "one more plain tx must NOT fit (gas={gas}, cap={MAX_BLOCK_GAS})"
    );
}
