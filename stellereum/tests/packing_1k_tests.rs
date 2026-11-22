//! Packing-math pin for the 1k-TPS recipe: 1785 plain transfers fit 500M gas.
//!
//! COMPUTE, don't execute: this builds a synthetic pool and runs the real
//! producer selection (`select_for_block_multi`) — no engine, no apply, no
//! timing. If `GAS_BASIC_TRANSFER` or `MAX_BLOCK_GAS` ever change, the
//! asserted count (derived, not hardcoded) follows automatically, and this
//! test fails loudly instead of letting docs/PERF_1K.md rot.

use stellereum::mempool::Mempool;
use stellereum::post_quantum::{derive_pq_address, FalconKeypair, PqScheme, PqSignatureEnvelope};
use stellereum::runtime::{MAX_BLOCK_GAS, MAX_BLOCK_TXS};
use stellereum::sharding::Transaction;
use stellereum::svm::GAS_BASIC_TRANSFER;

const BAL: u64 = 1_000_000_000_000;
const RECIPIENT: [u8; 32] = [9u8; 32];

/// FULL-PQ plain transfer from sender `i`: an implicit Falcon-512 envelope
/// (key registered globally, so admission charges no activation surcharge).
///
/// One Falcon keypair is shared across the synthetic senders (the suite is
/// about GAS PACKING, not key distribution): distinct addresses come from
/// distinct registration salts, which is exactly what
/// `derive_pq_address(scheme, pk, salt)` supports. Signing is per-transaction
/// because the signing message commits to `from`.
fn pq_tx(i: u64, kp: &FalconKeypair) -> Transaction {
    let mut salt = [0u8; 16];
    salt[..8].copy_from_slice(&i.to_le_bytes());
    let from = derive_pq_address(PqScheme::Falcon512, &kp.public_key, &salt);
    Transaction::global_implicit_registry()
        .register(from, PqScheme::Falcon512, &kp.public_key, &salt)
        .expect("PQ test key must register");
    let mut tx = Transaction {
        from,
        to: RECIPIENT,
        amount: 1,
        gas_limit: GAS_BASIC_TRANSFER,
        nonce: 0,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg = tx.signing_message();
    let sig = kp.sign(&msg);
    tx.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig).encode();
    tx
}

#[test]
fn packing_plain_transfers_fit_max_gas() {
    // Derived, not hardcoded: 500_000_000 / 280_000 = 1785 (remainder 200k).
    let expect = (MAX_BLOCK_GAS / GAS_BASIC_TRANSFER) as usize;
    assert_eq!(expect, 1785, "recipe math assumes 1785 plain/block");
    assert_eq!(MAX_BLOCK_TXS, 10_000, "count cap must not bind before gas");

    // Oversupply the pool: 1800 distinct senders x nonce 0, every tx at the
    // cheapest real gas price, so selection stops on the GAS cap exactly.
    let kp = FalconKeypair::generate_from_seed(0xA5);
    let mut pool = Mempool::new(2048, 2048);
    for i in 0..1800u64 {
        let tx = pq_tx(310_000 + i, &kp);
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
