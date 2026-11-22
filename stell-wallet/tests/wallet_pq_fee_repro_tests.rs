//! Repro for live PQ pay rejection: explicit 325k tx must clear a 280k-base mempool.
use stellereum::mempool::{Mempool, PQ_ACTIVATION_SURCHARGE_GAS};
use stellereum::post_quantum::{
    derive_pq_address, FalconKeypair, PqScheme, PqSignatureEnvelope, DEFAULT_SALT,
};
use stellereum::sharding::Transaction;
use stellereum::svm::GAS_BASIC_TRANSFER;

#[test]
fn pq_explicit_325k_clears_280k_mempool() {
    let seed = [0x77u8; 32];
    let key = FalconKeypair::generate_from_seed_bytes(&seed);
    let from = derive_pq_address(PqScheme::Falcon512, key.public_key(), &DEFAULT_SALT);
    let to = [0x99u8; 32];
    let gas = GAS_BASIC_TRANSFER.saturating_add(PQ_ACTIVATION_SURCHARGE_GAS);
    assert_eq!(gas, 325_000);
    let mut tx = Transaction {
        from,
        to,
        amount: 1_000_000_000,
        gas_limit: gas,
        nonce: 0,
        source_shard: 0,
        target_shard: 0,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg = tx.signing_message();
    let sig = key.sign(&msg);
    tx.signature =
        PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, key.public_key().to_vec(), sig)
            .encode();
    assert!(tx.is_pq_activation(), "must be activation");
    assert!(tx.verify_signature(), "local sig verify must pass");
    let mut mp = Mempool::default().with_base_fee(GAS_BASIC_TRANSFER);
    let floor = mp.effective_floor_for_tx(&tx);
    eprintln!("floor={floor} gas={}", tx.gas_limit);
    assert_eq!(floor, 325_000);
    let res = mp.add_checked_ctx(
        tx,
        1_000_000_000_000,
        stellereum::mempool::AdmissionCtx::wall_now(),
    );
    assert!(res.is_ok(), "admission must accept: {:?}", res.err());
}
