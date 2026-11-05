//! Security tests for chain (fork-choice/tree) and mempool hardening.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use stellereum::chain::ChainManager;
use stellereum::mempool::{Mempool, MempoolError};
use stellereum::post_quantum::{derive_pq_address, PqScheme, PqSignatureEnvelope, DEFAULT_SALT};
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};

fn sk() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

fn block(height: u64, prev: [u8; 32], tag: u8, signer: &SigningKey) -> Block {
    let mut b = Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash: prev,
        state_root: [tag; 32],
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: height,
        proposer: signer.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    b.sign_block(signer);
    b
}

/// A block with NO signature must be rejected by validated insertion.
#[test]
fn unsigned_block_rejected() {
    let signer = sk();
    let mut cm = ChainManager::new(block(0, [0u8; 32], 0, &signer));
    let g = cm.best_head();

    let mut unsigned = block(1, g, 1, &signer);
    unsigned.validator_signatures.clear(); // strip signature
    assert!(
        cm.insert_validated(unsigned).is_err(),
        "unsigned block must be rejected"
    );
}

/// A block with a tampered proposer signature must be rejected.
#[test]
fn tampered_block_signature_rejected() {
    let signer = sk();
    let mut cm = ChainManager::new(block(0, [0u8; 32], 0, &signer));
    let g = cm.best_head();

    let mut b = block(1, g, 1, &signer);
    // tamper the block (changes the hash) after signing
    b.timestamp = 999;
    assert!(
        cm.insert_validated(b).is_err(),
        "tampered block must be rejected"
    );
}

/// A block whose parent is unknown (orphan) must be rejected.
#[test]
fn orphan_block_rejected() {
    let signer = sk();
    let mut cm = ChainManager::new(block(0, [0u8; 32], 0, &signer));
    let orphan = block(5, [0xEE; 32], 5, &signer);
    assert!(
        cm.insert_validated(orphan).is_err(),
        "orphan must be rejected"
    );
}

/// A block skipping a height must be rejected.
#[test]
fn height_gap_block_rejected() {
    let signer = sk();
    let mut cm = ChainManager::new(block(0, [0u8; 32], 0, &signer));
    let g = cm.best_head();
    let skip = block(3, g, 3, &signer);
    assert!(
        cm.insert_validated(skip).is_err(),
        "height gap must be rejected"
    );
}

// ============================================================================
// MEMPOOL
// ============================================================================

fn tx(seed: &u8, fee: u64, nonce: u64) -> Transaction {
    // FULL-PQ: implicit Falcon-512 (registered globally; no surcharge), so
    // fee/quota assertions match the old classical fixtures exactly.
    let pk = Transaction::sample_falcon512_pubkey(*seed);
    let from = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);
    Transaction::global_implicit_registry()
        .register(from, PqScheme::Falcon512, &pk, &DEFAULT_SALT)
        .expect("PQ test key must register");
    let mut t = Transaction {
        from,
        to: [1u8; 32],
        amount: 10,
        gas_limit: fee,
        nonce,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg = t.signing_message();
    let sig = Transaction::create_falcon512_test_signature(&pk, &msg, *seed);
    t.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig).encode();
    t
}

/// select_filtered skips txs that fail the acceptance predicate (e.g. bad nonce).
#[test]
fn select_filtered_skips_rejected_txs() {
    let k = 0xA1u8;
    let mut mp = Mempool::new(100, 100);
    mp.add(tx(&k, 100, 0)).unwrap(); // highest fee but we will reject nonce 0
    mp.add(tx(&k, 50, 1)).unwrap();
    mp.add(tx(&k, 10, 2)).unwrap();

    // Accept only nonce >= 1 (simulating "expected nonce is 1")
    let picked = mp.select_filtered(10, |t| t.nonce >= 1);
    assert_eq!(picked.len(), 2);
    assert!(
        picked.iter().all(|t| t.nonce >= 1),
        "invalid-nonce txs must be skipped"
    );
    assert_eq!(picked[0].gas_limit, 50, "still fee-ordered among accepted");
}

/// A flood of bad-signature txs is fully rejected (no mempool pollution).
#[test]
fn bad_signature_flood_rejected() {
    let k = 0xA2u8;
    let mut mp = Mempool::new(100, 100);
    for i in 0..50 {
        let mut t = tx(&k, 100, i);
        t.amount = 999_999; // tamper
        assert_eq!(mp.add(t), Err(MempoolError::BadSignature));
    }
    assert!(mp.is_empty(), "no bad tx may enter the mempool");
}

/// Per-sender quota prevents one key from filling the whole mempool.
#[test]
fn per_sender_quota_prevents_single_key_flood() {
    let k = 0xA3u8;
    let mut mp = Mempool::new(10_000, 5);
    for n in 0..5 {
        mp.add(tx(&k, 10, n)).unwrap();
    }
    assert_eq!(mp.add(tx(&k, 10, 5)), Err(MempoolError::TooManyFromSender));
    assert_eq!(mp.len(), 5, "only the quota may enter");
}

/// High-fee txs are preferred and displace low-fee ones under pressure.
#[test]
fn fee_priority_displaces_low_fee() {
    let k = 0xA4u8;
    let mut mp = Mempool::new(3, 100);
    let bal = 1_000_000;
    for n in 0..3 {
        mp.add_checked(tx(&k, 10, n), bal).unwrap();
    }
    let low_hashes: Vec<[u8; 32]> = mp.hashes();
    // a much higher-fee tx enters, evicting the lowest
    mp.add_checked(tx(&k, 1000, 99), bal).unwrap();
    assert_eq!(mp.len(), 3);
    // the evicted hash is one of the original low-fee ones
    let remaining = mp.hashes();
    assert!(
        low_hashes.iter().any(|h| !remaining.contains(h)),
        "a low-fee tx must be evicted"
    );
}
