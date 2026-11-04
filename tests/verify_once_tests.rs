//! Verify-once signature attestation (PERF_PROFILE §6.1).
//!
//! Pins the intake → apply carry: a signature verified at mempool admission
//! is attested so block apply skips re-verifying the EXACT same bytes under
//! the EXACT same chain context. Any divergence — mutated bytes, different
//! chain context — forces full re-verification, fail-closed.
//!
//! * happy path: admission-attested bytes apply with a cache hit and zero
//!   misses (crypto skipped), reaching the identical verdict as full verify;
//! * mutated bytes (amount or signature bit): attestation misses and apply
//!   refuses, exactly like an unattested forgery;
//! * cross-context replay (same bytes, different chain): attestation misses
//!   under the foreign chain and apply refuses via the chain-id check.
//!
//! The cache is process-global, so the three tests serialize on `TEST_LOCK`
//! and use distinct keys/nonces per test; stats are asserted as deltas.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use stellereum::consensus::consensus_chain_id;
use stellereum::mempool::Mempool;
use stellereum::sharding::Transaction;
use stellereum::state_engine::{
    record_verified_signature, verified_signature_covers, verify_once_clear,
    verify_once_reset_stats, verify_once_stats, InMemoryStateEngine,
};

static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const FUND: u64 = 100_000_000;
const TS: u64 = 1_700_000_000;

async fn funded_engine(chain: u64, addr: &[u8; 32]) -> InMemoryStateEngine {
    let engine = InMemoryStateEngine::new().with_chain_id(chain);
    engine.credit_native(addr, FUND).await.unwrap();
    engine
}

#[tokio::test]
async fn verify_once_happy_path_skips_second_verify() {
    let _guard = TEST_LOCK.lock().await;
    verify_once_clear();
    verify_once_reset_stats();

    let chain = consensus_chain_id();
    let sk = SigningKey::generate(&mut OsRng);
    let from = sk.verifying_key().to_bytes();
    let tx = Transaction::sign(&sk, [0x77u8; 32], 1_000, 50_000, 0, 1, 1);
    assert!(tx.verify_signature(), "fixture must verify");

    // Mempool admission verifies and attests (the intake half of verify-once).
    let mut mp = Mempool::new(100, 100);
    mp.add_checked(tx.clone(), FUND)
        .expect("funded valid tx admits");
    assert!(
        verified_signature_covers(&tx, chain),
        "admission must attest the exact bytes"
    );

    // Apply with the attestation: identical verdict, crypto skipped.
    verify_once_reset_stats();
    let engine = funded_engine(chain, &from).await;
    let (applied, failed, _, status, _) = engine
        .apply_block_parallel_fees(std::slice::from_ref(&tx), TS)
        .await;
    assert_eq!((applied, failed), (1, 0));
    assert_eq!(status.as_slice(), &[true]);
    let (hits, misses, _) = verify_once_stats();
    assert!(hits >= 1, "attested apply must skip crypto (hits={hits})");
    assert_eq!(misses, 0, "attested apply must not re-verify");

    // Same bytes with NO attestation: full verification, identical verdict.
    verify_once_clear();
    verify_once_reset_stats();
    let engine2 = funded_engine(chain, &from).await;
    let (applied2, failed2, _, status2, _) = engine2
        .apply_block_parallel_fees(std::slice::from_ref(&tx), TS)
        .await;
    assert_eq!((applied2, failed2), (1, 0));
    assert_eq!(status2.as_slice(), &[true]);
    let (hits2, misses2, _) = verify_once_stats();
    assert_eq!(hits2, 0, "unattested apply must not hit");
    assert!(misses2 >= 1, "unattested apply must fully verify");
}

#[tokio::test]
async fn verify_once_mutated_bytes_force_reverify_and_refuse() {
    let _guard = TEST_LOCK.lock().await;
    verify_once_clear();
    verify_once_reset_stats();

    let chain = consensus_chain_id();
    let sk = SigningKey::generate(&mut OsRng);
    let from = sk.verifying_key().to_bytes();
    let tx = Transaction::sign(&sk, [0x78u8; 32], 1_000, 50_000, 0, 1, 1);
    assert!(tx.verify_signature(), "fixture must verify");
    record_verified_signature(&tx, chain);
    assert!(verified_signature_covers(&tx, chain));

    // Mutated amount: the signature no longer matches AND the attestation
    // no longer covers (message preimage changed) — full re-verify, refuse.
    let mut bad_amount = tx.clone();
    bad_amount.amount = bad_amount.amount.wrapping_add(1);
    assert!(!bad_amount.verify_signature(), "mutated tx must not verify");
    assert!(
        !verified_signature_covers(&bad_amount, chain),
        "amount mutation must miss the attestation"
    );
    verify_once_reset_stats();
    let engine = funded_engine(chain, &from).await;
    let (applied, failed, _, status, _) = engine
        .apply_block_parallel_fees(std::slice::from_ref(&bad_amount), TS)
        .await;
    assert_eq!((applied, failed), (0, 1), "mutated amount must be refused");
    assert_eq!(status.as_slice(), &[false]);
    let (hits, misses, _) = verify_once_stats();
    assert_eq!(hits, 0, "forgery must never hit");
    assert!(misses >= 1, "forgery must force re-verification");

    // Mutated signature byte: same treatment.
    let mut bad_sig = tx.clone();
    bad_sig.signature[0] ^= 0xFF;
    assert!(!bad_sig.verify_signature(), "forged sig must not verify");
    assert!(
        !verified_signature_covers(&bad_sig, chain),
        "signature mutation must miss the attestation"
    );
    verify_once_reset_stats();
    let engine2 = funded_engine(chain, &from).await;
    let (applied2, failed2, _, status2, _) = engine2
        .apply_block_parallel_fees(std::slice::from_ref(&bad_sig), TS)
        .await;
    assert_eq!((applied2, failed2), (0, 1), "forged sig must be refused");
    assert_eq!(status2.as_slice(), &[false]);
    let (hits2, misses2, _) = verify_once_stats();
    assert_eq!(hits2, 0, "forgery must never hit");
    assert!(misses2 >= 1, "forgery must force re-verification");

    // Control: the original bytes still cover and still apply.
    assert!(verified_signature_covers(&tx, chain));
    verify_once_reset_stats();
    let engine3 = funded_engine(chain, &from).await;
    let (applied3, failed3, _, status3, _) = engine3
        .apply_block_parallel_fees(std::slice::from_ref(&tx), TS)
        .await;
    assert_eq!((applied3, failed3), (1, 0));
    assert_eq!(status3.as_slice(), &[true]);
    let (hits3, misses3, _) = verify_once_stats();
    assert!(hits3 >= 1);
    assert_eq!(misses3, 0);
}

#[tokio::test]
async fn verify_once_cross_context_replay_reverifies() {
    let _guard = TEST_LOCK.lock().await;
    verify_once_clear();
    verify_once_reset_stats();

    const CHAIN_A: u64 = 5757;
    const CHAIN_B: u64 = 9753;
    assert_ne!(CHAIN_A, CHAIN_B);

    let sk = SigningKey::generate(&mut OsRng);
    let from = sk.verifying_key().to_bytes();
    let tx = Transaction::sign_with_chain_id(&sk, [0x79u8; 32], 1_000, 50_000, 0, 1, 1, CHAIN_A);
    assert_eq!(tx.chain_id(), Some(CHAIN_A));
    assert!(tx.verify_signature(), "fixture must verify");

    // Attested on chain A only.
    record_verified_signature(&tx, CHAIN_A);
    assert!(verified_signature_covers(&tx, CHAIN_A));
    assert!(
        !verified_signature_covers(&tx, CHAIN_B),
        "same bytes under a different chain must miss"
    );

    // Replay of the SAME bytes on chain B: attestation misses (crypto
    // re-runs) and the chain-id domain check refuses — nothing applies.
    verify_once_reset_stats();
    let engine_b = funded_engine(CHAIN_B, &from).await;
    let (applied_b, failed_b, _, status_b, _) = engine_b
        .apply_block_parallel_fees(std::slice::from_ref(&tx), TS)
        .await;
    assert_eq!(
        (applied_b, failed_b),
        (0, 1),
        "foreign-chain replay must refuse"
    );
    assert_eq!(status_b.as_slice(), &[false]);
    let (hits_b, misses_b, _) = verify_once_stats();
    assert_eq!(hits_b, 0, "cross-chain replay must never hit");
    assert!(
        misses_b >= 1,
        "cross-chain replay must force re-verification"
    );

    // Control: the same bytes on the attested chain apply with a hit.
    verify_once_reset_stats();
    let engine_a = funded_engine(CHAIN_A, &from).await;
    let (applied_a, failed_a, _, status_a, _) = engine_a
        .apply_block_parallel_fees(std::slice::from_ref(&tx), TS)
        .await;
    assert_eq!((applied_a, failed_a), (1, 0));
    assert_eq!(status_a.as_slice(), &[true]);
    let (hits_a, misses_a, _) = verify_once_stats();
    assert!(hits_a >= 1, "home-chain apply must hit");
    assert_eq!(misses_a, 0, "home-chain apply must not re-verify");
}
