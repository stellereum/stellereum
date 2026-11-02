//! Parallel-intake parity: the §6.2 live path
//! (`Transaction::verify_signatures_batch_parallel`, now called by proposal
//! intake / timed attribution / adopt) returns byte-identical verdicts to
//! the serial `Transaction::verify_signatures_batch` it replaced.
//!
//! * `parallel_matches_serial_all_valid`: fixed all-valid plain fixtures at
//!   sizes straddling the 256-tx rayon chunk boundary (0, 1, 2, 20, 255,
//!   256, 257, 300, 428, 600) — every pair must be `(true, true)`.
//! * `parallel_matches_serial_mixed_shapes`: a fixed 300-tx block mixing
//!   plain, payload, chain-id-bound and sponsored transactions (every
//!   envelope branch the batch covers) — pair must be `(true, true)`.
//! * `parallel_matches_serial_corrupt`: single-byte signature corruptions at
//!   first/middle/last positions (sizes 20, 257, 428) plus an all-corrupt
//!   64-tx block — every pair must be `(false, false)`; one bad neighbor
//!   sinks the whole batch on BOTH paths.
//! * `pinned_intake_vectors`: pins the EXACT verdicts for a fixed 428-tx
//!   all-valid fixture and its one-corrupt variant. Any verdict divergence
//!   fails this test.

use ed25519_dalek::SigningKey;
use stellereum::sharding::Transaction;
use stellereum::svm::OpCode;
use stellereum::zkml::effective_chain_id;

const TO: [u8; 32] = [0x11u8; 32];
const GAS: u64 = 21_000;

fn det_key(i: u64) -> SigningKey {
    let mut seed = [0xA5u8; 32];
    seed[..8].copy_from_slice(&i.to_le_bytes());
    SigningKey::from_bytes(&seed)
}

fn plain_txs(n: usize, key_base: u64) -> Vec<Transaction> {
    (0..n as u64)
        .map(|i| Transaction::sign(&det_key(key_base + i), TO, 1_000, GAS, 0, 0, 0))
        .collect()
}

/// 300-tx block cycling the envelope branches the batch covers: plain,
/// SVM payload, chain-id-bound, sponsored (sponsor envelope + user sig).
fn mixed_shapes_txs(n: usize, key_base: u64) -> Vec<Transaction> {
    (0..n as u64)
        .map(|i| {
            let sk = det_key(key_base + i);
            match i % 4 {
                0 => Transaction::sign(&sk, TO, 1_000, GAS, 0, 0, 0),
                1 => Transaction::sign_with_payload(
                    &sk,
                    TO,
                    1_000,
                    GAS,
                    0,
                    0,
                    0,
                    vec![OpCode::Transfer {
                        recipient: TO,
                        amount: 1,
                    }],
                ),
                2 => Transaction::sign_with_payload_and_chain_id(
                    &sk,
                    TO,
                    1_000,
                    GAS,
                    0,
                    0,
                    0,
                    Vec::new(),
                    effective_chain_id(),
                ),
                _ => Transaction::sign_with_sponsor(
                    &sk,
                    &det_key(key_base + 1_000_000 + i),
                    TO,
                    1_000,
                    GAS,
                    0,
                    0,
                    0,
                    Vec::new(),
                    0,
                    1_000_000,
                    u64::MAX,
                    Vec::new(),
                    effective_chain_id(),
                ),
            }
        })
        .collect()
}

fn corrupt_first_sig_byte(txs: &mut [Transaction], idx: usize) {
    let sig = &mut txs[idx].signature;
    assert!(!sig.is_empty(), "fixture tx must carry a signature");
    sig[0] ^= 0xFF;
}

#[test]
fn parallel_matches_serial_all_valid() {
    for (n, base) in [
        (0usize, 10_000u64),
        (1, 10_001),
        (2, 10_002),
        (20, 10_003),
        (255, 10_004),
        (256, 10_005),
        (257, 10_006),
        (300, 10_007),
        (428, 10_008),
        (600, 10_009),
    ] {
        let txs = plain_txs(n, base);
        let serial = Transaction::verify_signatures_batch(&txs);
        let parallel = Transaction::verify_signatures_batch_parallel(&txs);
        assert!(serial, "serial must accept all-valid fixture n={n}");
        assert_eq!(
            serial, parallel,
            "verdict divergence on all-valid fixture n={n}"
        );
    }
}

#[test]
fn parallel_matches_serial_mixed_shapes() {
    let txs = mixed_shapes_txs(300, 20_000);
    let serial = Transaction::verify_signatures_batch(&txs);
    let parallel = Transaction::verify_signatures_batch_parallel(&txs);
    assert!(serial, "serial must accept the mixed-shapes fixture");
    assert_eq!(
        serial, parallel,
        "verdict divergence on mixed-shapes fixture"
    );
}

#[test]
fn parallel_matches_serial_corrupt() {
    for (n, base, positions) in [
        (20usize, 30_000u64, vec![0usize, 10, 19]),
        (257usize, 31_000u64, vec![0usize, 128, 256]),
        (428usize, 32_000u64, vec![0usize, 214, 427]),
    ] {
        for pos in positions {
            let mut txs = plain_txs(n, base);
            corrupt_first_sig_byte(&mut txs, pos);
            let serial = Transaction::verify_signatures_batch(&txs);
            let parallel = Transaction::verify_signatures_batch_parallel(&txs);
            assert!(!serial, "serial must reject corrupt@n={n}[{pos}]");
            assert_eq!(
                serial, parallel,
                "verdict divergence on corrupt@n={n}[{pos}]"
            );
        }
    }
    // All-corrupt block: every neighbor bad, batch still fails closed both ways.
    let mut txs = plain_txs(64, 33_000);
    for i in 0..txs.len() {
        corrupt_first_sig_byte(&mut txs, i);
    }
    assert!(!Transaction::verify_signatures_batch(&txs));
    assert!(!Transaction::verify_signatures_batch_parallel(&txs));
}

#[test]
fn pinned_intake_vectors() {
    // Fixed 428-tx all-valid recipe block: both paths accept.
    let txs = plain_txs(428, 500_000);
    assert_eq!(
        (
            Transaction::verify_signatures_batch(&txs),
            Transaction::verify_signatures_batch_parallel(&txs)
        ),
        (true, true),
        "pinned all-valid 428-tx verdicts",
    );
    // Same bytes with one corrupt signature (middle): both paths refuse.
    let mut bad = plain_txs(428, 500_000);
    corrupt_first_sig_byte(&mut bad, 214);
    assert_eq!(
        (
            Transaction::verify_signatures_batch(&bad),
            Transaction::verify_signatures_batch_parallel(&bad)
        ),
        (false, false),
        "pinned one-corrupt 428-tx verdicts",
    );
}
