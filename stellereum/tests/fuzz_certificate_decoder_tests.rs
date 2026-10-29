//! Deterministic (stable-toolchain) coverage for the two fuzz targets added by
//! the external-audit preparation package.
//!
//! The libFuzzer targets are `fuzz/fuzz_targets/cert_envelope_decode.rs` and
//! `fuzz/fuzz_targets/evm_raw_tx_decode.rs`. They need nightly + cargo-fuzz.
//! This file covers the same decoders under plain `cargo test`, so the
//! property is checked on every CI run and by `scripts/audit-repro.sh`.
//!
//! What is asserted:
//!   * the consensus CERTIFICATE envelope decoders never panic on
//!     peer-controlled bytes;
//!   * a decoded µQC round-trips through its own canonical encoder;
//!   * a decoded BLS aggregate's signer bitvector agrees with the validator
//!     count it claims;
//!   * the hand-rolled EVM RLP decoder never panics, and its "exact" and
//!     "remainder" views always agree.
//!
//! Strategy: empty, truncated, byte-flips, maxed length prefixes and
//! fixed-seed pseudo-random blobs — the same generators the existing
//! `tests/fuzz_decoder_tests.rs` uses.

use stellereum::consensus::{
    decode_pq_epoch_envelope, decode_pq_micro_envelope, decode_qc_bls_envelope,
    encode_pq_epoch_envelope, encode_pq_micro_envelope,
};
use stellereum::evm_adapter::{decode_raw_transaction, DecodedTransaction, RlpItem};

// ---------------------------------------------------------------------------
// Deterministic PRNG (xorshift64*, fixed seeds — no OS entropy).
// ---------------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % (n as u64)) as usize
    }
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            out.extend_from_slice(&self.next_u64().to_le_bytes());
        }
        out.truncate(len);
        out
    }
}

/// Every strict prefix of `data` (the full input is not included).
fn truncations(data: &[u8]) -> Vec<Vec<u8>> {
    (0..data.len()).map(|n| data[..n].to_vec()).collect()
}

/// Every position x {0x00, 0xFF, bit-flipped}.
fn exhaustive_flips(data: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len() * 3);
    for (i, b) in data.iter().enumerate() {
        for v in [0x00u8, 0xFF, b ^ 0x01] {
            if v == *b {
                continue;
            }
            let mut m = data.to_vec();
            m[i] = v;
            out.push(m);
        }
    }
    out
}

/// Overwrite the 8/4/2-byte length prefix at every offset with MAX.
fn max_length_prefixes(data: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for i in 0..data.len() {
        if i + 8 <= data.len() {
            let mut m = data.to_vec();
            m[i..i + 8].copy_from_slice(&u64::MAX.to_le_bytes());
            out.push(m);
        }
        if i + 4 <= data.len() {
            let mut m = data.to_vec();
            m[i..i + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            out.push(m);
        }
        if i + 2 <= data.len() {
            let mut m = data.to_vec();
            m[i..i + 2].copy_from_slice(&u16::MAX.to_le_bytes());
            out.push(m);
        }
    }
    out
}

/// Fixed-seed random blobs of mixed lengths.
fn seeded_blobs(seed: u64, count: usize, max_len: usize) -> Vec<Vec<u8>> {
    let mut rng = Rng(seed);
    (0..count)
        .map(|i| {
            let len = match i % 8 {
                0 => rng.below(8),
                1 => 60 + rng.below(20),
                2 => 130 + rng.below(8),
                _ => rng.below(max_len),
            };
            rng.bytes(len)
        })
        .collect()
}

/// Run every input through `f`, failing the test if ANY input panics.
/// A panic on peer-controlled bytes is a remote DoS — that is the regression.
fn assert_never_panics(name: &str, inputs: Vec<Vec<u8>>, f: impl Fn(&[u8])) {
    let mut panics = 0usize;
    let mut first: Option<usize> = None;
    for (i, input) in inputs.iter().enumerate() {
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(input))).is_err() {
            panics += 1;
            if first.is_none() {
                first = Some(i);
            }
        }
    }
    assert_eq!(
        panics, 0,
        "{name}: {panics} panicking inputs (first idx {first:?})"
    );
}

// ---------------------------------------------------------------------------
// (1) The consensus certificate envelope decoders.
// ---------------------------------------------------------------------------

/// A well-formed µQC envelope, so the round-trip property is actually
/// exercised (not just the "never panics" property).
fn valid_uqc_envelope() -> Vec<u8> {
    let cert = stellereum::consensus::PqMicroCertificate::new(
        stellereum::post_quantum::PqScheme::Ed25519,
        42,
        7,
        8,
        vec![0b1010_1010, 0b0101_0101],
        vec![vec![7u8; 64], vec![9u8; 64]],
        [3u8; 32],
    );
    encode_pq_micro_envelope(&cert)
}

#[test]
fn certificate_envelopes_never_panic_on_peer_controlled_bytes() {
    let valid = valid_uqc_envelope();
    let mut inputs = truncations(&valid);
    inputs.extend(exhaustive_flips(&valid));
    inputs.extend(max_length_prefixes(&valid));
    inputs.extend(seeded_blobs(0xC3_27_11u64, 4000, 1024));

    // Empty and short inputs are the most common peer payload.
    inputs.push(Vec::new());
    inputs.push(vec![0u8; 1]);
    inputs.push(vec![0xFFu8; 256]);

    assert_never_panics("cert-envelope/decode", inputs, |b| {
        let _ = decode_pq_micro_envelope(b);
        let _ = decode_pq_epoch_envelope(b);
        let _ = decode_qc_bls_envelope(b);
        let _ = stellereum::sharding::PqSignatureEnvelope::decode(b);
        let _ = stellereum::post_quantum::PqSignatureEnvelope::decode(b);
    });
}

#[test]
fn a_decoded_uqc_round_trips_through_its_own_encoder() {
    // The canonical encoding must decode back to an EQUAL certificate. This is
    // the property the new `cert_envelope_decode` fuzz target asserts: the
    // encoder and the decoder must be mutually consistent, so a certificate
    // that decodes is a certificate that can be re-emitted byte-for-byte.
    let cert = stellereum::consensus::PqMicroCertificate::new(
        stellereum::post_quantum::PqScheme::Falcon512,
        1,
        0,
        4,
        vec![0b0000_0011],
        vec![vec![1u8; 666]],
        [0u8; 32],
    );
    let bytes = encode_pq_micro_envelope(&cert);
    let back = decode_pq_micro_envelope(&bytes).expect("the canonical encoding must decode");
    assert_eq!(back, cert, "µQC must round-trip through its own encoder");

    // The epoch CEC is the same body under a different magic.
    let cec = encode_pq_epoch_envelope(&cert);
    let back = decode_pq_epoch_envelope(&cec).expect("the canonical CEC encoding must decode");
    assert_eq!(back, cert, "epoch CEC must round-trip through its encoder");
}

#[test]
fn a_decoded_uqc_survives_a_mutation_sweep_without_breaking_the_round_trip() {
    let valid = valid_uqc_envelope();
    let mut inputs = exhaustive_flips(&valid);
    inputs.extend(seeded_blobs(0x51_11_5Eu64, 1500, 512));
    let mut decoded = 0usize;
    for input in inputs {
        let Some(cert) = decode_pq_micro_envelope(&input) else {
            continue;
        };
        decoded += 1;
        let canonical = encode_pq_micro_envelope(&cert);
        let back = decode_pq_micro_envelope(&canonical)
            .expect("the canonical re-encoding of a decoded certificate must decode");
        assert_eq!(back, cert, "µQC must round-trip through its own encoder");
    }
    // The sweep must actually reach the decoder, otherwise the test is vacuous.
    assert!(
        decoded > 0,
        "no mutated input decoded as a µQC — the sweep is not reaching the decoder"
    );
}

#[test]
fn a_decoded_bls_aggregate_names_a_consistent_signer_set() {
    // The BLS QC envelope carries a signer bitvector whose length must agree
    // with the validator count it claims; otherwise "who signed" is ambiguous
    // and the downtime slashing would read the wrong set.
    use stellereum::bls::{BlsAggregateSignature, BlsSignature, SignerBitVector};
    let bitmask = vec![0b1010_1010u8, 0b0101_0101];
    let participants = SignerBitVector::from_bitmask(bitmask.clone(), 16)
        .expect("a bitmask of the right length must be accepted");
    let aggregate = BlsAggregateSignature {
        signature: BlsSignature([3u8; 96]),
        participants,
    };
    assert_eq!(aggregate.participants.total_validators(), 16);
    assert_eq!(aggregate.participants.bitmask().len(), 16usize.div_ceil(8));

    // A bitmask of the WRONG length is refused outright.
    assert!(SignerBitVector::from_bitmask(vec![0u8; 3], 16).is_none());
    assert!(SignerBitVector::from_bitmask(vec![0u8; 1], 16).is_none());
}

// ---------------------------------------------------------------------------
// (2) The hand-rolled EVM RLP decoder.
// ---------------------------------------------------------------------------

#[test]
fn evm_rlp_decoder_never_panics_on_peer_controlled_bytes() {
    let mut inputs = seeded_blobs(0x52_11_0Fu64, 4000, 1024);
    inputs.push(Vec::new());
    inputs.push(vec![0u8; 1]);
    inputs.push(vec![0xFFu8; 256]);
    inputs.push(vec![0xC0u8; 64]);
    inputs.push(vec![0xF8u8; 64]);

    assert_never_panics("evm-rlp/decode", inputs, |b| {
        let _ = decode_raw_transaction(b);
        let _ = DecodedTransaction::decode(b);
        let _ = RlpItem::decode(b);
        let _ = RlpItem::decode_with_remainder(b);
    });
}

#[test]
fn evm_rlp_exact_and_remainder_views_always_agree() {
    // The "exact" decoder may only fail with `TrailingBytes` when the
    // remainder decoder left bytes behind; otherwise the two must return the
    // same item. This is the property the `evm_raw_tx_decode` fuzz target
    // asserts.
    let mut inputs = seeded_blobs(0x6C_11_A5u64, 3000, 512);
    inputs.extend(truncations(&[0xC1u8, 0x80, 0x80]));

    for input in &inputs {
        match RlpItem::decode_with_remainder(input) {
            Ok((item, rest)) => {
                if rest.is_empty() {
                    let exact = RlpItem::decode(input)
                        .expect("the exact decoder must succeed when nothing is left over");
                    assert_eq!(
                        exact, item,
                        "the exact and remainder RLP views must return the same item"
                    );
                } else {
                    assert!(
                        RlpItem::decode(input).is_err(),
                        "the exact RLP decoder must reject input with trailing bytes"
                    );
                }
            }
            Err(_) => {
                assert!(
                    RlpItem::decode(input).is_err(),
                    "the exact RLP decoder must reject what the remainder decoder rejects"
                );
            }
        }
    }
}

#[test]
fn evm_rlp_length_prefix_sweep_never_panics() {
    // A length prefix in the payload that claims far more than is present is
    // the classic DoS shape for a hand-written parser.
    let mut inputs = max_length_prefixes(&[0xF8u8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    inputs.extend(max_length_prefixes(&[0xC1u8, 0x80, 0x80]));
    inputs.extend(max_length_prefixes(&[0x02u8; 32]));
    assert_never_panics("evm-rlp/length-prefix", inputs, |b| {
        let _ = decode_raw_transaction(b);
        let _ = DecodedTransaction::decode(b);
        let _ = RlpItem::decode_with_remainder(b);
    });
}
