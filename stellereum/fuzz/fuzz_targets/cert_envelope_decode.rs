// Fuzz target: consensus CERTIFICATE envelope decoders.
//
// These are the raw-byte (NOT bincode) decoders that carry the fast-finality
// proof and the post-quantum signature framing:
//
//   * `consensus::decode_pq_micro_envelope`  - the µQC (post-quantum
//     micro-certificate) wire envelope, `QC_UQC_MAGIC || ...`.
//   * `consensus::decode_pq_epoch_envelope`  - the epoch CEC envelope, the
//     same body under `QC_PQ_MAGIC`.
//   * `consensus::decode_qc_bls_envelope`    - the BLS12-381 aggregate
//     certificate envelope, `QC_BLS_MAGIC || ...`.
//   * `sharding::PqSignatureEnvelope::decode`      - the consensus tx
//     signature envelope (salt + chain-id framing).
//   * `post_quantum::PqSignatureEnvelope::decode`  - the strict, salt-free
//     envelope variant.
//
// WHY THIS TARGET EXISTS (audit-prep gap, 2026-10):
// the pre-existing corpus covers the `bincode` decoders (`ConsensusMsg`,
// `Block`, `Transaction`, the infnode `Frame`), but the certificate
// envelopes above are parsed by HAND, byte by byte, from bytes a remote peer
// controls. They were NOT in the fuzz corpus at all, and they are exactly
// where a length-prefix or bitmask off-by-one turns into an accepted
// under-powered certificate.
//
// WHAT IT ASSERTS:
//   1. no decoder PANICS on peer-controlled bytes (a panic here is a remote
//      DoS in the node's message handler);
//   2. a µQC that decodes must round-trip through its own canonical encoder
//      to an EQUAL certificate (the encoder/decoder pair must be mutually
//      consistent);
//   3. a BLS aggregate that decodes must name a signer bitvector whose length
//      matches the validator count it claims (otherwise the "who signed"
//      set would be ambiguous).
//
// Run: cargo +nightly fuzz run cert_envelope_decode
// Stable fallback: cargo test --test fuzz_decoder_tests cert_
#![no_main]
#[cfg(feature = "libfuzzer")]
use libfuzzer_sys::fuzz_target;

#[cfg(feature = "libfuzzer")]
fuzz_target!(|data: &[u8]| {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // --- (1) the post-quantum micro-certificate envelope --------------
        if let Some(cert) = stellereum::consensus::decode_pq_micro_envelope(data) {
            let canonical = stellereum::consensus::encode_pq_micro_envelope(&cert);
            if let Some(back) = stellereum::consensus::decode_pq_micro_envelope(&canonical) {
                assert_eq!(
                    back, cert,
                    "µQC must round-trip through its own canonical encoder"
                );
            }
            let epoch = stellereum::consensus::encode_pq_epoch_envelope(&cert);
            if let Some(back) = stellereum::consensus::decode_pq_epoch_envelope(&epoch) {
                assert_eq!(back, cert, "epoch CEC must round-trip through its encoder");
            }
        }

        // --- (2) the epoch CEC envelope -----------------------------------
        if let Some(cert) = stellereum::consensus::decode_pq_epoch_envelope(data) {
            let canonical = stellereum::consensus::encode_pq_epoch_envelope(&cert);
            if let Some(back) = stellereum::consensus::decode_pq_epoch_envelope(&canonical) {
                assert_eq!(back, cert, "epoch CEC must round-trip through its encoder");
            }
        }

        // --- (3) the BLS aggregate certificate envelope -------------------
        if let Some((_h, _r, _kind, _bh, aggregate)) =
            stellereum::consensus::decode_qc_bls_envelope(data)
        {
            let signers = aggregate.participants.total_validators();
            assert!(signers > 0, "a decoded BLS aggregate must name at least one signer");
            assert_eq!(
                aggregate.participants.bitmask().len(),
                signers.div_ceil(8),
                "the BLS signer bitvector length must match the validator count it claims"
            );
        }

        // --- (4) the two post-quantum signature envelopes -----------------
        let _ = stellereum::sharding::PqSignatureEnvelope::decode(data);
        let _ = stellereum::post_quantum::PqSignatureEnvelope::decode(data);
    }));
});
#[cfg(not(feature = "libfuzzer"))]
fn main() {}
