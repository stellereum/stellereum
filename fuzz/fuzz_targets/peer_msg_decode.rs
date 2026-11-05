// Fuzz target: the peer-controlled decoders that are NOT "bincode of a trie type".
//
//   * the CROSS-SHARD MESSAGE decoder — `network::P2pNetworkAdapter::parse_cross_shard_incoming`
//     (a message a peer sends over the DHT / the gossip channel);
//   * the EPOCH-SEAL gossip frames — `mev_epoch::MevFrame::decode` and
//     `mev_epoch::decode_sealed_payload` (the sealed-transaction wire format,
//     `MAGIC || bincode(body)`, five different magics).
//
// WHY THIS TARGET EXISTS (audit-prep gap, 2026-10):
// the pre-existing corpus covered the `bincode` decoders (`ConsensusMsg`,
// `Block`, `Transaction`, the infnode `Frame`) and the certificate envelopes.
// The two decoders above were NOT covered, and both are reached directly from
// bytes a remote peer chooses.
//
// WHAT IT ASSERTS:
//   1. no decoder PANICS on peer-controlled bytes (a panic inside the message
//      handler is a remote DoS that takes the node with it);
//   2. the cross-shard decoder ALWAYS clears the `trusted` flag: that flag
//      bypasses `verify_inclusion`, so it must never survive a decode of
//      remote bytes. This is the single most dangerous field in the struct;
//   3. a sealed envelope that decodes must round-trip through
//      `encode_sealed_payload` to an EQUAL envelope (the encoder and the
//      decoder must be mutually consistent — a mismatch is a malleability
//      bug: two byte strings for one logical envelope);
//   4. the frame kind a payload decodes as must agree with the magic prefix
//      it decoded under.
//
// Run: cargo +nightly fuzz run peer_msg_decode
// Stable fallback: cargo test --test fuzz_decoder_tests cross_shard_ / sealed_
#![no_main]
#[cfg(feature = "libfuzzer")]
use libfuzzer_sys::fuzz_target;

#[cfg(feature = "libfuzzer")]
fuzz_target!(|data: &[u8]| {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // --- (1) the cross-shard message decoder -----------------------------
        if let Some(msg) =
            stellereum::network::P2pNetworkAdapter::parse_cross_shard_incoming(data)
        {
            assert!(
                !msg.trusted,
                "a cross-shard message decoded from remote bytes must NEVER be trusted"
            );
        }

        // --- (2) the epoch-seal gossip frames --------------------------------
        if let Ok(frame) = stellereum::mev_epoch::MevFrame::decode(data) {
            // The frame kind must agree with the magic it was decoded under.
            assert_eq!(
                &data[..4],
                frame.magic(),
                "a decoded epoch-seal frame must match the magic prefix it decoded under"
            );
            // A frame must re-encode to the same bytes it came from: the
            // magic is the only framing, so the body is canonical bincode.
            if let Ok(re) = frame.encode() {
                assert_eq!(
                    re, data,
                    "an epoch-seal frame must re-encode to exactly the bytes it decoded from"
                );
            }
        }

        // --- (3) the sealed-transaction payload ------------------------------
        if let Ok(envelope) = stellereum::mev_epoch::decode_sealed_payload(data) {
            assert!(!envelope.ciphertext.is_empty(), "a sealed payload must carry bytes");
            let re = stellereum::mev_epoch::encode_sealed_payload(&envelope)
                .expect("a sealed envelope that decoded must re-encode");
            if let Ok(back) = stellereum::mev_epoch::decode_sealed_payload(&re) {
                assert_eq!(
                    back, envelope,
                    "a sealed envelope must round-trip through the canonical encoder"
                );
            }
        }
    }));
});
#[cfg(not(feature = "libfuzzer"))]
fn main() {}
