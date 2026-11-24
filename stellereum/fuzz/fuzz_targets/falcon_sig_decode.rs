// Fuzz target: arbitrary 666-byte Falcon-512 signature frames.
//
// WHY THIS TARGET EXISTS (Wave 4, 2026-11):
// `unpack_falcon_sig` is the hand-written decoder for the Falcon-512 signature
// frame (`0x29 || 40-byte nonce || comp_encode(s2) || zero padding`). It is
// reached for every peer vote, every proposal, and every consensus-transaction
// envelope. It is private (`post_quantum::unpack_falcon_sig`), so this harness
// uses the nearest public entry point: `consensus::verify_falcon_signature`
// (a thin alias for `post_quantum::verify_pq_signature` with `Falcon512`),
// which unpacks both the public key and the signature before doing the lattice
// check.
//
// The public key is a deterministic Falcon-512 keypair generated once from a
// fixed seed (`generate_from_seed_bytes`; the single-byte `generate_from_seed`
// helper is only compiled with debug assertions, and fuzz builds are release).
// The message is fixed, so a frame that returned `true` would be a genuine
// forgery — impossible for a fuzzer without the private key.
//
// WHAT IT ASSERTS:
//   1. no frame PANICS the verifier;
//   2. an arbitrary 666-byte frame NEVER verifies against the fixed key.
//
// A second, attacker-chosen public key is read from the remaining bytes when
// present and fed to the same verifier for coverage of `unpack_falcon_pubkey_ntt`;
// its verdict is not asserted (a fuzzer discovering a real keypair is not a bug).
//
// Run: cargo +nightly fuzz run falcon_sig_decode
#![no_main]
#[cfg(feature = "libfuzzer")]
use libfuzzer_sys::fuzz_target;

#[cfg(feature = "libfuzzer")]
use std::sync::OnceLock;

#[cfg(feature = "libfuzzer")]
const MAX_INPUT: usize = 1 << 20;

#[cfg(feature = "libfuzzer")]
const FALCON_PUBKEY_LEN: usize = stellereum::post_quantum::FALCON512_PUBKEY_LEN;

/// The fixed, deterministic verification key. Generated once per fuzz process.
#[cfg(feature = "libfuzzer")]
fn fixed_pubkey() -> &'static [u8] {
    static PUBKEY: OnceLock<Vec<u8>> = OnceLock::new();
    PUBKEY.get_or_init(|| {
        // A 32-byte secret is public knowledge here: this key only verifies.
        let seed = [0x42u8; 32];
        stellereum::post_quantum::FalconKeypair::generate_from_seed_bytes(&seed)
            .pubkey()
            .to_vec()
    })
}

#[cfg(feature = "libfuzzer")]
fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if data.len() < stellereum::post_quantum::FALCON512_SIG_LEN {
            return;
        }
        let sig = &data[..stellereum::post_quantum::FALCON512_SIG_LEN];
        let message = b"stellereum-fuzz/falcon_sig_decode";

        // (2) arbitrary frames must fail closed against the known key.
        assert!(
            !stellereum::consensus::verify_falcon_signature(fixed_pubkey(), message, sig),
            "an arbitrary 666-byte frame must never verify"
        );

        // Coverage for the public-key decoder; no verdict assertion (a real
        // keypair + signature in the input is not a bug).
        if data.len() >= stellereum::post_quantum::FALCON512_SIG_LEN + FALCON_PUBKEY_LEN {
            let pk = &data[stellereum::post_quantum::FALCON512_SIG_LEN
                ..stellereum::post_quantum::FALCON512_SIG_LEN + FALCON_PUBKEY_LEN];
            let _ = stellereum::consensus::verify_falcon_signature(pk, message, sig);
        }
    }));
    // A panic (including an assertion above) is the bug this harness
    // exists to find: never let catch_unwind swallow it.
    if panicked.is_err() {
        std::process::abort();
    }
});

#[cfg(not(feature = "libfuzzer"))]
fn main() {}
