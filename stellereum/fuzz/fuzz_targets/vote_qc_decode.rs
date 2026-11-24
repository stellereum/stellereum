// Fuzz target: peer-controlled `Vote` and `QuorumCertificate` bincode frames.
//
// WHY THIS TARGET EXISTS (Wave 4, 2026-11):
// the C1 consensus review found remote-abort bugs by reading the decoder
// paths. Votes and QCs are nested inside `ConsensusMsg::decode`, but a bug in
// their own length prefixes (`signatures: Vec<(ValidatorId, Vec<u8>)>`) is
// easier to see, and cheaper to reproduce, at the standalone type boundary.
// A decoded certificate is also a TRUST claim: it must never verify when its
// signatures are empty or forged.
//
// WHAT IT ASSERTS:
//   1. neither decode path PANICS on peer bytes (a panic in the message
//      handler is a remote DoS);
//   2. a QC decoded from remote bytes never verifies against an EMPTY
//      validator set;
//   3. the same QC with its signature bytes stripped never verifies even when
//      every signer id is given voting power (empty bytes cannot be a Falcon
//      signature);
//   4. a vote whose signature bytes are stripped never verifies.
//
// The bincode options mirror production (`consensus_net::ConsensusMsg::decode`
// uses fixint encoding plus a byte limit), so a length prefix cannot ask for
// more bytes than the fuzzer actually supplied.
//
// Run: cargo +nightly fuzz run vote_qc_decode
#![no_main]
#[cfg(feature = "libfuzzer")]
use libfuzzer_sys::fuzz_target;

#[cfg(feature = "libfuzzer")]
use bincode::Options;

#[cfg(feature = "libfuzzer")]
const MAX_INPUT: usize = 1 << 20;

// One megabyte is far above an honest vote (<= VOTE_FALCON_PART_LEN) or a
// useful QC, and keeps one fuzz iteration cheap.
#[cfg(feature = "libfuzzer")]
fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let limit = data.len().min(MAX_INPUT) as u64;

        // --- (1) Vote -----------------------------------------------------
        if let Ok(vote) = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(limit)
            .reject_trailing_bytes()
            .deserialize::<stellereum::consensus::Vote>(data)
        {
            let mut stripped = vote.clone();
            stripped.signature.clear();
            // (4) no signature bytes can never verify.
            assert!(
                !stripped.verify(),
                "a Vote with an empty signature must never verify"
            );
        }

        // --- (2) QuorumCertificate ---------------------------------------
        if let Ok(qc) = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(limit)
            .reject_trailing_bytes()
            .deserialize::<stellereum::consensus::QuorumCertificate>(data)
        {
            // (2) an empty committee must never reach quorum.
            assert!(
                !qc.verify(&stellereum::consensus::ValidatorSet::new()),
                "a QC must never verify against an empty validator set"
            );

            // (3) forge every signature: keep the ids (and their power), empty
            // the bytes. Quorum arithmetic may pass, crypto must not.
            let mut forged = qc.clone();
            for (_, sig) in &mut forged.signatures {
                sig.clear();
            }
            let mut committee = stellereum::consensus::ValidatorSet::new();
            for (id, _) in &qc.signatures {
                committee.add(*id, 1);
            }
            assert!(
                !forged.verify(&committee),
                "a QC whose signature bytes are empty must never verify, \
                 even when every signer id carries voting power"
            );
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
