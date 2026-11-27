//! Corpus parity: every persisted fuzz corpus file is replayed through the
//! clean-room decoders and compared with `stellereum`.
//!
//! The corpus root is `../stellereum/fuzz/corpus`. A missing directory is
//! skipped (the fuzz workspace is not part of the main build), and an empty
//! directory simply runs zero cases.
//!
//! Two classes of assertion are made:
//!
//! * **Exact parity** for the hand-written certificate envelopes and for
//!   Falcon-512 verification: both implementations must return the same
//!   verdict on the same bytes.
//! * **Strict-subset parity** for the bincode types (`Block`, `Transaction`,
//!   `Vote`, `QuorumCertificate`): the clean-room decoders add canonical
//!   round-trip checks, so anything they accept MUST also be accepted by
//!   `stellereum` (and must re-encode to the identical bytes). The reverse is
//!   allowed to differ precisely because non-canonical bytes are refused.
//!
//! Every clean-room call is wrapped in `catch_unwind`; a panic on peer bytes
//! is a remote-DoS bug, so the test fails loudly instead of aborting.

use std::fs;
use std::path::{Path, PathBuf};

use bincode::Options;

use stellereum::consensus as reference;
use stellereum_verifier::consensus as verifier;
use stellereum_verifier::falcon512::verify_falcon512;
use stellereum_verifier::tx::PqSignatureEnvelope;
use stellereum_verifier::wire;

const MAX_INPUT: usize = 1 << 20;

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("stellereum")
        .join("fuzz")
        .join("corpus")
}

fn each_corpus_file(name: &str, mut check: impl FnMut(&Path, &[u8])) {
    let dir = corpus_root().join(name);
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) => {
            eprintln!("skip `{}`: {error}", dir.display());
            return;
        }
    };
    let mut count = 0usize;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                eprintln!("skip an entry in `{}`: {error}", dir.display());
                continue;
            }
        };
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) => panic!("cannot read corpus file {}: {error}", path.display()),
        };
        if bytes.len() > MAX_INPUT {
            continue;
        }
        check(&path, &bytes);
        count += 1;
    }
    eprintln!("{name}: {count} corpus files replayed");
}

fn panic_text(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_string()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

fn no_panic<T>(path: &Path, what: &str, f: impl FnOnce() -> T) -> T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(value) => value,
        Err(payload) => panic!(
            "{what} panicked on {}: {}",
            path.display(),
            panic_text(payload)
        ),
    }
}

fn micro_matches(ours: &wire::PqMicroCertificate, theirs: &reference::PqMicroCertificate) -> bool {
    ours.scheme.id() == theirs.scheme.id()
        && ours.sortition_parent == theirs.sortition_parent
        && ours.height == theirs.height
        && ours.round == theirs.round
        && ours.committee_size == theirs.committee_size
        && ours.signers_bitmask == theirs.signers_bitmask
        && ours.signatures == theirs.signatures
}

fn reference_options(bytes: &[u8]) -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(bytes.len() as u64)
        .reject_trailing_bytes()
}

#[test]
fn corpus_block_decode_parity() {
    each_corpus_file("block_decode", |path, bytes| {
        let (ours, reference_ok) = no_panic(path, "block decode", || {
            let ours = wire::decode_block_v7_strict(bytes);
            let reference_ok = bincode::deserialize::<stellereum::sharding::Block>(bytes).is_ok();
            (ours, reference_ok)
        });

        if let Ok(block) = ours {
            assert!(
                reference_ok,
                "clean-room strict acceptance implies reference acceptance: {}",
                path.display()
            );
            let canonical =
                wire::encode_block_v7_canonical(&block).expect("canonical block re-encode");
            assert_eq!(
                canonical,
                bytes,
                "a strictly accepted block must be canonical: {}",
                path.display()
            );
            assert!(
                block.shard_headers_canonical(),
                "strict decoder must refuse non-canonical shard_headers: {}",
                path.display()
            );
        }
    });
}

#[test]
fn corpus_transaction_decode_parity() {
    each_corpus_file("transaction_decode", |path, bytes| {
        let (ours, reference_ok) = no_panic(path, "transaction decode", || {
            let ours = wire::decode_transaction_v7_strict(bytes);
            let reference_ok =
                bincode::deserialize::<stellereum::sharding::Transaction>(bytes).is_ok();
            (ours, reference_ok)
        });

        if let Ok(tx) = ours {
            assert!(
                reference_ok,
                "clean-room strict acceptance implies reference acceptance: {}",
                path.display()
            );
            let canonical = wire::encode_transaction_v7_canonical(&tx)
                .expect("canonical transaction re-encode");
            assert_eq!(
                canonical,
                bytes,
                "a strictly accepted transaction must be canonical: {}",
                path.display()
            );
        }
    });
}

#[test]
fn corpus_vote_qc_decode_parity() {
    each_corpus_file("vote_qc_decode", |path, bytes| {
        let (ours_vote, ref_vote) = no_panic(path, "vote decode", || {
            let ours = wire::decode_vote_v7_strict(bytes);
            let reference = reference_options(bytes)
                .deserialize::<reference::Vote>(bytes)
                .ok();
            (ours, reference)
        });
        if let Ok(vote) = &ours_vote {
            assert!(
                ref_vote.is_some(),
                "strict vote acceptance implies reference acceptance: {}",
                path.display()
            );
            // Re-encode must be byte-identical.
            let canonical = bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .serialize(&vote)
                .expect("canonical vote encode");
            assert_eq!(
                canonical,
                bytes,
                "vote must be canonical: {}",
                path.display()
            );
        }
        if let Some(vote) = &ref_vote {
            let mut stripped = vote.clone();
            stripped.signature.clear();
            let verdict = no_panic(path, "reference stripped-vote verify", || stripped.verify());
            assert!(
                !verdict,
                "reference: a vote with an empty signature must never verify: {}",
                path.display()
            );
        }
        if let Ok(vote) = &ours_vote {
            let mut stripped = vote.clone();
            stripped.signature.clear();
            let keys = verifier::StaticPqKeyRegistry::new();
            let verdict = no_panic(path, "clean-room stripped-vote verify", || {
                stripped.verify(&keys, wire::DEFAULT_CHAIN_ID)
            });
            assert!(
                !verdict,
                "clean-room: a vote with an empty signature must never verify: {}",
                path.display()
            );
        }

        let (ours_qc, ref_qc) = no_panic(path, "QC decode", || {
            let ours = wire::decode_qc_v7_strict(bytes);
            let reference = reference_options(bytes)
                .deserialize::<reference::QuorumCertificate>(bytes)
                .ok();
            (ours, reference)
        });
        if let Ok(qc) = &ours_qc {
            assert!(
                ref_qc.is_some(),
                "strict QC acceptance implies reference acceptance: {}",
                path.display()
            );
            let canonical = bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .serialize(&qc)
                .expect("canonical QC encode");
            assert_eq!(canonical, bytes, "QC must be canonical: {}", path.display());
        }
        if let Some(qc) = &ref_qc {
            let empty_verdict = no_panic(path, "reference empty-set QC verify", || {
                qc.verify(&reference::ValidatorSet::new())
            });
            assert!(
                !empty_verdict,
                "reference: a QC must never verify against an empty set: {}",
                path.display()
            );
            let mut forged = qc.clone();
            for (_, sig) in &mut forged.signatures {
                sig.clear();
            }
            let mut committee = reference::ValidatorSet::new();
            for (id, _) in &qc.signatures {
                committee.add(*id, 1);
            }
            let forged_verdict = no_panic(path, "reference forged QC verify", || {
                forged.verify(&committee)
            });
            assert!(
                !forged_verdict,
                "reference: empty signature bytes can never carry quorum: {}",
                path.display()
            );
        }
        if let Ok(qc) = &ours_qc {
            let empty = verifier::ValidatorSet::new();
            let keys = verifier::StaticPqKeyRegistry::new();
            let empty_verdict = no_panic(path, "clean-room empty-set QC verify", || {
                qc.verify(&empty, &keys)
            });
            assert!(
                !empty_verdict,
                "clean-room: a QC must never verify against an empty set: {}",
                path.display()
            );
            let mut forged = qc.clone();
            for (_, sig) in &mut forged.signatures {
                sig.clear();
            }
            let mut committee = verifier::ValidatorSet::new();
            for (id, _) in &qc.signatures {
                committee.add(*id, 1);
            }
            let forged_verdict = no_panic(path, "clean-room forged QC verify", || {
                forged.verify(&committee, &keys)
            });
            assert!(
                !forged_verdict,
                "clean-room: empty signature bytes can never carry quorum: {}",
                path.display()
            );
        }
    });
}

#[test]
fn corpus_cert_envelope_decode_parity() {
    each_corpus_file("cert_envelope_decode", |path, bytes| {
        let (ours_micro, ref_micro) = no_panic(path, "micro-envelope decode", || {
            (
                wire::decode_pq_micro_envelope(bytes),
                reference::decode_pq_micro_envelope(bytes),
            )
        });
        assert_eq!(
            ours_micro.is_some(),
            ref_micro.is_some(),
            "µQC envelope verdict: {}",
            path.display()
        );
        if let Some(cert) = &ours_micro {
            let reference_cert = ref_micro.as_ref().expect("verdict parity");
            assert!(
                micro_matches(cert, reference_cert),
                "µQC envelope field parity: {}",
                path.display()
            );
            let canonical = wire::encode_pq_micro_envelope(cert);
            let back = wire::decode_pq_micro_envelope(&canonical)
                .expect("µQC must round-trip through its own encoder");
            assert_eq!(&back, cert, "µQC canonical round-trip: {}", path.display());
        }

        let (ours_epoch, ref_epoch) = no_panic(path, "epoch-envelope decode", || {
            (
                wire::decode_pq_epoch_envelope(bytes),
                reference::decode_pq_epoch_envelope(bytes),
            )
        });
        assert_eq!(
            ours_epoch.is_some(),
            ref_epoch.is_some(),
            "CEC envelope verdict: {}",
            path.display()
        );
        if let Some(cert) = &ours_epoch {
            let reference_cert = ref_epoch.as_ref().expect("verdict parity");
            assert!(
                micro_matches(cert, reference_cert),
                "CEC envelope field parity: {}",
                path.display()
            );
        }

        // Strict `PQ1` signature envelope: our canonical decoder may only be
        // stricter than the reference's canonical decoder.
        let (ours_env, ref_env) = no_panic(path, "PQ1 envelope decode", || {
            (
                PqSignatureEnvelope::decode_canonical(bytes),
                stellereum::sharding::PqSignatureEnvelope::decode_canonical(bytes),
            )
        });
        if let Ok(envelope) = &ours_env {
            assert!(
                ref_env.is_ok(),
                "our canonical envelope acceptance implies the reference's: {}",
                path.display()
            );
            assert_eq!(
                envelope.encode(),
                bytes,
                "a canonical envelope must re-encode identically: {}",
                path.display()
            );
        }
    });
}

#[test]
fn corpus_falcon_sig_decode_parity() {
    let keypair = stellereum::post_quantum::FalconKeypair::generate_from_seed_bytes(&[0x42u8; 32]);
    let public_key = keypair.public_key().to_vec();
    let message = b"stellereum-fuzz/falcon_sig_decode";

    each_corpus_file("falcon_sig_decode", |path, bytes| {
        if bytes.len() < stellereum_verifier::falcon512::FALCON512_SIG_LEN {
            return;
        }
        let signature = &bytes[..stellereum_verifier::falcon512::FALCON512_SIG_LEN];

        let (ours, theirs) = no_panic(path, "fixed-key Falcon verify", || {
            (
                verify_falcon512(&public_key, message, signature),
                reference::verify_falcon_signature(&public_key, message, signature),
            )
        });
        assert_eq!(
            ours,
            theirs,
            "fixed-key Falcon-512 verdict parity: {}",
            path.display()
        );
        assert!(
            !ours,
            "an arbitrary 666-byte frame must never verify: {}",
            path.display()
        );

        if bytes.len()
            >= stellereum_verifier::falcon512::FALCON512_SIG_LEN
                + stellereum_verifier::falcon512::FALCON512_PUBKEY_LEN
        {
            let offset = stellereum_verifier::falcon512::FALCON512_SIG_LEN;
            let attacker_key =
                &bytes[offset..offset + stellereum_verifier::falcon512::FALCON512_PUBKEY_LEN];
            let (ours, theirs) = no_panic(path, "attacker-key Falcon verify", || {
                (
                    verify_falcon512(attacker_key, message, signature),
                    reference::verify_falcon_signature(attacker_key, message, signature),
                )
            });
            assert_eq!(
                ours,
                theirs,
                "attacker-key Falcon-512 verdict parity: {}",
                path.display()
            );
        }
    });
}
