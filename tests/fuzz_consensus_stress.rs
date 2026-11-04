//! Structured fuzz / stress for the consensus-critical decode + verify paths.
//!
//! Complements `tests/fuzz_decoder_tests.rs` (broad corpus, no timing) with
//! targeted, budgeted checks:
//!   (1) a 50k random-byte storm against `ConsensusMsg::decode`;
//!   (2) exhaustive mutations of a valid `Batch` — truncate at every offset,
//!       flip every byte of the length prefix, huge declared counts, nesting;
//!   (3) `QuorumCertificate::verify` against adversarial signer lists
//!       (empty / over-cap / mismatched / malformed);
//!   (4) `vote_sign_bytes` domain separation and field injectivity;
//!   (5) bincode roundtrip of `Block` with `precommit_qc`, plus the old
//!       (pre-`precommit_qc`) `Block` layout behaviour in BOTH directions.
//!
//! Every input runs under `catch_unwind` with a PER-INPUT time budget: a panic
//! on peer bytes is a remote DoS, and an input that blows the budget means the
//! decoder/verifier did unbounded work (or allocation) on peer-controlled
//! bytes. All tests are plain `#[test]` (never `#[ignore]`) and the whole file
//! is bounded to a few seconds.
//!
//! Stable-toolchain companion to the `cargo +nightly fuzz run <target>`
//! targets in `fuzz/fuzz_targets/`.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::time::{Duration, Instant};
use stellereum::consensus::{
    vote_sign_bytes, QuorumCertificate, ValidatorSet, Vote, VoteKind, MAX_COMMIT_CERT_SIGNERS,
};
use stellereum::consensus_net::{ConsensusMsg, MAX_BATCH_BYTES, MAX_BATCH_ITEMS};
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};

/// Per-input wall-clock budget. Anything slower than this on a sub-32 MiB
/// input is unbounded work (allocation or loop) on peer-controlled bytes, not
/// legitimate parsing.
// 1s, not 100ms: the point is to catch UNBOUNDED work (which runs to seconds
// or forever), not to benchmark. This box is a single core shared with builds
// and two live nodes, where scheduler noise alone measured >400ms for an
// 8-byte input -- a 100ms budget reported false positives under load.
const PER_INPUT: Duration = Duration::from_millis(1_000);

/// Whole-test budget. Generous for loaded CI; measured runtimes are far lower.
const TOTAL: Duration = Duration::from_secs(15);

// ---------------------------------------------------------------------------
// Deterministic PRNG (xorshift64*, fixed seeds — no OS entropy in mutations).
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

// ---------------------------------------------------------------------------
// Corpus builders.
// ---------------------------------------------------------------------------

fn sample_block() -> Block {
    let sk = SigningKey::generate(&mut OsRng);
    let mut b = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 7,
        prev_hash: [1u8; 32],
        state_root: [2u8; 32],
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 123,
        proposer: sk.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    b.sign_block(&sk);
    b
}

/// Deterministic key from a counter (no OS RNG) so the 4k-signer fixtures stay
/// reproducible and cheap.
fn keypair_at(i: u64) -> SigningKey {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&i.to_le_bytes());
    seed[8..16].copy_from_slice(&0x5A5A_5A5A_A5A5_A5A5u64.to_le_bytes());
    SigningKey::from_bytes(&seed)
}

/// A valid `Batch` (2 votes + 1 proposal) as it would appear on the wire.
/// Header layout: `[0..4]` = enum variant tag (u32 LE, `Batch` = 3),
/// `[4..12]` = Vec item count (u64 LE).
fn valid_batch_bytes() -> Vec<u8> {
    let sk = keypair_at(0);
    let items = vec![
        ConsensusMsg::Vote {
            vote: Vote::sign(&sk, 7, 0, VoteKind::Prevote, Some([1u8; 32])),
            locked: None,
        },
        ConsensusMsg::Vote {
            vote: Vote::sign(&sk, 7, 0, VoteKind::Precommit, Some([1u8; 32])),
            locked: Some([2u8; 32]),
        },
        ConsensusMsg::Proposal {
            height: 7,
            round: 0,
            block: sample_block(),
        },
    ];
    ConsensusMsg::batch_encode(&items).expect("valid batch must encode")
}

// ---------------------------------------------------------------------------
// Guards.
// ---------------------------------------------------------------------------

/// Decode under a panic + per-input time budget. Panics (test failure) if the
/// input panics the decoder or takes longer than `PER_INPUT`.
fn decode_guarded(input: &[u8]) -> Result<ConsensusMsg, String> {
    let t = Instant::now();
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ConsensusMsg::decode(input)));
    let dt = t.elapsed();
    assert!(
        dt < PER_INPUT,
        "decode of {}-byte input took {dt:?} (budget {PER_INPUT:?}): unbounded work/allocation",
        input.len()
    );
    match r {
        Ok(res) => res,
        Err(_) => panic!(
            "ConsensusMsg::decode panicked on a {}-byte input",
            input.len()
        ),
    }
}

/// Structural invariants that must hold for ANY `Ok` decode of a `Batch`,
/// mutated input or not: `check_batch` is what enforces them, so a mutation
/// that produces an `Ok` batch violating one of these is a decode bug.
fn assert_batch_invariants(input_len: usize, msg: &ConsensusMsg) {
    if let ConsensusMsg::Batch(items) = msg {
        assert!(
            !items.is_empty(),
            "decode returned an EMPTY batch (input {input_len} B)"
        );
        assert!(
            items.len() <= MAX_BATCH_ITEMS,
            "decode returned a batch with {} items (> {MAX_BATCH_ITEMS})",
            items.len()
        );
        assert!(
            input_len <= MAX_BATCH_BYTES,
            "decode returned Ok for a {input_len}-byte batch (> {MAX_BATCH_BYTES})"
        );
        assert!(
            !items.iter().any(|m| matches!(m, ConsensusMsg::Batch(_))),
            "decode returned a NESTED batch"
        );
    }
}

// ---------------------------------------------------------------------------
// (1) 50k random-byte storm against ConsensusMsg::decode.
// ---------------------------------------------------------------------------

#[test]
fn random_byte_storm_50k_no_panic_no_timeout_fail_closed() {
    const N: usize = 50_000;
    let mut rng = Rng(0xF0_55_C1_DE);
    let wall = Instant::now();
    let mut accepted = 0usize;

    for i in 0..N {
        // Mixed lengths: tiny headers, mid sizes, deep-field scans, big blobs.
        let len = match i % 16 {
            0 => rng.below(12),
            1 => 12 + rng.below(64),
            2 => 64 + rng.below(512),
            3 => 512 + rng.below(4096),
            4 => 4096 + rng.below(16384),
            _ => rng.below(256),
        };
        let mut input = rng.bytes(len);
        // Almost every input gets a VALID enum tag (cycling all four variants)
        // so decode walks deep into the random body instead of bailing at
        // byte 0 — that is where length prefixes and counts live. The rest
        // keep their random tag to exercise tag rejection too.
        if input.len() >= 4 && i % 8 != 7 {
            input[0..4].copy_from_slice(&((i % 4) as u32).to_le_bytes());
        }
        if let Ok(msg) = decode_guarded(&input) {
            accepted += 1;
            assert_batch_invariants(input.len(), &msg);
        }
    }

    let total = wall.elapsed();
    // Fail-closed observation, pinned for this fixed corpus: no random blob
    // (valid tag or not) decodes into a message. If this ever trips, inspect
    // the accepted input before loosening the assertion — decode-without-verify
    // is exactly how a garbage peer payload becomes a live message.
    assert_eq!(
        accepted, 0,
        "{accepted}/{N} random inputs decoded Ok (fixed seed — new variant or looser framing?)"
    );
    assert!(
        total < TOTAL,
        "50k-input storm took {total:?} (budget {TOTAL:?})"
    );
    eprintln!("random_byte_storm: {N} inputs in {total:?} ({accepted} accepted)");
}

// ---------------------------------------------------------------------------
// (2) Mutations of a valid Batch.
// ---------------------------------------------------------------------------

#[test]
fn valid_batch_roundtrips_and_truncations_at_every_offset_fail_closed() {
    let valid = valid_batch_bytes();
    match decode_guarded(&valid) {
        Ok(ConsensusMsg::Batch(items)) => {
            assert_eq!(items.len(), 3, "fixture must carry 3 items");
        }
        other => panic!("valid batch must decode as Batch, got {other:?}"),
    }

    let wall = Instant::now();
    // Every strict prefix: the input is cut mid-field, so bincode must hit EOF
    // and ConsensusMsg::decode must return Err — never Ok, never a panic.
    for n in 0..valid.len() {
        let res = decode_guarded(&valid[..n]);
        assert!(
            res.is_err(),
            "truncation to {n}/{} bytes was ACCEPTED",
            valid.len()
        );
    }
    // Empty input is a specific case of the above and must stay rejected.
    assert!(ConsensusMsg::decode(&[]).is_err());
    assert!(wall.elapsed() < TOTAL);
}

#[test]
fn batch_length_prefix_flips_never_accept_invalid_structure() {
    let valid = valid_batch_bytes();
    assert_eq!(
        &valid[0..4],
        &3u32.to_le_bytes(),
        "Batch must be variant tag 3"
    );
    let declared = u64::from_le_bytes(valid[4..12].try_into().unwrap());
    assert_eq!(declared, 3);

    let wall = Instant::now();
    let mut accepted = 0usize;

    // (a) Flips inside the Vec length prefix [4..12]: every byte × {clear,
    //     set-all, ^0x01, ^0x80}. A corrupted count may only ever DECODE FEWER
    //     items (bincode ignores the trailing ones — documented trailing-byte
    //     class); a count larger than what is present must fail closed.
    for i in 4..12 {
        let b = valid[i];
        for v in [0x00u8, 0xFF, b ^ 0x01, b ^ 0x80] {
            if v == b {
                continue;
            }
            let mut m = valid.clone();
            m[i] = v;
            if let Ok(msg) = decode_guarded(&m) {
                accepted += 1;
                assert_batch_invariants(m.len(), &msg);
                if let ConsensusMsg::Batch(items) = &msg {
                    assert!(
                        (items.len() as u64) <= declared,
                        "length-prefix flip at byte {i} invented items: {} > {declared}",
                        items.len()
                    );
                }
            }
        }
    }

    // (b) Corrupt the enum tag [0..4]: tags outside 0..3 must be rejected; a
    //     tag that lands on another variant just gets decoded as that variant
    //     (and then fails on the random body, or decodes as garbage — the
    //     documented decode-vs-verify split, never a panic).
    for i in 0..4 {
        for v in [4u32, 7, 1_000, u32::MAX] {
            let mut m = valid.clone();
            m[i..i + 4].copy_from_slice(&v.to_le_bytes());
            let res = decode_guarded(&m);
            assert!(res.is_err(), "enum tag {v} at byte {i} must be rejected");
        }
    }

    // (c) Every 8-byte window forced to u64::MAX — hits Vec length prefixes
    //     (including the inner signature vecs) and count fields wherever they
    //     are. Structurally valid `Ok` results are allowed only if the batch
    //     invariants still hold.
    for off in 0..valid.len() {
        if off + 8 > valid.len() {
            break;
        }
        let mut m = valid.clone();
        m[off..off + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        if let Ok(msg) = decode_guarded(&m) {
            accepted += 1;
            assert_batch_invariants(m.len(), &msg);
        }
    }

    assert!(wall.elapsed() < TOTAL);
    eprintln!("batch_length_prefix_flips: {accepted} accepted (all structurally valid)");
}

#[test]
fn batch_huge_declared_counts_fail_closed_fast() {
    let valid = valid_batch_bytes();

    // Counts the input cannot possibly satisfy (0 = empty batch, anything
    // above the 3 present items = EOF mid-item): all must be Err, fast.
    for count in [
        0u64,
        4,
        33,
        1_000,
        (MAX_BATCH_ITEMS as u64 + 1),
        u64::from(u32::MAX),
        1 << 40,
        u64::MAX / 2,
        u64::MAX,
    ] {
        let mut m = valid.clone();
        m[4..12].copy_from_slice(&count.to_le_bytes());
        let res = decode_guarded(&m);
        assert!(
            res.is_err(),
            "declared count {count} must be rejected, got Ok"
        );
    }

    // HARDENED BEHAVIOUR (PENTEST F1 `reject_trailing_bytes`): a REDUCED count
    // no longer decodes Ok — the trailing items are trailing bytes and the
    // decode fails closed. Same class as
    // `fuzz_decoder_tests::report_trailing_bytes_are_accepted_by_bincode_decoders`
    // (now also fail-closed) — callers can treat "decoded Ok" as "exactly the
    // items the sender put in".
    for count in [1u64, 2] {
        let mut m = valid.clone();
        m[4..12].copy_from_slice(&count.to_le_bytes());
        let res = decode_guarded(&m);
        assert!(
            res.is_err(),
            "reduced count {count} must fail closed on trailing bytes, got {res:?}"
        );
    }

    // Oversized count on the outer message size gate too: >32 MiB is rejected
    // before any parsing happens.
    let big = vec![0u8; stellereum::consensus_net::MAX_CONSENSUS_MSG + 1];
    let t = Instant::now();
    assert!(ConsensusMsg::decode(&big).is_err());
    assert!(
        t.elapsed() < PER_INPUT,
        "oversize gate took {:?}",
        t.elapsed()
    );
}

#[test]
fn nested_batches_fail_closed_at_every_depth() {
    let sk = keypair_at(1);
    let one = ConsensusMsg::Vote {
        vote: Vote::sign(&sk, 1, 0, VoteKind::Prevote, None),
        locked: None,
    };

    let wall = Instant::now();
    // Depth 2.
    let d2 = ConsensusMsg::Batch(vec![ConsensusMsg::Batch(vec![one.clone()])]);
    let raw = bincode::serialize(&d2).unwrap();
    let err = decode_guarded(&raw).unwrap_err();
    assert!(
        err.contains("nested"),
        "depth-2 nest rejected for the wrong reason: {err}"
    );

    // Depth 3 (nested inside nested).
    let d3 = ConsensusMsg::Batch(vec![ConsensusMsg::Batch(vec![ConsensusMsg::Batch(vec![
        one.clone(),
    ])])]);
    let raw = bincode::serialize(&d3).unwrap();
    let err = decode_guarded(&raw).unwrap_err();
    assert!(
        err.contains("nested"),
        "depth-3 nest rejected for the wrong reason: {err}"
    );

    // A nested batch buried among valid siblings.
    let mixed = ConsensusMsg::Batch(vec![
        one.clone(),
        ConsensusMsg::Batch(vec![one.clone()]),
        one,
    ]);
    let raw = bincode::serialize(&mixed).unwrap();
    let err = decode_guarded(&raw).unwrap_err();
    assert!(
        err.contains("nested"),
        "buried nest rejected for the wrong reason: {err}"
    );

    // The encoder refuses nesting up front as well (belt and braces).
    if let ConsensusMsg::Batch(items) = d2 {
        assert!(
            ConsensusMsg::batch_encode(&items).is_err(),
            "encoder must refuse nested batches"
        );
    }

    // Truncations of a nested payload must also fail closed, never panic.
    let raw = bincode::serialize(&mixed).unwrap();
    for n in 0..raw.len() {
        assert!(
            decode_guarded(&raw[..n]).is_err(),
            "nested truncation to {n} accepted"
        );
    }
    assert!(wall.elapsed() < TOTAL);
}

// ---------------------------------------------------------------------------
// (3) QuorumCertificate::verify with adversarial signer lists.
// ---------------------------------------------------------------------------

/// `n` validators (power 1 each) + a QC with one honest precommit signature
/// from each.
fn qc_fixture(n: u64) -> (ValidatorSet, QuorumCertificate) {
    let hash = [7u8; 32];
    let mut set = ValidatorSet::new();
    let mut sigs = Vec::new();
    for i in 0..n {
        let sk = keypair_at(i);
        set.add(sk.verifying_key().to_bytes(), 1);
        let v = Vote::sign(&sk, 10, 0, VoteKind::Precommit, Some(hash));
        sigs.push((v.voter, v.signature));
    }
    let qc = QuorumCertificate {
        height: 10,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(hash),
        signatures: sigs,
    };
    (set, qc)
}

#[test]
fn qc_verify_empty_signer_list_false_quickly() {
    let (set, mut qc) = qc_fixture(4);
    qc.signatures.clear();

    let t = Instant::now();
    assert!(!qc.verify(&set), "empty signer list must never verify");
    assert!(t.elapsed() < PER_INPUT, "empty list took {:?}", t.elapsed());

    // Valid signatures against an EMPTY validator set: quorum_power() is
    // u64::MAX there, so nothing can ever reach it.
    let (_, qc4) = qc_fixture(4);
    let empty_set = ValidatorSet::new();
    assert_eq!(empty_set.total_power(), 0);
    let t = Instant::now();
    assert!(
        !qc4.verify(&empty_set),
        "empty validator set must never verify"
    );
    assert!(t.elapsed() < PER_INPUT, "empty set took {:?}", t.elapsed());
}

#[test]
fn qc_verify_huge_signer_lists_false_quickly() {
    let (set, mut qc) = qc_fixture(4);

    // (a) One past the cap: the O(1) pre-check must reject before ANY crypto.
    qc.signatures = vec![([0u8; 32], vec![0u8; 64]); MAX_COMMIT_CERT_SIGNERS + 1];
    let t = Instant::now();
    assert!(!qc.verify(&set), "cap+1 signer list must be rejected");
    let dt = t.elapsed();
    assert!(
        dt < Duration::from_millis(50),
        "cap+1 took {dt:?}: cap check is not O(1)"
    );

    // (b) Two orders of magnitude past the cap.
    qc.signatures = vec![([0u8; 32], vec![0u8; 64]); 100_000];
    let t = Instant::now();
    assert!(!qc.verify(&set), "100k signer list must be rejected");
    let dt = t.elapsed();
    assert!(
        dt < Duration::from_millis(50),
        "100k took {dt:?}: cap check is not O(1)"
    );

    // (c) AT the cap with parseable, in-set, distinct voters and well-shaped
    //     but wrong signatures: this is the designed worst case (batch verify
    //     fails, then one bounded per-signature pass over <= 4096 entries).
    //     Must be bounded work and must return false — no quorum of VALID
    //     signatures exists.
    let mut set_big = ValidatorSet::new();
    let mut sigs = Vec::new();
    for i in 0..MAX_COMMIT_CERT_SIGNERS as u64 {
        let sk = keypair_at(1_000_000 + i);
        set_big.add(sk.verifying_key().to_bytes(), 1);
        // well-formed 64-byte signature, but over nothing meaningful
        let mut sig = [0u8; 64];
        sig[0..8].copy_from_slice(&i.to_le_bytes());
        sig[8] = 0xFF;
        sigs.push((sk.verifying_key().to_bytes(), sig.to_vec()));
    }
    let qc_cap = QuorumCertificate {
        height: 10,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some([7u8; 32]),
        signatures: sigs,
    };
    assert_eq!(qc_cap.signatures.len(), MAX_COMMIT_CERT_SIGNERS);
    let t = Instant::now();
    assert!(
        !qc_cap.verify(&set_big),
        "all-bad signatures at the cap must not verify"
    );
    let dt = t.elapsed();
    assert!(
        dt < Duration::from_secs(3),
        "at-cap verify took {dt:?} (expected ~100-300ms)"
    );
    eprintln!("qc_verify at-cap ({MAX_COMMIT_CERT_SIGNERS} bad sigs): {dt:?}");

    // (d) Duplicate-heavy list: 4096 copies of ONE honest signature must dedup
    //     to a single vote (power 1) and fail — no amplification via repeats.
    let (set4, qc4) = qc_fixture(4);
    let single = qc4.signatures[0].clone();
    let qc_dup = QuorumCertificate {
        signatures: vec![single; MAX_COMMIT_CERT_SIGNERS],
        ..qc4.clone()
    };
    let t = Instant::now();
    assert!(
        !qc_dup.verify(&set4),
        "duplicated signatures must dedup, not accumulate power"
    );
    assert!(
        t.elapsed() < Duration::from_millis(500),
        "dedup path took {:?}",
        t.elapsed()
    );
}

#[test]
fn qc_verify_mismatched_and_malformed_signatures_false() {
    let (set, mut qc) = qc_fixture(4);

    // (a) Voters that are not in the validator set (even with valid sigs).
    let mut foreign = qc.clone();
    foreign.signatures = (0..4u64)
        .map(|i| {
            let sk = keypair_at(50_000 + i);
            let v = Vote::sign(&sk, 10, 0, VoteKind::Precommit, Some([7u8; 32]));
            (v.voter, v.signature)
        })
        .collect();
    assert!(
        !foreign.verify(&set),
        "non-validator voters must not verify"
    );

    // (b) Malformed signature lengths: each skipped as a candidate, list ends
    //     up empty -> false. Includes the overlong case (bytes that are not a
    //     canonical Ed25519 point encoding).
    for bad_len in [0usize, 1, 32, 63, 65, 128, 1024] {
        let mut m = qc.clone();
        for (_, sig) in m.signatures.iter_mut() {
            *sig = vec![0u8; bad_len];
        }
        assert!(!m.verify(&set), "{bad_len}-byte signatures must not verify");
    }

    // (c) Mismatched arrays: voters and signatures swapped between entries.
    let mut swapped = qc.clone();
    let (v1, s1) = swapped.signatures[0].clone();
    let (v2, s2) = swapped.signatures[1].clone();
    swapped.signatures[0] = (v1, s2);
    swapped.signatures[1] = (v2, s1);
    assert!(
        !swapped.verify(&set),
        "cross-wired voter/signature pairs must not verify"
    );

    // (d) Right signers, wrong message: votes were cast at height 10, the QC
    //     claims height 11 -> every signature fails.
    let mut wrong_height = qc.clone();
    wrong_height.height = 11;
    assert!(
        !wrong_height.verify(&set),
        "height-mismatched QC must not verify"
    );

    let mut wrong_round = qc.clone();
    wrong_round.round = 9;
    assert!(
        !wrong_round.verify(&set),
        "round-mismatched QC must not verify"
    );

    let mut wrong_hash = qc.clone();
    wrong_hash.block_hash = Some([9u8; 32]);
    assert!(
        !wrong_hash.verify(&set),
        "hash-mismatched QC must not verify"
    );

    let mut nil_hash = qc.clone();
    nil_hash.block_hash = None;
    assert!(
        !nil_hash.verify(&set),
        "nil-vs-block mismatch must not verify"
    );

    let mut wrong_kind = qc.clone();
    wrong_kind.kind = VoteKind::Prevote;
    assert!(
        !wrong_kind.verify(&set),
        "prevote signatures must not prove a precommit QC"
    );

    // (e) Garbage voter keys (not even valid curve points).
    let mut garbage_keys = qc.clone();
    for (voter, _) in garbage_keys.signatures.iter_mut() {
        *voter = [0xFFu8; 32];
    }
    assert!(
        !garbage_keys.verify(&set),
        "unparseable voter keys must not verify"
    );

    // (f) Only half the quorum present.
    let (_, qc4) = qc_fixture(4);
    let mut half = qc4.clone();
    half.signatures.truncate(2);
    assert!(
        !half.verify(&set),
        "2 of 4 signatures (< 3 needed) must not verify"
    );

    // Still fail-closed under time budget for the whole battery.
    qc.signatures.clear();
    assert!(!qc.verify(&set));
}

#[test]
fn qc_verify_accepts_true_quorum_and_survives_single_bad_sig() {
    let (set, qc) = qc_fixture(4);
    let t = Instant::now();
    assert!(
        qc.verify(&set),
        "4/4 honest precommits must verify (quorum = 3)"
    );

    // One corrupted signature: batch verify fails, slow path must still count
    // the 3 good ones and accept (an attacker must not be able to break a real
    // quorum by appending one bad signature).
    let mut one_bad = qc.clone();
    one_bad.signatures[2].1[0] ^= 0x01;
    assert!(
        one_bad.verify(&set),
        "3/4 valid must still reach quorum (slow path)"
    );

    // Two corrupted: 2 < 3 -> false.
    let mut two_bad = qc.clone();
    two_bad.signatures[2].1[0] ^= 0x01;
    two_bad.signatures[3].1[0] ^= 0x01;
    assert!(!two_bad.verify(&set), "2/4 valid must not reach quorum");

    let dt = t.elapsed();
    assert!(dt < Duration::from_secs(1), "QC verify battery took {dt:?}");
    eprintln!("qc_verify quorum sanity: {dt:?}");
}

// ---------------------------------------------------------------------------
// (4) vote_sign_bytes: domain separation + field injectivity.
// ---------------------------------------------------------------------------

#[test]
fn vote_sign_bytes_is_deterministic_and_field_injective() {
    let prefix = b"STELLEREUM_BFT_VOTE_V2";
    let hash = Some([3u8; 32]);

    // Fixed layout: domain tag + chain_id(BE8) + height(BE8) + round(BE4)
    // + kind(1) + flag(1) [+ hash(32) when Some].
    let with_hash = vote_sign_bytes(1, 2, VoteKind::Prevote, &hash);
    assert_eq!(
        &with_hash[..prefix.len()],
        prefix,
        "missing domain separator"
    );
    assert_eq!(with_hash.len(), prefix.len() + 8 + 8 + 4 + 1 + 1 + 32);
    assert_eq!(with_hash[prefix.len() + 20], 0, "Prevote must encode as 0");
    assert_eq!(with_hash[prefix.len() + 21], 1, "Some(hash) flag");
    assert_eq!(&with_hash[prefix.len() + 22..], &[3u8; 32][..]);

    let no_hash = vote_sign_bytes(1, 2, VoteKind::Precommit, &None);
    assert_eq!(no_hash.len(), prefix.len() + 8 + 8 + 4 + 1 + 1);
    assert_eq!(no_hash[prefix.len() + 20], 1, "Precommit must encode as 1");
    assert_eq!(no_hash[prefix.len() + 21], 0, "None flag");

    // The chain id is part of the preimage: the same vote on another chain
    // signs different bytes (cross-chain replay protection).
    assert_eq!(
        &with_hash[prefix.len()..prefix.len() + 8],
        &stellereum::consensus::consensus_chain_id().to_be_bytes(),
        "the chain id must be bound into the vote preimage"
    );

    // Deterministic: same inputs -> identical bytes (remote signer and local
    // signer must produce the exact same preimage).
    assert_eq!(with_hash, vote_sign_bytes(1, 2, VoteKind::Prevote, &hash));

    // Injective over every field: no two distinct (height, round, kind, hash)
    // tuples may collide — a collision would let one signature authorise two
    // different votes.
    let mut seen = std::collections::HashSet::new();
    let mut checked = 0usize;
    for h in 0..4u64 {
        for r in 0..4u32 {
            for k in [VoteKind::Prevote, VoteKind::Precommit] {
                for bh in [None, Some([0u8; 32]), Some([1u8; 32]), Some([0xFFu8; 32])] {
                    let b = vote_sign_bytes(h, r, k, &bh);
                    assert!(
                        seen.insert(b.clone()),
                        "preimage collision for h={h} r={r} k={k:?} bh={bh:?}"
                    );
                    checked += 1;
                }
            }
        }
    }
    assert_eq!(checked, 128);
    assert_eq!(seen.len(), checked);
}

// ---------------------------------------------------------------------------
// (5) Block bincode roundtrip with precommit_qc + old-format assumptions.
// ---------------------------------------------------------------------------

#[test]
fn block_precommit_qc_roundtrip_and_old_format_assumptions() {
    // --- Roundtrip: a finalized block carries its QC through encode/decode
    // byte-for-byte (Block is consensus state: the encoding must be canonical).
    let (set, qc) = qc_fixture(4);
    assert!(qc.verify(&set), "fixture QC must be a real quorum");
    let mut block = sample_block();
    block.precommit_qc = Some(qc.clone());
    let bytes = bincode::serialize(&block).expect("block must serialize");

    let back: Block = bincode::deserialize(&bytes).expect("block with qc must decode");
    assert_eq!(
        back.precommit_qc,
        Some(qc.clone()),
        "QC must survive the roundtrip"
    );
    assert_eq!(back.height, block.height);
    assert_eq!(
        bincode::serialize(&back).unwrap(),
        bytes,
        "re-encoding must be byte-identical (canonical form)"
    );

    // The QC is evidence ABOUT the block and is excluded from the block hash:
    // attaching / changing / stripping it must never change block identity,
    // otherwise finalisation would fork the identity of an already-voted block.
    let mut without = block.clone();
    without.precommit_qc = None;
    assert_eq!(
        block.compute_hash(),
        without.compute_hash(),
        "qc must not affect the hash"
    );
    let mut other_qc = block.clone();
    if let Some(q) = other_qc.precommit_qc.as_mut() {
        q.round += 1;
    }
    assert_eq!(
        block.compute_hash(),
        other_qc.compute_hash(),
        "qc content must not affect the hash"
    );

    // A proposal wrapping the finalized block roundtrips too (wire path).
    let msg = ConsensusMsg::Proposal {
        height: 7,
        round: 0,
        block: block.clone(),
    };
    let enc = msg.encode().unwrap();
    match ConsensusMsg::decode(&enc).expect("proposal with qc-bearing block must decode") {
        ConsensusMsg::Proposal { block: b2, .. } => {
            assert_eq!(b2.precommit_qc, Some(qc));
        }
        other => panic!("wrong variant: {other:?}"),
    }

    // --- OLD-FORMAT ASSUMPTION (documented, both directions) ---------------
    //
    // `precommit_qc` was APPENDED as the last field of `Block`. bincode has no
    // self-describing framing and `bincode::deserialize` allows trailing
    // bytes, so:
    //
    //  (a) OLD bytes (no qc field) -> NEW decoder: FAILS CLOSED with an EOF
    //      error. Appending a field is a breaking change for every stored or
    //      gossiped Block: a new binary rejects the old encoding rather than
    //      inventing a default.
    //  (b) NEW bytes (with qc) -> OLD decoder: ACCEPTS and SILENTLY DROPS the
    //      qc (trailing bytes ignored). An un-upgraded peer therefore keeps
    //      working but never sees the certificate — anything that now relies on
    //      `precommit_qc` being present (block sync verifying the QC instead
    //      of bare signatures) degrades on such a peer without an error.
    //  (c) If the qc FIELD ITSELF changes layout (QuorumCertificate gains or
    //      loses a field, or the field moves/reorders), the same rule applies
    //      one level down: new decoders REJECT old encodings (fail-closed, no
    //      silent truncation of the signer list), old decoders accept new
    //      encodings and drop the tail. This is why the field is wire-compat
    //      sensitive in one direction only — upgrades must be simultaneous for
    //      anything that READS the certificate, and hash-stability means the
    //      block identity itself is unaffected either way.
    #[derive(serde::Serialize, serde::Deserialize)]
    struct OldBlock {
        shard_id: stellereum::sharding::ShardId,
        height: u64,
        prev_hash: [u8; 32],
        state_root: [u8; 32],
        transactions: Vec<stellereum::sharding::Transaction>,
        cross_shard_out: Vec<stellereum::sharding::CrossShardMessage>,
        timestamp: u64,
        proposer: [u8; 32],
        validator_signatures: Vec<([u8; 32], Vec<u8>)>,
        // no precommit_qc — the pre-qc Block layout
    }

    // (b) new bytes -> old decoder: accepted, qc dropped.
    let old: OldBlock = bincode::deserialize(&bytes)
        .expect("an old binary must still decode the new block (trailing qc ignored)");
    assert_eq!(old.height, block.height);
    let old_bytes = bincode::serialize(&old).unwrap();
    assert!(
        old_bytes.len() < bytes.len(),
        "the dropped qc must account for the size difference"
    );

    // (a) old bytes -> new decoder: fail closed.
    let err = bincode::deserialize::<Block>(&old_bytes)
        .expect_err("new decoder must REJECT a block that is missing the qc field");
    eprintln!("new Block decoder on old (pre-qc) bytes: {err}");

    // (c) hypothetical change of the qc field layout itself: a QC without the
    // `signatures` field (i.e. the struct grew a field) embedded in a block.
    #[derive(serde::Serialize, serde::Deserialize)]
    struct QcWithoutSignatures {
        height: u64,
        round: u32,
        kind: VoteKind,
        block_hash: Option<[u8; 32]>,
    }
    #[derive(serde::Serialize, serde::Deserialize)]
    struct BlockWithShortQc {
        shard_id: stellereum::sharding::ShardId,
        height: u64,
        prev_hash: [u8; 32],
        state_root: [u8; 32],
        transactions: Vec<stellereum::sharding::Transaction>,
        cross_shard_out: Vec<stellereum::sharding::CrossShardMessage>,
        timestamp: u64,
        proposer: [u8; 32],
        validator_signatures: Vec<([u8; 32], Vec<u8>)>,
        precommit_qc: Option<QcWithoutSignatures>,
        last_qc: Option<stellereum::consensus::QuorumCertificate>,
    }
    let short = BlockWithShortQc {
        shard_id: block.shard_id,
        height: block.height,
        prev_hash: block.prev_hash,
        state_root: block.state_root,
        transactions: block.transactions.clone(),
        cross_shard_out: block.cross_shard_out.clone(),
        timestamp: block.timestamp,
        proposer: block.proposer,
        validator_signatures: block.validator_signatures.clone(),
        precommit_qc: Some(QcWithoutSignatures {
            height: 10,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: Some([7u8; 32]),
        }),
        last_qc: None,
    };
    let short_bytes = bincode::serialize(&short).unwrap();
    let err = bincode::deserialize::<Block>(&short_bytes)
        .expect_err("a changed qc layout must be REJECTED, not partially decoded");
    eprintln!("new Block decoder on changed-qc bytes: {err}");

    // And the same rule holds for the standalone QC type.
    assert!(
        bincode::deserialize::<QuorumCertificate>(
            &bincode::serialize(&QcWithoutSignatures {
                height: 10,
                round: 0,
                kind: VoteKind::Precommit,
                block_hash: Some([7u8; 32]),
            })
            .unwrap()
        )
        .is_err(),
        "changed QuorumCertificate layout must fail closed"
    );
}
