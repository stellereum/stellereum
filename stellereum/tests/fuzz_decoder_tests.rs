//! Decoder fuzzing (deterministic, stable-toolchain).
//!
//! Everything a peer sends is untrusted; a panic on malformed input is a
//! remote DoS. Targets:
//!   (1) infnode `Frame::decode` (network entry point),
//!   (2) `parse_incoming` / `parse_tx_incoming` / `ConsensusMsg::decode`,
//!   (3) `Transaction` bincode decode (size, opcode count, length prefixes),
//!   (4) `Block` decode incl. `validator_signatures`.
//!
//! Strategy per target: empty, truncated, byte-flips, oversized lengths, MAX
//! length-prefix counts, and fixed-seed pseudo-random blobs. Every case asserts
//! the decoder *never panics*; well-formedness assertions (Err/None) are added
//! only where the contract guarantees rejection.
//!
//! The same inputs back the `cargo-fuzz` targets in `fuzz/fuzz_targets/` for
//! nightly libFuzzer runs: `cargo +nightly fuzz run <target>`.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use stellereum::consensus::{QuorumCertificate, Vote, VoteKind};
use stellereum::consensus_net::{parse_incoming, parse_tx_incoming, ConsensusMsg};
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};

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
// Valid corpus builders (mutation starting points).
// ---------------------------------------------------------------------------

fn valid_frame() -> Vec<u8> {
    let f = infnode::proto::Frame {
        kind: infnode::proto::kind::REQ,
        seq: 7,
        ts: 1_700_000_000_000,
        src: [1u8; 20],
        dst: [2u8; 20],
        svc: 42,
        payload: b"hello-consensus".to_vec(),
        nonce: vec![0u8; 12],
        sig: [9u8; 64],
    };
    f.encode()
}

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

fn valid_consensus_vote() -> Vec<u8> {
    let sk = SigningKey::generate(&mut OsRng);
    let v = Vote::sign(&sk, 3, 1, VoteKind::Prevote, Some([9u8; 32]));
    ConsensusMsg::Vote {
        vote: v,
        locked: None,
    }
    .encode()
    .unwrap()
}

fn valid_consensus_proposal() -> Vec<u8> {
    ConsensusMsg::Proposal {
        height: 7,
        round: 0,
        block: sample_block(),
    }
    .encode()
    .unwrap()
}

fn sample_tx() -> Transaction {
    let sk = SigningKey::generate(&mut OsRng);
    Transaction::sign(&sk, [1u8; 32], 10, 5, 0, 1, 1)
}

fn valid_tx() -> Vec<u8> {
    bincode::serialize(&sample_tx()).unwrap()
}

fn valid_block() -> Vec<u8> {
    bincode::serialize(&sample_block()).unwrap()
}

// ---------------------------------------------------------------------------
// Mutation generators.
// ---------------------------------------------------------------------------

/// Every strict prefix (empty .. len-1). The full input is NOT included.
fn truncations(data: &[u8]) -> Vec<Vec<u8>> {
    (0..data.len()).map(|n| data[..n].to_vec()).collect()
}

/// Every position x {0x00, 0xFF, bit-flipped}. Caller caps input size.
fn exhaustive_flips(data: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len() * 3);
    for (i, b) in data.iter().enumerate() {
        for v in [0x00u8, 0xFFu8, b ^ 0x01] {
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

/// `count` random single/multi-byte substitutions from a fixed seed.
fn sampled_flips(data: &[u8], seed: u64, count: usize) -> Vec<Vec<u8>> {
    let mut rng = Rng(seed);
    (0..count)
        .map(|_| {
            let mut m = data.to_vec();
            let n = 1 + rng.below(4);
            for _ in 0..n {
                let i = rng.below(m.len());
                m[i] = rng.next_u64() as u8;
            }
            m
        })
        .collect()
}

/// Overwrite the 8/4/2-byte length prefix at every offset with MAX
/// (bincode uses u64 LE lengths; Frame header uses u32 plen + u16 nlen).
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
            // Cycle lengths: tiny headers, mid sizes, occasional big ones.
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
    let mut first_idx: Option<usize> = None;
    let mut first_len: Option<usize> = None;
    for (i, input) in inputs.iter().enumerate() {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(input)));
        if r.is_err() {
            panics += 1;
            if first_idx.is_none() {
                first_idx = Some(i);
                first_len = Some(input.len());
            }
        }
    }
    assert_eq!(
        panics, 0,
        "{name}: {panics} panicking inputs (first idx {first_idx:?}, len {first_len:?})"
    );
}

// ---------------------------------------------------------------------------
// (1) infnode Frame::decode — the network entry point.
// ---------------------------------------------------------------------------

#[test]
fn frame_empty_and_truncated_rejected_without_panic() {
    // Empty must be rejected.
    assert!(infnode::proto::Frame::decode(&[]).is_err());
    let valid = valid_frame();
    assert!(infnode::proto::Frame::decode(&valid).is_ok());
    // Every strict prefix must be rejected (short header / length mismatch).
    let mut rejected = 0;
    for t in truncations(&valid) {
        if infnode::proto::Frame::decode(&t).is_err() {
            rejected += 1;
        }
    }
    assert_eq!(
        rejected,
        valid.len(),
        "all {} prefixes must be rejected",
        valid.len()
    );
    assert_never_panics("frame/truncate", truncations(&valid), |b| {
        let _ = infnode::proto::Frame::decode(b);
    });
}

#[test]
fn frame_oversized_lengths_rejected_without_panic() {
    let valid = valid_frame();
    // Header layout: [0]=ver [1]=kind [2..6]=seq [6..14]=ts [14..34]=src
    // [34..54]=dst [54..62]=svc [62..64]=nlen u16 LE [64..68]=plen u32 LE.
    let mut cases: Vec<Vec<u8>> = Vec::new();
    // plen claims more than the 32 MiB cap.
    for plen in [
        u32::MAX,
        (infnode::proto::MAX_FRAME as u32) + 1,
        0x0100_0000u32,
    ] {
        let mut m = valid.clone();
        m[64..68].copy_from_slice(&plen.to_le_bytes());
        cases.push(m);
    }
    // nlen claims far more than present.
    for nlen in [u16::MAX, 0x4000u16] {
        let mut m = valid.clone();
        m[62..64].copy_from_slice(&nlen.to_le_bytes());
        cases.push(m);
    }
    // plen/nlen individually small but jointly inconsistent with total length.
    let mut m = valid.clone();
    m[64..68].copy_from_slice(&0u32.to_le_bytes());
    m[62..64].copy_from_slice(&0u16.to_le_bytes());
    cases.push(m);
    // Bad version byte (valid length, wrong version).
    let mut m = valid.clone();
    m[0] = 0xFF;
    cases.push(m);
    let mut m = valid;
    m[0] = 2;
    cases.push(m);

    for c in &cases {
        assert!(
            infnode::proto::Frame::decode(c).is_err(),
            "oversized/mismatched frame must be rejected (len {})",
            c.len()
        );
    }
    assert_never_panics("frame/oversize", cases, |b| {
        let _ = infnode::proto::Frame::decode(b);
    });
}

#[test]
fn frame_byte_flips_and_seeded_random_never_panic() {
    let valid = valid_frame();
    let mut inputs = exhaustive_flips(&valid);
    inputs.extend(sampled_flips(&valid, 0x0F2A_4E11_u64, 2000));
    inputs.extend(seeded_blobs(0xB10C_C0DE_u64, 3000, 512));
    assert_never_panics("frame/flips+random", inputs, |b| {
        let _ = infnode::proto::Frame::decode(b);
    });
}

// ---------------------------------------------------------------------------
// (2) ConsensusMsg::decode + parse_incoming + parse_tx_incoming.
// ---------------------------------------------------------------------------

#[test]
fn consensus_msg_empty_truncated_flips_never_panic() {
    assert!(ConsensusMsg::decode(&[]).is_err());
    for valid in [valid_consensus_vote(), valid_consensus_proposal()] {
        assert!(ConsensusMsg::decode(&valid).is_ok());
        let mut inputs = truncations(&valid);
        // Strict prefixes of a valid encoding must be rejected, never panic.
        for t in &inputs {
            assert!(
                ConsensusMsg::decode(t).is_err(),
                "prefix of len {} must be rejected",
                t.len()
            );
        }
        inputs.extend(exhaustive_flips(&valid));
        inputs.extend(max_length_prefixes(&valid));
        assert_never_panics("consensus/decode", inputs, |b| {
            let _ = ConsensusMsg::decode(b);
        });
    }
}

#[test]
fn consensus_msg_oversized_rejected_without_panic() {
    let big = vec![0u8; stellereum::consensus_net::MAX_CONSENSUS_MSG + 1];
    assert!(ConsensusMsg::decode(&big).is_err());
    // A valid message with trailing garbage: documents bincode trailing-byte
    // behavior (see accepted_but_should_reject report below).
    let mut inputs = vec![big];
    inputs.extend(seeded_blobs(0x0C01_1555_u64, 2000, 512));
    assert_never_panics("consensus/oversize+random", inputs, |b| {
        let _ = ConsensusMsg::decode(b);
    });
}

#[test]
fn parse_incoming_fail_closed_on_fuzz() {
    // Fixed malformed shapes.
    for raw in [
        String::from(""),
        String::from("not json"),
        String::from("{}"),
        String::from(r#"{"data": 123}"#),
        String::from(r#"{"data": null}"#),
        String::from(r#"{"data": "zzzz"}"#), // bad hex
        String::from(r#"{"topic": "x"}"#),   // missing data
        format!(r#"{{"data": "{}"}}"#, "ff".repeat(1024)), // valid hex, garbage payload
        // oversized for ConsensusMsg (32 MiB cap) must be rejected even as hex
        format!(
            r#"{{"data": "{}"}}"#,
            "00".repeat(stellereum::consensus_net::MAX_CONSENSUS_MSG + 1)
        ),
    ] {
        assert!(
            parse_incoming(&raw).is_none(),
            "must be fail-closed: {raw:.60}"
        );
        assert!(
            parse_tx_incoming(&raw).is_none(),
            "must be fail-closed: {raw:.60}"
        );
    }
    // Fuzz the JSON envelope itself: random blobs as `raw`, plus random hex in
    // a well-formed envelope.
    let mut rng = Rng(0x009A_11C5_u64);
    let mut inputs: Vec<String> = seeded_blobs(0x009A_11C5_u64, 1500, 256)
        .into_iter()
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .collect();
    for _ in 0..1500 {
        let hexlen = rng.below(300);
        let data = hex::encode(rng.bytes(hexlen));
        inputs.push(format!(r#"{{"topic": "t", "data": "{data}"}}"#));
    }
    let mut panics = 0;
    for raw in &inputs {
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| parse_incoming(raw))).is_err() {
            panics += 1;
        }
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| parse_tx_incoming(raw)))
            .is_err()
        {
            panics += 1;
        }
    }
    assert_eq!(
        panics, 0,
        "parse_incoming/parse_tx_incoming panicked on {panics} inputs"
    );
    // A well-formed envelope around a valid message still parses.
    let data = hex::encode(valid_consensus_vote());
    let raw = serde_json::json!({ "topic": "t", "data": data }).to_string();
    assert!(matches!(
        parse_incoming(&raw),
        Some(ConsensusMsg::Vote { .. })
    ));
    let data = hex::encode(valid_tx());
    let raw = serde_json::json!({ "topic": "t", "data": data }).to_string();
    assert!(parse_tx_incoming(&raw).is_some());
}

#[test]
fn parse_tx_incoming_size_bounds_hold_on_fuzz() {
    assert!(
        parse_tx_incoming(r#"{"data": ""}"#).is_none(),
        "empty must be rejected"
    );
    // Oversized payload (> 1 MiB) is rejected even if it would decode.
    let big_hex = hex::encode(vec![0u8; stellereum::consensus_net::MAX_TX_MSG + 1]);
    let raw = serde_json::json!({ "data": big_hex }).to_string();
    assert!(parse_tx_incoming(&raw).is_none());
    // Boundary: exactly MAX_TX_MSG bytes of garbage is *not* size-rejected
    // (it fails decode instead) — and must not panic either way.
    let edge_hex = hex::encode(vec![0xABu8; stellereum::consensus_net::MAX_TX_MSG]);
    let raw = serde_json::json!({ "data": edge_hex }).to_string();
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| parse_tx_incoming(&raw)));
    assert!(r.is_ok(), "boundary-size input panicked");
    assert!(r.unwrap().is_none());
}

// ---------------------------------------------------------------------------
// (3) Transaction bincode decode: size, opcode count, length prefixes.
// ---------------------------------------------------------------------------

fn decode_tx(b: &[u8]) -> Result<Transaction, Box<bincode::ErrorKind>> {
    bincode::deserialize(b)
}

#[test]
fn transaction_empty_truncated_flips_maxprefix_random_never_panic() {
    let valid = valid_tx();
    assert!(decode_tx(&valid).is_ok());
    assert!(decode_tx(&[]).is_err());
    let mut inputs = truncations(&valid);
    for t in &inputs {
        assert!(
            decode_tx(t).is_err(),
            "tx prefix of len {} must be rejected",
            t.len()
        );
    }
    inputs.extend(exhaustive_flips(&valid));
    inputs.extend(max_length_prefixes(&valid));
    inputs.extend(seeded_blobs(0x7A_C1u64, 3000, 512));
    assert_never_panics("tx/decode", inputs, |b| {
        let _ = decode_tx(b);
    });
}

#[test]
fn transaction_oversized_and_maxcount_prefixes_never_panic() {
    // Length-prefix attack shapes: signature Vec len = MAX, payload vec len =
    // MAX, and every-4-byte u32::MAX sweep over a minimal tx encoding.
    let valid = valid_tx();
    let mut inputs = max_length_prefixes(&valid);
    // Signature length field lives right after from/to/amount/gas/nonce/shards
    // (32+32+8+8+8+4+4 = 96); also try common small-but-huge counts there.
    for siglen in [0xFFFF_FFFFu64, 0x00FF_FFFFu64, 0x0000_FFFFu64, 1_000_000u64] {
        if valid.len() >= 104 {
            let mut m = valid.clone();
            m[96..104].copy_from_slice(&siglen.to_le_bytes());
            inputs.push(m);
        }
    }
    for m in &inputs {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| decode_tx(m)));
        assert!(
            r.is_ok(),
            "tx length-prefix input (len {}) panicked",
            m.len()
        );
    }
    // A tx with a large-but-valid opcode payload still decodes (scale check).
    let sk = SigningKey::generate(&mut OsRng);
    let payload = vec![stellereum::svm::OpCode::Nop; 1024];
    let big = Transaction::sign_with_payload(&sk, [3u8; 32], 1, 100_000, 0, 1, 1, payload);
    let enc = bincode::serialize(&big).unwrap();
    assert!(decode_tx(&enc).is_ok());
    assert_never_panics("tx/maxprefix", inputs, |b| {
        let _ = decode_tx(b);
    });
}

// ---------------------------------------------------------------------------
// (4) Block decode incl. validator_signatures.
// ---------------------------------------------------------------------------

fn decode_block(b: &[u8]) -> Result<Block, Box<bincode::ErrorKind>> {
    bincode::deserialize(b)
}

#[test]
fn block_empty_truncated_flips_maxprefix_random_never_panic() {
    let valid = valid_block();
    assert!(decode_block(&valid).is_ok());
    assert!(decode_block(&[]).is_err());
    let mut inputs = truncations(&valid);
    for t in &inputs {
        assert!(
            decode_block(t).is_err(),
            "block prefix of len {} must be rejected",
            t.len()
        );
    }
    inputs.extend(exhaustive_flips(&valid));
    inputs.extend(max_length_prefixes(&valid));
    inputs.extend(seeded_blobs(0x000B_10C4_u64, 3000, 1024));
    assert_never_panics("block/decode", inputs, |b| {
        let _ = decode_block(b);
    });
}

#[test]
fn block_validator_signatures_abuse_never_panics() {
    // validator_signatures is Vec<([u8;32], Vec<u8>)>: fuzz the outer count
    // and the inner per-signature length prefixes.
    let valid = valid_block();
    let inputs = max_length_prefixes(&valid);
    // A block carrying many signatures decodes at scale (functional check).
    let mut many = sample_block();
    for i in 0..64u8 {
        let sk = SigningKey::generate(&mut OsRng);
        let mut m = many.clone();
        m.proposer = sk.verifying_key().to_bytes();
        m.validator_signatures.clear();
        m.sign_block(&sk);
        many.validator_signatures.extend(m.validator_signatures);
        let _ = i;
    }
    let enc = bincode::serialize(&many).unwrap();
    assert!(decode_block(&enc).is_ok());
    // Duplicate signers and empty signature bytes decode (verification, not
    // decoding, rejects them) — pinned here, see report below.
    let mut dup = sample_block();
    let sig = dup.validator_signatures.first().cloned().unwrap();
    dup.validator_signatures.push(sig.clone());
    dup.validator_signatures.push(sig);
    let enc = bincode::serialize(&dup).unwrap();
    assert!(
        decode_block(&enc).is_ok(),
        "duplicates must decode (verify dedups)"
    );
    assert_never_panics("block/sigs", inputs, |b| {
        let _ = decode_block(b);
    });
}

#[test]
fn vote_and_qc_decode_never_panic() {
    let sk = SigningKey::generate(&mut OsRng);
    let v = Vote::sign(&sk, 1, 0, VoteKind::Precommit, Some([5u8; 32]));
    let venv = bincode::serialize(&v).unwrap();
    assert!(bincode::deserialize::<Vote>(&venv).is_ok());
    let qc = QuorumCertificate {
        height: 1,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some([5u8; 32]),
        signatures: vec![(v.voter, v.signature.clone())],
    };
    let qenv = bincode::serialize(&qc).unwrap();
    assert!(bincode::deserialize::<QuorumCertificate>(&qenv).is_ok());
    let mut inputs = truncations(&venv);
    inputs.extend(exhaustive_flips(&venv));
    inputs.extend(max_length_prefixes(&venv));
    inputs.extend(truncations(&qenv));
    inputs.extend(max_length_prefixes(&qenv));
    inputs.extend(seeded_blobs(0x90_7Eu64, 2000, 512));
    assert_never_panics("vote-qc/decode", inputs, |b| {
        let _: Result<Vote, _> = bincode::deserialize(b);
        let _: Result<QuorumCertificate, _> = bincode::deserialize(b);
    });
}

// ---------------------------------------------------------------------------
// Accepted-but-should-reject classes (documented, pinned by tests).
// ---------------------------------------------------------------------------

#[test]
fn report_trailing_bytes_are_accepted_by_bincode_decoders() {
    // SPLIT HARDENING (PENTEST F1): the WIRE path `ConsensusMsg::decode` now uses
    // `reject_trailing_bytes` and fails closed on suffixes; raw
    // `bincode::deserialize` of plain structs still accepts them. The pin
    // documents both: wire-rejected, struct-tolerant.
    let mut v = valid_consensus_vote();
    v.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    v.extend_from_slice(&[0xFFu8; 64]);
    assert!(
        ConsensusMsg::decode(&v).is_err(),
        "trailing bytes must now be rejected by ConsensusMsg::decode (wire hardening)"
    );
    let mut t = valid_tx();
    t.extend_from_slice(&[1, 2, 3, 4]);
    assert!(
        decode_tx(&t).is_ok(),
        "raw bincode Transaction decode still tolerates trailing bytes (callers must use the exact-fit Transaction::decode on the wire path)"
    );
    let mut b = valid_block();
    b.extend_from_slice(&[9u8; 32]);
    assert!(
        decode_block(&b).is_ok(),
        "raw bincode Block decode still tolerates trailing bytes (wire path must reject)"
    );
}

#[test]
fn report_all_zero_payloads_decode_as_valid_messages() {
    // SPLIT HARDENING (PENTEST F1 `reject_trailing_bytes`): a 1024-zero blob
    // no longer decodes as a height-0 Proposal — the zero prefix is a valid
    // Vote-shaped prefix but the surplus zeros are trailing bytes, so the
    // wire `ConsensusMsg::decode` fails closed (None). The plain-tx path
    // still uses lenient `bincode::deserialize`, so a 256-zero blob still
    // decodes as a zero tx (rejected downstream by signature verification).
    let raw = serde_json::json!({ "data": "00".repeat(1024) }).to_string();
    assert!(
        parse_incoming(&raw).is_none(),
        "zero blob must now fail closed on the wire path (trailing-bytes hardening)"
    );
    let raw = serde_json::json!({ "data": "00".repeat(256) }).to_string();
    let tx = parse_tx_incoming(&raw).expect("zero tx currently decodes");
    assert!(
        !tx.verify_signature(),
        "zero tx must fail signature verification"
    );
}

#[test]
fn report_decode_accepts_semantically_invalid_values() {
    // Decoding succeeds for values that only VERIFICATION rejects. Any path
    // that decodes without verifying inherits these as live inputs:
    //  - Vote with empty / overlong signature bytes;
    //  - Transaction with empty / 1 KiB signature;
    //  - Block with zero signatures, duplicate signers, or 1 MiB signatures;
    //  - CrossShardMessage with trusted=true (verify_inclusion bypass flag).
    let sk = SigningKey::generate(&mut OsRng);
    let mut v = Vote::sign(&sk, 1, 0, VoteKind::Prevote, Some([1u8; 32]));
    v.signature.clear();
    let enc = bincode::serialize(&v).unwrap();
    let back: Vote = bincode::deserialize(&enc).unwrap();
    assert!(!back.verify());

    let mut tx = sample_tx();
    tx.signature = vec![0u8; 1024];
    let enc = bincode::serialize(&tx).unwrap();
    let back: Transaction = bincode::deserialize(&enc).unwrap();
    assert!(!back.verify_signature());

    let mut b = sample_block();
    b.validator_signatures.clear();
    let enc = bincode::serialize(&b).unwrap();
    assert!(bincode::deserialize::<Block>(&enc).is_ok());

    let x = stellereum::sharding::CrossShardMessage::new_trusted(
        1,
        2,
        sample_tx(),
        [0u8; 32],
        [0u8; 32],
    );
    let enc = bincode::serialize(&x).unwrap();
    let back: stellereum::sharding::CrossShardMessage = bincode::deserialize(&enc).unwrap();
    assert!(back.trusted, "trusted=true survives a decode round-trip");
}
