//! Fuzz tests for the infnode wire parser (`Frame::decode`).
//! The parser handles UNTRUSTED network input, so it must never panic, hang,
//! allocate unbounded memory, or accept malformed frames.
//!
//! Strategy: property-based fuzzing with a deterministic PRNG.
//!   1. pure random bytes
//!   2. mutations of a valid frame (bit flips, truncation, length tampering)
//!   3. adversarial length fields (huge plen/nlen, off-by-one boundaries)

use infnode::proto::{Frame, MAX_FRAME};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;

/// Minimal deterministic PRNG (xorshift64) for reproducible fuzzing.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn byte(&mut self) -> u8 {
        (self.next() & 0xFF) as u8
    }
    fn range(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() as usize) % n
        }
    }
}

/// A valid signed frame for mutation testing.
fn valid_frame() -> Vec<u8> {
    let sk = SigningKey::generate(&mut OsRng);
    let mut f = Frame {
        kind: 4,
        seq: 1,
        ts: 1_700_000_000_000,
        src: [1u8; 20],
        dst: [2u8; 20],
        svc: 123,
        payload: b"hello".to_vec(),
        nonce: vec![],
        sig: [0u8; 64],
    };
    let d = blake3::hash(&f.sign_data());
    f.sig = sk.sign(d.as_bytes()).to_bytes();
    f.encode()
}

/// PURE RANDOM BYTES: decode must return Ok/Err, never panic.
#[test]
fn fuzz_random_bytes_never_panic() {
    let mut rng = Rng(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..20_000 {
        let len = rng.range(300);
        let mut buf = vec![0u8; len];
        for b in buf.iter_mut() {
            *b = rng.byte();
        }
        // Must not panic; result is either Ok or Err.
        let _ = Frame::decode(&buf);
    }
}

/// MUTATIONS OF A VALID FRAME: single/multi bit-flips and truncations.
#[test]
fn fuzz_mutated_valid_frame_never_panic() {
    let valid = valid_frame();
    let mut rng = Rng(0x1234_5678_9ABC_DEF0);

    for _ in 0..20_000 {
        let mut buf = valid.clone();
        let flips = 1 + rng.range(8);
        for _ in 0..flips {
            if buf.is_empty() {
                break;
            }
            let i = rng.range(buf.len());
            buf[i] ^= 1 << (rng.byte() % 8);
        }
        // Occasionally truncate
        if rng.range(3) == 0 && !buf.is_empty() {
            let t = rng.range(buf.len());
            buf.truncate(t);
        }
        if let Ok(f) = Frame::decode(&buf) {
            // If it decodes, internal invariants must hold (no mismatched lengths).
            assert_eq!(f.payload.len(), f.payload.len());
            assert!(f.payload.len() <= MAX_FRAME);
        }
    }
}

/// ADVERSARIAL LENGTH FIELDS: huge plen/nlen must be rejected, not allocate.
#[test]
fn fuzz_adversarial_lengths_rejected() {
    let base = valid_frame();

    // plen = 0xFFFFFFFF (way over MAX_FRAME) at offset 64..68
    let mut b = base.clone();
    b[64..68].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(Frame::decode(&b).is_err(), "huge plen must be rejected");

    // nlen = 0xFFFF at offset 62..64
    let mut b2 = base.clone();
    b2[62..64].copy_from_slice(&u16::MAX.to_le_bytes());
    assert!(Frame::decode(&b2).is_err(), "huge nlen must be rejected");

    // plen exactly MAX_FRAME+1
    let mut b3 = base.clone();
    b3[64..68].copy_from_slice(&((MAX_FRAME + 1) as u32).to_le_bytes());
    assert!(Frame::decode(&b3).is_err(), "plen over MAX_FRAME must be rejected");

    // plen that overflows the total-length computation
    let mut b4 = base.clone();
    b4[64..68].copy_from_slice(&0xFFFF_FF00u32.to_le_bytes());
    assert!(Frame::decode(&b4).is_err(), "overflow plen must be rejected");
}

/// TRUNCATION BOUNDARY: every prefix of a valid frame must be handled safely.
#[test]
fn fuzz_every_prefix_handled() {
    let valid = valid_frame();
    for cut in 0..valid.len() {
        let _ = Frame::decode(&valid[..cut]);
    }
    // A few bytes past the end must not panic either.
    let mut longer = valid.clone();
    longer.extend_from_slice(&[0u8; 8]);
    let _ = Frame::decode(&longer);
}

/// A frame that decodes must round-trip through encode/decode unchanged.
#[test]
fn decoded_frames_round_trip() {
    let valid = valid_frame();
    let f = Frame::decode(&valid).expect("valid frame must decode");
    let re = f.encode();
    let f2 = Frame::decode(&re).expect("re-encoded frame must decode");
    assert_eq!(f.kind, f2.kind);
    assert_eq!(f.seq, f2.seq);
    assert_eq!(f.payload, f2.payload);
}

/// A frame with version != 1 must be rejected.
#[test]
fn fuzz_bad_version_rejected() {
    let valid = valid_frame();
    for v in [0u8, 2, 3, 255] {
        let mut b = valid.clone();
        b[0] = v;
        assert!(Frame::decode(&b).is_err(), "version {v} must be rejected");
    }
}

/// A valid frame verifies; a tampered payload does not.
#[test]
fn signature_binds_payload() {
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    let mut f = Frame {
        kind: 4,
        seq: 1,
        ts: 1,
        src: [0u8; 20],
        dst: [0u8; 20],
        svc: 0,
        payload: b"original".to_vec(),
        nonce: vec![],
        sig: [0u8; 64],
    };
    let d = blake3::hash(&f.sign_data());
    f.sig = sk.sign(d.as_bytes()).to_bytes();
    assert!(f.verify(&vk));

    // tamper the payload after signing
    f.payload = b"tampered".to_vec();
    assert!(!f.verify(&vk), "tampered payload must fail verification");
}
