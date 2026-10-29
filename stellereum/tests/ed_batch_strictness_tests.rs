//! Batch-vs-scalar strictness differential (F-MED-6): an S-malleated Ed25519
//! signature must NOT verify in batch while scalar refuses it.
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use stellereum::consensus::{Vote, VoteKind};

fn mkvote(k: &SigningKey) -> Vote {
    let bh = [0xabu8; 32];
    Vote::sign(k, 1, 0, VoteKind::Prevote, Some(bh))
}

// Ed25519 group order L (little-endian).
const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x26, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0x2a, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

fn scalar_lt(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

fn add_l(s: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry: u16 = 0;
    for i in 0..32 {
        let sum = s[i] as u16 + L[i] as u16 + carry;
        out[i] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    out
}

#[test]
fn batch_and_scalar_agree_on_valid_and_garbage() {
    let k = SigningKey::generate(&mut OsRng);
    let v = mkvote(&k);
    assert!(v.verify(), "control: valid vote verifies scalar");
    assert!(
        Vote::verify_batch(std::slice::from_ref(&v)),
        "control: valid batch verifies"
    );
    let mut bad = v.clone();
    bad.signature = vec![0x77u8; 64];
    assert!(!bad.verify(), "garbage refused scalar");
    assert!(
        !Vote::verify_batch(std::slice::from_ref(&bad)),
        "garbage refused batch"
    );
}

#[test]
fn high_s_malleation_must_not_pass_batch_when_scalar_refuses() {
    let k = SigningKey::generate(&mut OsRng);
    let v = mkvote(&k);
    // Malleate S -> S + L (still verifies the equation, non-canonical).
    let raw = v.ed25519_signature().to_vec();
    assert_eq!(raw.len(), 64);
    let mut s = [0u8; 32];
    s.copy_from_slice(&raw[32..]);
    assert!(scalar_lt(&s, &L), "control: original S canonical");
    let s2 = add_l(&s);
    let mut raw2 = raw[..32].to_vec();
    raw2.extend_from_slice(&s2);
    let mut m = v.clone();
    m.signature = raw2;
    assert!(!m.verify(), "high-S must be refused by strict scalar");
    assert!(
        !Vote::verify_batch(std::slice::from_ref(&m)),
        "high-S must ALSO be refused by batch (no strictness gap)"
    );
    assert_eq!(
        Vote::partition_valid(std::slice::from_ref(&m)),
        vec![false],
        "partition must mark malleated vote invalid"
    );
}
