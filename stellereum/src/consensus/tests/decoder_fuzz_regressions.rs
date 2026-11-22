use ed25519_dalek::SigningKey;

use super::*;

#[test]
fn vote_qc_max_prefixes_and_truncations_never_panic() {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let v = Vote::sign(&sk, 1, 0, VoteKind::Prevote, Some([1u8; 32]));
    let enc = bincode::serialize(&v).unwrap();
    for i in 0..enc.len() {
        if i + 8 <= enc.len() {
            let mut m = enc.clone();
            m[i..i + 8].copy_from_slice(&u64::MAX.to_le_bytes());
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _: Result<Vote, _> = bincode::deserialize(&m);
                let _: Result<QuorumCertificate, _> = bincode::deserialize(&m);
            }));
            assert!(r.is_ok(), "vote/qc decode panicked on MAX prefix at {i}");
        }
    }
    for n in 0..enc.len() {
        let t = enc[..n].to_vec();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: Result<Vote, _> = bincode::deserialize(&t);
        }));
        assert!(r.is_ok(), "vote decode panicked on truncation len {n}");
    }
}
