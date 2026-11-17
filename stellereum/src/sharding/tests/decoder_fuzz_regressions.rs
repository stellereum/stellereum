/// Decoder fuzz regressions (Agent 1): Transaction/Block bincode decode must
/// never panic on peer bytes (length-prefix / opcode-count / sig abuse).
/// Appended without touching existing code.
use super::*;

#[test]
fn tx_and_block_max_prefixes_never_panic() {
    let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let tx = Transaction::sign(&sk, [1u8; 32], 10, 5, 0, 1, 1);
    let enc = bincode::serialize(&tx).unwrap();
    let transactions = vec![tx];
    let order_merkle_root = crate::mev::compute_order_merkle_root(&transactions);
    let mut block = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 1,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions,
        cross_shard_out: vec![],
        timestamp: 0,
        proposer: sk.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
        cnvrf_v3: None,
    };
    block.sign_block(&sk);
    let benc = bincode::serialize(&block).unwrap();
    for base in [&enc, &benc] {
        for i in 0..base.len() {
            if i + 8 <= base.len() {
                let mut m = base.clone();
                m[i..i + 8].copy_from_slice(&u64::MAX.to_le_bytes());
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _: Result<Transaction, _> = bincode::deserialize(&m);
                    let _: Result<Block, _> = bincode::deserialize(&m);
                }));
                assert!(r.is_ok(), "decode panicked on MAX prefix at {i}");
            }
        }
        for n in 0..base.len() {
            let t = base[..n].to_vec();
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _: Result<Transaction, _> = bincode::deserialize(&t);
                let _: Result<Block, _> = bincode::deserialize(&t);
            }));
            assert!(r.is_ok(), "decode panicked on truncation len {n}");
        }
    }
}
