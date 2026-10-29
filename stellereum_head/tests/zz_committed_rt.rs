use stellereum::consensus::{QuorumCertificate, Vote, VoteKind, ValidatorSet};
use stellereum::consensus_net::ConsensusMsg;
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
#[test]
fn committed_with_qc_roundtrips() {
    let ks: Vec<SigningKey> = (0..2).map(|_| SigningKey::generate(&mut OsRng)).collect();
    let bh = [5u8; 32];
    let sigs: Vec<([u8;32], Vec<u8>)> = ks.iter().map(|k| {
        let v = Vote::sign(k, 9, 0, VoteKind::Precommit, Some(bh));
        (v.voter, v.signature)
    }).collect();
    let qc = QuorumCertificate { height: 9, round: 0, kind: VoteKind::Precommit, block_hash: Some(bh), signatures: sigs };
    let mut b = Block { shard_id: MASTERCHAIN_SHARD, height: 9, prev_hash: [0u8;32], state_root: [1u8;32], transactions: vec![], cross_shard_out: vec![], timestamp: 1, proposer: [2u8;32], validator_signatures: vec![], precommit_qc: Some(qc) };
    b.sign_block(&ks[0]);
    let msg = ConsensusMsg::Committed { height: 9, block: b, certificate: QuorumCertificate { height: 9, round: 0, kind: VoteKind::Precommit, block_hash: Some(bh), signatures: vec![] } };
    let bytes = msg.encode().unwrap();
    println!("committed bytes: {}", bytes.len());
    let back = ConsensusMsg::decode(&bytes).unwrap();
    assert!(matches!(back, ConsensusMsg::Committed { .. }));
}
