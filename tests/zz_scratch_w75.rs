//! TEMPORARY scratch probe (deleted before the final run).

use ed25519_dalek::SigningKey;
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};

const GOLDEN_TX_BYTES: &str = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c0909090909090909090909090909090909090909090909090909090909090909e8030000000000003200000000000000030000000000000001000000010000004000000000000000ec92a88d6c30df1625df08d1172e2baecf20964110ce727278849ee953418106c995e7ac322958b6ea6910abe8a7c55f709d5fe935ae09a53fa099b843dee8060000000000000000";
const GOLDEN_BLOCK_BYTES: &str = "000000000100000000000000000000000000000000000000000000000000000000000000000000000000000002020202020202020202020202020202020202020202020202020202020202020100000000000000ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c0909090909090909090909090909090909090909090909090909090909090909e8030000000000003200000000000000030000000000000001000000010000004000000000000000ec92a88d6c30df1625df08d1172e2baecf20964110ce727278849ee953418106c995e7ac322958b6ea6910abe8a7c55f709d5fe935ae09a53fa099b843dee8060000000000000000000000000000000000f1536500000000ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c0100000000000000ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c40000000000000003d12d67dfedc7232b0bef033e5182e4dfde39cb6255567a82e0eee1e76b4bd9c25be7ce4374cca6fd75128f79201c184069972b9b753a89f62b3cd887c4a470300";

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex")
}

#[test]
fn probe() {
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let tx: Transaction = bincode::deserialize(&h(GOLDEN_TX_BYTES)).unwrap();
    let raw_block = h(GOLDEN_BLOCK_BYTES);
    println!("raw_block len = {}", raw_block.len());

    let decoded: Result<Block, _> = bincode::deserialize(&raw_block);
    println!("strict decode: {:?}", decoded.is_ok());

    let legacy: Block = stellereum::sharding::with_legacy_block_tolerance(|| {
        bincode::deserialize(&raw_block).unwrap()
    });
    println!(
        "legacy block: height={} shard={} ts={} txs={} sigs={} order_root={:?}",
        legacy.height,
        legacy.shard_id,
        legacy.timestamp,
        legacy.transactions.len(),
        legacy.validator_signatures.len(),
        legacy.order_merkle_root
    );
    println!("legacy hash   = {}", hex::encode(legacy.compute_hash()));

    // Rebuilt with the DERIVED order root.
    let txs = vec![tx.clone()];
    let omr = stellereum::mev::compute_order_merkle_root(&txs);
    println!("order_merkle_root = {}", hex::encode(omr));
    let mut rebuilt = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 1,
        prev_hash: [0u8; 32],
        state_root: [2u8; 32],
        transactions: txs,
        cross_shard_out: vec![],
        timestamp: 1_700_000_000,
        proposer: sk.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: omr,
        epoch_key_commitment: [0u8; 32],
    };
    rebuilt.sign_block(&sk);
    println!(
        "rebuilt(omr) hash = {}",
        hex::encode(rebuilt.compute_hash())
    );

    let mut rebuilt0 = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 1,
        prev_hash: [0u8; 32],
        state_root: [2u8; 32],
        transactions: vec![tx.clone()],
        cross_shard_out: vec![],
        timestamp: 1_700_000_000,
        proposer: sk.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    rebuilt0.sign_block(&sk);
    println!(
        "rebuilt(zero) hash = {}",
        hex::encode(rebuilt0.compute_hash())
    );

    let re = bincode::serialize(&rebuilt).unwrap();
    println!(
        "re(omr) len = {} (raw {}) diff = {}",
        re.len(),
        raw_block.len(),
        re.len() as i64 - raw_block.len() as i64
    );
    let re0 = bincode::serialize(&rebuilt0).unwrap();
    println!(
        "re(zero) len = {} diff = {}",
        re0.len(),
        re0.len() as i64 - raw_block.len() as i64
    );
    println!(
        "prefix match (zero): {}",
        re0[..raw_block.len()] == raw_block[..]
    );
    println!("chain id = {}", stellereum::consensus::consensus_chain_id());
    println!("tx hash = {}", hex::encode(tx.compute_tx_hash()));
}

#[test]
fn probe2() {
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let _tx: Transaction = bincode::deserialize(&h(GOLDEN_TX_BYTES)).unwrap();
    let raw_block = h(GOLDEN_BLOCK_BYTES);
    let legacy: Block = stellereum::sharding::with_legacy_block_tolerance(|| {
        bincode::deserialize(&raw_block).unwrap()
    });
    println!("legacy sigs = {:?}", legacy.validator_signatures);
    println!("legacy qc = {:?}", legacy.precommit_qc.is_some());
    println!("legacy tx = {:?}", legacy.transactions[0].compute_tx_hash());
    let re = bincode::serialize(&legacy).unwrap();
    println!("re len {}", re.len());
    for i in 0..raw_block.len().min(re.len()) {
        if raw_block[i] != re[i] {
            println!(
                "first diff at byte {}: raw={:02x} re={:02x}",
                i, raw_block[i], re[i]
            );
            println!(
                "raw  ctx: {}",
                hex::encode(&raw_block[i.saturating_sub(8)..(i + 24).min(raw_block.len())])
            );
            println!(
                "re   ctx: {}",
                hex::encode(&re[i.saturating_sub(8)..(i + 24).min(re.len())])
            );
            break;
        }
    }
    let _ = sk;
}

#[test]
fn probe3() {
    use ed25519_dalek::Signer;
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let _tx: Transaction = bincode::deserialize(&h(GOLDEN_TX_BYTES)).unwrap();
    let raw_block = h(GOLDEN_BLOCK_BYTES);
    let legacy: Block = stellereum::sharding::with_legacy_block_tolerance(|| {
        bincode::deserialize(&raw_block).unwrap()
    });
    println!(
        "legacy proposer sig verifies: {}",
        legacy.verify_proposer_signature()
    );
    let old_hash =
        hex::decode("9031e6d999be635fe8530173e3c8cf3524c6876b9faa142ef83343a06870a2b3").unwrap();
    let mut o = [0u8; 32];
    o.copy_from_slice(&old_hash);
    let sig_old = sk.sign(&o);
    println!("sig over OLD hash : {}", hex::encode(sig_old.to_bytes()));
    println!(
        "stored signature  : {}",
        hex::encode(&legacy.validator_signatures[0].1)
    );
    let new_hash = legacy.compute_hash();
    let sig_new = sk.sign(&new_hash);
    println!("sig over NEW hash : {}", hex::encode(sig_new.to_bytes()));
}
