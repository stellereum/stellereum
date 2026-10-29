//! SCRATCH: probe whether a cross-shard transfer produced at height >= 2 can
//! still be anchored (and therefore consumed) by the target shard.

use std::sync::Arc;
use ed25519_dalek::SigningKey;
use stellereum::runtime::ShardedCluster;
use stellereum::state_engine::{InMemoryStateEngine, AccountState};
use stellereum::sharding::{
    ShardRegistry, MASTERCHAIN_SHARD, BASE_WORKCHAIN_SHARD_INITIAL, Transaction,
};
use stellereum::network::CrossShardTransport;

const SHARD0: u32 = MASTERCHAIN_SHARD;
const SHARD1: u32 = BASE_WORKCHAIN_SHARD_INITIAL;

fn test_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

#[tokio::test]
async fn probe_multi_height_anchor() {
    let validator = test_key(10);
    let sender = test_key(20);
    let recipient = test_key(30);
    let sender_addr = sender.verifying_key().to_bytes();
    let recipient_addr = recipient.verifying_key().to_bytes();

    let s0 = Arc::new(InMemoryStateEngine::new());
    s0.update_account(AccountState::new(sender_addr, 5_000_000_000u64)).await;
    let s1 = Arc::new(InMemoryStateEngine::new());
    let mut cluster = ShardedCluster::new(
        ShardRegistry::from_ids([SHARD0, SHARD1]),
        vec![
            (SHARD0, vec![(validator.clone(), s0)]),
            (SHARD1, vec![(validator.clone(), s1)]),
        ],
        CrossShardTransport::local(),
    );

    // Height 1: a NON-EMPTY block, so shard 0's post-h1 root != its declared
    // pre-h1 root. Then the transfer is produced at height 2.
    let filler = Transaction::sign(
        &sender,
        sender_addr,
        1_000u64,
        280_000u64,
        0,
        SHARD0,
        SHARD0,
    );
    cluster.broadcast_tx(filler).await;
    cluster.run_height(SHARD0, 100).await;

    let tx = Transaction::sign(
        &sender,
        recipient_addr,
        1_500_000_000u64,
        280_000u64,
        1,
        SHARD0,
        SHARD1,
    );
    cluster.broadcast_tx(tx.clone()).await;
    let h2 = cluster.run_height(SHARD0, 200).await;
    let blk = cluster.shard(SHARD0).nodes[0].blocks.get(&h2).cloned().unwrap();
    println!("shard0 h2 cross_shard_out = {}", blk.cross_shard_out.len());
    for m in &blk.cross_shard_out {
        let reg = cluster.shard(SHARD0).nodes[0].finalized_headers.as_ref().unwrap();
        let g = reg.read().unwrap();
        println!("  msg transfer={} anchored={}", m.is_transfer(), m.verify_anchored(Some(&g)));
        println!("  msg src_root={:?}", hex::encode(m.source_state_root));
        println!("  msg fin_block={:?}", hex::encode(m.finalized_in_block));
        println!("  lookup(fin_block)={:?}", g.lookup(SHARD0, &m.finalized_in_block).map(hex::encode));
        println!("  block.state_root={:?}", hex::encode(blk.state_root));
        println!("  block.hash={:?}", hex::encode(&h2));
    }

    // Now let shard 1 consume.
    cluster.run_height(SHARD1, 300).await;
    let bal = cluster.shard(SHARD1).nodes[0].state.get_account(&recipient_addr).await.map(|a| a.balance);
    println!("recipient balance on shard1 = {:?}", bal);
    assert!(bal.unwrap_or(0) > 0, "transfer produced at height 2 must be consumable");
}
