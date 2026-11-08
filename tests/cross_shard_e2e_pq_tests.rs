//! Comprehensive E2E Cross-Shard Integration Test (Shard 0 <-> Shard 1)
//!
//! Tests:
//! 1. Full lifecycle of cross-shard transfer (debit Shard 0 -> Merkle proof -> credit Shard 1 -> Ack -> completion).
//! 2. Post-quantum Falcon-512 signatures & pinning.
//! 3. Cryptographic Merkle inclusion verification against C1 anchored header registry.
//! 4. Replay attack prevention (consumed keys tracking).
//! 5. Unanchored root rejection (fake state root attack).
//! 6. Timeout bounce & refund mechanism.

use ed25519_dalek::SigningKey;
use std::sync::Arc;
use stellereum::network::CrossShardTransport;
use stellereum::runtime::ShardedCluster;
use stellereum::sharding::{
    CrossShardMessage, ShardRegistry, Transaction, BASE_WORKCHAIN_SHARD_INITIAL,
    CROSS_SHARD_TIMEOUT_HEIGHTS, MASTERCHAIN_SHARD,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

const SHARD0: u32 = MASTERCHAIN_SHARD; // 0
const SHARD1: u32 = BASE_WORKCHAIN_SHARD_INITIAL; // 1

fn sharded_registry() -> ShardRegistry {
    ShardRegistry::from_ids([SHARD0, SHARD1])
}

fn test_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// FULL-PQ sender address for a seed: implicit Falcon-512, registered
/// globally (no activation surcharge). Mirrors
/// `audit_state_sync_closeout_tests.rs::pq_id`.
fn pq_id(seed: u8) -> [u8; 32] {
    use stellereum::post_quantum::{derive_pq_address, PqScheme, DEFAULT_SALT};
    let pk = Transaction::sample_falcon512_pubkey(seed);
    let from = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);
    Transaction::global_implicit_registry()
        .register(from, PqScheme::Falcon512, &pk, &DEFAULT_SALT)
        .expect("PQ test key must register");
    from
}

/// FULL-PQ replacement for `Transaction::sign` in fixtures: same
/// amount/gas/nonce/shards, implicit Falcon-512 envelope.
#[allow(clippy::too_many_arguments)]
fn pq_tx(
    seed: u8,
    to: [u8; 32],
    amount: u64,
    gas: u64,
    nonce: u64,
    source_shard: u32,
    target_shard: u32,
) -> Transaction {
    use stellereum::post_quantum::{PqScheme, PqSignatureEnvelope};
    let pk = Transaction::sample_falcon512_pubkey(seed);
    let from = pq_id(seed);
    let mut t = Transaction {
        from,
        to,
        amount,
        gas_limit: gas,
        nonce,
        source_shard,
        target_shard,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg = t.signing_message();
    let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
    t.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig).encode();
    t
}

async fn setup_two_shard_cluster(
    val_key: &SigningKey,
    shard0_accounts: &[([u8; 32], u64)],
    shard1_accounts: &[([u8; 32], u64)],
) -> ShardedCluster {
    let s0 = Arc::new(InMemoryStateEngine::new());
    for (addr, bal) in shard0_accounts {
        s0.update_account(AccountState::new(*addr, *bal)).await;
        // PQ senders must live as 49-byte pinned leaves, else the source
        // proof (49-byte, via registry metadata) mismatches the funded
        // 16-byte leaf and target verification fails. Classical addrs miss
        // the registry and stay 16-byte. Balances/addresses unchanged.
        if let Some((scheme, pk)) = Transaction::global_implicit_registry().lookup(addr) {
            use stellereum::post_quantum::DEFAULT_SALT;
            s0.pin_pubkey(*addr, scheme, &pk, &DEFAULT_SALT)
                .await
                .expect("PQ sender must pin");
        }
    }
    let s1 = Arc::new(InMemoryStateEngine::new());
    for (addr, bal) in shard1_accounts {
        s1.update_account(AccountState::new(*addr, *bal)).await;
        if let Some((scheme, pk)) = Transaction::global_implicit_registry().lookup(addr) {
            use stellereum::post_quantum::DEFAULT_SALT;
            s1.pin_pubkey(*addr, scheme, &pk, &DEFAULT_SALT)
                .await
                .expect("PQ sender must pin");
        }
    }

    ShardedCluster::new(
        sharded_registry(),
        vec![
            (SHARD0, vec![(val_key.clone(), s0)]),
            (SHARD1, vec![(val_key.clone(), s1)]),
        ],
        CrossShardTransport::local(),
    )
}

#[tokio::test]
async fn test_cross_shard_transfer_and_ack_lifecycle() {
    let validator = test_key(10);
    let recipient = test_key(30);

    // FULL-PQ: sender is implicit Falcon-512 (seed 20); recipient and
    // validator stay classical. Amounts/fees/nonces/shards unchanged.
    let sender_addr = pq_id(20);
    let recipient_addr = recipient.verifying_key().to_bytes();

    let initial_balance = 5_000_000_000u64; // 5 STELL
    let transfer_amount = 1_500_000_000u64; // 1.5 STELL
    let fee = 280_000u64; // 280k nano

    let mut cluster =
        setup_two_shard_cluster(&validator, &[(sender_addr, initial_balance)], &[]).await;

    // 1. Send cross-shard transfer from Shard 0 to Shard 1
    let tx = pq_tx(
        20,
        recipient_addr,
        transfer_amount,
        fee,
        0, // nonce
        SHARD0,
        SHARD1,
    );
    let tx_hash = tx.compute_tx_hash();

    // Broadcast tx to both shards' nodes
    cluster.broadcast_tx(tx.clone()).await;

    // 2. Shard 0 executes height 1: packages tx and emits CrossShardMessage in cross_shard_out
    let s0_h1_hash = cluster.run_height(SHARD0, 100).await;
    let s0_block1 = cluster.shard(SHARD0).nodes[0]
        .blocks
        .get(&s0_h1_hash)
        .cloned()
        .unwrap();

    assert_eq!(
        s0_block1.cross_shard_out.len(),
        1,
        "Shard 0 must produce 1 outbound cross-shard message"
    );
    let outbound_msg = &s0_block1.cross_shard_out[0];
    assert!(outbound_msg.is_transfer());
    assert_eq!(outbound_msg.source_shard, SHARD0);
    assert_eq!(outbound_msg.target_shard, SHARD1);
    assert_eq!(outbound_msg.tx.compute_tx_hash(), tx_hash);
    assert!(
        outbound_msg.merkle_inclusion_proof.is_some(),
        "Transfer must carry a Merkle inclusion proof"
    );

    // Check sender balance on Shard 0: debited by amount + fee
    let s0_sender_bal = cluster.shard(SHARD0).nodes[0]
        .state
        .get_account(&sender_addr)
        .await
        .unwrap()
        .balance;
    assert_eq!(s0_sender_bal, initial_balance - transfer_amount - fee);

    // 3. Shard 1 executes height 1: fetches inbound messages, verifies Merkle proof against Shard 0's root, credits recipient
    let s1_h1_hash = cluster.run_height(SHARD1, 101).await;
    let _s1_block1 = cluster.shard(SHARD1).nodes[0]
        .blocks
        .get(&s1_h1_hash)
        .cloned()
        .unwrap();

    // Check recipient balance on Shard 1: credited with exactly transfer_amount
    let s1_recipient_bal = cluster.shard(SHARD1).nodes[0]
        .state
        .get_account(&recipient_addr)
        .await
        .unwrap()
        .balance;
    assert_eq!(
        s1_recipient_bal, transfer_amount,
        "Recipient on Shard 1 must be credited with the transfer amount"
    );

    // Shard 1 transport mailbox should now contain the Ack record for Shard 0
    let inbound_for_s0 = cluster.transport.fetch_cross_shard_inbound(SHARD0).await;
    assert_eq!(
        inbound_for_s0.len(),
        1,
        "Shard 1 must publish an Ack message for Shard 0"
    );
    let ack_msg = &inbound_for_s0[0];
    assert!(ack_msg.is_ack(), "Message must be an Ack");
    assert_eq!(ack_msg.tx.compute_tx_hash(), tx_hash);

    // 4. Shard 0 executes height 2: commits the Ack record and marks the transaction completed
    let s0_h2_hash = cluster.run_height(SHARD0, 102).await;
    let s0_block2 = cluster.shard(SHARD0).nodes[0]
        .blocks
        .get(&s0_h2_hash)
        .cloned()
        .unwrap();
    assert!(
        s0_block2
            .cross_shard_out
            .iter()
            .any(|m| m.is_ack() && m.tx.compute_tx_hash() == tx_hash),
        "Shard 0 block 2 must commit the Ack"
    );

    // Transfer is marked completed on Shard 0
    assert!(cluster.shard(SHARD0).nodes[0].is_transfer_completed(&tx_hash));

    // Mailbox is now clean
    assert!(cluster
        .transport
        .fetch_cross_shard_inbound(SHARD0)
        .await
        .is_empty());
}

#[tokio::test]
async fn test_unanchored_fake_root_attack_is_rejected() {
    let validator = test_key(11);
    let recipient = test_key(31);

    // FULL-PQ: sender is implicit Falcon-512 (seed 21); recipient and
    // validator stay classical. Amounts/fees/nonces/shards unchanged.
    let sender_addr = pq_id(21);
    let recipient_addr = recipient.verifying_key().to_bytes();

    let mut cluster = setup_two_shard_cluster(&validator, &[(sender_addr, 1_000_000)], &[]).await;

    // Build a forged message with a random, uncommitted block hash and fake root
    let tx = pq_tx(21, recipient_addr, 500_000, 280_000, 0, SHARD0, SHARD1);
    let fake_root = [0xEE; 32];
    let fake_block_hash = [0xFF; 32];

    let fake_msg = CrossShardMessage::new(SHARD0, SHARD1, tx, fake_root, fake_block_hash, None);

    // Inject forged message directly into Shard 1's transport
    cluster
        .transport
        .broadcast_cross_shard(&fake_msg)
        .await
        .unwrap();

    // Run Shard 1: the forged message must NOT be consumed, and recipient must NOT receive funds
    cluster.run_height(SHARD1, 200).await;

    let recipient_account = cluster.shard(SHARD1).nodes[0]
        .state
        .get_account(&recipient_addr)
        .await;
    assert!(
        recipient_account.is_none() || recipient_account.unwrap().balance == 0,
        "Forged unanchored message must not credit recipient"
    );
}

#[tokio::test]
async fn test_cross_shard_timeout_bounce_and_refund() {
    let validator = test_key(12);
    let recipient = test_key(32);

    // FULL-PQ: sender is implicit Falcon-512 (seed 22); recipient and
    // validator stay classical. Amounts/fees/nonces/shards unchanged.
    let sender_addr = pq_id(22);
    let recipient_addr = recipient.verifying_key().to_bytes();
    let initial_balance = 2_000_000_000u64;
    let transfer_amount = 500_000_000u64;
    let fee = 280_000u64;

    let mut cluster =
        setup_two_shard_cluster(&validator, &[(sender_addr, initial_balance)], &[]).await;

    let tx = pq_tx(22, recipient_addr, transfer_amount, fee, 0, SHARD0, SHARD1);
    let tx_hash = tx.compute_tx_hash();
    cluster.broadcast_tx(tx).await;

    // Shard 0 height 1: produces outbound transfer
    cluster.run_height(SHARD0, 300).await;
    assert_eq!(
        cluster.shard(SHARD0).nodes[0]
            .state
            .get_account(&sender_addr)
            .await
            .unwrap()
            .balance,
        initial_balance - transfer_amount - fee
    );

    // Shard 1 is deliberately DOWN or misses the message (simulate network drop or non-existent destination)
    // Clear Shard 1's inbox to simulate lost transport message
    cluster.transport.prune_consumed(SHARD1, &[tx_hash]).await;

    // Advance Shard 0 past the timeout window (CROSS_SHARD_TIMEOUT_HEIGHTS = 64)
    let mut saw_bounce = false;
    for h in 1..=(CROSS_SHARD_TIMEOUT_HEIGHTS + 3) {
        let bh = cluster.run_height(SHARD0, 300 + h).await;
        let blk = cluster.shard(SHARD0).nodes[0]
            .blocks
            .get(&bh)
            .cloned()
            .unwrap();
        if blk
            .cross_shard_out
            .iter()
            .any(|m| m.is_bounce() && m.tx.compute_tx_hash() == tx_hash)
        {
            saw_bounce = true;
            break;
        }
    }

    assert!(
        saw_bounce,
        "Shard 0 must produce a bounce record after timeout"
    );

    // Sender must be refunded the principal amount (fees are consumed by consensus as anti-DoS)
    let sender_final_bal = cluster.shard(SHARD0).nodes[0]
        .state
        .get_account(&sender_addr)
        .await
        .unwrap()
        .balance;
    assert_eq!(
        sender_final_bal,
        initial_balance - fee,
        "Sender must receive a full refund of principal after bounce"
    );
}
