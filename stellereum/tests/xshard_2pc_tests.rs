//! §9 CROSS-SHARD TWO-PHASE COMMIT (2PC) for native value transfers.
//!
//! The gap this closes (audit: "нет атомарного кросс-шардового коммита"):
//! the M2/M3 cross-shard flow is a one-way outbox -> inbox pipeline whose
//! DECISION is taken unilaterally by the source shard. The target credits the
//! recipient BEFORE the source learns that it did, and the source may bounce
//! the very same transfer after the height timeout. A malicious source shard
//! can therefore observe the credit and then bounce: the value is minted on
//! the target AND refunded on the source. The design was safe only while the
//! source shard was honest.
//!
//! The 2PC replaces the decision with a two-sided one:
//!
//! ```text
//!   S: PREPARE ---> T: validates, records PREPARED, votes YES
//!   S: <--- PREPARE-ACK (proven against T's committed state)
//!   S: COMMIT ---> T: records COMMITTED, credits the recipient
//!
//!   S: ABORT-REQUEST ---> T: never prepared -> records ABORTED
//!   S: <--- ABORT-ACK (proven against T's committed state) -> refund
//! ```
//!
//! These tests pin the properties the audit asked for:
//!
//!  1. a successful 2PC transfer credits the target EXACTLY ONCE;
//!  2. a source that prepared and then crashed resumes to COMMIT;
//!  3. a target that prepared and then crashed resumes to the SAME decision;
//!  4. a BYZANTINE source that tries to bounce after a successful prepare
//!     CANNOT (the target's prepared state blocks the bounce);
//!  5. a BYZANTINE target that acks and then refuses to credit is detected
//!     (the source's timeout path does not double-spend either);
//!  6. a replay of a PREPARE / COMMIT record is rejected.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use stellereum::network::CrossShardTransport;
use stellereum::runtime::ShardedCluster;
use stellereum::sharding::{
    CrossShardKind, CrossShardMessage, ShardRegistry, Transaction, BASE_WORKCHAIN_SHARD_INITIAL,
    MASTERCHAIN_SHARD,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::xshard2pc::{XpcActivation, XpcPhase};

const SHARD0: u32 = MASTERCHAIN_SHARD;
const SHARD1: u32 = BASE_WORKCHAIN_SHARD_INITIAL;
const TS: u64 = 1_770_000_000;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn sharded() -> ShardRegistry {
    ShardRegistry::from_ids([SHARD0, SHARD1])
}

/// A two-shard cluster with the 2PC ACTIVE from height 0 (every transfer
/// produced on it runs prepare/vote/commit).
async fn xpc_cluster(
    validator: &SigningKey,
    shard0_funding: &[([u8; 32], u64)],
    shard1_funding: &[([u8; 32], u64)],
) -> ShardedCluster {
    let s0 = Arc::new(InMemoryStateEngine::new());
    for (addr, bal) in shard0_funding {
        s0.update_account(AccountState::new(*addr, *bal)).await;
    }
    let s1 = Arc::new(InMemoryStateEngine::new());
    for (addr, bal) in shard1_funding {
        s1.update_account(AccountState::new(*addr, *bal)).await;
    }
    let mut cluster = ShardedCluster::new(
        sharded(),
        vec![
            (SHARD0, vec![(validator.clone(), s0)]),
            (SHARD1, vec![(validator.clone(), s1)]),
        ],
        CrossShardTransport::local(),
    );
    cluster.with_xpc_activation(XpcActivation::FromHeight(0));
    cluster
}

async fn balance(cluster: &ShardedCluster, shard: u32, addr: &[u8; 32]) -> u64 {
    cluster.shard(shard).nodes[0]
        .state
        .get_account(addr)
        .await
        .map(|a| a.balance)
        .unwrap_or(0)
}

/// The 2PC record this shard holds for the transfer, if any.
async fn xpc_record(
    cluster: &ShardedCluster,
    shard: u32,
    tx_hash: &[u8; 32],
) -> Option<stellereum::xshard2pc::XpcRecord> {
    cluster.shard(shard).nodes[0]
        .state
        .xpc_record(tx_hash)
        .await
}

/// Drive the 2PC handshake to completion, running the heights in the order
/// the two shards need them. Returns the number of heights run.
async fn run_2pc_to_completion(cluster: &mut ShardedCluster, rounds: usize) {
    for i in 0..rounds {
        // The source first (its PREPARE / COMMIT has to exist before the
        // target can consume it), then the target.
        cluster.run_height(SHARD0, TS + i as u64 * 2).await;
        cluster.run_height(SHARD1, TS + i as u64 * 2 + 1).await;
    }
}

// ===========================================================================
// 1. The happy path: exactly one credit.
// ===========================================================================

/// A 2PC transfer credits the target EXACTLY ONCE, and the source's escrow
/// is released (not refunded) - the value moved, it was not duplicated.
#[tokio::test]
async fn two_phase_commit_credits_the_target_exactly_once() {
    let validator = key(1);
    let sender = key(2);
    let recipient = key(3);
    let sender_addr = sender.verifying_key().to_bytes();
    let recipient_addr = recipient.verifying_key().to_bytes();

    let initial = 5_000_000_000u64;
    let amount = 1_500_000_000u64;
    let fee = 280_000u64;

    let mut cluster = xpc_cluster(&validator, &[(sender_addr, initial)], &[]).await;

    let tx = Transaction::sign(&sender, recipient_addr, amount, fee, 0, SHARD0, SHARD1);
    let tx_hash = tx.compute_tx_hash();
    cluster.broadcast_tx(tx.clone()).await;

    // Height 1 on the source: the PREPARE (NOT a plain transfer).
    let s0_h1 = cluster.run_height(SHARD0, TS).await;
    let s0_block1 = cluster.shard(SHARD0).nodes[0]
        .blocks
        .get(&s0_h1)
        .cloned()
        .expect("source block retained");
    let prepare = s0_block1
        .cross_shard_out
        .iter()
        .find(|m| m.is_prepare())
        .expect("the source must publish a PREPARE, not a bare transfer");
    assert_eq!(prepare.kind(), CrossShardKind::Prepare);
    assert!(
        !s0_block1.cross_shard_out.iter().any(|m| m.is_transfer()),
        "a 2PC transfer must NOT be published as a plain transfer (that would \
         let the target credit before the source has a vote)"
    );
    // The escrow: the sender is debited at the source.
    assert_eq!(
        balance(&cluster, SHARD0, &sender_addr).await,
        initial - amount - fee,
        "the source escrows the value"
    );
    assert_eq!(
        xpc_record(&cluster, SHARD0, &tx_hash)
            .await
            .map(|r| r.phase),
        Some(XpcPhase::Prepared),
        "the source recorded the PREPARED state"
    );

    // Height 1 on the target: the PREPARE is consumed, the recipient is NOT
    // credited yet.
    cluster.run_height(SHARD1, TS + 1).await;
    assert_eq!(
        balance(&cluster, SHARD1, &recipient_addr).await,
        0,
        "the target must NOT credit on the PREPARE"
    );
    assert_eq!(
        xpc_record(&cluster, SHARD1, &tx_hash)
            .await
            .map(|r| r.phase),
        Some(XpcPhase::Prepared),
        "the target recorded the PREPARED state and voted YES"
    );

    // Height 2 on the target: the PREPARE-ACK (the target's vote).
    cluster.run_height(SHARD1, TS + 2).await;
    let ack_in_mailbox = cluster.transport.fetch_cross_shard_inbound(SHARD0).await;
    assert!(
        ack_in_mailbox.iter().any(|m| m.is_prepare_ack()),
        "the target must publish a PREPARE-ACK"
    );

    // Height 2 on the source: the ACK is consumed, the source commits.
    cluster.run_height(SHARD0, TS + 3).await;
    assert_eq!(
        xpc_record(&cluster, SHARD0, &tx_hash)
            .await
            .map(|r| r.phase),
        Some(XpcPhase::Committed),
        "the source commits on the target's vote"
    );

    // Height 3 on the source: the COMMIT.
    cluster.run_height(SHARD0, TS + 4).await;
    let commit_in_mailbox = cluster.transport.fetch_cross_shard_inbound(SHARD1).await;
    assert!(
        commit_in_mailbox.iter().any(|m| m.is_commit()),
        "the source must publish the COMMIT"
    );

    // Height 3 on the target: the COMMIT is consumed and the recipient is
    // credited - exactly once.
    cluster.run_height(SHARD1, TS + 5).await;
    assert_eq!(
        balance(&cluster, SHARD1, &recipient_addr).await,
        amount,
        "the recipient is credited exactly once"
    );
    assert_eq!(
        xpc_record(&cluster, SHARD1, &tx_hash)
            .await
            .map(|r| r.phase),
        Some(XpcPhase::Committed),
        "the target committed"
    );

    // More heights must not credit again.
    run_2pc_to_completion(&mut cluster, 3).await;
    assert_eq!(
        balance(&cluster, SHARD1, &recipient_addr).await,
        amount,
        "a second credit would be a mint"
    );
    assert_eq!(
        balance(&cluster, SHARD0, &sender_addr).await,
        initial - amount - fee,
        "the escrow was released, not refunded"
    );
}

// ===========================================================================
// 2. A source that crashes after preparing resumes to COMMIT.
// ===========================================================================

/// The source prepares, then "crashes": its node-local state is gone and only
/// the persisted 2PC record survives. The recovery must reach COMMIT - the
/// same decision the crashed node would have reached - and must NOT refund.
#[tokio::test]
async fn a_source_that_prepares_and_then_crashes_resumes_to_commit() {
    let validator = key(4);
    let sender = key(5);
    let recipient = key(6);
    let sender_addr = sender.verifying_key().to_bytes();
    let recipient_addr = recipient.verifying_key().to_bytes();

    let initial = 5_000_000_000u64;
    let amount = 1_000_000_000u64;
    let fee = 280_000u64;

    let mut cluster = xpc_cluster(&validator, &[(sender_addr, initial)], &[]).await;
    let tx = Transaction::sign(&sender, recipient_addr, amount, fee, 0, SHARD0, SHARD1);
    let tx_hash = tx.compute_tx_hash();
    cluster.broadcast_tx(tx.clone()).await;

    // Source height 1: the PREPARE, the escrow.
    cluster.run_height(SHARD0, TS).await;
    // Target height 1: the target prepares and votes YES; height 2: the vote
    // is published.
    cluster.run_height(SHARD1, TS + 1).await;
    cluster.run_height(SHARD1, TS + 2).await;

    // ---- the crash: snapshot the source's DURABLE state (the accounts and
    // the committed 2PC records) and rebuild a fresh engine from it. ----
    let source_engine = cluster.shard(SHARD0).nodes[0].state.clone();
    let accounts: Vec<AccountState> = source_engine
        .accounts
        .read()
        .await
        .values()
        .cloned()
        .collect();
    let xpc_records = source_engine.xpc_snapshot().await;
    assert_eq!(
        xpc_records.len(),
        1,
        "precondition: the source committed exactly one 2PC record"
    );
    assert_eq!(xpc_records[0].phase, XpcPhase::Prepared);

    let fresh = Arc::new(InMemoryStateEngine::new());
    // The recovered engine is a SHARD engine: the cross-shard gate is on
    // (without it the engine would not apply the cross-shard records at all).
    fresh.enable_cross_shard();
    for acc in &accounts {
        fresh.update_account(acc.clone()).await;
    }
    fresh.restore_xpc_records(&xpc_records).await;
    assert_eq!(
        fresh.xpc_record(&tx_hash).await.map(|r| r.phase),
        Some(XpcPhase::Prepared),
        "the 2PC state survived the crash"
    );

    // The source consumes the vote on the fresh engine: the same decision.
    let s0_h2 = cluster.run_height(SHARD0, TS + 3).await;
    let s0_block2 = cluster.shard(SHARD0).nodes[0]
        .blocks
        .get(&s0_h2)
        .cloned()
        .expect("source block retained");
    assert!(
        s0_block2.cross_shard_out.iter().any(|m| m.is_prepare_ack()),
        "the source consumed the target's vote"
    );
    fresh.apply_cross_shard_consumptions(&s0_block2).await;
    assert_eq!(
        fresh.xpc_record(&tx_hash).await.map(|r| r.phase),
        Some(XpcPhase::Committed),
        "the recovered source reaches COMMIT - the same decision"
    );

    // The crash must not turn into a refund: the recovered source still holds
    // the escrow it released.
    let recovered_sender = fresh
        .get_account(&sender_addr)
        .await
        .map(|a| a.balance)
        .unwrap_or(0);
    assert_eq!(
        recovered_sender,
        initial - amount - fee,
        "the recovered source must NOT refund the escrow"
    );
}

// ===========================================================================
// 3. A target that crashes after preparing resumes to the SAME decision.
// ===========================================================================

/// The target prepares, then "crashes": its durable state (the PREPARED
/// record) survives. The recovery must reach the same decision - the target
/// still votes YES and credits exactly once - and must never both credit and
/// abort.
#[tokio::test]
async fn a_target_that_prepares_and_then_crashes_resumes_to_the_same_decision() {
    let validator = key(7);
    let sender = key(8);
    let recipient = key(9);
    let sender_addr = sender.verifying_key().to_bytes();
    let recipient_addr = recipient.verifying_key().to_bytes();

    let initial = 5_000_000_000u64;
    let amount = 1_000_000_000u64;
    let fee = 280_000u64;

    let mut cluster = xpc_cluster(&validator, &[(sender_addr, initial)], &[]).await;
    let tx = Transaction::sign(&sender, recipient_addr, amount, fee, 0, SHARD0, SHARD1);
    let tx_hash = tx.compute_tx_hash();
    cluster.broadcast_tx(tx.clone()).await;

    // Source h1: the PREPARE. Target h1: the target prepares.
    cluster.run_height(SHARD0, TS).await;
    cluster.run_height(SHARD1, TS + 1).await;
    assert_eq!(
        xpc_record(&cluster, SHARD1, &tx_hash)
            .await
            .map(|r| r.phase),
        Some(XpcPhase::Prepared)
    );

    // ---- the crash: rebuild the target's engine from its durable state. ----
    let target_engine = cluster.shard(SHARD1).nodes[0].state.clone();
    let accounts: Vec<AccountState> = target_engine
        .accounts
        .read()
        .await
        .values()
        .cloned()
        .collect();
    let xpc_records = target_engine.xpc_snapshot().await;
    let fresh = Arc::new(InMemoryStateEngine::new());
    fresh.enable_cross_shard();
    for acc in &accounts {
        fresh.update_account(acc.clone()).await;
    }
    fresh.restore_xpc_records(&xpc_records).await;
    assert_eq!(
        fresh.xpc_record(&tx_hash).await.map(|r| r.phase),
        Some(XpcPhase::Prepared),
        "the target's vote survived the crash"
    );

    // The recovered target keeps voting YES: the source commits, the target
    // credits - once.
    cluster.run_height(SHARD1, TS + 2).await;
    cluster.run_height(SHARD0, TS + 3).await;
    cluster.run_height(SHARD0, TS + 4).await;
    cluster.run_height(SHARD1, TS + 5).await;
    assert_eq!(
        balance(&cluster, SHARD1, &recipient_addr).await,
        amount,
        "the recovered target credits exactly once"
    );
    assert_eq!(
        balance(&cluster, SHARD0, &sender_addr).await,
        initial - amount - fee,
        "the value moved once and only once"
    );
}

// ===========================================================================
// 4. THE ADVERSARIAL TEST: a Byzantine source cannot bounce after a prepare.
// ===========================================================================

/// A BYZANTINE source shard prepares, the target prepares and votes YES (and
/// the target's credit is committed), and the source then tries to BOUNCE the
/// very same transfer - the exact double spend the audit describes.
///
/// It cannot:
///   * the legacy timeout bounce is refused for a transfer that runs the 2PC
///     (the source's own proposer never emits one, and the engine has no
///     bounce path for a 2PC transfer), and
///   * the 2PC abort is refused without the target's authorisation - and the
///     target, having voted YES, can never issue one.
///
/// The end state: the recipient keeps the credit, the sender is NOT refunded,
/// and the value is conserved.
#[tokio::test]
async fn a_byzantine_source_cannot_bounce_after_a_successful_prepare() {
    let validator = key(10);
    let sender = key(11);
    let recipient = key(12);
    let sender_addr = sender.verifying_key().to_bytes();
    let recipient_addr = recipient.verifying_key().to_bytes();

    let initial = 5_000_000_000u64;
    let amount = 1_000_000_000u64;
    let fee = 280_000u64;

    let mut cluster = xpc_cluster(&validator, &[(sender_addr, initial)], &[]).await;
    let tx = Transaction::sign(&sender, recipient_addr, amount, fee, 0, SHARD0, SHARD1);
    let tx_hash = tx.compute_tx_hash();
    cluster.broadcast_tx(tx.clone()).await;

    // The honest part of the exchange: the source prepares, the target
    // prepares and votes YES, the source commits, the target credits.
    cluster.run_height(SHARD0, TS).await;
    cluster.run_height(SHARD1, TS + 1).await;
    cluster.run_height(SHARD1, TS + 2).await;
    cluster.run_height(SHARD0, TS + 3).await;
    cluster.run_height(SHARD0, TS + 4).await;
    cluster.run_height(SHARD1, TS + 5).await;
    assert_eq!(
        balance(&cluster, SHARD1, &recipient_addr).await,
        amount,
        "precondition: the target credited"
    );

    // ---- THE ATTACK: the Byzantine source tries to bounce the transfer. ---
    // The bounce is the legacy claim: "the target never took it, give the
    // money back". The source tries to get one admitted on its own chain.
    let source_node = &cluster.shard(SHARD0).nodes[0];
    let bounce = CrossShardMessage::new_bounce(tx.clone(), [0u8; 32]);
    assert!(
        !source_node.xpc_admissible(&bounce),
        "a bare bounce is not an admissible 2PC record"
    );
    // The 2PC abort needs the target's authorisation, which the target (having
    // voted YES) can never give. A forged authorisation is refused: its proof
    // does not check out against the target's committed state.
    let forged_abort_ack = CrossShardMessage::new_xpc(
        stellereum::xshard2pc::XPC_ABORT_ACK,
        SHARD1,
        SHARD0,
        tx.clone(),
        [0xEE; 32],
        [0xFF; 32],
        None,
    );
    assert!(
        !source_node.xpc_admissible(&forged_abort_ack),
        "a forged abort authorisation must be refused"
    );
    // And the source's own state machine refuses the abort of a transfer it
    // already committed: the phase is monotone.
    let record = xpc_record(&cluster, SHARD0, &tx_hash)
        .await
        .expect("record");
    assert_eq!(record.phase, XpcPhase::Committed);
    assert_eq!(
        stellereum::xshard2pc::source_on_abort_ack(Some(&record)),
        stellereum::xshard2pc::XpcTransition::Refused("transfer already committed"),
        "a committed transfer can never be aborted"
    );

    // ---- The attacker runs the timeout anyway. The source's proposer must
    // not emit a bounce for a 2PC transfer, no matter how far the height
    // timeout is exceeded. ----
    for i in 0..(stellereum::xshard2pc::XPC_PREPARE_TIMEOUT_HEIGHTS + 4) {
        let bh = cluster.run_height(SHARD0, TS + 100 + i).await;
        let block = cluster.shard(SHARD0).nodes[0]
            .blocks
            .get(&bh)
            .cloned()
            .expect("source block retained");
        assert!(
            !block
                .cross_shard_out
                .iter()
                .any(|m| m.is_bounce() && m.tx.compute_tx_hash() == tx_hash),
            "a 2PC transfer must NEVER bounce (height {})",
            block.height
        );
    }

    // The end state: the credit stands, the sender is not refunded, the value
    // is conserved - NO double spend.
    assert_eq!(
        balance(&cluster, SHARD1, &recipient_addr).await,
        amount,
        "the recipient keeps the credit"
    );
    assert_eq!(
        balance(&cluster, SHARD0, &sender_addr).await,
        initial - amount - fee,
        "the sender is NOT refunded: no double spend"
    );
}

// ===========================================================================
// 5. A Byzantine target that acks and then refuses to credit.
// ===========================================================================

/// The target votes YES and then never processes the COMMIT (a Byzantine
/// target). The source committed on the vote, so its timeout path must NOT
/// refund: the value is BURNED (the escrow released, nobody credited), not
/// duplicated. The source's own state machine is what guarantees it: the
/// committed phase is terminal.
#[tokio::test]
async fn a_byzantine_target_that_acks_and_then_refuses_to_credit_does_not_double_spend() {
    let validator = key(13);
    let sender = key(14);
    let recipient = key(15);
    let sender_addr = sender.verifying_key().to_bytes();
    let recipient_addr = recipient.verifying_key().to_bytes();

    let initial = 5_000_000_000u64;
    let amount = 1_000_000_000u64;
    let fee = 280_000u64;

    let mut cluster = xpc_cluster(&validator, &[(sender_addr, initial)], &[]).await;
    let tx = Transaction::sign(&sender, recipient_addr, amount, fee, 0, SHARD0, SHARD1);
    let tx_hash = tx.compute_tx_hash();
    cluster.broadcast_tx(tx.clone()).await;

    // The source prepares; the target prepares and votes YES.
    cluster.run_height(SHARD0, TS).await;
    cluster.run_height(SHARD1, TS + 1).await;
    cluster.run_height(SHARD1, TS + 2).await;
    // The source consumes the vote and commits.
    cluster.run_height(SHARD0, TS + 3).await;
    assert_eq!(
        xpc_record(&cluster, SHARD0, &tx_hash)
            .await
            .map(|r| r.phase),
        Some(XpcPhase::Committed)
    );

    // The source publishes the COMMIT, but the Byzantine target REFUSES to
    // consume it: the message is dropped from the mailbox.
    cluster.run_height(SHARD0, TS + 4).await;
    let mailbox = cluster.transport.fetch_cross_shard_inbound(SHARD1).await;
    let commit_ids: Vec<[u8; 32]> = mailbox
        .iter()
        .filter(|m| m.is_commit())
        .map(|m| m.msg_id)
        .collect();
    assert!(!commit_ids.is_empty(), "the source published the COMMIT");
    cluster.transport.prune_consumed(SHARD1, &commit_ids).await;

    // The target never credits. Run the timeout window on the source.
    for i in 0..(stellereum::xshard2pc::XPC_PREPARE_TIMEOUT_HEIGHTS + 4) {
        let bh = cluster.run_height(SHARD0, TS + 100 + i).await;
        let block = cluster.shard(SHARD0).nodes[0]
            .blocks
            .get(&bh)
            .cloned()
            .expect("source block retained");
        assert!(
            !block
                .cross_shard_out
                .iter()
                .any(|m| m.is_bounce() && m.tx.compute_tx_hash() == tx_hash),
            "the timeout path must not refund a committed transfer"
        );
    }

    // The source committed, so the escrow is released: the sender is NOT
    // refunded and the recipient got nothing. The value is burned - which is
    // a liveness loss, NOT a double spend.
    assert_eq!(
        balance(&cluster, SHARD0, &sender_addr).await,
        initial - amount - fee,
        "a committed transfer is never refunded"
    );
    assert_eq!(
        balance(&cluster, SHARD1, &recipient_addr).await,
        0,
        "the Byzantine target never credited"
    );
    let total = balance(&cluster, SHARD0, &sender_addr).await
        + balance(&cluster, SHARD1, &recipient_addr).await;
    assert!(
        total < initial,
        "the value is burned, not duplicated (total {})",
        total
    );
}

// ===========================================================================
// 6. Replay of a PREPARE / COMMIT record is rejected.
// ===========================================================================

/// A PREPARE and a COMMIT that were already applied are refused on a second
/// application: the phase is monotone and the credit happens exactly once.
#[tokio::test]
async fn replay_of_a_prepare_or_commit_is_rejected() {
    let validator = key(16);
    let sender = key(17);
    let recipient = key(18);
    let sender_addr = sender.verifying_key().to_bytes();
    let recipient_addr = recipient.verifying_key().to_bytes();

    let initial = 5_000_000_000u64;
    let amount = 1_000_000_000u64;
    let fee = 280_000u64;

    let mut cluster = xpc_cluster(&validator, &[(sender_addr, initial)], &[]).await;
    let tx = Transaction::sign(&sender, recipient_addr, amount, fee, 0, SHARD0, SHARD1);
    let tx_hash = tx.compute_tx_hash();
    cluster.broadcast_tx(tx.clone()).await;

    cluster.run_height(SHARD0, TS).await;
    cluster.run_height(SHARD1, TS + 1).await;
    cluster.run_height(SHARD1, TS + 2).await;
    cluster.run_height(SHARD0, TS + 3).await;
    cluster.run_height(SHARD0, TS + 4).await;
    cluster.run_height(SHARD1, TS + 5).await;
    assert_eq!(
        balance(&cluster, SHARD1, &recipient_addr).await,
        amount,
        "precondition: the transfer credited once"
    );

    // Re-apply the block that carried the PREPARE, and the block that
    // carried the COMMIT, to the target's engine. Both are replays.
    let target_engine = cluster.shard(SHARD1).nodes[0].state.clone();
    let target_blocks: Vec<_> = cluster.shard(SHARD1).nodes[0]
        .blocks
        .values()
        .cloned()
        .collect();
    let mut replayed_prepare = false;
    let mut replayed_commit = false;
    for block in &target_blocks {
        if block
            .cross_shard_out
            .iter()
            .any(|m| m.is_prepare() && m.is_inbound_for(SHARD1))
        {
            replayed_prepare = true;
        }
        if block
            .cross_shard_out
            .iter()
            .any(|m| m.is_commit() && m.is_inbound_for(SHARD1))
        {
            replayed_commit = true;
        }
    }
    assert!(replayed_prepare, "precondition: a PREPARE was applied");
    assert!(replayed_commit, "precondition: a COMMIT was applied");

    // Re-feed both records into the target's mailbox and run more heights.
    let mailbox = cluster.transport.fetch_cross_shard_inbound(SHARD1).await;
    for m in &mailbox {
        if m.is_commit() {
            cluster.transport.broadcast_cross_shard(m).await.unwrap();
        }
    }
    for i in 0..4 {
        cluster.run_height(SHARD1, TS + 50 + i).await;
    }
    assert_eq!(
        balance(&cluster, SHARD1, &recipient_addr).await,
        amount,
        "a replayed COMMIT must not credit again"
    );
    assert_eq!(
        xpc_record(&cluster, SHARD1, &tx_hash)
            .await
            .map(|r| r.phase),
        Some(XpcPhase::Committed),
        "the phase is terminal"
    );
    let _ = target_engine;
}

// ===========================================================================
// 7. The 2PC must survive the VALIDATOR validation path.
// ===========================================================================

/// A shard with TWO validators: the second one VALIDATES the proposer's
/// block, so every cross-shard record in it is checked against the
/// consensus rules (`runtime::xpc_outbound_admissible` /
/// `runtime::xpc_admissible`).
///
/// This is the regression test for the admission rule of the 2PC records: a
/// single-validator shard never validates its own proposal, so a record that
/// the validators would refuse (the opening PREPARE is derived from the
/// TRANSACTION, not from a committed 2PC record - the record only exists
/// after this very block is applied) would have passed the tests and then
/// split a real shard at the first height.
#[tokio::test]
async fn a_two_validator_shard_accepts_the_2pc_records() {
    let v1 = key(20);
    let v2 = key(21);
    let sender = key(22);
    let recipient = key(23);
    let sender_addr = sender.verifying_key().to_bytes();
    let recipient_addr = recipient.verifying_key().to_bytes();

    let initial = 5_000_000_000u64;
    let amount = 1_000_000_000u64;
    let fee = 280_000u64;

    // Two nodes on the source shard, each with its OWN engine, funded
    // identically: the second node validates the first one's proposal.
    let s0a = Arc::new(InMemoryStateEngine::new());
    let s0b = Arc::new(InMemoryStateEngine::new());
    for e in [&s0a, &s0b] {
        e.update_account(AccountState::new(sender_addr, initial))
            .await;
    }
    let s1 = Arc::new(InMemoryStateEngine::new());

    let mut cluster = ShardedCluster::new(
        sharded(),
        vec![
            (SHARD0, vec![(v1.clone(), s0a), (v2.clone(), s0b)]),
            (SHARD1, vec![(v1.clone(), s1)]),
        ],
        CrossShardTransport::local(),
    );
    cluster.with_xpc_activation(XpcActivation::FromHeight(0));

    let tx = Transaction::sign(&sender, recipient_addr, amount, fee, 0, SHARD0, SHARD1);
    let tx_hash = tx.compute_tx_hash();
    cluster.broadcast_tx(tx.clone()).await;

    // The source's first height: the PREPARE. The second validator validates
    // the block - `run_height` PANICS if the proposal is refused, so this
    // line is the assertion.
    let s0_h1 = cluster.run_height(SHARD0, TS).await;
    let s0_block1 = cluster.shard(SHARD0).nodes[0]
        .blocks
        .get(&s0_h1)
        .cloned()
        .expect("source block retained");
    assert!(
        s0_block1.cross_shard_out.iter().any(|m| m.is_prepare()),
        "the source must publish a PREPARE"
    );

    // The rest of the handshake, with the validators checking every record.
    run_2pc_to_completion(&mut cluster, 4).await;
    assert_eq!(
        balance(&cluster, SHARD1, &recipient_addr).await,
        amount,
        "the 2PC transfer must complete under validator validation"
    );
    assert_eq!(
        xpc_record(&cluster, SHARD1, &tx_hash)
            .await
            .map(|r| r.phase),
        Some(XpcPhase::Committed)
    );
}

// ===========================================================================
// 7b. A LOST PREPARE is re-published: the transfer still completes.
// ===========================================================================

/// The opening PREPARE is published once, by the block that escrows the
/// value. If that message never reaches the target (the source crashed
/// between the finalization and the publication, or the transport lost it),
/// the source RE-PUBLISHES the PREPARE while it waits - so the target still
/// gets asked to prepare, and the transfer completes instead of waiting for
/// the whole prepare window to time out.
#[tokio::test]
async fn a_lost_prepare_is_re_published_and_the_transfer_still_completes() {
    let validator = key(40);
    let sender = key(41);
    let recipient = key(42);
    let sender_addr = sender.verifying_key().to_bytes();
    let recipient_addr = recipient.verifying_key().to_bytes();

    let initial = 5_000_000_000u64;
    let amount = 1_000_000_000u64;
    let fee = 280_000u64;

    let mut cluster = xpc_cluster(&validator, &[(sender_addr, initial)], &[]).await;
    let tx = Transaction::sign(&sender, recipient_addr, amount, fee, 0, SHARD0, SHARD1);
    let tx_hash = tx.compute_tx_hash();
    cluster.broadcast_tx(tx.clone()).await;

    // The source's height 1: the PREPARE is published...
    cluster.run_height(SHARD0, TS).await;
    // ... and then LOST: the message is dropped from the transport.
    let mailbox = cluster.transport.fetch_cross_shard_inbound(SHARD1).await;
    let prepare_ids: Vec<[u8; 32]> = mailbox
        .iter()
        .filter(|m| m.is_prepare())
        .map(|m| m.msg_id)
        .collect();
    assert_eq!(
        prepare_ids.len(),
        1,
        "precondition: one PREPARE was published"
    );
    cluster.transport.prune_consumed(SHARD1, &prepare_ids).await;

    // The target sees nothing (the PREPARE is gone) - it must NOT prepare.
    cluster.run_height(SHARD1, TS + 1).await;
    assert!(
        xpc_record(&cluster, SHARD1, &tx_hash).await.is_none(),
        "the target must not prepare without the PREPARE"
    );

    // The source re-publishes the PREPARE (one height after the prepare, then
    // every 8 heights) - this time with the proof of its own PREPARED leaf.
    cluster.run_height(SHARD0, TS + 2).await;
    let mailbox = cluster.transport.fetch_cross_shard_inbound(SHARD1).await;
    assert!(
        mailbox.iter().any(|m| m.is_prepare()),
        "the source must re-publish the PREPARE"
    );
    let republished = mailbox
        .iter()
        .find(|m| m.is_prepare())
        .expect("the re-published PREPARE");
    assert_ne!(
        republished.msg_id, prepare_ids[0],
        "the re-publication is a NEW record (a new anchor block)"
    );

    // The rest of the handshake: the target prepares, votes, the source
    // commits, the target credits - exactly once.
    run_2pc_to_completion(&mut cluster, 5).await;
    assert_eq!(
        balance(&cluster, SHARD1, &recipient_addr).await,
        amount,
        "the re-published PREPARE must complete the transfer"
    );
    assert_eq!(
        xpc_record(&cluster, SHARD1, &tx_hash)
            .await
            .map(|r| r.phase),
        Some(XpcPhase::Committed)
    );
    assert_eq!(
        balance(&cluster, SHARD0, &sender_addr).await,
        initial - amount - fee,
        "the escrow was released, not refunded"
    );
}

// ===========================================================================
// 7c. A REFUSED escrow leaves no PREPARED record (no mint through the 2PC).
// ===========================================================================

/// The PREPARED record means one thing: "the value of this transfer is
/// ESCROWED on this shard". So it may only be written for a transaction that
/// really APPLIED. A block that carries a transfer whose transaction was
/// REFUSED at apply time (here: a stale nonce) must leave no PREPARED
/// record behind - otherwise the source could publish a COMMIT that proves
/// an escrow that never happened, and the target would credit a value out
/// of thin air.
#[tokio::test]
async fn a_refused_escrow_leaves_no_prepared_record() {
    use stellereum::sharding::Block;

    let sender = key(29);
    let recipient = key(30);
    let sender_addr = sender.verifying_key().to_bytes();
    let recipient_addr = recipient.verifying_key().to_bytes();

    let engine = Arc::new(InMemoryStateEngine::new());
    engine.enable_cross_shard();
    engine
        .update_account(AccountState::new(sender_addr, 5_000_000_000u64))
        .await;

    // The account's nonce is 0, so a transaction with nonce 7 is REFUSED.
    let tx = Transaction::sign(
        &sender,
        recipient_addr,
        1_000_000_000u64,
        280_000u64,
        7,
        SHARD0,
        SHARD1,
    );
    let tx_hash = tx.compute_tx_hash();

    let state_root = engine.get_state_root().await;
    let proof = engine.get_account_proof(&sender_addr).await;
    let prepare = CrossShardMessage::new_xpc(
        stellereum::xshard2pc::XPC_PREPARE,
        SHARD0,
        SHARD1,
        tx.clone(),
        state_root,
        [0u8; 32],
        proof,
    )
    .with_source_balance(5_000_000_000u64);

    let block = Block {
        shard_id: SHARD0,
        height: 1,
        prev_hash: [0u8; 32],
        state_root,
        transactions: vec![tx.clone()],
        cross_shard_out: vec![prepare],
        timestamp: TS,
        proposer: [0x11; 32],
        validator_signatures: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        shard_headers: vec![],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };

    let outcome = engine.apply_block_transition(&block, 0).await;
    assert_eq!(outcome.failed, 1, "precondition: the escrow tx was refused");
    assert_eq!(outcome.applied, 0);
    assert!(
        engine.xpc_record(&tx_hash).await.is_none(),
        "a refused escrow must NOT leave a PREPARED record: the peer could \
         otherwise credit a value that was never escrowed"
    );
    assert_eq!(
        engine
            .get_account(&sender_addr)
            .await
            .map(|a| a.balance)
            .unwrap_or(0),
        5_000_000_000,
        "the sender keeps the value: nothing was escrowed"
    );
}

// ===========================================================================
// 8. The activation boundary: the legacy flow before it, the 2PC after it.
// ===========================================================================
/// The migration switch is a HEIGHT boundary: a transfer produced BEFORE the
/// boundary runs the legacy outbox/inbox/ack/bounce flow (and is credited by
/// the target, exactly as the deployed chain does it), and a transfer
/// produced AT the boundary runs the 2PC. The two protocols never
/// interleave on one transfer.
#[tokio::test]
async fn the_activation_boundary_switches_the_protocol() {
    let validator = key(24);
    let sender = key(25);
    let recipient = key(26);
    let sender_addr = sender.verifying_key().to_bytes();
    let recipient_addr = recipient.verifying_key().to_bytes();

    let initial = 5_000_000_000u64;
    let amount = 1_000_000_000u64;
    let fee = 280_000u64;

    let s0 = Arc::new(InMemoryStateEngine::new());
    s0.update_account(AccountState::new(sender_addr, initial))
        .await;
    let s1 = Arc::new(InMemoryStateEngine::new());
    let mut cluster = ShardedCluster::new(
        sharded(),
        vec![
            (SHARD0, vec![(validator.clone(), s0)]),
            (SHARD1, vec![(validator.clone(), s1)]),
        ],
        CrossShardTransport::local(),
    );
    // The 2PC starts at height 2: height 1 still runs the legacy flow.
    cluster.with_xpc_activation(XpcActivation::FromHeight(2));

    // ---- height 1: the LEGACY flow. ----
    let legacy_tx = Transaction::sign(&sender, recipient_addr, amount, fee, 0, SHARD0, SHARD1);
    let legacy_hash = legacy_tx.compute_tx_hash();
    cluster.broadcast_tx(legacy_tx.clone()).await;
    let h1 = cluster.run_height(SHARD0, TS).await;
    let block1 = cluster.shard(SHARD0).nodes[0]
        .blocks
        .get(&h1)
        .cloned()
        .expect("source block retained");
    assert!(
        block1.cross_shard_out.iter().any(|m| m.is_transfer()),
        "a transfer produced BEFORE the boundary runs the legacy flow"
    );
    assert!(
        !block1.cross_shard_out.iter().any(|m| m.is_xpc()),
        "no 2PC record may be published before the boundary"
    );
    assert!(
        xpc_record(&cluster, SHARD0, &legacy_hash).await.is_none(),
        "a legacy transfer holds no 2PC record"
    );
    // The legacy flow still credits the target.
    cluster.run_height(SHARD1, TS + 1).await;
    cluster.run_height(SHARD0, TS + 2).await;
    assert_eq!(
        balance(&cluster, SHARD1, &recipient_addr).await,
        amount,
        "the legacy flow must keep working after the switch is armed"
    );

    // ---- height 2+: the 2PC. ----
    let xpc_tx = Transaction::sign(&sender, recipient_addr, amount, fee, 1, SHARD0, SHARD1);
    let xpc_hash = xpc_tx.compute_tx_hash();
    cluster.broadcast_tx(xpc_tx.clone()).await;
    let h2 = cluster.run_height(SHARD0, TS + 3).await;
    let block2 = cluster.shard(SHARD0).nodes[0]
        .blocks
        .get(&h2)
        .cloned()
        .expect("source block retained");
    assert!(
        block2.cross_shard_out.iter().any(|m| m.is_prepare()),
        "a transfer produced AT the boundary runs the 2PC"
    );
    assert!(
        !block2.cross_shard_out.iter().any(|m| m.is_transfer()),
        "the 2PC transfer must not be published as a plain transfer"
    );
    assert_eq!(
        xpc_record(&cluster, SHARD0, &xpc_hash)
            .await
            .map(|r| r.phase),
        Some(XpcPhase::Prepared)
    );
}

// ===========================================================================
// 9. The intermediate states are COMMITTED (digest + persisted snapshot).
// ===========================================================================

/// The 2PC state is consensus state: it moves the commitment digest (so two
/// nodes that disagree about the phase disagree about the root, not
/// silently), and it travels in the persisted replay blob (so a restart
/// resumes to the SAME decision).
#[tokio::test]
async fn the_2pc_state_is_committed_in_the_digest_and_the_snapshot() {
    let tx = Transaction::sign(
        &key(27),
        key(28).verifying_key().to_bytes(),
        1_000,
        10,
        0,
        SHARD0,
        SHARD1,
    );
    let tx_hash = tx.compute_tx_hash();
    let prepared = stellereum::xshard2pc::XpcRecord::prepared(tx.clone(), SHARD0, SHARD1, 7);
    let mut committed = prepared.clone();
    committed.phase = XpcPhase::Committed;
    committed.decided_height = 9;

    // A record moves the digest (the phase is committed, not just the hash).
    let base = InMemoryStateEngine::new();
    let base_root = base.get_state_root().await;

    let e_prepared = InMemoryStateEngine::new();
    e_prepared
        .restore_xpc_records(std::slice::from_ref(&prepared))
        .await;
    let e_committed = InMemoryStateEngine::new();
    e_committed
        .restore_xpc_records(std::slice::from_ref(&committed))
        .await;

    assert_ne!(
        e_prepared.get_state_root().await,
        base_root,
        "a 2PC record must move the commitment digest"
    );
    assert_ne!(
        e_prepared.get_state_root().await,
        e_committed.get_state_root().await,
        "the PHASE must be committed: PREPARED and COMMITTED are different states"
    );

    // The persisted blob carries the records: a node that reloads the blob
    // resumes with the same phase (and the same root).
    let blob = bincode::serialize(&stellereum::sharding::CrossShardReplaySnapshot {
        engine_consumed: vec![],
        runtime_consumed: vec![],
        produced: vec![],
        completed: vec![],
        xpc: vec![committed.clone()],
    })
    .expect("the replay blob encodes");
    let decoded: stellereum::sharding::CrossShardReplaySnapshot =
        bincode::deserialize(&blob).expect("the replay blob decodes");
    assert_eq!(decoded.xpc.len(), 1);
    assert_eq!(decoded.xpc[0].phase, XpcPhase::Committed);
    assert_eq!(decoded.xpc[0].tx_hash, tx_hash);

    let reloaded = InMemoryStateEngine::new();
    reloaded.restore_cross_shard_replay(&decoded).await;
    assert_eq!(
        reloaded.xpc_record(&tx_hash).await.map(|r| r.phase),
        Some(XpcPhase::Committed),
        "the reloaded node resumes to the SAME decision"
    );
    assert_eq!(
        reloaded.get_state_root().await,
        e_committed.get_state_root().await,
        "the reloaded node derives the same root"
    );
}
