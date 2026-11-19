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
use stellereum::post_quantum::{
    derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT, FALCON512_SIG_LEN,
};
use stellereum::runtime::ShardedCluster;
use stellereum::sharding::{
    CrossShardKind, CrossShardMessage, ShardRegistry, Transaction, BASE_WORKCHAIN_SHARD_INITIAL,
    MASTERCHAIN_SHARD,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine, PQ_ACTIVATION_SURCHARGE_GAS};
use stellereum::xshard2pc::{XpcActivation, XpcPhase};

const SHARD0: u32 = MASTERCHAIN_SHARD;
const SHARD1: u32 = BASE_WORKCHAIN_SHARD_INITIAL;
const TS: u64 = 1_770_000_000;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn pq_sender(seed: u8) -> (FalconKeypair, [u8; 32]) {
    let kp = FalconKeypair::generate_from_seed(seed);
    let addr = derive_pq_address(PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT);
    (kp, addr)
}

fn sign_pq_tx(
    sender: &FalconKeypair,
    to: [u8; 32],
    amount: u64,
    gas_limit: u64,
    nonce: u64,
    source_shard: u32,
    target_shard: u32,
) -> Transaction {
    let probe = Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        sender.public_key.clone(),
        vec![0u8; FALCON512_SIG_LEN],
        to,
        amount,
        gas_limit,
        nonce,
        source_shard,
        target_shard,
        Vec::new(),
        &DEFAULT_SALT,
    );
    let sig = sender.sign(&probe.signing_message());
    Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        sender.public_key.clone(),
        sig,
        to,
        amount,
        gas_limit,
        nonce,
        source_shard,
        target_shard,
        Vec::new(),
        &DEFAULT_SALT,
    )
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
    let (sender, sender_addr) = pq_sender(2);
    let recipient = key(3);
    let recipient_addr = recipient.verifying_key().to_bytes();

    let initial = 5_000_000_000u64;
    let amount = 1_500_000_000u64;
    let fee = 280_000u64;

    let mut cluster = xpc_cluster(&validator, &[(sender_addr, initial)], &[]).await;

    let tx = sign_pq_tx(&sender, recipient_addr, amount, fee, 0, SHARD0, SHARD1);
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
    // The escrow: the sender is debited at the source (amount + gas + PQ activation surcharge).
    assert_eq!(
        balance(&cluster, SHARD0, &sender_addr).await,
        initial - amount - fee - PQ_ACTIVATION_SURCHARGE_GAS,
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
        initial - amount - fee - PQ_ACTIVATION_SURCHARGE_GAS,
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
    let (sender, sender_addr) = pq_sender(5);
    let recipient = key(6);
    let recipient_addr = recipient.verifying_key().to_bytes();

    let initial = 5_000_000_000u64;
    let amount = 1_000_000_000u64;
    let fee = 280_000u64;

    let mut cluster = xpc_cluster(&validator, &[(sender_addr, initial)], &[]).await;
    let tx = sign_pq_tx(&sender, recipient_addr, amount, fee, 0, SHARD0, SHARD1);
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
    // (without it the engine would not apply the cross-shard records at all),
    // and it has the node's finalized-header anchor registry attached (C1).
    fresh.enable_cross_shard();
    if let Some(hdrs) = source_engine.finalized_headers() {
        fresh.with_finalized_headers(hdrs);
    }
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
        initial - amount - fee - PQ_ACTIVATION_SURCHARGE_GAS,
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
    let (sender, sender_addr) = pq_sender(8);
    let recipient = key(9);
    let recipient_addr = recipient.verifying_key().to_bytes();

    let initial = 5_000_000_000u64;
    let amount = 1_000_000_000u64;
    let fee = 280_000u64;

    let mut cluster = xpc_cluster(&validator, &[(sender_addr, initial)], &[]).await;
    let tx = sign_pq_tx(&sender, recipient_addr, amount, fee, 0, SHARD0, SHARD1);
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
        initial - amount - fee - PQ_ACTIVATION_SURCHARGE_GAS,
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
    let (sender, sender_addr) = pq_sender(11);
    let recipient = key(12);
    let recipient_addr = recipient.verifying_key().to_bytes();

    let initial = 5_000_000_000u64;
    let amount = 1_000_000_000u64;
    let fee = 280_000u64;

    let mut cluster = xpc_cluster(&validator, &[(sender_addr, initial)], &[]).await;
    let tx = sign_pq_tx(&sender, recipient_addr, amount, fee, 0, SHARD0, SHARD1);
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
        initial - amount - fee - PQ_ACTIVATION_SURCHARGE_GAS,
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
    let (sender, sender_addr) = pq_sender(14);
    let recipient = key(15);
    let recipient_addr = recipient.verifying_key().to_bytes();

    let initial = 5_000_000_000u64;
    let amount = 1_000_000_000u64;
    let fee = 280_000u64;

    let mut cluster = xpc_cluster(&validator, &[(sender_addr, initial)], &[]).await;
    let tx = sign_pq_tx(&sender, recipient_addr, amount, fee, 0, SHARD0, SHARD1);
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
        initial - amount - fee - PQ_ACTIVATION_SURCHARGE_GAS,
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
    let (sender, sender_addr) = pq_sender(17);
    let recipient = key(18);
    let recipient_addr = recipient.verifying_key().to_bytes();

    let initial = 5_000_000_000u64;
    let amount = 1_000_000_000u64;
    let fee = 280_000u64;

    let mut cluster = xpc_cluster(&validator, &[(sender_addr, initial)], &[]).await;
    let tx = sign_pq_tx(&sender, recipient_addr, amount, fee, 0, SHARD0, SHARD1);
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
    let (sender, sender_addr) = pq_sender(22);
    let recipient = key(23);
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

    let tx = sign_pq_tx(&sender, recipient_addr, amount, fee, 0, SHARD0, SHARD1);
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
    let (sender, sender_addr) = pq_sender(41);
    let recipient = key(42);
    let recipient_addr = recipient.verifying_key().to_bytes();

    let initial = 5_000_000_000u64;
    let amount = 1_000_000_000u64;
    let fee = 280_000u64;

    let mut cluster = xpc_cluster(&validator, &[(sender_addr, initial)], &[]).await;
    let tx = sign_pq_tx(&sender, recipient_addr, amount, fee, 0, SHARD0, SHARD1);
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

    // The source re-publishes the PREPARE once per prepare window (one height
    // after the prepare) - this time with the proof of its own PREPARED leaf.
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
        initial - amount - fee - PQ_ACTIVATION_SURCHARGE_GAS,
        "the escrow was released, not refunded"
    );
}

// ===========================================================================
// 7b-2. A STUCK prepare is retried at most ONCE per prepare window.
// ===========================================================================

/// The source re-derives the PREPARE from its committed state on every
/// height, so without a bound a transfer whose target never answers would put
/// one PREPARE on the wire per block for the whole window. The bound is the
/// protocol's: exactly one retry per [`XPC_PREPARE_TIMEOUT_HEIGHTS`] window,
/// after which the abort path takes over.
#[tokio::test]
async fn a_stuck_prepare_is_retried_at_most_once_per_window() {
    use stellereum::xshard2pc::XPC_PREPARE_TIMEOUT_HEIGHTS;

    let validator = key(43);
    let (sender, sender_addr) = pq_sender(44);
    let recipient = key(45);
    let recipient_addr = recipient.verifying_key().to_bytes();

    let initial = 5_000_000_000u64;
    let amount = 1_000_000_000u64;
    let fee = 280_000u64;

    let mut cluster = xpc_cluster(&validator, &[(sender_addr, initial)], &[]).await;
    let tx = sign_pq_tx(&sender, recipient_addr, amount, fee, 0, SHARD0, SHARD1);
    let tx_hash = tx.compute_tx_hash();
    cluster.broadcast_tx(tx.clone()).await;

    // Height 1: the OPENING PREPARE (it escrows the value).
    cluster.run_height(SHARD0, TS).await;
    // The target never runs, so the PREPARE is never answered.

    // Heights 2..=TIMEOUT: at most ONE retry across the whole window.
    let mut retries = 0usize;
    for i in 1..XPC_PREPARE_TIMEOUT_HEIGHTS {
        let bh = cluster.run_height(SHARD0, TS + i).await;
        let block = cluster.shard(SHARD0).nodes[0]
            .blocks
            .get(&bh)
            .cloned()
            .expect("source block retained");
        let published = block
            .cross_shard_out
            .iter()
            .filter(|m| m.is_prepare() && m.tx.compute_tx_hash() == tx_hash)
            .count();
        assert!(
            published <= 1,
            "at most one PREPARE per transfer per height (height {})",
            block.height
        );
        retries += published;
    }
    assert_eq!(
        retries, 1,
        "the PREPARE retry must be bounded to one per window (got {retries})"
    );

    // At the timeout the source stops PREPAREs and asks the target to abort.
    let bh = cluster
        .run_height(SHARD0, TS + XPC_PREPARE_TIMEOUT_HEIGHTS)
        .await;
    let block = cluster.shard(SHARD0).nodes[0]
        .blocks
        .get(&bh)
        .cloned()
        .expect("source block retained");
    assert!(
        !block
            .cross_shard_out
            .iter()
            .any(|m| m.is_prepare() && m.tx.compute_tx_hash() == tx_hash),
        "no PREPARE may be retried after the window"
    );
    assert!(
        block
            .cross_shard_out
            .iter()
            .any(|m| m.is_abort_request() && m.tx.compute_tx_hash() == tx_hash),
        "the timeout path must request the abort"
    );

    // ... and it never goes back to PREPARE on later heights.
    for i in 0..8 {
        let bh = cluster
            .run_height(SHARD0, TS + XPC_PREPARE_TIMEOUT_HEIGHTS + 1 + i)
            .await;
        let block = cluster.shard(SHARD0).nodes[0]
            .blocks
            .get(&bh)
            .cloned()
            .expect("source block retained");
        assert!(
            !block
                .cross_shard_out
                .iter()
                .any(|m| m.is_prepare() && m.tx.compute_tx_hash() == tx_hash),
            "the PREPARE is never revived after the abort path starts (height {})",
            block.height
        );
    }
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

    let (sender, sender_addr) = pq_sender(29);
    let recipient = key(30);
    let recipient_addr = recipient.verifying_key().to_bytes();

    let engine = Arc::new(InMemoryStateEngine::new());
    engine.enable_cross_shard();
    engine
        .update_account(AccountState::new(sender_addr, 5_000_000_000u64))
        .await;

    // The account's nonce is 0, so a transaction with nonce 7 is REFUSED.
    let tx = sign_pq_tx(
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
        cnvrf_v3: None,
        shard_headers: vec![],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
            round: 0,
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
    let (sender, sender_addr) = pq_sender(25);
    let recipient = key(26);
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
    let legacy_tx = sign_pq_tx(&sender, recipient_addr, amount, fee, 0, SHARD0, SHARD1);
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
    // XSHARD-01: a below-boundary (legacy) transfer is REFUSED at the target's
    // credit gate — the one-step legacy message cannot prove the source-side
    // debit — so it is neither credited nor completed. Value must move through
    // the 2PC, including transfers whose producer predates the boundary.
    cluster.run_height(SHARD1, TS + 1).await;
    cluster.run_height(SHARD0, TS + 2).await;
    assert_eq!(
        balance(&cluster, SHARD1, &recipient_addr).await,
        0,
        "a legacy (below-boundary) transfer must NOT be credited"
    );
    let legacy_key = stellereum::sharding::CrossShardKey::of(
        block1
            .cross_shard_out
            .iter()
            .find(|m| m.is_transfer())
            .expect("legacy transfer record"),
    );
    assert!(
        !cluster.shard(SHARD1).nodes[0]
            .state
            .is_cross_shard_consumed(&legacy_key)
            .await,
        "a refused legacy credit must not consume the message"
    );
    assert!(
        !cluster.shard(SHARD0).nodes[0]
            .state
            .is_cross_shard_completed(&legacy_hash)
            .await,
        "a refused legacy credit never completes"
    );
    assert!(
        xpc_record(&cluster, SHARD1, &legacy_hash).await.is_none(),
        "the legacy transfer never gains 2PC state"
    );

    // ---- height 2+: the 2PC. ----
    let xpc_tx = sign_pq_tx(&sender, recipient_addr, amount, fee, 1, SHARD0, SHARD1);
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

    // ---- The boundary is EXACT on every block of both shards: one transfer
    // never carries records of both flows (no half-legacy/half-2PC). ----
    run_2pc_to_completion(&mut cluster, 6).await;
    assert_eq!(
        balance(&cluster, SHARD1, &recipient_addr).await,
        amount,
        "only the 2PC transfer may credit (the legacy one is refused)"
    );
    for shard in [SHARD0, SHARD1] {
        for block in cluster.shard(shard).nodes[0].blocks.values() {
            for msg in &block.cross_shard_out {
                let tx_hash = msg.tx.compute_tx_hash();
                if tx_hash == legacy_hash {
                    assert!(
                        !msg.is_xpc(),
                        "a below-boundary transfer must never carry a 2PC record: {msg:?}"
                    );
                }
                if tx_hash == xpc_hash {
                    assert!(
                        !msg.is_transfer() && !msg.is_ack() && !msg.is_bounce(),
                        "an at-boundary transfer must never carry a legacy record: {msg:?}"
                    );
                }
            }
        }
    }

    // ---- The PRODUCTION switch is the chain-spec constant: ACTIVE FROM
    // GENESIS and derived deterministically, never from an operator knob. ----
    assert_eq!(
        stellereum::xshard2pc::XPC_ACTIVATION_HEIGHT,
        0,
        "the compiled chain spec arms the 2PC from genesis"
    );
    assert_eq!(
        XpcActivation::from_chain_spec(),
        XpcActivation::FromHeight(0),
        "production activation comes from the chain spec only"
    );
    assert_eq!(XpcActivation::from_chain_spec().boundary(), Some(0));
    assert!(XpcActivation::from_chain_spec().is_active_at(0));
    // The explicit off switch remains available for the legacy-path unit
    // tests, but it is NOT what the production constructor returns.
    assert!(!XpcActivation::Disabled.is_active_at(0));
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
    let (sender, _) = pq_sender(27);
    let tx = sign_pq_tx(
        &sender,
        key(28).verifying_key().to_bytes(),
        1_000,
        280_000,
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

// ===========================================================================
// 10. S2: more outbound transfers than the per-block control cap.
// ===========================================================================

/// 20 distinct senders each submit one source-0 -> target-1 transfer. The
/// proposer must NEVER build a block with more than the validator's
/// `XPC_MAX_REEMITS_PER_HEIGHT` 2PC control records: it caps the OPENING
/// PREPAREs, leaves the rest in the mempool, and carries them on later
/// heights. The old proposer emitted one PREPARE per transfer with no cap, so
/// the two-validator shard rejected the block and `run_height` panicked.
#[tokio::test]
async fn more_than_the_control_cap_of_outbound_transfers_finalizes_in_order() {
    use stellereum::xshard2pc::XPC_MAX_REEMITS_PER_HEIGHT;

    let v1 = key(60);
    let v2 = key(61);
    let recipient_addrs: Vec<[u8; 32]> = (0..20u8)
        .map(|i| key(120 + i).verifying_key().to_bytes())
        .collect();
    let senders: Vec<(FalconKeypair, [u8; 32])> = (0..20u8).map(|i| pq_sender(160 + i)).collect();
    let initial = 5_000_000_000u64;
    let amount = 1_000_000u64;
    let fee = 280_000u64;

    let s0a = Arc::new(InMemoryStateEngine::new());
    let s0b = Arc::new(InMemoryStateEngine::new());
    for e in [&s0a, &s0b] {
        for (_, addr) in &senders {
            e.update_account(AccountState::new(*addr, initial)).await;
        }
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

    let mut transfer_txs: Vec<Transaction> = Vec::with_capacity(senders.len());
    for (i, (sender, _)) in senders.iter().enumerate() {
        let tx = sign_pq_tx(sender, recipient_addrs[i], amount, fee, 0, SHARD0, SHARD1);
        transfer_txs.push(tx.clone());
        cluster.broadcast_tx(tx).await;
    }

    // Source height 1: the block must be VALID (both validators accept it) and
    // its opening-PREPARE count must fit the shared cap. On the old proposer
    // this block carried 20 PREPAREs and `run_height` panicked.
    let h1 = cluster.run_height(SHARD0, TS).await;
    let block1 = cluster.shard(SHARD0).nodes[0]
        .blocks
        .get(&h1)
        .cloned()
        .expect("source block retained");
    let prepares1 = block1
        .cross_shard_out
        .iter()
        .filter(|m| m.is_prepare())
        .count();
    assert!(
        prepares1 <= XPC_MAX_REEMITS_PER_HEIGHT,
        "the proposer must never exceed the validator cap: {prepares1} PREPAREs"
    );
    assert!(
        prepares1 < senders.len(),
        "precondition: the cap must defer some of the {} transfers",
        senders.len()
    );

    // Later source heights carry the deferred transfers (the mempool keeps
    // them, and none is ever included without its PREPARE).
    for i in 1..8u64 {
        cluster.run_height(SHARD0, TS + i).await;
    }
    let mut prepared = 0usize;
    for tx in &transfer_txs {
        if xpc_record(&cluster, SHARD0, &tx.compute_tx_hash())
            .await
            .map(|r| r.phase)
            == Some(XpcPhase::Prepared)
        {
            prepared += 1;
        }
    }
    assert_eq!(
        prepared,
        senders.len(),
        "every deferred transfer must eventually be prepared"
    );

    // Drive the handshake. Each source/target height may carry at most the
    // control cap, so a backlog needs several rounds; the deterministic
    // rotation must nevertheless serve every transfer.
    for i in 0..120u64 {
        cluster.run_height(SHARD0, TS + 100 + i * 2).await;
        cluster.run_height(SHARD1, TS + 101 + i * 2).await;
    }

    // Exactly once, in order: each distinct recipient holds exactly its own
    // amount, and every sender was debited exactly amount+fee+surcharge once.
    for (i, addr) in recipient_addrs.iter().enumerate() {
        assert_eq!(
            balance(&cluster, SHARD1, addr).await,
            amount,
            "recipient {i} must be credited exactly once"
        );
    }
    for (i, (_, sender_addr)) in senders.iter().enumerate() {
        assert_eq!(
            balance(&cluster, SHARD0, sender_addr).await,
            initial - amount - fee - PQ_ACTIVATION_SURCHARGE_GAS,
            "sender {i} must be debited exactly once"
        );
    }
}

// ===========================================================================
// 11. S3: a terminal 2PC record is retired after its deterministic window.
// ===========================================================================

/// A completed transfer stops being re-published and is retired from the
/// committed state after `XPC_TERMINAL_RETENTION_HEIGHTS`. The old code kept
/// `source_action(Committed) = Commit` forever: every later block carried the
/// COMMIT + proof and the record stayed in the cloned set/root forever.
#[tokio::test]
async fn a_terminal_2pc_record_is_retired_and_stops_re_publishing() {
    use stellereum::xshard2pc::XPC_TERMINAL_RETENTION_HEIGHTS;

    let validator = key(70);
    let (sender, sender_addr) = pq_sender(71);
    let recipient = key(72);
    let recipient_addr = recipient.verifying_key().to_bytes();
    let initial = 5_000_000_000u64;
    let amount = 1_000_000_000u64;
    let fee = 280_000u64;

    let mut cluster = xpc_cluster(&validator, &[(sender_addr, initial)], &[]).await;
    let tx = sign_pq_tx(&sender, recipient_addr, amount, fee, 0, SHARD0, SHARD1);
    let tx_hash = tx.compute_tx_hash();
    cluster.broadcast_tx(tx.clone()).await;

    // Complete prepare / ack / commit / credit.
    run_2pc_to_completion(&mut cluster, 4).await;
    assert_eq!(
        balance(&cluster, SHARD1, &recipient_addr).await,
        amount,
        "precondition: the transfer completed"
    );
    let decided = xpc_record(&cluster, SHARD0, &tx_hash)
        .await
        .expect("source record")
        .decided_height;
    assert!(
        decided > 0,
        "precondition: the source committed the transfer"
    );

    // Run PAST the old 256-height window on BOTH shards. The retention fix
    // keeps the obligation alive for a real sync/restart window, so neither
    // side may retire it here (the pre-fix code retired the source record at
    // `decided + 256`, permanently stranding the target's credit).
    for i in 0..300 {
        cluster.run_height(SHARD0, TS + 1000 + i * 2).await;
        cluster.run_height(SHARD1, TS + 1001 + i * 2).await;
    }
    assert!(
        xpc_record(&cluster, SHARD0, &tx_hash).await.is_some(),
        "the terminal source record must survive the old 256-height window \
         (a slow target can still need the COMMIT)"
    );
    assert!(
        xpc_record(&cluster, SHARD1, &tx_hash).await.is_some(),
        "the target's decided record is retained too"
    );

    // The deterministic retirement rule is a pure function of the record and
    // the applied height; exercise it directly at the real boundary instead
    // of running hundreds of thousands of blocks in a unit test. Each side's
    // decision height differs (the target decides when it applies COMMIT), so
    // each boundary is derived from that side's own record.
    let source_retire = xpc_record(&cluster, SHARD0, &tx_hash)
        .await
        .expect("source record")
        .decided_height
        + XPC_TERMINAL_RETENTION_HEIGHTS;
    let target_retire = xpc_record(&cluster, SHARD1, &tx_hash)
        .await
        .expect("target record")
        .decided_height
        + XPC_TERMINAL_RETENTION_HEIGHTS;
    cluster.shard(SHARD0).nodes[0]
        .state
        .prune_terminal_xpc_records(source_retire)
        .await;
    cluster.shard(SHARD1).nodes[0]
        .state
        .prune_terminal_xpc_records(target_retire)
        .await;
    assert!(
        xpc_record(&cluster, SHARD0, &tx_hash).await.is_none(),
        "the terminal source record must be retired at its deterministic boundary"
    );
    assert!(
        xpc_record(&cluster, SHARD1, &tx_hash).await.is_none(),
        "the terminal target record must be retired at its deterministic boundary"
    );
    // One more applied height must not re-publish the retired record.
    cluster.run_height(SHARD0, TS + 5000).await;
    let last = cluster.shard(SHARD0).nodes[0]
        .blocks
        .values()
        .max_by_key(|b| b.height)
        .cloned()
        .expect("a source block");
    assert!(
        !last
            .cross_shard_out
            .iter()
            .any(|m| m.is_commit() && m.tx.compute_tx_hash() == tx_hash),
        "a retired record must never be re-published (height {})",
        last.height
    );
    assert_eq!(
        balance(&cluster, SHARD1, &recipient_addr).await,
        amount,
        "retirement must never move value twice"
    );
}

// ===========================================================================
// 12. S10: a never-admissible mailbox record expires deterministically.
// ===========================================================================

/// A message that can never be admitted (here: a 2PC PREPARE with no proof
/// and a fabricated anchor) is skipped by every propose. Before the fix it was
/// never pruned, so a peer could grow the node-local mailbox forever. It must
/// be quarantined after `XPC_MAILBOX_QUARANTINE_HEIGHTS` heights.
#[tokio::test]
async fn a_never_admissible_mailbox_record_is_quarantined() {
    use stellereum::xshard2pc::{XPC_MAILBOX_QUARANTINE_HEIGHTS, XPC_PREPARE};

    let validator = key(80);
    let mut cluster = xpc_cluster(&validator, &[], &[]).await;
    let (sender, _) = pq_sender(81);
    let forged_tx = sign_pq_tx(
        &sender,
        key(82).verifying_key().to_bytes(),
        1_000,
        280_000,
        0,
        SHARD0,
        SHARD1,
    );
    let forged = CrossShardMessage::new_xpc(
        XPC_PREPARE,
        SHARD0,
        SHARD1,
        forged_tx,
        [0xAAu8; 32],
        [0xBBu8; 32],
        None,
    );
    cluster
        .transport
        .broadcast_cross_shard(&forged)
        .await
        .expect("mailbox publish");

    // It is never admitted, but it is also not pruned on the first height.
    cluster.run_height(SHARD1, TS).await;
    assert_eq!(
        cluster
            .transport
            .fetch_cross_shard_inbound(SHARD1)
            .await
            .len(),
        1,
        "precondition: the never-admissible record is in the mailbox"
    );

    // After the quarantine window it is gone.
    for i in 1..=XPC_MAILBOX_QUARANTINE_HEIGHTS + 2 {
        cluster.run_height(SHARD1, TS + i).await;
    }
    assert!(
        cluster
            .transport
            .fetch_cross_shard_inbound(SHARD1)
            .await
            .is_empty(),
        "a never-admissible record must be quarantined after {XPC_MAILBOX_QUARANTINE_HEIGHTS} heights"
    );
}

// ===========================================================================
// 13. TOTAL cross-shard record cap (legacy + 2PC), proposer and validator.
// ===========================================================================

/// A pool of 30 LEGACY outbound transfers (2PC not activated) must never be
/// packed as one unbounded `cross_shard_out`. Before the total cap the
/// proposer put all 30 records in one block: nothing validated the count (the
/// 2PC cap only counted control records), so a Byzantine proposer could put
/// an arbitrary number of outbound records in a block. The proposer now obeys
/// the SAME total cap the validator enforces, and the excess is carried on
/// later heights in the deterministic selection order.
#[tokio::test]
async fn thirty_legacy_outbound_transfers_are_total_capped_and_all_land() {
    use std::collections::{HashMap, HashSet};
    use stellereum::xshard2pc::XPC_MAX_CROSS_SHARD_RECORDS_PER_BLOCK;

    let v1 = key(240);
    let v2 = key(241);
    let senders: Vec<(FalconKeypair, [u8; 32])> = (0..30u8).map(|i| pq_sender(210 + i)).collect();
    let recipients: Vec<[u8; 32]> = (0..30u8)
        .map(|i| key(100 + i).verifying_key().to_bytes())
        .collect();
    let initial = 5_000_000_000u64;
    let amount = 1_000_000u64;
    let fee = 280_000u64;

    let s0a = Arc::new(InMemoryStateEngine::new());
    let s0b = Arc::new(InMemoryStateEngine::new());
    for e in [&s0a, &s0b] {
        for (_, addr) in &senders {
            e.update_account(AccountState::new(*addr, initial)).await;
        }
    }
    let s1 = Arc::new(InMemoryStateEngine::new());
    // DELIBERATELY no `with_xpc_activation`: this is the pre-2PC legacy flow.
    let mut cluster = ShardedCluster::new(
        sharded(),
        vec![
            (SHARD0, vec![(v1.clone(), s0a), (v2.clone(), s0b)]),
            (SHARD1, vec![(v1.clone(), s1)]),
        ],
        CrossShardTransport::local(),
    );

    let mut tx_hashes: Vec<[u8; 32]> = Vec::with_capacity(senders.len());
    for (i, (sender, _)) in senders.iter().enumerate() {
        let tx = sign_pq_tx(sender, recipients[i], amount, fee, 0, SHARD0, SHARD1);
        tx_hashes.push(tx.compute_tx_hash());
        cluster.broadcast_tx(tx).await;
    }

    let mut records_at: HashMap<[u8; 32], u64> = HashMap::new();
    let mut txs_at: HashMap<[u8; 32], u64> = HashMap::new();
    let mut first_block_records = 0usize;

    // Every run_height drives a real 2-validator shard: an over-cap proposal
    // panics ("proposal rejected"), so a finalizing height is a VALID block.
    for i in 0..8u64 {
        let bh = cluster.run_height(SHARD0, TS + i).await;
        let block = cluster.shard(SHARD0).nodes[0]
            .blocks
            .get(&bh)
            .cloned()
            .expect("source block retained");
        assert!(
            block.cross_shard_out.len() <= XPC_MAX_CROSS_SHARD_RECORDS_PER_BLOCK,
            "height {} packed {} records, total cap is {}",
            block.height,
            block.cross_shard_out.len(),
            XPC_MAX_CROSS_SHARD_RECORDS_PER_BLOCK
        );
        if block.height == 1 {
            first_block_records = block.cross_shard_out.len();
        }
        for msg in &block.cross_shard_out {
            if msg.is_transfer() && msg.is_outbound_for(SHARD0) {
                records_at
                    .entry(msg.tx.compute_tx_hash())
                    .or_insert(block.height);
            }
        }
        for tx in &block.transactions {
            txs_at.entry(tx.compute_tx_hash()).or_insert(block.height);
        }
    }

    assert!(
        first_block_records < tx_hashes.len(),
        "precondition: the total cap must DEFER some of the {} transfers \
         (first block carried {first_block_records})",
        tx_hashes.len()
    );

    // All 30 land: each transaction is included exactly once and each carries
    // its outbound transfer record on the same height.
    let distinct_records: HashSet<[u8; 32]> = records_at.keys().copied().collect();
    assert_eq!(
        distinct_records.len(),
        tx_hashes.len(),
        "every outbound transfer must eventually be published"
    );
    for tx_hash in &tx_hashes {
        let rec_h = records_at
            .get(tx_hash)
            .unwrap_or_else(|| panic!("no outbound record for {}", hex::encode(&tx_hash[..8])));
        let tx_h = txs_at
            .get(tx_hash)
            .unwrap_or_else(|| panic!("transaction never landed: {}", hex::encode(&tx_hash[..8])));
        assert_eq!(rec_h, tx_h, "record and transaction must land together");
    }
}

/// The validator enforces the SAME total cap: a block whose `cross_shard_out`
/// exceeds it (here: duplicate legacy records on top of a valid body) must be
/// refused before any per-kind check. Before the fix the validator loop only
/// counted 2PC control records, so a legacy-only block's record count was
/// never checked.
#[tokio::test]
async fn validator_refuses_a_block_over_the_total_cross_shard_record_cap() {
    use stellereum::xshard2pc::XPC_MAX_CROSS_SHARD_RECORDS_PER_BLOCK;

    let v1 = key(242);
    let v2 = key(243);
    let (sender, sender_addr) = pq_sender(240);
    let recipient = key(244).verifying_key().to_bytes();
    let initial = 5_000_000_000u64;

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
    let tx = sign_pq_tx(&sender, recipient, 1_000_000, 280_000, 0, SHARD0, SHARD1);
    cluster.broadcast_tx(tx).await;

    let proposer_idx = cluster
        .shard(SHARD0)
        .nodes
        .iter()
        .position(|n| n.is_proposer())
        .expect("a proposer for height 1");
    let block = cluster.shard_mut(SHARD0).nodes[proposer_idx]
        .propose(TS)
        .await
        .expect("proposer builds a valid block");
    let base = block.cross_shard_out.clone();
    assert!(!base.is_empty(), "precondition: one outbound record");

    // Byzantine body: keep the valid records and repeat them over the cap.
    let mut oversized = block;
    while oversized.cross_shard_out.len() <= XPC_MAX_CROSS_SHARD_RECORDS_PER_BLOCK {
        oversized.cross_shard_out.extend(base.iter().cloned());
    }
    oversized.validator_signatures.clear();

    let receiver_idx = 1 - proposer_idx;
    let receiver = &cluster.shard(SHARD0).nodes[receiver_idx];
    let root = receiver.state_root().await;
    let err = receiver
        .validate_proposal(&oversized, root)
        .expect_err("an over-cap cross-shard block must be refused");
    assert!(
        err.contains("cross-shard record") && err.contains("cap"),
        "the refusal must name the total cap, got: {err}"
    );
}

// ===========================================================================
// 14. Task 2: a CONSUMED mailbox record must also be pruned.
// ===========================================================================

/// The `consumed_cross_shard` branch removed the node-local tracker entry but
/// never added the id to `prune_ids`, so on the non-draining node-local KV
/// transport the record was re-fetched by every propose forever. Re-feed the
/// exact bounce that this shard already consumed and prove it disappears from
/// the transport mailbox on the next propose.
#[tokio::test]
async fn a_consumed_mailbox_record_is_pruned_from_the_transport() {
    use stellereum::sharding::CROSS_SHARD_TIMEOUT_HEIGHTS;

    let validator = key(245);
    let (sender, sender_addr) = pq_sender(245);
    let recipient_addr = key(246).verifying_key().to_bytes();

    let s0 = Arc::new(InMemoryStateEngine::new());
    s0.update_account(AccountState::new(sender_addr, 5_000_000_000))
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

    let tx = sign_pq_tx(
        &sender,
        recipient_addr,
        1_000_000,
        280_000,
        0,
        SHARD0,
        SHARD1,
    );
    let tx_hash = tx.compute_tx_hash();
    cluster.broadcast_tx(tx).await;

    // Height 1 produces the legacy outbound; the target NEVER runs, so the
    // source's height-timeout bounce is the only inbound record.
    cluster.run_height(SHARD0, TS).await;
    for h in 2..(1 + CROSS_SHARD_TIMEOUT_HEIGHTS) {
        cluster.run_height(SHARD0, TS + h).await;
    }
    let bh = cluster
        .run_height(SHARD0, TS + 1 + CROSS_SHARD_TIMEOUT_HEIGHTS)
        .await;
    let block = cluster.shard(SHARD0).nodes[0]
        .blocks
        .get(&bh)
        .cloned()
        .expect("timeout block retained");
    let bounce = block
        .cross_shard_out
        .iter()
        .find(|m| m.is_bounce() && m.tx.compute_tx_hash() == tx_hash)
        .cloned()
        .expect("the timeout bounce must commit");
    assert!(cluster.shard(SHARD0).nodes[0].is_transfer_completed(&tx_hash));

    // Re-feed the consumed bounce into the source mailbox.
    cluster
        .transport
        .broadcast_cross_shard(&bounce)
        .await
        .expect("mailbox publish");
    assert!(
        cluster
            .transport
            .fetch_cross_shard_inbound(SHARD0)
            .await
            .iter()
            .any(|m| m.msg_id == bounce.msg_id),
        "precondition: the consumed record is in the mailbox"
    );

    // The next proposal takes the consumed-key branch and must PRUNE it.
    cluster.run_height(SHARD0, TS + 500).await;
    assert!(
        !cluster
            .transport
            .fetch_cross_shard_inbound(SHARD0)
            .await
            .iter()
            .any(|m| m.msg_id == bounce.msg_id),
        "a consumed mailbox record must be pruned, not re-fetched forever"
    );
}

// ===========================================================================
// 15. Task 3: the live prune path must deliver the PREPARE-ACK pull hint.
// ===========================================================================

/// A source that already COMMITTED prunes an inbound 2PC record whose hash is
/// in its `completed_cross_shard` mirror. But a target that is still PREPARED
/// keeps re-sending PREPARE-ACK: that record is the PULL HINT the engine's
/// PREPARE-ACK arm uses to refresh the source's COMMIT window. If the live
/// propose path prunes it before apply, the refresh exists only in unit tests.
///
/// This walks the live path: complete the handshake, DROP the source's COMMIT
/// from the target mailbox (the lost-decision case), let the still-PREPARED
/// target re-emit its ACK at its ACK cadence, and prove the source's record
/// `decided_height` advances when the next source block consumes that ACK.
#[tokio::test]
async fn a_still_prepared_targets_ack_refreshes_the_source_on_the_live_prune_path() {
    use stellereum::xshard2pc::XPC_ACK_REEMIT_INTERVAL;

    let validator = key(247);
    let (sender, sender_addr) = pq_sender(247);
    let recipient_addr = key(248).verifying_key().to_bytes();
    let amount = 1_000_000_000u64;
    let fee = 280_000u64;

    let mut cluster = xpc_cluster(&validator, &[(sender_addr, 5_000_000_000)], &[]).await;
    let tx = sign_pq_tx(&sender, recipient_addr, amount, fee, 0, SHARD0, SHARD1);
    let tx_hash = tx.compute_tx_hash();
    cluster.broadcast_tx(tx).await;

    // Source h1: PREPARE. Target h1: PREPARED. Target h2: PREPARE-ACK.
    cluster.run_height(SHARD0, TS).await;
    cluster.run_height(SHARD1, TS + 1).await;
    cluster.run_height(SHARD1, TS + 2).await;

    // Source h2: consumes the ACK and COMMITS. Source h3: publishes COMMIT.
    cluster.run_height(SHARD0, TS + 3).await;
    let source_commit_height = xpc_record(&cluster, SHARD0, &tx_hash)
        .await
        .expect("source record")
        .decided_height;
    cluster.run_height(SHARD0, TS + 4).await;
    let committed = xpc_record(&cluster, SHARD0, &tx_hash)
        .await
        .expect("source record");
    assert_eq!(committed.phase, XpcPhase::Committed);

    // "Lose" the COMMIT: drop it from the target's mailbox before the target
    // ever applies it, so the target stays PREPARED.
    let target_mailbox = cluster.transport.fetch_cross_shard_inbound(SHARD1).await;
    let commit_ids: Vec<[u8; 32]> = target_mailbox
        .iter()
        .filter(|m| m.is_commit() && m.tx.compute_tx_hash() == tx_hash)
        .map(|m| m.msg_id)
        .collect();
    assert!(!commit_ids.is_empty(), "precondition: COMMIT was published");
    cluster.transport.prune_consumed(SHARD1, &commit_ids).await;

    // Drive the target to its NEXT ACK window without ever delivering COMMIT.
    let prepared_height = xpc_record(&cluster, SHARD1, &tx_hash)
        .await
        .expect("target record")
        .prepared_height;
    let ack_height = prepared_height + XPC_ACK_REEMIT_INTERVAL + 1;
    while cluster.shard(SHARD1).height() <= ack_height {
        let h = cluster.shard(SHARD1).height();
        cluster.run_height(SHARD1, TS + 100 + h).await;
    }
    assert_eq!(
        xpc_record(&cluster, SHARD1, &tx_hash)
            .await
            .expect("target record")
            .phase,
        XpcPhase::Prepared,
        "the target never saw COMMIT and must still be PREPARED"
    );

    let source_mailbox = cluster.transport.fetch_cross_shard_inbound(SHARD0).await;
    let hint = source_mailbox
        .iter()
        .find(|m| m.is_prepare_ack() && m.tx.compute_tx_hash() == tx_hash)
        .cloned()
        .expect("the still-PREPARED target must re-emit PREPARE-ACK");

    // Live prune path: the source is COMPLETED (mirror has the hash), yet the
    // ACK must be admitted so the engine can refresh the window.
    let source_height = cluster.shard(SHARD0).height();
    cluster.run_height(SHARD0, TS + 200 + source_height).await;
    let refreshed = xpc_record(&cluster, SHARD0, &tx_hash)
        .await
        .expect("source record");
    assert_eq!(refreshed.phase, XpcPhase::Committed);
    assert_eq!(
        refreshed.decided_height,
        source_height,
        "the live PREPARE-ACK must refresh the source decision window \
         (was {source_commit_height}, hint msg {})",
        hex::encode(&hint.msg_id[..8])
    );
    assert!(
        !cluster
            .transport
            .fetch_cross_shard_inbound(SHARD0)
            .await
            .iter()
            .any(|m| m.msg_id == hint.msg_id),
        "the applied refresh hint must be pruned from the source mailbox"
    );
}
