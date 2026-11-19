//! Sharding milestone M2: atomic, deterministic cross-shard value transfer.
//!
//! M1 proved two shards can run in one process. M2 proves value can move
//! between them:
//!
//!  1. A transaction whose `target_shard` differs from its `source_shard` is
//!     admitted to the SOURCE shard's mempool. When the source block finalizes,
//!     the transaction is applied there (sender debited), an outbound
//!     `CrossShardMessage` is committed into `Block.cross_shard_out`, and the
//!     value leaves the source exactly once.
//!  2. The target shard, producing its next block, pulls inbound messages from
//!     the node-local KV, commits a consumption record (the same
//!     `cross_shard_out` field), and credits the recipient.
//!  3. A consumed message can never be credited twice, and a caught-up node
//!     replays the same chain to the same state root.
//!
//! Everything is gated on `ShardRegistry::is_sharded()`, and `Block` /
//! `Transaction` gain NO new fields (`cross_shard_out` is pre-existing and is
//! already hashed into block identity), so every pre-sharding test is
//! untouched.

use ed25519_dalek::SigningKey;
use std::sync::Arc;
use stellereum::network::CrossShardTransport;
use stellereum::runtime::{Cluster, ShardedCluster};
use stellereum::sharding::{
    Block, CrossShardKey, CrossShardMessage, ShardRegistry, Transaction,
    BASE_WORKCHAIN_SHARD_INITIAL, MASTERCHAIN_SHARD,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

const SHARD0: u32 = MASTERCHAIN_SHARD;
const SHARD1: u32 = BASE_WORKCHAIN_SHARD_INITIAL;

fn key(seed: u8) -> SigningKey {
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

fn sharded() -> ShardRegistry {
    ShardRegistry::from_ids([SHARD0, SHARD1])
}

/// A fresh shard pair sharing one node-local cross-shard transport.
async fn sharded_pair(
    validator: &SigningKey,
    shard0_funding: &[([u8; 32], u64)],
    shard1_funding: &[([u8; 32], u64)],
) -> ShardedCluster {
    let s0 = Arc::new(InMemoryStateEngine::new());
    for (addr, bal) in shard0_funding {
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
    for (addr, bal) in shard1_funding {
        s1.update_account(AccountState::new(*addr, *bal)).await;
        if let Some((scheme, pk)) = Transaction::global_implicit_registry().lookup(addr) {
            use stellereum::post_quantum::DEFAULT_SALT;
            s1.pin_pubkey(*addr, scheme, &pk, &DEFAULT_SALT)
                .await
                .expect("PQ sender must pin");
        }
    }
    ShardedCluster::new(
        sharded(),
        vec![
            (SHARD0, vec![(validator.clone(), s0)]),
            (SHARD1, vec![(validator.clone(), s1)]),
        ],
        CrossShardTransport::local(),
    )
}

async fn balance(cluster: &Cluster, addr: &[u8; 32]) -> u64 {
    cluster.nodes[0]
        .state
        .get_account(addr)
        .await
        .map(|a| a.balance)
        .unwrap_or(0)
}

/// Build a genuine ESCROW-BACKED legacy inbound message for `tx`, the way a
/// two-step legacy producer would: the source applies the escrow block (the
/// debit), writes its SOURCE-SIDE ESCROW/DEBIT record, and then proves that
/// record against a source block header the target anchors to.
///
/// XSHARD-01: this — not the sender's account leaf — is the only proof an
/// inbound legacy credit accepts. Returns the source engine, the shared
/// finalized-header registry (holding the escrow block's post-apply root), and
/// the message.
async fn escrow_backed_legacy_message(
    tx: &Transaction,
) -> (
    Arc<InMemoryStateEngine>,
    Arc<std::sync::RwLock<stellereum::sharding::FinalizedHeaderRegistry>>,
    CrossShardMessage,
) {
    use stellereum::sharding::FinalizedHeaderRegistry;

    let tx_hash = tx.compute_tx_hash();
    let source = Arc::new(InMemoryStateEngine::new());
    source.enable_cross_shard();
    source
        .update_account(AccountState::new(tx.from, 1_000))
        .await;
    if let Some((scheme, pk)) = Transaction::global_implicit_registry().lookup(&tx.from) {
        use stellereum::post_quantum::DEFAULT_SALT;
        source
            .pin_pubkey(tx.from, scheme, &pk, &DEFAULT_SALT)
            .await
            .expect("PQ sender must pin");
    }
    let pre_root = source.get_state_root().await;
    let anchor_block = [0xABu8; 32];
    let placeholder = CrossShardMessage::new(
        tx.source_shard,
        tx.target_shard,
        tx.clone(),
        pre_root,
        anchor_block,
        None,
    );

    // Apply the escrow block on the SOURCE: this debits the sender and (the
    // `cross_shard_enabled` hook) writes the escrow/debit record.
    let escrow_block = Block {
        shard_id: tx.source_shard,
        height: 1,
        prev_hash: anchor_block,
        state_root: pre_root,
        transactions: vec![tx.clone()],
        cross_shard_out: vec![placeholder],
        timestamp: 1,
        proposer: [0x11u8; 32],
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        cnvrf_v3: None,
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
            round: 0,
    };    let out = source.apply_block_transition(&escrow_block, 0).await;
    assert_eq!(out.status, vec![true], "the escrow tx must apply");
    let post_root = source.get_state_root().await;
    assert_eq!(
        source.get_account(&tx.from).await.map(|a| a.balance),
        Some(1_000 - tx.amount - tx.gas_limit),
        "the source debited the sender (the escrow is real)"
    );

    let proof = source
        .get_legacy_escrow_proof(&tx_hash)
        .await
        .expect("the source recorded the escrow/debit leaf");

    let registry = Arc::new(std::sync::RwLock::new(FinalizedHeaderRegistry::default()));
    registry
        .write()
        .unwrap()
        .note_finalized(tx.source_shard, anchor_block, post_root);

    let msg = CrossShardMessage::new(
        tx.source_shard,
        tx.target_shard,
        tx.clone(),
        post_root,
        anchor_block,
        Some(proof),
    );
    assert!(
        msg.verify_escrow_proof(),
        "precondition: the escrow proof verifies"
    );
    (source, registry, msg)
}

/// Carrier block that delivers exactly the given records to `shard_id`.
fn carrier(shard_id: u32, height: u64, msgs: Vec<CrossShardMessage>) -> Block {
    Block {
        shard_id,
        height,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: vec![],
        cross_shard_out: msgs,
        timestamp: 1,
        proposer: [0x11u8; 32],
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        cnvrf_v3: None,
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
        round: 0,
    }}

// ===========================================================================
// XSHARD-01: the affordability-only inbound credit is REFUSED.
// ===========================================================================

/// THE XSHARD-01 REGRESSION. The legacy credit used to be paid against the
/// SENDER'S ACCOUNT LEAF at the source's pre-transfer root — a proof that the
/// sender COULD AFFORD the amount, not that the source ever DEBITED it.
///
/// This fixture is exactly the attack: a funded source account, a correctly
/// signed transaction that is NEVER applied on the source, and a perfectly
/// valid Merkle proof of the sender's unchanged leaf at a finalized source
/// header. Every old check passes (message id, signature, anchor, inclusion);
/// the credit must still be REFUSED, because no source-side escrow/debit
/// record exists for the transfer.
#[tokio::test]
async fn affordability_only_legacy_credit_is_refused() {
    let sender_addr = pq_id(61);
    let recipient_addr = key(62).verifying_key().to_bytes();
    let tx = pq_tx(61, recipient_addr, 250, 5, 0, SHARD0, SHARD1);

    // The source state the attacker points at: a funded sender that NEVER
    // applies the transaction.
    let source = InMemoryStateEngine::new();
    source
        .update_account(AccountState::new(sender_addr, 1_000))
        .await;
    if let Some((scheme, pk)) = Transaction::global_implicit_registry().lookup(&sender_addr) {
        use stellereum::post_quantum::DEFAULT_SALT;
        source
            .pin_pubkey(sender_addr, scheme, &pk, &DEFAULT_SALT)
            .await
            .expect("pin");
    }
    let source_root = source.get_state_root().await;
    let account_proof = source
        .get_account_proof(&sender_addr)
        .await
        .expect("the sender's account leaf");
    let pk_hash = source
        .get_account(&sender_addr)
        .await
        .and_then(|a| a.pubkey_hash)
        .expect("pinned PQ hash");
    let anchor_block = [0xCDu8; 32];
    let registry = Arc::new(std::sync::RwLock::new(
        stellereum::sharding::FinalizedHeaderRegistry::default(),
    ));
    registry
        .write()
        .unwrap()
        .note_finalized(SHARD0, anchor_block, source_root);

    let forged = CrossShardMessage::new(
        SHARD0,
        SHARD1,
        tx,
        source_root,
        anchor_block,
        Some(account_proof),
    )
    .with_source_balance(1_000)
    .with_sender_pubkey_hash(stellereum::post_quantum::PqScheme::Falcon512.id(), pk_hash);

    // Precondition: the OLD rule is fully satisfied — this is an
    // affordability-only proof, and it is cryptographically valid.
    assert!(
        forged.verify_inclusion_strict(),
        "precondition: the account-leaf (affordability) proof is valid"
    );
    assert!(
        forged.verify_anchored(Some(&registry.read().unwrap())),
        "precondition: the account-leaf proof is anchored"
    );
    // ...but it is NOT a source-side escrow/debit proof.
    assert!(
        !forged.verify_escrow_proof(),
        "an account-leaf proof must not pass as an escrow proof"
    );

    let target = InMemoryStateEngine::new();
    target.enable_cross_shard();
    target.with_finalized_headers(registry);
    let credited = target
        .apply_cross_shard_consumptions(&carrier(SHARD1, 1, vec![forged.clone()]))
        .await;
    assert_eq!(
        credited, 0,
        "a forged affordability-only credit must NOT pay"
    );
    assert_eq!(
        target.get_account(&recipient_addr).await.map(|a| a.balance),
        None,
        "the recipient must not be credited"
    );
    assert_eq!(
        target.cross_shard_consumed_len().await,
        0,
        "a refused message must not touch the replay set"
    );
    assert!(
        !target
            .is_cross_shard_consumed(&CrossShardKey::of(&forged))
            .await,
        "a refused message must stay unconsumed (and refundable by the source)"
    );

    // A later apply of the SAME forgery is still refused (no delayed credit).
    assert_eq!(
        target
            .apply_cross_shard_consumptions(&carrier(SHARD1, 2, vec![forged]))
            .await,
        0
    );
    assert_eq!(
        target.get_account(&recipient_addr).await.map(|a| a.balance),
        None
    );
}

/// The POSITIVE control for the same gate: the SAME transfer, but with the
/// source's committed ESCROW/DEBIT proof, credits exactly once — and a replay
/// is refused. This is the stronger proof the legacy path now requires.
#[tokio::test]
async fn escrow_backed_legacy_credit_is_paid_exactly_once() {
    let recipient_addr = key(64).verifying_key().to_bytes();
    let tx = pq_tx(63, recipient_addr, 250, 5, 0, SHARD0, SHARD1);

    let (_source, registry, msg) = escrow_backed_legacy_message(&tx).await;
    assert!(msg.is_transfer(), "precondition: a legacy transfer record");

    let target = Arc::new(InMemoryStateEngine::new());
    target.enable_cross_shard();
    target.with_finalized_headers(registry);
    let block = carrier(SHARD1, 1, vec![msg.clone()]);

    assert_eq!(
        target.apply_cross_shard_consumptions(&block).await,
        1,
        "an escrow-backed message must credit exactly once"
    );
    assert_eq!(
        target.get_account(&recipient_addr).await.map(|a| a.balance),
        Some(250)
    );
    assert_eq!(target.cross_shard_consumed_len().await, 1);
    assert!(
        target
            .is_cross_shard_consumed(&CrossShardKey::of(&msg))
            .await
    );

    // Replay: the atomic claim refuses a second credit with the root unmoved.
    let root_after = target.get_state_root().await;
    assert_eq!(
        target.apply_cross_shard_consumptions(&block).await,
        0,
        "a replayed escrow-backed message must not credit twice"
    );
    assert_eq!(
        target.get_account(&recipient_addr).await.map(|a| a.balance),
        Some(250)
    );
    assert_eq!(target.get_state_root().await, root_after);
    assert_eq!(target.cross_shard_consumed_len().await, 1);
}

/// The value transfer at the heart of M2, run through the §9 2PC (the ONLY
/// cross-shard value path: XSHARD-01 disabled the legacy one-step credit,
/// because a message published in the same block that escrows it cannot prove
/// the source-side debit).
#[tokio::test]
async fn cross_shard_transfer_debits_source_credits_target_and_conserves_supply() {
    use stellereum::xshard2pc::XpcActivation;

    let validator = key(1);
    let sender_addr = pq_id(2);
    let recipient_addr = key(3).verifying_key().to_bytes();
    let validator_addr = validator.verifying_key().to_bytes();

    let mut sc = sharded_pair(&validator, &[(sender_addr, 1_000)], &[]).await;
    sc.with_xpc_activation(XpcActivation::FromHeight(0));
    let supply_before = balance(sc.shard(SHARD0), &sender_addr).await
        + balance(sc.shard(SHARD0), &validator_addr).await
        + balance(sc.shard(SHARD1), &recipient_addr).await;

    let amount = 100u64;
    let gas = 10u64;
    let tx = pq_tx(2, recipient_addr, amount, gas, 0, SHARD0, SHARD1);

    // Admitted to the SOURCE shard's mempool. The destination rejects it (its
    // sender has no balance there), which is exactly the single-source rule.
    sc.shard_mut(SHARD0).broadcast_tx(tx.clone()).await;
    sc.shard_mut(SHARD1).broadcast_tx(tx.clone()).await;

    // 1. Source block: debit + emit the committed PREPARE (never a bare
    //    transfer: a bare transfer is what XSHARD-01 refuses to credit).
    let src_bh = sc.run_height(SHARD0, 1).await;
    let src_block = sc.shard(SHARD0).nodes[0]
        .blocks
        .get(&src_bh)
        .cloned()
        .expect("source block body retained");

    assert_eq!(src_block.shard_id, SHARD0);
    assert!(
        src_block
            .transactions
            .iter()
            .any(|t| t.compute_tx_hash() == tx.compute_tx_hash()),
        "the cross-shard tx must be applied on its source shard"
    );
    assert_eq!(
        src_block.cross_shard_out.len(),
        1,
        "source must emit one outbound message"
    );
    let msg = src_block.cross_shard_out[0].clone();
    assert!(msg.is_outbound_for(SHARD0));
    assert!(
        !msg.is_transfer(),
        "a 2PC transfer must not be published as a bare transfer"
    );
    assert!(
        !msg.trusted,
        "a block-carried message must never be locally trusted"
    );

    // Sender debited amount + gas; the amount is burned off-source into the
    // escrow; the gas is the proposer fee. The recipient does NOT exist on the
    // source shard.
    assert_eq!(
        balance(sc.shard(SHARD0), &sender_addr).await,
        1_000 - amount - gas
    );
    assert_eq!(balance(sc.shard(SHARD0), &validator_addr).await, gas);
    assert!(sc.shard(SHARD0).nodes[0]
        .state
        .get_account(&recipient_addr)
        .await
        .is_none());

    // 2. Target block: consume the PREPARE (record PREPARED, vote YES) but do
    //    NOT credit yet.
    let tgt_bh = sc.run_height(SHARD1, 2).await;
    let tgt_block = sc.shard(SHARD1).nodes[0]
        .blocks
        .get(&tgt_bh)
        .cloned()
        .expect("target block body retained");

    assert_eq!(tgt_block.shard_id, SHARD1);
    assert!(
        tgt_block.transactions.is_empty(),
        "the destination must not re-apply the transaction as a normal tx"
    );
    assert!(
        tgt_block
            .cross_shard_out
            .iter()
            .any(|m| m.is_inbound_for(SHARD1)),
        "the target block must commit the 2PC record"
    );
    assert_eq!(
        balance(sc.shard(SHARD1), &recipient_addr).await,
        0,
        "the target must not credit before the source commits"
    );

    // 3. Drive the handshake to COMMIT: the recipient is credited exactly once.
    let mut ts = 3u64;
    for _ in 0..4 {
        sc.run_height(SHARD0, ts).await;
        ts += 1;
        sc.run_height(SHARD1, ts).await;
        ts += 1;
    }
    assert_eq!(
        balance(sc.shard(SHARD1), &recipient_addr).await,
        amount,
        "the recipient must be credited exactly once on the target shard"
    );

    // Supply across BOTH shards is conserved (the escrow is released, not
    // minted): the amount moved, the fee paid the proposer.
    let supply_after = balance(sc.shard(SHARD0), &sender_addr).await
        + balance(sc.shard(SHARD0), &validator_addr).await
        + balance(sc.shard(SHARD1), &recipient_addr).await;
    assert_eq!(
        supply_after, supply_before,
        "cross-shard transfer must conserve supply"
    );

    // Determinism: a block's cross-shard records are bound into its identity.
    let commit_block = sc.shard(SHARD1).nodes[0]
        .blocks
        .values()
        .find(|b| !b.cross_shard_out.is_empty())
        .cloned()
        .expect("the target committed at least one cross-shard record");
    let mut tampered = commit_block.clone();
    tampered.cross_shard_out.clear();
    tampered.validator_signatures.clear();
    tampered.sign_block(&validator);
    assert_ne!(
        tampered.compute_hash(),
        commit_block.compute_hash(),
        "dropping a consumption record must change the target block hash"
    );
}

/// REGRESSION (was F2 FINDING, high): an inbound cross-shard credit moves
/// value the SOURCE shard already escrowed, so it must be a transfer of
/// existing supply, never a mint. The old code credited through the capped
/// `credit_native`; a target at the global cap refused the credit, never
/// marked the message consumed and lost the value.
///
/// This drives the LIVE target path (`ShardedCluster::run_height`, i.e.
/// `apply_block_transition`) with zero mint headroom along the only
/// cross-shard value path (the §9 2PC, XSHARD-01): the recipient must still be
/// credited exactly once, the mint counter must not move, and a later target
/// height must not credit again.
#[tokio::test]
async fn inbound_credit_at_the_supply_cap_still_credits_on_the_live_target() {
    use stellereum::xshard2pc::XpcActivation;

    let validator = key(50);
    let sender_addr = pq_id(51);
    let recipient_addr = key(52).verifying_key().to_bytes();
    let amount = 250u64;
    let gas = 5u64;

    let mut sc = sharded_pair(&validator, &[(sender_addr, 1_000)], &[]).await;
    sc.with_xpc_activation(XpcActivation::FromHeight(0));
    let tx = pq_tx(51, recipient_addr, amount, gas, 0, SHARD0, SHARD1);
    let tx_hash = tx.compute_tx_hash();
    sc.shard_mut(SHARD0).broadcast_tx(tx).await;
    sc.run_height(SHARD0, 1).await;
    assert_eq!(
        balance(sc.shard(SHARD0), &sender_addr).await,
        1_000 - amount - gas,
        "precondition: the source already escrowed the amount"
    );

    // Exhaust the TARGET shard's CHAIN-WIDE mint share before it can commit.
    // With two shards the share is cap/2 (ruleset v5); the property under test
    // is "a transfer still credits at ZERO mint headroom", not the size of the
    // share.
    let target = sc.shard(SHARD1).nodes[0].state.clone();
    let seeded = target.genesis_allocation_nano().await;
    let share = target.chain_mint_limit_nano();
    target
        .mint_native(&[0xF9u8; 32], share - seeded)
        .await
        .expect("fill the target's chain-wide supply share");
    assert_eq!(target.remaining_mint_headroom_nano(), 0);
    let minted_before = target.total_minted_nano();

    // Drive the 2PC handshake: the credit lands on the COMMIT, at zero headroom.
    let mut ts = 2u64;
    for _ in 0..4 {
        sc.run_height(SHARD0, ts).await;
        ts += 1;
        sc.run_height(SHARD1, ts).await;
        ts += 1;
    }

    assert_eq!(
        balance(sc.shard(SHARD1), &recipient_addr).await,
        amount,
        "an inbound transfer must be credited at zero mint headroom"
    );
    assert_eq!(
        target.total_minted_nano(),
        minted_before,
        "a transfer must not move the mint counter"
    );
    assert_eq!(
        target.remaining_mint_headroom_nano(),
        0,
        "the credit consumed no headroom"
    );
    assert!(
        target.is_cross_shard_completed(&tx_hash).await,
        "the transfer completed exactly once"
    );
    assert!(
        target.mint_native(&[0xFAu8; 32], 1).await.is_err(),
        "real issuance stays refused at the cap"
    );

    // A later target height never credits the (completed) transfer again.
    sc.run_height(SHARD1, ts).await;
    assert_eq!(balance(sc.shard(SHARD1), &recipient_addr).await, amount);
}

/// The replay proof, at the state-engine level: applying the SAME escrow-backed
/// inbound message twice credits exactly once and never mints a second time.
/// This is the guard that makes a rebuilding/caught-up shard deterministic.
#[tokio::test]
async fn replaying_a_consumed_message_is_credited_only_once() {
    let recipient_addr = key(12).verifying_key().to_bytes();
    let tx = pq_tx(11, recipient_addr, 250, 5, 0, SHARD0, SHARD1);

    // A genuine message carrying the SOURCE's escrow/debit proof (XSHARD-01:
    // the affordability-only form is refused, see
    // `affordability_only_legacy_credit_is_refused`).
    let (_source, registry, msg) = escrow_backed_legacy_message(&tx).await;
    assert!(
        msg.verify_escrow_proof(),
        "the emitted message must carry a valid escrow proof"
    );

    // A pristine target engine (what a rebuilding node starts from).
    let engine = Arc::new(InMemoryStateEngine::new());
    engine.enable_cross_shard();
    engine.with_finalized_headers(registry);
    let block = carrier(SHARD1, 1, vec![msg.clone()]);

    let first = engine.apply_cross_shard_consumptions(&block).await;
    assert_eq!(first, 1, "the first application must credit");
    assert_eq!(
        engine.get_account(&recipient_addr).await.unwrap().balance,
        250
    );

    // Replaying the identical consumption record (as a Byzantine proposer
    // might) must be a no-op.
    let second = engine.apply_cross_shard_consumptions(&block).await;
    assert_eq!(second, 0, "a replayed message must be rejected");
    assert_eq!(
        engine.get_account(&recipient_addr).await.unwrap().balance,
        250,
        "replay must not mint a second time"
    );
    assert_eq!(engine.cross_shard_consumed_len().await, 1);
    assert!(
        engine
            .is_cross_shard_consumed(&CrossShardKey::of(&msg))
            .await
    );
}

/// The runtime-level replay proof: a duplicate lingering in the KV is filtered
/// out of the next target block, and `validate_proposal` refuses a forged
/// proposal that re-includes it.
///
/// XSHARD-01: the value path is the §9 2PC, so the record replayed here is the
/// terminal COMMIT (the one that credits). The `completed` guard must still
/// make a double credit impossible.
#[tokio::test]
async fn target_filters_and_rejects_a_replayed_inbound_message() {
    use stellereum::xshard2pc::XpcActivation;

    let validator = key(20);
    let sender_addr = pq_id(21);
    let recipient_addr = key(22).verifying_key().to_bytes();

    let mut sc = sharded_pair(&validator, &[(sender_addr, 1_000)], &[]).await;
    sc.with_xpc_activation(XpcActivation::FromHeight(0));
    let tx = pq_tx(21, recipient_addr, 300, 5, 0, SHARD0, SHARD1);
    let tx_hash = tx.compute_tx_hash();
    sc.shard_mut(SHARD0).broadcast_tx(tx).await;

    // Drive the handshake; the credit lands on the COMMIT.
    let mut ts = 1u64;
    for _ in 0..4 {
        sc.run_height(SHARD0, ts).await;
        ts += 1;
        sc.run_height(SHARD1, ts).await;
        ts += 1;
    }
    assert_eq!(balance(sc.shard(SHARD1), &recipient_addr).await, 300);

    // The terminal record the target consumed: the inbound COMMIT.
    let commit = sc.shard(SHARD1).nodes[0]
        .blocks
        .values()
        .flat_map(|b| b.cross_shard_out.iter())
        .find(|m| m.is_inbound_for(SHARD1) && m.is_commit())
        .cloned()
        .expect("the target consumed a COMMIT");

    // Re-publish the SAME record (a stale KV entry) and run another height:
    // the target must skip it rather than credit twice.
    sc.transport.broadcast_cross_shard(&commit).await.unwrap();
    let bh2 = sc.run_height(SHARD1, ts).await;
    let block2 = sc.shard(SHARD1).nodes[0].blocks.get(&bh2).cloned().unwrap();
    assert!(
        block2
            .cross_shard_out
            .iter()
            .all(|m| m.msg_id != commit.msg_id),
        "a completed message must not be re-included"
    );
    assert_eq!(balance(sc.shard(SHARD1), &recipient_addr).await, 300);

    // A forged proposal that re-includes the completed record is refused by
    // validation, even though its proof is cryptographically valid: the
    // lifecycle already completed on this chain.
    let node = &sc.shard(SHARD1).nodes[0];
    let height = node.height();
    let prev = node.finalized.last().map(|(_, h)| *h).unwrap_or([0u8; 32]);
    let root = node.state_root().await;
    let mut forged = Block {
        shard_id: SHARD1,
        height,
        prev_hash: prev,
        state_root: root,
        transactions: vec![],
        cross_shard_out: vec![commit.clone()],
        timestamp: ts + 1,
        proposer: validator.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        cnvrf_v3: None,
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
        round: 0,
    };    forged.sign_block(&validator);
    let err = node
        .validate_proposal(&forged, root)
        .expect_err("a replayed consumption must be refused");
    assert!(
        err.contains("replayed") || err.contains("completed"),
        "refusal must name the replay/completion: {err}"
    );
    assert!(
        sc.shard(SHARD1).nodes[0]
            .state
            .is_cross_shard_completed(&tx_hash)
            .await
    );
}

/// Two independently-built target shards, given the SAME committed message,
/// derive the SAME state root. This is the determinism guarantee requirement 3
/// asks for: state moves only from a block, and the block is the same bytes.
#[tokio::test]
async fn two_independent_target_shards_derive_the_same_root() {
    let recipient_addr = key(32).verifying_key().to_bytes();
    let tx = pq_tx(31, recipient_addr, 123, 7, 0, SHARD0, SHARD1);

    // One source escrow: a genuine message carrying the SOURCE's escrow/debit
    // proof (XSHARD-01: the affordability-only form is refused).
    let (_source, registry, msg) = escrow_backed_legacy_message(&tx).await;
    let block = carrier(SHARD1, 1, vec![msg]);

    // Two independent target shards with identical genesis, each applying the
    // SAME committed record. State moves only from the block, so the roots must
    // agree.
    let mut roots = Vec::new();
    for _ in 0..2 {
        let engine = Arc::new(InMemoryStateEngine::new());
        engine.enable_cross_shard();
        engine.with_finalized_headers(registry.clone());
        // Identical genesis on both: one unrelated funded account so the root
        // is not the empty-trie root.
        engine
            .update_account(AccountState::new([0xAAu8; 32], 777))
            .await;
        assert_eq!(
            engine.apply_cross_shard_consumptions(&block).await,
            1,
            "the escrow-backed credit must be paid on each target"
        );
        roots.push(engine.get_state_root().await);
    }

    assert_eq!(
        roots[0], roots[1],
        "two independently-built target shards must derive the same state root"
    );
}

/// A caught-up / rebuilding target shard replays the SAME committed records and
/// reaches the SAME state root as the node that originally applied them.
///
/// The live target applies block H and credits the recipient; a second target
/// starts from identical genesis and applies an equivalent block carrying the
/// same message. State moves only from the block, so the roots must agree —
/// and a replay of the record on the rebuilt engine must then be a no-op.
#[tokio::test]
async fn a_rebuilding_target_reproduces_the_same_root_and_rejects_replay() {
    let recipient_addr = key(42).verifying_key().to_bytes();
    let tx = pq_tx(41, recipient_addr, 400, 5, 0, SHARD0, SHARD1);

    // A genuine message carrying the SOURCE's escrow/debit proof.
    let (_source, registry, msg) = escrow_backed_legacy_message(&tx).await;
    let record = carrier(SHARD1, 1, vec![msg.clone()]);

    // Live target: applies the committed record.
    let live = Arc::new(InMemoryStateEngine::new());
    live.enable_cross_shard();
    live.with_finalized_headers(registry.clone());
    assert_eq!(live.apply_cross_shard_consumptions(&record).await, 1);
    let live_root = live.get_state_root().await;
    assert_eq!(
        live.get_account(&recipient_addr).await.unwrap().balance,
        400
    );

    // Rebuilding target: identical genesis, SAME committed record bytes.
    let engine = Arc::new(InMemoryStateEngine::new());
    engine.enable_cross_shard();
    engine.with_finalized_headers(registry);
    engine.apply_block_transition(&record, 0).await;
    assert_eq!(
        engine.get_account(&recipient_addr).await.unwrap().balance,
        400
    );
    assert_eq!(
        engine.get_state_root().await,
        live_root,
        "a rebuilding target must derive the state root the live target committed"
    );

    // Replaying the same committed record on the rebuilt engine is refused.
    let again = engine.apply_cross_shard_consumptions(&record).await;
    assert_eq!(again, 0, "replay must credit nothing");
    assert_eq!(
        engine.get_account(&recipient_addr).await.unwrap().balance,
        400
    );
    assert_eq!(engine.get_state_root().await, live_root);
}
