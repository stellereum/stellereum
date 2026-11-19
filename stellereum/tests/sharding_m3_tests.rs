//! Sharding milestone M3 (§5 core): shared-sequencer-adjacent two-phase
//! atomicity — ack/bounce protocol over `Block.cross_shard_out`.
//!
//! M2 proved one-way source-burn + target-mint. M3 proves the return path:
//!
//!  1. Happy path: target consumes, publishes an ack; the source commits the
//!     ack record and the transfer COMPLETES (no bounce may ever follow).
//!  2. Failure path: target never consumes; after a deterministic TIMEOUT in
//!     heights (`CROSS_SHARD_TIMEOUT_HEIGHTS`) the source commits a
//!     bounce-back record refunding `tx.amount` to `tx.from` — exactly once.
//!  3. Replay of an ack/bounce (same bytes, or a rebuilt carrier) is refused
//!     at proposal, at validation, and at apply; two independent shards
//!     applying the same bounce derive the same root.
//!  4. Control records carry NO Merkle proof and are refused if they do (the
//!     engine would otherwise credit `tx.to` on the source — a mint).
//!
//! No new `Block`/`Transaction` fields anywhere: kinds ride the pre-existing
//! `source_shard`/`target_shard` direction + `bounce`/`bounced` flags.

use ed25519_dalek::SigningKey;
use std::sync::Arc;
use stellereum::consensus::VoteKind;
use stellereum::network::CrossShardTransport;
use stellereum::post_quantum::FalconKeypair;
use stellereum::runtime::ShardedCluster;
use stellereum::sharding::{
    bounce_eligible, Block, CrossShardKey, ShardRegistry, Transaction,
    BASE_WORKCHAIN_SHARD_INITIAL, CROSS_SHARD_TIMEOUT_HEIGHTS, MASTERCHAIN_SHARD,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

#[path = "support/falcon_votes.rs"]
#[allow(dead_code)]
// GATE: replay test uses only `fvote_deterministic`; `fvote` stays for other suites (realism preserved).
mod falcon_votes;

const SHARD0: u32 = MASTERCHAIN_SHARD;
const SHARD1: u32 = BASE_WORKCHAIN_SHARD_INITIAL;
const TS: u64 = 1_760_000_000;

/// FULL-PQ cross-shard transfer with a NON-ZERO amount, carrying the source /
/// target shard pair of the §9 2PC tests below.
fn pq_xpc_tx(sender_seed: u8, to: [u8; 32], amount: u64) -> Transaction {
    use stellereum::post_quantum::{PqScheme, PqSignatureEnvelope};
    let pk = Transaction::sample_falcon512_pubkey(sender_seed);
    let from = pq_id(sender_seed);
    let mut t = Transaction {
        from,
        to,
        amount,
        gas_limit: 5,
        nonce: 0,
        source_shard: SHARD0,
        target_shard: SHARD1,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg = t.signing_message();
    let sig = Transaction::create_falcon512_test_signature(&pk, &msg, sender_seed);
    t.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig).encode();
    t
}

/// A carrier block that delivers exactly one record to `shard_id`.
fn xpc_carrier(shard_id: u32, height: u64, msg: stellereum::sharding::CrossShardMessage) -> Block {
    Block {
        shard_id,
        height,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: vec![],
        cross_shard_out: vec![msg],
        timestamp: TS,
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

/// REGRESSION (was F2 FINDING, refund leg): the §9 ABORT-ACK refunds value the
/// source already ESCROWED, so it is a transfer of existing supply and must not
/// be refused at the global mint cap. Exactly-once is an ATOMIC CLAIM (audit
/// F3 twin): the `cross_shard_completed` insert decides which apply pays.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn xpc_abort_refund_at_the_cap_is_paid_exactly_once_under_concurrency() {
    use stellereum::sharding::{CrossShardMessage, FinalizedHeaderRegistry};
    use stellereum::tokenomics::TOTAL_SUPPLY_CAP;
    use stellereum::xshard2pc::{XpcPhase, XpcRecord, XPC_ABORT_ACK};

    const N: usize = 8;
    let sender_seed = 0xB0u8;
    let sender = pq_id(sender_seed);
    let recipient = key(0xB1).verifying_key().to_bytes();
    let amount = 320u64;
    let tx = pq_xpc_tx(sender_seed, recipient, amount);
    let tx_hash = tx.compute_tx_hash();

    // The PEER (target) shard never prepared: its committed record is ABORTED.
    let peer = InMemoryStateEngine::new();
    let aborted = XpcRecord {
        tx: tx.clone(),
        tx_hash,
        source_shard: SHARD0,
        target_shard: SHARD1,
        phase: XpcPhase::Aborted,
        prepared_height: 5,
        decided_height: 6,
    };
    assert!(aborted.is_consistent(), "precondition: well-formed record");
    peer.restore_xpc_records(std::slice::from_ref(&aborted))
        .await;
    let peer_root = peer.get_state_root().await;
    let peer_block = [0xB7u8; 32];
    let proof = peer
        .get_xpc_proof(&tx_hash)
        .await
        .expect("the ABORTED leaf is provable at the peer root");
    let registry = Arc::new(std::sync::RwLock::new(FinalizedHeaderRegistry::default()));
    registry
        .write()
        .unwrap()
        .note_finalized(SHARD1, peer_block, peer_root);

    // The source under test: escrowed, then filled to the global cap.
    let source = Arc::new(InMemoryStateEngine::new());
    source.enable_cross_shard();
    source.with_finalized_headers(registry);
    source
        .update_account(AccountState::new(sender, 1_000))
        .await;
    source
        .restore_xpc_records(&[XpcRecord::prepared(tx.clone(), SHARD0, SHARD1, 4)])
        .await;
    // Fill EXACTLY to the cap: the seeded balance is pre-minted supply and is
    // folded into the counter by this reservation (F4), so subtract it.
    let seeded = source.genesis_allocation_nano().await;
    source
        .mint_native(&[0xB8u8; 32], TOTAL_SUPPLY_CAP - seeded)
        .await
        .expect("fill the source to the global cap");
    assert_eq!(source.remaining_mint_headroom_nano(), 0);
    let minted_before = source.total_minted_nano();

    let msg = CrossShardMessage::new_xpc(
        XPC_ABORT_ACK,
        SHARD1,
        SHARD0,
        tx,
        peer_root,
        peer_block,
        Some(proof),
    );
    assert!(msg.is_abort_ack());
    assert!(msg.is_inbound_for(SHARD0));
    let carrier = xpc_carrier(SHARD0, 7, msg);

    // Deterministic race: hold the accounts write lock so every task reaches
    // the claim window before any of them can credit.
    let gate = source.accounts.write().await;
    let barrier = Arc::new(tokio::sync::Barrier::new(N + 1));
    let mut tasks = Vec::new();
    for _ in 0..N {
        let source = source.clone();
        let carrier = carrier.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            source.apply_cross_shard_consumptions(&carrier).await;
        }));
    }
    barrier.wait().await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    drop(gate);
    for t in tasks {
        t.await.expect("no task may panic");
    }

    assert_eq!(
        source.get_account(&sender).await.map(|a| a.balance),
        Some(1_000 + amount),
        "exactly one refund at zero mint headroom"
    );
    assert_eq!(
        source.total_minted_nano(),
        minted_before,
        "a refund is a transfer, not a mint"
    );
    assert_eq!(source.remaining_mint_headroom_nano(), 0);
    assert_eq!(
        source.xpc_record(&tx_hash).await.map(|r| r.phase),
        Some(XpcPhase::Aborted)
    );
    assert!(source.is_cross_shard_completed(&tx_hash).await);
    assert!(
        source.mint_native(&[0xB9u8; 32], 1).await.is_err(),
        "issuance is still refused at the cap"
    );
}

/// The COMMIT twin of the test above (audit F3, §9 credit): 8 concurrent
/// applies of ONE COMMIT at zero mint headroom credit the recipient exactly
/// once, through the uncapped transfer primitive.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_xpc_commit_at_the_cap_credits_exactly_once() {
    use stellereum::sharding::{CrossShardMessage, FinalizedHeaderRegistry};
    use stellereum::tokenomics::TOTAL_SUPPLY_CAP;
    use stellereum::xshard2pc::{XpcPhase, XpcRecord, XPC_COMMIT};

    const N: usize = 8;
    let sender_seed = 0xB2u8;
    let _sender = pq_id(sender_seed);
    let recipient = key(0xB3).verifying_key().to_bytes();
    let amount = 444u64;
    let tx = pq_xpc_tx(sender_seed, recipient, amount);
    let tx_hash = tx.compute_tx_hash();

    // The SOURCE peer escrowed the value: its committed record is PREPARED and
    // the COMMIT proves that leaf against its finalized root.
    let peer = InMemoryStateEngine::new();
    peer.restore_xpc_records(&[XpcRecord::prepared(tx.clone(), SHARD0, SHARD1, 4)])
        .await;
    let peer_root = peer.get_state_root().await;
    let peer_block = [0xB4u8; 32];
    let proof = peer
        .get_xpc_proof(&tx_hash)
        .await
        .expect("the PREPARED leaf is provable at the source root");
    let registry = Arc::new(std::sync::RwLock::new(FinalizedHeaderRegistry::default()));
    registry
        .write()
        .unwrap()
        .note_finalized(SHARD0, peer_block, peer_root);

    // The target under test: it voted YES (PREPARED), then the cap is filled.
    let target = Arc::new(InMemoryStateEngine::new());
    target.enable_cross_shard();
    target.with_finalized_headers(registry);
    target
        .restore_xpc_records(&[XpcRecord::prepared(tx.clone(), SHARD0, SHARD1, 4)])
        .await;
    // Fill EXACTLY to the cap (pre-minted balances are folded into the counter
    // by the reservation itself, F4).
    let seeded = target.genesis_allocation_nano().await;
    target
        .mint_native(&[0xB5u8; 32], TOTAL_SUPPLY_CAP - seeded)
        .await
        .expect("fill the target to the global cap");
    assert_eq!(target.remaining_mint_headroom_nano(), 0);
    let minted_before = target.total_minted_nano();

    let msg = CrossShardMessage::new_xpc(
        XPC_COMMIT,
        SHARD0,
        SHARD1,
        tx,
        peer_root,
        peer_block,
        Some(proof),
    );
    assert!(msg.is_commit());
    assert!(msg.is_inbound_for(SHARD1));
    let carrier = xpc_carrier(SHARD1, 7, msg);

    let gate = target.accounts.write().await;
    let barrier = Arc::new(tokio::sync::Barrier::new(N + 1));
    let mut tasks = Vec::new();
    for _ in 0..N {
        let target = target.clone();
        let carrier = carrier.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            target.apply_cross_shard_consumptions(&carrier).await;
        }));
    }
    barrier.wait().await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    drop(gate);
    for t in tasks {
        t.await.expect("no task may panic");
    }

    assert_eq!(
        target.get_account(&recipient).await.map(|a| a.balance),
        Some(amount),
        "exactly one credit at zero mint headroom"
    );
    assert_eq!(
        target.total_minted_nano(),
        minted_before,
        "a COMMIT credit is a transfer, not a mint"
    );
    assert_eq!(target.remaining_mint_headroom_nano(), 0);
    assert_eq!(
        target.xpc_record(&tx_hash).await.map(|r| r.phase),
        Some(XpcPhase::Committed)
    );
    assert_eq!(
        target.cross_shard_consumed_len().await,
        0,
        "§9 value keys stay out of the legacy consumed set"
    );
}

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

async fn balance(sc: &ShardedCluster, shard: u32, addr: &[u8; 32]) -> u64 {
    sc.shard(shard).nodes[0]
        .state
        .get_account(addr)
        .await
        .map(|a| a.balance)
        .unwrap_or(0)
}

fn block_of(sc: &ShardedCluster, shard: u32, bh: [u8; 32]) -> Block {
    sc.shard(shard).nodes[0]
        .blocks
        .get(&bh)
        .cloned()
        .expect("block body retained")
}

/// Produce one outbound transfer on the source shard and return its tx hash.
async fn produce_transfer(
    sc: &mut ShardedCluster,
    sender_seed: u8,
    to: [u8; 32],
    ts: u64,
) -> [u8; 32] {
    let tx = pq_tx(sender_seed, to, 100, 10, 0, SHARD0, SHARD1);
    produce_transfer_of(sc, &tx, ts).await
}

/// Broadcast an already-signed transfer and run the source height.
/// Byte-identical input across callers: Falcon signing randomizes per
/// signing (FIPS 206), so two independent signings are two DIFFERENT
/// transfers. Determinism tests feed the SAME signed bytes here; every
/// assert matches `produce_transfer`.
async fn produce_transfer_of(sc: &mut ShardedCluster, tx: &Transaction, ts: u64) -> [u8; 32] {
    let txh = tx.compute_tx_hash();
    sc.shard_mut(SHARD0).broadcast_tx(tx.clone()).await;
    sc.shard_mut(SHARD1).broadcast_tx(tx.clone()).await;
    let bh = sc.run_height(SHARD0, ts).await;
    let blk = block_of(sc, SHARD0, bh);
    assert_eq!(blk.cross_shard_out.len(), 1);
    assert!(blk.cross_shard_out[0].is_transfer());
    assert_eq!(
        sc.shard(SHARD0).nodes[0].produced_cross_shard_height(&txh),
        Some(1)
    );
    txh
}

/// TEST-ONLY deterministic height driver for the bounce-replay test.
///
/// Mirrors `Cluster::run_height` for the single-node shard but mints the
/// prevote/precommit via `falcon_votes::fvote_deterministic` (seed 0 = the
/// single node's Falcon index, matching `Cluster::new_sharded`'s
/// `generate_from_seed(i)`). Same vote contents reuse the same Falcon bytes
/// (process-global cache), so two independent clusters fed the same tx walk
/// derive the same QCs, the same block hashes, the same msg_ids and the same
/// state roots. Production `run_height` (fresh randomness per sig) is
/// untouched; every other test keeps it (realism preserved).
async fn det_run_height(sc: &mut ShardedCluster, validator: &SigningKey, ts: u64) -> [u8; 32] {
    let cluster = sc.shard_mut(SHARD0);
    assert_eq!(
        cluster.nodes.len(),
        1,
        "det path is single-node only (bounce replay)"
    );
    let h = cluster.nodes[0].hc.height;
    let r = cluster.nodes[0].hc.round;
    let block = cluster.nodes[0]
        .propose(ts)
        .await
        .expect("det propose must succeed");
    let bh = block.compute_hash();
    // Single-node Falcon index is 0 (see `Cluster::new_sharded`).
    let fk = FalconKeypair::generate_from_seed(0);
    let pv =
        falcon_votes::fvote_deterministic(0, validator, &fk, h, r, VoteKind::Prevote, Some(bh));
    let _ = cluster.nodes[0].on_prevote(pv);
    let pc =
        falcon_votes::fvote_deterministic(0, validator, &fk, h, r, VoteKind::Precommit, Some(bh));
    let _ = cluster.nodes[0].on_precommit(pc);
    let finalized = cluster.nodes[0]
        .try_finalize()
        .await
        .expect("det finalize must succeed");
    assert_eq!(finalized, bh, "det finalize must return the proposed hash");
    bh
}

/// Deterministic variant of `produce_transfer_of` for the replay test.
async fn det_produce_transfer_of(
    sc: &mut ShardedCluster,
    validator: &SigningKey,
    tx: &Transaction,
    ts: u64,
) -> [u8; 32] {
    let txh = tx.compute_tx_hash();
    sc.shard_mut(SHARD0).broadcast_tx(tx.clone()).await;
    sc.shard_mut(SHARD1).broadcast_tx(tx.clone()).await;
    let bh = det_run_height(sc, validator, ts).await;
    let blk = block_of(sc, SHARD0, bh);
    assert_eq!(blk.cross_shard_out.len(), 1);
    assert!(blk.cross_shard_out[0].is_transfer());
    assert_eq!(
        sc.shard(SHARD0).nodes[0].produced_cross_shard_height(&txh),
        Some(1)
    );
    txh
}

/// The timeout rule is pure heights, never seconds.
#[tokio::test]
async fn timeout_rule_is_in_heights_not_seconds() {
    assert_eq!(CROSS_SHARD_TIMEOUT_HEIGHTS, 64);
    assert!(!bounce_eligible(1, 1));
    assert!(!bounce_eligible(1, 64));
    assert!(bounce_eligible(1, 65));
    assert!(bounce_eligible(1, 10_000));
    assert!(!bounce_eligible(100, 163));
    assert!(bounce_eligible(100, 164));
    // Saturating, never wraps on absurd heights.
    assert!(bounce_eligible(1, u64::MAX));
}

/// Kind encoding uses only pre-existing fields: direction + flags.
#[tokio::test]
async fn message_kinds_come_from_direction_and_flags_only() {
    let b = key(22);
    // FULL-PQ: same amount/gas/nonce/shards as the classical fixture;
    // sender is implicit Falcon-512 (seed 21), recipient unchanged.
    let tx = pq_tx(21, b.verifying_key().to_bytes(), 10, 1, 0, SHARD0, SHARD1);
    let transfer = stellereum::sharding::CrossShardMessage::new(
        SHARD0,
        SHARD1,
        tx.clone(),
        [0u8; 32],
        [1u8; 32],
        None,
    );
    assert!(transfer.is_transfer());
    assert!(!transfer.is_ack() && !transfer.is_bounce());
    let ack = stellereum::sharding::CrossShardMessage::new_ack(tx.clone(), [2u8; 32]);
    assert!(ack.is_ack());
    assert!(!ack.is_transfer() && !ack.is_bounce());
    assert!(
        ack.merkle_inclusion_proof.is_none(),
        "control records carry no proof"
    );
    let bounce = stellereum::sharding::CrossShardMessage::new_bounce(tx.clone(), [3u8; 32]);
    assert!(bounce.is_bounce());
    assert!(!bounce.is_transfer() && !bounce.is_ack());
    assert!(
        bounce.merkle_inclusion_proof.is_none(),
        "control records carry no proof"
    );
    // A transfer-shaped record with flags set is Unknown (fail closed).
    let mut weird = transfer.clone();
    weird.bounced = true;
    assert!(!weird.is_transfer() && !weird.is_ack() && !weird.is_bounce());
}

/// Happy path: the §9 2PC PREPARE -> PREPARE-ACK -> COMMIT flow completes the
/// transfer (one credit) -> no bounce is ever admitted afterwards (even past
/// the timeout), and a replayed terminal record cannot credit twice.
///
/// XSHARD-01: this replaces the legacy consume->ack dance. The legacy inbound
/// CREDIT is refused (it cannot prove the source-side debit in one step), so
/// value moves through the 2PC only; the M3 property under test — a completed
/// transfer never bounces and a replay never pays — is unchanged.
#[tokio::test]
async fn ack_flow_completes_transfer_and_blocks_any_later_bounce() {
    use stellereum::xshard2pc::XpcActivation;

    let validator = key(1);
    let sender_addr = pq_id(2);
    let recipient_addr = key(3).verifying_key().to_bytes();

    let mut sc = sharded_pair(&validator, &[(sender_addr, 1_000)], &[]).await;
    sc.with_xpc_activation(XpcActivation::FromHeight(0));
    let tx = pq_tx(2, recipient_addr, 100, 10, 0, SHARD0, SHARD1);
    let txh = tx.compute_tx_hash();
    sc.shard_mut(SHARD0).broadcast_tx(tx.clone()).await;

    // Source height 1: PREPARE + escrow (the debit).
    let bh = sc.run_height(SHARD0, 1).await;
    let blk = block_of(&sc, SHARD0, bh);
    assert!(
        blk.cross_shard_out.iter().any(|m| m.is_prepare()),
        "the source must publish a PREPARE, not a bare transfer"
    );
    assert_eq!(balance(&sc, SHARD0, &sender_addr).await, 1_000 - 100 - 10);

    // Target height 2: PREPARED (vote YES), no credit yet. Height 3 publishes
    // the PREPARE-ACK ("ack" in the M3 sense: the target's vote).
    sc.run_height(SHARD1, 2).await;
    assert_eq!(balance(&sc, SHARD1, &recipient_addr).await, 0);
    sc.run_height(SHARD1, 3).await;
    let vote = sc
        .transport
        .fetch_cross_shard_inbound(SHARD0)
        .await
        .into_iter()
        .find(|m| m.is_prepare_ack() && m.tx.compute_tx_hash() == txh)
        .expect("target must publish a PREPARE-ACK");
    assert!(vote.merkle_inclusion_proof.is_some());

    // Source height 4: consumes the vote -> COMMITTED. Height 5 publishes the
    // COMMIT.
    sc.run_height(SHARD0, 4).await;
    let bh = sc.run_height(SHARD0, 5).await;
    let blk = block_of(&sc, SHARD0, bh);
    let commit = blk
        .cross_shard_out
        .iter()
        .find(|m| m.is_commit() && m.tx.compute_tx_hash() == txh)
        .cloned()
        .expect("source must publish the COMMIT");
    assert!(sc.shard(SHARD0).nodes[0].is_transfer_completed(&txh));

    // Target height 6: consumes the COMMIT, credits exactly once.
    sc.run_height(SHARD1, 6).await;
    assert_eq!(balance(&sc, SHARD1, &recipient_addr).await, 100);

    // Consumed KV entries are pruned: nothing lingers for the source shard.
    assert!(sc
        .transport
        .fetch_cross_shard_inbound(SHARD0)
        .await
        .iter()
        .all(|m| m.tx.compute_tx_hash() != txh));

    // Past the timeout, no bounce may be constructed for a completed 2PC
    // transfer (its decision is two-sided; the unilateral bounce is gone).
    let mut saw_bounce = false;
    for h in 6..=(6 + CROSS_SHARD_TIMEOUT_HEIGHTS + 2) {
        let bh = sc.run_height(SHARD0, 100 + h).await;
        let blk = block_of(&sc, SHARD0, bh);
        saw_bounce |= blk.cross_shard_out.iter().any(|m| m.is_bounce());
    }
    assert!(!saw_bounce, "a completed transfer must never bounce");
    assert_eq!(balance(&sc, SHARD0, &sender_addr).await, 1_000 - 100 - 10);
    assert_eq!(balance(&sc, SHARD1, &recipient_addr).await, 100);

    // Replaying the terminal COMMIT is filtered at proposal (completion) and
    // refused at validation; the credit stays exactly once.
    sc.transport.broadcast_cross_shard(&commit).await.unwrap();
    let bh = sc.run_height(SHARD1, 999).await;
    let blk = block_of(&sc, SHARD1, bh);
    assert!(
        blk.cross_shard_out
            .iter()
            .all(|m| m.msg_id != commit.msg_id),
        "a completed record must not be re-included"
    );
    assert_eq!(balance(&sc, SHARD1, &recipient_addr).await, 100);
    let node = &sc.shard(SHARD1).nodes[0];
    let root = node.state_root().await;
    let mut forged = Block {
        shard_id: SHARD1,
        height: node.height(),
        prev_hash: node.finalized.last().map(|(_, h)| *h).unwrap_or([0u8; 32]),
        state_root: root,
        transactions: vec![],
        cross_shard_out: vec![commit.clone()],
        timestamp: 1_000,
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
        .expect_err("replayed terminal record must be refused");
    assert!(
        err.contains("replayed") || err.contains("completed"),
        "{err}"
    );
    let _ = CrossShardKey::of(&commit);
}

/// Failure path: the target never consumes; at produce_height + TIMEOUT the
/// source commits a bounce-back refunding `tx.amount` to `tx.from`, exactly
/// once — and a second carrier for the same transaction cannot refund again.
#[tokio::test]
async fn bounce_on_failure_refunds_sender_after_timeout_exactly_once() {
    let validator = key(11);
    let sender_addr = pq_id(12);
    let recipient_addr = key(13).verifying_key().to_bytes();

    let mut sc = sharded_pair(&validator, &[(sender_addr, 1_000)], &[]).await;
    let txh = produce_transfer(&mut sc, 12, recipient_addr, 1).await;
    assert_eq!(balance(&sc, SHARD0, &sender_addr).await, 1_000 - 100 - 10);

    // Target NEVER runs: heights 2..=64 carry no bounce (timeout not reached).
    for h in 2..(1 + CROSS_SHARD_TIMEOUT_HEIGHTS) {
        let bh = sc.run_height(SHARD0, 10 + h).await;
        let blk = block_of(&sc, SHARD0, bh);
        assert!(
            blk.cross_shard_out.iter().all(|m| !m.is_bounce()),
            "no bounce before height {}",
            1 + CROSS_SHARD_TIMEOUT_HEIGHTS
        );
    }
    assert_eq!(balance(&sc, SHARD0, &sender_addr).await, 1_000 - 100 - 10);

    // Height 65 == 1 + TIMEOUT: the bounce commits and refunds the amount
    // (gas stays with the source proposer — only `amount` is refunded).
    let bh = sc
        .run_height(SHARD0, 10 + 1 + CROSS_SHARD_TIMEOUT_HEIGHTS)
        .await;
    let blk = block_of(&sc, SHARD0, bh);
    let bounce = blk
        .cross_shard_out
        .iter()
        .find(|m| m.is_bounce())
        .expect("timeout bounce must commit")
        .clone();
    assert_eq!(bounce.tx.compute_tx_hash(), txh);
    assert!(sc.shard(SHARD0).nodes[0].is_transfer_completed(&txh));
    assert_eq!(balance(&sc, SHARD0, &sender_addr).await, 1_000 - 10);
    // The recipient never got anything anywhere (target never consumed).
    assert_eq!(balance(&sc, SHARD1, &recipient_addr).await, 0);

    // Replaying the consumed bounce is filtered; a rebuilt second carrier for
    // the same transaction is refused (completion guard, not just msg_id).
    sc.transport.broadcast_cross_shard(&bounce).await.unwrap();
    let rebuilt = stellereum::sharding::CrossShardMessage::new_bounce(bounce.tx.clone(), [9u8; 32]);
    sc.transport.broadcast_cross_shard(&rebuilt).await.unwrap();
    let bh2 = sc.run_height(SHARD0, 999).await;
    let blk2 = block_of(&sc, SHARD0, bh2);
    assert!(
        blk2.cross_shard_out.iter().all(|m| !m.is_bounce()),
        "no second refund for a completed transfer"
    );
    assert_eq!(balance(&sc, SHARD0, &sender_addr).await, 1_000 - 10);
    let node = &sc.shard(SHARD0).nodes[0];
    let root = node.state_root().await;
    let mut forged = Block {
        shard_id: SHARD0,
        height: node.height(),
        prev_hash: node.finalized.last().map(|(_, h)| *h).unwrap_or([0u8; 32]),
        state_root: root,
        transactions: vec![],
        cross_shard_out: vec![rebuilt],
        timestamp: 1_000,
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
        .expect_err("second bounce must be refused");
    assert!(
        err.contains("completed") || err.contains("replayed") || err.contains("linkage"),
        "{err}"
    );
}

/// A proof-carrying control record is refused: the engine would credit
/// `tx.to` on the source shard for it (a mint), so proposal and validation
/// must fail closed before it can be committed.
#[tokio::test]
async fn proof_carrying_ack_or_bounce_is_refused() {
    let validator = key(31);
    let sender_addr = pq_id(32);
    let recipient_addr = key(33).verifying_key().to_bytes();

    let mut sc = sharded_pair(&validator, &[(sender_addr, 1_000)], &[]).await;
    produce_transfer(&mut sc, 32, recipient_addr, 1).await;
    // Steal the genuine transfer's proof onto a bounce-shaped record.
    let src_bh = sc.shard(SHARD0).nodes[0]
        .finalized
        .last()
        .map(|(_, h)| *h)
        .unwrap();
    let transfer = block_of(&sc, SHARD0, src_bh).cross_shard_out[0].clone();
    assert!(transfer.merkle_inclusion_proof.is_some());
    let mut evil =
        stellereum::sharding::CrossShardMessage::new_bounce(transfer.tx.clone(), [7u8; 32]);
    evil.merkle_inclusion_proof = transfer.merkle_inclusion_proof.clone();
    assert!(evil.is_bounce(), "shape must still classify as bounce");

    // Proposal filters it (never committed)...
    sc.transport.broadcast_cross_shard(&evil).await.unwrap();
    let bh = sc.run_height(SHARD0, 50).await;
    let blk = block_of(&sc, SHARD0, bh);
    assert!(
        blk.cross_shard_out.iter().all(|m| m.msg_id != evil.msg_id),
        "a proof-carrying bounce must never be proposed"
    );
    // ...and validation refuses a forged block carrying it.
    let node = &sc.shard(SHARD0).nodes[0];
    let root = node.state_root().await;
    let mut forged = Block {
        shard_id: SHARD0,
        height: node.height(),
        prev_hash: node.finalized.last().map(|(_, h)| *h).unwrap_or([0u8; 32]),
        state_root: root,
        transactions: vec![],
        cross_shard_out: vec![evil],
        timestamp: 51,
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
    assert!(node.validate_proposal(&forged, root).is_err());
    // No mint happened on the source shard either way.
    assert_eq!(balance(&sc, SHARD0, &sender_addr).await, 1_000 - 100 - 10);
}

/// Two independently-run source shards, fed the same transfer and the same
/// timeout walk, derive the SAME state root (bounce determinism).
#[tokio::test]
async fn two_independent_sources_applying_the_same_bounce_derive_the_same_root() {
    // Falcon signing randomizes per signing (FIPS 206): two independent
    // signings are different transfers with different hashes. Feed the SAME
    // signed bytes to both clusters so the test compares bounce application
    // determinism, not re-signing randomness. Amount/nonce/shards identical.
    // Votes use TEST-ONLY `fvote_deterministic` (seed 0): same vote contents
    // reuse the same Falcon bytes, so QCs, block hashes, msg_ids and state
    // roots are byte-identical across the two runs. Production signing
    // (fresh randomness) is untouched; every other test keeps it.
    let recipient_addr = key(43).verifying_key().to_bytes();
    let shared_tx = pq_tx(42, recipient_addr, 100, 10, 0, SHARD0, SHARD1);
    let mut roots = Vec::new();
    for _ in 0..2 {
        let validator = key(41);
        let sender_addr = pq_id(42);
        let mut sc = sharded_pair(&validator, &[(sender_addr, 1_000)], &[]).await;
        det_produce_transfer_of(&mut sc, &validator, &shared_tx, 1).await;
        for h in 2..=(1 + CROSS_SHARD_TIMEOUT_HEIGHTS) {
            det_run_height(&mut sc, &validator, 10 + h).await;
        }
        let bounce_block = sc.shard(SHARD0).nodes[0]
            .blocks
            .values()
            .find(|b| b.cross_shard_out.iter().any(|m| m.is_bounce()))
            .expect("bounce must have committed");
        assert_eq!(balance(&sc, SHARD0, &sender_addr).await, 1_000 - 10);
        roots.push((
            sc.shard(SHARD0).nodes[0].state_root().await,
            bounce_block.compute_hash(),
        ));
    }
    assert_eq!(
        roots[0], roots[1],
        "independent shards must converge on root AND bounce block hash"
    );
}
