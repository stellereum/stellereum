//! Audit F1 (HIGH): cross-shard replay sets vs snapshot install.
//!
//! The snapshot install used to clear the consumed set and silently treat an
//! absent `cross_shard` blob as empty, while the produced/consumed/completed
//! sets were deliberately excluded from the state digest. A synced/restarted
//! node therefore re-opened every consumed inbound for a second credit, and
//! no root comparison could catch it.
//!
//! These tests pin the fail-closed fix:
//!   1. the replay sets (consumed keys, produced `(tx hash, height)` pairs,
//!      completed tx hashes) move the commitment digest - any divergence is a
//!      root mismatch, not a silent split; empty sets contribute zero bytes
//!      (single-shard chains root identically to before);
//!   2. a snapshot that omits the `cross_shard` blob is REFUSED when the
//!      target holds replay state, and accepted for a replay-empty target
//!      (the never-cross-sharded chain keeps fast-syncing);
//!   3. a snapshot whose replay set covers the target installs (fast-forward);
//!      one that does not - missing keys, or a conflicting produce height -
//!      is refused before touching the target;
//!   4. after a covering install, re-applying the same consumed receipt
//!      credits nothing (no double mint), with the root unmoved.

use ed25519_dalek::SigningKey;
use std::sync::Arc;
use stellereum::network::CrossShardTransport;
use stellereum::runtime::ShardedCluster;
use stellereum::sharding::{
    Block, CrossShardKey, CrossShardReplaySnapshot, ShardRegistry, Transaction,
    BASE_WORKCHAIN_SHARD_INITIAL, MASTERCHAIN_SHARD,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::sync::fast_sync_state;

const SHARD0: u32 = MASTERCHAIN_SHARD;
const SHARD1: u32 = BASE_WORKCHAIN_SHARD_INITIAL;
const TS: u64 = 1_760_000_000;

#[path = "support/xshard_escrow.rs"]
mod xshard_escrow;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// FULL-PQ sender address for a seed: implicit Falcon-512, registered
/// globally (no activation surcharge). Mirrors the `pq_tx` pattern in
/// `audit_state_sync_closeout_tests.rs`.
fn pq_id(seed: u8) -> [u8; 32] {
    use stellereum::post_quantum::{derive_pq_address, PqScheme, DEFAULT_SALT};
    let pk = Transaction::sample_falcon512_pubkey(seed);
    let from = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);
    Transaction::global_implicit_registry()
        .register(from, PqScheme::Falcon512, &pk, &DEFAULT_SALT)
        .expect("PQ test key must register");
    from
}

/// FULL-PQ cross-shard transfer fixture (implicit Falcon-512 envelope).
/// Same shards/amount/gas/nonce shape as the classical `Transaction::sign`
/// fixture it replaces: FULL-PQ refuses classical envelopes at admission
/// ("Pure PQ mode"), so the classical fixture can no longer be consumed and
/// the consumption record below would never exist.
fn pq_xshard_tx(seed: u8, to: [u8; 32], amount: u64, gas: u64, nonce: u64) -> Transaction {
    use stellereum::post_quantum::{PqScheme, PqSignatureEnvelope};
    let pk = Transaction::sample_falcon512_pubkey(seed);
    let from = pq_id(seed);
    let mut t = Transaction {
        from,
        to,
        amount,
        gas_limit: gas,
        nonce,
        source_shard: SHARD0,
        target_shard: SHARD1,
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

async fn funded(addr: [u8; 32], balance: u64) -> InMemoryStateEngine {
    let e = InMemoryStateEngine::new();
    e.update_account(AccountState::new(addr, balance)).await;
    e
}

fn fabric_key(a: u8, b: u8) -> CrossShardKey {
    CrossShardKey {
        source_shard: SHARD0,
        finalized_in_block: [a; 32],
        msg_id: [b; 32],
    }
}

async fn sharded_pair(
    validator: &SigningKey,
    shard0_funding: &[([u8; 32], u64)],
    shard1_funding: &[([u8; 32], u64)],
) -> ShardedCluster {
    // FULL-PQ: funded PQ senders must live as 49-byte pinned leaves, else the
    // source proof (49-byte, via registry metadata) mismatches the funded
    // 16-byte leaf and target verification fails (mirrors
    // `cross_shard_e2e_pq_tests::setup_two_shard_cluster`).
    let s0 = Arc::new(InMemoryStateEngine::new());
    for (addr, bal) in shard0_funding {
        s0.update_account(AccountState::new(*addr, *bal)).await;
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

/// Drive a single transfer SHARD0 -> SHARD1 to full consumption. Returns the
/// consumed message (the record a replay would re-present) for later replay.
///
/// XSHARD-01: the record is ESCROW-BACKED (the source debited the sender in an
/// applied escrow block, and the message proves that escrow against an
/// anchored source header). An affordability-only record is refused by the
/// gate, so it can no longer be used to seed replay tests.
async fn consume_one(
    sc: &mut ShardedCluster,
    sender_seed: u8,
    recipient_addr: [u8; 32],
    amount: u64,
) -> stellereum::sharding::CrossShardMessage {
    let tx = pq_xshard_tx(sender_seed, recipient_addr, amount, 10, 0);
    let registry = sc.shard(SHARD1).nodes[0]
        .finalized_headers
        .clone()
        .expect("the fixture wires the finalized-header registry");
    let msg = xshard_escrow::escrow_backed_message(&tx, &registry).await;

    // Apply the committed record on the target engine (the credit + the
    // atomic replay claim).
    let target = sc.shard(SHARD1).nodes[0].state.clone();
    let record = xshard_escrow::carrier(SHARD1, 1, vec![msg.clone()]);
    assert_eq!(
        target.apply_cross_shard_consumptions(&record).await,
        1,
        "the escrow-backed record must credit once"
    );

    // Mirror the RUNTIME half of the replay state exactly as the live apply
    // path would: the same key lands in the runtime set alongside the engine's
    // (the two halves are snapshotted together).
    let mirrored = stellereum::sharding::CrossShardReplaySnapshot {
        runtime_consumed: vec![CrossShardKey::of(&msg)],
        ..Default::default()
    };
    sc.shard_mut(SHARD1).nodes[0].restore_cross_shard_sets(&mirrored);
    msg
}

// ===========================================================================
// 1. The replay sets move the commitment digest.
// ===========================================================================

#[tokio::test]
async fn replay_sets_move_the_commitment_digest() {
    let addr = [0xF1; 32];
    let base = funded(addr, 1_000_000).await.get_state_root().await;

    // Consumed alone moves the root.
    let e1 = funded(addr, 1_000_000).await;
    e1.restore_cross_shard_consumed(&[fabric_key(0xA1, 0xB1)])
        .await;
    let d_consumed = e1.get_state_root().await;
    assert_ne!(d_consumed, base, "a consumed key must move the root");

    // Produced alone moves the root, to a different value.
    let e2 = funded(addr, 1_000_000).await;
    let tx = Transaction::sign(&key(90), [0x99; 32], 50, 10, 0, SHARD0, SHARD1);
    let tx_hash = tx.compute_tx_hash();
    e2.restore_cross_shard_replay(&CrossShardReplaySnapshot {
        engine_consumed: vec![],
        runtime_consumed: vec![],
        produced: vec![(tx_hash, tx, 7)],
        completed: vec![],
        xpc: vec![],
    })
    .await;
    let d_produced = e2.get_state_root().await;
    assert_ne!(d_produced, base, "a produced entry must move the root");
    assert_ne!(
        d_produced, d_consumed,
        "different replay states must not alias"
    );

    // Produced heights are committed, not just hashes: same tx hash at two
    // heights must root differently (the height decides bounce linkage).
    let e2b = funded(addr, 1_000_000).await;
    let tx2 = Transaction::sign(&key(90), [0x99; 32], 50, 10, 0, SHARD0, SHARD1);
    assert_eq!(tx2.compute_tx_hash(), tx_hash);
    e2b.restore_cross_shard_replay(&CrossShardReplaySnapshot {
        engine_consumed: vec![],
        runtime_consumed: vec![],
        produced: vec![(tx_hash, tx2, 9)],
        completed: vec![],
        xpc: vec![],
    })
    .await;
    assert_ne!(
        e2b.get_state_root().await,
        d_produced,
        "produce height decides linkage, so it must be committed"
    );

    // Completed alone moves the root.
    let e3 = funded(addr, 1_000_000).await;
    e3.restore_cross_shard_replay(&CrossShardReplaySnapshot {
        engine_consumed: vec![],
        runtime_consumed: vec![],
        produced: vec![],
        completed: vec![[0xC3; 32]],
        xpc: vec![],
    })
    .await;
    let d_completed = e3.get_state_root().await;
    assert_ne!(d_completed, base, "a completed entry must move the root");

    // Empty sets contribute zero bytes: the conditional contract that keeps
    // single-shard chains (and every genesis KAT) byte-identical.
    let e4 = funded(addr, 1_000_000).await;
    e4.restore_cross_shard_replay(&CrossShardReplaySnapshot::default())
        .await;
    assert_eq!(
        e4.get_state_root().await,
        base,
        "restoring empty replay sets must not move the root"
    );

    // Order independence: insertion order must not fork the digest.
    let a = funded(addr, 1_000_000).await;
    a.restore_cross_shard_consumed(&[fabric_key(1, 2)]).await;
    a.restore_cross_shard_consumed(&[fabric_key(3, 4)]).await;
    let b = funded(addr, 1_000_000).await;
    b.restore_cross_shard_consumed(&[fabric_key(3, 4)]).await;
    b.restore_cross_shard_consumed(&[fabric_key(1, 2)]).await;
    assert_eq!(
        a.get_state_root().await,
        b.get_state_root().await,
        "identical replay sets must digest identically regardless of order"
    );
}

// ===========================================================================
// 2. Missing blob: refused when replay state exists, accepted when empty.
// ===========================================================================

#[tokio::test]
async fn snapshot_install_with_missing_blob_is_refused() {
    let user = [0x55u8; 32];
    let source = funded(user, 777_000).await;
    let root = source.get_state_root().await;
    let snap = source.create_snapshot().await;

    // Target holds replay state the snapshot cannot account for.
    let target = funded(user, 777_000).await;
    target
        .restore_cross_shard_consumed(&[fabric_key(0xD1, 0xD2)])
        .await;
    let target_root_before = target.get_state_root().await;
    assert_ne!(
        target_root_before, root,
        "precondition: replay state moves the target root"
    );

    let res = fast_sync_state(
        &target,
        root,
        || async { Some(snap.clone()) },
        |_| async { None },
    )
    .await;
    let err = res.expect_err("a snapshot without the cross_shard blob must be refused");
    assert!(
        err.contains("cross_shard") || err.contains("cross-shard"),
        "refusal must name the missing replay domain: {err}"
    );
    // Fail-closed means untouched: accounts AND the local replay set survive.
    assert_eq!(
        target.get_account(&user).await.unwrap().balance,
        777_000,
        "refused install must not touch accounts"
    );
    assert_eq!(
        target.cross_shard_consumed_len().await,
        1,
        "refused install must not drop local replay state"
    );
    assert_eq!(
        target.get_state_root().await,
        target_root_before,
        "refused install must not move the target root"
    );

    // Control: a replay-empty target still fast-syncs without the blob (the
    // never-cross-sharded chain is unaffected by the gate).
    let clean = funded(user, 777_000).await;
    fast_sync_state(
        &clean,
        root,
        || async { Some(snap.clone()) },
        |_| async { None },
    )
    .await
    .expect("replay-empty target must sync without the blob");
    assert_eq!(clean.get_state_root().await, root);
}

// ===========================================================================
// 3. Covering set installs; short or conflicting sets are refused.
// ===========================================================================

struct CoveringFixture {
    root: [u8; 32],
    snap_bytes: Vec<u8>,
    blob: Vec<u8>,
    consumed_key: CrossShardKey,
    tx_hash: [u8; 32],
    tx: Transaction,
    produce_height: u64,
    completed_hash: [u8; 32],
}

async fn covering_fixture() -> CoveringFixture {
    let user = [0x66u8; 32];
    let source = funded(user, 1_000_000).await;
    let consumed_key = fabric_key(0xE1, 0xE2);
    let tx = Transaction::sign(&key(91), [0x98; 32], 50, 10, 0, SHARD0, SHARD1);
    let tx_hash = tx.compute_tx_hash();
    let replay = CrossShardReplaySnapshot {
        engine_consumed: vec![consumed_key],
        runtime_consumed: vec![consumed_key],
        produced: vec![(tx_hash, tx.clone(), 7)],
        completed: vec![[0xC7; 32]],
        xpc: vec![],
    };
    source.restore_cross_shard_replay(&replay).await;
    let root = source.get_state_root().await;
    let snap_bytes = source.create_snapshot().await;
    let blob = bincode::serialize(&replay).expect("replay blob encodes");
    CoveringFixture {
        root,
        snap_bytes,
        blob,
        consumed_key,
        tx_hash,
        tx,
        produce_height: 7,
        completed_hash: [0xC7; 32],
    }
}

async fn sync_with_blob(
    target: &InMemoryStateEngine,
    fx: &CoveringFixture,
    blob_override: Option<Vec<u8>>,
) -> Result<(), String> {
    let blob = blob_override.unwrap_or_else(|| fx.blob.clone());
    fast_sync_state(
        target,
        fx.root,
        || async { Some(fx.snap_bytes.clone()) },
        |kind: &'static str| {
            let blob = blob.clone();
            async move {
                if kind == "cross_shard" {
                    Some(blob)
                } else {
                    None
                }
            }
        },
    )
    .await
}

#[tokio::test]
async fn snapshot_install_with_covering_set_is_accepted() {
    let fx = covering_fixture().await;

    // Empty target: full fast-forward.
    let target = funded([0x66u8; 32], 1_000_000).await;
    sync_with_blob(&target, &fx, None)
        .await
        .expect("covering set must install");
    assert_eq!(target.get_state_root().await, fx.root);
    assert!(target.is_cross_shard_consumed(&fx.consumed_key).await);
    assert_eq!(target.cross_shard_consumed_len().await, 1);
    assert_eq!(target.cross_shard_produced_len().await, 1);
    assert_eq!(target.cross_shard_completed_len().await, 1);
    assert!(target.is_cross_shard_completed(&fx.completed_hash).await);

    // Subset target: local state is older but covered - fast-forward accepts.
    let subset = funded([0x66u8; 32], 1_000_000).await;
    subset
        .restore_cross_shard_consumed(&[fx.consumed_key])
        .await;
    sync_with_blob(&subset, &fx, None)
        .await
        .expect("covered subset must fast-forward");
    assert_eq!(subset.get_state_root().await, fx.root);
    assert_eq!(subset.cross_shard_produced_len().await, 1);
}

#[tokio::test]
async fn snapshot_install_with_short_set_is_refused() {
    let fx = covering_fixture().await;

    // Target holds a consumed key the snapshot lacks: refuse, untouched.
    let target = funded([0x66u8; 32], 1_000_000).await;
    let extra = fabric_key(0xF0, 0xF1);
    target.restore_cross_shard_consumed(&[extra]).await;
    let before = target.get_state_root().await;
    let err = sync_with_blob(&target, &fx, None)
        .await
        .expect_err("short incoming set must be refused");
    assert!(
        err.contains("cross_shard"),
        "refusal must name the domain: {err}"
    );
    assert_eq!(target.cross_shard_consumed_len().await, 1);
    assert!(target.is_cross_shard_consumed(&extra).await);
    assert_eq!(target.get_state_root().await, before);

    // Same tx hash but a conflicting produce height: the two sides applied
    // different chains - refuse, even though the key sets match.
    let conflicted = funded([0x66u8; 32], 1_000_000).await;
    conflicted
        .restore_cross_shard_replay(&CrossShardReplaySnapshot {
            engine_consumed: vec![fx.consumed_key],
            runtime_consumed: vec![fx.consumed_key],
            produced: vec![(fx.tx_hash, fx.tx.clone(), fx.produce_height + 100)],
            completed: vec![fx.completed_hash],
            xpc: vec![],
        })
        .await;
    let err = sync_with_blob(&conflicted, &fx, None)
        .await
        .expect_err("conflicting produce height must be refused");
    assert!(
        err.contains("cross_shard"),
        "refusal must name the domain: {err}"
    );

    // Corrupt blob: fail closed, never installed as empty.
    let corrupt_target = funded([0x66u8; 32], 1_000_000).await;
    let err = sync_with_blob(&corrupt_target, &fx, Some(vec![0xDE, 0xAD, 0xBE, 0xEF]))
        .await
        .expect_err("corrupt replay blob must be refused");
    assert!(
        err.contains("cross-shard"),
        "refusal must name the domain: {err}"
    );
    assert_eq!(corrupt_target.cross_shard_consumed_len().await, 0);
}

// ===========================================================================
// 4. After a covering install, the same receipt cannot credit twice.
// ===========================================================================

#[tokio::test]
async fn double_apply_refused_after_snapshot_install() {
    let validator = key(1);
    const SENDER_SEED: u8 = 2;
    let recipient_addr = key(3).verifying_key().to_bytes();
    let sender_addr = pq_id(SENDER_SEED);

    let mut sc = sharded_pair(&validator, &[(sender_addr, 1_000_000)], &[]).await;
    let consumed_msg = consume_one(&mut sc, SENDER_SEED, recipient_addr, 100).await;
    let consumed_key = CrossShardKey::of(&consumed_msg);

    // Publish-path artifacts: the accounts snapshot plus the runtime's replay
    // blob (the real wire format, produced/completed included).
    let src_engine = &sc.shard(SHARD1).nodes[0].state;
    let source_root = src_engine.get_state_root().await;
    let snap_bytes = src_engine.create_snapshot().await;
    let replay = sc.shard(SHARD1).nodes[0]
        .cross_shard_replay_snapshot()
        .await;
    assert!(replay.engine_consumed.contains(&consumed_key));
    let blob = bincode::serialize(&replay).expect("replay blob encodes");

    // Fresh node installs via snapshot-sync.
    let fresh = InMemoryStateEngine::new();
    fresh.enable_cross_shard();
    fresh.with_finalized_headers(
        sc.shard(SHARD1).nodes[0]
            .finalized_headers
            .clone()
            .expect("the fixture wires the finalized-header registry"),
    );
    fast_sync_state(
        &fresh,
        source_root,
        || async { Some(snap_bytes.clone()) },
        |kind: &'static str| {
            let blob = blob.clone();
            async move {
                if kind == "cross_shard" {
                    Some(blob)
                } else {
                    None
                }
            }
        },
    )
    .await
    .expect("covering install must succeed");
    assert_eq!(fresh.get_state_root().await, source_root);
    assert!(fresh.is_cross_shard_consumed(&consumed_key).await);
    assert_eq!(
        fresh.cross_shard_consumed_len().await,
        src_engine.cross_shard_consumed_len().await
    );
    // The installed replay state is exactly the source's: balances agree.
    let credited_balance = fresh
        .get_account(&recipient_addr)
        .await
        .map(|a| a.balance)
        .unwrap_or(0);
    assert_eq!(credited_balance, 100);

    // Re-applying the SAME (proof-valid) receipt credits nothing: the gate
    // fires on the installed set, not on a missing proof.
    let carrier = Block {
        shard_id: SHARD1,
        height: 1,
        prev_hash: [0u8; 32],
        state_root: fresh.get_state_root().await,
        transactions: vec![],
        cross_shard_out: vec![consumed_msg],
        timestamp: TS + 500,
        proposer: validator.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        cnvrf_v3: None,
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    let credited = fresh.apply_cross_shard_consumptions(&carrier).await;
    assert_eq!(credited, 0, "replayed receipt must credit nothing");
    assert_eq!(
        fresh.cross_shard_consumed_len().await,
        src_engine.cross_shard_consumed_len().await,
        "replay must not insert a second key"
    );
    assert_eq!(
        fresh
            .get_account(&recipient_addr)
            .await
            .map(|a| a.balance)
            .unwrap_or(0),
        100,
        "no double mint"
    );
    assert_eq!(
        fresh.get_state_root().await,
        source_root,
        "replay must not move the root"
    );
}

// ===========================================================================
// 5. Reorg restore clears the §9 2PC records; the sync twin keeps them.
// ===========================================================================

/// REGRESSION (was F11 FINDING, low, latent): `restore_snapshot_chunked` cleared
/// consumed/produced/completed but NOT `cross_shard_xpc`, while the monolithic
/// `restore_snapshot` cleared all four. A chunked reorg therefore kept stale 2PC
/// records whose state-trie leaves the restore had rebuilt away — a latent
/// double-mint (a peer could still complete a transfer the reorg removed).
///
/// FIX: the chunked REORG restore clears `cross_shard_xpc` (and bumps its
/// domain) exactly like the monolithic twin, so both paths reproduce the
/// checkpoint root. The snapshot-sync twin stays deliberately non-clearing: its
/// caller installs the replay blob behind `cross_shard_replay_covers`.
#[tokio::test]
async fn chunked_reorg_restore_clears_xpc_while_the_sync_twin_preserves_it() {
    let checkpoint = funded([0x84u8; 32], 777_000).await;
    let chunks = checkpoint.create_snapshot_chunked(Some(64)).await;
    let rec = stellereum::xshard2pc::XpcRecord::prepared(
        Transaction::sign(&key(92), [0x87u8; 32], 7, 10, 0, SHARD0, SHARD1),
        SHARD0,
        SHARD1,
        3,
    );
    assert!(rec.is_consistent(), "precondition: well-formed record");

    // Reorg path: cleared, root equals the checkpoint.
    let reorg = InMemoryStateEngine::new();
    reorg.restore_xpc_records(std::slice::from_ref(&rec)).await;
    assert_eq!(reorg.xpc_len().await, 1);
    reorg.restore_snapshot_chunked(&chunks).await.unwrap();
    assert_eq!(
        reorg.xpc_len().await,
        0,
        "the chunked reorg restore must clear cross_shard_xpc"
    );
    assert!(reorg.xpc_record(&rec.tx_hash).await.is_none());
    assert_eq!(
        reorg.get_state_root().await,
        checkpoint.get_state_root().await,
        "a chunked reorg restore must reproduce the checkpoint root"
    );

    // Snapshot-sync path: preserved for the coverage-gated replay install.
    let sync = InMemoryStateEngine::new();
    sync.restore_xpc_records(std::slice::from_ref(&rec)).await;
    sync.restore_snapshot_chunked_preserve_replay_sets(&chunks)
        .await
        .unwrap();
    assert_eq!(
        sync.xpc_len().await,
        1,
        "the sync twin must not silently drop local 2PC state"
    );
    assert!(sync.xpc_record(&rec.tx_hash).await.is_some());
}
