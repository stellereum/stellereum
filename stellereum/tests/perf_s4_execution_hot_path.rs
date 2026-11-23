//! S4 (perf) regression: STRUCTURAL invariants of the execution hot path.
//!
//! These are counting tests, not timing tests. Wall-clock assertions are flaky
//! in CI (and the crypto in this crate dominates any measurement), so each
//! optimization is pinned by the property that makes it an optimization:
//!
//!  * `payload_resolves_one_governed_policy_snapshot`: one payload execution
//!    resolves the governed PMM/staking policy from ONE governance read. The
//!    value used to be read three times (three lock acquisitions) inside the
//!    `VmContext` literal; re-inlining those reads makes this test fail.
//!  * `empty_mailbox_returns_without_the_accounts_write_lock`: a block with no
//!    queued actor message returns from a READ-only accounts check instead of
//!    taking the exclusive lock (which every concurrent state reader waits on).
//!    A queued message must still be delivered (the write path is unchanged).
//!
//! Both counters are process-global relaxed atomics that no execution path
//! reads; the two tests touch disjoint counters, so they may run in parallel.

use std::sync::atomic::{AtomicU8, Ordering};

use stellereum::post_quantum::{derive_pq_address, PqScheme, DEFAULT_SALT};
use stellereum::sharding::{Block, PqSignatureEnvelope, Transaction, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, ActorMessage, ActorSendBody, InMemoryStateEngine};
use stellereum::svm::{OpCode, GAS_BASIC_TRANSFER};

const TS: u64 = 1_760_000_000;
const BAL: u64 = 10_000_000;
const GAS: u64 = 1_000_000;

/// FULL-PQ sender fixture (implicit Falcon-512, registered globally): the
/// post-quantum envelope gate is satisfied without a surcharge, exactly like
/// the shared `apply_floor_tests` fixture.
static NEXT_PQ: AtomicU8 = AtomicU8::new(0x40);

fn pq_user() -> u8 {
    NEXT_PQ.fetch_add(1, Ordering::Relaxed)
}

fn pq_id(seed: &u8) -> [u8; 32] {
    derive_pq_address(
        PqScheme::Falcon512,
        &Transaction::sample_falcon512_pubkey(*seed),
        &DEFAULT_SALT,
    )
}

fn signed_tx(
    seed: &u8,
    to: [u8; 32],
    amount: u64,
    gas: u64,
    nonce: u64,
    payload: Vec<OpCode>,
) -> Transaction {
    let pk = Transaction::sample_falcon512_pubkey(*seed);
    let from = pq_id(seed);
    Transaction::global_implicit_registry()
        .register(from, PqScheme::Falcon512, &pk, &DEFAULT_SALT)
        .expect("PQ test key must register");
    let mut t = Transaction {
        from,
        to,
        amount,
        gas_limit: gas,
        nonce,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload,
        priority_fee_per_gas: 0,
    };
    let msg = t.signing_message();
    let sig = Transaction::create_falcon512_test_signature(&pk, &msg, *seed);
    t.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig).encode();
    t
}

/// A block body the mailbox pass can be pointed at. `apply_actor_messages_at`
/// reads only `block.timestamp`, so no proposer signature is required here.
fn block_at(timestamp: u64) -> Block {
    Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 1,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: Vec::new(),
        cross_shard_out: vec![],
        timestamp,
        proposer: [0u8; 32],
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32],
        cnvrf_v3: None,
        round: 0,
    }
}

/// INVARIANT (S4): one governed-policy snapshot per PAYLOAD execution.
///
/// `execute_payload` builds the VM context once per payload. The governed PMM
/// redemption buffer, the minimum validator bond and the default commission
/// are the SAME policy pair a payload's syscalls must all observe, so they are
/// resolved from a single governance read. Three separate reads (the previous
/// shape) would push the counter to 3; no payload execution at all (a plain
/// value transfer, which never enters the VM) leaves it flat.
#[tokio::test]
async fn payload_resolves_one_governed_policy_snapshot() {
    let engine = InMemoryStateEngine::new();
    let seed = pq_user();
    let from = pq_id(&seed);
    engine.update_account(AccountState::new(from, BAL)).await;

    let before = InMemoryStateEngine::perf_s4_gov_payload_snapshots();

    let payload_tx = signed_tx(
        &seed,
        [0xB0; 32],
        0,
        GAS,
        0,
        vec![OpCode::Transfer {
            recipient: [0xB1; 32],
            amount: 1,
        }],
    );
    engine
        .apply_transaction(&payload_tx, TS)
        .await
        .expect("a funded transfer payload must apply");

    let after_payload = InMemoryStateEngine::perf_s4_gov_payload_snapshots();
    assert_eq!(
        after_payload - before,
        1,
        "S4: a payload must resolve its governed policy from exactly ONE governance snapshot \
         (three reads = the regressed shape)"
    );

    // A plain value transfer runs no VM: zero policy snapshots.
    let plain_tx = signed_tx(&seed, [0xB2; 32], 1, GAS_BASIC_TRANSFER, 1, Vec::new());
    engine
        .apply_transaction(&plain_tx, TS)
        .await
        .expect("a funded plain transfer must apply");
    assert_eq!(
        InMemoryStateEngine::perf_s4_gov_payload_snapshots(),
        after_payload,
        "S4: an empty payload must not take the governed-policy snapshot at all"
    );
}

/// INVARIANT (S4): the mailbox pass takes the exclusive accounts lock ONLY
/// when there is something to deliver.
///
/// The pass runs once per block, and the overwhelming majority of blocks queue
/// no actor message. Taking `accounts.write()` just to discover that blocks
/// every concurrent reader (RPC balance/state reads, other apply snapshots).
/// The optimized shape proves the queue is empty under a READ guard.
#[tokio::test]
async fn empty_mailbox_returns_without_the_accounts_write_lock() {
    let engine = InMemoryStateEngine::new();
    let alice = [0xA1; 32];
    let bob = [0xA2; 32];
    engine.update_account(AccountState::new(alice, BAL)).await;
    engine.update_account(AccountState::new(bob, BAL)).await;

    let before = InMemoryStateEngine::perf_s4_actor_mailbox_read_fast_paths();
    let processed = engine.apply_actor_messages_at(&block_at(TS)).await;
    assert_eq!(processed, 0, "nothing is queued");
    assert_eq!(
        InMemoryStateEngine::perf_s4_actor_mailbox_read_fast_paths() - before,
        1,
        "S4: an empty mailbox must return from the read-only check"
    );

    // With a message queued the delivering path runs (no fast path), and the
    // message is really delivered - the fast path must never swallow work.
    let body = bincode::serialize(&ActorSendBody {
        program: Vec::new(),
        gas_budget: GAS,
    })
    .expect("actor body serializes");
    engine
        .send_message(ActorMessage::new(alice, bob, 7, body, true))
        .await
        .expect("a funded actor message is accepted");

    let before_delivery = InMemoryStateEngine::perf_s4_actor_mailbox_read_fast_paths();
    let processed = engine.apply_actor_messages_at(&block_at(TS)).await;
    assert!(
        processed >= 1,
        "the queued message must be processed, got {processed}"
    );
    assert_eq!(
        InMemoryStateEngine::perf_s4_actor_mailbox_read_fast_paths(),
        before_delivery,
        "S4: a non-empty mailbox takes the delivering path, never the read-only fast path"
    );
    let bob_acc = engine.get_account(&bob).await.expect("recipient exists");
    assert!(
        bob_acc.inbox.is_empty() || processed > 1,
        "the pass drained what it visited"
    );
}
