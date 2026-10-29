//! Block-packing at scale: 10k-transaction blocks build and apply
//! deterministically after the packing/parallel-apply optimization.
//!
//! What this pins (invariant -> test):
//!
//! | Invariant | Test |
//! |---|---|
//! | A full 10k mempool proposes 10k contiguous-nonce txs that all apply (propose/apply parity at scale) | `scale_ten_k_propose_selects_all_contiguous_and_applies_clean` |
//! | Same block bytes applied on two fresh engines give the same root (deterministic build+certify+apply) | `scale_ten_k_same_root_twice_through_encode` |
//! | Selection still respects nonce contiguity and session scope/registry parity at scale (gaps skipped, revoked grants excluded by propose AND refused by apply) | `scale_selection_skips_nonce_gaps_and_revoked_session_grants` |
//! | No state divergence between parallel and sequential apply at 10k (grouped senders, shared recipient) | `scale_parallel_matches_sequential_at_ten_k` |
//! | Same, on the trie-dedup no-op path (every account touched exactly once) | `scale_parallel_matches_sequential_distinct_accounts` |
//! | The parallel MEV unseal gate (>=512 txs) keeps exactly the sequential set in the same order | `scale_mev_parallel_gate_matches_sequential_filter` |
//! | Trie root is independent of insert order (the premise the apply-time write dedup relies on) | `scale_trie_insert_order_does_not_move_root` |
//! | `Mempool::senders` is exactly the sender set of `all()` (the propose path reads this, not cloned txs) | `scale_senders_matches_all_derivation` |
//!
//! Determinism note: keys are derived from fixed seeds (no wall clock, no
//! OsRng), fees from a fixed scatter, timestamps are constants — every test
//! below reproduces byte-identically on every run.
//!
//! Scope note: session grants that are expired or out of scope can never reach
//! the propose filter — mempool admission rejects them by design (node-local
//! policy against the admission clock). The poolable session-exclusion path is
//! the on-chain registry (revocation after admission), which is what test 3
//! exercises at scale.

use ed25519_dalek::SigningKey;
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use stellereum::consensus::ValidatorSet;
use stellereum::mempool::Mempool;
use stellereum::runtime::ValidatorRuntime;
use stellereum::sharding::{Block, Transaction};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::OpCode;
use stellereum::zkml::{SessionKeyAuthorization, SCOPE_TRANSFER};

/// Ten thousand transactions: 100 senders x 100 nonces (the MAX_BLOCK_TXS cap).
const N_SENDERS: usize = 100;
const PER_SENDER: u64 = 100;
const N_TXS: usize = 10_000;
/// Far-future block timestamp (deterministic; admission wall-clock stays below
/// every grant expiry used here).
const TS: u64 = 9_000_000_007;
/// Funding that covers any amount + gas_limit used here.
const BAL: u64 = 1_000_000_000_000;
/// Chain id every grant in this file carries (== the engine default).
const CHAIN_ID: u64 = 5757;

fn det_key(i: u64) -> SigningKey {
    let mut seed = [0xA5u8; 32];
    seed[..8].copy_from_slice(&i.to_le_bytes());
    SigningKey::from_bytes(&seed)
}

fn id_of(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

/// Deterministic fee scatter in 1..=1000 (total gas ~5M, well under the 30M
/// block cap), forcing fee order far from nonce order so multi-pass selection
/// does real work.
fn fee(i: u64) -> u64 {
    (i.wrapping_mul(7919) % 1000) + 1
}

fn legacy_tx(sk: &SigningKey, to: [u8; 32], nonce: u64, seq: u64) -> Transaction {
    Transaction::sign(sk, to, 1, fee(seq), nonce, 1, 1)
}

fn grant(
    master: &SigningKey,
    session: &SigningKey,
    valid_until: u64,
    max_gas_spend: u64,
) -> SessionKeyAuthorization {
    SessionKeyAuthorization::sign_delegation(
        master,
        session.verifying_key().to_bytes(),
        valid_until,
        max_gas_spend,
        SCOPE_TRANSFER,
        u64::MAX,
        CHAIN_ID,
    )
}

/// One single-validator runtime at height 1 with `funding` pre-funded, sharing
/// `pool`.
async fn runtime_with_pool(
    pool: Arc<tokio::sync::RwLock<Mempool>>,
    funding: &[([u8; 32], u64)],
) -> ValidatorRuntime {
    // Far outside every sender/session index space used below.
    let val_sk = det_key(42_000_000);
    let val = id_of(&val_sk);
    let engine = Arc::new(InMemoryStateEngine::new());
    engine.update_account(AccountState::new(val, BAL)).await;
    for (addr, bal) in funding {
        engine.update_account(AccountState::new(*addr, *bal)).await;
    }
    let vs = ValidatorSet::from_list(vec![(val, 1)]);
    ValidatorRuntime::new(val_sk, vs, engine, 1).with_mempool(pool)
}

// `det_key` seeds below must not collide with sender index spaces.
const RECIPIENT: [u8; 32] = [9u8; 32];

/// Fill a pool with the canonical 10k contiguous workload; returns the senders.
fn fill_canonical(pool: &mut Mempool) -> Vec<SigningKey> {
    let keys: Vec<SigningKey> = (0..N_SENDERS as u64).map(det_key).collect();
    let mut seq = 0u64;
    for sk in &keys {
        for nonce in 0..PER_SENDER {
            let tx = legacy_tx(sk, RECIPIENT, nonce, seq);
            seq += 1;
            pool.add_checked(tx, BAL)
                .expect("funded admission must succeed");
        }
    }
    assert_eq!(pool.len(), N_TXS);
    keys
}

// ============================================================================
// 1. Full 10k propose: contiguous per sender, everything applies (parity).
// ============================================================================

#[tokio::test]
async fn scale_ten_k_propose_selects_all_contiguous_and_applies_clean() {
    let mut pool = Mempool::new(20_000, 10_000);
    let keys = fill_canonical(&mut pool);
    let funding: Vec<([u8; 32], u64)> = keys.iter().map(|k| (id_of(k), BAL)).collect();
    let pool = Arc::new(tokio::sync::RwLock::new(pool));
    let mut rt = runtime_with_pool(pool, &funding).await;

    let block = rt.propose(TS).await.expect("full pool must propose");
    assert_eq!(block.transactions.len(), N_TXS, "all 10k must be selected");

    // Contiguous nonce runs per sender, from the account nonce (0).
    let mut by_sender: HashMap<[u8; 32], Vec<u64>> = HashMap::new();
    for t in &block.transactions {
        by_sender.entry(t.from).or_default().push(t.nonce);
    }
    assert_eq!(by_sender.len(), N_SENDERS);
    for nonces in by_sender.values() {
        let mut sorted = nonces.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..PER_SENDER).collect::<Vec<_>>());
    }

    // Propose/apply parity: everything proposed must apply, nothing fail.
    let (applied, failed, _, _, _) = rt
        .state
        .apply_block_parallel_fees(&block.transactions, TS)
        .await;
    assert_eq!(applied, N_TXS);
    assert_eq!(failed, 0);
}

// ============================================================================
// 2. Same block bytes on two fresh engines: same root (determinism at scale).
// ============================================================================

#[tokio::test]
async fn scale_ten_k_same_root_twice_through_encode() {
    let mut pool = Mempool::new(20_000, 10_000);
    let keys = fill_canonical(&mut pool);
    let funding: Vec<([u8; 32], u64)> = keys.iter().map(|k| (id_of(k), BAL)).collect();
    let pool = Arc::new(tokio::sync::RwLock::new(pool));
    let mut rt = runtime_with_pool(pool, &funding).await;

    let block = rt.propose(TS).await.expect("full pool must propose");
    // Encode stability at 1.76MB: the certified bytes round-trip exactly.
    let bytes = bincode::serialize(&block).expect("block encodes");
    let back: Block = bincode::deserialize(&bytes).expect("block decodes");
    assert_eq!(back.compute_hash(), block.compute_hash());

    // Two identically-funded engines apply the same bytes: same outcome.
    let mut roots = Vec::new();
    for _ in 0..2 {
        let e = Arc::new(InMemoryStateEngine::new());
        e.update_account(AccountState::new(block.proposer, BAL))
            .await;
        for (addr, bal) in &funding {
            e.update_account(AccountState::new(*addr, *bal)).await;
        }
        e.update_account(AccountState::new(RECIPIENT, 0)).await;
        let outcome = e.apply_block_transition(&back, 0).await;
        assert_eq!(outcome.applied, N_TXS);
        assert_eq!(outcome.failed, 0);
        assert_eq!(outcome.status.len(), N_TXS);
        assert!(outcome.status.iter().all(|s| *s));
        roots.push(e.get_state_root().await);
    }
    assert_eq!(
        roots[0], roots[1],
        "same block must certify the same root twice"
    );
}

// ============================================================================
// 3. Nonce gaps skipped, revoked session grants excluded by propose AND
//    refused by apply (scope/registry parity at scale).
// ============================================================================

#[tokio::test]
async fn scale_selection_skips_nonce_gaps_and_revoked_session_grants() {
    const LEGACY_SENDERS: usize = 90;
    const SESSION_MASTERS: usize = 10;
    const SESSION_TXS: u64 = 10;
    // Every 9th legacy sender is gapped at nonce 50 (0..50 pooled contiguously
    // plus 51..100 pooled behind the gap).
    const GAP_AT: u64 = 50;

    let legacy: Vec<SigningKey> = (0..LEGACY_SENDERS as u64).map(det_key).collect();
    let masters: Vec<SigningKey> = (0..SESSION_MASTERS as u64)
        .map(|i| det_key(1_000_000 + i))
        .collect();
    let sessions: Vec<SigningKey> = (0..SESSION_MASTERS as u64)
        .map(|i| det_key(2_000_000 + i))
        .collect();
    // Master 9 is revoked on chain before propose; its pooled session
    // transactions start at nonce 2 (setup consumed 0 and 1).
    const REVOKED: usize = 9;

    let mut funding: Vec<([u8; 32], u64)> = legacy.iter().map(|k| (id_of(k), BAL)).collect();
    for m in &masters {
        funding.push((id_of(m), BAL));
    }
    let pool = Arc::new(tokio::sync::RwLock::new(Mempool::new(20_000, 10_000)));
    let mut rt = runtime_with_pool(pool.clone(), &funding).await;

    // Setup on the RUNTIME engine: master 9 applies one session tx (nonce 0,
    // lazily registers the grant record), then a master-signed revoke
    // (nonce 1) commits `revoked = true`.
    let m9 = &masters[REVOKED];
    let s9 = &sessions[REVOKED];
    let grant9 = grant(m9, s9, u64::MAX, 1_000_000);
    let first =
        Transaction::sign_with_session(s9, grant9.clone(), [7u8; 32], 1, 1_000, 0, 1, 1, vec![]);
    let (a, f, _, _, _) = rt.state.apply_block_parallel_fees(&[first], TS).await;
    assert_eq!((a, f), (1, 0), "setup session tx must register the grant");
    let revoke = Transaction::sign_with_payload(
        m9,
        [7u8; 32],
        1,
        100_000,
        1,
        1,
        1,
        vec![OpCode::SysCallRevokeSession {
            session_pubkey: id_of(s9),
        }],
    );
    let (a, f, _, _, _) = rt.state.apply_block_parallel_fees(&[revoke], TS).await;
    assert_eq!((a, f), (1, 0), "setup revoke must land");

    // Fill the pool: legacy (with gaps) + session txs.
    {
        let mut pool = pool.write().await;
        let mut seq = 0u64;
        for (li, sk) in legacy.iter().enumerate() {
            for nonce in 0..PER_SENDER {
                if li % 9 == 8 && nonce == GAP_AT {
                    continue; // the gap: pooled successors must wait
                }
                let tx = legacy_tx(sk, RECIPIENT, nonce, seq);
                seq += 1;
                pool.add_checked(tx, BAL).expect("funded admission");
            }
        }
        for (mi, (m, s)) in masters.iter().zip(sessions.iter()).enumerate() {
            let g = grant(m, s, u64::MAX, 1_000_000);
            let base = if mi == REVOKED { 2 } else { 0 };
            for j in 0..SESSION_TXS {
                let tx = Transaction::sign_with_session(
                    s,
                    g.clone(),
                    [7u8; 32],
                    1,
                    1_000,
                    base + j,
                    1,
                    1,
                    vec![],
                );
                pool.add_checked(tx, BAL)
                    .expect("statelessly valid grant admits");
            }
        }
    }

    let block = rt
        .propose(TS)
        .await
        .expect("gapped pool must still propose");

    // Gapped senders contribute exactly 0..50; ungapped 0..100.
    let mut by_sender: HashMap<[u8; 32], Vec<u64>> = HashMap::new();
    for t in &block.transactions {
        by_sender.entry(t.from).or_default().push(t.nonce);
    }
    for (li, sk) in legacy.iter().enumerate() {
        let mut nonces = by_sender.remove(&id_of(sk)).unwrap_or_default();
        nonces.sort_unstable();
        if li % 9 == 8 {
            assert_eq!(
                nonces,
                (0..GAP_AT).collect::<Vec<_>>(),
                "gap successors wait"
            );
        } else {
            assert_eq!(nonces, (0..PER_SENDER).collect::<Vec<_>>());
        }
    }
    // Healthy session masters contribute all 10; the revoked master none.
    for (mi, m) in masters.iter().enumerate() {
        let mut nonces = by_sender.remove(&id_of(m)).unwrap_or_default();
        nonces.sort_unstable();
        if mi == REVOKED {
            assert!(
                nonces.is_empty(),
                "revoked grant must be filtered at propose"
            );
        } else {
            assert_eq!(nonces, (0..SESSION_TXS).collect::<Vec<_>>());
        }
    }
    assert!(by_sender.is_empty(), "no strangers selected: {by_sender:?}");
    // 80x100 ungapped legacy + 10x50 gap prefixes + 9x10 healthy session = 8590.
    assert_eq!(block.transactions.len(), 80 * 100 + 10 * 50 + 9 * 10);

    // Propose/apply parity at scale: everything proposed applies.
    let (applied, failed, _, _, _) = rt
        .state
        .apply_block_parallel_fees(&block.transactions, TS)
        .await;
    assert_eq!(applied, block.transactions.len());
    assert_eq!(failed, 0);

    // And the apply path refuses the revoked grant directly, like propose did.
    let bad = Transaction::sign_with_session(s9, grant9, [7u8; 32], 1, 1_000, 2, 1, 1, vec![]);
    let (_, _, _, status, _) = rt.state.apply_block_parallel_fees(&[bad], TS).await;
    assert_eq!(status, vec![false], "revoked grant is refused at apply too");
}

// ============================================================================
// 4+5. Parallel vs sequential apply at 10k (grouped + distinct accounts).
// ============================================================================

/// Mirror of `fill_canonical` straight into an engine (funding + tx vec).
async fn grouped_workload() -> (Arc<InMemoryStateEngine>, Vec<Transaction>) {
    let e = Arc::new(InMemoryStateEngine::new());
    let mut txs = Vec::with_capacity(N_TXS);
    let mut seq = 0u64;
    for i in 0..N_SENDERS as u64 {
        let sk = det_key(i);
        e.update_account(AccountState::new(id_of(&sk), BAL)).await;
        for nonce in 0..PER_SENDER {
            txs.push(legacy_tx(&sk, RECIPIENT, nonce, seq));
            seq += 1;
        }
    }
    e.update_account(AccountState::new(RECIPIENT, 0)).await;
    (e, txs)
}

async fn balances(e: &InMemoryStateEngine, addrs: &[[u8; 32]]) -> Vec<(u64, u64)> {
    let mut out = Vec::with_capacity(addrs.len());
    for a in addrs {
        let acc = e.get_account(a).await.expect("account exists");
        out.push((acc.balance, acc.nonce));
    }
    out
}

#[tokio::test]
async fn scale_parallel_matches_sequential_at_ten_k() {
    let (a, txs) = grouped_workload().await;
    let (b, _) = grouped_workload().await;

    // Sequential baseline: single-tx path, one by one in block order.
    // (Empty payloads charge gas_limit on BOTH paths, so the pinned fee-rule
    // divergence does not apply here; see PROTOCOL.md.)
    for tx in &txs {
        b.apply_transaction(tx, TS).await.expect("baseline applies");
    }
    let (applied, failed, _, _, _) = a.apply_block_parallel_fees(&txs, TS).await;
    assert_eq!(applied, N_TXS);
    assert_eq!(failed, 0);

    assert_eq!(
        a.get_state_root().await,
        b.get_state_root().await,
        "parallel root must equal sequential root at 10k"
    );
    let mut addrs: Vec<[u8; 32]> = (0..N_SENDERS as u64).map(|i| id_of(&det_key(i))).collect();
    addrs.push(RECIPIENT);
    assert_eq!(balances(&a, &addrs).await, balances(&b, &addrs).await);
}

#[tokio::test]
async fn scale_parallel_matches_sequential_distinct_accounts() {
    // Dedup no-op path: every account is touched exactly once.
    async fn setup() -> (Arc<InMemoryStateEngine>, Vec<Transaction>, Vec<[u8; 32]>) {
        let e = Arc::new(InMemoryStateEngine::new());
        let mut txs = Vec::with_capacity(N_TXS);
        let mut addrs = Vec::with_capacity(N_TXS + 1);
        for i in 0..N_TXS as u64 {
            let sk = det_key(500_000 + i);
            let from = id_of(&sk);
            let mut to = [0xDDu8; 32];
            to[..8].copy_from_slice(&i.to_le_bytes());
            e.update_account(AccountState::new(from, BAL)).await;
            txs.push(legacy_tx(&sk, to, 0, i));
            addrs.push(from);
            addrs.push(to);
        }
        (e, txs, addrs)
    }
    let (a, txs, addrs) = setup().await;
    let (b, _, _) = setup().await;
    for tx in &txs {
        b.apply_transaction(tx, TS).await.expect("baseline applies");
    }
    let (applied, failed, _, _, _) = a.apply_block_parallel_fees(&txs, TS).await;
    assert_eq!(applied, N_TXS);
    assert_eq!(failed, 0);
    assert_eq!(
        a.get_state_root().await,
        b.get_state_root().await,
        "parallel root must equal sequential root with distinct accounts"
    );
    assert_eq!(balances(&a, &addrs).await, balances(&b, &addrs).await);
}

// ============================================================================
// 6. Parallel MEV gate (>=512 txs) keeps exactly the sequential set, in order.
// ============================================================================

#[tokio::test]
async fn scale_mev_parallel_gate_matches_sequential_filter() {
    const N: usize = 600; // over the 512-tx parallel-gate threshold
    let keys: Vec<SigningKey> = (0..N as u64).map(|i| det_key(700_000 + i)).collect();
    let funding: Vec<([u8; 32], u64)> = keys.iter().map(|k| (id_of(k), BAL)).collect();
    let pool = Arc::new(tokio::sync::RwLock::new(Mempool::new(4_096, 4_096)));
    {
        let mut pool = pool.write().await;
        for (i, sk) in keys.iter().enumerate() {
            pool.add_checked(legacy_tx(sk, RECIPIENT, 0, i as u64), BAL)
                .expect("admission");
        }
    }
    let mut rt = runtime_with_pool(pool.clone(), &funding).await;
    let block = rt.propose(TS).await.expect("600-tx pool must propose");
    assert_eq!(block.transactions.len(), N);

    // Independent expectation: fee-order multi-pass selection (contiguous from
    // nonce 0, funded) filtered by the SEQUENTIAL unseal check.
    let pool = pool.read().await;
    let expected = pool.select_for_block_multi(10_000, 30_000_000, |t| t.nonce == 0);
    let expected: Vec<Transaction> = expected
        .into_iter()
        .filter(|t| {
            matches!(
                pool.mev.verify_pool_tx(t),
                stellereum::mev::SealVerdict::Match | stellereum::mev::SealVerdict::NotSealed
            )
        })
        .collect();
    let got: Vec<[u8; 32]> = block
        .transactions
        .iter()
        .map(|t| t.compute_tx_hash())
        .collect();
    let want: Vec<[u8; 32]> = expected.iter().map(|t| t.compute_tx_hash()).collect();
    assert_eq!(
        got, want,
        "parallel gate must keep the sequential set in order"
    );
}

// ============================================================================
// 7. Trie root is independent of insert order (dedup premise, public API only).
// ============================================================================

#[tokio::test]
async fn scale_trie_insert_order_does_not_move_root() {
    const N: usize = 2_000;
    let addrs: Vec<[u8; 32]> = (0..N as u64)
        .map(|i| id_of(&det_key(900_000 + i)))
        .collect();
    // Deterministic "shuffle": multiply-permute (coprime stride), plus reverse.
    let perm: Vec<usize> = (0..N).map(|i| (i * 1_009 + 17) % N).collect();
    assert_eq!(perm.iter().collect::<BTreeSet<_>>().len(), N);
    let rev: Vec<usize> = (0..N).rev().collect();
    let mut roots = Vec::new();
    for order in [&(0..N).collect::<Vec<_>>(), &perm, &rev] {
        let e = InMemoryStateEngine::new();
        for &i in order.iter() {
            e.update_account(AccountState::new(addrs[i], 1_000 + i as u64))
                .await;
        }
        roots.push(e.get_state_root().await);
        // Reads see the same values regardless of insert order.
        assert_eq!(
            e.get_account(&addrs[0]).await.unwrap().balance,
            1_000,
            "reads are order-independent"
        );
    }
    assert_eq!(roots[0], roots[1]);
    assert_eq!(roots[0], roots[2]);
}

// ============================================================================
// 8. senders() is exactly the sender set of all().
// ============================================================================

#[test]
fn scale_senders_matches_all_derivation() {
    let mut pool = Mempool::new(1_024, 1_024);
    for i in 0..300u64 {
        // 30 senders x 10 nonces.
        let sk = det_key(i / 10);
        pool.add(legacy_tx(&sk, RECIPIENT, i % 10, i))
            .expect("admission");
    }
    let want: BTreeSet<[u8; 32]> = pool.all().iter().map(|t| t.from).collect();
    assert_eq!(pool.senders(), want);
    assert_eq!(pool.senders().len(), 30);
}
