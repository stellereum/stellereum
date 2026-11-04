//! Session keys PHASE 2: the stateful, committed registry.
//!
//! Phase 0+1 made the grant self-contained and stateless: expiry, scope, value
//! cap and budget were all checked against the grant the transaction carries.
//! That cannot express the two things a master actually needs after handing a
//! key to an agent:
//!
//!   1. SPEND THAT ACCUMULATES. Two transactions of one grant in the same
//!      block must not each pass against the same remaining budget, and the
//!      spend must survive the block, the restart and the restore.
//!   2. REVOCATION. A master must be able to kill a key on chain, once, with a
//!      transaction, and have EVERY path agree afterwards - mempool admission,
//!      the proposer filter and execution.
//!
//! Invariants pinned here:
//!   * the registry is consensus state (it is in the state root) and it
//!     persists through `snapshot_domains` -> `load_full_state_into`;
//!   * the digest domain is CONDITIONAL, so a chain with no session keys
//!     hashes byte-identically to before (the unpinned genesis KAT is the
//!     real proof; `conditional_session_domain_...` shows why);
//!   * `OpCode::SysCallRevokeSession` was APPENDED to the enum, so an old
//!     node fails closed on a block carrying it instead of misreading it.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use stellereum::consensus::ValidatorSet;
use stellereum::mempool::{AdmissionCtx, Mempool, MempoolError};
use stellereum::runtime::ValidatorRuntime;
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::OpCode;
use stellereum::zkml::{SessionKeyAuthorization, SessionKeyRecord, SCOPE_ALL, SCOPE_TRANSFER};

const CHAIN_ID: u64 = 5757;
/// Block clock for every test here. Deterministic: never wall time.
const TS: u64 = 2_000_000;
/// Generous enough that no grant in these tests expires.
const VALID_UNTIL: u64 = 5_000_000;
const BALANCE: u64 = 10_000_000;

fn key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

fn grant(
    master: &SigningKey,
    session: &SigningKey,
    max_gas_spend: u64,
    scope: u64,
    max_value_per_tx: u64,
) -> SessionKeyAuthorization {
    SessionKeyAuthorization::sign_delegation(
        master,
        session.verifying_key().to_bytes(),
        VALID_UNTIL,
        max_gas_spend,
        scope,
        max_value_per_tx,
        CHAIN_ID,
    )
}

#[allow(clippy::too_many_arguments)]
fn session_tx(
    session: &SigningKey,
    delegation: SessionKeyAuthorization,
    amount: u64,
    gas_limit: u64,
    nonce: u64,
    payload: Vec<OpCode>,
) -> Transaction {
    Transaction::sign_with_session(
        session, delegation, [1u8; 32], amount, gas_limit, nonce, 1, 1, payload,
    )
}

async fn funded_state(owner: [u8; 32], balance: u64) -> InMemoryStateEngine {
    let st = InMemoryStateEngine::new();
    st.update_account(AccountState::new(owner, balance)).await;
    st
}

// ============================================================================
// 1. Persistence: the registry survives snapshot -> restore, root and all.
// ============================================================================

#[tokio::test]
async fn registry_persists_across_snapshot_and_restore() {
    use stellereum::storage::{load_full_state_into, AsyncPersistence, Storage};

    const SNAP_H: u64 = 500;
    const NEXT_H: u64 = SNAP_H + 1;

    let master = key();
    let session = key();
    let master_pub = master.verifying_key().to_bytes();
    let session_pub = session.verifying_key().to_bytes();

    // Post-SNAP_H state: a registered session key with real spend against it.
    let engine = funded_state(master_pub, BALANCE).await;
    let tx = session_tx(
        &session,
        grant(&master, &session, 10_000, SCOPE_ALL, u64::MAX),
        10,
        1_000,
        0,
        vec![],
    );
    let (_, _, _, status, _) = engine.apply_block_parallel_fees(&[tx], TS).await;
    assert_eq!(status, vec![true], "the registering transaction must apply");
    {
        let reg = engine.session_keys_read().await;
        assert_eq!(reg.len(), 1, "first use registers the key");
        let rec = reg.get(&session_pub).expect("record");
        assert_eq!(rec.master, master_pub, "the grant's master is recorded");
        assert_eq!(
            rec.gas_spent, 1_000,
            "an empty-payload transfer charges its declared limit"
        );
        assert!(!rec.revoked);
    }
    let root = engine.get_state_root().await;

    // Persist through the REAL path: the account snapshot directly, the domain
    // + session-key snapshots through `AsyncPersistence::snapshot_domains`
    // (background writer and all - the same call `main.rs` makes each period).
    let dir = std::env::temp_dir().join(format!(
        "stell-session-restore-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let store = std::sync::Arc::new(Storage::open(&dir).expect("open storage"));
    store
        .put_state(SNAP_H, &engine.create_snapshot().await)
        .expect("state");
    let ap = AsyncPersistence::start(store.clone());
    ap.snapshot_domains(
        &engine,
        &stellereum::staking::StakingLedger::new(),
        &stellereum::governance::Governance::new(),
        SNAP_H,
    )
    .await;
    let mut persisted = false;
    for _ in 0..500 {
        let domains_ok =
            matches!(store.latest_domains().ok().flatten(), Some((h, _)) if h == SNAP_H);
        let session_ok = store.session_keys_at(SNAP_H).ok().flatten().is_some();
        if domains_ok && session_ok {
            persisted = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        persisted,
        "snapshot_domains must persist BOTH the domain and the session-key snapshot"
    );

    // Anchor: the block at SNAP_H+1 commits to the post-SNAP_H root, which is
    // what the restore verifier compares against.
    let sk = SigningKey::from_bytes(&[0x11u8; 32]);
    let mut anchor = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: NEXT_H,
        prev_hash: [0u8; 32],
        state_root: root,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: TS + NEXT_H,
        proposer: sk.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    anchor.sign_block(&sk);
    let anchor_hash = store.put_block(&anchor).expect("anchor");
    store
        .set_finalized(NEXT_H, &anchor_hash)
        .expect("finalized");
    store.flush().expect("flush");
    drop(ap);

    // Restart: a fresh engine must come back with the registry AND the same
    // root - a registry that restored empty would re-root the chain (the
    // domain is committed), and one that restored stale would be refused by
    // `verify_restored_root`.
    let fresh = InMemoryStateEngine::new();
    let (height, _staking, _gov) = load_full_state_into(&store, &fresh)
        .await
        .expect("load verifies")
        .expect("snapshot present");
    assert_eq!(height, SNAP_H);
    {
        let reg = fresh.session_keys_read().await;
        assert_eq!(reg.len(), 1, "the registry must come back from disk");
        let rec = reg.get(&session_pub).expect("restored record");
        assert_eq!(rec.master, master_pub);
        assert_eq!(
            rec.gas_spent, 1_000,
            "spend is part of the persisted record"
        );
        assert_eq!(
            rec.max_gas_spend, 10_000,
            "the copied ceilings come back too"
        );
        assert_eq!(rec.scope, SCOPE_ALL);
        assert!(!rec.revoked);
    }
    assert_eq!(
        fresh.get_state_root().await,
        root,
        "the restored engine must compute the SAME state root"
    );

    // And the restored registry still gates: the budget is a fact after a
    // restart, not something the agent can re-present its way out of.
    let next = session_tx(
        &session,
        grant(&master, &session, 10_000, SCOPE_ALL, u64::MAX),
        10,
        9_500,
        1,
        vec![],
    );
    let err = fresh
        .apply_transaction(&next, TS)
        .await
        .expect_err("1000 already spent of a 10000 budget must still gate");
    assert!(
        err.contains("session key delegation"),
        "the refusal must name the delegation: {err}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ============================================================================
// 2-3. Cumulative budget on the live path (apply_block_transition region).
// ============================================================================

#[tokio::test]
async fn budget_exhaustion_blocks_the_next_tx_on_the_live_path() {
    let master = key();
    let session = key();
    let master_pub = master.verifying_key().to_bytes();
    let session_pub = session.verifying_key().to_bytes();
    let state = funded_state(master_pub, BALANCE).await;

    // Budget of exactly two declared transfers of 1000 each.
    let g = || grant(&master, &session, 2_000, SCOPE_ALL, u64::MAX);
    let tx1 = session_tx(&session, g(), 10, 1_000, 0, vec![]);
    let tx2 = session_tx(&session, g(), 10, 1_000, 1, vec![]);
    let tx3 = session_tx(&session, g(), 10, 1_000, 2, vec![]);

    let (_, _, _, s12, _) = state.apply_block_parallel_fees(&[tx1, tx2], TS).await;
    assert_eq!(s12, vec![true, true]);
    {
        let reg = state.session_keys_read().await;
        assert_eq!(
            reg.get(&session_pub).map(|r| r.gas_spent),
            Some(2_000),
            "two applied transfers of 1000 must have consumed the whole budget"
        );
    }
    let after_two = state.get_account(&master_pub).await.unwrap().balance;
    assert!(after_two < BALANCE, "two transfers moved value");

    // The NEXT transaction on the live path is refused - both live entry
    // points, and it moves nothing.
    let (applied, failed, _, status, _) = state
        .apply_block_parallel_fees(std::slice::from_ref(&tx3), TS)
        .await;
    assert_eq!(status, vec![false], "an exhausted grant must not execute");
    assert_eq!((applied, failed), (0, 1));
    let err = state
        .apply_transaction(&tx3, TS)
        .await
        .expect_err("the single-tx path must refuse it too");
    assert!(
        err.contains("session key delegation"),
        "the refusal must name the delegation: {err}"
    );
    assert_eq!(
        state.get_account(&master_pub).await.unwrap().balance,
        after_two,
        "a refused transaction moved nothing"
    );
    {
        let reg = state.session_keys_read().await;
        assert_eq!(
            reg.get(&session_pub).map(|r| r.gas_spent),
            Some(2_000),
            "a refused transaction must NOT be charged"
        );
    }
}

#[tokio::test]
async fn in_block_budget_accumulates_across_two_txs_of_one_grant() {
    let master = key();
    let session = key();
    let master_pub = master.verifying_key().to_bytes();
    let session_pub = session.verifying_key().to_bytes();
    let state = funded_state(master_pub, BALANCE).await;

    let g = || grant(&master, &session, 2_000, SCOPE_ALL, u64::MAX);
    let tx1 = session_tx(&session, g(), 10, 1_000, 0, vec![]);
    let tx2 = session_tx(&session, g(), 10, 1_000, 1, vec![]);
    let tx3 = session_tx(&session, g(), 10, 1_000, 2, vec![]);

    // ONE block, three transactions, budget for two: the admission pass
    // carries the in-block overlay, execution charges for real as each one
    // applies, and the third is refused on both counts.
    let (_, _, _, status, _) = state.apply_block_parallel_fees(&[tx1, tx2, tx3], TS).await;
    assert_eq!(
        status,
        vec![true, true, false],
        "the first two of one grant apply in the same block, the third does not"
    );
    {
        let reg = state.session_keys_read().await;
        assert_eq!(reg.len(), 1, "one grant, one record");
        assert_eq!(reg.get(&session_pub).map(|r| r.gas_spent), Some(2_000));
    }
    // Exactly two transfers' worth of value moved, not three.
    let acct = state.get_account(&master_pub).await.unwrap();
    assert_eq!(
        acct.nonce, 2,
        "only the two applied transactions bumped the nonce"
    );
    assert_eq!(state.get_account(&[1u8; 32]).await.unwrap().balance, 20);

    // The accumulation is durable: a LATER block still sees a full budget.
    let tx4 = session_tx(&session, g(), 10, 1_000, 3, vec![]);
    let (_, _, _, later, _) = state.apply_block_parallel_fees(&[tx4], TS).await;
    assert_eq!(
        later,
        vec![false],
        "the budget spent in-block is spent for good"
    );
}

// ============================================================================
// 4. Revocation: lands in a block, then blocks EVERY path.
// ============================================================================

#[tokio::test]
async fn revoke_lands_in_a_block_and_blocks_subsequent_admissions_on_all_paths() {
    let master = key();
    let session = key();
    let attacker = key();
    let master_pub = master.verifying_key().to_bytes();
    let session_pub = session.verifying_key().to_bytes();
    let state = funded_state(master_pub, BALANCE).await;
    state
        .update_account(AccountState::new(
            attacker.verifying_key().to_bytes(),
            BALANCE,
        ))
        .await;

    let g = || grant(&master, &session, 100_000, SCOPE_ALL, u64::MAX);

    // 0. First use registers the key (master's nonce 0 -> 1).
    let use_tx = session_tx(&session, g(), 10, 1_000, 0, vec![]);
    let (_, _, _, s0, _) = state.apply_block_parallel_fees(&[use_tx], TS).await;
    assert_eq!(s0, vec![true]);

    // The transaction that will be blocked later: admitted into the proposer's
    // pool NOW, while the key is still good (nonce 2 is the master's next free
    // nonce once the revoke below lands). This is the realistic race - a
    // transaction sits in the mempool, a revoke lands, and the proposer must
    // not select it any more.
    let blocked = session_tx(&session, g(), 10, 1_000, 2, vec![]);
    let vset = ValidatorSet::from_list(vec![(master_pub, 1)]);
    let mut rt = ValidatorRuntime::new(master.clone(), vset, std::sync::Arc::new(state), 1);
    rt.mempool
        .write()
        .await
        .add_checked_ctx(blocked.clone(), BALANCE, AdmissionCtx::new(TS))
        .expect("admitted while the key is still good");
    let state = rt.state.clone();

    // 1. A third party cannot revoke what it does not own: the payload reaches
    //    the VM and REVERTS there (`only the delegator may revoke...`), so the
    //    record is untouched and the attacker's transaction is reported failed.
    let attack = Transaction::sign_with_payload(
        &attacker,
        [1u8; 32],
        10,
        5_000,
        0,
        1,
        1,
        vec![OpCode::SysCallRevokeSession {
            session_pubkey: session_pub,
        }],
    );
    let (_, _, _, s_attack, _) = state.apply_block_parallel_fees(&[attack], TS).await;
    assert_eq!(s_attack, vec![false], "a non-delegator's revoke must fail");
    assert!(
        !state.session_keys_read().await.is_revoked(&session_pub),
        "a failed revoke revoked nothing"
    );

    // 2. The DELEGATOR revokes, in a real block, through the real transition
    //    (`apply_block_transition` - the shared core of the live and reorg
    //    paths). Legacy tx: signed by the master key, so `tx.from` IS the
    //    delegator. (Master nonce 1 -> 2, which is exactly the nonce the
    //    pooled `blocked` transaction carries.)
    let revoke = Transaction::sign_with_payload(
        &master,
        [1u8; 32],
        10,
        5_000,
        1,
        1,
        1,
        vec![OpCode::SysCallRevokeSession {
            session_pubkey: session_pub,
        }],
    );
    let transactions = vec![revoke];
    let order_merkle_root = stellereum::mev::compute_order_merkle_root(&transactions);
    let block = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 2,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions,
        cross_shard_out: vec![],
        timestamp: TS,
        proposer: master_pub,
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
    };
    let outcome = state.apply_block_transition(&block, 0).await;
    assert_eq!(
        outcome.status,
        vec![true],
        "the delegator's revoke must land in the block"
    );
    {
        let reg = state.session_keys_read().await;
        let rec = reg.get(&session_pub).expect("the record exists");
        assert!(rec.revoked, "the revoke is committed");
        assert_eq!(rec.master, master_pub);
    }

    // 3. Every path now refuses a transaction under that key. The grant itself
    //    is still perfectly valid statelessly - only the registry says no,
    //    which is the whole point of committing it.
    assert!(
        blocked.check_session_policy(TS).is_ok(),
        "precondition: the CARRIED grant is still valid (revocation is on chain)"
    );

    // (a) mempool admission is NODE-LOCAL and deliberately does NOT consult the
    //     on-chain registry any more: the old synchronous `try_read` silently
    //     SKIPPED the stateful check under lock contention, so the same
    //     transaction was admitted or not depending on lock timing. Since
    //     admission does not decide INCLUSION (the proposer and execution do),
    //     it falls back to the local deterministic check - the carried grant -
    //     and ACCEPTS this still-statically-valid transaction. That is safe:
    //     the next two steps prove the revoked key cannot be included or
    //     executed no matter what the pool holds.
    let mut mp = Mempool::new(16, 16).with_session_registry(state.session_keys_handle());
    assert!(
        mp.add_checked_ctx(blocked.clone(), BALANCE, AdmissionCtx::new(TS))
            .is_ok(),
        "admission is node-local: it may pool a revoked tx, it never decides inclusion"
    );
    assert_eq!(
        blocked.check_session_policy(TS),
        Ok(()),
        "the local deterministic check (the carried grant) still passes"
    );

    // (b) the proposer filter: the pooled transaction is still there (it was
    //     admitted while valid), its nonce and balance are fine, and it is the
    //     ONLY reason it is not selected is the registry.
    assert!(
        rt.mempool.read().await.contains(&blocked.compute_tx_hash()),
        "precondition: the transaction is still pooled"
    );
    let proposed = rt.propose(TS).await.expect("propose must produce a block");
    assert!(
        proposed
            .transactions
            .iter()
            .all(|t| t.compute_tx_hash() != blocked.compute_tx_hash()),
        "the proposer must filter the revoked transaction out"
    );

    // (c) execution, both apply paths, on the very engine that revoked it.
    let (applied, failed, _, status, _) = state
        .apply_block_parallel_fees(std::slice::from_ref(&blocked), TS)
        .await;
    assert_eq!(status, vec![false], "the block path must refuse it");
    assert_eq!((applied, failed), (0, 1));
    let err = state
        .apply_transaction(&blocked, TS)
        .await
        .expect_err("the single-tx path must refuse it too");
    assert!(
        err.contains("revoked"),
        "the refusal must name the revocation: {err}"
    );

    // Terminal: a brand-new grant for the SAME key cannot resurrect it either.
    let resurrect = session_tx(
        &session,
        grant(&master, &session, 999_999, SCOPE_ALL, u64::MAX),
        10,
        1_000,
        2,
        vec![],
    );
    let (_, _, _, s_res, _) = state.apply_block_parallel_fees(&[resurrect], TS).await;
    assert_eq!(s_res, vec![false], "revoked is terminal, not per-grant");

    // ...while the master's own (legacy) transactions are unaffected: only the
    // session key died.
    let own = Transaction::sign(&master, [1u8; 32], 10, 1_000, 2, 1, 1);
    let (_, _, _, s_own, _) = state.apply_block_parallel_fees(&[own], TS).await;
    assert_eq!(s_own, vec![true], "revocation must not touch the master");
}

// ============================================================================
// 4b. DEFERRED ITEM 1: only the MASTER may revoke - not a delegated key.
// ============================================================================

#[tokio::test]
async fn session_authorized_revoke_of_another_key_is_rejected() {
    let master = key();
    let session = key();
    let other = key();
    let master_pub = master.verifying_key().to_bytes();
    let session_pub = session.verifying_key().to_bytes();
    let other_pub = other.verifying_key().to_bytes();
    let state = funded_state(master_pub, BALANCE).await;

    // Register BOTH session keys under the SAME master (first use, nonces 0,1).
    let (_, _, _, s0, _) = state
        .apply_block_parallel_fees(
            &[session_tx(
                &session,
                grant(&master, &session, 100_000, SCOPE_ALL, u64::MAX),
                10,
                1_000,
                0,
                vec![],
            )],
            TS,
        )
        .await;
    assert_eq!(s0, vec![true]);
    let (_, _, _, s1, _) = state
        .apply_block_parallel_fees(
            &[session_tx(
                &other,
                grant(&master, &other, 100_000, SCOPE_ALL, u64::MAX),
                10,
                1_000,
                1,
                vec![],
            )],
            TS,
        )
        .await;
    assert_eq!(s1, vec![true]);
    assert!(!state.session_keys_read().await.is_revoked(&other_pub));

    // The ATTACK: the delegated `session` key (tx.from == master, but signed by
    // the session key) tries to revoke the OTHER key. The VM's own rule
    // (`record.master == tx.from`) would allow it, because the master IS the
    // sender - the session gate must refuse before the payload runs.
    let attack = session_tx(
        &session,
        grant(&master, &session, 100_000, SCOPE_ALL, u64::MAX),
        10,
        5_000,
        2,
        vec![OpCode::SysCallRevokeSession {
            session_pubkey: other_pub,
        }],
    );
    assert!(attack.is_session_keyed());
    let (applied, failed, _, status, _) = state
        .apply_block_parallel_fees(std::slice::from_ref(&attack), TS)
        .await;
    assert_eq!(status, vec![false], "a delegated key may not revoke");
    assert_eq!((applied, failed), (0, 1));
    let err = state
        .apply_transaction(&attack, TS)
        .await
        .expect_err("the single-tx path must reject it too");
    assert!(
        err.contains("revoke"),
        "the refusal names revocation: {err}"
    );
    assert!(
        !state.session_keys_read().await.is_revoked(&other_pub),
        "the OTHER key must survive a delegated revoke"
    );
    assert!(
        !state.session_keys_read().await.is_revoked(&session_pub),
        "and the attacker's own key is not revoked either"
    );

    // The master's OWN legacy revoke still works: revocation is a master right.
    let real = Transaction::sign_with_payload(
        &master,
        [1u8; 32],
        10,
        5_000,
        // The refused attack above consumed the master's nonce (F-01: a failed
        // attempt is not free), so the master's own revoke carries the next one.
        3,
        1,
        1,
        vec![OpCode::SysCallRevokeSession {
            session_pubkey: other_pub,
        }],
    );
    let (_, _, _, s2, _) = state.apply_block_parallel_fees(&[real], TS).await;
    assert_eq!(s2, vec![true], "the master's legacy revoke must still land");
    assert!(state.session_keys_read().await.is_revoked(&other_pub));
}

// ============================================================================
// 4c. DEFERRED ITEM 2: preventive revocation of an UNUSED grant (tombstone).
// ============================================================================

#[tokio::test]
async fn preventive_revocation_tombstones_an_unused_grant() {
    let master = key();
    let session = key();
    let master_pub = master.verifying_key().to_bytes();
    let session_pub = session.verifying_key().to_bytes();
    let state = funded_state(master_pub, BALANCE).await;

    // Minted but never used: the registry is empty, so the VM revoke handler
    // fails closed on the unknown key.
    assert!(state.session_keys_read().await.get(&session_pub).is_none());
    let g = grant(&master, &session, 100_000, SCOPE_ALL, u64::MAX);

    // Without proof of authority the revoke leaves no tombstone: nobody can
    // pre-tombstone a key by guessing its public key.
    let unproven = Transaction::sign_with_payload(
        &master,
        [1u8; 32],
        10,
        5_000,
        0,
        1,
        1,
        vec![OpCode::SysCallRevokeSession {
            session_pubkey: session_pub,
        }],
    );
    let (_, _, _, su, _) = state.apply_block_parallel_fees(&[unproven], TS).await;
    assert_eq!(su, vec![false], "unknown key: nothing to revoke");
    assert!(!state.session_keys_read().await.is_revoked(&session_pub));

    // The master revokes the UNUSED grant in one payload that also PUBLISHES
    // the signed grant - the proof of authority. The tombstone commits.
    let revoke = Transaction::sign_with_payload(
        &master,
        [1u8; 32],
        10,
        5_000,
        // The failed `unproven` attempt above consumed the master's nonce
        // (F-01: a failed attempt is not free), so the revoke carries the
        // next one.
        1,
        1,
        1,
        vec![
            OpCode::SysCallPublishSessionGrant(Box::new(g.clone())),
            OpCode::SysCallRevokeSession {
                session_pubkey: session_pub,
            },
        ],
    );
    let (_, _, _, s0, _) = state.apply_block_parallel_fees(&[revoke], TS).await;
    assert_eq!(s0, vec![true], "the preventive revoke must land");
    {
        let reg = state.session_keys_read().await;
        assert!(reg.get(&session_pub).is_some(), "a tombstone record exists");
        assert!(reg.is_revoked(&session_pub), "and the denial is terminal");
    }

    // The later-presented copy of the SAME grant is refused everywhere, even
    // though it is still perfectly valid statelessly.
    let later = session_tx(&session, g.clone(), 10, 1_000, 1, vec![]);
    assert_eq!(
        later.check_session_policy(TS),
        Ok(()),
        "the grant the agent later presents is still valid on its own"
    );
    let (_, _, _, s1, _) = state
        .apply_block_parallel_fees(std::slice::from_ref(&later), TS)
        .await;
    assert_eq!(
        s1,
        vec![false],
        "the tombstone blocks the later presentation"
    );
    assert!(state.apply_transaction(&later, TS).await.is_err());

    // ...and a brand-new, larger grant cannot resurrect the key either.
    let fresh = session_tx(
        &session,
        grant(&master, &session, 999_999, SCOPE_ALL, u64::MAX),
        10,
        1_000,
        1,
        vec![],
    );
    let (_, _, _, s2, _) = state.apply_block_parallel_fees(&[fresh], TS).await;
    assert_eq!(s2, vec![false], "revocation is terminal, not per-grant");

    // The tombstone is part of the committed state root: an otherwise
    // identical registry with no tombstone roots differently.
    let empty = funded_state(master_pub, BALANCE).await;
    assert_ne!(
        state.get_state_root().await,
        empty.get_state_root().await,
        "a tombstone is committed state, not node-local"
    );
}

// ============================================================================
// 4d. DEFERRED ITEM 3: admission is deterministic; consensus owns the registry.
// ============================================================================

#[tokio::test]
async fn admission_is_deterministic_and_registry_is_enforced_at_consensus() {
    let master = key();
    let session = key();
    let master_pub = master.verifying_key().to_bytes();
    let session_pub = session.verifying_key().to_bytes();
    let state = funded_state(master_pub, BALANCE).await;

    // Register, then revoke, via the master's legacy transaction.
    let (_, _, _, s0, _) = state
        .apply_block_parallel_fees(
            &[session_tx(
                &session,
                grant(&master, &session, 100_000, SCOPE_ALL, u64::MAX),
                10,
                1_000,
                0,
                vec![],
            )],
            TS,
        )
        .await;
    assert_eq!(s0, vec![true]);
    let revoke = Transaction::sign_with_payload(
        &master,
        [1u8; 32],
        10,
        5_000,
        1,
        1,
        1,
        vec![OpCode::SysCallRevokeSession {
            session_pubkey: session_pub,
        }],
    );
    let (_, _, _, s1, _) = state.apply_block_parallel_fees(&[revoke], TS).await;
    assert_eq!(s1, vec![true]);
    assert!(state.session_keys_read().await.is_revoked(&session_pub));

    // Admission with the handle attached does not take the registry lock at
    // all, so the verdict cannot depend on lock timing (the old `try_read`
    // could silently skip the stateful check under contention).
    let mut mp = Mempool::new(64, 64).with_session_registry(state.session_keys_handle());
    let pooled = session_tx(
        &session,
        grant(&master, &session, 100_000, SCOPE_ALL, u64::MAX),
        10,
        1_000,
        2,
        vec![],
    );
    assert!(
        mp.add_checked_ctx(pooled.clone(), BALANCE, AdmissionCtx::new(TS))
            .is_ok(),
        "admission is local and deterministic"
    );
    assert_eq!(
        mp.add_checked_ctx(pooled, BALANCE, AdmissionCtx::new(TS)),
        Err(MempoolError::Duplicate),
        "the first admission landed; nothing registry-dependent happened"
    );

    // Consensus - the only place inclusion is decided - refuses it.
    let (applied, failed, _, status, _) = state
        .apply_block_parallel_fees(
            &[session_tx(
                &session,
                grant(&master, &session, 100_000, SCOPE_ALL, u64::MAX),
                10,
                1_000,
                2,
                vec![],
            )],
            TS,
        )
        .await;
    assert_eq!(status, vec![false], "the proposer/apply gate rejects it");
    assert_eq!((applied, failed), (0, 1));
}

// ============================================================================
// 4e. DEFERRED ITEM 4: node chain-id enforcement; digest stays conditional.
// ============================================================================

#[tokio::test]
async fn node_rejects_grants_minted_for_another_chain_and_digest_is_unchanged() {
    let master = key();
    let session = key();
    let master_pub = master.verifying_key().to_bytes();
    let session_pub = session.verifying_key().to_bytes();

    // This node is chain 42; the network's default is 5757.
    let state = InMemoryStateEngine::new().with_chain_id(42);
    state
        .update_account(AccountState::new(master_pub, BALANCE))
        .await;

    // A grant minted for the default chain is well-signed but foreign: the
    // domain binds chain_id and the node now COMPARES it.
    let foreign = SessionKeyAuthorization::sign_delegation(
        &master,
        session_pub,
        VALID_UNTIL,
        100_000,
        SCOPE_ALL,
        u64::MAX,
        5757,
    );
    let foreign_tx = session_tx(&session, foreign, 10, 1_000, 0, vec![]);
    assert!(foreign_tx.verify_signature(), "the grant is well-formed");
    let err = state
        .apply_transaction(&foreign_tx, TS)
        .await
        .expect_err("a foreign-chain grant must be refused");
    assert!(
        err.contains("chain id"),
        "the refusal names the chain id: {err}"
    );
    assert_eq!(
        state.get_account(&master_pub).await.unwrap().balance,
        BALANCE,
        "a refused foreign grant moves nothing"
    );

    // The SAME grant for this node's chain applies (nonce 0). A second
    // transaction (nonce 1) confirms the window is open, not a fluke.
    let native = SessionKeyAuthorization::sign_delegation(
        &master,
        session_pub,
        VALID_UNTIL,
        100_000,
        SCOPE_ALL,
        u64::MAX,
        42,
    );
    state
        .apply_transaction(
            &session_tx(&session, native.clone(), 10, 1_000, 0, vec![]),
            TS,
        )
        .await
        .expect("a native-chain grant must apply");
    state
        .apply_transaction(&session_tx(&session, native, 10, 1_000, 1, vec![]), TS)
        .await
        .expect("and stays applicable");

    // GOLDEN: chain id is node-local and must NOT move the digest or the
    // version. An empty engine roots identically whatever its chain id, so the
    // conditional session domain (and tests/genesis_root_known_answer_tests.rs)
    // is untouched.
    assert_eq!(stellereum::commitment::COMMITMENT_VERSION, 5);
    let e_a = InMemoryStateEngine::new().with_chain_id(42);
    let e_b = InMemoryStateEngine::new().with_chain_id(5757);
    assert_eq!(
        e_a.get_state_root().await,
        e_b.get_state_root().await,
        "chain id must never enter the committed digest"
    );
}

// ============================================================================
// 5. The digest domain is CONDITIONAL: empty contributes nothing at all.
// ============================================================================

#[tokio::test]
async fn conditional_session_domain_leaves_the_root_unchanged_when_empty() {
    let e = InMemoryStateEngine::new();
    let before = e.get_state_root().await;

    // Register something (any record will do - the point is non-empty).
    {
        let mut reg = e.session_keys_write().await;
        reg.entries.insert(
            [7u8; 32],
            SessionKeyRecord {
                master: [1u8; 32],
                valid_until: VALID_UNTIL,
                max_gas_spend: 100,
                gas_spent: 1,
                scope: SCOPE_TRANSFER,
                max_value_per_tx: 0,
                revoked: false,
            },
        );
    }
    let after = e.get_state_root().await;
    assert_ne!(
        before, after,
        "a registered session key IS committed - otherwise two nodes that
         disagreed about revocation or budget would share a state root"
    );

    // Remove it: the root must come back to EXACTLY the pre-registration
    // value. Not "close", not "equal modulo the domain" - identical, which is
    // only possible if an empty registry contributes zero bytes to the
    // digest. That is what leaves tests/genesis_root_known_answer_tests.rs
    // (which this change deliberately does NOT touch) green.
    e.session_keys_write().await.entries.clear();
    assert_eq!(
        e.get_state_root().await,
        before,
        "an empty registry must contribute NOTHING to the digest"
    );
    assert_eq!(
        stellereum::commitment::COMMITMENT_VERSION,
        5,
        "Genesis v5 version"
    );
}

// ============================================================================
// 6. Old nodes: fail closed on the appended opcode.
// ============================================================================

#[test]
fn old_node_fails_closed_on_the_revoke_opcode() {
    use serde::{Deserialize, Serialize};

    // The OpCode enum exactly as a PRE-phase-2 node compiled it: the same
    // variants in the same order, stopping at `SysCallSubmitPriceFeed`. This
    // mirrors the `old_decoder_rejects_batch` style in src/consensus_net.rs -
    // model the old decoder, feed it new bytes, require a hard failure rather
    // than a misread.
    #[derive(Serialize, Deserialize)]
    enum OldOpCode {
        Nop,
        Push(u64),
        Pop,
        Add,
        Sub,
        Mul,
        Div,
        LoadBalance,
        Transfer {
            recipient: [u8; 32],
            amount: u64,
        },
        SysCallPlaceOrder {
            pair_id: u32,
            is_buy: bool,
            price: u64,
            amount: u64,
        },
        SysCallCancelOrder {
            order_id: u64,
        },
        SysCallVerifyZkMl,
        SysCallPatriciaLookup(stellereum::cell::CellHash),
        SysCallTokenTransfer {
            token_id: [u8; 32],
            to: [u8; 32],
            amount: u64,
        },
        SysCallTokenTransferFrom {
            token_id: [u8; 32],
            from: [u8; 32],
            to: [u8; 32],
            amount: u64,
        },
        SysCallTokenMint {
            token_id: [u8; 32],
            to: [u8; 32],
            amount: u64,
        },
        SysCallTokenBurn {
            token_id: [u8; 32],
            from: [u8; 32],
            amount: u64,
        },
        SysCallTokenApprove {
            token_id: [u8; 32],
            spender: [u8; 32],
            amount: u64,
        },
        SysCallTokenBalanceOf {
            token_id: [u8; 32],
            account: [u8; 32],
        },
        SysCallDeployContract {
            code: Vec<u8>,
        },
        SysCallCallContract {
            contract: [u8; 32],
            method: Vec<u8>,
            arg: i64,
        },
        SysCallStake {
            validator: [u8; 32],
            amount: u64,
        },
        SysCallUnbond {
            validator: [u8; 32],
            amount: u64,
        },
        SysCallDelegate {
            validator: [u8; 32],
            amount: u64,
        },
        SysCallUndelegate {
            validator: [u8; 32],
        },
        SysCallClaimRewards {
            validator: [u8; 32],
        },
        Halt,
        SysCallSubmitPriceFeed(Box<stellereum::oracle::PriceFeedUpdate>),
    }

    // The old node's transaction shape (bincode has no field names, and the
    // layout is the one tests/session_key_tests.rs pins byte-for-byte).
    #[derive(Serialize, Deserialize)]
    struct OldTransaction {
        from: [u8; 32],
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: u32,
        target_shard: u32,
        signature: Vec<u8>,
        payload: Vec<OldOpCode>,
    }

    let sk = key();

    // (1) NEW bytes -> OLD decoder: fail closed. The appended variant's
    //     discriminant simply does not exist in the old enum, so decoding the
    //     payload - and therefore the transaction, and therefore the block -
    //     is an error, never a misinterpretation as some earlier opcode.
    let revoke_payload = vec![OpCode::SysCallRevokeSession {
        session_pubkey: [9u8; 32],
    }];
    let bytes = bincode::serialize(&revoke_payload).expect("payload serializes");
    let old: Result<Vec<OldOpCode>, _> = bincode::deserialize(&bytes);
    assert!(
        old.is_err(),
        "an old node must fail closed on a payload carrying the revoke opcode"
    );

    let revoke_tx =
        Transaction::sign_with_payload(&sk, [1u8; 32], 10, 5_000, 0, 1, 1, revoke_payload);
    let tx_bytes = bincode::serialize(&revoke_tx).expect("tx serializes");
    let old_tx: Result<OldTransaction, _> = bincode::deserialize(&tx_bytes);
    assert!(
        old_tx.is_err(),
        "an old node must fail closed on the TRANSACTION carrying it"
    );

    // (2) APPEND-ONLY: every variant that existed before kept its
    //     discriminant, so old payloads still decode - on both sides.
    let legacy_new = bincode::serialize(&vec![OpCode::Halt, OpCode::Push(7)]).unwrap();
    let legacy_old: Vec<OldOpCode> = bincode::deserialize(&legacy_new)
        .expect("an old node must still decode pre-existing opcodes");
    assert!(matches!(legacy_old[0], OldOpCode::Halt));
    assert!(matches!(legacy_old[1], OldOpCode::Push(7)));
    assert_eq!(
        bincode::serialize(&legacy_old).unwrap(),
        legacy_new,
        "re-encoding through the old enum must be byte-identical"
    );
    let back: Vec<OpCode> = bincode::deserialize(&legacy_new).unwrap();
    assert!(matches!(back[0], OpCode::Halt) && matches!(back[1], OpCode::Push(7)));
}
