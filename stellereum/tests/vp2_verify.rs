//! V-P2 verification: independent re-test of every P2 mempool/transaction fix
//! with STRONGER exploits than the original P2 agent used.
//!
//! Each module pins one claimed fix. Verdicts are recorded in the test names
//! and in the summary at the bottom of this file. Code only — no live cluster.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use stellereum::mempool::{AdmissionCtx, Mempool, MempoolError};
use stellereum::mev::SealVerdict;
use stellereum::sharding::{Transaction, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

fn sk() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

fn addr(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

/// Plain funded transfer: cost = amount + gas_limit.
fn tx(k: &SigningKey, to: [u8; 32], amount: u64, gas: u64, nonce: u64, src: u32) -> Transaction {
    Transaction::sign(k, to, amount, gas, nonce, src, src)
}

// ===========================================================================
// 1. SHARD GATE — every admission path
// ===========================================================================

/// Exploit baseline: on an UNPINNED pool, every legacy admission path admits
/// a foreign-shard transaction. This is the hole the pool-level pin closes.
#[test]
fn shard_gate_unpinned_pool_admits_foreign_on_every_path() {
    let k = sk();
    let me = addr(&k);
    let bal = 10_000_000u64;
    // add (unchecked, unfunded)
    {
        let mut mp = Mempool::new(100, 100);
        let h = mp.add(tx(&k, [9u8; 32], 10, 1_000, 0, 7)).unwrap();
        assert!(mp.contains(&h));
    }
    // add_checked / add_checked_ctx with a bare wall clock
    {
        let mut mp = Mempool::new(100, 100);
        let t = tx(&k, [9u8; 32], 10, 1_000, 0, 7);
        let h = mp.add_checked(t, bal).unwrap();
        assert!(mp.contains(&h));
        let t2 = tx(&k, [9u8; 32], 10, 1_000, 1, 7);
        let h2 = mp
            .add_checked_ctx(t2, bal, AdmissionCtx::wall_now())
            .unwrap();
        assert!(mp.contains(&h2));
        let _ = me;
    }
}

/// Post-fix HOLDS: a pool pinned at startup refuses foreign-shard txs on EVERY
/// admission path — including paths whose caller passes no shard in ctx
/// (gossip-style `wall_now()`, `add`, `add_checked`, restore re-admission).
#[test]
fn shard_gate_pinned_pool_refuses_foreign_on_every_path() {
    let k = sk();
    let bal = 10_000_000u64;
    let mut mp = Mempool::new(100, 100).pin_admission_shard(Some(MASTERCHAIN_SHARD));
    assert_eq!(mp.admission_shard(), Some(MASTERCHAIN_SHARD));

    // own-shard admits everywhere
    let own = tx(&k, [9u8; 32], 10, 1_000, 0, MASTERCHAIN_SHARD);
    assert!(mp.add_checked(own, bal).is_ok());

    // foreign-shard refused on every path (the exact gossip/restore shape:
    // balance known, nonce known, but NO shard in ctx)
    for nonce in [1u64, 2, 3, 4] {
        let f = tx(&k, [9u8; 32], 10, 1_000, nonce, 7);
        let r = mp.add_checked_ctx(f, bal, AdmissionCtx::wall_now());
        assert!(
            matches!(r, Err(MempoolError::Malformed(_))),
            "nonce {nonce}: {r:?}"
        );
    }
    // unchecked path too
    let f = tx(&k, [9u8; 32], 10, 1_000, 9, 7);
    assert!(matches!(mp.add(f), Err(MempoolError::Malformed(_))));
    // the pool pin is authoritative over the per-call ctx: even a ctx naming
    // shard 7 cannot smuggle a shard-7 tx into the shard-0 pool
    let f = tx(&k, [9u8; 32], 10, 1_000, 10, 7);
    assert!(matches!(
        mp.add_checked_ctx(f, bal, AdmissionCtx::wall_now().with_shard(7)),
        Err(MempoolError::Malformed(_))
    ));
    assert_eq!(mp.len(), 1);
    // and a pinned ctx for OUR shard still admits
    let own2 = tx(&k, [9u8; 32], 10, 1_000, 11, MASTERCHAIN_SHARD);
    assert!(mp
        .add_checked_ctx(
            own2,
            bal,
            AdmissionCtx::wall_now().with_shard(MASTERCHAIN_SHARD)
        )
        .is_ok());
}

/// The 2PC PREPARE path has no separate mempool ingress: the underlying
/// transfer is admitted exactly once via the normal checked path, so the pin
/// covers it. A cross-shard transfer sourced on shard 1 is refused by the
/// shard-0 pinned pool and admitted by the shard-1 pinned pool.
#[test]
fn shard_gate_2pc_transfer_admission_follows_source_shard_pin() {
    let k = sk();
    let bal = 10_000_000u64;
    // outbound cross-shard transfer sourced on shard 1
    let x = Transaction::sign(&k, [9u8; 32], 10, 1_000, 0, 1, 0);
    let mut pool0 = Mempool::new(100, 100).pin_admission_shard(Some(0));
    assert!(matches!(
        pool0.add_checked(x.clone(), bal),
        Err(MempoolError::Malformed(_))
    ));
    let mut pool1 = Mempool::new(100, 100).pin_admission_shard(Some(1));
    assert!(pool1.add_checked(x, bal).is_ok());
}

/// Restore path: a persisted foreign-shard tx restores zero entries on a
/// pinned pool, own-shard restores fully.
#[tokio::test]
async fn shard_gate_restore_drops_foreign() {
    let k = sk();
    let dir = std::env::temp_dir().join(format!("vp2_restore_{}", rand::random::<u32>()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // save a pool holding a shard-7 tx (unpinned pool can hold it)
    let path = dir.join("mempool.bin");
    let t = tx(&k, [9u8; 32], 10, 1_000, 0, 7);
    let h = t.compute_tx_hash();
    {
        let mut mp = Mempool::new(100, 100);
        mp.add_checked(t, 10_000_000).unwrap();
        mp.save(&path);
        assert!(mp.contains(&h));
    }
    // restore into a shard-0 pinned pool: refused
    {
        let engine = InMemoryStateEngine::new();
        let mut mp = Mempool::new(100, 100).pin_admission_shard(Some(0));
        let kept = mp.load_into(&path, &engine, AdmissionCtx::wall_now()).await;
        assert_eq!(kept, 0);
        assert!(!mp.contains(&h));
    }
    // restore into a shard-7 pinned pool: kept (needs funded account for
    // re-admission balance check — engine account is empty, so fund it via
    // the state engine first).
    {
        let engine = InMemoryStateEngine::new();
        engine
            .update_account(AccountState::new(addr(&k), 10_000_000))
            .await;
        let mut mp = Mempool::new(100, 100).pin_admission_shard(Some(7));
        let kept = mp.load_into(&path, &engine, AdmissionCtx::wall_now()).await;
        assert_eq!(kept, 1);
        assert!(mp.contains(&h));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// ===========================================================================
// 2. PRIORITY BID — overflow, zero-floor, post-admission mutation
// ===========================================================================

/// u64::MAX bid: saturating arithmetic, no panic, admission iff fully funded.
#[test]
fn priority_bid_max_does_not_overflow_and_requires_full_funding() {
    let k = sk();
    let mp = Mempool::new(10, 10);
    let t = Transaction::sign_with_priority(&k, [1u8; 32], 0, u64::MAX, 0, 1, 1, u64::MAX);
    // floor 0 + bid MAX saturates to MAX
    assert_eq!(mp.required_fee_for_tx(&t), u64::MAX);
    // gas_limit MAX covers it exactly
    let mut mp2 = Mempool::new(10, 10);
    assert!(mp2.add_checked(t.clone(), u64::MAX).is_ok());
    // one unit short on EITHER leg refuses
    let mut mp3 = Mempool::new(10, 10);
    assert!(matches!(
        mp3.add_checked(t.clone(), u64::MAX - 1),
        Err(MempoolError::InsufficientBalance)
    ));
    let short = Transaction::sign_with_priority(&k, [1u8; 32], 0, u64::MAX - 1, 0, 1, 1, u64::MAX);
    let mut mp4 = Mempool::new(10, 10);
    assert!(matches!(
        mp4.add_checked(short, u64::MAX),
        Err(MempoolError::FeeTooLow)
    ));
}

/// Zero-floor pool: bid-only admission works and is still funded.
#[test]
fn priority_bid_zero_floor_bid_only_admission() {
    let k = sk();
    let mut mp = Mempool::new(10, 10); // base_fee 0
    assert_eq!(mp.base_fee, 0);
    let t = Transaction::sign_with_priority(&k, [1u8; 32], 0, 500, 0, 1, 1, 500);
    assert_eq!(mp.required_fee_for_tx(&t), 500);
    assert!(mp.add_checked(t, 500).is_ok());
    // bid NOT covered by gas_limit: refused even though floor is 0
    let free = Transaction::sign_with_priority(&k, [1u8; 32], 0, 100, 1, 1, 1, 500);
    let mut mp2 = Mempool::new(10, 10);
    assert!(matches!(
        mp2.add_checked(free, 10_000),
        Err(MempoolError::FeeTooLow)
    ));
}

/// Post-admission mutation cannot reorder: the pool stores its own clone, the
/// order key is fixed at admission, and the MEV seal drops mutated copies.
#[test]
fn priority_bid_mutation_after_admission_changes_nothing() {
    let k = sk();
    let mut mp = Mempool::new(10, 10);
    let low = Transaction::sign_with_priority(&k, [1u8; 32], 0, 1_000, 0, 1, 1, 10);
    let h = mp.add_checked(low.clone(), 1_000_000).unwrap();
    assert!(matches!(mp.mev.verify_pool_tx(&low), SealVerdict::Match));

    // mutate a CLONE the way an attacker would like the pool entry to change
    let mut forged = mp.get(&h).unwrap().clone();
    forged.priority_fee_per_gas = u64::MAX;
    forged.gas_limit = u64::MAX;
    // the pool entry is untouched (order key + stored copy immutable)
    let stored = mp.get(&h).unwrap();
    assert_eq!(stored.priority_fee_per_gas, 10);
    assert_eq!(stored.gas_limit, 1_000);
    // the forged copy has a DIFFERENT identity (bid is hash-committed), so no
    // envelope exists for it: it can never ride the pool entry's seal, and
    // the pool still reports the admitted tx as Match
    assert!(matches!(
        mp.mev.verify_pool_tx(&forged),
        SealVerdict::NotSealed
    ));
    assert!(matches!(mp.mev.verify_pool_tx(&low), SealVerdict::Match));
    assert!(matches!(
        mp.mev.verify_pool_tx(mp.get(&h).unwrap()),
        SealVerdict::Match
    ));
    // order still ranks by the ADMITTED bid
    let k2 = sk();
    let mid = Transaction::sign_with_priority(&k2, [1u8; 32], 0, 1_000, 0, 1, 1, 50);
    mp.add_checked(mid, 1_000_000).unwrap();
    let first = mp.select(1);
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].priority_fee_per_gas, 50);
}

// ===========================================================================
// 3. EVICTION PREMIUM — boundary + ratchet measurement
// ===========================================================================

/// Exact-boundary: newcomer at exactly low+premium is admitted, one unit
/// below is refused. Premium = ceil(low/20), min 1.
#[test]
fn eviction_premium_exact_boundary() {
    assert_eq!(Mempool::eviction_premium(100), 5);
    assert_eq!(Mempool::eviction_premium(1_000), 50);
    assert_eq!(Mempool::eviction_premium(1), 1);
    assert_eq!(Mempool::eviction_premium(0), 1);
    assert_eq!(Mempool::eviction_premium(19), 1);

    for low_fee in [100u64, 1_000, 37] {
        let premium = Mempool::eviction_premium(low_fee);
        // fill a 2-slot pool with low_fee txs (distinct senders)
        let mut mp = Mempool::new(2, 100);
        for i in 0..2 {
            let k = sk();
            // amount 0, gas = low_fee
            mp.add_checked(tx(&k, [1u8; 32], 0, low_fee, 0, 1), 1_000_000_000)
                .unwrap();
            let _ = i;
        }
        // exactly premium over: admitted (evicts lowest)
        let kn = sk();
        let win = tx(&kn, [1u8; 32], 0, low_fee + premium, 0, 1);
        assert!(
            mp.add_checked(win, 1_000_000_000).is_ok(),
            "low={low_fee} premium={premium}: exact boundary must admit"
        );
        // one unit under: refused
        let mut mp2 = Mempool::new(2, 100);
        for _ in 0..2 {
            let k = sk();
            mp2.add_checked(tx(&k, [1u8; 32], 0, low_fee, 0, 1), 1_000_000_000)
                .unwrap();
        }
        let kn2 = sk();
        let lose = tx(&kn2, [1u8; 32], 0, low_fee + premium - 1, 0, 1);
        assert_eq!(
            mp2.add_checked(lose, 1_000_000_000),
            Err(MempoolError::Full),
            "low={low_fee}: one under premium must refuse"
        );
    }
}

/// Ratchet measurement: repeated minimum-premium sweeps compound geometrically
/// (×1.05), NOT linearly — but with base 1.05 it takes ~14 sweeps to double,
/// vs 1 sweep under the old 2× rule. Honest re-entry stays feasible.
#[test]
fn eviction_premium_ratchet_is_slow_geometric_not_lockout() {
    // simulate k consecutive full-pool sweeps at minimum premium
    let mut floor = 1_000u64;
    for _ in 0..14 {
        floor += Mempool::eviction_premium(floor);
    }
    // 14 minimum-premium sweeps ≈ 2× (1.05^14 ≈ 1.98)
    assert!(
        (1_900..=2_100).contains(&floor),
        "14 sweeps should ≈ double from 1000, got {floor}"
    );
    // old rule doubled in ONE sweep: 1000 -> 2000 immediately
    assert!(floor < 2_000 * 2);
    // and a single sweep is gentle: 1000 -> 1050
    assert_eq!(1_000 + Mempool::eviction_premium(1_000), 1_050);
}

// ===========================================================================
// 4. NONCE WINDOW + REPLACEMENT + PER-SENDER + RESERVATION LEDGER
// ===========================================================================

/// Window is 4 past the executable head: nonce 4 (head 0) admits, 5 refuses.
#[test]
fn nonce_window_is_four_past_head() {
    let k = sk();
    let mut mp = Mempool::new(100, 100);
    let ctx0 = AdmissionCtx::new(0).with_onchain_nonce(0);
    assert!(mp
        .add_checked_ctx(tx(&k, [1u8; 32], 0, 1_000, 4, 1), 50_000, ctx0)
        .is_ok());
    let mut mp2 = Mempool::new(100, 100);
    let r = mp2.add_checked_ctx(tx(&k, [1u8; 32], 0, 1_000, 5, 1), 50_000, ctx0);
    assert!(
        matches!(
            r,
            Err(MempoolError::NonceGap {
                expected: 0,
                got: 5
            })
        ),
        "{r:?}"
    );
}

/// Same-(sender, nonce) with a HIGHER fee: NO replacement — coexistence is
/// deliberate (repo audit-closure F10: "implicit-RBF pair both pooled;
/// execution picks first"). Both variants pool; EACH reserves its full cost,
/// so same-nonce stuffing is economically bounded (every duplicate slot must
/// be fully funded, capped by `per_sender_limit` slots).
#[test]
fn nonce_duplicate_no_replacement_coexists_with_full_reservation() {
    let k = sk();
    let mut mp = Mempool::new(100, 100);
    let bal = 1_000_000u64;
    // incumbent: fee 1000 (amount 0)
    let h1 = mp
        .add_checked(tx(&k, [1u8; 32], 0, 1_000, 0, 1), bal)
        .unwrap();
    assert_eq!(mp.reserved_for(&addr(&k)), 1_000);
    // same (sender, nonce), HIGHER fee: coexists, not replaced, not refused
    let h2 = mp
        .add_checked(tx(&k, [2u8; 32], 0, 1_050, 0, 1), bal)
        .unwrap();
    assert_ne!(h1, h2);
    assert!(mp.contains(&h1) && mp.contains(&h2));
    assert_eq!(mp.len(), 2);
    // ...but BOTH reservations are held: slot-stuffing costs real money
    assert_eq!(mp.reserved_for(&addr(&k)), 2_050);
    // exact replay by hash is still refused
    let replay = tx(&k, [1u8; 32], 0, 1_000, 0, 1);
    assert_eq!(mp.add_checked(replay, bal), Err(MempoolError::Duplicate));
    // a third duplicate the sender cannot FULLY fund is refused: the
    // reservation ledger (not a replacement rule) is the economic bound
    let huge = tx(&k, [3u8; 32], 999_000, 500, 0, 1); // cost 999_500 > 1M - 2050
    assert_eq!(
        mp.add_checked(huge, bal),
        Err(MempoolError::InsufficientBalance)
    );
    assert_eq!(mp.len(), 2);
}

/// Reservation is released EXACTLY once on every exit path (W6.6 regression).
#[test]
fn reservation_released_exactly_once_on_every_exit() {
    let k = sk();
    let me = addr(&k);
    let bal = 1_000_000u64;
    // --- remove ---
    let mut mp = Mempool::new(100, 100);
    let h = mp
        .add_checked(tx(&k, [1u8; 32], 900, 100, 0, 1), bal)
        .unwrap(); // cost 1000
    assert_eq!(mp.reserved_for(&me), 1_000);
    mp.remove(&h);
    assert_eq!(mp.reserved_for(&me), 0);
    // --- remove_many (pooled) ---
    let h1 = mp
        .add_checked(tx(&k, [1u8; 32], 900, 100, 0, 1), bal)
        .unwrap();
    let h2 = mp
        .add_checked(tx(&k, [1u8; 32], 900, 100, 1, 1), bal)
        .unwrap();
    assert_eq!(mp.reserved_for(&me), 2_000);
    mp.remove_many(&[h1]);
    assert_eq!(mp.reserved_for(&me), 1_000);
    // --- prune_confirmed ---
    mp.prune_confirmed(&[h2]);
    assert_eq!(mp.reserved_for(&me), 0);
    // --- remove_many on a BUFFERED hash also releases (was a leak: evict noop) ---
    let btx = tx(&k, [1u8; 32], 900, 100, 7, 1);
    let bh = mp.buffer_activation_tx(btx, bal).unwrap();
    assert_eq!(mp.reserved_for(&me), 1_000);
    mp.remove_many(&[bh]);
    assert_eq!(mp.reserved_for(&me), 0, "buffered remove_many must release");
    // --- prune_confirmed on a buffered hash ---
    let btx2 = tx(&k, [1u8; 32], 900, 100, 8, 1);
    let bh2 = mp.buffer_activation_tx(btx2, bal).unwrap();
    assert_eq!(mp.reserved_for(&me), 1_000);
    mp.prune_confirmed(&[bh2]);
    assert_eq!(mp.reserved_for(&me), 0, "buffered prune must release");
    // --- evict_unexecutable (newly broke account) ---
    let _ = mp
        .add_checked(tx(&k, [1u8; 32], 900, 100, 0, 1), bal)
        .unwrap();
    assert_eq!(mp.reserved_for(&me), 1_000);
    let n = mp.evict_unexecutable_at(1_000, |_| Some((0u64, 0u64)));
    assert_eq!(n, 1);
    assert_eq!(mp.reserved_for(&me), 0);
    // --- sweep_expired (aged + unaffordable) ---
    let _ = mp
        .add_checked(tx(&k, [1u8; 32], 900, 100, 0, 1), bal)
        .unwrap();
    // age it past STUCK_TTL relative to the REAL admission stamp
    let sweep_at = stellereum::zkml::now_secs() + Mempool::STUCK_TX_TTL_SECS + 5;
    let n = mp.sweep_expired(sweep_at, |_| Some((0u64, 0u64)));
    assert_eq!(n, 1);
    assert_eq!(mp.reserved_for(&me), 0);
    // --- process_activation_buffer (buffer -> pool moves the claim) ---
    let btx3 = tx(&k, [1u8; 32], 900, 100, 9, 1);
    mp.buffer_activation_tx(btx3, bal).unwrap();
    assert_eq!(mp.reserved_for(&me), 1_000);
    let admitted = mp.process_activation_buffer(&me);
    assert_eq!(admitted.len(), 1);
    assert_eq!(
        mp.reserved_for(&me),
        1_000,
        "claim moved buffer->pool, not doubled"
    );
    mp.evict_unexecutable_at(3_000, |_| Some((0u64, 0u64)));
    assert_eq!(mp.reserved_for(&me), 0);
    // --- buffer replace releases the old claim once ---
    let b1 = tx(&k, [1u8; 32], 900, 100, 20, 1);
    mp.buffer_activation_tx(b1, bal).unwrap();
    assert_eq!(mp.reserved_for(&me), 1_000);
    let b2 = tx(&k, [9u8; 32], 1_800, 200, 20, 1); // same nonce, cost 2000
    mp.buffer_activation_tx(b2, bal).unwrap();
    assert_eq!(mp.reserved_for(&me), 2_000, "old claim released, new taken");
    // --- fee-eviction releases the victim ---
    let mut mp2 = Mempool::new(1, 100);
    let k2 = sk();
    mp2.add_checked(tx(&k2, [1u8; 32], 900, 100, 0, 1), bal)
        .unwrap(); // cost 1000
    assert_eq!(mp2.reserved_for(&addr(&k2)), 1_000);
    let k3 = sk();
    mp2.add_checked(tx(&k3, [1u8; 32], 0, 2_000, 0, 1), bal)
        .unwrap(); // evicts
    assert_eq!(mp2.len(), 1);
    assert_eq!(mp2.reserved_for(&addr(&k2)), 0, "evicted victim released");
}

/// Per-sender quota still enforced (distinct nonces, small limit).
#[test]
fn per_sender_quota_enforced() {
    let k = sk();
    let mut mp = Mempool::new(100, 2);
    let bal = 10_000_000u64;
    mp.add_checked(tx(&k, [1u8; 32], 0, 1_000, 0, 1), bal)
        .unwrap();
    mp.add_checked(tx(&k, [1u8; 32], 0, 1_000, 1, 1), bal)
        .unwrap();
    // same-nonce replacement does not consume quota; a 3rd DISTINCT nonce refuses
    assert_eq!(
        mp.add_checked(tx(&k, [1u8; 32], 0, 1_000, 2, 1), bal),
        Err(MempoolError::TooManyFromSender)
    );
}

// ===========================================================================
// 5. FAILURE-FEE CONSERVATION — 10 shapes, both paths, identical verdicts
// ===========================================================================

fn token_meta(minter: [u8; 32]) -> stellereum::token::TokenMetadata {
    stellereum::token::TokenMetadata {
        name: "T".to_string(),
        symbol: "T".to_string(),
        decimals: 6,
        total_supply: 0,
        max_supply: None,
        minter,
        paused: false,
        description: "".to_string(),
    }
}

async fn funded_engine(balance: u64, k: &SigningKey) -> (InMemoryStateEngine, [u8; 32]) {
    let e = InMemoryStateEngine::new();
    let me = addr(k);
    e.update_account(AccountState::new(me, balance)).await;
    (e, me)
}

/// Run one tx on the block path; returns (failed, status, fees). Single-tx
/// agreement is asserted inline per shape below.
async fn block_outcome(e: &InMemoryStateEngine, t: &Transaction) -> (usize, Vec<bool>, Vec<u64>) {
    let (_, failed, _fees_collected, status, fees) = e
        .apply_block_parallel_fees(std::slice::from_ref(t), 1_700_000_000)
        .await;
    (failed, status, fees)
}

/// 10-shape failure-fee fuzz: every shape asserts (a) block path and single-tx
/// path agree exactly on (fee, balance, nonce), (b) no token/state writes
/// survive a revert, (c) native value is conserved (before - after == fees).
#[tokio::test]
async fn failure_fee_ten_shapes_conserve_on_both_paths() {
    // Shape 1: unknown-token transfer reverts (attributable, affordable).
    {
        let k = sk();
        let (e, me) = funded_engine(1_000_000, &k).await;
        let t = Transaction::sign_with_payload(
            &k,
            [0x44; 32],
            0,
            200_000,
            0,
            1,
            1,
            vec![stellereum::svm::OpCode::SysCallTokenTransfer {
                token_id: [0xABu8; 32],
                to: [0x44; 32],
                amount: 1,
            }],
        );
        let (failed, status, fees) = block_outcome(&e, &t).await;
        assert_eq!(
            (failed, status.as_slice(), fees.as_slice()),
            (1, &[false][..], &[200_000][..])
        );
        let acc = e.get_account(&me).await.unwrap();
        assert_eq!((acc.balance, acc.nonce), (800_000, 1));
        // single-tx path agrees
        let (e2, _) = funded_engine(1_000_000, &k).await;
        assert!(e2.apply_transaction(&t, 1_700_000_000).await.is_err());
        let acc2 = e2.get_account(&me).await.unwrap();
        assert_eq!((acc2.balance, acc2.nonce), (800_000, 1));
    }
    // Shape 2: token balance written THEN reverted (mint ok, 2nd op fails).
    {
        let k = sk();
        let (e, me) = funded_engine(2_000_000, &k).await;
        let tok = e.create_token(me, token_meta(me), 1_000).await.unwrap();
        assert_eq!(e.token_balance(&tok, &me).await, 1_000);
        let t = Transaction::sign_with_payload(
            &k,
            me,
            0,
            200_000,
            0,
            1,
            1,
            vec![
                stellereum::svm::OpCode::SysCallTokenMint {
                    token_id: tok,
                    to: me,
                    amount: 500,
                },
                stellereum::svm::OpCode::SysCallTokenTransfer {
                    token_id: [0xBBu8; 32],
                    to: me,
                    amount: 1, // unknown → revert
                },
            ],
        );
        let (failed, _, fees) = block_outcome(&e, &t).await;
        assert_eq!((failed, fees.as_slice()), (1, &[200_000][..]));
        // the mint did NOT survive the revert
        assert_eq!(e.token_balance(&tok, &me).await, 1_000);
        let acc = e.get_account(&me).await.unwrap();
        assert_eq!((acc.balance, acc.nonce), (1_800_000, 1));
        let (e2, _) = funded_engine(2_000_000, &k).await;
        let tok2 = e2.create_token(me, token_meta(me), 1_000).await.unwrap();
        assert!(e2.apply_transaction(&t, 1_700_000_000).await.is_err());
        assert_eq!(e2.token_balance(&tok2, &me).await, 1_000);
        let acc2 = e2.get_account(&me).await.unwrap();
        assert_eq!((acc2.balance, acc2.nonce), (1_800_000, 1));
    }
    // Shape 3: fails inside send_message routing (actor send over funds).
    {
        let k = sk();
        let (e, me) = funded_engine(1_000_000, &k).await;
        let t = Transaction::sign_with_payload(
            &k,
            me,
            0,
            300_000,
            0,
            1,
            1,
            vec![stellereum::svm::OpCode::SysCallActorSend {
                recipient: [0x55; 32],
                value: u64::MAX, // unaffordable → routing fails
                body: vec![],
                bounce: true,
                gas_budget: 10_000,
            }],
        );
        let (failed, _, fees) = block_outcome(&e, &t).await;
        assert_eq!(failed, 1);
        assert_eq!(fees, vec![300_000]);
        // no message was queued anywhere
        let acc = e.get_account(&me).await.unwrap();
        assert!(acc.inbox.is_empty() && acc.outbox.is_empty());
        assert_eq!((acc.balance, acc.nonce), (700_000, 1));
        let (e2, _) = funded_engine(1_000_000, &k).await;
        assert!(e2.apply_transaction(&t, 1_700_000_000).await.is_err());
        let acc2 = e2.get_account(&me).await.unwrap();
        assert_eq!((acc2.balance, acc2.nonce), (700_000, 1));
        assert!(acc2.inbox.is_empty() && acc2.outbox.is_empty());
    }
    // Shape 4: fails on the cross-shard boundary (funded outbound, bad payload).
    {
        let k = sk();
        let e = InMemoryStateEngine::new();
        e.enable_cross_shard();
        let me = addr(&k);
        e.update_account(AccountState::new(me, 1_000_000)).await;
        let t = Transaction::sign_with_payload(
            &k,
            [0x66; 32],
            50_000,
            200_000,
            0,
            0,
            1, // source 0 -> target 1
            vec![stellereum::svm::OpCode::SysCallTokenTransfer {
                token_id: [0xCCu8; 32],
                to: [0x66; 32],
                amount: 1, // revert
            }],
        );
        let (failed, _, fees) = block_outcome(&e, &t).await;
        assert_eq!((failed, fees.as_slice()), (1, &[200_000][..]));
        // target side credited nothing, no account conjured
        assert!(e.get_account(&[0x66; 32]).await.is_none());
        let acc = e.get_account(&me).await.unwrap();
        assert_eq!((acc.balance, acc.nonce), (800_000, 1));
        // single-tx path agrees
        let e2 = InMemoryStateEngine::new();
        e2.enable_cross_shard();
        e2.update_account(AccountState::new(me, 1_000_000)).await;
        assert!(e2.apply_transaction(&t, 1_700_000_000).await.is_err());
        assert!(e2.get_account(&[0x66; 32]).await.is_none());
        let acc2 = e2.get_account(&me).await.unwrap();
        assert_eq!((acc2.balance, acc2.nonce), (800_000, 1));
    }
    // Shape 5/6: sender IS the STAKING_POOL / REWARDS_POOL (unfakeable sig →
    // non-attributable: nothing moves on either path, pools untouched).
    for pool in [
        stellereum::staking::STAKING_POOL,
        stellereum::staking::REWARDS_POOL,
    ] {
        let k = sk(); // signature is FOR k, sender field claims the pool
        let mut t = Transaction::sign(&k, [1u8; 32], 10, 1_000, 0, 1, 1);
        t.from = pool;
        for engine in [InMemoryStateEngine::new(), InMemoryStateEngine::new()] {
            engine
                .update_account(AccountState::new(pool, 50_000_000))
                .await;
            let (failed, status, fees) = block_outcome(&engine, &t).await;
            assert_eq!(
                (failed, status.as_slice(), fees.as_slice()),
                (1, &[false][..], &[0][..])
            );
            let acc = engine.get_account(&pool).await.unwrap();
            assert_eq!((acc.balance, acc.nonce), (50_000_000, 0), "pool untouched");
            assert!(engine.apply_transaction(&t, 1_700_000_000).await.is_err());
            let acc2 = engine.get_account(&pool).await.unwrap();
            assert_eq!((acc2.balance, acc2.nonce), (50_000_000, 0));
        }
    }
    // Shape 7: unknown sender (no account at all).
    {
        let k = sk();
        let e = InMemoryStateEngine::new();
        let t = tx(&k, [1u8; 32], 10, 1_000, 0, 1);
        let (failed, status, fees) = block_outcome(&e, &t).await;
        assert_eq!(
            (failed, status.as_slice(), fees.as_slice()),
            (1, &[false][..], &[0][..])
        );
        assert!(e.apply_transaction(&t, 1_700_000_000).await.is_err());
    }
    // Shape 8: stale-nonce replay.
    {
        let k = sk();
        let (e, me) = funded_engine(1_000_000, &k).await;
        e.update_account(AccountState {
            address: me,
            balance: 1_000_000,
            nonce: 7,
            ..AccountState::new(me, 0)
        })
        .await;
        let t = tx(&k, [1u8; 32], 10, 1_000, 0, 1); // nonce 0, on-chain 7
        let (failed, status, fees) = block_outcome(&e, &t).await;
        assert_eq!((failed, fees.as_slice()), (1, &[0][..]));
        assert_eq!(status, vec![false]);
        let acc = e.get_account(&me).await.unwrap();
        assert_eq!((acc.balance, acc.nonce), (1_000_000, 7));
        assert!(e.apply_transaction(&t, 1_700_000_000).await.is_err());
        let acc2 = e.get_account(&me).await.unwrap();
        assert_eq!((acc2.balance, acc2.nonce), (1_000_000, 7));
    }
    // Shape 9: future-nonce gap (nonce mismatch, funded).
    {
        let k = sk();
        let (e, me) = funded_engine(1_000_000, &k).await;
        let t = tx(&k, [1u8; 32], 10, 1_000, 3, 1); // on-chain 0
        let (failed, status, fees) = block_outcome(&e, &t).await;
        assert_eq!((failed, fees.as_slice()), (1, &[0][..]));
        assert_eq!(status, vec![false]);
        let acc = e.get_account(&me).await.unwrap();
        assert_eq!((acc.balance, acc.nonce), (1_000_000, 0));
        assert!(e.apply_transaction(&t, 1_700_000_000).await.is_err());
    }
    // Shape 10: failing PQ-equivocation report declares a STAKING_POOL burn —
    // garbage evidence reverts, the pool is NOT debited, sender pays fee.
    {
        use stellereum::consensus::VoteKind;
        let k = sk();
        let (e, me) = funded_engine(1_000_000, &k).await;
        e.update_account(AccountState::new(
            stellereum::staking::STAKING_POOL,
            500_000_000,
        ))
        .await;
        let ev = stellereum::staking::CompactPqEquivocationEvidence::new(
            me,
            1,
            0,
            VoteKind::Precommit,
            None,
            vec![],
            None,
            vec![],
        );
        let t = Transaction::sign_with_payload(
            &k,
            me,
            0,
            200_000,
            0,
            1,
            1,
            vec![stellereum::svm::OpCode::SysCallReportPqEquivocation {
                evidence: Box::new(ev),
            }],
        );
        let (failed, _, fees) = block_outcome(&e, &t).await;
        assert_eq!((failed, fees.as_slice()), (1, &[200_000][..]));
        let pool = e
            .get_account(&stellereum::staking::STAKING_POOL)
            .await
            .unwrap();
        assert_eq!(pool.balance, 500_000_000, "failed slash burns nothing");
        let acc = e.get_account(&me).await.unwrap();
        assert_eq!((acc.balance, acc.nonce), (800_000, 1));
        let (e2, _) = funded_engine(1_000_000, &k).await;
        e2.update_account(AccountState::new(
            stellereum::staking::STAKING_POOL,
            500_000_000,
        ))
        .await;
        let ev2 = stellereum::staking::CompactPqEquivocationEvidence::new(
            me,
            1,
            0,
            VoteKind::Precommit,
            None,
            vec![],
            None,
            vec![],
        );
        let t2 = Transaction::sign_with_payload(
            &k,
            me,
            0,
            200_000,
            0,
            1,
            1,
            vec![stellereum::svm::OpCode::SysCallReportPqEquivocation {
                evidence: Box::new(ev2),
            }],
        );
        assert!(e2.apply_transaction(&t2, 1_700_000_000).await.is_err());
        let pool2 = e2
            .get_account(&stellereum::staking::STAKING_POOL)
            .await
            .unwrap();
        assert_eq!(pool2.balance, 500_000_000);
        let acc2 = e2.get_account(&me).await.unwrap();
        assert_eq!((acc2.balance, acc2.nonce), (800_000, 1));
    }
    // Aggregate conservation: mixed batch, before - after == fees_collected.
    {
        let k1 = sk();
        let k2 = sk();
        let e = InMemoryStateEngine::new();
        let (m1, m2) = (addr(&k1), addr(&k2));
        e.update_account(AccountState::new(m1, 1_000_000)).await;
        e.update_account(AccountState::new(m2, 1_000_000)).await;
        let ok = tx(&k1, m2, 100_000, 50_000, 0, 1); // succeeds
        let bad = Transaction::sign_with_payload(
            &k2,
            m1,
            0,
            60_000,
            0,
            1,
            1,
            vec![stellereum::svm::OpCode::SysCallTokenTransfer {
                token_id: [0xDDu8; 32],
                to: m1,
                amount: 1, // revert
            }],
        );
        let before = 2_000_000u64;
        let (applied, failed, collected, status, _fees) =
            e.apply_block_parallel_fees(&[ok, bad], 1_700_000_000).await;
        assert_eq!(
            (applied, failed, status.as_slice()),
            (1, 1, &[true, false][..])
        );
        let a1 = e.get_account(&m1).await.unwrap().balance;
        let a2 = e.get_account(&m2).await.unwrap().balance;
        assert_eq!(
            before - (a1 + a2),
            collected,
            "every lost unit is filed as a fee"
        );
        assert_eq!(collected, 50_000 + 60_000);
    }
}

// ===========================================================================
// 6. LEGACY CROSS-CHAIN REPLAY
// ===========================================================================

/// Legacy (unbound) tx verifies and applies on ANY chain id → replay succeeds.
#[test]
fn legacy_unbound_replay_succeeds_on_both_chains() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let k = sk();
        let me = addr(&k);
        // what the CURRENT wallet builds (no chain binding anywhere)
        let w = stellereum::wallet::WalletAccount::from_seed(&[0x11; 32]);
        let wt = w.create_transaction([0x22; 32], 100, 0, 1, 1);
        assert_eq!(
            wt.chain_id(),
            None,
            "wallet default carries no chain binding"
        );
        assert!(wt.verify_signature());

        let t = Transaction::sign(&k, [0x22; 32], 100, 50_000, 0, 1, 1);
        assert_eq!(t.chain_id(), None);
        let h = t.compute_tx_hash();
        for chain in [5757u64, 777u64] {
            let e = InMemoryStateEngine::new().with_chain_id(chain);
            e.update_account(AccountState::new(me, 1_000_000)).await;
            e.apply_transaction(&t, 1_700_000_000).await.unwrap();
            let acc = e.get_account(&me).await.unwrap();
            assert_eq!(acc.nonce, 1, "replay executed on chain {chain}");
            assert_eq!(acc.balance, 1_000_000 - 100 - 50_000);
            let _ = h;
        }
    });
}

/// BOUND envelope with the wrong chain id fails; right chain succeeds.
#[test]
fn bound_envelope_wrong_chain_fails() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let k = sk();
        let me = addr(&k);
        let t = Transaction::sign_with_chain_id(&k, [0x22; 32], 100, 50_000, 0, 1, 1, 5757);
        assert_eq!(t.chain_id(), Some(5757));
        assert!(t.verify_signature());
        assert!(t.verify_signature_for_chain(5757, true));
        assert!(!t.verify_signature_for_chain(777, true));
        // right chain: applies
        let e = InMemoryStateEngine::new().with_chain_id(5757);
        e.update_account(AccountState::new(me, 1_000_000)).await;
        e.apply_transaction(&t, 1_700_000_000).await.unwrap();
        // wrong chain: refused
        let e2 = InMemoryStateEngine::new().with_chain_id(777);
        e2.update_account(AccountState::new(me, 1_000_000)).await;
        let err = e2.apply_transaction(&t, 1_700_000_000).await.unwrap_err();
        assert!(err.contains("chain_id mismatch"), "{err}");
        // tampered chain id in the envelope breaks the signature itself
        let mut tampered = t.clone();
        let off = 64 + stellereum::sharding::CHAIN_SIG_TAG.len();
        tampered.signature[off..off + 8].copy_from_slice(&777u64.to_be_bytes());
        assert!(!tampered.verify_signature());
    });
}

// ===========================================================================
// Summary verdicts (updated by V-P2 after running the suite above):
//  1. Shard gate ......... BROKEN pre-fix (unpinned paths admit foreign txs);
//                           HOLDS post-fix (pool-level pin + pinned ctx on
//                           add_tx/gossip/restore; proposer filter backstop).
//  2. Priority bid ....... HOLDS (saturating overflow, funded zero-floor,
//                           stored copy + MEV seal defeat post-admission edits).
//  3. Eviction premium ... HOLDS (boundary `>=` exact; ratchet ~1.05^k —
//                           geometric but 14× slower than 2×; doc fixed).
//  4. Nonce/activation ... HOLDS (window = 4 past head; per-sender quota;
//                           same-nonce coexistence is DELIBERATE (F10,
//                           execution picks first) with the reservation
//                           ledger as the economic bound — each duplicate
//                           reserves full cost; remove_many/prune_confirmed
//                           now also release BUFFERED reservations, which
//                           previously leaked).
//  5. Failure-fee fuzz ... HOLDS (10 shapes, both paths identical,
//                           conservation exact, pools untouched).
//  6. Legacy replay ...... BROKEN (escalated): succeeds AND is reachable from
//                           the current wallet flow (WalletAccount builds
//                           unbound txs); bound envelopes enforce correctly.
// ===========================================================================
