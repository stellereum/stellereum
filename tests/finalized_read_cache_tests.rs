//! Finalized-read cache: latency probe + soundness gates.
//!
//! The cache (see `stellereum::rpc`) keys finalized reads by
//! `(method, height, params-hash)`. This file first MEASURES per-method
//! latency on a fixed workload so the cached set is picked on numbers, then
//! pins the soundness rules:
//!
//! * cached responses are byte-identical to fresh ones;
//! * unfinalized churn (mempool admissions) never changes a finalized key;
//! * height advance invalidates (miss, then identical bytes), new heights
//!   serve fresh;
//! * a late adopted body evicts the height it upgrades (no stale `txs: 0`);
//! * live / tip-relative / mempool-dependent / error responses bypass;
//! * growth is bounded by the const cap with fail-closed eviction;
//! * TTL expiry recomputes identical bytes.
//!
//! All tests in this binary serialize on `TEST_LOCK`: the finalized-header
//! window and the cache are process-wide, so assertions on exact hit/miss
//! deltas must not interleave.

use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Instant;

use stellereum::consensus::{QuorumCertificate, Vote, VoteKind};
use stellereum::mempool::{AdmissionCtx, Mempool};
use stellereum::rpc::{ReceiptIndex, RpcState};
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

static TEST_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

fn test_keys() -> Vec<ed25519_dalek::SigningKey> {
    (0..4)
        .map(|i| ed25519_dalek::SigningKey::from_bytes(&[(i as u8) + 1; 32]))
        .collect()
}

fn test_state(tip: u64) -> Arc<RpcState> {
    let engine = Arc::new(InMemoryStateEngine::new());
    Arc::new(RpcState {
        engine,
        mempool: Arc::new(tokio::sync::RwLock::new(Mempool::default())),
        height: Arc::new(std::sync::atomic::AtomicU64::new(tip)),
        node_id: "inf1:cache-probe".to_string(),
        chain_id: 777,
        staking: Arc::new(tokio::sync::RwLock::new(
            stellereum::staking::StakingLedger::new(),
        )),
        governance: Arc::new(tokio::sync::RwLock::new(
            stellereum::governance::Governance::new(),
        )),
        recent_blocks: Arc::new(tokio::sync::RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(tokio::sync::RwLock::new(ReceiptIndex::default())),
        auth_token: None,
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        archive_store: None,
        msg_signing_seed: None,
        shard_registry: stellereum::sharding::ShardRegistry::single(),
    })
}

fn qc_for(
    signers: &[ed25519_dalek::SigningKey],
    height: u64,
    hash: [u8; 32],
) -> QuorumCertificate {
    let signatures = signers
        .iter()
        .map(|k| {
            let v = Vote::sign(k, height, 0, VoteKind::Precommit, Some(hash));
            (v.voter, v.signature)
        })
        .collect();
    QuorumCertificate {
        height,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(hash),
        signatures,
    }
}

fn block_hash_of(h: u64, tag: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&h.to_be_bytes());
    b[8] = tag;
    b
}

/// Publish height `h` in production order: receipts first, then the block
/// summary (the order RPC readers depend on), then the finalized header.
async fn publish_height(st: &Arc<RpcState>, ks: &[ed25519_dalek::SigningKey], h: u64, ntx: u64) {
    let bh = block_hash_of(h, 0xB0);
    let mut txs = Vec::new();
    for i in 0..ntx {
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&h.to_be_bytes());
        seed[8..16].copy_from_slice(&i.to_be_bytes());
        seed[16] = 0xC4;
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let mut to = [0u8; 32];
        to[..8].copy_from_slice(&i.to_be_bytes());
        txs.push(stellereum::sharding::Transaction::sign(
            &sk, to, 1_000 + i, 21_000, i, 0, 0,
        ));
    }
    let statuses = vec![true; txs.len()];
    let fees = vec![21_000u64; txs.len()];
    st.record_receipts(h, bh, &txs, &statuses, &fees).await;
    st.record_block(h, bh, txs.len(), 1_700_000_000 + h).await;
    let mut b = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: h,
        prev_hash: if h == 0 { [0u8; 32] } else { block_hash_of(h - 1, 0xB0) },
        state_root: [(h % 251) as u8; 32],
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1_700_000_000 + h,
        proposer: ks[0].verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    let fbh = b.compute_hash();
    b.precommit_qc = Some(qc_for(&ks[..3], h, fbh));
    st.record_finalized_header(&b).await;
    st.height
        .store(h, std::sync::atomic::Ordering::Relaxed);
}

fn stats() -> (usize, u64, u64) {
    stellereum::rpc::finalized_read_cache_stats()
}

async fn time_calls(st: &Arc<RpcState>, method: &str, params: Value, iters: usize) -> (f64, f64) {
    for _ in 0..5 {
        let _ = st.call(method, params.clone()).await;
    }
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t = Instant::now();
        let _ = st.call(method, params.clone()).await;
        samples.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    (samples[samples.len() / 2], samples.iter().sum::<f64>() / samples.len() as f64)
}

fn probe_addr(i: u64) -> String {
    let mut a = [0u8; 32];
    a[..8].copy_from_slice(&i.to_be_bytes());
    a[8] = 0xA0;
    hex::encode(a)
}

fn probe_val(i: u64) -> String {
    let mut v = [0u8; 32];
    v[..8].copy_from_slice(&i.to_be_bytes());
    v[8] = 0xBE;
    hex::encode(v)
}

/// Fixed workload: 101 blocks in the recent window, 1000 receipts over 20
/// heights, 129 finalized headers (epoch 8: 1024..=1151 + boundary 1152),
/// 200 funded accounts, 50 validators.
async fn fixed_workload() -> Arc<RpcState> {
    let st = test_state(1000);
    for h in 900u64..=1000 {
        st.record_block(h, block_hash_of(h, 0xB0), ((h % 7) as usize) + 1, 1_700_000_000 + h)
            .await;
    }
    for h in 980u64..1000 {
        let mut txs = Vec::new();
        for i in 0u64..50 {
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&h.to_be_bytes());
            seed[8..16].copy_from_slice(&i.to_be_bytes());
            let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
            let mut to = [0u8; 32];
            to[..8].copy_from_slice(&i.to_be_bytes());
            txs.push(stellereum::sharding::Transaction::sign(
                &sk, to, 1_000_000_000, 21_000, i, 0, 0,
            ));
        }
        let statuses = vec![true; 50];
        let fees = vec![21_000u64; 50];
        st.record_receipts(h, block_hash_of(h, 0xB0), &txs, &statuses, &fees)
            .await;
    }
    let ks = test_keys();
    for h in 1024u64..=1152 {
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: h,
            prev_hash: block_hash_of(h.saturating_sub(1), 0xB0),
            state_root: [(h % 251) as u8; 32],
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 1_700_000_000 + h,
            proposer: ks[0].verifying_key().to_bytes(),
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
        };
        let bh = b.compute_hash();
        b.precommit_qc = Some(qc_for(&ks[..3], h, bh));
        st.record_finalized_header(&b).await;
    }
    st.height
        .store(1152, std::sync::atomic::Ordering::Relaxed);
    for i in 0u64..200 {
        let mut a = [0u8; 32];
        a[..8].copy_from_slice(&i.to_be_bytes());
        a[8] = 0xA0;
        st.engine
            .update_account(AccountState::new(a, 1_000_000_000 + i))
            .await;
    }
    {
        let mut ledger = st.staking.write().await;
        for i in 0u64..50 {
            let mut v = [0u8; 32];
            v[..8].copy_from_slice(&i.to_be_bytes());
            v[8] = 0xBE;
            ledger.validators.insert(
                v,
                stellereum::staking::ValidatorStake {
                    self_bond: 10_000_000_000 + i,
                    delegated: 1_000_000,
                    commission_bps: 500,
                    pending_rewards: 0,
                    total_slashed: 0,
                    missed: 0,
                    last_downtime_penalty: 0,
                },
            );
        }
    }
    st
}

#[tokio::test]
async fn finalized_read_latency_probe() {
    let _g = TEST_LOCK.lock().await;
    let st = fixed_workload().await;
    let tip = st.height.load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(tip, 1152);
    let h = json!({ "height": 990u64 });
    let fh = json!({ "height": 1100u64 });

    let receipt_hash = {
        let idx = st.receipts.read().await;
        let r = idx.values().next().expect("receipts present").clone();
        hex::encode(r.tx_hash)
    };

    let cases: Vec<(&str, Value)> = vec![
        ("stell_getBlock", h.clone()),
        ("stell_getBlockTransactions", h.clone()),
        ("stell_getFinalizedHeader", fh.clone()),
        ("stell_getEpochRoot", json!({ "epoch": 8u64 })),
        ("stell_getBalance", json!(probe_addr(7))),
        ("stell_getBalanceSpv", json!({ "address": probe_addr(7) })),
        ("stell_getProof", json!({ "address": probe_addr(7) })),
        ("stell_getValidators", json!({})),
        ("stell_stakeOf", json!({ "validator": probe_val(3) })),
        (
            "stell_getTransactionReceipt",
            json!({ "hash": receipt_hash.clone() }),
        ),
        (
            "stell_getTransactionStatus",
            json!({ "hash": receipt_hash.clone() }),
        ),
    ];
    eprintln!("=== finalized-read latency probe (200 iters, ms) ===");
    for (m, p) in &cases {
        let (med, mean) = time_calls(&st, m, p.clone(), 200).await;
        eprintln!("probe {m:32} median={med:.4}ms mean={mean:.4}ms");
    }
    eprintln!("=== end probe ===");
}

/// Soundness: byte-identical cached vs fresh; unfinalized churn changes
/// nothing; height advance invalidates; late adopt evicts; TTL expiry
/// recomputes identical bytes. Uses heights 4000..4011 and epoch 40
/// (5120..=5247 + boundary 5248) — unique to this test.
#[tokio::test]
async fn finalized_read_cache_soundness_and_invalidation() {
    let _g = TEST_LOCK.lock().await;
    let ks = test_keys();
    let st = test_state(4000);
    for h in 4000u64..=4010 {
        publish_height(&st, &ks, h, 3).await;
    }
    // Full epoch 40 plus its boundary commitment, then pin the tip there.
    for h in 5120u64..=5248 {
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: h,
            prev_hash: [0x51u8; 32],
            state_root: [(h % 251) as u8; 32],
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 1_700_000_000 + h,
            proposer: ks[0].verifying_key().to_bytes(),
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
        };
        let bh = b.compute_hash();
        b.precommit_qc = Some(qc_for(&ks[..3], h, bh));
        st.record_finalized_header(&b).await;
    }
    st.height
        .store(5248, std::sync::atomic::Ordering::Relaxed);

    let block_p = json!({ "height": 4005u64 });
    let blocktx_p = json!({ "height": 4005u64 });
    let header_p = json!({ "height": 5200u64 });
    let epoch_p = json!({ "epoch": 40u64 });

    // 1. Fill: first call misses, second call hits, bytes identical.
    for (m, p) in [
        ("stell_getBlock", &block_p),
        ("stell_getBlockTransactions", &blocktx_p),
        ("stell_getFinalizedHeader", &header_p),
        ("stell_getEpochRoot", &epoch_p),
    ] {
        let (l0, h0, m0) = stats();
        let first = st.call(m, p.clone()).await;
        assert!(first.get("error").is_none(), "{m} must serve: {first}");
        if m == "stell_getEpochRoot" {
            assert_eq!(first["complete"], true, "epoch 40 must be complete");
            assert!(first["committed_root"].is_string(), "boundary must commit");
        }
        let (l1, h1, m1) = stats();
        assert_eq!((h1, m1), (h0, m0 + 1), "{m}: first call must miss");
        assert!(l1 >= l0, "fill must not shrink the cache");
        let second = st.call(m, p.clone()).await;
        let (l2, h2, m2) = stats();
        assert_eq!((h2, m2), (h1 + 1, m1), "{m}: second call must hit");
        assert_eq!(l2, l1, "{m}: hit must not grow the cache");
        assert_eq!(first, second, "{m}: cached must be byte-identical to fresh");
    }

    // 2. Unfinalized churn: admit 20 pending txs; finalized keys unchanged.
    // (Pure-PQ mode: classical signatures are rejected at admission, so the
    // churn uses PQ1 explicit-envelope transfers — the same shape the faucet
    // builds.)
    {
        let pq_key =
            stellereum::post_quantum::FalconKeypair::generate_from_seed_bytes(&[0x77u8; 32]);
        let sender = stellereum::post_quantum::derive_pq_address(
            stellereum::post_quantum::PqScheme::Falcon512,
            &pq_key.public_key,
            &stellereum::post_quantum::DEFAULT_SALT,
        );
        st.engine
            .update_account(AccountState::new(sender, 1_000_000_000_000))
            .await;
        let mut pool = st.mempool.write().await;
        for n in 0u64..20 {
            let tx = stellereum::rpc::sign_pq_explicit_transfer(
                &pq_key,
                [0x99u8; 32],
                1_000,
                stellereum::svm::GAS_BASIC_TRANSFER
                    + stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS,
                n,
                0,
                0,
            );
            pool
                .add_checked_ctx(tx, 1_000_000_000_000, AdmissionCtx::wall_now())
                .expect("churn admission must succeed");
        }
    }
    for (m, p) in [
        ("stell_getBlock", &block_p),
        ("stell_getBlockTransactions", &blocktx_p),
        ("stell_getFinalizedHeader", &header_p),
        ("stell_getEpochRoot", &epoch_p),
    ] {
        let before = st.call(m, p.clone()).await;
        let (hb1, mb1) = (stats().1, stats().2);
        stellereum::rpc::finalized_read_cache_expire_all_for_tests();
        let fresh = st.call(m, p.clone()).await;
        let (hb2, mb2) = (stats().1, stats().2);
        assert_eq!((hb2, mb2), (hb1, mb1 + 1), "{m}: expiry must miss");
        assert_eq!(
            before, fresh,
            "{m}: unfinalized churn must not change a finalized key"
        );
    }

    // 3. TTL expiry recomputes identical bytes (and re-admits the key).
    // NOTE: step 2 expired every key on its last iteration, so refill first.
    {
        let cached = st.call("stell_getBlock", block_p.clone()).await;
        let (l0, h0, m0) = stats();
        let cached2 = st.call("stell_getBlock", block_p.clone()).await;
        let (_, h1, _) = stats();
        assert!(h1 > h0, "must hit before expiry");
        assert_eq!(cached, cached2, "hit must be byte-identical");
        stellereum::rpc::finalized_read_cache_expire_all_for_tests();
        let recomputed = st.call("stell_getBlock", block_p.clone()).await;
        let (l2, h2, m2) = stats();
        assert_eq!(cached, recomputed, "TTL expiry must recompute identical bytes");
        assert_eq!(h2, h1, "expiry must miss, not hit");
        assert!(m2 > m0, "expiry must count a miss");
        assert_eq!(l2, l0, "expiry must re-admit under the same key");
    }

    // 4. Height advance invalidates (miss) but serves identical bytes; the
    // new height serves fresh and then caches.
    {
        publish_height(&st, &ks, 5249, 2).await;
        let tip = st.height.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(tip, 5249);
        let (l0, h0, m0) = stats();
        let after = st.call("stell_getBlock", block_p.clone()).await;
        let (l1, h1, m1) = stats();
        assert_eq!((h1, m1), (h0, m0 + 1), "advance must invalidate (miss)");
        assert!(
            l1 <= stellereum::rpc::FINALIZED_READ_CACHE_CAP,
            "refill must stay bounded"
        );
        let _ = l0;
        // Refill is a real cache entry: the next call hits byte-identical.
        let again = st.call("stell_getBlock", block_p.clone()).await;
        let (_, h1b, _) = stats();
        assert_eq!(after, again, "post-advance bytes must be stable");
        assert!(h1b > h1, "refill must hit");
        let fresh = {
            stellereum::rpc::finalized_read_cache_expire_all_for_tests();
            st.call("stell_getBlock", block_p.clone()).await
        };
        assert_eq!(after, fresh, "post-advance bytes must match fresh");
        // New height: miss then hit.
        let new_p = json!({ "height": 5249u64 });
        let r1 = st.call("stell_getFinalizedHeader", new_p.clone()).await;
        assert!(r1.get("error").is_none(), "new header must serve");
        let r2 = st.call("stell_getFinalizedHeader", new_p.clone()).await;
        assert_eq!(r1, r2, "new height must cache");
        let (_, h3, _) = stats();
        assert!(h3 > h1, "new height second call must hit");
    }

    // 5. Late adopted body evicts: publish txs=0, cache it, adopt the body.
    // Uses fresh height 4020 (never published above): no prior receipts, so
    // the adopted body of exactly 2 txs is the whole answer.
    {
        let h = 4020u64;
        let bh = block_hash_of(h, 0xAD);
        st.record_block(h, bh, 0, 1_700_000_111).await;
        let bp = json!({ "height": h });
        let empty = st.call("stell_getBlock", bp.clone()).await;
        assert_eq!(empty["txs"], 0);
        let (l0, h0, m0) = stats();
        let _ = st.call("stell_getBlock", bp.clone()).await;
        let (_, h1, _) = stats();
        assert!(h1 > h0, "empty-but-known block must cache");
        // The body arrives late via adopt (same hash, real txs).
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0xABu8; 32]);
        let txs = vec![
            stellereum::sharding::Transaction::sign(&sk, [0x01u8; 32], 5, 21_000, 0, 0, 0),
            stellereum::sharding::Transaction::sign(&sk, [0x02u8; 32], 6, 21_000, 1, 0, 0),
        ];
        st.record_adopted_block(h, bh, &txs, &[true, true], &[21_000, 21_000], 1_700_000_222)
            .await;
        let upgraded = st.call("stell_getBlock", bp.clone()).await;
        let (_, h2, m2) = stats();
        assert_eq!(upgraded["txs"], 2, "adopt must upgrade the summary");
        assert!(upgraded["timestamp"] != empty["timestamp"]);
        assert!(m2 > m0, "adopt must evict (miss)");
        assert_eq!(h2, h1, "adopt must evict (no hit)");
        let _ = l0;
        // Block transactions: empty answers are never cached, the filed
        // answer is cached and correct.
        let btp = json!({ "height": h });
        let filed = st.call("stell_getBlockTransactions", btp.clone()).await;
        assert_eq!(filed["txs"].as_array().unwrap().len(), 2);
        let r2 = st.call("stell_getBlockTransactions", btp.clone()).await;
        assert_eq!(filed, r2, "filed block txs must cache byte-identical");
    }

    // 6. Errors never cache: unknown-but-finalized height + above-tip height.
    {
        let (l0, _, m0) = stats();
        let miss_p = json!({ "height": 3999u64 });
        let e1 = st.call("stell_getBlock", miss_p.clone()).await;
        assert!(e1.get("error").is_some(), "unknown height must error");
        let e2 = st.call("stell_getBlock", miss_p.clone()).await;
        assert_eq!(e1, e2, "errors must be deterministic");
        let (l1, _, m1) = stats();
        assert_eq!(l1, l0, "errors must never fill the cache");
        assert_eq!(m1, m0 + 2, "errors must always miss");
        let above_p = json!({ "height": 999_999u64 });
        let (l2, h2, m2) = stats();
        let ea = st.call("stell_getBlock", above_p.clone()).await;
        assert!(ea.get("error").is_some(), "above-tip must error");
        let (l3, h3, m3) = stats();
        assert_eq!((l3, h3, m3), (l2, h2, m2), "above-tip must bypass entirely");
    }

    // 7. Incomplete epoch never fills (lookups miss, nothing cached).
    {
        let (l0, h0, m0) = stats();
        let inc_p = json!({ "epoch": 41u64 });
        let i1 = st.call("stell_getEpochRoot", inc_p.clone()).await;
        assert!(i1.get("error").is_some() || i1["complete"] == false);
        let i2 = st.call("stell_getEpochRoot", inc_p.clone()).await;
        assert_eq!(i1, i2);
        let (l1, h1, m1) = stats();
        assert_eq!((l1, h1), (l0, h0), "incomplete epoch must never fill");
        assert_eq!(m1, m0 + 2, "incomplete epoch must always miss");
    }
}

/// Live / tip-relative / mempool-dependent / error reads bypass the cache
/// always: same-tip state changes are served fresh, and the cache counters
/// do not move.
#[tokio::test]
async fn finalized_read_cache_live_reads_bypass() {
    let _g = TEST_LOCK.lock().await;
    let st = test_state(700);
    let mut a = [0u8; 32];
    a[0] = 0xBA;
    st.engine.update_account(AccountState::new(a, 500)).await;
    let addr = hex::encode(a);
    st.record_block(700, block_hash_of(700, 0xB0), 0, 1_700_000_700).await;

    // Balance / Spv / proof / validators: fresh after a same-tip mutation.
    let b1 = st.call("stell_getBalance", json!(addr.clone())).await;
    assert_eq!(b1["balance"], "500");
    st.engine.update_account(AccountState::new(a, 999)).await;
    let (l0, h0, m0) = stats();
    let b2 = st.call("stell_getBalance", json!(addr.clone())).await;
    let b3 = st.call("stell_getBalanceSpv", json!({ "address": addr.clone() })).await;
    let b4 = st.call("stell_getProof", json!({ "address": addr.clone() })).await;
    let b5 = st.call("stell_getValidators", json!({})).await;
    let b6 = st.call("stell_stakeOf", json!({ "validator": probe_val(3) })).await;
    let (l1, h1, m1) = stats();
    assert_eq!(b2["balance"], "999", "balance must track same-tip writes");
    assert_eq!((l1, h1, m1), (l0, h0, m0), "live reads must bypass entirely");
    assert_eq!(b3["balance"], "999");
    assert_eq!(b4["balance"], 999);
    assert!(b5.get("error").is_none());
    assert!(b6.get("error").is_none());
    // Unknown-but-finalized height: lookup misses (unavoidable — absence is
    // only known after looking), but nothing is ever filled.
    let (l2, h2, m2) = stats();
    let b7 = st.call("stell_getBlock", json!({ "height": 699u64 })).await;
    let (l3, h3, m3) = stats();
    assert!(b7.get("error").is_some(), "unknown height must error");
    assert_eq!((l3, h3), (l2, h2), "errors must never fill the cache");
    assert_eq!(m3, m2 + 1, "absent key must miss");

    // Mempool-dependent status: unknown -> pending, always fresh, uncached.
    let pq_key = stellereum::post_quantum::FalconKeypair::generate_from_seed_bytes(&[0xD0u8; 32]);
    let tx = stellereum::rpc::sign_pq_explicit_transfer(
        &pq_key,
        [0xEEu8; 32],
        1,
        stellereum::svm::GAS_BASIC_TRANSFER + stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS,
        0,
        0,
        0,
    );
    let th = hex::encode(tx.compute_tx_hash());
    let s1 = st
        .call("stell_getTransactionStatus", json!({ "hash": th.clone() }))
        .await;
    assert_eq!(s1["status"], "unknown");
    st.engine
        .update_account(AccountState::new(
            stellereum::post_quantum::derive_pq_address(
                stellereum::post_quantum::PqScheme::Falcon512,
                &pq_key.public_key,
                &stellereum::post_quantum::DEFAULT_SALT,
            ),
            10_000_000,
        ))
        .await;
    st.mempool
        .write()
        .await
        .add_checked_ctx(tx, 10_000_000, AdmissionCtx::wall_now())
        .expect("admission must succeed");
    let (l2, h2, m2) = stats();
    let s2 = st
        .call("stell_getTransactionStatus", json!({ "hash": th.clone() }))
        .await;
    let s3 = st
        .call("stell_getTransactionReceipt", json!({ "hash": th.clone() }))
        .await;
    let (l3, h3, m3) = stats();
    assert_eq!(s2["status"], "pending", "mempool admission must show");
    assert_eq!((l3, h3, m3), (l2, h2, m2), "pending reads must bypass");
    assert!(s3.get("error").is_some() || s3["status"] == "pending");
}

/// Bounded growth: 550+ distinct finalized keys stay within the const cap,
/// fail-closed eviction keeps every key serving correct bytes.
#[tokio::test]
async fn finalized_read_cache_bounded_growth() {
    let _g = TEST_LOCK.lock().await;
    let ks = test_keys();
    let st = test_state(6000);
    // 100 blocks with 2 receipts each (production order) + 100 block-tx keys.
    for h in 6000u64..6100 {
        publish_height(&st, &ks, h, 2).await;
    }
    // 350 finalized headers -> 350 header keys. Epoch 55 (7040..7167) is
    // fully covered plus its boundary 7168, so one epoch key joins too.
    for h in 7000u64..=7350 {
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: h,
            prev_hash: [0x70u8; 32],
            state_root: [(h % 251) as u8; 32],
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 1_700_000_000 + h,
            proposer: ks[0].verifying_key().to_bytes(),
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
        };
        let bh = b.compute_hash();
        b.precommit_qc = Some(qc_for(&ks[..3], h, bh));
        st.record_finalized_header(&b).await;
    }
    st.height
        .store(7350, std::sync::atomic::Ordering::Relaxed);

    let mut keys: Vec<(&str, Value)> = Vec::new();
    for h in 6000u64..6100 {
        keys.push(("stell_getBlock", json!({ "height": h })));
        keys.push(("stell_getBlockTransactions", json!({ "height": h })));
    }
    for h in 7000u64..=7349 {
        keys.push(("stell_getFinalizedHeader", json!({ "height": h })));
    }
    keys.push(("stell_getEpochRoot", json!({ "epoch": 55u64 })));
    assert!(
        keys.len() > stellereum::rpc::FINALIZED_READ_CACHE_CAP,
        "must overfill the cap: {} keys",
        keys.len()
    );
    // Fill every key; all must serve.
    for (m, p) in &keys {
        let r = st.call(m, p.clone()).await;
        assert!(
            r.get("error").is_none(),
            "{m} {} must serve: {r}",
            p["height"].as_u64().unwrap_or(55)
        );
    }
    let (len, _, _) = stats();
    assert!(
        len <= stellereum::rpc::FINALIZED_READ_CACHE_CAP,
        "cache must stay bounded: len={len}"
    );
    // Every key — hit or evicted-and-recomputed — serves correct bytes:
    // block summaries match the published window, headers match the record.
    for (m, p) in &keys {
        let r = st.call(m, p.clone()).await;
        assert!(r.get("error").is_none(), "{m} {p} must still serve");
        if *m == "stell_getBlock" {
            let h = p["height"].as_u64().unwrap();
            assert_eq!(r["height"], h);
            assert_eq!(r["txs"], 2);
        } else if *m == "stell_getBlockTransactions" {
            assert_eq!(r["txs"].as_array().unwrap().len(), 2);
        } else if *m == "stell_getFinalizedHeader" {
            assert_eq!(r["height"], p["height"].as_u64().unwrap());
        } else if *m == "stell_getEpochRoot" {
            assert_eq!(r["complete"], true);
            assert!(r["committed_root"].is_string());
        }
    }
    let (len2, _, _) = stats();
    assert!(
        len2 <= stellereum::rpc::FINALIZED_READ_CACHE_CAP,
        "re-reads must stay bounded: len={len2}"
    );
}

/// Before/after on the fixed workload: forced-recompute (expired) vs cache
/// hit, per method. This is the gate's perf number.
#[tokio::test]
async fn finalized_read_cache_before_after() {
    let _g = TEST_LOCK.lock().await;
    let ks = test_keys();
    let st = test_state(8000);
    for h in 8000u64..=8010 {
        publish_height(&st, &ks, h, 5).await;
    }
    for h in 8192u64..=8320 {
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: h,
            prev_hash: [0x80u8; 32],
            state_root: [(h % 251) as u8; 32],
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 1_700_000_000 + h,
            proposer: ks[0].verifying_key().to_bytes(),
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
        };
        let bh = b.compute_hash();
        b.precommit_qc = Some(qc_for(&ks[..3], h, bh));
        st.record_finalized_header(&b).await;
    }
    st.height
        .store(8320, std::sync::atomic::Ordering::Relaxed);

    let cases: Vec<(&str, Value)> = vec![
        ("stell_getBlock", json!({ "height": 8005u64 })),
        ("stell_getBlockTransactions", json!({ "height": 8005u64 })),
        ("stell_getFinalizedHeader", json!({ "height": 8250u64 })),
        ("stell_getEpochRoot", json!({ "epoch": 64u64 })),
    ];
    eprintln!("=== finalized-read cache before/after (ms per call) ===");
    for (m, p) in &cases {
        // BEFORE: force a miss every iteration (expiry), i.e. fresh compute.
        let mut cold = Vec::new();
        for _ in 0..100 {
            stellereum::rpc::finalized_read_cache_expire_all_for_tests();
            let t = Instant::now();
            let r = st.call(m, p.clone()).await;
            assert!(r.get("error").is_none(), "{m} must serve");
            cold.push(t.elapsed().as_secs_f64() * 1000.0);
        }
        // AFTER: fill once, then hits.
        let _ = st.call(m, p.clone()).await;
        let mut hot = Vec::new();
        for _ in 0..500 {
            let t = Instant::now();
            let r = st.call(m, p.clone()).await;
            assert!(r.get("error").is_none(), "{m} must serve");
            hot.push(t.elapsed().as_secs_f64() * 1000.0);
        }
        cold.sort_by(|a, b| a.partial_cmp(b).unwrap());
        hot.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let (cmed, hmed) = (cold[cold.len() / 2], hot[hot.len() / 2]);
        let (cmean, hmean) = (
            cold.iter().sum::<f64>() / cold.len() as f64,
            hot.iter().sum::<f64>() / hot.len() as f64,
        );
        eprintln!(
            "cache {m:32} before median={cmed:.4}ms mean={cmean:.4}ms | after median={hmed:.4}ms mean={hmean:.4}ms | speedup={:.1}x",
            cmed / hmed.max(1e-9)
        );
    }
    eprintln!("=== end before/after ===");
}
