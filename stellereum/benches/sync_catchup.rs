//! Catch-up / snapshot LOCAL-CPU bench (report only, no timing asserts).
//!
//! Run in RELEASE with `--nocapture`:
//!     cargo test --release --bench sync_catchup -- --nocapture
//!
//! What is measured, and why (the live `[perf] tick ... catchup_ms` lines are
//! dominated by DHT round trips, so they cannot rank LOCAL work):
//!
//! 1. `collect_missing`  — the backward `prev_hash` walk (`src/sync.rs`),
//!    including the fetch-boundary body-hash check.
//! 2. `validate`         — `validate_sync_chain_for_shard_with_sets`: per-block
//!    hashing + proposer signature + precommit-QC verification.
//! 3. `walk_tail`        — the per-block tail `walk_chain` runs AFTER
//!    validation (retention key, apply, RPC record, successor-root lookahead,
//!    body clone). Two shapes are measured: `naive` = the pre-optimisation
//!    loop shape (O(n^2) successor search, one block hash per use, three full
//!    body copies); `shipped` = the same work with the hashes reused from
//!    validation, an O(1) successor read and two body copies (the persist job
//!    takes the body by move). The production loop must perform the `shipped`
//!    shape.
//! 4. `snapshot_entry`   — the snapshot-sync entry sequence: fetch the state
//!    snapshot, prove the anchor, then verify+commit it. `two_fetch` = the
//!    pre-optimisation shape (the state snapshot is downloaded TWICE: once as
//!    the presence/pointer probe, once inside `fast_sync_state_with_set_binding`);
//!    `one_fetch` = the shipped shape (the probed bytes are handed to the
//!    restore, so the blob crosses the wire once).
//!
//! Fixtures are deterministic (fixed seeds, fixed balances), like every other
//! bench in this directory. The Falcon key material is derived from a fixed
//! seed, so the measured crypto is the production crypto.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use ed25519_dalek::SigningKey;
use stellereum::consensus::{
    register_validator_pq_key, QuorumCertificate, ValidatorSet, Vote, VoteKind, VoteSet,
};
use stellereum::post_quantum::{FalconKeypair, PqScheme};
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::sync::{collect_missing_blocks, validate_sync_chain_for_shard_with_sets};

// ---------------------------------------------------------------------------
// deterministic fixtures
// ---------------------------------------------------------------------------

fn det32(seed: u8, i: u64) -> [u8; 32] {
    let mut b = [seed; 32];
    b[..8].copy_from_slice(&i.to_be_bytes());
    b
}

fn keys(n: usize) -> Vec<SigningKey> {
    (0..n)
        .map(|i| SigningKey::from_bytes(&det32(0x51, i as u64)))
        .collect()
}

fn fks_for(ks: &[SigningKey]) -> Vec<FalconKeypair> {
    ks.iter()
        .enumerate()
        .map(|(i, _)| FalconKeypair::generate_from_seed_bytes(&det32(0x71, i as u64)))
        .collect()
}

fn vset(ks: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    )
}

fn det_tx(i: u64) -> Transaction {
    Transaction {
        from: det32(0x11, i),
        to: det32(0x22, i),
        amount: 1_000 + i,
        gas_limit: 280_000,
        nonce: i,
        source_shard: MASTERCHAIN_SHARD,
        target_shard: MASTERCHAIN_SHARD,
        signature: vec![0xAB; 64],
        payload: vec![],
        priority_fee_per_gas: 0,
    }
}

fn attach_quorum(
    b: &mut Block,
    ks: &[SigningKey],
    fks: &[FalconKeypair],
    vs: &ValidatorSet,
    height: u64,
    bh: [u8; 32],
    parent: [u8; 32],
) {
    for (k, fk) in ks.iter().zip(fks.iter()) {
        register_validator_pq_key(
            k.verifying_key().to_bytes(),
            PqScheme::Falcon512,
            fk.public_key.clone(),
        );
    }
    let mut set = VoteSet::new();
    for (k, fk) in ks.iter().zip(fks.iter()) {
        let v = Vote::sign_with_falcon(k, fk, height, 0, VoteKind::Precommit, Some(bh));
        set.add(v, vs, height, 0, VoteKind::Precommit)
            .expect("genuine vote admits");
    }
    b.precommit_qc = set.certificate_with_parent(Some(bh), vs, Some(&parent));
}

/// A QC-bearing chain of `n` blocks (heights 1..=n) with `txs` per block.
fn build_chain(ks: &[SigningKey], fks: &[FalconKeypair], n: u64, txs: u64) -> Vec<Block> {
    let vs = vset(ks);
    let mut out: Vec<Block> = Vec::with_capacity(n as usize);
    let mut prev = [0u8; 32];
    let transactions: Vec<Transaction> = (0..txs).map(det_tx).collect();
    let order_merkle_root = stellereum::mev::compute_order_merkle_root(&transactions);
    for h in 1..=n {
        let proposer_id = vs.proposer_for(h, 0).expect("non-empty set has a proposer");
        let proposer_idx = ks
            .iter()
            .position(|k| k.verifying_key().to_bytes() == proposer_id)
            .expect("proposer is a member");
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: h,
            prev_hash: prev,
            state_root: [0x11u8; 32],
            transactions: transactions.clone(),
            cross_shard_out: vec![],
            timestamp: 1_000 + h,
            proposer: proposer_id,
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            cnvrf_v3: None,
            order_merkle_root,
            epoch_key_commitment: [0u8; 32],
            round: 0,
        };
        b.sign_block_with_falcon(&ks[proposer_idx], &fks[proposer_idx]);
        let bh = b.compute_hash();
        attach_quorum(&mut b, ks, fks, &vs, h, bh, prev);
        prev = b.compute_hash();
        out.push(b);
    }
    out
}

// ---------------------------------------------------------------------------
// timing helper
// ---------------------------------------------------------------------------

fn timed<T>(label: &str, reps: usize, mut f: impl FnMut() -> T) -> f64 {
    // One warm-up pass so allocator/cache state is not what we measure.
    std::hint::black_box(f());
    let mut best = f64::MAX;
    let mut total = 0.0f64;
    for _ in 0..reps {
        let t0 = Instant::now();
        let out = f();
        let ms = t0.elapsed().as_secs_f64() * 1000.0;
        std::hint::black_box(out);
        best = best.min(ms);
        total += ms;
    }
    let mean = total / reps as f64;
    println!("[bench][sync] {label}: best_ms={best:.3} mean_ms={mean:.3} reps={reps}");
    best
}

// ---------------------------------------------------------------------------
// 1. backward body walk
// ---------------------------------------------------------------------------

#[test]
fn bench_collect_missing_walk() {
    let ks = keys(4);
    let fks = fks_for(&ks);
    // Empty bodies: this bench isolates the fetch-boundary hash check + the
    // walk bookkeeping, not transaction hashing (see `bench_walk_tail`).
    let blocks = build_chain(&ks, &fks, 512, 0);
    let by_hash: HashMap<[u8; 32], Block> = blocks
        .iter()
        .map(|b| (b.compute_hash(), b.clone()))
        .collect();
    let head = blocks.last().unwrap().compute_hash();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    timed("collect_missing N=512 bodies", 5, || {
        let map = by_hash.clone();
        let got = rt.block_on(collect_missing_blocks(head, [0u8; 32], 1024, move |h| {
            let b = map.get(&h).cloned();
            async move { b }
        }));
        let got = got.expect("walk succeeds");
        assert_eq!(got.len(), 512);
        got.len()
    });
}

// ---------------------------------------------------------------------------
// 2. chain validation (per-height hashing + proposer sig + QC)
// ---------------------------------------------------------------------------

#[test]
fn bench_validate_chain() {
    let ks = keys(4);
    let fks = fks_for(&ks);
    let vs = vset(&ks);
    let blocks = build_chain(&ks, &fks, 512, 32);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    // Live callers pass a per-height resolver (the runtime's
    // `validator_set_for_height`): one distinct set per height here, so the
    // resolver cost is the clone, exactly as on a single-set chain.
    let resolve = |_h: u64| Some(vs.clone());
    timed("validate N=512 txs=32 (per-height resolver)", 3, || {
        rt.block_on(async {
            validate_sync_chain_for_shard_with_sets(
                &blocks,
                1,
                [0u8; 32],
                &resolve,
                MASTERCHAIN_SHARD,
            )
            .expect("genuine chain validates")
        })
    });
}

// ---------------------------------------------------------------------------
// 2b. the body hashing chain validation used to repeat
// ---------------------------------------------------------------------------

#[test]
fn bench_block_hashing() {
    // `Block::compute_hash` is the unit of the eliminated work: the validator
    // used to hash each body once for the QC binding and once again as the NEXT
    // block's parent link (the proposer-signature check hashes its own copy
    // inside `consensus::verify_proposer_signature`, which lives outside this
    // module). The walk then hashed the same body again for its retention key,
    // its apply call and its RPC record. One pass below = one of those.
    let ks = keys(4);
    let fks = fks_for(&ks);
    let blocks = build_chain(&ks, &fks, 512, 32);
    timed("block compute_hash pass x512 txs=32", 5, || {
        let mut acc = [0u8; 32];
        for b in &blocks {
            let h = b.compute_hash();
            acc[0] ^= h[0];
        }
        acc
    });
}

// ---------------------------------------------------------------------------
// 3. the post-validation per-block tail of `walk_chain`
// ---------------------------------------------------------------------------

/// Pre-optimisation loop shape, copied from the shipped loop as it stood: one
/// `compute_hash` per USE (retention key, apply key, RPC key), an O(n^2)
/// successor scan, and three deep body copies per block (retention, persist
/// queue, last-decision) plus one tail hash after the loop.
fn walk_tail_naive(blocks: &[Block]) -> (Vec<[u8; 32]>, usize) {
    let mut retained: Vec<([u8; 32], Block)> = Vec::with_capacity(blocks.len());
    let mut persisted = 0usize;
    let mut last_decision: Option<(u64, Block, QuorumCertificate)> = None;
    for b in blocks {
        // retention key + body copy #1
        retained.push((b.compute_hash(), b.clone()));
        // persist-queue body copy #2 (a clone: the loop only borrows `blocks`)
        persisted += b.clone().transactions.len();
        // last-decision body copy #3 + QC clone (no hash)
        if let Some(qc) = b.precommit_qc.clone() {
            last_decision = Some((b.height, b.clone(), qc));
        }
        // apply key + RPC record key
        let _apply = b.compute_hash();
        let _rpc = b.compute_hash();
        // successor-root lookahead (O(n) scan per block)
        let _next = blocks.iter().find(|x| x.height == b.height + 1);
    }
    let _keep = last_decision.is_some();
    // the broadcast tail is re-hashed once after the loop
    let tail = blocks.last().unwrap().compute_hash();
    (
        retained.into_iter().map(|(h, _)| h).chain([tail]).collect(),
        persisted,
    )
}

/// Shipped shape: hashes reused from validation (ZERO re-hash in the tail),
/// successor read by index, two body copies (retention + last decision) and the
/// persist queue takes the body by move instead of a third copy.
fn walk_tail_shipped(blocks: &[Block], hashes: &[[u8; 32]]) -> usize {
    let mut persisted = 0usize;
    let mut retained: Vec<([u8; 32], Block)> = Vec::with_capacity(blocks.len());
    let mut last_decision: Option<([u8; 32], Block, QuorumCertificate)> = None;
    for (i, b) in blocks.iter().enumerate() {
        retained.push((hashes[i], b.clone()));
        if let Some(qc) = b.precommit_qc.clone() {
            last_decision = Some((hashes[i], b.clone(), qc));
        }
        // persist queue: the body is MOVED into the job (no third copy)
        persisted += b.transactions.len();
        let _apply = hashes[i];
        let _rpc = hashes[i];
        // contiguous heights: the successor is the next element, no scan
        let _next = blocks.get(i + 1);
    }
    let _keep = last_decision.is_some();
    let _tail = hashes[blocks.len() - 1];
    retained.len() + persisted + _tail.len()
}

#[test]
fn bench_walk_tail() {
    // 128-tx bodies make the per-use body hashing visible (a real walked block
    // carries transactions; empty bodies would under-state the win).
    let ks = keys(4);
    let fks = fks_for(&ks);
    let blocks = build_chain(&ks, &fks, 512, 128);

    timed(
        "walk_tail N=512 txs=128 naive (pre-change shape)",
        5,
        || walk_tail_naive(&blocks),
    );

    let hashes: Vec<[u8; 32]> = blocks.iter().map(|b| b.compute_hash()).collect();
    timed(
        "walk_tail N=512 txs=128 shipped (hash once, O(1) next, 1 clone)",
        5,
        || walk_tail_shipped(&blocks, &hashes),
    );
}

// ---------------------------------------------------------------------------
// 4. snapshot-sync entry sequence
// ---------------------------------------------------------------------------

/// Deterministic multi-megabyte state snapshot blob (fixture only: the bytes
/// are never decoded in this case — the case measures how many times the blob
/// is REQUESTED, which is what the wire pays for).
fn fat_blob(len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    for (i, b) in v.iter_mut().enumerate() {
        *b = (i * 31 % 251) as u8;
    }
    v
}

#[test]
fn bench_snapshot_entry_downloads() {
    const SNAP_BYTES: usize = 8 * 1024 * 1024;
    let blob = Arc::new(fat_blob(SNAP_BYTES));
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    // One "download" = a full copy of the peer-supplied bytes.
    let fetch = || {
        let b = blob.clone();
        async move { Some(b.as_slice().to_vec()) }
    };

    // Pre-optimisation shape (what `try_snapshot_sync` does today): the probe
    // fetch, then `fast_sync_state_with_set_binding` fetches the SAME blob
    // again through its `fetch_snapshot` closure.
    let two = std::sync::atomic::AtomicU64::new(0);
    let two_ms = timed(
        "snapshot_entry two_fetch (probe + restore each download the blob)",
        3,
        || {
            rt.block_on(async {
                let probe = fetch().await;
                assert!(probe.is_some(), "probe hit");
                let verify = fetch().await;
                assert_eq!(verify.expect("restore fetch").len(), SNAP_BYTES);
                two.fetch_add(2, std::sync::atomic::Ordering::Relaxed);
            })
        },
    );

    // Shipped shape: the probed bytes ARE the restore input.
    let one = std::sync::atomic::AtomicU64::new(0);
    let one_ms = timed(
        "snapshot_entry one_fetch (probed bytes handed to restore)",
        3,
        || {
            rt.block_on(async {
                let probe = fetch().await;
                assert!(probe.is_some(), "probe hit");
                let bytes = probe.expect("restore input");
                assert_eq!(bytes.len(), SNAP_BYTES);
                one.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            })
        },
    );
    // `timed` runs one un-timed warm-up pass plus `reps` measured passes.
    const PASSES: u64 = 4;
    assert_eq!(two.load(std::sync::atomic::Ordering::Relaxed), 2 * PASSES);
    assert_eq!(one.load(std::sync::atomic::Ordering::Relaxed), PASSES);
    println!(
        "[bench][sync] snapshot_entry per attempt: two_fetch=2 downloads ({:.3} ms), \
         one_fetch=1 download ({:.3} ms), blob_bytes={SNAP_BYTES}, saved_bytes_per_attempt={SNAP_BYTES}",
        two_ms / PASSES as f64,
        one_ms / PASSES as f64,
    );
}

// ---------------------------------------------------------------------------
// 4b. per-height validator-set resolution (the `resolve_set` clone cost)
// ---------------------------------------------------------------------------

#[test]
fn bench_resolve_set_clone() {
    // A 128-member set: cloning it is what a per-height resolver call costs on
    // top of the runtime's history scan. Measured so the "cache the resolver
    // per height range" candidate can be accepted or REJECTED on numbers.
    let ks = keys(128);
    let vs = vset(&ks);
    let heights: Vec<u64> = (1..=512u64).collect();
    timed("resolve_set clone x512 (128 members, one pass)", 5, || {
        let mut acc = 0usize;
        for h in &heights {
            let s = vs.clone();
            acc += s.validators.len() + (*h as usize & 1);
        }
        acc
    });
}

// ---------------------------------------------------------------------------
// 4c. aux-domain snapshot reads done by one local restore
// ---------------------------------------------------------------------------

#[test]
fn bench_aux_domain_reads() {
    use stellereum::storage::Storage;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "stell-bench-sync-aux-{tag}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    // One aux blob of a realistic live-chain size class (cross-shard replay /
    // zkML models / CN-VRF chain are megabytes on an active chain).
    const BLOB: usize = 4 * 1024 * 1024;
    let dir = tmpdir("reads");
    let store = Storage::open(&dir).expect("open");
    let h = 100u64;
    let blob: Vec<u8> = (0..BLOB).map(|i| (i * 37 % 251) as u8).collect();
    store.put_session_keys(h, &blob).expect("session");
    store.put_bridge(h, &blob).expect("bridge");
    store.put_zkml_models(h, &blob).expect("zkml");
    store.put_cross_shard(h, &blob).expect("xshard");
    store.put_cnvrf_v3(h, &blob).expect("cnvrf");
    store.flush().expect("flush");

    // The five aux blobs, read twice (verify phase + commit phase) — the
    // pre-change shape of `load_full_state_into`.
    let twice_ms = timed("aux_domain_reads 5 blobs x2 (pre-change shape)", 5, || {
        let mut total = 0usize;
        for _phase in 0..2 {
            total += store.session_keys_at(h).unwrap().map_or(0, |b| b.len());
            total += store.bridge_at(h).unwrap().map_or(0, |b| b.len());
            total += store.zkml_models_at(h).unwrap().map_or(0, |b| b.len());
            total += store.cross_shard_at(h).unwrap().map_or(0, |b| b.len());
            total += store.cnvrf_v3_at(h).unwrap().map_or(0, |b| b.len());
        }
        total
    });
    // Shipped shape: read once, hand the same bytes to both phases.
    let once_ms = timed("aux_domain_reads 5 blobs x1 (shipped shape)", 5, || {
        let mut total = 0usize;
        total += store.session_keys_at(h).unwrap().map_or(0, |b| b.len());
        total += store.bridge_at(h).unwrap().map_or(0, |b| b.len());
        total += store.zkml_models_at(h).unwrap().map_or(0, |b| b.len());
        total += store.cross_shard_at(h).unwrap().map_or(0, |b| b.len());
        total += store.cnvrf_v3_at(h).unwrap().map_or(0, |b| b.len());
        total
    });
    println!(
        "[bench][sync] aux_domain_reads per restore: twice={twice_ms:.3} ms once={once_ms:.3} ms \
         blob_bytes={BLOB} (5 aux domains)"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// 5. local restore (`load_full_state_into`) at 10k accounts
// ---------------------------------------------------------------------------

#[test]
fn bench_restore() {
    use stellereum::governance::Governance;
    use stellereum::staking::StakingLedger;
    use stellereum::storage::{load_full_state_into, DomainSnapshot, Storage};

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "stell-bench-sync-{tag}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    const N: usize = 10_000;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let dir = tmpdir("restore");
    let store = Storage::open(&dir).expect("open");
    let engine = InMemoryStateEngine::new();
    rt.block_on(async {
        for i in 0..N {
            engine
                .update_account(AccountState::new(det32(0xA0, i as u64), 10_000 + i as u64))
                .await;
        }
        let snap = engine.create_snapshot().await;
        let dom = DomainSnapshot::capture(&engine, &StakingLedger::new(), &Governance::new()).await;
        let dbytes = bincode::serialize(&dom).expect("domains encode");
        let h = 100u64;
        store.put_state(h, &snap).expect("put state");
        store.put_domains(h, &dbytes).expect("put domains");
        // No anchor block: the restore is semantically verified by the root the
        // snapshot carries, which this bench does not compare (the perf suite
        // `storage_restore_perf_tests` owns the correctness gate).
        store.flush().expect("flush");
    });

    timed("restore load_full_state_into N=10000", 5, || {
        let fresh = InMemoryStateEngine::new();
        rt.block_on(async {
            load_full_state_into(&store, &fresh)
                .await
                .expect("restore")
                .map(|(h, _, _)| h)
                .expect("snapshot present")
        })
    });
    let _ = std::fs::remove_dir_all(&dir);
}
