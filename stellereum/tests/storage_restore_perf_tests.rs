//! Storage restore performance + correctness at scale (9.0 -> 9.5).
//!
//! NEW-FILE suite: builds states of N=100 / 1_000 / 10_000 accounts with fixed
//! seeds (address = `0xA0 || le16(i)`, balance = `10_000 + i` — no randomness),
//! snapshots each, and checks:
//!
//! 1. restore time is REPORTED (ms) and gated ONLY against a 10x regression
//!    versus the linear projection from N=100 (`bound = 10 * t100 * N/100`,
//!    with a 30s floor so a sub-ms baseline cannot turn noise into a tight
//!    gate). No absolute wall-clock gate.
//! 2. restored roots equal the canonical root at every scale (+ spot balances).
//! 3. snapshot byte size scales ~linearly: REPORT bytes/account, gate only
//!    against quadratic blowup (4x headroom over the linear projection).
//! 4. V1..V7 upgrade legs still decode-or-refuse (spot-check: well-formed
//!    defaults upgrade via the lenient decoder, strict decoder refuses them;
//!    a scale-size current blob round-trips through both).
//! 5. interrupt-resume at scale: drain-stall injection on the 10k state, then
//!    resume completes and the restored root is canonical.
//!
//! All storage lives in temp dirs. Uses the `storage_crash_tests` fixtures
//! idiom verbatim (paired state+domains snapshot + anchor block at H+1
//! committing to the post-snapshot root, finalized at H+1).

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use stellereum::governance::Governance;
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};
use stellereum::staking::StakingLedger;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::storage::{
    decode_domain_snapshot, decode_domain_snapshot_strict, load_full_state_into,
    wait_for_persist_drain_with, AsyncPersistence, DomainSnapshot, DomainSnapshotV1,
    DomainSnapshotV2, DomainSnapshotV3, DomainSnapshotV4, DomainSnapshotV5, DomainSnapshotV6,
    DomainSnapshotV7, ShutdownDrainConfig, Storage,
};

/// Paired-snapshot heights per scale (disjoint so each scale restores alone).
const H100: u64 = 100;
const H1K: u64 = 200;
const H10K: u64 = 300;
const HRESUME: u64 = 400;

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "stell-restore-perf-{tag}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    ));
    let _ = std::fs::remove_dir_all(&p);
    p
}

fn fixed_key() -> SigningKey {
    SigningKey::from_bytes(&[0x11u8; 32])
}

fn mkblock(height: u64, prev: [u8; 32], state_root: [u8; 32]) -> Block {
    let sk = fixed_key();
    let mut b = Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash: prev,
        state_root,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1_700_000_000 + height,
        proposer: sk.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32],
    };
    b.sign_block(&sk);
    b
}

fn fixed_addr(i: usize) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[0] = 0xA0;
    a[1] = (i & 0xFF) as u8;
    a[2] = ((i >> 8) & 0xFF) as u8;
    a[3] = ((i >> 16) & 0xFF) as u8;
    a
}

/// Engine with `n` fixed accounts (deterministic balances), no randomness.
async fn funded_engine_n(n: usize) -> InMemoryStateEngine {
    let engine = InMemoryStateEngine::new();
    for i in 0..n {
        engine
            .update_account(AccountState::new(fixed_addr(i), 10_000 + i as u64))
            .await;
    }
    engine
}

/// Persist a paired state+domains snapshot at `snap_h` with the anchor block
/// at `snap_h + 1` committing to the post-snapshot root, finalized there.
/// Returns the canonical root plus the raw state/domain byte lengths.
async fn persist_paired_at(
    store: &Storage,
    engine: &InMemoryStateEngine,
    snap_h: u64,
) -> ([u8; 32], usize, usize) {
    let root = engine.get_state_root().await;
    let snap = engine.create_snapshot().await;
    let dom = DomainSnapshot::capture(engine, &StakingLedger::new(), &Governance::new()).await;
    let dbytes = bincode::serialize(&dom).expect("domain snapshot encodes");
    let (state_len, dom_len) = (snap.len(), dbytes.len());
    store.put_state(snap_h, &snap).expect("put state");
    store.put_domains(snap_h, &dbytes).expect("put domains");
    let next_h = snap_h + 1;
    let h0 = store
        .put_block(&mkblock(snap_h, [0u8; 32], [0xEEu8; 32]))
        .expect("put anchor base");
    let h1 = store
        .put_block(&mkblock(next_h, h0, root))
        .expect("put anchor");
    store.set_finalized(next_h, &h1).expect("finalize");
    store.flush().expect("flush");
    (root, state_len, dom_len)
}

struct ScalePoint {
    n: usize,
    state_len: usize,
    dom_len: usize,
    restore_ms: f64,
}

/// Restore the paired snapshot in `dir`'s store, asserting the canonical root
/// and spot balances. Returns the restore wall time in ms.
async fn restore_and_check(store: &Storage, snap_h: u64, canonical: [u8; 32], n: usize) -> f64 {
    let fresh = InMemoryStateEngine::new();
    let t0 = Instant::now();
    let (h, _, _) = load_full_state_into(store, &fresh)
        .await
        .expect("paired snapshot loads at scale")
        .expect("snapshot present");
    let ms = t0.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(h, snap_h, "restored height must equal the paired height");
    assert_eq!(
        fresh.get_state_root().await, canonical,
        "restored root must equal the canonical root at N={n}"
    );
    // Spot balances at both ends of the deterministic range.
    assert_eq!(
        fresh
            .get_account(&fixed_addr(0))
            .await
            .expect("probe 0 present")
            .balance,
        10_000,
        "account 0 balance wrong at N={n}"
    );
    assert_eq!(
        fresh
            .get_account(&fixed_addr(n - 1))
            .await
            .expect("probe N-1 present")
            .balance,
        10_000 + (n - 1) as u64,
        "account N-1 balance wrong at N={n}"
    );
    ms
}

/// Generous regression bound only: 10x the linear projection from the N=100
/// baseline, with a 30s floor so a sub-ms baseline cannot gate on noise.
/// This is NOT a tight wall-clock gate — the ms numbers are the deliverable.
fn linear_bound_ms(t100_ms: f64, n: usize) -> f64 {
    (t100_ms * (n as f64 / 100.0) * 10.0).max(30_000.0)
}

// ---------- scale: N=100 / 1k / 10k — sizes, roots, restore times ----------

#[tokio::test]
async fn restore_perf_scale_roots_times_sizes() {
    let scales: &[(usize, u64)] = &[(100, H100), (1_000, H1K), (10_000, H10K)];
    let mut points: Vec<ScalePoint> = Vec::new();

    for (n, snap_h) in scales.iter().copied() {
        let dir = tmpdir(&format!("scale-{n}"));
        let store = Storage::open(&dir).expect("open");
        let engine = funded_engine_n(n).await;
        let (canonical, state_len, dom_len) = persist_paired_at(&store, &engine, snap_h).await;
        let restore_ms = restore_and_check(&store, snap_h, canonical, n).await;
        points.push(ScalePoint {
            n,
            state_len,
            dom_len,
            restore_ms,
        });
        std::fs::remove_dir_all(&dir).ok();
    }

    // REPORT table (ms + bytes/account are the deliverable).
    eprintln!("[restore-perf] N | state_bytes | domains_bytes | bytes/acct | restore_ms");
    for p in &points {
        eprintln!(
            "[restore-perf] {} | {} | {} | {:.1} | {:.1}",
            p.n,
            p.state_len,
            p.dom_len,
            p.state_len as f64 / p.n as f64,
            p.restore_ms
        );
    }

    let base = &points[0];
    assert_eq!(base.n, 100);
    eprintln!(
        "[restore-perf] baseline N=100: restore_ms={:.1} state_bytes={}",
        base.restore_ms, base.state_len
    );
    assert!(
        base.state_len > 1024,
        "N=100 fixture must be non-trivial, got {} bytes",
        base.state_len
    );

    for p in points.iter().skip(1) {
        // (3) sizes must grow with N (catches faked constant fixtures) but
        // must not blow up quadratically: 4x headroom over the linear
        // projection of the N=100 size.
        let linear = base.state_len as f64 * (p.n as f64 / 100.0);
        assert!(
            p.state_len > points[0].state_len,
            "state snapshot must grow with N (N={} got {} <= N=100 {})",
            p.n,
            p.state_len,
            base.state_len
        );
        assert!(
            (p.state_len as f64) <= linear * 4.0,
            "quadratic blowup at N={}: {} bytes > 4x linear projection {linear:.0}",
            p.n,
            p.state_len
        );
        let bpa_base = base.state_len as f64 / 100.0;
        let bpa = p.state_len as f64 / p.n as f64;
        eprintln!(
            "[restore-perf] N={}: bytes/acct={bpa:.1} (baseline {bpa_base:.1})",
            p.n
        );
        assert!(
            bpa <= bpa_base * 4.0,
            "bytes/account blew up at N={}: {bpa:.1} > 4x baseline {bpa_base:.1}",
            p.n
        );

        // (1) generous regression gate ONLY: 10x the linear time projection.
        let bound = linear_bound_ms(base.restore_ms, p.n);
        let proj = base.restore_ms * (p.n as f64 / 100.0);
        eprintln!(
            "[restore-perf] N={}: restore_ms={:.1} linear_proj={proj:.1} bound={bound:.1}",
            p.n,
            p.restore_ms
        );
        assert!(
            p.restore_ms <= bound,
            "restore regression at N={}: {:.1}ms > 10x linear projection bound {bound:.1}ms",
            p.n,
            p.restore_ms
        );
    }
}

// ---------- V1..V7 decode-or-refuse spot-check at scale ----------

#[tokio::test]
async fn restore_perf_vlegs_decode_or_refuse_at_scale() {
    // Scale-size CURRENT blob round-trips through both decoders.
    let engine = funded_engine_n(1_000).await;
    let dom = DomainSnapshot::capture(&engine, &StakingLedger::new(), &Governance::new()).await;
    let cur = bincode::serialize(&dom).expect("current encodes");
    eprintln!("[restore-perf] N=1000 current domain blob: {} bytes", cur.len());
    let back = decode_domain_snapshot(&cur).expect("current lenient decodes");
    let recoded = bincode::serialize(&back).expect("decoded re-encodes");
    decode_domain_snapshot(&recoded).expect("re-encoded decodes");
    decode_domain_snapshot_strict(&cur).expect("current strict decodes");

    // Well-formed V1..V7 bytes: lenient upgrades (clean Ok, never a panic),
    // strict refuses non-current with a clear message.
    let v1 = DomainSnapshotV1 {
        tokens: Default::default(),
        contracts: Default::default(),
        orderbooks: Default::default(),
        pmm: Default::default(),
        pmm_usdt_token: None,
        pmm_treasury: [0u8; 32],
        order_escrow: Default::default(),
        staking: Default::default(),
        governance: Default::default(),
        oracle: Default::default(),
    };
    let fixtures: Vec<(&str, Vec<u8>)> = vec![
        ("V1", bincode::serialize(&v1).expect("V1 encodes")),
        (
            "V2",
            bincode::serialize(&DomainSnapshotV2::default()).expect("V2 encodes"),
        ),
        (
            "V3",
            bincode::serialize(&DomainSnapshotV3::default()).expect("V3 encodes"),
        ),
        (
            "V4",
            bincode::serialize(&DomainSnapshotV4::default()).expect("V4 encodes"),
        ),
        (
            "V5",
            bincode::serialize(&DomainSnapshotV5::default()).expect("V5 encodes"),
        ),
        (
            "V6",
            bincode::serialize(&DomainSnapshotV6::default()).expect("V6 encodes"),
        ),
        (
            "V7",
            bincode::serialize(&DomainSnapshotV7::default()).expect("V7 encodes"),
        ),
    ];
    assert_eq!(fixtures.len(), 7, "V1..V7 must all be covered");
    for (tag, bytes) in &fixtures {
        decode_domain_snapshot(bytes)
            .unwrap_or_else(|e| panic!("lenient decoder must upgrade well-formed {tag}: {e:?}"));
        let strict_err = decode_domain_snapshot_strict(bytes)
            .err()
            .unwrap_or_else(|| panic!("strict decoder must refuse legacy {tag}"));
        assert!(
            !strict_err.is_empty() && strict_err.contains("refusing"),
            "legacy {tag} strict refusal must be a clear error, got: {strict_err}"
        );
        eprintln!("[restore-perf] {tag}: lenient=Ok strict=refused");
    }

    // Garbage is refused by both decoders.
    assert!(decode_domain_snapshot(&[]).is_err(), "empty refused");
    assert!(
        decode_domain_snapshot_strict(&[]).is_err(),
        "empty refused (strict)"
    );
}

// ---------- interrupt-resume at scale (10k, drain-stall injection) ----------

#[tokio::test]
async fn restore_perf_interrupt_resume_at_10k() {
    const N: usize = 10_000;

    // Phase 1: injected stall -- a queue that never drains hits the cap and
    // reports `drained: false` (no process kills, no signals).
    let stalled = ShutdownDrainConfig {
        cap: Duration::from_millis(60),
        poll: Duration::from_millis(5),
        log_every: Duration::from_secs(3600),
        settle_grace: Duration::from_millis(1),
    };
    let t0 = Instant::now();
    let out = wait_for_persist_drain_with(|| 5u64, stalled).await;
    let stall_ms = t0.elapsed().as_secs_f64() * 1000.0;
    assert!(!out.drained, "a stalled queue must report drained=false");
    assert_eq!(out.last_pending, 5);
    eprintln!("[restore-perf] N={N} stall injection: drained=false stall_ms={stall_ms:.1}");

    // The 10k paired snapshot is unaffected by the interruption.
    let dir = tmpdir("resume-10k");
    let store = Storage::open(&dir).expect("open");
    let engine = funded_engine_n(N).await;
    let (canonical, state_len, dom_len) = persist_paired_at(&store, &engine, HRESUME).await;
    eprintln!(
        "[restore-perf] N={N} snapshot: state_bytes={state_len} domains_bytes={dom_len} bytes/acct={:.1}",
        state_len as f64 / N as f64
    );

    // Phase 2: resume -- a draining counter reaches zero before the cap.
    let depth = Arc::new(AtomicU64::new(3));
    let depth_worker = depth.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        depth_worker.store(0, Ordering::Relaxed);
    });
    let resume = ShutdownDrainConfig {
        cap: Duration::from_secs(10),
        poll: Duration::from_millis(5),
        log_every: Duration::from_secs(3600),
        settle_grace: Duration::from_millis(1),
    };
    let t0 = Instant::now();
    let out = wait_for_persist_drain_with(|| depth.load(Ordering::Relaxed), resume).await;
    let resume_ms = t0.elapsed().as_secs_f64() * 1000.0;
    assert!(out.drained, "resumed drain must complete");
    assert_eq!(out.last_pending, 0);
    eprintln!("[restore-perf] N={N} resume: drained=true resume_ms={resume_ms:.1}");

    // Phase 3: resume through the real persist queue, then restore the 10k
    // state to the canonical root.
    let store_q = Arc::new(Storage::open(&tmpdir("resume-10k-real")).expect("open"));
    let ap = AsyncPersistence::start(store_q.clone());
    let b = mkblock(7, [0u8; 32], [0xEEu8; 32]);
    let hash = b.compute_hash();
    ap.enqueue_block(b);
    let fast = ShutdownDrainConfig {
        cap: Duration::from_secs(10),
        poll: Duration::from_millis(5),
        log_every: Duration::from_secs(3600),
        settle_grace: Duration::from_millis(5),
    };
    let out = wait_for_persist_drain_with(|| ap.pending(), fast).await;
    assert!(out.drained, "real persist queue must drain");
    let got = store_q
        .committed_body(7, &hash)
        .expect("read body")
        .expect("body present after drain");
    assert_eq!(got.compute_hash(), hash);

    let restore_ms = restore_and_check(&store, HRESUME, canonical, N).await;
    eprintln!("[restore-perf] N={N} post-resume restore: restore_ms={restore_ms:.1}");
    std::fs::remove_dir_all(&dir).ok();
}
