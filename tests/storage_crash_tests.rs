//! Storage crash-consistency battery (8.5 -> 9.0).
//!
//! Deterministic fault injection at the API level -- NO process kills, NO
//! signals, NO real crashes. Every test uses temp dirs only and fixed
//! fixtures:
//!
//! * torn write: truncate a valid state snapshot at every 1KB boundary; every
//!   truncation must refuse cleanly and never half-load into the live engine.
//! * interrupted drain: simulate a shutdown stopped mid-drain through
//!   [`wait_for_persist_drain_with`](stellereum::storage::wait_for_persist_drain_with)
//!   with an injected stall, assert no torn state, then resume to a clean drain.
//! * corrupt tail: single-bit flips at 32 spread positions (covering the length
//!   prefix and the tail bytes); all must be refused with a clear error.
//! * version mix: V1..V7 well-formed bytes must decode-or-clean-refuse per
//!   their contract (lenient upgrades, strict refuses non-current); the
//!   current shape must round-trip through both decoders.
//! * restore-after-crash: N blocks + snapshot, corrupt the tip, restore must
//!   still match the pre-corruption canonical root.

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;

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

const SNAP_H: u64 = 100;
const NEXT_H: u64 = 101;

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "stell-crash-{tag}-{}-{:?}",
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

/// Persist a paired state+domains snapshot at `SNAP_H` with the anchor block
/// at `NEXT_H` committing to the post-snapshot root, finalized at `NEXT_H`.
/// Returns the canonical root and the raw state bytes.
async fn persist_paired(store: &Storage, engine: &InMemoryStateEngine) -> ([u8; 32], Vec<u8>) {
    let root = engine.get_state_root().await;
    let snap = engine.create_snapshot().await;
    let dom = DomainSnapshot::capture(engine, &StakingLedger::new(), &Governance::new()).await;
    let dbytes = bincode::serialize(&dom).expect("domain snapshot encodes");
    store.put_state(SNAP_H, &snap).expect("put state");
    store.put_domains(SNAP_H, &dbytes).expect("put domains");
    let h0 = store
        .put_block(&mkblock(SNAP_H, [0u8; 32], [0xEEu8; 32]))
        .expect("put anchor base");
    let h1 = store
        .put_block(&mkblock(NEXT_H, h0, root))
        .expect("put anchor");
    store.set_finalized(NEXT_H, &h1).expect("finalize");
    store.flush().expect("flush");
    (root, snap)
}

// ---------- (a) torn write: truncation at every 1KB boundary ----------

#[tokio::test]
async fn torn_snapshot_truncations_refuse_cleanly() {
    let dir = tmpdir("torn-trunc");
    let store = Storage::open(&dir).expect("open");
    // 400 fixed accounts => snapshot well above 2KB, so several 1KB cuts exist.
    let engine = funded_engine_n(400).await;
    let (root, snap) = persist_paired(&store, &engine).await;
    assert!(
        snap.len() > 2048,
        "fixture snapshot must span several 1KB cuts, got {} bytes",
        snap.len()
    );
    let probe = fixed_addr(0);

    let mut cases = 0u32;
    let mut off = 1024usize;
    while off < snap.len() {
        store
            .put_state(SNAP_H, &snap[..off])
            .expect("put truncated state");
        let fresh = InMemoryStateEngine::new();
        let err = load_full_state_into(&store, &fresh)
            .await
            .expect_err(&format!("truncation at {off} bytes must be refused"));
        assert!(
            !format!("{err:?}").is_empty(),
            "truncation at {off} bytes refused without a message"
        );
        assert!(
            fresh.get_account(&probe).await.is_none(),
            "truncation at {off} bytes half-loaded into the live engine"
        );
        cases += 1;
        off += 1024;
    }
    assert!(cases >= 1, "expected at least one 1KB truncation case");

    // Healing the torn write restores the canonical state.
    store.put_state(SNAP_H, &snap).expect("heal torn write");
    let fresh = InMemoryStateEngine::new();
    let (h, _, _) = load_full_state_into(&store, &fresh)
        .await
        .expect("healed snapshot loads")
        .expect("snapshot present");
    assert_eq!(h, SNAP_H);
    assert_eq!(fresh.get_state_root().await, root);
    assert_eq!(
        fresh.get_account(&probe).await.expect("probe present").balance,
        10_000
    );
    std::fs::remove_dir_all(&dir).ok();
}

// ---------- (b) interrupted drain via the drain API with injected stop ----------

#[tokio::test]
async fn interrupted_drain_no_torn_state_resume_completes() {
    // Phase 1: injected stop -- a queue that never drains hits the cap and
    // reports `drained: false` without touching storage (no process kills).
    let stalled = ShutdownDrainConfig {
        cap: Duration::from_millis(60),
        poll: Duration::from_millis(5),
        log_every: Duration::from_secs(3600),
        settle_grace: Duration::from_millis(1),
    };
    let out = wait_for_persist_drain_with(|| 5u64, stalled).await;
    assert!(!out.drained, "a stalled queue must report drained=false");
    assert_eq!(out.last_pending, 5);

    // No torn state from the interruption: the paired snapshot still loads.
    let dir = tmpdir("drain-state");
    let store = Storage::open(&dir).expect("open");
    let engine = funded_engine_n(8).await;
    let (root, _) = persist_paired(&store, &engine).await;
    let fresh = InMemoryStateEngine::new();
    let (h, _, _) = load_full_state_into(&store, &fresh)
        .await
        .expect("paired snapshot loads after interrupted drain")
        .expect("present");
    assert_eq!(h, SNAP_H);
    assert_eq!(fresh.get_state_root().await, root);

    // Phase 2: resume -- a draining counter reaches zero before the cap.
    let depth = Arc::new(AtomicU64::new(3));
    let depth_worker = depth.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        depth_worker.store(0, Ordering::Relaxed);
    });
    let resume = ShutdownDrainConfig {
        cap: Duration::from_secs(5),
        poll: Duration::from_millis(5),
        log_every: Duration::from_secs(3600),
        settle_grace: Duration::from_millis(1),
    };
    let out = wait_for_persist_drain_with(|| depth.load(Ordering::Relaxed), resume).await;
    assert!(out.drained, "resumed drain must complete");
    assert_eq!(out.last_pending, 0);

    // Phase 3: resume through the real persist queue -- enqueue a block, drain
    // via `pending()`, and the body is durably servable afterwards.
    let store = Arc::new(Storage::open(&tmpdir("drain-real")).expect("open"));
    let ap = AsyncPersistence::start(store.clone());
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
    let got = store
        .committed_body(7, &hash)
        .expect("read body")
        .expect("body present after drain");
    assert_eq!(got.compute_hash(), hash);
    std::fs::remove_dir_all(&dir).ok();
}

// ---------- (c) corrupt tail: 32 spread bit-flips in the domain blob ----------

#[tokio::test]
async fn corrupt_tail_bitflips_refused() {
    let dir = tmpdir("corrupt-tail");
    let store = Storage::open(&dir).expect("open");
    let engine = funded_engine_n(64).await;
    let (root, _) = persist_paired(&store, &engine).await;
    let good = store
        .domain_at(SNAP_H)
        .expect("read domains")
        .expect("domains present");
    assert!(good.len() > 64, "fixture domain blob must be non-trivial");
    let probe = fixed_addr(1);

    // 32 deterministic positions spanning [0, len-1]: index 0 covers the
    // length prefixes, the tail covers the committed digest domains. Any
    // single-bit change either breaks the decode or moves the restored root
    // away from the anchor -- both must refuse loudly, never half-apply.
    for i in 0..32usize {
        let pos = (i * (good.len() - 1)) / 31;
        let mut bad = good.clone();
        bad[pos] ^= 0x01;
        store.put_domains(SNAP_H, &bad).expect("put corrupted domains");
        let fresh = InMemoryStateEngine::new();
        let err = load_full_state_into(&store, &fresh)
            .await
            .expect_err(&format!("bit-flip at byte {pos} must be refused"));
        let msg = format!("{err:?}");
        assert!(
            !msg.is_empty(),
            "bit-flip at byte {pos} refused without a clear error"
        );
        assert!(
            fresh.get_account(&probe).await.is_none(),
            "bit-flip at byte {pos} half-loaded into the live engine"
        );
    }

    // Healing restores the canonical root.
    store.put_domains(SNAP_H, &good).expect("heal corruption");
    let fresh = InMemoryStateEngine::new();
    let (h, _, _) = load_full_state_into(&store, &fresh)
        .await
        .expect("healed snapshot loads")
        .expect("present");
    assert_eq!(h, SNAP_H);
    assert_eq!(fresh.get_state_root().await, root);
    std::fs::remove_dir_all(&dir).ok();
}

// ---------- (d) version mix: V1..V7 lenient-upgrade, strict refuses ----------

#[tokio::test]
async fn version_mix_decode_contract() {
    // Current shape round-trips through both decoders.
    let engine = funded_engine_n(4).await;
    let dom = DomainSnapshot::capture(&engine, &StakingLedger::new(), &Governance::new()).await;
    let cur = bincode::serialize(&dom).expect("current encodes");
    let back = decode_domain_snapshot(&cur).expect("current lenient decodes");
    let recoded = bincode::serialize(&back).expect("decoded re-encodes");
    decode_domain_snapshot(&recoded).expect("re-encoded decodes");
    decode_domain_snapshot_strict(&cur).expect("current strict decodes");

    // Well-formed V1..V7 bytes: the lenient decoder upgrades them (clean Ok,
    // never a panic or half-state); the strict decoder refuses non-current.
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
    }

    // Garbage and truncated current bytes are refused by both decoders.
    assert!(decode_domain_snapshot(&[]).is_err(), "empty refused");
    assert!(
        decode_domain_snapshot_strict(&[]).is_err(),
        "empty refused (strict)"
    );
    let cut = cur[..cur.len() / 2].to_vec();
    assert!(
        decode_domain_snapshot(&cut).is_err(),
        "truncated current refused (lenient)"
    );
    assert!(
        decode_domain_snapshot_strict(&cut).is_err(),
        "truncated current refused (strict)"
    );
}

// ---------- (e) restore-after-crash equals the canonical root ----------

#[tokio::test]
async fn restore_after_crash_equals_canonical() {
    const N: u64 = 8;
    let dir = tmpdir("restore-canon");
    let store = Storage::open(&dir).expect("open");
    let engine = funded_engine_n(3).await;
    let canonical = engine.get_state_root().await;

    // Write N blocks with a paired snapshot at N and the anchor at N+1.
    let snap = engine.create_snapshot().await;
    let dom = DomainSnapshot::capture(&engine, &StakingLedger::new(), &Governance::new()).await;
    let dbytes = bincode::serialize(&dom).expect("domains encode");
    store.put_state(N, &snap).expect("put state");
    store.put_domains(N, &dbytes).expect("put domains");
    let mut prev = [0u8; 32];
    for h in 1..=N {
        prev = store
            .put_block(&mkblock(h, prev, [h as u8; 32]))
            .expect("put block");
    }
    let anchor = store
        .put_block(&mkblock(N + 1, prev, canonical))
        .expect("put anchor");
    store.set_finalized(N + 1, &anchor).expect("finalize");

    // Crash tip: an unpaired torn tail (state with no domains) plus a poisoned
    // overwrite of the tip label. The loader must ignore the unpaired tail and
    // refuse the poisoned label -- never install either.
    let poison_engine = funded_engine_n(3).await;
    poison_engine
        .update_account(AccountState::new(fixed_addr(0), 999_999_999))
        .await;
    let poisoned = poison_engine.create_snapshot().await;
    assert_ne!(poisoned, snap, "poison must differ from canonical bytes");
    store.put_state(N + 100, &poisoned).expect("torn tail");
    let fresh = InMemoryStateEngine::new();
    let (h, _, _) = load_full_state_into(&store, &fresh)
        .await
        .expect("restore ignores the torn tail")
        .expect("present");
    assert_eq!(h, N, "only the newest PAIRED height may load");
    assert_eq!(
        fresh.get_state_root().await, canonical,
        "restored root must equal the pre-corruption canonical root"
    );
    assert_eq!(
        fresh
            .get_account(&fixed_addr(0))
            .await
            .expect("probe present")
            .balance,
        10_000
    );

    // Direct tip corruption is refused, then heals back to canonical.
    store
        .put_state(N, &snap[..snap.len() / 2])
        .expect("corrupt tip");
    let fresh = InMemoryStateEngine::new();
    assert!(
        load_full_state_into(&store, &fresh).await.is_err(),
        "corrupted tip must be refused"
    );
    assert!(fresh.get_account(&fixed_addr(0)).await.is_none());
    store.put_state(N, &snap).expect("heal tip");
    let fresh = InMemoryStateEngine::new();
    let (h, _, _) = load_full_state_into(&store, &fresh)
        .await
        .expect("healed tip restores")
        .expect("present");
    assert_eq!(h, N);
    assert_eq!(fresh.get_state_root().await, canonical);
    std::fs::remove_dir_all(&dir).ok();
}
