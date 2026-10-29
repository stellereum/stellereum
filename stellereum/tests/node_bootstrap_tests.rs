//! `node-bootstrap` readiness: a fresh observer goes from ZERO to the tip
//! with NO manual data copy, across a weak link and stale peers.
//!
//! Criterion proof for OPERATIONS §10: the observer starts from a GENESIS
//! engine (empty data dir — nothing is `cp`-ed), and reaches the source tip
//! root exactly while the network
//!
//! * drops snapshot fetches (misses/timeouts) before serving them,
//! * drops header fetches inside the tail-anchor window,
//! * serves a STALE (garbage) `domains` blob first — it carries the staking
//!   ledger, so it must be REJECTED with a retry, never committed — then the
//!   genuine bundle,
//! * withholds each post-snapshot body once before serving it.
//!
//! The driver uses the REAL sync primitives (`fast_sync_state`,
//! `verify_snapshot_anchor_tail`, `collect_missing_blocks`,
//! `validate_sync_chain_for_shard`) plus the REAL bootstrap planner
//! (`stellereum::bootstrap::{select_bootstrap_boundary,
//! next_boundary_after_stale, BOOTSTRAP_MAX_STALE_PER_BOUNDARY}`): the only
//! faked layer is the transport. Attempt/retry counters assert the run was
//! genuinely flaky (a test that never hits a miss proves nothing).

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use stellereum::bootstrap;
use stellereum::consensus::{QuorumCertificate, ValidatorSet, Vote, VoteKind};
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::sync::{
    collect_missing_blocks, fast_sync_state, validate_sync_chain_for_shard,
    verify_snapshot_anchor_tail, HeaderLink,
};

fn effect_account(h: u64) -> [u8; 32] {
    let mut addr = [0u8; 32];
    addr[0..8].copy_from_slice(&h.to_le_bytes());
    addr[8] = 0x0B;
    addr
}

fn effect_balance(h: u64) -> u64 {
    1_000_000 + h * 7
}

fn observer_keys(n: usize) -> Vec<SigningKey> {
    (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect()
}

fn observer_vset(ks: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    )
}

fn attach_quorum(b: &mut Block, ks: &[SigningKey], height: u64, bh: [u8; 32]) {
    let sigs = ks
        .iter()
        .map(|k| {
            let v = Vote::sign(k, height, 0, VoteKind::Precommit, Some(bh));
            (v.voter, v.signature)
        })
        .collect();
    b.precommit_qc = Some(QuorumCertificate {
        height,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(bh),
        signatures: sigs,
    });
}

struct LiveChain {
    blocks: Vec<Block>,
    snapshots: HashMap<u64, Vec<u8>>,
    domains: HashMap<u64, Vec<u8>>,
    roots: HashMap<u64, [u8; 32]>,
}

/// Chain builder with a mid-chain staking BOND at height 150: the ledger must
/// ride the `domains` blob to the observer (this is the "включая леджер"
/// half of the bootstrap criterion — accounts alone are not enough).
async fn build_live_chain(
    ks: &[SigningKey],
    bonded: &SigningKey,
    tip: u64,
) -> (LiveChain, InMemoryStateEngine) {
    let vs = observer_vset(ks);
    let engine = InMemoryStateEngine::new();
    let mut blocks = Vec::new();
    let mut snapshots = HashMap::new();
    let mut domains = HashMap::new();
    let mut roots = HashMap::new();
    roots.insert(0, engine.get_state_root().await);
    let mut prev = [0u8; 32];
    for h in 1..=tip {
        let root_before = engine.get_state_root().await;
        let proposer_id = vs.proposer_for(h, 0).expect("non-empty set has a proposer");
        let proposer = ks
            .iter()
            .find(|k| k.verifying_key().to_bytes() == proposer_id)
            .expect("proposer is a member")
            .clone();
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: h,
            prev_hash: prev,
            state_root: root_before,
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 1_000 + h,
            proposer: proposer.verifying_key().to_bytes(),
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
        };
        b.sign_block(&proposer);
        let bh = b.compute_hash();
        attach_quorum(&mut b, ks, h, bh);
        prev = bh;
        blocks.push(b);
        engine
            .update_account(AccountState::new(effect_account(h), effect_balance(h)))
            .await;
        if h == 150 {
            // A live-chain stake, mid-history: whoever restores height 300+
            // without the ledger restores the WRONG validator set.
            let id = bonded.verifying_key().to_bytes();
            engine
                .credit_native(&id, 100_000 * 1_000_000_000)
                .await
                .expect("faucet credit must apply");
            engine
                .staking_write()
                .await
                .bond(id, 5 * stellereum::staking::MIN_VALIDATOR_BOND, 0)
                .expect("mid-chain bond must apply");
        }
        roots.insert(h, engine.get_state_root().await);
        if h % 100 == 0 {
            snapshots.insert(h, engine.create_snapshot().await);
            let staking = engine.staking_read().await.clone();
            let gov = engine.governance_read().await.clone();
            let dom = stellereum::storage::DomainSnapshot::capture(&engine, &staking, &gov).await;
            domains.insert(h, bincode::serialize(&dom).unwrap());
        }
    }
    (
        LiveChain {
            blocks,
            snapshots,
            domains,
            roots,
        },
        engine,
    )
}

/// Transport fake: pruned, flaky, and once-dishonest — the weak-link + stale
/// peer shape from the C incident. Every miss/timeout/stale event is counted
/// so the test can prove the bootstrap survived them rather than never
/// meeting them.
struct FlakyPeers<'a> {
    chain: &'a LiveChain,
    tip: u64,
    keep: u64,
    /// Snapshot fetches to drop before serving (weak link).
    snapshot_misses_left: Arc<AtomicU64>,
    /// Header fetches to drop before serving (DHT blindness).
    header_misses_left: Arc<AtomicU64>,
    /// Domain fetches served STALE (garbage) before the genuine blob.
    stale_domains_left: Arc<AtomicU64>,
    /// Body fetches to drop once each (slow peer on a weak link).
    flaked_bodies: std::sync::Mutex<std::collections::HashSet<[u8; 32]>>,
    /// Counters: proof the run was genuinely adversarial.
    n_snapshot_miss: Arc<AtomicU64>,
    n_header_miss: Arc<AtomicU64>,
    n_stale_domain: Arc<AtomicU64>,
    n_body_miss: Arc<AtomicU64>,
}

impl<'a> FlakyPeers<'a> {
    fn retained(&self, h: u64) -> bool {
        h > self.tip.saturating_sub(self.keep)
    }

    fn link_at(&self, h: u64) -> Option<HeaderLink> {
        if self
            .header_misses_left
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            self.n_header_miss.fetch_add(1, Ordering::SeqCst);
            return None; // timeout on a weak link: retried, never trusted
        }
        if h == 0 || h > self.tip || !self.retained(h) {
            return None;
        }
        let b = self.chain.blocks.get(h as usize - 1)?;
        if b.height != h {
            return None;
        }
        Some(HeaderLink {
            height: b.height,
            block_hash: b.compute_hash(),
            prev_hash: b.prev_hash,
            state_root: b.state_root,
            proposer: b.proposer,
            qc: b.precommit_qc.clone()?,
        })
    }

    fn snapshot_at(&self, h: u64) -> Option<Vec<u8>> {
        if self
            .snapshot_misses_left
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            self.n_snapshot_miss.fetch_add(1, Ordering::SeqCst);
            return None; // miss/timeout: honest retry, same boundary
        }
        self.chain.snapshots.get(&h).cloned()
    }

    fn domain_at(&self, h: u64, kind: &str) -> Option<Vec<u8>> {
        if kind != "domains" {
            return None; // this chain only exercises accounts + staking ledger
        }
        if self
            .stale_domains_left
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            self.n_stale_domain.fetch_add(1, Ordering::SeqCst);
            return Some(vec![0xFF; 64]); // PRESENT but garbage: must be REJECTED
        }
        self.chain.domains.get(&h).cloned()
    }

    fn body_at(&self, hash: &[u8; 32]) -> Option<Block> {
        {
            let mut flaked = self.flaked_bodies.lock().unwrap();
            if !flaked.contains(hash) {
                flaked.insert(*hash);
                self.n_body_miss.fetch_add(1, Ordering::SeqCst);
                return None; // first ask per body is dropped on a weak link
            }
        }
        let b = self
            .chain
            .blocks
            .iter()
            .find(|b| b.compute_hash() == *hash)?
            .clone();
        if !self.retained(b.height) {
            return None;
        }
        (b.compute_hash() == *hash).then_some(b)
    }
}

/// The criterion, end to end: FRESH observer (genesis engine, zero manual
/// bytes) → snapshot-sync with ledger → body walk → tip, across misses,
/// timeouts and a stale domain blob.
#[tokio::test]
async fn node_bootstrap_reaches_tip_from_zero_over_weak_link_and_stale_peers() {
    const TIP: u64 = 350;
    const KEEP: u64 = 120;
    let ks = observer_keys(2);
    let bonded = SigningKey::generate(&mut OsRng);
    let bonded_id = bonded.verifying_key().to_bytes();
    let vs = observer_vset(&ks);
    let (chain, source_engine) = build_live_chain(&ks, &bonded, TIP).await;
    let source_tip_root = source_engine.get_state_root().await;
    // The bond is real on the source: the observer must inherit it via the
    // domains blob, not via any manual copy.
    assert!(
        source_engine
            .staking_read()
            .await
            .to_validator_set()
            .power_of(&bonded_id)
            > 0,
        "the source chain must carry the mid-chain bond, or the ledger half proves nothing"
    );

    let peers = FlakyPeers {
        chain: &chain,
        tip: TIP,
        keep: KEEP,
        snapshot_misses_left: Arc::new(AtomicU64::new(2)),
        header_misses_left: Arc::new(AtomicU64::new(3)),
        stale_domains_left: Arc::new(AtomicU64::new(1)),
        flaked_bodies: std::sync::Mutex::new(std::collections::HashSet::new()),
        n_snapshot_miss: Arc::new(AtomicU64::new(0)),
        n_header_miss: Arc::new(AtomicU64::new(0)),
        n_stale_domain: Arc::new(AtomicU64::new(0)),
        n_body_miss: Arc::new(AtomicU64::new(0)),
    };

    // The observer starts from NOTHING: a genesis engine, no copied bytes.
    // (This is the "БЕЗ ручного копирования" half: the only inputs are
    // fetched blobs, every one verified before commit.)
    let observer_engine = InMemoryStateEngine::new();
    assert_eq!(
        observer_engine.get_state_root().await,
        InMemoryStateEngine::new().get_state_root().await,
        "the observer must start at genesis, not from a copy"
    );

    // --- Stage 2: snapshot-sync with the REAL bootstrap planner -------------
    let boundary = bootstrap::select_bootstrap_boundary(TIP, 0, Some(300))
        .expect("a 350-tip chain must offer a snapshot boundary");
    assert_eq!(boundary, 300);
    let mut consecutive_stale = 0u32;
    let current = boundary;
    let committed = loop {
        // Tail-anchored proof, over dropping headers: a miss retries the
        // SAME window (absence is transient), never a skip.
        let mut trusted = None;
        for _ in 0..25 {
            match verify_snapshot_anchor_tail(current + 1, &vs, |h| {
                let l = peers.link_at(h);
                async move { l }
            })
            .await
            {
                Ok(root) => {
                    trusted = Some(root);
                    break;
                }
                Err(_) => continue,
            }
        }
        let trusted = trusted.expect("the tail window is retained: it must anchor");
        assert_eq!(
            trusted.state_root, chain.roots[&current],
            "the trusted root is the post-boundary state the snapshot must hash to"
        );
        // State + domains, with the flaky transport: misses retry the same
        // boundary, STALE domains count toward stepping to an older one.
        let snap = loop {
            if let Some(s) = peers.snapshot_at(current) {
                break s;
            }
        };
        let res = fast_sync_state(
            &observer_engine,
            trusted.state_root,
            || async { Some(snap.clone()) },
            |kind: &'static str| {
                let d = peers.domain_at(current, kind);
                async move { d }
            },
        )
        .await;
        match res {
            Ok(()) => break current,
            Err(e) => {
                // The stale `domains` blob must FAIL here (rejected, never
                // committed): the retry below is what makes it honest.
                assert!(
                    e.contains("domains") || e.contains("root mismatch") || e.contains("restore"),
                    "a stale bundle must fail LOUDLY with a domain/root cause, got: {e}"
                );
                consecutive_stale += 1;
                assert!(
                    consecutive_stale <= bootstrap::BOOTSTRAP_MAX_STALE_PER_BOUNDARY,
                    "one stale blob must not exhaust the per-boundary budget"
                );
                match bootstrap::next_boundary_after_stale(current, consecutive_stale, 0) {
                    Some(next) => {
                        assert_eq!(
                            next, current,
                            "budget holds: the SAME boundary is retried, not abandoned"
                        );
                        continue;
                    }
                    None => panic!("a single stale blob must never strand bootstrap"),
                }
            }
        }
    };
    assert_eq!(committed, 300);
    assert_eq!(observer_engine.get_state_root().await, chain.roots[&300]);

    // The LEDGER arrived with the domains blob: the bonded key has power on
    // the observer without any manual copy.
    assert!(
        observer_engine
            .staking_read()
            .await
            .to_validator_set()
            .power_of(&bonded_id)
            > 0,
        "the observer must inherit the mid-chain bond via the snapshot domains blob"
    );

    // --- Stage 3: walk the remainder over dropping bodies --------------------
    let tip_block = &chain.blocks[(TIP - 1) as usize];
    let tip_hash = tip_block.compute_hash();
    let boundary_block = &chain.blocks[(committed - 1) as usize];
    let boundary_hash = boundary_block.compute_hash();
    // Each dropped body aborts one whole walk attempt (fail-closed), so a
    // 50-height remainder with one drop per body needs up to 51 attempts —
    // exactly the honest-retry shape a weak link produces live.
    let mut walked = None;
    for _ in 0..60 {
        if let Ok(w) = collect_missing_blocks(tip_hash, boundary_hash, 1_000_000, |h| {
            let b = peers.body_at(&h);
            async move { b }
        })
        .await
        {
            walked = Some(w);
            break;
        }
    }
    let walked = walked.expect("post-snapshot bodies are retained: the walk must complete");
    validate_sync_chain_for_shard(
        &walked,
        committed + 1,
        boundary_hash,
        &vs,
        MASTERCHAIN_SHARD,
    )
    .expect("the remainder carries a genuine quorum per height");
    for b in &walked {
        let ours = observer_engine.get_state_root().await;
        assert_eq!(
            b.state_root, ours,
            "block {} must extend our state",
            b.height
        );
        observer_engine
            .update_account(AccountState::new(
                effect_account(b.height),
                effect_balance(b.height),
            ))
            .await;
    }
    assert_eq!(walked.last().unwrap().compute_hash(), tip_hash);
    assert_eq!(
        observer_engine.get_state_root().await,
        source_tip_root,
        "the observer converges on the source tip state EXACTLY — no manual copy involved"
    );

    // Proof the run was genuinely adversarial: misses, header drops, a stale
    // domain and body drops all fired — and were all survived by retries.
    assert!(
        peers.n_snapshot_miss.load(Ordering::SeqCst) >= 2,
        "snapshot misses must have fired"
    );
    assert!(
        peers.n_header_miss.load(Ordering::SeqCst) >= 1,
        "header drops must have fired"
    );
    assert_eq!(
        peers.n_stale_domain.load(Ordering::SeqCst),
        1,
        "exactly one stale domain blob, rejected once"
    );
    assert!(
        peers.n_body_miss.load(Ordering::SeqCst) >= 1,
        "body drops must have fired"
    );
}
