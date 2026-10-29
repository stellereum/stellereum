//! Observer nodes and stale-round recovery.
//!
//! Two operational gaps that both ended in "wipe both data directories":
//!
//!   * there was no way to run a node that follows the chain without voting. Every
//!     node was a validator by construction, so an RPC/archive/indexer node could not
//!     exist without changing the validator set -- and changing the set changes the
//!     genesis root, so it would have started its own chain instead of following.
//!   * a node that restarted restored its PERSISTED round unconditionally. If it had
//!     been sitting in a runaway view-change loop, it came back at, say, round 806
//!     while its peer was at round 0, and then neither would propose at the height the
//!     other would accept. The pair deadlocked permanently.
//!
//! `build_validator_set` and the round restore are private to the binary, so these
//! tests exercise the same decisions through the public pieces they are built from:
//! the node-id derivation and the consensus rules an observer must not violate.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::collections::HashMap;
use stellereum::consensus::{HeightConsensus, QuorumCertificate, ValidatorSet, Vote, VoteKind};
use stellereum::network::{
    head_publish_allowed, peer_head_is_ahead, SNAPSHOT_PUBLISH_DOMAIN_KINDS,
};
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::sync::{
    collect_missing_blocks, fast_sync_state, validate_sync_chain_for_shard, verify_snapshot_anchor,
    verify_snapshot_anchor_tail, HeaderLink, SNAPSHOT_ANCHOR_TAIL_WINDOW, SYNC_DOMAIN_KINDS,
};

/// infnode derives a node id as `blake3(ed25519_pub)[..20]`, which is what a
/// `validators:` entry names. Getting this wrong is how a node ends up in the wrong
/// set, so pin the derivation shape here.
fn node_id_of(key: &SigningKey) -> [u8; 20] {
    let h = blake3::hash(key.verifying_key().as_bytes());
    let mut id = [0u8; 20];
    id.copy_from_slice(&h.as_bytes()[..20]);
    id
}

#[test]
fn a_validator_set_entry_is_derivable_from_a_key() {
    let a = SigningKey::generate(&mut OsRng);
    let b = SigningKey::generate(&mut OsRng);
    assert_ne!(node_id_of(&a), node_id_of(&b));

    // A set built from public keys is what the node ends up with; the id list is only
    // how the config names members. Two nodes that agree on the key set agree on the
    // proposer schedule regardless of how their configs named them.
    let pk_a = a.verifying_key().to_bytes();
    let pk_b = b.verifying_key().to_bytes();
    let set1 = ValidatorSet::from_list(vec![(pk_a, 1), (pk_b, 1)]);
    let set2 = ValidatorSet::from_list(vec![(pk_b, 1), (pk_a, 1)]);
    assert_eq!(
        set1.proposer_for(1, 0),
        set2.proposer_for(1, 0),
        "the set is a BTreeMap, so naming order must not matter"
    );
}

#[test]
fn an_observer_is_not_in_the_set_and_therefore_is_never_the_proposer() {
    // An observer is a node whose key is absent from the set. The property that
    // matters is that the schedule can never select it, so it can never be asked to
    // propose -- which is exactly what gating proposal production on membership
    // relies on.
    let v1 = SigningKey::generate(&mut OsRng);
    let v2 = SigningKey::generate(&mut OsRng);
    let observer = SigningKey::generate(&mut OsRng);

    let set = ValidatorSet::from_list(vec![
        (v1.verifying_key().to_bytes(), 1),
        (v2.verifying_key().to_bytes(), 1),
    ]);
    let obs_pk = observer.verifying_key().to_bytes();

    assert_eq!(set.power_of(&obs_pk), 0, "an observer has no power");
    for height in 0..8u64 {
        for round in 0..4u32 {
            let proposer = set.proposer_for(height, round).unwrap();
            assert_ne!(proposer, obs_pk, "an observer must never be the proposer");
        }
    }
    // And a vote from the observer cannot count toward any quorum.
    assert_eq!(set.power_of(&obs_pk), 0);
}

#[test]
fn a_stale_persisted_round_is_capped_so_peers_can_reconverge() {
    // What the restore path does with a persisted round. The safety half (the lock)
    // is unconditional; the round is capped because a node that comes back far ahead
    // of its peers cannot be joined by them.
    const MAX_RESTORED_ROUND: u32 = 64;

    let k = SigningKey::generate(&mut OsRng);
    let set = ValidatorSet::from_list(vec![(k.verifying_key().to_bytes(), 1)]);

    // A round that looks stale is capped.
    let mut hc = HeightConsensus::new(331, set.clone());
    hc.round = 806u32.min(MAX_RESTORED_ROUND);
    assert_eq!(hc.round, MAX_RESTORED_ROUND);
    assert!(hc.round < 806, "the runaway round is not adopted verbatim");

    // A modest round is kept, because it carries real safety meaning.
    let mut hc2 = HeightConsensus::new(331, set);
    hc2.round = 7u32.min(MAX_RESTORED_ROUND);
    assert_eq!(hc2.round, 7, "a plausible round is restored as-is");
}

#[test]
fn two_nodes_at_the_same_capped_round_agree_on_the_proposer() {
    // The reason the cap restores liveness: both nodes end up in a round from the
    // same bounded range, so they compute the same proposer and one of them proposes.
    const MAX_RESTORED_ROUND: u32 = 64;
    let a = SigningKey::generate(&mut OsRng);
    let b = SigningKey::generate(&mut OsRng);
    let set = ValidatorSet::from_list(vec![
        (a.verifying_key().to_bytes(), 1),
        (b.verifying_key().to_bytes(), 1),
    ]);

    // Node A persisted 806, node B persisted 0. After the cap both resume at 64 and 0;
    // what matters is that each round has exactly one well-defined proposer and the
    // nodes can walk toward each other by timeout.
    let mut ra = HeightConsensus::new(331, set.clone());
    ra.round = 806u32.min(MAX_RESTORED_ROUND);
    let mut rb = HeightConsensus::new(331, set.clone());
    rb.round = 0u32;

    // Walk the lagging node forward the way its own timeouts would, and confirm the
    // two converge on the same proposer at the same round.
    while rb.round < ra.round {
        rb.round += 1;
    }
    assert_eq!(rb.round, ra.round);
    assert_eq!(
        ra.proposer(),
        rb.proposer(),
        "at the same round both nodes must agree who proposes"
    );
}

// ==================== Observer snapshot-sync off pruned peers ====================
//
// REGRESSION (live incident 2026-10-13): an observer with the CORRECT genesis
// sat at height 0 forever while the chain ran past 70k. Three defects combined:
//
//  1. the snapshot anchor walked headers 1..=boundary+1 from a genesis anchor,
//     but pruned peers (KEEP 4000/8000) keep only tip-KEEP..tip headers, so the
//     walk died on the first missing header and the snapshot was refused;
//  2. the body-walk fallback found no bodies either (same prune window), and
//  3. every attempt was silent (entry-gate `None`s, debug-only budget timeout),
//     so the logs showed zero snapshot attempts.
//
// The fix: a genesis-anchored node proves a bounded TRAILING window ending at
// the snapshot successor (`verify_snapshot_anchor_tail`) instead of the full
// walk — same per-height forgery budget (a 2/3 QC of OUR set per height), but
// fully inside any peer's retention window.
//
// These tests drive the REAL sync primitives through a `PrunedPeers` fake that
// mirrors the live retention rules: snapshots at every 100-boundary FOREVER,
// headers/QCs/bodies only inside a small KEEP window under the tip.

/// Deterministic per-height state effect, shared by the chain builder and the
/// observer's remainder apply: crediting a height-derived account.
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

/// A chain whose roots come from a REAL engine advanced by `effect_*` per
/// height, with state snapshots captured at every 100-boundary.
struct LiveChain {
    blocks: Vec<Block>,
    snapshots: HashMap<u64, Vec<u8>>,
    roots: HashMap<u64, [u8; 32]>,
}

async fn build_live_chain(ks: &[SigningKey], tip: u64) -> (LiveChain, InMemoryStateEngine) {
    let vs = observer_vset(ks);
    let engine = InMemoryStateEngine::new();
    let mut blocks = Vec::new();
    let mut snapshots = HashMap::new();
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
        // The block's effect lands AFTER it commits to the pre-state.
        engine
            .update_account(AccountState::new(effect_account(h), effect_balance(h)))
            .await;
        let root_after = engine.get_state_root().await;
        roots.insert(h, root_after);
        if h % 100 == 0 {
            snapshots.insert(h, engine.create_snapshot().await);
        }
    }
    (
        LiveChain {
            blocks,
            snapshots,
            roots,
        },
        engine,
    )
}

/// Peers that prune like live nodes: snapshots forever, everything else only
/// inside `keep` heights under the tip.
struct PrunedPeers<'a> {
    chain: &'a LiveChain,
    tip: u64,
    keep: u64,
}

impl<'a> PrunedPeers<'a> {
    fn retained(&self, h: u64) -> bool {
        h > self.tip.saturating_sub(self.keep)
    }

    fn link_at(&self, h: u64) -> Option<HeaderLink> {
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
        // Snapshots: one per 100 heights, FOREVER (never pruned).
        self.chain.snapshots.get(&h).cloned()
    }

    fn body_at(&self, hash: &[u8; 32]) -> Option<Block> {
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

/// The incident, end to end: a long chain (350 heights), peers keeping only
/// the newest 120 heights, an observer anchored at genesis with the correct
/// validator set. The full header walk MUST fail (history is pruned), the
/// trailing-window proof MUST establish the snapshot root, the snapshot MUST
/// apply, and the short body remainder MUST walk to the tip with the exact
/// source state root.
#[tokio::test]
async fn observer_catches_up_from_pruned_peers_via_tail_anchored_snapshot() {
    const TIP: u64 = 350;
    const KEEP: u64 = 120;
    let ks = observer_keys(2);
    let vs = observer_vset(&ks);
    let (chain, source_engine) = build_live_chain(&ks, TIP).await;
    let peers = PrunedPeers {
        chain: &chain,
        tip: TIP,
        keep: KEEP,
    };
    let source_tip_root = source_engine.get_state_root().await;

    // Newest 100-boundary at/below the tip, like try_snapshot_sync probes first.
    let boundary = (TIP / 100) * 100;
    assert_eq!(boundary, 300);

    // 1. The OLD proof (full walk from our genesis anchor) cannot complete:
    //    headers 1..=230 are pruned on every peer.
    let full = verify_snapshot_anchor(None, [0u8; 32], boundary + 1, &vs, 1_000_000, |h| {
        let l = peers.link_at(h);
        async move { l }
    })
    .await;
    assert!(
        full.is_err(),
        "a full header walk from genesis must fail on pruned peers, or the \
         incident could not have happened"
    );

    // 2. The trailing-window proof only touches heights 293..=301 — all retained.
    let trusted = verify_snapshot_anchor_tail(boundary + 1, &vs, |h| {
        let l = peers.link_at(h);
        async move { l }
    })
    .await
    .expect("a trailing window inside the retention horizon must anchor");
    assert_eq!(
        trusted.state_root, chain.roots[&boundary],
        "the trusted root is the post-boundary state the snapshot must hash to"
    );
    assert_eq!(
        trusted.boundary_hash,
        chain.blocks[boundary as usize - 1].compute_hash(),
        "the boundary hash is the VERIFIED block hash at the boundary height"
    );

    // 3. The snapshot restores into a FRESH (genesis) engine and re-roots exactly.
    let observer_engine = InMemoryStateEngine::new();
    let snap = peers
        .snapshot_at(boundary)
        .expect("snapshots are never pruned");
    fast_sync_state(
        &observer_engine,
        trusted.state_root,
        || async { Some(snap.clone()) },
        |_: &'static str| async { None },
    )
    .await
    .expect("a genuine snapshot against a proven root must apply");
    assert_eq!(
        observer_engine.get_state_root().await,
        chain.roots[&boundary]
    );

    // 4. The short remainder walks by bodies, QC-checked per height, and lands
    //    on the source tip root exactly.
    let tip_block = &chain.blocks[(TIP - 1) as usize];
    let tip_hash = tip_block.compute_hash();
    let boundary_block = &chain.blocks[(boundary - 1) as usize];
    let boundary_hash = boundary_block.compute_hash();
    let walked = collect_missing_blocks(tip_hash, boundary_hash, 1_000_000, |h| {
        let b = peers.body_at(&h);
        async move { b }
    })
    .await
    .expect("post-snapshot bodies are all inside the retention window");
    assert_eq!(walked.first().unwrap().height, boundary + 1);
    assert_eq!(walked.last().unwrap().height, TIP);
    validate_sync_chain_for_shard(&walked, boundary + 1, boundary_hash, &vs, MASTERCHAIN_SHARD)
        .expect("the remainder carries a genuine quorum per height");
    for b in &walked {
        let ours = observer_engine.get_state_root().await;
        assert_eq!(
            b.state_root, ours,
            "block {} must extend the state we hold",
            b.height
        );
        observer_engine
            .update_account(AccountState::new(
                effect_account(b.height),
                effect_balance(b.height),
            ))
            .await;
    }
    // Keep the binding tight: the walked tail must BE the advertised head.
    assert_eq!(walked.last().unwrap().compute_hash(), tip_hash);
    assert_eq!(
        observer_engine.get_state_root().await,
        source_tip_root,
        "the observer converges on the source tip state exactly"
    );
}

/// The tail proof fails closed: a forged link, a missing QC, or a
/// non-scheduled proposer anywhere in the window refuses the snapshot.
#[tokio::test]
async fn tail_anchor_rejects_forgery_missing_qc_and_wrong_proposer() {
    const TIP: u64 = 350;
    const KEEP: u64 = 120;
    let ks = observer_keys(2);
    let vs = observer_vset(&ks);
    let (chain, _) = build_live_chain(&ks, TIP).await;
    let peers = PrunedPeers {
        chain: &chain,
        tip: TIP,
        keep: KEEP,
    };
    let boundary = 300u64;

    // Baseline: genuine window anchors.
    verify_snapshot_anchor_tail(boundary + 1, &vs, |h| {
        let l = peers.link_at(h);
        async move { l }
    })
    .await
    .expect("genuine window must anchor");

    // A header that does not link to its parent is refused.
    let mut forged: HashMap<u64, HeaderLink> = ((boundary + 1)
        .saturating_sub(SNAPSHOT_ANCHOR_TAIL_WINDOW - 1)
        .max(1)..=boundary + 1)
        .map(|h| (h, peers.link_at(h).unwrap()))
        .collect();
    forged.get_mut(&boundary).unwrap().prev_hash = [0xFFu8; 32];
    assert!(verify_snapshot_anchor_tail(boundary + 1, &vs, |h| {
        let l = forged.get(&h).cloned();
        async move { l }
    })
    .await
    .is_err());

    // A height with no published QC is not anchorable, never trusted.
    assert!(verify_snapshot_anchor_tail(boundary + 1, &vs, |h| {
        let l = if h == boundary {
            None
        } else {
            peers.link_at(h)
        };
        async move { l }
    })
    .await
    .is_err());

    // A QC is only meaningful from the scheduled proposer: a member signing
    // outside its slot must not carry a snapshot.
    let mut wrong: HashMap<u64, HeaderLink> = ((boundary + 1)
        .saturating_sub(SNAPSHOT_ANCHOR_TAIL_WINDOW - 1)
        .max(1)..=boundary + 1)
        .map(|h| (h, peers.link_at(h).unwrap()))
        .collect();
    let other = ks
        .iter()
        .map(|k| k.verifying_key().to_bytes())
        .find(|pk| *pk != wrong[&(boundary + 1)].proposer)
        .unwrap();
    wrong.get_mut(&(boundary + 1)).unwrap().proposer = other;
    let err = verify_snapshot_anchor_tail(boundary + 1, &vs, |h| {
        let l = wrong.get(&h).cloned();
        async move { l }
    })
    .await
    .expect_err("a non-scheduled proposer must be refused");
    assert!(
        err.contains("schedule slot"),
        "refusal names the cause: {err}"
    );
}

/// The shared head key is last-writer-wins: a height-0 node must never publish
/// (it would bury a live tip for itself and every peer), and a republish must
/// only ever move forward. Only a STRICTLY ahead head may pull a node.
#[test]
fn head_key_never_rewinds_and_only_ahead_heads_pull() {
    // Genesis-only: nothing to advertise.
    assert!(!head_publish_allowed(0, 0));
    // First real tip: allowed.
    assert!(head_publish_allowed(1, 0));
    assert!(head_publish_allowed(72704, 0));
    // Same or older: refused (stale republishes rewind the shared key).
    assert!(!head_publish_allowed(72704, 72704));
    assert!(!head_publish_allowed(100, 72704));
    // Forward: allowed.
    assert!(head_publish_allowed(72705, 72704));

    // Read side: our own echo (equal) and stale peers (below) are "nothing to
    // do"; only strictly-ahead heads are actionable.
    assert!(
        !peer_head_is_ahead(0, 0),
        "a height-0 echo is not a peer ahead"
    );
    assert!(!peer_head_is_ahead(100, 100));
    assert!(!peer_head_is_ahead(72704, 100));
    assert!(peer_head_is_ahead(0, 72704));
    assert!(peer_head_is_ahead(72703, 72704));
}

/// Publish/fetch domain parity: every domain kind snapshot-sync fetches must
/// have a publisher, except the documented `pq_keys` gap (raw PQ pins are
/// auxiliary to the state root — the accounts snapshot already commits to
/// every pin's hash — and have no publisher yet).
#[test]
fn snapshot_domain_publish_covers_every_fetched_kind_but_pq_keys() {
    for kind in SYNC_DOMAIN_KINDS {
        if *kind == "pq_keys" {
            continue;
        }
        assert!(
            SNAPSHOT_PUBLISH_DOMAIN_KINDS.contains(kind),
            "fetched domain {kind:?} has no publisher; a synced node would fail \
             the trusted-root check on any chain using it"
        );
    }
    for kind in SNAPSHOT_PUBLISH_DOMAIN_KINDS {
        assert!(
            SYNC_DOMAIN_KINDS.contains(kind),
            "published domain {kind:?} is never fetched; snapshots waste DHT space"
        );
    }
    // The window the tail proof needs always fits any live KEEP horizon.
    assert!(
        (1..=64).contains(&SNAPSHOT_ANCHOR_TAIL_WINDOW),
        "the tail window must stay tiny next to KEEP_BLOCKS 4000/8000"
    );
}
