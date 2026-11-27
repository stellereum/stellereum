use std::sync::Arc;
use tracing::info;

use crate::node::policy::*;
use stellereum::consensus_net::{ConsensusMsg, ConsensusNetwork};
use stellereum::network::P2pNetworkAdapter;
use stellereum::runtime::ValidatorRuntime;

/// A blind-QC-probe sidecar is only usable as catch-up EVIDENCE (it can scale
/// the pass budget and re-arm the reactive latch) when it is a GENUINE
/// precommit quorum for exactly that height and block under the set in force
/// there. Decoding plus a height match is not enough: a hostile DHT peer can
/// publish a well-formed `QuorumCertificate` struct with no signatures, and
/// trusting it would let a forged sidecar pin the node in an expensive
/// catch-up pass (the old blind anchor paid a bounded one-shot cost; the
/// hint/latch plumbing makes the evidence persistent, so it must be verified).
fn verified_qc_sidecar_hash(
    rt: &ValidatorRuntime,
    qc: &stellereum::consensus::QuorumCertificate,
    height: u64,
) -> Option<[u8; 32]> {
    if qc.kind != stellereum::consensus::VoteKind::Precommit || qc.height != height {
        return None;
    }
    let bh = qc.block_hash?;
    let validators = rt.validator_set_for_height_strict(height)?;
    if !qc.verify_with_schedule(&validators, rt.committee_schedule_at(height)) {
        return None;
    }
    Some(bh)
}

/// PUSH-BASED BLOCK PROPAGATION (fast path): hand a finalized block's commit
/// to every directly connected validator peer IMMEDIATELY.
///
/// The DHT publication (head pointer, body, header) is untouched and stays the
/// slow/recovery path — this only adds the direct one. `ConsensusNetwork`
/// delivers `pubsub.msg` straight to each configured peer's app subscription
/// (per-peer, concurrent, bounded by the broadcast join budget), which is the
/// channel the consensus drain already consumes, so a lagging peer sees the
/// `Committed` on its next tick instead of waiting for its next DHT poll.
///
/// Runs DETACHED on purpose: the consensus tick calls this at finalize and
/// must not wait for any peer's ACK (a slow peer once stretched every height
/// by the per-peer round trip). Sends are idempotent, and `ConsensusNetwork`'s
/// health ledger/backoff is unchanged.
pub(crate) fn spawn_committed_push(
    net: &Arc<ConsensusNetwork>,
    height: u64,
    block: stellereum::sharding::Block,
    certificate: stellereum::consensus::QuorumCertificate,
) {
    let net = Arc::clone(net);
    tokio::spawn(async move {
        net.broadcast(&ConsensusMsg::Committed {
            height,
            block,
            certificate,
        })
        .await;
        tracing::debug!("[sync][push] committed #{height} pushed to every directly connected peer");
    });
}

/// Awaitable form of [`spawn_committed_push`] for callers that already run off
/// the tick (the body walk after a successful catch-up).
pub(crate) async fn push_committed(
    net: &ConsensusNetwork,
    height: u64,
    block: stellereum::sharding::Block,
    certificate: stellereum::consensus::QuorumCertificate,
) {
    net.broadcast(&ConsensusMsg::Committed {
        height,
        block,
        certificate,
    })
    .await;
}

/// Try to catch up from a state SNAPSHOT plus the headers above it.
///
/// Returns `Some(height)` when a snapshot was found, verified and applied.
///
/// This is what makes recovery independent of the block-retro-publish depth, INCLUDING
/// a cold start at genesis. The chain of trust, and every root in it, comes from a
/// HEADER -- never from the snapshot:
///
///   1. walk headers down from the peer's head, one height at a time, verifying that
///      each header's hash is the one the parent names. A header is small and is
///      published for every block, so this works for a gap of any size, unlike bodies;
///   2. stop at the newest 100-height boundary `B` that a peer has a snapshot for;
///   3. the header at `B + 1` commits to the state AFTER block `B`, which is exactly
///      what a state snapshot at height `B` must hash to. That is the trusted root;
///   4. `fast_sync_state` restores the snapshot into a throwaway engine and requires
///      that exact root before committing, so a poisoned snapshot cannot touch live
///      state;
///   5. resume consensus at `B + 1`; the short remaining gap is covered by the body
///      walk and the retro-publish window.
///
/// Anchoring: the walk is accepted because every header is hash-linked to its parent,
/// so the only thing a peer can do is offer a chain, and the chain is pinned to the
/// head it advertised. It cannot substitute a different history for the same height
/// without breaking a hash link. (Pinning the walk to the locally-derived genesis
/// header would be stronger still and is noted in PROTOCOL.md as the next step; it
/// requires the genesis header to be published by every node, which is now done.)
#[allow(dead_code)]
// GATE: 4-arg compatibility wrapper used by integration tests via #[path = "../src/node/sync.rs"].
pub(crate) async fn try_snapshot_sync(
    adapter: &Arc<P2pNetworkAdapter>,
    rt: &mut ValidatorRuntime,
    shard: u32,
    peer_height: u64,
) -> Option<u64> {
    try_snapshot_sync_with_persistence(adapter, rt, shard, peer_height, None).await
}

async fn wait_snapshot_persistence_drain(
    ap: &stellereum::storage::AsyncPersistence,
    boundary: u64,
) -> Result<(), &'static str> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let drained = ap.pending() == 0
            && ap.storage().get_state(boundary).ok().flatten().is_some()
            && ap.storage().domain_at(boundary).ok().flatten().is_some()
            && ap
                .storage()
                .finalized()
                .ok()
                .flatten()
                .is_some_and(|(h, _)| h >= boundary);
        if drained {
            let _ = ap.storage().flush();
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(
                "snapshot persistence drain timed out; refusing to advance safety ahead of disk",
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
}

pub(crate) async fn try_snapshot_sync_with_persistence(
    adapter: &Arc<P2pNetworkAdapter>,
    rt: &mut ValidatorRuntime,
    shard: u32,
    peer_height: u64,
    persistence: Option<&std::sync::Arc<stellereum::storage::AsyncPersistence>>,
) -> Option<u64> {
    let our_height = rt.finalized.last().map(|(h, _)| *h).unwrap_or(0);
    if peer_height <= our_height + 1 {
        return None;
    }
    // Visible attempts: a node that never gets past the entry gate (no peer
    // head, or never ahead) leaves zero trace, which once hid a dead transport
    // for hours. Throttled so the 2s catch-up cadence does not spam.
    static SNAP_ATTEMPT_N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let attempt = SNAP_ATTEMPT_N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // Genesis-anchored (fresh observer, empty finalized chain) or continuing
    // our own chain: the anchor mode decides the header proof below.
    let genesis_anchored = rt.finalized.last().is_none();
    // Gap-aware anchor: a full walk from OUR head is only viable inside the
    // peers' retention window and only fast when short. Beyond
    // TAIL_ANCHOR_GAP_THRESHOLD the walk needs thousands of sequential
    // header+QC fetches (10+ min on a weak link, never fitting a tick
    // budget), while anything below tip−KEEP is pruned anyway. The trailing
    // window proves the same unforgeable fact (2/3 of OUR set per height —
    // a forked tip would need the real validators' keys), so use it.
    const TAIL_ANCHOR_GAP_THRESHOLD: u64 = 50;
    let use_tail_anchor =
        genesis_anchored || peer_height.saturating_sub(our_height) > TAIL_ANCHOR_GAP_THRESHOLD;
    if attempt.is_multiple_of(15) {
        info!(
            "[sync] snapshot-sync attempt {attempt}: peer={peer_height} ours={our_height} {}",
            if use_tail_anchor {
                "tail-anchored (trailing-window proof)"
            } else {
                "chain-anchored (full header walk)"
            }
        );
    } else {
        tracing::debug!(
            "[sync] snapshot-sync attempt {attempt}: peer={peer_height} ours={our_height}"
        );
    }

    // Probe snapshot boundaries downward. The window is derived from
    // `policy::snapshot_interval()` (audit F4), not a fixed 8 x 100 heights:
    // snapshots are published every `snapshot_interval()` heights (default
    // 1000) and pruning retains `3 * interval`, so a fixed 800-height walk
    // could land between two snapshots and never find the next one. The
    // window covers the proven worst-case publish gap (interval + catch-up
    // grid) with one extra interval of slack; it stays bounded, so a weak
    // link still spends only a few probes before giving up.
    let snap_int = crate::node::policy::snapshot_interval();
    let probe_step = stellereum::sync::snapshot_probe_step(snap_int);
    let probe_steps = stellereum::sync::snapshot_probe_steps(snap_int);
    let mut boundary = (peer_height / probe_step) * probe_step;
    // Latest-snapshot pointer first: snapshots complete on worker timing at
    // arbitrary heights (78519, 78620, ...), so fixed-grid probes miss them
    // all. A sane pointer (ahead of us, at or under the peer tip) jumps
    // straight to a usable boundary; otherwise the interval-spaced walk below
    // runs unchanged.
    if let Some(latest) = adapter.fetch_latest_snapshot(shard).await {
        if latest > our_height && latest <= peer_height {
            eprintln!(
                "[sync] snapshot-sync attempt {attempt}: latest-snapshot pointer at {latest} (peer={peer_height} ours={our_height})"
            );
            boundary = latest;
        }
    }
    // Silent fetch misses (no blob under this epoch/name yet) are counted and
    // summarized once per throttled attempt instead of per boundary: 128 lines
    // per 2s tick would bury the log, zero lines hid a dead network.
    let mut miss_snapshot = 0u64;
    let mut miss_header = 0u64;
    // Storm guard 2026-10-13: consecutive misses pace the probe loop. A tight
    // loop over 128 missing boundaries fired ~384 fetch_blobs back-to-back on
    // a 1-vCPU node, saturating the event loop (every request_to ~2.5s) and
    // starving consensus traffic behind the same 256 stream slots. Pacing
    // yields to the consensus sender; a hit resets the streak.
    let mut consecutive_misses: u32 = 0;
    for _ in 0..probe_steps {
        if boundary <= our_height || boundary == 0 {
            break;
        }

        // Trusted root: the header at boundary + 1, whose state_root is the state
        // after block `boundary`. Verify its identity and linkage explicitly rather
        // than trusting the transport.
        let Some(next_hash) = adapter.fetch_head_hash(shard, boundary + 1).await else {
            miss_header += 1;
            consecutive_misses = consecutive_misses.saturating_add(1);
            tokio::time::sleep(std::time::Duration::from_millis(
                stellereum::sync::snapshot_probe_pace_ms(consecutive_misses),
            ))
            .await;
            boundary = boundary.saturating_sub(probe_step);
            continue;
        };
        let Some(next_hdr) = adapter
            .fetch_block_header(shard, boundary + 1, next_hash)
            .await
        else {
            miss_header += 1;
            consecutive_misses = consecutive_misses.saturating_add(1);
            tokio::time::sleep(std::time::Duration::from_millis(
                stellereum::sync::snapshot_probe_pace_ms(consecutive_misses),
            ))
            .await;
            boundary = boundary.saturating_sub(probe_step);
            continue;
        };
        if next_hdr.height != boundary + 1 || next_hdr.block_hash != next_hash {
            miss_header += 1;
            consecutive_misses = consecutive_misses.saturating_add(1);
            tokio::time::sleep(std::time::Duration::from_millis(
                stellereum::sync::snapshot_probe_pace_ms(consecutive_misses),
            ))
            .await;
            boundary = boundary.saturating_sub(probe_step);
            continue;
        }

        // F1: the peer header is only trustworthy if it is part of OUR chain.
        // A1: linkage PLUS a precommit QC per height (verified against OUR
        // committed set, with the scheduled proposer). Hash linkage alone
        // accepts fully-forged chains; only quorum agreement proves finality.
        //
        // Verify the header anchor & QC BEFORE fetching any large snapshot blob
        // (up to 512 MiB) so an unanchored or forged boundary is refused before
        // paying the download cost.
        //
        // Which proof depends on the anchor:
        // * chain-anchored (we hold a finalized head): prove hash linkage from
        //   OUR head all the way up — continuity from our head is what stops a
        //   peer substituting a fork that diverges after it. Fail closed on
        //   any gap.
        // * genesis-anchored (fresh observer, nothing finalized): prove a
        //   bounded TRAILING window ending at the snapshot successor
        //   (`verify_snapshot_anchor_tail`). A full walk from height 1 is
        //   impossible on pruned peers (headers below tip − KEEP are gone) and
        //   proves nothing extra anyway: every chain roots at the zero
        //   prev-hash sentinel, so the walk shows "some QC-signed chain", which
        //   the window shows too, with the same per-height forgery budget (2/3
        //   of OUR set per height). Without this, a fresh observer on a long
        //   pruned chain can never snapshot-sync and sits at height 0 forever.
        let anchor_fetch = {
            let a = adapter.clone();
            move |h: u64| {
                let a = a.clone();
                async move {
                    let hash = a.fetch_head_hash(shard, h).await?;
                    if stellereum::sharding::header_commit_active_at(h) {
                        let rec_v2 = a.fetch_block_header_v2(shard, h, hash).await?;
                        let qc = a.fetch_block_qc(shard, h).await?;
                        return Some(stellereum::sync::HeaderLink::from_v2_record(&rec_v2, qc));
                    }
                    if let Some(rec_v2) = a.fetch_block_header_v2(shard, h, hash).await {
                        let qc = a.fetch_block_qc(shard, h).await?;
                        return Some(stellereum::sync::HeaderLink::from_v2_record(&rec_v2, qc));
                    }
                    let rec = a.fetch_block_header(shard, h, hash).await?;
                    let qc = a.fetch_block_qc(shard, h).await?;
                    Some(stellereum::sync::HeaderLink {
                        height: rec.height,
                        block_hash: rec.block_hash,
                        prev_hash: rec.prev_hash,
                        state_root: rec.state_root,
                        proposer: rec.proposer,
                        qc,
                        shard_id: shard,
                        round: 0,
                        body_commitment: None,
                        mmr_epoch_root: [0u8; 32],
                        epoch_key_commitment: [0u8; 32],
                        timestamp: rec.timestamp,
                    })
                }
            }
        };
        let anchor = if use_tail_anchor {
            // F5 set-at-height: each window height's QC is checked against the
            // strict set in force AT THAT height (`validator_set_for_height_strict`),
            // never the live set or a silent fallback.
            match stellereum::sync::verify_snapshot_anchor_tail_with_sets_and_schedule(
                boundary + 1,
                |h| rt.validator_set_for_height_strict(h),
                // Review F2: the same committee schedule the producer drew
                // under (epoch beacon at/after CN-VRF v3 activation, the
                // parent-hash draw below it).
                |h| rt.committee_schedule_at(h),
                anchor_fetch,
            )
            .await
            {
                Ok(a) => a,
                Err(e) => {
                    eprintln!(
                        "[sync] REFUSING snapshot at {boundary}: trailing header proof failed: {e}"
                    );
                    consecutive_misses = consecutive_misses.saturating_add(1);
                    tokio::time::sleep(std::time::Duration::from_millis(
                        stellereum::sync::snapshot_probe_pace_ms(consecutive_misses),
                    ))
                    .await;
                    boundary = boundary.saturating_sub(probe_step);
                    continue;
                }
            }
        } else {
            // F5 set-at-height: even a short-gap chain-anchored snapshot must
            // verify each height's QC and proposer slot against the exact set
            // in force AT THAT height, failing closed on any unknown height.
            match stellereum::sync::verify_snapshot_anchor_with_sets_and_schedule(
                rt.finalized.last().copied(),
                [0u8; 32],
                boundary + 1,
                |h| rt.validator_set_for_height_strict(h),
                // Review F2: header QCs are checked under the schedule in
                // force at each height, never a forced parent-hash draw.
                |h| rt.committee_schedule_at(h),
                1_000_000,
                anchor_fetch,
            )
            .await
            {
                Ok(a) => a,
                Err(e) => {
                    eprintln!(
                        "[sync] REFUSING snapshot at {boundary}: header anchor to our finalized \
                         head cannot be proven: {e}"
                    );
                    consecutive_misses = consecutive_misses.saturating_add(1);
                    tokio::time::sleep(std::time::Duration::from_millis(
                        stellereum::sync::snapshot_probe_pace_ms(consecutive_misses),
                    ))
                    .await;
                    boundary = boundary.saturating_sub(probe_step);
                    continue;
                }
            }
        };
        let trusted_root = anchor.state_root;
        let boundary_hash = anchor.boundary_hash;
        if next_hdr.prev_hash != boundary_hash {
            // The peer's successor header does not link to the VERIFIED
            // boundary block: the peer is serving an inconsistent (or forked)
            // view. Fail closed before touching `rt.state`.
            eprintln!(
                "[sync] REFUSING snapshot at {boundary}: successor header does not link to the verified boundary block"
            );
            consecutive_misses = consecutive_misses.saturating_add(1);
            tokio::time::sleep(std::time::Duration::from_millis(
                stellereum::sync::snapshot_probe_pace_ms(consecutive_misses),
            ))
            .await;
            boundary = boundary.saturating_sub(probe_step);
            continue;
        }
        // F5 set-at-height trust gate: the snapshot must additionally commit
        // to the strict validator set at `boundary`, and to exactly the set
        // that verified its anchor (resolved at the boundary height).
        let Some(anchor_set) = rt.validator_set_for_height_strict(boundary) else {
            eprintln!(
                "[sync] REFUSING snapshot at {boundary}: no validator set resolvable at boundary height"
            );
            consecutive_misses = consecutive_misses.saturating_add(1);
            tokio::time::sleep(std::time::Duration::from_millis(
                stellereum::sync::snapshot_probe_pace_ms(consecutive_misses),
            ))
            .await;
            boundary = boundary.saturating_sub(probe_step);
            continue;
        };

        // Prefer content-addressed SnapV4 manifest (small pre-fetch metadata);
        // fall back to legacy monolithic state snapshot if no SnapV4 Base manifest is served.
        let snapv4_manifest = adapter
            .fetch_snapv4_manifest(shard, boundary, &next_hdr.state_root, None)
            .await
            .filter(|m| matches!(m.kind, stellereum::snapshot_v4::SnapshotKind::Base));
        let mut installed_via_snapv4 = false;
        if let Some(manifest) = snapv4_manifest {
            let snap_anchor = stellereum::snapshot_v4::TrustedSnapshotAnchor {
                chain_id: stellereum::consensus::consensus_chain_id(),
                shard_id: shard,
                target_height: boundary,
                trusted_boundary_hash: boundary_hash,
                trusted_state_root: trusted_root,
                validator_set: &anchor_set,
            };
            match stellereum::sync::verify_snapv4_manifest_pre_fetch(&manifest, &snap_anchor) {
                Ok(()) => {
                    match stellereum::sync::fetch_verified_snapv4_chunks(
                        &manifest,
                        |_, _, chunk_hash| {
                            let a = adapter.clone();
                            async move { a.fetch_snapv4_unit(shard, &chunk_hash).await }
                        },
                    )
                    .await
                    {
                        Ok(chunks) => {
                            match stellereum::sync::fast_sync_snapv4_base(
                                &rt.state,
                                &snap_anchor,
                                &manifest,
                                &chunks,
                                None,
                            )
                            .await
                            {
                                Ok(_) => installed_via_snapv4 = true,
                                Err(e) => {
                                    eprintln!("[sync] snap_v4 at {boundary} rejected: {e}");
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("[sync] snap_v4 chunks at {boundary} failed: {e}");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[sync] snap_v4 manifest at {boundary} rejected: {e}");
                }
            }
        }
        if !installed_via_snapv4 {
            let Some(snapshot) = adapter.fetch_state_snapshot(shard, boundary).await else {
                miss_snapshot += 1;
                consecutive_misses = consecutive_misses.saturating_add(1);
                tokio::time::sleep(std::time::Duration::from_millis(
                    stellereum::sync::snapshot_probe_pace_ms(consecutive_misses),
                ))
                .await;
                boundary = boundary.saturating_sub(probe_step);
                continue;
            };
            let fetch_domain = {
                let a = adapter.clone();
                move |kind: &'static str| {
                    let a = a.clone();
                    async move { a.fetch_domain_snapshot(shard, boundary, kind).await }
                }
            };
            if let Err(e) = stellereum::sync::fast_sync_state_with_set_binding_prefetched(
                &rt.state,
                trusted_root,
                snapshot,
                fetch_domain,
                boundary,
                &anchor_set,
            )
            .await
            .map(|_| ())
            {
                eprintln!("[sync] snapshot at {boundary} rejected: {e}");
                consecutive_misses = consecutive_misses.saturating_add(1);
                tokio::time::sleep(std::time::Duration::from_millis(
                    stellereum::sync::snapshot_probe_pace_ms(consecutive_misses),
                ))
                .await;
                boundary = boundary.saturating_sub(probe_step);
                continue;
            }
        }

        // The snapshot's root is verified. Record the boundary so the normal
        // machinery continues from here.
        {
            let pq_reg = rt.state.pq_registry_read().await;
            let active = stellereum::pq_registry::pq_lifecycle_active_at(boundary);
            if !pq_reg.is_empty() {
                stellereum::consensus::sync_committed_pq_registry(&pq_reg, active);
            }
        }
        // Fetch the boundary block before persisting/advancing so it can be
        // made durable alongside the snapshot and also reused for light-client
        // re-anchoring below without a duplicate network fetch.
        let fetched_boundary_block = adapter
            .fetch_block(&boundary_hash)
            .await
            .filter(|blk| blk.height == boundary && blk.compute_hash() == boundary_hash);
        // Persist the verified snapshot state, domains, boundary block (if
        // fetched), and finalized pointer BEFORE advancing `rt.safety` /
        // `rt.finalized` (`advance_to_verified_snapshot`), so a crash right
        // after snapshot sync never leaves `safety_record_v1` ahead of disk.
        if let Some(ap) = persistence {
            if let Some(ref blk) = fetched_boundary_block {
                ap.enqueue_block(blk.clone());
            }
            ap.snapshot_state(&rt.state, boundary).await;
            let (staking, governance) = {
                let s = rt.state.staking_read().await.clone();
                let g = rt.state.governance_read().await.clone();
                (s, g)
            };
            ap.snapshot_domains(&rt.state, &staking, &governance, boundary)
                .await;
            let _ = ap.storage().put_finalized_post_root(boundary, trusted_root);
            ap.enqueue_finalized(boundary, boundary_hash);
            ap.request_flush();
            if let Err(e) = wait_snapshot_persistence_drain(ap, boundary).await {
                eprintln!("[sync] REFUSING snapshot at {boundary}: {e}");
                tracing::error!(shard, boundary, "[sync] {e}");
                return None;
            }
        }
        //
        // Safety invariant (W1 §2.6): snapshot sync NEVER clears, overwrites, or
        // resets `safety_record_v1`, `ConsensusCheckpoint`, or `VoteWatermark`;
        // `rt.safety.advance_height` only advances monotonically via CAS and
        // preserves quarantine on any mismatch.
        rt.advance_to_verified_snapshot(boundary, boundary_hash);
        // The restored ledger may name a different validator set than our
        // config (bonds/slashes since genesis): converge now, not at the next
        // finalize, or proposer schedules disagree with the network.
        //
        // STALE-LEDGER GUARD (node C): the fast-synced bundle carries state
        // AND domains at the same boundary when peers publish both; a bundle
        // with missing/stale domains installs accounts at `boundary` with an
        // ANCIENT (or empty) ledger — the foreign-set trap. The checked
        // refresh below compares both heights (both `boundary` when the
        // bundle was complete) and fail-closes to observer on staleness.
        // A node that lands here stale repairs via
        // `refresh_validator_set_from_fresh_snapshot` (set-only pull,
        // separate from the block walk) instead of waiting for a walk that
        // can never replay its ancient bond.
        rt.refresh_validator_set_from_staking_checked(boundary, boundary)
            .await;
        if rt.is_validator_set_stale() {
            eprintln!(
                "[validator-set] WARN snapshot-sync at {boundary} left a stale set — node runs as OBSERVER (no votes) until a fresh domain snapshot arrives"
            );
        }
        log_quorum_safety("snapshot-sync ledger set", &rt.validators);
        // W10.5 heal (2026-10-25): the jump above moves the finalized head
        // and consensus, but the light client stays anchored at genesis
        // (expecting block 1) — so the body walk below refuses the whole
        // tail and a jumped node never closes its final gap. Re-anchor AT
        // the verified boundary from the boundary block's own QC
        // (fail-closed: a fetch miss or mismatch keeps today's behavior).
        if let Some(ref blk) = fetched_boundary_block {
            rt.reanchor_light_client_at_snapshot(boundary, blk);
        } else {
            eprintln!(
                "[sync] light-client re-anchor skipped: boundary block {boundary} missing or mismatched"
            );
        }
        info!(
            "[sync] fast-synced state from a snapshot at height {boundary}; resuming at {}",
            boundary + 1
        );
        return Some(boundary);
    }
    // Nothing usable in the whole probe window. Say what was missing (throttled
    // with the attempt log above): "no snapshot at any recent boundary" means
    // the peers publish none / the epoch is wrong, "no successor header" means
    // the headers were pruned or never published.
    if attempt.is_multiple_of(15) {
        eprintln!(
            "[sync] snapshot-sync attempt {attempt}: no usable snapshot (peer={peer_height} \
             ours={our_height}): {miss_snapshot} boundaries without a state snapshot, \
             {miss_header} without a successor header"
        );
    } else {
        tracing::debug!(
            "[sync] snapshot-sync attempt {attempt}: no usable snapshot \
             (miss_snapshot={miss_snapshot} miss_header={miss_header})"
        );
    }
    None
}

/// Refresh ONLY the validator set from fresh domain snapshots, without moving
/// a single block (the lagging-node repair path for node C).
///
/// A node whose bond predates every walkable body can never learn the CURRENT
/// set by walking: the walk replays only the tip window, and the ancient bond
/// height is long pruned. But peers publish domain snapshots (which embed the
/// staking ledger) every 100 heights with FOREVER retention, so the set is
/// fetchable on its own. This probes the newest boundaries (latest-snapshot
/// pointer first, then interval-spaced downward, bounded by the cadence (see
/// [`stellereum::sync::snapshot_probe_steps`]) for a `domains` blob NEWER
/// than the ledger the runtime currently trusts, decodes it, and installs it
/// through the freshness-gated
/// [`ValidatorRuntime::refresh_validator_set_from_domain_bytes`].
///
/// Fail-closed: missing/undecodable/stale blobs only log and return `false`;
/// the runtime keeps its old set AND its stale flag. `state_height` is the
/// height whose post-state the engine holds (the restored/synced height);
/// every candidate `ledger_height` is the snapshot boundary its blob was
/// published at. Returns `true` when a fresh set was installed (stale
/// cleared) — the caller should re-announce and resume voting.
pub(crate) async fn refresh_validator_set_from_fresh_snapshot(
    adapter: &Arc<P2pNetworkAdapter>,
    rt: &mut ValidatorRuntime,
    shard: u32,
    state_height: u64,
) -> bool {
    let current_ledger = rt.validator_set_ledger_height.unwrap_or(0);
    // Candidate boundaries: the exact newest pointer first (snapshots complete
    // on worker timing at arbitrary heights, so fixed-grid probes miss them),
    // then interval-spaced boundaries downward. Bounded: a peer with no
    // domains must not make us probe forever, and the window tracks the
    // configured cadence instead of a fixed 8 x 100 (audit F4).
    let snap_int = crate::node::policy::snapshot_interval();
    let probe_step = stellereum::sync::snapshot_probe_step(snap_int);
    let probe_steps = stellereum::sync::snapshot_probe_steps(snap_int);
    let mut candidates: Vec<u64> = Vec::new();
    if let Some(latest) = adapter.fetch_latest_snapshot(shard).await {
        if latest > current_ledger {
            candidates.push(latest);
        }
    }
    if let Some(head) = adapter.fetch_head(shard).await.map(|(h, _)| h) {
        let mut b = (head / probe_step) * probe_step;
        for _ in 0..probe_steps {
            if b == 0 || b <= current_ledger {
                break;
            }
            if !candidates.contains(&b) {
                candidates.push(b);
            }
            b = b.saturating_sub(probe_step);
        }
    }
    candidates.sort_unstable();
    candidates.dedup();
    // Newest first: the first fresh install wins (freshest set).
    candidates.sort_unstable_by(|a, b| b.cmp(a));
    for boundary in candidates {
        let Some(blob) = adapter
            .fetch_domain_snapshot(shard, boundary, "domains")
            .await
        else {
            continue;
        };
        match rt
            .refresh_validator_set_from_domain_bytes(&blob, state_height, boundary)
            .await
        {
            Ok(true) => {
                info!(
                    "[validator-set] set-only refresh installed a fresh set from domain snapshot at {boundary} (state {state_height}); stale cleared, resuming franchise"
                );
                log_quorum_safety("set-only refreshed ledger set", &rt.validators);
                return true;
            }
            Ok(false) => {
                // Fresh but unchanged, or still stale (logged inside) — either
                // way this boundary taught us nothing new; try an older one
                // only if we are still stale.
                if !rt.is_validator_set_stale() {
                    return false;
                }
            }
            Err(e) => {
                eprintln!("[validator-set] set-only refresh: {e}");
            }
        }
    }
    false
}

/// Optional background lanes + shared consensus network passed by the live
/// consensus driver so `walk_chain_once` offloads RPC indexing and tip DHT
/// publishes off the consensus tick without breaking standalone/test callers.
#[derive(Clone, Copy, Default)]
pub(crate) struct SyncLanes<'a> {
    pub record_lane: Option<&'a TickLane>,
    pub publish_lane: Option<&'a TickLane>,
    pub consensus_net: Option<&'a Arc<ConsensusNetwork>>,
}

/// Bring this node up to a peer's published head.
///
/// Returns `Some(height)` when the node actually caught up.
///
/// This is deliberately *not* only a startup concern. A node that falls behind
/// while running used to have no way out: it kept proposing at its own height,
/// the peer rejected those proposals as `wrong height`, and neither side moved.
/// A one-block skew was enough to deadlock the pair forever. Running this from
/// inside the consensus loop is what breaks that deadlock, and discarding the
/// round state (`rt.hc`) on success is what makes a partition recoverable — the
/// runaway round counter a node accumulates while isolated is thrown away
/// instead of being carried into the rejoined network.
///
/// Safety is unchanged from the original startup path: the peer chain must
/// continue OUR finalized chain, carry a real validator quorum, and every block
/// header must commit to the state root we actually have *before* it is applied.
pub(crate) async fn try_catch_up(
    adapter: &Arc<P2pNetworkAdapter>,
    rt: &mut ValidatorRuntime,
    shard: u32,
    persist: Option<&std::sync::Arc<stellereum::storage::AsyncPersistence>>,
    rpc: &Arc<stellereum::rpc::RpcState>,
) -> Option<u64> {
    try_catch_up_with_evidence(adapter, rt, shard, persist, rpc, 0).await
}

/// [`try_catch_up`] with the tallest height a VERIFIED peer message named, even
/// when no block hash accompanies it (a vote names only `height`).
///
/// A vote cannot anchor a body walk (there is no `peer_hash`), but it is still
/// proof the peer's chain is ahead. When the DHT head read is a stale echo and
/// the tip+1 blind-QC sidecar is pruned, that height is the ONLY evidence left;
/// the snapshot path needs no hash, so a material gap can still be bridged.
/// Liveness only: the snapshot restores against a header-derived, quorum-signed
/// root and every block above it is re-verified.
pub(crate) async fn try_catch_up_with_evidence(
    adapter: &Arc<P2pNetworkAdapter>,
    rt: &mut ValidatorRuntime,
    shard: u32,
    persist: Option<&std::sync::Arc<stellereum::storage::AsyncPersistence>>,
    rpc: &Arc<stellereum::rpc::RpcState>,
    named_peer_height: u64,
) -> Option<u64> {
    try_catch_up_with_lanes(
        adapter,
        rt,
        shard,
        persist,
        rpc,
        SyncLanes::default(),
        named_peer_height,
    )
    .await
}

pub(crate) async fn try_catch_up_with_lanes(
    adapter: &Arc<P2pNetworkAdapter>,
    rt: &mut ValidatorRuntime,
    shard: u32,
    persist: Option<&std::sync::Arc<stellereum::storage::AsyncPersistence>>,
    rpc: &Arc<stellereum::rpc::RpcState>,
    lanes: SyncLanes<'_>,
    named_peer_height: u64,
) -> Option<u64> {
    // Read the replicated head pointer, not the local one: `get_latest_shard_height`
    // reads this node's own KV, so it can only ever report our own height and the
    // catch-up condition would be unsatisfiable by construction. Prefer a head
    // observed DIRECTLY in a validated proposal (height-1 + prev_hash): the DHT
    // read is best-effort and goes blind for minutes at a time, while proposals
    // arrive every round on the reliable direct path.
    let our_height = rt.finalized.last().map(|(h, _)| *h).unwrap_or(0);
    // EVENT-DRIVEN PREFERENCE (push-based propagation): when a verified peer
    // message already named a head above ours, use it and SKIP the DHT head
    // query. The query is the blind, expensive half — one round trip that can
    // consume the whole catch-up budget on a dead peer (the live stall), while
    // the push channel just handed us the same answer. Only a node with no
    // ahead evidence still polls the DHT.
    let probed_dht = should_probe_dht_head(our_height, rt.peer_hint);
    let dht = if probed_dht {
        adapter.fetch_head(shard).await
    } else {
        tracing::debug!(
            "[sync] peer hint is already ahead (ours={our_height}, hint={:?}): skipping the DHT head read",
            rt.peer_hint.map(|(h, _)| h)
        );
        None
    };
    if probed_dht && dht.is_none() {
        // Throttled visibility: a blind fetch_head (DHT miss, unpublished peer,
        // wrong shard/epoch, or the fetch timing out on a dead transport) is
        // otherwise indistinguishable from "in sync".
        static FETCH_MISS_N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = FETCH_MISS_N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if n.is_multiple_of(30) {
            eprintln!(
                "[sync] cannot read any peer head (miss {n}; peer may publish nothing yet, \
                 the epoch/shard may be wrong, or the transport may be down)"
            );
        }
    }
    let dht_hint_head = [dht, rt.peer_hint]
        .into_iter()
        .flatten()
        .max_by_key(|(h, _)| *h);
    // BLIND-QC-PROBE (live-recovery 2026-10-30, audit note): when neither the
    // DHT head read nor the proposal-observed peer hint is ahead of us, do NOT
    // conclude "in sync". Both go blind together: the shared head key is
    // last-writer-wins so a node can read back its OWN head (echo chamber),
    // and a node that receives no proposals never sets peer_hint (deaf
    // follower). Observed live: B sat one height behind a converged quorum
    // (654 vs 655) retrying a no-op catch-up every 2s forever while its
    // broadcasts were absorbed as stale elsewhere — "a silent follower can
    // never be rescued". Fallback: directly probe the precommit-QC sidecar
    // for tip+1 (a B-initiated DHT read, NAT-proof like every request_to). A
    // present, height-bound QC proves finality with no head advertisement at
    // all; walk_chain below re-verifies everything (per-block QC against the
    // set in force at that height, parent/root continuity, tip connection),
    // so a forged or stale sidecar is refused exactly as before. Fail-closed:
    // miss/nil-QC/height-mismatch returns None. Liveness-only: no wire, no
    // quorum, no apply change. Bounded by the caller's catch-up budget.
    let (peer_height, peer_hash) = match dht_hint_head {
        Some((ph, phash)) if stellereum::network::peer_head_is_ahead(our_height, ph) => (ph, phash),
        _ => {
            let probe_h = our_height.saturating_add(1);
            match adapter.fetch_block_qc_probe(shard, probe_h).await {
                Some(qc) if qc.height == probe_h => {
                    // The WALK anchor may keep the structural (height + block
                    // hash) binding exactly as before; only the EVIDENCE used
                    // for budget scaling / latch re-arm requires a verified
                    // quorum. That keeps a far-behind node's snapshot path
                    // alive across a set rotation it cannot verify yet, while
                    // a forged sidecar can never pin the node in repeated long
                    // catch-up ticks.
                    let raw_bh = qc.block_hash?;
                    let verified = verified_qc_sidecar_hash(rt, &qc, probe_h);
                    // BLIND-ANCHOR-EXTEND (live 2026-11-23): adopting ONE
                    // height per pass capped a silent follower's catch-up at
                    // the pass cadence (~2 heights/s). At the live tempo
                    // (2.5 blocks/s) a node that fell behind could never close
                    // the gap — it stayed out of the quorum while its CPU sat
                    // idle. Probe a small ladder ahead and anchor on the
                    // FURTHEST height that already carries a decided sidecar,
                    // so the normal snapshot-first/batched walk handles a
                    // material gap. Liveness only: the walk still verifies
                    // every block, QC, parent and state root.
                    //
                    // The ladder is ascending and stops at the first miss:
                    // decided heights are contiguous, so a miss means the
                    // chain is not that far ahead (and we avoid polluting a
                    // future height's QC-miss backoff).
                    let mut anchor = (probe_h, raw_bh);
                    // VERIFIED EVIDENCE FOR THE DRIVER (liveness): the ladder
                    // proves decided heights ahead, so record the largest one
                    // that fits `peer_hint`'s credible lookahead/TTL bounds.
                    // Without it the driver had NO ahead evidence after a blind
                    // pass: the end-of-tick latch could not re-arm, the
                    // follow-up pass kept the 2 s blind budget (instead of the
                    // gap-scaled one), and a timeout dropped it to the 120 s
                    // at-tip cadence. The 64-height pre-hash gate used to cap
                    // this too, discarding every rung past `+64` (nodeC).
                    let hint_cap = our_height.saturating_add(PEER_HINT_MAX_LOOKAHEAD);
                    let mut hint_anchor = verified.map(|bh| (probe_h, bh));
                    for &step in BLIND_PROBE_LADDER {
                        let h = our_height.saturating_add(step);
                        match adapter.fetch_block_qc_probe(shard, h).await {
                            Some(q) if q.height == h => match q.block_hash {
                                Some(b) => {
                                    // WALK anchor: the historical structural
                                    // (height + hash) binding, so a set this
                                    // node cannot verify yet still reaches the
                                    // snapshot path.
                                    anchor = (h, b);
                                    // EVIDENCE: only a verified quorum may
                                    // scale the next pass's budget / re-arm.
                                    if h <= hint_cap {
                                        if let Some(vb) = verified_qc_sidecar_hash(rt, &q, h) {
                                            hint_anchor = Some((h, vb));
                                        }
                                    }
                                }
                                None => break,
                            },
                            _ => break,
                        }
                    }
                    if let Some((hh, hb)) = hint_anchor.filter(|(hh, _)| *hh > our_height) {
                        rt.peer_hint = Some((hh, hb));
                    }
                    if anchor.0 == probe_h {
                        eprintln!(
                            "[sync] blind-QC-probe: tip+1 height {probe_h} carries a QC sidecar; walking one height to adopt it"
                        );
                    } else {
                        eprintln!(
                            "[sync] blind-QC-probe: tip+1 present; anchoring the walk at decided height {} so a material gap uses the batched/snapshot path",
                            anchor.0
                        );
                    }
                    anchor
                }
                _ => {
                    // VOTE-ONLY EVIDENCE (live 2026-11-23): a verified vote
                    // names a height but no hash, so neither the DHT echo nor
                    // the tip+1 sidecar can anchor a walk. A material gap can
                    // still be bridged by the SNAPSHOT path, which needs no
                    // peer hash — every restored root is derived from a
                    // quorum-signed header and verified below. Without this a
                    // node whose only ahead evidence is votes (or whose local
                    // sidecars are pruned) never reaches snapshot-sync at all.
                    if named_peer_height > our_height.saturating_add(100) {
                        eprintln!(
                            "[sync] no peer head/hash available, but a verified peer named height {named_peer_height} (ours={our_height}): trying snapshot-first"
                        );
                        if let Some(b) = try_snapshot_sync_with_persistence(
                            adapter,
                            rt,
                            shard,
                            named_peer_height,
                            persist,
                        )
                        .await
                        {
                            return Some(b);
                        }
                    }
                    static BLIND_MISS_N: std::sync::atomic::AtomicU64 =
                        std::sync::atomic::AtomicU64::new(0);
                    let n = BLIND_MISS_N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if n.is_multiple_of(30) {
                        tracing::debug!("[sync] blind-QC-probe miss {n} (no QC sidecar for tip+1)");
                    }
                    return None;
                }
            }
        }
    };
    // The head key is shared and last-writer-wins, so this may be our OWN head
    // coming back (our local manifest shadows peers on read), or a stale peer.
    // Only a STRICTLY ahead head means someone knows more than us
    // (`peer_head_is_ahead`); anything else is "nothing to do", never a reason
    // to move — and a height-0 node must never treat its own echo as a peer.
    // (peer_height, peer_hash) is ahead by construction here: either the DHT/hint
    // head passed peer_head_is_ahead above, or the blind-QC-probe pinned tip+1
    // (strictly ahead of a non-wrapping tip; on a u64::MAX tip probe saturates
    // to tip itself and the walk below refuses it on continuity).
    // Bounded: a peer claiming to be millions of blocks ahead is either a
    // different chain or a lie, and we refuse to walk it.
    if peer_height - our_height > 1_000_000 {
        eprintln!(
            "[sync] peer claims height {peer_height}, we are at {our_height}: refusing to walk"
        );
        return None;
    }

    // Snapshot-first for any material gap, body walk otherwise and as fallback.
    // Snapshots (every 100 heights) carry post-state directly, so they bridge
    // history the body walk cannot reproduce: heterogeneous rules across binary
    // eras, or effects outside bodies. Observed live: a node replaying 642
    // matching heights then failing at #643 with no in-band recovery, retrying
    // the doomed walk every 2s forever. Walk first would waste that retry loop;
    // snapshot first lands on a verified recent state and walks only the short
    // remainder with current code. If no snapshot is available, the walk still
    // runs (small gaps, full windows); if the walk then fails, one snapshot
    // attempt bridges it.
    // STALE-SET repair (node C) runs BEFORE the body walk and independently
    // of it: a node whose ledger lags the state by more than the freshness
    // ring pulls the CURRENT set from fresh domain snapshots alone. The walk
    // replays only the tip window and can never reach an ancient bond height,
    // so without this the node keeps the foreign set forever (no votes,
    // foreign quorums) even while bodies flow. Set-only: moves no height.
    //
    // SYNC TRAP N4 (R3 CODE-TAILS sweep, stale-set verification trap): the
    // pull below runs ONLY when `is_validator_set_stale()` is already set,
    // but a node that joined with an outdated CONFIG set and a fresh-looking
    // (empty or same-height) ledger never sets the flag — so it verifies
    // every peer chain against the wrong set, refuses everything, and never
    // repairs (the set never refreshes pre-join). Minimal fix (no wire
    // change, bounded): when the peer is ahead AND both the walk and the
    // snapshot attempt fail in this round, run
    // `refresh_validator_set_from_fresh_snapshot` ONCE more (it is already
    // bounded + fail-closed) and retry the walk before giving up for the
    // round. Until then the operator repair is: wipe + re-bootstrap with the
    // current validator set, or wait for a fresh domain snapshot.
    if rt.is_validator_set_stale() {
        let state_h = rt.finalized.last().map(|(h, _)| *h).unwrap_or(0);
        if refresh_validator_set_from_fresh_snapshot(adapter, rt, shard, state_h).await {
            info!(
                "[validator-set] stale set repaired from fresh domain snapshot; franchise restored"
            );
        }
    }
    let mut snapshotted_boundary = None;
    if peer_height - our_height > 100 {
        if let Some(b) =
            try_snapshot_sync_with_persistence(adapter, rt, shard, peer_height, persist).await
        {
            snapshotted_boundary = Some(b);
        }
    }

    if let Some(h) = walk_chain_with_lanes(
        adapter,
        rt,
        shard,
        peer_height,
        peer_hash,
        persist,
        rpc,
        lanes,
    )
    .await
    {
        return Some(h);
    }
    // If snapshot-sync advanced our height to a verified boundary, return it
    // even if the short body walk to the tip has not finished yet — so the caller
    // resets its per-round consensus timers and resumes cleanly from the new
    // boundary instead of discarding the progress.
    if let Some(b) = snapshotted_boundary {
        return Some(b);
    }
    if snapshotted_boundary.is_none() {
        let our_now = rt.finalized.last().map(|(h, _)| *h).unwrap_or(0);
        if peer_height > our_now && peer_height - our_now > 100 {
            if let Some(b) =
                try_snapshot_sync_with_persistence(adapter, rt, shard, peer_height, persist).await
            {
                if let Some(h) = walk_chain_with_lanes(
                    adapter,
                    rt,
                    shard,
                    peer_height,
                    peer_hash,
                    persist,
                    rpc,
                    lanes,
                )
                .await
                {
                    return Some(h);
                }
                return Some(b);
            }
        }
    }
    None
}

/// Walk bodies from our tip to the peer's head, applying the full finalized
/// transition per block (see the parity comment inside). Returns the peer
/// height on success, None (loudly logged) on any failure.
///
/// This entry point is **multi-hop**: a gap larger than one honest walk window
/// is closed in bounded hops (see [`walk_chain_multi_hop`]) instead of being
/// refused. Each hop still runs the unchanged [`walk_chain_once`] verification
/// (hash linkage, per-height QC/proposer, parent-root continuity), so the
/// recovery path never accepts an unverified chain; only the AMOUNT fetched
/// per pass changes, and that is node-local sync policy.
#[cfg(test)]
pub(crate) async fn walk_chain(
    adapter: &Arc<P2pNetworkAdapter>,
    rt: &mut ValidatorRuntime,
    shard: u32,
    peer_height: stellereum::consensus::Height,
    peer_hash: stellereum::consensus::BlockHash,
    persist: Option<&std::sync::Arc<stellereum::storage::AsyncPersistence>>,
    rpc: &Arc<stellereum::rpc::RpcState>,
) -> Option<u64> {
    walk_chain_with_lanes(
        adapter,
        rt,
        shard,
        peer_height,
        peer_hash,
        persist,
        rpc,
        SyncLanes::default(),
    )
    .await
}

#[allow(clippy::too_many_arguments)] // GATE: mirrors `walk_chain` with optional background lanes.
pub(crate) async fn walk_chain_with_lanes(
    adapter: &Arc<P2pNetworkAdapter>,
    rt: &mut ValidatorRuntime,
    shard: u32,
    peer_height: stellereum::consensus::Height,
    peer_hash: stellereum::consensus::BlockHash,
    persist: Option<&std::sync::Arc<stellereum::storage::AsyncPersistence>>,
    rpc: &Arc<stellereum::rpc::RpcState>,
    lanes: SyncLanes<'_>,
) -> Option<u64> {
    walk_chain_multi_hop_with_lanes(
        adapter,
        rt,
        shard,
        peer_height,
        peer_hash,
        persist,
        rpc,
        crate::node::policy::max_walk_gap(),
        lanes,
    )
    .await
}

/// Per-pass hop ceiling for recovery mode. `hop_cap * RECOVERY_MAX_HOPS` is
/// the hard bound on work one catch-up pass can spend walking bodies, so a
/// peer advertising millions of blocks cannot turn recovery into an unbounded
/// WAN walk. The caller's timeout is the wall-clock bound; this is the work
/// bound. A pass that hits it returns the height it DID reach, so the next
/// tick continues from there.
const RECOVERY_MAX_HOPS: u32 = 64;

/// Close a body gap that is longer than one walk window, WITHOUT waiting for a
/// newer snapshot.
///
/// Why this exists (`docs/UPGRADE_AND_RECOVERY.md` §0.4): after a snapshot
/// restore at boundary `B` the node resumes with finalized head `B`, but the
/// next snapshot may be up to `snap_int + CATCHUP_GRID` heights away. On a
/// LIVE chain that is a bounded wait; on a HALTED chain (finality stopped) no
/// newer snapshot is ever produced, so a single-walk cap strands the node
/// permanently. Recovery therefore walks in hops:
///
/// * each hop targets `our_tip + hop_cap` and resolves that height's hash from
///   the published header index (falling back to the QC sidecar, which carries
///   the decided hash even when the index blob is missing);
/// * [`walk_chain_once`] fetches at most `hop_cap` bodies and applies the full
///   verified transition, so memory/CPU per hop is the same as the old walk;
/// * the final hop targets the advertised head, and `walked_head_anchor` still
///   refuses a peer whose served chain does not end at that exact hash/height;
/// * at most [`RECOVERY_MAX_HOPS`] hops run per pass; hitting the bound returns
///   the reached height (progress, not failure) and the next pass continues.
///
/// Determinism: hop sizing is a local sync policy, never consensus input. Two
/// nodes may take different numbers of hops and still apply the identical
/// blocks in the identical order, ending on the identical state root.
#[cfg(test)]
#[allow(clippy::too_many_arguments)] // GATE: mirrors `walk_chain`'s production signature; grouping into a struct would churn every caller.
pub(crate) async fn walk_chain_multi_hop(
    adapter: &Arc<P2pNetworkAdapter>,
    rt: &mut ValidatorRuntime,
    shard: u32,
    peer_height: stellereum::consensus::Height,
    peer_hash: stellereum::consensus::BlockHash,
    persist: Option<&std::sync::Arc<stellereum::storage::AsyncPersistence>>,
    rpc: &Arc<stellereum::rpc::RpcState>,
    hop_cap: u64,
) -> Option<u64> {
    walk_chain_multi_hop_with_lanes(
        adapter,
        rt,
        shard,
        peer_height,
        peer_hash,
        persist,
        rpc,
        hop_cap,
        SyncLanes::default(),
    )
    .await
}

#[allow(clippy::too_many_arguments)] // GATE: same verified multi-hop walk with optional off-tick lanes.
pub(crate) async fn walk_chain_multi_hop_with_lanes(
    adapter: &Arc<P2pNetworkAdapter>,
    rt: &mut ValidatorRuntime,
    shard: u32,
    peer_height: stellereum::consensus::Height,
    peer_hash: stellereum::consensus::BlockHash,
    persist: Option<&std::sync::Arc<stellereum::storage::AsyncPersistence>>,
    rpc: &Arc<stellereum::rpc::RpcState>,
    hop_cap: u64,
    lanes: SyncLanes<'_>,
) -> Option<u64> {
    // A zero cap would make every hop target our own tip; treat it as one
    // block rather than looping forever.
    let hop_cap = hop_cap.max(1);
    let start_height = rt.finalized.last().map(|(h, _)| *h).unwrap_or(0);
    if peer_height.saturating_sub(start_height) <= hop_cap {
        return walk_chain_once_with_lanes(
            adapter,
            rt,
            shard,
            peer_height,
            peer_hash,
            persist,
            rpc,
            hop_cap,
            lanes,
        )
        .await;
    }

    let entry = format!(
        "[sync][recovery] body gap {} > one walk window {hop_cap}; entering bounded multi-hop \
         recovery (peer={peer_height} ours={start_height}, max {RECOVERY_MAX_HOPS} hops/pass) \
         — no newer snapshot is required to converge",
        peer_height.saturating_sub(start_height)
    );
    eprintln!("{entry}");
    tracing::info!("{entry}");

    let mut hops = 0u32;
    loop {
        let our_height = rt.finalized.last().map(|(h, _)| *h).unwrap_or(0);
        if our_height >= peer_height {
            return Some(our_height);
        }
        let (target_height, target_hash) = if peer_height - our_height <= hop_cap {
            // Final hop: the advertised head, verified exactly as before.
            (peer_height, peer_hash)
        } else {
            let target = our_height.saturating_add(hop_cap);
            let Some(hash) = fetch_hop_head(adapter, shard, target).await else {
                eprintln!(
                    "[sync][recovery] no published head for hop height {target} \
                     (ours={our_height}, peer={peer_height}); cannot continue this pass"
                );
                return None;
            };
            (target, hash)
        };

        let before = our_height;
        if walk_chain_once_with_lanes(
            adapter,
            rt,
            shard,
            target_height,
            target_hash,
            persist,
            rpc,
            hop_cap,
            lanes,
        )
        .await
        .is_none()
        {
            eprintln!(
                "[sync][recovery] hop to {target_height} failed at {before} \
                 (peer={peer_height}); recovered nothing this pass"
            );
            return None;
        }
        let after = rt.finalized.last().map(|(h, _)| *h).unwrap_or(0);
        if after <= before {
            eprintln!(
                "[sync][recovery] hop to {target_height} made no progress \
                 (before={before}, after={after}); refusing to loop"
            );
            return None;
        }
        hops += 1;
        eprintln!(
            "[sync][recovery] hop {hops} reached {after}/{peer_height} \
             ({} heights left, hop cap {hop_cap})",
            peer_height.saturating_sub(after)
        );
        if after >= peer_height {
            return Some(after);
        }
        if hops >= RECOVERY_MAX_HOPS {
            eprintln!(
                "[sync][recovery] per-pass hop budget {RECOVERY_MAX_HOPS} exhausted at \
                 {after}/{peer_height}; returning progress and continuing next pass"
            );
            return Some(after);
        }
    }
}

/// Resolve the decided hash at `height` for an intermediate hop.
///
/// Preferred source is the header index (`finalize` publishes it every block).
/// The QC sidecar is the fallback: it binds height -> block hash and does not
/// depend on the separately-published index blob. Every caller still verifies
/// the fetched chain to this hash inside [`walk_chain_once`], so an untrusted
/// or stale answer can only make the hop fail, never re-anchor us.
async fn fetch_hop_head(
    adapter: &Arc<P2pNetworkAdapter>,
    shard: u32,
    height: u64,
) -> Option<stellereum::consensus::BlockHash> {
    if let Some(hash) = adapter.fetch_head_hash(shard, height).await {
        return Some(hash);
    }
    match adapter.fetch_block_qc(shard, height).await {
        Some(qc) if qc.height == height => qc.block_hash,
        _ => None,
    }
}

/// Fast single-attempt hash lookup for concurrent multi-block prefetch.
async fn fetch_hop_head_fast(
    adapter: &Arc<P2pNetworkAdapter>,
    shard: u32,
    height: u64,
) -> Option<stellereum::consensus::BlockHash> {
    if let Some(hash) = adapter.fetch_head_hash_probe(shard, height).await {
        return Some(hash);
    }
    match adapter.fetch_block_qc_probe(shard, height).await {
        Some(qc) if qc.height == height => qc.block_hash,
        _ => None,
    }
}

/// One verified walk window: fetch at most `walk_cap` bodies back to our
/// finalized tip, validate every height, apply the full transition, and
/// re-anchor consensus on the walked tail.
#[cfg_attr(not(test), allow(dead_code))] // GATE: test-compatible wrapper delegating to `walk_chain_once_with_lanes`.
#[allow(clippy::too_many_arguments)] // GATE: same verified walk, split only to bound one hop's fetch/apply window.
async fn walk_chain_once(
    adapter: &Arc<P2pNetworkAdapter>,
    rt: &mut ValidatorRuntime,
    shard: u32,
    peer_height: stellereum::consensus::Height,
    peer_hash: stellereum::consensus::BlockHash,
    persist: Option<&std::sync::Arc<stellereum::storage::AsyncPersistence>>,
    rpc: &Arc<stellereum::rpc::RpcState>,
    walk_cap: u64,
) -> Option<u64> {
    walk_chain_once_with_lanes(
        adapter,
        rt,
        shard,
        peer_height,
        peer_hash,
        persist,
        rpc,
        walk_cap,
        SyncLanes::default(),
    )
    .await
}

#[allow(clippy::too_many_arguments)] // GATE: same verified walk with optional off-tick record/publish lanes.
async fn walk_chain_once_with_lanes(
    adapter: &Arc<P2pNetworkAdapter>,
    rt: &mut ValidatorRuntime,
    shard: u32,
    peer_height: stellereum::consensus::Height,
    peer_hash: stellereum::consensus::BlockHash,
    persist: Option<&std::sync::Arc<stellereum::storage::AsyncPersistence>>,
    rpc: &Arc<stellereum::rpc::RpcState>,
    walk_cap: u64,
    lanes: SyncLanes<'_>,
) -> Option<u64> {
    use futures::stream::{self, StreamExt};
    // F3(c): anchor the walk on OUR finalized head and demand the NEXT height,
    // never the walked chain's own first height (passing `blocks[0].height` made
    // the height check a tautology). At genesis the chain roots at the zero
    // prev-hash sentinel and the first block we may apply is height 1.
    let (our_last, expected_first_height) = match rt.finalized.last() {
        Some((h, hash)) => (*hash, h.saturating_add(1)),
        None => ([0u8; 32], 1u64),
    };
    // One hop stays inside `walk_cap` bodies. A bounded window is load-bearing
    // (an unbounded WAN walk is a DoS vector); multi-hop recovery above is the
    // way a larger gap is closed when no newer snapshot exists. A single hop
    // larger than the cap is refused here so callers cannot bypass the bound.
    let walk_cap = walk_cap.max(1);
    if peer_height.saturating_sub(expected_first_height) > walk_cap {
        tracing::debug!(
            "[sync] gap (peer={peer_height} ours={}) > {walk_cap} blocks; body walk skipped for this hop",
            expected_first_height.saturating_sub(1)
        );
        return None;
    }

    let store = persist.map(|ap| ap.storage());
    // Seed local cache from `rt.blocks` (in-memory) ONLY for blocks that already
    // carry a decision QC (`precommit_qc.is_some()`): `rt.blocks` also holds
    // uncertified candidate proposals (`precommit_qc: None`), which would
    // otherwise shadow the DHT's decided body and fail `carries no decision proof`.
    let mut prefetched: std::collections::HashMap<[u8; 32], stellereum::sharding::Block> = rt
        .blocks
        .iter()
        .filter(|(_, b)| {
            b.height >= expected_first_height && b.height <= peer_height && b.precommit_qc.is_some()
        })
        .map(|(h, b)| (*h, b.clone()))
        .collect();

    // Fetch & verify the tail block (`peer_hash`) first so an unreachable or
    // forged tip fails in one fetch instead of triggering concurrent fan-out.
    if peer_hash != our_last {
        let tip_blk = if let Some(b) = prefetched.get(&peer_hash).cloned() {
            Some(b)
        } else if let Some(st) = store.clone() {
            let h = peer_hash;
            match tokio::task::spawn_blocking(move || {
                st.get_block(&h)
                    .ok()
                    .flatten()
                    .filter(|b| b.precommit_qc.is_some())
            })
            .await
            .ok()
            .flatten()
            {
                Some(b) => Some(b),
                None => adapter.fetch_block(&peer_hash).await,
            }
        } else {
            adapter.fetch_block(&peer_hash).await
        };
        let Some(raw_tip) = tip_blk else {
            eprintln!(
                "[sync] block sync: missing block {}",
                hex::encode(peer_hash)
            );
            return None;
        };
        let verified_tip = match stellereum::sync::verify_fetched_block(peer_hash, raw_tip) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("[sync] {e}");
                return None;
            }
        };
        let mut cur_hash = verified_tip.prev_hash;
        let mut cur_height = verified_tip.height.saturating_sub(1);
        prefetched.insert(peer_hash, verified_tip);

        // Walk backward locally through `rt.blocks` + `Storage` before querying DHT.
        let mut local_steps = 1u64;
        while cur_hash != our_last && cur_height >= expected_first_height && local_steps < walk_cap
        {
            let maybe_local = if let Some(b) = prefetched.get(&cur_hash).cloned() {
                Some(b)
            } else if let Some(st) = store.clone() {
                let h = cur_hash;
                tokio::task::spawn_blocking(move || {
                    st.get_block(&h)
                        .ok()
                        .flatten()
                        .filter(|b| b.precommit_qc.is_some())
                })
                .await
                .ok()
                .flatten()
            } else {
                None
            };
            let Some(local_blk) = maybe_local else {
                break;
            };
            let Ok(verified) = stellereum::sync::verify_fetched_block(cur_hash, local_blk) else {
                break;
            };
            if verified.precommit_qc.is_none() {
                break;
            }
            let block_hash = cur_hash;
            cur_hash = verified.prev_hash;
            cur_height = verified.height.saturating_sub(1);
            prefetched.insert(block_hash, verified);
            local_steps += 1;
        }

        // Bounded-concurrent catch-up when >= 2 blocks remain missing.
        if cur_hash != our_last && cur_height > expected_first_height {
            let resolved_hashes: Vec<(u64, Option<stellereum::consensus::BlockHash>)> =
                stream::iter(expected_first_height..cur_height)
                    .map(|h| {
                        let a = adapter.clone();
                        async move { (h, fetch_hop_head_fast(&a, shard, h).await) }
                    })
                    .buffer_unordered(stellereum::sync::FETCH_MAX_CONCURRENCY)
                    .collect()
                    .await;

            let mut seen_fetch: std::collections::HashSet<[u8; 32]> =
                std::collections::HashSet::new();
            let mut hashes_to_fetch: Vec<[u8; 32]> = Vec::new();
            if !prefetched.contains_key(&cur_hash) && seen_fetch.insert(cur_hash) {
                hashes_to_fetch.push(cur_hash);
            }
            for (_, maybe_h) in resolved_hashes {
                if let Some(h) = maybe_h {
                    if h != our_last && !prefetched.contains_key(&h) && seen_fetch.insert(h) {
                        hashes_to_fetch.push(h);
                    }
                }
            }

            if !hashes_to_fetch.is_empty() {
                let fetched_bodies: Vec<([u8; 32], Option<stellereum::sharding::Block>)> =
                    stream::iter(hashes_to_fetch)
                        .map(|h| {
                            let a = adapter.clone();
                            let st = store.clone();
                            async move {
                                if let Some(st) = st {
                                    if let Ok(Some(b)) = tokio::task::spawn_blocking(move || {
                                        st.get_block(&h)
                                            .ok()
                                            .flatten()
                                            .filter(|b| b.precommit_qc.is_some())
                                    })
                                    .await
                                    {
                                        return (h, Some(b));
                                    }
                                }
                                (h, a.fetch_block(&h).await)
                            }
                        })
                        .buffer_unordered(stellereum::sync::FETCH_MAX_CONCURRENCY)
                        .collect()
                        .await;
                for (h, maybe_blk) in fetched_bodies {
                    if let Some(blk) = maybe_blk {
                        if let Ok(verified) = stellereum::sync::verify_fetched_block(h, blk) {
                            if verified.precommit_qc.is_some() {
                                prefetched.insert(h, verified);
                            }
                        }
                    }
                }
            }
        }
    }

    let prefetched = Arc::new(prefetched);
    let fetch_adapter = adapter.clone();
    let fetch_store = store.clone();
    let mut blocks = match stellereum::sync::collect_missing_blocks(
        peer_hash,
        our_last,
        // `walk_cap` is bounded by `policy::max_walk_gap()` (clamped
        // 256..=4096) in production, so the u64 -> usize conversion is
        // lossless on every supported target.
        walk_cap as usize,
        move |h| {
            let p = Arc::clone(&prefetched);
            let st = fetch_store.clone();
            let a = fetch_adapter.clone();
            async move {
                if let Some(b) = p.get(&h) {
                    return Some(b.clone());
                }
                if let Some(st) = st {
                    if let Ok(Some(b)) = tokio::task::spawn_blocking(move || {
                        st.get_block(&h)
                            .ok()
                            .flatten()
                            .filter(|b| b.precommit_qc.is_some())
                    })
                    .await
                    {
                        return Some(b);
                    }
                }
                a.fetch_block(&h).await
            }
        },
    )
    .await
    {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[sync] {e}");
            return None;
        }
    };
    if blocks.is_empty() {
        return None;
    }

    // F3(b): the walked tail must BE the advertised head. A peer that advertises
    // a height above the chain it actually served must be refused, and we
    // re-anchor on the WALKED height, never the advertised one.
    let next_height = match stellereum::sync::walked_head_anchor(&blocks, peer_hash, peer_height) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("[sync] rejecting peer chain: {e}");
            return None;
        }
    };

    // Drop any leading block at or below our finalized height (at genesis this is
    // the height-0 root block), so validation starts exactly at the first height
    // we have not already applied.
    let remove_count = blocks
        .iter()
        .take_while(|b| b.height < expected_first_height)
        .count();
    if remove_count > 0 {
        blocks.drain(..remove_count);
    }
    if blocks.is_empty() {
        return None;
    }

    // W6-A1-4: when CN-VRF v3 is active at any walked height, extract & verify
    // `block.cnvrf_v3.epoch_vdf` into `rt.ready_vdf_beacons` BEFORE calling
    // `validate_sync_chain_*` (which consults `rt.committee_schedule_at(h)`).
    // Below `CNVRF_V3_ACTIVATION_HEIGHT` this is a complete no-op.
    let mut staged_vdf_epochs: Vec<u64> = Vec::new();
    for b in &blocks {
        match rt.extract_and_verify_epoch_vdf_from_block(b) {
            Ok(Some(ep)) => staged_vdf_epochs.push(ep),
            Ok(None) => {}
            Err(e) => {
                for ep in staged_vdf_epochs {
                    rt.remove_ready_vdf_beacon(ep);
                }
                eprintln!("[sync] rejecting peer chain: {e}");
                return None;
            }
        }
    }

    // Shard-aware: a peer must not feed another shard's blocks under our anchor.
    //
    // Validate against the runtime's OWN block shard (`rt.shard_id`), not the
    // raw `shard` argument: the latter is the DHT/blob namespace, which on a
    // single-shard node legitimately differs from the block shard (blocks are
    // always produced on MASTERCHAIN; `--shard N` only picks the namespace).
    // Using the namespace here made a `--shard 1` node reject every masterchain
    // catch-up chain and stall finality. `rt.shard_id` is MASTERCHAIN_SHARD in
    // that case and the shard's own id only in a genuine multi-shard process.
    // W10.5: every block's decision proof is verified against the validator
    // set IN FORCE AT THAT BLOCK'S HEIGHT (never the live set), so a sync
    // window spanning a set change accepts exactly the quorums each height
    // genuinely reached. The validator also returns the canonical hash of each
    // block it hashed, so the apply loop below reuses them instead of hashing
    // every (unchanged) body again for the retention key, the apply call, the
    // RPC record and the parent link.
    let block_hashes =
        match stellereum::sync::validate_sync_chain_for_shard_with_sets_hashed_with_schedule(
            &blocks,
            expected_first_height,
            our_last,
            &|h| rt.validator_set_for_height_strict(h),
            rt.shard_id,
            // Review F2: every block's decision proof is verified and
            // attributed under the committee schedule IN FORCE AT ITS HEIGHT
            // (epoch beacon at/after CN-VRF v3 activation, the parent-hash
            // draw below it). Passing the runtime resolver keeps sync aligned
            // with the producer and the finalize gate.
            &|h| rt.committee_schedule_at(h),
        ) {
            Ok(h) => h,
            Err(e) => {
                for ep in staged_vdf_epochs {
                    rt.remove_ready_vdf_beacon(ep);
                }
                eprintln!("[sync] rejecting peer chain: {e}");
                return None;
            }
        };

    // LIGHT CLIENT ANCHOR (audit W8.3 / production blocker A10).
    //
    // The peer chain must extend the node's OWN quorum-certified chain: the
    // light client is anchored at this node's finalized head (the header that
    // carries the precommit quorum certificate that decided it), and every
    // block the peer offers is applied to a CLONE of that client before
    // anything is applied here. A peer chain that forks off the anchor, that
    // carries a certificate the node's validator set does not accept, or that
    // rolls the state root back is REFUSED here — before a single
    // transaction of it runs.
    //
    // OWN-FINALITY BYPASS (post-restart wedge repair): the light client
    // starts anchored at GENESIS and only advances via `note_light_anchor`
    // on finalize — so a node that restarts onto a stale anchor and then
    // cannot finalize (one height behind a converged quorum, e.g. #388560
    // while peers decide #388561) rejects EVERY peer chain on anchor
    // continuity ("leaves a gap") and can never adopt its way back: no
    // adopt, no finalize, no anchor advance, forever. When the walked chain
    // connects DIRECTLY to this node's own finalized tip (first height is
    // exactly tip+1 AND its prev-hash is exactly the tip hash — the same
    // continuity F3(c) already demands above), the node's own finality IS
    // the anchor: our tip is quorum-certified by construction (we only
    // finalize on a precommit QC), so extending it preserves safety without
    // the light-client view. Everything else still applies unchanged:
    // per-block QC verification above, per-block parent-root continuity and
    // the decision-proof requirement below. Any walk that does NOT connect
    // to our tip takes the light-client path exactly as before (fail-closed
    // preserved).
    //
    // The returned root is the one the last block COMMITS TO (the chain's
    // convention: a header commits to the state it builds on), i.e. the state
    // BEFORE the last block — which the per-block root check below compares
    // against the node's own root.
    let tip_connected = blocks
        .first()
        .is_some_and(|b| b.height == expected_first_height && b.prev_hash == our_last);
    if tip_connected {
        eprintln!(
            "[sync] walk connects to our finalized tip (height {} hash {}): \
             light-client continuity implied by our own finality, anchor check bypassed (per-block QC + root checks still enforced)",
            expected_first_height.saturating_sub(1),
            hex::encode(our_last),
        );
    }
    let anchored_root = match rt.light_client() {
        Some(light) if !tip_connected => {
            match stellereum::sync::verify_synced_blocks_against_anchor_with_sets(
                light,
                &blocks,
                &|h| rt.validator_set_for_height_strict(h),
            ) {
                Ok(r) => Some(r),
                Err(e) => {
                    for ep in staged_vdf_epochs {
                        rt.remove_ready_vdf_beacon(ep);
                    }
                    eprintln!("[sync] rejecting peer chain: light-client anchor: {e}");
                    return None;
                }
            }
        }
        _ => {
            // No anchor (the node has no genesis root wired — a library or
            // test runtime), or the walk is anchored by our own finalized tip
            // (see above). The per-block quorum check above still applies.
            if !tip_connected {
                eprintln!("[sync] light-client anchor: NONE (no genesis anchor wired)");
            }
            None
        }
    };

    // Hoisted out of the loop: the chain is contiguous and already validated,
    // so the tail height/hash and each block's successor are known up front.
    // The previous loop re-derived the tail height on every iteration and did
    // an O(n) scan for the successor (O(n^2) over a full walk), and re-hashed
    // every body for each use.
    let tail_height = blocks.last().map(|x| x.height).unwrap_or(0);
    let tail_hash = block_hashes.last().copied().unwrap_or([0u8; 32]);

    for (i, bh) in block_hashes.iter().copied().enumerate() {
        // The walk CONSUMES each body: its only use after this iteration is the
        // persistence job, which takes ownership of the verified bytes instead
        // of paying a third full copy per block. Slot `i` is never read again
        // (the successor and the pre-extracted tail are).
        let mut b = std::mem::take(&mut blocks[i]);
        // A block header commits to the state it BUILDS ON, so this is checked
        // against the root before applying, not after.
        let root_before = rt.state.get_state_root().await;
        if root_before != b.state_root {
            for ep in &staged_vdf_epochs {
                rt.remove_ready_vdf_beacon(*ep);
            }
            eprintln!(
                "[sync] rejecting peer chain: block {} commits to parent root {} but our state is {}",
                b.height,
                hex::encode(b.state_root),
                hex::encode(root_before)
            );
            return None;
        }
        // The light client's view and the node's view must agree on the state
        // the LAST block builds on: the anchor committed to a root a quorum
        // vouched for, and the node's own state is the root it is really in.
        // (A disagreement means the two views of the chain diverged — exactly
        // the class of bug this wiring exists to catch.)
        if let Some(anchored) = anchored_root {
            if b.height == tail_height && anchored != root_before {
                for ep in &staged_vdf_epochs {
                    rt.remove_ready_vdf_beacon(*ep);
                }
                eprintln!(
                    "[sync] rejecting peer chain: the light-client anchor commits to root {} but our state is {}",
                    hex::encode(anchored),
                    hex::encode(root_before)
                );
                return None;
            }
        }
        // FULL transition parity with live finalization (same as adopt's
        // DOWNTIME PARITY): fees, rewards, unbonding, slashes, rotation -- not
        // just transaction effects (`apply_and_advance` already counts applied
        // txs internally, so nothing is tallied here). A tx-only apply yields
        // a different state root whenever rewards or slashes move balances
        // (every stall height burns downtime for the missed rounds), forking
        // same-height nodes into mutual rejection forever -- observed live:
        // one node finalized #1303 with slashes, the other caught it up
        // tx-only, and the two refused each other's #1304 proposals on
        // state-root mismatch. `validate_sync_chain` above verified each
        // block's precommit QC, which is the slash evidence; install it as
        // this height's QC the same way adoption does. (Equivocation slashing
        // is deferred on ALL paths -- audit F4: its evidence is local vote
        // gossip, not block content, so applying it here while the
        // local-finalize path also applied it split the chain. See
        // `ValidatorRuntime::apply_equivocation_slashes`.)
        //
        // §7 Phase 2 actor-mailbox cap (walk side): a walked block that is
        // over-cap is refused like an adopted one, so a peer cannot smuggle a
        // root-invisible leftover past the decision boundary via the walk.
        if let Err(e) = rt.check_actor_cap(&b).await {
            for ep in &staged_vdf_epochs {
                rt.remove_ready_vdf_beacon(*ep);
            }
            eprintln!("[sync] rejecting peer chain: block {} {e}", b.height);
            return None;
        }
        let Some(qc) = b.precommit_qc.clone() else {
            for ep in &staged_vdf_epochs {
                rt.remove_ready_vdf_beacon(*ep);
            }
            eprintln!(
                "[sync] rejecting peer chain: block {} has no decision proof",
                b.height
            );
            return None;
        };
        rt.hc.precommit_qc = Some(qc);
        // Retain the body: later heights may need it (lock re-proposals,
        // catch-up broadcasts, RPC), and nothing else stores walked blocks.
        rt.blocks.insert(bh, b.clone());
        if let Some(ref qc) = b.precommit_qc {
            rt.last_decision = Some((b.height, b.clone(), qc.clone()));
            // A verified walked decision restores the parent downtime evidence
            // a failed boot reconstruction could not (DOWNTIME-RESTORE).
            rt.parent_evidence_missing = false;
        }
        // S1-WALK-SAFETY-QUARANTINE: WRITE-AHEAD the durable finality record.
        //
        // `apply_and_advance` below durably fsyncs `safety_record_v1` with
        // `finalized_height = b.height` (and every later iteration fsyncs the
        // next height), while the walked BODY and the finalized tip pointer
        // used to be merely ENQUEUED and only flushed once after the whole
        // loop. An aborted walk (an early `return None`) or a crash before the
        // persist queue drained therefore left
        // `safety_record_v1.finalized_height > storage.finalized()`, and
        // `SafetyAuthority::open_from_storage` fail-closes that direction
        // permanently ("finalized_height ... exceeds restored finalized").
        //
        // Write the body and the pointer FIRST, through the same `Storage`
        // handle, so they precede the safety record in sled's log: the safety
        // record's own `db.flush()` inside `advance_height` then makes them
        // durable too (sled's flush covers every tree of the Db). This is
        // write-ahead, not a per-block fsync: no extra barrier is added to a
        // walk of up to `policy::max_walk_gap()` blocks. A crash in the window
        // between this write and the apply can only leave the finalized
        // pointer AHEAD of the safety record with the QC-carrying body present,
        // which boot reconciles (it can never quarantine the node).
        if let Some(ap) = persist {
            let store = ap.storage();
            let height = b.height;
            let hash = bh;
            let written = tokio::task::spawn_blocking(move || {
                let res = store
                    .put_block(&b)
                    .and_then(|_| store.set_finalized(height, &hash));
                (b, res)
            })
            .await;
            match written {
                Ok((body, Ok(()))) => b = body,
                Ok((_, Err(e))) => {
                    for ep in &staged_vdf_epochs {
                        rt.remove_ready_vdf_beacon(*ep);
                    }
                    // Fail closed without advancing safety: a durable order we
                    // cannot establish must not be papered over.
                    eprintln!(
                        "[sync] refusing peer chain: cannot persist finalized block {} before advancing safety: {e}",
                        hex::encode(bh)
                    );
                    return None;
                }
                Err(e) => {
                    for ep in &staged_vdf_epochs {
                        rt.remove_ready_vdf_beacon(*ep);
                    }
                    eprintln!(
                        "[sync] refusing peer chain: finalized persist task for block {} failed: {e}",
                        hex::encode(bh)
                    );
                    return None;
                }
            }
        }
        rt.apply_and_advance(bh, &b).await;
        {
            let pq_reg = rt.state.pq_registry_read().await;
            let active = stellereum::pq_registry::pq_lifecycle_active_at(b.height);
            if !pq_reg.is_empty() {
                stellereum::consensus::sync_committed_pq_registry(&pq_reg, active);
            }
        }
        // Replication for walked heights (same as the adopt path): file this
        // application's outcome so the serve path covers walked heights
        // too. Verified data only: every block here passed validate_sync_chain
        // (QC per height) plus the parent-root/divergence checks in this loop.
        // When `record_lane` is provided (live consensus loop), RPC indexing
        // rides the off-tick FIFO lane just like adopt/finalize; standalone
        // callers without lanes await inline.
        if let Some(lane) = lanes.record_lane {
            let hdr = b.clone();
            let r = rpc.clone();
            let statuses = rt.applied_statuses.clone();
            let fees = rt.applied_fees.clone();
            let events = rt.applied_events.clone();
            lane.submit(async move {
                // LIGHT CLIENT (audit W8.3): publish the finalized header with its
                // quorum certificate, so an external verifier can check a served
                // proof against a root a QUORUM committed to.
                r.record_finalized_header(&hdr).await;
                if statuses.len() == hdr.transactions.len() {
                    r.record_adopted_block_with_events(
                        hdr.height,
                        bh,
                        &hdr.transactions,
                        &statuses,
                        &fees,
                        &events,
                        hdr.timestamp,
                    )
                    .await;
                } else {
                    eprintln!(
                        "[repl] walk #{}: statuses {}/{} txs, receipts skipped",
                        hdr.height,
                        statuses.len(),
                        hdr.transactions.len()
                    );
                }
            });
        } else {
            // LIGHT CLIENT (audit W8.3): publish the finalized header with its
            // quorum certificate, so an external verifier can check a served
            // proof against a root a QUORUM committed to.
            rpc.record_finalized_header(&b).await;
            if rt.applied_statuses.len() == b.transactions.len() {
                rpc.record_adopted_block_with_events(
                    b.height,
                    bh,
                    &b.transactions,
                    &rt.applied_statuses,
                    &rt.applied_fees,
                    &rt.applied_events,
                    b.timestamp,
                )
                .await;
            } else {
                eprintln!(
                    "[repl] walk #{}: statuses {}/{} txs, receipts skipped",
                    b.height,
                    rt.applied_statuses.len(),
                    b.transactions.len()
                );
            }
        }
        // Persist the post-apply artifacts (finalize-path parity). The BODY and
        // the finalized tip pointer were already written above, BEFORE the
        // safety advance (S1-WALK-SAFETY-QUARANTINE); only the state artifacts
        // that require the applied state root are written here.
        let applied_height = b.height;
        let walked_post_root = rt.state.get_state_root().await;
        if let Some(ap) = persist {
            let store = ap.storage();
            let _ = store.put_finalized_post_root(applied_height, walked_post_root);
            if b.shard_id == stellereum::sharding::MASTERCHAIN_SHARD {
                let exec_hardening =
                    stellereum::chain_spec::exec_hardening_v1_active_at(applied_height);
                for (tx_i, tx) in b.transactions.iter().enumerate() {
                    if !rt.applied_statuses.get(tx_i).copied().unwrap_or(false) {
                        continue;
                    }
                    if let Some((evm, pq)) =
                        stellereum::evm_adapter::verified_binding_from_tx_at(tx, exec_hardening)
                    {
                        let _ = store.put_evm_binding_if_absent(&evm, &pq);
                    }
                }
                if store
                    .evm_bindings_cursor()
                    .ok()
                    .flatten()
                    .map(|c| applied_height > c)
                    .unwrap_or(true)
                {
                    let _ = store.set_evm_bindings_cursor(applied_height);
                }
            }
        }
        // Fail fast on divergence: the NEXT block in this same validated chain
        // commits to the state our apply must have produced. Without this, a
        // wrong apply (nondeterminism, heterogeneous history, missed effects)
        // is silent and surfaces hundreds of heights later as an unexplainable
        // parent-root mismatch -- observed live as a failure at #643 after 642
        // matching heights. Pinpoint beats mystery.
        if let Some(next) = blocks.get(i + 1) {
            let ours = rt.state.get_state_root().await;
            if ours != next.state_root {
                for ep in &staged_vdf_epochs {
                    rt.remove_ready_vdf_beacon(*ep);
                }
                eprintln!(
                    "[sync] refusing peer chain: applying block {} moved our root to {} but block {} commits to {}",
                    applied_height,
                    hex::encode(ours),
                    next.height,
                    hex::encode(next.state_root),
                );
                return None;
            }
        }
    }
    if let Some(ap) = persist {
        let hist = rt.export_validator_set_history();
        if !hist.is_empty() {
            ap.enqueue_validator_set_history(hist);
        }
        ap.request_flush();
    }
    // Re-anchor consensus on the WALKED height with FRESH round state (never the
    // advertised height, which `walked_head_anchor` proved equal in any case).
    // This is the part that makes a healed partition work.
    rt.hc = stellereum::consensus::HeightConsensus::new(next_height, rt.validators.clone());
    // Sortition entropy for the re-anchored height: the parent block hash the
    // chain committed (the head we just walked to). Only set it when we
    // actually KNOW it: a placeholder (the zero hash) would elect a committee
    // no other node elects, and the node could never assemble a certificate
    // they accept (audit W6.4b). Unknown => no committee => fail closed.
    if let Some((_, h)) = rt.finalized.last().copied() {
        rt.hc.set_parent_hash(h);
    } else {
        tracing::warn!(
            height = next_height,
            "[sync] re-anchored without a known parent block hash: the sortition committee for this \
             height cannot be elected until the parent is known"
        );
    }
    // S1-WALK-SCHEDULE-RESET: `HeightConsensus::new` starts on the legacy
    // ParentHash schedule. A node that just caught up would keep electing
    // committees the parent-hash way while the rest of the network votes under
    // the CN-VRF v3 epoch-beacon schedule (at/after activation), so its votes
    // would be attributed to the wrong committee and it could never certify
    // the caught-up height. Install the height-correct schedule exactly like
    // `apply_and_advance` does after every finalized block.
    rt.install_committee_schedule();
    // Announce the caught-up tip so peers behind US learn it in place: a node
    // that catches up silently strands whoever waits for its old-height votes
    // (they moved on and will never vote the old height again). Same broadcast
    // the finalize path sends, built from the last walked block's proof.
    //
    // The body comes from the retention map the loop above filled (the walk
    // consumes its own vector, so `blocks.last()` is no longer the tail); the
    // hash and height were pinned before the loop from the validated tail.
    if let Some(last) = rt.blocks.get(&tail_hash).cloned() {
        if let Some(qc) = last.precommit_qc.clone() {
            let net = lanes.consensus_net.cloned().unwrap_or_else(|| {
                Arc::new(ConsensusNetwork::new_for_shard(
                    adapter.clone(),
                    rt.shard_id,
                    &rt.shard_registry,
                ))
            });
            if let Some(lane) = lanes.publish_lane {
                // PUSH (fast path): detached push onto direct peers, and tip
                // DHT publishes offloaded onto `publish_lane` off the tick.
                spawn_committed_push(&net, tail_height, last.clone(), qc);
                let a = adapter.clone();
                lane.submit(async move {
                    let _ = a.retro_publish_blocks([&last], 1).await;
                    a.persist_block_header(shard, &last).await;
                });
            } else {
                push_committed(&net, tail_height, last.clone(), qc).await;
                let _ = adapter.retro_publish_blocks([&last], 1).await;
                adapter.persist_block_header(shard, &last).await;
            }
        }
    }
    Some(next_height.saturating_sub(1))
}

/// Effective retro-publish depth: at least `RETRO_PUBLISH_DEPTH`, widened to
/// cover the full snapshot probe span (`probe_step * probe_steps + tail`) up
/// to the DHT retention horizon so published snapshot boundaries always have
/// retro-published headers and bodies within retention.
pub(crate) fn effective_retro_publish_depth(snapshot_interval: u64, keep_blocks: u64) -> u64 {
    let step = stellereum::sync::snapshot_probe_step(snapshot_interval);
    let steps = stellereum::sync::snapshot_probe_steps(snapshot_interval);
    let max_snap_span = step
        .saturating_mul(steps)
        .saturating_add(stellereum::sync::SNAPSHOT_ANCHOR_TAIL_WINDOW);
    RETRO_PUBLISH_DEPTH
        .max(max_snap_span)
        .min(keep_blocks.max(RETRO_PUBLISH_DEPTH))
}

/// Snapshot-boundary anchor windows (`[B - 1, B, B + 1]`) inside the active
/// retro-publish horizon so lagging peers never stall waiting for the
/// oldest-first backfill cursor to reach the newest snapshot boundaries.
pub(crate) fn snapshot_boundary_anchor_heights(
    tip: u64,
    snapshot_interval: u64,
    depth: u64,
) -> Vec<u64> {
    if tip == 0 {
        return Vec::new();
    }
    let step = stellereum::sync::snapshot_probe_step(snapshot_interval);
    let steps = stellereum::sync::snapshot_probe_steps(snapshot_interval);
    let floor = tip.saturating_sub(depth).saturating_add(1).max(1);
    let mut b = (tip / step) * step;
    let mut heights = Vec::new();
    for _ in 0..steps {
        if b == 0 || b < floor {
            break;
        }
        for h in [b.saturating_sub(1), b, b.saturating_add(1)] {
            if h >= floor && h <= tip && !heights.contains(&h) {
                heights.push(h);
            }
        }
        b = b.saturating_sub(step);
    }
    heights.sort_unstable();
    heights
}

/// Re-publish this node's already-finalized block BODIES and immutable headers,
/// oldest first (plus recent snapshot-boundary anchor windows when backfilling).
///
/// A body only reaches the DHT from `P2pNetworkAdapter::broadcast_block`, and
/// that is called in exactly one place in the tree -- genesis. The live finalize
/// path publishes the head POINTER but never the body. So in practice nothing was
/// putting bodies on the DHT at all, and a peer that was even one block behind
/// asked the network for a body nobody had and its `prev_hash` walk aborted with
/// `block sync: missing block <hash>`. Walking our own history back from the tip
/// makes that walk meet a contiguous run of fetchable bodies.
///
/// NO HEAD POINTER REWIND: `retro_publish_blocks` writes immutable bodies and
/// per-height header/index/QC blobs only, with zero KV writes and zero
/// `shard_head` writes, which is what makes this safe to run from a node that
/// is itself behind: replaying the head pointer from a stale chain would rewind
/// the advertised head and strand the very node trying to catch up.
///
/// Bodies come from `rt.blocks` (this run, in memory) first and from the local
/// block store second (earlier runs -- the case that actually bites). A pruned
/// body is genuinely gone; only its header record survives.
pub(crate) async fn retro_publish_pass(
    adapter: Arc<P2pNetworkAdapter>,
    rt: &ValidatorRuntime,
    persistence: Option<&Arc<stellereum::storage::AsyncPersistence>>,
    published_upto: &mut u64,
    publish_lane: Option<&TickLane>,
) {
    let Some(ap) = persistence else { return };
    let tip = rt.hc.height.saturating_sub(1);
    let snap_int = crate::node::policy::snapshot_interval();
    let depth =
        effective_retro_publish_depth(snap_int, stellereum::network::retention_keep_blocks());
    // The next bounded window above the cursor, never further back than `depth` so a
    // restart does not try to publish an entire chain at once.
    let from = (*published_upto + 1).max(tip.saturating_sub(depth) + 1);
    if from > tip {
        return; // at our own tip: nothing new to push
    }
    let to = (from + RETRO_PUBLISH_MAX_PER_PASS as u64 - 1).min(tip);

    // This run's bodies: no disk I/O, and `finalized` is in height order.
    let start_idx = rt.finalized.partition_point(|(h, _)| *h < from);
    let mut bodies: Vec<stellereum::sharding::Block> = rt.finalized[start_idx..]
        .iter()
        .take_while(|(h, _)| *h <= to)
        .filter_map(|(_, hash)| rt.blocks.get(hash).cloned())
        .collect();

    // Everything from earlier runs: the only copy is the local block store.
    // `Storage` is synchronous sled, so keep it off the async executor.
    let have: std::collections::HashSet<u64> = bodies.iter().map(|b| b.height).collect();
    let mut wanted: Vec<u64> = (from..=to).filter(|h| !have.contains(h)).collect();

    // When backfilling below tip (`to < tip`), also collect any missing blocks
    // in the recent snapshot-boundary anchor windows `[B - 1, B, B + 1]` so
    // snapshot boundaries have immutable headers immediately without waiting
    // for the oldest-first cursor to crawl up to tip.
    let mut boundary_bodies: Vec<stellereum::sharding::Block> = Vec::new();
    let boundary_heights: Vec<u64> = if to < tip {
        snapshot_boundary_anchor_heights(tip, snap_int, depth)
            .into_iter()
            .filter(|h| *h < from || *h > to)
            .collect()
    } else {
        Vec::new()
    };
    let mut boundary_wanted: Vec<u64> = Vec::new();
    for h in &boundary_heights {
        if let Ok(idx) = rt.finalized.binary_search_by_key(h, |(fh, _)| *fh) {
            let (_, hash) = &rt.finalized[idx];
            if let Some(b) = rt.blocks.get(hash) {
                boundary_bodies.push(b.clone());
                continue;
            }
        }
        boundary_wanted.push(*h);
    }

    if !wanted.is_empty() || !boundary_wanted.is_empty() {
        let store = ap.storage();
        wanted.sort_unstable();
        let (from_disk, boundary_from_disk) = tokio::task::spawn_blocking(move || {
            let mut out: Vec<stellereum::sharding::Block> = Vec::new();
            for h in wanted {
                let Ok(hashes) = store.hashes_at_height(h) else {
                    continue;
                };
                for hash in hashes {
                    if let Ok(Some(b)) = store.get_block(&hash) {
                        out.push(b);
                    }
                }
            }
            let mut b_out: Vec<stellereum::sharding::Block> = Vec::new();
            for h in boundary_wanted {
                let Ok(hashes) = store.hashes_at_height(h) else {
                    continue;
                };
                for hash in hashes {
                    if let Ok(Some(b)) = store.get_block(&hash) {
                        b_out.push(b);
                    }
                }
            }
            (out, b_out)
        })
        .await
        .unwrap_or_default();
        bodies.extend(from_disk);
        bodies.sort_by_key(|b| b.height);
        boundary_bodies.extend(boundary_from_disk);
        boundary_bodies.sort_by_key(|b| b.height);
    }
    // A fork can put more than one body at a height; the pass stays bounded anyway.
    bodies.truncate(RETRO_PUBLISH_MAX_PER_PASS);

    if !bodies.is_empty() || !boundary_bodies.is_empty() {
        if let Some(lane) = publish_lane {
            let a = adapter.clone();
            lane.submit(async move {
                if !bodies.is_empty() {
                    let report = a
                        .retro_publish_blocks(bodies.iter(), RETRO_PUBLISH_MAX_PER_PASS)
                        .await;
                    if report.published > 0 || report.failed > 0 {
                        info!(
                            "[retro-publish] heights {from}..={to}: published {}/{}, failed {}{}",
                            report.published,
                            report.attempted,
                            report.failed,
                            match &report.first_error {
                                Some(e) => format!(" ({e})"),
                                None => String::new(),
                            }
                        );
                    }
                }
                if !boundary_bodies.is_empty() {
                    let max_b = boundary_bodies.len();
                    let _ = a.retro_publish_blocks(boundary_bodies.iter(), max_b).await;
                }
            });
        } else {
            if !bodies.is_empty() {
                let report = adapter
                    .retro_publish_blocks(bodies.iter(), RETRO_PUBLISH_MAX_PER_PASS)
                    .await;
                if report.published > 0 || report.failed > 0 {
                    info!(
                        "[retro-publish] heights {from}..={to}: published {}/{}, failed {}{}",
                        report.published,
                        report.attempted,
                        report.failed,
                        match &report.first_error {
                            Some(e) => format!(" ({e})"),
                            None => String::new(),
                        }
                    );
                }
            }
            if !boundary_bodies.is_empty() {
                let max_b = boundary_bodies.len();
                let _ = adapter
                    .retro_publish_blocks(boundary_bodies.iter(), max_b)
                    .await;
            }
        }
    }
    // Advance past the whole window, failures included: a body we cannot publish
    // (pruned locally, or a DHT with no storage role) will not do better next pass,
    // and a cursor left behind it would stall the window on the same dead block
    // forever. The count and reason are logged above, never swallowed.
    *published_upto = to;
}

#[cfg(test)]
mod recovery_walk_tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::path::PathBuf;
    use stellereum::consensus::{register_validator_pq_key, ValidatorSet, Vote, VoteKind, VoteSet};
    use stellereum::post_quantum::{FalconKeypair, PqScheme};
    use stellereum::sharding::{Block, MASTERCHAIN_SHARD};
    use stellereum::state_engine::InMemoryStateEngine;

    fn vset(ks: &[SigningKey]) -> ValidatorSet {
        ValidatorSet::from_list(
            ks.iter()
                .map(|k| (k.verifying_key().to_bytes(), 1))
                .collect(),
        )
    }

    fn fks_for(ks: &[SigningKey]) -> Vec<FalconKeypair> {
        ks.iter()
            .enumerate()
            .map(|(i, _)| FalconKeypair::generate_from_seed(i as u8))
            .collect()
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

    async fn seed_engine_pq_keys(
        engine: &InMemoryStateEngine,
        ks: &[SigningKey],
        fks: &[FalconKeypair],
    ) {
        let mut ledger = engine.staking_write().await;
        let mut pq_reg = engine.pq_registry_write().await;
        for (k, fk) in ks.iter().zip(fks.iter()) {
            let id = k.verifying_key().to_bytes();
            ledger
                .validator_pq_keys
                .insert(id, (PqScheme::Falcon512, fk.public_key.clone()));
            let _ =
                pq_reg.adopt_legacy_key_at(id, PqScheme::Falcon512, fk.public_key.clone(), 0, true);
        }
        stellereum::consensus::sync_committed_pq_registry(&pq_reg, true);
    }

    /// Build a contiguous chain by running the SAME full transition the walk
    /// applies (`apply_and_advance`), so every block's committed parent root
    /// is exactly the root a node holding the prefix will have.
    async fn build_chain(
        ks: &[SigningKey],
        fks: &[FalconKeypair],
        n: u64,
    ) -> (Vec<Block>, [u8; 32]) {
        let vs = vset(ks);
        let engine = Arc::new(InMemoryStateEngine::new());
        seed_engine_pq_keys(&engine, ks, fks).await;
        let mut builder = ValidatorRuntime::new(ks[0].clone(), vs.clone(), engine, 1);
        let mut blocks = Vec::with_capacity(n as usize);
        let mut prev = [0u8; 32];
        for h in 1..=n {
            let root = builder.state.get_state_root().await;
            let proposer_id = vs.proposer_for(h, 0).expect("non-empty set has a proposer");
            let proposer_idx = ks
                .iter()
                .position(|k| k.verifying_key().to_bytes() == proposer_id)
                .expect("proposer is a member");
            let mut b = Block {
                shard_id: MASTERCHAIN_SHARD,
                height: h,
                prev_hash: prev,
                state_root: root,
                transactions: vec![],
                cross_shard_out: vec![],
                timestamp: 1_000 + h,
                proposer: proposer_id,
                validator_signatures: vec![],
                shard_headers: vec![],
                precommit_qc: None,
                last_qc: None,
                mmr_epoch_root: [0u8; 32],
                cnvrf_v3: None,
                order_merkle_root: [0u8; 32],
                epoch_key_commitment: [0u8; 32],
                round: 0,
            };
            b.sign_block_with_falcon(&ks[proposer_idx], &fks[proposer_idx]);
            let bh = b.compute_hash();
            attach_quorum(&mut b, ks, fks, &vs, h, bh, prev);
            builder.apply_and_advance(bh, &b).await;
            prev = bh;
            blocks.push(b);
        }
        let tip_root = builder.state.get_state_root().await;
        (blocks, tip_root)
    }

    async fn test_adapter(tag: &str) -> (P2pNetworkAdapter, PathBuf) {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "stell-recovery-walk-{tag}-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let cfg = infnode::config::NodeConfig {
            name: "test".to_string(),
            listen: "127.0.0.1:0".to_string(),
            client_listen: None,
            advertise: None,
            peers: vec![],
            allow_unknown: false,
            unknown_allow: vec![],
            metrics_listen: None,
            log_level: Some(0),
            roles: Default::default(),
            outbox_ttl_secs: 3600,
            storage_roles: vec![],
            validators: vec![],
            domain: None,
            web_listen: None,
            wallet: None,
            web_static: None,
        };
        let node = infnode::node::Node::new(
            cfg,
            infnode::keyring::NodeKeys::generate(),
            infnode::keyring::PqKeys::generate(),
            dir.clone(),
            PathBuf::new(),
        )
        .await
        .expect("test node");
        let adapter = P2pNetworkAdapter::new(node);
        adapter.set_epoch(stellereum::network::EpochTag::from_genesis(&[0x77u8; 32]));
        (adapter, dir)
    }

    fn test_rpc_state() -> Arc<stellereum::rpc::RpcState> {
        Arc::new(stellereum::rpc::RpcState {
            engine: Arc::new(InMemoryStateEngine::new()),
            mempool: Arc::new(tokio::sync::RwLock::new(
                stellereum::mempool::Mempool::default(),
            )),
            height: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            node_id: "recovery-walk-test".to_string(),
            chain_id: stellereum::zkml::DEFAULT_CHAIN_ID,
            staking: Arc::new(tokio::sync::RwLock::new(
                stellereum::staking::StakingLedger::new(),
            )),
            governance: Arc::new(tokio::sync::RwLock::new(
                stellereum::governance::Governance::new(),
            )),
            recent_blocks: Arc::new(tokio::sync::RwLock::new(std::collections::VecDeque::new())),
            receipts: Arc::new(tokio::sync::RwLock::new(
                stellereum::rpc::ReceiptIndex::default(),
            )),
            auth_token: None,
            tx_broadcast: None,
            faucet: None,
            faucet_token: None,
            msg_signing_seed: None,
            archive_store: None,
            shard_registry: stellereum::sharding::ShardRegistry::single(),
        })
    }

    /// A node restored at `B` with NO snapshot at or above `B` must still
    /// reach the head by walking bodies. `gap` deliberately exceeds one walk
    /// window (400 > the documented 256 cap; 1100 > the cadence-derived
    /// 1064), the next snapshot is never published, and the resulting state
    /// root must equal the never-fell-behind builder's.
    async fn run_recovery_case(seed: u8, gap: u64, hop_cap: u64, use_production_wrapper: bool) {
        const B: u64 = 64;
        let n = B + gap;
        let ks = vec![SigningKey::from_bytes(&[seed; 32])];
        let fks = fks_for(&ks);
        let vs = vset(&ks);
        let (blocks, tip_root) = build_chain(&ks, &fks, n).await;

        let (adapter, dir) = test_adapter(&format!("{seed}-{gap}")).await;
        let adapter = Arc::new(adapter);

        // Bodies above our restored boundary (the walk never needs the prefix)
        // and only the headers the hops will ask for. No state snapshot exists.
        let tail: Vec<&Block> = blocks.iter().filter(|b| b.height > B).collect();
        let report = adapter.retro_publish_blocks(tail, blocks.len()).await;
        assert_eq!(
            report.failed, 0,
            "all recovery bodies must publish: {:?}",
            report.first_error
        );
        let mut hop_height = B;
        while n - hop_height > hop_cap {
            hop_height += hop_cap;
            adapter
                .persist_block_header(MASTERCHAIN_SHARD, &blocks[(hop_height - 1) as usize])
                .await;
        }

        // The lagging node replays only its prefix through the same full
        // transition, then has to close `gap` by the walk alone.
        let lagging_engine = Arc::new(InMemoryStateEngine::new());
        seed_engine_pq_keys(&lagging_engine, &ks, &fks).await;
        let mut lagging = ValidatorRuntime::new(ks[0].clone(), vs, lagging_engine, 1);
        for b in blocks.iter().take(B as usize) {
            let bh = b.compute_hash();
            lagging.apply_and_advance(bh, b).await;
        }
        assert_eq!(
            lagging.finalized.last().map(|(h, _)| *h),
            Some(B),
            "fixture must restore at exactly height B"
        );

        let head_hash = blocks.last().expect("non-empty chain").compute_hash();
        let rpc = test_rpc_state();

        // Pre-fix proof, on the SAME fixture: one window refuses this gap and
        // applies nothing. That refusal used to be the only body path, so the
        // node retried forever when no newer snapshot existed. Multi-hop below
        // must then close it.
        if gap > hop_cap {
            let single = walk_chain_once(
                &adapter,
                &mut lagging,
                MASTERCHAIN_SHARD,
                n,
                head_hash,
                None,
                &rpc,
                hop_cap,
            )
            .await;
            assert_eq!(
                single, None,
                "a single {hop_cap}-block window must refuse the {gap}-block gap \
                 (this is the pre-fix deadlock)"
            );
            assert_eq!(
                lagging.finalized.last().map(|(h, _)| *h),
                Some(B),
                "the refused single window must not move the node"
            );
        }

        let got = if use_production_wrapper {
            walk_chain(
                &adapter,
                &mut lagging,
                MASTERCHAIN_SHARD,
                n,
                head_hash,
                None,
                &rpc,
            )
            .await
        } else {
            walk_chain_multi_hop(
                &adapter,
                &mut lagging,
                MASTERCHAIN_SHARD,
                n,
                head_hash,
                None,
                &rpc,
                hop_cap,
            )
            .await
        };
        assert_eq!(
            got,
            Some(n),
            "gap {gap} (hop cap {hop_cap}) must walk to the head without a snapshot"
        );
        assert_eq!(
            lagging.state.get_state_root().await,
            tip_root,
            "the recovered node's state root must equal the node that never fell behind \
             (gap {gap}, hop cap {hop_cap})"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // GATE: process-global PQ registry tests serialize across awaits
    async fn recovery_walk_closes_400_and_1100_without_a_new_snapshot() {
        // The fixtures below seed/replace the process-global PQ registry and
        // verify votes against it; hold the ONE shared test lock so no
        // parallel test can swap the key set mid-walk.
        let _global = crate::node::policy::test_support::global_lock();
        // Production entry point, cadence-derived cap: 400 fits one hop on
        // current policy, 1100 does NOT (1064 default) and must enter
        // multi-hop recovery. On the pre-fix code the 1100 case returns None
        // at the cap check instead of reaching the head.
        run_recovery_case(0x41, 400, crate::node::policy::max_walk_gap(), true).await;
        run_recovery_case(0x42, 1100, crate::node::policy::max_walk_gap(), true).await;
        // Explicit 256-block per-hop window (the historical honest bound):
        // 400 must now take MULTIPLE verified hops, not one long walk.
        run_recovery_case(0x43, 400, 256, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // GATE: process-global PQ registry tests serialize across awaits
    async fn walk_ignores_uncertified_proposal_in_rt_blocks_and_fetches_decided_body() {
        // See `recovery_walk_closes_*`: this test also seeds the global PQ
        // registry before checking that votes admit.
        let _global = crate::node::policy::test_support::global_lock();
        const B: u64 = 4;
        const N: u64 = 7;
        let ks = vec![SigningKey::from_bytes(&[0x59; 32])];
        let fks = fks_for(&ks);
        let vs = vset(&ks);
        let (blocks, tip_root) = build_chain(&ks, &fks, N).await;

        let (adapter, dir) = test_adapter("uncert-proposal").await;
        let adapter = Arc::new(adapter);
        let tail: Vec<&Block> = blocks.iter().filter(|b| b.height > B).collect();
        let report = adapter.retro_publish_blocks(tail, blocks.len()).await;
        assert_eq!(report.failed, 0);

        let lagging_engine = Arc::new(InMemoryStateEngine::new());
        seed_engine_pq_keys(&lagging_engine, &ks, &fks).await;
        let mut lagging = ValidatorRuntime::new(ks[0].clone(), vs, lagging_engine, 1);
        for b in blocks.iter().take(B as usize) {
            let bh = b.compute_hash();
            lagging.apply_and_advance(bh, b).await;
        }

        // Inject an uncertified copy of block B+1 (`precommit_qc: None`, matching an
        // in-flight proposal that was never finalized) into `lagging.blocks`:
        // `walk_chain_once` must skip it and fetch the QC-certified block from DHT.
        let mut uncert = blocks[B as usize].clone();
        let decided_hash = uncert.compute_hash();
        uncert.precommit_qc = None;
        assert_eq!(uncert.compute_hash(), decided_hash);
        lagging.blocks.insert(decided_hash, uncert);

        let head_hash = blocks.last().expect("non-empty chain").compute_hash();
        let rpc = test_rpc_state();
        let got = walk_chain_once(
            &adapter,
            &mut lagging,
            MASTERCHAIN_SHARD,
            N,
            head_hash,
            None,
            &rpc,
            64,
        )
        .await;
        assert_eq!(got, Some(N));
        assert_eq!(lagging.state.get_state_root().await, tip_root);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A blind-QC-probe sidecar is catch-up EVIDENCE only when it carries a
    /// REAL precommit quorum for that exact height. A well-formed but
    /// signature-less sidecar decoded from the DHT must never be able to
    /// scale the pass budget or re-arm the reactive latch (that would let any
    /// DHT peer pin a validator in repeated expensive catch-up ticks).
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // GATE: the PQ registry is process-global; this test must not race it.
    async fn blind_probe_evidence_requires_a_verified_precommit_quorum() {
        let _global = crate::node::policy::test_support::global_lock();
        let ks = vec![SigningKey::from_bytes(&[0x61; 32])];
        let fks = fks_for(&ks);
        let vs = vset(&ks);
        let (blocks, _root) = build_chain(&ks, &fks, 1).await;
        let block = &blocks[0];
        let qc = block.precommit_qc.clone().expect("genuine QC attached");
        let rt = ValidatorRuntime::new(ks[0].clone(), vs, Arc::new(InMemoryStateEngine::new()), 1);

        assert_eq!(
            verified_qc_sidecar_hash(&rt, &qc, 1),
            Some(block.compute_hash()),
            "a genuine precommit quorum is usable evidence"
        );

        let mut unsigned = qc.clone();
        unsigned.signatures.clear();
        assert!(
            verified_qc_sidecar_hash(&rt, &unsigned, 1).is_none(),
            "a signature-less sidecar must never become catch-up evidence"
        );

        let mut prevote_kind = qc.clone();
        prevote_kind.kind = VoteKind::Prevote;
        assert!(verified_qc_sidecar_hash(&rt, &prevote_kind, 1).is_none());
        assert!(
            verified_qc_sidecar_hash(&rt, &qc, 2).is_none(),
            "a sidecar is bound to its own height"
        );
    }

    /// S1-WALK-SAFETY-QUARANTINE + S1-WALK-SCHEDULE-RESET.
    ///
    /// A walk with persistence enabled must (1) have already written the
    /// durable finalized tip pointer and the QC-carrying body for the walked
    /// head by the time it returns -- they are written BEFORE
    /// `apply_and_advance` fsyncs `safety_record_v1`, so an aborted walk or a
    /// crash can never leave the safety record ahead of `storage.finalized()`
    /// (the direction boot quarantines) -- and (2) leave consensus on the
    /// height-correct CN-VRF v3 epoch-beacon schedule instead of the
    /// `ParentHash` default that `HeightConsensus::new` installs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::await_holding_lock)] // GATE: process-global PQ registry, as in the tests above.
    async fn recovery_walk_write_aheads_finality_and_installs_beacon_schedule() {
        let _global = crate::node::policy::test_support::global_lock();
        const B: u64 = 4;
        const N: u64 = 10;
        let ks = vec![SigningKey::from_bytes(&[0x6A; 32])];
        let fks = fks_for(&ks);
        let vs = vset(&ks);
        let (blocks, tip_root) = build_chain(&ks, &fks, N).await;

        let (adapter, dir) = test_adapter("walk-durable-finality").await;
        let adapter = Arc::new(adapter);
        let tail: Vec<&Block> = blocks.iter().filter(|b| b.height > B).collect();
        let report = adapter.retro_publish_blocks(tail, blocks.len()).await;
        assert_eq!(
            report.failed, 0,
            "all recovery bodies must publish: {:?}",
            report.first_error
        );
        adapter
            .persist_block_header(MASTERCHAIN_SHARD, blocks.last().expect("non-empty chain"))
            .await;

        let lagging_engine = Arc::new(InMemoryStateEngine::new());
        seed_engine_pq_keys(&lagging_engine, &ks, &fks).await;
        let mut lagging = ValidatorRuntime::new(ks[0].clone(), vs, lagging_engine, 1);
        for b in blocks.iter().take(B as usize) {
            lagging.apply_and_advance(b.compute_hash(), b).await;
        }
        // CN-VRF v3 activates at the RE-ANCHORED height (N + 1) for the
        // lagging node: every WALKED block (<= N) still validates/applies under
        // the same ParentHash rules the producer used (so the fixture's roots
        // are unchanged), while the freshly built `HeightConsensus` for N + 1
        // must not be left on its `ParentHash` default. The epoch-0 bootstrap
        // beacon is deterministic (see `active_epoch_beacon`), so
        // `Beacon(Some(_))` is installed rather than fail-closed.
        const ACTIVATION: u64 = N + 1;
        lagging.set_cnvrf_v3_activation_height_for_tests(ACTIVATION);

        let store_dir = dir.join("walk-store");
        std::fs::create_dir_all(&store_dir).expect("store tmpdir");
        let storage =
            Arc::new(stellereum::storage::Storage::open(&store_dir).expect("open walk storage"));
        let persist = Arc::new(stellereum::storage::AsyncPersistence::start(
            storage.clone(),
        ));

        let head_hash = blocks.last().expect("non-empty chain").compute_hash();
        let rpc = test_rpc_state();
        let got = walk_chain_once_with_lanes(
            &adapter,
            &mut lagging,
            MASTERCHAIN_SHARD,
            N,
            head_hash,
            Some(&persist),
            &rpc,
            crate::node::policy::max_walk_gap(),
            SyncLanes::default(),
        )
        .await;
        assert_eq!(got, Some(N), "walk must reach the advertised head");
        assert_eq!(
            lagging.state.get_state_root().await,
            tip_root,
            "walked state must equal the producer's"
        );

        // (1) Write-ahead durability: the pointer + body are already in the
        // store even though the walk only `request_flush`ed asynchronously.
        assert_eq!(
            storage.finalized().expect("read finalized"),
            Some((N, head_hash)),
            "the walked finalized tip must be durable before/with the safety record"
        );
        assert!(
            storage
                .get_block(&head_hash)
                .expect("read walked body")
                .is_some(),
            "the walked body (with its decision QC) must be durable too"
        );

        // (2) The caught-up node keeps the epoch-beacon schedule.
        assert_eq!(
            lagging.hc.committee_schedule,
            lagging.committee_schedule_at(lagging.hc.height),
            "re-anchored height must use the runtime's height-correct schedule"
        );
        assert!(
            lagging.hc.committee_schedule.is_beacon(),
            "a caught-up node must not reset to the ParentHash schedule"
        );

        drop(persist);
        std::fs::remove_dir_all(&dir).ok();
    }
}
