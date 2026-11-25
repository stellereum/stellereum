use super::naming::{
    block_body_blob_name, block_name, head_name, header_index_name, header_name, header_qc_name,
    header_v2_name, snapshot_latest_name, snapshot_name, snapv4_manifest_name, snapv4_unit_name,
    EpochTag, BUCKET_STELLEREUM_BLOCKS, BUCKET_STELLEREUM_HEAD, BUCKET_STELLEREUM_HEADERS,
    BUCKET_STELLEREUM_STATE, PREFIX_BLOCK_HASH, PREFIX_LATEST_HEIGHT, PREFIX_MEMPOOL_TX,
    PREFIX_MEV_COMMIT, PREFIX_ORACLE, PREFIX_SHARD_MEMPOOL,
};
use super::retention::{
    dht_blob_ttl_ms, dht_forever_ttl_ms, header_publish_slots, paced_store_blob,
    paced_store_blob_in_lane, retention_keep_blocks, ReplStoreKind,
};
use super::{
    decode_wire_limited, verify_bytes_blake3_hash, P2pNetworkAdapter, RecentHqPublishCache,
    MAX_WIRE_BLOCK_BYTES,
};
use crate::mev::BlindRoundCommitment;
use crate::oracle::PriceFeedUpdate;
use crate::sharding::{Block, Transaction};
use infnode::node::Node;
use std::sync::Arc;

/// Whether publishing `height` as a shard head is safe, given `last_published`
/// is the highest head this process has advertised before.
///
/// Two refusals, both fail-closed:
/// * `height == 0`: a node that knows only genesis has no tip to advertise. Its
///   height-0 write would last-writer-win over a live tip and strand every
///   catching-up node (including itself) on "peer height 0".
/// * `height <= last_published`: a stale republish rewinds the advertised head.
///   Pure so tests pin it without a live DHT.
pub fn head_publish_allowed(height: u64, last_published: u64) -> bool {
    height > 0 && height > last_published
}

/// Committed-domain kinds published beside every state snapshot (see
/// `P2pNetworkAdapter::persist_domain_snapshot`). The single source of truth
/// for the publish path in `src/main.rs`: adding a kind here publishes it,
/// removing one stops. Must stay a SUPERSET of what a synced node needs to
/// re-root, minus the documented gap: `sync::SYNC_DOMAIN_KINDS` additionally
/// fetches `pq_keys` (forward-compatible — absent means empty), which has no
/// publisher yet because raw PQ pins are auxiliary to the state root (the
/// accounts snapshot already commits to every pin's hash). Pinned by
/// `tests/observer_and_recovery_tests.rs`.
pub const SNAPSHOT_PUBLISH_DOMAIN_KINDS: &[&str] = &[
    "domains",
    "session",
    "bridge",
    "zkml",
    "cross_shard",
    "cnvrf_v3",
    "pq_keys",
    "evm_bindings",
    "pq_registry",
];

/// Pacing between retro-publish bodies (ms). Each `store_blob` spawns a
/// background `replicate_blob` (up to 20s, fanning out to K peers), so a
/// 128-body pass fired back-to-back spawns 128 concurrent replicators.
/// 5ms spreads the burst (~0.64s per full pass) without slowing the window.
pub const RETRO_PUBLISH_PACE_MS: u64 = 5;

impl P2pNetworkAdapter {
    /// Broadcast a newly finalized block to the P2P overlay network
    pub async fn broadcast_block(&self, block: &Block) -> Result<[u8; 32], String> {
        let block_hash = block.compute_hash();
        let hash_hex = hex::encode(block_hash);

        let block_bytes =
            bincode::serialize(block).map_err(|e| format!("Serialization failed: {:?}", e))?;

        // 1. Store block binary chunks in infnode blob storage. The manifest
        // carries the retention-window TTL (`dht_blob_ttl_ms`): bodies below
        // finalized − KEEP are pruned by `maybe_prune_retained`, and this TTL
        // collects replicas/strays in the sweep even where no prune runs.
        // Paced (backpressure 2026-10-14): bounded concurrency + min interval +
        // bounded retries + circuit breaker, so a slow peer cannot turn this
        // into a mutual-DDoS retry storm.
        paced_store_blob(
            &self.node,
            BUCKET_STELLEREUM_BLOCKS,
            &block_name(&self.epoch(), &hash_hex),
            &block_bytes,
            dht_blob_ttl_ms(retention_keep_blocks()),
            ReplStoreKind::Bulk,
        )
        .await;

        // 2. Publish block hash to DHT KV for discovery by peers
        let block_kv_key = format!("{}{}", PREFIX_BLOCK_HASH, hash_hex);
        self.node.kv_store_local(&block_kv_key, &hash_hex).await;

        // 3. Update shard latest height in DHT KV
        let height_kv_key = format!("{}{}", PREFIX_LATEST_HEIGHT, block.shard_id);
        let height_val = format!("{}:{}", block.height, hash_hex);
        self.node.kv_store_local(&height_kv_key, &height_val).await;

        Ok(block_hash)
    }

    /// Publish a height's `_hq_` precommit-QC sidecar EARLY, as soon as the QC
    /// exists — before the body is persisted/executed.
    ///
    /// The sidecar used to ride `publish_block`/`persist_block_header` only,
    /// i.e. after header/index writes and often after the apply. Peers that
    /// missed the deciding votes therefore read "header/body present, QC
    /// missing" for a window and paid a `fetch_block_qc` miss (the live
    /// `shard=0 height=21508 ... failed; backing off 2000ms`). This publishes
    /// the same bytes, under the same name/TTL/lane, directly from the
    /// finalize path while the QC is already in hand.
    ///
    /// Exactly-once is preserved by the shared `claim_hq_publish` cache: a
    /// later `publish_block`/`persist_block_header` for the same
    /// `(shard, height, block_hash)` is a no-op duplicate.
    ///
    /// ORDERING INVARIANT (same as `persist_block_header`): the header blob
    /// and index for this `(shard, height)` MUST already be published (the
    /// proposer publishes them at propose/finalize time). The QC is never the
    /// only blob present for a height: callers that do not publish the header
    /// must not call this, because a lone QC sidecar would look to a reader
    /// like a half-trusted anchor. The finalize call site therefore publishes
    /// header+index first in the same `publish_lane` job.
    pub async fn publish_block_qc(
        &self,
        shard_id: u32,
        height: u64,
        block_hash: [u8; 32],
        qc: &crate::consensus::QuorumCertificate,
    ) {
        if !claim_hq_publish(&self.recent_hq_published, shard_id, height, block_hash) {
            return;
        }
        let Ok(bytes) = bincode::serialize(qc) else {
            return;
        };
        let ttl = dht_blob_ttl_ms(retention_keep_blocks());
        let qc_slot = header_publish_slots()[2];
        paced_store_blob_in_lane(
            &self.node,
            BUCKET_STELLEREUM_HEADERS,
            &header_qc_name(&self.epoch(), shard_id, height),
            &bytes,
            ttl,
            qc_slot.charge,
            qc_slot.lane,
        )
        .await;
    }

    // ==================== Retro-publish of already-finalized bodies ====================
    //
    // A body is only ever written to the DHT by `broadcast_block`, which runs at
    // the moment of finalization. So a body finalized by an earlier run, or
    // before retro-publishing existed, exists only in this node's local disk
    // store, and a fresh or lagging node can never fetch it: `collect_missing_blocks`
    // walks `prev_hash` and dies with `block sync: missing block <hash>` no matter
    // how far ahead the advertised head is. That is exactly the 1007-block catch-up
    // failure on the live stand.
    //
    // The fix is to push this node's recent history back onto the DHT after the
    // fact, WITHOUT repeating what `broadcast_block` does. Only the body is
    // republished: the height pointer and the block-hash index are head
    // announcements, and replaying them from a stale node would rewind the
    // network's advertised head to the middle of the stale node's own chain.

    /// Publish one already-finalized block body, by hash, for peers to fetch.
    ///
    /// Same bucket and name convention as `broadcast_block`, so `fetch_block`
    /// finds it — but it writes NO `PREFIX_LATEST_HEIGHT` and NO
    /// `PREFIX_BLOCK_HASH` entry. See `plan_block_body_publish` for why those two
    /// writes must not be replayed from a re-publish.
    pub async fn retro_publish_block(&self, block: &Block) -> Result<[u8; 32], String> {
        let epoch = self.epoch();
        let writes = plan_block_body_publish(&epoch, block)?;
        apply_publish_plan(&self.node, &writes).await?;
        let block_hash = block.compute_hash();
        if publish_block_header_companion(&self.node, &epoch, block).await
            && claim_hq_publish(
                &self.recent_hq_published,
                block.shard_id,
                block.height,
                block_hash,
            )
        {
            publish_block_qc_companion(&self.node, &epoch, block).await;
        }
        Ok(block_hash)
    }

    /// Publish one already-finalized block body from its stored bytes, addressed
    /// by the hash a peer will ask for.
    ///
    /// For a caller reading raw bodies off disk, so the body is never
    /// re-serialized through a `Block` it had to decode first. The bytes are
    /// checked against `block_hash` before anything is written: a body filed
    /// under the wrong hash is a body `fetch_block` will hand to a peer as if it
    /// were the block that peer asked for, and the resulting `prev_hash` walk
    /// would follow a chain that does not exist.
    ///
    /// Like every other re-publish path this touches no head pointer and no
    /// block-hash index entry.
    pub async fn retro_publish_block_by_hash(
        &self,
        block_hash: [u8; 32],
        body: &[u8],
    ) -> Result<(), String> {
        let write = plan_block_body_publish_bytes(&self.epoch(), block_hash, body)?;
        apply_publish_plan(&self.node, &[write]).await
    }

    /// Re-publish a BOUNDED window of already-finalized block bodies.
    ///
    /// `blocks` is any iterator of block references — the caller decides which
    /// ones (e.g. the most recent N of `rt.finalized`, read back out of the local
    /// block store). `max` caps how many bodies this pass may touch, so a node
    /// with a long history never builds one enormous DHT write nor holds an
    /// unbounded amount of serialized state in memory: the caller runs pass after
    /// pass, feeding the remainder back in, while `report.maybe_more` is true.
    ///
    /// Tolerant by design: one body failing (a local block that is gone, a blob
    /// that reached neither local storage nor a replica) must not abandon the
    /// other N-1, because those are the ones that unblock the peer. The failures
    /// are counted and the first reason kept in `report.first_error` — never
    /// swallowed.
    pub async fn retro_publish_blocks<'a, I>(&self, blocks: I, max: usize) -> RetroPublishReport
    where
        I: IntoIterator<Item = &'a Block>,
    {
        let shared = self.node.clone();
        let epoch = self.epoch();
        let recent_hq = Arc::clone(&self.recent_hq_published);
        let mut it = blocks.into_iter();
        retro_publish_chunk(&mut it, max, move |b| {
            let node = shared.clone();
            let epoch = epoch.clone();
            let recent_hq = Arc::clone(&recent_hq);
            async move {
                match plan_block_body_publish(&epoch, b) {
                    Ok(writes) => {
                        apply_publish_plan(&node, &writes).await?;
                        if publish_block_header_companion(&node, &epoch, b).await
                            && claim_hq_publish(&recent_hq, b.shard_id, b.height, b.compute_hash())
                        {
                            publish_block_qc_companion(&node, &epoch, b).await;
                        }
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
        })
        .await
    }

    /// Overwrite a fixed-name pointer blob without orphaning its chunks.
    ///
    /// Chunk ids are content-addressed (every id mixes `H(plaintext)`), so ANY
    /// content change retires the WHOLE old chunk set, while the kv sweep only
    /// collects EXPIRED manifests — never an overwritten one. Without this, the
    /// head pointer (`{epoch}_shard_{n}_head`, rewritten every finalize and
    /// every ~30s probe) and the snapshot pointer (`{epoch}_snap_latest_{n}`,
    /// rewritten every snapshot) leak one chunk set per rewrite. Deleting the
    /// old blob first keeps the steady state at one live chunk set.
    ///
    /// LOCAL-ONLY (`delete_blob_local`, no replica fan-out) on purpose: the
    /// per-finalize path must not gain DHT traffic, the wire format is
    /// unchanged (old/new nodes interoperate), and the store below rewrites
    /// the manifest synchronously on the same FIFO lane, so readers see at
    /// most a momentary miss, repaired by the next finalize/probe republish.
    /// A failed store leaves the same state as before this change (the
    /// overwrite itself already replaced the manifest).
    async fn store_pointer_overwrite(&self, bucket: &str, name: &str, payload: &[u8], ttl_ms: i64) {
        self.node.delete_blob_local(bucket, name).await;
        // Same backpressure as every other publish (bounded, never infinite);
        // charged as a Pointer (small floor) rather than Bulk so the per-finalize
        // head republish cannot lag the tip behind the bulk lane.
        paced_store_blob(
            &self.node,
            bucket,
            name,
            payload,
            ttl_ms,
            ReplStoreKind::Pointer,
        )
        .await;
    }

    /// Publish this node's finalized head so a peer can discover it.
    ///
    /// This exists because the shard head pointer kept in DHT KV is written with
    /// `kv_store_local` and read back with `get_local_kv` — both strictly local.
    /// So `get_latest_shard_height` could only ever return *this* node's own
    /// published height, and a node asking "is a peer ahead of me?" was really
    /// asking "am I ahead of myself?". Block sync therefore never fired, and a
    /// node that fell behind had no way to learn that anyone was ahead of it.
    ///
    /// The head is stored as a blob in the replicated DHT bucket instead, which
    /// is the same path `fetch_block` uses, so a peer can actually read it.
    ///
    /// SELF-SHADOW GUARD: the head key is shared and last-writer-wins, so this
    /// refuses anything that is not a forward move of THIS process
    /// (`head_publish_allowed`): height 0 (genesis-only nodes have no tip to
    /// advertise — their write would bury a live tip) and heights at or below
    /// what this process already published (a stale republish rewinds the
    /// advertised head for every reader, including ourselves: the local
    /// manifest shadows peers on read). Returns true when published.
    pub async fn publish_head(&self, shard_id: u32, height: u64, hash: [u8; 32]) -> bool {
        let last = self
            .last_published_head
            .lock()
            .map(|m| m.get(&shard_id).copied().unwrap_or(0))
            .unwrap_or(0);
        if !head_publish_allowed(height, last) {
            tracing::debug!(
                "head publish refused: shard={shard_id} height={height} last_published={last} \
                 (genesis-only or stale; refusing to rewind the shared head key)"
            );
            return false;
        }
        if let Ok(mut m) = self.last_published_head.lock() {
            m.insert(shard_id, height);
        }
        let payload = format!("{height}:{}", hex::encode(hash));
        // The head pointer stays FOREVER: it is one entry per shard (overwritten
        // every finalize and every ~30s probe), and a lagging node needs a live
        // head to discover the tip at all. Overwrite via `store_pointer_overwrite`
        // so the retired chunk set is deleted instead of orphaned (chunk ids are
        // content-addressed: every rewrite would otherwise leak one file set).
        self.store_pointer_overwrite(
            BUCKET_STELLEREUM_HEAD,
            &head_name(&self.epoch(), shard_id),
            payload.as_bytes(),
            dht_forever_ttl_ms(),
        )
        .await;
        true
    }

    /// Publish a finalized block's HEADER so a cold node can chain from a snapshot.
    ///
    /// A header is small (no transactions) and is published every block, unlike the
    /// bounded body window, which is what lets recovery work for a gap of any size:
    /// the walk needs headers all the way, and bodies only above the snapshot.
    pub async fn persist_block_header(&self, shard_id: u32, block: &Block) {
        let rec = crate::storage::BlockHeaderRecord::of(block);
        if let Ok(bytes) = bincode::serialize(&rec) {
            let ttl = dht_blob_ttl_ms(retention_keep_blocks());
            let block_hash = block.compute_hash();
            // One logical publish: only the header body charges the pacing gate;
            // the index + QC sidecar ride along (same bounded store, no extra
            // interval charge) so a 3-blob header never pays 3x the floor.
            //
            // LANE (see [`header_publish_slots`]): all three blobs ride the
            // header's Pointer lane, so the per-lane circuit breaker treats
            // them as ONE unit. They used to split: the header went to the
            // Pointer lane while the sidecars went to the Bulk lane, so a
            // bulk-lane cooldown shed the QC sidecar while the header still
            // landed — and a catch-up node reads "header present, QC missing"
            // as "not anchorable" and rejects the header as unanchored. A
            // split pair is worse than a missing pair: a missing pair is
            // skipped consistently, a split pair looks like an unanchored
            // header.
            let slots = header_publish_slots();
            paced_store_blob_in_lane(
                &self.node,
                BUCKET_STELLEREUM_HEADERS,
                &header_name(&self.epoch(), block.height),
                &bytes,
                ttl,
                slots[0].charge,
                slots[0].lane,
            )
            .await;
            // Additive v2 header record carrying full v4 BlockHeader fields.
            let rec_v2 = crate::storage::BlockHeaderRecordV2::of(block);
            if let Ok(v2_bytes) = bincode::serialize(&rec_v2) {
                paced_store_blob_in_lane(
                    &self.node,
                    BUCKET_STELLEREUM_HEADERS,
                    &header_v2_name(&self.epoch(), shard_id, block.height),
                    &v2_bytes,
                    ttl,
                    ReplStoreKind::Companion,
                    slots[0].lane,
                )
                .await;
            }
            // And the height -> hash pointer, so a caller can ask for "the header at
            // height N" without already knowing the hash.
            let idx = format!("{}:{}", block.height, hex::encode(block_hash));
            paced_store_blob_in_lane(
                &self.node,
                BUCKET_STELLEREUM_HEADERS,
                &header_index_name(&self.epoch(), shard_id, block.height),
                idx.as_bytes(),
                ttl,
                slots[1].charge,
                slots[1].lane,
            )
            .await;
            // A1 anchor: QC sidecar beside the header (same bucket, same
            // TTL, SAME LANE). Blocks without a QC (e.g. genesis) publish no
            // sidecar; readers treat a missing sidecar as "not anchorable",
            // never as trusted. Header first, then QC: a crash between writes
            // yields "missing QC → skip", never a half-trusted header.
            if let Some(qc) = block.precommit_qc.as_ref() {
                if claim_hq_publish(
                    &self.recent_hq_published,
                    shard_id,
                    block.height,
                    block_hash,
                ) {
                    if let Ok(qc_bytes) = bincode::serialize(qc) {
                        paced_store_blob_in_lane(
                            &self.node,
                            BUCKET_STELLEREUM_HEADERS,
                            &header_qc_name(&self.epoch(), shard_id, block.height),
                            &qc_bytes,
                            ttl,
                            slots[2].charge,
                            slots[2].lane,
                        )
                        .await;
                    }
                }
            }
        }
        // Retention rides the per-height publish traffic: this runs on
        // `publish_lane` (never the consensus tick), throttled to the snapshot
        // cadence and capped per pass inside `maybe_prune_retained`.
        self.maybe_prune_retained(shard_id, block.height).await;
    }

    /// Persist in-memory state snapshot to P2P network
    ///
    /// FAIL-CLOSED POINTER (fix 2026-10-15, live incident): the state blob and
    /// the latest-snapshot pointer used to publish independently — a shed or
    /// dropped Bulk store (backpressure SHED/DROP, 5s-timeout exhaustion on a
    /// tens-of-MB blob) left NO manifest anywhere while the Pointer-lane
    /// pointer write still succeeded, so the pointer advertised heights whose
    /// manifests every fetcher then missed ("boundary likely unpublished").
    /// The pointer now advances ONLY when the state blob demonstrably landed
    /// (`paced_store_blob` > 0, i.e. local chunks or at least one replica);
    /// otherwise the pointer stays at the last GOOD height and the failure is
    /// LOUD on both channels. Returns true when the snapshot (and pointer)
    /// published.
    pub async fn persist_state_snapshot(
        &self,
        shard_id: u32,
        height: u64,
        snapshot_data: &[u8],
    ) -> bool {
        let name = snapshot_name(&self.epoch(), shard_id, height);
        // Snapshots stay FOREVER (one per 100 heights): `try_snapshot_sync`
        // probes recent 100-height boundaries downward, and the snapshot at the
        // boundary plus the header above it is what lets a node thousands of
        // blocks behind skip execution. Pruning them would strand far-behind
        // nodes with no in-band recovery.
        // Paced as Bulk: a tens-of-MB snapshot fans out to a per-chunk
        // `replicate_blob` burst, the exact hammer shape of 2026-10-14.
        {
            let line = format!(
                "[snapshot-publish] state snapshot shard={shard_id} height={height} \
                 publishing {} bytes as {name}",
                snapshot_data.len()
            );
            eprintln!("{line}");
            tracing::info!("{line}");
        }
        let stored = paced_store_blob(
            &self.node,
            BUCKET_STELLEREUM_STATE,
            &name,
            snapshot_data,
            dht_forever_ttl_ms(),
            ReplStoreKind::Bulk,
        )
        .await;
        if stored == 0 {
            // The Bulk store shed/dropped (LOUD line already emitted by
            // `paced_store_blob`): there is no manifest anywhere, so the
            // pointer MUST NOT move — otherwise every catcher probes a
            // boundary that can never resolve.
            let line = format!(
                "[snapshot-publish] state snapshot shard={shard_id} height={height} \
                 FAILED to land (store reached nobody; see [repl-backpressure] line above); \
                 pointer NOT advancing (fail-closed)"
            );
            eprintln!("{line}");
            tracing::error!("{line}");
            return false;
        }
        {
            let line = format!(
                "[snapshot-publish] state snapshot shard={shard_id} height={height} \
                 manifest landed (store count {stored}); advancing latest pointer"
            );
            eprintln!("{line}");
            tracing::info!("{line}");
        }
        // Latest-snapshot pointer (same FOREVER TTL): snapshots complete on
        // worker timing, so their heights are arbitrary (78519, 78620, ...),
        // not round hundreds. A catcher reading this pointer fetches the exact
        // boundary first instead of missing 128 round-hundred probes.
        let ptr_name = snapshot_latest_name(&self.epoch(), shard_id);
        // Fixed-name pointer, rewritten on every snapshot (same orphan rule as
        // the head pointer: without the delete-first overwrite each rewrite
        // would leak its content-addressed chunk set).
        self.store_pointer_overwrite(
            BUCKET_STELLEREUM_STATE,
            &ptr_name,
            &height.to_le_bytes(),
            dht_forever_ttl_ms(),
        )
        .await;
        {
            let line = format!(
                "[snapshot-publish] latest-snapshot pointer shard={shard_id} advanced to {height}"
            );
            eprintln!("{line}");
            tracing::info!("{line}");
        }
        true
    }

    /// Publish one committed-domain blob beside the state snapshot (audit
    /// follow-up F-J): snapshot-sync restored ACCOUNTS ONLY, so a far-behind
    /// node on a live chain could never fast-sync (root check failed on any
    /// staking/token/bridge activity). `kind` is one of: domains, session,
    /// bridge, zkml, cross_shard. Same FOREVER retention as the
    /// state blob (one set per 100 heights).
    ///
    /// Fail-closed (fix 2026-10-15): a shed/dropped Bulk store is LOUD (not
    /// silent) and reported to the caller. Returns true when the blob landed.
    pub async fn persist_domain_snapshot(
        &self,
        shard_id: u32,
        height: u64,
        kind: &str,
        data: &[u8],
    ) -> bool {
        let name = format!(
            "{}_dom_{kind}",
            snapshot_name(&self.epoch(), shard_id, height)
        );
        // Paced as Bulk like the state blob it rides beside (same fan-out shape).
        let stored = paced_store_blob(
            &self.node,
            BUCKET_STELLEREUM_STATE,
            &name,
            data,
            dht_forever_ttl_ms(),
            ReplStoreKind::Bulk,
        )
        .await;
        if stored == 0 {
            let line = format!(
                "[snapshot-publish] domain snapshot shard={shard_id} height={height} kind={kind} \
                 FAILED to land (store reached nobody; see [repl-backpressure] line above)"
            );
            eprintln!("{line}");
            tracing::error!("{line}");
            return false;
        }
        {
            let line = format!(
                "[snapshot-publish] domain snapshot shard={shard_id} height={height} kind={kind} \
                 published {} bytes (store count {stored})",
                data.len()
            );
            eprintln!("{line}");
            tracing::info!("{line}");
        }
        true
    }

    // ==================== W1 SnapV4 Content-Addressed DHT Transport ====================

    /// Publish a `SnapV4` `SnapshotManifestV1` under its content-addressed
    /// `snapv4_manifest_name(epoch, shard_id, target_height, target_state_root)`.
    pub async fn persist_snapv4_manifest(
        &self,
        shard_id: u32,
        manifest: &crate::snapshot_v4::SnapshotManifestV1,
    ) -> Result<usize, String> {
        if manifest.shard_id != shard_id {
            return Err(format!(
                "persist_snapv4_manifest: shard mismatch ({} != {shard_id})",
                manifest.shard_id
            ));
        }
        let bytes = crate::snapshot_v4::encode_manifest_strict(manifest)
            .map_err(|e| format!("encode snapv4 manifest: {e}"))?;
        let name = snapv4_manifest_name(
            &self.epoch(),
            shard_id,
            manifest.target_height,
            &manifest.target_state_root,
        );
        let stored = paced_store_blob(
            &self.node,
            BUCKET_STELLEREUM_STATE,
            &name,
            &bytes,
            dht_forever_ttl_ms(),
            ReplStoreKind::Bulk,
        )
        .await;
        if stored == 0 {
            return Err(format!(
                "snapv4 manifest {name} reached no local chunk and no replica"
            ));
        }
        Ok(stored)
    }

    /// Publish a single `SnapV4` unit/chunk under its BLAKE3 content-addressed
    /// `snapv4_unit_name(epoch, shard_id, chunk_hash)`.
    pub async fn persist_snapv4_unit(
        &self,
        shard_id: u32,
        chunk_hash: &[u8; 32],
        bytes: &[u8],
    ) -> Result<usize, String> {
        if bytes.len() > crate::snapshot_v4::MAX_SNAP_CHUNK_BYTES {
            return Err(format!(
                "persist_snapv4_unit: chunk len {} exceeds MAX_SNAP_CHUNK_BYTES ({})",
                bytes.len(),
                crate::snapshot_v4::MAX_SNAP_CHUNK_BYTES
            ));
        }
        if !verify_bytes_blake3_hash(bytes, chunk_hash) {
            return Err("persist_snapv4_unit: blake3(bytes) != chunk_hash".to_string());
        }
        let name = snapv4_unit_name(&self.epoch(), shard_id, chunk_hash);
        let stored = paced_store_blob(
            &self.node,
            BUCKET_STELLEREUM_STATE,
            &name,
            bytes,
            dht_forever_ttl_ms(),
            ReplStoreKind::Bulk,
        )
        .await;
        if stored == 0 {
            return Err(format!(
                "snapv4 unit {name} reached no local chunk and no replica"
            ));
        }
        Ok(stored)
    }

    /// Broadcast transaction into mempool over infnode DHT KV
    pub async fn broadcast_transaction(&self, tx: &Transaction) -> Result<[u8; 32], String> {
        if !tx.verify_signature() {
            return Err("Invalid transaction signature".to_string());
        }
        let tx_hash = tx.compute_tx_hash();
        let hash_hex = hex::encode(tx_hash);
        let tx_bytes =
            bincode::serialize(tx).map_err(|e| format!("Tx serialize error: {:?}", e))?;

        let tx_key = format!("{}{}", PREFIX_MEMPOOL_TX, hash_hex);
        self.node
            .kv_store_local(&tx_key, &hex::encode(&tx_bytes))
            .await;

        // Append to shard mempool index
        let shard_key = format!("{}{}", PREFIX_SHARD_MEMPOOL, tx.source_shard);
        let current_index = self.node.get_local_kv(&shard_key).await.unwrap_or_default();
        let mut hashes: Vec<String> = serde_json::from_str(&current_index).unwrap_or_default();
        if !hashes.contains(&hash_hex) {
            hashes.push(hash_hex);
            let serialized = serde_json::to_string(&hashes).unwrap_or_default();
            self.node.kv_store_local(&shard_key, &serialized).await;
        }

        Ok(tx_hash)
    }

    /// Broadcast a SEALED transaction into the mempool over infnode DHT KV.
    ///
    /// Only the CIPHERTEXT is written to the DHT: the plaintext of a sealed
    /// transaction never touches the network store.
    pub async fn broadcast_sealed_transaction(
        &self,
        envelope: &crate::mev_epoch::SealedEnvelope,
    ) -> Result<[u8; 32], String> {
        envelope
            .validate()
            .map_err(|e| format!("refusing to broadcast a malformed sealed transaction: {e}"))?;
        let tx_hash = envelope.tx_hash;
        let hash_hex = hex::encode(tx_hash);
        let tx_bytes = crate::mev_epoch::encode_sealed_payload(envelope)?;

        let tx_key = format!("{}{}", PREFIX_MEMPOOL_TX, hash_hex);
        self.node
            .kv_store_local(&tx_key, &hex::encode(&tx_bytes))
            .await;

        // Append to shard mempool index
        let shard_key = format!("{}{}", PREFIX_SHARD_MEMPOOL, envelope.meta.source_shard);
        let current_index = self.node.get_local_kv(&shard_key).await.unwrap_or_default();
        let mut hashes: Vec<String> = serde_json::from_str(&current_index).unwrap_or_default();
        if !hashes.contains(&hash_hex) {
            hashes.push(hash_hex);
            let serialized = serde_json::to_string(&hashes).unwrap_or_default();
            self.node.kv_store_local(&shard_key, &serialized).await;
        }

        Ok(tx_hash)
    }

    /// Clear confirmed transactions from mempool
    pub async fn clear_mempool_transactions(&self, shard_id: u32, confirmed_hashes: &[[u8; 32]]) {
        let shard_key = format!("{}{}", PREFIX_SHARD_MEMPOOL, shard_id);
        let Some(index_str) = self.node.get_local_kv(&shard_key).await else {
            return;
        };

        let mut hashes: Vec<String> = serde_json::from_str(&index_str).unwrap_or_default();
        let confirmed_hexes: Vec<String> = confirmed_hashes.iter().map(hex::encode).collect();

        hashes.retain(|h| !confirmed_hexes.contains(h));

        for h in &confirmed_hexes {
            let tx_key = format!("{}{}", PREFIX_MEMPOOL_TX, h);
            self.node.kv_remove_local(&tx_key).await;
        }

        let serialized = serde_json::to_string(&hashes).unwrap_or_default();
        self.node.kv_store_local(&shard_key, &serialized).await;
    }

    /// Publish oracle price update to P2P network
    pub async fn broadcast_price_feed(&self, update: &PriceFeedUpdate) -> Result<(), String> {
        if !update.verify() {
            return Err("Invalid oracle signature".to_string());
        }
        let update_bytes = bincode::serialize(update)
            .map_err(|e| format!("PriceFeedUpdate serialize error: {:?}", e))?;
        let key = format!("{}{}", PREFIX_ORACLE, update.asset);
        self.node
            .kv_store_local(&key, &hex::encode(&update_bytes))
            .await;
        Ok(())
    }

    /// Broadcast MEV blind round commitment
    pub async fn broadcast_blind_round(&self, commit: &BlindRoundCommitment) -> Result<(), String> {
        let commit_bytes = bincode::serialize(commit)
            .map_err(|e| format!("BlindRoundCommitment serialize error: {:?}", e))?;
        let key = format!("{}{}", PREFIX_MEV_COMMIT, commit.round_number);
        self.node
            .kv_store_local(&key, &hex::encode(&commit_bytes))
            .await;
        Ok(())
    }
}

/// One network write performed by a block publish: a blob into `bucket` named
/// `name`, plus any local DHT KV entries committed alongside it.
///
/// A publish is PLANNED as data and then applied, so the complete set of network
/// effects is inspectable without a live DHT. That matters most for the
/// retro-publish path, whose safety property is "this writes no KV at all" — a
/// property that is only checkable if the effects are values rather than a
/// sequence of `await`s buried in a method body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishWrite {
    pub bucket: &'static str,
    pub name: String,
    pub bytes: Vec<u8>,
    /// Local DHT KV entries committed together with the blob. A BODY publish
    /// carries none of these; see `plan_block_body_publish`.
    pub kv: Vec<(String, String)>,
}

/// Plan the network writes that publish `block`'s BODY, and nothing else.
///
/// Deliberately carries no `PREFIX_LATEST_HEIGHT` and no `PREFIX_BLOCK_HASH`
/// write, because those two are head ANNOUNCEMENTS rather than body storage.
/// Replaying them from a re-publish is actively harmful: a node 1000 blocks
/// behind that re-published its own history would overwrite the advertised head
/// with `height:hash` from the middle of its own chain, so every peer would watch
/// the network's head rewind by a thousand blocks and the lagging node would
/// stop being able to find the very tip it is trying to catch. The body is what
/// the peer is missing; the pointer is not.
pub fn plan_block_body_publish(
    epoch: &EpochTag,
    block: &Block,
) -> Result<Vec<PublishWrite>, String> {
    let block_hash = block.compute_hash();
    let bytes = bincode::serialize(block).map_err(|e| format!("block serialize failed: {e:?}"))?;
    Ok(vec![body_write(epoch, block_hash, bytes)])
}

/// The same single body write, from stored bytes addressed by a hash the caller
/// already has.
///
/// The body is decoded and re-hashed, and a mismatch is refused rather than
/// published: the DHT name IS the hash, so a body filed under a hash it does
/// not compute to is a permanently poisoned slot — `fetch_block` would return
/// it to a peer as the block that peer requested. Cheap relative to the write,
/// and it makes the "publish by hash" entry point safe to drive from a disk
/// scan without trusting the scan.
pub fn plan_block_body_publish_bytes(
    epoch: &EpochTag,
    block_hash: [u8; 32],
    body: &[u8],
) -> Result<PublishWrite, String> {
    let block: Block = decode_wire_limited(body, MAX_WIRE_BLOCK_BYTES)
        .map_err(|e| format!("block body deserialize failed: {e:?}"))?;
    let computed = block.compute_hash();
    if computed != block_hash {
        return Err(format!(
            "block body hashes to {} but was addressed as {}",
            hex::encode(computed),
            hex::encode(block_hash)
        ));
    }
    Ok(body_write(epoch, block_hash, body.to_vec()))
}

/// Plan the immutable header, v2 header, and height-to-hash index writes for `block`
/// (`_h_`, `_h2_`, `_hi_`) that ride alongside retro-published blocks.
///
/// Safe to republish from any node: keyed by `(epoch, shard_id, height)` with zero
/// `kv` writes and zero effect on `shard_{shard}_head` or `PREFIX_LATEST_HEIGHT`.
pub fn plan_block_header_writes(epoch: &EpochTag, block: &Block) -> Vec<PublishWrite> {
    let mut writes = Vec::with_capacity(3);
    let block_hash = block.compute_hash();
    let rec = crate::storage::BlockHeaderRecord::of(block);
    if let Ok(bytes) = bincode::serialize(&rec) {
        writes.push(PublishWrite {
            bucket: BUCKET_STELLEREUM_HEADERS,
            name: header_name(epoch, block.height),
            bytes,
            kv: Vec::new(),
        });
    }
    let rec_v2 = crate::storage::BlockHeaderRecordV2::of(block);
    if let Ok(v2_bytes) = bincode::serialize(&rec_v2) {
        writes.push(PublishWrite {
            bucket: BUCKET_STELLEREUM_HEADERS,
            name: header_v2_name(epoch, block.shard_id, block.height),
            bytes: v2_bytes,
            kv: Vec::new(),
        });
    }
    let idx = format!("{}:{}", block.height, hex::encode(block_hash));
    writes.push(PublishWrite {
        bucket: BUCKET_STELLEREUM_HEADERS,
        name: header_index_name(epoch, block.shard_id, block.height),
        bytes: idx.into_bytes(),
        kv: Vec::new(),
    });
    writes
}

/// Plan the optional height-addressed precommit-QC sidecar write (`_hq_{shard}_{height}`)
/// that rides alongside retro-published block bodies.
///
/// Safe to republish from any node: keyed strictly by `(epoch, shard_id, height)`
/// and carries a cryptographic [`crate::consensus::QuorumCertificate`], with zero
/// `kv` writes and zero effect on `shard_{shard}_head`.
pub fn plan_block_qc_publish(epoch: &EpochTag, block: &Block) -> Option<PublishWrite> {
    let qc = block.precommit_qc.as_ref()?;
    let bytes = bincode::serialize(qc).ok()?;
    Some(PublishWrite {
        bucket: BUCKET_STELLEREUM_HEADERS,
        name: header_qc_name(epoch, block.shard_id, block.height),
        bytes,
        kv: Vec::new(),
    })
}

const RECENT_HQ_CACHE_CAP: usize = 512;
const RECENT_HQ_TTL_SECS: u64 = 30;

fn claim_hq_publish(
    cache: &RecentHqPublishCache,
    shard_id: u32,
    height: u64,
    block_hash: [u8; 32],
) -> bool {
    let now = std::time::Instant::now();
    let ttl = std::time::Duration::from_secs(RECENT_HQ_TTL_SECS);
    let Ok(mut guard) = cache.lock() else {
        return true;
    };
    if let Some((prev_hash, prev_at)) = guard.get(&(shard_id, height)) {
        if *prev_hash == block_hash && now.saturating_duration_since(*prev_at) < ttl {
            return false;
        }
    }
    if guard.len() >= RECENT_HQ_CACHE_CAP {
        guard.retain(|_, (_, at)| now.saturating_duration_since(*at) < ttl);
        if guard.len() >= RECENT_HQ_CACHE_CAP {
            if let Some(oldest_key) = guard.iter().min_by_key(|(_, (_, at))| *at).map(|(k, _)| *k) {
                guard.remove(&oldest_key);
            }
        }
    }
    guard.insert((shard_id, height), (block_hash, now));
    true
}

async fn publish_block_header_companion(node: &Arc<Node>, epoch: &EpochTag, block: &Block) -> bool {
    let ttl = dht_blob_ttl_ms(retention_keep_blocks());
    let slots = header_publish_slots();
    let writes = plan_block_header_writes(epoch, block);
    if writes.len() < 3 {
        return false;
    }
    let mut all_stored = true;
    for (idx, w) in writes.into_iter().enumerate() {
        let (charge, lane) = match idx {
            0 => (slots[0].charge, slots[0].lane),
            1 => (ReplStoreKind::Companion, slots[0].lane),
            _ => (slots[1].charge, slots[1].lane),
        };
        let stored =
            paced_store_blob_in_lane(node, w.bucket, &w.name, &w.bytes, ttl, charge, lane).await;
        if stored == 0 {
            all_stored = false;
        }
    }
    all_stored
}

async fn publish_block_qc_companion(node: &Arc<Node>, epoch: &EpochTag, block: &Block) {
    if let Some(w) = plan_block_qc_publish(epoch, block) {
        let ttl = dht_blob_ttl_ms(retention_keep_blocks());
        let qc_slot = header_publish_slots()[2];
        paced_store_blob_in_lane(
            node,
            w.bucket,
            &w.name,
            &w.bytes,
            ttl,
            qc_slot.charge,
            qc_slot.lane,
        )
        .await;
    }
}

/// The one write a body publish is: a blob in the block bucket, named by hash,
/// with no local KV riding along.
fn body_write(epoch: &EpochTag, block_hash: [u8; 32], bytes: Vec<u8>) -> PublishWrite {
    PublishWrite {
        bucket: BUCKET_STELLEREUM_BLOCKS,
        name: block_body_blob_name(epoch, &block_hash),
        bytes,
        kv: Vec::new(),
    }
}

/// Apply a publish plan against the DHT.
///
/// A `store_blob` that landed on neither local storage nor a replica is reported
/// as a failure rather than ignored the way `broadcast_block` ignores it: it
/// means the body exists on nobody's disk, which is the exact condition this
/// whole path exists to repair, so it must never be counted as a success.
async fn apply_publish_plan(node: &Arc<Node>, writes: &[PublishWrite]) -> Result<(), String> {
    // Retro-published bodies are the same bodies `broadcast_block` publishes,
    // so they carry the same retention-window TTL (see `dht_blob_ttl_ms`).
    let ttl = dht_blob_ttl_ms(retention_keep_blocks());
    for w in writes {
        // Bounded publish (backpressure 2026-10-14): retries + circuit breaking
        // live inside `paced_store_blob`. A body that reaches nobody after the
        // full budget is still an Err here (the repair condition), counted by
        // the caller — never retried unboundedly.
        let stored =
            paced_store_blob(node, w.bucket, &w.name, &w.bytes, ttl, ReplStoreKind::Bulk).await;
        if stored == 0 {
            return Err(format!(
                "block body {}/{} reached no local chunk and no replica",
                w.bucket, w.name
            ));
        }
        for (k, v) in &w.kv {
            node.kv_store_local(k, v).await;
        }
    }
    Ok(())
}

/// What one bounded retro-publish pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RetroPublishReport {
    /// Bodies taken from the caller's iterator during this pass.
    pub attempted: usize,
    /// Bodies that reached the DHT.
    pub published: usize,
    /// Bodies that did not. Counted and reported, never silently swallowed, and
    /// never fatal to the rest of the pass.
    pub failed: usize,
    /// The pass stopped because it hit `max`, so the iterator MAY still hold
    /// bodies and the caller should run another pass. An over-approximation on
    /// purpose: a window that exactly filled with nothing left over still
    /// reports `true`, and the extra pass publishes 0 and returns immediately.
    pub maybe_more: bool,
    /// The first failure's reason, so a log line can say WHY and not only how
    /// many. Later failures are counted but not retained, so a fully broken
    /// pass cannot grow without bound either.
    pub first_error: Option<String>,
}

/// Take at most `max` items from `iter` and `publish` each one, tolerantly.
///
/// The transport is the caller's closure, so this bounded-chunking and
/// failure-accounting logic is the same code both the live batch method and a
/// unit test drive — the bound cannot drift between them. One failing item is
/// recorded and the walk continues: aborting would forfeit the N-1 bodies that
/// are precisely the ones a lagging peer needs.
pub async fn retro_publish_chunk<I, T, F, Fut>(
    iter: &mut I,
    max: usize,
    mut publish: F,
) -> RetroPublishReport
where
    I: Iterator<Item = T>,
    F: FnMut(T) -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    let mut report = RetroPublishReport::default();
    let mut taken = 0usize;
    while taken < max {
        let Some(item) = iter.next() else { break };
        taken += 1;
        report.attempted += 1;
        match publish(item).await {
            Ok(()) => report.published += 1,
            Err(e) => {
                report.failed += 1;
                if report.first_error.is_none() {
                    report.first_error = Some(e);
                }
            }
        }
        if taken < max {
            // Jittered pacing: the base 5ms spread plus a 0..=5ms draw so
            // publishers that woke on the same cadence do not re-synchronize
            // their `replicate_blob` bursts onto the same newcomer. Floor is
            // always the base pace — pushes never fire faster than before.
            tokio::time::sleep(std::time::Duration::from_millis(
                crate::sync::retro_publish_pace_with_jitter_ms(rand::random::<u64>()),
            ))
            .await;
        }
    }
    // `max == 0` is a no-op pass and NOT "there may be more", so a caller that
    // loops on `maybe_more` can never spin.
    report.maybe_more = max > 0 && taken == max;
    report
}
