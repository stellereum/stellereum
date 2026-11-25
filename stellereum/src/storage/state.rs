use super::Storage;
use crate::sharding::FinalizedHeaderRegistry;
use crate::state_engine::InMemoryStateEngine;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Atomic commit marker for W1 `SnapV4` checkpoints in `"snap_committed"`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapCommitMarker {
    pub height: u64,
    pub state_root: [u8; 32],
    pub block_hash: [u8; 32],
    pub is_base: bool,
    pub base_height: Option<u64>,
}

impl Storage {
    // ---------- Consensus checkpoint (safety across restarts) ----------

    /// Persist the consensus safety state (height, round, lock, finality).
    pub fn set_consensus(&self, cp: &ConsensusCheckpoint) -> Result<()> {
        let bytes = bincode::serialize(cp)?;
        self.set_meta("consensus", &bytes)
    }

    pub fn consensus(&self) -> Result<Option<ConsensusCheckpoint>> {
        match self.get_meta("consensus")? {
            Some(b) => Ok(Some(bincode::deserialize(&b)?)),
            None => Ok(None),
        }
    }

    /// Persist the write-ahead vote watermark (one sled ACID insert).
    ///
    /// Callers MUST call this BEFORE broadcasting the vote. It is a separate
    /// meta key from the consensus checkpoint on purpose: finalization rewrites
    /// the checkpoint, and the watermark must survive that.
    pub fn set_vote_watermark(&self, wm: &VoteWatermark) -> Result<()> {
        let bytes = bincode::serialize(wm)?;
        self.set_meta("vote_watermark", &bytes)
    }

    /// Write-ahead vote watermark: insert + durability barrier.
    ///
    /// The barrier is what makes the record survive a power loss, not just a
    /// process crash, so the node can never re-vote a round it already used.
    /// A vote is cast at most once per round and kind, so the fsync cost is
    /// bounded by the round cadence (seconds), not by transaction throughput.
    pub fn persist_vote_watermark(&self, wm: &VoteWatermark) -> Result<()> {
        self.set_vote_watermark(wm)?;
        self.flush()
    }

    pub fn vote_watermark(&self) -> Result<Option<VoteWatermark>> {
        match self.get_meta("vote_watermark")? {
            Some(b) => Ok(Some(bincode::deserialize(&b)?)),
            None => Ok(None),
        }
    }

    // ---------- State snapshots ----------

    pub fn put_state(&self, height: u64, snapshot: &[u8]) -> Result<()> {
        self.state.insert(height.to_be_bytes(), snapshot)?;
        Ok(())
    }

    pub fn get_state(&self, height: u64) -> Result<Option<Vec<u8>>> {
        Ok(self.state.get(height.to_be_bytes())?.map(|v| v.to_vec()))
    }

    /// The most recent state snapshot (highest height) and its height.
    pub fn latest_state(&self) -> Result<Option<(u64, Vec<u8>)>> {
        match self.state.last()? {
            Some((k, v)) if k.len() == 8 => {
                let mut h = [0u8; 8];
                h.copy_from_slice(&k);
                Ok(Some((u64::from_be_bytes(h), v.to_vec())))
            }
            _ => Ok(None),
        }
    }

    /// Height of the most recent state snapshot, WITHOUT copying the blob.
    ///
    /// Boot-time predicates (the upgrade-halt guard) only need "how far has
    /// applied state advanced". [`Self::latest_state`] clones the whole
    /// snapshot value (`v.to_vec()`), which can be tens of megabytes, just to
    /// read the 8-byte key. This reads the same key ordering but drops the
    /// value IVec immediately, so the whole blob is never materialised.
    pub fn latest_state_height(&self) -> Result<Option<u64>> {
        // `keys()` (unlike `last()`) never hands the stored value to this
        // caller at all, so boot cost is one key read regardless of snapshot
        // size.
        match self.state.iter().keys().next_back() {
            Some(Ok(k)) if k.len() == 8 => {
                let mut h = [0u8; 8];
                h.copy_from_slice(&k);
                Ok(Some(u64::from_be_bytes(h)))
            }
            Some(Ok(_)) => Ok(None),
            Some(Err(e)) => Err(e.into()),
            None => Ok(None),
        }
    }

    pub fn put_domains(&self, height: u64, bytes: &[u8]) -> Result<()> {
        self.domains.insert(height.to_be_bytes(), bytes)?;
        Ok(())
    }

    /// The domain snapshot exactly as it stood after `height`, when one was stored.
    ///
    /// Strictly paired read: callers holding a paired height (see
    /// `latest_paired_snapshot`) must use this instead of `latest_domains`,
    /// so state@H is never combined with domains@D!=H from an unpaired tail
    /// left by a crash between the two snapshot jobs.
    pub fn domain_at(&self, height: u64) -> Result<Option<Vec<u8>>> {
        Ok(self.domains.get(height.to_be_bytes())?.map(|v| v.to_vec()))
    }

    /// Newest height holding BOTH a state and a domains snapshot.
    ///
    /// State and domain snapshots are enqueued as separate jobs, so a crash can leave
    /// an unpaired tail (state@H with no domains@H, or vice versa). Loading such a
    /// pair builds engine state no anchor can validate. Callers must use this, never
    /// `latest_state` alone, when they need a restorable snapshot.
    pub fn latest_paired_snapshot(&self) -> Result<Option<(u64, Vec<u8>)>> {
        let state_heights: std::collections::BTreeSet<u64> = self
            .state
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| k.len() == 8)
            .map(|k| u64::from_be_bytes(k.as_ref().try_into().unwrap()))
            .collect();
        let domain_heights: std::collections::BTreeSet<u64> = self
            .domains
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| k.len() == 8)
            .map(|k| u64::from_be_bytes(k.as_ref().try_into().unwrap()))
            .collect();
        let mut candidates: Vec<u64> = state_heights
            .intersection(&domain_heights)
            .copied()
            .collect();
        if !self.pq_registry.is_empty() {
            let pq_heights: std::collections::BTreeSet<u64> = self
                .pq_registry
                .iter()
                .keys()
                .filter_map(|k| k.ok())
                .filter(|k| k.len() == 8)
                .map(|k| u64::from_be_bytes(k.as_ref().try_into().unwrap()))
                .collect();
            let with_pq: Vec<u64> = candidates
                .iter()
                .copied()
                .filter(|h| pq_heights.contains(h))
                .collect();
            if !with_pq.is_empty() {
                candidates = with_pq;
            }
        }
        let Some(height) = candidates.into_iter().max() else {
            return Ok(None);
        };
        let Some(bytes) = self.state.get(height.to_be_bytes())? else {
            return Ok(None);
        };
        Ok(Some((height, bytes.to_vec())))
    }

    pub fn latest_domains(&self) -> Result<Option<(u64, Vec<u8>)>> {
        match self.domains.last()? {
            Some((k, v)) if k.len() == 8 => {
                let mut h = [0u8; 8];
                h.copy_from_slice(&k);
                Ok(Some((u64::from_be_bytes(h), v.to_vec())))
            }
            _ => Ok(None),
        }
    }

    // ---------- Session-key registry snapshots (phase 2) ----------

    pub fn put_session_keys(&self, height: u64, bytes: &[u8]) -> Result<()> {
        self.session_keys.insert(height.to_be_bytes(), bytes)?;
        Ok(())
    }

    /// The registry exactly as it stood after `height`, when one was stored.
    ///
    /// `None` for a data directory written before phase 2 - which is
    /// CORRECT, not a gap: an empty registry contributes nothing to the
    /// commitment digest, so a pre-phase-2 snapshot restores to the same root
    /// it was written with (that is what makes the genesis KAT survive).
    pub fn session_keys_at(&self, height: u64) -> Result<Option<Vec<u8>>> {
        Ok(self
            .session_keys
            .get(height.to_be_bytes())?
            .map(|v| v.to_vec()))
    }

    pub fn latest_session_keys(&self) -> Result<Option<(u64, Vec<u8>)>> {
        match self.session_keys.last()? {
            Some((k, v)) if k.len() == 8 => {
                let mut h = [0u8; 8];
                h.copy_from_slice(&k);
                Ok(Some((u64::from_be_bytes(h), v.to_vec())))
            }
            _ => Ok(None),
        }
    }

    // ---------- Bridge domain snapshots (the §8 replay set / queue) ----------

    pub fn put_bridge(&self, height: u64, bytes: &[u8]) -> Result<()> {
        self.bridge.insert(height.to_be_bytes(), bytes)?;
        Ok(())
    }

    /// The committed bridge domain exactly as it stood after `height`, when
    /// one was stored.
    ///
    /// `None` for a directory written before the bridge landed - which is
    /// CORRECT, not a gap: an empty domain contributes nothing to the
    /// commitment digest, so a pre-bridge snapshot restores to the same root it
    /// was written with (that is what keeps the genesis KAT alive). `Some`
    /// means the replay set and the withdrawal queue come back with the node,
    /// so a restored node still refuses a `source_tx_hash` it already credited
    /// instead of minting it a second time.
    pub fn bridge_at(&self, height: u64) -> Result<Option<Vec<u8>>> {
        Ok(self.bridge.get(height.to_be_bytes())?.map(|v| v.to_vec()))
    }

    pub fn put_zkml_models(&self, height: u64, bytes: &[u8]) -> Result<()> {
        self.zkml_models.insert(height.to_be_bytes(), bytes)?;
        Ok(())
    }

    /// The committed zkML model registry exactly as it stood after `height`.
    /// `None` for older directories means "empty" (zero digest bytes), which
    /// restores to the written root.
    pub fn zkml_models_at(&self, height: u64) -> Result<Option<Vec<u8>>> {
        Ok(self
            .zkml_models
            .get(height.to_be_bytes())?
            .map(|v| v.to_vec()))
    }

    pub fn put_cross_shard(&self, height: u64, bytes: &[u8]) -> Result<()> {
        self.cross_shard.insert(height.to_be_bytes(), bytes)?;
        Ok(())
    }

    /// The cross-shard replay state exactly as it stood after `height`.
    /// `None` for older directories (or single-shard chains that never used
    /// it) means "empty sets", which is also what a fresh process holds.
    ///
    /// COMMITTED domain (audit F1): the three replay sets are folded into
    /// the state digest by `commitment::write_cross_shard_domain`
    /// (conditional on non-emptiness, so pre-cross-shard snapshots root
    /// identically to before). A stored snapshot whose blob is absent
    /// therefore restores to a DIFFERENT root than an anchor that committed
    /// replay state — the root check refuses it loudly instead of silently
    /// re-opening consumed inbounds (see [`load_full_state_into`], which
    /// installs the FULL snapshot: engine + runtime consumed halves,
    /// produced heights and completed lifecycles).
    pub fn cross_shard_at(&self, height: u64) -> Result<Option<Vec<u8>>> {
        Ok(self
            .cross_shard
            .get(height.to_be_bytes())?
            .map(|v| v.to_vec()))
    }

    pub fn put_cnvrf_v3(&self, height: u64, bytes: &[u8]) -> Result<()> {
        self.cnvrf_v3.insert(height.to_be_bytes(), bytes)?;
        Ok(())
    }

    /// The committed CN-VRF v3 subsystem state exactly as it stood after
    /// `height`, when one was stored. `None` (or empty bytes) for older
    /// directories means `CnVrfV3EngineSnapshot::default()` (empty), which
    /// contributes zero bytes to the commitment digest.
    pub fn cnvrf_v3_at(&self, height: u64) -> Result<Option<Vec<u8>>> {
        Ok(self.cnvrf_v3.get(height.to_be_bytes())?.map(|v| v.to_vec()))
    }

    // ---------- Canonical EVM bindings domain snapshots (`Domain::EvmBindings`) ----------

    pub fn put_evm_bindings_state(&self, height: u64, bytes: &[u8]) -> Result<()> {
        self.evm_bindings_state
            .insert(height.to_be_bytes(), bytes)?;
        Ok(())
    }

    /// The canonical `Domain::EvmBindings` snapshot at `height`, when stored.
    /// `None` (or empty bytes) on older directories means empty `EvmBindingsState`
    /// (contributes 0 bytes to the commitment digest).
    pub fn evm_bindings_state_at(&self, height: u64) -> Result<Option<Vec<u8>>> {
        Ok(self
            .evm_bindings_state
            .get(height.to_be_bytes())?
            .map(|v| v.to_vec()))
    }

    // ---------- Canonical PQ key registry domain snapshots (`Domain::PqRegistry`) ----------

    pub fn put_pq_registry(&self, height: u64, bytes: &[u8]) -> Result<()> {
        self.pq_registry.insert(height.to_be_bytes(), bytes)?;
        Ok(())
    }

    /// The canonical `Domain::PqRegistry` snapshot at `height`, when stored.
    /// `None` (or empty bytes) on older directories means empty `PqRegistry`
    /// (contributes 0 bytes to the commitment digest).
    pub fn pq_registry_at(&self, height: u64) -> Result<Option<Vec<u8>>> {
        Ok(self
            .pq_registry
            .get(height.to_be_bytes())?
            .map(|v| v.to_vec()))
    }

    // ---------- Non-consensus crash-safe EVM bindings index (`"evm_bindings"`) ----------
    //
    // Key layout:
    //   b"e:" || evm(20)  -> pq(32)
    //   b"p:" || pq(32)   -> evm(20)
    //   b"meta:cursor"    -> u64 BE
    //
    // NEVER pruned by `prune_blocks_below` / `prune_receipts_below`!

    const EVM_BINDING_CURSOR_KEY: &'static [u8] = b"meta:cursor";

    fn evm_binding_e_key(evm: &[u8; 20]) -> Vec<u8> {
        let mut k = Vec::with_capacity(22);
        k.extend_from_slice(b"e:");
        k.extend_from_slice(evm);
        k
    }

    fn evm_binding_p_key(pq: &[u8; 32]) -> Vec<u8> {
        let mut k = Vec::with_capacity(34);
        k.extend_from_slice(b"p:");
        k.extend_from_slice(pq);
        k
    }

    /// Atomically record `(evm, pq)` under strict first-writer-wins semantics:
    /// - If `(evm, pq)` is already identically mapped -> `Ok(false)` (idempotent).
    /// - If either `evm` or `pq` is already mapped to a different address -> `Err`
    ///   without overwriting.
    /// - Otherwise inserts both `b"e:"` and `b"p:"` in one sled transaction -> `Ok(true)`.
    pub fn put_evm_binding_if_absent(&self, evm: &[u8; 20], pq: &[u8; 32]) -> Result<bool> {
        let e_key = Self::evm_binding_e_key(evm);
        let p_key = Self::evm_binding_p_key(pq);
        let evm_val = *evm;
        let pq_val = *pq;
        let inserted = self
            .evm_bindings
            .transaction(
                |tree| -> sled::transaction::ConflictableTransactionResult<bool, String> {
                    let existing_e = tree.get(&e_key)?;
                    let existing_p = tree.get(&p_key)?;
                    match (existing_e, existing_p) {
                        (Some(epq), Some(eevm)) => {
                            if epq.as_ref() == &pq_val[..] && eevm.as_ref() == &evm_val[..] {
                                Ok(false)
                            } else {
                                Err(sled::transaction::ConflictableTransactionError::Abort(
                                    format!(
                                        "evm_bindings conflict for evm=0x{} / pq={}",
                                        hex::encode(evm_val),
                                        hex::encode(pq_val)
                                    ),
                                ))
                            }
                        }
                        (Some(_), None) | (None, Some(_)) => Err(
                            sled::transaction::ConflictableTransactionError::Abort(format!(
                                "evm_bindings first-writer-wins conflict for evm=0x{} / pq={}",
                                hex::encode(evm_val),
                                hex::encode(pq_val)
                            )),
                        ),
                        (None, None) => {
                            tree.insert(e_key.as_slice(), &pq_val[..])?;
                            tree.insert(p_key.as_slice(), &evm_val[..])?;
                            Ok(true)
                        }
                    }
                },
            )
            .map_err(|e| match e {
                sled::transaction::TransactionError::Abort(msg) => anyhow!(msg),
                sled::transaction::TransactionError::Storage(err) => {
                    anyhow!("evm_bindings sled error: {err}")
                }
            })?;
        Ok(inserted)
    }

    pub fn evm_binding_by_evm(&self, evm: &[u8; 20]) -> Result<Option<[u8; 32]>> {
        match self.evm_bindings.get(Self::evm_binding_e_key(evm))? {
            Some(v) => {
                if v.len() != 32 {
                    return Err(anyhow!(
                        "corrupt evm_bindings e: value length {} != 32",
                        v.len()
                    ));
                }
                let mut pq = [0u8; 32];
                pq.copy_from_slice(&v);
                Ok(Some(pq))
            }
            None => Ok(None),
        }
    }

    pub fn evm_binding_by_pq(&self, pq: &[u8; 32]) -> Result<Option<[u8; 20]>> {
        match self.evm_bindings.get(Self::evm_binding_p_key(pq))? {
            Some(v) => {
                if v.len() != 20 {
                    return Err(anyhow!(
                        "corrupt evm_bindings p: value length {} != 20",
                        v.len()
                    ));
                }
                let mut evm = [0u8; 20];
                evm.copy_from_slice(&v);
                Ok(Some(evm))
            }
            None => Ok(None),
        }
    }

    pub fn evm_bindings_cursor(&self) -> Result<Option<u64>> {
        match self.evm_bindings.get(Self::EVM_BINDING_CURSOR_KEY)? {
            Some(v) => {
                if v.len() != 8 {
                    return Err(anyhow!(
                        "corrupt evm_bindings meta:cursor length {} != 8",
                        v.len()
                    ));
                }
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&v);
                Ok(Some(u64::from_be_bytes(arr)))
            }
            None => Ok(None),
        }
    }

    pub fn set_evm_bindings_cursor(&self, height: u64) -> Result<()> {
        self.evm_bindings
            .insert(Self::EVM_BINDING_CURSOR_KEY, &height.to_be_bytes())?;
        Ok(())
    }

    pub fn iter_evm_bindings(&self) -> Result<Vec<([u8; 20], [u8; 32])>> {
        let mut out = Vec::new();
        for kv in self.evm_bindings.scan_prefix(b"e:") {
            let (k, v) = kv?;
            if k.len() != 22 || v.len() != 32 {
                return Err(anyhow!(
                    "corrupt evm_bindings entry: key_len={} val_len={}",
                    k.len(),
                    v.len()
                ));
            }
            let mut evm = [0u8; 20];
            evm.copy_from_slice(&k[2..22]);
            let mut pq = [0u8; 32];
            pq.copy_from_slice(&v);
            out.push((evm, pq));
        }
        Ok(out)
    }

    #[doc(hidden)]
    pub fn evm_bindings_tree_for_test(&self) -> sled::Tree {
        self.evm_bindings.clone()
    }

    // ---------- W1 SnapV4 persistent trees (never touch safety_record_v1/meta) ----------

    fn snap_staging_key(height: u64, unit_tag: u16, sub_index: u16) -> [u8; 12] {
        let mut k = [0u8; 12];
        k[0..8].copy_from_slice(&height.to_be_bytes());
        k[8..10].copy_from_slice(&unit_tag.to_be_bytes());
        k[10..12].copy_from_slice(&sub_index.to_be_bytes());
        k
    }

    pub fn put_snap_unit(&self, chunk_hash: &[u8; 32], bytes: &[u8]) -> Result<()> {
        self.snap_units.insert(&chunk_hash[..], bytes)?;
        Ok(())
    }

    pub fn snap_unit(&self, chunk_hash: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        Ok(self.snap_units.get(&chunk_hash[..])?.map(|v| v.to_vec()))
    }

    pub fn has_snap_unit(&self, chunk_hash: &[u8; 32]) -> Result<bool> {
        Ok(self.snap_units.contains_key(&chunk_hash[..])?)
    }

    pub fn put_snap_manifest(&self, height: u64, manifest_bytes: &[u8]) -> Result<()> {
        self.snap_manifests
            .insert(height.to_be_bytes(), manifest_bytes)?;
        Ok(())
    }

    pub fn snap_manifest(&self, height: u64) -> Result<Option<Vec<u8>>> {
        Ok(self
            .snap_manifests
            .get(height.to_be_bytes())?
            .map(|v| v.to_vec()))
    }

    pub fn put_snap_staging_chunk(
        &self,
        height: u64,
        unit_tag: u16,
        sub_index: u16,
        bytes: &[u8],
    ) -> Result<()> {
        let key = Self::snap_staging_key(height, unit_tag, sub_index);
        self.snap_staging.insert(key, bytes)?;
        Ok(())
    }

    pub fn snap_staging_chunk(
        &self,
        height: u64,
        unit_tag: u16,
        sub_index: u16,
    ) -> Result<Option<Vec<u8>>> {
        let key = Self::snap_staging_key(height, unit_tag, sub_index);
        Ok(self.snap_staging.get(key)?.map(|v| v.to_vec()))
    }

    pub fn clear_snap_staging(&self, height: u64) -> Result<usize> {
        let keys: Vec<sled::IVec> = self
            .snap_staging
            .scan_prefix(height.to_be_bytes())
            .keys()
            .filter_map(|k| k.ok())
            .collect();
        let n = keys.len();
        for k in keys {
            self.snap_staging.remove(k)?;
        }
        Ok(n)
    }

    pub fn sweep_all_snap_staging(&self) -> Result<usize> {
        let n = self.snap_staging.len();
        self.snap_staging.clear()?;
        Ok(n)
    }

    /// Atomically commit a verified `SnapV4` checkpoint (data-before-index):
    /// 1. Write all content-addressed units into `snap_units`.
    /// 2. Write the canonical manifest into `snap_manifests`.
    /// 3. Flush to disk (`db.flush()`).
    /// 4. Insert the commit marker into `snap_committed` + `finalized_post_root_v1`.
    /// 5. Clear `snap_staging` for `marker.height`.
    ///
    /// Never reads or modifies `safety_record_v1`, `meta["consensus"]`, or
    /// `meta["vote_watermark"]`.
    pub fn commit_snap_v4(
        &self,
        marker: &SnapCommitMarker,
        manifest_bytes: &[u8],
        units: &[([u8; 32], &[u8])],
    ) -> Result<()> {
        for (hash, bytes) in units {
            self.snap_units.insert(&hash[..], *bytes)?;
        }
        self.snap_manifests
            .insert(marker.height.to_be_bytes(), manifest_bytes)?;
        self.db.flush()?;
        let marker_bytes = bincode::serialize(marker)?;
        self.snap_committed
            .insert(marker.height.to_be_bytes(), marker_bytes)?;
        self.put_finalized_post_root(marker.height, marker.state_root)?;
        let _ = self.clear_snap_staging(marker.height);
        Ok(())
    }

    pub fn snap_committed_at(&self, height: u64) -> Result<Option<SnapCommitMarker>> {
        match self.snap_committed.get(height.to_be_bytes())? {
            Some(v) => Ok(Some(bincode::deserialize(&v)?)),
            None => Ok(None),
        }
    }

    pub fn latest_snap_committed(&self) -> Result<Option<SnapCommitMarker>> {
        match self.snap_committed.last()? {
            Some((_, v)) => Ok(Some(bincode::deserialize(&v)?)),
            None => Ok(None),
        }
    }

    /// Reconstruct a committed `SnapV4` state at `height` (resolving any
    /// `Base -> Δ_1 -> ... -> Δ_k` chain up to `MAX_DELTA_CHAIN_LEN`).
    pub async fn load_snap_v4_state(
        &self,
        height: u64,
    ) -> Result<Option<crate::snapshot_v4::SnapStateV4>> {
        use crate::snapshot_v4::{
            apply_delta_state, assemble_base_state, decode_manifest_strict, verify_unit_chunk,
            SnapshotKind, SnapshotManifestV1, MAX_DELTA_CHAIN_LEN, UNIT_ENC_UNCHANGED,
        };
        use std::collections::BTreeMap;

        let Some(marker) = self.snap_committed_at(height)? else {
            return Ok(None);
        };
        if marker.height != height {
            return Err(anyhow!(
                "snap_committed marker height {} != key {height}",
                marker.height
            ));
        }

        let mut chain: Vec<SnapshotManifestV1> = Vec::new();
        let mut cur_h = height;
        let mut expected_root = marker.state_root;
        loop {
            let mbytes = self.snap_manifest(cur_h)?.ok_or_else(|| {
                anyhow!("missing snap_manifests entry for committed height {cur_h}")
            })?;
            let manifest = decode_manifest_strict(&mbytes)
                .map_err(|e| anyhow!("decode snap_manifest at height {cur_h}: {e}"))?;
            if manifest.target_height != cur_h || manifest.target_state_root != expected_root {
                return Err(anyhow!(
                    "snap_manifest mismatch at height {cur_h}: target=({}, {}), expected=({cur_h}, {})",
                    manifest.target_height,
                    hex::encode(manifest.target_state_root),
                    hex::encode(expected_root)
                ));
            }
            match manifest.kind {
                SnapshotKind::Base => {
                    chain.push(manifest);
                    break;
                }
                SnapshotKind::Delta {
                    base_height,
                    base_state_root,
                } => {
                    if base_height >= cur_h {
                        return Err(anyhow!(
                            "non-monotonic snap_v4 delta chain: base={base_height} >= target={cur_h}"
                        ));
                    }
                    if chain.len() >= MAX_DELTA_CHAIN_LEN {
                        return Err(anyhow!(
                            "snap_v4 delta chain exceeds MAX_DELTA_CHAIN_LEN ({MAX_DELTA_CHAIN_LEN})"
                        ));
                    }
                    chain.push(manifest);
                    cur_h = base_height;
                    expected_root = base_state_root;
                }
            }
        }
        chain.reverse();

        let load_chunks = |m: &SnapshotManifestV1| -> Result<BTreeMap<(u16, u16), Vec<u8>>> {
            let mut map = BTreeMap::new();
            for desc in &m.units {
                if desc.encoding == UNIT_ENC_UNCHANGED {
                    continue;
                }
                let raw = self.snap_unit(&desc.chunk_hash)?.ok_or_else(|| {
                    anyhow!(
                        "missing snap_unit {} for ({}, {}) at height {}",
                        hex::encode(desc.chunk_hash),
                        desc.unit_tag,
                        desc.sub_index,
                        m.target_height
                    )
                })?;
                verify_unit_chunk(desc, &raw)
                    .map_err(|e| anyhow!("verify snap_unit at {}: {e}", m.target_height))?;
                map.insert((desc.unit_tag, desc.sub_index), raw);
            }
            Ok(map)
        };

        let base_manifest = &chain[0];
        let base_chunks = load_chunks(base_manifest)?;
        let mut state = assemble_base_state(base_manifest, &base_chunks)
            .await
            .map_err(|e| {
                anyhow!(
                    "assemble base snap_v4 at {}: {e}",
                    base_manifest.target_height
                )
            })?;
        let mut prev_h = base_manifest.target_height;
        let mut prev_root = base_manifest.target_state_root;
        for delta_manifest in &chain[1..] {
            let delta_chunks = load_chunks(delta_manifest)?;
            state = apply_delta_state(&state, prev_h, prev_root, delta_manifest, &delta_chunks)
                .await
                .map_err(|e| {
                    anyhow!(
                        "apply delta snap_v4 at {}: {e}",
                        delta_manifest.target_height
                    )
                })?;
            prev_h = delta_manifest.target_height;
            prev_root = delta_manifest.target_state_root;
        }
        Ok(Some(state))
    }

    // ---------- Durable cross-shard finalized-header registry ----------

    /// The single row holding the latest registry snapshot.
    const XSHARD_HEADERS_KEY: &'static [u8] = b"latest";

    /// Write one complete registry snapshot. Additive tree: an older data
    /// directory simply has no row and hydrates as an empty registry, exactly
    /// like a fresh process.
    pub fn put_xshard_headers(&self, bytes: &[u8]) -> Result<()> {
        self.xshard_headers
            .insert(Self::XSHARD_HEADERS_KEY, bytes)?;
        Ok(())
    }

    /// The latest persisted registry blob, if any. `None` means "never
    /// written" (fresh directory / single-shard chain), which hydrates as the
    /// empty registry — the same fail-closed start a cold process has.
    pub fn xshard_headers(&self) -> Result<Option<Vec<u8>>> {
        Ok(self
            .xshard_headers
            .get(Self::XSHARD_HEADERS_KEY)?
            .map(|v| v.to_vec()))
    }

    /// Hydrate `registry` from this store BEFORE the runtime starts voting or
    /// syncing. Called at startup.
    ///
    /// FAIL CLOSED: a corrupt blob (or an I/O error) clears the registry and
    /// returns the error, so the node starts with NO anchors — it can re-anchor
    /// blocks it finalizes from now on, but it never accepts an anchor it could
    /// not verify from disk. The caller logs the error loudly; silence would
    /// hide the difference between "restart lost history" and "restart trusted
    /// forged history".
    pub fn hydrate_finalized_headers(&self, registry: &mut FinalizedHeaderRegistry) -> Result<()> {
        let bytes = match self.xshard_headers() {
            Ok(bytes) => bytes,
            Err(e) => {
                registry.clear_anchors();
                return Err(anyhow!("read xshard_headers: {e}"));
            }
        };
        let Some(bytes) = bytes else {
            return Ok(());
        };
        registry
            .restore_from_bytes(&bytes)
            .map_err(|e| anyhow!("xshard_headers blob rejected (registry left EMPTY): {e}"))
    }

    /// The trusted state root a snapshot at `snapshot_height` must hash to.
    ///
    /// A block header commits to the state BEFORE the block applies it (the
    /// proposer reads the live root in `propose`, and `validate_proposal`,
    /// `adopt_committed` and the sync replay loop all check the header against
    /// the pre-apply root). A snapshot at height S is written AFTER block S is
    /// finalized and applied, so it holds the post-S state -- which is exactly
    /// the pre-state of block S+1. The expected root is therefore the
    /// `state_root` of the block at S+1, never of the block at S: comparing
    /// against S would reject every valid restore on a chain whose block S
    /// changed any state.
    ///
    /// The anchor comes from the already-persisted finalized chain data (the
    /// header record, which survives body pruning, falling back to a retained
    /// block body), NOT from the snapshot itself -- comparing the snapshot
    /// against anything derived from the snapshot would verify nothing.
    ///
    /// Returns `None` when no block at S+1 is persisted (a snapshot at the
    /// finalized tip with no successor yet, or a data directory from before
    /// headers were written): there is nothing independent to compare against.
    pub fn expected_restore_root(&self, snapshot_height: u64) -> Result<Option<[u8; 32]>> {
        let next = snapshot_height
            .checked_add(1)
            .ok_or_else(|| anyhow!("snapshot height overflows u64"))?;
        if let Some(rec) = self.header_at(next)? {
            return Ok(Some(rec.state_root));
        }
        for hash in self.hashes_at_height(next)? {
            if let Some(block) = self.get_block(&hash)? {
                return Ok(Some(block.state_root));
            }
        }
        Ok(None)
    }

    /// Compare a restored engine's root against the trusted root for
    /// `snapshot_height`. Missing anchor ==> `Ok(())` (nothing to compare, see
    /// `expected_restore_root`); a present-but-different anchor ==> `Err`
    /// naming both roots so the operator can see what diverged.
    pub async fn verify_restored_root(
        &self,
        engine: &InMemoryStateEngine,
        snapshot_height: u64,
    ) -> Result<()> {
        let expected = match self.expected_restore_root(snapshot_height)? {
            Some(root) => root,
            None => {
                let tip = self.finalized()?.map(|(h, _)| h).unwrap_or(snapshot_height);
                if snapshot_height < tip {
                    return Err(anyhow!(
                        "no anchor to verify snapshot at height {snapshot_height} (finalized head is {tip}); \
                         refusing to resume on unprovable state -- wipe the data directory or restore a verified backup"
                    ));
                }
                // SNAP-TIP-SKIP: when at the tip (no successor block yet), check
                // the durable finalized_post_root_v1 meta entry if present.
                // Legacy directories and unit tests without it keep Ok(()) compat.
                match self.finalized_post_root_at(snapshot_height)? {
                    Some(root) => root,
                    None => return Ok(()),
                }
            }
        };
        if let Some(bytes) = self.cnvrf_v3_at(snapshot_height)? {
            if !bytes.is_empty() {
                let snap: crate::state_engine::CnVrfV3EngineSnapshot = bincode::deserialize(&bytes)
                    .map_err(|e| anyhow!("restore cnvrf_v3 at height {snapshot_height}: {e}"))?;
                engine.restore_cnvrf_v3_snapshot(&snap).await;
            }
        }
        let computed = engine.get_state_root().await;
        if computed != expected {
            // No height-0 exception: a genesis snapshot whose bytes hash
            // differently from what the finalized block at height 1 commits
            // to is corrupt, stale, or mislabeled, and accepting it installs
            // unverified genesis state under a chain that already disagrees.
            // The old path purged the height-0 trees and returned Ok, which
            // both destroyed evidence AND installed the same mismatched bytes
            // into the live engine (the caller holds them in hand) — a
            // fail-open bypass of this very check. Refuse loudly instead; the
            // operator wipes or restores a verified backup.
            return Err(anyhow!(
                "restore root mismatch at height {snapshot_height}: snapshot hashes to {} but the finalized block at {} commits to {} (truncated, corrupt or wrong-height snapshot rejected)",
                hex::encode(computed),
                snapshot_height + 1,
                hex::encode(expected),
            ));
        }
        Ok(())
    }

    // ---------- Validator-set freshness (stale-ledger guard, node C) ----------
    //
    // A restored node derives its validator set (proposer schedule, quorum)
    // from the staking ledger inside the domain snapshot. When the ledger
    // snapshot is far older than the state snapshot, the derived set is a
    // FOREIGN set: the node neither votes (its bond is missing) nor verifies
    // quorums against the right keys, and the block walk can never teach it
    // (the bond height is outside every walk/body window, and peer domain
    // snapshots are probed separately). Fail CLOSED: refuse the stale set
    // for quorum use and run as observer instead, LOUDLY.
    //
    // Ledger height = height of the domains snapshot the ledger was loaded
    // from; state height = height of the state snapshot. Both are storage
    // keys, never ledger content (the ledger carries no height).

    /// The newest height holding a domains (= ledger) snapshot, if any.
    pub fn latest_ledger_height(&self) -> Result<Option<u64>> {
        Ok(self.latest_domains()?.map(|(h, _)| h))
    }

    /// Gap between the newest state snapshot and the newest domains snapshot.
    ///
    /// `Ok(None)` when either side is missing (nothing to compare — the
    /// caller treats it as "no ledger yet", not as stale).
    pub fn ledger_state_gap(&self) -> Result<Option<(u64, u64)>> {
        let state_h = self.latest_state()?.map(|(h, _)| h);
        let ledger_h = self.latest_ledger_height()?;
        match (state_h, ledger_h) {
            (Some(s), Some(l)) => Ok(Some((s, l))),
            _ => Ok(None),
        }
    }

    // ---------- Post-quantum public keys (pq_keys) ----------
    //
    // Namespaced keys: `a:<address>` holds bincode(scheme, pubkey, salt),
    // `h:<pk_hash>` holds the raw pubkey. The two namespaces share one tree
    // but never collide: a 32-byte address can equal a 32-byte pk hash, and
    // without the prefix the second insert would overwrite the first.

    fn pq_addr_key(address: &[u8; 32]) -> Vec<u8> {
        let mut k = Vec::with_capacity(34);
        k.extend_from_slice(b"a:");
        k.extend_from_slice(address);
        k
    }

    fn pq_hash_key(pk_hash: &[u8; 32]) -> Vec<u8> {
        let mut k = Vec::with_capacity(34);
        k.extend_from_slice(b"h:");
        k.extend_from_slice(pk_hash);
        k
    }

    fn decode_pq_value(bytes: &[u8]) -> Option<(crate::post_quantum::PqScheme, Vec<u8>, [u8; 16])> {
        if let Ok((scheme, pk, salt)) =
            bincode::deserialize::<(crate::post_quantum::PqScheme, Vec<u8>, [u8; 16])>(bytes)
        {
            return Some((scheme, pk, salt));
        }
        if let Ok((scheme, pk)) =
            bincode::deserialize::<(crate::post_quantum::PqScheme, Vec<u8>)>(bytes)
        {
            return Some((scheme, pk, crate::post_quantum::DEFAULT_SALT));
        }
        if bytes.len() > 1 {
            if let Ok(scheme) = crate::post_quantum::PqScheme::from_id(bytes[0]) {
                return Some((
                    scheme,
                    bytes[1..].to_vec(),
                    crate::post_quantum::DEFAULT_SALT,
                ));
            }
        }
        None
    }

    pub fn put_pq_key(
        &self,
        address: &[u8; 32],
        scheme: crate::post_quantum::PqScheme,
        pubkey: &[u8],
        salt: &[u8; 16],
    ) -> Result<()> {
        let val = bincode::serialize(&(scheme, pubkey, *salt))?;
        self.pq_keys
            .insert(Self::pq_addr_key(address), val.as_slice())?;
        let pk_hash = *blake3::hash(pubkey).as_bytes();
        self.pq_keys.insert(Self::pq_hash_key(&pk_hash), pubkey)?;
        self.pq_keys.flush()?;
        Ok(())
    }

    pub fn get_pq_key(
        &self,
        address: &[u8; 32],
    ) -> Result<Option<(crate::post_quantum::PqScheme, Vec<u8>)>> {
        // Namespaced read first, legacy 32-byte fallback for pre-prefix data dirs.
        let key = Self::pq_addr_key(address);
        let bytes_opt = match self.pq_keys.get(&key)? {
            Some(v) => Some(v),
            None => self.pq_keys.get(address)?,
        };
        if let Some(bytes) = bytes_opt {
            if let Some((scheme, pk, _salt)) = Self::decode_pq_value(&bytes) {
                return Ok(Some((scheme, pk)));
            }
        }
        Ok(None)
    }

    pub fn pq_key_count(&self) -> usize {
        self.pq_keys.len()
    }

    /// Hydrate `GLOBAL_IMPLICIT_KEY_REGISTRY` by iterating all `(address, data)`
    /// pairs in `storage.pq_keys` and registering them into `sharding::global_implicit_key_registry()`.
    /// Guarantees that upon node reboot, all previously activated accounts are
    /// immediately available in memory for steady-state transaction verification.
    pub fn hydrate_implicit_pq_keys(&self) -> Result<usize> {
        let registry = crate::sharding::global_implicit_key_registry();
        let mut count = 0;
        for kv in self.pq_keys.iter() {
            let (k, v) = kv?;
            // Namespaced layout: `a:<addr>` carries the key record, `h:<hash>`
            // carries the raw pubkey for hash lookup and must be skipped here.
            // Legacy 32-byte keys (pre-prefix data dirs) are address records.
            let addr_bytes: Option<&[u8]> = if k.len() == 34 && k[0] == b'a' && k[1] == b':' {
                Some(&k[2..])
            } else if k.len() == 34 && k[0] == b'h' && k[1] == b':' {
                continue;
            } else if k.len() == 32 {
                Some(&k)
            } else {
                continue;
            };
            let addr_bytes = addr_bytes.expect("branch guarantees Some");
            let mut address = [0u8; 32];
            address.copy_from_slice(addr_bytes);

            let registered = if let Some((scheme, pk, salt)) = Self::decode_pq_value(&v) {
                registry.register(address, scheme, &pk, &salt).is_ok()
            } else {
                false
            };

            if registered {
                count += 1;
            }
        }
        Ok(count)
    }

    /// Export all persistent `pq_keys` as (address, data) pairs for backup and migration flows.
    pub fn export_pq_keys(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut out = Vec::new();
        for kv in self.pq_keys.iter() {
            let (k, v) = kv?;
            out.push((k.to_vec(), v.to_vec()));
        }
        Ok(out)
    }

    /// Snapshot-sync wire encoding of the `pq_keys` domain (audit F7): the
    /// bincode of [`Self::export_pq_keys`]'s pairs. Published beside the
    /// state snapshot under `kind == "pq_keys"` and installed by
    /// `InMemoryStateEngine::restore_pq_keys` on the sync path, so the fetch
    /// set (`sync::SYNC_DOMAIN_KINDS`) finally equals the install set. Absent
    /// blob (pre-publisher directory) installs as nothing — keys then heal
    /// via gossip re-pin + the accounts snapshot's pinned `pubkey_hash`
    /// (admission refuses PQ-gated txs until healed: availability, never a
    /// fork, and the root check already passed without this domain).
    pub fn export_pq_keys_blob(&self) -> Result<Vec<u8>> {
        Ok(bincode::serialize(&self.export_pq_keys()?)?)
    }

    /// Import `pq_keys` from backup data into persistent storage.
    pub fn import_pq_keys(&self, entries: &[(Vec<u8>, Vec<u8>)]) -> Result<()> {
        for (k, v) in entries {
            self.pq_keys.insert(k.as_slice(), v.as_slice())?;
        }
        self.pq_keys.flush()?;
        Ok(())
    }
}

/// Consensus safety checkpoint. Persisted so that a validator which restarted
/// mid-height does NOT prevote a conflicting value for a height it already
/// locked (Tendermint safety survives a crash).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Default)]
pub struct ConsensusCheckpoint {
    pub height: u64,
    pub round: u32,
    pub locked_hash: Option<[u8; 32]>,
    pub locked_round: u32,
    pub finalized_height: u64,
    pub finalized_hash: [u8; 32],
}

/// One write-ahead vote watermark entry: the EXACT `(height, round, kind,
/// target, shard)` the node signed.
///
/// Persisted BEFORE the vote is broadcast, so a crash between the vote and the
/// next consensus checkpoint can never lose it and let the node re-vote in a
/// round it already used (Finding C).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VoteWatermarkEntry {
    pub height: u64,
    pub round: u32,
    /// 0 = prevote, 1 = precommit (same tag as the signed preimage).
    pub kind: u8,
    /// `None` is a NIL vote — a real, signed statement, not "no vote".
    pub target: Option<[u8; 32]>,
    pub shard_id: u32,
}

/// Write-ahead vote watermark for ONE height: the last prevote and the last
/// precommit this node signed, each with its exact target and shard.
///
/// Stored under its own meta key (NOT inside [`ConsensusCheckpoint`]) for two
/// reasons:
///  * the checkpoint is rewritten with `round: 0` on every finalize; sharing
///    the record would erase the watermark for the new height's first round;
///  * the vote must be durable BEFORE it is broadcast, while the checkpoint is
///    written after finality — different durability points.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VoteWatermark {
    pub prevote: Option<VoteWatermarkEntry>,
    pub precommit: Option<VoteWatermarkEntry>,
}

impl VoteWatermark {
    /// Record a signed vote (overwrites the entry of the same kind).
    pub fn note(&mut self, entry: VoteWatermarkEntry) {
        match entry.kind {
            0 => self.prevote = Some(entry),
            1 => self.precommit = Some(entry),
            _ => {}
        }
    }

    /// The highest round at which this node signed ANY vote at `height`.
    ///
    /// `None` means no recorded vote at that height. Used as the round FLOOR
    /// on restore and as the "never vote below" guard.
    pub fn floor_round(&self, height: u64) -> Option<u32> {
        [self.prevote, self.precommit]
            .into_iter()
            .flatten()
            .filter(|e| e.height == height)
            .map(|e| e.round)
            .max()
    }

    /// The prevote entry recorded at `height`, if any.
    pub fn prevote_at(&self, height: u64) -> Option<VoteWatermarkEntry> {
        self.prevote.filter(|e| e.height == height)
    }

    /// The precommit entry recorded at `height`, if any.
    pub fn precommit_at(&self, height: u64) -> Option<VoteWatermarkEntry> {
        self.precommit.filter(|e| e.height == height)
    }
}

/// A full snapshot of every non-account consensus domain. Persisted alongside the
/// account snapshot so a node restores the COMPLETE state after a restart (A9):
/// previously tokens, contracts, orderbooks, the PMM, staking and governance were
/// lost on restart while only account balances survived.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Default)]
pub struct DomainSnapshot {
    pub tokens: crate::token::TokenRegistry,
    pub contracts: crate::contract::ContractRegistry,
    pub orderbooks: crate::orderbook::OrderbookManager,
    pub pmm: crate::pmm::PrimaryMarketMaker,
    pub pmm_usdt_token: Option<[u8; 32]>,
    pub pmm_treasury: [u8; 32],
    pub order_escrow: HashMap<(u32, u64), crate::state_engine::EscrowRecord>,
    pub staking: crate::staking::StakingLedger,
    pub governance: crate::governance::Governance,
    /// Committed oracle state. APPENDED to the end of the struct: the field is
    /// part of the state root, so a snapshot without it would restore to a
    /// different root and be rejected by `verify_restored_root` anyway - but
    /// bincode has no field names, so this also changes the on-disk format and
    /// old domain snapshots no longer decode (a wipe, which the
    /// `COMMITMENT_VERSION` 3 -> 4 bump already requires).
    pub oracle: crate::oracle::OracleState,
}

impl DomainSnapshot {
    /// Capture the live domains from an engine + the runtime ledgers.
    pub async fn capture(
        engine: &InMemoryStateEngine,
        staking: &crate::staking::StakingLedger,
        governance: &crate::governance::Governance,
    ) -> Self {
        Self {
            tokens: engine.tokens_read().await.clone(),
            contracts: engine.contracts_read().await.clone(),
            orderbooks: engine.orderbooks_read().await.clone(),
            pmm: engine.pmm_read().await.clone(),
            pmm_usdt_token: *engine.pmm_usdt_token_read().await,
            pmm_treasury: *engine.pmm_treasury_read().await,
            order_escrow: engine.order_escrow_read().await.clone(),
            staking: staking.clone(),
            governance: governance.clone(),
            oracle: engine.oracle_read().await.clone(),
        }
    }

    /// Install the domains into the engine and return (staking, governance) for
    /// the caller to place into its shared locks.
    ///
    /// Staking and governance are ALSO installed into the engine itself: both
    /// are folded into the state-root commitment, so a restored engine whose
    /// staking/governance were left empty would compute a different root from
    /// the one the chain committed to, and root verification would false-reject
    /// every valid restore on a chain with any staking activity.
    pub async fn apply(
        self,
        engine: &InMemoryStateEngine,
    ) -> (crate::staking::StakingLedger, crate::governance::Governance) {
        *engine.tokens_write().await = self.tokens;
        *engine.contracts_write().await = self.contracts;
        *engine.orderbooks_write().await = self.orderbooks;
        *engine.pmm_write().await = self.pmm;
        *engine.pmm_usdt_token_write().await = self.pmm_usdt_token;
        *engine.pmm_treasury_write().await = self.pmm_treasury;
        *engine.order_escrow_write().await = self.order_escrow;
        *engine.staking_write().await = self.staking.clone();
        *engine.governance_write().await = self.governance.clone();
        *engine.oracle_write().await = self.oracle;
        // Re-commit token + contract entries to the state trie so SPV proofs for
        // balances and contract code keep working after a restore.
        engine.sync_aux_trie().await;
        (self.staking, self.governance)
    }
}

/// `DomainSnapshot` as written before the E2 rewards-pool fix / E7
/// governance locks changed `StakingLedger` (see
/// [`crate::staking::StakingLedgerV1`]). Kept ONLY for reading old snapshots:
/// every other domain is byte-identical, so the V1 shape differs solely in
/// the `staking` field. NEVER written; `upgrade` carries every domain across
/// and zeroes the new staking counters (see `StakingLedgerV1` for the
/// headroom caveat).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DomainSnapshotV1 {
    pub tokens: crate::token::TokenRegistry,
    pub contracts: crate::contract::ContractRegistry,
    pub orderbooks: crate::orderbook::OrderbookManager,
    pub pmm: crate::pmm::PrimaryMarketMaker,
    pub pmm_usdt_token: Option<[u8; 32]>,
    pub pmm_treasury: [u8; 32],
    pub order_escrow: HashMap<(u32, u64), crate::state_engine::EscrowRecord>,
    pub staking: crate::staking::StakingLedgerV1,
    pub governance: crate::governance::Governance,
    pub oracle: crate::oracle::OracleState,
}

impl DomainSnapshotV1 {
    pub fn upgrade(self) -> DomainSnapshot {
        DomainSnapshot {
            tokens: self.tokens,
            contracts: self.contracts,
            orderbooks: self.orderbooks,
            pmm: self.pmm,
            pmm_usdt_token: self.pmm_usdt_token,
            pmm_treasury: self.pmm_treasury,
            order_escrow: self.order_escrow,
            staking: self.staking.upgrade(),
            governance: self.governance,
            oracle: self.oracle,
        }
    }
}

/// Pre-`equivocation_dedup`/`vesting_schedules` domain shape: identical to
/// [`DomainSnapshot`] except the staking ledger is [`crate::staking::StakingLedgerV2`]
/// (everything the live network persisted before the coordinated upgrade that
/// appended those two trailing ledger fields). Upgrades with both new sets
/// empty — exact, since neither registry existed when those bytes were
/// written (see `StakingLedgerV2`).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DomainSnapshotV2 {
    pub tokens: crate::token::TokenRegistry,
    pub contracts: crate::contract::ContractRegistry,
    pub orderbooks: crate::orderbook::OrderbookManager,
    pub pmm: crate::pmm::PrimaryMarketMaker,
    pub pmm_usdt_token: Option<[u8; 32]>,
    pub pmm_treasury: [u8; 32],
    pub order_escrow: HashMap<(u32, u64), crate::state_engine::EscrowRecord>,
    pub staking: crate::staking::StakingLedgerV2,
    pub governance: crate::governance::Governance,
    pub oracle: crate::oracle::OracleState,
}

impl DomainSnapshotV2 {
    pub fn upgrade(self) -> DomainSnapshot {
        DomainSnapshot {
            tokens: self.tokens,
            contracts: self.contracts,
            orderbooks: self.orderbooks,
            pmm: self.pmm,
            pmm_usdt_token: self.pmm_usdt_token,
            pmm_treasury: self.pmm_treasury,
            order_escrow: self.order_escrow,
            staking: self.staking.upgrade(),
            governance: self.governance,
            oracle: self.oracle,
        }
    }
}

/// Pre-lazy-accumulator domain shape: identical to [`DomainSnapshot`]
/// except the staking ledger is [`crate::staking::StakingLedgerV3`] (the
/// shape the live network persisted before the F1 lazy delegator-reward
/// accumulator appended its two trailing maps). Upgrades with both new maps
/// empty — EXACT: the eager implementation credited every delegator at
/// distribution time, so every reward a pre-upgrade ledger knows about is
/// already materialised and no accumulator state has to be reconstructed.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DomainSnapshotV3 {
    pub tokens: crate::token::TokenRegistry,
    pub contracts: crate::contract::ContractRegistry,
    pub orderbooks: crate::orderbook::OrderbookManager,
    pub pmm: crate::pmm::PrimaryMarketMaker,
    pub pmm_usdt_token: Option<[u8; 32]>,
    pub pmm_treasury: [u8; 32],
    pub order_escrow: HashMap<(u32, u64), crate::state_engine::EscrowRecord>,
    pub staking: crate::staking::StakingLedgerV3,
    pub governance: crate::governance::Governance,
    pub oracle: crate::oracle::OracleState,
}

impl DomainSnapshotV3 {
    pub fn upgrade(self) -> DomainSnapshot {
        DomainSnapshot {
            tokens: self.tokens,
            contracts: self.contracts,
            orderbooks: self.orderbooks,
            pmm: self.pmm,
            pmm_usdt_token: self.pmm_usdt_token,
            pmm_treasury: self.pmm_treasury,
            order_escrow: self.order_escrow,
            staking: self.staking.upgrade(),
            governance: self.governance,
            oracle: self.oracle,
        }
    }
}

/// Pre-W3 [`crate::staking::ValidatorStake`] shape (7 fields, before
/// `withdrawal_address: Option<[u8; 32]>` was appended).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorStakeV1 {
    pub self_bond: u64,
    pub delegated: u64,
    pub commission_bps: u64,
    pub pending_rewards: u64,
    pub total_slashed: u64,
    pub missed: u32,
    pub last_downtime_penalty: u64,
}

impl ValidatorStakeV1 {
    pub fn upgrade(self) -> crate::staking::ValidatorStake {
        crate::staking::ValidatorStake {
            self_bond: self.self_bond,
            delegated: self.delegated,
            commission_bps: self.commission_bps,
            pending_rewards: self.pending_rewards,
            total_slashed: self.total_slashed,
            missed: self.missed,
            last_downtime_penalty: self.last_downtime_penalty,
            withdrawal_address: None,
        }
    }
}

/// Pre-jail/commission/lock ledger shape: identical to
/// [`crate::staking::StakingLedger`] except WITHOUT `withdrawal_address` on
/// validator rows and WITHOUT the trailing maps (`jail`, `commission_schedule`,
/// `redelegation_lock`, `recent_full_exits`) appended after the lazy
/// delegator-reward accumulator.
///
/// This is what the live network persisted between the F1 lazy-accumulator
/// upgrade and the downtime-jail/commission/lock upgrade: bincode has no
/// field names, so those bytes do not decode as the current struct
/// (`UnexpectedEof` on the missing trailing maps) and must not be decoded as
/// [`DomainSnapshotV3`] either (a shorter ledger shape would read the two
/// accumulator maps as governance — refused loudly instead). NEVER written;
/// `upgrade` fills the new maps EMPTY and sets `withdrawal_address: None`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StakingLedgerV4 {
    pub validators: HashMap<crate::consensus::ValidatorId, ValidatorStakeV1>,
    pub delegations: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub delegator_rewards: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub unbonding: Vec<crate::staking::UnbondingEntry>,
    pub withdrawable: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub total_burned: u64,
    #[serde(default)]
    pub rewards_pool: u64,
    #[serde(default)]
    pub rewards_minted: u64,
    #[serde(default)]
    pub locked_governance: HashMap<[u8; 32], u64>,
    #[serde(default)]
    pub pq_equivocation_dedup: std::collections::HashSet<[u8; 32]>,
    #[serde(default)]
    pub equivocation_dedup: std::collections::HashSet<[u8; 32]>,
    #[serde(default)]
    pub validator_pq_keys:
        HashMap<crate::consensus::ValidatorId, (crate::post_quantum::PqScheme, Vec<u8>)>,
    #[serde(default)]
    pub min_validator_bond: Option<u64>,
    #[serde(default)]
    pub vesting_schedules:
        std::collections::BTreeMap<[u8; 32], crate::tokenomics::TeamVestingSchedule>,
    #[serde(default)]
    pub reward_accumulators:
        HashMap<crate::consensus::ValidatorId, crate::staking::ValidatorRewardState>,
    #[serde(default)]
    pub delegator_reward_checkpoints: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u128>,
}

impl StakingLedgerV4 {
    pub fn upgrade(self) -> crate::staking::StakingLedger {
        crate::staking::StakingLedger {
            validators: self
                .validators
                .into_iter()
                .map(|(k, v)| (k, v.upgrade()))
                .collect(),
            delegations: self.delegations,
            delegator_rewards: self.delegator_rewards,
            reward_accumulators: self.reward_accumulators,
            delegator_reward_checkpoints: self.delegator_reward_checkpoints,
            // Exact: no jail, commission-schedule or redelegation-lock rows
            // can exist in pre-feature bytes (the paths that create them did
            // not exist), so empty is not a guess.
            jail: HashMap::new(),
            commission_schedule: HashMap::new(),
            redelegation_lock: HashMap::new(),
            unbonding: self.unbonding,
            withdrawable: self.withdrawable,
            total_burned: self.total_burned,
            rewards_pool: self.rewards_pool,
            rewards_minted: self.rewards_minted,
            locked_governance: self.locked_governance,
            pq_equivocation_dedup: self.pq_equivocation_dedup,
            equivocation_dedup: self.equivocation_dedup,
            validator_pq_keys: self.validator_pq_keys,
            vesting_schedules: self.vesting_schedules,
            min_validator_bond: self.min_validator_bond,
            // Exact: pre-change bytes cannot carry a full-exit record (the
            // recorder is applied per block and the map holds only the
            // current + previous height), so empty is not a guess.
            recent_full_exits: std::collections::HashMap::new(),
            emission_carry_q64: 0,
        }
    }
}

/// Ledger shape written after the downtime-jail/commission/lock upgrade but
/// BEFORE the forensic `recent_full_exits` map and `ValidatorStake::withdrawal_address`
/// were appended.
///
/// bincode has no field names and no "missing trailing field" rule, so those
/// bytes do not decode as the current struct. NEVER written; `upgrade` fills
/// `recent_full_exits` EMPTY and `withdrawal_address: None`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StakingLedgerV5 {
    pub validators: HashMap<crate::consensus::ValidatorId, ValidatorStakeV1>,
    pub delegations: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub delegator_rewards: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub unbonding: Vec<crate::staking::UnbondingEntry>,
    pub withdrawable: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub total_burned: u64,
    pub rewards_pool: u64,
    pub rewards_minted: u64,
    pub locked_governance: HashMap<[u8; 32], u64>,
    pub pq_equivocation_dedup: std::collections::HashSet<[u8; 32]>,
    pub equivocation_dedup: std::collections::HashSet<[u8; 32]>,
    pub validator_pq_keys:
        HashMap<crate::consensus::ValidatorId, (crate::post_quantum::PqScheme, Vec<u8>)>,
    pub min_validator_bond: Option<u64>,
    pub vesting_schedules:
        std::collections::BTreeMap<[u8; 32], crate::tokenomics::TeamVestingSchedule>,
    pub reward_accumulators:
        HashMap<crate::consensus::ValidatorId, crate::staking::ValidatorRewardState>,
    pub delegator_reward_checkpoints: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u128>,
    pub jail: HashMap<crate::consensus::ValidatorId, crate::staking::JailRecord>,
    pub commission_schedule:
        HashMap<crate::consensus::ValidatorId, crate::staking::CommissionSchedule>,
    pub redelegation_lock: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
}

impl StakingLedgerV5 {
    pub fn upgrade(self) -> crate::staking::StakingLedger {
        crate::staking::StakingLedger {
            validators: self
                .validators
                .into_iter()
                .map(|(k, v)| (k, v.upgrade()))
                .collect(),
            delegations: self.delegations,
            delegator_rewards: self.delegator_rewards,
            reward_accumulators: self.reward_accumulators,
            delegator_reward_checkpoints: self.delegator_reward_checkpoints,
            jail: self.jail,
            commission_schedule: self.commission_schedule,
            redelegation_lock: self.redelegation_lock,
            unbonding: self.unbonding,
            withdrawable: self.withdrawable,
            total_burned: self.total_burned,
            rewards_pool: self.rewards_pool,
            rewards_minted: self.rewards_minted,
            locked_governance: self.locked_governance,
            pq_equivocation_dedup: self.pq_equivocation_dedup,
            equivocation_dedup: self.equivocation_dedup,
            validator_pq_keys: self.validator_pq_keys,
            vesting_schedules: self.vesting_schedules,
            min_validator_bond: self.min_validator_bond,
            recent_full_exits: HashMap::new(),
            emission_carry_q64: 0,
        }
    }
}

/// Pre-W3 ledger shape: identical to [`crate::staking::StakingLedger`]
/// (including `recent_full_exits`) except validator entries use the 7-field
/// [`ValidatorStakeV1`] without `withdrawal_address`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StakingLedgerV6 {
    pub validators: HashMap<crate::consensus::ValidatorId, ValidatorStakeV1>,
    pub delegations: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub delegator_rewards: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub unbonding: Vec<crate::staking::UnbondingEntry>,
    pub withdrawable: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub total_burned: u64,
    pub rewards_pool: u64,
    pub rewards_minted: u64,
    pub locked_governance: HashMap<[u8; 32], u64>,
    pub pq_equivocation_dedup: std::collections::HashSet<[u8; 32]>,
    pub equivocation_dedup: std::collections::HashSet<[u8; 32]>,
    pub validator_pq_keys:
        HashMap<crate::consensus::ValidatorId, (crate::post_quantum::PqScheme, Vec<u8>)>,
    pub min_validator_bond: Option<u64>,
    pub vesting_schedules:
        std::collections::BTreeMap<[u8; 32], crate::tokenomics::TeamVestingSchedule>,
    pub reward_accumulators:
        HashMap<crate::consensus::ValidatorId, crate::staking::ValidatorRewardState>,
    pub delegator_reward_checkpoints: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u128>,
    pub jail: HashMap<crate::consensus::ValidatorId, crate::staking::JailRecord>,
    pub commission_schedule:
        HashMap<crate::consensus::ValidatorId, crate::staking::CommissionSchedule>,
    pub redelegation_lock: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub recent_full_exits: HashMap<crate::consensus::ValidatorId, (u64, u64)>,
}

impl StakingLedgerV6 {
    pub fn upgrade(self) -> crate::staking::StakingLedger {
        crate::staking::StakingLedger {
            validators: self
                .validators
                .into_iter()
                .map(|(k, v)| (k, v.upgrade()))
                .collect(),
            delegations: self.delegations,
            delegator_rewards: self.delegator_rewards,
            reward_accumulators: self.reward_accumulators,
            delegator_reward_checkpoints: self.delegator_reward_checkpoints,
            jail: self.jail,
            commission_schedule: self.commission_schedule,
            redelegation_lock: self.redelegation_lock,
            unbonding: self.unbonding,
            withdrawable: self.withdrawable,
            total_burned: self.total_burned,
            rewards_pool: self.rewards_pool,
            rewards_minted: self.rewards_minted,
            locked_governance: self.locked_governance,
            pq_equivocation_dedup: self.pq_equivocation_dedup,
            equivocation_dedup: self.equivocation_dedup,
            validator_pq_keys: self.validator_pq_keys,
            vesting_schedules: self.vesting_schedules,
            min_validator_bond: self.min_validator_bond,
            recent_full_exits: self.recent_full_exits,
            emission_carry_q64: 0,
        }
    }
}

/// Pre-jail/commission/lock domain shape: identical to [`DomainSnapshot`]
/// except the staking ledger is [`StakingLedgerV4`] (the shape the live
/// network persisted after the F1 lazy accumulator and before the
/// downtime-jail/commission/lock maps). Upgrades with the three new maps
/// empty — EXACT, since none of the paths that create them existed when
/// those bytes were written (see [`StakingLedgerV4`]).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DomainSnapshotV7 {
    pub tokens: crate::token::TokenRegistry,
    pub contracts: crate::contract::ContractRegistry,
    pub orderbooks: crate::orderbook::OrderbookManager,
    pub pmm: crate::pmm::PrimaryMarketMaker,
    pub pmm_usdt_token: Option<[u8; 32]>,
    pub pmm_treasury: [u8; 32],
    pub order_escrow: HashMap<(u32, u64), crate::state_engine::EscrowRecord>,
    pub staking: StakingLedgerV4,
    pub governance: crate::governance::Governance,
    pub oracle: crate::oracle::OracleState,
}

impl DomainSnapshotV7 {
    pub fn upgrade(self) -> DomainSnapshot {
        DomainSnapshot {
            tokens: self.tokens,
            contracts: self.contracts,
            orderbooks: self.orderbooks,
            pmm: self.pmm,
            pmm_usdt_token: self.pmm_usdt_token,
            pmm_treasury: self.pmm_treasury,
            order_escrow: self.order_escrow,
            staking: self.staking.upgrade(),
            governance: self.governance,
            oracle: self.oracle,
        }
    }
}

/// Domain shape written immediately before the forensic `recent_full_exits`
/// ledger map was appended (pentest F6). Identical to the current
/// [`DomainSnapshot`] except the staking ledger is [`StakingLedgerV5`].
///
/// This is the fallback that keeps an EXISTING current-shape data dir
/// bootable: without it the added trailing map makes bincode run off the end
/// of the ledger into `governance`. Upgrade fills the map empty (exact — it
/// only ever holds the current + previous block's exits).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DomainSnapshotV8 {
    pub tokens: crate::token::TokenRegistry,
    pub contracts: crate::contract::ContractRegistry,
    pub orderbooks: crate::orderbook::OrderbookManager,
    pub pmm: crate::pmm::PrimaryMarketMaker,
    pub pmm_usdt_token: Option<[u8; 32]>,
    pub pmm_treasury: [u8; 32],
    pub order_escrow: HashMap<(u32, u64), crate::state_engine::EscrowRecord>,
    pub staking: StakingLedgerV5,
    pub governance: crate::governance::Governance,
    pub oracle: crate::oracle::OracleState,
}

impl DomainSnapshotV8 {
    pub fn upgrade(self) -> DomainSnapshot {
        DomainSnapshot {
            tokens: self.tokens,
            contracts: self.contracts,
            orderbooks: self.orderbooks,
            pmm: self.pmm,
            pmm_usdt_token: self.pmm_usdt_token,
            pmm_treasury: self.pmm_treasury,
            order_escrow: self.order_escrow,
            staking: self.staking.upgrade(),
            governance: self.governance,
            oracle: self.oracle,
        }
    }
}

/// Pre-W3 domain shape: identical to [`DomainSnapshot`] except the staking
/// ledger is [`StakingLedgerV6`] (which uses 7-field [`ValidatorStakeV1`]
/// without `withdrawal_address`). Upgrade fills `withdrawal_address: None`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DomainSnapshotV9 {
    pub tokens: crate::token::TokenRegistry,
    pub contracts: crate::contract::ContractRegistry,
    pub orderbooks: crate::orderbook::OrderbookManager,
    pub pmm: crate::pmm::PrimaryMarketMaker,
    pub pmm_usdt_token: Option<[u8; 32]>,
    pub pmm_treasury: [u8; 32],
    pub order_escrow: HashMap<(u32, u64), crate::state_engine::EscrowRecord>,
    pub staking: StakingLedgerV6,
    pub governance: crate::governance::Governance,
    pub oracle: crate::oracle::OracleState,
}

impl DomainSnapshotV9 {
    pub fn upgrade(self) -> DomainSnapshot {
        DomainSnapshot {
            tokens: self.tokens,
            contracts: self.contracts,
            orderbooks: self.orderbooks,
            pmm: self.pmm,
            pmm_usdt_token: self.pmm_usdt_token,
            pmm_treasury: self.pmm_treasury,
            order_escrow: self.order_escrow,
            staking: self.staking.upgrade(),
            governance: self.governance,
            oracle: self.oracle,
        }
    }
}

/// Pre-W4 `emission_carry_q64` ledger shape: identical to
/// [`crate::staking::StakingLedger`] (including 8-field `ValidatorStake` and
/// `recent_full_exits`) without the trailing `emission_carry_q64: u64`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StakingLedgerV7 {
    pub validators: HashMap<crate::consensus::ValidatorId, crate::staking::ValidatorStake>,
    pub delegations: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub delegator_rewards: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub unbonding: Vec<crate::staking::UnbondingEntry>,
    pub withdrawable: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub total_burned: u64,
    pub rewards_pool: u64,
    pub rewards_minted: u64,
    pub locked_governance: HashMap<[u8; 32], u64>,
    pub pq_equivocation_dedup: std::collections::HashSet<[u8; 32]>,
    pub equivocation_dedup: std::collections::HashSet<[u8; 32]>,
    pub validator_pq_keys:
        HashMap<crate::consensus::ValidatorId, (crate::post_quantum::PqScheme, Vec<u8>)>,
    pub min_validator_bond: Option<u64>,
    pub vesting_schedules:
        std::collections::BTreeMap<[u8; 32], crate::tokenomics::TeamVestingSchedule>,
    pub reward_accumulators:
        HashMap<crate::consensus::ValidatorId, crate::staking::ValidatorRewardState>,
    pub delegator_reward_checkpoints: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u128>,
    pub jail: HashMap<crate::consensus::ValidatorId, crate::staking::JailRecord>,
    pub commission_schedule:
        HashMap<crate::consensus::ValidatorId, crate::staking::CommissionSchedule>,
    pub redelegation_lock: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub recent_full_exits: HashMap<crate::consensus::ValidatorId, (u64, u64)>,
}

impl StakingLedgerV7 {
    pub fn upgrade(self) -> crate::staking::StakingLedger {
        crate::staking::StakingLedger {
            validators: self.validators,
            delegations: self.delegations,
            delegator_rewards: self.delegator_rewards,
            reward_accumulators: self.reward_accumulators,
            delegator_reward_checkpoints: self.delegator_reward_checkpoints,
            jail: self.jail,
            commission_schedule: self.commission_schedule,
            redelegation_lock: self.redelegation_lock,
            unbonding: self.unbonding,
            withdrawable: self.withdrawable,
            total_burned: self.total_burned,
            rewards_pool: self.rewards_pool,
            rewards_minted: self.rewards_minted,
            locked_governance: self.locked_governance,
            pq_equivocation_dedup: self.pq_equivocation_dedup,
            equivocation_dedup: self.equivocation_dedup,
            validator_pq_keys: self.validator_pq_keys,
            vesting_schedules: self.vesting_schedules,
            min_validator_bond: self.min_validator_bond,
            recent_full_exits: self.recent_full_exits,
            emission_carry_q64: 0,
        }
    }
}

/// Pre-W4 `emission_carry_q64` domain shape: identical to [`DomainSnapshot`]
/// except the staking ledger is [`StakingLedgerV7`]. Upgrade sets
/// `emission_carry_q64: 0`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DomainSnapshotV10 {
    pub tokens: crate::token::TokenRegistry,
    pub contracts: crate::contract::ContractRegistry,
    pub orderbooks: crate::orderbook::OrderbookManager,
    pub pmm: crate::pmm::PrimaryMarketMaker,
    pub pmm_usdt_token: Option<[u8; 32]>,
    pub pmm_treasury: [u8; 32],
    pub order_escrow: HashMap<(u32, u64), crate::state_engine::EscrowRecord>,
    pub staking: StakingLedgerV7,
    pub governance: crate::governance::Governance,
    pub oracle: crate::oracle::OracleState,
}

impl DomainSnapshotV10 {
    pub fn upgrade(self) -> DomainSnapshot {
        DomainSnapshot {
            tokens: self.tokens,
            contracts: self.contracts,
            orderbooks: self.orderbooks,
            pmm: self.pmm,
            pmm_usdt_token: self.pmm_usdt_token,
            pmm_treasury: self.pmm_treasury,
            order_escrow: self.order_escrow,
            staking: self.staking.upgrade(),
            governance: self.governance,
            oracle: self.oracle,
        }
    }
}

// ---------------------------------------------------------------------------
// Legacy contract / governance shapes.
//
// The contract registry grew two trailing fields (a per-contract `balance` and
// an optional typed `abi` manifest) and the registry itself grew
// `last_return_data`; the governance applied-params grew `upgrade_plan`. All
// three are APPENDED, so the ON-DISK bytes of a chain written before them are
// a strict PREFIX of the current ones — but bincode has no field names and no
// "missing trailing field" rule, so the current types CANNOT read them: the
// decoder runs off the end of the appended field into the next struct and
// finally mis-reads a byte string as an enum discriminant ("invalid value:
// integer N, expected variant index 0 <= i < 2").
//
// `#[serde(default)]` does NOT help here: it is a JSON/self-describing-format
// feature, and bincode (a non-self-describing format) has no way to know a
// field is absent.
//
// The shadow types below reproduce the OLD layout byte-for-byte so a legacy
// domain snapshot decodes, and `upgrade` fills the appended fields with their
// exact pre-upgrade meaning:
//   * `Contract.balance` = 0  — the field did not exist, so no contract held
//     a balance in the old chain; the balance lives in the contract's storage
//     slots, which ARE carried across.
//   * `Contract.abi` = None   — no manifest was stored, so no manifest is
//     claimed. (The ABI is committed to the state trie next to the code hash
//     when present; an absent manifest contributes the same bytes as before.)
//   * `ContractRegistry.last_return_data` = empty — a transient per-call
//     value, never consensus state.
//   * `AppliedParams.upgrade_plan` = None — no coordinated upgrade plan was
//     ratified in the old chain.
//
// The commitments are unaffected by the upgrade of these four fields: none of
// them is hashed into the state root (the ABI manifest is, but only when it
// is present, and the old chain has none), so a legacy restore reproduces the
// SAME state root the old chain committed to.
// ---------------------------------------------------------------------------

/// Pre-ABI contract shape (7 fields, the layout before `balance` and `abi`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContractLegacy {
    pub address: [u8; 32],
    pub creator: [u8; 32],
    pub code_hash: [u8; 32],
    pub code: Vec<u8>,
    pub storage: HashMap<i64, i64>,
    pub created_at: u64,
    pub paused: bool,
}

impl ContractLegacy {
    pub fn upgrade(self) -> crate::contract::Contract {
        crate::contract::Contract {
            address: self.address,
            creator: self.creator,
            code_hash: self.code_hash,
            code: self.code,
            storage: self.storage,
            created_at: self.created_at,
            paused: self.paused,
            balance: 0,
            abi: None,
            // No source was ever registered on the old chain: absent =
            // unverified, which contributes nothing to the state digest, so
            // the restored root is byte-identical to the legacy one.
            source_hash: None,
        }
    }
}

/// Pre-`last_return_data` contract registry (2 fields).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ContractRegistryLegacy {
    pub contracts: HashMap<[u8; 32], ContractLegacy>,
    pub next_nonce: u64,
}

impl ContractRegistryLegacy {
    pub fn upgrade(self) -> crate::contract::ContractRegistry {
        crate::contract::ContractRegistry {
            contracts: self
                .contracts
                .into_iter()
                .map(|(k, v)| (k, v.upgrade()))
                .collect(),
            next_nonce: self.next_nonce,
            last_return_data: Vec::new(),
        }
    }
}

/// Pre-`upgrade_plan` applied-params shape (7 fields).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AppliedParamsLegacy {
    pub min_validator_bond: Option<u64>,
    pub equivocation_slash_bps: Option<u64>,
    pub default_commission_bps: Option<u64>,
    pub block_reward: Option<u64>,
    pub pmm_redemption_buffer_bps: Option<u64>,
    pub min_gas_limit: Option<u64>,
    pub signal: Option<String>,
}

impl AppliedParamsLegacy {
    pub fn upgrade(self) -> crate::governance::AppliedParams {
        crate::governance::AppliedParams {
            min_validator_bond: self.min_validator_bond,
            equivocation_slash_bps: self.equivocation_slash_bps,
            default_commission_bps: self.default_commission_bps,
            block_reward: self.block_reward,
            pmm_redemption_buffer_bps: self.pmm_redemption_buffer_bps,
            min_gas_limit: self.min_gas_limit,
            signal: self.signal,
            upgrade_plan: None,
        }
    }
}

/// Pre-`upgrade_plan` governance shape (the proposals map is unchanged: the
/// `GovAction` variants added since then were APPENDED, so the existing
/// discriminants — and therefore the persisted bytes — are identical).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GovernanceLegacy {
    pub proposals: HashMap<u64, crate::governance::Proposal>,
    pub next_id: u64,
    pub quorum_bps: u64,
    pub applied: AppliedParamsLegacy,
}

impl GovernanceLegacy {
    pub fn upgrade(self) -> crate::governance::Governance {
        crate::governance::Governance {
            proposals: self.proposals,
            next_id: self.next_id,
            quorum_bps: self.quorum_bps,
            applied: self.applied.upgrade(),
            // KI-23: legacy storage predates the timelock map — no maturities
            // (pre-timelock Passed executes immediately, one-time migration).
            timelocks: Default::default(),
            // Operator-signed governance: legacy storage predates signed
            // nonces — the set starts empty (exact: no signed nonce existed
            // when those bytes were written, so nothing can be replayed).
            gov_propose_nonces: Default::default(),
        }
    }
}

/// A domain snapshot whose CONTRACT REGISTRY and GOVERNANCE are in the legacy
/// layout, parameterised over the staking-ledger shape.
macro_rules! legacy_contract_domain_snapshot {
    ($vis:vis $name:ident, $staking:ty) => {
        #[derive(Clone, Debug, Default, Serialize, Deserialize)]
        $vis struct $name {
            pub tokens: crate::token::TokenRegistry,
            pub contracts: ContractRegistryLegacy,
            pub orderbooks: crate::orderbook::OrderbookManager,
            pub pmm: crate::pmm::PrimaryMarketMaker,
            pub pmm_usdt_token: Option<[u8; 32]>,
            pub pmm_treasury: [u8; 32],
            pub order_escrow: HashMap<(u32, u64), crate::state_engine::EscrowRecord>,
            pub staking: $staking,
            pub governance: GovernanceLegacy,
            pub oracle: crate::oracle::OracleState,
        }
        impl $name {
            $vis fn upgrade(self) -> DomainSnapshot {
                DomainSnapshot {
                    tokens: self.tokens,
                    contracts: self.contracts.upgrade(),
                    orderbooks: self.orderbooks,
                    pmm: self.pmm,
                    pmm_usdt_token: self.pmm_usdt_token,
                    pmm_treasury: self.pmm_treasury,
                    order_escrow: self.order_escrow,
                    staking: self.staking.upgrade(),
                    governance: self.governance.upgrade(),
                    oracle: self.oracle,
                }
            }
        }
    };
}

legacy_contract_domain_snapshot!(pub DomainSnapshotV4, crate::staking::StakingLedgerV3);
legacy_contract_domain_snapshot!(pub DomainSnapshotV5, crate::staking::StakingLedgerV2);
legacy_contract_domain_snapshot!(pub DomainSnapshotV6, crate::staking::StakingLedgerV1);

// Private 7-field `ValidatorStakeV1` shadow shapes for V1..V3 ledgers (which live
// in `staking.rs` with 8-field `ValidatorStake`) so real pre-W3 V1..V6 domain
// snapshots on disk also decode cleanly with `withdrawal_address: None`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct StakingLedgerV1WithV1Stake {
    pub validators: HashMap<crate::consensus::ValidatorId, ValidatorStakeV1>,
    pub delegations: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub delegator_rewards: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub unbonding: Vec<crate::staking::UnbondingEntry>,
    pub withdrawable: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub total_burned: u64,
}

impl StakingLedgerV1WithV1Stake {
    fn upgrade(self) -> crate::staking::StakingLedger {
        crate::staking::StakingLedgerV1 {
            validators: self
                .validators
                .into_iter()
                .map(|(k, v)| (k, v.upgrade()))
                .collect(),
            delegations: self.delegations,
            delegator_rewards: self.delegator_rewards,
            unbonding: self.unbonding,
            withdrawable: self.withdrawable,
            total_burned: self.total_burned,
        }
        .upgrade()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct StakingLedgerV2WithV1Stake {
    pub validators: HashMap<crate::consensus::ValidatorId, ValidatorStakeV1>,
    pub delegations: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub delegator_rewards: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub unbonding: Vec<crate::staking::UnbondingEntry>,
    pub withdrawable: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub total_burned: u64,
    #[serde(default)]
    pub rewards_pool: u64,
    #[serde(default)]
    pub rewards_minted: u64,
    #[serde(default)]
    pub locked_governance: HashMap<[u8; 32], u64>,
    #[serde(default)]
    pub pq_equivocation_dedup: std::collections::HashSet<[u8; 32]>,
    #[serde(default)]
    pub validator_pq_keys:
        HashMap<crate::consensus::ValidatorId, (crate::post_quantum::PqScheme, Vec<u8>)>,
}

impl StakingLedgerV2WithV1Stake {
    fn upgrade(self) -> crate::staking::StakingLedger {
        crate::staking::StakingLedgerV2 {
            validators: self
                .validators
                .into_iter()
                .map(|(k, v)| (k, v.upgrade()))
                .collect(),
            delegations: self.delegations,
            delegator_rewards: self.delegator_rewards,
            unbonding: self.unbonding,
            withdrawable: self.withdrawable,
            total_burned: self.total_burned,
            rewards_pool: self.rewards_pool,
            rewards_minted: self.rewards_minted,
            locked_governance: self.locked_governance,
            pq_equivocation_dedup: self.pq_equivocation_dedup,
            validator_pq_keys: self.validator_pq_keys,
        }
        .upgrade()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct StakingLedgerV3WithV1Stake {
    pub validators: HashMap<crate::consensus::ValidatorId, ValidatorStakeV1>,
    pub delegations: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub delegator_rewards: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub unbonding: Vec<crate::staking::UnbondingEntry>,
    pub withdrawable: HashMap<(crate::consensus::ValidatorId, [u8; 32]), u64>,
    pub total_burned: u64,
    #[serde(default)]
    pub rewards_pool: u64,
    #[serde(default)]
    pub rewards_minted: u64,
    #[serde(default)]
    pub locked_governance: HashMap<[u8; 32], u64>,
    #[serde(default)]
    pub pq_equivocation_dedup: std::collections::HashSet<[u8; 32]>,
    #[serde(default)]
    pub equivocation_dedup: std::collections::HashSet<[u8; 32]>,
    #[serde(default)]
    pub validator_pq_keys:
        HashMap<crate::consensus::ValidatorId, (crate::post_quantum::PqScheme, Vec<u8>)>,
    #[serde(default)]
    pub min_validator_bond: Option<u64>,
    #[serde(default)]
    pub vesting_schedules:
        std::collections::BTreeMap<[u8; 32], crate::tokenomics::TeamVestingSchedule>,
}

impl StakingLedgerV3WithV1Stake {
    fn upgrade(self) -> crate::staking::StakingLedger {
        crate::staking::StakingLedgerV3 {
            validators: self
                .validators
                .into_iter()
                .map(|(k, v)| (k, v.upgrade()))
                .collect(),
            delegations: self.delegations,
            delegator_rewards: self.delegator_rewards,
            unbonding: self.unbonding,
            withdrawable: self.withdrawable,
            total_burned: self.total_burned,
            rewards_pool: self.rewards_pool,
            rewards_minted: self.rewards_minted,
            locked_governance: self.locked_governance,
            pq_equivocation_dedup: self.pq_equivocation_dedup,
            equivocation_dedup: self.equivocation_dedup,
            validator_pq_keys: self.validator_pq_keys,
            min_validator_bond: self.min_validator_bond,
            vesting_schedules: self.vesting_schedules,
        }
        .upgrade()
    }
}

macro_rules! current_contract_v1_stake_domain_snapshot {
    ($name:ident, $staking:ty) => {
        #[derive(Clone, Debug, Default, Serialize, Deserialize)]
        struct $name {
            pub tokens: crate::token::TokenRegistry,
            pub contracts: crate::contract::ContractRegistry,
            pub orderbooks: crate::orderbook::OrderbookManager,
            pub pmm: crate::pmm::PrimaryMarketMaker,
            pub pmm_usdt_token: Option<[u8; 32]>,
            pub pmm_treasury: [u8; 32],
            pub order_escrow: HashMap<(u32, u64), crate::state_engine::EscrowRecord>,
            pub staking: $staking,
            pub governance: crate::governance::Governance,
            pub oracle: crate::oracle::OracleState,
        }
        impl $name {
            fn upgrade(self) -> DomainSnapshot {
                DomainSnapshot {
                    tokens: self.tokens,
                    contracts: self.contracts,
                    orderbooks: self.orderbooks,
                    pmm: self.pmm,
                    pmm_usdt_token: self.pmm_usdt_token,
                    pmm_treasury: self.pmm_treasury,
                    order_escrow: self.order_escrow,
                    staking: self.staking.upgrade(),
                    governance: self.governance,
                    oracle: self.oracle,
                }
            }
        }
    };
}

legacy_contract_domain_snapshot!(DomainSnapshotV4WithV1Stake, StakingLedgerV3WithV1Stake);
legacy_contract_domain_snapshot!(DomainSnapshotV5WithV1Stake, StakingLedgerV2WithV1Stake);
legacy_contract_domain_snapshot!(DomainSnapshotV6WithV1Stake, StakingLedgerV1WithV1Stake);
current_contract_v1_stake_domain_snapshot!(DomainSnapshotV3WithV1Stake, StakingLedgerV3WithV1Stake);
current_contract_v1_stake_domain_snapshot!(DomainSnapshotV2WithV1Stake, StakingLedgerV2WithV1Stake);
current_contract_v1_stake_domain_snapshot!(DomainSnapshotV1WithV1Stake, StakingLedgerV1WithV1Stake);

/// Decode a persisted [`crate::pq_registry::PqRegistry`] snapshot blob.
///
/// Empty bytes decode to an empty registry; non-empty bytes require exact
/// fixint bincode decoding with trailing bytes rejected.
pub fn decode_pq_registry(bytes: &[u8]) -> Result<crate::pq_registry::PqRegistry> {
    use bincode::Options;
    if bytes.is_empty() {
        return Ok(crate::pq_registry::PqRegistry::default());
    }
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(DOMAIN_SNAPSHOT_STRICT_MAX_BYTES)
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|e| anyhow!("decode pq_registry: {e}"))
}

/// Decode a persisted domain snapshot, accepting the pre-E2/E7 V1 shape.
///
/// Current bytes decode directly. Older bytes (a `StakingLedger` without the
/// rewards counters and governance locks) fail the direct decode with
/// `UnexpectedEof` and are retried as `DomainSnapshotV1`, whose staking
/// ledger upgrades with zeroed counters. LOUD on fallback — the same
/// contract as the bridge V1 upgrade (`restore_bridge`): a zeroed
/// `rewards_minted` overstates emission-cap headroom on a chain that minted
/// pre-upgrade, so operators must see this line and verify real minted
/// supply out-of-band (exact on fresh/test chains).
///
/// The LEGACY CONTRACT/GOVERNANCE shapes are tried BEFORE the current-shape
/// variants: a snapshot written before the contract ABI manifest and the
/// coordinated upgrade plan existed cannot be read by the current types at
/// all (bincode has no field names), so without this leg EVERY node of a
/// running cluster would refuse to start after the binary swap.
pub fn decode_domain_snapshot(bytes: &[u8]) -> Result<DomainSnapshot> {
    if let Ok(snap) = bincode::deserialize::<DomainSnapshot>(bytes) {
        return Ok(snap);
    }
    // V10: pre-W4 current-shape domains (`StakingLedgerV7`), identical to
    // current except `emission_carry_q64` was appended last. Upgrade sets
    // `emission_carry_q64: 0` (exact for any pre-W4 snapshot).
    if let Ok(v10) = bincode::deserialize::<DomainSnapshotV10>(bytes) {
        tracing::warn!(
            "[domains] restored pre-W4 V10 staking state: emission_carry_q64 starts at 0"
        );
        return Ok(v10.upgrade());
    }
    // V9: pre-W3 current-shape domains (`StakingLedgerV6`, including
    // `recent_full_exits`), with 7-field `ValidatorStakeV1` (no
    // `withdrawal_address`). Upgrade sets `withdrawal_address: None`.
    if let Ok(v9) = bincode::deserialize::<DomainSnapshotV9>(bytes) {
        tracing::warn!(
            "[domains] restored pre-W3 V9 staking state: validator withdrawal_address starts as None until claimed via SysCallClaimWithdrawal"
        );
        return Ok(v9.upgrade());
    }
    // V8: current domains written before the forensic `recent_full_exits`
    // ledger map was appended. Closest to the current shape, so tried next.
    // The map is empty on upgrade, which is exact at a snapshot boundary (it
    // only ever holds the current + previous block's exits).
    if let Ok(v8) = bincode::deserialize::<DomainSnapshotV8>(bytes) {
        tracing::warn!(
            "[domains] restored pre-full-exit-record V8 staking state: the forensic recent-full-exit map starts EMPTY (exact — it is repopulated by the next applied block)"
        );
        return Ok(v8.upgrade());
    }
    // LEGACY CONTRACTS + GOVERNANCE (the live-cluster shape): the contract
    // registry without the per-contract balance/ABI and without
    // `last_return_data`, and the applied params without `upgrade_plan`.
    if let Ok(v4) = bincode::deserialize::<DomainSnapshotV4>(bytes) {
        tracing::warn!(
            "[domains] restored pre-ABI/upgrade-plan domain state: contract balances, contract ABI manifests, the registry's last-return-data and the coordinated upgrade plan start EMPTY (exact — none of them existed when written)"
        );
        return Ok(v4.upgrade());
    }
    if let Ok(v4) = bincode::deserialize::<DomainSnapshotV4WithV1Stake>(bytes) {
        tracing::warn!(
            "[domains] restored pre-ABI/upgrade-plan domain state (pre-W3 ValidatorStakeV1): contract balances, contract ABI manifests, the registry's last-return-data and the coordinated upgrade plan start EMPTY"
        );
        return Ok(v4.upgrade());
    }
    if let Ok(v5) = bincode::deserialize::<DomainSnapshotV5>(bytes) {
        tracing::warn!(
            "[domains] restored pre-ABI/upgrade-plan domain state (older staking ledger): contract balances, contract ABI manifests, the registry's last-return-data and the coordinated upgrade plan start EMPTY (exact — none of them existed when written)"
        );
        return Ok(v5.upgrade());
    }
    if let Ok(v5) = bincode::deserialize::<DomainSnapshotV5WithV1Stake>(bytes) {
        tracing::warn!(
            "[domains] restored pre-ABI/upgrade-plan domain state (older staking ledger, pre-W3 ValidatorStakeV1): contract balances, contract ABI manifests, the registry's last-return-data and the coordinated upgrade plan start EMPTY"
        );
        return Ok(v5.upgrade());
    }
    if let Ok(v6) = bincode::deserialize::<DomainSnapshotV6>(bytes) {
        tracing::warn!(
            "[domains] restored pre-ABI/upgrade-plan domain state (oldest staking ledger): contract balances, contract ABI manifests, the registry's last-return-data and the coordinated upgrade plan start EMPTY (exact — none of them existed when written)"
        );
        return Ok(v6.upgrade());
    }
    if let Ok(v6) = bincode::deserialize::<DomainSnapshotV6WithV1Stake>(bytes) {
        tracing::warn!(
            "[domains] restored pre-ABI/upgrade-plan domain state (oldest staking ledger, pre-W3 ValidatorStakeV1): contract balances, contract ABI manifests, the registry's last-return-data and the coordinated upgrade plan start EMPTY"
        );
        return Ok(v6.upgrade());
    }
    // V7: pre-jail/commission/lock ledger shape (current contracts, the
    // ledger with the lazy accumulator but without the three trailing maps).
    // Upgrades with the three new maps empty — EXACT: none of the paths that
    // create them existed when those bytes were written. Tried here, at the
    // head of the current-contract group (after the legacy-contract V4/V5/V6
    // legs, before V3): the grouping rule above (legacy contracts first)
    // decides the position, and closeness to the current shape decides the
    // order within the group. LOUD so operators see the migration.
    if let Ok(v7) = bincode::deserialize::<DomainSnapshotV7>(bytes) {
        tracing::warn!(
            "[domains] restored pre-jail/commission/lock V7 staking state: the jail records, the commission schedules and the redelegation locks start EMPTY (exact — none of the paths that create them existed when written)"
        );
        return Ok(v7.upgrade());
    }
    // V3: pre-lazy-accumulator ledger shape (what the live network persisted
    // before the F1 delegator-reward accumulator appended its two trailing
    // maps). Upgrades with both maps empty — EXACT: the eager implementation
    // materialised every delegator reward at distribution time, so nothing has
    // to be reconstructed. LOUD so operators see the migration.
    if let Ok(v3) = bincode::deserialize::<DomainSnapshotV3>(bytes) {
        tracing::warn!(
            "[domains] restored pre-lazy-accumulator V3 staking state: the reward accumulator and the delegator checkpoints start EMPTY (exact — the eager implementation materialised every delegator reward)"
        );
        return Ok(v3.upgrade());
    }
    if let Ok(v3) = bincode::deserialize::<DomainSnapshotV3WithV1Stake>(bytes) {
        tracing::warn!(
            "[domains] restored pre-lazy-accumulator V3 staking state (pre-W3 ValidatorStakeV1): the reward accumulator and the delegator checkpoints start EMPTY"
        );
        return Ok(v3.upgrade());
    }
    // V2: pre-equivocation-dedup/vesting ledger shape (what the live network
    // persisted before the coordinated upgrade appending those two trailing
    // fields). Upgrades with both new sets empty — exact, neither registry
    // existed. LOUD so operators see the migration.
    if let Ok(v2) = bincode::deserialize::<DomainSnapshotV2>(bytes) {
        tracing::warn!(
            "[domains] restored pre-dedup/vesting V2 staking state: equivocation_dedup and vesting_schedules start EMPTY (exact — neither registry existed when written)"
        );
        return Ok(v2.upgrade());
    }
    if let Ok(v2) = bincode::deserialize::<DomainSnapshotV2WithV1Stake>(bytes) {
        tracing::warn!(
            "[domains] restored pre-dedup/vesting V2 staking state (pre-W3 ValidatorStakeV1): equivocation_dedup and vesting_schedules start EMPTY"
        );
        return Ok(v2.upgrade());
    }
    // Fall through to the oldest format below.
    if let Ok(v1) = bincode::deserialize::<DomainSnapshotV1>(bytes) {
        tracing::warn!(
            "[domains] restored pre-E2 V1 staking state: rewards counters start at ZERO — verify real minted supply out-of-band before trusting emission-cap headroom (exact on fresh/test chains)"
        );
        return Ok(v1.upgrade());
    }
    let v1: DomainSnapshotV1WithV1Stake =
        bincode::deserialize(bytes).map_err(|e| anyhow!("restore domains: {e}"))?;
    tracing::warn!(
        "[domains] restored pre-E2 V1 staking state (pre-W3 ValidatorStakeV1): rewards counters start at ZERO — verify real minted supply out-of-band before trusting emission-cap headroom (exact on fresh/test chains)"
    );
    Ok(v1.upgrade())
}

/// Maximum bytes [`decode_domain_snapshot_strict`] accepts for one domain
/// blob (fail-closed anti-DoS on peer-supplied input: a snapshot is tens of
/// MB; 512 MiB is two orders of magnitude above any honest blob and bounds
/// the allocator before the first field decodes).
pub const DOMAIN_SNAPSHOT_STRICT_MAX_BYTES: u64 = 512 * 1024 * 1024;

/// Strict trust-anchor parser for a persisted/fetched domain snapshot.
///
/// Accepts ONLY the current [`DomainSnapshot`] shape, with trailing bytes
/// rejected (same wire contract as `ConsensusMsg::decode`: fixint bincode,
/// exact-length). Any legacy shape (`DomainSnapshotV1`..`V9`, pre-ABI
/// governance, pre-lazy ledgers) or unknown/future version is a hard `Err`
/// naming the refusal — NO warn-and-upgrade fallback, NO silent skip.
///
/// Split from [`decode_domain_snapshot`] on purpose: the LOCAL restore path
/// keeps the lenient decoder so pre-upgrade data directories still boot
/// (pinned by `staking_ledger_migration_tests` and the `pre_e2`/`pre_lazy`
/// unit tests), while every path that treats a snapshot as a TRUST ANCHOR
/// (sync `install_bundle`, [`crate::sync::check_snapshot_set_binding`])
/// uses this strict parser, so a legacy blob can never become quorum state.
/// A legacy snapshot is re-published from a current binary, never upgraded
/// in place on the trust path.
pub fn decode_domain_snapshot_strict(bytes: &[u8]) -> Result<DomainSnapshot, String> {
    use bincode::Options;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(DOMAIN_SNAPSHOT_STRICT_MAX_BYTES)
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|e| {
            format!(
                "refusing domain snapshot: not a current-shape DomainSnapshot \
                 (legacy or unknown version — no downgrade applied, refusing \
                 fail-closed; re-publish the snapshot from a current binary): {e}"
            )
        })
}

/// Validator set committed by the domain snapshot at `snapshot_height`.
///
/// Strict-decodes `domain_bytes` (see [`decode_domain_snapshot_strict`]) and
/// derives the consensus set from the enclosed staking ledger. This is the
/// F5 set-at-height commitment: a snapshot used as a trust anchor MUST carry
/// the set in force at its height, so the anchor proof (QCs verified under a
/// resolved set) and the adopted set (installed from this ledger) agree.
/// Returns the derived set (possibly empty — the caller decides whether an
/// empty commitment is usable; [`crate::sync::check_snapshot_set_binding`]
/// refuses it as a trust anchor).
pub fn snapshot_validator_set_strict(
    snapshot_height: u64,
    domain_bytes: &[u8],
) -> Result<crate::consensus::ValidatorSet, String> {
    let snap = decode_domain_snapshot_strict(domain_bytes).map_err(|e| {
        format!("snapshot at height {snapshot_height} commits to no usable validator set: {e}")
    })?;
    Ok(snap.staking.to_validator_set())
}

/// Default ceiling for how far the ledger (domains) snapshot may lag the
/// state snapshot before the derived validator set is refused as STALE.
///
/// The local snapshot ring keeps `height - 300` and newer (see the prune
/// window in `main.rs`: snapshots every 100 heights, three kept), so a lag
/// beyond one full ring means the ledger predates every locally retained
/// snapshot — exactly the node-C shape (bond outside every window).
pub const VALIDATOR_SET_FRESHNESS_DEFAULT_LAG: u64 = 300;

/// Effective ceiling for [`check_validator_set_freshness`].
///
/// Env `STELL_VALIDATOR_SET_MAX_LAG` (alias `STELL_LEDGER_FRESHNESS_MAX_LAG`),
/// default [`VALIDATOR_SET_FRESHNESS_DEFAULT_LAG`]. Unparseable/zero values
/// fall back to the default (zero would mark every paired restore stale).
pub fn validator_set_freshness_max_lag() -> u64 {
    for key in [
        "STELL_VALIDATOR_SET_MAX_LAG",
        "STELL_LEDGER_FRESHNESS_MAX_LAG",
    ] {
        if let Ok(raw) = std::env::var(key) {
            if let Ok(v) = raw.trim().parse::<u64>() {
                if v > 0 {
                    return v;
                }
            }
        }
    }
    VALIDATOR_SET_FRESHNESS_DEFAULT_LAG
}

/// Pure core of [`check_validator_set_freshness`] over an explicit ceiling.
/// `Ok(())` when fresh; `Err(reason)` naming both heights and the ceiling
/// when the ledger lags the state by more than `max_lag`, or when the ledger
/// claims to be AHEAD of the state (clock/label corruption — never trusted).
pub fn check_validator_set_freshness_with_lag(
    state_height: u64,
    ledger_height: u64,
    max_lag: u64,
) -> Result<(), String> {
    if ledger_height > state_height {
        return Err(format!(
            "STALE validator set: ledger height {ledger_height} is AHEAD of state height {state_height} (label corruption — refusing the set for quorum use)"
        ));
    }
    let lag = state_height.saturating_sub(ledger_height);
    if lag > max_lag {
        return Err(format!(
            "STALE validator set: ledger height {ledger_height} lags state height {state_height} by {lag} heights (max {max_lag}) — bond history outside every window, refusing the set for quorum use"
        ));
    }
    Ok(())
}

/// Freshness gate for a restored / snapshot-refreshed validator set.
///
/// Compares the ledger height (domains-snapshot height) against the state
/// height and, on staleness, logs a LOUD warn on BOTH channels
/// (`tracing::warn!` + `eprintln!`) before returning `Err`. Callers must
/// treat `Err` as fail-closed: do NOT install the stale set for quorum use,
/// run as observer instead. `Ok(())` means the set may be used.
pub fn check_validator_set_freshness(state_height: u64, ledger_height: u64) -> Result<(), String> {
    let max_lag = validator_set_freshness_max_lag();
    match check_validator_set_freshness_with_lag(state_height, ledger_height, max_lag) {
        Ok(()) => Ok(()),
        Err(reason) => {
            tracing::warn!("[validator-set] WARN {reason}");
            eprintln!("[validator-set] WARN {reason}");
            Err(reason)
        }
    }
}

/// Load the full node state (accounts + all domains). Returns the height and the
/// restored staking/governance ledgers, or None if nothing is stored.
///
/// The whole restore is first performed in a throwaway engine and its root is
/// verified against the finalized block at height+1 (see
/// `Storage::verify_restored_root`). Only on success is the live engine
/// touched. A mismatch therefore returns `Err` LOUDLY -- the corrupt state is
/// never installed -- while leaving both the live engine and the disk
/// untouched, so the operator can inspect, replace, or wipe the snapshot and
/// retry instead of being stranded on poisoned state (or on a wiped data
/// directory: nothing here deletes).
///
/// Verification is enforced when the domain snapshot is paired with the state
/// snapshot (same height) or when no domains are stored at all; a domain
/// snapshot from a different height is a partial write from a crash between
/// the two enqueues, and rejecting it would brick nodes for a pre-existing
/// crash-window quirk rather than for snapshot corruption.
pub async fn load_full_state_into(
    storage: &Storage,
    engine: &InMemoryStateEngine,
) -> Result<
    Option<(
        u64,
        crate::staking::StakingLedger,
        crate::governance::Governance,
    )>,
> {
    engine.attach_pq_tree(storage.pq_keys.clone());
    storage.hydrate_implicit_pq_keys()?;
    let paired_opt = storage.latest_paired_snapshot()?;
    let snap_v4_opt = storage.latest_snap_committed()?;
    if let Some(marker) = snap_v4_opt {
        if paired_opt
            .as_ref()
            .is_none_or(|(ph, _)| marker.height > *ph)
        {
            if let Some(snap_v4) = storage.load_snap_v4_state(marker.height).await? {
                let tmp = InMemoryStateEngine::new();
                tmp.attach_pq_tree(storage.pq_keys.clone());
                snap_v4
                    .apply_to_engine(&tmp)
                    .await
                    .map_err(|e| anyhow!("restore snap_v4 throwaway at {}: {e}", marker.height))?;
                storage.verify_restored_root(&tmp, marker.height).await?;
                let (staking, gov) = snap_v4
                    .apply_to_engine(engine)
                    .await
                    .map_err(|e| anyhow!("restore snap_v4 live at {}: {e}", marker.height))?;
                return Ok(Some((marker.height, staking, gov)));
            }
        }
    }
    // Take the newest height at which BOTH a state and a domains snapshot exist.
    // A crash between the two writes (they are separate enqueued jobs) can leave an
    // unpaired tail; loading state@H with domains@D!=H builds a frankestate no anchor
    // can validate. Pairing is the precondition for everything below.
    let Some((height, state_bytes)) = paired_opt else {
        // Distinguish "nothing stored" (genuine fresh start) from "snapshots exist
        // but none are paired" (a crash between the two snapshot jobs, or corruption).
        // The latter must NOT silently start fresh: finalized metadata may claim a
        // head whose state we cannot reconstruct, and starting from genesis while
        // believing we resumed would fork. Refuse loudly instead.
        if storage.latest_state()?.is_some() || storage.latest_domains()?.is_some() {
            return Err(anyhow!(
                "snapshots exist but no height holds both a state and a domains snapshot                  (crashed mid-snapshot or corrupt); wipe the data directory or restore a                  verified backup -- refusing to resume on half a snapshot"
            ));
        }
        return Ok(None);
    };
    let domains_opt: Option<Vec<u8>> = storage.domain_at(height)?;

    // Aux-domain blobs are read ONCE and shared by the verify (throwaway) and
    // commit (live) phases below. Both phases install byte-identical state, so
    // the second sled read was pure duplication: each read is a tree lookup
    // plus decompression plus a full copy, and on an active chain the
    // cross-shard replay set, the zkML model registry and the CN-VRF v3 chain
    // are megabytes. Read order is unchanged (same keys, same sequence).
    //
    // Residency: these are the AUX domains only (a small fraction of the state
    // snapshot that is held by `state_bytes` across both phases regardless), so
    // keeping them for the commit phase costs a few MB at most and removes the
    // duplicate I/O.
    let session_keys_opt: Option<Vec<u8>>;
    let bridge_opt: Option<Vec<u8>>;
    let zkml_opt: Option<Vec<u8>>;
    // Decoded ONCE as well: `restore_cross_shard_replay` /
    // `restore_cnvrf_v3_snapshot` take `&snap`, so the commit phase reuses the
    // verify phase's decoded value instead of paying a second bincode pass
    // over the same multi-MB bytes.
    let cross_shard_snap: Option<crate::sharding::CrossShardReplaySnapshot>;
    let cnvrf_snap: Option<crate::state_engine::CnVrfV3EngineSnapshot>;
    let evm_bindings_opt: Option<Vec<u8>>;
    let pq_registry_opt: Option<Vec<u8>>;

    // Phase 1 (throwaway): restore + verify without touching live state. The
    // verification is MANDATORY whenever an anchor exists: a snapshot labeled H whose
    // bytes decode to other state is exactly how a node starts on a fork while
    // believing it resumed (observed live: label 367, content of ~290).
    {
        let tmp = InMemoryStateEngine::new();
        tmp.attach_pq_tree(storage.pq_keys.clone());
        tmp.restore_snapshot_preserve_replay_sets(&state_bytes)
            .await
            .map_err(|e| anyhow!("restore state: {e}"))?;
        if let Some(bytes) = &domains_opt {
            let snap = decode_domain_snapshot(bytes)?;
            snap.apply(&tmp).await;
        }
        // Session-key registry of the SAME height, into the throwaway engine
        // too: it is part of the state root (conditional on being non-empty),
        // so verifying without it would reject every honest restore on a chain
        // that has ever registered a session key. Absent (pre-phase-2
        // directory) simply means "empty", which hashes to the same digest an
        // old node computed.
        session_keys_opt = storage.session_keys_at(height)?;
        if let Some(bytes) = &session_keys_opt {
            tmp.restore_session_keys(bytes)
                .await
                .map_err(|e| anyhow!("restore session keys: {e}"))?;
        }
        // Bridge domain of the SAME height, into the throwaway engine too: the
        // replay set and the withdrawal queue are part of the state root
        // (conditionally, on being non-empty), so verifying without it would
        // reject every honest restore on a chain that has ever bridged - and a
        // restore that quietly DROPPED it would re-root the chain while still
        // re-opening the source-tx replay. Absent (pre-bridge directory) simply
        // means "empty", which hashes to the digest an old node computed.
        bridge_opt = storage.bridge_at(height)?;
        if let Some(bytes) = &bridge_opt {
            tmp.restore_bridge(bytes)
                .await
                .map_err(|e| anyhow!("restore bridge domain: {e}"))?;
        }
        // Ristretto deletion wave: confidential ledger removed; no restore.
        zkml_opt = storage.zkml_models_at(height)?;
        if let Some(bytes) = &zkml_opt {
            tmp.restore_zkml_models(bytes)
                .await
                .map_err(|e| anyhow!("restore zkML models: {e}"))?;
        }
        let cross_shard_bytes = storage.cross_shard_at(height)?;
        cross_shard_snap = match &cross_shard_bytes {
            // The STORE tolerates the legacy shape (a snapshot persisted
            // before the 2PC records existed).
            Some(bytes) => Some(
                crate::sharding::with_legacy_block_tolerance(|| bincode::deserialize(bytes))
                    .map_err(|e| anyhow!("restore cross-shard replay: {e:?}"))?,
            ),
            None => None,
        };
        if let Some(snap) = &cross_shard_snap {
            // FULL replay install (audit F1): consumed halves + produced +
            // completed, extend-only. Restoring only `engine_consumed` here
            // used to drop the produced/completed halves on every restart:
            // the produced map gates timeout-bounce linkage and the completed
            // set gates ack/bounce completion, so a restarted node derived a
            // different root than its anchor (refused when an anchor exists)
            // or, at the tip with no anchor, silently re-opened lifecycles.
            tmp.restore_cross_shard_replay(snap).await;
        }
        let cnvrf_bytes = storage.cnvrf_v3_at(height)?;
        cnvrf_snap = match &cnvrf_bytes {
            Some(bytes) if !bytes.is_empty() => {
                Some(bincode::deserialize(bytes).map_err(|e| anyhow!("restore cnvrf_v3: {e}"))?)
            }
            _ => None,
        };
        if let Some(snap) = &cnvrf_snap {
            tmp.restore_cnvrf_v3_snapshot(snap).await;
        }
        evm_bindings_opt = storage.evm_bindings_state_at(height)?;
        if let Some(bytes) = &evm_bindings_opt {
            tmp.restore_evm_bindings(bytes)
                .await
                .map_err(|e| anyhow!("restore evm_bindings_state: {e}"))?;
        }
        pq_registry_opt = storage.pq_registry_at(height)?;
        if let Some(bytes) = &pq_registry_opt {
            let _pq_reg =
                decode_pq_registry(bytes).map_err(|e| anyhow!("restore pq_registry: {e}"))?;
            tmp.restore_pq_registry(bytes)
                .await
                .map_err(|e| anyhow!("restore pq_registry: {e}"))?;
        }
        storage.verify_restored_root(&tmp, height).await?;
    }

    // Phase 2 (commit): the snapshot is genuine; install it into the live engine.
    // Same blobs as phase 1, from the copies read there — no second sled read.
    engine
        .restore_snapshot_preserve_replay_sets(&state_bytes)
        .await
        .map_err(|e| anyhow!("restore state: {e}"))?;
    if let Some(bytes) = &session_keys_opt {
        engine
            .restore_session_keys(bytes)
            .await
            .map_err(|e| anyhow!("restore session keys: {e}"))?;
    }
    if let Some(bytes) = &bridge_opt {
        engine
            .restore_bridge(bytes)
            .await
            .map_err(|e| anyhow!("restore bridge domain: {e}"))?;
    }
    // Ristretto deletion wave: confidential ledger removed; no restore.
    if let Some(bytes) = &zkml_opt {
        engine
            .restore_zkml_models(bytes)
            .await
            .map_err(|e| anyhow!("restore zkML models: {e}"))?;
    }
    if let Some(snap) = &cross_shard_snap {
        // Same FULL install as the throwaway phase above: the two phases must
        // install byte-identical replay state, or the verified root would not
        // describe the live engine.
        engine.restore_cross_shard_replay(snap).await;
    }
    if let Some(snap) = &cnvrf_snap {
        engine.restore_cnvrf_v3_snapshot(snap).await;
    }
    if let Some(bytes) = &evm_bindings_opt {
        engine
            .restore_evm_bindings(bytes)
            .await
            .map_err(|e| anyhow!("restore evm_bindings_state: {e}"))?;
    }
    if let Some(bytes) = &pq_registry_opt {
        let _pq_reg = decode_pq_registry(bytes).map_err(|e| anyhow!("restore pq_registry: {e}"))?;
        engine
            .restore_pq_registry(bytes)
            .await
            .map_err(|e| anyhow!("restore pq_registry: {e}"))?;
    }
    match domains_opt {
        Some(bytes) => {
            let snap = decode_domain_snapshot(&bytes)?;
            let (staking, gov) = snap.apply(engine).await;
            Ok(Some((height, staking, gov)))
        }
        None => Ok(Some((
            height,
            crate::staking::StakingLedger::new(),
            crate::governance::Governance::new(),
        ))),
    }
}

/// Load a node's state from storage into a fresh engine, returning the height
/// it corresponds to. Falls back to an empty state if nothing is stored.
///
/// Like `fast_sync_state`, the snapshot is first restored into a throwaway
/// engine whose root must exactly match the finalized block at height+1 (see
/// `Storage::verify_restored_root`); only then is the live engine written. A
/// truncated, corrupt, or wrong-height snapshot returns `Err` and leaves the
/// engine untouched.
///
/// When a domain snapshot is paired with this state snapshot (same height) the
/// account-only root is only part of the committed state, so verification is
/// deferred to `load_full_state_into`, which checks the complete root after
/// the domains are applied.
/// TEST-ONLY legacy restore (audit 2026-10-06): restores state +
/// session-keys + bridge, omitting confidential/zkml/cross-shard — on a chain
/// with shielded/zkml activity the root check false-rejects. Live boot uses
/// `load_full_state_into` (paired snapshots); this exists for unit tests that
/// pin the legacy path. MUST NOT be wired into boot.
#[cfg(any(test, debug_assertions))]
pub async fn load_state_into(
    storage: &Storage,
    engine: &InMemoryStateEngine,
) -> Result<Option<u64>> {
    engine.attach_pq_tree(storage.pq_keys.clone());
    let _ = storage.hydrate_implicit_pq_keys();
    match storage.latest_state()? {
        Some((height, snap)) => {
            let tmp = InMemoryStateEngine::new();
            tmp.attach_pq_tree(storage.pq_keys.clone());
            tmp.restore_snapshot(&snap)
                .await
                .map_err(|e| anyhow!("restore state: {e}"))?;
            // The session-key registry AND the bridge domain are part of the
            // committed state, so both engines (the verifying throwaway and
            // the live one) get them - see `load_full_state_into` for why
            // absence simply means "empty".
            if let Some(bytes) = storage.session_keys_at(height)? {
                tmp.restore_session_keys(&bytes)
                    .await
                    .map_err(|e| anyhow!("restore session keys: {e}"))?;
            }
            if let Some(bytes) = storage.bridge_at(height)? {
                tmp.restore_bridge(&bytes)
                    .await
                    .map_err(|e| anyhow!("restore bridge domain: {e}"))?;
            }
            let domains_paired = matches!(storage.latest_domains()?, Some((dh, _)) if dh == height);
            if !domains_paired {
                storage.verify_restored_root(&tmp, height).await?;
            }
            engine
                .restore_snapshot(&snap)
                .await
                .map_err(|e| anyhow!("restore state: {e}"))?;
            if let Some(bytes) = storage.session_keys_at(height)? {
                engine
                    .restore_session_keys(&bytes)
                    .await
                    .map_err(|e| anyhow!("restore session keys: {e}"))?;
            }
            if let Some(bytes) = storage.bridge_at(height)? {
                engine
                    .restore_bridge(&bytes)
                    .await
                    .map_err(|e| anyhow!("restore bridge domain: {e}"))?;
            }
            Ok(Some(height))
        }
        None => Ok(None),
    }
}
