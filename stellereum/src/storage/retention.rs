use super::blocks::{
    decode_receipt, events_by_contract_key_parts, receipt_index_key, receipt_meta_v2_key,
    tx_by_addr_key_parts, StoredReceipt, RECEIPTS_BY_HEIGHT_READY_META_KEY, RECEIPT_INDEX_KEY_LEN,
};
use super::Storage;
use anyhow::Result;

/// Disk retention policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetentionConfig {
    /// Keep every block body forever. The default, because it is the only mode
    /// that allows re-executing a historical block for an audit.
    pub archive: bool,
    /// In prune mode, how many recent blocks keep their full body.
    pub keep_blocks: u64,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            archive: true,
            keep_blocks: 50_000,
        }
    }
}

impl RetentionConfig {
    /// Read the retention policy from the environment, with the same semantics
    /// the live node uses (`STELL_ARCHIVE`, `STELL_KEEP_BLOCKS`).
    ///
    /// `STELL_ARCHIVE=0/false` opts into pruning; anything else (including
    /// unset) is archive mode. `STELL_KEEP_BLOCKS=<n>` bounds the body window
    /// in prune mode (default 50 000).
    pub fn from_env() -> Self {
        let archive = std::env::var("STELL_ARCHIVE")
            .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true);
        let keep_blocks = std::env::var("STELL_KEEP_BLOCKS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(50_000);
        Self {
            archive,
            keep_blocks,
        }
    }

    /// Whether this node retains the data needed to serve per-key archive
    /// proofs for every snapshot height it ever takes.
    ///
    /// Archive mode never calls `prune_blocks_below` / `prune_state_below` /
    /// `prune_domains_below` (see the finalize path in `main.rs`), so every
    /// persisted snapshot stays servable. Prune mode keeps only the recent
    /// window (see the retention rule in the archive-proofs section below)
    /// and must refuse older heights honestly.
    pub fn keeps_snapshots_forever(&self) -> bool {
        self.archive
    }
}

/// Maximum blocks removed by one prune job.
///
/// The flusher task is a single writer, so a prune that scanned a multi-gigabyte
/// tree inline would stall every other write behind it. Work is bounded per job
/// and the next prune is scheduled from the regular snapshot cadence instead.
const PRUNE_BATCH: usize = 20_000;

impl Storage {
    /// Prune stored header records (both legacy `headers` and `headers_v2`)
    /// below `keep_from`, always retaining the highest header for bootability.
    pub fn prune_headers_below(&self, keep_from: u64) -> Result<usize> {
        let mut max_v1: Option<u64> = None;
        for res in self.headers.iter().keys() {
            let k = res?;
            if k.len() == 8 {
                let h = u64::from_be_bytes(k.as_ref().try_into().unwrap());
                max_v1 = Some(max_v1.map_or(h, |m| m.max(h)));
            }
        }
        let mut max_v2: Option<u64> = None;
        for res in self.headers_v2.iter().keys() {
            let k = res?;
            if k.len() == 8 {
                let h = u64::from_be_bytes(k.as_ref().try_into().unwrap());
                max_v2 = Some(max_v2.map_or(h, |m| m.max(h)));
            }
        }
        let max_h = match (max_v1, max_v2) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        let mut removed = 0usize;
        let mut v1_keys: Vec<sled::IVec> = Vec::new();
        for res in self.headers.iter().keys() {
            let k = res?;
            if k.len() == 8 {
                let h = u64::from_be_bytes(k.as_ref().try_into().unwrap());
                if h < keep_from && Some(h) != max_h {
                    v1_keys.push(k);
                }
            }
        }
        for k in v1_keys {
            self.headers.remove(k)?;
            removed += 1;
        }
        let mut v2_keys: Vec<sled::IVec> = Vec::new();
        for res in self.headers_v2.iter().keys() {
            let k = res?;
            if k.len() == 8 {
                let h = u64::from_be_bytes(k.as_ref().try_into().unwrap());
                if h < keep_from && Some(h) != max_h {
                    v2_keys.push(k);
                }
            }
        }
        for k in v2_keys {
            self.headers_v2.remove(k)?;
            removed += 1;
        }
        Ok(removed)
    }

    /// Drop receipts below the retention window (audit 2026-10-06: the tree
    /// grew forever — one entry per tx, no prune path). Scans the height-ordered
    /// `receipts_by_height` index in bounded batches (no bincode decoding of
    /// receipt bodies) and deletes `receipts_by_height`, `receipt_meta_v2`, and
    /// `receipts`. Wallet receipts older than the window read as "unknown"
    /// (same honest answer as an evicted in-memory receipt).
    pub fn prune_receipts_below(&self, keep_from: u64) -> Result<usize> {
        let mut removed = 0usize;
        if keep_from > 0 {
            let end = keep_from.to_be_bytes();
            loop {
                let mut stale: Vec<(sled::IVec, [u8; 32])> = Vec::new();
                for kv in self.receipts_by_height.range(..end.as_slice()) {
                    let (k, _) = kv?;
                    if k.len() != RECEIPT_INDEX_KEY_LEN {
                        continue;
                    }
                    let h = u64::from_be_bytes(k[0..8].try_into().unwrap());
                    if h >= keep_from {
                        break;
                    }
                    let mut tx_hash = [0u8; 32];
                    tx_hash.copy_from_slice(&k[12..RECEIPT_INDEX_KEY_LEN]);
                    stale.push((k, tx_hash));
                    if stale.len() >= PRUNE_BATCH {
                        break;
                    }
                }
                if stale.is_empty() {
                    break;
                }
                let mut index_rows = sled::Batch::default();
                let mut meta_rows = sled::Batch::default();
                let mut bodies = sled::Batch::default();
                for (k, tx_hash) in &stale {
                    index_rows.remove(k);
                    meta_rows.remove(&receipt_meta_v2_key(tx_hash)[..]);
                    bodies.remove(&tx_hash[..]);
                }
                self.receipts_by_height.apply_batch(index_rows)?;
                self.receipt_meta_v2.apply_batch(meta_rows)?;
                self.receipts.apply_batch(bodies)?;
                removed += stale.len();
                if removed >= PRUNE_BATCH * 4 {
                    break; // one pass drains 80k; the rest next cadence
                }
            }

            // Crash-recovery / pre-upgrade fallback: if a prior mid-prune crash
            // removed `receipts_by_height` rows without removing `receipts`,
            // or the height index is incomplete, sweep any orphaned bodies.
            // In steady state (`index_ready && receipts.len() <= receipts_by_height.len()`)
            // this branch is skipped completely (zero full-tree scans).
            let index_ready = self.meta.get(RECEIPTS_BY_HEIGHT_READY_META_KEY)?.is_some();
            if removed < PRUNE_BATCH * 4
                && (!index_ready || self.receipts.len() > self.receipts_by_height.len())
            {
                loop {
                    let budget = (PRUNE_BATCH * 4 - removed).min(PRUNE_BATCH);
                    if budget == 0 {
                        break;
                    }
                    let mut stale: Vec<(sled::IVec, StoredReceipt)> = Vec::new();
                    for kv in self.receipts.iter() {
                        let (k, v) = kv?;
                        if let Ok(r) = decode_receipt(&v) {
                            if r.height < keep_from {
                                stale.push((k, r));
                                if stale.len() >= budget {
                                    break;
                                }
                            }
                        }
                    }
                    if stale.is_empty() {
                        break;
                    }
                    let mut index_rows = sled::Batch::default();
                    let mut meta_rows = sled::Batch::default();
                    let mut bodies = sled::Batch::default();
                    for (k, r) in &stale {
                        index_rows.remove(&receipt_index_key(r)[..]);
                        meta_rows.remove(&receipt_meta_v2_key(&r.tx_hash)[..]);
                        bodies.remove(k);
                    }
                    self.receipts_by_height.apply_batch(index_rows)?;
                    self.receipt_meta_v2.apply_batch(meta_rows)?;
                    self.receipts.apply_batch(bodies)?;
                    removed += stale.len();
                    if removed >= PRUNE_BATCH * 4 {
                        break;
                    }
                }
            }
        }
        // The address/event indexes encode the height IN THE KEY, so they are
        // pruned by a bounded height scan (filter-then-take, never a prefix:
        // the key starts with the address/contract, not the height).
        self.prune_history_below(keep_from)?;
        Ok(removed)
    }

    /// Drop `tx_by_addr` / `events_by_contract` rows below `keep_from`.
    ///
    /// Bounded by [`PRUNE_BATCH`] per tree per call, matching the receipt and
    /// body prunes: the flusher is the only writer, so one giant inline scan
    /// would stall every other write. Rows whose key cannot be decoded are
    /// left untouched (never deleted blind).
    fn prune_history_below(&self, keep_from: u64) -> Result<usize> {
        let mut removed = 0;
        let stale_addr: Vec<sled::IVec> = self
            .tx_by_addr
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| {
                tx_by_addr_key_parts(k)
                    .map(|(_, height, _)| height < keep_from)
                    .unwrap_or(false)
            })
            .take(PRUNE_BATCH)
            .collect();
        for k in stale_addr {
            if self.tx_by_addr.remove(k)?.is_some() {
                removed += 1;
            }
        }
        let stale_events: Vec<sled::IVec> = self
            .events_by_contract
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| {
                events_by_contract_key_parts(k)
                    .map(|(_, height, _, _)| height < keep_from)
                    .unwrap_or(false)
            })
            .take(PRUNE_BATCH)
            .collect();
        for k in stale_events {
            if self.events_by_contract.remove(k)?.is_some() {
                removed += 1;
            }
        }
        Ok(removed)
    }

    // ---------- Retention ----------

    /// Whether a block body at `height` may be removed given a cursor.
    ///
    /// The boundary rule is the whole point: a block may go only if its child
    /// stays, otherwise the retained suffix no longer links back to genesis and
    /// the chain cannot be walked at all.
    ///
    /// `prune_blocks_below` and `has_blocks_below` share this so they cannot
    /// disagree. They did once: the predicate ignored the boundary, so a caller
    /// asking "is there more to do" was told yes forever by blocks that were
    /// deliberately being kept, and the prune loop never terminated.
    fn body_is_removable(height: u64, keep_from: u64) -> bool {
        height.saturating_add(1) < keep_from
    }

    /// Delete block bodies below `keep_from`, keeping their header records.
    ///
    /// Returns how many bodies were removed. Bounded by `PRUNE_BATCH` per call
    /// because the flusher task is the only writer and an unbounded scan would
    /// stall every other write behind it.
    pub fn prune_blocks_below(&self, keep_from: u64) -> Result<usize> {
        let mut entries: Vec<(sled::IVec, sled::IVec)> = Vec::new();
        for kv in self.by_height.iter() {
            let (hk, hash) = kv?;
            if hk.len() != 40 {
                continue;
            }
            let h = u64::from_be_bytes(hk[0..8].try_into().unwrap());
            if !Self::body_is_removable(h, keep_from) {
                break;
            }
            entries.push((hk, hash));
            if entries.len() >= PRUNE_BATCH {
                break;
            }
        }
        let mut removed = 0;
        for (hk, hash) in entries {
            // Remove the body before the height index so a crash never leaves
            // an unreachable orphan body; `sweep_dangling_indexes` (at open)
            // and subsequent prunes clean up any remaining dangling `by_height` row.
            self.blocks.remove(&hash)?;
            self.by_height.remove(&hk)?;
            removed += 1;
        }
        Ok(removed)
    }

    /// True when another prune pass would remove something.
    pub fn has_blocks_below(&self, keep_from: u64) -> Result<bool> {
        for k in self.by_height.iter().keys().filter_map(|k| k.ok()) {
            if k.len() == 40 {
                let h = u64::from_be_bytes(k[0..8].try_into().unwrap());
                if Self::body_is_removable(h, keep_from) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Total live entries across the block trees, for metrics and warnings.
    ///
    /// sled 0.34 does not expose a per-tree `size_on_disk`, so this counts keys
    /// rather than bytes. It answers "is the store growing without bound", which
    /// is the question a retention policy has to be able to answer.
    pub fn stored_block_entries(&self) -> usize {
        self.blocks.len() + self.by_height.len()
    }

    /// Highest height present in BOTH `state` and `domains`.
    fn max_paired_snapshot_height(&self) -> Option<u64> {
        let state_heights: std::collections::BTreeSet<u64> = self
            .state
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| k.len() == 8)
            .map(|k| u64::from_be_bytes(k.as_ref().try_into().unwrap()))
            .collect();
        self.domains
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| k.len() == 8)
            .map(|k| u64::from_be_bytes(k.as_ref().try_into().unwrap()))
            .filter(|h| state_heights.contains(h))
            .max()
    }

    /// Drop state snapshots older than `keep_from` (retain the last few for reorgs).
    /// Never drops the latest snapshot (`max_h`) or the newest paired
    /// `(state ∩ domains)` height (`max_paired`) so `state@H` is never deleted
    /// while `domains@(H+interval)` has not landed yet.
    pub fn prune_state_below(&self, keep_from: u64) -> Result<usize> {
        let max_paired = self.max_paired_snapshot_height();
        let max_h = self
            .state
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| k.len() == 8)
            .map(|k| u64::from_be_bytes(k.as_ref().try_into().unwrap()))
            .max();
        let mut removed = 0;
        let keys: Vec<sled::IVec> = self
            .state
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| {
                if k.len() != 8 {
                    return false;
                }
                let h = u64::from_be_bytes(k.as_ref().try_into().unwrap());
                h < keep_from && Some(h) != max_h && Some(h) != max_paired
            })
            .collect();
        for k in keys {
            self.state.remove(k)?;
            removed += 1;
        }
        Ok(removed)
    }

    // ---------- Domain snapshots (tokens/contracts/orderbooks/PMM/staking/gov) ----------

    /// Drop domain snapshots older than `keep_from`.
    /// Never drops the latest snapshot (`max_h`) or the newest paired
    /// `(state ∩ domains)` height (`max_paired`) to preserve bootability.
    pub fn prune_domains_below(&self, keep_from: u64) -> Result<usize> {
        let max_paired = self.max_paired_snapshot_height();
        let max_h = self
            .domains
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| k.len() == 8)
            .map(|k| u64::from_be_bytes(k.as_ref().try_into().unwrap()))
            .max();
        let mut removed = 0;
        let keys: Vec<sled::IVec> = self
            .domains
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| {
                if k.len() != 8 {
                    return false;
                }
                let h = u64::from_be_bytes(k.as_ref().try_into().unwrap());
                h < keep_from && Some(h) != max_h && Some(h) != max_paired
            })
            .collect();
        for k in keys {
            self.domains.remove(k)?;
            removed += 1;
        }
        let retained = self.aux_retained_heights();
        self.prune_session_keys_below_with_retained(keep_from, &retained)?;
        self.prune_bridge_below_with_retained(keep_from, &retained)?;
        self.prune_zkml_models_below_with_retained(keep_from, &retained)?;
        self.prune_cross_shard_below_with_retained(keep_from, &retained)?;
        self.prune_cnvrf_v3_below_with_retained(keep_from, &retained)?;
        self.prune_cnvrf_freeze_inputs_below_with_retained(keep_from, &retained)?;
        self.prune_evm_bindings_state_below_with_retained(keep_from, &retained)?;
        self.prune_pq_registry_below_with_retained(keep_from, &retained)?;
        self.prune_evm_settled_state_below_with_retained(keep_from, &retained)?;
        Ok(removed)
    }

    /// Heights whose auxiliary domain snapshots must survive any prune:
    /// every height holding a state or a domains snapshot. The loader only
    /// ever reads an aux blob at a height it also reads state+domains from
    /// (`load_full_state_into` at the paired height, `rebuild_historical_trie`
    /// at the proven height), so an aux row is live exactly when its height
    /// is snapshotted — and deleting the aux row of a retained snapshot
    /// height strands that height (the restored root no longer matches, or a
    /// committed replay set is silently dropped). State/domains preserve their
    /// own newest entry; the aux trees preserve every snapshotted height, and
    /// only prune rows no snapshot height needs.
    fn aux_retained_heights(&self) -> std::collections::BTreeSet<u64> {
        let mut keep = std::collections::BTreeSet::new();
        for tree in [&self.state, &self.domains] {
            for k in tree.iter().keys().filter_map(|k| k.ok()) {
                if k.len() == 8 {
                    keep.insert(u64::from_be_bytes(k.as_ref().try_into().unwrap()));
                }
            }
        }
        keep
    }

    fn prune_aux_tree_below(
        tree: &sled::Tree,
        keep_from: u64,
        retained: &std::collections::BTreeSet<u64>,
    ) -> Result<usize> {
        let mut removed = 0;
        let mut keys: Vec<sled::IVec> = Vec::new();
        for res in tree.iter().keys() {
            let k = res?;
            if k.len() == 8 {
                let h = u64::from_be_bytes(k.as_ref().try_into().unwrap());
                if h < keep_from && !retained.contains(&h) {
                    keys.push(k);
                }
            }
        }
        for k in keys {
            tree.remove(k)?;
            removed += 1;
        }
        Ok(removed)
    }

    fn prune_session_keys_below_with_retained(
        &self,
        keep_from: u64,
        retained: &std::collections::BTreeSet<u64>,
    ) -> Result<usize> {
        Self::prune_aux_tree_below(&self.session_keys, keep_from, retained)
    }

    /// Drop session-key snapshots older than `keep_from`. Called from
    /// `prune_domains_below` so the third tree follows the same window. Never
    /// drops a row at a snapshotted height (see [`Self::aux_retained_heights`]):
    /// state/domains preserve their newest entry so a node always stays
    /// bootable, and the aux trees must keep the rows those heights restore
    /// with — deleting the newest aux blob while state/domains keep theirs
    /// would strand the retained height behind a root mismatch.
    pub fn prune_session_keys_below(&self, keep_from: u64) -> Result<usize> {
        let retained = self.aux_retained_heights();
        self.prune_session_keys_below_with_retained(keep_from, &retained)
    }

    // ---------- Bridge domain snapshots (the §8 replay set / queue) ----------

    fn prune_bridge_below_with_retained(
        &self,
        keep_from: u64,
        retained: &std::collections::BTreeSet<u64>,
    ) -> Result<usize> {
        Self::prune_aux_tree_below(&self.bridge, keep_from, retained)
    }

    /// Drop bridge snapshots older than `keep_from`. Called from
    /// `prune_domains_below` so this tree follows the same window. Never
    /// drops a row at a snapshotted height: see [`Self::aux_retained_heights`].
    pub fn prune_bridge_below(&self, keep_from: u64) -> Result<usize> {
        let retained = self.aux_retained_heights();
        self.prune_bridge_below_with_retained(keep_from, &retained)
    }

    // ---------- zkML model registry snapshots (audit F-B) ----------

    fn prune_zkml_models_below_with_retained(
        &self,
        keep_from: u64,
        retained: &std::collections::BTreeSet<u64>,
    ) -> Result<usize> {
        Self::prune_aux_tree_below(&self.zkml_models, keep_from, retained)
    }

    /// Drop registry snapshots older than `keep_from`. Called from
    /// `prune_domains_below` so this tree follows the same window. Never
    /// drops a row at a snapshotted height: see [`Self::aux_retained_heights`].
    pub fn prune_zkml_models_below(&self, keep_from: u64) -> Result<usize> {
        let retained = self.aux_retained_heights();
        self.prune_zkml_models_below_with_retained(keep_from, &retained)
    }

    // ---------- Cross-shard replay snapshots (audit F-I) ----------

    fn prune_cross_shard_below_with_retained(
        &self,
        keep_from: u64,
        retained: &std::collections::BTreeSet<u64>,
    ) -> Result<usize> {
        Self::prune_aux_tree_below(&self.cross_shard, keep_from, retained)
    }

    /// Drop replay snapshots older than `keep_from`. Called from
    /// `prune_domains_below` so this tree follows the same window. Never
    /// drops a row at a snapshotted height (see [`Self::aux_retained_heights`]):
    /// deleting the replay blob of a retained paired height would leave a
    /// bootable-looking snapshot whose restore roots differently (or silently
    /// re-opens consumed inbounds) — a self-inflicted refusal at best, a
    /// double-mint at worst.
    pub fn prune_cross_shard_below(&self, keep_from: u64) -> Result<usize> {
        let retained = self.aux_retained_heights();
        self.prune_cross_shard_below_with_retained(keep_from, &retained)
    }

    // ---------- CN-VRF v3 domain snapshots ----------

    fn prune_cnvrf_v3_below_with_retained(
        &self,
        keep_from: u64,
        retained: &std::collections::BTreeSet<u64>,
    ) -> Result<usize> {
        Self::prune_aux_tree_below(&self.cnvrf_v3, keep_from, retained)
    }

    /// Drop CN-VRF v3 snapshots older than `keep_from`. Called from
    /// `prune_domains_below` so this tree follows the same window. Never drops
    /// a row at a snapshotted height: see [`Self::aux_retained_heights`].
    pub fn prune_cnvrf_v3_below(&self, keep_from: u64) -> Result<usize> {
        let retained = self.aux_retained_heights();
        self.prune_cnvrf_v3_below_with_retained(keep_from, &retained)
    }

    fn prune_cnvrf_freeze_inputs_below_with_retained(
        &self,
        keep_from: u64,
        retained: &std::collections::BTreeSet<u64>,
    ) -> Result<usize> {
        Self::prune_aux_tree_below(&self.cnvrf_freeze_inputs, keep_from, retained)
    }

    /// Drop `cnvrf_freeze_inputs` snapshots older than `keep_from`. Called from
    /// `prune_domains_below`. Never drops a row at a retained snapshot height:
    /// see [`Self::aux_retained_heights`].
    pub fn prune_cnvrf_freeze_inputs_below(&self, keep_from: u64) -> Result<usize> {
        let retained = self.aux_retained_heights();
        self.prune_cnvrf_freeze_inputs_below_with_retained(keep_from, &retained)
    }

    fn prune_evm_bindings_state_below_with_retained(
        &self,
        keep_from: u64,
        retained: &std::collections::BTreeSet<u64>,
    ) -> Result<usize> {
        Self::prune_aux_tree_below(&self.evm_bindings_state, keep_from, retained)
    }

    /// Drop `evm_bindings_state` snapshots older than `keep_from`. Called from
    /// `prune_domains_below`. Never drops a row at a retained snapshot height:
    /// see [`Self::aux_retained_heights`].
    pub fn prune_evm_bindings_state_below(&self, keep_from: u64) -> Result<usize> {
        let retained = self.aux_retained_heights();
        self.prune_evm_bindings_state_below_with_retained(keep_from, &retained)
    }

    fn prune_pq_registry_below_with_retained(
        &self,
        keep_from: u64,
        retained: &std::collections::BTreeSet<u64>,
    ) -> Result<usize> {
        Self::prune_aux_tree_below(&self.pq_registry, keep_from, retained)
    }

    /// Drop `pq_registry` snapshots older than `keep_from`. Called from
    /// `prune_domains_below`. Never drops a row at a retained snapshot height:
    /// see [`Self::aux_retained_heights`].
    pub fn prune_pq_registry_below(&self, keep_from: u64) -> Result<usize> {
        let retained = self.aux_retained_heights();
        self.prune_pq_registry_below_with_retained(keep_from, &retained)
    }

    fn prune_evm_settled_state_below_with_retained(
        &self,
        keep_from: u64,
        retained: &std::collections::BTreeSet<u64>,
    ) -> Result<usize> {
        Self::prune_aux_tree_below(&self.evm_settled_state, keep_from, retained)
    }

    /// Drop `evm_settled_state` snapshots older than `keep_from`. Called from
    /// `prune_domains_below`. Never drops a row at a retained snapshot height:
    /// see [`Self::aux_retained_heights`].
    pub fn prune_evm_settled_state_below(&self, keep_from: u64) -> Result<usize> {
        let retained = self.aux_retained_heights();
        self.prune_evm_settled_state_below_with_retained(keep_from, &retained)
    }

    /// Prune old `SnapV4` committed checkpoints, manifests, and unreferenced
    /// content-addressed units below `keep_from`, keeping the newest committed
    /// checkpoint and any `Base`/intermediate deltas it depends on.
    ///
    /// Never touches `safety_record_v1`, `meta["consensus"]`, or `meta["vote_watermark"]`.
    pub fn prune_deltas_below(&self, keep_from: u64) -> Result<usize> {
        use crate::snapshot_v4::{decode_manifest_strict, SnapshotKind, UNIT_ENC_UNCHANGED};
        use std::collections::{BTreeMap, BTreeSet};

        let mut committed_heights = BTreeSet::new();
        for kv in self.snap_committed.iter().keys() {
            let k = kv?;
            if k.len() == 8 {
                committed_heights.insert(u64::from_be_bytes(k.as_ref().try_into().unwrap()));
            }
        }

        let mut retain: BTreeSet<u64> = BTreeSet::new();
        let mut manifests: BTreeMap<u64, crate::snapshot_v4::SnapshotManifestV1> = BTreeMap::new();
        if !committed_heights.is_empty() {
            let max_h = committed_heights.iter().copied().max();
            for kv in self.snap_manifests.iter() {
                let (k, v) = kv?;
                if k.len() == 8 {
                    let h = u64::from_be_bytes(k.as_ref().try_into().unwrap());
                    if let Ok(m) = decode_manifest_strict(&v) {
                        manifests.insert(h, m);
                    }
                }
            }

            for &h in &committed_heights {
                if h >= keep_from || Some(h) == max_h {
                    retain.insert(h);
                }
            }
            // Transitive dependency closure: any retained Delta must retain its Base chain.
            let mut work: Vec<u64> = retain.iter().copied().collect();
            while let Some(h) = work.pop() {
                if let Some(m) = manifests.get(&h) {
                    if let SnapshotKind::Delta { base_height, .. } = m.kind {
                        if retain.insert(base_height) {
                            work.push(base_height);
                        }
                    }
                }
            }
        }

        // Prune stale `snap_staging` keys (`height(8B BE)||unit_tag(2B BE)||sub_index(2B BE)`)
        // whose encoded height `< keep_from` (and not a retained checkpoint).
        if keep_from > 0 {
            let end = keep_from.to_be_bytes();
            let mut stale_staging: Vec<sled::IVec> = Vec::new();
            for kv in self.snap_staging.range(..end.as_slice()).keys() {
                let k = kv?;
                if k.len() >= 8 {
                    let h = u64::from_be_bytes(k[0..8].try_into().unwrap());
                    if h < keep_from && !retain.contains(&h) {
                        stale_staging.push(k);
                    }
                }
            }
            for k in stale_staging {
                self.snap_staging.remove(k)?;
            }
        }

        if committed_heights.is_empty() {
            return Ok(0);
        }

        let mut removed = 0usize;
        for &h in &committed_heights {
            if !retain.contains(&h) {
                self.snap_committed.remove(h.to_be_bytes())?;
                removed += 1;
            }
        }
        for &h in manifests.keys() {
            if !retain.contains(&h) {
                self.snap_manifests.remove(h.to_be_bytes())?;
            }
        }
        let mut live_hashes: BTreeSet<[u8; 32]> = BTreeSet::new();
        for h in &retain {
            if let Some(m) = manifests.get(h) {
                for d in &m.units {
                    if d.encoding != UNIT_ENC_UNCHANGED {
                        live_hashes.insert(d.chunk_hash);
                    }
                }
            }
        }
        let mut dead_units: Vec<sled::IVec> = Vec::new();
        for kv in self.snap_units.iter().keys() {
            let k = kv?;
            if k.len() != 32 {
                dead_units.push(k);
                continue;
            }
            let mut h = [0u8; 32];
            h.copy_from_slice(&k);
            if !live_hashes.contains(&h) {
                dead_units.push(k);
            }
        }
        for k in dead_units {
            self.snap_units.remove(k)?;
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sharding::Transaction;
    use ed25519_dalek::SigningKey;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "stell_retention_unit_{tag}_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn prune_receipts_below_uses_receipts_by_height_index() {
        let dir = tmpdir("receipts_idx");
        let st = Storage::open(&dir).expect("open storage");

        let kp = SigningKey::from_bytes(&[0x22u8; 32]);
        let mut tx_hashes = Vec::new();
        for h in 1..=10u64 {
            let tx = Transaction::sign(&kp, [0x44u8; 32], 10, 100, h, 0, 0);
            let bh = [h as u8; 32];
            tx_hashes.push((h, tx.compute_tx_hash()));
            st.put_receipts_for_block(h, &bh, &[tx], &[true], &[50])
                .expect("put_receipts_for_block");
        }

        // Overwrite receipt body at h=2 with non-bincode bytes: a height-index
        // scan removes `receipts_by_height`, `receipt_meta_v2`, AND `receipts`
        // without trying to decode the body.
        let h2_hash = tx_hashes[1].1;
        st.receipts_tree_for_test()
            .insert(h2_hash, b"not-valid-bincode")
            .expect("overwrite body");

        let removed = st.prune_receipts_below(6).expect("prune_receipts_below");
        assert_eq!(removed, 5);
        assert_eq!(st.receipt_count().unwrap(), 5);
        assert_eq!(st.receipts_by_height_tree_for_test().len(), 5);
        assert!(st.receipts_tree_for_test().get(h2_hash).unwrap().is_none());

        for (h, hash) in &tx_hashes {
            if *h < 6 {
                assert!(st.get_receipt(hash).unwrap().is_none());
                assert!(st.receipt_meta(hash).unwrap().is_none());
            } else {
                assert!(st.get_receipt(hash).unwrap().is_some());
                assert!(st.receipt_meta(hash).unwrap().is_some());
            }
        }

        drop(st);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prune_deltas_below_cleans_stale_snap_staging() {
        use crate::snapshot_v4::{
            encode_manifest_strict, SnapshotKind, SnapshotManifestV1, SNAP_MANIFEST_MAGIC,
            SNAP_MANIFEST_VERSION,
        };

        let dir = tmpdir("snap_staging");
        let st = Storage::open(&dir).expect("open storage");

        // 1. Even with no committed checkpoints, stale snap_staging < keep_from is pruned.
        st.put_snap_staging_chunk(5, 1, 0, b"stale-5").unwrap();
        st.put_snap_staging_chunk(10, 1, 0, b"stale-10").unwrap();
        st.put_snap_staging_chunk(20, 1, 0, b"live-20").unwrap();
        assert_eq!(st.prune_deltas_below(15).unwrap(), 0);
        assert!(st.snap_staging_chunk(5, 1, 0).unwrap().is_none());
        assert!(st.snap_staging_chunk(10, 1, 0).unwrap().is_none());
        assert_eq!(
            st.snap_staging_chunk(20, 1, 0).unwrap(),
            Some(b"live-20".to_vec())
        );

        // 2. With committed Base@12 and Delta@18, stale staging at 11 and 14
        //    (< keep_from=15) are pruned while staging at 25 and committed 12/18 survive.
        let m12 = SnapshotManifestV1 {
            magic: SNAP_MANIFEST_MAGIC,
            version: SNAP_MANIFEST_VERSION,
            chain_id: 1,
            shard_id: 0,
            kind: SnapshotKind::Base,
            target_height: 12,
            target_block_hash: [0xAAu8; 32],
            target_state_root: [0x12u8; 32],
            validator_set_hash: [0u8; 32],
            total_wire_bytes: 0,
            total_uncompressed_bytes: 0,
            units_merkle_root: [0u8; 32],
            units: vec![],
            publisher_id: [0u8; 32],
            publisher_sig: vec![],
        };
        let m18 = SnapshotManifestV1 {
            magic: SNAP_MANIFEST_MAGIC,
            version: SNAP_MANIFEST_VERSION,
            chain_id: 1,
            shard_id: 0,
            kind: SnapshotKind::Delta {
                base_height: 12,
                base_state_root: [0x12u8; 32],
            },
            target_height: 18,
            target_block_hash: [0xBBu8; 32],
            target_state_root: [0x18u8; 32],
            validator_set_hash: [0u8; 32],
            total_wire_bytes: 0,
            total_uncompressed_bytes: 0,
            units_merkle_root: [0u8; 32],
            units: vec![],
            publisher_id: [0u8; 32],
            publisher_sig: vec![],
        };
        st.commit_snap_v4(
            &crate::storage::SnapCommitMarker {
                height: 12,
                state_root: [0x12u8; 32],
                block_hash: [0xAAu8; 32],
                is_base: true,
                base_height: None,
            },
            &encode_manifest_strict(&m12).unwrap(),
            &[],
        )
        .unwrap();
        st.commit_snap_v4(
            &crate::storage::SnapCommitMarker {
                height: 18,
                state_root: [0x18u8; 32],
                block_hash: [0xBBu8; 32],
                is_base: false,
                base_height: Some(12),
            },
            &encode_manifest_strict(&m18).unwrap(),
            &[],
        )
        .unwrap();

        st.put_snap_staging_chunk(11, 2, 0, b"stale-11").unwrap();
        st.put_snap_staging_chunk(14, 2, 1, b"stale-14").unwrap();
        st.put_snap_staging_chunk(25, 2, 0, b"live-25").unwrap();

        assert_eq!(st.prune_deltas_below(15).unwrap(), 0);
        assert!(st.snap_staging_chunk(11, 2, 0).unwrap().is_none());
        assert!(st.snap_staging_chunk(14, 2, 1).unwrap().is_none());
        assert_eq!(
            st.snap_staging_chunk(25, 2, 0).unwrap(),
            Some(b"live-25".to_vec())
        );
        assert!(st.snap_committed_at(12).unwrap().is_some());
        assert!(st.snap_committed_at(18).unwrap().is_some());

        drop(st);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
