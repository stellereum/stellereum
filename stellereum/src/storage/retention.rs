use super::blocks::{
    decode_receipt, events_by_contract_key_parts, receipt_index_key, receipt_meta_v2_key,
    tx_by_addr_key_parts, StoredReceipt,
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
        let max_v1 = self
            .headers
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| k.len() == 8)
            .map(|k| u64::from_be_bytes(k.as_ref().try_into().unwrap()))
            .max();
        let max_v2 = self
            .headers_v2
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| k.len() == 8)
            .map(|k| u64::from_be_bytes(k.as_ref().try_into().unwrap()))
            .max();
        let max_h = match (max_v1, max_v2) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        let mut removed = 0usize;
        let v1_keys: Vec<sled::IVec> = self
            .headers
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| {
                if k.len() != 8 {
                    return false;
                }
                let h = u64::from_be_bytes(k.as_ref().try_into().unwrap());
                h < keep_from && Some(h) != max_h
            })
            .collect();
        for k in v1_keys {
            self.headers.remove(k)?;
            removed += 1;
        }
        let v2_keys: Vec<sled::IVec> = self
            .headers_v2
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| {
                if k.len() != 8 {
                    return false;
                }
                let h = u64::from_be_bytes(k.as_ref().try_into().unwrap());
                h < keep_from && Some(h) != max_h
            })
            .collect();
        for k in v2_keys {
            self.headers_v2.remove(k)?;
            removed += 1;
        }
        Ok(removed)
    }

    /// Drop receipts below the retention window (audit 2026-10-06: the tree
    /// grew forever — one entry per tx, no prune path). Keyed by tx hash, so
    /// this scans values in batches; bounded by PRUNE_BATCH per call like the
    /// body prune. Wallet receipts older than the window read as "unknown"
    /// (same honest answer as an evicted in-memory receipt).
    pub fn prune_receipts_below(&self, keep_from: u64) -> Result<usize> {
        // Filter FIRST, take after (audit follow-up): iteration is tx-hash
        // order (random vs height), so take-first grabbed an arbitrary prefix
        // and could delete 0 forever while stale entries sat beyond it.
        // Scan in bounded chunks to avoid one giant pass on huge trees.
        // The tip-ordered index row of every removed receipt goes in the same
        // chunk (per-tree atomic batches), so the index cannot grow forever.
        let mut removed = 0;
        loop {
            let stale: Vec<(sled::IVec, StoredReceipt)> = self
                .receipts
                .iter()
                .filter_map(|kv| kv.ok())
                .filter_map(|(k, v)| {
                    let r: StoredReceipt = decode_receipt(&v).ok()?;
                    (r.height < keep_from).then_some((k, r))
                })
                .take(PRUNE_BATCH)
                .collect();
            if stale.is_empty() {
                break;
            }
            let mut bodies = sled::Batch::default();
            let mut index_rows = sled::Batch::default();
            let mut meta_rows = sled::Batch::default();
            for (k, r) in &stale {
                bodies.remove(k);
                index_rows.remove(&receipt_index_key(r)[..]);
                // `receipt_meta_v2` is keyed by the SAME tx hash, so the meta
                // row is removed in this pass instead of growing a separate
                // forever-tree.
                meta_rows.remove(&receipt_meta_v2_key(&r.tx_hash)[..]);
            }
            self.receipts_by_height.apply_batch(index_rows)?;
            self.receipt_meta_v2.apply_batch(meta_rows)?;
            self.receipts.apply_batch(bodies)?;
            removed += stale.len();
            if removed >= PRUNE_BATCH * 4 {
                break; // one pass drains 80k; the rest next cadence
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
        let mut removed = 0;
        let keys: Vec<sled::IVec> = self
            .by_height
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .take(PRUNE_BATCH)
            .filter(|k| k.len() == 40)
            .filter(|k| {
                let h = u64::from_be_bytes(k[0..8].try_into().unwrap());
                Self::body_is_removable(h, keep_from)
            })
            .collect();
        for hk in keys {
            if let Some(hash) = self.by_height.remove(&hk)? {
                self.blocks.remove(hash)?;
            }
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
        self.prune_session_keys_below(keep_from)?;
        self.prune_bridge_below(keep_from)?;
        self.prune_zkml_models_below(keep_from)?;
        self.prune_cross_shard_below(keep_from)?;
        self.prune_cnvrf_v3_below(keep_from)?;
        self.prune_cnvrf_freeze_inputs_below(keep_from)?;
        self.prune_evm_bindings_state_below(keep_from)?;
        self.prune_pq_registry_below(keep_from)?;
        self.prune_evm_settled_state_below(keep_from)?;
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

    /// Drop session-key snapshots older than `keep_from`. Called from
    /// `prune_domains_below` so the third tree follows the same window. Never
    /// drops a row at a snapshotted height (see [`Self::aux_retained_heights`]):
    /// state/domains preserve their newest entry so a node always stays
    /// bootable, and the aux trees must keep the rows those heights restore
    /// with — deleting the newest aux blob while state/domains keep theirs
    /// would strand the retained height behind a root mismatch.
    pub fn prune_session_keys_below(&self, keep_from: u64) -> Result<usize> {
        let keep = self.aux_retained_heights();
        let mut removed = 0;
        let keys: Vec<sled::IVec> = self
            .session_keys
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| {
                if k.len() != 8 {
                    return false;
                }
                let h = u64::from_be_bytes(k.as_ref().try_into().unwrap());
                h < keep_from && !keep.contains(&h)
            })
            .collect();
        for k in keys {
            self.session_keys.remove(k)?;
            removed += 1;
        }
        Ok(removed)
    }

    // ---------- Bridge domain snapshots (the §8 replay set / queue) ----------

    /// Drop bridge snapshots older than `keep_from`. Called from
    /// `prune_domains_below` so this tree follows the same window. Never
    /// drops a row at a snapshotted height: see [`Self::aux_retained_heights`].
    pub fn prune_bridge_below(&self, keep_from: u64) -> Result<usize> {
        let keep = self.aux_retained_heights();
        let mut removed = 0;
        let keys: Vec<sled::IVec> = self
            .bridge
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| {
                if k.len() != 8 {
                    return false;
                }
                let h = u64::from_be_bytes(k.as_ref().try_into().unwrap());
                h < keep_from && !keep.contains(&h)
            })
            .collect();
        for k in keys {
            self.bridge.remove(k)?;
            removed += 1;
        }
        Ok(removed)
    }

    // ---------- zkML model registry snapshots (audit F-B) ----------

    /// Drop registry snapshots older than `keep_from`. Called from
    /// `prune_domains_below` so this tree follows the same window. Never
    /// drops a row at a snapshotted height: see [`Self::aux_retained_heights`].
    pub fn prune_zkml_models_below(&self, keep_from: u64) -> Result<usize> {
        let keep = self.aux_retained_heights();
        let mut removed = 0;
        let keys: Vec<sled::IVec> = self
            .zkml_models
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| {
                if k.len() != 8 {
                    return false;
                }
                let h = u64::from_be_bytes(k.as_ref().try_into().unwrap());
                h < keep_from && !keep.contains(&h)
            })
            .collect();
        for k in keys {
            self.zkml_models.remove(k)?;
            removed += 1;
        }
        Ok(removed)
    }

    // ---------- Cross-shard replay snapshots (audit F-I) ----------

    /// Drop replay snapshots older than `keep_from`. Called from
    /// `prune_domains_below` so this tree follows the same window. Never
    /// drops a row at a snapshotted height (see [`Self::aux_retained_heights`]):
    /// deleting the replay blob of a retained paired height would leave a
    /// bootable-looking snapshot whose restore roots differently (or silently
    /// re-opens consumed inbounds) — a self-inflicted refusal at best, a
    /// double-mint at worst.
    pub fn prune_cross_shard_below(&self, keep_from: u64) -> Result<usize> {
        let keep = self.aux_retained_heights();
        let mut removed = 0;
        let keys: Vec<sled::IVec> = self
            .cross_shard
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| {
                if k.len() != 8 {
                    return false;
                }
                let h = u64::from_be_bytes(k.as_ref().try_into().unwrap());
                h < keep_from && !keep.contains(&h)
            })
            .collect();
        for k in keys {
            self.cross_shard.remove(k)?;
            removed += 1;
        }
        Ok(removed)
    }

    // ---------- CN-VRF v3 domain snapshots ----------

    /// Drop CN-VRF v3 snapshots older than `keep_from`. Called from
    /// `prune_domains_below` so this tree follows the same window. Never drops
    /// a row at a snapshotted height: see [`Self::aux_retained_heights`].
    pub fn prune_cnvrf_v3_below(&self, keep_from: u64) -> Result<usize> {
        let keep = self.aux_retained_heights();
        let mut removed = 0;
        let keys: Vec<sled::IVec> = self
            .cnvrf_v3
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| {
                if k.len() != 8 {
                    return false;
                }
                let h = u64::from_be_bytes(k.as_ref().try_into().unwrap());
                h < keep_from && !keep.contains(&h)
            })
            .collect();
        for k in keys {
            self.cnvrf_v3.remove(k)?;
            removed += 1;
        }
        Ok(removed)
    }

    /// Drop `cnvrf_freeze_inputs` snapshots older than `keep_from`. Called from
    /// `prune_domains_below`. Never drops a row at a retained snapshot height:
    /// see [`Self::aux_retained_heights`].
    pub fn prune_cnvrf_freeze_inputs_below(&self, keep_from: u64) -> Result<usize> {
        let keep = self.aux_retained_heights();
        let mut removed = 0;
        let keys: Vec<sled::IVec> = self
            .cnvrf_freeze_inputs
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| {
                if k.len() != 8 {
                    return false;
                }
                let h = u64::from_be_bytes(k.as_ref().try_into().unwrap());
                h < keep_from && !keep.contains(&h)
            })
            .collect();
        for k in keys {
            self.cnvrf_freeze_inputs.remove(k)?;
            removed += 1;
        }
        Ok(removed)
    }

    /// Drop `evm_bindings_state` snapshots older than `keep_from`. Called from
    /// `prune_domains_below`. Never drops a row at a retained snapshot height:
    /// see [`Self::aux_retained_heights`].
    pub fn prune_evm_bindings_state_below(&self, keep_from: u64) -> Result<usize> {
        let keep = self.aux_retained_heights();
        let mut removed = 0;
        let keys: Vec<sled::IVec> = self
            .evm_bindings_state
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| {
                if k.len() != 8 {
                    return false;
                }
                let h = u64::from_be_bytes(k.as_ref().try_into().unwrap());
                h < keep_from && !keep.contains(&h)
            })
            .collect();
        for k in keys {
            self.evm_bindings_state.remove(k)?;
            removed += 1;
        }
        Ok(removed)
    }

    /// Drop `pq_registry` snapshots older than `keep_from`. Called from
    /// `prune_domains_below`. Never drops a row at a retained snapshot height:
    /// see [`Self::aux_retained_heights`].
    pub fn prune_pq_registry_below(&self, keep_from: u64) -> Result<usize> {
        let keep = self.aux_retained_heights();
        let mut removed = 0;
        let keys: Vec<sled::IVec> = self
            .pq_registry
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| {
                if k.len() != 8 {
                    return false;
                }
                let h = u64::from_be_bytes(k.as_ref().try_into().unwrap());
                h < keep_from && !keep.contains(&h)
            })
            .collect();
        for k in keys {
            self.pq_registry.remove(k)?;
            removed += 1;
        }
        Ok(removed)
    }

    /// Drop `evm_settled_state` snapshots older than `keep_from`. Called from
    /// `prune_domains_below`. Never drops a row at a retained snapshot height:
    /// see [`Self::aux_retained_heights`].
    pub fn prune_evm_settled_state_below(&self, keep_from: u64) -> Result<usize> {
        let keep = self.aux_retained_heights();
        let mut removed = 0;
        let keys: Vec<sled::IVec> = self
            .evm_settled_state
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| {
                if k.len() != 8 {
                    return false;
                }
                let h = u64::from_be_bytes(k.as_ref().try_into().unwrap());
                h < keep_from && !keep.contains(&h)
            })
            .collect();
        for k in keys {
            self.evm_settled_state.remove(k)?;
            removed += 1;
        }
        Ok(removed)
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
        if committed_heights.is_empty() {
            return Ok(0);
        }
        let max_h = committed_heights.iter().copied().max();
        let mut manifests: BTreeMap<u64, crate::snapshot_v4::SnapshotManifestV1> = BTreeMap::new();
        for kv in self.snap_manifests.iter() {
            let (k, v) = kv?;
            if k.len() == 8 {
                let h = u64::from_be_bytes(k.as_ref().try_into().unwrap());
                if let Ok(m) = decode_manifest_strict(&v) {
                    manifests.insert(h, m);
                }
            }
        }

        let mut retain: BTreeSet<u64> = BTreeSet::new();
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
        let dead_units: Vec<sled::IVec> = self
            .snap_units
            .iter()
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| {
                if k.len() != 32 {
                    return true;
                }
                let mut h = [0u8; 32];
                h.copy_from_slice(k);
                !live_hashes.contains(&h)
            })
            .collect();
        for k in dead_units {
            self.snap_units.remove(k)?;
        }
        Ok(removed)
    }
}
