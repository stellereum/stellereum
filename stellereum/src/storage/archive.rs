use super::state::{decode_domain_snapshot, decode_pq_registry, DomainSnapshot};
use super::Storage;
use crate::state_engine::InMemoryStateEngine;
use anyhow::{anyhow, Result};

/// The provable "slots" of the state: which trie keys carry a per-key
/// archive proof, and which domains are only folded into the commitment
/// digest (see the slot model in the archive-proofs section below).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchiveSlot {
    /// A native account leaf, keyed by the 32-byte address.
    Account([u8; 32]),
    /// An STS token balance cell.
    TokenBalance {
        token_id: [u8; 32],
        account: [u8; 32],
    },
    /// An STS token total-supply cell.
    TokenSupply([u8; 32]),
    /// A contract's committed code hash.
    ContractCode([u8; 32]),
    /// A contract's committed ABI manifest (when one is attached).
    ContractAbi([u8; 32]),
    /// The single consensus-commitment digest leaf (proves the digest as a
    /// whole, never a single folded entry — see the slot model below).
    CommitmentDigest,
}

/// The state-trie key a slot is proven at.
pub fn archive_slot_key(slot: &ArchiveSlot) -> [u8; 32] {
    match *slot {
        ArchiveSlot::Account(addr) => addr,
        ArchiveSlot::TokenBalance { token_id, account } => {
            crate::state_engine::token_balance_key(&token_id, &account)
        }
        ArchiveSlot::TokenSupply(token_id) => crate::state_engine::token_supply_key(&token_id),
        ArchiveSlot::ContractCode(addr) => crate::state_engine::contract_key(&addr),
        ArchiveSlot::ContractAbi(addr) => crate::state_engine::contract_abi_key(&addr),
        ArchiveSlot::CommitmentDigest => crate::commitment::commitment_key(),
    }
}

/// An authenticated historical root: the post-`height` state root together
/// with the quorum certificate that commits to it.
///
/// The root is the `state_root` of the finalized block at
/// [`crate::chain_spec::anchor_height_for_post_state_at`]`(height)` (`height + 1`
/// below `EXECUTION_PIPELINE_V1`, `height + 2` at/above it; a header commits to
/// the state BEFORE its own block), and `cert` is that block's precommit QC. A
/// client verifies `cert` against its own validator set before trusting
/// `state_root` — without the QC the root is just a number the server asserts.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoricalRoot {
    /// Height whose post-state `state_root` is.
    pub height: u64,
    /// The historical state root.
    pub state_root: [u8; 32],
    /// The anchoring finalized block (`height + 1` below the execution-pipeline
    /// gate, `height + 2` at/above it).
    pub anchor_height: u64,
    /// Hash of the anchoring block (`cert` is bound to it).
    pub anchor_hash: [u8; 32],
    /// Hash of the anchoring block's parent (so the answer converts
    /// losslessly into a light-client checkpoint).
    pub anchor_prev_hash: [u8; 32],
    /// The precommit quorum certificate that decided the anchoring block.
    pub cert: crate::consensus::QuorumCertificate,
    /// Always true when served: the anchor is a finalized block.
    pub finalized: bool,
    /// Anchoring block's shard id (v4 header commitment).
    #[serde(default)]
    pub anchor_shard_id: u32,
    /// Anchoring block's round (v4 header commitment).
    #[serde(default)]
    pub anchor_round: u32,
    /// Anchoring block's body commitment (`Some` at `anchor_height >= H`, `None` below `H`).
    #[serde(default)]
    pub anchor_body_commitment: Option<[u8; 32]>,
    /// Anchoring block's MMR epoch root (v4 header commitment).
    #[serde(default)]
    pub anchor_mmr_epoch_root: [u8; 32],
    /// Anchoring block's epoch key commitment (v4 header commitment).
    #[serde(default)]
    pub anchor_epoch_key_commitment: [u8; 32],
    /// Anchoring block's timestamp (v4 header commitment).
    #[serde(default)]
    pub anchor_timestamp: u64,
    /// Anchoring block's proposer (v4 header commitment).
    #[serde(default)]
    pub anchor_proposer: [u8; 32],
}

struct LoadedArchiveSnapshot {
    state_bytes: Vec<u8>,
    domains: DomainSnapshot,
    session_keys: Option<Vec<u8>>,
    bridge: Option<Vec<u8>>,
    zkml_models: Option<Vec<u8>>,
    cross_shard: Option<crate::sharding::CrossShardReplaySnapshot>,
    cnvrf_v3: Option<crate::state_engine::CnVrfV3EngineSnapshot>,
    evm_bindings_state: Option<Vec<u8>>,
    pq_registry: Option<Vec<u8>>,
    evm_settled_state: Option<Vec<u8>>,
}

impl Storage {
    // ---------- Per-key ARCHIVE proofs + state proofs by "slot" ----------
    //
    // WHAT THIS IS. The node has always been able to prove the CURRENT state
    // (`stell_getProof`: account + storage proofs against the live trie root).
    // What was missing (storage audit: "no per-key archive proofs, no SPV
    // proofs by slot"): proving what key K held at a HISTORICAL height H long
    // after the node pruned the live trie forward, and saying precisely WHICH
    // keys are provable at all.
    //
    // PROOF FORMAT. An archive proof is
    // `{ height, state_root, key, value_or_absence, proof_nodes }` where
    // `proof_nodes` is the canonical `cpat2::MerkleProof::to_nodes` hex-node
    // list (leaf first) and `value_or_absence` is the proven leaf value
    // (`None` for an exclusion proof). It verifies with
    // `cpat2::ArchiveProof::verify` against the HISTORICAL root — a root the
    // node no longer holds in memory. The root itself is authenticated by
    // `stell_getHistoricalRoot` (a quorum certificate on the anchoring block);
    // a proof against an untrusted root proves nothing, so the two RPCs are
    // one unit: the proof and its anchor.
    //
    // WHERE IT COMES FROM. The archive node rebuilds the historical trie from
    // its persisted snapshot history (the `state` / `domains` / aux trees),
    // NOT from the live trie: the live trie has moved on and must never be
    // rewound (rewinding it would fork a validating node). The rebuild runs
    // in a throwaway engine, the recomputed root is checked against the
    // finalized header that anchors it (fail closed on mismatch), and only
    // then is the proof generated. The live trie is untouched.
    //
    // SLOT MODEL. Provability is per trie key:
    //
    // * DIRECTLY PROVABLE (one trie leaf each, inclusion AND exclusion):
    //   - account leaf: `address` -> `balance_be || nonce_be[ || scheme ||
    //     pubkey_hash]` (16 or 49 bytes);
    //   - STS balance cell: `sha256("STS_BAL" || token_id || account)` ->
    //     `balance_be`;
    //   - STS supply cell: `sha256("STS_SUPPLY" || token_id)` ->
    //     `total_supply_be`;
    //   - contract code hash: `sha256("STELL_CONTRACT_CODE" || addr)` ->
    //     `code_hash`;
    //   - contract ABI manifest: `sha256("STELL_CONTRACT_ABI" || addr)` ->
    //     `abi_json` (when a manifest is attached);
    //   - consensus commitment leaf:
    //     `sha256("STELL_CONSENSUS_COMMITMENT_V1")` -> `digest` (proves the
    //     digest as a whole, not any field inside it).
    //   See `ArchiveSlot` for the key derivation of each slot.
    //
    // * DIGEST-FOLDED (NOT per-key provable): everything committed only
    //   through the consensus commitment digest — the staking ledger
    //   (validators, delegations, rewards, unbonding, ...), order books and
    //   every order's fields, order escrow, the PMM state, contract STORAGE
    //   slots, governance proposals and voters, the oracle feeds, the
    //   session-key registry, the bridge queue, the shielded ledger, the zkML
    //   registries and the cross-shard replay sets. For these the node can
    //   only prove the digest, never a single entry: the trie holds one leaf
    //   for all of them together. WHAT WOULD MAKE THEM PROVABLE: committing
    //   each entry under its own namespaced trie key (the way STS balances
    //   are committed under `STS_BAL` keys) instead of folding them into one
    //   digest — a consensus format change, deliberately NOT done here.
    //
    // RETENTION RULE (explicit and bounded). Snapshots are taken every
    // `STELL_SNAPSHOT_INTERVAL` heights (default 1000, minimum 50).
    //
    // * ARCHIVE mode (`STELL_ARCHIVE=1`, the default): the node never prunes
    //   block bodies, state snapshots, domain snapshots or aux-domain
    //   snapshots. It serves archive proofs and historical roots for EVERY
    //   snapshot height it ever took. The cost is explicit and unbounded:
    //   roughly one full state + domain snapshot per snapshot interval,
    //   forever. Operators who cannot pay it run prune mode.
    // * PRUNE mode (`STELL_ARCHIVE=0` + `STELL_KEEP_BLOCKS=<n>`, default
    //   50 000): the node keeps the last `keep_blocks` block bodies, all
    //   header records (they survive body pruning), the last three snapshot
    //   intervals of state/domain/aux snapshots, and the last 512
    //   quorum-certified headers in memory. It serves archive proofs ONLY
    //   for retained snapshot heights and historical roots ONLY while the
    //   anchoring body's quorum certificate is retained; anything older is
    //   refused with a `pruned` error — never fabricated, never an empty
    //   answer.
    //
    // The live trie is never rewound and pruning is never weakened: serving
    // archive proofs costs MORE retained data in archive mode, and an honest
    // refusal in prune mode.

    /// Every height holding BOTH a state and a domains snapshot (the heights
    /// an archive proof can be served for), oldest first.
    pub fn retained_archive_heights(&self) -> Result<Vec<u64>> {
        let mut out = Vec::new();
        for item in self.state.iter().keys() {
            let Ok(k) = item else { continue };
            if k.len() != 8 {
                continue;
            }
            if self.domains.contains_key(&k)? {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&k);
                out.push(u64::from_be_bytes(arr));
            }
        }
        Ok(out)
    }

    /// Nearest retained snapshot heights `(below, above)` around `height` and a
    /// bounded one-line coverage summary, computed in a single scan of
    /// `retained_archive_heights`.
    fn retained_archive_heights_summary(&self, height: u64) -> (Option<u64>, Option<u64>, String) {
        match self.retained_archive_heights() {
            Ok(h) if h.is_empty() => (None, None, "no snapshots retained".to_string()),
            Ok(h) => {
                let below_idx = h.partition_point(|&v| v < height);
                let below = below_idx.checked_sub(1).map(|i| h[i]);
                let above_idx = h.partition_point(|&v| v <= height);
                let above = h.get(above_idx).copied();
                let lo = h[0];
                let hi = h[h.len() - 1];
                let coverage = format!("{} paired snapshot(s), heights {lo}..={hi}", h.len());
                (below, above, coverage)
            }
            Err(_) => (None, None, "snapshot index unreadable".to_string()),
        }
    }

    /// Rebuild the historical state trie at `height` from the persisted
    /// snapshot history and return it with the state root it computes to.
    ///
    /// The rebuild runs in a throwaway engine (the live trie is never
    /// touched) and the recomputed root is checked against the finalized
    /// header anchoring it (`expected_restore_root`, i.e. the `state_root`
    /// of the block at [`crate::chain_spec::anchor_height_for_post_state_at`]:
    /// `height + 1` below the execution-pipeline gate, `height + 2` above it).
    /// Fail closed at every step: a height
    /// above the tip, an unknown height, a pruned height, an unpaired
    /// snapshot or a root mismatch is an error, never an empty proof.
    ///
    /// `tip` is the node's current finalized height, used to tell "above the
    /// tip" (retry later) apart from "pruned" (never coming back).
    pub async fn rebuild_historical_trie(
        &self,
        height: u64,
        tip: u64,
    ) -> Result<(crate::cpat2::CompressedTrie, [u8; 32])> {
        if height > tip {
            return Err(anyhow!(
                "height {height} is above the tip ({tip}): refusing to prove the future"
            ));
        }

        let storage = self.clone();
        let loaded = tokio::task::spawn_blocking(move || -> Result<LoadedArchiveSnapshot> {
            let state_bytes = storage.get_state(height)?.ok_or_else(|| {
                let (below, above, coverage) = storage.retained_archive_heights_summary(height);
                // Below the oldest retained snapshot the data is gone for good;
                // inside the retained span a missing snapshot means this height
                // was never snapshotted (snapshots are taken every
                // `STELL_SNAPSHOT_INTERVAL` heights, not every height).
                let reason = match below {
                    None => format!("pruned or never snapshotted ({coverage})"),
                    Some(lo) if height < lo => {
                        format!("pruned on this node (oldest retained snapshot is at {lo}; {coverage})")
                    }
                    _ => format!(
                        "no snapshot at this height (snapshots are taken every `STELL_SNAPSHOT_INTERVAL` heights; nearest retained: below={below:?}, above={above:?}; {coverage})"
                    ),
                };
                anyhow!("no state snapshot at height {height}: {reason}")
            })?;
            let domains_bytes = storage.domain_at(height)?.ok_or_else(|| {
                anyhow!(
                    "state snapshot at height {height} has no paired domains snapshot (unpaired snapshot, possible crash between the snapshot jobs): refusing rather than proving from half a state"
                )
            })?;
            let domains = decode_domain_snapshot(&domains_bytes)?;
            let session_keys = storage.session_keys_at(height)?;
            let bridge = storage.bridge_at(height)?;
            let zkml_models = storage.zkml_models_at(height)?;
            let cross_shard = storage
                .cross_shard_at(height)?
                .map(|bytes| {
                    crate::sharding::with_legacy_block_tolerance(|| bincode::deserialize(&bytes))
                        .map_err(|e| anyhow!("restore cross-shard replay at height {height}: {e:?}"))
                })
                .transpose()?;
            let cnvrf_v3 = match storage.cnvrf_v3_at(height)? {
                Some(bytes) if !bytes.is_empty() => Some(
                    bincode::deserialize(&bytes)
                        .map_err(|e| anyhow!("restore cnvrf_v3 at height {height}: {e}"))?,
                ),
                _ => None,
            };
            let evm_bindings_state = storage.evm_bindings_state_at(height)?;
            let pq_registry = match storage.pq_registry_at(height)? {
                Some(bytes) => {
                    let _pq_reg = decode_pq_registry(&bytes)
                        .map_err(|e| anyhow!("restore pq_registry at height {height}: {e}"))?;
                    Some(bytes)
                }
                None => None,
            };
            let evm_settled_state = storage.evm_settled_state_at(height)?;
            Ok(LoadedArchiveSnapshot {
                state_bytes,
                domains,
                session_keys,
                bridge,
                zkml_models,
                cross_shard,
                cnvrf_v3,
                evm_bindings_state,
                pq_registry,
                evm_settled_state,
            })
        })
        .await
        .map_err(|e| anyhow!("archive snapshot load task panicked: {e}"))??;

        // Phase 1 (throwaway): restore + verify before proving anything, the
        // same shape as `load_full_state_into`.
        let tmp = InMemoryStateEngine::new();
        tmp.attach_pq_tree(self.pq_keys.clone());
        tmp.restore_snapshot_preserve_replay_sets(&loaded.state_bytes)
            .await
            .map_err(|e| anyhow!("restore state snapshot at height {height}: {e}"))?;
        loaded.domains.apply(&tmp).await;
        if let Some(bytes) = loaded.session_keys {
            tmp.restore_session_keys(&bytes)
                .await
                .map_err(|e| anyhow!("restore session keys at height {height}: {e}"))?;
        }
        if let Some(bytes) = loaded.bridge {
            tmp.restore_bridge(&bytes)
                .await
                .map_err(|e| anyhow!("restore bridge domain at height {height}: {e}"))?;
        }
        // Ristretto deletion wave: confidential/shielded ledger removed with
        // crypto_privacy; no restore (transparent paths unchanged).
        if let Some(bytes) = loaded.zkml_models {
            tmp.restore_zkml_models(&bytes)
                .await
                .map_err(|e| anyhow!("restore zkML models at height {height}: {e}"))?;
        }
        if let Some(replay) = loaded.cross_shard {
            tmp.restore_cross_shard_replay(&replay).await;
        }
        if let Some(snap) = loaded.cnvrf_v3 {
            tmp.restore_cnvrf_v3_snapshot(&snap).await;
        }
        if let Some(bytes) = loaded.evm_bindings_state {
            tmp.restore_evm_bindings(&bytes)
                .await
                .map_err(|e| anyhow!("restore evm_bindings_state at height {height}: {e}"))?;
        }
        if let Some(bytes) = loaded.pq_registry {
            tmp.restore_pq_registry(&bytes)
                .await
                .map_err(|e| anyhow!("restore pq_registry at height {height}: {e}"))?;
        }
        if let Some(bytes) = loaded.evm_settled_state {
            tmp.restore_evm_settled(&bytes)
                .await
                .map_err(|e| anyhow!("restore evm_settled_state at height {height}: {e}"))?;
        }

        // Anchor the recomputed root: the header at
        // `anchor_height_for_post_state_at(height)` commits to the
        // post-`height` state (`height + 1` below the execution-pipeline gate,
        // `height + 2` at/above it). At the tip (no successor yet) check
        // `finalized_post_root_at(height)` if present, else skip for compat.
        let computed = tmp.get_state_root().await;
        let storage = self.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            match storage.expected_restore_root(height)? {
                Some(expected) if computed != expected => Err(anyhow!(
                    "snapshot at height {height} hashes to {} but the finalized block at {} commits to {} (truncated, corrupt or wrong-height snapshot): refusing to prove from it",
                    hex::encode(computed),
                    crate::chain_spec::anchor_height_for_post_state_at(height),
                    hex::encode(expected),
                )),
                Some(_) => Ok(()),
                None => {
                    let finalized_tip = storage.finalized()?.map(|(h, _)| h).unwrap_or(tip);
                    if height < finalized_tip {
                        return Err(anyhow!(
                            "no anchor to verify snapshot at height {height} (finalized head is {finalized_tip}): refusing to prove from unanchored state"
                        ));
                    }
                    if let Some(expected) = storage.finalized_post_root_at(height)? {
                        if computed != expected {
                            return Err(anyhow!(
                                "snapshot at tip height {height} hashes to {} but finalized_post_root_v1 commits to {}: refusing to prove from it",
                                hex::encode(computed),
                                hex::encode(expected),
                            ));
                        }
                    }
                    Ok(())
                }
            }
        })
        .await
        .map_err(|e| anyhow!("archive root check task panicked: {e}"))??;
        let trie = tmp.state_trie.read().await.compressed().clone();
        Ok((trie, computed))
    }

    /// Serve a per-key archive proof for `key` at `height` from the persisted
    /// snapshot history.
    ///
    /// Inclusion when the key is in the historical trie, exclusion when it is
    /// provably absent. Fail closed: unknown, pruned and above-tip heights
    /// are errors (see `rebuild_historical_trie`), never empty answers.
    pub async fn serve_archive_proof(
        &self,
        height: u64,
        key: &[u8; 32],
        tip: u64,
    ) -> Result<crate::cpat2::ArchiveProof> {
        let (trie, root) = self.rebuild_historical_trie(height, tip).await?;
        let key = *key;
        tokio::task::spawn_blocking(move || {
            if let Some(p) = trie.generate_proof(&key) {
                crate::cpat2::ArchiveProof::inclusion(height, root, key, &p).ok_or_else(|| {
                    anyhow!("internal error: generated inclusion proof is not for the queried key")
                })
            } else if let Some(p) = trie.generate_exclusion_proof(&key) {
                crate::cpat2::ArchiveProof::exclusion(height, root, key, &p).ok_or_else(|| {
                    anyhow!("internal error: generated exclusion proof is not for the queried key")
                })
            } else {
                // An empty historical trie has nothing to prove against. The
                // snapshot exists but holds no keys (genesis): absence is still
                // answered as an error rather than an unprovable empty proof,
                // because an empty proof is not evidence of absence.
                Err(anyhow!(
                    "historical trie at height {height} is empty: no proof can be served for it"
                ))
            }
        })
        .await
        .map_err(|e| anyhow!("archive proof task panicked: {e}"))?
    }

    /// The authenticated historical root for `height`: the post-`height`
    /// state root together with the quorum certificate that commits to it.
    ///
    /// The root is the `state_root` of the finalized block at
    /// [`crate::chain_spec::anchor_height_for_post_state_at`]`(height)` —
    /// `height + 1` on the legacy lag-1 chain, `height + 2` once
    /// `EXECUTION_PIPELINE_V1` is active (a header commits to the state BEFORE
    /// its own block) — and the proof is that block's precommit QC. Without the
    /// QC the root is just a number the server asserts — the client verifies
    /// the QC against its own validator set before trusting the root.
    ///
    /// Identity below the gate: the helper returns `height + 1`, so this method
    /// serves exactly the same anchor and root as before.
    ///
    /// Fail closed: a height above the tip, an unknown height, or a height
    /// whose anchoring body (and hence its QC) was pruned is an error.
    /// Header records alone do not authenticate: they carry no certificate.
    pub fn historical_root(&self, height: u64, tip: u64) -> Result<HistoricalRoot> {
        if height > tip {
            return Err(anyhow!(
                "height {height} is above the tip ({tip}): refusing to authenticate the future"
            ));
        }
        let anchor_height = crate::chain_spec::anchor_height_for_post_state_at(height);
        // The helper saturates at `u64::MAX`; an anchor that is not strictly
        // above the state height means no successor can anchor it.
        if anchor_height <= height {
            return Err(anyhow!(
                "height {height} overflows: no successor can anchor it"
            ));
        }
        // The anchor: header record first (survives body pruning), falling
        // back to the block body. But only the BODY carries the quorum
        // certificate, so a header without its body authenticates nothing.
        let anchor_hash = if let Some(rec) = self.header_at(anchor_height)? {
            rec.block_hash
        } else {
            let hashes = self.hashes_at_height(anchor_height)?;
            let hash = hashes.into_iter().next().ok_or_else(|| {
                anyhow!(
                    "no record of height {anchor_height} (and hence no authenticated root for height {height}): unknown height on this node"
                )
            })?;
            hash
        };
        // The QC must come from a retained body. A pruned body leaves the
        // header record behind, and serving the root on the header's word
        // alone would be exactly the hole this closes.
        let mut cert = None;
        for hash in self.hashes_at_height(anchor_height)? {
            if hash != anchor_hash {
                continue;
            }
            if let Some(block) = self.get_block(&hash)? {
                if block.height != anchor_height {
                    continue;
                }
                if block.compute_hash() != anchor_hash {
                    continue;
                }
                cert = block.precommit_qc.clone();
                break;
            }
        }
        // Hash-index miss (pruned index entry): try the body by hash in case
        // the index is what is gone.
        if cert.is_none() {
            if let Some(block) = self.get_block(&anchor_hash)? {
                if block.height == anchor_height && block.compute_hash() == anchor_hash {
                    cert = block.precommit_qc.clone();
                }
            }
        }
        let cert = cert.ok_or_else(|| {
            anyhow!(
                "quorum certificate for the anchoring block at height {anchor_height} is not retained on this node (body pruned or never finalized with a certificate): refusing to authenticate the root for height {height}"
            )
        })?;
        // The root the anchor commits to. Taken from the header record when
        // present (it is the canonical chain record), else from the body.
        let (state_root, anchor_prev_hash, legacy_ts, legacy_proposer) = if let Some(rec) =
            self.header_at(anchor_height)?
        {
            (rec.state_root, rec.prev_hash, rec.timestamp, rec.proposer)
        } else if let Some(block) = self.get_block(&anchor_hash)? {
            (
                block.state_root,
                block.prev_hash,
                block.timestamp,
                block.proposer,
            )
        } else {
            return Err(anyhow!(
                    "anchoring block at height {anchor_height} names a body this node no longer holds: refusing"
                ));
        };
        let v2_opt = self.header_v2_at(anchor_height)?;
        let (
            anchor_shard_id,
            anchor_round,
            anchor_body_commitment,
            anchor_mmr_epoch_root,
            anchor_epoch_key_commitment,
            anchor_timestamp,
            anchor_proposer,
        ) = if crate::sharding::header_commit_active_at(anchor_height) {
            let v2 = v2_opt.ok_or_else(|| {
                anyhow!(
                    "missing v2 header record for anchoring height {anchor_height} under v4 header commitment: refusing fail-closed"
                )
            })?;
            if v2.block_hash != anchor_hash
                || v2.header.compute_hash() != anchor_hash
                || v2.header.state_root != state_root
                || v2.header.prev_hash != anchor_prev_hash
            {
                return Err(anyhow!(
                    "anchoring header v2 at height {anchor_height} failed BlockHeader::compute_hash() binding against anchor_hash"
                ));
            }
            (
                v2.header.shard_id,
                v2.header.round,
                Some(v2.header.body_commitment),
                v2.header.mmr_epoch_root,
                v2.header.epoch_key_commitment,
                v2.header.timestamp,
                v2.header.proposer,
            )
        } else if let Some(v2) = v2_opt {
            (
                v2.header.shard_id,
                v2.header.round,
                None,
                v2.header.mmr_epoch_root,
                v2.header.epoch_key_commitment,
                v2.header.timestamp,
                v2.header.proposer,
            )
        } else {
            (0, 0, None, [0u8; 32], [0u8; 32], legacy_ts, legacy_proposer)
        };
        Ok(HistoricalRoot {
            height,
            state_root,
            anchor_height,
            anchor_hash,
            anchor_prev_hash,
            cert,
            finalized: true,
            anchor_shard_id,
            anchor_round,
            anchor_body_commitment,
            anchor_mmr_epoch_root,
            anchor_epoch_key_commitment,
            anchor_timestamp,
            anchor_proposer,
        })
    }
}
