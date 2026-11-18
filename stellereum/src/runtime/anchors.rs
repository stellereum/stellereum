use super::{
    ValidatorRuntime, VdfLane, MAX_CNVRF_V3_COMMITS_PER_BLOCK, MAX_PENDING_CNVRF_V3_COMMITS,
};
use crate::consensus::{FalconKeypair, Height, HeightConsensus, ValidatorId, ValidatorSet};
use crate::mempool::Mempool;
use crate::sharding::{
    Block, CrossShardMessage, MasterStakingLedger, ShardId, ShardRegistry, Transaction,
    MASTERCHAIN_SHARD,
};
use crate::state_engine::InMemoryStateEngine;
use crate::storage::BlockHash;
use ed25519_dalek::{Signer as _, SigningKey};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

impl ValidatorRuntime {
    pub fn new(
        key: SigningKey,
        validators: ValidatorSet,
        state: Arc<InMemoryStateEngine>,
        start_height: Height,
    ) -> Self {
        let id = key.verifying_key().to_bytes();
        let hc = HeightConsensus::new(start_height, validators.clone());
        // The ledger is shared with the state engine, never copied out of it.
        let staking = state.staking_handle();
        // Same for the session-key registry (phase 2): the default pool gets
        // the engine's lock so admission can see revocations. A pool swapped in
        // via `with_mempool` carries its own handle (the node wires both).
        //
        // The DEFAULT pool has NO admission floor of its own: it is the
        // library default (`Mempool::default()`, floor 0) and the NODE always
        // injects its own floored pool through `with_mempool` (main.rs), so
        // the production pool carries the frozen `FROZEN_MIN_GAS_FLOOR`
        // floor. A runtime built WITHOUT an injected pool would accept
        // zero-fee transactions - that is a deployment hazard, not a code
        // path, and it is called out in the operations notes.
        let mempool = Arc::new(tokio::sync::RwLock::new(
            Mempool::default().with_session_registry(state.session_keys_handle()),
        ));
        let mut rt = Self {
            key,
            remote_signer: None,
            id,
            validators,
            hc,
            state: state.clone(),
            mempool,
            tx_gossip: None,
            blocks: HashMap::new(),
            demanded: HashSet::new(),
            demanded_height: start_height,
            peer_hint: None,
            last_followed_round: None,
            finalized: Vec::new(),
            applied_txs: 0,
            applied_statuses: Vec::new(),
            applied_fees: Vec::new(),
            applied_events: Vec::new(),
            staking,
            master_staking: None,
            governance: None,
            block_reward: 0,
            last_decision: None,
            shard_id: MASTERCHAIN_SHARD,
            shard_registry: ShardRegistry::single(),
            cross_shard: None,
            finalized_headers: None,
            consumed_cross_shard: HashSet::new(),
            produced_cross_shard: HashMap::new(),
            completed_cross_shard: HashSet::new(),
            xpc_activation: crate::xshard2pc::XpcActivation::Disabled,
            xpc_records: HashMap::new(),
            apply_lane: None,
            apply_in_flight: None,
            snapshot_in_flight: None,
            parallel_exec: state.is_parallel_exec_enabled(),
            validator_set_stale: false,
            validator_set_stale_reason: None,
            validator_set_state_height: None,
            validator_set_ledger_height: None,
            validator_reentry_warns_total: 0,
            reentry_watch: HashMap::new(),
            falcon_key: None,
            deterministic_sim_signing: false,
            pending_validators: None,
            validator_set_history: std::collections::VecDeque::new(),
            slow_validation_total: 0,
            validation_last_stages: Vec::new(),
            pack_snapshot: std::sync::Mutex::new(None),
            actor_backlog_cache: std::sync::Mutex::new(None),
            order_root_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
            batch_verify_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
            proposer_sig_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
            qc_power_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
            prebuilt_selection: std::sync::Mutex::new(None),
            vdf_lane: None,
            pending_vdf_rx: None,
            ready_vdf_beacons: BTreeMap::new(),
            finalized_epoch_beacons: BTreeMap::new(),
            cnvrf_v3_mirror: crate::cn_vrf::CnVrfV3State::default(),
            cnvrf_freeze_inputs: BTreeMap::new(),
            cnvrf_v3_chains: BTreeMap::new(),
            cnvrf_v3_disabled_epochs: HashSet::new(),
            pending_cnvrf_v3_commits: Vec::new(),
            cnvrf_v3_dir: None,
            cnvrf_v3_chain_id: state.chain_id,
            cnvrf_v3_vdf_steps: crate::minroot_vdf::DEFAULT_VDF_STEPS_PER_EPOCH,
            #[cfg(any(test, debug_assertions))]
            cnvrf_v3_activation_override: None,
            last_progress_at: std::time::Instant::now(),
            last_breaker_at: None,
            // The fork-choice tree starts EMPTY: the node learns its
            // finalized head from the consensus layer, and the first block
            // it finalizes becomes the root of the tree.
            chain: crate::chain::ChainManager::detached(),
            invalidation_sink: None,
            // The node's LIGHT CLIENT (audit W8.3 / blocker A10): the trusted
            // anchor every peer-supplied block is checked against. `None`
            // until the node knows its genesis root (see
            // `with_light_client`); from then on it is the quorum-certified
            // chain this node has finalized.
            light: None,
        };
        rt.install_committee_schedule();
        rt
    }

    // =========================================================================
    // CN-VRF v3 (7,200-block reverse hash-chain + MinRoot PQ-VDF epoch beacon)
    // =========================================================================

    /// Configure test/debug CN-VRF v3 activation height on both this runtime and
    /// its backing state engine, leaving the frozen `CNVRF_V3_ACTIVATION_HEIGHT`
    /// constant untouched.
    ///
    /// The ACTIVATION-HEIGHT RULE (review F4) is enforced here: a height on an
    /// epoch boundary (or inside the freeze lookahead before one) would make the
    /// activation block an epoch boundary whose `epoch_vdf` was never dispatched
    /// (`H_freeze < activation`), i.e. an unproposable block. See
    /// [`crate::consensus::cnvrf_v3_activation_height_allowed`].
    #[cfg(any(test, debug_assertions))]
    pub fn set_cnvrf_v3_activation_height_for_tests(&mut self, activation: u64) {
        crate::consensus::assert_cnvrf_v3_activation_height(activation);
        self.cnvrf_v3_activation_override = Some(activation);
        self.state
            .set_cnvrf_v3_activation_height_for_tests(activation);
        self.install_committee_schedule();
    }

    /// The CN-VRF v3 activation height in force for this node: the test/debug
    /// override when installed, else the frozen
    /// [`crate::consensus::CNVRF_V3_ACTIVATION_HEIGHT`].
    pub fn cnvrf_v3_activation_height(&self) -> Height {
        #[cfg(any(test, debug_assertions))]
        {
            if let Some(activation) = self.cnvrf_v3_activation_override {
                return activation;
            }
        }
        crate::consensus::CNVRF_V3_ACTIVATION_HEIGHT
    }

    /// Builder: override MinRoot VDF steps per epoch (e.g. `64` in tests).
    pub fn with_cnvrf_v3_vdf_steps(mut self, steps: u64) -> Self {
        self.cnvrf_v3_vdf_steps = steps.max(1);
        self
    }

    /// Set MinRoot VDF steps per epoch at runtime.
    pub fn set_cnvrf_v3_vdf_steps(&mut self, steps: u64) {
        self.cnvrf_v3_vdf_steps = steps.max(1);
    }

    /// Configure encrypted (`enc2:`) disk custody directory and chain ID for
    /// CN-VRF v3 per-epoch secrets.
    pub fn configure_cnvrf_v3_custody(&mut self, dir: std::path::PathBuf, chain_id: u64) {
        self.cnvrf_v3_dir = Some(dir);
        self.cnvrf_v3_chain_id = chain_id;
    }

    /// Returns `true` when CN-VRF v3 is active at `height`.
    pub fn cnvrf_v3_is_active_at(&self, height: Height) -> bool {
        if crate::consensus::cnvrf_v3_active_at(height) {
            return true;
        }
        #[cfg(any(test, debug_assertions))]
        {
            if let Some(activation) = self.cnvrf_v3_activation_override {
                if height >= activation {
                    return true;
                }
            }
            if self.state.cnvrf_v3_is_active_at(height) {
                return true;
            }
        }
        false
    }

    /// Synchronous lookup of the active CN-VRF v3 [`crate::consensus::EpochBeacon`]
    /// for `height`, reading from finalized state mirrors and locally completed
    /// `MinRoot` VDF proofs.
    ///
    /// For epoch 0 (or an activation epoch whose `H_freeze` occurred prior to
    /// CN-VRF v3 activation), returns a deterministic genesis/activation bootstrap
    /// beacon derived from `(chain_id, epoch)` so `proposer_for_with_beacon` and
    /// `QuorumCertificate::verify_with_beacon` remain deterministic across all nodes.
    /// For any subsequent epoch whose `H_freeze` ran under active CN-VRF v3,
    /// fails closed (`None`) until the verified VDF beacon is ready or finalized.
    pub fn active_epoch_beacon(&self, height: Height) -> Option<crate::consensus::EpochBeacon> {
        if !self.cnvrf_v3_is_active_at(height) {
            return None;
        }
        let epoch = crate::cn_vrf::epoch_of_height(height);
        if let Some(&output) = self.finalized_epoch_beacons.get(&epoch) {
            return Some(crate::consensus::EpochBeacon { epoch, output });
        }
        if let Some(vdf) = self.ready_vdf_beacons.get(&epoch) {
            let output = crate::minroot_vdf::derive_vdf_output(&vdf.raw_seed, &vdf.proof);
            return Some(crate::consensus::EpochBeacon { epoch, output });
        }
        // THE bootstrap rule (shared with the producer/validator/apply seed
        // derivation, review F3): an epoch whose `H_freeze` predates activation
        // never ran a VDF, so its canonical beacon is the deterministic
        // `epoch_bootstrap_beacon` — the same value `epoch_seed` chains.
        let output = crate::cn_vrf::epoch_beacon_for(
            self.cnvrf_v3_chain_id,
            epoch,
            None,
            self.cnvrf_v3_activation_height(),
        )?;
        Some(crate::consensus::EpochBeacon { epoch, output })
    }

    /// THE schedule of "who signs at height `height`" for this node: the epoch
    /// beacon at/after the CN-VRF v3 activation height, the canonical
    /// parent-hash draw below it.
    ///
    /// Every producer and verifier in the runtime goes through this (via
    /// [`Self::install_committee_schedule`] and the `verify_qc_for_height`
    /// family), so a certificate this node builds and the certificate it
    /// attributes can never be drawn from different committees (review F2).
    pub fn committee_schedule_at(&self, height: Height) -> crate::consensus::CommitteeSchedule {
        if self.cnvrf_v3_is_active_at(height) {
            crate::consensus::CommitteeSchedule::Beacon(self.active_epoch_beacon(height))
        } else {
            crate::consensus::CommitteeSchedule::ParentHash
        }
    }

    /// Push [`Self::committee_schedule_at`] into the height state machine
    /// BEFORE it produces a decision certificate.
    ///
    /// Called at every height anchor this crate owns and, defensively, at the
    /// top of the cert-producing entry points — the engine is also re-anchored
    /// by the node's startup/sync code, and the schedule must never be left at
    /// its parent-hash default once activation is in force.
    pub fn install_committee_schedule(&mut self) {
        let schedule = self.committee_schedule_at(self.hc.height);
        self.hc.set_committee_schedule(schedule);
    }

    /// Lazily spawn the off-tick sequential MinRoot VDF worker on first active use.
    pub(super) fn ensure_vdf_lane(&mut self) -> VdfLane {
        if self.vdf_lane.is_none() {
            self.vdf_lane = Some(VdfLane::spawn());
        }
        self.vdf_lane.clone().expect("vdf lane just spawned")
    }

    /// Non-blocking poll of the pending VDF job; moves a completed
    /// `VdfJobOutput` into `ready_vdf_beacons`.
    pub fn poll_vdf_lane(&mut self) {
        let Some((expected_epoch, mut rx)) = self.pending_vdf_rx.take() else {
            return;
        };
        match rx.try_recv() {
            Ok(Some(out)) => {
                if out.epoch == expected_epoch {
                    self.ready_vdf_beacons.insert(
                        out.epoch,
                        crate::sharding::EpochVdfBeacon {
                            epoch: out.epoch,
                            raw_seed: out.raw_seed,
                            proof: out.proof,
                        },
                    );
                }
            }
            Ok(None) => {
                tracing::warn!(
                    epoch = expected_epoch,
                    "CN-VRF v3 VDF lane returned None (superseded or panicked)"
                );
            }
            Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {
                self.pending_vdf_rx = Some((expected_epoch, rx));
            }
            Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                tracing::error!(
                    epoch = expected_epoch,
                    "CN-VRF v3 VDF lane channel closed before delivering beacon"
                );
            }
        }
    }

    /// True if a verified or locally computed `EpochVdfBeacon` for `epoch` is
    /// already ready (either in `ready_vdf_beacons` or `finalized_epoch_beacons`).
    pub fn has_ready_vdf_beacon(&self, epoch: u64) -> bool {
        self.ready_vdf_beacons.contains_key(&epoch)
            || self.finalized_epoch_beacons.contains_key(&epoch)
    }

    /// Number of queued outbound CN-VRF v3 commitments waiting to be packed.
    pub fn pending_cnvrf_v3_commits_len(&self) -> usize {
        self.pending_cnvrf_v3_commits.len()
    }

    /// True if local reveal/propose is disabled for `epoch` due to custody mismatch.
    pub fn cnvrf_v3_is_epoch_disabled(&self, epoch: u64) -> bool {
        self.cnvrf_v3_disabled_epochs.contains(&epoch)
    }

    pub(super) fn cnvrf_v3_secret_path(&self, epoch_n: u64) -> Option<std::path::PathBuf> {
        self.cnvrf_v3_dir.as_ref().map(|dir| {
            dir.join(format!(
                "cnvrf_v3_epoch_{epoch_n}_{}.secret",
                hex::encode(&self.id[..8])
            ))
        })
    }

    /// Resolve a validator's active PQ key synchronously (matching `apply_cnvrf_v3`).
    pub(super) fn resolve_validator_pq_key_sync(
        &self,
        validator_id: &ValidatorId,
        height: Height,
    ) -> Result<(crate::post_quantum::PqScheme, Vec<u8>), String> {
        let ledger = self.staking.try_read().map_err(|_| {
            "proposal: staking ledger unavailable for CN-VRF commit check".to_string()
        })?;
        if !ledger.validators.contains_key(validator_id) {
            return Err("proposal: CN-VRF v3 commit from unknown/unbonded validator".to_string());
        }
        let key_opt = ledger
            .validator_pq_keys
            .get(validator_id)
            .cloned()
            .or_else(|| crate::consensus::pq_key_at_height(validator_id, height))
            .or_else(|| self.state.get_pinned_pubkey(validator_id));
        let Some((scheme, pk)) = key_opt else {
            return Err("proposal: CN-VRF v3 commit validator has no active PQ key".to_string());
        };
        if scheme.is_disabled() || pk.len() != crate::cn_vrf::CNVRF_PK_LEN {
            return Err(
                "proposal: CN-VRF v3 commit validator has invalid PQ key scheme or length"
                    .to_string(),
            );
        }
        Ok((scheme, pk))
    }

    /// Enqueue a gossiped peer [`crate::cn_vrf::CommitCarrierV3`] to be included
    /// in our next block proposal before `H_freeze`. Deduplicated and bounded.
    pub fn enqueue_peer_cnvrf_v3_commit(&mut self, carrier: crate::cn_vrf::CommitCarrierV3) {
        if !self.cnvrf_v3_is_active_at(self.hc.height) {
            return;
        }
        let current_epoch = crate::cn_vrf::epoch_of_height(self.hc.height);
        if carrier.epoch_n != current_epoch.saturating_add(1) {
            return;
        }
        let h_freeze = carrier
            .epoch_n
            .saturating_mul(crate::cn_vrf::EPOCH_LEN)
            .saturating_sub(crate::cn_vrf::V3_COMMIT_LOOKAHEAD_BLOCKS);
        if self.hc.height >= h_freeze {
            return;
        }
        if self
            .cnvrf_v3_mirror
            .get_record(&carrier.validator_id, carrier.epoch_n)
            .is_some()
        {
            return;
        }
        if self
            .pending_cnvrf_v3_commits
            .iter()
            .any(|c| c.validator_id == carrier.validator_id && c.epoch_n == carrier.epoch_n)
        {
            return;
        }
        if self.pending_cnvrf_v3_commits.len() >= MAX_PENDING_CNVRF_V3_COMMITS {
            return;
        }
        let Ok((_, pk)) = self.resolve_validator_pq_key_sync(&carrier.validator_id, self.hc.height)
        else {
            return;
        };
        if crate::cn_vrf::cnvrf_v3_verify_commit(&carrier, self.cnvrf_v3_chain_id, &pk).is_err() {
            return;
        }
        self.pending_cnvrf_v3_commits.push(carrier);
    }

    /// Restore CN-VRF v3 state mirrors on boot and verify local `enc2:` secret
    /// custody against any existing on-chain commitments for `self.id`.
    pub async fn sync_cnvrf_v3_on_boot(&mut self) {
        self.finalized_epoch_beacons = self.state.epoch_vdf_beacons_read().await.clone();
        let v3_state = self.state.cnvrf_v3_read().await.clone();
        self.cnvrf_v3_mirror = v3_state.clone();

        if !self.cnvrf_v3_is_active_at(self.hc.height) {
            return;
        }

        let current_epoch = crate::cn_vrf::epoch_of_height(self.hc.height);
        for epoch in [current_epoch, current_epoch.saturating_add(1)] {
            let Some(rec) = v3_state.get_record(&self.id, epoch) else {
                continue;
            };
            if let Some(existing) = self.cnvrf_v3_chains.get(&epoch) {
                if existing.anchors() == &rec.anchors
                    && existing.validator_id() == &rec.anchor_validator_id
                {
                    self.cnvrf_v3_disabled_epochs.remove(&epoch);
                    continue;
                }
            }
            if let Some(path) = self.cnvrf_v3_secret_path(epoch) {
                if !path.exists() {
                    tracing::error!(
                        validator = %hex::encode(self.id),
                        epoch,
                        path = %path.display(),
                        "CN-VRF v3 secret file missing for on-chain commitment; disabling local reveal/propose for this epoch"
                    );
                    self.cnvrf_v3_disabled_epochs.insert(epoch);
                    continue;
                }
                match crate::cn_vrf::load_cnvrf_v3_secret(&path) {
                    Ok(secret) => {
                        if crate::cn_vrf::verify_v3_secret_matches_commit(
                            &secret,
                            self.cnvrf_v3_chain_id,
                            &rec.anchor_validator_id,
                            epoch,
                            &rec.anchors,
                        ) {
                            let chain = crate::cn_vrf::CnVrfV3Chain::generate(
                                self.cnvrf_v3_chain_id,
                                &rec.anchor_validator_id,
                                epoch,
                                &secret,
                            );
                            self.cnvrf_v3_chains.insert(epoch, chain);
                            self.cnvrf_v3_disabled_epochs.remove(&epoch);
                        } else {
                            tracing::error!(
                                validator = %hex::encode(self.id),
                                epoch,
                                path = %path.display(),
                                "CN-VRF v3 secret on disk does NOT match on-chain commitment anchors; disabling local reveal/propose for this epoch"
                            );
                            self.cnvrf_v3_disabled_epochs.insert(epoch);
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            validator = %hex::encode(self.id),
                            epoch,
                            path = %path.display(),
                            error = %e,
                            "CN-VRF v3 failed to load encrypted secret for committed epoch; disabling local reveal/propose for this epoch"
                        );
                        self.cnvrf_v3_disabled_epochs.insert(epoch);
                    }
                }
            } else {
                tracing::error!(
                    validator = %hex::encode(self.id),
                    epoch,
                    "CN-VRF v3 on-chain commitment exists with no custody directory or matching in-memory chain; disabling local reveal/propose for this epoch"
                );
                self.cnvrf_v3_disabled_epochs.insert(epoch);
            }
        }

        // Also prepare next epoch's commitment if we are before H_freeze.
        if self.validators.validators.contains_key(&self.id) {
            let next_epoch = current_epoch.saturating_add(1);
            let h_freeze = next_epoch
                .saturating_mul(crate::cn_vrf::EPOCH_LEN)
                .saturating_sub(crate::cn_vrf::V3_COMMIT_LOOKAHEAD_BLOCKS);
            if self.hc.height < h_freeze {
                self.ensure_cnvrf_v3_chain_and_commit(next_epoch);
            }
        }
    }

    /// Ensure local `CnVrfV3Chain` + `CommitCarrierV3` exists for `epoch` (with
    /// write-ahead `enc2:` persistence BEFORE signing/queuing when `cnvrf_v3_dir`
    /// is configured).
    pub(super) fn ensure_cnvrf_v3_chain_and_commit(&mut self, epoch: u64) {
        if self.cnvrf_v3_disabled_epochs.contains(&epoch) {
            return;
        }
        if self.cnvrf_v3_mirror.get_record(&self.id, epoch).is_some() {
            return;
        }
        if let Some(chain) = self.cnvrf_v3_chains.get(&epoch) {
            if !self
                .pending_cnvrf_v3_commits
                .iter()
                .any(|c| c.validator_id == self.id && c.epoch_n == epoch)
            {
                if let Some(fk) = self.falcon_signing_key() {
                    let carrier = chain.commit_carrier(fk);
                    if self.pending_cnvrf_v3_commits.len() < MAX_PENDING_CNVRF_V3_COMMITS {
                        self.pending_cnvrf_v3_commits.push(carrier);
                    }
                }
            }
            return;
        }

        let secret: zeroize::Zeroizing<[u8; crate::cn_vrf::V3_LINK_LEN]> = if let Some(path) =
            self.cnvrf_v3_secret_path(epoch)
        {
            if path.exists() {
                match crate::cn_vrf::load_cnvrf_v3_secret(&path) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!(
                            validator = %hex::encode(self.id),
                            epoch,
                            path = %path.display(),
                            error = %e,
                            "CN-VRF v3 failed to load existing epoch secret; refusing to commit"
                        );
                        self.cnvrf_v3_disabled_epochs.insert(epoch);
                        return;
                    }
                }
            } else {
                let mut raw = zeroize::Zeroizing::new([0u8; crate::cn_vrf::V3_LINK_LEN]);
                if self.deterministic_sim_signing {
                    let derived = crate::cn_vrf::derive_v3_epoch_secret(
                        &self.key.to_bytes(),
                        self.cnvrf_v3_chain_id,
                        &self.id,
                        epoch,
                    );
                    raw.copy_from_slice(&*derived);
                } else {
                    use rand::RngCore as _;
                    rand::rngs::OsRng.fill_bytes(&mut *raw);
                }
                // Write-ahead persist enc2: secret BEFORE signing/queuing CommitCarrierV3.
                if let Err(e) = crate::cn_vrf::save_cnvrf_v3_secret(&path, &raw) {
                    tracing::error!(
                        validator = %hex::encode(self.id),
                        epoch,
                        path = %path.display(),
                        error = %e,
                        "CN-VRF v3 write-ahead secret persistence failed; refusing to sign/queue CommitCarrierV3"
                    );
                    return;
                }
                raw
            }
        } else if self.deterministic_sim_signing {
            crate::cn_vrf::derive_v3_epoch_secret(
                &self.key.to_bytes(),
                self.cnvrf_v3_chain_id,
                &self.id,
                epoch,
            )
        } else {
            use rand::RngCore as _;
            let mut raw = zeroize::Zeroizing::new([0u8; crate::cn_vrf::V3_LINK_LEN]);
            rand::rngs::OsRng.fill_bytes(&mut *raw);
            raw
        };

        let Some(fk) = self.falcon_signing_key() else {
            return;
        };
        let chain =
            crate::cn_vrf::CnVrfV3Chain::generate(self.cnvrf_v3_chain_id, &self.id, epoch, &secret);
        let carrier = chain.commit_carrier(fk);
        self.cnvrf_v3_chains.insert(epoch, chain);
        if self.pending_cnvrf_v3_commits.len() < MAX_PENDING_CNVRF_V3_COMMITS
            && !self
                .pending_cnvrf_v3_commits
                .iter()
                .any(|c| c.validator_id == self.id && c.epoch_n == epoch)
        {
            self.pending_cnvrf_v3_commits.push(carrier);
        }
    }

    /// Build the CN-VRF v3 payload a proposal at `height` must carry.
    ///
    /// Only the proposer's own chain step, our queued peer commit carriers,
    /// and (on an epoch boundary) the ready `MinRoot` beacon travel with the
    /// block — never another validator's reveal, and never a value we cannot
    /// prove. `None` below the gate and when there is nothing to publish, so
    /// pre-activation blocks keep their legacy wire shape and hash.
    pub(super) fn build_cnvrf_v3_payload(
        &mut self,
        height: Height,
    ) -> Option<crate::sharding::CnVrfV3BlockPayload> {
        if !self.cnvrf_v3_is_active_at(height) {
            return None;
        }
        let epoch = crate::cn_vrf::epoch_of_height(height);

        // A reveal may be emitted ONLY for an epoch whose commitment is already
        // ON-CHAIN (`epoch == current + 1` at commit time, so the record for
        // the current epoch can only come from the previous epoch's proposal).
        // Emitting one without a record would be refused by every peer as
        // `UnexpectedReveal` — and rightly so: the chain would be unverifiable.
        let reveal = if self.cnvrf_v3_mirror.get_record(&self.id, epoch).is_some() {
            self.cnvrf_v3_chains
                .get(&epoch)
                .and_then(|chain| chain.reveal_for_slot(height % crate::cn_vrf::EPOCH_LEN))
        } else {
            None
        };
        let commits = self.collect_pending_cnvrf_v3_commits(height);
        let epoch_vdf = if height.is_multiple_of(crate::cn_vrf::EPOCH_LEN)
            && height >= crate::cn_vrf::EPOCH_LEN
        {
            self.ready_vdf_beacons
                .get(&(height / crate::cn_vrf::EPOCH_LEN))
                .cloned()
        } else {
            None
        };

        let payload = crate::sharding::CnVrfV3BlockPayload {
            reveal,
            commits,
            epoch_vdf,
        };
        if payload.is_empty() {
            None
        } else {
            Some(payload)
        }
    }

    /// Collect canonical, verified, non-expired, deduplicated pending
    /// `CommitCarrierV3` entries admissible at `height`.
    pub(super) fn collect_pending_cnvrf_v3_commits(
        &self,
        height: Height,
    ) -> Vec<crate::cn_vrf::CommitCarrierV3> {
        let current_epoch = crate::cn_vrf::epoch_of_height(height);
        let target_epoch = current_epoch.saturating_add(1);
        let h_freeze = target_epoch
            .saturating_mul(crate::cn_vrf::EPOCH_LEN)
            .saturating_sub(crate::cn_vrf::V3_COMMIT_LOOKAHEAD_BLOCKS);
        if height >= h_freeze {
            return Vec::new();
        }
        let mut out: Vec<crate::cn_vrf::CommitCarrierV3> = self
            .pending_cnvrf_v3_commits
            .iter()
            .filter(|c| {
                if c.epoch_n != target_epoch {
                    return false;
                }
                if self
                    .cnvrf_v3_mirror
                    .get_record(&c.validator_id, c.epoch_n)
                    .is_some()
                {
                    return false;
                }
                let Ok((_, pk)) = self.resolve_validator_pq_key_sync(&c.validator_id, height)
                else {
                    return false;
                };
                crate::cn_vrf::cnvrf_v3_verify_commit(c, self.cnvrf_v3_chain_id, &pk).is_ok()
            })
            .cloned()
            .collect();
        out.sort_by(|a, b| {
            a.validator_id
                .cmp(&b.validator_id)
                .then_with(|| a.epoch_n.cmp(&b.epoch_n))
        });
        out.dedup_by(|a, b| a.validator_id == b.validator_id && a.epoch_n == b.epoch_n);
        out.truncate(MAX_CNVRF_V3_COMMITS_PER_BLOCK);
        out
    }

    /// Epoch hooks run on every finalized-block advance (`install_apply_outcome`,
    /// `try_finalize`, and `apply_and_advance`): refreshes synchronous CN-VRF v3
    /// mirrors, prepares `next_epoch` commitment before `H_freeze`, and dispatches
    /// `VdfLane::submit` at `H_freeze`.
    pub async fn prepare_cnvrf_v3_epoch_hooks(
        &mut self,
        finalized_height: Height,
        finalized_hash: BlockHash,
    ) {
        self.poll_vdf_lane();

        let next_height = finalized_height.saturating_add(1);
        if !self.cnvrf_v3_is_active_at(next_height) && !self.cnvrf_v3_is_active_at(finalized_height)
        {
            return;
        }

        // Refresh synchronous mirrors from the authoritative state engine.
        self.finalized_epoch_beacons = self.state.epoch_vdf_beacons_read().await.clone();
        self.cnvrf_v3_mirror = self.state.cnvrf_v3_read().await.clone();

        let current_epoch = crate::cn_vrf::epoch_of_height(next_height);
        let min_keep_epoch = current_epoch.saturating_sub(1);
        self.cnvrf_v3_chains.retain(|&e, _| e >= min_keep_epoch);
        self.cnvrf_v3_disabled_epochs
            .retain(|&e| e >= min_keep_epoch);
        self.ready_vdf_beacons
            .retain(|&e, _| e >= min_keep_epoch && !self.finalized_epoch_beacons.contains_key(&e));
        self.pending_cnvrf_v3_commits.retain(|c| {
            let h_freeze = c
                .epoch_n
                .saturating_mul(crate::cn_vrf::EPOCH_LEN)
                .saturating_sub(crate::cn_vrf::V3_COMMIT_LOOKAHEAD_BLOCKS);
            c.epoch_n == current_epoch.saturating_add(1)
                && next_height < h_freeze
                && self
                    .cnvrf_v3_mirror
                    .get_record(&c.validator_id, c.epoch_n)
                    .is_none()
        });

        // At exact H_freeze: snapshot freeze inputs and dispatch VdfLane.
        if self.cnvrf_v3_is_active_at(finalized_height)
            && finalized_height >= crate::cn_vrf::V3_COMMIT_LOOKAHEAD_BLOCKS
        {
            if let Some(boundary) =
                finalized_height.checked_add(crate::cn_vrf::V3_COMMIT_LOOKAHEAD_BLOCKS)
            {
                if boundary.is_multiple_of(crate::cn_vrf::EPOCH_LEN) {
                    let target_epoch = boundary / crate::cn_vrf::EPOCH_LEN;
                    let prev_epoch = target_epoch.saturating_sub(1);
                    let freeze_mix = self.cnvrf_v3_mirror.rolling_mix_for_epoch(prev_epoch);
                    self.cnvrf_freeze_inputs
                        .insert(target_epoch, (finalized_hash, freeze_mix));

                    let already_done = self.finalized_epoch_beacons.contains_key(&target_epoch)
                        || self.ready_vdf_beacons.contains_key(&target_epoch)
                        || self
                            .pending_vdf_rx
                            .as_ref()
                            .is_some_and(|(e, _)| *e == target_epoch);
                    if !already_done {
                        // ONE seed rule (review F3): chain the predecessor's
                        // committed beacon, or its deterministic bootstrap
                        // beacon when that epoch never ran a VDF. The boundary
                        // validator derives the SAME value.
                        let raw_seed = crate::cn_vrf::epoch_seed(
                            self.cnvrf_v3_chain_id,
                            target_epoch,
                            self.finalized_epoch_beacons.get(&prev_epoch),
                            crate::cn_vrf::epoch_had_vdf(
                                prev_epoch,
                                self.cnvrf_v3_activation_height(),
                            ),
                            &finalized_hash,
                            &freeze_mix,
                        );
                        let lane = self.ensure_vdf_lane();
                        let rx = lane.submit(target_epoch, raw_seed, self.cnvrf_v3_vdf_steps, 16);
                        self.pending_vdf_rx = Some((target_epoch, rx));
                    }
                }
            }
        }

        // Before H_freeze of next_epoch, ensure local chain + commit exist.
        if self.cnvrf_v3_is_active_at(next_height)
            && self.validators.validators.contains_key(&self.id)
        {
            let next_epoch = current_epoch.saturating_add(1);
            let h_freeze = next_epoch
                .saturating_mul(crate::cn_vrf::EPOCH_LEN)
                .saturating_sub(crate::cn_vrf::V3_COMMIT_LOOKAHEAD_BLOCKS);
            if next_height < h_freeze {
                self.ensure_cnvrf_v3_chain_and_commit(next_epoch);
            }
        }
    }

    pub(super) fn expected_proposer_at(
        &self,
        validators: &ValidatorSet,
        height: Height,
        round: crate::consensus::Round,
    ) -> Option<ValidatorId> {
        validators.proposer_for_with_schedule(height, round, self.committee_schedule_at(height))
    }

    pub(super) fn verify_qc_for_height(
        &self,
        qc: &crate::consensus::QuorumCertificate,
        validators: &ValidatorSet,
    ) -> bool {
        qc.verify_with_schedule(validators, self.committee_schedule_at(qc.height))
    }

    /// Verify a QC AND return the power its verified signers carry under
    /// `validators`, in one attribution pass (live adoption path).
    ///
    /// Identical verdict/power to `verify_qc_for_height` followed by
    /// [`Self::qc_signed_power_for_height`], without verifying every
    /// signature twice.
    pub(super) fn verify_qc_for_height_with_power(
        &self,
        qc: &crate::consensus::QuorumCertificate,
        validators: &ValidatorSet,
    ) -> (bool, u64) {
        qc.verify_and_signed_power_with_schedule(validators, self.committee_schedule_at(qc.height))
    }

    pub(super) fn qc_signed_power_for_height(
        &self,
        validators: &ValidatorSet,
        qc: &crate::consensus::QuorumCertificate,
    ) -> u64 {
        validators.qc_signed_power_with_schedule(qc, self.committee_schedule_at(qc.height))
    }

    /// Who the schedule names for OUR current (height, round).
    ///
    /// Parent-hash schedule below `CNVRF_V3_ACTIVATION_HEIGHT`; epoch-beacon
    /// schedule at/above it (fail-closed `None` when the epoch beacon is not
    /// known yet, exactly like `ValidatorSet::proposer_for_with_beacon`).
    pub fn expected_proposer_now(&self) -> Option<ValidatorId> {
        self.expected_proposer_at(&self.hc.validators, self.hc.height, self.hc.round)
    }

    /// Validate the CN-VRF v3 payload of `block` when the gate is active.
    ///
    /// Pure mirror of what `state_engine::apply_cnvrf_v3` will do: every commit
    /// must be admissible (epoch `current + 1`, before `H_freeze`, Falcon
    /// signature valid under the validator's active PQ key, no conflicting
    /// re-commit) and the proposer reveal must be either a valid chain step, a
    /// deliberate omission by a COMMITTED proposer (the transition slashes
    /// that height), or no reveal at all by an uncommitted newcomer.
    ///
    /// Rejected verdicts (fail closed, so a proposer cannot stuff garbage the
    /// transition would silently ignore):
    /// * `InvalidReveal` — a commit exists but the bytes do not walk the chain;
    /// * `UnexpectedReveal` — no commit, yet the proposer injected a reveal;
    /// * unforgeable commit entry (bad signature / wrong epoch / past cutoff);
    /// * a boundary block that omits or mis-verifies its `MinRoot` epoch beacon.
    pub(super) fn validate_cnvrf_v3_payload(&self, block: &Block) -> Result<(), String> {
        use crate::cn_vrf::{
            epoch_of_height, SlotRevealOutcome, EPOCH_LEN, V3_COMMIT_LOOKAHEAD_BLOCKS,
        };

        let payload = block.cnvrf_v3.as_ref();
        if let Some(p) = payload {
            if p.commits.len() > MAX_CNVRF_V3_COMMITS_PER_BLOCK {
                return Err("proposal: CN-VRF v3 carries too many commit carriers".to_string());
            }
            // Commits are validated in canonical order against a CLONE of the
            // mirror: validation must never mutate consensus state.
            let mut scratch = self.cnvrf_v3_mirror.clone();
            let current_epoch = epoch_of_height(block.height);
            for carrier in &p.commits {
                if carrier.epoch_n <= current_epoch {
                    return Err("proposal: CN-VRF v3 commit for a stale/current epoch".to_string());
                }
                let h_freeze = carrier
                    .epoch_n
                    .saturating_mul(EPOCH_LEN)
                    .saturating_sub(V3_COMMIT_LOOKAHEAD_BLOCKS);
                if block.height >= h_freeze {
                    return Err("proposal: CN-VRF v3 commit past the freeze cutoff".to_string());
                }
                let (_, pk) =
                    self.resolve_validator_pq_key_sync(&carrier.validator_id, block.height)?;
                match scratch.admit_commit(carrier, block.height, self.cnvrf_v3_chain_id, &pk) {
                    Ok(_) => {}
                    Err(e) => {
                        return Err(format!(
                            "proposal: CN-VRF v3 commit for {} rejected: {e}",
                            hex::encode(&carrier.validator_id[..8])
                        ))
                    }
                }
            }

            let reveal = p.reveal.as_ref();
            match scratch.apply_slot_reveal(
                self.cnvrf_v3_chain_id,
                &block.proposer,
                block.height,
                reveal,
            ) {
                // A committed proposer that omits its step is ACCEPTED here on
                // purpose: the apply transition charges it through the
                // leaky-bucket abort counter (that is the only way an abort
                // can ever be slashed on-chain — rejecting the block would let
                // an offender escape by simply never proposing again).
                SlotRevealOutcome::Revealed { .. }
                | SlotRevealOutcome::CommittedMissingReveal
                | SlotRevealOutcome::AbsentNoCommit => {}
                SlotRevealOutcome::InvalidReveal => {
                    return Err(
                        "proposal: CN-VRF v3 proposer reveal does not walk its committed chain"
                            .to_string(),
                    )
                }
                SlotRevealOutcome::UnexpectedReveal => {
                    return Err(
                        "proposal: CN-VRF v3 reveal from a proposer with no commitment".to_string(),
                    )
                }
            }
        }

        // Epoch-boundary beacon: REQUIRED once a previous epoch's VDF could
        // exist (epoch >= 1), verified against the freeze input this node
        // recorded at `H_freeze`.
        if block.height.is_multiple_of(EPOCH_LEN) && block.height >= EPOCH_LEN {
            let epoch = block.height / EPOCH_LEN;
            let Some(vdf) = payload.and_then(|p| p.epoch_vdf.as_ref()) else {
                return Err(format!(
                    "proposal: boundary block {} omits the epoch {epoch} MinRoot VDF beacon",
                    block.height
                ));
            };
            if vdf.epoch != epoch {
                return Err(format!(
                    "proposal: epoch VDF beacon names epoch {} but the block is {}",
                    vdf.epoch, epoch
                ));
            }
            if vdf.proof.steps != self.cnvrf_v3_vdf_steps {
                return Err(format!(
                    "proposal: epoch VDF beacon uses {} steps, the network agrees on {}",
                    vdf.proof.steps, self.cnvrf_v3_vdf_steps
                ));
            }
            // The seed is checked ONLY when this node recorded the freeze
            // input itself: a node that joined after `H_freeze` has nothing to
            // contradict, and manufacturing a claim from zeros would reject a
            // beacon the quorum already verified (the same principle as
            // `check_epoch_mmr_commitment`). The MinRoot proof below is
            // self-contained and always enforced.
            //
            // ONE seed rule (review F3): the SAME `epoch_seed` the producer and
            // `apply_cnvrf_v3` call. The predecessor's beacon is its committed
            // on-chain beacon, or the deterministic bootstrap beacon when that
            // epoch's `H_freeze` preceded activation — never a bare zero link
            // (that mismatch made the first post-activation boundary
            // unverifiable).
            if let Some((freeze_hash, freeze_mix)) = self.cnvrf_freeze_inputs.get(&epoch).copied() {
                let prev_epoch = epoch.saturating_sub(1);
                let expected_seed = crate::cn_vrf::epoch_seed(
                    self.cnvrf_v3_chain_id,
                    epoch,
                    self.finalized_epoch_beacons.get(&prev_epoch),
                    crate::cn_vrf::epoch_had_vdf(prev_epoch, self.cnvrf_v3_activation_height()),
                    &freeze_hash,
                    &freeze_mix,
                );
                if vdf.raw_seed != expected_seed {
                    return Err(format!(
                        "proposal: epoch VDF beacon {epoch} does not match the freeze input"
                    ));
                }
            }
            if crate::minroot_vdf::verify(&vdf.raw_seed, vdf.proof.steps, &vdf.proof).is_none() {
                return Err(format!(
                    "proposal: epoch VDF beacon {epoch} fails MinRoot verification"
                ));
            }
        } else if let Some(p) = payload {
            if p.epoch_vdf.is_some() {
                return Err("proposal: epoch VDF beacon on a non-boundary height".to_string());
            }
        }

        Ok(())
    }

    /// Attach the node's LIGHT CLIENT, anchored at the chain's GENESIS.
    ///
    /// The genesis state root is the one this node built its own genesis
    /// from, so it is trusted BY CONSTRUCTION; every block above it must
    /// carry a quorum certificate, and every peer-supplied block is checked
    /// against this anchor before it is applied (see
    /// `crate::sync::verify_synced_blocks_against_anchor`).
    pub fn set_light_client(
        &mut self,
        validators: ValidatorSet,
        genesis_root: [u8; 32],
    ) -> Result<(), String> {
        let light = crate::light_client::LightClient::with_genesis_anchor(
            validators,
            crate::sync::genesis_light_anchor(genesis_root),
        )?;
        self.light = Some(light);
        self.configure_light_client_cnvrf_v3();
        Ok(())
    }

    /// Teach the node's light client the CN-VRF v3 activation height, the chain
    /// id (bootstrap-beacon derivation) and every epoch beacon this node has
    /// finalized — otherwise its beacon-aware verification fails closed on the
    /// first post-activation header (review F2's light-client leg).
    pub(super) fn configure_light_client_cnvrf_v3(&mut self) {
        let chain_id = self.cnvrf_v3_chain_id;
        let activation = self.cnvrf_v3_activation_height();
        let beacons: Vec<(u64, [u8; 48])> = self
            .finalized_epoch_beacons
            .iter()
            .map(|(e, b)| (*e, *b))
            .collect();
        if let Some(light) = self.light.as_mut() {
            light.configure_cnvrf_v3(chain_id, activation);
            for (epoch, output) in beacons {
                light.record_epoch_beacon(epoch, output);
            }
        }
    }

    /// The node's light client, if it has one.
    pub fn light_client(&self) -> Option<&crate::light_client::LightClient> {
        self.light.as_ref()
    }

    /// Configure a Falcon-512 keypair for post-quantum consensus voting and proposal signing.
    pub fn with_falcon_key(mut self, key: FalconKeypair) -> Self {
        crate::consensus::register_validator_pq_key(
            self.id,
            crate::post_quantum::PqScheme::Falcon512,
            key.public_key.clone(),
        );
        let falcon_id = key.validator_id();
        if falcon_id != self.id {
            crate::consensus::register_validator_pq_key(
                falcon_id,
                crate::post_quantum::PqScheme::Falcon512,
                key.public_key.clone(),
            );
        }
        self.falcon_key = Some(key);
        self
    }

    /// Enable seeded Falcon vote signing for reproducible simulator runs.
    pub fn with_deterministic_sim_signing(mut self) -> Self {
        self.deterministic_sim_signing = true;
        self
    }

    /// Falcon keypair to sign a proposal or vote with, or `None` when signing
    /// must be REFUSED.
    ///
    /// Under Pure PQ a missing keypair is a hard stop, never a derivation
    /// fallback. The old fallback did
    /// `FalconKeypair::generate_from_seed(self.id[0])`, i.e. derived a PRIVATE
    /// key from a single byte of the PUBLIC validator id: 256 candidate
    /// keypairs total, so anyone who reads the validator's id out of
    /// `node.yaml` could reproduce its private key and forge its proposals and
    /// votes. That is exactly the failure `main.rs` warns about on the real key
    /// path ("deriving a PRIVATE key deterministically from a PUBLIC validator
    /// id would let anyone forge any validator's votes").
    ///
    /// Production always installs a persisted key via
    /// [`ValidatorRuntime::with_falcon_key`] before consensus starts, so this
    /// only fires for a misconfigured runtime - where not signing is the safe
    /// outcome: the set refuses to accept a vote it cannot attribute.
    pub(super) fn falcon_signing_key(&self) -> Option<&FalconKeypair> {
        if let Some(k) = &self.falcon_key {
            return Some(k);
        }
        if crate::post_quantum::is_pure_pq_enforced() {
            tracing::error!(
                "[post-quantum] Pure PQ requires a persisted Falcon-512 keypair and this \
                 validator has none; refusing to sign proposals/votes (a derived key would \
                 be forgeable from the public validator id)"
            );
        }
        None
    }

    /// Run this runtime as a specific shard of a multi-shard process.
    ///
    /// With the default registry (`is_sharded() == false`) this only sets the
    /// block's `shard_id`; the shard-aware proposal checks and the mempool
    /// target filter stay off, so single-shard behaviour is unchanged.
    pub fn with_shard(mut self, shard_id: ShardId, registry: ShardRegistry) -> Self {
        self.shard_id = shard_id;
        // A genuine multi-shard process turns on cross-shard execution on the
        // engine. A single-shard registry leaves it off, so the historical
        // "always credit `to`" semantics (and every pre-sharding test) hold.
        if registry.is_sharded() {
            self.state.enable_cross_shard();
        }
        self.shard_registry = registry;
        self
    }

    /// Share the MASTERCHAIN's staking ledger with this runtime.
    ///
    /// The masterchain runtime passes its OWN ledger handle (its state
    /// engine's — the registry it commits), and every workchain runtime of
    /// the same process passes THE SAME handle. From then on a rotation on
    /// the masterchain (bond / unbond / slash) is visible to the workchain's
    /// consensus, which adopts the new [`ValidatorSet`] at its next height
    /// boundary — no restart, no second registry.
    ///
    /// The handle is an ALIAS, never a copy: two copies could disagree about
    /// who the validators are, and the validator set decides who proposes.
    pub fn with_master_staking(mut self, master: MasterStakingLedger) -> Self {
        self.master_staking = Some(master);
        self
    }

    /// Attach the node-local cross-shard transport (shared with the process's
    /// other shard runtimes). Without one, a sharded runtime produces and
    /// consumes no cross-shard messages.
    pub fn with_cross_shard(mut self, transport: Arc<crate::network::CrossShardTransport>) -> Self {
        self.cross_shard = Some(transport);
        self
    }

    /// Attach the process-shared finalized-header registry (C1 anchor).
    /// Same `Arc` for every shard runtime and engine in the process.
    pub fn with_finalized_headers(
        mut self,
        registry: Arc<std::sync::RwLock<crate::sharding::FinalizedHeaderRegistry>>,
    ) -> Self {
        self.finalized_headers = Some(registry);
        self
    }

    /// Record a finalized block's header for cross-shard anchoring. Called
    /// on every finalize path (live, adopt, walk); idempotent.
    ///
    /// The FULL header is recorded (height, block hash, state root,
    /// timestamp), not just the root: the masterchain reads the registry to
    /// publish the shard-head commitments (TON `shard_hashes`), and a
    /// commitment is only verifiable when it names the shard block it
    /// commits to.
    ///
    /// The ANCHOR map gets a second entry: the state root the shard reached
    /// AFTER applying this block. A cross-shard message carries the root its
    /// inclusion proof was made against, and it names the PARENT block - so
    /// the anchor it is checked against is the parent's POST-APPLY root. The
    /// block's own DECLARED root is its parent's pre-state, which is a
    /// different value; anchoring against it made every transfer produced
    /// after a state-changing block unverifiable at the target (the transfer
    /// was silently never consumed).
    pub async fn note_finalized_header(&self, block: &Block) {
        // The post-apply root: the state this shard is in NOW that the block
        // has been applied. Read BEFORE the lock (the lock guard is not
        // `Send`, so it may not be held across an await) and AFTER the apply
        // (this runs on the finalize path), so it is exactly the root the
        // next block will be built on - the root a cross-shard message
        // produced by the next block carries.
        let post_apply_root = self.state.get_state_root().await;
        if let Some(reg) = self.finalized_headers.as_ref() {
            if let Ok(mut r) = reg.write() {
                let block_hash = block.compute_hash();
                // ONE mutation (and therefore one durable snapshot): the head
                // commitment AND its post-apply anchor land together, so a
                // restart sees the exact pair the runtime verified against.
                r.note_finalized_commitment_with_anchor(
                    crate::sharding::ShardHeaderCommitment {
                        shard_id: block.shard_id,
                        height: block.height,
                        block_hash,
                        state_root: block.state_root,
                        timestamp: block.timestamp,
                    },
                    post_apply_root,
                );
            }
        }
    }

    /// Keep the node's LIGHT CLIENT in step with the chain it finalizes.
    ///
    /// The light client is the node's TRUSTED ANCHOR: a peer chain is
    /// accepted only if it extends the quorum-certified chain this node
    /// finalized (see `crate::sync::verify_synced_blocks_against_anchor`),
    /// and the roots this node will answer proofs against are the ones a
    /// quorum committed to.
    ///
    /// Called on every finalize path (live, adopt, walk), right after the
    /// header was recorded. A block with no precommit quorum certificate is
    /// not DECIDED, so it is not an anchor and is ignored here.
    ///
    /// Three steps, in order, so a re-anchored chain (a rotation, a re-apply)
    /// can never leave the light client pointing at a chain the node has left:
    ///  1. accept the header on top of the current tip;
    ///  2. otherwise re-anchor on this finalized head (the window is full, or
    ///     the chain moved);
    ///  3. otherwise rebuild the client anchored at this finalized head.
    pub fn note_light_anchor(&mut self, block: &Block) {
        if self.light.is_none() {
            return;
        }
        let Some(header) = crate::light_client::LightHeader::of_block(block) else {
            // No quorum certificate: nothing decided, nothing to anchor on.
            return;
        };
        // The validator set rotates with the chain, and a certificate is
        // checked under the set that was in force at ITS height. The node's
        // current set is that set (the same simplification `validate_sync_chain`
        // makes — see its F5 note).
        let cnvrf_chain_id = self.cnvrf_v3_chain_id;
        let cnvrf_activation = self.cnvrf_v3_activation_height();
        let cnvrf_beacons: Vec<(u64, [u8; 48])> = self
            .finalized_epoch_beacons
            .iter()
            .map(|(e, b)| (*e, *b))
            .collect();
        if let Some(light) = self.light.as_mut() {
            light.validators = self.validators.clone();
            light.configure_cnvrf_v3(cnvrf_chain_id, cnvrf_activation);
            for (epoch, output) in cnvrf_beacons.iter() {
                light.record_epoch_beacon(*epoch, *output);
            }
            if light.apply_header(header.clone()).is_ok() {
                return;
            }
        }
        let cp = header.checkpoint();
        let rebuilt = match self.light.as_mut() {
            Some(light) => light.advance_to_checkpoint(cp.clone()).is_ok(),
            None => false,
        };
        if rebuilt {
            return;
        }
        // Last resort: rebuild the client anchored at this finalized head.
        // The chain BELOW the anchor was verified when this node finalized it,
        // and the anchor itself is quorum-certified, so the light client is
        // sound from here on.
        match crate::light_client::LightClient::with_checkpoint_under_cnvrf_v3(
            self.validators.clone(),
            cp,
            cnvrf_chain_id,
            cnvrf_activation,
        ) {
            Ok(mut fresh) => {
                for (epoch, output) in cnvrf_beacons.iter() {
                    fresh.record_epoch_beacon(*epoch, *output);
                }
                tracing::warn!(
                    "[light-client] rebuilt the anchor at height {} (the previous anchor was inconsistent)",
                    block.height
                );
                self.light = Some(fresh);
            }
            Err(e) => {
                tracing::error!(
                    "[light-client] could not anchor at height {}: {e}",
                    block.height
                );
            }
        }
    }

    /// Re-anchor the light client at a snapshot-sync boundary.
    ///
    /// `try_snapshot_sync` (main.rs) jumps the finalized head and the
    /// consensus height to a QC-verified boundary, but the light client
    /// stays anchored at genesis and expects block 1 next — so the
    /// subsequent body walk refuses every tail block ("leaves a gap;
    /// expected 1") and a node that jumped can never close its final gap
    /// (live 2026-10-25: B/D parked at 296000/297000, walk refused
    /// forever). This re-anchors the client AT the verified boundary using
    /// the boundary block's own precommit QC, verified against the set in
    /// force AT the boundary height (never the live set).
    ///
    /// Fail-closed on every mismatch (no light client, no QC on the block,
    /// height/hash/linkage mismatch, QC failure): the old anchor — and
    /// today's walk refusal — is left untouched, loudly.
    pub fn reanchor_light_client_at_snapshot(&mut self, boundary: u64, block: &Block) {
        if self.light.is_none() {
            return;
        }
        let vs = self.validator_set_for_height(boundary);
        let Some(header) = crate::light_client::LightHeader::of_block(block) else {
            tracing::error!(
                boundary,
                "REFUSING light-client re-anchor: boundary block carries no precommit QC"
            );
            eprintln!(
                "[light-client] REFUSING re-anchor at height {boundary}: boundary block carries no precommit QC"
            );
            return;
        };
        if header.height != boundary || header.block_hash != block.compute_hash() {
            tracing::error!(
                boundary,
                "REFUSING light-client re-anchor: boundary block height/hash mismatch"
            );
            eprintln!(
                "[light-client] REFUSING re-anchor at height {boundary}: boundary block height/hash mismatch"
            );
            return;
        }
        let expected_prev = self.finalized.last().map(|(_, h)| *h).unwrap_or([0u8; 32]);
        if header.block_hash != expected_prev {
            tracing::error!(
                boundary,
                "REFUSING light-client re-anchor: boundary block does not extend our finalized head"
            );
            eprintln!(
                "[light-client] REFUSING re-anchor at height {boundary}: boundary block does not extend our finalized head"
            );
            return;
        }
        let cnvrf_chain_id = self.cnvrf_v3_chain_id;
        let cnvrf_activation = self.cnvrf_v3_activation_height();
        let cnvrf_beacons: Vec<(u64, [u8; 48])> = self
            .finalized_epoch_beacons
            .iter()
            .map(|(e, b)| (*e, *b))
            .collect();
        if let Some(light) = self.light.as_mut() {
            light.validators = vs.clone();
            light.configure_cnvrf_v3(cnvrf_chain_id, cnvrf_activation);
            for (epoch, output) in cnvrf_beacons.iter() {
                light.record_epoch_beacon(*epoch, *output);
            }
            if light.apply_header(header.clone()).is_ok() {
                return;
            }
        }
        let cp = header.checkpoint();
        if let Some(light) = self.light.as_mut() {
            if light.advance_to_checkpoint(cp.clone()).is_ok() {
                tracing::warn!(
                    "[light-client] advanced the anchor to snapshot boundary {boundary}"
                );
                return;
            }
        }
        match crate::light_client::LightClient::with_checkpoint_under_cnvrf_v3(
            vs,
            cp,
            cnvrf_chain_id,
            cnvrf_activation,
        ) {
            Ok(mut fresh) => {
                for (epoch, output) in cnvrf_beacons.iter() {
                    fresh.record_epoch_beacon(*epoch, *output);
                }
                tracing::warn!("[light-client] rebuilt the anchor at snapshot boundary {boundary}");
                self.light = Some(fresh);
            }
            Err(e) => {
                tracing::error!(
                    boundary,
                    "REFUSING light-client re-anchor: could not anchor at snapshot boundary: {e}"
                );
                eprintln!(
                    "[light-client] REFUSING re-anchor at height {boundary}: could not anchor at snapshot boundary: {e}"
                );
            }
        }
    }

    /// The shard-head commitments a block of THIS shard publishes.
    ///
    /// Only a MASTERCHAIN block publishes shard heads, and only for the
    /// WORKCHAIN shards (id >= 1) — a block never commits to its own head.
    /// The set comes from the process-shared finalized-header registry, so it
    /// holds exactly the shards this process has finalized a header for, in
    /// ascending shard order (canonical — the set is hashed as a sequence,
    /// so a fixed order is what keeps the block hash deterministic).
    ///
    /// A missing or contended registry yields an EMPTY set: the block still
    /// proposes, it just commits to no shard head this round (the next block
    /// picks them up). That keeps a lock contention from stalling the
    /// masterchain.
    pub(super) fn collect_shard_header_commitments(
        &self,
    ) -> Vec<crate::sharding::ShardHeaderCommitment> {
        if self.shard_id != MASTERCHAIN_SHARD {
            return Vec::new();
        }
        let Some(reg) = self.finalized_headers.as_ref() else {
            return Vec::new();
        };
        let Ok(guard) = reg.read() else {
            return Vec::new();
        };
        let mut out = guard.workchain_headers();
        // Canonical order (ascending shard id), stated explicitly so the
        // block hash never depends on the registry's internal iteration.
        out.sort_by_key(|h| h.shard_id);
        out
    }

    /// The epoch-MMR root this proposal commits to (V5 Tier-2), if any.
    ///
    /// Only the first masterchain block of an epoch commits (height H with
    /// `H > 0` and `H % 128 == 0`, committing epoch `H / 128 - 1`), and only
    /// when this node finalized all 128 heights of that epoch. Otherwise —
    /// workchain, non-boundary height, pruned history, fresh restart — the
    /// block carries the all-zero root and hashes exactly like a legacy
    /// block. A proposer commits to a root it derived from its own
    /// finalized chain, never to a root it cannot prove.
    pub(super) fn epoch_mmr_commitment(&self) -> [u8; 32] {
        if self.shard_id != MASTERCHAIN_SHARD {
            return [0u8; 32];
        }
        let Some(epoch) = crate::mmr::commits_epoch_root(self.hc.height) else {
            return [0u8; 32];
        };
        self.chain
            .epoch_mmr_root(epoch)
            .map(|(root, _)| root)
            .unwrap_or([0u8; 32])
    }

    /// Check the epoch-MMR commitment of a proposal (V5 Tier-2).
    ///
    /// * a zero root is ALWAYS accepted: it means "not committed" (a
    ///   pre-MMR block, a non-boundary height, or a proposer that did not
    ///   know the epoch's bodies). Requiring a root would fork proposers
    ///   that pruned history from the ones that did not;
    /// * a non-zero root is accepted ONLY on a masterchain block at an
    ///   epoch-committing boundary height (the first height of an epoch,
    ///   committing the previous one — see `crate::mmr::commits_epoch_root`);
    /// * a non-zero root must not CONTRADICT this process's own finalized
    ///   chain: if we finalized all 128 heights of the committed epoch and
    ///   derive a different root, the proposal is refused. A node that has
    ///   not finalized the epoch yet has nothing to contradict, so it
    ///   accepts — the quorum that signs the block is the backstop.
    pub(super) fn check_epoch_mmr_commitment(&self, block: &Block) -> Result<(), String> {
        if block.mmr_epoch_root == [0u8; 32] {
            return Ok(());
        }
        if block.shard_id != MASTERCHAIN_SHARD {
            return Err(
                "proposal: epoch MMR root published by a non-masterchain block".to_string(),
            );
        }
        let Some(epoch) = crate::mmr::commits_epoch_root(block.height) else {
            return Err("proposal: epoch MMR root on a non-boundary height".to_string());
        };
        if let Some((mine, _)) = self.chain.epoch_mmr_root(epoch) {
            if mine != block.mmr_epoch_root {
                return Err(format!(
                    "proposal: epoch {epoch} MMR root contradicts the finalized chain"
                ));
            }
        }
        Ok(())
    }

    /// Check the shard-head commitments of a proposal (TON `shard_hashes`).
    ///
    /// * only a masterchain block may publish shard heads;
    /// * the set must be CANONICAL: strictly ascending shard ids, no
    ///   duplicates, and never an entry for the masterchain itself (a block
    ///   cannot commit to its own head);
    /// * the set must not CONTRADICT this process's own finalized headers: if
    ///   we finalized shard S at height H with hash X, a proposal committing
    ///   shard S at height H with a different hash or root is refused (that
    ///   is a shard-chain equivocation dressed up as a commitment).
    ///
    /// A node that has NOT finalized that shard yet (or is behind) has
    /// nothing to contradict, so the proposal is accepted — the commitment is
    /// still checked by the quorum that signs the block.
    pub(super) fn check_shard_header_commitments(&self, block: &Block) -> Result<(), String> {
        if block.shard_headers.is_empty() {
            return Ok(());
        }
        if block.shard_id != MASTERCHAIN_SHARD {
            return Err("proposal: shard heads published by a non-masterchain block".to_string());
        }
        if !block.shard_headers_canonical() {
            return Err("proposal: shard head set is not canonical".to_string());
        }
        if let Some(reg) = self.finalized_headers.as_ref().and_then(|r| r.read().ok()) {
            for h in &block.shard_headers {
                let Some(mine) = reg.latest_header(h.shard_id) else {
                    continue;
                };
                if mine.height == h.height
                    && (mine.block_hash != h.block_hash || mine.state_root != h.state_root)
                {
                    return Err(format!(
                        "proposal: shard {} head at height {} contradicts the finalized header",
                        h.shard_id, h.height
                    ));
                }
            }
        }
        Ok(())
    }

    /// Anchored inclusion check for one inbound message (C1): proof AND a
    /// locally-finalized source header with the claimed root. `false` covers
    /// both "forged" and "not finalized here yet" — callers treat it as
    /// not-ready (skip/refuse + retry after catching up), never as verified.
    pub fn verify_cross_shard_anchored(&self, msg: &CrossShardMessage) -> bool {
        let guard = self.finalized_headers.as_ref().and_then(|r| r.read().ok());
        let Some(reg) = guard.as_deref() else {
            return false;
        };
        msg.verify_anchored(Some(reg))
    }

    /// The §9 2PC admission rule for an OUTBOUND 2PC record.
    ///
    /// The outbound 2PC records (the target's vote, the source's decision,
    /// the abort request) are DERIVED from this shard's committed 2PC state,
    /// not from a transaction in the block. A validator therefore re-derives
    /// the same rule the proposer used:
    ///
    ///  * this shard holds the 2PC record of the transfer, in the phase the
    ///    record's kind implies (the target's vote only while PREPARED, the
    ///    source's decision only once COMMITTED, the abort request only
    ///    while PREPARED and past the prepare window);
    ///  * the record carries a valid Merkle proof of THAT state, against the
    ///    block's own state root, anchored to a finalized header of this
    ///    shard - so the peer can verify the vote;
    ///  * the direction matches the record (the target answers the source and
    ///    the other way round).
    ///
    /// A proposer that invents a vote the shard never made is refused.
    pub fn xpc_outbound_admissible(&self, msg: &CrossShardMessage, block: &Block) -> bool {
        use crate::sharding::CrossShardKind;
        use crate::xshard2pc::XpcPhase;
        let tx_hash = msg.tx.compute_tx_hash();
        // BOUNDED RE-EMIT: a shard may publish at most
        // `XPC_MAX_REEMITS_PER_HEIGHT` 2PC control messages per block, chosen
        // deterministically. Validation enforces the same bound on the
        // incoming block, so an over-eager proposer cannot amplify traffic.
        if matches!(
            msg.kind(),
            CrossShardKind::Prepare
                | CrossShardKind::PrepareAck
                | CrossShardKind::AbortRequest
                | CrossShardKind::AbortAck
        ) {
            let control = block
                .cross_shard_out
                .iter()
                .filter(|m| {
                    matches!(
                        m.kind(),
                        CrossShardKind::Prepare
                            | CrossShardKind::PrepareAck
                            | CrossShardKind::AbortRequest
                            | CrossShardKind::AbortAck
                    )
                })
                .count();
            if control > crate::xshard2pc::XPC_MAX_REEMITS_PER_HEIGHT {
                return false;
            }
        }
        // The OPENING record (the PREPARE) is the one 2PC record that is NOT
        // derived from an already-committed 2PC state: the source's PREPARED
        // record is created by the APPLICATION of this very block, so at
        // validation time it does not exist yet. It comes in TWO forms, and
        // both are admissible:
        //
        //   (a) the OPENING PREPARE: the TRANSACTION is in this block (so the
        //       debit that escrows the value happens in the same block that
        //       publishes the PREPARE), and the record proves the SENDER's
        //       leaf against the block's own state root (so the target can
        //       check that the sender really had the funds at the source's
        //       committed root);
        //
        //   (b) the RE-PUBLISHED PREPARE: the transaction is NOT in this
        //       block (it was escrowed by an earlier one), but this shard
        //       holds the transfer's PREPARED record and the record proves
        //       that leaf against the block's own state root. The PREPARED
        //       leaf IS the escrow, so the proof is strictly stronger than
        //       the account leaf: it says "the value is already escrowed
        //       here".
        //
        // A proposer that publishes a PREPARE for a transaction it is not
        // including and without holding the PREPARED record, or without the
        // matching proof, is refused.
        if msg.kind() == CrossShardKind::Prepare {
            let tx_present = block.transactions.iter().any(|t| {
                t.compute_tx_hash() == tx_hash
                    && crate::sharding::tx_is_outbound_cross_shard(t, self.shard_id)
            });
            if tx_present {
                if msg.source_state_root != block.state_root {
                    return false;
                }
                return msg.verify_inclusion_strict();
            }
            // Form (b): the re-published PREPARE.
            let Some(rec) = self.xpc_records.get(&tx_hash) else {
                return false;
            };
            if rec.source_shard != self.shard_id {
                return false;
            }
            if rec.phase != XpcPhase::Prepared {
                return false;
            }
            if !crate::xshard2pc::should_reprepare(rec, block.height) {
                return false;
            }
            if msg.source_state_root != block.state_root {
                return false;
            }
            return msg.verify_xpc_anchored(
                self.finalized_headers
                    .as_ref()
                    .and_then(|r| r.read().ok())
                    .as_deref(),
                &[XpcPhase::Prepared],
            );
        }
        let Some(rec) = self.xpc_records.get(&tx_hash) else {
            return false;
        };
        let (side_is_target, phase) = match msg.kind() {
            CrossShardKind::PrepareAck => (true, XpcPhase::Prepared),
            CrossShardKind::AbortAck => (true, XpcPhase::Aborted),
            CrossShardKind::Commit => (false, XpcPhase::Committed),
            CrossShardKind::AbortRequest => (false, XpcPhase::Prepared),
            _ => return false,
        };
        if side_is_target {
            if rec.target_shard != self.shard_id {
                return false;
            }
        } else if rec.source_shard != self.shard_id {
            return false;
        }
        if rec.phase != phase {
            return false;
        }
        // The abort request is only admissible once the prepare window
        // elapsed (the same rule the proposer used).
        if msg.kind() == CrossShardKind::AbortRequest
            && !matches!(
                crate::xshard2pc::source_action(rec, block.height),
                crate::xshard2pc::SourceAction::AbortRequest
            )
        {
            return false;
        }
        // The record must prove the state it claims, against the block's own
        // state root, and be anchored to a finalized header of this shard.
        if msg.source_state_root != block.state_root {
            return false;
        }
        msg.verify_xpc_anchored(
            self.finalized_headers
                .as_ref()
                .and_then(|r| r.read().ok())
                .as_deref(),
            &[phase],
        )
    }

    /// §5 M3: linkage rule for ack/bounce control records, checked at a given
    /// chain height (the proposed block's height at propose/validate time, the
    /// applied block's height at apply time).
    ///
    /// A control record is valid iff ALL hold:
    ///  * it carries NO Merkle proof and is NOT locally trusted. The engine
    ///    credits any proof-carrying inbound to `tx.to`, so a proof-carrying
    ///    reversed-direction record would mint on the source shard; refusing
    ///    it here (and skipping proof-less records in the engine) is what
    ///    makes the refund path safe without a state-engine change;
    ///  * its transaction's outbound transfer was committed on THIS chain
    ///    (`produced_cross_shard`, rebuilt from applied blocks);
    ///  * the transaction has not already completed (no ack/bounce committed);
    ///  * for a bounce, the height timeout has elapsed
    ///    (`bounce_eligible(produce_height, at_height)` — heights, not seconds).
    ///
    /// Unknown kinds fail closed (false).
    pub(super) fn control_linkage_ok(&self, msg: &CrossShardMessage, at_height: u64) -> bool {
        if !msg.is_ack() && !msg.is_bounce() {
            return false;
        }
        if msg.merkle_inclusion_proof.is_some() || msg.trusted {
            return false;
        }
        let tx_hash = msg.tx.compute_tx_hash();
        if self.completed_cross_shard.contains(&tx_hash) {
            return false;
        }
        let Some((_, produce_height)) = self.produced_cross_shard.get(&tx_hash) else {
            return false;
        };
        if msg.is_bounce() {
            return crate::sharding::bounce_eligible(*produce_height, at_height);
        }
        true
    }

    // ==================== §9 CROSS-SHARD 2PC ====================

    /// Set the §9 two-phase-commit activation switch.
    ///
    /// `FromHeight(h)` makes every transfer PRODUCED at height `h` or later
    /// run the 2PC; transfers produced before `h` keep running the legacy
    /// outbox/inbox/ack/bounce flow. The switch is node configuration (like
    /// the shard registry), but the HEIGHT it names is consensus-visible: it
    /// decides which flow a transfer takes, so every node of a shard must
    /// agree on it.
    pub fn with_xpc_activation(mut self, activation: crate::xshard2pc::XpcActivation) -> Self {
        self.xpc_activation = activation;
        self
    }

    /// The §9 2PC activation switch in force on this shard.
    pub fn xpc_activation(&self) -> crate::xshard2pc::XpcActivation {
        self.xpc_activation
    }

    /// True when this shard holds a §9 2PC record for the transfer.
    pub async fn xpc_owns(&self, tx_hash: &[u8; 32]) -> bool {
        self.state.xpc_record(tx_hash).await.is_some()
    }

    /// The §9 2PC admission rule for an INBOUND 2PC record.
    ///
    /// Every 2PC record carries a Merkle proof of the PEER's committed 2PC
    /// state, and that proof must check out against a state root a LOCALLY
    /// FINALIZED header of the peer shard committed to (the C1 anchor). A
    /// record that fails either test is refused, so a malicious peer cannot
    /// make this shard credit a recipient (a COMMIT) or authorise a refund
    /// (an ABORT-ACK) out of thin air.
    ///
    /// The proof is checked against the phases that are legitimate for the
    /// record's kind:
    ///  * PREPARE: EITHER the source's ACCOUNT leaf (the opening PREPARE -
    ///    the same proof the legacy transfer carries - it proves the sender
    ///    had the funds) OR the source's PREPARED leaf (the re-published
    ///    PREPARE - it proves the value is already escrowed at the source);
    ///  * PREPARE-ACK: the target's PREPARED leaf (its vote);
    ///  * COMMIT: the source's PREPARED or COMMITTED leaf (the source really
    ///    escrowed the value);
    ///  * ABORT-REQUEST: the source's PREPARED or COMMITTED leaf;
    ///  * ABORT-ACK: the target's ABORTED leaf (its authorisation - and the
    ///    target can only hold that leaf if it NEVER prepared).
    pub fn xpc_admissible(&self, msg: &CrossShardMessage) -> bool {
        use crate::sharding::CrossShardKind;
        use crate::xshard2pc::XpcPhase;
        let guard = self.finalized_headers.as_ref().and_then(|r| r.read().ok());
        let Some(reg) = guard.as_deref() else {
            // No anchor registry: fail closed (the C1 rule).
            return false;
        };
        match msg.kind() {
            CrossShardKind::Prepare => {
                // The opening PREPARE (the sender's account leaf) or the
                // re-published one (the source's PREPARED leaf). Both are
                // anchored to a finalized header of the source shard.
                msg.verify_anchored(Some(reg))
                    || msg.verify_xpc_anchored(Some(reg), &[XpcPhase::Prepared])
            }
            CrossShardKind::PrepareAck => msg.verify_xpc_anchored(Some(reg), &[XpcPhase::Prepared]),
            CrossShardKind::Commit | CrossShardKind::AbortRequest => {
                msg.verify_xpc_anchored(Some(reg), &[XpcPhase::Prepared, XpcPhase::Committed])
            }
            CrossShardKind::AbortAck => msg.verify_xpc_anchored(Some(reg), &[XpcPhase::Aborted]),
            _ => false,
        }
    }

    /// Producing height of a committed outbound transfer on this chain, if any
    /// (§5 M3; test/debug introspection over `produced_cross_shard`).
    pub fn produced_cross_shard_height(&self, tx_hash: &[u8; 32]) -> Option<u64> {
        self.produced_cross_shard.get(tx_hash).map(|(_, h)| *h)
    }

    /// True once an ack or bounce for `tx_hash` committed on this chain (§5 M3).
    pub fn is_transfer_completed(&self, tx_hash: &[u8; 32]) -> bool {
        self.completed_cross_shard.contains(tx_hash)
    }

    /// Snapshot the whole cross-shard replay state for persistence (audit
    /// F-I): the engine credit gate plus the three runtime mirrors, sorted
    /// for deterministic bytes. Called where the runtime is alive (periodic
    /// snapshot block); a fresh runtime snapshots empty sets, which is correct
    /// (nothing committed yet to protect).
    pub async fn cross_shard_replay_snapshot(&self) -> crate::sharding::CrossShardReplaySnapshot {
        let mut engine_consumed = self.state.cross_shard_consumed_snapshot().await;
        engine_consumed.sort();
        let mut runtime_consumed: Vec<crate::sharding::CrossShardKey> =
            self.consumed_cross_shard.iter().copied().collect();
        runtime_consumed.sort();
        let mut produced: Vec<([u8; 32], Transaction, u64)> = self
            .produced_cross_shard
            .iter()
            .map(|(h, (tx, height))| (*h, tx.clone(), *height))
            .collect();
        produced.sort_by_key(|(h, _, _)| *h);
        let mut completed: Vec<[u8; 32]> = self.completed_cross_shard.iter().copied().collect();
        completed.sort();
        // §9 2PC: the committed two-phase-commit records travel with the
        // replay state, so a node that restarts mid-2PC resumes to the SAME
        // decision instead of re-opening the lifecycle.
        let xpc = self.state.xpc_snapshot().await;
        crate::sharding::CrossShardReplaySnapshot {
            engine_consumed,
            runtime_consumed,
            produced,
            completed,
            xpc,
        }
    }

    /// Install persisted replay state (startup restore). Extends (never
    /// replaces: live sets may already hold entries committed after the
    /// snapshot was taken). The engine half travels separately through the
    /// load paths (`restore_cross_shard_consumed`); calling both with the
    /// same blob is idempotent.
    pub fn restore_cross_shard_sets(&mut self, snap: &crate::sharding::CrossShardReplaySnapshot) {
        self.consumed_cross_shard
            .extend(snap.runtime_consumed.iter().copied());
        for (h, tx, height) in &snap.produced {
            self.produced_cross_shard.insert(*h, (tx.clone(), *height));
        }
        self.completed_cross_shard
            .extend(snap.completed.iter().copied());
        // §9 2PC: the mirror of the committed 2PC records.
        for rec in &snap.xpc {
            self.xpc_records
                .entry(rec.tx_hash)
                .or_insert_with(|| rec.clone());
        }
    }

    /// Seed the staking ledger (tests / genesis). The ledger lives in the state
    /// engine, so this writes there; there is deliberately no second copy on the
    /// runtime, because a second copy is a second opinion about who the
    /// validators are - and the validator set decides who proposes.
    pub fn with_staking(self, _ledger: crate::staking::StakingLedger) -> Self {
        // The ledger now lives in the state engine; this setter is kept so
        // existing call sites keep compiling, and seeds the engine if it can take
        // the lock synchronously.
        if let Some(mut guard) = self.state.try_staking_write() {
            *guard = _ledger;
        }
        self
    }

    /// Attach a governance engine (on-chain parameter control).
    pub fn with_governance(mut self, g: crate::governance::Governance) -> Self {
        self.governance = Some(g);
        self
    }

    /// Set the per-block proposer reward (nano-STELL). Requires a staking ledger
    /// to have any effect.
    /// Attach the transaction-gossip handle used to publish the epoch-seal
    /// frames (the DKG contribution, the order commitment, the share
    /// release). Without it the epoch-seal protocol runs node-locally and
    /// the plain path is unaffected.
    pub fn with_tx_gossip(mut self, gossip: Arc<crate::consensus_net::TxGossip>) -> Self {
        self.tx_gossip = Some(gossip);
        self
    }

    /// Use a mempool that is shared with the RPC layer, so a transaction
    /// submitted over RPC is the very same one the proposer selects.
    pub fn with_mempool(mut self, mempool: Arc<tokio::sync::RwLock<Mempool>>) -> Self {
        self.mempool = mempool;
        self
    }

    pub fn with_block_reward(mut self, reward: u64) -> Self {
        self.block_reward = reward;
        self
    }

    /// Configure disjoint wave parallel block execution for this runtime.
    pub fn with_parallel_exec(mut self, enabled: bool) -> Self {
        self.parallel_exec = enabled;
        self.state.set_parallel_exec(enabled);
        self
    }

    /// Set parallel block execution flag on this runtime and its state engine.
    pub fn set_parallel_exec(&mut self, enabled: bool) {
        self.parallel_exec = enabled;
        self.state.set_parallel_exec(enabled);
    }

    /// Attach the invalidation sink: the RPC / streaming layer.
    ///
    /// Every block this node invalidates (a branch that lost the
    /// fork-choice, a reorg that rolled a branch back) is published through
    /// this sink, so a client that was told about those blocks learns that
    /// they are not on the chain.
    pub fn with_invalidation_sink(mut self, sink: crate::chain::InvalidationSink) -> Self {
        self.invalidation_sink = Some(sink);
        self
    }

    /// Publish the invalidation signals to the sink.
    ///
    /// With no sink wired the signals are LOGGED, never silently dropped:
    /// a node that forgot to wire the transport must still leave a trace of
    /// the fact that it invalidated blocks.
    ///
    /// A signal without orphaned blocks carries no information (nothing was
    /// retracted) and is never published: the window would fill up with
    /// noise.
    pub(super) fn publish_invalidations(&self, signals: &[crate::chain::InvalidationSignal]) {
        let signals: Vec<&crate::chain::InvalidationSignal> =
            signals.iter().filter(|s| !s.is_empty()).collect();
        if signals.is_empty() {
            return;
        }
        match &self.invalidation_sink {
            Some(sink) => {
                for s in signals {
                    sink(s.clone());
                }
            }
            None => {
                for s in signals {
                    tracing::warn!(
                        "[chain] invalidated {} block(s) at height {}: {}",
                        s.orphaned_blocks.len(),
                        s.height,
                        s.reason
                    );
                }
            }
        }
    }

    /// Record a VALID candidate block into the fork-choice tree, BEFORE it
    /// is finalized.
    ///
    /// This is what makes a fork observable in a live node. Without it the
    /// node only ever learns the branch it finalized, and the competing one
    /// disappears without a trace — so nobody can ever be told "that block
    /// you saw is not on the chain".
    ///
    /// The block is validated as an extension of a KNOWN block (parent
    /// known, height chained, proposer signature valid), so a forged or
    /// unrelated block can never pollute the tree. Returns true when the
    /// block was recorded.
    pub fn record_candidate_block(&mut self, block: &Block) -> bool {
        if self.chain.is_empty() {
            // The tree has no root yet. A node that joined mid-chain knows a
            // finalized head long before it finalizes anything itself: use
            // it as the root so the candidates that extend it are tracked.
            self.seed_chain_root();
            if self.chain.is_empty() {
                // No root and nothing to build one from: we cannot tell a
                // candidate from noise.
                return false;
            }
        }
        if block.height <= self.chain.finalized_height {
            // A block for an already-finalized height can never be applied.
            // It is invalidated on the spot (the honest answer, not silence).
            let signal = self.chain.invalidate_block(block);
            self.publish_invalidations(std::slice::from_ref(&signal));
            return false;
        }
        match self.chain.insert_candidate(block.clone()) {
            Ok(_) => {
                // The fork-choice's own candidate-window trim may have dropped
                // a branch to make room. That drop is a FORK the world has to
                // hear about: publish the parked signal (audit W6.4b — the
                // trim used to record the invalidation internally and nobody
                // ever published it, so a client following the trimmed branch
                // was never told it lost).
                let pending = self.chain.take_pending_invalidations();
                self.publish_invalidations(&pending);
                true
            }
            Err(e) => {
                tracing::debug!("[chain] candidate not recorded: {e}");
                false
            }
        }
    }

    /// Seed the fork-choice tree with the finalized head this runtime
    /// already knows, so a candidate that extends it can be validated.
    ///
    /// A node that joined mid-chain (or that restored from the store) has a
    /// finalized head long before it finalizes anything itself. Without
    /// this the tree would stay empty and the first competing candidates
    /// would go untracked — the fork would be invisible again.
    pub(super) fn seed_chain_root(&mut self) {
        if !self.chain.is_empty() {
            return;
        }
        let Some((_, head)) = self.finalized.last().copied() else {
            return;
        };
        let Some(block) = self.blocks.get(&head).cloned() else {
            return;
        };
        let (_h, signals) = self.chain.adopt_root(block);
        self.publish_invalidations(&signals);
    }

    /// Fold a FINALIZED block into the fork-choice tree.
    ///
    /// The block becomes the new finality anchor, and every candidate branch
    /// it superseded is pruned: the orphaned blocks are published as
    /// invalidation signals, so a client that followed the losing branch
    /// learns that it lost.
    pub fn note_finalized_block(&mut self, block: &Block) -> Vec<crate::chain::InvalidationSignal> {
        let hash = block.compute_hash();
        if self.chain.is_empty() {
            // The first block we learn as FINALIZED becomes the root of our
            // tree: a node that joined mid-chain never saw the ancestors.
            let (_h, signals) = self.chain.adopt_root(block.clone());
            self.publish_invalidations(&signals);
            return signals;
        }
        // A block at or below the finalized height is either the block we
        // ALREADY finalized (a duplicate — idempotent, nothing to do) or a
        // CONFLICTING block for a height the chain already decided. The
        // second must NEVER re-root the fork-choice: the state has the
        // decided block applied, so re-rooting would make the canonical view
        // disagree with the applied state — and it would move the finality
        // ANCHOR backwards (the finalized height must never decrease).
        if block.height <= self.chain.finalized_height {
            let already = self.chain.finalized_at_height(block.height) == Some(hash);
            if already {
                // Duplicate finalize of the block we already decided: a
                // no-op, NOT a re-root.
                return Vec::new();
            }
            tracing::error!(
                height = block.height,
                finalized_height = self.chain.finalized_height,
                "refusing to re-root the fork-choice on a block at or below the finalized height"
            );
            return Vec::new();
        }
        self.chain.insert(block.clone());
        if let Err(e) = self.chain.finalize(hash) {
            // The finalized chain moved discontinuously (we never saw the
            // intermediate blocks): re-root on the new block instead of
            // keeping a chain we cannot vouch for.
            tracing::warn!("[chain] finalized block does not extend our chain ({e}); re-rooting");
            let (_h, signals) = self.chain.adopt_root(block.clone());
            self.publish_invalidations(&signals);
            return signals;
        }
        let signals = self.chain.prune_superseded_candidates();
        self.publish_invalidations(&signals);
        // The finalized history below the head is not needed by the
        // fork-choice any more: drop the bodies so a long-running node's
        // memory stays bounded (the hashes stay in the finalized index).
        self.chain.prune_below_finalized();
        signals
    }

    /// Fork-choice over the recorded candidate branches.
    ///
    /// When a LONGER branch appears, the reorg plan from the current
    /// candidate head to the new one is computed and EXECUTED: the head
    /// moves and the losing branch's blocks are invalidated (and published).
    ///
    /// A branch of the SAME length is NOT a reorg: the finalization (the
    /// quorum) decides which of the two is on the chain, so both stay live
    /// candidates until it does, and the loser is invalidated then (by the
    /// prune path). Switching the head between them would publish an
    /// invalidation for a block that may still be finalized — a lie.
    ///
    /// The rolled-back blocks are CANDIDATES — blocks that were validated
    /// but never applied — so the state needs no rollback: it is already
    /// exactly on the finalized chain, and the new branch is not applied
    /// until it is finalized in its own right. A plan that would roll back
    /// an APPLIED block is refused (see the check below): that would be a
    /// state rollback across finality, which BFT forbids.
    pub fn run_fork_choice(&mut self) -> Option<crate::chain::ReorgOutcome> {
        let new_head = self.chain.best_candidate()?;
        let current = self.chain.candidate_head;
        if current == Some(new_head) {
            return None;
        }
        // Only a STRICTLY deeper branch reorgs. A branch of the same
        // length is still alive (the quorum decides), so it must not be
        // invalidated here.
        let current_height = current.map(|h| self.chain.height_of(&h)).unwrap_or(0);
        let new_height = self.chain.height_of(&new_head);
        if new_height <= current_height {
            return None;
        }
        let plan = self.chain.candidate_reorg_plan(&new_head).ok().flatten()?;
        // SAFETY: refuse a reorg that would undo an APPLIED block. In the
        // BFT path the rolled-back blocks are candidates that were never
        // executed, so this never fires; it is the guard that keeps a
        // future non-finalizing path from silently rewinding committed
        // state.
        if plan
            .rollback
            .iter()
            .any(|h| self.finalized.iter().any(|(_, fh)| fh == h))
        {
            tracing::error!("[chain] refusing a reorg that would roll back an applied block");
            return None;
        }
        let signal = self.chain.commit_candidate_reorg(&plan, new_head);
        let invalidations = if signal.is_empty() {
            Vec::new()
        } else {
            vec![signal]
        };
        self.publish_invalidations(&invalidations);
        Some(crate::chain::ReorgOutcome {
            plan,
            invalidations,
        })
    }

    /// Check whether disjoint wave parallel execution is enabled.
    pub fn is_parallel_exec_enabled(&self) -> bool {
        self.parallel_exec || self.state.is_parallel_exec_enabled()
    }

    /// Slash the offenders named by THIS NODE'S local equivocation observations.
    /// Returns the total burned.
    ///
    /// SECURITY / F4: this is deliberately NOT called from any state-transition
    /// path (`try_finalize`, `apply_and_advance`, `replay_historical_block`).
    /// The evidence comes from `self.hc.equivocations()`, i.e. from whichever
    /// conflicting votes this node happened to receive over best-effort gossip.
    /// Two nodes that decide the SAME block by different routes (local finalize
    /// vs adopt vs walk vs replay) therefore observe different evidence, burn
    /// different stake, and commit different state roots — a chain split that a
    /// single Byzantine double-voter triggers at will by choosing gossip
    /// delivery (audit finding F4).
    ///
    /// Equivocation slashing therefore travels inside the block as verifiable
    /// content (approach "carry evidence in the block"): no new `Block` field
    /// was needed — the evidence rides the block BODY as
    /// `OpCode::SysCallReportEquivocation` payloads (appended terminal
    /// variant; old nodes fail closed on the unknown discriminant instead of
    /// misreading the block). Gossip-direct slashing stays DEAD: determinism
    /// is preserved by slashing ONLY from block bytes. Direct callers in
    /// tests exercise the primitive; production code must not call this from
    /// a transition.
    ///
    /// PRODUCT DECISION (audit O1 — gossip-direct equivocation stays
    /// unwired, stated without ambiguity): THIS function (local-observation
    /// slash) must never run in a state transition — double-signing observed
    /// only over gossip is still FREE by design, and only downtime slashing
    /// plus BLOCK-CARRIED equivocation slashing are live. The wired path is
    /// `InMemoryStateEngine::apply_block_transition` (step 5b), which meets
    /// all three preconditions together with fail-closed tests:
    ///   (1) block-carried, signature-verifiable equivocation evidence
    ///       (`SysCallReportEquivocation` payloads, both votes fully
    ///       included, re-verified from block bytes on every node);
    ///   (2) the live call site debits `STAKING_POOL` by `burned` (the
    ///       primitive mutates ledger fields only; without the debit
    ///       pool/ledger drift by `burned` per slash);
    ///   (3) per-offense (`BLAKE3(voter‖height‖round‖kind‖targets)`) dedup
    ///       in the ledger, so one offense slashes exactly once on every
    ///       node. Wire gossip evidence instead and nodes slash different
    ///       stake from the same height (audit finding F4).
    pub async fn apply_equivocation_slashes(&mut self) -> u64 {
        let mut guard = self.state.staking_write().await;
        let ledger = &mut *guard;
        let mut burned = 0u64;
        for ev in self.hc.equivocations() {
            if let Ok(b) = ledger.slash_equivocation(&ev) {
                burned = burned.saturating_add(b);
            }
        }
        burned
    }

    /// Block-carried equivocation feed: deterministic envelopes for the NEXT
    /// block this node helps build.
    ///
    /// Converts THIS node's local double-vote observations
    /// (`HeightConsensus::equivocations()` — which transactions may never
    /// read, audit F4) into canonical, verified
    /// [`crate::consensus::EquivocationEvidence`] envelopes ready to embed
    /// as `OpCode::SysCallReportEquivocation` payloads (permissionless: any
    /// funded account may report, like the price-feed path). Verified
    /// against the consensus validator set, sorted by offense key, in-block
    /// duplicates dropped, capped at
    /// [`crate::consensus::MAX_BLOCK_EQUIVOCATION_EVIDENCES`] — so every
    /// caller feeds the same bytes for the same observations.
    ///
    /// This feeds PROPOSAL content only. The slash itself fires at apply
    /// (`InMemoryStateEngine::apply_block_transition`, step 5b), which
    /// re-verifies every envelope from block bytes and dedupes per offense
    /// in the staking ledger — so a re-included (already-slashed) offense
    /// burns 0 and the feed needs no ledger access. Fail-closed: anything
    /// unverifiable never leaves this function.
    pub fn equivocation_feed_evidence(&self) -> Vec<crate::consensus::EquivocationEvidence> {
        let pairs = self.hc.equivocations();
        if pairs.is_empty() {
            return Vec::new();
        }
        let items: Vec<crate::consensus::EquivocationEvidence> = pairs
            .into_iter()
            .map(|(voter, a, b)| crate::consensus::EquivocationEvidence::new(voter, a, b))
            .collect();
        let mut out = crate::consensus::canonicalize_equivocation_evidence(items, &|v| {
            self.validators.validators.contains_key(v)
        });
        out.truncate(crate::consensus::MAX_BLOCK_EQUIVOCATION_EVIDENCES);
        out
    }

    // ==================== Staking lifecycle (on-chain) ====================

    /// Register a validator self-bond through the node.
    ///
    /// A8: the bonded STELL is actually DEBITED from the validator's account, so
    /// voting power is backed by real funds (previously the ledger was updated
    /// without moving any balance, letting a validator stake funds it never had).
    pub async fn stake_bond(
        &mut self,
        validator: ValidatorId,
        amount: u64,
        commission_bps: u64,
    ) -> Result<(), crate::staking::StakingError> {
        use crate::staking::StakingError;
        // The ledger lives in the state engine, so a bond through this helper
        // lands in exactly the place a SysCallStake bond does.
        self.state
            .debit_native(&validator, amount)
            .await
            .map_err(|_| StakingError::InsufficientBond)?;
        let _ = self
            .state
            .credit_native_transfer(&crate::staking::STAKING_POOL, amount)
            .await;
        let res = self
            .state
            .staking_write()
            .await
            .bond(validator, amount, commission_bps);
        if let Err(e) = res {
            // M2: the ledger refused AFTER the pool was credited — remove the
            // pool credit symmetrically (fail-closed) before refunding the
            // validator, or the pool keeps coins no ledger entry backs (mint).
            let _ = self
                .state
                .debit_native(&crate::staking::STAKING_POOL, amount)
                .await;
            let _ = self.state.credit_native_transfer(&validator, amount).await;
            return Err(e);
        }
        Ok(())
    }

    /// Begin unbonding self-bond (subject to cooldown). Funds are already held by
    /// the ledger from `stake_bond`, so nothing moves until withdrawal.
    pub async fn stake_unbond(
        &mut self,
        validator: ValidatorId,
        amount: u64,
        now: u64,
    ) -> Result<(), crate::staking::StakingError> {
        let mut engine = self.state.staking_write().await;
        let l = &mut *engine;
        l.unbond(validator, amount, now)
    }

    /// Delegate stake to a validator. The STELL is actually DEBITED from the
    /// delegator's account.
    ///
    /// M2: the debit is escrowed into [`crate::staking::STAKING_POOL`] exactly
    /// like `stake_bond`, so the delegated ledger entry is always pool-backed
    /// and a later `stake_withdraw_delegator` can debit the pool instead of
    /// minting. Every native leg unwinds symmetrically on failure.
    pub async fn stake_delegate(
        &mut self,
        delegator: [u8; 32],
        validator: ValidatorId,
        amount: u64,
    ) -> Result<(), crate::staking::StakingError> {
        // L2: the zero delegator would collide with the validator's own
        // matured self-bond key — refuse before moving any coins.
        if delegator == [0u8; 32] {
            return Err(crate::staking::StakingError::ZeroAddress);
        }
        use crate::staking::StakingError;
        self.state
            .debit_native(&delegator, amount)
            .await
            .map_err(|_| StakingError::InsufficientDelegation)?;
        if self
            .state
            .credit_native_transfer(&crate::staking::STAKING_POOL, amount)
            .await
            .is_err()
        {
            let _ = self.state.credit_native_transfer(&delegator, amount).await;
            return Err(StakingError::InsufficientDelegation);
        }
        let res = self
            .state
            .staking_write()
            .await
            .delegate(delegator, validator, amount);
        if let Err(e) = res {
            let _ = self
                .state
                .debit_native(&crate::staking::STAKING_POOL, amount)
                .await;
            let _ = self.state.credit_native_transfer(&delegator, amount).await;
            return Err(e);
        }
        Ok(())
    }

    /// Begin undelegating (subject to cooldown).
    pub async fn stake_undelegate(
        &mut self,
        delegator: [u8; 32],
        validator: ValidatorId,
        amount: u64,
        now: u64,
    ) -> Result<(), crate::staking::StakingError> {
        self.state
            .staking_write()
            .await
            .undelegate(delegator, validator, amount, now)
    }

    /// Mature any unbonding entries whose cooldown has elapsed (called on
    /// finalization so funds become withdrawable without an external trigger).
    /// Fail-closed (audit P2): an overflow refusal is logged LOUD and the
    /// entries stay pending (retried next finalization); maturation never
    /// destroys dust to keep liveness.
    pub async fn process_unbonding(&mut self, now: u64) {
        if let Err(e) = self.state.staking_write().await.process_unbonding(now) {
            tracing::error!("unbonding maturation refused (funds stay pending): {e}");
        }
    }

    /// Withdraw matured self-bond funds (credited back to the validator).
    ///
    /// M2: withdrawals are paid OUT OF [`crate::staking::STAKING_POOL`], never
    /// minted. The pool is debited FIRST (fail-closed on shortfall: the
    /// consumed ledger entry is restored and nothing is paid); if the final
    /// credit then fails, the pool debit is refunded AND the ledger entry is
    /// restored, so a failed withdrawal moves no coins anywhere.
    pub async fn stake_withdraw(
        &mut self,
        validator: ValidatorId,
    ) -> Result<u64, crate::staking::StakingError> {
        use crate::staking::StakingError;
        let amount = self.state.staking_write().await.withdraw(validator)?;
        if self
            .state
            .debit_native(&crate::staking::STAKING_POOL, amount)
            .await
            .is_err()
        {
            let mut l = self.state.staking_write().await;
            let key = (validator, [0u8; 32]);
            let back = l
                .withdrawable
                .get(&key)
                .copied()
                .unwrap_or(0)
                .saturating_add(amount);
            l.withdrawable.insert(key, back);
            return Err(StakingError::NothingToWithdraw);
        }
        if self
            .state
            .credit_native_transfer(&validator, amount)
            .await
            .is_err()
        {
            let _ = self
                .state
                .credit_native_transfer(&crate::staking::STAKING_POOL, amount)
                .await;
            let mut l = self.state.staking_write().await;
            let key = (validator, [0u8; 32]);
            let back = l
                .withdrawable
                .get(&key)
                .copied()
                .unwrap_or(0)
                .saturating_add(amount);
            l.withdrawable.insert(key, back);
            return Err(StakingError::NothingToWithdraw);
        }
        Ok(amount)
    }

    /// Withdraw matured undelegated funds as a delegator (credited to delegator).
    ///
    /// M2: same pool-backed discipline as [`Self::stake_withdraw`] — the pool
    /// is debited first (fail-closed on shortfall, ledger entry restored) and
    /// both legs unwind on a failed credit.
    pub async fn stake_withdraw_delegator(
        &mut self,
        delegator: [u8; 32],
        validator: ValidatorId,
    ) -> Result<u64, crate::staking::StakingError> {
        use crate::staking::StakingError;
        let amount = self
            .state
            .staking_write()
            .await
            .withdraw_delegator(delegator, validator)?;
        if self
            .state
            .debit_native(&crate::staking::STAKING_POOL, amount)
            .await
            .is_err()
        {
            let mut l = self.state.staking_write().await;
            let key = (validator, delegator);
            let back = l
                .withdrawable
                .get(&key)
                .copied()
                .unwrap_or(0)
                .saturating_add(amount);
            l.withdrawable.insert(key, back);
            return Err(StakingError::NothingToWithdraw);
        }
        if self
            .state
            .credit_native_transfer(&delegator, amount)
            .await
            .is_err()
        {
            let _ = self
                .state
                .credit_native_transfer(&crate::staking::STAKING_POOL, amount)
                .await;
            let mut l = self.state.staking_write().await;
            let key = (validator, delegator);
            let back = l
                .withdrawable
                .get(&key)
                .copied()
                .unwrap_or(0)
                .saturating_add(amount);
            l.withdrawable.insert(key, back);
            return Err(StakingError::NothingToWithdraw);
        }
        Ok(amount)
    }

    /// Claim accrued validator rewards (credited to the validator).
    ///
    /// E2: paid out of the minted [`crate::staking::REWARDS_POOL`], never out
    /// of bonded principal and never minted from thin air. The ledger claim
    /// already consumed the pool backing; the native leg debits the pool
    /// first (fail-closed on shortfall) and restores the ledger entry if
    /// either native leg fails.
    pub async fn stake_claim_rewards(
        &mut self,
        validator: ValidatorId,
    ) -> Result<u64, crate::staking::StakingError> {
        let amount = self
            .state
            .staking_write()
            .await
            .claim_validator_rewards(validator)?;
        if amount > 0 {
            if self
                .state
                .debit_native(&crate::staking::REWARDS_POOL, amount)
                .await
                .is_err()
            {
                // Restore pool backing + pending rewards: nothing was paid.
                let mut l = self.state.staking_write().await;
                l.rewards_pool = l.rewards_pool.saturating_add(amount);
                if let Some(v) = l.validators.get_mut(&validator) {
                    v.pending_rewards = v.pending_rewards.saturating_add(amount);
                }
                return Err(crate::staking::StakingError::RewardCreditFailed);
            }
            if let Err(_e) = self.state.credit_native_transfer(&validator, amount).await {
                // Refund the pool debit and restore the ledger entry.
                let _ = self
                    .state
                    .credit_native_transfer(&crate::staking::REWARDS_POOL, amount)
                    .await;
                let mut l = self.state.staking_write().await;
                l.rewards_pool = l.rewards_pool.saturating_add(amount);
                if let Some(v) = l.validators.get_mut(&validator) {
                    v.pending_rewards = v.pending_rewards.saturating_add(amount);
                }
                return Err(crate::staking::StakingError::RewardCreditFailed);
            }
        }
        Ok(amount)
    }

    /// Claim accrued delegator rewards (credited to the delegator).
    ///
    /// E2: same funding discipline as [`Self::stake_claim_rewards`] — the
    /// native leg debits [`crate::staking::REWARDS_POOL`], never principal.
    pub async fn stake_claim_delegator_rewards(
        &mut self,
        delegator: [u8; 32],
        validator: ValidatorId,
    ) -> u64 {
        let amount = self
            .state
            .staking_write()
            .await
            .claim_delegator_rewards(delegator, validator);
        if amount > 0 {
            if self
                .state
                .debit_native(&crate::staking::REWARDS_POOL, amount)
                .await
                .is_err()
            {
                // Restore pool backing + the consumed entry: nothing was paid.
                let mut l = self.state.staking_write().await;
                l.rewards_pool = l.rewards_pool.saturating_add(amount);
                *l.delegator_rewards
                    .entry((validator, delegator))
                    .or_insert(0) = l
                    .delegator_rewards
                    .get(&(validator, delegator))
                    .copied()
                    .unwrap_or(0)
                    .saturating_add(amount);
                return 0;
            }
            if self
                .state
                .credit_native_transfer(&delegator, amount)
                .await
                .is_err()
            {
                // Refund the pool debit and restore the ledger entry.
                let _ = self
                    .state
                    .credit_native_transfer(&crate::staking::REWARDS_POOL, amount)
                    .await;
                {
                    let mut l = self.state.staking_write().await;
                    l.rewards_pool = l.rewards_pool.saturating_add(amount);
                    *l.delegator_rewards
                        .entry((validator, delegator))
                        .or_insert(0) = l
                        .delegator_rewards
                        .get(&(validator, delegator))
                        .copied()
                        .unwrap_or(0)
                        .saturating_add(amount);
                }
                return 0;
            }
        }
        amount
    }

    // ==================== Governance (on-chain) ====================

    /// Submit a governance proposal.
    pub fn gov_propose(
        &mut self,
        proposer: ValidatorId,
        title: String,
        action: crate::governance::GovAction,
        now: u64,
    ) -> Result<u64, crate::governance::GovError> {
        // Single-node write guard (fail-closed on multi-node deployments):
        // the in-force validator set size (`self.validators.len()`) is the
        // canonical multi-node signal — a local-only proposal here would
        // diverge the state root from peers that never saw it. The
        // deterministic finalize sweep is NOT gated (it derives from decided
        // blocks, identically on every node).
        if let Err(msg) =
            crate::governance::governance_write_allowed_from_env(self.validators.len())
        {
            return Err(crate::governance::GovError::MultiNodeRefused(msg));
        }
        let mut ledger = self
            .staking
            .try_write()
            .map_err(|_| crate::governance::GovError::NotStaker)?;
        let g = self
            .governance
            .as_mut()
            .ok_or(crate::governance::GovError::NotStaker)?;
        g.propose(&mut ledger, proposer, title, action, now)
    }

    /// Cast a governance vote.
    pub fn gov_vote(
        &mut self,
        voter: [u8; 32],
        proposal_id: u64,
        choice: crate::governance::VoteChoice,
        now: u64,
    ) -> Result<u128, crate::governance::GovError> {
        // Same single-node write guard as `gov_propose` (gate FIRST, before
        // any lock or lookup, so a multi-node vote is refused as
        // multi-node — never as some downstream UnknownProposal).
        if let Err(msg) =
            crate::governance::governance_write_allowed_from_env(self.validators.len())
        {
            return Err(crate::governance::GovError::MultiNodeRefused(msg));
        }
        // E7: `Governance::vote` locks the voter's stake in the ledger, so it
        // needs a write guard (via the state engine, which also bumps the
        // commitment generation — a bare handle write would leave the root
        // cache stale). Same underlying lock as `self.staking`.
        let mut ledger = self
            .state
            .try_staking_write()
            .ok_or(crate::governance::GovError::NotStaker)?;
        let g = self
            .governance
            .as_mut()
            .ok_or(crate::governance::GovError::NotStaker)?;
        g.vote(&mut ledger, voter, proposal_id, choice, now)
    }

    /// Finalize a proposal after its voting window.
    pub fn gov_finalize(
        &mut self,
        proposal_id: u64,
        now: u64,
    ) -> Result<crate::governance::ProposalStatus, crate::governance::GovError> {
        // E7: `Governance::finalize` releases voters' staking locks (see
        // `gov_vote` for why this goes through the state engine).
        let mut ledger = self
            .state
            .try_staking_write()
            .ok_or(crate::governance::GovError::NotStaker)?;
        let g = self
            .governance
            .as_mut()
            .ok_or(crate::governance::GovError::NotStaker)?;
        g.finalize(&mut ledger, proposal_id, now)
    }

    /// Execute a passed proposal's action.
    pub fn gov_execute(
        &mut self,
        executor: [u8; 32],
        proposal_id: u64,
    ) -> Result<crate::governance::AppliedParams, crate::governance::GovError> {
        let g = self
            .governance
            .as_mut()
            .ok_or(crate::governance::GovError::NotStaker)?;
        let applied = g.execute(executor, proposal_id).cloned()?;
        if let Some(min_bond) = applied.min_validator_bond {
            if let Ok(mut st) = self.staking.try_write() {
                st.min_validator_bond = Some(min_bond);
            }
        }
        Ok(applied)
    }

    pub fn height(&self) -> Height {
        self.hc.height
    }

    pub fn is_proposer(&self) -> bool {
        self.expected_proposer_at(&self.hc.validators, self.hc.height, self.hc.round)
            == Some(self.id)
    }

    pub async fn add_tx(&mut self, tx: Transaction) {
        // Check the sender's balance so an unfunded tx can never occupy queue
        // space or evict a funded one at the mempool.
        let acct = self.state.get_account(&tx.from).await;
        let balance = acct.as_ref().map(|a| a.balance).unwrap_or(0);
        // F-02: carry the on-chain head so `insert` enforces the nonce-gap
        // fail-fast at the choke point itself (not just at the RPC/gossip
        // pre-checks). `None`-head callers keep legacy behavior; here the
        // head is already in hand, so enforce unconditionally. Node-local
        // admission only — never consensus.
        let onchain = acct.as_ref().map(|a| a.nonce).unwrap_or(0);
        // P2 shard gate: in a sharded process the pool only admits what this
        // shard owns, so foreign-shard spam cannot squat in pool space the
        // proposer must skip. Single-shard mode stays shard-blind (historical
        // source=1/target=1 traffic must keep admitting).
        let mut ctx = crate::mempool::AdmissionCtx::wall_now().with_onchain_nonce(onchain);
        // PAYMASTER: gossiped sponsored transactions carry their sponsor's
        // head too (fail-closed without it); legacy ignores the extra head.
        if let Some(sbal) = self.state.sponsor_balance_of(&tx).await {
            ctx = ctx.with_sponsor_balance(sbal);
        }
        if self.shard_registry.is_sharded() {
            ctx = ctx.with_shard(self.shard_id);
        }
        let _ = self.mempool.write().await.add_checked_ctx(tx, balance, ctx);
    }

    /// Read the staking ledger through the state engine. Same lock the engine
    /// commits, so reads always see committed state.
    pub async fn staking_read(
        &self,
    ) -> tokio::sync::RwLockReadGuard<'_, crate::staking::StakingLedger> {
        self.state.staking_read().await
    }

    /// Write the staking ledger through the state engine, bumping the commitment
    /// generation so the state root cannot go stale.
    pub async fn staking_write(
        &self,
    ) -> tokio::sync::RwLockWriteGuard<'_, crate::staking::StakingLedger> {
        self.state.staking_write().await
    }

    /// Attach an out-of-process signer. Kept as a builder so every existing
    /// construction site (tests, simulator) is unaffected.
    ///
    /// Refuses a signer whose public key is not this node's identity. `self.id` is
    /// fixed at construction from `key` and is what the validator set and every vote's
    /// `voter` field are keyed on; a remote signer for a DIFFERENT key would produce
    /// signatures that verify against nothing (or worse, attribute a signature to the
    /// wrong validator), so it is rejected here rather than at vote time.
    pub fn with_remote_signer(
        mut self,
        signer: Arc<dyn crate::remote_signer::Signer>,
    ) -> Result<Self, String> {
        let remote_pk = signer.public_key();
        if remote_pk != self.id {
            return Err(format!(
                "remote signer key {} does not match this node's validator identity {}",
                hex::encode(&remote_pk[..8]),
                hex::encode(&self.id[..8])
            ));
        }
        self.remote_signer = Some(signer);
        Ok(self)
    }

    /// The public key this node votes with. For a remote signer this is the key the
    /// signer pinned at construction, so it is the same value `id` was set from.
    pub fn signer_public_key(&self) -> [u8; 32] {
        match &self.remote_signer {
            Some(s) => s.public_key(),
            None => self.key.verifying_key().to_bytes(),
        }
    }

    /// Produce a signature over `bytes`, via the remote signer when one is configured.
    ///
    /// Returns `None` on any signer failure. Deliberately NOT `unwrap_or`-style
    /// fallback to `self.key`: a node that believes its key is in an HSM while it
    /// quietly signs from a plaintext seed in its own heap is the exact failure this
    /// exists to prevent, so the caller must skip the vote instead.
    pub(super) fn sign_bytes(&self, bytes: &[u8]) -> Option<Vec<u8>> {
        match &self.remote_signer {
            Some(s) => match s.sign(bytes) {
                Ok(sig) => Some(sig.to_vec()),
                Err(e) => {
                    eprintln!("[signer] refusing to vote, remote signer failed: {e}");
                    None
                }
            },
            None => Some(self.key.sign(bytes).to_vec()),
        }
    }

    /// Downtime slash for the certificate this runtime currently holds in `hc`:
    /// punish validators that did not contribute to it and burn the slashed
    /// stake from the staking pool. The evidence is the certificate itself, so
    /// every node reaches the same verdict; a local timeout would be neither
    /// sound nor deterministic.
    ///
    /// The production state transition no longer comes here: it runs inside
    /// `InMemoryStateEngine::apply_block_transition`, from the BLOCK's own
    /// `precommit_qc` and `height`, so every route that applies a block -
    /// local finalize, adopt, walk, replay and a reorg re-apply - derives one
    /// verdict from one piece of block content and cannot fork. This entry
    /// point is kept for the consensus-view primitive: tests that build an
    /// `hc` by hand and want to observe what the certificate they hold burns.
    pub async fn apply_downtime_slashes(&mut self) -> u64 {
        // Snapshot the certificate and height BEFORE anything resets them.
        let Some(cert) = self.hc.precommit_qc.clone() else {
            return 0;
        };
        let height = self.hc.height;
        self.state.apply_downtime_slash(height, Some(&cert)).await
    }

    pub async fn state_root(&self) -> [u8; 32] {
        self.state.get_state_root().await
    }
}

// ============================================================================
// CN-VRF v3 activation wiring (review F2 + F3), unit-level
// ============================================================================
#[cfg(test)]
mod cnvrf_v3_activation_unit_tests {
    use super::*;
    use crate::consensus::{
        register_validator_pq_key, CommitteeSchedule, Vote, VoteKind, VoteSet,
        MICRO_COMMITTEE_MAX_SIZE,
    };
    use crate::post_quantum::{FalconKeypair, PqScheme};
    use crate::sharding::{Block, CnVrfV3BlockPayload, EpochVdfBeacon, MASTERCHAIN_SHARD};

    fn vote_keys(n: usize) -> (ValidatorSet, Vec<SigningKey>, Vec<FalconKeypair>) {
        let mut vs = ValidatorSet::new();
        let mut keys = Vec::with_capacity(n);
        let mut fks = Vec::with_capacity(n);
        for i in 0..n {
            // Distinct id pattern (first byte varies, 0x9D filler) so this
            // fixture can never collide with another test's global PQ keys.
            let mut id_bytes = [0x9Du8; 32];
            id_bytes[0] = i as u8;
            let sk = SigningKey::from_bytes(&id_bytes);
            let fk = FalconKeypair::generate_from_seed(i as u8);
            register_validator_pq_key(
                sk.verifying_key().to_bytes(),
                PqScheme::Falcon512,
                fk.public_key.clone(),
            );
            vs.add(sk.verifying_key().to_bytes(), 1);
            keys.push(sk);
            fks.push(fk);
        }
        (vs, keys, fks)
    }

    fn boundary_block(height: u64, prev_hash: [u8; 32], beacon: EpochVdfBeacon) -> Block {
        Block {
            shard_id: MASTERCHAIN_SHARD,
            height,
            prev_hash,
            state_root: [0u8; 32],
            transactions: Vec::new(),
            cross_shard_out: Vec::new(),
            timestamp: 1_760_000_000,
            proposer: [0x11u8; 32],
            validator_signatures: Vec::new(),
            shard_headers: Vec::new(),
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            cnvrf_v3: Some(CnVrfV3BlockPayload {
                reveal: None,
                commits: Vec::new(),
                epoch_vdf: Some(beacon),
            }),
            order_merkle_root: crate::mev::compute_order_merkle_root(&[]),
            epoch_key_commitment: [0u8; 32],
        }
    }

    async fn poll_ready_beacon(rt: &mut ValidatorRuntime, epoch: u64) -> EpochVdfBeacon {
        for _ in 0..400 {
            rt.poll_vdf_lane();
            if let Some(beacon) = rt.ready_vdf_beacons.get(&epoch).cloned() {
                return beacon;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        panic!("the VDF lane never delivered the epoch {epoch} beacon");
    }

    /// F3 END-TO-END: the REAL producer hook (`H_freeze` dispatch) and the REAL
    /// boundary validator derive the SAME seed, so the beacon chain starts at
    /// the first post-activation boundary and continues across the next one.
    ///
    /// Pre-fix this test fails: the producer chained a zero link while the
    /// validator chained the bootstrap beacon, so `validate_cnvrf_v3_payload`
    /// refused the very beacon the producer dispatched.
    #[tokio::test]
    async fn beacon_chain_starts_across_the_first_boundary() {
        let key = SigningKey::from_bytes(&[0x31u8; 32]);
        let me = key.verifying_key().to_bytes();
        let validators = ValidatorSet::from_list(vec![(me, 1)]);
        let mut rt =
            ValidatorRuntime::new(key, validators, Arc::new(InMemoryStateEngine::new()), 1)
                .with_falcon_key(FalconKeypair::generate_from_seed(0x77));
        // Genesis warm start: the activation-height rule allows 0.
        rt.set_cnvrf_v3_activation_height_for_tests(0);
        rt.set_cnvrf_v3_vdf_steps(64);

        // --- first boundary: epoch 1, `H_freeze` = 6840 -------------------
        let freeze_hash = [0xA1u8; 32];
        rt.prepare_cnvrf_v3_epoch_hooks(6840, freeze_hash).await;
        assert!(
            rt.cnvrf_freeze_inputs.contains_key(&1),
            "the producer must snapshot epoch 1's freeze inputs at H_freeze"
        );
        let beacon1 = poll_ready_beacon(&mut rt, 1).await;
        let block_7200 = boundary_block(7200, [0x71u8; 32], beacon1.clone());
        rt.validate_cnvrf_v3_payload(&block_7200)
            .expect("the FIRST post-activation boundary beacon must verify (F3)");

        // The state engine records the beacon; the runtime mirror follows.
        let out1 = crate::minroot_vdf::derive_vdf_output(&beacon1.raw_seed, &beacon1.proof);
        rt.state.epoch_vdf_beacons_write().await.insert(1, out1);
        rt.finalized_epoch_beacons.insert(1, out1);
        rt.ready_vdf_beacons.remove(&1);

        // --- second boundary: epoch 2, `H_freeze` = 14040 ------------------
        let freeze2 = [0xB2u8; 32];
        rt.prepare_cnvrf_v3_epoch_hooks(14040, freeze2).await;
        let beacon2 = poll_ready_beacon(&mut rt, 2).await;
        let block_14400 = boundary_block(14400, [0x72u8; 32], beacon2);
        rt.validate_cnvrf_v3_payload(&block_14400)
            .expect("the beacon chain must continue across the second boundary");

        // The second seed really chained the first beacon (not zeros).
        let expected = crate::cn_vrf::epoch_seed(
            rt.cnvrf_v3_chain_id,
            2,
            Some(&out1),
            crate::cn_vrf::epoch_had_vdf(1, 0),
            &freeze2,
            &rt.cnvrf_freeze_inputs
                .get(&2)
                .expect("freeze inputs for epoch 2")
                .1,
        );
        assert_eq!(
            rt.ready_vdf_beacons.get(&2).map(|b| b.raw_seed),
            Some(expected),
            "epoch 2's seed must chain epoch 1's committed beacon"
        );
    }

    /// F2 AT THE NODE: the engine's own decision-certificate producer (as
    /// driven by `try_precommit_quorum`) draws the beacon committee at
    /// activation, and the SAME node's verifier accepts it — while the legacy
    /// parent-hash verifier refuses it (the pre-fix halt). Uses more than
    /// `MICRO_COMMITTEE_MAX_SIZE` validators so the two draws differ.
    #[tokio::test]
    async fn node_accepts_its_own_beacon_certificate_at_activation() {
        let activation = crate::cn_vrf::EPOCH_LEN + 1;
        let n = MICRO_COMMITTEE_MAX_SIZE as usize + 2;
        let (vs, keys, fks) = vote_keys(n);
        let key = keys[0].clone();
        let mut rt = ValidatorRuntime::new(
            key,
            vs.clone(),
            Arc::new(InMemoryStateEngine::new()),
            activation,
        );
        rt.set_cnvrf_v3_activation_height_for_tests(activation);
        rt.hc.set_parent_hash([0x21u8; 32]);

        let block = [0x55u8; 32];
        let parent = [0x21u8; 32];
        for (sk, fk) in keys.iter().zip(fks.iter()) {
            rt.hc
                .add_prevote(Vote::sign_with_falcon(
                    sk,
                    fk,
                    activation,
                    0,
                    VoteKind::Prevote,
                    Some(block),
                ))
                .expect("prevote admits");
        }
        for (sk, fk) in keys.iter().zip(fks.iter()) {
            rt.hc
                .add_precommit(Vote::sign_with_falcon(
                    sk,
                    fk,
                    activation,
                    0,
                    VoteKind::Precommit,
                    Some(block),
                ))
                .expect("precommit admits");
        }
        let decided = rt
            .hc
            .try_precommit_quorum()
            .expect("the whole set precommitted, so the height decides");
        assert_eq!(decided, block);
        let qc = rt.hc.precommit_qc.clone().expect("decision certificate");

        // The schedule the node produced under is the beacon draw.
        let schedule = rt.committee_schedule_at(activation);
        assert!(matches!(schedule, CommitteeSchedule::Beacon(Some(_))));
        assert!(
            rt.verify_qc_for_height(&qc, &vs),
            "the same node must verify its OWN decision certificate (F2)"
        );
        assert!(
            vs.qc_signed_power_with_schedule(&qc, schedule) >= vs.quorum_power(),
            "the beacon-attributed signers must carry quorum power"
        );

        // Negative control: the pre-fix parent-hash gate refuses it.
        assert!(
            !qc.verify(&vs),
            "the legacy parent-hash verifier must refuse the beacon-drawn QC"
        );

        // --- `last_qc` downtime evidence is beacon-aware too ----------------
        // Evidence for a height ABOVE activation: the parent QC is drawn from
        // the epoch beacon, so the parent-hash gate would refuse it (the F2
        // downtime-attribution halt).
        let evidence_height = activation + 1;
        let parent_len = parent_height(evidence_height);
        let mut votes = VoteSet::new();
        for (sk, fk) in keys.iter().zip(fks.iter()) {
            votes
                .add(
                    Vote::sign_with_falcon(
                        sk,
                        fk,
                        parent_len,
                        0,
                        VoteKind::Precommit,
                        Some(parent),
                    ),
                    &vs,
                    parent_len,
                    0,
                    VoteKind::Precommit,
                )
                .expect("parent vote admits");
        }
        let parent_qc = crate::consensus::produce_decision_certificate_with_schedule(
            &votes,
            Some(parent),
            &vs,
            Some(&[0x20u8; 32]),
            rt.committee_schedule_at(parent_len),
        )
        .expect("parent certificate compiles");
        assert!(
            !parent_qc.verify(&vs),
            "the legacy parent-hash verifier must refuse the beacon-drawn last_qc"
        );
        let mut evidence_block = boundary_block(
            evidence_height,
            parent,
            EpochVdfBeacon {
                epoch: 0,
                raw_seed: [0u8; 48],
                proof: crate::minroot_vdf::eval(&[0u8; 48], 1, 1),
            },
        );
        evidence_block.last_qc = Some(parent_qc);
        // The check only cares about the parent height / hash / kind / quorum.
        rt.check_last_qc_evidence(&evidence_block)
            .expect("an honest beacon-drawn last_qc must be accepted (F2)");
    }

    fn parent_height(height: u64) -> u64 {
        height - 1
    }
}
