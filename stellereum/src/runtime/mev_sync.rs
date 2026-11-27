use super::lanes::{
    count_program_sends, missing_sender_accounts, PackFilterCtx, PrebuiltSelection,
};
use super::{
    DropReason, ValidatorRuntime, DKG_REPUBLISH_INTERVAL, MAX_BLOCK_GAS, MAX_BLOCK_TXS,
    SEAL_PARTIAL_POLL_MS,
};
use crate::consensus::{Height, Round, Step};
use crate::mempool::Mempool;
use crate::sharding::{Block, CrossShardKey, CrossShardMessage, Transaction};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

impl ValidatorRuntime {
    /// Resolve the node-local MEV KEM material for THIS node.
    ///
    /// Precedence is explicit and per-runtime first: a runtime built with
    /// [`ValidatorRuntime::with_mev_kem`] uses those fields. Otherwise the
    /// shared mempool's bootstrap-installed wiring is used (the node path:
    /// bootstrap derives the seed and calls `Mempool::with_mev_kem` before the
    /// consensus runtime is spawned). Both halves are required — a registry
    /// without the seed, or a seed without the registry, is NOT enough and the
    /// caller must fail closed.
    ///
    /// The returned seed is a fresh `Zeroizing` copy for one protocol call; it
    /// is never placed in a plain array and never logged.
    async fn mev_kem_material(
        &self,
    ) -> Option<(
        Arc<crate::mev_kem_registry::MevKemRegistry>,
        zeroize::Zeroizing<[u8; 64]>,
    )> {
        if let (Some(registry), Some(seed)) = (&self.mev_kem_registry, &self.mev_kem_seed) {
            let pool = self.mempool.read().await;
            if pool.peer_kem_keys.is_empty() {
                return Some((Arc::clone(registry), zeroize::Zeroizing::new(**seed)));
            }
            let mut merged = (**registry).clone();
            merged.merge_non_conflicting(&pool.peer_kem_keys);
            return Some((Arc::new(merged), zeroize::Zeroizing::new(**seed)));
        }
        let pool = self.mempool.read().await;
        pool.mev_kem().map(|wiring| {
            let reg = wiring.effective_registry();
            if pool.peer_kem_keys.is_empty() {
                return (reg, wiring.seed());
            }
            let mut merged = (*reg).clone();
            merged.merge_non_conflicting(&pool.peer_kem_keys);
            (Arc::new(merged), wiring.seed())
        })
    }

    /// Whether a sealed transaction's transparent metadata matches the
    /// transaction it was sealed from.
    ///
    /// The metadata is what the mempool ordered by, so a wallet that lies about
    /// it could buy priority for free. The check happens right after the
    /// unseal, BEFORE the transaction can enter a block: a mismatch drops the
    /// transaction (fail closed).
    pub fn sealed_meta_matches(tx: &Transaction, meta: &crate::mev_epoch::TransparentMeta) -> bool {
        tx.from == meta.from
            && tx.nonce == meta.nonce
            && tx.gas_limit == meta.gas_limit
            && tx.priority_fee_per_gas == meta.priority_fee_per_gas
            && tx.source_shard == meta.source_shard
            && tx.target_shard == meta.target_shard
    }

    /// Plain-path pack admissibility: the exact predicate `propose` passes to
    /// `select_for_block_multi`, factored so the prebuild and the revalidation
    /// run THE SAME checks as a fresh build.
    ///
    /// Pure function of (tx, ctx, block timestamp): shard scope, session
    /// policy + registry (expiry, scope, remaining budget via the in-block
    /// spend simulation), nonce continuity, D2 failure-penalty + PQ
    /// surcharge + priority-bid fee floor, and balance — SKIP-only on every
    /// failure, mutating only the filter state (expected nonces, session
    /// spend, used senders, rejection census). Accepting here is necessary
    /// but not sufficient for block validity (caps, unseal gate, actor cap,
    /// state-root recompute and the proposer signature still run at propose);
    /// receivers re-verify all of it, so reuse can only ever change block
    /// COMPOSITION (liveness), never validity (safety).
    pub fn pack_filter_accept(ctx: &PackFilterCtx, t: &Transaction) -> bool {
        let timestamp = ctx.timestamp;
        if ctx.sharded && !crate::sharding::tx_belongs_to_shard(t, ctx.my_shard) {
            ctx.rej_shard.set(ctx.rej_shard.get() + 1);
            return false;
        }
        let is_cross = ctx.sharded && crate::sharding::tx_is_outbound_cross_shard(t, ctx.my_shard);
        if is_cross && ctx.used_senders.borrow().contains(&t.from) {
            ctx.rej_shard.set(ctx.rej_shard.get() + 1);
            return false;
        }
        // Session-key delegation policy against THIS block's timestamp (the
        // deterministic clock): expiry, scope, value cap and remaining
        // budget. The exact same predicate the apply path re-checks.
        if t.check_session_policy(timestamp).is_err() {
            ctx.rej_session.set(ctx.rej_session.get() + 1);
            return false;
        }
        // ...joined by the registry: a revoked key is refused here exactly
        // as it is at admission and at execution, and this block's own
        // in-flight session spend counts against the budget the same way the
        // apply path's simulation does.
        if let Some(d) = t.delegation() {
            // Same single definition the apply path uses (including the
            // actor-mailbox scope), so a proposer can never select a
            // transaction execution would refuse for scope.
            let required_scope = t.required_scope();
            if ctx
                .session_keys
                .check(
                    &d,
                    t.amount,
                    t.gas_limit,
                    required_scope,
                    timestamp,
                    &mut ctx.session_sim.borrow_mut(),
                )
                .is_err()
            {
                ctx.rej_session.set(ctx.rej_session.get() + 1);
                return false;
            }
        }
        let Some(&(expected, balance)) = ctx.next_nonce.borrow().get(&t.from) else {
            // No account means no balance, so it cannot pay.
            ctx.rej_noacct.set(ctx.rej_noacct.get() + 1);
            return false;
        };
        if t.nonce != expected {
            ctx.rej_nonce.set(ctx.rej_nonce.get() + 1);
            return false;
        }
        // Failure-penalized floor (D2) + PQ surcharge + explicit priority bid:
        // mirrors admission exactly, SKIP-only like every other condition.
        let pq_surch = if t.is_pq_activation() {
            crate::mempool::PQ_ACTIVATION_SURCHARGE_GAS
        } else {
            0
        };
        let floor = ctx
            .base_fee
            .saturating_add(ctx.penalty_floors.get(&t.from).copied().unwrap_or(0))
            .saturating_add(pq_surch)
            .saturating_add(t.priority_fee_per_gas);
        if t.gas_limit < floor {
            ctx.rej_basefee.set(ctx.rej_basefee.get() + 1);
            return false;
        }
        // PAYMASTER v1 (mid-mempool re-check, plain path): the legs split —
        // the user covers VALUE, the sponsor covers FEE — and the grant's
        // policy is re-checked at the block timestamp, SKIP-only.
        if let Some(auth) = t.sponsored_grant() {
            if !t.has_pq_sponsor_inner() || !t.verify_sponsor_sig(&auth) {
                ctx.rej_sponsor.set(ctx.rej_sponsor.get() + 1);
                return false;
            }
            let fee = t.gas_limit.max(floor).saturating_add(pq_surch);
            if t.check_sponsor_policy(timestamp, fee).is_err() {
                ctx.rej_sponsor.set(ctx.rej_sponsor.get() + 1);
                return false;
            }
            if balance < t.amount {
                ctx.rej_funds.set(ctx.rej_funds.get() + 1);
                return false;
            }
            let Some(&(sponsor_nonce, sponsor_balance)) =
                ctx.next_nonce.borrow().get(&auth.sponsor)
            else {
                ctx.rej_funds.set(ctx.rej_funds.get() + 1);
                return false;
            };
            if sponsor_balance < fee {
                ctx.rej_funds.set(ctx.rej_funds.get() + 1);
                return false;
            }
            ctx.next_nonce
                .borrow_mut()
                .insert(t.from, (expected + 1, balance - t.amount));
            ctx.next_nonce
                .borrow_mut()
                .insert(auth.sponsor, (sponsor_nonce, sponsor_balance - fee));
            ctx.used_senders.borrow_mut().insert(t.from);
            return true;
        }
        // F-07: the pack balance check mirrors admission execution
        // (amount + gas_limit + PQ surcharge for activation txs).
        let cost = t
            .amount
            .saturating_add(t.gas_limit)
            .saturating_add(pq_surch);
        if balance < cost {
            ctx.rej_funds.set(ctx.rej_funds.get() + 1);
            return false;
        }
        // Accepting it advances this sender's nonce and debits its budget.
        ctx.next_nonce
            .borrow_mut()
            .insert(t.from, (expected + 1, balance - cost));
        ctx.used_senders.borrow_mut().insert(t.from);
        true
    }

    /// Enforce every block cap on a combined (kept + top-up) selection by
    /// dropping from the end. Kept transactions precede new ones and each
    /// run is internally selection-ordered, so suffix truncation preserves
    /// per-sender nonce contiguity and the survivors still satisfy the
    /// filter's own checks. A kept-only prefix always satisfied these same
    /// caps at prebuild time (identical constants), so truncation only ever
    /// sheds top-up transactions — liveness-only, never validity.
    pub(super) fn truncate_to_block_caps(txs: &mut Vec<Transaction>) {
        let mut gas = 0u64;
        let mut wire = 0usize;
        let mut proofs = 0usize;
        let mut keep = 0usize;
        for t in txs.iter() {
            let g = gas.saturating_add(t.gas_limit);
            let w = wire.saturating_add(crate::mempool::Mempool::estimate_tx_wire_bytes(t));
            let p = proofs.saturating_add(crate::mempool::Mempool::count_tx_proof_units(t));
            if keep >= MAX_BLOCK_TXS
                || g > MAX_BLOCK_GAS
                || w > crate::mempool::Mempool::MAX_BLOCK_WIRE_BYTES
                || p > crate::mempool::Mempool::MAX_BLOCK_PROOF_UNITS
            {
                break;
            }
            gas = g;
            wire = w;
            proofs = p;
            keep += 1;
        }
        txs.truncate(keep);
    }

    /// The FINAL block body: the sealed (preferred) prefix followed by the
    /// plain selection, subject to ONE set of block caps.
    ///
    /// Each selector is capped INDEPENDENTLY: the plain selection gets the
    /// full [`MAX_BLOCK_TXS`]/[`MAX_BLOCK_GAS`] budget, while the sealed loop
    /// is only bounded by the tx count (it never accumulates gas). Simply
    /// concatenating them therefore admits a union of up to 2x either cap.
    /// The validator enforces the caps on the committed body
    /// (`validate_proposal_unaligned`), so an over-cap union is a block our
    /// OWN validators refuse — a liveness outage for any sealed-heavy pool.
    ///
    /// Truncate the union deterministically with the same rule the packer uses:
    /// the sealed prefix stays (it is the preferred path), the plain tail
    /// sheds first, and per-sender nonce contiguity survives because both runs
    /// are internally selection-ordered and the plain filter was seeded with
    /// the post-sealed nonce state.
    pub(super) fn final_block_body(
        sealed: Vec<Transaction>,
        plain: Vec<Transaction>,
    ) -> Vec<Transaction> {
        let mut txs: Vec<Transaction> = sealed.into_iter().chain(plain).collect();
        Self::truncate_to_block_caps(&mut txs);
        txs
    }

    /// Whether a prebuilt selection for `height` is cached.
    pub fn has_prebuild_for(&self, height: Height) -> bool {
        self.prebuilt_selection
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|c| c.for_height == height))
            .unwrap_or(false)
    }

    /// VEL-1 proposer-prebuild: run the plain-tx selection early (during the
    /// prevote idle window) and cache the ordered candidate list.
    ///
    /// Called by the tick when this node is about to need a proposal it has
    /// not built yet: either it owns the current round and is waiting out
    /// `min_block_time`, or it owns round 0 of the NEXT height (proposer
    /// lookahead is inherent to the hash schedule). The selection runs
    /// against CURRENT state with the CURRENT pool; `propose` revalidates
    /// every cached tx against LIVE state through the SAME predicate and
    /// tops up from the pool, so a parent that changed under the prebuild
    /// (the height finalized a different block, new txs arrived, a session
    /// expired) only shrinks or refreshes the reuse — validity is preserved
    /// by construction, and a total miss costs one bounded O(block)
    /// revalidation before falling back to a fresh build.
    ///
    /// Liveness-only, proposer-local: no wire bytes, no quorum input, no
    /// state transition. Skipped (no-op) while an apply is in flight (the
    /// state root would mislead the snapshot), when sealed txs are pending
    /// (the sealed path conditions plain selection on its own effects —
    /// reuse is disabled then, see `propose`), and when the cache already
    /// covers the target height.
    pub async fn prebuild_next_proposal(&mut self, timestamp: u64) {
        if !self.apply_in_flight.is_empty() {
            return;
        }
        // Target: our own imminent proposal — current round if we own it and
        // have not proposed, else round 0 of the next height if scheduled.
        let target = if self.is_proposer() && !self.hc.has_live_proposal() {
            self.hc.height
        } else if self.expected_proposer_at(&self.validators, self.hc.height + 1, 0)
            == Some(self.id)
        {
            // CN-VRF v3: never prebuild ACROSS an epoch boundary. The block at
            // `height + 1 == N * EPOCH_LEN` must carry that epoch's `MinRoot`
            // beacon and the beacon-driven schedule, neither of which is known
            // while the last block of the previous epoch is unfinalized.
            if self.cnvrf_v3_is_active_at(self.hc.height + 1)
                && (self.hc.height + 1).is_multiple_of(crate::cn_vrf::EPOCH_LEN)
            {
                return;
            }
            self.hc.height + 1
        } else {
            return;
        };
        if self.has_prebuild_for(target) {
            return;
        }
        // Sealed path conditions plain selection: a pending sealed set at
        // prebuild time may differ at propose time, so skip caching then
        // (bounded waste avoided entirely; propose falls back to fresh).
        // Cheap gate: the sealed index is empty in the common case.
        let has_sealed = !self.mempool.read().await.sealed_candidates().is_empty();
        if has_sealed {
            return;
        }
        let Some(ctx) = self.pack_filter_ctx(timestamp).await else {
            return;
        };
        let txs =
            self.mempool
                .read()
                .await
                .select_for_block_multi(MAX_BLOCK_TXS, MAX_BLOCK_GAS, |t| {
                    Self::pack_filter_accept(&ctx, t)
                });
        if let Ok(mut g) = self.prebuilt_selection.lock() {
            *g = Some(PrebuiltSelection {
                for_height: target,
                txs,
            });
        }
    }

    /// Build a fresh [`PackFilterCtx`] over live state (snapshot + fees +
    /// registry). `None` only when the snapshot cannot be taken; callers fall
    /// back to a fresh build path that reports the miss.
    pub(super) async fn pack_filter_ctx(&self, timestamp: u64) -> Option<PackFilterCtx> {
        let state_root = self.state.get_state_root().await;
        let senders: Vec<[u8; 32]> = self.mempool.read().await.fee_payers().into_iter().collect();
        let guard = self.state.accounts.read().await;
        let mut accounts: HashMap<[u8; 32], (u64, u64)> = HashMap::with_capacity(senders.len());
        for a in &senders {
            if let Some(acct) = guard.get(a) {
                accounts.insert(*a, (acct.nonce, acct.balance));
            }
        }
        drop(guard);
        // Soundness: only an exact root match means the entries are the live
        // state; anything else still yields a usable snapshot for the
        // revalidation/top-up (every kept tx is re-checked tx-by-tx below),
        // so no store gate is needed here.
        let _ = state_root;
        let fresh: Vec<[u8; 32]> = self.mempool.read().await.fee_payers().into_iter().collect();
        for s in missing_sender_accounts(&accounts, &fresh) {
            if let Some(acct) = self.state.get_account(&s).await {
                accounts.insert(s, (acct.nonce, acct.balance));
            }
        }
        let (base_fee, penalty_floors) = {
            let pool = self.mempool.read().await;
            (pool.base_fee, pool.penalty_snapshot())
        };
        let session_keys = self.state.session_keys_read().await.clone();
        Some(PackFilterCtx::new(
            timestamp,
            self.shard_registry.is_sharded(),
            self.shard_id,
            base_fee,
            penalty_floors,
            session_keys,
            accounts,
            crate::zkml::SessionSpendSim::default(),
            HashSet::new(),
        ))
    }

    // If we are the proposer, build a block from the mempool and sign it.
    // ==================================================================
    // Epoch seal (asymmetric, threshold-sealed transaction gossip)
    // ==================================================================

    /// How long the proposer waits for the peers' decryption partials.
    ///
    /// The share release is a network round trip (the peers release only
    /// after they see the order commitment), so the proposer waits for it —
    /// but BOUNDED, so a member that withholds its share can DELAY the
    /// round, never stall it. Zero disables the wait entirely (the sealed
    /// path then only ever unseals what the local node can unseal alone,
    /// which is nothing on a real committee).
    pub(super) fn seal_partial_wait_ms() -> u64 {
        static BUDGET: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
        *BUDGET.get_or_init(|| {
            std::env::var("STELL_MEV_UNSEAL_WAIT_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(500)
        })
    }

    /// Move the node's epoch-seal state to the current epoch.
    ///
    /// Called from the tick: when the chain crosses an epoch boundary the
    /// node starts the epoch's DKG (publishing its own contribution) and
    /// rotates the epoch key. The plain path is untouched: a node that is
    /// not a committee member, or whose remote signer keeps the long-term
    /// secret away from this process, simply has no epoch key and keeps
    /// serving plain transactions.
    pub async fn sync_mev_epoch(&mut self) {
        let epoch = crate::mev_epoch::epoch_of_height(self.hc.height);
        // --- MEV RESHARE HOOK (INACTIVE by default) ---
        // While MEV_RESHARE_ACTIVATION_HEIGHT == u64::MAX this branch never
        // fires and the single-DKG path below is byte-identical (pinned by the
        // pre-activation no-op test). When the lead flips the activation
        // height, a fresh DKG round starts only when reshare_due fires
        // (key_epoch + DELTA* <= chain epoch); otherwise NOTHING is synced —
        // the manager keeps the old key material AND the pool keeps admitting
        // the key epoch, so wallets sealing to the advertised (old) key are
        // still admitted (advancing admission without a fresh key would admit
        // envelopes nobody can unseal).
        if crate::mev_epoch::is_reshare_active(self.hc.height) {
            let last_reshare = self.mempool.read().await.mev_seal.epoch;
            if !crate::mev_epoch::reshare_due(
                epoch,
                last_reshare,
                crate::mev_epoch::MEV_RESHARE_DELTA_STAR_EPOCHS,
            ) {
                return;
            }
        }
        let ids: Vec<[u8; 32]> = self.validators.validators.keys().copied().collect();
        let our_id = self.key.verifying_key().to_bytes();
        let seed = self.key.to_bytes();
        let now = std::time::Instant::now();
        let pure_pq = crate::post_quantum::is_pure_pq_enforced();
        let mev_kem = self.mev_kem_material().await;
        let falcon = self.falcon_signing_key().cloned();
        let kem_announce: Option<crate::mev_epoch::MevFrame> = if pure_pq
            && self.validators.contains(&our_id)
        {
            if let (Some((registry, kem_seed)), Some(fk)) = (mev_kem.as_ref(), falcon.as_ref()) {
                let ek = crate::mev_epoch::pq_kem_ek_from_seed(kem_seed);
                if registry
                    .get_active_ek(&our_id, self.hc.height)
                    .is_some_and(|reg_ek| reg_ek != ek)
                {
                    tracing::warn!(
                        "[mev-seal] epoch {epoch}: local ML-KEM seed does not match our \
                             registered key; refusing to announce mismatched KEM key"
                    );
                    None
                } else {
                    let mut pool = self.mempool.write().await;
                    let due = pool
                        .last_kem_announce
                        .is_none_or(|last| now.duration_since(last) >= DKG_REPUBLISH_INTERVAL);
                    if due {
                        let activation_height = registry
                            .record_of(&our_id)
                            .map(|r| match &r.pending {
                                Some(p) if self.hc.height >= p.effective_height => {
                                    p.effective_height
                                }
                                _ => r.activated_at,
                            })
                            .unwrap_or(self.hc.height)
                            .min(self.hc.height);
                        match crate::mev_epoch::kem_key_announcement_seal(
                            fk,
                            self.state.chain_id,
                            our_id,
                            ek,
                            activation_height,
                        ) {
                            Ok(ann) => {
                                pool.last_kem_announce = Some(now);
                                pool.own_kem_announcement = Some(ann.clone());
                                Some(crate::mev_epoch::MevFrame::KemKey(ann))
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "[mev-seal] epoch {epoch}: failed to seal kem key \
                                         announcement: {e}"
                                );
                                None
                            }
                        }
                    } else {
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        };
        if let Some(frame) = kem_announce {
            tracing::info!("[mev-seal] epoch {epoch}: announcing our ML-KEM-768 transport key");
            self.gossip_mev_frame(frame).await;
        }
        let published: Option<crate::mev_epoch::MevFrame> = {
            let mut pool = self.mempool.write().await;
            pool.set_sealed_epoch(epoch);
            if !pure_pq {
                // The legacy `sync_epoch` entry point is an unconditional
                // refusal now (the classical X25519 transport is removed).
                // There is no safe non-PQ construction path, so fail closed
                // with the cause instead of calling a known-dead stub.
                tracing::warn!(
                    "[mev-seal] epoch {epoch}: legacy node-side DKG is disabled (classical \
                     X25519 transport removed); refusing epoch sealing"
                );
                None
            } else if let Some((registry, kem_seed)) = mev_kem.as_ref() {
                match pool.mev_seal.sync_epoch_pq(
                    epoch,
                    &ids,
                    our_id,
                    &seed,
                    kem_seed,
                    registry,
                    self.hc.height,
                ) {
                    Ok(c) => {
                        if let Some(contribution) = c {
                            let Some(fk) = falcon.as_ref() else {
                                tracing::warn!(
                                    "[mev-seal] epoch {epoch}: no Falcon-512 keypair; cannot \
                                     authenticate the DKG contribution in pure-PQ mode"
                                );
                                return;
                            };
                            let envelope = crate::mev_epoch::pq_transport_seal(fk, contribution);
                            // Ingest OUR OWN contribution locally: the epoch key
                            // is the aggregate over the WHOLE contributor set,
                            // and our own evaluation is one of its terms.
                            if let Err(e) = pool.mev_seal.ingest_contribution_pq(
                                &envelope,
                                kem_seed,
                                &our_id,
                                fk.public_key(),
                                registry,
                                self.hc.height,
                            ) {
                                tracing::debug!(
                                    "[mev-seal] our own pq dkg contribution refused: {e}"
                                );
                            }
                            pool.mev_seal.note_published(now);
                            Some(crate::mev_epoch::MevFrame::PqDkg(envelope))
                        } else {
                            None
                        }
                    }
                    Err(e) => {
                        tracing::debug!("[mev-seal] epoch {epoch}: no dkg ({e})");
                        None
                    }
                }
            } else {
                // Pinned fail-closed state: no registry/seed => no material.
                tracing::warn!(
                    "[mev-seal] epoch {epoch}: MEV sealing unavailable without KEM wiring \
                     (MEV KEM registry + node-local ML-KEM seed absent); refusing node-side DKG"
                );
                None
            }
        };
        if let Some(frame) = published {
            tracing::info!("[mev-seal] epoch {epoch}: published our pq dkg contribution");
            self.gossip_mev_frame(frame).await;
            // The DKG may have completed with our own contribution (we are
            // the last contributor the node was waiting for).
            self.publish_epoch_announcement().await;
            return;
        }
        // RE-PUBLISH: the contribution is re-sent on an interval until the
        // epoch key is ready. A peer that missed the first frame (a restart,
        // a dropped gossip message) would otherwise never receive it, and
        // the epoch's key generation would never complete.
        let republish = {
            let mut pool = self.mempool.write().await;
            if pure_pq
                && mev_kem.is_some()
                && pool
                    .mev_seal
                    .should_publish_contribution(now, DKG_REPUBLISH_INTERVAL)
            {
                let c = pool.mev_seal.own_contribution().cloned();
                if c.is_some() {
                    pool.mev_seal.note_published(now);
                }
                c
            } else {
                None
            }
        };
        if let Some(c) = republish {
            if let Some(fk) = falcon.as_ref() {
                tracing::debug!("[mev-seal] epoch {epoch}: re-publishing our pq dkg contribution");
                let envelope = crate::mev_epoch::pq_transport_seal(fk, c);
                self.gossip_mev_frame(crate::mev_epoch::MevFrame::PqDkg(envelope))
                    .await;
            }
        }
    }

    /// Publish the epoch-key announcement (the committee's agreement on the
    /// epoch key), once the DKG has completed.
    ///
    /// The announcement carries our signature over the epoch key; a light
    /// client collects the members' announcements, checks the quorum against
    /// the validator set and checks the commitment against the block.
    pub(super) async fn publish_epoch_announcement(&mut self) {
        let announcement = {
            let pool = self.mempool.read().await;
            if let Some(fk) = self.falcon_signing_key() {
                pool.mev_seal.build_announcement_pq(&self.key, fk).ok()
            } else if !crate::post_quantum::is_pure_pq_enforced() {
                pool.mev_seal.build_announcement(&self.key).ok()
            } else {
                None
            }
        };
        let Some(announcement) = announcement else {
            return;
        };
        tracing::info!(
            "[mev-seal] epoch {}: announcing the epoch key ({})",
            announcement.epoch,
            hex::encode(&announcement.commitment()[..6])
        );
        self.gossip_mev_frame(crate::mev_epoch::MevFrame::Announcement(announcement))
            .await;
    }

    /// Publish an epoch-seal frame on the transaction-gossip channel.
    pub(super) async fn gossip_mev_frame(&self, frame: crate::mev_epoch::MevFrame) {
        let Some(gossip) = self.tx_gossip.as_ref() else {
            return;
        };
        gossip.broadcast_mev_frame(&frame).await;
    }

    /// Handle one epoch-seal frame received from a peer.
    ///
    /// * a DKG contribution joins the epoch's key generation;
    /// * an order commitment releases OUR decryption partials (the gate on
    ///   the reveal: the order is fixed before anybody can read the
    ///   transactions);
    /// * a share release adds the peer's partials to the pool we unseal
    ///   with.
    pub async fn on_mev_frame(&mut self, frame: crate::mev_epoch::MevFrame) {
        match frame {
            crate::mev_epoch::MevFrame::Sealed(envelope) => {
                let mut pool = self.mempool.write().await;
                if let Err(e) = pool.add_sealed(envelope) {
                    tracing::debug!("[mev-seal] sealed admission refused: {e}");
                }
            }
            crate::mev_epoch::MevFrame::Dkg(_contribution) => {
                // FAIL-CLOSED: `ingest_contribution` is an unconditional
                // refusal now (the classical X25519 transport is removed) and
                // this frame carries no Falcon authentication, so it can never
                // enter the ML-KEM path either. Never call the dead stub and
                // never fall back.
                if crate::post_quantum::is_pure_pq_enforced() {
                    tracing::warn!(
                        "[mev-seal] unauthenticated dkg contribution refused in pure-PQ mode"
                    );
                } else {
                    tracing::warn!(
                        "[mev-seal] legacy dkg contribution refused: unauthenticated classical \
                         ingest removed (use the Falcon-sealed PqDkg frame)"
                    );
                }
            }
            crate::mev_epoch::MevFrame::PqDkg(envelope) => {
                let Some((scheme, pk)) = crate::consensus::pq_key_at_height(
                    &envelope.contribution.validator_id,
                    self.hc.height,
                ) else {
                    tracing::warn!(
                        "[mev-seal] pq dkg envelope refused: no registered PQ key for contributor"
                    );
                    return;
                };
                // FULL-PQ: Hybrid (0x04) is removed; a registered PQ key is
                // either Falcon-512 (verify directly) or ML-DSA-44 (disabled
                // fail-closed — refuse).
                let expected_falcon_pk: &[u8] = match scheme {
                    crate::post_quantum::PqScheme::Falcon512 => &pk,
                    _ => {
                        tracing::warn!(
                            "[mev-seal] pq dkg envelope refused: unsupported registered PQ scheme {:?}",
                            scheme
                        );
                        return;
                    }
                };
                if let Err(e) = crate::mev_epoch::pq_transport_verify(&envelope, expected_falcon_pk)
                {
                    tracing::warn!("[mev-seal] pq dkg envelope refused: {e}");
                    return;
                }
                if !crate::post_quantum::is_pure_pq_enforced() {
                    tracing::warn!(
                        "[mev-seal] pq dkg envelope refused: node-side DKG ingest requires \
                         pure-PQ mode (legacy classical ingest is removed)"
                    );
                    return;
                }
                let Some((registry, kem_seed)) = self.mev_kem_material().await else {
                    // Pinned fail-closed state: a valid envelope is NOT
                    // material without the KEM wiring. Never fall back to the
                    // removed classical transport.
                    tracing::warn!(
                        "[mev-seal] pq dkg envelope refused: MEV sealing unavailable without \
                         KEM wiring (MEV KEM registry + node-local ML-KEM seed absent)"
                    );
                    return;
                };
                let (material, announcement) = {
                    let mut pool = self.mempool.write().await;
                    if let Err(e) = pool.mev_seal.ingest_contribution_pq(
                        &envelope,
                        &kem_seed,
                        &self.id,
                        expected_falcon_pk,
                        &registry,
                        self.hc.height,
                    ) {
                        tracing::debug!("[mev-seal] pq dkg contribution refused: {e}");
                        return;
                    }
                    let material = pool.mev_seal.material().cloned();
                    let announcement = material.as_ref().and_then(|_| {
                        if let Some(fk) = self.falcon_signing_key() {
                            pool.mev_seal.build_announcement_pq(&self.key, fk).ok()
                        } else if !crate::post_quantum::is_pure_pq_enforced() {
                            pool.mev_seal.build_announcement(&self.key).ok()
                        } else {
                            None
                        }
                    });
                    (material, announcement)
                };
                if let Some(material) = material {
                    tracing::info!(
                        "[mev-seal] epoch {} key ready (threshold {})",
                        material.epoch,
                        material.threshold
                    );
                }
                if let Some(announcement) = announcement {
                    self.gossip_mev_frame(crate::mev_epoch::MevFrame::Announcement(announcement))
                        .await;
                }
            }
            crate::mev_epoch::MevFrame::OrderCommit(commitment) => {
                let Some(expected_proposer) = self.expected_proposer_at(
                    &self.validators,
                    commitment.height,
                    commitment.round,
                ) else {
                    tracing::warn!(
                        "[mev-seal] order commitment refused: no scheduled proposer for h={} r={}",
                        commitment.height,
                        commitment.round
                    );
                    return;
                };
                let expected_falcon_pk =
                    crate::consensus::pq_key_at_height(&commitment.proposer, commitment.height)
                        .and_then(|(scheme, pk)| {
                            if scheme == crate::post_quantum::PqScheme::Falcon512 {
                                Some(pk)
                            } else {
                                None
                            }
                        });
                {
                    let mut pool = self.mempool.write().await;
                    if let Err(e) = pool.mev_seal.note_commitment_verified(
                        commitment.clone(),
                        Some(expected_proposer),
                        expected_falcon_pk.as_deref(),
                    ) {
                        tracing::warn!("[mev-seal] order commitment refused: {e}");
                        return;
                    }
                }
                // The order is committed: release our decryption partials.
                self.release_sealed_partials(&commitment).await;
            }
            crate::mev_epoch::MevFrame::Release(release) => {
                if crate::post_quantum::is_pure_pq_enforced() {
                    tracing::warn!(
                        "[mev-seal] unauthenticated share release refused in pure-PQ mode"
                    );
                    return;
                }
                let mut pool = self.mempool.write().await;
                match pool.mev_seal.ingest_release(release) {
                    Ok(n) => tracing::debug!("[mev-seal] accepted {n} decryption partial(s)"),
                    Err(e) => tracing::debug!("[mev-seal] share release refused: {e}"),
                }
            }
            crate::mev_epoch::MevFrame::PqRelease(envelope) => {
                let Some((scheme, pk)) = crate::consensus::pq_key_at_height(
                    &envelope.signer_id,
                    envelope.release.height,
                ) else {
                    tracing::warn!(
                        "[mev-seal] pq share release refused: no registered PQ key for signer"
                    );
                    return;
                };
                let expected_falcon_pk: &[u8] = match scheme {
                    crate::post_quantum::PqScheme::Falcon512 => &pk,
                    _ => {
                        tracing::warn!(
                            "[mev-seal] pq share release refused: unsupported PQ scheme {:?}",
                            scheme
                        );
                        return;
                    }
                };
                let mut pool = self.mempool.write().await;
                let ephemeral_pks: HashMap<[u8; 32], [u8; 32]> = envelope
                    .release
                    .partials
                    .iter()
                    .filter_map(|(tx_hash, _)| {
                        pool.sealed_envelope(tx_hash)
                            .map(|env| (*tx_hash, env.ephemeral_pk))
                    })
                    .collect();
                match pool.mev_seal.ingest_release_authenticated_with_ephemeral(
                    &envelope,
                    expected_falcon_pk,
                    |tx_hash| ephemeral_pks.get(tx_hash).copied(),
                ) {
                    Ok(n) => tracing::debug!("[mev-seal] accepted {n} pq decryption partial(s)"),
                    Err(e) => tracing::debug!("[mev-seal] pq share release refused: {e}"),
                }
            }
            crate::mev_epoch::MevFrame::Announcement(announcement) => {
                // The epoch-key announcement: the committee's agreement on
                // the epoch key. It is merged (its signatures only) so a
                // light client can check the quorum against the validator
                // set, and the commitment against the block.
                let mut pool = self.mempool.write().await;
                if let Err(e) = pool.mev_seal.merge_announcement(announcement) {
                    tracing::debug!("[mev-seal] epoch announcement refused: {e}");
                }
            }
            crate::mev_epoch::MevFrame::KemKey(ann) => {
                if !self.validators.contains(&ann.validator_id) {
                    tracing::warn!(
                        "[mev-seal] kem key announcement refused: sender is not in validator set"
                    );
                    return;
                }
                if ann.chain_id != self.state.chain_id {
                    tracing::warn!(
                        "[mev-seal] kem key announcement refused: chain_id {} != expected {}",
                        ann.chain_id,
                        self.state.chain_id
                    );
                    return;
                }
                if ann.activation_height > self.hc.height {
                    tracing::warn!(
                        "[mev-seal] kem key announcement refused: activation_height {} > current height {}",
                        ann.activation_height,
                        self.hc.height
                    );
                    return;
                }
                if !crate::post_quantum::is_pure_pq_enforced() {
                    tracing::warn!(
                        "[mev-seal] kem key announcement refused: requires pure-PQ mode"
                    );
                    return;
                }
                let Some((base_registry, _)) = self.mev_kem_material().await else {
                    tracing::warn!(
                        "[mev-seal] kem key announcement refused: MEV sealing unavailable \
                         without KEM wiring (MEV KEM registry + node-local ML-KEM seed absent)"
                    );
                    return;
                };
                let Some((scheme, pk)) =
                    crate::consensus::pq_key_at_height(&ann.validator_id, self.hc.height)
                else {
                    tracing::warn!(
                        "[mev-seal] kem key announcement refused: no registered PQ key for validator"
                    );
                    return;
                };
                let expected_falcon_pk: &[u8] = match scheme {
                    crate::post_quantum::PqScheme::Falcon512 => &pk,
                    _ => {
                        tracing::warn!(
                            "[mev-seal] kem key announcement refused: unsupported registered PQ \
                             scheme {:?}",
                            scheme
                        );
                        return;
                    }
                };
                if let Err(e) = crate::mev_epoch::kem_key_announcement_verify(
                    &ann,
                    self.state.chain_id,
                    expected_falcon_pk,
                ) {
                    tracing::warn!("[mev-seal] kem key announcement refused: {e}");
                    return;
                }
                if let Some(existing) = base_registry.record_of(&ann.validator_id) {
                    if existing.ek == ann.ek {
                        tracing::debug!(
                            "[mev-seal] idempotent ML-KEM-768 key re-announcement for validator {}",
                            hex::encode(&ann.validator_id[..6])
                        );
                        return;
                    }
                    tracing::warn!(
                        "[mev-seal] kem key announcement refused for {}: already registered with \
                         a different key (rotation required)",
                        hex::encode(&ann.validator_id[..6])
                    );
                    return;
                }
                let mut pool = self.mempool.write().await;
                match pool.upsert_peer_kem_ek(
                    ann.validator_id,
                    ann.ek,
                    ann.activation_height,
                    self.hc.height,
                    true,
                ) {
                    Ok(true) => {
                        tracing::info!(
                            "[mev-seal] learned ML-KEM-768 transport key for validator {}",
                            hex::encode(&ann.validator_id[..6])
                        );
                    }
                    Ok(false) => {
                        tracing::debug!(
                            "[mev-seal] idempotent ML-KEM-768 key re-announcement for validator {}",
                            hex::encode(&ann.validator_id[..6])
                        );
                    }
                    Err(e) => {
                        tracing::warn!("[mev-seal] kem key announcement refused by registry: {e}");
                    }
                }
            }
        }
    }

    /// Release our decryption partials for the transactions of a committed
    /// order, and publish them.
    ///
    /// The release happens ONLY after the order commitment has been seen:
    /// that is the property the whole scheme exists for.
    pub(super) async fn release_sealed_partials(
        &mut self,
        commitment: &crate::mev_epoch::OrderCommitment,
    ) {
        let height = commitment.height;
        let round = commitment.round;
        let epoch = commitment.epoch;
        let order_root = commitment.order_root;
        let mut release = crate::mev_epoch::ShareRelease {
            epoch,
            height,
            round,
            order_root,
            partials: Vec::new(),
        };
        let mut dleq_proofs: Vec<([u8; 32], crate::mev_epoch::PartialDleqProof)> = Vec::new();
        let envelopes: Vec<([u8; 32], crate::mev_epoch::SealedEnvelope)> = {
            let pool = self.mempool.read().await;
            commitment
                .tx_hashes
                .iter()
                .filter_map(|tx_hash| {
                    pool.sealed_envelope(tx_hash)
                        .cloned()
                        .map(|env| (*tx_hash, env))
                })
                .collect()
        };
        if envelopes.is_empty() {
            return;
        }
        {
            let mut pool = self.mempool.write().await;
            for (tx_hash, envelope) in &envelopes {
                let partial = pool.mev_seal.release_partial(height, round, envelope);
                let dleq_opt = match (&partial, pool.mev_seal.material()) {
                    (Ok(p), Some(mat)) => crate::mev_epoch::prove_partial_dleq(
                        &mat.share,
                        epoch,
                        p.validator_index,
                        &envelope.ephemeral_pk,
                        &p.point,
                    )
                    .ok(),
                    _ => None,
                };
                match partial {
                    Ok(p) => {
                        if let Some(proof) = dleq_opt {
                            dleq_proofs.push((*tx_hash, proof));
                        }
                        release.partials.push((*tx_hash, p));
                    }
                    Err(e) => tracing::debug!("[mev-seal] partial refused: {e}"),
                }
            }
        }
        if release.partials.is_empty() {
            return;
        }
        tracing::info!(
            "[mev-seal] released {} decryption partial(s) for h={height} r={round}",
            release.partials.len()
        );
        if let Some(fk) = self.falcon_signing_key() {
            let envelope = crate::mev_epoch::pq_share_release_seal_with_dleq(
                fk,
                self.id,
                release,
                dleq_proofs,
            );
            self.gossip_mev_frame(crate::mev_epoch::MevFrame::PqRelease(envelope))
                .await;
        } else {
            tracing::warn!(
                "[mev-seal] Falcon-512 keypair required to release authenticated partials; skipping gossip"
            );
        }
    }

    /// The EPOCH-SEAL proposer path: unseal the committed sealed
    /// transactions.
    /// THE ORDER OF OPERATIONS (the whole point of the scheme):
    ///
    /// 1. the candidate order (the sealed transaction hashes, in the pool's
    ///    order) is COMMITTED — signed and gossiped — BEFORE any content is
    ///    revealed;
    /// 2. only then are the decryption partials released and collected;
    /// 3. only then is the content unsealed.
    ///
    /// A sealed transaction whose partials never arrive is DROPPED (its
    /// sender is charged the failure bond): the round is never stalled by a
    /// member that withholds its share.
    pub(super) async fn sealed_proposer_path(&mut self, timestamp: u64) -> Vec<Transaction> {
        let (committee_hash, threshold, candidates) = {
            let pool = self.mempool.read().await;
            let Some(material) = pool.mev_seal.material() else {
                return Vec::new();
            };
            let candidates = pool.sealed_candidates();
            if candidates.is_empty() {
                return Vec::new();
            }
            (material.committee_hash, material.threshold, candidates)
        };
        let height = self.hc.height;
        let round = self.hc.round;
        // 1. COMMIT the order.
        //
        //    The order of a HEIGHT is committed ONCE: a second round of the
        //    same height re-uses the commitment it already made, so a sealed
        //    transaction that arrives mid-height cannot silently re-order the
        //    round (it waits for the next height). The first commitment for
        //    the height is the one that is gossiped, and it is the one the
        //    members release their partials against.
        let (commitment, candidates) = {
            let mut pool = self.mempool.write().await;
            let existing = pool.mev_seal.height_commitment(height).cloned();
            match existing {
                Some(commitment) => {
                    // Re-use the committed order: only the transactions it
                    // names are unsealed, in ITS order.
                    let mut ordered = Vec::with_capacity(commitment.tx_hashes.len());
                    for tx_hash in &commitment.tx_hashes {
                        if let Some(envelope) = pool.sealed_envelope(tx_hash) {
                            ordered.push(envelope.clone());
                        }
                    }
                    (commitment, ordered)
                }
                None => {
                    let tx_hashes: Vec<[u8; 32]> = candidates.iter().map(|c| c.tx_hash).collect();
                    let res = if let Some(fk) = self.falcon_signing_key() {
                        pool.mev_seal
                            .commit_order_pq(height, round, tx_hashes, &self.key, fk)
                    } else if !crate::post_quantum::is_pure_pq_enforced() {
                        pool.mev_seal
                            .commit_order(height, round, tx_hashes, &self.key)
                    } else {
                        Err("pure-PQ requires Falcon-512 keypair for order commitment".to_string())
                    };
                    match res {
                        Ok(c) => (c, candidates),
                        Err(e) => {
                            tracing::warn!("[mev-seal] order commitment refused: {e}");
                            return Vec::new();
                        }
                    }
                }
            }
        };
        if candidates.is_empty() {
            return Vec::new();
        }
        // 2. Release our own partials and publish the commitment, so the
        //    peers can release theirs.
        self.gossip_mev_frame(crate::mev_epoch::MevFrame::OrderCommit(commitment.clone()))
            .await;
        self.release_sealed_partials(&commitment).await;
        // 2b. WAIT (BOUNDED) for the peers' partials.
        //
        // The share release is a network round trip: the peers can only
        // release after they have seen the commitment we just gossiped. The
        // proposer therefore waits — but only BOUNDED, and only when there
        // is something to unseal: a member that withholds its share must
        // never be able to stall the round (the timeout path below drops
        // the transaction and charges its sender).
        self.await_sealed_partials(&candidates, threshold).await;
        // 3. Unseal what we can.
        let mut out: Vec<Transaction> = Vec::new();
        let mut dropped: Vec<(crate::mev_epoch::SealedEnvelope, DropReason)> = Vec::new();
        let committee_size = {
            let pool = self.mempool.read().await;
            pool.mev_seal.committee().map(|c| c.members.len())
        };
        for candidate in &candidates {
            let partials = {
                let pool = self.mempool.read().await;
                pool.mev_seal.partials_for(&candidate.tx_hash)
            };
            if partials.len() < threshold {
                // Not enough shares: the transaction is dropped (the sender
                // is charged the failure bond), never stalled.
                dropped.push((candidate.clone(), DropReason::NotEnoughShares));
                continue;
            }
            if let Some(n) = committee_size {
                if let Err(e) = crate::mev_epoch::combine_partials_checked(&partials, threshold, n)
                {
                    tracing::warn!("[mev-seal] partial bounds check failed: {e}");
                    dropped.push((candidate.clone(), DropReason::Undecryptable));
                    continue;
                }
            }
            let plaintext = match match committee_size {
                Some(n) => crate::mev_epoch::unseal_transaction_checked(
                    candidate,
                    &partials,
                    threshold,
                    &committee_hash,
                    n,
                ),
                None => crate::mev_epoch::unseal_transaction(
                    candidate,
                    &partials,
                    threshold,
                    &committee_hash,
                ),
            } {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!("[mev-seal] unseal failed: {e}");
                    dropped.push((candidate.clone(), DropReason::Undecryptable));
                    continue;
                }
            };
            let tx: Transaction = match bincode::deserialize(&plaintext) {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!("[mev-seal] unsealed payload is not a transaction: {e}");
                    dropped.push((candidate.clone(), DropReason::NotATransaction));
                    continue;
                }
            };
            // The plaintext MUST match the envelope: the hash binds the
            // content, and the transparent metadata binds the ordering
            // fields. A wallet that lies about either is dropped.
            if tx.compute_tx_hash() != candidate.tx_hash {
                tracing::warn!("[mev-seal] unsealed transaction does not match its envelope");
                dropped.push((candidate.clone(), DropReason::HashMismatch));
                continue;
            }
            if !Self::sealed_meta_matches(&tx, &candidate.meta) {
                tracing::warn!("[mev-seal] unsealed transaction does not match its metadata");
                dropped.push((candidate.clone(), DropReason::MetaMismatch));
                continue;
            }
            if !tx.verify_signature() {
                tracing::warn!("[mev-seal] unsealed transaction has an invalid signature");
                dropped.push((candidate.clone(), DropReason::BadSignature));
                continue;
            }
            out.push(tx);
        }
        // 4. The DROPPED transactions: evict them from the pool (a sealed
        //    transaction that can never be unsealed must not hold pool
        //    space) and charge their sender the failure bond, exactly like
        //    a transaction that fails at apply.
        {
            let mut pool = self.mempool.write().await;
            pool.mev_seal.unsealed += out.len() as u64;
            pool.mev_seal.unseal_failures += dropped.len() as u64;
            for (envelope, reason) in &dropped {
                pool.drop_sealed(&envelope.tx_hash, &envelope.meta.from);
                tracing::info!(
                    "[mev-seal] dropped sealed transaction {} ({reason:?}): the sender is charged the failure bond",
                    hex::encode(&envelope.tx_hash[..6])
                );
            }
        }
        if !dropped.is_empty() {
            crate::metrics::global().inc_mev_unsealed(out.len() as u64);
            crate::metrics::global().inc_mev_unseal_failed(dropped.len() as u64);
            tracing::info!(
                "[mev-seal] h={height} r={round}: unsealed {} of {} sealed transaction(s), dropped {}",
                out.len(),
                candidates.len(),
                dropped.len()
            );
        } else {
            crate::metrics::global().inc_mev_unsealed(out.len() as u64);
        }
        let _ = timestamp;
        out
    }

    /// Wait (BOUNDED) for the peers' decryption partials.
    ///
    /// The wait is bounded by [`seal_partial_wait_ms`] and is skipped
    /// entirely when every candidate already has enough partials. It is the
    /// only place the proposer BLOCKS on the private path, and it is
    /// bounded so that a member which withholds its share can delay the
    /// round but never stall it.
    pub(super) async fn await_sealed_partials(
        &self,
        candidates: &[crate::mev_epoch::SealedEnvelope],
        threshold: usize,
    ) {
        let budget = Self::seal_partial_wait_ms();
        if budget == 0 {
            return;
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(budget);
        loop {
            let pending = {
                let pool = self.mempool.read().await;
                candidates
                    .iter()
                    .filter(|c| pool.mev_seal.partial_count(&c.tx_hash) < threshold)
                    .count()
            };
            if pending == 0 || std::time::Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(SEAL_PARTIAL_POLL_MS)).await;
        }
    }

    /// Re-stamp a rescued (locked/demanded) body at `round` and re-sign it
    /// (ruleset v6, R-B).
    ///
    /// The block hash commits the signed BFT round, so serving a locked body
    /// "verbatim" re-serves an OLD round forever. Acceptors then prevote the
    /// body's old signed round; once the fsynced vote watermark has moved
    /// above it (a nil vote in a later round is enough), the driver refuses
    /// that vote and no value vote is ever cast — the live permanent stall.
    ///
    /// The VALUE identity is round-free ([`Block::value_id`]), so the body's
    /// author rebuilds the identical value at the round it is proposing for
    /// (all fields except `round`, plus fresh signatures) and serves THAT.
    /// Locked peers recognise it through `HeightConsensus::same_value`, and
    /// every voter stamps the current round, strictly above the watermark.
    ///
    /// A body authored by ANOTHER validator is returned unmodified: only its
    /// author can produce a valid proposer signature, and rewriting
    /// `proposer` would change the value identity (hence the lock) itself.
    /// The demanded rescue only ever stores our own bodies; for a foreign
    /// locked body the normal phase-alignment path still applies.
    fn restamp_for_round(&self, body: &Block, round: Round) -> Option<Block> {
        if !self.safety.can_sign() {
            return None;
        }
        if body.proposer != self.id || body.round == round {
            return Some(body.clone());
        }
        let mut out = body.clone();
        out.round = round;
        out.validator_signatures.clear();
        // One hash for the proposer signature and the store key below.
        let digest = out.compute_hash();
        let req = crate::remote_signer::ConsensusSignRequest::Proposal {
            chain_id: crate::consensus::consensus_chain_id(),
            shard_id: self.shard_id,
            height: out.height,
            round,
            block_hash: digest,
        };
        let signer = self.vote_signer_for(req);
        let (sig, falcon_sig) = self
            .safety
            .authorize_and_sign_proposal(out.height, round, digest, &signer)
            .ok()?;
        out.validator_signatures.push((self.id, sig));
        if let Some((falcon_id, fsig)) = falcon_sig {
            out.validator_signatures.push((falcon_id, fsig));
        }
        Some(out)
    }

    pub async fn propose(&mut self, timestamp: u64) -> Option<Block> {
        if !self.safety.can_sign() {
            return None;
        }
        if self.parallel_exec {
            self.state.set_parallel_exec(true);
        }
        if !self.is_proposer() || self.hc.step != Step::Propose {
            return None;
        }
        if crate::chain_spec::execution_pipeline_v1_active_at(self.hc.height) {
            self.ensure_genesis_root_seeded().await;
        }
        // §7 Phase 2 / Wave 12 Phase 2b gate: below `EXECUTION_PIPELINE_V1`, any
        // pending apply blocks proposing (state_root is PRE-H). At/above the
        // gate, lag-2 pipelining allows proposing when `apply_in_flight` holds
        // at most 1 block and the committed post-state for `height - 2` is
        // already recorded.
        if !self.can_propose_at_height(self.hc.height) {
            return None;
        }
        let pipeline_active = crate::chain_spec::execution_pipeline_v1_active_at(self.hc.height);
        // PARENT-BOUND PROPOSAL (HEIGHT-SPLIT): a block's `prev_hash` is always
        // our decided tip (`finalized.last()`, or the queued `height - 1`
        // parent in `apply_in_flight` when lag-2 pipelining is active).
        let (finalized_tip, finalized_hash) = if pipeline_active {
            if let Some(inflight) = self
                .apply_in_flight
                .back()
                .filter(|a| a.height.checked_add(1) == Some(self.hc.height))
            {
                (inflight.height, inflight.hash)
            } else {
                self.finalized.last().copied().unwrap_or((0, [0u8; 32]))
            }
        } else {
            self.finalized.last().copied().unwrap_or((0, [0u8; 32]))
        };
        if finalized_tip.checked_add(1) != Some(self.hc.height) {
            tracing::warn!(
                hc_height = self.hc.height,
                finalized_tip,
                "refusing to propose above our own finalized parent (height/head disagrees)"
            );
            return None;
        }
        // DOWNTIME-RESTORE (fail closed): if boot could not rebuild the
        // parent's decision QC from the persisted finalized block, this node
        // cannot attach the canonical downtime evidence. Peers that decided
        // the parent reject such an omission, so emitting the block would
        // stall the network while we hold the slot. Skip the slot instead and
        // wait for a verified peer decision to restore the evidence.
        if self.parent_evidence_missing {
            tracing::error!(
                height = self.hc.height,
                parent_height = finalized_tip,
                parent_hash = %hex::encode(finalized_hash),
                "DOWNTIME-RESTORE: refusing to propose without the parent downtime evidence (fail closed)"
            );
            eprintln!(
                "[consensus] REFUSING to propose at height {}: the downtime evidence for \
                 decided height {} ({}) could not be reconstructed from persisted data; \
                 skipping this proposal slot (fail closed)",
                self.hc.height,
                finalized_tip,
                hex::encode(finalized_hash)
            );
            return None;
        }
        // Liveness: a locked proposer re-proposes its locked value. Building a
        // fresh block while locked is voted nil by every node locked on the old
        // value (including ourselves) while unlocked nodes vote the fresh one
        // -- no quorum either way, forever. Re-proposing the locked body lets
        // the network converge on it: unlocked nodes vote it, nodes locked on
        // it vote it, a QC forms, finalize. The lock is per-height (a new
        // height constructs a fresh HeightConsensus), bodies are retained, and
        // we only ever lock values we voted for, so the body is present; if it
        // is somehow gone, fall through to a fresh block rather than forfeit
        // our proposer rounds entirely.
        // C1 genesis anchor: first messages reference the zero-hash parent
        // with the current (genesis) root, which no finalize event ever
        // records. Note it here (idempotent, overwritten by real finals):
        // without this, height-1 cross-shard transfers can never anchor.
        // Root read FIRST, lock second: the guard must never be held across
        // the await (std guards are !Send).
        if self.finalized.is_empty() {
            if let Some(reg) = self.finalized_headers.clone() {
                let root = self.state.get_state_root().await;
                if let Ok(mut r) = reg.write() {
                    r.note_finalized(self.shard_id, [0u8; 32], root);
                }
            }
        }
        if let Some((locked_hash, _)) = self.hc.locked {
            // LOCK RESCUE (protocol-critical): re-propose the locked VALUE.
            //
            // The lookup is by VALUE as well as by signed hash (ruleset v6):
            // a lock may name a hash we re-stamped away from, so if the exact
            // body is gone we serve any body at this height with the same
            // round-free `value_id`. Substituting a DIFFERENT value would
            // abandon what the network is locked on — `sim_nil_grace_tests`
            // shows the failure directly (nodes vote NIL instead of VALUE and
            // the height churns).
            //
            // The body is then RE-STAMPED at our current round and re-signed
            // (`restamp_for_round`). Serving the original signed round is the
            // permanent-stall bug: acceptors prevote that stale round and the
            // fsynced watermark refuses it. A body another validator authored
            // is served unmodified (only its author can sign it; rewriting
            // `proposer` would change the value itself).
            let locked_body = self.blocks.get(&locked_hash).cloned().or_else(|| {
                let vid = self.hc.value_id_of(&locked_hash)?;
                self.blocks
                    .values()
                    .find(|b| b.height == self.hc.height && b.value_id() == vid)
                    .cloned()
            });
            if let Some(body) = locked_body {
                // Info when bypassing a non-empty pool (audit: blocks
                // troubles): locked re-proposals skip fresh selection, so an
                // empty locked body with a full mempool looks identical to an
                // empty chain without this line.
                let pool_len = self.mempool.read().await.len();
                if pool_len > 0 {
                    tracing::info!(
                        "propose h={} r={}: path=locked txs={} mempool={} (bypasses fresh selection)",
                        self.hc.height,
                        self.hc.round,
                        body.transactions.len(),
                        pool_len,
                    );
                } else {
                    tracing::debug!(
                        "propose h={} r={}: path=locked txs={} mempool=0",
                        self.hc.height,
                        self.hc.round,
                        body.transactions.len(),
                    );
                }
                let served = self.restamp_for_round(&body, self.hc.round)?;
                let served_hash = served.compute_hash();
                // Register BOTH signed hashes against the same round-free
                // value: the lock rule then treats the re-stamp as the locked
                // value. Keep the ORIGINAL body available in `blocks` (body
                // serving and lock-hint resolution may still name it).
                self.hc.note_value_id(locked_hash, body.value_id());
                self.hc.note_value_id(served_hash, served.value_id());
                if served_hash != locked_hash {
                    self.blocks.insert(served_hash, served.clone());
                }
                // Self-record like the fresh path: without this the section-1
                // gate (`!has_live_proposal`) refires every tick and
                // rebroadcasts the identical hash all round (refire spam).
                let expected = self.expected_proposer_now();
                self.hc
                    .receive_proposal_for(self.id, served_hash, expected)
                    .ok()?;
                return Some(served);
            }
        }
        // PROPOSER VALUE PREFERENCE (WAN late-polka liveness): while this
        // height has NO observed polka, prefer re-proposing the value WE
        // LAST PREVOTED over building a fresh, conflicting one.
        //
        // WHY (measured on `masterchain_liveness_tests::
        // a_late_polka_is_still_precommitted{,_four_validators}`): the
        // validator with the stalled inbound link never sees the polka that
        // its own prevote helped form. It times out, becomes proposer, and
        // offers a FRESH block at a later round; peers locked on the polka
        // value nil it, the proposer prevotes it itself, and that later
        // non-nil prevote is exactly what the cross-kind guard then uses to
        // refuse `precommit(r_polka, B0)` when the late polka finally
        // arrives. The height then waits for the polka author's next proposer
        // slot (which can be far away), so a 300 s stand finalizes at most one
        // height. Re-proposing the last prevoted value instead keeps the
        // validator's own signed history coherent with the network: it either
        // votes that value (same round it was signed in, already-voted rounds
        // are refused by the watermark) or casts NO prevote at all -- never a
        // conflicting non-nil one. If WE authored the value, `restamp_for_round`
        // re-stamps it at the current round and the polka re-forms there; if
        // another validator did, the body is served unmodified and its author
        // re-stamps it on its own slot, still above our untouched floor.
        //
        // SAFETY: proposing is not voting. The body is one this node already
        // validated and voted for, at this height; voters apply the normal
        // signature/round/lock/watermark checks. The lock branch above keeps
        // priority (an adopted lock is never bypassed by a stale prevote).
        //
        // BOUNDED WINDOW: the preference lasts only `ROUND_LOOKBACK` rounds.
        // A foreign value cannot be re-stamped by us (only its author can
        // sign it), so if its author is gone the network must still be able
        // to move on: after the window a fresh block is proposed again, which
        // is exactly the pre-existing behaviour. The window is wide enough to
        // cover the live late-polka shape (the deaf node's own slots fall
        // within a few rounds of the prevote).
        if self.hc.locked.is_none() && self.hc.observed_polka().is_none() {
            if let Some(last) = self
                .safety
                .current_state()
                .and_then(|s| s.last_non_nil_prevote)
                .filter(|last| {
                    self.hc.round.saturating_sub(last.round) <= crate::consensus::ROUND_LOOKBACK
                })
            {
                let body = self.blocks.get(&last.block_hash).cloned().or_else(|| {
                    let vid = self.hc.value_id_of(&last.block_hash)?;
                    self.blocks
                        .values()
                        .find(|b| b.height == self.hc.height && b.value_id() == vid)
                        .cloned()
                });
                if let Some(body) = body {
                    if body.height == self.hc.height
                        && body.proposer == self.id
                        && body.timestamp > 0
                    {
                        let served = self.restamp_for_round(&body, self.hc.round)?;
                        let served_hash = served.compute_hash();
                        self.hc.note_value_id(last.block_hash, body.value_id());
                        self.hc.note_value_id(served_hash, served.value_id());
                        if served_hash != last.block_hash {
                            self.blocks.insert(served_hash, served.clone());
                        }
                        let expected = self.expected_proposer_now();
                        self.hc
                            .receive_proposal_for(self.id, served_hash, expected)
                            .ok()?;
                        return Some(served);
                    }
                }
            }
        }
        // Rescue: a peer is locked on one of OUR VALUES (learned via nil-vote
        // lock hints). The demand is keyed by the round-free `value_id`
        // (ruleset v6), so a hint naming an older signed round still resolves
        // after any number of re-stamps. Re-propose the value at our own
        // current round: receivers validate it normally, the locked peer
        // votes it (same value, lock comparison accepts the re-stamp),
        // unlocked peers vote it, QC forms, finalize. One shot per hint batch
        // -- a still-stuck peer re-hints and we serve again.
        if self.demanded_height != self.hc.height {
            self.demanded.clear();
            self.demanded_height = self.hc.height;
        }
        if let Some(value_id) = self.demanded.iter().copied().min() {
            let demanded_body = self
                .blocks
                .values()
                .filter(|b| {
                    b.height == self.hc.height && b.proposer == self.id && b.value_id() == value_id
                })
                // Any signed copy is the same value; prefer the newest round
                // for deterministic selection independent of map order.
                .max_by_key(|b| b.round)
                .cloned();
            match demanded_body {
                None => {
                    // Unknown or stale value (never seen, or a previous
                    // height): drop it and fall through to fresh selection
                    // below; a still-stuck peer re-hints on its next nil
                    // prevote.
                    self.demanded.remove(&value_id);
                }
                Some(body) => {
                    let root = if pipeline_active {
                        self.state_root_for_committed_height(self.hc.height)?
                    } else {
                        self.state.get_state_root().await
                    };
                    if self.validate_proposal_unaligned(&body, root).is_ok()
                        && self.check_actor_cap(&body).await.is_ok()
                    {
                        let pool_len = self.mempool.read().await.len();
                        if pool_len > 0 {
                            tracing::info!(
                            "propose h={} r={}: path=demanded txs={} mempool={} (bypasses fresh selection)",
                            self.hc.height,
                            self.hc.round,
                            body.transactions.len(),
                            pool_len,
                        );
                        } else {
                            tracing::debug!(
                                "propose h={} r={}: path=demanded txs={} mempool=0",
                                self.hc.height,
                                self.hc.round,
                                body.transactions.len(),
                            );
                        }
                        // Re-stamp the demanded value at the round we are
                        // proposing for and re-sign it (ruleset v6). Serving
                        // the original signed round would be refused by the
                        // fsynced watermark exactly when it matters.
                        let Some(served) = self.restamp_for_round(&body, self.hc.round) else {
                            // No signer right now: keep the demand so the
                            // next tick retries; never serve an unsigned body.
                            return None;
                        };
                        let bh = served.compute_hash();
                        // Register both signed identities against the value,
                        // and keep the ORIGINAL body for body serving.
                        self.hc.note_value_id(bh, served.value_id());
                        self.hc.note_value_id(body.compute_hash(), body.value_id());
                        self.blocks.insert(bh, served.clone());
                        let expected = self.expected_proposer_now();
                        self.hc.receive_proposal_for(self.id, bh, expected).ok()?;
                        // Served: consume one-shot (a still-stuck peer re-hints).
                        self.demanded.remove(&value_id);
                        return Some(served);
                    }
                    // Re-validation failed (transient state/backlog read):
                    // KEEP the demand so the next tick retries instead of
                    // waiting a full hint round-trip. The set stays bounded
                    // (MAX_DEMANDED) and height-scoped, so this cannot pile up.
                }
            }
        }
        let state_root = if pipeline_active {
            self.state_root_for_committed_height(self.hc.height)?
        } else {
            self.state.get_state_root().await
        };
        // Anti-DoS: bound the block by BOTH tx count and total gas.
        // Both caps plus the admission filter, so a flood of transactions that
        // cannot execute (spent nonce, drained balance) cannot occupy the block
        // and be paid for like real work. `evict_unexecutable` cleans these up
        // each round; this stops them costing anything in the meantime.
        //
        // Sender state is gathered first because the filter itself is
        // synchronous: it walks the fee-ordered index once and must not await
        // inside the loop.
        //
        // R-TEMPO pack cache: account (nonce, balance) is a pure function of
        // committed state, so for a FIXED state root every entry is exact. A
        // hit skips one `get_account` await per sender (measured ~0.4ms for
        // 1785 senders; more on contended/small stacks) AND replaces N
        // sequential lock acquisitions with one guarded scan; the refresh
        // pass below still fetches senders that arrived after the snapshot,
        // and any state mutation (finalize advances the height; faucet/test
        // funding moves the root) misses the cache. Selection output is
        // identical to a fresh scan for the same (state, mempool) —
        // proposer-local only.
        let mut accounts: std::collections::HashMap<[u8; 32], (u64, u64)> =
            match self.pack_snapshot.lock().ok().and_then(|g| {
                g.as_ref()
                    .filter(|(h, r, _)| *h == self.hc.height && *r == state_root)
                    .map(|(_, _, m)| m.clone())
            }) {
                Some(cached) => cached,
                None => {
                    // PAYMASTER: snapshot every fee payer — each sender PLUS
                    // each third-party sponsor backing a sponsored
                    // transaction — because the filter debits the fee leg
                    // from the sponsor. A sponsor missing from the snapshot
                    // reads as unfunded below (SKIP-only, like every other
                    // filter condition).
                    let senders: Vec<[u8; 32]> =
                        self.mempool.read().await.fee_payers().into_iter().collect();
                    // ONE guard, no awaits inside the loop: the snapshot is
                    // mutually consistent AND atomic against concurrent
                    // writers (a writer would move the root and miss the
                    // store gate below instead of poisoning it).
                    let guard = self.state.accounts.read().await;
                    let mut fresh: std::collections::HashMap<[u8; 32], (u64, u64)> =
                        std::collections::HashMap::with_capacity(senders.len());
                    for a in &senders {
                        if let Some(acct) = guard.get(a) {
                            fresh.insert(*a, (acct.nonce, acct.balance));
                        }
                    }
                    drop(guard);
                    // Store only if the state did not move under the snapshot.
                    if !pipeline_active || self.apply_in_flight.is_empty() {
                        let root1 = self.state.get_state_root().await;
                        if root1 == state_root {
                            if let Ok(mut g) = self.pack_snapshot.lock() {
                                *g = Some((self.hc.height, state_root, fresh.clone()));
                            }
                        }
                    }
                    fresh
                }
            };
        if pipeline_active && !self.apply_in_flight.is_empty() {
            for (addr, entry) in accounts.iter_mut() {
                if let (Some(n), Some(b)) = (
                    self.pending_exec_view.predicted_nonce(addr),
                    self.pending_exec_view.predicted_balance(addr),
                ) {
                    *entry = (n, b);
                }
            }
        }
        // R0-fullness refresh (packing mechanics, no consensus change): the
        // sender snapshot above is taken BEFORE the per-sender account reads,
        // and each read awaits. The RPC layer shares this mempool, so
        // transactions admitted DURING those reads have senders missing from
        // the map and the filter below rejects them as account-less — the
        // live shape was r0 carrying 52tx while r2 carried 200tx from the same
        // pool. One bounded refresh pass fetches exactly the senders that
        // arrived mid-build, so selection sees the pool as of select time.
        // No waiting is added (no artificial delay): this only stops using a
        // stale snapshot of what is ALREADY available.
        {
            // PAYMASTER: same fee-payer set as the snapshot above, so a
            // sponsor that arrived mid-build is fetched, not skipped.
            let fresh: Vec<[u8; 32]> = self.mempool.read().await.fee_payers().into_iter().collect();
            for s in missing_sender_accounts(&accounts, &fresh) {
                if let Some(acct) = self.state.get_account(&s).await {
                    accounts.insert(s, (acct.nonce, acct.balance));
                }
            }
        }
        // A block must carry a CONTIGUOUS nonce sequence per sender, so the
        // expected nonce advances as transactions are accepted. Comparing
        // against the account's nonce alone would admit a gap - a transaction
        // whose nonce is ahead of the next expected one cannot execute, and
        // would be included, fail at application, and still be paid for.
        let next_nonce = std::cell::RefCell::new(accounts.clone());
        // PHASE 2: the on-chain session-key registry, cloned out BEFORE the
        // filter runs because the closure is synchronous (it must not await).
        // The filter therefore evaluates exactly what execution will: terminal
        // revocation, the registered record's ceilings, and the CUMULATIVE
        // spend across the transactions it has already selected for THIS
        // block - in `SessionSpendSim`, so two transactions of one grant can
        // never both be selected against the same remaining budget.
        let session_keys = self.state.session_keys_read().await.clone();
        let session_sim = std::cell::RefCell::new(crate::zkml::SessionSpendSim::default());
        // Rejection census for the empty-block hunt (temporary diagnostics):
        // counts WHY the filter refuses, so a live empty-with-mempool names
        // its reason instead of staying silent.
        let rej_noacct = std::cell::Cell::new(0u32);
        let rej_nonce = std::cell::Cell::new(0u32);
        let rej_funds = std::cell::Cell::new(0u32);
        let rej_session = std::cell::Cell::new(0u32);
        let rej_shard = std::cell::Cell::new(0u32);
        let rej_basefee = std::cell::Cell::new(0u32);
        // PAYMASTER: sponsored transactions skipped for an expired/over-cap/
        // off-allowlist grant or a sponsor that spent down mid-mempool land
        // here (the mid-mempool re-check: admission is not the last word).
        let rej_sponsor = std::cell::Cell::new(0u32);
        // Admission floor, mirrored in the proposer filter: the mempool
        // refuses `gas_limit < effective_floor(sender)` on every admission
        // path, so a proposer must not pack such a transaction either.
        // SKIP-only like every other filter condition (never a hard reject):
        // selection stays a pure function of the same inputs on every node,
        // so proposers cannot diverge over it. The snapshot carries the D2
        // failure penalties: a sender whose transactions keep failing at
        // apply (paying nothing) is skipped until it over-posts.
        let (base_fee, penalty_floors) = {
            let pool = self.mempool.read().await;
            (pool.base_fee, pool.penalty_snapshot())
        };
        // SHARD SCOPE: a transaction belongs to the shard it is SOURCED from.
        // That includes outbound cross-shard transfers (source == this shard,
        // target != this shard): the source shard is the one that debits the
        // sender, emits the committed CrossShardMessage and burns the value off
        // this shard; the target credits the recipient from that message. Gated
        // on `is_sharded()`, so the single-shard path (where txs carry the
        // legacy source=1/target=1 tags while the chain's block shard is 0) is
        // untouched and keeps including exactly what it always did.
        let sharded = self.shard_registry.is_sharded();
        let my_shard = self.shard_id;
        // A sender may contribute at most ONE outbound cross-shard transfer per
        // block, and it must be its first accepted transaction. The inclusion
        // proof is generated against the PRE-block account leaf, so a second
        // cross-shard transfer from the same sender (at a later nonce) could
        // not be proven against the same root. Later sends wait for the next
        // block; nothing is lost, the mempool keeps them.
        let used_senders: std::cell::RefCell<std::collections::HashSet<[u8; 32]>> =
            std::cell::RefCell::new(std::collections::HashSet::new());
        // EPOCH-SEAL PATH (the private path the proposer PREFERS): the
        // sealed transactions are unsealed (after their order was
        // committed) and placed FIRST in the block; the plain selection
        // fills the remaining slots.
        //
        // The unsealed transactions go through the SAME admission filters
        // as the plain ones (shard scope, fee floor, nonce continuity,
        // funds), so a sealed transaction can never enter a block in a
        // state the plain path would have refused. Their nonce/funds
        // effects are applied to the filter state BEFORE the plain
        // selection, so the same sender's nonce is never packed twice.
        let sealed_txs = self.sealed_proposer_path(timestamp).await;
        let mut sealed_kept: Vec<Transaction> = Vec::with_capacity(sealed_txs.len());
        for t in sealed_txs {
            if sealed_kept.len() >= MAX_BLOCK_TXS {
                break;
            }
            if sharded && !crate::sharding::tx_belongs_to_shard(&t, my_shard) {
                rej_shard.set(rej_shard.get() + 1);
                continue;
            }
            if t.check_session_policy(timestamp).is_err() {
                rej_session.set(rej_session.get() + 1);
                continue;
            }
            // PAYMASTER v1 (mid-mempool re-check, sealed path): the grant's
            // policy (expiry / allowlist / per-tx cap at the BLOCK timestamp)
            // and BOTH funding legs are re-verified here, SKIP-only. A
            // sponsor that spent its balance down after admission (the
            // economic "revoke") is skipped here and again at apply; an
            // expired grant is skipped on time, not on funds.
            if let Some(auth) = t.sponsored_grant() {
                if !t.has_pq_sponsor_inner() || !t.verify_sponsor_sig(&auth) {
                    rej_sponsor.set(rej_sponsor.get() + 1);
                    continue;
                }
                let pq_surch = if t.is_pq_activation() {
                    crate::mempool::PQ_ACTIVATION_SURCHARGE_GAS
                } else {
                    0
                };
                let floor = base_fee
                    .saturating_add(penalty_floors.get(&t.from).copied().unwrap_or(0))
                    .saturating_add(pq_surch)
                    .saturating_add(t.priority_fee_per_gas);
                if t.gas_limit < floor {
                    rej_basefee.set(rej_basefee.get() + 1);
                    continue;
                }
                let fee = t.gas_limit.max(floor).saturating_add(pq_surch);
                if t.check_sponsor_policy(timestamp, fee).is_err() {
                    rej_sponsor.set(rej_sponsor.get() + 1);
                    continue;
                }
                let Some(&(expected, user_balance)) = next_nonce.borrow().get(&t.from) else {
                    rej_noacct.set(rej_noacct.get() + 1);
                    continue;
                };
                if t.nonce != expected {
                    rej_nonce.set(rej_nonce.get() + 1);
                    continue;
                }
                if user_balance < t.amount {
                    rej_funds.set(rej_funds.get() + 1);
                    continue;
                }
                let Some(&(sponsor_nonce, sponsor_balance)) =
                    next_nonce.borrow().get(&auth.sponsor)
                else {
                    rej_funds.set(rej_funds.get() + 1);
                    continue;
                };
                if sponsor_balance < fee {
                    rej_funds.set(rej_funds.get() + 1);
                    continue;
                }
                next_nonce
                    .borrow_mut()
                    .insert(t.from, (expected + 1, user_balance - t.amount));
                next_nonce
                    .borrow_mut()
                    .insert(auth.sponsor, (sponsor_nonce, sponsor_balance - fee));
                used_senders.borrow_mut().insert(t.from);
                sealed_kept.push(t);
                continue;
            }
            let Some(&(expected, balance)) = next_nonce.borrow().get(&t.from) else {
                rej_noacct.set(rej_noacct.get() + 1);
                continue;
            };
            if t.nonce != expected {
                rej_nonce.set(rej_nonce.get() + 1);
                continue;
            }
            let floor = base_fee
                .saturating_add(penalty_floors.get(&t.from).copied().unwrap_or(0))
                .saturating_add(if t.is_pq_activation() {
                    crate::mempool::PQ_ACTIVATION_SURCHARGE_GAS
                } else {
                    0
                })
                .saturating_add(t.priority_fee_per_gas);
            if t.gas_limit < floor {
                rej_basefee.set(rej_basefee.get() + 1);
                continue;
            }
            let cost =
                t.amount
                    .saturating_add(t.gas_limit)
                    .saturating_add(if t.is_pq_activation() {
                        crate::mempool::PQ_ACTIVATION_SURCHARGE_GAS
                    } else {
                        0
                    });
            if balance < cost {
                rej_funds.set(rej_funds.get() + 1);
                continue;
            }
            next_nonce
                .borrow_mut()
                .insert(t.from, (expected + 1, balance - cost));
            used_senders.borrow_mut().insert(t.from);
            sealed_kept.push(t);
        }
        // VEL-1: run plain selection through the factored predicate over
        // filter state seeded from the post-sealed locals — the same cells
        // the inline closure above shared, so the fresh path below is
        // byte-identical to the pre-factoring build.
        let fctx = PackFilterCtx::new(
            timestamp,
            sharded,
            my_shard,
            base_fee,
            penalty_floors,
            session_keys,
            next_nonce.borrow().clone(),
            session_sim.borrow().clone(),
            used_senders.borrow().clone(),
        );
        // VEL-1 bounded proposer-prebuild reuse: a cached selection for THIS
        // height is revalidated tx-by-tx against live state (same predicate,
        // cached order replays the acceptance sequence) and topped up from
        // the pool; kept txs are skipped by hash in the top-up scan. A stale
        // cache (parent changed, txs evicted/spent, sessions expired) only
        // shrinks the kept set — validity is preserved by construction and
        // receivers re-verify everything, so the worst case is a bounded
        // O(cached) revalidation before a fresh-equivalent build.
        let plain_txs: Vec<Transaction> = if sealed_kept.is_empty() {
            if let Some(cached) = self.prebuilt_selection.lock().ok().and_then(|g| {
                g.as_ref()
                    .filter(|c| c.for_height == self.hc.height)
                    .map(|c| c.txs.clone())
            }) {
                let mut kept: Vec<Transaction> = Vec::with_capacity(cached.len());
                {
                    let pool = self.mempool.read().await;
                    for t in &cached {
                        let th = t.compute_tx_hash();
                        if !pool.contains(&th)
                            || (pipeline_active
                                && !self.apply_in_flight.is_empty()
                                && self.pending_exec_view.is_in_flight(&th))
                        {
                            // Evicted since the prebuild or riding an in-flight block: skip.
                            continue;
                        }
                        if Self::pack_filter_accept(&fctx, t) {
                            kept.push(t.clone());
                        }
                    }
                }
                let kept_hashes: HashSet<[u8; 32]> =
                    kept.iter().map(|t| t.compute_tx_hash()).collect();
                let kept_gas: u64 = kept
                    .iter()
                    .map(|t| t.gas_limit)
                    .fold(0u64, |a, g| a.saturating_add(g));
                let mut new_txs = if kept.len() < MAX_BLOCK_TXS {
                    self.mempool.read().await.select_for_block_multi(
                        MAX_BLOCK_TXS - kept.len(),
                        MAX_BLOCK_GAS.saturating_sub(kept_gas),
                        |t| {
                            let th = t.compute_tx_hash();
                            if kept_hashes.contains(&th)
                                || (pipeline_active
                                    && !self.apply_in_flight.is_empty()
                                    && self.pending_exec_view.is_in_flight(&th))
                            {
                                return false;
                            }
                            Self::pack_filter_accept(&fctx, t)
                        },
                    )
                } else {
                    Vec::new()
                };
                let mut combined = kept;
                combined.append(&mut new_txs);
                Self::truncate_to_block_caps(&mut combined);
                combined
            } else {
                // No usable prebuild (first visit, sealed-free): fresh build
                // through the same predicate. The slot is written ONLY by
                // `prebuild_next_proposal` (never here), so a future-height
                // prebuild cached during this height's voting is never
                // evicted by a round retry at the current height.
                self.mempool.read().await.select_for_block_multi(
                    MAX_BLOCK_TXS,
                    MAX_BLOCK_GAS,
                    |t| {
                        if pipeline_active
                            && !self.apply_in_flight.is_empty()
                            && self.pending_exec_view.is_in_flight(&t.compute_tx_hash())
                        {
                            return false;
                        }
                        Self::pack_filter_accept(&fctx, t)
                    },
                )
            }
        } else {
            // The sealed path conditions plain selection on its own effects,
            // which the prebuild did not see: no reuse, fresh build, no store.
            self.mempool
                .read()
                .await
                .select_for_block_multi(MAX_BLOCK_TXS, MAX_BLOCK_GAS, |t| {
                    if pipeline_active
                        && !self.apply_in_flight.is_empty()
                        && self.pending_exec_view.is_in_flight(&t.compute_tx_hash())
                    {
                        return false;
                    }
                    Self::pack_filter_accept(&fctx, t)
                })
        };
        // Fold the factored predicate's census into the shared counters so
        // the rejection log below keeps its shape (sealed + plain combined).
        rej_noacct.set(rej_noacct.get() + fctx.rej_noacct.get());
        rej_nonce.set(rej_nonce.get() + fctx.rej_nonce.get());
        rej_funds.set(rej_funds.get() + fctx.rej_funds.get());
        rej_session.set(rej_session.get() + fctx.rej_session.get());
        rej_shard.set(rej_shard.get() + fctx.rej_shard.get());
        rej_basefee.set(rej_basefee.get() + fctx.rej_basefee.get());
        rej_sponsor.set(rej_sponsor.get() + fctx.rej_sponsor.get());
        // The sealed transactions come first (the proposer prefers the
        // private path), the plain ones fill the rest — ONE cap set over the
        // UNION: `sealed_kept` and `plain_txs` were budgeted independently, so
        // without this the body can exceed the caps every validator enforces
        // (see `final_block_body`).
        let txs: Vec<Transaction> = Self::final_block_body(sealed_kept, plain_txs);
        let mempool_len = self.mempool.read().await.len();
        // Empty block with a non-empty mempool is the shape to watch (usually
        // a per-sender nonce gap: filter needs exact nonces, evict keeps
        // future ones by design): log it at info, the rest at debug.
        if txs.is_empty() && mempool_len > 0 {
            tracing::info!(
                "propose h={} r={} shard={}: path=fresh selected=0 mempool={} (noacct={} nonce={} funds={} session={} shardfilter={} basefee={} sponsor={})",
                self.hc.height,
                self.hc.round,
                self.shard_id,
                mempool_len,
                rej_noacct.get(),
                rej_nonce.get(),
                rej_funds.get(),
                rej_session.get(),
                rej_shard.get(),
                rej_basefee.get(),
                rej_sponsor.get(),
            );
        } else {
            tracing::debug!(
                "propose h={} r={} shard={}: path=fresh selected={} mempool={}",
                self.hc.height,
                self.hc.round,
                self.shard_id,
                txs.len(),
                mempool_len,
            );
        }
        // MEV blind-round unseal gate: a transaction sealed at admission must
        // unseal to EXACTLY the bytes we are about to execute. Anything whose
        // envelope fails to open or whose pool copy no longer matches the
        // ciphertext is dropped here — fail closed, before it can waste block
        // space on a body every validator would reject. Transactions admitted
        // without an envelope (restored pools) pass through unchanged.
        let txs = {
            let pool = self.mempool.read().await;
            // The unseal check is a pure function of (envelope, transaction):
            // decrypt plus a byte-compare, with no shared mutation. Large
            // blocks therefore verify it across cores while the kept set, its
            // order and every verdict stay exactly the sequential ones (the
            // parallel pass returns verdicts in input order; filtering and the
            // drop warnings below run sequentially). Small blocks skip the
            // thread-pool round trip and run the original loop.
            const PARALLEL_UNSEAL_MIN_TXS: usize = 512;
            let selected_n: usize;
            let kept = if txs.len() >= PARALLEL_UNSEAL_MIN_TXS {
                use rayon::prelude::*;
                let checked: Vec<(Transaction, crate::mev::SealVerdict)> = txs
                    .into_par_iter()
                    .map(|tx| {
                        let verdict = pool.mev.verify_pool_tx(&tx);
                        (tx, verdict)
                    })
                    .collect();
                selected_n = checked.len();
                let mut kept = Vec::with_capacity(checked.len());
                for (tx, verdict) in checked {
                    match verdict {
                        crate::mev::SealVerdict::Match | crate::mev::SealVerdict::NotSealed => {
                            kept.push(tx)
                        }
                        _ => {
                            tracing::warn!(
                                tx = %hex::encode(tx.compute_tx_hash()),
                                ?verdict,
                                "propose: dropping transaction that failed the blind-round unseal gate"
                            );
                        }
                    }
                }
                kept
            } else {
                selected_n = txs.len();
                let mut kept = Vec::with_capacity(txs.len());
                for tx in txs {
                    match pool.mev.verify_pool_tx(&tx) {
                        crate::mev::SealVerdict::Match | crate::mev::SealVerdict::NotSealed => {
                            kept.push(tx)
                        }
                        verdict => {
                            tracing::warn!(
                                tx = %hex::encode(tx.compute_tx_hash()),
                                ?verdict,
                                "propose: dropping transaction that failed the blind-round unseal gate"
                            );
                        }
                    }
                }
                kept
            };
            // Post-unseal recount (audit: blocks troubles): the census above
            // counts SELECTED, but the gate can only shrink. Without this line
            // an emptied-by-unseal block looked identical to an empty mempool.
            if kept.len() != selected_n {
                tracing::info!(
                    "propose h={} r={} shard={}: unseal gate dropped {} of {} selected",
                    self.hc.height,
                    self.hc.round,
                    self.shard_id,
                    selected_n - kept.len(),
                    selected_n
                );
            }
            kept
        };
        // §9 deterministic control-record budget (S2). The proposer derives
        // the SAME bounded re-emission plan the protocol defines BEFORE it
        // chooses how many new outbound transfers may ride this height, and
        // caps the OPENING PREPAREs so the total never exceeds
        // `XPC_MAX_REEMITS_PER_HEIGHT`. Every validator rejects a block above
        // that cap, so building an over-cap block would halt the chain (17
        // outbound transfers used to do exactly that). Transfers that do not
        // fit are simply not selected this block: their transactions stay in
        // the mempool and are proposed, in the same deterministic order, on a
        // later height. A transaction is NEVER included without its PREPARE
        // (that would escrow value with no peer-facing record).
        let xpc_on = self.xpc_activation.boundary().is_some();
        let xpc_active = xpc_on && self.xpc_activation.is_active_at(self.hc.height);
        let xpc_plan = if xpc_on {
            let mut records: Vec<crate::xshard2pc::XpcRecord> =
                self.xpc_records.values().cloned().collect();
            records.sort_by_key(|r| r.tx_hash);
            crate::xshard2pc::bounded_reemit_plan(&records, self.shard_id, self.hc.height)
        } else {
            Vec::new()
        };
        let opening_budget = if sharded {
            // ONE total cap for BOTH kinds: the 2PC plan slots are reserved,
            // and the remaining budget (minus the inbound reserve) bounds the
            // opening PREPAREs AND the legacy one-way outbound records the
            // pre-activation flow still produces. The validator re-checks the
            // same total, so the proposer never builds an over-cap block.
            crate::xshard2pc::outbound_record_budget(xpc_plan.len())
        } else {
            usize::MAX
        };
        let txs = if sharded {
            let mut kept: Vec<Transaction> = Vec::with_capacity(txs.len());
            // A dropped outbound transfer also invalidates every LATER
            // transaction from the same sender (their nonce sequence assumed
            // the dropped one applied). Both stay in the mempool for a later
            // block, so no value is lost and the order is preserved.
            let mut dropped_senders: HashSet<[u8; 32]> = HashSet::new();
            let mut openings = 0usize;
            // XSHARD bounce-escrow gate: when the gate is active and the §9
            // 2PC is NOT the configured flow, an outbound legacy record can
            // never validate (it must prove a same-block escrow anchored to
            // the parent root, which a one-step producer cannot do). Including
            // the transaction would only build a block every validator refuses,
            // so it stays in the mempool until the 2PC is active. On the
            // supported activation sequence (XPC from genesis) this branch is
            // never taken.
            let legacy_outbound_disabled =
                crate::chain_spec::xshard_bounce_escrow_required_active_at(self.hc.height)
                    && !xpc_active;
            for tx in txs {
                if dropped_senders.contains(&tx.from) {
                    continue;
                }
                if crate::sharding::tx_is_outbound_cross_shard(&tx, my_shard) {
                    if legacy_outbound_disabled {
                        dropped_senders.insert(tx.from);
                        continue;
                    }
                    if openings >= opening_budget {
                        dropped_senders.insert(tx.from);
                        continue;
                    }
                    openings += 1;
                }
                kept.push(tx);
            }
            if openings < opening_budget {
                tracing::debug!(
                    "propose h={}: opening cross-shard budget {}/{} (plan={}, xpc_active={})",
                    self.hc.height,
                    openings,
                    opening_budget,
                    xpc_plan.len(),
                    xpc_active
                );
            }
            kept
        } else {
            txs
        };
        let opening_count = txs
            .iter()
            .filter(|t| crate::sharding::tx_is_outbound_cross_shard(t, my_shard))
            .count();
        let prev_hash = self.expected_parent_hash_for_height(self.hc.height);
        // TRANSACTION-ORDER COMMITMENT: computed over the EXACT ordered list
        // this block packs, and put into the block BEFORE it is signed, so
        // the quorum that votes for the block votes for its ORDER too (the
        // root is inside `compute_hash`). A validator re-computes it from the
        // proposed body and refuses a proposal that does not match, so this
        // order cannot be changed after the votes.
        let order_merkle_root = crate::mev::compute_order_merkle_root(&txs);
        // Validation-layer close of the actor-mailbox gap (propose side): the
        // engine's mailbox pass is a defensive clamp — whatever is still
        // queued when `MAX_ACTOR_MSGS_PER_BLOCK` (or the round bound) runs out
        // stays for a later block, but inboxes are NOT trie state, so that
        // leftover is invisible to the state root and two nodes can queue
        // different leftovers behind the same root. An over-cap block is
        // therefore never built: the backlog this block would add to what is
        // already queued must fit the cap, or there is no proposal this round
        // (fail closed; every validator rejects such a block below, so no
        // honest node can be split by one).
        {
            let backlog = self.pending_actor_backlog().await;
            let sends: usize = txs
                .iter()
                .map(|t| count_program_sends(&t.payload))
                .fold(0usize, |acc, n| acc.saturating_add(n));
            if backlog.saturating_add(sends) > crate::state_engine::MAX_ACTOR_MSGS_PER_BLOCK {
                tracing::warn!(
                    "propose h={}: refusing to build an over-cap actor block ({} queued + {} in block)",
                    self.hc.height,
                    backlog,
                    sends,
                );
                return None;
            }
        }
        // Cross-shard commit records for this block. In a sharded process a
        // block carries BOTH directions in the one existing `cross_shard_out`
        // field:
        //   * OUTBOUND (source == this shard): one record per outbound
        //     transfer selected above, with a Merkle proof of the sender's
        //     pre-block leaf and the pre-block balance. Applying the block
        //     debits the sender here; the record is what lets the target mint.
        //   * INBOUND (target == this shard): messages pulled from the
        //     node-local KV, filtered against what this chain already
        //     consumed, each carrying its source inclusion proof. Applying the
        //     block credits each recipient exactly once.
        let mut cross_shard_out: Vec<CrossShardMessage> = Vec::new();
        if sharded {
            // §9 2PC: from the activation height on, a NEW cross-shard
            // transfer is published as a PREPARE record instead of a plain
            // transfer. The PREPARE does not credit anybody: it escrows the
            // value on the source and asks the target to prepare, and the
            // target votes with a PREPARE-ACK. Transfers produced BEFORE the
            // activation keep running the legacy outbox/inbox/ack/bounce
            // flow; on an upgraded chain that flow is REFUND-ONLY (the target
            // refuses the legacy credit under XSHARD-01), never a delivery.
            // `xpc_on` / `xpc_active` / `xpc_plan` were derived above, before
            // the transaction selection was capped.
            for tx in &txs {
                if !crate::sharding::tx_is_outbound_cross_shard(tx, my_shard) {
                    continue;
                }
                let sender_acct = self.state.get_account(&tx.from).await;
                let balance = sender_acct.as_ref().map(|a| a.balance).unwrap_or(0);
                let proof = self.state.get_account_proof(&tx.from).await;
                let msg = if xpc_active {
                    CrossShardMessage::new_xpc(
                        crate::xshard2pc::XPC_PREPARE,
                        my_shard,
                        tx.target_shard,
                        tx.clone(),
                        state_root,
                        prev_hash,
                        proof,
                    )
                    .with_source_balance(balance)
                } else {
                    CrossShardMessage::new(
                        my_shard,
                        tx.target_shard,
                        tx.clone(),
                        state_root,
                        prev_hash,
                        proof,
                    )
                    .with_source_balance(balance)
                };
                // Only attach 49-byte PQ leaf metadata when the sender account
                // at the pre-block `state_root` is ALREADY pinned; unpinned
                // accounts (including first-time explicit PQ activations) live
                // as 16-byte leaves in `state_root`.
                let msg = match sender_acct
                    .as_ref()
                    .and_then(|a| a.pubkey_hash.map(|h| (a.scheme.id(), h)))
                {
                    Some((scheme_id, pk_hash)) => msg.with_sender_pubkey_hash(scheme_id, pk_hash),
                    None => msg.with_unpinned_sender(),
                };
                cross_shard_out.push(msg);
            }
            if let Some(transport) = &self.cross_shard {
                let mut inbound = transport.fetch_cross_shard_inbound(my_shard).await;
                // Deterministic order, independent of KV enumeration order.
                inbound.sort_by_key(CrossShardKey::of);
                let mut prune_ids: Vec<[u8; 32]> = Vec::new();
                // S2: every 2PC control record in the block counts against the
                // SAME per-height cap the validator enforces. The opening
                // PREPAREs were capped above; reserve the plan's slots too, and
                // admit inbound control records only while the budget lasts
                // (the rest stay in the mailbox for a later height).
                let mut control_used = xpc_plan.len().saturating_add(opening_count);
                // S10: expire/quarantine tracked mailbox entries that are no
                // longer even fetched, so the tracker cannot grow forever.
                let cutoff = self
                    .hc
                    .height
                    .saturating_sub(crate::xshard2pc::XPC_MAILBOX_QUARANTINE_HEIGHTS);
                let expired: Vec<[u8; 32]> = self
                    .xpc_mailbox_seen
                    .iter()
                    .filter(|(_, first)| **first <= cutoff)
                    .map(|(id, _)| *id)
                    .collect();
                for id in expired {
                    self.xpc_mailbox_seen.remove(&id);
                    prune_ids.push(id);
                }
                for msg in inbound {
                    if !msg.is_inbound_for(my_shard) {
                        continue;
                    }
                    // S10: deterministic first-seen age. A record that never
                    // becomes admissible is quarantined (pruned) after
                    // XPC_MAILBOX_QUARANTINE_HEIGHTS heights instead of being
                    // rescanned by every propose forever. Node-local transport
                    // bookkeeping; never consensus state.
                    let first_seen = *self
                        .xpc_mailbox_seen
                        .entry(msg.msg_id)
                        .or_insert(self.hc.height);
                    if self.hc.height.saturating_sub(first_seen)
                        >= crate::xshard2pc::XPC_MAILBOX_QUARANTINE_HEIGHTS
                    {
                        self.xpc_mailbox_seen.remove(&msg.msg_id);
                        prune_ids.push(msg.msg_id);
                        continue;
                    }
                    let key = CrossShardKey::of(&msg);
                    if self.consumed_cross_shard.contains(&key) {
                        self.xpc_mailbox_seen.remove(&msg.msg_id);
                        // S10/prune: a record this chain already consumed will
                        // never be admitted again. Without the prune the
                        // non-draining node-local KV transport re-fetched it
                        // on EVERY propose (the tracker entry was dropped, so
                        // it looked brand new and never aged out to
                        // quarantine).
                        prune_ids.push(msg.msg_id);
                        continue;
                    }
                    // Belt beyond the runtime mirrors: the PERSISTED engine
                    // set survives restarts (audit F-I) while the mirrors may
                    // be empty (fresh process). If the engine already credited
                    // this key, prune it from the mailbox so no future propose
                    // wastes a round on it, and skip it now. Without the prune
                    // a restarted proposer would re-propose it forever (its
                    // mirrors are empty) while every apply refuses it.
                    if self.state.is_cross_shard_consumed(&key).await {
                        self.xpc_mailbox_seen.remove(&msg.msg_id);
                        prune_ids.push(msg.msg_id);
                        continue;
                    }
                    // S2 budget: Commit is counted with the other control
                    // records (it is a decision re-publication, not a value
                    // transfer), so a Byzantine proposer cannot flood a block
                    // with uncapped historical COMMITs either.
                    let tx_hash = msg.tx.compute_tx_hash();
                    // PULL HINT: a PREPARE-ACK is the target saying it is
                    // STILL PREPARED. Our own record being terminal (this
                    // shard COMMITTED and the mirror marks the tx completed)
                    // does NOT prove the TARGET is complete: if it missed the
                    // COMMIT it keeps re-sending this vote. That vote is what
                    // refreshes the engine's decision height (the `PrepareAck`
                    // arm in `state_engine/xshard.rs`), restarting the
                    // deterministic COMMIT window. The old completion prune
                    // below ran BEFORE any admission, so the refresh existed
                    // in unit tests but never on the live propose path.
                    let refresh_hint = msg.is_xpc()
                        && msg.kind() == crate::sharding::CrossShardKind::PrepareAck
                        && matches!(
                            self.xpc_records.get(&tx_hash).map(|r| r.phase),
                            Some(crate::xshard2pc::XpcPhase::Committed)
                        );
                    let is_control = matches!(
                        msg.kind(),
                        crate::sharding::CrossShardKind::Prepare
                            | crate::sharding::CrossShardKind::PrepareAck
                            | crate::sharding::CrossShardKind::AbortRequest
                            | crate::sharding::CrossShardKind::AbortAck
                            | crate::sharding::CrossShardKind::Commit
                    );
                    if is_control && control_used >= crate::xshard2pc::XPC_MAX_REEMITS_PER_HEIGHT {
                        // Leave it in the mailbox: a later height has budget.
                        continue;
                    }
                    // TOTAL record cap: one budget covers the 2PC control
                    // plan (reserved via `xpc_plan.len()`), the outbound
                    // transfer records already appended, and every inbound
                    // record (legacy transfers included). The validator
                    // enforces the same constant; the excess stays in the
                    // mailbox for a later height.
                    if cross_shard_out.len().saturating_add(xpc_plan.len())
                        >= crate::xshard2pc::XPC_MAX_CROSS_SHARD_RECORDS_PER_BLOCK
                    {
                        continue;
                    }
                    // §5 M3 kind-dispatched admission: transfers prove
                    // inclusion against the source root; acks/bounces prove
                    // linkage to a committed outbound on this chain (plus the
                    // height timeout for bounces). Anything else fails closed.
                    if msg.is_ack() || msg.is_bounce() {
                        if !self.control_linkage_ok(&msg, self.hc.height) {
                            continue;
                        }
                        // XSHARD bounce-escrow gate: the proposer only admits
                        // a bounce backed by a committed source escrow leaf,
                        // and never for a transaction whose §9 2PC record is
                        // this block's plan or already committed. This keeps
                        // an honest proposer from building a block validation
                        // and apply would refuse, while the apply gate still
                        // refuses a forged one.
                        if crate::chain_spec::xshard_bounce_escrow_required_active_at(
                            self.hc.height,
                        ) {
                            if self.xpc_records.contains_key(&tx_hash)
                                || xpc_plan.iter().any(|r| r.tx_hash == tx_hash)
                                || cross_shard_out
                                    .iter()
                                    .any(|m| m.is_xpc() && m.tx.compute_tx_hash() == tx_hash)
                            {
                                continue;
                            }
                            if msg.is_bounce() && !self.state.has_legacy_escrow_leaf(&msg.tx).await
                            {
                                continue;
                            }
                        }
                    } else if msg.is_xpc() {
                        if !xpc_on {
                            continue;
                        }
                        // STALE AFTER COMPLETION: a terminal 2PC transfer can
                        // never need another control record, and the SOURCE
                        // re-publishes its COMMIT until the target's mailbox
                        // is drained. Check completion BEFORE the anchor gate
                        // and PRUNE such a record: once the target has
                        // credited (or refunded), later copies are
                        // worthless, and an old copy whose parent block has
                        // already aged out of the finalized-header window
                        // fails `xpc_admissible` FOREVER. Leaving it in the
                        // node-local mailbox made every propose rescan an
                        // ever-growing set of dead records (they are never
                        // included, so apply never prunes them).
                        if self.completed_cross_shard.contains(&tx_hash) && !refresh_hint {
                            self.xpc_mailbox_seen.remove(&msg.msg_id);
                            prune_ids.push(msg.msg_id);
                            continue;
                        }
                        // §9 2PC admission. Every 2PC record carries a proof of
                        // the PEER's committed 2PC state (the peer is the
                        // message's `source_shard`), anchored to a locally
                        // finalized header of that peer shard - the same C1
                        // anchor the legacy flow uses, applied to the 2PC
                        // state instead of the account leaf. A record whose
                        // proof or anchor does not check out is refused.
                        if !self.xpc_admissible(&msg) {
                            continue;
                        }
                    } else if msg.is_transfer() {
                        // C1 anchored (not just proof-checked): the root must
                        // be a locally-finalized source header, or the message
                        // waits for a later block (NOT-READY, not verified).
                        if !self.verify_cross_shard_anchored(&msg) {
                            continue;
                        }
                    } else {
                        continue;
                    }
                    // Stale after completion: the transaction already acked or
                    // bounced (e.g. a late duplicate lingering in the KV).
                    // A still-PREPARED target's PREPARE-ACK is the exception:
                    // it must reach apply so the engine can refresh the
                    // source's COMMIT window.
                    if self.completed_cross_shard.contains(&tx_hash) && !refresh_hint {
                        continue;
                    }
                    if cross_shard_out.iter().any(|m| m.msg_id == msg.msg_id) {
                        continue;
                    }
                    if is_control {
                        control_used = control_used.saturating_add(1);
                    }
                    self.xpc_mailbox_seen.remove(&msg.msg_id);
                    cross_shard_out.push(msg);
                }
                // S10 hard bound: even a same-height burst cannot leave the
                // tracker above XPC_MAILBOX_MAX_TRACKED. Oldest entries are
                // pruned first (deterministic within this node).
                if self.xpc_mailbox_seen.len() > crate::xshard2pc::XPC_MAILBOX_MAX_TRACKED {
                    let mut entries: Vec<([u8; 32], u64)> = self
                        .xpc_mailbox_seen
                        .iter()
                        .map(|(id, first)| (*id, *first))
                        .collect();
                    entries.sort_by_key(|(id, first)| (*first, *id));
                    let overflow = self
                        .xpc_mailbox_seen
                        .len()
                        .saturating_sub(crate::xshard2pc::XPC_MAILBOX_MAX_TRACKED);
                    for (id, _) in entries.into_iter().take(overflow) {
                        self.xpc_mailbox_seen.remove(&id);
                        if !prune_ids.contains(&id) {
                            prune_ids.push(id);
                        }
                    }
                }
                if !prune_ids.is_empty() {
                    transport.prune_consumed(my_shard, &prune_ids).await;
                }
                // §9 2PC: the OUTBOUND records of the transfers this shard
                // owns are the DETERMINISTIC, BOUNDED plan computed above
                // (`bounded_reemit_plan`): at most XPC_MAX_REEMITS_PER_HEIGHT
                // records for this height, rotated so a busy shard cannot
                // starve the tail. It is the SAME pure function of the
                // committed records and the height that the validator
                // re-derives, so the proposer never invents a re-emission the
                // validator refuses (and never exceeds the control cap).
                // Deriving them from the committed state (and not from a
                // message) is what makes the protocol RECOVERABLE: a node that
                // crashed mid-2PC re-derives exactly the same records and
                // reaches the same decision.
                for reemit in &xpc_plan {
                    let Some(rec) = self.xpc_records.get(&reemit.tx_hash) else {
                        continue;
                    };
                    let (phase, from_shard, to_shard) = match reemit.phase {
                        crate::xshard2pc::XPC_PREPARE
                        | crate::xshard2pc::XPC_COMMIT
                        | crate::xshard2pc::XPC_ABORT_REQUEST => {
                            if rec.source_shard != my_shard {
                                continue;
                            }
                            (reemit.phase, rec.source_shard, rec.target_shard)
                        }
                        crate::xshard2pc::XPC_PREPARE_ACK | crate::xshard2pc::XPC_ABORT_ACK => {
                            if rec.target_shard != my_shard {
                                continue;
                            }
                            (reemit.phase, rec.target_shard, rec.source_shard)
                        }
                        _ => continue,
                    };
                    // The proof of THIS shard's committed 2PC state: the
                    // peer verifies it against the peer's own state root and
                    // the anchor, so the vote cannot be forged.
                    let proof = self.state.get_xpc_proof(&rec.tx_hash).await;
                    if proof.is_none() {
                        continue;
                    }
                    let msg = CrossShardMessage::new_xpc(
                        phase,
                        from_shard,
                        to_shard,
                        rec.tx.clone(),
                        state_root,
                        prev_hash,
                        proof,
                    );
                    if cross_shard_out.iter().any(|m| m.msg_id == msg.msg_id) {
                        continue;
                    }
                    if cross_shard_out.len()
                        >= crate::xshard2pc::XPC_MAX_CROSS_SHARD_RECORDS_PER_BLOCK
                    {
                        break;
                    }
                    cross_shard_out.push(msg);
                }
                // §5 M3 timeout bounces: outbounds this chain produced that
                // never completed and aged past the height timeout are
                // refunded by committing a bounce-back record. Deterministic
                // in (tx hash, height): every node builds the same record for
                // the same chain, and `validate_proposal` re-checks the rule.
                //
                // §9 2PC: a transfer that runs the 2PC NEVER bounces. Its
                // abort is a two-sided decision (the target must confirm it
                // never prepared), and the unilateral timeout bounce is
                // exactly the double-spend the 2PC removes.
                let xpc_owned: std::collections::HashSet<[u8; 32]> = if xpc_on {
                    self.xpc_records.keys().copied().collect()
                } else {
                    std::collections::HashSet::new()
                };
                // XSHARD bounce-escrow gate: derived bounces must be backed by
                // the committed source escrow leaf, and a §9 2PC transfer never
                // bounces through this legacy path. Above, the `xpc_owned`
                // filter already covers the activation switch; this covers the
                // case where a 2PC record exists while the legacy flow is the
                // configured one (the S6-2 double-spend shape) AND a produced
                // entry from below the gate that has no escrow leaf.
                let bounce_escrow_gate =
                    crate::chain_spec::xshard_bounce_escrow_required_active_at(self.hc.height);
                let mut expired: Vec<([u8; 32], Transaction)> = self
                    .produced_cross_shard
                    .iter()
                    .filter(|(tx_hash, (_, hp))| {
                        !self.completed_cross_shard.contains(*tx_hash)
                            && !xpc_owned.contains(*tx_hash)
                            && crate::sharding::bounce_eligible(*hp, self.hc.height)
                    })
                    .map(|(tx_hash, (tx, _))| (*tx_hash, tx.clone()))
                    .collect();
                expired.sort_by_key(|(tx_hash, _)| *tx_hash);
                if bounce_escrow_gate {
                    let mut proven: Vec<([u8; 32], Transaction)> =
                        Vec::with_capacity(expired.len());
                    for (tx_hash, tx) in expired {
                        if self.xpc_records.contains_key(&tx_hash)
                            || cross_shard_out
                                .iter()
                                .any(|m| m.is_xpc() && m.tx.compute_tx_hash() == tx_hash)
                        {
                            continue;
                        }
                        if self.state.has_legacy_escrow_leaf(&tx).await {
                            proven.push((tx_hash, tx));
                        }
                    }
                    expired = proven;
                }
                for (tx_hash, tx) in expired {
                    if cross_shard_out
                        .iter()
                        .any(|m| m.tx.compute_tx_hash() == tx_hash)
                    {
                        continue;
                    }
                    // The total cap covers every record kind, bounces too: a
                    // bounce does not fit this height stays derived and
                    // eligible, so the next height carries it (same sorted
                    // order, no value lost).
                    if cross_shard_out.len()
                        >= crate::xshard2pc::XPC_MAX_CROSS_SHARD_RECORDS_PER_BLOCK
                    {
                        break;
                    }
                    cross_shard_out.push(CrossShardMessage::new_bounce(tx, prev_hash));
                }
            }
        }
        let timestamp = if let Some(parent_ts) = self
            .blocks
            .get(&prev_hash)
            .map(|b| b.timestamp)
            .or_else(|| {
                self.last_decision.as_ref().and_then(|(h, b, _)| {
                    if *h + 1 == self.hc.height && self.decision_block_hash(*h, b) == prev_hash {
                        Some(b.timestamp)
                    } else {
                        None
                    }
                })
            }) {
            // SAME deterministic bound the validator gate applies
            // (`consensus_step::check_block_timestamp`): the honest proposer
            // clamps into [parent, parent + MAX_BLOCK_TIMESTAMP_DRIFT_MS/1000]
            // so a slightly fast local clock can never build a body that every
            // validator must refuse.
            let max_drift_secs = crate::protocol::MAX_BLOCK_TIMESTAMP_DRIFT_MS / 1_000;
            timestamp
                .min(parent_ts.saturating_add(max_drift_secs))
                .max(parent_ts)
        } else {
            timestamp
        };
        // The EPOCH-KEY commitment: the block pins the MEV epoch key that the
        // sealed transactions of this epoch are encrypted to (see
        // `crate::mev_epoch`). It is the chain's word on WHICH key the
        // network uses for this epoch: a wallet (or a light client) takes the
        // key from a full node and checks it against the block, so a single
        // node cannot hand out a key the network never agreed on.
        //
        // The commitment is the one of OUR epoch material, and only when the
        // material belongs to THIS block's epoch: a node whose DKG has not
        // completed (or whose view of the validator set diverged) commits to
        // nothing rather than to a key the network may not use.
        let epoch_key_commitment = {
            let pool = self.mempool.read().await;
            let manager = &pool.mev_seal;
            if manager.epoch == crate::mev_epoch::epoch_of_height(self.hc.height) {
                manager.epoch_commitment().unwrap_or([0u8; 32])
            } else {
                [0u8; 32]
            }
        };
        // CN-VRF v3 payload: our own chain step, queued peer commit
        // carriers, and the epoch-boundary MinRoot beacon. `None` below the
        // gate, so pre-activation blocks keep their legacy shaped hash.
        let cnvrf_v3 = self.build_cnvrf_v3_payload(self.hc.height);
        let mut block = Block {
            shard_id: self.shard_id,
            height: self.hc.height,
            prev_hash,
            state_root,
            transactions: txs,
            cross_shard_out,
            timestamp,
            proposer: self.id,
            validator_signatures: vec![],
            precommit_qc: None,
            // W10.5 CANONICAL DOWNTIME EVIDENCE: the QC that decided the
            // parent height, chosen once here — every applier attributes the
            // same evidence and converges. It must name THIS proposal's
            // parent (height + hash). `None` only for the genesis child;
            // a restored node without reconstructible evidence never gets
            // here (`parent_evidence_missing` fails closed above).
            last_qc: self.decided_parent_qc(&prev_hash),
            // SHARD-HEAD COMMITMENTS (TON `shard_hashes`): a masterchain block
            // publishes the latest finalized header of every workchain shard,
            // so a cross-shard state root becomes provable from a
            // masterchain block alone. A workchain block commits to nothing
            // but its own body.
            shard_headers: self.collect_shard_header_commitments(),
            // The order commitment over the exact list packed above.
            order_merkle_root,
            // The commitment to the epoch key this block's epoch uses.
            epoch_key_commitment,
            // THE EPOCH-MMR commitment (V5 Tier-2): the MMR root over the
            // previous epoch's finalized block hashes on a masterchain
            // epoch-boundary height, zero everywhere else (see
            // `epoch_mmr_commitment`). Zero keeps the legacy hash
            // byte-for-byte; non-zero is covered by the block hash the
            // quorum signs.
            mmr_epoch_root: self.epoch_mmr_commitment(),
            cnvrf_v3,
            // RULESET v4: the signed BFT round this proposal belongs to. The
            // proposer knows it (`self.hc.round`); validators require the
            // block's round to equal the round the proposal is for on the
            // admission AND adopt paths.
            round: self.hc.round,
        };
        // Proposer-side pre-gossip size check (packing/visibility only, no
        // consensus change): estimate wire size with deterministic placeholder
        // signature lengths BEFORE signing once through `SafetyAuthority`, so a
        // trimmed block never double-signs the same `(height, round)` (`SLASH-B`).
        block.validator_signatures.push((self.id, vec![0u8; 64]));
        if let Some((ps, _)) = self.pq_signer_entry() {
            block.validator_signatures.push((
                ps.validator_id(),
                vec![0u8; crate::post_quantum::FALCON512_SIG_LEN],
            ));
        } else if let Some(fk) = self.falcon_signing_key() {
            block.validator_signatures.push((
                fk.validator_id(),
                vec![0u8; crate::post_quantum::FALCON512_SIG_LEN],
            ));
        }
        {
            #[derive(serde::Serialize)]
            enum ProposalMsgSizeProbe<'a> {
                Proposal {
                    height: u64,
                    round: u32,
                    block: &'a Block,
                },
            }
            let cap = crate::consensus_net::MAX_CONSENSUS_MSG;
            let mut encoded_len = bincode::serialized_size(&ProposalMsgSizeProbe::Proposal {
                height: self.hc.height,
                round: self.hc.round,
                block: &block,
            })
            .map(|n| n as usize)
            .unwrap_or(usize::MAX);
            if encoded_len > cap {
                let orig_txs = block.transactions.len();
                // Fattest-first: indices by descending estimated wire bytes.
                let mut order: Vec<usize> = (0..block.transactions.len()).collect();
                order.sort_by_key(|&i| {
                    std::cmp::Reverse(Mempool::estimate_tx_wire_bytes(&block.transactions[i]))
                });
                let mut drop: Vec<bool> = vec![false; block.transactions.len()];
                let mut dropped = 0usize;
                for &i in &order {
                    if encoded_len <= cap {
                        break;
                    }
                    drop[i] = true;
                    dropped += 1;
                    // Re-measure the candidate survivor set each drop without
                    // allocating an encoded Vec<u8> buffer.
                    let kept: Vec<crate::sharding::Transaction> = block
                        .transactions
                        .iter()
                        .enumerate()
                        .filter(|(j, _)| !drop[*j])
                        .map(|(_, t)| t.clone())
                        .collect();
                    let probe = Block {
                        transactions: kept,
                        ..block.clone()
                    };
                    encoded_len = bincode::serialized_size(&ProposalMsgSizeProbe::Proposal {
                        height: self.hc.height,
                        round: self.hc.round,
                        block: &probe,
                    })
                    .map(|n| n as usize)
                    .unwrap_or(usize::MAX);
                }
                if encoded_len > cap {
                    // Even empty-of-txs is un-sendable (giant inbound
                    // cross-shard section). Fail closed: no proposal this
                    // round rather than bytes no peer can receive.
                    tracing::error!(
                        "propose h={} r={}: pre-gossip fallback FAILED ({} txs, {} bytes > {} cap even empty); proposing nothing",
                        self.hc.height,
                        self.hc.round,
                        orig_txs,
                        encoded_len,
                        cap,
                    );
                    return None;
                }
                let dropped_hashes: std::collections::HashSet<[u8; 32]> = block
                    .transactions
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| drop[*j])
                    .map(|(_, t)| t.compute_tx_hash())
                    .collect();
                let mut kept_txs = Vec::with_capacity(orig_txs - dropped);
                for (j, t) in block.transactions.into_iter().enumerate() {
                    if !drop[j] {
                        kept_txs.push(t);
                    }
                }
                block.transactions = kept_txs;
                // Outbound records naming a dropped tx would burn value with
                // nobody able to claim it (validate rejects tx-without-record
                // only in the outbound direction; the reverse — record without
                // tx — is equally unclaimable). Prune them with the txs.
                block
                    .cross_shard_out
                    .retain(|m| !dropped_hashes.contains(&m.tx.compute_tx_hash()));
                // The body changed, so the ORDER COMMITMENT must be recomputed
                // over the surviving (still ordered) list BEFORE the block is
                // signed below: the root is inside the signed hash.
                block.order_merkle_root =
                    crate::mev::compute_order_merkle_root(&block.transactions);
                tracing::error!(
                    "propose h={} r={}: pre-gossip fallback SHRANK block {} -> {} txs ({} bytes est, cap {}); dropped fattest first, survivors kept in order",
                    self.hc.height,
                    self.hc.round,
                    orig_txs,
                    block.transactions.len(),
                    encoded_len,
                    cap,
                );
            }
        }
        block.validator_signatures.clear();
        let proposal_msg = block.compute_hash();
        let req = crate::remote_signer::ConsensusSignRequest::Proposal {
            chain_id: crate::consensus::consensus_chain_id(),
            shard_id: self.shard_id,
            height: self.hc.height,
            round: self.hc.round,
            block_hash: proposal_msg,
        };
        let (sig, falcon_sig) = {
            let signer = self.vote_signer_for(req);
            self.safety
                .authorize_and_sign_proposal(self.hc.height, self.hc.round, proposal_msg, &signer)
                .ok()?
        };
        block.validator_signatures.push((self.id, sig));
        if let Some((falcon_id, fsig)) = falcon_sig {
            block.validator_signatures.push((falcon_id, fsig));
        }
        // MEV order commitment at build: record (and sign) the exact execution
        // order BEFORE the block is proposed or voted on. `try_finalize`
        // re-verifies this commitment against the block it is about to apply,
        // so this node never executes an order it did not commit to build.
        let bh = proposal_msg;
        {
            let mut pool = self.mempool.write().await;
            pool.mev.commit_block_order(
                self.hc.height,
                bh,
                &block.transactions,
                std::slice::from_ref(&self.key),
            );
        }
        self.blocks.insert(bh, block.clone());
        // Round-free identity (ruleset v6): every lock comparison on this
        // body (now or after a later re-stamp of the same value) resolves
        // through it.
        self.hc.note_value_id(bh, block.value_id());
        let expected = self.expected_proposer_now();
        self.hc.receive_proposal_for(self.id, bh, expected).ok()?;
        Some(block)
    }
}
