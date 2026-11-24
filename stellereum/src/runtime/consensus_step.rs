use super::lanes::{block_actor_sends_exceed_cap, count_block_actor_sends};
use super::{
    master_set_stamp, publish_master_set_stamp, set_fingerprint, workchain_set_activation_height,
    BlockHash, DecidedParentVotes, ValidatorRuntime, MAX_BLOCK_GAS, MAX_BLOCK_TXS,
    MAX_COMMIT_CERT_SIGNERS, PROPOSAL_ALIGN_WINDOW_ROUNDS, SLOW_VALIDATION_THRESHOLD_MS,
    VALIDATOR_SET_HISTORY_CAP,
};
use crate::consensus::{
    CommitteeSchedule, Height, Round, Step, ValidatorId, ValidatorSet, Vote, VoteKind, VoteSet,
};
use crate::sharding::{Block, CrossShardKey, Transaction, ValidatorSetSource};
use sha2::{Digest as _, Sha256};

/// A proposal that arrived while the apply worker was still executing the
/// decided height.
///
/// The proposal is NOT validated here (our state root is still PRE-H, so a
/// root check would compare against the wrong parent). It is parked and
/// replayed through [`ValidatorRuntime::on_proposal`] the moment the worker
/// reports back, so authentication, height/round, root and actor-cap checks
/// all run again — fail-closed, never a bypass.
#[derive(Clone, Debug)]
pub struct ParkedProposal {
    pub proposer: ValidatorId,
    pub block: Block,
    pub round: Round,
    /// `(hc.height, hc.round)` when this item was parked.
    ///
    /// Used to invalidate the slot on replay: an item is only replayed while
    /// it still targets the CURRENT consensus height and its envelope round is
    /// within `SUPERSEDED_ROUND_LAG`; any further height/round advance makes
    /// it stale and it is dropped instead of replayed.
    pub parked_at: (Height, Round),
}

/// A peer commit that arrived while the apply worker was still executing.
///
/// Covers the "execution in flight" window of [`ValidatorRuntime::adopt_committed`]: parking
/// keeps the certificate instead of dropping it, and the replay re-runs the
/// full precommit-quorum, height, proposer, parent and lock checks.
#[derive(Clone, Debug)]
pub struct ParkedCommit {
    pub height: Height,
    pub block: Block,
    pub certificate: crate::consensus::QuorumCertificate,
    /// `(hc.height, hc.round)` when this item was parked; see
    /// [`ParkedProposal::parked_at`].
    pub parked_at: (Height, Round),
}

/// Measures one consensus entry point and reports it on EVERY return path
/// (`Drop` runs for early returns too). Timing only; no behaviour change.
struct PhaseTimer(&'static str, std::time::Instant);

impl Drop for PhaseTimer {
    fn drop(&mut self) {
        stellereum::metrics::global().observe_phase(self.0, self.1.elapsed().as_secs_f64());
    }
}

fn phase_timer(name: &'static str) -> PhaseTimer {
    PhaseTimer(name, std::time::Instant::now())
}

impl ValidatorRuntime {
    /// Park the newest proposal for replay (bounded: overwrites any older
    /// parked proposal, so at most one is ever held).
    ///
    /// Only `hc.height + 1` is ever replayable: the install advances the
    /// height by exactly one, and `take_parked` drops any other target. A
    /// proposal for any other height is therefore junk in this slot — and
    /// letting it overwrite the REAL H+1 proposal (park depth 1) means the
    /// useful copy is lost and the peer must retransmit it. One unauthenticated
    /// frame could evict it, so refuse to park non-replayable heights.
    pub(super) fn park_proposal(&mut self, proposer: ValidatorId, block: Block, round: Round) {
        if block.height != self.hc.height.saturating_add(1) {
            tracing::debug!(
                height = block.height,
                round,
                local_height = self.hc.height,
                "not parking a proposal that cannot be replayed after this apply"
            );
            return;
        }
        if self.parked_proposal.is_some() {
            tracing::debug!(
                height = block.height,
                round,
                "replacing a parked proposal with a newer one (park depth is 1)"
            );
        }
        self.parked_proposal = Some(ParkedProposal {
            proposer,
            block,
            round,
            parked_at: (self.hc.height, self.hc.round),
        });
    }

    /// Park the newest peer commit for replay (bounded: overwrites any older
    /// parked commit, so at most one is ever held).
    ///
    /// Same replayable-target rule as [`Self::park_proposal`]: only
    /// `hc.height + 1` can be adopted after the install, so a commit for any
    /// other height must never evict the useful slot (park depth 1).
    pub(super) fn park_commit(
        &mut self,
        height: Height,
        block: Block,
        certificate: crate::consensus::QuorumCertificate,
    ) {
        if height != self.hc.height.saturating_add(1) {
            tracing::debug!(
                height,
                local_height = self.hc.height,
                "not parking a commit that cannot be replayed after this apply"
            );
            return;
        }
        if self.parked_commit.is_some() {
            tracing::debug!(
                height,
                "replacing a parked commit with a newer one (park depth is 1)"
            );
        }
        self.parked_commit = Some(ParkedCommit {
            height,
            block,
            certificate,
            parked_at: (self.hc.height, self.hc.round),
        });
    }

    /// Take (and clear) both park slots, dropping any item that went stale
    /// while parked.
    ///
    /// STALENESS (explicit): `hc.height`/`hc.round` can advance while an item
    /// sits in a slot, so each item carries the epoch it was parked in and is
    /// only returned when it still targets the current height with a
    /// non-superseded envelope round. Everything else is DROPPED here (and the
    /// slot cleared) — a stale item can never be replayed a height late. Note
    /// that `hc` legitimately advances by exactly one between parking (during
    /// the H apply) and replay (H installed), which is why the check is
    /// "target == current height" rather than "no advance happened".
    ///
    /// Returns at most one of each (two entries total, fixed memory).
    pub fn take_parked(&mut self) -> (Option<ParkedProposal>, Option<ParkedCommit>) {
        let now = (self.hc.height, self.hc.round);
        let proposal = self.parked_proposal.take().filter(|p| {
            // The apply window that parked this item must have closed (a
            // height advance happened) AND the body must target the height
            // now in progress, with a non-superseded envelope round.
            p.parked_at.0 < now.0
                && p.block.height == now.0
                && p.round
                    .saturating_add(crate::consensus_net::SUPERSEDED_ROUND_LAG)
                    > now.1
        });
        // A commit parked while the PREVIOUS height applied targets the height
        // that just became current; one parked during the CURRENT height's own
        // apply is redundant after the advance and is dropped by the same
        // target-height rule.
        let commit = self
            .parked_commit
            .take()
            .filter(|c| c.parked_at.0 <= c.height && c.height == now.0);
        (proposal, commit)
    }

    /// Drop everything parked without replaying it (used when the node
    /// deliberately abandons the window, e.g. a hard reset of consensus).
    pub fn clear_parked(&mut self) {
        self.parked_proposal = None;
        self.parked_commit = None;
    }

    /// Drop slots that can no longer be replayed even after a legitimate
    /// advance: anything targeting a height more than one ahead of the
    /// current one (or, for commits, a height already behind us) is stale.
    /// Called on every round change so a slot cannot linger across view
    /// changes; the precise stale check (target height AND envelope round)
    /// runs again in [`Self::take_parked`] at replay time.
    fn prune_stale_parked(&mut self) {
        let height = self.hc.height;
        if self
            .parked_proposal
            .as_ref()
            .is_some_and(|p| p.block.height > height.saturating_add(1))
        {
            self.parked_proposal = None;
        }
        if self
            .parked_commit
            .as_ref()
            .is_some_and(|c| c.height > height.saturating_add(1) || c.height < height)
        {
            self.parked_commit = None;
        }
    }

    /// True while a proposal or commit is waiting for the apply worker.
    pub fn has_parked(&self) -> bool {
        self.parked_proposal.is_some() || self.parked_commit.is_some()
    }
}

impl ValidatorRuntime {
    /// Validate a proposed block before accepting/prevoting it.
    /// SECURITY: rejects wrong height/proposer/prev_hash, oversized blocks and
    /// transactions with bad signatures.
    ///
    /// `expected_state_root` is OUR current root. The block header commits to the
    /// state it builds on - the root after the previous block, which is the
    /// standard convention and is what lets a chain be walked without replaying
    /// it - so that value is checkable, and it was not being checked at all. A
    /// proposer could put any root in the header and every validator accepted the
    /// block, which left the whole state commitment decorative on the live path.
    /// Fail-closed block-timestamp gate (A3/S8): refuse on a bad or missing
    /// timestamp using deterministic rules only. The bound is
    /// [`crate::protocol::MAX_BLOCK_TIMESTAMP_DRIFT_MS`]: monotone versus the
    /// parent and at most that drift ahead of it.
    ///
    /// The parent timestamp resolves from, in order: (1) the stored parent
    /// body (`blocks[prev_hash]`, the common live case); (2) `last_decision`
    /// when it names exactly this parent (hash AND height match, so a stale
    /// decision from an older height can never vouch for a new parent);
    /// (3) the zero parent of a height-1 block (`prev_hash == [0; 32]`
    /// anchors at 0). Anything else — a parent this node never saw — is
    /// refused rather than skipped: accepting first and hoping the parent
    /// turns up is the fail-open this closes.
    ///
    /// Pure function of (`self.blocks`, `self.last_decision`, `block`): no
    /// wall clock, so every validator derives the same verdict. Called on the
    /// proposal path AND the adopt path, so a Byzantine commit cannot smuggle
    /// past the decision boundary a timestamp no proposer could publish.
    pub(super) fn check_block_timestamp(&self, block: &Block) -> Result<(), String> {
        if block.height == 0 {
            return Ok(()); // genesis carries no parent; nothing to be monotone against
        }
        if block.timestamp == 0 {
            return Err("proposal: missing block timestamp".to_string());
        }
        // Whether the parent resolved to the zero-genesis anchor rather than a
        // seen body: the first block after genesis legitimately jumps from the
        // anchor to the proposer's wall clock (billions of seconds), so the
        // forward jump bound below cannot apply to it. Monotonicity still
        // holds (any non-zero timestamp is past the anchor).
        let mut from_genesis_anchor = false;
        let parent_ts = self
            .blocks
            .get(&block.prev_hash)
            .map(|b| b.timestamp)
            .or_else(|| {
                self.last_decision.as_ref().and_then(|(h, b, _)| {
                    if *h + 1 == block.height && self.decision_block_hash(*h, b) == block.prev_hash
                    {
                        Some(b.timestamp)
                    } else {
                        None
                    }
                })
            })
            .or_else(|| {
                if block.height == 1 && block.prev_hash == [0u8; 32] {
                    from_genesis_anchor = true;
                    Some(0)
                } else {
                    None
                }
            });
        let Some(parent_ts) = parent_ts else {
            return Err("proposal: unknown parent timestamp (fail-closed)".to_string());
        };
        if block.timestamp < parent_ts {
            return Err("proposal: timestamp moved backwards".to_string());
        }
        if !from_genesis_anchor
            && !crate::protocol::timestamp_within_bounds(parent_ts, block.timestamp)
        {
            return Err("proposal: timestamp too far ahead of parent".to_string());
        }
        Ok(())
    }

    /// The CONSENSUS-enforced transaction-order commitment check.
    ///
    /// The block carries the order Merkle root over its own transaction list
    /// (`Block::order_merkle_root`) and that root is inside the SIGNED block
    /// hash, so the BFT quorum that voted for the block voted for its ORDER
    /// as well. This check re-computes the root from the body on the wire and
    /// refuses anything that does not match: a proposer therefore cannot
    /// reorder a block after it has been signed and voted on, which is the
    /// whole point of committing to the order.
    ///
    /// PURE: a function of the block body alone (no state, no clock, no
    /// node-local key), so the proposer and every validator derive the SAME
    /// verdict from the SAME body. An EMPTY block commits to nothing and
    /// carries the all-zero root, which is what the recomputation returns for
    /// it.
    ///
    /// COORDINATED ROLLOUT: this is a hard rule, so every validator must run
    /// it before it votes — a block whose order root does not match its body
    /// is refused, not warned about.
    ///
    /// Cache-key soundness (STAB fix): `Block::compute_hash` deliberately
    /// EXCLUDES transaction signatures (they sign the hash), so two bodies
    /// that differ ONLY in tx signatures share a block hash. The batch-verify
    /// verdict is a pure function of exactly those signatures, so keying it
    /// on the block hash alone aliases a tampered body onto the genuine
    /// body's ACCEPT verdict (caught by
    /// `proposal_validation_rejects_tampering`). The key below commits to
    /// the signatures too: hashing 64 B x N is memcmp-cheap next to N
    /// Ed25519 verifies, so the verify-once speedup is kept and the verdict
    /// is a pure function of the key.
    pub(super) fn decision_block_hash(&self, h: Height, b: &Block) -> BlockHash {
        self.decided_parent_votes
            .as_ref()
            .filter(|dpv| dpv.height == h)
            .map(|dpv| dpv.decision_block_hash)
            .unwrap_or_else(|| b.compute_hash())
    }

    pub(super) fn batch_verify_cache_key_with_hash(block: &Block, bh: &BlockHash) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(bh);
        h.update((block.transactions.len() as u32).to_be_bytes());
        for tx in &block.transactions {
            h.update((tx.signature.len() as u32).to_be_bytes());
            h.update(&tx.signature);
        }
        h.finalize().into()
    }

    /// Same aliasing class as above: `compute_hash` excludes
    /// `validator_signatures` (evidence ABOUT the block, decided after the
    /// hash is fixed), so a body with a FORGED proposer signature shares the
    /// genuine block hash. The proposer-sig verdict is a pure function of
    /// (block hash, proposer, validator_signatures), which is exactly what
    /// this key commits to (`proposer` is hashed already; it is mixed in
    /// again so the key is self-describing).
    pub(super) fn proposer_sig_cache_key_with_hash(block: &Block, bh: &BlockHash) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(bh);
        h.update(block.proposer);
        h.update((block.validator_signatures.len() as u32).to_be_bytes());
        for (id, sig) in &block.validator_signatures {
            h.update(id);
            h.update((sig.len() as u32).to_be_bytes());
            h.update(sig);
        }
        h.finalize().into()
    }

    pub(super) fn verify_proposer_sig_cached(
        &self,
        block: &Block,
        bh: &BlockHash,
        cache_failures: bool,
    ) -> bool {
        let cache_key = Self::proposer_sig_cache_key_with_hash(block, bh);
        if let Some(v) = self
            .proposer_sig_cache
            .lock()
            .ok()
            .and_then(|g| g.get(&cache_key).copied())
        {
            return v;
        }
        let ok = crate::consensus::verify_proposer_signature_with_hash(block, bh);
        if ok || cache_failures {
            if let Ok(mut g) = self.proposer_sig_cache.lock() {
                if g.len() > 1024 {
                    g.clear();
                }
                g.insert(cache_key, ok);
            }
        }
        ok
    }

    pub(super) fn check_order_commitment_with_hash(
        &self,
        block: &Block,
        bh: &BlockHash,
    ) -> Result<(), String> {
        // STAB: per-block-hash cache — the root is a pure function of the body,
        // so repeat validations of the same block (round retries, demanded
        // re-propose, adopt) hit O(1) instead of re-hashing O(txs).
        if let Some(cached) = self
            .order_root_cache
            .lock()
            .ok()
            .and_then(|g| g.get(bh).copied())
        {
            if block.order_merkle_root != cached {
                return Err(format!(
                    "proposal: transaction order does not match the committed order root (block {} != recomputed {})",
                    hex::encode(block.order_merkle_root),
                    hex::encode(cached)
                ));
            }
            return Ok(());
        }
        let expected = crate::mev::compute_order_merkle_root(&block.transactions);
        if let Ok(mut g) = self.order_root_cache.lock() {
            if g.len() > 1024 {
                g.clear();
            }
            g.insert(*bh, expected);
        }
        if block.order_merkle_root != expected {
            return Err(format!(
                "proposal: transaction order does not match the committed order root (block {} != recomputed {})",
                hex::encode(block.order_merkle_root),
                hex::encode(expected)
            ));
        }
        Ok(())
    }

    /// CANONICAL DOWNTIME EVIDENCE (W10.5): verify the QC the proposer
    /// embedded for the PARENT height (`block.last_qc`).
    ///
    /// The transition attributes downtime for height H-1 from the certificate
    /// embedded in block H — chosen once, by H's proposer — so every node
    /// that applies the block attributes identically, no matter which quorate
    /// QC subset its own vote assembly observed (the 2026-10-23 #292786 fork:
    /// {A,C} vs {A,B,C} both passed the same quorum but bumped different
    /// `missed` counters and split the state root). The evidence is covered
    /// by the block hash, and this check pins it before any vote:
    /// * height linkage: evidence for exactly H-1, naming the parent hash;
    /// * finality shape: a precommit quorum (prevotes never prove finality);
    /// * quorum under the set IN FORCE AT H-1 (never the live set), with the
    ///   exact power shortfall on refusal.
    ///
    /// `None` is accepted ONLY when this node knows no decision for H-1
    /// (genesis child, or a node restored/healed without finalizing since —
    /// it cannot distinguish "predates evidence" from "withheld evidence",
    /// so it must not veto what the knowledgeable quorum accepts; the
    /// applier then skips attribution for that height — deterministic, since
    /// `None` is canonical bytes). A node that DID finalize H-1 (its
    /// `last_decision` names it) rejects `None` outright: the evidence exists
    /// and omitting it would silently suppress one height of downtime
    /// accounting.
    #[cfg(test)]
    pub(super) fn check_last_qc_evidence(&self, block: &Block) -> Result<(), String> {
        self.check_last_qc_evidence_with_hash(block, &block.compute_hash())
    }

    pub(super) fn check_last_qc_evidence_with_hash(
        &self,
        block: &Block,
        bh: &BlockHash,
    ) -> Result<(), String> {
        let Some(parent_h) = block.height.checked_sub(1) else {
            return Ok(());
        };
        let Some(qc) = &block.last_qc else {
            let knows_parent_decision = self.last_decision.as_ref().is_some_and(|(h, b, _)| {
                *h == parent_h && self.decision_block_hash(*h, b) == block.prev_hash
            });
            if knows_parent_decision {
                return Err(format!(
                    "proposal: block at height {} omits the downtime evidence for decided height {parent_h}",
                    block.height
                ));
            }
            return Ok(());
        };
        if qc.height != parent_h {
            return Err(format!(
                "proposal: downtime evidence is for height {} not parent {parent_h}",
                qc.height
            ));
        }
        if qc.block_hash != Some(block.prev_hash) {
            return Err("proposal: downtime evidence names a different parent block".to_string());
        }
        if qc.kind != crate::consensus::VoteKind::Precommit {
            return Err("proposal: downtime evidence is not a precommit quorum".to_string());
        }
        // SHARD BINDING (Finding A): a certificate aggregates one shard's
        // votes and its signatures are bound to that shard's V3 preimage. A
        // parent certificate from a SIBLING shard (possible for a nil QC,
        // whose target hash is absent) must not be embedded here: it would
        // attribute downtime from another shard's participation. The target
        // block's own shard is the only acceptable scope, and it is also this
        // runtime's shard.
        if qc.shard_id != block.shard_id || qc.shard_id != self.shard_id {
            return Err(format!(
                "proposal: downtime evidence is for shard {} but this block/shard is {}/{}",
                qc.shard_id, block.shard_id, self.shard_id
            ));
        }
        // STAB verify-once: the QC power is a pure function of (block bytes,
        // validator history at parent_h). Round retries re-validate the same
        // block; the second+ visits hit O(1) instead of re-running
        // verify-grade `signers_set` crypto. Failures are NOT cached (a
        // history advance could turn a weak QC into a passing one).
        if let Some((ok, _)) = self
            .qc_power_cache
            .lock()
            .ok()
            .and_then(|g| g.get(bh).copied())
        {
            if ok {
                return Ok(());
            }
        }
        let set = self.validator_set_for_height(parent_h);
        // SAME VERDICT AS APPLY (PENTEST F-2): `apply_downtime_slash_with_set`
        // accepts evidence only after a verify-grade check. The gate used to
        // use attribution (`qc_signed_power`, no verify) instead, so an
        // over-cap `last_qc` carrying a genuine quorum passed the gate and was
        // then silently skipped by apply: any proposer could suppress the
        // downtime attribution for a height. Attribution is now capped (F-1),
        // but the two paths must not merely agree on this input class — they
        // must share ONE verdict.
        //
        // CN-VRF v3 (review F2): the verdict is the HEIGHT-AWARE one. At/after
        // activation an honest `last_qc` is a µQC drawn from the epoch beacon,
        // so verifying it through the parent-hash draw found no committee
        // match and refused every honest proposal that carried the required
        // downtime evidence. `verify_qc_for_height` / `qc_signed_power_for_height`
        // use the same schedule the producer used.
        if !self.verify_qc_for_height(qc, &set) {
            let signed = self.qc_signed_power_for_height(&set, qc);
            let required = set.quorum_power();
            crate::metrics::global().inc_weak_qc_refused();
            return Err(format!(
                "proposal: downtime evidence carries only {signed} of {required} required power at height {parent_h}"
            ));
        }
        if let Ok(mut g) = self.qc_power_cache.lock() {
            if g.len() > 1024 {
                g.clear();
            }
            // `verify` is the authoritative verdict (same one apply uses).
            // Do NOT run attribution again just to fill a readout number: no
            // caller reads the second tuple element, and a second Falcon pass
            // per proposal is exactly the CPU cost the cap work removed.
            g.insert(*bh, (true, 0));
        }
        Ok(())
    }

    /// The downtime-evidence QC to embed in a proposal for the current
    /// height: the QC that decided the parent (H-1), known from the last
    /// decision this node recorded (local finalize, adopt, sync walk and the
    /// boot restore from the persisted finalized tip all stash it).
    ///
    /// The parent HASH is checked too: a stale/divergent decision at the same
    /// height must never be attached to a different parent (the evidence has
    /// to name this proposal's exact parent block).
    ///
    /// `None` when this node knows no parent decision yet: the genesis child
    /// (nothing decided before height 1), or a node whose boot could not
    /// reconstruct the evidence. The latter is fail-closed at `propose`
    /// (`parent_evidence_missing`), so it skips the slot rather than emitting
    /// an omission. Validators that DO know the parent decision reject the
    /// omission; validators that do not accept it and skip attribution for
    /// that height. Either way the verdict is a pure function of agreed
    /// inputs, so no fork.
    pub(super) fn decided_parent_qc(
        &self,
        parent_hash: &BlockHash,
    ) -> Option<crate::consensus::QuorumCertificate> {
        let h = self.hc.height.checked_sub(1)?;
        let (dh, b, qc) = self.last_decision.as_ref()?;
        if *dh != h || self.decision_block_hash(*dh, b) != *parent_hash {
            return None;
        }
        if let Some(dpv) = self.decided_parent_votes.as_ref() {
            if dpv.height == h
                && dpv.block_hash == *parent_hash
                && dpv.decision_block_hash == *parent_hash
            {
                let current_signers = qc.pq_signer_count();
                let target_votes = dpv
                    .votes
                    .falcon_votes_count_for_target(Some(dpv.block_hash));
                if target_votes > current_signers {
                    if let Some(rebuilt) =
                        crate::consensus::produce_decision_certificate_with_schedule(
                            &dpv.votes,
                            Some(dpv.block_hash),
                            &dpv.validators,
                            dpv.parent_hash.as_ref(),
                            dpv.schedule,
                        )
                    {
                        if rebuilt.pq_signer_count() > current_signers
                            && rebuilt.verify_with_schedule(&dpv.validators, dpv.schedule)
                        {
                            return Some(rebuilt);
                        }
                    }
                }
            }
        }
        Some(qc.clone())
    }

    pub(super) fn seed_decided_parent_votes_from_qc(
        &mut self,
        height: Height,
        bh: BlockHash,
        qc: &crate::consensus::QuorumCertificate,
        validators: ValidatorSet,
        parent_hash: Option<[u8; 32]>,
        schedule: CommitteeSchedule,
    ) {
        // O6: index the certificate's Ed25519 half ONCE. The old lookup ran
        // `signatures.iter().find(...)` for every Falcon signer (O(signers *
        // entries)); this is the same "first 64-byte entry for this id wins"
        // result without the quadratic scan. Insertion order is preserved by
        // `or_insert_with`, so a duplicate Ed entry still resolves exactly as
        // `find` did.
        let mut ed_by_signer: std::collections::HashMap<ValidatorId, &[u8]> =
            std::collections::HashMap::with_capacity(qc.signatures.len());
        for (id, s) in &qc.signatures {
            if s.len() == 64 {
                ed_by_signer.entry(*id).or_insert_with(|| s.as_slice());
            }
        }
        let mut votes = VoteSet::new();
        for (voter, fsig) in qc.pq_signer_signatures_with_schedule(&validators, schedule) {
            let mut sig = ed_by_signer
                .get(&voter)
                .map(|s| s.to_vec())
                .unwrap_or_else(|| vec![0u8; 64]);
            crate::consensus::attach_vote_falcon_sig(&fsig, &mut sig);
            let vote = Vote::signed_with_in_shard(
                voter,
                qc.shard_id,
                height,
                qc.round,
                VoteKind::Precommit,
                Some(bh),
                sig,
            );
            let _ = votes.add_verified_in_scope(
                vote,
                &validators,
                height,
                qc.round,
                VoteKind::Precommit,
            );
        }
        if self.hc.height == height {
            if let Some(hc_set) = self.hc.precommit_set(qc.round) {
                for voter in validators.validators.keys() {
                    if votes.vote_by(voter).is_some() {
                        continue;
                    }
                    if let Some(v) = hc_set.vote_by(voter) {
                        if v.block_hash == Some(bh)
                            && v.shard_id == qc.shard_id
                            && v.falcon_signature().is_some()
                        {
                            let _ = votes.add_verified_in_scope(
                                v.clone(),
                                &validators,
                                height,
                                qc.round,
                                VoteKind::Precommit,
                            );
                        }
                    }
                }
            }
        }
        self.decided_parent_votes = Some(DecidedParentVotes {
            height,
            round: qc.round,
            block_hash: bh,
            shard_id: qc.shard_id,
            validators,
            parent_hash,
            schedule,
            votes,
            decision_block_hash: bh,
        });
    }

    /// Admit a late-arriving valid `Precommit` for the already-decided parent
    /// height (`H-1`) into `decided_parent_votes.votes` ONLY so `Block.last_qc`
    /// includes slower honest validators without touching `self.hc`,
    /// `self.safety`, floors, or round chasing.
    pub fn record_late_parent_precommit(&mut self, v: &Vote) -> bool {
        if v.kind != VoteKind::Precommit || v.shard_id != self.shard_id {
            return false;
        }
        let Some(dpv) = self.decided_parent_votes.as_mut() else {
            return false;
        };
        if v.shard_id != dpv.shard_id
            || v.height != dpv.height
            || v.round != dpv.round
            || v.block_hash != Some(dpv.block_hash)
        {
            return false;
        }
        if dpv.validators.power_of(&v.voter) == 0 {
            return false;
        }
        if dpv.votes.vote_by(&v.voter).is_some() {
            return false;
        }
        if !v.verify() {
            return false;
        }
        dpv.votes
            .add_verified_in_scope(
                v.clone(),
                &dpv.validators,
                dpv.height,
                dpv.round,
                VoteKind::Precommit,
            )
            .is_ok()
    }

    pub(super) fn try_admit_late_parent_precommit(&mut self, v: &Vote) -> bool {
        let eligible = v.height.checked_add(1) == Some(self.hc.height)
            || (v.height == self.hc.height && self.apply_in_flight.is_some());
        if !eligible {
            return false;
        }
        self.record_late_parent_precommit(v)
    }

    /// SHARD SCOPE, shared by every entry point that can apply a block.
    ///
    /// In a multi-shard process each consensus instance only accepts blocks
    /// for its own shard, and only transactions it OWNS (`source_shard ==
    /// this shard`). That covers same-shard transfers and OUTBOUND cross-shard
    /// transfers; the destination receives value through a committed
    /// consumption record, never through `transactions`. Single-shard mode
    /// skips all of this, so the historical masterchain blocks that carry
    /// source=1/target=1 txs still validate.
    ///
    /// PENTEST F-7 (LOW): `adopt_committed` re-implements a subset of
    /// proposal validation and had no shard gate, so a quorum-signed foreign
    /// block was applied to this shard's state while both siblings (proposal
    /// and the body walk) refused it. One helper keeps the three entry points
    /// on one rule.
    pub(super) fn check_block_shard_scope(&self, block: &Block) -> Result<(), String> {
        if !self.shard_registry.is_sharded() {
            return Ok(());
        }
        if block.shard_id != self.shard_id {
            return Err(format!(
                "proposal: wrong shard {} (expected {})",
                block.shard_id, self.shard_id
            ));
        }
        if let Some(bad) = block
            .transactions
            .iter()
            .find(|t| !crate::sharding::tx_belongs_to_shard(t, self.shard_id))
        {
            return Err(format!(
                "proposal: transaction targets shard {} not {}",
                bad.source_shard, self.shard_id
            ));
        }
        Ok(())
    }

    /// Wire-size and proof-unit caps, the two the proposer's packer enforces
    /// (`Mempool::select_for_block_multi` / `truncate_to_block_caps`) that the
    /// tx-count and gas checks do NOT cover.
    ///
    /// PURE function of the body, so every entry point that admits a block
    /// (proposal, adopt) derives the same verdict on every node. A Byzantine
    /// proposer that packs over them would otherwise force validators to carry
    /// bytes/proof work no honest packer can reproduce.
    pub(super) fn check_block_wire_and_proof_caps(block: &Block) -> Result<(), String> {
        let mut wire = 0usize;
        let mut proofs = 0usize;
        for t in &block.transactions {
            wire = wire.saturating_add(crate::mempool::Mempool::estimate_tx_wire_bytes(t));
            proofs = proofs.saturating_add(crate::mempool::Mempool::count_tx_proof_units(t));
        }
        if wire > crate::mempool::Mempool::MAX_BLOCK_WIRE_BYTES {
            return Err("proposal: block wire size exceeded".to_string());
        }
        if proofs > crate::mempool::Mempool::MAX_BLOCK_PROOF_UNITS {
            return Err("proposal: block proof-unit cap exceeded".to_string());
        }
        Ok(())
    }

    /// Round-INDEPENDENT proposal checks: everything `validate_proposal` verifies
    /// except which round's proposer slot the block claims. Used by `on_proposal`
    /// to prove a block is genuine (signed by its declared proposer, building on
    /// our state) BEFORE any round alignment happens: aligning first and asking
    /// questions later would let a forged envelope shove us +64 rounds per
    /// message, wiping our live proposal each time -- a round-DoS.
    pub(super) fn validate_proposal_unaligned(
        &self,
        block: &Block,
        expected_state_root: [u8; 32],
    ) -> Result<(), String> {
        self.validate_proposal_unaligned_with_hash(
            block,
            expected_state_root,
            &block.compute_hash(),
        )
    }

    pub(super) fn validate_proposal_unaligned_with_hash(
        &self,
        block: &Block,
        expected_state_root: [u8; 32],
        bh: &BlockHash,
    ) -> Result<(), String> {
        if block.height != self.hc.height {
            return Err("proposal: wrong height".to_string());
        }
        // TIMESTAMP VALIDITY (A3, fail-closed): the proposer timestamp is
        // hashed into the block and used as the VM's "now" (session expiry,
        // unbonding, order stamps) — an unbounded proposer could skew all of
        // them. Both bounds are deterministic functions of (parent, child):
        // (a) monotone vs the parent block's timestamp (agreed state, no
        // clock involved); (b) at most MAX_BLOCK_TIMESTAMP_DRIFT_MS ahead of
        // the parent (ruleset v4 S8). There is deliberately NO wall-clock read
        // here: a `now_secs()` bound makes the verdict node-local (two validators
        // with skewed clocks disagree about the same block), and there is no
        // grace or skip path — a bad or unresolvable timestamp is refused.
        self.check_block_timestamp(block)?;
        // SHARD SCOPE (gated): see `check_block_shard_scope` for the rule and
        // the F-7 note (the same helper now gates the adopt path).
        self.check_block_shard_scope(block)?;
        // Cross-shard commit consistency: every OUTBOUND message must name a
        // transaction actually in this block (so the debit happens), and
        // every INBOUND consumption record must prove inclusion against the
        // source root and must not be a replay of a message already
        // credited on this chain.
        if self.shard_registry.is_sharded() {
            // TOTAL cross-shard record cap (legacy transfers + 2PC control
            // records). Checked once, before any per-record work, so a
            // Byzantine proposer cannot make validators carry an unbounded
            // `cross_shard_out` body. The proposer uses the same constant.
            if !Self::cross_shard_record_cap_ok(block) {
                return Err(format!(
                    "proposal: cross-shard record cap exceeded ({} > {})",
                    block.cross_shard_out.len(),
                    crate::xshard2pc::XPC_MAX_CROSS_SHARD_RECORDS_PER_BLOCK
                ));
            }
            for msg in &block.cross_shard_out {
                if msg.is_outbound_for(self.shard_id) {
                    if msg.is_xpc() {
                        // §9 2PC: the outbound 2PC records are derived from
                        // this shard's committed 2PC state (not from a
                        // transaction in this block), so the rule is the
                        // re-derivation of that state, not "the transaction
                        // is in the block".
                        if !self.xpc_outbound_admissible(msg, block) {
                            return Err(format!(
                                "proposal: cross-shard 2PC record {} is not backed by this shard's 2PC state",
                                hex::encode(&msg.msg_id[..8])
                            ));
                        }
                        continue;
                    }
                    let tx_present = block
                        .transactions
                        .iter()
                        .any(|t| t.compute_tx_hash() == msg.tx.compute_tx_hash());
                    if !tx_present {
                        return Err(
                            "proposal: outbound cross-shard message has no transaction in the block"
                                .to_string(),
                        );
                    }
                    // XSHARD bounce-escrow gate: "the tx is present in the
                    // block" is NOT proof that the source debited anybody (a
                    // transaction can be included and fail at apply). At/above
                    // the gate the outbound legacy record must carry the SAME
                    // anchored source-escrow proof the inbound legacy credit
                    // verifies (XSHARD-01). An outbound legacy message cannot
                    // prove a same-block escrow (it anchors to the parent
                    // root), so on a gate-active chain legacy cross-shard value
                    // is disabled and the §9 2PC is the only delivery path.
                    if crate::chain_spec::xshard_bounce_escrow_required_active_at(block.height)
                        && !self.state.verify_cross_shard_escrow_anchored(msg)
                    {
                        return Err(format!(
                            "proposal: outbound cross-shard legacy record {} has no anchored source escrow proof (XSHARD bounce gate)",
                            hex::encode(&msg.msg_id[..8])
                        ));
                    }
                    continue;
                }
                if msg.is_inbound_for(self.shard_id) {
                    let key = CrossShardKey::of(msg);
                    if self.consumed_cross_shard.contains(&key) {
                        return Err(format!(
                            "proposal: replayed cross-shard message {}",
                            hex::encode(&msg.msg_id[..8])
                        ));
                    }
                    // §5 M3 kind-dispatched validation (mirrors `propose`):
                    // transfers prove inclusion; acks/bounces prove linkage
                    // to a committed outbound (+ timeout for bounces); a
                    // record for an already-completed transaction is stale.
                    if msg.is_ack() || msg.is_bounce() {
                        if !self.control_linkage_ok(msg, block.height) {
                            return Err(format!(
                                "proposal: cross-shard ack/bounce {} fails linkage/timeout",
                                hex::encode(&msg.msg_id[..8])
                            ));
                        }
                        // XSHARD bounce-escrow gate: a control record must not
                        // complete a transaction whose §9 2PC record rides the
                        // SAME block (the runtime mirror is refreshed only on
                        // apply, so the block scan closes the same-block gap).
                        if crate::chain_spec::xshard_bounce_escrow_required_active_at(block.height)
                        {
                            let tx_hash = msg.tx.compute_tx_hash();
                            if block
                                .cross_shard_out
                                .iter()
                                .any(|m| m.is_xpc() && m.tx.compute_tx_hash() == tx_hash)
                            {
                                return Err(format!(
                                    "proposal: cross-shard ack/bounce {} is for a transaction with a 2PC record in this block (XSHARD bounce gate)",
                                    hex::encode(&msg.msg_id[..8])
                                ));
                            }
                        }
                    } else if msg.is_xpc() {
                        // §9 2PC: the inbound record must carry a valid proof
                        // of the PEER's committed 2PC state, anchored to a
                        // finalized header of the peer shard.
                        if !self.xpc_admissible(msg) {
                            return Err(format!(
                                "proposal: cross-shard 2PC record {} fails its proof or anchor",
                                hex::encode(&msg.msg_id[..8])
                            ));
                        }
                    } else if msg.is_transfer() {
                        if !self.verify_cross_shard_anchored(msg) {
                            return Err(format!(
                                "proposal: cross-shard message {} fails anchored inclusion (uncommitted source root or unfinalized source block)",
                                hex::encode(&msg.msg_id[..8])
                            ));
                        }
                    } else {
                        return Err(format!(
                            "proposal: cross-shard message {} has an unknown kind",
                            hex::encode(&msg.msg_id[..8])
                        ));
                    }
                    if self
                        .completed_cross_shard
                        .contains(&msg.tx.compute_tx_hash())
                    {
                        return Err(format!(
                            "proposal: cross-shard message {} is for a completed transfer",
                            hex::encode(&msg.msg_id[..8])
                        ));
                    }
                }
            }
            // The reverse direction too: an outbound cross-shard transaction
            // with no committed message would burn the value with nobody able
            // to claim it. Require the pair.
            for tx in &block.transactions {
                if !crate::sharding::tx_is_outbound_cross_shard(tx, self.shard_id) {
                    continue;
                }
                let committed = block.cross_shard_out.iter().any(|m| {
                    m.is_outbound_for(self.shard_id)
                        && m.tx.compute_tx_hash() == tx.compute_tx_hash()
                });
                if !committed {
                    return Err(
                        "proposal: outbound cross-shard transaction has no committed message"
                            .to_string(),
                    );
                }
            }
        }
        if block.state_root != expected_state_root {
            // CONSENSUS-SAFETY DIVERGENCE (2026-10-22 #288000): the quorum can
            // finalize a block hash WITHOUT agreeing on the post-state — the
            // hash commits to the PRE-state root only. When two nodes compute
            // different post-states for the same finalized hash, the next
            // proposals carry the proposer's post-state root and the other
            // side lands exactly here: same chain, same height, different
            // state, finalization stalled. This branch is the ONLY
            // in-protocol witness of that split, so it is LOUD on purpose: a
            // structured error log with a greppable DIVERGENCE tag (the
            // watchdog pages on it) plus a monotonic counter for dashboards.
            // Resync is deliberately NOT automatic here: picking which side is
            // canonical needs an operator with the offline `stelops diverge`
            // comparison, never a machine guessing from one side.
            let their_root = hex::encode(block.state_root);
            let our_root = hex::encode(expected_state_root);
            tracing::error!(
                target: "stellereum::consensus",
                "DIVERGENCE height={} block={} proposer={} their_root={} our_root={} \
                 same finalized hash, different post-state: execution diverged, resync the minority side from a canonical snapshot",
                block.height,
                hex::encode(bh),
                hex::encode(block.proposer),
                their_root,
                our_root,
            );
            crate::metrics::global().inc_divergence();
            return Err(format!(
                "proposal: state root {their_root} does not match our state {our_root}"
            ));
        }
        // SHARD-HEAD COMMITMENTS (TON `shard_hashes`): the masterchain's
        // published shard heads must be canonical and must not contradict a
        // header this process already finalized. The commitment itself is
        // covered by the block hash, so the quorum that signs the block
        // stands behind it.
        self.check_shard_header_commitments(block)?;
        // EPOCH-MMR COMMITMENT (V5 Tier-2): the masterchain boundary block's
        // root over the previous epoch's finalized hashes must be canonical
        // (boundary height only, masterchain only) and must not contradict
        // the root this process derives from its own finalized chain. A node
        // that has not finalized the epoch yet has nothing to contradict, so
        // the proposal is accepted — the commitment is still checked by the
        // quorum that signs the block.
        self.check_epoch_mmr_commitment(block)?;
        // TRANSACTION-ORDER COMMITMENT (consensus-enforced): the block
        // carries the order Merkle root over its transaction list and the
        // root is inside the signed block hash, so the quorum that votes for
        // the block votes for its ORDER. Re-compute the root from the body
        // on the wire and REFUSE the proposal when it does not match: a
        // proposer cannot reorder a block after it has been signed/voted on.
        // (This is what turns the order commitment from a node-local note
        // into a protocol rule — see `mev`.)
        //
        // It runs BEFORE the signature check on purpose: a body whose order
        // no longer matches the commitment is refused for the ORDER reason,
        // not for the incidental "the signature does not cover this body"
        // reason — the order commitment is the rule that is being violated.
        self.check_order_commitment_with_hash(block, bh)?;
        // CANONICAL DOWNTIME EVIDENCE (W10.5): the proposer-chosen QC for the
        // parent height — verified here (linkage, finality shape, quorum under
        // the set in force at H-1) so the evidence every applier attributes
        // from is byte-identical across the network.
        self.check_last_qc_evidence_with_hash(block, bh)?;
        // Authenticity: the block must actually be signed by its declared
        // proposer, otherwise a peer could propose on another validator's behalf.
        // STAB verify-once: cache the verdict per block hash (pure function
        // of block bytes); the timed attribution path below hits the cache
        // instead of re-verifying the same Ed25519/Falcon signature.
        if !self.verify_proposer_sig_cached(block, bh, true) {
            return Err("proposal: invalid or missing proposer signature".to_string());
        }
        let expected_prev = self.finalized.last().map(|(_, h)| *h).unwrap_or([0u8; 32]);
        if block.prev_hash != expected_prev {
            return Err("proposal: wrong prev_hash (not chained to finalized head)".to_string());
        }
        if block.transactions.len() > MAX_BLOCK_TXS {
            return Err("proposal: block too large".to_string());
        }
        // Actor-mailbox cap, block-static half (no state read, so it stays in
        // the synchronous validator): a block whose OWN sends already exceed
        // `MAX_ACTOR_MSGS_PER_BLOCK` can never drain-to-empty and is rejected
        // here. The backlog-inclusive half is checked by the async callers
        // (`on_proposal`, `adopt_committed`, `propose`), which agree with this
        // whenever the backlog is empty.
        if block_actor_sends_exceed_cap(block) {
            return Err(format!(
                "proposal: actor mailbox over cap ({} sends in block > {})",
                count_block_actor_sends(block),
                crate::state_engine::MAX_ACTOR_MSGS_PER_BLOCK
            ));
        }
        let total_gas = block
            .transactions
            .iter()
            .fold(0u64, |acc, t| acc.saturating_add(t.gas_limit));
        if total_gas > MAX_BLOCK_GAS {
            return Err("proposal: block gas limit exceeded".to_string());
        }
        // SAME CAP SET THE PACKER ENFORCES (`Mempool::select_for_block_multi`
        // / `truncate_to_block_caps`): a proposer must not hand validators a
        // body no honest packer can reproduce. The tx-count and gas caps above
        // already reject the sealed+plain union overflow; these two close the
        // remaining halves so the proposer and the validator agree on EVERY
        // cap (wire bytes bound the decode/amortized bandwidth, proof units
        // bound verification work).
        Self::check_block_wire_and_proof_caps(block)?;
        // Batched Ed25519 verification: much faster than one-by-one for a full block.
        // STAB verify-once: cache per signature-committing key; the timed attribution re-run
        // below becomes an O(1) HashMap hit with a byte-identical verdict.
        {
            let batch_key = Self::batch_verify_cache_key_with_hash(block, bh);
            let cached = self
                .batch_verify_cache
                .lock()
                .ok()
                .and_then(|g| g.get(&batch_key).copied());
            let ok = match cached {
                Some(v) => v,
                None => {
                    // PERF_PROFILE §6.2: parallel intake batch — byte-identical
                    // verdict to the serial batch (par_chunks().all(serial);
                    // small blocks take the serial path verbatim).
                    let v = Transaction::verify_signatures_batch_parallel(&block.transactions);
                    if let Ok(mut g) = self.batch_verify_cache.lock() {
                        if g.len() > 1024 {
                            g.clear();
                        }
                        g.insert(batch_key, v);
                    }
                    v
                }
            };
            if !ok {
                return Err("proposal: bad transaction signature".to_string());
            }
        }
        // F-01 CONSENSUS FEE FLOOR (fail-closed, cheap, before execution):
        // admission (`Mempool::insert`) and the honest proposer filter both
        // refuse `gas_limit` below the effective floor, but neither binds a
        // Byzantine proposer — and until now neither did this function, so a
        // custom-built block of valid-signature underpriced (or zero-fee)
        // transactions was accepted and executed by every honest validator,
        // with failures paying nothing. Refuse such blocks here.
        //
        // The verdict is THE single admission helper
        // (`Mempool::effective_floor_for_tx`: base + D2 failure penalty + PQ
        // activation surcharge where applicable), so the formula cannot drift
        // from admission. It reads this validator's mempool floor state via a
        // non-blocking lock: a contended pool fails CLOSED (the block is
        // refused, not skipped) rather than executing underpriced work. An
        // empty block passes vacuously.
        //
        // CONSENSUS NOTE: the base here is the admission base
        // (`max(frozen, governed)`, synced every finalize); the apply path
        // charges the governed base (see `consensus_floor_parts`) — the
        // frozen half is the same const on every node and cannot move
        // consensus. Validate is therefore
        // never looser than apply: anything apply would up-charge is either
        // refused here or arrives declaring at least the floor. The penalty
        // half converges across honest nodes that finalized the same chain
        // (identical verdict feeds in identical order); a node whose mempool
        // missed feedback (reorg/sync paths feed nothing) holds a LOWER floor
        // and may accept what peers refuse — fail-open for that node only,
        // never a network split, and closed the moment its live path
        // re-feeds. Coordinated rollout: all validators run the identical
        // floor config, exactly like admission today.
        {
            let pool = self
                .mempool
                .try_read()
                .map_err(|_| "proposal: fee floor unavailable (fail-closed)".to_string())?;
            // Snapshot once for the diagnostic breakdown below; the verdict
            // itself comes from the single helper (cannot drift).
            let penalty_snapshot = pool.penalty_snapshot();
            // The CONSENSUS floor the apply path will charge with (the D2
            // penalty - the governed base is already covered by `base_fee`,
            // which is synced to `max(frozen, governed)`), snapshotted once. The
            // validation floor is `max(admission floor, consensus floor)`: it
            // must NEVER be looser than the floor execution charges with,
            // otherwise a transaction whose fee depends on the penalty could
            // be packed by a node whose penalty view is stale and charged
            // DIFFERENTLY by two validators - a different balance, a
            // different state root, a consensus split (audit W6.6).
            //
            // A contended read fails CLOSED (the block is refused), exactly
            // like the mempool floor read above: a floor that cannot be read
            // must never be silently lowered.
            let consensus_penalties = self
                .state
                .consensus_penalty_try_read()
                .map_err(|_| "proposal: fee floor unavailable (fail-closed)".to_string())?;
            for tx in &block.transactions {
                // THE SAME FLOOR AS ADMISSION AND AS THE PROPOSER'S OWN
                // FILTER: `required_fee_for_tx` = base + D2 failure penalty +
                // PQ activation surcharge + the transaction's EXPLICIT PRIORITY
                // BID. The bid is a price, so it must be covered by the
                // transaction's own fee; the proposer filter already refuses a
                // transaction whose `gas_limit` does not cover it, so a
                // Byzantine proposer must not be able to sneak an UNFUNDED bid
                // into a block the honest validators accept (the bid would
                // then buy priority without paying for it).
                let surcharge = if tx.is_pq_activation() {
                    crate::mempool::PQ_ACTIVATION_SURCHARGE_GAS
                } else {
                    0
                };
                let consensus_floor = consensus_penalties
                    .get(&tx.from)
                    .copied()
                    .unwrap_or(0)
                    .saturating_add(surcharge);
                let floor = pool.required_fee_for_tx(tx).max(consensus_floor);
                if tx.gas_limit < floor {
                    return Err(format!(
                        "proposal: tx {} from {} below fee floor (gas_limit {} < floor {} = base {} + penalty {} + pq_surcharge {} + priority {} + consensus_penalty {})",
                        hex::encode(tx.compute_tx_hash()),
                        hex::encode(&tx.from[..6]),
                        tx.gas_limit,
                        floor,
                        pool.base_fee,
                        penalty_snapshot.get(&tx.from).copied().unwrap_or(0),
                        surcharge,
                        tx.priority_fee_per_gas,
                        consensus_penalties.get(&tx.from).copied().unwrap_or(0),
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn validate_proposal(
        &self,
        block: &Block,
        expected_state_root: [u8; 32],
    ) -> Result<(), String> {
        self.validate_proposal_unaligned(block, expected_state_root)?;
        if Some(block.proposer) != self.expected_proposer_now() {
            return Err("proposal: wrong proposer".to_string());
        }
        // SIGNED ROUND (ruleset v4): the block must belong to the round this
        // proposal is for, not merely carry the right proposer slot. The round
        // is inside the block hash, so a mismatch is both a signature-covered
        // claim and a cheap deterministic refusal.
        if !self.accepts_block_round(block) {
            return Err(format!(
                "proposal: block round {} does not match proposal round {}",
                block.round, self.hc.round
            ));
        }
        Ok(())
    }

    /// Whether `block`'s SIGNED round is legal for the proposal we are
    /// accepting at our current round.
    ///
    /// The normal case is exact equality (ruleset v4): both sides of the
    /// bid signed the same round.
    ///
    /// The lock-rescue / demanded-rescue paths deliberately re-serve a LOCKED
    /// value VERBATIM (`propose` returns the stored body unchanged), because
    /// the hash is the value peers are locked on: re-signing that body for the
    /// new round would change its identity and every locked peer would (and
    /// must) nil it. Such a re-proposal therefore carries the round it was
    /// ORIGINALLY signed under, which is necessarily EARLIER than the round
    /// it is re-proposed in.
    ///
    /// We accept that exception ONLY for a body we already hold: it was
    /// admitted here at its own signed round, so this is a re-proposal of a
    /// `block.round <= self.hc.round` — a proposal signed at an EARLIER round
    /// is accepted (that is the lock-rescue / one-round-lag path: a node that
    /// timed out to round r+1 must still be able to vote for the body proposed
    /// at round r, or a single late frame desynchronises the cluster forever).
    /// A FUTURE signed round is refused: the proposer cannot claim a round the
    /// network has not reached.
    ///
    /// Safety is unchanged: votes carry their own round, the QC commits to the
    /// exact block hash (which includes the signed round), and
    /// proposal-equivocation evidence still requires the SAME signed round
    /// with different hashes — an older-round body is never evidence by
    /// itself.
    fn accepts_block_round(&self, block: &Block) -> bool {
        block.round <= self.hc.round
    }

    /// Timed proposal validation (BACKPRESSURE HONESTY).
    ///
    /// Runs the SAME verdict as [`Self::validate_proposal_unaligned`] but
    /// attributes wall time per stage so a node that is too slow to validate
    /// can SAY so instead of silently voting nil. Stages are deliberately the
    /// expensive ones an operator must distinguish: `proposer_sig_verify`
    /// (Ed25519/Falcon), `state_root_check` (state-root recompute / trie
    /// read), `order_commit`, `tx_batch_verify` (per-tx sig verifies),
    /// `fee_floor_mempool` (mempool filter), `header_checks` (everything
    /// else: timestamp, shard scope, gas caps, actor cap).
    ///
    /// MEASUREMENT ONLY: the `Instant`s here never enter round timing (see
    /// task 4 — the deterministic timeout takes no clock). The verdict is
    /// byte-identical to the untimed path: this function CALLS it once and
    /// attributes via the per-block verify-once caches (order root, batch
    /// verify, proposer sig) populated by that single run — no second
    /// O(txs) crypto pass, so verdicts cannot diverge and the tail is halved.
    pub fn validate_proposal_timed(
        &self,
        block: &Block,
        expected_state_root: [u8; 32],
    ) -> (Result<(), String>, Vec<(String, u64)>) {
        self.validate_proposal_timed_with_hash(block, expected_state_root, &block.compute_hash())
    }

    pub(super) fn validate_proposal_timed_with_hash(
        &self,
        block: &Block,
        expected_state_root: [u8; 32],
        bh: &BlockHash,
    ) -> (Result<(), String>, Vec<(String, u64)>) {
        // Authoritative verdict: exactly one run, same order, same errors.
        // STAB verify-once: the verdict above populates the per-block caches
        // (order root, batch verify, proposer sig); attribution below reads
        // those caches O(1) instead of re-running O(txs) crypto, so the timed
        // path costs one verification per block, not two, with a
        // byte-identical verdict.
        let verdict = self.validate_proposal_unaligned_with_hash(block, expected_state_root, bh);
        let mut stages: Vec<(String, u64)> = Vec::with_capacity(6);
        let t = std::time::Instant::now();
        let _ = self
            .proposer_sig_cache
            .lock()
            .ok()
            .and_then(|g| {
                g.get(&Self::proposer_sig_cache_key_with_hash(block, bh))
                    .copied()
            })
            .unwrap_or_else(|| crate::consensus::verify_proposer_signature_with_hash(block, bh));
        stages.push(("proposer_sig_verify".into(), t.elapsed().as_millis() as u64));
        let t = std::time::Instant::now();
        let _ = block.state_root == expected_state_root;
        stages.push(("state_root_check".into(), t.elapsed().as_millis() as u64));
        let t = std::time::Instant::now();
        // Cache hit: `check_order_commitment` already cached the root during
        // the verdict above, so this is a HashMap lookup, not O(txs) hashes.
        let _ = self.check_order_commitment_with_hash(block, bh);
        stages.push(("order_commit".into(), t.elapsed().as_millis() as u64));
        let t = std::time::Instant::now();
        let _ = self
            .batch_verify_cache
            .lock()
            .ok()
            .and_then(|g| {
                g.get(&Self::batch_verify_cache_key_with_hash(block, bh))
                    .copied()
            })
            .unwrap_or_else(|| Transaction::verify_signatures_batch_parallel(&block.transactions));
        stages.push(("tx_batch_verify".into(), t.elapsed().as_millis() as u64));
        let t = std::time::Instant::now();
        {
            if let Ok(pool) = self.mempool.try_read() {
                for tx in &block.transactions {
                    let _ = pool.required_fee_for_tx(tx);
                }
            }
        }
        stages.push(("fee_floor_mempool".into(), t.elapsed().as_millis() as u64));
        let t = std::time::Instant::now();
        {
            let _ = self.check_block_timestamp(block);
            let _ = block_actor_sends_exceed_cap(block);
        }
        stages.push(("header_checks".into(), t.elapsed().as_millis() as u64));
        (verdict, stages)
    }

    /// Record one validation's timing: meter + loud log when slow.
    ///
    /// Fires when the SUM exceeds [`SLOW_VALIDATION_THRESHOLD_MS`]: increments
    /// `slow_validation_total` (+ metrics), and logs ONE line naming the
    /// slowest stage (`state-root recompute? sig verifies? trie? mempool
    /// filter?`) with the full breakdown. Never changes the verdict — the
    /// caller already accepted or refused the proposal.
    pub fn note_validation_timing(&mut self, stages: &[(String, u64)]) {
        self.validation_last_stages = stages.to_vec();
        let total: u64 = stages.iter().map(|(_, ms)| *ms).sum();
        if total < SLOW_VALIDATION_THRESHOLD_MS {
            return;
        }
        self.slow_validation_total = self.slow_validation_total.saturating_add(1);
        crate::metrics::global().inc_slow_validation();
        let slowest = stages.iter().max_by_key(|(_, ms)| *ms);
        let breakdown = stages
            .iter()
            .map(|(s, ms)| format!("{s}={ms}ms"))
            .collect::<Vec<_>>()
            .join(" ");
        let slow_name = slowest.map(|(s, _)| s.as_str()).unwrap_or("unknown");
        let msg = format!(
            "[slow-validation] h={} r={} total={}ms slowest={} ({}) slow_total={}",
            self.hc.height, self.hc.round, total, slow_name, breakdown, self.slow_validation_total,
        );
        eprintln!("{msg}");
        tracing::warn!("{msg}");
    }

    /// Record a peer's lock hint from a nil prevote: "I am stuck on the block
    /// `hint`, which you authored -- re-propose it". Only nil prevotes at our
    /// height qualify, and only hints naming OUR bodies for THIS height are
    /// kept (anything else is another author's turn, or junk). Bounded and
    /// height-scoped; serving is one-shot per hint (see `propose`).
    pub fn note_lock_hint(
        &mut self,
        vote_height: Height,
        kind: VoteKind,
        target: Option<BlockHash>,
        hint: Option<BlockHash>,
    ) {
        if vote_height != self.hc.height || kind != VoteKind::Prevote || target.is_some() {
            return;
        }
        let Some(h) = hint else { return };
        if self.demanded_height != self.hc.height {
            self.demanded.clear();
            self.demanded_height = self.hc.height;
        }
        // "OUR body" means we AUTHORED it, not merely that we happen to hold a
        // copy. A body another validator authored must never enter the
        // rescue set: serving it would re-propose somebody else's block under
        // OUR proposer slot, which every receiver rejects ("proposer field
        // mismatch") — the rescue would fail, the stuck peer would stay
        // stuck, and our own proposer round would be spent on a block the
        // network can never accept.
        //
        // DEMANDED LOOKUP BY VALUE (ruleset v6): the hint carries the SIGNED
        // hash the peer is locked on. Resolve it to the body we hold and key
        // the demand by that body's ROUND-FREE `value_id`, so the demand
        // survives the re-stamp we are about to serve and cannot be lost
        // merely because the peer's lock names an older signed round.
        let Some(value_id) = self
            .blocks
            .get(&h)
            .filter(|b| b.height == self.hc.height && b.proposer == self.id)
            .map(|b| b.value_id())
        else {
            return;
        };
        const MAX_DEMANDED: usize = 8;
        if self.demanded.len() >= MAX_DEMANDED && !self.demanded.contains(&value_id) {
            return;
        }
        self.demanded.insert(value_id);
    }

    /// Record a peer's SIGNED round. Returns true when we moved.
    ///
    /// Tendermint future-round rule: a verified vote for a round ahead of ours
    /// carries us TO that round. A peer within a few rounds is normal
    /// operation, and jumping wipes per-round proposal state -- but NOT
    /// jumping left a PERSISTENT one-round offset between two honest nodes
    /// (they prevoted the SAME value at r15 and r16, so no same-round QC could
    /// ever form and each height burned ~10 rounds). The behind node must
    /// follow. The view-change hold separately keeps near nodes in phase, and
    /// proposal-acceptance carries its own atomic align (a sync that brings
    /// its proposal can never strand us proposalless). Jumps land exactly ON
    /// the peer's round, never past it, so following cannot overshoot into a
    /// leapfrog: landing near stops further syncing.
    pub fn note_peer_vote_round(&mut self, vote_height: Height, vote_round: Round) -> bool {
        self.note_peer_vote_round_for(vote_height, vote_round, None)
    }

    /// [`Self::note_peer_vote_round`] with the vote's TARGET.
    ///
    /// The target is what makes the signed-round re-proposal coherent: when a
    /// verified peer votes for the SAME body we already hold a live proposal
    /// for, the peer's round is the round that body is being voted in, so we
    /// follow all the way to it and KEEP the proposal live there. Without
    /// this, the forward sync wiped the proposal and the node arrived at the
    /// peer's round unarmed — it could not vote the body the rest of the
    /// network was voting without waiting for another copy of the same
    /// (older-signed) proposal, and on a WAN the proposer had already moved
    /// on. Live v5 shape: the same locked body prevoted at r505/r507/r515
    /// and no round ever collected three votes.
    ///
    /// Safety: the body was already validated and accepted; its signed round
    /// is <= the round we move to (forward-only), the value is one this node
    /// already holds, and the watermark still refuses a vote at or below the
    /// last signed round. A nil or different-target vote keeps the old
    /// conservative path (wipe an unlocked proposal, chase at most one step
    /// without corroboration), so the accept-wipe protection is unchanged
    /// for values the network is not voting.
    pub fn note_peer_vote_round_for(
        &mut self,
        vote_height: Height,
        vote_round: Round,
        vote_target: Option<BlockHash>,
    ) -> bool {
        // Any verified lead pulls us up -- including 1 round. Callers invoke this
        // only AFTER `Vote::verify` + membership (see the F2 fix in the drain),
        // and `sync_round_to` is capped at ROUND_LOOKBACK=8, so this cannot be
        // used for the round explosion we saw from unverified votes with a +64
        // cap. Suppressing near (1-3 round) sync instead left a PERSISTENT
        // one-round offset between two honest nodes: they prevoted the SAME
        // value at r15 and r16, so no same-round QC could ever form and each
        // height burned ~10 rounds (30s+). The behind node must follow.
        //
        // (A sit-while-armed variant was tried for 3-member WAN liveness and
        // reverted: refusing near jumps while holding a proposal deadlocks two
        // armed nodes on different rounds AND breaks the pinned
        // `round_nudge_reopens_gate_once_not_per_tick` convergence. The
        // 3-racer leapfrog cascade stays a known open issue for ≥3 WAN-skewed
        // equal-power members; the fix there is quorum-gated jumps (≥2
        // distinct voters), not unilateral sitting.)
        if vote_height != self.hc.height || vote_round <= self.hc.round {
            return false;
        }
        // The SAME vote must never move the round twice: the cap applies per
        // jump, and the vote path follows the round as well as the drain
        // (the vote path covers every consumer of the runtime, the drain
        // covers the node loop). Without this, one vote would move the node
        // twice as far as `ROUND_LOOKBACK` allows.
        //
        // CORROBORATION RE-OPENS THE CHASE (P3-R1): the dedup above is keyed
        // by (height, round), so a second DISTINCT validator vouching for the
        // same far round would be suppressed as a "replay" -- and the
        // corroboration gate below would never see the second witness. A
        // round reported by 2+ distinct validators (1 on a 2-member set) is
        // new evidence, not a replay, so it bypasses the dedup and re-runs
        // the chase. A lone liar replaying its own vote stays suppressed.
        // SAME-VALUE COHERENCE (the signed-round liveness rule): a verified
        // vote for the body we already hold is evidence that the network is
        // voting that body in THIS round. Follow it all the way and keep the
        // proposal live (restored after the sync below). Any other vote keeps
        // the conservative corroboration path.
        //
        // CORROBORATION WINDOW: the BFT bound is `f + 1`, derived from the
        // validator set (N=3 -> 1, N=4..6 -> 2, N=7..9 -> 3, ...). Requiring
        // a constant two was unsatisfiable exactly when it mattered: in a
        // 3-node cluster only ONE node can be at the head (live: r505 / r507
        // / r515, `supporting_peers_count(515)` was 1). A peer whose reported
        // round is within one ROUND_LOOKBACK BELOW the target certifies that
        // the network has moved to the target region, so the loop may finish
        // the jump. A lone far reporter still buys only the first step when
        // the set needs more than one supporter; two peers at a stale round
        // cannot re-open a replay of a much newer claim (pinned by
        // `spent_budget_blocks_fresh_votes_until_view_change`). The cumulative
        // per-height jump budget bounds whatever a single Byzantine reporter
        // can buy.
        let held_proposal = self.hc.proposal;
        let same_value = vote_target.is_some() && held_proposal.map(|(_, h)| h) == vote_target;
        let min_supporters = crate::consensus::round_corroboration_threshold(self.validators.len());
        let corroboration_floor = vote_round.saturating_sub(crate::consensus::ROUND_LOOKBACK);
        let corroborated =
            same_value || self.hc.supporting_peers_count(corroboration_floor) >= min_supporters;
        if !corroborated && self.last_followed_round == Some((vote_height, vote_round)) {
            return false;
        }
        self.last_followed_round = Some((vote_height, vote_round));
        let before = self.hc.round;
        // CONVERGE, don't nudge (liveness fix, live 2026-10-19: the
        // masterchain parked at height 285027 while the node rounds drifted
        // ~30 apart and the network spent its life in view changes). One
        // `sync_round_to` moves at most ROUND_LOOKBACK rounds, so a single
        // call used to carry us one cap-step toward the peer while the dedup
        // above suppressed every further step for that (height, round): a
        // node 30 rounds behind advanced 8 and then had to grind its own
        // 3.5 s+ timeouts one round at a time for the rest -- each timeout
        // wiping its proposal -- so the skew never closed. Loop to the
        // peer's round instead, within the existing per-round jump budget.
        //
        // CORROBORATION GATE (P3-R1 round-DoS fix): the FIRST step is always
        // taken -- a genuinely-behind node must follow even a single peer --
        // but CONTINUING past one step needs the round corroborated by a
        // second DISTINCT validator (same rule as the deadlock breaker, which
        // already refuses single-reporter jumps). Without this, ONE Byzantine
        // vote 1000 rounds ahead dragged an honest node +64 in a single call
        // (8 jumps x 8 rounds), and a trickle of such votes walked it off the
        // network's cliff one budget at a time -- a round-DoS with a single
        // key. `peer_rounds` already includes this vote (`observe_peer_vote`
        // runs before this on the vote path), so an actually-ahead network
        // (2+ distinct voters within one ROUND_LOOKBACK of the target) still
        // opens the full chase, and a 2-member set still follows its single
        // peer. The corroboration window is what lets a 3-node cluster finish
        // the jump when only ONE node is at the head (live r505/r507/r515).
        //
        // Residual: a lone liar still buys +8 per vote (fresh round each
        // time, the dedup only covers replays). Each step is a signed,
        // attributable vote and the per-round jump budget caps the rate; a
        // quorum gate on the FIRST step would break behind-node catch-up, so
        // the +8 unilateral nudge stays by design. The per-HEIGHT budget
        // (`MAX_PEER_ROUND_ADVANCE_PER_HEIGHT`, PENTEST F-9) caps the
        // cumulative drift, so a trickle of such votes can no longer walk the
        // node out of the re-phase scan window however many timeouts it burns.
        //
        // The bounds are otherwise unchanged in aggregate: at most
        // MAX_SYNC_JUMPS_PER_ROUND capped jumps per call (the documented
        // per-round bound), forward-only, verified-votes-only (callers gate),
        // landing exactly ON the peer's round. The dedup still means one
        // vote moves us once -- the vote-path + drain double stays a no-op
        // because we are already there.
        let mut first_step = true;
        while vote_round > self.hc.round {
            if !first_step && !corroborated {
                break; // lone reporter: keep the nudge, refuse the cliff
            }
            first_step = false;
            let r = self.hc.round;
            self.hc.sync_round_to(vote_round);
            if self.hc.round == r {
                break; // jump budget exhausted; our own view change refills it
            }
        }
        // Keep an accepted SAME-VALUE proposal live in the round the peers
        // are voting it (see `note_peer_vote_round_for`). This is what makes
        // every acceptor prevote the re-served locked body in the SAME round
        // instead of each at its own local round.
        if same_value && self.hc.round != before {
            if let Some((proposer, hash)) = held_proposal {
                self.hc.proposal = Some((proposer, hash));
                self.hc.proposal_round = Some(self.hc.round);
            }
        }
        self.hc.round != before
    }

    /// Feed a (possibly stale/absurd) peer vote into round-sync WITHOUT voting
    /// (deadlock fix 2026-10-14).
    ///
    /// Verifies the vote (signature + validator membership) and requires
    /// `vote.height == hc.height`; on success records the peer's round via
    /// `HeightConsensus::observe_peer_round` (counter only, bounded
    /// `sync_round_to` chase). Returns true when our round moved. A vote for
    /// a stale round or beyond `MAX_ROUND_AHEAD` — both rejected by
    /// `on_prevote`/`on_precommit` — still teaches us the peer's round here,
    /// so a 1200-round desync collapses instead of being dropped both ways.
    pub fn observe_peer_vote(&mut self, vote: &Vote) -> bool {
        if vote.height != self.hc.height || vote.shard_id != self.shard_id {
            return false;
        }
        if !vote.verify() {
            return false;
        }
        if self.validators.power_of(&vote.voter) == 0 {
            return false;
        }
        // RECORD ONLY. The chase (moving our round to the peer's) is the
        // future-round rule and lives in `note_peer_vote_round`, which the
        // vote path applies right after this. Keeping the two apart lets the
        // counter be updated for EVERY verified vote - accepted or not -
        // without also chasing on votes the caller has already accounted for.
        self.hc.note_peer_round(vote.voter, vote.round);
        // EMISSION ONLY (calibration feed, FIXES.md §2.12 `q = 1 − p̂ − λ̂`):
        // one vote counted per verified same-height member vote, by kind, on
        // the process-global registry. Unverified, non-member and
        // wrong-height votes return false above and never reach this line, so
        // forged traffic cannot inflate the series. This statement cannot
        // affect consensus: it neither reads nor writes any engine state and
        // the return value below is unchanged.
        crate::metrics::global().inc_vote(crate::metrics::VoteKind::from(vote.kind));
        true
    }

    /// Stamp finalization progress (call on every finalize/adopt).
    pub fn record_progress(&mut self) {
        self.last_progress_at = std::time::Instant::now();
    }

    /// Breaker timeout (`STELL_DEADLOCK_TIMEOUT_SECS`, default 300s).
    pub fn deadlock_timeout() -> std::time::Duration {
        std::time::Duration::from_secs(crate::consensus::HeightConsensus::deadlock_timeout_secs())
    }

    /// Deadlock circuit breaker (live 2026-10-14: A r1550 vs B r318 at h92078).
    ///
    /// Fires only when ALL hold (fail-safe):
    ///  * no finalization progress for the timeout window,
    ///  * a verified peer round ahead of us exists (`max_peer_round`),
    ///  * the jump is forward-only, and at most once per timeout window.
    ///
    /// On fire, performs the bounded jump to `max(peer rounds)`, stamps the
    /// rate limit, logs LOUDLY (tracing + stderr), and returns the new round.
    /// The caller must reset its round timer so it does not view-change past
    /// the peer it just joined.
    pub fn check_deadlock_breaker(&mut self) -> Option<Round> {
        let timeout = Self::deadlock_timeout();
        if self.last_progress_at.elapsed() < timeout {
            return None;
        }
        if let Some(last) = self.last_breaker_at {
            if last.elapsed() < timeout {
                return None;
            }
        }
        let no_progress_secs = self.last_progress_at.elapsed().as_secs();
        let timeout_secs = timeout.as_secs().max(1);
        let target = self
            .hc
            .deadlock_breaker_target(no_progress_secs, timeout_secs)?;
        let from = self.hc.round;
        if !self.hc.apply_deadlock_jump(target) {
            return None;
        }
        self.last_breaker_at = Some(std::time::Instant::now());
        tracing::error!(
            height = self.hc.height,
            from_round = from,
            to_round = target,
            no_progress_secs,
            "DEADLOCK-BREAKER: no finalization, jumping round forward to max(peer rounds)"
        );
        eprintln!(
            "[consensus][DEADLOCK-BREAKER] h={} r{} -> r{} after {}s without finalization (timeout {}s)",
            self.hc.height, from, target, no_progress_secs, timeout_secs
        );
        Some(target)
    }

    /// Receive a proposal from the (correct) proposer for the current round.
    pub async fn on_proposal(
        &mut self,
        proposer: ValidatorId,
        block: Block,
        envelope_round: Round,
    ) -> Result<BlockHash, String> {
        let _phase = phase_timer("on_proposal");
        // §7 Phase 2 gate: the header's root check below reads OUR root, which
        // is PRE-H while a decided block is still executing. Checking now
        // would compare the proposal against the wrong parent state (a valid
        // H+1 proposal looks corrupt, a stale one looks fine), so the
        // proposal is deferred, not validated, until the worker reports back.
        // No state is read and none moves.
        //
        // PARK-AND-REPLAY (liveness, incident #21508): the proposal used to be
        // DROPPED here, so recovering it cost a full retransmit cycle (the
        // first vote retransmit alone was >=1.5s before the retransmit fix).
        // It is now parked in a bounded one-slot buffer and replayed through
        // this same function (all checks run) as soon as the worker reports.
        if self.apply_in_flight.is_some() {
            self.park_proposal(proposer, block, envelope_round);
            return Err("proposal parked for replay: apply in flight".to_string());
        }
        // Read our root BEFORE accepting, so the header is checked against the
        // state the block would actually extend.
        let our_root = self.state.get_state_root().await;
        let bh = block.compute_hash();
        // Authenticity FIRST, before height/state checks: only the declared
        // proposer could have signed this, so a verified signature makes the
        // header's claims (height, prev_hash) attributable -- and worth
        // learning from even when we must refuse the block itself.
        if !self.verify_proposer_sig_cached(&block, &bh, false) {
            return Err("proposal: invalid or missing proposer signature".to_string());
        }
        // Record the peer head BEFORE any refusal below: a genuine proposal at
        // height H proves finalized H-1 even when it is not for us (wrong
        // height or round). Refused proposals previously taught us nothing, so
        // a node exactly one height behind never learned the head and spun in
        // view changes at its own height forever.
        //
        // VERIFICATION G1: attribution requires membership, not just a valid
        // signature — anyone can self-sign a proposal with their own key, so
        // a signature-only gate lets a zero-stake outsider plant hints and
        // force the catch-up timer every tick (forged H+1 proposals keeping
        // the node on loudly-failing DHT walks). A Byzantine MEMBER
        // advertising false heads only triggers loudly-failing walks, bounded
        // by caps.
        if block.height > 0
            && crate::consensus_net::proposal_hint_admissible(&block, &self.validators)
        {
            let h = (block.height - 1, block.prev_hash);
            if self.peer_hint.map(|(ph, _)| ph < h.0).unwrap_or(true) {
                self.peer_hint = Some(h);
            }
        }
        // Prove the block genuine BEFORE any round alignment: a forged envelope
        // must never move our round (see `validate_proposal_unaligned`).
        // C2 BACKPRESSURE HONESTY: run the TIMED validation (same verdict,
        // plus per-stage attribution). A node too slow to validate says WHICH
        // stage was slow instead of silently voting nil.
        let (vres, stages) = self.validate_proposal_timed_with_hash(&block, our_root, &bh);
        self.note_validation_timing(&stages);
        vres?;
        // Actor-mailbox cap, backlog-inclusive half (async: reads the engine).
        // The static half already ran inside `validate_proposal_unaligned`;
        // this adds what is already queued, so a block that fits on its own
        // but overflows on top of leftovers is still rejected deterministically
        // instead of carried over.
        self.check_actor_cap(&block).await?;
        // Freshness: the envelope round is the sender's claimed round. A
        // genuine body arriving LATE (delayed in transit) must not be adopted
        // as the current round's value: the proposer has moved on, the rest of
        // the network votes something else, and voting the stale body spends
        // our one vote on a quorum that can never form -- observed live as two
        // nodes voting different bodies at the same round for hundreds of
        // rounds. The envelope is only a freshness hint (it is unsigned), and
        // it is consulted strictly AFTER authentication: a forged envelope on
        // garbage dies above without moving anything; a forged envelope on a
        // genuine body is indistinguishable from network delay, which is
        // harmless (idempotent at worst).
        // ONE lag predicate everywhere: the driver, the compact layer and the
        // vote filter all use SUPERSEDED_ROUND_LAG. Rejecting ANY older
        // envelope here made a single late frame fatal: a node that timed out
        // to r+1 could never accept the body proposed at r, so a staggered
        // 3-node cluster advanced in lockstep forever and never finalised
        // (observed live at ruleset v5). A body within the lag window is still
        // a signed block for this height; voting it costs at most one round,
        // while rejecting it costs liveness.
        if envelope_round.saturating_add(crate::consensus_net::SUPERSEDED_ROUND_LAG)
            <= self.hc.round
        {
            return Err("proposal: stale round".to_string());
        }
        // Phase-align: if the block is genuinely this height's proposer's work
        // but for a NEAR-FUTURE round, we are simply behind -- jump to the
        // earliest round this proposer owns and accept it there instead of
        // rejecting it as "wrong proposer" and then missing it forever (the
        // vote that would have synced us arrives after the proposal it should
        // have preceded). Bounded to near rounds: a far claim is answered by
        // the vote path, not by an unsigned envelope.
        // PROPOSER SLOT = the round the BODY was signed for, not our current
        // round. A re-stamped rescue body is valid for its own `block.round`;
        // an older body is still valid for the round it was signed in. The old
        // scan picked the EARLIEST future slot this proposer owns, so a
        // genuine future body could be aligned to a different (earlier) slot
        // and then refused — audit F5.
        let body_round = block.round;
        if self.expected_proposer_at(&self.validators, self.hc.height, body_round)
            != Some(block.proposer)
        {
            return Err("proposal: wrong proposer".to_string());
        }
        if body_round > self.hc.round {
            // Near-future only. Far claims are answered by the verified vote
            // path (bounded chase), never by an unsigned envelope.
            if body_round > self.hc.round.saturating_add(PROPOSAL_ALIGN_WINDOW_ROUNDS) {
                return Err("proposal: wrong proposer".to_string());
            }
            self.hc.sync_round_to(body_round);
        }
        // R-TEMPO single validation (was: a SECOND full `validate_proposal`
        // here after `validate_proposal_timed` above — 2x order-commit +
        // 2x batch sig-verify + 2x fee-floor scan per proposal per node,
        // ~36ms on a loaded 1785-tx block, ~5x that on a 1-vCPU member).
        // `validate_proposal_timed` ALREADY returned the authoritative
        // `validate_proposal_unaligned` verdict for this exact
        // (block, our_root) above, and nothing between the two calls mutates
        // state (the actor-cap check is a read lock; the phase-align moves
        // only our local round counter). Re-running it can therefore only
        // repeat the same verdict at full cost. The only half of
        // `validate_proposal` not covered by the timed run is the
        // proposer-slot check against the ALIGNED round, kept here verbatim
        // so the accept/refuse verdict is byte-identical to before.
        if Some(block.proposer) != self.expected_proposer_now() {
            return Err("proposal: wrong proposer".to_string());
        }
        // SIGNED ROUND (ruleset v4): after any near-future alignment above,
        // the block's SIGNED round must be the round we are accepting it for.
        // The one exception is a VERBATIM re-proposal of a body we already
        // hold (lock rescue / demanded rescue), which keeps the round it was
        // originally signed under; see `accepts_block_round`. This is what
        // makes an honest cross-round re-proposal distinguishable from a
        // double-propose for the slasher.
        if !self.accepts_block_round(&block) {
            return Err(format!(
                "proposal: block round {} does not match proposal round {}",
                block.round, self.hc.round
            ));
        }
        // CN-VRF v3 payload (commit carriers + proposer reveal + epoch-boundary
        // MinRoot beacon). No-op below the activation gate.
        if self.cnvrf_v3_is_active_at(block.height) {
            self.validate_cnvrf_v3_payload(&block)?;
        }
        // EPOCH-KEY COMMITMENT: the block pins the MEV epoch key the network
        // uses for this epoch (see `crate::mev_epoch`). Record it: a node
        // whose OWN key differs from the committed one has DIVERGED (a
        // different validator view at the epoch boundary), and it must then
        // stop releasing decryption partials — its shares would reconstruct a
        // different shared point, and the ciphertext would not authenticate
        // for anybody.
        if block.epoch_key_commitment != [0u8; 32] {
            let mut pool = self.mempool.write().await;
            pool.mev_seal
                .note_committed_epoch_key(block.epoch_key_commitment);
        }
        if block.proposer != proposer {
            return Err("proposal: proposer field mismatch".to_string());
        }
        // ROUND-FREE VALUE IDENTITY (ruleset v6): register the value behind
        // this signed hash so the lock rules can recognise a re-stamped body
        // of the SAME value. The signed hash stays the vote/QC identity.
        self.hc.note_value_id(bh, block.value_id());
        let expected = self.expected_proposer_now();
        // RESTART-LIVELOCK: key the one-value-per-round rule on the BODY's
        // signed round (`block.round`), not on our local acceptance round. A
        // delayed/re-served body signed at an older round may be admitted
        // here, but the scheduled proposer's genuine body for THIS round (a
        // re-stamp at `block.round == hc.round`) must be able to supersede it;
        // otherwise it is refused as "already recorded for this round" and
        // this node can only vote the older signed round (at/below its
        // watermark after a restart), so the height never reaches quorum.
        // A body this HEIGHT admitted at its own signed round may be re-served
        // VERBATIM many rounds later (lock rescue / demanded rescue) and must
        // stay live. A body first seen under a fresh envelope after a restart
        // was never admitted here, so it must not own this round's slot
        // (RESTART-SPLIT). The marker is per-HeightConsensus and is therefore
        // empty on a restart even when the lock body itself was restored.
        let already_admitted = self.hc.was_signed_admitted(&bh);
        self.hc.receive_proposal_for_known_at(
            proposer,
            bh,
            expected,
            block.round,
            already_admitted,
        )?;
        // Fork-choice: the proposal is recorded as a CANDIDATE before it is
        // finalized, so a competing branch is KNOWN. When it loses (another
        // block is finalized at this height) the blocks that lost can be
        // signalled instead of vanishing.
        self.record_candidate_block(&block);
        let _ = self.run_fork_choice();
        self.blocks.insert(bh, block);
        Ok(bh)
    }

    /// The round a prevote for the CURRENT live proposal would carry.
    ///
    /// Ruleset v4/v5 put the BFT round inside the block identity, and the
    /// lock-rescue/demanded-rescue paths deliberately re-serve the SAME body
    /// VERBATIM. That body keeps the round it was SIGNED under, which is
    /// older than the local round it is re-served in. Stamping the prevote
    /// with the LOCAL round made every acceptor vote the same hash in a
    /// DIFFERENT bucket (live: r505/r507/r515, no round ever reaching a
    /// quorum). The signed round is signed by the proposer and is identical
    /// on every node holding the body, so it is the coherent vote round.
    ///
    /// Safety: the runtime only accepts `block.round <= hc.round`, so this is
    /// never a FUTURE round; the local round counter itself is untouched
    /// (no rewind — a node that already voted in a later round keeps its
    /// counter and the driver's fsynced watermark refuses this vote instead,
    /// see `round_at_or_below_vote_floor`). Nil votes (no proposal) keep the
    /// local round.
    pub fn prevote_round(&self) -> Round {
        match (self.hc.proposal, self.hc.decide_prevote()) {
            (Some((_, bh)), Some(_)) => self
                .blocks
                .get(&bh)
                .map(|b| b.round)
                .unwrap_or(self.hc.round),
            _ => self.hc.round,
        }
    }

    pub fn make_prevote(&self) -> Option<Vote> {
        if !self.safety.can_sign() {
            return None;
        }
        if self.hc.step != Step::Propose && self.hc.step != Step::Prevote {
            return None;
        }
        let target = self.hc.decide_prevote();
        let (round, target_with_vid) = match target {
            None => (self.hc.round, None),
            Some(bh) => {
                let vid = self
                    .blocks
                    .get(&bh)
                    .map(|b| b.value_id())
                    .or_else(|| self.hc.value_id_of(&bh))?;
                (self.prevote_round(), Some((bh, vid)))
            }
        };
        let req = crate::remote_signer::ConsensusSignRequest::Vote {
            chain_id: crate::consensus::consensus_chain_id(),
            shard_id: self.shard_id,
            height: self.hc.height,
            round,
            kind: crate::consensus::VoteKind::Prevote,
            block_hash: target_with_vid.map(|(bh, _)| bh),
        };
        let signer = self.vote_signer_for(req);
        match self.safety.authorize_and_sign_prevote(
            self.hc.height,
            round,
            self.shard_id,
            target_with_vid,
            &signer,
        ) {
            Ok(vote) => Some(vote),
            // F8 liveness: the durable lock names a DIFFERENT value from an
            // EARLIER round while the engine has already unlocked (it observed a
            // polka for this round's value). The durable authority therefore
            // refuses the non-nil prevote, and refusing to vote at all costs the
            // validator its whole round. A NIL prevote is always safe — it
            // endorses no value, so it cannot break the lock — and it keeps the
            // validator participating. The lock itself is NOT relaxed here.
            Err(crate::safety::SafetyRefusal::LockedConflict { lock, .. })
                if round > lock.round =>
            {
                tracing::warn!(
                    height = self.hc.height,
                    round,
                    locked_round = lock.round,
                    "[safety] locked for another value at an earlier round; \
                     casting NIL prevote instead of staying silent"
                );
                let nil_req = crate::remote_signer::ConsensusSignRequest::Vote {
                    chain_id: crate::consensus::consensus_chain_id(),
                    shard_id: self.shard_id,
                    height: self.hc.height,
                    round,
                    kind: crate::consensus::VoteKind::Prevote,
                    block_hash: None,
                };
                let nil_signer = self.vote_signer_for(nil_req);
                self.safety
                    .authorize_and_sign_prevote(
                        self.hc.height,
                        round,
                        self.shard_id,
                        None,
                        &nil_signer,
                    )
                    .ok()
            }
            Err(refusal) => {
                tracing::debug!(
                    height = self.hc.height,
                    round,
                    "[safety] prevote refused: {refusal}"
                );
                None
            }
        }
    }

    pub fn on_prevote(&mut self, v: Vote) -> Result<(), String> {
        let _phase = phase_timer("on_prevote");
        // SHARD SCOPE (Finding A). This runtime is one shard's consensus
        // instance; a vote signed for another shard is a different statement
        // (V3 preimage) and must not be admitted. The signature verifies
        // under its OWN shard, so without this check a foreign-shard vote
        // could enter the set (e.g. via a shared gossip path) and poison the
        // certificate's shard.
        if v.shard_id != self.shard_id {
            return Err(format!(
                "prevote from shard {} (this node serves shard {})",
                v.shard_id, self.shard_id
            ));
        }
        let res = self.hc.add_prevote(v.clone());
        // EVERY verified same-height vote feeds the peer-round counter, not
        // only the rejected ones. The counter is where the network is: the
        // deadlock breaker's corroboration and the quorum-scan anchor both
        // read it, and both were blind while only REJECTED votes updated it
        // (a healthy network rejects almost nothing, so the breaker never
        // fired and the anchor never moved).
        //
        // The return value says whether the vote VERIFIED (signature +
        // membership): only a verified vote is evidence that the network is
        // at that round.
        let verified = self.observe_peer_vote(&v);
        // FUTURE ROUND RULE (Tendermint): a node that receives a valid vote
        // for a round GREATER than its own must move to that round. Without
        // it a node that fell behind walks its rounds one timeout at a time
        // and never rejoins the network's round, so the two never prevote
        // the same value in the same round and no quorum can ever form.
        // The rule lives HERE (on the vote path) and not only in the node
        // loop, so every consumer of the runtime gets it - including the
        // in-process cluster, which is where the regression test lives.
        // Forward-only and bounded (`sync_round_to`): a node can never be
        // dragged backwards, and a single message cannot shove it far.
        //
        // ONLY A VERIFIED VOTE MAY MOVE THE ROUND. A vote that failed the
        // verification (a tampered body, a non-member) is not evidence of
        // anything, and a forged vote must never fast-forward a node (the
        // `round_converges_only_on_verified_peer_rounds` test pins this).
        // A verified vote that the round-window REFUSED (a vote absurdly far
        // ahead) still syncs, bounded: the F2 finding is that a verified far
        // vote is evidence of where the network is.
        if verified {
            self.note_peer_vote_round_for(v.height, v.round, v.block_hash);
        }
        res
    }

    /// Once a prevote quorum exists, lock and produce our precommit.
    ///
    /// Audit F10: `try_prevote_quorum` scans back a window of rounds (so a late
    /// quorum still decides), but a precommit must be cast for the round we are
    /// actually in. Casting a precommit at the CURRENT round off a prevote QC
    /// that formed in an OLDER round would vote a round in which we never
    /// prevoted, and lock us at the wrong round -- a validator only precommits
    /// after prevoting in that same round. So require a prevote QC recorded for
    /// `self.hc.round` whose target is the quorum target we are about to
    /// precommit. Finalization of an older round is unaffected: `try_finalize`
    /// inspects the same lookback window and can still commit it.
    pub fn make_precommit(&mut self) -> Option<Vote> {
        if !self.safety.can_sign() {
            return None;
        }
        let prev_hc_locked = self.hc.locked;
        self.install_committee_schedule();
        self.hc.try_prevote_quorum_at();
        let Some((qc_round, target)) = self.hc.best_polka() else {
            self.hc.locked = self
                .safety
                .locked()
                .map(|l| (l.block_hash, l.round))
                .or(prev_hc_locked);
            return None;
        };
        let Some(qc) = self.hc.prevote_qc.get(&qc_round).cloned() else {
            self.hc.locked = self
                .safety
                .locked()
                .map(|l| (l.block_hash, l.round))
                .or(prev_hc_locked);
            return None;
        };
        if qc.block_hash != Some(target) {
            self.hc.locked = self
                .safety
                .locked()
                .map(|l| (l.block_hash, l.round))
                .or(prev_hc_locked);
            return None;
        }
        // Require the full validated block body before locking or signing
        // (no hash-only locks, `05_LOCK_SAFETY_P0.md` §2.3 Step 1).
        let Some(polka_block) = self.blocks.get(&target).cloned() else {
            self.hc.locked = self
                .safety
                .locked()
                .map(|l| (l.block_hash, l.round))
                .or(prev_hc_locked);
            return None;
        };
        if polka_block.height != self.hc.height || polka_block.compute_hash() != target {
            self.hc.locked = self
                .safety
                .locked()
                .map(|l| (l.block_hash, l.round))
                .or(prev_hc_locked);
            return None;
        }
        let value_id = polka_block.value_id();
        // Enforce any in-memory lock still held on `self.hc.locked` (e.g.
        // unit tests that seed `hc.locked` directly) in addition to `SafetyAuthority`.
        if let Some((locked_block, locked_round)) = self.hc.locked {
            if !self.hc.same_value(locked_block, target) && qc_round <= locked_round {
                return None;
            }
        }

        let validators = self.validator_set_for_height(self.hc.height);
        let schedule = self.hc.committee_schedule;
        let req = crate::remote_signer::ConsensusSignRequest::Vote {
            chain_id: crate::consensus::consensus_chain_id(),
            shard_id: self.shard_id,
            height: self.hc.height,
            round: qc_round,
            kind: crate::consensus::VoteKind::Precommit,
            block_hash: Some(target),
        };
        let res = {
            let signer = self.vote_signer_for(req);
            self.safety.authorize_and_sign_precommit(
                self.hc.height,
                qc_round,
                self.shard_id,
                &polka_block,
                &qc,
                &validators,
                schedule,
                &signer,
            )
        };

        match res {
            Ok((vote, next_locked)) => {
                self.hc.note_value_id(target, value_id);
                if let Some(nl) = next_locked {
                    if self.hc.locked.is_none_or(|(_, round)| nl.round > round) {
                        self.hc.locked = Some((nl.block_hash, nl.round));
                    }
                }
                Some(vote)
            }
            Err(crate::safety::SafetyRefusal::CrossKindConflict(_)) => {
                // Liveness recovery without weakening safety (§1.6.1): adopt the
                // verified polka lock durably so subsequent rounds re-stamp and
                // prevote the locked value instead of proposing fresh conflicting
                // blocks, while refusing to sign a precommit at `qc_round`.
                match self.safety.record_polka_lock_transition(
                    self.hc.height,
                    qc_round,
                    &polka_block,
                    &qc,
                    &validators,
                    schedule,
                ) {
                    Ok(Some(nl)) => {
                        self.hc.note_value_id(target, value_id);
                        if self.hc.locked.is_none_or(|(_, round)| nl.round > round) {
                            self.hc.locked = Some((nl.block_hash, nl.round));
                        }
                    }
                    Ok(None) | Err(_) => {
                        self.hc.locked = self
                            .safety
                            .locked()
                            .map(|l| (l.block_hash, l.round))
                            .or(prev_hc_locked);
                    }
                }
                None
            }
            Err(crate::safety::SafetyRefusal::SignerFailed) => {
                // Non-rollback on ambiguous signer failure (§2.3 Step C): sync
                // `hc.locked` to the durably persisted lock and return `None`.
                if let Some(nl) = self.safety.locked() {
                    self.hc.note_value_id(nl.block_hash, nl.value_id);
                    self.hc.locked = Some((nl.block_hash, nl.round));
                }
                None
            }
            Err(_) => {
                self.hc.locked = self
                    .safety
                    .locked()
                    .map(|l| (l.block_hash, l.round))
                    .or(prev_hc_locked);
                None
            }
        }
    }

    pub fn on_precommit(&mut self, v: Vote) -> Result<(), String> {
        let _phase = phase_timer("on_precommit");
        // SHARD SCOPE — same rule as `on_prevote`.
        if v.shard_id != self.shard_id {
            return Err(format!(
                "precommit from shard {} (this node serves shard {})",
                v.shard_id, self.shard_id
            ));
        }
        // Late-precommit enrichment for the already-decided parent height H-1
        // (both during `apply_in_flight` and after advancing to H): admits into
        // `decided_parent_votes.votes` ONLY so `Block.last_qc` includes slower
        // honest validators without mutating `hc`, `safety`, or floors.
        let _ = self.try_admit_late_parent_precommit(&v);
        let res = self.hc.add_precommit(v.clone());
        // V-P34 (R1 verification gap): the round chase MUST be gated on
        // verification here, exactly as on the prevote path.
        // `observe_peer_vote` returns true only for a verified member vote
        // (signature + membership + same height); an unverified precommit —
        // forged signature or non-member voter — previously ran
        // `note_peer_vote_round` unconditionally and bought +8 per fresh
        // round with zero keys. The gate preserves the documented behavior
        // for verified votes (a far-ahead verified vote still syncs,
        // bounded) while forged votes move nothing.
        if self.observe_peer_vote(&v) {
            // FUTURE ROUND RULE: see `on_prevote`.
            self.note_peer_vote_round_for(v.height, v.round, v.block_hash);
        }
        res
    }

    /// Whether the validator set is currently refused as STALE (fail-closed
    /// observer mode: the node follows and validates but must NOT vote).
    pub fn is_validator_set_stale(&self) -> bool {
        self.validator_set_stale
    }

    /// Human-readable stale reason, if any (see [`Self::is_validator_set_stale`]).
    pub fn validator_set_stale_reason(&self) -> Option<&str> {
        self.validator_set_stale_reason.as_deref()
    }

    /// Effective franchise: the static config flag AND ledger membership, MINUS
    /// the stale gate. A node with a stale ledger is an observer even if its
    /// key is in the (foreign) set — voting with a foreign set is exactly the
    /// node-C failure (silent wrong quorums instead of an honest observer).
    pub fn effective_can_vote(&self, config_is_validator: bool) -> bool {
        if self.validator_set_stale || !self.safety.can_sign() {
            return false;
        }
        config_is_validator || self.validators.validators.contains_key(&self.id)
    }

    /// Mark the set STALE (fail-closed to observer). LOUD on both channels;
    /// records both heights so the operator sees how far the ledger lags.
    pub fn mark_validator_set_stale(
        &mut self,
        state_height: u64,
        ledger_height: u64,
        reason: String,
    ) {
        self.validator_set_stale = true;
        self.validator_set_stale_reason = Some(reason.clone());
        self.validator_set_state_height = Some(state_height);
        self.validator_set_ledger_height = Some(ledger_height);
        tracing::warn!(
            "[validator-set] WARN stale validator set at state {state_height} (ledger {ledger_height}): {reason} — fail-closed to observer (no votes) until a fresh ledger arrives"
        );
        eprintln!(
            "[validator-set] WARN stale validator set at state {state_height} (ledger {ledger_height}): {reason} — fail-closed to observer (no votes) until a fresh ledger arrives"
        );
    }

    /// Clear the stale gate after a FRESH set was installed or verified.
    pub fn clear_validator_set_stale(&mut self) {
        self.validator_set_stale = false;
        self.validator_set_stale_reason = None;
    }

    /// Re-entry hysteresis sweep: LOUD-warn every member the derived set
    /// GAINS over the previous set, count it, watch it for liveness, and
    /// re-WARN watched re-entrants that still show no votes after N heights.
    ///
    /// ADDITIVE LOGGING ONLY — no logic change: the derived set the caller
    /// installs is never filtered, reordered or refused here. Both channels
    /// (tracing + stderr) because an offline re-entrant in a micro-quorum is
    /// a chain-halt precursor and must be unmissable.
    ///
    /// Liveness signal: the ledger's QC-derived `missed` streak (same
    /// evidence the downtime slasher uses — block content, identical on every
    /// node), via [`crate::staking::reentry_liveness_risk`]. A watched member
    /// leaves the watch when it drops out of the derived set again or its
    /// streak is forgiven (`missed == 0`, i.e. it signed a certificate).
    pub(super) fn note_validator_set_gains(
        &mut self,
        derived: &crate::consensus::ValidatorSet,
        ledger: &crate::staking::StakingLedger,
    ) {
        let height = self.hc.height;
        // Snapshot the pre-existing watch BEFORE inserting this refresh's
        // gains: a member gained right now has a clean `missed` streak (it
        // could not miss certificates while unelected), so sweeping it in the
        // same pass would instantly unwatch it and the liveness watch would
        // never hold a fresh re-entrant.
        let watched: Vec<(ValidatorId, u64)> =
            self.reentry_watch.iter().map(|(m, h)| (*m, *h)).collect();
        for (member, power) in crate::staking::validator_set_gains(&self.validators, derived) {
            let msg = crate::staking::reentry_warn_message_for(&member, power, height);
            tracing::warn!("{msg}");
            eprintln!("{msg}");
            self.validator_reentry_warns_total =
                self.validator_reentry_warns_total.saturating_add(1);
            self.reentry_watch.insert(member, height);
        }
        let mut unwatched: Vec<ValidatorId> = Vec::new();
        for (member, rejoined_at) in &watched {
            let power = derived.validators.get(member).copied().unwrap_or(0);
            if power == 0 {
                // Re-ejected (or never installed): stop watching silently.
                unwatched.push(*member);
                continue;
            }
            let missed = ledger.validators.get(member).map(|v| v.missed).unwrap_or(0);
            if missed == 0 {
                // Signed a certificate since rejoining: healthy, stop watching.
                unwatched.push(*member);
                continue;
            }
            if crate::staking::reentry_liveness_risk(*rejoined_at, height, missed)
                && height.saturating_sub(*rejoined_at) % 10 == 0
            {
                let msg = crate::staking::reentry_liveness_warn_message_for(
                    member,
                    power,
                    *rejoined_at,
                    height,
                    missed,
                );
                tracing::warn!("{msg}");
                eprintln!("{msg}");
            }
        }
        for m in unwatched {
            self.reentry_watch.remove(&m);
        }
    }

    /// Core installer used by every refresh path: freshness-gated set install
    /// from an explicit ledger with explicit heights.
    ///
    /// * STALE (`ledger_height` lags `state_height` beyond
    ///   [`crate::storage::validator_set_freshness_max_lag`]): LOUD warn,
    ///   stale flag set, set NOT installed, returns `false`. The caller keeps
    ///   its old set for READS but must not vote (see
    ///   [`Self::effective_can_vote`]).
    /// * FRESH: derives the set from `ledger`; installs on change (with the
    ///   usual before/after warn), clears the stale flag, returns whether the
    ///   set changed. Empty stays a no-op (pre-bond network keeps its config
    ///   set), exactly like [`Self::refresh_validator_set_from_staking`].
    pub async fn refresh_validator_set_from_ledger(
        &mut self,
        ledger: &crate::staking::StakingLedger,
        state_height: u64,
        ledger_height: u64,
    ) -> bool {
        if let Err(reason) =
            crate::storage::check_validator_set_freshness(state_height, ledger_height)
        {
            self.mark_validator_set_stale(state_height, ledger_height, reason);
            return false;
        }
        // Boot / snapshot restore at an already-finalized tip (`state_height < hc.height`,
        // e.g. `TIP` while `hc.height == TIP + 1`) with no prior history in memory and
        // a unit-power config bootstrap placeholder in `self.validators`:
        // Do NOT record `(0, config_set)` as if the boot placeholder governed `0..=TIP`.
        // Seed `(ledger_height, vs)` as the authoritative bonded set covering `state_height`
        // (`TIP`) so `validator_set_for_height(TIP)` and `validator_set_for_height_strict(TIP)`
        // attribute the tip's own QC instead of falling back to the 4x1 config set, while
        // `validator_set_for_height_strict(h)` for `h < ledger_height` still fails closed (`None`).
        let is_unit_power_config =
            !self.validators.is_empty() && self.validators.validators.values().all(|&p| p == 1);
        if self.validator_set_history.is_empty()
            && state_height > 0
            && state_height < self.hc.height
            && ledger_height <= state_height
            && self.finalized.len() <= 1
            && is_unit_power_config
        {
            let vs = ledger.to_validator_set();
            if !vs.is_empty() && vs.validators.values().any(|&p| p > 1) {
                self.validator_set_history.push_back((ledger_height, vs));
            }
        }
        self.install_validator_set_from_ledger(
            ledger,
            state_height,
            ledger_height,
            crate::sharding::validator_set_adoption_height(ledger_height),
        )
        .await
    }

    /// Install the validator set derived from `ledger` (already known to be
    /// acceptable) into the runtime AND the height consensus.
    ///
    /// W10.5 ACTIVATION BOUNDARY: the STAGED set becomes the in-force
    /// consensus set only when the node reaches `activation`
    /// ([`Self::install_due_validator_set`], called on every finalize/adopt
    /// advance and after every refresh), never mid-flight. The boundary itself
    /// is supplied by the caller because it is NOT always `ledger_height + 1`
    /// in this node's own height space:
    ///
    ///  * the MASTERCHAIN (and every single-chain node) derives it from its own
    ///    ledger: `validator_set_adoption_height(ledger_height)`;
    ///  * a WORKCHAIN derives it from the masterchain stamp of the derived set
    ///    (see [`super::MasterSetStamp`]) — the masterchain's own
    ///    activation height for that rotation, identical on every node.
    ///
    /// Staging at a boundary derived from the *workchain's* tip was the
    /// rotation wedge: two shards that observed the same masterchain rotation
    /// at different local heights staged it at different heights, disagreed
    /// about the proposer and never advanced again. The caller-supplied
    /// boundary is a pure function of the chain that adopted the rotation.
    ///
    /// MASTERCHAIN AUTHORITY: when this runtime IS the masterchain, the same
    /// call publishes the stamp a workchain binds to (see
    /// [`publish_master_set_stamp`]), keyed by the derived set's fingerprint.
    /// Publishing here — on the masterchain's own set-install path, which runs
    /// on apply, restore and repair — is what makes the datum a property of
    /// the masterchain block that adopted the rotation instead of a local
    /// observation of it.
    ///
    /// Split out of [`Self::refresh_validator_set_from_ledger`] so the
    /// masterchain-registry path (a workchain reading the masterchain's
    /// ledger) can install a set WITHOUT the cross-chain height comparison
    /// the local path needs: the workchain's height and the masterchain's
    /// height are different chains, so comparing them is meaningless.
    ///
    /// Empty stays a no-op: a registry nobody has met the minimum bond in
    /// keeps the config-defined set (the pre-bond network behaviour).
    pub(super) async fn install_validator_set_from_ledger(
        &mut self,
        ledger: &crate::staking::StakingLedger,
        state_height: u64,
        ledger_height: u64,
        activation: u64,
    ) -> bool {
        let vs = ledger.to_validator_set();
        // MASTERCHAIN: publish the deterministic datum BEFORE any early return,
        // so an unchanged set also (re)publishes/keeps its stamp. The boundary
        // published for a set that is ALREADY in force is the one recorded when
        // it took effect (`validator_set_history`), never the current height:
        // re-dating a live set on every refresh would make the workchain's
        // adoption height depend on when the masterchain last refreshed.
        if self.shard_id == crate::sharding::MASTERCHAIN_SHARD {
            let published_activation = if vs.validators == self.validators.validators {
                if self.validator_set_history.is_empty() {
                    // The set this runtime was CONSTRUCTED with is in force
                    // from genesis; that is its true boundary.
                    0
                } else {
                    self.validator_set_history
                        .iter()
                        .rev()
                        .find(|(_, set)| set.validators == vs.validators)
                        .map(|(h, _)| *h)
                        // Not in the bounded history: publish the conservative
                        // (later) boundary rather than an early one.
                        .unwrap_or_else(|| workchain_set_activation_height(ledger_height))
                }
            } else {
                // A rotation: the masterchain's own W10.5 boundary for the
                // ledger height it derived the new set at.
                workchain_set_activation_height(ledger_height)
            };
            publish_master_set_stamp(
                &self.state.staking_handle(),
                set_fingerprint(&vs),
                published_activation,
            );
        }
        // Re-entry hysteresis (local policy + visibility ONLY — the derived
        // set `vs` below is installed or compared verbatim, never filtered).
        // урок валидатора C: an ejected-then-topped-up validator silently
        // rejoined while offline and halted a micro-quorum. Every gain gets a
        // LOUD warn + counter + liveness watch; watched re-entrants with no
        // votes for N heights get a repeating liveness-risk WARN.
        self.note_validator_set_gains(&vs, ledger);
        if vs.is_empty() || vs.validators == self.validators.validators {
            // Fresh ledger that changes nothing proves we are NOT stale.
            // A staged pending set for the same content is redundant: drop
            // it so a flapping refresh cannot resurrect an older derivation.
            if let Some((_, ref pending)) = self.pending_validators {
                if pending.validators == vs.validators {
                    self.pending_validators = None;
                }
            }
            self.clear_validator_set_stale();
            self.validator_set_state_height = Some(state_height);
            self.validator_set_ledger_height = Some(ledger_height);
            // The in-force set is unchanged, but a due pending set (staged by
            // an earlier derivation) may now be installable at this height.
            self.install_due_validator_set();
            return false;
        }
        // IDEMPOTENCE (repair-timer contract): the exact transition
        // `(activation, vs)` is already staged. Re-staging it would re-WARN on
        // every timer tick without changing anything, so only refresh the
        // freshness bookkeeping and let `install_due_validator_set` install it
        // if the boundary has arrived. Never re-stage a set already in force:
        // that case is the unchanged-set branch above.
        if matches!(
            &self.pending_validators,
            Some((staged_at, staged)) if *staged_at == activation && staged.validators == vs.validators
        ) {
            self.clear_validator_set_stale();
            self.validator_set_state_height = Some(state_height);
            self.validator_set_ledger_height = Some(ledger_height);
            self.install_due_validator_set();
            return false;
        }
        let fmt = |m: &std::collections::BTreeMap<ValidatorId, u64>| {
            m.iter()
                .map(|(k, p)| format!("{}:{}", hex::encode(&k[..4]), p))
                .collect::<Vec<_>>()
                .join(",")
        };
        tracing::warn!(
            "validator set change staged at ledger height {} (activation {}): [{}] -> [{}]",
            ledger_height,
            activation,
            fmt(&self.validators.validators),
            fmt(&vs.validators),
        );
        eprintln!(
            "[validator-set] shard {} staged a validator-set change at ledger height {} (in force from height {}): [{}] -> [{}]",
            self.shard_id,
            ledger_height,
            activation,
            fmt(&self.validators.validators),
            fmt(&vs.validators),
        );
        self.pending_validators = Some((activation, vs));
        self.clear_validator_set_stale();
        self.validator_set_state_height = Some(state_height);
        self.validator_set_ledger_height = Some(ledger_height);
        // A staged change whose activation is already reached (restore /
        // repair paths that derive from an old ledger while the consensus
        // height already moved past it) installs immediately: the network is
        // already voting that set, and running the previous one would fork.
        self.install_due_validator_set();
        true
    }

    /// Install the staged validator-set change if its activation height has
    /// been reached.
    ///
    /// Called after every refresh (covers restore/repair derivations whose
    /// activation is already due) and on every height advance (finalize,
    /// sequenced-apply completion, adopt): the set staged for H+1 becomes
    /// in-force exactly when the node moves to H+1. Returns true when a new
    /// set took effect.
    pub fn install_due_validator_set(&mut self) -> bool {
        let due = matches!(&self.pending_validators, Some((activation, _)) if *activation <= self.hc.height);
        if !due {
            return false;
        }
        let (activation, vs) = self.pending_validators.take().expect("checked above");
        // First install of this process: also record the set being superseded
        // as in force since height 0. Without it, `validator_set_for_height`
        // has no answer for heights below the first recorded activation and
        // falls back to the NEW set — which would verify PRE-change
        // certificates against post-change powers (fail-OPEN for ancient
        // windows). The superseded entry makes those heights verify against
        // the pre-change set instead (fail-CLOSED: a newer set may refuse an
        // ancient QC, never accept a quorum that was not one). Heights at or
        // above the first recorded activation are exact either way.
        if self.validator_set_history.is_empty() {
            self.validator_set_history
                .push_back((0, self.validators.clone()));
        }
        let fmt = |m: &std::collections::BTreeMap<ValidatorId, u64>| {
            m.iter()
                .map(|(k, p)| format!("{}:{}", hex::encode(&k[..4]), p))
                .collect::<Vec<_>>()
                .join(",")
        };
        tracing::warn!(
            "validator set activated at height {}: [{}] -> [{}]",
            activation,
            fmt(&self.validators.validators),
            fmt(&vs.validators),
        );
        eprintln!(
            "[validator-set] shard {} ACTIVATED the staged set at height {}: [{}] -> [{}]",
            self.shard_id,
            activation,
            fmt(&self.validators.validators),
            fmt(&vs.validators),
        );
        self.validators = vs.clone();
        self.hc.validators = vs.clone();
        if self
            .validator_set_history
            .back()
            .is_none_or(|(_, cur)| cur.validators != vs.validators)
        {
            self.validator_set_history.push_back((activation, vs));
            while self.validator_set_history.len() > VALIDATOR_SET_HISTORY_CAP {
                self.validator_set_history.pop_front();
            }
        }
        true
    }

    /// Re-align the consensus-local validator set with the runtime's in-force
    /// set when they diverged without a height advance.
    ///
    /// INVARIANT: `hc.validators` is the in-force set for `hc.height`; it is
    /// rebuilt from `validators` on every height advance and mirrored by
    /// [`Self::install_due_validator_set`]. That covers every path that moves
    /// heights — but a refresh can move `validators` WITHOUT moving heights
    /// (restore from a lagging domains snapshot, then a live-ledger refresh
    /// that derives a newer set; or the reverse order). The consensus copy
    /// then strands on the older set: this node computes a different
    /// proposer schedule from peers that derived the same newer set, rejects
    /// their proposals as "wrong proposer", and no height ever advances to
    /// heal it (observed live: post-restart wedge at #388561, B on the
    /// post-change set vs C/D on the pre-change one, zero finality until the
    /// copies realigned).
    ///
    /// The runtime set is strictly fresher-or-equal here: every path that
    /// assigns `validators` derives it from a ledger at least as new as the
    /// consensus copy's basis (the copy is only ever written from
    /// `validators` itself — construction, height advance, install-due — so
    /// it cannot run ahead). Syncing the copy forward therefore completes an
    /// already-decided transition; it never reverts one. A staged future
    /// change is untouched: when its activation arrives,
    /// `install_due_validator_set` installs the same values (a no-op content
    /// change plus the history entry).
    ///
    /// Called from the periodic set-repair timer (no height advance needed).
    /// Returns true when a resync happened. LOUD: a resync means this node
    /// was voting a stale schedule.
    pub fn resync_consensus_set_to_runtime(&mut self) -> bool {
        if self.hc.validators.validators == self.validators.validators {
            return false;
        }
        let fmt = |m: &std::collections::BTreeMap<ValidatorId, u64>| {
            m.iter()
                .map(|(k, p)| format!("{}:{}", hex::encode(&k[..4]), p))
                .collect::<Vec<_>>()
                .join(",")
        };
        tracing::warn!(
            "validator-set resync at height {}: consensus copy [{}] -> runtime in-force [{}]",
            self.hc.height,
            fmt(&self.hc.validators.validators),
            fmt(&self.validators.validators),
        );
        eprintln!(
            "[validator-set] shard {} resync at height {}: consensus copy [{}] -> runtime in-force [{}]",
            self.shard_id,
            self.hc.height,
            fmt(&self.hc.validators.validators),
            fmt(&self.validators.validators),
        );
        self.hc.validators = self.validators.clone();
        true
    }

    /// The validator set IN FORCE at height `h`: the newest set whose
    /// activation height is at most `h`.
    ///
    /// W10.5: every quorum check for a certificate at height H — local
    /// decide, adopt, sync-chain verify, light-client anchor, replay, and the
    /// downtime-attribution gate — MUST use this, never the live set. A set
    /// change takes effect at a clean H+1 boundary on every node, so the set
    /// in force at H is a pure function of the chain (the prefix finalized
    /// before H), not of when this node happened to refresh.
    ///
    /// Heights at/above the current consensus height use the live in-force
    /// set; older heights walk the activation history. When the history does
    /// not reach back far enough (a change predates this process's start and
    /// no entry covers `h`), the OLDEST known set is returned: it is the
    /// current set, which is correct for every height since the last change —
    /// and a change older than the history can only make this conservative
    /// (verify against a newer set may refuse an ancient QC, never accept a
    /// quorum that was not one).
    pub fn validator_set_for_height(&self, h: u64) -> ValidatorSet {
        let mut best: Option<(u64, &ValidatorSet)> = None;
        for (activation, vs) in &self.validator_set_history {
            if *activation <= h {
                best = Some((*activation, vs));
            }
        }
        // A staged change already answers for heights at/above its
        // activation, even before the node advances there: the switch is
        // pre-agreed, not speculative.
        if let Some((activation, pending)) = &self.pending_validators {
            if *activation <= h && best.is_none_or(|(b_act, _)| *activation >= b_act) {
                return pending.clone();
            }
        }
        if h >= self.hc.height
            && self
                .validator_set_history
                .back()
                .is_none_or(|(last_act, _)| *last_act <= self.hc.height)
        {
            return self.validators.clone();
        }
        best.map(|(_, vs)| vs.clone()).unwrap_or_else(|| {
            self.validator_set_history
                .front()
                .map(|(_, vs)| vs.clone())
                .unwrap_or_else(|| self.validators.clone())
        })
    }

    /// Strict per-height validator-set resolver for snapshot anchor and sync
    /// verification (`P0-PEER-SNAPSHOT-ANCHOR`).
    ///
    /// Unlike [`Self::validator_set_for_height`], this NEVER silently
    /// substitutes a neighboring/oldest history entry when `h` predates the
    /// earliest recorded activation in `validator_set_history`, and refuses
    /// (`None`) whenever the runtime's validator set is marked stale.
    pub fn validator_set_for_height_strict(&self, h: u64) -> Option<ValidatorSet> {
        if self.validator_set_stale {
            return None;
        }
        let mut best: Option<(u64, &ValidatorSet)> = None;
        for (activation, vs) in &self.validator_set_history {
            if *activation <= h {
                best = Some((*activation, vs));
            }
        }
        if let Some((activation, pending)) = &self.pending_validators {
            if *activation <= h && best.is_none_or(|(b_act, _)| *activation >= b_act) {
                return Some(pending.clone());
            }
        }
        if h >= self.hc.height
            && self
                .validator_set_history
                .back()
                .is_none_or(|(last_act, _)| *last_act <= self.hc.height)
        {
            return Some(self.validators.clone());
        }
        if self.validator_set_history.is_empty() {
            return Some(self.validators.clone());
        }
        best.map(|(_, vs)| vs.clone())
    }

    /// Snapshot of the ordered `(activation_height, ValidatorSet)` history for
    /// durable persistence in [`crate::storage::Storage`].
    pub fn export_validator_set_history(&self) -> Vec<(u64, ValidatorSet)> {
        self.validator_set_history.iter().cloned().collect()
    }

    /// Restore a previously persisted `(activation_height, ValidatorSet)`
    /// history into the runtime (bounded by [`VALIDATOR_SET_HISTORY_CAP`]).
    ///
    /// Aligns `self.validators` and `self.hc.validators` to the newest entry
    /// with `activation <= self.hc.height` if one exists.
    pub fn restore_validator_set_history(&mut self, mut history: Vec<(u64, ValidatorSet)>) {
        history.sort_by_key(|(h, _)| *h);
        history.dedup_by(|a, b| a.0 == b.0 && a.1.validators == b.1.validators);
        if history.len() > VALIDATOR_SET_HISTORY_CAP {
            let drain = history.len() - VALIDATOR_SET_HISTORY_CAP;
            history.drain(..drain);
        }
        self.validator_set_history = history.into_iter().collect();
        if let Some((_, in_force)) = self
            .validator_set_history
            .iter()
            .rev()
            .find(|(act, _)| *act <= self.hc.height)
        {
            self.validators = in_force.clone();
            self.hc.validators = in_force.clone();
        }
    }

    /// Install a validator set derived from the MASTERCHAIN's staking ledger.
    ///
    /// This is the workchain path: the masterchain owns the staking registry
    /// (bond / unbond / slash are masterchain transactions) and the workchain
    /// has none of its own, so the workchain's consensus set is derived from
    /// the master's ledger, shared process-wide through
    /// [`Self::master_staking`].
    ///
    /// DETERMINISTIC ACTIVATION: the set is bound to the masterchain's
    /// published [`super::MasterSetStamp`] — the masterchain height
    /// at which the block that adopted the rotation was finalized, expressed as
    /// that rotation's `master ledger height + 1` (see
    /// [`super::workchain_set_activation_height`]). The workchain
    /// does NOT use its own tip to date the rotation: the stamp is a property
    /// of the rotation, so two workchains at different local heights stage it
    /// at the SAME activation height.
    ///
    /// FAIL CLOSED: when the derived set has no matching stamp (the
    /// masterchain never published one for this content, or the shared ledger
    /// already moved past the last published set), this node cannot prove
    /// which masterchain block defined the set. It then arms the stale gate
    /// (observer, no votes — see [`Self::effective_can_vote`]) and stages
    /// NOTHING rather than inventing a boundary. Guessing `tip + 1` here is
    /// exactly the per-shard divergence ("wrong proposer", no finality) this
    /// binding removes.
    ///
    /// NO cross-chain height comparison: the two heights belong to DIFFERENT
    /// chains (the workchain's and the masterchain's), so the freshness gate
    /// of [`Self::refresh_validator_set_from_ledger`] does not apply. What that
    /// gate protects against, a restored ledger that lags the state by more
    /// than the snapshot window, is the masterchain runtime's own business: it
    /// is the one that restores the ledger and the one that knows whether it is
    /// fresh (see [`Self::refresh_validator_set_from_staking_checked`] on the
    /// masterchain side, and the fail-closed observer mode it arms).
    ///
    /// The shared ledger is written by the masterchain runtime under the SAME
    /// lock this read takes, so the read is atomic and never torn: the
    /// workchain installs either the pre-rotation or the post-rotation set,
    /// never a mixture. The stamp is bound to the snapshot by the set's
    /// CONTENT fingerprint, so a ledger that changed after the masterchain
    /// last derived it cannot pair with the older stamp.
    pub async fn refresh_validator_set_from_master_ledger(
        &mut self,
        ledger: &crate::staking::StakingLedger,
    ) -> bool {
        let Some(master) = self.master_staking.clone() else {
            self.mark_validator_set_stale(
                self.hc.height,
                self.hc.height,
                "masterchain set activation unavailable: no master ledger handle wired".to_string(),
            );
            return false;
        };
        let derived = ledger.to_validator_set();
        if derived.is_empty() {
            // Nobody bonded on the masterchain (yet): the config-defined set
            // stays in force, and there is no rotation to date.
            return false;
        }
        let fingerprint = set_fingerprint(&derived);
        let Some(stamp) = master_set_stamp(&master).filter(|s| s.set_fingerprint == fingerprint)
        else {
            self.mark_validator_set_stale(
                self.hc.height,
                self.hc.height,
                format!(
                    "masterchain set {} has no published activation stamp: cannot prove which masterchain block defined it (fail-closed observer, no votes)",
                    hex::encode(&fingerprint[..8])
                ),
            );
            return false;
        };
        // The stamp carries the masterchain's activation boundary. The
        // freshness bookkeeping stays in WORKCHAIN height space (this node's
        // state and its own (empty) registry are what it describes); the
        // cross-chain datum lives in the activation height.
        self.install_validator_set_from_ledger(
            ledger,
            self.hc.height,
            self.hc.height,
            stamp.activation_height,
        )
        .await
    }

    /// The MASTERCHAIN registry, when this runtime must take its consensus
    /// set from it.
    ///
    /// `Some` only for a WORKCHAIN with the shared handle wired and a
    /// registry that holds a set: the masterchain owns the staking registry,
    /// and a workchain's own ledger is empty by design, so deriving the set
    /// from it froze the workchain on the config-defined set for the whole
    /// life of the process (the audit's "validator set gap").
    ///
    /// An empty master registry (nobody bonded yet) yields `None`: the
    /// config-defined set is kept, exactly as before.
    pub(super) async fn master_registry(&self) -> Option<crate::staking::StakingLedger> {
        if !ValidatorSetSource::for_shard(self.shard_id).uses_masterchain() {
            return None;
        }
        let master = self.master_staking.as_ref()?;
        let ledger = master.read().await.clone();
        if ledger.to_validator_set().is_empty() {
            return None;
        }
        Some(ledger)
    }

    /// Checked refresh from the live engine ledger with explicit heights.
    ///
    /// Restore / snapshot-refresh paths MUST call this (not the unchecked
    /// [`Self::refresh_validator_set_from_staking`]): it compares the ledger
    /// height against the state height and fail-closed to observer on
    /// staleness instead of silently installing a foreign set.
    ///
    /// A WORKCHAIN has no ledger of its own to be stale about: its set comes
    /// from the masterchain's registry (see [`Self::master_staking`]), whose
    /// freshness is the masterchain runtime's own business. The cross-chain
    /// height comparison is therefore skipped for it, because the workchain's
    /// height and the masterchain's height belong to different chains and
    /// comparing them would refuse a perfectly fresh set.
    pub async fn refresh_validator_set_from_staking_checked(
        &mut self,
        state_height: u64,
        ledger_height: u64,
    ) -> bool {
        if let Some(ledger) = self.master_registry().await {
            return self.refresh_validator_set_from_master_ledger(&ledger).await;
        }
        let ledger = self.state.staking_read().await.clone();
        self.refresh_validator_set_from_ledger(&ledger, state_height, ledger_height)
            .await
    }

    /// Refresh the set from FRESH domain-snapshot bytes fetched separately
    /// from blocks (the lagging-node repair path).
    ///
    /// Decodes `domain_bytes` (V0/V1 via
    /// [`crate::storage::decode_domain_snapshot`]) and installs its staking
    /// ledger through [`Self::refresh_validator_set_from_ledger`] with the
    /// snapshot's height as `ledger_height` and the node's current state
    /// height as `state_height`. Undecodable bytes are a loud `Err` and never
    /// touch the set. This is how a node whose bond predates every walkable
    /// body pulls the CURRENT set without replaying ancient history.
    ///
    /// A WORKCHAIN ignores its own snapshot's registry: the staking registry
    /// lives on the masterchain, so the masterchain's ledger is the only
    /// source of the consensus set (a workchain-local snapshot could never
    /// define who the workchain's validators are).
    pub async fn refresh_validator_set_from_domain_bytes(
        &mut self,
        domain_bytes: &[u8],
        state_height: u64,
        ledger_height: u64,
    ) -> Result<bool, String> {
        if let Some(ledger) = self.master_registry().await {
            return Ok(self.refresh_validator_set_from_master_ledger(&ledger).await);
        }
        let snap = crate::storage::decode_domain_snapshot(domain_bytes).map_err(|e| {
            format!("validator-set refresh: domain snapshot at {ledger_height} undecodable: {e}")
        })?;
        Ok(self
            .refresh_validator_set_from_ledger(&snap.staking, state_height, ledger_height)
            .await)
    }

    /// Recompute the validator set (and voting power) from the staking ledger.
    ///
    /// Reads the ledger out of the **state engine**, not from a node-local copy:
    /// consensus has to be a function of the block, otherwise two nodes that
    /// heard different bond transactions over RPC would derive different
    /// validators and deadlock on disagreeing about who proposes.
    ///
    /// No-op when nobody meets the minimum self-bond, so a network that has
    /// never been bonded keeps using its config-defined set.
    ///
    /// WORKCHAIN: the registry is the MASTERCHAIN's, shared process-wide (see
    /// [`Self::master_staking`]). A masterchain rotation is therefore adopted
    /// here at the rotation's OWN activation boundary — the masterchain height
    /// at which the adopting block was finalized, plus one, carried by the
    /// [`super::MasterSetStamp`] — never at this node's `height + 1`.
    /// Two shards at different local heights therefore switch quorums at the
    /// same agreed height; no node restart, no separate registry to reconcile.
    /// A workchain that cannot obtain the stamp for the derived set fail-closes
    /// to observer instead of guessing (see
    /// [`Self::refresh_validator_set_from_master_ledger`]).
    ///
    /// Apply-path wrapper: the ledger just came out of the transition at the
    /// current height, so state and ledger heights coincide (always fresh).
    /// Restore / snapshot paths must use
    /// [`Self::refresh_validator_set_from_staking_checked`] with real heights
    /// instead, or a stale ledger installs silently (node C).
    pub async fn refresh_validator_set_from_staking(&mut self) -> bool {
        let h = self.hc.height;
        self.refresh_validator_set_from_staking_checked(h, h).await
    }

    /// Periodic workchain validator-set repair (R3 CODE-TAILS sweep).
    ///
    /// Every other refresh site sits on a height-advance path (live finalize,
    /// adopt, walk, snapshot-sync, restore): a workchain that stops finalizing
    /// — the wedged shard-1 state (`wrong proposer` rejects on a diverged set,
    /// no height ever advances) — therefore never re-reads the masterchain
    /// registry and can never converge on its own. This is the one call site
    /// that re-reads the master ledger WITHOUT requiring any height advance:
    /// it routes through [`Self::refresh_validator_set_from_staking`] (so a
    /// workchain with the master handle wired derives from
    /// [`Self::master_registry`], binds the change to the masterchain's
    /// published activation stamp and clears/sets the stale gate exactly like
    /// the finalize path), then installs whatever is due. No-op (`false`,
    /// nothing touched) for the masterchain and single-shard nodes, so the
    /// consensus loop can call it unconditionally on a timer.
    ///
    /// IDEMPOTENT: the installer reports `false` when the derived transition is
    /// already staged for the same activation, or already in force, so a
    /// converged timer tick is silent (no re-stage, no repeated WARN). Note
    /// that the repair does NOT move the height: a rotation whose activation
    /// boundary is already behind the wedged height is installed in place
    /// (`install_due_validator_set`), which is what lets the shard resume
    /// finalizing the height it is stuck on.
    ///
    /// The repair unblocks the wedge transitively: once the CURRENT master set
    /// is staged, the next walk verifies block H+1 against
    /// [`Self::validator_set_for_height`] (which answers pending sets at/above
    /// their activation), applies it, advances, and installs the set due —
    /// the same convergence the finalize path performs, without needing a
    /// finalize to start it. When the masterchain has not published the stamp
    /// for the derived set, the refresh fail-closes (observer, no votes): the
    /// timer keeps retrying until the masterchain's next finalize publishes it,
    /// and never guesses a boundary in the meantime.
    pub async fn refresh_workchain_set_from_master(&mut self) -> bool {
        if !crate::sharding::ValidatorSetSource::for_shard(self.shard_id).uses_masterchain() {
            return false;
        }
        if self.master_staking.is_none() {
            return false;
        }
        let changed = self.refresh_validator_set_from_staking().await;
        self.install_due_validator_set();
        changed
    }

    /// Advance the finalized tip to a snapshot boundary the SYNC layer has
    /// already verified (trusted state root, QC-anchored header proof and
    /// validator-set binding all ran in `try_snapshot_sync`).
    ///
    /// A catch-up jump IS chain progress, so it must stamp the deadlock
    /// breaker's clock (`record_progress`). Without that stamp a node that
    /// spent longer than `deadlock_timeout()` behind read an hours-old "no
    /// finalization" on its very next tick and fired a spurious LOCAL
    /// RE-PHASE — advancing the round it had just rejoined (and skipping its
    /// own scheduled proposal slot) — even though it had just made more
    /// progress than any single finalize would.
    pub fn advance_to_verified_snapshot(&mut self, boundary: u64, boundary_hash: [u8; 32]) {
        self.finalized.push((boundary, boundary_hash));
        if let Err(e) = self
            .safety
            .advance_height(boundary + 1, boundary, boundary_hash)
        {
            tracing::error!(
                boundary,
                error = %e,
                "[safety] snapshot sync advance_height failed; quarantining"
            );
            self.safety
                .quarantine(format!("snapshot_sync advance_height({boundary}): {e}"));
        }
        self.hc = crate::consensus::HeightConsensus::new(boundary + 1, self.validators.clone());
        // The sortition committee of this height is elected from the PARENT
        // block hash — the finalized head we just restored. Every node must
        // use the same parent, or they elect different committees.
        self.hc.set_parent_hash(boundary_hash);
        self.record_progress();
    }

    /// View change: move to the next round.
    pub fn next_round(&mut self) {
        // A parked slot must not survive an unbounded number of view changes;
        // this drops only items that are provably unreplayable (more than one
        // height ahead). Round staleness of a still-targeted height is
        // enforced by `take_parked`'s envelope-round predicate.
        self.prune_stale_parked();
        self.hc.next_round();
    }

    /// Adopt a block a peer reports as committed, once its certificate proves a
    /// real quorum of our own validators signed it.
    ///
    /// This is the catch-up path for a node that fell a round behind: the
    /// certificate is checked against the *local* validator set, so a peer can
    /// only make us apply a block that the network genuinely finalized. A peer
    /// cannot invent one.
    pub async fn adopt_committed(
        &mut self,
        height: u64,
        mut block: Block,
        certificate: crate::consensus::QuorumCertificate,
    ) -> Result<crate::cell::CellHash, String> {
        if self.parallel_exec {
            self.state.set_parallel_exec(true);
        }
        // §7 Phase 2 gate: adopting means executing, and execution is still
        // running for the decided height. The checks below read our root
        // (PRE-H until the worker reports back) and `apply_and_advance` would
        // queue a second apply behind it — for a height we have not advanced
        // past. PARK-AND-REPLAY (liveness): the commit used to be dropped, so
        // the peer had to rebroadcast; it is now parked (one slot, newest
        // wins) and replayed through this same function, fail-closed, when
        // the worker reports.
        if self.apply_in_flight.is_some() {
            self.park_commit(height, block, certificate);
            return Err("committed block parked for replay: apply in flight".to_string());
        }
        // W10.5: verify against the set IN FORCE AT THIS HEIGHT, never the
        // live set. A peer can only make us apply a block the network genuinely
        // finalized — under the quorum rules every node used for this height.
        // (A validator-set change takes effect at a clean H+1 boundary on
        // every node; checking a height-H certificate against today's set
        // accepts quorums H never had and refuses quorums H genuinely reached.)
        let validators = self.validator_set_for_height(height);
        if height != self.hc.height {
            return Err(format!(
                "height mismatch (ours {}, peer {height})",
                self.hc.height
            ));
        }
        if block.height != height {
            return Err("block height does not match the commit".to_string());
        }
        // SHARD SCOPE (PENTEST F-7): adopt is the third entry point that can
        // apply a block, and it must enforce the same rule the proposal path
        // (`check_block_shard_scope`) and the body walk enforce. A quorum can
        // exist for a foreign block in a misconfigured/overlapping set; without
        // this gate that block is applied to THIS shard's state.
        self.check_block_shard_scope(&block)?;
        // SECURITY: the certificate must be a COMMIT certificate. `certificate.kind`
        // was never read, and `QuorumCertificate::verify` signs over the
        // certificate's own fields, so a PREVOTE quorum verified just as well.
        // Prevotes are broadcast in the clear for every round, including rounds
        // that never finalize, so a passive peer could harvest one off the wire,
        // relabel the kind and ship it as proof of finality -- with zero stake of
        // its own. "2/3 saw this block" is not "2/3 committed to it".
        if certificate.kind != crate::consensus::VoteKind::Precommit {
            return Err("commit certificate is not a precommit quorum".to_string());
        }
        // SECURITY: bind the certificate to this height AND round. Both fields are
        // signed, so without this check a quorum harvested at any height or round
        // replayed as a commit for our current height. `height` is already pinned
        // to `self.hc.height` above, so this makes the certificate describe the
        // height it is being used to prove.
        if certificate.height != height {
            return Err(format!(
                "certificate is for height {} not {height}",
                certificate.height
            ));
        }
        // A commit that landed while we already timed out into a later round is
        // still a valid quorum for THIS height — refusing it forced a full
        // catch-up for a one-round skew ("60% of time 1 round apart"). Accept
        // anything within the same lookback the finalizer itself uses, so
        // adoption and finalization agree on what "recent" means.
        //
        // THE "BEHIND" BOUND IS THE SCAN SPAN, NOT THE LOOKBACK (liveness fix,
        // live 2026-10-21: the masterchain parked at height 285027 with a
        // prevote QC and NO precommit QC). The finalizer no longer restricts
        // itself to the recent rounds: a decision that was taken in an OLD
        // round (because the deciding quorum only completed long after the
        // network moved on) is still the decision of THIS height, and the node
        // that was the last one to see it MUST be able to adopt it — that is
        // how it gets the body it is missing. Refusing it here left the node
        // stuck in the "decided but no body" state forever: it could not
        // finalize (no body), it could not vote again (its step is Commit) and
        // it could not adopt the decision the peers kept offering it.
        //
        // The height is already bound above (the certificate must be for
        // `self.hc.height`) and the quorum is verified against our own
        // validator set below, so the round of the decision carries no
        // authority of its own: a height has ONE decision, and this is it.
        //
        // ROUND DIRECTION IS NOT A SAFETY GATE ON THE ADOPT PATH.
        //
        // A certificate here is a VERIFIED PRECOMMIT QUORUM for THIS height and
        // THIS block, and the block is bound to our exact next height and to
        // our finalized parent. That is a DECISION, not a live vote: a height
        // decides once, and adopting it cannot double-finalize (we are at
        // tip+1, the height has not been decided locally) and cannot
        // double-sign (the height advances immediately, so we never vote it).
        // The lock/value check below is the real conflict gate, and the vote
        // watermark remains the hard floor.
        //
        // A FORWARD certificate (its round above our restored round) is the
        // normal catch-up shape after a restart: the node comes back at round
        // 0 (or its watermark floor) while the network decided its next height
        // several rounds in — there are no votes at OUR height to chase,
        // because every peer has already moved on. Refusing it as "forward"
        // left the node depending on a body walk that can fail (pruned/missing
        // bodies) and it never recovered; only a data wipe did. See
        // OPEN_DEFECTS HEIGHT-SPLIT.
        //
        // The remaining bound is ONE-DIRECTIONAL: a certificate from a round
        // absurdly far BELOW our own is stale evidence and is still refused.
        // There is no forward cap to keep: an absurdly high round still has to
        // carry a genuine quorum under the set in force at this height (the
        // verification below), and the proposer slot is attributed under the
        // certificate's own round.
        if certificate.round != self.hc.round {
            let behind = self.hc.round.saturating_sub(certificate.round);
            if behind as u64 > crate::consensus::MAX_SCAN_SPAN as u64 {
                return Err(format!(
                    "certificate is for round {} not {} (scan span {})",
                    certificate.round,
                    self.hc.round,
                    crate::consensus::MAX_SCAN_SPAN
                ));
            }
        }
        let bh = block.compute_hash();
        // Cheap binding check BEFORE the signature loop: `verify` runs one
        // Ed25519 verification per entry and the list is attacker-supplied and
        // uncapped, so checking the cheap thing first avoids an unbounded
        // signature-verification loop driven by one message.
        if certificate.block_hash != Some(bh) {
            return Err("certificate commits to a different block".to_string());
        }
        if certificate.signatures.len() > MAX_COMMIT_CERT_SIGNERS {
            return Err("commit certificate has an implausible number of signers".to_string());
        }
        // HOT-PATH ORDER (observer C, 2026-10-13): every check below is fail-closed,
        // so order changes cost, not safety. The expensive one is `certificate.verify`
        // (one Ed25519 + one Falcon-512 verify per signer on Pure PQ) — run ALL cheap
        // header checks first so a forked/misaddressed commit dies before burning
        // weak-CPU verifier time. Previously the QC verify ran before the linkage
        // checks and every stale commit paid full crypto cost.
        //
        // SECURITY: the proposer must be the one the schedule names for this
        // height/round, not merely a key that signed. Otherwise a peer names an
        // address it controls, and `apply_block_fees_rewards` credits the fees to
        // it with no membership test.
        if Some(block.proposer) != self.expected_proposer_at(&validators, height, certificate.round)
        {
            return Err("committed block's proposer is not the expected proposer".to_string());
        }
        // SIGNED ROUND (ruleset v4, adopt side): the block header commits the
        // round it was SIGNED under, and the certificate commits the round the
        // quorum voted in. Normally they are the same round.
        //
        // A lock-rescue / demanded-rescue re-proposal is the one exception:
        // the verbatim signed body keeps its ORIGINAL round while the network
        // (including us, in the local path) finalizes it at a LATER round. A
        // lagging node must be able to adopt that same certificate, or it can
        // never catch up on a height won through the rescue. The certificate
        // still signs the exact block hash, so the body is bound; only the
        // signed round may be older. A FUTURE signed round is always refused
        // (a body cannot have been proposed after the quorum that adopted it).
        if block.round > certificate.round {
            return Err(format!(
                "committed block round {} does not match certificate round {}",
                block.round, certificate.round
            ));
        }
        // The block must still be a valid extension of what we finalized.
        // Checked here (before any signature loop) so a commit for a forked head
        // is refused on two hash comparisons, not on quorum verification.
        let expected_prev = self.finalized.last().map(|(_, h)| *h).unwrap_or([0u8; 32]);
        if block.prev_hash != expected_prev {
            return Err("committed block does not extend our finalized head".to_string());
        }
        if block.transactions.len() > MAX_BLOCK_TXS {
            return Err("committed block is oversized".to_string());
        }
        let total_gas = block
            .transactions
            .iter()
            .fold(0u64, |acc, t| acc.saturating_add(t.gas_limit));
        if total_gas > MAX_BLOCK_GAS {
            return Err("committed block exceeds the gas limit".to_string());
        }
        // Same wire/proof caps the proposal path (and the packer) enforce.
        Self::check_block_wire_and_proof_caps(&block)?;
        // Same TOTAL cross-shard record cap the proposal path enforces: a
        // quorum-signed block must not be able to smuggle an unbounded
        // `cross_shard_out` through the adopt path.
        if !Self::cross_shard_record_cap_ok(&block) {
            return Err(format!(
                "committed block exceeds the cross-shard record cap ({} > {})",
                block.cross_shard_out.len(),
                crate::xshard2pc::XPC_MAX_CROSS_SHARD_RECORDS_PER_BLOCK
            ));
        }
        // Single proposer signature before the quorum loop: one verify
        // filters forged bodies before paying per-signer QC cost.
        if !self.verify_proposer_sig_cached(&block, &bh, false) {
            return Err("committed block has no valid proposer signature".to_string());
        }
        if !certificate.binds_to_parent(&block.prev_hash) {
            return Err("commit certificate was elected with a different parent block".to_string());
        }
        // ONE attribution pass: `verify_qc_for_height` followed by
        // `validators.qc_signed_power(&certificate)` used to verify every
        // Falcon signature twice (once for the verdict, once for the power).
        // The fused call reaches the SAME verdict and the SAME union-of-
        // verified-signers power in a single pass.
        let (quorum_ok, signed) = self.verify_qc_for_height_with_power(&certificate, &validators);
        if !quorum_ok {
            return Err("commit certificate does not carry a validator quorum".to_string());
        }
        // W10.5 HARDENING (fail LOUD): the power behind the certificate must
        // reach the quorum of the set in force at THIS height — with the
        // numbers attached, not just a boolean. `verify` above already
        // enforces quorum, so this fires only when the two disagree (a bug),
        // or names the exact shortfall for the operator when a peer serves a
        // weak certificate (e.g. a unilateral finalization carrying only the
        // joiner's power after the set already moved on). Either way it is
        // unmissable: error log + metric + refusal.
        {
            let required = validators.quorum_power();
            if signed < required {
                tracing::error!(
                    height,
                    signed,
                    required,
                    total = validators.total_power(),
                    "REFUSING weak commit certificate: carries {signed} of {required} required power (total {}) — unilateral finalization is never adopted",
                    validators.total_power(),
                );
                eprintln!(
                    "[quorum] REFUSING weak commit certificate at height {height}: carries {signed} of {required} required power — unilateral finalization is never adopted"
                );
                crate::metrics::global().inc_weak_qc_refused();
                return Err(format!(
                    "commit certificate carries only {signed} of {required} required power at height {height}"
                ));
            }
        }
        // SECURITY: do not let the adopt path decide a block that contradicts a lock
        // we already took.
        //
        // The lock is taken on a polka at round `locked_round`. A commit
        // certificate for a DIFFERENT block is only acceptable when it comes
        // from a STRICTLY LATER round: that is the proof that the network moved
        // on without us, so the lock is superseded and must be followed (the
        // old `locked_round <= certificate.round` test refused exactly that and
        // partitioned the node from every canonical commit after a single
        // lost vote).
        //
        // A certificate at the SAME round as the lock (or earlier) that names a
        // different block is a genuine safety conflict - two conflicting
        // polkas in one round need more than 1/3 Byzantine power - so it is
        // refused. A certificate for the SAME block is always fine: that is
        // our own lock being confirmed.
        //
        // ROUND-FREE VALUE IDENTITY BEFORE THE LOCK CHECK (ruleset v6): the
        // incoming commit body may be the OTHER signed round of a value this
        // node locked on (the QC carries the round-0 hash, our lock names a
        // later re-stamp). This node need not have held that exact signed body
        // before — the commit is the first place it sees it — so register the
        // identity FIRST. Otherwise `same_value` sees an unknown hash, refuses
        // the commit as conflicting, and the node never adopts the height it
        // already locked (the late-polka liveness shape). Registration is
        // exact: `value_id` is the round-free hash of THIS body, so a genuinely
        // different value still fails the comparison below.
        self.hc.note_value_id(bh, block.value_id());
        if let Some((locked_block, locked_round)) = self.hc.locked {
            // OUR OWN EARLIER PRECOMMIT OUTRANKS A LATER LOCK (ruleset v6
            // liveness). A commit certificate for a round BEFORE our lock can
            // only be adopted when it is our value — unless WE already
            // precommitted exactly this block in that round. Then the
            // certificate merely confirms our own signed statement; the later
            // lock was taken after a higher polka for another value and says
            // nothing about the round that was already committed. Refusing
            // here parked the height on the very nodes whose precommits made
            // the certificate (the late-polka shape: a node unlocks on a
            // higher polka while a valid earlier commit is still in flight).
            // The same-round case stays refused below, a NEWER locally
            // decidable precommit quorum wins (never prefer an older commit
            // over a newer decision this node can already make), and a lock
            // whose value identity matches still adopts without this escape.
            // A hash-only lock (we saw the polka's votes but never its body)
            // has no registered value identity, so `same_value` cannot equate
            // it with the commit body. Rebuild the commit value at the lock's
            // signed round: if its hash is exactly the locked hash, the lock
            // names THIS value at another round. Hash equality proves it; a
            // genuinely different value cannot collide.
            let lock_matches_restamp = self.hc.value_id_of(&locked_block).is_none() && {
                let mut candidate = block.clone();
                candidate.round = locked_round;
                candidate.compute_hash() == locked_block
            };
            let own_precommit = certificate.round < locked_round
                && !self
                    .hc
                    .has_decidable_precommit_quorum_after(certificate.round)
                && self
                    .hc
                    .precommit_set(certificate.round)
                    .and_then(|s| s.vote_by(&self.id))
                    .is_some_and(|v| v.kind == VoteKind::Precommit && v.block_hash == Some(bh));
            // LOCK COMPARISON (ruleset v6, site 7): a re-stamped round of the
            // locked value does not contradict the lock; a different value
            // still does.
            if certificate.round <= locked_round
                && !self.hc.same_value(locked_block, bh)
                && !lock_matches_restamp
                && !own_precommit
            {
                return Err("refusing to adopt a block that contradicts our lock".to_string());
            }
        }
        // PREVOTE-QUORUM CONSISTENCY (parity with `try_precommit_quorum`):
        // the local path refuses to decide a block unless a prevote quorum for
        // the SAME block exists in the same round. The adopt path receives only
        // the precommit QC on the wire, so full parity is IMPOSSIBLE without a
        // wire change: the peer would have to ship a prevote QC for
        // (height, round, block) alongside the commit certificate (new param or
        // envelope field), and we would `verify` it against `self.validators`
        // exactly like the precommit QC above. The signature is deliberately
        // unchanged (main.rs + tests call `adopt_committed(height, block,
        // certificate)`), so what we CAN do soundly is consult `self.hc`'s
        // recorded prevotes for `certificate.round`: if we observed a quorum
        // for a DIFFERENT target (another block, or nil), adopting this block
        // contradicts evidence we already hold and is refused. If we observed
        // nothing -- the normal catching-up node -- the check is VACUOUS and
        // the precommit QC is trusted transitively (honest validators only
        // precommit after a prevote quorum, so 2/3 precommits imply one
        // existed). Residual gap, stated plainly: a Byzantine quorum (or key
        // compromise reaching quorum power) can fabricate precommits for a
        // block nobody prevoted, and a lagging node with empty prevote sets
        // cannot tell; closing it requires the wire change above, not a
        // stricter local check (refusing on empty local prevotes would make
        // catch-up impossible by construction).
        if let Some(set) = self.hc.prevote_set(certificate.round) {
            if let Some(local_target) = set.quorum_target(&validators) {
                if local_target != Some(bh) {
                    return Err("refusing to adopt: our prevote quorum for this round is for a different block".to_string());
                }
            }
        }
        // SECURITY: bind the block to the state it builds on. A block header commits
        // to the state root BEFORE it is applied, and the linkage check above already
        // forces the block to extend our own finalized head -- so the parent state IS
        // ours and our live root is the right thing to compare against. Without this
        // the adopt path applied blocks to a state the network never committed to,
        // and computed a root nobody else had.
        // (Linkage, size/gas and proposer-signature checks ran above, before the QC
        // verify — not repeated here: the hot path verifies each once.)
        let root_before = self.state.get_state_root().await;
        if block.state_root != root_before {
            return Err(format!(
                "committed block claims parent state root {} but our state is {}",
                hex::encode(block.state_root),
                hex::encode(root_before)
            ));
        }
        // PERF_PROFILE §6.2: parallel intake batch — byte-identical verdict
        // to the serial batch (see sharding.rs: same primitive apply uses).
        if !crate::sharding::Transaction::verify_signatures_batch_parallel(&block.transactions) {
            return Err("committed block contains a bad transaction signature".to_string());
        }
        // Actor-mailbox cap (adopt side): the same deterministic refusal as
        // propose/finalize, so a Byzantine commit carrying an over-cap block
        // cannot smuggle a root-invisible leftover past the decision boundary.
        self.check_actor_cap(&block).await?;
        // TRANSACTION-ORDER COMMITMENT (adopt side): the same rule the
        // proposal and finalize paths apply. The quorum certificate already
        // binds the block hash (which contains the order root), so on an
        // upgraded network this can only fire for a body whose order was
        // never committed — refused, never applied.
        self.check_order_commitment_with_hash(&block, &bh)?;
        // Timestamp gate (adopt side, A3): the same fail-closed parent check
        // the proposal path runs, so a commit cannot smuggle a timestamp no
        // proposer could publish. Runs BEFORE the body is stored: the check
        // reads the parent out of `blocks`/`last_decision`, and storing first
        // would let a block vouch for itself.
        self.check_block_timestamp(&block)?;
        // CANONICAL DOWNTIME EVIDENCE (adopt side, W10.5): the same rule the
        // proposal path applies. The transition attributes downtime from the
        // embedded parent QC, so an adopted block must carry evidence the
        // network actually decided — verified against the set in force at H-1.
        self.check_last_qc_evidence_with_hash(&block, &bh)?;

        // DOWNTIME PARITY with the local path: the transition reads its slash
        // evidence from `block.last_qc` (canonical, proposer-chosen — see
        // `check_last_qc_evidence`), and this body never ran the height's
        // rounds locally, so the body may arrive without a certificate while
        // the commit message carries the verified one. Attach the
        // just-verified certificate to the body BEFORE it is stored and applied
        // as the FINALITY proof (checkpoints, light clients, sync); it is no
        // longer slash evidence. A later reorg re-apply of this very body
        // reproduces the same burn from the same embedded evidence instead of
        // finding no evidence at all.
        // `Block::compute_hash` deliberately excludes the finality QC (it
        // commits to the header + transactions + canonical evidence), so
        // attaching it cannot change `bh`.
        // Without this, a node catching up skipped the burn (and the pool
        // debit) while a node that finalized locally applied it, and the two
        // reached different state roots from the same block.
        self.hc.precommit_qc = Some(certificate.clone());
        block.precommit_qc = Some(certificate.clone());
        // W10.5: record the decision exactly like the local-finalize path, so
        // the NEXT proposal embeds it as canonical downtime evidence. A boot
        // that could not reconstruct the old tip's evidence (DOWNTIME-RESTORE)
        // is healed by this verified peer decision.
        let parent_hash_for_dpv = Some(block.prev_hash);
        let schedule_for_dpv = self.committee_schedule_at(height);
        self.last_decision = Some((height, block.clone(), certificate.clone()));
        self.seed_decided_parent_votes_from_qc(
            height,
            bh,
            &certificate,
            validators,
            parent_hash_for_dpv,
            schedule_for_dpv,
        );
        self.parent_evidence_missing = false;
        self.blocks.insert(bh, block.clone());
        self.apply_and_advance(bh, &block).await;
        {
            let pq_reg = self.state.pq_registry_read().await;
            let active = crate::pq_registry::pq_lifecycle_active_at(height);
            if !pq_reg.is_empty() {
                crate::consensus::sync_committed_pq_registry(&pq_reg, active);
            }
        }
        Ok(bh)
    }
}

#[cfg(test)]
mod consensus_step_tests {
    use crate::consensus::{FalconKeypair, ValidatorId, ValidatorSet, Vote, VoteKind};
    use crate::runtime::ValidatorRuntime;
    use crate::state_engine::InMemoryStateEngine;
    use ed25519_dalek::SigningKey;
    use std::sync::Arc;

    /// Serializes this module's tests: `make_4node_cluster` replaces the
    /// PROCESS-GLOBAL committed PQ registry (`sync_committed_pq_registry`), so
    /// two tests running in parallel would erase each other's validator keys
    /// and fail as "bad vote signature" / "invalid proposer signature".
    static STEP_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn step_lock() -> std::sync::MutexGuard<'static, ()> {
        STEP_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    async fn make_4node_cluster(seed_base: u8) -> (Vec<ValidatorRuntime>, ValidatorSet) {
        let keys: Vec<SigningKey> = (0..4u8)
            .map(|i| SigningKey::from_bytes(&[seed_base.wrapping_add(i); 32]))
            .collect();
        let ids: Vec<ValidatorId> = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();
        let falcons: Vec<FalconKeypair> = (0..4u8)
            .map(|i| FalconKeypair::generate_from_seed(seed_base.wrapping_add(0x40 + i)))
            .collect();
        let validators = ValidatorSet::from_list(ids.iter().map(|id| (*id, 10)).collect());
        let mut nodes = Vec::with_capacity(4);
        for (i, k) in keys.into_iter().enumerate() {
            let st = Arc::new(InMemoryStateEngine::new());
            crate::runtime::fund_genesis(&st, &validators, 1_000_000).await;
            {
                let mut ledger = st.staking_write().await;
                let mut pq_reg = st.pq_registry_write().await;
                for (vid, fk) in ids.iter().zip(falcons.iter()) {
                    ledger.validator_pq_keys.insert(
                        *vid,
                        (
                            crate::post_quantum::PqScheme::Falcon512,
                            fk.public_key.clone(),
                        ),
                    );
                    let _ = pq_reg.adopt_legacy_key_at(
                        *vid,
                        crate::post_quantum::PqScheme::Falcon512,
                        fk.public_key.clone(),
                        0,
                        true,
                    );
                }
                crate::consensus::sync_committed_pq_registry(&pq_reg, true);
            }
            let mut rt = ValidatorRuntime::new(k, validators.clone(), st, 1)
                .with_falcon_key(falcons[i].clone());
            rt.hc.set_parent_hash([0u8; 32]);
            nodes.push(rt);
        }
        (nodes, validators)
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // GATE: the committed PQ registry is process-global; these tests must not race it.
    async fn late_precommit_enriches_last_qc_during_apply_in_flight_and_after_advance() {
        let _global = step_lock();
        // Window A: 4th precommit arrives while `apply_in_flight` is active at H-1=1.
        {
            let (mut nodes, validators) = make_4node_cluster(0x10).await;
            let ts = 1_700_001_000u64;
            let pidx = nodes
                .iter()
                .position(|n| validators.proposer_for(1, 0) == Some(n.id))
                .expect("proposer for h=1 r=0");
            let block = nodes[pidx].propose(ts).await.expect("propose h=1");
            let bh = block.compute_hash();
            let pid = nodes[pidx].id;
            for (i, n) in nodes.iter_mut().enumerate() {
                if i != pidx {
                    n.on_proposal(pid, block.clone(), 0)
                        .await
                        .expect("on_proposal h=1");
                }
            }
            let prevotes: Vec<Vote> = nodes.iter().filter_map(|n| n.make_prevote()).collect();
            assert_eq!(prevotes.len(), 4);
            for v in &prevotes {
                for n in nodes.iter_mut() {
                    n.on_prevote(v.clone()).expect("on_prevote");
                }
            }
            let precommits: Vec<Vote> = nodes
                .iter_mut()
                .filter_map(|n| n.make_precommit())
                .collect();
            assert_eq!(precommits.len(), 4);

            // Deliver only 3 of 4 precommits to the proposer (node[pidx]) and submit apply.
            let target_idx = pidx;
            let late_idx = (0..4).find(|&i| i != target_idx).unwrap();
            for (i, v) in precommits.iter().enumerate() {
                if i != late_idx {
                    nodes[target_idx]
                        .on_precommit(v.clone())
                        .expect("on_precommit");
                }
            }
            let submitted = nodes[target_idx]
                .try_finalize_submit()
                .await
                .expect("3/4 quorum decides h=1");
            assert_eq!(submitted, bh);
            assert!(nodes[target_idx].has_pending_apply());
            assert_eq!(nodes[target_idx].hc.height, 1);

            let safety_before = nodes[target_idx].safety.current_state();
            let round_before = nodes[target_idx].hc.round;

            // 4th precommit arrives during Window A (`apply_in_flight` active).
            let late_vote = precommits[late_idx].clone();
            nodes[target_idx]
                .on_precommit(late_vote)
                .expect("same-height Window A precommit");
            assert_eq!(
                nodes[target_idx].safety.current_state(),
                safety_before,
                "Window A late precommit must not mutate SafetyAuthority"
            );
            assert_eq!(
                nodes[target_idx].hc.round, round_before,
                "Window A late precommit must not mutate hc.round"
            );

            // Complete apply -> advances to height 2.
            let completed = nodes[target_idx]
                .await_apply_completion()
                .await
                .expect("apply completion");
            assert_eq!(completed.height, 1);
            assert_eq!(nodes[target_idx].hc.height, 2);

            let enriched = nodes[target_idx]
                .decided_parent_qc(&bh)
                .expect("decided_parent_qc");
            assert_eq!(enriched.pq_signer_count(), 4);

            // Also advance a peer to height 2 and verify check_last_qc_evidence accepts enriched QC.
            let peer_idx = late_idx;
            for v in &precommits {
                nodes[peer_idx]
                    .on_precommit(v.clone())
                    .expect("peer precommit");
            }
            assert_eq!(nodes[peer_idx].try_finalize().await, Some(bh));
            assert_eq!(nodes[peer_idx].hc.height, 2);
            let mut h2_probe = block;
            h2_probe.height = 2;
            h2_probe.prev_hash = bh;
            h2_probe.last_qc = Some(enriched);
            nodes[peer_idx]
                .check_last_qc_evidence(&h2_probe)
                .expect("enriched Window A last_qc must pass check_last_qc_evidence");
        }

        // Window B: 4th precommit arrives AFTER hc.height already moved to H=2.
        {
            let (mut nodes, validators) = make_4node_cluster(0x60).await;
            let ts = 1_700_002_000u64;
            let pidx = nodes
                .iter()
                .position(|n| validators.proposer_for(1, 0) == Some(n.id))
                .expect("proposer for h=1 r=0");
            let block = nodes[pidx].propose(ts).await.expect("propose h=1");
            let bh = block.compute_hash();
            let pid = nodes[pidx].id;
            for (i, n) in nodes.iter_mut().enumerate() {
                if i != pidx {
                    n.on_proposal(pid, block.clone(), 0)
                        .await
                        .expect("on_proposal h=1");
                }
            }
            let prevotes: Vec<Vote> = nodes.iter().filter_map(|n| n.make_prevote()).collect();
            for v in &prevotes {
                for n in nodes.iter_mut() {
                    n.on_prevote(v.clone()).expect("on_prevote");
                }
            }
            let precommits: Vec<Vote> = nodes
                .iter_mut()
                .filter_map(|n| n.make_precommit())
                .collect();
            assert_eq!(precommits.len(), 4);

            let target_idx = pidx;
            let late_idx = (0..4).find(|&i| i != target_idx).unwrap();
            for (i, v) in precommits.iter().enumerate() {
                if i != late_idx {
                    nodes[target_idx]
                        .on_precommit(v.clone())
                        .expect("on_precommit");
                }
            }
            assert_eq!(nodes[target_idx].try_finalize().await, Some(bh));
            assert_eq!(nodes[target_idx].hc.height, 2);
            assert_eq!(
                nodes[target_idx]
                    .decided_parent_qc(&bh)
                    .expect("3/4 qc")
                    .pq_signer_count(),
                3
            );

            let safety_before = nodes[target_idx].safety.current_state();
            let round_before = nodes[target_idx].hc.round;
            let hc_precommits_before = nodes[target_idx].hc.precommit_set(0).map(|s| s.len());

            // Negative checks on record_late_parent_precommit before admitting valid 4th vote.
            let late_vote = precommits[late_idx].clone();
            let mut wrong_kind = late_vote.clone();
            wrong_kind.kind = VoteKind::Prevote;
            assert!(!nodes[target_idx].record_late_parent_precommit(&wrong_kind));
            let mut wrong_round = late_vote.clone();
            wrong_round.round = 1;
            assert!(!nodes[target_idx].record_late_parent_precommit(&wrong_round));
            let mut wrong_hash = late_vote.clone();
            wrong_hash.block_hash = Some([0xAA; 32]);
            assert!(!nodes[target_idx].record_late_parent_precommit(&wrong_hash));
            let mut forged = late_vote.clone();
            let last = forged.signature.len() - 1;
            forged.signature[last] ^= 0xFF;
            assert!(!nodes[target_idx].record_late_parent_precommit(&forged));

            // Valid 4th precommit arrives at height 2 (Window B) via `on_precommit`.
            assert!(nodes[target_idx].on_precommit(late_vote.clone()).is_err());
            // Duplicate is a no-op.
            assert!(!nodes[target_idx].record_late_parent_precommit(&late_vote));
            assert_eq!(
                nodes[target_idx].safety.current_state(),
                safety_before,
                "Window B late precommit must not mutate SafetyAuthority"
            );
            assert_eq!(
                nodes[target_idx].hc.round, round_before,
                "Window B late precommit must not mutate hc.round"
            );
            assert_eq!(
                nodes[target_idx].hc.precommit_set(0).map(|s| s.len()),
                hc_precommits_before,
                "Window B late precommit must not mutate hc.precommits"
            );

            let enriched = nodes[target_idx]
                .decided_parent_qc(&bh)
                .expect("enriched Window B qc");
            assert_eq!(enriched.pq_signer_count(), 4);

            // Peer checks enriched last_qc and accepts it; adopt_committed path also enriches.
            let peer_idx = late_idx;
            let qc3 = nodes[peer_idx].decided_parent_qc(&bh);
            assert!(qc3.is_none());
            // Build a 3/4 certificate for peer adopt_committed.
            let mut set3 = crate::consensus::VoteSet::new();
            for (i, v) in precommits.iter().enumerate() {
                if i != late_idx {
                    set3.add(v.clone(), &validators, 1, 0, VoteKind::Precommit)
                        .expect("add");
                }
            }
            let cert3 = crate::consensus::produce_decision_certificate_with_schedule(
                &set3,
                Some(bh),
                &validators,
                Some(&[0u8; 32]),
                crate::consensus::CommitteeSchedule::ParentHash,
            )
            .expect("3/4 cert");
            assert_eq!(cert3.pq_signer_count(), 3);
            let adopted = nodes[peer_idx]
                .adopt_committed(1, block.clone(), cert3)
                .await
                .expect("adopt_committed h=1");
            assert_eq!(adopted, bh);
            assert_eq!(nodes[peer_idx].hc.height, 2);
            assert_eq!(
                nodes[peer_idx]
                    .decided_parent_qc(&bh)
                    .expect("3/4 qc after adopt")
                    .pq_signer_count(),
                3
            );
            assert!(nodes[peer_idx].on_precommit(late_vote).is_err());
            let adopted_enriched = nodes[peer_idx]
                .decided_parent_qc(&bh)
                .expect("enriched after adopt + Window B");
            assert_eq!(adopted_enriched.pq_signer_count(), 4);

            let mut h2_probe = block;
            h2_probe.height = 2;
            h2_probe.prev_hash = bh;
            h2_probe.last_qc = Some(enriched);
            nodes[peer_idx]
                .check_last_qc_evidence(&h2_probe)
                .expect("enriched Window B last_qc must pass check_last_qc_evidence");
        }
    }

    /// Decide height 1 on a 4-node cluster and leave `target_idx` with the
    /// apply IN FLIGHT (height still 1), while every other node advances to
    /// height 2. Returns the decided block and hash.
    async fn decide_h1_and_leave_apply_in_flight(
        nodes: &mut [ValidatorRuntime],
        validators: &ValidatorSet,
        target_idx: usize,
        ts: u64,
    ) -> (crate::sharding::Block, [u8; 32]) {
        let pidx = nodes
            .iter()
            .position(|n| validators.proposer_for(1, 0) == Some(n.id))
            .expect("proposer for h=1 r=0");
        let block = nodes[pidx].propose(ts).await.expect("propose h=1");
        let bh = block.compute_hash();
        let pid = nodes[pidx].id;
        for (i, n) in nodes.iter_mut().enumerate() {
            if i != pidx {
                n.on_proposal(pid, block.clone(), 0)
                    .await
                    .expect("on_proposal h=1");
            }
        }
        let prevotes: Vec<Vote> = nodes.iter().filter_map(|n| n.make_prevote()).collect();
        assert_eq!(prevotes.len(), 4);
        for v in &prevotes {
            for n in nodes.iter_mut() {
                n.on_prevote(v.clone()).expect("on_prevote");
            }
        }
        let precommits: Vec<Vote> = nodes
            .iter_mut()
            .filter_map(|n| n.make_precommit())
            .collect();
        assert_eq!(precommits.len(), 4);
        for v in &precommits {
            for n in nodes.iter_mut() {
                n.on_precommit(v.clone()).expect("on_precommit");
            }
        }
        assert_eq!(nodes[target_idx].try_finalize_submit().await, Some(bh));
        assert!(nodes[target_idx].has_pending_apply());
        assert_eq!(nodes[target_idx].hc.height, 1);
        for (i, n) in nodes.iter_mut().enumerate() {
            if i != target_idx {
                assert_eq!(n.try_finalize().await, Some(bh));
                assert_eq!(n.hc.height, 2);
            }
        }
        (block, bh)
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // GATE: the committed PQ registry is process-global; these tests must not race it.
    async fn parked_proposal_is_replayed_after_apply_and_never_double_votes() {
        let _global = step_lock();
        let (mut nodes, validators) = make_4node_cluster(0x70).await;
        let ts = 1_700_020_000u64;
        // Target must NOT be the h=2 proposer: it needs to stay at height 1
        // while the H+1 proposal is built by a peer that already advanced.
        let h2_idx = nodes
            .iter()
            .position(|n| validators.proposer_for(2, 0) == Some(n.id))
            .expect("proposer for h=2 r=0");
        let target_idx = (h2_idx + 1) % nodes.len();
        let (_h1, _bh) =
            decide_h1_and_leave_apply_in_flight(&mut nodes, &validators, target_idx, ts).await;
        assert_eq!(nodes[h2_idx].hc.height, 2);

        let block2 = nodes[h2_idx]
            .propose(ts.saturating_add(30))
            .await
            .expect("propose h=2");
        let bh2 = block2.compute_hash();
        let pid2 = nodes[h2_idx].id;

        // H+1 proposal arrives during the H apply: PARKED, not dropped, and
        // deliberately NOT validated yet (our root is still PRE-H).
        let err = nodes[target_idx]
            .on_proposal(pid2, block2.clone(), 0)
            .await
            .expect_err("proposal during apply must be parked");
        assert!(err.contains("parked"), "unexpected error: {err}");
        assert!(nodes[target_idx].has_parked());
        assert_eq!(
            nodes[target_idx].hc.height, 1,
            "parking must not move consensus state"
        );

        // The worker reports back: H=1 is installed, H=2 is current.
        nodes[target_idx]
            .await_apply_completion()
            .await
            .expect("apply completion");
        assert_eq!(nodes[target_idx].hc.height, 2);

        let (parked, parked_commit) = nodes[target_idx].take_parked();
        assert!(parked_commit.is_none());
        let p = parked.expect("proposal must survive the apply window");
        assert_eq!(p.block.compute_hash(), bh2);

        // Replay through the ORIGINAL entry point: every check runs again.
        let accepted = nodes[target_idx]
            .on_proposal(p.proposer, p.block, p.round)
            .await
            .expect("replayed proposal must be accepted");
        assert_eq!(accepted, bh2);
        assert!(!nodes[target_idx].has_parked());

        // REGRESSION: the replay must not enable a second vote for the same
        // (height, round) target. The SafetyAuthority watermark stays
        // authoritative: one prevote, and the immediate second attempt is
        // refused.
        let v1 = nodes[target_idx]
            .make_prevote()
            .expect("first prevote at (2,0)");
        assert_eq!((v1.height, v1.round), (2, 0));
        assert!(
            nodes[target_idx].make_prevote().is_none(),
            "parked-then-replayed proposal must never double-vote (2,0)"
        );
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // GATE: the committed PQ registry is process-global; these tests must not race it.
    async fn parked_commit_is_revalidated_and_bad_certificate_still_refused() {
        let _global = step_lock();
        let (mut nodes, validators) = make_4node_cluster(0x72).await;
        let ts = 1_700_030_000u64;
        let h2_idx = nodes
            .iter()
            .position(|n| validators.proposer_for(2, 0) == Some(n.id))
            .expect("proposer for h=2 r=0");
        let target_idx = (h2_idx + 1) % nodes.len();
        decide_h1_and_leave_apply_in_flight(&mut nodes, &validators, target_idx, ts).await;

        let block2 = nodes[h2_idx]
            .propose(ts.saturating_add(30))
            .await
            .expect("propose h=2");
        let bh2 = block2.compute_hash();
        // Structurally well-addressed, cryptographically EMPTY certificate:
        // right height/round/kind/block hash, zero signers.
        let bad = crate::consensus::QuorumCertificate {
            height: 2,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: Some(bh2),
            signatures: vec![],
            shard_id: block2.shard_id,
        };

        // Parked during the apply window (the gate fires before validation).
        let err = nodes[target_idx]
            .adopt_committed(2, block2.clone(), bad)
            .await
            .expect_err("commit during apply must be parked");
        assert!(err.contains("parked"), "unexpected error: {err}");
        assert!(nodes[target_idx].has_parked());

        nodes[target_idx]
            .await_apply_completion()
            .await
            .expect("apply completion");
        assert_eq!(nodes[target_idx].hc.height, 2);

        let (_, parked) = nodes[target_idx].take_parked();
        let c = parked.expect("commit must survive the apply window");
        assert_eq!(c.height, 2);
        // Replay goes through adopt_committed: the empty certificate is still
        // refused on quorum verification (fail-closed, nothing bypassed).
        let refused = nodes[target_idx]
            .adopt_committed(c.height, c.block, c.certificate)
            .await
            .expect_err("bad certificate must be refused on replay");
        assert!(
            refused.contains("quorum"),
            "expected a quorum refusal, got: {refused}"
        );
        assert_eq!(
            nodes[target_idx].hc.height, 2,
            "refused replay must not advance the height"
        );
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // GATE: the committed PQ registry is process-global; these tests must not race it.
    async fn parked_slots_are_bounded_and_overwrite_the_oldest() {
        let _global = step_lock();
        let (mut nodes, validators) = make_4node_cluster(0x74).await;
        let ts = 1_700_040_000u64;
        let target_idx = 1;
        let (block, _bh) =
            decide_h1_and_leave_apply_in_flight(&mut nodes, &validators, target_idx, ts).await;

        // Two distinct proposals arriving during the same apply window. The
        // second overwrites the first: the pad is exactly one slot, so memory
        // cannot grow with proposal traffic.
        let mut a = block.clone();
        a.height = 2;
        a.timestamp = a.timestamp.saturating_add(1);
        let mut b = a.clone();
        b.timestamp = b.timestamp.saturating_add(1);
        let (ha, hb) = (a.compute_hash(), b.compute_hash());
        assert_ne!(ha, hb);

        let pid = nodes[0].id;
        assert!(nodes[target_idx]
            .on_proposal(pid, a, 0)
            .await
            .unwrap_err()
            .contains("parked"));
        assert!(nodes[target_idx]
            .on_proposal(pid, b, 0)
            .await
            .unwrap_err()
            .contains("parked"));

        // Exactly one proposal slot exists, and it holds the NEWEST item.
        let slot = nodes[target_idx]
            .parked_proposal
            .as_ref()
            .expect("newest proposal is retained");
        assert_eq!(
            slot.block.compute_hash(),
            hb,
            "a second park must overwrite the first (bounded depth 1)"
        );
        assert!(nodes[target_idx].parked_commit.is_none());

        // Explicit abandonment clears both slots without replay.
        nodes[target_idx].clear_parked();
        assert!(!nodes[target_idx].has_parked());
        assert!(nodes[target_idx].parked_proposal.is_none());
        assert!(nodes[target_idx].parked_commit.is_none());

        // One more item parked during the remaining window still fits and is
        // replayed after the worker reports back (the pad is reusable, never
        // growing).
        let mut c = block;
        c.height = 2;
        c.timestamp = c.timestamp.saturating_add(2);
        let hc = c.compute_hash();
        assert!(nodes[target_idx]
            .on_proposal(pid, c, 0)
            .await
            .unwrap_err()
            .contains("parked"));
        nodes[target_idx]
            .await_apply_completion()
            .await
            .expect("apply completion");
        let (parked, parked_commit) = nodes[target_idx].take_parked();
        assert!(parked_commit.is_none());
        assert_eq!(
            parked
                .expect("parked proposal survives")
                .block
                .compute_hash(),
            hc
        );
        assert!(!nodes[target_idx].has_parked());
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // GATE: the committed PQ registry is process-global; these tests must not race it.
    async fn parked_items_are_dropped_after_the_height_moves_past_them() {
        let _global = step_lock();
        let (mut nodes, validators) = make_4node_cluster(0x76).await;
        let ts = 1_700_050_000u64;
        let target_idx = 1;
        let (block, _bh) =
            decide_h1_and_leave_apply_in_flight(&mut nodes, &validators, target_idx, ts).await;

        // Park a proposal for height 5 while the H=1 apply is in flight. The
        // apply advances hc to 2, so on take the item targets neither the
        // current height nor a fresh epoch: it MUST be discarded, never
        // replayed a few heights late.
        let mut stale = block;
        stale.height = 5;
        let pid = nodes[0].id;
        assert!(nodes[target_idx]
            .on_proposal(pid, stale, 0)
            .await
            .unwrap_err()
            .contains("parked"));

        nodes[target_idx]
            .await_apply_completion()
            .await
            .expect("apply completion");
        assert_eq!(nodes[target_idx].hc.height, 2);
        let (parked, parked_commit) = nodes[target_idx].take_parked();
        assert!(
            parked.is_none(),
            "a parked item for a height other than the current one must be dropped"
        );
        assert!(parked_commit.is_none());
        assert!(!nodes[target_idx].has_parked());
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // GATE: the committed PQ registry is process-global; these tests must not race it.
    async fn parked_proposal_is_dropped_after_the_round_moves_beyond_the_lag() {
        let _global = step_lock();
        let (mut nodes, validators) = make_4node_cluster(0x78).await;
        let ts = 1_700_060_000u64;
        let target_idx = 1;
        let (block, _bh) =
            decide_h1_and_leave_apply_in_flight(&mut nodes, &validators, target_idx, ts).await;

        let mut next = block;
        next.height = 2;
        next.timestamp = next.timestamp.saturating_add(1);
        let pid = nodes[0].id;
        assert!(nodes[target_idx]
            .on_proposal(pid, next, 0)
            .await
            .unwrap_err()
            .contains("parked"));

        // Completion installs H=2 at round 0: the parked r0 envelope is still
        // fresh there...
        nodes[target_idx]
            .await_apply_completion()
            .await
            .expect("apply completion");
        assert_eq!(nodes[target_idx].hc.height, 2);
        assert!(nodes[target_idx].has_parked());

        // ...but once the CURRENT round advances beyond
        // `SUPERSEDED_ROUND_LAG`, the parked envelope is stale and the slot
        // must drop it instead of replaying a proposal the live path would
        // refuse.
        for _ in 0..=crate::consensus_net::SUPERSEDED_ROUND_LAG {
            nodes[target_idx].next_round();
        }
        assert!(nodes[target_idx].hc.round > crate::consensus_net::SUPERSEDED_ROUND_LAG);
        let (parked, parked_commit) = nodes[target_idx].take_parked();
        assert!(
            parked.is_none(),
            "round advance past the lag must invalidate the parked proposal"
        );
        assert!(parked_commit.is_none());
        assert!(!nodes[target_idx].has_parked());
    }

    /// PARK-DEPTH EVICTION (liveness): the slot holds ONE item, so a frame
    /// that can never be replayed must not overwrite the real H+1 proposal.
    /// Before the guard, any proposal arriving during the apply window was
    /// parked, so one junk frame (wrong height) evicted the only useful copy
    /// and the height lost its body until the peer retransmitted.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // GATE: process-global PQ registry; serialized with the other step tests.
    async fn non_replayable_proposal_cannot_evict_the_parked_next_height_slot() {
        let _global = step_lock();
        let (mut nodes, validators) = make_4node_cluster(0x76).await;
        let ts = 1_700_050_000u64;
        let h2_idx = nodes
            .iter()
            .position(|n| validators.proposer_for(2, 0) == Some(n.id))
            .expect("proposer for h=2 r=0");
        let target_idx = (h2_idx + 1) % nodes.len();
        decide_h1_and_leave_apply_in_flight(&mut nodes, &validators, target_idx, ts).await;

        let block2 = nodes[h2_idx]
            .propose(ts.saturating_add(30))
            .await
            .expect("propose h=2");
        let bh2 = block2.compute_hash();
        let pid2 = nodes[h2_idx].id;
        nodes[target_idx]
            .on_proposal(pid2, block2.clone(), 0)
            .await
            .expect_err("H+1 proposal during apply is parked");

        // The CURRENT height is the one executing (already decided) and a far
        // height cannot be replayed after a single advance: neither may take
        // the slot.
        let mut current = block2.clone();
        current.height = 1;
        current.prev_hash = [0u8; 32];
        let _ = nodes[target_idx].on_proposal(pid2, current, 0).await;
        let mut far = block2.clone();
        far.height = 9;
        let _ = nodes[target_idx].on_proposal(pid2, far, 0).await;

        nodes[target_idx]
            .await_apply_completion()
            .await
            .expect("apply completion");
        assert_eq!(nodes[target_idx].hc.height, 2);

        let (parked, commit) = nodes[target_idx].take_parked();
        assert!(commit.is_none());
        let p = parked.expect("the real H+1 proposal must survive junk parking attempts");
        assert_eq!(p.block.compute_hash(), bh2);
    }

    /// Same guard on the commit slot: only the post-install height (H+1) is
    /// adoptable, so a current/far-height commit must not evict it.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // GATE: process-global PQ registry; serialized with the other step tests.
    async fn non_replayable_commit_cannot_evict_the_parked_next_height_slot() {
        let _global = step_lock();
        let (mut nodes, validators) = make_4node_cluster(0x78).await;
        let ts = 1_700_060_000u64;
        let h2_idx = nodes
            .iter()
            .position(|n| validators.proposer_for(2, 0) == Some(n.id))
            .expect("proposer for h=2 r=0");
        let target_idx = (h2_idx + 1) % nodes.len();
        decide_h1_and_leave_apply_in_flight(&mut nodes, &validators, target_idx, ts).await;

        let block2 = nodes[h2_idx]
            .propose(ts.saturating_add(30))
            .await
            .expect("propose h=2");
        let empty = crate::consensus::QuorumCertificate {
            height: 2,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: Some(block2.compute_hash()),
            signatures: vec![],
            shard_id: block2.shard_id,
        };
        // The useful H+1 commit (parking happens before certification).
        let err = nodes[target_idx]
            .adopt_committed(2, block2.clone(), empty)
            .await
            .expect_err("commit during apply is parked");
        assert!(err.contains("parked"));
        // Junk at the current and a far height: must not evict the H+1 slot.
        let current_cert = crate::consensus::QuorumCertificate {
            height: 1,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: None,
            signatures: vec![],
            shard_id: block2.shard_id,
        };
        let mut current = block2.clone();
        current.height = 1;
        let _ = nodes[target_idx]
            .adopt_committed(1, current, current_cert)
            .await;
        let far_cert = crate::consensus::QuorumCertificate {
            height: 9,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: None,
            signatures: vec![],
            shard_id: block2.shard_id,
        };
        let mut far = block2.clone();
        far.height = 9;
        let _ = nodes[target_idx].adopt_committed(9, far, far_cert).await;

        nodes[target_idx]
            .await_apply_completion()
            .await
            .expect("apply completion");
        assert_eq!(nodes[target_idx].hc.height, 2);

        let (_, parked) = nodes[target_idx].take_parked();
        let c = parked.expect("the real H+1 commit must survive junk parking attempts");
        assert_eq!(c.height, 2);
    }

    /// O6 DIFFERENTIAL: the single-pass Ed-half index seeds the SAME votes as
    /// the old per-signer `signatures.iter().find(...)` scan, for a randomly
    /// populated certificate (duplicates, wrong-length entries, junk ids,
    /// signers with no Ed entry at all).
    #[test]
    fn o6_seed_ed_lookup_matches_linear_scan() {
        use crate::consensus::{
            attach_vote_falcon_sig, derive_sortition_committee, encode_pq_micro_envelope,
            micro_committee_size, CommitteeSchedule, PqMicroCertificate, QuorumCertificate,
            VoteSet, PQ_UQC_MARKER_ID,
        };

        const H: crate::consensus::Height = 42;
        const R: crate::consensus::Round = 3;
        let parent = [0x5Au8; 32];
        let block_hash = [0x6Bu8; 32];

        // 11 validators, distinct powers; all ids have power > 0.
        let mut vs = crate::consensus::ValidatorSet::new();
        for i in 1..=11u8 {
            let mut id = [0u8; 32];
            id[0] = i;
            id[7] = 0xA5;
            vs.add(id, 100 + i as u64);
        }
        let csize = micro_committee_size(vs.len());
        assert!(csize > 0);
        let committee = derive_sortition_committee(&vs, H, R, csize, &parent);
        assert_eq!(committee.len(), csize as usize);

        // Full-committee µQC: one Falcon half per member (bytes are opaque to
        // the seeding path, which never verifies them).
        let mut bitmask = vec![0u8; (csize as usize).div_ceil(8)];
        for i in 0..committee.len() {
            bitmask[i / 8] |= 1 << (i % 8);
        }
        let falcon_halves: Vec<Vec<u8>> = (0..committee.len())
            .map(|i| vec![(0x90 + i % 16) as u8; 64 + i])
            .collect();
        let cert = PqMicroCertificate::new(
            crate::post_quantum::PqScheme::Falcon512,
            H,
            R,
            csize,
            bitmask,
            falcon_halves,
            parent,
        );

        // Deterministic LCG so the fixture is "random" but reproducible.
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            state >> 33
        };

        let mut signatures: Vec<(crate::consensus::ValidatorId, Vec<u8>)> =
            vec![(PQ_UQC_MARKER_ID, encode_pq_micro_envelope(&cert))];
        // Random filler: 0..=3 entries per committee member, random length in
        // 0..=80 (so some are 64, some are not, some duplicate the id) plus a
        // few junk ids that are not validators.
        for &member in &committee {
            let n = (next() % 4) as usize;
            for _ in 0..n {
                let len = (next() % 81) as usize;
                let fill = (next() % 251) as u8;
                signatures.push((member, vec![fill; len]));
            }
        }
        for _ in 0..7 {
            let mut junk = [0u8; 32];
            junk[0] = 0xF0;
            junk[1] = (next() % 16) as u8;
            let len = (next() % 81) as usize;
            signatures.push((junk, vec![0xEE; len]));
        }

        let qc = QuorumCertificate {
            shard_id: 0,
            height: H,
            round: R,
            kind: crate::consensus::VoteKind::Precommit,
            block_hash: Some(block_hash),
            signatures: signatures.clone(),
        };

        // ---- test-local copy of the OLD algorithm ----
        fn old_seed(
            qc: &QuorumCertificate,
            validators: &crate::consensus::ValidatorSet,
            schedule: CommitteeSchedule,
        ) -> Vec<(crate::consensus::ValidatorId, Vec<u8>)> {
            let mut out = Vec::new();
            for (voter, fsig) in qc.pq_signer_signatures_with_schedule(validators, schedule) {
                let mut sig = qc
                    .signatures
                    .iter()
                    .find(|(id, s)| *id == voter && s.len() == 64)
                    .map(|(_, s)| s.clone())
                    .unwrap_or_else(|| vec![0u8; 64]);
                attach_vote_falcon_sig(&fsig, &mut sig);
                out.push((voter, sig));
            }
            out
        }
        let mut expected = old_seed(&qc, &vs, CommitteeSchedule::ParentHash);
        assert!(!expected.is_empty(), "fixture must seed signers");
        expected.sort_unstable_by(|a, b| a.0.cmp(&b.0));

        // ---- actual ----
        let key = SigningKey::from_bytes(&[0x42; 32]);
        let mut rt =
            ValidatorRuntime::new(key, vs.clone(), Arc::new(InMemoryStateEngine::new()), H);
        rt.seed_decided_parent_votes_from_qc(
            H,
            block_hash,
            &qc,
            vs.clone(),
            Some(parent),
            CommitteeSchedule::ParentHash,
        );
        let dpv = rt.decided_parent_votes.expect("seeded votes recorded");
        let seeded: &VoteSet = &dpv.votes;
        assert_eq!(seeded.len(), expected.len(), "same seeded vote count");

        let mut actual: Vec<(crate::consensus::ValidatorId, Vec<u8>)> = expected
            .iter()
            .map(|(voter, _)| {
                let vote = seeded.vote_by(voter).expect("expected voter seeded");
                (*voter, vote.signature.clone())
            })
            .collect();
        actual.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(actual, expected, "seeded signatures must be byte-identical");
        // No unexpected voters.
        for member in vs.validators.keys() {
            if seeded.vote_by(member).is_some() {
                assert!(
                    expected.iter().any(|(v, _)| v == member),
                    "unexpected seeded voter {member:?}"
                );
            }
        }
    }

    /// F8: the durable lock names a DIFFERENT value from an EARLIER round while
    /// the engine has already moved on (it unlocked on a polka). The authority
    /// refuses the non-nil prevote; the validator must then cast a NIL prevote
    /// instead of going silent for the round. The lock itself is untouched.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // GATE: the committed PQ registry is process-global; these tests must not race it.
    async fn f8_locked_conflict_casts_a_nil_prevote_instead_of_silence() {
        use crate::consensus::Step;
        use crate::post_quantum::PqScheme;
        let _g = step_lock();

        // One-validator set: a single prevote IS a polka, so a precommit (and
        // therefore a durable lock) forms without driving a whole cluster.
        let key = SigningKey::from_bytes(&[0x91u8; 32]);
        let fk = FalconKeypair::generate_from_seed(0x92);
        let id = key.verifying_key().to_bytes();
        let validators = ValidatorSet::from_list(vec![(id, 10)]);
        let st = Arc::new(InMemoryStateEngine::new());
        crate::runtime::fund_genesis(&st, &validators, 1_000_000).await;
        {
            let mut ledger = st.staking_write().await;
            let mut pq_reg = st.pq_registry_write().await;
            ledger
                .validator_pq_keys
                .insert(id, (PqScheme::Falcon512, fk.public_key.clone()));
            let _ =
                pq_reg.adopt_legacy_key_at(id, PqScheme::Falcon512, fk.public_key.clone(), 0, true);
            crate::consensus::sync_committed_pq_registry(&pq_reg, true);
        }
        let mut node = ValidatorRuntime::new(key, validators.clone(), st, 1).with_falcon_key(fk);

        // Lock it on value A.
        let a = node.propose(1_700_200_000).await.expect("proposal A");
        let a_hash = a.compute_hash();
        let pv = node.make_prevote().expect("prevote A");
        node.on_prevote(pv).unwrap();
        let pc = node.make_precommit().expect("precommit A");
        node.on_precommit(pc).unwrap();
        let lock = node.safety.locked().expect("locked on A");
        assert_eq!(lock.block_hash, a_hash);
        assert_eq!(lock.round, 0);

        // Engine state after a polka unlock at a later round: no engine lock,
        // live proposal B with a DIFFERENT value id, round 5.
        let b_hash = [0xBBu8; 32];
        let b_value = [0xCCu8; 32];
        node.hc.note_value_id(b_hash, b_value);
        node.hc.proposal = Some((node.hc.proposer().expect("proposer"), b_hash));
        node.hc.locked = None;
        node.hc.round = 5;
        node.hc.step = Step::Propose;

        let vote = node
            .make_prevote()
            .expect("F8: must cast a NIL prevote, not stay silent");
        assert_eq!(vote.kind, VoteKind::Prevote);
        assert_eq!(vote.round, 5);
        assert_eq!(vote.block_hash, None, "the prevote must be NIL");
        // The durable lock is NOT relaxed by the fallback.
        let lock_after = node.safety.locked().expect("lock kept");
        assert_eq!(lock_after.block_hash, a_hash);
        assert_eq!(lock_after.round, 0);
    }
}
