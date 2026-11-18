use super::lanes::{block_actor_sends_exceed_cap, count_block_actor_sends};
use super::{
    master_set_stamp, publish_master_set_stamp, set_fingerprint, workchain_set_activation_height,
    BlockHash, ValidatorRuntime, MAX_BLOCK_GAS, MAX_BLOCK_TXS, MAX_COMMIT_CERT_SIGNERS,
    MAX_TIMESTAMP_JUMP_SECS, PROPOSAL_ALIGN_WINDOW_ROUNDS, SLOW_VALIDATION_THRESHOLD_MS,
    VALIDATOR_SET_HISTORY_CAP,
};
use crate::consensus::{Height, Round, Step, ValidatorId, ValidatorSet, Vote, VoteKind};
use crate::sharding::{Block, CrossShardKey, Transaction, ValidatorSetSource};
use sha2::{Digest as _, Sha256};

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
    /// Fail-closed block-timestamp gate (A3): refuse on a bad or missing
    /// timestamp using deterministic rules only.
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
                    if *h + 1 == block.height && b.compute_hash() == block.prev_hash {
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
            && block.timestamp > parent_ts.saturating_add(MAX_TIMESTAMP_JUMP_SECS)
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
    pub(super) fn batch_verify_cache_key(block: &Block) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(block.compute_hash());
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
    pub(super) fn proposer_sig_cache_key(block: &Block) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(block.compute_hash());
        h.update(block.proposer);
        h.update((block.validator_signatures.len() as u32).to_be_bytes());
        for (id, sig) in &block.validator_signatures {
            h.update(id);
            h.update((sig.len() as u32).to_be_bytes());
            h.update(sig);
        }
        h.finalize().into()
    }
    pub(super) fn check_order_commitment(&self, block: &Block) -> Result<(), String> {
        // STAB: per-block-hash cache — the root is a pure function of the body,
        // so repeat validations of the same block (round retries, demanded
        // re-propose, adopt) hit O(1) instead of re-hashing O(txs).
        let bh = block.compute_hash();
        if let Some(cached) = self
            .order_root_cache
            .lock()
            .ok()
            .and_then(|g| g.get(&bh).copied())
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
            g.insert(bh, expected);
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
    pub(super) fn check_last_qc_evidence(&self, block: &Block) -> Result<(), String> {
        let Some(parent_h) = block.height.checked_sub(1) else {
            return Ok(());
        };
        let Some(qc) = &block.last_qc else {
            let knows_parent_decision = self
                .last_decision
                .as_ref()
                .is_some_and(|(h, b, _)| *h == parent_h && b.compute_hash() == block.prev_hash);
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
        // STAB verify-once: the QC power is a pure function of (block bytes,
        // validator history at parent_h). Round retries re-validate the same
        // block; the second+ visits hit O(1) instead of re-running
        // verify-grade `signers_set` crypto. Failures are NOT cached (a
        // history advance could turn a weak QC into a passing one).
        let bh = block.compute_hash();
        if let Some((ok, _)) = self
            .qc_power_cache
            .lock()
            .ok()
            .and_then(|g| g.get(&bh).copied())
        {
            if ok {
                return Ok(());
            }
        }
        let set = self.validator_set_for_height(parent_h);
        // SAME VERDICT AS APPLY (PENTEST F-2): `apply_downtime_slash_with_set`
        // accepts evidence only after `cert.verify(val_set)`. The gate used to
        // use attribution (`qc_signed_power`, no verify) instead, so an
        // over-cap `last_qc` carrying a genuine quorum passed the gate and was
        // then silently skipped by apply: any proposer could suppress the
        // downtime attribution for a height. Attribution is now capped (F-1),
        // but the two paths must not merely agree on this input class — they
        // must share ONE verdict. `qc.verify` is that verdict; attribution is
        // consulted only to name the shortfall in the refusal message.
        if !qc.verify(&set) {
            let signed = set.qc_signed_power(qc);
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
            g.insert(bh, (true, 0));
        }
        Ok(())
    }

    /// The downtime-evidence QC to embed in a proposal for the current
    /// height: the QC that decided the parent (H-1), known from the last
    /// decision this node recorded (local finalize AND adopt both stash it).
    ///
    /// `None` when this node knows no parent decision yet: the genesis child
    /// (nothing decided before height 1), or a node restored/healed without
    /// finalizing since. Validators that DO know the parent decision reject
    /// the omission; validators that do not accept it and skip attribution
    /// for that height. Either way the verdict is a pure function of agreed
    /// inputs, so no fork.
    pub(super) fn decided_parent_qc(&self) -> Option<crate::consensus::QuorumCertificate> {
        let h = self.hc.height.checked_sub(1)?;
        self.last_decision
            .as_ref()
            .and_then(|(dh, _, qc)| if *dh == h { Some(qc.clone()) } else { None })
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
        if block.height != self.hc.height {
            return Err("proposal: wrong height".to_string());
        }
        // TIMESTAMP VALIDITY (A3, fail-closed): the proposer timestamp is
        // hashed into the block and used as the VM's "now" (session expiry,
        // unbonding, order stamps) — an unbounded proposer could skew all of
        // them. Both bounds are deterministic functions of (parent, child):
        // (a) monotone vs the parent block's timestamp (agreed state, no
        // clock involved); (b) at most MAX_TIMESTAMP_JUMP_SECS ahead of the
        // parent. There is deliberately NO wall-clock read here: a
        // `now_secs()` bound makes the verdict node-local (two validators
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
                hex::encode(block.compute_hash()),
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
        self.check_order_commitment(block)?;
        // CANONICAL DOWNTIME EVIDENCE (W10.5): the proposer-chosen QC for the
        // parent height — verified here (linkage, finality shape, quorum under
        // the set in force at H-1) so the evidence every applier attributes
        // from is byte-identical across the network.
        self.check_last_qc_evidence(block)?;
        // Authenticity: the block must actually be signed by its declared
        // proposer, otherwise a peer could propose on another validator's behalf.
        // STAB verify-once: cache the verdict per block hash (pure function
        // of block bytes); the timed attribution path below hits the cache
        // instead of re-verifying the same Ed25519/Falcon signature.
        {
            let bh = Self::proposer_sig_cache_key(block);
            let cached = self
                .proposer_sig_cache
                .lock()
                .ok()
                .and_then(|g| g.get(&bh).copied());
            let ok = match cached {
                Some(v) => v,
                None => {
                    let v = crate::consensus::verify_proposer_signature(block);
                    if let Ok(mut g) = self.proposer_sig_cache.lock() {
                        if g.len() > 1024 {
                            g.clear();
                        }
                        g.insert(bh, v);
                    }
                    v
                }
            };
            if !ok {
                return Err("proposal: invalid or missing proposer signature".to_string());
            }
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
        // Batched Ed25519 verification: much faster than one-by-one for a full block.
        // STAB verify-once: cache per signature-committing key; the timed attribution re-run
        // below becomes an O(1) HashMap hit with a byte-identical verdict.
        {
            let bh = Self::batch_verify_cache_key(block);
            let cached = self
                .batch_verify_cache
                .lock()
                .ok()
                .and_then(|g| g.get(&bh).copied());
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
                        g.insert(bh, v);
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
        Ok(())
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
        // Authoritative verdict: exactly one run, same order, same errors.
        // STAB verify-once: the verdict above populates the per-block caches
        // (order root, batch verify, proposer sig); attribution below reads
        // those caches O(1) instead of re-running O(txs) crypto, so the timed
        // path costs one verification per block, not two, with a
        // byte-identical verdict.
        let verdict = self.validate_proposal_unaligned(block, expected_state_root);
        let mut stages: Vec<(String, u64)> = Vec::with_capacity(6);
        let t = std::time::Instant::now();
        let _ = self
            .proposer_sig_cache
            .lock()
            .ok()
            .and_then(|g| g.get(&Self::proposer_sig_cache_key(block)).copied())
            .unwrap_or_else(|| crate::consensus::verify_proposer_signature(block));
        stages.push(("proposer_sig_verify".into(), t.elapsed().as_millis() as u64));
        let t = std::time::Instant::now();
        let _ = block.state_root == expected_state_root;
        stages.push(("state_root_check".into(), t.elapsed().as_millis() as u64));
        let t = std::time::Instant::now();
        // Cache hit: `check_order_commitment` already cached the root during
        // the verdict above, so this is a HashMap lookup, not O(txs) hashes.
        let _ = self.check_order_commitment(block);
        stages.push(("order_commit".into(), t.elapsed().as_millis() as u64));
        let t = std::time::Instant::now();
        let _ = self
            .batch_verify_cache
            .lock()
            .ok()
            .and_then(|g| g.get(&Self::batch_verify_cache_key(block)).copied())
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
        let ours = self
            .blocks
            .get(&h)
            .is_some_and(|b| b.height == self.hc.height && b.proposer == self.id);
        if !ours {
            return;
        }
        const MAX_DEMANDED: usize = 8;
        if self.demanded.len() >= MAX_DEMANDED && !self.demanded.contains(&h) {
            return;
        }
        self.demanded.insert(h);
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
        let min_supporters = if self.validators.len() >= 3 { 2 } else { 1 };
        let corroborated = self.hc.supporting_peers_count(vote_round) >= min_supporters;
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
        // (2+ distinct voters at/above the target) still opens the full
        // chase, and a 2-member set still follows its single peer.
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
            if !first_step && self.hc.supporting_peers_count(vote_round) < min_supporters {
                break; // lone reporter: keep the nudge, refuse the cliff
            }
            first_step = false;
            let r = self.hc.round;
            self.hc.sync_round_to(vote_round);
            if self.hc.round == r {
                break; // jump budget exhausted; our own view change refills it
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
        if vote.height != self.hc.height {
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
        // §7 Phase 2 gate: the header's root check below reads OUR root, which
        // is PRE-H while a decided block is still executing. Checking now
        // would compare the proposal against the wrong parent state (a valid
        // H+1 proposal looks corrupt, a stale one looks fine), so the
        // proposal is deferred, not validated, until the worker reports back.
        // No state is read and none moves.
        if self.apply_in_flight.is_some() {
            return Err("proposal deferred: apply in flight".to_string());
        }
        // Read our root BEFORE accepting, so the header is checked against the
        // state the block would actually extend.
        let our_root = self.state.get_state_root().await;
        // Authenticity FIRST, before height/state checks: only the declared
        // proposer could have signed this, so a verified signature makes the
        // header's claims (height, prev_hash) attributable -- and worth
        // learning from even when we must refuse the block itself.
        if !crate::consensus::verify_proposer_signature(&block) {
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
        let (vres, stages) = self.validate_proposal_timed(&block, our_root);
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
        if envelope_round < self.hc.round {
            return Err("proposal: stale round".to_string());
        }
        // Phase-align: if the block is genuinely this height's proposer's work
        // but for a NEAR-FUTURE round, we are simply behind -- jump to the
        // earliest round this proposer owns and accept it there instead of
        // rejecting it as "wrong proposer" and then missing it forever (the
        // vote that would have synced us arrives after the proposal it should
        // have preceded). Bounded to near rounds: a far claim is answered by
        // the vote path, not by an unsigned envelope.
        if Some(block.proposer) != self.expected_proposer_now() {
            // Near-future phase alignment (widened +4 -> +8, see
            // `PROPOSAL_ALIGN_WINDOW_ROUNDS`): early delivery of a
            // GENUINE future proposal must align, not reject — the scan is
            // deliberate, pinned by test. Abuse is bounded elsewhere: the
            // jump runs through `sync_round_to`, which caps each jump at
            // ROUND_LOOKBACK and budgets MAX_SYNC_JUMPS_PER_ROUND jumps per
            // round (audit 2026-10-06; per-round since the wall-clock
            // budget removal), and
            // the body is signature-authenticated before this point, so only
            // the slot owner can pull us to their own slots.
            let mut target = None;
            for r in (self.hc.round.saturating_add(1))
                ..=(self.hc.round.saturating_add(PROPOSAL_ALIGN_WINDOW_ROUNDS))
            {
                if self.expected_proposer_at(&self.validators, self.hc.height, r)
                    == Some(block.proposer)
                {
                    target = Some(r);
                    break;
                }
            }
            match target {
                Some(r) => self.hc.sync_round_to(r),
                None => return Err("proposal: wrong proposer".to_string()),
            }
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
        let bh = block.compute_hash();
        let expected = self.expected_proposer_now();
        self.hc.receive_proposal_for(proposer, bh, expected)?;
        // Fork-choice: the proposal is recorded as a CANDIDATE before it is
        // finalized, so a competing branch is KNOWN. When it loses (another
        // block is finalized at this height) the blocks that lost can be
        // signalled instead of vanishing.
        self.record_candidate_block(&block);
        let _ = self.run_fork_choice();
        self.blocks.insert(bh, block);
        Ok(bh)
    }

    /// Build a vote signed by whichever signer is configured.
    pub(super) fn make_vote(&self, kind: VoteKind, target: Option<BlockHash>) -> Option<Vote> {
        self.make_vote_at(kind, target, self.hc.round)
    }

    /// Build a vote stamped with an explicit round. Precommits use the round
    /// of the POLKA they follow, not the local round: the decision needs the
    /// prevote QC and the precommit QC in the SAME bucket, and the two nodes
    /// are routinely one round apart (60% of sampled time on the live stand).
    pub(super) fn make_vote_at(
        &self,
        kind: VoteKind,
        target: Option<BlockHash>,
        round: Round,
    ) -> Option<Vote> {
        let msg = crate::consensus::vote_sign_bytes(self.hc.height, round, kind, &target);
        let sig = self.sign_bytes(&msg)?;
        let mut vote = Vote::signed_with(self.id, self.hc.height, round, kind, target, sig);

        let fk_ref = self.falcon_signing_key();
        if let Some(fk) = fk_ref {
            if self.deterministic_sim_signing {
                crate::consensus::attach_vote_falcon_deterministic(fk, &msg, &mut vote.signature);
            } else {
                crate::consensus::attach_vote_falcon(fk, &msg, &mut vote.signature);
            }
        }

        Some(vote)
    }

    pub fn make_prevote(&self) -> Option<Vote> {
        if self.hc.step != Step::Propose && self.hc.step != Step::Prevote {
            return None;
        }
        let target = self.hc.decide_prevote();
        self.make_vote(VoteKind::Prevote, target)
    }

    pub fn on_prevote(&mut self, v: Vote) -> Result<(), String> {
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
            self.note_peer_vote_round(v.height, v.round);
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
        // Cast at the polka's OWN round (Tendermint), not at `hc.round`.
        // The old rule ("the QC must be in my current round") meant that a
        // one-round skew -- the normal state of the two-node stand -- made BOTH
        // nodes refuse to precommit: each saw the QC one round behind, so a
        // full prevote QC never decided (31 of 180 wasted rounds, measured
        // live: prevote QC present, no precommit ever cast).
        //
        // The scan also runs the polka-UNLOCK rule (a polka for another block
        // at a higher round releases our lock), so it must run first.
        self.hc.try_prevote_quorum_at();
        // The precommit follows the newest POLKA -- a quorum of prevotes FOR A
        // BLOCK. It must NOT follow the newest quorum of any kind: a NIL
        // quorum (the network timed out in a later round) is not a polka and
        // used to SHADOW the real polka, so the node emitted a nil precommit
        // for the newer round instead of precommitting the certified block,
        // and the dedup key then suppressed the correct precommit forever.
        // Live 2026-10-21: the masterchain sat at height 285027 with a full
        // prevote QC formed and NO precommit QC.
        //
        // THE POLKA LEDGER (liveness fix, live 2026-10-21). `best_polka` is the
        // newest polka this node has OBSERVED -- the one whose quorum was
        // completed by a prevote that arrived -- or the newest one inside the
        // scan window, whichever is newer. The ledger is what makes a LATE
        // polka work: the quorum-completing prevote can arrive long after
        // this node raced ahead of the network, and a scan of the rounds
        // around the local counter cannot see that round at all. The live
        // cluster showed it exactly: the prevote QC for one block was in
        // every validator's vote set and only ONE of them ever cast a
        // precommit, so the precommit quorum never formed and the height
        // stayed parked for three days.
        let (qc_round, target) = self.hc.best_polka()?;
        let qc = self.hc.prevote_qc.get(&qc_round)?;
        if qc.block_hash != Some(target) {
            return None;
        }
        // SAFETY (lock rule): never precommit a block that contradicts our own
        // lock. The unlock rule above already released the lock when the
        // network certified a DIFFERENT block at a HIGHER round; a polka at or
        // below our lock round for another block is stale evidence and must
        // not be voted.
        if let Some((locked_block, locked_round)) = self.hc.locked {
            if locked_block != target && qc_round <= locked_round {
                return None;
            }
        }
        // Lock at the polka round too: the lock round is what the safety
        // check in `try_precommit_quorum` compares against.
        self.hc.locked = Some((target, qc_round));
        self.make_vote_at(VoteKind::Precommit, Some(target), qc_round)
    }

    pub fn on_precommit(&mut self, v: Vote) -> Result<(), String> {
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
            self.note_peer_vote_round(v.height, v.round);
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
        if self.validator_set_stale {
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
        self.validator_set_history.push_back((activation, vs));
        while self.validator_set_history.len() > VALIDATOR_SET_HISTORY_CAP {
            self.validator_set_history.pop_front();
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
        // A staged change already answers for heights at/above its
        // activation, even before the node advances there: the switch is
        // pre-agreed, not speculative.
        if let Some((activation, pending)) = &self.pending_validators {
            if *activation <= h {
                return pending.clone();
            }
        }
        if h >= self.hc.height {
            return self.validators.clone();
        }
        let mut best: Option<&ValidatorSet> = None;
        for (activation, vs) in &self.validator_set_history {
            if *activation <= h {
                best = Some(vs);
            }
        }
        best.cloned().unwrap_or_else(|| {
            self.validator_set_history
                .front()
                .map(|(_, vs)| vs.clone())
                .unwrap_or_else(|| self.validators.clone())
        })
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

    /// View change: move to the next round.
    pub fn next_round(&mut self) {
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
        // past. Deferred, not validated; the peer rebroadcasts (and catch-up
        // re-walks) until we are ready.
        if self.apply_in_flight.is_some() {
            return Err("committed block deferred: apply in flight".to_string());
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
        // FUTURE rounds are normally refused (forward sync owns them, not
        // adoption) — with ONE exception: a certificate from a round that is
        // STRICTLY LATER than our own lock is the proof that the network moved
        // on without us. That is exactly the case a locked node must follow
        // (adopting it is the SEC-01 fix); refusing it as "forward" left the
        // node partitioned from the canonical chain forever. The exception is
        // bounded by the same lookback, so a certificate from an absurdly far
        // future round is still refused, and it still has to pass the
        // validator-quorum verification below.
        let lock_supersedes = self
            .hc
            .locked
            .map(|(_, locked_round)| certificate.round > locked_round)
            .unwrap_or(false);
        if certificate.round != self.hc.round {
            let behind = self.hc.round.saturating_sub(certificate.round);
            let lookback = crate::consensus::ROUND_LOOKBACK as u64;
            let forward = certificate.round.saturating_sub(self.hc.round);
            let forward_ok = lock_supersedes && forward as u64 <= lookback;
            if (certificate.round > self.hc.round && !forward_ok)
                || behind as u64 > crate::consensus::MAX_SCAN_SPAN as u64
            {
                return Err(format!(
                    "certificate is for round {} not {} (lookback {lookback})",
                    certificate.round, self.hc.round
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
        // Single proposer signature before the quorum loop: one Ed25519 verify
        // filters forged bodies before paying per-signer QC cost.
        if !crate::consensus::verify_proposer_signature(&block) {
            return Err("committed block has no valid proposer signature".to_string());
        }
        if !certificate.binds_to_parent(&block.prev_hash) {
            return Err("commit certificate was elected with a different parent block".to_string());
        }
        if !self.verify_qc_for_height(&certificate, &validators) {
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
            let signed = validators.qc_signed_power(&certificate);
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
        if let Some((locked_block, locked_round)) = self.hc.locked {
            if certificate.round <= locked_round && locked_block != bh {
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
        self.check_order_commitment(&block)?;
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
        self.check_last_qc_evidence(&block)?;

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
        // the NEXT proposal embeds it as canonical downtime evidence.
        self.last_decision = Some((height, block.clone(), certificate));
        self.blocks.insert(bh, block.clone());
        self.apply_and_advance(bh, &block).await;
        Ok(bh)
    }
}
