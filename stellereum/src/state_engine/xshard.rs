use super::InMemoryStateEngine;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

impl InMemoryStateEngine {
    // ==================== M2: cross-shard gate and inbound credits ====================

    /// Turn on cross-shard execution for this engine. Called by
    /// `ValidatorRuntime::with_shard` exactly when the process runs more than one
    /// shard, so a single-shard engine never sees a behavioural change.
    pub fn enable_cross_shard(&self) {
        self.cross_shard_enabled
            .store(true, std::sync::atomic::Ordering::Release);
    }

    pub fn cross_shard_enabled(&self) -> bool {
        self.cross_shard_enabled
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// Attach the process-shared finalized-header registry (C1 anchor).
    /// Same `Arc` as every shard runtime in the process.
    pub fn with_finalized_headers(
        &self,
        registry: Arc<std::sync::RwLock<crate::sharding::FinalizedHeaderRegistry>>,
    ) {
        if let Ok(mut slot) = self.finalized_headers.write() {
            *slot = Some(registry);
        }
    }

    /// The process-shared finalized-header registry, if one is attached.
    ///
    /// The registry holds the full header (height, block hash, state root,
    /// timestamp) of every shard this process COMMITTED, and is written only
    /// by the block-application paths — never from gossip, RPC or DHT blobs.
    /// The RPC reads it to answer `stell_getShards` with heads this node
    /// actually applied. `None` on a node with no registry attached (most
    /// single-shard setups and the unit tests): the caller then falls back to
    /// its own chain's height / head / state root.
    pub fn finalized_headers(
        &self,
    ) -> Option<Arc<std::sync::RwLock<crate::sharding::FinalizedHeaderRegistry>>> {
        self.finalized_headers
            .read()
            .ok()
            .and_then(|slot| slot.clone())
    }

    /// Anchored inclusion check for one inbound message (C1): proof AND a
    /// locally-finalized source header with the claimed root. `false` covers
    /// both "forged" and "not finalized here yet" — callers treat it as
    /// not-ready (skip + retry after catching up), never as verified.
    /// A poisoned lock here would wedge every apply, so a failed lock read
    /// fails closed (false) instead of blocking.
    pub fn verify_cross_shard_anchored(&self, msg: &crate::sharding::CrossShardMessage) -> bool {
        let guard = self
            .finalized_headers
            .read()
            .ok()
            .and_then(|slot| slot.clone());
        let Some(reg_arc) = guard else {
            return false;
        };
        let inner = reg_arc.read().ok();
        let Some(reg) = inner.as_deref() else {
            return false;
        };
        msg.verify_anchored(Some(reg))
    }

    /// True once the given message has been credited on this shard.
    pub async fn is_cross_shard_consumed(&self, key: &crate::sharding::CrossShardKey) -> bool {
        self.cross_shard_consumed.read().await.contains(key)
    }

    /// How many inbound cross-shard messages this engine has credited. A
    /// replay attempt must not move this number.
    pub async fn cross_shard_consumed_len(&self) -> usize {
        self.cross_shard_consumed.read().await.len()
    }

    /// Snapshot the engine's consumed set for persistence (audit F-I), sorted
    /// for deterministic bytes. The set gates the actual credit at apply time;
    /// without persisting it a restart re-opened every consumed message for a
    /// second credit (the runtime mirrors alone cannot stop the apply).
    pub async fn cross_shard_consumed_snapshot(&self) -> Vec<crate::sharding::CrossShardKey> {
        let mut v: Vec<crate::sharding::CrossShardKey> = self
            .cross_shard_consumed
            .read()
            .await
            .iter()
            .copied()
            .collect();
        v.sort();
        v
    }

    /// Install persisted consumed keys (startup restore). Extends (never
    /// replaces: a live set may already hold entries committed after the
    /// snapshot was taken). Bumps the commitment generation: the set IS folded
    /// into the digest (audit F1), so restoring it moves the root exactly as
    /// re-applying the consuming blocks would.
    pub async fn restore_cross_shard_consumed(&self, keys: &[crate::sharding::CrossShardKey]) {
        self.cross_shard_consumed
            .write()
            .await
            .extend(keys.iter().copied());
        self.bump_domain_generation(crate::commitment::Domain::CrossShard);
    }

    /// How many outbound cross-shard transfers this engine has recorded.
    pub async fn cross_shard_produced_len(&self) -> usize {
        self.cross_shard_produced.read().await.len()
    }

    /// How many cross-shard lifecycles this engine has seen complete.
    pub async fn cross_shard_completed_len(&self) -> usize {
        self.cross_shard_completed.read().await.len()
    }

    // ============ §9 CROSS-SHARD 2PC ============

    /// The §9 two-phase-commit record of one transfer, if this shard owns it.
    pub async fn xpc_record(&self, tx_hash: &[u8; 32]) -> Option<crate::xshard2pc::XpcRecord> {
        self.cross_shard_xpc.read().await.get(tx_hash).cloned()
    }

    /// Every §9 two-phase-commit record this shard owns, sorted by the
    /// transaction hash (deterministic bytes for the snapshot).
    pub async fn xpc_snapshot(&self) -> Vec<crate::xshard2pc::XpcRecord> {
        let mut v: Vec<crate::xshard2pc::XpcRecord> = self
            .cross_shard_xpc
            .read()
            .await
            .values()
            .cloned()
            .collect();
        v.sort_by_key(|r| r.tx_hash);
        v
    }

    /// How many §9 two-phase-commit records this shard owns.
    pub async fn xpc_len(&self) -> usize {
        self.cross_shard_xpc.read().await.len()
    }

    /// The Merkle inclusion proof of the §9 2PC state leaf of one transfer,
    /// in this shard's state trie.
    ///
    /// This is what the peer shard verifies: the proof binds the phase this
    /// shard committed to (PREPARED / COMMITTED / ABORTED) to a state root
    /// this shard's quorum signed, so the peer's vote (PREPARE-ACK /
    /// ABORT-ACK) or decision (COMMIT) cannot be forged.
    pub async fn get_xpc_proof(&self, tx_hash: &[u8; 32]) -> Option<crate::cell::MerkleProof> {
        let key = crate::xshard2pc::xpc_state_key(tx_hash);
        self.state_trie.read().await.generate_merkle_proof(&key)
    }

    /// Install persisted §9 two-phase-commit records (startup restore).
    ///
    /// Extends (never replaces) the live map, and RE-INSERTS the state-trie
    /// leaf of every restored record: the trie is rebuilt from the accounts
    /// alone on a snapshot restore, so without this the peer's proofs (which
    /// are Merkle proofs of that leaf) would stop verifying after a restart
    /// and a prepared transfer could never be completed.
    pub async fn restore_xpc_records(&self, records: &[crate::xshard2pc::XpcRecord]) {
        if records.is_empty() {
            return;
        }
        let installed: Vec<crate::xshard2pc::XpcRecord> = {
            let mut map = self.cross_shard_xpc.write().await;
            records
                .iter()
                .map(|rec| {
                    map.entry(rec.tx_hash)
                        .or_insert_with(|| rec.clone())
                        .clone()
                })
                .collect()
        };
        {
            let mut trie = self.state_trie.write().await;
            for rec in &installed {
                let key = crate::xshard2pc::xpc_state_key(&rec.tx_hash);
                let value = crate::xshard2pc::xpc_state_value(rec.phase, &rec.tx_hash);
                trie.insert(&key, &value);
            }
        }
        // The 2PC map moved: bump its domain (global moves with it).
        self.bump_domain_generation(crate::commitment::Domain::Xpc);
    }

    /// Write a §9 two-phase-commit record: the committed map AND the
    /// state-trie leaf that the peer's proofs are made against.
    ///
    /// The two are written together so the leaf can never disagree with the
    /// map: a peer that proves the leaf proves the map's phase, and the map
    /// is what the commitment digest covers.
    pub(crate) async fn write_xpc_record(&self, rec: &crate::xshard2pc::XpcRecord) {
        {
            let mut map = self.cross_shard_xpc.write().await;
            map.insert(rec.tx_hash, rec.clone());
        }
        {
            let mut trie = self.state_trie.write().await;
            let key = crate::xshard2pc::xpc_state_key(&rec.tx_hash);
            let value = crate::xshard2pc::xpc_state_value(rec.phase, &rec.tx_hash);
            trie.insert(&key, &value);
        }
        self.bump_domain_generation(crate::commitment::Domain::Xpc);
    }

    /// True once an ack or bounce for `tx_hash` committed on this chain.
    pub async fn is_cross_shard_completed(&self, tx_hash: &[u8; 32]) -> bool {
        self.cross_shard_completed.read().await.contains(tx_hash)
    }

    /// Snapshot the engine's produced map for persistence, sorted by tx hash
    /// for deterministic bytes.
    pub async fn cross_shard_produced_snapshot(&self) -> Vec<([u8; 32], u64)> {
        let mut v: Vec<([u8; 32], u64)> = self
            .cross_shard_produced
            .read()
            .await
            .iter()
            .map(|(h, height)| (*h, *height))
            .collect();
        v.sort();
        v
    }

    /// Snapshot the engine's completed set for persistence, sorted for
    /// deterministic bytes.
    pub async fn cross_shard_completed_snapshot(&self) -> Vec<[u8; 32]> {
        let mut v: Vec<[u8; 32]> = self
            .cross_shard_completed
            .read()
            .await
            .iter()
            .copied()
            .collect();
        v.sort();
        v
    }

    /// Install a full persisted replay snapshot (snapshot-sync / startup
    /// restore). Extends every set, never replaces - same contract as
    /// `restore_cross_shard_consumed`, applied to all three committed sets at
    /// once so a partial install cannot leave the digest half-moved.
    ///
    /// Both the engine half (`engine_consumed`) and the runtime mirror half
    /// (`runtime_consumed`) feed the consumed set: on an honest chain the two
    /// coincide (the runtime mirrors exactly what the engine credited, plus
    /// the linkage-checked control records the engine records itself), and the
    /// union is idempotent. Produced heights keep first-wins (`or_insert`,
    /// the live path's rule), so reinstalling an older blob over newer live
    /// state cannot re-date an outbound.
    pub async fn restore_cross_shard_replay(
        &self,
        snap: &crate::sharding::CrossShardReplaySnapshot,
    ) {
        self.cross_shard_consumed
            .write()
            .await
            .extend(snap.engine_consumed.iter().copied());
        self.cross_shard_consumed
            .write()
            .await
            .extend(snap.runtime_consumed.iter().copied());
        {
            let mut produced = self.cross_shard_produced.write().await;
            for (h, _tx, height) in &snap.produced {
                produced.entry(*h).or_insert(*height);
            }
        }
        self.cross_shard_completed
            .write()
            .await
            .extend(snap.completed.iter().copied());
        // §9 2PC: the two-phase-commit records are restored too, and their
        // state-trie leaves are re-inserted, so a node that restarts
        // mid-2PC resumes to the SAME decision (and the peer's proofs of
        // this shard's vote still verify).
        self.restore_xpc_records(&snap.xpc).await;
        // The replay sets moved (`restore_xpc_records` already moved Xpc):
        // bump their domain (global moves with it).
        self.bump_domain_generation(crate::commitment::Domain::CrossShard);
    }

    /// True when the incoming snapshot provably covers the local replay
    /// state: every locally consumed key, every locally produced outbound
    /// (with the SAME produce height - a height disagreement means the two
    /// sides applied different chains) and every locally completed lifecycle
    /// is present incoming. Snapshot install may only fast-forward on `true`;
    /// anything else must be refused loudly, never silently dropped or
    /// silently kept (keeping would fork the root, dropping would double
    /// mint).
    pub async fn cross_shard_replay_covers(
        &self,
        snap: &crate::sharding::CrossShardReplaySnapshot,
    ) -> bool {
        let consumed = self.cross_shard_consumed.read().await;
        let incoming_consumed: HashSet<crate::sharding::CrossShardKey> = snap
            .engine_consumed
            .iter()
            .chain(snap.runtime_consumed.iter())
            .copied()
            .collect();
        if !consumed.iter().all(|k| incoming_consumed.contains(k)) {
            return false;
        }
        let produced = self.cross_shard_produced.read().await;
        let mut incoming_heights: HashMap<[u8; 32], u64> = HashMap::new();
        for (h, _tx, height) in &snap.produced {
            incoming_heights.entry(*h).or_insert(*height);
        }
        for (h, height) in produced.iter() {
            match incoming_heights.get(h) {
                Some(in_h) if in_h == height => {}
                _ => return false,
            }
        }
        let completed = self.cross_shard_completed.read().await;
        let incoming_completed: HashSet<[u8; 32]> = snap.completed.iter().copied().collect();
        if !completed.iter().all(|h| incoming_completed.contains(h)) {
            return false;
        }
        // §9 2PC: the committed two-phase-commit records must be covered too.
        // A snapshot that does not carry them would re-open a decided
        // transfer (the phase decides where the value is), so the coverage
        // gate refuses it exactly like the consumed set.
        let xpc = self.cross_shard_xpc.read().await;
        let incoming_xpc: HashMap<[u8; 32], crate::xshard2pc::XpcPhase> =
            snap.xpc.iter().map(|r| (r.tx_hash, r.phase)).collect();
        for (tx_hash, rec) in xpc.iter() {
            match incoming_xpc.get(tx_hash) {
                Some(phase) if *phase == rec.phase => {}
                _ => return false,
            }
        }
        true
    }

    /// Credit every INBOUND cross-shard message this block commits to, in the
    /// block's own order, exactly once. Also records the block's OUTBOUND
    /// transfers (produced) and its linkage-valid ack/bounce completions, so
    /// the committed replay sets derive deterministically from applied blocks.
    ///
    /// A block only ever carries an inbound record for the shard it belongs to
    /// (a source block carries outbound records, which are applied by the
    /// transaction path, not here). Each credit requires the message's Merkle
    /// inclusion proof against the source state root — the local `trusted`
    /// shortcut is IGNORED because the flag is part of attacker-supplied block
    /// content. The replay key is inserted only after the credit succeeds, so a
    /// duplicate cannot mint a second time.
    ///
    /// Recording rules (all deterministic functions of the block, hence
    /// identical on every node that applied it):
    /// * produced: every transfer that is outbound for this block's shard,
    ///   first height wins - the same predicate the runtime uses, recorded
    ///   BEFORE the inbound pass so same-block linkage reads it, exactly like
    ///   the runtime's apply order;
    /// * consumed (transfers): unchanged - proof-checked credit, key inserted
    ///   only on success;
    /// * consumed + completed (acks/bounces): the runtime's linkage rule,
    ///   mirrored - proof-less, untrusted, produced entry known, lifecycle not
    ///   already complete, bounce past the height timeout - processed in the
    ///   same deterministic key order. NO value movement: the bounce refund
    ///   stays the runtime's job; the engine only records, never pays, so a
    ///   recorded bounce can never double-pay against the runtime's refund.
    pub async fn apply_cross_shard_consumptions(&self, block: &crate::sharding::Block) -> usize {
        if !self.cross_shard_enabled() || block.cross_shard_out.is_empty() {
            return 0;
        }
        let mut mutated = false;
        // Produced first: same-block linkage reads the map including this
        // block's own outbounds, exactly like the runtime's apply order.
        {
            let mut produced = self.cross_shard_produced.write().await;
            for msg in &block.cross_shard_out {
                if msg.is_transfer() && msg.is_outbound_for(block.shard_id) {
                    let tx_hash = msg.tx.compute_tx_hash();
                    if let std::collections::hash_map::Entry::Vacant(e) = produced.entry(tx_hash) {
                        e.insert(block.height);
                        mutated = true;
                    }
                }
            }
        }
        // §9 2PC, SOURCE side: the PREPARED state of a transfer this block
        // produces is recorded in `apply_xpc_source_prepares` - AFTER the
        // transactions of this block have been applied, because the record
        // means "the value is ESCROWED here" and that is only true when the
        // escrow transaction actually applied (a transaction the block
        // carries but that was REFUSED at apply time debits nobody, so a
        // record written for it would let the peer credit a value that was
        // never escrowed - a mint). The peer shard proves this record (the
        // COMMIT record carries a Merkle proof of this leaf), and a restart
        // resumes the same decision.
        //
        // Deterministic order: sort by the replay key, so two independently
        // assembled target nodes that received the same set of messages derive
        // the same credit order and therefore the same state root, regardless
        // of KV enumeration order.
        let mut inbound: Vec<&crate::sharding::CrossShardMessage> = block
            .cross_shard_out
            .iter()
            .filter(|m| m.is_inbound_for(block.shard_id))
            .collect();
        inbound.sort_by_key(|m| crate::sharding::CrossShardKey::of(m));

        let mut credited = 0usize;
        for msg in inbound {
            let key = crate::sharding::CrossShardKey::of(msg);
            if msg.is_xpc() {
                // §9 2PC: the intermediate states. Every transition is a pure
                // function of the committed record, so a replay is a no-op and
                // a crash mid-2PC resumes to the SAME decision.
                if self.apply_xpc_record(msg, block.height).await {
                    mutated = true;
                }
                // The replay key is recorded for every 2PC record that reached
                // a terminal phase, so the audit trail (and the digest) show
                // which lifecycles were decided.
                continue;
            }
            if msg.is_ack() || msg.is_bounce() {
                // Control record: linkage-checked bookkeeping only, never a
                // credit. Mirrors `ValidatorRuntime::control_linkage_ok` at
                // apply height: proof-carrying control records are refused
                // (the engine would otherwise credit them to `tx.to` on the
                // source shard - a mint), unknown produced entries fail
                // closed, an already-completed lifecycle is skipped, and a
                // premature bounce waits for its timeout. Same-block
                // ack+bounce for one transaction resolves first-in-key-order,
                // exactly like the runtime: the consumed insert lands before
                // the completed insert, and the second record finds the
                // lifecycle complete.
                if msg.merkle_inclusion_proof.is_some() || msg.trusted {
                    continue;
                }
                let tx_hash = msg.tx.compute_tx_hash();
                {
                    let produced = self.cross_shard_produced.read().await;
                    let Some(produce_height) = produced.get(&tx_hash) else {
                        continue;
                    };
                    if msg.is_bounce()
                        && !crate::sharding::bounce_eligible(*produce_height, block.height)
                    {
                        continue;
                    }
                }
                if self.cross_shard_completed.read().await.contains(&tx_hash) {
                    continue;
                }
                {
                    let mut consumed = self.cross_shard_consumed.write().await;
                    if !consumed.insert(key) {
                        continue;
                    }
                }
                mutated = true;
                if !self.cross_shard_completed.write().await.insert(tx_hash) {
                    continue;
                }
                mutated = true;
                continue;
            }
            if self.is_cross_shard_consumed(&key).await {
                continue;
            }
            // ANCHORED + SIGNED credit (cross-shard integrity hardening): the
            // legacy credit path anchors the message to a LOCALLY FINALIZED
            // source header (via `verify_cross_shard_anchored`: proof AND a
            // committed source root) instead of checking the proof alone. A
            // self-attested root (attacker trie + valid-for-that-root proof)
            // names no committed header and is refused here.
            //
            // Fail-closed NOT-READY: a missing registry (single-shard
            // contexts, most unit tests) or an unfinalized source header
            // SKIPS the credit (never credits, never marks consumed), exactly
            // like a bad proof. The carrying block's QC is NOT the trust for
            // the message body: the quorum signs the block hash, and the
            // block hash binds the full message bytes, but only the source
            // shard's finalized header proves the claimed state root existed.
            //
            // PQ-only (live rule): the carried transaction must pass
            // `tx.verify_signature()` — a legacy Ed cross-shard message is
            // refused here, never credited.
            if !msg.verify_msg_id() {
                continue;
            }
            if !msg.tx.verify_signature() {
                continue;
            }
            if !self.verify_cross_shard_anchored(msg) {
                continue;
            }
            if !msg.verify_inclusion_strict() {
                continue;
            }
            if self.credit_native(&msg.tx.to, msg.tx.amount).await.is_err() {
                continue;
            }
            self.cross_shard_consumed.write().await.insert(key);
            mutated = true;
            credited += 1;
        }
        if mutated {
            // The replay sets are digest-covered (audit F1): any mutation must
            // move the commitment generation, or the next root read serves a
            // stale digest that cannot see the consume/produce/complete.
            // The domain bump moves the global with it.
            self.bump_domain_generation(crate::commitment::Domain::CrossShard);
        }
        if credited > 0 {
            tracing::info!(
                "cross-shard inbound credited {credited} message(s) on shard {}",
                block.shard_id
            );
        }
        credited
    }

    /// §9 2PC, SOURCE side: record the PREPARED state of every transfer this
    /// block ESCROWED.
    ///
    /// Called AFTER the block's transactions have been applied, because the
    /// record means exactly one thing: "the value of this transfer is
    /// escrowed on this shard". That is only true when the escrow
    /// transaction APPLIED - a transaction the block carries but that was
    /// refused at apply time (a stale nonce, an insufficient balance, a
    /// vesting lock) debits nobody, and a PREPARED record written for it
    /// would let the peer shard credit a value that was never escrowed: a
    /// MINT. So the record is written only for the transfers whose
    /// transaction really applied (`status[i] == true`).
    ///
    /// The record is written into the committed state (the map AND the state
    /// trie leaf), so:
    ///
    ///  * the peer shard can PROVE it - the COMMIT record carries a Merkle
    ///    proof of this leaf, and the peer credits the recipient only
    ///    against that proof, so the credit is backed by the source's
    ///    committed escrow and not by a claim;
    ///  * a restart resumes to the SAME decision (the record is part of the
    ///    committed state, the digest and the persisted replay blob).
    ///
    /// Idempotent: a re-published PREPARE for a transfer that is already
    /// PREPARED is a no-op (the phase is monotone), so the source can
    /// re-publish the PREPARE as often as it likes.
    pub async fn apply_xpc_source_prepares(
        &self,
        block: &crate::sharding::Block,
        status: &[bool],
    ) -> usize {
        if !self.cross_shard_enabled() {
            return 0;
        }
        let mut created = 0usize;
        for msg in &block.cross_shard_out {
            if !msg.is_prepare() || !msg.is_outbound_for(block.shard_id) {
                continue;
            }
            let tx = &msg.tx;
            let tx_hash = tx.compute_tx_hash();
            // The escrow transaction must be in this block AND must have
            // applied. A PREPARE without its transaction is refused (the
            // proposal path refuses it too), and a transaction that was
            // refused at apply time escrows nothing.
            let Some(idx) = block
                .transactions
                .iter()
                .position(|t| t.compute_tx_hash() == tx_hash)
            else {
                continue;
            };
            if !status.get(idx).copied().unwrap_or(false) {
                continue;
            }
            let existing = self.xpc_record(&tx_hash).await;
            if crate::xshard2pc::source_prepare(existing.as_ref())
                != crate::xshard2pc::XpcTransition::Created
            {
                continue;
            }
            let rec = crate::xshard2pc::XpcRecord::prepared(
                tx.clone(),
                tx.source_shard,
                tx.target_shard,
                block.height,
            );
            self.write_xpc_record(&rec).await;
            created += 1;
        }
        created
    }

    /// Apply ONE inbound §9 two-phase-commit record to this shard's
    /// committed 2PC state. Returns true when the committed state changed.
    ///
    /// The record is the WHOLE state machine: every transition is a pure
    /// function of the committed record plus the message, so
    ///
    /// * a REPLAY of a record that was already applied is a no-op (the
    ///   record's phase is already past the transition), and
    /// * a CRASH mid-2PC resumes to the same decision, because the decision
    ///   lives in the committed record and not in the node's memory.
    ///
    /// The value movements live here too, so they are part of the canonical
    /// state transition (and therefore of the reorg replay path):
    ///
    /// * the TARGET credits the recipient exactly once, on the
    ///   `Prepared -> Committed` transition;
    /// * the SOURCE refunds the escrow exactly once, on the
    ///   `Prepared -> Aborted` transition.
    async fn apply_xpc_record(
        &self,
        msg: &crate::sharding::CrossShardMessage,
        height: u64,
    ) -> bool {
        use crate::sharding::CrossShardKind;
        use crate::xshard2pc::{XpcPhase, XpcRecord, XpcTransition};
        // ANCHORED 2PC apply (cross-shard integrity hardening): EVERY phase
        // verifies proof-only no more. The message must anchor to a LOCALLY
        // FINALIZED header of the peer shard (`verify_xpc_anchored`
        // semantics: anchor AND phase proof), read from the process-shared
        // `FinalizedHeaderRegistry` this engine was given via
        // `with_finalized_headers` — the same `Arc` every shard runtime in
        // the process holds, never a global.
        //
        // Fail-closed NOT-READY: a missing registry, a poisoned lock, or an
        // unfinalized source header returns false (no state change, never
        // verified) — the caller treats it exactly like a bad proof. The
        // `msg_id` is recomputed at this apply boundary first: a rebound id
        // is refused before any registry or trie work. The lock guard below
        // is dropped before any await (the anchor verdict is a bool), so no
        // async path ever holds the std registry lock across a yield.
        if !msg.verify_msg_id() {
            return false;
        }
        let anchor_ok = {
            let slot = self
                .finalized_headers
                .read()
                .ok()
                .and_then(|guard| guard.clone());
            let Some(reg_arc) = slot else {
                return false;
            };
            let Ok(reg) = reg_arc.read() else {
                return false;
            };
            reg.anchor_holds(
                msg.source_shard,
                &msg.finalized_in_block,
                &msg.source_state_root,
            )
        };
        if !anchor_ok {
            return false;
        }
        let tx = &msg.tx;
        let tx_hash = tx.compute_tx_hash();
        let existing = self.xpc_record(&tx_hash).await;
        match msg.kind() {
            // TARGET side: the source escrowed the value and asks us to
            // prepare. The proof is EITHER the SOURCE's account leaf (the
            // opening PREPARE - it proves the sender really had the funds at
            // the source's committed root) OR the SOURCE's PREPARED leaf
            // (the re-published PREPARE - it proves the value is already
            // escrowed at the source, which is the stronger statement).
            CrossShardKind::Prepare => {
                if !msg.verify_inclusion_strict() && !msg.verify_xpc_proof(&[XpcPhase::Prepared]) {
                    return false;
                }
                if !msg.tx.verify_signature() {
                    return false;
                }
                let transition = crate::xshard2pc::target_prepare(existing.as_ref());
                if transition != XpcTransition::Created {
                    return false;
                }
                let rec = XpcRecord::prepared(tx.clone(), tx.source_shard, tx.target_shard, height);
                self.write_xpc_record(&rec).await;
                true
            }
            // SOURCE side: the target voted YES. The proof is the TARGET's
            // PREPARED leaf, so the vote is a fact of the target's committed
            // state (and not a claim the source could forge).
            CrossShardKind::PrepareAck => {
                if !msg.verify_xpc_proof(&[XpcPhase::Prepared]) {
                    return false;
                }
                let transition = crate::xshard2pc::source_on_prepare_ack(existing.as_ref());
                if transition != XpcTransition::Advanced(XpcPhase::Committed) {
                    return false;
                }
                let Some(mut rec) = existing else {
                    return false;
                };
                rec.phase = XpcPhase::Committed;
                rec.decided_height = height;
                self.write_xpc_record(&rec).await;
                self.cross_shard_completed.write().await.insert(tx_hash);
                true
            }
            // TARGET side: the source decided COMMIT. The proof is the
            // SOURCE's PREPARED (or already COMMITTED) leaf: the source
            // really escrowed the value, so this is not a mint.
            CrossShardKind::Commit => {
                if !msg.verify_xpc_proof(&[XpcPhase::Prepared, XpcPhase::Committed]) {
                    return false;
                }
                // PQ-only on the TARGET-side credit (live rule): the carried
                // transaction must pass `tx.verify_signature()` — a legacy Ed
                // COMMIT is refused, never credited. (The anchor + `msg_id`
                // gates above already ran for this arm.)
                if !msg.tx.verify_signature() {
                    return false;
                }
                let transition = crate::xshard2pc::target_on_commit(existing.as_ref());
                if transition != XpcTransition::Advanced(XpcPhase::Committed) {
                    return false;
                }
                let Some(mut rec) = existing else {
                    return false;
                };
                // THE credit. Only reachable from PREPARED, so the recipient
                // is credited exactly once and never for an aborted transfer.
                if self.credit_native(&tx.to, tx.amount).await.is_err() {
                    return false;
                }
                rec.phase = XpcPhase::Committed;
                rec.decided_height = height;
                self.write_xpc_record(&rec).await;
                self.cross_shard_completed.write().await.insert(tx_hash);
                true
            }
            // TARGET side: the source asks us to abort. The proof is the
            // SOURCE's PREPARED leaf. A target that is already PREPARED
            // REFUSES: it has voted YES, and a 2PC participant that voted YES
            // must commit. That refusal is what blocks the double spend.
            CrossShardKind::AbortRequest => {
                if !msg.verify_xpc_proof(&[XpcPhase::Prepared, XpcPhase::Committed]) {
                    return false;
                }
                let transition = crate::xshard2pc::target_on_abort_request(existing.as_ref());
                if transition != XpcTransition::Advanced(XpcPhase::Aborted) {
                    return false;
                }
                let rec = XpcRecord {
                    tx: tx.clone(),
                    tx_hash,
                    source_shard: tx.source_shard,
                    target_shard: tx.target_shard,
                    phase: XpcPhase::Aborted,
                    prepared_height: height,
                    decided_height: height,
                };
                self.write_xpc_record(&rec).await;
                true
            }
            // SOURCE side: the target authorises the abort. The proof is the
            // TARGET's ABORTED leaf - and the target can only hold that leaf
            // if it NEVER prepared, so a source that got a PREPARE-ACK can
            // never obtain this authorisation. THIS is the block on the
            // audit's double-spend attack.
            CrossShardKind::AbortAck => {
                if !msg.verify_xpc_proof(&[XpcPhase::Aborted]) {
                    return false;
                }
                let transition = crate::xshard2pc::source_on_abort_ack(existing.as_ref());
                if transition != XpcTransition::Advanced(XpcPhase::Aborted) {
                    return false;
                }
                let Some(mut rec) = existing else {
                    return false;
                };
                // THE refund: the escrow goes back to the sender, exactly
                // once. A transfer that is already COMMITTED never reaches
                // this arm (the transition is refused above).
                if self.credit_native(&tx.from, tx.amount).await.is_err() {
                    return false;
                }
                rec.phase = XpcPhase::Aborted;
                rec.decided_height = height;
                self.write_xpc_record(&rec).await;
                self.cross_shard_completed.write().await.insert(tx_hash);
                true
            }
            _ => false,
        }
    }

    /// Take and drain all queued outbound cross-shard messages.
    pub async fn take_cross_shard_out(&self) -> Vec<crate::sharding::CrossShardMessage> {
        let mut out = self.cross_shard_out.write().await;
        std::mem::take(&mut *out)
    }

    /// Retrieve a snapshot of queued outbound cross-shard messages without draining.
    pub async fn get_cross_shard_out(&self) -> Vec<crate::sharding::CrossShardMessage> {
        self.cross_shard_out.read().await.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::super::AccountState;
    use super::*;
    use crate::post_quantum::{
        derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT, FALCON512_SIG_LEN,
    };
    use crate::sharding::{Block, CrossShardMessage, FinalizedHeaderRegistry, Transaction};
    use crate::xshard2pc::{XpcPhase, XPC_PREPARE};

    #[tokio::test]
    async fn unsigned_xpc_prepare_is_rejected() {
        let kp = FalconKeypair::generate_from_seed(33);
        let sender_addr = derive_pq_address(PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT);
        let recipient = [0x77u8; 32];
        let initial_bal = 5_000_000_000u64;

        // Build a valid source state + trie proof + finalized header anchor so
        // ONLY the transaction signature distinguishes the two prepares.
        let source = InMemoryStateEngine::new();
        source
            .update_account(AccountState::new(sender_addr, initial_bal))
            .await;
        source
            .pin_pubkey(
                sender_addr,
                PqScheme::Falcon512,
                &kp.public_key,
                &DEFAULT_SALT,
            )
            .await
            .expect("pin pq key");
        let source_root = source.get_state_root().await;
        let proof = source.get_account_proof(&sender_addr).await;
        let pk_hash = source
            .get_account(&sender_addr)
            .await
            .and_then(|a| a.pubkey_hash)
            .expect("pinned pq pubkey hash");
        let anchor_block = [0xABu8; 32];

        let reg = Arc::new(std::sync::RwLock::new(FinalizedHeaderRegistry::default()));
        reg.write()
            .unwrap()
            .note_finalized(0, anchor_block, source_root);

        let target = InMemoryStateEngine::new();
        target.enable_cross_shard();
        target.with_finalized_headers(reg);

        // 1) Unsigned XPC_PREPARE with valid anchor + valid inclusion proof -> REFUSED.
        let unsigned_tx = Transaction {
            from: sender_addr,
            to: recipient,
            amount: 1_000_000,
            gas_limit: 280_000,
            nonce: 0,
            source_shard: 0,
            target_shard: 1,
            signature: vec![],
            payload: vec![],
            priority_fee_per_gas: 0,
        };
        let unsigned_hash = unsigned_tx.compute_tx_hash();
        let unsigned_prepare = CrossShardMessage::new_xpc(
            XPC_PREPARE,
            0,
            1,
            unsigned_tx,
            source_root,
            anchor_block,
            proof.clone(),
        )
        .with_source_balance(initial_bal)
        .with_sender_pubkey_hash(PqScheme::Falcon512.id(), pk_hash);
        assert!(
            unsigned_prepare.verify_inclusion_strict(),
            "precondition: proof itself is valid so signature check is isolated"
        );
        let block_bad = Block {
            shard_id: 1,
            height: 1,
            prev_hash: [0u8; 32],
            state_root: [0u8; 32],
            transactions: vec![],
            cross_shard_out: vec![unsigned_prepare],
            timestamp: 1_770_000_001,
            proposer: [0x11; 32],
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
        };
        target.apply_cross_shard_consumptions(&block_bad).await;
        assert!(
            target.xpc_record(&unsigned_hash).await.is_none(),
            "unsigned XPC_PREPARE must be rejected"
        );

        // 2) Signed XPC_PREPARE with identical anchor + proof -> ACCEPTED.
        let probe = Transaction::new_pq_explicit(
            PqScheme::Falcon512,
            kp.public_key.clone(),
            vec![0u8; FALCON512_SIG_LEN],
            recipient,
            1_000_000,
            280_000,
            0,
            0,
            1,
            vec![],
            &DEFAULT_SALT,
        );
        let sig = kp.sign(&probe.signing_message());
        let signed_tx = Transaction::new_pq_explicit(
            PqScheme::Falcon512,
            kp.public_key.clone(),
            sig,
            recipient,
            1_000_000,
            280_000,
            0,
            0,
            1,
            vec![],
            &DEFAULT_SALT,
        );
        let signed_hash = signed_tx.compute_tx_hash();
        let signed_prepare = CrossShardMessage::new_xpc(
            XPC_PREPARE,
            0,
            1,
            signed_tx,
            source_root,
            anchor_block,
            proof,
        )
        .with_source_balance(initial_bal)
        .with_sender_pubkey_hash(PqScheme::Falcon512.id(), pk_hash);
        let block_ok = Block {
            cross_shard_out: vec![signed_prepare],
            ..block_bad
        };
        target.apply_cross_shard_consumptions(&block_ok).await;
        assert_eq!(
            target.xpc_record(&signed_hash).await.map(|r| r.phase),
            Some(XpcPhase::Prepared),
            "signed XPC_PREPARE must be accepted"
        );
    }
}
