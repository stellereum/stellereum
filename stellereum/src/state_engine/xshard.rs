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

    /// Anchored ESCROW/DEBIT check for one inbound LEGACY value transfer
    /// (XSHARD-01).
    ///
    /// This is the only proof an inbound legacy credit may be paid against:
    /// a Merkle proof of the SOURCE's escrow record for the transfer
    /// ([`crate::sharding::xshard_escrow_state_key`]) verified against a state
    /// root that a locally finalized source header committed to. The record is
    /// written by the source's apply path (`record_legacy_escrow_receipts`)
    /// only when the escrow transaction actually applied, so it proves the
    /// source DEBITED the sender. The old rule
    /// ([`Self::verify_cross_shard_anchored`]) proves only that the sender
    /// could AFFORD the amount before the transfer, which a colluding target
    /// proposer can pair with a signed-but-never-applied transaction to mint.
    ///
    /// `false` covers "forged", "not escrowed at the named source block" and
    /// "not finalized here yet" — every caller must treat it as NOT-READY and
    /// never credit, never claim the replay key. A missing or poisoned
    /// registry fails closed.
    pub fn verify_cross_shard_escrow_anchored(
        &self,
        msg: &crate::sharding::CrossShardMessage,
    ) -> bool {
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
        msg.verify_escrow_anchored(Some(reg))
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

    /// The Merkle inclusion proof of the SOURCE-side escrow/debit record of one
    /// legacy cross-shard transfer (XSHARD-01).
    ///
    /// This is what a target verifies before paying an inbound legacy credit:
    /// the leaf is written by [`Self::record_legacy_escrow_receipts`] only when
    /// the escrow transaction applied, so the proof says "the source DEBITED
    /// the sender for this transfer", not merely "the sender could afford it".
    pub async fn get_legacy_escrow_proof(
        &self,
        tx_hash: &[u8; 32],
    ) -> Option<crate::cell::MerkleProof> {
        let key = crate::sharding::xshard_escrow_state_key(tx_hash);
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
        let mut refused = 0usize;
        let installed: Vec<crate::xshard2pc::XpcRecord> = {
            let mut map = self.cross_shard_xpc.write().await;
            records
                .iter()
                .filter(|rec| {
                    // FAIL CLOSED: a record whose own bytes disagree (wrong
                    // shard pair, wrong tx hash, a decision before the
                    // prepare, a decision height on a PREPARED record) is
                    // never installed. Installing it would re-open a decided
                    // transfer with a phase the chain never committed to.
                    if rec.is_consistent() {
                        true
                    } else {
                        refused += 1;
                        false
                    }
                })
                .map(|rec| {
                    map.entry(rec.tx_hash)
                        .or_insert_with(|| rec.clone())
                        .clone()
                })
                .collect()
        };
        if refused > 0 {
            tracing::warn!("[xpc] refused {refused} inconsistent 2PC record(s) on restore");
        }
        if installed.is_empty() {
            return;
        }
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
    /// is what the commitment digest covers. An INCONSISTENT record (see
    /// [`crate::xshard2pc::XpcRecord::is_consistent`]) is refused outright:
    /// writing it would bind a state leaf to a transaction it does not
    /// describe. Returns `true` only when the record was committed.
    pub(crate) async fn write_xpc_record(&self, rec: &crate::xshard2pc::XpcRecord) -> bool {
        if !rec.is_consistent() {
            tracing::warn!(
                "[xpc] refusing to write an inconsistent 2PC record (tx {:?})",
                rec.tx_hash
            );
            return false;
        }
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
        true
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
        // XSHARD-01: the PRODUCED outbounds carry their full transaction, so
        // the source-side escrow/debit leaf of every one of them is re-derived
        // here exactly as the block that produced it derived it. Without this
        // a restart (the trie is rebuilt from the accounts alone) would lose
        // the escrow leaves and the restored node's root would stop matching
        // the chain that produced them.
        {
            let mut leaves: Vec<([u8; 32], Vec<u8>)> = snap
                .produced
                .iter()
                .map(|(tx_hash, tx, _height)| {
                    (
                        crate::sharding::xshard_escrow_state_key(tx_hash),
                        crate::sharding::xshard_escrow_state_value(tx),
                    )
                })
                .collect();
            leaves.sort();
            leaves.dedup();
            if !leaves.is_empty() {
                let mut trie = self.state_trie.write().await;
                for (key, value) in &leaves {
                    trie.insert(key, value);
                }
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
    /// content.
    ///
    /// ATOMIC PER ENGINE (audit F3): the replay key is CLAIMED with one
    /// `HashSet::insert` under the `cross_shard_consumed` write lock BEFORE the
    /// credit, and the claim is rolled back only if the credit itself refuses.
    /// `insert` is the linearization point: of N concurrent consumptions of the
    /// same message exactly one observes "absent -> present" and only that one
    /// proceeds to the credit, so the message is credited exactly once. The
    /// previous order (check -> credit -> insert) let every overlapping apply
    /// observe "absent" and credit, i.e. free native STELL per duplicate.
    /// The claim is taken AFTER the cryptographic checks so a forged/not-ready
    /// message never touches the committed set.
    ///
    /// Recording rules (all deterministic functions of the block, hence
    /// identical on every node that applied it):
    /// * produced: every transfer that is outbound for this block's shard,
    ///   first height wins - the same predicate the runtime uses, recorded
    ///   BEFORE the inbound pass so same-block linkage reads it, exactly like
    ///   the runtime's apply order;
    /// * consumed (transfers): the replay key is CLAIMED (atomic insert) before
    ///   the credit and released only if the credit refuses, so exactly one
    ///   concurrent consumer credits and the key is present iff it was paid;
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

        // §9 COEXISTENCE GUARD: a transaction this block (or this shard)
        // already treats as a 2PC transfer can never be credited through the
        // legacy one-way path. The production gate picks exactly one flow per
        // produced transfer, so a block that carries both is Byzantine; the
        // legacy credit is refused in EITHER order (pre-scan, not order
        // dependent), and a record committed by an earlier block refuses it
        // too. Nothing here "upgrades" a legacy transfer into a 2PC one.
        let xpc_in_block: HashSet<[u8; 32]> = block
            .cross_shard_out
            .iter()
            .filter(|m| m.is_xpc())
            .map(|m| m.tx.compute_tx_hash())
            .collect();

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
            // §9 COEXISTENCE GUARD (see above): a 2PC record for this
            // transaction — in this block or committed earlier — refuses the
            // legacy credit, so one transfer can never be half-legacy.
            let tx_hash = msg.tx.compute_tx_hash();
            if xpc_in_block.contains(&tx_hash)
                || self.cross_shard_xpc.read().await.contains_key(&tx_hash)
            {
                continue;
            }
            // PQ-only (live rule): the carried transaction must pass
            // `tx.verify_signature()` — a legacy Ed cross-shard message is
            // refused here, never credited. The `msg_id` recompute is part of
            // the escrow verifier too, but it is kept explicit at this
            // boundary so a rebound id is refused before any registry work.
            if !msg.verify_msg_id() {
                continue;
            }
            if !msg.tx.verify_signature() {
                continue;
            }
            // XSHARD-01 (P0, multi-shard): the legacy inbound credit is paid
            // ONLY against proof of the SOURCE-SIDE ESCROW/DEBIT.
            //
            // The previous rule (`verify_cross_shard_anchored` +
            // `verify_inclusion_strict`) proved the SENDER'S ACCOUNT LEAF at a
            // finalized source root — a statement about the PRE-transfer state
            // ("the sender could afford the amount"). It proved neither
            // inclusion nor a debit. A colluding target proposer plus one
            // funded source account could therefore include a
            // signed-but-never-applied transaction with a valid affordability
            // proof: the source balance stayed put, the target credited the
            // amount, and the value was minted on the target. Repeatable, so it
            // drains the target shard.
            //
            // The gate below requires the source's ESCROW record
            // (`xshard_escrow_state_key(tx_hash)`), which the source writes
            // only for an outbound transfer whose escrow transaction APPLIED,
            // proven against a state root anchored to a locally finalized
            // source header — the same shape as the 2PC COMMIT's proof of the
            // source's PREPARED leaf.
            //
            // FAIL CLOSED (documented consequence): the one-step legacy
            // producer publishes the transfer in the SAME block that escrows
            // it, and a message can only anchor to its parent's committed root,
            // which predates the escrow. An honest one-step legacy message
            // therefore cannot carry this proof and is REFUSED here — legacy
            // cross-shard VALUE is disabled at this gate; cross-shard value
            // moves through the §9 2PC, whose COMMIT is paid against the
            // source's committed escrow. The refusal happens BEFORE the replay
            // claim, so the message is neither consumed nor paid and the source
            // can still refund it on the timeout path.
            if !self.verify_cross_shard_escrow_anchored(msg) {
                continue;
            }
            // THE ATOMIC CLAIM (audit F3). `HashSet::insert` under the write
            // lock is the single linearization point of "is this message
            // already consumed": exactly one concurrent consumer can move the
            // key from absent to present. Every other consumer sees `false`
            // and skips BEFORE it can credit, so a duplicate never pays.
            {
                let mut consumed = self.cross_shard_consumed.write().await;
                if !consumed.insert(key) {
                    continue;
                }
            }
            // THE CREDIT (audit F2): the value already existed on the source
            // shard (it was debited/burned when the source block applied), so
            // this is a TRANSFER of existing supply, not a mint. Using the
            // capped `credit_native` here made a full global cap drop the
            // credit (and, before F3, burn the message): an inbound transfer
            // must never consume mint headroom and must never be refused for
            // it. `credit_native_transfer` is the uncapped transfer primitive.
            if let Err(e) = self.credit_native_transfer(&msg.tx.to, msg.tx.amount).await {
                // Roll the claim back so the message stays replayable instead
                // of being lost: the source debit is real, so the target must
                // be able to credit it on a later apply. Only the consumer
                // that won the claim above can remove it, so no concurrent
                // winner's claim is ever dropped here.
                self.cross_shard_consumed.write().await.remove(&key);
                // The claim moved the committed replay domain and the rollback
                // restored it, so the net state is unchanged; bump anyway so a
                // digest cached INSIDE the claim window cannot be served for
                // the restored set (the bump only keys the digest cache, it is
                // not part of the digest, so an extra bump cannot fork).
                self.bump_domain_generation(crate::commitment::Domain::CrossShard);
                tracing::warn!(
                    "cross-shard inbound credit refused for {}: {e} (message left replayable)",
                    hex::encode(&msg.msg_id[..8])
                );
                continue;
            }
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

    /// XSHARD-01: record the SOURCE-side ESCROW/DEBIT of every outbound LEGACY
    /// transfer this block committed.
    ///
    /// This is the record an inbound legacy credit must prove (see
    /// [`Self::verify_cross_shard_escrow_anchored`]). It is written into the
    /// committed state trie at [`crate::sharding::xshard_escrow_state_key`],
    /// which means:
    ///
    ///  * the value really left the sender's balance on this shard — the leaf
    ///    is written ONLY for a transfer whose transaction is IN this block AND
    ///    `status[idx] == true` (a refused transaction debits nobody, and a leaf
    ///    written for it would let the target credit value that was never
    ///    escrowed: a mint);
    ///  * the leaf is part of the committed state (and therefore of the next
    ///    block's state root), so it can be PROVED with a Merkle proof against
    ///    an anchored source header, exactly like the 2PC PREPARED leaf;
    ///  * it is deterministic: a pure function of the block's own bytes plus
    ///    the apply status, so every node applying the block derives the same
    ///    leaf and the same root.
    ///
    /// Idempotent (the same key/value is rewritten on a re-apply), so a replay
    /// or a reorg re-apply cannot double-record anything.
    ///
    /// NOTE ON THE ONE-STEP LEGACY PRODUCER. The legacy outbox publishes a
    /// transfer in the SAME block that escrows it, and a cross-shard message can
    /// only anchor to its PARENT's committed root. That root predates the
    /// escrow, so an honest one-step legacy message cannot carry this proof and
    /// the inbound credit refuses it (see `apply_cross_shard_consumptions`):
    /// cross-shard value must move through the §9 2PC (PREPARE → PREPARE-ACK →
    /// COMMIT), whose COMMIT is paid only against a proof of the source's
    /// committed escrow. This writer exists so the source-side escrow is a real,
    /// provable, committed record (and so a future two-step legacy producer can
    /// be verified without touching this gate).
    pub async fn record_legacy_escrow_receipts(
        &self,
        block: &crate::sharding::Block,
        status: &[bool],
    ) -> usize {
        if !self.cross_shard_enabled() {
            return 0;
        }
        // Collect first (deterministic block order), then write under ONE trie
        // lock: the trie is the shared committed structure, so a single
        // critical section keeps the apply cheap and the order irrelevant
        // (each leaf has its own key).
        let mut leaves: Vec<([u8; 32], Vec<u8>)> = Vec::new();
        for msg in &block.cross_shard_out {
            if !msg.is_transfer() || !msg.is_outbound_for(block.shard_id) {
                continue;
            }
            let tx = &msg.tx;
            let tx_hash = tx.compute_tx_hash();
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
            leaves.push((
                crate::sharding::xshard_escrow_state_key(&tx_hash),
                crate::sharding::xshard_escrow_state_value(tx),
            ));
        }
        if leaves.is_empty() {
            return 0;
        }
        let mut trie = self.state_trie.write().await;
        for (key, value) in &leaves {
            trie.insert(key, value);
        }
        drop(trie);
        leaves.len()
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
        // XSHARD-01: the SOURCE-side escrow/debit record of every outbound
        // LEGACY transfer this block committed. It runs after the transactions
        // (this hook is called post-apply) so it can consult `status`: only a
        // transfer whose escrow transaction APPLIED is recorded.
        let _escrows = self.record_legacy_escrow_receipts(block, status).await;
        let mut created = 0usize;
        for msg in &block.cross_shard_out {
            if !msg.is_prepare() || !msg.is_outbound_for(block.shard_id) {
                continue;
            }
            let tx = &msg.tx;
            let tx_hash = tx.compute_tx_hash();
            // §9 COEXISTENCE GUARD: a transfer already produced through the
            // LEGACY outbound path is never re-opened as a 2PC transfer. The
            // two flows must not coexist on one transfer, so a PREPARE for a
            // transaction this shard already published as a plain transfer is
            // refused (no escrow record, no peer-facing 2PC state).
            if self
                .cross_shard_produced
                .read()
                .await
                .contains_key(&tx_hash)
            {
                continue;
            }
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
        // FAIL CLOSED on a mismatched or self-inconsistent PHASE record: the
        // record this shard owns can only be advanced by a message travelling
        // the record's OWN direction, and a record whose bytes disagree with
        // themselves is refused before it is used as a proof base. Neither
        // ever advances silently.
        if let Some(rec) = existing.as_ref() {
            if !rec.is_consistent() {
                return false;
            }
            let direction_matches = match msg.kind() {
                CrossShardKind::Prepare | CrossShardKind::Commit | CrossShardKind::AbortRequest => {
                    rec.source_shard == msg.source_shard && rec.target_shard == msg.target_shard
                }
                CrossShardKind::PrepareAck | CrossShardKind::AbortAck => {
                    rec.source_shard == msg.target_shard && rec.target_shard == msg.source_shard
                }
                _ => false,
            };
            if !direction_matches {
                return false;
            }
            // A decision cannot predate the prepare: a record that would be
            // written with `decided_height < prepared_height` is refused
            // BEFORE any value moves (the credit/refund below must never
            // happen for a record the shard will not commit to).
            if height < rec.prepared_height {
                return false;
            }
        }
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
                //
                // ATOMICITY (audit F3, 2PC twin): `cross_shard_completed` is
                // the atomic claim for this value movement. Two concurrent
                // COMMIT applies can both read the same PREPARED record and
                // both pass the transition check, so the insert below - not
                // the read above - decides which one pays. A failed credit
                // releases the claim so the decision stays replayable.
                if !self.cross_shard_completed.write().await.insert(tx_hash) {
                    return false;
                }
                // Audit F2: an inbound cross-shard credit moves value that the
                // source already escrowed, so it is a TRANSFER, never a mint.
                // The capped `credit_native` would drop it at the global cap.
                if let Err(e) = self.credit_native_transfer(&tx.to, tx.amount).await {
                    self.cross_shard_completed.write().await.remove(&tx_hash);
                    // The claim moved a committed domain; a rollback must move
                    // it again so a digest cached inside the window is not
                    // served for the restored set.
                    self.bump_domain_generation(crate::commitment::Domain::CrossShard);
                    tracing::warn!(
                        "xpc commit credit refused for {}: {e} (decision left replayable)",
                        hex::encode(&tx_hash[..8])
                    );
                    return false;
                }
                rec.phase = XpcPhase::Committed;
                rec.decided_height = height;
                self.write_xpc_record(&rec).await;
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
                //
                // ATOMICITY (audit F3, refund twin): the `cross_shard_completed`
                // insert is the claim, so two concurrent ABORT-ACK applies
                // cannot both refund. Released on a failed credit.
                if !self.cross_shard_completed.write().await.insert(tx_hash) {
                    return false;
                }
                // Audit F2: the refund returns value the source already held
                // (it was escrowed, not minted), so it is a TRANSFER and must
                // not be refused at the global supply cap.
                if let Err(e) = self.credit_native_transfer(&tx.from, tx.amount).await {
                    self.cross_shard_completed.write().await.remove(&tx_hash);
                    // See the COMMIT arm: a rolled-back claim must invalidate
                    // any digest cached inside the claim window.
                    self.bump_domain_generation(crate::commitment::Domain::CrossShard);
                    tracing::warn!(
                        "xpc abort refund refused for {}: {e} (decision left replayable)",
                        hex::encode(&tx_hash[..8])
                    );
                    return false;
                }
                rec.phase = XpcPhase::Aborted;
                rec.decided_height = height;
                self.write_xpc_record(&rec).await;
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
            cnvrf_v3: None,
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

    /// A record whose own bytes disagree (decided phase with no decision
    /// height) is refused on BOTH the write and the restore path. It is never
    /// "repaired" into a phase the chain did not commit to.
    #[tokio::test]
    async fn inconsistent_xpc_records_are_refused() {
        let engine = InMemoryStateEngine::new();
        engine.enable_cross_shard();
        let signer = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let tx = Transaction::sign(&signer, [1u8; 32], 10, 280_000, 0, 0, 1);
        let mut rec = crate::xshard2pc::XpcRecord::prepared(tx, 0, 1, 5);
        rec.phase = XpcPhase::Committed; // decided_height is still 0
        assert!(!rec.is_consistent(), "precondition: the record is broken");

        assert!(
            !engine.write_xpc_record(&rec).await,
            "an inconsistent record must be refused at write time"
        );
        assert!(engine.xpc_record(&rec.tx_hash).await.is_none());
        assert_eq!(engine.xpc_len().await, 0);

        engine.restore_xpc_records(&[rec.clone()]).await;
        assert!(
            engine.xpc_record(&rec.tx_hash).await.is_none(),
            "an inconsistent record must be refused at restore time"
        );
    }

    /// A transfer that was produced through the LEGACY outbound path is never
    /// re-opened as a 2PC transfer: the PREPARE is refused and no PREPARED
    /// record appears.
    #[tokio::test]
    async fn a_legacy_produced_transfer_cannot_be_reopened_as_2pc() {
        let signer = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
        let tx = Transaction::sign(&signer, [2u8; 32], 1_000, 280_000, 0, 0, 1);
        let tx_hash = tx.compute_tx_hash();

        let engine = InMemoryStateEngine::new();
        engine.enable_cross_shard();

        // Height 1: the transfer is published the LEGACY way (outbound from
        // shard 0), which records it in `cross_shard_produced`.
        let legacy = CrossShardMessage::new(0, 1, tx.clone(), [0u8; 32], [0u8; 32], None);
        let legacy_block = Block {
            shard_id: 0,
            height: 1,
            prev_hash: [0u8; 32],
            state_root: [0u8; 32],
            transactions: vec![],
            cross_shard_out: vec![legacy],
            timestamp: 1_770_000_000,
            proposer: [0x11; 32],
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            cnvrf_v3: None,
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
        };
        engine.apply_cross_shard_consumptions(&legacy_block).await;
        assert_eq!(engine.cross_shard_produced_len().await, 1);

        // Height 2: a Byzantine proposer tries to escrow the SAME transfer as
        // a 2PC PREPARE (with the escrow transaction in the block).
        let prepare =
            CrossShardMessage::new_xpc(XPC_PREPARE, 0, 1, tx.clone(), [0u8; 32], [0u8; 32], None);
        let prepare_block = Block {
            shard_id: 0,
            height: 2,
            transactions: vec![tx.clone()],
            cross_shard_out: vec![prepare],
            ..legacy_block
        };
        assert_eq!(
            engine
                .apply_xpc_source_prepares(&prepare_block, &[true])
                .await,
            0,
            "a legacy-produced transfer must not be re-opened as 2PC"
        );
        assert!(engine.xpc_record(&tx_hash).await.is_none());

        // Control: the same PREPARE on a fresh engine DOES create the record.
        let fresh = InMemoryStateEngine::new();
        fresh.enable_cross_shard();
        assert_eq!(
            fresh
                .apply_xpc_source_prepares(&prepare_block, &[true])
                .await,
            1
        );
    }

    /// The legacy credit path refuses a transaction the shard already holds a
    /// 2PC record for, even when the legacy message carries a fully valid
    /// proof and anchor. This is the coexistence gate: one transfer is never
    /// half-legacy/half-2PC.
    #[tokio::test]
    async fn a_legacy_credit_is_refused_when_a_2pc_record_exists() {
        let kp = FalconKeypair::generate_from_seed(45);
        let sender_addr = derive_pq_address(PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT);
        let recipient = [0x5Au8; 32];
        let amount = 1_000_000u64;
        let initial_bal = 5_000_000_000u64;

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
        let anchor_block = [0xCDu8; 32];
        let reg = Arc::new(std::sync::RwLock::new(FinalizedHeaderRegistry::default()));
        reg.write()
            .unwrap()
            .note_finalized(0, anchor_block, source_root);

        let probe = Transaction::new_pq_explicit(
            PqScheme::Falcon512,
            kp.public_key.clone(),
            vec![0u8; FALCON512_SIG_LEN],
            recipient,
            amount,
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
            amount,
            280_000,
            0,
            0,
            1,
            vec![],
            &DEFAULT_SALT,
        );
        let tx_hash = signed_tx.compute_tx_hash();
        let legacy =
            CrossShardMessage::new(0, 1, signed_tx.clone(), source_root, anchor_block, proof)
                .with_source_balance(initial_bal)
                .with_sender_pubkey_hash(PqScheme::Falcon512.id(), pk_hash);
        let block = Block {
            shard_id: 1,
            height: 5,
            prev_hash: [0u8; 32],
            state_root: [0u8; 32],
            transactions: vec![],
            cross_shard_out: vec![legacy],
            timestamp: 1_770_000_000,
            proposer: [0x11; 32],
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            cnvrf_v3: None,
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
        };

        // Control: this message carries NO source-escrow proof, so the legacy
        // credit is refused even with no 2PC record (pentest XSHARD-01: an
        // affordability-only leaf proves nothing about a source debit). The
        // positive escrow-backed path is covered end to end by
        // `sharding_m2_tests::escrow_backed_legacy_credit_is_paid_exactly_once`.
        let clean = InMemoryStateEngine::new();
        clean.enable_cross_shard();
        clean.with_finalized_headers(reg.clone());
        clean.apply_cross_shard_consumptions(&block).await;
        assert_eq!(
            clean.get_account(&recipient).await.map(|a| a.balance),
            None,
            "an unproven legacy credit must never mint on the target"
        );
        assert_eq!(
            clean.cross_shard_consumed_len().await,
            0,
            "a refused credit must not claim the replay key"
        );

        // Armed: the SAME message is refused because a 2PC record exists.
        let armed = InMemoryStateEngine::new();
        armed.enable_cross_shard();
        armed.with_finalized_headers(reg);
        assert!(
            armed
                .write_xpc_record(&crate::xshard2pc::XpcRecord::prepared(signed_tx, 0, 1, 1))
                .await
        );
        armed.apply_cross_shard_consumptions(&block).await;
        assert_eq!(
            armed.get_account(&recipient).await.map(|a| a.balance),
            None,
            "a 2PC transaction must never be credited as a legacy transfer"
        );
        assert_eq!(armed.cross_shard_consumed_len().await, 0);
        assert!(armed.xpc_record(&tx_hash).await.is_some());
    }
}
