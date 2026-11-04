//! Chain management: block tree, fork-choice and reorg planning.
//!
//! With BFT finality, a block at height H becomes irreversible once finalized.
//! Reorgs therefore only ever affect blocks ABOVE the finalized height. This
//! module keeps the full block tree, selects the canonical head (fork-choice)
//! and produces an explicit reorg plan (which blocks to roll back and which to
//! apply) so the state engine can replay deterministically.

use crate::sharding::Block;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

pub type BlockHash = [u8; 32];
pub type Height = u64;

/// How many invalidation signals the rolling window keeps.
pub const MAX_INVALIDATION_WINDOW: usize = 64;

/// How many candidate blocks are tracked at once.
///
/// A candidate is a block that was received and validated but NOT yet
/// finalized. The cap bounds the memory a fork-heavy node spends on
/// branches that never win; the oldest (lowest) candidates are dropped
/// first, and the drop is reported as an invalidation (the blocks are gone
/// for good — they will never be applied).
pub const MAX_TRACKED_CANDIDATES: usize = 256;

/// How many finalized heights are kept in the fork-choice index.
///
/// The index answers "which block did the finalized chain decide at height
/// X?", and it is only ever consulted for the heights near the head (a
/// candidate branch is always within a few heights of it). The window
/// bounds the memory of a node that has been running for months: the
/// durable store keeps the full history, the fork-choice needs only the
/// recent part.
pub const MAX_FINALIZED_INDEX: usize = 4096;

/// The DAG of all known blocks with parent/child links.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BlockTree {
    pub blocks: HashMap<BlockHash, Block>,
    pub parent: HashMap<BlockHash, Option<BlockHash>>,
    pub children: HashMap<BlockHash, Vec<BlockHash>>,
    pub height: HashMap<BlockHash, Height>,
}

impl BlockTree {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a block. Returns its hash. Idempotent.
    pub fn insert(&mut self, block: Block) -> BlockHash {
        let hash = block.compute_hash();
        if self.blocks.contains_key(&hash) {
            return hash;
        }
        let parent = if block.height == 0 {
            None
        } else {
            Some(block.prev_hash)
        };
        self.height.insert(hash, block.height);
        self.parent.insert(hash, parent);
        if let Some(p) = parent {
            self.children.entry(p).or_default().push(hash);
        }
        self.blocks.insert(hash, block);
        hash
    }

    pub fn get(&self, hash: &BlockHash) -> Option<&Block> {
        self.blocks.get(hash)
    }

    pub fn contains(&self, hash: &BlockHash) -> bool {
        self.blocks.contains_key(hash)
    }

    pub fn parent_of(&self, hash: &BlockHash) -> Option<BlockHash> {
        self.parent.get(hash).copied().flatten()
    }

    pub fn height_of(&self, hash: &BlockHash) -> Option<Height> {
        self.height.get(hash).copied()
    }

    /// Path from `hash` back to the root (genesis last).
    pub fn ancestors(&self, hash: &BlockHash) -> Vec<BlockHash> {
        let mut out = Vec::new();
        let mut cur = Some(*hash);
        while let Some(h) = cur {
            if !self.blocks.contains_key(&h) {
                break;
            }
            out.push(h);
            cur = self.parent_of(&h);
        }
        out
    }

    /// Path from genesis to `hash` (root first).
    pub fn chain_to(&self, hash: &BlockHash) -> Vec<BlockHash> {
        let mut v = self.ancestors(hash);
        v.reverse();
        v
    }
}

/// An explicit reorg: undo `rollback` (tip-first) then apply `apply` (ancestor-first).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReorgPlan {
    pub common_ancestor: BlockHash,
    pub rollback: Vec<BlockHash>,
    pub apply: Vec<BlockHash>,
}

impl ReorgPlan {
    pub fn is_empty(&self) -> bool {
        self.rollback.is_empty() && self.apply.is_empty()
    }
}

/// A published invalidation signal: the blocks that will NEVER be applied,
/// and why.
///
/// The signal is the node's answer to "I told you about that block". A
/// block is invalidated when a reorg rolls it back, when a competing
/// candidate branch loses the fork-choice, or when the finalized chain
/// decided a different block at the same height. None of these blocks were
/// ever executed (BFT finality forbids rolling back an applied block), so
/// the signal is a "your view of these blocks was wrong" notice for
/// indexers, wallets and light clients — not a state rollback.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvalidationSignal {
    /// The orphaned blocks, TIP-FIRST — the same order as
    /// [`ReorgPlan::rollback`], so a consumer can unwind in the order the
    /// chain unwound them.
    pub orphaned_blocks: Vec<BlockHash>,
    /// Human-readable reason (stable enough to log, not a machine contract:
    /// the machine contract is `orphaned_blocks` + `height`).
    pub reason: String,
    /// The height of the LOWEST orphaned block — the FIRST height that was
    /// invalidated. A consumer that has to re-sync asks "from which height
    /// is my view wrong", and that is this number.
    pub height: Height,
}

impl InvalidationSignal {
    /// A signal with no orphaned block carries no information and is never
    /// published (the rolling window would fill up with noise).
    pub fn is_empty(&self) -> bool {
        self.orphaned_blocks.is_empty()
    }
}

/// Where invalidation signals are published (the RPC / streaming layer).
///
/// A plain function so the consensus runtime never depends on the RPC
/// transport: the node wires an `Arc` closure that files the signal into
/// the RPC window and notifies the streaming subscribers.
pub type InvalidationSink = std::sync::Arc<dyn Fn(InvalidationSignal) + Send + Sync>;

/// The outcome of a fork-choice switch: the plan that was EXECUTED and the
/// invalidation signals it published.
#[derive(Clone, Debug)]
pub struct ReorgOutcome {
    /// The plan that was executed.
    pub plan: ReorgPlan,
    /// The signals published for the orphaned blocks.
    pub invalidations: Vec<InvalidationSignal>,
}

/// Manages finality, the canonical chain and fork-choice over the block tree.
#[derive(Debug)]
pub struct ChainManager {
    pub tree: BlockTree,
    pub finalized_height: Height,
    pub finalized_hash: BlockHash,
    /// Canonical chain from genesis to the current best head (root first).
    pub canonical: Vec<BlockHash>,
    /// Every block this node FINALIZED, by height.
    ///
    /// The tree holds the same blocks, but this index is what the
    /// fork-choice compares a candidate branch against: a candidate that
    /// sits at a height the finalized chain already decided is either the
    /// finalized block itself (canonical) or an orphan. Bounded to
    /// [`MAX_FINALIZED_INDEX`] entries (oldest first) so a long-running
    /// node's memory stays flat.
    pub finalized_index: HashMap<Height, BlockHash>,
    /// The heights of `finalized_index`, oldest first (the eviction order).
    pub finalized_order: std::collections::VecDeque<Height>,
    /// Candidate blocks: received, validated, and NOT yet finalized.
    ///
    /// They are tracked so a fork is OBSERVABLE: without them the live node
    /// only ever learns the branch it finalized, and the competing one
    /// vanishes without a trace. A candidate is never canonical on its own
    /// — a canonical head is always a finalized block.
    pub candidates: HashSet<BlockHash>,
    /// The candidate branch the fork-choice currently prefers.
    pub candidate_head: Option<BlockHash>,
    /// Rolling window of the invalidation signals published so far (oldest
    /// first).
    pub invalidations: Vec<InvalidationSignal>,
    /// Invalidations raised by the last operation that the caller has NOT
    /// published yet.
    ///
    /// The candidate-window trim ([`Self::trim_candidates`]) drops blocks
    /// that can never be applied, and that drop MUST be signalled: a client
    /// that followed the trimmed branch has to learn that it lost. The trim
    /// happens inside [`Self::insert_candidate`], which cannot publish
    /// anything itself, so the signal is parked here and the caller drains
    /// it (and publishes it) right after.
    pending_invalidations: Vec<InvalidationSignal>,
    /// STAB: epoch-MMR roots per epoch, computed once and reused.
    /// `epoch_mmr_root` is a pure function of the 128 finalized hashes of
    /// the epoch; without this the boundary height paid one 128-leaf MMR
    /// build on the proposer path AND one on every validator path (plus one
    /// per round retry). The cache moves the periodic O(128) spike off the
    /// hot path: first builder pays it, everyone else hits O(1).
    /// Bounded (32 epochs ≈ 4096 heights): evicted FIFO. Never on the wire.
    #[allow(clippy::type_complexity)]
    // GATE: shape is local to this cache field; alias adds indirection
    mmr_cache: std::sync::Mutex<HashMap<u64, ([u8; 32], Vec<[u8; 32]>)>>,
}

impl Clone for ChainManager {
    fn clone(&self) -> Self {
        Self {
            tree: self.tree.clone(),
            finalized_height: self.finalized_height,
            finalized_hash: self.finalized_hash,
            canonical: self.canonical.clone(),
            finalized_index: self.finalized_index.clone(),
            finalized_order: self.finalized_order.clone(),
            candidates: self.candidates.clone(),
            candidate_head: self.candidate_head,
            invalidations: self.invalidations.clone(),
            pending_invalidations: self.pending_invalidations.clone(),
            mmr_cache: std::sync::Mutex::new(
                self.mmr_cache
                    .lock()
                    .ok()
                    .map(|g| g.clone())
                    .unwrap_or_default(),
            ),
        }
    }
}

impl ChainManager {
    /// Create from a genesis block (height 0).
    pub fn new(genesis: Block) -> Self {
        let mut tree = BlockTree::new();
        let g = tree.insert(genesis);
        let height = tree.height_of(&g).unwrap_or(0);
        let mut finalized_index = HashMap::new();
        finalized_index.insert(height, g);
        Self {
            tree,
            finalized_height: height,
            finalized_hash: g,
            canonical: vec![g],
            finalized_index,
            finalized_order: std::collections::VecDeque::from([height]),
            candidates: HashSet::new(),
            candidate_head: None,
            invalidations: Vec::new(),
            pending_invalidations: Vec::new(),
            mmr_cache: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// A manager with NO root yet.
    ///
    /// A live node learns its finalized head from the consensus layer, and it
    /// may join mid-chain (never seeing the ancestors). The first block it
    /// learns as finalized becomes the root of the tree
    /// ([`Self::adopt_root`]); until then the manager is empty and tracks
    /// nothing.
    pub fn detached() -> Self {
        Self {
            tree: BlockTree::new(),
            finalized_height: 0,
            finalized_hash: [0u8; 32],
            canonical: Vec::new(),
            finalized_index: HashMap::new(),
            finalized_order: std::collections::VecDeque::new(),
            candidates: HashSet::new(),
            candidate_head: None,
            invalidations: Vec::new(),
            pending_invalidations: Vec::new(),
            mmr_cache: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// True when no root has been adopted yet.
    pub fn is_empty(&self) -> bool {
        self.finalized_index.is_empty()
    }

    /// Insert a block into the tree (no fork-choice yet). Returns its hash.
    pub fn insert(&mut self, block: Block) -> BlockHash {
        self.tree.insert(block)
    }

    /// Insert a block ONLY if it is a valid extension (parent known, height
    /// chained, block signature self-consistent). Returns Err otherwise — this
    /// prevents unbounded tree pollution from arbitrary/forged blocks.
    pub fn insert_validated(&mut self, block: Block) -> Result<BlockHash, String> {
        self.validate_extension(&block)?;
        Ok(self.tree.insert(block))
    }

    pub fn best_head(&self) -> BlockHash {
        *self.canonical.last().unwrap()
    }

    /// Fork-choice: among blocks descending from the finalized head, pick the
    /// highest; ties broken by the smallest hash (deterministic).
    ///
    /// CANDIDATES ARE NOT ELIGIBLE: a candidate is a block that was
    /// validated but not finalized, so it must never become the canonical
    /// head on its own — the canonical head is a finalized block, and the
    /// candidates are only compared against each other (see
    /// [`Self::best_candidate`]).
    fn choose_head(&self) -> BlockHash {
        let mut best: Option<(Height, BlockHash)> = None;
        for (hash, h) in &self.tree.height {
            if *h < self.finalized_height {
                continue;
            }
            if self.candidates.contains(hash) {
                continue;
            }
            if !self.descends_from_finalized(hash) {
                continue;
            }
            let cand = (*h, *hash);
            best = match best {
                None => Some(cand),
                Some((bh, bhash)) => {
                    if cand.0 > bh || (cand.0 == bh && cand.1 < bhash) {
                        Some(cand)
                    } else {
                        Some((bh, bhash))
                    }
                }
            };
        }
        best.map(|(_, h)| h).unwrap_or(self.finalized_hash)
    }

    fn descends_from_finalized(&self, hash: &BlockHash) -> bool {
        self.tree.ancestors(hash).contains(&self.finalized_hash)
    }

    /// Truncate a chain so it starts at the finalized head.
    fn truncate_from_finalized(&self, mut chain: Vec<BlockHash>) -> Vec<BlockHash> {
        if chain.first() != Some(&self.finalized_hash) {
            if let Some(pos) = chain.iter().position(|h| *h == self.finalized_hash) {
                chain.drain(0..pos);
            }
        }
        chain
    }

    /// Recompute fork-choice and update the canonical chain. If the head moved,
    /// returns the reorg plan (rollback old tip-first, then apply new ancestor-first).
    pub fn recompute_canonical(&mut self) -> Option<ReorgPlan> {
        let old_chain = self.canonical.clone();
        let new_head = self.choose_head();
        let new_chain = self.truncate_from_finalized(self.tree.chain_to(&new_head));

        let plan = if old_chain == new_chain {
            None
        } else {
            let mut ca_idx = 0usize;
            while ca_idx < old_chain.len()
                && ca_idx < new_chain.len()
                && old_chain[ca_idx] == new_chain[ca_idx]
            {
                ca_idx += 1;
            }
            if ca_idx == 0 {
                None
            } else {
                Some(ReorgPlan {
                    common_ancestor: old_chain[ca_idx - 1],
                    rollback: old_chain[ca_idx..].iter().rev().copied().collect(),
                    apply: new_chain[ca_idx..].to_vec(),
                })
            }
        };
        self.canonical = new_chain;
        plan
    }

    /// Finalize a block that extends the canonical finalized chain.
    /// SECURITY: blocks at or below the finalized height can never be reorged.
    pub fn finalize(&mut self, hash: BlockHash) -> Result<(), String> {
        let h = self
            .tree
            .height_of(&hash)
            .ok_or_else(|| "unknown block".to_string())?;
        if h <= self.finalized_height {
            return Err("block at or below finalized height".to_string());
        }
        if !self.tree.ancestors(&hash).contains(&self.finalized_hash) {
            return Err("block does not extend the finalized chain".to_string());
        }
        self.finalized_height = h;
        self.finalized_hash = hash;
        self.note_finalized_height(h, hash);
        // A finalized block is canonical, not a candidate any more.
        self.candidates.remove(&hash);
        let _ = self.recompute_canonical();
        Ok(())
    }

    pub fn is_finalized(&self, hash: &BlockHash) -> bool {
        self.tree
            .height_of(hash)
            .map(|h| h <= self.finalized_height)
            .unwrap_or(false)
    }

    /// Compute a reorg plan from the current canonical chain to `new_head`
    /// WITHOUT mutating state. None if no reorg is needed. Errors if it would
    /// touch finalized blocks.
    pub fn reorg_plan(&self, new_head: &BlockHash) -> Result<Option<ReorgPlan>, String> {
        if !self.tree.contains(new_head) {
            return Err("unknown block".to_string());
        }
        if self.best_head() == *new_head {
            return Ok(None);
        }
        let new_chain = self.truncate_from_finalized(self.tree.chain_to(new_head));
        let old_chain = &self.canonical;

        let mut ca_idx = 0usize;
        while ca_idx < old_chain.len()
            && ca_idx < new_chain.len()
            && old_chain[ca_idx] == new_chain[ca_idx]
        {
            ca_idx += 1;
        }
        if ca_idx == 0 {
            return Err("no common ancestor".to_string());
        }
        let common_ancestor = old_chain[ca_idx - 1];

        let ca_height = self.tree.height_of(&common_ancestor).unwrap_or(0);
        if ca_height < self.finalized_height {
            return Err("reorg would touch finalized blocks".to_string());
        }

        let rollback: Vec<BlockHash> = old_chain[ca_idx..].iter().rev().copied().collect();
        let apply: Vec<BlockHash> = new_chain[ca_idx..].to_vec();

        Ok(Some(ReorgPlan {
            common_ancestor,
            rollback,
            apply,
        }))
    }

    /// All known block hashes (for pruning / diagnostics).
    pub fn known_hashes(&self) -> Vec<BlockHash> {
        self.tree.blocks.keys().copied().collect()
    }

    /// Reject an obviously invalid extension (anti-DoS / anti-fork-spam):
    /// height must be parent height + 1, prev_hash must reference a known block,
    /// and the block must carry a valid proposer signature.
    pub fn validate_extension(&self, block: &Block) -> Result<(), String> {
        if block.height == 0 {
            return Err("use genesis constructor for height 0".to_string());
        }
        // SECURITY: a block must be signed by its proposer (self-consistency).
        if !block.verify_signatures(1) {
            return Err("block has no valid proposer signature".to_string());
        }
        if !self.tree.contains(&block.prev_hash) {
            return Err("unknown parent".to_string());
        }
        let ph = self.tree.height_of(&block.prev_hash).unwrap();
        if block.height != ph + 1 {
            return Err("height is not parent height + 1".to_string());
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Candidate branches (the fork-choice over the UNFINALIZED region)
    // ------------------------------------------------------------------

    /// Insert a block as a CANDIDATE: validated as an extension of a known
    /// block and tracked for fork-choice, but NOT canonical (only a
    /// finalized block is).
    ///
    /// This is what makes a fork observable in a live node: the competing
    /// branch is KNOWN before finality, so when it loses, the blocks that
    /// lost can be signalled instead of vanishing.
    pub fn insert_candidate(&mut self, block: Block) -> Result<BlockHash, String> {
        self.validate_extension(&block)?;
        let hash = self.tree.insert(block);
        if self.candidates.insert(hash) {
            self.trim_candidates();
        }
        Ok(hash)
    }

    /// The finalized block at `height`, if this node finalized one.
    pub fn finalized_at_height(&self, height: Height) -> Option<BlockHash> {
        self.finalized_index.get(&height).copied()
    }

    /// The MMR root over epoch `epoch`'s finalized block hashes (V5 Tier-2).
    ///
    /// Returns the root and the peaks when this node finalized ALL 128
    /// heights of the epoch, `None` otherwise (behind, pruned, or freshly
    /// restarted — the proposer then commits the all-zero root instead of a
    /// root it cannot prove; see `Block::mmr_epoch_root`). The leaves are
    /// the finalized block hashes in height order, so every node that
    /// finalized the epoch derives the same root.
    /// STAB: cached per epoch (O(1) hits after the first build per epoch);
    /// the MMR build leaves the hot path after one computation.
    pub fn epoch_mmr_root(&self, epoch: u64) -> Option<([u8; 32], Vec<[u8; 32]>)> {
        if let Some(cached) = self
            .mmr_cache
            .lock()
            .ok()
            .and_then(|g| g.get(&epoch).cloned())
        {
            return Some(cached);
        }
        let start = crate::mmr::epoch_start(epoch);
        let end = crate::mmr::epoch_end(epoch);
        let mut leaves = Vec::with_capacity(crate::mmr::MMR_EPOCH_BLOCKS as usize);
        for h in start..=end {
            leaves.push(self.finalized_at_height(h)?);
        }
        let out = crate::mmr::mmr_root_for_leaves(&leaves);
        if let Ok(mut g) = self.mmr_cache.lock() {
            if g.len() >= 32 {
                if let Some(min) = g.keys().min().copied() {
                    g.remove(&min);
                }
            }
            g.insert(epoch, out.clone());
        }
        Some(out)
    }

    /// The height of a block this manager knows (0 when it does not know
    /// it).
    pub fn height_of(&self, hash: &BlockHash) -> Height {
        self.tree.height_of(hash).unwrap_or(0)
    }

    /// Record a finalized height in the index, evicting the oldest entry
    /// when the window is full.
    ///
    /// The window is bounded so a node that runs for months does not grow
    /// its fork-choice index without limit; the durable store keeps the
    /// full history.
    fn note_finalized_height(&mut self, height: Height, hash: BlockHash) {
        if self.finalized_index.insert(height, hash).is_none() {
            self.finalized_order.push_back(height);
        }
        while self.finalized_order.len() > MAX_FINALIZED_INDEX {
            if let Some(oldest) = self.finalized_order.pop_front() {
                self.finalized_index.remove(&oldest);
            }
        }
    }

    /// The ancestor path of `hash`, root first.
    fn path_to_root(&self, hash: &BlockHash) -> Vec<BlockHash> {
        let mut v = self.tree.ancestors(hash);
        v.reverse();
        v
    }

    /// The candidate branch ending at `tip`, ancestor-first, EXCLUDING the
    /// finalized head. Empty when the tip does not descend from it (the
    /// branch is detached).
    pub fn candidate_chain(&self, tip: &BlockHash) -> Vec<BlockHash> {
        let mut path = self.path_to_root(tip);
        match path.iter().position(|h| *h == self.finalized_hash) {
            Some(p) => {
                path.drain(0..=p);
                path
            }
            None => Vec::new(),
        }
    }

    /// The candidate blocks at a given height (sorted: deterministic).
    pub fn candidates_at(&self, height: Height) -> Vec<BlockHash> {
        let mut out: Vec<BlockHash> = self
            .candidates
            .iter()
            .copied()
            .filter(|h| self.tree.height_of(h) == Some(height))
            .collect();
        out.sort();
        out
    }

    /// The tips of the tracked candidate branches: the candidate blocks that
    /// have no candidate CHILD (sorted: deterministic).
    pub fn candidate_tips(&self) -> Vec<BlockHash> {
        let mut with_child: HashSet<BlockHash> = HashSet::new();
        for h in &self.candidates {
            if let Some(p) = self.tree.parent_of(h) {
                if self.candidates.contains(&p) {
                    // The PARENT has a candidate child, so it is not a tip.
                    with_child.insert(p);
                }
            }
        }
        let mut tips: Vec<BlockHash> = self
            .candidates
            .iter()
            .copied()
            .filter(|h| !with_child.contains(h))
            .collect();
        tips.sort();
        tips
    }

    /// The fork-choice winner among the candidate branches: the branch tip
    /// with the HIGHEST height; ties broken by the smallest hash
    /// (deterministic, exactly like the canonical fork-choice).
    ///
    /// `None` when no candidate is tracked.
    ///
    /// NOTE: a branch of the same length is NOT out-competed by this rule.
    /// The finalization (the quorum) decides which of two equal-length
    /// branches is on the chain, so a caller that invalidates the loser
    /// must wait for that decision — see
    /// [`Self::prune_superseded_candidates`].
    pub fn best_candidate(&self) -> Option<BlockHash> {
        let mut best: Option<(Height, BlockHash)> = None;
        for tip in self.candidate_tips() {
            let h = self.tree.height_of(&tip).unwrap_or(0);
            best = match best {
                None => Some((h, tip)),
                Some((bh, bhash)) => {
                    if h > bh || (h == bh && tip < bhash) {
                        Some((h, tip))
                    } else {
                        Some((bh, bhash))
                    }
                }
            };
        }
        best.map(|(_, h)| h)
    }

    /// Plan the switch from the current candidate head to `new_head`.
    ///
    /// Both are candidate branches of the SAME finalized chain. The plan
    /// rolls back the old branch's blocks above the common ancestor
    /// (tip-first) and applies the new branch's (ancestor-first). `None`
    /// when the head does not move.
    pub fn candidate_reorg_plan(&self, new_head: &BlockHash) -> Result<Option<ReorgPlan>, String> {
        if !self.candidates.contains(new_head) {
            return Err("not a tracked candidate".to_string());
        }
        let new_chain = self.candidate_chain(new_head);
        let old_chain = match self.candidate_head {
            Some(h) if self.candidates.contains(&h) => self.candidate_chain(&h),
            _ => Vec::new(),
        };
        if old_chain == new_chain {
            return Ok(None);
        }
        let mut c = 0usize;
        while c < old_chain.len() && c < new_chain.len() && old_chain[c] == new_chain[c] {
            c += 1;
        }
        let common_ancestor = if c == 0 {
            self.finalized_hash
        } else {
            old_chain[c - 1]
        };
        Ok(Some(ReorgPlan {
            common_ancestor,
            rollback: old_chain[c..].iter().rev().copied().collect(),
            apply: new_chain[c..].to_vec(),
        }))
    }

    /// EXECUTE a candidate reorg: the candidate head moves to `new_head`,
    /// the rolled-back blocks leave the candidate set, and the invalidation
    /// signal for them is recorded in the rolling window.
    ///
    /// Returns the signal (its `orphaned_blocks` are empty when the plan
    /// rolled nothing back).
    pub fn commit_candidate_reorg(
        &mut self,
        plan: &ReorgPlan,
        new_head: BlockHash,
    ) -> InvalidationSignal {
        for h in &plan.rollback {
            self.candidates.remove(h);
        }
        self.candidate_head = Some(new_head);
        // The rollback is tip-first, so its LAST element is the LOWEST
        // orphaned block — the first height that was invalidated.
        let height = plan
            .rollback
            .last()
            .and_then(|h| self.tree.height_of(h))
            .unwrap_or(self.finalized_height);
        let signal = InvalidationSignal {
            orphaned_blocks: plan.rollback.clone(),
            reason: format!("reorg: candidate branch superseded at height {height}"),
            height,
        };
        self.record_invalidation(signal.clone());
        signal
    }

    /// Record an invalidation signal in the rolling window (oldest first).
    ///
    /// A signal without orphaned blocks carries no information and is
    /// dropped: the window must only hold real invalidations.
    pub fn record_invalidation(&mut self, signal: InvalidationSignal) {
        if signal.is_empty() {
            return;
        }
        self.invalidations.push(signal);
        while self.invalidations.len() > MAX_INVALIDATION_WINDOW {
            self.invalidations.remove(0);
        }
    }

    /// Park an invalidation for the CALLER to publish.
    ///
    /// Used by the operations that cannot publish themselves (they are
    /// `&mut self` methods on the manager, and the sink lives on the
    /// runtime). The caller drains the parked signals and publishes them.
    fn park_invalidation(&mut self, signal: InvalidationSignal) {
        if signal.is_empty() {
            return;
        }
        self.pending_invalidations.push(signal);
    }

    /// Take the invalidation signals raised since the last drain.
    ///
    /// The caller MUST publish them: an invalidation nobody hears about is
    /// a fork that vanishes without a trace, which is exactly what the
    /// fork-choice is there to prevent.
    pub fn take_pending_invalidations(&mut self) -> Vec<InvalidationSignal> {
        std::mem::take(&mut self.pending_invalidations)
    }

    /// Invalidate a block that can never be applied (it sits at or below
    /// the finalized height, so the finalized chain already decided that
    /// height) and record the signal.
    ///
    /// The block that WAS finalized at that height is NOT invalidated: it was
    /// applied, and announcing an applied block as invalidated would be a
    /// lie. The signal returned for it is empty (nothing was orphaned), so
    /// it is never published.
    pub fn invalidate_block(&mut self, block: &Block) -> InvalidationSignal {
        let hash = block.compute_hash();
        let height = block.height;
        self.candidates.remove(&hash);
        if self.finalized_at_height(height) == Some(hash) {
            // This IS the finalized block: it was applied, not orphaned.
            return InvalidationSignal {
                orphaned_blocks: Vec::new(),
                reason: format!("block at height {height} is the finalized block"),
                height,
            };
        }
        let signal = InvalidationSignal {
            orphaned_blocks: vec![hash],
            reason: format!("block at height {height} is below the finalized height"),
            height,
        };
        self.record_invalidation(signal.clone());
        signal
    }

    /// The recent invalidation signals (oldest first).
    pub fn recent_invalidations(&self) -> &[InvalidationSignal] {
        &self.invalidations
    }

    /// Prune the candidate branches that can no longer win, returning the
    /// invalidation signals for the blocks that were orphaned.
    ///
    /// A candidate block is ORPHANED when the finalized chain decided a
    /// DIFFERENT block at its height (that branch will never be applied) or
    /// when the finalized chain moved past its height without it (the
    /// branch is detached). The orphaned blocks are reported TIP-FIRST.
    ///
    /// A candidate that IS the finalized block is not orphaned — it was
    /// applied; it simply stops being a candidate.
    pub fn prune_superseded_candidates(&mut self) -> Vec<InvalidationSignal> {
        let mut signals: Vec<InvalidationSignal> = Vec::new();
        for tip in self.candidate_tips() {
            // The full ancestor path of the branch tip (root-first).
            let path = self.path_to_root(&tip);
            // The first CANDIDATE on the path that can never be applied.
            let mut diverged_at: Option<usize> = None;
            for (i, h) in path.iter().enumerate() {
                if !self.candidates.contains(h) {
                    // An applied ancestor: it was finalized, it is canonical.
                    continue;
                }
                let bh = self.tree.height_of(h).unwrap_or(0);
                let invalid = match self.finalized_at_height(bh) {
                    // The finalized chain decided a DIFFERENT block here.
                    Some(f) => f != *h,
                    // The finalized chain moved past this height without
                    // this block: the branch is detached.
                    None => bh < self.finalized_height,
                };
                if invalid {
                    diverged_at = Some(i);
                    break;
                }
            }
            let Some(i) = diverged_at else { continue };
            // Only the CANDIDATE blocks are orphaned: the ancestors below
            // them were applied (they are canonical, not invalidated).
            let orphaned: Vec<BlockHash> = path[i..]
                .iter()
                .rev()
                .filter(|h| self.candidates.contains(*h))
                .copied()
                .collect();
            if orphaned.is_empty() {
                continue;
            }
            let height = self
                .tree
                .height_of(orphaned.last().unwrap_or(&orphaned[0]))
                .unwrap_or(0);
            for h in &orphaned {
                self.candidates.remove(h);
            }
            let signal = InvalidationSignal {
                orphaned_blocks: orphaned,
                reason: format!("candidate branch superseded at height {height}"),
                height,
            };
            self.record_invalidation(signal.clone());
            signals.push(signal);
        }
        if self
            .candidate_head
            .map(|h| !self.candidates.contains(&h))
            .unwrap_or(false)
        {
            self.candidate_head = None;
        }
        signals
    }

    /// Adopt `block` as the ROOT of the tree.
    ///
    /// The node's known committed tip becomes the anchor the fork-choice
    /// works from: the ancestors below it were never seen by this node, so
    /// they are not in the tree. Candidate branches that do not descend from
    /// the new root are orphaned, and their invalidation signal is
    /// returned.
    pub fn adopt_root(&mut self, block: Block) -> (BlockHash, Vec<InvalidationSignal>) {
        let hash = self.tree.insert(block);
        let height = self.tree.height_of(&hash).unwrap_or(0);
        self.finalized_height = height;
        self.finalized_hash = hash;
        self.canonical = vec![hash];
        self.finalized_index.clear();
        self.finalized_order.clear();
        // STAB: the epoch-MMR cache keys epochs to finalized hashes of THIS
        // chain; a re-anchor drops a different chain underneath, so cached
        // roots must go with the old index (stale entries are unreachable
        // today because heights only finalize forward, but a re-anchor is
        // exactly the event that breaks that invariant).
        if let Ok(mut g) = self.mmr_cache.lock() {
            g.clear();
        }
        self.note_finalized_height(height, hash);
        self.candidates.remove(&hash);
        let signals = self.prune_detached_candidates();
        (hash, signals)
    }

    /// Drop the candidates that no longer descend from the finalized head
    /// and report them as orphaned.
    fn prune_detached_candidates(&mut self) -> Vec<InvalidationSignal> {
        let detached: Vec<BlockHash> = self
            .candidates
            .iter()
            .copied()
            .filter(|h| !self.descends_from_finalized(h))
            .collect();
        let mut signals = Vec::new();
        for h in detached {
            self.candidates.remove(&h);
            let height = self.tree.height_of(&h).unwrap_or(0);
            let signal = InvalidationSignal {
                orphaned_blocks: vec![h],
                reason: "candidate branch detached from the finalized chain".to_string(),
                height,
            };
            self.record_invalidation(signal.clone());
            signals.push(signal);
        }
        if self
            .candidate_head
            .map(|h| !self.candidates.contains(&h))
            .unwrap_or(false)
        {
            self.candidate_head = None;
        }
        signals
    }

    /// Bound the candidate set: the OLDEST (lowest) candidates are dropped
    /// first, and the drop is reported as an invalidation (those blocks are
    /// gone for good — they will never be applied).
    fn trim_candidates(&mut self) {
        if self.candidates.len() <= MAX_TRACKED_CANDIDATES {
            return;
        }
        let mut ordered: Vec<(Height, BlockHash)> = self
            .candidates
            .iter()
            .map(|h| (self.tree.height_of(h).unwrap_or(0), *h))
            .collect();
        ordered.sort();
        let excess = self.candidates.len() - MAX_TRACKED_CANDIDATES;
        let dropped: Vec<BlockHash> = ordered.into_iter().take(excess).map(|(_, h)| h).collect();
        for h in &dropped {
            self.candidates.remove(h);
        }
        let height = dropped
            .iter()
            .filter_map(|h| self.tree.height_of(h))
            .min()
            .unwrap_or(self.finalized_height);
        let signal = InvalidationSignal {
            orphaned_blocks: dropped,
            reason: "candidate window trimmed (too many tracked branches)".to_string(),
            height,
        };
        self.record_invalidation(signal.clone());
        // PARK it as well: the trim happens inside `insert_candidate`, which
        // cannot publish anything itself, and a dropped candidate that nobody
        // hears about is a fork that vanishes without a trace (audit W6.4b).
        self.park_invalidation(signal);
    }

    /// Drop the tree entries strictly BELOW the finalized head.
    ///
    /// The fork-choice only needs the blocks at and above the finalized head
    /// (the candidate region); the finalized history is kept as hashes in
    /// `finalized_index`. This keeps a live node's memory bounded — without
    /// it the tree would hold every block the node ever saw.
    ///
    /// The finalized head's own parent link is dropped too, so the ancestor
    /// walk stops there instead of walking into the pruned history.
    pub fn prune_below_finalized(&mut self) {
        let keep = self.finalized_hash;
        let stale: Vec<BlockHash> = self
            .tree
            .blocks
            .keys()
            .copied()
            .filter(|h| {
                *h != keep
                    && self
                        .tree
                        .height_of(h)
                        .map(|hh| hh < self.finalized_height)
                        .unwrap_or(false)
            })
            .collect();
        for h in stale {
            self.tree.blocks.remove(&h);
            self.tree.height.remove(&h);
            if let Some(p) = self.tree.parent.get(&h).copied().flatten() {
                if let Some(cs) = self.tree.children.get_mut(&p) {
                    cs.retain(|c| c != &h);
                    if cs.is_empty() {
                        self.tree.children.remove(&p);
                    }
                }
            }
            self.tree.parent.remove(&h);
        }
        // The finalized head keeps its body (the candidate region is built
        // on it) but not its link to the pruned history.
        self.tree.parent.remove(&keep);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sharding::{Transaction, MASTERCHAIN_SHARD};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn block(height: u64, prev: [u8; 32], tag: u8) -> Block {
        let sk = SigningKey::generate(&mut OsRng);
        // make distinct hashes for forks at the same height via a unique tx
        let tx = Transaction {
            from: [tag; 32],
            to: [0u8; 32],
            amount: tag as u64,
            gas_limit: 0,
            nonce: 0,
            source_shard: 1,
            target_shard: 1,
            signature: vec![],
            payload: vec![],
            priority_fee_per_gas: 0,
        };
        let transactions = if height == 0 { vec![] } else { vec![tx] };
        let order_merkle_root = crate::mev::compute_order_merkle_root(&transactions);
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
            height,
            prev_hash: prev,
            state_root: [tag; 32],
            transactions,
            cross_shard_out: vec![],
            timestamp: height,
            proposer: sk.verifying_key().to_bytes(),
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            order_merkle_root,
            epoch_key_commitment: [0u8; 32],
            mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
        };
        b.sign_block(&sk);
        b
    }

    #[test]
    fn tree_links_and_ancestors() {
        let mut tree = BlockTree::new();
        let g = tree.insert(block(0, [0u8; 32], 0));
        let b1 = tree.insert(block(1, g, 1));
        let b2 = tree.insert(block(2, b1, 2));
        assert_eq!(tree.height_of(&b2), Some(2));
        assert_eq!(tree.parent_of(&b2), Some(b1));
        assert_eq!(tree.ancestors(&b2), vec![b2, b1, g]);
        assert_eq!(tree.chain_to(&b2), vec![g, b1, b2]);
    }

    #[test]
    fn fork_choice_picks_longest_chain() {
        let mut cm = ChainManager::new(block(0, [0u8; 32], 0));
        let g = cm.best_head();
        let a1 = cm.insert(block(1, g, 0xA1));
        let _a2 = cm.insert(block(2, a1, 0xA2));
        let b1 = cm.insert(block(1, g, 0xB1));
        let b2 = cm.insert(block(2, b1, 0xB2));
        let b3 = cm.insert(block(3, b2, 0xB3));
        cm.recompute_canonical();
        assert_eq!(
            cm.best_head(),
            b3,
            "fork-choice must pick the longest chain"
        );
    }

    #[test]
    fn reorg_plan_switches_fork() {
        let mut cm = ChainManager::new(block(0, [0u8; 32], 0));
        let g = cm.best_head();
        let a1 = cm.insert(block(1, g, 0xA1));
        let a2 = cm.insert(block(2, a1, 0xA2));
        cm.recompute_canonical();
        assert_eq!(cm.best_head(), a2);

        let b1 = cm.insert(block(1, g, 0xB1));
        let b2 = cm.insert(block(2, b1, 0xB2));
        let b3 = cm.insert(block(3, b2, 0xB3));

        // Plan BEFORE recompute: from canonical a2 to the new head b3.
        let plan = cm.reorg_plan(&b3).unwrap().unwrap();
        assert_eq!(plan.common_ancestor, g);
        assert_eq!(plan.rollback.len(), 2, "roll back A2, A1");
        assert_eq!(plan.apply.len(), 3, "apply B1, B2, B3");

        // Applying via recompute returns the same plan and moves the head.
        let applied = cm.recompute_canonical().unwrap();
        assert_eq!(applied, plan);
        assert_eq!(cm.best_head(), b3);
    }

    #[test]
    fn finalized_blocks_cannot_be_reorged() {
        let mut cm = ChainManager::new(block(0, [0u8; 32], 0));
        let g = cm.best_head();
        let a1 = cm.insert(block(1, g, 0xA1));
        let a2 = cm.insert(block(2, a1, 0xA2));
        cm.recompute_canonical();
        cm.finalize(a2).unwrap();
        assert!(cm.is_finalized(&a2));
        assert!(cm.is_finalized(&a1));

        // A competing fork below finality appears
        let b1 = cm.insert(block(1, g, 0xB1));
        let _b2 = cm.insert(block(2, b1, 0xB2));
        let b3 = cm.insert(block(3, b1, 0xB3));
        cm.recompute_canonical();
        // Best head must remain the finalized chain head (fork does not descend from it)
        assert_eq!(cm.best_head(), a2);
        // Reorg to a fork diverging below finality must be rejected
        assert!(
            cm.reorg_plan(&b3).is_err(),
            "reorg below finality must be rejected"
        );
    }

    #[test]
    fn finalize_rejects_non_extension() {
        let mut cm = ChainManager::new(block(0, [0u8; 32], 0));
        let g = cm.best_head();
        let a1 = cm.insert(block(1, g, 0xA1));
        let b1 = cm.insert(block(1, g, 0xB1));
        cm.finalize(a1).unwrap();
        // finalizing b1 (a sibling, not descending from a1) must fail
        assert!(cm.finalize(b1).is_err());
    }

    #[test]
    fn finalize_rejects_below_finalized_height() {
        let mut cm = ChainManager::new(block(0, [0u8; 32], 0));
        let g = cm.best_head();
        let a1 = cm.insert(block(1, g, 0xA1));
        let a2 = cm.insert(block(2, a1, 0xA2));
        cm.finalize(a2).unwrap();
        assert!(
            cm.finalize(a1).is_err(),
            "cannot finalize below the finalized height"
        );
    }

    #[test]
    fn validate_extension_checks_parent_and_height() {
        let mut cm = ChainManager::new(block(0, [0u8; 32], 0));
        let g = cm.best_head();
        let a1 = cm.insert(block(1, g, 0xA1));

        // valid: height 2 extending a1
        assert!(cm.validate_extension(&block(2, a1, 0xC1)).is_ok());
        // bad parent
        assert!(cm.validate_extension(&block(2, [0xEE; 32], 0xC2)).is_err());
        // wrong height (skips a level)
        assert!(cm.validate_extension(&block(5, a1, 0xC3)).is_err());
    }

    // ------------------------------------------------------------------
    // Candidates, fork-choice and invalidation signals
    // ------------------------------------------------------------------

    /// A candidate must be validated like any other extension: a forged
    /// block (no proposer signature) or one with an unknown parent never
    /// enters the tree.
    #[test]
    fn candidates_are_validated_extensions() {
        let mut cm = ChainManager::new(block(0, [0u8; 32], 0));
        let g = cm.best_head();
        // Unknown parent -> refused.
        assert!(cm.insert_candidate(block(1, [0xEE; 32], 0xC1)).is_err());
        // Wrong height -> refused.
        assert!(cm.insert_candidate(block(5, g, 0xC2)).is_err());
        // Valid -> recorded as a candidate, and NOT canonical.
        let c1 = cm.insert_candidate(block(1, g, 0xC3)).unwrap();
        assert_eq!(cm.candidates_at(1), vec![c1]);
        assert!(cm.canonical.is_empty() || !cm.canonical.contains(&c1));
    }

    /// The live-node case: two competing candidates at the same height, and
    /// the chain finalizes a THIRD block. The two candidates lost and are
    /// invalidated; the finalized block is not.
    #[test]
    fn superseded_candidates_are_invalidated() {
        let mut cm = ChainManager::new(block(0, [0u8; 32], 0));
        let g = cm.best_head();
        let c1 = cm.insert_candidate(block(1, g, 0xC1)).unwrap();
        let c2 = cm.insert_candidate(block(1, g, 0xC2)).unwrap();
        assert_eq!(cm.candidates_at(1).len(), 2);
        assert_eq!(cm.best_candidate(), Some(c1).min(Some(c2)));

        // A third block at the same height is finalized: it wins.
        let w = cm.insert(block(1, g, 0xF1));
        cm.finalize(w).unwrap();

        let signals = cm.prune_superseded_candidates();
        assert_eq!(signals.len(), 2, "one signal per lost branch");
        let mut orphaned: Vec<BlockHash> = signals
            .iter()
            .flat_map(|s| s.orphaned_blocks.clone())
            .collect();
        orphaned.sort();
        let mut expected = vec![c1, c2];
        expected.sort();
        assert_eq!(orphaned, expected, "both candidates are orphaned");
        assert!(signals.iter().all(|s| s.height == 1));
        assert!(
            !orphaned.contains(&w),
            "the finalized block was applied, it is not orphaned"
        );
        assert!(cm.candidates.is_empty(), "the lost branches are pruned");
        assert_eq!(cm.recent_invalidations().len(), 2);
    }

    /// A candidate branch of SEVERAL blocks that loses at its lowest height:
    /// every block of the branch is orphaned, and the signal reports the
    /// LOWEST invalidated height (the first height to re-sync from).
    #[test]
    fn a_multi_block_branch_reports_its_lowest_invalidated_height() {
        let mut cm = ChainManager::new(block(0, [0u8; 32], 0));
        let g = cm.best_head();
        let c1 = cm.insert_candidate(block(1, g, 0xC1)).unwrap();
        let c2 = cm.insert_candidate(block(2, c1, 0xC2)).unwrap();
        // Another block at height 1 is finalized: the whole branch loses.
        let w = cm.insert(block(1, g, 0xF1));
        cm.finalize(w).unwrap();
        let signals = cm.prune_superseded_candidates();
        assert_eq!(signals.len(), 1);
        assert_eq!(
            signals[0].orphaned_blocks,
            vec![c2, c1],
            "the orphaned blocks are reported tip-first"
        );
        assert_eq!(
            signals[0].height, 1,
            "the signal reports the LOWEST invalidated height"
        );
    }

    /// The candidate that WON the fork-choice and got finalized is not
    /// orphaned: it was applied, not invalidated.
    #[test]
    fn the_finalized_candidate_is_not_orphaned() {
        let mut cm = ChainManager::new(block(0, [0u8; 32], 0));
        let g = cm.best_head();
        let b = block(1, g, 0xC1);
        let c1 = cm.insert_candidate(b.clone()).unwrap();
        cm.insert(b);
        cm.finalize(c1).unwrap();
        let signals = cm.prune_superseded_candidates();
        assert!(signals.is_empty(), "the finalized candidate was applied");
        assert!(cm.candidates.is_empty(), "it is not a candidate any more");
    }

    /// A LONGER candidate branch wins the fork-choice: the plan rolls the
    /// old branch back and applies the new one, and the rolled-back blocks
    /// are signalled.
    #[test]
    fn a_longer_candidate_branch_triggers_a_reorg_plan() {
        let mut cm = ChainManager::new(block(0, [0u8; 32], 0));
        let g = cm.best_head();

        // Branch A: one block. The fork-choice adopts it.
        let a1 = cm.insert_candidate(block(1, g, 0xA1)).unwrap();
        let first = cm.candidate_reorg_plan(&a1).unwrap().unwrap();
        assert!(
            first.rollback.is_empty(),
            "the first candidate rolls nothing back"
        );
        cm.commit_candidate_reorg(&first, a1);
        assert_eq!(cm.candidate_head, Some(a1));

        // Branch B: two blocks. It is LONGER, so it wins.
        let b1 = cm.insert_candidate(block(1, g, 0xB1)).unwrap();
        let b2 = cm.insert_candidate(block(2, b1, 0xB2)).unwrap();
        assert_eq!(cm.best_candidate(), Some(b2));

        let plan = cm.candidate_reorg_plan(&b2).unwrap().unwrap();
        assert_eq!(plan.common_ancestor, g);
        assert_eq!(plan.rollback, vec![a1], "branch A is rolled back");
        assert_eq!(plan.apply, vec![b1, b2], "branch B is applied");

        let signal = cm.commit_candidate_reorg(&plan, b2);
        assert_eq!(signal.orphaned_blocks, vec![a1]);
        assert_eq!(signal.height, 1, "the first invalidated height");
        assert_eq!(cm.candidate_head, Some(b2));
        assert_eq!(cm.recent_invalidations().len(), 1);
        assert!(
            !cm.candidates.contains(&a1),
            "the rolled-back block is gone"
        );
    }

    /// A block that WAS finalized is NOT invalidated: it was applied, and
    /// announcing an applied block as invalidated would be a lie to every
    /// client that follows the chain.
    #[test]
    fn the_finalized_block_is_not_invalidated_on_the_spot() {
        let mut cm = ChainManager::new(block(0, [0u8; 32], 0));
        let g = cm.best_head();
        let f1 = block(1, g, 0xF1);
        let f1h = f1.compute_hash();
        cm.insert(f1.clone());
        cm.finalize(f1h).unwrap();
        let signal = cm.invalidate_block(&f1);
        assert!(signal.is_empty(), "an applied block is never invalidated");
        assert!(
            cm.recent_invalidations().is_empty(),
            "nothing is published for an applied block"
        );
    }

    /// The invalidation window is bounded and keeps the newest signals.
    #[test]
    fn the_invalidation_window_is_bounded() {
        let mut cm = ChainManager::new(block(0, [0u8; 32], 0));
        for i in 0..(MAX_INVALIDATION_WINDOW + 10) {
            cm.record_invalidation(InvalidationSignal {
                orphaned_blocks: vec![[i as u8; 32]],
                reason: format!("signal {i}"),
                height: i as u64,
            });
        }
        let win = cm.recent_invalidations();
        assert_eq!(win.len(), MAX_INVALIDATION_WINDOW);
        assert_eq!(
            win.last().unwrap().height,
            (MAX_INVALIDATION_WINDOW + 9) as u64
        );
        // An empty signal carries no information and is never recorded.
        let before = cm.recent_invalidations().len();
        cm.record_invalidation(InvalidationSignal {
            orphaned_blocks: vec![],
            reason: "nothing".to_string(),
            height: 0,
        });
        assert_eq!(cm.recent_invalidations().len(), before);
    }

    /// A node that joined mid-chain adopts the first finalized block it sees
    /// as the root of its tree; the candidates that do not descend from it
    /// are detached and invalidated.
    #[test]
    fn a_mid_chain_resume_adopts_a_root_and_detaches_the_rest() {
        let mut cm = ChainManager::detached();
        assert!(cm.is_empty());
        let root = block(10, [0xAA; 32], 0x10);
        let root_hash = root.compute_hash();
        let (_h, signals) = cm.adopt_root(root);
        assert!(signals.is_empty());
        assert_eq!(cm.finalized_height, 10);
        assert_eq!(cm.finalized_hash, root_hash);
        assert_eq!(cm.finalized_at_height(10), Some(root_hash));

        // A candidate on the new root is tracked.
        let c = cm.insert_candidate(block(11, root_hash, 0x11)).unwrap();
        assert_eq!(cm.candidates_at(11), vec![c]);
    }

    /// The tree must not grow without bound in a long-running node: the
    /// bodies below the finalized head are dropped, the hashes stay.
    #[test]
    fn pruning_below_the_finalized_head_keeps_the_history_hashes() {
        let mut cm = ChainManager::new(block(0, [0u8; 32], 0));
        let g = cm.best_head();
        let a1 = cm.insert(block(1, g, 0xA1));
        let a2 = cm.insert(block(2, a1, 0xA2));
        cm.finalize(a2).unwrap();
        cm.prune_below_finalized();
        assert!(!cm.tree.contains(&g), "the genesis body is dropped");
        assert!(cm.tree.contains(&a2), "the finalized head body is kept");
        assert_eq!(cm.finalized_at_height(0), Some(g));
        assert_eq!(cm.finalized_at_height(2), Some(a2));
    }

    /// V5 Tier-2: the MMR root over a fully finalized epoch commits to the
    /// finalized hashes in height order, and an incomplete epoch commits to
    /// nothing (`None` — the proposer carries zero instead of a guess).
    #[test]
    fn epoch_mmr_root_covers_a_fully_finalized_epoch() {
        let mut cm = ChainManager::new(block(0, [0u8; 32], 0));
        // Epoch 0 is heights 0..=127. Finalize 1..=127 sequentially.
        let mut prev = cm.best_head();
        for h in 1u64..=127 {
            let hash = cm.insert(block(h, prev, (h % 251) as u8));
            cm.finalize(hash).unwrap();
            prev = hash;
        }
        let (root, peaks) = cm.epoch_mmr_root(0).expect("epoch 0 is fully finalized");
        // Independent recomputation from the finalized hashes.
        let leaves: Vec<BlockHash> = (0u64..=127)
            .map(|h| cm.finalized_at_height(h).unwrap())
            .collect();
        let (expected, expected_peaks) = crate::mmr::mmr_root_for_leaves(&leaves);
        assert_eq!(root, expected);
        assert_eq!(peaks, expected_peaks);
        assert_eq!(peaks.len(), 1, "128 leaves form a single mountain");
        // A finalized leaf proves against the committed root.
        let m = crate::mmr::Mmr::of(&leaves);
        let proof = m.prove(5).expect("height 5 proves");
        assert_eq!(proof.leaf, cm.finalized_at_height(5).unwrap());
        assert!(proof.verify(&root));
        // Epoch 1 (heights 128..=255) is not finalized: no root.
        assert!(cm.epoch_mmr_root(1).is_none());
    }

    /// The finalized index is bounded: a node that runs for months does not
    /// grow its fork-choice index without limit.
    #[test]
    fn the_finalized_index_is_bounded() {
        let mut cm = ChainManager::new(block(0, [0u8; 32], 0));
        for i in 1..(MAX_FINALIZED_INDEX as u64 + 10) {
            cm.note_finalized_height(i, [i as u8; 32]);
        }
        assert!(
            cm.finalized_index.len() <= MAX_FINALIZED_INDEX,
            "the finalized index must stay bounded"
        );
        // The newest heights are the ones that survive.
        assert_eq!(
            cm.finalized_at_height(MAX_FINALIZED_INDEX as u64 + 9),
            Some([(MAX_FINALIZED_INDEX as u64 + 9) as u8; 32])
        );
        // The oldest are dropped.
        assert_eq!(cm.finalized_at_height(1), None);
    }
}
