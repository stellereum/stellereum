//! Chain management: block tree, fork-choice and reorg planning.
//!
//! With BFT finality, a block at height H becomes irreversible once finalized.
//! Reorgs therefore only ever affect blocks ABOVE the finalized height. This
//! module keeps the full block tree, selects the canonical head (fork-choice)
//! and produces an explicit reorg plan (which blocks to roll back and which to
//! apply) so the state engine can replay deterministically.

use crate::sharding::Block;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub type BlockHash = [u8; 32];
pub type Height = u64;

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

/// Manages finality, the canonical chain and fork-choice over the block tree.
#[derive(Clone, Debug)]
pub struct ChainManager {
    pub tree: BlockTree,
    pub finalized_height: Height,
    pub finalized_hash: BlockHash,
    /// Canonical chain from genesis to the current best head (root first).
    pub canonical: Vec<BlockHash>,
}

impl ChainManager {
    /// Create from a genesis block (height 0).
    pub fn new(genesis: Block) -> Self {
        let mut tree = BlockTree::new();
        let g = tree.insert(genesis);
        Self {
            tree,
            finalized_height: 0,
            finalized_hash: g,
            canonical: vec![g],
        }
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
    fn choose_head(&self) -> BlockHash {
        let mut best: Option<(Height, BlockHash)> = None;
        for (hash, h) in &self.tree.height {
            if *h < self.finalized_height {
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
        self.tree
            .ancestors(hash)
            .iter()
            .any(|h| *h == self.finalized_hash)
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
        if !self.tree.ancestors(&hash).iter().any(|x| *x == self.finalized_hash) {
            return Err("block does not extend the finalized chain".to_string());
        }
        self.finalized_height = h;
        self.finalized_hash = hash;
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
        };
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
            height,
            prev_hash: prev,
            state_root: [tag; 32],
            transactions: if height == 0 { vec![] } else { vec![tx] },
            cross_shard_out: vec![],
            timestamp: height,
            proposer: sk.verifying_key().to_bytes(),
            validator_signatures: vec![],
            precommit_qc: None,
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
        assert_eq!(cm.best_head(), b3, "fork-choice must pick the longest chain");
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
        assert!(cm.reorg_plan(&b3).is_err(), "reorg below finality must be rejected");
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
        assert!(cm.finalize(a1).is_err(), "cannot finalize below the finalized height");
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
}
