//! Independent verification of block headers, body commitments, order Merkle roots,
//! cross-shard message commitments, and deterministic timestamp bounds.

use crate::wire::{
    Block, BlockHeader, CrossShardMessage, Transaction, VoteKind, DEFAULT_CHAIN_ID, XPC_LEGACY,
};
use sha2::{Digest, Sha256};

/// Domain separator for [`BlockHeader::compute_hash`] (v4 two-level header commitment).
pub const HEADER_COMMIT_V4_DOMAIN: &[u8] = b"STELLEREUM_HDR_V4\0";

/// Domain separator for [`body_commitment`] (v4 two-level header commitment).
pub const BODY_COMMITMENT_V4_DOMAIN: &[u8] = b"STELLEREUM_BODY_V4\0";

/// Domain separator for the legacy/v3 block hash fallback (`STELLEREUM_BLOCK_V3`).
pub const BLOCK_V3_DOMAIN: &[u8] = b"STELLEREUM_BLOCK_V3";

/// Compiled Ruleset v7 activation height for two-level header commitments.
pub const HEADER_COMMIT_ACTIVATION_HEIGHT: u64 = 0;

/// Domain separator for the transaction order Merkle root.
pub const ORDER_ROOT_DOMAIN: &[u8; 17] = b"STELL_ORDER_ROOT1";

/// Domain separator tags inside `STELLEREUM_BLOCK_V3` and `message_commitment`.
pub const ROUND_COMMITMENT_TAG: &[u8; 8] = b"ROUND001";
pub const ORDER_MERKLE_COMMITMENT_TAG: &[u8; 8] = b"ORDROOT1";
pub const XSHARD_FULL_COMMITMENT_TAG: &[u8; 8] = b"XSHARD01";
pub const SHARD_HEADERS_COMMITMENT_TAG: &[u8; 8] = b"SHARDHDR";
pub const EPOCH_KEY_COMMITMENT_TAG: &[u8; 8] = b"EPKEYC01";
pub const LAST_QC_COMMITMENT_TAG: &[u8; 8] = b"LASTQC01";
pub const MMR_EPOCH_COMMITMENT_TAG: &[u8; 8] = b"MMRROOT1";
pub const CNVRF_V3_COMMITMENT_TAG: &[u8; 8] = b"CNVRFV31";

/// Deterministic ceiling for a block timestamp ahead of its parent, in milliseconds.
pub const MAX_BLOCK_TIMESTAMP_DRIFT_MS: u64 = 60 * 60 * 1_000;

/// True iff the two-level `BlockHeader` v4 commitment is active at `height`
/// under the given activation gate (`u64::MAX` means gated off).
pub const fn header_commit_active_at(height: u64, activation_height: u64) -> bool {
    activation_height != u64::MAX && height >= activation_height
}

/// True when `block_ts` is a deterministic extension of `parent_ts`:
/// monotone (`block_ts >= parent_ts`) and at most `MAX_BLOCK_TIMESTAMP_DRIFT_MS / 1000` seconds ahead.
pub const fn timestamp_within_bounds(parent_ts: u64, block_ts: u64) -> bool {
    block_ts >= parent_ts
        && block_ts <= parent_ts.saturating_add(MAX_BLOCK_TIMESTAMP_DRIFT_MS / 1_000)
}

impl BlockHeader {
    /// Compute the v4 header-level block hash (`b"STELLEREUM_HDR_V4\0"`) for `chain_id`.
    pub fn compute_hash(&self, chain_id: u64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(HEADER_COMMIT_V4_DOMAIN);
        hasher.update(chain_id.to_be_bytes());
        hasher.update(self.shard_id.to_be_bytes());
        hasher.update(self.height.to_be_bytes());
        hasher.update(self.round.to_be_bytes());
        hasher.update(self.prev_hash);
        hasher.update(self.state_root);
        hasher.update(self.body_commitment);
        hasher.update(self.mmr_epoch_root);
        hasher.update(self.epoch_key_commitment);
        hasher.update(self.timestamp.to_be_bytes());
        hasher.update(self.proposer);
        hasher.finalize().into()
    }

    /// Compute the v4 header-level block hash using [`DEFAULT_CHAIN_ID`] (`5757`).
    pub fn compute_hash_default_chain(&self) -> [u8; 32] {
        self.compute_hash(DEFAULT_CHAIN_ID)
    }
}

impl CrossShardMessage {
    /// Recompute the expected `msg_id` from the message fields.
    pub fn expected_msg_id(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        if self.xpc_phase != XPC_LEGACY {
            hasher.update(b"XPC2");
            hasher.update([self.xpc_phase]);
        }
        hasher.update(self.source_shard.to_be_bytes());
        hasher.update(self.target_shard.to_be_bytes());
        hasher.update(self.tx.compute_tx_hash());
        hasher.update(self.finalized_in_block);
        hasher.finalize().into()
    }

    /// True iff `self.msg_id` matches [`Self::expected_msg_id`].
    pub fn verify_msg_id(&self) -> bool {
        self.msg_id == self.expected_msg_id()
    }

    /// Canonical commitment bytes over all consensus-relevant fields of the message
    /// (excluding `msg_id` and local-only `trusted`).
    pub fn commitment_bytes(&self) -> Vec<u8> {
        bincode::serialize(&(
            self.source_shard,
            self.target_shard,
            &self.tx,
            &self.merkle_inclusion_proof,
            &self.source_state_root,
            &self.finalized_in_block,
            self.source_balance,
            self.bounce,
            self.bounced,
            &self.sender_pubkey_hash,
            &self.sender_scheme,
            self.xpc_phase,
        ))
        .unwrap_or_default()
    }

    /// Domain-tagged SHA-256 commitment over [`Self::commitment_bytes`].
    pub fn message_commitment(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(XSHARD_FULL_COMMITMENT_TAG);
        let bytes = self.commitment_bytes();
        hasher.update((bytes.len() as u32).to_be_bytes());
        hasher.update(&bytes);
        hasher.finalize().into()
    }
}

/// Verify that every [`CrossShardMessage`] in `block.cross_shard_out` has a valid `msg_id`.
pub fn verify_cross_shard_msg_ids(block: &Block) -> bool {
    block.cross_shard_out.iter().all(|m| m.verify_msg_id())
}

/// Verify that a candidate `CrossShardMessage` matches its expected `msg_id` and
/// optionally a claimed `message_commitment`.
pub fn verify_xshard_message_commitment(
    msg: &CrossShardMessage,
    expected_commitment: Option<&[u8; 32]>,
) -> bool {
    if !msg.verify_msg_id() {
        return false;
    }
    if let Some(expected) = expected_commitment {
        return &msg.message_commitment() == expected;
    }
    true
}

/// Compute the BLAKE3 order Merkle root over an ordered slice of 32-byte transaction hashes.
pub fn order_merkle_root_of_hashes(hashes: &[[u8; 32]]) -> [u8; 32] {
    if hashes.is_empty() {
        return [0u8; 32];
    }
    let mut level: Vec<[u8; 32]> = hashes
        .iter()
        .map(|h| {
            let mut hasher = blake3::Hasher::new();
            hasher.update(ORDER_ROOT_DOMAIN);
            hasher.update(&[0x00u8]);
            hasher.update(h);
            *hasher.finalize().as_bytes()
        })
        .collect();
    while level.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::with_capacity(level.len().div_ceil(2));
        let mut pair = level.chunks_exact(2);
        for c in pair.by_ref() {
            let mut hasher = blake3::Hasher::new();
            hasher.update(ORDER_ROOT_DOMAIN);
            hasher.update(&[0x01u8]);
            hasher.update(&c[0]);
            hasher.update(&c[1]);
            next.push(*hasher.finalize().as_bytes());
        }
        if let Some(last) = pair.remainder().first() {
            next.push(*last);
        }
        level = next;
    }
    let tree = level[0];
    let mut hasher = blake3::Hasher::new();
    hasher.update(ORDER_ROOT_DOMAIN);
    hasher.update(&[0x02u8]);
    hasher.update(&(hashes.len() as u64).to_be_bytes());
    hasher.update(&tree);
    let mut root = *hasher.finalize().as_bytes();
    let mut counter: u8 = 0;
    while root == [0u8; 32] {
        counter = counter.wrapping_add(1);
        let mut retry = blake3::Hasher::new();
        retry.update(ORDER_ROOT_DOMAIN);
        retry.update(&[0x03u8]);
        retry.update(&counter.to_be_bytes());
        retry.update(&tree);
        root = *retry.finalize().as_bytes();
    }
    root
}

/// Compute the BLAKE3 order Merkle root over an ordered slice of [`Transaction`].
pub fn compute_order_merkle_root(txs: &[Transaction]) -> [u8; 32] {
    if txs.is_empty() {
        return [0u8; 32];
    }
    let hashes: Vec<[u8; 32]> = txs.iter().map(Transaction::compute_tx_hash).collect();
    order_merkle_root_of_hashes(&hashes)
}

/// True iff `block.order_merkle_root` equals [`compute_order_merkle_root(&block.transactions)`].
pub fn verify_order_merkle_root(block: &Block) -> bool {
    block.order_merkle_root == compute_order_merkle_root(&block.transactions)
}

/// Compute the canonical v4 body commitment (`b"STELLEREUM_BODY_V4\0"`) over the
/// 6 body fields of `block`: `transactions`, `order_merkle_root`, `cross_shard_out`,
/// `shard_headers`, `last_qc`, and `cnvrf_v3`.
pub fn body_commitment(block: &Block) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(BODY_COMMITMENT_V4_DOMAIN);

    // 1. transactions
    hasher.update((block.transactions.len() as u32).to_be_bytes());
    if !block.transactions.is_empty() {
        let mut payload_buf = Vec::new();
        let mut tx_hasher = Sha256::new();
        for tx in &block.transactions {
            tx.hash_into(&mut tx_hasher, &mut payload_buf);
            let h: [u8; 32] = tx_hasher.finalize_reset().into();
            hasher.update(h);
        }
    }

    // 2. order_merkle_root (32 B, unconditionally)
    hasher.update(block.order_merkle_root);

    // 3. cross_shard_out (msg_id + fixed 32 B message_commitment)
    hasher.update((block.cross_shard_out.len() as u32).to_be_bytes());
    for m in &block.cross_shard_out {
        hasher.update(m.msg_id);
        hasher.update(m.message_commitment());
    }

    // 4. shard_headers (length-prefixed commitment_bytes per entry)
    hasher.update((block.shard_headers.len() as u32).to_be_bytes());
    for sh in &block.shard_headers {
        let sh_bytes = sh.commitment_bytes();
        hasher.update((sh_bytes.len() as u32).to_be_bytes());
        hasher.update(&sh_bytes);
    }

    // 5. last_qc (includes shard_id, canonical sorted (voter, sig))
    match &block.last_qc {
        None => hasher.update([0u8]),
        Some(qc) => {
            hasher.update([1u8]);
            hasher.update(qc.shard_id.to_be_bytes());
            hasher.update(qc.height.to_be_bytes());
            hasher.update(qc.round.to_be_bytes());
            hasher.update([match qc.kind {
                VoteKind::Prevote => 0u8,
                VoteKind::Precommit => 1u8,
            }]);
            match &qc.block_hash {
                Some(bh) => {
                    hasher.update([1u8]);
                    hasher.update(bh);
                }
                None => hasher.update([0u8]),
            }
            let mut sigs: Vec<(&[u8; 32], &[u8])> = qc
                .signatures
                .iter()
                .map(|(voter, sig)| (voter, sig.as_slice()))
                .collect();
            sigs.sort_by(|a, b| a.0.cmp(b.0).then_with(|| a.1.cmp(b.1)));
            hasher.update((sigs.len() as u32).to_be_bytes());
            for (voter, sig) in sigs {
                hasher.update(voter);
                hasher.update((sig.len() as u32).to_be_bytes());
                hasher.update(sig);
            }
        }
    }

    // 6. cnvrf_v3 (length-prefixed canonical_bytes)
    match &block.cnvrf_v3 {
        None => hasher.update([0u8]),
        Some(payload) => {
            hasher.update([1u8]);
            let cb = payload.canonical_bytes();
            hasher.update((cb.len() as u32).to_be_bytes());
            hasher.update(&cb);
        }
    }

    hasher.finalize().into()
}

impl Block {
    /// Compute [`body_commitment`] for this block.
    pub fn body_commitment(&self) -> [u8; 32] {
        body_commitment(self)
    }

    /// Construct the two-level [`BlockHeader`] for this block.
    pub fn header(&self) -> BlockHeader {
        BlockHeader {
            shard_id: self.shard_id,
            height: self.height,
            round: self.round,
            prev_hash: self.prev_hash,
            state_root: self.state_root,
            body_commitment: self.body_commitment(),
            mmr_epoch_root: self.mmr_epoch_root,
            epoch_key_commitment: self.epoch_key_commitment,
            timestamp: self.timestamp,
            proposer: self.proposer,
        }
    }

    /// Compute the block hash under Ruleset v7 (`HEADER_COMMIT_ACTIVATION_HEIGHT = 0`)
    /// for `chain_id`.
    pub fn compute_hash(&self, chain_id: u64) -> [u8; 32] {
        compute_block_hash(self, chain_id)
    }

    /// Compute the round-free value identity (`round = 0`) under Ruleset v7 for `chain_id`.
    pub fn value_id(&self, chain_id: u64) -> [u8; 32] {
        value_id(self, chain_id)
    }
}

/// Compute the v4 two-level block hash for `block` with an explicit `round` and `chain_id`.
pub fn compute_block_hash_v4_with_round(block: &Block, chain_id: u64, round: u32) -> [u8; 32] {
    BlockHeader {
        round,
        ..block.header()
    }
    .compute_hash(chain_id)
}

/// Compute the legacy v3 flat block hash (`b"STELLEREUM_BLOCK_V3"`) with an explicit `round` and `chain_id`.
pub fn compute_block_hash_v3_with_round(block: &Block, chain_id: u64, round: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(BLOCK_V3_DOMAIN);
    hasher.update(chain_id.to_be_bytes());
    hasher.update(block.shard_id.to_be_bytes());
    hasher.update(block.height.to_be_bytes());
    if round != 0 {
        hasher.update(ROUND_COMMITMENT_TAG);
        hasher.update(round.to_be_bytes());
    }
    hasher.update(block.prev_hash);
    hasher.update(block.state_root);
    hasher.update((block.transactions.len() as u32).to_be_bytes());
    if !block.transactions.is_empty() {
        let mut payload_buf = Vec::new();
        let mut tx_hasher = Sha256::new();
        for tx in &block.transactions {
            tx.hash_into(&mut tx_hasher, &mut payload_buf);
            let h: [u8; 32] = tx_hasher.finalize_reset().into();
            hasher.update(h);
        }
    }
    if block.order_merkle_root != [0u8; 32] {
        hasher.update(ORDER_MERKLE_COMMITMENT_TAG);
        hasher.update(block.order_merkle_root);
    }
    hasher.update((block.cross_shard_out.len() as u32).to_be_bytes());
    for m in &block.cross_shard_out {
        hasher.update(m.msg_id);
    }
    if !block.cross_shard_out.is_empty() {
        hasher.update(XSHARD_FULL_COMMITMENT_TAG);
        hasher.update((block.cross_shard_out.len() as u32).to_be_bytes());
        for m in &block.cross_shard_out {
            hasher.update(m.message_commitment());
        }
    }
    if !block.shard_headers.is_empty() {
        hasher.update(SHARD_HEADERS_COMMITMENT_TAG);
        hasher.update((block.shard_headers.len() as u32).to_be_bytes());
        for h in &block.shard_headers {
            hasher.update(h.commitment_bytes());
        }
    }
    if block.epoch_key_commitment != [0u8; 32] {
        hasher.update(EPOCH_KEY_COMMITMENT_TAG);
        hasher.update(block.epoch_key_commitment);
    }
    if let Some(qc) = &block.last_qc {
        hasher.update(LAST_QC_COMMITMENT_TAG);
        hasher.update(qc.height.to_be_bytes());
        hasher.update(qc.round.to_be_bytes());
        hasher.update([match qc.kind {
            VoteKind::Prevote => 0u8,
            VoteKind::Precommit => 1u8,
        }]);
        if let Some(bh) = &qc.block_hash {
            hasher.update([1u8]);
            hasher.update(bh);
        } else {
            hasher.update([0u8]);
        }
        let mut sigs = qc.signatures.clone();
        sigs.sort_by(|a, b| a.0.cmp(&b.0));
        hasher.update((sigs.len() as u32).to_be_bytes());
        for (voter, sig) in &sigs {
            hasher.update(voter);
            hasher.update((sig.len() as u32).to_be_bytes());
            hasher.update(sig);
        }
    }
    if block.mmr_epoch_root != [0u8; 32] {
        hasher.update(MMR_EPOCH_COMMITMENT_TAG);
        hasher.update(block.mmr_epoch_root);
    }
    if let Some(payload) = &block.cnvrf_v3 {
        hasher.update(CNVRF_V3_COMMITMENT_TAG);
        hasher.update(payload.canonical_bytes());
    }
    hasher.update(block.timestamp.to_be_bytes());
    hasher.update(block.proposer);
    hasher.finalize().into()
}

/// Compute the block hash at an explicit `header_commit_activation_height` and `round`.
pub fn compute_block_hash_committing_round_at(
    block: &Block,
    chain_id: u64,
    round: u32,
    header_commit_activation_height: u64,
) -> [u8; 32] {
    if header_commit_active_at(block.height, header_commit_activation_height) {
        compute_block_hash_v4_with_round(block, chain_id, round)
    } else {
        compute_block_hash_v3_with_round(block, chain_id, round)
    }
}

/// Compute the canonical block hash under an explicit `header_commit_activation_height`.
pub fn compute_block_hash_at(
    block: &Block,
    chain_id: u64,
    header_commit_activation_height: u64,
) -> [u8; 32] {
    compute_block_hash_committing_round_at(
        block,
        chain_id,
        block.round,
        header_commit_activation_height,
    )
}

/// Compute the canonical block hash under Ruleset v7 (`HEADER_COMMIT_ACTIVATION_HEIGHT = 0`).
pub fn compute_block_hash(block: &Block, chain_id: u64) -> [u8; 32] {
    compute_block_hash_at(block, chain_id, HEADER_COMMIT_ACTIVATION_HEIGHT)
}

/// Compute the round-free value identity (`round = 0`) under an explicit
/// `header_commit_activation_height`.
pub fn value_id_at(block: &Block, chain_id: u64, header_commit_activation_height: u64) -> [u8; 32] {
    compute_block_hash_committing_round_at(block, chain_id, 0, header_commit_activation_height)
}

/// Compute the round-free value identity (`round = 0`) under Ruleset v7.
pub fn value_id(block: &Block, chain_id: u64) -> [u8; 32] {
    value_id_at(block, chain_id, HEADER_COMMIT_ACTIVATION_HEIGHT)
}
