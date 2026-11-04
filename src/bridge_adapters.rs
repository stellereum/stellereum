//! §8 chain adapters: LIVE deposit-proof verification framework.
//!
//! The audit gap this module closes: `TonWatcher` / `MultisigRelayer` /
//! `EvmWatcher` in `super` are OFFLINE MODELS - finality counters and
//! deduplication sets that never check source-chain data. Nothing in the
//! tree verified that a claimed deposit actually EXISTS on TON, Ethereum /
//! Arbitrum, or Solana. `TeleportBridgeEngine`'s `zk_proof` field is likewise
//! ALWAYS `None`.
//!
//! What this module IS:
//!
//! * a [`ChainAdapter`] trait every chain implements: `chain()` names the
//!   chain, `verify_deposit()` checks EVIDENCE SUPPLIED IN THE TRANSACTION
//!   against the claimed deposit, deterministically (no wall clock, no
//!   network, no RNG - safe to run inside consensus);
//! * a [`VerificationEvidence`] / [`DepositEvidence`] enum with three kinds:
//!   (a) [`DepositEvidence::QuorumAttested`] - the already-live
//!   relayer-quorum rule, adapted (same canonical message, same 2/3 DISTINCT
//!   threshold, same [`super::verify_quorum_signatures`] helper - no
//!   duplicated counting logic);
//!   (b) SPV-style header + inclusion-proof evidence, one variant per chain
//!   ([`DepositEvidence::TonCell`], [`DepositEvidence::EvmReceipt`],
//!   [`DepositEvidence::SolanaTx`]) - each one does REAL cryptographic
//!   verification (BoC cell-hash chain / compressed Patricia-Trie receipt
//!   proof / binary Merkle proof) against a quorum-signed header, plus a
//!   confirmation-depth check;
//!   (c) [`DepositEvidence::ZkProofPlaceholder`] - FAILS CLOSED, always,
//!   documenting where a real zk deposit proof plugs in;
//! * a generic, committable header-chain store ([`StoredHeader`] +
//!   [`HeaderStore`]) with real chaining validation, used TODAY by the
//!   off-chain watcher side and in tests.
//!
//! What this module is NOT (the explicit boundary):
//!
//! * consensus NEVER fetches. Adapters verify evidence carried in the
//!   transaction; they do no I/O. Header gossip / watchers that poll real
//!   chains are OFF-CHAIN daemons (out of scope by design): they PRODUCE the
//!   evidence, every node VERIFIES the same bytes. A full EVM light client
//!   (header-chain sync, fork choice, difficulty checks) is likewise out of
//!   scope - header authenticity on-chain is anchored TODAY by the same 2/3
//!   committed-validator quorum that already authorizes relay attestations,
//!   plus a cryptographic inclusion proof that binds the claimed coins to
//!   source-chain data. Committing header roots into consensus state (so a
//!   header needs no per-deposit signatures) is the documented next step.
//!
//! Per-adapter honesty ledger (what is REAL vs what stays stubbed):
//!
//! * TON (`TonAdapter`): REAL - BoC parsing via `crate::cell`, per-cell
//!   hash re-verification, root equality against the header `tx_root`,
//!   byte-exact leaf match binding `source_tx_hash`/`recipient`/`amount`,
//!   quorum-signed header, masterchain depth check. STUBBED - actual TON
//!   block layout parsing (the leaf is OUR canonical encoding, not a raw
//!   TON shard-block cell), header gossip/commitment.
//! * EVM (`EvmAdapter`): REAL - compressed Patricia-Trie receipt inclusion
//!   proof via `crate::cell::PatriciaTrie::verify_merkle_proof` (the same
//!   `cpat2` cryptography the state trie uses), receipt bytes bound to the
//!   claim, quorum-signed header, finality-depth check. STUBBED - RLP log
//!   decoding (receipts are OUR canonical encoding, not raw EVM logs),
//!   header sync.
//! * Solana (`SolanaAdapter`): REAL - binary SHA-256 Merkle inclusion proof
//!   with strict index binding, leaf bound to the claim, quorum-signed
//!   header, slot-depth check. STUBBED - Solana shred/ledger parsing, PoH
//!   verification, validator-vote anchoring (the header is quorum-signed by
//!   OUR relayers, not by Solana validators).
//! * zk deposit proofs: NO verification exists - the placeholder kind is
//!   rejected at BOTH layers (`validate_shape` and `verify`), loudly.

use crate::bridge::{
    SupportedChain, ARBITRUM_FINALITY_BLOCKS, ETHEREUM_FINALITY_BLOCKS, MIN_TON_CONFIRMATIONS,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Limits: every evidence field comes from untrusted transaction bytes, so
// every variable-length field has a hard cap enforced BEFORE any crypto.
// ---------------------------------------------------------------------------

/// Largest BoC blob an evidence may carry (64 KiB - a deposit leaf chain is
/// a handful of cells; anything bigger is garbage or a DoS attempt).
pub const MAX_DEPOSIT_BOC_BYTES: usize = 64 * 1024;
/// Largest receipt blob an EVM evidence may carry.
pub const MAX_RECEIPT_BYTES: usize = 64 * 1024;
/// Most Merkle siblings / MPT steps a proof may carry (a 256-bit key needs
/// at most 256 branch points; 64/256 are generous but bounded).
pub const MAX_BINARY_PROOF_SIBLINGS: usize = 64;
pub const MAX_MPT_PROOF_STEPS: usize = 256;
/// Most header signatures an evidence may carry (the validator set itself is
/// the practical bound; 1024 stops a junk vector from burning verify time).
pub const MAX_HEADER_SIGNATURES: usize = 1024;
/// Slots of Solana finality required before a Solana deposit is credited.
/// v1 choice: Solana finalizes in slots, and 32 matches the Arbitrum depth
/// already used for the optimistic rollup - documented as a policy knob, not
/// a measured Solana finality bound.
pub const SOLANA_FINALITY_SLOTS: u64 = 32;

// ---------------------------------------------------------------------------
// Deposit claim: the consensus-side statement an evidence must prove.
// ---------------------------------------------------------------------------

/// The deposit a transaction claims, in chain-agnostic form. Built by
/// `BridgeState::plan` from the [`super::BridgeIntent::Deposit`] under
/// review, so the adapter can never be asked to verify anything but the
/// exact coins the block would mint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositClaim {
    pub chain: SupportedChain,
    pub source_tx_hash: [u8; 32],
    pub recipient: [u8; 32],
    pub amount: u64,
}

/// What a successful verification returns: the claim, echoed back, plus
/// WHICH evidence kind proved it (observability for logs/tests - the plan
/// re-checks the echoed fields against the deposit before crediting).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDeposit {
    pub chain: SupportedChain,
    pub source_tx_hash: [u8; 32],
    pub recipient: [u8; 32],
    pub amount: u64,
    pub via: EvidenceKind,
}

/// Which evidence kind carried a verification (no wall clock, no data -
/// just the discriminant, so it stays deterministic).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceKind {
    Quorum,
    TonCell,
    EvmReceipt,
    SolanaTx,
}

// ---------------------------------------------------------------------------
// Canonical leaf / receipt encodings: the bytes each adapter binds to the
// claim. Domain-separated tags keep TON leaves, EVM receipts and Solana
// leaves from ever colliding with each other (or with anything else).
// ---------------------------------------------------------------------------

/// TON deposit leaf: what the BoC chain must decode to, byte-for-byte.
pub fn ton_leaf_encoding(claim: &DepositClaim) -> Vec<u8> {
    let mut b = Vec::with_capacity(20 + 32 + 32 + 8);
    b.extend_from_slice(b"STELL_TON_DEPOSIT_V1");
    b.extend_from_slice(&claim.source_tx_hash);
    b.extend_from_slice(&claim.recipient);
    b.extend_from_slice(&claim.amount.to_be_bytes());
    b
}

/// EVM receipt key: where this deposit's receipt lives in the receipts trie.
pub fn evm_receipt_key(source_tx_hash: &[u8; 32], log_index: u32) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"STELL_EVM_RECEIPT_KEY_V1");
    h.update(source_tx_hash);
    h.update(log_index.to_be_bytes());
    h.finalize().into()
}

/// EVM receipt value: the receipt bytes the MPT proof must authenticate.
pub fn evm_receipt_encoding(
    chain: SupportedChain,
    source_tx_hash: &[u8; 32],
    log_index: u32,
    recipient: &[u8; 32],
    amount: u64,
) -> Vec<u8> {
    let tag = match chain {
        SupportedChain::Ethereum => 0x01u8,
        SupportedChain::Arbitrum => 0x02u8,
        _ => 0x00u8,
    };
    let mut b = Vec::with_capacity(21 + 1 + 32 + 4 + 32 + 8);
    b.extend_from_slice(b"STELL_EVM_RECEIPT_V1");
    b.push(tag);
    b.extend_from_slice(source_tx_hash);
    b.extend_from_slice(&log_index.to_be_bytes());
    b.extend_from_slice(recipient);
    b.extend_from_slice(&amount.to_be_bytes());
    b
}

/// Solana deposit leaf: the Merkle leaf the inclusion proof must open to.
pub fn solana_leaf_encoding(claim: &DepositClaim) -> Vec<u8> {
    let mut b = Vec::with_capacity(20 + 32 + 32 + 8);
    b.extend_from_slice(b"STELL_SOL_DEPOSIT_V1");
    b.extend_from_slice(&claim.source_tx_hash);
    b.extend_from_slice(&claim.recipient);
    b.extend_from_slice(&claim.amount.to_be_bytes());
    b
}

// ---------------------------------------------------------------------------
// StoredHeader + HeaderStore: the generic, committable header chain.
// ---------------------------------------------------------------------------

/// One source-chain header, in chain-agnostic form. `height` is the chain's
/// native block number (masterchain seqno / EVM block number / Solana slot)
/// and `tx_root` is the chain's native inclusion root (TON BoC root / EVM
/// receipts-trie root / Solana transaction-Merkle root).
///
/// Deliberately free of signatures: the header is DATA, the quorum over it
/// travels with the evidence that cites it (or, off-chain, in the watcher's
/// store discipline below).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredHeader {
    pub chain: SupportedChain,
    pub height: u64,
    pub prev_hash: [u8; 32],
    pub tx_root: [u8; 32],
}

impl StoredHeader {
    /// Explicit 1-byte chain tag (NOT the enum discriminant order, which a
    /// future variant reorder must never silently change under a hash).
    pub fn chain_tag(chain: SupportedChain) -> u8 {
        match chain {
            SupportedChain::Ton => 0x54,      // 'T'
            SupportedChain::Arbitrum => 0x41, // 'A'
            SupportedChain::Ethereum => 0x45, // 'E'
            SupportedChain::Solana => 0x53,   // 'S'
        }
    }

    /// Canonical bytes everything hashes and signs.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(1 + 8 + 32 + 32);
        b.push(Self::chain_tag(self.chain));
        b.extend_from_slice(&self.height.to_be_bytes());
        b.extend_from_slice(&self.prev_hash);
        b.extend_from_slice(&self.tx_root);
        b
    }

    /// `sha256(canonical_bytes)` - the header id chaining and (off-chain)
    /// the store link.
    pub fn header_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.canonical_bytes());
        h.finalize().into()
    }

    /// What validators sign to attest this header.
    pub fn signing_message(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(22 + 73);
        b.extend_from_slice(b"STELL_BRIDGE_HEADER_V1");
        b.extend_from_slice(&self.canonical_bytes());
        b
    }
}

/// Deterministic header-chain store for the OFF-CHAIN watcher side (and for
/// tests). `BTreeMap` only - iteration order is identical on every node.
///
/// Chaining discipline, enforced in [`HeaderStore::insert`]: a header whose
/// parent is already known must link to it (`prev_hash ==
/// parent.header_hash()`); a header that conflicts with a KNOWN
/// `(chain, height)` is refused rather than overwritten (a reorg cannot
/// silently rewrite history - it has to be handled explicitly).
///
/// NOT consulted by consensus `verify` paths: on-chain trust comes from the
/// quorum signatures carried with the evidence (see the module docs). This
/// store is where a future committed-headers design would read from.
#[derive(Clone, Debug, Default)]
pub struct HeaderStore {
    headers: BTreeMap<(u8, u64), StoredHeader>,
}

impl HeaderStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.headers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    /// Insert a header, enforcing the chaining discipline above. Idempotent
    /// for the identical header; FAILS CLOSED on conflicts and broken links.
    pub fn insert(&mut self, header: StoredHeader) -> Result<(), String> {
        let key = (StoredHeader::chain_tag(header.chain), header.height);
        if let Some(known) = self.headers.get(&key) {
            if *known == header {
                return Ok(());
            }
            return Err(format!(
                "header store: conflicting header for chain tag {} at height {}",
                key.0, key.1
            ));
        }
        if header.height > 0 {
            if let Some(parent) = self.headers.get(&(key.0, header.height - 1)) {
                if header.prev_hash != parent.header_hash() {
                    return Err(format!(
                        "header store: header at height {} does not link to its parent",
                        header.height
                    ));
                }
            }
        }
        self.headers.insert(key, header);
        Ok(())
    }

    pub fn get(&self, chain: SupportedChain, height: u64) -> Option<&StoredHeader> {
        self.headers.get(&(StoredHeader::chain_tag(chain), height))
    }

    pub fn contains(&self, chain: SupportedChain, height: u64) -> bool {
        self.get(chain, height).is_some()
    }

    /// Newest header known for `chain`, if any (deterministic: max height).
    pub fn latest(&self, chain: SupportedChain) -> Option<&StoredHeader> {
        let tag = StoredHeader::chain_tag(chain);
        self.headers
            .iter()
            .rev()
            .find(|((t, _), _)| *t == tag)
            .map(|(_, h)| h)
    }
}

// ---------------------------------------------------------------------------
// Binary Merkle proofs (Solana adapter + generic SPV fixture support).
// ---------------------------------------------------------------------------

/// One step of a binary SHA-256 inclusion path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryMerkleSibling {
    /// Hash of the sibling node at this level.
    pub hash: [u8; 32],
    /// True when the sibling sits to the RIGHT of the running node.
    pub sibling_is_right: bool,
}

/// A binary inclusion proof: `siblings[0]` is the leaf level.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryMerkleProof {
    pub leaf_index: u32,
    pub siblings: Vec<BinaryMerkleSibling>,
}

fn binary_leaf_hash(leaf: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"STELL_ADAPTER_LEAF_V1");
    h.update(leaf);
    h.finalize().into()
}

fn binary_parent(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"STELL_ADAPTER_NODE_V1");
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Root of `leaves` under the domain-separated binary tree (odd nodes are
/// duplicated, the standard Bitcoin-style rule). `Err` on empty input -
/// there is no meaningful root of nothing.
pub fn build_binary_merkle_root(leaves: &[Vec<u8>]) -> Result<[u8; 32], String> {
    if leaves.is_empty() {
        return Err("binary merkle tree needs at least one leaf".to_string());
    }
    let mut level: Vec<[u8; 32]> = leaves.iter().map(|l| binary_leaf_hash(l)).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let (l, r) = match pair {
                [l, r] => (*l, *r),
                [l] => (*l, *l),
                _ => unreachable!("chunks(2) yields 1 or 2 items"),
            };
            next.push(binary_parent(&l, &r));
        }
        level = next;
    }
    Ok(level[0])
}

/// Inclusion proof for `leaves[index]`. The position bits are cross-checked
/// at verify time, so a proof cannot be transplanted to another index.
pub fn binary_proof_for(leaves: &[Vec<u8>], index: usize) -> Result<BinaryMerkleProof, String> {
    if leaves.is_empty() {
        return Err("binary merkle tree needs at least one leaf".to_string());
    }
    if index >= leaves.len() {
        return Err("binary merkle proof index out of range".to_string());
    }
    let mut level: Vec<[u8; 32]> = leaves.iter().map(|l| binary_leaf_hash(l)).collect();
    let mut pos = index;
    let mut siblings = Vec::new();
    while level.len() > 1 {
        let sibling_pos = if pos.is_multiple_of(2) {
            if pos + 1 < level.len() {
                pos + 1
            } else {
                pos // duplicated odd node is its own sibling
            }
        } else {
            pos - 1
        };
        siblings.push(BinaryMerkleSibling {
            hash: level[sibling_pos],
            sibling_is_right: pos.is_multiple_of(2),
        });
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let (l, r) = match pair {
                [l, r] => (*l, *r),
                [l] => (*l, *l),
                _ => unreachable!("chunks(2) yields 1 or 2 items"),
            };
            next.push(binary_parent(&l, &r));
        }
        level = next;
        pos /= 2;
    }
    Ok(BinaryMerkleProof {
        leaf_index: index as u32,
        siblings,
    })
}

/// Verify `proof` opens `leaf` at `proof.leaf_index` under `root`. Strict:
/// the running position must agree with each sibling side, and the final
/// node must equal `root`. Anything else - wrong root, transplanted proof,
/// truncated path - fails CLOSED.
pub fn verify_binary_merkle_proof(
    root: &[u8; 32],
    leaf: &[u8],
    proof: &BinaryMerkleProof,
) -> Result<(), String> {
    if proof.siblings.len() > MAX_BINARY_PROOF_SIBLINGS {
        return Err(format!(
            "binary merkle proof too long: {} steps",
            proof.siblings.len()
        ));
    }
    let mut cur = binary_leaf_hash(leaf);
    let mut pos = proof.leaf_index as usize;
    for sib in &proof.siblings {
        let expect_right = pos.is_multiple_of(2);
        if sib.sibling_is_right != expect_right {
            return Err("binary merkle proof side does not match leaf index".to_string());
        }
        cur = if sib.sibling_is_right {
            binary_parent(&cur, &sib.hash)
        } else {
            binary_parent(&sib.hash, &cur)
        };
        pos /= 2;
    }
    if &cur != root {
        return Err("binary merkle inclusion proof does not match the header root".to_string());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// DepositEvidence: what a deposit may cite INSTEAD OF (or alongside) the
// quorum attestation bundle.
// ---------------------------------------------------------------------------

/// Evidence a [`super::BridgeIntent::Deposit`] cites via the paired
/// [`super::BridgeIntent::DepositProof`] intent (same payload, paired by
/// `source_tx_hash` - exactly the `Attest` pattern, so existing `Deposit`
/// payload bytes are untouched).
///
/// Every chain-specific variant carries its OWN header plus the quorum
/// signatures ATTESTING THAT HEADER: the header is untrusted bytes until
/// the committed validator set has signed it, and the inclusion proof then
/// binds the claimed coins to that header's root. `finalized_*` is likewise
/// evidence-supplied (the watcher states what head it saw); the adapter
/// only checks the DEPTH arithmetic, never a clock, never the network.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DepositEvidence {
    /// (a) The already-live relay rule as evidence: ed25519 signatures over
    /// `TeleportBridgeEngine::deposit_signing_message` of the claim.
    /// Verified by the SAME [`super::verify_quorum_signatures`] helper the
    /// engine uses - no duplicated threshold logic.
    QuorumAttested {
        signatures: Vec<([u8; 32], Vec<u8>)>,
    },
    /// (b-TON) BoC cell-chain inclusion: `boc_bytes` must parse as a bag of
    /// cells whose every cell hash re-verifies, whose root equals
    /// `header.tx_root`, and whose bytes equal the claim's TON leaf.
    TonCell {
        header: StoredHeader,
        /// Quorum over `header.signing_message()`.
        header_signatures: Vec<([u8; 32], Vec<u8>)>,
        /// Finalized masterchain seqno the watcher observed (depth =
        /// `finalized_seqno - header.height`).
        finalized_seqno: u64,
        boc_bytes: Vec<u8>,
    },
    /// (b-EVM) Receipts-trie inclusion: `receipt_value` must equal the
    /// claim's canonical receipt AND open under `header.tx_root` via the
    /// compressed Patricia-Trie proof.
    EvmReceipt {
        header: StoredHeader,
        /// Quorum over `header.signing_message()`.
        header_signatures: Vec<([u8; 32], Vec<u8>)>,
        /// Finalized head the watcher observed (depth =
        /// `finalized_number - header.height`).
        finalized_number: u64,
        log_index: u32,
        receipt_value: Vec<u8>,
        mpt_proof: crate::cell::MerkleProof,
    },
    /// (b-SOL) Transaction Merkle inclusion: the claim's Solana leaf must
    /// open under `header.tx_root` via the binary proof.
    SolanaTx {
        header: StoredHeader,
        /// Quorum over `header.signing_message()`.
        header_signatures: Vec<([u8; 32], Vec<u8>)>,
        /// Finalized slot the watcher observed (depth =
        /// `finalized_slot - header.height`).
        finalized_slot: u64,
        tx_index: u32,
        proof: BinaryMerkleProof,
    },
    /// (c) Where a real zk deposit proof plugs in. Carries nothing
    /// verifiable and is REJECTED at every layer - shape validation and
    /// verification both fail closed with a message that says exactly this.
    ZkProofPlaceholder { note: String },
}

impl DepositEvidence {
    /// Which kind this is (for `VerifiedDeposit::via` and for logs).
    pub fn kind(&self) -> EvidenceKind {
        match self {
            DepositEvidence::QuorumAttested { .. } => EvidenceKind::Quorum,
            DepositEvidence::TonCell { .. } => EvidenceKind::TonCell,
            DepositEvidence::EvmReceipt { .. } => EvidenceKind::EvmReceipt,
            DepositEvidence::SolanaTx { .. } => EvidenceKind::SolanaTx,
            DepositEvidence::ZkProofPlaceholder { .. } => {
                // Unreachable in honest code: the placeholder never verifies,
                // so no `VerifiedDeposit::via` ever names it. The label exists
                // so error paths can name the kind without a second match.
                EvidenceKind::Quorum
            }
        }
    }

    /// Cheap, deterministic shape check the VM runs BEFORE settlement (it
    /// has no validator set, so this checks sizes and kinds only - the
    /// cryptography runs at settlement, where the committed set is at hand).
    pub fn validate_shape(&self) -> Result<(), String> {
        match self {
            DepositEvidence::QuorumAttested { signatures } => {
                if signatures.is_empty() {
                    return Err("quorum evidence must carry at least one signature".to_string());
                }
                if signatures.len() > MAX_HEADER_SIGNATURES {
                    return Err("quorum evidence carries too many signatures".to_string());
                }
                Ok(())
            }
            DepositEvidence::TonCell {
                header_signatures,
                boc_bytes,
                ..
            } => {
                if header_signatures.is_empty() || header_signatures.len() > MAX_HEADER_SIGNATURES {
                    return Err("TON evidence needs 1..=1024 header signatures".to_string());
                }
                if boc_bytes.is_empty() || boc_bytes.len() > MAX_DEPOSIT_BOC_BYTES {
                    return Err("TON evidence BoC blob has an impossible size".to_string());
                }
                Ok(())
            }
            DepositEvidence::EvmReceipt {
                header_signatures,
                receipt_value,
                mpt_proof,
                ..
            } => {
                if header_signatures.is_empty() || header_signatures.len() > MAX_HEADER_SIGNATURES {
                    return Err("EVM evidence needs 1..=1024 header signatures".to_string());
                }
                if receipt_value.is_empty() || receipt_value.len() > MAX_RECEIPT_BYTES {
                    return Err("EVM evidence receipt has an impossible size".to_string());
                }
                if mpt_proof.path.len() > MAX_MPT_PROOF_STEPS {
                    return Err("EVM evidence proof path is too long".to_string());
                }
                Ok(())
            }
            DepositEvidence::SolanaTx {
                header_signatures,
                proof,
                ..
            } => {
                if header_signatures.is_empty() || header_signatures.len() > MAX_HEADER_SIGNATURES {
                    return Err("Solana evidence needs 1..=1024 header signatures".to_string());
                }
                if proof.siblings.len() > MAX_BINARY_PROOF_SIBLINGS {
                    return Err("Solana evidence proof is too long".to_string());
                }
                Ok(())
            }
            // FAIL CLOSED, loudly: a zk deposit proof kind exists on the wire
            // but no verifier exists behind it, so even a well-formed one is
            // refused here (and again in `verify`, belt and suspenders).
            DepositEvidence::ZkProofPlaceholder { .. } => Err(
                "zk deposit proofs are not yet supported: failing closed (no verifier exists)"
                    .to_string(),
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// ChainAdapter trait + adapters. Each adapter VERIFIES SOMETHING REAL (see
// the module honesty ledger); anything it cannot check fails closed.
// ---------------------------------------------------------------------------

/// A LIVE chain adapter: names its chain and verifies deposit evidence
/// against a claim, using ONLY the bytes handed to it plus the committed
/// validator set. No I/O, no clock, no RNG - deterministic across nodes.
pub trait ChainAdapter {
    fn chain(&self) -> SupportedChain;
    fn min_confirmations(&self) -> u64;
    fn verify_deposit(
        &self,
        claim: &DepositClaim,
        evidence: &DepositEvidence,
        validators: &[[u8; 32]],
    ) -> Result<VerifiedDeposit, String>;
}

/// Shared header gate every SPV adapter runs FIRST: the evidence variant
/// must be the adapter's own, the header must name the adapter's chain, and
/// the header must carry a 2/3 DISTINCT-validator quorum over its signing
/// message (the same rule as relay attestations - an unsigned or
/// outsider-signed header is "unknown" and fails closed).
fn check_header(
    adapter_chain: SupportedChain,
    header: &StoredHeader,
    header_signatures: &[([u8; 32], Vec<u8>)],
    evidence_name: &str,
    validators: &[[u8; 32]],
) -> Result<(), String> {
    if header.chain != adapter_chain {
        return Err(format!(
            "{evidence_name}: header chain mismatch (header names {:?})",
            header.chain
        ));
    }
    crate::bridge::verify_quorum_signatures(
        &header.signing_message(),
        header_signatures,
        validators,
    )
    .map(|_| ())
    .map_err(|e| format!("{evidence_name}: header is not quorum-attested: {e}"))?;
    Ok(())
}

/// Shared depth gate: `finalized - header.height` must reach the adapter's
/// minimum. Pure subtraction on evidence-supplied numbers - the adapter
/// trusts neither clocks nor chains, only this arithmetic.
fn check_depth(
    evidence_name: &str,
    header_height: u64,
    finalized: u64,
    min_confirmations: u64,
) -> Result<(), String> {
    // A header ahead of the finalized head is from the future, not buried:
    // refuse explicitly instead of letting `saturating_sub` report a 0 depth
    // that a zero-minimum adapter would accept (audit BR-OR-04).
    if header_height > finalized {
        return Err(format!(
            "{evidence_name}: header is ahead of the finalized head (refusing)"
        ));
    }
    let depth = finalized.saturating_sub(header_height);
    if depth < min_confirmations {
        return Err(format!(
            "{evidence_name}: not final ({depth} < {min_confirmations} confirmations)"
        ));
    }
    Ok(())
}

// --- TON: BoC cell-chain inclusion ------------------------------------------

/// LIVE TON adapter. Verifies, in order: evidence kind, header quorum,
/// masterchain depth, BoC parse, EVERY cell hash, root equality with the
/// header, and the byte-exact deposit leaf.
#[derive(Clone, Debug)]
pub struct TonAdapter {
    pub min_confirmations: u64,
    /// Watcher-side header memory (off-chain population via
    /// [`TonAdapter::track_header`]; NOT read by `verify_deposit` - see the
    /// module docs for why consensus trusts quorum-signed headers instead).
    pub headers: HeaderStore,
}

impl TonAdapter {
    pub fn new(min_confirmations: u64) -> Self {
        Self {
            min_confirmations,
            headers: HeaderStore::new(),
        }
    }

    /// Off-chain watcher entry point: remember a TON masterchain header.
    pub fn track_header(&mut self, header: StoredHeader) -> Result<(), String> {
        if header.chain != SupportedChain::Ton {
            return Err("TON adapter tracks only TON headers".to_string());
        }
        self.headers.insert(header)
    }
}

impl ChainAdapter for TonAdapter {
    fn chain(&self) -> SupportedChain {
        SupportedChain::Ton
    }

    fn min_confirmations(&self) -> u64 {
        self.min_confirmations
    }

    fn verify_deposit(
        &self,
        claim: &DepositClaim,
        evidence: &DepositEvidence,
        validators: &[[u8; 32]],
    ) -> Result<VerifiedDeposit, String> {
        if claim.chain != SupportedChain::Ton {
            return Err("TON adapter: claim is not a TON deposit".to_string());
        }
        let DepositEvidence::TonCell {
            header,
            header_signatures,
            finalized_seqno,
            boc_bytes,
        } = evidence
        else {
            return Err("TON adapter: evidence is not TON cell inclusion".to_string());
        };
        if boc_bytes.len() > MAX_DEPOSIT_BOC_BYTES {
            return Err("TON adapter: BoC blob exceeds the size cap".to_string());
        }
        check_header(
            SupportedChain::Ton,
            header,
            header_signatures,
            "TON evidence",
            validators,
        )?;
        check_depth(
            "TON evidence",
            header.height,
            *finalized_seqno,
            self.min_confirmations,
        )?;

        // REAL verification 1: the BoC must parse ...
        let boc = crate::cell::BagOfCells::from_boc_bytes(boc_bytes)
            .map_err(|e| format!("TON evidence: BoC does not parse: {e}"))?;
        if boc.roots.is_empty() {
            return Err("TON evidence: BoC carries no root".to_string());
        }
        // REAL verification 2: ... every stored cell hash must re-verify
        // (from_boc_bytes trusts the bytes; we do not) ...
        for (hash, cell) in &boc.cells {
            if &cell.compute_hash() != hash {
                return Err("TON evidence: BoC cell hash mismatch (tampered bag)".to_string());
            }
        }
        // REAL verification 3: ... the BoC root must BE the header's tx root ...
        if boc.roots[0] != header.tx_root {
            return Err("TON evidence: BoC root does not match the header tx root".to_string());
        }
        // REAL verification 4: ... and the chain must decode to EXACTLY the
        // claimed deposit (amount, recipient and source tx bound together).
        let expected = ton_leaf_encoding(claim);
        let actual = boc
            .read_bytes(&boc.roots[0])
            .ok_or_else(|| "TON evidence: BoC chain is unreadable".to_string())?;
        if actual != expected {
            return Err("TON evidence: BoC leaf does not match the claimed deposit".to_string());
        }
        Ok(VerifiedDeposit {
            chain: claim.chain,
            source_tx_hash: claim.source_tx_hash,
            recipient: claim.recipient,
            amount: claim.amount,
            via: EvidenceKind::TonCell,
        })
    }
}

// --- EVM: receipts-trie (Merkle-Patricia) inclusion --------------------------

/// LIVE EVM adapter (Ethereum and Arbitrum share the receipts-trie design;
/// the instance is pinned to one chain). Verifies: evidence kind + chain,
/// header quorum, finality depth, receipt-to-claim binding, and the REAL
/// compressed Patricia-Trie inclusion proof against the header root.
#[derive(Clone, Debug)]
pub struct EvmAdapter {
    pub chain: SupportedChain,
    pub min_confirmations: u64,
    /// Watcher-side header memory (off-chain; see [`TonAdapter::headers`]).
    pub headers: HeaderStore,
}

impl EvmAdapter {
    pub fn new(chain: SupportedChain, min_confirmations: u64) -> Self {
        debug_assert!(
            matches!(chain, SupportedChain::Ethereum | SupportedChain::Arbitrum),
            "EvmAdapter pins one EVM chain"
        );
        Self {
            chain,
            min_confirmations,
            headers: HeaderStore::new(),
        }
    }

    /// Off-chain watcher entry point: remember an EVM header.
    pub fn track_header(&mut self, header: StoredHeader) -> Result<(), String> {
        if header.chain != self.chain {
            return Err("EVM adapter tracks only its own chain's headers".to_string());
        }
        self.headers.insert(header)
    }
}

impl ChainAdapter for EvmAdapter {
    fn chain(&self) -> SupportedChain {
        self.chain
    }

    fn min_confirmations(&self) -> u64 {
        self.min_confirmations
    }

    fn verify_deposit(
        &self,
        claim: &DepositClaim,
        evidence: &DepositEvidence,
        validators: &[[u8; 32]],
    ) -> Result<VerifiedDeposit, String> {
        if claim.chain != self.chain {
            return Err("EVM adapter: claim is not for this chain".to_string());
        }
        let DepositEvidence::EvmReceipt {
            header,
            header_signatures,
            finalized_number,
            log_index,
            receipt_value,
            mpt_proof,
        } = evidence
        else {
            return Err("EVM adapter: evidence is not EVM receipt inclusion".to_string());
        };
        if receipt_value.len() > MAX_RECEIPT_BYTES {
            return Err("EVM adapter: receipt exceeds the size cap".to_string());
        }
        if mpt_proof.path.len() > MAX_MPT_PROOF_STEPS {
            return Err("EVM adapter: proof path exceeds the step cap".to_string());
        }
        check_header(
            self.chain,
            header,
            header_signatures,
            "EVM evidence",
            validators,
        )?;
        check_depth(
            "EVM evidence",
            header.height,
            *finalized_number,
            self.min_confirmations,
        )?;

        // REAL verification 1: the receipt bytes must be EXACTLY the claim's
        // canonical receipt (a valid proof for somebody else's receipt proves
        // nothing about this deposit).
        let expected = evm_receipt_encoding(
            claim.chain,
            &claim.source_tx_hash,
            *log_index,
            &claim.recipient,
            claim.amount,
        );
        if *receipt_value != expected {
            return Err("EVM evidence: receipt does not match the claimed deposit".to_string());
        }
        // REAL verification 2: the compressed Patricia-Trie proof must open
        // that receipt under the header's receipts root - the same `cpat2`
        // cryptography the state trie is verified with.
        let key = evm_receipt_key(&claim.source_tx_hash, *log_index);
        if !crate::cell::PatriciaTrie::verify_merkle_proof(
            &header.tx_root,
            &key,
            &expected,
            mpt_proof,
        ) {
            return Err("EVM evidence: receipt proof does not match the header root".to_string());
        }
        Ok(VerifiedDeposit {
            chain: claim.chain,
            source_tx_hash: claim.source_tx_hash,
            recipient: claim.recipient,
            amount: claim.amount,
            via: EvidenceKind::EvmReceipt,
        })
    }
}

// --- Solana: transaction-Merkle inclusion ------------------------------------

/// LIVE Solana adapter. Verifies: evidence kind, header quorum, slot depth,
/// and the REAL binary Merkle inclusion proof (with strict index binding)
/// opening the claim's leaf under the header root.
#[derive(Clone, Debug)]
pub struct SolanaAdapter {
    pub min_confirmations: u64,
    /// Watcher-side header memory (off-chain; see [`TonAdapter::headers`]).
    pub headers: HeaderStore,
}

impl SolanaAdapter {
    pub fn new(min_confirmations: u64) -> Self {
        Self {
            min_confirmations,
            headers: HeaderStore::new(),
        }
    }

    /// Off-chain watcher entry point: remember a Solana slot header.
    pub fn track_header(&mut self, header: StoredHeader) -> Result<(), String> {
        if header.chain != SupportedChain::Solana {
            return Err("Solana adapter tracks only Solana headers".to_string());
        }
        self.headers.insert(header)
    }
}

impl ChainAdapter for SolanaAdapter {
    fn chain(&self) -> SupportedChain {
        SupportedChain::Solana
    }

    fn min_confirmations(&self) -> u64 {
        self.min_confirmations
    }

    fn verify_deposit(
        &self,
        claim: &DepositClaim,
        evidence: &DepositEvidence,
        validators: &[[u8; 32]],
    ) -> Result<VerifiedDeposit, String> {
        if claim.chain != SupportedChain::Solana {
            return Err("Solana adapter: claim is not a Solana deposit".to_string());
        }
        let DepositEvidence::SolanaTx {
            header,
            header_signatures,
            finalized_slot,
            tx_index,
            proof,
        } = evidence
        else {
            return Err("Solana adapter: evidence is not Solana transaction inclusion".to_string());
        };
        check_header(
            SupportedChain::Solana,
            header,
            header_signatures,
            "Solana evidence",
            validators,
        )?;
        check_depth(
            "Solana evidence",
            header.height,
            *finalized_slot,
            self.min_confirmations,
        )?;
        if proof.leaf_index != *tx_index {
            return Err("Solana evidence: proof index does not match tx index".to_string());
        }
        // REAL verification: the claim's leaf must open under the header
        // root (index-bound, so the proof cannot wander to another leaf).
        let leaf = solana_leaf_encoding(claim);
        verify_binary_merkle_proof(&header.tx_root, &leaf, proof)
            .map_err(|e| format!("Solana evidence: {e}"))?;
        Ok(VerifiedDeposit {
            chain: claim.chain,
            source_tx_hash: claim.source_tx_hash,
            recipient: claim.recipient,
            amount: claim.amount,
            via: EvidenceKind::SolanaTx,
        })
    }
}

// ---------------------------------------------------------------------------
// Quorum-attested evidence (the live relay rule, adapted not duplicated).
// ---------------------------------------------------------------------------

/// Verify a quorum RETRACTION of `claim`: the committed validator set signed
/// the domain-separated "this deposit FAILED" message for exactly this
/// claim.
///
/// THE ONLY FRAUD PROOF IN LAYER 1 (audit W7.1). Nothing a transaction
/// carries can prove the ABSENCE of a source-chain event, so "evidence that
/// fails to verify" is NOT a fraud signal (SEC-01: an attacker could submit
/// dummy failing signatures and farm the 10% finder bounty on an honest
/// deposit). A retraction is the sound alternative: the relayer quorum - the
/// only body that witnesses the source chain - withdraws its own attestation
/// explicitly. It is verified with the SAME shared helper and the SAME
/// 2/3-distinct rule as every other quorum check, so it cannot be forged by
/// a challenger and cannot be transplanted onto another deposit (the
/// preimage binds chain, source tx hash, recipient and amount).
///
/// The retraction preimage lives next to the deposit preimage in
/// [`super::TeleportBridgeEngine::deposit_failure_signing_message`] - the two
/// are domain-separated, so a signature over one never verifies as the other.
pub fn verify_quorum_retraction(
    claim: &DepositClaim,
    signatures: &[([u8; 32], Vec<u8>)],
    validators: &[[u8; 32]],
) -> Result<(), String> {
    let msg = super::TeleportBridgeEngine::deposit_failure_signing_message(
        claim.chain,
        claim.source_tx_hash,
        claim.recipient,
        claim.amount,
    );
    crate::bridge::verify_quorum_signatures(&msg, signatures, validators)
        .map(|_| ())
        .map_err(|e| format!("quorum retraction: {e}"))
}

/// Verify [`DepositEvidence::QuorumAttested`] for `claim`: rebuild the exact
/// [`super::TeleportBridgeEngine::deposit_signing_message`] the live path
/// signs and count DISTINCT committed validators with the SHARED helper.
/// Replay and the empty-set guard stay where they belong (the engine/plan) -
/// this answers only "did the relayers attest THIS claim".
pub fn verify_quorum_evidence(
    claim: &DepositClaim,
    signatures: &[([u8; 32], Vec<u8>)],
    validators: &[[u8; 32]],
) -> Result<VerifiedDeposit, String> {
    let event = super::TeleportDepositEvent {
        source_chain: claim.chain,
        source_tx_hash: claim.source_tx_hash,
        recipient: claim.recipient,
        asset: super::LIVE_DEPOSIT_ASSET.to_string(),
        amount: claim.amount,
        validator_signatures: signatures.to_vec(),
        zk_proof: None,
    };
    let msg = super::TeleportBridgeEngine::deposit_signing_message(&event);
    crate::bridge::verify_quorum_signatures(&msg, signatures, validators)
        .map_err(|e| format!("quorum evidence: {e}"))?;
    Ok(VerifiedDeposit {
        chain: claim.chain,
        source_tx_hash: claim.source_tx_hash,
        recipient: claim.recipient,
        amount: claim.amount,
        via: EvidenceKind::Quorum,
    })
}

// ---------------------------------------------------------------------------
// verify_evidence: the single consensus entry point (called by plan).
// ---------------------------------------------------------------------------

/// Verify ANY evidence kind for `claim` against the committed validator set.
/// Dispatches on the CLAIM's chain (so a TON adapter can never be tricked
/// into verifying an EVM receipt and vice versa); the adapter then checks
/// the evidence variant matches. Deterministic: no I/O, no clock.
///
/// Depth policy per chain: TON `MIN_TON_CONFIRMATIONS`, Ethereum
/// `ETHEREUM_FINALITY_BLOCKS`, Arbitrum `ARBITRUM_FINALITY_BLOCKS`, Solana
/// `SOLANA_FINALITY_SLOTS` - the same constants the offline watchers use,
/// so the live verdict cannot drift from the modeled finality depths.
pub fn verify_evidence(
    claim: &DepositClaim,
    evidence: &DepositEvidence,
    validators: &[[u8; 32]],
) -> Result<VerifiedDeposit, String> {
    // Shape caps first: plan (and tests) may call this without the VM's
    // pre-check, so verification is self-sufficient. The placeholder is
    // refused HERE too, not just in validate_shape.
    evidence
        .validate_shape()
        .map_err(|e| format!("deposit evidence refused: {e}"))?;
    match evidence {
        DepositEvidence::QuorumAttested { signatures } => {
            verify_quorum_evidence(claim, signatures, validators)
        }
        DepositEvidence::TonCell { .. } => {
            TonAdapter::new(MIN_TON_CONFIRMATIONS).verify_deposit(claim, evidence, validators)
        }
        DepositEvidence::EvmReceipt { .. } => {
            let min = match claim.chain {
                SupportedChain::Ethereum => ETHEREUM_FINALITY_BLOCKS,
                SupportedChain::Arbitrum => ARBITRUM_FINALITY_BLOCKS,
                _ => {
                    return Err(
                        "EVM evidence for a non-EVM claim (Ethereum/Arbitrum only)".to_string()
                    );
                }
            };
            EvmAdapter::new(claim.chain, min).verify_deposit(claim, evidence, validators)
        }
        DepositEvidence::SolanaTx { .. } => {
            SolanaAdapter::new(SOLANA_FINALITY_SLOTS).verify_deposit(claim, evidence, validators)
        }
        DepositEvidence::ZkProofPlaceholder { .. } => Err(
            "zk deposit proofs are not yet supported: failing closed (no verifier exists)"
                .to_string(),
        ),
    }
}
