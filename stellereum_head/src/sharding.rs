//! Sharding, Shared-Liquidity Hub & Blockchain Consensus
//! Masterchain + Shardchain paradigm (TON architecture)
//! Dynamic & infinite sharding with auto-split and merge under load.
//! Cross-shard atomic transactions with tight-coupling cryptographic Merkle proofs.
//! Shared Sequencer for unified execution and external L2 ordering.

use crate::cell::{CellHash, MerkleProof, PatriciaTrie};
use crate::post_quantum::{
    derive_pq_address, verify_pq_signature, PqScheme,
    StatefulImplicitKeyRegistry, DEFAULT_SALT, PQ_ENVELOPE_MAGIC,
};
use crate::zkml::SessionKeyAuthorization;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

static GLOBAL_IMPLICIT_KEY_REGISTRY: std::sync::OnceLock<StatefulImplicitKeyRegistry> =
    std::sync::OnceLock::new();

/// Global thread-safe implicit key registry for post-quantum wire verification.
pub fn global_implicit_key_registry() -> &'static StatefulImplicitKeyRegistry {
    GLOBAL_IMPLICIT_KEY_REGISTRY.get_or_init(StatefulImplicitKeyRegistry::new)
}

/// Signature envelope carrying post-quantum or hybrid signature payload.
///
/// Encoded format:
/// `b"PQ1" (3B) || scheme_id (1B) || is_implicit (1B) || [pubkey_len (2B) || pubkey || salt (16B)]? || sig_len (2B) || sig_bytes`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSignatureEnvelope {
    pub scheme: PqScheme,
    pub is_implicit: bool,
    pub pubkey: Option<Vec<u8>>,
    pub signature_bytes: Vec<u8>,
    pub salt: [u8; 16],
    #[serde(default)]
    pub chain_id: Option<u64>,
}

impl PqSignatureEnvelope {
    /// Create envelope with explicit public key attached and default salt.
    pub fn new_explicit(scheme: PqScheme, pubkey: Vec<u8>, signature_bytes: Vec<u8>) -> Self {
        Self {
            scheme,
            is_implicit: false,
            pubkey: Some(pubkey),
            signature_bytes,
            salt: DEFAULT_SALT,
            chain_id: None,
        }
    }

    /// Create envelope with explicit public key and custom salt attached.
    pub fn new_explicit_with_salt(
        scheme: PqScheme,
        pubkey: Vec<u8>,
        signature_bytes: Vec<u8>,
        salt: [u8; 16],
    ) -> Self {
        Self {
            scheme,
            is_implicit: false,
            pubkey: Some(pubkey),
            signature_bytes,
            salt,
            chain_id: None,
        }
    }

    /// Create envelope with explicit public key, custom salt, and chain_id bound.
    pub fn new_explicit_with_chain(
        scheme: PqScheme,
        pubkey: Vec<u8>,
        signature_bytes: Vec<u8>,
        salt: [u8; 16],
        chain_id: u64,
    ) -> Self {
        Self {
            scheme,
            is_implicit: false,
            pubkey: Some(pubkey),
            signature_bytes,
            salt,
            chain_id: Some(chain_id),
        }
    }

    /// Create envelope relying on implicit registered public key.
    pub fn new_implicit(scheme: PqScheme, signature_bytes: Vec<u8>) -> Self {
        Self {
            scheme,
            is_implicit: true,
            pubkey: None,
            signature_bytes,
            salt: DEFAULT_SALT,
            chain_id: None,
        }
    }

    /// Create envelope relying on implicit registered public key with chain_id bound.
    pub fn new_implicit_with_chain(
        scheme: PqScheme,
        signature_bytes: Vec<u8>,
        chain_id: u64,
    ) -> Self {
        Self {
            scheme,
            is_implicit: true,
            pubkey: None,
            signature_bytes,
            salt: DEFAULT_SALT,
            chain_id: Some(chain_id),
        }
    }

    /// Encodes envelope into canonical bytes prefixed by `b"PQ1"`.
    /// Includes `salt` (16 bytes) in explicit envelopes (`is_implicit = false`).
    /// Appends `chain_id` (8 bytes) if bound (Finding F1).
    pub fn encode(&self) -> Vec<u8> {
        let salt_len = if !self.is_implicit { 16 } else { 0 };
        let pk_len = self.pubkey.as_ref().map_or(0, |k| k.len());
        let chain_len = if self.chain_id.is_some() { 8 } else { 0 };
        let mut out = Vec::with_capacity(
            3 + 1 + 1 + 2 + pk_len + salt_len + 2 + self.signature_bytes.len() + chain_len,
        );
        out.extend_from_slice(PQ_ENVELOPE_MAGIC);
        out.push(self.scheme.id());
        out.push(if self.is_implicit { 1 } else { 0 });

        if let Some(pk) = &self.pubkey {
            let pk_len_u16 = pk.len() as u16;
            out.extend_from_slice(&pk_len_u16.to_le_bytes());
            out.extend_from_slice(pk);
        } else {
            out.extend_from_slice(&0u16.to_le_bytes());
        }

        if !self.is_implicit {
            out.extend_from_slice(&self.salt);
        }

        let sig_len = self.signature_bytes.len() as u16;
        out.extend_from_slice(&sig_len.to_le_bytes());
        out.extend_from_slice(&self.signature_bytes);
        if let Some(cid) = self.chain_id {
            out.extend_from_slice(&cid.to_be_bytes());
        }
        out
    }

    /// Wire byte length for legacy envelopes without salt.
    pub fn legacy_encode_len(&self) -> usize {
        let chain_len = if self.chain_id.is_some() { 8 } else { 0 };
        3 + 1 + 1 + 2 + self.pubkey.as_ref().map_or(0, |k| k.len()) + 2 + self.signature_bytes.len() + chain_len
    }

    /// Decodes envelope from byte slice.
    /// Supports explicit envelopes with salt, implicit envelopes, and legacy explicit envelopes.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 7 {
            return Err("Envelope bytes too short".to_string());
        }
        if &bytes[0..3] != PQ_ENVELOPE_MAGIC {
            return Err("Missing PQ1 magic header".to_string());
        }

        let scheme = PqScheme::from_id(bytes[3])?;
        let is_implicit = bytes[4] != 0;

        if is_implicit {
            let pk_len = u16::from_le_bytes([bytes[5], bytes[6]]) as usize;
            let mut cursor = 7 + pk_len;
            if bytes.len() < cursor + 2 {
                return Err("Truncated signature length in envelope".to_string());
            }
            let sig_len = u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
            cursor += 2;
            if bytes.len() != cursor + sig_len && bytes.len() != cursor + sig_len + 8 {
                return Err("Truncated signature bytes in envelope".to_string());
            }
            let signature_bytes = bytes[cursor..cursor + sig_len].to_vec();
            cursor += sig_len;
            let chain_id = if bytes.len() == cursor + 8 {
                Some(u64::from_be_bytes(bytes[cursor..cursor + 8].try_into().unwrap()))
            } else {
                None
            };
            return Ok(Self {
                scheme,
                is_implicit: true,
                pubkey: None,
                signature_bytes,
                salt: DEFAULT_SALT,
                chain_id,
            });
        }

        // Explicit envelope (is_implicit = false)
        // Check Option 1 (salt before pk): b"PQ1" (3) || scheme (1) || is_implicit (1) || salt (16) || pk_len (2) || pk || sig_len (2) || sig
        if bytes.len() >= 23 {
            let pk_len_opt1 = u16::from_le_bytes([bytes[21], bytes[22]]) as usize;
            if pk_len_opt1 == scheme.pubkey_size() {
                let cursor_sig = 23 + pk_len_opt1;
                if bytes.len() >= cursor_sig + 2 {
                    let sig_len = u16::from_le_bytes([bytes[cursor_sig], bytes[cursor_sig + 1]]) as usize;
                    if cursor_sig + 2 + sig_len == bytes.len() || cursor_sig + 2 + sig_len + 8 == bytes.len() {
                        let mut salt = [0u8; 16];
                        salt.copy_from_slice(&bytes[5..21]);
                        let pubkey = Some(bytes[23..23 + pk_len_opt1].to_vec());
                        let signature_bytes = bytes[cursor_sig + 2..cursor_sig + 2 + sig_len].to_vec();
                        let rem = cursor_sig + 2 + sig_len;
                        let chain_id = if bytes.len() == rem + 8 {
                            Some(u64::from_be_bytes(bytes[rem..rem + 8].try_into().unwrap()))
                        } else {
                            None
                        };
                        return Ok(Self {
                            scheme,
                            is_implicit: false,
                            pubkey,
                            signature_bytes,
                            salt,
                            chain_id,
                        });
                    }
                }
            }
        }

        // Option 2 (salt after pk) or legacy (without salt)
        let pk_len = u16::from_le_bytes([bytes[5], bytes[6]]) as usize;
        let mut cursor = 7;
        if bytes.len() < cursor + pk_len + 2 {
            return Err("Truncated public key in envelope".to_string());
        }
        let pubkey = if pk_len > 0 {
            let pk = bytes[cursor..cursor + pk_len].to_vec();
            cursor += pk_len;
            Some(pk)
        } else {
            None
        };

        // Check if salt is present (Option 2):
        if bytes.len() >= cursor + 16 + 2 {
            let maybe_sig_len = u16::from_le_bytes([bytes[cursor + 16], bytes[cursor + 17]]) as usize;
            if cursor + 16 + 2 + maybe_sig_len == bytes.len() || cursor + 16 + 2 + maybe_sig_len + 8 == bytes.len() {
                let mut salt = [0u8; 16];
                salt.copy_from_slice(&bytes[cursor..cursor + 16]);
                cursor += 16;
                let sig_len = u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
                cursor += 2;
                let signature_bytes = bytes[cursor..cursor + sig_len].to_vec();
                cursor += sig_len;
                let chain_id = if bytes.len() == cursor + 8 {
                    Some(u64::from_be_bytes(bytes[cursor..cursor + 8].try_into().unwrap()))
                } else {
                    None
                };
                return Ok(Self {
                    scheme,
                    is_implicit: false,
                    pubkey,
                    signature_bytes,
                    salt,
                    chain_id,
                });
            }
        }

        // Legacy format without salt:
        if bytes.len() >= cursor + 2 {
            let sig_len = u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
            cursor += 2;
            if bytes.len() == cursor + sig_len || bytes.len() == cursor + sig_len + 8 {
                let signature_bytes = bytes[cursor..cursor + sig_len].to_vec();
                cursor += sig_len;
                let chain_id = if bytes.len() == cursor + 8 {
                    Some(u64::from_be_bytes(bytes[cursor..cursor + 8].try_into().unwrap()))
                } else {
                    None
                };
                return Ok(Self {
                    scheme,
                    is_implicit: false,
                    pubkey,
                    signature_bytes,
                    salt: DEFAULT_SALT,
                    chain_id,
                });
            }
        }

        Err("Truncated envelope bytes".to_string())
    }
}

pub type ShardId = u32;
pub const MASTERCHAIN_SHARD: ShardId = 0;
pub const BASE_WORKCHAIN_SHARD_INITIAL: ShardId = 1;

/// Environment variable listing the shards a single process runs, comma
/// separated (e.g. `STELL_SHARDS=0,1`). Unset/empty keeps the process on the
/// one shard it was started with, which is the pre-sharding behaviour.
pub const SHARD_REGISTRY_ENV: &str = "STELL_SHARDS";

/// The set of shards a single process is responsible for.
///
/// Before sharding, one process ran exactly one chain and every block was a
/// masterchain block. That must stay byte-for-byte identical, so the DEFAULT
/// registry is `{MASTERCHAIN_SHARD}` and `is_sharded()` is false. Every new
/// shard-aware check in the runtime is gated on `is_sharded()`, which means the
/// single-shard path is untouched and all pre-sharding tests keep passing.
///
/// A process that should run several shards over ONE infnode node sets
/// `STELL_SHARDS`, e.g. `STELL_SHARDS=0,1`. The cross-shard KV helpers in
/// `network.rs` are node-local, so the two consensus instances must share one
/// process (and one `Node`) for messages to flow between them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardRegistry {
    shards: std::collections::BTreeSet<ShardId>,
}

impl Default for ShardRegistry {
    fn default() -> Self {
        Self::single()
    }
}

impl ShardRegistry {
    /// The pre-sharding registry: exactly the masterchain.
    pub fn single() -> Self {
        Self::from_ids([MASTERCHAIN_SHARD])
    }

    /// Build a registry from an explicit set of shard ids. An empty set falls
    /// back to the masterchain so a misparsed env var can never produce a
    /// process that runs no chain at all.
    pub fn from_ids<I: IntoIterator<Item = ShardId>>(ids: I) -> Self {
        let mut shards: std::collections::BTreeSet<ShardId> = ids.into_iter().collect();
        if shards.is_empty() {
            shards.insert(MASTERCHAIN_SHARD);
        }
        Self { shards }
    }

    /// Parse the registry from the environment, falling back to `cli_shard`
    /// when `STELL_SHARDS` is unset or empty. With the CLI default of 0 this is
    /// exactly `{MASTERCHAIN_SHARD}`, preserving single-shard behaviour.
    pub fn from_env_or(cli_shard: ShardId) -> Self {
        match std::env::var(SHARD_REGISTRY_ENV) {
            Ok(v) if !v.trim().is_empty() => {
                let ids: Vec<ShardId> = v
                    .split(',')
                    .filter_map(|p| p.trim().parse::<ShardId>().ok())
                    .collect();
                Self::from_ids(ids)
            }
            _ => Self::from_ids([cli_shard]),
        }
    }

    /// True when this process runs MORE THAN ONE shard. This is the single gate
    /// for every new shard-aware check; with the default registry it is false.
    pub fn is_sharded(&self) -> bool {
        self.shards.len() > 1
    }

    /// True when `shard_id` is one of the shards this process runs.
    pub fn contains(&self, shard_id: ShardId) -> bool {
        self.shards.contains(&shard_id)
    }

    /// The shards in ascending order (deterministic iteration).
    pub fn ids(&self) -> impl Iterator<Item = ShardId> + '_ {
        self.shards.iter().copied()
    }

    pub fn len(&self) -> usize {
        self.shards.len()
    }

    pub fn is_empty(&self) -> bool {
        self.shards.is_empty()
    }
}

/// Which shard a transaction is destined for. In single-shard mode this
/// predicate is never consulted; it exists so a sharded producer and validator
/// agree on which transactions belong to which shard. A transaction targets the
/// block shard named by its `target_shard` field.
pub fn tx_targets_shard(tx: &Transaction, shard_id: ShardId) -> bool {
    tx.target_shard == shard_id
}

/// Which shard OWNS (produces) a transaction.
///
/// M2: the source shard is the one that debits the sender, so a shard's block
/// selects every transaction whose `source_shard` is that shard — both
/// same-shard transfers (`source == target == shard`) and outbound cross-shard
/// transfers (`source == shard`, `target != shard`). The destination shard
/// never re-includes the transaction in `Block.transactions`; it receives the
/// value through a committed [`CrossShardMessage`] consumption record instead.
///
/// In single-shard mode this predicate is never consulted; the pre-sharding
/// path still uses [`tx_targets_shard`].
pub fn tx_belongs_to_shard(tx: &Transaction, shard_id: ShardId) -> bool {
    tx.source_shard == shard_id
}

/// True when `tx` is an outbound cross-shard transfer out of `shard_id`.
pub fn tx_is_outbound_cross_shard(tx: &Transaction, shard_id: ShardId) -> bool {
    tx.source_shard == shard_id && tx.target_shard != shard_id
}

/// The shard a node's blocks belong to, given the DHT/blob NAMESPACE shard it
/// was started with (`--shard N`) and its [`ShardRegistry`].
///
/// These are deliberately NOT the same thing. Before sharding, one process ran
/// one chain and every block was a MASTERCHAIN block, while `--shard N` only
/// selected the DHT/blob namespace. The default registry
/// (`is_sharded() == false`) must preserve exactly that: the block shard stays
/// [`MASTERCHAIN_SHARD`] even when `--shard 1` is passed. Conflating the two
/// made a `--shard 1` node stamp `block.shard_id = 1` while its persisted chain
/// and sync validation expected shard 0, so catch-up rejected every chain and
/// finality stalled at an ever-increasing round.
///
/// Only a genuine multi-shard process (`STELL_SHARDS` selecting more than one
/// shard) scopes blocks to the namespace shard it was started with.
pub fn block_shard_for(namespace_shard: ShardId, registry: &ShardRegistry) -> ShardId {
    if registry.is_sharded() {
        namespace_shard
    } else {
        MASTERCHAIN_SHARD
    }
}

/// Tag that separates a legacy signature from a session-key envelope inside
/// `Transaction::signature`:
///
/// * legacy  : `64B ed25519 sig` (master key == `tx.from`)
/// * envelope: `64B ed25519 sig` (SESSION key) ++ `b"SK1"` ++ `bincode(SessionKeyAuthorization)`
///
/// This is how delegation rides inside the pre-existing `signature: Vec<u8>`
/// field: `Transaction`/`Block` gain NO new field, so bincode 1.3 keeps
/// decoding every persisted block byte-for-byte, and an old node rejects an
/// envelope at `Signature::from_slice` (64-byte expected, envelope is longer)
/// — fail-closed, exactly as required by the bincode verdict.
pub const SESSION_SIG_TAG: &[u8; 3] = b"SK1";

/// Tag that separates a legacy signature from a chain-id bound envelope inside
/// `Transaction::signature` (Finding F1):
///
/// `64B ed25519 sig` ++ `b"CH1"` ++ `chain_id (8B, big-endian)`
pub const CHAIN_SIG_TAG: &[u8; 3] = b"CH1";

/// Tag that separates a legacy signature from a Phase-2 EVM (secp256k1)
/// settlement envelope inside `Transaction::signature`:
///
/// `b"EV1"` ++ `canonical EVM raw transaction bytes`
/// (RLP legacy, or `0x02` EIP-1559 envelope).
///
/// `Transaction`/`Block` gain NO new field (bincode 1.3 compat — the §5 M3
/// rule: a new struct field would change every persisted block's bytes and
/// break the pinned golden vectors in `actor_envelope_compat_tests`). The
/// envelope rides the pre-existing `signature: Vec<u8>` field, exactly like
/// the `SK1`/`CH1`/`SC1` envelopes before it, and an old node rejects it at
/// `Signature::from_slice` (64 bytes expected, an EV1 envelope is never 64)
/// — fail-closed, as required.
pub const EVM_SIG_TAG: &[u8; 3] = b"EV1";

/// Chain id every EVM-settled transaction must carry. Strict equality, no
/// negotiation: this is the EIP-155 replay-protection domain AND the
/// consensus chain id in one value.
pub const EVM_CHAIN_ID: u64 = 5757;

// Compile-time drift guards: the consensus envelope, the EVM adapter and the
// session-grant default must agree on one chain id, or EVM settlement and
// grant binding silently diverge.
const _: () = assert!(EVM_CHAIN_ID == crate::evm_adapter::CHAIN_ID);
const _: () = assert!(EVM_CHAIN_ID == crate::zkml::DEFAULT_CHAIN_ID);

/// Maximum raw EVM bytes accepted inside an EV1 envelope. Mirrors the RPC
/// gate `evm_adapter::MAX_EVM_RAW_TX_BYTES` (generous for calldata); the
/// mempool wire estimator accounts the envelope bytes, so packing still
/// respects the block gossip cap.
pub const MAX_EVM_ENVELOPE_BYTES: usize = 128 * 1024;

/// Commitment tag bound into the signed message for chain-id-bound transactions.
pub const CHAIN_ID_COMMITMENT_TAG: &[u8; 8] = b"CHAIN_ID";

/// Why a session-keyed transaction fails the delegation policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionPolicyError {
    /// `now > delegation.valid_until`.
    Expired,
    /// The grant's scope mask does not cover this transaction kind, or the
    /// amount exceeds `max_value_per_tx`.
    OutOfScope,
    /// The grant cannot cover this transaction's declared gas: the remaining
    /// budget (`max_gas_spend - gas_spent`) is too small. In phase 1 this is
    /// the stateless form of revocation (a spent-out grant authorizes
    /// nothing); the stateful registry lands in phase 2.
    BudgetExhausted,
    /// The grant itself is unusable: it does not parse, is not minted for this
    /// sender (`master_address != tx.from`) or the master's grant signature is
    /// invalid / tampered with.
    BadGrant,
}

impl std::fmt::Display for SessionPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            SessionPolicyError::Expired => "session key delegation has expired",
            SessionPolicyError::OutOfScope => {
                "session key delegation does not cover this transaction (scope/value cap)"
            }
            SessionPolicyError::BudgetExhausted => {
                "session key delegation has no remaining gas budget"
            }
            SessionPolicyError::BadGrant => "invalid session key delegation grant",
        };
        write!(f, "{s}")
    }
}

pub const SHARD_SPLIT_LOAD_THRESHOLD: u64 = 500; // txs per block window triggers auto-split
pub const SHARD_MERGE_LOAD_THRESHOLD: u64 = 50;  // low load triggers auto-merge

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardDescriptor {
    pub shard_id: ShardId,
    pub workchain_id: i32,
    pub prefix: u64,
    pub prefix_len: u8,
    pub tx_load: u64,
}

impl ShardDescriptor {
    pub fn new(shard_id: ShardId, workchain_id: i32, prefix: u64, prefix_len: u8) -> Self {
        Self {
            shard_id,
            workchain_id,
            prefix,
            prefix_len,
            tx_load: 0,
        }
    }

    /// Check whether an account address falls within this shard's address prefix
    pub fn contains_address(&self, address: &[u8; 32]) -> bool {
        if self.shard_id == MASTERCHAIN_SHARD {
            return false;
        }
        if self.prefix_len == 0 {
            return true;
        }
        let addr_prefix = u64::from_be_bytes(address[..8].try_into().unwrap());
        let shift = 64 - self.prefix_len;
        let mask = if shift >= 64 { 0 } else { !0u64 << shift };
        (addr_prefix & mask) == (self.prefix & mask)
    }
}

/// Dynamic Infinite Sharding Manager
#[derive(Clone, Debug, Default)]
pub struct DynamicShardManager {
    pub shards: HashMap<ShardId, ShardDescriptor>,
    pub next_shard_id: ShardId,
}

impl DynamicShardManager {
    pub fn new() -> Self {
        let mut shards = HashMap::new();
        shards.insert(
            MASTERCHAIN_SHARD,
            ShardDescriptor::new(MASTERCHAIN_SHARD, -1, 0, 0),
        );
        shards.insert(
            BASE_WORKCHAIN_SHARD_INITIAL,
            ShardDescriptor::new(BASE_WORKCHAIN_SHARD_INITIAL, 0, 0, 0),
        );
        Self {
            shards,
            next_shard_id: BASE_WORKCHAIN_SHARD_INITIAL + 1,
        }
    }

    pub fn route_address(&self, address: &[u8; 32]) -> ShardId {
        // Deterministic routing: pick the MOST SPECIFIC matching shard (longest
        // prefix), tie-broken by the smallest shard id. Iterating a HashMap
        // directly was nondeterministic, so different nodes could route the same
        // address to different shards (cross-node divergence).
        let mut best: Option<&ShardDescriptor> = None;
        for s in self.shards.values() {
            if !s.contains_address(address) {
                continue;
            }
            best = match best {
                None => Some(s),
                Some(b)
                    if s.prefix_len > b.prefix_len
                        || (s.prefix_len == b.prefix_len && s.shard_id < b.shard_id) =>
                {
                    Some(s)
                }
                other => other,
            };
        }
        best.map(|s| s.shard_id).unwrap_or(BASE_WORKCHAIN_SHARD_INITIAL)
    }

    pub fn record_tx_load(&mut self, shard_id: ShardId, tx_count: u64) {
        if let Some(s) = self.shards.get_mut(&shard_id) {
            s.tx_load += tx_count;
        }
    }

    /// Check and trigger automatic shard split if load exceeds threshold
    pub fn check_and_split(&mut self, shard_id: ShardId) -> Option<(ShardDescriptor, ShardDescriptor)> {
        let s = self.shards.get(&shard_id)?;
        if shard_id == MASTERCHAIN_SHARD || s.tx_load < SHARD_SPLIT_LOAD_THRESHOLD || s.prefix_len >= 60 {
            return None;
        }

        let parent = self.shards.remove(&shard_id)?;
        let new_len = parent.prefix_len + 1;
        let shift = 64 - new_len;

        let child0_prefix = if shift + 1 >= 64 {
            0
        } else {
            (parent.prefix >> (shift + 1)) << (shift + 1)
        };
        let child1_prefix = child0_prefix | (1u64 << shift);

        let id0 = self.next_shard_id;
        let id1 = self.next_shard_id + 1;
        self.next_shard_id += 2;

        let child0 = ShardDescriptor::new(id0, parent.workchain_id, child0_prefix, new_len);
        let child1 = ShardDescriptor::new(id1, parent.workchain_id, child1_prefix, new_len);

        self.shards.insert(id0, child0.clone());
        self.shards.insert(id1, child1.clone());

        Some((child0, child1))
    }

    /// Check and trigger automatic shard merge if companion shards load is low
    pub fn check_and_merge(&mut self, id0: ShardId, id1: ShardId) -> Option<ShardDescriptor> {
        let s0 = self.shards.get(&id0)?.clone();
        let s1 = self.shards.get(&id1)?.clone();

        if s0.prefix_len != s1.prefix_len || s0.prefix_len == 0 {
            return None;
        }

        if s0.tx_load + s1.tx_load > SHARD_MERGE_LOAD_THRESHOLD {
            return None;
        }

        let new_len = s0.prefix_len - 1;
        let shift = 64 - new_len;
        let parent_prefix = if shift >= 64 {
            0
        } else {
            (s0.prefix >> shift) << shift
        };

        self.shards.remove(&id0);
        self.shards.remove(&id1);

        let parent_id = self.next_shard_id;
        self.next_shard_id += 1;

        let parent = ShardDescriptor::new(parent_id, s0.workchain_id, parent_prefix, new_len);
        self.shards.insert(parent_id, parent.clone());

        Some(parent)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub from: [u8; 32],
    pub to: [u8; 32],
    pub amount: u64,
    pub gas_limit: u64,
    pub nonce: u64,
    pub source_shard: ShardId,
    pub target_shard: ShardId,
    pub signature: Vec<u8>,
    /// Optional SVM program (micro-gas ops) executed against the sender's account
    /// during block application. Empty = a plain value transfer.
    #[serde(default)]
    pub payload: Vec<crate::svm::OpCode>,
}

impl Transaction {
    pub fn sign(
        from_key: &SigningKey,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
    ) -> Self {
        Self::sign_with_payload(from_key, to, amount, gas_limit, nonce, source_shard, target_shard, Vec::new())
    }

    /// Sign a transaction carrying an SVM payload (contract call / token syscalls /
    /// orderbook ops). The payload is committed into the signature, so a payload
    /// cannot be swapped after signing.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_with_payload(
        from_key: &SigningKey,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        payload: Vec<crate::svm::OpCode>,
    ) -> Self {
        let from_pub = from_key.verifying_key().to_bytes();
        let msg = Self::base_signing_message(
            &from_pub,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            &payload,
        );

        let sig = from_key.sign(&msg);

        Self {
            from: from_pub,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            signature: sig.to_vec(),
            payload,
        }
    }

    /// Sign a transaction bound to a specific chain_id (Finding F1: anti cross-chain replay).
    pub fn sign_with_chain_id(
        from_key: &SigningKey,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        chain_id: u64,
    ) -> Self {
        Self::sign_with_payload_and_chain_id(
            from_key,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            Vec::new(),
            chain_id,
        )
    }

    /// Sign a transaction carrying an SVM payload and bound to a specific chain_id.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_with_payload_and_chain_id(
        from_key: &SigningKey,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        payload: Vec<crate::svm::OpCode>,
        chain_id: u64,
    ) -> Self {
        let from_pub = from_key.verifying_key().to_bytes();
        let mut msg = Self::base_signing_message(
            &from_pub,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            &payload,
        );
        Self::append_chain_id_commitment(&mut msg, chain_id);

        let sig = from_key.sign(&msg);
        let mut signature = sig.to_vec();
        signature.extend_from_slice(CHAIN_SIG_TAG);
        signature.extend_from_slice(&chain_id.to_be_bytes());

        Self {
            from: from_pub,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            signature,
            payload,
        }
    }

    /// Sign a transaction with a DELEGATED session key instead of the master
    /// key. The master's grant rides inside `signature` as an envelope:
    /// `session_sig(64B) || b"SK1" || bincode(grant)`.
    ///
    /// `tx.from` stays the master address (the master's account is the one
    /// debited), and both the grant and the payload are committed into what
    /// the session key signs, so neither can be swapped after signing: grafting
    /// this envelope onto another sender's transaction, or grafting another
    /// grant onto this one, invalidates the signature.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_with_session(
        session_key: &SigningKey,
        delegation: SessionKeyAuthorization,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        payload: Vec<crate::svm::OpCode>,
    ) -> Self {
        // The grant must have been minted FOR this session key: verification
        // selects the verifying key from `delegation.session_pubkey`, so a
        // mismatch could only ever produce a transaction nobody can verify.
        debug_assert_eq!(
            session_key.verifying_key().to_bytes(),
            delegation.session_pubkey,
            "session key must match the delegation it is used with"
        );
        let from_pub = delegation.master_address;
        let mut msg = Self::base_signing_message(
            &from_pub,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            &payload,
        );
        Self::append_delegation_commitment(&mut msg, &delegation);

        let sig = session_key.sign(&msg);
        let mut signature = sig.to_vec();
        signature.extend_from_slice(SESSION_SIG_TAG);
        // Serialization of this struct cannot realistically fail (fixed-size
        // fields plus one Vec). If it somehow did, the envelope would not
        // parse and the transaction fails closed at verification.
        signature.extend_from_slice(&bincode::serialize(&delegation).unwrap_or_default());

        Self {
            from: from_pub,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            signature,
            payload,
        }
    }

    /// The signed message WITHOUT the delegation commitment: every legacy
    /// transaction's exact signing bytes, kept byte-identical so old
    /// signatures, old hashes and the python client's layout still hold.
    fn base_signing_message(
        from: &[u8; 32],
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        payload: &[crate::svm::OpCode],
    ) -> Vec<u8> {
        let mut msg = Vec::with_capacity(115);
        msg.extend_from_slice(from);
        msg.extend_from_slice(&to);
        msg.extend_from_slice(&amount.to_be_bytes());
        msg.extend_from_slice(&gas_limit.to_be_bytes());
        msg.extend_from_slice(&nonce.to_be_bytes());
        msg.extend_from_slice(&source_shard.to_be_bytes());
        msg.extend_from_slice(&target_shard.to_be_bytes());
        Self::append_payload_commitment(&mut msg, payload);
        msg
    }

    /// Deterministic commitment of the payload bound into the signed message.
    fn append_payload_commitment(msg: &mut Vec<u8>, payload: &[crate::svm::OpCode]) {
        msg.extend_from_slice(b"PAYLOAD");
        match bincode::serialize(payload) {
            Ok(bytes) => {
                msg.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                msg.extend_from_slice(&bytes);
            }
            Err(_) => {
                // Unserializable payload -> bind an impossible marker so the
                // signature can never validate (fail closed).
                msg.extend_from_slice(&u32::MAX.to_be_bytes());
            }
        }
    }

    /// Parse the master's grant out of the signature envelope, if this
    /// transaction carries one. `None` for a legacy signature — and for any
    /// blob that does not parse as an exact-fit envelope, which then fails
    /// `Signature::from_slice` (wrong length), so malformed input fails closed.
    pub fn delegation(&self) -> Option<SessionKeyAuthorization> {
        let sig = self.signature.as_slice();
        let tag_len = SESSION_SIG_TAG.len();
        if sig.len() <= 64 + tag_len || &sig[64..64 + tag_len] != &SESSION_SIG_TAG[..] {
            return None;
        }
        let grant: SessionKeyAuthorization = bincode::deserialize(&sig[64 + tag_len..]).ok()?;
        // Exact fit: the envelope is exactly `sig(64) || tag || grant`, with no
        // trailing junk — otherwise one transaction could carry two byte
        // encodings under a single hash.
        let expected = 64 + tag_len + bincode::serialized_size(&grant).ok()? as usize;
        if expected != sig.len() {
            return None;
        }
        Some(grant)
    }

    /// True when this transaction carries a session-key envelope.
    pub fn is_session_keyed(&self) -> bool {
        self.delegation().is_some()
    }

    /// Commitment of the grant, bound into BOTH the signed message and the tx
    /// hash. Empty for legacy transactions (`delegation()` is `None`), which is
    /// what keeps every pre-envelope byte string — tx bytes, tx hashes, block
    /// hashes — unchanged.
    fn delegation_commitment_bytes(delegation: &SessionKeyAuthorization) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"SESSION");
        match bincode::serialize(delegation) {
            Ok(bytes) => {
                out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                out.extend_from_slice(&bytes);
            }
            Err(_) => out.extend_from_slice(&u32::MAX.to_be_bytes()),
        }
        out
    }

    fn append_delegation_commitment(msg: &mut Vec<u8>, delegation: &SessionKeyAuthorization) {
        msg.extend_from_slice(&Self::delegation_commitment_bytes(delegation));
    }

    /// Append chain_id commitment to signing message (Finding F1).
    fn append_chain_id_commitment(msg: &mut Vec<u8>, chain_id: u64) {
        msg.extend_from_slice(CHAIN_ID_COMMITMENT_TAG);
        msg.extend_from_slice(&chain_id.to_be_bytes());
    }

    /// True if transaction carries an Ed25519 chain_id envelope (CH1).
    pub fn is_chain_id_bound(&self) -> bool {
        let sig = self.signature.as_slice();
        let tag_len = CHAIN_SIG_TAG.len();
        sig.len() == 64 + tag_len + 8 && &sig[64..64 + tag_len] == &CHAIN_SIG_TAG[..]
    }

    /// Extract chain_id from CH1 envelope if present.
    pub fn chain_id_from_envelope(&self) -> Option<u64> {
        if !self.is_chain_id_bound() {
            return None;
        }
        let offset = 64 + CHAIN_SIG_TAG.len();
        let bytes: [u8; 8] = self.signature[offset..offset + 8].try_into().ok()?;
        Some(u64::from_be_bytes(bytes))
    }

    /// True when this transaction carries a Phase-2 EVM (secp256k1)
    /// settlement envelope (`b"EV1"` prefix). Never 64 bytes long, so every
    /// pre-EV1 verifier fails it closed at `Signature::from_slice`.
    pub fn is_evm(&self) -> bool {
        self.signature.len() > EVM_SIG_TAG.len()
            && self.signature[..EVM_SIG_TAG.len()] == EVM_SIG_TAG[..]
    }

    /// Raw canonical EVM bytes carried by the envelope (`None` for non-EVM
    /// transactions).
    pub fn evm_raw(&self) -> Option<&[u8]> {
        if !self.is_evm() {
            return None;
        }
        Some(&self.signature[EVM_SIG_TAG.len()..])
    }

    /// Decode the EVM envelope into its separate-enum view
    /// ([`crate::evm_adapter::DecodedTransaction`], legacy or EIP-1559).
    /// Fail-closed: oversized envelopes and any RLP parse error yield `None`.
    pub fn evm_decoded(&self) -> Option<crate::evm_adapter::DecodedTransaction> {
        let raw = self.evm_raw()?;
        if raw.is_empty() || raw.len() > MAX_EVM_ENVELOPE_BYTES {
            return None;
        }
        crate::evm_adapter::parse_raw_transaction(raw).ok()
    }

    /// Assemble a Phase-2 EVM settlement transaction. `raw_evm_tx` must be
    /// the canonical EVM wire bytes; every consensus check re-derives from
    /// them, so any mismatch with the mapped fields fails closed in
    /// [`Self::verify_evm_signature`]. The SVM payload stays empty: Phase-2
    /// settles value movement, calldata is not executed.
    pub fn new_evm(
        from: [u8; 32],
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        raw_evm_tx: Vec<u8>,
    ) -> Self {
        let mut signature = Vec::with_capacity(EVM_SIG_TAG.len() + raw_evm_tx.len());
        signature.extend_from_slice(EVM_SIG_TAG);
        signature.extend_from_slice(&raw_evm_tx);
        Self {
            from,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            signature,
            payload: Vec::new(),
        }
    }

    /// Phase-2 EVM (secp256k1) envelope verification.
    ///
    /// Re-derives EVERYTHING from the canonical raw bytes in the envelope, so
    /// block data alone decides — no RPC trust, no wall clock, no state:
    ///
    /// * the raw parses as legacy-EIP-155 or EIP-1559 type-2 AND re-encodes
    ///   byte-exact (non-canonical RLP / trailing junk fails closed);
    /// * [`crate::evm_adapter::DecodedTransaction::verify_signature`] passes —
    ///   strict `chain_id == 5757` (EIP-155 replay protection required, never
    ///   `v = 27/28`), EIP-2 low-s, secp256k1 ecrecover;
    /// * contract creation (`to == None`) is rejected — Phase-2 settles value
    ///   transfers and there is no Stell recipient to invent for a deployment;
    /// * `tx.from` equals `evm_to_stell_address(recovered)`: the mapping the
    ///   mempool nonce/balance checks and the engine apply path then use;
    /// * `tx.nonce` / `gas_limit` / `amount` / `to` equal the mapped EVM
    ///   fields (`amount = wei_to_nano(value)`, sub-nano wei truncated
    ///   deterministically; `gas_limit` is carried verbatim as the nano fee
    ///   so consensus verification stays a pure function of the tx bytes).
    pub fn verify_evm_signature(&self) -> bool {
        let Some(raw) = self.evm_raw() else {
            return false;
        };
        if raw.is_empty() || raw.len() > MAX_EVM_ENVELOPE_BYTES {
            return false;
        }
        let Ok(decoded) = crate::evm_adapter::parse_raw_transaction(raw) else {
            return false;
        };
        // Exact-fit: the envelope commits to canonical bytes only.
        if decoded.encode() != raw {
            return false;
        }
        // Strict chain_id == 5757 + low-s + ecrecover (enforced inside for
        // both the legacy and the EIP-1559 variant).
        let Ok(evm_from) = decoded.verify_signature() else {
            return false;
        };
        // No recipient to map for a deployment — fail closed, don't invent one.
        let Some(evm_to) = decoded.to() else {
            return false;
        };
        if crate::evm_adapter::evm_to_stell_address(&evm_from) != self.from {
            return false;
        }
        if crate::evm_adapter::evm_to_stell_address(&evm_to) != self.to {
            return false;
        }
        if decoded.nonce() != self.nonce {
            return false;
        }
        if decoded.gas_limit() != self.gas_limit {
            return false;
        }
        if crate::evm_adapter::wei_to_nano(decoded.value()) != self.amount {
            return false;
        }
        // EVM-settled transactions carry no SVM payload (no mixed execution
        // model under one signature).
        if !self.payload.is_empty() {
            return false;
        }
        true
    }

    /// Returns the chain_id bound to this transaction, if any.
    ///
    /// - For session key transactions: returns `delegation.chain_id`.
    /// - For chain-bound Ed25519 transactions: returns envelope `chain_id`.
    /// - For PQ transactions with chain binding: returns `envelope.chain_id`.
    /// - For EVM (secp256k1) settlement transactions: returns `EVM_CHAIN_ID`.
    /// - For legacy transactions: returns `None`.
    pub fn chain_id(&self) -> Option<u64> {
        if let Some(d) = self.delegation() {
            Some(d.chain_id)
        } else if let Some(cid) = self.chain_id_from_envelope() {
            Some(cid)
        } else if let Some(env) = self.pq_envelope() {
            env.chain_id
        } else if self.is_evm() {
            Some(EVM_CHAIN_ID)
        } else {
            None
        }
    }

    pub fn compute_tx_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.from);
        hasher.update(&self.to);
        hasher.update(self.amount.to_be_bytes());
        hasher.update(self.gas_limit.to_be_bytes());
        hasher.update(self.nonce.to_be_bytes());
        hasher.update(self.source_shard.to_be_bytes());
        hasher.update(self.target_shard.to_be_bytes());
        hasher.update(b"PAYLOAD");
        match bincode::serialize(&self.payload) {
            Ok(bytes) => {
                hasher.update((bytes.len() as u32).to_be_bytes());
                hasher.update(&bytes);
            }
            Err(_) => hasher.update(u32::MAX.to_be_bytes()),
        }
        // Conditional commitment: nothing is appended for a legacy signature,
        // so legacy tx hashes (and every block hash built from them) are
        // byte-identical to before session keys existed.
        if let Some(d) = self.delegation() {
            hasher.update(Self::delegation_commitment_bytes(&d));
        }
        if self.is_chain_id_bound() {
            hasher.update(CHAIN_ID_COMMITMENT_TAG);
            if let Some(cid) = self.chain_id_from_envelope() {
                hasher.update(cid.to_be_bytes());
            }
        }
        // EVM settlement commits the full envelope (tag + canonical raw), so
        // an EVM transaction can never share a hash with a legacy transaction
        // over identical mapped fields (legacy hashes ignore `signature`).
        if self.is_evm() {
            hasher.update(b"EVM_TX");
            hasher.update(&self.signature);
        }
        if self.is_pq() {
            hasher.update(b"PQ_ENV");
            hasher.update(&self.signature);
        }
        hasher.finalize().into()
    }

    /// True if the transaction signature begins with the PQ1 framing marker.
    pub fn is_pq(&self) -> bool {
        self.signature.starts_with(PQ_ENVELOPE_MAGIC)
    }

    /// Decode the post-quantum signature envelope if present, ensuring exact fit (no trailing bytes).
    pub fn pq_envelope(&self) -> Option<PqSignatureEnvelope> {
        if !self.is_pq() {
            return None;
        }
        let env = PqSignatureEnvelope::decode(&self.signature).ok()?;
        if env.encode().len() != self.signature.len() && env.legacy_encode_len() != self.signature.len() {
            return None;
        }
        Some(env)
    }

    /// True if this transaction carries a raw public key in a PQ envelope (activation tx).
    pub fn is_pq_activation(&self) -> bool {
        self.pq_envelope()
            .map(|e| !e.is_implicit && e.pubkey.is_some())
            .unwrap_or(false)
    }

    /// True if this transaction is an implicit PQ transaction (public key omitted from wire).
    pub fn is_pq_implicit(&self) -> bool {
        self.pq_envelope()
            .map(|e| e.is_implicit || e.pubkey.is_none())
            .unwrap_or(false)
    }

    /// Returns a reference to the global in-memory implicit key registry.
    pub fn global_implicit_registry() -> &'static StatefulImplicitKeyRegistry {
        global_implicit_key_registry()
    }

    /// Create a post-quantum transaction with an explicit public key attached (activation tx).
    pub fn new_pq_explicit(
        scheme: PqScheme,
        pubkey: Vec<u8>,
        signature_bytes: Vec<u8>,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        payload: Vec<crate::svm::OpCode>,
        salt: &[u8; 16],
    ) -> Self {
        let from = derive_pq_address(scheme, &pubkey, salt);
        let envelope = PqSignatureEnvelope::new_explicit_with_salt(scheme, pubkey, signature_bytes, *salt);
        Self {
            from,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            signature: envelope.encode(),
            payload,
        }
    }

    /// Create a post-quantum transaction with an implicit public key (pubkey omitted from wire).
    pub fn new_pq_implicit(
        from: [u8; 32],
        scheme: PqScheme,
        signature_bytes: Vec<u8>,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        payload: Vec<crate::svm::OpCode>,
    ) -> Self {
        let envelope = PqSignatureEnvelope::new_implicit(scheme, signature_bytes);
        Self {
            from,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            signature: envelope.encode(),
            payload,
        }
    }

    /// Create a post-quantum transaction with an explicit public key and chain_id attached.
    #[allow(clippy::too_many_arguments)]
    pub fn new_pq_explicit_with_chain(
        scheme: PqScheme,
        pubkey: Vec<u8>,
        signature_bytes: Vec<u8>,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        payload: Vec<crate::svm::OpCode>,
        salt: &[u8; 16],
        chain_id: u64,
    ) -> Self {
        let from = derive_pq_address(scheme, &pubkey, salt);
        let envelope = PqSignatureEnvelope::new_explicit_with_chain(
            scheme,
            pubkey,
            signature_bytes,
            *salt,
            chain_id,
        );
        Self {
            from,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            signature: envelope.encode(),
            payload,
        }
    }

    /// Create a post-quantum transaction with an implicit public key and chain_id attached.
    #[allow(clippy::too_many_arguments)]
    pub fn new_pq_implicit_with_chain(
        from: [u8; 32],
        scheme: PqScheme,
        signature_bytes: Vec<u8>,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        payload: Vec<crate::svm::OpCode>,
        chain_id: u64,
    ) -> Self {
        let envelope = PqSignatureEnvelope::new_implicit_with_chain(scheme, signature_bytes, chain_id);
        Self {
            from,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            signature: envelope.encode(),
            payload,
        }
    }

    /// Create a deterministic test Falcon-512 signature for a given message and pubkey.
    #[cfg(any(test, debug_assertions))]
    pub fn create_falcon512_test_signature(_pubkey: &[u8], message: &[u8], seed: u8) -> Vec<u8> {
        crate::post_quantum::FalconKeypair::generate_from_seed(seed).sign(message)
    }

    /// Generate a sample Falcon-512 public key with canonical header byte.
    #[cfg(any(test, debug_assertions))]
    pub fn sample_falcon512_pubkey(seed: u8) -> Vec<u8> {
        crate::post_quantum::FalconKeypair::generate_from_seed(seed).public_key.clone()
    }

    /// Envelope-aware signature verification.
    ///
    /// * legacy  : `tx.from` is the verifying key over `signing_message()`.
    /// * envelope: the delegation must be minted FOR this sender
    ///   (`master_address == tx.from` — the graft-attack guard), the master's
    ///   grant must verify, and the SESSION key must sign `signing_message()`
    ///   (which commits to the grant).
    /// * post-quantum (PQ1 envelope):
    ///   - If explicit pubkey in envelope: verify signature using provided pubkey,
    ///     and verify `derive_pq_address(scheme, pubkey, salt) == self.from`.
    ///     The key is registered into the implicit key registry.
    ///   - If implicit (pubkey omitted from wire): verify signature against the
    ///     address's implicit key registry (`StatefulImplicitKeyRegistry`).
    ///
    /// Malformed input (including a bare 64-byte signature followed by junk)
    /// fails closed: a pre-envelope node rejects the envelope at
    /// `Signature::from_slice`, and so does the legacy branch here.
    pub fn verify_signature(&self) -> bool {
        self.verify_signature_with_registry(Self::global_implicit_registry())
    }

    /// Verify signature against a caller-supplied implicit key registry with default salt.
    pub fn verify_signature_with_registry(&self, registry: &StatefulImplicitKeyRegistry) -> bool {
        self.verify_signature_with_registry_and_salt(registry, &DEFAULT_SALT)
    }

    /// Verify signature against a caller-supplied implicit key registry and salt.
    pub fn verify_signature_with_registry_and_salt(
        &self,
        registry: &StatefulImplicitKeyRegistry,
        _salt: &[u8; 16],
    ) -> bool {
        // Phase-2 EVM settlement: the envelope carries its own secp256k1
        // authentication (re-derived from the canonical raw on every check),
        // independent of ed25519 keys, PQ key registries and delegations.
        if self.is_evm() {
            return self.verify_evm_signature();
        }
        if self.is_pq() {
            let Some(env) = self.pq_envelope() else {
                return false;
            };
            if env.signature_bytes.len() != env.scheme.signature_size() {
                return false;
            }
            if !env.is_implicit {
                let Some(ref pk) = env.pubkey else {
                    return false;
                };
                if pk.len() != env.scheme.pubkey_size() {
                    return false;
                }
                let derived = derive_pq_address(env.scheme, pk, &env.salt);
                if derived != self.from {
                    return false;
                }
                let valid = if env.scheme == PqScheme::Falcon512 {
                    crate::consensus::verify_falcon_signature_or_test(
                        pk,
                        &self.signing_message(),
                        &env.signature_bytes,
                    )
                } else {
                    verify_pq_signature(
                        env.scheme,
                        pk,
                        &self.signing_message(),
                        &env.signature_bytes,
                    )
                };
                if !valid {
                    return false;
                }
                let _ = registry.register(self.from, env.scheme, pk, &env.salt);
                true
            } else {
                if env.pubkey.is_some() {
                    return false;
                }
                let Some((scheme, pk)) = registry.lookup(&self.from) else {
                    return false;
                };
                if scheme != env.scheme {
                    return false;
                }
                if scheme == PqScheme::Falcon512 {
                    crate::consensus::verify_falcon_signature_or_test(
                        &pk,
                        &self.signing_message(),
                        &env.signature_bytes,
                    )
                } else {
                    verify_pq_signature(
                        scheme,
                        &pk,
                        &self.signing_message(),
                        &env.signature_bytes,
                    )
                }
            }
        } else {
            match self.delegation() {
                None => {
                    let sig_slice = if self.is_chain_id_bound() && self.signature.len() >= 64 {
                        &self.signature[..64]
                    } else {
                        &self.signature
                    };
                    if let (Ok(vk), Ok(sig)) = (VerifyingKey::from_bytes(&self.from), Signature::from_slice(sig_slice)) {
                        if vk.verify(&self.signing_message(), &sig).is_ok() {
                            return true;
                        }
                    }
                    crate::crypto_privacy::verify_stealth_signature(
                        &self.from,
                        &self.signing_message(),
                        sig_slice,
                    )
                }
                Some(d) => {
                    if d.master_address != self.from {
                        return false;
                    }
                    if !d.verify_signature() {
                        return false;
                    }
                    let Ok(vk) = VerifyingKey::from_bytes(&d.session_pubkey) else {
                        return false;
                    };
                    let Ok(sig) = Signature::from_slice(&self.signature[..64]) else {
                        return false;
                    };
                    vk.verify(&self.signing_message(), &sig).is_ok()
                }
            }
        }
    }

    /// The exact bytes that the sender signs (used for both single and batch
    /// verify). For an envelope transaction this INCLUDES the grant or chain_id
    /// commitment, so the grant / chain_id cannot be swapped after signing.
    pub fn signing_message(&self) -> Vec<u8> {
        let mut msg = Self::base_signing_message(
            &self.from,
            self.to,
            self.amount,
            self.gas_limit,
            self.nonce,
            self.source_shard,
            self.target_shard,
            &self.payload,
        );
        // EVM-settled transactions are never verified against this preimage
        // (their envelope IS the secp256k1-signed raw); return the base
        // message deterministically with no grant/chain commitment appended.
        if self.is_evm() {
            return msg;
        }
        if let Some(d) = self.delegation() {
            Self::append_delegation_commitment(&mut msg, &d);
        } else if let Some(cid) = self.chain_id() {
            Self::append_chain_id_commitment(&mut msg, cid);
        }
        msg
    }

    /// Construct signing message for a specific chain_id (before attaching an envelope).
    pub fn signing_message_for_chain(&self, chain_id: u64) -> Vec<u8> {
        let mut msg = Self::base_signing_message(
            &self.from,
            self.to,
            self.amount,
            self.gas_limit,
            self.nonce,
            self.source_shard,
            self.target_shard,
            &self.payload,
        );
        if let Some(d) = self.delegation() {
            Self::append_delegation_commitment(&mut msg, &d);
        } else {
            Self::append_chain_id_commitment(&mut msg, chain_id);
        }
        msg
    }

    /// Verify signature and enforce chain_id binding (Finding F1: anti cross-chain replay).
    /// If `require_chain_id` is true, legacy transactions without chain_id are rejected.
    pub fn verify_signature_for_chain(
        &self,
        expected_chain_id: u64,
        require_chain_id: bool,
    ) -> bool {
        if require_chain_id && self.chain_id().is_none() {
            return false;
        }
        if let Some(cid) = self.chain_id() {
            if cid != expected_chain_id {
                return false;
            }
        }
        self.verify_signature()
    }

    /// The session scope THIS transaction's payload requires of a grant.
    ///
    /// One definition, used by every path that asks the question, so propose,
    /// mempool admission, block admission and the execution-time gate can
    /// never disagree about which capability a transaction needs:
    ///
    ///  * empty payload -> [`crate::zkml::SCOPE_TRANSFER`];
    ///  * a payload carrying an actor-mailbox send ->
    ///    `SCOPE_SVM_PAYLOAD | SCOPE_ACTOR_SEND` - BOTH bits, because the
    ///    actor send is an extra capability layered on top of "may run a
    ///    payload", never a substitute for it (see `SCOPE_ACTOR_SEND`);
    ///  * any other payload -> [`crate::zkml::SCOPE_SVM_PAYLOAD`].
    ///
    /// Deterministic from the payload bytes alone (no clock, no state), which
    /// is what lets it be mirrored at propose time against the block clock.
    pub fn required_scope(&self) -> u64 {
        if self.payload.is_empty() {
            crate::zkml::SCOPE_TRANSFER
        } else if self
            .payload
            .iter()
            .any(|op| matches!(op, crate::svm::OpCode::SysCallActorSend { .. }))
        {
            crate::zkml::SCOPE_SVM_PAYLOAD | crate::zkml::SCOPE_ACTOR_SEND
        } else {
            crate::zkml::SCOPE_SVM_PAYLOAD
        }
    }

    /// Delegation policy check for this transaction at a given time.
    ///
    /// `now` must be a DETERMINISTIC clock — the block timestamp at propose
    /// selection and at execution, the admission context's time at mempool
    /// entry. Never the local wall clock inside consensus execution.
    ///
    /// Legacy transactions pass unconditionally. Session-keyed transactions
    /// need a grant minted for this sender, not expired, in scope for this
    /// transaction kind, within the per-transaction value cap, and with enough
    /// remaining gas budget for the declared `gas_limit`.
    ///
    /// The signature itself is NOT re-checked here (that is
    /// `verify_signature`); this is the grant's POLICY.
    pub fn check_session_policy(&self, now: u64) -> Result<(), SessionPolicyError> {
        let Some(d) = self.delegation() else {
            // Legacy signature. Anything that claims envelope shape but did
            // not parse is rejected by `verify_signature` instead.
            return Ok(());
        };
        if d.master_address != self.from {
            return Err(SessionPolicyError::BadGrant);
        }
        if !d.verify_signature() {
            return Err(SessionPolicyError::BadGrant);
        }
        if now > d.valid_until {
            return Err(SessionPolicyError::Expired);
        }
        let required_scope = self.required_scope();
        if !d.grants_scope(required_scope) {
            return Err(SessionPolicyError::OutOfScope);
        }
        if self.amount > d.max_value_per_tx {
            return Err(SessionPolicyError::OutOfScope);
        }
        if self.gas_limit > d.remaining_gas() {
            return Err(SessionPolicyError::BudgetExhausted);
        }
        Ok(())
    }

    /// Batched verification of many transactions at once (Ed25519 batch verify).
    /// This is significantly faster than verifying signatures one-by-one and is
    /// used when validating a whole block. Returns true iff ALL are valid.
    ///
    /// Envelope transactions contribute their SESSION key (not `tx.from`) to
    /// the batch, and their grant is checked (sender binding + master
    /// signature) before batching, so mixed plain + session batches work.
    pub fn verify_signatures_batch(txs: &[Transaction]) -> bool {
        use ed25519_dalek::verify_batch;
        if txs.is_empty() {
            return true;
        }
        // If any tx has a malformed key/signature, fall back to rejecting the batch
        // (batch verify would error anyway).
        let mut msgs: Vec<Vec<u8>> = Vec::with_capacity(txs.len());
        let mut sigs: Vec<Signature> = Vec::with_capacity(txs.len());
        let mut keys: Vec<VerifyingKey> = Vec::with_capacity(txs.len());
        for tx in txs {
            // Phase-2 EVM settlement authenticates via secp256k1 over its own
            // envelope, not via the ed25519 batch below.
            if tx.is_evm() {
                if !tx.verify_evm_signature() {
                    return false;
                }
                continue;
            }
            if tx.is_pq() {
                if !tx.verify_signature() {
                    return false;
                }
                continue;
            }
            if crate::post_quantum::is_pure_pq_enforced() {
                return false;
            }
            let delegation = tx.delegation();
            if let Some(d) = &delegation {
                // The grant must belong to the sender and be authentically
                // minted by that sender — the same rules as the single verify.
                if d.master_address != tx.from || !d.verify_signature() {
                    return false;
                }
            }
            let key_bytes: [u8; 32] = delegation.as_ref().map_or(tx.from, |d| d.session_pubkey);
            let Ok(vk) = VerifyingKey::from_bytes(&key_bytes) else {
                return false;
            };
            let sig_bytes: &[u8] = if delegation.is_some() || tx.is_chain_id_bound() {
                // Envelope: only the leading 64 bytes are the session / Ed25519 signature.
                match tx.signature.get(..64) {
                    Some(s) => s,
                    None => return false,
                }
            } else {
                &tx.signature
            };
            let Ok(sig) = Signature::from_slice(sig_bytes) else {
                return false;
            };
            msgs.push(tx.signing_message());
            sigs.push(sig);
            keys.push(vk);
        }
        if msgs.is_empty() {
            return true;
        }
        let msg_refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
        verify_batch(&msg_refs, &sigs, &keys).is_ok()
    }

    /// Parallel batched verification across CPU cores (rayon).
    /// Splits the block into chunks and batch-verifies each chunk in parallel.
    /// Falls back to the sequential batch for tiny inputs. Returns true iff ALL valid.
    pub fn verify_signatures_batch_parallel(txs: &[Transaction]) -> bool {
        use rayon::prelude::*;
        const CHUNK: usize = 256;
        if txs.len() <= CHUNK {
            return Self::verify_signatures_batch(txs);
        }
        txs.par_chunks(CHUNK)
            .all(|chunk| Self::verify_signatures_batch(chunk))
    }

    /// Per-transaction validity for a batch of transactions (Ed25519 batch verify
    /// with deterministic scalar fallback).
    ///
    /// Fallback semantics (TRANSACTIONS — keep the good ones): a batch MUST fail
    /// closed, but one bad neighbor must NOT sink honest transactions (mempool
    /// admission, proposer filtering and block execution all keep per-tx
    /// outcomes). So: the fast path batch-verifies everything at once; if the
    /// batch rejects, each transaction is re-checked with the scalar
    /// `verify_signature` in INPUT order and only the bad ones are marked
    /// `false`. `verify_signatures_batch(txs)` is exactly
    /// `partitioned(txs).iter().all(|b| *b)` — same verdict, with the offenders
    /// identified.
    ///
    /// Determinism: per-item validity never depends on batch ORDER (each item
    /// verifies against its own message/key); the fallback iterates input order,
    /// so the returned vector is stable for a given input regardless of which
    /// path was taken.
    ///
    /// No behavior change: element `i` of the result equals
    /// `txs[i].verify_signature()` in all cases (the batch path can only be
    /// stricter than the scalar one, never looser, and any batch rejection
    /// falls back to the scalar verdict per item).
    pub fn verify_signatures_partitioned(txs: &[Transaction]) -> Vec<bool> {
        use ed25519_dalek::verify_batch;
        if txs.is_empty() {
            return Vec::new();
        }
        // Stage each item exactly as the scalar `verify_signature` would check
        // it. Items that cannot even be parsed (bad key bytes, bad sig length,
        // broken envelope, grant mismatch) are marked bad WITHOUT failing the
        // whole batch — the good ones still get their batch verdict.
        struct Staged {
            idx: usize,
            msg: Vec<u8>,
            sig: Signature,
            key: VerifyingKey,
        }
        let mut out = vec![false; txs.len()];
        let mut staged: Vec<Staged> = Vec::with_capacity(txs.len());
        for (i, tx) in txs.iter().enumerate() {
            // Phase-2 EVM settlement: scalar secp256k1 verdict per item (the
            // batch below only speaks ed25519).
            if tx.is_evm() {
                out[i] = tx.verify_evm_signature();
                continue;
            }
            if tx.is_pq() {
                out[i] = tx.verify_signature();
                continue;
            }
            if crate::post_quantum::is_pure_pq_enforced() {
                out[i] = false;
                continue;
            }
            let delegation = tx.delegation();
            if let Some(d) = &delegation {
                if d.master_address != tx.from || !d.verify_signature() {
                    out[i] = false;
                    continue;
                }
            }
            let key_bytes: [u8; 32] =
                delegation.as_ref().map_or(tx.from, |d| d.session_pubkey);
            let Ok(vk) = VerifyingKey::from_bytes(&key_bytes) else {
                out[i] = false;
                continue;
            };
            let sig_bytes: &[u8] = if delegation.is_some() || tx.is_chain_id_bound() {
                match tx.signature.get(..64) {
                    Some(s) => s,
                    None => {
                        out[i] = false;
                        continue;
                    }
                }
            } else {
                &tx.signature
            };
            let Ok(sig) = Signature::from_slice(sig_bytes) else {
                out[i] = false;
                continue;
            };
            staged.push(Staged { idx: i, msg: tx.signing_message(), sig, key: vk });
        }
        if staged.is_empty() {
            return out;
        }
        // Fast path: one batch verification over the well-formed items.
        {
            let msg_refs: Vec<&[u8]> = staged.iter().map(|s| s.msg.as_slice()).collect();
            let sigs: Vec<Signature> = staged.iter().map(|s| s.sig).collect();
            let keys: Vec<VerifyingKey> = staged.iter().map(|s| s.key).collect();
            if verify_batch(&msg_refs, &sigs, &keys).is_ok() {
                for s in &staged {
                    out[s.idx] = true;
                }
                return out;
            }
        }
        // Slow path: batch rejected — at least one staged signature is bad.
        // Fall back to the scalar verdict per item, in input order, so honest
        // transactions survive a bad neighbor (fail closed per item).
        for s in &staged {
            out[s.idx] = txs[s.idx].verify_signature();
        }
        out
    }

    /// The valid subset of `txs`, in input (stable) order.
    ///
    /// Convenience over [`Self::verify_signatures_partitioned`] for proposer
    /// filtering / gossip batching: keeps every transaction whose scalar
    /// `verify_signature` passes, drops only the bad ones.
    pub fn filter_valid_transactions(txs: &[Transaction]) -> Vec<Transaction> {
        let keep = Self::verify_signatures_partitioned(txs);
        txs.iter()
            .zip(keep.iter())
            .filter(|(_, k)| **k)
            .map(|(tx, _)| tx.clone())
            .collect()
    }
}

/// Cross-shard atomic transfer message with tight-coupling cryptographic proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrossShardMessage {
    pub msg_id: [u8; 32],
    pub source_shard: ShardId,
    pub target_shard: ShardId,
    pub tx: Transaction,
    pub merkle_inclusion_proof: Option<MerkleProof>,
    pub source_state_root: CellHash,
    pub finalized_in_block: [u8; 32],
    /// Sender's balance proven at `source_state_root` (binds the transfer to the
    /// account leaf and lets the target check the sender actually had the funds).
    #[serde(default)]
    pub source_balance: u64,
    pub bounce: bool,
    pub bounced: bool,
    /// Marks a message as already consensus-attested (locally generated only).
    /// SECURITY: MUST NEVER be set from untrusted network input. If true,
    /// `verify_inclusion` is bypassed. This flag exists for in-process routing
    /// (simulator / same-validator pipeline), not for wire messages.
    pub trusted: bool,
    #[serde(default)]
    pub sender_pubkey_hash: Option<[u8; 32]>,
    #[serde(default)]
    pub sender_scheme: Option<u8>,
}

impl CrossShardMessage {
    /// Construct a wire (untrusted) cross-shard message. Requires a Merkle proof
    /// for value-bearing transfers — a missing proof will be rejected.
    pub fn new(
        source_shard: ShardId,
        target_shard: ShardId,
        tx: Transaction,
        source_state_root: CellHash,
        finalized_in_block: [u8; 32],
        proof: Option<MerkleProof>,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(source_shard.to_be_bytes());
        hasher.update(target_shard.to_be_bytes());
        hasher.update(&tx.compute_tx_hash());
        hasher.update(&finalized_in_block);
        let msg_id = hasher.finalize().into();

        let mut sender_pubkey_hash = None;
        let mut sender_scheme = None;

        if let Some(env) = tx.pq_envelope() {
            if let Some(ref pk) = env.pubkey {
                sender_scheme = Some(env.scheme.id());
                sender_pubkey_hash = Some(*blake3::hash(pk).as_bytes());
            } else if let Some((_, pk)) = global_implicit_key_registry().lookup(&tx.from) {
                sender_scheme = Some(env.scheme.id());
                sender_pubkey_hash = Some(*blake3::hash(&pk).as_bytes());
            }
        } else if let Some((scheme, pk)) = global_implicit_key_registry().lookup(&tx.from) {
            sender_scheme = Some(scheme.id());
            sender_pubkey_hash = Some(*blake3::hash(&pk).as_bytes());
        }

        Self {
            msg_id,
            source_shard,
            target_shard,
            tx,
            merkle_inclusion_proof: proof,
            source_state_root,
            finalized_in_block,
            source_balance: 0,
            bounce: true,
            bounced: false,
            trusted: false,
            sender_pubkey_hash,
            sender_scheme,
        }
    }

    /// Attach the source-account balance that the inclusion proof attests to.
    pub fn with_source_balance(mut self, balance: u64) -> Self {
        self.source_balance = balance;
        self
    }

    /// Attach the sender's post-quantum scheme and public key hash (SEC-PQ-03).
    pub fn with_sender_pubkey_hash(mut self, scheme: u8, pubkey_hash: [u8; 32]) -> Self {
        self.sender_scheme = Some(scheme);
        self.sender_pubkey_hash = Some(pubkey_hash);
        self
    }

    /// Construct a locally-trusted message (already attested by this node's own
    /// consensus pipeline). NEVER deserialize a network message into this state.
    pub fn new_trusted(
        source_shard: ShardId,
        target_shard: ShardId,
        tx: Transaction,
        source_state_root: CellHash,
        finalized_in_block: [u8; 32],
    ) -> Self {
        let mut m = Self::new(source_shard, target_shard, tx, source_state_root, finalized_in_block, None);
        m.trusted = true;
        m
    }

    /// Verify cryptographic tight coupling Merkle proof against source state root.
    /// SECURITY (Nomad-style forgery prevention): a missing proof is REJECTED
    /// unless the message is explicitly locally-trusted.
    pub fn verify_inclusion(&self) -> bool {
        if self.trusted {
            return true;
        }
        self.verify_inclusion_untrusted()
    }

    /// The same inclusion check but the local `trusted` shortcut is IGNORED.
    ///
    /// M2: this is the ONLY form a target shard may use when applying a message
    /// that travelled inside a block. `trusted` is set by the local producer of
    /// a message, but the flag is serialized with the block and a Byzantine
    /// proposer could set it on a message with no proof at all; honoring it here
    /// would mint value out of nothing on every node that applied the block.
    /// Requiring the Merkle proof makes the mint prove it corresponds to a
    /// source-shard account leaf.
    pub fn verify_inclusion_strict(&self) -> bool {
        self.verify_inclusion_untrusted()
    }

    /// Anchored inclusion (C1 fix): the Merkle proof PLUS a check that
    /// `source_state_root` is the state root of a source block THIS process
    /// finalized (or adopted with a verified QC) — looked up by the
    /// `finalized_in_block` hash the message commits to. A self-attested
    /// root (attacker trie + valid-for-that-root proof) fails here because
    /// its hash names no committed header. A lagging node fails here too
    /// (miss, not proof-failure): callers must treat that as NOT-READY
    /// (skip embedding / refuse the carrying block and retry after catching
    /// up), never as verified. `None` registry (single-shard contexts,
    /// unit tests) also fails closed.
    pub fn verify_anchored(
        &self,
        registry: Option<&FinalizedHeaderRegistry>,
    ) -> bool {
        let Some(reg) = registry else {
            return false;
        };
        if !reg.anchor_holds(self.source_shard, &self.finalized_in_block, &self.source_state_root) {
            return false;
        }
        self.verify_inclusion_untrusted()
    }

    fn verify_inclusion_untrusted(&self) -> bool {
        let Some(proof) = &self.merkle_inclusion_proof else {
            // No proof from an untrusted source -> reject.
            return false;
        };
        // The proven balance must actually cover the transfer, so an attacker
        // cannot inflate `amount` and keep an old proof for a smaller balance.
        if self.source_balance < self.tx.amount {
            return false;
        }
        // Prove the SENDER ACCOUNT LEAF (balance || nonce) at the source state
        // root — the same 16-byte encoding the state trie uses. This binds the
        // message to real state (not an ad-hoc amount||nonce value).
        let mut account_value = Vec::with_capacity(16);
        account_value.extend_from_slice(&self.source_balance.to_be_bytes());
        account_value.extend_from_slice(&self.tx.nonce.to_be_bytes());

        // Support pinned PQ accounts with explicit proof metadata (SEC-PQ-03)
        // If sender_pubkey_hash and sender_scheme are present, construct the exact 49-byte leaf:
        // account_value (16B) || scheme (1B) || pubkey_hash (32B)
        // and verify the Merkle proof against source_state_root!
        // This ensures Shard 2 can verify the proof completely independently without needing local RAM keys!
        if let (Some(pk_hash), Some(scheme)) = (self.sender_pubkey_hash, self.sender_scheme) {
            let mut pq_leaf = Vec::with_capacity(49);
            pq_leaf.extend_from_slice(&account_value);
            pq_leaf.push(scheme);
            pq_leaf.extend_from_slice(&pk_hash);
            return PatriciaTrie::verify_merkle_proof(
                &self.source_state_root,
                &self.tx.from,
                &pq_leaf,
                proof,
            );
        }

        if PatriciaTrie::verify_merkle_proof(
            &self.source_state_root,
            &self.tx.from,
            &account_value,
            proof,
        ) {
            return true;
        }

        // Support pinned PQ accounts (49-byte leaf: balance || nonce || scheme || pk_hash)
        if let Some(env) = self.tx.pq_envelope() {
            let maybe_pk = env.pubkey.as_ref().cloned().or_else(|| {
                global_implicit_key_registry()
                    .lookup(&self.tx.from)
                    .map(|(_, pk)| pk)
            });
            if let Some(ref pk) = maybe_pk {
                let pk_hash = blake3::hash(pk);
                let mut pq_leaf = Vec::with_capacity(49);
                pq_leaf.extend_from_slice(&account_value);
                pq_leaf.push(env.scheme.id());
                pq_leaf.extend_from_slice(pk_hash.as_bytes());
                if PatriciaTrie::verify_merkle_proof(
                    &self.source_state_root,
                    &self.tx.from,
                    &pq_leaf,
                    proof,
                ) {
                    return true;
                }
            }
        }

        // Support pinned accounts registered in implicit key registry (even if tx is not marked PQ)
        if let Some((scheme, pk)) = global_implicit_key_registry().lookup(&self.tx.from) {
            let pk_hash = blake3::hash(&pk);
            let mut pq_leaf = Vec::with_capacity(49);
            pq_leaf.extend_from_slice(&account_value);
            pq_leaf.push(scheme.id());
            pq_leaf.extend_from_slice(pk_hash.as_bytes());
            if PatriciaTrie::verify_merkle_proof(
                &self.source_state_root,
                &self.tx.from,
                &pq_leaf,
                proof,
            ) {
                return true;
            }
        }

        // Support pinned Ed25519 accounts where pubkey_hash = blake3(from)
        let ed_pk_hash = blake3::hash(&self.tx.from);
        let mut ed_pq_leaf = Vec::with_capacity(49);
        ed_pq_leaf.extend_from_slice(&account_value);
        ed_pq_leaf.push(PqScheme::Ed25519.id());
        ed_pq_leaf.extend_from_slice(ed_pk_hash.as_bytes());
        if PatriciaTrie::verify_merkle_proof(
            &self.source_state_root,
            &self.tx.from,
            &ed_pq_leaf,
            proof,
        ) {
            return true;
        }

        // Support pinned Ed25519 accounts where pubkey_hash = from
        let mut direct_pq_leaf = Vec::with_capacity(49);
        direct_pq_leaf.extend_from_slice(&account_value);
        direct_pq_leaf.push(PqScheme::Ed25519.id());
        direct_pq_leaf.extend_from_slice(&self.tx.from);
        if PatriciaTrie::verify_merkle_proof(
            &self.source_state_root,
            &self.tx.from,
            &direct_pq_leaf,
            proof,
        ) {
            return true;
        }

        false
    }

    /// True when this message is an OUTBOUND (produce) record for `shard_id`:
    /// the value leaves this shard when the block that carries it is applied.
    pub fn is_outbound_for(&self, shard_id: ShardId) -> bool {
        self.source_shard == shard_id && self.target_shard != shard_id
    }

    /// True when this message is an INBOUND (consume) record for `shard_id`:
    /// the recipient is credited on this shard when the block is applied.
    pub fn is_inbound_for(&self, shard_id: ShardId) -> bool {
        self.target_shard == shard_id && self.source_shard != shard_id
    }
}

/// Replay-protection key for a consumed cross-shard message.
///
/// `Block`/`Transaction`/`CrossShardMessage` gain NO new fields (bincode 1.3
/// would break every persisted block), so the source height is not carried as a
/// separate integer. The source block identity is [`CrossShardMessage::finalized_in_block`]
/// (the source shard's finalized head that the producing block extends) and the
/// `msg_id` commits to the source shard, the target shard, the full transaction
/// hash and that block identity. `(source_shard, finalized_in_block, msg_id)` is
/// therefore a unique, deterministic key for the source (height, shard, id):
/// two blocks at different source heights cannot share it, and it is identical
/// on every node that saw the same source block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CrossShardKey {
    pub source_shard: ShardId,
    pub finalized_in_block: [u8; 32],
    pub msg_id: [u8; 32],
}
/// Process-local registry of finalized block headers, shared by every shard
/// runtime in the process (C1 anchor). Maps (shard, source block hash) to the
/// state root THIS process committed to — keyed by PAIR because different
/// shards' geneses (and the zero-hash genesis placeholder below) must never
/// collide. Reads never block consensus: lookups are a BTreeMap probe, and
/// a MISS is fail-closed (message not verifiable YET — the proposer skips
/// it, a validator refuses the block carrying it; both retry after catching
/// up). Wrote on finalize AND adopt (adopted blocks carry verified QCs, so
/// they anchor exactly like local finals) plus an explicit genesis note at
/// every chain start (the first messages reference the genesis parent, which
/// no finalize event ever records). NEVER populated from gossip, RPC, or DHT
/// blobs: only block-application paths write here, so an attacker cannot
/// plant a root.
#[derive(Clone, Debug, Default)]
pub struct FinalizedHeaderRegistry {
    headers: std::collections::BTreeMap<(ShardId, [u8; 32]), crate::cell::CellHash>,
}

impl FinalizedHeaderRegistry {
    /// Record a finalized block. Idempotent (same hash = same header).
    pub fn note_finalized(&mut self, shard: ShardId, block_hash: [u8; 32], state_root: crate::cell::CellHash) {
        self.headers.insert((shard, block_hash), state_root);
    }

    /// Look up a source block hash. Returns the state root this process
    /// committed to — `None` means "not finalized here (yet)".
    pub fn lookup(&self, shard: ShardId, block_hash: &[u8; 32]) -> Option<crate::cell::CellHash> {
        self.headers.get(&(shard, *block_hash)).copied()
    }

    /// Mirror of [`CrossShardMessage::verify_anchored`] for callers that only
    /// need the anchor verdict without the proof check.
    pub fn anchor_holds(
        &self,
        source_shard: ShardId,
        block_hash: &[u8; 32],
        claimed_root: &crate::cell::CellHash,
    ) -> bool {
        matches!(self.lookup(source_shard, block_hash), Some(r) if &r == claimed_root)
    }
}

/// Process-shared finalized-header registry (C1 anchor plumbing). Every
/// shard runtime and state engine in the process holds the SAME `Arc`
/// (constructed once per process/cluster, passed explicitly — never a
/// global: independent test clusters must not mix their geneses).

/// The whole cross-shard replay state in one snapshot blob (audit F-I).
///
/// The engine's consumed set gates the actual credit at apply time; the
/// runtime's three sets gate proposal/validation (consumed filter), ack/bounce
/// linkage + timeout-bounce generation (produced), and completion marking
/// (completed). ALL of them are memory-only today, so a restart wiped them
/// and a replayed message passed every check: the target credited twice, or a
/// bounce refunded twice. Snapshotted height-keyed like every other domain;
/// restored on startup (full replay via `restore_cross_shard_replay`, engine
/// part in the load paths, runtime part where the runtime is constructed).
/// Sorted vecs (deterministic bytes); a missing entry means "empty", which is
/// also what a fresh process holds.
///
/// COMMITTED into `commitment_digest` (audit F1 fix) via
/// `commitment::write_cross_shard_domain`: a CONDITIONAL domain — all three
/// sets empty writes zero bytes, so existing chains (`COMMITMENT_VERSION`
/// unchanged) and every single-shard snapshot root byte-identically to
/// before, while any non-empty replay state moves the root. Two nodes with
/// identical blocks derive identical sets, so no consensus divergence can
/// arise from the sets themselves — and a node that drops them can no longer
/// agree with one that kept them under one root.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CrossShardReplaySnapshot {
    /// Engine credit gate (one entry per consumed inbound message).
    pub engine_consumed: Vec<CrossShardKey>,
    /// Runtime propose/validate filter mirror.
    pub runtime_consumed: Vec<CrossShardKey>,
    /// Outbounds this chain committed: (tx hash, transaction, height).
    pub produced: Vec<([u8; 32], Transaction, u64)>,
    /// Completed lifecycles (acked or bounced tx hashes).
    pub completed: Vec<[u8; 32]>,
}

impl CrossShardKey {
    pub fn of(msg: &CrossShardMessage) -> Self {
        Self {
            source_shard: msg.source_shard,
            finalized_in_block: msg.finalized_in_block,
            msg_id: msg.msg_id,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub shard_id: ShardId,
    pub height: u64,
    pub prev_hash: [u8; 32],
    pub state_root: CellHash,
    pub transactions: Vec<Transaction>,
    pub cross_shard_out: Vec<CrossShardMessage>,
    pub timestamp: u64,
    pub proposer: [u8; 32],
    pub validator_signatures: Vec<([u8; 32], Vec<u8>)>,
    /// The precommit quorum certificate that finalized this block, if any.
    /// Attached at finalization time. Deliberately EXCLUDED from `compute_hash`
    /// (like `validator_signatures`): it is evidence ABOUT the block, decided by
    /// a quorum that only exists after the block hash is fixed. Including it in
    /// the hash would make finalization change the block's identity.
    /// Block sync verifies this QC instead of trusting bare signatures, because
    /// vote signatures are over `vote_sign_bytes`, not over the block hash, and
    /// can never verify as block signatures.
    pub precommit_qc: Option<crate::consensus::QuorumCertificate>,
}

impl Block {
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        // Domain separator: version the block-commitment scheme.
        hasher.update(b"STELLEREUM_BLOCK_V2");
        hasher.update(self.shard_id.to_be_bytes());
        hasher.update(self.height.to_be_bytes());
        hasher.update(&self.prev_hash);
        hasher.update(&self.state_root);
        // CRITICAL: commit to EVERY transaction field (nonce, gas_limit, shards
        // and especially the SVM payload) via the full tx hash. Hashing only
        // from/to/amount let a proposer equivocate with two distinct bodies under
        // a single voted block hash, which would diverge node state after
        // finality. Signatures are intentionally excluded (they sign this hash).
        hasher.update((self.transactions.len() as u32).to_be_bytes());
        for tx in &self.transactions {
            hasher.update(tx.compute_tx_hash());
        }
        // Commit to cross-shard outbound messages as well.
        hasher.update((self.cross_shard_out.len() as u32).to_be_bytes());
        for m in &self.cross_shard_out {
            hasher.update(m.msg_id);
        }
        hasher.update(self.timestamp.to_be_bytes());
        hasher.update(&self.proposer);
        hasher.finalize().into()
    }

    pub fn sign_block(&mut self, validator_key: &SigningKey) {
        let block_hash = self.compute_hash();
        let sig = validator_key.sign(&block_hash);
        self.validator_signatures.push((
            validator_key.verifying_key().to_bytes(),
            sig.to_vec(),
        ));
    }

    /// Verify the block carries a valid signature by its DECLARED proposer.
    ///
    /// SECURITY: proposal authenticity. Without this, any peer could broadcast a
    /// `Proposal` for another validator's slot (with valid transactions but no
    /// proposer signature) and have honest nodes prevote it — breaking
    /// attribution and letting an attacker inject proposals on someone's behalf.
    pub fn verify_proposer_signature(&self) -> bool {
        let hash = self.compute_hash();
        for (pubkey, sig_bytes) in &self.validator_signatures {
            if *pubkey != self.proposer {
                continue;
            }
            let Ok(vk) = VerifyingKey::from_bytes(pubkey) else { continue };
            let Ok(sig) = Signature::from_slice(sig_bytes) else { continue };
            if vk.verify(&hash, &sig).is_ok() {
                return true;
            }
        }
        false
    }

    /// Verify the block carries a real validator quorum, by POWER.
    ///
    /// `verify_signatures(count)` counted distinct pubkeys with a valid signature
    /// and never checked whether any of them was a validator at all, so three
    /// throwaway keypairs satisfied it - a forged block history verified. The
    /// caller then made it worse by passing `quorum_power()`, a sum of stake
    /// units, where a head count was expected. Both halves had to change
    /// together: a signature is only evidence if it comes from a validator, and
    /// the threshold is a fraction of stake, not a number of names.
    ///
    /// A set with no power fails closed, because `quorum_power` is then
    /// unreachable.
    pub fn verify_validator_quorum(&self, validators: &crate::consensus::ValidatorSet) -> bool {
        let required = validators.quorum_power();
        if required == u64::MAX {
            return false;
        }
        let block_hash = self.compute_hash();
        // Dedup + membership first (cheap per item, input order preserved for a
        // deterministic fallback). The expensive crypto happens once below.
        let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        let mut candidates: Vec<(VerifyingKey, Signature, u64)> = Vec::new();
        for (pubkey, sig_bytes) in &self.validator_signatures {
            // Count each validator at most once, or one key could sign N times to
            // fake an N-of-M quorum.
            if !seen.insert(*pubkey) {
                continue;
            }
            // Membership FIRST: an unknown key has no power and must not be
            // counted even if the signature is perfectly valid.
            let vp = validators.power_of(pubkey);
            if vp == 0 {
                continue;
            }
            let Ok(vk) = VerifyingKey::from_bytes(pubkey) else { continue };
            let Ok(sig) = Signature::from_slice(sig_bytes) else { continue };
            candidates.push((vk, sig, vp));
        }
        if candidates.is_empty() {
            return false;
        }
        // Fast path: one batch verification over the shared block hash.
        // Same-message batching; result is order-independent.
        {
            let msgs: Vec<&[u8]> = candidates.iter().map(|_| block_hash.as_slice()).collect();
            let sigs: Vec<Signature> = candidates.iter().map(|(_, s, _)| *s).collect();
            let keys: Vec<VerifyingKey> = candidates.iter().map(|(k, _, _)| *k).collect();
            if ed25519_dalek::verify_batch(&msgs, &sigs, &keys).is_ok() {
                let power: u64 = candidates.iter().map(|(_, _, p)| p).sum();
                return power >= required;
            }
        }
        // Slow path: batch rejected, so at least one signature is bad. Fall back
        // to per-signature checks in input order and count exactly the valid
        // power — one forged neighbor must not sink a good quorum, and a bad
        // quorum must not pass on its good members. Identical verdict to the
        // old scalar loop in all cases.
        let mut power = 0u64;
        for (vk, sig, vp) in &candidates {
            if vk.verify(&block_hash, sig).is_ok() {
                power = power.saturating_add(*vp);
            }
        }
        power >= required
    }

    /// Count distinct valid signers. Retained for tests and for code that has
    /// its own membership check; the consensus path must use
    /// `verify_validator_quorum`, which also weights by stake.
    pub fn verify_signatures(&self, required_quorum: usize) -> bool {
        // A zero quorum is nonsensical for consensus and must never accept a block.
        if required_quorum == 0 {
            return false;
        }
        let block_hash = self.compute_hash();
        // SECURITY: count each DISTINCT validator at most once. Otherwise a single
        // validator key signing the same block N times would fake an N-of-M quorum.
        let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        let mut candidates: Vec<(VerifyingKey, Signature)> = Vec::new();
        for (pubkey, sig_bytes) in &self.validator_signatures {
            if !seen.insert(*pubkey) {
                continue; // duplicate signer -> ignore
            }
            let Ok(vk) = VerifyingKey::from_bytes(pubkey) else { continue };
            let Ok(sig) = Signature::from_slice(sig_bytes) else { continue };
            candidates.push((vk, sig));
        }
        if candidates.is_empty() {
            return false;
        }
        // Fast path: one batch verification over the shared block hash.
        {
            let msgs: Vec<&[u8]> = candidates.iter().map(|_| block_hash.as_slice()).collect();
            let sigs: Vec<Signature> = candidates.iter().map(|(_, s)| *s).collect();
            let keys: Vec<VerifyingKey> = candidates.iter().map(|(k, _)| *k).collect();
            if ed25519_dalek::verify_batch(&msgs, &sigs, &keys).is_ok() {
                return candidates.len() >= required_quorum;
            }
        }
        // Slow path: deterministic scalar fallback in input order — identical
        // verdict to the old per-signature loop.
        let mut valid = 0usize;
        for (vk, sig) in &candidates {
            if vk.verify(&block_hash, sig).is_ok() {
                valid += 1;
            }
        }
        valid >= required_quorum
    }
}

/// Shared Sequencer for unified cross-shard ordering and external L2 rollup scheduling
#[derive(Clone, Debug, Default)]
pub struct SharedSequencer {
    pub current_sequence: u64,
    pub scheduled_cross_shard: Vec<(u64, CrossShardMessage)>,
    /// §5 M3: per-source sequenced-height watermark (see `assign_from_block`).
    /// Advanced ONLY from finalized block content — never by time/operator.
    pub watermark: std::collections::BTreeMap<ShardId, u64>,
}

impl SharedSequencer {
    pub fn new() -> Self {
        Self {
            current_sequence: 1,
            scheduled_cross_shard: Vec::new(),
            watermark: std::collections::BTreeMap::new(),
        }
    }

    pub fn sequence_message(&mut self, msg: CrossShardMessage) -> u64 {
        let seq = self.current_sequence;
        self.current_sequence += 1;
        self.scheduled_cross_shard.push((seq, msg));
        seq
    }
}

/// Shared Liquidity Hub across all shards providing atomic all-or-nothing execution
pub struct SharedLiquidityHub {
    pub active_shards: Vec<ShardId>,
    pub pending_inbound_cross_shard: HashMap<ShardId, Vec<CrossShardMessage>>,
    pub sequencer: SharedSequencer,
    /// Replay protection: msg_id of every message already routed/delivered.
    pub seen_cross_shard: std::collections::HashSet<[u8; 32]>,
}

impl SharedLiquidityHub {
    pub fn new(active_shards: Vec<ShardId>) -> Self {
        Self {
            active_shards,
            pending_inbound_cross_shard: HashMap::new(),
            sequencer: SharedSequencer::new(),
            seen_cross_shard: std::collections::HashSet::new(),
        }
    }

    /// Route cross-shard messages directly to destination shard with sequencer ordering.
    /// SECURITY:
    ///  - A message that fails inclusion verification is NEVER routed (bounced or dropped).
    ///  - Duplicate msg_id is rejected (cross-shard replay protection).
    pub fn route_cross_shard_message(&mut self, mut msg: CrossShardMessage) -> u64 {
        // Replay protection: reject an already-seen message id.
        if self.seen_cross_shard.contains(&msg.msg_id) {
            return 0;
        }

        // Unknown/inactive target shard: never queue into a phantom shard.
        // NOTE: a rejected message does NOT reserve its id — otherwise an invalid
        // message could block a later VALID one (e.g. a rejected untrusted copy of
        // a legitimate in-process message). Only accepted messages are marked seen.
        if !self.active_shards.contains(&msg.target_shard) {
            if msg.bounce && !msg.bounced {
                msg.bounced = true;
                std::mem::swap(&mut msg.source_shard, &mut msg.target_shard);
                return self.sequencer.sequence_message(msg);
            }
            return 0;
        }

        if !msg.verify_inclusion() {
            if msg.bounce && !msg.bounced {
                msg.bounced = true;
                std::mem::swap(&mut msg.source_shard, &mut msg.target_shard);
                return self.sequencer.sequence_message(msg);
            }
            // Invalid and non-bounceable: drop, never route.
            return 0;
        }

        self.seen_cross_shard.insert(msg.msg_id);
        let target = msg.target_shard;
        let seq = self.sequencer.sequence_message(msg.clone());
        self.pending_inbound_cross_shard
            .entry(target)
            .or_insert_with(Vec::new)
            .push(msg);
        seq
    }

    pub fn take_inbound_messages(&mut self, shard: ShardId) -> Vec<CrossShardMessage> {
        self.pending_inbound_cross_shard
            .remove(&shard)
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shard_registry_default_is_single_and_not_sharded() {
        let r = ShardRegistry::default();
        assert!(!r.is_sharded(), "the default registry must be single-shard");
        assert_eq!(r.ids().collect::<Vec<_>>(), vec![MASTERCHAIN_SHARD]);
        assert!(r.contains(MASTERCHAIN_SHARD));
        assert!(!r.contains(BASE_WORKCHAIN_SHARD_INITIAL));
    }

    #[test]
    fn shard_registry_from_ids_marks_multi_shard() {
        let r = ShardRegistry::from_ids([MASTERCHAIN_SHARD, BASE_WORKCHAIN_SHARD_INITIAL]);
        assert!(r.is_sharded());
        assert_eq!(
            r.ids().collect::<Vec<_>>(),
            vec![MASTERCHAIN_SHARD, BASE_WORKCHAIN_SHARD_INITIAL]
        );
        // A single non-masterchain shard is still one chain in this process.
        assert!(!ShardRegistry::from_ids([BASE_WORKCHAIN_SHARD_INITIAL]).is_sharded());
        // An empty set can never produce a process with no chain at all.
        assert_eq!(ShardRegistry::from_ids([]).ids().collect::<Vec<_>>(), vec![MASTERCHAIN_SHARD]);
    }

    #[test]
    fn block_shard_ignores_namespace_shard_when_not_sharded() {
        // Regression: a single-shard node started with `--shard 1` uses shard 1
        // only as the DHT/blob namespace. Its BLOCKS must stay masterchain (0),
        // matching its persisted chain, or sync validation rejects every chain
        // and finality stalls. This was the live stand deadlock.
        let single_via_cli = ShardRegistry::from_env_or(BASE_WORKCHAIN_SHARD_INITIAL);
        assert!(!single_via_cli.is_sharded());
        assert_eq!(
            block_shard_for(BASE_WORKCHAIN_SHARD_INITIAL, &single_via_cli),
            MASTERCHAIN_SHARD
        );
        // A genuine multi-shard process does scope blocks to its namespace shard.
        let multi = ShardRegistry::from_ids([MASTERCHAIN_SHARD, BASE_WORKCHAIN_SHARD_INITIAL]);
        assert!(multi.is_sharded());
        assert_eq!(
            block_shard_for(BASE_WORKCHAIN_SHARD_INITIAL, &multi),
            BASE_WORKCHAIN_SHARD_INITIAL
        );
    }

    #[test]
    fn route_address_is_deterministic_and_most_specific() {
        let mut m = DynamicShardManager::new();
        m.record_tx_load(BASE_WORKCHAIN_SHARD_INITIAL, SHARD_SPLIT_LOAD_THRESHOLD);
        let (c0, c1) = m.check_and_split(BASE_WORKCHAIN_SHARD_INITIAL).expect("split");
        assert_eq!((c0.prefix_len, c1.prefix_len), (1, 1));

        let mut a0 = [0u8; 32];
        a0[0] = 0b0000_0000;
        let mut a1 = [0u8; 32];
        a1[0] = 0b1000_0000;

        let r0 = m.route_address(&a0);
        let r1 = m.route_address(&a1);
        // deterministic across repeated calls
        assert_eq!(r0, m.route_address(&a0));
        assert_eq!(r1, m.route_address(&a1));
        // routed to a shard that actually contains the address, and differently
        assert!(m.shards.get(&r0).unwrap().contains_address(&a0));
        assert!(m.shards.get(&r1).unwrap().contains_address(&a1));
        assert_ne!(r0, r1);
    }

    #[test]
    fn test_explicit_pq_transaction_verification() {
        let registry = StatefulImplicitKeyRegistry::new();
        let seed = 0x42;
        let pk = Transaction::sample_falcon512_pubkey(seed);
        let salt = DEFAULT_SALT;
        let from = derive_pq_address(PqScheme::Falcon512, &pk, &salt);

        // Pre-create transaction with empty signature to obtain exact signing message
        let mut tx = Transaction {
            from,
            to: [2u8; 32],
            amount: 1000,
            gas_limit: 50_000,
            nonce: 0,
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload: Vec::new(),
        };
        let msg = tx.signing_message();
        let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
        let envelope = PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk.clone(), sig);
        tx.signature = envelope.encode();

        assert!(tx.is_pq());
        assert!(tx.is_pq_activation());
        assert!(!tx.is_pq_implicit());

        // Verification against isolated registry succeeds and auto-registers the key
        assert!(tx.verify_signature_with_registry(&registry));
        let registered = registry.lookup(&from).expect("Address must be registered after explicit verify");
        assert_eq!(registered.0, PqScheme::Falcon512);
        assert_eq!(registered.1, pk);

        // Global registry verification also succeeds
        assert!(tx.verify_signature());

        // Explicit Ed25519 PQ envelope
        let ed_sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let ed_pk = ed_sk.verifying_key().to_bytes().to_vec();
        let ed_from = derive_pq_address(PqScheme::Ed25519, &ed_pk, &salt);
        let mut ed_tx = Transaction {
            from: ed_from,
            to: [3u8; 32],
            amount: 500,
            gas_limit: 30_000,
            nonce: 0,
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload: Vec::new(),
        };
        let ed_msg = ed_tx.signing_message();
        let ed_sig = ed_sk.sign(&ed_msg).to_bytes().to_vec();
        ed_tx.signature = PqSignatureEnvelope::new_explicit(PqScheme::Ed25519, ed_pk, ed_sig).encode();
        assert!(ed_tx.verify_signature());
    }

    #[test]
    fn test_implicit_pq_transaction_verification_zero_wire_overhead() {
        let registry = StatefulImplicitKeyRegistry::new();
        let seed = 0x77;
        let pk = Transaction::sample_falcon512_pubkey(seed);
        let salt = DEFAULT_SALT;
        let from = derive_pq_address(PqScheme::Falcon512, &pk, &salt);

        // Build Tx2 (implicit, nonce 1)
        let mut tx2 = Transaction {
            from,
            to: [5u8; 32],
            amount: 250,
            gas_limit: 50_000,
            nonce: 1,
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload: Vec::new(),
        };
        let msg = tx2.signing_message();
        let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
        let envelope = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig);
        tx2.signature = envelope.encode();

        assert!(tx2.is_pq());
        assert!(!tx2.is_pq_activation());
        assert!(tx2.is_pq_implicit());

        // Before registration, implicit verification MUST fail (cannot verify without pubkey)
        assert!(!tx2.verify_signature_with_registry(&registry));

        // Now register address in registry (e.g. from Tx1 activation)
        registry.register(from, PqScheme::Falcon512, &pk, &salt).expect("Register");

        // After registration, implicit verification MUST succeed!
        assert!(tx2.verify_signature_with_registry(&registry));

        // Verify wire size difference: implicit envelope carries NO public key or salt bytes
        let explicit_env = PqSignatureEnvelope::new_explicit(
            PqScheme::Falcon512,
            pk.clone(),
            envelope.signature_bytes.clone(),
        );
        let explicit_len = explicit_env.encode().len();
        let implicit_len = tx2.signature.len();
        assert_eq!(explicit_len - implicit_len, pk.len() + 16);
        assert!(explicit_len > 1500);
        assert!(implicit_len < 700);
    }

    #[test]
    fn test_tampering_detection_on_pq_signatures() {
        let registry = StatefulImplicitKeyRegistry::new();
        let seed = 0x99;
        let pk = Transaction::sample_falcon512_pubkey(seed);
        let salt = DEFAULT_SALT;
        let from = derive_pq_address(PqScheme::Falcon512, &pk, &salt);

        let mut tx = Transaction {
            from,
            to: [8u8; 32],
            amount: 100,
            gas_limit: 50_000,
            nonce: 0,
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload: Vec::new(),
        };
        let msg = tx.signing_message();
        let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
        let envelope = PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk.clone(), sig.clone());
        tx.signature = envelope.encode();

        // Baseline: original transaction verifies
        assert!(tx.verify_signature_with_registry(&registry));

        // 1. Tampered amount
        let mut tampered_amt = tx.clone();
        tampered_amt.amount += 1;
        assert!(!tampered_amt.verify_signature_with_registry(&registry), "Tampered amount must fail");

        // 2. Tampered recipient
        let mut tampered_to = tx.clone();
        tampered_to.to[0] ^= 0x01;
        assert!(!tampered_to.verify_signature_with_registry(&registry), "Tampered recipient must fail");

        // 3. Tampered sender address (does not match derived address from pk)
        let mut tampered_from = tx.clone();
        tampered_from.from[0] ^= 0x01;
        assert!(!tampered_from.verify_signature_with_registry(&registry), "Tampered sender must fail");

        // 4. Tampered signature bytes inside envelope
        let mut tampered_sig_bytes = sig.clone();
        tampered_sig_bytes[50] ^= 0xAA;
        let bad_env = PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk.clone(), tampered_sig_bytes);
        let mut tx_bad_sig = tx.clone();
        tx_bad_sig.signature = bad_env.encode();
        assert!(!tx_bad_sig.verify_signature_with_registry(&registry), "Corrupted signature bytes must fail");

        // 5. Tampered public key bytes inside envelope
        let mut bad_pk = pk.clone();
        bad_pk[10] ^= 0x55;
        let bad_pk_env = PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, bad_pk, sig.clone());
        let mut tx_bad_pk = tx.clone();
        tx_bad_pk.signature = bad_pk_env.encode();
        assert!(!tx_bad_pk.verify_signature_with_registry(&registry), "Corrupted pubkey must fail");

        // 6. Envelope header corruption (magic mismatch)
        let mut corrupted_magic = tx.clone();
        corrupted_magic.signature[0] = b'X';
        assert!(!corrupted_magic.verify_signature_with_registry(&registry), "Corrupted envelope magic must fail");

        // 7. Trailing junk attached to envelope
        let mut trailing_junk = tx.clone();
        trailing_junk.signature.push(0xDE);
        trailing_junk.signature.push(0xAD);
        assert!(!trailing_junk.verify_signature_with_registry(&registry), "Trailing bytes must fail exact-fit check");

        // 8. Truncated envelope
        let mut truncated = tx.clone();
        truncated.signature.truncate(tx.signature.len() - 10);
        assert!(!truncated.verify_signature_with_registry(&registry), "Truncated envelope must fail");
    }

    #[test]
    fn test_cross_shard_transfer_from_49_byte_pinned_account_leaf() {
        let seed = 0x5a;
        let pk = Transaction::sample_falcon512_pubkey(seed);
        let salt = DEFAULT_SALT;
        let from = derive_pq_address(PqScheme::Falcon512, &pk, &salt);
        let to = [9u8; 32];
        let amount = 5_000u64;
        let nonce = 2u64;
        let source_balance = 20_000u64;

        // Build PQ transaction with explicit activation envelope
        let mut tx = Transaction {
            from,
            to,
            amount,
            gas_limit: 30_000,
            nonce,
            source_shard: 1,
            target_shard: 2,
            signature: Vec::new(),
            payload: Vec::new(),
        };
        let msg = tx.signing_message();
        let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
        let envelope = PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk.clone(), sig.clone());
        tx.signature = envelope.encode();

        // Sender has a 49-byte pinned leaf in the source shard trie
        let pk_hash = blake3::hash(&pk);
        let leaf_49 = crate::cpat2::AccountLeaf::new_pinned(
            source_balance,
            nonce,
            PqScheme::Falcon512.id(),
            *pk_hash.as_bytes(),
        ).encode();
        assert_eq!(leaf_49.len(), crate::cpat2::ACCOUNT_LEAF_LEN_PQ);

        let mut trie = PatriciaTrie::new();
        trie.insert(&from, &leaf_49);
        let source_state_root = trie.root_hash();
        let proof = trie.generate_merkle_proof(&from).expect("merkle proof");

        let finalized_in_block = [0x77u8; 32];
        let cross_msg = CrossShardMessage::new(
            1,
            2,
            tx.clone(),
            source_state_root,
            finalized_in_block,
            Some(proof.clone()),
        ).with_source_balance(source_balance);

        // 1. Inclusion verification succeeds on 49-byte pinned leaf
        assert!(cross_msg.verify_inclusion(), "49-byte pinned leaf inclusion proof must verify");
        assert!(cross_msg.verify_inclusion_strict(), "Strict inclusion must verify");

        // 2. Fund loss prevention: underfunded transfer (source_balance < amount) fails closed
        let underfunded_msg = CrossShardMessage::new(
            1,
            2,
            tx.clone(),
            source_state_root,
            finalized_in_block,
            Some(proof.clone()),
        ).with_source_balance(amount - 1);
        assert!(!underfunded_msg.verify_inclusion(), "Underfunded transfer must be rejected");

        // 3. Fund loss prevention: tampered source_balance fails proof verification
        let tampered_balance_msg = CrossShardMessage::new(
            1,
            2,
            tx.clone(),
            source_state_root,
            finalized_in_block,
            Some(proof.clone()),
        ).with_source_balance(source_balance + 1_000);
        assert!(!tampered_balance_msg.verify_inclusion(), "Tampered balance must fail proof verification");

        // 4. Implicit PQ cross-shard transaction verification
        let implicit_envelope = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig);
        let mut implicit_tx = tx.clone();
        implicit_tx.signature = implicit_envelope.encode();

        Transaction::global_implicit_registry()
            .register(from, PqScheme::Falcon512, &pk, &salt)
            .expect("register implicit key");

        let implicit_cross_msg = CrossShardMessage::new(
            1,
            2,
            implicit_tx,
            source_state_root,
            finalized_in_block,
            Some(proof.clone()),
        ).with_source_balance(source_balance);
        assert!(implicit_cross_msg.verify_inclusion(), "Implicit PQ cross-shard message must verify");

        // 5. Also verify legacy 16-byte leaf cross-shard transfer works cleanly
        let legacy_from = [0x88u8; 32];
        let legacy_leaf = crate::cpat2::AccountLeaf::new_unpinned(10_000, 0).encode();
        assert_eq!(legacy_leaf.len(), crate::cpat2::ACCOUNT_LEAF_LEN_LEGACY);
        let mut legacy_trie = PatriciaTrie::new();
        legacy_trie.insert(&legacy_from, &legacy_leaf);
        let legacy_root = legacy_trie.root_hash();
        let legacy_proof = legacy_trie.generate_merkle_proof(&legacy_from).expect("proof");

        let legacy_tx = Transaction {
            from: legacy_from,
            to,
            amount: 1_000,
            gas_limit: 21_000,
            nonce: 0,
            source_shard: 1,
            target_shard: 2,
            signature: vec![0u8; 64],
            payload: Vec::new(),
        };
        let legacy_cross_msg = CrossShardMessage::new(
            1,
            2,
            legacy_tx,
            legacy_root,
            finalized_in_block,
            Some(legacy_proof),
        ).with_source_balance(10_000);
        assert!(legacy_cross_msg.verify_inclusion(), "Legacy 16B leaf cross-shard message must verify");
    }

    #[test]
    fn test_explicit_pq_custom_non_zero_salt_verification() {
        let registry = StatefulImplicitKeyRegistry::new();
        let seed = 0x88;
        let pk = Transaction::sample_falcon512_pubkey(seed);
        let custom_salt = [0x5au8; 16];
        assert_ne!(custom_salt, DEFAULT_SALT);

        let from = derive_pq_address(PqScheme::Falcon512, &pk, &custom_salt);
        let default_from = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);
        assert_ne!(from, default_from, "Custom salt must derive disjoint address from default salt");

        let tx_probe = Transaction {
            from,
            to: [7u8; 32],
            amount: 1000,
            gas_limit: 50_000,
            nonce: 0,
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload: Vec::new(),
        };
        let msg = tx_probe.signing_message();
        let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);

        let tx = Transaction::new_pq_explicit(
            PqScheme::Falcon512,
            pk.clone(),
            sig,
            [7u8; 32],
            1000,
            50_000,
            0,
            1,
            1,
            Vec::new(),
            &custom_salt,
        );

        assert_eq!(tx.from, from);
        assert!(tx.is_pq());
        assert!(tx.is_pq_activation());

        let env = tx.pq_envelope().expect("PQ envelope must decode");
        assert_eq!(env.salt, custom_salt, "Envelope must carry custom salt");

        // Verification must use env.salt from the envelope and succeed
        assert!(
            tx.verify_signature_with_registry(&registry),
            "Explicit PQ tx carrying custom non-zero salt must verify"
        );
        let registered = registry.lookup(&from).expect("Address must be registered with custom salt");
        assert_eq!(registered.0, PqScheme::Falcon512);
        assert_eq!(registered.1, pk);

        // Global registry also succeeds
        assert!(tx.verify_signature());

        // Subsequent implicit transaction from this sender cleanly verifies via registry
        let tx2_probe = Transaction {
            from,
            to: [8u8; 32],
            amount: 500,
            gas_limit: 50_000,
            nonce: 1,
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload: Vec::new(),
        };
        let msg2 = tx2_probe.signing_message();
        let sig2 = Transaction::create_falcon512_test_signature(&pk, &msg2, seed);
        let tx2 = Transaction::new_pq_implicit(
            from,
            PqScheme::Falcon512,
            sig2,
            [8u8; 32],
            500,
            50_000,
            1,
            1,
            1,
            Vec::new(),
        );
        assert!(tx2.verify_signature_with_registry(&registry));

        // Wrong salt envelope fails closed (e.g. envelope with DEFAULT_SALT does not match `from`)
        let mut bad_salt_tx = tx.clone();
        let bad_env = PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk, env.signature_bytes);
        bad_salt_tx.signature = bad_env.encode();
        assert!(
            !bad_salt_tx.verify_signature_with_registry(&registry),
            "Envelope with mismatched salt must fail verification"
        );
    }

    #[test]
    fn test_pq_tx_hash_envelope_binding() {
        let seed = 0x66;
        let pk = Transaction::sample_falcon512_pubkey(seed);
        let salt = [0x12u8; 16];
        let from = derive_pq_address(PqScheme::Falcon512, &pk, &salt);

        let tx_probe = Transaction {
            from,
            to: [9u8; 32],
            amount: 100,
            gas_limit: 50_000,
            nonce: 0,
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload: Vec::new(),
        };
        let msg = tx_probe.signing_message();
        let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);

        let tx = Transaction::new_pq_explicit(
            PqScheme::Falcon512,
            pk.clone(),
            sig.clone(),
            [9u8; 32],
            100,
            50_000,
            0,
            1,
            1,
            Vec::new(),
            &salt,
        );

        let baseline_hash = tx.compute_tx_hash();

        // 1. Modifying signature bytes changes tx hash
        let mut tx_mutated_sig = tx.clone();
        let last_idx = tx_mutated_sig.signature.len() - 1;
        tx_mutated_sig.signature[last_idx] ^= 0x01;
        assert_ne!(
            baseline_hash,
            tx_mutated_sig.compute_tx_hash(),
            "Mutating signature bytes must change compute_tx_hash"
        );

        // 2. Modifying salt in envelope changes tx hash
        let mut env_tampered_salt = tx.pq_envelope().unwrap();
        env_tampered_salt.salt[0] ^= 0xFF;
        let mut tx_mutated_salt = tx.clone();
        tx_mutated_salt.signature = env_tampered_salt.encode();
        assert_ne!(
            baseline_hash,
            tx_mutated_salt.compute_tx_hash(),
            "Mutating envelope salt must change compute_tx_hash"
        );

        // 3. Modifying public key in envelope changes tx hash
        let mut env_tampered_pk = tx.pq_envelope().unwrap();
        env_tampered_pk.pubkey.as_mut().unwrap()[5] ^= 0xFF;
        let mut tx_mutated_pk = tx.clone();
        tx_mutated_pk.signature = env_tampered_pk.encode();
        assert_ne!(
            baseline_hash,
            tx_mutated_pk.compute_tx_hash(),
            "Mutating envelope public key must change compute_tx_hash"
        );

        // 4. Verify explicit SEC-PQ-07 commitment layout:
        // Hasher includes prefix b"PQ_ENV" followed by &self.signature
        let mut manual_hasher = Sha256::new();
        manual_hasher.update(&tx.from);
        manual_hasher.update(&tx.to);
        manual_hasher.update(tx.amount.to_be_bytes());
        manual_hasher.update(tx.gas_limit.to_be_bytes());
        manual_hasher.update(tx.nonce.to_be_bytes());
        manual_hasher.update(tx.source_shard.to_be_bytes());
        manual_hasher.update(tx.target_shard.to_be_bytes());
        manual_hasher.update(b"PAYLOAD");
        let payload_bytes = bincode::serialize(&tx.payload).unwrap();
        manual_hasher.update((payload_bytes.len() as u32).to_be_bytes());
        manual_hasher.update(&payload_bytes);
        manual_hasher.update(b"PQ_ENV");
        manual_hasher.update(&tx.signature);
        let expected_hash: [u8; 32] = manual_hasher.finalize().into();
        assert_eq!(baseline_hash, expected_hash, "compute_tx_hash must bind b\"PQ_ENV\" and &self.signature");
    }

    #[test]
    fn test_legacy_tx_hash_remains_byte_identical() {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let to = [4u8; 32];
        let amount = 2500;
        let gas_limit = 21_000;
        let nonce = 7;
        let source_shard = 0;
        let target_shard = 0;

        let tx = Transaction::sign(&sk, to, amount, gas_limit, nonce, source_shard, target_shard);
        assert!(!tx.is_pq(), "Legacy transaction must not be marked as PQ");
        assert_eq!(tx.signature.len(), 64);

        let tx_hash = tx.compute_tx_hash();

        // Exact pre-PQ legacy transaction hash algorithm
        let mut legacy_hasher = Sha256::new();
        legacy_hasher.update(&tx.from);
        legacy_hasher.update(&tx.to);
        legacy_hasher.update(tx.amount.to_be_bytes());
        legacy_hasher.update(tx.gas_limit.to_be_bytes());
        legacy_hasher.update(tx.nonce.to_be_bytes());
        legacy_hasher.update(tx.source_shard.to_be_bytes());
        legacy_hasher.update(tx.target_shard.to_be_bytes());
        legacy_hasher.update(b"PAYLOAD");
        let payload_bytes = bincode::serialize(&tx.payload).unwrap();
        legacy_hasher.update((payload_bytes.len() as u32).to_be_bytes());
        legacy_hasher.update(&payload_bytes);
        // Note: no PQ_ENV commitment added for legacy
        let expected_legacy_hash: [u8; 32] = legacy_hasher.finalize().into();

        assert_eq!(
            tx_hash, expected_legacy_hash,
            "Legacy transaction hash must remain strictly byte-identical"
        );

        // Modifying signature on legacy transaction does NOT change compute_tx_hash (preserving legacy semantics)
        let mut tx_mutated_sig = tx.clone();
        tx_mutated_sig.signature[0] ^= 0xFF;
        assert_eq!(
            tx_mutated_sig.compute_tx_hash(),
            tx_hash,
            "Legacy tx hash does not bind signature, preserving backward compatibility"
        );
    }

    #[test]
    fn test_cross_shard_verification_target_shard_pinned_pq_account() {
        // Audit finding SEC-PQ-03: When a pinned account on Shard 1 sends an implicit
        // cross-shard transfer to Shard 2, Shard 2 doesn't have the public key in local RAM.
        // CrossShardMessage carries `sender_pubkey_hash` and `sender_scheme`, enabling
        // Shard 2 to construct the 49-byte leaf and verify inclusion without local RAM keys!

        let seed = 0x88;
        let pk = Transaction::sample_falcon512_pubkey(seed);
        let salt = DEFAULT_SALT;
        let from = derive_pq_address(PqScheme::Falcon512, &pk, &salt);
        let to = [0x55u8; 32];
        let amount = 3_000u64;
        let nonce = 5u64;
        let source_balance = 15_000u64;

        // 1. Build an implicit PQ transaction (omitting public key from wire)
        let mut tx_probe = Transaction {
            from,
            to,
            amount,
            gas_limit: 40_000,
            nonce,
            source_shard: 1,
            target_shard: 2,
            signature: Vec::new(),
            payload: Vec::new(),
        };
        let msg = tx_probe.signing_message();
        let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
        let implicit_envelope = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig);
        tx_probe.signature = implicit_envelope.encode();

        assert!(tx_probe.is_pq());
        assert!(tx_probe.is_pq_implicit());

        // 2. Set up the 49-byte leaf in Shard 1's state trie:
        //    account_value (16B) || scheme (1B) || pubkey_hash (32B)
        let pk_hash = blake3::hash(&pk);
        let leaf_49 = crate::cpat2::AccountLeaf::new_pinned(
            source_balance,
            nonce,
            PqScheme::Falcon512.id(),
            *pk_hash.as_bytes(),
        ).encode();
        assert_eq!(leaf_49.len(), crate::cpat2::ACCOUNT_LEAF_LEN_PQ);

        let mut trie = PatriciaTrie::new();
        trie.insert(&from, &leaf_49);
        let source_state_root = trie.root_hash();
        let proof = trie.generate_merkle_proof(&from).expect("merkle proof");

        // Register the key in Shard 1's local implicit registry before producing the message
        Transaction::global_implicit_registry()
            .register(from, PqScheme::Falcon512, &pk, &salt)
            .expect("register implicit key on source shard");

        let finalized_in_block = [0xAAu8; 32];
        let cross_msg = CrossShardMessage::new(
            1,
            2,
            tx_probe.clone(),
            source_state_root,
            finalized_in_block,
            Some(proof.clone()),
        ).with_source_balance(source_balance);

        // Verify that CrossShardMessage::new automatically populated sender_pubkey_hash and sender_scheme
        assert_eq!(cross_msg.sender_scheme, Some(PqScheme::Falcon512.id()));
        assert_eq!(cross_msg.sender_pubkey_hash, Some(*pk_hash.as_bytes()));

        // 3. Simulate wire transmission to Shard 2 via bincode serialization/deserialization
        let wire_bytes = bincode::serialize(&cross_msg).expect("serialize CrossShardMessage");
        let received_msg: CrossShardMessage = bincode::deserialize(&wire_bytes).expect("deserialize CrossShardMessage");

        assert_eq!(received_msg.sender_scheme, Some(PqScheme::Falcon512.id()));
        assert_eq!(received_msg.sender_pubkey_hash, Some(*pk_hash.as_bytes()));

        // 4. On Shard 2: verify inclusion strictly without needing local RAM keys!
        assert!(
            received_msg.verify_inclusion(),
            "Target shard must verify 49-byte leaf inclusion proof using sender_pubkey_hash metadata"
        );
        assert!(
            received_msg.verify_inclusion_strict(),
            "Strict untrusted verification must succeed without local keys"
        );

        // 5. Tampering detection:
        // (a) Tampered sender_pubkey_hash must fail proof verification
        let mut tampered_pk_hash_msg = received_msg.clone();
        tampered_pk_hash_msg.sender_pubkey_hash = Some([0xEEu8; 32]);
        assert!(
            !tampered_pk_hash_msg.verify_inclusion(),
            "Tampered sender_pubkey_hash must be rejected"
        );

        // (b) Tampered sender_scheme must fail proof verification
        let mut tampered_scheme_msg = received_msg.clone();
        tampered_scheme_msg.sender_scheme = Some(PqScheme::Ed25519.id());
        assert!(
            !tampered_scheme_msg.verify_inclusion(),
            "Tampered sender_scheme must be rejected"
        );

        // (c) Explicit PQ envelope cross-shard message
        let explicit_env = PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk.clone(), vec![0u8; 666]);
        let mut explicit_tx = tx_probe.clone();
        explicit_tx.signature = explicit_env.encode();
        let explicit_msg = CrossShardMessage::new(
            1,
            2,
            explicit_tx,
            source_state_root,
            finalized_in_block,
            Some(proof.clone()),
        ).with_source_balance(source_balance);
        assert_eq!(explicit_msg.sender_scheme, Some(PqScheme::Falcon512.id()));
        assert_eq!(explicit_msg.sender_pubkey_hash, Some(*pk_hash.as_bytes()));
        assert!(explicit_msg.verify_inclusion());
    }

    #[tokio::test]
    async fn test_finding_f1_chain_id_binding_ed25519() {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let from = sk.verifying_key().to_bytes();
        let to = [0x42u8; 32];
        let chain_id_main = 5757u64;
        let chain_id_alt = 777u64;

        let tx = Transaction::sign_with_chain_id(
            &sk,
            to,
            1_000,
            50_000,
            0,
            1,
            1,
            chain_id_main,
        );

        assert!(tx.is_chain_id_bound(), "Transaction must carry CH1 envelope");
        assert_eq!(tx.chain_id(), Some(chain_id_main));
        assert!(tx.verify_signature(), "Self verification must pass");
        assert!(
            tx.verify_signature_for_chain(chain_id_main, true),
            "Verification for target chain must pass"
        );
        assert!(
            !tx.verify_signature_for_chain(chain_id_alt, true),
            "Cross-chain replay on alt chain must be rejected"
        );

        // Tampering with chain_id in envelope invalidates cryptographic signature
        let mut tampered_envelope = tx.clone();
        let offset = 64 + CHAIN_SIG_TAG.len();
        tampered_envelope.signature[offset..offset + 8].copy_from_slice(&chain_id_alt.to_be_bytes());
        assert_eq!(tampered_envelope.chain_id(), Some(chain_id_alt));
        assert!(
            !tampered_envelope.verify_signature(),
            "Tampered chain_id envelope must fail signature verification"
        );

        // Stripping envelope to simulate legacy tx fails because signing_message committed chain_id
        let mut stripped = tx.clone();
        stripped.signature.truncate(64);
        assert_eq!(stripped.chain_id(), None);
        assert!(
            !stripped.verify_signature(),
            "Stripping CH1 envelope must fail signature verification"
        );

        // State engine cross-chain replay rejection
        let engine_main = crate::state_engine::InMemoryStateEngine::new().with_chain_id(chain_id_main);
        engine_main.credit_native(&from, 100_000).await.unwrap();
        assert!(
            engine_main.apply_transaction(&tx, 1_000).await.is_ok(),
            "Transaction must apply on matching chain engine"
        );

        let engine_alt = crate::state_engine::InMemoryStateEngine::new().with_chain_id(chain_id_alt);
        engine_alt.credit_native(&from, 100_000).await.unwrap();
        let err = engine_alt
            .apply_transaction(&tx, 1_000)
            .await
            .expect_err("Must reject transaction on different chain");
        assert!(
            err.contains("chain_id mismatch"),
            "Error must specify chain_id mismatch: {err}"
        );
    }

    #[test]
    fn test_finding_f1_chain_id_binding_pq() {
        let seed = 0x51;
        let pk = Transaction::sample_falcon512_pubkey(seed);
        let salt = DEFAULT_SALT;
        let from = derive_pq_address(PqScheme::Falcon512, &pk, &salt);
        let to = [0x77u8; 32];
        let chain_id_main = 5757u64;
        let chain_id_alt = 999u64;

        let tx_probe = Transaction {
            from,
            to,
            amount: 500,
            gas_limit: 40_000,
            nonce: 0,
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload: Vec::new(),
        };
        let msg = tx_probe.signing_message_for_chain(chain_id_main);
        let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);

        let tx = Transaction::new_pq_explicit_with_chain(
            PqScheme::Falcon512,
            pk,
            sig,
            to,
            500,
            40_000,
            0,
            1,
            1,
            Vec::new(),
            &salt,
            chain_id_main,
        );

        assert!(tx.is_pq());
        assert_eq!(tx.chain_id(), Some(chain_id_main));
        assert!(tx.verify_signature(), "PQ transaction must verify");
        assert!(tx.verify_signature_for_chain(chain_id_main, true));
        assert!(
            !tx.verify_signature_for_chain(chain_id_alt, true),
            "PQ transaction must reject verification for different chain"
        );
    }

    #[test]
    fn test_finding_f1_legacy_compatibility_unaffected() {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let to = [0x33u8; 32];
        let tx = Transaction::sign(&sk, to, 100, 21_000, 0, 1, 1);

        assert_eq!(tx.chain_id(), None);
        assert!(!tx.is_chain_id_bound());
        assert_eq!(tx.signature.len(), 64);
        assert_eq!(tx.signing_message().len(), 115);
        assert!(tx.verify_signature());
        assert!(tx.verify_signature_for_chain(5757, false));
        assert!(!tx.verify_signature_for_chain(5757, true));
    }

    #[test]
    fn test_finding_f1_batch_verification_with_chain_bound_tx() {
        let sk1 = SigningKey::generate(&mut rand::rngs::OsRng);
        let sk2 = SigningKey::generate(&mut rand::rngs::OsRng);
        let tx1 = Transaction::sign(&sk1, [1u8; 32], 100, 21_000, 0, 1, 1);
        let tx2 = Transaction::sign_with_chain_id(&sk2, [2u8; 32], 200, 21_000, 0, 1, 1, 5757);

        let txs = vec![tx1, tx2];
        assert!(Transaction::verify_signatures_batch(&txs));
        let results = Transaction::verify_signatures_partitioned(&txs);
        assert_eq!(results, vec![true, true]);
    }
}

/// Decoder fuzz regressions (Agent 1): Transaction/Block bincode decode must
/// never panic on peer bytes (length-prefix / opcode-count / sig abuse).
/// Appended without touching existing code.
#[cfg(test)]
mod decoder_fuzz_regressions {
    use super::*;

    #[test]
    fn tx_and_block_max_prefixes_never_panic() {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let tx = Transaction::sign(&sk, [1u8; 32], 10, 5, 0, 1, 1);
        let enc = bincode::serialize(&tx).unwrap();
        let mut block = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: 1,
            prev_hash: [0u8; 32],
            state_root: [0u8; 32],
            transactions: vec![tx],
            cross_shard_out: vec![],
            timestamp: 0,
            proposer: sk.verifying_key().to_bytes(),
            validator_signatures: vec![],
            precommit_qc: None,
        };
        block.sign_block(&sk);
        let benc = bincode::serialize(&block).unwrap();
        for base in [&enc, &benc] {
            for i in 0..base.len() {
                if i + 8 <= base.len() {
                    let mut m = base.clone();
                    m[i..i + 8].copy_from_slice(&u64::MAX.to_le_bytes());
                    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let _: Result<Transaction, _> = bincode::deserialize(&m);
                        let _: Result<Block, _> = bincode::deserialize(&m);
                    }));
                    assert!(r.is_ok(), "decode panicked on MAX prefix at {i}");
                }
            }
            for n in 0..base.len() {
                let t = base[..n].to_vec();
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _: Result<Transaction, _> = bincode::deserialize(&t);
                    let _: Result<Block, _> = bincode::deserialize(&t);
                }));
                assert!(r.is_ok(), "decode panicked on truncation len {n}");
            }
        }
    }
}

// ==================== §5 M3: shared sequencer + two-phase atomicity + L2 lane ====================
//
// SCOPE (§5 M3 core). Dynamic split/merge is OUT of scope (non-deterministic by
// load; `DynamicShardManager` wiring untouched). `Block` / `Transaction` gain NO
// new fields (bincode 1.3 compat): every new record rides the pre-existing
// `Block.cross_shard_out: Vec<CrossShardMessage>` field, and the ack/bounce
// kinds below reuse the pre-existing `CrossShardMessage` fields
// (`source_shard` / `target_shard` direction + `bounce` / `bounced` flags).
//
// 1. SHARED SEQUENCER (consensus-adjacent, deterministic). The old
//    `SharedSequencer::sequence_message` counter was Sim-only (call order =
//    whatever the simulator did). The consensus-adjacent rule is
//    [`SharedSequencer::assign_from_block`]: sequence numbers are assigned from
//    COMMITTED block content only, in a global order keyed by
//    `(source_height, source_shard, msg_id)`. Any node replaying the same
//    finalized blocks in `(height, shard)` order derives identical
//    `(CrossShardKey -> seq)` assignments. No wall-clock, no operator input,
//    no network read participates in the ordering rule. The watermark
//    (`note_finalized`) advances only from finalized block content.
// 2. TWO-PHASE ATOMICITY (ack/bounce). M2's source-debit is one-way. M3 adds:
//      * ACK: the target shard, having committed the consumption record,
//        publishes an ack (reversed direction, `bounced == false`). The source
//        shard commits the ack record; the transfer is then COMPLETE and no
//        bounce for it may ever be admitted.
//      * BOUNCE: when the target never consumes (failure/timeout), the source
//        shard commits a bounce-back record after a deterministic TIMEOUT
//        measured in HEIGHTS ([`CROSS_SHARD_TIMEOUT_HEIGHTS`]), refunding
//        `tx.amount` to `tx.from`. A bounce is valid iff the matching outbound
//        is committed on this chain, no ack/bounce for the same transaction
//        completed yet, and `at_height >= produce_height + TIMEOUT`.
//    Replay protection covers acks/bounces under the same [`CrossShardKey`]
//    discipline (each has a distinct `msg_id`), PLUS a per-transaction
//    completion guard (same `tx` hash can complete at most once even across
//    differing carrier hashes) enforced by the runtime.
//    KIND ENCODING (no new fields): with `S = tx.source_shard, T = tx.target_shard`
//      * transfer: `source == S && target == T && !bounced` (proof required);
//      * ack:      `source == T && target == S && !bounced && !bounce` (no proof;
//                  linkage to a committed outbound required);
//      * bounce:   `source == T && target == S && bounced && !bounce` (no proof;
//                  linkage + timeout required).
//    Control records (ack/bounce) MUST carry no Merkle proof: the state engine
//    credits any proof-carrying inbound to `tx.to`, so a proof-carrying
//    reversed-direction record would mint on the source shard. The runtime
//    refuses them (fail closed) and the engine skips proof-less records, which
//    is what makes the refund path safe without a state-engine change.
// 3. L2 SEQUENCING INTERFACE ([`L2Sequencer`] / [`L2Batch`]): a minimal,
//    documented append-only ordering service. Admission rules (contiguous
//    indices, payload-hash binding, signature verification) + ordering
//    guarantee (`(l2_id, batch_index)` FIFO). DA/bridging of L2 state is OUT
//    of scope: this is interface + ordering only; batch transactions reach
//    blocks through normal admission (no new `Block` fields).

/// Timeout for a cross-shard transfer, in SOURCE-shard heights.
///
/// A bounce-back refund for a transaction produced at source height `Hp` may
/// be committed in a source block at height `H` iff `H >= Hp + TIMEOUT`. Pure
/// heights, never seconds: every node applying the same source chain agrees
/// on `Hp` (the height that committed the outbound) and on `H` (the block
/// being validated), so the timeout verdict is deterministic. 64 heights is
/// far beyond any healthy consume+ack latency (2 heights in the honest flow)
/// and short enough that a failed transfer refunds promptly.
pub const CROSS_SHARD_TIMEOUT_HEIGHTS: u64 = 64;

/// True when a bounce-back for an outbound produced at `produce_height` may be
/// committed at `at_height`. Pure function of heights (no clock, no state).
pub fn bounce_eligible(produce_height: u64, at_height: u64) -> bool {
    at_height >= produce_height.saturating_add(CROSS_SHARD_TIMEOUT_HEIGHTS)
}

/// The M3 kind of a [`CrossShardMessage`], derived from its pre-existing
/// fields (direction relative to the carried transaction + flags).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrossShardKind {
    /// Value transfer `S -> T` (proof required).
    Transfer,
    /// Consumption receipt `T -> S` (linkage required, no value movement).
    Ack,
    /// Refund claim `T -> S` (linkage + timeout required, refunds `tx.from`).
    Bounce,
    /// Anything else (not committable; fail closed).
    Unknown,
}

impl CrossShardMessage {
    /// Classify this message without touching its bytes.
    pub fn kind(&self) -> CrossShardKind {
        let s = self.tx.source_shard;
        let t = self.tx.target_shard;
        if s == t {
            return CrossShardKind::Unknown;
        }
        match (self.source_shard, self.target_shard, self.bounced, self.bounce) {
            (a, b, false, _) if a == s && b == t => CrossShardKind::Transfer,
            (a, b, false, false) if a == t && b == s => CrossShardKind::Ack,
            (a, b, true, false) if a == t && b == s => CrossShardKind::Bounce,
            _ => CrossShardKind::Unknown,
        }
    }

    /// True for a value transfer `S -> T` (the only M2 kind).
    pub fn is_transfer(&self) -> bool {
        self.kind() == CrossShardKind::Transfer
    }

    /// True for a consumption receipt `T -> S`.
    pub fn is_ack(&self) -> bool {
        self.kind() == CrossShardKind::Ack
    }

    /// True for a refund claim `T -> S`.
    pub fn is_bounce(&self) -> bool {
        self.kind() == CrossShardKind::Bounce
    }

    /// Build the ack for a consumed transfer. The ack travels `T -> S`
    /// carrying the SAME transaction (linkage is by `tx` hash), with
    /// `consumed_in` naming the target block that committed the consumption
    /// (part of the deterministic `msg_id`, identical on every node that
    /// applied the same target block). No proof: the engine skips proof-less
    /// inbound records, and the source validates by linkage, not by proof.
    pub fn new_ack(tx: Transaction, consumed_in: [u8; 32]) -> Self {
        let mut m = Self::new(
            tx.target_shard,
            tx.source_shard,
            tx,
            [0u8; 32],
            consumed_in,
            None,
        );
        m.bounce = false;
        m.bounced = false;
        m.source_balance = 0;
        m
    }

    /// Build the bounce-back refund claim for a transfer that never completed.
    /// Same shape as an ack but `bounced == true`; the source shard credits
    /// `tx.amount` back to `tx.from` when it commits this record (after the
    /// timeout rule passes). `refunded_at` should be the source head the
    /// refunding block extends (deterministic per height). No proof, same
    /// reason as [`Self::new_ack`].
    pub fn new_bounce(tx: Transaction, refunded_at: [u8; 32]) -> Self {
        let mut m = Self::new(
            tx.target_shard,
            tx.source_shard,
            tx,
            [0u8; 32],
            refunded_at,
            None,
        );
        m.bounce = false;
        m.bounced = true;
        m.source_balance = 0;
        m
    }
}

impl SharedSequencer {
    /// Deterministically assign global sequence numbers to every cross-shard
    /// record in a FINALIZED block.
    ///
    /// ORDERING RULE (the M3 contract): records sort by
    /// `(block.height, msg.source_shard, msg.msg_id)` — source height first
    /// (causality across shards), then source shard (cross-shard tie-break),
    /// then message id (within-block tie-break). Each unseen
    /// [`CrossShardKey`] takes `next_sequence()` and the counter advances;
    /// already-sequenced keys keep their number (idempotent replay). Feed
    /// blocks in `(height, shard)` order and any two nodes derive identical
    /// assignments from identical chains. Returns the assignments in global
    /// order.
    pub fn assign_from_block(&mut self, block: &Block) -> Vec<(u64, CrossShardKey)> {
        let mut keys: Vec<CrossShardKey> = block.cross_shard_out.iter().map(CrossShardKey::of).collect();
        // Total order, independent of the carrier vec's order (KV enumeration
        // order must never leak into consensus-adjacent numbering).
        keys.sort_by(|a, b| {
            // `block.height` is common; order by (source_shard, msg_id, carrier).
            (a.source_shard, a.msg_id, a.finalized_in_block)
                .cmp(&(b.source_shard, b.msg_id, b.finalized_in_block))
        });
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            let seq = match self.sequence_of(&key) {
                Some(s) => s,
                None => {
                    let s = self.current_sequence;
                    self.current_sequence += 1;
                    // Keep the legacy schedule vector consistent (Sim reads it).
                    if let Some(msg) = block
                        .cross_shard_out
                        .iter()
                        .find(|m| CrossShardKey::of(m) == key)
                    {
                        self.scheduled_cross_shard.push((s, msg.clone()));
                    }
                    s
                }
            };
            out.push((seq, key));
        }
        // The watermark is finalized-block content only: the highest sequenced
        // source height per shard, advanced monotonically here.
        let wm = self.watermark.entry(block.shard_id).or_insert(0);
        if block.height > *wm {
            *wm = block.height;
        }
        out
    }

    /// The sequence number of an already-sequenced message, if any.
    pub fn sequence_of(&self, key: &CrossShardKey) -> Option<u64> {
        self.scheduled_cross_shard
            .iter()
            .find(|(_, m)| CrossShardKey::of(m) == *key)
            .map(|(s, _)| *s)
    }

    /// The next sequence number to be assigned.
    pub fn next_sequence(&self) -> u64 {
        self.current_sequence
    }

    /// Highest sequenced source height per shard (the sequencer watermark).
    /// Advanced ONLY by [`Self::assign_from_block`] / [`Self::note_finalized`]
    /// on finalized blocks — never by time or by operator action.
    pub fn watermark(&self) -> &std::collections::BTreeMap<ShardId, u64> {
        &self.watermark
    }

    /// Advance the watermark for a finalized `(shard, height)` without
    /// assigning numbers (e.g. a finalized block with no cross-shard records).
    /// Monotonic: a stale height never moves it backwards.
    pub fn note_finalized(&mut self, source_shard: ShardId, height: u64) {
        let wm = self.watermark.entry(source_shard).or_insert(0);
        if height > *wm {
            *wm = height;
        }
    }
}

// ==================== L2 sequencing interface ====================
//
// A minimal append-only ordering service through which an EXTERNAL L2 submits
// ordered batches for inclusion.
//
// * APPEND-ONLY: per L2, `batch_index` must be exactly the next expected
//   index — no gaps, no overwrites, no reordering. A batch that skips an
//   index is rejected until the missing one arrives; a duplicate index is
//   rejected.
// * ADMISSION: every batch binds its transactions by `payload_hash`
//   (recomputed and compared), every transaction signature must verify, and
//   batches are size-capped. Nothing unverifiable is ever queued.
// * ORDERING GUARANTEE: [`L2Sequencer::batches_for_inclusion`] yields pending
//   batches in canonical `(l2_id, batch_index)` order — FIFO per L2,
//   deterministic across L2s. A proposer pulling in that order gives every
//   node the same L2-derived prefix for the same pending set.
// * OUT OF SCOPE (explicit): DA/bridging of L2 state, execution of L2
//   semantics, and any `Block` format change. Batch transactions are ordinary
//   [`Transaction`]s and reach blocks through normal admission; this is
//   interface + ordering guarantees only.

/// Maximum transactions in one L2 batch (anti-DoS bound on a single submit).
pub const L2_MAX_TXS_PER_BATCH: usize = 1024;

/// One externally-submitted L2 batch: an ordered list of transactions with a
/// binding payload hash. Never embedded in `Block` (no format change); the
/// sequencer only orders batches, and inclusion reuses normal tx admission.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct L2Batch {
    /// Which L2 this batch belongs to (namespaces the index sequence).
    pub l2_id: u32,
    /// Append-only position within `l2_id` (0-based, contiguous).
    pub batch_index: u64,
    /// The transactions, in submission order (inclusion must preserve it).
    pub txs: Vec<Transaction>,
    /// Binding commitment over `txs` (recomputed and checked at admission).
    pub payload_hash: [u8; 32],
}

impl L2Batch {
    /// Build a batch, computing the binding payload hash.
    pub fn new(l2_id: u32, batch_index: u64, txs: Vec<Transaction>) -> Self {
        let payload_hash = Self::payload_hash_of(&txs);
        Self { l2_id, batch_index, txs, payload_hash }
    }

    /// The binding commitment: `sha256(count || tx_hash_0 || tx_hash_1 || ..)`.
    /// Order-sensitive, so a reordered batch has a different hash.
    pub fn payload_hash_of(txs: &[Transaction]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"STELLEREUM_L2_BATCH_V1");
        hasher.update((txs.len() as u64).to_be_bytes());
        for t in txs {
            hasher.update(t.compute_tx_hash());
        }
        hasher.finalize().into()
    }

    /// Admission verification: non-empty, size-capped, hash-bound, and every
    /// transaction signature verifies. Fails closed on any violation.
    pub fn verify(&self) -> Result<(), String> {
        if self.txs.is_empty() {
            return Err("L2 batch carries no transactions".to_string());
        }
        if self.txs.len() > L2_MAX_TXS_PER_BATCH {
            return Err(format!(
                "L2 batch of {} txs exceeds the cap of {}",
                self.txs.len(),
                L2_MAX_TXS_PER_BATCH
            ));
        }
        if self.payload_hash != Self::payload_hash_of(&self.txs) {
            return Err("L2 batch payload hash does not bind its transactions".to_string());
        }
        if !Transaction::verify_signatures_batch(&self.txs) {
            return Err("L2 batch contains a bad transaction signature".to_string());
        }
        Ok(())
    }
}

/// Append-only per-L2 batch sequencer. All state is a pure function of the
/// submitted batches (no clock, no network); ordering is the canonical
/// `(l2_id, batch_index)` order.
#[derive(Clone, Debug, Default)]
pub struct L2Sequencer {
    /// Next expected `batch_index` per L2 (starts at 0).
    expected: HashMap<u32, u64>,
    /// Admitted but not yet included, in canonical order.
    pending: std::collections::BTreeMap<(u32, u64), L2Batch>,
    /// Highest included `batch_index` per L2 (pruning watermark).
    included_through: HashMap<u32, u64>,
}

impl L2Sequencer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Submit one batch. Accepts it iff it verifies AND its index is exactly
    /// the next expected for its L2 (append-only: gaps and duplicates are
    /// rejected, never queued).
    pub fn submit_batch(&mut self, batch: L2Batch) -> Result<(), String> {
        batch.verify()?;
        let next = self.expected.get(&batch.l2_id).copied().unwrap_or(0);
        if batch.batch_index != next {
            return Err(format!(
                "L2 {} batch index {} is not the next expected ({next}): gaps and duplicates are rejected",
                batch.l2_id, batch.batch_index
            ));
        }
        self.pending.insert((batch.l2_id, batch.batch_index), batch.clone());
        self.expected.insert(batch.l2_id, next + 1);
        Ok(())
    }

    /// The next expected batch index for an L2 (0 for a never-seen L2).
    pub fn expected_index(&self, l2_id: u32) -> u64 {
        self.expected.get(&l2_id).copied().unwrap_or(0)
    }

    /// Pending batches in canonical inclusion order (`(l2_id, batch_index)`
    /// ascending), up to `limit`. A proposer taking a prefix of this list
    /// preserves the ordering guarantee.
    pub fn batches_for_inclusion(&self, limit: usize) -> Vec<L2Batch> {
        self.pending.values().take(limit).cloned().collect()
    }

    /// Number of admitted-but-unincluded batches.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Mark batches through `through_index` (inclusive) for `l2_id` as
    /// included: drops them from pending and advances the prune watermark.
    /// Only moves forward (a stale mark is a no-op, never a rewind).
    pub fn mark_included(&mut self, l2_id: u32, through_index: u64) {
        let cur = self.included_through.get(&l2_id).copied().unwrap_or(0);
        // `through_index` is inclusive; the watermark counts included batches.
        let want = through_index.saturating_add(1);
        if want <= cur {
            return;
        }
        self.included_through.insert(l2_id, want);
        self.pending.retain(|(id, idx), _| !(*id == l2_id && *idx <= through_index));
    }

    /// How many batches of `l2_id` have been marked included (0 if none).
    pub fn included_count(&self, l2_id: u32) -> u64 {
        self.included_through.get(&l2_id).copied().unwrap_or(0)
    }
}
