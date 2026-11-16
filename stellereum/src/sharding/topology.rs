use super::Transaction;
use crate::cell::PatriciaTrie;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub type ShardId = u32;
pub const MASTERCHAIN_SHARD: ShardId = 0;
pub const BASE_WORKCHAIN_SHARD_INITIAL: ShardId = 1;

/// Environment variable listing the shards a single process runs, comma
/// separated (e.g. `STELL_SHARDS=0,1`). Unset/empty keeps the process on the
/// one shard it was started with, which is the pre-sharding behaviour.
pub const SHARD_REGISTRY_ENV: &str = "STELL_SHARDS";

/// Escape hatch that re-allows a non-canonical shard registry for local
/// soak/tests only. One env var, no new config formats. Public launch is
/// single-shard canonical; the hatch is loudly logged at boot (see `main.rs`)
/// and never documented for operators.
pub const EXPERIMENTAL_SHARDS_ENV: &str = "STELL_EXPERIMENTAL_SHARDS";

/// Freeze doc pinned by the boot-guard refusal text below.
pub const WORKCHAIN_FREEZE_DOC: &str = "docs/PUBLIC_TESTNET_CODE_GAPS.md §1";

/// True only when `STELL_EXPERIMENTAL_SHARDS=1` (exact match). Anything else
/// (unset, empty, `0`, `true`, ...) is disabled — fail-closed.
pub fn experimental_shards_hatch_enabled() -> bool {
    matches!(std::env::var(EXPERIMENTAL_SHARDS_ENV).as_deref(), Ok("1"))
}

/// Boot guard: single-shard `{0}` canonical for public launch (protocol
/// freeze, see [`WORKCHAIN_FREEZE_DOC`]).
///
/// * `Ok(())` — registry is exactly `{MASTERCHAIN_SHARD}` (default path,
///   byte-identical), or the experimental hatch is enabled AND the registry
///   is a VALID configured set (see [`ShardRegistry::validate`]: every
///   multi-shard set names the masterchain and stays within the shard cap).
/// * `Err(msg)` — any other registry (`STELL_SHARDS != {0}`, i.e. any
///   multishard request or any non-canonical single shard) without the hatch,
///   or an INVALID registry (missing masterchain, over the cap) even WITH the
///   hatch: the hatch allows the CONFIGURED set, not just any set.
///   The message names the freeze doc, both env vars, and the recovery.
///
/// Pure except for the hatch env read; use
/// [`check_workchain_boot_guard_with_hatch`] for deterministic tests.
pub fn check_workchain_boot_guard(registry: &ShardRegistry) -> Result<(), String> {
    check_workchain_boot_guard_with_hatch(registry, experimental_shards_hatch_enabled())
}

/// Deterministic core of [`check_workchain_boot_guard`]: `hatch` is the
/// already-resolved `STELL_EXPERIMENTAL_SHARDS=1` flag.
///
/// The hatch allows the CONFIGURED set, not just any set: a registry that
/// fails [`ShardRegistry::validate`] (multi-shard without the masterchain,
/// or over the shard cap) is refused even with the hatch set, fail-closed.
pub fn check_workchain_boot_guard_with_hatch(
    registry: &ShardRegistry,
    hatch: bool,
) -> Result<(), String> {
    if *registry == ShardRegistry::single() {
        return Ok(());
    }
    registry.validate()?;
    if hatch {
        return Ok(());
    }
    Err(format!(
        "REFUSING startup: STELL_SHARDS {{{}}} is not single-shard canonical {{0}} \
         (protocol freeze {doc}). Multishard boot is parked until live-soak + flag-day. \
         For local soak/tests only, set {hatch_env}=1 (loudly logged). \
         Requested shards: {{{}}}",
        MASTERCHAIN_SHARD,
        registry
            .ids()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(","),
        doc = WORKCHAIN_FREEZE_DOC,
        hatch_env = EXPERIMENTAL_SHARDS_ENV,
    ))
}

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
    ///
    /// LENIENT (legacy): unparsable entries are skipped and duplicates
    /// collapse, so garbage can silently shrink to the default. New boot code
    /// must use [`ShardRegistry::parse_list`] (fail-closed) for an explicitly
    /// set `STELL_SHARDS`; this stays for the unset/empty default path and for
    /// existing callers.
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

    /// Parse an explicitly set `STELL_SHARDS` value, fail-closed.
    ///
    /// * empty value / empty entry (`"0,,1"`, whitespace-only) → `Err`;
    /// * an entry that is not a shard id (`"0,abc"`) → `Err` naming it;
    /// * a duplicate id (`"0,1,1"`) → `Err` naming it (the `BTreeSet`
    ///   backing would otherwise collapse it silently);
    /// * more than [`MAX_SHARDS`] ids → `Err` naming the cap;
    /// * a MULTI-shard set without [`MASTERCHAIN_SHARD`] → `Err` (every
    ///   configured process runs the masterchain; a lone non-masterchain
    ///   single shard stays the boot guard's business, not a parse error).
    ///
    /// On success the ids are unique and iterate in ascending order (the
    /// `BTreeSet` backing), so the registry IS the sorted N-shard set.
    pub fn parse_list(raw: &str) -> Result<Self, String> {
        if raw.trim().is_empty() {
            return Err(format!(
                "REFUSING startup: {env} is empty (set {env}=<id>[,<id>...], e.g. {env}=0,1,2, or unset it for the canonical single-shard {{0}})",
                env = SHARD_REGISTRY_ENV,
            ));
        }
        let mut ids: Vec<ShardId> = Vec::new();
        for (i, tok) in raw.split(',').enumerate() {
            let t = tok.trim();
            if t.is_empty() {
                return Err(format!(
                    "REFUSING startup: {env}={raw:?} has an empty entry at position {i} (every entry must be a shard id)",
                    env = SHARD_REGISTRY_ENV,
                ));
            }
            let id: ShardId = t.parse().map_err(|_| {
                format!(
                    "REFUSING startup: {env}={raw:?} has an invalid shard id `{t}` at position {i} (every entry must be a non-negative integer)",
                    env = SHARD_REGISTRY_ENV,
                )
            })?;
            if ids.contains(&id) {
                return Err(format!(
                    "REFUSING startup: {env}={raw:?} lists shard id {id} twice (ids must be unique)",
                    env = SHARD_REGISTRY_ENV,
                ));
            }
            ids.push(id);
        }
        let registry = Self::from_ids(ids);
        registry.validate()?;
        Ok(registry)
    }

    /// Fail-closed config check for a registry, independent of the hatch.
    ///
    /// * more than [`MAX_SHARDS`] shards → `Err` (the topology hard cap:
    ///   the process must never configure more shards than the network can
    ///   hold);
    /// * a MULTI-shard set without [`MASTERCHAIN_SHARD`] → `Err` (every
    ///   configured process runs the masterchain; cross-shard proofs anchor
    ///   to it).
    ///
    /// A single non-masterchain shard (`{1}`) PASSES: it is non-canonical but
    /// not malformed — refusing it is the boot guard's freeze business (which
    /// still refuses it without the hatch), and the pinned guard tests cover
    /// exactly that.
    pub fn validate(&self) -> Result<(), String> {
        if self.shards.len() > MAX_SHARDS {
            return Err(format!(
                "REFUSING startup: {env} configures {} shards {{{}}} — over the shard cap {cap} (reduce to at most {cap} comma-separated ids)",
                self.shards.len(),
                self.ids()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
                env = SHARD_REGISTRY_ENV,
                cap = MAX_SHARDS,
            ));
        }
        if self.is_sharded() && !self.shards.contains(&MASTERCHAIN_SHARD) {
            return Err(format!(
                "REFUSING startup: {env} configures {{{}}} without the masterchain shard {master} (every multi-shard process must include {master})",
                self.ids()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
                env = SHARD_REGISTRY_ENV,
                master = MASTERCHAIN_SHARD,
            ));
        }
        Ok(())
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

/// The process-wide MASTERCHAIN staking ledger, shared with every workchain
/// runtime of the same process.
///
/// The masterchain OWNS the staking registry: a bond, an unbond and a slash
/// are masterchain transactions, and only the masterchain's ledger is committed
/// chain state. A workchain deliberately keeps NO registry of its own (its
/// genesis seeds an empty ledger — see `runtime::fund_shard_genesis`), because
/// a second registry would be a second opinion about who the validators are,
/// and the validator set decides who proposes.
///
/// Sharing the master's ledger is therefore the ONLY way a workchain can learn
/// about a rotation: without it the workchain derived its set from its own
/// (empty) ledger, kept the config-defined set forever, and the audit's
/// "validator set gap" was exactly that — a rotation on the masterchain that
/// never reached the workchains.
pub type MasterStakingLedger = std::sync::Arc<tokio::sync::RwLock<crate::staking::StakingLedger>>;

/// Which staking registry defines a shard's consensus validator set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidatorSetSource {
    /// The shard's OWN ledger. Only the masterchain has one: it is the
    /// registry, and it is committed by the masterchain's own blocks.
    Local,
    /// The MASTERCHAIN's ledger, shared process-wide. Every workchain reads
    /// it, so a masterchain rotation is transmitted to the workchain at the
    /// next height boundary instead of being stranded on the masterchain.
    Masterchain,
}

impl ValidatorSetSource {
    /// The registry that defines the set for `shard_id`.
    pub fn for_shard(shard_id: ShardId) -> Self {
        if shard_id == MASTERCHAIN_SHARD {
            Self::Local
        } else {
            Self::Masterchain
        }
    }

    /// True when the shard takes the masterchain's ledger.
    pub fn uses_masterchain(self) -> bool {
        matches!(self, Self::Masterchain)
    }
}

/// True when `shard_id` is a workchain (any shard but the masterchain).
///
/// A workchain has no staking registry of its own: its consensus validator set
/// comes from the masterchain's ledger (see [`ValidatorSetSource`]).
pub fn is_workchain_shard(shard_id: ShardId) -> bool {
    shard_id != MASTERCHAIN_SHARD
}

/// The height at which a freshly derived validator set takes effect.
///
/// The set that signs height H is the set derived from the registry as of H,
/// so a rotation is installed for H+1 — the height boundary. Every node
/// derives the same set from the same registry, so the switch is a pure
/// function of the chain, not of local timing.
pub fn validator_set_adoption_height(current_height: u64) -> u64 {
    current_height.saturating_add(1)
}

/// Which shard a transaction is destined for. In single-shard mode this
/// predicate is never consulted; it exists so a sharded producer and validator
/// agree on which transactions belong to which shard. A transaction targets
/// the block shard named by its `target_shard` field.
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
/// value through a committed [`super::CrossShardMessage`] consumption record instead.
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

pub const SHARD_SPLIT_LOAD_THRESHOLD: u64 = 500; // txs per block window triggers auto-split
pub const SHARD_MERGE_LOAD_THRESHOLD: u64 = 50; // low load triggers auto-merge

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

    /// Check whether an account address falls within this shard's address prefix.
    ///
    /// The routing prefix is the top `prefix_len` bits of the address's
    /// leading 8 bytes — the same definition TON uses for workchain shard
    /// prefixes. The masterchain owns nothing by prefix: it is addressed
    /// EXPLICITLY, in the `-1:<addr>` form (see [`ShardAddress`]).
    pub fn contains_address(&self, address: &[u8; 32]) -> bool {
        if self.shard_id == MASTERCHAIN_SHARD {
            return false;
        }
        if self.prefix_len == 0 {
            return true;
        }
        let len = u64::from(self.prefix_len).min(64);
        let shift = 64 - len;
        let mask = if shift >= 64 { 0 } else { !0u64 << shift };
        let addr_prefix = u64::from_be_bytes(address[..8].try_into().unwrap());
        (addr_prefix & mask) == (self.prefix & mask)
    }
}

/// Dynamic Infinite Sharding Manager
///
/// The DECISION engine of the sharding architecture: it owns the shard set,
/// the routing-prefix arithmetic and the shard-id allocation. The account
/// ownership and the executable split/merge transitions live in
/// [`ShardTopology`], which drives this manager.
#[derive(Clone, Debug, Default)]
pub struct DynamicShardManager {
    /// The active shard set. A `BTreeMap`, so iteration (and therefore the
    /// routing tie-break) is deterministic across nodes.
    pub shards: BTreeMap<ShardId, ShardDescriptor>,
    /// The next shard id to hand out. Ids are never reused.
    pub next_shard_id: ShardId,
}

impl DynamicShardManager {
    pub fn new() -> Self {
        let mut shards = BTreeMap::new();
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

    /// THE ROUTING RULE, over the shard set.
    ///
    /// The MOST SPECIFIC matching shard wins (longest routing prefix),
    /// tie-broken by the smallest shard id — so the rule is a pure function
    /// of the shard set and two nodes with the same topology route an
    /// address to the same shard. The masterchain is never a candidate here:
    /// it is addressed EXPLICITLY (see [`ShardAddress`]).
    pub fn route_address(&self, address: &[u8; 32]) -> ShardId {
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
        match best {
            Some(s) => s.shard_id,
            // No workchain shard matches: fall back to the LOWEST workchain
            // shard id (deterministic), or the masterchain if the network
            // has no workchain shard at all.
            None => self
                .shards
                .keys()
                .copied()
                .filter(|id| *id != MASTERCHAIN_SHARD)
                .min()
                .unwrap_or(MASTERCHAIN_SHARD),
        }
    }

    pub fn record_tx_load(&mut self, shard_id: ShardId, tx_count: u64) {
        if let Some(s) = self.shards.get_mut(&shard_id) {
            s.tx_load += tx_count;
        }
    }

    /// Check and trigger automatic shard split if load exceeds threshold
    ///
    /// The manager owns the PREFIX ARITHMETIC and the ID ALLOCATION; the
    /// account re-assignment that makes the split real is performed by
    /// [`ShardTopology::check_and_split`], which drives this function.
    pub fn check_and_split(
        &mut self,
        shard_id: ShardId,
    ) -> Option<(ShardDescriptor, ShardDescriptor)> {
        let s = self.shards.get(&shard_id)?;
        if shard_id == MASTERCHAIN_SHARD
            || s.tx_load < SHARD_SPLIT_LOAD_THRESHOLD
            || s.prefix_len >= MAX_PREFIX_BITS
        {
            return None;
        }
        // The shard cap is a HARD cap: the topology never grows past it.
        if self.shards.len() >= MAX_SHARDS {
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

        // Ids are NEVER reused: a late cross-shard message addressed to a
        // retired shard id can then never be mistaken for the merged shard.
        let parent_id = self.next_shard_id;
        self.next_shard_id += 1;

        let parent = ShardDescriptor::new(parent_id, s0.workchain_id, parent_prefix, new_len);
        self.shards.insert(parent_id, parent.clone());

        Some(parent)
    }
}

// ===========================================================================
// Shard topology: the executable split/merge path and the published
// address→shard rule.
//
// HONESTY NOTE (read before quoting any sharding claim):
//
//   * DEMONSTRATED: the split/merge state machine, the account re-assignment
//     rule, the trie migration procedure and the routing rule are exercised
//     by a deterministic integration test over a synthetic account set
//     (`tests/sharding_topology_tests.rs`) and by `cargo test --lib sharding`.
//   * DESIGNED, NOT DEMONSTRATED: a LIVE-NETWORK split. No split has been
//     performed on the testnet or on mainnet; the split path has never been
//     driven by a live consensus event.
//
// The thresholds below are PUBLISHED constants, not folklore.
// ===========================================================================

/// Minimum number of accounts a shard must own before the topology is
/// willing to SPLIT it.
///
/// A shard below this size does not pay for its own consensus overhead, so
/// the topology keeps it as one shard. It is also the second half of the
/// anti-oscillation rule: the load thresholds (split at >= 500, merge at
/// <= 50) are disjoint, so a shard can never be simultaneously split- and
/// merge-eligible.
pub const MIN_ACCOUNTS_PER_SHARD: u64 = 100;

/// Maximum number of shards the topology will ever hold, masterchain
/// included.
///
/// HONESTY: the prefix-routing scheme admits a theoretical space of
/// [`MAX_WORKCHAIN_SHARD_SPACE`] (2^60) workchain shards. That is the
/// ADVERTISED ceiling, not a shipped capacity. What this network SHIPS is a
/// hard cap of 16 shards, enforced by [`ShardTopology::check_and_split`],
/// which refuses to grow past it. TON draws the same line publicly (it
/// advertises 2^60 shards and ships a cap of 16): the advertised number is
/// the address space, the cap is the capacity.
pub const MAX_SHARDS: usize = 16;

/// The theoretical workchain shard space of the prefix-routing scheme:
/// 2^60 shards. ADVERTISED, NOT SHIPPED — see [`MAX_SHARDS`].
pub const MAX_WORKCHAIN_SHARD_SPACE: u64 = 1u64 << 60;

/// Maximum routing-prefix length, in bits of the address.
///
/// 60 bits is the width of the theoretical shard space (2^60): a longer
/// prefix cannot name a distinct shard, so the topology refuses to split
/// past it.
pub const MAX_PREFIX_BITS: u8 = 60;

/// Identifier of the routing rule, published so a client can assert which
/// rule a node implements.
pub const ROUTING_RULE_ID: &str = "workchain-prefix-v1";

/// The routing rule, in words. This is the SINGLE SOURCE OF TRUTH: the RPC
/// layer (`stell_estimateFee`, `stell_runGetMethod`), the SVM's cross-shard
/// routing and the topology itself all resolve addresses through it.
///
/// * The MASTERCHAIN is addressed EXPLICITLY, in the `-1:<addr>` form (or by
///   naming shard 0). A bare 32-byte address NEVER routes to the masterchain.
/// * A WORKCHAIN address routes to the shard whose routing prefix is the
///   LONGEST prefix of the address's leading bits. Ties are broken by the
///   SMALLEST shard id, so the rule is a pure function of the topology.
/// * A split EXTENDS the prefix by one bit (the address's bit at the new
///   depth decides the child), a merge REMOVES the deepest bit and restores
///   the parent prefix. The routing rule therefore changes only at the
///   transition, never continuously.
pub const ROUTING_RULE: &str = "masterchain only via the -1: address form; \
workchain addresses route to the shard with the LONGEST matching routing \
prefix (ties broken by the smallest shard id); a split adds one routing bit, \
a merge removes the deepest one";

/// The address form that names the masterchain.
pub const MASTERCHAIN_ADDRESS_FORM: &str = "-1:<addr>";

/// The routing bit at index `bit` of an address.
///
/// `bit` is 0-based and counts from the MOST significant bit of byte 0 —
/// the same order as the routing prefix (see [`address_prefix_word`]).
///
/// Only the first 8 bytes are addressable by the routing prefix (the prefix
/// is a `u64`), so a `bit` of 64 or more reads as 0.
pub fn address_prefix_bit(address: &[u8; 32], bit: u8) -> u8 {
    let byte = (bit / 8) as usize;
    if byte >= 8 {
        return 0;
    }
    let shift = 7 - (bit % 8);
    (address[byte] >> shift) & 1
}

/// The top `prefix_len` bits of an address, as a big-endian `u64`.
///
/// The routing prefix of a shard is the top `prefix_len` bits of the
/// address's leading 8 bytes — the same definition TON uses for its
/// workchain shard prefixes.
///
/// The result is LEFT-ALIGNED, exactly like [`ShardDescriptor::prefix`]: the
/// meaningful bits sit at positions `63 ..= 64 - prefix_len` and the rest
/// are zero. Two descriptors with the same prefix word and the same prefix
/// length therefore cover the same address range.
pub fn address_prefix_word(address: &[u8; 32], prefix_len: u8) -> u64 {
    let word = u64::from_be_bytes(address[..8].try_into().unwrap());
    let len = u64::from(prefix_len).min(64);
    if len == 0 {
        return 0;
    }
    let shift = 64 - len;
    let mask = !0u64 << shift;
    word & mask
}

/// The bit at index `bit` (0-based, most-significant first) of a routing
/// prefix word.
pub(super) fn prefix_word_bit(prefix: u64, bit: u8) -> u8 {
    if bit >= 64 {
        return 0;
    }
    ((prefix >> (63 - bit)) & 1) as u8
}

/// True when two shard descriptors are SIBLINGS: they share every routing
/// bit but the deepest one, so they cover one parent range exactly.
fn are_siblings(a: &ShardDescriptor, b: &ShardDescriptor) -> bool {
    let len = a.prefix_len;
    if a.prefix_len != b.prefix_len || len == 0 {
        return false;
    }
    let deepest = len - 1;
    if prefix_word_bit(a.prefix, deepest) == prefix_word_bit(b.prefix, deepest) {
        return false;
    }
    // The higher bits (0..deepest) must agree.
    let hi_shift = 64u32.saturating_sub(u32::from(deepest));
    if hi_shift >= 64 {
        return true;
    }
    let mask = !0u64 << hi_shift;
    (a.prefix & mask) == (b.prefix & mask)
}

/// An address together with the chain it is addressed ON.
///
/// The distinction is load-bearing: a bare 32-byte address is a WORKCHAIN
/// address (it routes by prefix), while the masterchain form `-1:<addr>`
/// names the masterchain explicitly. A bare address NEVER routes to the
/// masterchain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ShardAddress {
    /// The masterchain (shard 0), addressed explicitly.
    Masterchain([u8; 32]),
    /// A workchain address, routed by prefix.
    Workchain([u8; 32]),
}

impl ShardAddress {
    /// The raw address bytes.
    pub fn bytes(&self) -> &[u8; 32] {
        match self {
            Self::Masterchain(a) | Self::Workchain(a) => a,
        }
    }

    /// The shard this address form names explicitly, if it names one.
    pub fn explicit_shard(&self) -> Option<ShardId> {
        match self {
            Self::Masterchain(_) => Some(MASTERCHAIN_SHARD),
            Self::Workchain(_) => None,
        }
    }

    /// Build an address from raw bytes and an optional explicit shard pin.
    ///
    /// `Some(MASTERCHAIN_SHARD)` means the caller wrote the masterchain form
    /// (`-1:<addr>` or `0:<addr>`); any other id is an explicit workchain
    /// pin, which the routing rule does not use but the RPC layer reports
    /// back to the caller.
    pub fn with_hint(address: [u8; 32], hint: Option<ShardId>) -> Self {
        match hint {
            Some(MASTERCHAIN_SHARD) => Self::Masterchain(address),
            _ => Self::Workchain(address),
        }
    }
}

/// Split a TON-style `<chain>:<address>` string into the shard it names and
/// the address text.
///
/// * `-1:` -> the masterchain (shard 0)
/// * `0:`  -> the masterchain as well (shard 0 IS the masterchain id)
/// * `N:`  -> workchain shard N, named explicitly
///
/// The text after the colon is returned unchanged; the caller parses it with
/// its own address decoder.
pub fn split_shard_prefix(s: &str) -> (Option<ShardId>, &str) {
    let trimmed = s.trim();
    match trimmed.split_once(':') {
        Some((prefix, rest)) => {
            let shard = if prefix == "-1" {
                Some(MASTERCHAIN_SHARD)
            } else {
                prefix.trim().parse::<ShardId>().ok()
            };
            (shard, rest.trim())
        }
        None => (None, trimmed),
    }
}

/// One account as the topology owns it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardAccount {
    /// The account address (the routing key).
    pub address: [u8; 32],
    /// The account balance.
    pub balance: u64,
}

/// The digest of an account set: SHA-256 over the addresses in ascending
/// order. Two account sets with the same digest hold the same addresses.
pub fn account_set_digest(accounts: &[ShardAccount]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"STELL_SHARD_ACCOUNTS_V1");
    for a in accounts {
        h.update(a.address);
    }
    h.finalize().into()
}

/// Which way a migration runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationDirection {
    /// One shard becomes two.
    Split,
    /// Two shards become one.
    Merge,
}

/// The account-level migration a transition performs.
///
/// The plan is the DETERMINISTIC description of what moves: which accounts,
/// where they go, and the digests that let a verifier prove the move was the
/// one that was planned.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationPlan {
    /// Split or merge.
    pub direction: MigrationDirection,
    /// The shard(s) the state comes from.
    pub source_shards: Vec<ShardId>,
    /// The shard(s) the state goes to.
    pub target_shards: Vec<ShardId>,
    /// The routing bit that decides the destination (splits only).
    pub split_bit: u8,
    /// How many accounts move.
    pub account_count: usize,
    /// Digest of the source account set BEFORE the move.
    pub source_digest: [u8; 32],
    /// Digest of each target account set AFTER the move.
    pub target_digests: Vec<[u8; 32]>,
    /// Balance of the source shard(s) BEFORE the move.
    pub source_balance: u128,
    /// Balance of each target shard AFTER the move.
    pub target_balances: Vec<u128>,
}

impl MigrationPlan {
    /// True when the move conserves the total balance.
    pub fn balances_conserve(&self) -> bool {
        let moved: u128 = self.target_balances.iter().sum();
        moved == self.source_balance
    }
}

/// The explicit map from a trie key to the address that owns it.
///
/// The trie stores account leaves under the raw address, but it also stores
/// NAMESPACED derived keys: a contract's code and ABI manifest
/// (`sha256("STELL_CONTRACT_CODE" || addr)`), a token balance
/// (`sha256("STS_BAL" || token_id || holder)`) and a token's supply
/// (`sha256("STS_SUPPLY" || token_id)`). Those keys are hashes, so the owner
/// CANNOT be recovered from the key alone.
///
/// The migration therefore carries an EXPLICIT manifest, built by the shard
/// that owns the state. A trie key the manifest does not classify ABORTS the
/// migration ([`MigrationError::UnclassifiedKey`]): a split fails closed
/// instead of silently dropping state.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationManifest {
    /// `(trie key, owning address)`, sorted by trie key.
    pub entries: Vec<([u8; 32], [u8; 32])>,
}

impl MigrationManifest {
    /// An empty manifest.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Record that `key` is owned by `owner`. Re-recording a key replaces the
    /// owner (last write wins, deterministically).
    pub fn own(&mut self, key: [u8; 32], owner: [u8; 32]) {
        match self.entries.binary_search_by(|probe| probe.0.cmp(&key)) {
            Ok(i) => self.entries[i].1 = owner,
            Err(i) => self.entries.insert(i, (key, owner)),
        }
    }

    /// The owner of `key`, if the manifest classifies it.
    pub fn owner_of(&self, key: &[u8; 32]) -> Option<[u8; 32]> {
        self.entries
            .binary_search_by(|probe| probe.0.cmp(key))
            .ok()
            .map(|i| self.entries[i].1)
    }

    /// How many keys the manifest classifies.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the manifest classifies nothing.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The digest of the manifest: SHA-256 over the sorted (key, owner)
    /// pairs. Two manifests with the same digest classify the same keys the
    /// same way.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"STELL_MIGRATION_MANIFEST_V1");
        for (k, o) in &self.entries {
            h.update(k);
            h.update(o);
        }
        h.finalize().into()
    }
}

/// Why a migration step could not be carried out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MigrationError {
    /// The split bit is outside the address prefix.
    BadSplitBit(u8),
    /// A trie key the manifest does not classify. The migration ABORTS: a
    /// split never silently drops state.
    UnclassifiedKey([u8; 32]),
    /// The manifest names a key the trie does not hold.
    MissingKey([u8; 32]),
    /// The key landed in both children.
    DuplicateAssignment([u8; 32]),
    /// The key landed in neither child.
    LostKey([u8; 32]),
    /// The value of a migrated key changed.
    ValueChanged([u8; 32]),
    /// A child holds a key the parent never had.
    ForeignKey([u8; 32]),
    /// The balances did not conserve.
    BalanceMismatch {
        /// The balance the plan says must survive.
        expected: u128,
        /// The balance that was actually there.
        actual: u128,
    },
}

impl std::fmt::Display for MigrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadSplitBit(b) => write!(f, "split bit {b} is outside the address prefix"),
            Self::UnclassifiedKey(k) => {
                write!(
                    f,
                    "trie key {} is not classified by the manifest",
                    hex::encode(k)
                )
            }
            Self::MissingKey(k) => write!(f, "manifest key {} is not in the trie", hex::encode(k)),
            Self::DuplicateAssignment(k) => {
                write!(f, "trie key {} landed in both children", hex::encode(k))
            }
            Self::LostKey(k) => write!(f, "trie key {} landed in neither child", hex::encode(k)),
            Self::ValueChanged(k) => write!(f, "trie key {} changed value", hex::encode(k)),
            Self::ForeignKey(k) => {
                write!(f, "trie key {} is not in the parent trie", hex::encode(k))
            }
            Self::BalanceMismatch { expected, actual } => {
                write!(
                    f,
                    "balance did not conserve: expected {expected}, got {actual}"
                )
            }
        }
    }
}

/// The trie-level migration: the account plan plus the explicit key→owner
/// manifest, and the procedure that executes it against a real trie.
///
/// The procedure is deterministic and fail-closed:
///
/// 1. every key of the source trie is classified by the MANIFEST
///    (trie key → owning address);
/// 2. the owner's address decides the destination child by the split bit;
/// 3. a key the manifest does not classify ABORTS the migration — the split
///    never silently drops state;
/// 4. the CONSENSUS COMMITMENT key is NOT migrated: it is a digest over the
///    whole state, so each child recomputes its own from its own state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrieMigration {
    /// The account-level plan this migration implements.
    pub plan: MigrationPlan,
    /// The explicit key → owner map.
    pub manifest: MigrationManifest,
}

impl TrieMigration {
    /// Pair a plan with the manifest that implements it.
    pub fn new(plan: MigrationPlan, manifest: MigrationManifest) -> Self {
        Self { plan, manifest }
    }

    /// Execute a SPLIT: build the two child tries from the parent trie.
    pub fn execute_split(
        &self,
        parent: &PatriciaTrie,
    ) -> Result<(PatriciaTrie, PatriciaTrie), MigrationError> {
        let split_bit = self.plan.split_bit;
        if split_bit >= 64 {
            return Err(MigrationError::BadSplitBit(split_bit));
        }
        let commitment_key = crate::commitment::commitment_key();
        let mut keys: Vec<[u8; 32]> = parent.compressed().entries.keys().copied().collect();
        keys.sort_unstable();
        let mut child0 = PatriciaTrie::new();
        let mut child1 = PatriciaTrie::new();
        for key in keys {
            if key == commitment_key {
                // Each child recomputes its own commitment digest over its
                // own state; migrating the parent's digest would make the
                // child claim a root it does not have.
                continue;
            }
            let owner = self
                .manifest
                .owner_of(&key)
                .ok_or(MigrationError::UnclassifiedKey(key))?;
            let value = parent
                .compressed()
                .entries
                .get(&key)
                .cloned()
                .ok_or(MigrationError::MissingKey(key))?;
            if address_prefix_bit(&owner, split_bit) == 0 {
                child0.insert(&key, &value);
            } else {
                child1.insert(&key, &value);
            }
        }
        Ok((child0, child1))
    }

    /// Verify a completed SPLIT: every parent key is in exactly one child,
    /// with the same value, and neither child holds a foreign key.
    pub fn verify_split(
        &self,
        parent: &PatriciaTrie,
        child0: &PatriciaTrie,
        child1: &PatriciaTrie,
    ) -> Result<(), MigrationError> {
        let commitment_key = crate::commitment::commitment_key();
        for (key, value) in parent.compressed().entries.iter() {
            if *key == commitment_key {
                continue;
            }
            let owner = self
                .manifest
                .owner_of(key)
                .ok_or(MigrationError::UnclassifiedKey(*key))?;
            let bit = address_prefix_bit(&owner, self.plan.split_bit);
            let (own, other) = if bit == 0 {
                (child0, child1)
            } else {
                (child1, child0)
            };
            match own.get(key) {
                None => return Err(MigrationError::LostKey(*key)),
                Some(got) if got != value.as_slice() => {
                    return Err(MigrationError::ValueChanged(*key))
                }
                Some(_) => {}
            }
            if other.get(key).is_some() {
                return Err(MigrationError::DuplicateAssignment(*key));
            }
        }
        for key in child0.compressed().entries.keys() {
            if !parent.compressed().entries.contains_key(key) {
                return Err(MigrationError::ForeignKey(*key));
            }
        }
        for key in child1.compressed().entries.keys() {
            if !parent.compressed().entries.contains_key(key) {
                return Err(MigrationError::ForeignKey(*key));
            }
        }
        if !self.plan.balances_conserve() {
            return Err(MigrationError::BalanceMismatch {
                expected: self.plan.source_balance,
                actual: self.plan.target_balances.iter().sum(),
            });
        }
        Ok(())
    }

    /// Execute a MERGE: build the parent trie from the two child tries.
    ///
    /// The merge is the INVERSE of the split: every key of both children
    /// lands in the parent, and a key the manifest does not classify aborts
    /// the merge (fail closed, same as the split).
    pub fn execute_merge(
        &self,
        child0: &PatriciaTrie,
        child1: &PatriciaTrie,
    ) -> Result<PatriciaTrie, MigrationError> {
        let commitment_key = crate::commitment::commitment_key();
        let mut keys: Vec<[u8; 32]> = child0
            .compressed()
            .entries
            .keys()
            .chain(child1.compressed().entries.keys())
            .copied()
            .collect();
        keys.sort_unstable();
        keys.dedup();
        let mut parent = PatriciaTrie::new();
        for key in keys {
            if key == commitment_key {
                continue;
            }
            // The manifest must classify EVERY key, even in a merge: an
            // unclassified key aborts the merge (fail closed) rather than
            // letting an unknown piece of state into the parent.
            self.manifest
                .owner_of(&key)
                .ok_or(MigrationError::UnclassifiedKey(key))?;
            let value = child0
                .compressed()
                .entries
                .get(&key)
                .or_else(|| child1.compressed().entries.get(&key))
                .cloned()
                .ok_or(MigrationError::MissingKey(key))?;
            parent.insert(&key, &value);
        }
        Ok(parent)
    }

    /// Verify a completed MERGE: the parent holds every key of both children
    /// with the same value, and holds nothing else.
    pub fn verify_merge(
        &self,
        parent: &PatriciaTrie,
        child0: &PatriciaTrie,
        child1: &PatriciaTrie,
    ) -> Result<(), MigrationError> {
        let commitment_key = crate::commitment::commitment_key();
        for (key, value) in child0.compressed().entries.iter() {
            if *key == commitment_key {
                continue;
            }
            match parent.get(key) {
                None => return Err(MigrationError::LostKey(*key)),
                Some(got) if got != value.as_slice() => {
                    return Err(MigrationError::ValueChanged(*key))
                }
                Some(_) => {}
            }
        }
        for (key, value) in child1.compressed().entries.iter() {
            if *key == commitment_key {
                continue;
            }
            match parent.get(key) {
                None => return Err(MigrationError::LostKey(*key)),
                Some(got) if got != value.as_slice() => {
                    return Err(MigrationError::ValueChanged(*key))
                }
                Some(_) => {}
            }
        }
        for key in parent.compressed().entries.keys() {
            if key == &commitment_key {
                continue;
            }
            if !child0.compressed().entries.contains_key(key)
                && !child1.compressed().entries.contains_key(key)
            {
                return Err(MigrationError::ForeignKey(*key));
            }
        }
        if !self.plan.balances_conserve() {
            return Err(MigrationError::BalanceMismatch {
                expected: self.plan.source_balance,
                actual: self.plan.target_balances.iter().sum(),
            });
        }
        Ok(())
    }
}

/// Why a split did not happen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SplitRefusal {
    /// No such shard.
    UnknownShard,
    /// The masterchain never splits.
    Masterchain,
    /// The shard's recorded load is below the split threshold.
    LoadTooLow {
        /// The recorded load.
        load: u64,
        /// The threshold that was not reached.
        threshold: u64,
    },
    /// The shard owns too few accounts to be worth splitting.
    TooFewAccounts {
        /// How many accounts the shard owns.
        accounts: u64,
        /// The minimum a shard must own.
        minimum: u64,
    },
    /// The shard cap is reached.
    ShardCapReached {
        /// The current number of shards.
        shards: usize,
        /// The cap.
        cap: usize,
    },
    /// The routing prefix is already as deep as it can go.
    PrefixTooDeep {
        /// The current prefix length.
        prefix_len: u8,
        /// The maximum prefix length.
        max: u8,
    },
}

impl std::fmt::Display for SplitRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownShard => write!(f, "unknown shard"),
            Self::Masterchain => write!(f, "the masterchain never splits"),
            Self::LoadTooLow { load, threshold } => {
                write!(f, "load {load} is below the split threshold {threshold}")
            }
            Self::TooFewAccounts { accounts, minimum } => {
                write!(
                    f,
                    "{accounts} accounts is below the split minimum {minimum}"
                )
            }
            Self::ShardCapReached { shards, cap } => {
                write!(f, "shard cap {cap} reached ({shards} active)")
            }
            Self::PrefixTooDeep { prefix_len, max } => {
                write!(
                    f,
                    "routing prefix {prefix_len} bits is already at the maximum {max}"
                )
            }
        }
    }
}

/// Why a merge did not happen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MergeRefusal {
    /// No such shard.
    UnknownShard(ShardId),
    /// The masterchain never merges.
    Masterchain,
    /// The two shards are not siblings (they do not share a parent range).
    NotSiblings,
    /// The two shards belong to different workchains.
    DifferentWorkchain,
    /// The combined load is above the merge threshold.
    LoadTooHigh {
        /// The combined recorded load.
        load: u64,
        /// The threshold that was exceeded.
        threshold: u64,
    },
}

impl std::fmt::Display for MergeRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownShard(id) => write!(f, "unknown shard {id}"),
            Self::Masterchain => write!(f, "the masterchain never merges"),
            Self::NotSiblings => write!(f, "the two shards are not siblings"),
            Self::DifferentWorkchain => write!(f, "the two shards belong to different workchains"),
            Self::LoadTooHigh { load, threshold } => {
                write!(f, "load {load} is above the merge threshold {threshold}")
            }
        }
    }
}

/// A topology invariant that does not hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TopologyError {
    /// The same address is owned by two shards.
    DuplicateOwner([u8; 32]),
    /// An address is owned by a shard the routing rule does not select.
    Misrouted {
        /// The address.
        address: [u8; 32],
        /// The shard that claims it.
        owner: ShardId,
        /// The shard the routing rule selects.
        routed: ShardId,
    },
    /// A shard owns an account outside its routing prefix.
    PrefixViolation {
        /// The shard.
        shard: ShardId,
        /// The address.
        address: [u8; 32],
    },
    /// The total balance changed.
    BalanceMismatch {
        /// The balance the plan says must survive.
        expected: u128,
        /// The balance that is actually there.
        actual: u128,
    },
}

impl std::fmt::Display for TopologyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateOwner(a) => write!(f, "address {} is owned twice", hex::encode(a)),
            Self::Misrouted {
                address,
                owner,
                routed,
            } => write!(
                f,
                "address {} is owned by shard {owner} but routes to shard {routed}",
                hex::encode(address)
            ),
            Self::PrefixViolation { shard, address } => write!(
                f,
                "address {} is outside the routing prefix of shard {shard}",
                hex::encode(address)
            ),
            Self::BalanceMismatch { expected, actual } => {
                write!(
                    f,
                    "balance did not conserve: expected {expected}, got {actual}"
                )
            }
        }
    }
}

/// A split that was executed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitTransition {
    /// The shard that was split.
    pub parent: ShardDescriptor,
    /// The two children, in prefix order (child 0 carries the 0 bit).
    pub children: [ShardDescriptor; 2],
    /// The account-level migration that was performed.
    pub plan: MigrationPlan,
}

/// A merge that was executed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeTransition {
    /// The two shards that were merged.
    pub children: [ShardDescriptor; 2],
    /// The shard that now holds their state.
    pub parent: ShardDescriptor,
    /// The account-level migration that was performed.
    pub plan: MigrationPlan,
}

/// The shard topology: the active shard set, who owns which account, and the
/// split/merge transitions between them.
///
/// This is the REACHABLE, TESTABLE home of the dynamic sharding logic. The
/// [`DynamicShardManager`] decides *whether* a shard may split or merge (it
/// owns the prefix arithmetic and the shard-id allocation); the topology
/// owns the ACCOUNT OWNERSHIP and performs the deterministic re-assignment
/// that makes a split real.
#[derive(Clone, Debug)]
pub struct ShardTopology {
    /// The shard set and the split/merge decision logic.
    pub manager: DynamicShardManager,
    /// Per-shard account ownership, sorted by address within each shard.
    pub ownership: BTreeMap<ShardId, Vec<ShardAccount>>,
    /// How many split/merge transitions this topology has applied.
    pub transitions: u64,
}

/// The default topology is the STARTING one (masterchain + base workchain
/// shard), never an empty shard set: a topology with no workchain shard
/// would route every bare address to the masterchain.
impl Default for ShardTopology {
    fn default() -> Self {
        Self::new()
    }
}

impl ShardTopology {
    /// The starting topology: the masterchain (shard 0) and the base
    /// workchain shard (shard 1), which holds every workchain address
    /// (its routing prefix is empty).
    pub fn new() -> Self {
        let manager = DynamicShardManager::new();
        let mut ownership: BTreeMap<ShardId, Vec<ShardAccount>> = BTreeMap::new();
        ownership.insert(MASTERCHAIN_SHARD, Vec::new());
        ownership.insert(BASE_WORKCHAIN_SHARD_INITIAL, Vec::new());
        Self {
            manager,
            ownership,
            transitions: 0,
        }
    }

    /// The active shard set, in ascending shard id.
    pub fn shards(&self) -> impl Iterator<Item = (&ShardId, &ShardDescriptor)> {
        self.manager.shards.iter()
    }

    /// The descriptor of one shard.
    pub fn descriptor(&self, shard: ShardId) -> Option<&ShardDescriptor> {
        self.manager.shards.get(&shard)
    }

    /// How many shards are active (the masterchain included).
    pub fn shard_count(&self) -> usize {
        self.manager.shards.len()
    }

    /// The accounts a shard owns, sorted by address.
    pub fn accounts_of(&self, shard: ShardId) -> &[ShardAccount] {
        self.ownership
            .get(&shard)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Every account in the topology, sorted by address.
    pub fn all_accounts(&self) -> Vec<ShardAccount> {
        let mut all: Vec<ShardAccount> = self
            .ownership
            .values()
            .flat_map(|v| v.iter().copied())
            .collect();
        all.sort_by(|a, b| a.address.cmp(&b.address));
        all
    }

    /// Register an account with a balance on the shard the routing rule
    /// selects. Returns the shard it landed on.
    pub fn register_account(&mut self, address: [u8; 32], balance: u64) -> ShardId {
        let shard = self.route_workchain(&address);
        let list = self.ownership.entry(shard).or_default();
        match list.binary_search_by(|probe| probe.address.cmp(&address)) {
            Ok(i) => list[i].balance = balance,
            Err(i) => list.insert(i, ShardAccount { address, balance }),
        }
        shard
    }

    /// Drop an account (it moved to another shard, or it closed).
    pub fn remove_account(&mut self, address: &[u8; 32]) -> Option<u64> {
        for list in self.ownership.values_mut() {
            if let Ok(i) = list.binary_search_by(|probe| probe.address.cmp(address)) {
                return Some(list.remove(i).balance);
            }
        }
        None
    }

    /// Which shard owns an account, if any.
    pub fn owner_of(&self, address: &[u8; 32]) -> Option<ShardId> {
        self.ownership.iter().find_map(|(id, list)| {
            list.binary_search_by(|probe| probe.address.cmp(address))
                .ok()
                .map(|_| *id)
        })
    }

    /// The total balance the topology holds.
    pub fn total_balance(&self) -> u128 {
        self.ownership
            .values()
            .flat_map(|v| v.iter())
            .map(|a| a.balance as u128)
            .sum()
    }

    /// The balance one shard holds.
    pub fn shard_balance(&self, shard: ShardId) -> u128 {
        self.accounts_of(shard)
            .iter()
            .map(|a| a.balance as u128)
            .sum()
    }

    /// THE ROUTING RULE.
    ///
    /// See [`ROUTING_RULE`]: the masterchain is addressed explicitly, a
    /// workchain address goes to the shard with the longest matching routing
    /// prefix (ties broken by the smallest shard id).
    pub fn route(&self, address: &ShardAddress) -> ShardId {
        match address {
            ShardAddress::Masterchain(_) => MASTERCHAIN_SHARD,
            ShardAddress::Workchain(a) => self.route_workchain(a),
        }
    }

    /// Route a WORKCHAIN address (the bare 32-byte form).
    pub fn route_workchain(&self, address: &[u8; 32]) -> ShardId {
        self.manager.route_address(address)
    }

    /// Record transaction load on a shard (the load window counter).
    pub fn record_tx_load(&mut self, shard: ShardId, count: u64) {
        self.manager.record_tx_load(shard, count);
    }

    /// Decay the recorded load of every shard. The load window rolls, so a
    /// quiet shard drains towards zero and becomes merge-eligible.
    pub fn decay_load(&mut self, amount: u64) {
        for s in self.manager.shards.values_mut() {
            s.tx_load = s.tx_load.saturating_sub(amount);
        }
    }

    /// The published split trigger for `shard_id`.
    ///
    /// A split happens when ALL of these hold:
    ///
    /// * the shard is not the masterchain;
    /// * the shard cap ([`MAX_SHARDS`]) is not reached;
    /// * the routing prefix is not already at [`MAX_PREFIX_BITS`];
    /// * the shard owns at least [`MIN_ACCOUNTS_PER_SHARD`] accounts;
    /// * the shard's recorded load is at least [`SHARD_SPLIT_LOAD_THRESHOLD`].
    pub fn split_preconditions(&self, shard_id: ShardId) -> Result<(), SplitRefusal> {
        let Some(desc) = self.manager.shards.get(&shard_id) else {
            return Err(SplitRefusal::UnknownShard);
        };
        if shard_id == MASTERCHAIN_SHARD {
            return Err(SplitRefusal::Masterchain);
        }
        if self.manager.shards.len() >= MAX_SHARDS {
            return Err(SplitRefusal::ShardCapReached {
                shards: self.manager.shards.len(),
                cap: MAX_SHARDS,
            });
        }
        if desc.prefix_len >= MAX_PREFIX_BITS {
            return Err(SplitRefusal::PrefixTooDeep {
                prefix_len: desc.prefix_len,
                max: MAX_PREFIX_BITS,
            });
        }
        let accounts = self.accounts_of(shard_id).len() as u64;
        if accounts < MIN_ACCOUNTS_PER_SHARD {
            return Err(SplitRefusal::TooFewAccounts {
                accounts,
                minimum: MIN_ACCOUNTS_PER_SHARD,
            });
        }
        if desc.tx_load < SHARD_SPLIT_LOAD_THRESHOLD {
            return Err(SplitRefusal::LoadTooLow {
                load: desc.tx_load,
                threshold: SHARD_SPLIT_LOAD_THRESHOLD,
            });
        }
        Ok(())
    }

    /// The published merge trigger for two shards.
    ///
    /// A merge happens when ALL of these hold:
    ///
    /// * both shards exist, are not the masterchain and belong to the same
    ///   workchain;
    /// * they are SIBLINGS — they share every routing bit but the deepest
    ///   one, so together they cover exactly one parent range;
    /// * their combined recorded load is at most
    ///   [`SHARD_MERGE_LOAD_THRESHOLD`].
    pub fn merge_preconditions(&self, a: ShardId, b: ShardId) -> Result<(), MergeRefusal> {
        let Some(d0) = self.manager.shards.get(&a) else {
            return Err(MergeRefusal::UnknownShard(a));
        };
        let Some(d1) = self.manager.shards.get(&b) else {
            return Err(MergeRefusal::UnknownShard(b));
        };
        if a == MASTERCHAIN_SHARD || b == MASTERCHAIN_SHARD {
            return Err(MergeRefusal::Masterchain);
        }
        if d0.prefix_len != d1.prefix_len || d0.prefix_len == 0 {
            return Err(MergeRefusal::NotSiblings);
        }
        if d0.workchain_id != d1.workchain_id {
            return Err(MergeRefusal::DifferentWorkchain);
        }
        if !are_siblings(d0, d1) {
            return Err(MergeRefusal::NotSiblings);
        }
        let load = d0.tx_load.saturating_add(d1.tx_load);
        if load > SHARD_MERGE_LOAD_THRESHOLD {
            return Err(MergeRefusal::LoadTooHigh {
                load,
                threshold: SHARD_MERGE_LOAD_THRESHOLD,
            });
        }
        Ok(())
    }

    /// Split `shard_id` if the published trigger fires.
    ///
    /// The split is EXECUTED, not merely planned:
    ///
    /// * the routing prefix grows by one bit; the address's bit at the new
    ///   depth decides the child (bit 0 → child 0, bit 1 → child 1);
    /// * the parent's accounts are re-assigned by that rule;
    /// * the parent's recorded load is divided between the children (child 0
    ///   gets the floor, child 1 the remainder), so the SUM is preserved.
    ///
    /// The load division is what makes the cycle converge: a split parent
    /// had a load of at least [`SHARD_SPLIT_LOAD_THRESHOLD`] (500) and the
    /// merge threshold is [`SHARD_MERGE_LOAD_THRESHOLD`] (50), so a shard
    /// that has just split is NOT merge-eligible — the topology can never
    /// oscillate between the two.
    pub fn check_and_split(&mut self, shard_id: ShardId) -> Option<SplitTransition> {
        self.split_preconditions(shard_id).ok()?;
        let parent_desc = self.manager.shards.get(&shard_id).cloned()?;
        let parent_load = parent_desc.tx_load;
        let parent_accounts = self.accounts_of(shard_id).to_vec();
        let source_digest = account_set_digest(&parent_accounts);
        let source_balance = parent_accounts
            .iter()
            .map(|a| a.balance as u128)
            .sum::<u128>();

        let (child0, child1) = self.manager.check_and_split(shard_id)?;
        let split_bit = child0.prefix_len - 1;

        let mut accounts0: Vec<ShardAccount> = Vec::new();
        let mut accounts1: Vec<ShardAccount> = Vec::new();
        for acct in parent_accounts {
            if address_prefix_bit(&acct.address, split_bit) == 0 {
                accounts0.push(acct);
            } else {
                accounts1.push(acct);
            }
        }
        self.ownership.remove(&shard_id);
        self.ownership.insert(child0.shard_id, accounts0);
        self.ownership.insert(child1.shard_id, accounts1);

        let share = parent_load / 2;
        if let Some(s) = self.manager.shards.get_mut(&child0.shard_id) {
            s.tx_load = share;
        }
        if let Some(s) = self.manager.shards.get_mut(&child1.shard_id) {
            s.tx_load = parent_load - share;
        }

        let target_balances = vec![
            self.shard_balance(child0.shard_id),
            self.shard_balance(child1.shard_id),
        ];
        let target_digests = vec![
            account_set_digest(self.accounts_of(child0.shard_id)),
            account_set_digest(self.accounts_of(child1.shard_id)),
        ];

        let plan = MigrationPlan {
            direction: MigrationDirection::Split,
            source_shards: vec![shard_id],
            target_shards: vec![child0.shard_id, child1.shard_id],
            split_bit,
            account_count: self.accounts_of(child0.shard_id).len()
                + self.accounts_of(child1.shard_id).len(),
            source_digest,
            target_digests,
            source_balance,
            target_balances,
        };

        self.transitions += 1;
        Some(SplitTransition {
            parent: parent_desc,
            children: [child0, child1],
            plan,
        })
    }

    /// Merge two sibling shards if the published trigger fires.
    ///
    /// The merge is the INVERSE of the split: the children are replaced by
    /// one parent whose routing prefix is the deepest common prefix, and
    /// both children's accounts move to it. The total balance is unchanged.
    ///
    /// The merged shard gets a NEW shard id: ids are never reused, so a late
    /// cross-shard message addressed to a retired id can never be mistaken
    /// for the merged shard.
    pub fn check_and_merge(&mut self, a: ShardId, b: ShardId) -> Option<MergeTransition> {
        self.merge_preconditions(a, b).ok()?;
        let desc_a = self.manager.shards.get(&a).cloned()?;
        let desc_b = self.manager.shards.get(&b).cloned()?;
        let combined_load = desc_a.tx_load.saturating_add(desc_b.tx_load);

        let mut accounts = self.accounts_of(a).to_vec();
        accounts.extend(self.accounts_of(b).iter().copied());
        accounts.sort_by(|x, y| x.address.cmp(&y.address));
        let source_digest = account_set_digest(&accounts);
        let source_balance = accounts.iter().map(|x| x.balance as u128).sum::<u128>();

        let parent = self.manager.check_and_merge(a, b)?;

        self.ownership.remove(&a);
        self.ownership.remove(&b);
        self.ownership.insert(parent.shard_id, accounts);

        if let Some(s) = self.manager.shards.get_mut(&parent.shard_id) {
            s.tx_load = combined_load;
        }

        let plan = MigrationPlan {
            direction: MigrationDirection::Merge,
            source_shards: vec![a, b],
            target_shards: vec![parent.shard_id],
            split_bit: parent.prefix_len,
            account_count: self.accounts_of(parent.shard_id).len(),
            source_digest,
            target_digests: vec![account_set_digest(self.accounts_of(parent.shard_id))],
            source_balance,
            target_balances: vec![self.shard_balance(parent.shard_id)],
        };

        self.transitions += 1;
        Some(MergeTransition {
            children: [desc_a, desc_b],
            parent,
            plan,
        })
    }

    /// Verify the invariants a topology must hold after every transition:
    ///
    /// * every account is owned by EXACTLY one shard;
    /// * the routing rule resolves every account to the shard that owns it
    ///   (so the rule and the ownership never drift apart);
    /// * every owned address falls inside its shard's routing prefix.
    pub fn verify_invariants(&self) -> Result<(), TopologyError> {
        let mut seen: BTreeMap<[u8; 32], ShardId> = BTreeMap::new();
        for (shard, list) in &self.ownership {
            for acct in list {
                if seen.insert(acct.address, *shard).is_some() {
                    return Err(TopologyError::DuplicateOwner(acct.address));
                }
                let routed = self.route_workchain(&acct.address);
                if routed != *shard {
                    return Err(TopologyError::Misrouted {
                        address: acct.address,
                        owner: *shard,
                        routed,
                    });
                }
                if let Some(desc) = self.manager.shards.get(shard) {
                    if !desc.contains_address(&acct.address) {
                        return Err(TopologyError::PrefixViolation {
                            shard: *shard,
                            address: acct.address,
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// The published sharding parameters, as the RPC layer reports them.
    pub fn parameters(&self) -> ShardingParameters {
        let prefix_bits = self
            .manager
            .shards
            .values()
            .map(|d| d.prefix_len)
            .max()
            .unwrap_or(0);
        ShardingParameters {
            rule_id: ROUTING_RULE_ID.to_string(),
            rule: ROUTING_RULE.to_string(),
            prefix_bits,
            masterchain_shard: MASTERCHAIN_SHARD,
            base_workchain_shard: BASE_WORKCHAIN_SHARD_INITIAL,
            masterchain_address_form: MASTERCHAIN_ADDRESS_FORM.to_string(),
            min_accounts_per_shard: MIN_ACCOUNTS_PER_SHARD,
            max_shards: MAX_SHARDS,
            split_load_threshold: SHARD_SPLIT_LOAD_THRESHOLD,
            merge_load_threshold: SHARD_MERGE_LOAD_THRESHOLD,
            max_prefix_bits: MAX_PREFIX_BITS,
            max_workchain_shard_space: MAX_WORKCHAIN_SHARD_SPACE,
            active_shards: self.shard_count(),
        }
    }

    /// The full topology report (parameters + every shard).
    pub fn report(&self) -> ShardTopologyReport {
        let mut shards = Vec::new();
        for (id, desc) in &self.manager.shards {
            shards.push(ShardTopologyEntry {
                shard_id: *id,
                shard_type: if *id == MASTERCHAIN_SHARD {
                    "masterchain".to_string()
                } else {
                    "workchain".to_string()
                },
                workchain_id: desc.workchain_id,
                prefix: desc.prefix,
                prefix_len: desc.prefix_len,
                prefix_bits: prefix_bits_string(desc.prefix, desc.prefix_len),
                accounts: self.accounts_of(*id).len(),
                balance: self.shard_balance(*id),
                tx_load: desc.tx_load,
            });
        }
        ShardTopologyReport {
            parameters: self.parameters(),
            shards,
            transitions: self.transitions,
            total_accounts: self.ownership.values().map(|v| v.len()).sum(),
            total_balance: self.total_balance(),
        }
    }
}

/// The routing prefix of a shard as a bit string (most significant first).
pub fn prefix_bits_string(prefix: u64, prefix_len: u8) -> String {
    let len = u64::from(prefix_len).min(64);
    if len == 0 {
        return String::new();
    }
    let shifted = prefix >> (64 - len);
    format!("{:0width$b}", shifted, width = len as usize)
}

/// The published sharding parameters, as `stell_getShards` reports them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShardingParameters {
    /// The identifier of the routing rule.
    pub rule_id: String,
    /// The routing rule, in words.
    pub rule: String,
    /// The routing prefix length the topology currently uses.
    pub prefix_bits: u8,
    /// The masterchain shard id.
    pub masterchain_shard: ShardId,
    /// The base workchain shard id.
    pub base_workchain_shard: ShardId,
    /// The address form that names the masterchain.
    pub masterchain_address_form: String,
    /// Minimum accounts a shard must own to be split.
    pub min_accounts_per_shard: u64,
    /// The hard cap on the number of shards.
    pub max_shards: usize,
    /// Load that triggers a split (txs per window).
    pub split_load_threshold: u64,
    /// Load that allows a merge (txs per window).
    pub merge_load_threshold: u64,
    /// The maximum routing prefix length, in bits.
    pub max_prefix_bits: u8,
    /// The ADVERTISED shard space (2^60) — not the shipped capacity.
    pub max_workchain_shard_space: u64,
    /// How many shards are active right now.
    pub active_shards: usize,
}

/// One shard, as the topology report describes it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShardTopologyEntry {
    /// The shard id.
    pub shard_id: ShardId,
    /// `"masterchain"` or `"workchain"`.
    pub shard_type: String,
    /// The workchain this shard belongs to (`-1` for the masterchain).
    pub workchain_id: i32,
    /// The routing prefix word.
    pub prefix: u64,
    /// The routing prefix length, in bits.
    pub prefix_len: u8,
    /// The routing prefix as a bit string.
    pub prefix_bits: String,
    /// How many accounts the shard owns.
    pub accounts: usize,
    /// The balance the shard holds.
    pub balance: u128,
    /// The shard's recorded load (txs per window).
    pub tx_load: u64,
}

/// The full topology report.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShardTopologyReport {
    /// The published parameters.
    pub parameters: ShardingParameters,
    /// Every active shard.
    pub shards: Vec<ShardTopologyEntry>,
    /// How many transitions the topology has applied.
    pub transitions: u64,
    /// How many accounts the topology holds.
    pub total_accounts: usize,
    /// The total balance the topology holds.
    pub total_balance: u128,
}

/// Resolve an address to its shard under `topology`.
///
/// THIS IS THE SINGLE SOURCE OF TRUTH of the address→shard rule: the RPC
/// layer, the SVM's cross-shard routing and the topology itself all call
/// this (or [`ShardTopology::route`], which is the same rule).
pub fn route_shard(topology: &ShardTopology, address: &ShardAddress) -> ShardId {
    topology.route(address)
}

/// Route an address to its target shard using dynamic shard routing and prefix rules.
///
/// This is the DEFAULT (single-shard) rule: the starting topology, where the
/// base workchain shard holds every workchain address. For the rule as the
/// live topology applies it, use [`route_shard`] with the node's topology —
/// that is the single source of truth.
pub fn route_address(address: &[u8; 32]) -> ShardId {
    DynamicShardManager::new().route_address(address)
}
