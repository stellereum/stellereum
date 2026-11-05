//! Canonical commitment to every consensus-visible subsystem that does NOT
//! live in the Patricia trie.
//!
//! # Why this file exists
//!
//! The state root is the Patricia trie's root. The trie commits native
//! balances, STS token balances and supply, and contract code hashes. For years
//! the remaining subsystems were mutated freely without ever touching the trie,
//! so the root could not see them.
//!
//! That is a soundness hole, not a tidiness issue. Block sync compares roots to
//! decide whether two nodes agree, and the validator set is re-derived from the
//! staking ledger at every height boundary. If the staking ledger is invisible
//! to the root, two nodes can disagree about who the validators are while the
//! root says they agree, and no amount of re-syncing detects it.
//!
//! # The invariant this module enforces
//!
//! `commitment_digest` enumerates every field of the consensus state. The root
//! is then a hash over both the trie root and this digest.
//!
//! Two consequences, both deliberate:
//!
//! 1. A subsystem cannot be added to consensus state and silently left
//!    uncommitted. It has to be listed in exactly one place, and omitting it
//!    from that list now fails the completeness test in
//!    `tests/state_root_completeness_tests.rs`.
//! 2. The commitment is computed at root-read time rather than at each
//!    mutation site. Mutation sites are where the original bug lived: fifty
//!    call sites, each of which had to remember. There is now no call site to
//!    forget.
//!
//! The digest is recomputed lazily at root-read time and cached against a
//! mutation-generation counter (`commitment_generation`). That cache is only
//! sound because the subsystem locks in `InMemoryStateEngine` are private and
//! every write accessor bumps the counter before handing out a guard; see
//! `commit_consensus_domains_if_stale`. The cache does not weaken the authority
//! of the trie: the digest is still written into the trie, which a reader can
//! cross-check independently.
//!
//! # Determinism
//!
//! `HashMap` iteration order differs between processes, so walking a map
//! naively would give two nodes with identical state different digests - a
//! consensus split with no attacker involved. Every map here is therefore
//! sorted by key before hashing, and every length is written explicitly so
//! that no two different states can encode to the same bytes.

use sha2::{Digest, Sha256};
use std::cmp::Reverse;
use std::collections::HashMap;

/// Byte sink for the commitment preimage.
///
/// `Sha256` is the live sink (streaming hash); `Vec<u8>` is the caching sink
/// (capture the exact preimage bytes of one domain so an unchanged domain can
/// be re-fed without re-walking its state). Both implement the same framing,
/// so the bytes hashed on a cache hit are bit-for-bit the bytes the streaming
/// path would have fed — the split is behaviour-preserving by construction.
///
/// The trait is also implemented by downstream domains
/// so every committed domain can be captured, not just the ones defined
/// in this module.
pub trait PreimageSink {
    /// Append raw bytes to the preimage.
    fn push_preimage(&mut self, bytes: &[u8]);
}

impl PreimageSink for Sha256 {
    #[inline(always)]
    fn push_preimage(&mut self, bytes: &[u8]) {
        self.update(bytes);
    }
}

impl PreimageSink for Vec<u8> {
    #[inline(always)]
    fn push_preimage(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

use crate::contract::ContractRegistry;
use crate::orderbook::{Order, OrderSide, OrderType, OrderbookManager};
use crate::pmm::PrimaryMarketMaker;
use crate::sharding::CrossShardKey;
use crate::staking::{StakingLedger, UnbondingEntry};
use crate::state_engine::EscrowRecord;

/// Bumped whenever the set of committed fields changes. Two nodes with
/// different versions must not compare roots, so the version is part of the
/// digest and a mismatch shows up as a root difference rather than as a
/// mysterious validation failure.
///
/// v3 -> v4: the oracle (`OracleState`: publishers, committed feeds, breaker
/// latch) joined the digest. A field that can move without moving the root is
/// the exact hole this module exists to close, so the re-root is deliberate:
/// every data directory needs a wipe (and `tests/genesis_root_known_answer_tests.rs`
/// a new pinned root) in the commit that bumps this.
pub const COMMITMENT_VERSION: u32 = 5;

/// The single trie key that carries the commitment digest.
///
/// The digest goes into the trie under one namespaced key rather than becoming
/// part of the state root's own hash. That keeps `state_root == trie_root`,
/// which matters: Merkle proofs and the block-sync comparison are defined
/// against the trie root, and a light client verifying an account proof must
/// not need a second, separately sourced root. One extra key folds the whole
/// non-trie state into the same root everything else already uses.
pub fn commitment_key() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"STELL_CONSENSUS_COMMITMENT_V1");
    h.finalize().into()
}

// Per-domain generation caching: each domain's digest bytes are captured once and
// reused while its `DomainGenerations` counter is unchanged (bit-for-bit the streaming
// digest; single-domain mutation re-walks one domain). FORK SAFETY: `DomainCache` lives in
// the engine instance only — never `static` — so diverged forks/snapshots can't share bytes.

/// One committed domain of the digest. Order matches `commitment_digest_into`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Domain {
    Tokens,
    Staking,
    Pmm,
    Contracts,
    Escrow,
    Governance,
    Oracle,
    SessionKeys,
    Books,
    Bridge,
    CrossShard,
    Xpc,
    Zkml,
}

impl Domain {
    /// Every domain, in digest order.
    pub const ALL: [Domain; 13] = [
        Domain::Tokens,
        Domain::Staking,
        Domain::Pmm,
        Domain::Contracts,
        Domain::Escrow,
        Domain::Governance,
        Domain::Oracle,
        Domain::SessionKeys,
        Domain::Books,
        Domain::Bridge,
        Domain::CrossShard,
        Domain::Xpc,
        Domain::Zkml,
    ];

    #[inline(always)]
    pub fn index(self) -> usize {
        self as usize
    }
}

/// Per-domain content-generation counters.
///
/// Each counter is bumped exactly when its domain is mutated (alongside the
/// global `commitment_generation`, which is preserved unchanged). A counter
/// value therefore identifies the CONTENT of its domain within one engine
/// instance: equal counter ⇒ equal bytes, without ever consulting a clock.
///
/// The struct lives behind one `Arc` on the engine. Counters are plain
/// `AtomicU64`s; wrapping is harmless (equality against the cache slot is
/// what matters, and a wrap-around collision would require 2^64 mutations of
/// one domain on one instance).
#[derive(Debug, Default)]
pub struct DomainGenerations {
    pub tokens: std::sync::atomic::AtomicU64,
    pub staking: std::sync::atomic::AtomicU64,
    pub pmm: std::sync::atomic::AtomicU64,
    pub contracts: std::sync::atomic::AtomicU64,
    pub escrow: std::sync::atomic::AtomicU64,
    pub governance: std::sync::atomic::AtomicU64,
    pub oracle: std::sync::atomic::AtomicU64,
    pub session_keys: std::sync::atomic::AtomicU64,
    pub books: std::sync::atomic::AtomicU64,
    pub bridge: std::sync::atomic::AtomicU64,
    pub cross_shard: std::sync::atomic::AtomicU64,
    pub xpc: std::sync::atomic::AtomicU64,
    pub zkml: std::sync::atomic::AtomicU64,
}

impl DomainGenerations {
    /// Load the counter for one domain.
    pub fn load(&self, domain: Domain) -> u64 {
        self.counter(domain)
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// Snapshot every counter (for tests and diagnostics).
    pub fn snapshot(&self) -> [u64; 13] {
        let mut out = [0u64; 13];
        for d in Domain::ALL {
            out[d.index()] = self.load(d);
        }
        out
    }

    /// Copy every counter value into a fresh instance (deep-copy / fork
    /// path: the fork holds equal state at equal generations, with an empty
    /// cache that re-populates on demand).
    pub fn copy_values_into(&self, dst: &DomainGenerations) {
        for d in Domain::ALL {
            let v = self.load(d);
            dst.counter(d)
                .store(v, std::sync::atomic::Ordering::Release);
        }
    }

    fn counter(&self, domain: Domain) -> &std::sync::atomic::AtomicU64 {
        match domain {
            Domain::Tokens => &self.tokens,
            Domain::Staking => &self.staking,
            Domain::Pmm => &self.pmm,
            Domain::Contracts => &self.contracts,
            Domain::Escrow => &self.escrow,
            Domain::Governance => &self.governance,
            Domain::Oracle => &self.oracle,
            Domain::SessionKeys => &self.session_keys,
            Domain::Books => &self.books,
            Domain::Bridge => &self.bridge,
            Domain::CrossShard => &self.cross_shard,
            Domain::Xpc => &self.xpc,
            Domain::Zkml => &self.zkml,
        }
    }

    /// Bump one domain's counter (alongside the global generation, which the
    /// caller bumps separately — the two are always moved together).
    pub fn bump(&self, domain: Domain) {
        self.counter(domain)
            .fetch_add(1, std::sync::atomic::Ordering::Release);
    }

    /// Bump every domain's counter (restore / reorg paths where the whole
    /// world may have changed; equivalent to invalidating the full cache).
    pub fn bump_all(&self) {
        for d in Domain::ALL {
            self.bump(d);
        }
    }
}

/// Content fingerprint of one contract's ABI manifest.
///
/// This is a CACHE KEY only, never hashed into the digest and never
/// persisted or compared across processes: it only decides whether the
/// cached JSON string may be reused. The string form is canonical
/// (`serde_json::to_string` of the same struct), so equal structs ⇒ equal
/// JSON; the fingerprint additionally guards the map lookup. `DefaultHasher`
/// (process-random SipHash) is fine here precisely because the key never
/// leaves the process — determinism across nodes comes from the JSON bytes,
/// not from the key.
fn abi_fingerprint(abi: &crate::contract_abi::ContractAbi) -> u64 {
    use std::hash::{Hash, Hasher};
    fn abi_type_tag<H: Hasher>(t: &crate::contract_abi::AbiType, h: &mut H) {
        h.write_u8(t.tag());
    }
    let mut h = std::collections::hash_map::DefaultHasher::new();
    abi.methods.len().hash(&mut h);
    for m in &abi.methods {
        m.name.hash(&mut h);
        m.params.len().hash(&mut h);
        for p in &m.params {
            p.name.hash(&mut h);
            abi_type_tag(&p.ty, &mut h);
        }
        abi_type_tag(&m.returns, &mut h);
        m.mutates_state.hash(&mut h);
    }
    abi.events.len().hash(&mut h);
    for e in &abi.events {
        e.name.hash(&mut h);
        e.topics.len().hash(&mut h);
        for t in e.topics.iter().chain(e.data.iter()) {
            t.name.hash(&mut h);
            abi_type_tag(&t.ty, &mut h);
        }
        e.data.len().hash(&mut h);
    }
    h.finish()
}

/// Per-contract cache of serialized ABI manifests.
///
/// `contracts_digest` calls `ContractAbi::to_json()` once per contract per
/// commit — string building plus allocation over every method/event. The
/// manifest of a contract changes rarely (deploy / `set_abi`), so the JSON
/// is cached per contract address and reused while the content fingerprint
/// matches. Keyed by (address, content fingerprint): a changed manifest has
/// a different fingerprint and re-serializes; an unchanged one reuses the
/// exact bytes `to_json()` would have produced.
#[derive(Debug, Default)]
pub struct AbiJsonCache {
    map: HashMap<[u8; 32], (u64, Vec<u8>)>,
    /// Cache hits (reused JSON) since creation / last reset.
    pub hits: u64,
    /// Cache misses (fresh `to_json`) since creation / last reset.
    pub misses: u64,
}

impl AbiJsonCache {
    /// The JSON bytes for one contract's manifest: cached when the
    /// fingerprint matches, freshly serialized otherwise.
    pub fn json_for(&mut self, addr: &[u8; 32], abi: &crate::contract_abi::ContractAbi) -> Vec<u8> {
        let fp = abi_fingerprint(abi);
        if let Some((cached_fp, json)) = self.map.get(addr) {
            if *cached_fp == fp {
                self.hits += 1;
                return json.clone();
            }
        }
        self.misses += 1;
        let json = abi.to_json().into_bytes();
        self.map.insert(*addr, (fp, json.clone()));
        json
    }

    /// Drop every entry (tests; the live path never needs this because
    /// entries are keyed by content and go stale-safe automatically).
    pub fn clear(&mut self) {
        self.map.clear();
        self.hits = 0;
        self.misses = 0;
    }

    /// Number of cached contracts.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// True when no contract JSON is cached.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// One cached domain preimage: the generation it was built from plus the
/// exact bytes that were (and will be) fed to the digest hasher.
#[derive(Clone, Debug)]
struct DomainSlot {
    generation: u64,
    bytes: Vec<u8>,
}

/// Per-engine-instance cache of per-domain commitment preimages.
///
/// Lives on the engine (never process-wide): a deep copy of an engine
/// (fork, simulation clone, snapshot install target) starts with an EMPTY
/// cache, so one fork's bytes can never be served to another. Within one
/// instance, a slot is valid only while its stored generation equals the
/// domain's current content-generation counter — the counters move only on
/// mutation, so equality implies byte-identical content.
#[derive(Debug, Default)]
pub struct DomainCache {
    slots: [Option<DomainSlot>; 13],
    /// Per-contract ABI JSON cache (feeds the contracts domain).
    pub abi: AbiJsonCache,
    /// Domain-level hits (reused preimage) since creation / last reset.
    pub hits: u64,
    /// Domain-level misses (rebuilt preimage) since creation / last reset.
    pub misses: u64,
}

impl DomainCache {
    /// Fetch a cached preimage when its generation still matches.
    pub fn get(&mut self, domain: Domain, generation: u64) -> Option<Vec<u8>> {
        match &self.slots[domain.index()] {
            Some(slot) if slot.generation == generation => {
                self.hits += 1;
                Some(slot.bytes.clone())
            }
            _ => {
                self.misses += 1;
                None
            }
        }
    }

    /// Store a freshly built preimage under its generation.
    pub fn put(&mut self, domain: Domain, generation: u64, bytes: Vec<u8>) {
        self.slots[domain.index()] = Some(DomainSlot { generation, bytes });
    }

    /// Borrow a cached preimage when its generation still matches.
    ///
    /// Zero-copy twin of [`get`](Self::get): the hit/miss accounting is
    /// identical, but no bytes are cloned — the caller hashes the borrowed
    /// slice in place. A cache hit therefore costs a refcount-free borrow
    /// plus one hasher update instead of a ~28KB-average `memcpy` (387KB
    /// total at the tempo-probe fixture). Miss semantics match `get` exactly.
    pub fn get_ref(&mut self, domain: Domain, generation: u64) -> Option<&[u8]> {
        let hit = matches!(
            &self.slots[domain.index()],
            Some(slot) if slot.generation == generation
        );
        if hit {
            self.hits += 1;
            // Re-borrow after the counter bump: the slot is still present
            // (only `&mut self` aliasing was in play, no mutation happened).
            self.slots[domain.index()].as_ref().map(|s| s.bytes.as_slice())
        } else {
            self.misses += 1;
            None
        }
    }

    /// Invalidate one domain (tests; the live path invalidates implicitly
    /// because the generation counters move on mutation).
    pub fn invalidate(&mut self, domain: Domain) {
        self.slots[domain.index()] = None;
    }

    /// Hit rate over domain slots, `None` when nothing was looked up yet.
    pub fn hit_rate(&self) -> Option<f64> {
        let total = self.hits + self.misses;
        if total == 0 {
            None
        } else {
            Some(self.hits as f64 / total as f64)
        }
    }

    /// Number of domains with a stored preimage (diagnostics / fork-isolation
    /// tests: a deep copy must start at zero).
    pub fn slots_filled(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    /// Reset counters (tests / diagnostics; entries are kept).
    pub fn reset_counters(&mut self) {
        self.hits = 0;
        self.misses = 0;
        self.abi.hits = 0;
        self.abi.misses = 0;
    }
}

fn put_bytes<S: PreimageSink>(h: &mut S, tag: &[u8], bytes: &[u8]) {
    h.push_preimage(&(tag.len() as u64).to_be_bytes());
    h.push_preimage(tag);
    h.push_preimage(&(bytes.len() as u64).to_be_bytes());
    h.push_preimage(bytes);
}

fn put_u64<S: PreimageSink>(h: &mut S, tag: &[u8], v: u64) {
    put_bytes(h, tag, &v.to_be_bytes());
}

fn put_u128<S: PreimageSink>(h: &mut S, tag: &[u8], v: u128) {
    put_bytes(h, tag, &v.to_be_bytes());
}

fn put_bool<S: PreimageSink>(h: &mut S, tag: &[u8], v: bool) {
    put_bytes(h, tag, &[v as u8]);
}

fn put_addr<S: PreimageSink>(h: &mut S, tag: &[u8], v: &[u8; 32]) {
    put_bytes(h, tag, v);
}

/// Sort-buffer element types: the `Vec` + `sort_unstable` replacements for
/// the old `BTreeMap` sort buffers (same key `Ord`, so byte-identical
/// iteration order). Named once so the annotations stay readable and
/// `clippy::type_complexity` stays quiet.
type KeyPairAmount<'a> = (&'a ([u8; 32], [u8; 32]), &'a u64);
type KeyPairAmount128<'a> = (&'a ([u8; 32], [u8; 32]), &'a u128);
type PqKeyEntry<'a> = (&'a [u8; 32], &'a (crate::post_quantum::PqScheme, Vec<u8>));

/// A snapshot of the non-trie consensus state, cloned under the subsystem locks
/// and hashed without them. Hashing while holding every subsystem lock would
/// serialise every block behind the slowest one; cloning first costs a copy per
/// block and keeps the critical section short.
#[derive(Clone)]
pub struct CommitmentSnapshot {
    pub tokens: crate::token::TokenRegistry,
    pub staking: StakingLedger,
    pub orderbooks: OrderbookManager,
    pub order_escrow: HashMap<(u32, u64), EscrowRecord>,
    pub pmm: PrimaryMarketMaker,
    pub pmm_usdt_token: Option<[u8; 32]>,
    pub pmm_treasury: [u8; 32],
    pub contracts: ContractRegistry,
    /// Governance. It was the one consensus-visible subsystem left out of the digest,
    /// which meant a node and its peer could disagree about a proposal or a passed
    /// parameter change and still compute the same state root -- the disagreement would
    /// only surface later, as a forked validator set or a different block reward.
    pub governance: crate::governance::Governance,
    /// Committed oracle state. Prices decide whether an order is accepted
    /// (`SysCallPlaceOrder` / `place_order_settled` gate on them) and the
    /// breaker latch pauses trading, so two nodes holding different feeds
    /// would apply different blocks to the SAME root - the same class of split
    /// as an uncommitted staking ledger.
    pub oracle: crate::oracle::OracleState,
    /// On-chain session-key registry (phase 2): lazy registration, cumulative
    /// gas spend and terminal revocation, keyed by session pubkey.
    ///
    /// Uncommitted, a node that had revoked a session key would still agree on
    /// the state root with one that had not, and the two would then apply the
    /// same block's session transactions differently - the exact hole this
    /// module exists to close.
    ///
    /// CONDITIONAL: `commitment_digest` hashes this domain only when the
    /// registry is NON-EMPTY (see `session_keys_digest`), so a chain that has
    /// never registered a session key - every genesis KAT, every pre-phase-2
    /// snapshot - hashes byte-for-byte identically to before. The price is
    /// that an emptied registry must contribute nothing at all, not even a
    /// zero length prefix.
    pub session_keys: crate::zkml::SessionKeyRegistry,
    /// Committed bridge domain (`BridgeState`): the source-tx replay set, the
    /// parked withdrawal queue, the hourly rate-limit window and the escrow
    /// mirror behind `OpCode::SysCallBridge`.
    ///
    /// Uncommitted, a node that had credited a deposit would still agree on the
    /// state root with one that had not, and the two would then apply the same
    /// block's bridge transactions differently - the same class of split as an
    /// uncommitted staking ledger (and a replayable deposit is a mint bug).
    ///
    /// CONDITIONAL: `commitment_digest` hashes this domain only when it is
    /// NON-EMPTY (see `bridge_digest`), so a chain that has never bridged -
    /// every genesis KAT - hashes byte-for-byte identically to before and
    /// `COMMITMENT_VERSION` stays put. Like `session_keys`, an empty domain
    /// must contribute nothing at all, not even a zero length prefix.
    pub bridge: crate::bridge::BridgeState,
    /// Cross-shard replay sets (audit F1): the engine credit gate
    /// (`cross_shard_consumed`), the outbound-transfer log (`cross_shard_produced`
    /// as `(tx hash, produce height)` pairs) and the ack/bounce completion set
    /// (`cross_shard_completed` as tx hashes).
    ///
    /// A node that had consumed a message (or produced an outbound, or
    /// completed a lifecycle) must not report the same root as one that had
    /// not: the two would then apply the next block's cross-shard records
    /// differently under one root - a silent split, and a wiped consumed set
    /// is a double mint. Committing the sets turns any divergence into a root
    /// mismatch that snapshot verification and block sync refuse loudly.
    ///
    /// CONDITIONAL, exactly like `session_keys` / `bridge`: all three empty
    /// writes zero bytes, so a chain that never used cross-shard messaging -
    /// every genesis KAT, every single-shard snapshot - digests byte-for-byte
    /// identically to before and `COMMITMENT_VERSION` stays put.
    ///
    /// Callers pass SORTED vecs (the engine sorts its snapshots); the digest
    /// re-sorts defensively so a hand-built snapshot cannot fork by order.
    pub cross_shard_consumed: Vec<CrossShardKey>,
    pub cross_shard_produced: Vec<([u8; 32], u64)>,
    pub cross_shard_completed: Vec<[u8; 32]>,
    /// §9 CROSS-SHARD 2PC: the committed two-phase-commit records (the
    /// intermediate states of the cross-shard transfer lifecycle).
    ///
    /// The phase of a transfer decides where the VALUE is: prepared (the
    /// escrow is held by the source), committed (the target credited the
    /// recipient) or aborted (the source refunded the escrow). Two nodes that
    /// disagree about a phase disagree about who owns the value, so the
    /// records must move the state root exactly as re-applying the deciding
    /// block would.
    ///
    /// CONDITIONAL: the domain writes ZERO bytes when there is no 2PC
    /// record, so a chain that never used the 2PC hashes byte-for-byte
    /// identically to before.
    pub cross_shard_xpc: Vec<crate::xshard2pc::XpcRecord>,
}

/// Governance digest.
///
/// `Governance.proposals` and `Proposal.voters` are `HashMap`s, so they MUST be
/// normalised before hashing or two nodes with identical governance would compute
/// different roots -- the same trap `I2` in PROTOCOL.md calls out for every other
/// subsystem. Live tallies (`yes`/`no`/`abstain`) are included, not just the final
/// status, because a node that has counted a different set of votes has genuinely
/// different state even before finalization.
fn governance_digest<S: PreimageSink>(h: &mut S, g: &crate::governance::Governance) {
    use crate::governance::{ProposalStatus, VoteChoice};

    put_u64(h, b"gov_next_id", g.next_id);
    put_u64(h, b"gov_quorum_bps", g.quorum_bps);

    let mut proposals: Vec<(u64, &crate::governance::Proposal)> =
        g.proposals.iter().map(|(k, v)| (*k, v)).collect();
    proposals.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    put_u64(h, b"gov_proposals_len", proposals.len() as u64);
    for (id, p) in proposals {
        put_u64(h, b"gov_prop_id", id);
        put_bytes(h, b"gov_prop_proposer", &p.proposer);
        put_bytes(h, b"gov_prop_title", p.title.as_bytes());
        put_u64(h, b"gov_prop_action_tag", gov_action_tag(&p.action));
        put_u64(h, b"gov_prop_action_value", gov_action_value(&p.action));
        // The oracle publisher actions carry a key, not a number. Without this
        // the tag+value pair of "register 0x11.." and "register 0x22.." would be
        // identical bytes, so two nodes could hold different pending
        // registrations under the same root. It is emitted ONLY for the appended
        // variants: every action that existed before keeps exactly the preimage
        // it had, so no already-committed proposal changes its digest.
        if let crate::governance::GovAction::RegisterOraclePublisher(pk)
        | crate::governance::GovAction::UnregisterOraclePublisher(pk) = &p.action
        {
            put_addr(h, b"gov_prop_action_pubkey", pk);
        }
        if let crate::governance::GovAction::Signal(text) = &p.action {
            put_bytes(h, b"gov_prop_action_signal", text.as_bytes());
        }
        if let crate::governance::GovAction::SoftwareUpgrade { name, sha256, .. } = &p.action {
            put_bytes(h, b"gov_prop_action_upg_name", name.as_bytes());
            put_bytes(h, b"gov_prop_action_upg_sha", sha256);
        }
        put_u64(h, b"gov_prop_created_at", p.created_at);
        put_u64(h, b"gov_prop_voting_end", p.voting_end);
        // u128 tallies: split, because put_u64 only carries 64 bits.
        put_u64(h, b"gov_prop_yes_lo", p.yes as u64);
        put_u64(h, b"gov_prop_yes_hi", (p.yes >> 64) as u64);
        put_u64(h, b"gov_prop_no_lo", p.no as u64);
        put_u64(h, b"gov_prop_no_hi", (p.no >> 64) as u64);
        put_u64(h, b"gov_prop_abstain_lo", p.abstain as u64);
        put_u64(h, b"gov_prop_abstain_hi", (p.abstain >> 64) as u64);
        put_u64(
            h,
            b"gov_prop_status",
            match p.status {
                ProposalStatus::Open => 0,
                ProposalStatus::Passed => 1,
                ProposalStatus::Rejected => 2,
                ProposalStatus::Executed => 3,
            },
        );
        let mut voters: Vec<([u8; 32], VoteChoice)> =
            p.voters.iter().map(|(k, v)| (*k, *v)).collect();
        voters.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        put_u64(h, b"gov_prop_voters_len", voters.len() as u64);
        for (voter, choice) in voters {
            put_bytes(h, b"gov_voter", &voter);
            put_u64(
                h,
                b"gov_vote",
                match choice {
                    VoteChoice::Yes => 0,
                    VoteChoice::No => 1,
                    VoteChoice::Abstain => 2,
                },
            );
        }
        // E7: the frozen quorum base and the per-voter locked weights. Both
        // decide every future finalize of this proposal, so both move the
        // root. APPENDED inside the per-proposal block: a chain with no
        // proposals (every genesis KAT) never reaches these bytes, so its
        // digest is byte-identical to before and COMMITMENT_VERSION stays 4.
        put_u64(h, b"gov_prop_electorate_lo", p.electorate as u64);
        put_u64(h, b"gov_prop_electorate_hi", (p.electorate >> 64) as u64);
        let mut weights: Vec<([u8; 32], u128)> =
            p.weights.iter().map(|(k, v)| (*k, *v)).collect();
        weights.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        put_u64(h, b"gov_prop_weights_len", weights.len() as u64);
        for (voter, w) in weights {
            put_bytes(h, b"gov_weight_voter", &voter);
            put_u64(h, b"gov_weight_lo", w as u64);
            put_u64(h, b"gov_weight_hi", (w >> 64) as u64);
        }
    }

    // Applied parameters. Each is an Option, so the discriminant is hashed too --
    // otherwise `None` and `Some(0)` would collide.
    let ap = &g.applied;
    for (tag, v) in [
        (b"gov_applied_min_bond".as_slice(), ap.min_validator_bond),
        (
            b"gov_applied_equiv_slash".as_slice(),
            ap.equivocation_slash_bps,
        ),
        (
            b"gov_applied_commission".as_slice(),
            ap.default_commission_bps,
        ),
        (b"gov_applied_block_reward".as_slice(), ap.block_reward),
        (
            b"gov_applied_pmm_buffer".as_slice(),
            ap.pmm_redemption_buffer_bps,
        ),
    ] {
        match v {
            Some(x) => {
                put_u64(h, tag, 1);
                put_u64(h, tag, x);
            }
            None => put_u64(h, tag, 0),
        }
    }
    // min_gas_limit is SELF-CONDITIONAL (audit follow-up): it joined the
    // digest after genesis, so writing even a None discriminant would move
    // the genesis root (hard fork). Skipped-when-None keeps every pre-floor
    // preimage byte-identical; a set floor visibly enters the digest.
    if let Some(x) = ap.min_gas_limit {
        put_u64(h, b"gov_applied_min_gas_present", 1);
        put_u64(h, b"gov_applied_min_gas", x);
    }
    match &ap.signal {
        Some(s) => {
            put_u64(h, b"gov_applied_signal_present", 1);
            put_bytes(h, b"gov_applied_signal", s.as_bytes());
        }
        None => put_u64(h, b"gov_applied_signal_present", 0),
    }
}

/// Explicit discriminants, so the committed value cannot drift if the enum is
/// reordered.
fn gov_action_tag(a: &crate::governance::GovAction) -> u64 {
    use crate::governance::GovAction::*;
    match a {
        SetMinValidatorBond(_) => 0,
        SetEquivocationSlashBps(_) => 1,
        SetDefaultCommissionBps(_) => 2,
        SetBlockReward(_) => 3,
        SetPmmRedemptionBufferBps(_) => 4,
        SetGovernanceQuorumBps(_) => 5,
        Signal(_) => 6,
        RegisterOraclePublisher(_) => 7,
        UnregisterOraclePublisher(_) => 8,
        ResetOracleBreaker => 9,
        SetMinGasLimit(_) => 10,
        SoftwareUpgrade { .. } => 11,
        CancelUpgrade => 12,
    }
}

/// The numeric payload of an action, or 0 for the non-numeric ones.
fn gov_action_value(a: &crate::governance::GovAction) -> u64 {
    use crate::governance::GovAction::*;
    match a {
        SetMinValidatorBond(v)
        | SetEquivocationSlashBps(v)
        | SetDefaultCommissionBps(v)
        | SetBlockReward(v)
        | SetPmmRedemptionBufferBps(v)
        | SetGovernanceQuorumBps(v)
        | SetMinGasLimit(v) => *v,
        SoftwareUpgrade { height, .. } => *height,
        // The keyed/non-numeric actions carry no value here; the publisher key
        // is committed separately in `governance_digest`.
        Signal(_)
        | RegisterOraclePublisher(_)
        | UnregisterOraclePublisher(_)
        | ResetOracleBreaker
        | CancelUpgrade => 0,
    }
}

/// Stable numeric tag for the order enums.
///
/// Written out by hand rather than via `as u64`: these enums are not `Copy`,
/// and an explicit mapping keeps the committed values independent of any future
/// change to how the enums are laid out or ordered.
fn side_tag(s: &OrderSide) -> u64 {
    match s {
        OrderSide::Buy => 0,
        OrderSide::Sell => 1,
    }
}

fn order_type_tag(t: &OrderType) -> u64 {
    match t {
        OrderType::Limit => 0,
        OrderType::Market => 1,
    }
}

fn order_digest<S: PreimageSink>(h: &mut S, o: &Order) {
    put_u64(h, b"order_id", o.order_id);
    put_addr(h, b"trader", &o.trader);
    put_u64(h, b"side", side_tag(&o.side));
    put_u64(h, b"order_type", order_type_tag(&o.order_type));
    put_u64(h, b"price", o.price);
    put_u64(h, b"amount", o.amount);
    put_u64(h, b"filled", o.filled);
    put_u64(h, b"timestamp", o.timestamp);
}

fn book_digest<S: PreimageSink>(h: &mut S, book: &crate::orderbook::OrderbookActor) {
    put_u64(h, b"pair_id", book.pair_id as u64);
    put_u64(h, b"next_order_id", book.next_order_id);
    // NOTE: `book.version` (the RPC snapshot sequence) is INTENTIONALLY not
    // part of the preimage. It is write-only staleness metadata: no execution
    // path branches on it, so it cannot fork the chain, and keeping it out
    // is what lets a node that loaded a pre-version snapshot (version
    // defaulted to 0) agree byte-for-byte with a node that replayed the same
    // history from genesis (version N). Committing it would split those two
    // honest nodes and invalidate the pinned genesis root.
    put_u64(h, b"max_depth", book.max_depth as u64);

    // BTreeMap, so already ordered; hashed explicitly anyway so a switch to a
    // hash-ordered container cannot silently change the commitment.
    put_u64(h, b"bids_len", book.bids.len() as u64);
    for (Reverse(price), orders) in &book.bids {
        put_u64(h, b"bid_price", *price);
        put_u64(h, b"bid_orders", orders.len() as u64);
        for o in orders {
            order_digest(h, o);
        }
    }
    put_u64(h, b"asks_len", book.asks.len() as u64);
    for (price, orders) in &book.asks {
        put_u64(h, b"ask_price", *price);
        put_u64(h, b"ask_orders", orders.len() as u64);
        for o in orders {
            order_digest(h, o);
        }
    }
}

/// Commit the token registry.
///
/// Balances and total supply are already in the trie under their own key
/// domains, but that is not the whole actor. `allowances` gates
/// `TransferFrom` succeeding, `minter`/`paused`/`max_supply` gate minting and
/// transferring, and `next_nonce` derives the next token id. A node that
/// disagreed on any of those would agree on the state root, which is exactly the
/// class of divergence this module exists to prevent.
fn tokens_digest<S: PreimageSink>(h: &mut S, reg: &crate::token::TokenRegistry) {
    put_u64(h, b"tokens_next_nonce", reg.next_nonce);
    // Sorted by token id: `HashMap` order is not reproducible across nodes.
    // A `Vec` + `sort_unstable` replaces the old `BTreeMap` sort buffer: one
    // allocation and O(n log n) comparisons instead of one heap node per
    // entry, with byte-identical iteration order (same key `Ord`).
    let mut sorted: Vec<(&[u8; 32], &crate::token::TokenActor)> =
        reg.tokens.iter().collect();
    sorted.sort_unstable_by(|a, b| a.0.cmp(b.0));
    put_u64(h, b"tokens_len", sorted.len() as u64);
    for (id, t) in sorted {
        put_addr(h, b"token_id", id);
        let m = &t.metadata;
        put_bytes(h, b"token_name", m.name.as_bytes());
        put_bytes(h, b"token_symbol", m.symbol.as_bytes());
        put_bytes(h, b"token_description", m.description.as_bytes());
        put_bytes(h, b"token_decimals", &[m.decimals]);
        put_u64(h, b"token_total_supply", m.total_supply);
        match m.max_supply {
            Some(v) => {
                put_bool(h, b"token_has_max_supply", true);
                put_u64(h, b"token_max_supply", v);
            }
            None => put_bool(h, b"token_has_max_supply", false),
        }
        put_addr(h, b"token_minter", &m.minter);
        put_bool(h, b"token_paused", m.paused);

        let mut bals: Vec<(&[u8; 32], &u64)> =
            t.balances.iter().collect();
        bals.sort_unstable_by(|a, b| a.0.cmp(b.0));
        put_u64(h, b"token_balances_len", bals.len() as u64);
        for (acct, bal) in bals {
            put_addr(h, b"token_balance_owner", acct);
            put_u64(h, b"token_balance", *bal);
        }

        let mut alls: Vec<KeyPairAmount<'_>> = t.allowances.iter().collect();
        alls.sort_unstable_by(|a, b| a.0.cmp(b.0));
        put_u64(h, b"token_allowances_len", alls.len() as u64);
        for ((owner, spender), amt) in alls {
            put_addr(h, b"token_allowance_owner", owner);
            put_addr(h, b"token_allowance_spender", spender);
            put_u64(h, b"token_allowance", *amt);
        }
    }
}

fn staking_digest<S: PreimageSink>(h: &mut S, l: &StakingLedger) {
    // Sorted by validator id: HashMap order is not reproducible across nodes.
    // `Vec` + `sort_unstable` sort buffer (one allocation, same key `Ord`).
    let mut vals: Vec<(&[u8; 32], &crate::staking::ValidatorStake)> =
        l.validators.iter().collect();
    vals.sort_unstable_by(|a, b| a.0.cmp(b.0));
    put_u64(h, b"validators_len", vals.len() as u64);
    for (id, s) in vals {
        put_addr(h, b"validator", id);
        put_u64(h, b"self_bond", s.self_bond);
        put_u64(h, b"delegated", s.delegated);
        put_u64(h, b"commission_bps", s.commission_bps);
        put_u64(h, b"pending_rewards", s.pending_rewards);
        put_u64(h, b"total_slashed", s.total_slashed);
        put_u64(h, b"missed", s.missed as u64);
        put_u64(h, b"last_downtime_penalty", s.last_downtime_penalty);
    }

    let mut dels: Vec<KeyPairAmount<'_>> = l.delegations.iter().collect();
    dels.sort_unstable_by(|a, b| a.0.cmp(b.0));
    put_u64(h, b"delegations_len", dels.len() as u64);
    for ((val, del), amt) in dels {
        put_addr(h, b"del_val", val);
        put_addr(h, b"del_owner", del);
        put_u64(h, b"del_amount", *amt);
    }

    let mut rews: Vec<KeyPairAmount<'_>> = l.delegator_rewards.iter().collect();
    rews.sort_unstable_by(|a, b| a.0.cmp(b.0));
    put_u64(h, b"delegator_rewards_len", rews.len() as u64);
    for ((val, del), amt) in rews {
        put_addr(h, b"rew_val", val);
        put_addr(h, b"rew_owner", del);
        put_u64(h, b"rew_amount", *amt);
    }

    // A Vec: order is part of the value, so it is hashed as-is.
    put_u64(h, b"unbonding_len", l.unbonding.len() as u64);
    for e in &l.unbonding {
        unbonding_digest(h, e);
    }

    let mut wths: Vec<KeyPairAmount<'_>> = l.withdrawable.iter().collect();
    wths.sort_unstable_by(|a, b| a.0.cmp(b.0));
    put_u64(h, b"withdrawable_len", wths.len() as u64);
    for ((val, owner), amt) in wths {
        put_addr(h, b"wth_val", val);
        put_addr(h, b"wth_owner", owner);
        put_u64(h, b"wth_amount", *amt);
    }

    put_u64(h, b"total_burned", l.total_burned);

    // E2 rewards-pool domain, CONDITIONAL like every domain in this module:
    // a ledger that never minted rewards (rewards_pool == 0 AND
    // rewards_minted == 0 — every genesis KAT) writes zero bytes, so the
    // genesis root stays byte-identical and COMMITMENT_VERSION stays at 4.
    // Once any reward is minted the domain is always present (minted is
    // monotonic, so it cannot flap back to absent), and every value that
    // decides future mints/payouts is committed.
    if l.rewards_pool != 0 || l.rewards_minted != 0 {
        put_bytes(h, b"staking_rewards_domain", b"STAKING_REWARDS_V1");
        put_u64(h, b"rewards_pool", l.rewards_pool);
        put_u64(h, b"rewards_minted", l.rewards_minted);
    }

    // E7 governance-lock domain, CONDITIONAL like the rewards domain above:
    // empty whenever no vote is open (every genesis KAT, and every ledger
    // whose proposals all finalized — `unlock_governance` removes the entry
    // at zero), so those chains digest byte-for-byte identically to before
    // and COMMITMENT_VERSION stays at 4. A non-empty lock decides whether
    // the next unbond/undelegate applies, so it must move the root.
    if !l.locked_governance.is_empty() {
        put_bytes(h, b"staking_gov_locks_domain", b"STAKING_GOV_LOCKS_V1");
        let mut locks: Vec<(&[u8; 32], &u64)> =
            l.locked_governance.iter().collect();
        locks.sort_unstable_by(|a, b| a.0.cmp(b.0));
        put_u64(h, b"gov_locks_len", locks.len() as u64);
        for (owner, amt) in locks {
            put_addr(h, b"gov_lock_owner", owner);
            put_u64(h, b"gov_lock_amount", *amt);
        }
    }

    // ---- Equivocation dedup sets, PQ keys and vesting schedules ----
    //
    // FOUR CONDITIONAL DOMAINS, each one gated on ITS OWN map being
    // non-empty - exactly the contract the session-key and bridge domains
    // use (see `CommitmentSnapshot::session_keys` / `::bridge`): an EMPTY
    // domain writes ZERO bytes, so a chain that never used the feature
    // digests byte-for-byte identically to before and `COMMITMENT_VERSION`
    // stays put. That is what keeps the pinned genesis KAT
    // (`tests/genesis_root_known_answer_tests.rs`) valid without re-pinning
    // it.
    //
    // APPENDED AFTER every pre-existing staking domain, so every already
    // committed preimage keeps exactly the byte sequence it had: a chain
    // with a rewards pool AND a dedup set digests
    // `[...rewards][...gov-locks][...dedup]`, and the old preimage is a
    // strict PREFIX of the new one.
    //
    // WHY EACH ONE MATTERS (an uncommitted field is a silent fork):
    //
    //  * `equivocation_dedup` / `pq_equivocation_dedup`: the per-offense
    //    "already slashed" sets. They decide whether the SAME equivocation
    //    burns 5% again on the next block. Two nodes that disagree about
    //    the set disagree about the BURN, and the burn moves the pool
    //    balance and the validator's stake - a divergence that must never
    //    be invisible to the root.
    //  * `validator_pq_keys`: the registered post-quantum key + scheme per
    //    validator. It is the key the PQ equivocation evidence is verified
    //    against, so two nodes holding different keys reach DIFFERENT
    //    verdicts on the same evidence (slash vs no slash) under one root.
    //  * `vesting_schedules`: the per-account vesting floor. It gates
    //    whether a spend is allowed at all, so a node with a different
    //    schedule accepts a transaction the other refuses - under the same
    //    root.
    if !l.equivocation_dedup.is_empty() {
        put_bytes(h, b"staking_equiv_dedup_domain", b"STAKING_EQUIV_DEDUP_V1");
        // Sorted: a `HashSet` iterates in hash order, which differs between
        // processes (PROTOCOL.md I2 - two identical states must not hash to
        // different bytes).
        let mut keys: Vec<&[u8; 32]> = l.equivocation_dedup.iter().collect();
        keys.sort();
        put_u64(h, b"equiv_dedup_len", keys.len() as u64);
        for key in keys {
            put_addr(h, b"equiv_dedup_key", key);
        }
    }

    if !l.pq_equivocation_dedup.is_empty() {
        put_bytes(
            h,
            b"staking_pq_equiv_dedup_domain",
            b"STAKING_PQ_EQUIV_DEDUP_V1",
        );
        let mut keys: Vec<&[u8; 32]> = l.pq_equivocation_dedup.iter().collect();
        keys.sort();
        put_u64(h, b"pq_equiv_dedup_len", keys.len() as u64);
        for key in keys {
            put_addr(h, b"pq_equiv_dedup_key", key);
        }
    }

    if !l.validator_pq_keys.is_empty() {
        put_bytes(h, b"staking_pq_keys_domain", b"STAKING_PQ_KEYS_V1");
        let mut keys: Vec<PqKeyEntry<'_>> = l.validator_pq_keys.iter().collect();
        keys.sort_unstable_by(|a, b| a.0.cmp(b.0));
        put_u64(h, b"pq_keys_len", keys.len() as u64);
        for (validator, (scheme, pubkey)) in keys {
            put_addr(h, b"pq_key_validator", validator);
            // The scheme id is the discriminant of the verification path:
            // the same key bytes mean different things under Falcon-512 and
            // under the hybrid scheme, so it is committed explicitly (never
            // derived from the key length).
            put_u64(h, b"pq_key_scheme", scheme.id() as u64);
            // `put_bytes` writes the length explicitly, so a key cannot be
            // confused with a shorter one plus padding.
            put_bytes(h, b"pq_key_pubkey", pubkey);
        }
    }

    if !l.vesting_schedules.is_empty() {
        put_bytes(h, b"staking_vesting_domain", b"STAKING_VESTING_V1");
        // Already a `BTreeMap` (ordered by account); walked in that order
        // anyway so a container swap cannot silently change the commitment.
        put_u64(h, b"vesting_len", l.vesting_schedules.len() as u64);
        for (account, s) in &l.vesting_schedules {
            put_addr(h, b"vesting_account", account);
            put_u64(h, b"vesting_total", s.total_allocation);
            put_u64(h, b"vesting_start", s.start_timestamp);
            put_u64(h, b"vesting_cliff", s.cliff_duration_secs);
            put_u64(h, b"vesting_duration", s.vesting_duration_secs);
            put_u64(h, b"vesting_claimed", s.claimed_amount);
        }
    }

    // LAZY (F1) DELEGATOR-REWARD ACCUMULATOR — CONDITIONAL domain, exactly
    // like the rewards / gov-locks / dedup domains above: a ledger that never
    // distributed a delegator reward has an EMPTY accumulator map and an EMPTY
    // checkpoint map, so this writes ZERO bytes and the pinned genesis
    // known-answer vectors stay byte-identical (COMMITMENT_VERSION stays put).
    //
    // WHY IT MUST BE COMMITTED (an uncommitted field is a silent fork): the
    // accumulator IS the delegator payout formula now. Two nodes holding
    // different `reward_per_token` values compute DIFFERENT entitlements for
    // the same delegator under the same state root — and the payout is a
    // transfer of real coins. Same for the checkpoints: a stale checkpoint
    // pays a delegator twice (or not at all) for the same accrual.
    //
    // Everything that decides a future payout is committed: the rate, the
    // allocated/remaining pools, the carried division remainder AND its
    // denominator (the remainder only means something against the delegated
    // total it was carried from).
    if !l.reward_accumulators.is_empty() || !l.delegator_reward_checkpoints.is_empty() {
        put_bytes(
            h,
            b"staking_reward_accumulator_domain",
            b"STAKING_REWARD_ACC_V1",
        );
        let mut accs: Vec<(&[u8; 32], &crate::staking::ValidatorRewardState)> =
            l.reward_accumulators.iter().collect();
        accs.sort_unstable_by(|a, b| a.0.cmp(b.0));
        put_u64(h, b"reward_acc_len", accs.len() as u64);
        for (id, a) in accs {
            put_addr(h, b"reward_acc_validator", id);
            put_u128(h, b"reward_acc_per_token", a.reward_per_token);
            put_u128(h, b"reward_acc_historical", a.historical_rewards);
            put_u128(h, b"reward_acc_remaining", a.remaining_rewards);
            put_u128(h, b"reward_acc_remainder", a.remainder);
            put_u64(h, b"reward_acc_remainder_den", a.remainder_den);
        }
        let mut cps: Vec<KeyPairAmount128<'_>> =
            l.delegator_reward_checkpoints.iter().collect();
        cps.sort_unstable_by(|a, b| a.0.cmp(b.0));
        put_u64(h, b"reward_checkpoint_len", cps.len() as u64);
        for ((val, del), cp) in cps {
            put_addr(h, b"reward_cp_validator", val);
            put_addr(h, b"reward_cp_owner", del);
            put_u128(h, b"reward_cp_value", *cp);
        }
    }

    // ---- Downtime-jail, commission-schedule and redelegation-lock domains ----
    //
    // THREE CONDITIONAL DOMAINS, each one gated on ITS OWN map being
    // non-empty — exactly the contract every domain above uses: an EMPTY map
    // writes ZERO bytes, so a chain that never jailed a validator, never
    // announced a commission change and never redelegated digests
    // byte-for-byte identically to before and `COMMITMENT_VERSION` stays put
    // (the pinned genesis KAT stays valid).
    //
    // APPENDED AFTER every pre-existing staking domain in STRUCT FIELD ORDER
    // (jail, commission_schedule, redelegation_lock — the order the fields
    // are declared in `StakingLedger`), so every already-committed preimage
    // keeps exactly the byte sequence it had.
    //
    // WHY EACH ONE MATTERS (an uncommitted field is a silent fork):
    //
    //  * `jail`: a jailed validator is EXCLUDED from the validator set until
    //    `unjail` re-admits it. Two nodes that disagreed about the jail map
    //    would derive DIFFERENT validator sets — and the set is what every
    //    quorum check runs against — under one root.
    //  * `commission_schedule`: the pending change and the cooldown basis
    //    decide the FUTURE commission rate, which decides future delegator
    //    payouts (real coins). A stale schedule pays delegators differently.
    //  * `redelegation_lock`: the lock decides whether the next `redelegate`
    //    from a position is ADMITTED at all — one node accepts a transaction
    //    the other refuses, under the same root.
    if !l.jail.is_empty() {
        put_bytes(h, b"staking_jail_domain", b"STAKING_JAIL_V1");
        let mut jailed: Vec<(&[u8; 32], &crate::staking::JailRecord)> =
            l.jail.iter().collect();
        jailed.sort_unstable_by(|a, b| a.0.cmp(b.0));
        put_u64(h, b"jail_len", jailed.len() as u64);
        for (id, r) in jailed {
            put_addr(h, b"jail_validator", id);
            put_u64(h, b"jail_jailed_at", r.jailed_at_height);
            put_u64(h, b"jail_release", r.release_height);
        }
    }

    if !l.commission_schedule.is_empty() {
        put_bytes(h, b"staking_commission_domain", b"STAKING_COMMISSION_V1");
        let mut scheds: Vec<(&[u8; 32], &crate::staking::CommissionSchedule)> =
            l.commission_schedule.iter().collect();
        scheds.sort_unstable_by(|a, b| a.0.cmp(b.0));
        put_u64(h, b"commission_len", scheds.len() as u64);
        for (id, s) in scheds {
            put_addr(h, b"commission_validator", id);
            match s.last_effective_height {
                Some(x) => {
                    put_u64(h, b"commission_last_present", 1);
                    put_u64(h, b"commission_last", x);
                }
                None => put_u64(h, b"commission_last_present", 0),
            }
            match &s.pending {
                Some(p) => {
                    put_bool(h, b"commission_has_pending", true);
                    put_u64(h, b"commission_pending_bps", p.new_bps);
                    put_u64(h, b"commission_pending_effective", p.effective_height);
                    put_u64(h, b"commission_pending_announced", p.announced_height);
                }
                None => put_bool(h, b"commission_has_pending", false),
            }
        }
    }

    if !l.redelegation_lock.is_empty() {
        put_bytes(
            h,
            b"staking_redelegation_lock_domain",
            b"STAKING_REDELEGATION_LOCK_V1",
        );
        let mut locks: Vec<KeyPairAmount<'_>> = l.redelegation_lock.iter().collect();
        locks.sort_unstable_by(|a, b| a.0.cmp(b.0));
        put_u64(h, b"redelegation_lock_len", locks.len() as u64);
        for ((val, owner), until) in locks {
            put_addr(h, b"relock_validator", val);
            put_addr(h, b"relock_owner", owner);
            put_u64(h, b"relock_until", *until);
        }
    }
}

fn unbonding_digest<S: PreimageSink>(h: &mut S, e: &UnbondingEntry) {
    put_addr(h, b"unbond_validator", &e.validator);
    match &e.owner {
        Some(o) => {
            put_bool(h, b"unbond_has_owner", true);
            put_addr(h, b"unbond_owner", o);
        }
        None => put_bool(h, b"unbond_has_owner", false),
    }
    put_u64(h, b"unbond_amount", e.amount);
    put_u64(h, b"unbond_release_at", e.release_at);
}

fn pmm_digest<S: PreimageSink>(
    h: &mut S,
    p: &PrimaryMarketMaker,
    usdt: &Option<[u8; 32]>,
    treasury: &[u8; 32],
) {
    put_u128(h, b"pmm_minted_nano", p.minted_nano);
    put_u128(h, b"pmm_reserve_micro", p.reserve_micro);
    put_u128(h, b"pmm_redemption_buffer_micro", p.redemption_buffer_micro);
    put_u128(h, b"pmm_depth_cap_nano", p.depth_cap_nano);
    put_u64(h, b"pmm_base_price_micro", p.base_price_micro);
    match usdt {
        Some(t) => {
            put_bool(h, b"pmm_has_usdt", true);
            put_addr(h, b"pmm_usdt", t);
        }
        None => put_bool(h, b"pmm_has_usdt", false),
    }
    put_addr(h, b"pmm_treasury", treasury);
}

fn contracts_digest<S: PreimageSink>(h: &mut S, reg: &ContractRegistry) {
    contracts_digest_inner(h, reg, None)
}

/// The contracts domain with an optional per-contract ABI JSON cache.
///
/// `cache == None` is the reference path (every ABI re-serialized, exactly as
/// before). `Some` enables the content-keyed cache: the cached JSON is only
/// used when the contract's ABI fingerprint matches, so the bytes fed are
/// identical either way. See [`AbiJsonCache`].
fn contracts_digest_inner<S: PreimageSink>(
    h: &mut S,
    reg: &ContractRegistry,
    mut cache: Option<&mut AbiJsonCache>,
) {
    put_u64(h, b"contracts_next_nonce", reg.next_nonce);
    let mut sorted: Vec<(&[u8; 32], &crate::contract::Contract)> =
        reg.contracts.iter().collect();
    sorted.sort_unstable_by(|a, b| a.0.cmp(b.0));
    put_u64(h, b"contracts_len", sorted.len() as u64);
    for (addr, c) in sorted {
        put_addr(h, b"contract_addr", addr);
        put_addr(h, b"contract_creator", &c.creator);
        put_addr(h, b"contract_code_hash", &c.code_hash);
        put_u64(h, b"contract_created_at", c.created_at);
        put_bool(h, b"contract_paused", c.paused);

        // The ABI manifest is part of the contract's interface: it decides
        // which calls are valid and how their arguments are decoded, so two
        // nodes holding different manifests must NOT report the same state
        // root.
        //
        // The JSON serialization is the most expensive single item in this
        // domain (string building + allocation per contract per commit). When
        // a cache is supplied, the JSON is reused across commits for every
        // contract whose ABI fingerprint is unchanged; the bytes fed are
        // identical either way (the cache is keyed by content, never by wall
        // clock — see `AbiJsonCache`).
        match &c.abi {
            Some(abi) => {
                put_bool(h, b"contract_has_abi", true);
                match cache.as_mut() {
                    Some(c) => {
                        let json = c.json_for(addr, abi);
                        put_bytes(h, b"contract_abi", &json);
                    }
                    None => put_bytes(h, b"contract_abi", abi.to_json().as_bytes()),
                }
            }
            None => put_bool(h, b"contract_has_abi", false),
        }

        // The verified-source fingerprint (P2-15). CONDITIONAL DOMAIN: it is
        // committed ONLY when present. An unverified contract (the only kind
        // that existed before this field) contributes byte-identically nothing,
        // so legacy chains keep their exact state root; the moment a source is
        // registered the domain appears in full. (Same pattern as the
        // session-keys digest below.)
        if let Some(sh) = &c.source_hash {
            put_bool(h, b"contract_has_source", true);
            put_addr(h, b"contract_source_hash", sh);
        }

        // Storage is where a contract's balances and counters actually live.
        // Committing only the code hash would let a node prove a contract
        // exists while proving nothing about what it holds.
        // Signed-key order matches the old `BTreeMap<&i64, _>` buffer exactly.
        let mut slots: Vec<(&i64, &i64)> =
            c.storage.iter().collect();
        slots.sort_unstable_by(|a, b| a.0.cmp(b.0));
        put_u64(h, b"contract_storage_len", slots.len() as u64);
        for (k, v) in slots {
            put_u64(h, b"contract_slot", *k as u64);
            put_u64(h, b"contract_value", *v as u64);
        }
    }
}

fn escrow_digest<S: PreimageSink>(h: &mut S, escrow: &HashMap<(u32, u64), EscrowRecord>) {
    let mut sorted: Vec<(&(u32, u64), &EscrowRecord)> =
        escrow.iter().collect();
    sorted.sort_unstable_by(|a, b| a.0.cmp(b.0));
    put_u64(h, b"escrow_len", sorted.len() as u64);
    for ((pair, order), rec) in sorted {
        put_u64(h, b"escrow_pair", *pair as u64);
        put_u64(h, b"escrow_order", *order);
        put_addr(h, b"escrow_trader", &rec.trader);
        put_u64(h, b"escrow_base", rec.locked_base_stell);
        put_u64(h, b"escrow_quote", rec.locked_quote_wusdt);
        // The SVM path locks a BUY's quote in native units instead of wUSDT;
        // leaving this field out of the digest would let two nodes holding
        // different native escrow report the same state root.
        put_u64(h, b"escrow_quote_native", rec.locked_quote_native);
    }
}

/// Oracle digest.
///
/// `OracleState` already stores its collections as `BTreeSet`/`BTreeMap`
/// (order is a function of the contents), so unlike the `HashMap` subsystems
/// there is nothing to re-sort here - but every length is still written
/// explicitly, so a publisher set and a feed map cannot trade bytes and the
/// same framing rules apply as everywhere else in this module.
fn oracle_digest<S: PreimageSink>(h: &mut S, o: &crate::oracle::OracleState) {
    // The latch pauses all trading: it is state, not a cache.
    put_bool(h, b"oracle_breaker_tripped", o.breaker_tripped);

    put_u64(h, b"oracle_publishers_len", o.publishers.len() as u64);
    for publisher in &o.publishers {
        put_addr(h, b"oracle_publisher", publisher);
    }

    put_u64(h, b"oracle_feeds_len", o.feeds.len() as u64);
    for (asset, feed) in &o.feeds {
        put_bytes(h, b"oracle_feed_asset", asset.as_bytes());
        put_u64(h, b"oracle_feed_price", feed.price_micro_usd);
        put_u64(h, b"oracle_feed_timestamp", feed.timestamp);
        put_addr(h, b"oracle_feed_publisher", &feed.publisher);
    }
}

/// Session-key registry digest.
///
/// CONDITIONAL DOMAIN: the caller only invokes this when the registry is
/// non-empty. Nothing about the framing is conditional INSIDE - lengths are
/// still explicit and the `BTreeMap` iteration is already sorted by session
/// pubkey - so the moment a key registers the domain appears in full, and the
/// moment the last one is gone the digest is byte-identical to a chain that
/// never had one (which is what keeps `tests/genesis_root_known_answer_tests.rs`
/// pinned without touching its pins).
///
/// Every field of the record is committed: `gas_spent` because two nodes that
/// disagreed on how much budget was left would accept different next
/// transactions under the same root, `revoked` because revocation IS a
/// consensus decision, and the copied ceilings for the same reason the grant's
/// own parameters are checked - they decide what executes next.
fn session_keys_digest<S: PreimageSink>(h: &mut S, reg: &crate::zkml::SessionKeyRegistry) {
    put_u64(h, b"session_keys_len", reg.entries.len() as u64);
    for (pk, r) in &reg.entries {
        put_addr(h, b"session_key", pk);
        put_addr(h, b"session_master", &r.master);
        put_u64(h, b"session_valid_until", r.valid_until);
        put_u64(h, b"session_max_gas_spend", r.max_gas_spend);
        put_u64(h, b"session_gas_spent", r.gas_spent);
        put_u64(h, b"session_scope", r.scope);
        put_u64(h, b"session_max_value_per_tx", r.max_value_per_tx);
        put_bool(h, b"session_revoked", r.revoked);
    }
}

/// Bridge domain digest.
///
/// CONDITIONAL DOMAIN: the caller only invokes this when the domain is
/// NON-EMPTY (see `BridgeState::is_empty`), so a chain that has never bridged
/// - every genesis KAT - digests byte-for-byte identically to before and
///   `COMMITMENT_VERSION` stays put. Nothing about the framing is conditional
///   INSIDE: lengths are explicit and the containers are `BTreeSet`/`BTreeMap`
///   (already ordered by their keys, like the oracle domain), so PROTOCOL.md I2
///   holds - two nodes with identical bridge state hash identical bytes.
///
/// Every field of the domain is committed, because every field of it DECIDES
/// THE NEXT BLOCK: the replay set decides whether a deposit credits again (a
/// disagreement is a double mint), the queue and its id counter decide which
/// release applies and whether it is time-locked, the rate window decides
/// whether the next withdrawal is admitted, and the escrow mirror reports how
/// much value the bridge holds. Omitting any of them would let two nodes
/// apply the same block to the same root and then disagree - exactly the hole
/// `tests/state_root_completeness_tests.rs` and I1 exist to close.
fn bridge_digest<S: PreimageSink>(h: &mut S, b: &crate::bridge::BridgeState) {
    put_u64(h, b"bridge_next_withdrawal_id", b.next_withdrawal_id);
    put_u64(h, b"bridge_hourly_withdrawn", b.hourly_withdrawn);
    put_u64(h, b"bridge_last_rate_limit_reset", b.last_rate_limit_reset);
    put_u64(h, b"bridge_escrow_balance", b.escrow_balance);
    put_u64(h, b"bridge_hourly_deposited", b.hourly_deposited);
    put_u64(h, b"bridge_last_deposit_reset", b.last_deposit_reset);
    put_u64(h, b"bridge_total_minted", b.total_minted);
    put_u64(h, b"bridge_next_dispute_id", b.next_dispute_id);

    put_u64(h, b"bridge_records_len", b.deposit_records.len() as u64);
    for (hash, r) in &b.deposit_records {
        put_addr(h, b"bridge_rec_hash", hash);
        put_addr(h, b"bridge_recipient", &r.recipient);
        put_u64(h, b"bridge_rec_amount", r.amount);
        put_u64(
            h,
            b"bridge_rec_chain",
            match r.chain {
                crate::bridge::SupportedChain::Ton => 0,
                crate::bridge::SupportedChain::Arbitrum => 1,
                crate::bridge::SupportedChain::Ethereum => 2,
                crate::bridge::SupportedChain::Solana => 3,
            },
        );
        put_bool(h, b"bridge_rec_via_quorum", r.via_quorum);
        put_u64(h, b"bridge_rec_deposited_at", r.deposited_at);
        put_bool(h, b"bridge_rec_disputed", r.disputed);
    }

    put_u64(h, b"bridge_disputes_len", b.disputes.len() as u64);
    for (id, d) in &b.disputes {
        put_u64(h, b"bridge_dispute_id", *id);
        put_addr(h, b"bridge_dispute_hash", &d.source_tx_hash);
        put_addr(h, b"bridge_dispute_challenger", &d.challenger);
        put_addr(h, b"bridge_dispute_recipient", &d.recipient);
        put_u64(h, b"bridge_dispute_amount", d.amount);
        put_u64(h, b"bridge_dispute_bond", d.bond);
        put_u64(h, b"bridge_dispute_deadline", d.deadline);
        put_bool(h, b"bridge_dispute_resolved", d.resolved);
        put_bool(h, b"bridge_dispute_confirmed", d.confirmed);
    }

    put_u64(h, b"bridge_replay_len", b.processed_source_txs.len() as u64);
    for tx in &b.processed_source_txs {
        put_addr(h, b"bridge_source_tx", tx);
    }

    put_u64(h, b"bridge_pending_len", b.pending_withdrawals.len() as u64);
    for (id, w) in &b.pending_withdrawals {
        put_u64(h, b"bridge_req_id", *id);
        put_addr(h, b"bridge_req_sender", &w.sender);
        put_u64(
            h,
            b"bridge_req_target_chain",
            match w.target_chain {
                crate::bridge::SupportedChain::Ton => 0,
                crate::bridge::SupportedChain::Arbitrum => 1,
                crate::bridge::SupportedChain::Ethereum => 2,
                crate::bridge::SupportedChain::Solana => 3,
            },
        );
        put_bytes(h, b"bridge_req_target_address", w.target_address.as_bytes());
        put_u64(h, b"bridge_req_amount", w.amount);
        put_u64(h, b"bridge_req_requested_at", w.requested_at);
        put_u64(h, b"bridge_req_unlock_at", w.unlock_at);
        put_bool(h, b"bridge_req_executed", w.executed);
    }
}

/// §2 zkML model-registry domain digest.
///
/// CONDITIONAL DOMAIN, exactly like the session-key / bridge
/// domains: the caller only invokes this when the registry is NON-EMPTY (see
/// [`write_zkml_models_domain`)), so a chain that has never registered a model
/// - every genesis KAT - digests byte-for-byte identically to before and
///   [`COMMITMENT_VERSION`] stays at 4. Nothing about the framing is conditional
///   INSIDE: lengths are explicit and the registry is a `BTreeMap` (already
///   ordered by `model_id`, like the oracle domain), so PROTOCOL.md I2 holds -
///   two nodes with identical registries hash identical bytes.
///
/// Every field that decides the next verification is committed: the `model_id`
/// the proof names, the `model_hash` the proof is matched against, and the full
/// weights/biases/dims the re-execution actually runs. Omitting any of them
/// would let two nodes verify the same proof against different weights under
/// one root - exactly the hole `tests/state_root_completeness_tests.rs` and I1
/// exist to close.
fn zkml_models_digest_inner<S: PreimageSink>(h: &mut S, reg: &crate::zkml::ZkMlModelRegistry) {
    write_zkml_models_domain(h, reg);
}

/// Fold the §2 zkML model registry into an existing hasher.
///
/// CONDITIONAL: an EMPTY registry writes zero bytes, so appending this
/// unconditionally keeps the genesis root (and every pre-§2 snapshot root)
/// byte-identical. Inside the domain nothing is conditional: `model_id`s are
/// walked in `BTreeMap` order and every collection's length is written, so two
/// different registries cannot encode to the same preimage.
pub fn write_zkml_models_domain<S: PreimageSink>(h: &mut S, reg: &crate::zkml::ZkMlModelRegistry) {
    if reg.is_empty() {
        return;
    }
    put_bytes(h, b"zkml_models_domain", b"ZKML_MODELS_V1");
    put_u64(h, b"zkml_models_len", reg.models.len() as u64);
    for (model_id, rec) in &reg.models {
        put_addr(h, b"zkml_model_id", model_id);
        put_bytes(h, b"zkml_model_hash", &rec.model_hash);
        put_u64(h, b"zkml_model_layers_len", rec.model.layers.len() as u64);
        for layer in &rec.model.layers {
            put_u64(h, b"zkml_layer_in_dim", layer.in_dim as u64);
            put_u64(h, b"zkml_layer_out_dim", layer.out_dim as u64);
            put_u64(h, b"zkml_layer_weights_len", layer.weights.len() as u64);
            for w in &layer.weights {
                put_u64(h, b"zkml_weight", *w as u64);
            }
            put_u64(h, b"zkml_layer_biases_len", layer.biases.len() as u64);
            for b in &layer.biases {
                put_u64(h, b"zkml_bias", *b as u64);
            }
        }
    }
}

/// Standalone digest of the §2 model registry (empty registry digests the
/// empty preimage, matching the zero-bytes conditional contract above).
pub fn zkml_models_digest(reg: &crate::zkml::ZkMlModelRegistry) -> [u8; 32] {
    let mut h = Sha256::new();
    write_zkml_models_domain(&mut h, reg);
    h.finalize().into()
}

/// Fold the §2 zkML VERIFYING-KEY set into an existing hasher.
///
/// CONDITIONAL, exactly like every domain in this module: while NO record
/// carries a VK this writes zero bytes, so appending it unconditionally
/// keeps the genesis root (and every pre-attestation snapshot root) byte-identical
/// and [`COMMITMENT_VERSION`] stays at 4. Inside the domain nothing is
/// conditional: `model_id`s are walked in `BTreeMap` order and every
/// collection's length is written, so two different key sets cannot encode
/// to the same preimage (PROTOCOL.md I2).
///
/// Committed per key: the `model_id` the proof names, the `spec_hash` the
/// verify handler matches on, the full `spec_bytes` (a node that disagreed on
/// the key would verify different proofs under one root), the I/O shape the
/// handler pins, and the setup attestation (which ceremony this key claims).
/// APPENDED after the models domain, so every pre-attestation preimage keeps
/// exactly the byte sequence it had.
pub fn write_zkml_vks_domain<S: PreimageSink>(h: &mut S, reg: &crate::zkml::ZkMlModelRegistry) {
    if !reg.has_any_spec() {
        return;
    }
    put_bytes(h, b"zkml_vks_domain", b"ZKML_VKS_V1");
    let keyed: Vec<([u8; 32], &crate::zkml_attestation::ModelSpec)> = reg
        .models
        .iter()
        .filter_map(|(id, rec)| rec.spec.as_ref().map(|vk| (*id, vk)))
        .collect();
    put_u64(h, b"zkml_vks_len", keyed.len() as u64);
    for (model_id, vk) in keyed {
        put_addr(h, b"zkml_vk_model_id", &model_id);
        put_bytes(h, b"zkml_vk_hash", &vk.spec_hash);
        put_u64(h, b"zkml_vk_in_dim", vk.in_dim);
        put_u64(h, b"zkml_vk_out_dim", vk.out_dim);
        put_u64(h, b"zkml_vk_n_public", vk.n_public_inputs);
        put_bytes(h, b"zkml_vk_bytes", &vk.spec_bytes);
        put_bytes(h, b"zkml_vk_attestation", &vk.setup_attestation);
    }
}

/// Standalone digest of the §2 VK set (no key anywhere digests the empty
/// preimage, matching the zero-bytes conditional contract above).
pub fn zkml_vks_digest(reg: &crate::zkml::ZkMlModelRegistry) -> [u8; 32] {
    let mut h = Sha256::new();
    write_zkml_vks_domain(&mut h, reg);
    h.finalize().into()
}

/// Write the commitment preimage into an existing hasher.
///
/// Split out of [`commitment_digest`] so digest variants below can share
/// the EXACT same byte sequence. The split is behaviour
/// preserving by construction: `commitment_digest` still calls this and
/// finalizes, so its output is byte-for-byte unchanged.
/// Cross-shard replay domain digest (audit F1).
///
/// CONDITIONAL DOMAIN: all three sets empty writes zero bytes, so appending
/// this unconditionally keeps the genesis root (and every pre-cross-shard
/// snapshot root) byte-identical with no `COMMITMENT_VERSION` bump - the same
/// contract as the session-key / bridge / zkML domains. Inside
/// the domain nothing is conditional: every set's length is written and
/// entries are hashed in sorted order, so two different replay states cannot
/// encode to the same preimage (PROTOCOL.md I2).
///
/// Committed per entry: the full consumed replay key (the source shard, the
/// source block identity and the message id - dropping any of them would let
/// two nodes disagree about WHAT was consumed under one root), the produced
/// `(tx hash, produce height)` pair (the height decides the timeout-bounce
/// linkage, so hashes alone would under-commit), and the completed tx hash
/// (decides whether the next ack/bounce for the same lifecycle applies).
pub fn write_cross_shard_domain<S: PreimageSink>(
    h: &mut S,
    consumed: &[CrossShardKey],
    produced: &[([u8; 32], u64)],
    completed: &[[u8; 32]],
) {
    if consumed.is_empty() && produced.is_empty() && completed.is_empty() {
        return;
    }
    put_bytes(h, b"xshard_domain", b"XSHARD_REPLAY_V1");
    let mut consumed_sorted: Vec<CrossShardKey> = consumed.to_vec();
    consumed_sorted.sort();
    put_u64(h, b"xshard_consumed_len", consumed_sorted.len() as u64);
    for k in &consumed_sorted {
        put_u64(h, b"xshard_consumed_src", k.source_shard as u64);
        put_addr(h, b"xshard_consumed_blk", &k.finalized_in_block);
        put_addr(h, b"xshard_consumed_msg", &k.msg_id);
    }
    let mut produced_sorted: Vec<([u8; 32], u64)> = produced.to_vec();
    produced_sorted.sort();
    put_u64(h, b"xshard_produced_len", produced_sorted.len() as u64);
    for (tx_hash, height) in &produced_sorted {
        put_addr(h, b"xshard_produced_tx", tx_hash);
        put_u64(h, b"xshard_produced_h", *height);
    }
    let mut completed_sorted: Vec<[u8; 32]> = completed.to_vec();
    completed_sorted.sort();
    put_u64(h, b"xshard_completed_len", completed_sorted.len() as u64);
    for tx_hash in &completed_sorted {
        put_addr(h, b"xshard_completed_tx", tx_hash);
    }
}

fn commitment_digest_into<S: PreimageSink>(h: &mut S, s: &CommitmentSnapshot) {
    put_u64(h, b"COMMITMENT_VERSION", COMMITMENT_VERSION as u64);
    tokens_digest(h, &s.tokens);
    staking_digest(h, &s.staking);
    pmm_digest(h, &s.pmm, &s.pmm_usdt_token, &s.pmm_treasury);
    contracts_digest(h, &s.contracts);
    escrow_digest(h, &s.order_escrow);
    governance_digest(h, &s.governance);
    oracle_digest(h, &s.oracle);
    // Conditional: included only when at least one session key is registered,
    // so an empty registry contributes zero bytes and the genesis root (and
    // every pre-session-key snapshot root) stays byte-identical.
    if !s.session_keys.is_empty() {
        session_keys_digest(h, &s.session_keys);
    }

    let mut books: Vec<(&u32, &crate::orderbook::OrderbookActor)> =
        s.orderbooks.books.iter().collect();
    books.sort_unstable_by(|a, b| a.0.cmp(b.0));
    put_u64(h, b"books_len", books.len() as u64);
    for (pair, book) in books {
        put_u64(h, b"book_pair", *pair as u64);
        book_digest(h, book);
    }

    // Conditional: included only when the bridge domain is NON-EMPTY (a replay
    // set entry, a parked withdrawal, a started rate window or a non-zero
    // escrow mirror), so a chain that has never bridged contributes ZERO bytes
    // here and the pinned genesis root stays byte-identical. APPENDED last so
    // every pre-bridge preimage keeps exactly the byte sequence it had.
    if !s.bridge.is_empty() {
        bridge_digest(h, &s.bridge);
    }

    // Conditional: included only when at least one cross-shard replay entry
    // exists (consumed credit, produced outbound, or completed lifecycle), so
    // a chain that never used cross-shard messaging contributes ZERO bytes
    // here and the pinned genesis root stays byte-identical. APPENDED after
    // the bridge domain so every pre-F1 preimage keeps exactly the byte
    // sequence it had. A non-empty replay set decides whether the next
    // inbound credits again (double mint if dropped), whether a bounce is
    // linkage-valid, and whether an ack completes - it must move the root.
    write_cross_shard_domain(
        h,
        &s.cross_shard_consumed,
        &s.cross_shard_produced,
        &s.cross_shard_completed,
    );
    // §9 2PC: the intermediate states of the cross-shard transfer lifecycle.
    // APPENDED after the cross-shard domain and CONDITIONAL on emptiness, so
    // every chain that never ran the 2PC keeps its exact preimage bytes.
    write_xshard_2pc_domain(h, &s.cross_shard_xpc);
}

/// The §9 cross-shard 2PC domain of the commitment digest.
///
/// The record of one transfer is committed as `(tx hash, phase, prepared
/// height, decided height)`: the transaction hash identifies the transfer
/// (and binds the source and target shards, because the transaction commits
/// to them), the phase is the decision, and the heights say WHEN it was
/// taken - the two facts a node needs to refuse a second credit, a second
/// refund, or a bounce of a transfer that is already decided.
///
/// CONDITIONAL: an empty record set writes ZERO bytes, so a chain that never
/// used the 2PC is byte-identical to before.
pub fn write_xshard_2pc_domain<S: PreimageSink>(
    h: &mut S,
    records: &[crate::xshard2pc::XpcRecord],
) {
    if records.is_empty() {
        return;
    }
    put_bytes(h, b"xshard_2pc_domain", b"XSHARD_2PC_V1");
    let mut sorted: Vec<&crate::xshard2pc::XpcRecord> = records.iter().collect();
    sorted.sort_by_key(|r| r.tx_hash);
    put_u64(h, b"xshard_2pc_len", sorted.len() as u64);
    for r in &sorted {
        put_addr(h, b"xshard_2pc_tx", &r.tx_hash);
        put_u64(h, b"xshard_2pc_phase", r.phase.code() as u64);
        put_u64(h, b"xshard_2pc_prepared_h", r.prepared_height);
        put_u64(h, b"xshard_2pc_decided_h", r.decided_height);
        put_u64(h, b"xshard_2pc_source", r.source_shard as u64);
        put_u64(h, b"xshard_2pc_target", r.target_shard as u64);
    }
}

// ---------------------------------------------------------------------------
// Per-domain preimage builders.
//
// Each captures EXACTLY the bytes its domain contributes to the streaming
// digest (same functions, `Vec<u8>` sink instead of `Sha256`). The cached
// commit path feeds these bytes back into the hasher in digest order, so a
// cache hit skips the O(domain) walk/sort/hash without changing one bit.
// ---------------------------------------------------------------------------

/// Capture one domain's preimage bytes with the reference (uncached) path.
fn capture<F: FnOnce(&mut Vec<u8>)>(f: F) -> Vec<u8> {
    let mut v = Vec::new();
    f(&mut v);
    v
}

/// Tokens domain preimage (byte-identical to the streaming contribution).
pub fn tokens_preimage(reg: &crate::token::TokenRegistry) -> Vec<u8> {
    capture(|h| tokens_digest(h, reg))
}

/// Staking domain preimage.
pub fn staking_preimage(l: &StakingLedger) -> Vec<u8> {
    capture(|h| staking_digest(h, l))
}

/// PMM domain preimage (curve + USDT token id + treasury).
pub fn pmm_preimage(
    p: &PrimaryMarketMaker,
    usdt: &Option<[u8; 32]>,
    treasury: &[u8; 32],
) -> Vec<u8> {
    capture(|h| pmm_digest(h, p, usdt, treasury))
}

/// Contracts domain preimage, reference path (every ABI re-serialized).
pub fn contracts_preimage(reg: &ContractRegistry) -> Vec<u8> {
    capture(|h| contracts_digest(h, reg))
}

/// Contracts domain preimage with the per-contract ABI JSON cache.
pub fn contracts_preimage_cached(reg: &ContractRegistry, cache: &mut AbiJsonCache) -> Vec<u8> {
    capture(|h| contracts_digest_inner(h, reg, Some(cache)))
}

/// Escrow domain preimage.
pub fn escrow_preimage(escrow: &HashMap<(u32, u64), EscrowRecord>) -> Vec<u8> {
    capture(|h| escrow_digest(h, escrow))
}

/// Governance domain preimage.
pub fn governance_preimage(g: &crate::governance::Governance) -> Vec<u8> {
    capture(|h| governance_digest(h, g))
}

/// Oracle domain preimage.
pub fn oracle_preimage(o: &crate::oracle::OracleState) -> Vec<u8> {
    capture(|h| oracle_digest(h, o))
}

/// Session-keys domain preimage (empty registry contributes zero bytes,
/// exactly like the streaming path: the caller passes the state through
/// unconditionally and the conditional lives inside).
pub fn session_keys_preimage(reg: &crate::zkml::SessionKeyRegistry) -> Vec<u8> {
    capture(|h| {
        if !reg.is_empty() {
            session_keys_digest(h, reg);
        }
    })
}

/// Orderbooks domain preimage (pair -> book, walked in id order).
pub fn books_preimage(manager: &crate::orderbook::OrderbookManager) -> Vec<u8> {
    capture(|h| {
        let mut books: Vec<(&u32, &crate::orderbook::OrderbookActor)> =
            manager.books.iter().collect();
        books.sort_unstable_by(|a, b| a.0.cmp(b.0));
        put_u64(h, b"books_len", books.len() as u64);
        for (pair, book) in books {
            put_u64(h, b"book_pair", *pair as u64);
            book_digest(h, book);
        }
    })
}

/// Bridge domain preimage (zero bytes while the domain is empty).
pub fn bridge_preimage(b: &crate::bridge::BridgeState) -> Vec<u8> {
    capture(|h| {
        if !b.is_empty() {
            bridge_digest(h, b);
        }
    })
}

/// Cross-shard replay domain preimage (zero bytes while all sets are empty).
pub fn cross_shard_preimage(
    consumed: &[CrossShardKey],
    produced: &[([u8; 32], u64)],
    completed: &[[u8; 32]],
) -> Vec<u8> {
    capture(|h| write_cross_shard_domain(h, consumed, produced, completed))
}

/// §9 2PC domain preimage.
pub fn xpc_preimage(records: &[crate::xshard2pc::XpcRecord]) -> Vec<u8> {
    capture(|h| write_xshard_2pc_domain(h, records))
}

/// zkML domain preimage (models, then verifying keys).
pub fn zkml_preimage(reg: &crate::zkml::ZkMlModelRegistry) -> Vec<u8> {
    capture(|h| {
        zkml_models_digest_inner(h, reg);
        write_zkml_vks_domain(h, reg);
    })
}

/// Assemble the full §2-aware commitment digest from per-domain preimage
/// bytes (digest order = [`Domain::ALL`]).
///
/// This is the byte-identical twin of the streaming path: the version prefix
/// is written directly and every domain's captured bytes are fed in order.
/// Feeding cached bytes into SHA-256 hashes the same concatenation the
/// streaming path hashes, so equal inputs ⇒ equal digests by construction.
pub fn assemble_cached_digest(domains: [&[u8]; 13]) -> [u8; 32] {
    let mut h = Sha256::new();
    put_u64(&mut h, b"COMMITMENT_VERSION", COMMITMENT_VERSION as u64);
    for bytes in domains {
        h.update(bytes);
    }
    h.finalize().into()
}

/// Zero-copy steady-state assembly: hash every cached domain preimage in
/// digest order without cloning a single byte.
///
/// Batch-hashing twin of [`assemble_cached_digest`]: the same version prefix
/// is written and the same slot bytes are fed to SHA-256 in the same order —
/// the only difference is the bytes are borrowed from the cache instead of
/// from caller-owned clones. Returns `None` (after recording the miss) when
/// any domain's generation is stale, so the caller rebuilds exactly that
/// domain through the usual `*_preimage` builders and `put`s it back.
///
/// Bit-for-bit equality with the streaming digest follows from the same
/// argument as `assemble_cached_digest` (same concatenation ⇒ same hash).
pub fn assemble_from_cache(
    cache: &mut DomainCache,
    generations: &[u64; 13],
) -> Option<[u8; 32]> {
    let mut h = Sha256::new();
    put_u64(&mut h, b"COMMITMENT_VERSION", COMMITMENT_VERSION as u64);
    for d in Domain::ALL {
        let bytes = cache.get_ref(d, generations[d.index()])?;
        h.update(bytes);
    }
    Some(h.finalize().into())
}

/// Digest of every consensus subsystem that lives outside the trie.
pub fn commitment_digest(s: &CommitmentSnapshot) -> [u8; 32] {
    let mut h = Sha256::new();
    commitment_digest_into(&mut h, s);
    h.finalize().into()
}

/// §2-aware commitment digest: the snapshot preimage, then the zkML
/// model-registry domain, then the zkML VK domain.
///
/// Both appended domains are CONDITIONAL and self-gating (empty writes
/// zero bytes), so this is byte-identical to [`commitment_digest`] on a chain
/// that has never used them - which is what lets the registry AND the
/// key set join the digest WITHOUT bumping [`COMMITMENT_VERSION`] or
/// re-pinning `tests/genesis_root_known_answer_tests.rs`. The zkML domains
/// are APPENDED last (models, then specs) so every pre-attestation preimage keeps
/// exactly the byte sequence it had.
///
/// This is the live-path digest: `InMemoryStateEngine` routes both
/// `commit_consensus_domains*` entry points through it.
pub fn commitment_digest_with_zkml(
    s: &CommitmentSnapshot,
    zkml_models: &crate::zkml::ZkMlModelRegistry,
) -> [u8; 32] {
    let mut h = Sha256::new();
    commitment_digest_into(&mut h, s);
    zkml_models_digest_inner(&mut h, zkml_models);
    write_zkml_vks_domain(&mut h, zkml_models);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A snapshot with EVERY domain empty: the state a fresh chain is in.
    fn empty_snapshot() -> CommitmentSnapshot {
        CommitmentSnapshot {
            tokens: crate::token::TokenRegistry::new(),
            staking: crate::staking::StakingLedger::new(),
            orderbooks: crate::orderbook::OrderbookManager::new(),
            order_escrow: HashMap::new(),
            pmm: crate::pmm::PrimaryMarketMaker::new(),
            pmm_usdt_token: None,
            pmm_treasury: [0u8; 32],
            contracts: crate::contract::ContractRegistry::new(),
            governance: crate::governance::Governance::new(),
            oracle: crate::oracle::OracleState::default(),
            session_keys: crate::zkml::SessionKeyRegistry::default(),
            bridge: crate::bridge::BridgeState::default(),
            cross_shard_consumed: Vec::new(),
            cross_shard_produced: Vec::new(),
            cross_shard_completed: Vec::new(),
            cross_shard_xpc: Vec::new(),
        }
    }

    /// PINNED: the digest of [`empty_snapshot`] as produced by the
    /// PRE-CHANGE `staking_digest` - i.e. before the equivocation-dedup,
    /// PQ-key and vesting domains joined the staking preimage.
    ///
    /// This is the BACKWARD-COMPATIBILITY contract in executable form: the
    /// four new domains are CONDITIONAL (an empty map writes ZERO bytes, not
    /// even a zero-length prefix), so a chain that never used them digests
    /// byte-for-byte identically to before. That is what keeps the pinned
    /// genesis root (`tests/genesis_root_known_answer_tests.rs`) valid
    /// without re-pinning it, and what keeps `COMMITMENT_VERSION` at 5.
    ///
    /// If a future change makes one of the four domains unconditional (or
    /// changes its framing), THIS TEST FAILS - and with it the pinned
    /// genesis root, which is the intended alarm.
    const EMPTY_SNAPSHOT_DIGEST: [u8; 32] = [
        0xa8, 0x80, 0x05, 0x51, 0xfe, 0x04, 0xdb, 0x76, 0xd0, 0x49, 0x09, 0x49, 0x46, 0x3e, 0x56,
        0xc3, 0x9b, 0x89, 0xa3, 0xed, 0xcd, 0xb5, 0x4c, 0xf1, 0x5f, 0xac, 0x20, 0x31, 0x4c, 0x53,
        0x5f, 0x86,
    ];

    fn digest_of(s: &CommitmentSnapshot) -> [u8; 32] {
        commitment_digest(s)
    }

    #[test]
    fn empty_staking_domains_contribute_zero_bytes() {
        // The pinned pre-change digest: an unused chain must hash exactly as
        // it did before the four domains were added.
        assert_eq!(
            digest_of(&empty_snapshot()),
            EMPTY_SNAPSHOT_DIGEST,
            "an unused chain must digest byte-for-byte identically to the pre-change code"
        );
    }

    #[test]
    fn equivocation_dedup_moves_the_digest() {
        let mut s = empty_snapshot();
        s.staking.equivocation_dedup.insert([0x11u8; 32]);
        assert_ne!(
            digest_of(&s),
            digest_of(&empty_snapshot()),
            "the per-offense slash dedup set decides whether the SAME equivocation \
             burns again, so it must move the root"
        );
    }

    #[test]
    fn pq_equivocation_dedup_moves_the_digest() {
        let mut s = empty_snapshot();
        s.staking.pq_equivocation_dedup.insert([0x22u8; 32]);
        assert_ne!(
            digest_of(&s),
            digest_of(&empty_snapshot()),
            "the PQ per-offense slash dedup set must move the root"
        );
    }

    #[test]
    fn validator_pq_keys_move_the_digest() {
        let mut s = empty_snapshot();
        s.staking.validator_pq_keys.insert(
            [0x33u8; 32],
            (crate::post_quantum::PqScheme::Falcon512, vec![0xAB; 32]),
        );
        assert_ne!(
            digest_of(&s),
            digest_of(&empty_snapshot()),
            "the registered PQ key is the key the evidence is verified against, so it \
             must move the root"
        );

        // The SCHEME is part of the commitment: the same key bytes mean
        // different things under Falcon512 and under the hybrid scheme.
        let mut other = empty_snapshot();
        other.staking.validator_pq_keys.insert(
            [0x33u8; 32],
            (crate::post_quantum::PqScheme::Hybrid, vec![0xAB; 32]),
        );
        assert_ne!(
            digest_of(&other),
            digest_of(&s),
            "the PQ scheme must be committed explicitly"
        );
    }

    #[test]
    fn vesting_schedules_move_the_digest() {
        let mut s = empty_snapshot();
        s.staking.vesting_schedules.insert(
            [0x44u8; 32],
            crate::tokenomics::TeamVestingSchedule::new(1_000),
        );
        assert_ne!(
            digest_of(&s),
            digest_of(&empty_snapshot()),
            "a vesting floor gates whether a spend is allowed at all, so it must \
             move the root"
        );

        // ...and so does the floor's own parameters.
        let mut moved = empty_snapshot();
        moved.staking.vesting_schedules.insert(
            [0x44u8; 32],
            crate::tokenomics::TeamVestingSchedule::new(1_000),
        );
        moved
            .staking
            .vesting_schedules
            .get_mut(&[0x44u8; 32])
            .unwrap()
            .claimed_amount = 7;
        assert_ne!(
            digest_of(&moved),
            digest_of(&s),
            "the claimed counter decides how much is still claimable"
        );
    }

    #[test]
    fn staking_domains_are_insertion_order_independent() {
        // `HashMap`/`HashSet` iteration order is not stable across processes.
        // Two ledgers holding identical data, filled in opposite order, must
        // digest identically - otherwise two nodes with the same state fork
        // with no attacker involved (PROTOCOL.md I2).
        let mut a = empty_snapshot();
        let mut b = empty_snapshot();
        for i in 0..8u8 {
            let key = [i.wrapping_add(1); 32];
            a.staking.equivocation_dedup.insert(key);
            a.staking.pq_equivocation_dedup.insert(key);
            a.staking
                .validator_pq_keys
                .insert(key, (crate::post_quantum::PqScheme::Falcon512, vec![i; 32]));
            a.staking
                .vesting_schedules
                .insert(key, crate::tokenomics::TeamVestingSchedule::new(i as u64));
        }
        for i in (0..8u8).rev() {
            let key = [i.wrapping_add(1); 32];
            b.staking.equivocation_dedup.insert(key);
            b.staking.pq_equivocation_dedup.insert(key);
            b.staking
                .validator_pq_keys
                .insert(key, (crate::post_quantum::PqScheme::Falcon512, vec![i; 32]));
            b.staking
                .vesting_schedules
                .insert(key, crate::tokenomics::TeamVestingSchedule::new(i as u64));
        }
        assert_eq!(
            digest_of(&a),
            digest_of(&b),
            "identical state must digest identically regardless of insertion order"
        );
    }

    /// The LAZY (F1) delegator-reward accumulator is part of the payout
    /// formula, so it MUST move the root: two nodes holding different
    /// `reward_per_token` values pay a delegator DIFFERENT amounts under the
    /// same root.
    #[test]
    fn lazy_reward_accumulator_moves_the_digest() {
        let mut s = empty_snapshot();
        let validator = [0x77u8; 32];
        s.staking
            .reward_accumulators
            .insert(validator, crate::staking::ValidatorRewardState::default());
        assert_ne!(
            digest_of(&s),
            digest_of(&empty_snapshot()),
            "the reward accumulator decides every future delegator payout, so it must \
             move the root"
        );

        // ...and so must the RATE inside it.
        let mut moved = empty_snapshot();
        let state = crate::staking::ValidatorRewardState {
            reward_per_token: 1,
            ..Default::default()
        };
        moved.staking.reward_accumulators.insert(validator, state);
        assert_ne!(
            digest_of(&moved),
            digest_of(&s),
            "the rate is the payout formula itself"
        );

        // ...and the delegator checkpoint (a stale checkpoint pays twice).
        let mut checkpointed = empty_snapshot();
        checkpointed
            .staking
            .delegator_reward_checkpoints
            .insert((validator, [0x88u8; 32]), 7);
        assert_ne!(
            digest_of(&checkpointed),
            digest_of(&empty_snapshot()),
            "a delegator checkpoint decides what has already been paid"
        );
    }

    /// The accumulator domain is INSERTION-ORDER independent, like every
    /// other map in this module (PROTOCOL.md I2).
    #[test]
    fn lazy_reward_accumulator_is_insertion_order_independent() {
        let mut a = empty_snapshot();
        let mut b = empty_snapshot();
        for i in 0..8u8 {
            let key = [i.wrapping_add(1); 32];
            let state = crate::staking::ValidatorRewardState {
                reward_per_token: i as u128,
                ..Default::default()
            };
            a.staking.reward_accumulators.insert(key, state);
            a.staking
                .delegator_reward_checkpoints
                .insert((key, [0x99u8; 32]), i as u128);
        }
        for i in (0..8u8).rev() {
            let key = [i.wrapping_add(1); 32];
            let state = crate::staking::ValidatorRewardState {
                reward_per_token: i as u128,
                ..Default::default()
            };
            b.staking.reward_accumulators.insert(key, state);
            b.staking
                .delegator_reward_checkpoints
                .insert((key, [0x99u8; 32]), i as u128);
        }
        assert_eq!(
            digest_of(&a),
            digest_of(&b),
            "identical state must digest identically regardless of insertion order"
        );
    }

    // -----------------------------------------------------------------------
    // THE CONDITIONAL-DOMAIN RULE (audit W6.7)
    //
    // A conditional domain writes ZERO bytes when its map is empty, so the
    // genesis known-answer vectors stay valid. The rule must be AIRTIGHT:
    //
    //  1. a map that becomes EMPTY again (it was non-empty and then lost its
    //     last entry) must digest EXACTLY like a map that was never used —
    //     the encoding is a pure function of the STATE, so two nodes that
    //     hold the same state always agree;
    //  2. and it must NOT collide with a state that differs anywhere else —
    //     an emptied domain may not "absorb" a difference;
    //  3. every length is written EXPLICITLY, so a one-entry map and a
    //     two-entry map (or a short key and a longer key) can never encode
    //     to the same bytes.
    // -----------------------------------------------------------------------

    /// A conditional map that becomes empty again digests like a map that
    /// was never used — and never like a state that differs somewhere else.
    #[test]
    fn a_conditional_map_that_becomes_empty_again_is_transparent() {
        // Start from a state that USED the domain...
        let mut used = empty_snapshot();
        used.staking.validator_pq_keys.insert(
            [0x33u8; 32],
            (crate::post_quantum::PqScheme::Falcon512, vec![0xAB; 32]),
        );
        assert_ne!(digest_of(&used), digest_of(&empty_snapshot()));

        // ...and empty it again (the PQ micro-committee arm removes a
        // validator's key, so this really happens on a live chain).
        let mut emptied = empty_snapshot();
        emptied.staking.validator_pq_keys.insert(
            [0x33u8; 32],
            (crate::post_quantum::PqScheme::Falcon512, vec![0xAB; 32]),
        );
        emptied.staking.validator_pq_keys.remove(&[0x33u8; 32]);
        assert_eq!(
            digest_of(&emptied),
            digest_of(&empty_snapshot()),
            "an emptied conditional domain must write zero bytes again"
        );

        // ...and the SAME emptied state must NOT collide with a state that
        // differs somewhere else (the empty domain may not absorb a
        // difference in another domain).
        let mut elsewhere = empty_snapshot();
        elsewhere.staking.total_burned = 1;
        assert_ne!(
            digest_of(&elsewhere),
            digest_of(&emptied),
            "an emptied conditional domain must not shadow a difference elsewhere"
        );
    }

    /// Every conditional domain writes its LENGTH explicitly: a one-entry map
    /// and a two-entry map (and a short value and a longer value) can never
    /// encode to the same bytes.
    #[test]
    fn conditional_domains_write_explicit_lengths() {
        let mut one = empty_snapshot();
        one.staking.equivocation_dedup.insert([0x11u8; 32]);
        let mut two = empty_snapshot();
        two.staking.equivocation_dedup.insert([0x11u8; 32]);
        two.staking.equivocation_dedup.insert([0x12u8; 32]);
        assert_ne!(
            digest_of(&one),
            digest_of(&two),
            "the dedup set's length must be committed"
        );

        // A PQ key of 32 bytes and one of 33 bytes must differ (the public
        // key length is written, never implied by the scheme).
        let mut short = empty_snapshot();
        short.staking.validator_pq_keys.insert(
            [0x33u8; 32],
            (crate::post_quantum::PqScheme::Falcon512, vec![0xAB; 32]),
        );
        let mut long = empty_snapshot();
        long.staking.validator_pq_keys.insert(
            [0x33u8; 32],
            (crate::post_quantum::PqScheme::Falcon512, vec![0xAB; 33]),
        );
        assert_ne!(
            digest_of(&short),
            digest_of(&long),
            "the PQ public key's length must be committed explicitly"
        );

        // The reward accumulator's two maps are committed SEPARATELY: an
        // accumulator without checkpoints and a checkpoint without an
        // accumulator are different states.
        let mut acc_only = empty_snapshot();
        acc_only.staking.reward_accumulators.insert(
            [0x77u8; 32],
            crate::staking::ValidatorRewardState::default(),
        );
        let mut cp_only = empty_snapshot();
        cp_only
            .staking
            .delegator_reward_checkpoints
            .insert(([0x77u8; 32], [0x88u8; 32]), 1);
        assert_ne!(
            digest_of(&acc_only),
            digest_of(&cp_only),
            "the accumulator and the checkpoints are separate commitments"
        );
    }

    /// The reward accumulator's CARRY (the un-truncated fraction of the last
    /// rate division) and its DENOMINATOR are part of the commitment: both
    /// decide the next rate increment.
    #[test]
    fn the_accumulator_carry_and_its_denominator_are_committed() {
        let mut base = empty_snapshot();
        let state = crate::staking::ValidatorRewardState {
            reward_per_token: 5,
            remainder: 7,
            remainder_den: 11,
            ..Default::default()
        };
        base.staking
            .reward_accumulators
            .insert([0x77u8; 32], state.clone());

        let mut no_carry = empty_snapshot();
        let mut state2 = state.clone();
        state2.remainder = 0;
        no_carry
            .staking
            .reward_accumulators
            .insert([0x77u8; 32], state2);
        assert_ne!(
            digest_of(&base),
            digest_of(&no_carry),
            "the carried division remainder decides the next rate increment"
        );

        let mut other_den = empty_snapshot();
        let mut state3 = state.clone();
        state3.remainder_den = 12;
        other_den
            .staking
            .reward_accumulators
            .insert([0x77u8; 32], state3);
        assert_ne!(
            digest_of(&base),
            digest_of(&other_den),
            "the remainder's denominator (the delegated total it came from) must be committed"
        );
    }

    // -----------------------------------------------------------------------
    // TAIL-1: PER-DOMAIN GENERATION CACHING.
    //
    // The cached assembly (`assemble_cached_digest` over per-domain
    // preimages) must be byte-identical to the streaming digest on every
    // state, including randomized mutation sequences; the per-contract ABI
    // JSON cache must serve byte-identical JSON; and the steady-state
    // recommit must be served entirely from cache (the perf-regression
    // signal: if a future change bypasses the cache, the hit counters below
    // catch it). Nothing here changes the wire format, the quorum rules or
    // the state transition: every assertion compares cached output against
    // the reference streaming path.
    // -----------------------------------------------------------------------

    use crate::contract_abi::{AbiMethod, AbiParam, AbiType, ContractAbi};

    fn populated_snapshot(
        n_tokens: usize,
        bals_per_token: usize,
        n_contracts: usize,
        n_validators: usize,
    ) -> CommitmentSnapshot {
        let mut s = empty_snapshot();
        for i in 0..n_tokens {
            let mut id = [0u8; 32];
            id[0..8].copy_from_slice(&(i as u64).to_be_bytes());
            id[8] = 0x70;
            let md = crate::token::TokenMetadata {
                name: format!("tok{i}"),
                symbol: format!("T{i}"),
                decimals: 8,
                total_supply: 1_000_000 + i as u64,
                max_supply: None,
                minter: [i as u8; 32],
                paused: false,
                description: String::new(),
            };
            let mut actor =
                crate::token::TokenActor::new(id, md, 1_000_000).expect("valid test metadata");
            for j in 0..bals_per_token {
                let mut acct = [0u8; 32];
                acct[0..8].copy_from_slice(&(j as u64).to_be_bytes());
                acct[8] = 0xA1;
                acct[9] = i as u8;
                actor.balances.insert(acct, (i as u64) * 1000 + j as u64);
            }
            s.tokens.tokens.insert(id, actor);
        }
        s.tokens.next_nonce = n_tokens as u64;
        for i in 0..n_validators {
            let mut v = [0u8; 32];
            v[0..8].copy_from_slice(&(i as u64).to_be_bytes());
            v[8] = 0x5A;
            // Validator zero can afford a governance proposal; the rest are
            // small (the digest does not care about the floor).
            let bond = if i == 0 {
                20_000u64 * 1_000_000_000
            } else {
                10_000_000 + i as u64
            };
            s.staking.validators.insert(
                v,
                crate::staking::ValidatorStake {
                    self_bond: bond,
                    delegated: i as u64 * 7,
                    commission_bps: 100,
                    pending_rewards: i as u64,
                    total_slashed: 0,
                    missed: 0,
                    last_downtime_penalty: 0,
                },
            );
        }
        for i in 0..n_contracts {
            let mut addr = [0u8; 32];
            addr[0..8].copy_from_slice(&(i as u64).to_be_bytes());
            addr[8] = 0xC0;
            let abi = ContractAbi {
                methods: vec![
                    AbiMethod::new(
                        format!("method{i}"),
                        vec![
                            AbiParam::new("x", AbiType::I64),
                            AbiParam::new("owner", AbiType::Address),
                        ],
                        AbiType::I64,
                        true,
                    ),
                    AbiMethod::new(
                        "view",
                        vec![AbiParam::new("note", AbiType::String)],
                        AbiType::U64,
                        false,
                    ),
                ],
                events: vec![crate::contract_abi::AbiEvent::new(
                    format!("ev{i}"),
                    vec![AbiParam::new("t", AbiType::I64)],
                    vec![AbiParam::new("blob", AbiType::Bytes)],
                )],
            };
            let mut storage = HashMap::new();
            for k in 0..16i64 {
                storage.insert(k, (i as i64) * 1000 + k);
            }
            s.contracts.contracts.insert(
                addr,
                crate::contract::Contract {
                    address: addr,
                    creator: [i as u8; 32],
                    code_hash: [0xCC; 32],
                    code: vec![0x00, 0x61, 0x73, 0x6D],
                    storage,
                    created_at: i as u64,
                    paused: i % 2 == 0,
                    balance: 0,
                    abi: Some(abi),
                    source_hash: None,
                },
            );
        }
        s.contracts.next_nonce = n_contracts as u64;
        // Governance with one live proposal (exercises the voters/weights maps).
        // The proposer is validator zero, the only one bonded above the floor.
        let mut gov_ledger = s.staking.clone();
        let mut proposer = [0u8; 32];
        proposer[8] = 0x5A;
        s.governance
            .propose(
                &mut gov_ledger,
                proposer,
                "raise-the-roof".to_string(),
                crate::governance::GovAction::Signal("test".to_string()),
                1,
            )
            .expect("test proposal proposes");
        // Oracle with one publisher + one feed.
        s.oracle.publishers.insert([0x0Au8; 32]);
        s.oracle.feeds.insert(
            "STELL/USD".to_string(),
            crate::oracle::CommittedFeed {
                price_micro_usd: 250_000,
                timestamp: 1,
                publisher: [0x0Au8; 32],
            },
        );
        // One session-key record.
        s.session_keys.entries.insert(
            [0x5Eu8; 32],
            crate::zkml::SessionKeyRecord {
                master: [0x6Eu8; 32],
                valid_until: 9999,
                max_gas_spend: 1_000_000,
                gas_spent: 3,
                scope: 1,
                max_value_per_tx: 500,
                revoked: false,
            },
        );
        // One parked bridge withdrawal (makes the bridge domain non-empty).
        s.bridge.processed_source_txs.insert([0xB1u8; 32]);
        s.bridge.escrow_balance = 42;
        // One orderbook with one resting order.
        let mut book = crate::orderbook::OrderbookActor::new(7, 64);
        book.next_order_id = 2;
        book.asks.insert(
            100,
            vec![crate::orderbook::Order {
                order_id: 1,
                trader: [0x07u8; 32],
                side: crate::orderbook::OrderSide::Sell,
                order_type: crate::orderbook::OrderType::Limit,
                price: 100,
                amount: 5,
                filled: 0,
                timestamp: 1,
            }],
        );
        s.orderbooks.books.insert(7, book);
        // One escrow entry, one xshard consumed key, one 2PC record.
        s.order_escrow.insert(
            (7, 1),
            EscrowRecord {
                trader: [0x07u8; 32],
                locked_base_stell: 5,
                locked_quote_wusdt: 0,
                locked_quote_native: 0,
            },
        );
        s.cross_shard_consumed.push(crate::sharding::CrossShardKey {
            source_shard: 1,
            finalized_in_block: [0x11u8; 32],
            msg_id: [0x22u8; 32],
        });
        let xpc_tx = crate::sharding::Transaction::sign(
            &ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]),
            [0x43u8; 32],
            1,
            1,
            0,
            0,
            0,
        );
        s.cross_shard_xpc
            .push(crate::xshard2pc::XpcRecord::prepared(xpc_tx, 0, 1, 3));
        s
    }

    /// Assemble a digest from per-domain preimages captured with `gens`
    /// (test mirror of the engine's cached commit path).
    fn assemble_test(
        s: &CommitmentSnapshot,
        zkml: &crate::zkml::ZkMlModelRegistry,
        gens: &[u64; 13],
        cache: &mut DomainCache,
    ) -> [u8; 32] {
        macro_rules! fill {
            ($domain:expr, $build:expr) => {{
                let gen = gens[$domain.index()];
                match cache.get($domain, gen) {
                    Some(b) => b,
                    None => {
                        let b: Vec<u8> = $build;
                        cache.put($domain, gen, b.clone());
                        b
                    }
                }
            }};
        }
        let domains = [
            fill!(Domain::Tokens, tokens_preimage(&s.tokens)),
            fill!(Domain::Staking, staking_preimage(&s.staking)),
            fill!(
                Domain::Pmm,
                pmm_preimage(&s.pmm, &s.pmm_usdt_token, &s.pmm_treasury)
            ),
            fill!(
                Domain::Contracts,
                contracts_preimage_cached(&s.contracts, &mut cache.abi)
            ),
            fill!(Domain::Escrow, escrow_preimage(&s.order_escrow)),
            fill!(Domain::Governance, governance_preimage(&s.governance)),
            fill!(Domain::Oracle, oracle_preimage(&s.oracle)),
            fill!(Domain::SessionKeys, session_keys_preimage(&s.session_keys)),
            fill!(Domain::Books, books_preimage(&s.orderbooks)),
            fill!(Domain::Bridge, bridge_preimage(&s.bridge)),
            fill!(
                Domain::CrossShard,
                cross_shard_preimage(
                    &s.cross_shard_consumed,
                    &s.cross_shard_produced,
                    &s.cross_shard_completed
                )
            ),
            fill!(Domain::Xpc, xpc_preimage(&s.cross_shard_xpc)),
            fill!(Domain::Zkml, zkml_preimage(zkml)),
        ];
        let refs: [&[u8]; 13] = [
            &domains[0],
            &domains[1],
            &domains[2],
            &domains[3],
            &domains[4],
            &domains[5],
            &domains[6],
            &domains[7],
            &domains[8],
            &domains[9],
            &domains[10],
            &domains[11],
            &domains[12],
        ];
        assemble_cached_digest(refs)
    }

    /// Reference streaming digest for the §2-aware live path.
    fn streaming_of(s: &CommitmentSnapshot, zkml: &crate::zkml::ZkMlModelRegistry) -> [u8; 32] {
        commitment_digest_with_zkml(s, zkml)
    }

    /// The cached assembly is byte-identical to the streaming digest on a
    /// populated state (every domain non-empty except the conditional
    /// zkML ones, which stay empty here).
    #[test]
    fn cached_assembly_matches_streaming_on_populated_snapshot() {
        let s = populated_snapshot(64, 4, 32, 16);
        let zkml = crate::zkml::ZkMlModelRegistry::default();
        let reference = streaming_of(&s, &zkml);
        let mut cache = DomainCache::default();
        let gens = [1u64; 13];
        let cached = assemble_test(&s, &zkml, &gens, &mut cache);
        assert_eq!(
            cached, reference,
            "cached per-domain assembly must equal the streaming digest"
        );
        // Second assembly with the same generations is served fully from cache.
        cache.reset_counters();
        let cached2 = assemble_test(&s, &zkml, &gens, &mut cache);
        assert_eq!(cached2, reference);
        assert_eq!(
            cache.hits, 13,
            "steady-state recommit must hit every domain"
        );
        assert_eq!(cache.misses, 0);
    }

    /// The per-contract ABI JSON cache serves byte-identical JSON and only
    /// re-serializes the contract whose manifest changed.
    #[test]
    fn abi_json_cache_is_byte_identical() {
        let s = populated_snapshot(8, 2, 16, 4);
        let reference = contracts_preimage(&s.contracts);
        let mut cache = AbiJsonCache::default();
        let cold = contracts_preimage_cached(&s.contracts, &mut cache);
        assert_eq!(cold, reference, "cold cache must match the reference path");
        assert_eq!(cache.misses as usize, s.contracts.contracts.len());
        assert_eq!(cache.hits, 0);
        let warm = contracts_preimage_cached(&s.contracts, &mut cache);
        assert_eq!(warm, reference, "warm cache must match the reference path");
        assert_eq!(
            cache.hits as usize,
            s.contracts.contracts.len(),
            "every unchanged manifest must be a hit"
        );
        // Change ONE manifest: only that contract re-serializes.
        let mut s2 = s.clone();
        let first = *s2.contracts.contracts.keys().next().unwrap();
        let hits_before = cache.hits;
        let misses_before = cache.misses;
        s2.contracts
            .contracts
            .get_mut(&first)
            .unwrap()
            .abi
            .as_mut()
            .unwrap()
            .methods
            .push(AbiMethod::new("fresh", vec![], AbiType::Bool, false));
        let changed = contracts_preimage_cached(&s2.contracts, &mut cache);
        assert_eq!(
            changed,
            contracts_preimage(&s2.contracts),
            "changed state must still match the reference path"
        );
        assert_ne!(
            changed, reference,
            "the manifest change must move the domain"
        );
        assert_eq!(
            cache.misses - misses_before,
            1,
            "exactly the changed contract re-serializes"
        );
        assert_eq!(
            cache.hits - hits_before,
            (s2.contracts.contracts.len() - 1) as u64,
            "every other contract stays a hit"
        );
    }

    /// Deterministic xorshift (no wall clock anywhere in the cache keys or
    /// the test itself).
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            self.0
        }
    }

    /// Randomized mutation sequences: the cached assembly equals the
    /// streaming digest after every step, with the generation of exactly the
    /// mutated domain bumped. This is the no-wire-format / no-quorum /
    /// no-state-transition-change proof for the cache: output bytes never
    /// differ from the reference path.
    #[test]
    fn randomized_mutations_cached_equals_streaming() {
        let mut s = populated_snapshot(32, 4, 16, 8);
        let zkml = crate::zkml::ZkMlModelRegistry::default();
        let mut cache = DomainCache::default();
        let mut gens = [1u64; 13];
        let mut rng = Lcg(0x1234_5678_9ABC_DEF1);
        for step in 0..200 {
            match rng.next() % 7 {
                0 => {
                    // Token balance touch.
                    let id = *s.tokens.tokens.keys().next().unwrap();
                    let actor = s.tokens.tokens.get_mut(&id).unwrap();
                    let acct = [((step as u8).wrapping_add(1)); 32];
                    *actor.balances.entry(acct).or_insert(0) += 1;
                    gens[Domain::Tokens.index()] += 1;
                }
                1 => {
                    // Staking touch.
                    s.staking.total_burned += 1;
                    gens[Domain::Staking.index()] += 1;
                }
                2 => {
                    // Contract storage touch.
                    let addr = *s.contracts.contracts.keys().next().unwrap();
                    let c = s.contracts.contracts.get_mut(&addr).unwrap();
                    *c.storage.entry(step as i64).or_insert(0) += 1;
                    gens[Domain::Contracts.index()] += 1;
                }
                3 => {
                    // Governance touch (a vote on the open proposal).
                    let mut ledger = s.staking.clone();
                    // Fund a fresh voter above the proposal floor via validator zero's
                    // delegation entry path: vote weight comes from stake, so
                    // register a delegation for the voter first.
                    let voter = [(step as u8).wrapping_add(0xF0); 32];
                    let val = s.staking.validators.keys().next().copied().unwrap();
                    ledger
                        .delegations
                        .insert((val, voter), 20_000u64 * 1_000_000_000);
                    let _ = s.governance.vote(
                        &mut ledger,
                        voter,
                        0,
                        crate::governance::VoteChoice::Yes,
                        step + 2,
                    );
                    gens[Domain::Governance.index()] += 1;
                }
                4 => {
                    // Oracle touch.
                    s.oracle.breaker_tripped = step % 2 == 0;
                    gens[Domain::Oracle.index()] += 1;
                }
                5 => {
                    // Escrow touch.
                    s.order_escrow.insert(
                        (7, step),
                        EscrowRecord {
                            trader: [step as u8; 32],
                            locked_base_stell: step,
                            locked_quote_wusdt: 0,
                            locked_quote_native: 0,
                        },
                    );
                    gens[Domain::Escrow.index()] += 1;
                }
                _ => {
                    // Books touch.
                    if let Some(book) = s.orderbooks.books.get_mut(&7) {
                        book.next_order_id += 1;
                    }
                    gens[Domain::Books.index()] += 1;
                }
            }
            let cached = assemble_test(&s, &zkml, &gens, &mut cache);
            let reference = streaming_of(&s, &zkml);
            assert_eq!(
                cached, reference,
                "step {step}: cached assembly diverged from streaming"
            );
        }
        // The run exercised both paths: every domain rebuilt at least once
        // and hits served the untouched ones.
        assert!(cache.hits > 0, "untouched domains must be cache hits");
        assert!(cache.misses > 0, "mutated domains must rebuild");
    }

    /// Differential: the zero-copy batch assembly (`assemble_from_cache`,
    /// no clones) and the `Vec`-sort buffers equal the streaming digest over
    /// randomized state sequences at fixed seeds — any 1-bit digest
    /// difference fails.
    ///
    /// Unlike `randomized_mutations_cached_equals_streaming` (which touches
    /// one representative map per domain), this populates EVERY map whose
    /// sort buffer changed (`BTreeMap` → `Vec` + `sort_unstable`) and mutates
    /// across all of them, so an ordering slip in any converted buffer is a
    /// hard failure here.
    #[test]
    fn zero_copy_and_sorted_buffers_match_streaming_over_randomized_sequences() {
        for seed in [0x1234_5678_9ABC_DEF1u64, 0x9E37_79B9_7F4A_7C15u64] {
            let mut s = populated_snapshot(32, 4, 16, 8);
            // Fill every converted sort buffer with several entries (insertion
            // order varies with `i`, so a missed sort would already diverge).
            let val0 = *s.staking.validators.keys().next().unwrap();
            for i in 0..6u8 {
                let a = [i.wrapping_add(0x10); 32];
                let b = [i.wrapping_add(0x20); 32];
                s.staking.delegations.insert((val0, a), i as u64);
                s.staking.delegator_rewards.insert((val0, a), i as u64);
                s.staking.withdrawable.insert((val0, a), i as u64);
                s.staking.locked_governance.insert(a, i as u64);
                s.staking.equivocation_dedup.insert(a);
                s.staking.pq_equivocation_dedup.insert(b);
                s.staking.validator_pq_keys.insert(
                    a,
                    (crate::post_quantum::PqScheme::Falcon512, vec![i; 32]),
                );
                s.staking.vesting_schedules.insert(
                    b,
                    crate::tokenomics::TeamVestingSchedule::new(i as u64),
                );
                s.staking.reward_accumulators.insert(
                    a,
                    crate::staking::ValidatorRewardState {
                        reward_per_token: i as u128,
                        ..Default::default()
                    },
                );
                s.staking
                    .delegator_reward_checkpoints
                    .insert((val0, a), i as u128);
                s.staking.jail.insert(
                    a,
                    crate::staking::JailRecord {
                        jailed_at_height: i as u64,
                        release_height: i as u64 + 100,
                    },
                );
                s.staking.commission_schedule.insert(
                    a,
                    crate::staking::CommissionSchedule {
                        last_effective_height: Some(i as u64),
                        pending: None,
                    },
                );
                s.staking.redelegation_lock.insert((val0, a), i as u64);
                let tok = *s.tokens.tokens.keys().next().unwrap();
                if let Some(actor) = s.tokens.tokens.get_mut(&tok) {
                    actor.allowances.insert((a, b), i as u64);
                }
            }
            let zkml = crate::zkml::ZkMlModelRegistry::default();
            // Cold-fill the cache, then check the zero-copy all-hit path.
            let mut cache = DomainCache::default();
            let mut gens = [3u64; 13];
            let reference = streaming_of(&s, &zkml);
            let cloned = assemble_test(&s, &zkml, &gens, &mut cache);
            assert_eq!(cloned, reference, "seed {seed:#x}: cold clone-path diverged");
            let zero = assemble_from_cache(&mut cache, &gens)
                .expect("seed: all-hit zero-copy assembly must succeed");
            assert_eq!(zero, reference, "seed {seed:#x}: zero-copy diverged");
            // Stale generation on any domain must be a `None` (rebuild signal),
            // never a wrong digest.
            let mut stale = gens;
            stale[Domain::Tokens.index()] += 1;
            assert_eq!(
                assemble_from_cache(&mut cache, &stale),
                None,
                "seed {seed:#x}: stale generation must miss, not mis-digest"
            );
            // Randomized mutation walk: every step rebuilds the touched
            // domain through the `Vec`-sort builders and checks BOTH assembly
            // paths against streaming.
            let mut rng = Lcg(seed);
            for step in 0..200 {
                match rng.next() % 10 {
                    0 => {
                        let id = *s.tokens.tokens.keys().next().unwrap();
                        let actor = s.tokens.tokens.get_mut(&id).unwrap();
                        let acct = [((step as u8).wrapping_add(1)); 32];
                        *actor.balances.entry(acct).or_insert(0) += 1;
                        gens[Domain::Tokens.index()] += 1;
                    }
                    1 => {
                        s.staking.total_burned += 1;
                        gens[Domain::Staking.index()] += 1;
                    }
                    2 => {
                        let a = [(step as u8).wrapping_add(0x40); 32];
                        s.staking.delegations.insert((val0, a), step);
                        s.staking.delegator_rewards.insert((val0, a), step);
                        s.staking.withdrawable.insert((val0, a), step);
                        gens[Domain::Staking.index()] += 1;
                    }
                    3 => {
                        let a = [(step as u8).wrapping_add(0x50); 32];
                        s.staking.locked_governance.insert(a, step);
                        s.staking.equivocation_dedup.insert(a);
                        s.staking.jail.insert(
                            a,
                            crate::staking::JailRecord {
                                jailed_at_height: step,
                                release_height: step + 100,
                            },
                        );
                        s.staking.redelegation_lock.insert((val0, a), step);
                        gens[Domain::Staking.index()] += 1;
                    }
                    4 => {
                        let a = [(step as u8).wrapping_add(0x60); 32];
                        s.staking.reward_accumulators.insert(
                            a,
                            crate::staking::ValidatorRewardState {
                                reward_per_token: step as u128,
                                ..Default::default()
                            },
                        );
                        s.staking
                            .delegator_reward_checkpoints
                            .insert((val0, a), step as u128);
                        gens[Domain::Staking.index()] += 1;
                    }
                    5 => {
                        let addr = *s.contracts.contracts.keys().next().unwrap();
                        let c = s.contracts.contracts.get_mut(&addr).unwrap();
                        *c.storage.entry(step as i64).or_insert(0) += 1;
                        gens[Domain::Contracts.index()] += 1;
                    }
                    6 => {
                        let mut ledger = s.staking.clone();
                        let voter = [(step as u8).wrapping_add(0xF0); 32];
                        let val = s.staking.validators.keys().next().copied().unwrap();
                        ledger
                            .delegations
                            .insert((val, voter), 20_000u64 * 1_000_000_000);
                        let _ = s.governance.vote(
                            &mut ledger,
                            voter,
                            0,
                            crate::governance::VoteChoice::Yes,
                            step + 2,
                        );
                        gens[Domain::Governance.index()] += 1;
                    }
                    7 => {
                        s.oracle.breaker_tripped = step % 2 == 0;
                        gens[Domain::Oracle.index()] += 1;
                    }
                    8 => {
                        s.order_escrow.insert(
                            (7, step),
                            EscrowRecord {
                                trader: [step as u8; 32],
                                locked_base_stell: step,
                                locked_quote_wusdt: 0,
                                locked_quote_native: 0,
                            },
                        );
                        gens[Domain::Escrow.index()] += 1;
                    }
                    _ => {
                        if let Some(book) = s.orderbooks.books.get_mut(&7) {
                            book.next_order_id += 1;
                        }
                        gens[Domain::Books.index()] += 1;
                    }
                }
                let cloned = assemble_test(&s, &zkml, &gens, &mut cache);
                let reference = streaming_of(&s, &zkml);
                assert_eq!(
                    cloned, reference,
                    "seed {seed:#x} step {step}: clone-path diverged from streaming"
                );
                let zero = assemble_from_cache(&mut cache, &gens).expect(
                    "seed: cache was just filled by the clone path, zero-copy must hit",
                );
                assert_eq!(
                    zero, reference,
                    "seed {seed:#x} step {step}: zero-copy diverged from streaming"
                );
            }
        }
    }

    /// Perf + regression: on a populated state the steady-state recommit is
    /// served entirely from cache. Prints measured ms for the report; the
    /// hard assertions are correctness (byte equality) and the hit-rate
    /// contract (13/13 hits, 0 misses, ABI hits for every manifest).
    #[test]
    fn perf_digest_cached_vs_streaming() {
        let s = populated_snapshot(1500, 8, 300, 200);
        let zkml = crate::zkml::ZkMlModelRegistry::default();
        // Warm up, then measure the reference streaming path.
        let reference = streaming_of(&s, &zkml);
        let t0 = std::time::Instant::now();
        let reference2 = streaming_of(&s, &zkml);
        let streaming_ms = t0.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(reference2, reference);
        // Cold cached build, then the steady-state (all-hit) recommit.
        let mut cache = DomainCache::default();
        let gens = [7u64; 13];
        let t0 = std::time::Instant::now();
        let cold = assemble_test(&s, &zkml, &gens, &mut cache);
        let cold_ms = t0.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(cold, reference, "cold cached build must equal streaming");
        cache.reset_counters();
        let t0 = std::time::Instant::now();
        let hot = assemble_test(&s, &zkml, &gens, &mut cache);
        let hot_ms = t0.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(hot, reference, "hot cached build must equal streaming");
        eprintln!(
            "[perf] commitment_digest populated (1500 tokens/300 contracts/200 vals): streaming={streaming_ms:.2}ms cold-cached={cold_ms:.2}ms hot-cached(all-hit)={hot_ms:.2}ms speedup={:.1}x",
            if hot_ms > 0.0 { streaming_ms / hot_ms } else { f64::INFINITY },
        );
        assert_eq!(
            cache.hits, 13,
            "steady-state recommit must hit every domain"
        );
        assert_eq!(cache.misses, 0);
        // Touch one contract's STORAGE (its manifest is unchanged) and bump
        // only the contracts generation: the domain rebuilds, but every
        // manifest must be served from the ABI cache.
        let mut s2 = s.clone();
        let addr = *s2.contracts.contracts.keys().next().unwrap();
        s2.contracts
            .contracts
            .get_mut(&addr)
            .unwrap()
            .storage
            .insert(-1, 7);
        let mut gens2 = gens;
        gens2[Domain::Contracts.index()] += 1;
        cache.reset_counters();
        let rebuilt = assemble_test(&s2, &zkml, &gens2, &mut cache);
        assert_eq!(
            rebuilt,
            streaming_of(&s2, &zkml),
            "contracts-domain rebuild must equal streaming"
        );
        assert_ne!(rebuilt, reference);
        assert_eq!(cache.hits, 12, "only the contracts domain rebuilds");
        assert_eq!(cache.misses, 1);
        assert_eq!(
            cache.abi.hits as usize,
            s2.contracts.contracts.len(),
            "every unchanged manifest must be an ABI hit"
        );
        assert_eq!(cache.abi.misses, 0);
    }
}
