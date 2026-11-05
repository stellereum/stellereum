//! Dandelion stem/fluff transaction-relay policy — pure, unwired.
//!
//! Network-layer privacy complement to on-chain stealth: a transaction
//! originator first relays its transaction along a short random "stem" path
//! (one peer per hop) and only then diffuses it with a normal "fluff"
//! broadcast. An observer watching the fluff phase therefore sees the
//! transaction enter the network at a random relayer, not at the originator's
//! IP — IP unlinkability for (e.g.) silent-payment senders.
//!
//! # Scope and wiring status
//!
//! This module is **policy only and deliberately unwired**: it decides
//! *what* to do with a transaction (`StemForward` / `FluffBroadcast` /
//! `IgnoreDuplicate`) but performs no I/O, owns no sockets, and knows nothing
//! about the gossip fanout paths. Wiring it into the gossip publish path is
//! explicitly OUT of scope here and is audit-gated (see
//! `docs/DANDELION_PLAN.md`). The module is not registered in `lib.rs` for
//! exactly that reason; the test suite includes it via `#[path]`.
//!
//! # Purity contract
//!
//! * Peer identities are abstract [`PeerId`]s (`u64`). No addresses, no
//!   sockets, no `std::net`, no async runtime.
//! * Randomness comes only from the internal seeded [`NodeRng`] (SplitMix64).
//!   Fixed seeds in tests make every path reproducible.
//! * Liveness information is supplied by the caller as a plain
//!   `is_alive: impl Fn(PeerId) -> bool` closure, so the policy stays a pure
//!   function of (state, inputs). Stale liveness data is tolerated: peer
//!   selection retries a bounded number of times.
//! * Transaction identities are opaque 32-byte hashes ([`TxHash`]); the
//!   policy never inspects payloads and invents no cryptography.
//!
//! # Geometric stem length
//!
//! The number of stem hops `H` for a fresh transaction is sampled from a
//! geometric distribution: each hop continues the stem independently with
//! probability `p_continue`, so `P(H = k) = p^k * (1 - p)` with mean
//! [`geometric_mean`] `= p / (1 - p)`. With the default
//! [`DEFAULT_P_CONTINUE`] `= 0.8` the mean stem length is 4 hops and
//! `P(H >= 2) = 0.64`. Lengths are hard-capped at [`MAX_STEM_HOPS`] (the
//! excess probability mass fluffs early — a fail-safe, not a silent queue).
//!
//! # Per-hop semantics
//!
//! The originator samples `H`. If `H == 0` (probability `1 - p`) it fluffs
//! immediately. Otherwise it forwards to one randomly-selected alive peer and
//! records the remaining hop budget `H - 1` in its bounded stem map (needed
//! for failover and the fluff timeout). Each stem relayer receiving the
//! transaction with remaining budget `r` fluffs when `r == 0` and otherwise
//! forwards to one random alive peer with budget `r - 1`. In a wired
//! implementation the remaining budget would travel in a stem header; here it
//! is an explicit function argument ([`DandelionRelay::on_stem_receive`]).
//!
//! # Safety properties (all specified here, all tested)
//!
//! * **Bounded memory (fail-closed):** the stem map holds at most
//!   [`MAX_STEM_ENTRIES`] entries and the seen-set at most
//!   [`MAX_SEEN_ENTRIES`]; both evict the *oldest* entry when full, so memory
//!   can never grow without bound under flood.
//! * **Loop handling without blackholes:** stem delivery has NO seen-gate.
//!   Each stem forward strictly consumes budget (`r → r-1`), so a stem that
//!   loops simply burns budget and then fluffs — it can never spin forever
//!   and never dies silently. Only already-*fluffed* transactions are
//!   dropped (`IgnoreDuplicate`), which is what terminates broadcast storms:
//!   each node relays a given fluff at most once. (An earlier revision killed
//!   looped stems outright; the virtualized-graph simulator showed this
//!   created silent blackholes AND truncated anonymity — fixed here.)
//! * **Fluff wins:** the first fluff sighting of a transaction drops any held
//!   stem state for it and is relayed onward exactly once; later sightings
//!   are ignored. A transaction is therefore never stem-held after the
//!   network has already fluffed it.
//! * **Failover:** peer selection draws uniformly among candidates and skips
//!   known-dead peers with at most [`MAX_FAILOVER_RETRIES`] extra draws. If
//!   no alive peer is found the node fluffs locally instead of blackholing.
//! * **Fluff timeout (stem-blackhole mitigation):** [`DandelionRelay::fluff_timeout`]
//!   force-fluffs a held stem entry. Wiring would arm one timer per stem entry
//!   (see `docs/DANDELION_PLAN.md`); an attacker that swallows stem traffic
//!   can therefore delay a transaction but cannot suppress it past the
//!   timeout.

use std::collections::{HashMap, VecDeque};

/// Abstract peer identifier. Deliberately opaque: the policy never resolves,
/// dials, or otherwise interprets it.
pub type PeerId = u64;

/// Opaque transaction identifier (e.g. a transaction hash). Never inspected.
pub type TxHash = [u8; 32];

/// Default per-hop stem-continuation probability `p`.
///
/// Rationale: mean stem length `p / (1 - p) = 4` hops gives an anonymity set
/// spanning several relays while keeping added propagation latency small
/// (4 sequential hops before diffusion starts). `P(H = 0) = 0.2` of
/// transactions fluff immediately, which bounds worst-case delay for a fixed
/// fraction of traffic. See `docs/DANDELION_PLAN.md` for the full trade-off.
pub const DEFAULT_P_CONTINUE: f64 = 0.8;

/// Hard cap on sampled stem hops. The tail of the geometric distribution
/// beyond this point fluffs early; with `p = 0.8`, `P(H > 10) ≈ 0.086`, so
/// the cap binds rarely and only shortens extreme stems.
pub const MAX_STEM_HOPS: u32 = 10;

/// Maximum per-node stem entries held concurrently. Fail-closed: inserting
/// past the cap evicts the oldest entry (which then fluffs via its timeout in
/// a wired implementation, or is simply dropped here and reported as
/// evicted). Sized so a flood of distinct transactions cannot grow memory
/// without bound.
pub const MAX_STEM_ENTRIES: usize = 512;

/// Maximum seen-set entries. Must exceed the stem cap by a wide margin so
/// recently-fluffed transactions are still recognised as duplicates while
/// their stem entries have long been evicted.
pub const MAX_SEEN_ENTRIES: usize = 4096;

/// Extra uniform draws allowed when hunting for an alive stem peer.
/// Total draws per selection are `1 + MAX_FAILOVER_RETRIES`.
pub const MAX_FAILOVER_RETRIES: u32 = 3;

/// Closed-form mean of the stem-hop distribution: `p / (1 - p)`.
///
/// This is the *uncapped* mean. Sampling caps at [`MAX_STEM_HOPS`], so the
/// realised mean is [`geometric_mean_capped`]; with the defaults the cap
/// binds `P(H > 10) = 0.8^11 ≈ 0.086` of samples and the realised mean is
/// ≈ 3.57, not 4.0. Tests assert against the capped value honestly.
///
/// Returns `f64::INFINITY` for `p >= 1.0` (never stem-terminating) and `0.0`
/// for `p <= 0.0` (always fluff immediately).
pub fn geometric_mean(p_continue: f64) -> f64 {
    if p_continue >= 1.0 {
        f64::INFINITY
    } else if p_continue <= 0.0 {
        0.0
    } else {
        p_continue / (1.0 - p_continue)
    }
}

/// Realised mean stem length under the [`MAX_STEM_HOPS`] cap:
/// `E[min(H, cap)] = Σ_{k=1..=cap} p^k`.
///
/// The sampler piles the tail `P(H > cap) = p^(cap+1)` onto `cap` (early
/// fluff), so this — not [`geometric_mean`] — is the value simulations must
/// reproduce. With `p = 0.8, cap = 10`: ≈ 3.570.
pub fn geometric_mean_capped(p_continue: f64, cap: u32) -> f64 {
    if p_continue >= 1.0 {
        return f64::from(cap);
    }
    if p_continue <= 0.0 {
        return 0.0;
    }
    let mut mean = 0.0;
    let mut p_pow = 1.0;
    for _ in 0..cap {
        p_pow *= p_continue;
        mean += p_pow;
    }
    mean
}

/// Closed-form stem-length probabilities: `P(H = k) = p^k * (1 - p)`.
///
/// Returns `0.0` for out-of-range `p` or for `k > MAX_STEM_HOPS` (the capped
/// tail is redistributed to shorter lengths by early fluffing).
pub fn geometric_pmf(p_continue: f64, k: u32) -> f64 {
    if !(0.0..1.0).contains(&p_continue) || k > MAX_STEM_HOPS {
        return 0.0;
    }
    p_continue.powi(k as i32) * (1.0 - p_continue)
}

// ---------------------------------------------------------------------------
// Seeded RNG (SplitMix64): the only randomness source in this module.
// ---------------------------------------------------------------------------

/// Minimal deterministic RNG (SplitMix64). Seeded explicitly by the caller;
/// fixed seeds in tests make every relay decision reproducible.
#[derive(Clone, Debug)]
pub struct NodeRng {
    state: u64,
}

impl NodeRng {
    /// Create an RNG from an explicit seed.
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Next raw `u64` (SplitMix64).
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform `f64` in `[0, 1)`.
    pub fn next_f64(&mut self) -> f64 {
        const DIVISOR: f64 = (1u64 << 53) as f64;
        ((self.next_u64() >> 11) as f64) / DIVISOR
    }

    /// Uniform index into a slice of length `n`, or `None` when empty.
    ///
    /// Uses the HIGH bits of the generator output: SplitMix64's low bits
    /// have measurably weaker randomness, so `state % n` straight off the
    /// raw word is biased for small `n`.
    pub fn pick_index(&mut self, n: usize) -> Option<usize> {
        if n == 0 {
            return None;
        }
        Some(((self.next_u64() >> 32) % n as u64) as usize)
    }
}

/// Sample a stem-hop count from the geometric distribution with continuation
/// probability `p_continue`, capped at [`MAX_STEM_HOPS`].
///
/// `H` counts stem *edges*: `H = 0` means "fluff immediately".
pub fn sample_stem_hops(rng: &mut NodeRng, p_continue: f64) -> u32 {
    if p_continue <= 0.0 {
        return 0;
    }
    let mut hops: u32 = 0;
    while rng.next_f64() < p_continue {
        hops += 1;
        if hops >= MAX_STEM_HOPS {
            break;
        }
    }
    hops
}

/// Uniformly pick one candidate peer, excluding `exclude_self`.
///
/// Returns `None` when no eligible candidate exists. Pure uniform choice —
/// liveness filtering happens in [`pick_alive_stem_peer`].
pub fn pick_uniform_peer(
    rng: &mut NodeRng,
    candidates: &[PeerId],
    exclude_self: PeerId,
) -> Option<PeerId> {
    if candidates.is_empty() {
        return None;
    }
    // Fast path: single candidate.
    if candidates.len() == 1 {
        return if candidates[0] == exclude_self {
            None
        } else {
            Some(candidates[0])
        };
    }
    // Bounded scan for a non-self candidate without allocating.
    let start = rng.pick_index(candidates.len())?;
    for offset in 0..candidates.len() {
        let peer = candidates[(start + offset) % candidates.len()];
        if peer != exclude_self {
            return Some(peer);
        }
    }
    None
}

/// Pick one *alive* stem peer: up to `1 + MAX_FAILOVER_RETRIES` uniform draws
/// via [`pick_uniform_peer`], returning the first draw reported alive by
/// `is_alive`.
///
/// Returns `None` when no alive peer was found within the retry budget (the
/// caller must then fluff locally — never blackhole). Stale liveness data
/// only costs retries, never correctness.
pub fn pick_alive_stem_peer(
    rng: &mut NodeRng,
    candidates: &[PeerId],
    exclude_self: PeerId,
    is_alive: &impl Fn(PeerId) -> bool,
) -> Option<PeerId> {
    for _ in 0..=MAX_FAILOVER_RETRIES {
        match pick_uniform_peer(rng, candidates, exclude_self) {
            Some(peer) if is_alive(peer) => return Some(peer),
            None => return None,
            Some(_) => continue,
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Relay state machine.
// ---------------------------------------------------------------------------

/// Per-transaction stem bookkeeping held by one node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StemEntry {
    /// Stem budget handed to the next hop (`H - 1` at the originator).
    pub hops_left: u32,
    /// Peer the stem was forwarded to (failover target if it goes down).
    pub next_peer: PeerId,
}

/// What the node should do with a transaction right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayAction {
    /// Forward along the stem to exactly one peer.
    StemForward {
        /// The single selected next peer.
        to: PeerId,
    },
    /// Diffuse with a normal broadcast (fluff).
    FluffBroadcast,
    /// Already seen: do nothing (loop protection / duplicate suppression).
    IgnoreDuplicate,
}

/// Dandelion stem/fluff relay state for one node.
///
/// All transitions are pure functions of (state, arguments, seeded RNG).
/// Memory is bounded: see [`MAX_STEM_ENTRIES`] and [`MAX_SEEN_ENTRIES`].
/// How a transaction was seen by this node. The distinction is what makes
/// both loop recovery and storm termination work: a repeated *stem* delivery
/// of a never-fluffed transaction converts to diffusion, while any repeat of
/// an already-*fluffed* transaction is dropped silently.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SeenKind {
    /// Seen over the stem only (originated or stem-relayed, never fluffed).
    Stem,
    /// Seen via fluff broadcast (or forced there by loop recovery / timeout).
    Fluff,
}

#[derive(Clone, Debug)]
pub struct DandelionRelay {
    p_continue: f64,
    /// Insertion-ordered stem entries (front = oldest, evicted first).
    stem: VecDeque<(TxHash, StemEntry)>,
    /// Insertion-ordered seen log (front = oldest) backing `seen_kind`.
    seen_order: VecDeque<TxHash>,
    seen_kind: HashMap<TxHash, SeenKind>,
}

impl DandelionRelay {
    /// Create relay state with an explicit continuation probability.
    pub fn new(p_continue: f64) -> Self {
        Self {
            p_continue,
            stem: VecDeque::new(),
            seen_order: VecDeque::new(),
            seen_kind: HashMap::new(),
        }
    }

    /// Create relay state with [`DEFAULT_P_CONTINUE`].
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_P_CONTINUE)
    }

    /// Number of currently held stem entries (always `<= MAX_STEM_ENTRIES`).
    pub fn stem_len(&self) -> usize {
        self.stem.len()
    }

    /// Number of seen-set entries (always `<= MAX_SEEN_ENTRIES`).
    pub fn seen_len(&self) -> usize {
        self.seen_kind.len()
    }

    /// Whether `tx` was already fluffed through this node.
    pub fn is_fluffed(&self, tx: &TxHash) -> bool {
        self.seen_kind.get(tx) == Some(&SeenKind::Fluff)
    }

    /// Held stem entry for `tx`, if any.
    pub fn stem_entry(&self, tx: &TxHash) -> Option<StemEntry> {
        self.stem
            .iter()
            .find(|(h, _)| h == tx)
            .map(|(_, e)| *e)
    }

    /// Whether `tx` was already acted on (loop-protection probe).
    pub fn is_seen(&self, tx: &TxHash) -> bool {
        self.seen_kind.contains_key(tx)
    }

    /// Originate a new local transaction.
    ///
    /// Samples a geometric stem length; on `H == 0` or when no alive peer
    /// exists the transaction fluffs immediately — and is then tagged
    /// fluffed, so later re-deliveries terminate. Otherwise records the stem
    /// entry and returns `StemForward` to exactly one peer.
    /// Re-originating an already-seen transaction returns `IgnoreDuplicate`.
    pub fn originate(
        &mut self,
        rng: &mut NodeRng,
        tx: TxHash,
        candidates: &[PeerId],
        self_id: PeerId,
        is_alive: &impl Fn(PeerId) -> bool,
    ) -> RelayAction {
        if self.seen_kind.contains_key(&tx) {
            self.drop_stem(&tx);
            return RelayAction::IgnoreDuplicate;
        }
        let hops = sample_stem_hops(rng, self.p_continue);
        if hops == 0 {
            self.mark_seen(tx, SeenKind::Fluff);
            return RelayAction::FluffBroadcast;
        }
        match pick_alive_stem_peer(rng, candidates, self_id, is_alive) {
            Some(next) => {
                let remaining = hops - 1;
                self.mark_seen(tx, SeenKind::Stem);
                self.insert_stem(
                    tx,
                    StemEntry {
                        hops_left: remaining,
                        next_peer: next,
                    },
                );
                RelayAction::StemForward { to: next }
            }
            // No alive peer: recover by fluffing immediately (tagged fluffed).
            None => {
                self.mark_seen(tx, SeenKind::Fluff);
                RelayAction::FluffBroadcast
            }
        }
    }

    /// Handle a transaction arriving over the stem with remaining budget
    /// `incoming_hops_left` (the value the previous hop handed over).
    ///
    /// There is deliberately NO seen-gate on this path: a stem that loops
    /// back over visited nodes simply consumes budget on each visit and
    /// fluffs when the budget runs out. This mirrors Dandelion, keeps the
    /// realised path-length distribution exactly geometric (cut only by dead
    /// ends / failover), and — together with the rules below — leaves no
    /// silent-death path for an unfluffed transaction:
    ///
    /// * Already fluffed → drop any held stem state (**fluff wins**) and
    ///   `IgnoreDuplicate`.
    /// * Budget exhausted (`== 0`) → this node becomes the fluff source:
    ///   `FluffBroadcast` (stale stem entry, if any, is dropped).
    /// * Inbound budget over [`MAX_STEM_HOPS`] (attacker-controlled wire
    ///   value; originate-side sampling caps but relay ingress did not, so
    ///   `u32::MAX` used to forward as `MAX - 1`) → fail closed to the SAME
    ///   fluff-source branch: `FluffBroadcast`, never a forward beyond the
    ///   cap. Choice documented: fluff (diffuse, visible, complete) rather
    ///   than `min()`-clamping to `MAX_STEM_HOPS`, so a remote peer cannot
    ///   force a max-length stem/delay out of this node; legitimate budgets
    ///   `0..=MAX_STEM_HOPS` (including exactly `MAX_STEM_HOPS`) are
    ///   untouched. No new branch, no `Drop`/blackhole: over-cap reuses the
    ///   existing budget-exhausted handling, so fluff-wins, loop-burndown
    ///   and fluff-timeout properties are unchanged.
    /// * Otherwise forward to one alive peer with budget `- 1`, recording
    ///   (or overwriting) the stem entry; with no alive peer, fluff locally
    ///   instead of blackholing.
    pub fn on_stem_receive(
        &mut self,
        rng: &mut NodeRng,
        tx: TxHash,
        incoming_hops_left: u32,
        candidates: &[PeerId],
        self_id: PeerId,
        is_alive: &impl Fn(PeerId) -> bool,
    ) -> RelayAction {
        if self.seen_kind.get(&tx) == Some(&SeenKind::Fluff) {
            self.drop_stem(&tx);
            return RelayAction::IgnoreDuplicate;
        }
        if incoming_hops_left == 0 || incoming_hops_left > MAX_STEM_HOPS {
            self.drop_stem(&tx);
            self.mark_seen(tx, SeenKind::Fluff);
            return RelayAction::FluffBroadcast;
        }
        match pick_alive_stem_peer(rng, candidates, self_id, is_alive) {
            Some(next) => {
                self.mark_seen(tx, SeenKind::Stem);
                self.insert_stem(
                    tx,
                    StemEntry {
                        hops_left: incoming_hops_left - 1,
                        next_peer: next,
                    },
                );
                RelayAction::StemForward { to: next }
            }
            // Dead end (or all neighbours down): recover by fluffing from
            // here so at least the reachable component receives the tx.
            None => {
                self.drop_stem(&tx);
                self.mark_seen(tx, SeenKind::Fluff);
                RelayAction::FluffBroadcast
            }
        }
    }

    /// Handle a transaction arriving via fluff broadcast.
    ///
    /// The first fluff sighting returns `FluffBroadcast` (the caller relays
    /// the broadcast onward) and drops any held stem state: **fluff wins**.
    /// Already-fluffed transactions return `IgnoreDuplicate`, which is what
    /// terminates broadcast storms — each node relays a given fluff at most
    /// once. A node that only ever stemmed `tx` upgrades to fluffed and
    /// relays once, aiding diffusion into regions the stem missed.
    pub fn on_fluff_receive(&mut self, tx: TxHash) -> RelayAction {
        if self.seen_kind.get(&tx) == Some(&SeenKind::Fluff) {
            self.drop_stem(&tx);
            return RelayAction::IgnoreDuplicate;
        }
        self.mark_seen(tx, SeenKind::Fluff);
        self.drop_stem(&tx);
        RelayAction::FluffBroadcast
    }

    /// Failover: the stem peer holding `tx` is (now believed) down.
    ///
    /// * No held entry → `IgnoreDuplicate` (nothing to recover).
    /// * Recorded peer still alive → re-emit `StemForward` to it unchanged.
    /// * Otherwise pick another alive peer (bounded retries); on success the
    ///   entry is updated, on failure it is dropped and the node fluffs
    ///   locally rather than holding a dead stem.
    pub fn on_peer_down(
        &mut self,
        rng: &mut NodeRng,
        tx: &TxHash,
        candidates: &[PeerId],
        self_id: PeerId,
        is_alive: &impl Fn(PeerId) -> bool,
    ) -> RelayAction {
        let entry = match self.stem_entry(tx) {
            Some(e) => e,
            None => return RelayAction::IgnoreDuplicate,
        };
        if is_alive(entry.next_peer) {
            return RelayAction::StemForward {
                to: entry.next_peer,
            };
        }
        match pick_alive_stem_peer(rng, candidates, self_id, is_alive) {
            Some(next) => {
                self.insert_stem(
                    *tx,
                    StemEntry {
                        hops_left: entry.hops_left,
                        next_peer: next,
                    },
                );
                RelayAction::StemForward { to: next }
            }
            None => {
                self.drop_stem(tx);
                RelayAction::FluffBroadcast
            }
        }
    }

    /// Fluff timeout: force-fluff a held stem entry.
    ///
    /// Returns `Some(FluffBroadcast)` when an entry was held (the caller
    /// broadcasts and the tx is tagged fluffed), `None` otherwise. This is
    /// the specified mitigation for a stem blackhole: an attacker swallowing
    /// stem traffic can delay a transaction only until the timeout fires.
    /// Wiring would arm one such timer per stem entry (see
    /// `docs/DANDELION_PLAN.md`).
    pub fn fluff_timeout(&mut self, tx: &TxHash) -> Option<RelayAction> {
        if self.stem_entry(tx).is_some() {
            self.drop_stem(tx);
            self.mark_seen(*tx, SeenKind::Fluff);
            Some(RelayAction::FluffBroadcast)
        } else {
            None
        }
    }

    /// Insert a stem entry, evicting the oldest entries past the cap
    /// (fail-closed: memory never exceeds [`MAX_STEM_ENTRIES`]).
    /// Re-inserting refreshes the entry in place without growing the map.
    fn insert_stem(&mut self, tx: TxHash, entry: StemEntry) {
        if let Some(slot) = self.stem.iter_mut().find(|(h, _)| *h == tx) {
            slot.1 = entry;
            return;
        }
        while self.stem.len() >= MAX_STEM_ENTRIES {
            self.stem.pop_front();
        }
        self.stem.push_back((tx, entry));
    }

    /// Drop any held stem entry for `tx`.
    fn drop_stem(&mut self, tx: &TxHash) {
        if let Some(pos) = self.stem.iter().position(|(h, _)| h == tx) {
            self.stem.remove(pos);
        }
    }

    /// Record `tx` as seen with `kind`, evicting the oldest entries past the
    /// cap. Re-marking upgrades stem-only sightings to fluffed in place
    /// without growing the map.
    fn mark_seen(&mut self, tx: TxHash, kind: SeenKind) {
        if let Some(existing) = self.seen_kind.get(&tx) {
            // Upgrade stem-only sightings to fluffed; never downgrade, never
            // duplicate the order log.
            if *existing == SeenKind::Stem && kind == SeenKind::Fluff {
                self.seen_kind.insert(tx, SeenKind::Fluff);
            }
            return;
        }
        while self.seen_order.len() >= MAX_SEEN_ENTRIES {
            if let Some(oldest) = self.seen_order.pop_front() {
                self.seen_kind.remove(&oldest);
            }
        }
        self.seen_order.push_back(tx);
        self.seen_kind.insert(tx, kind);
    }
}

/// Build a deterministic transaction id for tests and simulations.
/// Production wiring would use the real transaction hash; the policy only
/// needs uniqueness per transaction.
pub fn txid_from_u64(n: u64) -> TxHash {
    let mut id = [0u8; 32];
    id[..8].copy_from_slice(&n.to_le_bytes());
    id[8..16].copy_from_slice(&n.to_be_bytes());
    id
}
