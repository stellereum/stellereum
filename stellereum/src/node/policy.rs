use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use stellereum::consensus::{ValidatorSet, VoteKind};
use stellereum::consensus_net::{ConsensusMsg, ConsensusSender, MAX_BATCH_ITEMS};
use stellereum::runtime::ValidatorRuntime;

/// How often to push this node's own finalized block BODIES back onto the DHT.
/// Default 30000 ms; override with `STELL_RETRO_PUBLISH_INTERVAL_MS`.
/// Node-local DHT republication cadence, not consensus — nodes MAY differ.
pub(crate) const RETRO_PUBLISH_INTERVAL_DEFAULT_MS: u64 = 30_000;
/// Bodies per pass. Bounds both the memory held and the DHT work done inside one
/// tick of the consensus loop; the cursor makes the backlog drain across passes
/// instead of being skipped.
pub(crate) const RETRO_PUBLISH_MAX_PER_PASS: usize = 128;
/// How far back the passes reach. A peer further behind than this still cannot
/// catch up from us. 4096 blocks is roughly 27 minutes of chain at 400 ms/block.
pub(crate) const RETRO_PUBLISH_DEPTH: u64 = 4_096;

/// How often the consensus loop asks the network whether it has fallen behind.
///
/// CHANGED 2026-11-18 (event-driven catch-up): the PRIMARY catch-up path is
/// now REACTIVE. A verified `Committed` / `Proposal` / `Vote` that names a
/// height above ours — or a peer head pointer above ours — schedules the
/// attempt on the next tick ([`catchup_action`]). This timer is only a
/// BACKSTOP for a node that is already known to be behind; a node AT the tip
/// (no peer known to be ahead) never probes the DHT on it.
///
/// Default 30_000 ms (was 2_000 ms). The old 2-3 s cadence made every idle
/// node poll the DHT many times a minute, and with a dead peer in the table
/// each poll cost the whole `STELL_CATCHUP_BUDGET_MS` (measured live: 15 000 ms
/// burned on every tick, the stall the budget knob papered over). Reactive
/// triggers remove the need to poll at all; 30 s is a last-resort recheck.
///
/// Override with `STELL_CATCHUP_INTERVAL_MS`. Node-local liveness probe
/// cadence, not consensus — nodes MAY differ.
pub(crate) const CATCHUP_INTERVAL_DEFAULT_MS: u64 = 30_000;

/// Window in which a successful live adopt keeps the periodic catch-up machine
/// deferred (the "live flow is delivering" proof).
///
/// Deliberately NOT `CATCHUP_INTERVAL_DEFAULT_MS`: the backstop moved to 30 s
/// (event-driven catch-up), but this window must still track the LIVE message
/// tempo. At 1 block/s a 30 s window would suppress the DHT walk for half a
/// minute after the last adopt even when a hole in the pushed sequence needs
/// it; 2 s (the old interval value) preserved the proven defer behavior.
pub(crate) const LIVE_ADOPT_FRESH_MS: u64 = 2_000;

/// Hard expiry for a peer head hint (`rt.peer_hint`).
///
/// A hint is only ever planted from VERIFIED evidence (a QC-backed
/// `Committed`, or a proposal whose proposer signature + membership checked).
/// Even then it must not pin catch-up forever: a walk can fail (peer gone,
/// transport wedged, hash no longer on the canonical chain), and the DHT head
/// read it suppresses is the only alternative. After this window the hint is
/// dropped, `should_probe_dht_head` becomes true again, and the next pass can
/// read a real head. Node-local recovery policy — never consensus.
pub(crate) const PEER_HINT_TTL_MS: u64 = 60_000;

/// Low-frequency blind probe even when the node believes it is at the tip.
///
/// "At tip" is inferred from the ABSENCE of ahead evidence, so a behind-but-
/// silent node (one-way push loss, DHT-only follower, restored high round)
/// would otherwise skip `try_catch_up` forever and never reach the blind-QC
/// `tip+1` rescue. One cheap head/QC probe per this window is the backstop.
///
/// At the current ~240 ms block tempo this window is the node's DETECTION
/// LATENCY, so it must stay inside ONE snapshot generation: the rescue path
/// (`try_snapshot_sync`) can then use the state a peer published during this
/// window instead of crawling through several generations of pruned history.
/// 600 s (the old value, chosen at ~1 s blocks) is 2 500 blocks now; 120 s is
/// 500 blocks — still cheap (one head + one QC sidecar read), and well above
/// the 30 s backstop so it never becomes the primary poll.
pub(crate) const AT_TIP_PROBE_INTERVAL_MS: u64 = 120_000;

/// How far above our FINALIZED tip a peer-named height may be before it is
/// treated as "not this chain" for cheap pre-checks.
///
/// A `Committed` beyond this is rejected BEFORE any block hashing or QC
/// verification (pentest-2 F-5); the DHT head/walk remains the path for a
/// genuinely far-behind node. Local DoS bound — never a quorum rule.
pub(crate) const MAX_COMMITTED_LOOKAHEAD: u64 = 64;

/// Compact frames one peer may force us to process (index/mempool work) in a
/// single tick. Honest traffic is a handful of frames per round; beyond this
/// the extra frames are dropped loudly, so a flood cannot turn a 400 B frame
/// into unbounded whole-pool work.
pub(crate) const COMPACT_FRAMES_PER_PEER_PER_TICK: u32 = 16;

/// Bounded pulls one peer may cause us to EMIT per tick (pentest-2 H1).
pub(crate) const COMPACT_PULLS_PER_PEER_PER_TICK: u32 = 8;

/// Whole-node cap on compact short-id index BUILDS per tick.
///
/// A build clones and hashes the whole mempool (~50k txs), so per-peer frame
/// budgets alone are not enough: one peer can vary `prev_hash` on a
/// same-height header and force a fresh salt each time. Two builds/tick cover
/// the only two relevant heights (`hc.height`, `hc.height+1`); anything else
/// is dropped and retried next tick.
pub(crate) const COMPACT_INDEX_BUILDS_PER_TICK: u32 = 2;

/// Cap on resolved compact loopbacks waiting for re-entry into the drain.
///
/// Every entry holds a full proposal, so it must be bounded independently of
/// `INBOUND_DEFERRED_CAP` (the loopback is local and is drained with priority,
/// never parked behind peer traffic). On overflow the OLDEST loopback is
/// dropped with a loud counter: the originating peer re-announces, and an
/// attacker can never pin memory.
pub(crate) const LOOPBACK_QUEUE_CAP: usize = 64;

/// Default FLOOR for one catch-up pass (`STELL_CATCHUP_BUDGET_MS`).
///
/// Deliberately small: this loop IS the consensus clock, so a DHT/body walk
/// that overruns it must be abandoned, not waited out. The live stall had this
/// raised to 15 000 ms against a dead peer and every tick paid it in full;
/// with event-driven catch-up the attempt is rare, but it must still never
/// hold a tick hostage.
///
/// This is only what an AT-TIP node (no gap evidence) may spend on the cheap
/// blind probe. A node known to be behind uses
/// [`catchup_pass_budget_ms`], which scales the budget with the gap — a flat
/// 250 ms admits about one WAN round trip, i.e. one body, which cannot outrun
/// a ~240 ms/block chain (and could not even complete a head read + one body
/// fetch on a 400 ms-RTT link, the same 1-block-behind never-heals class the
/// 5 s `net_budget` floor was added for).
pub(crate) const CATCHUP_BUDGET_DEFAULT_MS: u64 = 2_000;

/// Minimum spacing between two REACTIVE catch-up attempts.
///
/// Behind evidence repeats every tick while it stays true (a stale peer hint,
/// a peer rebroadcasting its commit), so without a floor the loop would start
/// a DHT walk every tick (~50 ms). Half a second still reacts to a NEW event
/// far inside the 30 s backstop. Local pacing only — never consensus.
pub(crate) const REACTIVE_CATCHUP_MIN_GAP_MS: u64 = 500;

/// What this tick should do about catch-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatchupAction {
    /// Run the catch-up pass now (reactive evidence, or the backstop timer
    /// fired on a node that is NOT at the tip).
    Run,
    /// The backstop timer fired, but no peer is known to be ahead: skip the
    /// expensive DHT/body work. This is the event-driven default on an idle,
    /// in-sync node.
    SkipAtTip,
    /// At-tip backstop window elapsed ([`AT_TIP_PROBE_INTERVAL_MS`]): run the
    /// CHEAP blind probe (`try_catch_up` reads the head and probes tip+1; with
    /// no peer ahead the walk is a no-op). This is what rescues a silent
    /// behind node that never receives ahead evidence.
    BlindProbe,
    /// Nothing to do this tick (reactive event too recent, timer not due, or
    /// no reactive evidence yet).
    Wait,
}

/// Event-driven catch-up decision (pure; pins the new scheduling policy).
///
/// Inputs:
/// * `reactive_due` — a verified peer message named a height above ours, or a
///   peer head pointer above ours, since the last decision;
/// * `since_last_ms` — wall time since the last catch-up attempt (any kind);
/// * `interval_ms` — the backstop interval (`catchup_interval()`);
/// * `at_tip` — no peer is known to be ahead (see [`node_is_at_tip`]).
///
/// Rules:
/// 1. REACTIVE evidence wins and runs as soon as the short reactive floor
///    allows — never waiting for `interval_ms`;
/// 2. otherwise the backstop interval runs ONLY when we are not at the tip
///    (a node at the tip has nothing to fetch and must not poll the DHT);
/// 3. otherwise wait.
pub fn catchup_action(
    reactive_due: bool,
    since_last_ms: u64,
    interval_ms: u64,
    at_tip: bool,
) -> CatchupAction {
    if reactive_due && since_last_ms >= REACTIVE_CATCHUP_MIN_GAP_MS {
        return CatchupAction::Run;
    }
    if since_last_ms < interval_ms {
        return CatchupAction::Wait;
    }
    if at_tip {
        // Silence is not equality. Keep a low-frequency backstop probe so a
        // behind-but-silent node still runs the cheap head/tip+1 read.
        if since_last_ms >= AT_TIP_PROBE_INTERVAL_MS {
            CatchupAction::BlindProbe
        } else {
            CatchupAction::SkipAtTip
        }
    } else {
        CatchupAction::Run
    }
}

/// True when NO peer is known to be ahead of `our_tip`.
///
/// `peer_named_height` is the tallest height that VERIFIED peer traffic proves
/// FINALIZED: a commit's height, or a proposal/vote height minus one (a peer
/// building/voting at H has decided H-1). `peer_hint_height` is the head
/// pointer a peer published/committed. Either being above our tip means a peer
/// knows more than we do, so the node is NOT at the tip and the periodic
/// backstop may probe. Pure.
pub fn node_is_at_tip(our_tip: u64, peer_named_height: u64, peer_hint_height: Option<u64>) -> bool {
    peer_named_height <= our_tip && peer_hint_height.unwrap_or(0) <= our_tip
}

/// Whether the reactive latch must be re-armed after a catch-up pass that
/// ADVANCED us.
///
/// `try_catch_up` can stop SHORT of the peer's head: a snapshot restore lands
/// on the newest usable boundary and leaves the remaining gap to the body
/// walk. The evidence that scheduled the pass (a verified head hint, or the
/// at-tip evidence a vote/proposal named) is still ahead when the pass
/// returns, but the success path `continue`s the tick loop and therefore
/// skips the end-of-tick persistent-evidence re-arm. Without this predicate
/// the node drops to the 30 s backstop for a walk it could finish on the next
/// reactive tick — the difference between closing a gap in a second and
/// crawling toward a moving head. Pure; node-local pacing only.
pub fn catchup_still_behind(
    our_tip: u64,
    peer_hint: Option<(u64, [u8; 32])>,
    peer_named_height: u64,
) -> bool {
    peer_hint.is_some_and(|(ph, _)| ph > our_tip) || peer_named_height > our_tip
}

/// Height a message NAMES that is above `our_height`, if any.
///
/// One choke point for "a peer told us it is ahead", used by the drain for
/// `Proposal` and `Vote`. `Committed` is compared against our FINALIZED TIP by
/// the drain itself (a commit for the height we are voting on is already one
/// block ahead of what we decided), so it is also accepted here for callers
/// that measure against a consensus height. Returns `None` for messages that
/// carry no height (batches are flattened first) or that do not name a future
/// height. NOTE: callers must only act on the result AFTER the message passed
/// its own verification (QC / proposer signature / vote signature) — this
/// helper is arithmetic, not authentication. Pure.
pub fn inbound_names_ahead(our_height: u64, msg: &ConsensusMsg) -> Option<u64> {
    let named = match msg {
        ConsensusMsg::Committed { height, .. } => *height,
        // SIGNED value only: `block.height` is part of the proposer-signed
        // block hash, while the envelope `height` is unauthenticated duplicate
        // metadata (pentest-2 F-4). Replaying a public signed block with a
        // mutated envelope field must never re-arm catch-up.
        ConsensusMsg::Proposal { block, .. } => block.height,
        ConsensusMsg::Vote { vote, .. } => vote.height,
        _ => return None,
    };
    (named > our_height).then_some(named)
}

/// Whether a DHT head read is still needed: only when no peer has already told
/// us, in a verified message, that it is ahead.
///
/// This is the receive-side half of push-based propagation: the live stall was
/// a catch-up pass spending its whole budget on a DHT query to a dead peer
/// while the answer (a peer's head) was already in hand from the push channel.
/// Pure.
pub fn should_probe_dht_head(our_height: u64, peer_hint: Option<(u64, [u8; 32])>) -> bool {
    !peer_hint.is_some_and(|(h, _)| stellereum::network::peer_head_is_ahead(our_height, h))
}

/// Validated hint: `Some` only when it is AHEAD of `our_tip` and still inside
/// [`PEER_HINT_TTL_MS`]. A stale or reached hint must not keep suppressing the
/// DHT head read (pentest-2 F-2).
pub fn peer_hint_effective(
    our_tip: u64,
    hint: Option<(u64, [u8; 32])>,
    age_ms: u64,
) -> Option<(u64, [u8; 32])> {
    let hint = hint?;
    if age_ms > PEER_HINT_TTL_MS
        || !stellereum::network::peer_head_is_ahead(our_tip, hint.0)
        || hint.0 > our_tip.saturating_add(MAX_COMMITTED_LOOKAHEAD)
    {
        return None;
    }
    Some(hint)
}

/// True when a `Committed` height is inside the cheap pre-verification window.
///
/// Far-ahead commits are refused before `compute_hash`/QC work (F-5); the DHT
/// head read is their catch-up path.
pub fn committed_height_is_cheaply_relevant(our_tip: u64, height: u64) -> bool {
    height <= our_tip.saturating_add(MAX_COMMITTED_LOOKAHEAD)
}

/// Clamp a peer-named height to what this chain could plausibly be at.
///
/// A verified-but-absurd claim (a byzantine member signing `height = 10⁹`, or a
/// replayed member vote) must not keep the at-tip predicate false forever.
/// Clamping is arithmetic only; the evidence itself was already verified.
pub fn clamp_peer_named_height(our_tip: u64, named: u64) -> u64 {
    named.min(our_tip.saturating_add(MAX_COMMITTED_LOOKAHEAD))
}

/// Compact announcements are only worth resolving at the height we are about
/// to decide (or the next one after a push). Anything else is catch-up's job
/// and must not force mempool/index work (C2/F-8).
pub fn compact_proposal_height_is_relevant(our_hc_height: u64, height: u64) -> bool {
    height == our_hc_height || height == our_hc_height.saturating_add(1)
}

/// Parent plausibility for a compact announcement (cheap, before any index
/// build): a proposal at OUR height must build on our finalized tip; the only
/// other accepted height is the next one (whose parent is the in-flight block).
pub fn compact_parent_is_plausible(
    header_height: u64,
    prev_hash: [u8; 32],
    our_hc_height: u64,
    our_tip_hash: [u8; 32],
) -> bool {
    if header_height == our_hc_height {
        prev_hash == our_tip_hash
    } else {
        header_height == our_hc_height.saturating_add(1)
    }
}

/// Whether `FetchFull` should ask the proposer for the full body.
///
/// Only for the live/next height. A far-ahead or stale announcement is not
/// evidence and gets no request (it would only amplify), while the peer's own
/// re-announcement still reaches the normal catch-up path.
pub fn full_proposal_request_is_relevant(our_hc_height: u64, height: u64) -> bool {
    compact_proposal_height_is_relevant(our_hc_height, height)
}

/// Charge one compact frame against a peer's per-tick budget. Returns false
/// when the peer is over budget (caller counts/drops before any heavy work).
pub fn compact_frame_within_peer_budget(count: &mut u32, max: u32) -> bool {
    if *count >= max {
        return false;
    }
    *count = count.saturating_add(1);
    true
}

/// Insert into a bounded loopback queue, dropping the OLDEST entry on
/// overflow. Returns true when an older entry was dropped (caller counts it
/// loudly). Bounded memory is the invariant; dropping the oldest admits the
/// newest honest resolution (the attacker's earlier flood is what is lost).
pub fn push_bounded_loopback<T>(
    q: &mut std::collections::VecDeque<T>,
    item: T,
    cap: usize,
) -> bool {
    let dropped = if q.len() >= cap {
        q.pop_front();
        true
    } else {
        false
    };
    q.push_back(item);
    dropped
}

/// Effective retro-publish interval (`STELL_RETRO_PUBLISH_INTERVAL_MS`, default 30000).
pub(crate) fn retro_publish_interval() -> std::time::Duration {
    std::time::Duration::from_millis(
        std::env::var("STELL_RETRO_PUBLISH_INTERVAL_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(RETRO_PUBLISH_INTERVAL_DEFAULT_MS),
    )
}

/// How long without ANY inbound consensus message (vote/proposal/commit) before
/// an otherwise-stagnant retro-publish pass is suppressed. A returning peer
/// announces itself via votes/proposals first, which restamps the inbound
/// clock and resumes retro — so this only ever silences pushes to nobody.
pub(crate) const RETRO_SUPPRESS_IDLE_SECS: u64 = 60;

/// Node-loud count of suppressed dead-peer retro passes (visibility only).
pub(crate) static RETRO_SUPPRESSED_N: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Whether this retro-publish pass should be suppressed (dead-peer spin gate).
///
/// Pure (testable without a node): suppress only when BOTH hold —
///  * `finalized_tip == tip_at_last_retro_pass`: no new finalized block since
///    the last pass, so the pass would re-push the same window to nobody;
///  * `inbound_idle_secs >= RETRO_SUPPRESS_IDLE_SECS`: nothing arrived on the
///    consensus channel for a full minute, so no peer is even announcing.
///
/// A returning peer's first vote/proposal restamps the inbound clock and the
/// next pass runs; a new finalization advances the tip and the next pass runs.
/// Local policy + logging only — never consensus, never wire.
pub fn should_suppress_retro_publish(
    finalized_tip: u64,
    tip_at_last_retro_pass: u64,
    inbound_idle_secs: u64,
) -> bool {
    finalized_tip == tip_at_last_retro_pass && inbound_idle_secs >= RETRO_SUPPRESS_IDLE_SECS
}

/// How long without ANY verified vote/proposal from a BEHIND peer before a
/// retro-publish pass is suppressed (`STELL_RETRO_BEHIND_WINDOW_SECS`, default
/// 120). Retro serves SMALL gaps (a 1-8-block lag fetching recent bodies);
/// deep gaps (thousands of blocks) use snapshot-sync, a peer-initiated path
/// that never needs our push — so pushing our window at nobody for minutes is
/// pure tick stall (measured: exactly 5s per pass, a timeout, on ~half the
/// ticks). A behind-and-talking peer's next verified vote/proposal restamps
/// the clock and the next pass runs. Never suppresses when WE are behind
/// (the catch-up path is untouched; the stale-push guard above owns that).
pub(crate) const RETRO_BEHIND_WINDOW_DEFAULT_SECS: u64 = 120;

/// Effective behind-peer window (`STELL_RETRO_BEHIND_WINDOW_SECS`, default 120).
pub(crate) fn retro_behind_window_secs() -> u64 {
    std::env::var("STELL_RETRO_BEHIND_WINDOW_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(RETRO_BEHIND_WINDOW_DEFAULT_SECS)
}

/// Node-loud count of behind-gate-suppressed retro passes (visibility only).
pub(crate) static RETRO_BEHIND_SUPPRESSED_N: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Whether this retro-publish pass should be suppressed for lack of a
/// behind-and-talking peer (behind-peer gate).
///
/// Pure (testable without a node): suppress only when BOTH hold —
///  * `we_are_behind == false`: we are at/above the peer hint, so the
///    catch-up (fetch) path needs nothing from us right now;
///  * `secs_since_behind_peer` is `None` (never seen one this run) or
///    `>= behind_window_secs` (no VERIFIED vote/proposal from a peer at a
///    height below ours within the window).
///
/// A returning/lagging peer's first verified vote/proposal below our height
/// restamps the clock and the next pass runs. Local policy + logging only —
/// never consensus, never wire.
pub fn should_suppress_retro_no_behind_peer(
    secs_since_behind_peer: Option<u64>,
    behind_window_secs: u64,
    we_are_behind: bool,
) -> bool {
    if we_are_behind {
        return false;
    }
    match secs_since_behind_peer {
        None => true,
        Some(idle) => idle >= behind_window_secs.max(1),
    }
}

/// Fast view-change timeout for a PROVEN-DOWN scheduled proposer
/// (`STELL_DOWN_PROPOSER_TIMEOUT_MS`, default 800). Node-local policy only:
/// timeouts are never consensus — every peer applies its own, and a proposal
/// that arrives first wins regardless of the timer.
pub(crate) const DOWN_PROPOSER_TIMEOUT_DEFAULT_MS: u64 = 800;

/// Effective down-proposer timeout: env override if positive, else the default.
pub fn down_proposer_timeout_ms() -> u64 {
    std::env::var("STELL_DOWN_PROPOSER_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DOWN_PROPOSER_TIMEOUT_DEFAULT_MS)
}

/// Cap on round 0 propose waiting when no proposal has landed (`STELL_ROUND_ZERO_TIMEOUT_MS`, default 650ms).
pub fn round_zero_timeout_ms() -> u64 {
    std::env::var("STELL_ROUND_ZERO_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(650)
}

/// Straggler grace (proposer-rework §2c, docs/PROPOSER_REWORK.md): bounded
/// additive EXECUTION hold while a behind-but-live peer (or an unheard
/// scheduled proposal) may still deliver.
///
/// This is deliberately NOT part of the deterministic timeout VALUE
/// (`deterministic_timeout_for` stays byte-identical, same-on-all-nodes):
/// same category as the already-accepted local holds (peer-active wait,
/// retransmit). Tendermint safety is time-free; only liveness uses timing,
/// and the grace only ever WIDENS honest-round overlap, so heterogeneous
/// timeouts cannot fork.
///
/// Env, all default-off (0 = current behavior, the added term is 0 and every
/// gate below is byte-identical):
/// * `STELL_STRAGGLER_GRACE_MS` — hold length when fresh straggler evidence
///   exists (default 0 = disabled).
/// * `STELL_STRAGGLER_GRACE_CAP_MS` — per-round upper bound (default 30000).
/// * `STELL_STRAGGLER_FRESHNESS_MS` — how recent the evidence must be
///   (default: 5x the round-timeout base). Silent peers age out, so a dead
///   peer cannot park the chain — only a live-but-slow one buys extra time.
pub const STRAGGLER_GRACE_MS_DEFAULT: u64 = 0;
pub const STRAGGLER_GRACE_CAP_MS_DEFAULT: u64 = 30_000;

pub fn straggler_grace_ms() -> u64 {
    std::env::var("STELL_STRAGGLER_GRACE_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(|v| v.clamp(0, 600_000))
        .unwrap_or(STRAGGLER_GRACE_MS_DEFAULT)
}

pub fn straggler_grace_cap_ms() -> u64 {
    std::env::var("STELL_STRAGGLER_GRACE_CAP_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(|v| v.clamp(0, 600_000))
        .unwrap_or(STRAGGLER_GRACE_CAP_MS_DEFAULT)
}

pub fn straggler_freshness_ms(round_timeout_ms: u64) -> u64 {
    std::env::var("STELL_STRAGGLER_FRESHNESS_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(|v| v.clamp(1_000, 3_600_000))
        .unwrap_or_else(|| round_timeout_ms.saturating_mul(5).clamp(1_000, 3_600_000))
}

/// Pure straggler-hold decision (no clock read: caller passes the observed
/// age in ms). Returns hold ms in `[0, min(grace, cap)]`.
///
/// Evidence (both require FRESH observation, `age_ms < freshness_ms`):
/// * clause 1 (behind-vote): a live peer's newest vote names an older
///   `(height, round)` than ours — its vote for our round may still be in
///   flight, so hold the round open one grace before view-changing.
/// * clause 2 (scheduled-proposal): we hold no live proposal and a peer is
///   live at our height but not ahead of us — the scheduled value may still
///   be in flight, so wait instead of racing to the next round proposalless.
///   (Approximation of "scheduled proposer not demonstrably ahead" using the
///   single-slot peer signal available in the loop; same-height-not-ahead is
///   the only case where waiting can help — an ahead peer is followed via the
///   future-rule jumps, never waited on.)
pub fn straggler_hold_ms(
    our_height: u64,
    our_round: u32,
    has_live_proposal: bool,
    peer_seen: Option<(u64, u32, u64)>,
    grace_ms: u64,
    cap_ms: u64,
    freshness_ms: u64,
) -> u64 {
    if grace_ms == 0 {
        return 0;
    }
    let Some((ph, pr, age_ms)) = peer_seen else {
        return 0;
    };
    if age_ms >= freshness_ms {
        return 0;
    }
    let behind = ph < our_height || (ph == our_height && pr < our_round);
    let same_height_not_ahead = ph == our_height && pr <= our_round;
    let evidence = behind || (!has_live_proposal && same_height_not_ahead);
    if !evidence {
        return 0;
    }
    grace_ms.min(cap_ms)
}

/// Cap an additive execution hold (straggler grace) to the slack between the
/// deterministic view-change deadline and the pre-existing 2× peer-active
/// hold bound (`hold_bounded`: the gate fires at `max(effective, 2 * base)`
/// while a peer is active, so the effective rung is ~2× the configured base
/// — docs/TEMPO_PROFILE.md §5.3).
///
/// An UNSUBSUMED grace stacks past that bound (rung dwell up to
/// `effective + grace`); SUBSUMED, it only fills the slack up to the bound
/// the node already waits on, never past it. The deterministic core is
/// untouched (same-on-all-nodes); only the local hold shrinks.
///
/// Pure (no clock read), so `hold_ms == 0` returns 0 for every input — with
/// the straggler envs unset the gate below stays byte-identical (pinned by
/// `grace_zero_hold_zero_deadline_unchanged`).
#[cfg(test)]
pub(crate) fn cap_hold_to_two_x_bound(hold_ms: u64, effective_ms: u64, base_ms: u64) -> u64 {
    hold_ms.min(base_ms.saturating_mul(2).saturating_sub(effective_ms))
}

/// Effective snapshot creation interval (`STELL_SNAPSHOT_INTERVAL`, default 1000 blocks).
pub fn snapshot_interval() -> u64 {
    std::env::var("STELL_SNAPSHOT_INTERVAL")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(1000)
        .max(50)
}

/// Largest body gap the sequential back-walk may cover.
///
/// The walk cap exists to bound WAN work (an unbounded walk is a DoS vector),
/// but a FIXED 256 stranded any node whose newest snapshot was further back:
/// snapshots are published every `snapshot_interval()` heights (default 1000),
/// so a node that restored at boundary B could face a gap of up to
/// `interval + cadence_slack` > 256, and with finality stopped (two nodes
/// wiped) no newer snapshot is ever produced — the cluster could not
/// self-recover. The bound therefore tracks the snapshot cadence: a node always
/// has a walkable path to the next snapshot, while the ceiling keeps the DoS
/// property (never unbounded, never more than a few thousand blocks).
pub fn max_walk_gap() -> u64 {
    snapshot_interval().saturating_add(64).clamp(256, 4096)
}

/// Whether the CURRENT round's propose-timeout should be capped at
/// [`down_proposer_timeout_ms`] instead of growing with the round backoff.
///
/// Pure (testable without a node): true only when the scheduled proposer is
/// proven down — ledger `missed` streak at/above `DOWNTIME_MISS_THRESHOLD`
/// (10 consecutive heights absent from finalized QCs, counted identically on
/// every node from blocks, never from local observation) — AND no
/// signature-verified vote from it was observed at this height (a vote proves
/// it is alive right now, whatever the ledger says).
///
/// The caller additionally requires "no live proposal held this round": if the
/// proposer is merely slow, its proposal still arrives first, seats
/// `has_live_proposal`, and the normal backoff timeout applies — the race
/// resolves toward waiting, never toward a fork, because a timeout can only
/// move OUR round, never the chain.
#[cfg(test)]
pub(crate) fn should_use_down_proposer_timeout(
    missed_streak: u32,
    vote_seen_from_proposer: bool,
) -> bool {
    missed_streak >= stellereum::staking::DOWNTIME_MISS_THRESHOLD && !vote_seen_from_proposer
}

/// Effective catch-up probe interval (`STELL_CATCHUP_INTERVAL_MS`, default
/// 30000 — the BACKSTOP cadence; reactive peer evidence runs far sooner).
pub(crate) fn catchup_interval() -> std::time::Duration {
    std::time::Duration::from_millis(
        std::env::var("STELL_CATCHUP_INTERVAL_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(CATCHUP_INTERVAL_DEFAULT_MS),
    )
}

/// Effective wall-time budget for one catch-up pass (`STELL_CATCHUP_BUDGET_MS`,
/// default 250). A pass that exceeds it is abandoned and retried later; the
/// tick is the consensus clock and must not wait on a dead DHT.
pub(crate) fn catchup_budget() -> std::time::Duration {
    std::time::Duration::from_millis(
        std::env::var("STELL_CATCHUP_BUDGET_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(CATCHUP_BUDGET_DEFAULT_MS),
    )
}

/// Gap-aware wall-time budget for ONE catch-up pass.
///
/// `base_ms` is the configured floor ([`catchup_budget`],
/// [`CATCHUP_BUDGET_DEFAULT_MS`]). That value is enough for the cheap at-tip
/// blind probe and a 1-block self-heal, where holding the tick longer only
/// delays the next round. It is NOT enough for a node known to be behind: a
/// body fetch costs a WAN round trip, and at the current ~240 ms block tempo a
/// behind node must fetch more than one body per pass just to keep up, let
/// alone close the gap. The old flat 250 ms admitted roughly one body per pass
/// while the chain produced four per second — the node retried every
/// `REACTIVE_CATCHUP_MIN_GAP_MS` forever and never converged; snapshot-sync
/// (tens of MB) could never fit at all.
///
/// So the budget scales with the gap the same way the historical `net_budget`
/// documented: 30 s for a walkable gap (1..=100) and 180 s once only
/// snapshot-sync can bridge it (>100). While behind, the node validates
/// nothing the network needs, so a longer tick costs nothing and is the only
/// way to converge. Pure; node-local liveness policy, never consensus.
pub fn catchup_pass_budget_ms(base_ms: u64, gap: u64) -> u64 {
    const NEAR_GAP_BUDGET_MS: u64 = 30_000;
    const FAR_GAP_BUDGET_MS: u64 = 180_000;
    let gap_budget = match gap {
        0 => base_ms,
        1..=100 => NEAR_GAP_BUDGET_MS,
        _ => FAR_GAP_BUDGET_MS,
    };
    base_ms.max(gap_budget)
}

pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Parse the `--seed` argument of the devnet simulator.
///
/// The seed is hex (an optional `0x` prefix is accepted) and may have any
/// length; it is the ONLY source of randomness in the simulation, so the same
/// seed always yields the same genesis keys, the same workload and the same
/// state root. An empty seed falls back to a fixed default instead of failing
/// — an empty seed is still a perfectly good (constant) seed.
pub(crate) fn parse_devnet_seed(raw: &str) -> anyhow::Result<Vec<u8>> {
    let trimmed = raw.trim();
    let trimmed = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if trimmed.is_empty() {
        return Ok(b"stellereum-devnet".to_vec());
    }
    hex::decode(trimmed).map_err(|e| anyhow::anyhow!("invalid --seed hex value '{raw}': {e}"))
}

/// On-disk mempool file for one shard.
///
/// Single-shard nodes keep the historical `./data/mempool.bin` (so existing
/// deployments and tests are byte-identical). A multi-shard process gives each
/// shard its own file, or the pools of two shards would clobber each other on
/// every save/restore.
pub(crate) fn mempool_path_for_shard(shard: u32, sharded: bool) -> std::path::PathBuf {
    if sharded {
        std::path::PathBuf::from(format!("./data/mempool-shard{shard}.bin"))
    } else {
        std::path::PathBuf::from("./data/mempool.bin")
    }
}

/// On-disk block/state store directory for one shard.
///
/// Single-shard nodes (and the masterchain of a multi-shard process) keep the
/// historical `./data/store`; every workchain gets its own `./data/store-shardN`.
/// Sharing one directory would let the finalized height, consensus safety record
/// and genesis fingerprint of one shard overwrite the other's.
pub(crate) fn store_path_for_shard(shard: u32, sharded: bool) -> std::path::PathBuf {
    if sharded && shard != stellereum::sharding::MASTERCHAIN_SHARD {
        std::path::PathBuf::from("./data").join(format!("store-shard{shard}"))
    } else {
        std::path::PathBuf::from("./data").join("store")
    }
}

/// Fixed genesis balance credited to every validator account. Because it is the
/// SAME for every node and applied to the SAME validator set, all nodes derive an
/// identical genesis state root (deterministic genesis).
///
/// SUPPLY INVARIANT: the pre-mined genesis allocation is folded into the
/// engine's minted-supply counter on the first post-genesis mint, so
/// `validators * this + faucet <= TOTAL_SUPPLY_CAP` must hold for EVERY
/// supported set size. At the old 100M STELL a 250-validator network allocated
/// 25B against a 1B cap, which (correctly) refused all future emission and made
/// the node refuse to boot. 1M STELL per validator keeps the largest supported
/// set (250) at 250M + 1M faucet, i.e. a quarter of the cap, and is still
/// 1000x the minimum bond — ample for fees and transfers.
pub(crate) const GENESIS_VALIDATOR_BALANCE: u64 = 1_000_000_000_000_000;

/// Floor on the interval between blocks, in milliseconds. Without it a small
/// validator set finalizes as fast as the CPU allows (~5000 blocks/s on a single
/// node), which floods the disk and log with empty blocks. Override with
/// `STELL_MIN_BLOCK_MS`; `0` removes the guard.
///
/// FLOOR DECISION (R-tempo re-measurement, 2026-10-26 — CHANGED 400 -> 50):
/// the whole 4-node live fleet already runs `STELL_MIN_BLOCK_MS=50` via env,
/// and loaded-height bursts finalize at ~1s bumper-to-bumper with it, so the
/// 400ms default was pure dead air on the happy path, not flood protection
/// (50ms still caps empty blocks at 20/s vs unbounded without the guard).
/// Pinned by `floors_pinned_until_live_remeasurement`.
pub(crate) const DEFAULT_MIN_BLOCK_MS: u64 = 50;

/// THROUGHPUT BUDGET for a 2 heights/s target (packing-perf analysis, NO
/// constant changes — see the gated decisions above and at `TICK_MS`).
///
/// 2 heights/s = 500ms per height. Per-height costs, all measured or derived
/// from pinned constants (1-vCPU stand numbers; decent hardware shrinks the
/// CPU terms but NOT the floor or the round-trip terms):
///
/// * Floor: `MIN_BLOCK_MS` = 50ms between proposals (R-tempo: was 400ms;
///   the live fleet already ran 50ms via env and bursts finalize at ~1s
///   bumper-to-bumper with it). Leaves ~450ms for everything below before
///   the 2 heights/s target is missed.
/// * Tick/round-trip: a height needs propose + prevote + precommit + finalize
///   ticks (`TICK_MS` = 50ms quantum each) plus the round timeout ladder
///   (3500ms base live). Live r0 heights measure proposal->precommit-QC in
///   ~160-580ms, bumper-to-bumper ~0.5-1s. Multi-round waste (view-change
///   ladder; 1177s outlier at #307819 from skew/lock-split, NOT proposer
///   slowness) dominates the average, not the happy path.
/// * Apply: ~16ms per 428-transfer block (serial apply ~26k native tx/s
///   in-process; see `MAX_BLOCK_GAS`). 1k TPS at 2 heights/s = 500 txs/block
///   ≈ 19ms. NOT binding on decent hardware. Now OFF the tick entirely (§7
///   Phase 2 sequenced worker).
/// * Validation (R-tempo, measured release): a loaded 1785-tx block cost
///   ~164ms per proposal per node (2x full validation + attribution
///   re-verify); the single-validation fast path removes the repeated full
///   pass (~36ms here, ~5x on 1-vCPU members). Proposal packing ~41ms cold /
///   ~11ms warm (a per-(height, root) sender snapshot makes warm the norm).
/// * Broadcast: one `request_to` round trip per peer (2s cap, concurrent per
///   peer, overlapped via the background sender but still the delivery floor;
///   see `ConsensusNetwork::start_sender`). 500 minimal txs ≈ 60KB on the
///   wire — far under `MAX_BATCH_BYTES`/`MAX_CONSENSUS_MSG`. NOT binding at
///   this tx size; fat shielded blocks are capped earlier by the
///   `MAX_BLOCK_WIRE_BYTES`/`MAX_BLOCK_PROOF_UNITS` packing caps.
/// * Gas cap arithmetic: `MAX_BLOCK_GAS` (500M) / `GAS_BASIC_TRANSFER` (280k)
///   ≈ 1785 minimal txs/block → ≈ 3570 TPS at exactly 2 heights/s. So the gas
///   cap NO LONGER binds 1k TPS of minimal transfers (500 txs need ~140M gas,
///   well inside the 500M cap) — the cap was raised from 120M in 27b1bfb.
///
/// BINDING CONSTRAINT, in order: (1) multi-round waste when the network
/// desynchronizes (round skew + lock-split nil storms; the timeout ladder is
/// the cost), (2) WAN round-trip time on the happy path (~2xRTT vote
/// collection), (3) per-proposal CPU on weak members (validation + packing,
/// cut by the R-tempo fast paths). The gas cap used to bind before 27b1bfb;
/// the floor is no longer in the top 3 at 50ms.
/// Change NO constant here without a live re-measurement showing it binding
/// loaded heights.
///
/// Per-round view-change backoff (audit 2026-10-06): the round timeout grows
/// by this much per round number, so a persistently slow network converges
/// instead of spinning at constant cadence. Capped by
/// ROUND_TIMEOUT_BACKOFF_CAP_MS. Weak-node principle: this slows ONLY rounds
/// that already failed (fast rounds never see it), never the happy path.
#[cfg(test)]
pub(crate) const ROUND_TIMEOUT_BACKOFF_PER_ROUND_MS: u64 = 500;
#[cfg(test)]
pub(crate) const ROUND_TIMEOUT_BACKOFF_CAP_MS: u64 = 10_000;

/// Effective view-change timeout for a round: base + round * backoff, capped.
/// Pure (testable without a node); round is u32 so the multiplication cannot
/// overflow u64 in practice, saturating ops make it certain.
///
/// LEGACY path (kept for compat + pinned tests): takes the local failure
/// count. Prefer [`deterministic_timeout_for`] below, which takes the ROUND
/// and the deterministic proposer-missed signal instead of a local counter.
#[cfg(test)]
pub(crate) fn effective_round_timeout_ms(base_ms: u64, round: u32) -> u64 {
    base_ms
        .saturating_add((round as u64).saturating_mul(ROUND_TIMEOUT_BACKOFF_PER_ROUND_MS))
        .min(base_ms.saturating_add(ROUND_TIMEOUT_BACKOFF_CAP_MS))
}

/// C2 DETERMINISTIC ROUND TIMING: the canonical timeout for (height, round).
///
/// Inputs (exhaustive): `base_ms` (operator env, must match on all nodes),
/// `round` (the round the timeout is FOR), `proposer_missed_streak` (ledger
/// `missed` of the scheduled proposer — block content, identical on every
/// node). Delegates to
/// [`stellereum::consensus::deterministic_round_timeout_ms`]; this wrapper
/// exists so the node loop and its tests name one place.
///
/// NO wall-clock input: no `Instant::now`, no elapsed, no peer-seen
/// timestamps, no local vote-observation flags. The old down-proposer fast
/// path gated on `vote_seen_from_proposer` (LOCAL observation — two nodes
/// with the same state computed DIFFERENT timeouts); it is replaced here by
/// the ledger signal alone. Local holds (peer-active wait, retransmit) still
/// exist as EXECUTION delays, never as timeout VALUES.
pub fn deterministic_timeout_for(base_ms: u64, round: u32, proposer_missed_streak: u32) -> u64 {
    stellereum::consensus::deterministic_round_timeout_ms(base_ms, round, proposer_missed_streak)
}

/// Deterministic down-proposer predicate: cap the timeout only on ledger
/// evidence (missed streak ≥ threshold), never on local vote observation.
///
/// The legacy [`should_use_down_proposer_timeout`] additionally required
/// "no vote seen" — a node-local flag that diverges across honest nodes and
/// therefore made two honest nodes compute different timeouts for the same
/// (height, round). That is the wall-clock-divergence class of bug task 4
/// removes. Kept for compat; new code uses this.
pub fn should_use_down_proposer_timeout_deterministic(missed_streak: u32) -> bool {
    missed_streak >= stellereum::staking::DOWNTIME_MISS_THRESHOLD
}

/// Quorum-safety log gate (урок ночи C): a set whose quorum needs 100% of
/// its power — notably any N=3 equal-stake set (3/3) — halts on ANY single
/// stop. Fail-open (testnet): never refuses, but LOUD. Every site that
/// (re)derives the validator set calls this; `stell_getValidators` carries
/// the same verdict as its `fragile` flag.
pub(crate) fn log_quorum_safety(tag: &str, validators: &ValidatorSet) {
    let powers: Vec<u64> = validators.validators.values().copied().collect();
    if let Some(reason) = stellereum::staking::validator_powers_fragility(&powers) {
        tracing::warn!("QUORUM-SAFETY {tag}: {reason}");
    }
}

/// Genesis balance for the testnet faucet account (only when `STELL_FAUCET_KEY`
/// is set). Every node of the network must set the same key, otherwise the
/// genesis state roots differ and the chain splits.
pub(crate) const GENESIS_FAUCET_BALANCE: u64 = 1_000_000_000_000_000;

/// Per-address lifetime dispense cap of the testnet faucet (`Faucet::new`'s
/// `max_per_address`), in nano-STELL. Every faucet construction site (masterchain
/// endpoint, sharded faucet, restart path) must pass the SAME cap: the faucet
/// state it bounds is persisted and reloaded across restarts, so a node running
/// a different cap would over- or under-serve addresses relative to the rest of
/// the network.
pub(crate) const FAUCET_LIFETIME_CAP: u64 = 1_000 * 1_000_000_000;

pub(crate) fn lock_hint(
    rt: &ValidatorRuntime,
    v: &stellereum::consensus::Vote,
) -> Option<[u8; 32]> {
    if v.kind == VoteKind::Prevote && v.block_hash.is_none() {
        rt.hc.locked.map(|(b, _)| b)
    } else {
        None
    }
}

/// Gossip batching window (P3-H4): outbound consensus messages wait this long
/// to be packed into one [`ConsensusMsg::Batch`] (one encode + one
/// `request_to` per peer). Large messages flush immediately; everything else
/// rides the timer. Equals [`TICK_MS`] so a flush costs no extra wakeup.
pub(crate) const BATCH_MS: u64 = 50;

/// Consensus loop tick quantum. [`BATCH_MS`] rides this timer; the quantum is
/// local pacing only (timeouts are round-driven, never tick-driven), so all
/// members must still run the same value — the fleet already does (50ms via
/// env on every live member; R-tempo codifies it). Kept coupled to BATCH_MS
/// by the pinned test below.
pub(crate) const TICK_MS: u64 = 50;

/// Max inbound consensus messages verified per tick (audit 2026-10-06).
/// Honest 2-node traffic is tens/tick; a flood of max-size batches would
/// otherwise stretch verification past the round timeout and break the clock.
pub(crate) const MAX_INBOUND_PER_TICK: u32 = 512;
/// Cap on parked over-budget Batch envelopes (audit-network F1): deferral is
/// scheduling, not parking — beyond this the oldest is handled inline (loudly
/// counted) rather than growing memory without bound. Never dropped either way.
pub(crate) const INBOUND_DEFERRED_CAP: usize = 1024;
/// Rate-limit state for the tick-side flush ENQUEUE sub-timing WARN. The
/// transport cost itself is now logged by the background sender as
/// `flush_outbox`; this one proves the tick no longer waits for it.
pub(crate) static FLUSH_ENQUEUE_STAGE_GATE: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Dedup key for an outbound vote: one vote per (height, round, kind, voter).
/// Proposals and commits have no key (never deduped).
pub(crate) fn outbox_vote_key(msg: &ConsensusMsg) -> Option<(u64, u32, VoteKind, [u8; 32])> {
    match msg {
        ConsensusMsg::Vote { vote, .. } => Some((vote.height, vote.round, vote.kind, vote.voter)),
        _ => None,
    }
}

/// Enqueue a consensus message for batched broadcast (P3-H4). Votes dedup by
/// (height, round, kind, voter): re-enqueues of the same vote (timeout
/// re-send, double make) collapse to one — EXCEPT a re-enqueue that newly
/// carries a lock hint upgrades the queued hintless copy in place (returns
/// true so the caller still flushes). Without the upgrade the timeout/periodic
/// re-sends, which rebuild the vote with a fresh hint after locking, collapse
/// against the still-queued hintless original and the rescue hint never
/// reaches the wire. Returns true when queued (or upgraded).
pub(crate) fn enqueue_outbox(
    outbox: &mut std::collections::VecDeque<ConsensusMsg>,
    msg: ConsensusMsg,
) -> bool {
    // Audit-network F12: `Committed` was never deduped, so a wedged transport
    // (continuous enqueue-refusal) plus steady finality grew the outbox one
    // entry per finalize without bound. Dedup by height: a height's commit is
    // idempotent (same outcome proof), so a re-enqueue for an already-queued
    // height collapses. Heights are kept (only exact duplicates collapse), so
    // no catch-up proof is ever lost — only the same proof twice.
    if let Some(h) = stellereum::consensus_net::committed_height_of(&msg) {
        if outbox
            .iter()
            .any(|m| stellereum::consensus_net::committed_height_of(m) == Some(h))
        {
            return false;
        }
        outbox.push_back(msg);
        return true;
    }
    if let Some(key) = outbox_vote_key(&msg) {
        if let Some(pos) = outbox
            .iter()
            .position(|m| outbox_vote_key(m).as_ref() == Some(&key))
        {
            let new_locked = match &msg {
                ConsensusMsg::Vote { locked, .. } => *locked,
                _ => None,
            };
            let old_locked = match &outbox[pos] {
                ConsensusMsg::Vote { locked, .. } => *locked,
                _ => None,
            };
            if new_locked != old_locked && new_locked.is_some() {
                outbox[pos] = msg;
                return true;
            }
            return false;
        }
    }
    outbox.push_back(msg);
    true
}

/// True when the outbox already holds a proposal for `(height, round)`.
/// The periodic thin-proposal re-send pushes the same bytes every window;
/// without this guard the outbox fills with identical bodies (each a flush +
/// an encode + a wire copy for zero new information).
pub(crate) fn outbox_has_proposal(
    outbox: &std::collections::VecDeque<ConsensusMsg>,
    height: u64,
    round: u32,
) -> bool {
    outbox.iter().any(|m| {
        // One predicate for BOTH proposal representations: COMPACT_GOSSIP is
        // active, and a compact announcement occupies the same slot.
        stellereum::consensus_net::proposal_gossip_height_round(m) == Some((height, round))
    })
}

/// True when `msg` is a proposal superseded at `(height, round)`: a proposal
/// for any other height (we moved on), or for the same height two or more
/// rounds back (same lag as [`stellereum::consensus_net::is_superseded_vote`]:
/// the receiver refuses stale rounds, so it can no longer form a quorum).
/// Never true for votes, commits, or batches.
pub(crate) fn is_superseded_proposal(msg: &ConsensusMsg, height: u64, round: u32) -> bool {
    // Delegated so a compact announcement is pruned exactly like a full one.
    stellereum::consensus_net::is_superseded_proposal(msg, height, round)
}

/// Flatten an inbound message for the drain (P3-H4): a `Batch` expands to its
/// inners in sender order, anything else is a 1-item vec. Never returns a
/// `Batch` (a nested batch that slipped past decode is dropped here).
pub(crate) fn flatten_incoming(msg: ConsensusMsg) -> Vec<ConsensusMsg> {
    match msg {
        ConsensusMsg::Batch(items) => items
            .into_iter()
            .filter(|m| !matches!(m, ConsensusMsg::Batch(_)))
            .collect(),
        single => vec![single],
    }
}

/// Flush the outbox in [`MAX_BATCH_ITEMS`]-sized chunks (P3-H4) into the
/// dedicated background sender. This is deliberately NOT `async`: the
/// `request_to` round trip is performed on the sender task, so the consensus
/// tick never awaits the transport.
///
/// Why: on a 1-vCPU host the peer's pubsub handler can take 0.4-2.0s to be
/// scheduled, and a height needs several flushes. Awaiting each `request_to`
/// here made the tick a hard serial barrier on that scheduler delay. The
/// outbox is still drained front-to-back, one chunk at a time, into a FIFO
/// queue, so message ORDER, one-encode-per-chunk and the dedup-by-key
/// behaviour are all unchanged. If the queue is saturated the remaining items
/// stay in the outbox (still deduplicated) and are retried next flush.
///
/// Before chunking, superseded votes for `(height, round)` are dropped: a
/// vote two rounds old can never form a quorum, and flushing it burns a
/// serial `request_to` slot behind a slow peer for nothing. Superseded
/// proposals for old heights/rounds are dropped for the same reason: the
/// periodic thin-proposal re-send plus the view-change re-send enqueue one
/// body per round, and behind a slow peer the FIFO would otherwise flush stale
/// bodies ahead of the current round's thin empty proposal and its votes,
/// pushing the whole round past the timeout. Commits are never dropped (a
/// commit is the only outcome proof a lagging peer gets). See
/// `stellereum::consensus_net::is_superseded_vote` and
/// `is_superseded_proposal` above.
pub(crate) fn flush_outbox(
    sender: &ConsensusSender,
    outbox: &mut std::collections::VecDeque<ConsensusMsg>,
    height: u64,
    round: u32,
) {
    flush_outbox_with(outbox, height, round, sender.queued(), |chunk| {
        sender.try_enqueue(chunk)
    });
}

fn flush_outbox_with(
    outbox: &mut std::collections::VecDeque<ConsensusMsg>,
    height: u64,
    round: u32,
    queued_before: usize,
    mut enqueue: impl FnMut(Vec<ConsensusMsg>) -> Result<(), Vec<ConsensusMsg>>,
) {
    if outbox.is_empty() {
        return;
    }
    let before = outbox.len();
    outbox.retain(|m| !stellereum::consensus_net::is_superseded_vote(m, height, round));
    let pruned_votes = before - outbox.len();
    let before_p = outbox.len();
    outbox.retain(|m| !is_superseded_proposal(m, height, round));
    let pruned_proposals = before_p - outbox.len();
    let pruned = pruned_votes + pruned_proposals;
    if outbox.is_empty() {
        // Everything queued was superseded: nothing to send, and the timer
        // must not treat this as a flush.
        if pruned > 0 {
            tracing::debug!(
                "[consensus] flush_outbox h={} r={}: dropped {} superseded vote(s) and {} superseded proposal(s), nothing to send",
                height,
                round,
                pruned_votes,
                pruned_proposals
            );
        }
        return;
    }
    if pruned > 0 {
        tracing::debug!(
            "[consensus] flush_outbox h={} r={}: dropped {} superseded vote(s) and {} superseded proposal(s)",
            height,
            round,
            pruned_votes,
            pruned_proposals
        );
    }
    let items = outbox.len();
    let t_flush = std::time::Instant::now();
    while !outbox.is_empty() {
        let n = outbox.len().min(MAX_BATCH_ITEMS);
        let chunk: Vec<ConsensusMsg> = outbox.drain(..n).collect();
        if let Err(chunk) = enqueue(chunk) {
            // Restore the refused chunk ahead of the untouched suffix. No
            // signing, deduplication, or additional persistent queue is needed.
            for msg in chunk.into_iter().rev() {
                outbox.push_front(msg);
            }
            break;
        }
    }
    // Tick-side cost: should be microseconds. The transport happens later on
    // the sender task and logs its own `flush_outbox` line.
    stellereum::consensus_net::log_stage(
        &FLUSH_ENQUEUE_STAGE_GATE,
        "flush_enqueue",
        &format!("items={items} queued={queued_before}"),
        t_flush.elapsed(),
    );
}

#[cfg(test)]
mod refused_chunk_regression {
    use super::*;
    use std::collections::VecDeque;
    use stellereum::consensus::Vote;

    fn vote(id: u8, round: u32) -> ConsensusMsg {
        ConsensusMsg::Vote {
            vote: Vote {
                shard_id: 0,
                height: 9,
                round,
                kind: VoteKind::Prevote,
                block_hash: None,
                voter: [id; 32],
                signature: vec![id; 64],
            },
            locked: None,
        }
    }

    fn ids(messages: impl IntoIterator<Item = ConsensusMsg>) -> Vec<u8> {
        messages
            .into_iter()
            .map(|m| match m {
                ConsensusMsg::Vote { vote, .. } => vote.voter[0],
                _ => panic!("expected vote"),
            })
            .collect()
    }

    #[test]
    fn refused_chunk_restores_order_budget_and_dedup_then_retries() {
        let count = MAX_BATCH_ITEMS + 3;
        let mut outbox = VecDeque::new();
        for id in 0..count {
            assert!(enqueue_outbox(&mut outbox, vote(id as u8, 4)));
        }
        let mut accepted = Vec::new();
        let mut attempts = 0;
        flush_outbox_with(&mut outbox, 9, 4, 0, |chunk| {
            attempts += 1;
            assert!(chunk.len() <= MAX_BATCH_ITEMS);
            if attempts == 2 {
                Err(chunk)
            } else {
                accepted.extend(chunk);
                Ok(())
            }
        });
        assert_eq!(attempts, 2);
        assert_eq!(accepted.len(), MAX_BATCH_ITEMS);
        assert_eq!(
            ids(outbox.iter().cloned()),
            (MAX_BATCH_ITEMS..count).map(|x| x as u8).collect::<Vec<_>>()
        );
        assert!(!enqueue_outbox(&mut outbox, vote(MAX_BATCH_ITEMS as u8, 4)));
        flush_outbox_with(&mut outbox, 9, 4, 1, |chunk| {
            accepted.extend(chunk);
            Ok(())
        });
        assert!(outbox.is_empty());
        assert_eq!(
            ids(accepted),
            (0..count).map(|x| x as u8).collect::<Vec<_>>()
        );
    }

    #[test]
    fn refusal_closed_sender_restores_and_next_flush_prunes_stale() {
        let mut outbox = VecDeque::from([vote(1, 2), vote(2, 4)]);
        flush_outbox_with(&mut outbox, 9, 4, 0, Err);
        assert_eq!(ids(outbox.iter().cloned()), vec![2]);
        flush_outbox_with(&mut outbox, 9, 6, 0, |_| panic!("stale vote sent"));
        assert!(outbox.is_empty());
    }

    #[test]
    fn flush_outbox_retains_valid_late_polka_precommit_when_local_round_advanced() {
        let late_precommit = ConsensusMsg::Vote {
            vote: stellereum::consensus::Vote {
                shard_id: 0,
                height: 9,
                round: 0,
                kind: VoteKind::Precommit,
                block_hash: Some([0x42; 32]),
                voter: [7; 32],
                signature: vec![7; 64],
            },
            locked: None,
        };
        let stale_prevote = vote(1, 2);
        let mut outbox = VecDeque::from([stale_prevote, late_precommit.clone()]);
        let mut sent = Vec::new();
        flush_outbox_with(&mut outbox, 9, 11, 0, |chunk| {
            sent.extend(chunk);
            Ok(())
        });
        assert!(outbox.is_empty());
        assert_eq!(sent.len(), 1, "only late-polka precommit survives");
        match &sent[0] {
            ConsensusMsg::Vote { vote, .. } => {
                assert_eq!(vote.kind, VoteKind::Precommit);
                assert_eq!(vote.round, 0);
            }
            other => panic!("unexpected msg: {other:?}"),
        }
    }
}

// ==================== §7 Phase 1: non-transport work OFF the tick ====================
//
// The tick is consensus. Anything that waits on a peer, on disk, or on a
// multi-millisecond encode costs the round timer directly: on the 1-vCPU stand
// (ROUND_TIMEOUT 800ms) a single awaited `store_blob` -- which can wait for a
// replica -- or a blocking sled prune stretched one tick past the timeout and
// the whole loop crawled. Two primitives below move that work off the tick
// WITHOUT changing what runs, in what order, or with what bytes:
//
//  * [`TickLane`]  -- one ordered background task. Jobs execute one at a time,
//    strictly in submission order, exactly as the tick used to await them
//    serially. Only the WAITING moves.
//  * [`spawn_guarded_blocking`] -- a blocking job on the blocking pool with a
//    single-flight guard, so two triggers can never interleave writes to the
//    same file or prune range.

/// A job on a [`TickLane`]: an owned, `'static`, `Send` future.
pub(crate) type LaneJob = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

/// One ordered background lane: a single task drives every future it receives
/// to completion STRICTLY in submission order.
///
/// FIFO here replaces the old inline `await`: `publish_head` before the retro
/// body before the header before the snapshot publish of the same height keep
/// the exact order the tick used to give them, and two jobs on one lane can
/// never overlap (the lane awaits one to completion before polling the next).
///
/// Deliberately UNBOUNDED: every job this loop carries is a once-per-height,
/// idempotent publish (head pointer, body, header, snapshot) or a local record.
/// Dropping one on a full queue would lose that height's only announcement, and
/// the announcement is never retried for some of them; backpressure for the
/// gossip path stays where it was, in `flush_outbox`/`ConsensusSender`.
///
/// Cheap to clone; all clones feed the SAME queue and therefore the same FIFO
/// (same contract as `ConsensusSender`).
#[derive(Clone)]
pub(crate) struct TickLane {
    tx: tokio::sync::mpsc::UnboundedSender<LaneJob>,
}

impl TickLane {
    /// Hand one job to the lane. Non-blocking; returns false only when the
    /// lane's task is gone (runtime shutdown).
    pub(crate) fn submit<F>(&self, job: F) -> bool
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        self.tx.send(Box::pin(job)).is_ok()
    }
}

/// Spawn a fresh [`TickLane`]. One lane per concern: a stalled DHT write must
/// not be able to delay the lane carrying a wallet's receipts, and vice versa.
pub(crate) fn spawn_tick_lane() -> TickLane {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<LaneJob>();
    tokio::spawn(async move {
        while let Some(job) = rx.recv().await {
            job.await;
        }
    });
    TickLane { tx }
}

/// Run `job` on the blocking pool, single-flight per `guard`.
///
/// The guard is claimed BEFORE the job is spawned and released only after the
/// job returns, so while one save (or prune) is in flight a second trigger is
/// refused instead of overlapping it -- two threads writing the same file or
/// scanning the same sled range was never possible while these ran inline on
/// the tick, and must not become possible now that they are fire-and-forget.
/// Returns false when the job was refused; the caller drops that request (the
/// in-flight one covers the same window).
pub(crate) fn spawn_guarded_blocking<F>(guard: &Arc<std::sync::atomic::AtomicBool>, job: F) -> bool
where
    F: FnOnce() + Send + 'static,
{
    if guard
        .compare_exchange(
            false,
            true,
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
        )
        .is_err()
    {
        return false;
    }
    let guard = Arc::clone(guard);
    tokio::task::spawn_blocking(move || {
        job();
        guard.store(false, std::sync::atomic::Ordering::SeqCst);
    });
    true
}

/// The periodic mempool save, OFF the consensus tick.
///
/// The tick used to run `mempool.read().await.save(path)` inline: bincode plus
/// a blocking `fs::write` on the same runtime that drives consensus, holding
/// the pool's read lock (and therefore blocking every admission) for the whole
/// write. Now the read lock AND the write both happen on the blocking pool;
/// the tick only claims the guard and returns. Single-flight per shard: while a
/// save is in flight, the next 15s window is skipped rather than letting two
/// threads interleave writes to the same file. Returns whether the save was
/// scheduled (false = one already in flight).
pub(crate) fn schedule_mempool_save(
    mempool: &Arc<tokio::sync::RwLock<stellereum::mempool::Mempool>>,
    path: &std::path::Path,
    guard: &Arc<std::sync::atomic::AtomicBool>,
) -> bool {
    let mempool = Arc::clone(mempool);
    let path = path.to_path_buf();
    spawn_guarded_blocking(guard, move || {
        // Inside `spawn_blocking` a tokio `RwLock` is taken with
        // `blocking_read` (the supported off-executor path); the guard lives
        // exactly as long as the old inline `read().await` did -- across the
        // whole serialize + write.
        mempool.blocking_read().save(&path);
    })
}

/// Helper to determine whether parallel execution should be active based on env var,
/// CLI arguments, or pre-configured engine state.
pub(crate) fn is_parallel_exec_active(
    env_val: Option<&str>,
    has_cli_flag: bool,
    state_enabled: bool,
) -> bool {
    let env_parallel = env_val
        .map(|v| {
            let v = v.trim();
            v == "1" || v.eq_ignore_ascii_case("true")
        })
        .unwrap_or(false);
    env_parallel || has_cli_flag || state_enabled
}

/// The §9 CROSS-SHARD 2PC activation, derived from the CHAIN SPEC.
///
/// The protocol freeze (`docs/PUBLIC_TESTNET_CODE_GAPS.md`) forbids
/// env-driven protocol switches, so the operator variable this function used
/// to read (`STELL_XPC_ACTIVATION_HEIGHT`) is DEPRECATED: it is never
/// consulted for the decision. The only production source of
/// [`stellereum::xshard2pc::XpcActivation`] is the compile-time gate
/// [`stellereum::xshard2pc::XPC_ACTIVATION_HEIGHT`] (registered in
/// `chain_spec`), which keeps the frozen public protocol on the legacy
/// outbox/inbox/ack/bounce flow.
///
/// A variable left in a supervisor unit is logged loudly and IGNORED, so an
/// operator can never half-arm the 2PC on one node of a shard (which would
/// make two nodes classify the same transfer differently — a consensus
/// split). Test code that needs the boundary constructs
/// `XpcActivation::FromHeight(h)` directly and injects it through
/// `with_xpc_activation`.
pub(crate) fn xpc_activation_from_env() -> stellereum::xshard2pc::XpcActivation {
    if let Ok(raw) = std::env::var("STELL_XPC_ACTIVATION_HEIGHT") {
        let raw = raw.trim();
        if !raw.is_empty() {
            tracing::warn!(
                "[xpc] STELL_XPC_ACTIVATION_HEIGHT={raw:?} is DEPRECATED and IGNORED: \
                 the 2PC activation comes from the chain spec \
                 (XPC_ACTIVATION_HEIGHT), never from the environment"
            );
        }
    }
    let activation = stellereum::xshard2pc::XpcActivation::from_chain_spec();
    tracing::info!("[xpc] 2PC activation from the chain spec: {:?}", activation);
    activation
}

/// Startup-heal retry budget: missing bodies are transient (a peer that just
/// restarted is still publishing its window), so the heal loop retries with
/// backoff instead of exiting on the first miss.
pub(crate) const HEAL_MAX_ATTEMPTS: u32 = 3;

/// Fail-closed decision for the startup-heal loop (pure: unit-tested below).
///
/// Returns true only on the final attempt: earlier failures must retry
/// (transient), the final failure must refuse to join consensus on unhealed
/// state. The caller loud-errors + `process::exit(1)` on true so supervisors
/// restart into a clean retry; it must NEVER label the unhealed engine with
/// the finalized height (snapshotting S-state under the F label poisons
/// the store -- the next boot loads "state at F" that is really S, skips
/// healing (`S == F`), and votes from stale state while reporting healthy).
pub(crate) fn heal_failure_should_exit(attempt: u32) -> bool {
    attempt >= HEAL_MAX_ATTEMPTS
}
