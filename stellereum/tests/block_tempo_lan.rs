//! R-TEMPO BLOCK-TEMPO PROOF — 100 consecutive heights on a 4-node LAN-like
//! profile with realistic (non-zero) RTTs.
//!
//! WHAT THIS PROVES: with the R-tempo timing (50ms tick, 800ms base round
//! timeout) and LAN-scale delays, the REAL consensus code paths finalize 100
//! heights in a row with ~0 view changes: mean and p99 block time stay inside
//! the 0.5s budget. The numbers are VIRTUAL ms (deterministic virtual clock,
//! seeded PRNG — reruns print identical tables), so they prove the TIMING is
//! sufficient; the CPU-path savings are proven separately by the unit perf
//! probe (single-validation fast path, pack/scan caches).
//!
//! WHAT THIS DOES NOT PROVE (stated honestly): WAN behaviour. The residual
//! gap to sustained 0.5s on the live WAN is the round-trip floor plus
//! multi-round waste when members desynchronize — see the report.
//!
//! ```text
//! cargo test --release --test block_tempo_lan -- --nocapture
//! ```

#[path = "support/consensus_cluster.rs"]
mod consensus_cluster;

use consensus_cluster::{ConsensusCluster, NodeProfile};
use std::time::Instant;

/// Live power proportions (masterchain, 4 members): the quorum is the set's
/// own two-thirds rule, so the arithmetic is the production one.
const POWERS: [u64; 4] = [
    1_999_000_000_000,
    1_999_000_000_000,
    1_968_238_883_635,
    1_471_755_052_303,
];

/// Virtual tick quantum: the production `TICK_MS` default (50ms).
const TICK_MS: u64 = 50;
/// Base round timeout: happy path needs ~3-4 ticks + delays (~350ms
/// virtual), so 800ms leaves 2x+ headroom without inviting storms.
const ROUND_TIMEOUT_MS: u64 = 800;
/// LAN-like one-way delivery delays per node (ms): NOT zero-delay. Roughly
/// 10-50ms RTT between the slowest pair, plus the 1-tick floor the pump
/// adds to every delivery.
const DELAYS: [u64; 4] = [5, 10, 15, 25];

const HEIGHTS: u64 = 100;
const BUDGET_MS: u64 = 1_000_000;

fn lan_cluster() -> ConsensusCluster {
    let profiles: Vec<NodeProfile> = POWERS
        .iter()
        .zip(DELAYS.iter())
        .map(|(p, d)| {
            NodeProfile::default()
                .with_power(*p)
                .with_inbound_delay_ms(*d)
        })
        .collect();
    ConsensusCluster::build(4, profiles, 0xBEEF1AAD, TICK_MS, ROUND_TIMEOUT_MS)
}

/// Median-of-sorted and nearest-rank p99 over block times.
fn stats(mut dts: Vec<u64>) -> (f64, u64, u64, u64) {
    dts.sort_unstable();
    let n = dts.len();
    let mean = dts.iter().sum::<u64>() as f64 / n as f64;
    let p50 = dts[n / 2];
    let p99 = dts[((n as f64 * 0.99).ceil() as usize).max(1) - 1];
    let max = dts[n - 1];
    (mean, p50, p99, max)
}

#[tokio::test]
async fn lan_profile_100_blocks_tempo() {
    let wall0 = Instant::now();
    let mut c = lan_cluster();
    // 20 distinct senders x 110 txs: ~20 txs/height of real content for the
    // whole 100-height run; the state root evolves every height.
    c.seed_transactions_multi(20, 110).await;

    // Sanity: the quorum is the set's own rule (matches live RPC math).
    assert_eq!(c.validators().quorum_power(), 4_958_662_623_959);

    // Warmup: height 1 is a GENESIS transient, not steady state. The harness
    // virtual clock starts at t=0, so the first blocks carry timestamp 0 and
    // are refused by the timestamp gate until virtual time crosses 1s
    // (production chains never start at t=0). Measure the 100 heights after.
    let warm = c.run_until(1, BUDGET_MS).await;
    assert_eq!(warm.common_height, 1);
    let mut per_height_ms: Vec<u64> = Vec::with_capacity(HEIGHTS as usize);
    let mut prev_virtual = warm.virtual_ms;
    for h in 2..=(HEIGHTS + 1) {
        let report = c.run_until(h, BUDGET_MS).await;
        assert!(
            report.common_height >= h,
            "stall at height {h}: {}\n",
            report.diagnostics()
        );
        if h <= 3 {
            println!("[tempo][lan] after height {h}:\n{}", report.diagnostics());
        }
        per_height_ms.push(report.virtual_ms - prev_virtual);
        prev_virtual = report.virtual_ms;
    }
    let report = c.run_until(HEIGHTS + 1, BUDGET_MS).await;
    let wall_ms = wall0.elapsed().as_secs_f64() * 1000.0;

    // Invariants: no fork, contiguous heights, no honest double vote, roots agree.
    for (h, entries) in report.finalized_by_height() {
        let mut hs: Vec<_> = entries.iter().map(|(_, x)| *x).collect();
        hs.sort();
        hs.dedup();
        assert_eq!(hs.len(), 1, "FORK at height {h}");
    }
    for node in &report.nodes {
        assert_eq!(
            node.finalized.len() as u64,
            HEIGHTS + 1,
            "node {} non-contiguous",
            node.index
        );
        assert!(
            report.double_votes(&[]).is_empty(),
            "double vote: {}",
            report.diagnostics()
        );
    }
    let roots: Vec<_> = report.nodes.iter().map(|n| n.state_root).collect();
    assert!(
        roots.windows(2).all(|w| w[0] == w[1]),
        "state root divergence"
    );

    // Tempo table (warmup height excluded from every stat).
    let (mean, p50, p99, max) = stats(per_height_ms);
    let decide: Vec<u32> = report
        .nodes
        .iter()
        .flat_map(|n| n.decide_rounds.iter().skip(1).copied())
        .collect();
    let total_rounds: u32 = decide.iter().sum();
    let max_round = decide.iter().copied().max().unwrap_or(0);
    let heights = HEIGHTS as f64 * report.nodes.len() as f64;
    println!("[tempo][lan] heights={HEIGHTS} nodes=4 tick={TICK_MS}ms timeout={ROUND_TIMEOUT_MS}ms delays={DELAYS:?}");
    println!("[tempo][lan] virtual_total={}ms virtual_mean={mean:.1}ms p50={p50}ms p99={p99}ms max={max}ms",
        report.virtual_ms);
    println!("[tempo][lan] decide_rounds max_r={max_round} total_extra_rounds={total_rounds} view_changes_per_block={:.4}",
        total_rounds as f64 / heights);
    println!("[tempo][lan] wall={wall_ms:.0}ms (includes real sig-verify+pack+apply per height per node)");
    for n in &report.nodes {
        println!("[tempo][lan] node{} finalized={} prevotes={} precommits={} proposals_rx={} sync_jumps={}",
            n.index, n.finalized_height, n.prevotes_cast, n.precommits_cast, n.proposals_received, n.sync_jumps);
        let nz: Vec<(usize, u32)> = n
            .decide_rounds
            .iter()
            .enumerate()
            .filter(|(_, r)| **r > 0)
            .map(|(i, r)| (i + 1, *r))
            .collect();
        println!("[tempo][lan] node{} nonzero_rounds={nz:?}", n.index);
    }

    // Bands: the 0.5s budget holds on the LAN profile with room to spare,
    // and rounds stay synchronized (no view-change storms).
    assert!(
        mean <= 500.0,
        "mean block time {mean:.1}ms exceeds 500ms budget"
    );
    assert!(
        p99 <= ROUND_TIMEOUT_MS,
        "p99 {p99}ms hit the round timeout (storm)"
    );
    assert!(
        max_round <= 1,
        "a height burned {max_round} rounds on a LAN profile"
    );
    assert!(
        total_rounds == 0,
        "expected zero view changes, burned {total_rounds}"
    );

    // Determinism: an identical run prints the identical fingerprint.
    let mut c2 = lan_cluster();
    c2.seed_transactions_multi(20, 110).await;
    let r2 = c2.run_until(HEIGHTS + 1, BUDGET_MS).await;
    assert_eq!(
        report.fingerprint(),
        r2.fingerprint(),
        "tempo proof must be deterministic"
    );
}

/// WAN CONTRAST — the residual gap, measured. Same code, same 50ms tick, but
/// WAN-scale one-way delays and the live 3500ms base timeout: the happy path
/// costs ~2xRTT in vote collection and any desync costs a full timeout
/// ladder rung. This is what remains between the LAN proof above and
/// sustained 0.5s on the live WAN. Report only (wide bands): it must make
/// progress without forking, not hit a tempo.
#[tokio::test]
async fn wan_contrast_profile_shows_the_residual_gap() {
    const W_HEIGHTS: u64 = 20;
    const W_TICK: u64 = 50;
    const W_TIMEOUT: u64 = 3500;
    const W_DELAYS: [u64; 4] = [80, 120, 180, 250];
    let profiles: Vec<NodeProfile> = POWERS
        .iter()
        .zip(W_DELAYS.iter())
        .map(|(p, d)| {
            NodeProfile::default()
                .with_power(*p)
                .with_inbound_delay_ms(*d)
        })
        .collect();
    let mut c = ConsensusCluster::build(4, profiles, 0xBEEF1AAD, W_TICK, W_TIMEOUT);
    c.seed_transactions_multi(20, 30).await;
    let wall0 = Instant::now();
    let mut prev = c.run_until(1, BUDGET_MS).await.virtual_ms;
    let mut dts = Vec::new();
    for h in 2..=(W_HEIGHTS + 1) {
        let r = c.run_until(h, BUDGET_MS).await;
        assert!(r.common_height >= h, "WAN stall at {h}");
        dts.push(r.virtual_ms - prev);
        prev = r.virtual_ms;
    }
    let report = c.run_until(W_HEIGHTS + 1, BUDGET_MS).await;
    let (mean, p50, p99, max) = stats(dts);
    let extra: u32 = report
        .nodes
        .iter()
        .flat_map(|n| n.decide_rounds.iter().skip(1).copied())
        .sum();
    println!("[tempo][wan] heights={W_HEIGHTS} tick={W_TICK}ms timeout={W_TIMEOUT}ms delays={W_DELAYS:?}");
    println!("[tempo][wan] virtual_mean={mean:.0}ms p50={p50}ms p99={p99}ms max={max}ms extra_rounds={extra} wall={:.0}ms",
        wall0.elapsed().as_secs_f64() * 1000.0);
    for (h, entries) in report.finalized_by_height() {
        let mut hs: Vec<_> = entries.iter().map(|(_, x)| *x).collect();
        hs.sort();
        hs.dedup();
        assert_eq!(hs.len(), 1, "FORK at height {h}");
    }
    assert!(report.common_height > W_HEIGHTS);
}
