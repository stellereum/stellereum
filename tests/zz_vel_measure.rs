//! VEL measurement: WAN + slow member + MIXED content, 300 heights.
//! Categorize EVERY r1+ block. Run: cargo test --release --test zz_vel_measure -- --nocapture
//! BEFORE (production-faithful): VEL_BEFORE=1 (no prebuild fast-forward, no vote pipeline)
//! AFTER (fixes on): no env (both enabled).
#[path = "support/consensus_cluster.rs"]
mod consensus_cluster;
use consensus_cluster::{ConsensusCluster, NodeProfile};
use std::collections::HashMap;
use std::time::Instant;

const POWERS: [u64; 4] = [
    1_999_000_000_000,
    1_999_000_000_000,
    1_968_238_883_635,
    1_471_755_052_303,
];
const DELAYS: [u64; 4] = [80, 120, 180, 250];
const TICK: u64 = 50;
const TIMEOUT: u64 = 3500;
const HEIGHTS: u64 = 300;
// slow 1-vCPU members C,D: extra proposal build/schedule delay
const PROPOSE_DELAYS: [u64; 4] = [0, 0, 700, 900];
const R0_CAP: u64 = 650; // harness round-0 proposal wait cap (matches STELL_ROUND_ZERO_TIMEOUT_MS)

fn stats(mut dts: Vec<u64>) -> (f64, u64, u64, u64) {
    dts.sort_unstable();
    let n = dts.len();
    let mean = dts.iter().sum::<u64>() as f64 / n as f64;
    let p50 = dts[n / 2];
    let p99 = dts[((n as f64 * 0.99).ceil() as usize).max(1) - 1];
    let max = dts[n - 1];
    (mean, p50, p99, max)
}

fn is_slow_proposer(vs: &stellereum::consensus::ValidatorSet, height: u64, round: u32) -> bool {
    match vs.proposer_for(height, round) {
        Some(id) => {
            for (idx, pd) in PROPOSE_DELAYS.iter().enumerate() {
                if *pd > 0 {
                    let sid = consensus_cluster::key_at(0xBEEF1AAD, idx as u64)
                        .verifying_key()
                        .to_bytes();
                    if sid == id {
                        return true;
                    }
                }
            }
            false
        }
        None => false,
    }
}

#[tokio::test]
async fn vel_waste_composition_300() {
    let profiles: Vec<NodeProfile> = POWERS
        .iter()
        .zip(DELAYS.iter())
        .zip(PROPOSE_DELAYS.iter())
        .map(|((p, d), pd)| {
            NodeProfile::default()
                .with_power(*p)
                .with_inbound_delay_ms(*d)
                .with_propose_delay_ms(*pd)
        })
        .collect();
    let before = std::env::var("VEL_BEFORE").as_deref() == Ok("1");
    let no_pipeline = std::env::var("VEL_NO_PIPELINE").as_deref() == Ok("1");
    let c0 = ConsensusCluster::build(4, profiles, 0xBEEF1AAD, TICK, TIMEOUT);
    // BEFORE (production-faithful): no prebuild fast-forward, no vote pipeline.
    // MID (prebuild only): VEL_NO_PIPELINE=1. AFTER (both fixes): no env.
    let mut c = if before {
        c0.with_fast_forward(false).with_vote_pipeline(false)
    } else if no_pipeline {
        c0.with_vote_pipeline(false)
    } else {
        c0
    };
    println!("[vel][mode] {}", if before { "BEFORE" } else { "AFTER" });
    // MIXED tx content: 20 senders x 320 txs = 6400 txs ~ 21 txs/height over 300 heights
    c.seed_transactions_multi(20, 320).await;
    let wall0 = Instant::now();
    let warm = c.run_until(1, 5_000_000).await;
    assert_eq!(warm.common_height, 1);
    // per_height[i] = dt of height (i+2); decide_rounds[j] = height (j+1)
    let mut per_height: Vec<u64> = Vec::with_capacity(HEIGHTS as usize);
    let mut prev = warm.virtual_ms;
    for h in 2..=(HEIGHTS + 1) {
        let r = c.run_until(h, 50_000_000).await;
        assert!(r.common_height >= h, "stall at {h}");
        per_height.push(r.virtual_ms - prev);
        prev = r.virtual_ms;
    }
    let report = c.run_until(HEIGHTS + 1, 50_000_000).await;
    let wall = wall0.elapsed().as_secs_f64() * 1000.0;
    let (mean, p50, p99, max) = stats(per_height.clone());
    let gt1 = per_height.iter().filter(|&&x| x > 1000).count();
    let gt2 = per_height.iter().filter(|&&x| x > 2000).count();
    let gt5 = per_height.iter().filter(|&&x| x > 5000).count();
    // warmup height 1 excluded from round stats (genesis transient, like block_tempo_lan)
    let decide: Vec<u32> = report
        .nodes
        .iter()
        .flat_map(|n| n.decide_rounds.iter().skip(1).copied())
        .collect();
    let total_extra: u32 = decide.iter().sum();
    let views_per_block = total_extra as f64 / (HEIGHTS as f64 * 4.0);
    let vs = c.validators().clone();
    {
        let mut counts = [0usize; 4];
        for h in 2..=(HEIGHTS + 1) {
            if let Some(p) = vs.proposer_for(h, 0) {
                for idx in 0..4 {
                    let sid = consensus_cluster::key_at(0xBEEF1AAD, idx as u64)
                        .verifying_key()
                        .to_bytes();
                    if sid == p {
                        counts[idx as usize] += 1;
                    }
                }
            }
        }
        println!("[vel][slots] r0_proposer_counts={counts:?} (slow idx2,3)");
    }
    // nil prevotes per height (all rounds)
    let mut nil_by_height: HashMap<u64, usize> = HashMap::new();
    let mut total_nils = 0usize;
    for n in &report.nodes {
        for v in &n.cast_votes {
            if v.kind == stellereum::consensus::VoteKind::Prevote && v.target.is_none() {
                let h = v.height;
                if (2..=(HEIGHTS + 1)).contains(&h) {
                    *nil_by_height.entry(h).or_insert(0) += 1;
                    total_nils += 1;
                }
            }
        }
    }
    // baseline: median dt of r0-decided heights (happy-path WAN fan-in cost)
    let mut r0_dts: Vec<u64> = Vec::new();
    let mut slow_heights: Vec<(u64, u64, u32)> = Vec::new(); // (height, dt, max_decide_round)
    let mut nil_heights = 0usize;
    let mut split_heights = 0usize;
    let mut cascade_heights = 0usize;
    let mut cascade_extra: u64 = 0;
    for (i, dt) in per_height.iter().enumerate() {
        let h = i as u64 + 2;
        let rounds: Vec<u32> = report
            .nodes
            .iter()
            .map(|nd| nd.decide_rounds[i + 1])
            .collect();
        let mx = *rounds.iter().max().unwrap();
        let mn = *rounds.iter().min().unwrap();
        if mx == 0 {
            r0_dts.push(*dt);
        } else {
            slow_heights.push((h, *dt, mx));
            if mx >= 2 {
                cascade_heights += 1;
                // one clean recovery ≈ r0-cap timeout + one WAN round; rest is cascade
                cascade_extra += dt.saturating_sub(R0_CAP + 700);
            }
            if nil_by_height.get(&h).copied().unwrap_or(0) >= 2 {
                nil_heights += 1;
            }
            if mx - mn >= 1 {
                split_heights += 1;
            }
        }
    }
    r0_dts.sort_unstable();
    let baseline = r0_dts[r0_dts.len() / 2];
    let total_extra_ms: u64 = slow_heights
        .iter()
        .map(|(_, dt, _)| dt.saturating_sub(baseline))
        .sum();
    let first_miss_ms = (slow_heights.len() as u64).saturating_mul(R0_CAP);
    let total_nils2 = total_nils;
    println!("[vel] heights={HEIGHTS} tick={TICK} timeout={TIMEOUT} delays={DELAYS:?} propose_delays={PROPOSE_DELAYS:?}");
    println!("[vel] virtual_total={}ms mean={mean:.1} p50={p50} p99={p99} max={max} gt1s={gt1} gt2s={gt2} gt5s={gt5} extra_rounds={total_extra} views_per_block={views_per_block:.4} wall={wall:.0}ms", report.virtual_ms);
    println!(
        "[vel] baseline_r0_median={baseline}ms r0_heights={} slow_heights={}",
        r0_dts.len(),
        slow_heights.len()
    );
    println!("[vel][waste] proposer-late-first-miss: heights={} ({:.1}% of 300) first_timeout_ms_total={} (cap {R0_CAP}/height)",
        slow_heights.len(), 100.0 * slow_heights.len() as f64 / HEIGHTS as f64, first_miss_ms);
    println!("[vel][waste] votes-late-cascade (rounds>=2): heights={cascade_heights} cascade_extra_ms={cascade_extra} (dt beyond {R0_CAP}+700 one-clean-recovery)");
    println!("[vel][waste] total_extra_ms_over_baseline={total_extra_ms} first_miss_share={:.1}% cascade_share={:.1}%",
        100.0 * first_miss_ms as f64 / total_extra_ms.max(1) as f64,
        100.0 * cascade_extra as f64 / total_extra_ms.max(1) as f64);
    println!("[vel][waste] nil-voter: total_nil_prevotes={total_nils2} heights_with_>=2nils={nil_heights}");
    println!("[vel][waste] lock-split (decide-round spread>=1): heights={split_heights}");
    for n in &report.nodes {
        println!("[vel][node{}] finalized={} prevotes={}/{} precommits={}/{} proposals_rx/ref={}/{} sync_jumps={}",
            n.index, n.finalized_height, n.prevotes_cast, n.prevotes_received, n.precommits_cast,
            n.precommits_received, n.proposals_received, n.proposals_refused, n.sync_jumps);
    }
    // slow-validation CPU probe (host wall ms, real crypto): batch-verify + order-commit for 20-tx block
    {
        use ed25519_dalek::SigningKey;
        let sk = SigningKey::from_bytes(&[0x42u8; 32]);
        let to = [0x11u8; 32];
        let txs: Vec<stellereum::sharding::Transaction> = (0..20u64)
            .map(|n| stellereum::sharding::Transaction::sign(&sk, to, 1_000, 21_000, n, 0, 0))
            .collect();
        let t = Instant::now();
        let ok = stellereum::sharding::Transaction::verify_signatures_batch(&txs);
        let batch_ms = t.elapsed().as_secs_f64() * 1000.0;
        let t = Instant::now();
        let _root = stellereum::mev::compute_order_merkle_root(&txs);
        let order_ms = t.elapsed().as_secs_f64() * 1000.0;
        println!("[vel][cpu] batch_verify_20tx={batch_ms:.3}ms ok={ok} order_commit_20tx={order_ms:.3}ms (host; 1-vCPU member slower)");
    }
    // VEL-2 pipeline regression (60 heights, prebuild ON both sides to isolate
    // the pipeline): the pipelined cluster must finalize, cast no honest
    // double vote, be deterministic across reruns, and never be slower in
    // aggregate than the non-pipelined one.
    {
        async fn run_once(pipeline: bool) -> (Vec<u64>, consensus_cluster::ClusterReport) {
            let profiles: Vec<NodeProfile> = POWERS
                .iter()
                .zip(DELAYS.iter())
                .zip(PROPOSE_DELAYS.iter())
                .map(|((p, d), pd)| {
                    NodeProfile::default()
                        .with_power(*p)
                        .with_inbound_delay_ms(*d)
                        .with_propose_delay_ms(*pd)
                })
                .collect();
            // Fast-forward ON (prebuild model) on both sides: only the
            // pipeline differs.
            let mut c = ConsensusCluster::build(4, profiles, 0xBEEF1AAD, TICK, TIMEOUT)
                .with_vote_pipeline(pipeline);
            c.seed_transactions_multi(20, 20).await;
            let warm = c.run_until(1, 5_000_000).await;
            assert_eq!(warm.common_height, 1);
            let mut dts = Vec::new();
            let mut prev = warm.virtual_ms;
            for h in 2..=61u64 {
                let r = c.run_until(h, 50_000_000).await;
                assert!(r.common_height >= h, "stall at {h} pipeline={pipeline}");
                dts.push(r.virtual_ms - prev);
                prev = r.virtual_ms;
            }
            let report = c.run_until(61, 50_000_000).await;
            (dts, report)
        }
        let (dts_on, rep_on) = run_once(true).await;
        let (dts_off, rep_off) = run_once(false).await;
        // Determinism: an identical pipelined rerun prints the identical fingerprint.
        let (_, rep_on2) = run_once(true).await;
        assert_eq!(
            rep_on.fingerprint(),
            rep_on2.fingerprint(),
            "pipeline run must be deterministic"
        );
        // No honest double vote on either side.
        assert!(
            rep_on.double_votes(&[]).is_empty(),
            "pipeline must not double-vote"
        );
        assert!(rep_off.double_votes(&[]).is_empty());
        // No fork on either side.
        for (h, entries) in rep_on.finalized_by_height() {
            let mut hs: Vec<_> = entries.iter().map(|(_, x)| *x).collect();
            hs.sort();
            hs.dedup();
            assert_eq!(hs.len(), 1, "FORK at height {h} (pipeline on)");
        }
        let mean_on = dts_on.iter().sum::<u64>() as f64 / dts_on.len() as f64;
        let mean_off = dts_off.iter().sum::<u64>() as f64 / dts_off.len() as f64;
        let extra_on: u32 = rep_on
            .nodes
            .iter()
            .map(|n| n.decide_rounds.iter().skip(1).sum::<u32>())
            .sum();
        let extra_off: u32 = rep_off
            .nodes
            .iter()
            .map(|n| n.decide_rounds.iter().skip(1).sum::<u32>())
            .sum();
        println!("[vel][pipeline] 60h mean_on={mean_on:.1} mean_off={mean_off:.1} extra_on={extra_on} extra_off={extra_off}");
        assert!(
            mean_on <= mean_off,
            "pipeline must not be slower in aggregate ({mean_on:.1} vs {mean_off:.1})"
        );
        assert!(
            extra_on <= extra_off,
            "pipeline must not burn more rounds ({extra_on} vs {extra_off})"
        );
    }
    let mut idx: Vec<usize> = (0..per_height.len()).collect();
    idx.sort_by_key(|&i| std::cmp::Reverse(per_height[i]));
    println!("[vel][slowest10]");
    for &i in idx.iter().take(10) {
        let h = i as u64 + 2;
        let rounds: Vec<u32> = report
            .nodes
            .iter()
            .map(|nd| nd.decide_rounds[i + 1])
            .collect();
        println!(
            "  h={h} dt={}ms rounds={rounds:?} nils={} slow_r0={}",
            per_height[i],
            nil_by_height.get(&h).copied().unwrap_or(0),
            is_slow_proposer(&vs, h, 0)
        );
    }
}
