//! Dandelion stem/fluff relay-policy proofs: deterministic, virtualized-graph,
//! no sockets.
//!
//! The policy module under test is pure (`src/dandelion.rs`, NOT registered in
//! `lib.rs` — wiring is audit-gated), so it is included here via `#[path]`
//! following the same idiom as the sim-harness support modules:
//!
//! ```text
//! cargo test --test dandelion_tests -- --nocapture
//! ```
//!
//! DETERMINISM: every run uses [`NodeRng`] with fixed seeds. No wall clock,
//! no OS randomness, no network. Reported distributions are honest sample
//! statistics over fixed seeds with theoretical values beside them.

#[path = "../src/dandelion.rs"]
mod dandelion;

use dandelion::{
    geometric_mean, geometric_mean_capped, geometric_pmf, pick_alive_stem_peer, pick_uniform_peer, txid_from_u64,
    DandelionRelay, NodeRng, PeerId, RelayAction, TxHash, DEFAULT_P_CONTINUE, MAX_SEEN_ENTRIES,
    MAX_STEM_ENTRIES, MAX_STEM_HOPS,
};
use std::collections::{HashMap, HashSet, VecDeque};

// ---------------------------------------------------------------------------
// Virtualized graph harness (in-test, following the sim-harness idiom:
// deterministic, virtual delivery, no I/O).
// ---------------------------------------------------------------------------

/// A message in flight on the virtual network.
enum Msg {
    Stem {
        from: PeerId,
        to: PeerId,
        hops_left: u32,
    },
    Fluff {
        from: PeerId,
        to: PeerId,
    },
}

/// Outcome of propagating one transaction to quiescence.
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    /// Nodes that issued a stem forward, in order (stem edges = len).
    stem_path: Vec<PeerId>,
    /// First node whose relay action was `FluffBroadcast`, if any.
    first_fluffer: Option<PeerId>,
    /// Every alive node that received the transaction (stem or fluff).
    received: HashSet<PeerId>,
    /// How many stem forwards hit a dead peer and ran failover.
    failover_events: usize,
}

struct SimNet {
    adj: HashMap<PeerId, Vec<PeerId>>,
    relays: HashMap<PeerId, DandelionRelay>,
    alive: HashSet<PeerId>,
}

impl SimNet {
    fn new(adj: HashMap<PeerId, Vec<PeerId>>, alive: HashSet<PeerId>) -> Self {
        let relays = adj
            .keys()
            .map(|id| (*id, DandelionRelay::with_defaults()))
            .collect();
        Self { adj, relays, alive }
    }

    fn candidates(&self, node: PeerId) -> Vec<PeerId> {
        self.adj.get(&node).cloned().unwrap_or_default()
    }

    /// Propagate one transaction from `origin` until the queue drains.
    /// Always terminates: each stem forward strictly consumes budget and each
    /// (node, tx) fluff is relayed at most once (seen-kind loop protection).
    fn run_tx(&mut self, rng: &mut NodeRng, origin: PeerId, tx: TxHash) -> Outcome {
        self.run_tx_inner(rng, origin, tx, None)
    }

    /// Like [`SimNet::run_tx`], but kills `kill_on_delivery` the moment a
    /// stem message is about to be delivered to it — modelling STALE
    /// liveness: the sender selected the peer while it was alive. This is
    /// the only way `on_peer_down` failover can trigger (selection itself
    /// pre-filters known-dead peers).
    fn run_tx_inner(
        &mut self,
        rng: &mut NodeRng,
        origin: PeerId,
        tx: TxHash,
        kill_on_delivery: Option<PeerId>,
    ) -> Outcome {
        let mut out = Outcome {
            stem_path: Vec::new(),
            first_fluffer: None,
            received: HashSet::new(),
            failover_events: 0,
        };
        let mut queue: VecDeque<Msg> = VecDeque::new();
        out.received.insert(origin);

        let cands = self.candidates(origin);
        let is_alive = |p: PeerId| self.alive.contains(&p);
        let action = self.relays.get_mut(&origin).expect("origin relay").originate(
            rng,
            tx,
            &cands,
            origin,
            &is_alive,
        );
        self.apply_origin_action(rng, origin, tx, action, &mut queue, &mut out);

        while let Some(msg) = queue.pop_front() {
            match msg {
                Msg::Stem { from, to, hops_left } => {
                    if kill_on_delivery == Some(to) {
                        self.alive.remove(&to);
                    }
                    if !self.alive.contains(&to) {
                        // Stem into a dead peer: the SENDER runs failover.
                        out.failover_events += 1;
                        let cands = self.candidates(from);
                        let is_alive = |p: PeerId| self.alive.contains(&p);
                        let action = self
                            .relays
                            .get_mut(&from)
                            .expect("sender relay")
                            .on_peer_down(rng, &tx, &cands, from, &is_alive);
                        self.apply_origin_action(rng, from, tx, action, &mut queue, &mut out);
                        continue;
                    }
                    out.received.insert(to);
                    let cands = self.candidates(to);
                    let is_alive = |p: PeerId| self.alive.contains(&p);
                    let action = self
                        .relays
                        .get_mut(&to)
                        .expect("relay")
                        .on_stem_receive(rng, tx, hops_left, &cands, to, &is_alive);
                    match action {
                        RelayAction::StemForward { to: next } => {
                            let hops = self
                                .relays
                                .get(&to)
                                .expect("relay")
                                .stem_entry(&tx)
                                .expect("stem entry just recorded")
                                .hops_left;
                            out.stem_path.push(to);
                            queue.push_back(Msg::Stem {
                                from: to,
                                to: next,
                                hops_left: hops,
                            });
                        }
                        RelayAction::FluffBroadcast => {
                            if out.first_fluffer.is_none() {
                                out.first_fluffer = Some(to);
                            }
                            self.flood(to, &mut queue);
                        }
                        RelayAction::IgnoreDuplicate => {}
                    }
                }
                Msg::Fluff { from, to } => {
                    if !self.alive.contains(&to) {
                        continue;
                    }
                    out.received.insert(to);
                    let action = self
                        .relays
                        .get_mut(&to)
                        .expect("relay")
                        .on_fluff_receive(tx);
                    if action == RelayAction::FluffBroadcast {
                        if out.first_fluffer.is_none() {
                            out.first_fluffer = Some(to);
                        }
                        // Forward to every alive neighbour except the sender.
                        if let Some(nbs) = self.adj.get(&to) {
                            for nb in nbs.clone() {
                                if nb != from && self.alive.contains(&nb) {
                                    queue.push_back(Msg::Fluff { from: to, to: nb });
                                }
                            }
                        }
                    }
                }
            }
        }
        out
    }

    fn apply_origin_action(
        &mut self,
        rng: &mut NodeRng,
        node: PeerId,
        tx: TxHash,
        action: RelayAction,
        queue: &mut VecDeque<Msg>,
        out: &mut Outcome,
    ) {
        let _ = rng;
        let _ = tx;
        match action {
            RelayAction::StemForward { to } => {
                let hops = self
                    .relays
                    .get(&node)
                    .expect("relay")
                    .stem_entry(&tx)
                    .expect("stem entry just recorded")
                    .hops_left;
                out.stem_path.push(node);
                queue.push_back(Msg::Stem {
                    from: node,
                    to,
                    hops_left: hops,
                });
            }
            RelayAction::FluffBroadcast => {
                if out.first_fluffer.is_none() {
                    out.first_fluffer = Some(node);
                }
                self.flood(node, queue);
            }
            RelayAction::IgnoreDuplicate => {}
        }
    }

    fn flood(&self, from: PeerId, queue: &mut VecDeque<Msg>) {
        if let Some(nbs) = self.adj.get(&from) {
            for nb in nbs.clone() {
                if self.alive.contains(&nb) {
                    queue.push_back(Msg::Fluff { from, to: nb });
                }
            }
        }
    }
}

// --- Graph builders ---------------------------------------------------------

fn line_graph(n: u64) -> HashMap<PeerId, Vec<PeerId>> {
    let mut adj: HashMap<PeerId, Vec<PeerId>> = HashMap::new();
    for i in 0..n {
        let mut nbs = Vec::new();
        if i > 0 {
            nbs.push(i - 1);
        }
        if i + 1 < n {
            nbs.push(i + 1);
        }
        adj.insert(i, nbs);
    }
    adj
}

fn star_graph(n: u64) -> HashMap<PeerId, Vec<PeerId>> {
    let mut adj: HashMap<PeerId, Vec<PeerId>> = HashMap::new();
    let leaves: Vec<PeerId> = (1..n).collect();
    adj.insert(0, leaves.clone());
    for leaf in leaves {
        adj.insert(leaf, vec![0]);
    }
    adj
}

/// Connected degree-4 mesh: ring plus `i <-> i+5` chords (n = 25).
fn mesh_graph(n: u64) -> HashMap<PeerId, Vec<PeerId>> {
    let mut adj: HashMap<PeerId, Vec<PeerId>> = HashMap::new();
    for i in 0..n {
        let mut nbs = vec![(i + 1) % n, (i + n - 1) % n];
        // Chord i <-> i+5 (degree 4 with the ring edges).
        let (a, b) = ((i + 5) % n, (i + n - 5) % n);
        if !nbs.contains(&a) {
            nbs.push(a);
        }
        if !nbs.contains(&b) {
            nbs.push(b);
        }
        adj.insert(i, nbs);
    }
    adj
}

fn all_alive(adj: &HashMap<PeerId, Vec<PeerId>>) -> HashSet<PeerId> {
    adj.keys().copied().collect()
}

// ---------------------------------------------------------------------------
// 1. POLICY: geometric stem-length distribution matches theory.
// ---------------------------------------------------------------------------

#[test]
fn geometric_distribution_matches_theory() {
    const SEEDS: u64 = 40;
    const PER_SEED: usize = 200;
    let total = (SEEDS as usize) * PER_SEED;
    let mut hist = [0usize; MAX_STEM_HOPS as usize + 1];
    let mut sum: u64 = 0;
    for s in 0..SEEDS {
        let mut rng = NodeRng::new(0xDADE_1000 + s);
        for _ in 0..PER_SEED {
            let h = dandelion::sample_stem_hops(&mut rng, DEFAULT_P_CONTINUE);
            assert!(h <= MAX_STEM_HOPS, "stem hops honour the hard cap");
            hist[h as usize] += 1;
            sum += u64::from(h);
        }
    }
    let mean = sum as f64 / total as f64;
    let p0 = hist[0] as f64 / total as f64;
    let p_ge6: f64 = hist[6..].iter().sum::<usize>() as f64 / total as f64;
    // Honest reference values: the sampler caps at MAX_STEM_HOPS, piling the
    // tail P(H > cap) = p^(cap+1) onto `cap`. So the mean to beat is the
    // CAPPED mean (≈3.570, not the uncapped 4.0), and P(H>=6) is unaffected
    // by the cap (mass only moves within the >=6 region): p^6 ≈ 0.262.
    let theory_mean = geometric_mean_capped(DEFAULT_P_CONTINUE, MAX_STEM_HOPS);
    let theory_p0 = geometric_pmf(DEFAULT_P_CONTINUE, 0);
    let theory_ge6 = DEFAULT_P_CONTINUE.powi(6);

    println!("[dandelion][geo] n={total} seeds={SEEDS} mean={mean:.3} (capped theory {theory_mean:.3}; uncapped {:.3})", geometric_mean(DEFAULT_P_CONTINUE));
    println!("[dandelion][geo] P(H=0)={p0:.4} (theory {theory_p0:.4})");
    println!("[dandelion][geo] P(H>=6)={p_ge6:.4} (theory {theory_ge6:.4}, capped tail)");
    println!("[dandelion][geo] hist={hist:?}");

    assert!((mean - theory_mean).abs() < 0.30, "mean {mean:.3} vs theory {theory_mean:.3}");
    assert!((p0 - theory_p0).abs() < 0.025, "P(H=0) {p0:.4} vs theory {theory_p0:.4}");
    assert!(
        (p_ge6 - theory_ge6).abs() < 0.04,
        "tail P(H>=6) {p_ge6:.4} vs theory {theory_ge6:.4}"
    );
}

#[test]
fn peer_selection_is_uniform_alive_and_bounded() {
    // All dead -> None (failover input, never a blackhole decision here).
    let mut rng = NodeRng::new(1);
    let cands = vec![10u64, 11, 12];
    let none_alive = |_: PeerId| false;
    assert_eq!(pick_alive_stem_peer(&mut rng, &cands, 1, &none_alive), None);

    // Empty / self-only candidates -> None.
    let all_alive = |_: PeerId| true;
    let empty: Vec<PeerId> = vec![];
    assert_eq!(pick_alive_stem_peer(&mut rng, &empty, 1, &all_alive), None);
    assert_eq!(pick_alive_stem_peer(&mut rng, &[1], 1, &all_alive), None);

    // Single alive candidate is always picked, whatever the seed.
    for seed in 0..50u64 {
        let mut rng = NodeRng::new(seed);
        assert_eq!(
            pick_alive_stem_peer(&mut rng, &[1, 42], 1, &all_alive),
            Some(42)
        );
    }

    // Uniformity over fixed seeds: each of 4 peers picked within 20-30%.
    let cands = vec![21u64, 22, 23, 24];
    let mut counts = [0usize; 4];
    for seed in 0..400u64 {
        let mut rng = NodeRng::new(0x9EEC_0000 + seed);
        let pick = pick_uniform_peer(&mut rng, &cands, 99).expect("nonempty");
        counts[cands.iter().position(|c| *c == pick).expect("member")] += 1;
    }
    println!("[dandelion][pick] uniform counts={counts:?} over 400 seeds");
    for c in counts {
        let frac = c as f64 / 400.0;
        assert!((frac - 0.25).abs() < 0.05, "pick share {frac:.3} far from 0.25");
    }
}

// ---------------------------------------------------------------------------
// 2. ANONYMITY: stem-path lengths on a mesh + origin/first-fluffer unlinking.
// ---------------------------------------------------------------------------

#[test]
fn stem_path_anonymity_on_mesh() {
    const N: u64 = 15;
    const RUNS: u64 = 120;
    let adj = mesh_graph(N);
    let alive = all_alive(&adj);
    let mut lens: Vec<usize> = Vec::new();
    let mut origin_fluffed = 0usize;
    let mut fluffers: HashSet<PeerId> = HashSet::new();

    for r in 0..RUNS {
        let mut net = SimNet::new(adj.clone(), alive.clone());
        let mut rng = NodeRng::new(0xB17E_0000 + r);
        let out = net.run_tx(&mut rng, 0, txid_from_u64(r));
        lens.push(out.stem_path.len());
        let f = out.first_fluffer.expect("quiescent run always fluffs");
        fluffers.insert(f);
        if f == 0 {
            origin_fluffed += 1;
        }
        // Every run still delivers everywhere (anonymity must not cost
        // completeness on a connected graph).
        assert_eq!(out.received.len() as u64, N, "mesh run {r} lost the tx");
    }

    let mean = lens.iter().sum::<usize>() as f64 / RUNS as f64;
    let frac_ge1 = lens.iter().filter(|l| **l >= 1).count() as f64 / RUNS as f64;
    let frac_ge2 = lens.iter().filter(|l| **l >= 2).count() as f64 / RUNS as f64;
    let frac_origin = origin_fluffed as f64 / RUNS as f64;
    println!("[dandelion][anon] mesh N={N} runs={RUNS} mean_stem={mean:.3} (capped theory {:.3})", geometric_mean_capped(DEFAULT_P_CONTINUE, MAX_STEM_HOPS));
    println!(
        "[dandelion][anon] P(len>=1)={frac_ge1:.3} (theory 0.80) P(len>=2)={frac_ge2:.3} (theory 0.64)"
    );
    println!(
        "[dandelion][anon] origin==first_fluffer {origin_fluffed}/{RUNS} ({frac_origin:.3}, theory 0.20); distinct fluffers={} lens={lens:?}",
        fluffers.len()
    );

    assert!(
        (mean - geometric_mean_capped(DEFAULT_P_CONTINUE, MAX_STEM_HOPS)).abs() < 1.0,
        "mean stem length {mean:.3}"
    );
    assert!(frac_ge1 >= 0.70, "origin must usually be hidden (P>=1 = {frac_ge1:.3})");
    assert!(frac_ge2 >= 0.50, "multi-hop stems must dominate (P>=2 = {frac_ge2:.3})");
    // The origin fluffs first in two cases: immediate fluff (P(H=0) = 0.20)
    // AND walks that return to the origin exactly as the budget expires
    // (frequent on small dense graphs via one-step backtracks). Both are
    // honest diffusion — the bound below covers their sum with margin; the
    // SHARP anonymity invariant is P(len>=1) ≈ 0.80 (the walk left).
    assert!(frac_origin <= 0.40, "origin fluffs too often: {frac_origin:.3}");
    assert!(frac_origin >= 0.08, "origin must sometimes fluff (H=0): {frac_origin:.3}");
    // Anonymity set: the observer's first-fluff vantage point varies widely.
    assert!(fluffers.len() >= 5, "only {} distinct first-fluffers", fluffers.len());
}

// ---------------------------------------------------------------------------
// 3. COMPLETENESS: fluff reaches every alive node on line/star/mesh.
// ---------------------------------------------------------------------------

#[test]
fn fluff_completeness_line_star_mesh() {
    let cases: Vec<(&str, HashMap<PeerId, Vec<PeerId>>)> = vec![
        ("line-15", line_graph(15)),
        ("star-16", star_graph(16)),
        ("mesh-25", mesh_graph(25)),
    ];
    for (name, adj) in &cases {
        let n = adj.len();
        for (i, seed) in [11u64, 12, 13].iter().enumerate() {
            let mut net = SimNet::new(adj.clone(), all_alive(adj));
            let mut rng = NodeRng::new(0xF10F_F000 + (*seed * 7919));
            let out = net.run_tx(&mut rng, 0, txid_from_u64(i as u64 + 1));
            println!(
                "[dandelion][complete] {name} seed={seed} stem_len={} first_fluffer={:?} received={}/{}",
                out.stem_path.len(),
                out.first_fluffer,
                out.received.len(),
                n
            );
            assert_eq!(out.received.len(), n, "{name} seed {seed}: tx lost");
            assert!(out.first_fluffer.is_some(), "{name}: run never fluffed");
        }
    }
}

// ---------------------------------------------------------------------------
// 4. FAILOVER: dead-end stems fluff locally; dead peers reroute; partitions
//    are fail-closed and recover via timeout.
// ---------------------------------------------------------------------------

#[test]
fn dead_end_stem_recovers_via_local_fluff() {
    // A relay whose only neighbour is down cannot stem: it must fluff.
    let mut relay = DandelionRelay::with_defaults();
    let mut rng = NodeRng::new(5);
    let tx = txid_from_u64(99);
    let dead = |_: PeerId| false;
    let action = relay.on_stem_receive(&mut rng, tx, 4, &[3], 7, &dead);
    assert_eq!(action, RelayAction::FluffBroadcast);
    assert_eq!(relay.stem_len(), 0, "no stem held past a dead end");

    // Same at origination: no alive peer -> immediate fluff, no state.
    let mut relay = DandelionRelay::with_defaults();
    let action = relay.originate(&mut rng, txid_from_u64(100), &[3], 7, &dead);
    assert_eq!(action, RelayAction::FluffBroadcast);
    assert_eq!(relay.stem_len(), 0);
}

#[test]
fn dead_stem_peer_reroutes_and_still_delivers() {
    // Case 1 — KNOWN-dead leaf: perfect liveness information means selection
    // pre-filters it, so no failover fires, yet delivery still completes.
    // (This documents that the dead-target branch is unreachable without
    // staleness — it must NOT be mistaken for failover coverage.)
    let adj = star_graph(8);
    let mut alive = all_alive(&adj);
    alive.remove(&7);
    let mut net = SimNet::new(adj.clone(), alive.clone());
    let mut rng = NodeRng::new(0xDEAD_0001);
    let out = net.run_tx(&mut rng, 1, txid_from_u64(6001));
    println!(
        "[dandelion][failover][known-dead] stem={:?} fluffer={:?} received={}/{}",
        out.stem_path,
        out.first_fluffer,
        out.received.len(),
        alive.len()
    );
    assert_eq!(out.received, alive);
    assert_eq!(out.failover_events, 0, "known-dead peers are never selected");

    // Case 2 — STALE liveness (peer dies mid-stem): probe an all-alive run
    // for a seed whose walk visits a third node, then replay the seed while
    // killing that node just as the stem arrives. Failover must reroute and
    // the survivors must still complete.
    let seed = (0..20u64)
        .find(|r| {
            let mut net = SimNet::new(adj.clone(), all_alive(&adj));
            let mut rng = NodeRng::new(0xDEAD_1000 + r);
            net.run_tx(&mut rng, 1, txid_from_u64(7000 + r)).stem_path.len() >= 3
        })
        .expect("a walk of length >= 3 within 20 fixed seeds");
    let mut probe = SimNet::new(adj.clone(), all_alive(&adj));
    let mut rng = NodeRng::new(0xDEAD_1000 + seed);
    let probe_out = probe.run_tx(&mut rng, 1, txid_from_u64(7000 + seed));
    let victim = probe_out.stem_path[2];
    println!(
        "[dandelion][failover][stale] seed={seed} probe_stem={:?} victim={victim}",
        probe_out.stem_path
    );

    let mut net = SimNet::new(adj.clone(), all_alive(&adj));
    let mut rng = NodeRng::new(0xDEAD_1000 + seed);
    let out = net.run_tx_inner(&mut rng, 1, txid_from_u64(7000 + seed), Some(victim));
    let mut survivors = all_alive(&adj);
    survivors.remove(&victim);
    println!(
        "[dandelion][failover][stale] stem={:?} fluffer={:?} failovers={} received={}/{}",
        out.stem_path,
        out.first_fluffer,
        out.failover_events,
        out.received.len(),
        survivors.len()
    );
    assert!(out.failover_events >= 1, "killing the stem target must trigger failover");
    assert_eq!(out.received, survivors, "survivors must still complete");
    assert!(out.first_fluffer.is_some());
}

#[test]
fn on_peer_down_unit_semantics() {
    // Stale-liveness failover at the unit level (no graph needed).
    let mut rng = NodeRng::new(9);
    let tx = txid_from_u64(808);
    // No held entry -> nothing to recover.
    let mut relay = DandelionRelay::with_defaults();
    assert_eq!(
        relay.on_peer_down(&mut rng, &tx, &[2, 3], 1, &|_| true),
        RelayAction::IgnoreDuplicate
    );
    // Hold a stem to peer 2.
    let action = relay.on_stem_receive(&mut rng, tx, 4, &[2, 3], 1, &|_| true);
    assert_eq!(action, RelayAction::StemForward { to: 2 });
    // Peer 2 still alive -> re-emit unchanged.
    assert_eq!(
        relay.on_peer_down(&mut rng, &tx, &[2, 3], 1, &|_| true),
        RelayAction::StemForward { to: 2 }
    );
    // Peer 2 dead, peer 3 alive -> reroute (entry updated, budget kept).
    let reroute = |p: PeerId| p != 2;
    assert_eq!(
        relay.on_peer_down(&mut rng, &tx, &[2, 3], 1, &reroute),
        RelayAction::StemForward { to: 3 }
    );
    assert_eq!(relay.stem_entry(&tx).expect("entry").next_peer, 3);
    assert_eq!(relay.stem_entry(&tx).expect("entry").hops_left, 3);
    // All dead -> drop the stem and fluff locally, never blackhole.
    assert_eq!(
        relay.on_peer_down(&mut rng, &tx, &[2, 3], 1, &|_| false),
        RelayAction::FluffBroadcast
    );
    assert!(relay.stem_entry(&tx).is_none());
}

#[test]
fn partition_is_fail_closed_and_timeout_recovers() {
    // Line of 10 with node 5 dead: left component {0..4} must still get the
    // tx; the queue must drain (no hang); held stems clear via timeout.
    let adj = line_graph(10);
    let mut alive = all_alive(&adj);
    alive.remove(&5);
    let mut net = SimNet::new(adj, alive.clone());
    let mut rng = NodeRng::new(0x9A87_0101);
    let tx = txid_from_u64(777);
    let out = net.run_tx(&mut rng, 0, tx);
    let left: HashSet<PeerId> = (0..5).collect();
    println!(
        "[dandelion][partition] stem={:?} fluffer={:?} received={:?}",
        out.stem_path, out.first_fluffer, out.received
    );
    assert_eq!(out.received, left, "reachable component must be complete");
    assert!(!out.received.contains(&6), "partition must hold: node 6 unreachable");

    // Held stems (nodes still waiting on the severed path) recover via the
    // specified fluff timeout instead of blackholing.
    let mut timed_out = 0;
    for id in alive {
        let entry = net.relays.get(&id).expect("relay").stem_entry(&tx);
        if entry.is_some() {
            let fired = net
                .relays
                .get_mut(&id)
                .expect("relay")
                .fluff_timeout(&tx);
            assert_eq!(fired, Some(RelayAction::FluffBroadcast));
            timed_out += 1;
        }
    }
    println!("[dandelion][partition] fluff-timeout fired on {timed_out} held stem(s)");
    for (id, relay) in &net.relays {
        assert_eq!(relay.stem_len(), 0, "node {id} still holds stem after timeout");
    }
    // Timeout on a non-held tx is a no-op.
    assert_eq!(
        net.relays
            .get_mut(&0)
            .expect("relay")
            .fluff_timeout(&txid_from_u64(123_456)),
        None
    );
}

// ---------------------------------------------------------------------------
// 5. DUPLICATES: fluff wins, loops terminate.
// ---------------------------------------------------------------------------

#[test]
fn duplicate_handling_fluff_wins_and_loops_terminate() {
    let mut rng = NodeRng::new(42);
    let all_alive = |_: PeerId| true;
    // Find a seed that actually stems so the test exercises held state.
    let mut relay = DandelionRelay::with_defaults();
    let tx = txid_from_u64(31337);
    let mut stemmed = false;
    for seed in 0..10u64 {
        let mut r = DandelionRelay::with_defaults();
        let mut rng = NodeRng::new(seed);
        if r.originate(&mut rng, tx, &[2], 1, &all_alive) == (RelayAction::StemForward { to: 2 }) {
            relay = r;
            stemmed = true;
            break;
        }
    }
    assert!(stemmed, "10 seeds never stemmed — check DEFAULT_P_CONTINUE");
    assert!(relay.stem_entry(&tx).is_some());
    assert!(relay.is_seen(&tx));

    // Re-originating the same tx is a duplicate: no second stem.
    assert_eq!(
        relay.originate(&mut rng, tx, &[2], 1, &all_alive),
        RelayAction::IgnoreDuplicate
    );
    // First fluff sighting of a stem-held tx wins: it is relayed onward
    // exactly once and the stem state is dropped.
    assert_eq!(relay.on_fluff_receive(tx), RelayAction::FluffBroadcast);
    assert!(relay.stem_entry(&tx).is_none(), "fluff must drop stem state");
    assert!(relay.is_fluffed(&tx));
    // Repeats of the fluff are ignored (storm termination); each node relays
    // a given fluff at most once.
    assert_eq!(relay.on_fluff_receive(tx), RelayAction::IgnoreDuplicate);
    // Late stem deliveries of the fluffed tx are ignored (fluff wins).
    assert_eq!(
        relay.on_stem_receive(&mut rng, tx, 3, &[2], 1, &all_alive),
        RelayAction::IgnoreDuplicate
    );
    assert_eq!(relay.stem_len(), 0);
}

#[test]
fn stem_loop_consumes_budget_instead_of_blackholing() {
    // A stem that loops back over visited nodes must keep walking (budget
    // strictly decreases per forward) and fluff exactly when the budget runs
    // out — never die silently, never spin forever.
    let mut rng = NodeRng::new(3);
    let all_alive = |_: PeerId| true;
    let mut relay = DandelionRelay::with_defaults();
    let tx = txid_from_u64(4242);
    let action = relay.on_stem_receive(&mut rng, tx, 5, &[2], 1, &all_alive);
    assert_eq!(action, RelayAction::StemForward { to: 2 });
    // The stem loops back with remaining budget: keep walking, overwriting
    // the stale entry (budget 4 -> 3), not fluffing and not dying.
    let action = relay.on_stem_receive(&mut rng, tx, 4, &[2], 1, &all_alive);
    assert_eq!(action, RelayAction::StemForward { to: 2 });
    assert_eq!(
        relay.stem_entry(&tx).expect("entry").hops_left,
        3,
        "looped stem must consume budget"
    );
    assert!(!relay.is_fluffed(&tx));
    // Budget exhausted on a revisit: this node fluffs.
    let action = relay.on_stem_receive(&mut rng, tx, 0, &[2], 1, &all_alive);
    assert_eq!(action, RelayAction::FluffBroadcast);
    assert!(relay.is_fluffed(&tx));
    assert!(relay.stem_entry(&tx).is_none());
    // The emitted fluff terminates on re-receipt (relayed at most once).
    assert_eq!(relay.on_fluff_receive(tx), RelayAction::IgnoreDuplicate);
}

// ---------------------------------------------------------------------------
// 6. BOUNDED MAP: flood cannot grow memory; oldest evicted first.
// ---------------------------------------------------------------------------

#[test]
fn stem_map_stays_bounded_under_flood_with_oldest_eviction() {
    let mut relay = DandelionRelay::with_defaults();
    let mut rng = NodeRng::new(0xF100_D000);
    let all_alive = |_: PeerId| true;
    const FLOOD: u64 = 1200;
    let mut inserted: Vec<TxHash> = Vec::new();
    for i in 0..FLOOD {
        let tx = txid_from_u64(1_000_000 + i);
        if relay.originate(&mut rng, tx, &[9], 1, &all_alive) == (RelayAction::StemForward { to: 9 }) {
            inserted.push(tx);
        }
    }
    println!(
        "[dandelion][bound] flood={FLOOD} inserted={} stem_len={} seen_len={}",
        inserted.len(),
        relay.stem_len(),
        relay.seen_len()
    );
    assert!(inserted.len() > MAX_STEM_ENTRIES, "flood must exceed the cap");
    assert_eq!(relay.stem_len(), MAX_STEM_ENTRIES, "stem map must sit AT the cap");
    assert!(relay.seen_len() <= MAX_SEEN_ENTRIES, "seen-set must stay bounded");
    // Oldest-first eviction: the held set is exactly the most recent inserts.
    let want: HashSet<TxHash> = inserted[inserted.len() - MAX_STEM_ENTRIES..].iter().copied().collect();
    let held: HashSet<TxHash> = {
        let mut h = HashSet::new();
        for tx in &inserted {
            if relay.stem_entry(tx).is_some() {
                h.insert(*tx);
            }
        }
        h
    };
    assert_eq!(held, want, "eviction must drop oldest first");
}

// ---------------------------------------------------------------------------
// 7. DETERMINISM: identical seeds replay identically.
// ---------------------------------------------------------------------------

#[test]
fn deterministic_replay_is_identical() {
    let adj = mesh_graph(15);
    let run = |seed: u64| {
        let mut net = SimNet::new(adj.clone(), all_alive(&adj));
        let mut rng = NodeRng::new(seed);
        net.run_tx(&mut rng, 0, txid_from_u64(2026))
    };
    let (a, b) = (run(0xBE5E_0001), run(0xBE5E_0001));
    assert_eq!(a, b, "same seed must replay identically");
    println!(
        "[dandelion][replay] stem={:?} fluffer={:?} received={}",
        a.stem_path,
        a.first_fluffer,
        a.received.len()
    );
    let c = run(0xBE5E_0002);
    assert_ne!((a.stem_path, a.first_fluffer), (c.stem_path, c.first_fluffer),
        "different seeds should diverge (sanity: rng is wired in)");
}

// ---------------------------------------------------------------------------
// 8. RELAY INGRESS CLAMP (pentest Medium): adversarial wire budgets fail
//    closed to fluff; legitimate max-hop stems are untouched.
// ---------------------------------------------------------------------------

#[test]
fn inbound_over_cap_budgets_fail_closed_to_fluff() {
    // The wire budget is attacker-controlled: originate-side sampling caps at
    // MAX_STEM_HOPS but relay ingress did not, so u32::MAX forwarded as
    // MAX-1. Over-cap ingress must now take the existing fluff-source path
    // (no held stem, tagged fluffed), never a forward beyond the cap.
    let mut rng = NodeRng::new(0xC14A_0001);
    let all_alive = |_: PeerId| true;
    for incoming in [MAX_STEM_HOPS + 1, MAX_STEM_HOPS + 100, u32::MAX] {
        let mut relay = DandelionRelay::with_defaults();
        let tx = txid_from_u64(900_000 + incoming as u64);
        assert_eq!(
            relay.on_stem_receive(&mut rng, tx, incoming, &[2, 3], 1, &all_alive),
            RelayAction::FluffBroadcast,
            "over-cap {incoming} must fluff, never forward"
        );
        assert!(
            relay.stem_entry(&tx).is_none(),
            "over-cap {incoming} must hold no stem (nothing for timeout to chase)"
        );
        assert!(
            relay.is_fluffed(&tx),
            "over-cap {incoming} marks fluffed (fluff wins / storm termination)"
        );
        // No-stall: repeats terminate via the unchanged fluff-wins path.
        assert_eq!(
            relay.on_stem_receive(&mut rng, tx, incoming, &[2, 3], 1, &all_alive),
            RelayAction::IgnoreDuplicate
        );
        assert_eq!(relay.on_fluff_receive(tx), RelayAction::IgnoreDuplicate);
    }
    println!("[dandelion][clamp] over-cap {{11, 110, u32::MAX}} all fluff with no held stem");
}

#[test]
fn inbound_at_or_below_cap_stems_unaffected() {
    // Legitimate boundary: every budget 1..=MAX_STEM_HOPS still stems with
    // exactly one less (cap preserved end to end, including exactly MAX).
    let mut rng = NodeRng::new(0xC14A_0002);
    let all_alive = |_: PeerId| true;
    for incoming in 1..=MAX_STEM_HOPS {
        let mut relay = DandelionRelay::with_defaults();
        let tx = txid_from_u64(910_000 + incoming as u64);
        match relay.on_stem_receive(&mut rng, tx, incoming, &[2, 3], 1, &all_alive) {
            RelayAction::StemForward { .. } => {}
            other => panic!("in-cap {incoming} must forward, got {other:?}"),
        }
        assert_eq!(
            relay.stem_entry(&tx).expect("entry").hops_left,
            incoming - 1,
            "in-cap {incoming} must hand on exactly one less"
        );
        assert!(!relay.is_fluffed(&tx));
    }
    println!(
        "[dandelion][clamp] 1..={MAX_STEM_HOPS} all stem with budget-1 (at-cap hands on {})",
        MAX_STEM_HOPS - 1
    );
}
