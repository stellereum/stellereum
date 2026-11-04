# Dandelion Stem/Fluff Relay Policy — Plan & Wiring Gate

Status: **policy specified, tested, UNWIRED** (`stellereum/src/dandelion.rs` is
pure and NOT registered in `lib.rs`; `stellereum/tests/dandelion_tests.rs`
includes it via `#[path]`, sim-harness idiom). Wiring into the gossip publish
path is explicitly OUT OF SCOPE here and audit-gated (see §5).

## 1. Why: IP unlinkability for stealth-payment senders

On-chain stealth (one-time addresses, hidden amounts) hides *who pays whom*
in the ledger, but a silent-payment sender still broadcasts the transaction
from their own IP: the first node to fluff a transaction is, under naive
diffusion, usually its originator. A network observer linking IPs to
transactions undoes much of the on-chain privacy work.

Dandelion fixes the network layer by decoupling origination from diffusion:
the transaction first travels a short random **stem** (one peer per hop, `H`
edges sampled geometrically), and only the terminal relayer starts the
**fluff** broadcast. An observer watching diffusion sees the transaction
enter at a random relayer, not at the sender. Measured here (mesh N=15, 120
fixed-seed runs): the walk leaves the origin in 82.5% of runs and the first
fluffer is spread over 14 of 15 nodes.

## 2. Parameters chosen (+ why)

| Param | Value | Rationale |
|---|---|---|
| `P_CONTINUE` (per-hop stem continuation `p`) | **0.8** | Mean stem `p/(1-p)` = 4 hops (uncapped): long enough that the origin is 2+ hops away in 64% of runs, short enough to add only ~4 sequential-hop latency before diffusion. `P(H=0) = 0.2` fluffs immediately, bounding worst-case delay for a fixed share of traffic. |
| `MAX_STEM_HOPS` | **10** | Fail-safe cap on the geometric tail (`P(H>10) ≈ 0.086`). Realised mean becomes 3.57 (asserted honestly against the capped value, not 4.0). Binds extreme stems, never silently queues. |
| `MAX_STEM_ENTRIES` | **512** | Per-node bound on held stems; evicts oldest (fail-closed). Flood-tested: 1200-tx flood sits exactly at the cap with oldest-first eviction proven. |
| `MAX_SEEN_ENTRIES` | **4096** | 8× the stem cap so recently-fluffed txs are still recognised as duplicates long after stem eviction. |
| `MAX_FAILOVER_RETRIES` | **3** (4 draws) | Bounded hunt for an alive stem peer; exhaustion fluffs locally. |
| Fluff timeout | per-entry, value TBD at wiring | Specified mitigation for stem blackholes (§4); module exposes `fluff_timeout(tx)`. Suggested start: single-digit seconds, comparable to a few sequential-hop RTTs — set at wiring with sim measurement. |

RNG: internal SplitMix64, seeded per call chain; **no OS randomness, no
network imports, no new crypto** (hashes only for tx identity, which the
policy treats as opaque). High bits used for indexing (SplitMix64 low bits
are weak — caught by the uniformity test).

## 3. Specified behaviour (all implemented + tested)

- Stem budget strictly decreases per forward (`r → r-1`); loops consume
  budget, never die silently, never spin (an earlier loop-kill revision
  created silent blackholes — the sim caught it, fixed to budget-consumes-loops).
- No seen-gate on stem delivery; only already-*fluffed* txs are dropped
  (seen-kinds: stem-only vs fluffed). Each node relays a given fluff at most
  once → storms terminate, completeness holds (line-15 / star-16 / mesh-25:
  15/15, 16/16, 25/25 on all fixed seeds).
- Dead end / no alive peer → fluff locally (reachable component completes).
- `on_peer_down` failover: re-emit if the recorded peer is alive, else
  re-pick (bounded retries, budget kept), else drop + fluff. Only reachable
  via stale liveness (selection pre-filters known-dead) — the sim models
  mid-stem death explicitly and asserts reroute + survivor completeness.
- Duplicate handling: re-originate → ignore; first fluff sighting relays
  once and drops stem (**fluff wins**); repeats ignored.

## 4. Risks

- **Stem blackhole (attacker swallows stem traffic).** Mitigations, both
  specified: (a) failover re-picks around a dead peer within the retry
  budget, then fluffs locally; (b) per-entry **fluff timeout** force-fluffs
  held stems, so an attacker can delay a tx only until the timeout fires.
  Residual: delay + the timeout value is a latency/anonymity trade-off to
  measure at wiring.
- **Small-graph return-to-origin.** On dense small graphs the walk can end
  where it started (measured: origin first-fluffs in 34% of mesh-15 runs vs
  20% immediate-fluff baseline). Acceptable: still a minority, and production
  graphs are far larger/sparser. Re-measure on realistic topologies at wiring.
- **Timing correlation** (stem forwarding delays fingerprint the path) is
  NOT addressed here — needs per-hop delay + cover traffic, future work.

## 5. Wiring (OUT OF SCOPE — audit-gated)

Touching the gossip publish path requires, in order: spec update in
`docs/specs/`, `lib.rs` registration of the module, a stem-message header
carrying the remaining budget, per-entry fluff-timeout timers, topology-
realistic sim runs, and a full gate
(`cargo clippy --all-targets -- -D warnings`, `cargo test --no-fail-fast`,
`consensus_liveness_harness`). None of that is done here by design.
